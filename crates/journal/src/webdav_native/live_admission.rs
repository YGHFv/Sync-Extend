//! Complete private D01 admission from original held capture; no native effect issued.
use super::{
    budget_manifest::{self, BudgetLimits},
    execution::{self, WebDavDurableExecution, WebDavDurableExecutionLimits},
    future_history, invalid, manifest_audit, receipt_protocol,
    retained::RetainedDavBaseline,
    scope, WebDavNativeAdmission,
};
use crate::{storage_inventory::reader::add, CasAccessGuard, Journal, Result};
use rusqlite::{params, Transaction, TransactionBehavior};
use std::{cell::RefCell, path::Path, sync::Arc};
use sync_extend_core_model::{
    tree_restore_history::encode_history_record, webdav_mutation::WebDavMutationRequest,
    webdav_native::WebDavNativeLimits, ContentId, SpaceId,
};

/// Original guards live in this non-deserializable private object.
/// Reconcile must additionally borrow the original LocalSpace process owner.
pub struct LiveDavAdmission<'a> {
    data_owner: &'a sync_extend_platform_fs::WriterOwner,
    worktree_owner: &'a sync_extend_platform_fs::WriterOwner,
    journal: &'a Journal,
    coordination: CasAccessGuard,
    originals: RetainedDavBaseline,
    execution: WebDavDurableExecution,
    manifest_hash: ContentId,
    native_peak: super::native_capacity::NativePeak,
    native_owner: super::native_owner::InitialNativeOwner,
    failed: bool,
    collections: Option<super::held_collections::HeldCollections>,
    native_handle_limit: usize,
    failed_native_path: Option<sync_extend_core_model::PortablePath>,
    failed_native_status:
        Option<sync_extend_core_model::webdav_partial_response::WebDavCollectionFailure>,
    file_read_audit: RefCell<Option<Arc<VerifiedFileAudit>>>,
}

impl Journal {
    fn verify_complete_original_write(
        &self,
        before: &crate::storage_capacity::CapacitySnapshot,
        after: &crate::storage_capacity::CapacitySnapshot,
        manifest_hash: &ContentId,
    ) -> Result<()> {
        let audit = self.webdav_native_read_charges.read(&self.connection)?;
        let complete = audit.manifests(&self.connection)?;
        let accepted = complete
            .iter()
            .find(|row| &row.budget.manifest_hash == manifest_hash)
            .ok_or_else(invalid)?;
        if accepted.budget.manifest.original_main != budget_manifest::original_values(&before.rows)?
            || !after.report.within_accounted_limits()
            || !after.report.coverage_gaps().is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// One private owner, CAS→SQL→exact original capture→full ledger→commit.
    /// No public boolean or supplied serialized binding can invoke this writer.
    // Distinct live owners and bounded inputs remain explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_complete_dav<'a>(
        &'a self,
        data_owner: &'a sync_extend_platform_fs::WriterOwner,
        worktree_owner: &'a sync_extend_platform_fs::WriterOwner,
        space: &SpaceId,
        request: &WebDavMutationRequest,
        native_limits: WebDavNativeLimits,
        budget_limits: BudgetLimits,
        max_handles: usize,
        max_receipt_json: u64,
        time: u64,
    ) -> Result<LiveDavAdmission<'a>> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let data = self.database_path.parent().ok_or_else(invalid)?;
        if self.database_path != data.join("journal.sqlite")
            || std::fs::symlink_metadata(&self.database_path)?
                .file_type()
                .is_symlink()
        {
            return Err(invalid());
        }
        let worktree = self.state("worktree")?.ok_or_else(invalid)?;
        data_owner.verify(data)?;
        worktree_owner.verify(&Path::new(&worktree).join(".sync-extend"))?;
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let _dav_read_scope = self.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        scope(&tx, space, &request.origin_device)?;
        self.require_no_tree_restore(space, crate::limits::MAX_ENTRIES)?;
        let initial = self.webdav_native_read_charges.read(&tx)?;
        if initial.descriptions(&tx)?.iter().any(|row| {
            row.description.request.transaction_id == request.transaction_id || row.writer_gate_held
        }) {
            return Err(invalid());
        }
        let root = self.state("worktree")?.ok_or_else(invalid)?;
        let baseline =
            crate::snapshot_retention::audit_snapshot(&tx, space, &request.baseline)?.manifest;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        let original_map = budget_manifest::original_values(&before.rows)?;
        let originals = RetainedDavBaseline::capture(
            Path::new(&root),
            self.database_path.parent().ok_or_else(invalid)?,
            request,
            native_limits,
            &baseline,
            max_handles,
        )
        .map_err(|_| invalid())?;
        let description = originals
            .description(request, native_limits)
            .map_err(|_| invalid())?;
        let prepared = super::prepare(&tx, &description, space, time, true)?;
        if prepared.plan != *originals.plan() {
            return Err(invalid());
        }
        let native_peak = super::native_capacity::NativePeak::derive(&baseline, &prepared.plan)?;
        let owner_handles = data_owner
            .retained_handle_count()
            .checked_add(worktree_owner.retained_handle_count())
            .ok_or_else(invalid)?;
        let future_handles = native_peak
            .additional_directory_objects
            .checked_add(native_peak.additional_file_objects)
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(invalid)?;
        let peak_handles = (originals.retained_handle_count().map_err(|_| invalid())? as u64)
            .checked_add(owner_handles as u64)
            .and_then(|count| count.checked_add(future_handles))
            .and_then(|count| {
                count.checked_add(u64::from(native_peak.additional_file_objects != 0))
            })
            .ok_or_else(invalid)?;
        if peak_handles > max_handles as u64
            || max_handles > native_limits.max_bindings
            || native_peak.prospective_namespace_paths > native_limits.max_bindings as u64
            || native_peak.additional_logical_file_bytes > native_limits.max_staging_bytes
        {
            return Err(invalid());
        }
        let root_space = sync_extend_platform_fs::held_disk_space(
            originals.root_parent().map_err(|_| invalid())?,
            Path::new(&root),
        )?;
        if root_space.available_to_caller
            < native_peak.allocation_peak(root_space.allocation_unit)?
        {
            return Err(invalid());
        }
        for content in prepared.chunks.keys() {
            self.require_cas_access(content)?;
        }
        let description_hash = ContentId::hash(prepared.json.as_bytes());
        let admission = WebDavNativeAdmission {
            description: description.clone(),
            description_hash: description_hash.clone(),
            plan_hash: prepared.plan.fingerprint().clone(),
            admitted_at_ms: time,
            cancelled_at_ms: None,
            writer_gate_held: true,
            native_execution_admitted: false,
        };
        let scope = receipt_protocol::ReceiptScope {
            transaction_id: request.transaction_id.clone(),
            description_hash,
            request_hash: prepared.plan.request_hash().clone(),
            plan_hash: prepared.plan.fingerprint().clone(),
        };
        let templates = receipt_protocol::templates(
            &scope,
            &prepared.plan,
            budget_limits.max_templates,
            max_receipt_json,
            budget_limits.max_manifest_json,
        )?;
        let bindings = originals
            .initial_bindings(
                &baseline,
                budget_limits.max_binding_json,
                budget_limits.max_manifest_json,
            )
            .map_err(|_| invalid())?;
        let native_handles = super::native_capacity::NativeHandles::derive(
            &bindings.descriptions,
            &native_peak,
            max_handles,
        )?;
        if native_handles.maximum_live_handles != peak_handles
            || native_handles.original_objects
                != originals.retained_handle_count().map_err(|_| invalid())? as u64
            || native_handles.process_owner_handles != owner_handles as u64
        {
            return Err(invalid());
        }
        let expected_binding_set_hash = ContentId::hash(&encode_history_record(
            &(
                prepared.plan.fingerprint(),
                baseline.root()?,
                &bindings.hashes,
            ),
            budget_limits.max_manifest_json,
        )?);
        if bindings.complete_hash != expected_binding_set_hash {
            return Err(invalid());
        }
        let required_records = prepared
            .plan
            .steps()
            .len()
            .checked_mul(2)
            .ok_or_else(invalid)?;
        if budget_limits.execution_records != required_records
            || max_handles > budget_limits.max_bindings
            || max_handles > self.max_storage_entries
        {
            return Err(invalid());
        }
        let history = future_history::plan(
            space,
            request,
            &prepared.plan,
            &original_map,
            time,
            budget_limits.max_manifest_json,
            crate::limits::MAX_ENTRIES,
        )?;
        let budget = budget_manifest::prepare(
            &scope,
            &manifest_audit::catalog_hash(&tx)?,
            &original_map,
            &templates,
            &bindings.descriptions,
            &history,
            &native_peak,
            &native_handles,
            budget_limits,
            time,
        )?;
        let journal_headroom = budget
            .total_new_peak
            .logical_bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(4 * 1024 * 1024))
            .ok_or_else(invalid)?;
        let data_space = sync_extend_platform_fs::held_disk_space(
            originals.data_parent().map_err(|_| invalid())?,
            data,
        )?;
        if data_space.available_to_caller < journal_headroom {
            return Err(invalid());
        }
        // Original description/new chunks/cancellation peak/clock are additional
        // to the full execution manifest, matching the existing parent widths.
        let has_clock = before
            .rows
            .iter()
            .any(|row| row.table() == "webdav_native_clock");
        let description_rows = add(2 + u64::from(!has_clock), prepared.chunks.len() as u64)?;
        let description_bytes = add(
            280 + prepared.json.len() as u64,
            add(
                40 + 16 * u64::from(!has_clock),
                (prepared.chunks.len() as u64)
                    .checked_mul(104)
                    .ok_or_else(invalid)?,
            )?,
        )?;
        if add(
            before.report.accounted_total().rows,
            add(description_rows, budget.total_new_peak.rows)?,
        )? > bounds.max_rows
            || add(
                before.report.accounted_total().logical_bytes,
                add(description_bytes, budget.total_new_peak.logical_bytes)?,
            )? > bounds.max_logical_bytes
        {
            return Err(invalid());
        }
        super::advance_clock(&tx, time)?;
        self.webdav_native_description_issue.issue(
            prepared.plan.fingerprint().to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.webdav_native_admissions VALUES(?1,?2,?3,?4,?5,?6,?7,1,40)",
                    params![
                        request.transaction_id.as_str(),
                        space.as_str(),
                        request.baseline.as_str(),
                        prepared.plan.request_hash().as_str(),
                        prepared.plan.fingerprint().as_str(),
                        crate::sql_integer(time)?,
                        &prepared.json
                    ],
                )?;
                Ok(())
            },
        )?;
        for (content, length) in &prepared.chunks {
            self.webdav_native_object_issue
                .issue(content.to_string(), time, || {
                    tx.execute(
                        "INSERT INTO main.webdav_native_objects VALUES(?1,?2,?3)",
                        params![
                            request.transaction_id.as_str(),
                            content.as_str(),
                            crate::sql_integer(*length)?
                        ],
                    )?;
                    Ok(())
                })?;
        }
        let limits = WebDavDurableExecutionLimits {
            max_records: required_records,
            max_record_bytes: budget_limits.max_execution_record_json,
            max_total_bytes: budget_limits.max_total_execution_json,
        };
        let admission_hash =
            execution::admission_hash(&admission, prepared.plan.request_hash(), limits, time)?;
        self.webdav_native_execution_admission_issue.issue(admission_hash.to_string(),time,||{
            tx.execute("INSERT INTO main.webdav_native_execution_admissions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![request.transaction_id.as_str(),admission.description_hash.as_str(),
                    prepared.plan.request_hash().as_str(),prepared.plan.fingerprint().as_str(),
                    crate::sql_integer(required_records as u64)?,crate::sql_integer(limits.max_record_bytes)?,
                    crate::sql_integer(limits.max_total_bytes)?,crate::sql_integer(time)?,
                    admission_hash.as_str()])?;
            Ok(())
        })?;
        for template in &templates {
            let json = encode_history_record(template, budget_limits.max_manifest_json)?;
            let fingerprint = ContentId::hash(&json);
            self.webdav_native_execution_template_issue.issue(fingerprint.to_string(),time,||{
                tx.execute("INSERT INTO main.webdav_native_execution_templates VALUES(?1,?2,?3,1,?4,?5,?6)",
                    params![request.transaction_id.as_str(),crate::sql_integer(template.index as u64)?,fingerprint.as_str(),
                        crate::sql_integer(add(120,template.max_receipt_json_bytes)?)?,
                        crate::sql_integer(time)?,std::str::from_utf8(&json).map_err(|_|invalid())?])?;
                Ok(())
            })?;
        }
        for (index, (json, fingerprint)) in bindings.json.iter().zip(&bindings.hashes).enumerate() {
            self.webdav_native_execution_binding_issue.issue(
                fingerprint.to_string(),
                time,
                || {
                    tx.execute(
                        "INSERT INTO main.webdav_native_execution_bindings VALUES(?1,?2,?3,?4,?5)",
                        params![
                            request.transaction_id.as_str(),
                            crate::sql_integer(index as u64)?,
                            fingerprint.as_str(),
                            crate::sql_integer(time)?,
                            std::str::from_utf8(json).map_err(|_| invalid())?
                        ],
                    )?;
                    Ok(())
                },
            )?;
        }
        self.webdav_native_execution_manifest_issue.issue(budget.manifest_hash.to_string(),time,||{
            tx.execute("INSERT INTO main.webdav_native_execution_manifests VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![request.transaction_id.as_str(),budget.manifest_hash.as_str(),crate::sql_integer(templates.len() as u64)?,
                    crate::sql_integer(bindings.descriptions.len() as u64)?,crate::sql_integer(templates.len() as u64)?,crate::sql_integer(budget.future.rows)?,
                    crate::sql_integer(budget.future.logical_bytes)?,crate::sql_integer(time)?,
                    std::str::from_utf8(&budget.manifest_json).map_err(|_|invalid())?])?;
            Ok(())
        })?;
        let verified = self.webdav_native_read_charges.read(&tx)?;
        let accepted = verified
            .executions(&tx)?
            .iter()
            .find(|row| row.transaction_id == request.transaction_id)
            .ok_or_else(invalid)?
            .clone();
        if !verified
            .manifests(&tx)?
            .iter()
            .any(|row| row.budget.manifest_hash == budget.manifest_hash)
        {
            return Err(invalid());
        }
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        if !after.report.within_accounted_limits() || !after.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        originals.verify_initial(&baseline).map_err(|_| invalid())?;
        self.verify_complete_original_write(&before, &after, &budget.manifest_hash)?;
        data_owner.verify(data)?;
        worktree_owner.verify(&Path::new(&worktree).join(".sync-extend"))?;
        coordination.verify()?;
        super::checkpoint("webdav_complete_admission_before_commit");
        tx.commit()?;
        super::checkpoint("webdav_complete_admission_after_commit");
        let native_owner = super::native_owner::InitialNativeOwner::new(Path::new(&root), &scope);
        Ok(LiveDavAdmission {
            native_owner,
            failed: false,
            collections: None,
            native_handle_limit: max_handles,
            failed_native_path: None,
            failed_native_status: None,
            file_read_audit: RefCell::new(None),
            data_owner,
            worktree_owner,
            journal: self,
            coordination,
            originals,
            execution: accepted,
            manifest_hash: budget.manifest_hash,
            native_peak,
        })
    }
}

impl LiveDavAdmission<'_> {
    /// Descriptive view of the first retained capture; grants no native effects.
    pub fn native_plan(&self) -> &sync_extend_core_model::webdav_native::WebDavNativePlan {
        self.originals.plan()
    }

    pub fn execution(&self) -> &WebDavDurableExecution {
        &self.execution
    }

    /// Read-only original guard view; no supplied observation or skip list.
    pub fn verify_file_view(&self) -> Result<()> {
        let view = self.inventory_file_view()?;
        // The public compatibility entry keeps its original live receipt read.
        self.verify_native_space()?;
        view.verify_sql_generation()
    }
    fn verify_held_namespace(&self) -> Result<()> {
        self.verify_held_namespace_with_baseline(&self.baseline()?)
    }
    fn verify_held_namespace_with_baseline(
        &self,
        baseline: &sync_extend_core_model::Manifest,
    ) -> Result<()> {
        match &self.collections {
            Some(collections) => {
                self.originals
                    .verify_collection(baseline, &self.native_owner, collections)
            }
            None => self
                .originals
                .verify_with_owner(baseline, &self.native_owner),
        }
        .map_err(|_| invalid())
    }
    pub fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        self.verify_file_view()?;
        self.observe_held_file(path)
    }
    fn observe_held_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        if let Some(file) = self
            .originals
            .observe_original_file(path)
            .map_err(|_| invalid())?
        {
            return Ok(Some(file));
        }
        if let Some(collections) = &self.collections {
            if let Some(file) = collections.observe_file(path).map_err(|_| invalid())? {
                return Ok(Some(file));
            }
            self.native_owner
                .observe_file_with_collections(path, collections)
        } else {
            self.native_owner.observe_file(path)
        }
    }
    pub fn remaining_internal_bytes(&self) -> Result<u64> {
        let view = self.inventory_file_view()?;
        view.verify()?;
        let remaining = self.remaining_internal_bytes_from_held()?;
        view.verify_sql_generation()?;
        Ok(remaining)
    }
    fn remaining_internal_bytes_from_held(&self) -> Result<u64> {
        if super::reference_handoff::terminal(
            &self.journal.connection,
            &self.execution.transaction_id,
        )? {
            return Ok(0);
        }
        self.remaining_active_internal_bytes_from_held()
    }
    fn remaining_active_internal_bytes_from_held(&self) -> Result<u64> {
        let files = match &self.collections {
            Some(collections) => collections.materialized_bytes().map_err(|_| invalid())?,
            None => 0,
        };
        self.native_peak
            .additional_logical_file_bytes
            .checked_sub(self.native_owner.marker_bytes_present()?)
            .and_then(|remaining| remaining.checked_sub(files))
            .ok_or_else(invalid)
    }
    fn verify_native_space(&self) -> Result<()> {
        if super::reference_handoff::terminal(
            &self.journal.connection,
            &self.execution.transaction_id,
        )? {
            return Ok(());
        }
        self.verify_active_native_space()
    }
    fn verify_native_space_from_audit(&self, audit: &VerifiedFileAudit) -> Result<()> {
        if audit.terminal(self)? {
            return Ok(());
        }
        self.verify_active_native_space()
    }
    fn remaining_internal_bytes_from_audit(&self, audit: &VerifiedFileAudit) -> Result<u64> {
        if audit.terminal(self)? {
            return Ok(0);
        }
        self.remaining_active_internal_bytes_from_held()
    }
    fn verify_active_native_space(&self) -> Result<()> {
        let root = self.journal.state("worktree")?.ok_or_else(invalid)?;
        let space = sync_extend_platform_fs::held_disk_space(
            self.originals.root_parent().map_err(|_| invalid())?,
            Path::new(&root),
        )?;
        let marker = super::native_capacity::rounded_allocation(
            self.native_owner.marker_bytes_present()?,
            space.allocation_unit,
        )?;
        let payloads = match &self.collections {
            Some(collections) => collections
                .materialized_allocation(space.allocation_unit)
                .map_err(|_| invalid())?,
            None => 0,
        };
        let maximum = self.native_peak.allocation_peak(space.allocation_unit)?;
        let remaining = maximum
            .checked_sub(marker)
            .and_then(|bytes| bytes.checked_sub(payloads))
            .ok_or_else(invalid)?;
        // Caller availability already excludes materialized allocation. Keep the
        // metadata allowance conservative and subtract each actual file once.
        if space.available_to_caller < remaining {
            return Err(invalid());
        }
        Ok(())
    }
    fn verify_held_handle_budget(&self) -> Result<()> {
        let collections = match &self.collections {
            Some(collections) => collections.retained_handle_count().map_err(|_| invalid())?,
            None => 0,
        };
        let count = self
            .originals
            .retained_handle_count()
            .map_err(|_| invalid())?
            .checked_add(collections)
            .and_then(|count| count.checked_add(self.native_owner.retained_handle_count()))
            .and_then(|count| count.checked_add(self.data_owner.retained_handle_count()))
            .and_then(|count| count.checked_add(self.worktree_owner.retained_handle_count()))
            .ok_or_else(invalid)?;
        if count > self.native_handle_limit {
            return Err(invalid());
        }
        Ok(())
    }
    fn verify_process_owners(&self) -> Result<()> {
        let data = self.journal.database_path.parent().ok_or_else(invalid)?;
        let worktree = self.journal.state("worktree")?.ok_or_else(invalid)?;
        self.data_owner.verify(data)?;
        self.worktree_owner
            .verify(&Path::new(&worktree).join(".sync-extend"))?;
        Ok(())
    }

    /// Private intent only. Retains the original CAS coordination and objects.
    /// This method grants no native CREATE, action observation or Final effect.
    pub fn activate(
        &mut self,
        attempt: &sync_extend_core_model::EntryId,
        time: u64,
    ) -> Result<WebDavDurableExecution> {
        let journal = self.journal;
        if self.failed || !journal.connection.is_autocommit() {
            return Err(invalid());
        }
        // Replay may not adopt any externally advanced or changed transcript.
        if let Some(record) = self.execution.records.first() {
            if record.attempt_id != *attempt || record.recorded_at_ms != time {
                return Err(invalid());
            }
        }
        self.verify_process_owners()?;
        self.coordination.verify()?;
        let space: SpaceId = journal.state("space_id")?.ok_or_else(invalid)?.parse()?;
        let id = &self.execution.transaction_id;
        let _dav_read_scope = journal.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&journal.connection, TransactionBehavior::Immediate)?;
        let verified = journal.webdav_native_read_charges.read(&tx)?;
        let descriptions = verified.descriptions(&tx)?;
        let executions = verified.executions(&tx)?;
        let bound = verified
            .manifests(&tx)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        let description = descriptions
            .iter()
            .find(|row| &row.description.request.transaction_id == id)
            .ok_or_else(invalid)?;
        let old = executions
            .iter()
            .find(|row| &row.transaction_id == id)
            .ok_or_else(invalid)?;
        scope(&tx, &space, &description.description.request.origin_device)?;
        let baseline = crate::snapshot_retention::audit_snapshot(
            &tx,
            &space,
            &description.description.request.baseline,
        )?
        .manifest;
        self.originals
            .verify_with_owner(&baseline, &self.native_owner)
            .map_err(|_| invalid())?;
        if self.originals.plan().fingerprint() != &bound.budget.manifest.scope.plan_hash
            || old.cancelled
        {
            return Err(invalid());
        }
        if !old.records.is_empty() {
            if old.records.len() == 1
                && old.records[0].attempt_id == *attempt
                && old.records[0].recorded_at_ms == time
            {
                let old = old.clone();
                tx.commit()?;
                self.execution = old.clone();
                return Ok(old);
            }
            return Err(invalid());
        }
        if time < old.admitted_at_ms {
            return Err(invalid());
        }
        let record = sync_extend_core_model::webdav_native_execution::WebDavExecutionRecord {
            scope: sync_extend_core_model::webdav_native_execution::WebDavExecutionScope {
                format_version: sync_extend_core_model::FORMAT_VERSION,
                transaction_id: id.clone(),
                request_hash: old.request_hash.clone(),
                plan_hash: old.plan_hash.clone(),
                description_hash: old.description_hash.clone(),
            },
            record_index: 0,
            action_index: 0,
            attempt_id: attempt.clone(),
            previous_hash: old.description_hash.clone(),
            recorded_at_ms: time,
            phase: sync_extend_core_model::webdav_native_execution::WebDavExecutionPhase::Activated,
        };
        execution::build(
            &tx,
            description,
            old.limits,
            old.admitted_at_ms,
            vec![record.clone()],
        )?;
        let json = encode_history_record(&record, old.limits.max_record_bytes)?;
        let fingerprint = ContentId::hash(&json);
        let limits = journal.writer_capacity_limits(journal.max_storage_entries)?;
        let before = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        super::advance_clock(&tx, time)?;
        journal.webdav_native_execution_record_issue.issue(
            fingerprint.to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.webdav_native_execution_records VALUES(?1,0,?2,?3,?4)",
                    params![
                        id.as_str(),
                        fingerprint.as_str(),
                        crate::sql_integer(time)?,
                        std::str::from_utf8(&json).map_err(|_| invalid())?
                    ],
                )?;
                Ok(())
            },
        )?;
        let after = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        execution::exact_insert(
            &before,
            &after,
            "webdav_native_execution_records",
            vec![id.to_string(), "0".into()],
            vec![
                crate::JournalStorageColumnValue::Text(id.to_string()),
                crate::JournalStorageColumnValue::Integer(0),
                crate::JournalStorageColumnValue::Text(fingerprint.to_string()),
                crate::JournalStorageColumnValue::Integer(time),
                crate::JournalStorageColumnValue::Text(
                    std::str::from_utf8(&json)
                        .map_err(|_| invalid())?
                        .to_owned(),
                ),
            ],
            time,
        )?;
        self.originals
            .verify_with_owner(&baseline, &self.native_owner)
            .map_err(|_| invalid())?;
        self.verify_process_owners()?;
        self.coordination.verify()?;
        let accepted_read = journal.webdav_native_read_charges.read(&tx)?;
        let accepted = accepted_read
            .executions(&tx)?
            .iter()
            .find(|row| &row.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        super::checkpoint("webdav_held_activation_before_commit");
        tx.commit()?;
        super::checkpoint("webdav_held_activation_after_commit");
        self.execution = accepted.clone();
        Ok(accepted)
    }
}

impl LiveDavAdmission<'_> {
    fn baseline(&self) -> Result<sync_extend_core_model::Manifest> {
        let space: SpaceId = self
            .journal
            .state("space_id")?
            .ok_or_else(invalid)?
            .parse()?;
        Ok(crate::snapshot_retention::audit_snapshot(
            &self.journal.connection,
            &space,
            &self
                .originals
                .description(&self.execution_request()?, self.execution_limits()?)
                .map_err(|_| invalid())?
                .request
                .baseline,
        )?
        .manifest)
    }

    fn execution_request(&self) -> Result<WebDavMutationRequest> {
        let audit = self
            .journal
            .webdav_native_read_charges
            .read(&self.journal.connection)?;
        Ok(audit
            .descriptions(&self.journal.connection)?
            .iter()
            .find(|row| row.description.request.transaction_id == self.execution.transaction_id)
            .cloned()
            .ok_or_else(invalid)?
            .description
            .request)
    }
    fn execution_limits(&self) -> Result<WebDavNativeLimits> {
        let audit = self
            .journal
            .webdav_native_read_charges
            .read(&self.journal.connection)?;
        Ok(audit
            .descriptions(&self.journal.connection)?
            .iter()
            .find(|row| row.description.request.transaction_id == self.execution.transaction_id)
            .cloned()
            .ok_or_else(invalid)?
            .description
            .limits)
    }

    /// Append only locally derived intent or a real held CREATE proof.
    fn receipt(
        &mut self,
        stage: receipt_protocol::ReceiptStage,
        evidence: receipt_protocol::ReceiptEvidence,
        time: u64,
    ) -> Result<()> {
        self.receipt_transaction(stage, evidence, time, None)
    }
    fn receipt_transaction(
        &mut self,
        stage: receipt_protocol::ReceiptStage,
        evidence: receipt_protocol::ReceiptEvidence,
        time: u64,
        final_history: Option<&super::future_history::FutureHistory>,
    ) -> Result<()> {
        if self.failed || !self.journal.connection.is_autocommit() {
            return Err(invalid());
        }
        let journal = self.journal;
        self.verify_process_owners()?;
        self.coordination.verify()?;
        let _dav_read_scope = journal.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&journal.connection, TransactionBehavior::Immediate)?;
        let verified = journal.webdav_native_read_charges.read(&tx)?;
        let bound = verified
            .manifests(&tx)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        let index = bound.receipts.len();
        let template = bound.templates.get(index).ok_or_else(invalid)?;
        let internal_cleanup = matches!(
            stage,
            receipt_protocol::ReceiptStage::OwnerMarkerRemovalRequested
                | receipt_protocol::ReceiptStage::OwnerMarkerAbsent
                | receipt_protocol::ReceiptStage::OwnerRemovalRequested
                | receipt_protocol::ReceiptStage::OwnerAbsent
                | receipt_protocol::ReceiptStage::ReferenceHandoffRequested
                | receipt_protocol::ReceiptStage::ReferencesHandedOff
                | receipt_protocol::ReceiptStage::StagingRemovalRequested
                | receipt_protocol::ReceiptStage::StagingAbsent
                | receipt_protocol::ReceiptStage::Terminal
        );
        if template.stage != stage
            || !(self.execution.unresolved_activation
                || (internal_cleanup
                    && self.execution.records.len() == self.originals.plan().steps().len() * 2))
        {
            return Err(invalid());
        }
        let json = encode_history_record(template, bound.budget.manifest.limits.max_manifest_json)?;
        let previous = match bound.receipts.last() {
            Some(record) => ContentId::hash(&encode_history_record(
                record,
                bound.templates[record.template_index].max_receipt_json_bytes,
            )?),
            None => self.manifest_hash.clone(),
        };
        let evidence_hash = ContentId::hash(&encode_history_record(
            &evidence,
            template.max_receipt_json_bytes,
        )?);
        let record = receipt_protocol::ReceiptDescription {
            scope: bound.budget.manifest.scope.clone(),
            index,
            template_index: index,
            template_hash: ContentId::hash(&json),
            predecessor_hash: previous,
            generation: sync_extend_core_model::EntryId::random()?,
            recorded_at_ms: time,
            stage,
            evidence_hash,
            evidence,
        };
        let mut prefix = bound.receipts.clone();
        prefix.push(record.clone());
        receipt_protocol::audit_prefix(
            self.originals.plan(),
            &bound.templates,
            &prefix,
            &self.manifest_hash,
            bound.budget.manifest.admitted_at_ms,
            bound
                .templates
                .iter()
                .try_fold(0, |sum, template| add(sum, template.max_receipt_json_bytes))?,
        )?;
        let space: SpaceId = journal.state("space_id")?.ok_or_else(invalid)?.parse()?;
        let limits = journal.writer_capacity_limits(journal.max_storage_entries)?;
        let before = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        self.verify_held_namespace()?;
        let json = encode_history_record(&record, template.max_receipt_json_bytes)?;
        let fingerprint = ContentId::hash(&json);
        super::advance_clock(&tx, time)?;
        journal.webdav_native_execution_receipt_issue.issue(
            fingerprint.to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.webdav_native_execution_receipts VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        self.execution.transaction_id.as_str(),
                        crate::sql_integer(index as u64)?,
                        crate::sql_integer(index as u64)?,
                        fingerprint.as_str(),
                        crate::sql_integer(time)?,
                        std::str::from_utf8(&json).map_err(|_| invalid())?
                    ],
                )?;
                Ok(())
            },
        )?;
        if let Some(history) = final_history {
            let receipt_protocol::ReceiptEvidence::History { history_hash, .. } = &record.evidence
            else {
                return Err(invalid());
            };
            if !matches!(stage, receipt_protocol::ReceiptStage::HistoryCommitted(_))
                || history_hash != &history.fingerprint
                || *history != bound.budget.manifest.history
            {
                return Err(invalid());
            }
            super::final_history::apply(&tx, &journal.webdav_original_final_row_issue, history)?;
        }
        let after = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        if let Some(history) = final_history {
            super::final_history::verify_transition(
                &before,
                &after,
                history,
                &record,
                &fingerprint,
                std::str::from_utf8(&json).map_err(|_| invalid())?,
            )?;
        } else {
            execution::exact_insert(
                &before,
                &after,
                "webdav_native_execution_receipts",
                vec![self.execution.transaction_id.to_string(), index.to_string()],
                vec![
                    crate::JournalStorageColumnValue::Text(
                        self.execution.transaction_id.to_string(),
                    ),
                    crate::JournalStorageColumnValue::Integer(index as u64),
                    crate::JournalStorageColumnValue::Integer(index as u64),
                    crate::JournalStorageColumnValue::Text(fingerprint.to_string()),
                    crate::JournalStorageColumnValue::Integer(time),
                    crate::JournalStorageColumnValue::Text(
                        std::str::from_utf8(&json).map_err(|_| invalid())?.into(),
                    ),
                ],
                time,
            )?;
        }
        self.verify_held_namespace()?;
        self.verify_native_space()?;
        self.coordination.verify()?;
        super::checkpoint("webdav_owner_receipt_before_commit");
        super::checkpoint(&format!("webdav_owner_receipt_{index}_before_commit"));
        tx.commit()?;
        super::checkpoint("webdav_owner_receipt_after_commit");
        super::checkpoint(&format!("webdav_owner_receipt_{index}_after_commit"));
        Ok(())
    }

    /// Once any effect is attempted, failure leaves its exact requested prefix.
    /// The same live object cannot silently retry CREATE or adopt a pathname.
    pub fn create_initial_owner(&mut self, now: impl Fn() -> Result<u64>) -> Result<()> {
        self.create_initial_owner_with_policy(now, |_| Ok(()))
    }

    /// Inspect only a borrowed original owner; returning Ok grants no provenance.
    pub fn create_initial_owner_with_policy(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.create_initial_owner_inner(now, inspect);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn create_initial_owner_inner(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        use receipt_protocol::ReceiptStage as S;
        self.verify_process_owners()?;
        let verified = self
            .journal
            .webdav_native_read_charges
            .read(&self.journal.connection)?;
        let bound = verified
            .manifests(&self.journal.connection)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        if bound.receipts.len() == 10 {
            return self
                .originals
                .verify_with_owner(&self.baseline()?, &self.native_owner)
                .map_err(|_| invalid());
        }
        if !bound.receipts.is_empty() || self.execution.records.len() != 1 {
            return Err(invalid());
        }
        let evidence = self
            .native_owner
            .staging_intent(self.originals.root_parent().map_err(|_| invalid())?)?;
        self.verify_native_space()?;
        self.receipt(S::StagingCreationRequested, evidence, now()?)?;
        super::checkpoint("webdav_staging_requested");
        self.collection_policy(&inspect)?;
        let evidence = self
            .native_owner
            .create_staging(self.originals.root_parent().map_err(|_| invalid())?)?;
        super::checkpoint("webdav_staging_created");
        self.collection_policy(&inspect)?;
        self.receipt(S::StagingCreated, evidence, now()?)?;
        let evidence = self.native_owner.owner_intent()?;
        self.receipt(S::OwnerActivated, evidence, now()?)?;
        super::checkpoint("webdav_owner_requested");
        self.collection_policy(&inspect)?;
        let evidence = self.native_owner.create_owner()?;
        super::checkpoint("webdav_owner_created");
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerCreated, evidence, now()?)?;
        let evidence = self.native_owner.marker_intent()?;
        self.receipt(S::OwnerMarkerCreationRequested, evidence, now()?)?;
        super::checkpoint("webdav_marker_requested");
        self.collection_policy(&inspect)?;
        let evidence = self.native_owner.create_marker()?;
        super::checkpoint("webdav_marker_created");
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerMarkerCreated, evidence, now()?)?;
        let evidence = self.native_owner.write_intent()?;
        self.receipt(S::OwnerMarkerWriteRequested, evidence, now()?)?;
        super::checkpoint("webdav_marker_write_requested");
        self.collection_policy(&inspect)?;
        let evidence = self.native_owner.write_marker()?;
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerMarkerWritten, evidence, now()?)?;
        super::checkpoint("webdav_marker_written");
        let evidence = self.native_owner.close_intent()?;
        self.receipt(S::OwnerMarkerCloseRequested, evidence, now()?)?;
        super::checkpoint("webdav_marker_close_requested");
        self.collection_policy(&inspect)?;
        let evidence = self.native_owner.seal_marker()?;
        super::checkpoint("webdav_marker_closed");
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerMarkerClosed, evidence, now()?)?;
        self.verify_held_namespace()?;
        Ok(())
    }
}

impl LiveDavAdmission<'_> {
    /// Only the internal actual native action loop calls this after deriving its
    /// observation from original held results. No public observation parameter.
    fn append_collection_record(
        &mut self,
        phase: sync_extend_core_model::webdav_native_execution::WebDavExecutionPhase,
        time: u64,
    ) -> Result<()> {
        use sync_extend_core_model::webdav_native_execution::{
            WebDavExecutionPhase, WebDavExecutionRecord,
        };
        if self.failed || self.collections.is_none() || !self.journal.connection.is_autocommit() {
            return Err(invalid());
        }
        let journal = self.journal;
        self.verify_file_view()?;
        let _dav_read_scope = journal.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&journal.connection, TransactionBehavior::Immediate)?;
        let verified = journal.webdav_native_read_charges.read(&tx)?;
        let description = verified
            .descriptions(&tx)?
            .iter()
            .find(|row| row.description.request.transaction_id == self.execution.transaction_id)
            .ok_or_else(invalid)?;
        let current = verified
            .executions(&tx)?
            .iter()
            .find(|row| row.transaction_id == self.execution.transaction_id)
            .ok_or_else(invalid)?;
        if current.records != self.execution.records {
            return Err(invalid());
        }
        let last = current.records.last().ok_or_else(invalid)?;
        let index = current.records.len();
        let action = index / 2;
        let attempt = match &phase {
            WebDavExecutionPhase::Activated if index % 2 == 0 => {
                sync_extend_core_model::EntryId::random()?
            }
            WebDavExecutionPhase::Observed {
                activation_hash, ..
            } if index % 2 == 1
                && *activation_hash
                    == ContentId::hash(&encode_history_record(
                        last,
                        current.limits.max_record_bytes,
                    )?) =>
            {
                last.attempt_id.clone()
            }
            _ => return Err(invalid()),
        };
        let record = WebDavExecutionRecord {
            scope: last.scope.clone(),
            record_index: index,
            action_index: action,
            attempt_id: attempt,
            previous_hash: ContentId::hash(&encode_history_record(
                last,
                current.limits.max_record_bytes,
            )?),
            recorded_at_ms: time,
            phase,
        };
        let mut records = current.records.clone();
        records.push(record.clone());
        execution::build(
            &tx,
            description,
            current.limits,
            current.admitted_at_ms,
            records,
        )?;
        let post_write = journal.webdav_native_read_charges.read(&tx)?;
        let bound = post_write
            .manifests(&tx)?
            .iter()
            .find(|bound| bound.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        let space: SpaceId = journal.state("space_id")?.ok_or_else(invalid)?.parse()?;
        let limits = journal.writer_capacity_limits(journal.max_storage_entries)?;
        let before = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        if bound.budget.manifest.scope.transaction_id != record.scope.transaction_id {
            return Err(invalid());
        }
        self.verify_held_namespace()?;
        let json = encode_history_record(&record, current.limits.max_record_bytes)?;
        let fingerprint = ContentId::hash(&json);
        super::advance_clock(&tx, time)?;
        journal.webdav_native_execution_record_issue.issue(
            fingerprint.to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.webdav_native_execution_records VALUES(?1,?2,?3,?4,?5)",
                    params![
                        record.scope.transaction_id.as_str(),
                        crate::sql_integer(index as u64)?,
                        fingerprint.as_str(),
                        crate::sql_integer(time)?,
                        std::str::from_utf8(&json).map_err(|_| invalid())?
                    ],
                )?;
                Ok(())
            },
        )?;
        let after = journal.read_view().audit_original_provenance_capacity(
            &space,
            crate::limits::MAX_ENTRIES,
            limits,
        )?;
        execution::exact_insert(
            &before,
            &after,
            "webdav_native_execution_records",
            vec![record.scope.transaction_id.to_string(), index.to_string()],
            vec![
                crate::JournalStorageColumnValue::Text(record.scope.transaction_id.to_string()),
                crate::JournalStorageColumnValue::Integer(index as u64),
                crate::JournalStorageColumnValue::Text(fingerprint.to_string()),
                crate::JournalStorageColumnValue::Integer(time),
                crate::JournalStorageColumnValue::Text(
                    std::str::from_utf8(&json)
                        .map_err(|_| invalid())?
                        .to_owned(),
                ),
            ],
            time,
        )?;
        self.verify_held_namespace()?;
        self.verify_process_owners()?;
        self.coordination.verify()?;
        self.verify_native_space()?;
        let accepted_read = journal.webdav_native_read_charges.read(&tx)?;
        let accepted = accepted_read
            .executions(&tx)?
            .iter()
            .find(|row| row.transaction_id == self.execution.transaction_id)
            .cloned()
            .ok_or_else(invalid)?;
        super::checkpoint(&format!("webdav_action_record_{index}_before_commit"));
        tx.commit()?;
        super::checkpoint(&format!("webdav_action_record_{index}_after_commit"));
        self.execution = accepted;
        Ok(())
    }
}

impl LiveDavAdmission<'_> {
    /// Native actions retain the original objects; this stops before causal Final.
    /// No receipt/identity/observation can be supplied by the caller.
    pub fn execute_collection_actions_with_policy(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.execute_collection_actions_inner(now, inspect);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Read-only attribution from an actual internal native action error.
    /// Admission/SQL/policy/Final failures do not invent per-path failures.
    pub fn failed_native_path(&self) -> Option<&sync_extend_core_model::PortablePath> {
        self.failed_native_path.as_ref()
    }
    pub fn failed_native_status(
        &self,
    ) -> Option<sync_extend_core_model::webdav_partial_response::WebDavCollectionFailure> {
        self.failed_native_status
    }
    fn native_result<T>(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        result: std::result::Result<T, Box<dyn std::error::Error>>,
    ) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                use sync_extend_core_model::webdav_partial_response::WebDavCollectionFailure as F;
                let failure = error
                    .downcast_ref::<std::io::Error>()
                    .map(|error| match error.raw_os_error() {
                        Some(5) => F::Forbidden,
                        Some(2 | 3) => F::NotFound,
                        Some(32 | 33) => F::Locked,
                        Some(39 | 112) => F::InsufficientStorage,
                        Some(80 | 183) => F::Conflict,
                        _ => F::InternalError,
                    })
                    .unwrap_or(F::Conflict);
                self.failed_native_path = Some(path.clone());
                self.failed_native_status = Some(failure);
                Err(invalid())
            }
        }
    }
    fn collection_policy(
        &self,
        inspect: &impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        let view = self.inventory_file_view()?;
        view.verify()?;
        inspect(&view)?;
        view.verify()?;
        Ok(())
    }

    fn collection_receipt(
        &mut self,
        stage: receipt_protocol::ReceiptStage,
        object: super::ordered_receipts::ActionObject,
        time: u64,
    ) -> Result<()> {
        self.receipt(
            stage,
            receipt_protocol::ReceiptEvidence::CollectionObject { object },
            time,
        )
    }

    fn verify_durable_collection_projection(&self) -> Result<()> {
        let audit = self.immutable_file_read_audit()?;
        let bound = audit
            .snapshot
            .manifests(&self.journal.connection)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        let baseline = self.baseline()?;
        let projection = bound
            .projection
            .get(&baseline, self.originals.plan(), &bound.receipts)
            .map_err(|_| invalid())?;
        self.collections
            .as_ref()
            .ok_or_else(invalid)?
            .verify_projection(&baseline, self.originals.plan(), projection)
            .map_err(|_| invalid())
    }
    fn actual_collection_parent(
        &self,
        entry: &sync_extend_core_model::Entry,
    ) -> Result<super::collection_kernel::Parent<'_>> {
        let path = entry.path.parent();
        if let Some(held) = self
            .originals
            .collection_existing_parent(path.as_ref())
            .map_err(|_| invalid())?
        {
            return Ok(super::collection_kernel::Parent::Existing(held));
        }
        self.collections
            .as_ref()
            .ok_or_else(invalid)?
            .parent(&path.ok_or_else(invalid)?)
            .map_err(|_| invalid())
    }

    fn execute_collection_actions_inner(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        use receipt_protocol::ReceiptStage as S;
        use sync_extend_core_model::webdav_native::WebDavNativeAction as A;
        use sync_extend_core_model::webdav_native_execution::{
            WebDavExecutionObservation as O, WebDavExecutionPhase as P,
        };
        if self.collections.is_none() {
            self.verify_file_view()?;
            let audit = self.immutable_file_read_audit()?;
            let bound = audit
                .snapshot
                .manifests(&self.journal.connection)?
                .iter()
                .find(|row| row.budget.manifest_hash == self.manifest_hash)
                .ok_or_else(invalid)?;
            if bound.receipts.len() != 10
                || self.execution.records.len() != 1
                || bound.receipts[9].stage != S::OwnerMarkerClosed
            {
                return Err(invalid());
            }
            let collections = self
                .originals
                .take_collection_originals()
                .map_err(|_| invalid())?;
            self.collections = Some(collections);
            self.verify_file_view()?;
        }
        loop {
            let action = self.execution.records.len() / 2;
            let step = self
                .originals
                .plan()
                .steps()
                .get(action)
                .ok_or_else(invalid)?
                .clone();
            if matches!(&step.action, A::CommitHistory { .. }) {
                if self.execution.unresolved_activation {
                    return Err(invalid());
                }
                return self.collection_policy(&inspect);
            }
            if !matches!(
                &step.action,
                A::QuarantineOriginal { .. } | A::CreateDirectory { .. } | A::PublishFile { .. }
            ) {
                return Err(invalid());
            }
            if self.execution.records.len().is_multiple_of(2) {
                self.append_collection_record(P::Activated, now()?)?;
            } else if action != 0 || self.execution.records.len() != 1 {
                // Mid-effect retry never adopts a path or repeats a native action.
                return Err(invalid());
            }
            self.collection_policy(&inspect)?;
            let root = self.journal.state("worktree")?.ok_or_else(invalid)?;
            let root = std::path::PathBuf::from(root);
            let owner_path = root
                .join(".sync-tmp")
                .join(format!("dav-{}.owner", self.execution.transaction_id));
            let observation = match step.action {
                A::QuarantineOriginal {
                    entry,
                    identity,
                    owner_component,
                } => {
                    let parent = self
                        .actual_collection_parent(&entry)?
                        .key()
                        .map_err(|_| invalid())?;
                    let owner = self
                        .native_owner
                        .owner
                        .as_ref()
                        .ok_or_else(invalid)?
                        .key()?;
                    let object = super::ordered_receipts::ActionObject {
                        action,
                        entry_id: entry.entry_id.clone(),
                        path: entry.path.clone(),
                        source_parent:
                            sync_extend_core_model::tree_restore_identity::TreeNativeIdentity {
                                volume_serial: parent.volume,
                                file_id: format!("{:032x}", parent.id),
                            },
                        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity {
                            volume_serial: owner.volume,
                            file_id: format!("{:032x}", owner.id),
                        },
                        original: Some(identity.clone()),
                        component: owner_component.clone(),
                        content_hash: entry
                            .content
                            .as_ref()
                            .map(|content| content.content_id.clone()),
                        length: entry.content.as_ref().map_or(0, |content| content.length),
                    };
                    self.collection_receipt(S::QuarantineRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_quarantine_requested"));
                    self.collection_policy(&inspect)?;
                    let result = self.collections.as_mut().ok_or_else(invalid)?.quarantine(
                        &root,
                        self.native_owner.owner.as_ref().ok_or_else(invalid)?,
                        &owner_path,
                        &owner_component,
                        parent,
                        action,
                        &entry,
                    );
                    let object = self.native_result(&entry.path, result)?;
                    self.collection_policy(&inspect)?;
                    self.collection_receipt(S::QuarantineMoved(action), object, now()?)?;
                    O::QuarantinedOriginal { identity }
                }
                A::CreateDirectory { entry } => {
                    let object = super::collection_kernel::CreatedDirectory::intent(
                        &self.actual_collection_parent(&entry)?,
                        action,
                        &entry,
                    )
                    .map_err(|_| invalid())?;
                    self.collection_receipt(S::DirectoryCreationRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_directory_requested"));
                    self.collection_policy(&inspect)?;
                    let path = entry.path.parent();
                    let parent = self
                        .originals
                        .collection_existing_parent(path.as_ref())
                        .map_err(|_| invalid())?;
                    let result = self
                        .collections
                        .as_mut()
                        .ok_or_else(invalid)?
                        .create_directory(parent, &root, action, &entry);
                    let object = self.native_result(&entry.path, result)?;
                    let identity = object.original.clone().ok_or_else(invalid)?;
                    super::checkpoint(&format!("webdav_action_{action}_directory_created"));
                    self.collection_policy(&inspect)?;
                    self.collection_receipt(S::DirectoryCreated(action), object, now()?)?;
                    O::CreatedDirectory { identity }
                }
                A::PublishFile { entry } => {
                    let object = super::collection_kernel::CreatedFile::intent(
                        self.native_owner.owner.as_ref().ok_or_else(invalid)?,
                        &self.execution.transaction_id,
                        action,
                        &entry,
                    )
                    .map_err(|_| invalid())?;
                    self.collection_receipt(S::FileCreationRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_file_requested"));
                    self.collection_policy(&inspect)?;
                    let result = self.collections.as_mut().ok_or_else(invalid)?.create_file(
                        self.native_owner.owner.as_ref().ok_or_else(invalid)?,
                        &owner_path,
                        &self.execution.transaction_id,
                        action,
                        &entry,
                    );
                    let object = self.native_result(&entry.path, result)?;
                    super::checkpoint(&format!("webdav_action_{action}_file_created"));
                    self.collection_policy(&inspect)?;
                    self.collection_receipt(S::FileCreated(action), object, now()?)?;
                    let object = self
                        .collections
                        .as_ref()
                        .ok_or_else(invalid)?
                        .file(action)
                        .map_err(|_| invalid())?
                        .evidence(true)
                        .map_err(|_| invalid())?;
                    self.collection_receipt(S::FileWriteRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_write_requested"));
                    self.collection_policy(&inspect)?;
                    let chunks = self
                        .originals
                        .collection_cas_chunks()
                        .map_err(|_| invalid())?;
                    let result = self
                        .collections
                        .as_mut()
                        .ok_or_else(invalid)?
                        .file_mut(action)
                        .map_err(|_| invalid())?
                        .materialize(&chunks);
                    let object = self.native_result(&entry.path, result)?;
                    self.collection_policy(&inspect)?;
                    self.collection_receipt(S::FileWritten(action), object, now()?)?;
                    let object = self
                        .collections
                        .as_ref()
                        .ok_or_else(invalid)?
                        .file(action)
                        .map_err(|_| invalid())?
                        .evidence(false)
                        .map_err(|_| invalid())?;
                    self.collection_receipt(S::FileCloseRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_close_requested"));
                    self.collection_policy(&inspect)?;
                    let result = self
                        .collections
                        .as_mut()
                        .ok_or_else(invalid)?
                        .file_mut(action)
                        .map_err(|_| invalid())?
                        .seal();
                    let object = self.native_result(&entry.path, result)?;
                    super::checkpoint(&format!("webdav_action_{action}_file_closed"));
                    self.collection_policy(&inspect)?;
                    self.collection_receipt(S::FileClosed(action), object, now()?)?;
                    let parent = self
                        .actual_collection_parent(&entry)?
                        .key()
                        .map_err(|_| invalid())?;
                    let mut object = self
                        .collections
                        .as_ref()
                        .ok_or_else(invalid)?
                        .file(action)
                        .map_err(|_| invalid())?
                        .evidence(false)
                        .map_err(|_| invalid())?;
                    object.parent =
                        sync_extend_core_model::tree_restore_identity::TreeNativeIdentity {
                            volume_serial: parent.volume,
                            file_id: format!("{:032x}", parent.id),
                        };
                    object.component = entry
                        .path
                        .as_str()
                        .rsplit('/')
                        .next()
                        .ok_or_else(invalid)?
                        .into();
                    self.collection_receipt(S::FilePublicationRequested(action), object, now()?)?;
                    super::checkpoint(&format!("webdav_action_{action}_publication_requested"));
                    self.collection_policy(&inspect)?;
                    let path = entry.path.parent();
                    let parent = self
                        .originals
                        .collection_existing_parent(path.as_ref())
                        .map_err(|_| invalid())?;
                    let result = self
                        .collections
                        .as_mut()
                        .ok_or_else(invalid)?
                        .publish_file(parent, &root, action);
                    let object = self.native_result(&entry.path, result)?;
                    self.collection_policy(&inspect)?;
                    let identity = object.original.clone().ok_or_else(invalid)?;
                    self.collection_receipt(S::FilePublished(action), object, now()?)?;
                    let content = entry.content.ok_or_else(invalid)?;
                    O::PublishedFile {
                        identity,
                        content_id: content.content_id,
                        length: content.length,
                    }
                }
                _ => return Err(invalid()),
            };
            let last = self.execution.records.last().ok_or_else(invalid)?;
            let activation_hash = ContentId::hash(&encode_history_record(
                last,
                self.execution.limits.max_record_bytes,
            )?);
            self.append_collection_record(
                P::Observed {
                    activation_hash,
                    observation,
                },
                now()?,
            )?;
            self.verify_durable_collection_projection()?;
            self.collection_policy(&inspect)?;
        }
    }
}

impl LiveDavAdmission<'_> {
    /// Commit original operation bytes, final snapshot and native result atomically.
    /// The caller supplies a clock only; never a manifest, operation or native proof.
    pub fn commit_collection_final_with_policy(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.commit_collection_final_inner(now, inspect);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn commit_collection_final_inner(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        use receipt_protocol::{ReceiptEvidence as E, ReceiptStage as S};
        use sync_extend_core_model::webdav_native::WebDavNativeAction as A;
        use sync_extend_core_model::webdav_native_execution::{
            WebDavExecutionObservation as O, WebDavExecutionPhase as P,
        };
        self.collection_policy(&inspect)?;
        if self.collections.is_none() || self.execution.unresolved_activation {
            return Err(invalid());
        }
        let action = self.execution.records.len() / 2;
        let step = self
            .originals
            .plan()
            .steps()
            .get(action)
            .ok_or_else(invalid)?
            .clone();
        let A::CommitHistory {
            final_snapshot,
            operation_count,
        } = step.action
        else {
            return Err(invalid());
        };
        let audit = self.immutable_file_read_audit()?;
        let bound = audit
            .snapshot
            .manifests(&self.journal.connection)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        let baseline = self.baseline()?;
        let projection = bound
            .projection
            .get(&baseline, self.originals.plan(), &bound.receipts)
            .map_err(|_| invalid())?;
        let actual: std::collections::BTreeMap<_, _> = projection
            .user
            .iter()
            .map(|(path, object)| (path.clone(), object.entry.clone()))
            .collect();
        let expected: std::collections::BTreeMap<_, _> = self
            .originals
            .plan()
            .final_manifest()
            .entries
            .values()
            .map(|entry| (entry.path.clone(), entry.clone()))
            .collect();
        if actual != expected
            || operation_count != self.originals.plan().operations().len()
            || final_snapshot != self.originals.plan().final_manifest().root()?
        {
            return Err(invalid());
        }
        self.verify_durable_collection_projection()?;
        let history = bound.budget.manifest.history.clone();
        self.append_collection_record(P::Activated, now()?)?;
        let evidence = E::History {
            action,
            final_snapshot: final_snapshot.clone(),
            operation_count,
            history_hash: history.fingerprint.clone(),
        };
        self.receipt(S::HistoryCommitRequested(action), evidence.clone(), now()?)?;
        super::checkpoint(&format!("webdav_action_{action}_final_requested"));
        self.collection_policy(&inspect)?;
        // Snapshot creation time is fixed by the original admitted full row plan.
        // No operation timestamp or immutable row is rewritten at commit.
        self.receipt_transaction(
            S::HistoryCommitted(action),
            evidence,
            now()?,
            Some(&history),
        )?;
        super::checkpoint(&format!("webdav_action_{action}_final_committed"));
        self.collection_policy(&inspect)?;
        let activation = self.execution.records.last().ok_or_else(invalid)?;
        let activation_hash = ContentId::hash(&encode_history_record(
            activation,
            self.execution.limits.max_record_bytes,
        )?);
        self.append_collection_record(
            P::Observed {
                activation_hash,
                observation: O::HistoryCommitted {
                    final_snapshot,
                    operation_count,
                },
            },
            now()?,
        )?;
        self.collection_policy(&inspect)
    }
}

impl LiveDavAdmission<'_> {
    /// Dispose the exact quarantined originals after the original causal Final.
    /// Internal owner and reference handoff remain held for the following stage.
    pub fn dispose_collection_originals_with_policy(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.dispose_collection_originals_inner(now, inspect);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn dispose_collection_originals_inner(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        use receipt_protocol::ReceiptStage as S;
        use sync_extend_core_model::webdav_native::WebDavNativeAction as A;
        use sync_extend_core_model::webdav_native_execution::{
            WebDavExecutionObservation as O, WebDavExecutionPhase as P,
        };
        self.collection_policy(&inspect)?;
        if self.collections.is_none() || self.execution.unresolved_activation {
            return Err(invalid());
        }
        let audit = self.immutable_file_read_audit()?;
        let bound = audit
            .snapshot
            .manifests(&self.journal.connection)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        if !bound
            .receipts
            .iter()
            .any(|record| matches!(record.stage, S::HistoryCommitted(_)))
        {
            return Err(invalid());
        }
        while self.execution.records.len() / 2 < self.originals.plan().steps().len() {
            let action = self.execution.records.len() / 2;
            let step = self
                .originals
                .plan()
                .steps()
                .get(action)
                .ok_or_else(invalid)?
                .clone();
            let A::CleanupOriginal {
                quarantine_action, ..
            } = step.action
            else {
                return Err(invalid());
            };
            self.append_collection_record(P::Activated, now()?)?;
            let owner = self
                .native_owner
                .owner
                .as_ref()
                .ok_or_else(invalid)?
                .key()?;
            let evidence = self
                .collections
                .as_ref()
                .ok_or_else(invalid)?
                .disposal_intent(action, quarantine_action, owner)
                .map_err(|_| invalid())?;
            let receipt_protocol::ReceiptEvidence::Disposal { original, .. } = &evidence else {
                return Err(invalid());
            };
            let original = original.clone();
            self.receipt(S::DisposalRequested(action), evidence.clone(), now()?)?;
            super::checkpoint(&format!("webdav_action_{action}_disposal_requested"));
            self.collection_policy(&inspect)?;
            self.collections
                .as_mut()
                .ok_or_else(invalid)?
                .dispose_original(action, quarantine_action)
                .map_err(|_| invalid())?;
            self.collection_policy(&inspect)?;
            self.receipt(S::OriginalAbsent(action), evidence.clone(), now()?)?;
            self.receipt(S::OwnerSlotCleared(action), evidence, now()?)?;
            let activation = self.execution.records.last().ok_or_else(invalid)?;
            let activation_hash = ContentId::hash(&encode_history_record(
                activation,
                self.execution.limits.max_record_bytes,
            )?);
            self.append_collection_record(
                P::Observed {
                    activation_hash,
                    observation: O::OriginalAbsent {
                        quarantine_action,
                        original,
                    },
                },
                now()?,
            )?;
            self.collection_policy(&inspect)?;
        }
        self.verify_durable_collection_projection()?;
        self.collections
            .as_mut()
            .ok_or_else(invalid)?
            .release_published_owner_parents()
            .map_err(|_| invalid())?;
        self.collection_policy(&inspect)
    }
}

impl LiveDavAdmission<'_> {
    /// Keep every original user object and CAS guard until cleanup is fully durable.
    /// Caller clocks/policy can refuse, never manufacture native absence.
    pub fn finish_collection_cleanup_with_policy(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.finish_collection_cleanup_inner(now, inspect);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn finish_collection_cleanup_inner(
        &mut self,
        now: impl Fn() -> Result<u64>,
        inspect: impl Fn(&WebDavInventoryFileView<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        use receipt_protocol::ReceiptStage as S;
        self.collection_policy(&inspect)?;
        if self.execution.unresolved_activation
            || self.execution.records.len() != self.originals.plan().steps().len() * 2
        {
            return Err(invalid());
        }
        let audit = self.immutable_file_read_audit()?;
        let bound = audit
            .snapshot
            .manifests(&self.journal.connection)?
            .iter()
            .find(|row| row.budget.manifest_hash == self.manifest_hash)
            .ok_or_else(invalid)?;
        if bound
            .templates
            .get(bound.receipts.len())
            .ok_or_else(invalid)?
            .stage
            != S::OwnerMarkerRemovalRequested
        {
            return Err(invalid());
        }
        let final_record = bound
            .receipts
            .iter()
            .find(|record| matches!(record.stage, S::HistoryCommitted(_)))
            .ok_or_else(invalid)?;
        let receipt_protocol::ReceiptEvidence::History {
            final_snapshot,
            history_hash,
            ..
        } = &final_record.evidence
        else {
            return Err(invalid());
        };
        let references = super::reference_handoff::evidence(
            &self.journal.connection,
            &self.execution.transaction_id,
            final_snapshot,
            history_hash,
        )?;
        self.verify_durable_collection_projection()?;
        self.collections
            .as_mut()
            .ok_or_else(invalid)?
            .release_published_owner_parents()
            .map_err(|_| invalid())?;
        let evidence = self
            .native_owner
            .marker_removal_intent(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.receipt(S::OwnerMarkerRemovalRequested, evidence.clone(), now()?)?;
        super::checkpoint("webdav_cleanup_marker_requested");
        self.collection_policy(&inspect)?;
        self.native_owner
            .remove_marker(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerMarkerAbsent, evidence, now()?)?;
        let evidence = self
            .native_owner
            .owner_removal_intent(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.receipt(S::OwnerRemovalRequested, evidence.clone(), now()?)?;
        super::checkpoint("webdav_cleanup_owner_requested");
        self.collection_policy(&inspect)?;
        self.native_owner
            .remove_owner(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.collection_policy(&inspect)?;
        self.receipt(S::OwnerAbsent, evidence, now()?)?;
        self.receipt(S::ReferenceHandoffRequested, references.clone(), now()?)?;
        super::checkpoint("webdav_cleanup_reference_handoff_requested");
        self.collection_policy(&inspect)?;
        // All baseline/final immutable snapshot pins and CAS objects remain audited.
        // Existing history retains ownership; no physical CAS deletion is claimed.
        self.receipt(S::ReferencesHandedOff, references.clone(), now()?)?;
        super::checkpoint("webdav_cleanup_references_handed_off");
        let evidence = self
            .native_owner
            .staging_removal_intent(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.receipt(S::StagingRemovalRequested, evidence.clone(), now()?)?;
        super::checkpoint("webdav_cleanup_staging_requested");
        self.collection_policy(&inspect)?;
        self.native_owner
            .remove_staging(self.collections.as_ref().ok_or_else(invalid)?)?;
        self.collection_policy(&inspect)?;
        self.receipt(S::StagingAbsent, evidence, now()?)?;
        self.collection_policy(&inspect)?;
        self.receipt(S::Terminal, references, now()?)?;
        super::checkpoint("webdav_cleanup_terminal_committed");
        let verified = self
            .journal
            .webdav_native_read_charges
            .read(&self.journal.connection)?;
        self.execution = verified
            .executions(&self.journal.connection)?
            .iter()
            .find(|row| row.transaction_id == self.execution.transaction_id)
            .cloned()
            .ok_or_else(invalid)?;
        self.collection_policy(&inspect)
    }
}

/// Exact owned descriptive data for one immutable policy and inventory phase.
/// Construction performs every full audit; this private value issues no effects.
struct VerifiedFileAudit {
    snapshot: Arc<super::read_phase::VerifiedDavReadSnapshot>,
    description_index: usize,
    execution_index: usize,
    manifest_index: usize,
    baseline: sync_extend_core_model::Manifest,
    live_execution: WebDavDurableExecution,
}

impl VerifiedFileAudit {
    fn read(held: &LiveDavAdmission<'_>) -> Result<Self> {
        let journal = held.journal;
        if held.failed || !journal.connection.is_autocommit() {
            return Err(invalid());
        }
        held.verify_process_owners()?;
        held.verify_held_handle_budget()?;
        held.coordination.verify()?;
        let snapshot = journal
            .webdav_native_read_charges
            .read(&journal.connection)?;
        let descriptions = snapshot.descriptions(&journal.connection)?;
        let executions = snapshot.executions(&journal.connection)?;
        let manifests = snapshot.manifests(&journal.connection)?;
        let description_index = descriptions
            .iter()
            .position(|row| row.description.request.transaction_id == held.execution.transaction_id)
            .ok_or_else(invalid)?;
        let execution_index = executions
            .iter()
            .position(|row| row.transaction_id == held.execution.transaction_id)
            .ok_or_else(invalid)?;
        let manifest_index = manifests
            .iter()
            .position(|row| {
                row.budget.manifest_hash == held.manifest_hash
                    && row.budget.manifest.scope.transaction_id == held.execution.transaction_id
                    && row.budget.manifest.native_peak == held.native_peak
                    && row.budget.manifest.native_handles.admission_limit
                        == held.native_handle_limit as u64
            })
            .ok_or_else(invalid)?;
        let description = &descriptions[description_index];
        if held
            .originals
            .description(
                &description.description.request,
                description.description.limits,
            )
            .map_err(|_| invalid())?
            != description.description
        {
            return Err(invalid());
        }
        let bound = &manifests[manifest_index];
        let baseline = bound
            .projection
            .baseline_for(held.originals.plan(), &bound.receipts)
            .map_err(|_| invalid())?
            .clone();
        let result = Self {
            snapshot,
            description_index,
            execution_index,
            manifest_index,
            baseline,
            live_execution: held.execution.clone(),
        };
        result.verify_binding(held)?;
        Ok(result)
    }

    fn verify_binding(&self, held: &LiveDavAdmission<'_>) -> Result<()> {
        let connection = &held.journal.connection;
        self.snapshot.verify(connection)?;
        if held.failed || !connection.is_autocommit() || self.live_execution != held.execution {
            return Err(invalid());
        }
        let description = &self.snapshot.descriptions(connection)?[self.description_index];
        let execution = &self.snapshot.executions(connection)?[self.execution_index];
        let bound = &self.snapshot.manifests(connection)?[self.manifest_index];
        if description.description.request.transaction_id != held.execution.transaction_id
            || description.plan_hash != *held.originals.plan().fingerprint()
            || description.description.inventory != *held.originals.plan().inventory()
            || execution.transaction_id != held.execution.transaction_id
            || execution.description_hash != held.execution.description_hash
            || execution.request_hash != held.execution.request_hash
            || execution.plan_hash != held.execution.plan_hash
            || execution.limits != held.execution.limits
            || execution.admitted_at_ms != held.execution.admitted_at_ms
            || execution.admission_hash != held.execution.admission_hash
            || execution.records != held.execution.records
            || bound.budget.manifest_hash != held.manifest_hash
            || bound.budget.manifest.native_peak != held.native_peak
            || bound.budget.manifest.native_handles.admission_limit
                != held.native_handle_limit as u64
            || self.baseline.root()? != description.description.request.baseline
        {
            return Err(invalid());
        }
        bound
            .projection
            .get(&self.baseline, held.originals.plan(), &bound.receipts)
            .map_err(|_| invalid())?;
        // Pins remain live SQL observations at every view boundary, even when
        // immutable decoded descriptions, execution and projection are reused.
        let snapshot = crate::snapshot_retention::audit_snapshot(
            connection,
            &self.baseline.space_id,
            &description.description.request.baseline,
        )?;
        if snapshot.manifest != self.baseline {
            return Err(invalid());
        }
        for receipt in &bound.receipts {
            if let receipt_protocol::ReceiptEvidence::History {
                final_snapshot,
                history_hash,
                ..
            } = &receipt.evidence
            {
                super::reference_handoff::audit(
                    connection,
                    &held.execution.transaction_id,
                    &bound.receipts,
                    final_snapshot,
                    history_hash,
                )?;
            }
        }
        self.snapshot.verify(connection)
    }

    fn terminal(&self, held: &LiveDavAdmission<'_>) -> Result<bool> {
        self.verify_binding(held)?;
        Ok(
            self.snapshot.manifests(&held.journal.connection)?[self.manifest_index]
                .receipts
                .last()
                .is_some_and(|receipt| receipt.stage == receipt_protocol::ReceiptStage::Terminal),
        )
    }
}

/// An immutable borrow for one double inventory scan. The complete private
/// descriptive audit is reused only within this view's unchanged SQL phase.
/// No effects, transcript injection, owned handles, cloning or public fields.
pub struct WebDavInventoryFileView<'a, 'journal> {
    held: &'a LiveDavAdmission<'journal>,
    audit: Arc<VerifiedFileAudit>,
}

impl<'journal> LiveDavAdmission<'journal> {
    fn immutable_file_read_audit(&self) -> Result<Arc<VerifiedFileAudit>> {
        let connection = &self.journal.connection;
        let mut cached = self
            .file_read_audit
            .try_borrow_mut()
            .map_err(|_| invalid())?;
        if let Some(audit) = cached.as_ref() {
            if !self.failed
                && connection.is_autocommit()
                && audit.live_execution == self.execution
                && audit.snapshot.matches_generation(connection)?
            {
                audit.verify_binding(self)?;
                return Ok(Arc::clone(audit));
            }
        }
        // SQL writes, schema/data-version changes, transaction-state changes,
        // and changed exact execution discard the old read before rebuilding.
        *cached = None;
        let audit = Arc::new(VerifiedFileAudit::read(self)?);
        *cached = Some(Arc::clone(&audit));
        Ok(audit)
    }

    /// Fully audit once before lending a scoped inventory view. Every original
    /// handle, namespace, metadata and capacity check remains at all boundaries
    /// and observations; changed SQL or transaction state rejects the whole view.
    pub fn inventory_file_view(&self) -> Result<WebDavInventoryFileView<'_, 'journal>> {
        let audit = self.immutable_file_read_audit()?;
        let view = WebDavInventoryFileView { held: self, audit };
        view.verify()?;
        Ok(view)
    }
}

impl WebDavInventoryFileView<'_, '_> {
    fn verify_sql_generation(&self) -> Result<()> {
        self.audit.verify_binding(self.held)
    }
    pub fn verify(&self) -> Result<()> {
        self.verify_sql_generation()?;
        self.held.verify_process_owners()?;
        self.held.verify_held_handle_budget()?;
        self.held.coordination.verify()?;
        self.held
            .verify_held_namespace_with_baseline(&self.audit.baseline)?;
        self.held.verify_native_space_from_audit(&self.audit)?;
        self.verify_sql_generation()
    }

    /// Read-only compatibility name for existing policy callbacks.
    pub fn verify_file_view(&self) -> Result<()> {
        self.verify()
    }

    pub fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        self.verify()?;
        let observation = self.held.observe_held_file(path)?;
        self.verify_sql_generation()?;
        Ok(observation)
    }
    pub fn remaining_internal_bytes(&self) -> Result<u64> {
        self.verify()?;
        let remaining = self.held.remaining_internal_bytes_from_audit(&self.audit)?;
        self.verify_sql_generation()?;
        Ok(remaining)
    }
}
