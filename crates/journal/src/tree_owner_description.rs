//! Immutable owner creator/marker descriptions, not native ownership or admission.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeExecutionDescriptionAudit, TreeOriginalPinsAudit,
    TreeRestoreHistoryReservation, TreeRestoreNativeReservation, TreeRestorePreparation,
    TreeRestorePreparationIntent, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use sync_extend_core_model::{
    tree_original_reference::plan_tree_original_references,
    tree_owner_marker::{
        audit_tree_owner_records, plan_tree_owner, TreeOwnerInput, TreeOwnerIntent,
        TreeOwnerLimits, TreeOwnerPlan, TreeOwnerRecord, TreeOwnerRecordAudit,
        TreeOwnerRecordLimits,
    },
    tree_restore_history::encode_history_record,
    ContentId, Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeOwnerDescriptionAudit {
    pub intent: TreeOwnerIntent,
    pub intent_hash: ContentId,
    pub marker_hash: ContentId,
    pub marker_length: u64,
    pub records: Vec<TreeOwnerRecord>,
    pub fingerprint: ContentId,
    pub metadata_bytes: u64,
    pub description_complete: bool,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

#[allow(clippy::too_many_arguments)]
fn project(
    preparation: &TreeRestorePreparationIntent,
    history: &TreeRestoreHistoryReservation,
    native: &TreeRestoreNativeReservation,
    description: &TreeExecutionDescriptionAudit,
    original: &TreeOriginalPinsAudit,
    baseline: &Manifest,
    target: &Manifest,
    input: &TreeOwnerInput,
    max: usize,
) -> Result<TreeOwnerPlan> {
    if input.original_request_hash != ContentId::hash(&serde_json::to_vec(&original.request)?)
        || input.original_closure_hash != original.fingerprint
        || input.created_at_ms < original.request.reserved_at_ms
    {
        return Err(JournalError::Invariant(
            "tree owner exact original header binding",
        ));
    }
    let projection = crate::tree_restore_execution_intent::project(
        preparation,
        history,
        native,
        baseline,
        target,
        &description.intent.input,
        max,
    )?;
    let core = plan_tree_original_references(
        &projection.plan,
        &projection.identity,
        original.request.limits,
    )?;
    if core.intents() != &original.originals || core.fingerprint() != &original.fingerprint {
        return Err(JournalError::Invariant(
            "tree owner exact original projection",
        ));
    }
    Ok(plan_tree_owner(
        &projection.plan,
        &projection.identity,
        &core,
        input,
        TreeOwnerLimits {
            max_steps: max,
            max_encoded_bytes: MAX_OPERATION_BYTES as u64,
        },
    )?)
}

fn project_preparation(
    connection: &Connection,
    preparation: &TreeRestorePreparation,
    input: &TreeOwnerInput,
    max: usize,
) -> Result<TreeOwnerPlan> {
    let p = &preparation.intent;
    let baseline =
        audit_snapshot(connection, &p.scope.space_id, &p.scope.baseline_snapshot)?.manifest;
    let target = audit_snapshot(connection, &p.scope.space_id, &p.scope.target_snapshot)?.manifest;
    project(
        p,
        preparation
            .history_reservation
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner history missing"))?,
        preparation
            .native_reservation
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner native missing"))?,
        preparation
            .execution_description
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner coordinator missing"))?,
        preparation
            .original_pins
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner original pins missing"))?,
        &baseline,
        &target,
        input,
        max,
    )
}

fn bounds(max: usize) -> TreeOwnerRecordLimits {
    TreeOwnerRecordLimits {
        max_records: max.min(8),
        max_encoded_bytes: MAX_OPERATION_BYTES as u64,
    }
}

fn report(
    plan: &TreeOwnerPlan,
    records: &TreeOwnerRecordAudit,
    metadata_bytes: u64,
) -> TreeOwnerDescriptionAudit {
    TreeOwnerDescriptionAudit {
        intent: plan.intent().clone(),
        intent_hash: plan.intent_hash().clone(),
        marker_hash: plan.marker_hash().clone(),
        marker_length: plan.marker_bytes().len() as u64,
        records: records.records().to_vec(),
        fingerprint: records.fingerprint().clone(),
        metadata_bytes,
        description_complete: records.description_complete(),
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_owner(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    history: Option<&TreeRestoreHistoryReservation>,
    native: Option<&TreeRestoreNativeReservation>,
    description: Option<&TreeExecutionDescriptionAudit>,
    original: Option<&TreeOriginalPinsAudit>,
    baseline: &Manifest,
    target: &Manifest,
    cancelled: Option<u64>,
    max: usize,
) -> Result<Option<TreeOwnerDescriptionAudit>> {
    let json: Option<String> = connection.query_row(
        "SELECT CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END
         FROM tree_restore_owner_intents WHERE transaction_id=?1",
        [preparation.transaction_id.as_str()], |r|r.get(0),
    ).optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let stored: TreeOwnerIntent = serde_json::from_str(&json)?;
    let plan = project(
        preparation,
        history.ok_or(JournalError::Invariant("tree owner history missing"))?,
        native.ok_or(JournalError::Invariant("tree owner native missing"))?,
        description.ok_or(JournalError::Invariant("tree owner coordinator missing"))?,
        original.ok_or(JournalError::Invariant("tree owner original pins missing"))?,
        baseline,
        target,
        &stored.input,
        max,
    )?;
    let input = &stored.input;
    let exact: bool = connection.query_row(
        "SELECT coordinator_execution_id=?2 AND execution_intent_hash=?3 AND original_request_hash=?4
         AND original_closure_hash=?5 AND intent=?6 AND intent_hash=?7 AND marker_hash=?8
         AND marker_length=?9 AND created_at_ms=?10 FROM tree_restore_owner_intents WHERE transaction_id=?1",
        params![preparation.transaction_id.as_str(),input.coordinator_execution_id.as_str(),
            input.execution_intent_hash.as_str(),input.original_request_hash.as_str(),
            input.original_closure_hash.as_str(),serde_json::to_string(plan.intent())?,
            plan.intent_hash().as_str(),plan.marker_hash().as_str(),
            sql_integer(plan.marker_bytes().len() as u64)?,sql_integer(input.created_at_ms)?],
        |r|r.get(0),
    )?;
    if !exact || stored != *plan.intent() || cancelled.is_some_and(|t| t < input.created_at_ms) {
        return Err(JournalError::Invariant("tree owner exact intent mismatch"));
    }
    let mut bytes = json.len() as u64 + 400;
    let mut records = Vec::new();
    let mut statement = connection.prepare(
        "SELECT record_index,
         CASE WHEN length(CAST(coordinator_execution_id AS BLOB))=32 THEN coordinator_execution_id ELSE '' END,
         CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
         CASE WHEN length(CAST(previous_hash AS BLOB))=64 THEN previous_hash ELSE '' END,
         CASE WHEN length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216 THEN record ELSE '' END,
         CASE WHEN length(CAST(record_hash AS BLOB))=64 THEN record_hash ELSE '' END,
         recorded_at_ms FROM tree_restore_owner_records WHERE transaction_id=?1 ORDER BY record_index",
    )?;
    let mut rows = statement.query([preparation.transaction_id.as_str()])?;
    while let Some(row) = rows.next()? {
        if records.len() >= max.min(8) {
            return Err(JournalError::Invariant("tree owner record inventory"));
        }
        let json: String = row.get(4)?;
        bytes = bytes
            .checked_add(json.len() as u64 + 272)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant("tree owner record byte inventory"))?;
        let record: TreeOwnerRecord = serde_json::from_str(&json)?;
        if serde_json::to_string(&record)? != json
            || record.transaction_id != preparation.transaction_id
            || sql_integer(record.record_index as u64)? != row.get::<_, i64>(0)?
            || record.coordinator_execution_id.as_str() != row.get::<_, String>(1)?
            || record.intent_hash.as_str() != row.get::<_, String>(2)?
            || record.previous_hash.as_str() != row.get::<_, String>(3)?
            || ContentId::hash(json.as_bytes()).as_str() != row.get::<_, String>(5)?
            || sql_integer(record.recorded_at_ms)? != row.get::<_, i64>(6)?
            || cancelled.is_some_and(|t| t < record.recorded_at_ms)
        {
            return Err(JournalError::Invariant("tree owner exact record mismatch"));
        }
        records.push(record);
    }
    let core = audit_tree_owner_records(&plan, &records, bounds(max))?;
    Ok(Some(report(&plan, &core, bytes)))
}

impl Journal {
    /// Exact immutable metadata only; callback never authorizes native creation.
    pub fn with_tree_owner_description<T, E>(
        &self,
        input: &TreeOwnerInput,
        max: usize,
        inspect: impl FnOnce(&TreeOwnerPlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeOwnerDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree owner space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == input.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree owner"))
        };
        let replay = |prior: &TreeOwnerDescriptionAudit| -> Result<()> {
            if prior.intent.input != *input {
                return Err(JournalError::Invariant("tree owner intent collision"));
            }
            Ok(())
        };
        let preparation = find()?;
        if let Some(prior) = preparation.owner_description {
            replay(&prior)?;
            return Ok((None, prior));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree owner").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        if let Some(prior) = preparation.owner_description {
            replay(&prior)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("tree owner cancelled").into());
        }
        let plan = project_preparation(&tx, &preparation, input, max)?;
        let json = String::from_utf8(
            encode_history_record(plan.intent(), MAX_OPERATION_BYTES as u64)
                .map_err(JournalError::from)?,
        )
        .map_err(|_| JournalError::Invariant("tree owner encoding"))?;
        check_storage_metadata_limit(&tx, max, 1, json.len() as u64 + 400)?;
        tx.execute(
            "INSERT INTO tree_restore_owner_intents VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                input.transaction_id.as_str(),
                input.coordinator_execution_id.as_str(),
                input.execution_intent_hash.as_str(),
                input.original_request_hash.as_str(),
                input.original_closure_hash.as_str(),
                json,
                plan.intent_hash().as_str(),
                plan.marker_hash().as_str(),
                sql_integer(plan.marker_bytes().len() as u64)?,
                sql_integer(input.created_at_ms)?
            ],
        )
        .map_err(JournalError::from)?;
        let expected = report(
            &plan,
            &audit_tree_owner_records(&plan, &[], bounds(max)).map_err(JournalError::from)?,
            json.len() as u64 + 400,
        );
        let held = inspect(&plan)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?
            .owner_description
            .ok_or(JournalError::Invariant("tree owner disappeared"))?;
        if audit != expected {
            return Err(JournalError::Invariant("tree owner changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }

    /// Append descriptions only; exact replay cannot renew native authority.
    pub fn with_tree_owner_record_description<T, E>(
        &self,
        record: &TreeOwnerRecord,
        max: usize,
        inspect: impl FnOnce(&TreeOwnerRecordAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeOwnerDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree owner space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == record.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree owner record"))
        };
        let replay = |prior: &TreeOwnerDescriptionAudit| -> Result<bool> {
            if let Some(p) = prior.records.get(record.record_index) {
                if p != record {
                    return Err(JournalError::Invariant("tree owner record collision"));
                }
                return Ok(true);
            }
            Ok(false)
        };
        let preparation = find()?;
        let prior = preparation
            .owner_description
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner intent missing"))?;
        if replay(prior)? {
            return Ok((None, prior.clone()));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree owner record").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        let prior = preparation
            .owner_description
            .as_ref()
            .ok_or(JournalError::Invariant("tree owner intent missing"))?;
        if replay(prior)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior.clone()));
        }
        if !preparation.writer_gate_held || prior.records.len() >= max.min(8) {
            return Err(JournalError::Invariant("tree owner record cancelled or full").into());
        }
        let plan = project_preparation(&tx, &preparation, &prior.intent.input, max)?;
        let json = String::from_utf8(
            encode_history_record(record, MAX_OPERATION_BYTES as u64)
                .map_err(JournalError::from)?,
        )
        .map_err(|_| JournalError::Invariant("tree owner record encoding"))?;
        let bytes = prior
            .metadata_bytes
            .checked_add(json.len() as u64 + 272)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant("tree owner record byte inventory"))?;
        check_storage_metadata_limit(&tx, max, 1, json.len() as u64 + 272)?;
        let mut records = prior.records.clone();
        records.push(record.clone());
        let core =
            audit_tree_owner_records(&plan, &records, bounds(max)).map_err(JournalError::from)?;
        let expected = report(&plan, &core, bytes);
        tx.execute(
            "INSERT INTO tree_restore_owner_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                record.transaction_id.as_str(),
                record.coordinator_execution_id.as_str(),
                record.intent_hash.as_str(),
                sql_integer(record.record_index as u64)?,
                record.previous_hash.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(record.recorded_at_ms)?
            ],
        )
        .map_err(JournalError::from)?;
        let held = inspect(&core)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?
            .owner_description
            .ok_or(JournalError::Invariant("tree owner records disappeared"))?;
        if audit != expected {
            return Err(
                JournalError::Invariant("tree owner records changed during inspection").into(),
            );
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }
}
