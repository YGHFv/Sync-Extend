//! Exact immutable complete budget audit for pre-native D01 prefixes only.
//! No serialized receipt can extend this prefix into native or Final authority.
use super::{
    budget_manifest::{self, BudgetManifest, OriginalMainRow},
    execution::WebDavDurableExecution,
    future_history,
    initial_binding::InitialHeldBinding,
    receipt_protocol, WebDavNativeAdmission,
};
use crate::{
    storage_inventory::reader::{add, hash, preflight, read_table},
    JournalError, JournalStorageColumnValue as Value, Result,
};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_restore_history::encode_history_record, tree_storage_capacity::TreeStorageCharge,
    ContentId,
};

type RowKey = (String, Vec<String>);
type MainMap = BTreeMap<RowKey, (Vec<String>, Vec<Value>)>;
type CompleteManifestRow = (String, String, u64, u64, u64, u64, u64, u64, String);

pub(super) struct CompleteManifest {
    #[cfg(windows)]
    pub budget: PreparedBudget,
    #[cfg(windows)]
    pub templates: Vec<receipt_protocol::ReceiptTemplate>,
    pub additional_future: TreeStorageCharge,
    #[cfg(windows)]
    pub receipts: Vec<receipt_protocol::ReceiptDescription>,
    #[cfg(windows)]
    pub projection: super::collection_projection::VerifiedProjection,
}

fn invalid() -> JournalError {
    JournalError::Invariant("full original DAV immutable manifest and pre-native prefix")
}

fn text(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}

pub(super) fn catalog_hash(connection: &Connection) -> Result<ContentId> {
    let rows: Vec<(String, String, String, Option<String>)> = connection
        .prepare_cached("SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    hash(&rows)
}

pub(super) fn current_rows(connection: &Connection) -> Result<Vec<crate::JournalStoredRow>> {
    let specs = crate::storage_inventory::tables();
    let tables = preflight(
        connection,
        &specs,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let mut result = Vec::new();
    for (spec, table) in specs.iter().zip(&tables) {
        result.extend(read_table(connection, spec, table)?);
    }
    Ok(result)
}

fn map(rows: &[OriginalMainRow]) -> Result<MainMap> {
    let specs = crate::storage_inventory::tables();
    let mut result = MainMap::new();
    for row in rows {
        let spec = specs
            .iter()
            .find(|spec| spec.name == row.table)
            .ok_or_else(invalid)?;
        if row.column_names.len() != spec.columns.len()
            || row.values.len() != spec.columns.len()
            || row
                .column_names
                .iter()
                .zip(spec.columns)
                .any(|(name, spec)| name != spec.name)
        {
            return Err(invalid());
        }
        let mut keys: Vec<_> = spec
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| column.primary_key != 0)
            .collect();
        keys.sort_by_key(|(_, column)| column.primary_key);
        let derived: Vec<String> = keys
            .into_iter()
            .map(|(index, _)| match &row.values[index] {
                Value::Text(value) => Ok(value.clone()),
                Value::Integer(value) => Ok(value.to_string()),
                Value::Null => Err(invalid()),
            })
            .collect::<Result<_>>()?;
        if derived != row.primary_key
            || result
                .insert(
                    (row.table.clone(), row.primary_key.clone()),
                    (row.column_names.clone(), row.values.clone()),
                )
                .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(result)
}

fn insert(expected: &mut MainMap, table: &str, key: Vec<String>, values: Vec<Value>) -> Result<()> {
    let specs = crate::storage_inventory::tables();
    let spec = specs
        .iter()
        .find(|spec| spec.name == table)
        .ok_or_else(invalid)?;
    if values.len() != spec.columns.len()
        || expected
            .insert(
                (table.into(), key),
                (
                    spec.columns
                        .iter()
                        .map(|column| column.name.to_owned())
                        .collect(),
                    values,
                ),
            )
            .is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Full exact current map before native effects. No ordinary or other-DAV row is excluded.
/// D04/D05 need their own independently issued actual receipt transformations.
pub(super) fn audit(
    connection: &Connection,
    descriptions: &[WebDavNativeAdmission],
    executions: &[WebDavDurableExecution],
) -> Result<Vec<CompleteManifest>> {
    let rows: Vec<CompleteManifestRow> = connection
        .prepare_cached(
            "SELECT transaction_id,manifest_hash,template_count,binding_count,max_receipts,
         future_rows,future_bytes,admitted_at_ms,manifest
         FROM main.webdav_native_execution_manifests ORDER BY transaction_id",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                crate::sql_u64(row, 2)?,
                crate::sql_u64(row, 3)?,
                crate::sql_u64(row, 4)?,
                crate::sql_u64(row, 5)?,
                crate::sql_u64(row, 6)?,
                crate::sql_u64(row, 7)?,
                row.get(8)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut result = Vec::new();
    let mut all_template_transactions = BTreeSet::new();
    let mut all_binding_transactions = BTreeSet::new();
    for table in [
        "webdav_native_execution_templates",
        "webdav_native_execution_bindings",
    ] {
        let ids: Vec<String> = connection
            .prepare_cached(&format!(
                "SELECT DISTINCT transaction_id FROM main.{table} ORDER BY transaction_id"
            ))?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if table.ends_with("templates") {
            all_template_transactions.extend(ids);
        } else {
            all_binding_transactions.extend(ids);
        }
    }
    let manifest_ids: BTreeSet<_> = rows.iter().map(|row| row.0.clone()).collect();
    if all_template_transactions != manifest_ids || all_binding_transactions != manifest_ids {
        return Err(invalid());
    }
    let receipt_ids: Vec<String> = connection.prepare_cached(
        "SELECT DISTINCT transaction_id FROM main.webdav_native_execution_receipts ORDER BY transaction_id")?
        .query_map([],|row|row.get(0))?.collect::<rusqlite::Result<_>>()?;
    if receipt_ids.iter().any(|id| !manifest_ids.contains(id)) {
        return Err(invalid());
    }
    // The orphan template, binding and receipt sets are checked above.
    // Without any DAV manifest there is no original DAV map to compare.
    // Unrelated ordinary APIs keep their own owner and capacity audits.
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let actual = map(&budget_manifest::original_values(&current_rows(
        connection,
    )?)?)?;
    for (
        id,
        stored_hash,
        template_count,
        binding_count,
        max_receipts,
        future_rows,
        future_bytes,
        admitted_at_ms,
        json,
    ) in rows
    {
        let manifest: BudgetManifest = serde_json::from_str(&json)?;
        let description = descriptions
            .iter()
            .find(|row| row.description.request.transaction_id.as_str() == id)
            .ok_or_else(invalid)?;
        let execution = executions
            .iter()
            .find(|row| row.transaction_id.as_str() == id)
            .ok_or_else(invalid)?;
        let request = &description.description.request;
        if serde_json::to_string(&manifest)? != json
            || ContentId::hash(json.as_bytes()).as_str() != stored_hash
            || manifest.scope.transaction_id != request.transaction_id
            || manifest.scope.description_hash != description.description_hash
            || manifest.scope.request_hash != execution.request_hash
            || manifest.scope.plan_hash != description.plan_hash
            || manifest.admitted_at_ms != admitted_at_ms
            || execution.admitted_at_ms != admitted_at_ms
            || description.admitted_at_ms != admitted_at_ms
            || manifest.original_schema_hash != catalog_hash(connection)?
        {
            return Err(invalid());
        }
        let stored_receipts: Vec<(u64,u64,String,u64,String)> = connection.prepare_cached(
            "SELECT receipt_index,template_index,receipt_hash,issued_at_ms,receipt
             FROM main.webdav_native_execution_receipts WHERE transaction_id=?1 ORDER BY receipt_index"
        )?.query_map([&id],|row|Ok((crate::sql_u64(row, 0)?,crate::sql_u64(row, 1)?,row.get(2)?,crate::sql_u64(row, 3)?,row.get(4)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let original = map(&manifest.original_main)?;
        let baseline_key = ("snapshots".to_owned(), vec![request.baseline.to_string()]);
        let baseline_values = &original.get(&baseline_key).ok_or_else(invalid)?.1;
        let Value::Text(baseline_json) = &baseline_values[2] else {
            return Err(invalid());
        };
        let baseline = serde_json::from_str(baseline_json)?;
        let plan = sync_extend_core_model::webdav_native::plan_webdav_native(
            &baseline,
            request,
            &description.description.inventory,
            description.description.limits,
        )?;
        let templates = receipt_protocol::templates(
            &manifest.scope,
            &plan,
            manifest.limits.max_templates,
            // Templates must use a single immutable per-receipt limit.
            connection
                .query_row(
                    "SELECT template FROM main.webdav_native_execution_templates
                 WHERE transaction_id=?1 AND template_index=0",
                    [&id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|json| serde_json::from_str::<receipt_protocol::ReceiptTemplate>(&json))
                .transpose()?
                .ok_or_else(invalid)?
                .max_receipt_json_bytes,
            manifest.limits.max_manifest_json,
        )?;
        let stored_templates: Vec<(u64,String,u64,u64,u64,String)> = connection.prepare_cached(
            "SELECT template_index,template_hash,max_new_rows,max_new_bytes,issued_at_ms,template
             FROM main.webdav_native_execution_templates WHERE transaction_id=?1 ORDER BY template_index"
        )?.query_map([&id],|row|Ok((crate::sql_u64(row, 0)?,row.get(1)?,crate::sql_u64(row, 2)?,crate::sql_u64(row, 3)?,crate::sql_u64(row, 4)?,row.get(5)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if stored_templates.len() != templates.len() {
            return Err(invalid());
        }
        for (template, (index, fingerprint, rows, bytes, time, json)) in
            templates.iter().zip(&stored_templates)
        {
            let encoded = encode_history_record(template, manifest.limits.max_manifest_json)?;
            if *index != template.index as u64
                || *time != admitted_at_ms
                || *rows != 1
                || *bytes != add(120, template.max_receipt_json_bytes)?
                || encoded != json.as_bytes()
                || ContentId::hash(&encoded).as_str() != fingerprint
            {
                return Err(invalid());
            }
        }
        let stored_bindings: Vec<(u64,String,u64,String)> = connection.prepare_cached(
            "SELECT binding_index,binding_hash,issued_at_ms,binding
             FROM main.webdav_native_execution_bindings WHERE transaction_id=?1 ORDER BY binding_index"
        )?.query_map([&id],|row|Ok((crate::sql_u64(row, 0)?,row.get(1)?,crate::sql_u64(row, 2)?,row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut bindings = Vec::new();
        for (index, fingerprint, time, json) in &stored_bindings {
            let binding: InitialHeldBinding = serde_json::from_str(json)?;
            let encoded = encode_history_record(&binding, manifest.limits.max_binding_json)?;
            if binding.index as u64 != *index
                || binding.index != bindings.len()
                || *time != admitted_at_ms
                || binding.plan_hash != manifest.scope.plan_hash
                || binding.baseline_hash != request.baseline
                || encoded != json.as_bytes()
                || ContentId::hash(&encoded).as_str() != fingerprint
            {
                return Err(invalid());
            }
            bindings.push(binding);
        }
        super::binding_audit::audit(
            &baseline,
            &plan,
            &manifest.original_main,
            &bindings,
            std::fs::canonicalize(connection.path().ok_or_else(invalid)?)?
                .parent()
                .ok_or_else(invalid)?,
        )?;
        let history = future_history::plan(
            &baseline.space_id,
            request,
            &plan,
            &manifest.original_main,
            admitted_at_ms,
            manifest.limits.max_manifest_json,
            crate::limits::MAX_ENTRIES,
        )?;
        if history != manifest.history {
            return Err(invalid());
        }
        let native_peak = super::native_capacity::NativePeak::derive(&baseline, &plan)?;
        if manifest.native_peak != native_peak
            || native_peak.prospective_namespace_paths
                > description.description.limits.max_bindings as u64
            || native_peak.additional_logical_file_bytes
                > description.description.limits.max_staging_bytes
        {
            return Err(invalid());
        }
        let native_handles = super::native_capacity::NativeHandles::derive(
            &bindings,
            &native_peak,
            usize::try_from(manifest.native_handles.admission_limit).map_err(|_| invalid())?,
        )?;
        if native_handles != manifest.native_handles
            || native_handles.admission_limit > description.description.limits.max_bindings as u64
        {
            return Err(invalid());
        }
        let budget = budget_manifest::prepare(
            &manifest.scope,
            &manifest.original_schema_hash,
            &manifest.original_main,
            &templates,
            &bindings,
            &history,
            &native_peak,
            &native_handles,
            manifest.limits,
            admitted_at_ms,
        )?;
        if budget.manifest != manifest
            || budget.manifest_json != json.as_bytes()
            || budget.manifest_hash.as_str() != stored_hash
            || templates.len() as u64 != template_count
            || bindings.len() as u64 != binding_count
            || max_receipts != template_count
            || future_rows != budget.future.rows
            || future_bytes != budget.future.logical_bytes
            || manifest.limits.execution_records != execution.limits.max_records
            || manifest.limits.max_execution_record_json != execution.limits.max_record_bytes
            || manifest.limits.max_total_execution_json != execution.limits.max_total_bytes
        {
            return Err(invalid());
        }
        let mut receipts = Vec::new();
        let mut receipt_json = Vec::new();
        for (index, template_index, fingerprint, time, json) in &stored_receipts {
            let receipt: receipt_protocol::ReceiptDescription = serde_json::from_str(json)?;
            let template = templates.get(receipt.template_index).ok_or_else(invalid)?;
            let encoded = encode_history_record(&receipt, template.max_receipt_json_bytes)?;
            if *index != receipts.len() as u64
                || receipt.index as u64 != *index
                || *template_index != receipt.template_index as u64
                || receipt.recorded_at_ms != *time
                || encoded != json.as_bytes()
                || ContentId::hash(&encoded).as_str() != fingerprint
            {
                return Err(invalid());
            }
            receipts.push(receipt);
            receipt_json.push(encoded);
        }
        let receipt_peak = templates.iter().try_fold(0_u64, |total, template| {
            add(total, template.max_receipt_json_bytes)
        })?;
        let verified = receipt_protocol::verified_prefix(
            &plan,
            &templates,
            &receipts,
            &budget.manifest_hash,
            admitted_at_ms,
            receipt_peak,
        )?;
        #[cfg(windows)]
        let projection =
            super::collection_projection::VerifiedProjection::derive(&baseline, &verified)?;
        drop(verified);
        if !receipts.is_empty() && execution.records.is_empty() {
            return Err(invalid());
        }
        if execution.cancelled && !receipts.is_empty() {
            return Err(invalid());
        }
        // Prefix evidence must bind the original captured root, not another equal tree.
        if let Some(first) = receipts.first() {
            let receipt_protocol::ReceiptEvidence::DirectoryIntent { parent, .. } = &first.evidence
            else {
                return Err(invalid());
            };
            if parent != &description.description.inventory.root {
                return Err(invalid());
            }
            let mut original_ids: BTreeSet<_> = bindings
                .iter()
                .map(|binding| binding.identity.clone())
                .collect();
            for receipt in &receipts {
                match &receipt.evidence {
                    receipt_protocol::ReceiptEvidence::DirectoryCreated { original, .. }
                    | receipt_protocol::ReceiptEvidence::MarkerCreated { original, .. } => {
                        if !original_ids.insert(original.clone()) {
                            return Err(invalid());
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut expected = original;
        // Historical cancellation never grants another native attempt.
        if execution.cancelled && !execution.records.is_empty() {
            return Err(invalid());
        }
        insert(
            &mut expected,
            "webdav_native_admissions",
            vec![id.clone()],
            vec![
                text(&id),
                text(&baseline.space_id),
                text(&request.baseline),
                text(&execution.request_hash),
                text(&description.plan_hash),
                Value::Integer(admitted_at_ms),
                text(serde_json::to_string(&description.description)?),
                Value::Integer(1),
                Value::Integer(40),
            ],
        )?;
        let mut chunks = BTreeMap::new();
        for chunk in baseline
            .entries
            .values()
            .chain(plan.final_manifest().entries.values())
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| &content.chunks)
        {
            if chunks
                .insert(chunk.content_id.clone(), u64::from(chunk.length))
                .is_some_and(|prior| prior != u64::from(chunk.length))
            {
                return Err(invalid());
            }
        }
        for (content, length) in chunks {
            insert(
                &mut expected,
                "webdav_native_objects",
                vec![id.clone(), content.to_string()],
                vec![text(&id), text(content), Value::Integer(length)],
            )?;
        }
        insert(
            &mut expected,
            "webdav_native_execution_admissions",
            vec![id.clone()],
            vec![
                text(&id),
                text(&description.description_hash),
                text(&execution.request_hash),
                text(&description.plan_hash),
                Value::Integer(execution.limits.max_records as u64),
                Value::Integer(execution.limits.max_record_bytes),
                Value::Integer(execution.limits.max_total_bytes),
                Value::Integer(admitted_at_ms),
                text(&execution.admission_hash),
            ],
        )?;
        for (index, fingerprint, rows, bytes, time, json) in stored_templates {
            insert(
                &mut expected,
                "webdav_native_execution_templates",
                vec![id.clone(), index.to_string()],
                vec![
                    text(&id),
                    Value::Integer(index),
                    text(fingerprint),
                    Value::Integer(rows),
                    Value::Integer(bytes),
                    Value::Integer(time),
                    text(json),
                ],
            )?;
        }
        for (index, fingerprint, time, json) in stored_bindings {
            insert(
                &mut expected,
                "webdav_native_execution_bindings",
                vec![id.clone(), index.to_string()],
                vec![
                    text(&id),
                    Value::Integer(index),
                    text(fingerprint),
                    Value::Integer(time),
                    text(json),
                ],
            )?;
        }
        insert(
            &mut expected,
            "webdav_native_execution_manifests",
            vec![id.clone()],
            vec![
                text(&id),
                text(stored_hash),
                Value::Integer(template_count),
                Value::Integer(binding_count),
                Value::Integer(max_receipts),
                Value::Integer(future_rows),
                Value::Integer(future_bytes),
                Value::Integer(admitted_at_ms),
                text(json),
            ],
        )?;
        let mut clock = admitted_at_ms;
        for record in &execution.records {
            let json = encode_history_record(record, execution.limits.max_record_bytes)?;
            insert(
                &mut expected,
                "webdav_native_execution_records",
                vec![id.clone(), record.record_index.to_string()],
                vec![
                    text(&id),
                    Value::Integer(record.record_index as u64),
                    text(ContentId::hash(&json)),
                    Value::Integer(record.recorded_at_ms),
                    text(std::str::from_utf8(&json).map_err(|_| invalid())?),
                ],
            )?;
            clock = clock.max(record.recorded_at_ms);
        }
        for (index, template_index, fingerprint, time, json) in &stored_receipts {
            insert(
                &mut expected,
                "webdav_native_execution_receipts",
                vec![id.clone(), index.to_string()],
                vec![
                    text(&id),
                    Value::Integer(*index),
                    Value::Integer(*template_index),
                    text(fingerprint),
                    Value::Integer(*time),
                    text(json),
                ],
            )?;
            clock = clock.max(*time);
        }
        let clock_key = ("webdav_native_clock".to_owned(), vec!["1".into()]);
        let old_clock = expected.remove(&clock_key);
        if old_clock.as_ref().is_some_and(|(_,values)|
            !matches!(values.as_slice(),[Value::Integer(1),Value::Integer(old)] if *old <= clock))
        { return Err(invalid()); }
        insert(
            &mut expected,
            "webdav_native_clock",
            vec!["1".into()],
            vec![Value::Integer(1), Value::Integer(clock)],
        )?;
        let terminal = receipts
            .last()
            .is_some_and(|record| record.stage == receipt_protocol::ReceiptStage::Terminal);
        if terminal {
            let final_record = receipts
                .iter()
                .find(|record| {
                    matches!(
                        record.stage,
                        receipt_protocol::ReceiptStage::HistoryCommitted(_)
                    )
                })
                .ok_or_else(invalid)?;
            let receipt_protocol::ReceiptEvidence::History {
                final_snapshot,
                history_hash,
                ..
            } = &final_record.evidence
            else {
                return Err(invalid());
            };
            super::reference_handoff::audit(
                connection,
                &request.transaction_id,
                &receipts,
                final_snapshot,
                history_hash,
            )?;
        }
        let mut history_applied = false;
        for record in &receipts {
            if let receipt_protocol::ReceiptEvidence::History { history_hash, .. } =
                &record.evidence
            {
                if history_hash != &manifest.history.fingerprint {
                    return Err(invalid());
                }
            }
            if matches!(
                record.stage,
                receipt_protocol::ReceiptStage::HistoryCommitted(_)
            ) {
                if history_applied {
                    return Err(invalid());
                }
                for row in &manifest.history.rows {
                    let key = (row.table.clone(), row.primary_key.clone());
                    if expected.get(&key).map(|(_, values)| values) != row.prior.as_ref() {
                        return Err(invalid());
                    }
                    expected.remove(&key);
                    if let Some(values) = &row.future {
                        insert(
                            &mut expected,
                            &row.table,
                            row.primary_key.clone(),
                            values.clone(),
                        )?;
                    }
                }
                history_applied = true;
            }
        }
        if execution.cancelled || terminal {
            let time = if terminal {
                receipts.last().ok_or_else(invalid)?.recorded_at_ms
            } else {
                description.cancelled_at_ms.ok_or_else(invalid)?
            };
            if time < admitted_at_ms {
                return Err(invalid());
            }
            if !terminal {
                insert(
                    &mut expected,
                    "webdav_native_cancellations",
                    vec![id.clone()],
                    vec![text(&id), Value::Integer(time)],
                )?;
            }
            // Terminal/cancelled history can advance under its ordinary protocols.
            // Compare every current row in this owner's immutable ledger in both
            // directions; future ordinary rows are historical values, not live pins.
            let owner_row = |key: &RowKey| {
                key.0.starts_with("webdav_native_")
                    && key.0 != "webdav_native_clock"
                    && key.1.first() == Some(&id)
            };
            let owner_expected: BTreeMap<_, _> =
                expected.iter().filter(|(key, _)| owner_row(key)).collect();
            let owner_actual: BTreeMap<_, _> =
                actual.iter().filter(|(key, _)| owner_row(key)).collect();
            if owner_expected != owner_actual {
                return Err(invalid());
            }
            let clock_key = ("webdav_native_clock".to_owned(), vec!["1".into()]);
            let observed_clock = actual.get(&clock_key).ok_or_else(invalid)?;
            if !matches!(observed_clock.1.as_slice(),
                [Value::Integer(1),Value::Integer(clock)] if *clock >= time)
            {
                return Err(invalid());
            }
        } else if expected != actual {
            return Err(invalid());
        }
        let remaining_receipts =
            budget_manifest::remaining_receipt_peak(&templates, &receipt_json, receipts.len())?;
        let additional_future = if execution.cancelled || terminal {
            TreeStorageCharge::default()
        } else {
            TreeStorageCharge {
                rows: add(
                    remaining_receipts.rows,
                    if history_applied {
                        0
                    } else {
                        manifest.history.charge.rows
                    },
                )?,
                logical_bytes: add(
                    remaining_receipts.logical_bytes,
                    if history_applied {
                        0
                    } else {
                        manifest.history.charge.logical_bytes
                    },
                )?,
            }
        };
        result.push(CompleteManifest {
            #[cfg(windows)]
            budget,
            #[cfg(windows)]
            templates,
            additional_future,
            #[cfg(windows)]
            receipts,
            #[cfg(windows)]
            projection,
        });
    }
    Ok(result)
}

/// The execution module already accounts its own future action records.
/// Add only independent internal native receipt and original Final row peaks.
pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let descriptions = super::audit_descriptions(connection)?;
    let executions = super::execution::audit(connection)?;
    audit(connection, &descriptions, &executions)?
        .iter()
        .try_fold(TreeStorageCharge::default(), |total, item| {
            Ok(TreeStorageCharge {
                rows: add(total.rows, item.additional_future.rows)?,
                logical_bytes: add(total.logical_bytes, item.additional_future.logical_bytes)?,
            })
        })
}

#[cfg(windows)]
use super::budget_manifest::PreparedBudget;
