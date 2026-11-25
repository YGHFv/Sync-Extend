//! Exact original Final values and transaction statements; issuer retains natives.
use super::receipt_protocol::{ReceiptDescription, ReceiptEvidence, ReceiptStage, VerifiedPrefix};
#[cfg(windows)]
use super::{
    final_row_gate::Gate,
    future_history::{FutureHistory, FutureHistoryRow},
};
#[cfg(windows)]
use crate::JournalStorageColumnValue as Value;
use crate::{JournalError, Result};
use rusqlite::Connection;
#[cfg(windows)]
use rusqlite::{Transaction, params_from_iter};
#[cfg(windows)]
use sync_extend_core_model::tree_restore_history::encode_history_record;
use sync_extend_core_model::{ContentId, ModelError, webdav_native::WebDavNativeAction};
fn invalid() -> JournalError {
    JournalError::Invariant("original complete DAV causal Final values")
}

pub(super) fn audit_receipt(
    record: &ReceiptDescription,
    prior: &VerifiedPrefix<'_>,
) -> sync_extend_core_model::Result<()> {
    let bad = || ModelError::InvalidData("original DAV causal Final receipt");
    let plan = prior.plan();
    let records = prior.records();
    let action = match record.stage {
        ReceiptStage::HistoryCommitRequested(action) | ReceiptStage::HistoryCommitted(action) => {
            action
        }
        _ => return Err(bad()),
    };
    let step = plan.steps().get(action).ok_or_else(bad)?;
    let WebDavNativeAction::CommitHistory {
        final_snapshot,
        operation_count,
    } = &step.action
    else {
        return Err(bad());
    };
    let ReceiptEvidence::History {
        action: actual,
        final_snapshot: snapshot,
        operation_count: count,
        history_hash,
    } = &record.evidence
    else {
        return Err(bad());
    };
    if *actual != action
        || snapshot != final_snapshot
        || count != operation_count
        || history_hash.as_str().len() != 64
        || records.len() < 10
    {
        return Err(bad());
    }
    if !prior.dependencies_verified(action) {
        for dependency in &step.dependencies {
            let finished = match &plan.steps().get(*dependency).ok_or_else(bad)?.action {
                WebDavNativeAction::QuarantineOriginal { .. } => {
                    ReceiptStage::QuarantineMoved(*dependency)
                }
                WebDavNativeAction::CreateDirectory { .. } => {
                    ReceiptStage::DirectoryCreated(*dependency)
                }
                WebDavNativeAction::PublishFile { .. } => ReceiptStage::FilePublished(*dependency),
                _ => return Err(bad()),
            };
            if *dependency >= action || prior.first(finished).is_none() {
                return Err(bad());
            }
        }
    }
    if matches!(record.stage, ReceiptStage::HistoryCommitted(_)) {
        let previous = records.last().ok_or_else(bad)?;
        if previous.stage != ReceiptStage::HistoryCommitRequested(action)
            || previous.evidence != record.evidence
        {
            return Err(bad());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn specification(table: &str) -> Result<(&'static [&'static str], &'static [usize])> {
    match table {
        "operations" => Ok((
            &[
                "op_id",
                "space_id",
                "origin_device_id",
                "origin_seq",
                "payload",
                "state",
            ],
            &[0],
        )),
        "receive_cursors" => Ok((&["space_id", "device_id", "contiguous_seq"], &[0, 1])),
        "snapshots" => Ok((
            &[
                "snapshot_id",
                "space_id",
                "manifest",
                "created_at_ms",
                "state",
                "locked",
            ],
            &[0],
        )),
        "current_manifests" => Ok((&["space_id", "snapshot_id"], &[0])),
        "snapshot_objects" => Ok((&["snapshot_id", "content_id"], &[0, 1])),
        "rename_observations" => Ok((
            &["space_id", "snapshot_id", "observation", "observation_hash"],
            &[0],
        )),
        _ => Err(invalid()),
    }
}
#[cfg(windows)]
fn sql(value: &Value) -> Result<rusqlite::types::Value> {
    Ok(match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Text(value) => rusqlite::types::Value::Text(value.clone()),
        Value::Integer(value) => rusqlite::types::Value::Integer(crate::sql_integer(*value)?),
    })
}
#[cfg(windows)]
fn stored(connection: &Connection, row: &FutureHistoryRow) -> Result<Option<Vec<Value>>> {
    let (columns, keys) = specification(&row.table)?;
    if row.primary_key.len() != keys.len() {
        return Err(invalid());
    }
    let predicate = keys
        .iter()
        .enumerate()
        .map(|(i, key)| format!("{}=?{}", columns[*key], i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let query = format!(
        "SELECT {} FROM main.{} WHERE {predicate}",
        columns.join(","),
        row.table
    );
    let values: Vec<Vec<Value>> = connection
        .prepare(&query)?
        .query_map(params_from_iter(row.primary_key.iter()), |row| {
            (0..columns.len())
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(value) if value >= 0 => {
                            Value::Integer(value as u64)
                        }
                        rusqlite::types::ValueRef::Text(value) => Value::Text(
                            std::str::from_utf8(value)
                                .map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        index,
                                        rusqlite::types::Type::Text,
                                        Box::new(error),
                                    )
                                })?
                                .to_owned(),
                        ),
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    })
                })
                .collect()
        })?
        .collect::<rusqlite::Result<_>>()?;
    if values.len() > 1 {
        return Err(invalid());
    }
    Ok(values.into_iter().next())
}

/// Apply only the immutable planner's future rows in the caller's original tx.
/// Complete before/after main-map verification remains the issuer's obligation.
#[cfg(windows)]
pub(super) fn apply(tx: &Transaction<'_>, gate: &Gate, history: &FutureHistory) -> Result<()> {
    if ContentId::hash(&encode_history_record(
        &history.rows,
        sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES,
    )?) != history.fingerprint
    {
        return Err(invalid());
    }
    for row in &history.rows {
        let (columns, keys) = specification(&row.table)?;
        if stored(tx, row)? != row.prior
            || row.prior.as_ref().is_some_and(|v| v.len() != columns.len())
            || row
                .future
                .as_ref()
                .is_some_and(|v| v.len() != columns.len())
        {
            return Err(invalid());
        }
        if row.prior == row.future {
            continue;
        }
        let predicate = keys
            .iter()
            .enumerate()
            .map(|(i, key)| format!("{}=?{}", columns[*key], i + 1))
            .collect::<Vec<_>>()
            .join(" AND ");
        let (query, parameters) = match (&row.prior, &row.future) {
            (None, Some(values)) => (
                format!(
                    "INSERT INTO main.{} VALUES({})",
                    row.table,
                    (1..=values.len())
                        .map(|i| format!("?{i}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                values.iter().map(sql).collect::<Result<Vec<_>>>()?,
            ),
            (Some(_), Some(values)) => {
                let mut parameters = values.iter().map(sql).collect::<Result<Vec<_>>>()?;
                parameters.extend(
                    row.primary_key
                        .iter()
                        .cloned()
                        .map(rusqlite::types::Value::Text),
                );
                let set = columns
                    .iter()
                    .enumerate()
                    .map(|(i, name)| format!("{name}=?{}", i + 1))
                    .collect::<Vec<_>>()
                    .join(",");
                let where_clause = keys
                    .iter()
                    .enumerate()
                    .map(|(i, key)| format!("{}=?{}", columns[*key], values.len() + i + 1))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                (
                    format!("UPDATE main.{} SET {set} WHERE {where_clause}", row.table),
                    parameters,
                )
            }
            (Some(_), None) => (
                format!("DELETE FROM main.{} WHERE {predicate}", row.table),
                row.primary_key
                    .iter()
                    .cloned()
                    .map(rusqlite::types::Value::Text)
                    .collect(),
            ),
            _ => return Err(invalid()),
        };
        gate.issue(&row.table, row.prior.clone(), row.future.clone(), || {
            if tx.execute(&query, params_from_iter(parameters))? != 1 {
                return Err(invalid());
            }
            Ok(())
        })?;
        if stored(tx, row)? != row.future {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Descriptive read used only to select baseline/current audit expectations.
/// Full prefix/hash/schema/value verification is mandatory in complete audit.
pub(super) fn committed(
    connection: &Connection,
    id: &sync_extend_core_model::EntryId,
) -> Result<Option<ReceiptDescription>> {
    let rows:Vec<String>=connection.prepare(
        "SELECT receipt FROM main.webdav_native_execution_receipts WHERE transaction_id=?1 ORDER BY receipt_index")?
        .query_map([id.as_str()],|row|row.get(0))?.collect::<rusqlite::Result<_>>()?;
    let mut result = None;
    for json in rows {
        let record: ReceiptDescription = serde_json::from_str(&json)?;
        if matches!(record.stage, ReceiptStage::HistoryCommitted(_)) {
            if record.scope.transaction_id != *id || result.is_some() {
                return Err(invalid());
            }
            result = Some(record);
        }
    }
    Ok(result)
}

pub(super) fn current_baseline_matches(
    connection: &Connection,
    description: &super::WebDavNativeDescription,
    current: Option<&str>,
) -> Result<bool> {
    let Some(record) = committed(connection, &description.request.transaction_id)? else {
        return Ok(current == Some(description.request.baseline.as_str()));
    };
    let ReceiptEvidence::History { final_snapshot, .. } = &record.evidence else {
        return Err(invalid());
    };
    if record.scope.description_hash != ContentId::hash(&serde_json::to_vec(description)?)
        || record.scope.request_hash != description.inventory.request_hash
    {
        return Err(invalid());
    }
    Ok(current == Some(final_snapshot.as_str()))
}

#[cfg(windows)]
pub(super) fn verify_transition(
    before: &crate::storage_capacity::CapacitySnapshot,
    after: &crate::storage_capacity::CapacitySnapshot,
    history: &FutureHistory,
    record: &ReceiptDescription,
    fingerprint: &ContentId,
    json: &str,
) -> Result<()> {
    let values = |snapshot: &crate::storage_capacity::CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.columns()
                        .iter()
                        .map(|column| column.value.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let mut expected = values(before);
    let clock = expected
        .get_mut(&("webdav_native_clock".into(), vec!["1".into()]))
        .ok_or_else(invalid)?;
    if !matches!(clock.as_slice(),[Value::Integer(1),Value::Integer(time)]
        if *time<=record.recorded_at_ms)
    {
        return Err(invalid());
    }
    clock[1] = Value::Integer(record.recorded_at_ms);
    if expected
        .insert(
            (
                "webdav_native_execution_receipts".into(),
                vec![
                    record.scope.transaction_id.to_string(),
                    record.index.to_string(),
                ],
            ),
            vec![
                Value::Text(record.scope.transaction_id.to_string()),
                Value::Integer(record.index as u64),
                Value::Integer(record.template_index as u64),
                Value::Text(fingerprint.to_string()),
                Value::Integer(record.recorded_at_ms),
                Value::Text(json.into()),
            ],
        )
        .is_some()
    {
        return Err(invalid());
    }
    for row in &history.rows {
        let key = (row.table.clone(), row.primary_key.clone());
        if expected.get(&key) != row.prior.as_ref() {
            return Err(invalid());
        }
        expected.remove(&key);
        if let Some(future) = &row.future {
            expected.insert(key, future.clone());
        }
    }
    if expected != values(after)
        || !after.report.within_accounted_limits()
        || !after.report.coverage_gaps().is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}
