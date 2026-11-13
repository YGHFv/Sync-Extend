//! Original owner progress only. File/directory steps and final history stay closed.
use crate::{
    storage_inventory::reader::{hash, invalid},
    JournalStorageColumnValue, JournalStoredRow, Result, TreeRestorePreparation,
    MAX_OPERATION_BYTES,
};
use rusqlite::{types::Value, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_native_action_layout::{
        plan_tree_native_action_layout, TreeNativeActionLayoutPlan, TreeNativeActionLayoutRecord,
        TreeNativeActionPayload, TreeNativeActionScope,
    },
    tree_restore_history::encode_history_record,
    tree_storage_capacity::TreeStorageCharge,
    tree_storage_footprint::{tree_native_action_row_values, TreeStorageColumnValue},
    ContentId, EntryId,
};

#[cfg(windows)]
mod cleanup;
mod disposition_state;
mod final_state;
pub(crate) mod issuance;
#[cfg(windows)]
pub(crate) mod owner;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    format_version: u32,
    scope: TreeNativeActionScope,
    layout_hash: ContentId,
    full_capacity_hash: ContentId,
    intended_record_hash: ContentId,
    attempt_id: EntryId,
    action_ordinal: usize,
    intended_record_index: usize,
    attempted_at_ms: u64,
}

pub(crate) struct Progress {
    #[cfg(windows)]
    pub(crate) records: Vec<TreeNativeActionLayoutRecord>,
    #[cfg(windows)]
    pub(crate) layout: TreeNativeActionLayoutPlan,
    pub(crate) fulfilled: BTreeMap<(String, Vec<String>), TreeStorageCharge>,
}

fn row_values(row: &JournalStoredRow) -> Result<Vec<Value>> {
    row.columns()
        .iter()
        .map(|column| {
            Ok(match &column.value {
                JournalStorageColumnValue::Text(value) => Value::Text(value.clone()),
                JournalStorageColumnValue::Integer(value) => {
                    Value::Integer(crate::sql_integer(*value)?)
                }
                JournalStorageColumnValue::Null => Value::Null,
            })
        })
        .collect()
}

fn text(row: &JournalStoredRow, name: &str) -> Result<String> {
    match row.columns().iter().find(|column| column.name == name) {
        Some(column) => match &column.value {
            JournalStorageColumnValue::Text(value) => Ok(value.clone()),
            _ => Err(invalid("tree progress text type")),
        },
        None => Err(invalid("tree progress named column absent")),
    }
}

pub(crate) fn preflight(connection: &Connection) -> Result<()> {
    validate_schema(connection)?;
    let orphan = crate::tree_native_future::schema::EFFECT_TABLES.iter()
        .filter(|table| table.name != "tree_native_action_attempts")
        .map(|table| format!(
            "EXISTS(SELECT 1 FROM main.{} e LEFT JOIN main.tree_native_future_admissions f USING(transaction_id) WHERE f.transaction_id IS NULL)",
            table.name,
        )).collect::<Vec<_>>().join(" OR ");
    let unexpected: bool = connection.query_row(
        &format!(
            "SELECT {} OR EXISTS(
                SELECT 1 FROM main.tree_native_action_attempts a
                LEFT JOIN main.tree_native_future_admissions f USING(transaction_id)
             WHERE f.transaction_id IS NULL OR a.action_ordinal>=f.action_count)
             OR EXISTS(
                SELECT 1 FROM main.tree_native_action_records r
                WHERE r.record_index>0 AND NOT EXISTS(
                    SELECT 1 FROM main.tree_native_future_admissions f
                    WHERE f.transaction_id=r.transaction_id
                    AND r.record_index<2*f.action_count))",
            orphan
        ),
        [],
        |row| row.get(0),
    )?;
    if unexpected {
        return Err(invalid("tree unsupported native step or orphan progress"));
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    let triggers = [
        include_str!("migration-052.sql"),
        include_str!("migration-053.sql"),
        include_str!("migration-054.sql"),
        include_str!("migration-055.sql"),
    ]
    .join("\n");
    let mut expected_triggers = BTreeMap::new();
    for body in triggers.split("CREATE TRIGGER ").skip(1) {
        let end = body
            .find("END;")
            .ok_or(invalid("tree owner schema source malformed"))?;
        let expected = format!("CREATE TRIGGER {}", &body[..end + 3]);
        let name = body
            .split_whitespace()
            .next()
            .ok_or(invalid("tree owner trigger name absent"))?;
        expected_triggers.insert(name, expected);
    }
    for (name, expected) in expected_triggers {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(|sql| sql.trim_end_matches(';'))
            != Some(expected.trim_end_matches(';'))
        {
            return Err(invalid("tree owner exact issuer trigger changed"));
        }
    }
    Ok(())
}

pub(crate) fn audit(
    connection: &Connection,
    preparation: &TreeRestorePreparation,
    rows: &[JournalStoredRow],
    max: usize,
) -> Result<Progress> {
    let prewrite = preparation
        .native_storage
        .as_ref()
        .ok_or(invalid("tree progress prewrite absent"))?;
    let future = preparation
        .native_future_admission
        .as_ref()
        .ok_or(invalid("tree progress future reservation absent"))?;
    let (projection, protocol, _) = crate::tree_native_storage::initial_layout(
        connection,
        preparation,
        prewrite.request(),
        max,
    )?;
    let id = preparation.intent.transaction_id.as_str();
    let mut record_rows: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.table() == "tree_native_action_records"
                && row.primary_key().first().map(String::as_str) == Some(id)
        })
        .collect();
    record_rows.sort_by_key(|row| {
        row.primary_key()
            .get(1)
            .and_then(|index| index.parse::<usize>().ok())
    });
    if record_rows.is_empty() || record_rows.len() > prewrite.request().layout_limits.max_records {
        return Err(invalid("tree owner record count"));
    }
    let mut records = Vec::new();
    let mut encoded_bytes = 2u64;
    for (index, row) in record_rows.iter().enumerate() {
        let raw = text(row, "record")?;
        encoded_bytes = encoded_bytes
            .checked_add(raw.len() as u64 + u64::from(index != 0))
            .filter(|bytes| *bytes <= prewrite.request().layout_limits.max_encoded_bytes)
            .ok_or(invalid("tree owner aggregate record bytes exceeded"))?;
        let record: TreeNativeActionLayoutRecord = serde_json::from_str(&raw)?;
        let expected = tree_native_action_row_values(&prewrite.header().layout_hash, &record)?;
        let values: Vec<_> = expected
            .columns()
            .iter()
            .map(|column| match &column.value {
                TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
                TreeStorageColumnValue::Integer(value) => {
                    Ok(Value::Integer(crate::sql_integer(*value)?))
                }
            })
            .collect::<Result<_>>()?;
        if record.record_index != index
            || encode_history_record(&record, MAX_OPERATION_BYTES as u64)? != raw.as_bytes()
            || row_values(row)? != values
        {
            return Err(invalid("tree owner exact stored record"));
        }
        records.push(record);
    }
    if &records[0] != prewrite.intended() {
        return Err(invalid("tree owner immutable initial intention differs"));
    }
    let layout = plan_tree_native_action_layout(
        &projection.context(),
        &protocol,
        &records,
        prewrite.request().layout_limits,
    )?;
    let mut fulfilled = BTreeMap::new();
    for row in record_rows.iter().skip(1) {
        fulfilled.insert(
            (row.table().to_owned(), row.primary_key().to_vec()),
            TreeStorageCharge {
                rows: 1,
                logical_bytes: row.logical_bytes(),
            },
        );
    }
    let mut attempts = BTreeSet::new();
    for row in rows.iter().filter(|row| {
        row.table() == "tree_native_action_attempts"
            && row.primary_key().first().map(String::as_str) == Some(id)
    }) {
        let raw = text(row, "request")?;
        let attempt: Attempt = serde_json::from_str(&raw)?;
        let ordinal = attempt.action_ordinal;
        if ordinal >= layout.action_count() {
            return Err(invalid("tree unsupported native activation ordinal"));
        }
        let intended = records
            .get(ordinal * 2)
            .ok_or(invalid("tree owner attempt preceding intention absent"))?;
        if ordinal >= layout.action_count()
            || !attempts.insert(ordinal)
            || attempt.format_version != 1
            || attempt.scope != intended.scope
            || !matches!(intended.payload, TreeNativeActionPayload::Intended { .. })
            || attempt.intended_record_index != ordinal * 2
            || attempt.layout_hash != prewrite.header().layout_hash
            || attempt.full_capacity_hash != *future.capacity_hash()
            || attempt.intended_record_hash != hash(intended)?
            || future.generations().attempt_ids.get(&ordinal) != Some(&attempt.attempt_id)
            || attempt.attempted_at_ms < intended.recorded_at_ms
            || attempt.attempted_at_ms < future.request().created_at_ms
            || records
                .get(ordinal * 2 + 1)
                .is_some_and(|observed| observed.recorded_at_ms < attempt.attempted_at_ms)
            || encode_history_record(&attempt, MAX_OPERATION_BYTES as u64)? != raw.as_bytes()
            || row_values(row)? != attempt_values(&attempt)?
        {
            return Err(invalid("tree owner exact activation binding"));
        }
        fulfilled.insert(
            (row.table().to_owned(), row.primary_key().to_vec()),
            TreeStorageCharge {
                rows: 1,
                logical_bytes: row.logical_bytes(),
            },
        );
    }
    for record in records
        .iter()
        .filter(|record| matches!(record.payload, TreeNativeActionPayload::Observed { .. }))
    {
        if !attempts.contains(&record.action_ordinal) {
            return Err(invalid("tree owner observation without durable activation"));
        }
    }
    final_state::audit(
        connection,
        preparation,
        &records,
        &layout,
        rows,
        max,
        &mut fulfilled,
    )?;
    disposition_state::audit(
        connection,
        preparation,
        &records,
        &layout,
        rows,
        max,
        &mut fulfilled,
    )?;
    Ok(Progress {
        #[cfg(windows)]
        records,
        #[cfg(windows)]
        layout,
        fulfilled,
    })
}

pub(crate) fn validate_all(
    connection: &Connection,
    preparations: &[TreeRestorePreparation],
    max: usize,
) -> Result<()> {
    if !preparations
        .iter()
        .any(|preparation| preparation.native_future_admission.is_some())
    {
        return Ok(());
    }
    let specs = crate::storage_inventory::tables();
    let tables =
        crate::storage_inventory::reader::preflight(connection, &specs, max, max as u64 * 1024)?;
    let mut rows = Vec::new();
    for (spec, table) in specs.iter().zip(&tables) {
        rows.extend(crate::storage_inventory::reader::read_table(
            connection, spec, table,
        )?);
    }
    for preparation in preparations {
        if preparation.native_future_admission.is_some() {
            audit(connection, preparation, &rows, max)?;
        }
    }
    Ok(())
}

fn attempt_values(attempt: &Attempt) -> Result<Vec<Value>> {
    let scope = &attempt.scope;
    Ok(vec![
        Value::Text(scope.space_id.to_string()),
        Value::Text(scope.transaction_id.to_string()),
        Value::Text(scope.coordinator_execution_id.to_string()),
        Value::Text(scope.admission_id.to_string()),
        Value::Text(scope.admission_hash.to_string()),
        Value::Text(scope.protocol_hash.to_string()),
        Value::Text(attempt.layout_hash.to_string()),
        Value::Text(attempt.full_capacity_hash.to_string()),
        Value::Text(attempt.intended_record_hash.to_string()),
        Value::Text(attempt.attempt_id.to_string()),
        Value::Integer(crate::sql_integer(attempt.action_ordinal as u64)?),
        Value::Integer(crate::sql_integer(attempt.intended_record_index as u64)?),
        Value::Integer(crate::sql_integer(attempt.attempted_at_ms)?),
        Value::Text(hash(attempt)?.to_string()),
        Value::Text(serde_json::to_string(attempt)?),
    ])
}
