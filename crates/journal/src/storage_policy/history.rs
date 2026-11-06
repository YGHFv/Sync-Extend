use crate::{
    storage_capacity::CapacitySnapshot, JournalError, JournalStorageCapacity, JournalStorageColumn,
    JournalStorageColumnValue, Result, SnapshotPruning,
};
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, SnapshotId};

pub(crate) fn within(report: &JournalStorageCapacity) -> Result<()> {
    if !report.within_accounted_limits() {
        return Err(JournalError::Invariant(
            "journal configured history capacity exceeded",
        ));
    }
    Ok(())
}

fn text(name: &str, value: &str) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: JournalStorageColumnValue::Text(value.into()),
    }
}

fn integer(name: &str, value: u64) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: JournalStorageColumnValue::Integer(value),
    }
}

pub(crate) fn initialized(
    before: &CapacitySnapshot,
    after: &CapacitySnapshot,
    identity: &[(&str, &str); 3],
) -> Result<()> {
    let primary_keys: Vec<_> = identity.iter().map(|(key, _)| [key.to_string()]).collect();
    let mut remaining: BTreeMap<_, _> = after
        .rows
        .iter()
        .map(|row| ((row.table(), row.primary_key()), row.columns()))
        .collect();
    for row in &before.rows {
        if row.table() == "local_state"
            || remaining.remove(&(row.table(), row.primary_key())) != Some(row.columns())
        {
            return Err(JournalError::Invariant(
                "initialization changed unrelated values",
            ));
        }
    }
    for ((key, value), primary_key) in identity.iter().zip(&primary_keys) {
        let expected = [text("key", key), text("value", value)];
        if remaining.remove(&("local_state", primary_key.as_slice())) != Some(expected.as_slice()) {
            return Err(JournalError::Invariant(
                "initialization identity receipt mismatch",
            ));
        }
    }
    if !remaining.is_empty() {
        return Err(JournalError::Invariant(
            "initialization created unrelated rows",
        ));
    }
    Ok(())
}

pub(crate) fn snapshot_locked(
    before: &CapacitySnapshot,
    after: &CapacitySnapshot,
    id: &SnapshotId,
    locked: bool,
) -> Result<()> {
    let mut remaining: BTreeMap<_, _> = after
        .rows
        .iter()
        .map(|row| ((row.table(), row.primary_key()), row.columns()))
        .collect();
    let mut own = 0;
    let primary_key = [id.to_string()];
    for row in &before.rows {
        let mut expected = row.columns().to_vec();
        if row.table() == "snapshots" && row.primary_key() == primary_key.as_slice() {
            own += 1;
            expected
                .iter_mut()
                .find(|column| column.name == "locked")
                .ok_or(JournalError::Invariant("snapshot lock column missing"))?
                .value = JournalStorageColumnValue::Integer(u64::from(locked));
        }
        if remaining.remove(&(row.table(), row.primary_key())) != Some(expected.as_slice()) {
            return Err(JournalError::Invariant(
                "snapshot lock changed unrelated values",
            ));
        }
    }
    if own != 1
        || !remaining.is_empty()
        || after.report.accounted_total() != before.report.accounted_total()
    {
        return Err(JournalError::Invariant(
            "snapshot lock exact capacity transition",
        ));
    }
    Ok(())
}

pub(crate) fn admit_pruning(before: &CapacitySnapshot, json: &str) -> Result<()> {
    let prior = before.report.accounted_total();
    let limits = before.report.limits();
    // The immutable receipt is inserted while every old snapshot pin still exists.
    if prior
        .rows
        .checked_add(1)
        .is_none_or(|rows| rows > limits.max_rows)
        || prior
            .logical_bytes
            .checked_add(232)
            .and_then(|bytes| bytes.checked_add(json.len() as u64))
            .is_none_or(|bytes| bytes > limits.max_logical_bytes)
    {
        return Err(JournalError::Invariant(
            "snapshot pruning receipt peak exceeds capacity",
        ));
    }
    Ok(())
}

pub(crate) fn snapshot_pruned(
    before: &CapacitySnapshot,
    after: &CapacitySnapshot,
    intent: &SnapshotPruning,
    json: &str,
) -> Result<()> {
    let mut remaining: BTreeMap<_, _> = after
        .rows
        .iter()
        .map(|row| ((row.table(), row.primary_key()), row.columns()))
        .collect();
    for row in &before.rows {
        if row.table() == "snapshot_objects"
            && row.primary_key().first().map(String::as_str) == Some(intent.snapshot_id.as_str())
        {
            continue;
        }
        if remaining.remove(&(row.table(), row.primary_key())) != Some(row.columns()) {
            return Err(JournalError::Invariant(
                "snapshot pruning changed unrelated values",
            ));
        }
    }
    let primary_key = [intent.snapshot_id.to_string()];
    let expected = [
        text("snapshot_id", intent.snapshot_id.as_str()),
        text("space_id", intent.space_id.as_str()),
        text("baseline_root", intent.baseline_root.as_str()),
        text("intent", json),
        text("intent_hash", ContentId::hash(json.as_bytes()).as_str()),
        integer("pruned_at_ms", intent.pruned_at_ms),
    ];
    if remaining.remove(&("snapshot_prunings", primary_key.as_slice())) != Some(expected.as_slice())
        || !remaining.is_empty()
    {
        return Err(JournalError::Invariant(
            "snapshot pruning exact receipt mismatch",
        ));
    }
    Ok(())
}
