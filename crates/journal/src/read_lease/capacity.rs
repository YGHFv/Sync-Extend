use crate::{
    storage_capacity::CapacitySnapshot, JournalError, JournalStorageCapacity, JournalStorageColumn,
    JournalStorageColumnValue, ReadLease, Result,
};
use std::collections::BTreeMap;
use sync_extend_core_model::EntryId;

pub(super) fn within(report: &JournalStorageCapacity) -> Result<()> {
    if !report.within_accounted_limits() {
        return Err(JournalError::Invariant(
            "journal configured capacity exceeded",
        ));
    }
    Ok(())
}

pub(super) fn expected_lease(actual: &ReadLease, expected: &ReadLease) -> Result<()> {
    if actual.intent != expected.intent
        || actual.state != expected.state
        || actual.observed_at_ms != expected.observed_at_ms
        || actual.expires_at_ms != expected.expires_at_ms
        || actual.finished_at_ms != expected.finished_at_ms
    {
        return Err(JournalError::Invariant(
            "lease changed during capacity transaction",
        ));
    }
    Ok(())
}

pub(super) fn identity(snapshot: &CapacitySnapshot) -> Vec<Vec<JournalStorageColumn>> {
    snapshot
        .rows
        .iter()
        .filter(|row| row.table() == "local_state")
        .map(|row| row.columns().to_vec())
        .collect()
}

pub(super) fn same_identity(
    before: &[Vec<JournalStorageColumn>],
    after: &CapacitySnapshot,
) -> Result<()> {
    if before != identity(after).as_slice() {
        return Err(JournalError::Invariant(
            "lease transaction changed local identity",
        ));
    }
    Ok(())
}

pub(super) fn observed(snapshot: &CapacitySnapshot, now: u64) -> Result<()> {
    let clock = snapshot
        .rows
        .iter()
        .find(|row| row.table() == "read_lease_clock")
        .ok_or(JournalError::Invariant("lease clock missing after write"))?;
    if !clock.columns().iter().any(|column| {
        column.name == "observed_at_ms" && column.value == JournalStorageColumnValue::Integer(now)
    }) {
        return Err(JournalError::Invariant(
            "lease clock changed during capacity transaction",
        ));
    }
    Ok(())
}

fn replace(
    columns: &mut [JournalStorageColumn],
    name: &str,
    value: JournalStorageColumnValue,
) -> Result<()> {
    columns
        .iter_mut()
        .find(|column| column.name == name)
        .ok_or(JournalError::Invariant("lease release column missing"))?
        .value = value;
    Ok(())
}

pub(super) fn released(
    before: &CapacitySnapshot,
    after: &CapacitySnapshot,
    id: &EntryId,
    now: u64,
) -> Result<()> {
    let mut remaining: BTreeMap<_, _> = after
        .rows
        .iter()
        .map(|row| ((row.table(), row.primary_key()), row.columns()))
        .collect();
    let mut own = 0;
    let mut clocks = 0;
    for row in &before.rows {
        let target = row.primary_key().first().map(String::as_str) == Some(id.as_str());
        if row.table() == "read_lease_objects" && target {
            continue;
        }
        let mut expected = row.columns().to_vec();
        if row.table() == "read_leases" && target {
            own += 1;
            replace(
                &mut expected,
                "state",
                JournalStorageColumnValue::Text("released".into()),
            )?;
            replace(
                &mut expected,
                "finished_at_ms",
                JournalStorageColumnValue::Integer(now),
            )?;
        } else if row.table() == "read_lease_clock" {
            clocks += 1;
            replace(
                &mut expected,
                "observed_at_ms",
                JournalStorageColumnValue::Integer(now),
            )?;
        }
        if remaining.remove(&(row.table(), row.primary_key())) != Some(expected.as_slice()) {
            return Err(JournalError::Invariant(
                "lease release changed unrelated values",
            ));
        }
    }
    let prior = before.report.accounted_total();
    let next = after.report.accounted_total();
    if own != 1
        || clocks != 1
        || !remaining.is_empty()
        || next.rows > prior.rows
        || next.logical_bytes > prior.logical_bytes
    {
        return Err(JournalError::Invariant(
            "lease release exact capacity transition",
        ));
    }
    Ok(())
}
