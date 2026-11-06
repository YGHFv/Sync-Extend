//! Immutable globally single-use future resource names, not native identity IDs.
use crate::{
    storage_inventory::reader::{add, invalid},
    Result,
};
use rusqlite::Connection;
use std::collections::BTreeSet;
use sync_extend_core_model::{
    tree_native_future_obligations::TreeNativeFutureGenerations, EntryId,
};

pub(super) fn ids(plan: &TreeNativeFutureGenerations) -> Result<BTreeSet<EntryId>> {
    let ids: BTreeSet<_> = [&plan.finalization_id, &plan.cleanup_id]
        .into_iter()
        .chain(plan.attempt_ids.values())
        .chain(plan.disposal_ids.values())
        .cloned()
        .collect();
    let expected = add(
        2,
        add(
            plan.attempt_ids.len() as u64,
            plan.disposal_ids.len() as u64,
        )?,
    )?;
    if ids.len() as u64 != expected {
        return Err(invalid("tree future generation alias"));
    }
    Ok(ids)
}

pub(super) fn audit_external(
    connection: &Connection,
    ids: &BTreeSet<EntryId>,
    max: usize,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let refs = ids.iter().collect();
    crate::tree_disposition_generations::audit_names(connection, &refs, max)?;
    let mut statement = connection.prepare(
        "SELECT admission_id FROM tree_restore_coordinator_admissions
         UNION ALL SELECT disposition_id FROM tree_restore_disposition_intents
         UNION ALL SELECT plan_id FROM original_disposals
         UNION ALL SELECT plan_id FROM gc_quarantines",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(invalid("tree future historical generation inventory"))?;
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        if ids.contains(&id) {
            return Err(invalid("tree future historical generation collision"));
        }
    }
    Ok(())
}

pub(super) fn stored(connection: &Connection, max: usize) -> Result<BTreeSet<EntryId>> {
    let mut statement = connection.prepare(
        "SELECT generation_id FROM main.tree_native_future_generations ORDER BY generation_id",
    )?;
    let mut rows = statement.query([])?;
    let mut ids = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        if ids.len() >= max || !ids.insert(id) {
            return Err(invalid("tree future stored generation inventory"));
        }
    }
    audit_external(connection, &ids, max)?;
    Ok(ids)
}

pub(super) fn admit(
    connection: &Connection,
    proposed: &TreeNativeFutureGenerations,
    max: usize,
) -> Result<()> {
    let prior = stored(connection, max)?;
    let ids = ids(proposed)?;
    if prior.len().checked_add(ids.len()).is_none_or(|n| n > max)
        || ids.iter().any(|id| prior.contains(id))
    {
        return Err(invalid("tree future generation single use"));
    }
    audit_external(connection, &ids, max)
}
