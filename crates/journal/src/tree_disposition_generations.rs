//! Single-use disposition generations across retained historical namespaces.
use crate::{JournalError, Result};
use rusqlite::Connection;
use std::collections::BTreeSet;
use sync_extend_core_model::{tree_original_disposition::TreeOriginalDispositionPlan, EntryId};

fn existing(connection: &Connection, max: usize) -> Result<BTreeSet<EntryId>> {
    let mut statement =
        connection.prepare("SELECT disposition_id FROM tree_restore_disposition_intents")?;
    let mut rows = statement.query([])?;
    let mut ids = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        if ids.len() >= max || !ids.insert(id) {
            return Err(JournalError::Invariant(
                "tree disposition generation inventory",
            ));
        }
    }
    Ok(ids)
}

fn audit_names(connection: &Connection, ids: &BTreeSet<&EntryId>, max: usize) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut statement = connection.prepare(
        "SELECT transaction_id FROM tree_restore_preparations
         UNION ALL SELECT execution_id FROM tree_restore_execution_intents
         UNION ALL SELECT execution_id FROM tree_restore_execution_step_intents
         UNION ALL SELECT transaction_id FROM publications
         UNION ALL SELECT json_extract(intent,'$.entry_id') FROM publications
         UNION ALL SELECT transaction_id FROM mutations
         UNION ALL SELECT json_extract(execution,'$.execution_id') FROM mutations
             WHERE execution IS NOT NULL
         UNION ALL SELECT owner_id FROM reference_reservations
         UNION ALL SELECT lease_id FROM read_leases
         UNION ALL SELECT mark_id FROM gc_marks
         UNION ALL SELECT authorization_id FROM gc_authorizations
         UNION ALL SELECT execution_id FROM gc_executions
         UNION ALL SELECT disposal_id FROM gc_disposals
         UNION ALL SELECT j.value FROM tree_restore_histories h,
             json_each(h.intent,'$.history.fresh_entry_ids') j",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant(
                "tree disposition namespace inventory",
            ))?;
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        if ids.contains(&id) {
            return Err(JournalError::Invariant(
                "tree disposition historical namespace collision",
            ));
        }
    }
    crate::tree_restore_execution_intent::audit_logical_generations(connection, ids, max)
}

pub(crate) fn audit_inventory(connection: &Connection, max: usize) -> Result<()> {
    let ids = existing(connection, max)?;
    audit_names(connection, &ids.iter().collect(), max)
}

pub(crate) fn admit(
    connection: &Connection,
    plan: &TreeOriginalDispositionPlan,
    max: usize,
) -> Result<()> {
    let old = existing(connection, max)?;
    let ids: BTreeSet<_> = plan.input().disposition_ids.values().collect();
    if ids.len() != plan.input().disposition_ids.len()
        || old.len().checked_add(ids.len()).is_none_or(|n| n > max)
        || ids.iter().any(|id| old.contains(*id))
    {
        return Err(JournalError::Invariant(
            "tree disposition generation single use",
        ));
    }
    audit_names(connection, &ids, max)
}
