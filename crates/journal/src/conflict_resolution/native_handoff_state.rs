//! Exact complete original history handoff; never a snapshot impersonation.
use super::*;

pub(super) fn present(connection: &Connection, parent: &Header) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_native_phases WHERE transaction_id=?1 AND phase='history_handoff')",
        [parent.transaction_id.as_str()],|r|r.get(0),
    )?)
}
pub(crate) fn reference_terminal(
    connection: &Connection,
    intent: &crate::ReferenceReservationIntent,
) -> Result<bool> {
    use rusqlite::OptionalExtension;
    let json: Option<String>=connection.query_row(
        "SELECT a.header FROM main.conflict_resolution_admissions a
         JOIN main.conflict_resolution_native_branch_handoffs b USING(transaction_id)
         JOIN main.conflict_resolution_native_phases p ON p.transaction_id=b.transaction_id AND p.phase='history_handoff'
         WHERE b.owner_id=?1",
        [intent.owner_id.as_str()],|r|r.get(0),
    ).optional()?;
    let Some(json) = json else {
        return Ok(false);
    };
    let parent: Header = serde_json::from_str(&json)?;
    native_final_state::exact_history(connection, &parent)?;
    let header = native_ledger_storage::stored(connection, &parent)?
        .ok_or(invalid("conflict complete handoff header missing"))?;
    if !header
        .history
        .branch_owners
        .iter()
        .any(|o| &o.intent == intent)
    {
        return Err(invalid("conflict complete history owner intent differs"));
    }
    Ok(true)
}
