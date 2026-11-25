//! Original retained CAS release ledger. Hashes describe exact audited rows only.
use super::receipt_protocol::{ReceiptDescription, ReceiptEvidence, ReceiptStage};
use crate::{JournalError, Result};
use rusqlite::Connection;
use sync_extend_core_model::{
    ContentId, EntryId, SnapshotId, tree_restore_history::encode_history_record,
};
fn invalid() -> JournalError {
    JournalError::Invariant("original DAV exact retained CAS handoff")
}

pub(super) fn records(connection: &Connection, id: &EntryId) -> Result<Vec<ReceiptDescription>> {
    connection.prepare(
        "SELECT receipt FROM main.webdav_native_execution_receipts WHERE transaction_id=?1 ORDER BY receipt_index")?
        .query_map([id.as_str()],|row|row.get::<_,String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?.into_iter()
        .map(|json|Ok(serde_json::from_str(&json)?)).collect()
}
pub(super) fn terminal(connection: &Connection, id: &EntryId) -> Result<bool> {
    Ok(records(connection, id)?
        .last()
        .is_some_and(|record| record.stage == ReceiptStage::Terminal))
}
fn retained(connection: &Connection, id: &EntryId) -> Result<Vec<(String, u64)>> {
    Ok(connection.prepare(
        "SELECT content_id,length FROM main.webdav_native_objects WHERE transaction_id=?1 ORDER BY content_id")?
        .query_map([id.as_str()],|row|Ok((row.get(0)?,crate::sql_u64(row, 1)?)))?
        .collect::<rusqlite::Result<_>>()?)
}
fn description(
    retained: &[(String, u64)],
    final_snapshot: &SnapshotId,
    history_hash: &ContentId,
) -> Result<ReceiptEvidence> {
    Ok(ReceiptEvidence::References {
        final_snapshot: final_snapshot.clone(),
        history_hash: history_hash.clone(),
        retained_objects_hash: ContentId::hash(&encode_history_record(
            &retained,
            sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES,
        )?),
    })
}
/// Before release the original live issuer requires actual snapshot pins.
pub(super) fn evidence(
    connection: &Connection,
    id: &EntryId,
    final_snapshot: &SnapshotId,
    history_hash: &ContentId,
) -> Result<ReceiptEvidence> {
    let retained = retained(connection, id)?;
    for (content, _length) in &retained {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshot_objects WHERE content_id=?1)",
            [content],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(invalid());
        }
    }
    description(&retained, final_snapshot, history_hash)
}
pub(super) fn audit(
    connection: &Connection,
    id: &EntryId,
    receipts: &[ReceiptDescription],
    final_snapshot: &SnapshotId,
    history_hash: &ContentId,
) -> Result<bool> {
    // Terminal records certify the historical handoff, not permanent native
    // ownership. Ordinary pruning is independently audited by its own protocol.
    let terminal = receipts
        .last()
        .is_some_and(|record| record.stage == ReceiptStage::Terminal);
    let expected = if terminal {
        description(&retained(connection, id)?, final_snapshot, history_hash)?
    } else {
        evidence(connection, id, final_snapshot, history_hash)?
    };
    let mut handed = false;
    for record in receipts {
        if matches!(
            record.stage,
            ReceiptStage::ReferenceHandoffRequested
                | ReceiptStage::ReferencesHandedOff
                | ReceiptStage::Terminal
        ) {
            if record.evidence != expected {
                return Err(invalid());
            }
            if record.stage == ReceiptStage::ReferencesHandedOff {
                handed = true;
            }
        }
    }
    Ok(handed)
}
