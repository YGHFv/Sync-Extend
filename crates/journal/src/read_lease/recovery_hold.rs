//! A restored archive can keep the original lease rows without issuing leases.
use crate::{JournalError, JournalStorageColumnValue, JournalStoredRow, Result};
use rusqlite::Connection;
use sync_extend_core_model::ContentId;

pub(crate) const KEY: &str = "original.recovered-read-lease-hold.v1";

pub(crate) fn inventory(rows: &[JournalStoredRow]) -> ContentId {
    let mut digest = blake3::Hasher::new();
    digest.update(b"sync-extend.archived-read-lease-hold.v1");
    for row in rows.iter().filter(|row| {
        matches!(
            row.table(),
            "read_lease_clock" | "read_leases" | "read_lease_objects"
        )
    }) {
        digest.update(row.fingerprint().as_str().as_bytes());
    }
    ContentId::from_hasher(&digest)
}

pub(crate) fn validate_rows(rows: &[JournalStoredRow]) -> Result<()> {
    let Some(hold) = rows
        .iter()
        .find(|row| row.table() == "local_state" && row.primary_key() == [KEY])
    else {
        return Ok(());
    };
    let held_id = hold
        .columns()
        .iter()
        .find(|column| column.name == "value")
        .map(|column| &column.value);
    if !matches!(held_id, Some(JournalStorageColumnValue::Text(id))
        if id == inventory(rows).as_str())
        || !rows.iter().any(|row| {
            row.table() == "read_leases"
                && row.columns().iter().any(|column| {
                    column.name == "state"
                        && matches!(&column.value, JournalStorageColumnValue::Text(value) if value == "active")
                })
        })
    {
        return Err(JournalError::Invariant(
            "recovered read lease hold inventory differs",
        ));
    }
    Ok(())
}

// Every effectful lease path advances the clock in its own write transaction.
// Keep both the shared watermark and every original owner and pin immutable.
pub(super) fn require_mutable(connection: &Connection) -> Result<()> {
    let held: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.local_state WHERE key=?1)",
        [KEY],
        |row| row.get(0),
    )?;
    if held {
        return Err(JournalError::Invariant(
            "recovered read lease owners are held as immutable history",
        ));
    }
    Ok(())
}
