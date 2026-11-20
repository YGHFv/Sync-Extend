//! Retained native metadata budget until an explicit original cleanup contract.
//! History commit/cancel and restart diagnostics cannot release this liability.
use super::{OriginalLocalHistoryReservation, Stored};
use crate::{JournalError, JournalStoredRow, Result};
use rusqlite::{params, Transaction};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};

const NAMESPACE: &str = "original.native-create.liability.";
pub(super) const PREFIX: &str = "original.native-create.liability.v1.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Liability {
    version: u32,
    attempt: EntryId,
    original_reservation: String,
    reservation_digest: ContentId,
}

fn parse(key: &str, json: &str) -> Result<(Liability, Stored)> {
    if json.len() > crate::MAX_OPERATION_BYTES {
        return Err(JournalError::Invariant(
            "original native liability byte bound",
        ));
    }
    let liability: Liability = serde_json::from_str(json)?;
    super::persisted_charge(
        &liability.original_reservation,
        sync_extend_core_model::limits::MAX_ENTRIES,
    )?;
    let stored: Stored = serde_json::from_str(&liability.original_reservation)?;
    if liability.version != 1
        || key != format!("{PREFIX}{}", liability.attempt)
        || liability.attempt != stored.attempt
        || liability.reservation_digest
            != ContentId::hash(liability.original_reservation.as_bytes())
        || serde_json::to_string(&liability)? != json
    {
        return Err(JournalError::Invariant(
            "original native liability schema attempt digest",
        ));
    }
    Ok((liability, stored))
}

pub(super) fn insert(tx: &Transaction<'_>, exact_json: &str) -> Result<()> {
    let stored: Stored = serde_json::from_str(exact_json)?;
    stored.validate(sync_extend_core_model::limits::MAX_ENTRIES)?;
    let key = format!("{PREFIX}{}", stored.attempt);
    let json = serde_json::to_string(&Liability {
        version: 1,
        attempt: stored.attempt,
        original_reservation: exact_json.to_owned(),
        reservation_digest: ContentId::hash(exact_json.as_bytes()),
    })?;
    parse(&key, &json)?;
    tx.execute("INSERT INTO local_state VALUES (?1,?2)", params![key, json])?;
    Ok(())
}

fn field<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant(
            "original native liability expected text",
        )),
    }
}

#[allow(dead_code)]
pub(crate) fn validate_rows(rows: &[JournalStoredRow]) -> Result<TreeStorageCharge> {
    let mut charge = TreeStorageCharge {
        rows: 0,
        logical_bytes: 0,
    };
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with(NAMESPACE))
    }) {
        let key = row.primary_key().first().ok_or(JournalError::Invariant(
            "original native liability key absent",
        ))?;
        let (_, stored) = parse(key, field(row, "value")?)?;
        let state = |key: &str| -> Result<&str> {
            let row = rows
                .iter()
                .find(|row| row.table() == "local_state" && row.primary_key() == [key.to_owned()])
                .ok_or(JournalError::Invariant(
                    "original native liability local identity absent",
                ))?;
            field(row, "value")
        };
        if state("space_id")? != stored.baseline.space_id.as_str()
            || state("device_id")? != stored.original_device.as_str()
            || ContentId::hash(state("worktree")?.as_bytes()) != stored.original_worktree_digest
        {
            return Err(JournalError::Invariant(
                "original native liability foreign identity",
            ));
        }
        let baseline = stored.baseline.root()?;
        let snapshot = rows
            .iter()
            .find(|row| row.table() == "snapshots" && row.primary_key() == [baseline.to_string()])
            .ok_or(JournalError::Invariant(
                "original native liability baseline snapshot absent",
            ))?;
        if field(snapshot, "manifest")? != serde_json::to_string(&stored.baseline)? {
            return Err(JournalError::Invariant(
                "original native liability exact baseline snapshot differs",
            ));
        }
        if super::linux_terminal::cleaned_rows(rows, &stored.attempt)? {
            continue;
        }
        charge.rows = charge
            .rows
            .checked_add(stored.native_footprint.phase_record_count + 2)
            .ok_or(JournalError::Invariant(
                "original native liability row charge overflow",
            ))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add(stored.native_footprint.metadata_peak_bytes)
            .ok_or(JournalError::Invariant(
                "original native liability byte charge overflow",
            ))?;
    }
    Ok(charge)
}

pub(crate) fn legacy_charge(connection: &rusqlite::Connection) -> Result<TreeStorageCharge> {
    let mut charge = TreeStorageCharge {
        rows: 0,
        logical_bytes: 0,
    };
    let mut query = connection.prepare(
        "SELECT key,length(CAST(value AS BLOB)),value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
    )?;
    let mut rows = query.query(params![
        i64::try_from(NAMESPACE.len())
            .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
        NAMESPACE,
        i64::try_from(sync_extend_core_model::limits::MAX_ENTRIES + 1)
            .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?
    ])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count += 1;
        let bytes: i64 = row.get(1)?;
        if count > sync_extend_core_model::limits::MAX_ENTRIES
            || bytes < 0
            || bytes as u64 > crate::MAX_OPERATION_BYTES as u64
        {
            return Err(JournalError::Invariant(
                "original native liability inventory byte count",
            ));
        }
        let key: String = row.get(0)?;
        let json: String = row.get(2)?;
        let (_, stored) = parse(&key, &json)?;
        let state = |key: &str| -> Result<String> {
            Ok(connection.query_row(
                "SELECT value FROM local_state WHERE key=?1",
                [key],
                |row| row.get(0),
            )?)
        };
        if state("space_id")? != stored.baseline.space_id.as_str()
            || state("device_id")? != stored.original_device.as_str()
            || ContentId::hash(state("worktree")?.as_bytes()) != stored.original_worktree_digest
        {
            return Err(JournalError::Invariant(
                "original native liability legacy foreign identity",
            ));
        }
        let actual: String = connection.query_row(
            "SELECT manifest FROM snapshots WHERE snapshot_id=?1",
            [stored.baseline.root()?.as_str()],
            |row| row.get(0),
        )?;
        if actual != serde_json::to_string(&stored.baseline)? {
            return Err(JournalError::Invariant(
                "original native liability legacy baseline differs",
            ));
        }
        if super::linux_terminal::cleaned_connection(connection, &stored.attempt)? {
            continue;
        }
        charge.rows = charge
            .rows
            .checked_add(stored.native_footprint.phase_record_count + 3)
            .ok_or(JournalError::Invariant(
                "original native liability legacy row overflow",
            ))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add(stored.native_footprint.metadata_peak_bytes)
            .and_then(|bytes| bytes.checked_add((key.len() + json.len()) as u64))
            .ok_or(JournalError::Invariant(
                "original native liability legacy byte overflow",
            ))?;
    }
    Ok(charge)
}

impl OriginalLocalHistoryReservation {
    pub fn native_liability_key(&self) -> String {
        format!("{PREFIX}{}", self.attempt)
    }
}

pub(crate) fn protected_content(
    connection: &rusqlite::Connection,
) -> Result<std::collections::BTreeSet<ContentId>> {
    // Validate original identities/snapshots before returning any owner set.
    legacy_charge(connection)?;
    let mut query = connection.prepare(
        "SELECT key,value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
    )?;
    let rows = query.query_map(
        params![
            i64::try_from(NAMESPACE.len())
                .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
            NAMESPACE,
            i64::try_from(sync_extend_core_model::limits::MAX_ENTRIES)
                .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?
        ],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut result = std::collections::BTreeSet::new();
    for row in rows {
        let (key, json) = row?;
        let (_, stored) = parse(&key, &json)?;
        if super::linux_terminal::cleaned_connection(connection, &stored.attempt)? {
            continue;
        }
        for content in stored
            .planned
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &content.chunks {
                result.insert(chunk.content_id.clone());
            }
        }
    }
    Ok(result)
}

pub(crate) fn verify_pending_connection(
    connection: &rusqlite::Connection,
    json: &str,
) -> Result<()> {
    super::persisted_charge(json, sync_extend_core_model::limits::MAX_ENTRIES)?;
    let stored: Stored = serde_json::from_str(json)?;
    let key = format!("{PREFIX}{}", stored.attempt);
    let exact: String = connection.query_row(
        "SELECT value FROM local_state WHERE key=?1",
        [&key],
        |row| row.get(0),
    )?;
    let (liability, _) = parse(&key, &exact)?;
    if liability.original_reservation != json {
        return Err(JournalError::Invariant(
            "original pending differs from retained native exact bytes",
        ));
    }
    Ok(())
}

pub(crate) fn verify_pending_rows(json: &str, rows: &[JournalStoredRow]) -> Result<()> {
    let stored: Stored = serde_json::from_str(json)?;
    let key = format!("{PREFIX}{}", stored.attempt);
    let native = rows
        .iter()
        .find(|row| row.table() == "local_state" && row.primary_key() == [key.clone()])
        .ok_or(JournalError::Invariant(
            "original pending native liability absent",
        ))?;
    let (liability, _) = parse(&key, field(native, "value")?)?;
    if liability.original_reservation != json {
        return Err(JournalError::Invariant(
            "original pending native row exact bytes differ",
        ));
    }
    Ok(())
}

pub(super) fn original_for_phase(key: &str, json: &str) -> Result<Stored> {
    Ok(parse(key, json)?.1)
}
