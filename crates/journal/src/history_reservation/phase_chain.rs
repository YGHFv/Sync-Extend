//! Complete original persisted chain. Read-only evidence; no restart issuer.
use super::{phase_evidence, Stored};
use crate::{JournalError, JournalStoredRow, Result};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{persisted_rename::RenameObservationMap, ContentId, EntryId};

const PREFIX: &str = "original.native-create.cursor.v1.";
const NAMESPACE: &str = "original.native-create.cursor.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u32,
    attempt: EntryId,
    reservation_digest: ContentId,
    phase_count: u32,
    tail_digest: Option<ContentId>,
}

/// Issued only inside the original history transaction after complete validation.
/// Exact phase bytes remain available for independent inspection.
pub struct OriginalNativePhaseChain {
    attempt: EntryId,
    exact_phase_json: Vec<String>,
    exact_digest: ContentId,
    intent_digest: ContentId,
    file_key: (u64, u64),
    parent_key: (u64, u64),
    payload_digest: ContentId,
    payload_bytes: u64,
}

impl OriginalNativePhaseChain {
    pub fn original_attempt(&self) -> &EntryId {
        &self.attempt
    }
    pub fn exact_phase_json(&self) -> &[String] {
        &self.exact_phase_json
    }
    pub fn exact_digest(&self) -> &ContentId {
        &self.exact_digest
    }
    pub fn verify_original_native(
        &self,
        intent: &[u8],
        file_key: (u64, u64),
        parent_key: (u64, u64),
        payload: &[u8],
    ) -> Result<()> {
        if self.intent_digest != ContentId::hash(intent)
            || self.file_key != file_key
            || self.parent_key != parent_key
            || self.payload_bytes != payload.len() as u64
            || self.payload_digest != ContentId::hash(payload)
            || self.exact_digest
                != ContentId::hash(&serde_json::to_vec(&(
                    1u32,
                    &self.attempt,
                    &self.exact_phase_json,
                ))?)
        {
            return Err(JournalError::Invariant(
                "original Final native values differ from persisted chain",
            ));
        }
        Ok(())
    }
}

fn cursor(key: &str, json: &str, stored: &Stored) -> Result<Cursor> {
    if json.len() > 4096 {
        return Err(JournalError::Invariant("original native cursor byte bound"));
    }
    let value: Cursor = serde_json::from_str(json)?;
    if value.version != 1
        || value.attempt != stored.attempt
        || value.phase_count > 4
        || value.reservation_digest != ContentId::hash(serde_json::to_string(stored)?.as_bytes())
        || key != format!("{PREFIX}{}", stored.attempt)
        || value.tail_digest.is_none() != (value.phase_count == 0)
        || serde_json::to_string(&value)? != json
    {
        return Err(JournalError::Invariant(
            "original native cursor canonical scope or progress differs",
        ));
    }
    Ok(value)
}

pub(super) fn insert(tx: &Transaction<'_>, exact_json: &str) -> Result<()> {
    let stored: Stored = serde_json::from_str(exact_json)?;
    let value = Cursor {
        version: 1,
        attempt: stored.attempt.clone(),
        reservation_digest: ContentId::hash(exact_json.as_bytes()),
        phase_count: 0,
        tail_digest: None,
    };
    let key = format!("{PREFIX}{}", value.attempt);
    let json = serde_json::to_string(&value)?;
    cursor(&key, &json, &stored)?;
    tx.execute("INSERT INTO local_state VALUES (?1,?2)", params![key, json])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn advance(
    tx: &Transaction<'_>,
    stored: &Stored,
    phase: &phase_evidence::Phase,
    json: &str,
) -> Result<()> {
    let key = format!("{PREFIX}{}", stored.attempt);
    let prior: String = tx.query_row(
        "SELECT value FROM local_state WHERE key=?1",
        [&key],
        |row| row.get(0),
    )?;
    let mut value = cursor(&key, &prior, stored)?;
    if value.phase_count != phase.sequence || value.tail_digest != phase.predecessor {
        return Err(JournalError::Invariant(
            "original native phase disagrees with retained cursor",
        ));
    }
    value.phase_count += 1;
    value.tail_digest = Some(ContentId::hash(json.as_bytes()));
    let next = serde_json::to_string(&value)?;
    cursor(&key, &next, stored)?;
    if tx.execute(
        "UPDATE local_state SET value=?1 WHERE key=?2 AND value=?3",
        params![next, key, prior],
    )? != 1
    {
        return Err(JournalError::Invariant(
            "original native cursor conditional update failed",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn field<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant(
            "original native cursor inventory requires text",
        )),
    }
}

fn verify_inventory(values: &BTreeMap<String, String>) -> Result<()> {
    let mut expected = std::collections::BTreeSet::new();
    for (key, json) in values
        .iter()
        .filter(|(key, _)| key.starts_with("original.native-create.liability."))
    {
        let stored = super::liability::original_for_phase(key, json)?;
        let cursor_key = format!("{PREFIX}{}", stored.attempt);
        let cursor_json = values.get(&cursor_key).ok_or(JournalError::Invariant(
            "retained native liability cursor absent",
        ))?;
        let progress = cursor(&cursor_key, cursor_json, &stored)?;
        expected.insert(cursor_key);
        let mut tail = None;
        for sequence in 0..progress.phase_count {
            let phase_key = format!("{}{}.{sequence:04}", phase_evidence::PREFIX, stored.attempt);
            let phase_json = values.get(&phase_key).ok_or(JournalError::Invariant(
                "retained native cursor phase absent",
            ))?;
            tail = Some(ContentId::hash(phase_json.as_bytes()));
            expected.insert(phase_key);
        }
        if tail != progress.tail_digest {
            return Err(JournalError::Invariant(
                "retained native cursor tail differs",
            ));
        }
    }
    if values
        .keys()
        .filter(|key| {
            key.starts_with(NAMESPACE) || key.starts_with("original.native-create.phase.")
        })
        .any(|key| !expected.contains(key))
    {
        return Err(JournalError::Invariant(
            "unowned or extra original native cursor phase",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn validate_rows(rows: &[JournalStoredRow]) -> Result<()> {
    let mut values = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with("original.native-create."))
    }) {
        let key = row.primary_key().first().ok_or(JournalError::Invariant(
            "original native inventory key absent",
        ))?;
        if values
            .insert(key.clone(), field(row, "value")?.to_owned())
            .is_some()
        {
            return Err(JournalError::Invariant(
                "duplicate original native inventory row",
            ));
        }
    }
    verify_inventory(&values)
}

pub(crate) fn validate_connection(connection: &Connection) -> Result<()> {
    let mut query = connection.prepare_cached(
        "SELECT key,length(CAST(value AS BLOB)),value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
    )?;
    let rows = query.query_map(
        params![
            i64::try_from("original.native-create.".len())
                .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
            "original.native-create.",
            i64::try_from(sync_extend_core_model::limits::MAX_ENTRIES + 1)
                .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    let mut values = BTreeMap::new();
    for row in rows {
        let (key, bytes, json) = row?;
        if bytes < 0
            || bytes as u64 > crate::MAX_OPERATION_BYTES as u64
            || values.len() >= sync_extend_core_model::limits::MAX_ENTRIES
        {
            return Err(JournalError::Invariant(
                "original native cursor inventory bound",
            ));
        }
        values.insert(key, json);
    }
    verify_inventory(&values)
}

pub(super) fn complete(
    tx: &Transaction<'_>,
    reservation: &super::OriginalLocalHistoryReservation,
    observations: &RenameObservationMap,
) -> Result<OriginalNativePhaseChain> {
    phase_evidence::validate_connection(tx)?;
    let stored: Stored = serde_json::from_str(reservation.exact_json())?;
    let mut exact_phase_json = Vec::with_capacity(4);
    for sequence in 0..4 {
        let key = format!("{}{}.{sequence:04}", phase_evidence::PREFIX, stored.attempt);
        let json: String = tx.query_row(
            "SELECT value FROM local_state WHERE key=?1",
            [&key],
            |row| row.get(0),
        )?;
        exact_phase_json.push(json);
    }

    let issued = reservation
        .original_issued_phases
        .lock()
        .map_err(|_| JournalError::Invariant("original live native phase lock poisoned"))?;
    if issued.as_slice() != exact_phase_json.as_slice() {
        return Err(JournalError::Invariant(
            "persisted complete chain differs from original live issued bytes",
        ));
    }
    let last: phase_evidence::Phase = serde_json::from_str(&exact_phase_json[3])?;
    let file_key = last.original_file_key.ok_or(JournalError::Invariant(
        "complete original CREATE file key absent",
    ))?;
    let parent_key = last.original_parent_key.ok_or(JournalError::Invariant(
        "complete original CREATE parent key absent",
    ))?;
    let planned = stored
        .planned
        .entries
        .values()
        .find(|entry| entry.path == stored.future_path)
        .ok_or(JournalError::Invariant(
            "complete original CREATE entry absent",
        ))?;
    let actual = observations
        .entries
        .iter()
        .find(|record| record.entry_id == planned.entry_id)
        .ok_or(JournalError::Invariant(
            "complete original CREATE observation absent",
        ))?;
    if actual.observed.physical_identity
        != ContentId::hash(format!("inode:{}:{}", file_key.0, file_key.1).as_bytes())
        || !actual.observed.single_link
        || !last.original_create_slot_absent
    {
        return Err(JournalError::Invariant(
            "original history observation differs from persisted CREATE key",
        ));
    }
    let exact_digest = ContentId::hash(&serde_json::to_vec(&(
        1u32,
        &stored.attempt,
        &exact_phase_json,
    ))?);
    Ok(OriginalNativePhaseChain {
        attempt: stored.attempt,
        exact_phase_json,
        exact_digest,
        intent_digest: last.intent_digest,
        file_key,
        parent_key,
        payload_digest: last.payload_digest.ok_or(JournalError::Invariant(
            "complete original CREATE payload digest absent",
        ))?,
        payload_bytes: last.payload_bytes,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn is_cursor_row(row: &JournalStoredRow, attempt: &EntryId) -> bool {
    row.table() == "local_state" && row.primary_key() == [format!("{PREFIX}{attempt}")]
}

#[cfg(target_os = "linux")]
pub(super) fn verify_live_prefix(
    connection: &Connection,
    reservation: &super::OriginalLocalHistoryReservation,
    issued: &[String],
) -> Result<()> {
    if issued.len() > 4 {
        return Err(JournalError::Invariant("original live phase count bound"));
    }
    phase_evidence::validate_connection(connection)?;
    let prefix = format!("{}{}.", phase_evidence::PREFIX, reservation.attempt());
    let mut query = connection.prepare_cached(
        "SELECT value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT 5",
    )?;
    let stored = query
        .query_map(
            params![
                i64::try_from(prefix.len())
                    .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
                prefix
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if stored != issued {
        return Err(JournalError::Invariant(
            "persisted native prefix differs from original live issued bytes",
        ));
    }
    Ok(())
}
