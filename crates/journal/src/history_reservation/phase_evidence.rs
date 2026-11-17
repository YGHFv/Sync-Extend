//! Bounded persisted phase chain validation; descriptive, never an execution issuer.
use super::Stored;
use crate::{JournalError, JournalStoredRow, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, EntryId};

pub(super) const PREFIX: &str = "original.native-create.phase.v1.";
const NAMESPACE: &str = "original.native-create.phase.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Phase {
    pub version: u32,
    pub attempt: EntryId,
    pub sequence: u32,
    pub predecessor: Option<ContentId>,
    pub stage: String,
    pub original_reservation_digest: ContentId,
    pub intent_digest: ContentId,
    pub original_file_key: Option<(u64, u64)>,
    pub original_parent_key: Option<(u64, u64)>,
    pub payload_digest: Option<ContentId>,
    pub payload_bytes: u64,
    pub original_create_slot_absent: bool,
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
            "original phase inventory text required",
        )),
    }
}

pub(super) fn validate(
    key: &str,
    json: &str,
    stored: &Stored,
    prior: Option<&Phase>,
    prior_json: Option<&str>,
) -> Result<Phase> {
    if json.len() as u64 > stored.native_footprint.max_phase_record_bytes {
        return Err(JournalError::Invariant("original native phase byte bound"));
    }
    let phase: Phase = serde_json::from_str(json)?;
    let stages = [
        "outside_intent_synced",
        "original_create_requested",
        "original_create_observed",
        "original_create_published_and_source_absent",
    ];
    if phase.version != 1
        || phase.sequence > 3
        || phase.attempt != stored.attempt
        || key != format!("{PREFIX}{}.{:04}", stored.attempt, phase.sequence)
        || phase.stage != stages[phase.sequence as usize]
        || serde_json::to_string(&phase)? != json
        || phase.original_reservation_digest
            != ContentId::hash(serde_json::to_string(stored)?.as_bytes())
        || phase.predecessor != prior_json.map(|json| ContentId::hash(json.as_bytes()))
        || prior.map_or(phase.sequence != 0, |prior| {
            prior.sequence + 1 != phase.sequence || prior.intent_digest != phase.intent_digest
        })
    {
        return Err(JournalError::Invariant(
            "original native phase canonical chain scope differs",
        ));
    }
    if phase.sequence < 2 {
        if phase.original_file_key.is_some()
            || phase.original_parent_key.is_some()
            || phase.payload_digest.is_some()
            || phase.payload_bytes != 0
            || phase.original_create_slot_absent
        {
            return Err(JournalError::Invariant(
                "pre-CREATE phase claims original native result",
            ));
        }
    } else {
        if !phase
            .original_file_key
            .is_some_and(|(device, inode)| device != 0 && inode != 0)
            || !phase
                .original_parent_key
                .is_some_and(|(device, inode)| device != 0 && inode != 0)
        {
            return Err(JournalError::Invariant(
                "original native phase actual keys required",
            ));
        }
        if phase.sequence == 2
            && (phase.payload_bytes != 0
                || phase.payload_digest != Some(ContentId::hash(b""))
                || phase.original_create_slot_absent)
        {
            return Err(JournalError::Invariant(
                "original CREATE observation must start empty",
            ));
        }
        if phase.sequence == 3 {
            let prior = prior.ok_or(JournalError::Invariant(
                "original CREATE prior phase absent",
            ))?;
            if phase.original_file_key != prior.original_file_key
                || phase.original_parent_key != prior.original_parent_key
                || phase.payload_bytes != stored.native_footprint.payload_bytes
                || phase.payload_digest.as_ref() != Some(&stored.native_footprint.payload_digest)
                || !phase.original_create_slot_absent
            {
                return Err(JournalError::Invariant(
                    "original native published phase differs from CREATE",
                ));
            }
        }
    }
    Ok(phase)
}

#[allow(dead_code)]
pub(crate) fn validate_rows(rows: &[JournalStoredRow]) -> Result<()> {
    super::phase_chain::validate_rows(rows)?;
    let mut previous: BTreeMap<EntryId, (Phase, String)> = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with(NAMESPACE))
    }) {
        let key = row
            .primary_key()
            .first()
            .ok_or(JournalError::Invariant("original phase row key absent"))?;
        let json = field(row, "value")?;
        let header: Phase = serde_json::from_str(json)?;
        let native_key = format!("original.native-create.liability.v1.{}", header.attempt);
        let native = rows
            .iter()
            .find(|row| row.table() == "local_state" && row.primary_key() == [native_key.clone()])
            .ok_or(JournalError::Invariant(
                "original phase native liability absent",
            ))?;
        let stored = super::liability::original_for_phase(&native_key, field(native, "value")?)?;
        let prior = previous.get(&header.attempt);
        let phase = validate(
            key,
            json,
            &stored,
            prior.map(|(phase, _)| phase),
            prior.map(|(_, json)| json.as_str()),
        )?;
        previous.insert(phase.attempt.clone(), (phase, json.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_connection(connection: &rusqlite::Connection) -> Result<()> {
    super::phase_chain::validate_connection(connection)?;
    let mut previous: BTreeMap<EntryId, (Phase, String)> = BTreeMap::new();
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
        if count > sync_extend_core_model::limits::MAX_ENTRIES || !(1..=4096).contains(&bytes) {
            return Err(JournalError::Invariant(
                "original native phase inventory bound",
            ));
        }
        let key: String = row.get(0)?;
        let json: String = row.get(2)?;
        let header: Phase = serde_json::from_str(&json)?;
        let native_key = format!("original.native-create.liability.v1.{}", header.attempt);
        let native: String = connection.query_row(
            "SELECT value FROM local_state WHERE key=?1",
            [&native_key],
            |row| row.get(0),
        )?;
        let stored = super::liability::original_for_phase(&native_key, &native)?;
        let prior = previous.get(&header.attempt);
        let phase = validate(
            &key,
            &json,
            &stored,
            prior.map(|(phase, _)| phase),
            prior.map(|(_, json)| json.as_str()),
        )?;
        previous.insert(phase.attempt.clone(), (phase, json));
    }
    Ok(())
}
