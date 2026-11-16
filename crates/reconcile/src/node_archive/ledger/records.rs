//! Strict evidence decoding. Recovered rows never mint living CREATE attempts.
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, PortablePath, SpaceId};
use sync_extend_journal::{JournalError, Result};

use super::bounds::LedgerBounds;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ObjectKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum Phase {
    Intended,
    Created,
    ContentClosed,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum InternalRole {
    WorktreeMarkerDirectory,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct Record {
    pub version: u32,
    pub archive_digest: ContentId,
    pub ledger_id: SpaceId,
    pub phase: Phase,
    pub intent_index: u64,
    pub kind: ObjectKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_role: Option<InternalRole>,
    pub parent_key: String,
    pub component: String,
    pub object_key: Option<String>,
    pub content_digest: Option<ContentId>,
    pub bytes: Option<u64>,
}

struct Intent {
    kind: ObjectKind,
    internal_role: Option<InternalRole>,
    parent: String,
    component: String,
    key: Option<String>,
    closed: bool,
}

pub(in super::super) struct ChainState {
    pub count: u64,
    pub record_bytes: u64,
    pub previous: String,
}

fn canonical_key(value: &str) -> bool {
    let fields: Vec<_> = value.split(':').collect();
    matches!(fields.as_slice(), ["windows", volume, id]
        if volume.parse::<u64>().is_ok_and(|number| number.to_string() == *volume)
        && id.parse::<u128>().is_ok_and(|number| number.to_string() == *id))
}

pub(in super::super) fn validate_component(value: &str) -> Result<()> {
    if value.len() > 255 {
        return Err(JournalError::Invariant("restore component byte bound"));
    }
    let path = PortablePath::new(value)?;
    if path.parent().is_some() || path.as_str() != value {
        return Err(JournalError::Invariant(
            "restore intent requires exact ordinary component",
        ));
    }
    Ok(())
}

/// Stream every row under one caller-held snapshot. Allocation is bounded by
/// explicit total record bytes and intent count, including unfinished intents.
pub(in super::super) fn verify_chain(
    connection: &Connection,
    archive: &ContentId,
    ledger: &SpaceId,
    bounds: LedgerBounds,
) -> Result<ChainState> {
    let (count, bytes): (i64, i64) = connection.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(record AS BLOB))),0) \
         FROM main.restore_records",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let count =
        u64::try_from(count).map_err(|_| JournalError::Invariant("negative ledger count"))?;
    let bytes =
        u64::try_from(bytes).map_err(|_| JournalError::Invariant("negative ledger byte sum"))?;
    if count > bounds.max_records || bytes > bounds.max_record_bytes {
        return Err(JournalError::Invariant("external ledger aggregate bound"));
    }
    let mut state = ChainState {
        count: 0,
        record_bytes: 0,
        previous: ContentId::hash(&[]).to_string(),
    };
    let mut intents: BTreeMap<u64, Intent> = BTreeMap::new();
    let mut slots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut statement = connection.prepare(
        "SELECT record_index,previous_hash,record,record_hash \
         FROM main.restore_records ORDER BY record_index",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let index = u64::try_from(row.get::<_, i64>(0)?)
            .map_err(|_| JournalError::Invariant("negative ledger record index"))?;
        let prior: String = row.get(1)?;
        let json: String = row.get(2)?;
        let hash: String = row.get(3)?;
        if json.is_empty() || json.len() > 65_536 || index != state.count || prior != state.previous
        {
            return Err(JournalError::Invariant("external ledger exact row chain"));
        }
        let record: Record = serde_json::from_str(&json)?;
        if serde_json::to_string(&record)? != json
            || record.version != 2
            || record.archive_digest != *archive
            || record.ledger_id != *ledger
            || !canonical_key(&record.parent_key)
            || record
                .object_key
                .as_deref()
                .is_some_and(|key| !canonical_key(key))
            || ContentId::hash(&serde_json::to_vec(&(index, &prior, &json))?).as_str() != hash
        {
            return Err(JournalError::Invariant(
                "external ledger typed canonical scope",
            ));
        }
        match record.internal_role {
            Some(InternalRole::WorktreeMarkerDirectory)
                if record.kind == ObjectKind::Directory && record.component == ".sync-extend" => {}
            None => validate_component(&record.component)?,
            _ => {
                return Err(JournalError::Invariant(
                    "exact fixed internal marker record",
                ))
            }
        }
        match record.phase {
            Phase::Intended => {
                // A possible orphan blocks this original slot for this entire ledger.
                // Case-insensitive NTFS aliases must not acquire separate intents.
                if record.intent_index != index
                    || record.object_key.is_some()
                    || record.content_digest.is_some()
                    || record.bytes.is_some()
                    || !slots.insert((record.parent_key.clone(), record.component.to_uppercase()))
                    || intents.len() >= bounds.max_intents
                {
                    return Err(JournalError::Invariant(
                        "external ledger intended transition",
                    ));
                }
                intents.insert(
                    index,
                    Intent {
                        kind: record.kind,
                        internal_role: record.internal_role,
                        parent: record.parent_key,
                        component: record.component,
                        key: None,
                        closed: false,
                    },
                );
            }
            Phase::Created | Phase::ContentClosed => {
                let intent =
                    intents
                        .get_mut(&record.intent_index)
                        .ok_or(JournalError::Invariant(
                            "external ledger transition without intended",
                        ))?;
                if intent.kind != record.kind
                    || intent.internal_role != record.internal_role
                    || intent.parent != record.parent_key
                    || intent.component != record.component
                {
                    return Err(JournalError::Invariant(
                        "external ledger transition lineage",
                    ));
                }
                match record.phase {
                    Phase::Created => {
                        let key = record.object_key.ok_or(JournalError::Invariant(
                            "external ledger created identity absent",
                        ))?;
                        if intent.key.is_some()
                            || record.content_digest.is_some()
                            || record.bytes.is_some()
                            || key == record.parent_key
                            || !keys.insert(key.clone())
                        {
                            return Err(JournalError::Invariant(
                                "external ledger created transition",
                            ));
                        }
                        intent.key = Some(key);
                    }
                    Phase::ContentClosed => {
                        if intent.kind != ObjectKind::File
                            || intent.closed
                            || intent.key.is_none()
                            || intent.key != record.object_key
                            || record.content_digest.is_none()
                            || record
                                .bytes
                                .is_none_or(|bytes| bytes > bounds.max_content_bytes)
                        {
                            return Err(JournalError::Invariant(
                                "external ledger content transition",
                            ));
                        }
                        intent.closed = true;
                    }
                    Phase::Intended => unreachable!(),
                }
            }
        }
        state.count += 1;
        state.record_bytes =
            state
                .record_bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant(
                    "external ledger record byte overflow",
                ))?;
        state.previous = hash;
    }
    if state.count != count || state.record_bytes != bytes {
        return Err(JournalError::Invariant(
            "external ledger audited aggregate differs",
        ));
    }
    Ok(state)
}
