use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError, Result,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    ChunkRef, ContentId, EntryId, SnapshotId, SpaceId,
};

const MAX_RESERVATION_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_RESERVATION_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceReservationIntent {
    pub owner_id: EntryId,
    pub scope: ReferenceOwnerScope,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceReservation {
    pub intent: ReferenceReservationIntent,
    pub state: &'static str,
    pub content_hashes_verified: bool,
    pub release_available: bool,
    pub worker_available: bool,
    pub remote_backup_complete: bool,
    pub snapshot_handoff: Option<ReferenceSnapshotHandoff>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceSnapshotHandoff {
    pub snapshot_id: SnapshotId,
    pub owner_intent_hash: ContentId,
}

impl ReferenceReservationIntent {
    fn chunks(&self, max: usize) -> Result<BTreeMap<ContentId, u32>> {
        self.scope.validate()?;
        sql_integer(self.created_at_ms)?;
        let mut seen = 0usize;
        let mut chunks = BTreeMap::new();
        if self.scope.files.len() > max {
            return Err(JournalError::Invariant("reservation file inventory limit"));
        }
        for file in &self.scope.files {
            seen = seen
                .checked_add(file.chunks.len())
                .filter(|n| *n <= max)
                .ok_or(JournalError::Invariant("reservation chunk inventory limit"))?;
            for chunk in &file.chunks {
                chunks.insert(chunk.content_id.clone(), chunk.length);
            }
        }
        Ok(chunks)
    }
}

impl Journal {
    /// Serialize bounded chunk ingestion against owner handoff, not just GC.
    /// No journal state/pin/clock changes; valid immutable CAS output may survive errors.
    pub fn with_reserved_chunk<T, E>(
        &self,
        space: &SpaceId,
        owner_id: &EntryId,
        content_id: &ContentId,
        max: usize,
        ingest: impl FnOnce(&ChunkRef) -> std::result::Result<T, E>,
    ) -> std::result::Result<(CasAccessGuard, T), E>
    where
        E: From<JournalError>,
    {
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(space, max)?;
        let owner = self
            .reference_reservations(space, max)?
            .into_iter()
            .find(|o| o.intent.owner_id == *owner_id)
            .ok_or(JournalError::Invariant("unknown reference reservation"))?;
        if owner.snapshot_handoff.is_some() {
            return Err(JournalError::Invariant("reference reservation is terminal").into());
        }
        let length =
            owner
                .intent
                .chunks(max)?
                .get(content_id)
                .copied()
                .ok_or(JournalError::Invariant(
                    "chunk is outside reservation scope",
                ))?;
        self.require_cas_access(content_id)?;
        let result = ingest(&ChunkRef {
            content_id: content_id.clone(),
            length,
        })?;
        self.audit_gc_owners(space, max)?;
        self.require_cas_access(content_id)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((coordination, result))
    }

    /// Audit durable missing-or-present content reservations, without reading CAS.
    pub fn reference_reservations(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<ReferenceReservation>> {
        self.check_storage_metadata_limit(max)?;
        if self.state("space_id")?.as_deref() != Some(space.as_str()) {
            return Err(JournalError::Invariant("reservation space mismatch"));
        }
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM reference_reservation_objects p
                LEFT JOIN reference_reservations o USING(owner_id) WHERE o.owner_id IS NULL)
             OR EXISTS(SELECT 1 FROM reference_snapshot_handoffs h
                LEFT JOIN reference_reservations o USING(owner_id) WHERE o.owner_id IS NULL)",
            [],
            |r| r.get(0),
        )?;
        if orphan {
            return Err(JournalError::Invariant("orphan reservation pin"));
        }
        let mut statement = self.connection.prepare(
            "SELECT owner_id,space_id,
                CASE WHEN length(CAST(intent AS BLOB))<=16777216 THEN intent ELSE '' END,
                intent_hash,created_at_ms FROM reference_reservations ORDER BY owner_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut owners = Vec::new();
        let mut all_lengths = BTreeMap::new();
        let mut all_chunks = 0usize;
        let mut all_files = 0usize;
        for row in rows {
            let (id, stored_space, json, hash, time) = row?;
            let intent: ReferenceReservationIntent = serde_json::from_str(&json)?;
            if intent.owner_id.as_str() != id
                || intent.scope.space_id != *space
                || stored_space != space.as_str()
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || sql_integer(intent.created_at_ms)? != time
            {
                return Err(JournalError::Invariant(
                    "reservation intent integrity mismatch",
                ));
            }
            let mut expected = intent.chunks(max)?;
            all_files = all_files
                .checked_add(intent.scope.files.len())
                .filter(|n| *n <= max)
                .ok_or(JournalError::Invariant("reservation aggregate file limit"))?;
            for file in &intent.scope.files {
                all_chunks = all_chunks
                    .checked_add(file.chunks.len())
                    .filter(|n| *n <= max)
                    .ok_or(JournalError::Invariant("reservation aggregate chunk limit"))?;
            }
            let handoff: Option<(String, String)> = self
                .connection
                .query_row(
                    "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))=64 THEN snapshot_id ELSE '' END,
                        CASE WHEN length(CAST(owner_intent_hash AS BLOB))=64 THEN owner_intent_hash ELSE '' END
                     FROM reference_snapshot_handoffs WHERE owner_id=?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let snapshot_handoff = if let Some((snapshot_id, owner_hash)) = handoff {
                if owner_hash != hash {
                    return Err(JournalError::Invariant("snapshot handoff hash mismatch"));
                }
                let snapshot_id = snapshot_id.parse()?;
                let snapshot = crate::snapshot_retention::audit_snapshot(
                    &self.connection,
                    space,
                    &snapshot_id,
                )?;
                require_snapshot_scope(&intent, &snapshot.manifest, &snapshot.state)?;
                expected.clear();
                Some(ReferenceSnapshotHandoff {
                    snapshot_id,
                    owner_intent_hash: owner_hash.parse()?,
                })
            } else {
                None
            };
            let mut pins = self.connection.prepare(
                "SELECT content_id FROM reference_reservation_objects WHERE owner_id=?1",
            )?;
            let actual: Vec<String> = pins
                .query_map([&id], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            if actual.len() != expected.len()
                || actual.iter().any(|id| {
                    id.parse::<ContentId>()
                        .map_or(true, |id| !expected.contains_key(&id))
                })
            {
                return Err(JournalError::Invariant("reservation exact pin mismatch"));
            }
            for (id, length) in expected {
                self.require_cas_access(&id)?;
                if all_lengths
                    .insert(id, length)
                    .is_some_and(|old| old != length)
                {
                    return Err(JournalError::Invariant("reservation length mismatch"));
                }
            }
            owners.push(ReferenceReservation {
                intent,
                state: if snapshot_handoff.is_some() {
                    "transferred_to_snapshot"
                } else {
                    "reserved"
                },
                content_hashes_verified: false,
                release_available: false,
                worker_available: false,
                remote_backup_complete: false,
                snapshot_handoff,
            });
        }
        Ok(owners)
    }

    /// Reserve exact content IDs before import, even when their bytes are missing.
    /// The retained shared guard precedes SQLite and survives the reference commit.
    pub fn with_reference_reservation<T, E>(
        &self,
        intent: &ReferenceReservationIntent,
        max: usize,
        inspect: impl FnOnce(&ReferenceReservationIntent) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, ReferenceReservation), E>
    where
        E: From<JournalError>,
    {
        let chunks = intent.chunks(max)?;
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(JournalError::from)?;
            if let Some(old) = self
                .reference_reservations(&intent.scope.space_id, max)?
                .into_iter()
                .find(|o| o.intent.owner_id == intent.owner_id)
            {
                if old.intent != *intent {
                    return Err(JournalError::Invariant("reservation owner ID collision").into());
                }
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&intent.scope.space_id, max)?;
        if let Some(old) = self
            .reference_reservations(&intent.scope.space_id, max)?
            .into_iter()
            .find(|o| o.intent.owner_id == intent.owner_id)
        {
            if old.intent != *intent {
                return Err(JournalError::Invariant("reservation owner ID collision").into());
            }
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        for id in chunks.keys() {
            self.require_cas_access(id)?;
        }
        let json = serde_json::to_string(intent).map_err(JournalError::from)?;
        if json.len() > MAX_RESERVATION_BYTES {
            return Err(JournalError::Invariant("reservation metadata byte limit").into());
        }
        check_storage_metadata_limit(
            &tx,
            max,
            chunks.len() as u64 + 2,
            json.len() as u64 + TERMINAL_RESERVATION_BYTES,
        )?;
        tx.execute(
            "INSERT INTO reference_reservations VALUES (?1,?2,?3,?4,?5)",
            params![
                intent.owner_id.as_str(),
                intent.scope.space_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(intent.created_at_ms)?,
            ],
        )
        .map_err(JournalError::from)?;
        for id in chunks.keys() {
            tx.execute(
                "INSERT INTO reference_reservation_objects VALUES (?1,?2)",
                params![intent.owner_id.as_str(), id.as_str()],
            )
            .map_err(JournalError::from)?;
        }
        let held = inspect(intent)?;
        self.audit_gc_owners(&intent.scope.space_id, max)?;
        self.gc_executions(&intent.scope.space_id, max)?;
        let owner = self
            .reference_reservations(&intent.scope.space_id, max)?
            .into_iter()
            .find(|o| o.intent.owner_id == intent.owner_id)
            .ok_or(JournalError::Invariant("reservation disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), owner))
    }

    /// Transfer only download/restore pins to an exact already retained snapshot.
    /// The caller verifies content under the returned CAS guard before commit.
    pub fn with_reference_snapshot_handoff<T, E>(
        &self,
        space: &SpaceId,
        owner_id: &EntryId,
        snapshot_id: &SnapshotId,
        max: usize,
        inspect: impl FnOnce(&ReferenceReservationIntent) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, ReferenceReservation), E>
    where
        E: From<JournalError>,
    {
        let find = || {
            self.reference_reservations(space, max)?
                .into_iter()
                .find(|o| o.intent.owner_id == *owner_id)
                .ok_or(JournalError::Invariant("unknown reference reservation"))
        };
        let replay = |owner: &ReferenceReservation| -> Result<bool> {
            if let Some(handoff) = &owner.snapshot_handoff {
                if handoff.snapshot_id != *snapshot_id {
                    return Err(JournalError::Invariant("snapshot handoff target collision"));
                }
                return Ok(true);
            }
            Ok(false)
        };
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(JournalError::from)?;
            let owner = find()?;
            if replay(&owner)? {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, owner));
            }
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(space, max)?;
        let owner = find()?;
        if replay(&owner)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, owner));
        }
        let snapshot = self.retained_snapshot(space, snapshot_id)?;
        require_snapshot_scope(&owner.intent, &snapshot.manifest, &snapshot.state)?;
        // The terminal row/bytes were reserved at admission, even under tighter limits.
        self.check_storage_metadata_limit(max)?;
        let held = inspect(&owner.intent)?;
        self.audit_gc_owners(space, max)?;
        let snapshot = self.retained_snapshot(space, snapshot_id)?;
        require_snapshot_scope(&owner.intent, &snapshot.manifest, &snapshot.state)?;
        let json = serde_json::to_string(&owner.intent).map_err(JournalError::from)?;
        self.connection
            .execute(
                "INSERT INTO reference_snapshot_handoffs VALUES (?1,?2,?3)",
                params![
                    owner_id.as_str(),
                    snapshot_id.as_str(),
                    ContentId::hash(json.as_bytes()).as_str(),
                ],
            )
            .map_err(JournalError::from)?;
        self.connection
            .execute(
                "DELETE FROM reference_reservation_objects WHERE owner_id=?1",
                [owner_id.as_str()],
            )
            .map_err(JournalError::from)?;
        self.audit_gc_owners(space, max)?;
        let owner = find()?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), owner))
    }
}

fn require_snapshot_scope(
    owner: &ReferenceReservationIntent,
    snapshot: &sync_extend_core_model::Manifest,
    state: &str,
) -> Result<()> {
    if !matches!(
        owner.scope.kind,
        ReferenceOwnerKind::Download | ReferenceOwnerKind::Restore
    ) || snapshot.space_id != owner.scope.space_id
        || state != "materialized"
        || owner.scope.files.iter().any(|file| {
            !snapshot
                .entries
                .values()
                .any(|e| e.content.as_ref() == Some(file))
        })
    {
        return Err(JournalError::Invariant("snapshot handoff scope mismatch"));
    }
    Ok(())
}
