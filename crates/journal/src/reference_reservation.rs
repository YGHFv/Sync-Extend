use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError, Result,
};
use rusqlite::{params, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{reference_owner::ReferenceOwnerScope, ContentId, EntryId, SpaceId};

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
            let expected = intent.chunks(max)?;
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
                state: "reserved",
                content_hashes_verified: false,
                release_available: false,
                worker_available: false,
                remote_backup_complete: false,
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
}
