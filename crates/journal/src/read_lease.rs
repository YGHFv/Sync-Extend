use crate::{
    check_storage_metadata_limit, sql_integer, Journal, JournalError, Result, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::*;

const MAX_TTL_MS: u64 = 86_400_000;

pub fn read_lease_expiry(now: u64, ttl_secs: u64) -> Result<u64> {
    if !(1..=86_400).contains(&ttl_secs) {
        return Err(JournalError::Invariant(
            "read lease TTL must be 1..86400 seconds",
        ));
    }
    let expiry = now
        .checked_add(ttl_secs * 1000)
        .ok_or(JournalError::Invariant("read lease expiry overflow"))?;
    sql_integer(expiry)?;
    Ok(expiry)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadLeaseIntent {
    pub format_version: u32,
    pub lease_id: EntryId,
    pub space_id: SpaceId,
    pub snapshot_id: SnapshotId,
    pub entry: Entry,
    pub created_at_ms: u64,
    pub initial_expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadLeaseState {
    Active,
    Released,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReadLease {
    pub intent: ReadLeaseIntent,
    pub state: ReadLeaseState,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

fn clock(connection: &Connection) -> Result<u64> {
    let time: i64 = connection.query_row(
        "SELECT observed_at_ms FROM read_lease_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    u64::try_from(time).map_err(|_| JournalError::Invariant("invalid read lease clock"))
}

fn observe(connection: &Connection, now: u64) -> Result<()> {
    if now < clock(connection)? {
        return Err(JournalError::Invariant("read lease clock moved backwards"));
    }
    if connection.execute(
        "UPDATE read_lease_clock SET observed_at_ms=?1 WHERE singleton=1",
        [sql_integer(now)?],
    )? != 1
    {
        return Err(JournalError::Invariant("read lease clock missing"));
    }
    Ok(())
}

impl Journal {
    fn validate_read_lease_intent(&self, intent: &ReadLeaseIntent) -> Result<()> {
        self.read_view().validate_read_lease_intent(intent)
    }

    pub fn read_lease(&self, id: &EntryId) -> Result<ReadLease> {
        self.read_view().read_lease(id)
    }

    pub fn read_leases(&self, space: &SpaceId, max_entries: usize) -> Result<Vec<ReadLease>> {
        self.check_storage_metadata_limit(max_entries)?;
        self.read_view().read_leases(space)
    }

    pub fn acquire_read_lease(
        &mut self,
        intent: &ReadLeaseIntent,
        max_entries: usize,
    ) -> Result<ReadLease> {
        self.check_storage_metadata_limit(max_entries)?;
        self.validate_read_lease_intent(intent)?;
        let exists: Option<String> = self
            .connection
            .query_row(
                "SELECT lease_id FROM read_leases WHERE lease_id=?1",
                [intent.lease_id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() {
            let lease = self.read_lease(&intent.lease_id)?;
            if lease.intent != *intent {
                return Err(JournalError::Invariant("read lease ID collision"));
            }
            return Ok(lease);
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("read lease metadata limit"));
        }
        let chunks: BTreeSet<_> = intent
            .entry
            .content
            .as_ref()
            .ok_or(JournalError::Invariant("read lease content missing"))?
            .chunks
            .iter()
            .map(|c| &c.content_id)
            .collect();
        let tx = self.connection.transaction()?;
        check_storage_metadata_limit(&tx, max_entries, chunks.len() as u64 + 1, json.len() as u64)?;
        observe(&tx, intent.created_at_ms)?;
        tx.execute(
            "INSERT INTO read_leases VALUES (?1,?2,?3,?4,?5,'active',?6,?7,NULL)",
            params![
                intent.lease_id.as_str(),
                intent.space_id.as_str(),
                intent.snapshot_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(intent.created_at_ms)?,
                sql_integer(intent.initial_expires_at_ms)?
            ],
        )?;
        for id in chunks {
            tx.execute(
                "INSERT INTO read_lease_objects VALUES (?1,?2)",
                params![intent.lease_id.as_str(), id.as_str()],
            )?;
        }
        tx.commit()?;
        self.read_lease(&intent.lease_id)
    }

    pub fn renew_read_lease(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Result<ReadLease> {
        self.check_storage_metadata_limit(max_entries)?;
        let lease = self.require_read_lease(space, id)?;
        let expiry = read_lease_expiry(now, ttl_secs)?.max(lease.expires_at_ms);
        if lease.state != ReadLeaseState::Active || now >= lease.expires_at_ms {
            return Err(JournalError::Invariant(
                "only unexpired active read lease can renew",
            ));
        }
        let tx = self.connection.transaction()?;
        check_storage_metadata_limit(&tx, max_entries, 0, 0)?;
        observe(&tx, now)?;
        if tx.execute(
            "UPDATE read_leases SET observed_at_ms=?2,expires_at_ms=?3
                WHERE lease_id=?1 AND state='active' AND expires_at_ms>?2",
            params![id.as_str(), sql_integer(now)?, sql_integer(expiry)?],
        )? != 1
        {
            return Err(JournalError::Invariant("read lease state changed"));
        }
        tx.commit()?;
        self.read_lease(id)
    }

    pub fn release_read_lease(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
    ) -> Result<ReadLease> {
        let lease = self.require_read_lease(space, id)?;
        if lease.state != ReadLeaseState::Active {
            return Ok(lease);
        }
        let now = now.max(clock(&self.connection)?).max(lease.observed_at_ms);
        let tx = self.connection.transaction()?;
        observe(&tx, now)?;
        if tx.execute("UPDATE read_leases SET state='released',finished_at_ms=?2 WHERE lease_id=?1 AND state='active'",
            params![id.as_str(),sql_integer(now)?])? != 1 {
            return Err(JournalError::Invariant("read lease state changed"));
        }
        tx.execute(
            "DELETE FROM read_lease_objects WHERE lease_id=?1",
            [id.as_str()],
        )?;
        tx.commit()?;
        self.read_lease(id)
    }

    pub fn expire_read_leases(
        &mut self,
        space: &SpaceId,
        now: u64,
        max_entries: usize,
    ) -> Result<Vec<ReadLease>> {
        let leases = self.read_leases(space, max_entries)?;
        let overdue: Vec<_> = leases
            .into_iter()
            .filter(|l| l.state == ReadLeaseState::Active && now >= l.expires_at_ms)
            .collect();
        let tx = self.connection.transaction()?;
        check_storage_metadata_limit(&tx, max_entries, 0, 0)?;
        observe(&tx, now)?;
        for lease in &overdue {
            let id = lease.intent.lease_id.as_str();
            if tx.execute(
                "UPDATE read_leases SET state='expired',finished_at_ms=?2
                    WHERE lease_id=?1 AND state='active' AND expires_at_ms<=?2",
                params![id, sql_integer(now)?],
            )? != 1
            {
                return Err(JournalError::Invariant("read lease state changed"));
            }
            tx.execute("DELETE FROM read_lease_objects WHERE lease_id=?1", [id])?;
        }
        tx.commit()?;
        overdue
            .into_iter()
            .map(|l| self.read_lease(&l.intent.lease_id))
            .collect()
    }

    pub fn admit_leased_read(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        max_entries: usize,
    ) -> Result<ReadLease> {
        self.check_storage_metadata_limit(max_entries)?;
        let lease = self.require_read_lease(space, id)?;
        if lease.state != ReadLeaseState::Active || now >= lease.expires_at_ms {
            return Err(JournalError::Invariant(
                "read lease is not active and unexpired",
            ));
        }
        let tx = self.connection.transaction()?;
        check_storage_metadata_limit(&tx, max_entries, 0, 0)?;
        observe(&tx, now)?;
        tx.commit()?;
        Ok(lease)
    }

    fn require_read_lease(&self, space: &SpaceId, id: &EntryId) -> Result<ReadLease> {
        let lease = self.read_lease(id)?;
        if lease.intent.space_id != *space {
            return Err(JournalError::Invariant(
                "read lease belongs to another space",
            ));
        }
        Ok(lease)
    }
}

impl crate::JournalReadView<'_> {
    pub(crate) fn validate_read_lease_intent(&self, intent: &ReadLeaseIntent) -> Result<()> {
        intent.entry.validate()?;
        if intent.format_version != FORMAT_VERSION
            || intent.entry.kind != EntryKind::File
            || intent.initial_expires_at_ms <= intent.created_at_ms
            || intent.initial_expires_at_ms - intent.created_at_ms > MAX_TTL_MS
            || intent.initial_expires_at_ms - intent.created_at_ms < 1000
        {
            return Err(JournalError::Invariant("invalid read lease intent"));
        }
        sql_integer(intent.initial_expires_at_ms)?;
        let manifest = self.snapshot(&intent.space_id, &intent.snapshot_id)?;
        if manifest.entries.get(&intent.entry.entry_id) != Some(&intent.entry) {
            return Err(JournalError::Invariant(
                "read lease snapshot entry mismatch",
            ));
        }
        let expected: BTreeSet<_> = manifest
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .flat_map(|c| c.chunks.iter().map(|chunk| chunk.content_id.clone()))
            .collect();
        let mut statement = self
            .connection
            .prepare("SELECT content_id FROM snapshot_objects WHERE snapshot_id=?1")?;
        let ids: Vec<String> = statement
            .query_map([intent.snapshot_id.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let actual = ids
            .into_iter()
            .map(|id| id.parse())
            .collect::<std::result::Result<BTreeSet<ContentId>, _>>()?;
        if actual != expected {
            return Err(JournalError::Invariant(
                "read lease retained snapshot protection mismatch",
            ));
        }
        Ok(())
    }

    pub(crate) fn read_lease(&self, id: &EntryId) -> Result<ReadLease> {
        let length: i64 = self.connection.query_row(
            "SELECT length(CAST(intent AS BLOB)) FROM read_leases WHERE lease_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) {
            return Err(JournalError::Invariant("read lease metadata limit"));
        }
        let (space, snapshot, json, hash, state, observed, expires, finished):
            (String,String,String,String,String,i64,i64,Option<i64>) = self.connection.query_row(
                "SELECT space_id,snapshot_id,intent,intent_hash,state,observed_at_ms,expires_at_ms,finished_at_ms
                 FROM read_leases WHERE lease_id=?1", [id.as_str()],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
            )?;
        let intent: ReadLeaseIntent = serde_json::from_str(&json)?;
        if intent.lease_id != *id
            || intent.space_id.as_str() != space
            || intent.snapshot_id.as_str() != snapshot
            || ContentId::hash(json.as_bytes()).as_str() != hash
        {
            return Err(JournalError::Invariant(
                "read lease intent integrity mismatch",
            ));
        }
        self.validate_read_lease_intent(&intent)?;
        let state = match state.as_str() {
            "active" => ReadLeaseState::Active,
            "released" => ReadLeaseState::Released,
            "expired" => ReadLeaseState::Expired,
            _ => return Err(JournalError::Invariant("unsupported read lease state")),
        };
        let observed_at_ms =
            u64::try_from(observed).map_err(|_| JournalError::Invariant("invalid lease time"))?;
        let expires_at_ms =
            u64::try_from(expires).map_err(|_| JournalError::Invariant("invalid lease expiry"))?;
        let finished_at_ms = finished
            .map(u64::try_from)
            .transpose()
            .map_err(|_| JournalError::Invariant("invalid lease finish time"))?;
        let watermark = clock(self.connection)?;
        if observed_at_ms < intent.created_at_ms
            || expires_at_ms < intent.initial_expires_at_ms
            || expires_at_ms <= observed_at_ms
            || expires_at_ms - observed_at_ms > MAX_TTL_MS
            || observed_at_ms > watermark
            || (state == ReadLeaseState::Active) != finished_at_ms.is_none()
            || finished_at_ms.is_some_and(|t| {
                t < observed_at_ms
                    || t > watermark
                    || (state == ReadLeaseState::Expired && t < expires_at_ms)
            })
        {
            return Err(JournalError::Invariant("read lease phase/time mismatch"));
        }
        let expected: BTreeSet<ContentId> = if state == ReadLeaseState::Active {
            intent
                .entry
                .content
                .as_ref()
                .ok_or(JournalError::Invariant("read lease content missing"))?
                .chunks
                .iter()
                .map(|c| c.content_id.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        let mut statement = self
            .connection
            .prepare("SELECT content_id FROM read_lease_objects WHERE lease_id=?1")?;
        let ids: Vec<String> = statement
            .query_map([id.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let actual = ids
            .into_iter()
            .map(|id| id.parse())
            .collect::<std::result::Result<BTreeSet<ContentId>, _>>()?;
        if actual != expected {
            return Err(JournalError::Invariant(
                "read lease object protection mismatch",
            ));
        }
        Ok(ReadLease {
            intent,
            state,
            observed_at_ms,
            expires_at_ms,
            finished_at_ms,
        })
    }

    pub(crate) fn read_leases(&self, space: &SpaceId) -> Result<Vec<ReadLease>> {
        clock(self.connection)?;
        let mut statement = self
            .connection
            .prepare("SELECT lease_id FROM read_leases WHERE space_id=?1 ORDER BY lease_id")?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| self.read_lease(&id.parse()?))
            .collect()
    }
}
