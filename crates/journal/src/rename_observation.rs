use crate::{Journal, JournalError, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::io::{self, Write};
use sync_extend_core_model::{persisted_rename::RenameObservationMap, Manifest, SpaceId};

pub(crate) const MAX_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;

impl Journal {
    /// Audit optional local inference metadata in one WAL read snapshot.
    /// Absence is safe loss of inference, not a missing durable content owner.
    pub fn rename_observation(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Option<RenameObservationMap>> {
        if self.state("space_id")?.as_deref() != Some(space.as_str()) {
            return Err(JournalError::Invariant("rename observation space mismatch"));
        }
        // Native admission callbacks already own a SQLite transaction. Audit
        // that snapshot instead of starting a nested BEGIN or committing it.
        if !self.connection.is_autocommit() {
            self.check_storage_metadata_limit(max)?;
            return audit_observation(&self.connection, space, max);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        self.check_storage_metadata_limit(max)?;
        let result = audit_observation(&tx, space, max)?;
        tx.commit()?;
        Ok(result)
    }
}

pub(crate) fn audit_observation(
    connection: &Connection,
    space: &SpaceId,
    max: usize,
) -> Result<Option<RenameObservationMap>> {
    let foreign: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM rename_observations WHERE space_id!=?1)",
        [space.as_str()],
        |r| r.get(0),
    )?;
    if foreign {
        return Err(JournalError::Invariant("foreign rename observation"));
    }
    let stored: Option<(String, String, String)> = connection
        .query_row(
            "SELECT snapshot_id,
                CASE WHEN length(CAST(observation AS BLOB)) BETWEEN 1 AND 16777216
                    THEN observation ELSE '' END,
                observation_hash
             FROM rename_observations WHERE space_id=?1",
            [space.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((root, json, hash)) = stored else {
        return Ok(None);
    };
    if connection
        .query_row(
            "SELECT value FROM local_state WHERE key='space_id'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .as_deref()
        != Some(space.as_str())
    {
        return Err(JournalError::Invariant("rename observation space mismatch"));
    }
    let map: RenameObservationMap = serde_json::from_str(&json)?;
    // Hash canonical typed serialization, not merely a mutable raw SQL string.
    let canonical = serialize_observation(&map)?;
    if canonical.as_slice() != json.as_bytes()
        || sync_extend_core_model::ContentId::hash(&canonical).as_str() != hash
        || map.scope.space_id != *space
        || map.scope.prior_snapshot.as_str() != root
    {
        return Err(JournalError::Invariant(
            "rename observation integrity mismatch",
        ));
    }
    let manifest: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(s.manifest AS BLOB)) BETWEEN 1 AND ?3
                THEN s.manifest ELSE '' END
             FROM current_manifests c JOIN snapshots s ON c.snapshot_id=s.snapshot_id
             WHERE c.space_id=?1 AND s.space_id=?1 AND s.snapshot_id=?2
                AND s.state='materialized'
                AND NOT EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=s.snapshot_id)",
            rusqlite::params![space.as_str(), root, max.saturating_mul(1024) as i64],
            |r| r.get(0),
        )
        .optional()?;
    let prior: Manifest = serde_json::from_str(
        &manifest.ok_or(JournalError::Invariant("rename observation is not current"))?,
    )?;
    map.validate(&prior, max)?;
    Ok(Some(map))
}

pub(crate) fn serialize_observation(map: &RenameObservationMap) -> Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_OBSERVATION_BYTES {
                return Err(io::Error::other("rename observation metadata byte limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, map)?;
    Ok(output.0)
}
