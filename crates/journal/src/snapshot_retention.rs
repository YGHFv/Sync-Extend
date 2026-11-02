use crate::{Journal, JournalError, Result, MAX_OPERATION_BYTES};
use rusqlite::{params, Connection};
use std::collections::BTreeSet;
use sync_extend_core_model::*;

#[derive(Clone, Debug)]
pub struct RetainedSnapshot {
    pub snapshot_id: SnapshotId,
    pub created_at_ms: u64,
    pub state: String,
    pub locked: bool,
    pub manifest: Manifest,
}

fn retained_snapshot(
    connection: &Connection,
    space: &SpaceId,
    id: &SnapshotId,
) -> Result<RetainedSnapshot> {
    let length: i64 = connection.query_row(
        "SELECT length(CAST(manifest AS BLOB)) FROM snapshots WHERE space_id=?1 AND snapshot_id=?2",
        params![space.as_str(), id.as_str()],
        |r| r.get(0),
    )?;
    if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) {
        return Err(JournalError::Invariant("snapshot metadata limit"));
    }
    let (json, time, state, locked): (String, i64, String, i64) = connection.query_row(
        "SELECT manifest,created_at_ms,state,locked FROM snapshots WHERE space_id=?1 AND snapshot_id=?2",
        params![space.as_str(), id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let manifest: Manifest = serde_json::from_str(&json)?;
    if manifest.space_id != *space
        || manifest.root()? != *id
        || !matches!(locked, 0 | 1)
        || !matches!(
            state.as_str(),
            "metadata_only" | "content_closed" | "materialized"
        )
    {
        return Err(JournalError::Invariant(
            "retained snapshot metadata mismatch",
        ));
    }
    let created_at_ms =
        u64::try_from(time).map_err(|_| JournalError::Invariant("invalid snapshot time"))?;
    let expected: BTreeSet<_> = manifest
        .entries
        .values()
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|content| content.chunks.iter().map(|c| c.content_id.clone()))
        .collect();
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM snapshot_objects WHERE snapshot_id=?1",
        [id.as_str()],
        |r| r.get(0),
    )?;
    if count < 0 || count as u64 > limits::MAX_CHUNKS as u64 {
        return Err(JournalError::Invariant(
            "snapshot reference inventory limit",
        ));
    }
    let mut statement =
        connection.prepare("SELECT content_id FROM snapshot_objects WHERE snapshot_id=?1")?;
    let ids: Vec<String> = statement
        .query_map([id.as_str()], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    let actual = ids
        .into_iter()
        .map(|id| id.parse())
        .collect::<std::result::Result<BTreeSet<ContentId>, _>>()?;
    if actual != expected {
        return Err(JournalError::Invariant(
            "retained snapshot protection mismatch",
        ));
    }
    Ok(RetainedSnapshot {
        snapshot_id: id.clone(),
        created_at_ms,
        state,
        locked: locked == 1,
        manifest,
    })
}

impl Journal {
    pub fn retained_snapshot(&self, space: &SpaceId, id: &SnapshotId) -> Result<RetainedSnapshot> {
        retained_snapshot(&self.connection, space, id)
    }

    pub fn retained_snapshots(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<RetainedSnapshot>> {
        self.check_storage_metadata_limit(max_entries)?;
        let mut statement = self
            .connection
            .prepare("SELECT snapshot_id FROM snapshots WHERE space_id=?1 ORDER BY snapshot_id")?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| self.retained_snapshot(space, &id.parse()?))
            .collect()
    }

    pub fn set_snapshot_locked(
        &mut self,
        space: &SpaceId,
        id: &SnapshotId,
        locked: bool,
    ) -> Result<RetainedSnapshot> {
        let tx = self.connection.transaction()?;
        let mut snapshot = retained_snapshot(&tx, space, id)?;
        if locked && snapshot.state != "materialized" {
            return Err(JournalError::Invariant("snapshot is not materialized"));
        }
        if snapshot.locked != locked
            && tx.execute(
                "UPDATE snapshots SET locked=?1 WHERE space_id=?2 AND snapshot_id=?3 AND locked=?4",
                params![locked, space.as_str(), id.as_str(), snapshot.locked],
            )? != 1
        {
            return Err(JournalError::Invariant("snapshot lock changed"));
        }
        tx.commit()?;
        snapshot.locked = locked;
        Ok(snapshot)
    }

    pub fn publications(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<crate::Publication>> {
        self.check_storage_metadata_limit(max_entries)?;
        let mut statement = self.connection.prepare(
            "SELECT transaction_id FROM publications WHERE space_id=?1 ORDER BY transaction_id",
        )?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id: EntryId = id.parse()?;
                let length: i64 = self.connection.query_row(
                    "SELECT length(CAST(intent AS BLOB)) FROM publications WHERE transaction_id=?1",
                    [id.as_str()],
                    |r| r.get(0),
                )?;
                if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) {
                    return Err(JournalError::Invariant("publication metadata limit"));
                }
                let publication = self.publication(&id)?;
                if publication.intent.space_id != *space
                    || (publication.state == crate::PublicationState::Committed)
                        != publication.committed_snapshot.is_some()
                    || (publication.cleaned
                        && publication.state != crate::PublicationState::Committed)
                {
                    return Err(JournalError::Invariant("publication phase/space mismatch"));
                }
                let expected: BTreeSet<_> =
                    if publication.state == crate::PublicationState::Committed {
                        BTreeSet::new()
                    } else {
                        publication
                            .intent
                            .content
                            .chunks
                            .iter()
                            .map(|c| c.content_id.clone())
                            .collect()
                    };
                let mut statement = self.connection.prepare(
                    "SELECT content_id FROM publication_objects WHERE transaction_id=?1",
                )?;
                let ids: Vec<String> = statement
                    .query_map([id.as_str()], |r| r.get(0))?
                    .collect::<std::result::Result<_, _>>()?;
                let actual = ids
                    .into_iter()
                    .map(|id| id.parse())
                    .collect::<std::result::Result<BTreeSet<ContentId>, _>>()?;
                if actual != expected {
                    return Err(JournalError::Invariant("publication protection mismatch"));
                }
                Ok(publication)
            })
            .collect()
    }
}
