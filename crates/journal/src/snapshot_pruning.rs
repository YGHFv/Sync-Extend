use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, Journal,
    JournalError, Result, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPruning {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub snapshot_id: SnapshotId,
    pub baseline_root: SnapshotId,
    pub pruned_at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct SnapshotAudit {
    pub snapshot_id: SnapshotId,
    pub created_at_ms: u64,
    pub state: String,
    pub locked: bool,
    pub content_retained: bool,
    pub pruning: Option<SnapshotPruning>,
}

pub(crate) fn require_unpruned(connection: &Connection, id: &SnapshotId) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM snapshot_prunings WHERE snapshot_id=?1)",
        [id.as_str()],
        |r| r.get(0),
    )?;
    if exists {
        return Err(JournalError::Invariant(
            "snapshot content has been explicitly pruned",
        ));
    }
    Ok(())
}

pub(crate) fn pruning(
    connection: &Connection,
    space: &SpaceId,
    id: &SnapshotId,
) -> Result<Option<SnapshotPruning>> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(intent AS BLOB)) FROM snapshot_prunings WHERE snapshot_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Ok(None);
    };
    if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) {
        return Err(JournalError::Invariant("snapshot pruning metadata limit"));
    }
    let (stored_space, baseline, json, hash, time): (String, String, String, String, i64) = connection.query_row(
        "SELECT space_id,baseline_root,intent,intent_hash,pruned_at_ms FROM snapshot_prunings WHERE snapshot_id=?1",
        [id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    )?;
    let intent: SnapshotPruning = serde_json::from_str(&json)?;
    if intent.format_version != FORMAT_VERSION
        || intent.space_id != *space
        || stored_space != space.as_str()
        || intent.snapshot_id != *id
        || intent.baseline_root.as_str() != baseline
        || intent.baseline_root == *id
        || sql_integer(intent.pruned_at_ms)? != time
        || ContentId::hash(json.as_bytes()).as_str() != hash
    {
        return Err(JournalError::Invariant(
            "snapshot pruning intent integrity mismatch",
        ));
    }
    // The baseline is an audit dependency only; later retirement must not require its CAS.
    let (json, length): (String, i64) = connection.query_row(
        "SELECT CASE WHEN length(CAST(manifest AS BLOB))<=?3 THEN manifest ELSE '' END,
         length(CAST(manifest AS BLOB)) FROM snapshots WHERE space_id=?1 AND snapshot_id=?2",
        params![space.as_str(), baseline, MAX_OPERATION_BYTES as i64],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) {
        return Err(JournalError::Invariant("pruning baseline metadata limit"));
    }
    let manifest: Manifest = serde_json::from_str(&json)?;
    if manifest.space_id != *space || manifest.root()? != intent.baseline_root {
        return Err(JournalError::Invariant(
            "pruning baseline integrity mismatch",
        ));
    }
    Ok(Some(intent))
}

pub(crate) fn validate_pruned_snapshot(
    connection: &Connection,
    space: &SpaceId,
    id: &SnapshotId,
    locked: i64,
    state: &str,
) -> Result<()> {
    let dependent: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM current_manifests WHERE snapshot_id=?1)
            OR EXISTS(SELECT 1 FROM read_leases WHERE snapshot_id=?1)
            OR EXISTS(SELECT 1 FROM mutations WHERE baseline_root=?1 OR committed_snapshot=?1)
            OR EXISTS(SELECT 1 FROM publications WHERE committed_snapshot=?1
                OR json_extract(intent,'$.baseline_root')=?1 OR json_extract(intent,'$.source_snapshot')=?1)",
        [id.as_str()], |r| r.get(0),
    )?;
    if locked != 0 || state != "materialized" || dependent {
        return Err(JournalError::Invariant(
            "pruned snapshot is still protected",
        ));
    }
    let stored_space: String = connection.query_row(
        "SELECT space_id FROM snapshots WHERE snapshot_id=?1",
        [id.as_str()],
        |r| r.get(0),
    )?;
    if stored_space != space.as_str() {
        return Err(JournalError::Invariant("pruned snapshot space mismatch"));
    }
    Ok(())
}

impl Journal {
    pub fn check_snapshot_prunings(&self, space: &SpaceId, max_entries: usize) -> Result<()> {
        self.snapshot_audit(space, max_entries)?;
        Ok(())
    }
    pub(crate) fn require_unpruned_root(&self, id: &SnapshotId) -> Result<()> {
        require_unpruned(&self.connection, id)
    }

    pub(crate) fn require_snapshot_retained(&self, space: &SpaceId, id: &SnapshotId) -> Result<()> {
        if pruning(&self.connection, space, id)?.is_some() {
            return Err(JournalError::Invariant(
                "snapshot content has been explicitly pruned",
            ));
        }
        Ok(())
    }

    pub fn snapshot_pruning(
        &self,
        space: &SpaceId,
        id: &SnapshotId,
    ) -> Result<Option<SnapshotPruning>> {
        let snapshot = audit_snapshot(&self.connection, space, id)?;
        let record = pruning(&self.connection, space, id)?;
        if record.is_some() && snapshot.locked {
            return Err(JournalError::Invariant("pruned snapshot locked"));
        }
        Ok(record)
    }

    pub fn snapshot_audit(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<SnapshotAudit>> {
        self.check_storage_metadata_limit(max_entries)?;
        let mut statement = self.connection.prepare("SELECT snapshot_id FROM snapshots WHERE space_id=?1 ORDER BY created_at_ms,snapshot_id")?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id = id.parse()?;
                let snapshot = audit_snapshot(&self.connection, space, &id)?;
                let pruning = pruning(&self.connection, space, &id)?;
                Ok(SnapshotAudit {
                    snapshot_id: id,
                    created_at_ms: snapshot.created_at_ms,
                    state: snapshot.state,
                    locked: snapshot.locked,
                    content_retained: pruning.is_none(),
                    pruning,
                })
            })
            .collect()
    }

    pub fn prune_snapshot(
        &mut self,
        intent: &SnapshotPruning,
        max_entries: usize,
    ) -> Result<SnapshotPruning> {
        if intent.format_version != FORMAT_VERSION || intent.snapshot_id == intent.baseline_root {
            return Err(JournalError::Invariant("invalid snapshot pruning intent"));
        }
        sql_integer(intent.pruned_at_ms)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(old) = self.snapshot_pruning(&intent.space_id, &intent.snapshot_id)? {
            if old.baseline_root != intent.baseline_root {
                return Err(JournalError::Invariant(
                    "snapshot pruning request baseline mismatch",
                ));
            }
            tx.commit()?;
            return Ok(old);
        }
        self.check_storage_metadata_limit(max_entries)?;
        self.snapshot_audit(&intent.space_id, max_entries)?;
        let snapshots = self.retained_snapshots(&intent.space_id, max_entries)?;
        let current = self
            .current(&intent.space_id)?
            .ok_or(JournalError::Invariant("missing current snapshot"))?;
        if current.root()? != intent.baseline_root {
            return Err(JournalError::Invariant("snapshot pruning baseline changed"));
        }
        let target = snapshots
            .iter()
            .find(|s| s.snapshot_id == intent.snapshot_id)
            .ok_or(JournalError::Invariant("pruning target not retained"))?;
        if target.locked || target.state != "materialized" {
            return Err(JournalError::Invariant("snapshot pruning target protected"));
        }
        // Validate every durable record before consulting its snapshot dependencies.
        self.read_leases(&intent.space_id, max_entries)?;
        for mutation in self.mutations(&intent.space_id)? {
            self.verify_mutation_references(&mutation.intent.transaction_id)?;
        }
        self.publications(&intent.space_id, max_entries)?;
        self.cleanup_plans(&intent.space_id)?;
        validate_pruned_snapshot(
            &tx,
            &intent.space_id,
            &intent.snapshot_id,
            0,
            "materialized",
        )?;
        let mut ordered = Vec::new();
        let mut visits = 0usize;
        for snapshot in &snapshots {
            for content in snapshot
                .manifest
                .entries
                .values()
                .filter_map(|e| e.content.as_ref())
            {
                visits = visits
                    .checked_add(content.chunks.len())
                    .filter(|n| *n <= max_entries)
                    .ok_or(JournalError::Invariant("pruning reference count limit"))?;
            }
            let rank = snapshot
                .manifest
                .version_vector
                .0
                .values()
                .try_fold(0u64, |sum, n| sum.checked_add(*n))
                .ok_or(JournalError::Invariant("pruning causal rank overflow"))?;
            ordered.push((
                rank,
                &snapshot.snapshot_id,
                &snapshot.manifest.version_vector,
            ));
        }
        ordered.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        if ordered.last().map(|s| s.1) != Some(&intent.baseline_root)
            || ordered
                .windows(2)
                .any(|p| p[1].2 == p[0].2 || !p[1].2.dominates(p[0].2))
            || ordered
                .iter()
                .rev()
                .take(4)
                .any(|s| s.1 == &intent.snapshot_id)
            || ordered.iter().rev().take(4).any(|s| {
                snapshots
                    .iter()
                    .find(|snapshot| &snapshot.snapshot_id == s.1)
                    .is_none_or(|snapshot| snapshot.state != "materialized")
            })
        {
            return Err(JournalError::Invariant(
                "pruning requires causal history outside current plus three",
            ));
        }
        let json = serde_json::to_string(intent)?;
        check_storage_metadata_limit(&tx, max_entries, 1, json.len() as u64)?;
        tx.execute(
            "INSERT INTO snapshot_prunings VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                intent.snapshot_id.as_str(),
                intent.space_id.as_str(),
                intent.baseline_root.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(intent.pruned_at_ms)?,
            ],
        )?;
        tx.execute(
            "DELETE FROM snapshot_objects WHERE snapshot_id=?1",
            [intent.snapshot_id.as_str()],
        )?;
        audit_snapshot(&tx, &intent.space_id, &intent.snapshot_id)?;
        tx.commit()?;
        Ok(intent.clone())
    }
}
