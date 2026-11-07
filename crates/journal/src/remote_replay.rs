//! Bounded original-operation diagnostics; no writer or native execution authority.
use crate::{Journal, JournalError, RemotePublicationProof, Result};
use rusqlite::OptionalExtension;
use serde::Serialize;
use sync_extend_core_model::{
    causal::{reduce_operations, CausalReduction, MAX_CAUSAL_OPERATIONS},
    *,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteReplayDisposition {
    AlreadyApplied,
    MissingAppliedDependencies,
    ConflictPreserved,
    NewFilePutCandidate,
    NativeMutationUnavailable,
    UnsupportedEntryKind,
    UnsupportedParentTopology,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RemoteReplayReport {
    pub operation_id: OperationId,
    pub baseline_root: SnapshotId,
    pub received_sequence: u64,
    pub applied_sequence: u64,
    pub stored_state: Option<String>,
    pub missing_applied_dependencies: VersionVector,
    pub disposition: RemoteReplayDisposition,
    pub received_frontiers: CausalReduction,
    pub candidate_frontiers: Option<CausalReduction>,
    pub execution_authorized: bool,
    pub worktree_inspected: bool,
    pub whole_space_converged: bool,
    pub remote_backup_complete: bool,
}

impl Journal {
    /// Signature proves original origin, not user peer approval. Read one bounded
    /// snapshot; the returned candidate is descriptive, never an executor token.
    pub fn replay_remote_operation(
        &self,
        proof: &RemotePublicationProof,
    ) -> Result<RemoteReplayReport> {
        proof.verify()?;
        if !self.connection.is_autocommit() {
            return Err(JournalError::Invariant("remote replay caller transaction"));
        }
        self.connection.execute_batch("BEGIN DEFERRED")?;
        let result = self.remote_replay_snapshot(proof);
        self.connection.execute_batch("ROLLBACK")?;
        result
    }

    fn remote_replay_snapshot(&self, proof: &RemotePublicationProof) -> Result<RemoteReplayReport> {
        let candidate = &proof.operation;
        let payload = &candidate.payload;
        if self.state("space_id")?.as_deref() != Some(payload.space_id.as_str())
            || self.state("device_id")?.as_deref() == Some(payload.origin_device_id.as_str())
        {
            return Err(JournalError::Invariant("remote replay original scope"));
        }
        let temporary: i64 =
            self.connection
                .query_row("SELECT count(*) FROM temp.sqlite_schema", [], |row| {
                    row.get(0)
                })?;
        let manifest_bytes: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(CAST(s.manifest AS BLOB))
             FROM main.current_manifests c JOIN main.snapshots s USING(snapshot_id)
             WHERE c.space_id=?1",
                [payload.space_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if temporary != 0
            || !manifest_bytes.is_some_and(|bytes| (1..=64 * 1024 * 1024).contains(&bytes))
        {
            return Err(JournalError::Invariant(
                "remote replay shadow or baseline byte budget",
            ));
        }
        let baseline = self
            .current(&payload.space_id)?
            .ok_or(JournalError::Invariant(
                "remote replay applied baseline missing",
            ))?;
        let received_sequence = self.cursor(&payload.space_id, &payload.origin_device_id)?;
        let applied_sequence = baseline.version_vector.get(&payload.origin_device_id);
        let mut statement = self.connection.prepare(
            "SELECT op_id,origin_device_id,origin_seq,
                CASE WHEN length(CAST(payload AS BLOB))<=16777216 THEN payload ELSE '' END,state
             FROM main.operations WHERE space_id=?1
             ORDER BY origin_device_id,origin_seq LIMIT ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![
            payload.space_id.as_str(),
            (MAX_CAUSAL_OPERATIONS + 1) as i64,
        ])?;
        let mut received = Vec::new();
        let mut applied = Vec::new();
        let mut applied_vector = VersionVector::default();
        let mut stored_state = None;
        let mut count = 0usize;
        let mut bytes = 0usize;
        while let Some(row) = rows.next()? {
            count += 1;
            if count > MAX_CAUSAL_OPERATIONS {
                return Err(JournalError::Invariant("remote replay operation budget"));
            }
            let json: String = row.get(3)?;
            bytes = bytes
                .checked_add(json.len())
                .filter(|n| *n <= 64 * 1024 * 1024)
                .ok_or(JournalError::Invariant("remote replay byte budget"))?;
            if json.is_empty() {
                return Err(JournalError::Invariant("remote replay oversized payload"));
            }
            let operation: Operation = serde_json::from_str(&json)?;
            operation.validate()?;
            let state: String = row.get(4)?;
            if operation.payload.space_id != payload.space_id
                || operation.op_id.as_str() != row.get::<_, String>(0)?
                || operation.payload.origin_device_id.as_str() != row.get::<_, String>(1)?
                || i64::try_from(operation.payload.origin_seq).ok() != Some(row.get::<_, i64>(2)?)
                || serde_json::to_string(&operation)? != json
                || !matches!(state.as_str(), "pending" | "received" | "materialized")
            {
                return Err(JournalError::Invariant(
                    "remote replay original row differs",
                ));
            }
            if operation.op_id == candidate.op_id {
                if operation != *candidate {
                    return Err(JournalError::Invariant(
                        "remote replay original identity collision",
                    ));
                }
                stored_state = Some(state.clone());
            } else if operation.payload.origin_device_id == payload.origin_device_id
                && operation.payload.origin_seq == payload.origin_seq
            {
                return Err(JournalError::Invariant(
                    "remote replay original sequence collision",
                ));
            }
            let in_applied = baseline
                .version_vector
                .get(&operation.payload.origin_device_id)
                >= operation.payload.origin_seq;
            if in_applied != (state == "materialized") {
                return Err(JournalError::Invariant(
                    "remote replay applied state differs",
                ));
            }
            if in_applied {
                applied_vector.observe(
                    operation.payload.origin_device_id.clone(),
                    operation.payload.origin_seq,
                );
                applied.push(operation.clone());
            }
            if state != "pending" {
                received.push(operation);
            }
        }
        if applied_vector != baseline.version_vector || received_sequence < applied_sequence {
            return Err(JournalError::Invariant(
                "remote replay applied vector differs",
            ));
        }
        let received_frontiers =
            reduce_operations(&payload.space_id, &received, MAX_CAUSAL_OPERATIONS)?;
        let mut cursor_statement = self.connection.prepare(
            "SELECT device_id,contiguous_seq FROM main.receive_cursors
             WHERE space_id=?1 ORDER BY device_id LIMIT 1025",
        )?;
        let mut cursor_rows = cursor_statement.query([payload.space_id.as_str()])?;
        let mut cursor_vector = VersionVector::default();
        let mut cursor_count = 0usize;
        while let Some(row) = cursor_rows.next()? {
            cursor_count += 1;
            let device: DeviceId = row.get::<_, String>(0)?.parse()?;
            let sequence = u64::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| JournalError::Invariant("remote replay negative cursor"))?;
            if cursor_count > 1024 {
                return Err(JournalError::Invariant("remote replay cursor budget"));
            }
            if sequence != 0 {
                cursor_vector.observe(device, sequence);
            }
        }
        if received_frontiers.received_vector != cursor_vector
            || cursor_vector.get(&payload.origin_device_id) != received_sequence
        {
            return Err(JournalError::Invariant(
                "remote replay received cursor differs",
            ));
        }
        let mut missing = VersionVector::default();
        for (device, sequence) in &payload.causal.0 {
            if baseline.version_vector.get(device) < *sequence {
                missing.observe(device.clone(), *sequence);
            }
        }
        let (disposition, candidate_frontiers) = if payload.origin_seq <= applied_sequence {
            if stored_state.as_deref() != Some("materialized") {
                return Err(JournalError::Invariant(
                    "remote replay applied original missing",
                ));
            }
            (RemoteReplayDisposition::AlreadyApplied, None)
        } else if !missing.0.is_empty() {
            (RemoteReplayDisposition::MissingAppliedDependencies, None)
        } else {
            if applied_sequence.checked_add(1) != Some(payload.origin_seq) {
                return Err(JournalError::Invariant(
                    "remote replay next original sequence differs",
                ));
            }
            applied.push(candidate.clone());
            let reduced = reduce_operations(&payload.space_id, &applied, MAX_CAUSAL_OPERATIONS)?;
            let entry_id = match &payload.change {
                Change::Put { entry } => &entry.entry_id,
                Change::Rename { entry_id, .. } | Change::Delete { entry_id } => entry_id,
            };
            let frontier = reduced
                .entries
                .get(entry_id)
                .ok_or(JournalError::Invariant(
                    "remote replay original frontier missing",
                ))?;
            let conflict = frontier.delete_conflict
                || frontier.paths.len() > 1
                || frontier.contents.len() > 1
                || reduced
                    .path_collisions
                    .iter()
                    .any(|collision| collision.entries.contains(entry_id));
            let disposition = if conflict {
                RemoteReplayDisposition::ConflictPreserved
            } else {
                match &payload.change {
                    Change::Put { entry } if entry.kind != EntryKind::File => {
                        RemoteReplayDisposition::UnsupportedEntryKind
                    }
                    Change::Put { entry }
                        if entry.path.parent().is_some_and(|parent| {
                            !baseline
                                .entries
                                .values()
                                .any(|old| old.kind == EntryKind::Directory && old.path == parent)
                        }) =>
                    {
                        RemoteReplayDisposition::UnsupportedParentTopology
                    }
                    Change::Put { entry }
                        if !baseline.entries.contains_key(entry_id)
                            && !baseline.tombstones.contains_key(entry_id)
                            && !baseline.entries.values().any(|old| {
                                old.path.collision_key() == entry.path.collision_key()
                            }) =>
                    {
                        RemoteReplayDisposition::NewFilePutCandidate
                    }
                    _ => RemoteReplayDisposition::NativeMutationUnavailable,
                }
            };
            (disposition, Some(reduced))
        };
        Ok(RemoteReplayReport {
            operation_id: candidate.op_id.clone(),
            baseline_root: baseline.root()?,
            received_sequence,
            applied_sequence,
            stored_state,
            missing_applied_dependencies: missing,
            disposition,
            received_frontiers,
            candidate_frontiers,
            execution_authorized: false,
            worktree_inspected: false,
            whole_space_converged: false,
            remote_backup_complete: false,
        })
    }
}
