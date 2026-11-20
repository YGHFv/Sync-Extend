//! Transactional bridge from an issued ordinary reservation to exact history.
use super::{consume, OriginalLocalHistoryReservation};
use crate::{Journal, JournalError, LocalHistoryCommitReceipt, Result};
use sync_extend_core_model::{
    persisted_rename::RenameObservationMap, Manifest, Operation, SnapshotId,
};

impl Journal {
    pub(super) fn commit_local_reserved_receipted(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: Option<(&RenameObservationMap, usize)>,
        reservation: Option<&OriginalLocalHistoryReservation>,
    ) -> Result<(
        LocalHistoryCommitReceipt,
        Option<super::OriginalNativePhaseChain>,
    )> {
        crate::sql_integer(timestamp)?;
        manifest.validate()?;
        if operations.len() > sync_extend_core_model::limits::MAX_ENTRIES {
            return Err(JournalError::Invariant(
                "local commit operation count limit",
            ));
        }
        let bounds = match observations {
            Some((_, max)) => self.writer_capacity_limits(max)?,
            None => crate::storage_policy::capacity_limits(self.max_storage_entries)?,
        };
        let mut chunk_visits = 0usize;
        for content in manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            chunk_visits = chunk_visits
                .checked_add(content.chunks.len())
                .ok_or(JournalError::Invariant("local commit chunk count overflow"))?;
            if chunk_visits > sync_extend_core_model::limits::MAX_CHUNKS {
                return Err(JournalError::Invariant("local commit chunk count limit"));
            }
        }
        let snapshot_json = serde_json::to_string(manifest)?;
        if snapshot_json.len() > crate::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("local commit snapshot byte limit"));
        }
        let mut operation_json = Vec::new();
        let mut input_bytes = snapshot_json.len() as u64;
        for op in operations {
            op.validate()?;
            crate::sql_integer(op.payload.origin_seq)?;
            let json = serde_json::to_string(op)?;
            if json.len() > crate::MAX_OPERATION_BYTES {
                return Err(JournalError::Invariant("local commit operation byte limit"));
            }
            input_bytes = input_bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant("local commit input byte overflow"))?;
            if input_bytes > sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024 {
                return Err(JournalError::Invariant(
                    "local commit aggregate input byte limit",
                ));
            }
            operation_json.push(json);
        }
        let observation_bytes = observations
            .map(|(map, max)| {
                map.validate(manifest, max)?;
                crate::rename_observation::serialize_observation(map)
            })
            .transpose()?;
        let observation_json = observation_bytes
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| JournalError::Invariant("rename observation serialization"))?;
        let evidence_digest = sync_extend_core_model::ContentId::hash(&serde_json::to_vec(&(
            1u32,
            expected_root,
            &snapshot_json,
            &operation_json,
            observation_json,
            timestamp,
        ))?);
        let retained_observation_json = observation_json.map(str::to_owned);
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let view = self.read_view();
        let (original_phase_chain, before) = if let Some(reservation) = reservation {
            let prior_reservation_view =
                view.audit_local_commit_capacity(&manifest.space_id, bounds)?;
            let original_phase_chain = consume(
                &tx,
                &self.original_local_history_issuer,
                reservation,
                expected_root,
                manifest,
                operations,
                timestamp,
                observations,
            )?;
            let consumed_view = view.audit_local_commit_capacity(&manifest.space_id, bounds)?;
            let retained = prior_reservation_view
                .rows
                .iter()
                .filter(|row| {
                    !(row.table() == "local_state" && row.primary_key() == [super::KEY.to_owned()])
                })
                .collect::<Vec<_>>();
            if retained.len() != consumed_view.rows.len()
                || retained.iter().any(|row| {
                    !consumed_view.rows.iter().any(|current| {
                        row.table() == current.table()
                            && row.primary_key() == current.primary_key()
                            && row.columns() == current.columns()
                    })
                })
            {
                return Err(JournalError::Invariant(
                    "original reservation consume collateral rows",
                ));
            }
            // This is already the audited pre-commit state in the same SQL
            // transaction. The collateral check above has made no writes.
            (Some(original_phase_chain), consumed_view)
        } else {
            if view.state(super::KEY)?.is_some() {
                return Err(JournalError::Invariant(
                    "original reserved history defers ordinary commit",
                ));
            }
            (
                None,
                view.audit_local_commit_capacity(&manifest.space_id, bounds)?,
            )
        };
        if observations.is_some() && view.state("worktree")?.is_none() {
            return Err(JournalError::Invariant(
                "observed commit requires initialized worktree",
            ));
        }
        let projection = crate::storage_policy::local_commit::project(
            &before,
            crate::storage_policy::local_commit::Input {
                expected_root,
                manifest,
                operations,
                operation_json: &operation_json,
                snapshot_json: &snapshot_json,
                timestamp,
                observation_json,
            },
        )?;
        let root = self.commit_history_sql(
            &tx,
            expected_root,
            manifest,
            operations,
            timestamp,
            crate::Completion::None,
        )?;
        if let Some((map, max)) = observations {
            let json = observation_json
                .ok_or(JournalError::Invariant("local observation bytes missing"))?;
            tx.execute(
                "INSERT INTO rename_observations VALUES (?1,?2,?3,?4)",
                rusqlite::params![
                    map.scope.space_id.as_str(),
                    root.as_str(),
                    json,
                    sync_extend_core_model::ContentId::hash(json.as_bytes()).as_str()
                ],
            )?;
            crate::rename_observation::audit_observation(&tx, &manifest.space_id, max)?;
        }
        let after = view.audit_local_commit_capacity(&manifest.space_id, bounds)?;
        projection.receipt(&after)?;
        tx.commit()?;
        Ok((
            LocalHistoryCommitReceipt::issued(
                root,
                expected_root.cloned(),
                snapshot_json,
                operation_json,
                retained_observation_json,
                evidence_digest,
            ),
            original_phase_chain,
        ))
    }
}
