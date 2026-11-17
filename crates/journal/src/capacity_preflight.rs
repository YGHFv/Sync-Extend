//! Read-only pre-effect ordinary history capacity; does not reserve or grant authority.
use crate::{Journal, JournalError, Result};
use sync_extend_core_model::{Manifest, Operation, SnapshotId};

impl Journal {
    /// Original projection against current rows under one read transaction.
    /// Observation and concurrent-write reservation remain separate obligations.
    pub fn preflight_local_history_capacity(
        &self,
        baseline: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: &sync_extend_core_model::persisted_rename::RenameObservationMap,
        max_entries: usize,
    ) -> Result<()> {
        manifest.validate()?;
        let snapshot_json = serde_json::to_string(manifest)?;
        let operation_json = operations
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if snapshot_json.len() > super::MAX_OPERATION_BYTES
            || operation_json
                .iter()
                .any(|bytes| bytes.len() > super::MAX_OPERATION_BYTES)
            || operation_json.len() > sync_extend_core_model::limits::MAX_ENTRIES
        {
            return Err(JournalError::Invariant(
                "pre-effect original history input budget",
            ));
        }
        for operation in operations {
            operation.validate()?;
        }
        observations.validate(manifest, max_entries)?;
        let observation_bytes = crate::rename_observation::serialize_observation(observations)?;
        let observation_json = std::str::from_utf8(&observation_bytes)
            .map_err(|_| JournalError::Invariant("pre-effect original observation encoding"))?;
        if observation_json.len() > super::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant(
                "pre-effect observation byte budget",
            ));
        }
        let aggregate = operation_json
            .iter()
            .try_fold(snapshot_json.len() as u64, |sum, bytes| {
                sum.checked_add(bytes.len() as u64)
            })
            .and_then(|sum| sum.checked_add(observation_json.len() as u64))
            .ok_or(JournalError::Invariant(
                "pre-effect aggregate byte overflow",
            ))?;
        if aggregate > sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024 {
            return Err(JournalError::Invariant("pre-effect aggregate input budget"));
        }
        crate::sql_integer(timestamp)?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let bounds = self.writer_capacity_limits(max_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&manifest.space_id, bounds)?;
        let _projection = crate::storage_policy::local_commit::project(
            &before,
            crate::storage_policy::local_commit::Input {
                expected_root: baseline,
                manifest,
                operations,
                operation_json: &operation_json,
                snapshot_json: &snapshot_json,
                timestamp,
                observation_json: Some(observation_json),
            },
        )?;
        tx.rollback()?;
        Ok(())
    }
}
