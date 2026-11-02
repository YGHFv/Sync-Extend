use crate::{fault::checkpoint, now_ms, LocalSpace, ReconcileError, Result};
use sync_extend_core_model::*;
use sync_extend_journal::{SnapshotAudit, SnapshotPruning};

impl LocalSpace {
    pub fn snapshot_audit(&self) -> Result<Vec<SnapshotAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .snapshot_audit(&self.space_id, self.limits.max_storage_entries)?)
    }

    pub fn prune_snapshot(
        &mut self,
        id: &SnapshotId,
        baseline: &SnapshotId,
    ) -> Result<SnapshotPruning> {
        self.verify_root()?;
        if let Some(record) = self.journal.snapshot_pruning(&self.space_id, id)? {
            if record.baseline_root != *baseline {
                return Err(ReconcileError::Invariant(
                    "snapshot pruning request baseline mismatch",
                ));
            }
            return Ok(record);
        }
        let report = self.retention_report(Default::default())?;
        if !report.ordering_blockers.is_empty() || !report.candidate_snapshots.contains(id) {
            return Err(ReconcileError::Invariant(
                "snapshot is not a default retention candidate",
            ));
        }
        checkpoint("before_snapshot_prune");
        self.verify_root()?;
        self.verify()?;
        let record = self.journal.prune_snapshot(
            &SnapshotPruning {
                format_version: FORMAT_VERSION,
                space_id: self.space_id.clone(),
                snapshot_id: id.clone(),
                baseline_root: baseline.clone(),
                pruned_at_ms: now_ms()?,
            },
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_snapshot_prune");
        Ok(record)
    }
}
