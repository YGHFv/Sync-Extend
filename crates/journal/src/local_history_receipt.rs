//! Exact ordinary history commit evidence. This supplies no native authority.
use sync_extend_core_model::{ContentId, SnapshotId};

/// Issued only after the original history projection, capacity receipt and
/// SQLite commit succeed. It cannot be constructed, cloned or deserialized.
pub struct LocalHistoryCommitReceipt {
    snapshot: SnapshotId,
    baseline: Option<SnapshotId>,
    snapshot_json: String,
    operation_json: Vec<String>,
    observation_json: Option<String>,
    evidence_digest: ContentId,
}

impl LocalHistoryCommitReceipt {
    pub(crate) fn issued(
        snapshot: SnapshotId,
        baseline: Option<SnapshotId>,
        snapshot_json: String,
        operation_json: Vec<String>,
        observation_json: Option<String>,
        evidence_digest: ContentId,
    ) -> Self {
        Self {
            snapshot,
            baseline,
            snapshot_json,
            operation_json,
            observation_json,
            evidence_digest,
        }
    }

    pub fn snapshot(&self) -> &SnapshotId {
        &self.snapshot
    }

    pub fn baseline(&self) -> Option<&SnapshotId> {
        self.baseline.as_ref()
    }

    /// Exact canonical bytes supplied to the original single transaction.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Complete original planner operation list, in the original order.
    pub fn operation_json(&self) -> &[String] {
        &self.operation_json
    }

    pub fn observation_json(&self) -> Option<&str> {
        self.observation_json.as_deref()
    }

    /// Description evidence only; digests cannot construct this receipt.
    pub fn evidence_digest(&self) -> &ContentId {
        &self.evidence_digest
    }
}
