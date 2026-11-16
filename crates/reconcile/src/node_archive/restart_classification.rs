//! Restart evidence categories never create living attempts or native ownership.
use serde::Serialize;
use sync_extend_core_model::ContentId;

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OriginalNodeRestartClassification {
    /// Original rows retain unresolved intents; preserve all objects and evidence.
    PartialEvidence {
        records: u64,
        original_terminal: ContentId,
    },
    /// Immutable completion evidence passed source/chain audits. This does not
    /// reverify current target objects or retain ownership from the old process.
    CompletedEvidence {
        records: u64,
        original_terminal: ContentId,
        completion_digest: ContentId,
    },
    /// Hot rollback, WAL/SHM, unknown version/schema or contradictory evidence.
    /// This is an explicit refusal; never translate it into CREATE or cleanup.
    RefusedEvidence { reason: String },
}

impl OriginalNodeRestartClassification {
    pub fn native_restart_authority_available(&self) -> bool {
        false
    }
    pub fn cleanup_authority_available(&self) -> bool {
        false
    }
}
