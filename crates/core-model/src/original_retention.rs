//! Prospective committed original disposition, not an executor or backup receipt.
//! Native/journal adapters must establish every claimed observation independently.

use crate::{
    ContentId, EntryId, FileManifest, ModelError, Result, SnapshotId, SpaceId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedOriginalAction {
    Delete,
    Replace,
    Move,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalRetentionScope {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub transaction_id: EntryId,
    pub execution_id: EntryId,
    pub action: RetainedOriginalAction,
    pub mutation_intent_hash: ContentId,
    pub execution_hash: ContentId,
    pub baseline_snapshot: SnapshotId,
    pub committed_snapshot: SnapshotId,
    pub original_identity: ContentId,
    pub content: FileManifest,
}

impl OriginalRetentionScope {
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        if self.format_version != FORMAT_VERSION
            || self.action == RetainedOriginalAction::Move
            || self.baseline_snapshot == self.committed_snapshot
        {
            return Err(ModelError::InvalidData("invalid retained original scope"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRetentionPhase {
    Retained,
    DeletePending,
    Disposed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRetentionRequest {
    Inspect,
    RecoverAudit,
    Prepare,
    Execute,
    FinalizeAbsence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalSlotEvidence {
    NotChecked,
    ExactVerified,
    Missing,
    Foreign,
    Corrupt,
    Inaccessible,
    DeletePendingError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRetentionEvidence {
    pub metadata_verified: bool,
    pub exact_committed_mutation: bool,
    pub owner_namespace_guarded: bool,
    pub historical_snapshot_retained: bool,
    pub exact_snapshot_pins: bool,
    pub cas_session_held: bool,
    pub baseline_content_verified: bool,
    pub slot: OriginalSlotEvidence,
    pub final_absence_rechecked_after_audit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRetentionBlocker {
    InvalidMetadata,
    NotCommittedOriginal,
    InvalidNamespaceOwner,
    HistoricalProtectionMissing,
    MissingCasSession,
    ContentNotVerified,
    WrongPhase,
    OriginalNotExact,
    ActualAbsenceNotVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRetentionStep {
    Defer(OriginalRetentionBlocker),
    Noop,
    AuditOnly,
    RecordDeletePending,
    RequestExactHandleDisposition,
    RecordDisposed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRetentionPlan {
    step: OriginalRetentionStep,
    phase_after_step: OriginalRetentionPhase,
}

impl OriginalRetentionPlan {
    pub fn step(self) -> OriginalRetentionStep {
        self.step
    }

    pub fn phase_after_step(self) -> OriginalRetentionPhase {
        self.phase_after_step
    }

    pub fn pending_after_step(self) -> bool {
        self.phase_after_step == OriginalRetentionPhase::DeletePending
    }

    pub fn executor_available(self) -> bool {
        false
    }

    pub fn durable_pending_implemented(self) -> bool {
        false
    }

    pub fn restoration_available(self) -> bool {
        false
    }

    pub fn physical_space_reclaimed(self) -> bool {
        false
    }

    pub fn remote_backup_complete(self) -> bool {
        false
    }
}

/// Propose one hypothetical step. Ordinary recovery is audit-only. A missing
/// original before precommitted pending is never adopted; request/close errors
/// are not absence. A terminal record never re-inspects later native occupants.
pub fn plan_original_retention(
    action: RetainedOriginalAction,
    phase: OriginalRetentionPhase,
    request: OriginalRetentionRequest,
    evidence: OriginalRetentionEvidence,
) -> OriginalRetentionPlan {
    use OriginalRetentionBlocker as Blocker;
    use OriginalRetentionPhase as Phase;
    use OriginalRetentionRequest as Request;
    use OriginalRetentionStep as Step;
    let plan = |step, next| OriginalRetentionPlan {
        step,
        phase_after_step: next,
    };
    let blocked = |reason| plan(Step::Defer(reason), phase);
    if !evidence.metadata_verified {
        return blocked(Blocker::InvalidMetadata);
    }
    if action == RetainedOriginalAction::Move || !evidence.exact_committed_mutation {
        return blocked(Blocker::NotCommittedOriginal);
    }
    if phase == Phase::Disposed {
        return plan(Step::Noop, phase);
    }
    if matches!(request, Request::Inspect | Request::RecoverAudit) {
        return plan(Step::AuditOnly, phase);
    }
    if !evidence.owner_namespace_guarded {
        return blocked(Blocker::InvalidNamespaceOwner);
    }
    if !evidence.historical_snapshot_retained || !evidence.exact_snapshot_pins {
        return blocked(Blocker::HistoricalProtectionMissing);
    }
    if !evidence.cas_session_held {
        return blocked(Blocker::MissingCasSession);
    }
    if !evidence.baseline_content_verified {
        return blocked(Blocker::ContentNotVerified);
    }
    match request {
        Request::Prepare => {
            if phase != Phase::Retained {
                return blocked(Blocker::WrongPhase);
            }
            if evidence.slot != OriginalSlotEvidence::ExactVerified {
                return blocked(Blocker::OriginalNotExact);
            }
            plan(Step::RecordDeletePending, Phase::DeletePending)
        }
        Request::Execute => {
            if phase != Phase::DeletePending {
                return blocked(Blocker::WrongPhase);
            }
            if evidence.slot != OriginalSlotEvidence::ExactVerified {
                return blocked(Blocker::OriginalNotExact);
            }
            plan(Step::RequestExactHandleDisposition, phase)
        }
        Request::FinalizeAbsence => {
            if phase != Phase::DeletePending {
                return blocked(Blocker::WrongPhase);
            }
            if evidence.slot != OriginalSlotEvidence::Missing
                || !evidence.final_absence_rechecked_after_audit
            {
                return blocked(Blocker::ActualAbsenceNotVerified);
            }
            plan(Step::RecordDisposed, Phase::Disposed)
        }
        Request::Inspect | Request::RecoverAudit => unreachable!(),
    }
}
