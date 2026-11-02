//! Prospective durable worker ownership, not a pin store or receipt verifier.
//! Evidence is a caller claim; journal/native adapters must establish it afresh.

use crate::{limits, DeviceId, FileManifest, ModelError, Result, SpaceId, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceOwnerKind {
    Upload,
    Download,
    Restore,
    OfflineDelivery,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOwnerScope {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub kind: ReferenceOwnerKind,
    pub target_device: Option<DeviceId>,
    pub files: Vec<FileManifest>,
}

impl ReferenceOwnerScope {
    /// Validate before serialization/pin admission, including aggregate bounds.
    /// Repeated chunks are legal, but one content ID cannot describe two lengths.
    pub fn validate(&self) -> Result<()> {
        let remote = matches!(
            self.kind,
            ReferenceOwnerKind::Upload | ReferenceOwnerKind::OfflineDelivery
        );
        if self.format_version != FORMAT_VERSION
            || remote != self.target_device.is_some()
            || self.files.is_empty()
            || self.files.len() > limits::MAX_ENTRIES
        {
            return Err(ModelError::InvalidData("invalid reference owner scope"));
        }
        let mut chunks = 0usize;
        let mut lengths = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut logical_bytes = 0u64;
        for file in &self.files {
            file.validate()?;
            chunks = chunks
                .checked_add(file.chunks.len())
                .filter(|n| *n <= limits::MAX_CHUNKS)
                .ok_or(ModelError::InvalidData("reference owner chunk limit"))?;
            logical_bytes = logical_bytes
                .checked_add(file.length)
                .ok_or(ModelError::InvalidData("reference owner length overflow"))?;
            if files
                .insert(&file.content_id, file)
                .is_some_and(|old| old != file)
            {
                return Err(ModelError::InvalidData(
                    "reference owner file description mismatch",
                ));
            }
            for chunk in &file.chunks {
                if lengths
                    .insert(&chunk.content_id, chunk.length)
                    .is_some_and(|old| old != chunk.length)
                {
                    return Err(ModelError::InvalidData(
                        "reference owner chunk description mismatch",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOwnerPhase {
    Reserved,
    ContentClosed,
    HandoffPending,
    Released,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOwnerRequest {
    Recover,
    CloseContent,
    StartHandoff,
    FinishHandoff,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceContentEvidence {
    Missing,
    VerifiedComplete,
    Corrupt,
    NotChecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceHandoffEvidence {
    NotChecked,
    Unverified,
    BoundDurableOwner,
    BoundTargetContentReceipt,
    BoundTargetMaterializedReceipt,
    BoundDurableConflictResolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceOwnerEvidence {
    pub metadata_verified: bool,
    pub exact_pins_present: bool,
    pub cas_session_held: bool,
    pub content: ReferenceContentEvidence,
    pub handoff: ReferenceHandoffEvidence,
    pub side_effects_absent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOwnerBlocker {
    InvalidMetadata,
    MissingPins,
    MissingSession,
    ContentNotVerified,
    IllegalPhase,
    HandoffNotVerified,
    CancellationForbidden,
    SideEffectsNotExcluded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOwnerStep {
    Defer(ReferenceOwnerBlocker),
    Noop,
    ResumeWithPins,
    RecordContentClosed,
    RecordHandoffPending,
    RecordReleased,
    RecordCancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceOwnerPlan {
    step: ReferenceOwnerStep,
    phase_after_step: ReferenceOwnerPhase,
}

impl ReferenceOwnerPlan {
    pub fn step(self) -> ReferenceOwnerStep {
        self.step
    }

    pub fn phase_after_step(self) -> ReferenceOwnerPhase {
        self.phase_after_step
    }

    pub fn pins_required_after_step(self) -> bool {
        !matches!(
            self.phase_after_step,
            ReferenceOwnerPhase::Released | ReferenceOwnerPhase::Cancelled
        )
    }

    pub fn durable_pins_implemented(self) -> bool {
        false
    }

    pub fn receipt_verified(self) -> bool {
        false
    }

    pub fn executor_available(self) -> bool {
        false
    }
}

/// Plan one hypothetical state record, without I/O, persistence or authority.
///
/// Reserved pins include missing chunks BEFORE import. Process death, wall time,
/// disconnect and ordinary recovery never release them. Handoff evidence means
/// the exact immutable scope/generation/target, not a pathname or generic ACK.
pub fn plan_reference_owner(
    kind: ReferenceOwnerKind,
    phase: ReferenceOwnerPhase,
    request: ReferenceOwnerRequest,
    evidence: ReferenceOwnerEvidence,
) -> ReferenceOwnerPlan {
    use ReferenceOwnerBlocker as Blocker;
    use ReferenceOwnerPhase as Phase;
    use ReferenceOwnerRequest as Request;
    use ReferenceOwnerStep as Step;

    let plan = |step, next| ReferenceOwnerPlan {
        step,
        phase_after_step: next,
    };
    let blocked = |reason| plan(Step::Defer(reason), phase);
    if !evidence.metadata_verified {
        return blocked(Blocker::InvalidMetadata);
    }
    // Terminal replay is metadata-only and never reacquires pins or CAS bytes.
    if matches!(phase, Phase::Released | Phase::Cancelled) {
        return plan(Step::Noop, phase);
    }
    if !evidence.exact_pins_present {
        return blocked(Blocker::MissingPins);
    }
    if request == Request::Recover {
        return plan(Step::ResumeWithPins, phase);
    }
    if request == Request::Cancel {
        if matches!(
            kind,
            ReferenceOwnerKind::OfflineDelivery | ReferenceOwnerKind::Conflict
        ) {
            return blocked(Blocker::CancellationForbidden);
        }
        if phase == Phase::HandoffPending {
            return blocked(Blocker::IllegalPhase);
        }
        if !evidence.side_effects_absent {
            return blocked(Blocker::SideEffectsNotExcluded);
        }
        return plan(Step::RecordCancelled, Phase::Cancelled);
    }
    match request {
        Request::CloseContent | Request::StartHandoff => {
            let expected = if request == Request::CloseContent {
                Phase::Reserved
            } else {
                Phase::ContentClosed
            };
            if phase != expected {
                return blocked(Blocker::IllegalPhase);
            }
            if !evidence.cas_session_held {
                return blocked(Blocker::MissingSession);
            }
            if evidence.content != ReferenceContentEvidence::VerifiedComplete {
                return blocked(Blocker::ContentNotVerified);
            }
            if request == Request::CloseContent {
                plan(Step::RecordContentClosed, Phase::ContentClosed)
            } else {
                plan(Step::RecordHandoffPending, Phase::HandoffPending)
            }
        }
        Request::FinishHandoff => {
            if phase != Phase::HandoffPending {
                return blocked(Blocker::IllegalPhase);
            }
            let verified = matches!(
                (kind, evidence.handoff),
                (
                    ReferenceOwnerKind::Upload,
                    ReferenceHandoffEvidence::BoundTargetContentReceipt
                        | ReferenceHandoffEvidence::BoundTargetMaterializedReceipt
                ) | (
                    ReferenceOwnerKind::Download | ReferenceOwnerKind::Restore,
                    ReferenceHandoffEvidence::BoundDurableOwner
                ) | (
                    ReferenceOwnerKind::OfflineDelivery,
                    ReferenceHandoffEvidence::BoundTargetMaterializedReceipt
                ) | (
                    ReferenceOwnerKind::Conflict,
                    ReferenceHandoffEvidence::BoundDurableConflictResolution
                )
            );
            if !verified {
                return blocked(Blocker::HandoffNotVerified);
            }
            plan(Step::RecordReleased, Phase::Released)
        }
        Request::Recover | Request::Cancel => unreachable!(),
    }
}
