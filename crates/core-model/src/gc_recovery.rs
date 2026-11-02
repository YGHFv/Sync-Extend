//! Prospective single-object GC recovery protocol, not a filesystem executor.
//! Evidence must be freshly established by a future guarded journal adapter.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcRecoveryPhase {
    Fenced,
    Quarantined,
    DeletePending,
    RestorePending,
    Deleted,
    Restored,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcObjectPresence {
    Absent,
    Expected,
    Foreign,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcRecoveryAuthority {
    FreshIntent,
    Denied,
    NotChecked,
    ClockRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcFenceEvidence {
    CompleteUnreferenced,
    Referenced,
    Unfenced,
    AuditIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcRecoveryEvidence {
    pub metadata_verified: bool,
    pub namespace_guarded: bool,
    pub fence: GcFenceEvidence,
    pub original: GcObjectPresence,
    pub quarantine: GcObjectPresence,
    pub authority: GcRecoveryAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcRecoveryBlocker {
    InvalidMetadata,
    UnguardedNamespace,
    ReferencesPresent,
    MissingFence,
    IncompleteOwnerAudit,
    UnverifiedObject,
    QuarantineOccupied,
    OriginalOccupied,
    AmbiguousLayout,
    MissingOriginal,
    OriginalReappeared,
    AuthorityNotChecked,
    ClockRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcRecoveryStep {
    Defer(GcRecoveryBlocker),
    Noop,
    QuarantineObject,
    RecordQuarantined,
    RecordDeletePending,
    RetireQuarantinedObject,
    RecordDeleted,
    RecordRestorePending,
    RestoreQuarantinedObject,
    RecordRestored,
    RecordAborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcRecoveryPlan {
    step: GcRecoveryStep,
    phase_after_step: GcRecoveryPhase,
}

impl GcRecoveryPlan {
    pub fn step(self) -> GcRecoveryStep {
        self.step
    }

    pub fn phase_after_step(self) -> GcRecoveryPhase {
        self.phase_after_step
    }

    pub fn deletion_authorized(self) -> bool {
        false
    }

    pub fn executor_available(self) -> bool {
        false
    }

    pub fn gc_enabled(self) -> bool {
        false
    }
}

/// Plans exactly one hypothetical step without I/O, authorization or persistence.
///
/// `Fenced` presupposes an explicit, durable, single-use admission. A fence must
/// exclude every reference writer across process death, not just hold a DB lock.
/// Presence means full identity/content checks, never a pathname/byte-only match.
pub fn plan_gc_recovery(phase: GcRecoveryPhase, evidence: GcRecoveryEvidence) -> GcRecoveryPlan {
    use GcObjectPresence as Presence;
    use GcRecoveryBlocker as Blocker;
    use GcRecoveryPhase as Phase;
    use GcRecoveryStep as Step;

    let blocked = |reason| GcRecoveryPlan {
        step: Step::Defer(reason),
        phase_after_step: phase,
    };
    let plan = |step, next| GcRecoveryPlan {
        step,
        phase_after_step: next,
    };
    if !evidence.metadata_verified {
        return blocked(Blocker::InvalidMetadata);
    }
    // Terminal replay audits metadata but never inspects or touches new occupants.
    if matches!(phase, Phase::Deleted | Phase::Restored | Phase::Aborted) {
        return plan(Step::Noop, phase);
    }
    if !evidence.namespace_guarded {
        return blocked(Blocker::UnguardedNamespace);
    }
    match evidence.fence {
        GcFenceEvidence::CompleteUnreferenced => {}
        GcFenceEvidence::Referenced => return blocked(Blocker::ReferencesPresent),
        GcFenceEvidence::Unfenced => return blocked(Blocker::MissingFence),
        GcFenceEvidence::AuditIncomplete => return blocked(Blocker::IncompleteOwnerAudit),
    }
    if evidence.original == Presence::Unverified || evidence.quarantine == Presence::Unverified {
        return blocked(Blocker::UnverifiedObject);
    }
    if evidence.quarantine == Presence::Foreign {
        return blocked(Blocker::QuarantineOccupied);
    }
    // Only a durable pre-disposition phase can explain an absent quarantine.
    // Fresh authority is unnecessary to record an already completed OS action.
    if phase == Phase::DeletePending && evidence.quarantine == Presence::Absent {
        return if evidence.original == Presence::Expected {
            blocked(Blocker::OriginalReappeared)
        } else {
            plan(Step::RecordDeleted, Phase::Deleted)
        };
    }
    if evidence.original == Presence::Foreign {
        return blocked(Blocker::OriginalOccupied);
    }
    match (evidence.original, evidence.quarantine) {
        (Presence::Expected, Presence::Expected) => blocked(Blocker::AmbiguousLayout),
        (Presence::Absent, Presence::Absent) => blocked(Blocker::MissingOriginal),
        (Presence::Expected, Presence::Absent) => match phase {
            Phase::Fenced => match evidence.authority {
                GcRecoveryAuthority::FreshIntent => plan(Step::QuarantineObject, phase),
                GcRecoveryAuthority::Denied => plan(Step::RecordAborted, Phase::Aborted),
                GcRecoveryAuthority::NotChecked => blocked(Blocker::AuthorityNotChecked),
                GcRecoveryAuthority::ClockRollback => blocked(Blocker::ClockRollback),
            },
            Phase::RestorePending => plan(Step::RecordRestored, Phase::Restored),
            _ => blocked(Blocker::OriginalReappeared),
        },
        (Presence::Absent, Presence::Expected) => match phase {
            Phase::Fenced => plan(Step::RecordQuarantined, Phase::Quarantined),
            Phase::RestorePending => plan(Step::RestoreQuarantinedObject, phase),
            Phase::Quarantined | Phase::DeletePending => match evidence.authority {
                GcRecoveryAuthority::Denied => {
                    plan(Step::RecordRestorePending, Phase::RestorePending)
                }
                GcRecoveryAuthority::NotChecked => blocked(Blocker::AuthorityNotChecked),
                GcRecoveryAuthority::ClockRollback => blocked(Blocker::ClockRollback),
                GcRecoveryAuthority::FreshIntent => {
                    if phase == Phase::Quarantined {
                        plan(Step::RecordDeletePending, Phase::DeletePending)
                    } else {
                        plan(Step::RetireQuarantinedObject, phase)
                    }
                }
            },
            _ => blocked(Blocker::AmbiguousLayout),
        },
        _ => blocked(Blocker::AmbiguousLayout),
    }
}
