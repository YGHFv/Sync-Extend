//! D05 exact original absence lineage. This audit never authorizes a path deletion.
use super::receipt_protocol::{
    ReceiptDescription, ReceiptEvidence as E, ReceiptStage as S, VerifiedPrefix,
};
use sync_extend_core_model::{ModelError, Result, webdav_native::WebDavNativeAction as A};
fn invalid() -> ModelError {
    ModelError::InvalidData("original DAV cleanup receipt lineage")
}
pub(super) fn audit(record: &ReceiptDescription, prior: &VerifiedPrefix<'_>) -> Result<()> {
    let plan = prior.plan();
    let records = prior.records();
    let final_record = prior.first_history_committed().ok_or_else(invalid)?;
    let E::History {
        history_hash,
        final_snapshot,
        ..
    } = &final_record.evidence
    else {
        return Err(invalid());
    };
    let previous = records.last().ok_or_else(invalid)?;
    match (&record.stage, &record.evidence) {
        (
            S::DisposalRequested(action) | S::OriginalAbsent(action) | S::OwnerSlotCleared(action),
            E::Disposal {
                action: actual,
                quarantine_action,
                original,
                parent,
                component,
            },
        ) => {
            original.validate()?;
            parent.validate()?;
            let step = plan.steps().get(*action).ok_or_else(invalid)?;
            let A::CleanupOriginal {
                quarantine_action: expected,
                entry,
                owner_component,
            } = &step.action
            else {
                return Err(invalid());
            };
            let moved = prior
                .first(S::QuarantineMoved(*quarantine_action))
                .ok_or_else(invalid)?;
            let E::CollectionObject { object } = &moved.evidence else {
                return Err(invalid());
            };
            if action != actual
                || quarantine_action != expected
                || *quarantine_action >= *action
                || original != object.original.as_ref().ok_or_else(invalid)?
                || parent != &object.parent
                || component != owner_component
                || entry.entry_id != object.entry_id
                || entry.path != object.path
            {
                return Err(invalid());
            }
            match record.stage {
                S::OriginalAbsent(_)
                    if previous.stage != S::DisposalRequested(*action)
                        || previous.evidence != record.evidence =>
                {
                    return Err(invalid());
                }
                S::OwnerSlotCleared(_)
                    if previous.stage != S::OriginalAbsent(*action)
                        || previous.evidence != record.evidence =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        (
            S::OwnerMarkerRemovalRequested
            | S::OwnerMarkerAbsent
            | S::OwnerRemovalRequested
            | S::OwnerAbsent
            | S::StagingRemovalRequested
            | S::StagingAbsent,
            E::InternalRemoval {
                original,
                parent,
                component,
            },
        ) => {
            original.validate()?;
            parent.validate()?;
            let (expected_original, expected_parent, expected_component) = match record.stage {
                S::OwnerMarkerRemovalRequested | S::OwnerMarkerAbsent => {
                    let E::MarkerClose {
                        original,
                        parent,
                        component,
                        ..
                    } = &records.get(9).ok_or_else(invalid)?.evidence
                    else {
                        return Err(invalid());
                    };
                    (original, parent, component)
                }
                S::OwnerRemovalRequested | S::OwnerAbsent => {
                    let E::DirectoryCreated {
                        original,
                        parent,
                        component,
                    } = &records.get(3).ok_or_else(invalid)?.evidence
                    else {
                        return Err(invalid());
                    };
                    (original, parent, component)
                }
                S::StagingRemovalRequested | S::StagingAbsent => {
                    let E::DirectoryCreated {
                        original,
                        parent,
                        component,
                    } = &records.get(1).ok_or_else(invalid)?.evidence
                    else {
                        return Err(invalid());
                    };
                    (original, parent, component)
                }
                _ => return Err(invalid()),
            };
            if original != expected_original
                || parent != expected_parent
                || component != expected_component
            {
                return Err(invalid());
            }
            let requested = match record.stage {
                S::OwnerMarkerAbsent => Some(S::OwnerMarkerRemovalRequested),
                S::OwnerAbsent => Some(S::OwnerRemovalRequested),
                S::StagingAbsent => Some(S::StagingRemovalRequested),
                _ => None,
            };
            if requested.is_some_and(|stage| previous.stage != stage)
                || (requested.is_some() && previous.evidence != record.evidence)
            {
                return Err(invalid());
            }
            if matches!(record.stage, S::OwnerMarkerRemovalRequested) {
                for step in plan.steps() {
                    if matches!(step.action, A::CleanupOriginal { .. })
                        && prior.first(S::OwnerSlotCleared(step.index)).is_none()
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        (
            S::ReferenceHandoffRequested | S::ReferencesHandedOff | S::Terminal,
            E::References {
                final_snapshot: snapshot,
                history_hash: history,
                ..
            },
        ) => {
            if snapshot != final_snapshot || history != history_hash {
                return Err(invalid());
            }
            match record.stage {
                S::ReferencesHandedOff
                    if previous.stage != S::ReferenceHandoffRequested
                        || previous.evidence != record.evidence =>
                {
                    return Err(invalid());
                }
                S::Terminal
                    if previous.stage != S::StagingAbsent
                        || !prior.any_evidence(S::ReferencesHandedOff, &record.evidence) =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
