//! Original-plan D03 lineage audit. Descriptions cannot issue native effects.
use super::receipt_protocol::{ReceiptDescription, ReceiptEvidence, ReceiptStage};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    tree_restore_identity::TreeNativeIdentity,
    webdav_native::{WebDavNativeAction, WebDavNativeParent, WebDavNativePlan, WebDavNativeSlot},
    ContentId, EntryId, ModelError, PortablePath, Result,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionObject {
    pub action: usize,
    pub entry_id: EntryId,
    pub path: PortablePath,
    pub source_parent: TreeNativeIdentity,
    pub parent: TreeNativeIdentity,
    pub original: Option<TreeNativeIdentity>,
    pub component: String,
    pub content_hash: Option<ContentId>,
    pub length: u64,
}

fn invalid() -> ModelError {
    ModelError::InvalidData("original DAV ordered action receipt lineage")
}

fn object(record: &ReceiptDescription) -> Result<&ActionObject> {
    match &record.evidence {
        ReceiptEvidence::CollectionObject { object } => Ok(object),
        _ => Err(invalid()),
    }
}

fn completed(
    prior: &[ReceiptDescription],
    action: usize,
    stage: ReceiptStage,
) -> Result<&ActionObject> {
    let record = prior
        .iter()
        .find(|record| record.stage == stage)
        .ok_or_else(invalid)?;
    let value = object(record)?;
    if value.action != action || value.original.is_none() {
        return Err(invalid());
    }
    Ok(value)
}

fn action_of(stage: ReceiptStage) -> Result<usize> {
    use ReceiptStage as S;
    match stage {
        S::QuarantineRequested(index)
        | S::QuarantineMoved(index)
        | S::DirectoryCreationRequested(index)
        | S::DirectoryCreated(index)
        | S::FileCreationRequested(index)
        | S::FileCreated(index)
        | S::FileWriteRequested(index)
        | S::FileWritten(index)
        | S::FileCloseRequested(index)
        | S::FileClosed(index)
        | S::FilePublicationRequested(index)
        | S::FilePublished(index) => Ok(index),
        _ => Err(invalid()),
    }
}

fn complete_stage(plan: &WebDavNativePlan, action: usize) -> Result<ReceiptStage> {
    use ReceiptStage as S;
    match &plan.steps().get(action).ok_or_else(invalid)?.action {
        WebDavNativeAction::QuarantineOriginal { .. } => Ok(S::QuarantineMoved(action)),
        WebDavNativeAction::CreateDirectory { .. } => Ok(S::DirectoryCreated(action)),
        WebDavNativeAction::PublishFile { .. } => Ok(S::FilePublished(action)),
        _ => Err(invalid()),
    }
}

fn destination_parent(
    plan: &WebDavNativePlan,
    action: usize,
    prior: &[ReceiptDescription],
) -> Result<TreeNativeIdentity> {
    match plan
        .steps()
        .get(action)
        .ok_or_else(invalid)?
        .parent
        .as_ref()
        .ok_or_else(invalid)?
    {
        WebDavNativeParent::Root => Ok(plan.inventory().root.clone()),
        WebDavNativeParent::Existing { identity, .. } => Ok(identity.clone()),
        WebDavNativeParent::CreatedBy {
            action: parent_action,
            path,
        } => {
            let value = completed(
                prior,
                *parent_action,
                ReceiptStage::DirectoryCreated(*parent_action),
            )?;
            if value.path != *path || *parent_action >= action {
                return Err(invalid());
            }
            value.original.clone().ok_or_else(invalid)
        }
    }
}

/// Validate bytes and causal lineage against the first immutable original plan.
/// Native issuers must separately keep real original handles through each effect.
pub(super) fn audit(
    plan: &WebDavNativePlan,
    record: &ReceiptDescription,
    prior: &[ReceiptDescription],
) -> Result<()> {
    use ReceiptStage as S;
    if prior.len() < 10 || prior[9].stage != S::OwnerMarkerClosed {
        return Err(invalid());
    }
    if matches!(
        record.stage,
        S::HistoryCommitRequested(_) | S::HistoryCommitted(_)
    ) {
        return super::final_history::audit_receipt(plan, record, prior);
    }
    if matches!(
        record.stage,
        S::DisposalRequested(_)
            | S::OriginalAbsent(_)
            | S::OwnerSlotCleared(_)
            | S::OwnerMarkerRemovalRequested
            | S::OwnerMarkerAbsent
            | S::OwnerRemovalRequested
            | S::OwnerAbsent
            | S::ReferenceHandoffRequested
            | S::ReferencesHandedOff
            | S::StagingRemovalRequested
            | S::StagingAbsent
            | S::Terminal
    ) {
        return super::cleanup_receipts::audit(plan, record, prior);
    }
    let action = action_of(record.stage)?;
    let step = plan
        .steps()
        .get(action)
        .filter(|step| step.index == action)
        .ok_or_else(invalid)?;
    if step.dependencies.iter().any(|dependency| {
        *dependency >= action
            || complete_stage(plan, *dependency)
                .and_then(|stage| completed(prior, *dependency, stage))
                .is_err()
    }) {
        return Err(invalid());
    }
    let owner_parent = match &prior[3].evidence {
        ReceiptEvidence::DirectoryCreated { original, .. } => original,
        _ => return Err(invalid()),
    };
    let value = object(record)?;
    let original_parent = destination_parent(plan, action, prior)?;
    value.parent.validate()?;
    value.source_parent.validate()?;
    if let Some(original) = &value.original {
        original.validate()?;
        if original == &value.parent || original.volume_serial != value.parent.volume_serial {
            return Err(invalid());
        }
    }
    let entry = match &step.action {
        WebDavNativeAction::QuarantineOriginal { entry, .. }
        | WebDavNativeAction::CreateDirectory { entry }
        | WebDavNativeAction::PublishFile { entry } => entry,
        _ => return Err(invalid()),
    };
    if value.action != action || value.entry_id != entry.entry_id || value.path != entry.path {
        return Err(invalid());
    }
    let component = entry.path.as_str().rsplit('/').next().ok_or_else(invalid)?;
    match &step.slot {
        Some(WebDavNativeSlot::VacatedBy {
            action: previous,
            entry: old,
            identity,
        }) => {
            let vacated = completed(prior, *previous, S::QuarantineMoved(*previous))?;
            if *previous >= action
                || vacated.path != old.path
                || vacated.entry_id != old.entry_id
                || vacated.original.as_ref() != Some(identity)
                || old.path != entry.path
            {
                return Err(invalid());
            }
        }
        Some(WebDavNativeSlot::Existing {
            entry: old,
            identity,
        }) => {
            if old != entry
                || !matches!(&step.action,
                WebDavNativeAction::QuarantineOriginal { identity: actual, .. } if actual == identity)
            {
                return Err(invalid());
            }
        }
        Some(WebDavNativeSlot::InitiallyAbsent) => {}
        Some(WebDavNativeSlot::BelowCreatedParent) => {
            if !matches!(&step.parent, Some(WebDavNativeParent::CreatedBy { .. })) {
                return Err(invalid());
            }
        }
        None => return Err(invalid()),
    }
    let previous = prior.last().ok_or_else(invalid)?;
    match (&step.action, record.stage) {
        (
            WebDavNativeAction::QuarantineOriginal {
                identity,
                owner_component,
                ..
            },
            S::QuarantineRequested(_) | S::QuarantineMoved(_),
        ) => {
            if value.original.as_ref() != Some(identity)
                || value.source_parent != original_parent
                || &value.parent != owner_parent
                || value.component != *owner_component
                || value.content_hash
                    != entry
                        .content
                        .as_ref()
                        .map(|content| content.content_id.clone())
                || value.length != entry.content.as_ref().map_or(0, |content| content.length)
            {
                return Err(invalid());
            }
            if matches!(record.stage, S::QuarantineMoved(_))
                && (previous.stage != S::QuarantineRequested(action) || object(previous)? != value)
            {
                return Err(invalid());
            }
        }
        (
            WebDavNativeAction::CreateDirectory { .. },
            S::DirectoryCreationRequested(_) | S::DirectoryCreated(_),
        ) => {
            if value.parent != original_parent
                || value.source_parent != original_parent
                || value.component != component
                || value.content_hash.is_some()
                || value.length != 0
            {
                return Err(invalid());
            }
            if matches!(record.stage, S::DirectoryCreationRequested(_)) {
                if value.original.is_some() {
                    return Err(invalid());
                }
            } else {
                let mut expected = object(previous)?.clone();
                expected.original = value.original.clone();
                if previous.stage != S::DirectoryCreationRequested(action)
                    || value.original.is_none()
                    || expected != *value
                    || object(previous)?.original.is_some()
                {
                    return Err(invalid());
                }
            }
        }
        (
            WebDavNativeAction::PublishFile { .. },
            S::FileCreationRequested(_)
            | S::FileCreated(_)
            | S::FileWriteRequested(_)
            | S::FileWritten(_)
            | S::FileCloseRequested(_)
            | S::FileClosed(_)
            | S::FilePublicationRequested(_)
            | S::FilePublished(_),
        ) => {
            let content = entry.content.as_ref().ok_or_else(invalid)?;
            let publication = matches!(
                record.stage,
                S::FilePublicationRequested(_) | S::FilePublished(_)
            );
            let empty = matches!(record.stage, S::FileCreated(_));
            if &value.source_parent != owner_parent
                || value.parent
                    != if publication {
                        original_parent
                    } else {
                        owner_parent.clone()
                    }
                || value.component
                    != if publication {
                        component.to_owned()
                    } else {
                        format!("dav-{}-{action}.payload", record.scope.transaction_id)
                    }
                || value.content_hash
                    != Some(if empty {
                        ContentId::hash(b"")
                    } else {
                        content.content_id.clone()
                    })
                || value.length != if empty { 0 } else { content.length }
            {
                return Err(invalid());
            }
            if matches!(record.stage, S::FileCreationRequested(_)) {
                if value.original.is_some() {
                    return Err(invalid());
                }
            } else {
                let wanted = match record.stage {
                    S::FileCreated(_) => S::FileCreationRequested(action),
                    S::FileWriteRequested(_) => S::FileCreated(action),
                    S::FileWritten(_) => S::FileWriteRequested(action),
                    S::FileCloseRequested(_) => S::FileWritten(action),
                    S::FileClosed(_) => S::FileCloseRequested(action),
                    S::FilePublicationRequested(_) => S::FileClosed(action),
                    S::FilePublished(_) => S::FilePublicationRequested(action),
                    _ => return Err(invalid()),
                };
                let old = object(previous)?;
                if previous.stage != wanted
                    || value.original.is_none()
                    || (!matches!(record.stage, S::FileCreated(_))
                        && value.original != old.original)
                    || old.action != value.action
                    || old.entry_id != value.entry_id
                    || old.path != value.path
                {
                    return Err(invalid());
                }
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
