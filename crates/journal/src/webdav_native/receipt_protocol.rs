//! D01-D05 draft: bounded exact internal stages for original native DAV actions.
//! Descriptions and this audit never issue native, Final or disposal authority.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    tree_restore_history::encode_history_record,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
    ContentId, EntryId, ModelError, Result,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptScope {
    pub transaction_id: EntryId,
    pub description_hash: ContentId,
    pub request_hash: ContentId,
    pub plan_hash: ContentId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "stage",
    content = "action",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReceiptStage {
    StagingCreationRequested,
    StagingCreated,
    OwnerActivated,
    OwnerCreated,
    OwnerMarkerCreationRequested,
    OwnerMarkerCreated,
    OwnerMarkerWriteRequested,
    OwnerMarkerWritten,
    OwnerMarkerCloseRequested,
    OwnerMarkerClosed,
    QuarantineRequested(usize),
    QuarantineMoved(usize),
    DirectoryCreationRequested(usize),
    DirectoryCreated(usize),
    FileCreationRequested(usize),
    FileCreated(usize),
    FileWriteRequested(usize),
    FileWritten(usize),
    FileCloseRequested(usize),
    FileClosed(usize),
    FilePublicationRequested(usize),
    FilePublished(usize),
    HistoryCommitRequested(usize),
    HistoryCommitted(usize),
    DisposalRequested(usize),
    OriginalAbsent(usize),
    OwnerSlotCleared(usize),
    OwnerMarkerRemovalRequested,
    OwnerMarkerAbsent,
    OwnerRemovalRequested,
    OwnerAbsent,
    ReferenceHandoffRequested,
    ReferencesHandedOff,
    StagingRemovalRequested,
    StagingAbsent,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptTemplate {
    pub scope: ReceiptScope,
    pub index: usize,
    pub predecessor: Option<usize>,
    pub stage: ReceiptStage,
    pub max_receipt_json_bytes: u64,
}

pub fn templates(
    scope: &ReceiptScope,
    plan: &WebDavNativePlan,
    maximum: usize,
    max_receipt_json_bytes: u64,
    max_total_template_bytes: u64,
) -> Result<Vec<ReceiptTemplate>> {
    if scope.request_hash != *plan.request_hash()
        || scope.plan_hash != *plan.fingerprint()
        || maximum == 0
        || maximum > sync_extend_core_model::limits::MAX_ENTRIES
        || max_receipt_json_bytes == 0
        || max_receipt_json_bytes
            > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData(
            "bounded exact DAV private receipt templates",
        ));
    }
    let mut result = Vec::new();
    let mut append = |stage| -> Result<()> {
        if result.len() >= maximum {
            return Err(ModelError::InvalidData(
                "DAV private receipt template count",
            ));
        }
        let index = result.len();
        result.push(ReceiptTemplate {
            scope: scope.clone(),
            index,
            predecessor: index.checked_sub(1),
            stage,
            max_receipt_json_bytes,
        });
        Ok(())
    };
    append(ReceiptStage::StagingCreationRequested)?;
    append(ReceiptStage::StagingCreated)?;
    append(ReceiptStage::OwnerActivated)?;
    append(ReceiptStage::OwnerCreated)?;
    append(ReceiptStage::OwnerMarkerCreationRequested)?;
    append(ReceiptStage::OwnerMarkerCreated)?;
    append(ReceiptStage::OwnerMarkerWriteRequested)?;
    append(ReceiptStage::OwnerMarkerWritten)?;
    append(ReceiptStage::OwnerMarkerCloseRequested)?;
    append(ReceiptStage::OwnerMarkerClosed)?;
    for step in plan.steps() {
        match &step.action {
            WebDavNativeAction::QuarantineOriginal { .. } => {
                append(ReceiptStage::QuarantineRequested(step.index))?;
                append(ReceiptStage::QuarantineMoved(step.index))?;
            }
            WebDavNativeAction::CreateDirectory { .. } => {
                append(ReceiptStage::DirectoryCreationRequested(step.index))?;
                append(ReceiptStage::DirectoryCreated(step.index))?;
            }
            WebDavNativeAction::PublishFile { .. } => {
                append(ReceiptStage::FileCreationRequested(step.index))?;
                append(ReceiptStage::FileCreated(step.index))?;
                append(ReceiptStage::FileWriteRequested(step.index))?;
                append(ReceiptStage::FileWritten(step.index))?;
                append(ReceiptStage::FileCloseRequested(step.index))?;
                append(ReceiptStage::FileClosed(step.index))?;
                append(ReceiptStage::FilePublicationRequested(step.index))?;
                append(ReceiptStage::FilePublished(step.index))?;
            }
            WebDavNativeAction::CommitHistory { .. } => {
                append(ReceiptStage::HistoryCommitRequested(step.index))?;
                append(ReceiptStage::HistoryCommitted(step.index))?;
            }
            WebDavNativeAction::CleanupOriginal { .. } => {
                append(ReceiptStage::DisposalRequested(step.index))?;
                append(ReceiptStage::OriginalAbsent(step.index))?;
                append(ReceiptStage::OwnerSlotCleared(step.index))?;
            }
        }
    }
    append(ReceiptStage::OwnerMarkerRemovalRequested)?;
    append(ReceiptStage::OwnerMarkerAbsent)?;
    append(ReceiptStage::OwnerRemovalRequested)?;
    append(ReceiptStage::OwnerAbsent)?;
    append(ReceiptStage::ReferenceHandoffRequested)?;
    append(ReceiptStage::ReferencesHandedOff)?;
    append(ReceiptStage::StagingRemovalRequested)?;
    append(ReceiptStage::StagingAbsent)?;
    append(ReceiptStage::Terminal)?;
    encode_history_record(&result, max_total_template_bytes)?;
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "evidence", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptEvidence {
    Disposal {
        action: usize,
        quarantine_action: usize,
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
    },
    InternalRemoval {
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
    },
    References {
        final_snapshot: sync_extend_core_model::SnapshotId,
        history_hash: ContentId,
        retained_objects_hash: ContentId,
    },
    History {
        action: usize,
        final_snapshot: sync_extend_core_model::SnapshotId,
        operation_count: usize,
        history_hash: ContentId,
    },
    CollectionObject {
        object: super::ordered_receipts::ActionObject,
    },
    DirectoryIntent {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
    },
    DirectoryCreated {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
    },
    MarkerIntent {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
        content_hash: ContentId,
        length: u64,
    },
    MarkerCreated {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
        content_hash: ContentId,
        length: u64,
    },
    MarkerWrite {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
        content_hash: ContentId,
        length: u64,
    },
    MarkerClose {
        parent: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        original: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        component: String,
        content_hash: ContentId,
        length: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDescription {
    pub scope: ReceiptScope,
    pub index: usize,
    pub template_index: usize,
    pub template_hash: ContentId,
    pub predecessor_hash: ContentId,
    pub generation: EntryId,
    pub recorded_at_ms: u64,
    pub stage: ReceiptStage,
    pub evidence_hash: ContentId,
    pub evidence: ReceiptEvidence,
}

/// Validate bytes/order only. Each evidence_hash must separately be produced
/// from an exact held private effect proof, not copied from this description.
pub fn audit_prefix(
    plan: &WebDavNativePlan,
    expected: &[ReceiptTemplate],
    records: &[ReceiptDescription],
    initial_hash: &ContentId,
    admitted_at_ms: u64,
    max_total_receipt_bytes: u64,
) -> Result<ContentId> {
    if expected.is_empty()
        || expected.len() > sync_extend_core_model::limits::MAX_ENTRIES
        || expected.iter().enumerate().any(|(index, template)| {
            template.index != index
                || template.predecessor != index.checked_sub(1)
                || template.scope != expected[0].scope
                || template.max_receipt_json_bytes == 0
                || template.max_receipt_json_bytes
                    > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES
        })
        || records.len() > expected.len()
        || admitted_at_ms > i64::MAX as u64
        || max_total_receipt_bytes
            > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("bounded exact DAV receipt prefix"));
    }
    let mut previous = initial_hash.clone();
    let mut time = admitted_at_ms;
    let mut generations = BTreeSet::new();
    let mut total = 0_u64;
    for (index, record) in records.iter().enumerate() {
        let template = &expected[index];
        let hash = ContentId::hash(&encode_history_record(
            template,
            sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES,
        )?);
        if record.scope != template.scope
            || template.index != index
            || template.predecessor != index.checked_sub(1)
            || record.index != index
            || record.template_index != index
            || record.template_hash != hash
            || record.predecessor_hash != previous
            || record.stage != template.stage
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
            || record.generation == record.scope.transaction_id
            || !generations.insert(record.generation.clone())
        {
            return Err(ModelError::InvalidData(
                "exact DAV receipt scope stage order generation",
            ));
        }
        if record.evidence_hash
            != ContentId::hash(&encode_history_record(
                &record.evidence,
                template.max_receipt_json_bytes,
            )?)
        {
            return Err(ModelError::InvalidData(
                "exact retained DAV receipt evidence bytes",
            ));
        }
        if index < 10 {
            audit_initial_owner_evidence(record, records.get(index.wrapping_sub(1)))?;
        } else {
            super::ordered_receipts::audit(plan, record, &records[..index])?;
        }
        let bytes = encode_history_record(record, template.max_receipt_json_bytes)?;
        total = total
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= max_total_receipt_bytes)
            .ok_or(ModelError::InvalidData(
                "DAV private receipt prefix byte limit",
            ))?;
        previous = ContentId::hash(&bytes);
        time = record.recorded_at_ms;
    }
    Ok(previous)
}

/// Audit description lineage only. The private stage issuer must retain originals.
/// Further D03-D05 evidence variants remain rejected until independently implemented.
fn audit_initial_owner_evidence(
    record: &ReceiptDescription,
    previous: Option<&ReceiptDescription>,
) -> Result<()> {
    use ReceiptEvidence as E;
    use ReceiptStage as S;
    let invalid = || ModelError::InvalidData("exact initial DAV owner CREATE evidence");
    match (&record.stage, &record.evidence) {
        (S::StagingCreationRequested, E::DirectoryIntent { parent, component }) => {
            parent.validate()?;
            if component != ".sync-tmp" || previous.is_some() {
                return Err(invalid());
            }
        }
        (
            S::StagingCreated,
            E::DirectoryCreated {
                parent,
                original,
                component,
            },
        )
        | (
            S::OwnerCreated,
            E::DirectoryCreated {
                parent,
                original,
                component,
            },
        ) => {
            parent.validate()?;
            original.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let E::DirectoryIntent {
                parent: expected,
                component: expected_component,
            } = &previous.evidence
            else {
                return Err(invalid());
            };
            if parent != expected
                || component != expected_component
                || original == parent
                || original.volume_serial != parent.volume_serial
            {
                return Err(invalid());
            }
        }
        (S::OwnerActivated, E::DirectoryIntent { parent, component }) => {
            parent.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let E::DirectoryCreated { original, .. } = &previous.evidence else {
                return Err(invalid());
            };
            if parent != original
                || component != &format!("dav-{}.owner", record.scope.transaction_id)
            {
                return Err(invalid());
            }
        }
        (
            S::OwnerMarkerCreationRequested,
            E::MarkerIntent {
                parent,
                component,
                content_hash,
                length,
            },
        ) => {
            parent.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let E::DirectoryCreated { original, .. } = &previous.evidence else {
                return Err(invalid());
            };
            let marker = format!(
                "{}:{}",
                record.scope.transaction_id, record.scope.description_hash
            );
            if parent != original
                || component != "owner-marker"
                || *length != marker.len() as u64
                || *content_hash != ContentId::hash(marker.as_bytes())
            {
                return Err(invalid());
            }
        }
        (
            S::OwnerMarkerCreated,
            E::MarkerCreated {
                parent,
                original,
                component,
                content_hash,
                length,
            },
        ) => {
            parent.validate()?;
            original.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let E::MarkerIntent {
                parent: expected,
                component: expected_component,
                content_hash: expected_hash,
                length: expected_length,
            } = &previous.evidence
            else {
                return Err(invalid());
            };
            if parent != expected
                || component != expected_component
                || *content_hash != ContentId::hash(b"")
                || *length != 0
                || *expected_hash
                    != ContentId::hash(
                        format!(
                            "{}:{}",
                            record.scope.transaction_id, record.scope.description_hash
                        )
                        .as_bytes(),
                    )
                || *expected_length != 97
                || original == parent
                || original.volume_serial != parent.volume_serial
            {
                return Err(invalid());
            }
        }
        (
            S::OwnerMarkerWriteRequested,
            E::MarkerWrite {
                parent,
                original,
                component,
                content_hash,
                length,
            },
        )
        | (
            S::OwnerMarkerWritten,
            E::MarkerWrite {
                parent,
                original,
                component,
                content_hash,
                length,
            },
        ) => {
            parent.validate()?;
            original.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let (prior_parent, prior_original, prior_component) = match &previous.evidence {
                E::MarkerCreated {
                    parent,
                    original,
                    component,
                    ..
                }
                | E::MarkerWrite {
                    parent,
                    original,
                    component,
                    ..
                } => (parent, original, component),
                _ => return Err(invalid()),
            };
            let intended = format!(
                "{}:{}",
                record.scope.transaction_id, record.scope.description_hash
            );
            if parent != prior_parent
                || original != prior_original
                || component != prior_component
                || *content_hash != ContentId::hash(intended.as_bytes())
                || *length != intended.len() as u64
            {
                return Err(invalid());
            }
        }
        (
            S::OwnerMarkerCloseRequested,
            E::MarkerClose {
                parent,
                original,
                component,
                content_hash,
                length,
            },
        )
        | (
            S::OwnerMarkerClosed,
            E::MarkerClose {
                parent,
                original,
                component,
                content_hash,
                length,
            },
        ) => {
            parent.validate()?;
            original.validate()?;
            let Some(previous) = previous else {
                return Err(invalid());
            };
            let (prior_parent, prior_original, prior_component, prior_hash, prior_length) =
                match &previous.evidence {
                    E::MarkerWrite {
                        parent,
                        original,
                        component,
                        content_hash,
                        length,
                    }
                    | E::MarkerClose {
                        parent,
                        original,
                        component,
                        content_hash,
                        length,
                    } => (parent, original, component, content_hash, length),
                    _ => return Err(invalid()),
                };
            if parent != prior_parent
                || original != prior_original
                || component != prior_component
                || content_hash != prior_hash
                || length != prior_length
            {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
