//! Exact coordinator-area descriptions, never native creation or ownership proof.
use crate::{
    limits,
    tree_original_reference::{
        plan_tree_original_references, TreeOriginalReferenceLimits, TreeOriginalReferencePlan,
    },
    tree_restore::TreeRestoreAction,
    tree_restore_execution_intent::TreeExecutionIntentPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{TreeIdentityPlan, TreeNativeIdentity},
    ContentId, EntryId, ModelError, Result, SpaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerInput {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub execution_intent_hash: ContentId,
    pub original_request_hash: ContentId,
    pub original_closure_hash: ContentId,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerMarkerPayload {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub input: TreeOwnerInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerStepSlots {
    pub step_execution_id: EntryId,
    pub new_component: Option<String>,
    pub original_component: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerIntent {
    pub input: TreeOwnerInput,
    pub parent: TreeNativeIdentity,
    pub stage_component: String,
    pub published_component: String,
    pub marker_component: String,
    pub marker_payload: TreeOwnerMarkerPayload,
    pub steps: BTreeMap<usize, TreeOwnerStepSlots>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerLimits {
    pub max_steps: usize,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOwnerPlan {
    intent: TreeOwnerIntent,
    intent_hash: ContentId,
    marker_bytes: Vec<u8>,
    marker_hash: ContentId,
    forbidden_native: BTreeSet<TreeNativeIdentity>,
    encoded_bytes: u64,
}
impl TreeOwnerPlan {
    pub fn intent(&self) -> &TreeOwnerIntent {
        &self.intent
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn marker_bytes(&self) -> &[u8] {
        &self.marker_bytes
    }
    pub fn marker_hash(&self) -> &ContentId {
        &self.marker_hash
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_tree_verified(&self) -> bool {
        false
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// Journal hashes stay descriptive until independently checked against actual rows.
pub fn plan_tree_owner(
    execution: &TreeExecutionIntentPlan,
    identity: &TreeIdentityPlan,
    originals: &TreeOriginalReferencePlan,
    input: &TreeOwnerInput,
    bounds: TreeOwnerLimits,
) -> Result<TreeOwnerPlan> {
    let e = execution.intent();
    if bounds.max_steps == 0
        || bounds.max_steps > limits::MAX_ENTRIES
        || e.steps.len() > bounds.max_steps
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || input.transaction_id != e.input.transaction_id
        || input.coordinator_execution_id != e.input.execution_id
        || input.created_at_ms < e.input.created_at_ms
        || input.created_at_ms > i64::MAX as u64
        || input.execution_intent_hash
            != ContentId::hash(&encode_history_record(e, MAX_TREE_HISTORY_BYTES)?)
        || input.original_closure_hash != *originals.fingerprint()
    {
        return Err(ModelError::InvalidData("tree owner exact scope or bounds"));
    }
    let rebound = plan_tree_original_references(
        execution,
        identity,
        TreeOriginalReferenceLimits {
            max_owners: limits::MAX_ENTRIES,
            max_chunk_visits: limits::MAX_CHUNKS,
            max_reference_rows: limits::MAX_CHUNKS,
            max_encoded_bytes: MAX_TREE_HISTORY_BYTES,
        },
    )?;
    if &rebound != originals {
        return Err(ModelError::InvalidData("tree owner exact original closure"));
    }
    let published_component = format!("tree-{}", input.coordinator_execution_id);
    let marker_payload = TreeOwnerMarkerPayload {
        format_version: 1,
        space_id: e.scope.space_id.clone(),
        input: input.clone(),
    };
    let marker_bytes = encode_history_record(&marker_payload, bounds.max_encoded_bytes)?;
    let mut steps = BTreeMap::new();
    for step in &e.steps {
        let new_component = match step.step.action {
            TreeRestoreAction::CreateDirectory => Some(format!("{}.dir", step.step_execution_id)),
            TreeRestoreAction::PublishNewFile | TreeRestoreAction::ReplaceFile => {
                Some(format!("{}.new", step.step_execution_id))
            }
            _ => None,
        };
        let original_component = matches!(
            step.step.action,
            TreeRestoreAction::DeleteFile | TreeRestoreAction::ReplaceFile
        )
        .then(|| format!("{}.original", step.step_execution_id));
        steps.insert(
            step.step.index,
            TreeOwnerStepSlots {
                step_execution_id: step.step_execution_id.clone(),
                new_component,
                original_component,
            },
        );
    }
    let intent = TreeOwnerIntent {
        input: input.clone(),
        parent: identity.inventory().marker_directory.clone(),
        stage_component: format!("{published_component}.creating"),
        published_component,
        marker_component: "owner".into(),
        marker_payload,
        steps,
    };
    let encoded = encode_history_record(&intent, bounds.max_encoded_bytes)?;
    let forbidden_native = [
        &identity.inventory().root,
        &identity.inventory().marker_directory,
        &identity.inventory().marker_file,
    ]
    .into_iter()
    .chain(identity.inventory().entries.values().map(|e| &e.identity))
    .cloned()
    .collect();
    Ok(TreeOwnerPlan {
        intent,
        intent_hash: ContentId::hash(&encoded),
        marker_hash: ContentId::hash(&marker_bytes),
        marker_bytes,
        forbidden_native,
        encoded_bytes: encoded.len() as u64,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeOwnerEvent {
    CreateIntended {
        parent: TreeNativeIdentity,
    },
    DirectoryBound {
        directory: TreeNativeIdentity,
    },
    PublicationIntended {
        directory: TreeNativeIdentity,
    },
    DirectoryPublished {
        directory: TreeNativeIdentity,
    },
    MarkerCreateIntended {
        directory: TreeNativeIdentity,
    },
    MarkerBound {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
    },
    MarkerMaterialized {
        marker: TreeNativeIdentity,
        payload_hash: ContentId,
        payload_length: u64,
    },
    Ready {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerRecord {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub intent_hash: ContentId,
    pub record_index: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeOwnerEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerRecordLimits {
    pub max_records: usize,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOwnerRecordAudit {
    records: Vec<TreeOwnerRecord>,
    directory: Option<TreeNativeIdentity>,
    marker: Option<TreeNativeIdentity>,
    fingerprint: ContentId,
    encoded_bytes: u64,
}
impl TreeOwnerRecordAudit {
    pub fn records(&self) -> &[TreeOwnerRecord] {
        &self.records
    }
    pub fn directory(&self) -> Option<&TreeNativeIdentity> {
        self.directory.as_ref()
    }
    pub fn marker(&self) -> Option<&TreeNativeIdentity> {
        self.marker.as_ref()
    }
    pub fn description_complete(&self) -> bool {
        self.records.len() == 8
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_tree_verified(&self) -> bool {
        false
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

fn fresh_native(plan: &TreeOwnerPlan, id: &TreeNativeIdentity) -> Result<()> {
    id.validate()?;
    if id.volume_serial != plan.intent.parent.volume_serial || plan.forbidden_native.contains(id) {
        return Err(ModelError::InvalidData("tree owner native identity alias"));
    }
    Ok(())
}

/// A complete chain is still a metadata description, never proof of native readiness.
pub fn audit_tree_owner_records(
    plan: &TreeOwnerPlan,
    records: &[TreeOwnerRecord],
    bounds: TreeOwnerRecordLimits,
) -> Result<TreeOwnerRecordAudit> {
    if bounds.max_records > 8
        || records.len() > bounds.max_records
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("tree owner record bounds"));
    }
    let mut previous = plan.intent_hash.clone();
    let mut time = plan.intent.input.created_at_ms;
    let mut directory = None;
    let mut marker = None;
    for (index, record) in records.iter().enumerate() {
        if record.record_index != index
            || record.transaction_id != plan.intent.input.transaction_id
            || record.coordinator_execution_id != plan.intent.input.coordinator_execution_id
            || record.intent_hash != plan.intent_hash
            || record.previous_hash != previous
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
        {
            return Err(ModelError::InvalidData("tree owner record exact chain"));
        }
        match (&record.event, index) {
            (TreeOwnerEvent::CreateIntended { parent }, 0) if parent == &plan.intent.parent => {}
            (TreeOwnerEvent::DirectoryBound { directory: id }, 1) => {
                fresh_native(plan, id)?;
                directory = Some(id.clone());
            }
            (TreeOwnerEvent::PublicationIntended { directory: id }, 2)
                if Some(id) == directory.as_ref() => {}
            (TreeOwnerEvent::DirectoryPublished { directory: id }, 3)
                if Some(id) == directory.as_ref() => {}
            (TreeOwnerEvent::MarkerCreateIntended { directory: id }, 4)
                if Some(id) == directory.as_ref() => {}
            (
                TreeOwnerEvent::MarkerBound {
                    directory: id,
                    marker: m,
                },
                5,
            ) if Some(id) == directory.as_ref() => {
                fresh_native(plan, m)?;
                if Some(m) == directory.as_ref() {
                    return Err(ModelError::InvalidData(
                        "tree owner marker aliases directory",
                    ));
                }
                marker = Some(m.clone());
            }
            (
                TreeOwnerEvent::MarkerMaterialized {
                    marker: m,
                    payload_hash,
                    payload_length,
                },
                6,
            ) if Some(m) == marker.as_ref()
                && payload_hash == &plan.marker_hash
                && *payload_length == plan.marker_bytes.len() as u64 => {}
            (
                TreeOwnerEvent::Ready {
                    directory: id,
                    marker: m,
                },
                7,
            ) if Some(id) == directory.as_ref() && Some(m) == marker.as_ref() => {}
            _ => return Err(ModelError::InvalidData("tree owner action-specific record")),
        }
        previous = ContentId::hash(&encode_history_record(record, MAX_TREE_HISTORY_BYTES)?);
        time = record.recorded_at_ms;
    }
    let encoded = encode_history_record(&(plan.intent(), records), bounds.max_encoded_bytes)?;
    Ok(TreeOwnerRecordAudit {
        records: records.to_vec(),
        directory,
        marker,
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
    })
}
