//! Admission-bound prospective native record layouts, never native effect proof.
use crate::{
    limits,
    tree_coordinator_lifecycle::{
        plan_tree_coordinator_admission, TreeCoordinatorAdmissionInput, TreeCoordinatorContext,
        TreeCoordinatorLimits,
    },
    tree_execution_records::{
        audit_tree_execution_records, TreeExecutionRecord, TreeExecutionRecordAudit,
        TreeExecutionRecordLimits,
    },
    tree_owner_marker::{
        audit_tree_owner_records, TreeOwnerRecord, TreeOwnerRecordAudit, TreeOwnerRecordLimits,
    },
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeAdmissionBinding {
    pub input: TreeCoordinatorAdmissionInput,
    pub limits: TreeCoordinatorLimits,
    pub intent_hash: ContentId,
    pub request_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeProtocolInput {
    pub format_version: u32,
    pub admission: TreeNativeAdmissionBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeProtocolLimits {
    pub max_records: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeNativeProtocolPlan {
    input: TreeNativeProtocolInput,
    intent_hash: ContentId,
    encoded_bytes: u64,
}
impl TreeNativeProtocolPlan {
    pub fn input(&self) -> &TreeNativeProtocolInput {
        &self.input
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
struct AdmissionRequest<'a> {
    input: &'a TreeCoordinatorAdmissionInput,
    limits: TreeCoordinatorLimits,
}

/// Reprojects the complete context and request shape. A matching hash is NOT
/// evidence that the irreversible admission row exists in a real Journal.
pub fn plan_tree_native_protocol(
    context: &TreeCoordinatorContext<'_>,
    input: &TreeNativeProtocolInput,
    bounds: TreeNativeProtocolLimits,
) -> Result<TreeNativeProtocolPlan> {
    if input.format_version != 1
        || bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("tree native protocol bounds"));
    }
    encode_history_record(
        &(
            context.execution.intent(),
            context.identity.inventory(),
            context.history_input,
            context.history.manifest(),
            context.history.operations(),
            context.originals.intents(),
            context.originals.closures(),
            context.owner.intent(),
            context.baseline,
            context.target,
            input,
        ),
        bounds.max_input_bytes,
    )?;
    let binding = &input.admission;
    let admission = plan_tree_coordinator_admission(context, &binding.input, binding.limits)?;
    let request = AdmissionRequest {
        input: &binding.input,
        limits: binding.limits,
    };
    if admission.intent_hash() != &binding.intent_hash
        || ContentId::hash(&encode_history_record(&request, bounds.max_input_bytes)?)
            != binding.request_hash
    {
        return Err(ModelError::InvalidData("tree native admission binding"));
    }
    let bytes = encode_history_record(
        &("sync-extend-tree-native-protocol-v1", input),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeNativeProtocolPlan {
        input: input.clone(),
        intent_hash: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeNativeProtocolEvent {
    Owner {
        record: TreeOwnerRecord,
    },
    Step {
        owner_ready_record_hash: ContentId,
        record: TreeExecutionRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeProtocolRecord {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub admission_hash: ContentId,
    pub protocol_hash: ContentId,
    pub record_index: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeNativeProtocolEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeNativeProtocolAudit {
    records: Vec<TreeNativeProtocolRecord>,
    owner: TreeOwnerRecordAudit,
    steps: TreeExecutionRecordAudit,
    owner_ready_record_hash: Option<ContentId>,
    fingerprint: ContentId,
    encoded_bytes: u64,
}
impl TreeNativeProtocolAudit {
    pub fn records(&self) -> &[TreeNativeProtocolRecord] {
        &self.records
    }
    pub fn owner(&self) -> &TreeOwnerRecordAudit {
        &self.owner
    }
    pub fn steps(&self) -> &TreeExecutionRecordAudit {
        &self.steps
    }
    pub fn owner_ready_record_hash(&self) -> Option<&ContentId> {
        self.owner_ready_record_hash.as_ref()
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_effects_verified(&self) -> bool {
        false
    }
    pub fn history_commit_available(&self) -> bool {
        false
    }
    pub fn input_reference_release_available(&self) -> bool {
        false
    }
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// One admission-bound root/step chain fixes pre-effect ordering and exact
/// payloads. Native/SQL adapters must independently establish actual effects.
pub fn audit_tree_native_protocol_records(
    context: &TreeCoordinatorContext<'_>,
    plan: &TreeNativeProtocolPlan,
    records: &[TreeNativeProtocolRecord],
    bounds: TreeNativeProtocolLimits,
) -> Result<TreeNativeProtocolAudit> {
    if records.len() > bounds.max_records {
        return Err(ModelError::InvalidData("tree native protocol inventory"));
    }
    // Bound nested materialization and all caller-controlled record payloads
    // before transcript copies and the older descriptive auditors.
    let bytes = encode_history_record(&(plan.input(), records), bounds.max_encoded_bytes)?;
    if plan_tree_native_protocol(context, plan.input(), bounds)? != *plan {
        return Err(ModelError::InvalidData("tree native private projection"));
    }
    let admission = &plan.input.admission;
    let mut owner_records = Vec::new();
    let mut step_records = BTreeMap::<usize, Vec<TreeExecutionRecord>>::new();
    let mut owner_ready = None;
    let mut previous = plan.intent_hash.clone();
    let mut time = admission.input.admitted_at_ms;
    for (index, record) in records.iter().enumerate() {
        if record.transaction_id != admission.input.transaction_id
            || record.coordinator_execution_id != admission.input.coordinator_execution_id
            || record.admission_id != admission.input.admission_id
            || record.admission_hash != admission.intent_hash
            || record.protocol_hash != plan.intent_hash
            || record.record_index != index
            || record.previous_hash != previous
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
        {
            return Err(ModelError::InvalidData("tree native exact record chain"));
        }
        match &record.event {
            TreeNativeProtocolEvent::Owner { record: inner }
                if step_records.is_empty()
                    && owner_records.len() < 8
                    && inner.recorded_at_ms == record.recorded_at_ms =>
            {
                owner_records.push(inner.clone());
                if owner_records.len() == 8 {
                    owner_ready = Some(ContentId::hash(&encode_history_record(
                        record,
                        bounds.max_encoded_bytes,
                    )?));
                }
            }
            TreeNativeProtocolEvent::Step {
                owner_ready_record_hash,
                record: inner,
            } if owner_ready.as_ref() == Some(owner_ready_record_hash)
                && inner.recorded_at_ms == record.recorded_at_ms =>
            {
                let expected_step = step_records.keys().next_back().copied().unwrap_or(0);
                if inner.step_index < expected_step
                    || inner.step_index > expected_step + usize::from(!step_records.is_empty())
                    || inner.record_index != step_records.get(&inner.step_index).map_or(0, Vec::len)
                {
                    return Err(ModelError::InvalidData(
                        "tree native deterministic step order",
                    ));
                }
                step_records
                    .entry(inner.step_index)
                    .or_default()
                    .push(inner.clone());
            }
            _ => return Err(ModelError::InvalidData("tree native root before steps")),
        }
        previous = ContentId::hash(&encode_history_record(record, bounds.max_encoded_bytes)?);
        time = record.recorded_at_ms;
    }
    let owner = audit_tree_owner_records(
        context.owner,
        &owner_records,
        TreeOwnerRecordLimits {
            max_records: 8,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let steps = audit_tree_execution_records(
        context.execution,
        context.identity,
        &step_records,
        TreeExecutionRecordLimits {
            max_records: bounds.max_records.max(1),
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    // The separate descriptive auditors exclude baseline aliases but cannot
    // independently exclude aliases with this newly owned root area.
    for record in steps.records().values().flatten() {
        if let crate::tree_execution_records::TreeExecutionEvent::CreatorBound { creator } =
            &record.event
        {
            if owner.directory() == Some(creator) || owner.marker() == Some(creator) {
                return Err(ModelError::InvalidData("tree native owner creator alias"));
            }
        }
    }
    Ok(TreeNativeProtocolAudit {
        records: records.to_vec(),
        owner,
        steps,
        owner_ready_record_hash: owner_ready,
        fingerprint: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
    })
}
