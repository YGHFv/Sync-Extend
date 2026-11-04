//! Coordinator lifecycle representations, never native or SQL release authority.
use crate::{
    limits,
    tree_execution_records::TreeExecutionRecordAudit,
    tree_final_description::{
        plan_tree_final_description, TreeFinalLimits, TreeFinalPlan,
        TreeRetainedOriginalDescription,
    },
    tree_original_reference::{
        plan_tree_original_references, TreeOriginalReferenceLimits, TreeOriginalReferencePlan,
    },
    tree_owner_marker::{plan_tree_owner, TreeOwnerLimits, TreeOwnerPlan, TreeOwnerRecordAudit},
    tree_restore::{plan_tree_restore, TreeRestoreLimits},
    tree_restore_execution_intent::{plan_tree_execution_intent, TreeExecutionIntentPlan},
    tree_restore_history::{
        encode_history_record, TreeRestoreHistoryInput, TreeRestoreHistoryPlan,
        MAX_TREE_HISTORY_BYTES,
    },
    tree_restore_identity::TreeIdentityPlan,
    ContentId, EntryId, Manifest, ModelError, OperationId, Result, SnapshotId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub struct TreeCoordinatorContext<'a> {
    pub execution: &'a TreeExecutionIntentPlan,
    pub identity: &'a TreeIdentityPlan,
    pub history: &'a TreeRestoreHistoryPlan,
    pub history_input: &'a TreeRestoreHistoryInput,
    pub originals: &'a TreeOriginalReferencePlan,
    pub owner: &'a TreeOwnerPlan,
    pub baseline: &'a Manifest,
    pub target: &'a Manifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorLimits {
    pub max_steps: usize,
    pub max_owners: usize,
    pub max_reference_rows: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorAdmissionInput {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub preparation_hash: ContentId,
    pub execution_intent_hash: ContentId,
    pub original_request_hash: ContentId,
    pub original_closure_hash: ContentId,
    pub owner_intent_hash: ContentId,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCoordinatorAdmissionPlan {
    input: TreeCoordinatorAdmissionInput,
    intent_hash: ContentId,
    encoded_bytes: u64,
}
impl TreeCoordinatorAdmissionPlan {
    pub fn input(&self) -> &TreeCoordinatorAdmissionInput {
        &self.input
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn cancellation_gate_changed(&self) -> bool {
        false
    }
}

fn check_limits(context: &TreeCoordinatorContext<'_>, b: TreeCoordinatorLimits) -> Result<()> {
    if b.max_steps == 0
        || b.max_steps > limits::MAX_ENTRIES
        || b.max_owners > limits::MAX_ENTRIES
        || b.max_reference_rows > limits::MAX_CHUNKS
        || b.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || b.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || context.execution.intent().steps.len() > b.max_steps
        || context.originals.intents().len() > b.max_owners
        || context.originals.reference_rows() > b.max_reference_rows
    {
        return Err(ModelError::InvalidData("tree coordinator bounds"));
    }
    Ok(())
}

fn reproject(context: &TreeCoordinatorContext<'_>, b: TreeCoordinatorLimits) -> Result<()> {
    check_limits(context, b)?;
    let e = context.execution;
    encode_history_record(
        &(
            context.baseline,
            context.target,
            context.history_input,
            context.history.manifest(),
            context.history.operations(),
            e.intent(),
            context.identity.inventory(),
            context.originals.intents(),
            context.originals.closures(),
            context.owner.intent(),
        ),
        b.max_input_bytes,
    )?;
    let tree = plan_tree_restore(
        &e.intent().scope,
        context.baseline,
        context.target,
        TreeRestoreLimits {
            max_entries: limits::MAX_ENTRIES,
            max_steps: b.max_steps,
            max_chunk_visits: limits::MAX_CHUNKS,
            max_target_bytes: u64::MAX,
            max_retained_and_staging_bytes: u64::MAX,
            max_plan_bytes: MAX_TREE_HISTORY_BYTES,
        },
    )?;
    let execution = plan_tree_execution_intent(
        &tree,
        context.baseline,
        context.target,
        context.history,
        context.history_input,
        context.identity,
        &e.intent().input,
    )?;
    let originals = plan_tree_original_references(
        &execution,
        context.identity,
        TreeOriginalReferenceLimits {
            max_owners: b.max_steps,
            max_chunk_visits: limits::MAX_CHUNKS,
            max_reference_rows: b.max_reference_rows,
            max_encoded_bytes: b.max_input_bytes,
        },
    )?;
    let owner = plan_tree_owner(
        &execution,
        context.identity,
        &originals,
        &context.owner.intent().input,
        TreeOwnerLimits {
            max_steps: b.max_steps,
            max_encoded_bytes: b.max_input_bytes,
        },
    )?;
    if execution != *e || originals != *context.originals || owner != *context.owner {
        return Err(ModelError::InvalidData(
            "tree coordinator private projection",
        ));
    }
    Ok(())
}

fn require_fresh(context: &TreeCoordinatorContext<'_>, ids: &[&EntryId]) -> Result<()> {
    let e = context.execution.intent();
    let mut forbidden = BTreeSet::from([&e.input.transaction_id, &e.input.execution_id]);
    forbidden.extend(e.steps.iter().map(|s| &s.step_execution_id));
    for manifest in [context.baseline, context.target, context.history.manifest()] {
        forbidden.extend(manifest.entries.keys().chain(manifest.tombstones.keys()));
    }
    if ids.iter().any(|id| !forbidden.insert(id)) {
        return Err(ModelError::InvalidData("tree coordinator generation alias"));
    }
    Ok(())
}

/// A durable adapter must persist irreversible admission BEFORE any native effect.
/// This private model only checks the prospective binding; it changes no gate.
pub fn plan_tree_coordinator_admission(
    context: &TreeCoordinatorContext<'_>,
    input: &TreeCoordinatorAdmissionInput,
    bounds: TreeCoordinatorLimits,
) -> Result<TreeCoordinatorAdmissionPlan> {
    reproject(context, bounds)?;
    let e = &context.execution.intent().input;
    let owner = &context.owner.intent().input;
    if input.transaction_id != e.transaction_id
        || input.coordinator_execution_id != e.execution_id
        || input.preparation_hash != e.preparation_hash
        || input.execution_intent_hash
            != ContentId::hash(&encode_history_record(
                context.execution.intent(),
                bounds.max_input_bytes,
            )?)
        || input.original_request_hash != owner.original_request_hash
        || input.original_closure_hash != *context.originals.fingerprint()
        || input.owner_intent_hash != *context.owner.intent_hash()
        || input.admitted_at_ms < e.created_at_ms
        || input.admitted_at_ms < owner.created_at_ms
        || input.admitted_at_ms > i64::MAX as u64
    {
        return Err(ModelError::InvalidData(
            "tree coordinator admission exact binding",
        ));
    }
    require_fresh(context, &[&input.admission_id])?;
    let bytes = encode_history_record(input, bounds.max_encoded_bytes)?;
    Ok(TreeCoordinatorAdmissionPlan {
        input: input.clone(),
        intent_hash: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorCompletionInput {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub admission_hash: ContentId,
    pub finalization_id: EntryId,
    pub final_description_hash: ContentId,
    pub described_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorCompletionIntent {
    pub input: TreeCoordinatorCompletionInput,
    pub final_snapshot_id: SnapshotId,
    pub new_operation_ids: Vec<OperationId>,
    pub input_references: BTreeMap<ContentId, u32>,
    pub input_closure_hash: ContentId,
    pub retained_originals: BTreeMap<usize, TreeRetainedOriginalDescription>,
    pub retained_handoff_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCoordinatorCompletionPlan {
    intent: TreeCoordinatorCompletionIntent,
    intent_hash: ContentId,
    encoded_bytes: u64,
    input_reference_rows: usize,
    original_reference_rows: usize,
}
impl TreeCoordinatorCompletionPlan {
    pub fn intent(&self) -> &TreeCoordinatorCompletionIntent {
        &self.intent
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn input_reference_rows(&self) -> usize {
        self.input_reference_rows
    }
    pub fn original_reference_rows(&self) -> usize {
        self.original_reference_rows
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

#[derive(Serialize)]
struct BorrowedCompletion<'a> {
    input: &'a TreeCoordinatorCompletionInput,
    final_snapshot_id: &'a SnapshotId,
    new_operation_ids: &'a [OperationId],
    input_references: &'a BTreeMap<ContentId, u32>,
    input_closure_hash: ContentId,
    retained_originals: &'a BTreeMap<usize, TreeRetainedOriginalDescription>,
    retained_handoff_hash: ContentId,
}

/// Final/input-release/retained-owner handoff are distinct from cancellation.
/// Complete descriptive transcripts cannot substitute for an actual NEW commit.
#[allow(clippy::too_many_arguments)]
pub fn plan_tree_coordinator_completion(
    context: &TreeCoordinatorContext<'_>,
    admission: &TreeCoordinatorAdmissionPlan,
    final_plan: &TreeFinalPlan,
    owner_records: &TreeOwnerRecordAudit,
    steps: &TreeExecutionRecordAudit,
    input: &TreeCoordinatorCompletionInput,
    bounds: TreeCoordinatorLimits,
) -> Result<TreeCoordinatorCompletionPlan> {
    let exact_admission = plan_tree_coordinator_admission(context, admission.input(), bounds)?;
    if exact_admission != *admission
        || input.transaction_id != admission.input.transaction_id
        || input.coordinator_execution_id != admission.input.coordinator_execution_id
        || input.admission_id != admission.input.admission_id
        || input.admission_hash != *admission.intent_hash()
        || input.final_description_hash != *final_plan.intent_hash()
        || input.described_at_ms < final_plan.intent().input.described_at_ms
        || input.described_at_ms < admission.input.admitted_at_ms
        || input.described_at_ms > i64::MAX as u64
        || owner_records.records().is_empty()
        || owner_records
            .records()
            .iter()
            .any(|r| r.recorded_at_ms < admission.input.admitted_at_ms)
        || steps
            .records()
            .values()
            .flatten()
            .any(|r| r.recorded_at_ms < admission.input.admitted_at_ms)
    {
        return Err(ModelError::InvalidData(
            "tree coordinator completion admission order",
        ));
    }
    require_fresh(context, &[&input.admission_id, &input.finalization_id])?;
    let exact_final = plan_tree_final_description(
        context.execution,
        context.identity,
        context.history,
        context.originals,
        context.owner,
        owner_records,
        steps,
        &final_plan.intent().input,
        TreeFinalLimits {
            max_steps: bounds.max_steps,
            max_entries: limits::MAX_ENTRIES,
            max_records: limits::MAX_ENTRIES,
            max_reference_rows: bounds.max_reference_rows,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    if exact_final != *final_plan {
        return Err(ModelError::InvalidData(
            "tree coordinator completion final projection",
        ));
    }
    let mut references = BTreeMap::new();
    for chunk in [context.baseline, context.target]
        .into_iter()
        .flat_map(|m| m.entries.values())
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| &f.chunks)
    {
        if !references.contains_key(&chunk.content_id)
            && references.len() >= bounds.max_reference_rows
        {
            return Err(ModelError::InvalidData(
                "tree coordinator input reference inventory",
            ));
        }
        if references
            .insert(chunk.content_id.clone(), chunk.length)
            .is_some_and(|length| length != chunk.length)
        {
            return Err(ModelError::InvalidData(
                "tree coordinator input chunk length",
            ));
        }
    }
    // Original rows remain per-owner even when their chunks also occur in inputs.
    let original_reference_rows = context.originals.reference_rows();
    let input_reference_rows = references.len();
    if original_reference_rows
        .checked_add(input_reference_rows)
        .is_none_or(|rows| rows > bounds.max_reference_rows)
    {
        return Err(ModelError::InvalidData(
            "tree coordinator combined reference inventory",
        ));
    }
    let candidate = BorrowedCompletion {
        input,
        final_snapshot_id: context.history.snapshot_id(),
        new_operation_ids: &final_plan.intent().new_operation_ids,
        input_closure_hash: ContentId::hash(&encode_history_record(
            &references,
            bounds.max_input_bytes,
        )?),
        input_references: &references,
        retained_originals: &final_plan.intent().retained_originals,
        retained_handoff_hash: ContentId::hash(&encode_history_record(
            &final_plan.intent().retained_originals,
            bounds.max_input_bytes,
        )?),
    };
    let bytes = encode_history_record(&candidate, bounds.max_encoded_bytes)?;
    Ok(TreeCoordinatorCompletionPlan {
        intent: serde_json::from_slice(&bytes)?,
        intent_hash: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
        input_reference_rows,
        original_reference_rows,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeCoordinatorCompletionEvent {
    FinalAuthorizationDescribed {
        final_description_hash: ContentId,
    },
    NewHistoryCommitDescribed {
        snapshot_id: SnapshotId,
        operation_ids: Vec<OperationId>,
        retained_handoff_hash: ContentId,
    },
    InputReleaseDescribed {
        input_closure_hash: ContentId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorCompletionRecord {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub finalization_id: EntryId,
    pub intent_hash: ContentId,
    pub record_index: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeCoordinatorCompletionEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorRecordLimits {
    pub max_records: usize,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCoordinatorCompletionAudit {
    records: Vec<TreeCoordinatorCompletionRecord>,
    fingerprint: ContentId,
    encoded_bytes: u64,
}
impl TreeCoordinatorCompletionAudit {
    pub fn records(&self) -> &[TreeCoordinatorCompletionRecord] {
        &self.records
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn description_complete(&self) -> bool {
        self.records.len() == 3
    }
    pub fn committed_new_history_verified(&self) -> bool {
        false
    }
    pub fn input_reference_release_available(&self) -> bool {
        false
    }
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
}

/// One ordered metadata chain describes the future single final transaction.
pub fn audit_tree_coordinator_completion_records(
    plan: &TreeCoordinatorCompletionPlan,
    records: &[TreeCoordinatorCompletionRecord],
    bounds: TreeCoordinatorRecordLimits,
) -> Result<TreeCoordinatorCompletionAudit> {
    if bounds.max_records > 3
        || records.len() > bounds.max_records
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData(
            "tree coordinator completion record bounds",
        ));
    }
    // Bound caller-controlled event vectors before hashing individual records.
    let bytes = encode_history_record(&(plan.intent(), records), bounds.max_encoded_bytes)?;
    let intent = plan.intent();
    let input = &intent.input;
    let mut previous = plan.intent_hash().clone();
    let mut time = input.described_at_ms;
    for (index, record) in records.iter().enumerate() {
        if record.transaction_id != input.transaction_id
            || record.coordinator_execution_id != input.coordinator_execution_id
            || record.admission_id != input.admission_id
            || record.finalization_id != input.finalization_id
            || record.intent_hash != *plan.intent_hash()
            || record.record_index != index
            || record.previous_hash != previous
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
        {
            return Err(ModelError::InvalidData(
                "tree coordinator completion exact chain",
            ));
        }
        let exact = match (&record.event, index) {
            (
                TreeCoordinatorCompletionEvent::FinalAuthorizationDescribed {
                    final_description_hash,
                },
                0,
            ) => final_description_hash == &input.final_description_hash,
            (
                TreeCoordinatorCompletionEvent::NewHistoryCommitDescribed {
                    snapshot_id,
                    operation_ids,
                    retained_handoff_hash,
                },
                1,
            ) => {
                snapshot_id == &intent.final_snapshot_id
                    && operation_ids == &intent.new_operation_ids
                    && retained_handoff_hash == &intent.retained_handoff_hash
            }
            (TreeCoordinatorCompletionEvent::InputReleaseDescribed { input_closure_hash }, 2) => {
                input_closure_hash == &intent.input_closure_hash
            }
            _ => false,
        };
        if !exact {
            return Err(ModelError::InvalidData(
                "tree coordinator completion exact event",
            ));
        }
        previous = ContentId::hash(&encode_history_record(record, bounds.max_encoded_bytes)?);
        time = record.recorded_at_ms;
    }
    Ok(TreeCoordinatorCompletionAudit {
        records: records.to_vec(),
        fingerprint: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
    })
}
