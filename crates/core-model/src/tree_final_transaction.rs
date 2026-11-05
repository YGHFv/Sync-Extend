//! Exact prospective final SQL row values, never native proof or write authority.
use crate::{
    limits,
    persisted_rename::RenameObservationMap,
    tree_coordinator_lifecycle::{
        plan_tree_coordinator_admission, plan_tree_coordinator_completion,
        TreeCoordinatorCompletionInput, TreeCoordinatorContext, TreeCoordinatorLimits,
    },
    tree_final_description::{
        plan_tree_final_description, TreeFinalInput, TreeFinalLimits,
        TreeRetainedOriginalDescription,
    },
    tree_native_protocol::{
        audit_tree_native_protocol_records, TreeNativeProtocolAudit, TreeNativeProtocolLimits,
        TreeNativeProtocolPlan,
    },
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    ContentId, DeviceId, EntryId, ModelError, OperationId, Result, SnapshotId, SpaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTransactionInput {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub finalization_id: EntryId,
    pub protocol_hash: ContentId,
    pub protocol_records_hash: ContentId,
    pub described_at_ms: u64,
    /// Exact local row to invalidate, or explicit absence; never a wildcard.
    pub prior_observation: Option<RenameObservationMap>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTransactionLimits {
    pub max_records: usize,
    pub max_reference_rows: usize,
    pub max_rows: u64,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
    pub max_logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalOperationRow {
    pub op_id: OperationId,
    pub space_id: SpaceId,
    pub origin_device_id: DeviceId,
    pub origin_seq: u64,
    pub payload: String,
    pub state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalSnapshotRow {
    pub snapshot_id: SnapshotId,
    pub space_id: SpaceId,
    pub manifest: String,
    pub created_at_ms: u64,
    pub state: String,
    pub locked: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalSnapshotObjectRow {
    pub snapshot_id: SnapshotId,
    pub content_id: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalInputReleaseRow {
    pub transaction_id: EntryId,
    pub content_id: ContentId,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalRetainedReferenceRow {
    pub transaction_id: EntryId,
    pub step_index: usize,
    pub step_execution_id: EntryId,
    pub content_id: ContentId,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalCursorWrite {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub prior_seq: u64,
    pub contiguous_seq: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalCurrentWrite {
    pub space_id: SpaceId,
    pub prior_snapshot_id: SnapshotId,
    pub snapshot_id: SnapshotId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalObservationInvalidation {
    pub space_id: SpaceId,
    pub snapshot_id: SnapshotId,
    pub observation: String,
    pub observation_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTransactionRows {
    pub operations: Vec<TreeFinalOperationRow>,
    pub snapshot: TreeFinalSnapshotRow,
    pub snapshot_objects: Vec<TreeFinalSnapshotObjectRow>,
    pub cursor: TreeFinalCursorWrite,
    pub current: TreeFinalCurrentWrite,
    pub input_release: Vec<TreeFinalInputReleaseRow>,
    pub retained_references: Vec<TreeFinalRetainedReferenceRow>,
    pub observation_invalidation: Option<TreeFinalObservationInvalidation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTransactionIntent {
    pub input: TreeFinalTransactionInput,
    pub admission_hash: ContentId,
    pub baseline_snapshot_id: SnapshotId,
    pub target_snapshot_id: SnapshotId,
    pub final_description_hash: ContentId,
    pub rows_hash: ContentId,
    pub input_closure_hash: ContentId,
    pub retained_handoff_hash: ContentId,
    pub retained_originals: BTreeMap<usize, TreeRetainedOriginalDescription>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeFinalTransactionFootprint {
    /// NEW operation/snapshot/ref rows plus values of current/cursor after update.
    pub history_value_rows: u64,
    pub history_logical_bytes: u64,
    pub input_release_rows: u64,
    pub input_release_logical_bytes: u64,
    pub retained_reference_rows: u64,
    pub retained_reference_logical_bytes: u64,
    pub observation_delete_rows: u64,
    pub observation_delete_logical_bytes: u64,
    pub sql_row_writes: u64,
    pub encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeFinalTransactionPlan {
    intent: TreeFinalTransactionIntent,
    intent_hash: ContentId,
    rows: TreeFinalTransactionRows,
    footprint: TreeFinalTransactionFootprint,
}

impl TreeFinalTransactionPlan {
    pub fn intent(&self) -> &TreeFinalTransactionIntent {
        &self.intent
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn rows(&self) -> &TreeFinalTransactionRows {
        &self.rows
    }
    pub fn footprint(&self) -> &TreeFinalTransactionFootprint {
        &self.footprint
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

#[derive(Serialize)]
struct BorrowedFinalIntent<'a> {
    input: &'a TreeFinalTransactionInput,
    admission_hash: &'a ContentId,
    baseline_snapshot_id: &'a SnapshotId,
    target_snapshot_id: &'a SnapshotId,
    final_description_hash: &'a ContentId,
    rows_hash: ContentId,
    input_closure_hash: &'a ContentId,
    retained_handoff_hash: &'a ContentId,
    retained_originals: &'a BTreeMap<usize, TreeRetainedOriginalDescription>,
}

/// Independently reproject every prospective value. Even a complete transcript
/// cannot establish native effects or actual Journal admission/NEW publication.
pub fn plan_tree_final_transaction(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    audit: &TreeNativeProtocolAudit,
    input: &TreeFinalTransactionInput,
    bounds: TreeFinalTransactionLimits,
) -> Result<TreeFinalTransactionPlan> {
    if input.format_version != 1
        || bounds.max_records == 0
        || bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_rows > limits::MAX_ENTRIES as u64
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_logical_bytes > MAX_TREE_HISTORY_BYTES
        || input.described_at_ms > i64::MAX as u64
    {
        return Err(ModelError::InvalidData("tree final transaction bounds"));
    }
    encode_history_record(
        &(
            context.baseline,
            context.target,
            context.execution.intent(),
            context.identity.inventory(),
            context.history_input,
            context.history.manifest(),
            context.history.operations(),
            context.originals.intents(),
            context.originals.closures(),
            context.owner.intent(),
            protocol.input(),
            audit.records(),
            input,
        ),
        bounds.max_input_bytes,
    )?;
    let binding = &protocol.input().admission;
    if input.transaction_id != binding.input.transaction_id
        || input.coordinator_execution_id != binding.input.coordinator_execution_id
        || input.admission_id != binding.input.admission_id
        || input.protocol_hash != *protocol.intent_hash()
        || input.protocol_records_hash != *audit.fingerprint()
        || input.finalization_id == input.admission_id
        || input.described_at_ms < binding.input.admitted_at_ms
        || audit
            .records()
            .last()
            .is_none_or(|r| input.described_at_ms < r.recorded_at_ms)
    {
        return Err(ModelError::InvalidData(
            "tree final transaction exact protocol",
        ));
    }
    let actual_audit = audit_tree_native_protocol_records(
        context,
        protocol,
        audit.records(),
        TreeNativeProtocolLimits {
            max_records: bounds.max_records,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    if &actual_audit != audit
        || !audit.owner().description_complete()
        || audit.steps().terminals().len() != context.execution.intent().steps.len()
    {
        return Err(ModelError::InvalidData(
            "tree final transaction incomplete protocol",
        ));
    }
    let coordinator_limits = TreeCoordinatorLimits {
        max_steps: limits::MAX_ENTRIES,
        max_owners: limits::MAX_ENTRIES,
        max_reference_rows: bounds.max_reference_rows,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_input_bytes,
    };
    let admission = plan_tree_coordinator_admission(context, &binding.input, binding.limits)?;
    let final_plan = plan_tree_final_description(
        context.execution,
        context.identity,
        context.history,
        context.originals,
        context.owner,
        audit.owner(),
        audit.steps(),
        &TreeFinalInput {
            transaction_id: input.transaction_id.clone(),
            coordinator_execution_id: input.coordinator_execution_id.clone(),
            execution_intent_hash: binding.input.execution_intent_hash.clone(),
            original_request_hash: binding.input.original_request_hash.clone(),
            original_closure_hash: binding.input.original_closure_hash.clone(),
            owner_intent_hash: binding.input.owner_intent_hash.clone(),
            owner_records_hash: audit.owner().fingerprint().clone(),
            step_records_hash: audit.steps().fingerprint().clone(),
            history_projection_hash: context.history.fingerprint().clone(),
            described_at_ms: input.described_at_ms,
        },
        TreeFinalLimits {
            max_steps: limits::MAX_ENTRIES,
            max_entries: limits::MAX_ENTRIES,
            max_records: bounds.max_records,
            max_reference_rows: bounds.max_reference_rows,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let completion = plan_tree_coordinator_completion(
        context,
        &admission,
        &final_plan,
        audit.owner(),
        audit.steps(),
        &TreeCoordinatorCompletionInput {
            transaction_id: input.transaction_id.clone(),
            coordinator_execution_id: input.coordinator_execution_id.clone(),
            admission_id: input.admission_id.clone(),
            admission_hash: binding.intent_hash.clone(),
            finalization_id: input.finalization_id.clone(),
            final_description_hash: final_plan.intent_hash().clone(),
            described_at_ms: input.described_at_ms,
        },
        coordinator_limits,
    )?;
    let projected =
        crate::tree_final_rows::project(context, input.prior_observation.as_ref(), bounds)?;
    let rows = projected.rows().clone();
    let input_closure: BTreeMap<_, _> = rows
        .input_release
        .iter()
        .map(|r| (r.content_id.clone(), r.length))
        .collect();
    if input_closure != completion.intent().input_references {
        return Err(ModelError::InvalidData("tree final shared input closure"));
    }
    let row_json = encode_history_record(&rows, bounds.max_encoded_bytes)?;
    let borrowed_intent = BorrowedFinalIntent {
        input,
        admission_hash: &binding.intent_hash,
        baseline_snapshot_id: &rows.current.prior_snapshot_id,
        target_snapshot_id: &context.execution.intent().scope.target_snapshot,
        final_description_hash: final_plan.intent_hash(),
        rows_hash: ContentId::hash(&row_json),
        input_closure_hash: &completion.intent().input_closure_hash,
        retained_handoff_hash: &completion.intent().retained_handoff_hash,
        retained_originals: &completion.intent().retained_originals,
    };
    // Include duplicated input/retained payloads before materializing the intent.
    let envelope = encode_history_record(
        &(
            "sync-extend-tree-final-transaction-v1",
            &borrowed_intent,
            &rows,
        ),
        bounds.max_encoded_bytes,
    )?;
    let intent = serde_json::from_slice(&encode_history_record(
        &borrowed_intent,
        bounds.max_encoded_bytes,
    )?)?;
    Ok(TreeFinalTransactionPlan {
        intent,
        intent_hash: ContentId::hash(&envelope),
        footprint: TreeFinalTransactionFootprint {
            encoded_bytes: envelope.len() as u64,
            ..projected.footprint().clone()
        },
        rows,
    })
}

/// Reject reordered, partial or altered values rather than a generic writer flag.
pub fn audit_tree_final_transaction_rows(
    plan: &TreeFinalTransactionPlan,
    rows: &TreeFinalTransactionRows,
    max_encoded_bytes: u64,
) -> Result<()> {
    if max_encoded_bytes > MAX_TREE_HISTORY_BYTES {
        return Err(ModelError::InvalidData("tree final row audit bounds"));
    }
    let encoded = encode_history_record(rows, max_encoded_bytes)?;
    if rows != &plan.rows || ContentId::hash(&encoded) != plan.intent.rows_hash {
        return Err(ModelError::InvalidData("tree final exact prospective rows"));
    }
    // Input refs are exact owner-scoped deletions, never retained-owner releases.
    let inputs: BTreeSet<_> = rows
        .input_release
        .iter()
        .map(|r| (&r.transaction_id, &r.content_id))
        .collect();
    if inputs.len() != rows.input_release.len() {
        return Err(ModelError::InvalidData(
            "tree final duplicate input release",
        ));
    }
    Ok(())
}
