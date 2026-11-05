//! Exact terminal row candidates. Caller layouts never establish committed proof.
use crate::{
    limits,
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_execution_records::TreeExecutionTerminal,
    tree_final_terminal_rows::{self, TreeFinalTerminalAssembly},
    tree_final_transaction::{
        plan_tree_final_transaction, TreeFinalTransactionInput, TreeFinalTransactionLimits,
        TreeFinalTransactionPlan,
    },
    tree_native_action_layout::{
        plan_tree_native_action_layout, TreeNativeActionLayoutLimits, TreeNativeActionLayoutRecord,
        TreeNativeActionScope,
    },
    tree_native_protocol::{
        audit_tree_native_protocol_records, TreeNativeProtocolLimits, TreeNativeProtocolPlan,
        TreeNativeProtocolRecord,
    },
    tree_original_reference::TreeOriginalReferenceIntent,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{TreeNativeEntry, TreeNativeIdentity},
    ContentId, EntryId, ModelError, OperationId, PortablePath, Result, SnapshotId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTerminalLayoutInput {
    pub final_transaction: TreeFinalTransactionInput,
    pub native_action_layout_hash: ContentId,
    pub fresh_observation_hash: ContentId,
    pub committed_at_ms: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTerminalLayoutLimits {
    pub max_records: usize,
    pub max_reference_rows: usize,
    pub max_rows: u64,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
    pub max_logical_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalOriginalHandoffLayout {
    pub original: TreeOriginalReferenceIntent,
    pub references: BTreeMap<ContentId, u32>,
    pub retained_component: String,
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub operation_id: OperationId,
    pub snapshot_id: SnapshotId,
    pub action_layout_hash: ContentId,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTerminalIntentLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub action_layout_hash: ContentId,
    pub action_last_record_hash: ContentId,
    pub action_record_count: usize,
    pub fresh_observation_hash: ContentId,
    pub exact_history_rows_hash: ContentId,
    pub final_snapshot_id: SnapshotId,
    pub operation_ids: Vec<OperationId>,
    pub final_native_entries: BTreeMap<PortablePath, TreeNativeEntry>,
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub input_references: BTreeMap<ContentId, u32>,
    pub input_closure_hash: ContentId,
    pub original_handoffs: BTreeMap<usize, TreeFinalOriginalHandoffLayout>,
    pub original_handoffs_hash: ContentId,
    pub intended_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalCommittedLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub terminal_intent_hash: ContentId,
    pub action_layout_hash: ContentId,
    pub fresh_observation_hash: ContentId,
    pub exact_history_rows_hash: ContentId,
    pub final_snapshot_id: SnapshotId,
    pub operation_ids: Vec<OperationId>,
    pub input_closure_hash: ContentId,
    pub input_reference_count: usize,
    pub original_handoffs_hash: ContentId,
    pub original_owner_count: usize,
    pub committed_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalInputReleaseLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub committed_record_hash: ContentId,
    pub input_closure_hash: ContentId,
    pub released_reference_count: usize,
    pub released_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalRetainedOwnerLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub committed_record_hash: ContentId,
    pub step_index: usize,
    pub step_execution_id: EntryId,
    pub handoff_hash: ContentId,
    pub handoff: TreeFinalOriginalHandoffLayout,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalTerminalRowsLayout {
    pub intent: TreeFinalTerminalIntentLayout,
    pub committed: TreeFinalCommittedLayout,
    pub input_release: TreeFinalInputReleaseLayout,
    pub retained_owners: BTreeMap<usize, TreeFinalRetainedOwnerLayout>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeFinalTerminalLayoutPlan {
    rows: TreeFinalTerminalRowsLayout,
    transaction: TreeFinalTransactionPlan,
    fingerprint: ContentId,
    encoded_bytes: u64,
    peak_encoded_bytes: u64,
    forbidden_generations: BTreeSet<EntryId>,
    owner_intent_hash: ContentId,
}
impl TreeFinalTerminalLayoutPlan {
    pub fn rows(&self) -> &TreeFinalTerminalRowsLayout {
        &self.rows
    }
    pub fn transaction(&self) -> &TreeFinalTransactionPlan {
        &self.transaction
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn peak_encoded_bytes(&self) -> u64 {
        self.peak_encoded_bytes
    }
    pub fn forbidden_generations(&self) -> &BTreeSet<EntryId> {
        &self.forbidden_generations
    }
    pub fn owner_intent_hash(&self) -> &ContentId {
        &self.owner_intent_hash
    }
    pub fn durable_native_action_evidence(&self) -> bool {
        false
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
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// Exact prospective terminal rows are not real observed/committed terminals.
/// Description records are used only for the existing prospective SQL projector;
/// distinct complete action layouts independently bind final native/original IDs.
pub fn plan_tree_final_terminal_layout(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    descriptions: &[TreeNativeProtocolRecord],
    actions: &[TreeNativeActionLayoutRecord],
    input: &TreeFinalTerminalLayoutInput,
    bounds: TreeFinalTerminalLayoutLimits,
) -> Result<TreeFinalTerminalLayoutPlan> {
    if bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_rows > limits::MAX_ENTRIES as u64
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_logical_bytes > MAX_TREE_HISTORY_BYTES
        || input.committed_at_ms > i64::MAX as u64
        || input.committed_at_ms < input.final_transaction.described_at_ms
    {
        return Err(ModelError::InvalidData(
            "final terminal layout bounds or time",
        ));
    }
    encode_history_record(
        &(protocol.input(), descriptions, actions, input),
        bounds.max_input_bytes,
    )?;
    let action = plan_tree_native_action_layout(
        context,
        protocol,
        actions,
        TreeNativeActionLayoutLimits {
            max_records: bounds.max_records,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_encoded_bytes,
        },
    )?;
    let completed = action
        .completed_native_layout()
        .ok_or(ModelError::InvalidData(
            "final terminal requires complete action layout",
        ))?;
    if action.fingerprint() != &input.native_action_layout_hash
        || input.final_transaction.described_at_ms < completed.last_recorded_at_ms
    {
        return Err(ModelError::InvalidData(
            "final terminal exact action layout binding",
        ));
    }
    let descriptive = audit_tree_native_protocol_records(
        context,
        protocol,
        descriptions,
        TreeNativeProtocolLimits {
            max_records: bounds.max_records,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_encoded_bytes,
        },
    )?;
    if descriptive.owner().directory() != Some(&completed.owner_directory)
        || descriptive.owner().marker() != Some(&completed.owner_marker)
    {
        return Err(ModelError::InvalidData(
            "final terminal distinct owner layout mismatch",
        ));
    }
    for step in &context.execution.intent().steps {
        let terminal = descriptive
            .steps()
            .terminals()
            .get(&step.step.index)
            .ok_or(ModelError::InvalidData(
                "final terminal described step incomplete",
            ))?;
        let published = match terminal {
            TreeExecutionTerminal::DirectoryPublished { published }
            | TreeExecutionTerminal::FilePublished { published }
            | TreeExecutionTerminal::FileReplaced { published, .. } => Some(published),
            _ => None,
        };
        if published.is_some_and(|id| {
            completed
                .entries
                .get(&step.step.path)
                .is_none_or(|e| &e.identity != id)
        }) {
            return Err(ModelError::InvalidData(
                "final terminal independent creator layout mismatch",
            ));
        }
    }
    let transaction = plan_tree_final_transaction(
        context,
        protocol,
        &descriptive,
        &input.final_transaction,
        TreeFinalTransactionLimits {
            max_records: bounds.max_records,
            max_reference_rows: bounds.max_reference_rows,
            max_rows: bounds.max_rows,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_encoded_bytes,
            max_logical_bytes: bounds.max_logical_bytes,
        },
    )?;
    // Preserve the old envelope bound while the common constructor derives values.
    let borrowed_bytes = encode_history_record(
        &(
            input,
            transaction.intent(),
            transaction.rows(),
            completed,
            context.originals.intents(),
            context.originals.closures(),
        ),
        bounds.max_encoded_bytes,
    )?;
    for (&index, original) in context.originals.intents() {
        let described = &transaction.intent().retained_originals[&index];
        if completed.retained_originals.get(&index) != Some(&original.original_identity)
            || described.owner_directory != completed.owner_directory
            || described.owner_marker != completed.owner_marker
            || described.new_operation_id
                != context.execution.intent().steps[index].new_operation_id
        {
            return Err(ModelError::InvalidData(
                "final terminal independent original owner mismatch",
            ));
        }
    }
    let rows = tree_final_terminal_rows::assemble(
        context,
        &action,
        transaction.rows(),
        TreeFinalTerminalAssembly {
            finalization_id: &input.final_transaction.finalization_id,
            fresh_observation_hash: &input.fresh_observation_hash,
            intended_at_ms: input.final_transaction.described_at_ms,
            committed_at_ms: input.committed_at_ms,
        },
        bounds.max_encoded_bytes,
    )?;
    let bytes = encode_history_record(&rows, bounds.max_encoded_bytes)?;
    let peak_encoded_bytes = (bytes.len() as u64)
        .max(borrowed_bytes.len() as u64)
        .max(action.peak_encoded_bytes())
        .max(transaction.footprint().encoded_bytes)
        .max(descriptive.encoded_bytes());
    let forbidden_generations = tree_final_terminal_rows::generations(
        context,
        action.scope(),
        &input.final_transaction.finalization_id,
    )?;
    Ok(TreeFinalTerminalLayoutPlan {
        rows,
        transaction,
        fingerprint: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
        peak_encoded_bytes,
        forbidden_generations,
        owner_intent_hash: context.owner.intent_hash().clone(),
    })
}

pub fn audit_tree_final_terminal_layout(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    descriptions: &[TreeNativeProtocolRecord],
    actions: &[TreeNativeActionLayoutRecord],
    input: &TreeFinalTerminalLayoutInput,
    rows: &TreeFinalTerminalRowsLayout,
    bounds: TreeFinalTerminalLayoutLimits,
) -> Result<TreeFinalTerminalLayoutPlan> {
    encode_history_record(&(input, rows), bounds.max_input_bytes)?;
    let expected =
        plan_tree_final_terminal_layout(context, protocol, descriptions, actions, input, bounds)?;
    if expected.rows() != rows {
        return Err(ModelError::InvalidData(
            "final terminal exact row candidate mismatch",
        ));
    }
    Ok(expected)
}
