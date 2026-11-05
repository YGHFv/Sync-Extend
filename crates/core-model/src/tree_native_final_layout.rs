//! Description-free final row candidates, not native provenance or SQL authority.
use crate::{
    limits,
    persisted_rename::RenameObservationMap,
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_final_rows::{self, TreeFinalHistoryRowsPlan},
    tree_final_terminal_layout::{TreeFinalTerminalLayoutLimits, TreeFinalTerminalRowsLayout},
    tree_final_terminal_rows::{self, TreeFinalTerminalAssembly},
    tree_final_transaction::TreeFinalTransactionLimits,
    tree_native_action_layout::{
        plan_tree_native_action_layout, TreeNativeActionLayoutLimits, TreeNativeActionLayoutRecord,
        TreeNativeActionScope,
    },
    tree_native_protocol::TreeNativeProtocolPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeFinalLayoutInput {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub native_action_layout_hash: ContentId,
    pub fresh_observation_hash: ContentId,
    pub intended_at_ms: u64,
    pub committed_at_ms: u64,
    pub prior_observation: Option<RenameObservationMap>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeNativeFinalLayoutPlan {
    rows: TreeFinalTerminalRowsLayout,
    history: TreeFinalHistoryRowsPlan,
    owner_intent_hash: ContentId,
    forbidden_generations: BTreeSet<EntryId>,
    fingerprint: ContentId,
    encoded_bytes: u64,
    peak_encoded_bytes: u64,
}

impl TreeNativeFinalLayoutPlan {
    pub fn rows(&self) -> &TreeFinalTerminalRowsLayout {
        &self.rows
    }
    pub fn history(&self) -> &TreeFinalHistoryRowsPlan {
        &self.history
    }
    pub fn owner_intent_hash(&self) -> &ContentId {
        &self.owner_intent_hash
    }
    pub fn forbidden_generations(&self) -> &BTreeSet<EntryId> {
        &self.forbidden_generations
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
    pub fn native_effects_verified(&self) -> bool {
        false
    }
    pub fn history_commit_available(&self) -> bool {
        false
    }
    pub fn reference_release_available(&self) -> bool {
        false
    }
    pub fn full_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

pub fn plan_tree_native_final_layout(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    actions: &[TreeNativeActionLayoutRecord],
    input: &TreeNativeFinalLayoutInput,
    bounds: TreeFinalTerminalLayoutLimits,
) -> Result<TreeNativeFinalLayoutPlan> {
    if input.format_version != 1
        || bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_rows > limits::MAX_ENTRIES as u64
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_logical_bytes > MAX_TREE_HISTORY_BYTES
        || input.committed_at_ms > i64::MAX as u64
        || input.committed_at_ms < input.intended_at_ms
    {
        return Err(ModelError::InvalidData("native final bounds or time"));
    }
    encode_history_record(&(protocol.input(), actions, input), bounds.max_input_bytes)?;
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
    if action.scope() != &input.scope || action.fingerprint() != &input.native_action_layout_hash {
        return Err(ModelError::InvalidData("native final exact action binding"));
    }
    let forbidden_generations =
        tree_final_terminal_rows::generations(context, action.scope(), &input.finalization_id)?;
    let history = tree_final_rows::project(
        context,
        input.prior_observation.as_ref(),
        TreeFinalTransactionLimits {
            max_records: bounds.max_records,
            max_reference_rows: bounds.max_reference_rows,
            max_rows: bounds.max_rows,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_encoded_bytes,
            max_logical_bytes: bounds.max_logical_bytes,
        },
    )?;
    let borrowed = encode_history_record(
        &(
            input,
            history.rows(),
            action.completed_native_layout(),
            context.originals.intents(),
            context.originals.closures(),
        ),
        bounds.max_encoded_bytes,
    )?
    .len() as u64;
    let rows = tree_final_terminal_rows::assemble(
        context,
        &action,
        history.rows(),
        TreeFinalTerminalAssembly {
            finalization_id: &input.finalization_id,
            fresh_observation_hash: &input.fresh_observation_hash,
            intended_at_ms: input.intended_at_ms,
            committed_at_ms: input.committed_at_ms,
        },
        bounds.max_encoded_bytes,
    )?;
    let encoded = encode_history_record(&rows, bounds.max_encoded_bytes)?;
    let peak_encoded_bytes = (encoded.len() as u64)
        .max(borrowed)
        .max(action.peak_encoded_bytes())
        .max(history.footprint().encoded_bytes);
    Ok(TreeNativeFinalLayoutPlan {
        rows,
        history,
        owner_intent_hash: context.owner.intent_hash().clone(),
        forbidden_generations,
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
        peak_encoded_bytes,
    })
}

/// Exact proposed rows remain only a layout, not a native or committed receipt.
pub fn audit_tree_native_final_layout(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    actions: &[TreeNativeActionLayoutRecord],
    input: &TreeNativeFinalLayoutInput,
    rows: &TreeFinalTerminalRowsLayout,
    bounds: TreeFinalTerminalLayoutLimits,
) -> Result<TreeNativeFinalLayoutPlan> {
    encode_history_record(&(input, rows), bounds.max_input_bytes)?;
    let expected = plan_tree_native_final_layout(context, protocol, actions, input, bounds)?;
    if expected.rows() != rows {
        return Err(ModelError::InvalidData(
            "native final exact row candidate mismatch",
        ));
    }
    Ok(expected)
}
