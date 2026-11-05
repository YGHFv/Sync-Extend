//! Shared terminal construction after independent action and history audits.
use crate::{
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_final_terminal_layout::{
        TreeFinalCommittedLayout, TreeFinalInputReleaseLayout, TreeFinalOriginalHandoffLayout,
        TreeFinalRetainedOwnerLayout, TreeFinalTerminalIntentLayout, TreeFinalTerminalRowsLayout,
    },
    tree_final_transaction::TreeFinalTransactionRows,
    tree_native_action_layout::{TreeNativeActionLayoutPlan, TreeNativeActionScope},
    tree_restore_history::encode_history_record,
    ContentId, EntryId, ModelError, Result,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct TreeFinalTerminalAssembly<'a> {
    pub finalization_id: &'a EntryId,
    pub fresh_observation_hash: &'a ContentId,
    pub intended_at_ms: u64,
    pub committed_at_ms: u64,
}

pub(crate) fn generations(
    context: &TreeCoordinatorContext<'_>,
    scope: &TreeNativeActionScope,
    finalization_id: &EntryId,
) -> Result<BTreeSet<EntryId>> {
    let mut ids: BTreeSet<_> = [
        &scope.transaction_id,
        &scope.coordinator_execution_id,
        &scope.admission_id,
    ]
    .into_iter()
    .cloned()
    .collect();
    ids.extend(
        context
            .execution
            .intent()
            .steps
            .iter()
            .map(|s| s.step_execution_id.clone()),
    );
    for manifest in [context.baseline, context.target, context.history.manifest()] {
        ids.extend(
            manifest
                .entries
                .keys()
                .chain(manifest.tombstones.keys())
                .cloned(),
        );
    }
    if !ids.insert(finalization_id.clone()) {
        return Err(ModelError::InvalidData("final terminal generation alias"));
    }
    Ok(ids)
}

fn hash<T: Serialize>(value: &T, max: u64) -> Result<ContentId> {
    Ok(ContentId::hash(&encode_history_record(value, max)?))
}

pub(crate) fn assemble(
    context: &TreeCoordinatorContext<'_>,
    action: &TreeNativeActionLayoutPlan,
    history: &TreeFinalTransactionRows,
    input: TreeFinalTerminalAssembly<'_>,
    max: u64,
) -> Result<TreeFinalTerminalRowsLayout> {
    let completed = action
        .completed_native_layout()
        .ok_or(ModelError::InvalidData(
            "final terminal incomplete action layout",
        ))?;
    if completed.last_recorded_at_ms > input.intended_at_ms
        || input.committed_at_ms < input.intended_at_ms
        || input.committed_at_ms > i64::MAX as u64
        || completed.entries.len() != context.history.manifest().entries.len()
        || completed.retained_originals.len() != context.originals.intents().len()
    {
        return Err(ModelError::InvalidData(
            "final terminal exact action binding",
        ));
    }
    for entry in context.history.manifest().entries.values() {
        if completed
            .entries
            .get(&entry.path)
            .is_none_or(|native| native.entry_id != entry.entry_id || native.kind != entry.kind)
        {
            return Err(ModelError::InvalidData(
                "final terminal logical native binding",
            ));
        }
    }
    let input_references: BTreeMap<_, _> = history
        .input_release
        .iter()
        .map(|r| (r.content_id.clone(), r.length))
        .collect();
    let mut original_handoffs = BTreeMap::new();
    for (&index, original) in context.originals.intents() {
        if completed.retained_originals.get(&index) != Some(&original.original_identity) {
            return Err(ModelError::InvalidData(
                "final terminal retained original binding",
            ));
        }
        original_handoffs.insert(
            index,
            TreeFinalOriginalHandoffLayout {
                original: original.clone(),
                references: context.originals.closures()[&index].clone(),
                retained_component: context.owner.intent().steps[&index]
                    .original_component
                    .clone()
                    .ok_or(ModelError::InvalidData(
                        "final original retained component missing",
                    ))?,
                owner_directory: completed.owner_directory.clone(),
                owner_marker: completed.owner_marker.clone(),
                operation_id: context.execution.intent().steps[index]
                    .new_operation_id
                    .clone(),
                snapshot_id: context.history.snapshot_id().clone(),
                action_layout_hash: action.fingerprint().clone(),
            },
        );
    }
    let intent = TreeFinalTerminalIntentLayout {
        format_version: 1,
        scope: action.scope().clone(),
        finalization_id: input.finalization_id.clone(),
        action_layout_hash: action.fingerprint().clone(),
        action_last_record_hash: completed.last_record_hash.clone(),
        action_record_count: action.record_count(),
        fresh_observation_hash: input.fresh_observation_hash.clone(),
        exact_history_rows_hash: hash(history, max)?,
        final_snapshot_id: context.history.snapshot_id().clone(),
        operation_ids: history.operations.iter().map(|r| r.op_id.clone()).collect(),
        final_native_entries: completed.entries.clone(),
        owner_directory: completed.owner_directory.clone(),
        owner_marker: completed.owner_marker.clone(),
        input_closure_hash: hash(&input_references, max)?,
        input_references,
        original_handoffs_hash: hash(&original_handoffs, max)?,
        original_handoffs,
        intended_at_ms: input.intended_at_ms,
    };
    let committed = TreeFinalCommittedLayout {
        format_version: 1,
        scope: intent.scope.clone(),
        finalization_id: intent.finalization_id.clone(),
        terminal_intent_hash: hash(&intent, max)?,
        action_layout_hash: intent.action_layout_hash.clone(),
        fresh_observation_hash: intent.fresh_observation_hash.clone(),
        exact_history_rows_hash: intent.exact_history_rows_hash.clone(),
        final_snapshot_id: intent.final_snapshot_id.clone(),
        operation_ids: intent.operation_ids.clone(),
        input_closure_hash: intent.input_closure_hash.clone(),
        input_reference_count: intent.input_references.len(),
        original_handoffs_hash: intent.original_handoffs_hash.clone(),
        original_owner_count: intent.original_handoffs.len(),
        committed_at_ms: input.committed_at_ms,
    };
    let committed_hash = hash(&committed, max)?;
    let input_release = TreeFinalInputReleaseLayout {
        format_version: 1,
        scope: intent.scope.clone(),
        finalization_id: intent.finalization_id.clone(),
        committed_record_hash: committed_hash.clone(),
        input_closure_hash: intent.input_closure_hash.clone(),
        released_reference_count: intent.input_references.len(),
        released_at_ms: input.committed_at_ms,
    };
    let retained_owners = intent
        .original_handoffs
        .iter()
        .map(|(&index, handoff)| {
            Ok((
                index,
                TreeFinalRetainedOwnerLayout {
                    format_version: 1,
                    scope: intent.scope.clone(),
                    finalization_id: intent.finalization_id.clone(),
                    committed_record_hash: committed_hash.clone(),
                    step_index: index,
                    step_execution_id: handoff.original.step_execution_id.clone(),
                    handoff_hash: hash(handoff, max)?,
                    handoff: handoff.clone(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(TreeFinalTerminalRowsLayout {
        intent,
        committed,
        input_release,
        retained_owners,
    })
}
