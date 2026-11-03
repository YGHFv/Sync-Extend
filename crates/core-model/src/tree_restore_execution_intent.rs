//! Exact coordinator/step descriptions, never native admission or capacity proof.
use crate::{
    limits,
    tree_restore::{TreeRestoreAction, TreeRestorePlan, TreeRestoreScope, TreeRestoreStep},
    tree_restore_history::{
        encode_history_record, plan_tree_restore_history, TreeRestoreHistoryInput,
        TreeRestoreHistoryPlan, MAX_TREE_HISTORY_BYTES,
    },
    tree_restore_identity::{
        plan_tree_restore_identities, TreeIdentityLimits, TreeIdentityPlan, TreeStepIdentityBinding,
    },
    Change, ContentId, EntryId, Manifest, ModelError, OperationId, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionIntentLimits {
    pub max_steps: usize,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionIntentInput {
    pub transaction_id: EntryId,
    pub preparation_hash: ContentId,
    /// Descriptive references only; the journal must verify actual whole intents.
    pub history_intent_hash: ContentId,
    pub native_intent_hash: ContentId,
    pub history_projection_hash: ContentId,
    pub native_identity_fingerprint: ContentId,
    pub execution_id: EntryId,
    pub step_execution_ids: BTreeMap<usize, EntryId>,
    pub created_at_ms: u64,
    pub limits: TreeExecutionIntentLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionStepIntent {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub step_execution_id: EntryId,
    pub step: TreeRestoreStep,
    pub identity_binding: TreeStepIdentityBinding,
    pub new_operation_id: OperationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionIntent {
    pub input: TreeExecutionIntentInput,
    pub scope: TreeRestoreScope,
    pub steps: Vec<TreeExecutionStepIntent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeExecutionIntentPlan {
    intent: TreeExecutionIntent,
    fingerprint: ContentId,
    encoded_bytes: u64,
}

impl TreeExecutionIntentPlan {
    pub fn intent(&self) -> &TreeExecutionIntent {
        &self.intent
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn durable_coordinator_available(&self) -> bool {
        false
    }
    pub fn native_tree_verified(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// Independently reproject history and identity from immutable manifest inputs.
/// Hash references to journal records remain descriptive until actual row audit.
pub fn plan_tree_execution_intent(
    tree: &TreeRestorePlan,
    baseline: &Manifest,
    target: &Manifest,
    history: &TreeRestoreHistoryPlan,
    history_input: &TreeRestoreHistoryInput,
    identity: &TreeIdentityPlan,
    input: &TreeExecutionIntentInput,
) -> Result<TreeExecutionIntentPlan> {
    let count = tree.steps().len();
    let b = input.limits;
    if count == 0
        || b.max_steps == 0
        || b.max_steps > limits::MAX_ENTRIES
        || count > b.max_steps
        || b.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || input.created_at_ms > i64::MAX as u64
        || input.step_execution_ids.len() != count
        || history.operations().len() != count
        || identity.steps().len() != count
        || identity.inventory().transaction_id != input.transaction_id
        || identity.inventory().preparation_hash != input.preparation_hash
        || *history.fingerprint() != input.history_projection_hash
        || *identity.fingerprint() != input.native_identity_fingerprint
        || history.manifest().space_id != tree.scope().space_id
    {
        return Err(ModelError::InvalidData(
            "tree execution intent scope or budget",
        ));
    }
    let projected = plan_tree_restore_history(tree, baseline, target, history_input)?;
    let rebound = plan_tree_restore_identities(
        tree,
        baseline,
        &input.transaction_id,
        &input.preparation_hash,
        identity.inventory(),
        TreeIdentityLimits {
            max_bindings: limits::MAX_ENTRIES,
            max_metadata_bytes: MAX_TREE_HISTORY_BYTES,
        },
    )?;
    if projected != *history || rebound != *identity {
        return Err(ModelError::InvalidData(
            "tree execution history or identity projection mismatch",
        ));
    }
    let mut ids = BTreeSet::new();
    ids.insert(&input.transaction_id);
    if !ids.insert(&input.execution_id) {
        return Err(ModelError::InvalidData("tree execution generation alias"));
    }
    let logical: BTreeSet<_> = baseline
        .entries
        .keys()
        .chain(baseline.tombstones.keys())
        .chain(target.entries.keys())
        .chain(target.tombstones.keys())
        .chain(history.manifest().entries.keys())
        .chain(history.manifest().tombstones.keys())
        .collect();
    if logical.contains(&input.transaction_id) || logical.contains(&input.execution_id) {
        return Err(ModelError::InvalidData(
            "tree execution generation is logical entry",
        ));
    }
    let mut steps = Vec::new();
    for (step, (binding, op)) in tree
        .steps()
        .iter()
        .zip(identity.steps().iter().zip(history.operations()))
    {
        let id = input
            .step_execution_ids
            .get(&step.index)
            .ok_or(ModelError::InvalidData("tree execution generation missing"))?;
        if !ids.insert(id)
            || logical.contains(id)
            || step.index != steps.len()
            || binding.step_index != step.index
            || binding.path != step.path
            || op.payload.space_id != tree.scope().space_id
            || op.payload.created_at_ms > input.created_at_ms
        {
            return Err(ModelError::InvalidData("tree execution step binding"));
        }
        op.validate()?;
        let matches = match (&step.action, &op.payload.change) {
            (
                TreeRestoreAction::CreateDirectory | TreeRestoreAction::PublishNewFile,
                Change::Put { entry },
            ) => step.historical_target_entry.as_ref().is_some_and(|target| {
                entry.path == step.path
                    && entry.kind == target.kind
                    && entry.content == target.content
                    && entry.entry_id != target.entry_id
            }),
            (TreeRestoreAction::ReplaceFile, Change::Put { entry }) => {
                step.baseline_entry
                    .as_ref()
                    .is_some_and(|old| entry.entry_id == old.entry_id && entry.path == step.path)
                    && step.historical_target_entry.as_ref().is_some_and(|target| {
                        entry.kind == target.kind && entry.content == target.content
                    })
            }
            (
                TreeRestoreAction::DeleteFile | TreeRestoreAction::RemoveEmptyDirectory,
                Change::Delete { entry_id },
            ) => step
                .baseline_entry
                .as_ref()
                .is_some_and(|old| old.entry_id == *entry_id),
            _ => false,
        };
        if !matches {
            return Err(ModelError::InvalidData(
                "tree execution exact NEW operation",
            ));
        }
        steps.push(TreeExecutionStepIntent {
            transaction_id: input.transaction_id.clone(),
            coordinator_execution_id: input.execution_id.clone(),
            step_execution_id: id.clone(),
            step: step.clone(),
            identity_binding: binding.clone(),
            new_operation_id: op.op_id.clone(),
        });
    }
    let intent = TreeExecutionIntent {
        input: input.clone(),
        scope: tree.scope().clone(),
        steps,
    };
    let bytes = encode_history_record(&intent, b.max_encoded_bytes)?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"SyncExtend descriptive tree execution intent v1\0");
    hash.update(&bytes);
    Ok(TreeExecutionIntentPlan {
        intent,
        fingerprint: ContentId::from_hasher(&hash),
        encoded_bytes: bytes.len() as u64,
    })
}
