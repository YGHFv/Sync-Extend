//! Exact per-original descriptive closure, not a journal or native ownership proof.
use crate::{
    limits,
    tree_restore::TreeRestoreAction,
    tree_restore_execution_intent::TreeExecutionIntentPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{TreeIdentityPlan, TreeNativeIdentity, TreeSlotBinding},
    ContentId, EntryId, FileManifest, ModelError, PortablePath, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalReferenceIntent {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub step_execution_id: EntryId,
    pub step_index: usize,
    pub step_intent_hash: ContentId,
    pub original_entry_id: EntryId,
    pub original_path: PortablePath,
    pub original_identity: TreeNativeIdentity,
    pub original_content: FileManifest,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalReferenceLimits {
    pub max_owners: usize,
    pub max_chunk_visits: usize,
    pub max_reference_rows: usize,
    pub max_encoded_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOriginalReferencePlan {
    intents: BTreeMap<usize, TreeOriginalReferenceIntent>,
    closures: BTreeMap<usize, BTreeMap<ContentId, u32>>,
    original_logical_bytes: u64,
    reference_rows: usize,
    encoded_bytes: u64,
    fingerprint: ContentId,
}
impl TreeOriginalReferencePlan {
    pub fn intents(&self) -> &BTreeMap<usize, TreeOriginalReferenceIntent> {
        &self.intents
    }
    pub fn closures(&self) -> &BTreeMap<usize, BTreeMap<ContentId, u32>> {
        &self.closures
    }
    pub fn original_logical_bytes(&self) -> u64 {
        self.original_logical_bytes
    }
    pub fn reference_rows(&self) -> usize {
        self.reference_rows
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn original_pin_store_available(&self) -> bool {
        false
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn native_tree_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// Derive a separate closure for every retained original, not a global pin union.
/// Empty originals still own intent records but add no artificial chunk references.
pub fn plan_tree_original_references(
    execution: &TreeExecutionIntentPlan,
    identity: &TreeIdentityPlan,
    bounds: TreeOriginalReferenceLimits,
) -> Result<TreeOriginalReferencePlan> {
    let input = &execution.intent().input;
    if bounds.max_owners == 0
        || bounds.max_owners > limits::MAX_ENTRIES
        || bounds.max_chunk_visits > limits::MAX_CHUNKS
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || *identity.fingerprint() != input.native_identity_fingerprint
        || identity.inventory().transaction_id != input.transaction_id
        || identity.inventory().preparation_hash != input.preparation_hash
        || identity.steps().len() != execution.intent().steps.len()
        || identity
            .steps()
            .iter()
            .zip(&execution.intent().steps)
            .any(|(a, b)| a != &b.identity_binding)
    {
        return Err(ModelError::InvalidData(
            "tree original closure scope or limits",
        ));
    }
    let mut intents = BTreeMap::new();
    let mut closures = BTreeMap::new();
    let mut rows = 0usize;
    let mut visits = 0usize;
    let mut bytes = 0u64;
    let mut lengths = BTreeMap::new();
    for step in &execution.intent().steps {
        if !matches!(
            step.step.action,
            TreeRestoreAction::DeleteFile | TreeRestoreAction::ReplaceFile
        ) {
            continue;
        }
        if intents.len() >= bounds.max_owners {
            return Err(ModelError::InvalidData("tree original owner inventory"));
        }
        let original = step
            .step
            .baseline_entry
            .as_ref()
            .ok_or(ModelError::InvalidData("tree original baseline missing"))?;
        let content = original.content.as_ref().ok_or(ModelError::InvalidData(
            "tree original file content missing",
        ))?;
        let native = match &step.identity_binding.slot {
            TreeSlotBinding::Existing { entry_id, identity } if entry_id == &original.entry_id => {
                identity
            }
            _ => return Err(ModelError::InvalidData("tree original slot binding")),
        };
        let actual = identity
            .inventory()
            .entries
            .get(&original.path)
            .ok_or(ModelError::InvalidData("tree original native missing"))?;
        if actual.entry_id != original.entry_id
            || actual.identity != *native
            || actual.kind != crate::EntryKind::File
        {
            return Err(ModelError::InvalidData("tree original native mismatch"));
        }
        visits = visits
            .checked_add(content.chunks.len())
            .filter(|n| *n <= bounds.max_chunk_visits)
            .ok_or(ModelError::InvalidData("tree original chunk visits"))?;
        content.validate()?;
        bytes = bytes
            .checked_add(content.length)
            .ok_or(ModelError::InvalidData("tree original logical bytes"))?;
        let mut closure = BTreeMap::new();
        for chunk in &content.chunks {
            if lengths
                .insert(chunk.content_id.clone(), chunk.length)
                .is_some_and(|old| old != chunk.length)
            {
                return Err(ModelError::InvalidData(
                    "tree original conflicting chunk length",
                ));
            }
            if !closure.contains_key(&chunk.content_id) {
                rows = rows
                    .checked_add(1)
                    .filter(|n| *n <= bounds.max_reference_rows)
                    .ok_or(ModelError::InvalidData("tree original reference rows"))?;
                closure.insert(chunk.content_id.clone(), chunk.length);
            }
        }
        let intent = TreeOriginalReferenceIntent {
            transaction_id: input.transaction_id.clone(),
            coordinator_execution_id: input.execution_id.clone(),
            step_execution_id: step.step_execution_id.clone(),
            step_index: step.step.index,
            step_intent_hash: ContentId::hash(&encode_history_record(
                step,
                MAX_TREE_HISTORY_BYTES,
            )?),
            original_entry_id: original.entry_id.clone(),
            original_path: original.path.clone(),
            original_identity: native.clone(),
            original_content: content.clone(),
        };
        intents.insert(step.step.index, intent);
        closures.insert(step.step.index, closure);
    }
    let encoded = encode_history_record(
        &(execution.intent(), &intents, &closures),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeOriginalReferencePlan {
        intents,
        closures,
        original_logical_bytes: bytes,
        reference_rows: rows,
        encoded_bytes: encoded.len() as u64,
        fingerprint: ContentId::hash(&encoded),
    })
}
