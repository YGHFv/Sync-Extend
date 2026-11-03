//! Bounded action-specific metadata transcripts; never native evidence/admission.
use crate::{
    limits,
    tree_restore::TreeRestoreAction,
    tree_restore_execution_intent::{TreeExecutionIntentPlan, TreeExecutionStepIntent},
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{
        TreeIdentityPlan, TreeNativeIdentity, TreeNativeInventory, TreeParentBinding,
        TreeSlotBinding,
    },
    ContentId, EntryId, FileManifest, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeExecutionEvent {
    ActionIntended {
        parent: TreeNativeIdentity,
    },
    OriginalMoveIntended {
        original: TreeNativeIdentity,
    },
    OriginalRetained {
        original: TreeNativeIdentity,
    },
    CreatorBound {
        creator: TreeNativeIdentity,
    },
    Materialized {
        creator: TreeNativeIdentity,
        content: FileManifest,
    },
    PublicationIntended {
        published: TreeNativeIdentity,
    },
    EmptyDispositionIntended {
        original: TreeNativeIdentity,
    },
    Terminal {
        native: TreeExecutionTerminal,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeExecutionTerminal {
    DirectoryPublished {
        published: TreeNativeIdentity,
    },
    FilePublished {
        published: TreeNativeIdentity,
    },
    FileReplaced {
        original: TreeNativeIdentity,
        published: TreeNativeIdentity,
    },
    FileRetained {
        original: TreeNativeIdentity,
    },
    EmptyDirectoryAbsent {
        original: TreeNativeIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionRecord {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub step_execution_id: EntryId,
    pub step_index: usize,
    pub record_index: usize,
    pub step_intent_hash: ContentId,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeExecutionEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeExecutionRecordLimits {
    pub max_records: usize,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeExecutionRecordAudit {
    records: BTreeMap<usize, Vec<TreeExecutionRecord>>,
    terminals: BTreeMap<usize, TreeExecutionTerminal>,
    fingerprint: ContentId,
    encoded_bytes: u64,
    record_count: usize,
}
impl TreeExecutionRecordAudit {
    pub fn records(&self) -> &BTreeMap<usize, Vec<TreeExecutionRecord>> {
        &self.records
    }
    pub fn terminals(&self) -> &BTreeMap<usize, TreeExecutionTerminal> {
        &self.terminals
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn record_count(&self) -> usize {
        self.record_count
    }
    pub fn execution_admission_available(&self) -> bool {
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Action,
    Move,
    Retain,
    Creator,
    Materialize,
    Publish,
    Dispose,
    Terminal,
}
fn kinds(action: TreeRestoreAction) -> &'static [Kind] {
    use Kind::*;
    match action {
        TreeRestoreAction::CreateDirectory => &[Action, Creator, Publish, Terminal],
        TreeRestoreAction::PublishNewFile => &[Action, Creator, Materialize, Publish, Terminal],
        TreeRestoreAction::ReplaceFile => &[
            Action,
            Move,
            Retain,
            Creator,
            Materialize,
            Publish,
            Terminal,
        ],
        TreeRestoreAction::DeleteFile => &[Action, Move, Retain, Terminal],
        TreeRestoreAction::RemoveEmptyDirectory => &[Action, Dispose, Terminal],
    }
}
fn kind(event: &TreeExecutionEvent) -> Kind {
    match event {
        TreeExecutionEvent::ActionIntended { .. } => Kind::Action,
        TreeExecutionEvent::OriginalMoveIntended { .. } => Kind::Move,
        TreeExecutionEvent::OriginalRetained { .. } => Kind::Retain,
        TreeExecutionEvent::CreatorBound { .. } => Kind::Creator,
        TreeExecutionEvent::Materialized { .. } => Kind::Materialize,
        TreeExecutionEvent::PublicationIntended { .. } => Kind::Publish,
        TreeExecutionEvent::EmptyDispositionIntended { .. } => Kind::Dispose,
        TreeExecutionEvent::Terminal { .. } => Kind::Terminal,
    }
}

/// Validate descriptive action chains. Hashes and identities supplied here are
/// not proof that native actions occurred, even for a complete transcript.
pub fn audit_tree_execution_records(
    plan: &TreeExecutionIntentPlan,
    identity: &TreeIdentityPlan,
    records: &BTreeMap<usize, Vec<TreeExecutionRecord>>,
    bounds: TreeExecutionRecordLimits,
) -> Result<TreeExecutionRecordAudit> {
    let intent = plan.intent();
    let inventory = identity.inventory();
    if bounds.max_records == 0
        || bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || inventory.transaction_id != intent.input.transaction_id
        || inventory.preparation_hash != intent.input.preparation_hash
        || *identity.fingerprint() != intent.input.native_identity_fingerprint
        || identity.steps().len() != intent.steps.len()
        || identity
            .steps()
            .iter()
            .zip(&intent.steps)
            .any(|(binding, step)| binding != &step.identity_binding)
        || records.len() > intent.steps.len()
    {
        return Err(ModelError::InvalidData("tree record scope or bounds"));
    }
    let record_count = records.values().try_fold(0usize, |total, chain| {
        total
            .checked_add(chain.len())
            .filter(|n| *n <= bounds.max_records)
            .ok_or(ModelError::InvalidData("tree record inventory"))
    })?;
    inventory.root.validate()?;
    inventory.marker_directory.validate()?;
    inventory.marker_file.validate()?;
    let mut identities = BTreeSet::from([
        inventory.root.clone(),
        inventory.marker_directory.clone(),
        inventory.marker_file.clone(),
    ]);
    if inventory.marker_directory.volume_serial != inventory.root.volume_serial
        || inventory.marker_file.volume_serial != inventory.root.volume_serial
    {
        return Err(ModelError::InvalidData("tree record inventory volume"));
    }
    if identities.len() != 3 {
        return Err(ModelError::InvalidData("tree record inventory alias"));
    }
    for entry in inventory.entries.values() {
        entry.identity.validate()?;
        if entry.identity.volume_serial != inventory.root.volume_serial {
            return Err(ModelError::InvalidData("tree record inventory volume"));
        }
        if !identities.insert(entry.identity.clone()) {
            return Err(ModelError::InvalidData("tree record inventory alias"));
        }
    }
    let mut terminals = BTreeMap::new();
    let mut prior_time = intent.input.created_at_ms;
    for (ordinal, (index, chain)) in records.iter().enumerate() {
        if *index != ordinal {
            return Err(ModelError::InvalidData(
                "tree record skipped deterministic step",
            ));
        }
        let step = intent
            .steps
            .get(*index)
            .filter(|s| s.step.index == *index)
            .ok_or(ModelError::InvalidData("tree record step index"))?;
        if chain.is_empty()
            || chain.len() > kinds(step.step.action).len()
            || step
                .step
                .dependencies
                .iter()
                .any(|dependency| !terminals.contains_key(dependency))
        {
            return Err(ModelError::InvalidData(
                "tree record incomplete dependencies",
            ));
        }
        let parent = parent(step, inventory, &terminals)?;
        let original =
            match &step.identity_binding.slot {
                TreeSlotBinding::Existing { entry_id, identity } => {
                    if inventory.entries.get(&step.step.path).is_none_or(|entry| {
                        &entry.entry_id != entry_id || &entry.identity != identity
                    }) {
                        return Err(ModelError::InvalidData("tree record exact existing slot"));
                    }
                    Some(identity)
                }
                TreeSlotBinding::VacatedBy {
                    step_index,
                    original_identity,
                    ..
                } => {
                    match terminals.get(step_index) {
                        Some(TreeExecutionTerminal::FileRetained { original })
                        | Some(TreeExecutionTerminal::EmptyDirectoryAbsent { original })
                            if original == original_identity => {}
                        _ => {
                            return Err(ModelError::InvalidData(
                                "tree record vacated slot dependency",
                            ))
                        }
                    }
                    None
                }
                _ => None,
            };
        let step_hash = ContentId::hash(&encode_history_record(step, MAX_TREE_HISTORY_BYTES)?);
        let mut previous = step_hash.clone();
        let mut creator: Option<TreeNativeIdentity> = None;
        for (position, record) in chain.iter().enumerate() {
            if record.transaction_id != intent.input.transaction_id
                || record.coordinator_execution_id != intent.input.execution_id
                || record.step_execution_id != step.step_execution_id
                || record.step_index != *index
                || record.record_index != position
                || record.step_intent_hash != step_hash
                || record.previous_hash != previous
                || record.recorded_at_ms < prior_time
                || record.recorded_at_ms > i64::MAX as u64
                || kind(&record.event) != kinds(step.step.action)[position]
            {
                return Err(ModelError::InvalidData("tree record exact chain"));
            }
            prior_time = record.recorded_at_ms;
            match &record.event {
                TreeExecutionEvent::ActionIntended { parent: actual } if actual == &parent => {}
                TreeExecutionEvent::OriginalMoveIntended { original: actual }
                | TreeExecutionEvent::OriginalRetained { original: actual }
                | TreeExecutionEvent::EmptyDispositionIntended { original: actual }
                    if Some(actual) == original => {}
                TreeExecutionEvent::CreatorBound { creator: actual } => {
                    actual.validate()?;
                    if actual.volume_serial != inventory.root.volume_serial
                        || !identities.insert(actual.clone())
                    {
                        return Err(ModelError::InvalidData(
                            "tree record creator alias or volume",
                        ));
                    }
                    creator = Some(actual.clone());
                }
                TreeExecutionEvent::Materialized {
                    creator: actual,
                    content,
                } => {
                    content.validate()?;
                    if Some(actual) != creator.as_ref()
                        || step
                            .step
                            .historical_target_entry
                            .as_ref()
                            .and_then(|e| e.content.as_ref())
                            != Some(content)
                    {
                        return Err(ModelError::InvalidData("tree record exact materialization"));
                    }
                }
                TreeExecutionEvent::PublicationIntended { published }
                    if Some(published) == creator.as_ref() => {}
                TreeExecutionEvent::Terminal { native } => {
                    let exact = match (step.step.action, native) {
                        (
                            TreeRestoreAction::CreateDirectory,
                            TreeExecutionTerminal::DirectoryPublished { published },
                        )
                        | (
                            TreeRestoreAction::PublishNewFile,
                            TreeExecutionTerminal::FilePublished { published },
                        ) => Some(published) == creator.as_ref(),
                        (
                            TreeRestoreAction::ReplaceFile,
                            TreeExecutionTerminal::FileReplaced {
                                original: old,
                                published,
                            },
                        ) => Some(old) == original && Some(published) == creator.as_ref(),
                        (
                            TreeRestoreAction::DeleteFile,
                            TreeExecutionTerminal::FileRetained { original: old },
                        )
                        | (
                            TreeRestoreAction::RemoveEmptyDirectory,
                            TreeExecutionTerminal::EmptyDirectoryAbsent { original: old },
                        ) => Some(old) == original,
                        _ => false,
                    };
                    if !exact {
                        return Err(ModelError::InvalidData("tree record exact terminal"));
                    }
                    terminals.insert(*index, native.clone());
                }
                _ => return Err(ModelError::InvalidData("tree record action identity")),
            }
            previous = ContentId::hash(&encode_history_record(record, MAX_TREE_HISTORY_BYTES)?);
        }
        if !terminals.contains_key(index) && records.keys().any(|next| next > index) {
            return Err(ModelError::InvalidData(
                "tree record sequential unfinished step",
            ));
        }
    }
    let encoded = encode_history_record(&(intent, records), bounds.max_encoded_bytes)?;
    Ok(TreeExecutionRecordAudit {
        records: records.clone(),
        terminals,
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
        record_count,
    })
}
fn parent(
    step: &TreeExecutionStepIntent,
    inventory: &TreeNativeInventory,
    terminals: &BTreeMap<usize, TreeExecutionTerminal>,
) -> Result<TreeNativeIdentity> {
    match &step.identity_binding.parent {
        TreeParentBinding::Root => Ok(inventory.root.clone()),
        TreeParentBinding::Existing { path, identity } => {
            if inventory.entries.get(path).is_none_or(|entry| {
                &entry.identity != identity || entry.kind != crate::EntryKind::Directory
            }) {
                return Err(ModelError::InvalidData("tree record exact existing parent"));
            }
            Ok(identity.clone())
        }
        TreeParentBinding::CreatedBy { step_index, .. } => match terminals.get(step_index) {
            Some(TreeExecutionTerminal::DirectoryPublished { published }) => Ok(published.clone()),
            _ => Err(ModelError::InvalidData(
                "tree record created parent terminal",
            )),
        },
    }
}
