//! Exact final handoff descriptions, never native execution or a history commit.
use crate::{
    limits,
    tree_execution_records::{
        audit_tree_execution_records, TreeExecutionRecordAudit, TreeExecutionRecordLimits,
        TreeExecutionTerminal,
    },
    tree_original_reference::{
        plan_tree_original_references, TreeOriginalReferenceIntent, TreeOriginalReferenceLimits,
        TreeOriginalReferencePlan,
    },
    tree_owner_marker::{
        audit_tree_owner_records, plan_tree_owner, TreeOwnerLimits, TreeOwnerPlan,
        TreeOwnerRecordAudit, TreeOwnerRecordLimits,
    },
    tree_restore::TreeRestoreAction,
    tree_restore_execution_intent::TreeExecutionIntentPlan,
    tree_restore_history::{encode_history_record, TreeRestoreHistoryPlan, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{TreeIdentityPlan, TreeNativeEntry, TreeNativeIdentity},
    Change, ContentId, EntryId, EntryKind, ModelError, OperationId, PortablePath, Result,
    SnapshotId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalInput {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub execution_intent_hash: ContentId,
    /// Descriptive until the Journal independently verifies the actual request.
    pub original_request_hash: ContentId,
    pub original_closure_hash: ContentId,
    pub owner_intent_hash: ContentId,
    pub owner_records_hash: ContentId,
    pub step_records_hash: ContentId,
    pub history_projection_hash: ContentId,
    pub described_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRetainedOriginalDescription {
    pub original: TreeOriginalReferenceIntent,
    pub references: BTreeMap<ContentId, u32>,
    pub step_terminal_hash: ContentId,
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub retained_component: String,
    pub final_snapshot_id: SnapshotId,
    pub new_operation_id: OperationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalIntent {
    pub input: TreeFinalInput,
    pub final_snapshot_id: SnapshotId,
    pub new_operation_ids: Vec<OperationId>,
    pub final_native_entries: BTreeMap<PortablePath, TreeNativeEntry>,
    pub step_terminal_hashes: BTreeMap<usize, ContentId>,
    pub retained_originals: BTreeMap<usize, TreeRetainedOriginalDescription>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalLimits {
    pub max_steps: usize,
    pub max_entries: usize,
    pub max_records: usize,
    pub max_reference_rows: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeFinalPlan {
    intent: TreeFinalIntent,
    intent_hash: ContentId,
    encoded_bytes: u64,
    input_encoded_bytes: u64,
    peak_native_entries: usize,
}
impl TreeFinalPlan {
    pub fn intent(&self) -> &TreeFinalIntent {
        &self.intent
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn input_encoded_bytes(&self) -> u64 {
        self.input_encoded_bytes
    }
    pub fn peak_native_entries(&self) -> usize {
        self.peak_native_entries
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
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
    pub fn history_commit_available(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
struct BorrowedOriginal<'a> {
    original: &'a TreeOriginalReferenceIntent,
    references: &'a BTreeMap<ContentId, u32>,
    step_terminal_hash: ContentId,
    owner_directory: &'a TreeNativeIdentity,
    owner_marker: &'a TreeNativeIdentity,
    retained_component: &'a str,
    final_snapshot_id: &'a SnapshotId,
    new_operation_id: &'a OperationId,
}
#[derive(Serialize)]
struct BorrowedNativeEntry<'a> {
    entry_id: &'a EntryId,
    kind: EntryKind,
    identity: &'a TreeNativeIdentity,
}
#[derive(Serialize)]
struct Candidate<'a> {
    input: &'a TreeFinalInput,
    final_snapshot_id: &'a SnapshotId,
    new_operation_ids: Vec<&'a OperationId>,
    final_native_entries: BTreeMap<&'a PortablePath, BorrowedNativeEntry<'a>>,
    step_terminal_hashes: BTreeMap<usize, ContentId>,
    retained_originals: BTreeMap<usize, BorrowedOriginal<'a>>,
}

/// All complete transcripts are descriptive. Actual Journal/native authority is separate.
#[allow(clippy::too_many_arguments)]
pub fn plan_tree_final_description(
    execution: &TreeExecutionIntentPlan,
    identity: &TreeIdentityPlan,
    history: &TreeRestoreHistoryPlan,
    originals: &TreeOriginalReferencePlan,
    owner: &TreeOwnerPlan,
    owner_records: &TreeOwnerRecordAudit,
    steps: &TreeExecutionRecordAudit,
    input: &TreeFinalInput,
    bounds: TreeFinalLimits,
) -> Result<TreeFinalPlan> {
    let e = execution.intent();
    if bounds.max_steps == 0
        || bounds.max_steps > limits::MAX_ENTRIES
        || bounds.max_entries > limits::MAX_ENTRIES
        || bounds.max_records == 0
        || bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || originals.reference_rows() > bounds.max_reference_rows
        || owner_records
            .records()
            .len()
            .saturating_add(steps.record_count())
            > bounds.max_records
        || e.steps.len() > bounds.max_steps
        || history.manifest().entries.len() > bounds.max_entries
        || identity.inventory().entries.len() > bounds.max_entries
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || input.transaction_id != e.input.transaction_id
        || input.coordinator_execution_id != e.input.execution_id
        || input.execution_intent_hash
            != ContentId::hash(&encode_history_record(e, MAX_TREE_HISTORY_BYTES)?)
        || input.original_request_hash != owner.intent().input.original_request_hash
        || input.original_closure_hash != *originals.fingerprint()
        || input.owner_intent_hash != *owner.intent_hash()
        || input.owner_records_hash != *owner_records.fingerprint()
        || input.step_records_hash != *steps.fingerprint()
        || input.history_projection_hash != *history.fingerprint()
        || *history.fingerprint() != e.input.history_projection_hash
        || history.operations().len() != e.steps.len()
        || !owner_records.description_complete()
        || steps.terminals().len() != e.steps.len()
        || input.described_at_ms > i64::MAX as u64
        || input.described_at_ms < owner.intent().input.created_at_ms
    {
        return Err(ModelError::InvalidData(
            "tree final exact description binding",
        ));
    }
    // Bound nested inputs before re-projection and deep output copies.
    let input_encoded_bytes = encode_history_record(
        &(
            e,
            identity.inventory(),
            originals.intents(),
            originals.closures(),
            owner.intent(),
            owner_records.records(),
            steps.records(),
            history.manifest(),
            history.operations(),
        ),
        bounds.max_input_bytes,
    )?
    .len() as u64;
    let exact_originals = plan_tree_original_references(
        execution,
        identity,
        TreeOriginalReferenceLimits {
            max_owners: bounds.max_steps,
            max_chunk_visits: limits::MAX_CHUNKS,
            max_reference_rows: bounds.max_reference_rows,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let exact_owner = plan_tree_owner(
        execution,
        identity,
        &exact_originals,
        &owner.intent().input,
        TreeOwnerLimits {
            max_steps: bounds.max_steps,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let exact_owner_records = audit_tree_owner_records(
        &exact_owner,
        owner_records.records(),
        TreeOwnerRecordLimits {
            max_records: 8,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let exact_steps = audit_tree_execution_records(
        execution,
        identity,
        steps.records(),
        TreeExecutionRecordLimits {
            max_records: bounds.max_records,
            max_encoded_bytes: bounds.max_input_bytes,
        },
    )?;
    let ready_time = owner_records
        .records()
        .last()
        .ok_or(ModelError::InvalidData("tree final owner ready missing"))?
        .recorded_at_ms;
    if &exact_originals != originals
        || &exact_owner != owner
        || &exact_owner_records != owner_records
        || &exact_steps != steps
        || owner_records
            .records()
            .iter()
            .any(|r| r.recorded_at_ms > input.described_at_ms)
        || steps
            .records()
            .values()
            .flatten()
            .any(|r| r.recorded_at_ms > input.described_at_ms || r.recorded_at_ms < ready_time)
    {
        return Err(ModelError::InvalidData(
            "tree final private transcript reproject",
        ));
    }
    let directory = owner_records
        .directory()
        .ok_or(ModelError::InvalidData("tree final owner directory"))?;
    let marker = owner_records
        .marker()
        .ok_or(ModelError::InvalidData("tree final owner marker"))?;
    let mut forbidden = BTreeSet::from([directory, marker]);
    forbidden.insert(&identity.inventory().root);
    forbidden.insert(&identity.inventory().marker_directory);
    forbidden.insert(&identity.inventory().marker_file);
    forbidden.extend(identity.inventory().entries.values().map(|e| &e.identity));
    let mut final_entries: BTreeMap<_, _> = identity
        .inventory()
        .entries
        .iter()
        .map(|(p, e)| {
            (
                p,
                BorrowedNativeEntry {
                    entry_id: &e.entry_id,
                    kind: e.kind,
                    identity: &e.identity,
                },
            )
        })
        .collect();
    let mut peak_native_entries = final_entries.len();
    let mut step_terminal_hashes = BTreeMap::new();
    let mut retained_originals = BTreeMap::new();
    let mut operation_ids = Vec::new();
    for (step, operation) in e.steps.iter().zip(history.operations()) {
        if step.new_operation_id != operation.op_id {
            return Err(ModelError::InvalidData("tree final new operation binding"));
        }
        operation_ids.push(&operation.op_id);
        let terminal = steps
            .terminals()
            .get(&step.step.index)
            .ok_or(ModelError::InvalidData("tree final step terminal missing"))?;
        let last = steps
            .records()
            .get(&step.step.index)
            .and_then(|rs| rs.last())
            .ok_or(ModelError::InvalidData(
                "tree final terminal record missing",
            ))?;
        let terminal_hash = ContentId::hash(&encode_history_record(last, bounds.max_input_bytes)?);
        step_terminal_hashes.insert(step.step.index, terminal_hash.clone());
        let created = match terminal {
            TreeExecutionTerminal::DirectoryPublished { published }
            | TreeExecutionTerminal::FilePublished { published }
            | TreeExecutionTerminal::FileReplaced { published, .. } => Some(published),
            _ => None,
        };
        if let Some(id) = created {
            if !forbidden.insert(id) {
                return Err(ModelError::InvalidData(
                    "tree final creator/owner native alias",
                ));
            }
        }
        match (&step.step.action, terminal) {
            (TreeRestoreAction::DeleteFile, TreeExecutionTerminal::FileRetained { .. })
            | (
                TreeRestoreAction::RemoveEmptyDirectory,
                TreeExecutionTerminal::EmptyDirectoryAbsent { .. },
            ) => {
                let removed =
                    final_entries
                        .remove(&step.step.path)
                        .ok_or(ModelError::InvalidData(
                            "tree final old native entry missing",
                        ))?;
                let original = match terminal {
                    TreeExecutionTerminal::FileRetained { original }
                    | TreeExecutionTerminal::EmptyDirectoryAbsent { original } => original,
                    _ => return Err(ModelError::InvalidData("tree final old terminal")),
                };
                if removed.identity != original
                    || !matches!(&operation.payload.change,
                    Change::Delete {entry_id} if entry_id==removed.entry_id)
                {
                    return Err(ModelError::InvalidData(
                        "tree final exact old logical native entry",
                    ));
                }
            }
            (
                TreeRestoreAction::CreateDirectory,
                TreeExecutionTerminal::DirectoryPublished { published },
            )
            | (
                TreeRestoreAction::PublishNewFile,
                TreeExecutionTerminal::FilePublished { published },
            ) => {
                let Change::Put { entry } = &operation.payload.change else {
                    return Err(ModelError::InvalidData("tree final NEW creation operation"));
                };
                if entry.path != step.step.path
                    || final_entries.len() >= bounds.max_entries
                    || final_entries
                        .insert(
                            &step.step.path,
                            BorrowedNativeEntry {
                                entry_id: &entry.entry_id,
                                kind: entry.kind,
                                identity: published,
                            },
                        )
                        .is_some()
                {
                    return Err(ModelError::InvalidData(
                        "tree final new native entry collision",
                    ));
                }
            }
            (
                TreeRestoreAction::ReplaceFile,
                TreeExecutionTerminal::FileReplaced { published, .. },
            ) => {
                let Change::Put { entry } = &operation.payload.change else {
                    return Err(ModelError::InvalidData(
                        "tree final NEW replacement operation",
                    ));
                };
                let TreeExecutionTerminal::FileReplaced { original, .. } = terminal else {
                    return Err(ModelError::InvalidData("tree final replacement terminal"));
                };
                let prior = final_entries
                    .insert(
                        &step.step.path,
                        BorrowedNativeEntry {
                            entry_id: &entry.entry_id,
                            kind: entry.kind,
                            identity: published,
                        },
                    )
                    .ok_or(ModelError::InvalidData(
                        "tree final replacement old entry missing",
                    ))?;
                if entry.path != step.step.path
                    || prior.entry_id != &entry.entry_id
                    || prior.identity != original
                {
                    return Err(ModelError::InvalidData(
                        "tree final exact replaced original",
                    ));
                }
            }
            _ => {
                return Err(ModelError::InvalidData(
                    "tree final action terminal mismatch",
                ))
            }
        }
        peak_native_entries = peak_native_entries.max(final_entries.len());
        if let Some(original) = originals.intents().get(&step.step.index) {
            let retained = match terminal {
                TreeExecutionTerminal::FileRetained { original }
                | TreeExecutionTerminal::FileReplaced { original, .. } => original,
                _ => return Err(ModelError::InvalidData("tree final original terminal")),
            };
            if retained != &original.original_identity {
                return Err(ModelError::InvalidData(
                    "tree final exact retained original",
                ));
            }
            retained_originals.insert(
                step.step.index,
                BorrowedOriginal {
                    original,
                    references: originals.closures().get(&step.step.index).ok_or(
                        ModelError::InvalidData("tree final original own closure missing"),
                    )?,
                    step_terminal_hash: terminal_hash,
                    owner_directory: directory,
                    owner_marker: marker,
                    retained_component: owner
                        .intent()
                        .steps
                        .get(&step.step.index)
                        .ok_or(ModelError::InvalidData(
                            "tree final original step slots missing",
                        ))?
                        .original_component
                        .as_deref()
                        .ok_or(ModelError::InvalidData(
                            "tree final retained original component",
                        ))?,
                    final_snapshot_id: history.snapshot_id(),
                    new_operation_id: &step.new_operation_id,
                },
            );
        }
    }
    if history.manifest().entries.len() != final_entries.len()
        || retained_originals.len() != originals.intents().len()
        || history.manifest().entries.values().any(|e| {
            final_entries
                .get(&e.path)
                .is_none_or(|n| n.entry_id != &e.entry_id || n.kind != e.kind)
        })
    {
        return Err(ModelError::InvalidData("tree final exact final namespace"));
    }
    let candidate = Candidate {
        input,
        final_snapshot_id: history.snapshot_id(),
        new_operation_ids: operation_ids,
        step_terminal_hashes,
        final_native_entries: final_entries,
        retained_originals,
    };
    // Materialize deep owned output only after the borrowed candidate is bounded.
    let encoded = encode_history_record(&candidate, bounds.max_encoded_bytes)?;
    Ok(TreeFinalPlan {
        intent: serde_json::from_slice(&encoded)?,
        intent_hash: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
        input_encoded_bytes,
        peak_native_entries,
    })
}
