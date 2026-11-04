//! Exact retained-original terminal descriptions, never disposition or pin release.
use crate::{
    limits,
    tree_final_description::{TreeFinalPlan, TreeRetainedOriginalDescription},
    tree_restore::{plan_tree_restore, TreeRestoreLimits},
    tree_restore_execution_intent::TreeExecutionIntentPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::TreeNativeIdentity,
    ContentId, EntryId, Manifest, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDispositionInput {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub final_description_hash: ContentId,
    pub disposition_ids: BTreeMap<usize, EntryId>,
    pub described_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDispositionIntent {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub step_index: usize,
    pub disposition_id: EntryId,
    pub final_description_hash: ContentId,
    pub retained_description_hash: ContentId,
    pub described_at_ms: u64,
    pub retained: TreeRetainedOriginalDescription,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDispositionLimits {
    pub max_owners: usize,
    pub max_encoded_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOriginalDispositionPlan {
    input: TreeOriginalDispositionInput,
    intents: BTreeMap<usize, TreeOriginalDispositionIntent>,
    intent_hashes: BTreeMap<usize, ContentId>,
    fingerprint: ContentId,
    encoded_bytes: u64,
}
impl TreeOriginalDispositionPlan {
    pub fn input(&self) -> &TreeOriginalDispositionInput {
        &self.input
    }
    pub fn intents(&self) -> &BTreeMap<usize, TreeOriginalDispositionIntent> {
        &self.intents
    }
    pub fn intent_hashes(&self) -> &BTreeMap<usize, ContentId> {
        &self.intent_hashes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_disposition_available(&self) -> bool {
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
struct BorrowedIntent<'a> {
    transaction_id: &'a EntryId,
    coordinator_execution_id: &'a EntryId,
    step_index: usize,
    disposition_id: &'a EntryId,
    final_description_hash: &'a ContentId,
    retained_description_hash: ContentId,
    described_at_ms: u64,
    retained: &'a TreeRetainedOriginalDescription,
}

/// A final candidate is descriptive, not independently committed NEW history.
pub fn plan_tree_original_dispositions(
    execution: &TreeExecutionIntentPlan,
    final_plan: &TreeFinalPlan,
    input: &TreeOriginalDispositionInput,
    bounds: TreeOriginalDispositionLimits,
    baseline: &Manifest,
    target: &Manifest,
) -> Result<TreeOriginalDispositionPlan> {
    let final_intent = final_plan.intent();
    let execution = execution.intent();
    if bounds.max_owners > limits::MAX_ENTRIES
        || final_intent.retained_originals.len() > bounds.max_owners
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || input.transaction_id != final_intent.input.transaction_id
        || input.coordinator_execution_id != final_intent.input.coordinator_execution_id
        || input.final_description_hash != *final_plan.intent_hash()
        || input.described_at_ms < final_intent.input.described_at_ms
        || input.described_at_ms > i64::MAX as u64
        || input.disposition_ids.len() != final_intent.retained_originals.len()
        || execution.input.transaction_id != input.transaction_id
        || execution.input.execution_id != input.coordinator_execution_id
        || final_intent.input.execution_intent_hash
            != ContentId::hash(&encode_history_record(execution, MAX_TREE_HISTORY_BYTES)?)
    {
        return Err(ModelError::InvalidData(
            "tree original disposition exact scope",
        ));
    }
    // Caller budgets bound immutable inputs before reprojecting their tree.
    encode_history_record(&(baseline, target), bounds.max_encoded_bytes)?;
    let tree = plan_tree_restore(
        &execution.scope,
        baseline,
        target,
        TreeRestoreLimits {
            max_entries: limits::MAX_ENTRIES,
            max_steps: limits::MAX_ENTRIES,
            max_chunk_visits: limits::MAX_CHUNKS,
            max_target_bytes: u64::MAX,
            max_retained_and_staging_bytes: u64::MAX,
            max_plan_bytes: MAX_TREE_HISTORY_BYTES,
        },
    )?;
    if tree.steps().len() != execution.steps.len()
        || tree
            .steps()
            .iter()
            .zip(&execution.steps)
            .any(|(a, b)| a != &b.step)
    {
        return Err(ModelError::InvalidData(
            "tree original disposition immutable input projection",
        ));
    }
    let mut forbidden = BTreeSet::from([&input.transaction_id, &input.coordinator_execution_id]);
    forbidden.extend(execution.steps.iter().map(|s| &s.step_execution_id));
    forbidden.extend(
        execution
            .steps
            .iter()
            .filter_map(|s| s.step.baseline_entry.as_ref())
            .map(|e| &e.entry_id),
    );
    forbidden.extend(
        execution
            .steps
            .iter()
            .filter_map(|s| s.step.historical_target_entry.as_ref())
            .map(|e| &e.entry_id),
    );
    forbidden.extend(
        final_intent
            .final_native_entries
            .values()
            .map(|e| &e.entry_id),
    );
    forbidden.extend(
        baseline
            .entries
            .keys()
            .chain(baseline.tombstones.keys())
            .chain(target.entries.keys())
            .chain(target.tombstones.keys()),
    );
    let mut borrowed = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for (index, retained) in &final_intent.retained_originals {
        let id = input
            .disposition_ids
            .get(index)
            .ok_or(ModelError::InvalidData(
                "tree original disposition generation missing",
            ))?;
        if !forbidden.insert(id) {
            return Err(ModelError::InvalidData(
                "tree original disposition generation alias",
            ));
        }
        let intent = BorrowedIntent {
            transaction_id: &input.transaction_id,
            coordinator_execution_id: &input.coordinator_execution_id,
            step_index: *index,
            disposition_id: id,
            final_description_hash: &input.final_description_hash,
            retained_description_hash: ContentId::hash(&encode_history_record(
                retained,
                bounds.max_encoded_bytes,
            )?),
            described_at_ms: input.described_at_ms,
            retained,
        };
        hashes.insert(
            *index,
            ContentId::hash(&encode_history_record(&intent, bounds.max_encoded_bytes)?),
        );
        borrowed.insert(*index, intent);
    }
    let encoded = encode_history_record(&(input, &borrowed), bounds.max_encoded_bytes)?;
    let (_, intents): (
        TreeOriginalDispositionInput,
        BTreeMap<usize, TreeOriginalDispositionIntent>,
    ) = serde_json::from_slice(&encoded)?;
    Ok(TreeOriginalDispositionPlan {
        input: input.clone(),
        intents,
        intent_hashes: hashes,
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeOriginalDispositionEvent {
    DispositionIntended { original: TreeNativeIdentity },
    DispositionRequested { original: TreeNativeIdentity },
    HandleClosed { original: TreeNativeIdentity },
    AbsenceDescribed { component: String },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDispositionRecord {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub step_index: usize,
    pub disposition_id: EntryId,
    pub intent_hash: ContentId,
    pub record_index: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeOriginalDispositionEvent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDispositionRecordLimits {
    pub max_records: usize,
    pub max_encoded_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOriginalDispositionRecordAudit {
    records: BTreeMap<usize, Vec<TreeOriginalDispositionRecord>>,
    terminals: BTreeSet<usize>,
    fingerprint: ContentId,
    encoded_bytes: u64,
}
impl TreeOriginalDispositionRecordAudit {
    pub fn records(&self) -> &BTreeMap<usize, Vec<TreeOriginalDispositionRecord>> {
        &self.records
    }
    pub fn terminals(&self) -> &BTreeSet<usize> {
        &self.terminals
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn native_absence_verified(&self) -> bool {
        false
    }
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
    pub fn physical_space_reclaimed(&self) -> bool {
        false
    }
    pub fn remote_backup_complete(&self) -> bool {
        false
    }
}

/// Ordered metadata transcripts never independently certify handle/absence effects.
pub fn audit_tree_original_disposition_records(
    plan: &TreeOriginalDispositionPlan,
    records: &BTreeMap<usize, Vec<TreeOriginalDispositionRecord>>,
    bounds: TreeOriginalDispositionRecordLimits,
) -> Result<TreeOriginalDispositionRecordAudit> {
    let count = records.values().try_fold(0usize, |n, r| {
        n.checked_add(r.len())
            .filter(|n| *n <= bounds.max_records)
            .ok_or(ModelError::InvalidData(
                "tree original disposition record inventory",
            ))
    })?;
    if bounds.max_records > limits::MAX_ENTRIES
        || count > bounds.max_records
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || records.len() > plan.intents.len()
    {
        return Err(ModelError::InvalidData(
            "tree original disposition record bounds",
        ));
    }
    let mut terminals = BTreeSet::new();
    let mut time = plan.input.described_at_ms;
    for ((index, chain), (expected_index, intent)) in records.iter().zip(&plan.intents) {
        if index != expected_index || chain.is_empty() || chain.len() > 4 {
            return Err(ModelError::InvalidData(
                "tree original disposition deterministic owner order",
            ));
        }
        let intent_hash = &plan.intent_hashes[index];
        let mut previous = intent_hash.clone();
        for (position, record) in chain.iter().enumerate() {
            if record.transaction_id != intent.transaction_id
                || record.coordinator_execution_id != intent.coordinator_execution_id
                || record.step_index != *index
                || record.disposition_id != intent.disposition_id
                || record.intent_hash != *intent_hash
                || record.record_index != position
                || record.previous_hash != previous
                || record.recorded_at_ms < time
                || record.recorded_at_ms > i64::MAX as u64
            {
                return Err(ModelError::InvalidData(
                    "tree original disposition exact record chain",
                ));
            }
            let exact = match (&record.event, position) {
                (TreeOriginalDispositionEvent::DispositionIntended { original }, 0)
                | (TreeOriginalDispositionEvent::DispositionRequested { original }, 1)
                | (TreeOriginalDispositionEvent::HandleClosed { original }, 2) => {
                    original == &intent.retained.original.original_identity
                }
                (TreeOriginalDispositionEvent::AbsenceDescribed { component }, 3) => {
                    component == &intent.retained.retained_component
                }
                _ => false,
            };
            if !exact {
                return Err(ModelError::InvalidData(
                    "tree original disposition exact event",
                ));
            }
            previous = ContentId::hash(&encode_history_record(record, MAX_TREE_HISTORY_BYTES)?);
            time = record.recorded_at_ms;
        }
        if chain.len() == 4 {
            terminals.insert(*index);
        } else if records.keys().any(|next| next > index) {
            return Err(ModelError::InvalidData(
                "tree original disposition unfinished predecessor",
            ));
        }
    }
    let encoded = encode_history_record(
        &(&plan.input, &plan.intents, records),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeOriginalDispositionRecordAudit {
        records: records.clone(),
        terminals,
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
    })
}
