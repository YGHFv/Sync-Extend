//! Exact original absence/release candidates, never real disposal or NEW proof.
use crate::{
    limits,
    tree_final_layout_source::TreeFinalLayoutSource,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::TreeNativeIdentity,
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalTerminalLayoutInput {
    pub final_terminal_layout_hash: ContentId,
    pub disposal_ids: BTreeMap<usize, EntryId>,
    pub intended_at_ms: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalTerminalLayoutLimits {
    pub max_owners: usize,
    pub max_reference_rows: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalDisposalIntentLayout {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub finalization_id: EntryId,
    pub committed_record_hash: ContentId,
    pub step_index: usize,
    pub step_execution_id: EntryId,
    pub disposal_id: EntryId,
    pub retained_owner_hash: ContentId,
    pub handoff_hash: ContentId,
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub retained_component: String,
    pub original_identity: TreeNativeIdentity,
    pub content_hash: ContentId,
    pub content_length: u64,
    pub references: BTreeMap<ContentId, u32>,
    pub reference_closure_hash: ContentId,
    pub intended_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalAbsenceLayout {
    pub format_version: u32,
    pub disposal_id: EntryId,
    pub intent_hash: ContentId,
    pub committed_record_hash: ContentId,
    pub original_identity: TreeNativeIdentity,
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub retained_component: String,
    pub observed_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalReleasedReferenceLayout {
    pub transaction_id: EntryId,
    pub step_index: usize,
    pub step_execution_id: EntryId,
    pub content_id: ContentId,
    pub length: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalReleaseTerminalLayout {
    pub format_version: u32,
    pub disposal_id: EntryId,
    pub intent_hash: ContentId,
    pub absence_hash: ContentId,
    pub committed_record_hash: ContentId,
    pub retained_owner_hash: ContentId,
    pub reference_closure_hash: ContentId,
    pub released_reference_count: usize,
    pub released_at_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalTerminalRowsLayout {
    pub absence: TreeOriginalAbsenceLayout,
    pub terminal: TreeOriginalReleaseTerminalLayout,
    pub release: Vec<TreeOriginalReleasedReferenceLayout>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOriginalTerminalLayoutPlan {
    intents: BTreeMap<usize, TreeOriginalDisposalIntentLayout>,
    fingerprint: ContentId,
    encoded_bytes: u64,
    peak_encoded_bytes: u64,
}
impl TreeOriginalTerminalLayoutPlan {
    pub fn intents(&self) -> &BTreeMap<usize, TreeOriginalDisposalIntentLayout> {
        &self.intents
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
    pub fn native_disposition_available(&self) -> bool {
        false
    }
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
    pub fn authenticated_handoff_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// This binds only final row candidates. Real Journal final NEW/action evidence
/// and fresh private absence inspection remain mandatory outside the shape model.
pub fn plan_tree_original_terminal_layout(
    final_layout: &impl TreeFinalLayoutSource,
    input: &TreeOriginalTerminalLayoutInput,
    bounds: TreeOriginalTerminalLayoutLimits,
) -> Result<TreeOriginalTerminalLayoutPlan> {
    let final_rows = final_layout.terminal_rows();
    if bounds.max_owners > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || final_rows.retained_owners.len() > bounds.max_owners
        || input.final_terminal_layout_hash != *final_layout.layout_fingerprint()
        || input.disposal_ids.len() != final_rows.retained_owners.len()
        || input.intended_at_ms < final_rows.committed.committed_at_ms
        || input.intended_at_ms > i64::MAX as u64
    {
        return Err(ModelError::InvalidData(
            "original terminal layout exact scope bounds or time",
        ));
    }
    encode_history_record(&(final_rows, input), bounds.max_input_bytes)?;
    let borrowed_bytes = encode_history_record(
        &(input, &final_rows.retained_owners),
        bounds.max_encoded_bytes,
    )?;
    let scope = &final_rows.intent.scope;
    let mut forbidden = BTreeSet::from([
        &scope.transaction_id,
        &scope.coordinator_execution_id,
        &scope.admission_id,
        &final_rows.intent.finalization_id,
    ]);
    forbidden.extend(final_layout.generation_inventory());
    forbidden.extend(
        final_layout
            .history_rows()
            .retained_references
            .iter()
            .map(|r| &r.step_execution_id),
    );
    forbidden.extend(
        final_rows
            .intent
            .final_native_entries
            .values()
            .map(|e| &e.entry_id),
    );
    forbidden.extend(
        final_rows
            .intent
            .original_handoffs
            .values()
            .flat_map(|h| [&h.original.step_execution_id, &h.original.original_entry_id]),
    );
    let mut count = 0usize;
    let mut intents = BTreeMap::new();
    for (&index, owner) in &final_rows.retained_owners {
        let disposal_id = input
            .disposal_ids
            .get(&index)
            .ok_or(ModelError::InvalidData(
                "original disposal owner key missing",
            ))?;
        if !forbidden.insert(disposal_id) {
            return Err(ModelError::InvalidData(
                "original disposal generation alias",
            ));
        }
        count = count
            .checked_add(owner.handoff.references.len())
            .filter(|n| *n <= bounds.max_reference_rows)
            .ok_or(ModelError::InvalidData(
                "original terminal own reference inventory",
            ))?;
        let handoff = &owner.handoff;
        intents.insert(
            index,
            TreeOriginalDisposalIntentLayout {
                format_version: 1,
                transaction_id: scope.transaction_id.clone(),
                coordinator_execution_id: scope.coordinator_execution_id.clone(),
                admission_id: scope.admission_id.clone(),
                finalization_id: owner.finalization_id.clone(),
                committed_record_hash: owner.committed_record_hash.clone(),
                step_index: index,
                step_execution_id: owner.step_execution_id.clone(),
                disposal_id: disposal_id.clone(),
                retained_owner_hash: ContentId::hash(&encode_history_record(
                    owner,
                    bounds.max_encoded_bytes,
                )?),
                handoff_hash: owner.handoff_hash.clone(),
                owner_directory: handoff.owner_directory.clone(),
                owner_marker: handoff.owner_marker.clone(),
                retained_component: handoff.retained_component.clone(),
                original_identity: handoff.original.original_identity.clone(),
                content_hash: handoff.original.original_content.content_id.clone(),
                content_length: handoff.original.original_content.length,
                references: handoff.references.clone(),
                reference_closure_hash: ContentId::hash(&encode_history_record(
                    &handoff.references,
                    bounds.max_encoded_bytes,
                )?),
                intended_at_ms: input.intended_at_ms,
            },
        );
    }
    let bytes = encode_history_record(&intents, bounds.max_encoded_bytes)?;
    Ok(TreeOriginalTerminalLayoutPlan {
        intents,
        fingerprint: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
        peak_encoded_bytes: (bytes.len() as u64).max(borrowed_bytes.len() as u64),
    })
}

/// Proposed absence shape is not actual absence. No public boolean or remote
/// receipt can turn this pure layout into native release or authenticated proof.
pub fn plan_tree_original_release_layout(
    plan: &TreeOriginalTerminalLayoutPlan,
    step_index: usize,
    observed_at_ms: u64,
    bounds: TreeOriginalTerminalLayoutLimits,
) -> Result<TreeOriginalTerminalRowsLayout> {
    let intent = plan
        .intents
        .get(&step_index)
        .ok_or(ModelError::InvalidData("original release owner missing"))?;
    if observed_at_ms < intent.intended_at_ms
        || observed_at_ms > i64::MAX as u64
        || bounds.max_owners > limits::MAX_ENTRIES
        || plan.intents.len() > bounds.max_owners
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || intent.references.len() > bounds.max_reference_rows
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData(
            "original release layout bounds or time",
        ));
    }
    encode_history_record(
        &(plan.intents(), step_index, observed_at_ms),
        bounds.max_input_bytes,
    )?;
    release_rows(intent, observed_at_ms, bounds)
}

// A caller with an already bounded, reprojected owner set need not encode that
// entire set again for every terminal in a cleanup closure.
pub(crate) fn release_rows(
    intent: &TreeOriginalDisposalIntentLayout,
    observed_at_ms: u64,
    bounds: TreeOriginalTerminalLayoutLimits,
) -> Result<TreeOriginalTerminalRowsLayout> {
    if observed_at_ms < intent.intended_at_ms
        || observed_at_ms > i64::MAX as u64
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || intent.references.len() > bounds.max_reference_rows
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData(
            "original release single owner bounds or time",
        ));
    }
    encode_history_record(intent, bounds.max_input_bytes)?;
    let intent_hash = ContentId::hash(&encode_history_record(intent, bounds.max_encoded_bytes)?);
    let absence = TreeOriginalAbsenceLayout {
        format_version: 1,
        disposal_id: intent.disposal_id.clone(),
        intent_hash: intent_hash.clone(),
        committed_record_hash: intent.committed_record_hash.clone(),
        original_identity: intent.original_identity.clone(),
        owner_directory: intent.owner_directory.clone(),
        owner_marker: intent.owner_marker.clone(),
        retained_component: intent.retained_component.clone(),
        observed_at_ms,
    };
    let terminal = TreeOriginalReleaseTerminalLayout {
        format_version: 1,
        disposal_id: intent.disposal_id.clone(),
        intent_hash,
        absence_hash: ContentId::hash(&encode_history_record(&absence, bounds.max_encoded_bytes)?),
        committed_record_hash: intent.committed_record_hash.clone(),
        retained_owner_hash: intent.retained_owner_hash.clone(),
        reference_closure_hash: intent.reference_closure_hash.clone(),
        released_reference_count: intent.references.len(),
        released_at_ms: observed_at_ms,
    };
    let release = intent
        .references
        .iter()
        .map(
            |(content_id, &length)| TreeOriginalReleasedReferenceLayout {
                transaction_id: intent.transaction_id.clone(),
                step_index: intent.step_index,
                step_execution_id: intent.step_execution_id.clone(),
                content_id: content_id.clone(),
                length,
            },
        )
        .collect();
    let result = TreeOriginalTerminalRowsLayout {
        absence,
        terminal,
        release,
    };
    encode_history_record(&result, bounds.max_encoded_bytes)?;
    Ok(result)
}

pub fn audit_tree_original_release_layout(
    plan: &TreeOriginalTerminalLayoutPlan,
    step_index: usize,
    observed_at_ms: u64,
    rows: &TreeOriginalTerminalRowsLayout,
    bounds: TreeOriginalTerminalLayoutLimits,
) -> Result<()> {
    encode_history_record(rows, bounds.max_input_bytes)?;
    if plan_tree_original_release_layout(plan, step_index, observed_at_ms, bounds)? != *rows {
        return Err(ModelError::InvalidData(
            "original release exact row candidate mismatch",
        ));
    }
    Ok(())
}
