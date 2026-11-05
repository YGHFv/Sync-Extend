//! Exact owner cleanup candidates. Shape never proves native absence or release.
use crate::{
    limits,
    tree_final_layout_source::TreeFinalLayoutSource,
    tree_native_action_layout::TreeNativeActionScope,
    tree_original_terminal_layout::{
        plan_tree_original_terminal_layout, release_rows, TreeOriginalTerminalLayoutInput,
        TreeOriginalTerminalLayoutLimits, TreeOriginalTerminalLayoutPlan,
        TreeOriginalTerminalRowsLayout,
    },
    tree_owner_marker::TreeOwnerPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::TreeNativeIdentity,
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerCleanupLayoutInput {
    pub cleanup_id: EntryId,
    pub final_terminal_layout_hash: ContentId,
    pub original_terminal_layout_hash: ContentId,
    pub intended_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerCleanupLayoutLimits {
    pub max_originals: usize,
    pub max_reference_rows: usize,
    pub max_records: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerCleanupOriginalTerminal {
    pub step_execution_id: EntryId,
    pub disposal_id: EntryId,
    pub terminal_hash: ContentId,
    pub released_reference_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerCleanupIntentLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub cleanup_id: EntryId,
    pub owner_intent_hash: ContentId,
    pub committed_record_hash: ContentId,
    pub input_release_hash: ContentId,
    pub original_terminals: BTreeMap<usize, TreeOwnerCleanupOriginalTerminal>,
    pub original_terminals_hash: ContentId,
    pub parent: TreeNativeIdentity,
    pub directory: TreeNativeIdentity,
    pub marker: TreeNativeIdentity,
    pub published_component: String,
    pub marker_component: String,
    pub marker_payload_hash: ContentId,
    pub marker_payload_length: u64,
    pub intended_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeOwnerCleanupEventLayout {
    MarkerDispositionIntended {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
        component: String,
        payload_hash: ContentId,
        payload_length: u64,
    },
    MarkerAbsenceObserved {
        directory: TreeNativeIdentity,
        original_marker: TreeNativeIdentity,
        component: String,
    },
    DirectoryDispositionIntended {
        parent: TreeNativeIdentity,
        directory: TreeNativeIdentity,
        component: String,
    },
    DirectoryAbsenceObserved {
        parent: TreeNativeIdentity,
        original_directory: TreeNativeIdentity,
        component: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOwnerCleanupRecordLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub finalization_id: EntryId,
    pub cleanup_id: EntryId,
    pub intent_hash: ContentId,
    pub record_index: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub event: TreeOwnerCleanupEventLayout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOwnerCleanupLayoutPlan {
    intent: TreeOwnerCleanupIntentLayout,
    intent_hash: ContentId,
    records: Vec<TreeOwnerCleanupRecordLayout>,
    fingerprint: ContentId,
    encoded_bytes: u64,
    input_encoded_bytes: u64,
    next_record_index: Option<usize>,
}

impl TreeOwnerCleanupLayoutPlan {
    pub fn intent(&self) -> &TreeOwnerCleanupIntentLayout {
        &self.intent
    }
    pub fn intent_hash(&self) -> &ContentId {
        &self.intent_hash
    }
    pub fn records(&self) -> &[TreeOwnerCleanupRecordLayout] {
        &self.records
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn input_encoded_bytes(&self) -> u64 {
        self.input_encoded_bytes
    }
    pub fn next_record_index(&self) -> Option<usize> {
        self.next_record_index
    }
    pub fn complete_layout(&self) -> bool {
        self.next_record_index.is_none()
    }
    /// A serialization candidate only; never a durable native event issuer.
    pub fn next_record_candidate(
        &self,
        recorded_at_ms: u64,
        max_encoded_bytes: u64,
    ) -> Result<Option<TreeOwnerCleanupRecordLayout>> {
        if max_encoded_bytes > MAX_TREE_HISTORY_BYTES
            || recorded_at_ms > i64::MAX as u64
            || recorded_at_ms
                < self
                    .records
                    .last()
                    .map_or(self.intent.intended_at_ms, |r| r.recorded_at_ms)
        {
            return Err(ModelError::InvalidData(
                "owner cleanup candidate bounds or time",
            ));
        }
        let Some(index) = self.next_record_index else {
            return Ok(None);
        };
        let previous_hash = match self.records.last() {
            Some(record) => hash(record, max_encoded_bytes)?,
            None => hash(
                &(
                    "sync-extend-tree-owner-cleanup-records-v1",
                    &self.intent_hash,
                ),
                max_encoded_bytes,
            )?,
        };
        let candidate = TreeOwnerCleanupRecordLayout {
            format_version: 1,
            scope: self.intent.scope.clone(),
            finalization_id: self.intent.finalization_id.clone(),
            cleanup_id: self.intent.cleanup_id.clone(),
            intent_hash: self.intent_hash.clone(),
            record_index: index,
            previous_hash,
            recorded_at_ms,
            event: cleanup_event(&self.intent, index)?,
        };
        encode_history_record(&candidate, max_encoded_bytes)?;
        Ok(Some(candidate))
    }
    pub fn native_cleanup_available(&self) -> bool {
        false
    }
    pub fn native_absence_verified(&self) -> bool {
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

fn hash<T: Serialize>(value: &T, max: u64) -> Result<ContentId> {
    Ok(ContentId::hash(&encode_history_record(value, max)?))
}

pub(crate) fn cleanup_event(
    intent: &TreeOwnerCleanupIntentLayout,
    index: usize,
) -> Result<TreeOwnerCleanupEventLayout> {
    use TreeOwnerCleanupEventLayout as E;
    match index {
        0 => Ok(E::MarkerDispositionIntended {
            directory: intent.directory.clone(),
            marker: intent.marker.clone(),
            component: intent.marker_component.clone(),
            payload_hash: intent.marker_payload_hash.clone(),
            payload_length: intent.marker_payload_length,
        }),
        1 => Ok(E::MarkerAbsenceObserved {
            directory: intent.directory.clone(),
            original_marker: intent.marker.clone(),
            component: intent.marker_component.clone(),
        }),
        2 => Ok(E::DirectoryDispositionIntended {
            parent: intent.parent.clone(),
            directory: intent.directory.clone(),
            component: intent.published_component.clone(),
        }),
        3 => Ok(E::DirectoryAbsenceObserved {
            parent: intent.parent.clone(),
            original_directory: intent.directory.clone(),
            component: intent.published_component.clone(),
        }),
        _ => Err(ModelError::InvalidData("owner cleanup excess stage")),
    }
}

/// Every original, including an empty file, must have its own exact terminal.
/// Native adapters must separately inspect marker-only and then empty membership.
#[allow(clippy::too_many_arguments)]
pub fn plan_tree_owner_cleanup_layout(
    owner: &TreeOwnerPlan,
    final_layout: &impl TreeFinalLayoutSource,
    originals: &TreeOriginalTerminalLayoutPlan,
    terminals: &BTreeMap<usize, TreeOriginalTerminalRowsLayout>,
    input: &TreeOwnerCleanupLayoutInput,
    records: &[TreeOwnerCleanupRecordLayout],
    bounds: TreeOwnerCleanupLayoutLimits,
) -> Result<TreeOwnerCleanupLayoutPlan> {
    let f = final_layout.terminal_rows();
    if bounds.max_originals > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_records > 4
        || records.len() > bounds.max_records
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || terminals.len() > bounds.max_originals
        || terminals.len() != originals.intents().len()
        || terminals.len() != f.retained_owners.len()
        || input.final_terminal_layout_hash != *final_layout.layout_fingerprint()
        || input.original_terminal_layout_hash != *originals.fingerprint()
        || input.intended_at_ms < f.input_release.released_at_ms
        || input.intended_at_ms > i64::MAX as u64
        || owner.intent_hash() != final_layout.owner_plan_hash()
        || owner.intent().input.transaction_id != f.intent.scope.transaction_id
        || owner.intent().input.coordinator_execution_id != f.intent.scope.coordinator_execution_id
    {
        return Err(ModelError::InvalidData("owner cleanup scope or bounds"));
    }
    let input_encoded_bytes = encode_history_record(
        &(
            owner.intent(),
            f,
            originals.intents(),
            terminals,
            input,
            records,
        ),
        bounds.max_input_bytes,
    )?
    .len() as u64;
    let original_bounds = TreeOriginalTerminalLayoutLimits {
        max_owners: bounds.max_originals,
        max_reference_rows: bounds.max_reference_rows,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_input_bytes,
    };
    let reprojected = plan_tree_original_terminal_layout(
        final_layout,
        &TreeOriginalTerminalLayoutInput {
            final_terminal_layout_hash: final_layout.layout_fingerprint().clone(),
            disposal_ids: originals
                .intents()
                .iter()
                .map(|(&i, v)| (i, v.disposal_id.clone()))
                .collect(),
            intended_at_ms: originals
                .intents()
                .values()
                .next()
                .map_or(f.committed.committed_at_ms, |i| i.intended_at_ms),
        },
        original_bounds,
    )?;
    if reprojected.intents() != originals.intents() {
        return Err(ModelError::InvalidData("owner cleanup original lineage"));
    }
    let mut generations: BTreeSet<_> = final_layout.generation_inventory().iter().collect();
    generations.extend(originals.intents().values().map(|i| &i.disposal_id));
    if !generations.insert(&input.cleanup_id) {
        return Err(ModelError::InvalidData("owner cleanup generation alias"));
    }
    let mut original_terminals = BTreeMap::new();
    let mut reference_rows = 0usize;
    for (&index, original) in originals.intents() {
        let terminal = terminals.get(&index).ok_or(ModelError::InvalidData(
            "owner cleanup missing original terminal",
        ))?;
        reference_rows = reference_rows
            .checked_add(terminal.release.len())
            .filter(|n| *n <= bounds.max_reference_rows)
            .ok_or(ModelError::InvalidData("owner cleanup reference inventory"))?;
        if release_rows(original, terminal.absence.observed_at_ms, original_bounds)? != *terminal {
            return Err(ModelError::InvalidData(
                "owner cleanup exact original release",
            ));
        }
        if terminal.terminal.released_at_ms > input.intended_at_ms {
            return Err(ModelError::InvalidData(
                "owner cleanup original terminal time",
            ));
        }
        original_terminals.insert(
            index,
            TreeOwnerCleanupOriginalTerminal {
                step_execution_id: original.step_execution_id.clone(),
                disposal_id: original.disposal_id.clone(),
                terminal_hash: hash(&terminal.terminal, bounds.max_input_bytes)?,
                released_reference_count: terminal.terminal.released_reference_count,
            },
        );
    }
    let intent = TreeOwnerCleanupIntentLayout {
        format_version: 1,
        scope: f.intent.scope.clone(),
        finalization_id: f.intent.finalization_id.clone(),
        cleanup_id: input.cleanup_id.clone(),
        owner_intent_hash: owner.intent_hash().clone(),
        committed_record_hash: hash(&f.committed, bounds.max_input_bytes)?,
        input_release_hash: hash(&f.input_release, bounds.max_input_bytes)?,
        original_terminals_hash: hash(&original_terminals, bounds.max_input_bytes)?,
        original_terminals,
        parent: owner.intent().parent.clone(),
        directory: f.intent.owner_directory.clone(),
        marker: f.intent.owner_marker.clone(),
        published_component: owner.intent().published_component.clone(),
        marker_component: owner.intent().marker_component.clone(),
        marker_payload_hash: owner.marker_hash().clone(),
        marker_payload_length: owner.marker_bytes().len() as u64,
        intended_at_ms: input.intended_at_ms,
    };
    let intent_hash = hash(&intent, bounds.max_encoded_bytes)?;
    let mut previous = hash(
        &("sync-extend-tree-owner-cleanup-records-v1", &intent_hash),
        bounds.max_encoded_bytes,
    )?;
    let mut time = intent.intended_at_ms;
    for (index, record) in records.iter().enumerate() {
        if record.format_version != 1
            || record.scope != intent.scope
            || record.finalization_id != intent.finalization_id
            || record.cleanup_id != intent.cleanup_id
            || record.intent_hash != intent_hash
            || record.record_index != index
            || record.previous_hash != previous
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
            || record.event != cleanup_event(&intent, index)?
        {
            return Err(ModelError::InvalidData("owner cleanup exact ordered stage"));
        }
        previous = hash(record, bounds.max_encoded_bytes)?;
        time = record.recorded_at_ms;
    }
    let encoded = encode_history_record(
        &("sync-extend-tree-owner-cleanup-layout-v1", &intent, records),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeOwnerCleanupLayoutPlan {
        intent,
        intent_hash,
        records: records.to_vec(),
        fingerprint: ContentId::hash(&encoded),
        encoded_bytes: encoded.len() as u64,
        input_encoded_bytes,
        next_record_index: (records.len() < 4).then_some(records.len()),
    })
}
