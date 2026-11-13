//! Exact tree future row maxima. Synthetic native candidates never escape sizing.
use crate::{
    limits,
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_final_terminal_layout::TreeFinalTerminalLayoutLimits,
    tree_native_action_layout::{
        plan_tree_native_action_layout, templates, TreeNativeActionLayoutLimits,
        TreeNativeActionLayoutRecord,
    },
    tree_native_attempt_layout::{plan_tree_native_attempt_layout, tree_native_attempt_row_values},
    tree_native_final_layout::{plan_tree_native_final_layout, TreeNativeFinalLayoutInput},
    tree_native_protocol::TreeNativeProtocolPlan,
    tree_original_terminal_layout::{
        plan_tree_original_terminal_layout, release_set, TreeOriginalTerminalLayoutInput,
        TreeOriginalTerminalLayoutLimits,
    },
    tree_owner_cleanup_layout::{
        plan_tree_owner_cleanup_layout, TreeOwnerCleanupLayoutInput, TreeOwnerCleanupLayoutLimits,
    },
    tree_owner_cleanup_values::tree_owner_cleanup_row_values,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_storage_capacity::{TreeStorageCharge, TreeStorageMetadataObligation},
    tree_storage_footprint::{
        tree_final_history_row_values, tree_final_terminal_row_values,
        tree_native_action_row_values, tree_original_terminal_row_values, TreeStorageRowValues,
    },
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeFutureGenerations {
    pub finalization_id: EntryId,
    pub cleanup_id: EntryId,
    pub disposal_ids: BTreeMap<usize, EntryId>,
    pub attempt_ids: BTreeMap<usize, EntryId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeFutureLimits {
    pub max_records: usize,
    pub max_originals: usize,
    pub max_reference_rows: usize,
    pub max_rows: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
    pub max_logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeNativeFuturePlan {
    obligations: Vec<TreeStorageMetadataObligation>,
    exact_new_values: Vec<TreeStorageRowValues>,
    action_count: usize,
    original_count: usize,
    future_charge: TreeStorageCharge,
    new_charge: TreeStorageCharge,
    encoded_bytes: u64,
}
impl TreeNativeFuturePlan {
    pub fn obligations(&self) -> &[TreeStorageMetadataObligation] {
        &self.obligations
    }
    pub fn exact_new_values(&self) -> &[TreeStorageRowValues] {
        &self.exact_new_values
    }
    pub fn action_count(&self) -> usize {
        self.action_count
    }
    pub fn original_count(&self) -> usize {
        self.original_count
    }
    pub fn future_charge(&self) -> TreeStorageCharge {
        self.future_charge
    }
    pub fn new_charge(&self) -> TreeStorageCharge {
        self.new_charge
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn journal_admission_available(&self) -> bool {
        false
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
    pub fn full_capacity_verified(&self) -> bool {
        false
    }
}

fn invalid(message: &'static str) -> ModelError {
    ModelError::InvalidData(message)
}

pub fn plan_tree_native_future_obligations(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    initial: &TreeNativeActionLayoutRecord,
    generations: &TreeNativeFutureGenerations,
    bounds: TreeNativeFutureLimits,
) -> Result<TreeNativeFuturePlan> {
    plan_tree_native_future_obligations_with_observation(
        context,
        protocol,
        initial,
        generations,
        bounds,
        None,
    )
}

pub fn plan_tree_native_future_obligations_with_observation(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    initial: &TreeNativeActionLayoutRecord,
    generations: &TreeNativeFutureGenerations,
    bounds: TreeNativeFutureLimits,
    prior_observation: Option<&crate::persisted_rename::RenameObservationMap>,
) -> Result<TreeNativeFuturePlan> {
    if bounds.max_records > limits::MAX_ENTRIES
        || bounds.max_originals > limits::MAX_ENTRIES
        || bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_rows > limits::MAX_ENTRIES
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_logical_bytes > limits::MAX_ENTRIES as u64 * 1024
        || generations.attempt_ids.len() > bounds.max_records / 2
        || generations.disposal_ids.len() > bounds.max_originals
        || context.originals.reference_rows() > bounds.max_reference_rows
    {
        return Err(invalid("tree future obligation bounds"));
    }
    encode_history_record(
        &(protocol.input(), initial, generations),
        bounds.max_input_bytes,
    )?;
    let action_bounds = TreeNativeActionLayoutLimits {
        max_records: bounds.max_records,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_encoded_bytes,
    };
    let zero = plan_tree_native_action_layout(context, protocol, &[], action_bounds)?;
    let original_count = context.originals.intents().len();
    let expected_rows = zero
        .action_count()
        .checked_mul(3)
        .and_then(|n| n.checked_add(7))
        .and_then(|n| n.checked_add(original_count.checked_mul(4)?))
        .filter(|n| *n <= bounds.max_rows)
        .ok_or(invalid("tree future metadata row limit"))?;
    if initial.record_index != 0
        || initial.action_ordinal != 0
        || initial.scope != *zero.scope()
        || generations.attempt_ids.len() != zero.action_count()
        || original_count > bounds.max_originals
        || generations.disposal_ids.len() != original_count
        || !generations
            .attempt_ids
            .keys()
            .copied()
            .eq(0..zero.action_count())
        || !generations
            .disposal_ids
            .keys()
            .eq(context.originals.intents().keys())
    {
        return Err(invalid("tree future exact generation inventory"));
    }
    let mut ids = crate::tree_final_terminal_rows::generations(
        context,
        zero.scope(),
        &generations.finalization_id,
    )?;
    if !ids.insert(generations.cleanup_id.clone()) {
        return Err(invalid("tree future cleanup generation alias"));
    }
    for id in generations
        .disposal_ids
        .values()
        .chain(generations.attempt_ids.values())
    {
        if !ids.insert(id.clone()) {
            return Err(invalid("tree future generation alias"));
        }
    }
    let (records, action) = templates::records(context, protocol, initial, action_bounds)?;
    let mut future_values = Vec::new();
    let mut future_bytes = 0u64;
    let mut push = |row: TreeStorageRowValues| -> Result<()> {
        future_bytes = future_bytes
            .checked_add(row.logical_bytes())
            .filter(|n| *n <= bounds.max_logical_bytes)
            .ok_or(invalid("tree future aggregate metadata bytes"))?;
        if future_values.len() >= expected_rows {
            return Err(invalid("tree future aggregate metadata rows"));
        }
        future_values.push(row);
        Ok(())
    };
    for record in records.iter().skip(1) {
        push(tree_native_action_row_values(action.layout_hash(), record)?)?;
    }
    // The real admission hash is unknown until its obligations are encoded.
    // Its fixed-width substitute stays inside this private serialization path.
    let capacity_hash_template = ContentId::hash(b"private capacity sizing only");
    for intended in records.iter().step_by(2) {
        let attempt = plan_tree_native_attempt_layout(
            intended,
            action.layout_hash(),
            &capacity_hash_template,
            &generations.attempt_ids[&intended.action_ordinal],
            i64::MAX as u64,
            bounds.max_encoded_bytes,
        )?;
        push(tree_native_attempt_row_values(&attempt)?)?;
    }
    let final_plan = plan_tree_native_final_layout(
        context,
        protocol,
        &records,
        &TreeNativeFinalLayoutInput {
            format_version: 1,
            scope: action.scope().clone(),
            finalization_id: generations.finalization_id.clone(),
            native_action_layout_hash: action.fingerprint().clone(),
            fresh_observation_hash: ContentId::hash(b"private final sizing only"),
            intended_at_ms: i64::MAX as u64,
            committed_at_ms: i64::MAX as u64,
            prior_observation: prior_observation.cloned(),
        },
        TreeFinalTerminalLayoutLimits {
            max_records: bounds.max_records,
            max_reference_rows: bounds.max_reference_rows,
            max_rows: bounds.max_rows as u64,
            max_input_bytes: bounds.max_input_bytes,
            max_encoded_bytes: bounds.max_encoded_bytes,
            max_logical_bytes: bounds.max_logical_bytes.min(MAX_TREE_HISTORY_BYTES),
        },
    )?;
    for row in tree_final_terminal_row_values(&final_plan)? {
        push(row)?;
    }
    let original_bounds = TreeOriginalTerminalLayoutLimits {
        max_owners: bounds.max_originals,
        max_reference_rows: bounds.max_reference_rows,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_encoded_bytes,
    };
    let originals = plan_tree_original_terminal_layout(
        &final_plan,
        &TreeOriginalTerminalLayoutInput {
            final_terminal_layout_hash: final_plan.fingerprint().clone(),
            disposal_ids: generations.disposal_ids.clone(),
            intended_at_ms: i64::MAX as u64,
        },
        original_bounds,
    )?;
    for row in tree_original_terminal_row_values(&originals, i64::MAX as u64, original_bounds)? {
        push(row)?;
    }
    let terminals = release_set(&originals, i64::MAX as u64, original_bounds)?;
    let cleanup_input = TreeOwnerCleanupLayoutInput {
        cleanup_id: generations.cleanup_id.clone(),
        final_terminal_layout_hash: final_plan.fingerprint().clone(),
        original_terminal_layout_hash: originals.fingerprint().clone(),
        intended_at_ms: i64::MAX as u64,
    };
    let cleanup_bounds = TreeOwnerCleanupLayoutLimits {
        max_originals: bounds.max_originals,
        max_reference_rows: bounds.max_reference_rows,
        max_records: 4,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_encoded_bytes,
    };
    let mut cleanup_records = Vec::new();
    let cleanup = loop {
        let layout = plan_tree_owner_cleanup_layout(
            context.owner,
            &final_plan,
            &originals,
            &terminals,
            &cleanup_input,
            &cleanup_records,
            cleanup_bounds,
        )?;
        let Some(record) =
            layout.next_record_candidate(i64::MAX as u64, bounds.max_encoded_bytes)?
        else {
            break layout;
        };
        cleanup_records.push(record);
    };
    for row in tree_owner_cleanup_row_values(&cleanup)? {
        push(row)?;
    }
    let exact_new_values: Vec<_> = tree_final_history_row_values(&final_plan)?
        .into_iter()
        .filter(TreeStorageRowValues::is_new_history)
        .collect();
    let obligations: Vec<_> = future_values
        .iter()
        .map(|row| TreeStorageMetadataObligation {
            key: row.key().clone(),
            max_logical_bytes: row.logical_bytes(),
        })
        .collect();
    let keys: BTreeSet<_> = obligations.iter().map(|o| &o.key).collect();
    if obligations.len() != expected_rows
        || keys.len() != expected_rows
        || expected_rows
            .checked_add(exact_new_values.len())
            .is_none_or(|n| n > bounds.max_rows)
    {
        return Err(invalid("tree future exact row inventory"));
    }
    let charge = |rows: &[TreeStorageRowValues]| -> Result<TreeStorageCharge> {
        let logical_bytes = rows.iter().try_fold(0u64, |sum, row| {
            sum.checked_add(row.logical_bytes())
                .ok_or(invalid("tree future logical byte overflow"))
        })?;
        Ok(TreeStorageCharge {
            rows: rows.len() as u64,
            logical_bytes,
        })
    };
    let future_charge = charge(&future_values)?;
    let new_charge = charge(&exact_new_values)?;
    if future_charge
        .logical_bytes
        .checked_add(new_charge.logical_bytes)
        .is_none_or(|n| n > bounds.max_logical_bytes)
    {
        return Err(invalid("tree future logical byte limit"));
    }
    let encoded = encode_history_record(
        &(generations, &obligations, &exact_new_values),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeNativeFuturePlan {
        obligations,
        exact_new_values,
        action_count: action.action_count(),
        original_count,
        future_charge,
        new_charge,
        encoded_bytes: encoded.len() as u64,
    })
}
