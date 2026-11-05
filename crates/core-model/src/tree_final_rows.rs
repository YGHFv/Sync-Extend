//! Shared exact history values. No descriptive transcript or write authority.
use crate::{
    limits,
    persisted_rename::RenameObservationMap,
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_final_transaction::{
        TreeFinalCurrentWrite, TreeFinalCursorWrite, TreeFinalInputReleaseRow,
        TreeFinalObservationInvalidation, TreeFinalOperationRow, TreeFinalRetainedReferenceRow,
        TreeFinalSnapshotObjectRow, TreeFinalSnapshotRow, TreeFinalTransactionFootprint,
        TreeFinalTransactionLimits, TreeFinalTransactionRows,
    },
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    ContentId, ModelError, Result,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeFinalHistoryRowsPlan {
    rows: TreeFinalTransactionRows,
    footprint: TreeFinalTransactionFootprint,
    fingerprint: ContentId,
}

impl TreeFinalHistoryRowsPlan {
    pub fn rows(&self) -> &TreeFinalTransactionRows {
        &self.rows
    }
    pub fn footprint(&self) -> &TreeFinalTransactionFootprint {
        &self.footprint
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
}

fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |total, n| {
        total
            .checked_add(n)
            .ok_or(ModelError::InvalidData("tree final row byte overflow"))
    })
}

pub(crate) fn project(
    context: &TreeCoordinatorContext<'_>,
    prior_observation: Option<&RenameObservationMap>,
    bounds: TreeFinalTransactionLimits,
) -> Result<TreeFinalHistoryRowsPlan> {
    if bounds.max_reference_rows > limits::MAX_CHUNKS
        || bounds.max_rows > limits::MAX_ENTRIES as u64
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_logical_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("tree final shared row bounds"));
    }
    encode_history_record(
        &(
            context.baseline,
            context.target,
            context.execution.intent(),
            context.history_input,
            context.history.manifest(),
            context.history.operations(),
            context.originals.intents(),
            context.originals.closures(),
            prior_observation,
        ),
        bounds.max_input_bytes,
    )?;
    let id = &context.execution.intent().input.transaction_id;
    let h = context.history;
    let mut inputs = BTreeMap::new();
    for chunk in [context.baseline, context.target]
        .into_iter()
        .flat_map(|m| m.entries.values())
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| &f.chunks)
    {
        if !inputs.contains_key(&chunk.content_id) && inputs.len() >= bounds.max_reference_rows {
            return Err(ModelError::InvalidData(
                "tree final input reference inventory",
            ));
        }
        if inputs
            .insert(chunk.content_id.clone(), chunk.length)
            .is_some_and(|length| length != chunk.length)
        {
            return Err(ModelError::InvalidData("tree final input chunk length"));
        }
    }
    if inputs
        .len()
        .checked_add(context.originals.reference_rows())
        .is_none_or(|n| n > bounds.max_reference_rows)
    {
        return Err(ModelError::InvalidData(
            "tree final combined reference inventory",
        ));
    }
    let operations = h
        .operations()
        .iter()
        .map(|op| {
            let p = &op.payload;
            Ok(TreeFinalOperationRow {
                op_id: op.op_id.clone(),
                space_id: p.space_id.clone(),
                origin_device_id: p.origin_device_id.clone(),
                origin_seq: p.origin_seq,
                payload: String::from_utf8(encode_history_record(op, bounds.max_encoded_bytes)?)
                    .map_err(|_| ModelError::InvalidData("tree final canonical encoding"))?,
                state: "materialized".into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let observation_invalidation = prior_observation
        .map(|map| {
            map.validate(context.baseline, limits::MAX_ENTRIES)?;
            let json = encode_history_record(map, bounds.max_input_bytes)?;
            Ok::<_, ModelError>(TreeFinalObservationInvalidation {
                space_id: map.scope.space_id.clone(),
                snapshot_id: map.scope.prior_snapshot.clone(),
                observation_hash: ContentId::hash(&json),
                observation: String::from_utf8(json)
                    .map_err(|_| ModelError::InvalidData("tree final observation encoding"))?,
            })
        })
        .transpose()?;
    let mut retained_references = Vec::new();
    for (&index, original) in context.originals.intents() {
        for (content, &length) in &context.originals.closures()[&index] {
            retained_references.push(TreeFinalRetainedReferenceRow {
                transaction_id: id.clone(),
                step_index: index,
                step_execution_id: original.step_execution_id.clone(),
                content_id: content.clone(),
                length,
            });
        }
    }
    let rows = TreeFinalTransactionRows {
        operations,
        snapshot: TreeFinalSnapshotRow {
            snapshot_id: h.snapshot_id().clone(),
            space_id: h.manifest().space_id.clone(),
            manifest: String::from_utf8(encode_history_record(
                h.manifest(),
                bounds.max_encoded_bytes,
            )?)
            .map_err(|_| ModelError::InvalidData("tree final snapshot encoding"))?,
            created_at_ms: context.history_input.created_at_ms,
            state: "materialized".into(),
            locked: 0,
        },
        snapshot_objects: h
            .chunks()
            .keys()
            .map(|content| TreeFinalSnapshotObjectRow {
                snapshot_id: h.snapshot_id().clone(),
                content_id: content.clone(),
            })
            .collect(),
        cursor: TreeFinalCursorWrite {
            space_id: h.manifest().space_id.clone(),
            device_id: context.history_input.origin_device_id.clone(),
            prior_seq: context
                .baseline
                .version_vector
                .get(&context.history_input.origin_device_id),
            contiguous_seq: h
                .operations()
                .last()
                .ok_or(ModelError::InvalidData("tree final no NEW operations"))?
                .payload
                .origin_seq,
        },
        current: TreeFinalCurrentWrite {
            space_id: h.manifest().space_id.clone(),
            prior_snapshot_id: context.execution.intent().scope.baseline_snapshot.clone(),
            snapshot_id: h.snapshot_id().clone(),
        },
        input_release: inputs
            .iter()
            .map(|(content, &length)| TreeFinalInputReleaseRow {
                transaction_id: id.clone(),
                content_id: content.clone(),
                length,
            })
            .collect(),
        retained_references,
        observation_invalidation,
    };
    let history_bytes = sum(rows
        .operations
        .iter()
        .map(|r| r.payload.len() as u64 + 180)
        .chain([
            rows.snapshot.manifest.len() as u64 + 124,
            104,
            96,
            rows.snapshot_objects.len() as u64 * 128,
        ]))?;
    let history_rows = rows.operations.len() as u64 + rows.snapshot_objects.len() as u64 + 3;
    if history_bytes != h.footprint().metadata_bytes || history_rows != h.footprint().row_writes {
        return Err(ModelError::InvalidData(
            "tree final exact history footprint",
        ));
    }
    let sql_row_writes = sum([
        history_rows,
        rows.input_release.len() as u64,
        u64::from(rows.observation_invalidation.is_some()),
    ])?;
    let retained_bytes = rows.retained_references.len() as u64 * 144;
    if sql_row_writes > bounds.max_rows
        || sum([history_bytes, retained_bytes])? > bounds.max_logical_bytes
    {
        return Err(ModelError::InvalidData("tree final prospective row budget"));
    }
    let encoded = encode_history_record(&rows, bounds.max_encoded_bytes)?;
    Ok(TreeFinalHistoryRowsPlan {
        fingerprint: ContentId::hash(&encoded),
        footprint: TreeFinalTransactionFootprint {
            history_value_rows: history_rows,
            history_logical_bytes: history_bytes,
            input_release_rows: rows.input_release.len() as u64,
            input_release_logical_bytes: rows.input_release.len() as u64 * 104,
            retained_reference_rows: rows.retained_references.len() as u64,
            retained_reference_logical_bytes: retained_bytes,
            observation_delete_rows: u64::from(rows.observation_invalidation.is_some()),
            observation_delete_logical_bytes: rows
                .observation_invalidation
                .as_ref()
                .map_or(0, |r| r.observation.len() as u64 + 160),
            sql_row_writes,
            encoded_bytes: encoded.len() as u64,
        },
        rows,
    })
}
