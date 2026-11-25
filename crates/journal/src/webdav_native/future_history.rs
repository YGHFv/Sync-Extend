//! D01/D04 draft: exact future history values projected from the original DAV plan.
//! Bound to real inventory inside the owned admission transaction before enabling effects.
use crate::{
    JournalError, JournalStorageColumnValue as Value, Result, storage_inventory::reader::add,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    Change, ContentId, EntryId, Manifest, Operation, SpaceId, VersionVector,
    tree_restore_history::encode_history_record,
    tree_storage_capacity::TreeStorageCharge,
    webdav_mutation::{WebDavMutation, WebDavMutationRequest},
    webdav_native::WebDavNativePlan,
};

use super::budget_manifest::OriginalMainRow;

type Key = (&'static str, Vec<String>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FutureHistoryRow {
    pub table: String,
    pub primary_key: Vec<String>,
    pub prior: Option<Vec<Value>>,
    pub future: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FutureHistory {
    pub rows: Vec<FutureHistoryRow>,
    pub charge: TreeStorageCharge,
    pub fingerprint: ContentId,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact original DAV future history row contract")
}

fn text(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}

fn bytes(values: &[Value]) -> Result<u64> {
    values.iter().try_fold(0, |total, value| {
        add(
            total,
            match value {
                Value::Null => 0,
                Value::Integer(_) => 8,
                Value::Text(value) => value.len() as u64,
            },
        )
    })
}

fn source_values(row: &OriginalMainRow) -> Vec<Value> {
    row.values.clone()
}

fn as_text(value: &Value) -> Result<&str> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(invalid()),
    }
}

fn as_integer(value: &Value) -> Result<u64> {
    match value {
        Value::Integer(value) if *value <= i64::MAX as u64 => Ok(*value),
        _ => Err(invalid()),
    }
}

fn exact_columns(row: &OriginalMainRow, expected: &[&str]) -> Result<Vec<Value>> {
    if row.column_names.len() != expected.len()
        || row.values.len() != expected.len()
        || row
            .column_names
            .iter()
            .zip(expected)
            .any(|(name, expected)| name != expected)
    {
        return Err(invalid());
    }
    Ok(source_values(row))
}

/// Run only on the full inventory from the same owned admission snapshot.
/// The caller must separately validate the exact schema and all original provenance.
fn audit_original_causal_inputs(
    space: &SpaceId,
    request: &WebDavMutationRequest,
    native: &WebDavNativePlan,
    original: &[OriginalMainRow],
    max_json: u64,
    max_rows: usize,
) -> Result<()> {
    if max_rows == 0
        || max_rows > crate::limits::MAX_ENTRIES
        || original.len() > max_rows
        || max_json == 0
        || max_json > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES
        || ContentId::hash(&encode_history_record(request, max_json)?) != *native.request_hash()
    {
        return Err(invalid());
    }
    let mut unique = BTreeSet::new();
    for row in original {
        if !unique.insert((row.table(), row.primary_key())) {
            return Err(invalid());
        }
    }
    let snapshot = original
        .iter()
        .find(|row| {
            row.table() == "snapshots" && row.primary_key() == [request.baseline.to_string()]
        })
        .ok_or_else(invalid)?;
    let values = exact_columns(
        snapshot,
        &[
            "snapshot_id",
            "space_id",
            "manifest",
            "created_at_ms",
            "state",
            "locked",
        ],
    )?;
    let baseline: Manifest = serde_json::from_str(as_text(&values[2])?)?;
    baseline.validate()?;
    if baseline.space_id != *space
        || baseline.root()? != request.baseline
        || values[0] != text(&request.baseline)
        || values[1] != text(space)
        || as_integer(&values[3])? > request.created_at_ms
        || values[4] != text("materialized")
        || as_integer(&values[5])? > 1
    {
        return Err(invalid());
    }
    let current = original
        .iter()
        .find(|row| row.table() == "current_manifests" && row.primary_key() == [space.to_string()])
        .ok_or_else(invalid)?;
    if exact_columns(current, &["space_id", "snapshot_id"])?
        != vec![text(space), text(&request.baseline)]
    {
        return Err(invalid());
    }
    let mut cursors = VersionVector::default();
    let mut operations = Vec::<Operation>::new();
    let mut fresh: BTreeSet<EntryId> = request.fresh_ids.values().cloned().collect();
    if matches!(&request.mutation, WebDavMutation::Mkcol { .. }) {
        fresh.insert(request.transaction_id.clone());
    }
    let mut observed_pins = BTreeSet::new();
    let mut visits = original.len();
    for row in original {
        match row.table() {
            "receive_cursors" => {
                let values = exact_columns(row, &["space_id", "device_id", "contiguous_seq"])?;
                let device = as_text(&values[1])?.parse()?;
                let sequence = as_integer(&values[2])?;
                if values[0] != text(space)
                    || sequence == 0
                    || cursors.0.insert(device, sequence).is_some()
                {
                    return Err(invalid());
                }
            }
            "operations" => {
                let values = exact_columns(
                    row,
                    &[
                        "op_id",
                        "space_id",
                        "origin_device_id",
                        "origin_seq",
                        "payload",
                        "state",
                    ],
                )?;
                let operation: Operation = serde_json::from_str(as_text(&values[4])?)?;
                operation.validate()?;
                let payload = &operation.payload;
                let id = match &payload.change {
                    Change::Put { entry } => &entry.entry_id,
                    Change::Delete { entry_id } | Change::Rename { entry_id, .. } => entry_id,
                };
                if values[0] != text(&operation.op_id)
                    || values[1] != text(space)
                    || payload.space_id != *space
                    || values[2] != text(&payload.origin_device_id)
                    || as_integer(&values[3])? != payload.origin_seq
                    || values[5] != text("materialized")
                    || payload.created_at_ms > request.created_at_ms
                    || payload.origin_seq > baseline.version_vector.get(&payload.origin_device_id)
                    || !baseline.version_vector.dominates(&payload.causal)
                    || fresh.contains(id)
                {
                    return Err(invalid());
                }
                encode_history_record(&operation, max_json)?;
                operations.push(operation);
            }
            "snapshots" => {
                let values = exact_columns(
                    row,
                    &[
                        "snapshot_id",
                        "space_id",
                        "manifest",
                        "created_at_ms",
                        "state",
                        "locked",
                    ],
                )?;
                let manifest: Manifest = serde_json::from_str(as_text(&values[2])?)?;
                manifest.validate()?;
                if values[0] != text(manifest.root()?)
                    || values[1] != text(space)
                    || manifest.space_id != *space
                    || manifest
                        .entries
                        .keys()
                        .chain(manifest.tombstones.keys())
                        .any(|id| fresh.contains(id))
                {
                    return Err(invalid());
                }
                encode_history_record(&manifest, max_json)?;
                visits = visits
                    .checked_add(manifest.entries.len())
                    .and_then(|count| count.checked_add(manifest.tombstones.len()))
                    .ok_or_else(invalid)?;
                for content in manifest
                    .entries
                    .values()
                    .filter_map(|entry| entry.content.as_ref())
                {
                    visits = visits
                        .checked_add(content.chunks.len())
                        .ok_or_else(invalid)?;
                }
                if visits > max_rows {
                    return Err(invalid());
                }
            }
            "snapshot_objects" => {
                let values = exact_columns(row, &["snapshot_id", "content_id"])?;
                if values[0] == text(&request.baseline) {
                    let id: ContentId = as_text(&values[1])?.parse()?;
                    if !observed_pins.insert(id) {
                        return Err(invalid());
                    }
                }
            }
            _ => {}
        }
    }
    if cursors != baseline.version_vector {
        return Err(invalid());
    }
    let expected_pins: BTreeSet<_> = baseline
        .entries
        .values()
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|content| content.chunks.iter().map(|chunk| chunk.content_id.clone()))
        .collect();
    if observed_pins != expected_pins {
        return Err(invalid());
    }
    operations.sort_by(|left, right| {
        (&left.payload.origin_device_id, left.payload.origin_seq)
            .cmp(&(&right.payload.origin_device_id, right.payload.origin_seq))
    });
    let mut seen = VersionVector::default();
    for operation in &operations {
        let payload = &operation.payload;
        if payload.origin_seq
            != seen
                .get(&payload.origin_device_id)
                .checked_add(1)
                .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        seen.observe(payload.origin_device_id.clone(), payload.origin_seq);
    }
    if seen != baseline.version_vector || native.operations().is_empty() {
        return Err(invalid());
    }
    for operation in native.operations() {
        operation.validate()?;
        let payload = &operation.payload;
        if payload.space_id != *space
            || payload.origin_device_id != request.origin_device
            || payload.created_at_ms != request.created_at_ms
            || payload.causal != seen
            || payload.origin_seq
                != seen
                    .get(&request.origin_device)
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || operations.iter().any(|old| old.op_id == operation.op_id)
        {
            return Err(invalid());
        }
        seen.observe(payload.origin_device_id.clone(), payload.origin_seq);
    }
    native.final_manifest().validate()?;
    if native.final_manifest().space_id != *space || native.final_manifest().version_vector != seen
    {
        return Err(invalid());
    }
    Ok(())
}

/// Do not mutate operation time, IDs, vectors, JSON, entry IDs or tombstones.
/// `commit_time` is sizing input only; the immutable peak is independent of its value.
pub(super) fn plan(
    space: &SpaceId,
    request: &WebDavMutationRequest,
    native: &WebDavNativePlan,
    original: &[OriginalMainRow],
    commit_time: u64,
    max_json: u64,
    max_rows: usize,
) -> Result<FutureHistory> {
    crate::sql_integer(commit_time)?;
    if commit_time < request.created_at_ms {
        return Err(invalid());
    }
    audit_original_causal_inputs(space, request, native, original, max_json, max_rows)?;
    let baseline = &request.baseline;
    if &native.final_manifest().space_id != space {
        return Err(invalid());
    }
    let final_root = native.final_manifest().root()?;
    let mut index = BTreeMap::<Key, &OriginalMainRow>::new();
    for row in original {
        let table = match row.table() {
            "operations" => "operations",
            "receive_cursors" => "receive_cursors",
            "snapshots" => "snapshots",
            "current_manifests" => "current_manifests",
            "snapshot_objects" => "snapshot_objects",
            "rename_observations" => "rename_observations",
            _ => continue,
        };
        if index
            .insert((table, row.primary_key().to_vec()), row)
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut rows = Vec::new();
    let mut keys = BTreeSet::<Key>::new();
    let mut append =
        |table: &'static str, key: Vec<String>, future: Option<Vec<Value>>| -> Result<()> {
            if !keys.insert((table, key.clone())) {
                return Err(invalid());
            }
            let prior = index
                .get(&(table, key.clone()))
                .map(|row| source_values(row));
            rows.push(FutureHistoryRow {
                table: table.to_owned(),
                primary_key: key,
                prior,
                future,
            });
            Ok(())
        };
    let mut cursors = BTreeMap::new();
    for operation in native.operations() {
        operation.validate()?;
        if &operation.payload.space_id != space {
            return Err(invalid());
        }
        let payload = String::from_utf8(encode_history_record(operation, max_json)?)
            .map_err(|_| invalid())?;
        let key = vec![operation.op_id.to_string()];
        if index.contains_key(&("operations", key.clone())) {
            return Err(invalid());
        }
        append(
            "operations",
            key,
            Some(vec![
                text(&operation.op_id),
                text(space),
                text(&operation.payload.origin_device_id),
                Value::Integer(operation.payload.origin_seq),
                text(payload),
                text("materialized"),
            ]),
        )?;
        cursors.insert(
            operation.payload.origin_device_id.to_string(),
            operation.payload.origin_seq,
        );
    }
    for (device, sequence) in cursors {
        append(
            "receive_cursors",
            vec![space.to_string(), device.clone()],
            Some(vec![text(space), text(device), Value::Integer(sequence)]),
        )?;
    }
    let manifest_json =
        String::from_utf8(encode_history_record(native.final_manifest(), max_json)?)
            .map_err(|_| invalid())?;
    let snapshot_key = vec![final_root.to_string()];
    let future_snapshot = if let Some(row) = index.get(&("snapshots", snapshot_key.clone())) {
        let values = source_values(row);
        if values.len() != 6
            || values[0] != text(&final_root)
            || values[1] != text(space)
            || values[2] != text(&manifest_json)
            || !matches!(values[3], Value::Integer(_))
            || values[4] != text("materialized")
            || !matches!(values[5], Value::Integer(0 | 1))
        {
            return Err(invalid());
        }
        // Preserve exact historical creation time and lock on identical snapshot reuse.
        values
    } else {
        vec![
            text(&final_root),
            text(space),
            text(manifest_json),
            Value::Integer(commit_time),
            text("materialized"),
            Value::Integer(0),
        ]
    };
    append("snapshots", snapshot_key, Some(future_snapshot))?;
    let current_key = vec![space.to_string()];
    let current = index
        .get(&("current_manifests", current_key.clone()))
        .ok_or_else(invalid)?;
    if source_values(current) != vec![text(space), text(baseline)] {
        return Err(invalid());
    }
    // Consume the exact deletion before the legacy current-pointer cascade.
    // The AFTER trigger then sees no row and cannot spend another permit.
    if index.contains_key(&("rename_observations", current_key.clone())) {
        append("rename_observations", current_key.clone(), None)?;
    }
    append(
        "current_manifests",
        current_key.clone(),
        Some(vec![text(space), text(&final_root)]),
    )?;
    let chunks: BTreeSet<_> = native
        .final_manifest()
        .entries
        .values()
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|content| content.chunks.iter().map(|chunk| chunk.content_id.clone()))
        .collect();
    for chunk in chunks {
        let key = vec![final_root.to_string(), chunk.to_string()];
        let future = vec![text(&final_root), text(chunk)];
        if index
            .get(&("snapshot_objects", key.clone()))
            .is_some_and(|row| source_values(row) != future)
        {
            return Err(invalid());
        }
        append("snapshot_objects", key, Some(future))?;
    }
    let charge = rows
        .iter()
        .try_fold(TreeStorageCharge::default(), |total, row| {
            // No prior deletion credit before its actual stage. Same-width updates
            // consume no additional inventory, but exact prior values remain bound.
            let prior = row.prior.as_deref().map(bytes).transpose()?.unwrap_or(0);
            let future = row.future.as_deref().map(bytes).transpose()?.unwrap_or(0);
            Ok::<_, JournalError>(TreeStorageCharge {
                rows: add(
                    total.rows,
                    u64::from(row.prior.is_none() && row.future.is_some()),
                )?,
                logical_bytes: add(total.logical_bytes, future.saturating_sub(prior))?,
            })
        })?;
    let fingerprint = ContentId::hash(&encode_history_record(&rows, max_json)?);
    Ok(FutureHistory {
        rows,
        charge,
        fingerprint,
    })
}
