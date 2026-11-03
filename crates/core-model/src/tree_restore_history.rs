//! A bounded NEW history projection, never native admission or a final commit.

use crate::{
    limits,
    tree_restore::{TreeRestoreAction, TreeRestorePlan},
    Change, ContentId, DeviceId, EntryId, Manifest, ModelError, Operation, OperationPayload,
    Result, SnapshotId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

pub const MAX_TREE_HISTORY_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreHistoryLimits {
    pub max_operations: usize,
    pub max_entries: usize,
    pub max_tombstones: usize,
    pub max_rows: u64,
    pub max_metadata_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreHistoryInput {
    pub format_version: u32,
    pub origin_device_id: DeviceId,
    pub created_at_ms: u64,
    pub fresh_entry_ids: BTreeMap<usize, EntryId>,
    pub limits: TreeRestoreHistoryLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreHistoryFootprint {
    pub operation_rows: u64,
    pub snapshot_object_rows: u64,
    pub row_writes: u64,
    pub metadata_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeRestoreHistoryPlan {
    manifest: Manifest,
    operations: Vec<Operation>,
    snapshot_id: SnapshotId,
    chunks: BTreeMap<ContentId, u32>,
    footprint: TreeRestoreHistoryFootprint,
    fingerprint: ContentId,
}

impl TreeRestoreHistoryPlan {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
    pub fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }
    pub fn chunks(&self) -> &BTreeMap<ContentId, u32> {
        &self.chunks
    }
    pub fn footprint(&self) -> &TreeRestoreHistoryFootprint {
        &self.footprint
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

/// Canonical JSON with a limit enforced during serialization, before allocation.
pub fn encode_history_record<T: Serialize>(value: &T, max: u64) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        max: u64,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if (self.bytes.len() as u64).saturating_add(bytes.len() as u64) > self.max {
                return Err(io::Error::other("tree history encoded byte limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        max: max.min(MAX_TREE_HISTORY_BYTES),
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(output.bytes)
}

fn charge(total: &mut u64, bytes: u64, max: u64) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= max)
        .ok_or(ModelError::InvalidData("tree history metadata budget"))?;
    Ok(())
}

/// Preserve current identities and causal history; historical IDs are input only.
/// The journal must additionally exclude IDs anywhere in recorded local history.
pub fn plan_tree_restore_history(
    tree: &TreeRestorePlan,
    baseline: &Manifest,
    target: &Manifest,
    input: &TreeRestoreHistoryInput,
) -> Result<TreeRestoreHistoryPlan> {
    let b = input.limits;
    if input.format_version != FORMAT_VERSION
        || input.created_at_ms > i64::MAX as u64
        || b.max_operations == 0
        || b.max_operations > limits::MAX_ENTRIES
        || b.max_entries == 0
        || b.max_entries > limits::MAX_ENTRIES
        || b.max_tombstones > limits::MAX_ENTRIES
        || b.max_rows > limits::MAX_ENTRIES as u64
        || b.max_metadata_bytes > MAX_TREE_HISTORY_BYTES
        || tree.steps().is_empty()
        || tree.steps().len() > b.max_operations
        || tree.steps().len() as u64 + 3 > b.max_rows
        || target.entries.len() > b.max_entries
        || baseline.tombstones.len() > b.max_tombstones
        || input.fresh_entry_ids.len() > tree.steps().len()
        || baseline
            .version_vector
            .0
            .values()
            .any(|n| *n > i64::MAX as u64)
    {
        return Err(ModelError::InvalidData("tree history input budget"));
    }
    if baseline.root()? != tree.scope().baseline_snapshot
        || target.root()? != tree.scope().target_snapshot
        || baseline.space_id != tree.scope().space_id
        || target.space_id != tree.scope().space_id
    {
        return Err(ModelError::InvalidData("tree history scope mismatch"));
    }
    let fresh_steps: BTreeSet<_> = tree
        .steps()
        .iter()
        .filter(|s| {
            matches!(
                s.action,
                TreeRestoreAction::CreateDirectory | TreeRestoreAction::PublishNewFile
            )
        })
        .map(|s| s.index)
        .collect();
    let fresh: BTreeSet<_> = input.fresh_entry_ids.values().collect();
    if input
        .fresh_entry_ids
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != fresh_steps
        || fresh.len() != input.fresh_entry_ids.len()
        || fresh.iter().any(|id| {
            [baseline, target]
                .iter()
                .any(|m| m.entries.contains_key(*id) || m.tombstones.contains_key(*id))
        })
    {
        return Err(ModelError::InvalidData(
            "tree history fresh identity mismatch",
        ));
    }
    let mut manifest = baseline.clone();
    let mut paths: BTreeSet<_> = baseline.entries.values().map(|e| e.path.clone()).collect();
    let mut operations = Vec::new();
    let mut bytes = 0;
    let mut hash = blake3::Hasher::new();
    hash.update(b"SyncExtend tree restore history projection v1\0");
    for step in tree.steps() {
        let change = match step.action {
            TreeRestoreAction::DeleteFile | TreeRestoreAction::RemoveEmptyDirectory => {
                let old = step.baseline_entry.as_ref().ok_or(ModelError::InvalidData(
                    "tree history deletion has no baseline",
                ))?;
                if manifest.entries.remove(&old.entry_id).as_ref() != Some(old)
                    || !paths.remove(&old.path)
                {
                    return Err(ModelError::InvalidData("tree history deletion mismatch"));
                }
                Change::Delete {
                    entry_id: old.entry_id.clone(),
                }
            }
            TreeRestoreAction::ReplaceFile
            | TreeRestoreAction::PublishNewFile
            | TreeRestoreAction::CreateDirectory => {
                let mut entry = step
                    .historical_target_entry
                    .clone()
                    .ok_or(ModelError::InvalidData("tree history missing target entry"))?;
                if let Some(old) = &step.baseline_entry {
                    if manifest.entries.get(&old.entry_id) != Some(old) {
                        return Err(ModelError::InvalidData("tree history replacement mismatch"));
                    }
                    entry.entry_id = old.entry_id.clone();
                } else {
                    entry.entry_id = input.fresh_entry_ids[&step.index].clone();
                    if !paths.insert(entry.path.clone()) {
                        return Err(ModelError::InvalidData("tree history occupied creation"));
                    }
                }
                manifest
                    .entries
                    .insert(entry.entry_id.clone(), entry.clone());
                Change::Put { entry }
            }
        };
        let seq = manifest
            .version_vector
            .get(&input.origin_device_id)
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(ModelError::InvalidData("tree history sequence exhausted"))?;
        let payload = OperationPayload {
            format_version: FORMAT_VERSION,
            space_id: baseline.space_id.clone(),
            origin_device_id: input.origin_device_id.clone(),
            origin_seq: seq,
            causal: manifest.version_vector.clone(),
            change,
            created_at_ms: input.created_at_ms,
        };
        // Operation::new hashes its own serialization; bound that allocation first.
        encode_history_record(&payload, b.max_metadata_bytes.saturating_sub(bytes))?;
        let operation = Operation::new(payload)?;
        let json = encode_history_record(&operation, b.max_metadata_bytes.saturating_sub(bytes))?;
        // IDs, SQL integer and state text duplicated outside the JSON payload.
        charge(&mut bytes, json.len() as u64 + 180, b.max_metadata_bytes)?;
        hash.update(&(json.len() as u64).to_le_bytes());
        hash.update(&json);
        if let Change::Delete { entry_id } = &operation.payload.change {
            manifest
                .tombstones
                .insert(entry_id.clone(), operation.op_id.clone());
        }
        manifest
            .version_vector
            .observe(input.origin_device_id.clone(), seq);
        if manifest.tombstones.len() > b.max_tombstones {
            return Err(ModelError::InvalidData("tree history tombstone budget"));
        }
        operations.push(operation);
    }
    let desired: BTreeMap<_, _> = target
        .entries
        .values()
        .map(|e| (&e.path, (e.kind, &e.content)))
        .collect();
    let actual: BTreeMap<_, _> = manifest
        .entries
        .values()
        .map(|e| (&e.path, (e.kind, &e.content)))
        .collect();
    if actual != desired {
        return Err(ModelError::InvalidData(
            "tree history final portable tree mismatch",
        ));
    }
    manifest.validate()?;
    let json = encode_history_record(&manifest, b.max_metadata_bytes.saturating_sub(bytes))?;
    let snapshot_id = manifest.root()?;
    if snapshot_id == tree.scope().baseline_snapshot || snapshot_id == tree.scope().target_snapshot
    {
        return Err(ModelError::InvalidData(
            "tree history requires a NEW snapshot",
        ));
    }
    let chunks: BTreeMap<_, _> = manifest
        .entries
        .values()
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| &f.chunks)
        .map(|c| (c.content_id.clone(), c.length))
        .collect();
    // NEW snapshot metadata, current pointer, one origin cursor and exact refs.
    charge(
        &mut bytes,
        json.len() as u64 + 324 + chunks.len() as u64 * 128,
        b.max_metadata_bytes,
    )?;
    let footprint = TreeRestoreHistoryFootprint {
        operation_rows: operations.len() as u64,
        snapshot_object_rows: chunks.len() as u64,
        row_writes: operations.len() as u64 + 3 + chunks.len() as u64,
        metadata_bytes: bytes,
    };
    if footprint.row_writes > b.max_rows {
        return Err(ModelError::InvalidData("tree history row budget"));
    }
    hash.update(&(json.len() as u64).to_le_bytes());
    hash.update(&json);
    Ok(TreeRestoreHistoryPlan {
        manifest,
        operations,
        snapshot_id,
        chunks,
        footprint,
        fingerprint: ContentId::from_hasher(&hash),
    })
}
