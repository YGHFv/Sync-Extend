//! Exact identity descriptions and prospective slot bindings, not native proof.
//! A durable adapter must capture and retain real handles before using this plan.

use crate::{
    limits,
    tree_restore::{TreeRestoreAction, TreeRestorePlan},
    tree_restore_history::encode_history_record,
    ContentId, EntryId, EntryKind, Manifest, ModelError, PortablePath, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeIdentity {
    pub volume_serial: u64,
    /// The full 128-bit native file ID, encoded as 32 lowercase hex digits.
    pub file_id: String,
}

impl TreeNativeIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.file_id.len() != 32
            || !self
                .file_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ModelError::InvalidData("tree native identity encoding"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeEntry {
    pub entry_id: EntryId,
    pub kind: EntryKind,
    pub identity: TreeNativeIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeInventory {
    pub transaction_id: EntryId,
    pub preparation_hash: ContentId,
    pub root: TreeNativeIdentity,
    pub marker_directory: TreeNativeIdentity,
    pub marker_file: TreeNativeIdentity,
    pub entries: BTreeMap<PortablePath, TreeNativeEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "binding", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeParentBinding {
    Root,
    Existing {
        path: PortablePath,
        identity: TreeNativeIdentity,
    },
    CreatedBy {
        step_index: usize,
        path: PortablePath,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "binding", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeSlotBinding {
    Existing {
        entry_id: EntryId,
        identity: TreeNativeIdentity,
    },
    InitiallyAbsent,
    /// A child slot does not exist yet; admission must not claim it was probed.
    BelowCreatedParent,
    VacatedBy {
        step_index: usize,
        original_entry_id: EntryId,
        original_identity: TreeNativeIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeStepIdentityBinding {
    pub step_index: usize,
    pub path: PortablePath,
    pub parent: TreeParentBinding,
    pub slot: TreeSlotBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeIdentityLimits {
    pub max_bindings: usize,
    pub max_metadata_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeIdentityPlan {
    inventory: TreeNativeInventory,
    steps: Vec<TreeStepIdentityBinding>,
    encoded_bytes: u64,
    fingerprint: ContentId,
}

impl TreeIdentityPlan {
    pub fn inventory(&self) -> &TreeNativeInventory {
        &self.inventory
    }
    pub fn steps(&self) -> &[TreeStepIdentityBinding] {
        &self.steps
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn native_tree_verified(&self) -> bool {
        false
    }
    pub fn execution_admission_available(&self) -> bool {
        false
    }
}

/// Bind every baseline entry (including unchanged ancestors), not just changes.
/// Future parent/slot identities must be supplied by durable completed steps.
pub fn plan_tree_restore_identities(
    tree: &TreeRestorePlan,
    baseline: &Manifest,
    transaction_id: &EntryId,
    preparation_hash: &ContentId,
    inventory: &TreeNativeInventory,
    bounds: TreeIdentityLimits,
) -> Result<TreeIdentityPlan> {
    let count = inventory
        .entries
        .len()
        .checked_add(tree.steps().len())
        .and_then(|n| n.checked_add(3))
        .ok_or(ModelError::InvalidData("tree identity inventory overflow"))?;
    if bounds.max_bindings == 0
        || bounds.max_bindings > limits::MAX_ENTRIES
        || count > bounds.max_bindings
        || inventory.transaction_id != *transaction_id
        || inventory.preparation_hash != *preparation_hash
        || baseline.space_id != tree.scope().space_id
        || baseline.root()? != tree.scope().baseline_snapshot
        || inventory.entries.len() != baseline.entries.len()
    {
        return Err(ModelError::InvalidData("tree identity scope or budget"));
    }
    baseline.validate()?;
    let mut identities = BTreeSet::new();
    for identity in [
        &inventory.root,
        &inventory.marker_directory,
        &inventory.marker_file,
    ]
    .into_iter()
    .chain(inventory.entries.values().map(|e| &e.identity))
    {
        identity.validate()?;
        if identity.volume_serial != inventory.root.volume_serial || !identities.insert(identity) {
            return Err(ModelError::InvalidData(
                "tree native identity alias or volume",
            ));
        }
    }
    let old: BTreeMap<_, _> = baseline
        .entries
        .values()
        .map(|e| (e.path.clone(), e))
        .collect();
    for (path, entry) in &old {
        let native = inventory
            .entries
            .get(path)
            .ok_or(ModelError::InvalidData("missing tree native entry"))?;
        if native.entry_id != entry.entry_id || native.kind != entry.kind {
            return Err(ModelError::InvalidData("tree native entry mismatch"));
        }
    }
    let mut created = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut steps = Vec::new();
    for step in tree.steps() {
        let parent = match step.path.parent() {
            None => TreeParentBinding::Root,
            Some(path) => {
                if let Some(index) = created.get(&path) {
                    if !step.dependencies.contains(index) {
                        return Err(ModelError::InvalidData("tree created parent dependency"));
                    }
                    TreeParentBinding::CreatedBy {
                        step_index: *index,
                        path,
                    }
                } else {
                    let native = inventory
                        .entries
                        .get(&path)
                        .filter(|e| e.kind == EntryKind::Directory)
                        .ok_or(ModelError::InvalidData("tree existing parent unavailable"))?;
                    if removed.contains_key(&path) {
                        return Err(ModelError::InvalidData("tree existing parent removed"));
                    }
                    TreeParentBinding::Existing {
                        path,
                        identity: native.identity.clone(),
                    }
                }
            }
        };
        let slot = if let Some(entry) = &step.baseline_entry {
            let native = &inventory.entries[&step.path];
            if native.entry_id != entry.entry_id || removed.contains_key(&step.path) {
                return Err(ModelError::InvalidData("tree occupied slot mismatch"));
            }
            TreeSlotBinding::Existing {
                entry_id: native.entry_id.clone(),
                identity: native.identity.clone(),
            }
        } else if let Some(index) = removed.get(&step.path) {
            if !step.dependencies.contains(index) {
                return Err(ModelError::InvalidData("tree vacated slot dependency"));
            }
            let native = &inventory.entries[&step.path];
            TreeSlotBinding::VacatedBy {
                step_index: *index,
                original_entry_id: native.entry_id.clone(),
                original_identity: native.identity.clone(),
            }
        } else if matches!(parent, TreeParentBinding::CreatedBy { .. }) {
            TreeSlotBinding::BelowCreatedParent
        } else {
            if inventory.entries.contains_key(&step.path) {
                return Err(ModelError::InvalidData("tree initial slot occupied"));
            }
            TreeSlotBinding::InitiallyAbsent
        };
        steps.push(TreeStepIdentityBinding {
            step_index: step.index,
            path: step.path.clone(),
            parent,
            slot,
        });
        match step.action {
            TreeRestoreAction::CreateDirectory => {
                created.insert(step.path.clone(), step.index);
            }
            TreeRestoreAction::DeleteFile | TreeRestoreAction::RemoveEmptyDirectory => {
                removed.insert(step.path.clone(), step.index);
            }
            TreeRestoreAction::PublishNewFile | TreeRestoreAction::ReplaceFile => {}
        }
    }
    let bytes = encode_history_record(&(inventory, &steps), bounds.max_metadata_bytes)?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"SyncExtend tree restore identity description v1\0");
    hash.update(&encode_history_record(
        tree.scope(),
        bounds.max_metadata_bytes,
    )?);
    hash.update(&bytes);
    Ok(TreeIdentityPlan {
        inventory: inventory.clone(),
        steps,
        encoded_bytes: bytes.len() as u64,
        fingerprint: ContentId::from_hasher(&hash),
    })
}
