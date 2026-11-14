//! Exact bounded native action descriptions; serialized plans never grant filesystem authority.
use crate::{
    tree_restore_history::encode_history_record,
    tree_restore_identity::{TreeNativeEntry, TreeNativeIdentity},
    webdav_mutation::{plan_webdav_mutation, WebDavMutation, WebDavMutationRequest},
    ContentId, Entry, EntryKind, Manifest, ModelError, PortablePath, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavNativeInventory {
    pub request_hash: ContentId,
    pub root: TreeNativeIdentity,
    pub marker_directory: TreeNativeIdentity,
    pub marker_file: TreeNativeIdentity,
    pub entries: BTreeMap<PortablePath, TreeNativeEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavNativeLimits {
    pub max_bindings: usize,
    pub max_actions: usize,
    pub max_metadata_bytes: u64,
    pub max_staging_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "binding", rename_all = "snake_case")]
pub enum WebDavNativeParent {
    Root,
    Existing {
        path: PortablePath,
        identity: TreeNativeIdentity,
    },
    CreatedBy {
        action: usize,
        path: PortablePath,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "binding", rename_all = "snake_case")]
pub enum WebDavNativeSlot {
    Existing {
        entry: Entry,
        identity: TreeNativeIdentity,
    },
    InitiallyAbsent,
    BelowCreatedParent,
    VacatedBy {
        action: usize,
        entry: Entry,
        identity: TreeNativeIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WebDavNativeAction {
    QuarantineOriginal {
        entry: Entry,
        identity: TreeNativeIdentity,
        owner_component: String,
    },
    CreateDirectory {
        entry: Entry,
    },
    PublishFile {
        entry: Entry,
    },
    CommitHistory {
        final_snapshot: crate::SnapshotId,
        operation_count: usize,
    },
    CleanupOriginal {
        quarantine_action: usize,
        entry: Entry,
        owner_component: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WebDavNativeStep {
    pub index: usize,
    pub action: WebDavNativeAction,
    pub parent: Option<WebDavNativeParent>,
    pub slot: Option<WebDavNativeSlot>,
    pub dependencies: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebDavNativePlan {
    request_hash: ContentId,
    inventory: WebDavNativeInventory,
    steps: Vec<WebDavNativeStep>,
    final_manifest: Manifest,
    operations: Vec<crate::Operation>,
    staging_bytes: u64,
    encoded_bytes: u64,
    fingerprint: ContentId,
}

impl WebDavNativePlan {
    pub fn request_hash(&self) -> &ContentId {
        &self.request_hash
    }
    pub fn inventory(&self) -> &WebDavNativeInventory {
        &self.inventory
    }
    pub fn steps(&self) -> &[WebDavNativeStep] {
        &self.steps
    }
    pub fn final_manifest(&self) -> &Manifest {
        &self.final_manifest
    }
    pub fn operations(&self) -> &[crate::Operation] {
        &self.operations
    }
    pub fn staging_bytes(&self) -> u64 {
        self.staging_bytes
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn native_execution_admitted(&self) -> bool {
        false
    }
    pub fn collection_atomic(&self) -> bool {
        false
    }
}

fn invalid() -> ModelError {
    ModelError::InvalidData("exact native DAV action binding")
}

fn below(path: &PortablePath, root: &PortablePath) -> bool {
    path == root
        || path
            .as_str()
            .strip_prefix(root.as_str())
            .is_some_and(|tail| tail.starts_with('/'))
}

fn parent(
    path: &PortablePath,
    remaining: &BTreeMap<PortablePath, Entry>,
    created: &BTreeMap<PortablePath, usize>,
    inventory: &WebDavNativeInventory,
) -> Result<WebDavNativeParent> {
    match path.parent() {
        None => Ok(WebDavNativeParent::Root),
        Some(path) => {
            if let Some(index) = created.get(&path) {
                return Ok(WebDavNativeParent::CreatedBy {
                    action: *index,
                    path,
                });
            }
            let entry = remaining
                .get(&path)
                .filter(|e| e.kind == EntryKind::Directory)
                .ok_or_else(invalid)?;
            let native = inventory
                .entries
                .get(&path)
                .filter(|n| n.entry_id == entry.entry_id)
                .ok_or_else(invalid)?;
            Ok(WebDavNativeParent::Existing {
                path,
                identity: native.identity.clone(),
            })
        }
    }
}

/// Plan quarantine before overwrite, parent-first publication, one exact causal
/// history commit and post-commit cleanup. Admission must retain actual handles,
/// prove absent slots, reserve complete main liabilities, and privately issue every effect.
pub fn plan_webdav_native(
    baseline: &Manifest,
    request: &WebDavMutationRequest,
    inventory: &WebDavNativeInventory,
    limits: WebDavNativeLimits,
) -> Result<WebDavNativePlan> {
    let logical = plan_webdav_mutation(baseline, request)?;
    if limits.max_actions == 0
        || limits.max_actions > crate::limits::MAX_ENTRIES
        || limits.max_bindings == 0
        || limits.max_bindings > crate::limits::MAX_ENTRIES
        || limits.max_metadata_bytes == 0
        || limits.max_metadata_bytes > crate::tree_restore_history::MAX_TREE_HISTORY_BYTES
        || limits.max_staging_bytes > i64::MAX as u64
        || inventory.request_hash != *logical.request_hash()
        || inventory.entries.len() != baseline.entries.len()
        || inventory
            .entries
            .len()
            .checked_add(3)
            .is_none_or(|n| n > limits.max_bindings)
    {
        return Err(invalid());
    }
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
            return Err(invalid());
        }
    }
    for entry in baseline.entries.values() {
        let native = inventory.entries.get(&entry.path).ok_or_else(invalid)?;
        if native.entry_id != entry.entry_id || native.kind != entry.kind {
            return Err(invalid());
        }
    }
    let parked: Vec<Entry> = match &request.mutation {
        WebDavMutation::Mkcol { .. } => Vec::new(),
        WebDavMutation::Delete { .. } | WebDavMutation::Move { .. } => {
            logical.retained_originals().to_vec()
        }
        WebDavMutation::Copy { destination, .. } => logical
            .retained_originals()
            .iter()
            .filter(|e| below(&e.path, destination))
            .cloned()
            .collect(),
    };
    let mut parked = parked;
    let park_paths: BTreeSet<_> = parked.iter().map(|e| &e.path).collect();
    let publish_count = logical
        .manifest()
        .entries
        .values()
        .filter(|entry| {
            park_paths.contains(&entry.path)
                || baseline.entries.get(&entry.entry_id) != Some(*entry)
        })
        .count();
    let action_count = parked
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(publish_count))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(invalid)?;
    if action_count > limits.max_actions
        || inventory
            .entries
            .len()
            .checked_add(3)
            .and_then(|n| n.checked_add(action_count))
            .is_none_or(|n| n > limits.max_bindings)
    {
        return Err(invalid());
    }
    parked.sort_by(|a, b| {
        b.path
            .as_str()
            .split('/')
            .count()
            .cmp(&a.path.as_str().split('/').count())
            .then_with(|| a.path.cmp(&b.path))
    });
    let mut remaining: BTreeMap<_, _> = baseline
        .entries
        .values()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();
    let mut vacated: BTreeMap<PortablePath, (usize, Entry, TreeNativeIdentity)> = BTreeMap::new();
    let mut created = BTreeMap::new();
    let mut steps = Vec::with_capacity(action_count);
    let mut staging = 0u64;
    for entry in parked {
        let native = &inventory.entries[&entry.path];
        let binding = parent(&entry.path, &remaining, &created, inventory)?;
        let dependencies = if steps.is_empty() {
            Vec::new()
        } else {
            vec![steps.len() - 1]
        };
        if entry.kind == EntryKind::Directory
            && remaining
                .keys()
                .any(|p| p != &entry.path && below(p, &entry.path))
        {
            return Err(invalid());
        }
        staging = staging
            .checked_add(entry.content.as_ref().map_or(0, |c| c.length))
            .filter(|n| *n <= limits.max_staging_bytes)
            .ok_or_else(invalid)?;
        let index = steps.len();
        steps.push(WebDavNativeStep {
            index,
            action: WebDavNativeAction::QuarantineOriginal {
                entry: entry.clone(),
                identity: native.identity.clone(),
                owner_component: format!("dav-{}-{index}.original", request.transaction_id),
            },
            parent: Some(binding),
            slot: Some(WebDavNativeSlot::Existing {
                entry: entry.clone(),
                identity: native.identity.clone(),
            }),
            dependencies,
        });
        remaining.remove(&entry.path);
        vacated.insert(entry.path.clone(), (index, entry, native.identity.clone()));
    }
    let mut desired: Vec<_> = logical
        .manifest()
        .entries
        .values()
        .filter(|e| remaining.get(&e.path) != Some(*e))
        .cloned()
        .collect();
    desired.sort_by(|a, b| {
        a.path
            .as_str()
            .split('/')
            .count()
            .cmp(&b.path.as_str().split('/').count())
            .then_with(|| a.path.cmp(&b.path))
    });
    for entry in desired {
        if remaining.contains_key(&entry.path) {
            return Err(invalid());
        }
        let binding = parent(&entry.path, &remaining, &created, inventory)?;
        let slot = if let Some((action, original, identity)) = vacated.get(&entry.path) {
            WebDavNativeSlot::VacatedBy {
                action: *action,
                entry: original.clone(),
                identity: identity.clone(),
            }
        } else if matches!(binding, WebDavNativeParent::CreatedBy { .. }) {
            WebDavNativeSlot::BelowCreatedParent
        } else {
            WebDavNativeSlot::InitiallyAbsent
        };
        staging = staging
            .checked_add(entry.content.as_ref().map_or(0, |c| c.length))
            .filter(|n| *n <= limits.max_staging_bytes)
            .ok_or_else(invalid)?;
        let index = steps.len();
        let mut dependencies = if index == 0 {
            Vec::new()
        } else {
            vec![index - 1]
        };
        if let WebDavNativeParent::CreatedBy { action, .. } = &binding {
            dependencies.push(*action);
        }
        if let WebDavNativeSlot::VacatedBy { action, .. } = &slot {
            dependencies.push(*action);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        let action = match entry.kind {
            EntryKind::Directory => {
                created.insert(entry.path.clone(), index);
                WebDavNativeAction::CreateDirectory {
                    entry: entry.clone(),
                }
            }
            EntryKind::File => WebDavNativeAction::PublishFile {
                entry: entry.clone(),
            },
        };
        steps.push(WebDavNativeStep {
            index,
            action,
            parent: Some(binding),
            slot: Some(slot),
            dependencies,
        });
        remaining.insert(entry.path.clone(), entry);
    }
    let expected: BTreeMap<_, _> = logical
        .manifest()
        .entries
        .values()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();
    if remaining != expected {
        return Err(invalid());
    }
    let commit = steps.len();
    steps.push(WebDavNativeStep {
        index: commit,
        action: WebDavNativeAction::CommitHistory {
            final_snapshot: logical.manifest().root()?,
            operation_count: logical.operations().len(),
        },
        parent: None,
        slot: None,
        dependencies: if commit == 0 {
            Vec::new()
        } else {
            vec![commit - 1]
        },
    });
    for (quarantine_action, entry, _) in vacated.values() {
        let index = steps.len();
        let mut dependencies = vec![commit, index - 1];
        dependencies.sort_unstable();
        dependencies.dedup();
        steps.push(WebDavNativeStep {
            index,
            action: WebDavNativeAction::CleanupOriginal {
                quarantine_action: *quarantine_action,
                entry: entry.clone(),
                owner_component: format!(
                    "dav-{}-{quarantine_action}.original",
                    request.transaction_id
                ),
            },
            parent: None,
            slot: None,
            dependencies,
        });
    }
    if steps.len() != action_count
        || steps.len() > limits.max_actions
        || inventory
            .entries
            .len()
            .checked_add(3)
            .and_then(|n| n.checked_add(steps.len()))
            .is_none_or(|n| n > limits.max_bindings)
        || staging > limits.max_staging_bytes
    {
        return Err(invalid());
    }
    let bytes = encode_history_record(
        &(
            request,
            inventory,
            &steps,
            logical.manifest(),
            logical.operations(),
            staging,
        ),
        limits.max_metadata_bytes,
    )?;
    Ok(WebDavNativePlan {
        request_hash: logical.request_hash().clone(),
        inventory: inventory.clone(),
        steps,
        final_manifest: logical.manifest().clone(),
        operations: logical.operations().to_vec(),
        staging_bytes: staging,
        encoded_bytes: bytes.len() as u64,
        fingerprint: ContentId::hash(&bytes),
    })
}
