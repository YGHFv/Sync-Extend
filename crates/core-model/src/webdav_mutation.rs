//! Bounded DAV metadata planning. Native execution requires a separate retained owner.
use crate::{
    Change, ContentId, DeviceId, Entry, EntryId, EntryKind, Manifest, ModelError, Operation,
    OperationPayload, PortablePath, Result, SnapshotId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebDavMutation {
    Mkcol {
        destination: PortablePath,
    },
    Delete {
        source: PortablePath,
    },
    Move {
        source: PortablePath,
        destination: PortablePath,
        overwrite: bool,
    },
    Copy {
        source: PortablePath,
        destination: PortablePath,
        overwrite: bool,
        recursive: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavMutationRequest {
    pub transaction_id: EntryId,
    pub baseline: SnapshotId,
    pub export_subtree: Option<PortablePath>,
    pub mutation: WebDavMutation,
    /// COPY maps every included original ID to its new ID. MKCOL uses the transaction ID.
    pub fresh_ids: BTreeMap<EntryId, EntryId>,
    pub origin_device: DeviceId,
    pub created_at_ms: u64,
    pub max_entries: usize,
    pub max_operations: usize,
    pub max_metadata_bytes: u64,
    pub max_retained_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebDavMutationPlan {
    request_hash: ContentId,
    baseline: SnapshotId,
    manifest: Manifest,
    operations: Vec<Operation>,
    originals: Vec<Entry>,
    target_existed: bool,
    retained_bytes: u64,
}

impl WebDavMutationPlan {
    pub fn request_hash(&self) -> &ContentId {
        &self.request_hash
    }
    pub fn baseline(&self) -> &SnapshotId {
        &self.baseline
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
    pub fn retained_originals(&self) -> &[Entry] {
        &self.originals
    }
    pub fn target_existed(&self) -> bool {
        self.target_existed
    }
    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
    pub fn native_execution_admitted(&self) -> bool {
        false
    }
    pub fn remote_backup_complete(&self) -> bool {
        false
    }
}

fn inside(path: &PortablePath, root: &PortablePath) -> bool {
    path == root
        || path
            .as_str()
            .strip_prefix(root.as_str())
            .is_some_and(|tail| tail.starts_with('/'))
}

fn find<'a>(manifest: &'a Manifest, path: &PortablePath) -> Option<&'a Entry> {
    manifest.entries.values().find(|entry| &entry.path == path)
}

fn authorize(request: &WebDavMutationRequest, path: &PortablePath) -> Result<()> {
    if request
        .export_subtree
        .as_ref()
        .is_some_and(|root| path == root || !inside(path, root))
    {
        return Err(ModelError::InvalidData(
            "DAV mutation must stay below its authorized export root",
        ));
    }
    Ok(())
}

fn existing_parent(manifest: &Manifest, path: &PortablePath) -> Result<()> {
    if path.parent().is_some_and(|parent| {
        find(manifest, &parent).is_none_or(|entry| entry.kind != EntryKind::Directory)
    }) {
        return Err(ModelError::InvalidData(
            "DAV destination parent must already be a collection",
        ));
    }
    Ok(())
}

fn descendants(manifest: &Manifest, root: &PortablePath, recursive: bool) -> Vec<Entry> {
    let mut entries: Vec<_> = manifest
        .entries
        .values()
        .filter(|entry| &entry.path == root || recursive && inside(&entry.path, root))
        .cloned()
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}

fn remove_entries(manifest: &mut Manifest, entries: &[Entry], changes: &mut Vec<Change>) {
    let mut removed: Vec<_> = entries.iter().collect();
    // Child-first DELETE lets each transmitted prefix retain valid parent membership.
    removed.sort_by(|a, b| {
        b.path
            .as_str()
            .split('/')
            .count()
            .cmp(&a.path.as_str().split('/').count())
            .then_with(|| a.path.cmp(&b.path))
    });
    for entry in removed {
        manifest.entries.remove(&entry.entry_id);
        changes.push(Change::Delete {
            entry_id: entry.entry_id.clone(),
        });
    }
}

/// Produces exact causal history and retention inputs without opening filesystem paths.
/// MOVE keeps every original ID; COPY requires new IDs for all included descendants.
pub fn plan_webdav_mutation(
    baseline: &Manifest,
    request: &WebDavMutationRequest,
) -> Result<WebDavMutationPlan> {
    baseline.validate()?;
    if request.baseline != baseline.root()?
        || request.max_entries == 0
        || request.max_entries > crate::limits::MAX_ENTRIES
        || request.max_operations == 0
        || request.max_operations > crate::limits::MAX_ENTRIES
        || request.max_metadata_bytes == 0
        || request.max_metadata_bytes > i64::MAX as u64
        || request.max_retained_bytes > i64::MAX as u64
        || request.created_at_ms > i64::MAX as u64
        || baseline.entries.len() > request.max_entries
        || baseline.tombstones.len() > request.max_entries
        || request.fresh_ids.len() > request.max_entries
    {
        return Err(ModelError::InvalidData("DAV baseline or mutation budget"));
    }
    let request_bytes =
        crate::tree_restore_history::encode_history_record(request, request.max_metadata_bytes)?;
    if let Some(export) = &request.export_subtree {
        if find(baseline, export).is_none_or(|entry| entry.kind != EntryKind::Directory) {
            return Err(ModelError::InvalidData("DAV export collection missing"));
        }
    }
    let mut manifest = baseline.clone();
    let mut changes = Vec::new();
    let mut originals = Vec::new();
    let target_existed;
    match &request.mutation {
        WebDavMutation::Mkcol { destination } => {
            authorize(request, destination)?;
            existing_parent(baseline, destination)?;
            if find(baseline, destination).is_some()
                || !request.fresh_ids.is_empty()
                || baseline.entries.contains_key(&request.transaction_id)
                || baseline.tombstones.contains_key(&request.transaction_id)
            {
                return Err(ModelError::InvalidData("DAV MKCOL destination or fresh ID"));
            }
            let entry = Entry {
                entry_id: request.transaction_id.clone(),
                path: destination.clone(),
                kind: EntryKind::Directory,
                content: None,
            };
            manifest
                .entries
                .insert(entry.entry_id.clone(), entry.clone());
            changes.push(Change::Put { entry });
            target_existed = false;
        }
        WebDavMutation::Delete { source } => {
            authorize(request, source)?;
            if find(baseline, source).is_none() || !request.fresh_ids.is_empty() {
                return Err(ModelError::InvalidData("DAV DELETE source or fresh IDs"));
            }
            originals = descendants(baseline, source, true);
            remove_entries(&mut manifest, &originals, &mut changes);
            target_existed = true;
        }
        WebDavMutation::Move {
            source,
            destination,
            overwrite,
        }
        | WebDavMutation::Copy {
            source,
            destination,
            overwrite,
            ..
        } => {
            authorize(request, source)?;
            authorize(request, destination)?;
            existing_parent(baseline, destination)?;
            let source_entry =
                find(baseline, source).ok_or(ModelError::InvalidData("DAV source missing"))?;
            if inside(source, destination)
                || inside(destination, source)
                || source.collision_key() == destination.collision_key()
            {
                return Err(ModelError::InvalidData("DAV overlapping mutation roots"));
            }
            let copying = matches!(&request.mutation, WebDavMutation::Copy { .. });
            let recursive = !matches!(
                &request.mutation,
                WebDavMutation::Copy {
                    recursive: false,
                    ..
                }
            );
            let selected = descendants(baseline, source, recursive);
            let target = find(baseline, destination);
            target_existed = target.is_some();
            if target_existed && !overwrite {
                return Err(ModelError::InvalidData(
                    "DAV Overwrite F destination exists",
                ));
            }
            if target.is_some_and(|entry| entry.kind != source_entry.kind) {
                return Err(ModelError::InvalidData("DAV overwrite kind mismatch"));
            }
            if target_existed {
                originals = descendants(baseline, destination, true);
                remove_entries(&mut manifest, &originals, &mut changes);
            }
            if copying {
                let ids: BTreeSet<_> = selected.iter().map(|entry| &entry.entry_id).collect();
                let keys: BTreeSet<_> = request.fresh_ids.keys().collect();
                let fresh: BTreeSet<_> = request.fresh_ids.values().collect();
                if ids != keys
                    || fresh.len() != ids.len()
                    || fresh.iter().any(|id| {
                        baseline.entries.contains_key(*id) || baseline.tombstones.contains_key(*id)
                    })
                {
                    return Err(ModelError::InvalidData(
                        "DAV COPY requires distinct fresh descendant IDs",
                    ));
                }
            } else if !request.fresh_ids.is_empty() {
                return Err(ModelError::InvalidData("DAV MOVE must preserve IDs"));
            }
            originals.extend(selected.iter().cloned());
            // Parent-first PUT gives COPY a valid prefix. A MOVE remains a retained
            // multi-entry transaction; each Rename preserves its source identity.
            for mut entry in selected {
                let tail = entry
                    .path
                    .as_str()
                    .strip_prefix(source.as_str())
                    .ok_or(ModelError::InvalidData("DAV selected descendant differs"))?;
                entry.path = PortablePath::new(format!("{destination}{tail}"))?;
                if copying {
                    entry.entry_id = request.fresh_ids[&entry.entry_id].clone();
                    changes.push(Change::Put {
                        entry: entry.clone(),
                    });
                } else {
                    changes.push(Change::Rename {
                        entry_id: entry.entry_id.clone(),
                        path: entry.path.clone(),
                    });
                }
                manifest.entries.insert(entry.entry_id.clone(), entry);
            }
        }
    }
    if changes.is_empty()
        || changes.len() > request.max_operations
        || manifest.entries.len() > request.max_entries
    {
        return Err(ModelError::InvalidData(
            "DAV operation or resulting entry budget",
        ));
    }
    // Final validation catches sibling case collisions and dangling parents.
    let mut operations = Vec::new();
    for change in changes {
        let sequence = manifest
            .version_vector
            .get(&request.origin_device)
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(ModelError::InvalidData("DAV causal sequence exhausted"))?;
        let operation = Operation::new(OperationPayload {
            format_version: FORMAT_VERSION,
            space_id: baseline.space_id.clone(),
            origin_device_id: request.origin_device.clone(),
            origin_seq: sequence,
            causal: manifest.version_vector.clone(),
            change,
            created_at_ms: request.created_at_ms,
        })?;
        if let Change::Delete { entry_id } = &operation.payload.change {
            manifest
                .tombstones
                .insert(entry_id.clone(), operation.op_id.clone());
        }
        manifest
            .version_vector
            .observe(request.origin_device.clone(), sequence);
        operations.push(operation);
    }
    manifest.validate()?;
    if manifest.tombstones.len() > request.max_entries {
        return Err(ModelError::InvalidData("DAV resulting tombstone budget"));
    }
    originals.sort_by(|a, b| a.entry_id.cmp(&b.entry_id));
    originals.dedup_by(|a, b| a.entry_id == b.entry_id);
    let mut chunks = BTreeMap::new();
    let mut retained_bytes = 0u64;
    for entry in &originals {
        if let Some(content) = &entry.content {
            for chunk in &content.chunks {
                match chunks.insert(&chunk.content_id, chunk.length) {
                    Some(previous) if previous != chunk.length => {
                        return Err(ModelError::InvalidData("DAV retained chunk length differs"));
                    }
                    Some(_) => (),
                    None => {
                        retained_bytes = retained_bytes
                            .checked_add(u64::from(chunk.length))
                            .filter(|n| *n <= request.max_retained_bytes)
                            .ok_or(ModelError::InvalidData("DAV original retention budget"))?;
                    }
                }
            }
        }
    }
    crate::tree_restore_history::encode_history_record(
        &(request, &manifest, &operations, &originals),
        request.max_metadata_bytes,
    )?;
    Ok(WebDavMutationPlan {
        request_hash: ContentId::hash(&request_bytes),
        baseline: request.baseline.clone(),
        manifest,
        operations,
        originals,
        target_existed,
        retained_bytes,
    })
}
