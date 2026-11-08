//! Pure bounded flat-file projection. No signatures, pins or native authority.
use crate::{
    causal::{reduce_operations, ContentAlternative, MAX_CAUSAL_OPERATIONS},
    ContentId, DeviceId, Entry, EntryId, EntryKind, FileManifest, Manifest, ModelError, Operation,
    OperationId, PortablePath, Result, SpaceId, VersionVector,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RESOLUTION_FILES: usize = 10_000;
pub const MAX_RESOLUTION_EVENTS: usize = 10_000;
pub const MAX_RESOLUTION_BYTES: usize = 64 * 1024 * 1024;
const MAX_NAME_ATTEMPTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionLimits {
    pub max_operations: usize,
    pub max_files: usize,
    pub max_events: usize,
    pub max_bytes: usize,
}
impl Default for ResolutionLimits {
    fn default() -> Self {
        Self {
            max_operations: MAX_CAUSAL_OPERATIONS,
            max_files: MAX_RESOLUTION_FILES,
            max_events: MAX_RESOLUTION_EVENTS,
            max_bytes: MAX_RESOLUTION_BYTES,
        }
    }
}
impl ResolutionLimits {
    fn validate(self) -> Result<()> {
        if self.max_operations == 0
            || self.max_operations > MAX_CAUSAL_OPERATIONS
            || self.max_files == 0
            || self.max_files > MAX_RESOLUTION_FILES
            || self.max_events == 0
            || self.max_events > MAX_RESOLUTION_EVENTS
            || self.max_bytes == 0
            || self.max_bytes > MAX_RESOLUTION_BYTES
        {
            return Err(invalid("resolution limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolutionFile {
    pub entry: Entry,
    pub source_entry_id: EntryId,
    pub content_operations: Vec<OperationId>,
    pub path_operations: Vec<OperationId>,
    pub preserved_copy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResolutionEvent {
    ContentConflict {
        source_entry_id: EntryId,
        preserved_entry_id: EntryId,
        selected_operations: Vec<OperationId>,
        preserved_operations: Vec<OperationId>,
    },
    DeleteConflict {
        source_entry_id: EntryId,
        deletions: Vec<OperationId>,
    },
    RenameConflict {
        source_entry_id: EntryId,
        selected_path: PortablePath,
        selected_operations: Vec<OperationId>,
        alternate_path: PortablePath,
        alternate_operations: Vec<OperationId>,
    },
    PathCollision {
        source_entry_id: EntryId,
        winning_entry_id: EntryId,
        requested_path: PortablePath,
        preserved_path: PortablePath,
    },
}

/// Serialization is descriptive. Recompute from originals before using a plan;
/// equality or a hash is never a native token or a verified operation signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileResolutionPlan {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub input_operations: Vec<OperationId>,
    pub received_vector: VersionVector,
    pub projected: Manifest,
    pub files: Vec<ResolutionFile>,
    pub events: Vec<ResolutionEvent>,
    pub worktree_materialized: bool,
    pub execution_authorized: bool,
}
impl FileResolutionPlan {
    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }
}

/// Canonical own-origin prefix only. This neither reserves sequence numbers nor
/// authenticates originals; durable admission must bind the complete local log.
pub fn resolving_file_operations(
    plan: &FileResolutionPlan,
    resolver: &DeviceId,
    created_at_ms: u64,
    limits: ResolutionLimits,
) -> Result<Vec<Operation>> {
    limits.validate()?;
    if plan.events.is_empty() || created_at_ms > i64::MAX as u64 {
        return Err(invalid(
            "resolution requires conflict and valid display time",
        ));
    }
    let mut causal = plan.received_vector.clone();
    let mut operations = Vec::new();
    for file in &plan.files {
        let mut changes = vec![crate::Change::Put {
            entry: file.entry.clone(),
        }];
        // Put cannot dominate an independent Rename register on a known path.
        if !file.preserved_copy
            && plan.events.iter().any(|event| {
                matches!(event, ResolutionEvent::RenameConflict { source_entry_id, .. }
                    if source_entry_id == &file.source_entry_id)
            })
        {
            changes.push(crate::Change::Rename {
                entry_id: file.entry.entry_id.clone(),
                path: file.entry.path.clone(),
            });
        }
        for change in changes {
            if plan.input_operations.len().saturating_add(operations.len()) >= limits.max_operations
            {
                return Err(invalid("resolution aggregate operation budget"));
            }
            let sequence = causal
                .get(resolver)
                .checked_add(1)
                .filter(|sequence| *sequence <= i64::MAX as u64)
                .ok_or(invalid("resolution own sequence exhausted"))?;
            let operation = Operation::new(crate::OperationPayload {
                format_version: crate::FORMAT_VERSION,
                space_id: plan.space_id.clone(),
                origin_device_id: resolver.clone(),
                origin_seq: sequence,
                causal: causal.clone(),
                change,
                created_at_ms,
            })?;
            causal.observe(resolver.clone(), sequence);
            operations.push(operation);
        }
    }
    Ok(operations)
}

/// Recompute the actual combined causal result, not merely a plan hash.
pub fn verify_file_resolution_projection(
    plan: &FileResolutionPlan,
    originals: &[Operation],
    resolving: &[Operation],
    limits: ResolutionLimits,
) -> Result<()> {
    limits.validate()?;
    let mut combined = originals.to_vec();
    combined.extend_from_slice(resolving);
    let reduced = reduce_operations(&plan.space_id, &combined, limits.max_operations)?;
    if !reduced.path_collisions.is_empty()
        || reduced.entries.len() != plan.projected.entries.len() + plan.projected.tombstones.len()
    {
        return Err(invalid("resolution reduced namespace differs"));
    }
    for (id, frontier) in &reduced.entries {
        if let Some(entry) = plan.projected.entries.get(id) {
            if frontier.deleted
                || frontier.delete_conflict
                || frontier.paths.len() != 1
                || frontier.paths[0].path != entry.path
                || frontier.contents.len() != 1
                || frontier.contents[0].kind != entry.kind
                || frontier.contents[0].content != entry.content
            {
                return Err(invalid("resolution actual causal result differs"));
            }
        } else if !frontier.deleted || !plan.projected.tombstones.contains_key(id) {
            return Err(invalid("resolution reduced deletion differs"));
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> ModelError {
    ModelError::InvalidData(message)
}
fn charge(bytes: &mut usize, value: &impl Serialize, limit: usize) -> Result<()> {
    let encoded = serde_json::to_vec(value)?;
    *bytes = bytes
        .checked_add(encoded.len())
        .filter(|bytes| *bytes <= limit)
        .ok_or(invalid("resolution byte budget"))?;
    Ok(())
}
fn copy_id(space: &SpaceId, source: &EntryId, content: &FileManifest) -> Result<EntryId> {
    let encoded = serde_json::to_vec(&("SyncExtend conflict file v1", space, source, content))?;
    ContentId::hash(&encoded).as_str()[..32].parse()
}
fn collision_id(space: &SpaceId, source: &EntryId, path: &PortablePath) -> Result<EntryId> {
    let encoded = serde_json::to_vec(&("SyncExtend conflict path v1", space, source, path))?;
    ContentId::hash(&encoded).as_str()[..32].parse()
}
fn content(alternative: &ContentAlternative) -> Result<&FileManifest> {
    if alternative.kind != EntryKind::File {
        return Err(invalid("resolution supports flat files only"));
    }
    alternative
        .content
        .as_ref()
        .ok_or(invalid("resolution missing file content"))
}

// Reserve every requested name, including alternate Renames and future primaries.
// A generated name never takes another original's slot, even on equal bytes.
fn conflict_path(
    requested: &PortablePath,
    discriminator: &EntryId,
    origin: &DeviceId,
    operation: &OperationId,
    occupied: &mut BTreeSet<String>,
) -> Result<PortablePath> {
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let attempt = if attempt == 0 {
            String::new()
        } else {
            format!("-{attempt}")
        };
        let suffix = format!(
            ".conflict-{}-{}-{discriminator}{attempt}",
            &origin.as_str()[..8],
            &operation.as_str()[..8],
        );
        let mut end = requested.as_str().len().min(255 - suffix.len());
        while !requested.as_str().is_char_boundary(end) {
            end -= 1;
        }
        let name = PortablePath::new(format!("{}{suffix}", &requested.as_str()[..end]))?;
        if occupied.insert(name.collision_key()) {
            return Ok(name);
        }
    }
    Err(invalid("resolution conflict name slots exhausted"))
}

fn push_event(
    events: &mut Vec<ResolutionEvent>,
    event: ResolutionEvent,
    bytes: &mut usize,
    limits: ResolutionLimits,
) -> Result<()> {
    if events.len() >= limits.max_events {
        return Err(invalid("resolution event budget"));
    }
    charge(bytes, &event, limits.max_bytes)?;
    events.push(event);
    Ok(())
}
fn push_file(
    files: &mut Vec<ResolutionFile>,
    file: ResolutionFile,
    bytes: &mut usize,
    limits: ResolutionLimits,
) -> Result<()> {
    if files.len() >= limits.max_files {
        return Err(invalid("resolution file budget"));
    }
    charge(bytes, &file, limits.max_bytes)?;
    files.push(file);
    Ok(())
}

/// Deterministic non-LWW projection of a complete original log. Nested/directory
/// topology is explicitly refused, not partially flattened or silently omitted.
/// Caller approval, original signatures, CAS closure and native work are separate.
pub fn plan_file_resolution(
    space: &SpaceId,
    input: &[Operation],
    limits: ResolutionLimits,
) -> Result<FileResolutionPlan> {
    limits.validate()?;
    if input.len() > limits.max_operations {
        return Err(invalid("resolution operation budget"));
    }
    let mut bytes = 0usize;
    for operation in input {
        charge(&mut bytes, operation, limits.max_bytes)?;
        match &operation.payload.change {
            crate::Change::Put { entry }
                if entry.kind != EntryKind::File || entry.path.parent().is_some() =>
            {
                return Err(invalid("resolution supports flat files only"));
            }
            crate::Change::Rename { path, .. } if path.parent().is_some() => {
                return Err(invalid("resolution supports flat files only"));
            }
            _ => {}
        }
    }
    let reduction = reduce_operations(space, input, limits.max_operations)?;
    let by_id: BTreeMap<_, _> = input
        .iter()
        .map(|operation| (operation.op_id.clone(), operation))
        .collect();
    let mut ids: BTreeSet<_> = reduction.entries.keys().cloned().collect();
    let mut occupied: BTreeSet<_> = reduction
        .entries
        .values()
        .flat_map(|entry| entry.paths.iter().map(|path| path.path.collision_key()))
        .collect();
    let mut primary_names: BTreeMap<String, EntryId> = BTreeMap::new();
    let mut files = Vec::new();
    let mut events = Vec::new();
    let mut projected = Manifest::empty(space.clone());
    projected.version_vector = reduction.received_vector.clone();
    for (source, frontier) in &reduction.entries {
        if frontier.deleted {
            projected.tombstones.insert(
                source.clone(),
                frontier
                    .deletions
                    .first()
                    .ok_or(invalid("resolution deletion provenance missing"))?
                    .clone(),
            );
            continue;
        }
        let selected_path = frontier
            .paths
            .first()
            .ok_or(invalid("resolution path provenance missing"))?;
        let mut alternatives: Vec<_> = frontier.contents.iter().collect();
        alternatives.sort_by(|a, b| a.operations.cmp(&b.operations));
        let selected = *alternatives
            .first()
            .ok_or(invalid("resolution content provenance missing"))?;
        let provenance = |alternative: &ContentAlternative| -> Result<&Operation> {
            let id = alternative
                .operations
                .first()
                .ok_or(invalid("resolution empty original provenance"))?;
            by_id
                .get(id)
                .copied()
                .ok_or(invalid("resolution original provenance missing"))
        };
        let mut primary_path = selected_path.path.clone();
        if let Some(winner) = primary_names.get(&primary_path.collision_key()) {
            let discriminator = collision_id(space, source, &primary_path)?;
            let original = provenance(selected)?;
            let preserved_path = conflict_path(
                &primary_path,
                &discriminator,
                &original.payload.origin_device_id,
                &original.op_id,
                &mut occupied,
            )?;
            push_event(
                &mut events,
                ResolutionEvent::PathCollision {
                    source_entry_id: source.clone(),
                    winning_entry_id: winner.clone(),
                    requested_path: primary_path,
                    preserved_path: preserved_path.clone(),
                },
                &mut bytes,
                limits,
            )?;
            primary_path = preserved_path;
        } else {
            primary_names.insert(primary_path.collision_key(), source.clone());
        }
        push_file(
            &mut files,
            ResolutionFile {
                entry: Entry {
                    entry_id: source.clone(),
                    path: primary_path.clone(),
                    kind: EntryKind::File,
                    content: Some(content(selected)?.clone()),
                },
                source_entry_id: source.clone(),
                content_operations: selected.operations.clone(),
                path_operations: selected_path.operations.clone(),
                preserved_copy: false,
            },
            &mut bytes,
            limits,
        )?;
        for alternative in alternatives.into_iter().skip(1) {
            let file = content(alternative)?;
            let id = copy_id(space, source, file)?;
            if !ids.insert(id.clone()) {
                return Err(invalid("resolution derived identity collision"));
            }
            let original = provenance(alternative)?;
            let path = conflict_path(
                &selected_path.path,
                &id,
                &original.payload.origin_device_id,
                &original.op_id,
                &mut occupied,
            )?;
            push_file(
                &mut files,
                ResolutionFile {
                    entry: Entry {
                        entry_id: id.clone(),
                        path,
                        kind: EntryKind::File,
                        content: Some(file.clone()),
                    },
                    source_entry_id: source.clone(),
                    content_operations: alternative.operations.clone(),
                    path_operations: selected_path.operations.clone(),
                    preserved_copy: true,
                },
                &mut bytes,
                limits,
            )?;
            push_event(
                &mut events,
                ResolutionEvent::ContentConflict {
                    source_entry_id: source.clone(),
                    preserved_entry_id: id,
                    selected_operations: selected.operations.clone(),
                    preserved_operations: alternative.operations.clone(),
                },
                &mut bytes,
                limits,
            )?;
        }
        if frontier.delete_conflict {
            push_event(
                &mut events,
                ResolutionEvent::DeleteConflict {
                    source_entry_id: source.clone(),
                    deletions: frontier.deletions.clone(),
                },
                &mut bytes,
                limits,
            )?;
        }
        for alternate in frontier.paths.iter().skip(1) {
            push_event(
                &mut events,
                ResolutionEvent::RenameConflict {
                    source_entry_id: source.clone(),
                    selected_path: primary_path.clone(),
                    selected_operations: selected_path.operations.clone(),
                    alternate_path: alternate.path.clone(),
                    alternate_operations: alternate.operations.clone(),
                },
                &mut bytes,
                limits,
            )?;
        }
    }
    files.sort_by(|a, b| a.entry.entry_id.cmp(&b.entry.entry_id));
    for file in &files {
        projected
            .entries
            .insert(file.entry.entry_id.clone(), file.entry.clone());
    }
    projected.validate()?;
    let result = FileResolutionPlan {
        format_version: 1,
        space_id: space.clone(),
        input_operations: by_id.into_keys().collect(),
        received_vector: reduction.received_vector,
        projected,
        files,
        events,
        worktree_materialized: false,
        execution_authorized: false,
    };
    if serde_json::to_vec(&result)?.len() > limits.max_bytes {
        return Err(invalid("resolution result byte budget"));
    }
    Ok(result)
}
