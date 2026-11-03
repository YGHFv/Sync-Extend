//! Prospective local inference only, not native continuity or rename authority.
//! An adapter must establish snapshot/root/epoch and stable observations afresh.

use crate::{
    limits, ContentId, EntryId, EntryKind, FileManifest, Manifest, ModelError, PortablePath,
    Result, SnapshotId, SpaceId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameObservationScope {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub prior_snapshot: SnapshotId,
    pub local_root_identity: ContentId,
    pub platform_epoch: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenamePathObservation {
    pub path: PortablePath,
    pub kind: EntryKind,
    pub content: Option<FileManifest>,
    pub physical_identity: ContentId,
    pub single_link: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorRenameObservation {
    pub entry_id: EntryId,
    pub observed: RenamePathObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameObservationMap {
    pub scope: RenameObservationScope,
    pub entries: Vec<PriorRenameObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameInferenceUnavailable {
    ScopeMismatch,
    StableScanNotVerified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameInferencePlan {
    candidates: BTreeMap<PortablePath, EntryId>,
    unavailable: Option<RenameInferenceUnavailable>,
}

impl RenameInferencePlan {
    pub fn candidates(&self) -> &BTreeMap<PortablePath, EntryId> {
        &self.candidates
    }

    pub fn unavailable(&self) -> Option<RenameInferenceUnavailable> {
        self.unavailable
    }

    pub fn persisted_map_implemented(&self) -> bool {
        false
    }

    pub fn native_continuity_verified(&self) -> bool {
        false
    }

    pub fn rename_modify_available(&self) -> bool {
        false
    }

    pub fn executor_available(&self) -> bool {
        false
    }
}

impl RenameObservationMap {
    pub fn validate(&self, prior: &Manifest, max_entries: usize) -> Result<()> {
        prior.validate()?;
        validate_scope(&self.scope)?;
        if self.scope.space_id != prior.space_id
            || self.scope.prior_snapshot != prior.root()?
            || self.entries.len() != prior.entries.len()
        {
            return Err(ModelError::InvalidData("rename map snapshot mismatch"));
        }
        validate_layout(self.entries.iter().map(|e| &e.observed), max_entries)?;
        let mut ids = BTreeMap::new();
        for record in &self.entries {
            let entry = prior
                .entries
                .get(&record.entry_id)
                .ok_or(ModelError::InvalidData("rename map entry binding mismatch"))?;
            if ids.insert(&record.entry_id, ()).is_some()
                || entry.path != record.observed.path
                || entry.kind != record.observed.kind
                || entry.content != record.observed.content
            {
                return Err(ModelError::InvalidData("rename map entry binding mismatch"));
            }
        }
        Ok(())
    }
}

/// Propose only identical-content file moves to previously unoccupied paths.
/// Reused IDs, changed content, source survivors, aliases and overwrites never
/// produce candidates. Same-path and portable unique-content inference are separate.
pub fn plan_persisted_rename(
    prior: &Manifest,
    map: &RenameObservationMap,
    current_scope: &RenameObservationScope,
    current: &[RenamePathObservation],
    stable_scan_verified: bool,
    max_entries: usize,
) -> Result<RenameInferencePlan> {
    map.validate(prior, max_entries)?;
    validate_scope(current_scope)?;
    validate_layout(current.iter(), max_entries)?;
    let mut plan = RenameInferencePlan {
        candidates: BTreeMap::new(),
        unavailable: None,
    };
    if &map.scope != current_scope {
        plan.unavailable = Some(RenameInferenceUnavailable::ScopeMismatch);
        return Ok(plan);
    }
    if !stable_scan_verified {
        plan.unavailable = Some(RenameInferenceUnavailable::StableScanNotVerified);
        return Ok(plan);
    }
    let old_paths: BTreeMap<_, _> = map
        .entries
        .iter()
        .map(|e| (e.observed.path.collision_key(), ()))
        .collect();
    let new_paths: BTreeMap<_, _> = current
        .iter()
        .map(|e| (e.path.collision_key(), ()))
        .collect();
    let mut old_ids = BTreeMap::<_, Vec<_>>::new();
    let mut new_ids = BTreeMap::<_, usize>::new();
    for record in &map.entries {
        old_ids
            .entry(&record.observed.physical_identity)
            .or_default()
            .push(record);
    }
    for observed in current {
        *new_ids.entry(&observed.physical_identity).or_default() += 1;
    }
    for observed in current {
        let Some(records) = old_ids.get(&observed.physical_identity) else {
            continue;
        };
        if records.len() != 1 || new_ids[&observed.physical_identity] != 1 {
            continue;
        }
        let record = records[0];
        let old = &record.observed;
        if old.kind == EntryKind::File
            && observed.kind == EntryKind::File
            && old.single_link
            && observed.single_link
            && old.content == observed.content
            && !new_paths.contains_key(&old.path.collision_key())
            && !old_paths.contains_key(&observed.path.collision_key())
        {
            plan.candidates
                .insert(observed.path.clone(), record.entry_id.clone());
        }
    }
    Ok(plan)
}

fn validate_scope(scope: &RenameObservationScope) -> Result<()> {
    if scope.format_version != FORMAT_VERSION {
        return Err(ModelError::InvalidData(
            "unsupported rename observation format",
        ));
    }
    Ok(())
}

fn validate_layout<'a>(
    entries: impl Iterator<Item = &'a RenamePathObservation>,
    max_entries: usize,
) -> Result<()> {
    if max_entries == 0 || max_entries > limits::MAX_ENTRIES {
        return Err(ModelError::InvalidData("rename observation entry budget"));
    }
    let mut paths = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut chunks = 0usize;
    let mut lengths = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut bytes = 0u64;
    for observed in entries {
        if paths.len() >= max_entries
            || paths
                .insert(observed.path.collision_key(), &observed.path)
                .is_some()
        {
            return Err(ModelError::InvalidData("rename observation path/budget"));
        }
        match (observed.kind, &observed.content) {
            (EntryKind::Directory, None) => {
                directories.insert(&observed.path, ());
            }
            (EntryKind::File, Some(file)) => {
                file.validate()?;
                chunks = chunks
                    .checked_add(file.chunks.len())
                    .filter(|n| *n <= limits::MAX_CHUNKS)
                    .ok_or(ModelError::InvalidData("rename observation chunk budget"))?;
                bytes = bytes
                    .checked_add(file.length)
                    .ok_or(ModelError::InvalidData("rename observation byte overflow"))?;
                if files
                    .insert(&file.content_id, file)
                    .is_some_and(|old| old != file)
                {
                    return Err(ModelError::InvalidData("rename file description mismatch"));
                }
                for chunk in &file.chunks {
                    if lengths
                        .insert(&chunk.content_id, chunk.length)
                        .is_some_and(|old| old != chunk.length)
                    {
                        return Err(ModelError::InvalidData("rename chunk description mismatch"));
                    }
                }
            }
            _ => return Err(ModelError::InvalidData("rename observation kind/content")),
        }
    }
    for path in paths.values() {
        if path
            .parent()
            .is_some_and(|parent| !directories.contains_key(&parent))
        {
            return Err(ModelError::InvalidData("rename observation missing parent"));
        }
    }
    Ok(())
}
