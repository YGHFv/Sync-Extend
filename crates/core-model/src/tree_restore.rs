//! Pure non-atomic planning, not certification of a durable owner or native executor.
//! Historical entry IDs identify inputs, not permission to resurrect those IDs.

use crate::{
    limits,
    restore_selection::{contains_component_path, destination_path, source_relative_path},
    ContentId, Entry, EntryKind, Manifest, ModelError, PortablePath, RestoreCurrentExtraPolicy,
    RestoreOccupiedTargetPolicy, RestoreSelection, Result, SnapshotId, SpaceId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreScope {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub baseline_snapshot: SnapshotId,
    pub target_snapshot: SnapshotId,
    /// Omitted scopes retain the original whole-TREE serialization and hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<TreeRestoreSelection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreSelection {
    pub format_version: u32,
    pub selection: RestoreSelection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_prefix: Option<PortablePath>,
    #[serde(default)]
    pub current_extra_policy: RestoreCurrentExtraPolicy,
    #[serde(default)]
    pub occupied_target_policy: RestoreOccupiedTargetPolicy,
}

impl TreeRestoreSelection {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(ModelError::InvalidData("unsupported TREE selection format"));
        }
        self.selection.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreLimits {
    pub max_entries: usize,
    pub max_steps: usize,
    pub max_chunk_visits: usize,
    pub max_target_bytes: u64,
    pub max_retained_and_staging_bytes: u64,
    pub max_plan_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeRestoreAction {
    CreateDirectory,
    PublishNewFile,
    ReplaceFile,
    DeleteFile,
    RemoveEmptyDirectory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreStep {
    pub index: usize,
    pub action: TreeRestoreAction,
    pub path: PortablePath,
    pub baseline_entry: Option<Entry>,
    pub historical_target_entry: Option<Entry>,
    pub dependencies: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeRestorePlan {
    scope: TreeRestoreScope,
    steps: Vec<TreeRestoreStep>,
    target_logical_bytes: u64,
    retained_and_staging_bytes: u64,
    conservative_plan_bytes: u64,
}

impl TreeRestorePlan {
    pub fn scope(&self) -> &TreeRestoreScope {
        &self.scope
    }
    pub fn steps(&self) -> &[TreeRestoreStep] {
        &self.steps
    }
    pub fn target_logical_bytes(&self) -> u64 {
        self.target_logical_bytes
    }
    pub fn retained_and_staging_bytes(&self) -> u64 {
        self.retained_and_staging_bytes
    }
    pub fn conservative_plan_bytes(&self) -> u64 {
        self.conservative_plan_bytes
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
    pub fn executor_available(&self) -> bool {
        false
    }
    pub fn durable_coordinator_available(&self) -> bool {
        false
    }
    pub fn resurrects_historical_entry_ids(&self) -> bool {
        false
    }
    pub fn resets_causal_vector(&self) -> bool {
        false
    }
    pub fn remote_backup_complete(&self) -> bool {
        false
    }
}

fn checked_add(total: &mut u64, bytes: u64, max: u64) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= max)
        .ok_or(ModelError::InvalidData("tree restore resource budget"))?;
    Ok(())
}

fn selected_path(roots: &[(PortablePath, EntryKind)], full: bool, path: &PortablePath) -> bool {
    full || roots.iter().any(|(root, kind)| {
        if *kind == EntryKind::Directory {
            contains_component_path(root, path)
        } else {
            root == path
        }
    })
}

/// Destination names are independent keys; borrowed historical entries remain
/// the actual retained source, with no hybrid snapshot or invented source IDs.
pub(crate) fn tree_restore_desired_entries<'a>(
    scope: &TreeRestoreScope,
    baseline: &'a Manifest,
    target: &'a Manifest,
) -> Result<BTreeMap<PortablePath, &'a Entry>> {
    let historical: BTreeMap<_, _> = target
        .entries
        .values()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let Some(selection) = &scope.selection else {
        return Ok(historical);
    };
    selection.validate()?;
    let current: BTreeMap<_, _> = baseline
        .entries
        .values()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let full = matches!(selection.selection, RestoreSelection::Full);
    let mut roots = Vec::new();
    for path in selection.selection.explicit_paths() {
        let entry = historical
            .get(path)
            .ok_or(ModelError::InvalidData("TREE selected source path missing"))?;
        if matches!(selection.selection, RestoreSelection::File { .. })
            && entry.kind != EntryKind::File
            || matches!(selection.selection, RestoreSelection::Directory { .. })
                && entry.kind != EntryKind::Directory
        {
            return Err(ModelError::InvalidData("TREE selected source type differs"));
        }
        roots.push((path.clone(), entry.kind));
    }
    if let Some(prefix) = &selection.destination_prefix {
        if current
            .get(prefix)
            .is_none_or(|entry| entry.kind != EntryKind::Directory)
        {
            return Err(ModelError::InvalidData(
                "TREE destination prefix requires an existing directory",
            ));
        }
    }
    let mut mapped = BTreeMap::new();
    for (path, entry) in historical {
        if selected_path(&roots, full, &path) {
            let destination = destination_path(selection.destination_prefix.as_ref(), &path)?;
            if mapped.insert(destination, entry).is_some() {
                return Err(ModelError::InvalidData("TREE selected destination alias"));
            }
        }
    }
    let current_cases: BTreeMap<_, _> = current
        .values()
        .map(|entry| (entry.path.collision_key(), *entry))
        .collect();
    for (path, desired) in &mapped {
        let mut ancestor = Some(path.clone());
        while let Some(name) = ancestor {
            if let Some(old) = current_cases.get(&name.collision_key()) {
                if old.path != name {
                    return Err(ModelError::InvalidData(
                        "case-only TREE selection is unsupported",
                    ));
                }
                if name != *path && old.kind != EntryKind::Directory {
                    return Err(ModelError::InvalidData("TREE selected ancestor is a file"));
                }
            }
            ancestor = name.parent();
        }
        if let Some(old) = current.get(path) {
            if old.kind != desired.kind {
                return Err(ModelError::InvalidData(
                    "TREE selected target type conflict",
                ));
            }
            if old.content != desired.content
                && selection.occupied_target_policy == RestoreOccupiedTargetPolicy::ReportConflicts
            {
                return Err(ModelError::InvalidData(
                    "TREE selected occupied file requires replace-files",
                ));
            }
        }
    }
    let mut desired = current;
    if selection.current_extra_policy == RestoreCurrentExtraPolicy::ReplaceSelectedScope {
        desired.retain(|path, _| {
            mapped.contains_key(path)
                || source_relative_path(selection.destination_prefix.as_ref(), path)
                    .is_none_or(|relative| !selected_path(&roots, full, &relative))
        });
    }
    desired.extend(mapped);
    let mut desired_cases = BTreeMap::new();
    for (path, entry) in &desired {
        if desired_cases
            .insert(path.collision_key(), path)
            .is_some_and(|previous| previous != path)
        {
            return Err(ModelError::InvalidData(
                "TREE selected destination case conflict",
            ));
        }
        if let Some(parent) = path.parent() {
            if desired
                .get(&parent)
                .is_none_or(|entry| entry.kind != EntryKind::Directory)
            {
                return Err(ModelError::InvalidData(
                    "TREE selected destination parent is missing",
                ));
            }
        }
        entry.validate()?;
    }
    Ok(desired)
}

/// Deterministic path/content diff with no rename shortcut. Limits account for
/// all original retention plus new staging, not the largest single operation.
pub fn plan_tree_restore(
    scope: &TreeRestoreScope,
    baseline: &Manifest,
    target: &Manifest,
    bounds: TreeRestoreLimits,
) -> Result<TreeRestorePlan> {
    if bounds.max_entries == 0
        || bounds.max_entries > limits::MAX_ENTRIES
        || bounds.max_steps == 0
        || bounds.max_steps > limits::MAX_ENTRIES
        || bounds.max_chunk_visits == 0
        || bounds.max_chunk_visits > limits::MAX_CHUNKS
        || baseline.entries.len() > bounds.max_entries
        || target.entries.len() > bounds.max_entries
        || baseline.tombstones.len() > bounds.max_entries
        || target.tombstones.len() > bounds.max_entries
    {
        return Err(ModelError::InvalidData("tree restore inventory budget"));
    }
    baseline.validate()?;
    target.validate()?;
    if scope.format_version != FORMAT_VERSION
        || scope.space_id != baseline.space_id
        || scope.space_id != target.space_id
        || scope.baseline_snapshot != baseline.root()?
        || scope.target_snapshot != target.root()?
        || baseline.policy_version != target.policy_version
    {
        return Err(ModelError::InvalidData(
            "tree restore snapshot scope mismatch",
        ));
    }
    let old: BTreeMap<_, _> = baseline
        .entries
        .values()
        .map(|e| (e.path.clone(), e))
        .collect();
    let desired = tree_restore_desired_entries(scope, baseline, target)?;
    if desired.len() > bounds.max_entries {
        return Err(ModelError::InvalidData(
            "TREE selected final inventory budget",
        ));
    }
    let mut chunks = BTreeMap::<ContentId, u32>::new();
    let mut files = BTreeMap::new();
    let mut visits = 0usize;
    let mut plan_bytes = 1024u64;
    let mut target_bytes = 0u64;
    let mut case_paths = BTreeMap::new();
    if let Some(selection) = &scope.selection {
        checked_add(
            &mut plan_bytes,
            serde_json::to_vec(selection)?.len() as u64 * 6,
            bounds.max_plan_bytes,
        )?;
        for path in desired.keys() {
            checked_add(
                &mut plan_bytes,
                path.as_str().len() as u64 * 6,
                bounds.max_plan_bytes,
            )?;
        }
    }
    for manifest in [baseline, target] {
        for e in manifest.entries.values() {
            if scope.selection.is_none()
                && case_paths
                    .insert(e.path.collision_key(), &e.path)
                    .is_some_and(|p| p != &e.path)
            {
                return Err(ModelError::InvalidData(
                    "case-only tree restore is unsupported",
                ));
            }
            checked_add(
                &mut plan_bytes,
                1024 + e.path.as_str().len() as u64 * 6,
                bounds.max_plan_bytes,
            )?;
            if let Some(content) = &e.content {
                visits = visits
                    .checked_add(content.chunks.len())
                    .filter(|n| *n <= bounds.max_chunk_visits)
                    .ok_or(ModelError::InvalidData("tree restore chunk visit budget"))?;
                if files
                    .insert(content.content_id.clone(), content)
                    .is_some_and(|previous| previous != content)
                {
                    return Err(ModelError::InvalidData(
                        "tree restore conflicting file description",
                    ));
                }
                for chunk in &content.chunks {
                    if chunks
                        .insert(chunk.content_id.clone(), chunk.length)
                        .is_some_and(|n| n != chunk.length)
                    {
                        return Err(ModelError::InvalidData(
                            "tree restore conflicting chunk length",
                        ));
                    }
                }
                checked_add(
                    &mut plan_bytes,
                    content.chunks.len() as u64 * 128,
                    bounds.max_plan_bytes,
                )?;
            }
        }
    }
    if plan_bytes > bounds.max_plan_bytes {
        return Err(ModelError::InvalidData("tree restore plan budget"));
    }
    for e in desired.values() {
        if let Some(content) = &e.content {
            checked_add(&mut target_bytes, content.length, bounds.max_target_bytes)?;
        }
    }
    let mut steps = Vec::<TreeRestoreStep>::new();
    let mut removals: Vec<_> = old
        .values()
        .copied()
        .filter(|e| desired.get(&e.path).is_none_or(|d| d.kind != e.kind))
        .collect();
    removals.sort_by(|a, b| {
        b.path
            .as_str()
            .split('/')
            .count()
            .cmp(&a.path.as_str().split('/').count())
            .then(a.path.cmp(&b.path))
    });
    let mut removal_index = BTreeMap::new();
    let mut removed_children = BTreeMap::<PortablePath, Vec<usize>>::new();
    let mut create_index = BTreeMap::new();
    let mut temporary_bytes = 0u64;
    for e in removals {
        let dependencies = if e.kind == EntryKind::Directory {
            removed_children.remove(&e.path).unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Some(content) = &e.content {
            checked_add(
                &mut temporary_bytes,
                content
                    .length
                    .checked_add(65)
                    .ok_or(ModelError::InvalidData("tree restore temporary overflow"))?,
                bounds.max_retained_and_staging_bytes,
            )?;
        } else {
            checked_add(
                &mut temporary_bytes,
                65,
                bounds.max_retained_and_staging_bytes,
            )?;
        }
        removal_index.insert(e.path.clone(), steps.len());
        if let Some(parent) = e.path.parent() {
            removed_children
                .entry(parent)
                .or_default()
                .push(steps.len());
        }
        steps.push(TreeRestoreStep {
            index: steps.len(),
            action: if e.kind == EntryKind::File {
                TreeRestoreAction::DeleteFile
            } else {
                TreeRestoreAction::RemoveEmptyDirectory
            },
            path: e.path.clone(),
            baseline_entry: Some(e.clone()),
            historical_target_entry: None,
            dependencies,
        });
        if steps.len() > bounds.max_steps {
            return Err(ModelError::InvalidData("tree restore step budget"));
        }
    }
    let mut additions: Vec<_> = desired
        .iter()
        .map(|(path, entry)| (path.clone(), *entry))
        .collect();
    additions.sort_by(|(a, _), (b, _)| {
        a.as_str()
            .split('/')
            .count()
            .cmp(&b.as_str().split('/').count())
            .then(a.cmp(b))
    });
    for (path, e) in additions {
        let previous = old.get(&path).copied().filter(|old| old.kind == e.kind);
        if previous.is_some_and(|old| old.content == e.content) {
            continue;
        }
        let mut dependencies = Vec::new();
        if let Some(index) = removal_index.get(&path) {
            dependencies.push(*index);
        }
        if let Some(index) = path.parent().and_then(|p| create_index.get(&p).copied()) {
            dependencies.push(index);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        let action = if e.kind == EntryKind::Directory {
            TreeRestoreAction::CreateDirectory
        } else if previous.is_some() {
            TreeRestoreAction::ReplaceFile
        } else {
            TreeRestoreAction::PublishNewFile
        };
        if let Some(content) = &e.content {
            let original = previous
                .and_then(|e| e.content.as_ref())
                .map_or(0, |c| c.length);
            let bytes = content
                .length
                .checked_add(original)
                .and_then(|n| n.checked_add(65))
                .ok_or(ModelError::InvalidData("tree restore temporary overflow"))?;
            checked_add(
                &mut temporary_bytes,
                bytes,
                bounds.max_retained_and_staging_bytes,
            )?;
        } else {
            checked_add(
                &mut temporary_bytes,
                65,
                bounds.max_retained_and_staging_bytes,
            )?;
        }
        create_index.insert(path.clone(), steps.len());
        steps.push(TreeRestoreStep {
            index: steps.len(),
            action,
            path,
            baseline_entry: previous.cloned(),
            historical_target_entry: Some(e.clone()),
            dependencies,
        });
        if steps.len() > bounds.max_steps {
            return Err(ModelError::InvalidData("tree restore step budget"));
        }
    }
    for step in &steps {
        // Reserve per-step terminal and dependency metadata before any admission.
        checked_add(
            &mut plan_bytes,
            4096 + step.dependencies.len() as u64 * 32,
            bounds.max_plan_bytes,
        )?;
    }
    Ok(TreeRestorePlan {
        scope: scope.clone(),
        steps,
        target_logical_bytes: target_bytes,
        retained_and_staging_bytes: temporary_bytes,
        conservative_plan_bytes: plan_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeRestorePhase {
    Prepared,
    Admitted,
    Partial,
    FinalVerified,
    Committed,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeRestoreRequest {
    Inspect,
    Admit,
    ApplyOneStep,
    VerifyFinal,
    Commit,
    Cancel,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeRestoreEvidence {
    pub metadata_verified: bool,
    pub durable_exact_target_pins: bool,
    pub fresh_cas_content_verified: bool,
    pub writer_namespace_guarded: bool,
    pub selected_step_dependencies_complete: bool,
    pub selected_step_exact_native_verified: bool,
    pub all_steps_complete: bool,
    pub final_tree_reference_verified: bool,
    pub atomic_new_snapshot_ref_handoff: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeRestoreDecision {
    Defer,
    AuditOnly,
    Admit,
    ApplyOneStep,
    VerifyFinal,
    CommitNewHistory,
    Cancel,
    Noop,
}

/// Prospective only: no bool can enable an actual directory/native coordinator.
pub fn decide_tree_restore(
    phase: TreeRestorePhase,
    request: TreeRestoreRequest,
    e: TreeRestoreEvidence,
) -> TreeRestoreDecision {
    use TreeRestoreDecision as D;
    use TreeRestorePhase as P;
    use TreeRestoreRequest as R;
    if !e.metadata_verified {
        return D::Defer;
    }
    if matches!(phase, P::Committed | P::Cancelled) {
        return D::Noop;
    }
    if request == R::Inspect {
        return D::AuditOnly;
    }
    if request == R::Cancel {
        return if phase == P::Prepared {
            D::Cancel
        } else {
            D::Defer
        };
    }
    if !e.durable_exact_target_pins || !e.fresh_cas_content_verified || !e.writer_namespace_guarded
    {
        return D::Defer;
    }
    match (phase, request) {
        (P::Prepared, R::Admit) => D::Admit,
        (P::Admitted | P::Partial, R::ApplyOneStep)
            if e.selected_step_dependencies_complete
                && e.selected_step_exact_native_verified
                && !e.all_steps_complete =>
        {
            D::ApplyOneStep
        }
        (P::Admitted | P::Partial, R::VerifyFinal)
            if e.all_steps_complete && e.final_tree_reference_verified =>
        {
            D::VerifyFinal
        }
        (P::FinalVerified, R::Commit)
            if e.all_steps_complete
                && e.final_tree_reference_verified
                && e.atomic_new_snapshot_ref_handoff =>
        {
            D::CommitNewHistory
        }
        _ => D::Defer,
    }
}
