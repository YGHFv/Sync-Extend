//! Portable history selection and new-operation descriptions. No execution,
//! native identity, CAS observation, reservation or implicit deletion is issued.
use crate::restore_preview::{
    validate_content_descriptions, validate_source, RestorePreviewCasReference,
    RestorePreviewResources, RestorePreviewSnapshot,
};
use crate::{ReadOnlyLocalSpace, ReconcileError, RestorePreviewLimits, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use sync_extend_core_model::{
    restore_selection::{contains_component_path, destination_path, source_relative_path},
    ContentId, Entry, EntryKind, PortablePath, RestoreCurrentExtraPolicy,
    RestoreOccupiedTargetPolicy, RestoreSelection, SnapshotId, SpaceId,
};
use sync_extend_journal::{ReadOnlyRestorePreviewSource, ReadOnlySnapshotPreviewSource};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSelectionPreviewRequest {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub snapshot: SnapshotId,
    pub expected_baseline: Option<SnapshotId>,
    pub selection: RestoreSelection,
    pub destination_prefix: Option<PortablePath>,
    #[serde(default)]
    pub current_extra_policy: RestoreCurrentExtraPolicy,
    #[serde(default)]
    pub occupied_target_policy: RestoreOccupiedTargetPolicy,
    pub limits: RestorePreviewLimits,
}

impl RestoreSelectionPreviewRequest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 2 {
            return Err(ReconcileError::Invariant(
                "unsupported selection preview version",
            ));
        }
        self.selection.validate()?;
        self.limits.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreSelectionSourceKind {
    ClosedMain,
    LiveOwner,
}

#[derive(Clone, Debug)]
pub struct RestoreSelectionPreviewSource {
    pub kind: RestoreSelectionSourceKind,
    pub space_id: SpaceId,
    pub current_snapshot: Option<SnapshotId>,
    pub current: Option<ReadOnlySnapshotPreviewSource>,
    pub baseline: Option<ReadOnlySnapshotPreviewSource>,
    pub target: ReadOnlySnapshotPreviewSource,
    pub source_image_bytes: Option<u64>,
    pub source_image_digest: Option<ContentId>,
    pub memory_header_projected: Option<bool>,
}

impl RestoreSelectionPreviewSource {
    pub fn closed_main(
        source: ReadOnlyRestorePreviewSource,
        current: Option<ReadOnlySnapshotPreviewSource>,
    ) -> Self {
        Self {
            kind: RestoreSelectionSourceKind::ClosedMain,
            space_id: source.space_id,
            current_snapshot: source.current_snapshot,
            current,
            baseline: source.baseline,
            target: source.target,
            source_image_bytes: Some(source.source_image_bytes),
            source_image_digest: Some(source.source_image_digest),
            memory_header_projected: Some(source.memory_header_projected),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreSelectionDifference {
    Unchanged,
    TargetOnly,
    FileContentsDiffer,
    CurrentOnly,
    TypeConflict,
    CaseConflict,
    AncestorFileConflict,
    BaselineUnchecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreProposedOperation {
    PreserveCurrent,
    NewCreateFile,
    NewCreateDirectory,
    NewReplaceFile,
    NewDeleteFile,
    NewRemoveDirectory,
    ReportConflict,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestoreSelectionPreviewEntry {
    pub source_path: Option<PortablePath>,
    pub destination_path: PortablePath,
    pub difference: RestoreSelectionDifference,
    pub proposed_operation: RestoreProposedOperation,
    pub current_kind: Option<EntryKind>,
    pub historical_kind: Option<EntryKind>,
    pub current_content_id: Option<ContentId>,
    pub historical_content_id: Option<ContentId>,
    pub current_bytes: Option<u64>,
    pub historical_bytes: Option<u64>,
    pub conflict_path: Option<PortablePath>,
    pub native_state: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RestoreSelectionPreviewCounts {
    pub selected_target_entries: usize,
    pub selected_target_files: usize,
    pub selected_target_directories: usize,
    pub selected_current_entries: usize,
    pub compared_paths: usize,
    pub preserved_current_paths: usize,
    pub proposed_create_files: usize,
    pub proposed_create_directories: usize,
    pub proposed_replace_files: usize,
    pub proposed_delete_files: usize,
    pub proposed_remove_directories: usize,
    pub reported_conflicts: usize,
    pub unchecked_paths: usize,
    pub target_chunk_visits: usize,
    pub unique_target_cas_references: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestoreSelectionPreview {
    pub preview_format_version: u32,
    pub mode: &'static str,
    pub space_id: SpaceId,
    pub current_snapshot_id: Option<SnapshotId>,
    pub baseline: Option<RestorePreviewSnapshot>,
    pub target: RestorePreviewSnapshot,
    pub selection: RestoreSelection,
    pub destination_prefix: Option<PortablePath>,
    pub destination_mapping: &'static str,
    pub current_extra_policy: RestoreCurrentExtraPolicy,
    pub occupied_target_policy: RestoreOccupiedTargetPolicy,
    pub selection_status: &'static str,
    pub expected_baseline_is_current: Option<bool>,
    pub metadata_diff_available: bool,
    pub counts: RestoreSelectionPreviewCounts,
    pub resources: RestorePreviewResources,
    pub entries: Vec<RestoreSelectionPreviewEntry>,
    pub entries_limit: usize,
    pub entries_truncated: bool,
    pub cas_references: Vec<RestorePreviewCasReference>,
    pub cas_references_limit: usize,
    pub cas_references_truncated: bool,
    pub output_byte_limit: usize,
    pub output_bytes_including_lf: usize,
    pub source_image_bytes: Option<u64>,
    pub source_image_digest: Option<ContentId>,
    pub memory_header_projected: Option<bool>,
    pub source_interpretation: &'static str,
    pub content_availability: &'static str,
    pub content_hashes_verified: bool,
    pub history_hash_authenticated: bool,
    pub worktree_scanned: bool,
    pub native_conflicts_checked: bool,
    pub restoration_performed: bool,
    pub preparation_performed: bool,
    pub native_authority: bool,
    pub cleanup_authority: bool,
    pub pending_resume_authority: bool,
    pub execution_available_from_preview: bool,
    pub new_operations_only: bool,
    pub historical_entry_ids_resurrected: bool,
    pub causal_vector_reset: bool,
    pub tree_atomic: bool,
}

impl ReadOnlyLocalSpace {
    pub fn restore_selection_preview_with_budget_file(
        data_dir: &std::path::Path,
        snapshot: SnapshotId,
        expected_baseline: Option<SnapshotId>,
        selection: RestoreSelection,
        destination_prefix: Option<PortablePath>,
        current_extra_policy: RestoreCurrentExtraPolicy,
        occupied_target_policy: RestoreOccupiedTargetPolicy,
        budgets: &std::path::Path,
    ) -> Result<RestoreSelectionPreview> {
        Self::restore_preview_available()?;
        selection.validate()?;
        #[cfg(target_os = "linux")]
        {
            crate::restore_preview::with_budget_source(data_dir, budgets, |reader, limits| {
                let (source, current) =
                    reader.selection_snapshots(&snapshot, expected_baseline.as_ref())?;
                let request = RestoreSelectionPreviewRequest {
                    format_version: 2,
                    space_id: source.space_id.clone(),
                    snapshot,
                    expected_baseline,
                    selection,
                    destination_prefix,
                    current_extra_policy,
                    occupied_target_policy,
                    limits,
                };
                project_restore_selection_preview(
                    &RestoreSelectionPreviewSource::closed_main(source, current),
                    &request,
                )
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                data_dir,
                snapshot,
                expected_baseline,
                selection,
                destination_prefix,
                current_extra_policy,
                occupied_target_policy,
                budgets,
            );
            Self::restore_preview_available()?;
            unreachable!()
        }
    }
}

fn charge(total: &mut u64, value: u64, limit: u64) -> Result<()> {
    *total = total.checked_add(value).filter(|sum| *sum <= limit).ok_or(
        ReconcileError::ResourceLimit("selection preview logical resource budget"),
    )?;
    Ok(())
}

fn entry_bytes(entry: Option<&Entry>) -> Option<u64> {
    entry.and_then(|entry| entry.content.as_ref().map(|file| file.length))
}

fn in_scope(roots: &[(PortablePath, EntryKind)], full: bool, path: &PortablePath) -> bool {
    full || roots.iter().any(|(root, kind)| {
        if *kind == EntryKind::Directory {
            contains_component_path(root, path)
        } else {
            root == path
        }
    })
}

/// The default entry point also bounds projection time. Live owners pass their
/// existing request deadline and cancellation flag to the same projector.
pub fn project_restore_selection_preview(
    source: &RestoreSelectionPreviewSource,
    request: &RestoreSelectionPreviewRequest,
) -> Result<RestoreSelectionPreview> {
    request.validate()?;
    let deadline = Instant::now() + Duration::from_millis(request.limits.source.max_query_millis);
    project_until(source, request, deadline, &AtomicBool::new(false))
}

pub(crate) fn project_until(
    source: &RestoreSelectionPreviewSource,
    request: &RestoreSelectionPreviewRequest,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<RestoreSelectionPreview> {
    use RestoreProposedOperation as Operation;
    use RestoreSelectionDifference as Difference;
    let check = || -> Result<()> {
        if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
            return Err(ReconcileError::ResourceLimit(
                "selection preview deadline or cancellation",
            ));
        }
        Ok(())
    };
    request.validate()?;
    check()?;
    if source.space_id != request.space_id
        || source.target.snapshot_id != request.snapshot
        || source.current.as_ref().map(|value| &value.snapshot_id)
            != source.current_snapshot.as_ref()
        || source.baseline.as_ref().map(|value| &value.snapshot_id)
            != request
                .expected_baseline
                .as_ref()
                .or(source.current_snapshot.as_ref())
    {
        return Err(ReconcileError::Invariant(
            "selection preview source binding differs",
        ));
    }
    match source.kind {
        RestoreSelectionSourceKind::ClosedMain => {
            if !source.source_image_bytes.is_some_and(|bytes| {
                (512..=request.limits.source.max_journal_bytes).contains(&bytes)
            }) || source.source_image_digest.is_none()
                || source.memory_header_projected.is_none()
            {
                return Err(ReconcileError::Invariant(
                    "selection preview closed-main provenance absent",
                ));
            }
        }
        RestoreSelectionSourceKind::LiveOwner => {
            if source.source_image_bytes.is_some()
                || source.source_image_digest.is_some()
                || source.memory_header_projected.is_some()
            {
                return Err(ReconcileError::Invariant(
                    "live preview cannot claim closed-main provenance",
                ));
            }
        }
    }
    for snapshot in [
        source.current.as_ref(),
        source.baseline.as_ref(),
        Some(&source.target),
    ]
    .into_iter()
    .flatten()
    {
        validate_source(snapshot, &source.space_id, request.limits.source)?;
        check()?;
    }
    if source
        .current
        .as_ref()
        .is_some_and(|value| value.metadata.is_none() || value.pruning.is_some())
    {
        return Err(ReconcileError::Invariant(
            "selection preview current root unavailable",
        ));
    }
    let current = source
        .current
        .as_ref()
        .and_then(|value| value.metadata.as_ref());
    let baseline = source
        .baseline
        .as_ref()
        .and_then(|value| value.metadata.as_ref());
    let target = source.target.metadata.as_ref();
    let policy_version = target.map(|value| value.manifest.policy_version);
    if [current, baseline]
        .into_iter()
        .flatten()
        .any(|value| policy_version.is_some_and(|version| version != value.manifest.policy_version))
    {
        return Err(ReconcileError::Invariant(
            "selection preview manifest policy versions differ",
        ));
    }
    validate_content_descriptions([current, baseline, target].into_iter().flatten())?;
    check()?;
    let all_target: BTreeMap<_, _> = target
        .into_iter()
        .flat_map(|value| value.manifest.entries.values())
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let all_current: BTreeMap<_, _> = current
        .into_iter()
        .flat_map(|value| value.manifest.entries.values())
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let full = matches!(request.selection, RestoreSelection::Full);
    let mut roots = Vec::new();
    let mut selection_status = if target.is_some() {
        "available"
    } else {
        "snapshot_missing"
    };
    if target.is_some() {
        for path in request.selection.explicit_paths() {
            match all_target.get(path) {
                Some(entry)
                    if matches!(&request.selection, RestoreSelection::File { .. })
                        && entry.kind != EntryKind::File =>
                {
                    selection_status = "source_is_not_file"
                }
                Some(entry)
                    if matches!(&request.selection, RestoreSelection::Directory { .. })
                        && entry.kind != EntryKind::Directory =>
                {
                    selection_status = "source_is_not_directory"
                }
                Some(entry) => roots.push((path.clone(), entry.kind)),
                None => selection_status = "source_path_missing",
            }
        }
    }
    let available = selection_status == "available";
    let mut selected_target = BTreeMap::new();
    for (path, entry) in &all_target {
        check()?;
        if available && in_scope(&roots, full, path) {
            selected_target.insert(
                destination_path(request.destination_prefix.as_ref(), path)?,
                *entry,
            );
        }
    }
    let mut selected_current = BTreeMap::new();
    for (path, entry) in &all_current {
        check()?;
        if available
            && source_relative_path(request.destination_prefix.as_ref(), path)
                .is_some_and(|relative| in_scope(&roots, full, &relative))
        {
            selected_current.insert(path.clone(), *entry);
        }
    }
    let cases: BTreeMap<_, _> = all_current
        .values()
        .map(|entry| (entry.path.collision_key(), *entry))
        .collect();
    let target_cases: BTreeMap<_, _> = selected_target
        .keys()
        .map(|path| (path.collision_key(), path))
        .collect();
    let names: BTreeMap<_, _> = all_current
        .values()
        .map(|entry| (entry.path.as_str(), *entry))
        .collect();
    let expected_is_current = request
        .expected_baseline
        .as_ref()
        .map(|id| source.current_snapshot.as_ref() == Some(id));
    let metadata_diff_available =
        available && current.is_some() && expected_is_current != Some(false);
    let mut counts = RestoreSelectionPreviewCounts {
        selected_target_entries: selected_target.len(),
        selected_current_entries: selected_current.len(),
        ..RestoreSelectionPreviewCounts::default()
    };
    let mut target_logical_bytes = 0u64;
    let mut unique_target_chunk_bytes = 0u64;
    let mut chunks = BTreeMap::<ContentId, u32>::new();
    for entry in selected_target.values() {
        check()?;
        if let Some(file) = &entry.content {
            counts.selected_target_files += 1;
            charge(
                &mut target_logical_bytes,
                file.length,
                request.limits.max_selected_logical_bytes,
            )?;
            counts.target_chunk_visits = counts
                .target_chunk_visits
                .checked_add(file.chunks.len())
                .filter(|count| *count <= request.limits.source.max_chunk_visits)
                .ok_or(ReconcileError::ResourceLimit(
                    "selection preview selected chunk visits",
                ))?;
            for chunk in &file.chunks {
                chunks.insert(chunk.content_id.clone(), chunk.length);
            }
        } else {
            counts.selected_target_directories += 1;
        }
    }
    for length in chunks.values() {
        charge(
            &mut unique_target_chunk_bytes,
            u64::from(*length),
            request.limits.max_selected_logical_bytes,
        )?;
    }
    counts.unique_target_cas_references = chunks.len();
    let paths: BTreeSet<_> = selected_target
        .keys()
        .chain(selected_current.keys())
        .cloned()
        .collect();
    let mut original_bytes = 0u64;
    let mut staging_bytes = 0u64;
    let mut metadata_bytes = 4096u64;
    charge(
        &mut metadata_bytes,
        counts.target_chunk_visits as u64 * 128,
        request.limits.max_resource_estimate_bytes,
    )?;
    let mut estimates_known = metadata_diff_available;
    let mut entries = Vec::new();
    for path in paths {
        check()?;
        let desired = selected_target.get(&path).copied();
        let old = all_current.get(&path).copied();
        let mut conflict_path = None;
        let mut structural_conflict = None;
        if desired.is_none() {
            if let Some(proposed) = target_cases.get(&path.collision_key()) {
                if **proposed != path {
                    structural_conflict = Some(Difference::CaseConflict);
                    conflict_path = Some((*proposed).clone());
                }
            }
        }
        if desired.is_some() {
            let parts: Vec<_> = path.as_str().split('/').collect();
            for depth in 1..=parts.len() {
                let ancestor = PortablePath::new(parts[..depth].join("/"))?;
                if let Some(prior) = cases.get(&ancestor.collision_key()) {
                    if prior.path != ancestor {
                        structural_conflict = Some(Difference::CaseConflict);
                        conflict_path = Some(prior.path.clone());
                        break;
                    }
                    if depth < parts.len() && prior.kind == EntryKind::File {
                        structural_conflict = Some(Difference::AncestorFileConflict);
                        conflict_path = Some(prior.path.clone());
                        break;
                    }
                }
            }
            if structural_conflict.is_none()
                && desired.is_some_and(|entry| entry.kind == EntryKind::File)
            {
                let prefix = format!("{path}/");
                if let Some((name, prior)) = names
                    .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                    .next()
                {
                    if name.starts_with(&prefix) {
                        structural_conflict = Some(Difference::TypeConflict);
                        conflict_path = Some(prior.path.clone());
                    }
                }
            }
        }
        let (difference, operation) = if !metadata_diff_available {
            (Difference::BaselineUnchecked, Operation::Unknown)
        } else if let Some(difference) = structural_conflict {
            (difference, Operation::ReportConflict)
        } else {
            match (old, desired) {
                (Some(old), Some(desired)) if old.kind != desired.kind => {
                    (Difference::TypeConflict, Operation::ReportConflict)
                }
                (Some(old), Some(desired)) if old.content == desired.content => {
                    (Difference::Unchanged, Operation::PreserveCurrent)
                }
                (Some(_), Some(_)) => (
                    Difference::FileContentsDiffer,
                    if request.occupied_target_policy == RestoreOccupiedTargetPolicy::ReplaceFiles {
                        Operation::NewReplaceFile
                    } else {
                        Operation::ReportConflict
                    },
                ),
                (None, Some(desired)) => (
                    Difference::TargetOnly,
                    if desired.kind == EntryKind::File {
                        Operation::NewCreateFile
                    } else {
                        Operation::NewCreateDirectory
                    },
                ),
                (Some(old), None) => (
                    Difference::CurrentOnly,
                    if request.current_extra_policy
                        == RestoreCurrentExtraPolicy::ReplaceSelectedScope
                    {
                        if old.kind == EntryKind::File {
                            Operation::NewDeleteFile
                        } else {
                            Operation::NewRemoveDirectory
                        }
                    } else {
                        Operation::PreserveCurrent
                    },
                ),
                (None, None) => {
                    return Err(ReconcileError::Invariant(
                        "selection preview union path absent",
                    ))
                }
            }
        };
        counts.compared_paths += 1;
        match operation {
            Operation::PreserveCurrent => counts.preserved_current_paths += 1,
            Operation::NewCreateFile => counts.proposed_create_files += 1,
            Operation::NewCreateDirectory => counts.proposed_create_directories += 1,
            Operation::NewReplaceFile => counts.proposed_replace_files += 1,
            Operation::NewDeleteFile => counts.proposed_delete_files += 1,
            Operation::NewRemoveDirectory => counts.proposed_remove_directories += 1,
            Operation::ReportConflict => {
                counts.reported_conflicts += 1;
                estimates_known = false;
            }
            Operation::Unknown => {
                counts.unchecked_paths += 1;
                estimates_known = false;
            }
        }
        if matches!(
            operation,
            Operation::NewReplaceFile | Operation::NewDeleteFile
        ) {
            charge(
                &mut original_bytes,
                entry_bytes(old).unwrap_or(0),
                request.limits.max_resource_estimate_bytes,
            )?;
        }
        if matches!(
            operation,
            Operation::NewCreateFile | Operation::NewReplaceFile
        ) {
            charge(
                &mut staging_bytes,
                entry_bytes(desired).unwrap_or(0),
                request.limits.max_resource_estimate_bytes,
            )?;
        }
        charge(
            &mut metadata_bytes,
            1024 + path.as_str().len() as u64 * 6,
            request.limits.max_resource_estimate_bytes,
        )?;
        if entries.len() < request.limits.max_output_entries {
            entries.push(RestoreSelectionPreviewEntry {
                source_path: desired.map(|entry| entry.path.clone()),
                destination_path: path,
                difference,
                proposed_operation: operation,
                current_kind: old.map(|entry| entry.kind),
                historical_kind: desired.map(|entry| entry.kind),
                current_content_id: old
                    .and_then(|entry| entry.content.as_ref().map(|file| file.content_id.clone())),
                historical_content_id: desired
                    .and_then(|entry| entry.content.as_ref().map(|file| file.content_id.clone())),
                current_bytes: entry_bytes(old),
                historical_bytes: entry_bytes(desired),
                conflict_path,
                native_state: "unchecked",
            });
        }
    }
    let mut combined = metadata_bytes;
    charge(
        &mut combined,
        original_bytes,
        request.limits.max_resource_estimate_bytes,
    )?;
    charge(
        &mut combined,
        staging_bytes,
        request.limits.max_resource_estimate_bytes,
    )?;
    let cas_references: Vec<_> = chunks
        .into_iter()
        .take(request.limits.max_output_cas_references)
        .map(|(content_id, length)| RestorePreviewCasReference {
            content_id,
            length,
            availability: "unchecked",
            retained_by_target_snapshot: target.map(|_| source.target.pruning.is_none()),
        })
        .collect();
    let mut preview = RestoreSelectionPreview {
        preview_format_version: 2,
        mode: "readonly_restore_selection_preview",
        space_id: source.space_id.clone(),
        current_snapshot_id: source.current_snapshot.clone(),
        baseline: source.baseline.as_ref().map(RestorePreviewSnapshot::from),
        target: RestorePreviewSnapshot::from(&source.target),
        selection: request.selection.clone(),
        destination_prefix: request.destination_prefix.clone(),
        destination_mapping: "prefix_plus_complete_source_relative_path",
        current_extra_policy: request.current_extra_policy,
        occupied_target_policy: request.occupied_target_policy,
        selection_status,
        expected_baseline_is_current: expected_is_current,
        metadata_diff_available,
        resources: RestorePreviewResources {
            target_logical_bytes,
            unique_target_chunk_bytes,
            baseline_original_bytes_estimate: estimates_known.then_some(original_bytes),
            staging_bytes_estimate: estimates_known.then_some(staging_bytes),
            metadata_bytes_estimate: metadata_bytes,
            estimate_basis: "new_operation_portable_path_and_chunk_descriptions_only",
            estimates_are_logical_only: true,
            physical_allocation_checked: false,
            free_space_checked: false,
            capacity_reserved: false,
        },
        entries_truncated: entries.len() < counts.compared_paths,
        entries_limit: request.limits.max_output_entries,
        entries,
        cas_references_truncated: cas_references.len() < counts.unique_target_cas_references,
        cas_references_limit: request.limits.max_output_cas_references,
        cas_references,
        counts,
        output_byte_limit: request.limits.max_output_bytes,
        output_bytes_including_lf: 0,
        source_image_bytes: source.source_image_bytes,
        source_image_digest: source.source_image_digest.clone(),
        memory_header_projected: source.memory_header_projected,
        source_interpretation: match source.kind {
            RestoreSelectionSourceKind::ClosedMain => {
                "closed_main_bytes_projected_to_readonly_owned_memory"
            }
            RestoreSelectionSourceKind::LiveOwner => "live_owner_deferred_transaction",
        },
        content_availability: if source.target.pruning.is_some() {
            "pruned"
        } else {
            "unchecked"
        },
        content_hashes_verified: false,
        history_hash_authenticated: false,
        worktree_scanned: false,
        native_conflicts_checked: false,
        restoration_performed: false,
        preparation_performed: false,
        native_authority: false,
        cleanup_authority: false,
        pending_resume_authority: false,
        execution_available_from_preview: false,
        new_operations_only: true,
        historical_entry_ids_resurrected: false,
        causal_vector_reset: false,
        tree_atomic: false,
    };
    loop {
        check()?;
        let length = encoded_length(&preview)? + 1;
        preview.output_bytes_including_lf = length;
        let actual = encoded_length(&preview)? + 1;
        if actual <= preview.output_byte_limit {
            if actual == length {
                break;
            }
            continue;
        }
        if !preview.cas_references.is_empty() {
            preview
                .cas_references
                .truncate(preview.cas_references.len() / 2);
            preview.cas_references_truncated = true;
        } else if !preview.entries.is_empty() {
            preview.entries.truncate(preview.entries.len() / 2);
            preview.entries_truncated = true;
        } else {
            return Err(ReconcileError::ResourceLimit(
                "selection preview fixed scope exceeds output budget",
            ));
        }
    }
    Ok(preview)
}

fn encoded_length(value: &impl Serialize) -> Result<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("selection preview output length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
