//! Inert retained-history source/diff projection. No mutable LocalSpace or TREE
//! preparation, CAS reader, reservation, scan, recovery or executor is called.
use crate::{ReadOnlyLocalSpace, ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    ContentId, Entry, EntryKind, FileManifest, PortablePath, SnapshotId, SpaceId,
};
use sync_extend_journal::{
    ReadOnlyRestorePreviewSource, ReadOnlySnapshotPreviewLimits, ReadOnlySnapshotPreviewSource,
    validate_preview_manifest,
};

#[cfg(not(target_os = "linux"))]
const PREVIEW_SOURCE_UNAVAILABLE: &str = "readonly restore preview requires the available Linux closed-main source capability; Windows same-handle no-atime source is unavailable on this build";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestorePreviewSelection {
    Full,
    File { path: PortablePath },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePreviewLimits {
    pub source: ReadOnlySnapshotPreviewLimits,
    pub max_output_entries: usize,
    pub max_output_cas_references: usize,
    /// Entire compact UTF-8 JSON response including its trailing line feed.
    pub max_output_bytes: usize,
    pub max_selected_logical_bytes: u64,
    pub max_resource_estimate_bytes: u64,
}

impl RestorePreviewLimits {
    pub fn validate(self) -> Result<()> {
        self.source.validate()?;
        if !(1..=4096).contains(&self.max_output_entries)
            || !(1..=4096).contains(&self.max_output_cas_references)
            || !(4096..=8 * 1024 * 1024).contains(&self.max_output_bytes)
            || self.max_selected_logical_bytes > 1 << 50
            || !(4096..=1 << 60).contains(&self.max_resource_estimate_bytes)
        {
            return Err(ReconcileError::Invariant(
                "explicit bounded readonly restore preview output and resource limits required",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePreviewRequest {
    pub format_version: u32,
    pub snapshot: SnapshotId,
    pub expected_baseline: Option<SnapshotId>,
    pub selection: RestorePreviewSelection,
    pub limits: RestorePreviewLimits,
}

impl RestorePreviewRequest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 {
            return Err(ReconcileError::Invariant(
                "unsupported readonly restore preview request version",
            ));
        }
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorePreviewSnapshot {
    pub snapshot_id: SnapshotId,
    pub exists: bool,
    pub created_at_ms: Option<u64>,
    pub recorded_state: Option<String>,
    pub locked: Option<bool>,
    pub content_retained: Option<bool>,
    pub pruned: Option<bool>,
    pub pruned_at_ms: Option<u64>,
    pub snapshot_metadata_validated: bool,
    pub manifest_entries: Option<usize>,
}

impl From<&ReadOnlySnapshotPreviewSource> for RestorePreviewSnapshot {
    fn from(source: &ReadOnlySnapshotPreviewSource) -> Self {
        let snapshot = source.metadata.as_ref();
        Self {
            snapshot_id: source.snapshot_id.clone(),
            exists: snapshot.is_some(),
            created_at_ms: snapshot.map(|value| value.created_at_ms),
            recorded_state: snapshot.map(|value| value.state.clone()),
            locked: snapshot.map(|value| value.locked),
            content_retained: snapshot.map(|_| source.pruning.is_none()),
            pruned: snapshot.map(|_| source.pruning.is_some()),
            pruned_at_ms: source.pruning.as_ref().map(|value| value.pruned_at_ms),
            snapshot_metadata_validated: snapshot.is_some(),
            manifest_entries: snapshot.map(|value| value.manifest.entries.len()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePreviewDifference {
    Unchanged,
    AddFile,
    AddDirectory,
    ReplaceFile,
    DeleteFile,
    RemoveDirectory,
    TypeConflict,
    CaseConflict,
    BaselineUnchecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorePreviewEntry {
    pub path: PortablePath,
    pub difference: RestorePreviewDifference,
    pub baseline_kind: Option<EntryKind>,
    pub target_kind: Option<EntryKind>,
    pub baseline_content_id: Option<ContentId>,
    pub target_content_id: Option<ContentId>,
    pub baseline_bytes: Option<u64>,
    pub target_bytes: Option<u64>,
    pub native_state: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorePreviewCasReference {
    pub content_id: ContentId,
    pub length: u32,
    pub availability: &'static str,
    pub retained_by_target_snapshot: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RestorePreviewCounts {
    pub selected_target_entries: usize,
    pub selected_target_files: usize,
    pub selected_target_directories: usize,
    pub selected_baseline_entries: usize,
    pub compared_paths: usize,
    pub unchanged_paths: usize,
    pub added_files: usize,
    pub added_directories: usize,
    pub replaced_files: usize,
    pub deleted_files: usize,
    pub removed_directories: usize,
    pub type_conflicts: usize,
    pub case_conflicts: usize,
    pub baseline_unchecked_paths: usize,
    pub target_chunk_visits: usize,
    pub unique_target_cas_references: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorePreviewResources {
    pub target_logical_bytes: u64,
    pub unique_target_chunk_bytes: u64,
    pub baseline_original_bytes_estimate: Option<u64>,
    pub staging_bytes_estimate: Option<u64>,
    pub metadata_bytes_estimate: u64,
    pub estimate_basis: &'static str,
    pub estimates_are_logical_only: bool,
    pub physical_allocation_checked: bool,
    pub free_space_checked: bool,
    pub capacity_reserved: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorePreview {
    pub preview_format_version: u32,
    pub mode: &'static str,
    pub space_id: SpaceId,
    pub current_snapshot_id: Option<SnapshotId>,
    pub baseline: Option<RestorePreviewSnapshot>,
    pub target: RestorePreviewSnapshot,
    pub selection: RestorePreviewSelection,
    pub selection_status: &'static str,
    pub expected_baseline_is_current: Option<bool>,
    pub metadata_diff_available: bool,
    pub counts: RestorePreviewCounts,
    pub resources: RestorePreviewResources,
    pub entries: Vec<RestorePreviewEntry>,
    pub entries_limit: usize,
    pub entries_truncated: bool,
    pub cas_references: Vec<RestorePreviewCasReference>,
    pub cas_references_limit: usize,
    pub cas_references_truncated: bool,
    pub output_byte_limit: usize,
    pub output_bytes_including_lf: usize,
    pub source_image_bytes: u64,
    pub source_image_digest: ContentId,
    pub memory_header_projected: bool,
    pub source_interpretation: &'static str,
    pub history_hash_authenticated: bool,
    pub content_hashes_verified: bool,
    pub content_availability: &'static str,
    pub worktree_scanned: bool,
    pub native_conflicts_checked: bool,
    pub restoration_performed: bool,
    pub preparation_performed: bool,
    pub native_authority: bool,
    pub cleanup_authority: bool,
    pub pending_resume_authority: bool,
    pub tree_atomic: bool,
    pub execution_available_from_preview: bool,
    pub historical_entry_ids_resurrected: bool,
    pub causal_vector_reset: bool,
    pub portable_file_times_supported: bool,
    pub portable_file_attributes_supported: bool,
    pub windows_acl_supported: bool,
    pub alternate_data_streams_supported: bool,
}

impl ReadOnlyLocalSpace {
    /// Pure platform capability gate. Call before opening any node or control
    /// input, including when the caller cannot decode its request yet.
    pub fn restore_preview_available() -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ReconcileError::Invariant(PREVIEW_SOURCE_UNAVAILABLE))
        }
    }

    /// Retain and preflight the original source before reading an explicitly
    /// bounded no-atime control input. Transfer the same source guard into the
    /// standalone memory reader only after its typed byte bound is validated.
    pub fn restore_preview_with_budget_file(
        data_dir: &std::path::Path,
        snapshot: SnapshotId,
        expected_baseline: Option<SnapshotId>,
        selection: RestorePreviewSelection,
        budgets: &std::path::Path,
    ) -> Result<RestorePreview> {
        Self::restore_preview_available()?;
        #[cfg(target_os = "linux")]
        {
            let files = sync_extend_platform_fs::ReadOnlyJournalFiles::preflight(
                &data_dir.join("journal.sqlite"),
            )?;
            let input = sync_extend_platform_fs::ReadOnlyControlInput::open(budgets, &files)?;
            let original_digest = ContentId::hash(input.bytes());
            let result = (|| {
                let request = RestorePreviewRequest {
                    format_version: 1,
                    snapshot,
                    expected_baseline,
                    selection,
                    limits: serde_json::from_slice(input.bytes())?,
                };
                request.validate()?;
                input.verify()?;
                let reader =
                    sync_extend_journal::ReadOnlyRestorePreviewJournal::from_existing_files(
                        files,
                        request.limits.source,
                    )?;
                let source =
                    reader.snapshots(&request.snapshot, request.expected_baseline.as_ref())?;
                let preview = project_restore_preview(&source, &request)?;
                reader.verify()?;
                Ok(preview)
            })();
            // Success and typed control-input refusal both recheck the retained
            // original raw bytes, name chain, identity and descriptor owner.
            if ContentId::hash(&input.read_verified()?) != original_digest {
                return Err(ReconcileError::Invariant(
                    "readonly restore preview control input digest changed",
                ));
            }
            result
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (data_dir, snapshot, expected_baseline, selection, budgets);
            Err(ReconcileError::Invariant(PREVIEW_SOURCE_UNAVAILABLE))
        }
    }

    /// Existing-only source observation. This associated readonly entry avoids
    /// the old `open` constructor's create-capable sentinel/SQLite path open.
    pub fn restore_preview(
        data_dir: &std::path::Path,
        request: &RestorePreviewRequest,
    ) -> Result<RestorePreview> {
        Self::restore_preview_available()?;
        request.validate()?;
        #[cfg(target_os = "linux")]
        {
            let reader = sync_extend_journal::ReadOnlyRestorePreviewJournal::open(
                &data_dir.join("journal.sqlite"),
                request.limits.source,
            )?;
            let source = reader.snapshots(&request.snapshot, request.expected_baseline.as_ref())?;
            let preview = project_restore_preview(&source, request)?;
            reader.verify()?;
            Ok(preview)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = data_dir;
            Err(ReconcileError::Invariant(PREVIEW_SOURCE_UNAVAILABLE))
        }
    }
}

fn add(total: &mut u64, value: u64, limit: u64) -> Result<()> {
    *total = total
        .checked_add(value)
        .filter(|total| *total <= limit)
        .ok_or(ReconcileError::ResourceLimit(
            "readonly restore preview logical resource budget",
        ))?;
    Ok(())
}

fn validate_source(
    source: &ReadOnlySnapshotPreviewSource,
    space: &SpaceId,
    bounds: ReadOnlySnapshotPreviewLimits,
) -> Result<()> {
    let Some(snapshot) = &source.metadata else {
        if source.pruning.is_some() {
            return Err(ReconcileError::Invariant(
                "readonly restore preview missing snapshot has pruning",
            ));
        }
        return Ok(());
    };
    validate_preview_manifest(&snapshot.manifest, bounds)?;
    if snapshot.snapshot_id != source.snapshot_id
        || snapshot.manifest.space_id != *space
        || snapshot.manifest.root()? != source.snapshot_id
        || !matches!(
            snapshot.state.as_str(),
            "metadata_only" | "content_closed" | "materialized"
        )
        || source.pruning.as_ref().is_some_and(|pruning| {
            pruning.space_id != *space
                || pruning.snapshot_id != source.snapshot_id
                || pruning.format_version != 1
                || pruning.baseline_root == source.snapshot_id
                || snapshot.locked
                || snapshot.state != "materialized"
        })
    {
        return Err(ReconcileError::Invariant(
            "readonly restore preview typed snapshot metadata mismatch",
        ));
    }
    Ok(())
}

fn bytes(entry: Option<&Entry>) -> Option<u64> {
    entry.and_then(|entry| entry.content.as_ref().map(|content| content.length))
}

/// Complete bounded typed diff. A caller-supplied projection cannot mint any
/// authority: every execution, cleanup, resume and recovery flag is fixed false.
pub fn project_restore_preview(
    source: &ReadOnlyRestorePreviewSource,
    request: &RestorePreviewRequest,
) -> Result<RestorePreview> {
    request.validate()?;
    if !(512..=request.limits.source.max_journal_bytes).contains(&source.source_image_bytes) {
        return Err(ReconcileError::ResourceLimit(
            "readonly restore preview physical source image bound",
        ));
    }
    if source.target.snapshot_id != request.snapshot {
        return Err(ReconcileError::Invariant(
            "readonly restore preview target request differs",
        ));
    }
    let expected_baseline = request
        .expected_baseline
        .as_ref()
        .or(source.current_snapshot.as_ref());
    if source
        .baseline
        .as_ref()
        .map(|baseline| &baseline.snapshot_id)
        != expected_baseline
    {
        return Err(ReconcileError::Invariant(
            "readonly restore preview baseline request differs",
        ));
    }
    validate_source(&source.target, &source.space_id, request.limits.source)?;
    if let Some(baseline) = &source.baseline {
        validate_source(baseline, &source.space_id, request.limits.source)?;
    }
    let baseline = source
        .baseline
        .as_ref()
        .and_then(|source| source.metadata.as_ref());
    let target = source.target.metadata.as_ref();
    if baseline.zip(target).is_some_and(|(baseline, target)| {
        baseline.manifest.policy_version != target.manifest.policy_version
    }) {
        return Err(ReconcileError::Invariant(
            "readonly restore preview manifest policy versions differ",
        ));
    }
    // Conflicting file/chunk descriptions are metadata corruption, even before
    // CAS availability is checked. Never treat a hash as authenticated bytes.
    let mut file_descriptions = BTreeMap::<ContentId, &FileManifest>::new();
    let mut chunk_descriptions = BTreeMap::<ContentId, u32>::new();
    for snapshot in [baseline, target].into_iter().flatten() {
        for content in snapshot
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            if file_descriptions
                .insert(content.content_id.clone(), content)
                .is_some_and(|previous| previous != content)
            {
                return Err(ReconcileError::Invariant(
                    "readonly restore preview conflicting file description",
                ));
            }
            for chunk in &content.chunks {
                if chunk_descriptions
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|previous| previous != chunk.length)
                {
                    return Err(ReconcileError::Invariant(
                        "readonly restore preview conflicting chunk length",
                    ));
                }
            }
        }
    }
    let all_baseline: BTreeMap<_, _> = baseline
        .into_iter()
        .flat_map(|snapshot| snapshot.manifest.entries.values())
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let all_target: BTreeMap<_, _> = target
        .into_iter()
        .flat_map(|snapshot| snapshot.manifest.entries.values())
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let (selected_target, selected_baseline, selection_status) = match &request.selection {
        RestorePreviewSelection::Full => (
            all_target.clone(),
            if target.is_some() {
                all_baseline.clone()
            } else {
                BTreeMap::new()
            },
            if target.is_some() {
                "available"
            } else {
                "snapshot_missing"
            },
        ),
        RestorePreviewSelection::File { path } => match all_target.get(path) {
            Some(entry) if entry.kind == EntryKind::File => (
                BTreeMap::from([(path.clone(), *entry)]),
                all_baseline
                    .get(path)
                    .map(|entry| BTreeMap::from([(path.clone(), *entry)]))
                    .unwrap_or_default(),
                "available",
            ),
            Some(_) => (BTreeMap::new(), BTreeMap::new(), "source_is_not_file"),
            None => (
                BTreeMap::new(),
                BTreeMap::new(),
                if target.is_some() {
                    "source_path_missing"
                } else {
                    "snapshot_missing"
                },
            ),
        },
    };
    let baseline_cases: BTreeMap<_, _> = all_baseline
        .values()
        .map(|entry| (entry.path.collision_key(), *entry))
        .collect();
    let mut case_conflicts = BTreeSet::new();
    for entry in selected_target.values() {
        if let Some(prior) = baseline_cases.get(&entry.path.collision_key()) {
            if prior.path != entry.path {
                case_conflicts.insert(prior.path.clone());
                case_conflicts.insert(entry.path.clone());
            }
        }
    }
    let mut counts = RestorePreviewCounts {
        selected_target_entries: selected_target.len(),
        selected_baseline_entries: selected_baseline.len(),
        ..RestorePreviewCounts::default()
    };
    let mut target_logical_bytes = 0u64;
    let mut unique_target_chunk_bytes = 0u64;
    let mut target_chunks = BTreeMap::<ContentId, u32>::new();
    for entry in selected_target.values() {
        if let Some(content) = &entry.content {
            counts.selected_target_files += 1;
            add(
                &mut target_logical_bytes,
                content.length,
                request.limits.max_selected_logical_bytes,
            )?;
            counts.target_chunk_visits = counts
                .target_chunk_visits
                .checked_add(content.chunks.len())
                .filter(|count| *count <= request.limits.source.max_chunk_visits)
                .ok_or(ReconcileError::ResourceLimit(
                    "readonly restore preview selected chunk visits",
                ))?;
            for chunk in &content.chunks {
                target_chunks.insert(chunk.content_id.clone(), chunk.length);
            }
        } else {
            counts.selected_target_directories += 1;
        }
    }
    for length in target_chunks.values() {
        add(
            &mut unique_target_chunk_bytes,
            u64::from(*length),
            request.limits.max_selected_logical_bytes,
        )?;
    }
    counts.unique_target_cas_references = target_chunks.len();
    let paths: BTreeSet<_> = selected_baseline
        .keys()
        .chain(selected_target.keys())
        .cloned()
        .collect();
    let metadata_diff_available =
        baseline.is_some() && target.is_some() && selection_status == "available";
    let mut original_bytes = 0u64;
    let mut staging_bytes = 0u64;
    let mut metadata_bytes = 4096u64;
    add(
        &mut metadata_bytes,
        counts.target_chunk_visits as u64 * 128,
        request.limits.max_resource_estimate_bytes,
    )?;
    let mut entries = Vec::new();
    for path in paths {
        let old = selected_baseline.get(&path).copied();
        let desired = selected_target.get(&path).copied();
        let difference = if !metadata_diff_available {
            RestorePreviewDifference::BaselineUnchecked
        } else if case_conflicts.contains(&path) {
            RestorePreviewDifference::CaseConflict
        } else {
            match (old, desired) {
                (Some(old), Some(desired)) if old.kind != desired.kind => {
                    RestorePreviewDifference::TypeConflict
                }
                (Some(old), Some(desired)) if old.content == desired.content => {
                    RestorePreviewDifference::Unchanged
                }
                (Some(_), Some(_)) => RestorePreviewDifference::ReplaceFile,
                (None, Some(desired)) if desired.kind == EntryKind::File => {
                    RestorePreviewDifference::AddFile
                }
                (None, Some(_)) => RestorePreviewDifference::AddDirectory,
                (Some(old), None) if old.kind == EntryKind::File => {
                    RestorePreviewDifference::DeleteFile
                }
                (Some(_), None) => RestorePreviewDifference::RemoveDirectory,
                (None, None) => unreachable!("union path has one entry"),
            }
        };
        counts.compared_paths += 1;
        match difference {
            RestorePreviewDifference::Unchanged => counts.unchanged_paths += 1,
            RestorePreviewDifference::AddFile => counts.added_files += 1,
            RestorePreviewDifference::AddDirectory => counts.added_directories += 1,
            RestorePreviewDifference::ReplaceFile => counts.replaced_files += 1,
            RestorePreviewDifference::DeleteFile => counts.deleted_files += 1,
            RestorePreviewDifference::RemoveDirectory => counts.removed_directories += 1,
            RestorePreviewDifference::TypeConflict => counts.type_conflicts += 1,
            RestorePreviewDifference::CaseConflict => counts.case_conflicts += 1,
            RestorePreviewDifference::BaselineUnchecked => counts.baseline_unchecked_paths += 1,
        }
        if metadata_diff_available && difference != RestorePreviewDifference::Unchanged {
            add(
                &mut original_bytes,
                bytes(old).unwrap_or(0),
                request.limits.max_resource_estimate_bytes,
            )?;
            add(
                &mut staging_bytes,
                bytes(desired).unwrap_or(0),
                request.limits.max_resource_estimate_bytes,
            )?;
        }
        add(
            &mut metadata_bytes,
            1024 + path.as_str().len() as u64 * 6,
            request.limits.max_resource_estimate_bytes,
        )?;
        if entries.len() < request.limits.max_output_entries {
            let old = old.or_else(|| {
                (difference == RestorePreviewDifference::CaseConflict)
                    .then(|| baseline_cases.get(&path.collision_key()).copied())
                    .flatten()
            });
            entries.push(RestorePreviewEntry {
                path,
                difference,
                baseline_kind: old.map(|entry| entry.kind),
                target_kind: desired.map(|entry| entry.kind),
                baseline_content_id: old.and_then(|entry| {
                    entry
                        .content
                        .as_ref()
                        .map(|content| content.content_id.clone())
                }),
                target_content_id: desired.and_then(|entry| {
                    entry
                        .content
                        .as_ref()
                        .map(|content| content.content_id.clone())
                }),
                baseline_bytes: bytes(old),
                target_bytes: bytes(desired),
                native_state: "unchecked",
            });
        }
    }
    let cas_references = target_chunks
        .into_iter()
        .take(request.limits.max_output_cas_references)
        .map(|(content_id, length)| RestorePreviewCasReference {
            content_id,
            length,
            availability: "unchecked",
            retained_by_target_snapshot: target.map(|_| source.target.pruning.is_none()),
        })
        .collect::<Vec<_>>();
    let mut preview = RestorePreview {
        preview_format_version: 1,
        mode: "readonly_retained_restore_preview",
        space_id: source.space_id.clone(),
        current_snapshot_id: source.current_snapshot.clone(),
        baseline: source.baseline.as_ref().map(RestorePreviewSnapshot::from),
        target: RestorePreviewSnapshot::from(&source.target),
        selection: request.selection.clone(),
        selection_status,
        expected_baseline_is_current: request
            .expected_baseline
            .as_ref()
            .map(|expected| Some(expected) == source.current_snapshot.as_ref()),
        metadata_diff_available,
        resources: RestorePreviewResources {
            target_logical_bytes,
            unique_target_chunk_bytes,
            baseline_original_bytes_estimate: (metadata_diff_available
                && counts.case_conflicts == 0)
                .then_some(original_bytes),
            staging_bytes_estimate: (metadata_diff_available && counts.case_conflicts == 0)
                .then_some(staging_bytes),
            metadata_bytes_estimate: metadata_bytes,
            estimate_basis: "portable_path_and_chunk_descriptions_only",
            estimates_are_logical_only: true,
            physical_allocation_checked: false,
            free_space_checked: false,
            capacity_reserved: false,
        },
        entries_limit: request.limits.max_output_entries,
        entries_truncated: entries.len() < counts.compared_paths,
        entries,
        cas_references_limit: request.limits.max_output_cas_references,
        cas_references_truncated: cas_references.len() < counts.unique_target_cas_references,
        cas_references,
        counts,
        output_byte_limit: request.limits.max_output_bytes,
        output_bytes_including_lf: 0,
        source_image_bytes: source.source_image_bytes,
        source_image_digest: source.source_image_digest.clone(),
        memory_header_projected: source.memory_header_projected,
        source_interpretation: "closed_main_bytes_projected_to_readonly_owned_memory",
        history_hash_authenticated: false,
        content_hashes_verified: false,
        content_availability: "unchecked",
        worktree_scanned: false,
        native_conflicts_checked: false,
        restoration_performed: false,
        preparation_performed: false,
        native_authority: false,
        cleanup_authority: false,
        pending_resume_authority: false,
        tree_atomic: false,
        execution_available_from_preview: false,
        historical_entry_ids_resurrected: false,
        causal_vector_reset: false,
        portable_file_times_supported: false,
        portable_file_attributes_supported: false,
        windows_acl_supported: false,
        alternate_data_streams_supported: false,
    };
    loop {
        let length = serde_json::to_vec(&preview)?.len() + 1;
        preview.output_bytes_including_lf = length;
        let length = serde_json::to_vec(&preview)?.len() + 1;
        if length <= preview.output_byte_limit {
            if preview.output_bytes_including_lf == length {
                break;
            }
            continue;
        }
        // Retain deterministic prefixes and complete counts. Halving avoids a
        // quadratic serialize/remove loop with adversarial long portable paths.
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
                "readonly restore preview fixed response exceeds output byte budget",
            ));
        }
    }
    Ok(preview)
}
