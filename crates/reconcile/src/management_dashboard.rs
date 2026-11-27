//! Bounded observations taken from the existing owner; never opens a second worktree.
use crate::{LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{
    ContentId, DeviceId, EntryId, EntryKind, PortableEntryMetadata,
    PortableMetadataCapabilityMatrix, PortableMetadataCertification,
    PortableMetadataFieldCapability, PortableMetadataSupport, PortableMetadataUnsupportedFields,
    PortableMetadataUnsupportedReason, PortablePath, SnapshotId, SpaceId,
    PORTABLE_METADATA_CAPABILITY_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DashboardEntryTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// Display projection of a captured source entry. Only fields with actual
/// captured values are emitted; unknown/unsupported source fields stay absent
/// so a client cannot mistake capability for a per-file result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DashboardEntryMetadata {
    pub format_version: u32,
    pub modified: DashboardEntryTimestamp,
    pub readonly: bool,
}

#[derive(Serialize)]
pub struct DashboardEntry {
    pub entry_id: EntryId,
    pub path: PortablePath,
    pub kind: EntryKind,
    pub logical_bytes: Option<u64>,
    pub metadata: Option<DashboardEntryMetadata>,
}

#[derive(Serialize)]
pub struct DashboardSnapshot {
    pub snapshot_id: SnapshotId,
    pub state: String,
    pub current: bool,
    pub created_at_ms: u64,
    pub locked: bool,
    pub content_retained: bool,
    pub pruned_at_ms: Option<u64>,
}

#[derive(Serialize)]
pub struct RestorePreviewOwnerContext {
    pub space_id: SpaceId,
    pub current_snapshot_id: Option<SnapshotId>,
    pub snapshots: Vec<DashboardSnapshot>,
    pub snapshots_limit: usize,
    pub snapshots_truncated: bool,
}

impl DashboardSnapshot {
    fn from_audit(
        snapshot: &sync_extend_journal::SnapshotAudit,
        current: Option<&SnapshotId>,
    ) -> Self {
        Self {
            snapshot_id: snapshot.snapshot_id.clone(),
            state: snapshot.state.clone(),
            current: current == Some(&snapshot.snapshot_id),
            created_at_ms: snapshot.created_at_ms,
            locked: snapshot.locked,
            content_retained: snapshot.content_retained,
            pruned_at_ms: snapshot.pruning.as_ref().map(|record| record.pruned_at_ms),
        }
    }
}

#[derive(Serialize)]
pub struct DashboardRecovery {
    pub retained_snapshots: usize,
    pub pruned_snapshots: usize,
    pub pruned_history: Vec<DashboardSnapshot>,
    pub pruned_history_truncated: bool,
    pub metadata_snapshot_consistent: bool,
    pub historical_content_hashes_verified: bool,
    pub restore_command: &'static str,
    pub whole_tree_restore_command: Option<&'static str>,
    pub recovered_archive_command: Option<&'static str>,
    pub restoration_performed: bool,
    pub native_authority: bool,
    pub cleanup_authority: bool,
    pub pending_resume_authority: bool,
}

#[derive(Serialize)]
pub struct DashboardConflict {
    pub transaction_id: EntryId,
    pub resolution_applied: bool,
    pub worktree_materialized: bool,
}

#[derive(Serialize)]
pub struct DashboardChunkCheck {
    pub checked_chunks: usize,
    pub checked_bytes: u64,
    pub total_current_chunks: usize,
    pub unavailable_chunks: Vec<ContentId>,
    pub all_current_chunks_checked: bool,
}

#[derive(Serialize)]
pub struct DashboardObservation {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub snapshot_id: Option<SnapshotId>,
    pub total_entries: usize,
    pub entries: Vec<DashboardEntry>,
    pub entries_truncated: bool,
    pub total_snapshots: usize,
    pub snapshots: Vec<DashboardSnapshot>,
    pub snapshots_truncated: bool,
    pub conflict_admissions: Vec<DashboardConflict>,
    pub conflict_admissions_truncated: bool,
    pub outstanding_publications: usize,
    pub outstanding_mutations: usize,
    pub chunks: DashboardChunkCheck,
    pub read_leases: DashboardReadLeases,
    pub metadata_capabilities: PortableMetadataCapabilityMatrix,
    pub recovery: DashboardRecovery,
    pub remote_backup_complete: bool,
}

#[derive(Serialize)]
pub struct DashboardReadLeases {
    pub total: usize,
    pub active: usize,
    pub expired_pending_recovery: usize,
    pub explicit_recovery_required: bool,
}

impl LocalSpace {
    pub fn management_restore_preview_space(&self) -> &SpaceId {
        &self.space_id
    }

    pub fn management_restore_preview_context(
        &mut self,
        bounds: sync_extend_journal::ReadOnlySnapshotPreviewLimits,
        deadline: std::time::Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<RestorePreviewOwnerContext> {
        let (space_id, current_snapshot_id, sources, snapshots_truncated) = self
            .journal
            .restore_preview_context(&self.space_id, bounds, deadline, cancelled)?;
        let mut snapshots = Vec::new();
        for source in sources {
            let snapshot = source
                .metadata
                .ok_or(ReconcileError::Invariant("context snapshot absent"))?;
            snapshots.push(DashboardSnapshot {
                current: current_snapshot_id.as_ref() == Some(&snapshot.snapshot_id),
                snapshot_id: snapshot.snapshot_id,
                state: snapshot.state,
                created_at_ms: snapshot.created_at_ms,
                locked: snapshot.locked,
                content_retained: source.pruning.is_none(),
                pruned_at_ms: source.pruning.map(|pruning| pruning.pruned_at_ms),
            });
        }
        Ok(RestorePreviewOwnerContext {
            space_id,
            current_snapshot_id,
            snapshots,
            snapshots_limit: 128,
            snapshots_truncated,
        })
    }

    /// Pure history metadata on this live owner, with no root/CAS/scan access.
    pub fn management_restore_preview(
        &mut self,
        request: &crate::RestoreSelectionPreviewRequest,
        deadline: std::time::Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<crate::RestoreSelectionPreview> {
        request.validate()?;
        if request.space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "live preview owner space differs",
            ));
        }
        let (space_id, current_snapshot, current, baseline, target) =
            self.journal.restore_preview_metadata(
                &self.space_id,
                &request.snapshot,
                request.expected_baseline.as_ref(),
                request.limits.source,
                deadline,
                cancelled.clone(),
            )?;
        crate::restore_selection_preview::project_until(
            &crate::RestoreSelectionPreviewSource {
                kind: crate::RestoreSelectionSourceKind::LiveOwner,
                space_id,
                current_snapshot,
                current,
                baseline,
                target,
                source_image_bytes: None,
                source_image_digest: None,
                memory_header_projected: None,
            },
            request,
            deadline,
            &cancelled,
        )
    }

    /// Use one validated metadata snapshot, retain CAS coordination, and bound
    /// both response records and content verification. No native effect is issued.
    pub fn management_dashboard(&self) -> Result<DashboardObservation> {
        self.verify_root()?;
        self.journal
            .with_gc_diagnostics(&self.space_id, self.limits.max_storage_entries, |gc| {
                let status = self.status_in_snapshot(gc)?;
                let leases = self.read_leases()?;
                let observed_at = crate::now_ms()?;
                let active = leases
                    .iter()
                    .filter(|lease| lease.state == sync_extend_journal::ReadLeaseState::Active)
                    .count();
                let expired_pending_recovery = leases
                    .iter()
                    .filter(|lease| {
                        lease.state == sync_extend_journal::ReadLeaseState::Active
                            && lease.expires_at_ms <= observed_at
                    })
                    .count();
                let read_leases = DashboardReadLeases {
                    total: leases.len(),
                    active,
                    expired_pending_recovery,
                    explicit_recovery_required: expired_pending_recovery != 0,
                };
                let manifest = self.manifest()?;
                // Use the typed snapshot/pruning audit within this same
                // existing read transaction. Historical content is not read.
                let snapshots = self
                    .journal
                    .snapshot_audit(&self.space_id, self.limits.max_storage_entries)?;
                let retained_snapshots = snapshots
                    .iter()
                    .filter(|snapshot| snapshot.content_retained)
                    .count();
                let pruned_snapshots = snapshots.len() - retained_snapshots;
                let recovery = DashboardRecovery {
                    retained_snapshots,
                    pruned_snapshots,
                    pruned_history: snapshots
                        .iter()
                        .rev()
                        .filter(|snapshot| !snapshot.content_retained)
                        .take(16)
                        .map(|snapshot| {
                            DashboardSnapshot::from_audit(snapshot, status.snapshot_id.as_ref())
                        })
                        .collect(),
                    pruned_history_truncated: pruned_snapshots > 16,
                    metadata_snapshot_consistent: true,
                    historical_content_hashes_verified: false,
                    restore_command: "restore",
                    whole_tree_restore_command: cfg!(windows).then_some("tree-prepare"),
                    recovered_archive_command: cfg!(windows).then_some("recovered-local"),
                    restoration_performed: false,
                    native_authority: false,
                    cleanup_authority: false,
                    pending_resume_authority: false,
                };
                let admissions = self
                    .journal
                    .conflict_resolution_admissions(&self.space_id)?;
                let mut entries = Vec::new();
                let mut chunks = DashboardChunkCheck {
                    checked_chunks: 0,
                    checked_bytes: 0,
                    total_current_chunks: 0,
                    unavailable_chunks: Vec::new(),
                    all_current_chunks_checked: false,
                };
                let mut eligible = Vec::new();
                if let Some(manifest) = &manifest {
                    for entry in manifest.entries.values() {
                        if entries.len() < 128 {
                            entries.push(DashboardEntry {
                                entry_id: entry.entry_id.clone(),
                                path: entry.path.clone(),
                                kind: entry.kind,
                                logical_bytes: entry.content.as_ref().map(|file| file.length),
                                metadata: DashboardEntryMetadata::project(entry.metadata.as_ref()),
                            });
                        }
                        if let Some(file) = &entry.content {
                            chunks.total_current_chunks = chunks
                                .total_current_chunks
                                .checked_add(file.chunks.len())
                                .ok_or(ReconcileError::ResourceLimit("dashboard chunk count"))?;
                            for chunk in &file.chunks {
                                if eligible.len() < 64
                                    && chunks.checked_bytes + u64::from(chunk.length)
                                        <= 16 * 1024 * 1024
                                {
                                    chunks.checked_bytes += u64::from(chunk.length);
                                    eligible.push(chunk.clone());
                                }
                            }
                        }
                    }
                }
                for chunk in eligible {
                    chunks.checked_chunks += 1;
                    // Refused access, missing bytes and corrupt bytes all remain
                    // unavailable; this observation does not relax the CAS gate.
                    if self.cas.read(&chunk).is_err() {
                        chunks.unavailable_chunks.push(chunk.content_id);
                    }
                }
                chunks.all_current_chunks_checked =
                    chunks.checked_chunks == chunks.total_current_chunks;
                let observation = DashboardObservation {
                    space_id: self.space_id.clone(),
                    device_id: self.device_id.clone(),
                    snapshot_id: status.snapshot_id.clone(),
                    total_entries: status.entries,
                    entries_truncated: status.entries > entries.len(),
                    entries,
                    total_snapshots: retained_snapshots,
                    snapshots_truncated: retained_snapshots > 128,
                    snapshots: snapshots
                        .iter()
                        .rev()
                        .filter(|snapshot| snapshot.content_retained)
                        .take(128)
                        .map(|snapshot| {
                            DashboardSnapshot::from_audit(snapshot, status.snapshot_id.as_ref())
                        })
                        .collect(),
                    conflict_admissions_truncated: admissions.len() > 128,
                    conflict_admissions: admissions
                        .into_iter()
                        .take(128)
                        .map(|admission| DashboardConflict {
                            transaction_id: admission.transaction_id,
                            resolution_applied: admission.resolution_applied,
                            worktree_materialized: admission.worktree_materialized,
                        })
                        .collect(),
                    outstanding_publications: status.outstanding_publications,
                    outstanding_mutations: status.outstanding_mutations,
                    chunks,
                    read_leases,
                    metadata_capabilities: portable_metadata_capability_matrix(),
                    recovery,
                    remote_backup_complete: false,
                };
                self.verify_root()?;
                Ok(observation)
            })
    }
}

impl DashboardEntryMetadata {
    fn project(metadata: Option<&PortableEntryMetadata>) -> Option<Self> {
        let metadata = metadata?;
        let (seconds, nanoseconds, readonly) = metadata.captured_modified_and_readonly()?;
        Some(Self {
            format_version: metadata.format_version,
            modified: DashboardEntryTimestamp {
                seconds,
                nanoseconds,
            },
            readonly,
        })
    }
}

fn supported(value: bool) -> PortableMetadataSupport {
    if value {
        PortableMetadataSupport::Supported
    } else {
        PortableMetadataSupport::Unsupported
    }
}

/// Reports the exact implemented handle-based routine for this build. The
/// certification names the grouped acceptance that backs it; an untested Unix
/// build stays explicitly uncertified instead of borrowing Windows NTFS
/// results. FAT/exFAT, emulated volumes, KernelSU, ACLs and ADS are never
/// inferred from this matrix.
pub(crate) fn portable_metadata_capability_matrix() -> PortableMetadataCapabilityMatrix {
    #[cfg(windows)]
    {
        let fields = PortableMetadataFieldCapability {
            modified: supported(true),
            creation: supported(true),
            readonly: supported(true),
            unix_executable: supported(false),
        };
        return PortableMetadataCapabilityMatrix {
            format_version: PORTABLE_METADATA_CAPABILITY_VERSION,
            capture: fields,
            apply: fields,
            verify: fields,
            timestamp_precision_ns: Some(
                sync_extend_platform_fs::WINDOWS_NTFS_TIME_RESOLUTION_NANOS,
            ),
            unsupported: PortableMetadataUnsupportedFields {
                creation: None,
                unix_executable: Some(PortableMetadataUnsupportedReason::Platform),
            },
            certification: PortableMetadataCertification::WindowsNtfsActualGroupedAcceptance,
        };
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fields = PortableMetadataFieldCapability {
            modified: PortableMetadataSupport::Unknown,
            creation: supported(false),
            readonly: PortableMetadataSupport::Unknown,
            unix_executable: PortableMetadataSupport::Unknown,
        };
        return PortableMetadataCapabilityMatrix {
            format_version: PORTABLE_METADATA_CAPABILITY_VERSION,
            capture: fields,
            apply: fields,
            verify: fields,
            timestamp_precision_ns: None,
            unsupported: PortableMetadataUnsupportedFields {
                creation: Some(PortableMetadataUnsupportedReason::Platform),
                unix_executable: None,
            },
            certification: PortableMetadataCertification::UnixImplementedNotVerifiedInThisRelease,
        };
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let fields = PortableMetadataFieldCapability {
            modified: PortableMetadataSupport::Unknown,
            creation: PortableMetadataSupport::Unknown,
            readonly: PortableMetadataSupport::Unknown,
            unix_executable: PortableMetadataSupport::Unknown,
        };
        PortableMetadataCapabilityMatrix {
            format_version: PORTABLE_METADATA_CAPABILITY_VERSION,
            capture: fields,
            apply: fields,
            verify: fields,
            timestamp_precision_ns: None,
            unsupported: PortableMetadataUnsupportedFields::none(),
            certification: PortableMetadataCertification::UnsupportedPlatform,
        }
    }
}
