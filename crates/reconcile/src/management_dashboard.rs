//! Bounded observations taken from the existing owner; never opens a second worktree.
use crate::{LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{
    ContentId, DeviceId, EntryId, EntryKind, PortablePath, SnapshotId, SpaceId,
};

#[derive(Serialize)]
pub struct DashboardEntry {
    pub entry_id: EntryId,
    pub path: PortablePath,
    pub kind: EntryKind,
    pub logical_bytes: Option<u64>,
}

#[derive(Serialize)]
pub struct DashboardSnapshot {
    pub snapshot_id: SnapshotId,
    pub state: String,
    pub current: bool,
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
                let snapshots = self.journal.snapshots(&self.space_id)?;
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
                    total_snapshots: snapshots.len(),
                    snapshots_truncated: snapshots.len() > 128,
                    snapshots: snapshots
                        .into_iter()
                        .rev()
                        .take(128)
                        .map(|(id, state)| DashboardSnapshot {
                            current: status.snapshot_id.as_ref() == Some(&id),
                            snapshot_id: id,
                            state,
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
                    remote_backup_complete: false,
                };
                self.verify_root()?;
                Ok(observation)
            })
    }
}
