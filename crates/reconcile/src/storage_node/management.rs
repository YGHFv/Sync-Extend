//! Bounded storage observations from the retained storage owner.
use super::StorageNode;
use crate::{now_ms, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{storage_node::StorageRole, ContentId, DeviceId, SnapshotId, SpaceId};

#[derive(Serialize)]
pub struct StorageDashboardSnapshot {
    pub origin_device: DeviceId,
    pub snapshot_id: SnapshotId,
    pub reported_at_ms: u64,
}

#[derive(Serialize)]
pub struct StorageDashboardObservation {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub role: StorageRole,
    pub worktree: Option<bool>,
    pub journal_snapshot_consistent: bool,
    pub cross_database_snapshot_consistent: bool,
    pub protected_chunks: usize,
    pub protected_bytes: u64,
    pub physical_cas_bytes: u64,
    pub stored_byte_limit: u64,
    pub request_byte_limit: u64,
    pub charged_logical_delivery_bytes: u64,
    pub traffic_byte_limit: u64,
    pub expired: bool,
    pub checked_chunks: usize,
    pub checked_bytes: u64,
    pub unavailable_chunks: Vec<ContentId>,
    pub all_protected_chunks_checked: bool,
    pub total_snapshot_reports: usize,
    pub snapshot_reports: Vec<StorageDashboardSnapshot>,
    pub snapshot_reports_truncated: bool,
    pub content_complete_certified: bool,
    pub backup_complete: bool,
}

impl StorageNode {
    /// Inspect existing ledgers and at most 64 chunks / 16 MiB. Reading the
    /// dashboard never admits a delivery or changes reference owners or charges.
    pub fn management_dashboard(&self) -> Result<StorageDashboardObservation> {
        self.verify_storage()?;
        self.journal.with_gc_diagnostics(
            &self.config.space_id,
            self.config.max_metadata_entries,
            |_| {
                let reserved = self.reserved_chunks()?;
                let protected_bytes = reserved.values().try_fold(0u64, |sum, chunk| {
                    sum.checked_add(u64::from(chunk.length))
                        .ok_or(ReconcileError::ResourceLimit("storage dashboard byte sum"))
                })?;
                let mut checked_chunks = 0usize;
                let mut checked_bytes = 0u64;
                let mut unavailable_chunks = Vec::new();
                for chunk in reserved.values() {
                    let next = checked_bytes
                        .checked_add(u64::from(chunk.length))
                        .ok_or(ReconcileError::ResourceLimit("storage dashboard read sum"))?;
                    if checked_chunks == 64 || next > 16 * 1024 * 1024 {
                        continue;
                    }
                    checked_chunks += 1;
                    checked_bytes = next;
                    if self.cas.read(chunk).is_err() {
                        unavailable_chunks.push(chunk.content_id.clone());
                    }
                }
                // This independently audited ledger is a different database.
                // It does not participate in the Journal's read transaction.
                let envelopes = self.traffic.snapshots(&self.config, &self.device)?;
                let total_snapshot_reports = envelopes.len();
                let snapshot_reports = envelopes
                    .into_iter()
                    .take(128)
                    .map(|envelope| StorageDashboardSnapshot {
                        origin_device: envelope.origin.device_id,
                        snapshot_id: envelope.signed_report.report.snapshot_id,
                        reported_at_ms: envelope.signed_report.report.reported_at_ms,
                    })
                    .collect();
                let observation = StorageDashboardObservation {
                    space_id: self.config.space_id.clone(),
                    device_id: self.device.clone(),
                    role: self.config.role,
                    worktree: None,
                    journal_snapshot_consistent: true,
                    cross_database_snapshot_consistent: false,
                    protected_chunks: reserved.len(),
                    protected_bytes,
                    physical_cas_bytes: self.physical_bytes()?,
                    stored_byte_limit: self.config.max_stored_bytes,
                    request_byte_limit: self.config.max_request_bytes,
                    charged_logical_delivery_bytes: self
                        .traffic
                        .charged_bytes(&self.config, &self.device)?,
                    traffic_byte_limit: self.config.max_traffic_bytes,
                    expired: now_ms()? >= self.config.expires_at_ms,
                    checked_chunks,
                    checked_bytes,
                    unavailable_chunks,
                    all_protected_chunks_checked: checked_chunks == reserved.len(),
                    total_snapshot_reports,
                    snapshot_reports,
                    snapshot_reports_truncated: total_snapshot_reports > 128,
                    content_complete_certified: false,
                    backup_complete: false,
                };
                self.verify_storage()?;
                Ok(observation)
            },
        )
    }
}
