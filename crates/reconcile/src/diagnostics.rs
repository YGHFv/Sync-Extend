use crate::{LocalSpace, Result, Status};
use serde::Serialize;

#[derive(Serialize)]
pub struct Diagnostics {
    pub diagnostic_format_version: u32,
    pub mode: &'static str,
    pub metadata_snapshot_consistent: bool,
    pub worktree_scanned: bool,
    pub content_hashes_verified: bool,
    pub recovery_performed: bool,
    pub status: Status,
    pub implemented_reference_owners: Vec<&'static str>,
    pub unavailable_reference_owners: Vec<&'static str>,
    pub implementation_gaps: Vec<&'static str>,
    pub uncertified_safety_boundaries: Vec<&'static str>,
    pub production_safety_certified: bool,
}

impl LocalSpace {
    pub fn diagnostics(&self) -> Result<Diagnostics> {
        Ok(Diagnostics {
            diagnostic_format_version: 1,
            mode: "local_offline_prototype",
            metadata_snapshot_consistent: true,
            worktree_scanned: false,
            content_hashes_verified: false,
            recovery_performed: false,
            status: self.status()?,
            implemented_reference_owners: vec![
                "retained_snapshots_including_current_and_locked",
                "outstanding_publications",
                "outstanding_mutations",
                "active_local_read_leases",
                "durable_worker_content_reservations",
            ],
            unavailable_reference_owners: vec!["offline_queue", "conflicts", "transfers"],
            implementation_gaps: vec![
                "persistent_identity_rename_inference",
                "whole_tree_restore_transaction",
                "non_move_transaction_marker_cleanup",
                "automatic_retention_and_bulk_gc",
                "authenticated_network_sync",
                "local_webdav",
                "service_user_isolation_and_native_credentials",
            ],
            uncertified_safety_boundaries: vec![
                "power_loss_cross_sqlite_filesystem",
                "mapped_writers_and_unmanaged_actors",
                "physical_file_id_reuse",
                "administrator_bypass",
                "trusted_elapsed_time",
                "hardware_platform_and_network_matrix",
            ],
            production_safety_certified: false,
        })
    }
}
