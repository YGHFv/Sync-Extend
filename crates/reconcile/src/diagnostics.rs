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
    pub implemented_capabilities: Vec<&'static str>,
    pub implementation_gaps: Vec<&'static str>,
    pub uncertified_safety_boundaries: Vec<&'static str>,
    pub file_content_representation: &'static str,
    pub tree_manifest_representation: &'static str,
    pub windows_acl_captured: bool,
    pub windows_acl_restored: bool,
    pub alternate_data_streams_enumerated: bool,
    pub alternate_data_streams_preserved: bool,
    pub links_and_reparse_points_rejected: bool,
    pub portable_file_times_captured: bool,
    pub portable_file_times_restored: bool,
    pub portable_file_attributes_captured: bool,
    pub portable_file_attributes_restored: bool,
    pub metadata_fidelity_disclosure: &'static str,
    pub production_safety_certified: bool,
}

impl LocalSpace {
    pub fn diagnostics(&self) -> Result<Diagnostics> {
        // Describe explicit production entry points separately from this
        // read-only invocation's status and from platform certification.
        let mut implemented_capabilities = vec![
            "bounded_authenticated_local_management_observation",
            "authenticated_local_webdav_gateway",
            "signed_peer_operation_and_quic_content_transport",
            "explicit_retained_snapshot_locks_and_pruning",
            "explicit_deletion_retention_policy_and_report",
            "single_file_retained_history_restore_as_new_operation",
            "persisted_local_identity_rename_candidates_without_native_continuity",
        ];
        let mut implementation_gaps = vec![
            "readonly_selective_directory_restore_preview",
            "portable_file_time_and_attribute_capture_restore",
            "general_portable_restore_of_root_bound_native_history",
            "history_snapshot_time_window_merging",
            "automatic_retention_and_bulk_gc",
            "automatic_transfer_retry_and_path_failover",
            "content_end_to_end_encryption",
        ];
        if cfg!(windows) {
            implemented_capabilities.extend([
                "bounded_immutable_archive_history_and_attempt_inspection",
                "explicit_read_lease_hold_and_inert_terminal_gc_history_mapping",
                "explicit_windows_fixed_ntfs_non_atomic_tree_restore_and_cleanup",
                "explicit_windows_fixed_ntfs_transaction_marker_cleanup",
                "explicit_windows_recovered_native_writer_and_history_chain",
                "explicit_same_user_dpapi_credential_mapping_and_private_install",
            ]);
        } else {
            implementation_gaps
                .push("native_whole_tree_restore_and_whole_tree_marker_cleanup_on_this_platform");
        }
        if cfg!(target_os = "linux") {
            implemented_capabilities
                .push("explicit_linux_owned_ext4_native_put_and_transaction_cleanup");
        }
        Ok(Diagnostics {
            diagnostic_format_version: 1,
            mode: "local_readonly_diagnostics",
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
                "explicit_upload_download_restore_offline_delivery_and_conflict_reservations",
                "prepared_tree_restore_inputs",
            ],
            unavailable_reference_owners: vec![
                "automatically_scheduled_offline_delivery_workers",
                "automatically_scheduled_transfer_retry_workers",
            ],
            implemented_capabilities,
            implementation_gaps,
            uncertified_safety_boundaries: vec![
                "power_loss_cross_sqlite_filesystem",
                "mapped_writers_and_unmanaged_actors",
                "physical_file_id_reuse",
                "administrator_bypass",
                "trusted_elapsed_time",
                "hardware_platform_and_network_matrix",
            ],
            file_content_representation: "portable_unnamed_file_bytes",
            tree_manifest_representation: "portable_tree_manifests",
            windows_acl_captured: false,
            windows_acl_restored: false,
            alternate_data_streams_enumerated: false,
            alternate_data_streams_preserved: false,
            links_and_reparse_points_rejected: true,
            portable_file_times_captured: false,
            portable_file_times_restored: false,
            portable_file_attributes_captured: false,
            portable_file_attributes_restored: false,
            metadata_fidelity_disclosure: "Content and history use portable unnamed file bytes and tree manifests. Original file times and attributes are not captured or restored. Windows ACLs are not captured or restored; alternate data streams are not enumerated or preserved. Links and reparse points are rejected.",
            production_safety_certified: false,
        })
    }
}
