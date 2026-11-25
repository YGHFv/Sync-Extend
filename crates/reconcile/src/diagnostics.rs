use crate::{LocalSpace, Result, Status};
use serde::Serialize;
use sync_extend_core_model::{
    PortableMetadataCapabilityMatrix, PortableMetadataCertification, PortableMetadataSupport,
};

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
    pub portable_creation_time_captured: bool,
    pub portable_creation_time_restored: bool,
    pub portable_unix_executable_captured: bool,
    pub portable_unix_executable_restored: bool,
    pub portable_metadata_verified_after_apply: bool,
    pub portable_metadata_timestamp_precision_ns: Option<u32>,
    pub portable_metadata_unsupported_fields: Vec<&'static str>,
    pub portable_metadata_certification: &'static str,
    pub portable_tree_restore_metadata_preserved: bool,
    pub portable_native_publish_metadata_preserved: bool,
    pub portable_metadata_capability: PortableMetadataCapabilityMatrix,
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
            "portable_metadata_in_tree_restore_and_reconcile_native_publish",
            "general_portable_restore_of_root_bound_native_history",
            "history_snapshot_time_window_merging",
            "automatic_retention_and_bulk_gc",
            "automatic_transfer_retry_and_path_failover",
            "content_end_to_end_encryption",
        ];
        let metadata_capability =
            crate::management_dashboard::portable_metadata_capability_matrix();
        let field_supported =
            |value: PortableMetadataSupport| value == PortableMetadataSupport::Supported;
        let modified = field_supported(metadata_capability.capture.modified)
            && field_supported(metadata_capability.apply.modified)
            && field_supported(metadata_capability.verify.modified);
        let readonly = field_supported(metadata_capability.capture.readonly)
            && field_supported(metadata_capability.apply.readonly)
            && field_supported(metadata_capability.verify.readonly);
        let creation = field_supported(metadata_capability.capture.creation)
            && field_supported(metadata_capability.apply.creation)
            && field_supported(metadata_capability.verify.creation);
        let unix_executable = field_supported(metadata_capability.capture.unix_executable)
            && field_supported(metadata_capability.apply.unix_executable)
            && field_supported(metadata_capability.verify.unix_executable);
        if modified && readonly {
            implemented_capabilities
                .push("portable_file_time_and_readonly_handle_capture_apply_verify");
        }
        if creation {
            implemented_capabilities.push("portable_creation_time_handle_capture_apply_verify");
        }
        if unix_executable {
            implemented_capabilities.push("portable_unix_executable_handle_capture_apply_verify");
        }
        let mut unsupported_fields = Vec::new();
        if !modified {
            unsupported_fields.push("modified");
        }
        if !creation {
            unsupported_fields.push("creation");
        }
        if !readonly {
            unsupported_fields.push("readonly");
        }
        if !unix_executable {
            unsupported_fields.push("unix_executable");
        }
        let certification = match metadata_capability.certification {
            PortableMetadataCertification::WindowsNtfsActualGroupedAcceptance => {
                "windows_ntfs_actual_grouped_acceptance"
            }
            PortableMetadataCertification::UnixImplementedNotVerifiedInThisRelease => {
                "unix_implemented_not_verified_in_this_release"
            }
            PortableMetadataCertification::UnsupportedPlatform => "unsupported_platform",
        };
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
            implementation_gaps
                .push("portable_metadata_actual_grouped_acceptance_on_this_platform");
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
            portable_file_times_captured: modified,
            portable_file_times_restored: modified,
            portable_file_attributes_captured: readonly,
            portable_file_attributes_restored: readonly,
            portable_creation_time_captured: creation,
            portable_creation_time_restored: creation,
            portable_unix_executable_captured: unix_executable,
            portable_unix_executable_restored: unix_executable,
            portable_metadata_verified_after_apply: modified && readonly,
            portable_metadata_timestamp_precision_ns: metadata_capability.timestamp_precision_ns,
            portable_metadata_unsupported_fields: unsupported_fields,
            portable_metadata_certification: certification,
            portable_tree_restore_metadata_preserved: false,
            portable_native_publish_metadata_preserved: false,
            portable_metadata_capability: metadata_capability,
            metadata_fidelity_disclosure: "Where the capability matrix reports support, portable modified time, readonly and platform-supported creation/executable fields are captured and applied through the already-open file handle, then re-observed. Unknown or unsupported fields are not claimed. Single-file new-operation restore carries captured metadata. TREE restore and the reconcile native-publish path do not yet carry portable metadata. Windows ACLs and alternate data streams are not captured or preserved, UID/GID and raw mode are not portable, and links/reparse points are rejected. FAT/exFAT, emulated volumes, KernelSU and ACL/ADS fidelity are not certified from NTFS/ext4 results; D5 remains open.",
            production_safety_certified: false,
        })
    }
}
