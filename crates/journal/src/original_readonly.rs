//! Bounded readonly original Journal constructor; no WAL, migration or CREATE.
use crate::*;
use rusqlite::Connection;
use std::path::Path;
use sync_extend_platform_fs::ReleasedOriginalFileIdentity;

impl Journal {
    pub fn reopen_original_readonly_image(
        path: &Path,
        bounds: NodeInspectionBounds,
        original: ReleasedOriginalFileIdentity,
    ) -> std::result::Result<Self, (Box<ReleasedOriginalFileIdentity>, JournalError)> {
        let open = || -> Result<Self> {
            original.verify()?;
            if !path.is_absolute() || !original.matches_path(path)? {
                return Err(JournalError::Invariant(
                    "readonly original Journal slot changed before open",
                ));
            }
            for suffix in ["-journal", "-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_owned();
                sidecar.push(suffix);
                match std::fs::symlink_metadata(Path::new(&sidecar)) {
                    Ok(_) => {
                        return Err(JournalError::Invariant(
                            "readonly original standalone Journal sidecar occupied",
                        ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
            }
            // ReOpenFile protects the actual same original against writes/deletes;
            // no pathname opener or numeric key can establish this reader.
            let protected = match original
                .retain_identity_observer()?
                .retain_read_after_creation()
            {
                Ok(protected) => protected,
                Err((_original, error)) => return Err(error.into()),
            };
            protected.verify_identity()?;
            let mut connection = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            if sync_extend_platform_fs::sqlite_main_file_identity(&connection)? != original.key()?
                || !original.matches_path(path)?
            {
                return Err(JournalError::Invariant(
                    "readonly SQLite opened foreign original main object",
                ));
            }
            // Only actual identity observation precedes SQL configuration.
            bounds.configure_original_connection(&mut connection)?;
            crate::storage_policy::validate(bounds.max_entries)?;
            let max_storage_entries = bounds.max_entries;
            let version: u32 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if version != crate::SCHEMA_VERSION {
                return Err(JournalError::Invariant(
                    "readonly original Journal exact current version required",
                ));
            }
            webdav_native::schema::validate(&connection)?;
            let webdav_native_execution_admission_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_admission_issue",
            )?;
            let webdav_native_execution_record_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_record_issue",
            )?;
            let webdav_native_execution_template_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_template_issue",
            )?;
            let webdav_native_execution_binding_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_binding_issue",
            )?;
            let webdav_native_execution_receipt_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_receipt_issue",
            )?;
            let webdav_native_execution_manifest_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_execution_manifest_issue",
            )?;
            let webdav_original_final_row_issue =
                webdav_native::final_row_gate::Gate::register(&connection)?;
            let webdav_native_description_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_description_issue",
            )?;
            let webdav_native_object_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_object_issue",
            )?;
            let webdav_native_cancel_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_webdav_native_cancel_issue",
            )?;
            storage_retirement::terminal_schema::validate(&connection)?;
            #[cfg(windows)]
            let storage_retirement_terminal_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_terminal_issue",
            )?;
            storage_retirement::disposal_schema::validate(&connection)?;
            #[cfg(windows)]
            let storage_retirement_disposal_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_disposal_issue",
            )?;
            storage_retirement::payload_schema::validate(&connection)?;
            #[cfg(windows)]
            let storage_retirement_payload_issue = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_payload_issue",
            )?;
            storage_retirement::schema::validate(&connection)?;
            storage_retirement::owner_schema::validate(&connection)?;
            #[cfg(windows)]
            let storage_retirement_owner_activation = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_owner_issue",
            )?;
            #[cfg(windows)]
            let storage_retirement_owner_receipt = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_owner_receipt",
            )?;
            let storage_retirement_issuance = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_issue",
            )?;
            let storage_retirement_cancellation = storage_retirement::gate::Gate::register(
                &connection,
                "sync_storage_retirement_cancel",
            )?;
            storage_page_handoff::validate_schema(&connection)?;
            storage_snapshot_handoff::validate_schema(&connection)?;
            tree_native_effects::validate_schema(&connection)?;
            let tree_native_issuance = tree_native_effects::issuance::Gate::register(&connection)?;
            #[cfg(not(windows))]
            let _ = tree_native_issuance;
            original_provenance::validate_schema(&connection)?;
            original_page_inbox::validate_schema(&connection)?;
            forwarded_page_inbox::validate_schema(&connection)?;
            let original_operation_issuance = original_provenance::Gate::register(&connection)?;
            conflict_resolution::validate_schema(&connection)?;
            let conflict_resolution_issuance =
                conflict_resolution::issuance::Gate::register(&connection)?;
            remote_replace::validate_schema(&connection)?;
            let remote_replace_issuance = remote_replace::issuance::Gate::register(&connection)?;
            #[cfg(not(windows))]
            let _ = remote_replace_issuance;
            remote_delete::validate_schema(&connection)?;
            let remote_delete_issuance = remote_delete::issuance::Gate::register(&connection)?;
            #[cfg(not(windows))]
            let _ = remote_delete_issuance;
            remote_rename::validate_schema(&connection)?;
            let remote_rename_issuance = remote_rename::issuance::Gate::register(&connection)?;
            #[cfg(not(windows))]
            let _ = remote_rename_issuance;
            native_publication::validate_schema(&connection)?;
            #[cfg(windows)]
            let native_issuance = native_publication::issuance::register(&connection)?;
            Ok(Self {
                connection,
                webdav_native_read_charges: crate::webdav_native::DavReadChargeCache::default(),
                original_local_history_issuer: std::sync::Arc::new(()),
                #[cfg(windows)]
                original_restored_image: None,
                original_cas_coordination: None,
                original_read_protection: Some(protected),
                original_coordination_observer: false,
                original_main_handoff: None,
                database_path: std::fs::canonicalize(path)?,
                max_storage_entries,
                conflict_resolution_issuance,
                original_operation_issuance,
                storage_retirement_issuance,
                storage_retirement_cancellation,
                webdav_native_description_issue,
                webdav_native_object_issue,
                webdav_native_cancel_issue,
                webdav_native_execution_admission_issue,
                webdav_native_execution_record_issue,
                webdav_native_execution_template_issue,
                webdav_native_execution_binding_issue,
                webdav_native_execution_receipt_issue,
                webdav_native_execution_manifest_issue,
                webdav_original_final_row_issue,
                #[cfg(windows)]
                storage_retirement_owner_activation,
                #[cfg(windows)]
                storage_retirement_owner_receipt,
                #[cfg(windows)]
                storage_retirement_payload_issue,
                #[cfg(windows)]
                storage_retirement_disposal_issue,
                #[cfg(windows)]
                storage_retirement_terminal_issue,
                #[cfg(windows)]
                tree_native_issuance,
                #[cfg(windows)]
                native_issuance,
                #[cfg(windows)]
                remote_rename_issuance,
                #[cfg(windows)]
                remote_delete_issuance,
                #[cfg(windows)]
                remote_replace_issuance,
            })
        };

        match open() {
            Ok(mut journal) => {
                journal.original_restored_image = Some(original);
                Ok(journal)
            }
            Err(error) => Err((Box::new(original), error)),
        }
    }
}
