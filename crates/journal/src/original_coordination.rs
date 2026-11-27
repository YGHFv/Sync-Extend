//! Additional Journal connections observe the same actual retained restored original.
use crate::{Journal, JournalError, Result};

impl Journal {
    /// A long-lived original CAS reader budgets each complete fence observation.
    /// The same connection, native IO and sentinel remain owned throughout;
    /// all SQL shares one finite budget, and its prior hook state is restored.
    #[cfg(windows)]
    pub fn acquire_original_cas_access_observed(
        &mut self,
        content: &sync_extend_core_model::ContentId,
    ) -> Result<crate::CasAccessGuard> {
        if !self.original_coordination_observer {
            return Err(JournalError::Invariant(
                "bounded original CAS observation requires its coordination reader",
            ));
        }
        let scope = self.connection.begin_original_observation()?;
        struct Guard {
            original: Option<crate::CasAccessGuard>,
            terminal: crate::original_observation_terminal::OriginalObservationTerminal,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(guard) = self.original.take() {
                    self.terminal
                        .record(guard.end_rejected_original_observation());
                }
            }
        }
        self.verify_original_created_image()?;
        let mut guard = Guard {
            original: Some(self.acquire_cas_coordination()?),
            terminal: self.connection.original_observation_terminal(),
        };
        self.require_cas_access(content)?;
        self.verify_original_created_image()?;
        // Errors and unwinding close the actual temporary lock and restore
        // the previous budget. Even sub-callback SQL checks this deadline.
        scope.finish()?;
        Ok(guard
            .original
            .take()
            .expect("same verified original CAS guard"))
    }

    /// Internal coordination readers must not fall back to unverified pathname
    /// Journal::open after the first restored connection has checked ownership.
    /// The additional connection receives only metadata identity continuity,
    /// never a fresh CREATE or content-immutable authority.
    #[cfg(windows)]
    pub fn open_original_coordination_connection(&self) -> Result<Self> {
        self.open_original_coordination_connection_retaining()
            .map_err(|original| original.retain_and_report())
    }

    #[cfg(windows)]
    pub fn open_original_coordination_connection_retaining(
        &self,
    ) -> std::result::Result<Self, crate::OriginalReadonlyJournalOpenFailure> {
        use crate::OriginalReadonlyJournalOpenFailure;
        self.verify_original_created_image()
            .map_err(OriginalReadonlyJournalOpenFailure::before_native)?;
        let inspection = crate::NodeInspectionBounds {
            max_entries: self.max_storage_entries,
            capacity: crate::JournalCapacityLimits {
                inventory: crate::TreeRestoreInventoryLimits {
                    max_rows: self.max_storage_entries,
                    max_logical_bytes: self.max_storage_entries as u64 * 1024,
                },
                max_rows: self.max_storage_entries as u64,
                max_logical_bytes: self.max_storage_entries as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let sentinel = self
            .original_cas_coordination
            .as_ref()
            .ok_or(JournalError::Invariant(
                "original coordination sentinel absent",
            ))
            .and_then(|sentinel| sentinel.retain_observer().map_err(JournalError::from))
            .map_err(OriginalReadonlyJournalOpenFailure::before_native)?;
        let original = match self
            .original_restored_image
            .as_ref()
            .ok_or(JournalError::Invariant("original Journal witness absent"))
            .and_then(|original| {
                original
                    .retain_identity_observer()
                    .map_err(JournalError::from)
            }) {
            Ok(original) => original,
            Err(error) => {
                return Err(OriginalReadonlyJournalOpenFailure::before_native(error)
                    .retain_sentinel(sentinel));
            }
        };
        let mut connection =
            match Self::reopen_original_readonly_image(&self.database_path, inspection, original) {
                Ok(connection) => connection,
                Err(original) => return Err(original.retain_sentinel(sentinel)),
            };
        if let Err((sentinel, error)) = connection.bind_original_cas_coordination(sentinel) {
            return Err(
                OriginalReadonlyJournalOpenFailure::from_failed_journal(connection, error)
                    .retain_sentinel(*sentinel),
            );
        }
        connection.original_coordination_observer = true;
        Ok(connection)
    }
}

impl Journal {
    /// End an additional original coordination reader without releasing its
    /// original identity/sentinel witnesses or creating any new main authority.
    /// Failed actual closes restore the same connection and read protection.
    #[cfg(windows)]
    pub fn close_original_coordination_connection(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        crate::OriginalReadonlyJournalCloseFailure,
    > {
        self.close_original_readonly_resources_retaining()
    }

    pub(crate) fn finish_original_coordination_observation<T>(
        self,
        result: Result<T>,
    ) -> Result<T> {
        match self.close_original_readonly_resources_retaining() {
            Ok(_) => result,
            Err(failure) => {
                let reported = JournalError::Io(std::io::Error::other(failure.error.to_string()));
                match result {
                    Ok(_) => {
                        failure.retain_until_process_exit();
                        Err(reported)
                    }
                    Err(first) => {
                        let _ = Box::leak(Box::new((failure, first.to_string())));
                        Err(first)
                    }
                }
            }
        }
    }
}
