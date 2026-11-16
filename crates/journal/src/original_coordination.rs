//! Additional Journal connections observe the same actual retained restored original.
use crate::{Journal, JournalError, Result};

impl Journal {
    /// Internal coordination readers must not fall back to unverified pathname
    /// Journal::open after the first restored connection has checked ownership.
    /// The additional connection receives only metadata identity continuity,
    /// never a fresh CREATE or content-immutable authority.
    #[cfg(windows)]
    pub fn open_original_coordination_connection(&self) -> Result<Self> {
        self.verify_original_created_image()?;
        let original = self
            .original_restored_image
            .as_ref()
            .ok_or(JournalError::Invariant("original Journal witness absent"))?
            .retain_identity_observer()?;
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
            ))?
            .retain_observer()?;
        let mut connection =
            Self::reopen_original_readonly_image(&self.database_path, inspection, original)
                .map_err(|(_original, error)| error)?;
        connection
            .bind_original_cas_coordination(sentinel)
            .map_err(|(_original, error)| error)?;
        connection.original_coordination_observer = true;
        Ok(connection)
    }
}

impl Journal {
    /// End an additional original coordination reader without releasing its
    /// original identity/sentinel witnesses or creating any new main authority.
    /// Failed actual closes restore the same connection and read protection.
    #[cfg(windows)]
    pub fn close_original_coordination_connection(&mut self) -> Result<()> {
        self.verify_original_created_image()?;
        if !self.original_coordination_observer
            || self.original_read_protection.is_none()
            || !self.connection.is_autocommit()
        {
            return Err(JournalError::Invariant(
                "coordination close requires an idle observer without main handoff",
            ));
        }
        let inert = rusqlite::Connection::open_in_memory()?;
        let actual = std::mem::replace(&mut self.connection, inert);
        if let Err((connection, error)) = actual.close() {
            self.connection = connection;
            return Err(error.into());
        }
        // Original metadata identities and parent witnesses remain retained.
        // Only the already closed observer's content read protection ends.
        drop(self.original_read_protection.take());
        Ok(())
    }
}
