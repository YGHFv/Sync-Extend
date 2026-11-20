//! Preserve an existing held SQLite physical reservation across metadata writes.
//! An ordinary writer has no such receipt and is never certified by this guard.
use crate::{Journal, Result};
#[cfg(target_os = "linux")]
use crate::JournalError;

pub(crate) struct PhysicalMetadataGuard {
    #[cfg(target_os = "linux")]
    before: Option<sync_extend_platform_fs::LinuxMetadataReceipt>,
}

impl PhysicalMetadataGuard {
    pub(crate) fn capture(journal: &Journal) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        let _ = journal;
        Ok(Self {
            #[cfg(target_os = "linux")]
            before: journal.linux_metadata_receipt()?,
        })
    }

    pub(crate) fn verify(&self, journal: &Journal) -> Result<()> {
        #[cfg(target_os = "linux")]
        match (&self.before, journal.linux_metadata_receipt()?) {
            (None, None) => {}
            (Some(before), Some(after))
                if before.format_version == after.format_version
                    && before.owner_generation == after.owner_generation
                    && before.backing_image == after.backing_image
                    && before.namespace == after.namespace
                    && before.parent == after.parent
                    && before.total_allocated_bytes == after.total_allocated_bytes
                    && before.total_physical_budget == after.total_physical_budget
                    && !before.disk_temp_files_allowed
                    && !after.disk_temp_files_allowed
                    && before.files.iter().zip(&after.files).all(|(old, new)| {
                        old.class == new.class
                            && old.identity == new.identity
                            && old.allocated_bytes == new.allocated_bytes
                            && old.capacity_bytes == new.capacity_bytes
                    }) => {}
            _ => {
                return Err(JournalError::Invariant(
                    "retention held metadata physical reservation changed",
                ))
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = journal;
        Ok(())
    }
}
