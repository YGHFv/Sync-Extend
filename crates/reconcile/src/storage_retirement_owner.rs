//! Storage-only original owner creation, distinct from worktree GC boundaries.
use crate::{Result, StorageNode};
use sync_extend_core_model::EntryId;
use sync_extend_journal::StorageRetirementOwnerReceipt;

impl StorageNode {
    pub fn storage_retirement_owner_receipts(&self) -> Result<Vec<StorageRetirementOwnerReceipt>> {
        self.verify_storage()?;
        Ok(self.journal.storage_retirement_owner_receipts()?)
    }

    #[cfg(windows)]
    pub fn create_storage_retirement_owner(
        &self,
        request: &EntryId,
    ) -> Result<sync_extend_journal::StorageRetirementOwnerCreation> {
        self.verify_storage()?;
        let created = self.journal.create_storage_retirement_owner(
            request,
            &self.config,
            &self.device,
            || {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| {
                            sync_extend_journal::JournalError::Invariant("storage owner clock")
                        })?
                        .as_millis(),
                )
                .map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("storage owner clock range")
                })
            },
        )?;
        self.verify_storage()?;
        Ok(created)
    }

    #[cfg(not(windows))]
    pub fn create_storage_retirement_owner(&self, _: &EntryId) -> Result<()> {
        Err(crate::ReconcileError::Invariant(
            "storage retirement original owner requires Windows fixed local NTFS",
        ))
    }
}
