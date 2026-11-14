use crate::{Result, StorageNode};
use sync_extend_journal::StorageRetirementDisposalReport;
impl StorageNode {
    pub fn storage_retirement_disposals(&self) -> Result<Vec<StorageRetirementDisposalReport>> {
        self.verify_storage()?;
        Ok(self.journal.storage_retirement_disposals()?)
    }
    #[cfg(windows)]
    pub fn dispose_storage_retirement_payload(
        &self,
        id: &sync_extend_core_model::EntryId,
    ) -> Result<StorageRetirementDisposalReport> {
        self.verify_storage()?;
        let result = self.journal.dispose_storage_retirement_payload(
            id,
            &self.config,
            &self.device,
            || {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| {
                            sync_extend_journal::JournalError::Invariant("storage disposal clock")
                        })?
                        .as_millis(),
                )
                .map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("storage disposal clock range")
                })
            },
        )?;
        self.verify_storage()?;
        Ok(result)
    }
}
