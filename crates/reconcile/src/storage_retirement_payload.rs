use crate::{Result, StorageNode};
#[cfg(windows)]
use sync_extend_core_model::EntryId;
use sync_extend_journal::StorageRetirementPayloadReport;

impl StorageNode {
    pub fn storage_retirement_payloads(&self) -> Result<Vec<StorageRetirementPayloadReport>> {
        self.verify_storage()?;
        Ok(self.journal.storage_retirement_payloads()?)
    }
    #[cfg(windows)]
    pub fn quarantine_storage_retirement_payload(
        &self,
        id: &EntryId,
    ) -> Result<StorageRetirementPayloadReport> {
        self.move_storage_retirement_payload(id, false)
    }
    #[cfg(windows)]
    pub fn restore_storage_retirement_payload(
        &self,
        id: &EntryId,
    ) -> Result<StorageRetirementPayloadReport> {
        self.move_storage_retirement_payload(id, true)
    }
    #[cfg(windows)]
    fn move_storage_retirement_payload(
        &self,
        id: &EntryId,
        restore: bool,
    ) -> Result<StorageRetirementPayloadReport> {
        self.verify_storage()?;
        let result = self.journal.move_storage_retirement_payload(
            id,
            &self.config,
            &self.device,
            restore,
            || {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| {
                            sync_extend_journal::JournalError::Invariant("storage payload clock")
                        })?
                        .as_millis(),
                )
                .map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("storage payload clock range")
                })
            },
        )?;
        self.verify_storage()?;
        Ok(result)
    }
}
