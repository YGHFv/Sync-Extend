use crate::{Result, StorageNode};
use sync_extend_core_model::EntryId;
use sync_extend_journal::{StorageRetirementAdmission, StorageRetirementTerminalReport};

fn clock() -> sync_extend_journal::Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| sync_extend_journal::JournalError::Invariant("storage terminal clock"))?
            .as_millis(),
    )
    .map_err(|_| sync_extend_journal::JournalError::Invariant("storage terminal clock range"))
}

impl StorageNode {
    pub fn storage_retirement_terminals(&self) -> Result<Vec<StorageRetirementTerminalReport>> {
        self.verify_storage()?;
        Ok(self.journal.storage_retirement_terminals()?)
    }

    #[cfg(windows)]
    pub fn close_restored_storage_retirement(
        &self,
        id: &EntryId,
    ) -> Result<StorageRetirementTerminalReport> {
        self.verify_storage()?;
        let result = self.journal.close_restored_storage_retirement(
            id,
            &self.config,
            &self.device,
            clock,
        )?;
        self.verify_storage()?;
        Ok(result)
    }

    pub fn release_storage_retirement_terminal(
        &self,
        id: &EntryId,
    ) -> Result<StorageRetirementAdmission> {
        self.verify_storage()?;
        let result = self.journal.release_storage_retirement_terminal(
            id,
            &self.config,
            &self.device,
            clock()?,
        )?;
        self.verify_storage()?;
        Ok(result)
    }
}
