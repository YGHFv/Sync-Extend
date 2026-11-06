use crate::{Journal, JournalCapacityLimits, JournalError, Result, TreeRestoreInventoryLimits};
use sync_extend_core_model::limits::MAX_ENTRIES;

pub(crate) mod history;
pub(crate) mod local_commit;
pub(crate) mod receive;

pub(crate) fn validate(max_entries: usize) -> Result<()> {
    if max_entries == 0 || max_entries > MAX_ENTRIES {
        return Err(JournalError::Invariant("journal storage policy limit"));
    }
    Ok(())
}

pub(crate) fn capacity_limits(max_entries: usize) -> Result<JournalCapacityLimits> {
    validate(max_entries)?;
    Ok(JournalCapacityLimits {
        inventory: TreeRestoreInventoryLimits {
            max_rows: MAX_ENTRIES,
            max_logical_bytes: MAX_ENTRIES as u64 * 1024,
        },
        max_rows: max_entries as u64,
        max_logical_bytes: max_entries as u64 * 1024,
    })
}

impl Journal {
    /// Current instance policy, not a certificate that every writer is converted.
    pub fn max_storage_entries(&self) -> usize {
        self.max_storage_entries
    }

    /// A tighter policy does not rewrite historical reservations or release pins.
    pub fn set_max_storage_entries(&mut self, max_entries: usize) -> Result<()> {
        validate(max_entries)?;
        if !self.connection.is_autocommit() {
            return Err(JournalError::Invariant(
                "journal storage policy change inside transaction",
            ));
        }
        self.max_storage_entries = max_entries;
        Ok(())
    }

    pub(crate) fn writer_capacity_limits(
        &self,
        max_entries: usize,
    ) -> Result<JournalCapacityLimits> {
        validate(max_entries)?;
        capacity_limits(self.max_storage_entries.min(max_entries))
    }
}
