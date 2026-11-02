use crate::{LocalSpace, Result};
use sync_extend_core_model::EntryId;
use sync_extend_journal::GcDisposalAudit;

impl LocalSpace {
    pub fn gc_disposals(&self) -> Result<Vec<GcDisposalAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .gc_disposals(&self.space_id, self.limits.max_storage_entries)?)
    }

    pub fn prepare_gc_disposal(&mut self, id: &EntryId) -> Result<GcDisposalAudit> {
        self.verify_root()?;
        if let Some(old) = self
            .gc_disposals()?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
        {
            return Ok(old);
        }
        self.prepare_gc_disposal_platform(id)
    }

    pub fn execute_gc_disposal(&mut self, id: &EntryId) -> Result<GcDisposalAudit> {
        self.verify_root()?;
        if let Some(old) = self
            .gc_disposals()?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
        {
            if matches!(
                old.state,
                sync_extend_journal::GcDisposalState::Restored
                    | sync_extend_journal::GcDisposalState::Deleted
            ) {
                return Ok(old);
            }
        }
        self.execute_gc_disposal_platform(id)
    }

    #[cfg(not(windows))]
    fn prepare_gc_disposal_platform(&self, _id: &EntryId) -> Result<GcDisposalAudit> {
        Err(crate::ReconcileError::Invariant(
            "GC disposal preparation requires Windows fixed local NTFS",
        ))
    }
    #[cfg(not(windows))]
    fn execute_gc_disposal_platform(&self, _id: &EntryId) -> Result<GcDisposalAudit> {
        Err(crate::ReconcileError::Invariant(
            "GC disposition requires Windows fixed local NTFS",
        ))
    }
}
