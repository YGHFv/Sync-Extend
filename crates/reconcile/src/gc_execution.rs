use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_core_model::EntryId;
use sync_extend_journal::{GcExecutionAudit, GcExecutionState};

impl LocalSpace {
    pub fn gc_executions(&self) -> Result<Vec<GcExecutionAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .gc_executions(&self.space_id, self.limits.max_storage_entries)?)
    }

    pub fn admit_gc_execution(&mut self, authorization: &EntryId) -> Result<GcExecutionAudit> {
        self.verify_root()?;
        if let Some(old) = self
            .gc_executions()?
            .into_iter()
            .find(|e| e.intent.authorization.authorization_id == *authorization)
        {
            return Ok(old);
        }
        self.admit_gc_platform(authorization)
    }

    pub fn abort_gc_execution(&mut self, id: &EntryId) -> Result<GcExecutionAudit> {
        self.verify_root()?;
        let old = self
            .gc_executions()?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(ReconcileError::Invariant("unknown GC execution"))?;
        if old.state == GcExecutionState::Aborted {
            return Ok(old);
        }
        crate::fault::checkpoint("before_gc_execution_abort");
        let audit =
            self.journal
                .abort_gc_execution(&self.space_id, id, self.limits.max_storage_entries)?;
        crate::fault::checkpoint("after_gc_execution_abort");
        Ok(audit)
    }

    #[cfg(not(windows))]
    fn admit_gc_platform(&self, _id: &EntryId) -> Result<GcExecutionAudit> {
        Err(ReconcileError::Invariant(
            "GC execution admission requires Windows fixed local NTFS",
        ))
    }

    #[cfg(windows)]
    fn admit_gc_platform(&self, id: &EntryId) -> Result<GcExecutionAudit> {
        self.storage_report()?;
        self.verify()?;
        crate::fault::checkpoint("before_gc_execution");
        let (guards, audit) = self.journal.with_gc_execution_admission(
            &self.space_id,
            id,
            self.limits.max_storage_entries,
            crate::now_ms,
            |authorization| -> Result<_> {
                crate::fault::checkpoint("after_gc_execution_journal_lock");
                let (guards, boundary) = crate::gc_preflight::windows::inspect(
                    self,
                    &authorization.mark,
                    "after_gc_execution_file_lock",
                )?;
                if boundary != authorization.boundary {
                    return Err(ReconcileError::Invariant("GC execution boundary changed"));
                }
                Ok(guards)
            },
        )?;
        crate::fault::checkpoint("after_gc_execution");
        drop(guards);
        Ok(audit)
    }
}
