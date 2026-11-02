use crate::{now_ms, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::EntryId;
use sync_extend_journal::{gc_authorization_expiry, GcAuthorizationAudit};

#[derive(Debug, Serialize)]
pub struct GcAuthorizationCheck {
    pub authorization_id: EntryId,
    pub checked_at_ms: u64,
    pub guarded_observation_complete: bool,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

impl LocalSpace {
    pub fn gc_authorizations(&self) -> Result<Vec<GcAuthorizationAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .gc_authorizations(&self.space_id, self.limits.max_storage_entries)?)
    }

    pub fn authorize_gc_mark(
        &mut self,
        id: &EntryId,
        ttl_secs: u64,
    ) -> Result<GcAuthorizationAudit> {
        gc_authorization_expiry(0, ttl_secs)?;
        self.verify_root()?;
        if let Some(old) = self
            .gc_authorizations()?
            .into_iter()
            .find(|a| a.intent.mark.mark_id == *id)
        {
            if old.intent.expires_at_ms - old.intent.authorized_at_ms != ttl_secs * 1000 {
                return Err(ReconcileError::Invariant("GC authorization TTL mismatch"));
            }
            return Ok(old);
        }
        self.authorize_gc_platform(id, ttl_secs)
    }

    pub fn revoke_gc_authorization(&mut self, id: &EntryId) -> Result<GcAuthorizationAudit> {
        self.verify_root()?;
        crate::fault::checkpoint("before_gc_revocation");
        let audit = self.journal.revoke_gc_authorization(
            &self.space_id,
            id,
            now_ms()?,
            self.limits.max_storage_entries,
        )?;
        crate::fault::checkpoint("after_gc_revocation");
        Ok(audit)
    }

    pub fn check_gc_authorization(&mut self, id: &EntryId) -> Result<GcAuthorizationCheck> {
        self.verify_root()?;
        self.gc_authorizations()?;
        self.check_gc_authorization_platform(id)
    }

    #[cfg(not(windows))]
    fn authorize_gc_platform(&self, _id: &EntryId, _ttl: u64) -> Result<GcAuthorizationAudit> {
        Err(ReconcileError::Invariant(
            "GC authorization requires Windows fixed local NTFS",
        ))
    }
    #[cfg(not(windows))]
    fn check_gc_authorization_platform(&self, _id: &EntryId) -> Result<GcAuthorizationCheck> {
        Err(ReconcileError::Invariant(
            "GC authorization check requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
impl LocalSpace {
    fn authorize_gc_platform(&self, id: &EntryId, ttl_secs: u64) -> Result<GcAuthorizationAudit> {
        self.storage_report()?;
        self.verify()?;
        crate::fault::checkpoint("before_gc_authorization");
        let (guards, audit) = self.journal.with_gc_authorization(
            &self.space_id,
            id,
            ttl_secs,
            self.limits.max_storage_entries,
            now_ms,
            |mark| {
                crate::fault::checkpoint("after_gc_authorization_journal_lock");
                crate::gc_preflight::windows::inspect(
                    self,
                    mark,
                    "after_gc_authorization_file_lock",
                )
            },
        )?;
        crate::fault::checkpoint("after_gc_authorization");
        drop(guards);
        Ok(audit)
    }

    fn check_gc_authorization_platform(&self, id: &EntryId) -> Result<GcAuthorizationCheck> {
        self.storage_report()?;
        self.verify()?;
        crate::fault::checkpoint("before_gc_authorization_check");
        let (guards, time) = self.journal.with_gc_authorization_check(
            &self.space_id,
            id,
            self.limits.max_storage_entries,
            now_ms,
            |intent| -> Result<_> {
                crate::fault::checkpoint("after_gc_authorization_check_journal_lock");
                let (guards, boundary) = crate::gc_preflight::windows::inspect(
                    self,
                    &intent.mark,
                    "after_gc_authorization_check_file_lock",
                )?;
                if boundary != intent.boundary {
                    return Err(ReconcileError::Invariant(
                        "GC authorization directory boundary changed",
                    ));
                }
                Ok(guards)
            },
        )?;
        crate::fault::checkpoint("after_gc_authorization_check");
        drop(guards);
        Ok(GcAuthorizationCheck {
            authorization_id: id.clone(),
            checked_at_ms: time,
            guarded_observation_complete: true,
            deletion_authorized: false,
            sweep_available: false,
            gc_enabled: false,
        })
    }
}
