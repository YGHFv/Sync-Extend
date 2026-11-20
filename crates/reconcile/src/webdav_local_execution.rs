//! Complete original lifetime DAV admission; no native effect grants from descriptions.
use crate::{LocalSpace, Result};
use sync_extend_core_model::{
    webdav_mutation::WebDavMutationRequest, webdav_native::WebDavNativeLimits, EntryId,
};
pub use sync_extend_journal::WebDavBudgetLimits;
use sync_extend_journal::{WebDavDurableExecution, WebDavLiveAdmission};

pub struct WebDavLocalExecution<'a> {
    local: &'a LocalSpace,
    held: WebDavLiveAdmission<'a>,
}

impl LocalSpace {
    pub fn admit_complete_webdav<'a>(
        &'a self,
        request: &WebDavMutationRequest,
        native: WebDavNativeLimits,
        budget: WebDavBudgetLimits,
        max_handles: usize,
        max_receipt_json: u64,
    ) -> Result<WebDavLocalExecution<'a>> {
        self.verify_root()?;
        if max_handles == 0
            || max_handles > self.limits.max_storage_entries
            || budget.max_templates > self.limits.max_storage_entries
            || budget.max_bindings > self.limits.max_storage_entries
            || budget.execution_records > self.limits.max_storage_entries
            || native.max_bindings > self.limits.max_storage_entries
            || native.max_actions > self.limits.max_storage_entries
            || native.max_staging_bytes > self.limits.max_staging_bytes
            || request.max_entries > self.limits.max_scan_entries
            || request.max_operations > self.limits.max_storage_entries
            || request.max_metadata_bytes > self.limits.max_scan_bytes
            || request.max_retained_bytes > self.limits.max_staging_bytes
        {
            return Err(crate::ReconcileError::Invariant(
                "bounded complete DAV original owner",
            ));
        }
        // Conservative full request headroom including initial marker. Later native
        // phases must use the borrowed original file view for exact remaining inventory.
        self.reserve_internal_worktree(native.max_staging_bytes)?;
        let held = self.journal.admit_complete_dav(
            &self._lock,
            &self._worktree_lock,
            &self.space_id,
            request,
            native,
            budget,
            max_handles,
            max_receipt_json,
            crate::now_ms()?,
        )?;
        self.reserve_native_internal_worktree(&held.inventory_file_view()?)?;
        Ok(WebDavLocalExecution { local: self, held })
    }
}

impl WebDavLocalExecution<'_> {
    pub fn failed_native_status(
        &self,
    ) -> Option<sync_extend_core_model::webdav_partial_response::WebDavCollectionFailure> {
        self.held.failed_native_status()
    }
    pub fn failed_native_path(&self) -> Option<&sync_extend_core_model::PortablePath> {
        self.held.failed_native_path()
    }
    pub fn verify_originals(&self) -> Result<()> {
        self.local.verify_root()?;
        self.held.verify_file_view()?;
        Ok(())
    }
    pub fn native_plan(&self) -> &sync_extend_core_model::webdav_native::WebDavNativePlan {
        self.held.native_plan()
    }

    pub fn execution(&self) -> &WebDavDurableExecution {
        self.held.execution()
    }

    /// Persist intent under original live ownership. This performs no native effect.
    pub fn activate(&mut self, attempt: &EntryId) -> Result<WebDavDurableExecution> {
        self.local.verify_root()?;
        self.local
            .reserve_native_internal_worktree(&self.held.inventory_file_view()?)?;
        let time = match self.held.execution().records.first() {
            Some(record) if &record.attempt_id == attempt => record.recorded_at_ms,
            Some(_) => {
                return Err(crate::ReconcileError::Invariant(
                    "complete DAV activation attempt already bound",
                ))
            }
            None => crate::now_ms()?,
        };
        Ok(self.held.activate(attempt, time)?)
    }
}

impl WebDavLocalExecution<'_> {
    /// Real private initial CREATE sequence after complete durable activation.
    pub fn create_initial_owner(&mut self) -> Result<()> {
        self.local.verify_root()?;
        self.local
            .reserve_native_internal_worktree(&self.held.inventory_file_view()?)?;
        let local = self.local;
        self.held.create_initial_owner_with_policy(
            || {
                crate::now_ms().map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("DAV collection clock unavailable")
                })
            },
            |view| {
                local.reserve_native_internal_worktree(view).map_err(|_| {
                    sync_extend_journal::JournalError::Invariant(
                        "current held DAV internal storage policy",
                    )
                })
            },
        )?;
        self.local
            .reserve_native_internal_worktree(&self.held.inventory_file_view()?)?;
        Ok(())
    }
}

impl crate::native_file_view::NativeFileView for WebDavLiveAdmission<'_> {
    fn verify(&self) -> sync_extend_journal::Result<()> {
        self.verify_file_view()
    }
    fn observe_file(
        &self,
        path: &std::path::Path,
    ) -> sync_extend_journal::Result<Option<sync_extend_journal::NativePublicationFileObservation>>
    {
        self.observe_file(path)
    }
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
        self.remaining_internal_bytes()
    }
}

impl WebDavLocalExecution<'_> {
    /// Actual native collection prefix, retaining originals while awaiting Final.
    pub fn execute_collection_actions(&mut self) -> Result<()> {
        let local = self.local;
        self.held.execute_collection_actions_with_policy(
            || {
                crate::now_ms().map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("DAV collection clock unavailable")
                })
            },
            |view| {
                local.reserve_native_internal_worktree(view).map_err(|_| {
                    sync_extend_journal::JournalError::Invariant(
                        "current original DAV collection policy",
                    )
                })
            },
        )?;
        Ok(())
    }
}

impl WebDavLocalExecution<'_> {
    pub fn commit_collection_final(&mut self) -> Result<()> {
        let local = self.local;
        self.held.commit_collection_final_with_policy(
            || {
                crate::now_ms().map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("DAV collection clock unavailable")
                })
            },
            |view| {
                local.reserve_native_internal_worktree(view).map_err(|_| {
                    sync_extend_journal::JournalError::Invariant(
                        "current original DAV Final policy",
                    )
                })
            },
        )?;
        Ok(())
    }
}

impl WebDavLocalExecution<'_> {
    pub fn dispose_collection_originals(&mut self) -> Result<()> {
        let local = self.local;
        self.held.dispose_collection_originals_with_policy(
            || {
                crate::now_ms().map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("DAV collection clock unavailable")
                })
            },
            |view| {
                local.reserve_native_internal_worktree(view).map_err(|_| {
                    sync_extend_journal::JournalError::Invariant(
                        "current original DAV disposal policy",
                    )
                })
            },
        )?;
        Ok(())
    }
}

impl WebDavLocalExecution<'_> {
    pub fn finish_collection_cleanup(&mut self) -> Result<()> {
        let local = self.local;
        self.held.finish_collection_cleanup_with_policy(
            || {
                crate::now_ms().map_err(|_| {
                    sync_extend_journal::JournalError::Invariant("DAV collection clock unavailable")
                })
            },
            |view| {
                local.reserve_native_internal_worktree(view).map_err(|_| {
                    sync_extend_journal::JournalError::Invariant(
                        "current original DAV owner cleanup policy",
                    )
                })
            },
        )?;
        Ok(())
    }
}

impl LocalSpace {
    /// Original plan, original live owner, actual native results, Final and cleanup.
    /// HTTP must authorize all paths/conditions before invoking this transaction.
    pub fn commit_complete_webdav_collection(
        &self,
        request: &WebDavMutationRequest,
        native: WebDavNativeLimits,
        budget: WebDavBudgetLimits,
        max_handles: usize,
        max_receipt_json: u64,
    ) -> Result<crate::WebDavCommit> {
        let mut held =
            self.admit_complete_webdav(request, native, budget, max_handles, max_receipt_json)?;
        held.activate(&EntryId::random()?)?;
        held.create_initial_owner()?;
        held.execute_collection_actions()?;
        held.commit_collection_final()?;
        held.dispose_collection_originals()?;
        held.finish_collection_cleanup()?;
        held.verify_originals()?;
        let snapshot_id = held.native_plan().final_manifest().root()?;
        if !held.execution().final_committed
            || held.execution().unresolved_activation
            || held.execution().future_rows != 0
            || held.execution().future_bytes != 0
            || held.execution().records.len() != held.native_plan().steps().len() * 2
        {
            return Err(crate::ReconcileError::Invariant(
                "complete original DAV lifecycle incomplete",
            ));
        }
        Ok(crate::WebDavCommit {
            transaction_id: request.transaction_id.clone(),
            snapshot_id,
            local_committed: true,
            remote_backup_complete: false,
        })
    }
}

impl crate::native_file_view::NativeFileView
    for sync_extend_journal::WebDavInventoryFileView<'_, '_>
{
    fn verify(&self) -> sync_extend_journal::Result<()> {
        self.verify()
    }
    fn observe_file(
        &self,
        path: &std::path::Path,
    ) -> sync_extend_journal::Result<Option<sync_extend_journal::NativePublicationFileObservation>>
    {
        self.observe_file(path)
    }
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
        self.remaining_internal_bytes()
    }
}

/// Borrow an immutable inventory view under the original root and quota policy.
/// The view retains live ownership and grants no native effects.
impl<'owner> WebDavLocalExecution<'owner> {
    pub fn inventory_file_view(
        &self,
    ) -> Result<sync_extend_journal::WebDavInventoryFileView<'_, 'owner>> {
        self.local.verify_root()?;
        let view = self.held.inventory_file_view()?;
        self.local.reserve_native_internal_worktree(&view)?;
        Ok(view)
    }
}
