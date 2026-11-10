//! Bounded scheduling over durable originals, with no catch-up bursts or fake retries.
#[cfg(windows)]
use crate::{LocalSpace, ReconcileError, Result};
#[cfg(windows)]
use std::collections::BTreeSet;
#[cfg(windows)]
use sync_extend_core_model::{ContentId, DeviceId};
#[cfg(windows)]
use sync_extend_transport::OriginalOperationPage;

#[cfg(windows)]
impl LocalSpace {
    /// Retry the first unfinished immutable page before a new connection.
    /// Pending native lineage or safety refusal stops new admission, not a rescan.
    pub fn resume_original_worker_page(&mut self, origin: &DeviceId) -> Result<Option<ContentId>> {
        self.resume_original_worker_page_with_conflicts(origin, None)
    }

    /// Conflict resolution is explicit opt-in with a supplied display time,
    /// never a default policy or unsigned best-effort overwrite.
    pub fn resume_original_worker_page_with_conflicts(
        &mut self,
        origin: &DeviceId,
        resolve_at_ms: Option<u64>,
    ) -> Result<Option<ContentId>> {
        let pages = self.original_content_inbox(64)?;
        let after = self.original_worker_after(origin)?;
        let pending = self.original_worker_pending_operations()?;
        let candidate = pages
            .into_iter()
            .filter(|e| {
                e.source.device_id == *origin
                    && e.signed_page.page.operations.iter().any(|s| {
                        pending.contains(&s.operation.op_id)
                            || s.operation.payload.origin_seq > after
                    })
            })
            .min_by_key(|e| {
                e.signed_page
                    .page
                    .operations
                    .first()
                    .map_or(0, |s| s.operation.payload.origin_seq)
            });
        let Some(envelope) = candidate else {
            return Ok(None);
        };
        let request = envelope
            .signed_page
            .page
            .request_id()
            .map_err(|_| ReconcileError::Invariant("original worker retained page identity"))?;
        let preparation = self.resume_original_content(&request)?;
        if !preparation.content_closed {
            // Missing protected bytes may be fetched under a new live channel.
            return Ok(None);
        }
        self.receive_original_page(&request)?;
        for signed in &envelope.signed_page.page.operations {
            match self.apply_original_operation(&request, &signed.operation.op_id) {
                Ok(outcome)
                    if matches!(
                        outcome.state,
                        crate::OriginalApplyState::Applied
                            | crate::OriginalApplyState::AlreadyApplied
                    ) => {}
                other => {
                    if let Some(time) = resolve_at_ms {
                        self.apply_retained_original_file_conflict(time, Default::default())?;
                        break;
                    }
                    other?;
                    return Err(ReconcileError::Invariant(
                        "original worker retained native page pending",
                    ));
                }
            }
        }
        self.original_applied_receipt(&request)?;
        Ok(Some(request))
    }

    fn original_worker_pending_operations(
        &self,
    ) -> Result<BTreeSet<sync_extend_core_model::OperationId>> {
        let mut operations = BTreeSet::new();
        for publication in self.journal.outstanding_publications(&self.space_id)? {
            if let Some(proof) = publication.intent.remote {
                operations.insert(proof.operation.op_id);
            }
        }
        for receipt in self.remote_replace_receipts()? {
            if !receipt.native_cleanup_complete {
                operations.insert(receipt.operation_id);
            }
        }
        for receipt in self.remote_delete_receipts()? {
            if !receipt.native_cleanup_complete {
                operations.insert(receipt.operation_id);
            }
        }
        for receipt in self.remote_rename_receipts()? {
            if !receipt.local_committed {
                operations.insert(receipt.operation_id);
            }
        }
        Ok(operations)
    }

    fn original_worker_native_pending(&self) -> Result<bool> {
        Ok(!self
            .journal
            .outstanding_publications(&self.space_id)?
            .is_empty()
            || self
                .remote_replace_receipts()?
                .iter()
                .any(|r| !r.native_cleanup_complete)
            || self
                .remote_delete_receipts()?
                .iter()
                .any(|r| !r.native_cleanup_complete)
            || self
                .remote_rename_receipts()?
                .iter()
                .any(|r| !r.local_committed))
    }

    /// No unsigned page can authorize content import, even after transport retry.
    pub fn original_worker_has_pending_native(&self) -> Result<bool> {
        self.verify_root()?;
        self.original_worker_native_pending()
    }

    /// Applied state is not the received cursor. Explicitly prefer a durable
    /// complete applied frontier for future native pages.
    pub fn original_worker_after(&self, origin: &DeviceId) -> Result<u64> {
        self.verify_root()?;
        let applied = self.manifest()?.map_or(0, |m| m.version_vector.get(origin));
        if applied > self.journal.cursor(&self.space_id, origin)? {
            return Err(ReconcileError::Invariant(
                "original worker applied ahead of received",
            ));
        }
        Ok(applied)
    }
}

/// Pure local budget, not transport permission or a native executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalWorkerBudget {
    pub attempts: u32,
    pub delay_seconds: u32,
}
impl OriginalWorkerBudget {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if !(1..=64).contains(&self.attempts) || !(1..=3600).contains(&self.delay_seconds) {
            return Err("original worker attempt/delay bounds");
        }
        Ok(())
    }
    #[cfg(windows)]
    pub fn last_page_sequence(page: &OriginalOperationPage) -> u64 {
        page.operations
            .last()
            .map_or(page.after_sequence, |s| s.operation.payload.origin_seq)
    }
}

/// Only lost connectivity or bounded I/O waits are retriable. Invalid signatures,
/// frames, content, serialization, policy or native safety are never downgraded.
pub fn original_worker_transport_retryable(error: &sync_extend_transport::TransportError) -> bool {
    use sync_extend_transport::TransportError;
    matches!(
        error,
        TransportError::Io(_)
            | TransportError::Connection(_)
            | TransportError::Protocol(
                "handshake timeout"
                    | "stream timeout"
                    | "send timeout"
                    | "receive timeout"
                    | "finish timeout"
                    | "peer finish timeout"
            )
    )
}

/// One delayed connection per attempt, not multiple immediate catch-up cycles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalPairedWorkerBudget {
    pub attempts: u32,
    pub delay_seconds: u32,
    pub rounds: u32,
}

impl OriginalPairedWorkerBudget {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        OriginalWorkerBudget {
            attempts: self.attempts,
            delay_seconds: self.delay_seconds,
        }
        .validate()?;
        if !(1..=64).contains(&self.rounds) {
            return Err("original paired worker round bounds");
        }
        Ok(())
    }
}

#[cfg(windows)]
impl LocalSpace {
    /// Reopen the original durable conflict lineage before admitting new pages.
    /// Incomplete one-shot creators still fail closed in the existing driver.
    pub fn resume_original_paired_worker(
        &mut self,
        origin: &DeviceId,
        resolve_at_ms: Option<u64>,
    ) -> Result<()> {
        self.resume_original_paired_native_lineage(origin)?;
        self.resume_original_worker_page_with_conflicts(origin, resolve_at_ms)?;
        if self.original_worker_has_pending_native()? {
            return Err(ReconcileError::Invariant(
                "original paired worker pending native lineage",
            ));
        }
        self.journal.require_no_conflict_resolution()?;
        self.verify_root()
    }

    /// A responder may retain received-only conflict pages while waiting for a
    /// foreign signed resolution. This does not reopen incomplete native owners.
    pub fn resume_original_paired_native_lineage(&mut self, origin: &DeviceId) -> Result<()> {
        self.verify_root()?;
        self.read_transport_peer(origin)?;
        // The retained conflict owns the writer gate until its scoped cleanup.
        // Recovery verifies current approval, quotas, CAS and the durable native
        // lineage before any effect. Check exclusion before admitting new work.
        for admission in self.conflict_resolution_admissions()? {
            self.recover_admitted_conflict_native(&admission.transaction_id)?;
        }
        self.require_no_mutation()?;
        if self.original_worker_has_pending_native()? {
            return Err(ReconcileError::Invariant(
                "original paired responder pending native lineage",
            ));
        }
        self.journal.require_no_conflict_resolution()?;
        self.verify_root()
    }

    /// A worker records settled changes only after recovery. An unchanged tree
    /// must not repopulate optional observations cleared by an original Final.
    pub fn scan_original_paired_worker(&mut self) -> Result<()> {
        self.journal.require_no_conflict_resolution()?;
        if self.original_worker_has_pending_native()? {
            return Err(ReconcileError::Invariant(
                "original paired worker scan pending native lineage",
            ));
        }
        self.recover()?;
        self.require_no_mutation()?;
        let scanned = self.stable_scan()?;
        if let Some(manifest) = self.manifest()? {
            // Audit retained inference evidence even when no write is needed.
            self.persisted_rename_candidates(&manifest, &scanned)?;
            if scanned.len() == manifest.entries.len()
                && manifest.entries.values().all(|entry| {
                    scanned.get(&entry.path).is_some_and(|observed| {
                        observed.kind == entry.kind && observed.content == entry.content
                    })
                })
            {
                self.snapshot_audit()?;
                let max = self.limits.max_storage_entries;
                let report = self.journal.storage_capacity(
                    &self.space_id,
                    sync_extend_core_model::limits::MAX_ENTRIES,
                    sync_extend_journal::JournalCapacityLimits {
                        inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                            max_rows: sync_extend_core_model::limits::MAX_ENTRIES,
                            max_logical_bytes: sync_extend_core_model::limits::MAX_ENTRIES as u64
                                * 1024,
                        },
                        max_rows: max as u64,
                        max_logical_bytes: max as u64 * 1024,
                    },
                )?;
                if !report.within_accounted_limits() {
                    return Err(ReconcileError::ResourceLimit(
                        "original paired worker unchanged journal capacity",
                    ));
                }
                return self.verify_root();
            }
        }
        self.commit_scan(&scanned, None)?;
        Ok(())
    }
}
