//! End every actual failed opening prefix before releasing its protective scope.
use super::{
    OriginalNodeWriteOpenFailure, OriginalNodeWriteOpening, OriginalNodeWriteRemainder,
    OriginalRestoredLocalSpace,
};
use crate::{
    node_archive::{
        read_close::OriginalReadPendingResources,
        scoped_close::{
            OriginalNodeCasReadersToClose, OriginalNodeJournalToClose,
            OriginalNodeOwnedResourceGroups, OriginalNodePendingResourceClose,
        },
        OriginalNodeResourceCloseAttempt, OriginalNodeResourceCloseFailure,
        OriginalNodeScopedResourceCloseFailure,
    },
    LocalSpace, ReconcileError,
};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, OriginalSqliteSidecarHandoff,
    OriginalSqliteSidecarHandoffFailure, OwnedFileCreation,
};

pub(super) fn copy_original_reconcile_error(error: &ReconcileError) -> ReconcileError {
    match error {
        ReconcileError::Io(error) => copy_original_io_error(error).into(),
        ReconcileError::Invariant(message) => ReconcileError::Invariant(message),
        ReconcileError::Unstable => ReconcileError::Unstable,
        ReconcileError::ResourceLimit(message) => ReconcileError::ResourceLimit(message),
        _ => std::io::Error::other(error.to_string()).into(),
    }
}

fn copy_original_io_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}

pub(super) fn sidecar_failure_error(error: &OriginalSqliteSidecarHandoffFailure) -> ReconcileError {
    let error = match error {
        OriginalSqliteSidecarHandoffFailure::Creator { error, .. }
        | OriginalSqliteSidecarHandoffFailure::Released { error, .. }
        | OriginalSqliteSidecarHandoffFailure::Terminating { error, .. } => error,
    };
    copy_original_io_error(error).into()
}

struct OriginalOpeningPendingResources {
    ledger: Option<crate::node_archive::node_write_transition::OriginalNodeWriteLedger>,
    ledger_failed:
        Option<crate::node_archive::node_write_transition::OriginalNodeWriteLedgerCreationFailure>,
    attempt: Option<crate::node_archive::node_write_transition::OriginalNodeWriteAttempt>,
    wal_creator: Option<OwnedFileCreation>,
    rollback_creator: Option<OwnedFileCreation>,
    wal: Option<OriginalSqliteSidecarHandoff>,
    rollback: Option<OriginalSqliteSidecarHandoff>,
    sidecar_failed: Option<OriginalSqliteSidecarHandoffFailure>,
}

impl<'scope> OriginalNodePendingResourceClose<'scope> for OriginalOpeningPendingResources {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalNodeResourceCloseFailure<'scope>>
    {
        let Self {
            ledger,
            ledger_failed,
            attempt,
            wal_creator,
            rollback_creator,
            wal,
            rollback,
            sidecar_failed,
        } = *self;
        let mut terminal = OriginalNodeResourceCloseAttempt::new();
        terminal.keep_context(attempt);
        if let Some(original) = wal_creator {
            original.close_into_attempt(&mut terminal.native);
        }
        if let Some(original) = rollback_creator {
            original.close_into_attempt(&mut terminal.native);
        }
        if let Some(original) = wal {
            original.close_into_attempt(&mut terminal.native);
        }
        if let Some(original) = rollback {
            original.close_into_attempt(&mut terminal.native);
        }
        if let Some(original) = sidecar_failed {
            original.close_into_attempt(&mut terminal.native);
        }
        if let Some(original) = ledger {
            original.close_into_attempt(&mut terminal);
        }
        if let Some(original) = ledger_failed {
            original.close_into_attempt(&mut terminal);
        }
        terminal.finish()
    }
}

impl<'scope> OriginalNodeWriteOpening<'scope> {
    fn actual_journal_open_attempted(&self) -> bool {
        self.original.is_some()
            || self.ready_failed.is_some()
            || self.journal_failed.as_ref().is_some_and(|original| {
                matches!(
                    original,
                    sync_extend_journal::OriginalJournalTransitionFailure::Opening { .. }
                        | sync_extend_journal::OriginalJournalTransitionFailure::Open { .. }
                )
            })
    }

    fn close_failed_original_resources_retaining(
        self: Box<Self>,
        error: ReconcileError,
    ) -> OriginalNodeScopedResourceCloseFailure<'scope> {
        let Self {
            local,
            remainder,
            journal,
            journal_failed,
            original,
            ready_failed,
            ledger,
            ledger_failed,
            attempt,
            wal_creator,
            rollback_creator,
            wal,
            rollback,
            sidecar_failed,
        } = *self;
        let mut originals = OriginalNodeOwnedResourceGroups::new();
        if let Some(original) = journal {
            originals
                .journals
                .push(OriginalNodeJournalToClose::Read(original));
        }
        if let Some(original) = journal_failed {
            originals
                .journals
                .push(OriginalNodeJournalToClose::TransitionFailure(original));
        }
        if let Some(original) = original {
            originals
                .journals
                .push(OriginalNodeJournalToClose::Write(original));
        }
        if let Some(original) = local {
            let OriginalRestoredLocalSpace {
                local,
                directories,
                readers,
                data_locks,
                archive_digest,
                original_cas_readers,
                original_observer_closed,
            } = original;
            let LocalSpace {
                space_id,
                device_id,
                worktree,
                data_dir,
                cas,
                journal,
                limits,
                root_identity,
                _lock,
                _worktree_lock,
            } = local;
            originals
                .journals
                .push(OriginalNodeJournalToClose::Read(journal));
            originals.cas.push(cas);
            originals
                .cas_readers
                .push(OriginalNodeCasReadersToClose::Read(original_cas_readers));
            originals
                .pending
                .push(Box::new(OriginalReadPendingResources {
                    directories,
                    readers,
                    data_locks,
                    writers: Some((_lock, _worktree_lock)),
                    identity: Some(root_identity),
                    identity_failure: None,
                    already_closed: vec![original_observer_closed],
                    context: (
                        archive_digest,
                        space_id,
                        device_id,
                        worktree,
                        data_dir,
                        limits,
                    ),
                }));
        }
        if let Some(original) = remainder {
            let OriginalNodeWriteRemainder {
                directories,
                readers,
                data_locks,
                archive_digest,
                worktree,
                limits,
                data_writer,
                worktree_writer,
                cas,
                original_cas_readers,
                root_identity,
                root_identity_failure,
                read_context_closed,
                original_local_context,
            } = original;
            originals.cas.push(cas);
            originals
                .cas_readers
                .push(OriginalNodeCasReadersToClose::Read(original_cas_readers));
            originals
                .pending
                .push(Box::new(OriginalReadPendingResources {
                    directories,
                    readers,
                    data_locks,
                    writers: Some((data_writer, worktree_writer)),
                    identity: root_identity,
                    identity_failure: root_identity_failure,
                    already_closed: read_context_closed.into_iter().collect(),
                    context: (archive_digest, worktree, limits, original_local_context),
                }));
        }
        if let Some(original) = ready_failed {
            original.append_original_resources(&mut originals);
        }
        originals
            .pending
            .push(Box::new(OriginalOpeningPendingResources {
                ledger,
                ledger_failed,
                attempt,
                wal_creator,
                rollback_creator,
                wal,
                rollback,
                sidecar_failed,
            }));
        originals.fail(error)
    }
}

impl<'scope> OriginalNodeWriteOpenFailure<'scope> {
    pub(super) fn from_failed_state(
        state: Box<OriginalNodeWriteOpening<'scope>>,
        error: ReconcileError,
    ) -> Self {
        let actual_journal_open_attempted = state.actual_journal_open_attempted();
        Self {
            state: Some(state),
            resources: None,
            error: Some(error),
            actual_journal_open_attempted,
        }
    }

    pub fn error(&self) -> &ReconcileError {
        self.error
            .as_ref()
            .expect("original opening first error retained")
    }

    pub fn actual_journal_open_attempted(&self) -> bool {
        self.actual_journal_open_attempted
    }

    pub fn has_retained_originals(&self) -> bool {
        self.state.is_some()
            || self
                .resources
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
    }

    /// Retry only the same native owners and failed original HANDLEs. This
    /// never yields a session, a completed write or permission to reopen paths.
    pub fn close_remaining(mut self) -> Self {
        if let Some(state) = self.state.take() {
            self.resources = Some(state.close_failed_original_resources_retaining(
                copy_original_reconcile_error(self.error()),
            ));
        } else if let Some(original) = self.resources.take() {
            self.resources = Some(original.close_remaining());
        }
        self
    }

    pub fn into_resource_close_failure(mut self) -> OriginalNodeScopedResourceCloseFailure<'scope> {
        let error = self
            .error
            .take()
            .expect("same original opening first error");
        if let Some(state) = self.state.take() {
            state.close_failed_original_resources_retaining(error)
        } else {
            let mut original = self
                .resources
                .take()
                .expect("same opening resource terminal");
            original.error = error;
            original
        }
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> ReconcileError {
        self.into_resource_close_failure().retain_and_report()
    }
}

impl std::fmt::Debug for OriginalNodeWriteOpenFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalNodeWriteOpenFailure")
            .field("error", &self.error())
            .field(
                "actual_journal_open_attempted",
                &self.actual_journal_open_attempted,
            )
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl Drop for OriginalNodeWriteOpenFailure<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            // Retain the whole failed prefix if an external caller abandons
            // it before the explicit resource-only terminal can consume it.
            let first_error = self.error.as_ref().map(ToString::to_string);
            let _ = Box::leak(Box::new((state, first_error)));
        }
    }
}
