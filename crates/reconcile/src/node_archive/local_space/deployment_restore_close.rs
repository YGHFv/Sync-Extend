//! The initial native writer and closed evidence share one actual resource terminal.
use super::{
    OrdinaryCasDirectory, OrdinaryRetainedMutation, OriginalNodeWriteClosed,
    OriginalNodeWriteSession, OriginalWriteMembership,
};
use crate::node_archive::scoped_close::{
    close_original_scoped_resources, OriginalNodeCasReadersToClose, OriginalNodeJournalToClose,
    OriginalNodeOwnedResourceGroups, OriginalNodePendingResourceClose,
};
use sync_extend_platform_fs::ClosedWindowsOriginalResources;

pub type OriginalNodeWriteResourceCloseFailure<'scope> =
    crate::node_archive::scoped_close::OriginalNodeScopedResourceCloseFailure<'scope>;

#[allow(dead_code)]
enum OriginalWriteTerminalContext {
    Session {
        ordinary_files:
            Vec<crate::node_archive::node_write_transition::OrdinaryFileCreationReceipt>,
        new_cas_evidence: Vec<crate::node_archive::node_write_transition::OrdinaryCasEvidence>,
        attempt: crate::node_archive::node_write_transition::OriginalNodeWriteAttempt,
        native_keys: [sync_extend_platform_fs::FileKey; 3],
        archive_digest: sync_extend_core_model::ContentId,
        membership: OriginalWriteMembership,
        worktree: std::path::PathBuf,
        limits: sync_extend_core_model::limits::LocalLimits,
        uncertain: bool,
        wrote: bool,
        original_local_context: (
            sync_extend_core_model::SpaceId,
            sync_extend_core_model::DeviceId,
            std::path::PathBuf,
            Option<sync_extend_core_model::ContentId>,
        ),
    },
    Closed {
        ordinary_files:
            Vec<crate::node_archive::node_write_transition::OrdinaryFileCreationReceipt>,
        new_cas_evidence: Vec<crate::node_archive::node_write_transition::OrdinaryCasEvidence>,
        archive_digest: sync_extend_core_model::ContentId,
        membership: OriginalWriteMembership,
        native_keys: [sync_extend_platform_fs::FileKey; 3],
        rows_observed_before_close: sync_extend_core_model::ContentId,
        original_local_context: (
            sync_extend_core_model::SpaceId,
            sync_extend_core_model::DeviceId,
            std::path::PathBuf,
            Option<sync_extend_core_model::ContentId>,
        ),
    },
}

struct OriginalWritePendingResources<'scope> {
    readonly_closed: Vec<ClosedWindowsOriginalResources>,
    journal_objects: Option<(
        [sync_extend_platform_fs::ReleasedOriginalFileIdentity; 3],
        sync_extend_platform_fs::ReleasedOriginalCoordinationFile,
    )>,
    directories: &'scope crate::node_archive::CreatedNodeDirectorySet<'scope>,
    readers: crate::node_archive::assembly::ReadContents,
    retained_mutations: Vec<OrdinaryRetainedMutation>,
    new_cas_directories: std::collections::BTreeMap<Vec<String>, OrdinaryCasDirectory>,
    data_locks: crate::node_archive::CreatedNodeDataLocks<'scope>,
    ledger: crate::node_archive::node_write_transition::OriginalNodeWriteLedger,
    data_writer: sync_extend_platform_fs::WriterOwner,
    worktree_writer: sync_extend_platform_fs::WriterOwner,
    context: OriginalWriteTerminalContext,
}

struct OriginalWriteResourceParts<'scope> {
    journal: Option<OriginalNodeJournalToClose>,
    cas: sync_extend_cas::Cas,
    cas_readers: crate::original_managed_cas::OriginalManagedCasReadResources,
    pending: OriginalWritePendingResources<'scope>,
}

impl<'scope> OriginalWriteResourceParts<'scope> {
    fn append_to(self, original: &mut OriginalNodeOwnedResourceGroups<'scope>) {
        let Self {
            journal,
            cas,
            cas_readers,
            pending,
        } = self;
        original.journals.extend(journal);
        original.cas.push(cas);
        original
            .cas_readers
            .push(OriginalNodeCasReadersToClose::Read(cas_readers));
        original.pending.push(Box::new(pending));
    }

    fn close(
        self,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        OriginalNodeWriteResourceCloseFailure<'scope>,
    > {
        let Self {
            journal,
            cas,
            cas_readers,
            pending,
        } = self;
        close_original_scoped_resources(journal, cas, cas_readers, pending)
    }

    fn fail(self, error: crate::ReconcileError) -> OriginalNodeWriteResourceCloseFailure<'scope> {
        let mut original = OriginalNodeOwnedResourceGroups::new();
        self.append_to(&mut original);
        original.fail(error)
    }
}

impl<'scope> OriginalNodeWriteSession<'scope> {
    pub fn close_failed_original_resources_retaining(
        self,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        OriginalNodeWriteResourceCloseFailure<'scope>,
    > {
        self.into_original_resource_parts().close()
    }

    pub(super) fn append_original_resources(
        self,
        original: &mut OriginalNodeOwnedResourceGroups<'scope>,
    ) {
        self.into_original_resource_parts().append_to(original);
    }

    pub(super) fn fail_original_resources_retaining(
        self,
        error: crate::ReconcileError,
    ) -> OriginalNodeWriteResourceCloseFailure<'scope> {
        self.into_original_resource_parts().fail(error)
    }

    fn into_original_resource_parts(self) -> OriginalWriteResourceParts<'scope> {
        let Self {
            original,
            directories,
            readers,
            ordinary_files,
            retained_mutations,
            new_cas_directories,
            new_cas_evidence,
            data_locks,
            ledger,
            attempt,
            native_keys,
            archive_digest,
            membership,
            worktree,
            limits,
            _data_writer,
            _worktree_writer,
            cas,
            original_cas_readers,
            uncertain,
            wrote,
            read_context_closed,
            original_local_context,
        } = self;
        let context = OriginalWriteTerminalContext::Session {
            ordinary_files,
            new_cas_evidence,
            attempt,
            native_keys,
            archive_digest,
            membership,
            worktree,
            limits,
            uncertain,
            wrote,
            original_local_context,
        };
        let pending = OriginalWritePendingResources {
            readonly_closed: vec![read_context_closed],
            journal_objects: None,
            directories,
            readers,
            retained_mutations,
            new_cas_directories,
            data_locks,
            ledger,
            data_writer: _data_writer,
            worktree_writer: _worktree_writer,
            context,
        };
        OriginalWriteResourceParts {
            journal: Some(OriginalNodeJournalToClose::Write(original)),
            cas,
            cas_readers: original_cas_readers,
            pending,
        }
    }
}

impl<'scope> OriginalNodeWriteClosed<'scope> {
    pub fn close_original_resources_retaining(
        self,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        OriginalNodeWriteResourceCloseFailure<'scope>,
    > {
        self.into_original_resource_parts().close()
    }

    pub(super) fn fail_original_resources_retaining(
        self,
        error: crate::ReconcileError,
    ) -> OriginalNodeWriteResourceCloseFailure<'scope> {
        self.into_original_resource_parts().fail(error)
    }

    fn into_original_resource_parts(self) -> OriginalWriteResourceParts<'scope> {
        let Self {
            objects,
            cas_coordination,
            readonly_closed,
            directories,
            readers,
            ordinary_files,
            retained_mutations,
            new_cas_directories,
            new_cas_evidence,
            data_locks,
            ledger,
            archive_digest,
            membership,
            native_keys,
            rows_observed_before_close,
            _data_writer,
            _worktree_writer,
            cas,
            original_cas_readers,
            read_context_closed,
            original_local_context,
        } = self;
        let context = OriginalWriteTerminalContext::Closed {
            ordinary_files,
            new_cas_evidence,
            archive_digest,
            membership,
            native_keys,
            rows_observed_before_close,
            original_local_context,
        };
        let pending = OriginalWritePendingResources {
            readonly_closed: vec![readonly_closed, read_context_closed],
            journal_objects: Some((objects, cas_coordination)),
            directories,
            readers,
            retained_mutations,
            new_cas_directories,
            data_locks,
            ledger,
            data_writer: _data_writer,
            worktree_writer: _worktree_writer,
            context,
        };
        OriginalWriteResourceParts {
            journal: None,
            cas,
            cas_readers: original_cas_readers,
            pending,
        }
    }
}

impl<'scope> OriginalNodePendingResourceClose<'scope> for OriginalWritePendingResources<'scope> {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        crate::node_archive::OriginalNodeResourceCloseFailure<'scope>,
    > {
        let Self {
            readonly_closed,
            journal_objects,
            directories,
            readers,
            retained_mutations,
            new_cas_directories,
            data_locks,
            ledger,
            data_writer,
            worktree_writer,
            context,
        } = *self;
        let mut attempt = crate::node_archive::OriginalNodeResourceCloseAttempt::new();
        for closed in readonly_closed {
            attempt.append_closed(closed);
        }
        attempt.keep_context((directories, context));
        if let Some((objects, cas_coordination)) = journal_objects {
            for original in objects {
                original.close_into_attempt(&mut attempt.native);
            }
            cas_coordination.close_into_attempt(&mut attempt.native);
        }
        for (slot, original) in readers {
            let crate::node_archive::assembly::ReadContent {
                original,
                bytes,
                digest,
            } = original;
            attempt.keep_context((slot, bytes, digest));
            original.close_into_attempt(&mut attempt.native);
        }
        for original in retained_mutations {
            let OrdinaryRetainedMutation {
                directory,
                path,
                original,
                evidence,
            } = original;
            let crate::node_archive::assembly::ReadContent {
                original,
                bytes,
                digest,
            } = original;
            attempt.keep_context((path, evidence, bytes, digest));
            original.close_into_attempt(&mut attempt.native);
            directory.close_into_attempt(&mut attempt.native);
        }
        for (slot, original) in new_cas_directories.into_iter().rev() {
            let OrdinaryCasDirectory {
                creator,
                path,
                key,
                parent,
            } = original;
            attempt.keep_context((slot, path, key, parent));
            creator.close_into_attempt(&mut attempt.native);
        }
        ledger.close_into_attempt(&mut attempt);
        data_writer.close_into_attempt(&mut attempt.native);
        worktree_writer.close_into_attempt(&mut attempt.native);
        data_locks.close_into_attempt(&mut attempt);
        attempt.finish()
    }
}
