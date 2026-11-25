//! Consuming actual readonly assembly and LocalSpace scope resources.
use super::{
    assembly::ReadContents, scoped_close::OriginalNodePendingResourceClose, CreatedNodeDataLocks,
    CreatedNodeDirectorySet, OriginalNodeReadAssembly, OriginalNodeResourceCloseAttempt,
    OriginalNodeResourceCloseFailure,
};
use sync_extend_platform_fs::ClosedWindowsOriginalResources;

pub(super) struct OriginalReadPendingResources<'scope, Context> {
    pub(super) directories: &'scope CreatedNodeDirectorySet<'scope>,
    pub(super) readers: ReadContents,
    pub(super) data_locks: CreatedNodeDataLocks<'scope>,
    pub(super) writers: Option<(
        sync_extend_platform_fs::WriterOwner,
        sync_extend_platform_fs::WriterOwner,
    )>,
    pub(super) identity: Option<crate::filesystem::PathIdentity>,
    pub(super) identity_failure:
        Option<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
    pub(super) already_closed: Vec<ClosedWindowsOriginalResources>,
    pub(super) context: Context,
}

impl<'scope, Context: 'scope> OriginalNodePendingResourceClose<'scope>
    for OriginalReadPendingResources<'scope, Context>
{
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalNodeResourceCloseFailure<'scope>>
    {
        let Self {
            directories,
            readers,
            data_locks,
            writers,
            identity,
            identity_failure,
            already_closed,
            context,
        } = *self;
        let mut attempt = OriginalNodeResourceCloseAttempt::new();
        attempt.keep_context((directories, context));
        for closed in already_closed {
            attempt.append_closed(closed);
        }
        if let Some(original) = identity_failure {
            attempt.native.append_failure(original.close_remaining());
        }
        for (slot, file) in readers {
            let super::assembly::ReadContent {
                original,
                bytes,
                digest,
            } = file;
            attempt.keep_context((slot, bytes, digest));
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some((data, worktree)) = writers {
            data.close_into_attempt(&mut attempt.native);
            worktree.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = identity {
            let physical = original.close_original_into_attempt(&mut attempt.native);
            attempt.keep_context(physical);
        }
        data_locks.close_into_attempt(&mut attempt);
        attempt.finish()
    }
}

impl<'scope> OriginalNodeReadAssembly<'scope> {
    pub(super) fn close_failed_original_resources_retaining(
        self,
        error: crate::ReconcileError,
    ) -> super::OriginalNodeScopedResourceCloseFailure<'scope> {
        let Self {
            directories,
            data_locks,
            readers,
            journal,
            cas,
            original_cas_readers,
            archive_digest,
            read_lease_hold,
            space,
        } = self;
        let pending = OriginalReadPendingResources {
            directories,
            readers,
            data_locks,
            writers: None,
            identity: None,
            identity_failure: None,
            already_closed: Vec::new(),
            context: (archive_digest, read_lease_hold, space),
        };
        super::scoped_close::fail_original_scoped_resources(
            error,
            Some(super::scoped_close::OriginalNodeJournalToClose::Read(
                journal,
            )),
            Some(cas),
            Some(super::scoped_close::OriginalNodeCasReadersToClose::Read(
                original_cas_readers,
            )),
            pending,
        )
    }

    pub fn close_original_resources_retaining(
        self,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        super::OriginalNodeScopedResourceCloseFailure<'scope>,
    > {
        let Self {
            directories,
            data_locks,
            readers,
            journal,
            cas,
            original_cas_readers,
            archive_digest,
            read_lease_hold,
            space,
        } = self;
        let pending = OriginalReadPendingResources {
            directories,
            readers,
            data_locks,
            writers: None,
            identity: None,
            identity_failure: None,
            already_closed: Vec::new(),
            context: (archive_digest, read_lease_hold, space),
        };
        super::scoped_close::close_original_scoped_resources(
            Some(super::scoped_close::OriginalNodeJournalToClose::Read(
                journal,
            )),
            cas,
            original_cas_readers,
            pending,
        )
    }
}
