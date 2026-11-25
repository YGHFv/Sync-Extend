//! Whole original readonly assembly and retained writer constructor prefixes.
use super::OriginalRestoredLocalSpace;
use crate::{
    filesystem, identity,
    node_archive::{
        read_close::OriginalReadPendingResources,
        roots::OriginalNodeWriterChainFailure,
        scoped_close::{
            fail_original_scoped_resources, OriginalNodeCasReadersToClose,
            OriginalNodeJournalToClose, OriginalNodePendingResourceClose,
        },
        OriginalNodeReadAssembly, OriginalNodeResourceCloseAttempt,
        OriginalNodeResourceCloseFailure, OriginalNodeScopedResourceCloseFailure,
        VerifiedNodeStateArchive,
    },
    LocalSpace, ReconcileError, Result,
};
use sync_extend_core_model::{limits::LocalLimits, DeviceId};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, RetainedWriterDirectory, WindowsOriginalCloseAttempt,
    WriterOriginalCreationFailure, WriterOwner,
};

struct OriginalLocalPreparation<'scope> {
    assembly: Option<OriginalNodeReadAssembly<'scope>>,
    data_chain: Vec<RetainedWriterDirectory>,
    worktree_chain: Vec<RetainedWriterDirectory>,
    chain_failure: Option<OriginalNodeWriterChainFailure<'scope>>,
    writer_failure: Option<WriterOriginalCreationFailure>,
    data_writer: Option<WriterOwner>,
    worktree_writer: Option<WriterOwner>,
    root_identity: Option<filesystem::PathIdentity>,
    device: Option<DeviceId>,
    native_prefix: WindowsOriginalCloseAttempt,
}

struct OriginalLocalPendingResources<'scope> {
    original: OriginalReadPendingResources<
        'scope,
        (
            sync_extend_core_model::ContentId,
            Option<sync_extend_core_model::ContentId>,
            sync_extend_core_model::SpaceId,
            Option<DeviceId>,
            LocalLimits,
            String,
        ),
    >,
    data_chain: Vec<RetainedWriterDirectory>,
    worktree_chain: Vec<RetainedWriterDirectory>,
    chain_failure: Option<OriginalNodeWriterChainFailure<'scope>>,
    writer_failure: Option<WriterOriginalCreationFailure>,
    data_writer: Option<WriterOwner>,
    worktree_writer: Option<WriterOwner>,
    native_prefix: WindowsOriginalCloseAttempt,
}

impl<'scope> OriginalNodePendingResourceClose<'scope> for OriginalLocalPendingResources<'scope> {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalNodeResourceCloseFailure<'scope>>
    {
        let Self {
            original,
            data_chain,
            worktree_chain,
            chain_failure,
            writer_failure,
            data_writer,
            worktree_writer,
            native_prefix,
        } = *self;
        let mut attempt = OriginalNodeResourceCloseAttempt::new();
        match native_prefix.finish() {
            Ok(closed) => attempt.append_closed(closed),
            Err(original) => attempt.native.append_failure(original.close_remaining()),
        }
        if let Some(original) = writer_failure {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = chain_failure {
            original.close_into_attempt(&mut attempt);
        }
        if let Some(original) = worktree_writer {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = data_writer {
            original.close_into_attempt(&mut attempt.native);
        }
        for original in worktree_chain
            .into_iter()
            .rev()
            .chain(data_chain.into_iter().rev())
        {
            original.close_into_attempt(&mut attempt.native);
        }
        match Box::new(original).close() {
            Ok(closed) => attempt.append_closed(closed),
            Err(original) => attempt.append_failure(original),
        }
        attempt.finish()
    }
}

impl<'scope> OriginalLocalPreparation<'scope> {
    fn fail(
        self,
        error: ReconcileError,
        limits: LocalLimits,
    ) -> OriginalNodeScopedResourceCloseFailure<'scope> {
        let Self {
            assembly,
            data_chain,
            worktree_chain,
            chain_failure,
            writer_failure,
            data_writer,
            worktree_writer,
            root_identity,
            device,
            native_prefix,
        } = self;
        let OriginalNodeReadAssembly {
            directories,
            data_locks,
            readers,
            journal,
            cas,
            original_cas_readers,
            archive_digest,
            read_lease_hold,
            space,
        } = assembly.expect("same original assembly remains retained through preparation");
        let pending = OriginalLocalPendingResources {
            original: OriginalReadPendingResources {
                directories,
                readers,
                data_locks,
                writers: None,
                identity: root_identity,
                identity_failure: None,
                already_closed: Vec::new(),
                context: (
                    archive_digest,
                    read_lease_hold,
                    space,
                    device,
                    limits,
                    error.to_string(),
                ),
            },
            data_chain,
            worktree_chain,
            chain_failure,
            writer_failure,
            data_writer,
            worktree_writer,
            native_prefix,
        };
        fail_original_scoped_resources(
            error,
            Some(OriginalNodeJournalToClose::Read(journal)),
            Some(cas),
            Some(OriginalNodeCasReadersToClose::Read(original_cas_readers)),
            pending,
        )
    }

    fn prepare(&mut self, archive: &VerifiedNodeStateArchive, limits: LocalLimits) -> Result<()> {
        let original = self
            .assembly
            .as_mut()
            .expect("same original assembly retained");
        original.verify()?;
        limits.validate()?;
        original
            .journal
            .set_max_storage_entries(limits.max_storage_entries)?;
        let current =
            original
                .journal
                .current(archive.space())?
                .ok_or(ReconcileError::Invariant(
                    "actual original current manifest absent beforeLocalSpace",
                ))?;
        if current.entries.len() > limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit(
                "actual restored LocalSpace entry bound",
            ));
        }
        if original.archive_digest != *archive.digest() || original.space != *archive.space() {
            return Err(ReconcileError::Invariant(
                "originalLocalSpace actual archive scope",
            ));
        }
        let inspection = sync_extend_journal::NodeInspectionBounds {
            max_entries: limits.max_storage_entries,
            capacity: sync_extend_journal::JournalCapacityLimits {
                inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                    max_rows: limits.max_storage_entries,
                    max_logical_bytes: limits.max_storage_entries as u64 * 1024,
                },
                max_rows: limits.max_storage_entries as u64,
                max_logical_bytes: limits.max_storage_entries as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let mapped = archive.map_original_restore_journal(
            &original.directories.roots.worktree_path,
            inspection,
            256 * 1024 * 1024,
            original.read_lease_hold.as_ref(),
        )?;
        original
            .journal
            .verify_original_image_rows(&mapped, archive.space(), inspection)?;
        original.directories.marker.enable_original_readers()?;
        let roots = original.directories.roots;
        let data = &roots.data_path;
        let worktree = &roots.worktree_path;
        self.device = Some(identity::load_or_create(
            &data.join("device.secret"),
            false,
        )?);
        if self.device.as_ref() != Some(archive.device())
            || original.journal.state("space_id")?.as_deref() != Some(archive.space().as_str())
            || original.journal.state("device_id")?.as_deref() != Some(archive.device().as_str())
            || original.journal.state("worktree")?.as_deref() != worktree.to_str()
        {
            return Err(ReconcileError::Invariant(
                "originalLocalSpace device/worktree states differ",
            ));
        }
        self.root_identity = Some(filesystem::PathIdentity::capture_original_into_attempt(
            worktree,
            &mut self.native_prefix,
        )?);
        self.data_chain = match roots.original_writer_chain_retaining(false) {
            Ok(chain) => {
                self.native_prefix.append_result(Ok(chain.actual_closed));
                chain.retained
            }
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.chain_failure = Some(original);
                return Err(error);
            }
        };
        match WriterOwner::from_original_creation_retaining(
            data,
            original.data_locks.writer.original_creation()?,
            std::mem::take(&mut self.data_chain),
        ) {
            Ok(writer) => self.data_writer = Some(writer),
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.writer_failure = Some(original);
                return Err(error);
            }
        }
        self.worktree_chain = match roots.original_writer_chain_retaining(true) {
            Ok(chain) => {
                self.native_prefix.append_result(Ok(chain.actual_closed));
                chain.retained
            }
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.chain_failure = Some(original);
                return Err(error);
            }
        };
        let marker = worktree.join(".sync-extend");
        self.worktree_chain.push(
            original
                .directories
                .marker
                .directory
                .original_creation()?
                .retain_writer_directory_into_attempt(&marker, &mut self.native_prefix)?,
        );
        match WriterOwner::from_original_creation_retaining(
            &marker,
            original
                .directories
                .marker
                .writer_lock
                .original_creation()?,
            std::mem::take(&mut self.worktree_chain),
        ) {
            Ok(writer) => self.worktree_writer = Some(writer),
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.writer_failure = Some(original);
                return Err(error);
            }
        }
        Ok(())
    }
}

pub(super) fn prepare_original_local<'scope>(
    assembly: OriginalNodeReadAssembly<'scope>,
    archive: &VerifiedNodeStateArchive,
    limits: LocalLimits,
) -> std::result::Result<
    OriginalRestoredLocalSpace<'scope>,
    OriginalNodeScopedResourceCloseFailure<'scope>,
> {
    let mut original = OriginalLocalPreparation {
        assembly: Some(assembly),
        data_chain: Vec::new(),
        worktree_chain: Vec::new(),
        chain_failure: None,
        writer_failure: None,
        data_writer: None,
        worktree_writer: None,
        root_identity: None,
        device: None,
        native_prefix: WindowsOriginalCloseAttempt::new(),
    };
    if let Err(error) = original.prepare(archive, limits.clone()) {
        return Err(original.fail(error, limits));
    }
    let prefix = match std::mem::take(&mut original.native_prefix).finish() {
        Ok(closed) => closed,
        Err(failed) => {
            // All original preparation objects remain held until this actual
            // refused observer prefix has ended.
            let error = ReconcileError::Io(std::io::Error::other(failed.error.to_string()));
            original.native_prefix.append_failure(failed);
            return Err(original.fail(error, limits));
        }
    };
    let OriginalNodeReadAssembly {
        directories,
        data_locks,
        readers,
        journal,
        cas,
        original_cas_readers,
        archive_digest,
        read_lease_hold: _,
        space: _,
    } = original
        .assembly
        .take()
        .expect("prepared same original assembly");
    let local = LocalSpace {
        space_id: archive.space().clone(),
        device_id: original.device.take().expect("prepared original device"),
        worktree: directories.roots.worktree_path.clone(),
        data_dir: directories.roots.data_path.clone(),
        cas,
        journal,
        limits,
        root_identity: original
            .root_identity
            .take()
            .expect("prepared same original identity handle"),
        _lock: original
            .data_writer
            .take()
            .expect("prepared same original data writer"),
        _worktree_lock: original
            .worktree_writer
            .take()
            .expect("prepared same original worktree writer"),
    };
    let result = OriginalRestoredLocalSpace {
        local,
        directories,
        readers,
        data_locks,
        archive_digest,
        original_cas_readers,
        original_observer_closed: prefix,
    };
    if let Err(error) = result.verify() {
        return Err(result.close_failed_original_resources_retaining(error));
    }
    crate::fault::checkpoint("node_actual_local_space_verified");
    Ok(result)
}
