//! Retain every actual original prefix while constructing the readonly node.
use super::{
    assembly::{ReadContent, ReadContents},
    files::CreatedFile,
    original_content::OriginalContent,
    scoped_close::{
        fail_original_scoped_resources, OriginalNodeCasReadersToClose, OriginalNodeJournalToClose,
        OriginalNodePendingResourceClose,
    },
    CreatedNodeDataLocks, CreatedNodeFileSet, NodeTargetRoot, OriginalNodeReadAssembly,
    OriginalNodeResourceCloseAttempt, OriginalNodeResourceCloseFailure,
    OriginalNodeScopedResourceCloseFailure,
};
use crate::{LocalSpace, ReconcileError, Result};
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, FileKey, OriginalFileSealFailure, OriginalSqliteMainHandoff,
    OriginalSqliteMainHandoffFailure, OwnedFileCreation, ReleasedOriginalCoordinationFile,
    ReleasedOriginalFileIdentity,
};

struct OriginalFileContext {
    slot: (NodeTargetRoot, Vec<String>),
    path: std::path::PathBuf,
    key: FileKey,
    parent: FileKey,
    bytes: u64,
    digest: ContentId,
}

#[derive(Default)]
struct OriginalContentPreparation {
    context: Option<OriginalFileContext>,
    creator: Option<OwnedFileCreation>,
    identity: Option<ReleasedOriginalFileIdentity>,
    seal_failure: Option<OriginalFileSealFailure>,
    original: Option<OriginalContent>,
}

impl OriginalContentPreparation {
    fn begin(&mut self, slot: (NodeTargetRoot, Vec<String>), file: CreatedFile) {
        let CreatedFile {
            creator,
            path,
            key,
            parent,
            bytes,
            digest,
        } = file;
        self.context = Some(OriginalFileContext {
            slot,
            path,
            key,
            parent,
            bytes,
            digest,
        });
        self.creator = Some(creator);
    }

    fn close_into_attempt<'scope>(self, attempt: &mut OriginalNodeResourceCloseAttempt<'scope>) {
        let Self {
            context,
            creator,
            identity,
            seal_failure,
            original,
        } = self;
        attempt.keep_context(context);
        if let Some(original) = original {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = seal_failure {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = identity {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = creator {
            original.close_into_attempt(&mut attempt.native);
        }
    }

    fn finish_read(&mut self) -> Result<((NodeTargetRoot, Vec<String>), ReadContent)> {
        let context = self.context.as_ref().ok_or(ReconcileError::Invariant(
            "original content preparation context absent",
        ))?;
        let creator = self.creator.take().ok_or(ReconcileError::Invariant(
            "original content preparation creator absent",
        ))?;
        if context.slot.0 == NodeTargetRoot::Worktree {
            match creator.seal_original_retaining() {
                Ok(original) => self.original = Some(OriginalContent::Sealed(original)),
                Err(original) => {
                    let error =
                        ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                    self.seal_failure = Some(original);
                    return Err(error);
                }
            }
        } else {
            match creator.release_for_identity_checked_reopen() {
                Ok(original) => self.identity = Some(original),
                Err((original, error)) => {
                    self.creator = Some(*original);
                    return Err(error.into());
                }
            }
            let identity = self
                .identity
                .take()
                .expect("same released identity retained");
            match identity.retain_read_after_creation() {
                Ok(original) => self.original = Some(OriginalContent::Read(original)),
                Err((original, error)) => {
                    self.identity = Some(original);
                    return Err(error.into());
                }
            }
        }
        let original = self
            .original
            .as_ref()
            .expect("same protected content retained");
        super::read_content::verify(original, context.bytes, &context.digest)?;
        if !original.matches_path(&context.path)? {
            return Err(ReconcileError::Invariant(
                "original content read handoff slot differs",
            ));
        }
        let context = self
            .context
            .take()
            .expect("verified original content context");
        let OriginalFileContext {
            slot,
            path,
            key,
            parent,
            bytes,
            digest,
        } = context;
        // Keys/path are still checked by the same protected object and slot.
        let _ = (path, key, parent);
        Ok((
            slot,
            ReadContent {
                original: self
                    .original
                    .take()
                    .expect("verified same protected content"),
                bytes,
                digest,
            },
        ))
    }
}

struct OriginalAssemblyPendingResources<'scope> {
    files: Option<CreatedNodeFileSet<'scope>>,
    data_locks: Option<CreatedNodeDataLocks<'scope>>,
    current: OriginalContentPreparation,
    main: Option<OriginalSqliteMainHandoff>,
    main_failure: Option<OriginalSqliteMainHandoffFailure>,
    sentinel: Option<ReleasedOriginalCoordinationFile>,
    readers: ReadContents,
    first_error: Option<String>,
}

impl<'scope> OriginalNodePendingResourceClose<'scope> for OriginalAssemblyPendingResources<'scope> {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalNodeResourceCloseFailure<'scope>>
    {
        let Self {
            files,
            data_locks,
            current,
            main,
            main_failure,
            sentinel,
            readers,
            first_error,
        } = *self;
        let mut attempt = OriginalNodeResourceCloseAttempt::new();
        if let Some(error) = first_error {
            attempt
                .native
                .note_error(std::io::Error::other(error.clone()));
            attempt.keep_context(error);
        }
        current.close_into_attempt(&mut attempt);
        if let Some(original) = main_failure {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = main {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = sentinel {
            original.close_into_attempt(&mut attempt.native);
        }
        for (slot, file) in readers {
            let ReadContent {
                original,
                bytes,
                digest,
            } = file;
            attempt.keep_context((slot, bytes, digest));
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = files {
            original.close_into_attempt(&mut attempt);
        }
        if let Some(original) = data_locks {
            original.close_into_attempt(&mut attempt);
        }
        attempt.finish()
    }
}

struct OriginalAssemblyPreparation<'scope> {
    pending: OriginalAssemblyPendingResources<'scope>,
    journal: Option<OriginalNodeJournalToClose>,
    cas: Option<sync_extend_cas::Cas>,
    cas_readers: Option<OriginalNodeCasReadersToClose>,
}

impl<'scope> OriginalAssemblyPreparation<'scope> {
    fn fail(mut self, error: ReconcileError) -> OriginalNodeScopedResourceCloseFailure<'scope> {
        self.pending.first_error = Some(error.to_string());
        let Self {
            pending,
            journal,
            cas,
            cas_readers,
        } = self;
        fail_original_scoped_resources(error, journal, cas, cas_readers, pending)
    }

    fn prepare(&mut self, maximum: usize) -> Result<SpaceId> {
        let files = self.pending.files.as_mut().expect("same file set retained");
        files.verify_inventory_with_data_locks(
            self.pending
                .data_locks
                .as_ref()
                .expect("same data locks retained"),
        )?;
        let journal_slot = (NodeTargetRoot::Data, vec!["journal.sqlite".to_owned()]);
        let file = files
            .files
            .remove(&journal_slot)
            .ok_or(ReconcileError::Invariant(
                "original created Journal slot absent",
            ))?;
        self.pending.current.begin(journal_slot, file);
        let path = self
            .pending
            .current
            .context
            .as_ref()
            .expect("same main context")
            .path
            .clone();
        let creator = self
            .pending
            .current
            .creator
            .take()
            .expect("same main creator");
        match creator.handoff_original_sqlite_main(&path) {
            Ok(original) => self.pending.main = Some(original),
            Err(original) => {
                let error = match &original {
                    OriginalSqliteMainHandoffFailure::Creator { error, .. }
                    | OriginalSqliteMainHandoffFailure::Released { error, .. }
                    | OriginalSqliteMainHandoffFailure::Terminating { error, .. } => {
                        ReconcileError::Io(std::io::Error::other(error.to_string()))
                    }
                };
                self.pending.main_failure = Some(original);
                return Err(error);
            }
        }
        crate::fault::checkpoint("node_assembly_journal_released");
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            match std::fs::symlink_metadata(std::path::Path::new(&sidecar)) {
                Ok(_) => {
                    return Err(ReconcileError::Invariant(
                        "original Journal sidecar occupied beforeSQLiteopen",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let inspection = sync_extend_journal::NodeInspectionBounds {
            max_entries: maximum,
            capacity: sync_extend_journal::JournalCapacityLimits {
                inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                    max_rows: maximum,
                    max_logical_bytes: maximum as u64 * 1024,
                },
                max_rows: maximum as u64,
                max_logical_bytes: maximum as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let main = self
            .pending
            .main
            .take()
            .expect("same original main handoff retained");
        let journal = match sync_extend_journal::Journal::reopen_original_handoff_readonly(
            main, inspection,
        ) {
            Ok(journal) => journal,
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.journal = Some(OriginalNodeJournalToClose::ReadOpenFailure(original));
                return Err(error);
            }
        };
        // Install the actual owner before the next fallible operation.
        self.journal = Some(OriginalNodeJournalToClose::Read(journal));
        let Some(OriginalNodeJournalToClose::Read(journal)) = self.journal.as_mut() else {
            return Err(ReconcileError::Invariant(
                "same original readonly owner absent",
            ));
        };
        journal.verify_original_created_image()?;
        crate::fault::checkpoint("node_assembly_journal_opened");
        self.pending.sentinel = Some(
            self.pending
                .data_locks
                .as_mut()
                .expect("same data locks")
                .release_cas()?,
        );
        let sentinel = self
            .pending
            .sentinel
            .take()
            .expect("same original CAS sentinel");
        if let Err((sentinel, error)) = journal.bind_original_cas_coordination(sentinel) {
            self.pending.sentinel = Some(*sentinel);
            return Err(error.into());
        }
        crate::fault::checkpoint("node_assembly_original_cas_bound");
        while let Some((slot, file)) = self
            .pending
            .files
            .as_mut()
            .expect("same files")
            .files
            .pop_first()
        {
            self.pending.current.begin(slot, file);
            let (slot, file) = self.pending.current.finish_read()?;
            self.pending.readers.insert(slot, file);
            crate::fault::checkpoint("node_assembly_file_read_verified");
        }
        let space: SpaceId = journal
            .state("space_id")?
            .ok_or(ReconcileError::Invariant("original space absent"))?
            .parse()?;
        let data = &self
            .pending
            .files
            .as_ref()
            .expect("same file context")
            .directories
            .roots
            .data_path;
        match LocalSpace::existing_original_managed_cas_retaining(data, journal) {
            Ok((cas, original)) => {
                self.cas = Some(cas);
                self.cas_readers = Some(OriginalNodeCasReadersToClose::Read(original));
            }
            Err(original) => {
                let error = ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                self.cas_readers =
                    Some(OriginalNodeCasReadersToClose::PreparationFailure(original));
                return Err(error);
            }
        }
        Ok(space)
    }
}

pub(super) fn assemble_original_files<'scope>(
    files: CreatedNodeFileSet<'scope>,
    maximum: usize,
    data_locks: CreatedNodeDataLocks<'scope>,
) -> std::result::Result<
    OriginalNodeReadAssembly<'scope>,
    OriginalNodeScopedResourceCloseFailure<'scope>,
> {
    let mut original = OriginalAssemblyPreparation {
        pending: OriginalAssemblyPendingResources {
            files: Some(files),
            data_locks: Some(data_locks),
            current: OriginalContentPreparation::default(),
            main: None,
            main_failure: None,
            sentinel: None,
            readers: BTreeMap::new(),
            first_error: None,
        },
        journal: None,
        cas: None,
        cas_readers: None,
    };
    let space = match original.prepare(maximum) {
        Ok(space) => space,
        Err(error) => return Err(original.fail(error)),
    };
    if original
        .pending
        .files
        .as_ref()
        .is_none_or(|files| !files.files.is_empty())
        || original.pending.current.creator.is_some()
        || original.pending.current.identity.is_some()
        || original.pending.current.seal_failure.is_some()
        || original.pending.current.original.is_some()
        || original.pending.main.is_some()
        || original.pending.main_failure.is_some()
        || original.pending.sentinel.is_some()
        || original.pending.data_locks.is_none()
        || original.cas.is_none()
    {
        return Err(original.fail(ReconcileError::Invariant(
            "prepared original assembly has an incomplete native prefix",
        )));
    }
    let journal = match original.journal.take() {
        Some(OriginalNodeJournalToClose::Read(journal)) => journal,
        other => {
            original.journal = other;
            return Err(original.fail(ReconcileError::Invariant(
                "prepared same readonly Journal absent",
            )));
        }
    };
    let original_cas_readers = match original.cas_readers.take() {
        Some(OriginalNodeCasReadersToClose::Read(readers)) => readers,
        other => {
            original.journal = Some(OriginalNodeJournalToClose::Read(journal));
            original.cas_readers = other;
            return Err(original.fail(ReconcileError::Invariant(
                "prepared same CAS readers absent",
            )));
        }
    };
    let files = original
        .pending
        .files
        .take()
        .expect("prepared same empty file set");
    let result = OriginalNodeReadAssembly {
        directories: files.directories,
        data_locks: original
            .pending
            .data_locks
            .take()
            .expect("prepared same data locks"),
        readers: std::mem::take(&mut original.pending.readers),
        journal,
        cas: original
            .cas
            .take()
            .expect("prepared same CAS callback owner"),
        original_cas_readers,
        archive_digest: files.archive_digest.clone(),
        read_lease_hold: files.read_lease_hold.clone(),
        space,
    };
    // Checked empty source/partial slots contain inert context only; every
    // actual creator moved into the Journal, readers, or data-lock owners.
    drop(files);
    if let Err(error) = result.verify() {
        return Err(result.close_failed_original_resources_retaining(error));
    }
    crate::fault::checkpoint("node_assembly_full_read_verified");
    Ok(result)
}
