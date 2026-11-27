//! Actual Unix restoration retains every created prefix and the sole Journal.
use super::plan::{PreparedUnixNodeRestore, Slot};
use crate::{ReconcileError, Result};
use std::collections::BTreeMap;
use sync_extend_journal::{OriginalUnixRestoredJournal, OriginalUnixRestoredJournalFailure};
use sync_extend_platform_fs::{
    AcquiredUnixChildDirectory, AcquiredUnixChildDirectoryFailure, ClosedUnixOriginalResources,
    FreshUnixNativeFile, FreshUnixNativeFileFailure, FreshUnixNativeSqliteIo,
    FreshUnixNativeSqliteIoFailure, OriginalUnixCasSentinel, OriginalUnixNamespace,
    OriginalUnixNativeRoot, OriginalUnixWriterLock, SealedUnixNativeFile,
    UnixNativeFileSealFailure, UnixOriginalCloseAttempt, UnixOriginalResourceCloseFailure,
};

pub struct OriginalUnixRestoredNode<'archive, 'namespace> {
    plan: PreparedUnixNodeRestore<'archive>,
    data: Option<OriginalUnixNativeRoot<'namespace>>,
    worktree: Option<OriginalUnixNativeRoot<'namespace>>,
    directories: BTreeMap<Slot, AcquiredUnixChildDirectory<'namespace>>,
    files: BTreeMap<Slot, SealedUnixNativeFile<'namespace>>,
    pending: Vec<FreshUnixNativeFile<'namespace>>,
    locks: Vec<OriginalUnixWriterLock<'namespace>>,
    cas: Option<OriginalUnixCasSentinel<'namespace>>,
    journal: Option<OriginalUnixRestoredJournal<'namespace>>,
    journal_failures: Vec<OriginalUnixRestoredJournalFailure<'namespace>>,
    io_failures: Vec<FreshUnixNativeSqliteIoFailure<'namespace>>,
    file_failures: Vec<FreshUnixNativeFileFailure<'namespace>>,
    directory_failures: Vec<AcquiredUnixChildDirectoryFailure<'namespace>>,
    seal_failures: Vec<UnixNativeFileSealFailure<'namespace>>,
    intent: Option<SealedUnixNativeFile<'namespace>>,
    intent_bytes: Vec<u8>,
    completed: bool,
}

pub struct OriginalUnixRestoreFailure<'archive, 'namespace> {
    pub error: ReconcileError,
    original: Option<OriginalUnixRestoredNode<'archive, 'namespace>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for OriginalUnixRestoreFailure<'_, '_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalUnixRestoreFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .field("original_close_uncertain", &self.original_close.is_some())
            .finish()
    }
}

pub struct ClosedOriginalUnixRestore {
    resources: ClosedUnixOriginalResources,
    archive_digest: sync_extend_core_model::ContentId,
}
impl ClosedOriginalUnixRestore {
    pub fn actual_closed_descriptors(&self) -> usize {
        self.resources.actual_closed_descriptors()
    }
    pub fn archive_digest(&self) -> &sync_extend_core_model::ContentId {
        &self.archive_digest
    }
}

impl OriginalUnixRestoreFailure<'_, '_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self.original_close.as_ref().is_some_and(|failure| {
                failure.retained_parent_scopes() != 0
            })
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(mut original) = self.original.take() {
            let mut close = UnixOriginalCloseAttempt::new();
            if let Some(previous) = self.original_close.take() {
                close.append_result(Err(previous));
            }
            original.close_resources(&mut close);
            self.original_close = close.finish().err();
            if original
                .journal_failures
                .iter()
                .any(OriginalUnixRestoredJournalFailure::has_retained_originals)
                || original
                    .io_failures
                    .iter()
                    .any(FreshUnixNativeSqliteIoFailure::has_retained_originals)
            {
                self.original = Some(original);
            }
        }
        if let Some(original) = self.original_close.take() {
            self.original_close = Some(original.close_remaining());
        }
        self
    }
}
impl Drop for OriginalUnixRestoreFailure<'_, '_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
        if let Some(original) = self.original_close.take() {
            original.retain_until_process_exit();
        }
    }
}

fn io_error(error: &impl std::fmt::Display) -> ReconcileError {
    ReconcileError::Io(std::io::Error::other(error.to_string()))
}

impl<'archive> PreparedUnixNodeRestore<'archive> {
    pub fn restore_originals<'namespace>(
        self,
        namespace: &'namespace OriginalUnixNamespace,
    ) -> std::result::Result<
        OriginalUnixRestoredNode<'archive, 'namespace>,
        OriginalUnixRestoreFailure<'archive, 'namespace>,
    > {
        let intent_bytes = serde_json::to_vec(
            &serde_json::json!({"format":1,"platform":"unix_acquired_directory",
            "archive_digest":self.archive.digest(),"mapped_journal":self.mapped.digest(),"data":self.data,
            "worktree":self.worktree,"planned_files":self.files.len(),"planned_directories":self.directories.len(),
            "prepared_native_projection":self.native_projection,
            "state":"original_acquisition_intent","restart_authority":false}),
        );
        let mut original = OriginalUnixRestoredNode {
            plan: self,
            data: None,
            worktree: None,
            directories: BTreeMap::new(),
            files: BTreeMap::new(),
            pending: Vec::new(),
            locks: Vec::new(),
            cas: None,
            journal: None,
            journal_failures: Vec::new(),
            io_failures: Vec::new(),
            file_failures: Vec::new(),
            directory_failures: Vec::new(),
            seal_failures: Vec::new(),
            intent: None,
            intent_bytes: Vec::new(),
            completed: false,
        };
        let restored = (|| -> Result<()> {
            original.intent_bytes = intent_bytes?;
            if original.intent_bytes.len() > 65_536 {
                return Err(ReconcileError::ResourceLimit(
                    "original Unix restore intent bytes",
                ));
            }
            namespace.verify_current()?;
            original.data = Some(OriginalUnixNativeRoot::acquire_private(
                namespace,
                &original.plan.data,
            )?);
            original.worktree = Some(OriginalUnixNativeRoot::acquire_private(
                namespace,
                &original.plan.worktree,
            )?);
            let data = original.data.as_ref().expect("acquired original data");
            let worktree = original
                .worktree
                .as_ref()
                .expect("acquired original worktree");
            data.require_empty()?;
            worktree.require_empty()?;
            if data.key()? == worktree.key()? {
                return Err(ReconcileError::Invariant(
                    "Unix target roots alias one actual directory",
                ));
            }
            match data.create_writer_lock() {
                Ok(lock) => original.locks.push(lock),
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.file_failures.push(failure);
                    return Err(error);
                }
            }
            let intent_slot = Slot::new(true, &["unix-restore.intent"]);
            let file = original.create_file(&intent_slot, 65_536)?;
            original.pending.push(file);
            original
                .pending
                .last_mut()
                .expect("actual intent creator")
                .write_ordered_and_sync(&[&original.intent_bytes])?;
            let file = original.pending.pop().expect("actual intent creator");
            match file.seal_projected_metadata(&[&original.intent_bytes], None) {
                Ok(file) => original.intent = Some(file),
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.seal_failures.push(failure);
                    return Err(error);
                }
            }
            for slot in original.plan.directories.clone() {
                original.acquire_directory(slot)?;
            }
            let marker = original
                .directories
                .get(&Slot::new(false, &[".sync-extend"]))
                .expect("acquired marker directory");
            match marker.create_writer_lock() {
                Ok(lock) => original.locks.push(lock),
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.file_failures.push(failure);
                    return Err(error);
                }
            }
            let slots: Vec<_> = original.plan.files.keys().cloned().collect();
            for slot in slots {
                let maximum = original.plan.files[&slot].bytes.max(1);
                let file = original.create_file(&slot, maximum)?;
                original.pending.push(file);
                let planned = &original.plan.files[&slot];
                let chunks = original.plan.chunks(planned)?;
                original
                    .pending
                    .last_mut()
                    .expect("original file creator")
                    .write_ordered_and_sync(&chunks)?;
                let metadata = planned
                    .projected
                    .as_ref()
                    .map(crate::filesystem::platform_metadata_for_apply)
                    .transpose()?;
                let file = original.pending.pop().expect("original file creator");
                let sealed = match file.seal_projected_metadata(&chunks, metadata.as_ref()) {
                    Ok(file) => file,
                    Err(failure) => {
                        let error = io_error(&failure.error);
                        original.seal_failures.push(failure);
                        return Err(error);
                    }
                };
                original.files.insert(slot, sealed);
            }
            for name in [
                "journal.sqlite",
                "journal.sqlite-wal",
                "journal.sqlite-journal",
                "journal.sqlite-shm",
            ] {
                let maximum = if name == "journal.sqlite" {
                    original.plan.bounds.maximum_journal_bytes as u64
                } else {
                    original.plan.bounds.journal_sidecar_bytes
                };
                let file = original.create_file(&Slot::new(true, &[name]), maximum)?;
                original.pending.push(file);
            }
            original.pending[0].write_ordered_and_sync(&[original.plan.mapped.bytes()])?;
            match original
                .data
                .as_ref()
                .expect("actual data")
                .create_cas_sentinel()
            {
                Ok(cas) => original.cas = Some(cas),
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.file_failures.push(failure);
                    return Err(error);
                }
            }
            let files: [FreshUnixNativeFile<'namespace>; 4] = std::mem::take(&mut original.pending)
                .try_into()
                .ok()
                .expect("exact planned four original SQLite creators");
            let io = match FreshUnixNativeSqliteIo::acquire(
                files,
                original.cas.take().expect("actual CAS sentinel"),
            ) {
                Ok(io) => io,
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.io_failures.push(failure);
                    return Err(error);
                }
            };
            match OriginalUnixRestoredJournal::open_original(
                io,
                &original.plan.mapped,
                original.plan.archive.space(),
                original.plan.inspection,
            ) {
                Ok(journal) => original.journal = Some(journal),
                Err(failure) => {
                    let error = io_error(&failure.error);
                    original.journal_failures.push(failure);
                    return Err(error);
                }
            }
            crate::fault::checkpoint("unix_restore_original_journal_opened");
            original.verify()?;
            original.completed = true;
            Ok(())
        })();
        match restored {
            Ok(()) => Ok(original),
            Err(error) => Err(OriginalUnixRestoreFailure {
                error,
                original: Some(original),
                original_close: None,
            }),
        }
    }
}

impl<'archive, 'namespace> OriginalUnixRestoredNode<'archive, 'namespace> {
    fn create_file(
        &mut self,
        slot: &Slot,
        maximum: u64,
    ) -> Result<FreshUnixNativeFile<'namespace>> {
        let parent = slot.parent();
        let created = if parent.parts.is_empty() {
            let root = if slot.data {
                self.data.as_ref()
            } else {
                self.worktree.as_ref()
            }
            .expect("original root");
            root.create_file(slot.name(), maximum)
        } else {
            self.directories
                .get(&parent)
                .expect("planned acquired parent")
                .create_file(slot.name(), maximum)
        };
        created.map_err(|failure| {
            let error = io_error(&failure.error);
            self.file_failures.push(failure);
            error
        })
    }
    fn acquire_directory(&mut self, slot: Slot) -> Result<()> {
        let parent = slot.parent();
        let acquired = if parent.parts.is_empty() {
            let root = if slot.data {
                self.data.as_ref()
            } else {
                self.worktree.as_ref()
            }
            .expect("original root");
            root.acquire_new_child(slot.name())
        } else {
            self.directories
                .get(&parent)
                .expect("planned acquired parent")
                .acquire_new_child(slot.name())
        };
        match acquired {
            Ok(directory) => {
                self.directories.insert(slot, directory);
                Ok(())
            }
            Err(failure) => {
                let error = io_error(&failure.error);
                self.directory_failures.push(failure);
                Err(error)
            }
        }
    }
    pub fn verify(&mut self) -> Result<()> {
        self.data
            .as_ref()
            .ok_or(ReconcileError::Invariant("original Unix data closed"))?
            .verify()?;
        self.worktree
            .as_ref()
            .ok_or(ReconcileError::Invariant("original Unix worktree closed"))?
            .verify()?;
        for lock in &self.locks {
            lock.verify()?;
        }
        if self.directories.len() != self.plan.directories.len()
            || self.files.len() != self.plan.files.len()
        {
            return Err(ReconcileError::Invariant(
                "complete original Unix object membership differs",
            ));
        }
        for directory in self.directories.values() {
            directory.verify()?;
        }
        for (slot, file) in &self.files {
            let planned = &self.plan.files[slot];
            let chunks = self.plan.chunks(planned)?;
            file.verify_ordered_bytes(&chunks)?;
            if file.bytes()? != planned.bytes {
                return Err(ReconcileError::Invariant(
                    "sealed original Unix file bytes differ",
                ));
            }
            let mut hash = blake3::Hasher::new();
            for chunk in chunks {
                hash.update(chunk);
            }
            if sync_extend_core_model::ContentId::from_hasher(&hash) != planned.digest {
                return Err(ReconcileError::Invariant(
                    "sealed original Unix ordered digest differs",
                ));
            }
            if let Some(expected) = &planned.projected {
                let observed = crate::filesystem::portable_metadata_from_capture(file.metadata()?)?;
                if !expected.matches_observed(&observed) {
                    return Err(ReconcileError::Unstable);
                }
            }
        }
        self.intent
            .as_ref()
            .ok_or(ReconcileError::Invariant("original Unix intent absent"))?
            .verify_ordered_bytes(&[&self.intent_bytes])?;
        self.journal
            .as_mut()
            .ok_or(ReconcileError::Invariant("original Unix Journal absent"))?
            .verify()?;
        Ok(())
    }
    fn close_resources(&mut self, close: &mut UnixOriginalCloseAttempt) {
        if let Some(journal) = self.journal.take() {
            match journal.close_retaining() {
                Ok(closed) => close.append_result(Ok(closed)),
                Err(failure) => {
                    close.note_error(std::io::Error::other(failure.error.to_string()));
                    self.journal_failures.push(failure);
                }
            }
        }
        self.journal_failures = std::mem::take(&mut self.journal_failures)
            .into_iter()
            .map(|failure| failure.close_remaining())
            .collect();
        self.io_failures = std::mem::take(&mut self.io_failures)
            .into_iter()
            .map(|failure| failure.close_remaining())
            .collect();
        for failure in &self.journal_failures {
            close.note_error(std::io::Error::other(failure.error.to_string()));
        }
        for failure in &self.io_failures {
            close.note_error(std::io::Error::other(failure.error.to_string()));
        }
        if self
            .journal_failures
            .iter()
            .any(OriginalUnixRestoredJournalFailure::has_retained_originals)
            || self
                .io_failures
                .iter()
                .any(FreshUnixNativeSqliteIoFailure::has_retained_originals)
        {
            // Live original SQLite work keeps every writer/CAS lock and the
            // complete native prefix until that same connection/IO ends.
            return;
        }
        for (_, file) in std::mem::take(&mut self.files) {
            close.append_result(file.close_retaining());
        }
        for file in std::mem::take(&mut self.pending) {
            close.append_result(file.close_retaining());
        }
        for mut failure in std::mem::take(&mut self.seal_failures) {
            if let Some(file) = failure.original.take() {
                close.append_result(file.close_retaining());
            }
        }
        for mut failure in std::mem::take(&mut self.file_failures) {
            if let Some(file) = failure.original.take() {
                close.append_result(file.close_retaining());
            }
            if let Some(file) = failure.failed_create.take() {
                close.append_result(file.close_retaining());
            }
        }
        if let Some(file) = self.intent.take() {
            close.append_result(file.close_retaining());
        }
        for lock in std::mem::take(&mut self.locks) {
            close.append_result(lock.close_retaining());
        }
        if let Some(cas) = self.cas.take() {
            close.append_result(cas.close_retaining());
        }
        for mut failure in std::mem::take(&mut self.directory_failures) {
            if let Some(directory) = failure.acquired.take() {
                close.append_result(directory.close_retaining());
            }
            if let Some(failure) = failure.original_close.take() {
                close.append_result(Err(failure));
            }
        }
        for (_, directory) in std::mem::take(&mut self.directories).into_iter().rev() {
            close.append_result(directory.close_retaining());
        }
        if let Some(root) = self.worktree.take() {
            close.append_result(root.close_retaining());
        }
        if let Some(root) = self.data.take() {
            close.append_result(root.close_retaining());
        }
    }
    pub fn close_retaining(
        mut self,
    ) -> std::result::Result<
        ClosedOriginalUnixRestore,
        OriginalUnixRestoreFailure<'archive, 'namespace>,
    > {
        let first = if self.completed {
            self.verify().err()
        } else {
            Some(ReconcileError::Invariant(
                "original Unix restore incomplete",
            ))
        };
        let mut close = UnixOriginalCloseAttempt::new();
        self.close_resources(&mut close);
        match close.finish() {
            Ok(resources) if first.is_none() => Ok(ClosedOriginalUnixRestore {
                resources,
                archive_digest: self.plan.archive.digest().clone(),
            }),
            result => Err(OriginalUnixRestoreFailure {
                error: first.unwrap_or(ReconcileError::Invariant(
                    "actual Unix restore resource close failed",
                )),
                original: Some(self),
                original_close: result.err(),
            }),
        }
    }
}

impl Drop for OriginalUnixRestoredNode<'_, '_> {
    fn drop(&mut self) {
        // Unconsumed actual objects survive cancellation; destructors issue no
        // success receipt or pathname deletion, and no source is re-adopted.
        macro_rules! keep {
            ($field:ident) => {
                if let Some(value) = self.$field.take() {
                    let _ = Box::leak(Box::new(value));
                }
            };
        }
        keep!(journal);
        keep!(data);
        keep!(worktree);
        keep!(cas);
        keep!(intent);
        macro_rules! keep_all {
            ($field:ident) => {
                if !self.$field.is_empty() {
                    let _ = Box::leak(Box::new(std::mem::take(&mut self.$field)));
                }
            };
        }
        keep_all!(directories);
        keep_all!(files);
        keep_all!(pending);
        keep_all!(locks);
        keep_all!(journal_failures);
        keep_all!(io_failures);
        keep_all!(file_failures);
        keep_all!(directory_failures);
        keep_all!(seal_failures);
    }
}
