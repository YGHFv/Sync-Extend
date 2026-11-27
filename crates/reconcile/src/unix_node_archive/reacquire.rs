//! Reacquire every recorded original before opening the next bounded session.
use super::{
    completion_frames, generation_budget as budget, plan::Slot, UnixNodeRestoreBounds,
    VerifiedNodeStateArchive,
};
use crate::{ReconcileError, Result};
use std::{collections::BTreeMap, path::Path};
use sync_extend_core_model::{ContentId, Manifest};
use sync_extend_journal::{
    NodeInspectionBounds, OriginalUnixRestoredJournal, OriginalUnixRestoredJournalFailure,
};
use sync_extend_platform_fs::*;
mod close;
mod lineage;
mod polling;
mod writes;
pub use close::ClosedReacquiredUnixGeneration;

pub struct ReacquiredOriginalUnixNode<'archive, 'namespace> {
    archive: &'archive VerifiedNodeStateArchive,
    record: budget::Record,
    record_digest: ContentId,
    manifest: Manifest,
    bounds: UnixNodeRestoreBounds,
    inspection: NodeInspectionBounds,
    data: Option<OriginalUnixNativeRoot<'namespace>>,
    worktree: Option<OriginalUnixNativeRoot<'namespace>>,
    directories: BTreeMap<Slot, AcquiredUnixChildDirectory<'namespace>>,
    observed: BTreeMap<Slot, ObservedUnixNativeFile<'namespace>>,
    record_file: Option<ObservedUnixNativeFile<'namespace>>,
    locks: Vec<ReacquiredUnixSqliteLock<'namespace>>,
    pending: Vec<ReacquiredUnixSqliteFile<'namespace>>,
    journal: Option<OriginalUnixRestoredJournal<'namespace>>,
    journal_failures: Vec<OriginalUnixRestoredJournalFailure<'namespace>>,
    io_failures: Vec<FreshUnixNativeSqliteIoFailure<'namespace>>,
    close_failures: Vec<UnixOriginalResourceCloseFailure>,
    created: BTreeMap<Slot, SealedUnixNativeFile<'namespace>>,
    creations: Vec<FreshUnixNativeFile<'namespace>>,
    create_failures: Vec<FreshUnixNativeFileFailure<'namespace>>,
    directory_failures: Vec<AcquiredUnixChildDirectoryFailure<'namespace>>,
    frame: Option<OriginalUnixCloseFrames<'namespace>>,
    poisoned: bool,
}
pub struct UnixGenerationReacquireFailure<'archive, 'namespace> {
    pub error: ReconcileError,
    original: Option<ReacquiredOriginalUnixNode<'archive, 'namespace>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}
impl std::fmt::Debug for UnixGenerationReacquireFailure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixGenerationReacquireFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .finish()
    }
}
impl UnixGenerationReacquireFailure<'_, '_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self
                .original_close
                .as_ref()
                .is_some_and(|f| f.retained_parent_scopes() != 0)
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(mut node) = self.original.take() {
            let mut close = UnixOriginalCloseAttempt::new();
            if let Some(old) = self.original_close.take() {
                close.append_result(Err(old));
            }
            node.close_resources(&mut close);
            self.original_close = close.finish().err();
            if node
                .journal_failures
                .iter()
                .any(OriginalUnixRestoredJournalFailure::has_retained_originals)
                || node
                    .io_failures
                    .iter()
                    .any(FreshUnixNativeSqliteIoFailure::has_retained_originals)
            {
                self.original = Some(node);
            }
        }
        if let Some(close) = self.original_close.take() {
            self.original_close = Some(close.close_remaining());
        }
        self
    }
}
impl Drop for UnixGenerationReacquireFailure<'_, '_> {
    fn drop(&mut self) {
        if let Some(node) = self.original.take() {
            let _ = Box::leak(Box::new(node));
        }
        if let Some(close) = self.original_close.take() {
            close.retain_until_process_exit();
        }
    }
}
fn io(error: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::Io(std::io::Error::other(error.to_string()))
}
fn slot(object: &budget::Object) -> Result<Slot> {
    let data = match object.role.as_str() {
        "data_directory" | "data_file" | "data_lock" | "restore_intent" | "local_intent"
        | "generation_record" => true,
        "work_directory" | "work_file" | "work_lock" => false,
        _ => {
            return Err(ReconcileError::Invariant(
                "known Unix generation member role",
            ))
        }
    };
    Ok(Slot {
        data,
        parts: object.path.split('/').map(str::to_owned).collect(),
    })
}
impl VerifiedNodeStateArchive {
    pub fn reacquire_unix_generation<'archive, 'namespace>(
        &'archive self,
        namespace: &'namespace OriginalUnixNamespace,
        data: &Path,
        worktree: &Path,
        generation: u32,
        expected_record: &ContentId,
        inspection: NodeInspectionBounds,
        bounds: UnixNodeRestoreBounds,
    ) -> std::result::Result<
        ReacquiredOriginalUnixNode<'archive, 'namespace>,
        UnixGenerationReacquireFailure<'archive, 'namespace>,
    > {
        // Parse only after anchoring and observing the original private record.
        let mut early_data = None;
        let mut early_record = None;
        let prepare = (|| -> Result<_> {
            bounds.validate()?;
            inspection.validate()?;
            if generation >= budget::MAX_GENERATIONS
                || data == worktree
                || data.starts_with(worktree)
                || worktree.starts_with(data)
            {
                return Err(ReconcileError::Invariant(
                    "independent bounded Unix generation roots",
                ));
            }
            early_data = Some(OriginalUnixNativeRoot::acquire_private(namespace, data)?);
            let data = early_data.as_ref().expect("retained early data root");
            early_record = Some(data.observe_file(
                &format!("unix-generation-{generation:04}.frames"),
                completion_frames::MAX_FRAME_BYTES,
                true,
            )?);
            let record_file = early_record.as_ref().expect("retained original record");
            (|| -> Result<_> {
                let bytes = record_file.read_bounded()?;
                if ContentId::hash(&bytes) != *expected_record {
                    return Err(ReconcileError::Invariant(
                        "exact original Unix generation digest",
                    ));
                }
                let record = budget::decode(&bytes)?;
                if record.archive != *self.digest()
                    || record.space != *self.space()
                    || record.generation != generation
                    || record.data.described() != data.key()?
                    || record.namespace.described() != namespace.observed_key()?
                {
                    return Err(ReconcileError::Invariant(
                        "original Unix generation root/source binding",
                    ));
                }
                let manifest = self.current_node_manifest(inspection)?;
                if record.generation == 0 && record.root != manifest.root()? {
                    return Err(ReconcileError::Invariant(
                        "initial Unix generation manifest differs",
                    ));
                }
                Ok((record, manifest))
            })()
        })();
        let (record, manifest) = match prepare {
            Ok(value) => value,
            Err(error) => {
                let mut close = UnixOriginalCloseAttempt::new();
                if let Some(record) = early_record.take() {
                    close.append_result(record.close_retaining());
                }
                if let Some(data) = early_data.take() {
                    close.append_result(data.close_retaining());
                }
                return Err(UnixGenerationReacquireFailure {
                    error,
                    original: None,
                    original_close: close.finish().err(),
                });
            }
        };
        let data = early_data.take().expect("actual early root");
        let record_file = early_record.take().expect("actual early record");
        let mut node = ReacquiredOriginalUnixNode {
            archive: self,
            record,
            record_digest: expected_record.clone(),
            manifest,
            bounds,
            inspection,
            data: Some(data),
            worktree: None,
            directories: BTreeMap::new(),
            observed: BTreeMap::new(),
            record_file: Some(record_file),
            locks: Vec::new(),
            pending: Vec::new(),
            journal: None,
            journal_failures: Vec::new(),
            io_failures: Vec::new(),
            close_failures: Vec::new(),
            created: BTreeMap::new(),
            creations: Vec::new(),
            create_failures: Vec::new(),
            directory_failures: Vec::new(),
            frame: None,
            poisoned: false,
        };
        let checked = (|| -> Result<()> {
            node.worktree = Some(OriginalUnixNativeRoot::acquire_private(
                namespace, worktree,
            )?);
            if node.worktree.as_ref().unwrap().key()? != node.record.worktree.described() {
                return Err(ReconcileError::Invariant(
                    "original Unix generation worktree differs",
                ));
            }
            // Acquire actual directory ancestry before any writable member.
            let mut directories: Vec<_> = node
                .record
                .objects
                .iter()
                .filter(|o| o.role.ends_with("_directory"))
                .cloned()
                .collect();
            directories.sort_by_key(|o| o.path.matches('/').count());
            for object in directories {
                let slot = slot(&object)?;
                let parent = slot.parent();
                let created = if parent.parts.is_empty() {
                    node.root(slot.data).acquire_existing_child(slot.name())
                } else {
                    node.directories
                        .get(&parent)
                        .ok_or(ReconcileError::Invariant("recorded Unix parent missing"))?
                        .acquire_existing_child(slot.name())
                };
                let directory = created.map_err(|mut f| {
                    let error = io(&f.error);
                    if let Some(d) = f.acquired.take() {
                        node.directories.insert(slot.clone(), d);
                    }
                    if let Some(c) = f.original_close.take() {
                        node.close_failures.push(c);
                    }
                    error
                })?;
                node.directories.insert(slot.clone(), directory);
                let directory = &node.directories[&slot];
                let same = directory.key()? == object.original.described()
                    && directory.parent_key()? == object.parent.described();
                if !same {
                    return Err(ReconcileError::Invariant(
                        "recorded Unix directory original differs",
                    ));
                }
            }
            // The actual data/work writer locks and CAS flock precede VFS registration.
            for object in node
                .record
                .objects
                .clone()
                .into_iter()
                .filter(|o| o.role.ends_with("_lock"))
            {
                let slot = slot(&object)?;
                let acquired = node.acquire_writable(&slot, object.original.described(), 4096)?;
                let locked = acquired.lock_exclusive().map_err(|mut f| {
                    let e = io(&f.error);
                    if let Some(v) = f.original.take() {
                        node.pending.push(v);
                    }
                    e
                })?;
                node.locks.push(locked);
            }
            if node.locks.len() != 2 {
                return Err(ReconcileError::Invariant(
                    "both recorded Unix writer locks required",
                ));
            }
            if !node
                .record
                .objects
                .iter()
                .any(|o| o.role == "data_lock" && o.path == "writer.lock")
                || !node
                    .record
                    .objects
                    .iter()
                    .any(|o| o.role == "work_lock" && o.path == ".sync-extend/writer.lock")
            {
                return Err(ReconcileError::Invariant(
                    "exact original data and worktree lock slots",
                ));
            }
            for object in node
                .record
                .objects
                .clone()
                .into_iter()
                .filter(|o| !o.role.ends_with("_lock") && !o.role.ends_with("_directory"))
            {
                let slot = slot(&object)?;
                let parent = slot.parent();
                let maximum = usize::try_from(object.bytes)
                    .map_err(|_| ReconcileError::ResourceLimit("observed Unix member capacity"))?
                    .max(1);
                let observed = if parent.parts.is_empty() {
                    node.root(slot.data)
                        .observe_file(slot.name(), maximum, slot.data)
                } else {
                    node.directories
                        .get(&parent)
                        .ok_or(ReconcileError::Invariant(
                            "recorded Unix file parent absent",
                        ))?
                        .observe_file(slot.name(), maximum, slot.data)
                }?;
                node.observed.insert(slot.clone(), observed);
                let observed = &node.observed[&slot];
                let same = observed.key()? == object.original.described()
                    && observed.parent_key()? == object.parent.described()
                    && observed.bytes()? == object.bytes;
                let content = observed.read_bounded()?;
                let metadata =
                    crate::filesystem::portable_metadata_from_capture(observed.metadata()?)?;
                if !same
                    || object
                        .digest
                        .as_ref()
                        .is_none_or(|digest| *digest != ContentId::hash(&content))
                    || object
                        .projected_metadata
                        .as_ref()
                        .is_some_and(|expected| !expected.matches_observed(&metadata))
                {
                    return Err(ReconcileError::Invariant(
                        "recorded Unix file complete observation differs",
                    ));
                }
            }
            node.verify_predecessors()?;
            let cas = node.acquire_writable(
                &Slot::new(true, &["cas.lock"]),
                node.record.database[4].described(),
                4096,
            )?;
            let cas = cas.lock_exclusive().map_err(|mut f| {
                let e = io(&f.error);
                if let Some(v) = f.original.take() {
                    node.pending.push(v);
                }
                e
            })?;
            // Keep CAS in locks until all four resources are acquired successfully.
            node.locks.push(cas);
            for (index, name) in [
                "journal.sqlite",
                "journal.sqlite-wal",
                "journal.sqlite-journal",
                "journal.sqlite-shm",
            ]
            .iter()
            .enumerate()
            {
                let maximum = if index == 0 {
                    bounds.maximum_journal_bytes as u64
                } else {
                    bounds.journal_sidecar_bytes
                };
                let acquired = node.acquire_writable(
                    &Slot::new(true, &[name]),
                    node.record.database[index].described(),
                    maximum,
                )?;
                node.pending.push(acquired);
            }
            let files: [ReacquiredUnixSqliteFile<'namespace>; 4] =
                match std::mem::take(&mut node.pending).try_into() {
                    Ok(files) => files,
                    Err(files) => {
                        node.pending = files;
                        return Err(ReconcileError::Invariant("exact four reacquired originals"));
                    }
                };
            let native_io = FreshUnixNativeSqliteIo::reacquire(
                files,
                node.locks.pop().expect("actual CAS lock"),
            )
            .map_err(|f| {
                let error = io(&f.error);
                node.io_failures.push(f);
                error
            })?;
            let journal = OriginalUnixRestoredJournal::reopen_original(
                native_io,
                &node.record.rows,
                &node.record.root,
                self.space(),
                inspection,
            )
            .map_err(|f| {
                let error = io(&f.error);
                node.journal_failures.push(f);
                error
            })?;
            node.journal = Some(journal);
            if let Some(source) = &node.record.source {
                let image = ContentId::hash(node.archive.journal_bytes()?);
                node.journal
                    .as_mut()
                    .expect("original reacquired Journal")
                    .verify_original_archive_source(source, &image)?;
            } else {
                return Err(ReconcileError::Invariant(
                    "Unix writable generation requires complete inert archive provenance",
                ));
            }
            node.manifest = node
                .journal
                .as_mut()
                .expect("actual reacquired Journal")
                .current_original_manifest()?;
            node.verify_manifest_membership()?;
            node.verify()
        })();
        match checked {
            Ok(()) => Ok(node),
            Err(error) => Err(UnixGenerationReacquireFailure {
                error,
                original: Some(node),
                original_close: None,
            }),
        }
    }
}
impl<'a, 'n> ReacquiredOriginalUnixNode<'a, 'n> {
    fn verify_manifest_membership(&self) -> Result<()> {
        for entry in self.manifest.entries.values() {
            let role = if entry.kind == sync_extend_core_model::EntryKind::Directory {
                "work_directory"
            } else {
                "work_file"
            };
            let object = self
                .record
                .objects
                .iter()
                .find(|o| o.role == role && o.path == entry.path.as_str())
                .ok_or(ReconcileError::Invariant(
                    "Unix current entry lacks actual original member",
                ))?;
            if let Some(content) = &entry.content {
                if object.bytes != content.length
                    || object.digest.as_ref() != Some(&content.content_id)
                {
                    return Err(ReconcileError::Invariant(
                        "Unix current content member differs",
                    ));
                }
                for chunk in &content.chunks {
                    let path = format!(
                        "cas/objects/{}/{}",
                        &chunk.content_id.as_str()[..2],
                        chunk.content_id
                    );
                    if !self.record.objects.iter().any(|o| {
                        o.role == "data_file"
                            && o.path == path
                            && o.bytes == u64::from(chunk.length)
                            && o.digest.as_ref() == Some(&chunk.content_id)
                    }) {
                        return Err(ReconcileError::Invariant(
                            "Unix current CAS chunk has no held original member",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    fn root(&self, data: bool) -> &OriginalUnixNativeRoot<'n> {
        if data {
            self.data.as_ref()
        } else {
            self.worktree.as_ref()
        }
        .expect("retained actual root")
    }
    fn acquire_writable(
        &mut self,
        slot: &Slot,
        key: UnixProtectedArtifactKey,
        maximum: u64,
    ) -> Result<ReacquiredUnixSqliteFile<'n>> {
        let parent = slot.parent();
        let result = if parent.parts.is_empty() {
            self.root(slot.data)
                .reacquire_sqlite_file(slot.name(), key, maximum)
        } else {
            self.directories
                .get(&parent)
                .ok_or(ReconcileError::Invariant(
                    "actual writable member parent missing",
                ))?
                .reacquire_sqlite_file(slot.name(), key, maximum)
        };
        result.map_err(|mut f| {
            let error = io(&f.error);
            if let Some(file) = f.original.take() {
                self.pending.push(file);
            }
            error
        })
    }
    pub fn verify(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(ReconcileError::Invariant(
                "Unix generation session poisoned",
            ));
        }
        self.root(true).verify()?;
        self.root(false).verify()?;
        for d in self.directories.values() {
            d.verify()?;
        }
        for f in self.observed.values() {
            f.verify()?;
        }
        for f in self.created.values() {
            f.verify()?;
        }
        for l in &self.locks {
            l.verify()?;
        }
        let record = self.record_file.as_ref().ok_or(ReconcileError::Invariant(
            "original generation record absent",
        ))?;
        if ContentId::hash(&record.read_bounded()?) != self.record_digest {
            return Err(ReconcileError::Invariant(
                "original generation record changed",
            ));
        }
        self.journal
            .as_mut()
            .ok_or(ReconcileError::Invariant(
                "original reacquired Journal absent",
            ))?
            .verify()?;
        Ok(())
    }
    fn close_resources(&mut self, close: &mut UnixOriginalCloseAttempt) {
        for failure in std::mem::take(&mut self.close_failures) {
            close.append_result(Err(failure));
        }
        if let Some(j) = self.journal.take() {
            match j.close_retaining() {
                Ok(v) => close.append_result(Ok(v)),
                Err(f) => self.journal_failures.push(f),
            }
        }
        self.journal_failures = std::mem::take(&mut self.journal_failures)
            .into_iter()
            .map(|f| f.close_remaining())
            .collect();
        self.io_failures = std::mem::take(&mut self.io_failures)
            .into_iter()
            .map(|f| f.close_remaining())
            .collect();
        for f in &self.journal_failures {
            close.note_error(std::io::Error::other(f.error.to_string()));
        }
        for f in &self.io_failures {
            close.note_error(std::io::Error::other(f.error.to_string()));
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
            return;
        }
        if let Some(frame) = self.frame.take() {
            close.append_result(frame.close_retaining());
        }
        for (_, file) in std::mem::take(&mut self.created) {
            close.append_result(file.close_retaining());
        }
        for file in std::mem::take(&mut self.creations) {
            close.append_result(file.close_retaining());
        }
        for mut f in std::mem::take(&mut self.create_failures) {
            if let Some(file) = f.original.take() {
                close.append_result(file.close_retaining());
            }
            if let Some(file) = f.failed_create.take() {
                close.append_result(file.close_retaining());
            }
        }
        for mut f in std::mem::take(&mut self.directory_failures) {
            if let Some(directory) = f.acquired.take() {
                close.append_result(directory.close_retaining());
            }
            if let Some(original) = f.original_close.take() {
                close.append_result(Err(original));
            }
        }
        for f in std::mem::take(&mut self.pending) {
            close.append_result(f.close_retaining());
        }
        for (_, f) in std::mem::take(&mut self.observed) {
            close.append_result(f.close_retaining());
        }
        if let Some(f) = self.record_file.take() {
            close.append_result(f.close_retaining());
        }
        for lock in std::mem::take(&mut self.locks) {
            close.append_result(lock.close_retaining());
        }
        for (_, d) in std::mem::take(&mut self.directories).into_iter().rev() {
            close.append_result(d.close_retaining());
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
    ) -> std::result::Result<ClosedUnixOriginalResources, UnixGenerationReacquireFailure<'a, 'n>>
    {
        let first = self.verify().err();
        let mut close = UnixOriginalCloseAttempt::new();
        self.close_resources(&mut close);
        match close.finish() {
            Ok(v) if first.is_none() => Ok(v),
            r => Err(UnixGenerationReacquireFailure {
                error: first.unwrap_or(ReconcileError::Invariant("reacquired Unix close failed")),
                original: Some(self),
                original_close: r.err(),
            }),
        }
    }
}
impl Drop for ReacquiredOriginalUnixNode<'_, '_> {
    fn drop(&mut self) {
        macro_rules! keep {
            ($n:ident) => {
                if let Some(v) = self.$n.take() {
                    let _ = Box::leak(Box::new(v));
                }
            };
        }
        macro_rules! all {
            ($n:ident) => {
                if !self.$n.is_empty() {
                    let _ = Box::leak(Box::new(std::mem::take(&mut self.$n)));
                }
            };
        }
        keep!(journal);
        keep!(data);
        keep!(worktree);
        keep!(record_file);
        keep!(frame);
        all!(directories);
        all!(observed);
        all!(locks);
        all!(pending);
        all!(journal_failures);
        all!(io_failures);
        all!(close_failures);
        all!(created);
        all!(creations);
        all!(create_failures);
        all!(directory_failures);
    }
}
