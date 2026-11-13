//! Native owner creation uses original handles and durable one-shot attempts.
use super::*;
use crate::{CasAccessGuard, Journal, TreeCoordinatorAdmissionInspection};
use rusqlite::{params_from_iter, Transaction, TransactionBehavior};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    tree_native_action_layout::TreeNativeActionObservation,
    tree_restore_identity::TreeNativeIdentity, EntryKind, FileManifest, SpaceId,
};
use sync_extend_platform_fs::{
    regular_file_matches_path, FileKey, GuardedReadFile, LockedDirectory, LockedDirectoryMutation,
    LockedFile, OwnedFileCreation,
};

#[path = "executor.rs"]
mod executor;
pub use executor::{
    TreeNativeCleanupReceipt, TreeNativeExecution, TreeNativeExecutionFileView,
    TreeNativeFinalized, TreeNativeObservation,
};

pub(super) struct Directory {
    pub(super) path: PathBuf,
    pub(super) held: LockedDirectory,
    pub(super) key: FileKey,
}
pub(super) struct File {
    pub(super) path: PathBuf,
    pub(super) held: LockedFile,
    pub(super) key: FileKey,
    pub(super) content: Option<FileManifest>,
}
pub(super) struct Scope {
    pub(super) directories: Vec<Directory>,
    pub(super) files: Vec<File>,
    pub(super) root: PathBuf,
    pub(super) parent: PathBuf,
    pub(super) parent_key: FileKey,
    pub(super) expected: BTreeMap<String, EntryKind>,
    pub(super) max: usize,
}

pub struct TreeNativeOwnerCreation {
    transaction: EntryId,
    space: SpaceId,
    scope: Scope,
    directory: LockedDirectoryMutation,
    marker: OwnedFileCreation,
    owner_path: PathBuf,
    marker_path: PathBuf,
    directory_key: FileKey,
    marker_key: FileKey,
    marker_bytes: Vec<u8>,
    _coordination: CasAccessGuard,
}

/// Borrow the exact retained files for quota reads while the original writer
/// remains exclusive. This view grants no native action or ownership.
pub struct TreeNativeOwnerFileView<'a> {
    creation: &'a TreeNativeOwnerCreation,
}

impl TreeNativeOwnerCreation {
    pub fn file_view(&self) -> TreeNativeOwnerFileView<'_> {
        TreeNativeOwnerFileView { creation: self }
    }
}

// Canonical local Windows roots may carry the verbatim drive prefix while
// quota visitors retain the ordinary spelling. Remove only that prefix, then
// require the same exact slot and its live non-following physical witness.
pub(super) fn same_slot_spelling(left: &Path, right: &Path) -> bool {
    fn ordinary(path: &Path) -> &Path {
        path.to_str()
            .and_then(|value| value.strip_prefix(r"\\?\"))
            .map(Path::new)
            .unwrap_or(path)
    }
    ordinary(left) == ordinary(right)
}

impl TreeNativeOwnerFileView<'_> {
    pub fn verify(&self) -> Result<()> {
        self.creation.verify(&self.creation.marker_bytes)
    }

    pub fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        let creation = self.creation;
        let file = if same_slot_spelling(path, &creation.marker_path) {
            creation.marker.reader()
        } else if let Some(file) = creation
            .scope
            .files
            .iter()
            .find(|file| same_slot_spelling(&file.path, path))
        {
            file.held.reader()
        } else {
            return Ok(None);
        };
        self.verify()?;
        if !regular_file_matches_path(file, path)? {
            return Err(invalid("tree owner view exact physical slot differs"));
        }
        let key = FileKey::from_file(file)?;
        Ok(Some(crate::NativePublicationFileObservation {
            metadata: file.metadata()?,
            physical_identity: ContentId::hash(
                format!("windows:{}:{}", key.volume, key.id).as_bytes(),
            ),
            content: None,
        }))
    }
}

/// Reopened exact read guards. It has no payload writer or native step endpoint.
pub struct TreeNativeOwnerReadiness {
    transaction: EntryId,
    _coordination: CasAccessGuard,
    _scope: Scope,
    _directory: LockedDirectory,
    _marker: LockedFile,
}

impl TreeNativeOwnerReadiness {
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction
    }
    pub fn owner_ready(&self) -> bool {
        true
    }
    pub fn whole_tree_completed(&self) -> bool {
        false
    }
}

pub(super) fn native(key: FileKey) -> TreeNativeIdentity {
    TreeNativeIdentity {
        volume_serial: key.volume,
        file_id: format!("{:032x}", key.id),
    }
}

pub(super) fn checkpoint(_phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(_phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{_phase}");
        while !std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
            .is_some_and(|path| Path::new(&path).is_file())
        {
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
}

pub(super) fn checkpoint_index(phase: &str, ordinal: usize) {
    checkpoint(phase);
    #[cfg(feature = "fault-injection")]
    checkpoint(&format!("{phase}:{ordinal}"));
    #[cfg(not(feature = "fault-injection"))]
    let _ = ordinal;
}

pub(super) fn verify_content(reader: &fs::File, content: &FileManifest) -> Result<()> {
    if reader.metadata()?.len() != content.length {
        return Err(invalid("tree owner captured file length differs"));
    }
    let mut reader = reader;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = content.length;
    let mut buffer = [0u8; 65536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or(invalid("tree owner captured file grew"))?;
        hasher.update(&buffer[..count]);
    }
    if remaining != 0 || ContentId::from_hasher(&hasher) != content.content_id {
        return Err(invalid("tree owner captured content differs"));
    }
    Ok(())
}

pub(super) fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid("tree owner target slot occupied")),
    }
}

impl Scope {
    fn capture(
        journal: &Journal,
        projection: &TreeCoordinatorAdmissionInspection,
        max: usize,
    ) -> Result<Self> {
        let root: PathBuf = journal
            .state("worktree")?
            .ok_or(invalid("tree owner worktree absent"))?
            .into();
        let parent = root.join(".sync-extend");
        let inventory = projection.identity().inventory();
        let mut scope = Self {
            directories: Vec::new(),
            files: Vec::new(),
            root,
            parent,
            parent_key: FileKey { volume: 0, id: 0 },
            expected: projection
                .baseline()
                .entries
                .values()
                .map(|entry| (entry.path.as_str().to_owned(), entry.kind))
                .collect(),
            max,
        };
        let mut ancestors: Vec<_> = scope
            .root
            .ancestors()
            .filter(|path| path.is_absolute())
            .map(Path::to_owned)
            .collect();
        ancestors.reverse();
        for path in ancestors {
            scope.directory(&path)?;
        }
        let root_key = scope
            .directories
            .last()
            .ok_or(invalid("tree owner root absent"))?
            .key;
        let parent = scope.parent.clone();
        scope.parent_key = scope.directory(&parent)?;
        if native(root_key) != inventory.root
            || native(scope.parent_key) != inventory.marker_directory
        {
            return Err(invalid("tree owner exact root marker directory changed"));
        }
        let marker = parent.join("space-id");
        let held = LockedFile::open(&marker)?;
        let key = held.key()?;
        if native(key) != inventory.marker_file {
            return Err(invalid("tree owner space marker changed"));
        }
        let mut bytes = Vec::new();
        let reader = held.reader();
        reader.take(1025).read_to_end(&mut bytes)?;
        if bytes != projection.baseline().space_id.as_str().as_bytes() {
            return Err(invalid("tree owner space marker bytes differ"));
        }
        scope.files.push(File {
            path: marker,
            held,
            key,
            content: None,
        });
        let mut entries: Vec<_> = projection.baseline().entries.values().collect();
        entries.sort_by_key(|entry| (entry.kind != EntryKind::Directory, entry.path.clone()));
        for entry in entries {
            if scope.files.len() + scope.directories.len() >= max {
                return Err(invalid("tree owner bounded captured handles"));
            }
            let path = scope.root.join(entry.path.as_str());
            let key = match entry.kind {
                EntryKind::Directory => scope.directory(&path)?,
                EntryKind::File => {
                    let held = LockedFile::open(&path)?;
                    let key = held.key()?;
                    let content = entry
                        .content
                        .clone()
                        .ok_or(invalid("tree owner file content absent"))?;
                    verify_content(held.reader(), &content)?;
                    scope.files.push(File {
                        path,
                        held,
                        key,
                        content: Some(content),
                    });
                    key
                }
            };
            if inventory.entries.get(&entry.path).is_none_or(|expected| {
                expected.entry_id != entry.entry_id
                    || expected.kind != entry.kind
                    || expected.identity != native(key)
            }) {
                return Err(invalid("tree owner baseline native full identity differs"));
            }
        }
        scope.verify()?;
        Ok(scope)
    }

    pub(super) fn directory(&mut self, path: &Path) -> Result<FileKey> {
        if self.directories.len() + self.files.len() >= self.max {
            return Err(invalid("tree owner directory handle bound"));
        }
        let held = LockedDirectory::open(path)?;
        held.require_case_insensitive()?;
        held.require_local_ntfs(path)?;
        let key = held.key()?;
        self.directories.push(Directory {
            path: path.to_owned(),
            held,
            key,
        });
        Ok(key)
    }

    pub(super) fn verify(&self) -> Result<()> {
        for directory in &self.directories {
            if directory.held.key()? != directory.key
                || !directory.held.matches_path(&directory.path)?
            {
                return Err(invalid("tree owner retained ancestor slot differs"));
            }
        }
        for file in &self.files {
            sync_extend_platform_fs::verify_regular_file(file.held.reader())?;
            if file.held.key()? != file.key
                || !regular_file_matches_path(file.held.reader(), &file.path)?
            {
                return Err(invalid("tree owner retained baseline file slot differs"));
            }
            if let Some(content) = &file.content {
                verify_content(file.held.reader(), content)?;
            }
        }
        let expected = &self.expected;
        let mut seen = BTreeMap::new();
        let mut directories = vec![self.root.clone()];
        while let Some(directory) = directories.pop() {
            for child in fs::read_dir(directory)? {
                let child = child?;
                let path = child.path();
                let name = child.file_name();
                let name = name.to_str().ok_or(invalid("tree owner non-UTF8 child"))?;
                if [".sync-extend", ".sync-tmp", ".git"]
                    .iter()
                    .any(|internal| name.eq_ignore_ascii_case(internal))
                {
                    continue;
                }
                if seen.len() >= self.max {
                    return Err(invalid("tree owner native membership bound"));
                }
                let relative = path
                    .strip_prefix(&self.root)
                    .map_err(|_| invalid("tree owner child escaped root"))?
                    .to_str()
                    .ok_or(invalid("tree owner non-UTF8 path"))?
                    .replace('\\', "/");
                let metadata = fs::symlink_metadata(&path)?;
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 || metadata.file_type().is_symlink() {
                    return Err(invalid("tree owner foreign reparse child"));
                }
                let kind = if metadata.is_dir() {
                    EntryKind::Directory
                } else if metadata.is_file() {
                    EntryKind::File
                } else {
                    return Err(invalid("tree owner foreign special child"));
                };
                if expected.get(&relative) != Some(&kind) || seen.insert(relative, kind).is_some() {
                    return Err(invalid("tree owner foreign native member"));
                }
                if kind == EntryKind::Directory {
                    directories.push(path);
                }
            }
        }
        if &seen != expected {
            return Err(invalid("tree owner missing baseline membership"));
        }
        Ok(())
    }
}

impl TreeNativeOwnerCreation {
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction
    }

    fn verify(&self, marker_bytes: &[u8]) -> Result<()> {
        self.scope.verify()?;
        let directory = self.directory.original_creation()?;
        directory.verify()?;
        let marker = self.marker.original_creation()?;
        marker.verify()?;
        if directory.key()? != self.directory_key
            || directory.parent_key()? != self.scope.parent_key
            || marker.key()? != self.marker_key
            || marker.parent_key()? != self.directory_key
            || !self.directory.matches_path(&self.owner_path)?
            || !regular_file_matches_path(self.marker.reader(), &self.marker_path)?
        {
            return Err(invalid("tree owner live original creator changed"));
        }
        verify_marker(self.marker.reader(), marker_bytes)?;
        owner_membership(&self.owner_path, &self.marker_path)
    }
}

fn owner_membership(owner: &Path, marker: &Path) -> Result<()> {
    let mut members = fs::read_dir(owner)?;
    let child = members
        .next()
        .ok_or(invalid("tree owner marker missing"))??;
    if child.path() != marker || members.next().is_some() {
        return Err(invalid("tree owner foreign child blocks Ready"));
    }
    Ok(())
}

pub(super) fn verify_marker(reader: &fs::File, expected: &[u8]) -> Result<()> {
    if reader.metadata()?.len() != expected.len() as u64 {
        return Err(invalid("tree owner marker extent differs"));
    }
    let mut reader = reader;
    reader.seek(SeekFrom::Start(0))?;
    let mut actual = Vec::new();
    reader
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    if actual != expected {
        return Err(invalid("tree owner marker bytes differ"));
    }
    Ok(())
}

impl Journal {
    /// Explicitly create the exact admitted owner. A previous activation never
    /// grants a second CREATE, even when its path is absent or has equal bytes.
    pub fn create_tree_native_owner(
        &self,
        space: &SpaceId,
        transaction: &EntryId,
        max: usize,
    ) -> Result<TreeNativeOwnerCreation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("tree owner CREATE refuses caller transaction"));
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) = self.tree_owner_state(space, transaction, max)?;
        if progress.records.len() != 1 {
            return Err(invalid("tree original owner CREATE cannot replay progress"));
        }
        let (projection, _, _) = crate::tree_native_storage::initial_layout(
            &self.connection,
            &preparation,
            preparation
                .native_storage
                .as_ref()
                .ok_or(invalid("tree owner prewrite missing"))?
                .request(),
            max,
        )?;
        let scope = Scope::capture(self, &projection, max)?;
        let owner = &preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree owner intent missing"))?
            .intent;
        let stage_path = scope.parent.join(&owner.stage_component);
        let owner_path = scope.parent.join(&owner.published_component);
        let marker_path = owner_path.join(&owner.marker_component);
        let marker_bytes =
            encode_history_record(&owner.marker_payload, MAX_OPERATION_BYTES as u64)?;
        absent(&stage_path)?;
        absent(&owner_path)?;
        tx.commit()?;
        let parent = scope
            .directories
            .iter()
            .find(|directory| directory.path == scope.parent)
            .ok_or(invalid("tree owner retained parent missing"))?;

        let attempt = self.tree_owner_attempt(space, transaction, max, &scope)?;
        checkpoint("after_tree_owner_directory_activation");
        let directory = parent.held.create_new_child(&owner.stage_component)?;
        checkpoint("after_tree_owner_directory_created");
        let original = directory.original_creation()?;
        let directory_key = original.key()?;
        self.tree_owner_observed(
            attempt,
            TreeNativeActionObservation::Created {
                identity: native(directory_key),
            },
            max,
            || {
                original.verify()?;
                scope.verify()?;
                if original.parent_key()? != scope.parent_key
                    || original.created_component() != owner.stage_component
                    || !directory.matches_path(&stage_path)?
                {
                    return Err(invalid("tree owner original directory creator differs"));
                }
                Ok(())
            },
        )?;
        checkpoint("after_tree_owner_directory_observed");

        let attempt = self.tree_owner_attempt(space, transaction, max, &scope)?;
        checkpoint("after_tree_owner_publish_activation");
        absent(&owner_path)?;
        if !directory.matches_path(&stage_path)? {
            return Err(invalid("tree owner original stage slot differs"));
        }
        directory.rename_no_replace(&owner_path)?;
        checkpoint("after_tree_owner_directory_published");
        self.tree_owner_observed(
            attempt,
            TreeNativeActionObservation::Moved {
                identity: native(directory_key),
            },
            max,
            || {
                directory.original_creation()?.verify()?;
                scope.verify()?;
                if !directory.matches_path(&owner_path)? {
                    return Err(invalid("tree owner published directory slot differs"));
                }
                absent(&stage_path)
            },
        )?;

        let attempt = self.tree_owner_attempt(space, transaction, max, &scope)?;
        checkpoint("after_tree_owner_marker_activation");
        absent(&marker_path)?;
        let mut marker = directory.create_new_file(&owner.marker_component)?;
        checkpoint("after_tree_owner_marker_created");
        let original = marker.original_creation()?;
        let marker_key = original.key()?;
        self.tree_owner_observed(
            attempt,
            TreeNativeActionObservation::Created {
                identity: native(marker_key),
            },
            max,
            || {
                original.verify()?;
                scope.verify()?;
                if original.parent_key()? != directory_key
                    || original.created_component() != owner.marker_component
                    || !regular_file_matches_path(marker.reader(), &marker_path)?
                {
                    return Err(invalid("tree owner original marker creator differs"));
                }
                owner_membership(&owner_path, &marker_path)
            },
        )?;

        let attempt = self.tree_owner_attempt(space, transaction, max, &scope)?;
        checkpoint("after_tree_owner_materialize_activation");
        marker.writer().write_all(&marker_bytes)?;
        marker.writer().sync_all()?;
        checkpoint("after_tree_owner_marker_materialized");
        self.tree_owner_observed(
            attempt,
            TreeNativeActionObservation::Materialized {
                identity: native(marker_key),
                content_hash: ContentId::hash(&marker_bytes),
                length: marker_bytes.len() as u64,
            },
            max,
            || {
                marker.original_creation()?.verify()?;
                scope.verify()?;
                verify_marker(marker.reader(), &marker_bytes)?;
                owner_membership(&owner_path, &marker_path)
            },
        )?;
        let creation = TreeNativeOwnerCreation {
            transaction: transaction.clone(),
            space: space.clone(),
            scope,
            directory,
            marker,
            owner_path,
            marker_path,
            directory_key,
            marker_key,
            marker_bytes: marker_bytes.clone(),
            _coordination: coordination,
        };
        creation.verify(&marker_bytes)?;
        Ok(creation)
    }

    /// Consume writable marker creation before issuing read-only owner Ready.
    pub fn seal_tree_native_owner(
        &self,
        creation: TreeNativeOwnerCreation,
        max: usize,
    ) -> Result<TreeNativeOwnerReadiness> {
        creation.verify(&creation.marker_bytes)?;
        let attempt =
            self.tree_owner_attempt(&creation.space, &creation.transaction, max, &creation.scope)?;
        checkpoint("after_tree_owner_ready_activation");
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let (preparation, _) =
            self.tree_owner_state(&creation.space, &creation.transaction, max)?;
        let payload = &preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree owner payload missing"))?
            .intent
            .marker_payload;
        let marker_bytes = encode_history_record(payload, MAX_OPERATION_BYTES as u64)?;
        tx.commit()?;
        creation.verify(&marker_bytes)?;
        let TreeNativeOwnerCreation {
            transaction,
            space,
            scope,
            directory,
            marker,
            owner_path,
            marker_path,
            directory_key,
            marker_key,
            marker_bytes: _,
            _coordination: coordination,
        } = creation;
        drop(marker);
        drop(directory);
        let held_directory = LockedDirectory::open(&owner_path)?;
        let held_marker = LockedFile::open(&marker_path)?;
        if held_directory.key()? != directory_key || held_marker.key()? != marker_key {
            return Err(invalid("tree owner Ready creator read handoff changed"));
        }
        self.tree_owner_observed(
            attempt,
            TreeNativeActionObservation::OwnerReady {
                directory: native(directory_key),
                marker: native(marker_key),
            },
            max,
            || {
                scope.verify()?;
                sync_extend_platform_fs::verify_regular_file(held_marker.reader())?;
                verify_marker(held_marker.reader(), &marker_bytes)?;
                if !held_directory.matches_path(&owner_path)?
                    || !held_marker.matches_path(&marker_path)?
                {
                    return Err(invalid("tree owner Ready current exact slots changed"));
                }
                owner_membership(&owner_path, &marker_path)
            },
        )?;
        checkpoint("after_tree_owner_ready_observed");
        drop(held_marker);
        drop(held_directory);
        drop(scope);
        let readiness = self.reopen_tree_native_owner_readiness(&space, &transaction, max)?;
        drop(coordination);
        Ok(readiness)
    }

    /// Reopen only all five complete original phases; partial activation refuses.
    pub fn reopen_tree_native_owner_readiness(
        &self,
        space: &SpaceId,
        transaction: &EntryId,
        max: usize,
    ) -> Result<TreeNativeOwnerReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("tree owner Ready refuses caller transaction"));
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) = self.tree_owner_state(space, transaction, max)?;
        if progress.records.len() != 10 || progress.layout.awaiting_observation() {
            return Err(invalid(
                "tree owner incomplete original phases cannot be adopted",
            ));
        }
        let (projection, _, _) = crate::tree_native_storage::initial_layout(
            &self.connection,
            &preparation,
            preparation
                .native_storage
                .as_ref()
                .ok_or(invalid("tree Ready prewrite missing"))?
                .request(),
            max,
        )?;
        let scope = Scope::capture(self, &projection, max)?;
        let owner = &preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree Ready intent missing"))?
            .intent;
        let owner_path = scope.parent.join(&owner.published_component);
        let marker_path = owner_path.join(&owner.marker_component);
        let marker_bytes =
            encode_history_record(&owner.marker_payload, MAX_OPERATION_BYTES as u64)?;
        let directory = LockedDirectory::open(&owner_path)?;
        let marker = LockedFile::open(&marker_path)?;
        let last = progress
            .records
            .last()
            .ok_or(invalid("tree Ready record missing"))?;
        let TreeNativeActionPayload::Observed {
            observation:
                TreeNativeActionObservation::OwnerReady {
                    directory: expected_directory,
                    marker: expected_marker,
                },
            ..
        } = &last.payload
        else {
            return Err(invalid("tree Ready exact terminal kind differs"));
        };
        if native(directory.key()?) != *expected_directory
            || native(marker.key()?) != *expected_marker
            || !directory.matches_path(&owner_path)?
            || !marker.matches_path(&marker_path)?
        {
            return Err(invalid("tree owner Ready current identity differs"));
        }
        verify_marker(marker.reader(), &marker_bytes)?;
        owner_membership(&owner_path, &marker_path)?;
        scope.verify()?;
        tx.commit()?;
        Ok(TreeNativeOwnerReadiness {
            transaction: transaction.clone(),
            _coordination: coordination,
            _scope: scope,
            _directory: directory,
            _marker: marker,
        })
    }

    pub(crate) fn tree_owner_state(
        &self,
        space: &SpaceId,
        transaction: &EntryId,
        max: usize,
    ) -> Result<(TreeRestorePreparation, Progress)> {
        // Native effect boundaries call this read-only audit after a preceding
        // SQL transaction commits. Retain one owned snapshot across capacity,
        // typed lineage and CAS validation; reuse an existing caller snapshot.
        let snapshot = if self.connection.is_autocommit() {
            Some(Transaction::new_unchecked(
                &self.connection,
                TransactionBehavior::Deferred,
            )?)
        } else {
            None
        };
        let capacity = self
            .read_view()
            .audit_local_commit_capacity(space, self.writer_capacity_limits(max)?)?;
        if !capacity.report.within_accounted_limits() || !capacity.report.coverage_gaps().is_empty()
        {
            return Err(invalid("tree owner current complete capacity unavailable"));
        }
        let preparation = self
            .read_view()
            .audit_tree_restore_preparations(space, max)?
            .into_iter()
            .find(|preparation| &preparation.intent.transaction_id == transaction)
            .ok_or(invalid("tree owner preparation missing"))?;
        let progress = audit(&self.connection, &preparation, &capacity.rows, max)?;
        self.tree_owner_cas(&preparation)?;
        if let Some(snapshot) = snapshot {
            snapshot.commit()?;
        }
        Ok((preparation, progress))
    }

    fn tree_owner_cas(&self, preparation: &TreeRestorePreparation) -> Result<()> {
        let parent = self
            .database_path
            .parent()
            .ok_or(invalid("tree owner CAS parent missing"))?;
        for table in ["tree_restore_objects", "tree_restore_original_objects"] {
            let mut statement = self.connection.prepare(&format!(
                "SELECT content_id,length FROM main.{table} WHERE transaction_id=?1"
            ))?;
            let mut rows = statement.query([preparation.intent.transaction_id.as_str()])?;
            while let Some(row) = rows.next()? {
                let content: ContentId = row.get::<_, String>(0)?.parse()?;
                let length: u32 = row.get(1)?;
                self.require_cas_access(&content)?;
                let path = parent
                    .join("cas/objects")
                    .join(&content.as_str()[..2])
                    .join(content.as_str());
                let held = GuardedReadFile::open(&path)?;
                held.verify_single_link()?;
                if held.reader().metadata()?.len() != u64::from(length) {
                    return Err(invalid("tree owner CAS length differs"));
                }
                let mut hasher = blake3::Hasher::new();
                let mut reader = held.reader();
                let mut buffer = [0u8; 65536];
                loop {
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
                if ContentId::from_hasher(&hasher) != content {
                    return Err(invalid("tree owner CAS hash differs"));
                }
            }
        }
        Ok(())
    }

    fn tree_owner_insert(&self, table: &str, values: Vec<Value>) -> Result<()> {
        if !["tree_native_action_attempts", "tree_native_action_records"].contains(&table) {
            return Err(invalid("tree owner unsupported effect table"));
        }
        let mut exact = vec![Value::Text(table.into())];
        exact.extend(values.clone());
        let permit = self.tree_native_issuance.permit(vec![exact])?;
        let placeholders = vec!["?"; values.len()].join(",");
        self.connection.execute(
            &format!("INSERT INTO main.{table} VALUES({placeholders})"),
            params_from_iter(values),
        )?;
        permit.require_consumed()?;
        Ok(())
    }

    fn tree_owner_record(
        &self,
        preparation: &TreeRestorePreparation,
        record: &TreeNativeActionLayoutRecord,
    ) -> Result<()> {
        let layout_hash = &preparation
            .native_storage
            .as_ref()
            .ok_or(invalid("tree owner prewrite absent"))?
            .header()
            .layout_hash;
        let row = tree_native_action_row_values(layout_hash, record)?;
        let values = row
            .columns()
            .iter()
            .map(|column| match &column.value {
                TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
                TreeStorageColumnValue::Integer(value) => {
                    Ok(Value::Integer(crate::sql_integer(*value)?))
                }
            })
            .collect::<Result<_>>()?;
        self.tree_owner_insert("tree_native_action_records", values)
    }

    fn tree_owner_attempt(
        &self,
        space: &SpaceId,
        transaction: &EntryId,
        max: usize,
        scope: &Scope,
    ) -> Result<Attempt> {
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) = self.tree_owner_state(space, transaction, max)?;
        scope.verify()?;
        let intended = progress
            .records
            .last()
            .ok_or(invalid("tree owner last intention absent"))?;
        if !progress.layout.awaiting_observation()
            || intended.action_ordinal >= progress.layout.action_count()
        {
            return Err(invalid("tree owner awaiting exact creation intention"));
        }
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tree_native_action_attempts WHERE transaction_id=?1 AND action_ordinal=?2)",
            rusqlite::params![transaction.as_str(), intended.action_ordinal as i64], |row| row.get(0),
        )?;
        if exists {
            return Err(invalid("tree original owner attempt cannot retry or adopt"));
        }
        let future = preparation
            .native_future_admission
            .as_ref()
            .ok_or(invalid("tree owner future missing"))?;
        let attempt = Attempt {
            format_version: 1,
            scope: intended.scope.clone(),
            layout_hash: preparation
                .native_storage
                .as_ref()
                .ok_or(invalid("tree owner prewrite missing"))?
                .header()
                .layout_hash
                .clone(),
            full_capacity_hash: future.capacity_hash().clone(),
            intended_record_hash: hash(intended)?,
            attempt_id: future.generations().attempt_ids[&intended.action_ordinal].clone(),
            action_ordinal: intended.action_ordinal,
            intended_record_index: intended.record_index,
            attempted_at_ms: intended.recorded_at_ms.max(future.request().created_at_ms),
        };
        self.tree_owner_insert("tree_native_action_attempts", attempt_values(&attempt)?)?;
        self.tree_owner_state(space, transaction, max)?;
        scope.verify()?;
        tx.commit()?;
        drop(coordination);
        Ok(attempt)
    }

    fn tree_owner_observed(
        &self,
        attempt: Attempt,
        observation: TreeNativeActionObservation,
        max: usize,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) =
            self.tree_owner_state(&attempt.scope.space_id, &attempt.scope.transaction_id, max)?;
        let before = self.read_view().audit_local_commit_capacity(
            &attempt.scope.space_id,
            self.writer_capacity_limits(max)?,
        )?;
        if !progress.layout.awaiting_observation()
            || progress.records.last().is_none_or(|record| {
                record.record_index != attempt.intended_record_index
                    || hash(record).ok().as_ref() != Some(&attempt.intended_record_hash)
            })
        {
            return Err(invalid("tree owner observed preceding activation differs"));
        }
        let observed = TreeNativeActionLayoutRecord {
            scope: attempt.scope.clone(),
            record_index: attempt.intended_record_index + 1,
            action_ordinal: attempt.action_ordinal,
            previous_hash: attempt.intended_record_hash.clone(),
            recorded_at_ms: attempt.attempted_at_ms,
            payload: TreeNativeActionPayload::Observed {
                intended_record_hash: attempt.intended_record_hash,
                observation,
            },
        };
        self.tree_owner_record(&preparation, &observed)?;
        let (preparation, next) =
            self.tree_owner_state(&attempt.scope.space_id, &attempt.scope.transaction_id, max)?;
        if observed.action_ordinal != 4 && next.layout.next_intent().is_some() {
            let intended = TreeNativeActionLayoutRecord {
                scope: observed.scope.clone(),
                record_index: observed.record_index + 1,
                action_ordinal: observed.action_ordinal + 1,
                previous_hash: hash(&observed)?,
                recorded_at_ms: observed.recorded_at_ms,
                payload: TreeNativeActionPayload::Intended {
                    intent: Box::new(
                        next.layout
                            .next_intent()
                            .ok_or(invalid("tree next owner action absent"))?
                            .clone(),
                    ),
                },
            };
            self.tree_owner_record(&preparation, &intended)?;
            self.tree_owner_state(&attempt.scope.space_id, &attempt.scope.transaction_id, max)?;
        }
        verify()?;
        let after = self.read_view().audit_local_commit_capacity(
            &attempt.scope.space_id,
            self.writer_capacity_limits(max)?,
        )?;
        let prior: BTreeMap<_, _> = before
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        let current: BTreeMap<_, _> = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        for key in prior.keys().chain(current.keys()) {
            let owned_new = key.0 == "tree_native_action_records"
                && key.1.first().map(String::as_str) == Some(attempt.scope.transaction_id.as_str())
                && key
                    .1
                    .get(1)
                    .and_then(|index| index.parse::<usize>().ok())
                    .is_some_and(|index| {
                        index == observed.record_index
                            || (index == observed.record_index + 1
                                && observed.action_ordinal != 4
                                && next.layout.next_intent().is_some())
                    });
            if !owned_new && prior.get(key) != current.get(key) {
                return Err(invalid(
                    "tree observation collateral row outside exact action scope",
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }
}
