use crate::{LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::*;
use sync_extend_journal::{MutationAction, MutationState};

#[derive(Serialize)]
pub struct DeleteResult {
    pub transaction_id: EntryId,
    pub snapshot_id: SnapshotId,
    pub original_retained_at_commit: bool,
    pub local_committed: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn execute_mutation(&mut self, id: &EntryId) -> Result<DeleteResult> {
        self.verify_root()?;
        let mutation = self.journal.mutation(id)?;
        if mutation.intent.space_id != self.space_id
            || mutation.intent.action != MutationAction::Delete
        {
            return Err(ReconcileError::Invariant(
                "only this space's single-file delete has an executor",
            ));
        }
        if mutation.state == MutationState::Cancelled {
            return Err(ReconcileError::Invariant(
                "cancelled mutation cannot execute",
            ));
        }
        if mutation.state != MutationState::Committed {
            self.execute_delete_platform(id)?;
        }
        let mutation = self.journal.mutation(id)?;
        self.journal.verify_mutation_references(id)?;
        Ok(DeleteResult {
            transaction_id: id.clone(),
            snapshot_id: mutation
                .committed_snapshot
                .ok_or(ReconcileError::Invariant("delete is not committed"))?,
            original_retained_at_commit: true,
            local_committed: true,
            remote_backup_complete: false,
        })
    }

    pub fn recover_mutations(&mut self) -> Result<Vec<DeleteResult>> {
        self.verify_root()?;
        let mutations = self.journal.outstanding_mutations(&self.space_id)?;
        if mutations
            .iter()
            .any(|mutation| mutation.state == MutationState::Prepared)
        {
            return Err(ReconcileError::Invariant(
                "prepared mutation requires explicit execute/cancel; recovery is not authorization",
            ));
        }
        mutations
            .into_iter()
            .map(|mutation| self.execute_mutation(&mutation.intent.transaction_id))
            .collect()
    }

    #[cfg(not(windows))]
    fn execute_delete_platform(&mut self, _id: &EntryId) -> Result<()> {
        Err(ReconcileError::Invariant(
            "delete executor requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{check_ancestors, fault::checkpoint, filesystem::physical_identity, now_ms};
    use std::{
        fs,
        io::{Read, Seek, SeekFrom, Write},
        path::Path,
    };
    use sync_extend_cas::sync_directory;
    use sync_extend_journal::{DeleteExecution, Mutation};
    use sync_extend_platform_fs::{LockedDirectory, LockedFile};

    fn directory_chain(path: &Path) -> Result<Vec<LockedDirectory>> {
        let mut paths: Vec<_> = path.ancestors().take_while(|p| p.is_absolute()).collect();
        paths.reverse();
        let mut guards = Vec::new();
        for path in paths {
            check_ancestors(path)?;
            let guard = LockedDirectory::open(path)?;
            if ContentId::hash(guard.key()?.to_string().as_bytes()) != physical_identity(path)? {
                return Err(ReconcileError::Unstable);
            }
            guards.push(guard);
        }
        Ok(guards)
    }

    fn identity(file: &LockedFile) -> Result<ContentId> {
        Ok(ContentId::hash(file.key()?.to_string().as_bytes()))
    }

    fn content_matches(file: &LockedFile, content: &FileManifest) -> Result<bool> {
        if file.reader().metadata()?.len() != content.length {
            return Ok(false);
        }
        let mut reader = file.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut hash = blake3::Hasher::new();
        let mut left = content.length;
        let mut buffer = [0u8; 65536];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if n as u64 > left {
                return Ok(false);
            }
            left -= n as u64;
            hash.update(&buffer[..n]);
        }
        Ok(left == 0 && ContentId::from_hasher(&hash) == content.content_id)
    }

    fn validate_directory(directory: &Path, mutation: &Mutation) -> Result<LockedFile> {
        let execution = mutation
            .execution
            .as_ref()
            .ok_or(ReconcileError::Invariant("missing delete execution"))?;
        if physical_identity(directory)? != execution.directory_identity {
            return Err(ReconcileError::Invariant(
                "delete quarantine directory identity changed",
            ));
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_name() != "owner" && entry.file_name() != "original" {
                return Err(ReconcileError::Invariant(
                    "unexpected delete quarantine path",
                ));
            }
            check_ancestors(&entry.path())?;
        }
        let owner_path = directory.join("owner");
        let owner = LockedFile::open(&owner_path)?;
        let marker = format!(
            "{}:{}",
            mutation.intent.transaction_id, execution.execution_id
        );
        let mut bytes = Vec::new();
        owner
            .reader()
            .take(marker.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if identity(&owner)? != execution.owner_identity || bytes != marker.as_bytes() {
            return Err(ReconcileError::Invariant(
                "delete quarantine ownership changed",
            ));
        }
        Ok(owner)
    }

    impl LocalSpace {
        fn validate_delete_baseline(&self, mutation: &Mutation) -> Result<()> {
            let intent = &mutation.intent;
            let baseline = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            let scan = self.stable_scan()?;
            if self
                .manifest()?
                .as_ref()
                .map(Manifest::root)
                .transpose()?
                .as_ref()
                != Some(&intent.baseline_root)
                || baseline.entries.len() != scan.len()
                || baseline.entries.values().any(|entry| {
                    scan.get(&entry.path)
                        .is_none_or(|s| s.kind != entry.kind || s.content != entry.content)
                })
                || scan
                    .get(&intent.baseline_entry.path)
                    .is_none_or(|s| s.physical_identity != intent.file_identity)
            {
                return Err(ReconcileError::Invariant(
                    "delete baseline changed; all files and pins preserved",
                ));
            }
            Ok(())
        }

        pub(super) fn execute_delete_platform(&mut self, id: &EntryId) -> Result<()> {
            let mut mutation = self.journal.mutation(id)?;
            self.journal.verify_mutation_references(id)?;
            let intent = mutation.intent.clone();
            let content = intent
                .baseline_entry
                .content
                .as_ref()
                .ok_or(ReconcileError::Invariant("missing delete content"))?;
            self.check_publication_limits(content)?;
            self.cas.verify(content)?;
            let parent = self.parent_for(&intent.baseline_entry.path)?;
            let _parents = directory_chain(&parent)?;
            if physical_identity(&self.worktree)? != intent.root_identity
                || physical_identity(&parent)? != intent.parent_identity
            {
                return Err(ReconcileError::Invariant(
                    "delete root/source parent identity changed",
                ));
            }
            let source = self.worktree.join(intent.baseline_entry.path.as_str());
            checkpoint("before_delete_lock");
            let mut held = None;
            let mut admission_guards = Vec::new();
            let mut admission_owner = None;
            if mutation.state == MutationState::Prepared {
                let file = LockedFile::open(&source)?;
                if identity(&file)? != intent.file_identity || !content_matches(&file, content)? {
                    return Err(ReconcileError::Invariant(
                        "delete source identity/content changed",
                    ));
                }
                checkpoint("after_delete_lock");
                self.validate_delete_baseline(&mutation)?;
                let base = parent.join(".sync-tmp");
                if !base.try_exists()? {
                    fs::create_dir(&base)?;
                }
                admission_guards.extend(directory_chain(&base)?);
                let execution_id = EntryId::random()?;
                let directory = base.join(execution_id.as_str());
                fs::create_dir(&directory)?;
                admission_guards.extend(directory_chain(&directory)?);
                let owner_path = directory.join("owner");
                let mut owner = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&owner_path)?;
                write!(owner, "{}:{}", id, execution_id)?;
                owner.sync_all()?;
                drop(owner);
                sync_directory(&directory)?;
                sync_directory(&base)?;
                let execution = DeleteExecution {
                    execution_id,
                    directory_identity: physical_identity(&directory)?,
                    owner_identity: physical_identity(&owner_path)?,
                };
                mutation.execution = Some(execution.clone());
                admission_owner = Some(validate_directory(&directory, &mutation)?);
                checkpoint("before_delete_execution");
                self.journal.start_delete(&self.space_id, id, &execution)?;
                mutation = self.journal.mutation(id)?;
                held = Some(file);
                checkpoint("after_delete_execution");
            }
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("missing delete execution"))?;
            let directory = parent
                .join(".sync-tmp")
                .join(execution.execution_id.as_str());
            let quarantine_guards = directory_chain(&directory)?;
            let _owner = match admission_owner {
                Some(owner) => owner,
                None => validate_directory(&directory, &mutation)?,
            };
            let quarantine = directory.join("original");
            let file = if quarantine.try_exists()? {
                // A native occupant is not owned merely because it has equal bytes.
                LockedFile::open(&quarantine)?
            } else {
                if mutation.state != MutationState::Executing {
                    return Err(ReconcileError::Invariant(
                        "quarantined original missing; intent preserved",
                    ));
                }
                let file = match held {
                    Some(file) => file,
                    None => LockedFile::open(&source)?,
                };
                if identity(&file)? != intent.file_identity || !content_matches(&file, content)? {
                    return Err(ReconcileError::Invariant("executing delete source changed"));
                }
                self.validate_delete_baseline(&mutation)?;
                if file.key()?.volume
                    != quarantine_guards
                        .last()
                        .ok_or(ReconcileError::Invariant("missing quarantine guard"))?
                        .key()?
                        .volume
                {
                    return Err(ReconcileError::Invariant(
                        "delete quarantine crossed volume",
                    ));
                }
                checkpoint("before_delete_rename");
                file.rename_no_replace(&quarantine)?;
                sync_directory(&parent)?;
                sync_directory(&directory)?;
                checkpoint("after_delete_rename");
                file
            };
            if identity(&file)? != intent.file_identity
                || physical_identity(&quarantine)? != intent.file_identity
                || !content_matches(&file, content)?
            {
                return Err(ReconcileError::Invariant(
                    "quarantined original identity/content mismatch",
                ));
            }
            if mutation.state == MutationState::Executing {
                self.journal.mark_delete_quarantined(&self.space_id, id)?;
                checkpoint("after_delete_quarantined");
            }
            let mut manifest = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            let timestamp = now_ms()?;
            let operation = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space_id.clone(),
                origin_device_id: self.device_id.clone(),
                origin_seq: manifest
                    .version_vector
                    .get(&self.device_id)
                    .checked_add(1)
                    .ok_or(ReconcileError::Invariant("sequence exhausted"))?,
                causal: manifest.version_vector.clone(),
                change: Change::Delete {
                    entry_id: intent.baseline_entry.entry_id.clone(),
                },
                created_at_ms: timestamp,
            })?;
            manifest.entries.remove(&intent.baseline_entry.entry_id);
            manifest
                .tombstones
                .insert(intent.baseline_entry.entry_id, operation.op_id.clone());
            manifest
                .version_vector
                .observe(self.device_id.clone(), operation.payload.origin_seq);
            checkpoint("before_delete_commit");
            if !content_matches(&file, content)? {
                return Err(ReconcileError::Invariant(
                    "quarantined original changed before completion",
                ));
            }
            self.journal
                .commit_delete(id, &manifest, &operation, timestamp)?;
            checkpoint("after_delete_commit");
            Ok(())
        }
    }
}
