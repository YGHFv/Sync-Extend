use crate::LocalSpace;
#[cfg(not(windows))]
use crate::Result;
use sync_extend_core_model::EntryId;

impl LocalSpace {
    #[cfg(not(windows))]
    pub(crate) fn execute_replace_platform(&mut self, _id: &EntryId) -> Result<()> {
        Err(crate::ReconcileError::Invariant(
            "Replace executor requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        fault::checkpoint,
        filesystem::physical_identity,
        guarded_mutation::{
            allocate_directory, content_matches, directory_chain, identity, validate_directory,
        },
        now_ms, ReconcileError, Result,
    };
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use sync_extend_cas::sync_directory;
    use sync_extend_core_model::*;
    use sync_extend_journal::{MutationAction, MutationState};
    use sync_extend_platform_fs::{FileKey, LockedFile};

    impl LocalSpace {
        pub(crate) fn execute_replace_platform(&mut self, id: &EntryId) -> Result<()> {
            let mut mutation = self.journal.mutation(id)?;
            self.journal.verify_mutation_references(id)?;
            let intent = mutation.intent.clone();
            let MutationAction::Replace { content } = &intent.action else {
                return Err(ReconcileError::Invariant("Replace action required"));
            };
            let original_content =
                intent
                    .baseline_entry
                    .content
                    .as_ref()
                    .ok_or(ReconcileError::Invariant(
                        "missing Replace baseline content",
                    ))?;
            self.check_publication_limits(original_content)?;
            self.check_publication_limits(content)?;
            if original_content
                .length
                .checked_add(content.length)
                .is_none_or(|bytes| bytes > self.limits.max_staging_bytes)
            {
                return Err(ReconcileError::ResourceLimit(
                    "Replace retained/staging bytes",
                ));
            }
            self.cas.verify(original_content)?;
            self.cas.verify(content)?;
            let parent = self.parent_for(&intent.baseline_entry.path)?;
            let parents = directory_chain(&parent)?;
            let parent_guard = parents
                .last()
                .ok_or(ReconcileError::Invariant("missing Replace parent guard"))?;
            parent_guard.require_case_insensitive()?;
            if physical_identity(&self.worktree)? != intent.root_identity
                || physical_identity(&parent)? != intent.parent_identity
            {
                return Err(ReconcileError::Invariant(
                    "Replace root/source parent changed",
                ));
            }
            let source = self.worktree.join(intent.baseline_entry.path.as_str());
            let mut held_source = None;
            let mut held_payload = None;
            let mut admission = None;
            checkpoint("before_replace_lock");
            if mutation.state == MutationState::Prepared {
                let file = LockedFile::open(&source)?;
                if identity(&file)? != intent.file_identity
                    || !content_matches(&file, original_content)?
                {
                    return Err(ReconcileError::Invariant(
                        "Replace source identity/content changed",
                    ));
                }
                checkpoint("after_replace_lock");
                self.validate_mutation_baseline(&mutation)?;
                let mut transaction = allocate_directory(&parent, &mutation)?;
                transaction
                    ._guards
                    .last()
                    .ok_or(ReconcileError::Invariant("missing Replace staging guard"))?
                    .require_case_insensitive()?;
                let payload_path = transaction.directory.join("payload");
                let mut writer = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .share_mode(0)
                    .open(&payload_path)?;
                let staged_id =
                    ContentId::hash(FileKey::from_file(&writer)?.to_string().as_bytes());
                checkpoint("before_replace_stage");
                self.cas.write_file(content, &mut writer)?;
                writer.sync_all()?;
                drop(writer);
                let payload = LockedFile::open(&payload_path)?;
                if identity(&payload)? != staged_id
                    || !content_matches(&payload, content)?
                    || payload.key()?.volume != file.key()?.volume
                {
                    return Err(ReconcileError::Invariant(
                        "Replace staged identity/content/volume changed",
                    ));
                }
                transaction.execution.payload_identity = Some(staged_id);
                sync_directory(&transaction.directory)?;
                checkpoint("after_replace_stage");
                self.validate_mutation_baseline(&mutation)?;
                checkpoint("before_replace_execution");
                self.journal
                    .start_replace(&self.space_id, id, &transaction.execution)?;
                admission = Some(transaction);
                held_source = Some(file);
                held_payload = Some(payload);
                mutation = self.journal.mutation(id)?;
                checkpoint("after_replace_execution");
            }
            let execution = mutation
                .execution
                .clone()
                .ok_or(ReconcileError::Invariant("missing Replace execution"))?;
            let payload_id =
                execution
                    .payload_identity
                    .clone()
                    .ok_or(ReconcileError::Invariant(
                        "missing Replace payload identity",
                    ))?;
            let directory = parent
                .join(".sync-tmp")
                .join(execution.execution_id.as_str());
            let guards = directory_chain(&directory)?;
            let directory_guard = guards.last().ok_or(ReconcileError::Invariant(
                "missing Replace transaction guard",
            ))?;
            directory_guard.require_case_insensitive()?;
            let _owner = if admission.is_none() {
                Some(validate_directory(&directory, &mutation)?)
            } else {
                None
            };
            let quarantine = directory.join("original");
            let payload_path = directory.join("payload");
            let staged = payload_path.try_exists()?;
            if mutation.state == MutationState::Replaced && staged {
                return Err(ReconcileError::Invariant(
                    "Replaced payload returned to staging",
                ));
            }
            // Physical identity, not equal bytes, establishes publication ownership.
            let payload = if staged {
                match held_payload {
                    Some(file) => file,
                    None => LockedFile::open(&payload_path)?,
                }
            } else {
                if !quarantine.try_exists()? {
                    return Err(ReconcileError::Invariant("Replace staged payload missing"));
                }
                LockedFile::open(&source)?
            };
            if identity(&payload)? != payload_id
                || !content_matches(&payload, content)?
                || payload.key()?.volume != directory_guard.key()?.volume
            {
                return Err(ReconcileError::Invariant(
                    "Replace payload identity/content/volume mismatch",
                ));
            }
            let original = if quarantine.try_exists()? {
                LockedFile::open(&quarantine)?
            } else {
                if mutation.state != MutationState::Executing || !staged {
                    return Err(ReconcileError::Invariant(
                        "Replace retained original missing",
                    ));
                }
                let file = match held_source {
                    Some(file) => file,
                    None => LockedFile::open(&source)?,
                };
                if identity(&file)? != intent.file_identity
                    || !content_matches(&file, original_content)?
                    || file.key()?.volume != directory_guard.key()?.volume
                {
                    return Err(ReconcileError::Invariant(
                        "executing Replace source changed",
                    ));
                }
                self.validate_mutation_baseline(&mutation)?;
                parent_guard.require_case_insensitive()?;
                checkpoint("before_replace_quarantine");
                file.rename_no_replace(&quarantine)?;
                sync_directory(&parent)?;
                sync_directory(&directory)?;
                checkpoint("after_replace_quarantine");
                file
            };
            if identity(&original)? != intent.file_identity
                || physical_identity(&quarantine)? != intent.file_identity
                || !content_matches(&original, original_content)?
            {
                return Err(ReconcileError::Invariant(
                    "Replace quarantined original mismatch",
                ));
            }
            if mutation.state == MutationState::Executing {
                self.journal.mark_replace_quarantined(&self.space_id, id)?;
                mutation = self.journal.mutation(id)?;
                checkpoint("after_replace_quarantined");
            }
            if staged {
                if mutation.state != MutationState::Quarantined
                    || self.occupied(&intent.baseline_entry.path)?
                {
                    return Err(ReconcileError::Invariant(
                        "Replace source occupied; original/payload/pins retained, no overwrite",
                    ));
                }
                parent_guard.require_case_insensitive()?;
                checkpoint("before_replace_publish");
                payload.rename_no_replace(&source)?;
                sync_directory(&directory)?;
                sync_directory(&parent)?;
                checkpoint("after_replace_publish");
            }
            if physical_identity(&source)? != payload_id || !content_matches(&payload, content)? {
                return Err(ReconcileError::Invariant(
                    "Replace published payload mismatch",
                ));
            }
            if mutation.state == MutationState::Quarantined {
                self.journal.mark_replace_replaced(&self.space_id, id)?;
                checkpoint("after_replace_replaced");
            }
            let mut manifest = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            let mut entry = intent.baseline_entry.clone();
            entry.content = Some(content.clone());
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
                change: Change::Put {
                    entry: entry.clone(),
                },
                created_at_ms: timestamp,
            })?;
            manifest.entries.insert(entry.entry_id.clone(), entry);
            manifest
                .version_vector
                .observe(self.device_id.clone(), operation.payload.origin_seq);
            checkpoint("before_replace_commit");
            if !content_matches(&payload, content)?
                || !content_matches(&original, original_content)?
            {
                return Err(ReconcileError::Invariant(
                    "Replace owned content changed before completion",
                ));
            }
            self.journal
                .commit_replace(id, &manifest, &operation, timestamp)?;
            checkpoint("after_replace_commit");
            Ok(())
        }
    }
}
