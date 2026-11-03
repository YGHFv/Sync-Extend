use crate::{LocalSpace, Result};
use sync_extend_core_model::EntryId;
use sync_extend_journal::OriginalDisposalAudit;

impl LocalSpace {
    pub fn original_disposals(&self) -> Result<Vec<OriginalDisposalAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .original_disposals(&self.space_id, self.limits.max_storage_entries)?)
    }

    /// Explicit preparation only. The original and ownership directories remain.
    pub fn prepare_original_disposal(&self, id: &EntryId) -> Result<OriginalDisposalAudit> {
        self.verify_root()?;
        if let Some(old) = self
            .original_disposals()?
            .into_iter()
            .find(|a| a.intent.scope.transaction_id == *id)
        {
            return Ok(old);
        }
        self.prepare_original_disposal_platform(id)
    }

    #[cfg(not(windows))]
    fn prepare_original_disposal_platform(&self, _id: &EntryId) -> Result<OriginalDisposalAudit> {
        Err(crate::ReconcileError::Invariant(
            "original preparation requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        check_ancestors,
        fault::checkpoint,
        filesystem::physical_identity,
        guarded_mutation::{content_matches, directory_chain, identity, validate_directory},
        now_ms, ReconcileError,
    };
    use std::{fs, io::Read, path::PathBuf, time::UNIX_EPOCH};
    use sync_extend_core_model::{
        original_retention::{OriginalRetentionScope, RetainedOriginalAction},
        ContentId, FORMAT_VERSION,
    };
    use sync_extend_journal::{Mutation, MutationAction, MutationState, OriginalDisposalIntent};
    use sync_extend_platform_fs::{
        verify_regular_file, GuardedReadFile, LockedDirectory, LockedFile,
    };

    struct Guards {
        _directories: Vec<LockedDirectory>,
        owner: GuardedReadFile,
        original: LockedFile,
        parent: PathBuf,
        base: PathBuf,
        directory: PathBuf,
    }

    fn modified_ns(file: &LockedFile) -> Result<u64> {
        file.reader()
            .metadata()?
            .modified()?
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|t| u64::try_from(t.as_nanos()).ok())
            .ok_or(ReconcileError::Invariant(
                "original timestamp is out of range",
            ))
    }

    impl Guards {
        fn verify(
            &self,
            local: &LocalSpace,
            mutation: &Mutation,
            intent: &OriginalDisposalIntent,
        ) -> Result<()> {
            local.verify_root()?;
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("original execution missing"))?;
            for d in &self._directories {
                d.require_case_insensitive()?;
            }
            if physical_identity(&local.worktree)? != mutation.intent.root_identity
                || physical_identity(&self.parent)? != mutation.intent.parent_identity
                || physical_identity(&self.base)? != intent.base_identity
                || physical_identity(&self.directory)? != execution.directory_identity
            {
                return Err(ReconcileError::Invariant("original namespace changed"));
            }
            let mut owner_found = false;
            let mut original_found = false;
            for entry in fs::read_dir(&self.directory)? {
                let entry = entry?;
                check_ancestors(&entry.path())?;
                if entry.file_name() == "owner" {
                    owner_found = true;
                } else if entry.file_name() == "original" {
                    original_found = true;
                } else {
                    return Err(ReconcileError::Invariant(
                        "unexpected original directory child",
                    ));
                }
            }
            let mut marker = Vec::new();
            let mut owner_reader = self.owner.reader();
            use std::io::{Seek, SeekFrom};
            owner_reader.seek(SeekFrom::Start(0))?;
            owner_reader.take(66).read_to_end(&mut marker)?;
            let owner_identity = ContentId::hash(self.owner.key()?.to_string().as_bytes());
            verify_regular_file(self.owner.reader())?;
            verify_regular_file(self.original.reader())?;
            if !owner_found
                || !original_found
                || owner_identity != execution.owner_identity
                || physical_identity(&self.directory.join("owner"))? != owner_identity
                || marker
                    != format!(
                        "{}:{}",
                        mutation.intent.transaction_id, execution.execution_id
                    )
                    .as_bytes()
                || identity(&self.original)? != intent.scope.original_identity
                || physical_identity(&self.directory.join("original"))?
                    != intent.scope.original_identity
                || self.original.reader().metadata()?.len() != intent.original_length
                || modified_ns(&self.original)? != intent.modified_at_ns
                || !content_matches(&self.original, &intent.scope.content)?
            {
                return Err(ReconcileError::Invariant("exact original or owner changed"));
            }
            Ok(())
        }
    }

    impl LocalSpace {
        pub(super) fn prepare_original_disposal_platform(
            &self,
            id: &EntryId,
        ) -> Result<OriginalDisposalAudit> {
            let _session = self.cas.acquire_session()?;
            let mutation = self.journal.mutation(id)?;
            if mutation.intent.space_id != self.space_id
                || mutation.state != MutationState::Committed
                || matches!(mutation.intent.action, MutationAction::Move { .. })
            {
                return Err(ReconcileError::Invariant(
                    "original preparation requires committed Delete/Replace",
                ));
            }
            self.journal.verify_mutation_references(id)?;
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("original execution missing"))?;
            let content = mutation
                .intent
                .baseline_entry
                .content
                .as_ref()
                .ok_or(ReconcileError::Invariant("original content missing"))?;
            if content.length > self.limits.max_file_bytes
                || content.chunks.len() > self.limits.max_storage_entries
            {
                return Err(ReconcileError::ResourceLimit(
                    "original preparation content budget",
                ));
            }
            self.storage_report()?;
            checkpoint("before_original_preparation_lock");
            let parent = self.parent_for(&mutation.intent.baseline_entry.path)?;
            let base = parent.join(".sync-tmp");
            let directory = base.join(execution.execution_id.as_str());
            let mut directories = directory_chain(&self.worktree)?;
            directories.extend(directory_chain(&directory)?);
            // Reuse the mutation ownership parser, then retain a read-only owner.
            let owner_check = validate_directory(&directory, &mutation)?;
            drop(owner_check);
            let guards = Guards {
                _directories: directories,
                owner: GuardedReadFile::open(&directory.join("owner"))?,
                original: LockedFile::open(&directory.join("original"))?,
                parent,
                base,
                directory,
            };
            let intent = OriginalDisposalIntent {
                plan_id: EntryId::random()?,
                scope: OriginalRetentionScope {
                    format_version: FORMAT_VERSION,
                    space_id: self.space_id.clone(),
                    transaction_id: id.clone(),
                    execution_id: execution.execution_id.clone(),
                    action: if matches!(mutation.intent.action, MutationAction::Delete) {
                        RetainedOriginalAction::Delete
                    } else {
                        RetainedOriginalAction::Replace
                    },
                    mutation_intent_hash: ContentId::hash(
                        serde_json::to_string(&mutation.intent)?.as_bytes(),
                    ),
                    execution_hash: ContentId::hash(serde_json::to_string(execution)?.as_bytes()),
                    baseline_snapshot: mutation.intent.baseline_root.clone(),
                    committed_snapshot: mutation
                        .committed_snapshot
                        .clone()
                        .ok_or(ReconcileError::Invariant("original completion missing"))?,
                    original_identity: mutation.intent.file_identity.clone(),
                    content: content.clone(),
                },
                base_identity: physical_identity(&guards.base)?,
                original_length: guards.original.reader().metadata()?.len(),
                modified_at_ns: modified_ns(&guards.original)?,
                prepared_at_ms: now_ms()?,
            };
            guards.verify(self, &mutation, &intent)?;
            checkpoint("after_original_preparation_lock");
            checkpoint("before_original_preparation_commit");
            let (retained, audit) = self.journal.prepare_original_disposal(
                &intent,
                self.limits.max_storage_entries,
                |intent| {
                    guards.verify(self, &mutation, intent)?;
                    self.cas.verify(&intent.scope.content)?;
                    checkpoint("after_original_preparation_content");
                    Ok::<_, ReconcileError>(guards)
                },
                |guards, intent| {
                    self.cas.verify(&intent.scope.content)?;
                    guards.verify(self, &mutation, intent)?;
                    checkpoint("after_original_preparation_recheck");
                    // A fault pause can expose unmanaged changes; verify once more.
                    self.cas.verify(&intent.scope.content)?;
                    guards.verify(self, &mutation, intent)?;
                    Ok(())
                },
            )?;
            checkpoint("after_original_preparation_commit");
            drop(retained);
            Ok(audit)
        }
    }
}
