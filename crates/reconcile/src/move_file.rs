use crate::LocalSpace;
#[cfg(not(windows))]
use crate::Result;
use sync_extend_core_model::EntryId;

impl LocalSpace {
    #[cfg(not(windows))]
    pub(crate) fn execute_move_platform(&mut self, _id: &EntryId) -> Result<()> {
        Err(crate::ReconcileError::Invariant(
            "Move executor requires Windows fixed local NTFS",
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
    use sync_extend_cas::sync_directory;
    use sync_extend_core_model::*;
    use sync_extend_journal::{MutationAction, MutationState};
    use sync_extend_platform_fs::LockedFile;

    impl LocalSpace {
        pub(crate) fn execute_move_platform(&mut self, id: &EntryId) -> Result<()> {
            let mut mutation = self.journal.mutation(id)?;
            self.journal.verify_mutation_references(id)?;
            let intent = mutation.intent.clone();
            let MutationAction::Move {
                destination,
                parent_identity,
            } = &intent.action
            else {
                return Err(ReconcileError::Invariant(
                    "Move executor requires Move action",
                ));
            };
            let mut moved_baseline = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            moved_baseline
                .entries
                .get_mut(&intent.baseline_entry.entry_id)
                .ok_or(ReconcileError::Invariant("missing Move baseline entry"))?
                .path = destination.clone();
            moved_baseline.validate()?;
            let content = intent
                .baseline_entry
                .content
                .as_ref()
                .ok_or(ReconcileError::Invariant("missing Move content"))?;
            self.check_publication_limits(content)?;
            self.cas.verify(content)?;
            let parent = self.parent_for(&intent.baseline_entry.path)?;
            let destination_parent = self.parent_for(destination)?;
            let source_guards = directory_chain(&parent)?;
            let destination_guards = directory_chain(&destination_parent)?;
            let source_parent_guard = source_guards
                .last()
                .ok_or(ReconcileError::Invariant("missing source parent guard"))?;
            let destination_parent_guard = destination_guards.last().ok_or(
                ReconcileError::Invariant("missing destination parent guard"),
            )?;
            source_parent_guard.require_case_insensitive()?;
            destination_parent_guard.require_case_insensitive()?;
            if source_parent_guard.key()?.volume != destination_parent_guard.key()?.volume {
                return Err(ReconcileError::Invariant(
                    "cross-volume Move is unsupported",
                ));
            }
            if physical_identity(&self.worktree)? != intent.root_identity
                || physical_identity(&parent)? != intent.parent_identity
                || physical_identity(&destination_parent)? != *parent_identity
            {
                return Err(ReconcileError::Invariant(
                    "Move root/source/destination parent identity changed",
                ));
            }
            let source = self.worktree.join(intent.baseline_entry.path.as_str());
            let target = self.worktree.join(destination.as_str());
            checkpoint("before_move_lock");
            let mut held = None;
            let mut admission = None;
            if mutation.state == MutationState::Prepared {
                let file = LockedFile::open(&source)?;
                if identity(&file)? != intent.file_identity
                    || !content_matches(&file, content)?
                    || file.key()?.volume != destination_parent_guard.key()?.volume
                {
                    return Err(ReconcileError::Invariant(
                        "Move source identity/content/volume changed",
                    ));
                }
                checkpoint("after_move_lock");
                self.validate_mutation_baseline(&mutation)?;
                if self.occupied(destination)? {
                    return Err(ReconcileError::Invariant(
                        "Move destination occupied before admission",
                    ));
                }
                let transaction = allocate_directory(&parent, &mutation)?;
                checkpoint("before_move_execution");
                self.journal
                    .start_move(&self.space_id, id, &transaction.execution)?;
                admission = Some(transaction);
                held = Some(file);
                mutation = self.journal.mutation(id)?;
                checkpoint("after_move_execution");
            }
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("missing Move execution"))?;
            let directory = parent
                .join(".sync-tmp")
                .join(execution.execution_id.as_str());
            let _transaction_guards = directory_chain(&directory)?;
            let _owner = if admission.is_none() {
                Some(validate_directory(&directory, &mutation)?)
            } else {
                None
            };
            let file = if self.occupied(destination)? {
                // Equal bytes and source absence are never proof that we moved it.
                LockedFile::open(&target)?
            } else {
                if mutation.state != MutationState::Executing {
                    return Err(ReconcileError::Invariant(
                        "moved original missing; active intent preserved",
                    ));
                }
                let file = match held {
                    Some(file) => file,
                    None => LockedFile::open(&source)?,
                };
                if identity(&file)? != intent.file_identity || !content_matches(&file, content)? {
                    return Err(ReconcileError::Invariant("executing Move source changed"));
                }
                self.validate_mutation_baseline(&mutation)?;
                source_parent_guard.require_case_insensitive()?;
                destination_parent_guard.require_case_insensitive()?;
                if self.occupied(destination)? {
                    return Err(ReconcileError::Invariant(
                        "Move destination became occupied",
                    ));
                }
                checkpoint("before_move_rename");
                file.rename_no_replace(&target)?;
                sync_directory(&parent)?;
                sync_directory(&destination_parent)?;
                checkpoint("after_move_rename");
                file
            };
            if identity(&file)? != intent.file_identity
                || physical_identity(&target)? != intent.file_identity
                || !content_matches(&file, content)?
            {
                return Err(ReconcileError::Invariant(
                    "moved original identity/content mismatch",
                ));
            }
            if mutation.state == MutationState::Executing {
                self.journal.mark_move_moved(&self.space_id, id)?;
                checkpoint("after_move_moved");
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
                change: Change::Rename {
                    entry_id: intent.baseline_entry.entry_id.clone(),
                    path: destination.clone(),
                },
                created_at_ms: timestamp,
            })?;
            manifest
                .entries
                .get_mut(&intent.baseline_entry.entry_id)
                .ok_or(ReconcileError::Invariant("missing Move baseline entry"))?
                .path = destination.clone();
            manifest
                .version_vector
                .observe(self.device_id.clone(), operation.payload.origin_seq);
            checkpoint("before_move_commit");
            if !content_matches(&file, content)? {
                return Err(ReconcileError::Invariant(
                    "moved original changed before completion",
                ));
            }
            self.journal
                .commit_move(id, &manifest, &operation, timestamp)?;
            checkpoint("after_move_commit");
            Ok(())
        }
    }
}
