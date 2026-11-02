use crate::{LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::*;
use sync_extend_journal::{MutationAction, MutationState};

#[derive(Serialize)]
pub struct MutationResult {
    pub transaction_id: EntryId,
    pub snapshot_id: SnapshotId,
    pub original_retained_at_commit: bool,
    pub local_committed: bool,
    pub remote_backup_complete: bool,
    pub action: &'static str,
    pub source_path: PortablePath,
    pub moved_path: Option<PortablePath>,
}

pub type DeleteResult = MutationResult;

impl LocalSpace {
    pub fn execute_mutation(&mut self, id: &EntryId) -> Result<MutationResult> {
        self.verify_root()?;
        let mutation = self.journal.mutation(id)?;
        if mutation.intent.space_id != self.space_id
            || matches!(mutation.intent.action, MutationAction::Replace { .. })
        {
            return Err(ReconcileError::Invariant(
                "only this space's single-file Delete/Move has an executor",
            ));
        }
        if mutation.state == MutationState::Cancelled {
            return Err(ReconcileError::Invariant(
                "cancelled mutation cannot execute",
            ));
        }
        if mutation.state != MutationState::Committed {
            match mutation.intent.action {
                MutationAction::Delete => self.execute_delete_platform(id)?,
                MutationAction::Move { .. } => self.execute_move_platform(id)?,
                MutationAction::Replace { .. } => unreachable!(),
            }
        }
        let mutation = self.journal.mutation(id)?;
        self.journal.verify_mutation_references(id)?;
        Ok(MutationResult {
            transaction_id: id.clone(),
            snapshot_id: mutation
                .committed_snapshot
                .ok_or(ReconcileError::Invariant("mutation is not committed"))?,
            original_retained_at_commit: mutation.intent.action == MutationAction::Delete,
            local_committed: true,
            remote_backup_complete: false,
            action: if mutation.intent.action == MutationAction::Delete {
                "delete"
            } else {
                "move"
            },
            source_path: mutation.intent.baseline_entry.path,
            moved_path: match mutation.intent.action {
                MutationAction::Move { destination, .. } => Some(destination),
                _ => None,
            },
        })
    }

    pub fn recover_mutations(&mut self) -> Result<Vec<MutationResult>> {
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
    use crate::guarded_mutation::{
        allocate_directory, content_matches, directory_chain, identity, validate_directory,
    };
    use crate::{fault::checkpoint, filesystem::physical_identity, now_ms};
    use sync_extend_cas::sync_directory;
    use sync_extend_platform_fs::LockedFile;

    impl LocalSpace {
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
            let mut admission = None;
            if mutation.state == MutationState::Prepared {
                let file = LockedFile::open(&source)?;
                if identity(&file)? != intent.file_identity || !content_matches(&file, content)? {
                    return Err(ReconcileError::Invariant(
                        "delete source identity/content changed",
                    ));
                }
                checkpoint("after_delete_lock");
                self.validate_mutation_baseline(&mutation)?;
                let transaction = allocate_directory(&parent, &mutation)?;
                checkpoint("before_delete_execution");
                self.journal
                    .start_delete(&self.space_id, id, &transaction.execution)?;
                admission = Some(transaction);
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
            let _owner = if admission.is_none() {
                Some(validate_directory(&directory, &mutation)?)
            } else {
                None
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
                self.validate_mutation_baseline(&mutation)?;
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
