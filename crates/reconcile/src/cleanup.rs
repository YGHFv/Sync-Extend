use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_core_model::EntryId;
use sync_extend_journal::{CleanupPlan, CleanupState};

impl LocalSpace {
    pub fn cleanup_plans(&self) -> Result<Vec<CleanupPlan>> {
        self.verify_root()?;
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        Ok(self.journal.cleanup_plans(&self.space_id)?)
    }

    pub fn prepare_cleanup(&mut self, id: &EntryId) -> Result<CleanupPlan> {
        self.verify_root()?;
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        if let Some(plan) = self.journal.cleanup_plan(id)? {
            if plan.intent.space_id != self.space_id {
                return Err(ReconcileError::Invariant(
                    "cleanup belongs to another space",
                ));
            }
            return Ok(plan);
        }
        self.prepare_cleanup_platform(id)
    }

    pub fn cancel_cleanup(&mut self, id: &EntryId) -> Result<()> {
        self.verify_root()?;
        self.journal.cancel_cleanup(&self.space_id, id)?;
        Ok(())
    }

    pub fn execute_cleanup(&mut self, id: &EntryId) -> Result<CleanupPlan> {
        self.verify_root()?;
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        let plan = self
            .journal
            .cleanup_plan(id)?
            .ok_or(ReconcileError::Invariant(
                "cleanup requires explicit preparation",
            ))?;
        if plan.intent.space_id != self.space_id || plan.state == CleanupState::Cancelled {
            return Err(ReconcileError::Invariant(
                "cleanup is cancelled or belongs to another space",
            ));
        }
        if plan.state != CleanupState::Cleaned {
            self.execute_cleanup_platform(&plan)?;
        }
        self.journal
            .cleanup_plan(id)?
            .ok_or(ReconcileError::Invariant("cleanup plan disappeared"))
    }

    pub fn recover_cleanups(&mut self) -> Result<Vec<CleanupPlan>> {
        self.cleanup_plans()?
            .into_iter()
            .filter(|plan| plan.state == CleanupState::Executing)
            .map(|plan| self.execute_cleanup(&plan.intent.transaction_id))
            .collect()
    }

    #[cfg(not(windows))]
    fn prepare_cleanup_platform(&mut self, _id: &EntryId) -> Result<CleanupPlan> {
        Err(ReconcileError::Invariant(
            "marker cleanup requires Windows fixed local NTFS",
        ))
    }

    #[cfg(not(windows))]
    fn execute_cleanup_platform(&mut self, _plan: &CleanupPlan) -> Result<()> {
        Err(ReconcileError::Invariant(
            "marker cleanup requires Windows fixed local NTFS",
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
        guarded_mutation::{directory_chain, validate_directory},
        now_ms,
    };
    use std::{fs, path::PathBuf};
    use sync_extend_core_model::{ContentId, FORMAT_VERSION};
    use sync_extend_journal::{CleanupIntent, Mutation, MutationAction, MutationState};
    use sync_extend_platform_fs::LockedDirectory;

    struct Boundary {
        parent: PathBuf,
        base: PathBuf,
        directory: PathBuf,
        _guards: Vec<LockedDirectory>,
    }

    impl Boundary {
        fn verify(&self, local: &LocalSpace, mutation: &Mutation, base: &ContentId) -> Result<()> {
            for guard in self._guards.iter().rev().take(3) {
                guard.require_case_insensitive()?;
            }
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("cleanup execution missing"))?;
            if physical_identity(&local.worktree)? != mutation.intent.root_identity
                || physical_identity(&self.parent)? != mutation.intent.parent_identity
                || physical_identity(&self.base)? != *base
                || physical_identity(&self.directory)? != execution.directory_identity
            {
                return Err(ReconcileError::Invariant(
                    "cleanup physical boundary changed",
                ));
            }
            Ok(())
        }

        fn owner_present(&self) -> Result<bool> {
            let mut owner = false;
            for entry in fs::read_dir(&self.directory)? {
                let entry = entry?;
                if entry.file_name() != "owner" {
                    return Err(ReconcileError::Invariant(
                        "unknown cleanup directory occupant",
                    ));
                }
                check_ancestors(&entry.path())?;
                owner = true;
            }
            Ok(owner)
        }
    }

    impl LocalSpace {
        fn cleanup_boundary(&self, mutation: &Mutation) -> Result<Boundary> {
            if mutation.intent.space_id != self.space_id
                || mutation.state != MutationState::Committed
                || !matches!(mutation.intent.action, MutationAction::Move { .. })
            {
                return Err(ReconcileError::Invariant(
                    "cleanup requires a committed Move",
                ));
            }
            self.journal
                .verify_mutation_references(&mutation.intent.transaction_id)?;
            let execution = mutation
                .execution
                .as_ref()
                .ok_or(ReconcileError::Invariant("cleanup execution missing"))?;
            let parent = self.parent_for(&mutation.intent.baseline_entry.path)?;
            let base = parent.join(".sync-tmp");
            let directory = base.join(execution.execution_id.as_str());
            let guards = directory_chain(&directory)?;
            Ok(Boundary {
                parent,
                base,
                directory,
                _guards: guards,
            })
        }

        pub(super) fn prepare_cleanup_platform(&mut self, id: &EntryId) -> Result<CleanupPlan> {
            let mutation = self.journal.mutation(id)?;
            let boundary = self.cleanup_boundary(&mutation)?;
            let base_identity = physical_identity(&boundary.base)?;
            boundary.verify(self, &mutation, &base_identity)?;
            let _owner = validate_directory(&boundary.directory, &mutation)?;
            if !boundary.owner_present()? {
                return Err(ReconcileError::Invariant(
                    "cleanup owner missing before preparation",
                ));
            }
            let intent = CleanupIntent {
                format_version: FORMAT_VERSION,
                transaction_id: id.clone(),
                space_id: self.space_id.clone(),
                execution: mutation
                    .execution
                    .clone()
                    .ok_or(ReconcileError::Invariant("cleanup execution missing"))?,
                base_identity,
                created_at_ms: now_ms()?.max(mutation.intent.created_at_ms),
            };
            checkpoint("before_cleanup_intent");
            boundary.verify(self, &mutation, &intent.base_identity)?;
            boundary.owner_present()?;
            let plan = self.journal.prepare_cleanup(&intent)?;
            checkpoint("after_cleanup_intent");
            Ok(plan)
        }

        pub(super) fn execute_cleanup_platform(&mut self, plan: &CleanupPlan) -> Result<()> {
            let id = &plan.intent.transaction_id;
            let mutation = self.journal.mutation(id)?;
            let boundary = self.cleanup_boundary(&mutation)?;
            boundary.verify(self, &mutation, &plan.intent.base_identity)?;
            checkpoint("before_cleanup_lock");
            let owner = if boundary.owner_present()? {
                Some(validate_directory(&boundary.directory, &mutation)?)
            } else if plan.state == CleanupState::Executing {
                None
            } else {
                return Err(ReconcileError::Invariant("prepared cleanup owner missing"));
            };
            checkpoint("after_cleanup_lock");
            boundary.verify(self, &mutation, &plan.intent.base_identity)?;
            boundary.owner_present()?;
            if plan.state == CleanupState::Prepared {
                checkpoint("before_cleanup_authorization");
                boundary.verify(self, &mutation, &plan.intent.base_identity)?;
                boundary.owner_present()?;
                self.journal.start_cleanup(
                    &self.space_id,
                    id,
                    now_ms()?.max(plan.intent.created_at_ms),
                )?;
                checkpoint("after_cleanup_authorization");
            }
            if let Some(owner) = owner {
                checkpoint("before_cleanup_disposition");
                boundary.verify(self, &mutation, &plan.intent.base_identity)?;
                boundary.owner_present()?;
                owner.delete_on_close()?;
                checkpoint("after_cleanup_disposition");
                drop(owner);
                checkpoint("after_cleanup_owner_close");
            }
            // Absence only completes an authorized plan under the same held
            // directory boundary. Missing/replaced directories are never adopted.
            boundary.verify(self, &mutation, &plan.intent.base_identity)?;
            if boundary.owner_present()? {
                return Err(ReconcileError::Invariant(
                    "cleanup owner still present; retry after readers close",
                ));
            }
            checkpoint("before_cleanup_finish");
            boundary.verify(self, &mutation, &plan.intent.base_identity)?;
            if boundary.owner_present()? {
                return Err(ReconcileError::Invariant("cleanup owner reappeared"));
            }
            let authorized = self
                .journal
                .cleanup_plan(id)?
                .and_then(|plan| plan.authorized_at_ms)
                .ok_or(ReconcileError::Invariant("cleanup authorization missing"))?;
            self.journal
                .finish_cleanup(&self.space_id, id, now_ms()?.max(authorized))?;
            checkpoint("after_cleanup_finish");
            Ok(())
        }
    }
}
