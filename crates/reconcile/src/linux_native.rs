//! Normal single-file native publication and transaction-specific cleanup.
//! Immutable history/Final/THAWED receipts survive every cleanup invocation.
use crate::{LocalSpace, ReconcileError, Result};
use std::path::Path;
use sync_extend_core_model::{EntryId, Manifest, PortablePath};
use sync_extend_platform_fs::{
    LinuxCleanupAbsenceObservation, LinuxMetadataBudget, LinuxNamespaceCapability,
    LinuxOutsideCleanupBoundary, OriginalPairTerminalRelease, OutsideHelperSession,
};

impl LocalSpace {
    pub fn original_linux_native_finals(
        &self,
    ) -> Result<Vec<sync_extend_journal::OriginalLinuxNativeFinalDiagnostic>> {
        self.verify_root()?;
        Ok(self.journal.original_linux_native_final_diagnostics()?)
    }

    pub fn publish_original_linux_native_file(
        &mut self,
        source: &Path,
        path: PortablePath,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
        helpers: &mut Option<OutsideHelperSession>,
        prepare_helpers: impl FnOnce() -> Result<OutsideHelperSession>,
    ) -> Result<(crate::PublishResult, OriginalPairTerminalRelease)> {
        self.validate_original_native_publisher(owner, budget, helpers)?;
        self.scan_without_recovery()?;
        let plan = self.plan_local_file_native_history(source, path)?;
        plan.publish_original_linux_native(owner, budget, helpers, prepare_helpers)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_original_linux_native_upload(
        &mut self,
        baseline: &Manifest,
        source: &std::fs::File,
        path: PortablePath,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
        helpers: &mut Option<OutsideHelperSession>,
        prepare_helpers: impl FnOnce() -> Result<OutsideHelperSession>,
    ) -> Result<(crate::PublishResult, OriginalPairTerminalRelease)> {
        self.validate_original_native_publisher(owner, budget, helpers)?;
        self.scan_without_recovery()?;
        let plan = self.plan_local_native_upload_history(baseline, path, source)?;
        plan.publish_original_linux_native(owner, budget, helpers, prepare_helpers)
    }

    fn validate_original_native_publisher(
        &self,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
        helpers: &Option<OutsideHelperSession>,
    ) -> Result<()> {
        self.verify_root()?;
        budget.validate_namespace_owner(owner)?;
        let original = self
            .linux_namespace
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "normal Linux namespace owner absent",
            ))?;
        if !std::ptr::eq(original.as_ref(), owner) {
            return Err(ReconcileError::Invariant(
                "native publisher did not retain this original namespace",
            ));
        }
        if helpers.is_some() {
            return Err(ReconcileError::Invariant(
                "native full planning requires helpers not yet started",
            ));
        }
        self.require_no_mutation()?;
        if !self
            .journal
            .outstanding_publications(&self.space_id)?
            .is_empty()
        {
            return Err(ReconcileError::Invariant(
                "native planning cannot recover a legacy worktree publication before ARM",
            ));
        }
        Ok(())
    }

    pub fn cleanup_original_linux_native(
        &mut self,
        owner: &LinuxNamespaceCapability,
        attempt: &EntryId,
    ) -> Result<serde_json::Value> {
        self.verify_root()?;
        self.require_no_mutation()?;
        let budget = self
            .linux_metadata
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "cleanup original metadata holder absent",
            ))?;
        let mut permit = self
            .journal
            .acquire_original_linux_cleanup(owner, budget, attempt)?;
        let was_prepared = permit.cleanup_was_prepared();
        let already_completed = permit.cleanup_was_completed();
        let outside = match LinuxOutsideCleanupBoundary::acquire(
            owner,
            permit.original_intent_parent(),
            permit.original_intent_component(),
            permit.original_intent_parent_key(),
            permit.original_intent_file_key(),
            permit.exact_original_intent_bytes(),
        ) {
            Ok(boundary) => Some(boundary),
            Err(error) if error.raw_os_error() == Some(2) && was_prepared => None,
            Err(error) => return Err(error.into()),
        };
        if already_completed && outside.is_some() {
            return Err(ReconcileError::Invariant(
                "completed original outside intent reappeared",
            ));
        }
        let retained_directory = permit.retained_directory().map(Path::to_path_buf);
        let mut prior_payload = Vec::new();
        if let Some(content) = permit.retained_content() {
            self.cas.verify(content)?;
            self.cas.write_file(content, &mut prior_payload)?;
        }
        let retained = if let Some(directory) = &retained_directory {
            match LinuxOutsideCleanupBoundary::acquire_retained(
                owner,
                directory,
                "original",
                permit
                    .retained_directory_key()
                    .ok_or(ReconcileError::Invariant(
                        "retained directory identity absent",
                    ))?,
                permit
                    .retained_file_key()
                    .ok_or(ReconcileError::Invariant("retained file identity absent"))?,
                &prior_payload,
            ) {
                Ok(boundary) => Some(boundary),
                Err(error) if error.raw_os_error() == Some(2) && was_prepared => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        if already_completed && retained.is_some() {
            return Err(ReconcileError::Invariant(
                "completed retained original reappeared",
            ));
        }
        // Complete the retained transaction-directory identity/content check
        // before the first journal append or outside unlink.  A restart may
        // legitimately find the transaction directory already absent; that
        // ENOENT is sealed against the original container and carried forward
        // as the later child-absence observation.
        let mut directory_absent_pre = None;
        let mut child_absent_pre = None;
        if let Some(directory) = &retained_directory {
            let directory_key = permit
                .retained_directory_key()
                .ok_or(ReconcileError::Invariant("retained directory key absent"))?;
            let file_key = permit
                .retained_file_key()
                .ok_or(ReconcileError::Invariant("retained file key absent"))?;
            let container_path = directory
                .parent()
                .ok_or(ReconcileError::Invariant("retained container path absent"))?;
            let container_key = permit
                .retained_container_key()
                .ok_or(ReconcileError::Invariant("retained container key absent"))?;
            if let Some(boundary) = &retained {
                let relative = directory.strip_prefix(owner.mount_path()).map_err(|_| {
                    ReconcileError::Invariant("cleanup retained directory escaped mount")
                })?;
                let held = owner.volume().directory(relative)?;
                held.verify_original_transaction_contents(file_key, &prior_payload, boundary)?;
            } else {
                // ENOENT from acquire_retained may refer to the child rather
                // than the transaction directory.  Reopen the directory
                // observation-only to distinguish that incomplete state from
                // a genuinely absent transaction directory before any effect.
                let relative = directory.strip_prefix(owner.mount_path()).map_err(|_| {
                    ReconcileError::Invariant("cleanup retained directory escaped mount")
                })?;
                match owner.volume().directory(relative) {
                    Ok(held) => {
                        if !was_prepared || already_completed {
                            return Err(ReconcileError::Invariant(
                                "unprepared or completed retained directory remains",
                            ));
                        }
                        held.verify_original_empty_transaction(directory_key)?;
                        child_absent_pre = Some(LinuxCleanupAbsenceObservation::observe_retained(
                            owner,
                            directory,
                            "original",
                            directory_key,
                            file_key,
                        )?);
                    }
                    Err(error) if error.raw_os_error() == Some(2) => {}
                    Err(error) => return Err(error.into()),
                }
                if !was_prepared {
                    return Err(ReconcileError::Invariant(
                        "unprepared retained directory missing",
                    ));
                }
                if child_absent_pre.is_none() {
                    directory_absent_pre = Some(LinuxCleanupAbsenceObservation::observe_retained(
                        owner,
                        container_path,
                        attempt.as_str(),
                        container_key,
                        directory_key,
                    )?);
                }
            }
        }
        // All present objects are validated before the first append or unlink.
        self.journal
            .prepare_original_linux_cleanup(&mut permit, self.limits.max_storage_entries)?;
        crate::fault::checkpoint("after_original_linux_cleanup_prepared");
        let outside_absent = if let Some(boundary) = outside {
            boundary.unlink_exact_original()?
        } else {
            LinuxCleanupAbsenceObservation::observe_outside(
                owner,
                permit.original_intent_parent(),
                permit.original_intent_component(),
                permit.original_intent_parent_key(),
                permit.original_intent_file_key(),
            )?
        };
        crate::fault::checkpoint("after_original_linux_outside_intent_unlinked");
        let mut backup_absent = None;
        let mut directory_absent = None;
        if let Some(directory) = retained_directory {
            let directory_key = permit
                .retained_directory_key()
                .ok_or(ReconcileError::Invariant("retained directory key absent"))?;
            let file_key = permit
                .retained_file_key()
                .ok_or(ReconcileError::Invariant("retained file key absent"))?;
            let container_path = directory
                .parent()
                .ok_or(ReconcileError::Invariant("retained container path absent"))?;
            let container_key = permit
                .retained_container_key()
                .ok_or(ReconcileError::Invariant("retained container key absent"))?;
            if retained.is_some() || child_absent_pre.is_some() {
                if let Some(boundary) = retained {
                    backup_absent = Some(boundary.unlink_exact_original()?);
                    crate::fault::checkpoint("after_original_linux_retained_inode_unlinked");
                } else {
                    backup_absent = child_absent_pre.take();
                }
                let relative = container_path
                    .strip_prefix(owner.mount_path())
                    .map_err(|_| {
                        ReconcileError::Invariant("cleanup retained container escaped mount")
                    })?;
                let container = owner.volume().directory(relative)?;
                if container.original_key()? != container_key {
                    return Err(ReconcileError::Invariant(
                        "cleanup retained container was substituted",
                    ));
                }
                container.remove_original_empty_child(attempt.as_str(), directory_key)?;
            } else {
                // A missing transaction directory was pre-observed through its
                // original retained container. The inode is not reconstructed
                // from equal bytes or a newly-created parent.
                directory_absent = Some(directory_absent_pre.take().ok_or(
                    ReconcileError::Invariant("original directory absence precheck missing"),
                )?);
            }
            if directory_absent.is_none() {
                directory_absent = Some(LinuxCleanupAbsenceObservation::observe_retained(
                    owner,
                    container_path,
                    attempt.as_str(),
                    container_key,
                    directory_key,
                )?);
            }
            if backup_absent.is_none() {
                backup_absent = Some(
                    LinuxCleanupAbsenceObservation::observe_child_of_original_absent_directory(
                        directory_absent.as_ref().ok_or(ReconcileError::Invariant(
                            "original directory absence missing",
                        ))?,
                        "original",
                        file_key,
                    )?,
                );
            }
        }
        let mut observations = vec![&outside_absent];
        if let Some(absent) = &backup_absent {
            observations.push(absent);
        }
        if let Some(absent) = &directory_absent {
            observations.push(absent);
        }
        self.journal.complete_original_linux_cleanup(
            permit,
            &observations,
            self.limits.max_storage_entries,
        )?;
        Ok(serde_json::json!({
            "transaction_id": attempt, "cleanup_completed": true, "already_completed": already_completed,
            "fresh_owner_generation": owner.owner_generation(), "outside_intent_absent": true,
            "immutable_history_and_native_receipts_retained": true, "unfamiliar_objects_removed": false,
        }))
    }
}
