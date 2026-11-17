//! Normal single-file native publication and transaction-specific cleanup.
//! Immutable history/Final/THAWED receipts survive every cleanup invocation.
use crate::{LocalSpace, ReconcileError, Result};
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};
use sync_extend_core_model::{ContentId, EntryId, PortablePath};
use sync_extend_platform_fs::{
    LinuxCleanupAbsenceObservation, LinuxMetadataBudget, LinuxNamespaceCapability,
    LinuxOutsideCleanupBoundary, OriginalPairTerminalRelease, OutsideHelperSession,
    OutsidePrivateIntentOwner,
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
            return Err(ReconcileError::Invariant("native full planning requires helpers not yet started"));
        }
        self.require_no_mutation()?;
        if !self.journal.outstanding_publications(&self.space_id)?.is_empty() {
            return Err(ReconcileError::Invariant("native planning cannot recover a legacy worktree publication before ARM"));
        }
        self.scan_without_recovery()?;
        let worktree = self.worktree.clone();
        let intent_parent = self.data_dir.join("native-intents");
        if !intent_parent.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(&intent_parent)?;
            fs::File::open(&self.data_dir)?.sync_all()?;
        }
        let volume = owner.volume();
        let outside = OutsidePrivateIntentOwner::open(&intent_parent, volume)?;
        let mut plan = self.plan_local_file_native_history(source, path.clone())?;
        let footprint = plan.original_native_create_footprint()?;
        // This aggregate budget includes the bounded outside intent and complete
        // future terminal records; the five SQLite capacities stay independently
        // physically reserved by the original metadata VFS.
        plan.reserve_original_native_internal_budget(footprint.native_peak_bytes)?;
        let attempt_id = plan.original_reservation().attempt().clone();
        let prior_content = plan
            .prior_manifest()
            .entries
            .values()
            .find(|entry| entry.path == path)
            .and_then(|entry| entry.content.clone());
        let content = plan.content().clone();
        let mut payload = Vec::new();
        plan.write_original_planned_payload(&mut payload)?;
        if payload.len() as u64 != content.length || ContentId::hash(&payload) != content.content_id
        {
            return Err(ReconcileError::Invariant(
                "native planned payload differs from original CAS",
            ));
        }
        let prior_payload = if let Some(prior) = &prior_content {
            let mut bytes = Vec::new();
            plan.write_original_prior_payload(prior, &mut bytes)?;
            if bytes.len() as u64 != prior.length || ContentId::hash(&bytes) != prior.content_id {
                return Err(ReconcileError::Invariant(
                    "native retained prior payload differs from original CAS",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let intent_bytes = plan.intent_evidence_bytes()?;
        let intent =
            outside.create_intent(&format!("intent-{attempt_id}"), &intent_bytes, volume)?;
        plan.observe_original_outside_intent(&intent, volume)?;
        plan.observe_original_create_request(&intent, volume)?;
        let relative_parent = worktree.join(
            path.parent()
                .map_or(String::new(), |parent| parent.to_string()),
        );
        let relative_parent = relative_parent
            .strip_prefix(owner.mount_path())
            .map_err(|_| ReconcileError::Invariant("native parent escaped acquired mount"))?;
        let parent = volume.directory(relative_parent)?;
        let component = path
            .as_str()
            .rsplit('/')
            .next()
            .ok_or(ReconcileError::Invariant("native target component absent"))?;
        let old = if prior_content.is_some() {
            Some(parent.writer_excluded_original(component)?)
        } else {
            None
        };
        let freeze = volume.prepare_original_pair_freeze()?;
        // SQL/CAS/full-plan, retained descriptor and outside intent preparation
        // finish before the actual PREPARED children begin their unchanged 3s
        // wait. The caller still runs on the original pre-runtime owner thread.
        *helpers = Some(prepare_helpers()?);
        let session = helpers.as_mut().ok_or(ReconcileError::Invariant(
            "original late prepared helper session absent",
        ))?;
        owner.verify_prepared_helpers(session)?;
        // Both actual ARM READY lines precede the first protected worktree effect.
        session.arm(attempt_id.as_str())?;
        let native = owner.admit_native_attempt(session.pair())?;
        budget.validate_native_attempt(&native)?;
        native.verify()?;
        let mut created =
            parent.create_original_file(&format!("stage-{attempt_id}"), content.length.max(1))?;
        native.verify()?;
        plan.observe_original_empty_create(&intent, volume, &created)?;
        native.verify()?;
        if !payload.is_empty() {
            created.observe_preallocated_original_payload(payload.len() as u64)?;
            native.verify()?;
        }
        created.write_all_bounded(&payload)?;
        native.verify()?;
        created.sync_original_and_parents()?;
        native.verify()?;
        let transaction = if old.is_some() {
            Some(parent.create_original_transaction_directory(attempt_id.as_str())?)
        } else {
            None
        };
        native.verify()?;
        let retained = match (old, transaction.as_ref(), prior_payload.as_ref()) {
            (Some(original), Some(transaction), Some(prior_payload)) => Some(
                original.retain_in_original_transaction(transaction, "original", prior_payload)?,
            ),
            (None, None, None) => None,
            _ => {
                return Err(ReconcileError::Invariant(
                    "native replacement original transaction incomplete",
                ))
            }
        };
        native.verify()?;
        created.rename_in_same_parent_no_replace(component)?;
        native.verify()?;
        plan.observe_original_published_create(&intent, volume, &created)?;
        native.verify()?;
        let frozen = freeze.freeze_for_original_pair_diagnostic(session.pair())?;
        native.verify()?;
        let (result, history) = plan.commit_after_original_native_observation()?;
        native.verify()?;
        let final_observation = crate::observe_original_linux_native_final(
            &created,
            &intent,
            volume,
            &frozen,
            session.pair(),
            &result,
            history,
        )?;
        self.journal.record_original_linux_native_final(
            &native,
            budget,
            &intent,
            &intent_parent,
            &worktree,
            &created,
            retained.as_ref(),
            &frozen,
            session.pair(),
            final_observation.original_history_receipt(),
            self.limits.max_storage_entries,
        )?;
        native.verify()?;
        drop(final_observation);
        drop(native);
        drop(frozen);
        let session = helpers.take().ok_or(ReconcileError::Invariant(
            "original armed session escaped owner",
        ))?;
        let terminal = session.finish_committed()?;
        self.journal.record_original_linux_committed_thaw(
            owner,
            &terminal,
            &attempt_id,
            self.limits.max_storage_entries,
        )?;
        budget.verify()?;
        Ok((
            crate::PublishResult {
                transaction_id: attempt_id,
                requested_path: path.clone(),
                published_path: path,
                conflict_copy: false,
                snapshot_id: result.snapshot_id,
                local_committed: true,
                remote_backup_complete: false,
            },
            terminal,
        ))
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
