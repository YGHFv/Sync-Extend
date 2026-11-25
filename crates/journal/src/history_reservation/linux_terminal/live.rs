//! Live issuance requires original native, metadata, helper and Journal holders.
use super::*;
use crate::{Journal, JournalError};
use sync_extend_platform_fs::{
    LinuxCleanupAbsenceObservation, LinuxMetadataBudget, LinuxNamespaceCapability,
    LinuxNativeAttempt, OriginalOutsideIntent, OriginalPairFrozenObservation,
    OriginalPairTerminalRelease, OriginalPrivateVolumeFile, OriginalRetainedVolumeFile,
    OutsidePreparationPair, UnixFileKey,
};

fn tuple(key: UnixFileKey) -> Key {
    (key.device, key.inode)
}
fn native_key(key: Key) -> UnixFileKey {
    UnixFileKey {
        device: key.0,
        inode: key.1,
    }
}

impl Journal {
    pub(super) fn append_original_linux_state(
        &mut self,
        name: &str,
        json: &str,
        space: &sync_extend_core_model::SpaceId,
        max: usize,
    ) -> Result<()> {
        let bounds = self.writer_capacity_limits(max)?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        tx.execute(
            "INSERT INTO local_state VALUES (?1,?2)",
            params![name, json],
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        if !after.report.within_accounted_limits()
            || after.rows.len() != before.rows.len() + 1
            || before.rows.iter().any(|row| {
                !after.rows.iter().any(|current| {
                    row.table() == current.table()
                        && row.primary_key() == current.primary_key()
                        && row.columns() == current.columns()
                })
            })
        {
            return Err(JournalError::Invariant(
                "native terminal append changed collateral rows or exceeded capacity",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_original_linux_native_final(
        &mut self,
        attempt: &LinuxNativeAttempt<'_>,
        budget: &LinuxMetadataBudget,
        intent: &OriginalOutsideIntent,
        intent_parent: &std::path::Path,
        worktree: &std::path::Path,
        creator: &OriginalPrivateVolumeFile<'_, '_>,
        retained: Option<&OriginalRetainedVolumeFile<'_, '_>>,
        frozen: &OriginalPairFrozenObservation<'_>,
        pair: &OutsidePreparationPair,
        history: &super::super::OriginalReservedHistoryCommitReceipt,
        max: usize,
    ) -> Result<OriginalLinuxNativeFinalDiagnostic> {
        attempt.verify()?;
        let owner = attempt.owner();
        budget.validate_native_attempt(attempt)?;
        history.verify_original_issuer(&self.original_local_history_issuer)?;
        intent.verify(owner.volume())?;
        creator.verify()?;
        frozen.verify_original_binding(pair)?;
        let stored: Stored = parse(history.exact_reservation_json())?;
        if attempt.transaction_id() != stored.attempt.as_str() {
            return Err(JournalError::Invariant(
                "native Final original transaction token differs",
            ));
        }
        let source_path = worktree.join(stored.future_path.as_str());
        creator.verify_original_slot(&source_path)?;
        let payload = creator.exact_bytes()?;
        history.native_phase_chain().verify_original_native(
            intent.exact_bytes(),
            tuple(creator.original_key()?),
            tuple(creator.original_parent_key()?),
            &payload,
        )?;
        let worktree_relative = worktree
            .strip_prefix(owner.mount_path())
            .map_err(|_| JournalError::Invariant("native Final worktree escaped acquired mount"))?;
        let worktree_key = owner
            .volume()
            .directory(worktree_relative)?
            .original_key()?;
        let parent_observed = std::fs::symlink_metadata(intent_parent)?;
        use std::os::unix::fs::MetadataExt;
        if !parent_observed.is_dir()
            || tuple(intent.original_parent_key()) != (parent_observed.dev(), parent_observed.ino())
        {
            return Err(JournalError::Invariant(
                "native Final outside intent parent differs",
            ));
        }
        let retained_record = if let Some(retained) = retained {
            retained.verify()?;
            let content = stored
                .baseline
                .entries
                .values()
                .find(|entry| entry.path == stored.future_path)
                .and_then(|entry| entry.content.as_ref())
                .ok_or(JournalError::Invariant(
                    "replacement Final prior file absent",
                ))?;
            if retained.exact_bytes().len() as u64 != content.length
                || ContentId::hash(retained.exact_bytes()) != content.content_id
            {
                return Err(JournalError::Invariant(
                    "replacement Final retained bytes differ",
                ));
            }
            let directory = source_path
                .parent()
                .ok_or(JournalError::Invariant("replacement target parent absent"))?
                .join(".sync-tmp")
                .join(stored.attempt.as_str());
            let container_relative = directory
                .parent()
                .ok_or(JournalError::Invariant("replacement container absent"))?
                .strip_prefix(owner.mount_path())
                .map_err(|_| {
                    JournalError::Invariant("retained container escaped acquired mount")
                })?;
            let container_key = tuple(
                owner
                    .volume()
                    .directory(container_relative)?
                    .original_key()?,
            );
            Some(Retained {
                directory,
                directory_key: tuple(retained.retained_parent_key()),
                container_key,
                file_key: tuple(retained.original_key()),
                source_parent_key: tuple(retained.source_parent_key()),
                content: content.clone(),
            })
        } else {
            None
        };
        let value = Final {
            version: 1,
            attempt: stored.attempt.clone(),
            owner_generation: owner.owner_generation(),
            persistent_metadata_generation: budget.persistent_owner_generation(),
            backing_image: tuple(owner.backing_image_key()),
            volume_root: tuple(owner.volume().observation().root_key),
            worktree_key: tuple(worktree_key),
            worktree: worktree.to_owned(),
            target: stored.future_path.clone(),
            target_key: tuple(creator.original_key()?),
            target_parent_key: tuple(creator.original_parent_key()?),
            intent_parent: intent_parent.to_owned(),
            intent_parent_key: tuple(intent.original_parent_key()),
            intent_file_key: tuple(intent.original_file_key()),
            intent_component: intent.component().to_owned(),
            intent_json: std::str::from_utf8(intent.exact_bytes())
                .map_err(|_| JournalError::Invariant("native intent UTF8"))?
                .to_owned(),
            reservation_json: history.exact_reservation_json().to_owned(),
            snapshot_json: history.snapshot_json().to_owned(),
            operation_json: history.operation_json().to_vec(),
            observation_json: history
                .observation_json()
                .ok_or(JournalError::Invariant("native Final observations absent"))?
                .to_owned(),
            history_digest: history.evidence_digest().clone(),
            phase_json: history.native_phase_chain().exact_phase_json().to_vec(),
            retained: retained_record,
        };
        let json = serde_json::to_string(&value)?;
        validate_final(&json)?;
        validate_context(&self.connection, &value, &stored)?;
        attempt.verify()?;
        self.append_original_linux_state(
            &key(FINAL, &value.attempt),
            &json,
            &stored.planned.space_id,
            max,
        )?;
        attempt.verify()?;
        Ok(OriginalLinuxNativeFinalDiagnostic {
            transaction_id: value.attempt,
            target: value.target,
            snapshot_id: stored.planned.root()?,
            native_action: if stored.version == 2 {
                "REPLACE"
            } else {
                "CREATE"
            },
            final_exact_digest: ContentId::hash(json.as_bytes()),
            helper_thawed: false,
            cleanup_prepared: false,
            cleanup_completed: false,
            immutable_history_and_native_receipts_retained: true,
        })
    }

    pub fn record_original_linux_committed_thaw(
        &mut self,
        owner: &LinuxNamespaceCapability,
        terminal: &OriginalPairTerminalRelease,
        attempt: &EntryId,
        max: usize,
    ) -> Result<()> {
        terminal.verify_committed_owner(owner, attempt.as_str())?;
        let final_json = state(&self.connection, &key(FINAL, attempt))?.ok_or(
            JournalError::Invariant("original Final absent before THAWED"),
        )?;
        let (value, stored) = validate_final(&final_json)?;
        if value.attempt != *attempt {
            return Err(JournalError::Invariant("THAWED Final row key differs"));
        }
        validate_context(&self.connection, &value, &stored)?;
        if value.owner_generation != owner.owner_generation()
            || value.backing_image != tuple(owner.backing_image_key())
        {
            return Err(JournalError::Invariant(
                "original THAWED owner differs from Final",
            ));
        }
        let startup = terminal.startup_bytes();
        let streams = terminal.terminal_bytes();
        let thawed = Thawed {
            version: 1,
            attempt: attempt.clone(),
            final_digest: ContentId::hash(final_json.as_bytes()),
            owner_generation: owner.owner_generation(),
            process_ids: terminal.process_ids(),
            startup: (startup.0.to_vec(), startup.1.to_vec()),
            stdout: (streams.0.0.to_vec(), streams.1.0.to_vec()),
            stderr: (streams.0.1.to_vec(), streams.1.1.to_vec()),
        };
        let json = serde_json::to_string(&thawed)?;
        validate_thawed(&json, &final_json, &value)?;
        self.append_original_linux_state(
            &key(THAWED, attempt),
            &json,
            &stored.planned.space_id,
            max,
        )
    }

    pub fn original_linux_native_final_diagnostics(
        &self,
    ) -> Result<Vec<OriginalLinuxNativeFinalDiagnostic>> {
        audit_source_native_terminals(&self.connection, self.max_storage_entries)
    }

    pub fn acquire_original_linux_cleanup(
        &self,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
        attempt: &EntryId,
    ) -> Result<OriginalLinuxCleanupPermit> {
        owner.verify()?;
        budget.validate_namespace_owner(owner)?;
        if state(&self.connection, super::super::KEY)?.is_some() {
            return Err(JournalError::Invariant(
                "pending native attempt refuses cleanup",
            ));
        }
        let final_json = state(&self.connection, &key(FINAL, attempt))?
            .ok_or(JournalError::Invariant("cleanup original Final absent"))?;
        let (value, stored) = validate_final(&final_json)?;
        if value.attempt != *attempt {
            return Err(JournalError::Invariant("cleanup Final row key differs"));
        }
        validate_context(&self.connection, &value, &stored)?;
        let volume = tuple(owner.volume().observation().root_key);
        if value.backing_image != tuple(owner.backing_image_key())
            || value.volume_root.1 != volume.1
            || value.persistent_metadata_generation != budget.persistent_owner_generation()
        {
            return Err(JournalError::Invariant(
                "cleanup fresh owner image or original metadata identity differs",
            ));
        }
        let worktree_relative = value
            .worktree
            .strip_prefix(owner.mount_path())
            .map_err(|_| JournalError::Invariant("cleanup worktree escaped acquired mount"))?;
        let current_worktree = tuple(
            owner
                .volume()
                .directory(worktree_relative)?
                .original_key()?,
        );
        if current_worktree.0 != volume.0 || current_worktree.1 != value.worktree_key.1 {
            return Err(JournalError::Invariant(
                "cleanup original worktree inode differs",
            ));
        }
        let thawed_json = state(&self.connection, &key(THAWED, attempt))?
            .ok_or(JournalError::Invariant("cleanup original THAWED absent"))?;
        validate_thawed(&thawed_json, &final_json, &value)?;
        let prepared_json = state(&self.connection, &key(PREPARED, attempt))?;
        if let Some(prepared) = &prepared_json {
            validate_progress(prepared, &final_json, &thawed_json, &value, None)?;
        }
        let cleaned_json = state(&self.connection, &key(CLEANED, attempt))?;
        if let Some(cleaned) = &cleaned_json {
            validate_progress(
                cleaned,
                &final_json,
                &thawed_json,
                &value,
                Some(
                    prepared_json
                        .as_deref()
                        .ok_or(JournalError::Invariant("cleaned preparation absent"))?,
                ),
            )?;
        }
        owner.verify()?;
        Ok(OriginalLinuxCleanupPermit {
            final_record: value,
            final_json,
            thawed_json,
            prepared_json,
            cleaned_json,
            issuer: self.original_local_history_issuer.clone(),
            cleanup_owner_generation: owner.owner_generation(),
            current_volume_root: volume,
        })
    }

    pub fn prepare_original_linux_cleanup(
        &mut self,
        permit: &mut OriginalLinuxCleanupPermit,
        max: usize,
    ) -> Result<()> {
        permit.verify_issuer(self)?;
        if permit.prepared_json.is_some() || permit.cleaned_json.is_some() {
            return Ok(());
        }
        let progress = Progress {
            version: 1,
            attempt: permit.final_record.attempt.clone(),
            final_digest: ContentId::hash(permit.final_json.as_bytes()),
            thawed_digest: ContentId::hash(permit.thawed_json.as_bytes()),
            cleanup_owner_generation: permit.cleanup_owner_generation,
            persistent_metadata_generation: permit.final_record.persistent_metadata_generation,
            backing_image: permit.final_record.backing_image,
            predecessor: None,
            observed_absent_slots: Vec::new(),
        };
        let json = serde_json::to_string(&progress)?;
        validate_progress(
            &json,
            &permit.final_json,
            &permit.thawed_json,
            &permit.final_record,
            None,
        )?;
        let stored: Stored = parse(&permit.final_record.reservation_json)?;
        self.append_original_linux_state(
            &key(PREPARED, &permit.final_record.attempt),
            &json,
            &stored.planned.space_id,
            max,
        )?;
        permit.prepared_json = Some(json);
        Ok(())
    }

    pub fn complete_original_linux_cleanup(
        &mut self,
        mut permit: OriginalLinuxCleanupPermit,
        absent: &[&LinuxCleanupAbsenceObservation<'_>],
        max: usize,
    ) -> Result<OriginalLinuxCleanupCompletion> {
        permit.verify_issuer(self)?;
        let prepared = permit
            .prepared_json
            .as_deref()
            .ok_or(JournalError::Invariant(
                "original cleanup preparation absent",
            ))?;
        let expected = permit.absence_bindings();
        if absent.len() != expected.len() {
            return Err(JournalError::Invariant(
                "original cleanup absence inventory incomplete",
            ));
        }
        for (observed, (parent, file, component)) in absent.iter().zip(&expected) {
            observed.verify()?;
            if tuple(observed.original_parent_key()) != *parent
                || tuple(observed.original_file_key()) != *file
                || observed.component() != component
                || observed.owner_generation() != permit.cleanup_owner_generation
            {
                return Err(JournalError::Invariant(
                    "original cleanup typed absence belongs to another permit",
                ));
            }
        }
        let stored: Stored = parse(&permit.final_record.reservation_json)?;
        if permit.cleaned_json.is_none() {
            let progress = Progress {
                version: 1,
                attempt: permit.final_record.attempt.clone(),
                final_digest: ContentId::hash(permit.final_json.as_bytes()),
                thawed_digest: ContentId::hash(permit.thawed_json.as_bytes()),
                cleanup_owner_generation: permit.cleanup_owner_generation,
                persistent_metadata_generation: permit.final_record.persistent_metadata_generation,
                backing_image: permit.final_record.backing_image,
                predecessor: Some(ContentId::hash(prepared.as_bytes())),
                observed_absent_slots: expected,
            };
            let json = serde_json::to_string(&progress)?;
            validate_progress(
                &json,
                &permit.final_json,
                &permit.thawed_json,
                &permit.final_record,
                Some(prepared),
            )?;
            self.append_original_linux_state(
                &key(CLEANED, &permit.final_record.attempt),
                &json,
                &stored.planned.space_id,
                max,
            )?;
            permit.cleaned_json = Some(json);
        }
        for observed in absent {
            observed.verify()?;
        }
        self.observe_after_current(&stored.planned.space_id, &stored.planned.root()?)?;
        permit.verify_issuer(self)?;
        Ok(OriginalLinuxCleanupCompletion { permit })
    }
}

impl OriginalLinuxCleanupPermit {
    pub(super) fn verify_issuer(&self, journal: &Journal) -> Result<()> {
        if !std::sync::Arc::ptr_eq(&self.issuer, &journal.original_local_history_issuer)
            || state(&journal.connection, &key(FINAL, &self.final_record.attempt))?.as_deref()
                != Some(self.final_json.as_str())
            || state(
                &journal.connection,
                &key(THAWED, &self.final_record.attempt),
            )?
            .as_deref()
                != Some(self.thawed_json.as_str())
            || state(
                &journal.connection,
                &key(PREPARED, &self.final_record.attempt),
            )? != self.prepared_json
            || state(
                &journal.connection,
                &key(CLEANED, &self.final_record.attempt),
            )? != self.cleaned_json
        {
            return Err(JournalError::Invariant(
                "live cleanup permit or immutable state changed",
            ));
        }
        Ok(())
    }
    fn inside(&self, key: Key) -> Key {
        (self.current_volume_root.0, key.1)
    }
    fn absence_bindings(&self) -> Vec<(Key, Key, String)> {
        let value = &self.final_record;
        let mut result = vec![(
            value.intent_parent_key,
            value.intent_file_key,
            value.intent_component.clone(),
        )];
        if let Some(retained) = &value.retained {
            result.push((
                self.inside(retained.directory_key),
                self.inside(retained.file_key),
                "original".into(),
            ));
            result.push((
                self.inside(retained.container_key),
                self.inside(retained.directory_key),
                value.attempt.to_string(),
            ));
        }
        result
    }
    pub fn transaction_id(&self) -> &EntryId {
        &self.final_record.attempt
    }
    pub fn original_intent_parent(&self) -> &std::path::Path {
        &self.final_record.intent_parent
    }
    pub fn original_intent_component(&self) -> &str {
        &self.final_record.intent_component
    }
    pub fn original_intent_parent_key(&self) -> UnixFileKey {
        native_key(self.final_record.intent_parent_key)
    }
    pub fn original_intent_file_key(&self) -> UnixFileKey {
        native_key(self.final_record.intent_file_key)
    }
    pub fn exact_original_intent_bytes(&self) -> &[u8] {
        self.final_record.intent_json.as_bytes()
    }
    pub fn retained_directory(&self) -> Option<&std::path::Path> {
        self.final_record
            .retained
            .as_ref()
            .map(|value| value.directory.as_path())
    }
    pub fn retained_directory_key(&self) -> Option<UnixFileKey> {
        self.final_record
            .retained
            .as_ref()
            .map(|value| native_key(self.inside(value.directory_key)))
    }
    pub fn retained_container_key(&self) -> Option<UnixFileKey> {
        self.final_record
            .retained
            .as_ref()
            .map(|value| native_key(self.inside(value.container_key)))
    }
    pub fn retained_file_key(&self) -> Option<UnixFileKey> {
        self.final_record
            .retained
            .as_ref()
            .map(|value| native_key(self.inside(value.file_key)))
    }
    pub fn retained_content(&self) -> Option<&FileManifest> {
        self.final_record
            .retained
            .as_ref()
            .map(|value| &value.content)
    }
    pub fn cleanup_was_prepared(&self) -> bool {
        self.prepared_json.is_some()
    }
    pub fn cleanup_was_completed(&self) -> bool {
        self.cleaned_json.is_some()
    }
}
