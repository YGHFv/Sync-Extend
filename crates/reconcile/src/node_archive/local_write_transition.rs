// Whole original live scope retained across explicit new restoration write attempt.
// Included inside local_space.rs where LocalSpace/readers/locks remain private.
pub struct OriginalNodeWriteSession<'scope> {
    original: sync_extend_journal::OriginalJournalWriteTransition,
    directories: &'scope super::CreatedNodeDirectorySet<'scope>,
    readers: super::assembly::ReadContents,
    ordinary_files: Vec<super::node_write_transition::OrdinaryFileCreationReceipt>,
    retained_mutations: Vec<OrdinaryRetainedMutation>,
    new_cas_directories: std::collections::BTreeMap<Vec<String>, OrdinaryCasDirectory>,
    new_cas_evidence: Vec<super::node_write_transition::OrdinaryCasEvidence>,
    data_locks: super::CreatedNodeDataLocks<'scope>,
    ledger: super::node_write_transition::OriginalNodeWriteLedger,
    attempt: super::node_write_transition::OriginalNodeWriteAttempt,
    native_keys: [sync_extend_platform_fs::FileKey; 3],
    archive_digest: ContentId,
    membership: OriginalWriteMembership,
    worktree: std::path::PathBuf,
    limits: sync_extend_core_model::limits::LocalLimits,
    _data_writer: sync_extend_platform_fs::WriterOwner,
    _worktree_writer: sync_extend_platform_fs::WriterOwner,
    cas: sync_extend_cas::Cas,
    uncertain: bool,
    wrote: bool,
}

/// Failed openings expose only phase text. Every retained handle and private
/// LocalSpace remains owned by this object; no reference can resume issuance.
pub struct OriginalNodeWriteOpenFailure<'scope> {
    state: Box<OriginalNodeWriteOpening<'scope>>,
    error: ReconcileError,
}
impl OriginalNodeWriteOpenFailure<'_> {
    pub fn error(&self) -> &ReconcileError {
        &self.error
    }
    pub fn actual_journal_open_attempted(&self) -> bool {
        self.state.journal_failed.is_some() || self.state.original.is_some()
    }
}
struct OriginalNodeWriteRemainder<'scope> {
    directories: &'scope super::CreatedNodeDirectorySet<'scope>,
    readers: super::assembly::ReadContents,
    data_locks: super::CreatedNodeDataLocks<'scope>,
    archive_digest: ContentId,
    worktree: std::path::PathBuf,
    limits: sync_extend_core_model::limits::LocalLimits,
    data_writer: sync_extend_platform_fs::WriterOwner,
    worktree_writer: sync_extend_platform_fs::WriterOwner,
    cas: sync_extend_cas::Cas,
}
struct OriginalNodeWriteOpening<'scope> {
    local: Option<OriginalRestoredLocalSpace<'scope>>,
    remainder: Option<OriginalNodeWriteRemainder<'scope>>,
    journal: Option<sync_extend_journal::Journal>,
    journal_failed: Option<sync_extend_journal::OriginalJournalTransitionFailure>,
    original: Option<sync_extend_journal::OriginalJournalWriteTransition>,
    ready_failed: Option<OriginalNodeWriteSession<'scope>>,
    ledger: Option<super::node_write_transition::OriginalNodeWriteLedger>,
    ledger_failed: Option<super::node_write_transition::OriginalNodeWriteLedgerCreationFailure>,
    attempt: Option<super::node_write_transition::OriginalNodeWriteAttempt>,
    wal_creator: Option<sync_extend_platform_fs::OwnedFileCreation>,
    rollback_creator: Option<sync_extend_platform_fs::OwnedFileCreation>,
    wal: Option<sync_extend_platform_fs::OriginalSqliteSidecarHandoff>,
    rollback: Option<sync_extend_platform_fs::OriginalSqliteSidecarHandoff>,
    sidecar_failed: Option<sync_extend_platform_fs::OriginalSqliteSidecarHandoffFailure>,
}
impl<'scope> OriginalRestoredLocalSpace<'scope> {
    /// Complete one freshly restored original Journal write and close it while
    /// the exact CREATE handles remain owned by this process. Returned paths
    /// identify historical evidence only; they do not carry live write rights.
    pub fn complete_original_restore_with_first_write(
        self,
        archive: &super::VerifiedNodeStateArchive,
        plan: &super::PreparedOriginalNodeRestore,
        ledger: &mut super::NodeRestoreLedger,
    ) -> Result<(super::OriginalNodeCompletionEvidence, std::path::PathBuf)> {
        if plan.read_lease_hold.is_some() {
            return Err(ReconcileError::Invariant(
                "held read lease restore has no native write transition",
            ));
        }
        let external = ledger
            .path()
            .parent()
            .ok_or(ReconcileError::Invariant(
                "original first-write ledger parent absent",
            ))?
            .to_owned();
        let observation = self.observe_original_completion(archive, plan, ledger)?;
        let completion = ledger.commit_original_completion_observation(&observation)?;
        let manifest = observation.into_manifest();
        let mut session = self
            .begin_original_node_write_session(archive, plan, &manifest, ledger, &external)
            .map_err(|failure| failure.error)?;
        session.attempt_first_journal_write()?;
        let closed = session.close_completed().map_err(|failure| match failure {
            OriginalNodeWriteCloseFailure::Open { error, .. }
            | OriginalNodeWriteCloseFailure::Closed { error, .. } => error,
        })?;
        closed.verify_retained_identity_evidence()?;
        Ok((completion, closed.ledger.path().to_owned()))
    }

    pub fn begin_original_node_write_session(
        self,
        archive: &super::VerifiedNodeStateArchive,
        plan: &super::PreparedOriginalNodeRestore,
        manifest: &super::completion::OriginalNodeCompletionManifest,
        original_ledger: &super::NodeRestoreLedger,
        external: &std::path::Path,
    ) -> std::result::Result<OriginalNodeWriteSession<'scope>, OriginalNodeWriteOpenFailure<'scope>>
    {
        let mut state = Box::new(OriginalNodeWriteOpening {
            local: Some(self),
            remainder: None,
            journal: None,
            journal_failed: None,
            original: None,
            ready_failed: None,
            ledger: None,
            ledger_failed: None,
            attempt: None,
            wal_creator: None,
            rollback_creator: None,
            wal: None,
            rollback: None,
            sidecar_failed: None,
        });
        let result = state.open(archive, plan, manifest, original_ledger, external);
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(OriginalNodeWriteOpenFailure { state, error }),
        }
    }
}
impl<'scope> OriginalNodeWriteOpening<'scope> {
    fn open(
        &mut self,
        archive: &super::VerifiedNodeStateArchive,
        plan: &super::PreparedOriginalNodeRestore,
        manifest: &super::completion::OriginalNodeCompletionManifest,
        original_ledger: &super::NodeRestoreLedger,
        external: &std::path::Path,
    ) -> Result<OriginalNodeWriteSession<'scope>> {
        let local = self.local.as_ref().ok_or(ReconcileError::Invariant(
            "new opening original local absent",
        ))?;
        if plan.read_lease_hold.is_some() || manifest.read_lease_hold.is_some() {
            return Err(ReconcileError::Invariant(
                "held read lease restore has no native write transition",
            ));
        }
        local.verify()?;
        local.verify_original_prepared_completion(plan)?;
        local.verify_original_completion_membership(manifest)?;
        local.verify_original_write_completed_objects(manifest)?;
        if archive.digest() != local.archive_digest()
            || plan.archive_digest() != local.archive_digest()
        {
            return Err(ReconcileError::Invariant(
                "new opening exact archive/plan scope",
            ));
        }
        let membership = OriginalWriteMembership::from_completed(manifest)?;
        use super::node_write_transition::{
            original_write_main_limit, ORIGINAL_WRITE_SIDECAR_LIMIT,
        };
        let max_main = original_write_main_limit(plan.journal.bytes().len() as u64)?;

        match super::node_write_transition::OriginalNodeWriteLedger::create_for_completed_original(
            external,
            local,
            archive,
            manifest,
            original_ledger,
            max_main,
            ORIGINAL_WRITE_SIDECAR_LIMIT,
            ORIGINAL_WRITE_SIDECAR_LIMIT,
        ) {
            Ok(value) => self.ledger = Some(value),
            Err(failed) => {
                let _ = (failed.error(), failed.created_objects());
                self.ledger_failed = Some(failed);
                return Err(ReconcileError::Invariant(
                    "new opening actual ledger CREATE refused",
                ));
            }
        }
        self.attempt = Some(
            self.ledger
                .as_mut()
                .ok_or(ReconcileError::Invariant("new opening ledger absent"))?
                .begin()?,
        );
        let root = local.directories.roots.data_path.clone();
        self.wal_creator = Some(
            local
                .directories
                .roots
                .data
                .create_new_file("journal.sqlite-wal")?,
        );
        let wal = self.wal_creator.as_mut().ok_or(ReconcileError::Invariant(
            "new opening original WAL creator absent",
        ))?;
        wal.writer().sync_all()?;
        self.ledger
            .as_mut()
            .ok_or(ReconcileError::Invariant("new opening ledger absent"))?
            .created_sidecar(
                self.attempt
                    .as_mut()
                    .ok_or(ReconcileError::Invariant("new opening attempt absent"))?,
                &wal.original_creation()?,
                true,
            )?;
        crate::fault::checkpoint("node_write_actual_wal_created_recorded");
        let walkey = wal.key()?;
        let wal = self
            .wal_creator
            .take()
            .ok_or(ReconcileError::Invariant("new opening WAL handoff absent"))?;
        match wal.handoff_original_sqlite_sidecar(
            &root.join("journal.sqlite-wal"),
            sync_extend_platform_fs::OriginalSqliteSidecarKind::Wal,
        ) {
            Ok(value) => self.wal = Some(value),
            Err(failed) => {
                self.sidecar_failed = Some(failed);
                return Err(ReconcileError::Invariant(
                    "new opening original WAL handoff refused",
                ));
            }
        }
        self.rollback_creator = Some(
            local
                .directories
                .roots
                .data
                .create_new_file("journal.sqlite-journal")?,
        );
        let rollback = self
            .rollback_creator
            .as_mut()
            .ok_or(ReconcileError::Invariant(
                "new opening rollback creator absent",
            ))?;
        rollback.writer().sync_all()?;
        self.ledger
            .as_mut()
            .ok_or(ReconcileError::Invariant("new opening ledger absent"))?
            .created_sidecar(
                self.attempt
                    .as_mut()
                    .ok_or(ReconcileError::Invariant("new opening attempt absent"))?,
                &rollback.original_creation()?,
                false,
            )?;
        crate::fault::checkpoint("node_write_actual_rollback_created_recorded");
        let rollbackkey = rollback.key()?;
        let rollback = self
            .rollback_creator
            .take()
            .ok_or(ReconcileError::Invariant(
                "new opening rollback handoff absent",
            ))?;
        match rollback.handoff_original_sqlite_sidecar(
            &root.join("journal.sqlite-journal"),
            sync_extend_platform_fs::OriginalSqliteSidecarKind::Rollback,
        ) {
            Ok(value) => self.rollback = Some(value),
            Err(failed) => {
                self.sidecar_failed = Some(failed);
                return Err(ReconcileError::Invariant(
                    "new opening original rollback handoff refused",
                ));
            }
        }
        let mainkey = local.local.journal.original_completion_main_identity()?.0;
        let max = local.local.limits.max_storage_entries;
        let inspection = sync_extend_journal::NodeInspectionBounds {
            max_entries: max,
            capacity: sync_extend_journal::JournalCapacityLimits {
                inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                    max_rows: max,
                    max_logical_bytes: max as u64 * 1024,
                },
                max_rows: max as u64,
                max_logical_bytes: max as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        self.ledger
            .as_mut()
            .ok_or(ReconcileError::Invariant("new opening ledger absent"))?
            .observed(
                self.attempt
                    .as_mut()
                    .ok_or(ReconcileError::Invariant("new opening attempt absent"))?,
                super::node_write_transition::WritePhase::MainReleaseIntended,
                mainkey,
                walkey,
                rollbackkey,
                None,
            )?;
        let local = self.local.take().ok_or(ReconcileError::Invariant(
            "new opening whole local handoff absent",
        ))?;
        let OriginalRestoredLocalSpace {
            local,
            directories,
            readers,
            data_locks,
            archive_digest,
        } = local;
        let crate::LocalSpace {
            journal,
            cas,
            worktree,
            _lock,
            _worktree_lock,
            space_id: _,
            device_id: _,
            data_dir: _,
            limits,
            root_identity: _,
        } = local;
        self.remainder = Some(OriginalNodeWriteRemainder {
            directories,
            readers,
            data_locks,
            archive_digest,
            worktree,
            limits,
            data_writer: _lock,
            worktree_writer: _worktree_lock,
            cas,
        });
        self.journal = Some(journal);
        // All original roots/readers/writer owners and main/sidecars remain
        // retained in this sealed opening. End only our extra CAS Journal
        // connections before entering SQLite's real share-zero handoff.
        self.remainder.as_mut().ok_or(ReconcileError::Invariant(
            "new opening original CAS remainder absent",
        ))?.cas.suspend_original_read_coordination()?;


        if self.wal.is_none() || self.rollback.is_none() || self.journal.is_none() {
            return Err(ReconcileError::Invariant(
                "new opening sealed ownership incomplete",
            ));
        }
        let wal = self.wal.take().expect("checked sealed WAL");
        let rollback = self.rollback.take().expect("checked sealed rollback");
        let journal = self.journal.take().expect("checked whole original Journal");
        match journal.begin_original_write_transition(
            wal,
            rollback,
            &plan.journal,
            archive.space(),
            inspection,
            [max_main, ORIGINAL_WRITE_SIDECAR_LIMIT, ORIGINAL_WRITE_SIDECAR_LIMIT],
            1024 * 1024,
        ) {
            Ok(value) => self.original = Some(value),
            Err(failed) => {
                self.journal_failed = Some(failed);
                return Err(ReconcileError::Invariant(
                    "new opening actual original Journal refused",
                ));
            }
        }
        let original = self.original.as_ref().ok_or(ReconcileError::Invariant(
            "new opening actual writable Journal absent",
        ))?;
        if original.actual_native_keys()? != [mainkey, walkey, rollbackkey] {
            return Err(ReconcileError::Invariant(
                "new opening actual original native keys changed",
            ));
        }
        let digest = original.actual_complete_rows_digest()?;
        self.ledger
            .as_mut()
            .ok_or(ReconcileError::Invariant("new opening ledger absent"))?
            .observed(
                self.attempt
                    .as_mut()
                    .ok_or(ReconcileError::Invariant("new opening attempt absent"))?,
                super::node_write_transition::WritePhase::Ready,
                mainkey,
                walkey,
                rollbackkey,
                Some(digest),
            )?;

        if self.remainder.is_none()
            || self.original.is_none()
            || self.ledger.is_none()
            || self.attempt.is_none()
        {
            return Err(ReconcileError::Invariant(
                "new opening ready ownership incomplete",
            ));
        }
        let remainder = self.remainder.take().expect("checked original remainder");
        let result = OriginalNodeWriteSession {
            original: self.original.take().expect("checked writable Journal"),
            directories: remainder.directories,
            readers: remainder.readers,
            ordinary_files: Vec::new(),
            retained_mutations: Vec::new(),
            new_cas_directories: std::collections::BTreeMap::new(),
            new_cas_evidence: Vec::new(),
            data_locks: remainder.data_locks,
            ledger: self.ledger.take().expect("checked new original ledger"),
            attempt: self.attempt.take().expect("checked new original attempt"),
            native_keys: [mainkey, walkey, rollbackkey],
            archive_digest: remainder.archive_digest,
            membership,
            worktree: remainder.worktree,
            limits: remainder.limits,
            _data_writer: remainder.data_writer,
            _worktree_writer: remainder.worktree_writer,
            cas: remainder.cas,
            uncertain: false,
            wrote: false,
        };
        if let Err(error) = result.verify() {
            self.ready_failed = Some(result);
            return Err(error);
        }
        crate::fault::checkpoint("node_write_actual_ready");
        Ok(result)
    }
}
impl OriginalNodeWriteSession<'_> {
    pub fn original_native_keys(&self) -> [sync_extend_platform_fs::FileKey; 3] {
        self.native_keys
    }
    pub fn original_session_id(&self) -> &sync_extend_core_model::SpaceId {
        self.ledger.session()
    }
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn verify(&self) -> Result<()> {
        if self.uncertain {
            return Err(ReconcileError::Invariant(
                "original write session uncertain issuance closed",
            ));
        }
        self.directories.verify()?;
        self.data_locks.verify()?;
        self.original.verify()?;
        self.membership.verify(self.directories, &self.new_cas_directories)?;
        for directory in self.new_cas_directories.values() {
            directory.verify()?;
        }
        for receipt in &self.new_cas_evidence {
            self.ledger.verify_ordinary_cas(receipt)?;
        }
        for retained in &self.retained_mutations {
            retained.verify(&self.ledger)?;
        }
        for receipt in &self.ordinary_files {
            self.ledger.verify_ordinary_file_receipt(receipt)?;
        }
        if self.archive_digest != *self.directories.archive_digest() {
            return Err(ReconcileError::Invariant(
                "new original write session archive differs",
            ));
        }
        for ((root, parts), content) in &self.readers {
            super::read_content::verify(&content.original, content.bytes, &content.digest)?;
            if !content
                .original
                .matches_path(&self.directories.path(*root, parts))?
            {
                return Err(ReconcileError::Invariant(
                    "new original write session protected content slot differs",
                ));
            }
        }
        let _ = (&self.cas, &self.worktree);
        Ok(())
    }
    /// This only establishes a fresh actual writable Journal session. Complete
    /// native mutations still require planner/namespace/Final/cleanup contracts.
    pub fn attempt_first_journal_write(&mut self) -> Result<()> {
        self.verify()?;
        if self.wrote {
            return Err(ReconcileError::Invariant(
                "new original session single first write",
            ));
        }
        self.wrote = true;
        let result = (|| -> Result<()> {
            let session = self.ledger.session().clone();
            self.original.attempt_original_recovery_session(&session)?;
            self.verify()?;
            let keys = self.original.actual_native_keys()?;
            if keys != self.native_keys {
                return Err(ReconcileError::Invariant(
                    "new write actual Journal native keys changed",
                ));
            }
            let digest = self.original.actual_complete_rows_digest()?;
            self.ledger.observed(
                &mut self.attempt,
                super::node_write_transition::WritePhase::SessionCommitted,
                keys[0],
                keys[1],
                keys[2],
                Some(digest),
            )?;
            self.verify()
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

/// Closed observations retain identity readers/locks/ledger but never become a
/// normal LocalSpace or a recovered native mutation/cleanup capability.
pub struct OriginalNodeWriteClosed<'scope> {
    objects: [sync_extend_platform_fs::ReleasedOriginalFileIdentity; 3],
    cas_coordination: sync_extend_platform_fs::ReleasedOriginalCoordinationFile,
    directories: &'scope super::CreatedNodeDirectorySet<'scope>,
    readers: super::assembly::ReadContents,
    ordinary_files: Vec<super::node_write_transition::OrdinaryFileCreationReceipt>,
    retained_mutations: Vec<OrdinaryRetainedMutation>,
    new_cas_directories: std::collections::BTreeMap<Vec<String>, OrdinaryCasDirectory>,
    new_cas_evidence: Vec<super::node_write_transition::OrdinaryCasEvidence>,
    data_locks: super::CreatedNodeDataLocks<'scope>,
    ledger: super::node_write_transition::OriginalNodeWriteLedger,
    archive_digest: ContentId,
    membership: OriginalWriteMembership,
    native_keys: [sync_extend_platform_fs::FileKey; 3],
    rows_observed_before_close: ContentId,
    _data_writer: sync_extend_platform_fs::WriterOwner,
    _worktree_writer: sync_extend_platform_fs::WriterOwner,
    cas: sync_extend_cas::Cas,
}
pub enum OriginalNodeWriteCloseFailure<'scope> {
    Open {
        session: Box<OriginalNodeWriteSession<'scope>>,
        error: ReconcileError,
    },
    Closed {
        evidence: Box<OriginalNodeWriteClosed<'scope>>,
        error: ReconcileError,
    },
}
impl<'scope> OriginalNodeWriteSession<'scope> {
    /// Only a completed actual first-write may checkpoint/close as successful
    /// evidence. No Drop path produces the Closed frame.
    pub fn close_completed(
        mut self,
    ) -> std::result::Result<OriginalNodeWriteClosed<'scope>, OriginalNodeWriteCloseFailure<'scope>>
    {
        let preclose = (|| -> Result<ContentId> {
            self.verify()?;
            if !self.wrote {
                return Err(ReconcileError::Invariant(
                    "new write close requires actual committed first session",
                ));
            }
            let before = self.original.actual_complete_rows_digest()?;
            self.original.checkpoint()?;
            if self.original.actual_complete_rows_digest()? != before {
                return Err(ReconcileError::Invariant(
                    "new write checkpoint changed logical Journal rows",
                ));
            }
            let keys = self.original.actual_native_keys()?;
            if keys != self.native_keys {
                return Err(ReconcileError::Invariant(
                    "new write checkpoint original native objects changed",
                ));
            }
            self.ledger.observed(
                &mut self.attempt,
                super::node_write_transition::WritePhase::Checkpointed,
                keys[0],
                keys[1],
                keys[2],
                Some(before.clone()),
            )?;
            self.verify()?;
            Ok(before)
        })();
        let digest = match preclose {
            Ok(value) => value,
            Err(error) => {
                self.uncertain = true;
                return Err(OriginalNodeWriteCloseFailure::Open {
                    session: Box::new(self),
                    error,
                });
            }
        };
        let Self {
            original,
            directories,
            readers,
            ordinary_files,
            retained_mutations,
            new_cas_directories,
            new_cas_evidence,
            data_locks,
            mut ledger,
            mut attempt,
            native_keys,
            archive_digest,
            membership,
            worktree,
            limits,
            _data_writer,
            _worktree_writer,
            cas,
            uncertain,
            wrote,
        } = self;
        let (objects, cas_coordination) = match original.close() {
            Ok(value) => value,
            Err((original, error)) => {
                return Err(OriginalNodeWriteCloseFailure::Open {
                    session: Box::new(Self {
                        original: *original,
                        directories,
                        readers,
            ordinary_files,
            retained_mutations,
            new_cas_directories,
            new_cas_evidence,
                        data_locks,
                        ledger,
                        attempt,
                        native_keys,
                        archive_digest,
                        membership,
                        worktree,
            limits,
                        _data_writer,
                        _worktree_writer,
                        cas,
                        uncertain: true,
                        wrote,
                    }),
                    error: error.into(),
                })
            }
        };
        let recorded = (|| -> Result<()> {
            for (object, key) in objects.iter().zip(native_keys) {
                if object.key()? != key {
                    return Err(ReconcileError::Invariant(
                        "actual close returned different original object",
                    ));
                }
            }
            ledger.observed(
                &mut attempt,
                super::node_write_transition::WritePhase::Closed,
                native_keys[0],
                native_keys[1],
                native_keys[2],
                Some(digest.clone()),
            )?;
            Ok(())
        })();
        let evidence = OriginalNodeWriteClosed {
            objects,
            cas_coordination,
            directories,
            readers,
            ordinary_files,
            retained_mutations,
            new_cas_directories,
            new_cas_evidence,
            data_locks,
            ledger,
            archive_digest,
            membership,
            native_keys,
            rows_observed_before_close: digest,
            _data_writer,
            _worktree_writer,
            cas,
        };
        let _ = uncertain;
        match recorded {
            Ok(()) => Ok(evidence),
            Err(error) => Err(OriginalNodeWriteCloseFailure::Closed {
                evidence: Box::new(evidence),
                error,
            }),
        }
    }
}
impl OriginalNodeWriteClosed<'_> {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn original_native_keys(&self) -> [sync_extend_platform_fs::FileKey; 3] {
        self.native_keys
    }
    pub fn rows_observed_before_close(&self) -> &ContentId {
        &self.rows_observed_before_close
    }
    pub fn verify_retained_identity_evidence(&self) -> Result<()> {
        self.directories.verify()?;
        self.data_locks.verify()?;
        for (object, key) in self.objects.iter().zip(self.native_keys) {
            if object.key()? != key {
                return Err(ReconcileError::Invariant(
                    "closed original object identity evidence differs",
                ));
            }
        }
        self.cas_coordination
            .verify(&self.directories.roots.data_path.join("cas-access.lock"))?;
        for content in self.readers.values() {
            super::read_content::verify(&content.original, content.bytes, &content.digest)?;
        }
        self.membership.verify(self.directories, &self.new_cas_directories)?;
        for directory in self.new_cas_directories.values() {
            directory.verify()?;
        }
        for receipt in &self.new_cas_evidence {
            self.ledger.verify_ordinary_cas(receipt)?;
        }
        for retained in &self.retained_mutations {
            retained.verify(&self.ledger)?;
        }
        for receipt in &self.ordinary_files {
            self.ledger.verify_ordinary_file_receipt(receipt)?;
        }
        self.ledger.verify_terminal_evidence()?;
        let _ = &self.cas;
        Ok(())
    }
}

struct OriginalWriteMembership {
    expected: std::collections::BTreeMap<(String, Vec<String>), std::collections::BTreeSet<String>>,
}
impl OriginalWriteMembership {
    fn from_completed(
        manifest: &super::completion::OriginalNodeCompletionManifest,
    ) -> Result<Self> {
        use std::collections::{BTreeMap, BTreeSet};
        manifest.validate()?;
        let mut expected: BTreeMap<(String, Vec<String>), BTreeSet<String>> = BTreeMap::new();
        for object in &manifest.objects {
            if object.kind == "directory" {
                expected
                    .entry((object.root.clone(), object.components.clone()))
                    .or_default();
            }
            if !object.components.is_empty() {
                expected
                    .entry((
                        object.root.clone(),
                        object.components[..object.components.len() - 1].to_vec(),
                    ))
                    .or_default()
                    .insert(object.created_component.clone());
            }
        }
        let data =
            expected
                .get_mut(&("data".into(), Vec::new()))
                .ok_or(ReconcileError::Invariant(
                    "new write complete data membership absent",
                ))?;
        if !data.insert("journal.sqlite-wal".into())
            || !data.insert("journal.sqlite-journal".into())
        {
            return Err(ReconcileError::Invariant(
                "new write sidecars already in completed image",
            ));
        }
        Ok(Self { expected })
    }
    fn verify(&self, directories: &super::CreatedNodeDirectorySet<'_>,
        added: &std::collections::BTreeMap<Vec<String>, OrdinaryCasDirectory>) -> Result<()> {
        use std::collections::BTreeSet;
        for ((root, parts), names) in &self.expected {
            let root = match root.as_str() {
                "worktree" => super::NodeTargetRoot::Worktree,
                "data" => super::NodeTargetRoot::Data,
                _ => return Err(ReconcileError::Invariant("new write unknown original root")),
            };
            let held = if root == super::NodeTargetRoot::Data {
                if let Some(directory) = added.get(parts) {
                    directory.verify()?;
                    &directory.creator
                } else { directories.parent(root, parts)? }
            } else { directories.parent(root, parts)? };
            let path = directories.path(root, parts);
            if !held.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "new write original parent slot differs",
                ));
            }
            let mut actual = BTreeSet::new();
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant("new write foreign reparse"));
                }
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| ReconcileError::Invariant("new write membership encoding"))?;
                if actual.len() >= names.len() || !names.contains(&name) || !actual.insert(name) {
                    return Err(ReconcileError::Invariant("new write foreign/excess member"));
                }
            }
            if actual != *names || !held.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "new write exact complete membership differs",
                ));
            }
        }
        Ok(())
    }
}

impl OriginalRestoredLocalSpace<'_> {
    fn verify_original_write_completed_objects(
        &self,
        manifest: &super::completion::OriginalNodeCompletionManifest,
    ) -> Result<()> {
        use super::completion::ObjectEvidence;
        manifest.validate()?;
        self.verify()?;
        if manifest.archive_digest != self.archive_digest
            || manifest.worktree_root_key != self.directories.roots.worktree.key()?.to_string()
            || manifest.data_root_key != self.directories.roots.data.key()?.to_string()
            || std::path::Path::new(&manifest.original_worktree_target)
                != self.directories.roots.worktree_path
            || std::path::Path::new(&manifest.original_data_target)
                != self.directories.roots.data_path
            || manifest.journal_rows_digest != self.original_complete_rows_digest()?
        {
            return Err(ReconcileError::Invariant(
                "new write complete live roots/rows/scope differ",
            ));
        }
        let sentinels = self.original_sentinel_completion_evidence()?;
        for object in &manifest.objects {
            let root = match object.root.as_str() {
                "worktree" => super::NodeTargetRoot::Worktree,
                "data" => super::NodeTargetRoot::Data,
                _ => {
                    return Err(ReconcileError::Invariant(
                        "new write complete root encoding",
                    ))
                }
            };
            let actual = if object.kind == "directory" {
                let held = self.directories.parent(root, &object.components)?;
                let original = held.original_creation()?;
                original.verify()?;
                if !held.matches_path(&self.directories.path(root, &object.components))? {
                    return Err(ReconcileError::Invariant(
                        "new write original directory slot differs",
                    ));
                }
                ObjectEvidence {
                    root: object.root.clone(),
                    components: object.components.clone(),
                    kind: "directory".into(),
                    created_component: original.created_component().to_owned(),
                    parent_key: original.parent_key()?.to_string(),
                    object_key: original.key()?.to_string(),
                    content_bytes: None,
                    content_digest: None,
                }
            } else if let Some(value) = sentinels
                .iter()
                .find(|value| value.root == object.root && value.components == object.components)
            {
                value.clone()
            } else if root == super::NodeTargetRoot::Worktree
                && object.components == [".sync-extend", "space-id"]
            {
                self.directories
                    .marker
                    .original_completion_marker_evidence()?
            } else if root == super::NodeTargetRoot::Data && object.components == ["journal.sqlite"]
            {
                let (key, parent) = self.local.journal.original_completion_main_identity()?;
                let bytes = self.local.journal.original_completion_image_bytes()?;
                ObjectEvidence {
                    root: "data".into(),
                    components: object.components.clone(),
                    kind: "file".into(),
                    created_component: "journal.sqlite".into(),
                    parent_key: parent.to_string(),
                    object_key: key.to_string(),
                    content_bytes: Some(bytes.len() as u64),
                    content_digest: Some(ContentId::hash(&bytes)),
                }
            } else {
                let content = self.readers.get(&(root, object.components.clone())).ok_or(
                    ReconcileError::Invariant("new write completed reader absent"),
                )?;
                super::read_content::verify(&content.original, content.bytes, &content.digest)?;
                if !content
                    .original
                    .matches_path(&self.directories.path(root, &object.components))?
                {
                    return Err(ReconcileError::Invariant(
                        "new write completed reader slot differs",
                    ));
                }
                ObjectEvidence {
                    root: object.root.clone(),
                    components: object.components.clone(),
                    kind: "file".into(),
                    created_component: object
                        .components
                        .last()
                        .ok_or(ReconcileError::Invariant("new write file component absent"))?
                        .clone(),
                    parent_key: content.original.original_parent_key()?.to_string(),
                    object_key: content.original.original_key()?.to_string(),
                    content_bytes: Some(content.bytes),
                    content_digest: Some(content.digest.clone()),
                }
            };
            if actual != *object {
                return Err(ReconcileError::Invariant(
                    "new write completed live object differs",
                ));
            }
        }
        self.verify_original_completion_membership(manifest)?;
        self.verify()
    }
}



impl OriginalNodeWriteSession<'_> {
    pub fn original_current_manifest(&self)->Result<sync_extend_core_model::Manifest> {
        self.verify()?;
        self.original.original_current_manifest().map_err(Into::into)
    }
    pub fn original_device_id(&self)->Result<sync_extend_core_model::DeviceId> {
        self.verify()?;
        self.original.original_device_id().map_err(Into::into)
    }
    pub(crate) fn commit_original_history(
        &mut self,previous:&sync_extend_core_model::SnapshotId,
        manifest:&sync_extend_core_model::Manifest,
        operations:&[sync_extend_core_model::Operation],timestamp:u64,
    )->Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        if !self.wrote {return Err(ReconcileError::Invariant("original first write handshake absent"));}
        let result=self.original.commit_original_local_history(previous,manifest,operations,timestamp);
        match result {
            Ok(root)=>{self.verify()?;Ok(root)}
            Err(error)=>{self.uncertain=true;Err(error.into())}
        }
    }
}

// Included within the original local write module; all owners remain private.
impl OriginalNodeWriteSession<'_> {
    /// Create a new ordinary file using existing verified current content only.
    /// The external original ledger records intent and each actual outcome.
    /// This does not recover native history or authorize deletion/replacement.
    pub fn create_original_file_from_current(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        source: &sync_extend_core_model::EntryId,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        let previous = self.original_current_manifest()?;
        let source = previous.entries.get(source)
            .filter(|entry| entry.kind == sync_extend_core_model::EntryKind::File)
            .ok_or(ReconcileError::Invariant("ordinary CREATE current file source absent"))?;
        let content = source.content.as_ref()
            .ok_or(ReconcileError::Invariant("ordinary CREATE source content absent"))?
            .clone();
        self.create_original_file_from_manifest(path, &content, timestamp)
    }
    fn create_original_file_from_manifest(
        &mut self, path: &sync_extend_core_model::PortablePath,
        content: &sync_extend_core_model::FileManifest, timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        use std::io::{Seek, SeekFrom, Write};
        self.verify()?;
        if !self.wrote || self.ordinary_files.len() + self.retained_mutations.len() >= 128 {
            return Err(ReconcileError::Invariant("ordinary CREATE first session absent"));
        }
        let previous = self.original_current_manifest()?;
        let previous_root = previous.root()?;
        if content.length > 8 * 1024 * 1024 || content.chunks.len() > 1024 {
            return Err(ReconcileError::ResourceLimit("ordinary CREATE explicit content bound"));
        }
        // The original readonly observers remain suspended. Hold the actual
        // original sentinel shared lock throughout fence audit, IO and commit.
        let _cas_session = self.original.acquire_original_cas_session()?;
        let mut allowed = std::collections::BTreeSet::new();
        for reference in previous.entries.values().filter_map(|entry| entry.content.as_ref())
            .flat_map(|file| &file.chunks)
        {
            if allowed.len() >= 4096 {
                return Err(ReconcileError::ResourceLimit("ordinary CREATE existing chunk set"));
            }
            self.original.require_original_cas_access(&reference.content_id)?;
            allowed.insert(reference.content_id.clone());
        }
        for reference in &content.chunks {
            if allowed.len() >= 4096 {
                return Err(ReconcileError::ResourceLimit("ordinary CREATE prospective chunks"));
            }
            self.original.require_original_cas_access(&reference.content_id)?;
            allowed.insert(reference.content_id.clone());
        }
        let cas = sync_extend_cas::Cas::open_existing_session_coordinated(
            &self.directories.roots.data_path.join("cas"),
            move |id| {
                if allowed.contains(id) { Ok(Box::new(())) }
                else { Err("ordinary CREATE chunk outside original fenced current set".into()) }
            },
            || Ok(Box::new(())),
        )?;
        // All adapter callbacks run inside the held outer original session.
        // New chunks are rejected before any CAS filesystem effect.
        cas.verify(content)?;
        let components: Vec<String> = path.as_str().split('/').map(str::to_owned).collect();
        let name = components.last()
            .ok_or(ReconcileError::Invariant("ordinary CREATE path absent"))?;
        if components.len() > 256 || name.starts_with('.') {
            return Err(ReconcileError::Invariant("ordinary CREATE reserved path"));
        }
        let parents = &components[..components.len()-1];
        let parent = self.directories.parent(super::NodeTargetRoot::Worktree, parents)?;
        parent.original_creation()?.verify()?;
        let expected_members = self.membership.expected
            .get(&("worktree".into(), parents.to_vec()))
            .ok_or(ReconcileError::Invariant("ordinary CREATE original parent absent"))?;
        if expected_members.contains(name)
            || previous.entries.values().any(|entry| entry.path.collision_key() == path.collision_key())
        {
            return Err(ReconcileError::Invariant("ordinary CREATE destination exists or collides"));
        }
        // Native CREATE remains no-replace even if a foreign name appears after this check.
        let key = parent.key()?;
        let mut receipt = self.ledger.begin_ordinary_file_creation(
            path, key, &previous_root, content)?;
        // Everything after durable intent consumes the attempt, including failures.
        self.uncertain = true;
        crate::fault::checkpoint("node_ordinary_create_after_intent");
        let mut creator = parent.create_new_file(name)?;
        creator.original_creation()?.verify()?;
        if creator.original_creation()?.parent_key()? != key {
            return Err(ReconcileError::Invariant("ordinary CREATE parent differs"));
        }
        let created_key = creator.key()?;
        self.ledger.ordinary_file_outcome(&mut receipt, "created", created_key, None)?;
        crate::fault::checkpoint("node_ordinary_create_recorded");
        cas.write_file(content, creator.writer())?;
        creator.writer().flush()?;
        creator.writer().sync_all()?;
        creator.writer().seek(SeekFrom::Start(0))?;
        creator.verify_single_link()?;
        if creator.reader().metadata()?.len() != content.length {
            return Err(ReconcileError::Invariant("ordinary CREATE exact written bytes"));
        }
        self.ledger.ordinary_file_outcome(&mut receipt, "materialized", created_key, None)?;
        crate::fault::checkpoint("node_ordinary_create_materialized");
        let original = super::original_content::OriginalContent::Sealed(
            creator.seal_original()?);
        super::read_content::verify(&original, content.length, &content.content_id)?;
        let target = self.directories.path(super::NodeTargetRoot::Worktree, &components);
        if !original.matches_path(&target)? || original.original_key()? != created_key {
            return Err(ReconcileError::Invariant("ordinary CREATE sealed original slot differs"));
        }
        self.readers.insert((super::NodeTargetRoot::Worktree, components.clone()),
            super::assembly::ReadContent {
                original, bytes: content.length, digest: content.content_id.clone(),
            });
        if !self.membership.expected.get_mut(&("worktree".into(), parents.to_vec()))
            .ok_or(ReconcileError::Invariant("ordinary CREATE retained membership parent"))?
            .insert(name.clone())
        {
            return Err(ReconcileError::Invariant("ordinary CREATE duplicate membership"));
        }
        self.membership.verify(self.directories, &self.new_cas_directories)?;
        // Original limits, scanner and manifest builder; no arbitrary SQL/Journal
        // or filesystem references cross the session boundary.
        let limits = self.limits.clone();
        limits.validate()?;
        let first = crate::scan::scan_native(&self.worktree, &cas, &limits, &OriginalSessionScanView { session: self })?;
        crate::fault::checkpoint("node_ordinary_create_after_first_scan");
        let second = crate::scan::scan_native(&self.worktree, &cas, &limits, &OriginalSessionScanView { session: self })?;
        if first != second {
            return Err(ReconcileError::Unstable);
        }
        self.membership.verify(self.directories, &self.new_cas_directories)?;
        let mut manifest = crate::build_manifest(&previous, &second, &std::collections::BTreeMap::new())?;
        let added: Vec<_> = manifest.entries.values()
            .filter(|entry| !previous.entries.contains_key(&entry.entry_id)).cloned().collect();
        if added.len() != 1 || added[0].path != *path || added[0].content.as_ref() != Some(content)
            || previous.entries.iter().any(|(id, entry)| manifest.entries.get(id) != Some(entry))
            || manifest.tombstones != previous.tombstones
        {
            return Err(ReconcileError::Invariant("ordinary CREATE exact original scan delta"));
        }
        let device = self.original.original_device_id()?;
        let seq = manifest.version_vector.get(&device).checked_add(1)
            .ok_or(ReconcileError::Invariant("ordinary CREATE sequence exhausted"))?;
        let operation = sync_extend_core_model::Operation::new(sync_extend_core_model::OperationPayload {
            format_version: sync_extend_core_model::FORMAT_VERSION,
            space_id: manifest.space_id.clone(), origin_device_id: device.clone(),
            origin_seq: seq, causal: manifest.version_vector.clone(),
            created_at_ms: timestamp,
            change: sync_extend_core_model::Change::Put { entry: added[0].clone() },
        })?;
        manifest.version_vector.observe(device, seq);
        self.uncertain = false;
        let root = self.commit_original_history(
            &previous_root, &manifest, std::slice::from_ref(&operation), timestamp)?;
        self.uncertain = true;
        if self.original.original_current_manifest()? != manifest || root != manifest.root()? {
            return Err(ReconcileError::Invariant("ordinary CREATE actual Journal result differs"));
        }
        self.ledger.ordinary_file_outcome(&mut receipt, "committed", created_key, Some(&root))?;
        crate::fault::checkpoint("node_ordinary_create_commit_recorded");
        self.ordinary_files.push(receipt);
        self.uncertain = false;
        self.verify()?;
        Ok(root)
    }
}

struct OrdinaryCasDirectory {
    creator: sync_extend_platform_fs::LockedDirectoryMutation,
    path: std::path::PathBuf,
    key: sync_extend_platform_fs::FileKey,
    parent: sync_extend_platform_fs::FileKey,
}
impl OrdinaryCasDirectory {
    fn verify(&self) -> Result<()> {
        let original = self.creator.original_creation()?;
        if original.key()? != self.key || original.parent_key()? != self.parent
            || !self.creator.matches_path(&self.path)?
        {
            return Err(ReconcileError::Invariant("new CAS original bucket identity/slot"));
        }
        Ok(())
    }
}
impl OriginalNodeWriteSession<'_> {
    /// Create a new file from bounded caller bytes through actual original
    /// bucket/chunk/file CREATE. No writable CAS or Journal reference escapes.
    pub fn create_original_file_from_bytes(
        &mut self, path: &sync_extend_core_model::PortablePath,
        bytes: &[u8], timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        let content = self.prepare_original_content(path, bytes, None)?;
        let root = self.create_original_file_from_manifest(path, &content, timestamp)?;
        self.uncertain = true;
        self.commit_original_new_cas_evidence(&root)?;
        self.uncertain = false;
        self.verify()?;
        Ok(root)
    }
    fn prepare_original_content(
        &mut self, path: &sync_extend_core_model::PortablePath, bytes: &[u8],
        replacing: Option<&sync_extend_core_model::Entry>,
    ) -> Result<sync_extend_core_model::FileManifest> {
        use std::io::Write;
        self.verify()?;
        let max_file_bytes = self.limits.max_file_bytes;
        let max_scan_chunks = self.limits.max_scan_chunks;
        let max_scan_bytes = self.limits.max_scan_bytes;
        if !self.wrote || bytes.len() as u64 > max_scan_bytes
            || self.new_cas_evidence.len() >= 1024 || self.ordinary_files.len() + self.retained_mutations.len() >= 128
        {
            return Err(ReconcileError::ResourceLimit("new content original session/aggregate"));
        }
        let plan = sync_extend_cas::plan_bounded_content(
            bytes, max_file_bytes.min(8 * 1024 * 1024), max_scan_chunks.min(128))?;
        if self.new_cas_evidence.len() + plan.chunks.len() * 2 > 1024
            || bytes.len() as u64 > self.limits.max_staging_bytes
        {
            return Err(ReconcileError::ResourceLimit("new content prospective evidence/staging"));
        }
        let previous = self.original_current_manifest()?;
        let entries = previous.entries.len().checked_add(usize::from(replacing.is_none()))
            .ok_or(ReconcileError::ResourceLimit("new content prospective entry count"))?;
        let (current_bytes, current_chunks) = previous.entries.values()
            .filter_map(|entry| entry.content.as_ref())
            .try_fold((0u64, 0usize), |(size, chunks), content| -> Result<_> {
                Ok((size.checked_add(content.length)
                    .ok_or(ReconcileError::ResourceLimit("new content current byte overflow"))?,
                    chunks.checked_add(content.chunks.len())
                    .ok_or(ReconcileError::ResourceLimit("new content current chunk overflow"))?))
            })?;
        let replaced = replacing.and_then(|entry| entry.content.as_ref());
        let current_bytes = current_bytes.checked_sub(replaced.map_or(0, |file| file.length))
            .ok_or(ReconcileError::Invariant("ordinary replacement current bytes"))?;
        let current_chunks = current_chunks.checked_sub(replaced.map_or(0, |file| file.chunks.len()))
            .ok_or(ReconcileError::Invariant("ordinary replacement current chunks"))?;
        if entries > self.limits.max_scan_entries
            || current_bytes.checked_add(bytes.len() as u64)
                .is_none_or(|size| size > self.limits.max_scan_bytes)
            || current_chunks.checked_add(plan.chunks.len())
                .is_none_or(|chunks| chunks > self.limits.max_scan_chunks)
        {
            return Err(ReconcileError::ResourceLimit("new content prospective whole scan bounds"));
        }
        let components: Vec<_> = path.as_str().split('/').map(str::to_owned).collect();
        if components.is_empty() || components.len() > 256
            || components.last().is_some_and(|name| name.starts_with('.'))
            || components.first().is_some_and(|name| name.eq_ignore_ascii_case(".sync-extend"))
        {
            return Err(ReconcileError::Invariant("new content reserved original target"));
        }
        if previous.entries.values().any(|entry|
            entry.path.collision_key() == path.collision_key() && replacing.is_none_or(|old| old.entry_id != entry.entry_id))
        {
            return Err(ReconcileError::Invariant("new content original destination collision"));
        }
        self.directories.parent(super::NodeTargetRoot::Worktree, &components[..components.len()-1])?
            .original_creation()?.verify()?;
        let _cas_session = self.original.acquire_original_cas_session()?;
        // Audit every prospective chunk before the first new directory/file intent.
        for (reference, _) in &plan.chunks {
            self.original.require_original_cas_access(&reference.content_id)?;
        }
        let result = (|| -> Result<_> {
            self.uncertain = true;
            for (reference, data) in &plan.chunks {
                let id = reference.content_id.as_str();
                let bucket_parts = vec!["cas".into(), "objects".into(), id[..2].into()];
                let bucket_path = self.directories.path(super::NodeTargetRoot::Data, &bucket_parts);
                if !self.membership.expected.contains_key(&("data".into(), bucket_parts.clone())) {
                    let parent_parts = &bucket_parts[..2];
                    let parent = self.directories.parent(super::NodeTargetRoot::Data, parent_parts)?;
                    let parent_key = parent.key()?;
                    let mut receipt = self.ledger.intend_ordinary_cas(
                        &bucket_parts, parent_key, "bucket", &ContentId::hash(&[]), 0)?;
                    crate::fault::checkpoint("node_new_cas_bucket_intended");
                    let creator = parent.create_new_child(&id[..2])?;
                    let key = creator.key()?;
                    self.ledger.record_ordinary_cas(&mut receipt, "created", key, None)?;
                    self.ledger.record_ordinary_cas(&mut receipt, "materialized", key, None)?;
                    self.new_cas_directories.insert(bucket_parts.clone(), OrdinaryCasDirectory {
                        creator, path: bucket_path, key, parent: parent_key,
                    });
                    self.membership.expected.get_mut(&("data".into(), parent_parts.to_vec()))
                        .ok_or(ReconcileError::Invariant("new CAS objects membership absent"))?
                        .insert(id[..2].into());
                    self.membership.expected.insert(("data".into(), bucket_parts.clone()),
                        std::collections::BTreeSet::new());
                    self.new_cas_evidence.push(receipt);
                }
                let chunk_parts = [bucket_parts.clone(), vec![id.to_owned()]].concat();
                let exists = self.membership.expected.get(&("data".into(), bucket_parts.clone()))
                    .is_some_and(|names| names.contains(id));
                if exists {
                    continue;
                }
                let parent = if let Some(bucket) = self.new_cas_directories.get(&bucket_parts) {
                    bucket.verify()?;
                    &bucket.creator
                } else {
                    self.directories.parent(super::NodeTargetRoot::Data, &bucket_parts)?
                };
                let parent_key = parent.key()?;
                let mut receipt = self.ledger.intend_ordinary_cas(
                    &chunk_parts, parent_key, "chunk", &reference.content_id, data.len() as u64)?;
                crate::fault::checkpoint("node_new_cas_chunk_intended");
                let mut creator = parent.create_new_file(id)?;
                let key = creator.key()?;
                self.ledger.record_ordinary_cas(&mut receipt, "created", key, None)?;
                creator.writer().write_all(data)?;
                creator.writer().sync_all()?;
                creator.verify_single_link()?;
                self.ledger.record_ordinary_cas(&mut receipt, "materialized", key, None)?;
                let original = creator.release_for_identity_checked_reopen()
                    .map_err(|(_creator, error)| error)?;
                let original = original.retain_read_after_creation()
                    .map_err(|(_original, error)| error)?;
                let original = super::original_content::OriginalContent::Read(original);
                super::read_content::verify(&original, data.len() as u64, &reference.content_id)?;
                self.readers.insert((super::NodeTargetRoot::Data, chunk_parts),
                    super::assembly::ReadContent { original, bytes: data.len() as u64,
                        digest: reference.content_id.clone() });
                self.membership.expected.get_mut(&("data".into(), bucket_parts))
                    .ok_or(ReconcileError::Invariant("new CAS chunk parent membership absent"))?
                    .insert(id.to_owned());
                self.new_cas_evidence.push(receipt);
                crate::fault::checkpoint("node_new_cas_chunk_materialized");
            }
            self.membership.verify(self.directories, &self.new_cas_directories)?;
            self.uncertain = false;
            self.verify()?;
            Ok(plan.manifest)
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

// Original scanner observes bounded bytes through retained original file handles.
struct OriginalSessionScanView<'a, 'scope> {
    session: &'a OriginalNodeWriteSession<'scope>,
}
impl crate::native_file_view::NativeFileView for OriginalSessionScanView<'_, '_> {
    fn verify(&self) -> sync_extend_journal::Result<()> {
        self.session.verify_content_scope()
            .map_err(|_| sync_extend_journal::JournalError::Invariant("original content scan scope changed"))
    }
    fn observe_file(&self, path: &std::path::Path)
        -> sync_extend_journal::Result<Option<sync_extend_journal::NativePublicationFileObservation>>
    {
        self.verify()?;
        let relative = path.strip_prefix(&self.session.worktree)
            .map_err(|_| sync_extend_journal::JournalError::Invariant("original scan escaped worktree"))?;
        let parts: Vec<String> = relative.iter().map(|part| part.to_str().map(str::to_owned)
            .ok_or(sync_extend_journal::JournalError::Invariant("original scan non UTF8")))
            .collect::<sync_extend_journal::Result<_>>()?;
        let content = self.session.readers.get(&(super::NodeTargetRoot::Worktree, parts))
            .ok_or(sync_extend_journal::JournalError::Invariant("original scan unheld file"))?;
        if !content.original.matches_path(path)? {
            return Err(sync_extend_journal::JournalError::Invariant("original scan slot changed"));
        }
        let bytes = original_content_bytes(content, self.session.limits.max_file_bytes)
            .map_err(|_| sync_extend_journal::JournalError::Invariant("original scan bounded bytes differ"))?;
        let planned = sync_extend_cas::plan_bounded_content(
            &bytes, self.session.limits.max_file_bytes.min(8 * 1024 * 1024),
            self.session.limits.max_scan_chunks.min(1024))
            .map_err(|_| sync_extend_journal::JournalError::Invariant("original scan chunk plan refused"))?;
        let key = content.original.original_key()?;
        if planned.manifest.content_id != content.digest || planned.manifest.length != content.bytes {
            return Err(sync_extend_journal::JournalError::Invariant("original scan complete hash changed"));
        }
        self.verify()?;
        Ok(Some(sync_extend_journal::NativePublicationFileObservation {
            metadata: content.original.reader().metadata()?,
            physical_identity: ContentId::hash(format!("windows:{}:{}", key.volume, key.id).as_bytes()),
            content: Some(planned.manifest),
        }))
    }
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
        self.verify()?;
        Ok(0)
    }
}
fn original_content_bytes(content: &super::assembly::ReadContent, maximum: u64) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    if content.bytes > maximum.min(8 * 1024 * 1024) {
        return Err(ReconcileError::ResourceLimit("original content read bound"));
    }
    super::read_content::verify(&content.original, content.bytes, &content.digest)?;
    let mut reader = content.original.reader().try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.take(content.bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != content.bytes || ContentId::hash(&bytes) != content.digest {
        return Err(ReconcileError::Invariant("original bounded content read differs"));
    }
    super::read_content::verify(&content.original, content.bytes, &content.digest)?;
    Ok(bytes)
}
impl OriginalNodeWriteSession<'_> {
    fn verify_content_scope(&self) -> Result<()> {
        self.directories.verify()?;
        self.data_locks.verify()?;
        self.membership.verify(self.directories, &self.new_cas_directories)?;
        for ((root, parts), content) in &self.readers {
            super::read_content::verify(&content.original, content.bytes, &content.digest)?;
            if !content.original.matches_path(&self.directories.path(*root, parts))? {
                return Err(ReconcileError::Invariant("original content scan retained slot differs"));
            }
        }
        Ok(())
    }
    pub fn read_original_file_bytes(&self, path: &sync_extend_core_model::PortablePath) -> Result<Vec<u8>> {
        self.verify()?;
        let parts = path.as_str().split('/').map(str::to_owned).collect();
        let content = self.readers.get(&(super::NodeTargetRoot::Worktree, parts))
            .ok_or(ReconcileError::Invariant("original owned content absent"))?;
        let bytes = original_content_bytes(content, self.limits.max_file_bytes)?;
        self.verify()?;
        Ok(bytes)
    }
}

impl OriginalNodeWriteSession<'_> {
    fn commit_original_new_cas_evidence(&mut self, root: &sync_extend_core_model::SnapshotId) -> Result<()> {
        for receipt in &mut self.new_cas_evidence {
            let actual = self.ledger.ordinary_cas_actual(receipt)?;
            if !self.ledger.ordinary_cas_committed(receipt)? {
                self.ledger.record_ordinary_cas(receipt, "committed", actual, Some(root))?;
            }
        }
        Ok(())
    }
}

struct OrdinaryRetainedMutation {
    directory: sync_extend_platform_fs::LockedDirectoryMutation,
    path: std::path::PathBuf,
    original: super::assembly::ReadContent,
    evidence: super::node_write_transition::OrdinaryMutationEvidence,
}
impl OrdinaryRetainedMutation {
    fn verify(&self, ledger: &super::node_write_transition::OriginalNodeWriteLedger) -> Result<()> {
        self.directory.original_creation()?.verify()?;
        if !self.directory.matches_path(&self.path)?
            || !self.original.original.matches_path(&self.path.join("original"))?
        {
            return Err(ReconcileError::Invariant("ordinary retained original directory differs"));
        }
        super::read_content::verify(&self.original.original, self.original.bytes, &self.original.digest)?;
        let names = std::fs::read_dir(&self.path)?.map(|item| item.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        if names != [std::ffi::OsString::from("original")] {
            return Err(ReconcileError::Invariant("ordinary retained original foreign member"));
        }
        ledger.verify_ordinary_mutation(&self.evidence)
    }
}
impl OriginalNodeWriteSession<'_> {
    pub fn delete_original_file(
        &mut self, path: &sync_extend_core_model::PortablePath, timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.mutate_original_file(path, None, timestamp)
    }
    pub fn replace_original_file_from_bytes(
        &mut self, path: &sync_extend_core_model::PortablePath, bytes: &[u8], timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.mutate_original_file(path, Some(bytes), timestamp)
    }
    fn mutate_original_file(
        &mut self, path: &sync_extend_core_model::PortablePath, bytes: Option<&[u8]>, timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        use sync_extend_core_model::{Change, EntryKind, Operation, OperationPayload, FORMAT_VERSION};
        use std::io::{Seek, SeekFrom, Write};
        self.verify()?;
        if !self.wrote || self.retained_mutations.len() >= 128
            || self.ordinary_files.len() + self.retained_mutations.len() >= 128
        {
            return Err(ReconcileError::ResourceLimit("ordinary mutation prospective attempts"));
        }
        let previous = self.original_current_manifest()?;
        let entry = previous.entries.values().find(|entry| entry.path == *path && entry.kind == EntryKind::File)
            .ok_or(ReconcileError::Invariant("ordinary mutation exact current file absent"))?.clone();
        let content = entry.content.as_ref()
            .ok_or(ReconcileError::Invariant("ordinary mutation original content absent"))?;
        let parts: Vec<String> = path.as_str().split('/').map(str::to_owned).collect();
        let parent_parts = &parts[..parts.len()-1];
        let name = parts.last().ok_or(ReconcileError::Invariant("ordinary mutation target empty"))?;
        let parent = self.directories.parent(super::NodeTargetRoot::Worktree, parent_parts)?;
        let parent_key = parent.key()?;
        let original = self.readers.get(&(super::NodeTargetRoot::Worktree, parts.clone()))
            .ok_or(ReconcileError::Invariant("ordinary mutation original handle absent"))?;
        if !matches!(original.original, super::original_content::OriginalContent::Sealed(_))
            || original.bytes != content.length || original.digest != content.content_id
            || original.original.original_parent_key()? != parent_key
        {
            return Err(ReconcileError::Invariant("ordinary mutation continuous sealed lineage required"));
        }
        let original_key = original.original.original_key()?;
        if self.ledger.ordinary_mutation_volume()? != original_key.volume {
            return Err(ReconcileError::Invariant("ordinary mutation same external volume required"));
        }
        let retained_bytes = self.retained_mutations.iter().try_fold(0u64, |total, retained|
            total.checked_add(retained.original.bytes)
                .ok_or(ReconcileError::ResourceLimit("ordinary mutation retained byte overflow")))?;
        if retained_bytes.checked_add(content.length)
            .is_none_or(|total| total > self.limits.max_staging_bytes)
        {
            return Err(ReconcileError::ResourceLimit("ordinary mutation prospective retained originals"));
        }
        if bytes.is_some_and(|bytes| ContentId::hash(bytes) == content.content_id) {
            return Err(ReconcileError::Invariant("ordinary replacement unchanged content refused"));
        }
        let replacement = if let Some(bytes) = bytes {
            Some(self.prepare_original_content(path, bytes, Some(&entry))?)
        } else { None };
        self.verify()?;
        let parent = self.directories.parent(super::NodeTargetRoot::Worktree, parent_parts)?;
        let previous_root = previous.root()?;
        let evidence = self.ledger.intend_ordinary_mutation(path, &previous_root,
            original_key, parent_key, content, replacement.as_ref())?;
        let _cas_session = self.original.acquire_original_cas_session()?;
        let allowed: std::collections::BTreeSet<_> = previous.entries.values()
            .filter_map(|entry| entry.content.as_ref()).chain(replacement.as_ref())
            .flat_map(|content| &content.chunks).map(|chunk| chunk.content_id.clone()).collect();
        for id in &allowed { self.original.require_original_cas_access(id)?; }
        let cas = sync_extend_cas::Cas::open_existing_session_coordinated(
            &self.directories.roots.data_path.join("cas"), move |id| {
                if allowed.contains(id) { Ok(Box::new(())) }
                else { Err("ordinary mutation unfenced content".into()) }
            }, || Ok(Box::new(())))?;
        self.uncertain = true;
        let result = (|| -> Result<_> {
            crate::fault::checkpoint("node_ordinary_mutation_intended");
            let (directory, retained_path) = self.ledger.create_ordinary_mutation_directory()?;
            if directory.key()?.volume != original_key.volume {
                return Err(ReconcileError::Invariant("ordinary mutation same volume required"));
            }
            let mut evidence = evidence;
            self.ledger.record_ordinary_mutation(&mut evidence, "directory_created", directory.key()?, None)?;
            crate::fault::checkpoint("node_ordinary_mutation_directory_created");
            let original = self.readers.get(&(super::NodeTargetRoot::Worktree, parts.clone()))
                .ok_or(ReconcileError::Invariant("ordinary mutation original disappeared"))?;
            let super::original_content::OriginalContent::Sealed(sealed) = &original.original else {
                return Err(ReconcileError::Invariant("ordinary mutation sealed handle absent"));
            };
            sealed.verify_original()?;
            if !sealed.matches_path(&self.directories.path(super::NodeTargetRoot::Worktree, &parts))? {
                return Err(ReconcileError::Invariant("ordinary mutation original slot changed"));
            }
            sealed.rename_no_replace_in(&directory, "original")?;
            self.ledger.record_ordinary_mutation(&mut evidence, "original_retained", original_key, None)?;
            crate::fault::checkpoint("node_ordinary_mutation_original_retained");
            let original = self.readers.remove(&(super::NodeTargetRoot::Worktree, parts.clone()))
                .ok_or(ReconcileError::Invariant("ordinary mutation original take failed"))?;
            let retained = OrdinaryRetainedMutation { directory, path: retained_path, original, evidence };
            self.retained_mutations.push(retained);
            let members = self.membership.expected.get_mut(&("worktree".into(), parent_parts.to_vec()))
                .ok_or(ReconcileError::Invariant("ordinary mutation parent membership absent"))?;
            if !members.remove(name) {
                return Err(ReconcileError::Invariant("ordinary mutation old member absent"));
            }
            let mut actual_key = original_key;
            if let Some(content) = &replacement {
                let mut creator = parent.create_new_file(name)?;
                actual_key = creator.key()?;
                for reference in &content.chunks {
                    self.original.require_original_cas_access(&reference.content_id)?;
                }
                cas.write_file(content, creator.writer())?;
                creator.writer().flush()?;
                creator.writer().sync_all()?;
                creator.writer().seek(SeekFrom::Start(0))?;
                let original = super::original_content::OriginalContent::Sealed(creator.seal_original()?);
                super::read_content::verify(&original, content.length, &content.content_id)?;
                self.readers.insert((super::NodeTargetRoot::Worktree, parts.clone()),
                    super::assembly::ReadContent { original, bytes: content.length, digest: content.content_id.clone() });
                if !members.insert(name.clone()) {
                    return Err(ReconcileError::Invariant("ordinary mutation duplicate new member"));
                }
            }
            self.verify_content_scope()?;
            let retained = self.retained_mutations.last_mut()
                .ok_or(ReconcileError::Invariant("ordinary mutation retained state absent"))?;
            self.ledger.record_ordinary_mutation(&mut retained.evidence, "target_observed", actual_key, None)?;
            crate::fault::checkpoint("node_ordinary_mutation_target_observed");
            let limits = self.limits.clone();
            let first = crate::scan::scan_native(&self.worktree, &cas, &limits,
                &OriginalSessionScanView { session: self })?;
            crate::fault::checkpoint("node_ordinary_mutation_first_scan");
            let second = crate::scan::scan_native(&self.worktree, &cas, &limits,
                &OriginalSessionScanView { session: self })?;
            if first != second { return Err(ReconcileError::Unstable); }
            let mut manifest = crate::build_manifest(&previous, &second, &std::collections::BTreeMap::new())?;
            if previous.entries.iter().filter(|(id, _)| *id != &entry.entry_id)
                .any(|(id, entry)| manifest.entries.get(id) != Some(entry))
                || manifest.tombstones != previous.tombstones
            {
                return Err(ReconcileError::Invariant("ordinary mutation unrelated scan delta"));
            }
            let change = if let Some(content) = &replacement {
                let actual = manifest.entries.get(&entry.entry_id)
                    .ok_or(ReconcileError::Invariant("ordinary replacement original entry id changed"))?;
                if actual.path != *path || actual.content.as_ref() != Some(content)
                    || manifest.entries.len() != previous.entries.len()
                { return Err(ReconcileError::Invariant("ordinary replacement exact delta")); }
                Change::Put { entry: actual.clone() }
            } else {
                if manifest.entries.contains_key(&entry.entry_id) || manifest.entries.len()+1 != previous.entries.len() {
                    return Err(ReconcileError::Invariant("ordinary delete exact delta"));
                }
                Change::Delete { entry_id: entry.entry_id.clone() }
            };
            let device = self.original.original_device_id()?;
            let sequence = manifest.version_vector.get(&device).checked_add(1)
                .ok_or(ReconcileError::Invariant("ordinary mutation sequence exhausted"))?;
            let operation = Operation::new(OperationPayload { format_version: FORMAT_VERSION,
                space_id: manifest.space_id.clone(), origin_device_id: device.clone(), origin_seq: sequence,
                causal: manifest.version_vector.clone(), created_at_ms: timestamp, change })?;
            if let Change::Delete { entry_id } = &operation.payload.change {
                manifest.tombstones.insert(entry_id.clone(), operation.op_id.clone());
            }
            manifest.version_vector.observe(device, sequence);
            self.uncertain = false;
            let root = self.commit_original_history(&previous_root, &manifest, std::slice::from_ref(&operation), timestamp)?;
            self.uncertain = true;
            let retained = self.retained_mutations.last_mut()
                .ok_or(ReconcileError::Invariant("ordinary mutation final retained state absent"))?;
            self.ledger.record_ordinary_mutation(&mut retained.evidence, "committed", actual_key, Some(&root))?;
            self.commit_original_new_cas_evidence(&root)?;
            crate::fault::checkpoint("node_ordinary_mutation_committed");
            self.uncertain = false;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() { self.uncertain = true; }
        result
    }
}
