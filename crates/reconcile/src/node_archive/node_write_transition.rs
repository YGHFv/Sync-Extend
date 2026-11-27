//! Exact original CREATE append frames. Restart bytes never mint living attempts.
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
};
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_platform_fs::{FileKey, OriginalFileCreation, OwnedFileCreation};

mod deployment_close;
mod polling;
pub use deployment_close::DeploymentFreshNodeResourceCloseFailure;
mod runtime_budget;
mod history_close_budget;
pub use runtime_budget::DeploymentNativeRuntimeLiability;
use runtime_budget::{
    FRESH_CAS_OBJECT_MAXIMUM, FRESH_HELD_HISTORY_AGGREGATE_MAXIMUM,
    FRESH_HELD_HISTORY_OBJECT_MAXIMUM, FRESH_HISTORY_GENERATION_MAXIMUM, FRESH_OPERATION_MAXIMUM,
    FRESH_RECEIPT_COUNT_MAXIMUM, FRESH_WORK_DIRECTORY_MAXIMUM, ORIGINAL_WRITE_CAS_RECEIPT_MAXIMUM,
    ORIGINAL_WRITE_FRAMES_MAXIMUM, ORIGINAL_WRITE_MAIN_GROWTH, ORIGINAL_WRITE_MAIN_MAXIMUM,
    ORIGINAL_WRITE_OWNER_MAXIMUM, ORIGINAL_WRITE_RECEIPT_MAXIMUM,
};
pub(super) use runtime_budget::{
    ORIGINAL_WRITE_CAS_EVIDENCE_MAXIMUM, ORIGINAL_WRITE_FILE_MAXIMUM,
    ORIGINAL_WRITE_OPERATION_MAXIMUM, ORIGINAL_WRITE_SIDECAR_LIMIT,
};

pub(super) fn original_native_shm_capacity() -> u64 {
    sync_extend_platform_fs::FRESH_NATIVE_WAL_SHM_CAPACITY
}

pub(super) fn original_write_main_limit(main_bytes: u64) -> Result<u64> {
    main_bytes
        .checked_add(ORIGINAL_WRITE_MAIN_GROWTH)
        .filter(|limit| main_bytes >= 512 && *limit <= ORIGINAL_WRITE_MAIN_MAXIMUM)
        .ok_or(ReconcileError::ResourceLimit(
            "original write Journal byte bound",
        ))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalWriteScope {
    pub(super) version: u32,
    pub(super) archive: ContentId,
    pub(super) completion: ContentId,
    pub(super) session: SpaceId,
    pub(super) worktree_root: String,
    pub(super) data_root: String,
    pub(super) original_main: String,
    pub(super) original_main_parent: String,
    pub(super) mapped_journal: ContentId,
    pub(super) complete_rows: ContentId,
    pub(super) main_bytes: u64,
    pub(super) max_main_bytes: u64,
    pub(super) max_wal_bytes: u64,
    pub(super) max_rollback_bytes: u64,
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WritePhase {
    Intended,
    WalCreated,
    RollbackCreated,
    MainReleaseIntended,
    Ready,
    SessionCommitted,
    Checkpointed,
    Closed,
}
impl WritePhase {
    fn index(self) -> u64 {
        match self {
            Self::Intended => 0,
            Self::WalCreated => 1,
            Self::RollbackCreated => 2,
            Self::MainReleaseIntended => 3,
            Self::Ready => 4,
            Self::SessionCommitted => 5,
            Self::Checkpointed => 6,
            Self::Closed => 7,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WriteRecord {
    version: u32,
    archive: ContentId,
    completion: ContentId,
    session: SpaceId,
    phase: WritePhase,
    main: String,
    wal: Option<String>,
    rollback: Option<String>,
    actual_rows: Option<ContentId>,
}

pub(super) struct OriginalNodeWriteLedger {
    file: OwnedFileCreation,
    path: PathBuf,
    scope: OriginalWriteScope,
    scope_bytes: Vec<u8>,
    owner: super::external::ExternalLedgerOwnership,
    instance: Arc<()>,
    next: u64,
    previous: ContentId,
    wal: Option<FileKey>,
    rollback: Option<FileKey>,
    length: u64,
    poisoned: bool,
}
pub(super) struct OriginalNodeWriteAttempt {
    instance: Arc<()>,
    phase: WritePhase,
}

/// All actual CREATE objects remain retained when construction fails. Disk
/// evidence is never reopened to reconstruct a living owner or attempt.
pub(super) struct OriginalNodeWriteLedgerCreationFailure {
    state: Box<OriginalNodeWriteLedgerCreating>,
    error: ReconcileError,
}
impl OriginalNodeWriteLedgerCreationFailure {
    pub(super) fn error(&self) -> &ReconcileError {
        &self.error
    }
    pub(super) fn created_objects(&self) -> usize {
        usize::from(self.state.owner_lock.is_some())
            + usize::from(self.state.file.is_some())
            + 2 * usize::from(self.state.complete.is_some())
    }

    pub(super) fn close_into_attempt<'scope>(
        self,
        attempt: &mut super::OriginalNodeResourceCloseAttempt<'scope>,
    ) {
        let Self { state, error } = self;
        let OriginalNodeWriteLedgerCreating {
            ancestors,
            owner_lock,
            file,
            complete,
        } = *state;
        attempt
            .native
            .note_error(std::io::Error::other(error.to_string()));
        attempt.keep_context(error);
        if let Some(original) = complete {
            original.close_into_attempt(attempt);
        }
        if let Some(original) = file {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = owner_lock {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(ancestors) = ancestors {
            for (path, original, key) in ancestors.into_iter().rev() {
                attempt.keep_context((path, key));
                attempt.native.close_directory(original);
            }
        }
    }
}
struct OriginalNodeWriteLedgerCreating {
    ancestors: Option<Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory, FileKey)>>,
    owner_lock: Option<OwnedFileCreation>,
    file: Option<OwnedFileCreation>,
    complete: Option<OriginalNodeWriteLedger>,
}
impl OriginalWriteScope {
    pub(super) fn validate(&self) -> Result<()> {
        if !matches!(self.version, 1 | 2)
            || self.main_bytes < 512
            || self.main_bytes > self.max_main_bytes
            || [
                self.max_main_bytes,
                self.max_wal_bytes,
                self.max_rollback_bytes,
            ]
            .iter()
            .any(|bytes| *bytes < 512 || *bytes > 256 * 1024 * 1024)
            || [
                self.max_main_bytes,
                self.max_wal_bytes,
                self.max_rollback_bytes,
            ]
            .iter()
            .try_fold(0u64, |sum, bytes| sum.checked_add(*bytes))
            .is_none_or(|sum| sum > 512 * 1024 * 1024)
        {
            return Err(ReconcileError::Invariant(
                "new write scope exact aggregate budgets",
            ));
        }
        for value in [
            &self.worktree_root,
            &self.data_root,
            &self.original_main,
            &self.original_main_parent,
        ] {
            let parts: Vec<_> = value.split(':').collect();
            if !matches!(parts.as_slice(),["windows",volume,id] if
                volume.parse::<u64>().is_ok_and(|number|number.to_string()==*volume) &&
                id.parse::<u128>().is_ok_and(|number|number.to_string()==*id))
            {
                return Err(ReconcileError::Invariant(
                    "new write scope native key encoding",
                ));
            }
        }
        if self.worktree_root == self.data_root || self.original_main == self.data_root {
            return Err(ReconcileError::Invariant(
                "new write scope distinct roots and main",
            ));
        }
        Ok(())
    }
}

impl OriginalNodeWriteLedger {
    pub(super) fn close_into_attempt<'scope>(
        self,
        attempt: &mut super::OriginalNodeResourceCloseAttempt<'scope>,
    ) {
        let Self {
            file,
            path,
            scope,
            scope_bytes,
            owner,
            instance,
            next,
            previous,
            wal,
            rollback,
            length,
            poisoned,
        } = self;
        attempt.keep_context((
            path,
            scope,
            scope_bytes,
            instance,
            next,
            previous,
            wal,
            rollback,
            length,
            poisoned,
        ));
        file.close_into_attempt(&mut attempt.native);
        owner.close_into_attempt(attempt);
    }

    pub(super) fn path(&self) -> &std::path::Path {
        &self.path
    }

    // Independent original scope and explicit budgets stay visible at issuance.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_for_completed_original(
        external: &std::path::Path,
        local: &super::OriginalRestoredLocalSpace<'_>,
        archive: &super::VerifiedNodeStateArchive,
        manifest: &super::completion::OriginalNodeCompletionManifest,
        original_ledger: &super::NodeRestoreLedger,
        max_main_bytes: u64,
        max_wal_bytes: u64,
        max_rollback_bytes: u64,
    ) -> std::result::Result<Self, OriginalNodeWriteLedgerCreationFailure> {
        let mut state = Box::new(OriginalNodeWriteLedgerCreating {
            ancestors: None,
            owner_lock: None,
            file: None,
            complete: None,
        });
        let result = (|| -> Result<()> {
            local.verify()?;
            original_ledger.verify_external()?;
            local.verify_original_completion_membership(manifest)?;
            manifest.validate()?;
            let completed = original_ledger.read_original_completion_evidence()?.ok_or(
                ReconcileError::Invariant("new framed write requires actual completed original"),
            )?;
            let manifest_bytes = manifest.bytes()?;
            if local.archive_digest() != archive.digest()
                || manifest.archive_digest != *archive.digest()
                || completed.archive_digest() != archive.digest()
                || completed.completion_digest() != &ContentId::hash(&manifest_bytes)
                || completed.ledger_id() != &manifest.ledger_id
                || completed.original_terminal() != &manifest.original_chain_terminal
            {
                return Err(ReconcileError::Invariant(
                    "new framed write exact living completion differs",
                ));
            }
            let main = manifest
                .objects
                .iter()
                .find(|object| object.root == "data" && object.components == ["journal.sqlite"])
                .ok_or(ReconcileError::Invariant("new framed write main absent"))?;
            let scope = OriginalWriteScope {
                version: 2,
                archive: archive.digest().clone(),
                completion: completed.completion_digest().clone(),
                session: SpaceId::random()?,
                worktree_root: manifest.worktree_root_key.clone(),
                data_root: manifest.data_root_key.clone(),
                original_main: main.object_key.clone(),
                original_main_parent: main.parent_key.clone(),
                mapped_journal: manifest.mapped_journal_digest.clone(),
                complete_rows: manifest.journal_rows_digest.clone(),
                main_bytes: main.content_bytes.ok_or(ReconcileError::Invariant(
                    "new framed write main length absent",
                ))?,
                max_main_bytes,
                max_wal_bytes,
                max_rollback_bytes,
            };
            scope.validate()?;
            let scope_bytes = serde_json::to_vec(&scope)?;
            if scope_bytes.is_empty() || scope_bytes.len() > 65536 {
                return Err(ReconcileError::Invariant(
                    "new framed write canonical scope byte bound",
                ));
            }
            if external.starts_with(&manifest.original_worktree_target)
                || external.starts_with(&manifest.original_data_target)
            {
                return Err(ReconcileError::Invariant(
                    "new framed write evidence must be outside original targets",
                ));
            }

            state.ancestors = Some(super::external::hold_ancestors(external)?);
            // Windows spelling is not a physical containment proof. Reject
            // every retained ancestor equal to either target root before CREATE.
            if state.ancestors.as_ref().is_none_or(|ancestors| {
                ancestors.iter().any(|(_, _, key)| {
                    key.to_string() == scope.worktree_root || key.to_string() == scope.data_root
                })
            }) {
                return Err(ReconcileError::Invariant(
                    "new framed external ancestor aliases original target root",
                ));
            }

            let name = format!("node-write-{}", scope.session);
            {
                let parent = &state
                    .ancestors
                    .as_ref()
                    .and_then(|value| value.last())
                    .ok_or(ReconcileError::Invariant(
                        "new framed external parent absent",
                    ))?
                    .1;
                state.owner_lock = Some(parent.create_new_file(&(name.clone() + ".owner"))?);
            }
            let owner_bytes =
                serde_json::to_vec(&(1u32, &scope.archive, &scope.completion, &scope.session))?;
            let owner = state
                .owner_lock
                .as_mut()
                .ok_or(ReconcileError::Invariant("new framed actual owner absent"))?;
            owner.writer().write_all(&owner_bytes)?;
            owner.writer().sync_all()?;
            crate::fault::checkpoint("node_write_actual_external_owner_synced");
            {
                let parent = &state
                    .ancestors
                    .as_ref()
                    .and_then(|value| value.last())
                    .ok_or(ReconcileError::Invariant(
                        "new framed external parent absent",
                    ))?
                    .1;
                state.file = Some(parent.create_new_file(&(name.clone() + ".frames"))?);
            }
            let mut header = Vec::with_capacity(16 + 4 + 64 + scope_bytes.len());
            header.extend_from_slice(b"SYNC-NODE-WRITE1");
            header.extend_from_slice(&(scope_bytes.len() as u32).to_le_bytes());
            header.extend_from_slice(ContentId::hash(&scope_bytes).as_str().as_bytes());
            header.extend_from_slice(&scope_bytes);
            let file = state
                .file
                .as_mut()
                .ok_or(ReconcileError::Invariant("new framed actual file absent"))?;
            file.writer().write_all(&header)?;
            file.writer().sync_all()?;
            crate::fault::checkpoint("node_write_actual_frame_header_synced");
            // No fallible work between the checked ownership move and storing the
            // whole ledger in state. Every later verification failure retains it.
            if state.ancestors.is_none() || state.owner_lock.is_none() || state.file.is_none() {
                return Err(ReconcileError::Invariant(
                    "new framed owner construction incomplete",
                ));
            }
            let owner = super::external::ExternalLedgerOwnership::from_original(
                state.ancestors.take().expect("checked original ancestors"),
                state.owner_lock.take().expect("checked original owner"),
            );
            state.complete = Some(Self {
                file: state.file.take().expect("checked original frames"),
                path: external.join(name + ".frames"),
                scope,
                scope_bytes,
                owner,
                instance: Arc::new(()),
                next: 0,
                previous: ContentId::hash(&[]),
                wal: None,
                rollback: None,
                length: header.len() as u64,
                poisoned: false,
            });
            let result = state
                .complete
                .as_ref()
                .ok_or(ReconcileError::Invariant("new framed whole owner absent"))?;
            result.verify()?;
            result.audit_prefix()?;
            local.verify_original_completion_membership(manifest)?;
            let final_completed = original_ledger.read_original_completion_evidence()?.ok_or(
                ReconcileError::Invariant("original completion lost after framed CREATE"),
            )?;
            if final_completed.completion_digest() != &result.scope.completion
                || final_completed.archive_digest() != &result.scope.archive
            {
                return Err(ReconcileError::Invariant(
                    "original completion changed after framed CREATE",
                ));
            }
            Ok(())
        })();
        match result {
            Ok(()) => match state.complete.take() {
                Some(ledger) => Ok(ledger),
                None => Err(OriginalNodeWriteLedgerCreationFailure {
                    state,
                    error: ReconcileError::Invariant("new framed constructor incomplete"),
                }),
            },
            Err(error) => Err(OriginalNodeWriteLedgerCreationFailure { state, error }),
        }
    }

    fn verify(&self) -> Result<()> {
        self.owner.verify()?;
        self.file.original_creation()?.verify()?;
        self.file.verify_single_link()?;
        if !sync_extend_platform_fs::regular_file_matches_path(self.file.reader(), &self.path)?
            || self.file.reader().metadata()?.len() != self.length
            || self.length > ORIGINAL_WRITE_FRAMES_MAXIMUM
        {
            return Err(ReconcileError::Invariant(
                "new framed write original object/slot/length differs",
            ));
        }
        self.scope.validate()?;
        Ok(())
    }
    pub(super) fn begin(&mut self) -> Result<OriginalNodeWriteAttempt> {
        self.verify()?;
        if self.poisoned || self.next != 0 {
            return Err(ReconcileError::Invariant(
                "new framed write single intention",
            ));
        }
        self.append(WritePhase::Intended, None)?;
        crate::fault::checkpoint("node_write_actual_intended_recorded");
        Ok(OriginalNodeWriteAttempt {
            instance: Arc::clone(&self.instance),
            phase: WritePhase::Intended,
        })
    }
    fn check_attempt(&self, attempt: &OriginalNodeWriteAttempt) -> Result<()> {
        self.verify()?;
        if self.poisoned
            || !Arc::ptr_eq(&self.instance, &attempt.instance)
            || self.next != attempt.phase.index() + 1
        {
            return Err(ReconcileError::Invariant(
                "new framed write attempt is not current original instance",
            ));
        }
        Ok(())
    }
    pub(super) fn session(&self) -> &SpaceId {
        &self.scope.session
    }
    pub(super) fn created_sidecar(
        &mut self,
        attempt: &mut OriginalNodeWriteAttempt,
        original: &OriginalFileCreation<'_>,
        wal: bool,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        original.verify()?;
        let phase = if wal {
            WritePhase::WalCreated
        } else {
            WritePhase::RollbackCreated
        };
        let name = if wal {
            "journal.sqlite-wal"
        } else {
            "journal.sqlite-journal"
        };
        if self.next != phase.index()
            || original.created_component() != name
            || original.parent_key()?.to_string() != self.scope.original_main_parent
        {
            return Err(ReconcileError::Invariant(
                "new framed write sidecar exact CREATE/parent/name",
            ));
        }
        let key = original.key()?;
        if key.to_string() == self.scope.original_main
            || self.wal == Some(key)
            || self.rollback == Some(key)
        {
            return Err(ReconcileError::Invariant(
                "new framed write original sidecar object alias",
            ));
        }
        if wal {
            self.wal = Some(key);
        } else {
            self.rollback = Some(key);
        }
        self.append(phase, None)?;
        attempt.phase = phase;
        crate::fault::checkpoint(match phase {
            WritePhase::WalCreated => "node_write_actual_wal_created_recorded",
            WritePhase::RollbackCreated => "node_write_actual_rollback_created_recorded",
            WritePhase::MainReleaseIntended => "node_write_actual_main_release_intended",
            WritePhase::Ready => "node_write_actual_ready_recorded",
            WritePhase::SessionCommitted => "node_write_actual_session_committed_recorded",
            WritePhase::Checkpointed => "node_write_actual_checkpointed_recorded",
            WritePhase::Closed => "node_write_actual_closed_recorded",
            WritePhase::Intended => "node_write_actual_intended_recorded",
        });
        Ok(())
    }
    pub(super) fn observed(
        &mut self,
        attempt: &mut OriginalNodeWriteAttempt,
        phase: WritePhase,
        main: FileKey,
        wal: FileKey,
        rollback: FileKey,
        rows: Option<ContentId>,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        if !matches!(
            phase,
            WritePhase::MainReleaseIntended
                | WritePhase::Ready
                | WritePhase::SessionCommitted
                | WritePhase::Checkpointed
                | WritePhase::Closed
        ) || self.next != phase.index()
            || main.to_string() != self.scope.original_main
            || self.wal != Some(wal)
            || self.rollback != Some(rollback)
            || (matches!(
                phase,
                WritePhase::Ready | WritePhase::SessionCommitted | WritePhase::Closed
            ) || (self.scope.version == 2 && phase == WritePhase::Checkpointed))
                != rows.is_some()
        {
            return Err(ReconcileError::Invariant(
                "new framed write exact original outcome stage/keys/rows",
            ));
        }
        self.append(phase, rows)?;
        attempt.phase = phase;
        crate::fault::checkpoint(match phase {
            WritePhase::WalCreated => "node_write_actual_wal_created_recorded",
            WritePhase::RollbackCreated => "node_write_actual_rollback_created_recorded",
            WritePhase::MainReleaseIntended => "node_write_actual_main_release_intended",
            WritePhase::Ready => "node_write_actual_ready_recorded",
            WritePhase::SessionCommitted => "node_write_actual_session_committed_recorded",
            WritePhase::Checkpointed => "node_write_actual_checkpointed_recorded",
            WritePhase::Closed => "node_write_actual_closed_recorded",
            WritePhase::Intended => "node_write_actual_intended_recorded",
        });
        Ok(())
    }
    fn append(&mut self, phase: WritePhase, rows: Option<ContentId>) -> Result<()> {
        self.verify()?;
        self.audit_prefix()?;
        if self.poisoned || self.next != phase.index() {
            return Err(ReconcileError::Invariant(
                "new framed write monotonic stage",
            ));
        }
        self.poisoned = true;
        let record = WriteRecord {
            version: self.scope.version,
            archive: self.scope.archive.clone(),
            completion: self.scope.completion.clone(),
            session: self.scope.session.clone(),
            phase,
            main: self.scope.original_main.clone(),
            wal: self.wal.map(|key| key.to_string()),
            rollback: self.rollback.map(|key| key.to_string()),
            actual_rows: rows,
        };
        let bytes = serde_json::to_vec(&record)?;
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err(ReconcileError::Invariant(
                "new framed write record byte bound",
            ));
        }
        let hash = ContentId::hash(&serde_json::to_vec(&(self.next, &self.previous, &bytes))?);
        let mut frame = Vec::with_capacity(4 + 8 + 64 + 64 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&self.next.to_le_bytes());
        frame.extend_from_slice(self.previous.as_str().as_bytes());
        frame.extend_from_slice(hash.as_str().as_bytes());
        frame.extend_from_slice(&bytes);
        let length = self
            .length
            .checked_add(frame.len() as u64)
            .filter(|value| *value <= ORIGINAL_WRITE_FRAMES_MAXIMUM)
            .ok_or(ReconcileError::Invariant(
                "new framed write aggregate before-append bound",
            ))?;
        self.file.writer().seek(SeekFrom::Start(self.length))?;
        crate::fault::checkpoint("node_write_frame_before_append");
        self.file.writer().write_all(&frame)?;
        crate::fault::checkpoint("node_write_frame_written_before_sync");
        self.file.writer().sync_all()?;
        crate::fault::checkpoint("node_write_frame_after_sync");
        self.length = length;
        self.next += 1;
        self.previous = hash;
        self.verify()?;
        self.audit_prefix()?;
        self.poisoned = phase == WritePhase::Closed;
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        let mut bytes = vec![0; self.length as usize];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let count = self
                .file
                .reader()
                .seek_read(&mut bytes[offset..], offset as u64)?;
            if count == 0 {
                return Err(ReconcileError::Invariant(
                    "new framed write actual original short read",
                ));
            }
            offset += count;
        }
        self.verify()?;
        Ok(bytes)
    }
    fn audit_prefix(&self) -> Result<()> {
        let bytes = self.bytes()?;
        let scope_length = self.scope_bytes.len();
        let header = 16 + 4 + 64;
        if bytes.len() < header + scope_length
            || bytes.get(..16) != Some(b"SYNC-NODE-WRITE1")
            || u32::from_le_bytes(
                bytes[16..20]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("frame scope size"))?,
            ) as usize
                != scope_length
            || bytes.get(20..84) != Some(ContentId::hash(&self.scope_bytes).as_str().as_bytes())
            || bytes.get(header..header + scope_length) != Some(self.scope_bytes.as_slice())
        {
            return Err(ReconcileError::Invariant(
                "new framed write exact original header scope/hash",
            ));
        }
        let mut offset = header + scope_length;
        let mut previous = ContentId::hash(&[]);
        let mut next = 0u64;
        let mut wal = None;
        let mut rollback = None;
        let mut terminal_rows = None;
        while offset < bytes.len() {
            if next >= 8 || bytes.len() - offset < 140 {
                return Err(ReconcileError::Invariant(
                    "new framed write incomplete/extra frame",
                ));
            }
            let size = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("frame length"))?,
            ) as usize;
            let index = u64::from_le_bytes(
                bytes[offset + 4..offset + 12]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("frame index"))?,
            );
            if size == 0
                || size > 65536
                || bytes.len() - offset - 140 < size
                || index != next
                || bytes.get(offset + 12..offset + 76) != Some(previous.as_str().as_bytes())
            {
                return Err(ReconcileError::Invariant(
                    "new framed write exact index/previous/length",
                ));
            }
            let payload = &bytes[offset + 140..offset + 140 + size];
            let record: WriteRecord = serde_json::from_slice(payload)?;
            let hash = ContentId::hash(&serde_json::to_vec(&(index, &previous, payload))?);
            if bytes.get(offset + 76..offset + 140) != Some(hash.as_str().as_bytes())
                || serde_json::to_vec(&record)? != payload
                || record.version != self.scope.version
                || record.phase.index() != next
                || record.archive != self.scope.archive
                || record.completion != self.scope.completion
                || record.session != self.scope.session
                || record.main != self.scope.original_main
            {
                return Err(ReconcileError::Invariant(
                    "new framed write canonical record scope/hash",
                ));
            }
            if next == 0 && (record.wal.is_some() || record.rollback.is_some()) {
                return Err(ReconcileError::Invariant(
                    "intended frame contains precreated sidecar",
                ));
            }
            if next == 1 {
                wal = record.wal.clone();
                if wal.is_none() || record.rollback.is_some() {
                    return Err(ReconcileError::Invariant("WAL CREATE frame identity"));
                }
            }
            if next == 2 {
                rollback = record.rollback.clone();
                if rollback.is_none() {
                    return Err(ReconcileError::Invariant("rollback CREATE frame identity"));
                }
            }
            for key in record.wal.iter().chain(record.rollback.iter()) {
                let parts: Vec<_> = key.split(':').collect();
                if !matches!(parts.as_slice(),["windows",volume,id] if
                    volume.parse::<u64>().is_ok_and(|number|number.to_string()==*volume) &&
                    id.parse::<u128>().is_ok_and(|number|number.to_string()==*id))
                    || key == &self.scope.original_main
                {
                    return Err(ReconcileError::Invariant(
                        "new framed write sidecar canonical key and main alias",
                    ));
                }
            }
            if wal.is_some() && wal == rollback {
                return Err(ReconcileError::Invariant(
                    "new framed write WAL rollback aliases",
                ));
            }
            if next >= 1 && record.wal != wal || next >= 2 && record.rollback != rollback {
                return Err(ReconcileError::Invariant(
                    "new framed write original sidecar identity closure",
                ));
            }
            if (matches!(
                record.phase,
                WritePhase::Ready | WritePhase::SessionCommitted | WritePhase::Closed
            ) || (self.scope.version == 2 && record.phase == WritePhase::Checkpointed))
                != record.actual_rows.is_some()
            {
                return Err(ReconcileError::Invariant(
                    "new framed write row digest phase closure",
                ));
            }
            if record.phase == WritePhase::SessionCommitted && self.scope.version == 1
                || record.phase == WritePhase::Checkpointed && self.scope.version == 2
            {
                terminal_rows = record.actual_rows.clone();
            }
            if record.phase == WritePhase::Closed && record.actual_rows != terminal_rows {
                return Err(ReconcileError::Invariant(
                    "write closed/checkpoint row commitment",
                ));
            }
            previous = hash;
            next += 1;
            offset += 140 + size;
        }
        if next != self.next || previous != self.previous {
            return Err(ReconcileError::Invariant(
                "new framed write exact terminal mismatch",
            ));
        }
        Ok(())
    }
}

impl OriginalNodeWriteLedger {
    pub(super) fn verify_terminal_evidence(&self) -> Result<()> {
        self.verify()?;
        self.audit_prefix()?;
        if self.next != 8 || !self.poisoned {
            return Err(ReconcileError::Invariant(
                "new write terminal not actual closed chain",
            ));
        }
        Ok(())
    }
}

/// A pure byte classification. No File, Journal, LocalSpace, native attempt or
/// live owner can be reconstructed from these serializable observations.
#[derive(Serialize)]
pub struct OriginalNodeWriteFrameClassification {
    pub state: &'static str,
    pub complete_frames: u64,
    pub last_phase: Option<&'static str>,
    pub session: Option<SpaceId>,
    pub completion: Option<ContentId>,
    pub native_authority: bool,
    pub cleanup_authority: bool,
}
impl super::VerifiedNodeStateArchive {
    pub fn classify_original_node_write_frames(
        &self,
        bytes: &[u8],
    ) -> OriginalNodeWriteFrameClassification {
        let classify = || -> Result<OriginalNodeWriteFrameClassification> {
            if bytes.len() < 84
                || bytes.len() > 1024 * 1024
                || bytes.get(..16) != Some(b"SYNC-NODE-WRITE1")
            {
                return Err(ReconcileError::Invariant(
                    "restart original frame header/bound",
                ));
            }
            let scope_length = u32::from_le_bytes(
                bytes[16..20]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("restart scope length"))?,
            ) as usize;
            if scope_length == 0 || scope_length > 65536 || bytes.len() - 84 < scope_length {
                return Err(ReconcileError::Invariant(
                    "restart original scope incomplete",
                ));
            }
            let scope_bytes = &bytes[84..84 + scope_length];
            let scope: OriginalWriteScope = serde_json::from_slice(scope_bytes)?;
            scope.validate()?;
            if scope.archive != *self.digest()
                || serde_json::to_vec(&scope)? != scope_bytes
                || bytes.get(20..84) != Some(ContentId::hash(scope_bytes).as_str().as_bytes())
            {
                return Err(ReconcileError::Invariant(
                    "restart exact canonical scope/archive/hash",
                ));
            }
            let mut offset = 84 + scope_length;
            let mut previous = ContentId::hash(&[]);
            let mut count = 0u64;
            let mut wal = None;
            let mut rollback = None;
            let mut last = None;
            let mut committed_rows = None;
            while offset < bytes.len() {
                if count >= 8 || bytes.len() - offset < 140 {
                    return Err(ReconcileError::Invariant("restart incomplete/excess frame"));
                }
                let size = u32::from_le_bytes(
                    bytes[offset..offset + 4]
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("restart frame length"))?,
                ) as usize;
                let index = u64::from_le_bytes(
                    bytes[offset + 4..offset + 12]
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("restart frame index"))?,
                );
                if size == 0
                    || size > 65536
                    || bytes.len() - offset - 140 < size
                    || index != count
                    || bytes.get(offset + 12..offset + 76) != Some(previous.as_str().as_bytes())
                {
                    return Err(ReconcileError::Invariant(
                        "restart frame prefix/index/length",
                    ));
                }
                let payload = &bytes[offset + 140..offset + 140 + size];
                let record: WriteRecord = serde_json::from_slice(payload)?;
                let hash = ContentId::hash(&serde_json::to_vec(&(index, &previous, payload))?);
                if bytes.get(offset + 76..offset + 140) != Some(hash.as_str().as_bytes())
                    || serde_json::to_vec(&record)? != payload
                    || record.version != scope.version
                    || record.phase.index() != count
                    || record.archive != scope.archive
                    || record.completion != scope.completion
                    || record.session != scope.session
                    || record.main != scope.original_main
                {
                    return Err(ReconcileError::Invariant(
                        "restart canonical frame scope/hash",
                    ));
                }
                if count == 0 && (record.wal.is_some() || record.rollback.is_some()) {
                    return Err(ReconcileError::Invariant(
                        "restart Intended has no sidecars",
                    ));
                }
                if count == 1 {
                    wal = record.wal.clone();
                    if wal.is_none() || record.rollback.is_some() {
                        return Err(ReconcileError::Invariant("restart original WAL CREATE"));
                    }
                }
                if count == 2 {
                    rollback = record.rollback.clone();
                    if rollback.is_none() {
                        return Err(ReconcileError::Invariant(
                            "restart original rollback CREATE",
                        ));
                    }
                }
                if count >= 1 && record.wal != wal || count >= 2 && record.rollback != rollback {
                    return Err(ReconcileError::Invariant(
                        "restart original sidecar key closure",
                    ));
                }
                for key in record.wal.iter().chain(record.rollback.iter()) {
                    let parts: Vec<_> = key.split(':').collect();
                    if !matches!(parts.as_slice(),["windows",volume,id] if
                        volume.parse::<u64>().is_ok_and(|number|number.to_string()==*volume) &&
                        id.parse::<u128>().is_ok_and(|number|number.to_string()==*id))
                        || key == &scope.original_main
                    {
                        return Err(ReconcileError::Invariant("restart sidecar key/alias"));
                    }
                }
                if wal.is_some() && wal == rollback
                    || (matches!(
                        record.phase,
                        WritePhase::Ready | WritePhase::SessionCommitted | WritePhase::Closed
                    ) || (scope.version == 2 && record.phase == WritePhase::Checkpointed))
                        != record.actual_rows.is_some()
                {
                    return Err(ReconcileError::Invariant(
                        "restart sidecar alias/rows closure",
                    ));
                }
                if record.phase == WritePhase::SessionCommitted && scope.version == 1
                    || record.phase == WritePhase::Checkpointed && scope.version == 2
                {
                    committed_rows = record.actual_rows.clone();
                }
                if record.phase == WritePhase::Closed && record.actual_rows != committed_rows {
                    return Err(ReconcileError::Invariant(
                        "restart closed/versioned terminal logical rows differ",
                    ));
                }
                last = Some(match record.phase {
                    WritePhase::Intended => "intended",
                    WritePhase::WalCreated => "wal_created",
                    WritePhase::RollbackCreated => "rollback_created",
                    WritePhase::MainReleaseIntended => "main_release_intended",
                    WritePhase::Ready => "ready",
                    WritePhase::SessionCommitted => "session_committed",
                    WritePhase::Checkpointed => "checkpointed",
                    WritePhase::Closed => "closed",
                });
                previous = hash;
                count += 1;
                offset += 140 + size;
            }
            Ok(OriginalNodeWriteFrameClassification {
                state: if count == 8 {
                    "closed_evidence"
                } else {
                    "incomplete_evidence"
                },
                complete_frames: count,
                last_phase: last,
                session: Some(scope.session),
                completion: Some(scope.completion),
                native_authority: false,
                cleanup_authority: false,
            })
        };
        classify().unwrap_or(OriginalNodeWriteFrameClassification {
            state: "refused_evidence",
            complete_frames: 0,
            last_phase: None,
            session: None,
            completion: None,
            native_authority: false,
            cleanup_authority: false,
        })
    }
}

// Separate original CREATE evidence per ordinary action; restart grants no authority.
pub(super) struct OrdinaryFileCreationReceipt {
    file: OwnedFileCreation,
    instance: Arc<()>,
    previous: ContentId,
    length: u64,
    next: u64,
    path: sync_extend_core_model::PortablePath,
    parent: FileKey,
    actual: Option<FileKey>,
    expected_bytes: Vec<u8>,
}
impl OriginalNodeWriteLedger {
    pub(super) fn begin_ordinary_file_creation(
        &self,
        path: &sync_extend_core_model::PortablePath,
        parent: FileKey,
        previous_root: &sync_extend_core_model::SnapshotId,
        content: &sync_extend_core_model::FileManifest,
    ) -> Result<OrdinaryFileCreationReceipt> {
        use std::io::Write;
        self.verify()?;
        self.audit_prefix()?;
        if self.poisoned || self.next != 6 {
            return Err(ReconcileError::Invariant(
                "ordinary CREATE original session not committed",
            ));
        }
        content.validate()?;
        let name = format!("node-ordinary-{}.frames", SpaceId::random()?);
        let mut file = self.owner.create_ordinary_evidence(&name)?;
        let payload = serde_json::to_vec(&(
            1u32,
            &self.scope.session,
            &self.scope.archive,
            &self.scope.completion,
            path,
            parent.to_string(),
            previous_root,
            content,
        ))?;
        if payload.len() > 128 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "ordinary CREATE intent bytes",
            ));
        }
        let previous = ContentId::hash(&payload);
        let mut bytes = b"SYNC-ORDINARY-CREATE1\n".to_vec();
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(previous.as_str().as_bytes());
        bytes.extend_from_slice(&payload);
        file.writer().write_all(&bytes)?;
        file.writer().sync_all()?;
        file.original_creation()?.verify()?;
        let receipt = OrdinaryFileCreationReceipt {
            file,
            instance: Arc::clone(&self.instance),
            previous,
            length: bytes.len() as u64,
            next: 0,
            path: path.clone(),
            parent,
            actual: None,
            expected_bytes: bytes,
        };
        Ok(receipt)
    }
    pub(super) fn ordinary_file_outcome(
        &self,
        receipt: &mut OrdinaryFileCreationReceipt,
        phase: &str,
        actual: FileKey,
        root: Option<&sync_extend_core_model::SnapshotId>,
    ) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.verify()?;
        self.audit_prefix()?;
        receipt.file.original_creation()?.verify()?;
        self.verify_ordinary_file_receipt(receipt)?;
        let expected = match receipt.next {
            0 => "created",
            1 => "materialized",
            2 => "committed",
            _ => {
                return Err(ReconcileError::Invariant(
                    "ordinary CREATE outcome consumed",
                ))
            }
        };
        if self.poisoned
            || self.next != 6
            || !Arc::ptr_eq(&self.instance, &receipt.instance)
            || phase != expected
            || (phase == "committed") != root.is_some()
            || receipt.actual.is_some_and(|key| key != actual)
            || receipt.file.reader().metadata()?.len() != receipt.length
        {
            return Err(ReconcileError::Invariant(
                "ordinary CREATE exact original outcome",
            ));
        }
        let payload = serde_json::to_vec(&(
            receipt.next,
            &receipt.previous,
            phase,
            &receipt.path,
            receipt.parent.to_string(),
            actual.to_string(),
            root,
        ))?;
        let digest = ContentId::hash(&payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(digest.as_str().as_bytes());
        frame.extend_from_slice(&payload);
        let length = receipt
            .length
            .checked_add(frame.len() as u64)
            .filter(|bytes| *bytes <= 256 * 1024)
            .ok_or(ReconcileError::ResourceLimit(
                "ordinary CREATE receipt bytes",
            ))?;
        receipt
            .file
            .writer()
            .seek(SeekFrom::Start(receipt.length))?;
        receipt.file.writer().write_all(&frame)?;
        receipt.file.writer().sync_all()?;
        receipt.expected_bytes.extend_from_slice(&frame);
        receipt.length = length;
        receipt.previous = digest;
        receipt.actual = Some(actual);
        receipt.next += 1;
        self.verify_ordinary_file_receipt(receipt)?;
        Ok(())
    }
    pub(super) fn verify_ordinary_file_receipt(
        &self,
        receipt: &OrdinaryFileCreationReceipt,
    ) -> Result<()> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        receipt.file.original_creation()?.verify()?;
        receipt.file.verify_single_link()?;
        if !Arc::ptr_eq(&self.instance, &receipt.instance)
            || receipt.next > 3
            || receipt.length > ORIGINAL_WRITE_RECEIPT_MAXIMUM
            || receipt.length as usize != receipt.expected_bytes.len()
            || receipt.file.reader().metadata()?.len() != receipt.length
        {
            return Err(ReconcileError::Invariant(
                "ordinary CREATE original receipt identity/length",
            ));
        }
        let mut bytes = vec![0; receipt.length as usize];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let read = receipt
                .file
                .reader()
                .seek_read(&mut bytes[offset..], offset as u64)?;
            if read == 0 {
                return Err(ReconcileError::Invariant(
                    "ordinary CREATE receipt short read",
                ));
            }
            offset += read;
        }
        if bytes != receipt.expected_bytes {
            return Err(ReconcileError::Invariant(
                "ordinary CREATE exact original receipt bytes",
            ));
        }
        Ok(())
    }
}

// Independent exact CREATE evidence for new CAS buckets/chunks.
// Original CREATE handles and byte mirrors remain held until explicit close.
pub(super) struct OrdinaryCasEvidence {
    file: OwnedFileCreation,
    instance: Arc<()>,
    expected: Vec<u8>,
    previous: ContentId,
    next: u64,
    path: Vec<String>,
    parent: FileKey,
    kind: &'static str,
    actual: Option<FileKey>,
}
impl OriginalNodeWriteLedger {
    pub(super) fn intend_ordinary_cas(
        &self,
        path: &[String],
        parent: FileKey,
        kind: &'static str,
        digest: &ContentId,
        bytes: u64,
    ) -> Result<OrdinaryCasEvidence> {
        self.verify()?;
        self.audit_prefix()?;
        if self.poisoned
            || self.next != 6
            || path.len() > 8
            || !matches!(kind, "bucket" | "chunk")
            || bytes > 8 * 1024 * 1024
        {
            return Err(ReconcileError::Invariant(
                "new CAS exact intent bounds/session",
            ));
        }
        let name = format!("node-cas-{}.frames", SpaceId::random()?);
        let mut file = self.owner.create_ordinary_evidence(&name)?;
        let payload = serde_json::to_vec(&(
            1u32,
            &self.scope.session,
            &self.scope.archive,
            &self.scope.completion,
            "data",
            path,
            parent.to_string(),
            kind,
            digest,
            bytes,
        ))?;
        if payload.len() > 16 * 1024 {
            return Err(ReconcileError::ResourceLimit("new CAS intent bytes"));
        }
        let previous = ContentId::hash(&payload);
        let mut expected = b"SYNC-ORDINARY-CAS1\n".to_vec();
        expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        expected.extend_from_slice(previous.as_str().as_bytes());
        expected.extend_from_slice(&payload);
        file.writer().write_all(&expected)?;
        file.writer().sync_all()?;
        let receipt = OrdinaryCasEvidence {
            file,
            instance: Arc::clone(&self.instance),
            expected,
            previous,
            next: 0,
            path: path.to_vec(),
            parent,
            kind,
            actual: None,
        };
        self.verify_ordinary_cas(&receipt)?;
        Ok(receipt)
    }
    pub(super) fn record_ordinary_cas(
        &self,
        receipt: &mut OrdinaryCasEvidence,
        phase: &'static str,
        actual: FileKey,
        root: Option<&sync_extend_core_model::SnapshotId>,
    ) -> Result<()> {
        self.verify_ordinary_cas(receipt)?;
        let expected = match receipt.next {
            0 => "created",
            1 => "materialized",
            2 => "committed",
            _ => return Err(ReconcileError::Invariant("new CAS outcome consumed")),
        };
        if phase != expected
            || (phase == "committed") != root.is_some()
            || receipt.actual.is_some_and(|key| key != actual)
        {
            return Err(ReconcileError::Invariant(
                "new CAS original monotonic outcome",
            ));
        }
        let payload = serde_json::to_vec(&(
            receipt.next,
            &receipt.previous,
            phase,
            "data",
            &receipt.path,
            receipt.parent.to_string(),
            receipt.kind,
            actual.to_string(),
            root,
        ))?;
        let previous = ContentId::hash(&payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(previous.as_str().as_bytes());
        frame.extend_from_slice(&payload);
        if receipt.expected.len() + frame.len() > 64 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "new CAS outcome aggregate bytes",
            ));
        }
        receipt
            .file
            .writer()
            .seek(SeekFrom::Start(receipt.expected.len() as u64))?;
        receipt.file.writer().write_all(&frame)?;
        receipt.file.writer().sync_all()?;
        receipt.expected.extend_from_slice(&frame);
        receipt.previous = previous;
        receipt.actual = Some(actual);
        receipt.next += 1;
        self.verify_ordinary_cas(receipt)
    }
    pub(super) fn ordinary_cas_actual(&self, receipt: &OrdinaryCasEvidence) -> Result<FileKey> {
        self.verify_ordinary_cas(receipt)?;
        receipt
            .actual
            .ok_or(ReconcileError::Invariant("new CAS actual CREATE absent"))
    }
    pub(super) fn ordinary_cas_committed(&self, receipt: &OrdinaryCasEvidence) -> Result<bool> {
        self.verify_ordinary_cas(receipt)?;
        Ok(receipt.next == 3)
    }
    pub(super) fn verify_ordinary_cas(&self, receipt: &OrdinaryCasEvidence) -> Result<()> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        receipt.file.original_creation()?.verify()?;
        receipt.file.verify_single_link()?;
        let expected_length = u64::try_from(receipt.expected.len())
            .map_err(|_| ReconcileError::Invariant("new CAS original evidence length overflow"))?;
        if !Arc::ptr_eq(&self.instance, &receipt.instance)
            || receipt.next > 3
            || expected_length > ORIGINAL_WRITE_CAS_RECEIPT_MAXIMUM
            || receipt.file.reader().metadata()?.len() != expected_length
        {
            return Err(ReconcileError::Invariant(
                "new CAS original evidence bounds/identity",
            ));
        }
        let mut bytes = vec![0; receipt.expected.len()];
        let mut offset = 0;
        while offset < bytes.len() {
            let read = receipt
                .file
                .reader()
                .seek_read(&mut bytes[offset..], offset as u64)?;
            if read == 0 {
                return Err(ReconcileError::Invariant(
                    "new CAS original evidence short read",
                ));
            }
            offset += read;
        }
        if bytes != receipt.expected {
            return Err(ReconcileError::Invariant(
                "new CAS exact original evidence bytes",
            ));
        }
        Ok(())
    }
}

// New live mutation evidence is never reconstructed from stored observations.
pub(super) struct OrdinaryMutationEvidence {
    file: OwnedFileCreation,
    instance: Arc<()>,
    expected: Vec<u8>,
    previous: ContentId,
    phase: u64,
    root: Option<sync_extend_core_model::SnapshotId>,
}
impl OriginalNodeWriteLedger {
    pub(super) fn ordinary_mutation_volume(&self) -> Result<u64> {
        self.verify()?;
        self.owner.ordinary_mutation_volume()
    }
    pub(super) fn intend_ordinary_mutation(
        &self,
        path: &sync_extend_core_model::PortablePath,
        previous: &sync_extend_core_model::SnapshotId,
        original: FileKey,
        parent: FileKey,
        content: &sync_extend_core_model::FileManifest,
        replacement: Option<&sync_extend_core_model::FileManifest>,
    ) -> Result<OrdinaryMutationEvidence> {
        self.verify()?;
        self.audit_prefix()?;
        if self.poisoned || self.next != 6 {
            return Err(ReconcileError::Invariant(
                "ordinary mutation live session unavailable",
            ));
        }
        content.validate()?;
        if let Some(content) = replacement {
            content.validate()?;
        }
        let mut file = self
            .owner
            .create_ordinary_evidence(&format!("node-mutation-{}.frames", SpaceId::random()?))?;
        let payload = serde_json::to_vec(&(
            1u32,
            &self.scope.session,
            &self.scope.archive,
            &self.scope.completion,
            path,
            previous,
            original.to_string(),
            parent.to_string(),
            content,
            replacement,
        ))?;
        if payload.len() > 128 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "ordinary mutation header bytes",
            ));
        }
        let digest = ContentId::hash(&payload);
        let mut expected = b"SYNC-ORDINARY-MUTATION1\n".to_vec();
        expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        expected.extend_from_slice(digest.as_str().as_bytes());
        expected.extend_from_slice(&payload);
        file.writer().write_all(&expected)?;
        file.writer().sync_all()?;
        let evidence = OrdinaryMutationEvidence {
            file,
            instance: Arc::clone(&self.instance),
            expected,
            previous: digest,
            phase: 0,
            root: None,
        };
        self.verify_ordinary_mutation(&evidence)?;
        Ok(evidence)
    }
    pub(super) fn record_ordinary_mutation(
        &self,
        evidence: &mut OrdinaryMutationEvidence,
        phase: &str,
        actual: FileKey,
        root: Option<&sync_extend_core_model::SnapshotId>,
    ) -> Result<()> {
        self.verify_ordinary_mutation(evidence)?;
        let expected = [
            "directory_created",
            "original_retained",
            "target_observed",
            "committed",
        ];
        if evidence.phase >= expected.len() as u64
            || phase != expected[evidence.phase as usize]
            || (phase == "committed") != root.is_some()
        {
            return Err(ReconcileError::Invariant("ordinary mutation exact phase"));
        }
        let payload = serde_json::to_vec(&(
            evidence.phase,
            &evidence.previous,
            phase,
            actual.to_string(),
            root,
        ))?;
        let digest = ContentId::hash(&payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(digest.as_str().as_bytes());
        frame.extend_from_slice(&payload);
        let length = evidence
            .expected
            .len()
            .checked_add(frame.len())
            .filter(|bytes| *bytes <= 256 * 1024)
            .ok_or(ReconcileError::ResourceLimit(
                "ordinary mutation evidence bytes",
            ))?;
        evidence
            .file
            .writer()
            .seek(SeekFrom::Start(evidence.expected.len() as u64))?;
        evidence.file.writer().write_all(&frame)?;
        evidence.file.writer().sync_all()?;
        evidence.expected.extend_from_slice(&frame);
        if evidence.expected.len() != length {
            return Err(ReconcileError::Invariant(
                "ordinary mutation exact receipt length",
            ));
        }
        evidence.previous = digest;
        evidence.phase += 1;
        evidence.root = root.cloned();
        self.verify_ordinary_mutation(evidence)
    }
    pub(super) fn verify_ordinary_mutation(
        &self,
        evidence: &OrdinaryMutationEvidence,
    ) -> Result<()> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        evidence.file.original_creation()?.verify()?;
        evidence.file.verify_single_link()?;
        let expected_length = u64::try_from(evidence.expected.len()).map_err(|_| {
            ReconcileError::Invariant("ordinary mutation original receipt length overflow")
        })?;
        if !Arc::ptr_eq(&self.instance, &evidence.instance)
            || evidence.phase > 4
            || expected_length > ORIGINAL_WRITE_RECEIPT_MAXIMUM
            || evidence.file.reader().metadata()?.len() != expected_length
            || (evidence.phase == 4) != evidence.root.is_some()
        {
            return Err(ReconcileError::Invariant(
                "ordinary mutation exact original receipt",
            ));
        }
        let mut actual = vec![0; evidence.expected.len()];
        let mut offset = 0;
        while offset < actual.len() {
            let count = evidence
                .file
                .reader()
                .seek_read(&mut actual[offset..], offset as u64)?;
            if count == 0 {
                return Err(ReconcileError::Invariant(
                    "ordinary mutation receipt short read",
                ));
            }
            offset += count;
        }
        if actual != evidence.expected {
            return Err(ReconcileError::Invariant(
                "ordinary mutation evidence changed",
            ));
        }
        Ok(())
    }
    pub(super) fn create_ordinary_mutation_directory(
        &self,
    ) -> Result<(sync_extend_platform_fs::LockedDirectoryMutation, PathBuf)> {
        self.verify()?;
        self.owner.create_ordinary_mutation_directory()
    }
}

// Explicit fresh read acquisition is separate from old completion classification.
struct ReacquiredDirectory {
    path: std::path::PathBuf,
    file: sync_extend_platform_fs::LockedDirectory,
    key: sync_extend_platform_fs::FileKey,
}
struct ReacquiredFile {
    path: std::path::PathBuf,
    file: RecoveredFileProtection,
    digest: ContentId,
    bytes: u64,
}
/// Holds only freshly acquired read protection. No write/cleanup/LocalSpace API.
pub struct ReacquiredClosedNodeReadScope {
    directories: Vec<ReacquiredDirectory>,
    files: Vec<ReacquiredFile>,
    worktree: std::path::PathBuf,
    data: std::path::PathBuf,
    expected_membership:
        std::collections::BTreeMap<std::path::PathBuf, std::collections::BTreeSet<String>>,
    manifest: sync_extend_core_model::Manifest,
    rows: ContentId,
}
impl ReacquiredClosedNodeReadScope {
    pub fn manifest(&self) -> Result<sync_extend_core_model::Manifest> {
        self.verify()?;
        Ok(self.manifest.clone())
    }
    pub fn complete_rows_digest(&self) -> Result<ContentId> {
        self.verify()?;
        Ok(self.rows.clone())
    }
    pub fn native_write_authority_available(&self) -> bool {
        false
    }
    pub fn verify(&self) -> Result<()> {
        for directory in &self.directories {
            if directory.file.key()? != directory.key
                || !directory.file.matches_path(&directory.path)?
            {
                return Err(ReconcileError::Invariant(
                    "reacquired directory identity changed",
                ));
            }
            directory.file.require_case_insensitive()?;
        }
        for file in &self.files {
            file.file.verify()?;
            let bytes = file.file.exact_bytes(file.bytes)?;
            if !file.file.matches_path(&file.path)?
                || bytes.len() as u64 != file.bytes
                || ContentId::hash(&bytes) != file.digest
            {
                return Err(ReconcileError::Invariant(
                    "reacquired file exact bytes changed",
                ));
            }
        }
        for (path, expected) in &self.expected_membership {
            let mut actual = std::collections::BTreeSet::new();
            for item in std::fs::read_dir(path)? {
                let entry = item?;
                let metadata = entry.metadata()?;
                if entry.file_type()?.is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant("reacquired foreign reparse"));
                }
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| ReconcileError::Invariant("reacquired member encoding"))?;
                if actual.len() >= expected.len()
                    || !expected.contains(&name)
                    || !actual.insert(name)
                {
                    return Err(ReconcileError::Invariant(
                        "reacquired foreign or excess member",
                    ));
                }
            }
            if &actual != expected {
                return Err(ReconcileError::Invariant(
                    "reacquired complete membership changed",
                ));
            }
        }
        let _ = (&self.worktree, &self.data);
        Ok(())
    }
}
impl super::VerifiedNodeStateArchive {
    pub fn reacquire_closed_node_read_scope(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
    ) -> Result<ReacquiredClosedNodeReadScope> {
        self.reacquire_closed_node_scope_internal(worktree, data, write_frames, bounds, false, None)
    }
    fn reacquire_closed_node_scope_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        exclusive_sqlite: bool,
        fresh_evidence: Option<&FreshSessionRecord>,
    ) -> Result<ReacquiredClosedNodeReadScope> {
        use std::collections::{BTreeMap, BTreeSet};
        use sync_extend_platform_fs::{LockedDirectory, ReacquiredNodeFile};
        if worktree == data
            || worktree.starts_with(data)
            || data.starts_with(worktree)
            || write_frames.starts_with(worktree)
            || write_frames.starts_with(data)
        {
            return Err(ReconcileError::Invariant(
                "recovery disjoint explicit roots required",
            ));
        }
        super::roots::split_target(worktree)?;
        super::roots::split_target(data)?;
        let mut directories = Vec::new();
        for root in [worktree, data] {
            for (path, file, key) in super::external::hold_ancestors(root)? {
                if !directories
                    .iter()
                    .any(|old: &ReacquiredDirectory| old.path == path)
                {
                    directories.push(ReacquiredDirectory { path, file, key });
                }
            }
        }
        let (frame_parent, frame_name) = super::roots::split_target(write_frames)?;
        let frame_directories = super::external::hold_ancestors(frame_parent)?;
        let frame_directory = &frame_directories
            .last()
            .ok_or(ReconcileError::Invariant("recovery frame parent absent"))?
            .1;
        let frames_file = frame_directory.reacquire_existing_node_read_file(frame_name)?;
        let frames = frames_file.exact_bytes(1024 * 1024)?;
        if self.classify_original_node_write_frames(&frames).state != "closed_evidence" {
            return Err(ReconcileError::Invariant(
                "recovery exact closed write evidence required",
            ));
        }
        let scope_length = u32::from_le_bytes(
            frames[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("recovery scope length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&frames[84..84 + scope_length])?;
        let work_key = directories
            .iter()
            .find(|directory| directory.path == worktree)
            .ok_or(ReconcileError::Invariant("recovery work root absent"))?
            .key;
        let data_key = directories
            .iter()
            .find(|directory| directory.path == data)
            .ok_or(ReconcileError::Invariant("recovery data root absent"))?
            .key;
        if scope.worktree_root != work_key.to_string() || scope.data_root != data_key.to_string() {
            return Err(ReconcileError::Invariant(
                "recovery actual roots differ from original closed scope",
            ));
        }
        // Reject an unowned or differently cased SHM by directory membership
        // before opening any SQLite file with exclusive sharing semantics.
        // Windows may report a sharing violation while trying to reopen a
        // foreign SHM, which would obscure the intended fail-closed result.
        let has_expected_shm = fresh_evidence.is_some_and(|evidence| evidence.wal_shm.is_some());
        for entry in std::fs::read_dir(data)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("recovery data member encoding"))?;
            if name.eq_ignore_ascii_case("journal.sqlite-shm")
                && (name != "journal.sqlite-shm" || !has_expected_shm)
            {
                return Err(ReconcileError::Invariant(
                    "recovery exact main and nonhot sidecar scope required",
                ));
            }
        }
        let mut offset = 84 + scope_length;
        let mut terminal = None;
        while offset < frames.len() {
            let length = u32::from_le_bytes(
                frames[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("recovery record length"))?,
            ) as usize;
            let record: WriteRecord =
                serde_json::from_slice(&frames[offset + 140..offset + 140 + length])?;
            terminal = Some(record);
            offset += 140 + length;
        }
        let closed = terminal.ok_or(ReconcileError::Invariant("recovery terminal frame absent"))?;
        let mut files = Vec::new();
        let mut expected_membership = BTreeMap::new();
        let mut pending = vec![worktree.to_path_buf(), data.to_path_buf()];
        let mut aggregate_bytes = 0u64;
        let mut aggregate_entries = 0usize;
        while let Some(path) = pending.pop() {
            if pending.len() > bounds.max_entries
                || directories.len() > bounds.max_entries
                || path.components().count() > 256
            {
                return Err(ReconcileError::ResourceLimit(
                    "recovery directory aggregate",
                ));
            }
            let held = if let Some(directory) =
                directories.iter().find(|directory| directory.path == path)
            {
                &directory.file
            } else {
                let file = LockedDirectory::open(&path)?;
                file.require_local_ntfs(&path)?;
                file.require_case_insensitive()?;
                let key = file.key()?;
                directories.push(ReacquiredDirectory {
                    path: path.clone(),
                    file,
                    key,
                });
                &directories
                    .last()
                    .ok_or(ReconcileError::Invariant("recovery directory push absent"))?
                    .file
            };
            let mut names = BTreeSet::new();
            for item in std::fs::read_dir(&path)? {
                let entry = item?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| ReconcileError::Invariant("recovery member encoding"))?;
                aggregate_entries = aggregate_entries
                    .checked_add(1)
                    .filter(|entries| *entries <= bounds.max_entries)
                    .ok_or(ReconcileError::ResourceLimit("recovery aggregate entries"))?;
                if names.len() >= bounds.max_entries || !names.insert(name.clone()) {
                    return Err(ReconcileError::ResourceLimit("recovery member count"));
                }
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant("recovery reparse member refused"));
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() {
                    if files.len() >= bounds.max_entries {
                        return Err(ReconcileError::ResourceLimit("recovery file count"));
                    }
                    let file = if exclusive_sqlite
                        && path == data
                        && matches!(
                            name.as_str(),
                            "journal.sqlite"
                                | "journal.sqlite-wal"
                                | "journal.sqlite-journal"
                                | "journal.sqlite-shm"
                        ) {
                        RecoveredFileProtection::Sqlite(
                            held.reacquire_existing_sqlite_exclusive_file(&name)?,
                        )
                    } else if path.starts_with(worktree)
                        && !path.starts_with(worktree.join(".sync-extend"))
                        && fresh_evidence
                            .and_then(|e| e.history_admission.as_ref())
                            .is_some_and(|a| a.mutation_requested)
                    {
                        RecoveredFileProtection::Mutation(
                            held.reacquire_existing_node_mutation_file(&name)?,
                        )
                    } else {
                        let file: ReacquiredNodeFile =
                            held.reacquire_existing_node_read_file(&name)?;
                        RecoveredFileProtection::Read(file)
                    };
                    aggregate_bytes = aggregate_bytes
                        .checked_add(metadata.len())
                        .filter(|bytes| {
                            *bytes <= bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024)
                        })
                        .ok_or(ReconcileError::ResourceLimit(
                            "recovery aggregate file bytes",
                        ))?;
                    let maximum = if path == data && name == "journal.sqlite" {
                        scope.max_main_bytes
                    } else if path == data && name == "journal.sqlite-wal" {
                        scope.max_wal_bytes
                    } else if path == data && name == "journal.sqlite-journal" {
                        scope.max_rollback_bytes
                    } else {
                        8 * 1024 * 1024
                    };
                    let bytes = file.exact_bytes(maximum)?;
                    files.push(ReacquiredFile {
                        path: entry.path(),
                        file,
                        digest: ContentId::hash(&bytes),
                        bytes: bytes.len() as u64,
                    });
                } else {
                    return Err(ReconcileError::Invariant("recovery unsupported member"));
                }
            }
            expected_membership.insert(path, names);
        }
        let main = files
            .iter()
            .find(|file| file.path == data.join("journal.sqlite"))
            .ok_or(ReconcileError::Invariant("recovery main file absent"))?;
        let wal = files
            .iter()
            .find(|file| file.path == data.join("journal.sqlite-wal"))
            .ok_or(ReconcileError::Invariant("recovery WAL file absent"))?;
        let rollback = files
            .iter()
            .find(|file| file.path == data.join("journal.sqlite-journal"))
            .ok_or(ReconcileError::Invariant("recovery rollback file absent"))?;
        if main.file.key()?.to_string() != scope.original_main
            || main.file.parent_key()?.to_string() != scope.original_main_parent
            || Some(wal.file.key()?.to_string()) != closed.wal
            || Some(rollback.file.key()?.to_string()) != closed.rollback
            || wal.bytes != 0
            || (rollback.bytes != 0
                && rollback.file.exact_bytes(rollback.bytes)?.get(..8) != Some(&[0; 8]))
            || files
                .iter()
                .any(|file| file.path == data.join("journal.sqlite-shm"))
                && fresh_evidence.is_none_or(|e| e.wal_shm.is_none())
        {
            return Err(ReconcileError::Invariant(
                "recovery exact main and nonhot sidecar scope required",
            ));
        }
        if let Some((expected_key, expected_digest)) =
            fresh_evidence.and_then(|e| e.wal_shm.as_ref())
        {
            let shm = files
                .iter()
                .find(|f| f.path == data.join("journal.sqlite-shm"))
                .ok_or(ReconcileError::Invariant("WAL2 held SHM absent"))?;
            if shm.file.key()?.to_string() != *expected_key
                || shm.digest != *expected_digest
                || shm.bytes != 1024 * 1024
            {
                return Err(ReconcileError::Invariant("WAL2 exact SHM key bytes"));
            }
        }
        let bytes = main.file.exact_bytes(scope.max_main_bytes)?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            self.space(),
            bounds,
        )?;
        let rows = image.closed_node_complete_rows_digest(self.space(), bounds)?;
        let admitted = if let Some(evidence) = fresh_evidence {
            let keys = [
                main.file.key()?.to_string(),
                wal.file.key()?.to_string(),
                rollback.file.key()?.to_string(),
            ];
            evidence.phase == "closed"
                && evidence.archive == *self.digest()
                && evidence.original_frames == ContentId::hash(&frames)
                && evidence.original_completion == scope.completion
                && evidence.worktree == worktree.to_string_lossy()
                && evidence.data == data.to_string_lossy()
                && evidence.keys == keys
                && evidence.rows == rows
                && evidence.main == ContentId::hash(&bytes)
                && if let Some(admission) = &evidence.history_admission {
                    Some(admission.original_rows.clone()) == closed.actual_rows
                        && admission.final_rows == rows
                        && admission.final_root
                            == manifest_root_from_recovered_image(&image, self.space(), bounds)?
                } else {
                    Some(image.recovered_session_preserved_rows_digest(
                        self.space(),
                        bounds,
                        &scope.session,
                        &evidence.fresh,
                    )?) == closed.actual_rows
                }
        } else {
            Some(rows.clone()) == closed.actual_rows
        };
        if !admitted {
            return Err(ReconcileError::Invariant(
                "recovery complete catalog or rows changed",
            ));
        }
        let manifest = image.with_audited_readonly(self.space(), bounds, |connection| {
            let json: String = connection.query_row(
                "SELECT s.manifest FROM main.current_manifests c JOIN main.snapshots s ON c.snapshot_id=s.snapshot_id WHERE c.space_id=?1",
                [self.space().as_str()], |row| row.get(0))?;
            Ok(serde_json::from_str::<sync_extend_core_model::Manifest>(&json)?)
        })?;
        let device = files
            .iter()
            .find(|file| file.path == data.join("device.secret"))
            .ok_or(ReconcileError::Invariant("recovery device secret absent"))?;
        let original_device = self
            .archive
            .section(&super::ArchiveRole::DeviceSecret)
            .ok_or(ReconcileError::Invariant("recovery original device absent"))?;
        if device.file.exact_bytes(device.bytes)? != original_device {
            return Err(ReconcileError::Invariant(
                "recovery original device secret changed",
            ));
        }
        let marker = files
            .iter()
            .find(|file| file.path == worktree.join(".sync-extend/space-id"))
            .ok_or(ReconcileError::Invariant("recovery marker absent"))?;
        if marker.file.exact_bytes(marker.bytes)? != self.space().as_str().as_bytes() {
            return Err(ReconcileError::Invariant("recovery space marker changed"));
        }
        for root in [data, &worktree.join(".sync-extend")] {
            let sentinel = files
                .iter()
                .find(|file| file.path == root.join("writer.lock"))
                .ok_or(ReconcileError::Invariant("recovery writer sentinel absent"))?;
            if sentinel.bytes != 0 {
                return Err(ReconcileError::Invariant(
                    "recovery writer sentinel bytes differ",
                ));
            }
        }
        for file in files.iter().filter(|file| file.path.starts_with(worktree)) {
            if file.path == worktree.join(".sync-extend/writer.lock")
                || file.path == worktree.join(".sync-extend/space-id")
            {
                continue;
            }
            if !manifest
                .entries
                .values()
                .any(|entry| worktree.join(entry.path.as_str()) == file.path)
            {
                return Err(ReconcileError::Invariant("recovery foreign worktree file"));
            }
        }
        for directory in directories
            .iter()
            .filter(|directory| directory.path.starts_with(worktree))
        {
            if directory.path == worktree || directory.path == worktree.join(".sync-extend") {
                continue;
            }
            if !manifest.entries.values().any(|entry| {
                entry.kind == sync_extend_core_model::EntryKind::Directory
                    && worktree.join(entry.path.as_str()) == directory.path
            }) {
                return Err(ReconcileError::Invariant(
                    "recovery foreign worktree directory",
                ));
            }
        }
        for file in files.iter().filter(|file| file.path.starts_with(data)) {
            let relative = file
                .path
                .strip_prefix(data)
                .map_err(|_| ReconcileError::Invariant("recovery file escaped data"))?;
            let parts: Vec<_> = relative
                .components()
                .filter_map(|component| component.as_os_str().to_str())
                .collect();
            match parts.as_slice() {
                ["writer.lock"
                | "cas-access.lock"
                | "device.secret"
                | "journal.sqlite"
                | "journal.sqlite-wal"
                | "journal.sqlite-journal"] => {}
                ["journal.sqlite-shm"] if fresh_evidence.is_some_and(|e| e.wal_shm.is_some()) => {}
                ["cas", "objects", prefix, id]
                    if id.len() == 64 && *prefix == &id[..2] && file.digest.as_str() == *id => {}
                _ => return Err(ReconcileError::Invariant("recovery foreign data file")),
            }
        }
        let sentinel = files
            .iter()
            .find(|file| file.path == data.join("cas-access.lock"))
            .ok_or(ReconcileError::Invariant("recovery CAS sentinel absent"))?;
        if sentinel.bytes != 0 {
            return Err(ReconcileError::Invariant("recovery CAS sentinel changed"));
        }
        for directory in directories
            .iter()
            .filter(|directory| directory.path.starts_with(data))
        {
            let relative = directory
                .path
                .strip_prefix(data)
                .map_err(|_| ReconcileError::Invariant("recovery directory escaped data"))?;
            let parts: Vec<_> = relative
                .components()
                .filter_map(|component| component.as_os_str().to_str())
                .collect();
            match parts.as_slice() {
                [] | ["cas"] | ["cas", "objects"] | ["cas", "tmp"] => {}
                ["cas", "objects", prefix]
                    if prefix.len() == 2
                        && prefix
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {
                }
                _ => return Err(ReconcileError::Invariant("recovery foreign data directory")),
            }
        }
        for entry in manifest.entries.values() {
            let path = worktree.join(entry.path.as_str());
            if entry.kind == sync_extend_core_model::EntryKind::Directory {
                if !directories.iter().any(|directory| directory.path == path) {
                    return Err(ReconcileError::Invariant(
                        "recovery manifest directory absent",
                    ));
                }
                continue;
            }
            let file = files
                .iter()
                .find(|file| file.path == path)
                .ok_or(ReconcileError::Invariant("recovery manifest file absent"))?;
            let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                "recovery manifest content absent",
            ))?;
            if file.bytes != content.length || file.digest != content.content_id {
                return Err(ReconcileError::Invariant(
                    "recovery manifest exact file differs",
                ));
            }
            for chunk in &content.chunks {
                let id = chunk.content_id.as_str();
                let path = data.join("cas/objects").join(&id[..2]).join(id);
                let actual = files
                    .iter()
                    .find(|file| file.path == path)
                    .ok_or(ReconcileError::Invariant("recovery manifest chunk absent"))?;
                if actual.bytes != u64::from(chunk.length) || actual.digest != chunk.content_id {
                    return Err(ReconcileError::Invariant(
                        "recovery exact CAS chunk differs",
                    ));
                }
            }
        }
        for (path, file, key) in frame_directories {
            if !directories.iter().any(|directory| directory.path == path) {
                directories.push(ReacquiredDirectory { path, file, key });
            }
        }
        files.push(ReacquiredFile {
            path: write_frames.to_owned(),
            file: RecoveredFileProtection::Read(frames_file),
            bytes: frames.len() as u64,
            digest: ContentId::hash(&frames),
        });
        let result = ReacquiredClosedNodeReadScope {
            directories,
            files,
            worktree: worktree.to_owned(),
            data: data.to_owned(),
            expected_membership,
            manifest,
            rows,
        };
        result.verify()?;
        Ok(result)
    }
}

// The locked recovery stage still grants no SQLite write or native cleanup.
struct ReacquiredExternalEvidence {
    path: std::path::PathBuf,
    file: sync_extend_platform_fs::ReacquiredNodeFile,
    digest: ContentId,
    bytes: u64,
}
pub struct ReacquiredClosedNodeLockedReadScope {
    read: ReacquiredClosedNodeReadScope,
    locks: Vec<sync_extend_platform_fs::ReacquiredNodeLock>,
    external: Vec<ReacquiredExternalEvidence>,
    metadata_observations: Vec<HistoryCurrentObject>,
}
impl ReacquiredClosedNodeLockedReadScope {
    pub fn verify(&self) -> Result<()> {
        self.read.verify()?;
        for lock in &self.locks {
            lock.verify()?;
        }
        for evidence in &self.external {
            if !evidence.file.matches_path(&evidence.path)?
                || ContentId::hash(&evidence.file.exact_bytes(evidence.bytes)?) != evidence.digest
            {
                return Err(ReconcileError::Invariant(
                    "recovery locked external bytes changed",
                ));
            }
        }
        Ok(())
    }
    pub fn manifest(&self) -> Result<sync_extend_core_model::Manifest> {
        self.verify()?;
        self.read.manifest()
    }
    pub fn native_write_authority_available(&self) -> bool {
        false
    }
    pub fn acquired_coordination_lock_count(&self) -> usize {
        self.locks.len()
    }
}
impl super::VerifiedNodeStateArchive {
    /// Explicitly reacquire current read protection and five fresh OS locks.
    /// CompletedEvidence is used solely to audit immutable old scope, never to
    /// construct OriginalFileCreation, a writer token or a living old attempt.
    pub fn reacquire_closed_node_locked_read_scope(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<ReacquiredClosedNodeLockedReadScope> {
        self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            false,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn reacquire_closed_node_locked_scope_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        exclusive_sqlite: bool,
        fresh_evidence: Option<&FreshSessionRecord>,
        separated_configs: Option<&crate::SeparatedDeploymentNodeConfigs>,
    ) -> Result<ReacquiredClosedNodeLockedReadScope> {
        let read = self.reacquire_closed_node_scope_internal(
            worktree,
            data,
            write_frames,
            bounds,
            exclusive_sqlite,
            fresh_evidence,
        )?;
        let frame_file = read
            .files
            .iter()
            .find(|file| file.path == write_frames)
            .ok_or(ReconcileError::Invariant("locked recovery frame absent"))?;
        let frames = frame_file.file.exact_bytes(frame_file.bytes)?;
        let size = u32::from_le_bytes(
            frames[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("locked recovery scope length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&frames[84..84 + size])?;
        let parent = write_frames.parent().ok_or(ReconcileError::Invariant(
            "locked recovery external parent absent",
        ))?;
        if restore_ledger.parent() != Some(parent) {
            return Err(ReconcileError::Invariant(
                "locked recovery exact external ledger parent",
            ));
        }
        let mut locks = Vec::new();
        for (path, shared) in [
            (data.join("writer.lock"), false),
            (worktree.join(".sync-extend/writer.lock"), false),
            (data.join("cas-access.lock"), true),
        ] {
            let file = read
                .files
                .iter()
                .find(|file| file.path == path)
                .ok_or(ReconcileError::Invariant("locked recovery sentinel absent"))?;
            if file.bytes != 0 {
                return Err(ReconcileError::Invariant(
                    "locked recovery nonempty sentinel",
                ));
            }
            locks.push(file.file.acquire_fresh_coordination_lock(shared)?);
        }
        let held = read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant(
                "locked recovery external directory absent",
            ))?;
        let write_owner_name = format!("node-write-{}.owner", scope.session);
        let ledger_name = restore_ledger
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ReconcileError::Invariant(
                "locked recovery ledger name encoding",
            ))?;
        let ledger_id: SpaceId = ledger_name
            .strip_prefix("node-restore-")
            .and_then(|name| name.strip_suffix(".sqlite"))
            .ok_or(ReconcileError::Invariant(
                "locked recovery exact restore ledger name",
            ))?
            .parse()?;
        let restore_owner_name = format!("node-restore-{ledger_id}.owner");
        let mut external = Vec::new();
        for (name, expected) in [
            (
                write_owner_name,
                serde_json::to_vec(&(1u32, &scope.archive, &scope.completion, &scope.session))?,
            ),
            (
                restore_owner_name,
                serde_json::to_vec(&(2u32, self.digest(), &ledger_id))?,
            ),
        ] {
            let file = held.file.reacquire_existing_node_read_file(&name)?;
            let bytes = file.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
            if bytes != expected {
                return Err(ReconcileError::Invariant(
                    "locked recovery exact external owner scope",
                ));
            }
            locks.push(file.acquire_fresh_coordination_lock(false)?);
            external.push(ReacquiredExternalEvidence {
                path: parent.join(name),
                digest: ContentId::hash(&bytes),
                bytes: bytes.len() as u64,
                file,
            });
        }
        let file = held.file.reacquire_existing_node_read_file(ledger_name)?;
        let bytes = file.exact_bytes(ledger_bounds.max_database_bytes)?;
        if let Some(configs) = separated_configs {
            configs.verify_for_archive(self, worktree, data)?;
        }
        let (classification, completion) = self.classify_original_node_restart_inner(
            restore_ledger, ledger_bounds, bounds, separated_configs,
        )?;
        if !matches!(classification, super::OriginalNodeRestartClassification::CompletedEvidence {
            completion_digest, .. } if completion_digest == scope.completion)
        {
            return Err(ReconcileError::Invariant(
                "locked recovery original complete ledger differs",
            ));
        }
        external.push(ReacquiredExternalEvidence {
            path: restore_ledger.to_owned(),
            digest: ContentId::hash(&bytes),
            bytes: bytes.len() as u64,
            file,
        });
        let completion = completion.ok_or(ReconcileError::Invariant("recovery completion objects absent"))?;
        let metadata_observations = completion.objects.into_iter()
            .filter(|object| object.root == "worktree" && object.kind == "file")
            .map(|object| HistoryCurrentObject {
                root: "work".into(),
                path: object.components.join("/"),
                directory: false,
                key: object.object_key,
                parent: object.parent_key,
                digest: object.content_digest,
                bytes: object.content_bytes.unwrap_or(0),
                local_metadata: object.local_metadata,
            }).collect();
        let result = ReacquiredClosedNodeLockedReadScope {
            read,
            locks,
            external,
            metadata_observations,
        };
        result.verify()?;
        Ok(result)
    }
}

enum RecoveredFileProtection {
    Mutation(sync_extend_platform_fs::FreshRecoveredMutationFile),
    Created(sync_extend_platform_fs::SealedOriginalFile),
    Read(sync_extend_platform_fs::ReacquiredNodeFile),
    Sqlite(sync_extend_platform_fs::FreshExclusiveSqliteFile),
}
impl RecoveredFileProtection {
    fn verify(&self) -> std::io::Result<()> {
        match self {
            Self::Created(file) => file.verify_original(),
            Self::Mutation(file) => file.verify(),
            Self::Read(file) => file.verify(),
            Self::Sqlite(file) => file.verify(),
        }
    }
    fn key(&self) -> std::io::Result<FileKey> {
        match self {
            Self::Created(file) => file.key(),
            Self::Mutation(file) => file.key(),
            Self::Read(file) => file.key(),
            Self::Sqlite(file) => file.key(),
        }
    }
    fn parent_key(&self) -> std::io::Result<FileKey> {
        match self {
            Self::Created(file) => file.parent_key(),
            Self::Mutation(file) => file.parent_key(),
            Self::Read(file) => file.parent_key(),
            Self::Sqlite(file) => file.parent_key(),
        }
    }
    fn matches_path(&self, path: &std::path::Path) -> std::io::Result<bool> {
        match self {
            Self::Created(file) => file.matches_path(path),
            Self::Mutation(file) => file.matches_path(path),
            Self::Read(file) => file.matches_path(path),
            Self::Sqlite(file) => file.matches_path(path),
        }
    }
    fn exact_bytes(&self, bound: u64) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Created(file) => {
                use std::os::windows::fs::FileExt;
                file.verify_original()?;
                let length = file.reader().metadata()?.len();
                if length > bound {
                    return Err(std::io::Error::other("created content bounded bytes"));
                }
                let mut bytes = vec![0u8; length as usize];
                let mut offset = 0;
                while offset < bytes.len() {
                    let n = file
                        .reader()
                        .seek_read(&mut bytes[offset..], offset as u64)?;
                    if n == 0 {
                        return Err(std::io::Error::other("created content short read"));
                    }
                    offset += n;
                }
                Ok(bytes)
            }
            Self::Mutation(file) => file.exact_bytes(bound),
            Self::Read(file) => file.exact_bytes(bound),
            Self::Sqlite(file) => file.exact_bytes(bound),
        }
    }
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        match self {
            Self::Mutation(file) => file.metadata(),
            Self::Created(file) => file.reader().metadata(),
            Self::Read(file) => file.metadata(),
            Self::Sqlite(_) => Err(std::io::Error::other(
                "native SQLite not ordinary scan file",
            )),
        }
    }
    fn portable_metadata(
        &self,
    ) -> std::io::Result<sync_extend_platform_fs::PortableMetadataCapture> {
        match self {
            Self::Mutation(file) => file.portable_metadata(),
            Self::Created(file) => {
                file.verify_original()?;
                sync_extend_platform_fs::capture_portable_file_metadata(file.reader())
            }
            Self::Read(file) => file.portable_metadata(),
            Self::Sqlite(_) => Err(std::io::Error::other(
                "native SQLite not ordinary scan file",
            )),
        }
    }
    fn acquire_fresh_coordination_lock(
        &self,
        shared: bool,
    ) -> std::io::Result<sync_extend_platform_fs::ReacquiredNodeLock> {
        match self {
            Self::Read(file) => file.acquire_fresh_coordination_lock(shared),
            Self::Mutation(_) | Self::Created(_) | Self::Sqlite(_) => Err(std::io::Error::other(
                "SQLite native file is not a coordination sentinel",
            )),
        }
    }
}

// Fresh native SQLite bridge retains newly acquired objects and all current locks.
pub struct FreshRecoveredNodeSqliteSession {
    read: ReacquiredClosedNodeLockedReadScope,
    native: sync_extend_platform_fs::FreshNativeSqliteConnection,
    bounds: sync_extend_journal::NodeInspectionBounds,
    space: SpaceId,
    previous: SpaceId,
    fresh: SpaceId,
    attempted: bool,
    predecessor_frames: Option<ContentId>,
}
impl FreshRecoveredNodeSqliteSession {
    pub fn verify(&self) -> Result<()> {
        self.read.verify()?;
        self.native.verify()?;
        let bytes = self.native.exact_main_bytes()?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        if !self.attempted
            && image.closed_node_complete_rows_digest(&self.space, self.bounds)?
                != self.read.read.rows
        {
            return Err(ReconcileError::Invariant(
                "fresh native SQLite rows differ before session write",
            ));
        }
        if self.attempted
            && image.recovered_session_preserved_rows_digest(
                &self.space,
                self.bounds,
                &self.previous,
                &self.fresh,
            )? != self.read.read.rows
        {
            return Err(ReconcileError::Invariant(
                "fresh native SQLite changed other catalog or row cells",
            ));
        }
        Ok(())
    }
    pub fn commit_fresh_session(&mut self) -> Result<SpaceId> {
        self.verify()?;
        if self.attempted {
            return Err(ReconcileError::Invariant(
                "fresh recovered session already attempted",
            ));
        }
        self.attempted = true;
        self.native
            .commit_fresh_session(self.previous.as_str(), self.fresh.as_str())?;
        self.verify()?;
        Ok(self.fresh.clone())
    }
    pub fn native_keys(&self) -> Result<[sync_extend_platform_fs::FileKey; 3]> {
        self.verify()?;
        Ok(self.native.keys()?)
    }
}
impl super::VerifiedNodeStateArchive {
    pub fn reacquire_closed_node_sqlite_session(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeSqliteSession> {
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            None,
            None,
        )?;
        let frames = read
            .read
            .files
            .iter()
            .find(|file| file.path == write_frames)
            .ok_or(ReconcileError::Invariant(
                "fresh recovered session frames absent",
            ))?;
        let bytes = frames.file.exact_bytes(frames.bytes)?;
        let size = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("fresh recovered scope length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&bytes[84..84 + size])?;
        let mut files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|file| file.path == data.join(name))
                .ok_or(ReconcileError::Invariant("fresh native SQLite file absent"))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "fresh native SQLite exclusive acquisition required",
                ));
            };
            files.push(file);
        }
        let files = files
            .try_into()
            .map_err(|_| ReconcileError::Invariant("fresh native SQLite complete file set"))?;
        let native = sync_extend_platform_fs::FreshNativeSqliteConnection::open(
            &data.join("journal.sqlite"),
            files,
            [
                scope.max_main_bytes,
                scope.max_wal_bytes,
                scope.max_rollback_bytes,
            ],
        )?;
        let result = FreshRecoveredNodeSqliteSession {
            read,
            native,
            bounds,
            space: self.space().clone(),
            previous: scope.session,
            fresh: SpaceId::random()?,
            attempted: false,
            predecessor_frames: None,
        };
        result.verify()?;
        Ok(result)
    }
}

// Every fresh session intent/commit/close is persisted to its own actual CREATE.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshSessionRecord {
    version: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    original_completion: ContentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_frames: Option<ContentId>,
    previous: SpaceId,
    fresh: SpaceId,
    worktree: String,
    data: String,
    keys: [String; 3],
    rows: ContentId,
    main: ContentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wal_shm: Option<(String, ContentId)>,
    #[serde(skip)]
    history_admission: Option<RecoveredHistoryAdmission>,
}
pub struct FreshDurableRecoveredSession {
    session: FreshRecoveredNodeSqliteSession,
    frames: OwnedFileCreation,
    owner: OwnedFileCreation,
    directory: sync_extend_platform_fs::LockedDirectory,
    path: PathBuf,
    archive: ContentId,
    original_frames: ContentId,
    original_completion: ContentId,
    next: u32,
    previous_record: ContentId,
    poisoned: bool,
    connection_closed: bool,
    native_keys: [String; 3],
}
impl FreshDurableRecoveredSession {
    fn verify_ownership(&self) -> Result<()> {
        if self.poisoned {
            return Err(ReconcileError::Invariant("fresh durable session uncertain"));
        }
        self.frames.original_creation()?.verify()?;
        self.owner.original_creation()?.verify()?;
        self.frames.verify_single_link()?;
        self.owner.verify_single_link()?;
        if !self
            .directory
            .matches_path(self.path.parent().ok_or(ReconcileError::Invariant(
                "fresh durable session parent absent",
            ))?)?
        {
            return Err(ReconcileError::Invariant(
                "fresh durable session parent changed",
            ));
        }
        if self.connection_closed {
            self.session.read.verify()?;
            self.session.native.verify_closed_native_objects()?;
            Ok(())
        } else {
            self.session.verify()
        }
    }
    fn append(&mut self, phase: &str) -> Result<()> {
        self.verify_ownership()?;
        let bytes = if self.connection_closed {
            self.session.native.exact_closed_main_bytes()?
        } else {
            self.session.native.exact_main_bytes()?
        };
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.session.space,
            self.session.bounds,
        )?;
        let rows =
            image.closed_node_complete_rows_digest(&self.session.space, self.session.bounds)?;
        let keys = if self.connection_closed {
            self.native_keys.clone()
        } else {
            self.session.native.keys()?.map(|key| key.to_string())
        };
        let record = FreshSessionRecord {
            version: 2,
            phase: phase.to_owned(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            original_completion: self.original_completion.clone(),
            predecessor_frames: self.session.predecessor_frames.clone(),
            previous: self.session.previous.clone(),
            fresh: self.session.fresh.clone(),
            worktree: self
                .session
                .read
                .read
                .worktree
                .to_string_lossy()
                .into_owned(),
            data: self.session.read.read.data.to_string_lossy().into_owned(),
            keys,
            rows,
            main: ContentId::hash(&bytes),
            wal_shm: None,
            history_admission: None,
        };
        let payload = serde_json::to_vec(&record)?;
        if payload.len() > 65536 || self.next >= 4 {
            return Err(ReconcileError::ResourceLimit(
                "fresh durable session frame bounds",
            ));
        }
        let mut envelope = Vec::with_capacity(payload.len() + 136);
        envelope.extend_from_slice(&self.next.to_le_bytes());
        envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        envelope.extend_from_slice(self.previous_record.as_str().as_bytes());
        envelope.extend_from_slice(ContentId::hash(&payload).as_str().as_bytes());
        envelope.extend_from_slice(&payload);
        if self
            .frames
            .reader()
            .metadata()?
            .len()
            .checked_add(envelope.len() as u64)
            .is_none_or(|n| n > 256 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "fresh durable session aggregate frames",
            ));
        }
        self.poisoned = true;
        self.frames.writer().write_all(&envelope)?;
        self.frames.writer().sync_all()?;
        self.previous_record = ContentId::hash(&envelope);
        self.next += 1;
        self.poisoned = false;
        Ok(())
    }
    pub fn commit_fresh_session(&mut self) -> Result<SpaceId> {
        self.verify_ownership()?;
        if self.next != 1 {
            return Err(ReconcileError::Invariant(
                "fresh durable session intended edge required",
            ));
        }
        let result = self.session.commit_fresh_session();
        let fresh = match result {
            Ok(fresh) => fresh,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.append("committed")?;
        Ok(fresh)
    }
    pub fn checkpoint_and_release(mut self) -> Result<PathBuf> {
        self.verify_ownership()?;
        if self.next != 2 {
            return Err(ReconcileError::Invariant(
                "fresh durable session commit required before checkpoint",
            ));
        }
        // This records the standalone main while the native connection is still
        // held. It is checkpoint evidence, not confirmed native-close evidence.
        self.append("checkpointed")?;
        self.session
            .native
            .close_connection_retaining_native_objects()?;
        self.connection_closed = true;
        self.append("closed")?;
        self.frames.writer().sync_all()?;
        Ok(self.path.clone())
    }
}
impl FreshRecoveredNodeSqliteSession {
    /// Independent actual new external CREATE precedes the first SQLite effect.
    pub fn begin_durable_session(
        self,
        archive: &super::VerifiedNodeStateArchive,
        write_frames: &std::path::Path,
    ) -> Result<FreshDurableRecoveredSession> {
        self.verify()?;
        let original = self
            .read
            .read
            .files
            .iter()
            .find(|file| file.path == write_frames)
            .ok_or(ReconcileError::Invariant(
                "fresh durable original frames absent",
            ))?;
        let bytes = original.file.exact_bytes(original.bytes)?;
        let size = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("fresh durable original scope length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&bytes[84..84 + size])?;
        if scope.archive != *archive.digest() {
            return Err(ReconcileError::Invariant(
                "fresh durable original archive/session differs",
            ));
        }
        let parent = write_frames.parent().ok_or(ReconcileError::Invariant(
            "fresh durable explicit external parent absent",
        ))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant(
                "fresh durable retained external parent absent",
            ))?;
        let name = format!("node-fresh-session-{}", self.fresh);
        let mut owner = held.file.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(1u32, archive.digest(), &self.fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.file.create_new_file(&(name.clone() + ".frames"))?;
        frames.writer().write_all(b"SYNC-FRESH-SESSION1\n")?;
        frames.writer().sync_all()?;
        let directory = sync_extend_platform_fs::LockedDirectory::open(parent)?;
        if directory.key()? != held.key {
            return Err(ReconcileError::Invariant(
                "fresh durable external parent key differs",
            ));
        }
        let native_keys = self.native.keys()?.map(|key| key.to_string());
        let mut result = FreshDurableRecoveredSession {
            session: self,
            frames,
            owner,
            directory,
            path: parent.join(name + ".frames"),
            archive: archive.digest().clone(),
            original_frames: ContentId::hash(&bytes),
            original_completion: scope.completion,
            next: 0,
            previous_record: ContentId::hash(&[]),
            poisoned: false,
            connection_closed: false,
            native_keys,
        };
        result.append("intended")?;
        Ok(result)
    }
}
impl super::VerifiedNodeStateArchive {
    /// Bounded descriptive restart audit. This never produces old attempts or
    /// grants write/cleanup rights, even when a terminal frame is complete.
    pub fn classify_fresh_session_frames(&self, bytes: &[u8]) -> Result<String> {
        const HEADER: &[u8] = b"SYNC-FRESH-SESSION1\n";
        if !bytes.starts_with(HEADER) || bytes.len() > 256 * 1024 {
            return Err(ReconcileError::Invariant(
                "fresh session exact header/aggregate bounds",
            ));
        }
        let mut offset = HEADER.len();
        let mut next = 0u32;
        let mut previous = ContentId::hash(&[]);
        let mut scope: Option<FreshSessionRecord> = None;
        let mut phase = "partial_evidence";
        while offset < bytes.len() {
            let prefix = bytes
                .get(offset..offset + 136)
                .ok_or(ReconcileError::Invariant("fresh session truncated frame"))?;
            let index = u32::from_le_bytes(
                prefix[..4]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("fresh session index"))?,
            );
            let size = u32::from_le_bytes(
                prefix[4..8]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("fresh session size"))?,
            ) as usize;
            if size > 65536
                || index != next
                || next >= 4
                || &prefix[8..72] != previous.as_str().as_bytes()
            {
                return Err(ReconcileError::Invariant("fresh session exact frame chain"));
            }
            let end = offset
                .checked_add(136 + size)
                .ok_or(ReconcileError::ResourceLimit(
                    "fresh session frame arithmetic",
                ))?;
            let payload = bytes
                .get(offset + 136..end)
                .ok_or(ReconcileError::Invariant("fresh session truncated payload"))?;
            if ContentId::hash(payload).as_str().as_bytes() != &prefix[72..136] {
                return Err(ReconcileError::Invariant(
                    "fresh session payload digest differs",
                ));
            }
            let record: FreshSessionRecord = serde_json::from_slice(payload)?;
            if record.wal_shm.is_some()
                || !matches!(record.version, 1 | 2)
                || (record.version == 1 && record.predecessor_frames.is_some())
                || record.archive != *self.digest()
                || record.previous == record.fresh
                || record.phase
                    != ["intended", "committed", "checkpointed", "closed"][next as usize]
                || serde_json::to_vec(&record)? != payload
            {
                return Err(ReconcileError::Invariant(
                    "fresh session canonical exact phase scope",
                ));
            }
            if let Some(original) = &scope {
                if original.version != record.version
                    || original.predecessor_frames != record.predecessor_frames
                    || original.original_frames != record.original_frames
                    || original.original_completion != record.original_completion
                    || original.previous != record.previous
                    || original.fresh != record.fresh
                    || original.worktree != record.worktree
                    || original.data != record.data
                    || original.keys != record.keys
                    || (next >= 2 && (original.rows != record.rows || original.main != record.main))
                {
                    return Err(ReconcileError::Invariant(
                        "fresh session scope changed across frame",
                    ));
                }
            }
            phase = if next == 3 {
                "closed_evidence"
            } else if next == 2 {
                "checkpointed_evidence"
            } else {
                "partial_evidence"
            };
            previous = ContentId::hash(&bytes[offset..end]);
            scope = Some(record);
            next += 1;
            offset = end;
        }
        if next == 0 {
            return Err(ReconcileError::Invariant("fresh session empty ledger"));
        }
        Ok(phase.to_owned())
    }
}

impl super::VerifiedNodeStateArchive {
    /// Explicitly reacquire every current target object and lock. The old disk
    /// record is admission evidence only; it never reconstructs a living owner.
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_fresh_closed_node_sqlite_session(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        fresh_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeSqliteSession> {
        let parent = original_frames.parent().ok_or(ReconcileError::Invariant(
            "fresh restart explicit external parent absent",
        ))?;
        if fresh_frames.parent() != Some(parent) || fresh_frames == original_frames {
            return Err(ReconcileError::Invariant(
                "fresh restart distinct same external frame slot required",
            ));
        }
        let ancestors = super::external::hold_ancestors(parent)?;
        let directory = &ancestors
            .last()
            .ok_or(ReconcileError::Invariant(
                "fresh restart external directory absent",
            ))?
            .1;
        let name = fresh_frames
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ReconcileError::Invariant(
                "fresh restart frame name encoding",
            ))?;
        let actual = directory.reacquire_existing_node_read_file(name)?;
        let bytes = actual.exact_bytes(256 * 1024)?;
        if self.classify_fresh_session_frames(&bytes)? != "closed_evidence" {
            return Err(ReconcileError::Invariant(
                "fresh restart confirmed closed terminal required",
            ));
        }
        let mut offset = b"SYNC-FRESH-SESSION1\n".len();
        let mut terminal = None;
        while offset < bytes.len() {
            let size = u32::from_le_bytes(
                bytes[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("fresh restart frame size"))?,
            ) as usize;
            terminal = Some(serde_json::from_slice::<FreshSessionRecord>(
                &bytes[offset + 136..offset + 136 + size],
            )?);
            offset += 136 + size;
        }
        let terminal =
            terminal.ok_or(ReconcileError::Invariant("fresh restart terminal absent"))?;
        if name != format!("node-fresh-session-{}.frames", terminal.fresh) {
            return Err(ReconcileError::Invariant(
                "fresh restart exact frame component/session differs",
            ));
        }
        let chain = self.acquire_fresh_session_predecessor_chain(
            directory,
            original_frames,
            fresh_frames,
            &bytes,
            &terminal,
        )?;
        let owner_name = format!("node-fresh-session-{}.owner", terminal.fresh);
        let owner = directory.reacquire_existing_node_read_file(&owner_name)?;
        let owner_bytes = owner.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
        if owner_bytes != serde_json::to_vec(&(1u32, self.digest(), &terminal.fresh))? {
            return Err(ReconcileError::Invariant(
                "fresh restart external owner bytes differ",
            ));
        }
        let owner_lock = owner.acquire_fresh_coordination_lock(false)?;
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            Some(&terminal),
            None,
        )?;
        read.locks.push(owner_lock);
        for (evidence, lock) in chain {
            read.external.push(evidence);
            if let Some(lock) = lock {
                read.locks.push(lock);
            }
        }
        read.external.push(ReacquiredExternalEvidence {
            path: fresh_frames.to_owned(),
            file: actual,
            digest: ContentId::hash(&bytes),
            bytes: bytes.len() as u64,
        });
        read.external.push(ReacquiredExternalEvidence {
            path: parent.join(owner_name),
            file: owner,
            digest: ContentId::hash(&owner_bytes),
            bytes: owner_bytes.len() as u64,
        });
        let mut native_files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|file| file.path == data.join(name))
                .ok_or(ReconcileError::Invariant(
                    "fresh restart actual native SQLite absent",
                ))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "fresh restart exclusive acquisition required",
                ));
            };
            native_files.push(file);
        }
        let frame = read
            .read
            .files
            .iter()
            .find(|file| file.path == original_frames)
            .ok_or(ReconcileError::Invariant(
                "fresh restart retained original frames absent",
            ))?;
        let original = frame.file.exact_bytes(frame.bytes)?;
        let size = u32::from_le_bytes(
            original[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("fresh restart original scope size"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&original[84..84 + size])?;
        let native = sync_extend_platform_fs::FreshNativeSqliteConnection::open(
            &data.join("journal.sqlite"),
            native_files
                .try_into()
                .map_err(|_| ReconcileError::Invariant("fresh restart complete native file set"))?,
            [
                scope.max_main_bytes,
                scope.max_wal_bytes,
                scope.max_rollback_bytes,
            ],
        )?;
        let result = FreshRecoveredNodeSqliteSession {
            read,
            native,
            bounds,
            space: self.space().clone(),
            previous: terminal.fresh,
            fresh: SpaceId::random()?,
            attempted: false,
            predecessor_frames: Some(ContentId::hash(&bytes)),
        };
        result.verify()?;
        Ok(result)
    }
}

type HeldFreshSessionPredecessor = (
    ReacquiredExternalEvidence,
    Option<sync_extend_platform_fs::ReacquiredNodeLock>,
);

impl super::VerifiedNodeStateArchive {
    /// Reacquire all actual predecessor files under the same held parent.
    /// Version-one disk bytes remain descriptive and never enter this v2 chain.
    fn acquire_fresh_session_predecessor_chain(
        &self,
        directory: &sync_extend_platform_fs::LockedDirectory,
        original_frames: &std::path::Path,
        current_frames: &std::path::Path,
        current_bytes: &[u8],
        current_terminal: &FreshSessionRecord,
    ) -> Result<Vec<HeldFreshSessionPredecessor>> {
        const HEADER: usize = b"SYNC-FRESH-SESSION1\n".len();
        fn records(bytes: &[u8]) -> Result<Vec<FreshSessionRecord>> {
            let mut out = Vec::new();
            let mut offset = HEADER;
            while offset < bytes.len() {
                let size = u32::from_le_bytes(
                    bytes[offset + 4..offset + 8]
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("fresh chain frame length"))?,
                ) as usize;
                out.push(serde_json::from_slice(
                    &bytes[offset + 136..offset + 136 + size],
                )?);
                offset += 136 + size;
            }
            if out.len() != 4 {
                return Err(ReconcileError::Invariant(
                    "fresh chain actual confirmed close required",
                ));
            }
            Ok(out)
        }
        let original_name = original_frames
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(ReconcileError::Invariant("fresh chain original name"))?;
        let original = directory.reacquire_existing_node_read_file(original_name)?;
        let original_bytes = original.exact_bytes(1024 * 1024)?;
        if self
            .classify_original_node_write_frames(&original_bytes)
            .state
            != "closed_evidence"
        {
            return Err(ReconcileError::Invariant(
                "fresh chain original closed scope",
            ));
        }
        let length = u32::from_le_bytes(
            original_bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("fresh chain scope length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&original_bytes[84..84 + length])?;
        let mut offset = 84 + length;
        let mut original_closed = None;
        while offset < original_bytes.len() {
            let size = u32::from_le_bytes(
                original_bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("fresh chain original record length"))?,
            ) as usize;
            original_closed = Some(serde_json::from_slice::<WriteRecord>(
                &original_bytes[offset + 140..offset + 140 + size],
            )?);
            offset += 140 + size;
        }
        let original_closed = original_closed.ok_or(ReconcileError::Invariant(
            "fresh chain original terminal absent",
        ))?;
        if current_terminal.version != 2
            || current_terminal.original_frames != ContentId::hash(&original_bytes)
            || current_terminal.original_completion != scope.completion
        {
            return Err(ReconcileError::Invariant(
                "fresh chain v2 original actual anchor differs",
            ));
        }
        let parent = current_frames
            .parent()
            .ok_or(ReconcileError::Invariant("fresh chain parent absent"))?;
        let mut held = Vec::new();
        let mut current = records(current_bytes)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut total = current_bytes.len() as u64;
        loop {
            let first = &current[0];
            let terminal = &current[3];
            if !seen.insert(terminal.fresh.clone())
                || seen.len() > 64
                || total > 4 * 1024 * 1024
                || first.version != 2
                || terminal.version != 2
                || terminal.archive != *self.digest()
                || terminal.original_frames != ContentId::hash(&original_bytes)
                || terminal.original_completion != scope.completion
                || terminal.worktree != current_terminal.worktree
                || terminal.data != current_terminal.data
                || terminal.keys != current_terminal.keys
            {
                return Err(ReconcileError::Invariant(
                    "fresh chain bounded original scope differs",
                ));
            }
            if terminal.previous == scope.session {
                if terminal.predecessor_frames.is_some()
                    || Some(first.rows.clone()) != original_closed.actual_rows
                {
                    return Err(ReconcileError::Invariant(
                        "fresh chain root original row anchor differs",
                    ));
                }
                break;
            }
            let expected =
                terminal
                    .predecessor_frames
                    .as_ref()
                    .ok_or(ReconcileError::Invariant(
                        "fresh chain predecessor digest absent",
                    ))?;
            let name = format!("node-fresh-session-{}.frames", terminal.previous);
            let file = directory.reacquire_existing_node_read_file(&name)?;
            let bytes = file.exact_bytes(256 * 1024)?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or(ReconcileError::ResourceLimit("fresh chain aggregate bytes"))?;
            if &ContentId::hash(&bytes) != expected
                || self.classify_fresh_session_frames(&bytes)? != "closed_evidence"
            {
                return Err(ReconcileError::Invariant(
                    "fresh chain actual predecessor hash differs",
                ));
            }
            let previous = records(&bytes)?;
            let old = &previous[3];
            if old.fresh != terminal.previous || old.rows != first.rows || old.main != first.main {
                return Err(ReconcileError::Invariant(
                    "fresh chain predecessor session/rows/main differs",
                ));
            }
            let owner_name = format!("node-fresh-session-{}.owner", old.fresh);
            let owner = directory.reacquire_existing_node_read_file(&owner_name)?;
            let owner_bytes = owner.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
            if owner_bytes != serde_json::to_vec(&(1u32, self.digest(), &old.fresh))? {
                return Err(ReconcileError::Invariant(
                    "fresh chain predecessor owner differs",
                ));
            }
            let lock = owner.acquire_fresh_coordination_lock(false)?;
            held.push((
                ReacquiredExternalEvidence {
                    path: parent.join(name),
                    file,
                    digest: ContentId::hash(&bytes),
                    bytes: bytes.len() as u64,
                },
                None,
            ));
            held.push((
                ReacquiredExternalEvidence {
                    path: parent.join(owner_name),
                    file: owner,
                    digest: ContentId::hash(&owner_bytes),
                    bytes: owner_bytes.len() as u64,
                },
                Some(lock),
            ));
            current = previous;
        }
        held.push((
            ReacquiredExternalEvidence {
                path: original_frames.to_owned(),
                file: original,
                digest: ContentId::hash(&original_bytes),
                bytes: original_bytes.len() as u64,
            },
            None,
        ));
        Ok(held)
    }
}

// Explicit freshly locked closed-node WAL protocol; no historical owner issuance.
pub struct FreshRecoveredNodeWalSession {
    read: ReacquiredClosedNodeLockedReadScope,
    native: sync_extend_journal::FreshNativeWalConnection,
    frames: OwnedFileCreation,
    owner: OwnedFileCreation,
    path: PathBuf,
    bounds: sync_extend_journal::NodeInspectionBounds,
    space: SpaceId,
    previous: SpaceId,
    fresh: SpaceId,
    before_rows: ContentId,
    archive: ContentId,
    original_frames: ContentId,
    next: u32,
    previous_record: ContentId,
    attempted: bool,
    committed: bool,
    closed: bool,
    poisoned: bool,
}
impl FreshRecoveredNodeWalSession {
    fn verify_objects(&self) -> Result<()> {
        if self.poisoned {
            return Err(ReconcileError::Invariant("recovered WAL uncertain"));
        }
        self.read.verify()?;
        self.frames.original_creation()?.verify()?;
        self.owner.original_creation()?.verify()?;
        if self.closed {
            self.native.verify_closed_native_objects()?;
        } else {
            self.native.verify()?;
        }
        Ok(())
    }
    fn record(&mut self, phase: &str, rows: Option<ContentId>) -> Result<()> {
        self.verify_objects()?;
        let value = serde_json::to_vec(&(
            1u32,
            self.next,
            phase,
            &self.archive,
            &self.original_frames,
            &self.previous,
            &self.fresh,
            rows,
        ))?;
        if value.len() > 65536 || self.next >= 4 {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL evidence bound",
            ));
        }
        let digest = ContentId::hash(&value);
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.next.to_le_bytes());
        frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
        frame.extend_from_slice(self.previous_record.as_str().as_bytes());
        frame.extend_from_slice(digest.as_str().as_bytes());
        frame.extend_from_slice(&value);
        if self
            .frames
            .reader()
            .metadata()?
            .len()
            .checked_add(frame.len() as u64)
            .is_none_or(|bytes| bytes > 256 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL aggregate evidence",
            ));
        }
        self.poisoned = true;
        self.frames.writer().write_all(&frame)?;
        self.frames.writer().sync_all()?;
        self.previous_record = ContentId::hash(&frame);
        self.next += 1;
        self.poisoned = false;
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        self.verify_objects()?;
        // The committed main is checked only after the actual checkpoint. An
        // uncheckpointed WAL main is never inspected as a standalone database.
        let bytes = if self.closed {
            self.native.exact_closed_main_bytes()?
        } else {
            self.native.exact_main_bytes()?
        };
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        let rows = if self.committed {
            image.recovered_session_preserved_rows_digest(
                &self.space,
                self.bounds,
                &self.previous,
                &self.fresh,
            )?
        } else {
            image.closed_node_complete_rows_digest(&self.space, self.bounds)?
        };
        if rows != self.before_rows {
            return Err(ReconcileError::Invariant(
                "recovered WAL other catalog rows changed",
            ));
        }
        Ok(())
    }
    pub fn commit_fresh_session(&mut self) -> Result<SpaceId> {
        self.verify()?;
        if self.attempted || self.next != 1 {
            return Err(ReconcileError::Invariant(
                "recovered WAL single intended attempt",
            ));
        }
        self.attempted = true;
        self.poisoned = true;
        self.native
            .commit_fresh_session(self.previous.as_str(), self.fresh.as_str())?;
        crate::fault::checkpoint("recovered_wal_actual_commit_before_checkpoint");
        self.native.checkpoint_to_standalone()?;
        self.committed = true;
        self.poisoned = false;
        self.verify()?;
        self.record("committed_checkpointed", Some(self.before_rows.clone()))?;
        Ok(self.fresh.clone())
    }
    pub fn close_completed(&mut self) -> Result<PathBuf> {
        self.verify()?;
        if !self.committed || self.closed || self.next != 2 {
            return Err(ReconcileError::Invariant(
                "recovered WAL close requires checkpoint",
            ));
        }
        self.record("close_intended", Some(self.before_rows.clone()))?;
        self.poisoned = true;
        self.native.close_connection_retaining_native_objects()?;
        self.closed = true;
        self.poisoned = false;
        self.verify()?;
        self.record("closed", Some(self.before_rows.clone()))?;
        Ok(self.path.clone())
    }
}
impl super::VerifiedNodeStateArchive {
    /// Fresh acquisition checks the complete original closed scope. Evidence
    /// never grants an old CREATE/cleanup token. Unknown SHM is refused before
    /// any new evidence or native object is created.
    pub fn reacquire_closed_node_wal_session(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalSession> {
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            None,
            None,
        )?;
        read.verify()?;
        let frame = read
            .read
            .files
            .iter()
            .find(|file| file.path == write_frames)
            .ok_or(ReconcileError::Invariant(
                "recovered WAL original frame absent",
            ))?;
        let bytes = frame.file.exact_bytes(frame.bytes)?;
        let size = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("recovered WAL original scope size"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&bytes[84..84 + size])?;
        scope.validate()?;
        let total = scope
            .max_main_bytes
            .checked_add(scope.max_wal_bytes)
            .and_then(|n| n.checked_add(scope.max_rollback_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(ReconcileError::ResourceLimit(
                "recovered WAL preeffect aggregate budget",
            ))?;
        if total > 512 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL preeffect aggregate budget",
            ));
        }
        let fresh = SpaceId::random()?;
        let external = write_frames
            .parent()
            .ok_or(ReconcileError::Invariant("recovered WAL external absent"))?;
        let held = read
            .read
            .directories
            .iter()
            .find(|dir| dir.path == external)
            .ok_or(ReconcileError::Invariant(
                "recovered WAL held external absent",
            ))?;
        // Current explicit external membership, held under all acquired
        // original coordination locks, is checked before any new CREATE.
        for (count, entry) in std::fs::read_dir(external)?.enumerate() {
            if u64::try_from(count).map_err(|_| {
                ReconcileError::ResourceLimit("recovered WAL member counter overflow")
            })? >= ledger_bounds.max_records
            {
                return Err(ReconcileError::ResourceLimit(
                    "recovered WAL external member bound",
                ));
            }
            let entry = entry?;
            let component = entry
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("recovered WAL external component"))?;
            if component.starts_with("node-recovered-wal-") {
                return Err(ReconcileError::Invariant(
                    "recovered WAL prior attempt requires explicit recovery",
                ));
            }
        }
        let name = format!("node-recovered-wal-{fresh}");
        let mut owner = held.file.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(1u32, self.digest(), &fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.file.create_new_file(&(name.clone() + ".frames"))?;
        frames.writer().write_all(b"SYNC-RECOVERED-WAL1\n")?;
        let intended = serde_json::to_vec(&(
            1u32,
            0u32,
            "intended",
            self.digest(),
            ContentId::hash(&bytes),
            &scope.session,
            &fresh,
            Option::<ContentId>::None,
        ))?;
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&0u32.to_le_bytes());
        envelope.extend_from_slice(&(intended.len() as u32).to_le_bytes());
        envelope.extend_from_slice(ContentId::hash(&[]).as_str().as_bytes());
        envelope.extend_from_slice(ContentId::hash(&intended).as_str().as_bytes());
        envelope.extend_from_slice(&intended);
        frames.writer().write_all(&envelope)?;
        frames.writer().sync_all()?;
        crate::fault::checkpoint("recovered_wal_actual_intended_before_shm_create");
        let mut native_files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|file| file.path == data.join(name))
                .ok_or(ReconcileError::Invariant(
                    "recovered WAL native file absent",
                ))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "recovered WAL exclusive file required",
                ));
            };
            native_files.push(file);
        }
        let held = read
            .read
            .directories
            .iter()
            .find(|dir| dir.path == data)
            .ok_or(ReconcileError::Invariant("recovered WAL held data absent"))?;
        let shm = held
            .file
            .create_new_file("journal.sqlite-shm")?
            .into_fresh_sqlite_shm()?;
        native_files.push(shm);
        read.read
            .expected_membership
            .get_mut(data)
            .ok_or(ReconcileError::Invariant("recovered WAL membership absent"))?
            .insert("journal.sqlite-shm".into());
        let native = sync_extend_journal::FreshNativeWalConnection::open(
            &data.join("journal.sqlite"),
            native_files
                .try_into()
                .map_err(|_| ReconcileError::Invariant("recovered WAL four files"))?,
            [
                scope.max_main_bytes,
                scope.max_wal_bytes,
                scope.max_rollback_bytes,
                1024 * 1024,
            ],
        )?;
        let before_rows = read.read.rows.clone();
        let result = FreshRecoveredNodeWalSession {
            read,
            native,
            frames,
            owner,
            path: external.join(name + ".frames"),
            bounds,
            space: self.space().clone(),
            previous: scope.session,
            fresh,
            before_rows,
            archive: self.digest().clone(),
            original_frames: ContentId::hash(&bytes),
            next: 1,
            previous_record: ContentId::hash(&envelope),
            attempted: false,
            committed: false,
            closed: false,
            poisoned: false,
        };
        result.verify()?;
        Ok(result)
    }
}

/// Descriptive WAL evidence state; never a native issuer or cleanup receipt.
pub struct RecoveredWalFrameClassification {
    pub state: String,
    pub complete_frames: u32,
    pub native_authority: bool,
    pub cleanup_authority: bool,
}
impl super::VerifiedNodeStateArchive {
    pub fn classify_recovered_wal_frames(&self, bytes: &[u8]) -> RecoveredWalFrameClassification {
        type Record = (
            u32,
            u32,
            String,
            ContentId,
            ContentId,
            SpaceId,
            SpaceId,
            Option<ContentId>,
        );
        let inspect = || -> Result<(String, u32)> {
            const HEADER: &[u8] = b"SYNC-RECOVERED-WAL1\n";
            if !bytes.starts_with(HEADER) || bytes.len() > 256 * 1024 {
                return Err(ReconcileError::Invariant("WAL frame exact header/bounds"));
            }
            let mut offset = HEADER.len();
            let mut next = 0u32;
            let mut previous = ContentId::hash(&[]);
            let mut original: Option<Record> = None;
            let mut rows = None;
            while offset < bytes.len() {
                let prefix = bytes
                    .get(offset..offset + 136)
                    .ok_or(ReconcileError::Invariant("WAL truncated frame prefix"))?;
                let index = u32::from_le_bytes(
                    prefix[..4]
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("WAL index bytes"))?,
                );
                let length = u32::from_le_bytes(
                    prefix[4..8]
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("WAL length bytes"))?,
                ) as usize;
                if index != next
                    || next >= 4
                    || length > 65536
                    || prefix[8..72] != *previous.as_str().as_bytes()
                {
                    return Err(ReconcileError::Invariant("WAL exact frame order"));
                }
                let end = offset
                    .checked_add(136 + length)
                    .ok_or(ReconcileError::ResourceLimit("WAL frame arithmetic"))?;
                let payload = bytes
                    .get(offset + 136..end)
                    .ok_or(ReconcileError::Invariant("WAL truncated payload"))?;
                if ContentId::hash(payload).as_str().as_bytes() != &prefix[72..136] {
                    return Err(ReconcileError::Invariant("WAL exact payload digest"));
                }
                let record: Record = serde_json::from_slice(payload)?;
                if record.0 != 1
                    || record.1 != next
                    || record.3 != *self.digest()
                    || record.5 == record.6
                    || record.2
                        != [
                            "intended",
                            "committed_checkpointed",
                            "close_intended",
                            "closed",
                        ][next as usize]
                    || record.7.is_none() != (next == 0)
                    || serde_json::to_vec(&record)? != payload
                {
                    return Err(ReconcileError::Invariant("WAL exact canonical record"));
                }
                if let Some(first) = &original {
                    if record.3 != first.3
                        || record.4 != first.4
                        || record.5 != first.5
                        || record.6 != first.6
                    {
                        return Err(ReconcileError::Invariant("WAL scope changed across frames"));
                    }
                } else {
                    original = Some(record.clone());
                }
                if let Some(current) = &record.7 {
                    if rows.as_ref().is_some_and(|value| value != current) {
                        return Err(ReconcileError::Invariant(
                            "WAL rows changed after checkpoint",
                        ));
                    }
                    rows = Some(current.clone());
                }
                previous = ContentId::hash(&bytes[offset..end]);
                offset = end;
                next += 1;
            }
            let state = match next {
                0 => "header_only_evidence",
                1 => "intended_evidence",
                2 => "checkpointed_evidence",
                3 => "close_intended_evidence",
                4 => "closed_evidence",
                _ => return Err(ReconcileError::Invariant("WAL excess frames")),
            };
            Ok((state.into(), next))
        };
        match inspect() {
            Ok((state, complete_frames)) => RecoveredWalFrameClassification {
                state,
                complete_frames,
                native_authority: false,
                cleanup_authority: false,
            },
            Err(_) => RecoveredWalFrameClassification {
                state: "refused_evidence".into(),
                complete_frames: 0,
                native_authority: false,
                cleanup_authority: false,
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredWalV2Record {
    version: u32,
    index: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    previous: SpaceId,
    fresh: SpaceId,
    predecessor: Option<ContentId>,
    worktree: String,
    data: String,
    keys: [String; 4],
    rows: ContentId,
    main: ContentId,
    shm: ContentId,
}
fn recovered_wal_v2_records(bytes: &[u8]) -> Result<Vec<RecoveredWalV2Record>> {
    const HEADER: &[u8] = b"SYNC-RECOVERED-WAL2\n";
    if !bytes.starts_with(HEADER) || bytes.len() > 256 * 1024 {
        return Err(ReconcileError::Invariant("WAL2 exact bounded header"));
    }
    let prefix = bytes
        .get(HEADER.len()..HEADER.len() + 4)
        .ok_or(ReconcileError::Invariant("WAL2 intent prefix"))?;
    let length = u32::from_le_bytes(
        prefix
            .try_into()
            .map_err(|_| ReconcileError::Invariant("WAL2 intent length"))?,
    ) as usize;
    if length > 65536 {
        return Err(ReconcileError::ResourceLimit("WAL2 intent bound"));
    }
    let start = HEADER.len() + 4;
    let intent = bytes
        .get(start..start + length)
        .ok_or(ReconcileError::Invariant("WAL2 incomplete intent"))?;
    let admitted: (u32, ContentId, ContentId, SpaceId, SpaceId) = serde_json::from_slice(intent)?;
    if admitted.0 != 2 || admitted.3 == admitted.4 || serde_json::to_vec(&admitted)? != intent {
        return Err(ReconcileError::Invariant("WAL2 canonical intent"));
    }
    let mut offset = start + length;
    let mut previous = ContentId::hash(intent);
    let mut result = Vec::new();
    while offset < bytes.len() {
        let prefix = bytes
            .get(offset..offset + 136)
            .ok_or(ReconcileError::Invariant("WAL2 truncated envelope"))?;
        let index = u32::from_le_bytes(
            prefix[..4]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 index"))?,
        );
        let size = u32::from_le_bytes(
            prefix[4..8]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 size"))?,
        ) as usize;
        if index as usize != result.len()
            || index >= 4
            || size > 65536
            || prefix[8..72] != *previous.as_str().as_bytes()
        {
            return Err(ReconcileError::Invariant("WAL2 order bounds chain"));
        }
        let payload = bytes
            .get(offset + 136..offset + 136 + size)
            .ok_or(ReconcileError::Invariant("WAL2 payload truncated"))?;
        let record: RecoveredWalV2Record = serde_json::from_slice(payload)?;
        if record.version != 2
            || record.index != index
            || record.archive != admitted.1
            || record.original_frames != admitted.2
            || record.previous != admitted.3
            || record.fresh != admitted.4
            || record.phase
                != [
                    "intended",
                    "committed_checkpointed",
                    "close_intended",
                    "closed",
                ][index as usize]
            || serde_json::to_vec(&record)? != payload
            || ContentId::hash(payload).as_str().as_bytes() != &prefix[72..136]
        {
            return Err(ReconcileError::Invariant("WAL2 exact canonical record"));
        }
        if let Some(first) = result.first() {
            let first: &RecoveredWalV2Record = first;
            if record.keys != first.keys
                || record.worktree != first.worktree
                || record.data != first.data
                || record.predecessor != first.predecessor
            {
                return Err(ReconcileError::Invariant(
                    "WAL2 native binding changed across records",
                ));
            }
        }
        if index == 3 {
            let checkpoint: &RecoveredWalV2Record = &result[2];
            if record.rows != checkpoint.rows
                || record.main != checkpoint.main
                || record.shm != checkpoint.shm
            {
                return Err(ReconcileError::Invariant(
                    "WAL2 close bytes changed after checkpoint",
                ));
            }
        }
        offset += 136 + size;
        previous = ContentId::hash(&bytes[offset - 136 - size..offset]);
        result.push(record);
    }
    if result.len() != 4 {
        return Err(ReconcileError::Invariant(
            "WAL2 actual closed terminal required",
        ));
    }
    Ok(result)
}
// Explicit freshly locked closed-node WAL protocol; no historical owner issuance.
#[derive(Clone, Eq, PartialEq)]
struct RecoveredVerificationKey {
    main: ContentId,
    sidecars: [ContentId; 3],
    connection_counters: Option<(u64, u64)>,
    expected_rows: ContentId,
    committed: bool,
}
pub struct FreshRecoveredNodeWalV2Session {
    separated_deployment_configs: Option<crate::SeparatedDeploymentNodeConfigs>,
    read: ReacquiredClosedNodeLockedReadScope,
    native: sync_extend_journal::FreshNativeWalConnection,
    frames: OwnedFileCreation,
    owner: OwnedFileCreation,
    path: PathBuf,
    bounds: sync_extend_journal::NodeInspectionBounds,
    space: SpaceId,
    previous: SpaceId,
    fresh: SpaceId,
    before_rows: ContentId,
    archive: ContentId,
    original_frames: ContentId,
    next: u32,
    previous_record: ContentId,
    attempted: bool,
    committed: bool,
    closed: bool,
    poisoned: bool,
    predecessor: Option<ContentId>,
    native_keys: [String; 4],
    history_count: u32,
    metadata_count: u32,
    retained_metadata_receipts: Vec<live_retention::RecoveredMetadataReceiptProof>,
    new_content_bytes: u64,
    new_file_bytes: u64,
    manifest_entry_limit: usize,
    retained_receipts: std::collections::BTreeMap<String, ReacquiredFile>,
    retained_receipt_bytes: u64,
    history_baseline: Vec<u8>,
    retained_history_evidence: Vec<ReacquiredFile>,
    history_chain_parent: Option<HistoryRestartObject>,
    history_chain_depth: u32,
    history_retained_originals: Vec<HistoryRetainedOriginal>,
    history_retained_directories: Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    retained_mutations: Vec<RecoveredRetainedMutation>,
    mutation_requested: bool,
    created_work_directories:
        std::collections::BTreeMap<PathBuf, sync_extend_platform_fs::LockedDirectoryMutation>,
    new_cas_bytes: u64,
    new_cas_objects: usize,
    new_cas_buckets: std::collections::BTreeMap<PathBuf, RecoveredCasBucket>,
    verified_main: std::cell::RefCell<Option<RecoveredVerificationKey>>,
    polling: Option<polling::RecoveredPollingState>,
    mutation_observation_closed: Option<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
    mutation_observation_failed: Option<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
}
impl FreshRecoveredNodeWalV2Session {
    fn verify_objects(&self) -> Result<()> {
        if self.poisoned {
            return Err(ReconcileError::Invariant("recovered WAL uncertain"));
        }
        if let Some(configs) = &self.separated_deployment_configs {
            configs.verify_acquired_scope(
                &self.archive,
                &self.read.read.worktree,
                &self.read.read.data,
            )?;
        }
        self.read.verify()?;
        for (path, bucket) in &self.new_cas_buckets {
            bucket.verify_exact(path)?;
        }
        for (path, directory) in &self.created_work_directories {
            directory.original_creation()?.verify()?;
            if !directory.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "created work directory key or slot",
                ));
            }
        }
        for retained in &self.retained_mutations {
            retained.verify()?;
        }
        for (path, directory) in &self.history_retained_directories {
            if !directory.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "retained mutation directory changed",
                ));
            }
        }
        for evidence in &self.retained_history_evidence {
            evidence.file.verify()?;
            if !evidence.file.matches_path(&evidence.path)?
                || ContentId::hash(&evidence.file.exact_bytes(evidence.bytes)?) != evidence.digest
            {
                return Err(ReconcileError::Invariant(
                    "history retained closure bytes or identity",
                ));
            }
        }
        for receipt in self.retained_receipts.values() {
            receipt.file.verify()?;
            if !receipt.file.matches_path(&receipt.path)?
                || ContentId::hash(&receipt.file.exact_bytes(receipt.bytes)?) != receipt.digest
            {
                return Err(ReconcileError::Invariant(
                    "recovered held receipt identity or bytes changed",
                ));
            }
        }
        self.frames.original_creation()?.verify()?;
        self.owner.original_creation()?.verify()?;
        if self.closed {
            self.native.verify_closed_native_objects()?;
        } else {
            self.native.verify()?;
        }
        Ok(())
    }
    fn record(&mut self, phase: &str, rows: Option<ContentId>) -> Result<()> {
        self.verify_objects()?;
        let bytes = if self.closed {
            self.native.exact_closed_main_bytes()?
        } else {
            self.native.exact_main_bytes()?
        };
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        let record = RecoveredWalV2Record {
            version: 2,
            index: self.next,
            phase: phase.into(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            previous: self.previous.clone(),
            fresh: self.fresh.clone(),
            predecessor: self.predecessor.clone(),
            worktree: self.read.read.worktree.to_string_lossy().into(),
            data: self.read.read.data.to_string_lossy().into(),
            keys: self.native_keys.clone(),
            rows: image.closed_node_complete_rows_digest(&self.space, self.bounds)?,
            main: ContentId::hash(&bytes),
            shm: ContentId::hash(&self.native.held_shm_bytes()?),
        };
        if (self.next == 0) != rows.is_none() {
            return Err(ReconcileError::Invariant("WAL2 explicit record phase"));
        }
        let value = serde_json::to_vec(&record)?;
        if value.len() > 65536 || self.next >= 4 {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL evidence bound",
            ));
        }
        let digest = ContentId::hash(&value);
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.next.to_le_bytes());
        frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
        frame.extend_from_slice(self.previous_record.as_str().as_bytes());
        frame.extend_from_slice(digest.as_str().as_bytes());
        frame.extend_from_slice(&value);
        if self
            .frames
            .reader()
            .metadata()?
            .len()
            .checked_add(frame.len() as u64)
            .is_none_or(|bytes| bytes > 256 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL aggregate evidence",
            ));
        }
        self.poisoned = true;
        self.frames.writer().write_all(&frame)?;
        self.frames.writer().sync_all()?;
        self.previous_record = ContentId::hash(&frame);
        self.next += 1;
        self.poisoned = false;
        Ok(())
    }
    fn verification_key(&self) -> Result<(Vec<u8>, RecoveredVerificationKey)> {
        let counters = self.native.verification_change_counters()?;
        // The committed main is checked only after the actual checkpoint. An
        // uncheckpointed WAL main is never inspected as a standalone database.
        let bytes = if self.closed {
            self.native.exact_closed_main_bytes()?
        } else {
            self.native.exact_main_bytes()?
        };
        let main_digest = ContentId::hash(&bytes);
        let sidecar_digests = [1usize, 2, 3]
            .map(|index| {
                self.native
                    .exact_sidecar_bytes(index)
                    .map(|bytes| ContentId::hash(&bytes))
            })
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| ReconcileError::Invariant("recovered WAL sidecar digest count"))?;
        if self.native.verification_change_counters()? != counters {
            return Err(ReconcileError::Invariant(
                "recovered WAL verification capture changed",
            ));
        }
        Ok((
            bytes,
            RecoveredVerificationKey {
                main: main_digest,
                sidecars: sidecar_digests,
                connection_counters: counters,
                expected_rows: self.before_rows.clone(),
                committed: self.committed,
            },
        ))
    }
    pub fn verify(&self) -> Result<()> {
        self.verify_objects()?;
        let (bytes, cache_key) = self.verification_key()?;
        // Native identities, retained evidence and all file bytes were checked
        // above. A live cache hit additionally binds all sidecars and the
        // same-connection SQLite counters; a closed session has no mutable
        // connection and is checked through its held native handles.
        if self.verified_main.borrow().as_ref() == Some(&cache_key) {
            if self.verification_key()?.1 != cache_key {
                return Err(ReconcileError::Invariant(
                    "recovered WAL verification cache capture changed",
                ));
            }
            return Ok(());
        }
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            cache_key.main.as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        let rows = if self.committed {
            image.recovered_session_preserved_rows_digest(
                &self.space,
                self.bounds,
                &self.previous,
                &self.fresh,
            )?
        } else {
            image.closed_node_complete_rows_digest(&self.space, self.bounds)?
        };
        if rows != self.before_rows {
            return Err(ReconcileError::Invariant(
                "recovered WAL other catalog rows changed",
            ));
        }
        if self.verification_key()?.1 != cache_key {
            return Err(ReconcileError::Invariant(
                "recovered WAL verification files or connection changed",
            ));
        }
        *self.verified_main.borrow_mut() = Some(cache_key);
        Ok(())
    }
    pub fn commit_fresh_session(&mut self) -> Result<SpaceId> {
        self.verify()?;
        if self.attempted || self.next != 1 {
            return Err(ReconcileError::Invariant(
                "recovered WAL single intended attempt",
            ));
        }
        self.attempted = true;
        self.poisoned = true;
        self.native
            .commit_fresh_session(self.previous.as_str(), self.fresh.as_str())?;
        crate::fault::checkpoint("recovered_wal2_actual_commit_before_checkpoint");
        self.native.checkpoint_to_standalone()?;
        self.history_baseline = self.native.exact_main_bytes()?;
        self.committed = true;
        self.poisoned = false;
        self.verify()?;
        self.record("committed_checkpointed", Some(self.before_rows.clone()))?;
        Ok(self.fresh.clone())
    }
    pub fn close_completed(&mut self) -> Result<PathBuf> {
        self.verify()?;
        if !self.committed || self.closed || self.next != 2 {
            return Err(ReconcileError::Invariant(
                "recovered WAL close requires checkpoint",
            ));
        }
        self.record("close_intended", Some(self.before_rows.clone()))?;
        self.poisoned = true;
        self.native.close_connection_retaining_native_objects()?;
        self.closed = true;
        self.poisoned = false;
        self.verify()?;
        self.record("closed", Some(self.before_rows.clone()))?;
        crate::fault::checkpoint("recovered_wal2_closed_after_terminal_sync");
        Ok(self.path.clone())
    }
}
impl super::VerifiedNodeStateArchive {
    /// Fresh acquisition checks the complete original closed scope. Evidence
    /// never grants an old CREATE/cleanup token. Unknown SHM is refused before
    /// any new evidence or native object is created.
    pub fn reacquire_closed_node_wal_v2_session(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_closed_node_wal_v2_session_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reacquire_closed_node_wal_v2_session_for_deployment(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        configs: crate::SeparatedDeploymentNodeConfigs,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        configs.verify_for_archive(self, worktree, data)?;
        let mut session = self.reacquire_closed_node_wal_v2_session_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            Some(&configs),
        )?;
        // No fallible consuming conversion follows the actual acquisition.
        session.separated_deployment_configs = Some(configs);
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    fn reacquire_closed_node_wal_v2_session_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        write_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        separated_configs: Option<&crate::SeparatedDeploymentNodeConfigs>,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            write_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            None,
            separated_configs,
        )?;
        read.verify()?;
        let frame = read
            .read
            .files
            .iter()
            .find(|file| file.path == write_frames)
            .ok_or(ReconcileError::Invariant(
                "recovered WAL original frame absent",
            ))?;
        let bytes = frame.file.exact_bytes(frame.bytes)?;
        let size = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("recovered WAL original scope size"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&bytes[84..84 + size])?;
        scope.validate()?;
        let total = scope
            .max_main_bytes
            .checked_add(scope.max_wal_bytes)
            .and_then(|n| n.checked_add(scope.max_rollback_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(ReconcileError::ResourceLimit(
                "recovered WAL preeffect aggregate budget",
            ))?;
        if total > 512 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "recovered WAL preeffect aggregate budget",
            ));
        }
        let fresh = SpaceId::random()?;
        let external = write_frames
            .parent()
            .ok_or(ReconcileError::Invariant("recovered WAL external absent"))?;
        let held = read
            .read
            .directories
            .iter()
            .find(|dir| dir.path == external)
            .ok_or(ReconcileError::Invariant(
                "recovered WAL held external absent",
            ))?;
        // Current explicit external membership, held under all acquired
        // original coordination locks, is checked before any new CREATE.
        for (count, entry) in std::fs::read_dir(external)?.enumerate() {
            if u64::try_from(count).map_err(|_| {
                ReconcileError::ResourceLimit("recovered WAL member counter overflow")
            })? >= ledger_bounds.max_records
            {
                return Err(ReconcileError::ResourceLimit(
                    "recovered WAL external member bound",
                ));
            }
            let entry = entry?;
            let component = entry
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("recovered WAL external component"))?;
            if component.starts_with("node-recovered-wal-")
                || component.starts_with("node-recovered-history-")
                || component.starts_with("node-recovered-file-")
                || component.starts_with("node-recovered-cas-")
            {
                return Err(ReconcileError::Invariant(
                    "recovered WAL prior attempt requires explicit recovery",
                ));
            }
        }
        let name = format!("node-recovered-wal-{fresh}");
        let mut owner = held.file.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(2u32, self.digest(), &fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.file.create_new_file(&(name.clone() + ".frames"))?;
        frames.writer().write_all(b"SYNC-RECOVERED-WAL2\n")?;
        frames.writer().sync_all()?;
        // Intent is recorded before the native SHM CREATE. This v2 header is
        // deliberately insufficient for restart if any following action fails.
        let before_native = serde_json::to_vec(&(
            2u32,
            self.digest(),
            ContentId::hash(&bytes),
            &scope.session,
            &fresh,
        ))?;
        frames
            .writer()
            .write_all(&(before_native.len() as u32).to_le_bytes())?;
        frames.writer().write_all(&before_native)?;
        frames.writer().sync_all()?;
        crate::fault::checkpoint("recovered_wal2_actual_intended_before_shm_create");
        let mut native_files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|file| file.path == data.join(name))
                .ok_or(ReconcileError::Invariant(
                    "recovered WAL native file absent",
                ))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "recovered WAL exclusive file required",
                ));
            };
            native_files.push(file);
        }
        let held = read
            .read
            .directories
            .iter()
            .find(|dir| dir.path == data)
            .ok_or(ReconcileError::Invariant("recovered WAL held data absent"))?;
        let shm = held
            .file
            .create_new_file("journal.sqlite-shm")?
            .into_fresh_sqlite_shm()?;
        native_files.push(shm);
        read.read
            .expected_membership
            .get_mut(data)
            .ok_or(ReconcileError::Invariant("recovered WAL membership absent"))?
            .insert("journal.sqlite-shm".into());
        let native = sync_extend_journal::FreshNativeWalConnection::open(
            &data.join("journal.sqlite"),
            native_files
                .try_into()
                .map_err(|_| ReconcileError::Invariant("recovered WAL four files"))?,
            [
                scope.max_main_bytes,
                scope.max_wal_bytes,
                scope.max_rollback_bytes,
                1024 * 1024,
            ],
        )?;
        let native_keys = native.all_native_keys()?.map(|key| key.to_string());
        let before_rows = read.read.rows.clone();
        let mut result = FreshRecoveredNodeWalV2Session {
            separated_deployment_configs: None,
            created_work_directories: std::collections::BTreeMap::new(),
            read,
            native,
            frames,
            owner,
            path: external.join(name + ".frames"),
            bounds,
            space: self.space().clone(),
            previous: scope.session,
            fresh,
            before_rows,
            archive: self.digest().clone(),
            original_frames: ContentId::hash(&bytes),
            next: 0,
            previous_record: ContentId::hash(&before_native),
            attempted: false,
            committed: false,
            closed: false,
            poisoned: false,
            predecessor: None,
            native_keys,
            history_count: 0,
            metadata_count: 0,
            retained_metadata_receipts: Vec::new(),
            new_content_bytes: 0,
            new_file_bytes: 0,
            manifest_entry_limit: bounds.max_entries,
            retained_receipts: std::collections::BTreeMap::new(),
            retained_receipt_bytes: 0,
            history_baseline: Vec::new(),
            history_chain_parent: None,
            history_chain_depth: 0,
            history_retained_originals: Vec::new(),
            history_retained_directories: Vec::new(),
            retained_history_evidence: Vec::new(),
            retained_mutations: Vec::new(),
            mutation_requested: false,
            new_cas_bytes: 0,
            new_cas_objects: 0,
            new_cas_buckets: std::collections::BTreeMap::new(),
            verified_main: std::cell::RefCell::new(None),
            polling: None,
            mutation_observation_closed: None,
            mutation_observation_failed: None,
        };
        result.record("intended", None)?;
        result.verify()?;
        Ok(result)
    }
}

impl super::VerifiedNodeStateArchive {
    /// Closed evidence is admission data; all current native objects, roots,
    /// original ledger and predecessor owners are explicitly reacquired.
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_fresh_closed_node_wal_v2_session(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        recovered_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_fresh_closed_node_wal_v2_session_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            recovered_frames,
            bounds,
            ledger_bounds,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reacquire_fresh_closed_node_wal_v2_session_for_deployment(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        recovered_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        configs: crate::SeparatedDeploymentNodeConfigs,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        configs.verify_for_archive(self, worktree, data)?;
        let mut session = self.reacquire_fresh_closed_node_wal_v2_session_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            recovered_frames,
            bounds,
            ledger_bounds,
            Some(&configs),
        )?;
        session.separated_deployment_configs = Some(configs);
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    fn reacquire_fresh_closed_node_wal_v2_session_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        recovered_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        separated_configs: Option<&crate::SeparatedDeploymentNodeConfigs>,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        let parent = original_frames
            .parent()
            .ok_or(ReconcileError::Invariant("WAL2 external parent"))?;
        if recovered_frames.parent() != Some(parent) || recovered_frames == original_frames {
            return Err(ReconcileError::Invariant(
                "WAL2 distinct exact external frame",
            ));
        }
        let ancestors = super::external::hold_ancestors(parent)?;
        let held = &ancestors
            .last()
            .ok_or(ReconcileError::Invariant("WAL2 external held parent"))?
            .1;
        let mut path = recovered_frames.to_path_buf();
        let mut chain = Vec::new();
        let mut all_names = std::collections::BTreeSet::new();
        let mut terminal: Option<RecoveredWalV2Record> = None;
        let mut current_digest = None;
        let mut newer: Option<RecoveredWalV2Record> = None;
        let mut aggregate = 0u64;
        loop {
            if chain.len() >= 64 {
                return Err(ReconcileError::ResourceLimit("WAL2 closed chain count"));
            }
            let component = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or(ReconcileError::Invariant("WAL2 frame name"))?;
            if !all_names.insert(component.to_owned()) {
                return Err(ReconcileError::Invariant("WAL2 chain cycle"));
            }
            let file = held.reacquire_existing_node_read_file(component)?;
            let bytes = file.exact_bytes(256 * 1024)?;
            aggregate = aggregate
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= 4 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "WAL2 held evidence aggregate",
                ))?;
            let records = recovered_wal_v2_records(&bytes)?;
            let old = records
                .last()
                .ok_or(ReconcileError::Invariant("WAL2 terminal absent"))?
                .clone();
            if old.archive != *self.digest()
                || old.worktree != worktree.to_string_lossy()
                || old.data != data.to_string_lossy()
                || component != format!("node-recovered-wal-{}.frames", old.fresh)
            {
                return Err(ReconcileError::Invariant(
                    "WAL2 exact terminal external scope",
                ));
            }
            let digest = ContentId::hash(&bytes);
            if let Some(newer) = &newer {
                if newer.predecessor.as_ref() != Some(&digest)
                    || newer.previous != old.fresh
                    || newer.keys != old.keys
                {
                    return Err(ReconcileError::Invariant("WAL2 linked predecessor differs"));
                }
            } else {
                terminal = Some(old.clone());
                current_digest = Some(digest.clone());
            }
            let owner_name = format!("node-recovered-wal-{}.owner", old.fresh);
            all_names.insert(owner_name.clone());
            let owner = held.reacquire_existing_node_read_file(&owner_name)?;
            let owner_bytes = owner.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
            if owner_bytes != serde_json::to_vec(&(2u32, self.digest(), &old.fresh))? {
                return Err(ReconcileError::Invariant("WAL2 exact owner"));
            }
            let owner_lock = owner.acquire_fresh_coordination_lock(false)?;
            chain.push((
                ReacquiredExternalEvidence {
                    path: path.clone(),
                    file,
                    digest,
                    bytes: bytes.len() as u64,
                },
                ReacquiredExternalEvidence {
                    path: parent.join(owner_name),
                    file: owner,
                    digest: ContentId::hash(&owner_bytes),
                    bytes: owner_bytes.len() as u64,
                },
                owner_lock,
            ));
            if let Some(predecessor) = &old.predecessor {
                let mut found = None;
                for (count, item) in std::fs::read_dir(parent)?.enumerate() {
                    if count as u64 >= ledger_bounds.max_records {
                        return Err(ReconcileError::ResourceLimit(
                            "WAL2 predecessor search bound",
                        ));
                    }
                    let item = item?;
                    let name = item
                        .file_name()
                        .into_string()
                        .map_err(|_| ReconcileError::Invariant("WAL2 external name"))?;
                    if name.starts_with("node-recovered-wal-")
                        && name.ends_with(".frames")
                        && !all_names.contains(&name)
                    {
                        let candidate = held.reacquire_existing_node_read_file(&name)?;
                        if ContentId::hash(&candidate.exact_bytes(256 * 1024)?) == *predecessor {
                            if found.is_some() {
                                return Err(ReconcileError::Invariant(
                                    "WAL2 duplicate predecessor",
                                ));
                            }
                            found = Some(parent.join(name));
                        }
                    }
                }
                path = found.ok_or(ReconcileError::Invariant("WAL2 predecessor missing"))?;
                newer = Some(old);
            } else {
                break;
            }
        }
        if chain.len() >= 64
            || aggregate
                .checked_add(256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "WAL2 next session preCREATE evidence budget",
            ));
        }
        for (count, item) in std::fs::read_dir(parent)?.enumerate() {
            if count as u64 >= ledger_bounds.max_records {
                return Err(ReconcileError::ResourceLimit("WAL2 membership bound"));
            }
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("WAL2 member name"))?;
            if name.starts_with("node-recovered-history-")
                || name.starts_with("node-recovered-file-")
                || name.starts_with("node-recovered-cas-")
                || (name.starts_with("node-recovered-wal-") && !all_names.contains(&name))
            {
                return Err(ReconcileError::Invariant("WAL2 unresolved foreign attempt"));
            }
        }
        let terminal = terminal.ok_or(ReconcileError::Invariant("WAL2 terminal"))?;
        let original_name = original_frames
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(ReconcileError::Invariant("WAL2 original name"))?;
        let original = held.reacquire_existing_node_read_file(original_name)?;
        let bytes = original.exact_bytes(1024 * 1024)?;
        if ContentId::hash(&bytes) != terminal.original_frames {
            return Err(ReconcileError::Invariant(
                "WAL2 exact original frame digest",
            ));
        }
        let length = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 original length"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&bytes[84..84 + length])?;
        let earliest = chain
            .last()
            .ok_or(ReconcileError::Invariant("WAL2 earliest chain"))?;
        let first = recovered_wal_v2_records(&earliest.0.file.exact_bytes(earliest.0.bytes)?)?;
        if first[0].previous != scope.session {
            return Err(ReconcileError::Invariant("WAL2 original previous session"));
        }
        drop(original);
        let admission = FreshSessionRecord {
            version: 2,
            phase: "closed".into(),
            archive: self.digest().clone(),
            original_frames: ContentId::hash(&bytes),
            original_completion: scope.completion.clone(),
            predecessor_frames: None,
            previous: scope.session.clone(),
            fresh: terminal.fresh.clone(),
            worktree: terminal.worktree.clone(),
            data: terminal.data.clone(),
            keys: terminal.keys[..3]
                .to_vec()
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 three keys"))?,
            rows: terminal.rows.clone(),
            main: terminal.main.clone(),
            wal_shm: Some((terminal.keys[3].clone(), terminal.shm.clone())),
            history_admission: None,
        };
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            Some(&admission),
            separated_configs,
        )?;
        for (frames, owner, lock) in chain {
            read.external.push(frames);
            read.external.push(owner);
            read.locks.push(lock);
        }
        read.verify()?;
        let fresh = SpaceId::random()?;
        let name = format!("node-recovered-wal-{fresh}");
        let mut owner = held.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(2u32, self.digest(), &fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.create_new_file(&(name.clone() + ".frames"))?;
        frames.writer().write_all(b"SYNC-RECOVERED-WAL2\n")?;
        let intent = serde_json::to_vec(&(
            2u32,
            self.digest(),
            ContentId::hash(&bytes),
            &terminal.fresh,
            &fresh,
        ))?;
        frames
            .writer()
            .write_all(&(intent.len() as u32).to_le_bytes())?;
        frames.writer().write_all(&intent)?;
        frames.writer().sync_all()?;
        crate::fault::checkpoint("recovered_wal2_restart_intended_before_open");
        let mut files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
            "journal.sqlite-shm",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|f| f.path == data.join(name))
                .ok_or(ReconcileError::Invariant("WAL2 native file absent"))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "WAL2 exclusive native acquisition",
                ));
            };
            files.push(file);
        }
        let native = sync_extend_journal::FreshNativeWalConnection::open(
            &data.join("journal.sqlite"),
            files
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 four files"))?,
            [
                scope.max_main_bytes,
                scope.max_wal_bytes,
                scope.max_rollback_bytes,
                1024 * 1024,
            ],
        )?;
        let native_keys = native.all_native_keys()?.map(|key| key.to_string());
        let before_rows = read.read.rows.clone();
        let mut result = FreshRecoveredNodeWalV2Session {
            separated_deployment_configs: None,
            created_work_directories: std::collections::BTreeMap::new(),
            read,
            native,
            frames,
            owner,
            path: parent.join(name + ".frames"),
            bounds,
            space: self.space().clone(),
            previous: terminal.fresh,
            fresh,
            before_rows,
            archive: self.digest().clone(),
            original_frames: ContentId::hash(&bytes),
            next: 0,
            previous_record: ContentId::hash(&intent),
            attempted: false,
            committed: false,
            closed: false,
            poisoned: false,
            predecessor: current_digest,
            native_keys,
            history_count: 0,
            metadata_count: 0,
            retained_metadata_receipts: Vec::new(),
            new_content_bytes: 0,
            new_file_bytes: 0,
            manifest_entry_limit: bounds.max_entries,
            retained_receipts: std::collections::BTreeMap::new(),
            retained_receipt_bytes: 0,
            history_baseline: Vec::new(),
            history_chain_parent: None,
            history_chain_depth: 0,
            history_retained_originals: Vec::new(),
            history_retained_directories: Vec::new(),
            retained_history_evidence: Vec::new(),
            retained_mutations: Vec::new(),
            mutation_requested: false,
            new_cas_bytes: 0,
            new_cas_objects: 0,
            new_cas_buckets: std::collections::BTreeMap::new(),
            verified_main: std::cell::RefCell::new(None),
            polling: None,
            mutation_observation_closed: None,
            mutation_observation_failed: None,
        };
        result.record("intended", None)?;
        result.verify()?;
        Ok(result)
    }
}

impl FreshRecoveredNodeWalV2Session {
    fn retain_recovered_receipt(&mut self, receipt: OwnedFileCreation) -> Result<()> {
        let name = receipt.original_creation()?.created_component().to_owned();
        let path = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("recovered receipt parent"))?
            .join(&name);
        let file = RecoveredFileProtection::Created(receipt.seal_original()?);
        let bytes = file.exact_bytes(256 * 1024)?;
        let length = bytes.len() as u64;
        let aggregate = self
            .retained_receipt_bytes
            .checked_add(length)
            .filter(|n| *n <= 4 * 1024 * 1024)
            .ok_or(ReconcileError::ResourceLimit(
                "recovered retained receipts aggregate",
            ))?;
        if self.retained_receipts.len() >= FRESH_RECEIPT_COUNT_MAXIMUM
            || self.retained_receipts.contains_key(&name)
            || !file.matches_path(&path)?
        {
            return Err(ReconcileError::Invariant(
                "recovered exact receipt unique slot",
            ));
        }
        self.retained_receipts.insert(
            name,
            ReacquiredFile {
                path,
                file,
                bytes: length,
                digest: ContentId::hash(&bytes),
            },
        );
        self.retained_receipt_bytes = aggregate;
        Ok(())
    }
}

impl FreshRecoveredNodeWalV2Session {
    /// Ordinary same-content Put: metadata history changes, all native file
    /// content stays held and unchanged; arbitrary manifest or SQL is not exposed.
    pub fn commit_same_content_history(
        &mut self,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        if !self.committed || self.closed || self.next != 2 {
            return Err(ReconcileError::Invariant(
                "recovered history requires committed live WAL2 session",
            ));
        }
        let previous = self.read.read.manifest.clone();
        let entry = previous
            .entries
            .values()
            .find(|e| e.kind == sync_extend_core_model::EntryKind::File)
            .ok_or(ReconcileError::Invariant(
                "recovered history ordinary file absent",
            ))?
            .clone();
        let device = self
            .read
            .read
            .files
            .iter()
            .find(|f| f.path == self.read.read.data.join("device.secret"))
            .ok_or(ReconcileError::Invariant(
                "recovered history protected device absent",
            ))?;
        let stored = device.file.exact_bytes(device.bytes)?;
        let key =
            ed25519_dalek::SigningKey::from_bytes(&crate::identity::decode_stored_backup(&stored)?);
        let origin =
            sync_extend_core_model::DeviceId::from_public_key(key.verifying_key().as_bytes());
        let seq = previous.version_vector.get(&origin).checked_add(1).ok_or(
            ReconcileError::Invariant("recovered history sequence overflow"),
        )?;
        let operation =
            sync_extend_core_model::Operation::new(sync_extend_core_model::OperationPayload {
                format_version: sync_extend_core_model::FORMAT_VERSION,
                space_id: self.space.clone(),
                origin_device_id: origin.clone(),
                origin_seq: seq,
                causal: previous.version_vector.clone(),
                change: sync_extend_core_model::Change::Put { entry },
                created_at_ms: timestamp,
            })?;
        let mut manifest = previous.clone();
        manifest.version_vector.observe(origin, seq);
        self.commit_exact_recovered_history(manifest, vec![operation], timestamp)
    }
    fn commit_exact_recovered_history(
        &mut self,
        manifest: sync_extend_core_model::Manifest,
        operations: Vec<sync_extend_core_model::Operation>,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        self.preflight_history_close_envelope(None, false, 0, 0, 1)?;
        if self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self
                .retained_receipt_bytes
                .checked_add(256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered history aggregate count or receipt bytes",
            ));
        }
        let expected = self.read.read.manifest.root()?;
        let bytes = self.native.exact_main_bytes()?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        let plan = image.plan_recovered_local_history(
            &self.space,
            &expected,
            &manifest,
            &operations,
            timestamp,
            self.bounds,
        )?;
        // Durable independent intended evidence precedes the actual history commit.
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("recovered history external"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == external)
            .ok_or(ReconcileError::Invariant("recovered history held external"))?;
        let intent = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            &expected,
            manifest.root()?,
            timestamp,
        ))?;
        if intent.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "recovered history intent preeffect bytes",
            ));
        }
        self.poisoned = true;
        let mut receipt = held.file.create_new_file(&format!(
            "node-recovered-history-{}-{}.frames",
            self.fresh, self.history_count
        ))?;
        receipt.writer().write_all(&intent)?;
        receipt.writer().sync_all()?;
        crate::fault::checkpoint("recovered_history_intended_before_sql");
        let root = plan.execute(&mut self.native)?;
        crate::fault::checkpoint("recovered_history_committed_before_receipt");
        let bytes = self.native.exact_main_bytes()?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        self.before_rows = image.recovered_session_preserved_rows_digest(
            &self.space,
            self.bounds,
            &self.previous,
            &self.fresh,
        )?;
        self.read.read.manifest = manifest;
        receipt.writer().write_all(&serde_json::to_vec(&(
            1u32,
            "committed",
            &root,
            ContentId::hash(&bytes),
        ))?)?;
        receipt.writer().sync_all()?;
        self.retain_recovered_receipt(receipt)?;
        self.history_count += 1;
        self.poisoned = false;
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.refresh_polling_after_commit(&operations) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(root)
    }
}

// Ordinary fresh CREATE through reacquired parents, retained through native scan.
impl FreshRecoveredNodeWalV2Session {
    pub fn create_recovered_file_from_existing_content(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        source: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        if !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered file session attempt bound",
            ));
        }
        let previous = self.read.read.manifest.clone();
        let original = previous
            .entries
            .values()
            .find(|e| e.path == *source && e.kind == sync_extend_core_model::EntryKind::File)
            .ok_or(ReconcileError::Invariant(
                "recovered file existing manifest source absent",
            ))?;
        let content = original
            .content
            .clone()
            .ok_or(ReconcileError::Invariant("recovered file source content"))?;
        let source_file = self
            .read
            .read
            .files
            .iter()
            .find(|f| f.path == self.read.read.worktree.join(source.as_str()))
            .ok_or(ReconcileError::Invariant("recovered source file absent"))?;
        let bytes = source_file.file.exact_bytes(8 * 1024 * 1024)?;
        self.create_recovered_file_materialized(path, content, bytes, timestamp)
    }
    fn create_recovered_file_materialized(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        content: sync_extend_core_model::FileManifest,
        bytes: Vec<u8>,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        self.preflight_recovered_file(path, &content)?;
        let previous = self.read.read.manifest.clone();
        let components: Vec<_> = path.as_str().split('/').collect();
        if components.len() > 256
            || components.iter().any(|name| name.starts_with('.'))
            || content.length > 8 * 1024 * 1024
            || content.chunks.len() > 128
            || previous
                .entries
                .len()
                .checked_add(1)
                .is_none_or(|n| n > self.manifest_entry_limit)
            || previous
                .entries
                .values()
                .any(|e| e.path.collision_key() == path.collision_key())
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered file preCREATE path content entry budget",
            ));
        }
        self.preflight_history_close_envelope(Some(path), true, 0, 1, 3)?;
        let name = components
            .last()
            .ok_or(ReconcileError::Invariant("recovered file component"))?;
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("recovered file parent"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant(
                "recovered file exact held parent absent",
            ))?;
        if self
            .read
            .read
            .expected_membership
            .get(parent)
            .is_none_or(|names| names.contains(*name))
        {
            return Err(ReconcileError::Invariant(
                "recovered file existing or unknown membership",
            ));
        }
        if bytes.len() as u64 != content.length
            || ContentId::hash(&bytes) != content.content_id
            || sync_extend_cas::plan_bounded_content(&bytes, 8 * 1024 * 1024, 128)?.manifest
                != content
        {
            return Err(ReconcileError::Invariant(
                "recovered file exact content plan differs",
            ));
        }
        // Existing CAS chunks were acquired with the complete manifest and
        // remain read-held; no new CAS object or namespace is inferred here.
        for chunk in &content.chunks {
            let file = self.held_recovered_cas_chunk(&chunk.content_id, u64::from(chunk.length))?;
        }
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("recovered file external parent"))?;
        let held_external = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == external)
            .ok_or(ReconcileError::Invariant(
                "recovered file external held parent",
            ))?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            path,
            &content.content_id,
            held.key.to_string(),
            previous.root()?,
            &content,
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "recovered file intended evidence bytes",
            ));
        }
        // Once any independent intent CREATE is attempted, failures retain an
        // uncertain session. No same-session retry can infer a clean boundary.
        self.poisoned = true;
        let mut evidence = held_external.file.create_new_file(&format!(
            "node-recovered-file-{}-{}.frames",
            self.fresh, self.history_count
        ))?;
        evidence.writer().write_all(&intended)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("recovered_file_intended_before_create");
        let mut creator = held.file.create_new_file(name)?;
        creator.writer().write_all(&bytes)?;
        creator.writer().sync_all()?;
        let file = creator.seal_original()?;
        let created_key = file.key()?;
        if file.parent_key()? != held.key || !file.matches_path(&target)? {
            return Err(ReconcileError::Invariant(
                "recovered file CREATE exact parent slot",
            ));
        }
        self.read.read.files.push(ReacquiredFile {
            path: target.clone(),
            file: RecoveredFileProtection::Created(file),
            digest: content.content_id.clone(),
            bytes: content.length,
        });
        self.new_file_bytes += content.length;
        self.read
            .read
            .expected_membership
            .get_mut(parent)
            .ok_or(ReconcileError::Invariant(
                "recovered file membership absent",
            ))?
            .insert((*name).into());
        evidence.writer().write_all(&serde_json::to_vec(&(
            1u32,
            "created",
            created_key.to_string(),
            &content.content_id,
        ))?)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("recovered_file_created_before_history");
        self.poisoned = false;
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            self.verify()?;
            let limits = sync_extend_core_model::limits::LocalLimits::default();
            let allowed: std::collections::BTreeSet<_> = previous
                .entries
                .values()
                .filter_map(|e| e.content.as_ref())
                .flat_map(|c| &c.chunks)
                .chain(content.chunks.iter())
                .map(|c| c.content_id.clone())
                .collect();
            let cas = sync_extend_cas::Cas::open_existing_session_coordinated(
                &self.read.read.data.join("cas"),
                move |id| {
                    if allowed.contains(id) {
                        Ok(Box::new(()))
                    } else {
                        Err("recovered scan CAS outside held current set".into())
                    }
                },
                || Ok(Box::new(())),
            )?;
            let view = RecoveredSessionScanView(self);
            let first = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
            let second = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
            if first != second {
                return Err(ReconcileError::Unstable);
            }
            let mut manifest =
                crate::build_manifest(&previous, &second, &std::collections::BTreeMap::new())?;
            let added: Vec<_> = manifest
                .entries
                .values()
                .filter(|e| !previous.entries.contains_key(&e.entry_id))
                .cloned()
                .collect();
            if added.len() != 1
                || added[0].path != *path
                || added[0].content.as_ref() != Some(&content)
                || previous
                    .entries
                    .iter()
                    .any(|(id, e)| manifest.entries.get(id) != Some(e))
            {
                return Err(ReconcileError::Invariant(
                    "recovered file original native scan delta",
                ));
            }
            let origin = self.recovered_device_id()?;
            let seq = manifest.version_vector.get(&origin).checked_add(1).ok_or(
                ReconcileError::Invariant("recovered file local sequence overflow"),
            )?;
            let operation =
                sync_extend_core_model::Operation::new(sync_extend_core_model::OperationPayload {
                    format_version: sync_extend_core_model::FORMAT_VERSION,
                    space_id: self.space.clone(),
                    origin_device_id: origin.clone(),
                    origin_seq: seq,
                    causal: manifest.version_vector.clone(),
                    change: sync_extend_core_model::Change::Put {
                        entry: added[0].clone(),
                    },
                    created_at_ms: timestamp,
                })?;
            manifest.version_vector.observe(origin, seq);
            let root = self.commit_exact_recovered_history(manifest, vec![operation], timestamp)?;
            evidence.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "committed",
                &root,
                created_key.to_string(),
            ))?)?;
            evidence.writer().sync_all()?;
            self.retain_recovered_receipt(evidence)?;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn recovered_device_id(&self) -> Result<sync_extend_core_model::DeviceId> {
        self.verify()?;
        let file = self
            .read
            .read
            .files
            .iter()
            .find(|f| f.path == self.read.read.data.join("device.secret"))
            .ok_or(ReconcileError::Invariant(
                "recovered protected identity absent",
            ))?;
        let secret = crate::identity::decode_stored_backup(&file.file.exact_bytes(file.bytes)?)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        Ok(sync_extend_core_model::DeviceId::from_public_key(
            key.verifying_key().as_bytes(),
        ))
    }
}
struct RecoveredSessionScanView<'a>(&'a FreshRecoveredNodeWalV2Session);
impl crate::native_file_view::NativeFileView for RecoveredSessionScanView<'_> {
    fn verify(&self) -> sync_extend_journal::Result<()> {
        self.0
            .verify()
            .map_err(|_| sync_extend_journal::JournalError::Invariant("recovered scan scope"))
    }
    fn observe_file(
        &self,
        path: &std::path::Path,
    ) -> sync_extend_journal::Result<Option<sync_extend_journal::NativePublicationFileObservation>>
    {
        self.verify()?;
        let file = self
            .0
            .read
            .read
            .files
            .iter()
            .find(|f| f.path == path)
            .ok_or(sync_extend_journal::JournalError::Invariant(
                "recovered scan unheld file",
            ))?;
        let bytes = file.file.exact_bytes(8 * 1024 * 1024)?;
        let plan =
            sync_extend_cas::plan_bounded_content(&bytes, 8 * 1024 * 1024, 128).map_err(|_| {
                sync_extend_journal::JournalError::Invariant("recovered scan content plan")
            })?;
        if plan.manifest.content_id != file.digest || plan.manifest.length != file.bytes {
            return Err(sync_extend_journal::JournalError::Invariant(
                "recovered scan exact content",
            ));
        }
        let key = file.file.key()?;
        Ok(Some(
            sync_extend_journal::NativePublicationFileObservation {
                metadata: file.file.metadata()?,
                portable: Some(self.0.recovered_logical_metadata_for_observed_file(
                    path, key, &plan.manifest,
                    crate::filesystem::portable_metadata_from_capture(
                        file.file.portable_metadata()?,
                    )
                    .map_err(|_| {
                        sync_extend_journal::JournalError::Invariant(
                            "recovered scan portable metadata",
                        )
                    })?,
                ).map_err(|_| sync_extend_journal::JournalError::Invariant("recovered logical metadata proof"))?),
                physical_identity: ContentId::hash(
                    format!("windows:{}:{}", key.volume, key.id).as_bytes(),
                ),
                content: Some(plan.manifest),
            },
        ))
    }
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
        self.verify()?;
        Ok(0)
    }
}

impl FreshRecoveredNodeWalV2Session {
    // This gate performs no CREATE and no SQLite effect. CAS publication calls
    // it before its own intent, so downstream ordinary-file limits apply first.
    fn preflight_recovered_file(
        &self,
        path: &sync_extend_core_model::PortablePath,
        content: &sync_extend_core_model::FileManifest,
    ) -> Result<()> {
        self.preflight_history_close_envelope(Some(path), true, content.chunks.len(), 1, 3)?;
        if !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self
                .retained_receipt_bytes
                .checked_add(3 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
            || content.length > 8 * 1024 * 1024
            || content.chunks.len() > 128
            || self
                .new_file_bytes
                .checked_add(content.length)
                .is_none_or(|n| n > 64 * 1024 * 1024)
            || self
                .read
                .read
                .manifest
                .entries
                .len()
                .checked_add(1)
                .is_none_or(|n| n > self.manifest_entry_limit)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered file aggregate preeffect bound",
            ));
        }
        let components: Vec<_> = path.as_str().split('/').collect();
        if components.len() > 256
            || components.iter().any(|n| n.starts_with('.'))
            || self
                .read
                .read
                .manifest
                .entries
                .values()
                .any(|e| e.path.collision_key() == path.collision_key())
        {
            return Err(ReconcileError::Invariant(
                "recovered file preeffect path scope",
            ));
        }
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("recovered file preeffect parent"))?;
        let name = components.last().ok_or(ReconcileError::Invariant(
            "recovered file preeffect component",
        ))?;
        if !self.read.read.directories.iter().any(|d| d.path == parent)
            || self
                .read
                .read
                .expected_membership
                .get(parent)
                .is_none_or(|names| names.contains(*name))
        {
            return Err(ReconcileError::Invariant(
                "recovered file preeffect exact held parent membership",
            ));
        }
        Ok(())
    }
}

impl FreshRecoveredNodeWalV2Session {
    /// Explicit caller limit can only reduce this already acquired session's
    /// future manifest capacity. It grants no effect or cleanup permission.
    pub fn constrain_recovered_entry_limit(&mut self, max_entries: usize) -> Result<()> {
        self.verify()?;
        if max_entries > self.manifest_entry_limit
            || max_entries < self.read.read.manifest.entries.len()
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered entry limit cannot expand or invalidate current manifest",
            ));
        }
        self.manifest_entry_limit = max_entries;
        self.verify()
    }
}

impl FreshRecoveredNodeWalV2Session {
    /// Scalar current capacity observation; does not expose native or Journal references.
    pub fn recovered_current_entry_count(&self) -> Result<usize> {
        self.verify()?;
        Ok(self.read.read.manifest.entries.len())
    }
}

impl FreshRecoveredNodeWalV2Session {
    /// Complete main digest through the actual held connection, no path reopen.
    pub fn recovered_current_main_digest(&self) -> Result<ContentId> {
        self.verify()?;
        Ok(ContentId::hash(&self.native.exact_main_bytes()?))
    }
}

// Explicit new CAS buckets/chunks retain their actual creators until session close.
impl FreshRecoveredNodeWalV2Session {
    pub fn create_recovered_file_from_bytes(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        bytes: &[u8],
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.materialize_recovered_file_bytes(path, bytes, timestamp, false)
    }
    pub fn replace_recovered_file_from_bytes(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        bytes: &[u8],
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.materialize_recovered_file_bytes(path, bytes, timestamp, true)
    }
    fn materialize_recovered_file_bytes(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        bytes: &[u8],
        timestamp: u64,
        replacing: bool,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        if !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || bytes.len() > 8 * 1024 * 1024
            || self
                .new_content_bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|n| n > 64 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered new content aggregate preeffect bound",
            ));
        }
        let plan = sync_extend_cas::plan_bounded_content(bytes, 8 * 1024 * 1024, 128)?;
        if replacing {
            self.preflight_recovered_replacement_bytes(path, &plan.manifest)?;
        } else {
            self.preflight_recovered_file(path, &plan.manifest)?;
        }
        // A file manifest may repeat the same content chunk. The physical
        // publication and its budget count unique object identities once.
        let mut unique = std::collections::BTreeMap::new();
        for (chunk, chunk_bytes) in &plan.chunks {
            if let Some((previous, bytes)) =
                unique.insert(chunk.content_id.clone(), (chunk, chunk_bytes))
            {
                if previous != chunk || bytes != chunk_bytes {
                    return Err(ReconcileError::Invariant(
                        "recovered CAS repeated identity differs",
                    ));
                }
            }
        }
        let mut new_chunk_bytes = 0u64;
        let mut missing_objects = 0usize;
        for (chunk, chunk_bytes) in unique.values().copied() {
            let id = chunk.content_id.as_str();
            let object = self
                .read
                .read
                .data
                .join("cas/objects")
                .join(&id[..2])
                .join(id);
            if let Some(actual) = self.read.read.files.iter().find(|f| f.path == object) {
                if actual.digest != chunk.content_id
                    || actual.bytes != u64::from(chunk.length)
                    || actual.file.exact_bytes(actual.bytes)? != *chunk_bytes
                {
                    return Err(ReconcileError::Invariant(
                        "recovered preeffect existing CAS content",
                    ));
                }
            } else {
                missing_objects =
                    missing_objects
                        .checked_add(1)
                        .ok_or(ReconcileError::ResourceLimit(
                            "recovered CAS object counter overflow",
                        ))?;
                new_chunk_bytes = new_chunk_bytes
                    .checked_add(chunk_bytes.len() as u64)
                    .ok_or(ReconcileError::ResourceLimit(
                        "recovered CAS physical bytes overflow",
                    ))?;
            }
        }
        if self
            .new_cas_bytes
            .checked_add(new_chunk_bytes)
            .is_none_or(|n| n > 64 * 1024 * 1024)
            || self
                .new_cas_objects
                .checked_add(missing_objects)
                .is_none_or(|n| n > FRESH_CAS_OBJECT_MAXIMUM)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered CAS aggregate physical preeffect budget",
            ));
        }
        // Reserve all three bounded intent streams and their terminal records,
        // including ordinary file/history streams, before any CAS-side CREATE.
        let intended_bound = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            path,
            &plan.manifest,
            timestamp,
        ))?;
        if intended_bound.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "recovered CAS intent preeffect bytes",
            ));
        }
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target.parent().ok_or(ReconcileError::Invariant(
            "recovered new content file parent",
        ))?;
        if path.as_str().split('/').any(|p| p.starts_with('.'))
            || !self.read.read.expected_membership.contains_key(parent)
            || (!replacing
                && self
                    .read
                    .read
                    .manifest
                    .entries
                    .values()
                    .any(|e| e.path.collision_key() == path.collision_key()))
        {
            return Err(ReconcileError::Invariant(
                "recovered new content destination scope",
            ));
        }
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("recovered CAS external"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == external)
            .ok_or(ReconcileError::Invariant("recovered CAS held external"))?;
        self.poisoned = true;
        let mut evidence = held.file.create_new_file(&format!(
            "node-recovered-cas-{}-{}.frames",
            self.fresh, self.history_count
        ))?;
        evidence.writer().write_all(&intended_bound)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("recovered_cas_intended_before_create");
        for (chunk, chunk_bytes) in unique.values().copied() {
            let id = chunk.content_id.as_str();
            let bucket = self.read.read.data.join("cas/objects").join(&id[..2]);
            let object = bucket.join(id);
            if let Some(actual) = self.read.read.files.iter().find(|f| f.path == object) {
                if actual.digest != chunk.content_id
                    || actual.file.exact_bytes(actual.bytes)? != *chunk_bytes
                {
                    return Err(ReconcileError::Invariant(
                        "recovered existing CAS exact content",
                    ));
                }
                continue;
            }
            let directory = if let Some(existing) = self.new_cas_buckets.get(&bucket) {
                existing.verify_exact(&bucket)?;
                None
            } else if self.read.read.directories.iter().any(|d| d.path == bucket) {
                None
            } else {
                let root = self.read.read.data.join("cas/objects");
                let parent = self
                    .read
                    .read
                    .directories
                    .iter()
                    .find(|d| d.path == root)
                    .ok_or(ReconcileError::Invariant(
                        "recovered CAS objects root absent",
                    ))?;
                let creator = parent.file.create_new_child(&id[..2])?;
                let key = creator.key()?;
                self.read
                    .read
                    .expected_membership
                    .get_mut(&root)
                    .ok_or(ReconcileError::Invariant("recovered CAS root membership"))?
                    .insert(id[..2].into());
                self.read
                    .read
                    .expected_membership
                    .insert(bucket.clone(), std::collections::BTreeSet::new());
                let guard = creator.duplicate_read_guard()?;
                self.read.read.directories.push(ReacquiredDirectory {
                    path: bucket.clone(),
                    file: guard,
                    key,
                });
                Some(RecoveredCasBucket { creator, key })
            };
            if let Some(directory) = directory {
                self.new_cas_buckets.insert(bucket.clone(), directory);
            }
            let mut creator = if let Some(created) = self.new_cas_buckets.get(&bucket) {
                created.verify_exact(&bucket)?;
                created.creator.create_new_file(id)?
            } else {
                self.read
                    .read
                    .directories
                    .iter()
                    .find(|d| d.path == bucket)
                    .ok_or(ReconcileError::Invariant("recovered CAS bucket absent"))?
                    .file
                    .create_new_file(id)?
            };
            creator.writer().write_all(chunk_bytes)?;
            creator.writer().sync_all()?;
            let sealed = creator.seal_original()?;
            if !sealed.matches_path(&object)? {
                return Err(ReconcileError::Invariant(
                    "recovered CAS original CREATE slot",
                ));
            }
            self.read.read.files.push(ReacquiredFile {
                path: object,
                file: RecoveredFileProtection::Created(sealed),
                digest: chunk.content_id.clone(),
                bytes: chunk_bytes.len() as u64,
            });
            self.read
                .read
                .expected_membership
                .get_mut(&bucket)
                .ok_or(ReconcileError::Invariant("recovered CAS bucket membership"))?
                .insert(id.into());
            evidence.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "created",
                &chunk.content_id,
                chunk.length,
            ))?)?;
            evidence.writer().sync_all()?;
        }
        self.new_content_bytes += bytes.len() as u64;
        self.new_cas_bytes += new_chunk_bytes;
        self.new_cas_objects += missing_objects;
        self.poisoned = false;
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            self.verify()?;
            crate::fault::checkpoint("recovered_cas_created_before_file");
            let root = if replacing {
                self.mutate_recovered_file(path, Some((plan.manifest, bytes.to_vec())), timestamp)?
            } else {
                self.create_recovered_file_materialized(
                    path,
                    plan.manifest,
                    bytes.to_vec(),
                    timestamp,
                )?
            };
            evidence.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "committed",
                root.clone(),
            ))?)?;
            evidence.writer().sync_all()?;
            self.retain_recovered_receipt(evidence)?;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
struct RecoveredCasBucket {
    creator: sync_extend_platform_fs::LockedDirectoryMutation,
    key: FileKey,
}
impl RecoveredCasBucket {
    fn verify_exact(&self, path: &std::path::Path) -> Result<()> {
        self.creator.original_creation()?.verify()?;
        if self.creator.key()? != self.key || !self.creator.matches_path(path)? {
            return Err(ReconcileError::Invariant("recovered new CAS held bucket"));
        }
        Ok(())
    }
}

impl FreshRecoveredNodeWalV2Session {
    fn preflight_recovered_replacement_bytes(
        &self,
        path: &sync_extend_core_model::PortablePath,
        content: &sync_extend_core_model::FileManifest,
    ) -> Result<()> {
        self.verify()?;
        self.preflight_history_close_envelope(Some(path), true, content.chunks.len(), 1, 3)?;
        if !self.mutation_requested
            || !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self.retained_mutations.len() >= 128
            || content.length > 8 * 1024 * 1024
            || content.chunks.len() > 128
            || self
                .retained_receipt_bytes
                .checked_add(3 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
            || self
                .new_file_bytes
                .checked_add(content.length)
                .is_none_or(|n| n > 64 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "replacement bytes aggregate preeffect bound",
            ));
        }
        let target = self.read.read.worktree.join(path.as_str());
        let original = self
            .read
            .read
            .files
            .iter()
            .find(|file| file.path == target)
            .ok_or(ReconcileError::Invariant(
                "replacement bytes held target absent",
            ))?;
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("replacement bytes parent"))?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ReconcileError::Invariant("replacement name"))?;
        if path.as_str().split('/').any(|name| name.starts_with('.'))
            || !self.read.read.manifest.entries.values().any(|entry| {
                entry.path == *path && entry.kind == sync_extend_core_model::EntryKind::File
            })
            || !matches!(
                original.file,
                RecoveredFileProtection::Mutation(_) | RecoveredFileProtection::Created(_)
            )
            || content.content_id == original.digest
            || self
                .read
                .read
                .expected_membership
                .get(parent)
                .is_none_or(|names| !names.contains(name))
            || self
                .read
                .read
                .directories
                .iter()
                .find(|directory| directory.path == parent)
                .is_none_or(|directory| original.file.parent_key().ok() != Some(directory.key))
        {
            return Err(ReconcileError::Invariant(
                "replacement bytes exact source rights and scope",
            ));
        }
        let retained = self.retained_mutations.iter().try_fold(0u64, |sum, item| {
            sum.checked_add(item.original.bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "replacement retained byte overflow",
                ))
        })?;
        if retained
            .checked_add(original.bytes)
            .is_none_or(|n| n > 64 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "replacement retained bytes preeffect",
            ));
        }
        Ok(())
    }
}

// Separate descriptive closed-history envelope. It never issues restart authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredHistoryCloseRecord {
    version: u32,
    index: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    session: SpaceId,
    worktree: String,
    data: String,
    keys: [String; 4],
    root: sync_extend_core_model::SnapshotId,
    rows: ContentId,
    main: ContentId,
    shm: ContentId,
    wal2_frames: Option<ContentId>,
    receipts: Vec<(String, ContentId, u64)>,
    history_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<live_retention::RecoveredMetadataCloseEvidence>,
}
#[derive(Serialize)]
pub struct RecoveredHistoryCloseClassification {
    pub state: &'static str,
    pub actual_records: usize,
    pub history_count: u32,
    pub receipts: usize,
    pub native_write_authority: bool,
    pub cleanup_authority: bool,
}
impl FreshRecoveredNodeWalV2Session {
    /// Close the actual native session, then bind complete final rows and all
    /// independently intended history/file/CAS receipts in a separate envelope.
    /// This preserves the original WAL2 record/parser and grants no restart API.
    pub fn close_recovered_history_with_evidence(&mut self) -> Result<PathBuf> {
        self.verify()?;
        let metadata = self.verified_metadata_close_evidence()?;
        if self.closed
            || (self.history_count == 0 && metadata.is_none())
            || self.history_count > FRESH_OPERATION_MAXIMUM
        {
            return Err(ReconcileError::Invariant(
                "explicit live recovered history required",
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("history close external parent"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history close held external"))?;
        let mut receipts = Vec::new();
        let mut aggregate = 0u64;
        for (count, item) in std::fs::read_dir(parent)?.enumerate() {
            if count >= 4096 {
                return Err(ReconcileError::ResourceLimit(
                    "history close external count",
                ));
            }
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("history close external encoding"))?;
            if ["history", "file", "cas", "retention"]
                .iter()
                .any(|kind| name.starts_with(&format!("node-recovered-{kind}-{}-", self.fresh)))
            {
                let file = self
                    .retained_receipts
                    .get(&name)
                    .ok_or(ReconcileError::Invariant(
                        "history close unheld or foreign receipt",
                    ))?;
                file.file.verify()?;
                let bytes = file.file.exact_bytes(file.bytes)?;
                if ContentId::hash(&bytes) != file.digest || !file.file.matches_path(&file.path)? {
                    return Err(ReconcileError::Invariant(
                        "history close original held receipt differs",
                    ));
                }
                aggregate = aggregate
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= 4 * 1024 * 1024)
                    .ok_or(ReconcileError::ResourceLimit(
                        "history close receipts aggregate",
                    ))?;
                // Each append-only local stream must end in its own synced
                // committed record. Mere intent or materialization stays open.
                live_retention::require_committed_receipt(&name, &bytes)?;
                receipts.push((name, ContentId::hash(&bytes), bytes.len() as u64));
            }
        }
        receipts.sort_by(|a, b| a.0.cmp(&b.0));
        let history_receipts = receipts
            .iter()
            .filter(|r| r.0.starts_with("node-recovered-history-"))
            .count();
        if history_receipts != self.history_count as usize {
            return Err(ReconcileError::Invariant(
                "history close exact committed history count",
            ));
        }
        let main = self.native.exact_main_bytes()?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            ContentId::hash(&main).as_str(),
            main.len(),
            &self.space,
            self.bounds,
        )?;
        let mut intended = RecoveredHistoryCloseRecord {
            version: 3,
            index: 0,
            phase: "close_intended".into(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            session: self.fresh.clone(),
            worktree: self.read.read.worktree.to_string_lossy().into(),
            data: self.read.read.data.to_string_lossy().into(),
            keys: self.native_keys.clone(),
            root: self.read.read.manifest.root()?,
            rows: image.closed_node_complete_rows_digest(&self.space, self.bounds)?,
            main: ContentId::hash(&main),
            shm: ContentId::hash(&self.native.held_shm_bytes()?),
            wal2_frames: None,
            receipts,
            history_count: self.history_count,
            metadata,
        };
        let bytes = serde_json::to_vec(&intended)?;
        if bytes.len() > 256 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history close envelope intended bound",
            ));
        }
        let path = parent.join(format!(
            "node-recovered-history-close-{}.frames",
            self.fresh
        ));
        self.poisoned = true;
        let mut evidence = held.file.create_new_file(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReconcileError::Invariant("history close component"))?,
        )?;
        evidence
            .writer()
            .write_all(b"SYNC-RECOVERED-HISTORY-CLOSE3\n")?;
        evidence
            .writer()
            .write_all(&(bytes.len() as u32).to_le_bytes())?;
        evidence.writer().write_all(&bytes)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("recovered_history_close_intended_before_native_close");
        self.poisoned = false;
        let result = (|| -> Result<PathBuf> {
            self.close_completed()?;
            intended.index = 1;
            intended.phase = "closed".into();
            {
                use std::os::windows::fs::FileExt;
                self.frames.original_creation()?.verify()?;
                let length = self.frames.reader().metadata()?.len();
                if length > 256 * 1024 {
                    return Err(ReconcileError::ResourceLimit("history close WAL2 bytes"));
                }
                let mut bytes = vec![0u8; length as usize];
                let mut offset = 0;
                while offset < bytes.len() {
                    let n = self
                        .frames
                        .reader()
                        .seek_read(&mut bytes[offset..], offset as u64)?;
                    if n == 0 {
                        return Err(ReconcileError::Invariant("history close WAL2 short read"));
                    }
                    offset += n;
                }
                intended.wal2_frames = Some(ContentId::hash(&bytes));
            }
            let after = self.native.exact_closed_main_bytes()?;
            if ContentId::hash(&after) != intended.main
                || ContentId::hash(&self.native.held_shm_bytes()?) != intended.shm
            {
                return Err(ReconcileError::Invariant(
                    "history close native bytes changed",
                ));
            }
            let terminal = serde_json::to_vec(&intended)?;
            if terminal.len() > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit(
                    "history close terminal bound",
                ));
            }
            evidence
                .writer()
                .write_all(&(terminal.len() as u32).to_le_bytes())?;
            evidence
                .writer()
                .write_all(ContentId::hash(&bytes).as_str().as_bytes())?;
            evidence.writer().write_all(&terminal)?;
            evidence.writer().sync_all()?;
            self.verify()?;
            self.retain_history_creation(evidence, 512 * 1024)?;
            crate::fault::checkpoint("recovered_history_closed_after_terminal_sync");
            Ok(path.clone())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
impl super::VerifiedNodeStateArchive {
    /// Classify bytes only. Neither historical native keys nor a digest become
    /// living ownership, cleanup permission, or a recovery writer capability.
    pub fn classify_recovered_history_close(
        &self,
        bytes: &[u8],
        wal2_frames: &[u8],
    ) -> RecoveredHistoryCloseClassification {
        let parsed = (|| -> Result<RecoveredHistoryCloseRecord> {
            const HEADER: &[u8] = b"SYNC-RECOVERED-HISTORY-CLOSE3\n";
            if !bytes.starts_with(HEADER)
                || bytes.len() > 512 * 1024
                || wal2_frames.len() > 256 * 1024
            {
                return Err(ReconcileError::Invariant("history close bounded header"));
            }
            let mut offset = HEADER.len();
            let read_size = |offset: usize| -> Result<usize> {
                let prefix = bytes
                    .get(offset..offset + 4)
                    .ok_or(ReconcileError::Invariant("history close size"))?;
                Ok(u32::from_le_bytes(
                    prefix
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("history close size encoding"))?,
                ) as usize)
            };
            let size = read_size(offset)?;
            offset += 4;
            if size > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history close intended size"));
            }
            let payload = bytes
                .get(offset..offset + size)
                .ok_or(ReconcileError::Invariant(
                    "history close intended truncated",
                ))?;
            let first: RecoveredHistoryCloseRecord = serde_json::from_slice(payload)?;
            offset += size;
            let size = read_size(offset)?;
            offset += 4;
            if size > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history close terminal size"));
            }
            let digest = bytes
                .get(offset..offset + 64)
                .ok_or(ReconcileError::Invariant("history close chain"))?;
            offset += 64;
            if digest != ContentId::hash(payload).as_str().as_bytes() {
                return Err(ReconcileError::Invariant(
                    "history close exact intended chain",
                ));
            }
            let final_bytes = bytes
                .get(offset..offset + size)
                .ok_or(ReconcileError::Invariant(
                    "history close terminal truncated",
                ))?;
            let terminal: RecoveredHistoryCloseRecord = serde_json::from_slice(final_bytes)?;
            if offset + size != bytes.len()
                || serde_json::to_vec(&first)? != payload
                || serde_json::to_vec(&terminal)? != final_bytes
                || first.version != 3
                || first.index != 0
                || first.phase != "close_intended"
                || first.archive != *self.digest()
                || first.wal2_frames.is_some()
                || (first.history_count == 0 && first.metadata.is_none())
                || first.history_count > FRESH_OPERATION_MAXIMUM
                || terminal.index != 1
                || terminal.phase != "closed"
                || terminal.wal2_frames.as_ref() != Some(&ContentId::hash(wal2_frames))
            {
                return Err(ReconcileError::Invariant(
                    "history close canonical phase and scope",
                ));
            }
            let mut normalized = terminal.clone();
            normalized.index = 0;
            normalized.phase = "close_intended".into();
            normalized.wal2_frames = None;
            if serde_json::to_vec(&normalized)? != payload {
                return Err(ReconcileError::Invariant(
                    "history close final bindings changed",
                ));
            }
            let mut total = 0u64;
            let mut last: Option<&str> = None;
            for (name, _, size) in &terminal.receipts {
                if *size > 256 * 1024
                    || last.is_some_and(|old| old >= name.as_str())
                    || !["history", "file", "cas", "retention"].iter().any(|kind| {
                        name.starts_with(&format!("node-recovered-{kind}-{}-", terminal.session))
                    })
                    || !name.ends_with(".frames")
                    || name.contains(['/', '\\'])
                {
                    return Err(ReconcileError::Invariant(
                        "history close exact receipt slots",
                    ));
                }
                total = total
                    .checked_add(*size)
                    .filter(|n| *n <= 4 * 1024 * 1024)
                    .ok_or(ReconcileError::ResourceLimit(
                        "history close exact aggregate",
                    ))?;
                last = Some(name);
            }
            if terminal
                .receipts
                .iter()
                .filter(|r| r.0.starts_with("node-recovered-history-"))
                .count()
                != terminal.history_count as usize
            {
                return Err(ReconcileError::Invariant(
                    "history close exact receipt count",
                ));
            }
            live_retention::validate_close_metadata(
                terminal.metadata.as_ref(),
                terminal.history_count,
                &terminal.receipts,
                &terminal.session,
                &terminal.main,
            )?;
            Ok(terminal)
        })();
        match parsed {
            Ok(record) => RecoveredHistoryCloseClassification {
                state: "closed_descriptive_history_evidence",
                actual_records: 2,
                history_count: record.history_count,
                receipts: record.receipts.len(),
                native_write_authority: false,
                cleanup_authority: false,
            },
            Err(_) => RecoveredHistoryCloseClassification {
                state: "refused_evidence",
                actual_records: 0,
                history_count: 0,
                receipts: 0,
                native_write_authority: false,
                cleanup_authority: false,
            },
        }
    }
}

// This new admission is never deserialized from caller input or a classification.
struct RecoveredHistoryAdmission {
    original_rows: ContentId,
    final_rows: ContentId,
    final_root: sync_extend_core_model::SnapshotId,
    mutation_requested: bool,
}
fn manifest_root_from_recovered_image(
    image: &sync_extend_journal::JournalBackupImage,
    space: &SpaceId,
    bounds: sync_extend_journal::NodeInspectionBounds,
) -> Result<sync_extend_core_model::SnapshotId> {
    image.with_audited_readonly(space,bounds,|connection| {
        let json:String=connection.query_row(
            "SELECT s.manifest FROM main.current_manifests c JOIN main.snapshots s ON c.snapshot_id=s.snapshot_id WHERE c.space_id=?1",
            [space.as_str()],|row|row.get(0))?;
        let manifest:sync_extend_core_model::Manifest=serde_json::from_str(&json)?;
        manifest.root().map_err(Into::into)
    }).map_err(Into::into)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRestartObject {
    name: String,
    key: String,
    parent: String,
    digest: ContentId,
    bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRestartRecord {
    version: u32,
    index: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    session: SpaceId,
    worktree: String,
    data: String,
    work_key: String,
    data_key: String,
    external_key: String,
    native_keys: [String; 4],
    root: sync_extend_core_model::SnapshotId,
    rows: ContentId,
    main: ContentId,
    shm: ContentId,
    baseline: HistoryRestartObject,
    receipts: Vec<HistoryRestartObject>,
    history_close: Option<HistoryRestartObject>,
    wal2: Option<HistoryRestartObject>,
}
fn history_restart_records(bytes: &[u8]) -> Result<HistoryRestartRecord> {
    const HEADER: &[u8] = b"SYNC-HISTORY-RESTART4\n";
    if !bytes.starts_with(HEADER) || bytes.len() > 1024 * 1024 {
        return Err(ReconcileError::Invariant(
            "history restart exact bounded header",
        ));
    }
    let mut offset = HEADER.len();
    let mut payloads: Vec<&[u8]> = Vec::new();
    for _ in 0..2 {
        let length = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or(ReconcileError::Invariant("history restart size"))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history restart size encoding"))?,
        ) as usize;
        offset += 4;
        if length > 384 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history restart record bytes",
            ));
        }
        if let Some(previous) = payloads.first() {
            let digest = bytes
                .get(offset..offset + 64)
                .ok_or(ReconcileError::Invariant("history restart chain"))?;
            if digest != ContentId::hash(previous).as_str().as_bytes() {
                return Err(ReconcileError::Invariant(
                    "history restart intended chain changed",
                ));
            }
            offset += 64;
        }
        let payload = bytes
            .get(offset..offset + length)
            .ok_or(ReconcileError::Invariant("history restart truncated"))?;
        payloads.push(payload);
        offset += length;
    }
    let first: HistoryRestartRecord = serde_json::from_slice(payloads[0])?;
    let terminal: HistoryRestartRecord = serde_json::from_slice(payloads[1])?;
    if offset != bytes.len()
        || first.version != 4
        || first.index != 0
        || first.phase != "close_intended"
        || first.wal2.is_some()
        || first.history_close.is_some()
        || terminal.index != 1
        || terminal.phase != "closed"
        || terminal.wal2.is_none()
        || terminal.history_close.is_none()
        || serde_json::to_vec(&first)? != payloads[0]
        || serde_json::to_vec(&terminal)? != payloads[1]
    {
        return Err(ReconcileError::Invariant(
            "history restart canonical terminal",
        ));
    }
    let mut normalized = terminal.clone();
    normalized.index = 0;
    normalized.phase = "close_intended".into();
    normalized.wal2 = None;
    normalized.history_close = None;
    if serde_json::to_vec(&normalized)? != payloads[0] {
        return Err(ReconcileError::Invariant(
            "history restart final bindings changed",
        ));
    }
    Ok(terminal)
}
fn history_object(file: &ReacquiredFile) -> Result<HistoryRestartObject> {
    file.file.verify()?;
    if !file.file.matches_path(&file.path)?
        || ContentId::hash(&file.file.exact_bytes(file.bytes)?) != file.digest
    {
        return Err(ReconcileError::Invariant(
            "history object held identity and bytes",
        ));
    }
    Ok(HistoryRestartObject {
        name: file
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ReconcileError::Invariant("history object exact name"))?
            .into(),
        key: file.file.key()?.to_string(),
        parent: file.file.parent_key()?.to_string(),
        digest: file.digest.clone(),
        bytes: file.bytes,
    })
}
impl FreshRecoveredNodeWalV2Session {
    fn retain_history_creation(
        &mut self,
        creator: OwnedFileCreation,
        maximum: u64,
    ) -> Result<HistoryRestartObject> {
        let name = creator.original_creation()?.created_component().to_owned();
        let path = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("history creation parent"))?
            .join(&name);
        let file = RecoveredFileProtection::Created(creator.seal_original()?);
        let bytes = file.exact_bytes(maximum)?;
        let held = ReacquiredFile {
            path,
            file,
            bytes: bytes.len() as u64,
            digest: ContentId::hash(&bytes),
        };
        let result = history_object(&held)?;
        self.retained_history_evidence.push(held);
        Ok(result)
    }
    /// Publish a fresh protocol that binds actual creator keys, immutable baseline
    /// and final complete history. The original descriptive close remains intact.
    pub fn close_recovered_history_for_explicit_restart(&mut self) -> Result<PathBuf> {
        self.verify()?;
        if self.history_count == 0
            || self.closed
            || self.history_baseline.is_empty()
            || self.history_baseline.len() > 64 * 1024 * 1024
        {
            return Err(ReconcileError::Invariant(
                "history restart explicit live baseline",
            ));
        }
        let main = self.native.exact_main_bytes()?;
        let baseline = sync_extend_journal::JournalBackupImage::from_current_node_image(
            self.history_baseline.clone(),
            ContentId::hash(&self.history_baseline).as_str(),
            self.history_baseline.len(),
            &self.space,
            self.bounds,
        )?;
        let final_image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            ContentId::hash(&main).as_str(),
            main.len(),
            &self.space,
            self.bounds,
        )?;
        final_image.audit_recovered_history_extension(&baseline, &self.space, self.bounds)?;
        let parent = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("history restart parent"))?
            .to_path_buf();
        let external = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history restart held external"))?;
        let external_key = external.key.to_string();
        let mut receipts = self
            .retained_receipts
            .values()
            .map(history_object)
            .collect::<Result<Vec<_>>>()?;
        receipts.sort_by(|a, b| a.name.cmp(&b.name));
        if receipts.is_empty()
            || receipts.len() > FRESH_RECEIPT_COUNT_MAXIMUM
            || receipts
                .iter()
                .try_fold(0u64, |sum, item| {
                    sum.checked_add(item.bytes)
                        .filter(|n| *n <= 4 * 1024 * 1024)
                        .ok_or(ReconcileError::ResourceLimit(
                            "history restart receipt aggregate",
                        ))
                })
                .is_err()
        {
            return Err(ReconcileError::ResourceLimit(
                "history restart bounded receipts",
            ));
        }
        self.poisoned = true;
        let mut creator = external
            .file
            .create_new_file(&format!("node-history-baseline-{}.image", self.fresh))?;
        creator.writer().write_all(&self.history_baseline)?;
        creator.writer().sync_all()?;
        let baseline = self.retain_history_creation(creator, 64 * 1024 * 1024)?;
        let root = self.read.read.manifest.root()?;
        let mut record = HistoryRestartRecord {
            version: 4,
            index: 0,
            phase: "close_intended".into(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            session: self.fresh.clone(),
            worktree: self.read.read.worktree.to_string_lossy().into(),
            data: self.read.read.data.to_string_lossy().into(),
            work_key: self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == self.read.read.worktree)
                .ok_or(ReconcileError::Invariant("history work root"))?
                .key
                .to_string(),
            data_key: self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == self.read.read.data)
                .ok_or(ReconcileError::Invariant("history data root"))?
                .key
                .to_string(),
            external_key,
            native_keys: self.native_keys.clone(),
            root,
            rows: final_image.closed_node_complete_rows_digest(&self.space, self.bounds)?,
            main: ContentId::hash(&main),
            shm: ContentId::hash(&self.native.held_shm_bytes()?),
            baseline,
            receipts,
            history_close: None,
            wal2: None,
        };
        let intended = serde_json::to_vec(&record)?;
        if intended.len() > 384 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history restart intended bound",
            ));
        }
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history restart external"))?;
        let path = parent.join(format!("node-history-restart-{}.frames", self.fresh));
        let mut evidence = held.file.create_new_file(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReconcileError::Invariant("history restart frame name"))?,
        )?;
        evidence.writer().write_all(b"SYNC-HISTORY-RESTART4\n")?;
        evidence
            .writer()
            .write_all(&(intended.len() as u32).to_le_bytes())?;
        evidence.writer().write_all(&intended)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("history_restart4_intended_before_native_close");
        self.poisoned = false;
        let result = (|| -> Result<PathBuf> {
            let closed_path = self.close_recovered_history_with_evidence()?;
            let close = self
                .retained_history_evidence
                .iter()
                .find(|e| e.path == closed_path)
                .ok_or(ReconcileError::Invariant(
                    "history restart close creator held",
                ))?;
            record.history_close = Some(history_object(close)?);
            let frame_bytes = self.frames.reader().metadata()?.len();
            if frame_bytes > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history restart WAL2 size"));
            }
            let wal_key = self.frames.original_creation()?.key()?.to_string();
            let wal_parent = self.frames.original_creation()?.parent_key()?.to_string();
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == parent)
                .ok_or(ReconcileError::Invariant("history restart frame external"))?;
            // The original creator is still held; reopen is unnecessary.
            let bytes = read_history_owned_bytes(&self.frames, 256 * 1024)?;
            let _ = held;
            record.wal2 = Some(HistoryRestartObject {
                name: self
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(ReconcileError::Invariant("history WAL name"))?
                    .into(),
                key: wal_key,
                parent: wal_parent,
                digest: ContentId::hash(&bytes),
                bytes: frame_bytes,
            });
            record.index = 1;
            record.phase = "closed".into();
            let terminal = serde_json::to_vec(&record)?;
            if terminal.len() > 384 * 1024 {
                return Err(ReconcileError::ResourceLimit(
                    "history restart terminal bound",
                ));
            }
            evidence
                .writer()
                .write_all(&(terminal.len() as u32).to_le_bytes())?;
            evidence
                .writer()
                .write_all(ContentId::hash(&intended).as_str().as_bytes())?;
            evidence.writer().write_all(&terminal)?;
            evidence.writer().sync_all()?;
            self.retain_history_creation(evidence, 1024 * 1024)?;
            self.verify()?;
            crate::fault::checkpoint("history_restart4_closed_after_terminal_sync");
            Ok(path)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
fn read_history_owned_bytes(file: &OwnedFileCreation, maximum: u64) -> Result<Vec<u8>> {
    use std::os::windows::fs::FileExt;
    file.original_creation()?.verify()?;
    let size = file.reader().metadata()?.len();
    if size > maximum {
        return Err(ReconcileError::ResourceLimit("history owned bytes"));
    }
    let mut bytes = vec![0u8; size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .reader()
            .seek_read(&mut bytes[offset..], offset as u64)?;
        if count == 0 {
            return Err(ReconcileError::Invariant("history owned short read"));
        }
        offset += count;
    }
    Ok(bytes)
}
impl super::VerifiedNodeStateArchive {
    /// Admit one explicitly closed history session by freshly held native roots,
    /// full current content, original completion and every exact receipt key.
    /// Classification bytes alone never construct this session.
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_closed_history_restart4(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        restart_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_history_restart4_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            restart_frames,
            bounds,
            ledger_bounds,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_closed_history_restart4_with_mutation(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        restart_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_history_restart4_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            restart_frames,
            bounds,
            ledger_bounds,
            true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn reacquire_history_restart4_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        restart_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        mutation_requested: bool,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        let parent = original_frames
            .parent()
            .ok_or(ReconcileError::Invariant("history recovery parent"))?;
        if restart_frames.parent() != Some(parent) || restore_ledger.parent() != Some(parent) {
            return Err(ReconcileError::Invariant(
                "history recovery explicit external slots",
            ));
        }
        let ancestors = super::external::hold_ancestors(parent)?;
        let held = &ancestors
            .last()
            .ok_or(ReconcileError::Invariant("history held parent"))?
            .1;
        let restart_name = restart_frames
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ReconcileError::Invariant("history recovery name"))?;
        let restart = held.reacquire_existing_node_read_file(restart_name)?;
        let restart_bytes = restart.exact_bytes(1024 * 1024)?;
        let record = history_restart_records(&restart_bytes)?;
        if record.archive != *self.digest()
            || record.worktree != worktree.to_string_lossy()
            || record.data != data.to_string_lossy()
            || held.key()?.to_string() != record.external_key
            || restart_name != format!("node-history-restart-{}.frames", record.session)
        {
            return Err(ReconcileError::Invariant(
                "history exact protocol and root binding",
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        names.insert(restart_name.to_owned());
        let mut retained = Vec::new();
        let mut aggregate = restart_bytes.len() as u64;
        let mut objects = record.receipts.clone();
        let close = record
            .history_close
            .as_ref()
            .ok_or(ReconcileError::Invariant("history close object"))?;
        let wal = record
            .wal2
            .as_ref()
            .ok_or(ReconcileError::Invariant("history WAL object"))?;
        if record.baseline.name != format!("node-history-baseline-{}.image", record.session)
            || close.name != format!("node-recovered-history-close-{}.frames", record.session)
            || wal.name != format!("node-recovered-wal-{}.frames", record.session)
            || record.receipts.len() > FRESH_RECEIPT_COUNT_MAXIMUM
        {
            return Err(ReconcileError::Invariant("history exact object slots"));
        }
        let mut receipt_bytes = 0u64;
        for item in &record.receipts {
            if item.bytes > 256 * 1024
                || !["history", "file", "cas"].iter().any(|kind| {
                    item.name
                        .starts_with(&format!("node-recovered-{kind}-{}-", record.session))
                })
            {
                return Err(ReconcileError::Invariant("history exact receipt namespace"));
            }
            receipt_bytes = receipt_bytes
                .checked_add(item.bytes)
                .filter(|n| *n <= 4 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "history receipt recovery aggregate",
                ))?;
        }
        objects.extend([record.baseline.clone(), close.clone(), wal.clone()]);
        for object in &objects {
            let maximum = if object.name == record.baseline.name {
                64 * 1024 * 1024
            } else if object.name == close.name {
                512 * 1024
            } else {
                256 * 1024
            };
            if object.name.contains(['/', '\\'])
                || !names.insert(object.name.clone())
                || object.bytes > maximum
                || object.parent != record.external_key
            {
                return Err(ReconcileError::Invariant(
                    "history exact unique bounded object",
                ));
            }
            aggregate = aggregate
                .checked_add(object.bytes)
                .filter(|n| *n <= 72 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "history restart aggregate before acquisition",
                ))?;
            let file = held.reacquire_existing_node_read_file(&object.name)?;
            let bytes = file.exact_bytes(maximum)?;
            if file.key()?.to_string() != object.key
                || file.parent_key()?.to_string() != object.parent
                || !file.matches_path(&parent.join(&object.name))?
                || bytes.len() as u64 != object.bytes
                || ContentId::hash(&bytes) != object.digest
            {
                return Err(ReconcileError::Invariant(
                    "history recovery actual key parent bytes",
                ));
            }
            retained.push(ReacquiredFile {
                path: parent.join(&object.name),
                file: RecoveredFileProtection::Read(file),
                bytes: object.bytes,
                digest: object.digest.clone(),
            });
        }
        retained.push(ReacquiredFile {
            path: restart_frames.to_owned(),
            file: RecoveredFileProtection::Read(restart),
            bytes: restart_bytes.len() as u64,
            digest: ContentId::hash(&restart_bytes),
        });
        let original_name = original_frames
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ReconcileError::Invariant("history original name"))?;
        let original = held.reacquire_existing_node_read_file(original_name)?;
        let original_bytes = original.exact_bytes(1024 * 1024)?;
        if ContentId::hash(&original_bytes) != record.original_frames
            || self
                .classify_original_node_write_frames(&original_bytes)
                .state
                != "closed_evidence"
        {
            return Err(ReconcileError::Invariant(
                "history original completed scope",
            ));
        }
        let size = u32::from_le_bytes(
            original_bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history original scope size"))?,
        ) as usize;
        let scope: OriginalWriteScope = serde_json::from_slice(&original_bytes[84..84 + size])?;
        scope.validate()?;
        let owner_name = format!("node-recovered-wal-{}.owner", record.session);
        names.insert(owner_name.clone());
        let owner = held.reacquire_existing_node_read_file(&owner_name)?;
        let owner_bytes = owner.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
        if owner_bytes != serde_json::to_vec(&(2u32, self.digest(), &record.session))? {
            return Err(ReconcileError::Invariant("history exact recovered owner"));
        }
        let owner_lock = owner.acquire_fresh_coordination_lock(false)?;
        let wal_bytes = retained
            .iter()
            .find(|e| e.path == parent.join(&wal.name))
            .ok_or(ReconcileError::Invariant("history held WAL bytes"))?
            .file
            .exact_bytes(wal.bytes)?;
        let wal_records = history_restart_wal_records(&wal_bytes)?;
        let first = &wal_records[1];
        let terminal = &wal_records[3];
        if terminal.archive != record.archive
            || terminal.original_frames != record.original_frames
            || terminal.fresh != record.session
            || terminal.previous != scope.session
            || terminal.predecessor.is_some()
            || terminal.keys != record.native_keys
            || terminal.rows != record.rows
            || terminal.main != record.main
            || terminal.shm != record.shm
            || terminal.worktree != record.worktree
            || terminal.data != record.data
        {
            return Err(ReconcileError::Invariant(
                "history exact terminal WAL binding",
            ));
        }
        let close_bytes = retained
            .iter()
            .find(|e| e.path == parent.join(&close.name))
            .ok_or(ReconcileError::Invariant("history held close bytes"))?
            .file
            .exact_bytes(close.bytes)?;
        let classification = self.classify_recovered_history_close(&close_bytes, &wal_bytes);
        if classification.state != "closed_descriptive_history_evidence"
            || classification.receipts != record.receipts.len()
        {
            return Err(ReconcileError::Invariant("history exact descriptive close"));
        }
        for (count, item) in std::fs::read_dir(parent)?.enumerate() {
            if count as u64 >= ledger_bounds.max_records {
                return Err(ReconcileError::ResourceLimit(
                    "history exact external membership bound",
                ));
            }
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("history external name encoding"))?;
            if (name.starts_with("node-recovered-") || name.starts_with("node-history-"))
                && !names.contains(&name)
            {
                return Err(ReconcileError::Invariant(
                    "history unresolved or foreign prior attempt",
                ));
            }
        }
        let baseline_bytes = retained
            .iter()
            .find(|e| e.path == parent.join(&record.baseline.name))
            .ok_or(ReconcileError::Invariant("history held baseline"))?
            .file
            .exact_bytes(record.baseline.bytes)?;
        let baseline = sync_extend_journal::JournalBackupImage::from_current_node_image(
            baseline_bytes.clone(),
            record.baseline.digest.as_str(),
            baseline_bytes.len(),
            self.space(),
            bounds,
        )?;
        if record.baseline.digest != first.main
            || baseline.closed_node_complete_rows_digest(self.space(), bounds)? != first.rows
        {
            return Err(ReconcileError::Invariant(
                "history baseline exact first checkpoint",
            ));
        }
        let original_rows = baseline.recovered_session_preserved_rows_digest(
            self.space(),
            bounds,
            &scope.session,
            &record.session,
        )?;
        let admission = FreshSessionRecord {
            version: 2,
            phase: "closed".into(),
            archive: self.digest().clone(),
            original_frames: record.original_frames.clone(),
            original_completion: scope.completion.clone(),
            predecessor_frames: None,
            previous: scope.session.clone(),
            fresh: record.session.clone(),
            worktree: record.worktree.clone(),
            data: record.data.clone(),
            keys: record.native_keys[..3]
                .to_vec()
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history three native keys"))?,
            rows: record.rows.clone(),
            main: record.main.clone(),
            wal_shm: Some((record.native_keys[3].clone(), record.shm.clone())),
            history_admission: Some(RecoveredHistoryAdmission {
                original_rows,
                final_rows: record.rows.clone(),
                final_root: record.root.clone(),
                mutation_requested,
            }),
        };
        drop(original);
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            Some(&admission),
            None,
        )?;
        if read
            .read
            .directories
            .iter()
            .find(|d| d.path == worktree)
            .is_none_or(|d| d.key.to_string() != record.work_key)
            || read
                .read
                .directories
                .iter()
                .find(|d| d.path == data)
                .is_none_or(|d| d.key.to_string() != record.data_key)
        {
            return Err(ReconcileError::Invariant(
                "history actual retained roots changed",
            ));
        }
        let main = read
            .read
            .files
            .iter()
            .find(|f| f.path == data.join("journal.sqlite"))
            .ok_or(ReconcileError::Invariant("history held current main"))?
            .file
            .exact_bytes(scope.max_main_bytes)?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            record.main.as_str(),
            main.len(),
            self.space(),
            bounds,
        )?;
        image.audit_recovered_history_extension(&baseline, self.space(), bounds)?;
        read.external.push(ReacquiredExternalEvidence {
            path: parent.join(owner_name),
            file: owner,
            digest: ContentId::hash(&owner_bytes),
            bytes: owner_bytes.len() as u64,
        });
        read.locks.push(owner_lock);
        read.verify()?;
        let total = scope
            .max_main_bytes
            .checked_add(scope.max_wal_bytes)
            .and_then(|n| n.checked_add(scope.max_rollback_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(ReconcileError::ResourceLimit(
                "history native aggregate overflow",
            ))?;
        if total > 512 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history native aggregate before effects",
            ));
        }
        let fresh = SpaceId::random()?;
        let name = format!("node-recovered-wal-{fresh}");
        let mut owner = held.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(2u32, self.digest(), &fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.create_new_file(&(name.clone() + ".frames"))?;
        let intent = serde_json::to_vec(&(
            2u32,
            self.digest(),
            &record.original_frames,
            &record.session,
            &fresh,
        ))?;
        frames.writer().write_all(b"SYNC-RECOVERED-WAL2\n")?;
        frames
            .writer()
            .write_all(&(intent.len() as u32).to_le_bytes())?;
        frames.writer().write_all(&intent)?;
        frames.writer().sync_all()?;
        crate::fault::checkpoint("history_restart4_reacquired_intended_before_open");
        let mut files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
            "journal.sqlite-shm",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|f| f.path == data.join(name))
                .ok_or(ReconcileError::Invariant("history next native file absent"))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "history fresh exclusive native handoff",
                ));
            };
            files.push(file);
        }
        // The fresh WAL2 intent is already durable. Resetting the retained SHM
        // index starts a new native epoch, never modifies prior admission bytes.
        let epoch_name = format!("node-recovered-shm-epoch-{fresh}.frames");
        let mut epoch = held.create_new_file(&epoch_name)?;
        let epoch_intent = serde_json::to_vec(&(
            1u32,
            "shm_epoch_intended",
            self.digest(),
            &record.original_frames,
            &record.session,
            &fresh,
            &record.native_keys,
            &record.main,
            &record.shm,
            &record.rows,
        ))?;
        if epoch_intent.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "new SHM epoch intended bound",
            ));
        }
        epoch.writer().write_all(&epoch_intent)?;
        epoch.writer().sync_all()?;
        crate::fault::checkpoint("history_restart4_intended_before_new_shm_epoch");
        let prior_shm = files[3].exact_bytes(1024 * 1024)?;
        if ContentId::hash(&prior_shm) != record.shm {
            return Err(ReconcileError::Invariant("exact prior held SHM bytes"));
        }
        let native =
            sync_extend_journal::FreshNativeWalConnection::open_after_explicit_shm_epoch(
                &data.join("journal.sqlite"),
                files
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("history native four files"))?,
                [
                    scope.max_main_bytes,
                    scope.max_wal_bytes,
                    scope.max_rollback_bytes,
                    1024 * 1024,
                ],
                (record.native_keys[3].as_str(), &prior_shm),
            )?;
        epoch.writer().write_all(&serde_json::to_vec(&(
            1u32,
            "shm_epoch_initialized",
            &fresh,
            ContentId::hash(&native.held_shm_bytes()?),
            native.all_native_keys()?.map(|key| key.to_string()),
        ))?)?;
        epoch.writer().sync_all()?;
        crate::fault::checkpoint("history_restart4_new_shm_epoch_before_session_commit");
        let epoch_file = RecoveredFileProtection::Created(epoch.seal_original()?);
        let epoch_bytes = epoch_file.exact_bytes(256 * 1024)?;
        retained.push(ReacquiredFile {
            path: parent.join(epoch_name),
            file: epoch_file,
            bytes: epoch_bytes.len() as u64,
            digest: ContentId::hash(&epoch_bytes),
        });
        let native_keys = native.all_native_keys()?.map(|key| key.to_string());
        let before_rows = read.read.rows.clone();
        let mut result = FreshRecoveredNodeWalV2Session {
            separated_deployment_configs: None,
            created_work_directories: std::collections::BTreeMap::new(),
            read,
            native,
            frames,
            owner,
            path: parent.join(name + ".frames"),
            bounds,
            space: self.space().clone(),
            previous: record.session,
            fresh,
            before_rows,
            archive: self.digest().clone(),
            original_frames: record.original_frames,
            next: 0,
            previous_record: ContentId::hash(&intent),
            attempted: false,
            committed: false,
            closed: false,
            poisoned: false,
            predecessor: Some(wal.digest.clone()),
            native_keys,
            history_count: 0,
            metadata_count: 0,
            retained_metadata_receipts: Vec::new(),
            new_content_bytes: 0,
            new_cas_buckets: std::collections::BTreeMap::new(),
            verified_main: std::cell::RefCell::new(None),
            polling: None,
            mutation_observation_closed: None,
            mutation_observation_failed: None,
            new_file_bytes: 0,
            new_cas_bytes: 0,
            new_cas_objects: 0,
            manifest_entry_limit: bounds.max_entries,
            retained_receipts: std::collections::BTreeMap::new(),
            retained_receipt_bytes: 0,
            history_baseline: Vec::new(),
            history_chain_parent: None,
            history_chain_depth: 0,
            history_retained_originals: Vec::new(),
            history_retained_directories: Vec::new(),
            retained_history_evidence: retained,
            retained_mutations: Vec::new(),
            mutation_requested,
        };
        result.record("intended", None)?;
        result.verify()?;
        Ok(result)
    }
}

fn history_restart_wal_records(bytes: &[u8]) -> Result<Vec<RecoveredWalV2Record>> {
    const HEADER: &[u8] = b"SYNC-RECOVERED-WAL2\n";
    if !bytes.starts_with(HEADER) || bytes.len() > 256 * 1024 {
        return Err(ReconcileError::Invariant("WAL2 exact bounded header"));
    }
    let prefix = bytes
        .get(HEADER.len()..HEADER.len() + 4)
        .ok_or(ReconcileError::Invariant("WAL2 intent prefix"))?;
    let length = u32::from_le_bytes(
        prefix
            .try_into()
            .map_err(|_| ReconcileError::Invariant("WAL2 intent length"))?,
    ) as usize;
    if length > 65536 {
        return Err(ReconcileError::ResourceLimit("WAL2 intent bound"));
    }
    let start = HEADER.len() + 4;
    let intent = bytes
        .get(start..start + length)
        .ok_or(ReconcileError::Invariant("WAL2 incomplete intent"))?;
    let admitted: (u32, ContentId, ContentId, SpaceId, SpaceId) = serde_json::from_slice(intent)?;
    if admitted.0 != 2 || admitted.3 == admitted.4 || serde_json::to_vec(&admitted)? != intent {
        return Err(ReconcileError::Invariant("WAL2 canonical intent"));
    }
    let mut offset = start + length;
    let mut previous = ContentId::hash(intent);
    let mut result = Vec::new();
    while offset < bytes.len() {
        let prefix = bytes
            .get(offset..offset + 136)
            .ok_or(ReconcileError::Invariant("WAL2 truncated envelope"))?;
        let index = u32::from_le_bytes(
            prefix[..4]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 index"))?,
        );
        let size = u32::from_le_bytes(
            prefix[4..8]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("WAL2 size"))?,
        ) as usize;
        if index as usize != result.len()
            || index >= 4
            || size > 65536
            || prefix[8..72] != *previous.as_str().as_bytes()
        {
            return Err(ReconcileError::Invariant("WAL2 order bounds chain"));
        }
        let payload = bytes
            .get(offset + 136..offset + 136 + size)
            .ok_or(ReconcileError::Invariant("WAL2 payload truncated"))?;
        let record: RecoveredWalV2Record = serde_json::from_slice(payload)?;
        if record.version != 2
            || record.index != index
            || record.archive != admitted.1
            || record.original_frames != admitted.2
            || record.previous != admitted.3
            || record.fresh != admitted.4
            || record.phase
                != [
                    "intended",
                    "committed_checkpointed",
                    "close_intended",
                    "closed",
                ][index as usize]
            || serde_json::to_vec(&record)? != payload
            || ContentId::hash(payload).as_str().as_bytes() != &prefix[72..136]
        {
            return Err(ReconcileError::Invariant("WAL2 exact canonical record"));
        }
        if let Some(first) = result.first() {
            let first: &RecoveredWalV2Record = first;
            if record.keys != first.keys
                || record.worktree != first.worktree
                || record.data != first.data
                || record.predecessor != first.predecessor
            {
                return Err(ReconcileError::Invariant(
                    "WAL2 native binding changed across records",
                ));
            }
        }
        if index == 3 {
            let checkpoint: &RecoveredWalV2Record = &result[2];
            if record.rows != checkpoint.rows
                || record.main != checkpoint.main
                || record.shm != checkpoint.shm
            {
                return Err(ReconcileError::Invariant(
                    "history WAL close bytes changed after checkpoint",
                ));
            }
        }
        offset += 136 + size;
        previous = ContentId::hash(&bytes[offset - 136 - size..offset]);
        result.push(record);
    }
    if result.len() != 4 {
        return Err(ReconcileError::Invariant(
            "WAL2 actual closed terminal required",
        ));
    }
    Ok(result)
}

// Newly acquired READ|DELETE authority retains the original in a fresh external
// directory. Old CREATE provenance and cleanup permission are never reconstructed.
struct RecoveredRetainedMutation {
    directory: sync_extend_platform_fs::LockedDirectoryMutation,
    path: PathBuf,
    original: ReacquiredFile,
}
impl RecoveredRetainedMutation {
    fn verify(&self) -> Result<()> {
        self.directory.original_creation()?.verify()?;
        self.original.file.verify()?;
        if !self.directory.matches_path(&self.path)?
            || !self
                .original
                .file
                .matches_path(&self.path.join("original"))?
            || ContentId::hash(&self.original.file.exact_bytes(self.original.bytes)?)
                != self.original.digest
        {
            return Err(ReconcileError::Invariant(
                "recovered retained original mutation bytes or key",
            ));
        }
        Ok(())
    }
}
impl FreshRecoveredNodeWalV2Session {
    pub fn replace_recovered_file_from_existing_content(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        source: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        let entry = self
            .read
            .read
            .manifest
            .entries
            .values()
            .find(|e| e.path == *source && e.kind == sync_extend_core_model::EntryKind::File)
            .ok_or(ReconcileError::Invariant("recovered replacement source"))?;
        let content = entry
            .content
            .clone()
            .ok_or(ReconcileError::Invariant("replacement source content"))?;
        let source = self
            .read
            .read
            .files
            .iter()
            .find(|f| f.path == self.read.read.worktree.join(source.as_str()))
            .ok_or(ReconcileError::Invariant("replacement held source"))?;
        let bytes = source.file.exact_bytes(8 * 1024 * 1024)?;
        self.mutate_recovered_file(path, Some((content, bytes)), timestamp)
    }
    pub fn delete_recovered_file(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.mutate_recovered_file(path, None, timestamp)
    }
    fn mutate_recovered_file(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        replacement: Option<(sync_extend_core_model::FileManifest, Vec<u8>)>,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        use sync_extend_core_model::{
            Change, EntryKind, Operation, OperationPayload, FORMAT_VERSION,
        };
        self.verify()?;
        self.preflight_history_close_envelope(Some(path), replacement.is_some(), 0, 1, 3)?;
        if !self.mutation_requested
            || !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self.retained_mutations.len() >= 128
            || self
                .retained_receipt_bytes
                .checked_add(2 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered mutation preeffect session receipts",
            ));
        }
        let previous = self.read.read.manifest.clone();
        let entry = previous
            .entries
            .values()
            .find(|e| e.path == *path && e.kind == EntryKind::File)
            .ok_or(ReconcileError::Invariant("recovered mutation exact file"))?
            .clone();
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("recovered mutation parent"))?
            .to_path_buf();
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ReconcileError::Invariant("recovered mutation name"))?
            .to_owned();
        if path.as_str().split('/').any(|n| n.starts_with('.')) {
            return Err(ReconcileError::Invariant(
                "recovered mutation reserved path",
            ));
        }
        let index = self
            .read
            .read
            .files
            .iter()
            .position(|f| f.path == target)
            .ok_or(ReconcileError::Invariant(
                "recovered mutation held file absent",
            ))?;
        let original = &self.read.read.files[index];
        if !matches!(
            original.file,
            RecoveredFileProtection::Mutation(_) | RecoveredFileProtection::Created(_)
        ) {
            return Err(ReconcileError::Invariant(
                "recovered mutation explicit native rights required",
            ));
        }
        let original_key = original.file.key()?;
        let original_parent = original.file.parent_key()?;
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("recovered mutation external"))?
            .to_path_buf();
        let held_external = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == external)
            .ok_or(ReconcileError::Invariant(
                "recovered mutation held external",
            ))?;
        let held_parent = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("recovered mutation held parent"))?;
        if held_parent.key != original_parent || held_external.key.volume != original_key.volume {
            return Err(ReconcileError::Invariant(
                "recovered mutation original parent same external volume",
            ));
        }
        let retained_bytes = self.retained_mutations.iter().try_fold(0u64, |sum, item| {
            sum.checked_add(item.original.bytes)
                .filter(|n| *n <= 64 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "recovered mutation retained byte aggregate",
                ))
        })?;
        if retained_bytes
            .checked_add(original.bytes)
            .is_none_or(|n| n > 64 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered mutation preeffect retained bytes",
            ));
        }
        if let Some((content, bytes)) = &replacement {
            if bytes.len() > 8 * 1024 * 1024
                || content.content_id == original.digest
                || self
                    .new_file_bytes
                    .checked_add(content.length)
                    .is_none_or(|n| n > 64 * 1024 * 1024)
                || sync_extend_cas::plan_bounded_content(bytes, 8 * 1024 * 1024, 128)?.manifest
                    != *content
            {
                return Err(ReconcileError::Invariant(
                    "recovered replacement exact bounded different content",
                ));
            }
            for chunk in &content.chunks {
                let id = chunk.content_id.as_str();
                let file = self
                    .read
                    .read
                    .files
                    .iter()
                    .find(|f| {
                        f.path
                            == self
                                .read
                                .read
                                .data
                                .join("cas/objects")
                                .join(&id[..2])
                                .join(id)
                    })
                    .ok_or(ReconcileError::Invariant("recovered replacement held CAS"))?;
                if file.digest != chunk.content_id || file.bytes != u64::from(chunk.length) {
                    return Err(ReconcileError::Invariant(
                        "recovered replacement CAS identity bytes",
                    ));
                }
            }
        }
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            path,
            previous.root()?,
            original_key.to_string(),
            original_parent.to_string(),
            &original.digest,
            original.bytes,
            replacement.as_ref().map(|r| &r.0),
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "recovered mutation intended bytes",
            ));
        }
        self.poisoned = true;
        let mut receipt = held_external.file.create_new_file(&format!(
            "node-recovered-mutation-{}-{}.frames",
            self.fresh, self.history_count
        ))?;
        receipt.writer().write_all(&intended)?;
        receipt.writer().sync_all()?;
        crate::fault::checkpoint("recovered_mutation_intended_before_directory");
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == external)
                .ok_or(ReconcileError::Invariant("mutation held directory creator"))?;
            let directory_name = format!(
                "node-recovered-retained-{}-{}",
                self.fresh, self.history_count
            );
            let directory = held.file.create_new_rename_destination(&directory_name)?;
            let retained_path = external.join(directory_name);
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "directory_created",
                directory.key()?.to_string(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_mutation_directory_before_move");
            match &self.read.read.files[index].file {
                RecoveredFileProtection::Mutation(file) => {
                    file.rename_no_replace_in(&directory, "original")?
                }
                RecoveredFileProtection::Created(file) => {
                    file.rename_no_replace_in(&directory, "original")?
                }
                _ => {
                    return Err(ReconcileError::Invariant(
                        "recovered original mutation capability",
                    ))
                }
            }
            let mut original = self.read.read.files.remove(index);
            original.path = retained_path.join("original");
            self.retained_mutations.push(RecoveredRetainedMutation {
                directory,
                path: retained_path,
                original,
            });
            self.read
                .read
                .expected_membership
                .get_mut(&parent)
                .ok_or(ReconcileError::Invariant("mutation parent membership"))?
                .remove(&name);
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "original_moved",
                original_key.to_string(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_mutation_moved_before_replacement");
            if let Some((content, bytes)) = &replacement {
                let held = self
                    .read
                    .read
                    .directories
                    .iter()
                    .find(|d| d.path == parent)
                    .ok_or(ReconcileError::Invariant(
                        "mutation replacement held parent",
                    ))?;
                let mut creator = held.file.create_new_file(&name)?;
                creator.writer().write_all(bytes)?;
                creator.writer().sync_all()?;
                let file = creator.seal_original()?;
                if !file.matches_path(&target)? || file.parent_key()? != original_parent {
                    return Err(ReconcileError::Invariant(
                        "mutation replacement exact new CREATE",
                    ));
                }
                self.read.read.files.push(ReacquiredFile {
                    path: target.clone(),
                    file: RecoveredFileProtection::Created(file),
                    digest: content.content_id.clone(),
                    bytes: content.length,
                });
                self.read
                    .read
                    .expected_membership
                    .get_mut(&parent)
                    .ok_or(ReconcileError::Invariant("mutation replacement membership"))?
                    .insert(name.clone());
                self.new_file_bytes += content.length;
            }
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "native_completed",
                replacement.is_some(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_mutation_native_before_history");
            self.poisoned = false;
            self.verify()?;
            let limits = sync_extend_core_model::limits::LocalLimits::default();
            let allowed: std::collections::BTreeSet<_> = previous
                .entries
                .values()
                .filter_map(|e| e.content.as_ref())
                .flat_map(|c| &c.chunks)
                .chain(replacement.iter().flat_map(|(content, _)| &content.chunks))
                .map(|c| c.content_id.clone())
                .collect();
            let cas = sync_extend_cas::Cas::open_existing_session_coordinated(
                &self.read.read.data.join("cas"),
                move |id| {
                    if allowed.contains(id) {
                        Ok(Box::new(()))
                    } else {
                        Err("mutation CAS outside held set".into())
                    }
                },
                || Ok(Box::new(())),
            )?;
            let view = RecoveredSessionScanView(self);
            let first = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
            let second = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
            if first != second {
                return Err(ReconcileError::Unstable);
            }
            let mut manifest =
                crate::build_manifest(&previous, &second, &std::collections::BTreeMap::new())?;
            let change = if let Some((content, _)) = &replacement {
                let actual = manifest
                    .entries
                    .get(&entry.entry_id)
                    .ok_or(ReconcileError::Invariant("mutation replacement entry id"))?;
                if actual.path != *path
                    || actual.content.as_ref() != Some(content)
                    || manifest.entries.len() != previous.entries.len()
                {
                    return Err(ReconcileError::Invariant(
                        "mutation replacement exact manifest delta",
                    ));
                }
                Change::Put {
                    entry: actual.clone(),
                }
            } else {
                if manifest.entries.contains_key(&entry.entry_id)
                    || manifest.entries.len() + 1 != previous.entries.len()
                {
                    return Err(ReconcileError::Invariant(
                        "mutation deletion exact manifest delta",
                    ));
                }
                Change::Delete {
                    entry_id: entry.entry_id.clone(),
                }
            };
            for (id, old) in &previous.entries {
                if id != &entry.entry_id && manifest.entries.get(id) != Some(old) {
                    return Err(ReconcileError::Invariant(
                        "mutation unchanged entry differs",
                    ));
                }
            }
            let device = self.recovered_device_id()?;
            let seq = manifest.version_vector.get(&device).checked_add(1).ok_or(
                ReconcileError::Invariant("mutation local sequence exhausted"),
            )?;
            let operation = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space.clone(),
                origin_device_id: device.clone(),
                origin_seq: seq,
                causal: manifest.version_vector.clone(),
                created_at_ms: timestamp,
                change,
            })?;
            if let Change::Delete { entry_id } = &operation.payload.change {
                manifest
                    .tombstones
                    .insert(entry_id.clone(), operation.op_id.clone());
            }
            manifest.version_vector.observe(device, seq);
            let root = self.commit_exact_recovered_history(manifest, vec![operation], timestamp)?;
            crate::fault::checkpoint("recovered_mutation_history_before_receipt");
            self.poisoned = true;
            receipt
                .writer()
                .write_all(&serde_json::to_vec(&(1u32, "committed", &root))?)?;
            receipt.writer().sync_all()?;
            self.retain_recovered_receipt(receipt)?;
            self.poisoned = false;
            self.verify()?;
            crate::fault::checkpoint("recovered_mutation_committed_after_sync");
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

// Separate descriptive closed-history envelope. It never issues restart authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredMutationHistoryCloseRecord {
    version: u32,
    index: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    session: SpaceId,
    worktree: String,
    data: String,
    keys: [String; 4],
    root: sync_extend_core_model::SnapshotId,
    rows: ContentId,
    main: ContentId,
    shm: ContentId,
    wal2_frames: Option<ContentId>,
    receipts: Vec<(String, ContentId, u64)>,
    history_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<live_retention::RecoveredMetadataCloseEvidence>,
}
#[derive(Serialize)]
pub struct RecoveredMutationHistoryCloseClassification {
    pub state: &'static str,
    pub actual_records: usize,
    pub history_count: u32,
    pub receipts: usize,
    pub native_write_authority: bool,
    pub cleanup_authority: bool,
}
impl FreshRecoveredNodeWalV2Session {
    /// Close the actual native session, then bind complete final rows and all
    /// independently intended history/file/CAS receipts in a separate envelope.
    /// This preserves the original WAL2 record/parser and grants no restart API.
    pub fn close_recovered_mutation_history_with_evidence(&mut self) -> Result<PathBuf> {
        self.verify()?;
        let metadata = self.verified_metadata_close_evidence()?;
        let empty_chain_continuation = self.history_count == 0
            && metadata.is_none()
            && self.history_chain_parent.is_some()
            && self.retained_receipts.is_empty();
        if self.closed
            || (!empty_chain_continuation && self.history_count == 0 && metadata.is_none())
            || self.history_count > FRESH_OPERATION_MAXIMUM
        {
            return Err(ReconcileError::Invariant(
                "explicit live recovered history required",
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("history close external parent"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history close held external"))?;
        let mut receipts = Vec::new();
        let mut aggregate = 0u64;
        for (count, item) in std::fs::read_dir(parent)?.enumerate() {
            if count >= 4096 {
                return Err(ReconcileError::ResourceLimit(
                    "history close external count",
                ));
            }
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("history close external encoding"))?;
            if [
                "history",
                "file",
                "cas",
                "mutation",
                "namespace",
                "retention",
            ]
            .iter()
            .any(|kind| name.starts_with(&format!("node-recovered-{kind}-{}-", self.fresh)))
            {
                let file = self
                    .retained_receipts
                    .get(&name)
                    .ok_or(ReconcileError::Invariant(
                        "history close unheld or foreign receipt",
                    ))?;
                file.file.verify()?;
                let bytes = file.file.exact_bytes(file.bytes)?;
                if ContentId::hash(&bytes) != file.digest || !file.file.matches_path(&file.path)? {
                    return Err(ReconcileError::Invariant(
                        "history close original held receipt differs",
                    ));
                }
                aggregate = aggregate
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= 4 * 1024 * 1024)
                    .ok_or(ReconcileError::ResourceLimit(
                        "history close receipts aggregate",
                    ))?;
                // Each append-only local stream must end in its own synced
                // committed record. Mere intent or materialization stays open.
                live_retention::require_committed_receipt(&name, &bytes)?;
                receipts.push((name, ContentId::hash(&bytes), bytes.len() as u64));
            }
        }
        receipts.sort_by(|a, b| a.0.cmp(&b.0));
        let history_receipts = receipts
            .iter()
            .filter(|r| r.0.starts_with("node-recovered-history-"))
            .count();
        if history_receipts != self.history_count as usize {
            return Err(ReconcileError::Invariant(
                "history close exact committed history count",
            ));
        }
        let main = self.native.exact_main_bytes()?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            ContentId::hash(&main).as_str(),
            main.len(),
            &self.space,
            self.bounds,
        )?;
        let mut intended = RecoveredMutationHistoryCloseRecord {
            version: 8,
            index: 0,
            phase: "close_intended".into(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            session: self.fresh.clone(),
            worktree: self.read.read.worktree.to_string_lossy().into(),
            data: self.read.read.data.to_string_lossy().into(),
            keys: self.native_keys.clone(),
            root: self.read.read.manifest.root()?,
            rows: image.closed_node_complete_rows_digest(&self.space, self.bounds)?,
            main: ContentId::hash(&main),
            shm: ContentId::hash(&self.native.held_shm_bytes()?),
            wal2_frames: None,
            receipts,
            history_count: self.history_count,
            metadata,
        };
        let bytes = serde_json::to_vec(&intended)?;
        if bytes.len() > 256 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history close envelope intended bound",
            ));
        }
        let path = parent.join(format!(
            "node-recovered-mutation-history-close-{}.frames",
            self.fresh
        ));
        self.poisoned = true;
        let mut evidence = held.file.create_new_file(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReconcileError::Invariant("history close component"))?,
        )?;
        evidence
            .writer()
            .write_all(b"SYNC-RECOVERED-MUTATION-HISTORY-CLOSE8\n")?;
        evidence
            .writer()
            .write_all(&(bytes.len() as u32).to_le_bytes())?;
        evidence.writer().write_all(&bytes)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("recovered_mutation_history_close_intended_before_native_close");
        self.poisoned = false;
        let result = (|| -> Result<PathBuf> {
            self.close_completed()?;
            intended.index = 1;
            intended.phase = "closed".into();
            {
                use std::os::windows::fs::FileExt;
                self.frames.original_creation()?.verify()?;
                let length = self.frames.reader().metadata()?.len();
                if length > 256 * 1024 {
                    return Err(ReconcileError::ResourceLimit("history close WAL2 bytes"));
                }
                let mut bytes = vec![0u8; length as usize];
                let mut offset = 0;
                while offset < bytes.len() {
                    let n = self
                        .frames
                        .reader()
                        .seek_read(&mut bytes[offset..], offset as u64)?;
                    if n == 0 {
                        return Err(ReconcileError::Invariant("history close WAL2 short read"));
                    }
                    offset += n;
                }
                intended.wal2_frames = Some(ContentId::hash(&bytes));
            }
            let after = self.native.exact_closed_main_bytes()?;
            if ContentId::hash(&after) != intended.main
                || ContentId::hash(&self.native.held_shm_bytes()?) != intended.shm
            {
                return Err(ReconcileError::Invariant(
                    "history close native bytes changed",
                ));
            }
            let terminal = serde_json::to_vec(&intended)?;
            if terminal.len() > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit(
                    "history close terminal bound",
                ));
            }
            evidence
                .writer()
                .write_all(&(terminal.len() as u32).to_le_bytes())?;
            evidence
                .writer()
                .write_all(ContentId::hash(&bytes).as_str().as_bytes())?;
            evidence.writer().write_all(&terminal)?;
            evidence.writer().sync_all()?;
            self.verify()?;
            self.retain_history_creation(evidence, 512 * 1024)?;
            crate::fault::checkpoint("recovered_mutation_history_closed_after_terminal_sync");
            Ok(path.clone())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
impl super::VerifiedNodeStateArchive {
    /// Classify bytes only. Neither historical native keys nor a digest become
    /// living ownership, cleanup permission, or a recovery writer capability.
    pub fn classify_recovered_mutation_history_close(
        &self,
        bytes: &[u8],
        wal2_frames: &[u8],
    ) -> RecoveredMutationHistoryCloseClassification {
        let parsed = (|| -> Result<RecoveredMutationHistoryCloseRecord> {
            const HEADER: &[u8] = b"SYNC-RECOVERED-MUTATION-HISTORY-CLOSE8\n";
            if !bytes.starts_with(HEADER)
                || bytes.len() > 512 * 1024
                || wal2_frames.len() > 256 * 1024
            {
                return Err(ReconcileError::Invariant("history close bounded header"));
            }
            let mut offset = HEADER.len();
            let read_size = |offset: usize| -> Result<usize> {
                let prefix = bytes
                    .get(offset..offset + 4)
                    .ok_or(ReconcileError::Invariant("history close size"))?;
                Ok(u32::from_le_bytes(
                    prefix
                        .try_into()
                        .map_err(|_| ReconcileError::Invariant("history close size encoding"))?,
                ) as usize)
            };
            let size = read_size(offset)?;
            offset += 4;
            if size > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history close intended size"));
            }
            let payload = bytes
                .get(offset..offset + size)
                .ok_or(ReconcileError::Invariant(
                    "history close intended truncated",
                ))?;
            let first: RecoveredMutationHistoryCloseRecord = serde_json::from_slice(payload)?;
            offset += size;
            let size = read_size(offset)?;
            offset += 4;
            if size > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history close terminal size"));
            }
            let digest = bytes
                .get(offset..offset + 64)
                .ok_or(ReconcileError::Invariant("history close chain"))?;
            offset += 64;
            if digest != ContentId::hash(payload).as_str().as_bytes() {
                return Err(ReconcileError::Invariant(
                    "history close exact intended chain",
                ));
            }
            let final_bytes = bytes
                .get(offset..offset + size)
                .ok_or(ReconcileError::Invariant(
                    "history close terminal truncated",
                ))?;
            let terminal: RecoveredMutationHistoryCloseRecord =
                serde_json::from_slice(final_bytes)?;
            if offset + size != bytes.len()
                || serde_json::to_vec(&first)? != payload
                || serde_json::to_vec(&terminal)? != final_bytes
                || first.version != 8
                || first.index != 0
                || first.phase != "close_intended"
                || first.archive != *self.digest()
                || first.wal2_frames.is_some()
                || (first.history_count == 0
                    && first.metadata.is_none()
                    && !first.receipts.is_empty())
                || first.history_count > FRESH_OPERATION_MAXIMUM
                || terminal.index != 1
                || terminal.phase != "closed"
                || terminal.wal2_frames.as_ref() != Some(&ContentId::hash(wal2_frames))
            {
                return Err(ReconcileError::Invariant(
                    "history close canonical phase and scope",
                ));
            }
            let mut normalized = terminal.clone();
            normalized.index = 0;
            normalized.phase = "close_intended".into();
            normalized.wal2_frames = None;
            if serde_json::to_vec(&normalized)? != payload {
                return Err(ReconcileError::Invariant(
                    "history close final bindings changed",
                ));
            }
            let mut total = 0u64;
            let mut last: Option<&str> = None;
            for (name, _, size) in &terminal.receipts {
                if *size > 256 * 1024
                    || last.is_some_and(|old| old >= name.as_str())
                    || ![
                        "history",
                        "file",
                        "cas",
                        "mutation",
                        "namespace",
                        "retention",
                    ]
                    .iter()
                    .any(|kind| {
                        name.starts_with(&format!("node-recovered-{kind}-{}-", terminal.session))
                    })
                    || !name.ends_with(".frames")
                    || name.contains(['/', '\\'])
                {
                    return Err(ReconcileError::Invariant(
                        "history close exact receipt slots",
                    ));
                }
                total = total
                    .checked_add(*size)
                    .filter(|n| *n <= 4 * 1024 * 1024)
                    .ok_or(ReconcileError::ResourceLimit(
                        "history close exact aggregate",
                    ))?;
                last = Some(name);
            }
            if terminal
                .receipts
                .iter()
                .filter(|r| r.0.starts_with("node-recovered-history-"))
                .count()
                != terminal.history_count as usize
            {
                return Err(ReconcileError::Invariant(
                    "history close exact receipt count",
                ));
            }
            live_retention::validate_close_metadata(
                terminal.metadata.as_ref(),
                terminal.history_count,
                &terminal.receipts,
                &terminal.session,
                &terminal.main,
            )?;
            Ok(terminal)
        })();
        match parsed {
            Ok(record) => RecoveredMutationHistoryCloseClassification {
                state: "closed_descriptive_history_evidence",
                actual_records: 2,
                history_count: record.history_count,
                receipts: record.receipts.len(),
                native_write_authority: false,
                cleanup_authority: false,
            },
            Err(_) => RecoveredMutationHistoryCloseClassification {
                state: "refused_evidence",
                actual_records: 0,
                history_count: 0,
                receipts: 0,
                native_write_authority: false,
                cleanup_authority: false,
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCurrentObject {
    root: String,
    path: String,
    directory: bool,
    key: String,
    parent: String,
    digest: Option<ContentId>,
    bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_metadata: Option<sync_extend_core_model::PortableEntryMetadata>,
}
fn history_current_objects(
    read: &ReacquiredClosedNodeReadScope,
) -> Result<Vec<HistoryCurrentObject>> {
    let mut objects = Vec::new();
    let mut aggregate = 0u64;
    for (label, root) in [("work", &read.worktree), ("data", &read.data)] {
        for directory in &read.directories {
            if directory.path == *root || !directory.path.starts_with(root) {
                continue;
            }
            let parent = directory
                .path
                .parent()
                .ok_or(ReconcileError::Invariant("current directory parent"))?;
            let held = read
                .directories
                .iter()
                .find(|item| item.path == parent)
                .ok_or(ReconcileError::Invariant("current directory parent unheld"))?;
            objects.push(HistoryCurrentObject {
                root: label.into(),
                path: directory
                    .path
                    .strip_prefix(root)
                    .map_err(|_| ReconcileError::Invariant("current directory root"))?
                    .to_string_lossy()
                    .replace('\\', "/"),
                directory: true,
                key: directory.key.to_string(),
                parent: held.key.to_string(),
                digest: None,
                bytes: 0,
                local_metadata: None,
            });
        }
        for file in &read.files {
            if !file.path.starts_with(root)
                || (label == "data"
                    && matches!(
                        file.path.file_name().and_then(|name| name.to_str()),
                        Some(
                            "journal.sqlite"
                                | "journal.sqlite-wal"
                                | "journal.sqlite-journal"
                                | "journal.sqlite-shm"
                        )
                    ))
            {
                continue;
            }
            aggregate = aggregate
                .checked_add(file.bytes)
                .filter(|bytes| *bytes <= 256 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "current objects byte aggregate",
                ))?;
            objects.push(HistoryCurrentObject {
                root: label.into(),
                path: file
                    .path
                    .strip_prefix(root)
                    .map_err(|_| ReconcileError::Invariant("current file root"))?
                    .to_string_lossy()
                    .replace('\\', "/"),
                directory: false,
                key: file.file.key()?.to_string(),
                parent: file.file.parent_key()?.to_string(),
                digest: Some(file.digest.clone()),
                bytes: file.bytes,
                local_metadata: if label == "work" && polling::managed(&file.path, root) {
                    Some(crate::filesystem::portable_metadata_from_capture(file.file.portable_metadata()?)?)
                } else { None },
            });
        }
    }
    objects.sort_by(|a, b| (&a.root, &a.path).cmp(&(&b.root, &b.path)));
    if objects.len() > 4096
        || objects
            .windows(2)
            .any(|pair| pair[0].root == pair[1].root && pair[0].path == pair[1].path)
    {
        return Err(ReconcileError::ResourceLimit(
            "current objects bounded unique slots",
        ));
    }
    let mut keys = std::collections::BTreeSet::new();
    for object in &objects {
        if !keys.insert(object.key.clone()) {
            return Err(ReconcileError::Invariant("current objects native alias"));
        }
    }
    Ok(objects)
}

fn history_current_objects_with_metadata_proof(
    read: &ReacquiredClosedNodeLockedReadScope,
) -> Result<Vec<HistoryCurrentObject>> {
    let mut objects = history_current_objects(&read.read)?;
    let previous: std::collections::BTreeMap<_, _> = read.metadata_observations.iter()
        .map(|object| (object.key.as_str(), object)).collect();
    for object in &mut objects {
        // Closing an old record must not turn a fresh capture into an original
        // projection assertion. Only completed Put or retained original proof
        // may carry full local metadata into the next generation.
        if previous.get(object.key.as_str()).is_none_or(|prior| {
            prior.local_metadata.is_none() || prior.local_metadata != object.local_metadata
                || prior.digest != object.digest || prior.bytes != object.bytes
        }) {
            object.local_metadata = None;
        }
    }
    Ok(objects)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRetainedOriginal {
    name: String,
    key: String,
    parent: String,
    source_parent: String,
    original: HistoryRestartObject,
}
// Independent v5 multi-generation contract. Original restart4 remains unchanged.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryChain8Record {
    version: u32,
    index: u32,
    phase: String,
    archive: ContentId,
    original_frames: ContentId,
    session: SpaceId,
    worktree: String,
    data: String,
    work_key: String,
    data_key: String,
    external_key: String,
    native_keys: [String; 4],
    predecessor: Option<HistoryRestartObject>,
    epoch: Option<HistoryRestartObject>,
    root: sync_extend_core_model::SnapshotId,
    rows: ContentId,
    main: ContentId,
    shm: ContentId,
    owner: HistoryRestartObject,
    baseline: HistoryRestartObject,
    receipts: Vec<HistoryRestartObject>,
    retained_originals: Vec<HistoryRetainedOriginal>,
    current_objects: Vec<HistoryCurrentObject>,
    history_close: Option<HistoryRestartObject>,
    wal2: Option<HistoryRestartObject>,
}
fn history_chain8_records(bytes: &[u8]) -> Result<HistoryChain8Record> {
    const HEADER: &[u8] = b"SYNC-HISTORY-CHAIN8\n";
    if !bytes.starts_with(HEADER) || bytes.len() > 1024 * 1024 {
        return Err(ReconcileError::Invariant(
            "history restart exact bounded header",
        ));
    }
    let mut offset = HEADER.len();
    let mut payloads: Vec<&[u8]> = Vec::new();
    for _ in 0..2 {
        let length = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or(ReconcileError::Invariant("history restart size"))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history restart size encoding"))?,
        ) as usize;
        offset += 4;
        if length > 384 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history restart record bytes",
            ));
        }
        if let Some(previous) = payloads.first() {
            let digest = bytes
                .get(offset..offset + 64)
                .ok_or(ReconcileError::Invariant("history restart chain"))?;
            if digest != ContentId::hash(previous).as_str().as_bytes() {
                return Err(ReconcileError::Invariant(
                    "history restart intended chain changed",
                ));
            }
            offset += 64;
        }
        let payload = bytes
            .get(offset..offset + length)
            .ok_or(ReconcileError::Invariant("history restart truncated"))?;
        payloads.push(payload);
        offset += length;
    }
    let first: HistoryChain8Record = serde_json::from_slice(payloads[0])?;
    let terminal: HistoryChain8Record = serde_json::from_slice(payloads[1])?;
    for object in &terminal.current_objects {
        if let Some(metadata) = &object.local_metadata {
            metadata.validate()?;
            if object.root != "work" || object.directory
                || object.path.split('/').next().is_none_or(|part| part == ".sync-extend") {
                return Err(ReconcileError::Invariant("history local metadata scope"));
            }
        }
    }
    if offset != bytes.len()
        || first.version != 8
        || first.index != 0
        || first.phase != "close_intended"
        || first.wal2.is_some()
        || first.history_close.is_some()
        || terminal.index != 1
        || terminal.phase != "closed"
        || terminal.wal2.is_none()
        || terminal.history_close.is_none()
        || serde_json::to_vec(&first)? != payloads[0]
        || serde_json::to_vec(&terminal)? != payloads[1]
    {
        return Err(ReconcileError::Invariant(
            "history restart canonical terminal",
        ));
    }
    let mut normalized = terminal.clone();
    normalized.index = 0;
    normalized.phase = "close_intended".into();
    normalized.wal2 = None;
    normalized.history_close = None;
    if serde_json::to_vec(&normalized)? != payloads[0] {
        return Err(ReconcileError::Invariant(
            "history restart final bindings changed",
        ));
    }
    Ok(terminal)
}
impl FreshRecoveredNodeWalV2Session {
    /// Publish a fresh protocol that binds actual creator keys, immutable baseline
    /// and final complete history. The original descriptive close remains intact.
    pub fn close_recovered_history_for_chain8(&mut self) -> Result<PathBuf> {
        self.verify()?;
        self.preflight_history_close_envelope(None, false, 0, 0, 0)?;
        self.verified_metadata_close_evidence()?;
        if (self.history_count == 0
            && self.metadata_count == 0
            && self.history_chain_parent.is_none())
            || self.closed
            || self.history_baseline.is_empty()
            || self.history_baseline.len() > 64 * 1024 * 1024
        {
            return Err(ReconcileError::Invariant(
                "history restart explicit live baseline",
            ));
        }
        if self.history_chain_depth >= FRESH_HISTORY_GENERATION_MAXIMUM as u32 {
            return Err(ReconcileError::ResourceLimit(
                "history chain generation preeffect bound",
            ));
        }
        let held_bytes = self
            .retained_history_evidence
            .iter()
            .try_fold(0u64, |sum, item| {
                sum.checked_add(item.bytes)
                    .ok_or(ReconcileError::ResourceLimit(
                        "history chain held bytes overflow",
                    ))
            })?;
        if held_bytes
            .checked_add(66 * 1024 * 1024)
            .is_none_or(|n| n > FRESH_HELD_HISTORY_AGGREGATE_MAXIMUM)
            || self.retained_history_evidence.len() + self.retained_receipts.len() + 4
                > FRESH_HELD_HISTORY_OBJECT_MAXIMUM
        {
            return Err(ReconcileError::ResourceLimit(
                "history chain close preeffect aggregate bound",
            ));
        }
        let main = self.native.exact_main_bytes()?;
        let baseline = sync_extend_journal::JournalBackupImage::from_current_node_image(
            self.history_baseline.clone(),
            ContentId::hash(&self.history_baseline).as_str(),
            self.history_baseline.len(),
            &self.space,
            self.bounds,
        )?;
        let final_image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            ContentId::hash(&main).as_str(),
            main.len(),
            &self.space,
            self.bounds,
        )?;
        let continuation_without_receipts = self.history_count == 0
            && self.metadata_count == 0
            && self.history_chain_parent.is_some()
            && self.retained_receipts.is_empty();
        if continuation_without_receipts {
            if baseline.closed_node_complete_rows_digest(&self.space, self.bounds)?
                != final_image.closed_node_complete_rows_digest(&self.space, self.bounds)?
            {
                return Err(ReconcileError::Invariant(
                    "read-only continuation changed native rows without history",
                ));
            }
        } else {
            final_image.audit_recovered_history_extension_allow_unchanged(
                &baseline,
                &self.space,
                self.bounds,
            )?;
        }
        let parent = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("history restart parent"))?
            .to_path_buf();
        let external = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history restart held external"))?;
        let external_key = external.key.to_string();
        let mut receipts = self
            .retained_receipts
            .values()
            .map(history_object)
            .collect::<Result<Vec<_>>>()?;
        receipts.sort_by(|a, b| a.name.cmp(&b.name));
        if (receipts.is_empty() && self.history_chain_parent.is_none())
            || receipts.len() > FRESH_RECEIPT_COUNT_MAXIMUM
            || receipts
                .iter()
                .try_fold(0u64, |sum, item| {
                    sum.checked_add(item.bytes)
                        .filter(|n| *n <= 4 * 1024 * 1024)
                        .ok_or(ReconcileError::ResourceLimit(
                            "history restart receipt aggregate",
                        ))
                })
                .is_err()
        {
            return Err(ReconcileError::ResourceLimit(
                "history restart bounded receipts",
            ));
        }
        let mut retained_originals = self.history_retained_originals.clone();
        for retained in &self.retained_mutations {
            retained.verify()?;
            let name = retained
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReconcileError::Invariant("mutation chain retained dirname"))?;
            let mut original = history_object(&retained.original)?;
            let source_parent = original.parent.clone();
            original.parent = retained.directory.key()?.to_string();

            retained_originals.push(HistoryRetainedOriginal {
                name: name.to_owned(),
                key: retained.directory.key()?.to_string(),
                parent: retained
                    .directory
                    .original_creation()?
                    .parent_key()?
                    .to_string(),
                source_parent,
                original,
            });
        }
        retained_originals.sort_by(|a, b| a.name.cmp(&b.name));
        if retained_originals.len() > 128
            || retained_originals
                .windows(2)
                .any(|p| p[0].name == p[1].name)
        {
            return Err(ReconcileError::ResourceLimit(
                "mutation chain retained originals bounded unique",
            ));
        }
        let epoch = self
            .retained_history_evidence
            .iter()
            .find(|e| {
                e.path.file_name().and_then(|name| name.to_str())
                    == Some(&format!("node-recovered-shm-epoch-{}.frames", self.fresh))
            })
            .map(history_object)
            .transpose()?;
        if self.history_chain_parent.is_some() != epoch.is_some() {
            return Err(ReconcileError::Invariant(
                "history chain explicit epoch lineage",
            ));
        }
        if let Some(parent) = &self.history_chain_parent {
            let prior = self
                .retained_history_evidence
                .iter()
                .find(|e| e.path.file_name().and_then(|n| n.to_str()) == Some(parent.name.as_str()))
                .ok_or(ReconcileError::Invariant(
                    "history chain predecessor not retained",
                ))?;
            let object = history_object(prior)?;
            if serde_json::to_vec(&object)? != serde_json::to_vec(parent)? {
                return Err(ReconcileError::Invariant(
                    "history chain retained predecessor changed",
                ));
            }
        }
        self.poisoned = true;
        let mut creator = external
            .file
            .create_new_file(&format!("node-history-baseline-{}.image", self.fresh))?;
        creator.writer().write_all(&self.history_baseline)?;
        creator.writer().sync_all()?;
        let baseline = self.retain_history_creation(creator, 64 * 1024 * 1024)?;
        let root = self.read.read.manifest.root()?;
        let mut record = HistoryChain8Record {
            version: 8,
            index: 0,
            phase: "close_intended".into(),
            archive: self.archive.clone(),
            original_frames: self.original_frames.clone(),
            session: self.fresh.clone(),
            worktree: self.read.read.worktree.to_string_lossy().into(),
            data: self.read.read.data.to_string_lossy().into(),
            work_key: self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == self.read.read.worktree)
                .ok_or(ReconcileError::Invariant("history work root"))?
                .key
                .to_string(),
            data_key: self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == self.read.read.data)
                .ok_or(ReconcileError::Invariant("history data root"))?
                .key
                .to_string(),
            external_key,
            native_keys: self.native_keys.clone(),
            predecessor: self.history_chain_parent.clone(),
            epoch,
            root,
            rows: final_image.closed_node_complete_rows_digest(&self.space, self.bounds)?,
            main: ContentId::hash(&main),
            shm: ContentId::hash(&self.native.held_shm_bytes()?),
            owner: HistoryRestartObject {
                name: format!("node-recovered-wal-{}.owner", self.fresh),
                key: self.owner.original_creation()?.key()?.to_string(),
                parent: self.owner.original_creation()?.parent_key()?.to_string(),
                digest: ContentId::hash(&read_history_owned_bytes(&self.owner, 65536)?),
                bytes: self.owner.reader().metadata()?.len(),
            },
            baseline,
            receipts,
            retained_originals,
            current_objects: history_current_objects_with_metadata_proof(&self.read)?,
            history_close: None,
            wal2: None,
        };
        let intended = history_close_budget::encode(&record)?;
        if intended.len() > 384 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history restart intended bound",
            ));
        }
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == parent)
            .ok_or(ReconcileError::Invariant("history restart external"))?;
        let path = parent.join(format!("node-history-chain8-{}.frames", self.fresh));
        let mut evidence = held.file.create_new_file(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReconcileError::Invariant("history restart frame name"))?,
        )?;
        evidence.writer().write_all(b"SYNC-HISTORY-CHAIN8\n")?;
        evidence
            .writer()
            .write_all(&(intended.len() as u32).to_le_bytes())?;
        evidence.writer().write_all(&intended)?;
        evidence.writer().sync_all()?;
        crate::fault::checkpoint("history_chain8_intended_before_native_close");
        self.poisoned = false;
        let result = (|| -> Result<PathBuf> {
            let closed_path = self.close_recovered_mutation_history_with_evidence()?;
            let close = self
                .retained_history_evidence
                .iter()
                .find(|e| e.path == closed_path)
                .ok_or(ReconcileError::Invariant(
                    "history restart close creator held",
                ))?;
            record.history_close = Some(history_object(close)?);
            let frame_bytes = self.frames.reader().metadata()?.len();
            if frame_bytes > 256 * 1024 {
                return Err(ReconcileError::ResourceLimit("history restart WAL2 size"));
            }
            let wal_key = self.frames.original_creation()?.key()?.to_string();
            let wal_parent = self.frames.original_creation()?.parent_key()?.to_string();
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|d| d.path == parent)
                .ok_or(ReconcileError::Invariant("history restart frame external"))?;
            // The original creator is still held; reopen is unnecessary.
            let bytes = read_history_owned_bytes(&self.frames, 256 * 1024)?;
            let _ = held;
            record.wal2 = Some(HistoryRestartObject {
                name: self
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(ReconcileError::Invariant("history WAL name"))?
                    .into(),
                key: wal_key,
                parent: wal_parent,
                digest: ContentId::hash(&bytes),
                bytes: frame_bytes,
            });
            record.index = 1;
            record.phase = "closed".into();
            let terminal = history_close_budget::encode(&record)?;
            if terminal.len() > 384 * 1024 {
                return Err(ReconcileError::ResourceLimit(
                    "history restart terminal bound",
                ));
            }
            evidence
                .writer()
                .write_all(&(terminal.len() as u32).to_le_bytes())?;
            evidence
                .writer()
                .write_all(ContentId::hash(&intended).as_str().as_bytes())?;
            evidence.writer().write_all(&terminal)?;
            evidence.writer().sync_all()?;
            self.retain_history_creation(evidence, 1024 * 1024)?;
            self.verify()?;
            crate::fault::checkpoint("history_chain8_closed_after_terminal_sync");
            Ok(path)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
struct LoadedHistoryGeneration {
    record: HistoryChain8Record,
    wal: Vec<RecoveredWalV2Record>,
    baseline: sync_extend_journal::JournalBackupImage,
    frame_object: HistoryRestartObject,
    retained_directories: Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    metadata: Option<live_retention::RecoveredMetadataCloseEvidence>,
}
fn hold_history_chain_object(
    held: &sync_extend_platform_fs::LockedDirectory,
    parent: &std::path::Path,
    object: &HistoryRestartObject,
    maximum: u64,
    retained: &mut std::collections::BTreeMap<String, ReacquiredFile>,
    aggregate: &mut u64,
) -> Result<Vec<u8>> {
    if object.name.is_empty()
        || object.name.contains(['/', '\\'])
        || object.name.len() > 255
        || object.bytes > maximum
        || object.parent != held.key()?.to_string()
    {
        return Err(ReconcileError::Invariant(
            "history chain bounded exact object slot",
        ));
    }
    if let Some(previous) = retained.get(&object.name) {
        if serde_json::to_vec(&history_object(previous)?)? != serde_json::to_vec(object)? {
            return Err(ReconcileError::Invariant(
                "history chain conflicting repeated object",
            ));
        }
        return previous.file.exact_bytes(object.bytes).map_err(Into::into);
    }
    if retained.len() >= 4096 {
        return Err(ReconcileError::ResourceLimit(
            "history chain aggregate held objects",
        ));
    }
    *aggregate = aggregate
        .checked_add(object.bytes)
        .filter(|n| *n <= 256 * 1024 * 1024)
        .ok_or(ReconcileError::ResourceLimit(
            "history chain aggregate bytes before acquisition",
        ))?;
    let file = held.reacquire_existing_node_read_file(&object.name)?;
    let bytes = file.exact_bytes(maximum)?;
    if bytes.len() as u64 != object.bytes
        || ContentId::hash(&bytes) != object.digest
        || file.key()?.to_string() != object.key
        || file.parent_key()?.to_string() != object.parent
        || !file.matches_path(&parent.join(&object.name))?
    {
        return Err(ReconcileError::Invariant(
            "history chain held key parent and exact bytes",
        ));
    }
    retained.insert(
        object.name.clone(),
        ReacquiredFile {
            path: parent.join(&object.name),
            file: RecoveredFileProtection::Read(file),
            bytes: object.bytes,
            digest: object.digest.clone(),
        },
    );
    Ok(bytes)
}

impl super::VerifiedNodeStateArchive {
    #[allow(clippy::too_many_arguments)]
    fn load_history_generation(
        &self,
        held: &sync_extend_platform_fs::LockedDirectory,
        parent: &std::path::Path,
        object: HistoryRestartObject,
        bounds: sync_extend_journal::NodeInspectionBounds,
        retained: &mut std::collections::BTreeMap<String, ReacquiredFile>,
        aggregate: &mut u64,
    ) -> Result<LoadedHistoryGeneration> {
        let bytes =
            hold_history_chain_object(held, parent, &object, 1024 * 1024, retained, aggregate)?;
        let record = history_chain8_records(&bytes)?;
        if object.name != format!("node-history-chain8-{}.frames", record.session)
            || record.archive != *self.digest()
            || record.external_key != held.key()?.to_string()
            || record.baseline.name != format!("node-history-baseline-{}.image", record.session)
            || record.predecessor.is_some() != record.epoch.is_some()
            || (record.receipts.is_empty() && record.predecessor.is_none())
            || record.receipts.len() > FRESH_RECEIPT_COUNT_MAXIMUM
        {
            return Err(ReconcileError::Invariant(
                "history chain exact generation binding",
            ));
        }
        let baseline_bytes = hold_history_chain_object(
            held,
            parent,
            &record.baseline,
            64 * 1024 * 1024,
            retained,
            aggregate,
        )?;
        let baseline = sync_extend_journal::JournalBackupImage::from_current_node_image(
            baseline_bytes.clone(),
            record.baseline.digest.as_str(),
            baseline_bytes.len(),
            self.space(),
            bounds,
        )?;
        let close = record
            .history_close
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "history chain closed evidence absent",
            ))?;
        let wal_object = record
            .wal2
            .as_ref()
            .ok_or(ReconcileError::Invariant("history chain closed WAL absent"))?;
        if close.name
            != format!(
                "node-recovered-mutation-history-close-{}.frames",
                record.session
            )
            || wal_object.name != format!("node-recovered-wal-{}.frames", record.session)
        {
            return Err(ReconcileError::Invariant("history chain exact close slots"));
        }
        let close_bytes =
            hold_history_chain_object(held, parent, close, 512 * 1024, retained, aggregate)?;
        let wal_bytes =
            hold_history_chain_object(held, parent, wal_object, 256 * 1024, retained, aggregate)?;
        let wal = history_restart_wal_records(&wal_bytes)?;
        let first = &wal[1];
        let terminal = &wal[3];
        let baseline_rows = baseline.closed_node_complete_rows_digest(self.space(), bounds)?;
        if terminal.archive != record.archive
            || terminal.original_frames != record.original_frames
            || terminal.fresh != record.session
            || terminal.keys != record.native_keys
            || terminal.rows != record.rows
            || terminal.main != record.main
            || terminal.shm != record.shm
            || terminal.worktree != record.worktree
            || terminal.data != record.data
            || first.main != record.baseline.digest
            || baseline_rows != first.rows
            || (record.receipts.is_empty() && baseline_rows != terminal.rows)
        {
            return Err(ReconcileError::Invariant(
                "history chain complete WAL and baseline binding",
            ));
        }
        let classification =
            self.classify_recovered_mutation_history_close(&close_bytes, &wal_bytes);
        if classification.state != "closed_descriptive_history_evidence"
            || classification.receipts != record.receipts.len()
        {
            return Err(ReconcileError::Invariant(
                "history chain exact descriptive close",
            ));
        }
        let header = b"SYNC-RECOVERED-MUTATION-HISTORY-CLOSE8\n";
        let size = u32::from_le_bytes(
            close_bytes
                .get(header.len()..header.len() + 4)
                .ok_or(ReconcileError::Invariant(
                    "history chain close intended length",
                ))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history chain close size encoding"))?,
        ) as usize;
        let final_offset = header.len() + 4 + size;
        let size = u32::from_le_bytes(
            close_bytes
                .get(final_offset..final_offset + 4)
                .ok_or(ReconcileError::Invariant(
                    "history chain close terminal length",
                ))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history chain close size encoding"))?,
        ) as usize;
        let terminal_close: RecoveredMutationHistoryCloseRecord = serde_json::from_slice(
            close_bytes
                .get(final_offset + 68..final_offset + 68 + size)
                .ok_or(ReconcileError::Invariant(
                    "history chain close final payload",
                ))?,
        )?;
        let receipts = record
            .receipts
            .iter()
            .map(|r| (r.name.clone(), r.digest.clone(), r.bytes))
            .collect::<Vec<_>>();
        if terminal_close.archive != record.archive
            || terminal_close.original_frames != record.original_frames
            || terminal_close.session != record.session
            || terminal_close.keys != record.native_keys
            || terminal_close.worktree != record.worktree
            || terminal_close.data != record.data
            || terminal_close.root != record.root
            || terminal_close.rows != record.rows
            || terminal_close.main != record.main
            || terminal_close.shm != record.shm
            || terminal_close.receipts != receipts
        {
            return Err(ReconcileError::Invariant(
                "history chain exact independent descriptive records",
            ));
        }
        let mut previous: Option<&str> = None;
        let mut receipt_bytes = 0u64;
        for receipt in &record.receipts {
            if previous.is_some_and(|old| old >= receipt.name.as_str())
                || ![
                    "history",
                    "file",
                    "cas",
                    "mutation",
                    "namespace",
                    "retention",
                ]
                .iter()
                .any(|kind| {
                    receipt
                        .name
                        .starts_with(&format!("node-recovered-{kind}-{}-", record.session))
                })
            {
                return Err(ReconcileError::Invariant(
                    "history chain exact receipt sequence",
                ));
            }
            receipt_bytes = receipt_bytes
                .checked_add(receipt.bytes)
                .filter(|n| *n <= 4 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "history chain generation receipt bytes",
                ))?;
            let bytes =
                hold_history_chain_object(held, parent, receipt, 256 * 1024, retained, aggregate)?;
            live_retention::require_committed_receipt(&receipt.name, &bytes)?;
            previous = Some(&receipt.name);
        }
        live_retention::verify_generation_metadata(
            self,
            &record,
            terminal_close.metadata.as_ref(),
            &baseline,
            retained,
            bounds,
        )?;
        if let Some(epoch) = &record.epoch {
            if epoch.name != format!("node-recovered-shm-epoch-{}.frames", record.session) {
                return Err(ReconcileError::Invariant("history chain epoch exact slot"));
            }
            let bytes =
                hold_history_chain_object(held, parent, epoch, 256 * 1024, retained, aggregate)?;
            let values = serde_json::Deserializer::from_slice(&bytes)
                .into_iter::<serde_json::Value>()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if values.len() != 2
                || values[0].get(1).and_then(|v| v.as_str()) != Some("shm_epoch_intended")
                || values[1].get(1).and_then(|v| v.as_str()) != Some("shm_epoch_initialized")
                || values[0].get(5).and_then(|v| v.as_str()) != Some(record.session.as_str())
                || values[1].get(2).and_then(|v| v.as_str()) != Some(record.session.as_str())
                || values[1].get(4) != Some(&serde_json::to_value(&record.native_keys)?)
            {
                return Err(ReconcileError::Invariant(
                    "history chain exact initialized epoch",
                ));
            }
        }
        for object in record.retained_originals.iter().filter(|item| {
            item.name
                .starts_with(&format!("node-recovered-retained-{}-", record.session))
        }) {
            let suffix = object
                .name
                .strip_prefix(&format!("node-recovered-retained-{}-", record.session))
                .ok_or(ReconcileError::Invariant("mutation retained exact session"))?;
            let receipt_name =
                format!("node-recovered-mutation-{}-{suffix}.frames", record.session);
            let receipt = record
                .receipts
                .iter()
                .find(|item| item.name == receipt_name)
                .ok_or(ReconcileError::Invariant(
                    "mutation retained exact intent receipt",
                ))?;
            let bytes = retained
                .get(&receipt.name)
                .ok_or(ReconcileError::Invariant("mutation held receipt absent"))?
                .file
                .exact_bytes(receipt.bytes)?;
            let values = serde_json::Deserializer::from_slice(&bytes)
                .into_iter::<serde_json::Value>()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let first = values.first().ok_or(ReconcileError::Invariant(
                "mutation intended receipt absent",
            ))?;
            if first.get(1) != Some(&serde_json::to_value(&record.archive)?)
                || first.get(2) != Some(&serde_json::to_value(&record.session)?)
                || first.get(5).and_then(|v| v.as_str()) != Some(object.original.key.as_str())
                || first.get(6).and_then(|v| v.as_str()) != Some(object.source_parent.as_str())
                || first.get(7) != Some(&serde_json::to_value(&object.original.digest)?)
                || first.get(8).and_then(|v| v.as_u64()) != Some(object.original.bytes)
                || !values.iter().any(|value| {
                    value.get(1).and_then(|v| v.as_str()) == Some("directory_created")
                        && value.get(2).and_then(|v| v.as_str()) == Some(object.key.as_str())
                })
                || !values.iter().any(|value| {
                    value.get(1).and_then(|v| v.as_str()) == Some("original_moved")
                        && value.get(2).and_then(|v| v.as_str())
                            == Some(object.original.key.as_str())
                })
            {
                return Err(ReconcileError::Invariant(
                    "mutation retained exact native intended bindings",
                ));
            }
        }
        for receipt in record
            .receipts
            .iter()
            .filter(|item| item.name.starts_with("node-recovered-mutation-"))
        {
            let suffix = receipt
                .name
                .strip_prefix(&format!("node-recovered-mutation-{}-", record.session))
                .and_then(|s| s.strip_suffix(".frames"))
                .ok_or(ReconcileError::Invariant(
                    "mutation receipt exact generation",
                ))?;
            if !record.retained_originals.iter().any(|item| {
                item.name == format!("node-recovered-retained-{}-{suffix}", record.session)
            }) {
                return Err(ReconcileError::Invariant(
                    "mutation receipt retained original absent",
                ));
            }
        }
        let mut retained_directories = Vec::new();
        let mut prior_name: Option<&str> = None;
        let mut retained_bytes = 0u64;
        for item in &record.retained_originals {
            if prior_name.is_some_and(|name| name >= item.name.as_str())
                || !item.name.starts_with("node-recovered-retained-")
                || item.name.contains(['/', '\\'])
                || item.original.name != "original"
                || item.parent != record.external_key
            {
                return Err(ReconcileError::Invariant(
                    "mutation chain exact retained directory namespace",
                ));
            }
            retained_bytes = retained_bytes
                .checked_add(item.original.bytes)
                .filter(|n| *n <= 64 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "mutation chain retained original aggregate",
                ))?;
            let path = parent.join(&item.name);
            let directory = sync_extend_platform_fs::LockedDirectory::open(&path)?;
            directory.require_local_ntfs(&path)?;
            if directory.key()?.to_string() != item.key || !directory.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "mutation chain retained directory native identity",
                ));
            }
            let names = std::fs::read_dir(&path)?
                .map(|entry| entry.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            if names != vec![std::ffi::OsString::from("original")]
                || item.original.parent != item.key
            {
                return Err(ReconcileError::Invariant(
                    "mutation chain retained original exact membership",
                ));
            }
            let slot = format!("{}/original", item.name);
            if let Some(previous) = retained.get(&slot) {
                let mut object = history_object(previous)?;
                object.parent = item.key.clone();
                if serde_json::to_vec(&object)? != serde_json::to_vec(&item.original)? {
                    return Err(ReconcileError::Invariant(
                        "mutation chain retained lineage differs",
                    ));
                }
            } else {
                *aggregate = aggregate
                    .checked_add(item.original.bytes)
                    .filter(|n| *n <= 256 * 1024 * 1024)
                    .ok_or(ReconcileError::ResourceLimit(
                        "mutation chain retained allbytes",
                    ))?;
                let file = directory.reacquire_existing_node_read_file("original")?;
                let bytes = file.exact_bytes(64 * 1024 * 1024)?;
                if file.key()?.to_string() != item.original.key
                    || file.parent_key()?.to_string() != item.key
                    || bytes.len() as u64 != item.original.bytes
                    || ContentId::hash(&bytes) != item.original.digest
                    || !file.matches_path(&path.join("original"))?
                {
                    return Err(ReconcileError::Invariant(
                        "mutation chain exact held retained original",
                    ));
                }
                retained.insert(
                    slot,
                    ReacquiredFile {
                        path: path.join("original"),
                        file: RecoveredFileProtection::Read(file),
                        bytes: item.original.bytes,
                        digest: item.original.digest.clone(),
                    },
                );
            }
            if !directory.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "mutation chain retained slot changed",
                ));
            }
            retained_directories.push((path, directory));
            prior_name = Some(&item.name);
        }
        Ok(LoadedHistoryGeneration {
            record,
            wal,
            baseline,
            frame_object: object,
            retained_directories,
            metadata: terminal_close.metadata,
        })
    }
}

impl super::VerifiedNodeStateArchive {
    /// Every generation is explicitly reacquired and fully checked before a
    /// fresh write intent. Historical digests identify evidence, never authority.
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_closed_history_chain8(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        chain_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_closed_history_chain8_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            chain_frames,
            bounds,
            ledger_bounds,
            false,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reacquire_closed_history_chain8_with_mutation(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        chain_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        self.reacquire_closed_history_chain8_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            chain_frames,
            bounds,
            ledger_bounds,
            true,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reacquire_closed_history_chain8_for_deployment(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        chain_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        configs: crate::SeparatedDeploymentNodeConfigs,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        configs.verify_for_archive(self, worktree, data)?;
        let mut session = self.reacquire_closed_history_chain8_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            chain_frames,
            bounds,
            ledger_bounds,
            false,
            None,
            Some(&configs),
        )?;
        session.separated_deployment_configs = Some(configs);
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    fn reacquire_closed_history_chain8_internal(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        chain_frames: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
        mutation_requested: bool,
        operation_preflight: Option<RecoveredHistoryOperation<'_>>,
        separated_configs: Option<&crate::SeparatedDeploymentNodeConfigs>,
    ) -> Result<FreshRecoveredNodeWalV2Session> {
        let parent = original_frames
            .parent()
            .ok_or(ReconcileError::Invariant("history chain external parent"))?;
        if chain_frames.parent() != Some(parent) || restore_ledger.parent() != Some(parent) {
            return Err(ReconcileError::Invariant(
                "history chain exact external slots",
            ));
        }
        let ancestors = super::external::hold_ancestors(parent)?;
        let held = &ancestors
            .last()
            .ok_or(ReconcileError::Invariant("history chain held parent"))?
            .1;
        let head_name = chain_frames
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ReconcileError::Invariant("history chain head component"))?;
        let head = held.reacquire_existing_node_read_file(head_name)?;
        let head_bytes = head.exact_bytes(1024 * 1024)?;
        let head_object = HistoryRestartObject {
            name: head_name.into(),
            key: head.key()?.to_string(),
            parent: head.parent_key()?.to_string(),
            digest: ContentId::hash(&head_bytes),
            bytes: head_bytes.len() as u64,
        };
        drop(head);
        let mut next = head_object.clone();
        let mut generations = Vec::new();
        let mut sessions = std::collections::BTreeSet::new();
        let mut retained = std::collections::BTreeMap::new();
        let mut aggregate = 0u64;
        let mut owner_evidence = Vec::new();
        let mut owner_locks = Vec::new();
        loop {
            if generations.len() >= FRESH_HISTORY_GENERATION_MAXIMUM {
                return Err(ReconcileError::ResourceLimit(
                    "history chain maximum generations",
                ));
            }
            let generation = self.load_history_generation(
                held,
                parent,
                next,
                bounds,
                &mut retained,
                &mut aggregate,
            )?;
            let record = &generation.record;
            if record.worktree != worktree.to_string_lossy()
                || record.data != data.to_string_lossy()
                || !sessions.insert(record.session.clone())
            {
                return Err(ReconcileError::Invariant(
                    "history chain exact roots or cycle",
                ));
            }
            let owner_name = format!("node-recovered-wal-{}.owner", record.session);
            let owner = held.reacquire_existing_node_read_file(&owner_name)?;
            let owner_bytes = owner.exact_bytes(ORIGINAL_WRITE_OWNER_MAXIMUM)?;
            let owner_object = HistoryRestartObject {
                name: owner_name.clone(),
                key: owner.key()?.to_string(),
                parent: owner.parent_key()?.to_string(),
                digest: ContentId::hash(&owner_bytes),
                bytes: owner_bytes.len() as u64,
            };
            if serde_json::to_vec(&owner_object)? != serde_json::to_vec(&record.owner)? {
                return Err(ReconcileError::Invariant(
                    "history chain exact native owner identity bytes",
                ));
            }

            if owner_bytes != serde_json::to_vec(&(2u32, self.digest(), &record.session))? {
                return Err(ReconcileError::Invariant("history chain canonical owner"));
            }
            aggregate = aggregate
                .checked_add(owner_bytes.len() as u64)
                .filter(|n| *n <= 256 * 1024 * 1024)
                .ok_or(ReconcileError::ResourceLimit(
                    "history chain owner aggregate",
                ))?;
            owner_locks.push(owner.acquire_fresh_coordination_lock(false)?);
            owner_evidence.push(ReacquiredExternalEvidence {
                path: parent.join(owner_name),
                file: owner,
                digest: ContentId::hash(&owner_bytes),
                bytes: owner_bytes.len() as u64,
            });
            let predecessor = record.predecessor.clone();
            generations.push(generation);
            if let Some(predecessor) = predecessor {
                next = predecessor;
            } else {
                break;
            }
        }
        let record = generations[0].record.clone();
        let mut history_retained_directories = Vec::new();
        for generation in &mut generations {
            history_retained_directories.append(&mut generation.retained_directories);
        }

        for pair in generations.windows(2) {
            let newer = &pair[0];
            let older = &pair[1];
            if newer.record.predecessor.as_ref().is_none_or(|object| {
                serde_json::to_vec(object).ok() != serde_json::to_vec(&older.frame_object).ok()
            }) || newer.record.original_frames != older.record.original_frames
                || newer.record.work_key != older.record.work_key
                || newer.record.data_key != older.record.data_key
                || newer.record.external_key != older.record.external_key
                || newer.record.native_keys != older.record.native_keys
                || newer.wal[3].previous != older.record.session
                || newer.wal[3].predecessor.as_ref()
                    != older.record.wal2.as_ref().map(|wal| &wal.digest)
            {
                return Err(ReconcileError::Invariant(
                    "history chain exact predecessor and native lineage",
                ));
            }
            if newer.baseline.recovered_session_preserved_rows_digest(
                self.space(),
                bounds,
                &older.record.session,
                &newer.record.session,
            )? != older.record.rows
            {
                return Err(ReconcileError::Invariant(
                    "history chain next baseline complete prior final rows",
                ));
            }
            for old in &older.record.retained_originals {
                let new = newer
                    .record
                    .retained_originals
                    .iter()
                    .find(|item| item.name == old.name)
                    .ok_or(ReconcileError::Invariant(
                        "mutation chain prior retained original missing",
                    ))?;
                if serde_json::to_vec(old)? != serde_json::to_vec(new)? {
                    return Err(ReconcileError::Invariant(
                        "mutation chain prior retained original altered",
                    ));
                }
            }
            if newer.record.retained_originals.iter().any(|item| {
                !older
                    .record
                    .retained_originals
                    .iter()
                    .any(|old| old.name == item.name)
                    && !item.name.starts_with(&format!(
                        "node-recovered-retained-{}-",
                        newer.record.session
                    ))
            }) {
                return Err(ReconcileError::Invariant(
                    "mutation chain foreign retained generation",
                ));
            }
            let normalized = newer.baseline.normalize_recovered_history_session(
                self.space(),
                bounds,
                &older.record.session,
                &newer.record.session,
            )?;
            normalized.audit_recovered_history_extension_allow_unchanged(
                &older.baseline,
                self.space(),
                bounds,
            )?;
            let epoch = newer
                .record
                .epoch
                .as_ref()
                .ok_or(ReconcileError::Invariant("history chain epoch absent"))?;
            let epoch_bytes = retained
                .get(&epoch.name)
                .ok_or(ReconcileError::Invariant("history chain epoch unheld"))?
                .file
                .exact_bytes(epoch.bytes)?;
            let values = serde_json::Deserializer::from_slice(&epoch_bytes)
                .into_iter::<serde_json::Value>()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if values[0]
                != serde_json::to_value((
                    1u32,
                    "shm_epoch_intended",
                    self.digest(),
                    &record.original_frames,
                    &older.record.session,
                    &newer.record.session,
                    &older.record.native_keys,
                    &older.record.main,
                    &older.record.shm,
                    &older.record.rows,
                ))?
            {
                return Err(ReconcileError::Invariant(
                    "history chain epoch exact predecessor effect",
                ));
            }
        }
        let oldest = generations
            .last()
            .ok_or(ReconcileError::Invariant("history chain empty"))?;
        if oldest.wal[3].predecessor.is_some() || oldest.record.epoch.is_some() {
            return Err(ReconcileError::Invariant(
                "history chain first generation cannot borrow predecessor",
            ));
        }
        let original_name = original_frames.file_name().and_then(|n| n.to_str()).ok_or(
            ReconcileError::Invariant("history chain original component"),
        )?;
        let original = held.reacquire_existing_node_read_file(original_name)?;
        let original_bytes = original.exact_bytes(1024 * 1024)?;
        if ContentId::hash(&original_bytes) != record.original_frames
            || self
                .classify_original_node_write_frames(&original_bytes)
                .state
                != "closed_evidence"
        {
            return Err(ReconcileError::Invariant(
                "history chain complete original scope",
            ));
        }
        let size = u32::from_le_bytes(
            original_bytes
                .get(16..20)
                .ok_or(ReconcileError::Invariant("history chain original size"))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history chain original size bytes"))?,
        ) as usize;
        let scope: OriginalWriteScope =
            serde_json::from_slice(original_bytes.get(84..84 + size).ok_or(
                ReconcileError::Invariant("history chain original scope truncated"),
            )?)?;
        scope.validate()?;
        if oldest.wal[3].previous != scope.session {
            return Err(ReconcileError::Invariant(
                "history chain original session lineage",
            ));
        }
        let original_rows = oldest.baseline.recovered_session_preserved_rows_digest(
            self.space(),
            bounds,
            &scope.session,
            &oldest.record.session,
        )?;
        let baseline = &generations[0].baseline;
        let wal = record.wal2.as_ref().ok_or(ReconcileError::Invariant(
            "history chain terminal WAL absent",
        ))?;
        let mut names = retained
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        names.extend(
            history_retained_directories.iter().filter_map(|(path, _)| {
                path.file_name().and_then(|n| n.to_str()).map(str::to_owned)
            }),
        );
        names.extend(owner_evidence.iter().filter_map(|e| {
            e.path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
        }));
        for (count, item) in std::fs::read_dir(parent)?.enumerate() {
            if count as u64 >= ledger_bounds.max_records {
                return Err(ReconcileError::ResourceLimit(
                    "history chain exact external membership bound",
                ));
            }
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("history chain name encoding"))?;
            if (name.starts_with("node-recovered-") || name.starts_with("node-history-"))
                && !names.contains(&name)
            {
                return Err(ReconcileError::Invariant(
                    "history chain unresolved or foreign attempt",
                ));
            }
        }
        let admission = FreshSessionRecord {
            version: 2,
            phase: "closed".into(),
            archive: self.digest().clone(),
            original_frames: record.original_frames.clone(),
            original_completion: scope.completion.clone(),
            predecessor_frames: None,
            previous: scope.session.clone(),
            fresh: record.session.clone(),
            worktree: record.worktree.clone(),
            data: record.data.clone(),
            keys: record.native_keys[..3]
                .to_vec()
                .try_into()
                .map_err(|_| ReconcileError::Invariant("history three native keys"))?,
            rows: record.rows.clone(),
            main: record.main.clone(),
            wal_shm: Some((record.native_keys[3].clone(), record.shm.clone())),
            history_admission: Some(RecoveredHistoryAdmission {
                original_rows,
                final_rows: record.rows.clone(),
                final_root: record.root.clone(),
                mutation_requested,
            }),
        };
        drop(original);
        let mut read = self.reacquire_closed_node_locked_scope_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            bounds,
            ledger_bounds,
            true,
            Some(&admission),
            separated_configs,
        )?;
        if read
            .read
            .directories
            .iter()
            .find(|d| d.path == worktree)
            .is_none_or(|d| d.key.to_string() != record.work_key)
            || read
                .read
                .directories
                .iter()
                .find(|d| d.path == data)
                .is_none_or(|d| d.key.to_string() != record.data_key)
        {
            return Err(ReconcileError::Invariant(
                "history actual retained roots changed",
            ));
        }
        let mut current_objects = history_current_objects(&read.read)?;
        for (object, old) in current_objects.iter_mut().zip(&record.current_objects) {
            // An older record has no full metadata proof. Keep its original
            // fields exact without manufacturing a new captured assertion.
            if old.local_metadata.is_none() {
                object.local_metadata = None;
            }
        }
        if serde_json::to_vec(&current_objects)? != serde_json::to_vec(&record.current_objects)? {
            return Err(ReconcileError::Invariant(
                "history8 complete current native objects key parent bytes changed",
            ));
        }
        read.metadata_observations = record.current_objects.clone();
        let main = read
            .read
            .files
            .iter()
            .find(|f| f.path == data.join("journal.sqlite"))
            .ok_or(ReconcileError::Invariant("history held current main"))?
            .file
            .exact_bytes(scope.max_main_bytes)?;
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            main.clone(),
            record.main.as_str(),
            main.len(),
            self.space(),
            bounds,
        )?;
        image.audit_recovered_history_extension_allow_unchanged(baseline, self.space(), bounds)?;
        live_retention::verify_chain_metadata_sql(self, &generations, &image, &retained, bounds)?;
        read.external.extend(owner_evidence);
        read.locks.extend(owner_locks);
        read.verify()?;
        if let Some(operation) = operation_preflight {
            live_retention::preflight_operation(
                self,
                &read,
                &image,
                &retained,
                &record.native_keys,
                &record.original_frames,
                operation,
                bounds,
            )?;
        }
        let total = scope
            .max_main_bytes
            .checked_add(scope.max_wal_bytes)
            .and_then(|n| n.checked_add(scope.max_rollback_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(ReconcileError::ResourceLimit(
                "history native aggregate overflow",
            ))?;
        if total > 512 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "history native aggregate before effects",
            ));
        }
        if generations.len() >= FRESH_HISTORY_GENERATION_MAXIMUM
            || retained.len() + read.external.len() + 4 > 4096
            || aggregate
                .checked_add(256 * 1024)
                .is_none_or(|n| n > 256 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "history chain fresh effects aggregate bound",
            ));
        }
        let fresh = SpaceId::random()?;
        let name = format!("node-recovered-wal-{fresh}");
        let mut owner = held.create_new_file(&(name.clone() + ".owner"))?;
        owner
            .writer()
            .write_all(&serde_json::to_vec(&(2u32, self.digest(), &fresh))?)?;
        owner.writer().sync_all()?;
        let mut frames = held.create_new_file(&(name.clone() + ".frames"))?;
        let intent = serde_json::to_vec(&(
            2u32,
            self.digest(),
            &record.original_frames,
            &record.session,
            &fresh,
        ))?;
        frames.writer().write_all(b"SYNC-RECOVERED-WAL2\n")?;
        frames
            .writer()
            .write_all(&(intent.len() as u32).to_le_bytes())?;
        frames.writer().write_all(&intent)?;
        frames.writer().sync_all()?;
        crate::fault::checkpoint("history_chain8_reacquired_intended_before_open");
        let mut files = Vec::new();
        for name in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-journal",
            "journal.sqlite-shm",
        ] {
            let index = read
                .read
                .files
                .iter()
                .position(|f| f.path == data.join(name))
                .ok_or(ReconcileError::Invariant("history next native file absent"))?;
            let evidence = read.read.files.remove(index);
            let RecoveredFileProtection::Sqlite(file) = evidence.file else {
                return Err(ReconcileError::Invariant(
                    "history fresh exclusive native handoff",
                ));
            };
            files.push(file);
        }
        // The fresh WAL2 intent is already durable. Resetting the retained SHM
        // index starts a new native epoch, never modifies prior admission bytes.
        let epoch_name = format!("node-recovered-shm-epoch-{fresh}.frames");
        let mut epoch = held.create_new_file(&epoch_name)?;
        let epoch_intent = serde_json::to_vec(&(
            1u32,
            "shm_epoch_intended",
            self.digest(),
            &record.original_frames,
            &record.session,
            &fresh,
            &record.native_keys,
            &record.main,
            &record.shm,
            &record.rows,
        ))?;
        if epoch_intent.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "new SHM epoch intended bound",
            ));
        }
        epoch.writer().write_all(&epoch_intent)?;
        epoch.writer().sync_all()?;
        crate::fault::checkpoint("history_chain8_intended_before_new_shm_epoch");
        let prior_shm = files[3].exact_bytes(1024 * 1024)?;
        if ContentId::hash(&prior_shm) != record.shm {
            return Err(ReconcileError::Invariant(
                "history chain exact prior held SHM",
            ));
        }
        let native =
            sync_extend_journal::FreshNativeWalConnection::open_after_explicit_shm_epoch(
                &data.join("journal.sqlite"),
                files
                    .try_into()
                    .map_err(|_| ReconcileError::Invariant("history native four files"))?,
                [
                    scope.max_main_bytes,
                    scope.max_wal_bytes,
                    scope.max_rollback_bytes,
                    1024 * 1024,
                ],
                (record.native_keys[3].as_str(), &prior_shm),
            )?;
        epoch.writer().write_all(&serde_json::to_vec(&(
            1u32,
            "shm_epoch_initialized",
            &fresh,
            ContentId::hash(&native.held_shm_bytes()?),
            native.all_native_keys()?.map(|key| key.to_string()),
        ))?)?;
        epoch.writer().sync_all()?;
        crate::fault::checkpoint("history_chain8_new_shm_epoch_before_session_commit");
        let epoch_file = RecoveredFileProtection::Created(epoch.seal_original()?);
        let epoch_bytes = epoch_file.exact_bytes(256 * 1024)?;
        retained.insert(
            epoch_name.clone(),
            ReacquiredFile {
                path: parent.join(epoch_name),
                file: epoch_file,
                bytes: epoch_bytes.len() as u64,
                digest: ContentId::hash(&epoch_bytes),
            },
        );
        let native_keys = native.all_native_keys()?.map(|key| key.to_string());
        let before_rows = read.read.rows.clone();
        let mut result = FreshRecoveredNodeWalV2Session {
            separated_deployment_configs: None,
            created_work_directories: std::collections::BTreeMap::new(),
            read,
            native,
            frames,
            owner,
            path: parent.join(name + ".frames"),
            bounds,
            space: self.space().clone(),
            previous: record.session,
            fresh,
            before_rows,
            archive: self.digest().clone(),
            original_frames: record.original_frames,
            next: 0,
            previous_record: ContentId::hash(&intent),
            attempted: false,
            committed: false,
            closed: false,
            poisoned: false,
            predecessor: Some(wal.digest.clone()),
            native_keys,
            history_count: 0,
            metadata_count: 0,
            retained_metadata_receipts: Vec::new(),
            new_content_bytes: 0,
            new_cas_buckets: std::collections::BTreeMap::new(),
            verified_main: std::cell::RefCell::new(None),
            polling: None,
            mutation_observation_closed: None,
            mutation_observation_failed: None,
            new_file_bytes: 0,
            new_cas_bytes: 0,
            new_cas_objects: 0,
            manifest_entry_limit: bounds.max_entries,
            retained_receipts: std::collections::BTreeMap::new(),
            retained_receipt_bytes: 0,
            history_baseline: Vec::new(),
            history_chain_depth: generations.len() as u32,
            history_chain_parent: Some(head_object),
            retained_mutations: Vec::new(),
            mutation_requested,
            history_retained_originals: record.retained_originals.clone(),
            history_retained_directories,
            retained_history_evidence: retained.into_values().collect(),
        };
        result.record("intended", None)?;
        result.verify()?;
        Ok(result)
    }
}

#[cfg(windows)]
#[path = "live_retention.rs"]
mod live_retention;
#[cfg(windows)]
pub use live_retention::RecoveredHistoryOperation;

impl FreshRecoveredNodeWalV2Session {
    fn recovered_local_query_image(&self) -> Result<sync_extend_journal::JournalBackupImage> {
        self.verify()?;
        let bytes = self.native.exact_main_bytes()?;
        sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )
        .map_err(Into::into)
    }
    pub fn recovered_local_manifest(&self) -> Result<sync_extend_core_model::Manifest> {
        self.verify()?;
        let manifest = self.read.read.manifest.clone();
        self.verify()?;
        Ok(manifest)
    }
    pub fn recovered_local_device_id(&self) -> Result<sync_extend_core_model::DeviceId> {
        self.recovered_device_id()
    }
    pub fn recovered_local_operations(&self) -> Result<Vec<sync_extend_core_model::Operation>> {
        let image = self.recovered_local_query_image()?;
        let operations=image.with_audited_readonly(&self.space,self.bounds,|connection| {
            let mut query=connection.prepare("SELECT payload FROM main.operations WHERE space_id=?1 ORDER BY origin_device_id,origin_seq")?;
            let rows=query.query_map([self.space.as_str()],|row|row.get::<_,String>(0))?;
            let mut result=Vec::new();let mut bytes=0u64;
            for row in rows {
                if result.len()>=self.bounds.capacity.max_rows as usize {
                    return Err(sync_extend_journal::JournalError::Invariant("recovered query operation count"));
                }
                let payload=row?;
                bytes=bytes.checked_add(payload.len() as u64)
                    .filter(|n|*n<=self.bounds.capacity.max_logical_bytes.min(256*1024*1024))
                    .ok_or(sync_extend_journal::JournalError::Invariant("recovered operation query byte aggregate"))?;
                let operation:sync_extend_core_model::Operation=serde_json::from_str(&payload)?;
                if operation.payload.space_id!=self.space {
                    return Err(sync_extend_journal::JournalError::Invariant("recovered operation query exact space"));
                }
                operation.validate()?;result.push(operation);
            }
            Ok(result)
        })?;
        self.verify()?;
        Ok(operations)
    }
    pub fn recovered_local_snapshots(
        &self,
    ) -> Result<Vec<(sync_extend_core_model::SnapshotId, String)>> {
        let image = self.recovered_local_query_image()?;
        let snapshots=image.with_audited_readonly(&self.space,self.bounds,|connection| {
            let mut query=connection.prepare("SELECT snapshot_id,state FROM main.snapshots WHERE space_id=?1 AND snapshot_id NOT IN (SELECT snapshot_id FROM main.snapshot_prunings) ORDER BY created_at_ms,snapshot_id")?;
            let rows=query.query_map([self.space.as_str()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?;
            let mut result=Vec::new();let mut bytes=0u64;
            for row in rows {
                if result.len()>=self.bounds.capacity.max_rows as usize {
                    return Err(sync_extend_journal::JournalError::Invariant("recovered query snapshot count"));
                }
                let (root,state)=row?;
                bytes=bytes.checked_add((root.len()+state.len()) as u64)
                    .filter(|n|*n<=self.bounds.capacity.max_logical_bytes.min(256*1024*1024))
                    .ok_or(sync_extend_journal::JournalError::Invariant("recovered snapshot query byte aggregate"))?;
                result.push((root.parse()?,state));
            }
            Ok(result)
        })?;
        self.verify()?;
        Ok(snapshots)
    }

    fn held_recovered_cas_chunk(
        &self,
        content: &ContentId,
        length: u64,
    ) -> Result<&ReacquiredFile> {
        let id = content.as_str();
        let path = self
            .read
            .read
            .data
            .join("cas/objects")
            .join(&id[..2])
            .join(id);
        let file = self
            .read
            .read
            .files
            .iter()
            .find(|file| file.path == path)
            .ok_or(ReconcileError::Invariant(
                "recovered file original CAS object absent",
            ))?;
        file.file.verify()?;
        if file.digest != *content || file.bytes != length || !file.file.matches_path(&path)? {
            return Err(ReconcileError::Invariant(
                "recovered file CAS chunk differs",
            ));
        }
        Ok(file)
    }

    pub(crate) fn recovered_local_file_bytes(
        &self,
        path: &sync_extend_core_model::PortablePath,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        // This path assembles the whole file in memory, so the caller's policy
        // ceiling is clamped to the memory bound rather than compared against
        // it. A larger policy limit must not reject every file.
        const MAX_RECOVERED_READ_BYTES: u64 = 256 * 1024 * 1024;
        self.deployment_runtime_binding()?.verify()?;
        if max_bytes == 0 {
            return Err(ReconcileError::ResourceLimit(
                "fresh recovered file read bound",
            ));
        }
        let max_bytes = max_bytes.min(MAX_RECOVERED_READ_BYTES);
        let manifest = self.recovered_local_manifest()?;
        let content = manifest
            .entries
            .values()
            .find(|entry| {
                entry.path == *path && entry.kind == sync_extend_core_model::EntryKind::File
            })
            .and_then(|entry| entry.content.as_ref())
            .ok_or(ReconcileError::Invariant(
                "fresh recovered read manifest file absent",
            ))?;
        if content.length > max_bytes || content.chunks.len() > self.bounds.max_entries {
            return Err(ReconcileError::ResourceLimit(
                "fresh recovered read content liability",
            ));
        }
        let capacity = usize::try_from(content.length)
            .map_err(|_| ReconcileError::ResourceLimit("fresh recovered read addressable bytes"))?;
        let mut bytes = Vec::with_capacity(capacity);
        for chunk in &content.chunks {
            let file = self.held_recovered_cas_chunk(&chunk.content_id, u64::from(chunk.length))?;
            let original = file.file.exact_bytes(file.bytes)?;
            if original.len() as u64 != file.bytes
                || ContentId::hash(&original) != chunk.content_id
                || bytes
                    .len()
                    .checked_add(original.len())
                    .is_none_or(|sum| sum > capacity)
            {
                return Err(ReconcileError::Invariant(
                    "fresh recovered original CAS read differs",
                ));
            }
            bytes.extend_from_slice(&original);
        }
        if bytes.len() != capacity || ContentId::hash(&bytes) != content.content_id {
            return Err(ReconcileError::Invariant(
                "fresh recovered assembled manifest content differs",
            ));
        }
        self.deployment_runtime_binding()?.verify()?;
        Ok(bytes)
    }
}

/// Borrowed only from the actual committed fresh native session. These values
/// cannot be supplied by a receipt or ordinary LocalSpace constructor.
pub(crate) struct DeploymentFreshNodeBinding<'proof> {
    original: &'proof FreshRecoveredNodeWalV2Session,
}

impl FreshRecoveredNodeWalV2Session {
    pub(crate) fn deployment_runtime_binding(&self) -> Result<DeploymentFreshNodeBinding<'_>> {
        let binding = DeploymentFreshNodeBinding { original: self };
        binding.verify()?;
        Ok(binding)
    }

    pub(crate) fn close_deployment_runtime(&mut self) -> Result<(bool, PathBuf)> {
        self.deployment_runtime_binding()?.verify()?;
        if self.history_count == 0
            && self.metadata_count == 0
            && self.history_chain_parent.is_none()
        {
            Ok((false, self.close_completed()?))
        } else {
            Ok((true, self.close_recovered_history_for_chain8()?))
        }
    }

    pub(crate) fn close_failed_deployment_connection(&mut self) -> Result<()> {
        // No clean completion, checkpoint or restart evidence is issued.
        // The actual original object stays poisoned and its files stay held.
        self.poisoned = true;
        self.native.close_actual_connection_after_failure()?;
        self.closed = true;
        Ok(())
    }
}

impl DeploymentFreshNodeBinding<'_> {
    pub(crate) fn verify(&self) -> Result<()> {
        let original = self.original;
        original.verify()?;
        if !original.committed || original.closed || original.poisoned || original.next != 2 {
            return Err(ReconcileError::Invariant(
                "deployment requires an actual live fresh recovered session",
            ));
        }
        Ok(())
    }

    pub(crate) fn archive_digest(&self) -> &ContentId {
        &self.original.archive
    }
    pub(crate) fn data_dir(&self) -> &std::path::Path {
        &self.original.read.read.data
    }
    pub(crate) fn worktree(&self) -> &std::path::Path {
        &self.original.read.read.worktree
    }
    pub(crate) fn space_id(&self) -> &SpaceId {
        &self.original.space
    }
    pub(crate) fn fresh_session_id(&self) -> &SpaceId {
        &self.original.fresh
    }
    pub(crate) fn device_id(&self) -> Result<sync_extend_core_model::DeviceId> {
        self.verify()?;
        let device = self.original.recovered_local_device_id()?;
        self.verify()?;
        Ok(device)
    }
    fn root_key(&self, path: &std::path::Path) -> Result<String> {
        self.verify()?;
        let root = self
            .original
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == path)
            .ok_or(ReconcileError::Invariant(
                "fresh recovered actual root descriptor absent",
            ))?;
        if root.file.key()? != root.key || !root.file.matches_path(path)? {
            return Err(ReconcileError::Invariant(
                "fresh recovered actual root changed",
            ));
        }
        self.verify()?;
        Ok(root.key.to_string())
    }
    pub(crate) fn data_key(&self) -> Result<String> {
        self.root_key(self.data_dir())
    }
    pub(crate) fn worktree_key(&self) -> Result<String> {
        self.root_key(self.worktree())
    }
    pub(crate) fn native_journal_keys(&self) -> Result<[String; 4]> {
        self.verify()?;
        let keys = self
            .original
            .native
            .all_native_keys()?
            .map(|key| key.to_string());
        if keys != self.original.native_keys {
            return Err(ReconcileError::Invariant(
                "fresh recovered native Journal keys changed",
            ));
        }
        Ok(keys)
    }
}

impl super::VerifiedNodeStateArchive {
    /// This explicit call reissues only current rights under new held roots,
    /// locks, complete history and native identity checks. No classification
    /// value or digest can construct the writable wrapper.
    #[allow(clippy::too_many_arguments)]
    pub fn open_recovered_local_space(
        &self,
        worktree: &std::path::Path,
        data: &std::path::Path,
        original_frames: &std::path::Path,
        restore_ledger: &std::path::Path,
        history_chain: &std::path::Path,
        bounds: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: super::LedgerBounds,
    ) -> Result<crate::RecoveredLocalSpace> {
        let mut session = self.reacquire_closed_history_chain8_with_mutation(
            worktree,
            data,
            original_frames,
            restore_ledger,
            history_chain,
            bounds,
            ledger_bounds,
        )?;
        session.verify()?;
        session.commit_fresh_session()?;
        session.verify()?;
        crate::RecoveredLocalSpace::from_reacquired_session(session)
    }
}

// Exact held native namespace changes, with independent append-only intent.
impl FreshRecoveredNodeWalV2Session {
    fn preflight_recovered_namespace_path(
        &self,
        path: &sync_extend_core_model::PortablePath,
        adding: bool,
    ) -> Result<(PathBuf, PathBuf, String)> {
        self.verify()?;
        self.preflight_history_close_envelope(Some(path), true, 0, 1, 3)?;
        if !self.mutation_requested
            || !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self
                .retained_receipt_bytes
                .checked_add(3 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
            || (adding
                && self
                    .read
                    .read
                    .manifest
                    .entries
                    .len()
                    .checked_add(1)
                    .is_none_or(|n| n > self.manifest_entry_limit))
        {
            return Err(ReconcileError::ResourceLimit(
                "recovered namespace preeffect capacity",
            ));
        }
        let parts: Vec<_> = path.as_str().split('/').collect();
        if parts.len() > 256
            || parts.iter().any(|part| part.starts_with('.'))
            || self
                .read
                .read
                .manifest
                .entries
                .values()
                .any(|entry| entry.path.collision_key() == path.collision_key())
        {
            return Err(ReconcileError::Invariant(
                "recovered namespace exact absent destination",
            ));
        }
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("namespace parent"))?
            .to_owned();
        let name = parts
            .last()
            .ok_or(ReconcileError::Invariant("namespace component"))?
            .to_string();
        if !self
            .read
            .read
            .directories
            .iter()
            .any(|directory| directory.path == parent)
            || self
                .read
                .read
                .expected_membership
                .get(&parent)
                .is_none_or(|names| names.contains(&name))
        {
            return Err(ReconcileError::Invariant(
                "namespace held parent and exact absence",
            ));
        }
        Ok((target, parent, name))
    }
    fn commit_recovered_namespace_scan(
        &mut self,
        previous: &sync_extend_core_model::Manifest,
        expected: &sync_extend_core_model::Manifest,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        use sync_extend_core_model::{Change, Operation, OperationPayload, FORMAT_VERSION};
        self.verify()?;
        let allowed: std::collections::BTreeSet<_> = expected
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| &content.chunks)
            .map(|chunk| chunk.content_id.clone())
            .collect();
        let cas = sync_extend_cas::Cas::open_existing_session_coordinated(
            &self.read.read.data.join("cas"),
            move |id| {
                if allowed.contains(id) {
                    Ok(Box::new(()))
                } else {
                    Err("namespace scan unheld CAS".into())
                }
            },
            || Ok(Box::new(())),
        )?;
        let limits = sync_extend_core_model::limits::LocalLimits::default();
        let view = RecoveredSessionScanView(self);
        let first = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
        let second = crate::scan::scan_native(&self.read.read.worktree, &cas, &limits, &view)?;
        if first != second
            || first.len() != expected.entries.len()
            || expected.entries.values().any(|entry| {
                first.get(&entry.path).is_none_or(|actual| {
                    actual.kind != entry.kind || actual.content != entry.content
                })
            })
        {
            return Err(ReconcileError::Unstable);
        }
        // Keep the original manifest builder and validate the explicit native
        // identity mapping independently of content-based rename inference.
        let scanned = crate::build_manifest(previous, &second, &std::collections::BTreeMap::new())?;
        if scanned.entries.len() != expected.entries.len()
            || scanned.entries.values().any(|entry| {
                !expected.entries.values().any(|wanted| {
                    wanted.path == entry.path
                        && wanted.kind == entry.kind
                        && wanted.content == entry.content
                })
            })
        {
            return Err(ReconcileError::Invariant(
                "namespace original builder differs",
            ));
        }
        let mut manifest = expected.clone();
        let origin = self.recovered_device_id()?;
        let mut operations = Vec::new();
        for old in previous.entries.values() {
            if manifest.entries.contains_key(&old.entry_id) {
                continue;
            }
            let seq = manifest.version_vector.get(&origin).checked_add(1).ok_or(
                ReconcileError::Invariant("namespace delete sequence exhausted"),
            )?;
            operations.push(Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space.clone(),
                origin_device_id: origin.clone(),
                origin_seq: seq,
                causal: manifest.version_vector.clone(),
                created_at_ms: timestamp,
                change: Change::Delete {
                    entry_id: old.entry_id.clone(),
                },
            })?);
            manifest.version_vector.observe(origin.clone(), seq);
        }
        for entry in manifest.entries.values() {
            if previous.entries.get(&entry.entry_id) == Some(entry) {
                continue;
            }
            let seq = manifest
                .version_vector
                .get(&origin)
                .checked_add(1)
                .ok_or(ReconcileError::Invariant("namespace sequence exhausted"))?;
            operations.push(Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space.clone(),
                origin_device_id: origin.clone(),
                origin_seq: seq,
                causal: manifest.version_vector.clone(),
                created_at_ms: timestamp,
                change: Change::Put {
                    entry: entry.clone(),
                },
            })?);
            manifest.version_vector.observe(origin.clone(), seq);
        }
        manifest.validate()?;
        self.commit_exact_recovered_history(manifest, operations, timestamp)
    }
    pub fn create_recovered_directory(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        let (target, parent, name) = self.preflight_recovered_namespace_path(path, true)?;
        if self.created_work_directories.len() >= FRESH_WORK_DIRECTORY_MAXIMUM {
            return Err(ReconcileError::ResourceLimit(
                "recovered created directory capacity",
            ));
        }
        let previous = self.read.read.manifest.clone();
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant("namespace retained parent"))?;
        let parent_key = held.key;
        let held = held.file.duplicate_read_guard()?;
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("namespace external"))?;
        let owner = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == external)
            .ok_or(ReconcileError::Invariant("namespace retained external"))?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            "directory",
            path,
            previous.root()?,
            parent_key.to_string(),
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit("namespace intended bytes"));
        }
        let owner = owner.file.duplicate_read_guard()?;
        self.poisoned = true;
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            let mut receipt = owner.create_new_file(&format!(
                "node-recovered-namespace-{}-{}.frames",
                self.fresh, self.history_count
            ))?;
            receipt.writer().write_all(&intended)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_namespace_intended_before_create");
            let creator = held.create_new_rename_destination(&name)?;
            let key = creator.key()?;
            if creator.original_creation()?.parent_key()? != parent_key
                || !creator.matches_path(&target)?
            {
                return Err(ReconcileError::Invariant(
                    "namespace exact new directory lineage",
                ));
            }
            let read = creator.duplicate_read_guard()?;
            self.read.read.directories.push(ReacquiredDirectory {
                path: target.clone(),
                file: read,
                key,
            });
            self.created_work_directories
                .insert(target.clone(), creator);
            self.read
                .read
                .expected_membership
                .get_mut(&parent)
                .ok_or(ReconcileError::Invariant("namespace parent membership"))?
                .insert(name);
            self.read
                .read
                .expected_membership
                .insert(target.clone(), std::collections::BTreeSet::new());
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "directory_created",
                key.to_string(),
                parent_key.to_string(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_namespace_created_before_history");
            self.poisoned = false;
            let mut expected = previous.clone();
            let id = sync_extend_core_model::EntryId::random()?;
            expected.entries.insert(
                id.clone(),
                sync_extend_core_model::Entry {
                    entry_id: id,
                    path: path.clone(),
                    kind: sync_extend_core_model::EntryKind::Directory,
                    content: None,
                    metadata: None,
                },
            );
            let root = self.commit_recovered_namespace_scan(&previous, &expected, timestamp)?;
            self.poisoned = true;
            receipt
                .writer()
                .write_all(&serde_json::to_vec(&(1u32, "committed", &root))?)?;
            receipt.writer().sync_all()?;
            self.retain_recovered_receipt(receipt)?;
            self.poisoned = false;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn move_recovered_file(
        &mut self,
        source: &sync_extend_core_model::PortablePath,
        destination: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        let (target, parent, name) = self.preflight_recovered_namespace_path(destination, false)?;
        let previous = self.read.read.manifest.clone();
        let entry = previous
            .entries
            .values()
            .find(|entry| {
                entry.path == *source && entry.kind == sync_extend_core_model::EntryKind::File
            })
            .ok_or(ReconcileError::Invariant("namespace exact file source"))?
            .clone();
        let original = self.read.read.worktree.join(source.as_str());
        let old_parent = original
            .parent()
            .ok_or(ReconcileError::Invariant("namespace source parent"))?
            .to_owned();
        let old_name = original
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ReconcileError::Invariant("namespace source component"))?
            .to_string();
        if source.as_str().split('/').any(|part| part.starts_with('.')) {
            return Err(ReconcileError::Invariant("namespace reserved source"));
        }
        let index = self
            .read
            .read
            .files
            .iter()
            .position(|file| file.path == original)
            .ok_or(ReconcileError::Invariant("namespace original file unheld"))?;
        let file = &self.read.read.files[index];
        if !matches!(
            file.file,
            RecoveredFileProtection::Mutation(_) | RecoveredFileProtection::Created(_)
        ) {
            return Err(ReconcileError::Invariant(
                "namespace explicit fresh DELETE authority",
            ));
        }
        let key = file.file.key()?;
        let from = file.file.parent_key()?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant("namespace retained destination"))?;
        if held.key.volume != key.volume
            || self
                .read
                .read
                .directories
                .iter()
                .find(|directory| directory.path == old_parent)
                .is_none_or(|directory| directory.key != from)
        {
            return Err(ReconcileError::Invariant(
                "namespace exact native source parent and volume",
            ));
        }
        let to = held.key;
        let held = held.file.duplicate_read_guard()?;
        let owner = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| Some(directory.path.as_path()) == self.path.parent())
            .ok_or(ReconcileError::Invariant("namespace retained external"))?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            "move_file",
            source,
            destination,
            previous.root()?,
            key.to_string(),
            from.to_string(),
            to.to_string(),
            &file.digest,
            file.bytes,
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit(
                "namespace move intended bytes",
            ));
        }
        let owner = owner.file.duplicate_read_guard()?;
        self.poisoned = true;
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            let mut receipt = owner.create_new_file(&format!(
                "node-recovered-namespace-{}-{}.frames",
                self.fresh, self.history_count
            ))?;
            receipt.writer().write_all(&intended)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_namespace_intended_before_move");
            match &mut self.read.read.files[index].file {
                RecoveredFileProtection::Mutation(file) => {
                    file.rename_no_replace_to_parent(&held, &name)?
                }
                RecoveredFileProtection::Created(file) => {
                    file.rename_no_replace_to_parent(&held, &name)?
                }
                _ => {
                    return Err(ReconcileError::Invariant(
                        "namespace original native authority",
                    ))
                }
            }
            self.read.read.files[index].path = target;
            self.read
                .read
                .expected_membership
                .get_mut(&old_parent)
                .ok_or(ReconcileError::Invariant("namespace source membership"))?
                .remove(&old_name);
            self.read
                .read
                .expected_membership
                .get_mut(&parent)
                .ok_or(ReconcileError::Invariant(
                    "namespace destination membership",
                ))?
                .insert(name);
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "file_moved",
                key.to_string(),
                from.to_string(),
                to.to_string(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_namespace_moved_before_history");
            self.poisoned = false;
            let mut expected = previous.clone();
            expected
                .entries
                .get_mut(&entry.entry_id)
                .ok_or(ReconcileError::Invariant("namespace original entry"))?
                .path = destination.clone();
            let root = self.commit_recovered_namespace_scan(&previous, &expected, timestamp)?;
            self.poisoned = true;
            receipt
                .writer()
                .write_all(&serde_json::to_vec(&(1u32, "committed", &root))?)?;
            receipt.writer().sync_all()?;
            self.retain_recovered_receipt(receipt)?;
            self.poisoned = false;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl FreshRecoveredNodeWalV2Session {
    fn preflight_created_empty_recovered_directory(
        &self,
        path: &sync_extend_core_model::PortablePath,
    ) -> Result<(
        sync_extend_core_model::Entry,
        PathBuf,
        PathBuf,
        String,
        usize,
    )> {
        self.verify()?;
        self.preflight_history_close_envelope(None, false, 0, 1, 3)?;
        if !self.mutation_requested
            || !self.committed
            || self.closed
            || self.next != 2
            || self.metadata_count != 0
            || self.history_count >= FRESH_OPERATION_MAXIMUM
            || self
                .retained_receipt_bytes
                .checked_add(3 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "empty directory preeffect capacity",
            ));
        }
        if path.as_str().split('/').any(|part| part.starts_with('.')) {
            return Err(ReconcileError::Invariant("empty directory reserved source"));
        }
        let target = self.read.read.worktree.join(path.as_str());
        let parent = target
            .parent()
            .ok_or(ReconcileError::Invariant("empty directory parent"))?
            .to_owned();
        let name = target
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(ReconcileError::Invariant("empty directory component"))?
            .to_string();
        let entry = self
            .read
            .read
            .manifest
            .entries
            .values()
            .find(|entry| {
                entry.path == *path && entry.kind == sync_extend_core_model::EntryKind::Directory
            })
            .ok_or(ReconcileError::Invariant(
                "empty directory exact manifest entry",
            ))?
            .clone();
        let creator =
            self.created_work_directories
                .get(&target)
                .ok_or(ReconcileError::Invariant(
                    "empty directory requires actual live CREATE",
                ))?;
        creator.original_creation()?.verify()?;
        let index = self
            .read
            .read
            .directories
            .iter()
            .position(|directory| directory.path == target)
            .ok_or(ReconcileError::Invariant("empty directory retained read"))?;
        if self.read.read.directories[index].key != creator.key()?
            || !creator.matches_path(&target)?
            || self
                .read
                .read
                .expected_membership
                .get(&target)
                .is_none_or(|names| !names.is_empty())
            || self.read.read.manifest.entries.values().any(|other| {
                other
                    .path
                    .as_str()
                    .starts_with(&(path.as_str().to_owned() + "/"))
            })
            || self
                .read
                .read
                .files
                .iter()
                .any(|file| file.path.starts_with(&target))
            || self
                .read
                .read
                .directories
                .iter()
                .any(|directory| directory.path != target && directory.path.starts_with(&target))
        {
            return Err(ReconcileError::Invariant(
                "empty directory exact no descendants",
            ));
        }
        // Directory read sharing does not freeze child membership. Observe
        // absence again before intent; the kernel rejects nonempty disposition.
        if std::fs::read_dir(&target)?.next().is_some() {
            return Err(ReconcileError::Invariant(
                "empty directory native membership differs",
            ));
        }
        Ok((entry, target, parent, name, index))
    }

    pub fn move_created_empty_recovered_directory(
        &mut self,
        source: &sync_extend_core_model::PortablePath,
        destination: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        let (target, parent, name) = self.preflight_recovered_namespace_path(destination, false)?;
        let (entry, original, old_parent, old_name, index) =
            self.preflight_created_empty_recovered_directory(source)?;
        let previous = self.read.read.manifest.clone();
        let key = self.read.read.directories[index].key;
        let from = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == old_parent)
            .ok_or(ReconcileError::Invariant("empty move source parent unheld"))?
            .key;
        let destination_parent = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant(
                "empty move destination parent unheld",
            ))?;
        let to = destination_parent.key;
        if key.volume != to.volume || parent.starts_with(&original) {
            return Err(ReconcileError::Invariant("empty move same volume no cycle"));
        }
        let destination_parent = destination_parent.file.duplicate_read_guard()?;
        let owner = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| Some(directory.path.as_path()) == self.path.parent())
            .ok_or(ReconcileError::Invariant("empty move external unheld"))?
            .file
            .duplicate_read_guard()?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            "move_created_empty_directory",
            source,
            destination,
            previous.root()?,
            key.to_string(),
            from.to_string(),
            to.to_string(),
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit("empty move intent bytes"));
        }
        self.poisoned = true;
        let result = (|| -> Result<sync_extend_core_model::SnapshotId> {
            let mut receipt = owner.create_new_file(&format!(
                "node-recovered-namespace-{}-{}.frames",
                self.fresh, self.history_count
            ))?;
            receipt.writer().write_all(&intended)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_empty_directory_intended_before_move");
            self.created_work_directories
                .get(&original)
                .ok_or(ReconcileError::Invariant("empty move creator missing"))?
                .rename_created_directory_to_parent(&destination_parent, &name)?;
            let creator = self
                .created_work_directories
                .remove(&original)
                .ok_or(ReconcileError::Invariant("empty move creator lost"))?;
            self.created_work_directories
                .insert(target.clone(), creator);
            self.read.read.directories[index].path = target.clone();
            let members = self.read.read.expected_membership.remove(&original).ok_or(
                ReconcileError::Invariant("empty move source membership lost"),
            )?;
            self.read
                .read
                .expected_membership
                .insert(target.clone(), members);
            self.read
                .read
                .expected_membership
                .get_mut(&old_parent)
                .ok_or(ReconcileError::Invariant(
                    "empty move source parent membership",
                ))?
                .remove(&old_name);
            self.read
                .read
                .expected_membership
                .get_mut(&parent)
                .ok_or(ReconcileError::Invariant(
                    "empty move destination membership",
                ))?
                .insert(name);
            if !self.read.read.directories[index]
                .file
                .matches_path(&target)?
            {
                return Err(ReconcileError::Invariant(
                    "empty move exact destination key",
                ));
            }
            receipt.writer().write_all(&serde_json::to_vec(&(
                1u32,
                "empty_directory_moved",
                key.to_string(),
                from.to_string(),
                to.to_string(),
            ))?)?;
            receipt.writer().sync_all()?;
            crate::fault::checkpoint("recovered_empty_directory_moved_before_history");
            self.poisoned = false;
            let mut expected = previous.clone();
            expected
                .entries
                .get_mut(&entry.entry_id)
                .ok_or(ReconcileError::Invariant(
                    "empty move original entry identity",
                ))?
                .path = destination.clone();
            let root = self.commit_recovered_namespace_scan(&previous, &expected, timestamp)?;
            self.poisoned = true;
            receipt
                .writer()
                .write_all(&serde_json::to_vec(&(1u32, "committed", &root))?)?;
            receipt.writer().sync_all()?;
            self.retain_recovered_receipt(receipt)?;
            self.poisoned = false;
            self.verify()?;
            Ok(root)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub fn delete_created_empty_recovered_directory(
        &mut self,
        path: &sync_extend_core_model::PortablePath,
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        let (entry, target, parent, name, index) =
            self.preflight_created_empty_recovered_directory(path)?;
        let previous = self.read.read.manifest.clone();
        let key = self.read.read.directories[index].key;
        let parent_key = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(ReconcileError::Invariant("empty delete parent unheld"))?
            .key;
        let owner = self
            .read
            .read
            .directories
            .iter()
            .find(|directory| Some(directory.path.as_path()) == self.path.parent())
            .ok_or(ReconcileError::Invariant("empty delete external unheld"))?
            .file
            .duplicate_read_guard()?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            "delete_created_empty_directory",
            path,
            previous.root()?,
            key.to_string(),
            parent_key.to_string(),
            timestamp,
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit("empty delete intent bytes"));
        }
        self.poisoned = true;
        let result =
            (|| -> Result<sync_extend_core_model::SnapshotId> {
                let mut receipt = owner.create_new_file(&format!(
                    "node-recovered-namespace-{}-{}.frames",
                    self.fresh, self.history_count
                ))?;
                receipt.writer().write_all(&intended)?;
                receipt.writer().sync_all()?;
                crate::fault::checkpoint("recovered_empty_directory_intended_before_disposition");
                self.created_work_directories
                    .get(&target)
                    .ok_or(ReconcileError::Invariant("empty delete creator missing"))?
                    .delete_empty_on_close()?;
                receipt.writer().write_all(&serde_json::to_vec(&(
                    1u32,
                    "empty_directory_disposition_requested",
                    key.to_string(),
                ))?)?;
                receipt.writer().sync_all()?;
                crate::fault::checkpoint("recovered_empty_directory_disposition_before_close");
                drop(self.read.read.directories.remove(index));
                drop(self.created_work_directories.remove(&target));
                match std::fs::symlink_metadata(&target) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => {
                        return Err(ReconcileError::Invariant(
                            "empty delete exact native absence uncertain",
                        ))
                    }
                }
                self.read.read.expected_membership.remove(&target).ok_or(
                    ReconcileError::Invariant("empty delete old membership lost"),
                )?;
                self.read
                    .read
                    .expected_membership
                    .get_mut(&parent)
                    .ok_or(ReconcileError::Invariant("empty delete parent membership"))?
                    .remove(&name);
                receipt.writer().write_all(&serde_json::to_vec(&(
                    1u32,
                    "empty_directory_absent",
                    key.to_string(),
                    parent_key.to_string(),
                ))?)?;
                receipt.writer().sync_all()?;
                crate::fault::checkpoint("recovered_empty_directory_absent_before_history");
                self.poisoned = false;
                let mut expected = previous.clone();
                expected.entries.remove(&entry.entry_id);
                let root = self.commit_recovered_namespace_scan(&previous, &expected, timestamp)?;
                self.poisoned = true;
                receipt
                    .writer()
                    .write_all(&serde_json::to_vec(&(1u32, "committed", &root))?)?;
                receipt.writer().sync_all()?;
                self.retain_recovered_receipt(receipt)?;
                self.poisoned = false;
                self.verify()?;
                Ok(root)
            })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

#[derive(Serialize)]
pub struct RecoveredLiveHistoryBinding {
    pub archive: ContentId,
    pub prior_session: SpaceId,
    pub current_session: SpaceId,
    pub root: sync_extend_core_model::SnapshotId,
    pub original_history: sync_extend_journal::RecoveredImmutableHistoryInventory,
    pub current_native_objects: ContentId,
    pub native_objects: usize,
    pub history_chain_depth: u32,
    pub old_native_receipts_rewritten: bool,
    pub gc_release_authority: bool,
    pub pending_attempt_resume_authority: bool,
}

impl FreshRecoveredNodeWalV2Session {
    pub fn recovered_live_history_binding(&self) -> Result<RecoveredLiveHistoryBinding> {
        self.verify()?;
        if !self.committed || self.closed || self.history_baseline.is_empty() {
            return Err(ReconcileError::Invariant(
                "live history committed native session required",
            ));
        }
        let image = self.recovered_local_query_image()?;
        let baseline = sync_extend_journal::JournalBackupImage::from_current_node_image(
            self.history_baseline.clone(),
            ContentId::hash(&self.history_baseline).as_str(),
            self.history_baseline.len(),
            &self.space,
            self.bounds,
        )?;
        let original_history = image.audit_recovered_immutable_history_inventory(
            &baseline,
            &self.space,
            self.bounds,
        )?;
        let objects = history_current_objects(&self.read.read)?;
        let encoded = serde_json::to_vec(&objects)?;
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "live native history encoded inventory",
            ));
        }
        let binding = RecoveredLiveHistoryBinding {
            archive: self.archive.clone(),
            prior_session: self.previous.clone(),
            current_session: self.fresh.clone(),
            root: self.read.read.manifest.root()?,
            original_history,
            current_native_objects: ContentId::hash(&encoded),
            native_objects: objects.len(),
            history_chain_depth: self.history_chain_depth,
            old_native_receipts_rewritten: false,
            gc_release_authority: false,
            pending_attempt_resume_authority: false,
        };
        self.verify()?;
        Ok(binding)
    }
}

#[cfg(windows)]
impl FreshRecoveredNodeWalV2Session {
    /// Read the immutable image's retained catalogue under the same verified session.
    pub fn recovered_history_tables(&self) -> Result<sync_extend_journal::RecoveredHistoryTables> {
        self.verify()?;
        let result = self
            .recovered_local_query_image()?
            .recovered_history_tables(&self.space, self.bounds)?;
        self.verify()?;
        Ok(result)
    }

    /// Read the complete immutable image catalogue without granting any writer authority.
    pub fn recovered_main_tables(&self) -> Result<sync_extend_journal::RecoveredMainTables> {
        self.verify()?;
        let result = self
            .recovered_local_query_image()?
            .recovered_main_tables(&self.space, self.bounds)?;
        self.verify()?;
        Ok(result)
    }

    /// Return bounded descriptive original pending-attempt diagnostics. The
    /// immutable image parser is shared with the live Journal and grants no
    /// restart, native or cleanup authority.
    pub fn recovered_attempt_diagnostics(
        &self,
    ) -> Result<Vec<sync_extend_journal::OriginalLocalHistoryAttemptDiagnostic>> {
        self.verify()?;
        let result = self
            .recovered_local_query_image()?
            .recovered_original_attempt_diagnostics(&self.space, self.bounds)?;
        self.verify()?;
        Ok(result)
    }
}
