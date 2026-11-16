//! Durable external evidence with living original CREATE lineage.
pub(super) mod bounds;
pub(super) mod records;
pub(super) mod schema;
use super::external::ExternalLedgerOwnership;
pub use bounds::LedgerBounds;

use super::{CreatedNodeCurrentFile, CreatedNodeSection};
use crate::{ReconcileError, Result};
use records::{ChainState, ObjectKind, Phase, Record};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, MAIN_DB};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_journal::{JournalError, Result as SqlResult};
use sync_extend_platform_fs::{
    FileKey, OriginalDirectoryCreation, OriginalFileCreation, OwnedFileCreation,
    ReleasedOriginalFileIdentity,
};

/// All target ancestors must remain retained by the complete restore coordinator.
/// This unregistered module does not yet provide that coordinator.
pub struct NodeRestoreLedger {
    connection: Connection,
    original: ReleasedOriginalFileIdentity,
    path: PathBuf,
    archive_digest: ContentId,
    ledger_id: SpaceId,
    live_instance: Arc<()>,
    state: ChainState,
    bounds: LedgerBounds,
    poisoned: bool,
    completion_reserve: Option<u64>,
    pub(super) external: Option<ExternalLedgerOwnership>,
}

/// Never cloned, deserialized or reconstructed from recovered ledger rows.
pub struct NodeRestoreAttempt {
    live_instance: Arc<()>,
    intent_index: u64,
    kind: ObjectKind,
    internal_role: Option<records::InternalRole>,
    parent_key: FileKey,
    component: String,
    created_key: Option<FileKey>,
    content_closed: bool,
}

/// Exact initialized bytes are still protected by the caller's live creator.
/// SQLite reopening requires a subsequent original identity handoff.
pub struct InitializedNodeLedger<'a> {
    creator: &'a OwnedFileCreation,
    ledger_id: SpaceId,
    digest: ContentId,
    bytes: u64,
    key: FileKey,
    parent: FileKey,
}

impl InitializedNodeLedger<'_> {
    pub fn ledger_id(&self) -> &SpaceId {
        &self.ledger_id
    }
    pub fn verify(&self) -> Result<()> {
        super::created_bytes::verify(
            self.creator,
            self.key,
            self.parent,
            self.bytes,
            &self.digest,
        )
    }
}

impl NodeRestoreLedger {
    /// Build the exact schema in memory, then write/sync/hash only the caller's
    /// actual empty exclusive CREATE. Partial errors preserve that creator.
    /// External root/ownerlock intent and ancestor retention remain caller duties.
    pub fn initialize_created<'a>(
        creator: &'a mut OwnedFileCreation,
        archive_digest: &ContentId,
        bounds: LedgerBounds,
    ) -> Result<InitializedNodeLedger<'a>> {
        let prepare = || -> SqlResult<(SpaceId, Vec<u8>)> {
            bounds.validate()?;
            let mut database = Connection::open_in_memory()?;
            bounds::configure(&mut database, bounds)?;
            database.execute_batch(schema::SCHEMA)?;
            let ledger_id = SpaceId::random()?;
            database.execute(
                "INSERT INTO restore_scope VALUES(1,?1,?2,2)",
                rusqlite::params![archive_digest.as_str(), ledger_id.as_str()],
            )?;
            let bytes = database.serialize(MAIN_DB)?.to_vec();
            if bytes.len() as u64 > bounds.max_database_bytes
                || bytes.get(..16) != Some(b"SQLite format 3\0")
                || bytes.get(18..20) != Some(&[1, 1])
            {
                return Err(JournalError::Invariant(
                    "initialized ledger standalone byte bound",
                ));
            }
            Ok((ledger_id, bytes))
        };
        let (ledger_id, bytes) = prepare().map_err(ReconcileError::from)?;
        let original = creator.original_creation()?;
        let key = original.key()?;
        let parent = original.parent_key()?;
        creator.verify_single_link()?;
        if creator.reader().metadata()?.len() != 0 {
            return Err(ReconcileError::Invariant(
                "external ledger requires empty original CREATE",
            ));
        }
        creator.writer().seek(SeekFrom::Start(0))?;
        crate::fault::checkpoint("node_ledger_created_empty");
        for (index, part) in bytes.chunks(64 * 1024).enumerate() {
            creator.verify_single_link()?;
            creator.writer().write_all(part)?;
            if index == 0 {
                crate::fault::checkpoint("node_ledger_created_first_chunk");
            }
        }
        creator.writer().flush()?;
        creator.writer().sync_all()?;
        crate::fault::checkpoint("node_ledger_created_synced");
        let receipt = InitializedNodeLedger {
            creator,
            ledger_id,
            digest: ContentId::hash(&bytes),
            bytes: bytes.len() as u64,
            key,
            parent,
        };
        receipt.verify()?;
        crate::fault::checkpoint("node_ledger_created_verified");
        Ok(receipt)
    }

    /// Existing exact original only, no CREATE flags or pathname adoption.
    /// Read-only audit precedes opening a writable connection. The complete
    /// coordinator must retain the independent external ownerlock and ancestors.
    /// Hot rollback journals and external writers need a later accepted protocol.
    pub(super) fn open_existing(
        path: &Path,
        original: ReleasedOriginalFileIdentity,
        archive_digest: ContentId,
        expected_ledger: &SpaceId,
        limits: LedgerBounds,
    ) -> std::result::Result<Self, (Box<ReleasedOriginalFileIdentity>, ReconcileError)> {
        let prepare = || -> SqlResult<(Connection, ChainState)> {
            limits.validate()?;
            original.verify()?;
            if !path.is_absolute() || !original.matches_path(path)? {
                return Err(JournalError::Invariant(
                    "exact external original ledger path",
                ));
            }
            let file = std::fs::OpenOptions::new().read(true).open(path)?;
            let size = file.metadata()?.len();
            if size < 512
                || size > limits.max_database_bytes
                || sync_extend_platform_fs::FileKey::from_file(&file)? != original.key()?
            {
                return Err(JournalError::Invariant(
                    "external ledger initial byte bound",
                ));
            }
            // The SQLite handle check below independently closes identity;
            // this initial read is a bounded header preflight only.
            let mut header = [0u8; 20];
            (&file).read_exact(&mut header)?;
            if header[..16] != *b"SQLite format 3\0" || header[18..20] != [1, 1] {
                return Err(JournalError::Invariant("external ledger standalone header"));
            }
            drop(file);
            let mut readonly = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            verify_identity(&readonly, &original, path)?;
            bounds::configure(&mut readonly, limits)?;
            readonly.pragma_update(None, "query_only", true)?;
            let read = Transaction::new_unchecked(&readonly, TransactionBehavior::Deferred)?;
            if schema::audit(&read, &archive_digest, limits)? != *expected_ledger {
                return Err(JournalError::Invariant(
                    "external ledger initialized scope differs",
                ));
            }
            let before = records::verify_chain(&read, &archive_digest, expected_ledger, limits)?;
            read.rollback()?;
            drop(readonly);
            let mut connection = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            verify_identity(&connection, &original, path)?;
            bounds::configure(&mut connection, limits)?;
            let read = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
            if schema::audit(&read, &archive_digest, limits)? != *expected_ledger {
                return Err(JournalError::Invariant(
                    "external ledger writable scope differs",
                ));
            }
            let state = records::verify_chain(&read, &archive_digest, expected_ledger, limits)?;
            read.rollback()?;
            if state.count != before.count
                || state.record_bytes != before.record_bytes
                || state.previous != before.previous
            {
                return Err(JournalError::Invariant(
                    "external ledger changed across reopen",
                ));
            }
            verify_identity(&connection, &original, path)?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            let synchronous: u32 =
                connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
            if synchronous != 2 {
                return Err(JournalError::Invariant(
                    "external ledger FULL synchronization",
                ));
            }
            Ok((connection, state))
        };
        match prepare() {
            Ok((connection, state)) => Ok(Self {
                connection,
                original,
                path: path.to_owned(),
                archive_digest,
                ledger_id: expected_ledger.clone(),
                live_instance: Arc::new(()),
                state,
                bounds: limits,
                poisoned: false,
                completion_reserve: None,
                external: None,
            }),
            Err(error) => Err((Box::new(original), error.into())),
        }
    }

    pub fn intend_file(
        &mut self,
        parent: &OriginalDirectoryCreation<'_>,
        component: &str,
    ) -> Result<NodeRestoreAttempt> {
        self.intend_child(parent, component, ObjectKind::File)
    }
    pub fn intend_directory(
        &mut self,
        parent: &OriginalDirectoryCreation<'_>,
        component: &str,
    ) -> Result<NodeRestoreAttempt> {
        self.intend_child(parent, component, ObjectKind::Directory)
    }
    fn intend_child(
        &mut self,
        parent: &OriginalDirectoryCreation<'_>,
        component: &str,
        kind: ObjectKind,
    ) -> Result<NodeRestoreAttempt> {
        self.verify_external()?;
        parent.verify()?;
        records::validate_component(component).map_err(ReconcileError::from)?;
        let parent_key = parent.key()?;
        let intent_index = self.state.count;
        let record = self.record(Phase::Intended, intent_index, kind, parent_key, component);
        self.append(&record).map_err(ReconcileError::from)?;
        crate::fault::checkpoint("node_ledger_intended_committed");
        Ok(NodeRestoreAttempt {
            live_instance: Arc::clone(&self.live_instance),
            intent_index,
            kind,
            internal_role: None,
            parent_key,
            component: component.to_owned(),
            created_key: None,
            content_closed: false,
        })
    }
    pub fn created_directory(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        original: &OriginalDirectoryCreation<'_>,
    ) -> Result<()> {
        original.verify()?;
        self.created(
            attempt,
            ObjectKind::Directory,
            original.key()?,
            original.parent_key()?,
            original.created_component(),
        )
    }
    pub fn created_file(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        original: &OriginalFileCreation<'_>,
    ) -> Result<()> {
        original.verify()?;
        self.created(
            attempt,
            ObjectKind::File,
            original.key()?,
            original.parent_key()?,
            original.created_component(),
        )
    }
    fn check_attempt(&self, attempt: &NodeRestoreAttempt) -> Result<()> {
        self.verify_external()?;
        if self.poisoned || !Arc::ptr_eq(&attempt.live_instance, &self.live_instance) {
            return Err(ReconcileError::Invariant(
                "restore attempt belongs to another live ledger",
            ));
        }
        Ok(())
    }
    fn created(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        kind: ObjectKind,
        key: FileKey,
        parent: FileKey,
        component: &str,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        if attempt.created_key.is_some()
            || kind != attempt.kind
            || parent != attempt.parent_key
            || component != attempt.component
        {
            return Err(ReconcileError::Invariant(
                "actual CREATE differs from living intended",
            ));
        }
        let mut record = self.record(
            Phase::Created,
            attempt.intent_index,
            kind,
            parent,
            component,
        );
        record.internal_role = attempt.internal_role;
        record.object_key = Some(key.to_string());
        self.append(&record).map_err(ReconcileError::from)?;
        attempt.created_key = Some(key);
        crate::fault::checkpoint("node_ledger_created_committed");
        Ok(())
    }
    pub fn close_section(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        receipt: &CreatedNodeSection<'_>,
    ) -> Result<()> {
        receipt.verify()?;
        self.close_verified(
            attempt,
            receipt.original()?,
            receipt.digest(),
            receipt.bytes(),
        )
    }
    pub fn close_current_file(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        receipt: &CreatedNodeCurrentFile<'_>,
    ) -> Result<()> {
        receipt.verify()?;
        self.close_verified(
            attempt,
            receipt.original()?,
            receipt.digest(),
            receipt.bytes(),
        )
    }
    /// Private glue only reachable from exact complete original content receipts.
    fn close_verified(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        original: OriginalFileCreation<'_>,
        digest: &ContentId,
        bytes: u64,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        original.verify()?;
        if attempt.kind != ObjectKind::File
            || attempt.content_closed
            || attempt.created_key != Some(original.key()?)
            || attempt.parent_key != original.parent_key()?
            || attempt.component != original.created_component()
            || bytes > self.bounds.max_content_bytes
        {
            return Err(ReconcileError::Invariant(
                "complete content receipt original differs",
            ));
        }
        let mut record = self.record(
            Phase::ContentClosed,
            attempt.intent_index,
            attempt.kind,
            attempt.parent_key,
            &attempt.component,
        );
        record.object_key = Some(original.key()?.to_string());
        record.internal_role = attempt.internal_role;
        record.content_digest = Some(digest.clone());
        record.bytes = Some(bytes);
        self.append(&record).map_err(ReconcileError::from)?;
        attempt.content_closed = true;
        crate::fault::checkpoint("node_ledger_content_committed");
        Ok(())
    }
    fn record(
        &self,
        phase: Phase,
        intent_index: u64,
        kind: ObjectKind,
        parent: FileKey,
        component: &str,
    ) -> Record {
        Record {
            version: 2,
            archive_digest: self.archive_digest.clone(),
            ledger_id: self.ledger_id.clone(),
            phase,
            intent_index,
            kind,
            internal_role: None,
            parent_key: parent.to_string(),
            component: component.to_owned(),
            object_key: None,
            content_digest: None,
            bytes: None,
        }
    }
    fn append(&mut self, record: &Record) -> SqlResult<()> {
        if self.poisoned {
            return Err(JournalError::Invariant(
                "external ledger uncertain terminal; audit required",
            ));
        }
        self.verify_external()
            .map_err(|_| JournalError::Invariant("external ledger ownership changed"))?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        let json = serde_json::to_string(record)?;
        if json.is_empty()
            || json.len() > 65_536
            || self.state.count >= self.bounds.max_records
            || self
                .state
                .record_bytes
                .checked_add(json.len() as u64)
                .is_none_or(|bytes| bytes > self.bounds.max_record_bytes)
        {
            return Err(JournalError::Invariant(
                "external ledger append aggregate bound",
            ));
        }
        bounds::configure(&mut self.connection, self.bounds)?;
        // An uncertain SQL/native terminal disables further live attempts.
        // Restart inspection does not recover this instance's tokens.
        self.poisoned = true;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if schema::audit(&transaction, &self.archive_digest, self.bounds)? != self.ledger_id {
            return Err(JournalError::Invariant(
                "external ledger append scope differs",
            ));
        }
        let before = records::verify_chain(
            &transaction,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if before.count != self.state.count
            || before.record_bytes != self.state.record_bytes
            || before.previous != self.state.previous
        {
            return Err(JournalError::Invariant(
                "external ledger concurrent chain change",
            ));
        }
        let hash = ContentId::hash(&serde_json::to_vec(&(
            before.count,
            &before.previous,
            &json,
        ))?);
        transaction.execute(
            "INSERT INTO main.restore_records VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                i64::try_from(before.count)
                    .map_err(|_| JournalError::Invariant("ledger index SQL range"))?,
                before.previous,
                json,
                hash.as_str()
            ],
        )?;
        let after = records::verify_chain(
            &transaction,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if after.count != before.count + 1 || after.previous != hash.as_str() {
            return Err(JournalError::Invariant(
                "external ledger appended chain differs",
            ));
        }
        transaction.commit()?;
        self.verify_external()
            .map_err(|_| JournalError::Invariant("external ledger ownership changed"))?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        self.state = after;
        self.poisoned = false;
        Ok(())
    }
}

fn verify_identity(
    connection: &Connection,
    original: &ReleasedOriginalFileIdentity,
    path: &Path,
) -> SqlResult<()> {
    original.verify()?;
    if !original.matches_path(path)?
        || sync_extend_platform_fs::sqlite_main_file_identity(connection)? != original.key()?
    {
        return Err(JournalError::Invariant(
            "external ledger exact SQLite original changed",
        ));
    }
    Ok(())
}

// Included inside ledger/mod.rs; only the original-root coordinator may call.
impl NodeRestoreLedger {
    pub(super) fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub(super) fn intend_root(
        &mut self,
        parent: &sync_extend_platform_fs::LockedDirectory,
        component: &str,
    ) -> Result<NodeRestoreAttempt> {
        self.verify_external()?;
        parent.require_case_insensitive()?;
        records::validate_component(component).map_err(ReconcileError::from)?;
        let parent_key = parent.key()?;
        let intent_index = self.state.count;
        let record = self.record(
            Phase::Intended,
            intent_index,
            ObjectKind::Directory,
            parent_key,
            component,
        );
        self.append(&record).map_err(ReconcileError::from)?;
        Ok(NodeRestoreAttempt {
            live_instance: Arc::clone(&self.live_instance),
            intent_index,
            kind: ObjectKind::Directory,
            internal_role: None,
            parent_key,
            component: component.to_owned(),
            created_key: None,
            content_closed: false,
        })
    }
}

// Private fixed reserved marker intent; ordinary caller strings still refuse.
impl NodeRestoreLedger {
    pub(super) fn intend_worktree_marker(
        &mut self,
        parent: &OriginalDirectoryCreation<'_>,
    ) -> Result<NodeRestoreAttempt> {
        self.verify_external()?;
        parent.verify()?;
        let parent_key = parent.key()?;
        let intent_index = self.state.count;
        let mut record = self.record(
            Phase::Intended,
            intent_index,
            ObjectKind::Directory,
            parent_key,
            ".sync-extend",
        );
        record.internal_role = Some(records::InternalRole::WorktreeMarkerDirectory);
        self.append(&record).map_err(ReconcileError::from)?;
        Ok(NodeRestoreAttempt {
            live_instance: Arc::clone(&self.live_instance),
            intent_index,
            kind: ObjectKind::Directory,
            parent_key,
            component: ".sync-extend".to_owned(),
            internal_role: Some(records::InternalRole::WorktreeMarkerDirectory),
            created_key: None,
            content_closed: false,
        })
    }
    pub(super) fn close_original_space_marker(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        creator: &OwnedFileCreation,
        archive: &super::VerifiedNodeStateArchive,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        if archive.digest() != &self.archive_digest || attempt.component != "space-id" {
            return Err(ReconcileError::Invariant(
                "space marker original archive scope",
            ));
        }
        let original = creator.original_creation()?;
        let bytes = archive.space().as_str().as_bytes();
        let digest = ContentId::hash(bytes);
        super::created_bytes::verify(
            creator,
            original.key()?,
            original.parent_key()?,
            bytes.len() as u64,
            &digest,
        )?;
        self.close_verified(attempt, original, &digest, bytes.len() as u64)
    }
}

// Private original image content closure, never caller chosen digest authority.
impl NodeRestoreLedger {
    pub(super) fn close_created_journal(
        &mut self,
        attempt: &mut NodeRestoreAttempt,
        receipt: &sync_extend_journal::CreatedJournalRestore<'_>,
    ) -> Result<()> {
        receipt.verify()?;
        let digest: ContentId = receipt.digest().parse()?;
        self.close_verified(attempt, receipt.original()?, &digest, receipt.bytes())
    }
}

// Private preflight checks on the exact living ledger, never recovered attempts.
impl NodeRestoreLedger {
    pub(super) fn require_original_preflight_capacity(
        &mut self,
        plan: &super::PreparedOriginalNodeRestore,
    ) -> Result<()> {
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        if self.poisoned
            || self.archive_digest != plan.archive_digest
            || self.state.count != 0
            || self.state.record_bytes != 0
            || self.bounds.max_records < plan.required_records
            || self.bounds.max_intents < plan.required_intents
            || self.bounds.max_record_bytes < plan.reserved_record_bytes
            || self.bounds.max_database_bytes < plan.reserved_database_bytes
            || self.bounds.max_content_bytes < plan.required_file_bytes
            || self.bounds.max_vm_instructions != plan.ledger_bounds.max_vm_instructions
            || self.bounds.max_query_time != plan.ledger_bounds.max_query_time
        {
            return Err(ReconcileError::Invariant(
                "preflight requires exact fresh living ledger and all reserved budgets",
            ));
        }
        bounds::configure(&mut self.connection, self.bounds)?;
        let snapshot = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        if schema::audit(&snapshot, &self.archive_digest, self.bounds)? != self.ledger_id {
            return Err(ReconcileError::Invariant(
                "preflight live ledger original catalog changed",
            ));
        }
        let chain = records::verify_chain(
            &snapshot,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if chain.count != 0 || chain.record_bytes != 0 || chain.previous != self.state.previous {
            return Err(ReconcileError::Invariant(
                "preflight live ledger original rows changed",
            ));
        }
        snapshot.rollback()?;
        let page_size: i64 = self
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        let page_size = u64::try_from(page_size)
            .map_err(|_| ReconcileError::Invariant("negative live ledger page size"))?;
        let pages = self
            .bounds
            .max_database_bytes
            .checked_div(page_size)
            .filter(|count| *count > 0)
            .ok_or(ReconcileError::ResourceLimit(
                "preflight ledger SQLite physical page budget",
            ))?;
        self.connection.pragma_update(
            None,
            "max_page_count",
            i64::try_from(pages)
                .map_err(|_| ReconcileError::ResourceLimit("ledger page SQL range"))?,
        )?;
        let actual: i64 = self
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))?;
        let actual = u64::try_from(actual)
            .map_err(|_| ReconcileError::Invariant("negative actual ledger page limit"))?;
        if actual > pages {
            return Err(ReconcileError::ResourceLimit(
                "preflight live ledger physical page limit unapplied",
            ));
        }
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        crate::fault::checkpoint("node_whole_preflight_before_roots");
        Ok(())
    }
}

// Private complete-chain scope read; it never advances the ledger or issues attempts.
impl NodeRestoreLedger {
    pub(super) fn original_completion_scope(&self) -> Result<(SpaceId, ContentId)> {
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        if self.poisoned {
            return Err(ReconcileError::Invariant(
                "completion original ledger uncertain terminal",
            ));
        }
        let connection = self.original_completion_reader()?;
        let snapshot = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
        if schema::audit(&snapshot, &self.archive_digest, self.bounds)? != self.ledger_id {
            return Err(ReconcileError::Invariant(
                "completion original external ledger catalog changed",
            ));
        }
        let chain = records::verify_chain(
            &snapshot,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if chain.count != self.state.count
            || chain.record_bytes != self.state.record_bytes
            || chain.previous != self.state.previous
        {
            return Err(ReconcileError::Invariant(
                "completion original external ledger rows changed",
            ));
        }
        snapshot.rollback()?;
        self.verify_external()?;
        verify_identity(&connection, &self.original, &self.path)?;
        Ok((self.ledger_id.clone(), chain.previous.parse()?))
    }
}

// Exact typed chain comparison; every SQL read owns a fresh snapshot/budget.
impl NodeRestoreLedger {
    pub(super) fn verify_original_completion_objects(
        &self,
        manifest: &super::completion::OriginalNodeCompletionManifest,
    ) -> Result<()> {
        self.verify_completion_original_identity()?;
        if self.poisoned || manifest.original_chain_terminal.as_str() != self.state.previous {
            return Err(ReconcileError::Invariant(
                "completion original live terminal mismatch",
            ));
        }
        let connection = self.original_completion_reader()?;
        let snapshot = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
        self.validate_completion_schema_and_scope(&snapshot)?;
        verify_completion_objects_connection(
            &snapshot,
            manifest,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        snapshot.rollback()?;
        verify_identity(&connection, &self.original, &self.path)?;
        self.verify_completion_original_identity()
    }
}
pub(super) fn verify_completion_objects_connection(
    connection: &Connection,
    manifest: &super::completion::OriginalNodeCompletionManifest,
    archive: &ContentId,
    ledger: &SpaceId,
    limits: LedgerBounds,
) -> Result<()> {
    use std::collections::BTreeMap;
    manifest.validate()?;
    let chain = records::verify_chain(connection, archive, ledger, limits)?;
    if manifest.archive_digest != *archive
        || manifest.ledger_id != *ledger
        || manifest.original_chain_terminal.as_str() != chain.previous
    {
        return Err(ReconcileError::Invariant(
            "completion stored original chain scope differs",
        ));
    }
    let expected: BTreeMap<_, _> = manifest
        .objects
        .iter()
        .map(|object| {
            (
                (object.parent_key.clone(), object.created_component.clone()),
                object,
            )
        })
        .collect();
    if expected.len() != manifest.objects.len() {
        return Err(ReconcileError::Invariant(
            "completion original parent/component duplicate",
        ));
    }
    let mut statement =
        connection.prepare("SELECT record FROM main.restore_records ORDER BY record_index")?;
    let mut rows = statement.query([])?;
    let mut created = BTreeMap::new();
    let mut closed = BTreeMap::new();
    let mut intended = 0usize;
    while let Some(row) = rows.next()? {
        let value: String = row.get(0)?;
        let record: Record = serde_json::from_str(&value)?;
        if record.phase == Phase::Intended {
            intended += 1;
        } else if record.phase == Phase::Created {
            let component = (record.parent_key.clone(), record.component.clone());
            let original = expected.get(&component).ok_or(ReconcileError::Invariant(
                "completion ledger contains unexpected original object",
            ))?;
            let kind = match record.kind {
                ObjectKind::Directory => "directory",
                ObjectKind::File => "file",
            };
            if original.kind != kind
                || record.object_key.as_deref() != Some(original.object_key.as_str())
                || created.insert(record.intent_index, *original).is_some()
            {
                return Err(ReconcileError::Invariant(
                    "completion original created key/kind mismatch",
                ));
            }
        } else if record.phase == Phase::ContentClosed {
            let original = created
                .get(&record.intent_index)
                .ok_or(ReconcileError::Invariant(
                    "completion content without original created",
                ))?;
            if original.content_bytes != record.bytes
                || original.content_digest != record.content_digest
                || closed.insert(record.intent_index, ()).is_some()
            {
                return Err(ReconcileError::Invariant(
                    "completion original ledger content mismatch",
                ));
            }
        }
    }
    // Writer/CAS empty sentinels intentionally have only intended/created;
    // all other original files, including the space marker, must be closed.
    if created.len() != manifest.object_count || intended != manifest.object_count {
        return Err(ReconcileError::Invariant(
            "completion original created inventory incomplete",
        ));
    }
    for (intent, object) in &created {
        let sentinel_slot = (object.root == "worktree"
            && object.components == [".sync-extend", "writer.lock"])
            || (object.root == "data"
                && (object.components == ["writer.lock"]
                    || object.components == ["cas-access.lock"]));
        let empty_lock = object.kind == "file"
            && sentinel_slot
            && object.content_bytes == Some(0)
            && object.content_digest.as_ref() == Some(&ContentId::hash(&[]));
        if object.kind == "file" && !empty_lock && !closed.contains_key(intent) {
            return Err(ReconcileError::Invariant(
                "completion original file lacks complete content receipt",
            ));
        }
    }

    drop(rows);
    drop(statement);
    Ok(())
}

// Insert-only durable original completion, always independent of restored targets.
use super::completion::{OriginalNodeCompletionManifest, OriginalNodeCompletionObservation};

/// Durable evidence can be inspected after restart, but never grants native
/// CREATE, adoption, continuation, mutation or cleanup permissions.
pub struct OriginalNodeCompletionEvidence {
    pub(super) archive_digest: ContentId,
    pub(super) ledger_id: SpaceId,
    pub(super) original_terminal: ContentId,
    pub(super) completion_digest: ContentId,
    pub(super) manifest_bytes: u64,
}

impl OriginalNodeCompletionEvidence {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn completion_digest(&self) -> &ContentId {
        &self.completion_digest
    }
    pub fn ledger_id(&self) -> &SpaceId {
        &self.ledger_id
    }
    pub fn original_terminal(&self) -> &ContentId {
        &self.original_terminal
    }
    pub fn manifest_bytes(&self) -> u64 {
        self.manifest_bytes
    }
}

impl NodeRestoreLedger {
    /// Only a currently verified original observation may reach this writer.
    /// The manifest is rechecked on both sides of the immediate transaction.
    /// Any uncertain SQL/native exit permanently poisons this living issuer.
    pub fn commit_original_completion(
        &mut self,
        observation: OriginalNodeCompletionObservation<'_, '_>,
    ) -> Result<OriginalNodeCompletionEvidence> {
        self.verify_original_completion_objects(&observation.manifest)?;
        // Close the original issuer before validating caller-held completion
        // memberships; refusal preserves targets and never permits retry minting.
        let bytes = observation.manifest.bytes()?;
        let (ledger_id, terminal) = self.original_completion_scope()?;
        self.poisoned = true;
        observation.verify()?;
        self.verify_external()?;
        self.verify_completion_original_identity()?;
        let digest = ContentId::hash(&bytes);
        if self.completion_reserve.is_none() {
            return Err(ReconcileError::Invariant(
                "completion requires original before-roots durable reservation",
            ));
        }
        self.require_completion_capacity(bytes.len() as u64)?;
        if observation.manifest.ledger_id != ledger_id
            || observation.manifest.original_chain_terminal != terminal
        {
            return Err(ReconcileError::Invariant(
                "durable completion observation no longer has exact original terminal",
            ));
        }
        self.configure_completion_budget()?;
        // This flag is intentionally set before transaction acquisition. Busy,
        // trigger refusal, rollback uncertainty or identity drift disables minting.
        self.poisoned = true;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_completion_schema_and_scope(&transaction)?;
        let prior: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.restore_completions)",
            [],
            |row| row.get(0),
        )?;
        if prior {
            return Err(ReconcileError::Invariant(
                "original completion is insert-only and single-use",
            ));
        }
        crate::fault::checkpoint("node_completion_before_insert");
        transaction.execute(
            "INSERT INTO main.restore_completions \
             (singleton,archive_digest,ledger_id,original_terminal,manifest,manifest_hash) \
             VALUES(1,?1,?2,?3,?4,?5)",
            rusqlite::params![
                observation.manifest.archive_digest.as_str(),
                ledger_id.as_str(),
                terminal.as_str(),
                &bytes,
                digest.as_str(),
            ],
        )?;
        crate::fault::checkpoint("node_completion_after_insert_before_commit");
        self.verify_completion_original_identity()?;
        observation.verify()?;
        verify_completion_objects_connection(
            &transaction,
            &observation.manifest,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        transaction.commit()?;
        crate::fault::checkpoint("node_completion_after_commit");
        self.verify_external()?;
        self.verify_completion_original_identity()?;
        let actual = self
            .read_original_completion_evidence()?
            .ok_or(ReconcileError::Invariant(
                "original completion absent after durable commit",
            ))?;
        if actual.completion_digest != digest
            || actual.original_terminal != terminal
            || actual.ledger_id != ledger_id
            || actual.manifest_bytes != bytes.len() as u64
        {
            return Err(ReconcileError::Invariant(
                "actual durable original completion differs",
            ));
        }
        observation.verify()?;
        // Completion closes this original living issuer permanently. It never
        // grants a writable restored LocalSpace or frees original owner scope.
        Ok(actual)
    }
}

pub(in super::super) fn parse_completion_manifest(
    bytes: &[u8],
    expected: &ContentId,
    max_bytes: usize,
) -> Result<OriginalNodeCompletionManifest> {
    if bytes.is_empty()
        || bytes.len() > max_bytes.min(super::completion_codec::MAX_BYTES)
        || ContentId::hash(bytes) != *expected
    {
        return Err(ReconcileError::Invariant(
            "durable original completion bytes/hash/budget differ",
        ));
    }
    super::completion_codec::preflight_decode(bytes)?;
    let manifest: OriginalNodeCompletionManifest = serde_json::from_slice(bytes)?;
    if manifest.bytes()? != bytes {
        return Err(ReconcileError::Invariant(
            "durable original completion canonical encoding differs",
        ));
    }
    Ok(manifest)
}

// Included inside ledger/mod.rs. Independent schema3 is installed before any root effect.
impl NodeRestoreLedger {
    pub(super) fn configure_completion_budget(&mut self) -> Result<()> {
        configure_completion_connection(&mut self.connection, self.bounds)?;
        Ok(())
    }
    pub(super) fn verify_completion_original_identity(&self) -> Result<()> {
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        Ok(())
    }
    pub(super) fn require_completion_capacity(&self, bytes: u64) -> Result<()> {
        if self
            .completion_reserve
            .is_some_and(|reserve| bytes > reserve)
        {
            return Err(ReconcileError::ResourceLimit(
                "completion actual manifest exceeds original preflight reservation",
            ));
        }
        let physical = bytes
            .checked_mul(2)
            .and_then(|count| count.checked_add(64 * 1024));
        if bytes == 0
            || bytes > 32 * 1024 * 1024
            || self
                .state
                .record_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.bounds.max_record_bytes)
            || physical.is_none_or(|size| size > self.bounds.max_database_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "whole completion manifest and page budget",
            ));
        }
        Ok(())
    }
    pub(super) fn validate_completion_schema_and_scope(
        &self,
        connection: &Connection,
    ) -> Result<()> {
        super::durable_schema::audit_current(
            connection,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds.max_database_bytes,
            true,
        )?;
        let chain = records::verify_chain(
            connection,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if chain.count != self.state.count
            || chain.record_bytes != self.state.record_bytes
            || chain.previous != self.state.previous
        {
            return Err(ReconcileError::Invariant(
                "completion original immutable chain differs",
            ));
        }
        Ok(())
    }
    pub fn read_original_completion_evidence(
        &self,
    ) -> Result<Option<OriginalNodeCompletionEvidence>> {
        use rusqlite::OptionalExtension;
        self.verify_completion_original_identity()?;
        let connection = self.original_completion_reader()?;
        let snapshot = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
        self.validate_completion_schema_and_scope(&snapshot)?;
        let row: Option<(String, String, String, Vec<u8>, String)> = snapshot
            .query_row(
                "SELECT archive_digest,ledger_id,original_terminal,manifest,manifest_hash \
             FROM main.restore_completions WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((archive, ledger, terminal, bytes, hash)) = row else {
            snapshot.rollback()?;
            verify_identity(&connection, &self.original, &self.path)?;
            self.verify_completion_original_identity()?;
            return Ok(None);
        };
        let digest: ContentId = hash.parse()?;
        let manifest =
            parse_completion_manifest(&bytes, &digest, self.bounds.max_record_bytes as usize)?;
        if archive != self.archive_digest.as_str()
            || ledger != self.ledger_id.as_str()
            || terminal != self.state.previous
            || manifest.archive_digest != self.archive_digest
            || manifest.ledger_id != self.ledger_id
            || manifest.original_chain_terminal.as_str() != terminal
        {
            return Err(ReconcileError::Invariant(
                "completion exact stored scope/hashchain differs",
            ));
        }
        verify_completion_objects_connection(
            &snapshot,
            &manifest,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        snapshot.rollback()?;
        verify_identity(&connection, &self.original, &self.path)?;
        self.verify_completion_original_identity()?;
        Ok(Some(OriginalNodeCompletionEvidence {
            archive_digest: self.archive_digest.clone(),
            ledger_id: self.ledger_id.clone(),
            original_terminal: terminal.parse()?,
            completion_digest: digest,
            manifest_bytes: bytes.len() as u64,
        }))
    }
}

// Exact schema2 -> schema3 only on the original fresh external ledger before roots.
impl NodeRestoreLedger {
    pub(super) fn prepare_durable_original_completion(
        &mut self,
        manifest_reserve: u64,
    ) -> Result<()> {
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        if self.poisoned || self.state.count != 0 || self.state.record_bytes != 0 {
            return Err(ReconcileError::Invariant(
                "completion schema requires original fresh empty live ledger",
            ));
        }
        self.require_completion_capacity(manifest_reserve)?;
        self.configure_completion_budget()?;
        let version: u32 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != 2 {
            return Err(ReconcileError::Invariant(
                "completion upgrade requires original schema2, never repeated schema3",
            ));
        }
        self.poisoned = true;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if schema::audit(&transaction, &self.archive_digest, self.bounds)? != self.ledger_id {
            return Err(ReconcileError::Invariant(
                "completion upgrade original schema2 scope differs",
            ));
        }
        let before = records::verify_chain(
            &transaction,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if before.count != 0 || before.record_bytes != 0 {
            return Err(ReconcileError::Invariant(
                "completion upgrade original records nonempty",
            ));
        }
        crate::fault::checkpoint("node_completion_schema_before_upgrade");
        transaction.execute_batch(super::durable_schema::COMPLETION_SCHEMA)?;
        super::durable_schema::audit_current(
            &transaction,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds.max_database_bytes,
            true,
        )?;
        let after = records::verify_chain(
            &transaction,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds,
        )?;
        if before.count != after.count
            || before.record_bytes != after.record_bytes
            || before.previous != after.previous
        {
            return Err(ReconcileError::Invariant(
                "completion upgrade changed original chain",
            ));
        }
        transaction.commit()?;
        crate::fault::checkpoint("node_completion_schema_after_upgrade");
        self.verify_external()?;
        verify_identity(&self.connection, &self.original, &self.path)?;
        super::durable_schema::audit_current(
            &self.connection,
            &self.archive_digest,
            &self.ledger_id,
            self.bounds.max_database_bytes,
            true,
        )?;
        self.completion_reserve = Some(manifest_reserve);
        self.poisoned = false;
        Ok(())
    }
}

// Every observation owns a fresh SQL budget and actual same-original main handle.
impl NodeRestoreLedger {
    pub(super) fn original_completion_reader(&self) -> Result<Connection> {
        self.verify_completion_original_identity()?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = self.path.as_os_str().to_owned();
            sidecar.push(suffix);
            match std::fs::symlink_metadata(Path::new(&sidecar)) {
                Ok(_) => {
                    return Err(ReconcileError::Invariant(
                        "completion observer sidecar refusal",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let mut connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        verify_identity(&connection, &self.original, &self.path)?;
        configure_completion_connection(&mut connection, self.bounds)?;
        connection.pragma_update(None, "query_only", true)?;
        self.verify_completion_original_identity()?;
        Ok(connection)
    }
}

pub(super) fn configure_completion_connection(
    connection: &mut Connection,
    limits: LedgerBounds,
) -> Result<()> {
    bounds::configure(connection, limits)?;
    // SQLite counts the entire row including scope/hash fields against LENGTH.
    let maximum = limits
        .max_record_bytes
        .min(super::completion_codec::MAX_BYTES as u64)
        .checked_add(4096)
        .ok_or(ReconcileError::ResourceLimit(
            "completion SQL row length overflow",
        ))?;
    let maximum = i32::try_from(maximum)
        .map_err(|_| ReconcileError::ResourceLimit("completion SQL row length bound"))?;
    connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, maximum)?;
    if connection.limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)? > maximum {
        return Err(ReconcileError::Invariant(
            "completion SQL row length bound unapplied",
        ));
    }
    Ok(())
}
