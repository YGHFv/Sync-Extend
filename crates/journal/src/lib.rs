use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::{path::Path, time::Duration};
use sync_extend_core_model::*;

const MAX_OPERATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING_OPS: u64 = 10_000;
const SCHEMA_VERSION: u32 = 38;

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("journal serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid journal model: {0}")]
    Model(#[from] ModelError),
    #[error("journal invariant failed: {0}")]
    Invariant(&'static str),
}

pub type Result<T> = std::result::Result<T, JournalError>;

mod causal_log;
mod operation_batch;
mod read_view;
use read_view::JournalReadView;
mod native_publication;
pub use native_publication::NativePublicationStage;
#[cfg(windows)]
pub use native_publication::{NativePublicationFileObservation, NativePublicationFileView};
mod publication_admission;
#[cfg(windows)]
pub use native_publication::creation::NativePublicationCreation;
#[cfg(windows)]
pub use native_publication::sealing::NativePublicationObservation;
#[cfg(windows)]
pub use native_publication::sealing::NativePublicationReadiness;
mod publication_lookup;
mod remote_publication;
pub use remote_publication::RemotePublicationProof;
mod remote_replay;
pub use remote_replay::{RemoteReplayDisposition, RemoteReplayReport};
mod storage_policy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Duplicate,
    Pending,
    Received,
}

pub struct Journal {
    connection: Connection,
    database_path: std::path::PathBuf,
    max_storage_entries: usize,
    #[cfg(windows)]
    native_issuance: native_publication::issuance::Gate,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_storage_limit(path, limits::MAX_ENTRIES)
    }

    /// Configures converted writers before opening or migrating the database.
    pub fn open_with_storage_limit(path: &Path, max_storage_entries: usize) -> Result<Self> {
        storage_policy::validate(max_storage_entries)?;
        for ancestor in path.ancestors() {
            match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) => {
                    #[cfg(windows)]
                    let reparse = {
                        use std::os::windows::fs::MetadataExt;
                        metadata.file_attributes() & 0x400 != 0
                    };
                    #[cfg(not(windows))]
                    let reparse = false;
                    if metadata.file_type().is_symlink() || reparse {
                        return Err(JournalError::Invariant("unsafe database path"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                let tx = connection.transaction()?;
                tx.execute_batch(include_str!("schema.sql"))?;
                tx.commit()?;
            }
            1..=SCHEMA_VERSION => {}
            _ => return Err(JournalError::Invariant("unsupported schema version")),
        }
        if version < 2 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-002.sql"))?;
            let retained: Vec<(String, String)> = {
                let mut statement = tx.prepare("SELECT snapshot_id,manifest FROM snapshots")?;
                let rows = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for (root, json) in retained {
                let manifest: Manifest = serde_json::from_str(&json)?;
                if manifest.root()?.as_str() != root {
                    return Err(JournalError::Invariant(
                        "snapshot integrity failed during migration",
                    ));
                }
                pin_snapshot(&tx, &root, &manifest)?;
            }
            tx.commit()?;
        }
        if version < 3 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-003.sql"))?;
            tx.commit()?;
        }
        if version < 4 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-004.sql"))?;
            tx.commit()?;
        }
        if version < 5 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-005.sql"))?;
            tx.commit()?;
        }
        if version < 6 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-006.sql"))?;
            tx.commit()?;
        }
        if version < 7 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-007.sql"))?;
            tx.commit()?;
        }
        if version < 8 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-008.sql"))?;
            tx.commit()?;
        }
        if version < 9 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-009.sql"))?;
            tx.commit()?;
        }
        if version < 10 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-010.sql"))?;
            tx.commit()?;
        }
        if version < 11 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-011.sql"))?;
            tx.commit()?;
        }
        if version < 12 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-012.sql"))?;
            tx.commit()?;
        }
        if version < 13 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-013.sql"))?;
            tx.commit()?;
        }
        if version < 14 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-014.sql"))?;
            tx.commit()?;
        }
        if version < 15 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-015.sql"))?;
            tx.commit()?;
        }
        if version < 16 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-016.sql"))?;
            tx.commit()?;
        }
        if version < 17 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-017.sql"))?;
            tx.commit()?;
        }
        if version < 18 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-018.sql"))?;
            tx.commit()?;
        }
        if version < 19 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-019.sql"))?;
            tx.commit()?;
        }
        if version < 20 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-020.sql"))?;
            tx.commit()?;
        }
        if version < 21 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-021.sql"))?;
            tx.commit()?;
        }
        if version < 22 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-022.sql"))?;
            tx.commit()?;
        }
        if version < 23 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-023.sql"))?;
            tx.commit()?;
        }
        if version < 24 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-024.sql"))?;
            tx.commit()?;
        }
        if version < 25 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-025.sql"))?;
            tx.commit()?;
        }
        if version < 26 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-026.sql"))?;
            tx.commit()?;
        }
        if version < 27 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-027.sql"))?;
            tx.commit()?;
        }
        if version < 28 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-028.sql"))?;
            tx.commit()?;
        }
        if version < 29 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-029.sql"))?;
            tx.commit()?;
        }
        if version < 30 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-030.sql"))?;
            tx.commit()?;
        }
        if version < 31 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-031.sql"))?;
            tx.commit()?;
        }
        if version < 32 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-032.sql"))?;
            tx.commit()?;
        }
        if version < 33 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-033.sql"))?;
            tx.commit()?;
        }
        if version < 34 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-034.sql"))?;
            tx.commit()?;
        }
        if version < 35 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-035.sql"))?;
            tx.commit()?;
        }
        if version < 36 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-036.sql"))?;
            tx.commit()?;
        }
        if version < 37 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-037.sql"))?;
            tx.commit()?;
        }
        if version < 38 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("migration-038.sql"))?;
            tx.commit()?;
        }
        native_publication::validate_schema(&connection)?;
        #[cfg(windows)]
        let native_issuance = native_publication::issuance::register(&connection)?;
        Ok(Self {
            connection,
            database_path: std::fs::canonicalize(path)?,
            max_storage_entries,
            #[cfg(windows)]
            native_issuance,
        })
    }

    pub fn state(&self, key: &str) -> Result<Option<String>> {
        self.read_view().state(key)
    }

    pub fn initialize(&mut self, space: &SpaceId, device: &DeviceId, root: &str) -> Result<()> {
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        if root.len() > MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("local root metadata limit"));
        }
        let tx =
            Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let view = self.read_view();
        let before = view.audit_history_capacity(space, bounds)?;
        let identity = [
            ("space_id", space.as_str()),
            ("device_id", device.as_str()),
            ("worktree", root),
        ];
        let mut present = 0;
        for (key, value) in identity {
            let old: Option<String> = tx
                .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                    row.get(0)
                })
                .optional()?;
            if old.as_deref().is_some_and(|old| old != value) {
                return Err(JournalError::Invariant("local identity/root mismatch"));
            }
            present += usize::from(old.is_some());
        }
        if present == identity.len() {
            tx.commit()?;
            return Ok(());
        }
        if present != 0 || before.rows.iter().any(|row| row.table() == "local_state") {
            return Err(JournalError::Invariant("incomplete local identity"));
        }
        storage_policy::history::within(&before.report)?;
        for (key, value) in identity {
            if tx.execute(
                "INSERT OR IGNORE INTO local_state VALUES (?1, ?2)",
                params![key, value],
            )? != 1
            {
                return Err(JournalError::Invariant("local identity changed"));
            }
        }
        let after = view.audit_history_capacity(space, bounds)?;
        storage_policy::history::initialized(&before, &after, &identity)?;
        storage_policy::history::within(&after.report)?;
        tx.commit()?;
        Ok(())
    }

    pub fn current(&self, space: &SpaceId) -> Result<Option<Manifest>> {
        self.read_view().current(space)
    }

    pub fn operations(&self, space: &SpaceId) -> Result<Vec<Operation>> {
        let mut statement = self.connection.prepare(
            "SELECT payload FROM operations WHERE space_id=?1 ORDER BY origin_device_id, origin_seq",
        )?;
        let rows = statement.query_map([space.as_str()], |row| row.get::<_, String>(0))?;
        let mut operations = Vec::new();
        for row in rows {
            let op: Operation = serde_json::from_str(&row?)?;
            op.validate()?;
            operations.push(op);
        }
        Ok(operations)
    }

    pub fn snapshots(&self, space: &SpaceId) -> Result<Vec<(SnapshotId, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_id,state FROM snapshots WHERE space_id=?1
             AND snapshot_id NOT IN (SELECT snapshot_id FROM snapshot_prunings)
             ORDER BY created_at_ms, snapshot_id",
        )?;
        let rows = statement.query_map([space.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, state) = row?;
            Ok((id.parse()?, state))
        })
        .collect()
    }

    pub fn retained_manifests(&self, space: &SpaceId) -> Result<Vec<Manifest>> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_id,manifest FROM snapshots WHERE space_id=?1
                AND snapshot_id NOT IN (SELECT snapshot_id FROM snapshot_prunings)",
        )?;
        let rows = statement.query_map([space.as_str()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut manifests = Vec::new();
        for row in rows {
            let (root, json) = row?;
            let manifest: Manifest = serde_json::from_str(&json)?;
            if manifest.space_id != *space || manifest.root()?.as_str() != root {
                return Err(JournalError::Invariant("retained snapshot root mismatch"));
            }
            manifests.push(manifest);
        }
        Ok(manifests)
    }

    pub fn snapshot(&self, space: &SpaceId, root: &SnapshotId) -> Result<Manifest> {
        self.read_view().snapshot(space, root)
    }

    pub fn publication(&self, id: &EntryId) -> Result<Publication> {
        self.read_view().publication(id)
    }

    pub fn outstanding_publications(&self, space: &SpaceId) -> Result<Vec<Publication>> {
        let mut statement = self.connection.prepare(
            "SELECT transaction_id FROM publications WHERE space_id=?1 AND (state!='committed' OR cleaned=0)",
        )?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| self.publication(&id.parse()?))
            .collect()
    }

    pub fn begin_publication(&mut self, intent: &PublicationIntent) -> Result<()> {
        if intent.remote.is_some() {
            return Err(JournalError::Invariant(
                "remote publication requires distinct native admission",
            ));
        }
        if intent.completion.is_some() {
            return self.begin_admitted_publication(intent);
        }
        self.require_no_tree_restore(&intent.space_id, limits::MAX_ENTRIES)?;
        intent.validate()?;
        let baseline = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        let expected = baseline
            .entries
            .values()
            .find(|entry| entry.path == intent.requested_path);
        if expected != intent.requested_baseline.as_ref()
            || baseline.entries.contains_key(&intent.entry_id)
        {
            return Err(JournalError::Invariant(
                "publication baseline/identity mismatch",
            ));
        }
        if let Some(root) = &intent.source_snapshot {
            let source = self.snapshot(&intent.space_id, root)?;
            if !source
                .entries
                .values()
                .any(|entry| entry.content.as_ref() == Some(&intent.content))
            {
                return Err(JournalError::Invariant(
                    "restore content is not in source snapshot",
                ));
            }
        }
        if intent.requested_baseline.is_some() && intent.target_path == intent.requested_path {
            return Err(JournalError::Invariant(
                "publication must not target an occupied baseline path",
            ));
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("publication resource limit"));
        }
        let tx = self.connection.transaction()?;
        let root: String = tx.query_row(
            "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
            [intent.space_id.as_str()],
            |r| r.get(0),
        )?;
        if root != intent.baseline_root.as_str() {
            return Err(JournalError::Invariant("publication baseline changed"));
        }
        tx.execute(
            "INSERT INTO publications VALUES (?1,?2,?3,?4,'preparing',NULL,0)",
            params![
                intent.transaction_id.as_str(),
                intent.space_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str()
            ],
        )?;
        for chunk in &intent.content.chunks {
            tx.execute(
                "INSERT OR IGNORE INTO publication_objects VALUES (?1,?2)",
                params![intent.transaction_id.as_str(), chunk.content_id.as_str()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn advance_publication(
        &mut self,
        id: &EntryId,
        expected: PublicationState,
        next: PublicationState,
    ) -> Result<()> {
        if self.publication(id)?.intent.completion.is_some() {
            return self.advance_admitted_publication(id, expected, next);
        }
        if !matches!(
            (expected, next),
            (PublicationState::Preparing, PublicationState::Ready)
                | (PublicationState::Ready, PublicationState::Published)
        ) {
            return Err(JournalError::Invariant("illegal publication transition"));
        }
        if self.connection.execute(
            "UPDATE publications SET state=?1 WHERE transaction_id=?2 AND state=?3",
            params![next.as_str(), id.as_str(), expected.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant("publication stage changed"));
        }
        Ok(())
    }

    pub fn retarget_publication(&mut self, id: &EntryId, path: PortablePath) -> Result<()> {
        if self.publication(id)?.intent.completion.is_some() {
            return self.retarget_admitted_publication(id, path);
        }
        let publication = self.publication(id)?;
        if publication.state == PublicationState::Committed
            || path == publication.intent.target_path
            || path == publication.intent.requested_path
        {
            return Err(JournalError::Invariant(
                "cannot retarget committed or unchanged publication",
            ));
        }
        let mut intent = publication.intent;
        intent.target_path = path;
        intent.attempt += 1;
        intent.validate()?;
        let json = serde_json::to_string(&intent)?;
        if self.connection.execute(
            "UPDATE publications SET intent=?1,intent_hash=?2,state='preparing'
             WHERE transaction_id=?3 AND state=?4",
            params![
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                id.as_str(),
                publication.state.as_str()
            ],
        )? != 1
        {
            return Err(JournalError::Invariant("publication stage changed"));
        }
        Ok(())
    }

    pub fn mark_publication_cleaned(&mut self, id: &EntryId) -> Result<()> {
        if self.publication(id)?.intent.completion.is_some() {
            return self.clean_admitted_publication(id);
        }
        if self.connection.execute(
            "UPDATE publications SET cleaned=1 WHERE transaction_id=?1 AND state='committed'",
            [id.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "cannot clean uncommitted publication",
            ));
        }
        Ok(())
    }

    pub fn mutation(&self, id: &EntryId) -> Result<Mutation> {
        self.read_view().mutation(id)
    }

    pub fn mutations(&self, space: &SpaceId) -> Result<Vec<Mutation>> {
        self.read_view().mutations(space)
    }

    pub fn outstanding_mutations(&self, space: &SpaceId) -> Result<Vec<Mutation>> {
        let mut statement = self.connection.prepare(
            "SELECT transaction_id FROM mutations WHERE space_id=?1 AND state IN ('prepared','executing','quarantined','moved','replaced')",
        )?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| self.mutation(&id.parse()?))
            .collect()
    }

    pub fn verify_mutation_references(&self, id: &EntryId) -> Result<()> {
        self.read_view().verify_mutation_references(id)
    }

    pub fn begin_mutation(&mut self, intent: &MutationIntent) -> Result<()> {
        self.require_no_tree_restore(&intent.space_id, limits::MAX_ENTRIES)?;
        intent.validate()?;
        let baseline = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        if baseline.entries.get(&intent.baseline_entry.entry_id) != Some(&intent.baseline_entry) {
            return Err(JournalError::Invariant("mutation baseline entry mismatch"));
        }
        if let MutationAction::Move { destination, .. } = &intent.action {
            if baseline
                .entries
                .values()
                .any(|entry| entry.path.collision_key() == destination.collision_key())
            {
                return Err(JournalError::Invariant(
                    "mutation move destination occupied",
                ));
            }
            // Reject noncanonical/missing indexed parents before any OS rename.
            let mut moved = baseline.clone();
            moved
                .entries
                .get_mut(&intent.baseline_entry.entry_id)
                .ok_or(JournalError::Invariant("missing move baseline entry"))?
                .path = destination.clone();
            moved.validate()?;
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("mutation resource limit"));
        }
        let tx = self.connection.transaction()?;
        let root: String = tx.query_row(
            "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
            [intent.space_id.as_str()],
            |r| r.get(0),
        )?;
        if root != intent.baseline_root.as_str() {
            return Err(JournalError::Invariant("mutation baseline changed"));
        }
        tx.execute(
            "INSERT INTO mutations (transaction_id,space_id,baseline_root,intent,intent_hash,state) VALUES (?1,?2,?3,?4,?5,'prepared')",
            params![
                intent.transaction_id.as_str(),
                intent.space_id.as_str(),
                intent.baseline_root.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str()
            ],
        )?;
        for content in std::iter::once(
            intent
                .baseline_entry
                .content
                .as_ref()
                .ok_or(JournalError::Invariant("mutation baseline content missing"))?,
        )
        .chain(match &intent.action {
            MutationAction::Replace { content } => Some(content),
            _ => None,
        }) {
            for chunk in &content.chunks {
                tx.execute(
                    "INSERT OR IGNORE INTO mutation_objects VALUES (?1,?2)",
                    params![intent.transaction_id.as_str(), chunk.content_id.as_str()],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn cancel_mutation(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        let mutation = self.mutation(id)?;
        if mutation.intent.space_id != *space {
            return Err(JournalError::Invariant("mutation belongs to another space"));
        }
        if mutation.state == MutationState::Cancelled {
            return Ok(());
        }
        let tx = self.connection.transaction()?;
        if tx.execute(
            "UPDATE mutations SET state='cancelled' WHERE transaction_id=?1 AND state='prepared'",
            [id.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant("mutation state changed"));
        }
        tx.execute(
            "DELETE FROM mutation_objects WHERE transaction_id=?1",
            [id.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn start_delete(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        execution: &DeleteExecution,
    ) -> Result<()> {
        self.start_file_mutation(space, id, execution, "delete")
    }

    pub fn start_move(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        execution: &MutationExecution,
    ) -> Result<()> {
        self.start_file_mutation(space, id, execution, "move")
    }

    pub fn start_replace(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        execution: &MutationExecution,
    ) -> Result<()> {
        self.start_file_mutation(space, id, execution, "replace")
    }

    fn start_file_mutation(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        execution: &MutationExecution,
        action: &str,
    ) -> Result<()> {
        let mutation = self.mutation(id)?;
        self.verify_mutation_references(id)?;
        if mutation.intent.space_id != *space
            || mutation.state != MutationState::Prepared
            || !matches!(
                (action, &mutation.intent.action),
                ("delete", MutationAction::Delete)
                    | ("move", MutationAction::Move { .. })
                    | ("replace", MutationAction::Replace { .. })
            )
            || execution.payload_identity.is_some() != (action == "replace")
        {
            return Err(JournalError::Invariant(
                "only a matching prepared file mutation can execute",
            ));
        }
        if let MutationAction::Move { destination, .. } = &mutation.intent.action {
            let mut baseline = self.snapshot(space, &mutation.intent.baseline_root)?;
            baseline
                .entries
                .get_mut(&mutation.intent.baseline_entry.entry_id)
                .ok_or(JournalError::Invariant("missing move baseline entry"))?
                .path = destination.clone();
            baseline.validate()?;
        }
        let json = serde_json::to_string(execution)?;
        let tx = self.connection.transaction()?;
        let root: String = tx.query_row(
            "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
            [space.as_str()],
            |r| r.get(0),
        )?;
        if root != mutation.intent.baseline_root.as_str() {
            return Err(JournalError::Invariant("mutation baseline changed"));
        }
        if tx.execute(
            "UPDATE mutations SET state='executing',execution=?1,execution_hash=?2 WHERE transaction_id=?3 AND state='prepared'",
            params![json, ContentId::hash(json.as_bytes()).as_str(), id.as_str()],
        )? != 1 {
            return Err(JournalError::Invariant("mutation state changed"));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn mark_delete_quarantined(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        self.mark_file_mutated(space, id, false)
    }

    pub fn mark_move_moved(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        self.mark_file_mutated(space, id, true)
    }

    pub fn mark_replace_quarantined(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        self.mark_replace_phase(
            space,
            id,
            MutationState::Executing,
            "executing",
            "quarantined",
        )
    }

    pub fn mark_replace_replaced(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        self.mark_replace_phase(
            space,
            id,
            MutationState::Quarantined,
            "quarantined",
            "replaced",
        )
    }

    fn mark_replace_phase(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        expected: MutationState,
        from: &str,
        to: &str,
    ) -> Result<()> {
        let mutation = self.mutation(id)?;
        self.verify_mutation_references(id)?;
        if mutation.intent.space_id != *space
            || mutation.state != expected
            || !matches!(mutation.intent.action, MutationAction::Replace { .. })
        {
            return Err(JournalError::Invariant("invalid Replace transition"));
        }
        if self.connection.execute(
            "UPDATE mutations SET state=?1 WHERE transaction_id=?2 AND state=?3",
            params![to, id.as_str(), from],
        )? != 1
        {
            return Err(JournalError::Invariant("mutation state changed"));
        }
        Ok(())
    }

    fn mark_file_mutated(&mut self, space: &SpaceId, id: &EntryId, moving: bool) -> Result<()> {
        let mutation = self.mutation(id)?;
        if mutation.intent.space_id != *space
            || mutation.state != MutationState::Executing
            || if moving {
                !matches!(mutation.intent.action, MutationAction::Move { .. })
            } else {
                mutation.intent.action != MutationAction::Delete
            }
        {
            return Err(JournalError::Invariant(
                "matching file mutation is not executing",
            ));
        }
        if self.connection.execute(
            "UPDATE mutations SET state=?1 WHERE transaction_id=?2 AND state='executing'",
            params![if moving { "moved" } else { "quarantined" }, id.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant("mutation state changed"));
        }
        Ok(())
    }

    pub fn protected_objects(&self) -> Result<Vec<ContentId>> {
        let mut statement = self.connection.prepare(
            "SELECT content_id FROM publication_objects UNION SELECT content_id FROM snapshot_objects
             UNION SELECT content_id FROM mutation_objects
             UNION SELECT content_id FROM read_lease_objects
             UNION SELECT content_id FROM reference_reservation_objects
             UNION SELECT content_id FROM tree_restore_objects
             UNION SELECT content_id FROM tree_restore_original_objects ORDER BY content_id",
        )?;
        let ids: Vec<String> = statement
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter().map(|id| Ok(id.parse()?)).collect()
    }

    pub fn check_storage_metadata_limit(&self, max_entries: usize) -> Result<()> {
        check_storage_metadata_limit(&self.connection, max_entries, 0, 0)
    }

    pub fn cursor(&self, space: &SpaceId, device: &DeviceId) -> Result<u64> {
        cursor(&self.connection, space, device)
    }

    // Trusted local transport only. Authentication must precede this API in M2.
    pub fn receive(&mut self, op: &Operation) -> Result<ReceiveOutcome> {
        op.validate()?;
        let json = serde_json::to_string(op)?;
        if json.len() > MAX_OPERATION_BYTES || op.payload.origin_seq > i64::MAX as u64 {
            return Err(JournalError::Invariant("operation resource limit"));
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx =
            Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let view = self.read_view();
        let before = view.audit_receive_capacity(&op.payload.space_id, bounds)?;
        storage_policy::receive::tree_gate(&before)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT payload FROM operations WHERE op_id=?1",
                [op.op_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            if existing != json {
                return Err(JournalError::Invariant("operation ID collision"));
            }
            tx.commit()?;
            return Ok(ReceiveOutcome::Duplicate);
        }
        storage_policy::receive::completion_gate(&before)?;
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM operations WHERE state='pending'",
            [],
            |r| r.get(0),
        )?;
        if pending >= MAX_PENDING_OPS as i64 {
            return Err(JournalError::Invariant("pending queue full"));
        }
        let projection = storage_policy::receive::project(&before, op, &json)?;
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2,?3,?4,?5,'pending')",
            params![
                op.op_id.as_str(),
                op.payload.space_id.as_str(),
                op.payload.origin_device_id.as_str(),
                sql_integer(op.payload.origin_seq)?,
                json
            ],
        )?;
        promote_pending(&tx, &projection)?;
        let state: String = tx.query_row(
            "SELECT state FROM operations WHERE op_id=?1",
            [op.op_id.as_str()],
            |r| r.get(0),
        )?;
        let after = view.audit_receive_capacity(&op.payload.space_id, bounds)?;
        let outcome = projection.receipt(&before, &after, op, &json, &state)?;
        tx.commit()?;
        Ok(outcome)
    }

    pub fn commit_local(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        self.commit_local_admitted(expected_root, manifest, operations, timestamp, None)
    }

    /// Commit optional local observations atomically with the exact visible tree.
    /// The caller establishes native evidence; this does not enable scan inference.
    pub fn commit_local_with_observations(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: &persisted_rename::RenameObservationMap,
        max_entries: usize,
    ) -> Result<SnapshotId> {
        self.commit_local_admitted(
            expected_root,
            manifest,
            operations,
            timestamp,
            Some((observations, max_entries)),
        )
    }

    pub fn commit_publication(
        &mut self,
        id: &EntryId,
        expected_root: &SnapshotId,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        if self.publication(id)?.intent.completion.is_some() {
            return self.commit_admitted_publication(
                id,
                expected_root,
                manifest,
                operations,
                timestamp,
            );
        }
        let publication = self.publication(id)?;
        let intent = &publication.intent;
        if publication.state != PublicationState::Published
            || intent.space_id != manifest.space_id
            || manifest.entries.get(&intent.entry_id).is_none_or(|entry| {
                entry.path != intent.target_path || entry.content.as_ref() != Some(&intent.content)
            })
            || !operations.iter().any(|op| {
                matches!(&op.payload.change, Change::Put { entry }
                if entry.entry_id == intent.entry_id && entry.path == intent.target_path
                    && entry.content.as_ref() == Some(&intent.content))
            })
        {
            return Err(JournalError::Invariant(
                "publication completion does not contain intended content",
            ));
        }
        self.commit_local_inner(
            Some(expected_root),
            manifest,
            operations,
            timestamp,
            Completion::Publication(id),
        )
    }

    pub fn commit_delete(
        &mut self,
        id: &EntryId,
        manifest: &Manifest,
        operation: &Operation,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let mutation = self.mutation(id)?;
        self.verify_mutation_references(id)?;
        let intent = &mutation.intent;
        if mutation.state != MutationState::Quarantined
            || intent.action != MutationAction::Delete
            || operation.payload.space_id != intent.space_id
            || operation.payload.change
                != (Change::Delete {
                    entry_id: intent.baseline_entry.entry_id.clone(),
                })
        {
            return Err(JournalError::Invariant("invalid delete completion"));
        }
        let mut expected = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        expected.entries.remove(&intent.baseline_entry.entry_id);
        expected.tombstones.insert(
            intent.baseline_entry.entry_id.clone(),
            operation.op_id.clone(),
        );
        expected.version_vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if &expected != manifest {
            return Err(JournalError::Invariant(
                "delete completion changed unrelated baseline entries",
            ));
        }
        self.commit_local_inner(
            Some(&intent.baseline_root),
            manifest,
            std::slice::from_ref(operation),
            timestamp,
            Completion::Mutation(id),
        )
    }

    pub fn commit_move(
        &mut self,
        id: &EntryId,
        manifest: &Manifest,
        operation: &Operation,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let mutation = self.mutation(id)?;
        self.verify_mutation_references(id)?;
        let intent = &mutation.intent;
        let MutationAction::Move { destination, .. } = &intent.action else {
            return Err(JournalError::Invariant(
                "move completion requires Move action",
            ));
        };
        if mutation.state != MutationState::Moved
            || operation.payload.space_id != intent.space_id
            || operation.payload.change
                != (Change::Rename {
                    entry_id: intent.baseline_entry.entry_id.clone(),
                    path: destination.clone(),
                })
        {
            return Err(JournalError::Invariant("invalid move completion"));
        }
        let mut expected = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        expected
            .entries
            .get_mut(&intent.baseline_entry.entry_id)
            .ok_or(JournalError::Invariant("missing move baseline entry"))?
            .path = destination.clone();
        expected.version_vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if &expected != manifest {
            return Err(JournalError::Invariant(
                "move completion changed unrelated baseline entries",
            ));
        }
        self.commit_local_inner(
            Some(&intent.baseline_root),
            manifest,
            std::slice::from_ref(operation),
            timestamp,
            Completion::Mutation(id),
        )
    }

    pub fn commit_replace(
        &mut self,
        id: &EntryId,
        manifest: &Manifest,
        operation: &Operation,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let mutation = self.mutation(id)?;
        self.verify_mutation_references(id)?;
        let intent = &mutation.intent;
        let MutationAction::Replace { content } = &intent.action else {
            return Err(JournalError::Invariant(
                "replace completion requires Replace action",
            ));
        };
        let mut entry = intent.baseline_entry.clone();
        entry.content = Some(content.clone());
        if mutation.state != MutationState::Replaced
            || operation.payload.space_id != intent.space_id
            || operation.payload.change
                != (Change::Put {
                    entry: entry.clone(),
                })
        {
            return Err(JournalError::Invariant("invalid replace completion"));
        }
        let mut expected = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        expected.entries.insert(entry.entry_id.clone(), entry);
        expected.version_vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if &expected != manifest {
            return Err(JournalError::Invariant(
                "replace completion changed unrelated baseline entries",
            ));
        }
        self.commit_local_inner(
            Some(&intent.baseline_root),
            manifest,
            std::slice::from_ref(operation),
            timestamp,
            Completion::Mutation(id),
        )
    }

    fn commit_local_admitted(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: Option<(&persisted_rename::RenameObservationMap, usize)>,
    ) -> Result<SnapshotId> {
        sql_integer(timestamp)?;
        manifest.validate()?;
        if operations.len() > limits::MAX_ENTRIES {
            return Err(JournalError::Invariant(
                "local commit operation count limit",
            ));
        }
        let bounds = match observations {
            Some((_, max)) => self.writer_capacity_limits(max)?,
            None => storage_policy::capacity_limits(self.max_storage_entries)?,
        };
        let mut chunk_visits = 0usize;
        for content in manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            chunk_visits = chunk_visits
                .checked_add(content.chunks.len())
                .ok_or(JournalError::Invariant("local commit chunk count overflow"))?;
            if chunk_visits > limits::MAX_CHUNKS {
                return Err(JournalError::Invariant("local commit chunk count limit"));
            }
        }
        let snapshot_json = serde_json::to_string(manifest)?;
        if snapshot_json.len() > MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("local commit snapshot byte limit"));
        }
        let mut operation_json = Vec::new();
        let mut input_bytes = snapshot_json.len() as u64;
        for op in operations {
            op.validate()?;
            sql_integer(op.payload.origin_seq)?;
            let json = serde_json::to_string(op)?;
            if json.len() > MAX_OPERATION_BYTES {
                return Err(JournalError::Invariant("local commit operation byte limit"));
            }
            input_bytes = input_bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant("local commit input byte overflow"))?;
            if input_bytes > limits::MAX_ENTRIES as u64 * 1024 {
                return Err(JournalError::Invariant(
                    "local commit aggregate input byte limit",
                ));
            }
            operation_json.push(json);
        }
        let observation_bytes = observations
            .map(|(map, max)| {
                map.validate(manifest, max)?;
                rename_observation::serialize_observation(map)
            })
            .transpose()?;
        let observation_json = observation_bytes
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| JournalError::Invariant("rename observation serialization"))?;
        let tx =
            Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let view = self.read_view();
        let before = view.audit_local_commit_capacity(&manifest.space_id, bounds)?;
        if observations.is_some() && view.state("worktree")?.is_none() {
            return Err(JournalError::Invariant(
                "observed commit requires initialized worktree",
            ));
        }
        let projection = storage_policy::local_commit::project(
            &before,
            storage_policy::local_commit::Input {
                expected_root,
                manifest,
                operations,
                operation_json: &operation_json,
                snapshot_json: &snapshot_json,
                timestamp,
                observation_json,
            },
        )?;
        let root = self.commit_history_sql(
            &tx,
            expected_root,
            manifest,
            operations,
            timestamp,
            Completion::None,
        )?;
        if let Some((map, max)) = observations {
            let json = observation_json
                .ok_or(JournalError::Invariant("local observation bytes missing"))?;
            tx.execute(
                "INSERT INTO rename_observations VALUES (?1,?2,?3,?4)",
                params![
                    map.scope.space_id.as_str(),
                    root.as_str(),
                    json,
                    ContentId::hash(json.as_bytes()).as_str()
                ],
            )?;
            rename_observation::audit_observation(&tx, &manifest.space_id, max)?;
        }
        let after = view.audit_local_commit_capacity(&manifest.space_id, bounds)?;
        projection.receipt(&after)?;
        tx.commit()?;
        Ok(root)
    }

    fn commit_local_inner(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        completion: Completion<'_>,
    ) -> Result<SnapshotId> {
        // Mandatory after-native completions retain their separate legacy contract.
        self.require_no_tree_restore(&manifest.space_id, limits::MAX_ENTRIES)?;
        sql_integer(timestamp)?;
        manifest.validate()?;
        self.require_unpruned_root(&manifest.root()?)?;
        let tx =
            Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Deferred)?;
        let root = self.commit_history_sql(
            &tx,
            expected_root,
            manifest,
            operations,
            timestamp,
            completion,
        )?;
        tx.commit()?;
        Ok(root)
    }

    fn commit_history_sql(
        &self,
        tx: &Transaction<'_>,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        completion: Completion<'_>,
    ) -> Result<SnapshotId> {
        let root = manifest.root()?;
        rename_observation::audit_observation(tx, &manifest.space_id, limits::MAX_ENTRIES)?;
        let mutation_active: Option<String> = tx.query_row(
            "SELECT transaction_id FROM mutations WHERE space_id=?1 AND state IN ('prepared','executing','quarantined','moved','replaced')",
            [manifest.space_id.as_str()], |r| r.get(0),
        ).optional()?;
        let mutation = match completion {
            Completion::Mutation(id) => Some(id),
            _ => None,
        };
        let publication = match completion {
            Completion::Publication(id) => Some(id),
            #[cfg(windows)]
            Completion::NativePublication(id) => Some(id),
            _ => None,
        };
        if mutation_active.as_deref() != mutation.map(EntryId::as_str) {
            return Err(JournalError::Invariant(
                "active mutation must be resolved first",
            ));
        }
        let active: Option<String> = tx.query_row(
            "SELECT transaction_id FROM publications WHERE space_id=?1 AND (state!='committed' OR cleaned=0)",
            [manifest.space_id.as_str()], |r| r.get(0),
        ).optional()?;
        if active.as_deref() != publication.map(EntryId::as_str) {
            return Err(JournalError::Invariant(
                "outstanding publication must be recovered first",
            ));
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
                [manifest.space_id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if existing.as_deref() != expected_root.map(SnapshotId::as_str) {
            return Err(JournalError::Invariant("manifest baseline changed"));
        }
        let previous_json: Option<String> = tx
            .query_row(
                "SELECT manifest FROM snapshots WHERE snapshot_id=?1",
                [existing.as_deref().unwrap_or("")],
                |r| r.get(0),
            )
            .optional()?;
        let mut expected_vector = match previous_json {
            Some(json) => serde_json::from_str::<Manifest>(&json)?.version_vector,
            None => VersionVector::default(),
        };
        for op in operations {
            op.validate()?;
            let p = &op.payload;
            if p.space_id != manifest.space_id
                || p.causal != expected_vector
                || p.origin_seq != cursor(tx, &p.space_id, &p.origin_device_id)? + 1
            {
                return Err(JournalError::Invariant("local sequence discontinuity"));
            }
            for (device, seq) in &p.causal.0 {
                if cursor(tx, &p.space_id, device)? < *seq {
                    return Err(JournalError::Invariant("missing causal dependency"));
                }
            }
            tx.execute(
                "INSERT INTO operations VALUES (?1,?2,?3,?4,?5,'materialized')",
                params![
                    op.op_id.as_str(),
                    p.space_id.as_str(),
                    p.origin_device_id.as_str(),
                    sql_integer(p.origin_seq)?,
                    serde_json::to_string(op)?
                ],
            )?;
            set_cursor(tx, &p.space_id, &p.origin_device_id, p.origin_seq)?;
            expected_vector.observe(p.origin_device_id.clone(), p.origin_seq);
        }
        if manifest.version_vector != expected_vector {
            return Err(JournalError::Invariant(
                "manifest vector does not match committed operations",
            ));
        }
        let json = serde_json::to_string(manifest)?;
        let stored: Option<(String, String, String)> = tx
            .query_row(
                "SELECT space_id,
                    CASE WHEN length(CAST(manifest AS BLOB))<=16777216 THEN manifest ELSE '' END,
                    state FROM snapshots WHERE snapshot_id=?1",
                [root.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((space, old, state)) = stored {
            if space != manifest.space_id.as_str() || old != json || state != "materialized" {
                return Err(JournalError::Invariant(
                    "existing snapshot differs from local commit",
                ));
            }
        } else {
            tx.execute(
                "INSERT INTO snapshots VALUES (?1,?2,?3,?4,'materialized',0)",
                params![
                    root.as_str(),
                    manifest.space_id.as_str(),
                    json,
                    sql_integer(timestamp)?
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO current_manifests VALUES (?1,?2)
             ON CONFLICT(space_id) DO UPDATE SET snapshot_id=excluded.snapshot_id",
            params![manifest.space_id.as_str(), root.as_str()],
        )?;
        pin_snapshot(tx, root.as_str(), manifest)?;
        if let Some(id) = publication {
            #[cfg(windows)]
            let native = matches!(completion, Completion::NativePublication(_));
            #[cfg(not(windows))]
            let native = false;
            let changed = if native {
                tx.execute(
                    "UPDATE publications SET state='committed',committed_snapshot=?1
                     WHERE transaction_id=?2 AND state='preparing'",
                    params![root.as_str(), id.as_str()],
                )?
            } else {
                tx.execute(
                    "UPDATE publications SET state='committed',committed_snapshot=?1
                 WHERE transaction_id=?2 AND state='published'",
                    params![root.as_str(), id.as_str()],
                )?
            };
            if changed != 1 {
                return Err(JournalError::Invariant(
                    "publication changed before completion",
                ));
            }
            tx.execute(
                "DELETE FROM publication_objects WHERE transaction_id=?1",
                [id.as_str()],
            )?;
        }
        if let Some(id) = mutation {
            if tx.execute(
                "UPDATE mutations SET state='committed',committed_snapshot=?1 WHERE transaction_id=?2 AND state IN ('quarantined','moved','replaced')",
                params![root.as_str(), id.as_str()],
            )? != 1 {
                return Err(JournalError::Invariant("mutation changed before completion"));
            }
            tx.execute(
                "DELETE FROM mutation_objects WHERE transaction_id=?1",
                [id.as_str()],
            )?;
        }
        Ok(root)
    }

    pub fn integrity_check(&self) -> Result<()> {
        let result: String = self
            .connection
            .pragma_query_value(None, "integrity_check", |r| r.get(0))?;
        if result != "ok" {
            return Err(JournalError::Invariant("SQLite integrity check failed"));
        }
        let mut foreign_keys = self.connection.prepare("PRAGMA foreign_key_check")?;
        if foreign_keys.query([])?.next()?.is_some() {
            return Err(JournalError::Invariant("SQLite foreign key check failed"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Completion<'a> {
    None,
    Publication(&'a EntryId),
    #[cfg(windows)]
    NativePublication(&'a EntryId),
    Mutation(&'a EntryId),
}

fn check_storage_metadata_limit(
    connection: &Connection,
    max_entries: usize,
    additional_rows: u64,
    additional_bytes: u64,
) -> Result<()> {
    let (rows, bytes) = storage_metadata_budget_usage(connection)?;
    let max_bytes = (max_entries as u64)
        .checked_mul(1024)
        .ok_or(JournalError::Invariant("storage metadata budget overflow"))?;
    if rows
        .checked_add(additional_rows)
        .is_none_or(|n| n > max_entries as u64)
        || bytes
            .checked_add(additional_bytes)
            .is_none_or(|n| n > max_bytes)
    {
        return Err(JournalError::Invariant("storage metadata inventory limit"));
    }
    Ok(())
}

// Legacy admission accounting includes reservations, not just persisted values.
fn storage_metadata_budget_usage(connection: &Connection) -> Result<(u64, u64)> {
    let (rows, bytes): (i64, i64) = connection.query_row(
        "SELECT
            (SELECT count(*) FROM snapshots) + (SELECT count(*) FROM mutations)
            + (SELECT count(*) FROM publications) + (SELECT count(*) FROM snapshot_objects)
            + (SELECT count(*) FROM mutation_objects) + (SELECT count(*) FROM publication_objects)
            + (SELECT count(*) FROM cleanup_plans) + (SELECT count(*) FROM read_leases)
            + (SELECT count(*) FROM read_lease_objects) + (SELECT count(*) FROM snapshot_prunings)
            + (SELECT 2*count(*) FROM gc_marks) + (SELECT count(*) FROM gc_cancellations)
            + (SELECT count(*) FROM gc_clock) + (SELECT count(*) FROM gc_authorizations)
            + (SELECT count(*) FROM gc_revocations) + (SELECT 2*count(*) FROM gc_executions)
            + (SELECT count(*) FROM gc_quarantines) + (SELECT 2*count(*) FROM gc_disposals)
            + (SELECT count(*) FROM reference_reservations)
            + max((SELECT count(*) FROM reference_reservations),
                (SELECT count(*) FROM reference_snapshot_handoffs))
            + (SELECT count(*) FROM reference_reservation_objects)
            + (SELECT count(*) FROM rename_observations)
            + (SELECT count(*) FROM original_disposals)
            + max((SELECT count(*) FROM original_disposals),
                (SELECT count(*) FROM original_disposal_completions))
            + (SELECT count(*) FROM operations) + (SELECT count(*) FROM receive_cursors)
            + (SELECT count(*) FROM current_manifests)
            + (SELECT count(*) FROM tree_restore_native_reservations)
            + (SELECT count(*) FROM tree_restore_execution_intents)
            + (SELECT count(*) FROM tree_restore_execution_step_intents)
            + (SELECT count(*) FROM tree_restore_execution_records)
            + (SELECT count(*) FROM tree_restore_owner_intents)
            + (SELECT count(*) FROM tree_restore_owner_records)
            + (SELECT count(*) FROM tree_restore_disposition_reservations)
            + (SELECT count(*) FROM tree_restore_disposition_intents)
            + (SELECT count(*) FROM tree_restore_disposition_records)
            + (SELECT count(*) FROM tree_restore_coordinator_admissions)
            + (SELECT count(*) FROM tree_restore_protocol_descriptions)
            + (SELECT count(*) FROM tree_restore_protocol_records)
            + (SELECT count(*) FROM tree_native_capacity_admissions)
            + (SELECT count(*) FROM tree_native_action_headers)
            + (SELECT count(*) FROM tree_native_action_records)
            + (SELECT count(*) FROM tree_native_future_admissions)
            + (SELECT count(*) FROM tree_native_future_generations)
            + (SELECT coalesce(sum(future_rows),0) FROM tree_native_future_admissions)
            + (SELECT count(*) FROM tree_restore_final_descriptions)
            + (SELECT count(*) FROM tree_restore_retained_descriptions)
            + max((SELECT coalesce(sum(reserved_rows),0) FROM tree_restore_original_reservations),
                (SELECT count(*) FROM tree_restore_original_reservations)
                + (SELECT count(*) FROM tree_restore_original_owners)
                + (SELECT count(*) FROM tree_restore_original_objects))
            + max((SELECT coalesce(sum(reserved_rows),0) FROM tree_restore_histories),
                (SELECT count(*) FROM tree_restore_histories))
            + max((SELECT coalesce(sum(reserved_rows),0) FROM tree_restore_preparations),
                (SELECT count(*) FROM tree_restore_preparations)
                + (SELECT 3*count(*) FROM tree_restore_steps)
                + (SELECT count(*) FROM tree_restore_objects)
                + (SELECT count(*) FROM tree_restore_cancellations)),
            (SELECT coalesce(sum(length(CAST(manifest AS BLOB))),0) FROM snapshots)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))
                + coalesce(length(CAST(execution AS BLOB)),0)),0) FROM mutations)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM publications)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM cleanup_plans)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM read_leases)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM snapshot_prunings)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM gc_marks)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM gc_authorizations)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM gc_executions)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM gc_quarantines)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM gc_disposals)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+4096),0)
                FROM reference_reservations)
            + (SELECT coalesce(sum(length(CAST(observation AS BLOB))),0)
                FROM rename_observations)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+4096),0)
                FROM original_disposals)
            + (SELECT coalesce(sum(length(CAST(payload AS BLOB))+180),0) FROM operations)
            + (SELECT 104*count(*) FROM receive_cursors)
            + (SELECT 96*count(*) FROM current_manifests)
            + (SELECT 124*count(*) FROM snapshots)
            + (SELECT 128*count(*) FROM snapshot_objects)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+384),0)
                FROM tree_restore_native_reservations)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+480),0)
                FROM tree_restore_execution_intents)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+168),0)
                FROM tree_restore_execution_step_intents)
            + (SELECT coalesce(sum(length(CAST(record AS BLOB))+312),0)
                FROM tree_restore_execution_records)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+400),0)
                FROM tree_restore_owner_intents)
            + (SELECT coalesce(sum(length(CAST(record AS BLOB))+272),0)
                FROM tree_restore_owner_records)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+288),0)
                FROM tree_restore_disposition_reservations)
            + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+336),0)
                FROM tree_restore_disposition_intents)
            + (SELECT coalesce(sum(length(CAST(record AS BLOB))+312),0)
                FROM tree_restore_disposition_records)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+552),0)
                FROM tree_restore_coordinator_admissions)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+232),0)
                FROM tree_restore_protocol_descriptions)
            + (SELECT coalesce(sum(length(CAST(record AS BLOB))+368),0)
                FROM tree_restore_protocol_records)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+length(CAST(capacity AS BLOB))+576),0)
                FROM tree_native_capacity_admissions)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+456),0)
                FROM tree_native_action_headers)
            + (SELECT coalesce(sum(length(CAST(record AS BLOB))+472),0)
                FROM tree_native_action_records)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+length(CAST(capacity AS BLOB))+752+future_bytes),0)
                FROM tree_native_future_admissions)
            + (SELECT coalesce(sum(136+length(CAST(purpose AS BLOB))),0)
                FROM tree_native_future_generations)
            + (SELECT coalesce(sum(length(CAST(request AS BLOB))+length(CAST(intent AS BLOB))+696),0)
                FROM tree_restore_final_descriptions)
            + (SELECT coalesce(sum(length(CAST(description AS BLOB))+488),0)
                FROM tree_restore_retained_descriptions)
            + max((SELECT coalesce(sum(reserved_bytes),0) FROM tree_restore_original_reservations),
                (SELECT coalesce(sum(length(CAST(request AS BLOB))+304),0)
                    FROM tree_restore_original_reservations)
                + (SELECT coalesce(sum(length(CAST(intent AS BLOB))+264),0)
                    FROM tree_restore_original_owners)
                + (SELECT 144*count(*) FROM tree_restore_original_objects))
            + max((SELECT coalesce(sum(reserved_bytes),0) FROM tree_restore_histories),
                (SELECT coalesce(sum(length(CAST(intent AS BLOB))+392),0) FROM tree_restore_histories))
            + max((SELECT coalesce(sum(reserved_bytes),0) FROM tree_restore_preparations),
                (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0)
                    FROM tree_restore_preparations)
                + max((SELECT 4096*count(*) FROM tree_restore_preparations),
                    (SELECT coalesce(sum(length(CAST(intent_hash AS BLOB))),0)
                        FROM tree_restore_cancellations))
                + (SELECT coalesce(sum(length(CAST(step AS BLOB))+4096),0) FROM tree_restore_steps)
                + (SELECT coalesce(sum(length(CAST(content_id AS BLOB))+64),0) FROM tree_restore_objects))",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if rows < 0 || bytes < 0 {
        return Err(JournalError::Invariant("storage metadata inventory limit"));
    }
    let specs = native_publication::schema::TABLES;
    let tables = storage_inventory::reader::preflight(
        connection,
        specs,
        sync_extend_core_model::limits::MAX_ENTRIES,
        sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let actual_rows: u64 = tables
        .iter()
        .filter(|table| table.table == "native_publication_headers")
        .map(|table| table.rows)
        .sum();
    let actual_bytes: u64 = tables
        .iter()
        .filter(|table| table.table == "native_publication_headers")
        .map(|table| table.logical_bytes)
        .sum();
    let (reserved_rows, reserved_bytes): (u64, u64) = connection.query_row(
        "SELECT coalesce(sum(reserved_rows),0),coalesce(sum(reserved_bytes),0) FROM native_publication_headers",
        [], |row| Ok((row.get::<_,i64>(0)? as u64, row.get::<_,i64>(1)? as u64)),
    )?;
    Ok((
        (rows as u64)
            .checked_add(actual_rows)
            .and_then(|n| n.checked_add(reserved_rows))
            .ok_or(JournalError::Invariant("native budget row overflow"))?,
        (bytes as u64)
            .checked_add(actual_bytes)
            .and_then(|n| n.checked_add(reserved_bytes))
            .ok_or(JournalError::Invariant("native budget byte overflow"))?,
    ))
}

fn pin_snapshot(tx: &Transaction<'_>, root: &str, manifest: &Manifest) -> Result<()> {
    for entry in manifest.entries.values() {
        if let Some(content) = &entry.content {
            for chunk in &content.chunks {
                tx.execute(
                    "INSERT OR IGNORE INTO snapshot_objects VALUES (?1,?2)",
                    params![root, chunk.content_id.as_str()],
                )?;
            }
        }
    }
    Ok(())
}

fn cursor(connection: &Connection, space: &SpaceId, device: &DeviceId) -> Result<u64> {
    let value: i64 = connection
        .query_row(
            "SELECT contiguous_seq FROM receive_cursors WHERE space_id=?1 AND device_id=?2",
            params![space.as_str(), device.as_str()],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(value).map_err(|_| JournalError::Invariant("negative sequence"))
}

fn set_cursor(tx: &Transaction<'_>, space: &SpaceId, device: &DeviceId, seq: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO receive_cursors VALUES (?1,?2,?3)
         ON CONFLICT(space_id,device_id) DO UPDATE SET contiguous_seq=excluded.contiguous_seq",
        params![space.as_str(), device.as_str(), sql_integer(seq)?],
    )?;
    Ok(())
}

fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| JournalError::Invariant("SQLite integer overflow"))
}

fn promote_pending(
    tx: &Transaction<'_>,
    projection: &storage_policy::receive::Projection,
) -> Result<()> {
    // The immutable prewrite plan bounds execution even if triggers undo progress.
    for step in projection.promotions() {
        if tx.execute(
            "UPDATE operations SET state='received' WHERE op_id=?1",
            [step.operation.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "projected pending operation changed",
            ));
        }
        set_cursor(tx, &step.space, &step.device, step.sequence)?;
    }
    Ok(())
}
mod publication;
pub use publication::{Publication, PublicationCompletion, PublicationIntent, PublicationState};
mod mutation;
pub use mutation::{
    DeleteExecution, Mutation, MutationAction, MutationExecution, MutationIntent, MutationState,
};
mod cleanup;
pub use cleanup::{CleanupIntent, CleanupPlan, CleanupState};
mod read_lease;
pub use read_lease::{read_lease_expiry, ReadLease, ReadLeaseIntent, ReadLeaseState};
mod snapshot_retention;
pub use snapshot_retention::RetainedSnapshot;
mod snapshot_pruning;
pub use snapshot_pruning::{SnapshotAudit, SnapshotPruning};
mod gc_mark;
pub use gc_mark::{gc_grace_until, GcCheck, GcMark, GcMarkAudit, GcObservation, GcState};
mod gc_authorization;
pub use gc_authorization::{
    gc_authorization_expiry, GcAuthorization, GcAuthorizationAudit, GcAuthorizationState,
    GcBoundary,
};
mod gc_execution;
pub use gc_execution::{GcExecutionAudit, GcExecutionIntent, GcExecutionState};
mod cas_access;
pub use cas_access::CasAccessGuard;
mod gc_quarantine;
pub use gc_quarantine::{GcQuarantineAudit, GcQuarantineIntent, GcQuarantineState};
mod gc_disposal;
pub use gc_disposal::{GcDisposalAudit, GcDisposalIntent, GcDisposalState, GcDisposalStep};
mod diagnostics;
pub use diagnostics::GcDiagnostics;
mod original_retention;
mod reference_reservation;
mod rename_observation;
mod storage_capacity;
mod storage_inventory;
mod tree_coordinator_admission;
mod tree_disposition_description;
mod tree_disposition_generations;
mod tree_execution_records;
mod tree_final_description;
mod tree_final_observation;
mod tree_native_future;
mod tree_native_protocol;
mod tree_native_storage;
mod tree_original_pins;
mod tree_owner_description;
mod tree_restore;
mod tree_restore_execution_intent;
mod tree_restore_history;
mod tree_restore_native_identity;
mod tree_storage_inventory;
pub use original_retention::{OriginalDisposalAudit, OriginalDisposalIntent, OriginalDisposalStep};
pub use reference_reservation::{
    ReferenceReservation, ReferenceReservationIntent, ReferenceSnapshotHandoff,
};
pub use storage_capacity::{
    JournalCapacityGap, JournalCapacityLimits, JournalCapacityObligation,
    JournalCapacityReservation, JournalCapacityRow, JournalStorageCapacity, JournalTreeCapacity,
};
pub use storage_inventory::{
    JournalStorageColumn, JournalStorageColumnValue, JournalStorageInventory, JournalStoredRow,
    JournalStoredTable,
};
pub use tree_coordinator_admission::{
    TreeCoordinatorAdmissionAudit, TreeCoordinatorAdmissionInspection,
    TreeCoordinatorAdmissionRequest,
};
pub use tree_disposition_description::{
    TreeDispositionDescriptionAudit, TreeDispositionDescriptionRequest,
};
pub use tree_execution_records::TreeExecutionRecordsAudit;
pub use tree_final_description::{TreeFinalDescriptionAudit, TreeFinalDescriptionRequest};
pub use tree_final_observation::{TreeFinalObservationInspection, TreeFinalObservationRequest};
pub use tree_native_future::{TreeNativeFutureAdmissionAudit, TreeNativeFutureAdmissionRequest};
pub use tree_native_protocol::{
    TreeNativeProtocolDescriptionAudit, TreeNativeProtocolDescriptionRequest,
};
pub use tree_native_storage::{TreeNativePrewriteAudit, TreeNativePrewriteRequest};
pub use tree_original_pins::{TreeOriginalPinRequest, TreeOriginalPinsAudit};
pub use tree_owner_description::TreeOwnerDescriptionAudit;
pub use tree_restore::{TreeRestorePreparation, TreeRestorePreparationIntent};
pub use tree_restore_execution_intent::TreeExecutionDescriptionAudit;
pub use tree_restore_history::{TreeRestoreHistoryIntent, TreeRestoreHistoryReservation};
pub use tree_restore_native_identity::{
    TreeRestoreNativeIntent, TreeRestoreNativeRequest, TreeRestoreNativeReservation,
};
pub use tree_storage_inventory::{
    TreeRestoreInventoryLimits, TreeRestoreLegacyBudget, TreeRestoreStorageInventory,
    TreeRestoreStoredOwner, TreeRestoreStoredReservation, TreeRestoreStoredRow,
    TreeRestoreStoredTable,
};

impl crate::JournalReadView<'_> {
    pub(crate) fn state(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub(crate) fn current(&self, space: &SpaceId) -> Result<Option<Manifest>> {
        let root: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
                [space.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(root) = &root {
            self.require_snapshot_retained(space, &root.parse()?)?;
        }
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT s.manifest FROM current_manifests c JOIN snapshots s USING(snapshot_id)
             WHERE c.space_id=?1",
                [space.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|json| {
            let manifest: Manifest = serde_json::from_str(&json)?;
            manifest.validate()?;
            if manifest.space_id != *space {
                return Err(JournalError::Invariant("current manifest space mismatch"));
            }
            let stored_root: String = self.connection.query_row(
                "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
                [space.as_str()],
                |r| r.get(0),
            )?;
            if manifest.root()?.as_str() != stored_root {
                return Err(JournalError::Invariant("current manifest root mismatch"));
            }
            Ok(manifest)
        })
        .transpose()
    }

    pub(crate) fn snapshot(&self, space: &SpaceId, root: &SnapshotId) -> Result<Manifest> {
        self.require_snapshot_retained(space, root)?;
        let json: String = self.connection.query_row(
            "SELECT manifest FROM snapshots WHERE space_id=?1 AND snapshot_id=?2",
            params![space.as_str(), root.as_str()],
            |r| r.get(0),
        )?;
        let manifest: Manifest = serde_json::from_str(&json)?;
        if manifest.space_id != *space || manifest.root()? != *root {
            return Err(JournalError::Invariant("snapshot integrity mismatch"));
        }
        Ok(manifest)
    }

    pub(crate) fn publication(&self, id: &EntryId) -> Result<Publication> {
        let (json, hash, state, root, cleaned): (String, String, String, Option<String>, bool) =
            self.connection.query_row(
                "SELECT intent,intent_hash,state,committed_snapshot,cleaned FROM publications WHERE transaction_id=?1",
                [id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        let intent: PublicationIntent = serde_json::from_str(&json)?;
        intent.validate()?;
        if ContentId::hash(json.as_bytes()).as_str() != hash || intent.transaction_id != *id {
            return Err(JournalError::Invariant(
                "publication intent integrity mismatch",
            ));
        }
        let state = match state.as_str() {
            "preparing" => PublicationState::Preparing,
            "ready" => PublicationState::Ready,
            "published" => PublicationState::Published,
            "committed" => PublicationState::Committed,
            _ => return Err(JournalError::Invariant("unsupported publication state")),
        };
        Ok(Publication {
            intent,
            state,
            committed_snapshot: root.map(|root| root.parse()).transpose()?,
            cleaned,
        })
    }

    pub(crate) fn mutation(&self, id: &EntryId) -> Result<Mutation> {
        let (space, root, json, hash, state): (String, String, String, String, String) =
            self.connection.query_row(
                "SELECT space_id,baseline_root,intent,intent_hash,state FROM mutations WHERE transaction_id=?1",
                [id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        if json.len() > MAX_OPERATION_BYTES || ContentId::hash(json.as_bytes()).as_str() != hash {
            return Err(JournalError::Invariant(
                "mutation intent integrity mismatch",
            ));
        }
        let intent: MutationIntent = serde_json::from_str(&json)?;
        intent.validate()?;
        if intent.transaction_id != *id
            || intent.space_id.as_str() != space
            || intent.baseline_root.as_str() != root
        {
            return Err(JournalError::Invariant("mutation intent row mismatch"));
        }
        let state = match state.as_str() {
            "prepared" => MutationState::Prepared,
            "cancelled" => MutationState::Cancelled,
            "executing" => MutationState::Executing,
            "quarantined" => MutationState::Quarantined,
            "moved" => MutationState::Moved,
            "replaced" => MutationState::Replaced,
            "committed" => MutationState::Committed,
            _ => return Err(JournalError::Invariant("unsupported mutation state")),
        };
        let (json, hash, root): (Option<String>, Option<String>, Option<String>) = self.connection.query_row(
            "SELECT execution,execution_hash,committed_snapshot FROM mutations WHERE transaction_id=?1",
            [id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let execution = match (json, hash) {
            (None, None) if matches!(state, MutationState::Prepared | MutationState::Cancelled) => {
                None
            }
            (Some(json), Some(hash))
                if matches!(
                    (&intent.action, state),
                    (
                        MutationAction::Delete,
                        MutationState::Executing
                            | MutationState::Quarantined
                            | MutationState::Committed
                    ) | (
                        MutationAction::Move { .. },
                        MutationState::Executing | MutationState::Moved | MutationState::Committed
                    ) | (
                        MutationAction::Replace { .. },
                        MutationState::Executing
                            | MutationState::Quarantined
                            | MutationState::Replaced
                            | MutationState::Committed
                    )
                ) && json.len() <= MAX_OPERATION_BYTES
                    && ContentId::hash(json.as_bytes()).as_str() == hash =>
            {
                Some(serde_json::from_str::<MutationExecution>(&json)?)
            }
            _ => {
                return Err(JournalError::Invariant(
                    "mutation execution integrity mismatch",
                ))
            }
        };
        if let Some(execution) = &execution {
            if execution.payload_identity.is_some()
                != matches!(intent.action, MutationAction::Replace { .. })
            {
                return Err(JournalError::Invariant(
                    "mutation payload identity mismatch",
                ));
            }
        }
        let committed_snapshot = root.map(|root| root.parse()).transpose()?;
        if (state == MutationState::Committed) != committed_snapshot.is_some() {
            return Err(JournalError::Invariant("mutation completion row mismatch"));
        }
        Ok(Mutation {
            intent,
            state,
            execution,
            committed_snapshot,
        })
    }

    pub(crate) fn mutations(&self, space: &SpaceId) -> Result<Vec<Mutation>> {
        let mut statement = self.connection.prepare(
            "SELECT transaction_id FROM mutations WHERE space_id=?1 ORDER BY transaction_id",
        )?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| self.mutation(&id.parse()?))
            .collect()
    }

    pub(crate) fn verify_mutation_references(&self, id: &EntryId) -> Result<()> {
        let mutation = self.mutation(id)?;
        let intent = &mutation.intent;
        let baseline = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        if baseline.entries.get(&intent.baseline_entry.entry_id) != Some(&intent.baseline_entry) {
            return Err(JournalError::Invariant(
                "mutation retained baseline mismatch",
            ));
        }
        let mut expected = std::collections::BTreeSet::new();
        if mutation.state.active() {
            for content in std::iter::once(
                intent
                    .baseline_entry
                    .content
                    .as_ref()
                    .ok_or(JournalError::Invariant("mutation baseline content missing"))?,
            )
            .chain(match &intent.action {
                MutationAction::Replace { content } => Some(content),
                _ => None,
            }) {
                expected.extend(content.chunks.iter().map(|chunk| chunk.content_id.clone()));
            }
        }
        let mut statement = self
            .connection
            .prepare("SELECT content_id FROM mutation_objects WHERE transaction_id=?1")?;
        let ids: Vec<String> = statement
            .query_map([id.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let actual = ids
            .into_iter()
            .map(|id| id.parse())
            .collect::<std::result::Result<std::collections::BTreeSet<ContentId>, _>>()?;
        if actual != expected {
            return Err(JournalError::Invariant(
                "mutation object protection mismatch",
            ));
        }
        if let Some(root) = &mutation.committed_snapshot {
            let completed = self.snapshot(&intent.space_id, root)?;
            let valid = match &intent.action {
                MutationAction::Delete => {
                    !completed
                        .entries
                        .contains_key(&intent.baseline_entry.entry_id)
                        && completed
                            .tombstones
                            .contains_key(&intent.baseline_entry.entry_id)
                }
                MutationAction::Move { destination, .. } => {
                    let mut entry = intent.baseline_entry.clone();
                    entry.path = destination.clone();
                    completed.entries.get(&entry.entry_id) == Some(&entry)
                        && !completed.tombstones.contains_key(&entry.entry_id)
                }
                MutationAction::Replace { content } => {
                    let mut entry = intent.baseline_entry.clone();
                    entry.content = Some(content.clone());
                    completed.entries.get(&entry.entry_id) == Some(&entry)
                        && !completed.tombstones.contains_key(&entry.entry_id)
                }
            };
            if !valid {
                return Err(JournalError::Invariant(
                    "mutation completion snapshot mismatch",
                ));
            }
        }
        Ok(())
    }
}
