use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::{path::Path, time::Duration};
use sync_extend_core_model::*;

const MAX_OPERATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING_OPS: u64 = 10_000;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Duplicate,
    Pending,
    Received,
}

pub struct Journal {
    connection: Connection,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
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
            1..=7 => {}
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
        Ok(Self { connection })
    }

    pub fn state(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn initialize(&mut self, space: &SpaceId, device: &DeviceId, root: &str) -> Result<()> {
        let tx = self.connection.transaction()?;
        for (key, value) in [
            ("space_id", space.as_str()),
            ("device_id", device.as_str()),
            ("worktree", root),
        ] {
            let old: Option<String> = tx
                .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                    row.get(0)
                })
                .optional()?;
            if old.as_deref().is_some_and(|old| old != value) {
                return Err(JournalError::Invariant("local identity/root mismatch"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO local_state VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn current(&self, space: &SpaceId) -> Result<Option<Manifest>> {
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
            "SELECT snapshot_id,state FROM snapshots WHERE space_id=?1 ORDER BY created_at_ms, snapshot_id",
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
        let mut statement = self
            .connection
            .prepare("SELECT snapshot_id,manifest FROM snapshots WHERE space_id=?1")?;
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

    pub fn publication(&self, id: &EntryId) -> Result<Publication> {
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

    pub fn mutations(&self, space: &SpaceId) -> Result<Vec<Mutation>> {
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

    pub fn begin_mutation(&mut self, intent: &MutationIntent) -> Result<()> {
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
             UNION SELECT content_id FROM mutation_objects ORDER BY content_id",
        )?;
        let ids: Vec<String> = statement
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter().map(|id| Ok(id.parse()?)).collect()
    }

    pub fn check_storage_metadata_limit(&self, max_entries: usize) -> Result<()> {
        let (rows, bytes): (i64, i64) = self.connection.query_row(
            "SELECT
                (SELECT count(*) FROM snapshots) + (SELECT count(*) FROM mutations)
                + (SELECT count(*) FROM publications) + (SELECT count(*) FROM snapshot_objects)
                + (SELECT count(*) FROM mutation_objects) + (SELECT count(*) FROM publication_objects)
                + (SELECT count(*) FROM cleanup_plans),
                (SELECT coalesce(sum(length(CAST(manifest AS BLOB))),0) FROM snapshots)
                + (SELECT coalesce(sum(length(CAST(intent AS BLOB))
                    + coalesce(length(CAST(execution AS BLOB)),0)),0) FROM mutations)
                + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM publications)
                + (SELECT coalesce(sum(length(CAST(intent AS BLOB))),0) FROM cleanup_plans)",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let max_bytes = (max_entries as u64)
            .checked_mul(1024)
            .ok_or(JournalError::Invariant("storage metadata budget overflow"))?;
        if rows < 0 || bytes < 0 || rows as u64 > max_entries as u64 || bytes as u64 > max_bytes {
            return Err(JournalError::Invariant("storage metadata inventory limit"));
        }
        Ok(())
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
        let tx = self.connection.transaction()?;
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
            return Ok(ReceiveOutcome::Duplicate);
        }
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM operations WHERE state='pending'",
            [],
            |r| r.get(0),
        )?;
        if pending >= MAX_PENDING_OPS as i64 {
            return Err(JournalError::Invariant("pending queue full"));
        }
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
        promote_pending(&tx)?;
        let state: String = tx.query_row(
            "SELECT state FROM operations WHERE op_id=?1",
            [op.op_id.as_str()],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(if state == "pending" {
            ReceiveOutcome::Pending
        } else {
            ReceiveOutcome::Received
        })
    }

    pub fn commit_local(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        self.commit_local_inner(
            expected_root,
            manifest,
            operations,
            timestamp,
            Completion::None,
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

    fn commit_local_inner(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        completion: Completion<'_>,
    ) -> Result<SnapshotId> {
        manifest.validate()?;
        let root = manifest.root()?;
        let tx = self.connection.transaction()?;
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
                || p.origin_seq != cursor(&tx, &p.space_id, &p.origin_device_id)? + 1
            {
                return Err(JournalError::Invariant("local sequence discontinuity"));
            }
            for (device, seq) in &p.causal.0 {
                if cursor(&tx, &p.space_id, device)? < *seq {
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
            set_cursor(&tx, &p.space_id, &p.origin_device_id, p.origin_seq)?;
            expected_vector.observe(p.origin_device_id.clone(), p.origin_seq);
        }
        if manifest.version_vector != expected_vector {
            return Err(JournalError::Invariant(
                "manifest vector does not match committed operations",
            ));
        }
        tx.execute(
            "INSERT OR IGNORE INTO snapshots VALUES (?1,?2,?3,?4,'materialized',0)",
            params![
                root.as_str(),
                manifest.space_id.as_str(),
                serde_json::to_string(manifest)?,
                sql_integer(timestamp)?
            ],
        )?;
        tx.execute(
            "INSERT INTO current_manifests VALUES (?1,?2)
             ON CONFLICT(space_id) DO UPDATE SET snapshot_id=excluded.snapshot_id",
            params![manifest.space_id.as_str(), root.as_str()],
        )?;
        pin_snapshot(&tx, root.as_str(), manifest)?;
        if let Some(id) = publication {
            if tx.execute(
                "UPDATE publications SET state='committed',committed_snapshot=?1
                 WHERE transaction_id=?2 AND state='published'",
                params![root.as_str(), id.as_str()],
            )? != 1
            {
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
        tx.commit()?;
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
    Mutation(&'a EntryId),
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

fn promote_pending(tx: &Transaction<'_>) -> Result<()> {
    loop {
        let candidates: Vec<String> = {
            let mut statement = tx.prepare(
                "SELECT payload FROM operations WHERE state='pending' ORDER BY origin_seq",
            )?;
            let rows = statement.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut progressed = false;
        for json in candidates {
            let op: Operation = serde_json::from_str(&json)?;
            let p = &op.payload;
            if p.origin_seq != cursor(tx, &p.space_id, &p.origin_device_id)? + 1 {
                continue;
            }
            let mut ready = true;
            for (device, seq) in &p.causal.0 {
                if cursor(tx, &p.space_id, device)? < *seq {
                    ready = false;
                    break;
                }
            }
            if ready {
                tx.execute(
                    "UPDATE operations SET state='received' WHERE op_id=?1",
                    [op.op_id.as_str()],
                )?;
                set_cursor(tx, &p.space_id, &p.origin_device_id, p.origin_seq)?;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    Ok(())
}
mod publication;
pub use publication::{Publication, PublicationIntent, PublicationState};
mod mutation;
pub use mutation::{
    DeleteExecution, Mutation, MutationAction, MutationExecution, MutationIntent, MutationState,
};
mod cleanup;
pub use cleanup::{CleanupIntent, CleanupPlan, CleanupState};
