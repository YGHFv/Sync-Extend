//! Durable per-turn admission to this actual target's ordinary live commit.
//! Prepared values and stored hashes never recreate native session authority.
use super::*;
use sync_extend_core_model::{ContentId, Manifest, Operation, SnapshotId};
use sync_extend_platform_fs::{OriginalUnixSqliteSessionBinding, SealedUnixNativeFile};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) struct PreparedOriginalUnixLocalCommit {
    binding: OriginalUnixSqliteSessionBinding,
    before: ContentId,
    turn: u32,
    expected_root: Option<SnapshotId>,
    manifest: Manifest,
    operations: Vec<Operation>,
    timestamp: u64,
    intent: Vec<u8>,
}
impl PreparedOriginalUnixLocalCommit {
    pub(crate) fn durable_intent_bytes(&self) -> &[u8] {
        &self.intent
    }
}

fn rows_digest(rows: &[JournalStoredRow]) -> ContentId {
    let mut hash = blake3::Hasher::new();
    hash.update(b"sync-extend.actual-unix-session-complete-rows.v1");
    hash.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hash.update(row.fingerprint().as_str().as_bytes());
    }
    ContentId::from_hasher(&hash)
}

fn mutable_table(table: &str) -> bool {
    matches!(
        table,
        "operations"
            | "snapshots"
            | "snapshot_objects"
            | "current_manifests"
            | "receive_cursors"
            | "deletion_retention_clock"
            | "deletion_retention_observations"
            | "rename_observations"
            | "gc_invalidations"
    )
}

fn local_sql(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Insert { table_name }
            if context.database_name == Some("main") && mutable_table(table_name)
                && !matches!(table_name, "rename_observations" | "gc_invalidations") =>
        {
            Authorization::Allow
        }
        AuthAction::Insert { table_name: "gc_invalidations" }
            if context.database_name == Some("main")
                && context.accessor == Some("gc_snapshot_pin_insert") => Authorization::Allow,
        AuthAction::Delete { table_name: "rename_observations" }
            if context.database_name == Some("main") && matches!(context.accessor,
                Some("rename_observation_current_insert" | "rename_observation_current_update")) => Authorization::Allow,
        AuthAction::Update { table_name, .. }
            if context.database_name == Some("main")
                && matches!(
                    table_name,
                    "current_manifests" | "receive_cursors" | "deletion_retention_clock"
                ) =>
        {
            Authorization::Allow
        }
        _ => restricted(context),
    }
}

fn configure_trusted_schema(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Pragma { pragma_name, .. } if pragma_name.eq_ignore_ascii_case("trusted_schema") => Authorization::Allow,
        _ => restricted(context),
    }
}

fn set_trusted_schema(journal: &mut Journal, enabled: bool) -> Result<()> {
    journal.connection.authorizer(Some(configure_trusted_schema))?;
    journal.connection.pragma_update(None, "trusted_schema", enabled)?;
    let observed: bool = journal.connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    if observed != enabled {
        return Err(JournalError::Invariant("original Unix trusted schema mode differs"));
    }
    Ok(())
}

struct LocalCall<'a> {
    journal: &'a mut Journal,
    scope: Option<crate::original_observation_budget::OriginalObservationScope>,
    restored: bool,
}
impl<'a> LocalCall<'a> {
    fn begin(journal: &'a mut Journal, bounds: NodeInspectionBounds) -> Result<Self> {
        let budget = crate::original_observation_budget::OriginalObservationBudget::new(bounds);
        let scope = budget.begin()?;
        journal
            .connection
            .progress_handler(1_000, Some(move || budget.interrupt()))?;
        let call = Self {
            journal,
            scope: Some(scope),
            restored: false,
        };
        // The complete catalog was just matched to trusted build bytes. Only
        // this fixed ordinary SQL scope may execute its known trigger bodies;
        // no SQL/Connection callback or platform native issuer is exposed.
        set_trusted_schema(call.journal, true)?;
        call.journal.connection.authorizer(Some(local_sql))?;
        Ok(call)
    }
    fn finish(mut self, result: Result<SnapshotId>) -> Result<SnapshotId> {
        let schema = set_trusted_schema(self.journal, false);
        let restricted = self.journal.connection.authorizer(Some(restricted));
        let cleared = self
            .journal
            .connection
            .progress_handler(0, None::<fn() -> bool>);
        self.restored = schema.is_ok() && restricted.is_ok() && cleared.is_ok();
        let bounded = self.scope.take().expect("same bounded local call").finish();
        let root = result?;
        schema?;
        restricted?;
        cleared?;
        bounded?;
        Ok(root)
    }
}
impl Drop for LocalCall<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = set_trusted_schema(self.journal, false);
            let _ = self.journal.connection.authorizer(Some(restricted));
            let _ = self
                .journal
                .connection
                .progress_handler(0, None::<fn() -> bool>);
        }
    }
}

impl OriginalUnixRestoredJournal<'_> {
    /// Prepare complete immutable inputs while the actual target's prior rows
    /// are still exactly audited. No SQL write or filesystem creator occurs.
    pub(crate) fn prepare_local_commit(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<PreparedOriginalUnixLocalCommit> {
        let started = Instant::now();
        self.verify()?;
        crate::sql_integer(timestamp)?;
        manifest.validate()?;
        if self.next_local_turn >= 4096 || manifest.space_id != self.space
            || operations.len() > self.bounds.max_entries
            || manifest.entries.len() > self.bounds.max_entries
        {
            return Err(JournalError::Invariant(
                "bounded original Unix local input scope",
            ));
        }
        for operation in operations {
            operation.validate()?;
        }
        let (input, bytes) = crate::backup_image::native_history_persistence::bounded_digest(
            &(expected_root, manifest, operations, timestamp),
            MAX_INPUT_BYTES,
        )?;
        let loan = self
            .io
            .as_ref()
            .ok_or(JournalError::Invariant("actual Unix IO absent"))?
            .session_loan()?;
        let keys = loan
            .observed_keys()?
            .map(|key| (key.device, key.inode, key.uid));
        let before = rows_digest(&self.expected);
        // Fixed-size identities/digests only; complete potentially large inputs
        // were streamed through the bounded hash before any clone or effect.
        let intent = serde_json::to_vec(&(
            "sync-extend.original-unix-local-intent.v1",
            &self.space,
            keys,
            self.next_local_turn,
            &before,
            input,
            bytes,
            timestamp,
        ))?;
        if intent.len() > 4096 {
            return Err(JournalError::Invariant(
                "bounded original Unix local intent",
            ));
        }
        let prepared = PreparedOriginalUnixLocalCommit {
            binding: loan.binding()?,
            before,
            turn: self.next_local_turn,
            expected_root: expected_root.cloned(),
            manifest: manifest.clone(),
            operations: operations.to_vec(),
            timestamp,
            intent,
        };
        if started.elapsed() >= self.bounds.max_query_time {
            return Err(JournalError::Invariant("original Unix local preparation completed late"));
        }
        Ok(prepared)
    }

    /// Consumes the prepared input only after the complete same-parent intent
    /// is durably sealed. Every mutation uses the target's actual live Journal;
    /// the memory preparation writer and all native source rows remain inert.
    pub(crate) fn commit_prepared_local(
        &mut self,
        prepared: PreparedOriginalUnixLocalCommit,
        intent: &SealedUnixNativeFile<'_>,
    ) -> Result<SnapshotId> {
        self.verify()?;
        let loan = self
            .io
            .as_ref()
            .ok_or(JournalError::Invariant("actual Unix IO absent"))?
            .session_loan()?;
        loan.verify_binding(&prepared.binding)?;
        loan.verify_durable_intent(intent, &prepared.intent)?;
        if prepared.turn != self.next_local_turn || rows_digest(&self.expected) != prepared.before {
            return Err(JournalError::Invariant(
                "original Unix local baseline changed",
            ));
        }
        self.poisoned = true;
        let call = LocalCall::begin(
            self.journal
                .as_mut()
                .ok_or(JournalError::Invariant("actual Unix Journal absent"))?,
            self.bounds,
        )?;
        let committed = call.journal.commit_local(
            prepared.expected_root.as_ref(),
            &prepared.manifest,
            &prepared.operations,
            prepared.timestamp,
        );
        let root = call.finish(committed)?;
        let actual = self.audit_rows()?;
        // Full provenance audit above covers every row. Additionally require
        // byte-for-byte preservation of every family outside the fixed live
        // commit set, including all original source/hold/fresh-writer records.
        if actual
            .iter()
            .filter(|row| !mutable_table(row.table()))
            .map(JournalStoredRow::fingerprint)
            .ne(self
                .expected
                .iter()
                .filter(|row| !mutable_table(row.table()))
                .map(JournalStoredRow::fingerprint))
        {
            return Err(JournalError::Invariant(
                "original Unix local commit changed protected history",
            ));
        }
        self.io
            .as_ref()
            .expect("same actual IO")
            .session_loan()?
            .verify_durable_intent(intent, &prepared.intent)?;
        self.expected = actual;
        self.next_local_turn += 1;
        self.poisoned = false;
        Ok(root)
    }
}
