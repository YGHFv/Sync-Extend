//! Private original Journal transition with complete row equality before handoff.
use crate::{Journal, JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use sync_extend_core_model::SpaceId;
use sync_extend_platform_fs::{
    OriginalSqliteConnection, OriginalSqliteMainHandoff, OriginalSqliteOpenFailure,
    OriginalSqliteQuery, OriginalSqliteReadBudget, OriginalSqliteRows,
    OriginalSqliteSidecarHandoff, OriginalSqliteValue, ReleasedOriginalCoordinationFile,
};

pub struct OriginalJournalWriteTransition {
    original: OriginalSqliteConnection,
    pub(crate) cas: ReleasedOriginalCoordinationFile,
    pub(crate) path: std::path::PathBuf,
    space: SpaceId,
    max_entries: usize,
    complete_queries: Vec<OriginalSqliteQuery>,
    inspection: NodeInspectionBounds,
}
pub enum OriginalJournalTransitionFailure {
    InertClosed {
        journal: Box<Journal>,
        main: Box<Option<OriginalSqliteMainHandoff>>,
        cas: Box<Option<ReleasedOriginalCoordinationFile>>,
        wal: Box<OriginalSqliteSidecarHandoff>,
        rollback: Box<OriginalSqliteSidecarHandoff>,
        error: JournalError,
    },

    Read {
        journal: Box<Journal>,
        wal: Box<OriginalSqliteSidecarHandoff>,
        rollback: Box<OriginalSqliteSidecarHandoff>,
        error: JournalError,
    },
    Closed {
        main: Box<OriginalSqliteMainHandoff>,
        wal: Box<OriginalSqliteSidecarHandoff>,
        rollback: Box<OriginalSqliteSidecarHandoff>,
        cas: Box<ReleasedOriginalCoordinationFile>,
        error: JournalError,
    },
    Opening {
        failed: Box<OriginalSqliteOpenFailure>,
        cas: Box<ReleasedOriginalCoordinationFile>,
    },
    Open {
        transition: Box<OriginalJournalWriteTransition>,
        error: JournalError,
    },
}

impl Journal {
    /// Requires a CREATE-issued main handoff retained from original assembly.
    /// Original restored metadata evidence alone cannot enter this branch.
    /// This is a transition to an opaque owner, without native mutation grants.
    // Each independently retained main/sidecar/image/budget input remains
    // explicit in the original linear capability API and original fixtures.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_original_write_transition(
        mut self,
        wal: OriginalSqliteSidecarHandoff,
        rollback: OriginalSqliteSidecarHandoff,
        image: &JournalBackupImage,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        limits: [u64; 3],
        max_write_bytes: u64,
    ) -> std::result::Result<OriginalJournalWriteTransition, OriginalJournalTransitionFailure> {
        let verify = || -> Result<()> {
            self.verify_original_created_image()?;
            if !self.connection.is_autocommit()
                || self.original_main_handoff.is_none()
                || self.original_cas_coordination.is_none()
            {
                return Err(JournalError::Invariant(
                    "original readonly Journal needs sealed main and original CAS before handoff",
                ));
            }
            let main = self
                .original_main_handoff
                .as_ref()
                .ok_or(JournalError::Invariant("original main capability missing"))?;
            main.verify()?;
            // The retained CREATE verifies its original parent/slot. SQLite's
            // actual main handle must be that same single-link object; Windows
            // canonical extended spelling need not equal the original drive spelling.
            if sync_extend_platform_fs::sqlite_main_file_identity(&self.connection)?
                != main.key()?
                || main.exact_protected_bytes(image.bytes().len() as u64)? != image.bytes()
                || wal.parent_key()? != main.parent_key()?
                || rollback.parent_key()? != main.parent_key()?
            {
                return Err(JournalError::Invariant(
                    "original Journal accepted image and sealed sidecar parent scope differ",
                ));
            }
            // Own a real read snapshot on this retained connection for the
            // complete typed audit and accepted-image comparison. Its original
            // bounded inspection hooks remain active throughout the transaction.
            let snapshot = rusqlite::Transaction::new_unchecked(
                &self.connection,
                rusqlite::TransactionBehavior::Deferred,
            )?;
            let actual = self.read_view().audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            image.with_audited_readonly(space, bounds, |connection| {
                let expected = crate::JournalReadView { connection }
                    .audit_original_provenance_capacity(
                        space,
                        bounds.max_entries,
                        bounds.capacity,
                    )?;
                if actual.rows != expected.rows {
                    return Err(JournalError::Invariant(
                        "original writable handoff full typed Journal rows differ",
                    ));
                }
                Ok(())
            })?;
            // End this read snapshot before closing the actual connection and
            // transferring its original main and sidecar capabilities.
            snapshot.rollback()?;
            let sentinel =
                self.original_cas_coordination
                    .as_ref()
                    .ok_or(JournalError::Invariant(
                        "original coordination capability absent",
                    ))?;
            sentinel.verify(
                &self
                    .database_path
                    .parent()
                    .ok_or(JournalError::Invariant("original Journal parent absent"))?
                    .join("cas-access.lock"),
            )?;
            Ok(())
        };
        if let Err(error) = verify() {
            return Err(OriginalJournalTransitionFailure::Read {
                journal: Box::new(self),
                wal: Box::new(wal),
                rollback: Box::new(rollback),
                error,
            });
        }
        // Allocate an inert memory placeholder before moving the live connection.
        // It is never returned as an accepted Journal or used for target writes.
        let replacement = match rusqlite::Connection::open_in_memory() {
            Ok(value) => value,
            Err(error) => {
                return Err(OriginalJournalTransitionFailure::Read {
                    journal: Box::new(self),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error: error.into(),
                })
            }
        };
        let actual = std::mem::replace(&mut self.connection, replacement);
        if let Err((connection, error)) = actual.close() {
            self.connection = connection;
            return Err(OriginalJournalTransitionFailure::Read {
                journal: Box::new(self),
                wal: Box::new(wal),
                rollback: Box::new(rollback),
                error: error.into(),
            });
        }
        // All own read Connection locks are actually closed before protected
        // readers can be relinquished. Observer connections cause share0 refusal.
        let main = self.original_main_handoff.take();
        let cas = self.original_cas_coordination.take();
        let (main, cas) = match (main, cas) {
            (Some(main), Some(cas)) => (main, cas),
            (main, cas) => {
                return Err(OriginalJournalTransitionFailure::InertClosed {
                    journal: Box::new(self),
                    main: Box::new(main),
                    cas: Box::new(cas),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error: JournalError::Invariant(
                        "original closed transition lacks sealed capability",
                    ),
                })
            }
        };
        // Keep the already verified original CREATE slot spelling for the
        // private VFS URI; this introduces no pathname-issued authority.
        let path = main.path().to_owned();
        let max_entries = self.max_storage_entries;
        // Drop the old plain read protection and gates before private VFS open.
        // The linear main's actual original/parent witnesses remain live.
        drop(self);
        let original = match OriginalSqliteConnection::open(
            main,
            wal,
            rollback,
            image.bytes(),
            crate::SCHEMA_VERSION,
            limits,
            max_write_bytes,
        ) {
            Ok(value) => value,
            Err(failed) => {
                return Err(OriginalJournalTransitionFailure::Opening {
                    failed: Box::new(failed),
                    cas: Box::new(cas),
                });
            }
        };
        let mut transition = OriginalJournalWriteTransition {
            original,
            cas,
            path,
            space: space.clone(),
            max_entries,
            complete_queries: Vec::new(),
            inspection: bounds,
        };
        if let Err(error) = transition.verify_complete_original_rows(image, bounds) {
            return Err(OriginalJournalTransitionFailure::Open {
                transition: Box::new(transition),
                error,
            });
        }
        Ok(transition)
    }
}

impl OriginalJournalWriteTransition {
    pub fn verify(&self) -> Result<()> {
        self.original.verify()?;
        self.cas.verify(
            &self
                .path
                .parent()
                .ok_or(JournalError::Invariant(
                    "original writable Journal parent absent",
                ))?
                .join("cas-access.lock"),
        )?;
        crate::storage_policy::validate(self.max_entries)?;
        Ok(())
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }

    /// One explicit original Journal local state transaction; never native effect
    /// authority, credentials or arbitrary caller SQL. Caller must hold the new
    /// restoration transition ledger and complete original scope.
    pub fn attempt_original_recovery_session(&mut self, session: &SpaceId) -> Result<()> {
        self.verify()?;
        let actual =
            self.original
                .execute_one_transaction(&[sync_extend_platform_fs::OriginalSqliteStatement {
                sql:
                    "INSERT INTO main.local_state(key,value) VALUES('original_recovery_session',?1)"
                        .into(),
                parameters: vec![sync_extend_platform_fs::OriginalSqliteValue::Text(
                    session.as_str().into(),
                )],
                expected_changed_rows: 1,
            }])?;
        if actual != [1] {
            return Err(JournalError::Invariant(
                "original session first-write row outcome",
            ));
        }
        self.verify()
    }
    pub fn checkpoint(&mut self) -> Result<()> {
        self.original.checkpoint().map_err(Into::into)
    }
    pub fn close(
        self,
    ) -> std::result::Result<
        (
            [sync_extend_platform_fs::ReleasedOriginalFileIdentity; 3],
            ReleasedOriginalCoordinationFile,
        ),
        (Box<Self>, JournalError),
    > {
        let Self {
            original,
            cas,
            path,
            space,
            max_entries,
            complete_queries,
            inspection,
        } = self;
        match original.close() {
            Ok(objects) => Ok((objects, cas)),
            Err((original, error)) => Err((
                Box::new(Self {
                    original: *original,
                    cas,
                    path,
                    space,
                    max_entries,
                    complete_queries,
                    inspection,
                }),
                error.into(),
            )),
        }
    }
    fn verify_complete_original_rows(
        &mut self,
        image: &JournalBackupImage,
        bounds: NodeInspectionBounds,
    ) -> Result<()> {
        self.verify()?;
        let space = self.space.clone();
        let complete_queries = image.with_audited_readonly(&space, bounds, |connection| {
            let mut aggregate = ExpectedAggregate { rows: 0, bytes: 0 };
            let mut catalog = connection.prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name",
            )?;
            let catalog_expected = expected_rows(&mut catalog, bounds, &mut aggregate)?;
            let mut queries = vec![OriginalSqliteQuery {
                sql: "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name"
                    .into(),
                parameters: Vec::new(),
            }];
            let mut expected = vec![catalog_expected];
            let mut tables = connection
                .prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")?;

            let mut names = Vec::new();
            let mut table_rows = tables.query([])?;
            while let Some(row) = table_rows.next()? {
                if names.len() >= 1023 {
                    return Err(JournalError::Invariant("original table query count bound"));
                }
                let name = row.get_ref(0)?.as_str().map_err(|_| {
                    JournalError::Invariant("original table identifier UTF8 required")
                })?;
                if name.len() > 255 {
                    return Err(JournalError::Invariant(
                        "original table identifier byte bound",
                    ));
                }
                names.push(name.to_owned());
            }
            drop(table_rows);
            drop(tables);
            for name in names {
                if name.len() > 255 {
                    return Err(JournalError::Invariant(
                        "original Journal table identifier byte bound",
                    ));
                }
                let quoted = '"'.to_string() + &name.replace('"', "\"\"") + "\"";
                let columns =
                    connection.prepare(&format!("SELECT * FROM main.{quoted} LIMIT 0"))?;
                let count = columns.column_count();
                if count == 0 || count > 1024 {
                    return Err(JournalError::Invariant("original table column order bound"));
                }
                let order = (1..=count)
                    .map(|index| index.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                drop(columns);
                let sql = format!("SELECT * FROM main.{quoted} ORDER BY {order}");
                let mut statement = connection.prepare(&sql)?;
                expected.push(expected_rows(&mut statement, bounds, &mut aggregate)?);
                queries.push(OriginalSqliteQuery {
                    sql,
                    parameters: Vec::new(),
                });
            }
            let actual = self.original.read_queries(
                &queries,
                OriginalSqliteReadBudget {
                    max_queries: queries.len(),
                    max_rows: bounds.capacity.max_rows.try_into().map_err(|_| {
                        JournalError::Invariant("original Journal row bound conversion")
                    })?,
                    max_columns: 1024,
                    max_owned_bytes: bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024),
                    max_vm_instructions: bounds.max_vm_instructions,
                    max_seconds: bounds.max_query_time.as_secs(),
                },
            )?;
            if expected.len() != actual.len() {
                return Err(JournalError::Invariant(
                    "original writable Journal full query count differs",
                ));
            }
            for (expected, actual) in expected.iter().zip(&actual) {
                compare_rows(expected, actual)?;
            }
            Ok(queries)
        })?;
        self.complete_queries = complete_queries;
        self.verify()
    }
}

struct ExpectedAggregate {
    rows: u64,
    bytes: u64,
}
fn expected_rows(
    statement: &mut rusqlite::Statement<'_>,
    bounds: NodeInspectionBounds,
    aggregate: &mut ExpectedAggregate,
) -> Result<OriginalSqliteRows> {
    if statement.column_count() == 0 || statement.column_count() > 1024 {
        return Err(JournalError::Invariant(
            "original expected row column bounds",
        ));
    }

    for name in statement.column_names() {
        aggregate.bytes =
            aggregate
                .bytes
                .checked_add(name.len() as u64 + 32)
                .ok_or(JournalError::Invariant(
                    "original expected column byte overflow",
                ))?;
        if aggregate.bytes > bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024) {
            return Err(JournalError::Invariant(
                "original expected column bound before clone",
            ));
        }
    }
    let columns: Vec<String> = statement.column_names().map(str::to_owned).collect();
    let mut rows = statement.query([])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        aggregate.rows = aggregate
            .rows
            .checked_add(1)
            .ok_or(JournalError::Invariant("original alltable row overflow"))?;
        if aggregate.rows > bounds.capacity.max_rows {
            return Err(JournalError::Invariant(
                "original expected row count budget",
            ));
        }
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value = row.get_ref(index)?;
            let length = match value {
                rusqlite::types::ValueRef::Null => 0,
                rusqlite::types::ValueRef::Integer(_) | rusqlite::types::ValueRef::Real(_) => 8,
                rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) => {
                    value.len() as u64
                }
            };
            aggregate.bytes =
                aggregate
                    .bytes
                    .checked_add(length + 32)
                    .ok_or(JournalError::Invariant(
                        "original expected row byte overflow",
                    ))?;
            if aggregate.bytes > bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024) {
                return Err(JournalError::Invariant(
                    "original expected row byte limit before clone",
                ));
            }
            values.push(match value {
                rusqlite::types::ValueRef::Null => OriginalSqliteValue::Null,
                rusqlite::types::ValueRef::Integer(value) => OriginalSqliteValue::Integer(value),
                rusqlite::types::ValueRef::Real(value) if value.is_finite() => {
                    OriginalSqliteValue::Real(value)
                }
                rusqlite::types::ValueRef::Real(_) => {
                    return Err(JournalError::Invariant(
                        "original expected nonfinite numeric cell",
                    ))
                }
                rusqlite::types::ValueRef::Text(value) => OriginalSqliteValue::Text(
                    std::str::from_utf8(value)
                        .map_err(|_| JournalError::Invariant("original expected UTF8 cell"))?
                        .into(),
                ),
                rusqlite::types::ValueRef::Blob(value) => OriginalSqliteValue::Blob(value.to_vec()),
            });
        }
        output.push(values);
    }
    Ok(OriginalSqliteRows {
        columns,
        rows: output,
    })
}
fn compare_rows(expected: &OriginalSqliteRows, actual: &OriginalSqliteRows) -> Result<()> {
    fn equal(left: &OriginalSqliteValue, right: &OriginalSqliteValue) -> bool {
        match (left, right) {
            (OriginalSqliteValue::Null, OriginalSqliteValue::Null) => true,
            (OriginalSqliteValue::Integer(left), OriginalSqliteValue::Integer(right)) => {
                left == right
            }
            (OriginalSqliteValue::Real(left), OriginalSqliteValue::Real(right)) => {
                left.to_bits() == right.to_bits()
            }
            (OriginalSqliteValue::Text(left), OriginalSqliteValue::Text(right)) => left == right,
            (OriginalSqliteValue::Blob(left), OriginalSqliteValue::Blob(right)) => left == right,
            _ => false,
        }
    }
    if expected.columns != actual.columns
        || expected.rows.len() != actual.rows.len()
        || expected.rows.iter().zip(&actual.rows).any(|(left, right)| {
            left.len() != right.len()
                || left
                    .iter()
                    .zip(right)
                    .any(|(left, right)| !equal(left, right))
        })
    {
        return Err(JournalError::Invariant(
            "actual writable original Journal catalog/full cell values differ",
        ));
    }
    Ok(())
}

// Only the actual original-creation assembler registers this handoff.

impl OriginalJournalWriteTransition {
    pub fn actual_native_keys(&self) -> Result<[sync_extend_platform_fs::FileKey; 3]> {
        self.verify()?;
        self.original.actual_native_keys().map_err(Into::into)
    }
    /// Exact current catalog and every table's bounded sorted values are queried
    /// in one actual WAL read snapshot. All bytes enter a deterministic digest.
    pub fn actual_complete_rows_digest(&self) -> Result<sync_extend_core_model::ContentId> {
        self.verify()?;
        if self.complete_queries.is_empty() {
            return Err(JournalError::Invariant(
                "complete original query set unbound",
            ));
        }
        let bounds = self.inspection;
        let result = self.original.read_queries(
            &self.complete_queries,
            OriginalSqliteReadBudget {
                max_queries: self.complete_queries.len(),
                max_rows: bounds
                    .capacity
                    .max_rows
                    .try_into()
                    .map_err(|_| JournalError::Invariant("complete original row bound"))?,
                max_columns: 1024,
                max_owned_bytes: bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024),
                max_vm_instructions: bounds.max_vm_instructions,
                max_seconds: bounds.max_query_time.as_secs(),
            },
        )?;
        let mut hash = blake3::Hasher::new();
        fn bytes(hash: &mut blake3::Hasher, value: &[u8]) {
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(value);
        }
        hash.update(b"OriginalJournalFullRows1");
        hash.update(&(result.len() as u64).to_le_bytes());
        for table in result {
            hash.update(&(table.columns.len() as u64).to_le_bytes());
            for column in &table.columns {
                bytes(&mut hash, column.as_bytes());
            }
            hash.update(&(table.rows.len() as u64).to_le_bytes());
            for row in table.rows {
                hash.update(&(row.len() as u64).to_le_bytes());
                for cell in row {
                    match cell {
                        OriginalSqliteValue::Null => {
                            hash.update(&[0]);
                        }
                        OriginalSqliteValue::Integer(value) => {
                            hash.update(&[1]);
                            hash.update(&value.to_le_bytes());
                        }
                        OriginalSqliteValue::Real(value) => {
                            hash.update(&[2]);
                            hash.update(&value.to_bits().to_le_bytes());
                        }
                        OriginalSqliteValue::Text(value) => {
                            hash.update(&[3]);
                            bytes(&mut hash, value.as_bytes());
                        }
                        OriginalSqliteValue::Blob(value) => {
                            hash.update(&[4]);
                            bytes(&mut hash, &value);
                        }
                    }
                }
            }
        }
        self.verify()?;
        Ok(sync_extend_core_model::ContentId::from_hasher(&hash))
    }
}

impl OriginalJournalWriteTransition {
    /// Continuous bounded ordinary history after the original first-write
    /// handshake. Uses the production Journal planner and all existing audits.
    /// The caller must establish actual current files before this commit.
    pub fn commit_original_local_history(
        &mut self,
        expected_root: &sync_extend_core_model::SnapshotId,
        manifest: &sync_extend_core_model::Manifest,
        operations: &[sync_extend_core_model::Operation],
        timestamp: u64,
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        if manifest.space_id != self.space || operations.is_empty() || operations.len() > 512 {
            return Err(JournalError::Invariant(
                "original ordinary history explicit scope",
            ));
        }
        let bounds = self.inspection;
        let budget = OriginalSqliteReadBudget {
            max_queries: self.complete_queries.len(),
            max_rows: bounds
                .capacity
                .max_rows
                .try_into()
                .map_err(|_| JournalError::Invariant("original continuous row bound"))?,
            max_columns: 1024,
            max_owned_bytes: bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024),
            max_vm_instructions: bounds.max_vm_instructions,
            max_seconds: bounds.max_query_time.as_secs(),
        };
        let before = self.original.read_queries(&self.complete_queries, budget)?;
        let mut memory = original_planning_memory(&before, bounds)?;
        let mut planner =
            Journal::from_original_planning_memory(memory, &self.path, self.max_entries)?;
        let before_audit = {
            let snapshot = planner.connection.unchecked_transaction()?;
            let audit = planner.read_view().audit_original_provenance_capacity(
                &self.space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            snapshot.rollback()?;
            audit
        };
        let root = planner.commit_local(Some(expected_root), manifest, operations, timestamp)?;
        let after_audit = {
            let snapshot = planner.connection.unchecked_transaction()?;
            let audit = planner.read_view().audit_original_provenance_capacity(
                &self.space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            snapshot.rollback()?;
            audit
        };
        // Planner's private Connection is moved back only inside this module.
        memory = planner.connection;
        let mut aggregate = ExpectedAggregate { rows: 0, bytes: 0 };
        let mut after = Vec::new();
        for query in &self.complete_queries {
            if !query.parameters.is_empty() {
                return Err(JournalError::Invariant(
                    "original full table query parameters",
                ));
            }
            let mut statement = memory.prepare(&query.sql)?;
            after.push(expected_rows(&mut statement, bounds, &mut aggregate)?);
        }
        let statements = original_history_diff(&before_audit.rows, &after_audit.rows)?;

        self.original.execute_admitted_rows(
            &statements,
            &self.complete_queries,
            &before,
            &after,
            budget,
        )?;
        let actual = self.original.read_queries(&self.complete_queries, budget)?;
        for (expected, actual) in after.iter().zip(&actual) {
            compare_rows(expected, actual)?;
        }
        self.verify()?;
        Ok(root)
    }
}

fn original_planning_memory(
    rows: &[OriginalSqliteRows],
    bounds: NodeInspectionBounds,
) -> Result<rusqlite::Connection> {
    let catalog = rows
        .first()
        .ok_or(JournalError::Invariant("original full catalog absent"))?;
    if catalog.columns != ["type", "name", "tbl_name", "sql"] {
        return Err(JournalError::Invariant(
            "original full catalog column order",
        ));
    }
    let mut memory = rusqlite::Connection::open_in_memory()?;
    bounds.configure_original_connection(&mut memory)?;
    memory.pragma_update(None, "query_only", false)?;
    memory.pragma_update(None, "temp_store", "MEMORY")?;
    memory.pragma_update(None, "foreign_keys", false)?;
    let tx = memory.transaction()?;
    for kind in ["table", "index"] {
        for row in &catalog.rows {
            if row.len() != 4 {
                return Err(JournalError::Invariant("original catalog cells"));
            }
            let (OriginalSqliteValue::Text(actual_kind), OriginalSqliteValue::Text(name)) =
                (&row[0], &row[1])
            else {
                return Err(JournalError::Invariant("original catalog name type"));
            };
            if actual_kind != kind || name.starts_with("sqlite_") {
                continue;
            }
            if let OriginalSqliteValue::Text(sql) = &row[3] {
                tx.execute_batch(sql)?;
            }
        }
    }
    for table in rows.iter().skip(1) {
        let index = rows
            .iter()
            .position(|candidate| std::ptr::eq(candidate, table))
            .ok_or(JournalError::Invariant("original planning table index"))?
            - 1;
        let names: Vec<_> = catalog
            .rows
            .iter()
            .filter_map(|entry| match (&entry[0], &entry[1]) {
                (OriginalSqliteValue::Text(kind), OriginalSqliteValue::Text(name))
                    if kind == "table" =>
                {
                    Some(name)
                }
                _ => None,
            })
            .collect();
        let name = names.get(index).ok_or(JournalError::Invariant(
            "original planning catalog table order",
        ))?;
        if name.starts_with("sqlite_") {
            return Err(JournalError::Invariant(
                "original unsupported internal table",
            ));
        }
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        let placeholders = (1..=table.columns.len())
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut insert =
            tx.prepare(&format!("INSERT INTO main.{quoted} VALUES({placeholders})"))?;
        for row in &table.rows {
            let values = row
                .iter()
                .map(original_owned_value)
                .collect::<Result<Vec<_>>>()?;
            insert.execute(rusqlite::params_from_iter(values))?;
        }
    }
    for row in &catalog.rows {
        if let (OriginalSqliteValue::Text(kind), OriginalSqliteValue::Text(sql)) =
            (&row[0], &row[3])
        {
            if kind == "trigger" || kind == "view" {
                tx.execute_batch(sql)?;
            }
        }
    }
    tx.pragma_update(None, "user_version", crate::SCHEMA_VERSION)?;
    tx.commit()?;
    bounds.configure_original_connection(&mut memory)?;
    memory.pragma_update(None, "query_only", false)?;
    memory.pragma_update(None, "trusted_schema", true)?;
    Ok(memory)
}
fn original_owned_value(value: &OriginalSqliteValue) -> Result<rusqlite::types::Value> {
    Ok(match value {
        OriginalSqliteValue::Null => rusqlite::types::Value::Null,
        OriginalSqliteValue::Integer(n) => rusqlite::types::Value::Integer(*n),
        OriginalSqliteValue::Real(n) if n.is_finite() => rusqlite::types::Value::Real(*n),
        OriginalSqliteValue::Real(_) => {
            return Err(JournalError::Invariant("original planning finite real"))
        }
        OriginalSqliteValue::Text(s) => rusqlite::types::Value::Text(s.clone()),
        OriginalSqliteValue::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
    })
}
fn original_history_diff(
    before: &[crate::JournalStoredRow],
    after: &[crate::JournalStoredRow],
) -> Result<Vec<sync_extend_platform_fs::OriginalSqliteStatement>> {
    use crate::JournalStorageColumnValue as Value;
    use std::collections::BTreeMap;
    fn key(row: &crate::JournalStoredRow) -> (String, Vec<String>) {
        (row.table().into(), row.primary_key().to_vec())
    }
    fn value(v: &Value) -> Result<OriginalSqliteValue> {
        Ok(match v {
            Value::Null => OriginalSqliteValue::Null,
            Value::Integer(n) => OriginalSqliteValue::Integer(
                i64::try_from(*n)
                    .map_err(|_| JournalError::Invariant("original admitted integer SQL range"))?,
            ),
            Value::Text(s) => OriginalSqliteValue::Text(s.clone()),
        })
    }
    fn allowed(table: &str) -> bool {
        matches!(
            table,
            "operations"
                | "receive_cursors"
                | "snapshots"
                | "snapshot_objects"
                | "current_manifests"
        )
    }
    let old: BTreeMap<_, _> = before.iter().map(|r| (key(r), r)).collect();
    let new: BTreeMap<_, _> = after.iter().map(|r| (key(r), r)).collect();
    if old.keys().any(|k| !new.contains_key(k)) {
        return Err(JournalError::Invariant(
            "original history cannot remove old rows",
        ));
    }
    let mut result = Vec::new();
    // Insert snapshots before their exact pin/current references.
    for table in [
        "operations",
        "receive_cursors",
        "snapshots",
        "snapshot_objects",
        "current_manifests",
    ] {
        for (key, row) in new.iter().filter(|(k, _)| k.0 == table) {
            if old.get(key).is_some_and(|old| *old == *row) {
                continue;
            }
            let mut parameters = Vec::new();
            let sql = if let Some(previous) = old.get(key) {
                if !matches!(table, "receive_cursors" | "current_manifests") {
                    return Err(JournalError::Invariant(
                        "original immutable history update refused",
                    ));
                }
                let sets = row
                    .columns()
                    .iter()
                    .map(|c| {
                        parameters.push(value(&c.value));
                        format!("\"{}\"=?{}", c.name, parameters.len())
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let mut predicates = Vec::new();
                for c in previous.columns() {
                    parameters.push(value(&c.value));
                    predicates.push(format!("\"{}\" IS ?{}", c.name, parameters.len()));
                }
                format!(
                    "UPDATE main.\"{table}\" SET {sets} WHERE {}",
                    predicates.join(" AND ")
                )
            } else {
                for c in row.columns() {
                    parameters.push(value(&c.value));
                }
                format!(
                    "INSERT INTO main.\"{table}\"({}) VALUES({})",
                    row.columns()
                        .iter()
                        .map(|c| format!("\"{}\"", c.name))
                        .collect::<Vec<_>>()
                        .join(","),
                    (1..=parameters.len())
                        .map(|n| format!("?{n}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            result.push(sync_extend_platform_fs::OriginalSqliteStatement {
                sql,
                parameters: parameters.into_iter().collect::<Result<Vec<_>>>()?,
                expected_changed_rows: 1,
            });
        }
    }
    for (key, row) in &new {
        if !allowed(&key.0) && old.get(key) != Some(row) {
            return Err(JournalError::Invariant(
                "original history changes another owner family",
            ));
        }
    }
    if result.is_empty() || result.len() > 1024 {
        return Err(JournalError::Invariant("original history statement count"));
    }
    Ok(result)
}

impl OriginalJournalWriteTransition {
    fn original_history_planner(&self) -> Result<Journal> {
        let bounds = self.inspection;
        let rows = self.original.read_queries(
            &self.complete_queries,
            OriginalSqliteReadBudget {
                max_queries: self.complete_queries.len(),
                max_rows: bounds.capacity.max_rows as usize,
                max_columns: 1024,
                max_owned_bytes: bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024),
                max_vm_instructions: bounds.max_vm_instructions,
                max_seconds: bounds.max_query_time.as_secs(),
            },
        )?;
        let memory = original_planning_memory(&rows, bounds)?;
        Journal::from_original_planning_memory(memory, &self.path, self.max_entries)
    }
    pub fn original_current_manifest(&self) -> Result<sync_extend_core_model::Manifest> {
        self.verify()?;
        self.original_history_planner()?
            .current(&self.space)?
            .ok_or(JournalError::Invariant(
                "original continuous current manifest absent",
            ))
    }
    pub fn original_device_id(&self) -> Result<sync_extend_core_model::DeviceId> {
        self.verify()?;
        self.original_history_planner()?
            .state("device_id")?
            .ok_or(JournalError::Invariant("original continuous device absent"))?
            .parse()
            .map_err(Into::into)
    }
}

impl OriginalJournalWriteTransition {
    pub fn require_original_cas_access(
        &self,
        content: &sync_extend_core_model::ContentId,
    ) -> Result<()> {
        self.verify()?;
        let planner = self.original_history_planner()?;
        planner.require_cas_access(content)?;
        self.verify()
    }
}

// Digest the same catalog/all-table values as the original live checkpoint.
impl JournalBackupImage {
    pub fn closed_node_complete_rows_digest(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<sync_extend_core_model::ContentId> {
        self.with_audited_readonly(space, bounds, |connection| {
            let mut names = Vec::new();
            let mut statement = connection
                .prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                if names.len() >= 1023 {
                    return Err(JournalError::Invariant("recovery table count"));
                }
                let name: String = row.get(0)?;
                if name.len() > 255 {
                    return Err(JournalError::Invariant("recovery table name bytes"));
                }
                names.push(name);
            }
            drop(rows);
            drop(statement);
            let mut queries = vec![
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name"
                    .to_owned(),
            ];
            for name in names {
                let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                let statement =
                    connection.prepare(&format!("SELECT * FROM main.{quoted} LIMIT 0"))?;
                let columns = statement.column_count();
                if columns == 0 || columns > 1024 {
                    return Err(JournalError::Invariant("recovery table columns"));
                }
                let order = (1..=columns)
                    .map(|index| index.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                queries.push(format!("SELECT * FROM main.{quoted} ORDER BY {order}"));
            }
            let mut hash = blake3::Hasher::new();
            fn bytes(hash: &mut blake3::Hasher, value: &[u8]) {
                hash.update(&(value.len() as u64).to_le_bytes());
                hash.update(value);
            }
            hash.update(b"OriginalJournalFullRows1");
            hash.update(&(queries.len() as u64).to_le_bytes());
            let mut aggregate = ExpectedAggregate { rows: 0, bytes: 0 };
            for sql in queries {
                let mut statement = connection.prepare(&sql)?;
                let table = expected_rows(&mut statement, bounds, &mut aggregate)?;
                hash.update(&(table.columns.len() as u64).to_le_bytes());
                for column in &table.columns {
                    bytes(&mut hash, column.as_bytes());
                }
                hash.update(&(table.rows.len() as u64).to_le_bytes());
                for row in table.rows {
                    hash.update(&(row.len() as u64).to_le_bytes());
                    for cell in row {
                        match cell {
                            OriginalSqliteValue::Null => {
                                hash.update(&[0]);
                            }
                            OriginalSqliteValue::Integer(value) => {
                                hash.update(&[1]);
                                hash.update(&value.to_le_bytes());
                            }
                            OriginalSqliteValue::Real(value) => {
                                hash.update(&[2]);
                                hash.update(&value.to_bits().to_le_bytes());
                            }
                            OriginalSqliteValue::Text(value) => {
                                hash.update(&[3]);
                                bytes(&mut hash, value.as_bytes());
                            }
                            OriginalSqliteValue::Blob(value) => {
                                hash.update(&[4]);
                                bytes(&mut hash, &value);
                            }
                        }
                    }
                }
            }
            Ok(sync_extend_core_model::ContentId::from_hasher(&hash))
        })
    }
}

// Normalize only the explicitly admitted session cell before full typed-row audit.
impl JournalBackupImage {
    pub fn recovered_session_preserved_rows_digest(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        expected_previous: &SpaceId,
        actual_fresh: &SpaceId,
    ) -> Result<sync_extend_core_model::ContentId> {
        self.with_audited_readonly(space, bounds, |connection| {
            let value: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key='original_recovery_session'",
                [],
                |row| row.get(0),
            )?;
            if value != actual_fresh.as_str() {
                return Err(JournalError::Invariant(
                    "fresh recovered session cell differs",
                ));
            }
            Ok(())
        })?;
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(self.bytes()),
            self.bytes().len(),
            false,
        )?;
        let changed = connection.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='original_recovery_session' AND value=?2",
            [expected_previous.as_str(), actual_fresh.as_str()])?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "fresh recovered exact session normalization",
            ));
        }
        let bytes = connection.serialize(rusqlite::MAIN_DB)?.to_vec();
        let image = JournalBackupImage::from_current_node_image(
            bytes.clone(),
            sync_extend_core_model::ContentId::hash(&bytes).as_str(),
            bytes.len(),
            space,
            bounds,
        )?;
        image.closed_node_complete_rows_digest(space, bounds)
    }
}


/// Opaque planner-issued ordinary history transition. Caller SQL cannot supply it.
pub struct RecoveredLocalHistoryPlan {
    statements:Vec<sync_extend_platform_fs::OriginalSqliteStatement>,
    queries:Vec<sync_extend_platform_fs::OriginalSqliteQuery>,
    before:Vec<sync_extend_platform_fs::OriginalSqliteRows>,
    after:Vec<sync_extend_platform_fs::OriginalSqliteRows>,
    budget:sync_extend_platform_fs::OriginalSqliteReadBudget,
    before_image:sync_extend_core_model::ContentId,
    root:sync_extend_core_model::SnapshotId,
}
impl RecoveredLocalHistoryPlan {
    pub fn execute(self,native:&mut sync_extend_platform_fs::FreshNativeWalConnection)
        ->Result<sync_extend_core_model::SnapshotId> {
        if sync_extend_core_model::ContentId::hash(&native.exact_main_bytes()?)!=self.before_image {
            return Err(JournalError::Invariant("recovered history exact before main changed"));
        }
        native.execute_planned_history(&self.statements,&self.queries,&self.before,&self.after,self.budget)?;
        Ok(self.root)
    }
}
impl JournalBackupImage {
    /// Same existing Journal planner, immutable old owner rows and original
    /// complete typed row diff; this object grants no ordinary native file rights.
    pub fn plan_recovered_local_history(
        &self,space:&SpaceId,expected_root:&sync_extend_core_model::SnapshotId,
        manifest:&sync_extend_core_model::Manifest,operations:&[sync_extend_core_model::Operation],
        timestamp:u64,bounds:NodeInspectionBounds,
    )->Result<RecoveredLocalHistoryPlan> {
        if manifest.space_id!=*space || operations.is_empty() || operations.len()>512 {
            return Err(JournalError::Invariant("recovered history exact scope bounds"));
        }
        let (queries,before)=self.with_audited_readonly(space,bounds,|connection| {
            let mut aggregate=ExpectedAggregate{rows:0,bytes:0};
            let mut sqls=vec!["SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name".to_owned()];
            let mut names=connection.prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")?;
            let names=names.query_map([],|row|row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            if names.len()>1023 {return Err(JournalError::Invariant("recovered history table count"));}
            for name in names {
                if name.len()>255 || name.starts_with("sqlite_") {return Err(JournalError::Invariant("recovered history table name"));}
                let quoted=format!("\"{}\"",name.replace('"',"\"\""));
                let count=connection.prepare(&format!("SELECT * FROM main.{quoted} LIMIT 0"))?.column_count();
                if count==0 || count>1024 {return Err(JournalError::Invariant("recovered history column count"));}
                let order=(1..=count).map(|n|n.to_string()).collect::<Vec<_>>().join(",");
                sqls.push(format!("SELECT * FROM main.{quoted} ORDER BY {order}"));
            }
            let mut queries=Vec::new();let mut before=Vec::new();
            for sql in sqls {
                before.push(expected_rows(&mut connection.prepare(&sql)?,bounds,&mut aggregate)?);
                queries.push(sync_extend_platform_fs::OriginalSqliteQuery{sql,parameters:Vec::new()});
            }
            Ok((queries,before))
        })?;
        let memory=original_planning_memory(&before,bounds)?;
        let mut planner=Journal::from_original_planning_memory(memory,std::path::Path::new("explicit-held-recovered-history"),bounds.max_entries)?;
        let before_audit={
            let snapshot=planner.connection.unchecked_transaction()?;
            let audit=planner.read_view().audit_original_provenance_capacity(space,bounds.max_entries,bounds.capacity)?;
            snapshot.rollback()?;audit
        };
        let root=planner.commit_local(Some(expected_root),manifest,operations,timestamp)?;
        let after_audit={
            let snapshot=planner.connection.unchecked_transaction()?;
            let audit=planner.read_view().audit_original_provenance_capacity(space,bounds.max_entries,bounds.capacity)?;
            snapshot.rollback()?;audit
        };
        let statements=original_history_diff(&before_audit.rows,&after_audit.rows)?;
        let mut aggregate=ExpectedAggregate{rows:0,bytes:0};let mut after=Vec::new();
        for query in &queries {after.push(expected_rows(&mut planner.connection.prepare(&query.sql)?,bounds,&mut aggregate)?);}
        let budget=sync_extend_platform_fs::OriginalSqliteReadBudget {
            max_queries:queries.len(),max_rows:bounds.capacity.max_rows.try_into()
                .map_err(|_|JournalError::Invariant("recovered history row bound"))?,
            max_columns:1024,max_owned_bytes:bounds.capacity.max_logical_bytes.min(256*1024*1024),
            max_vm_instructions:bounds.max_vm_instructions,max_seconds:bounds.max_query_time.as_secs(),
        };
        Ok(RecoveredLocalHistoryPlan {statements,queries,before,after,budget,
            before_image:sync_extend_core_model::ContentId::hash(self.bytes()),root})
    }
}

impl JournalBackupImage {
    /// Audit with the same typed whole-catalog queries and immutable-history
    /// difference rules used by the production ordinary history planner.
    pub fn audit_recovered_history_extension(
        &self,
        baseline: &JournalBackupImage,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<()> {
        fn rows(
            image: &JournalBackupImage,
            space: &SpaceId,
            bounds: NodeInspectionBounds,
        ) -> Result<Vec<OriginalSqliteRows>> {
            image.with_audited_readonly(space, bounds, |connection| {
                let mut names = connection.prepare(
                    "SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name",
                )?;
                let names = names
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if names.len() > 1023 {
                    return Err(JournalError::Invariant("history extension table bound"));
                }
                let mut queries = vec![
                    "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name"
                        .to_owned(),
                ];
                for name in names {
                    if name.len() > 255 || name.starts_with("sqlite_") {
                        return Err(JournalError::Invariant("history extension exact catalog"));
                    }
                    let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                    let count = connection
                        .prepare(&format!("SELECT * FROM main.{quoted} LIMIT 0"))?
                        .column_count();
                    if count == 0 || count > 1024 {
                        return Err(JournalError::Invariant("history extension columns"));
                    }
                    let order = (1..=count)
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    queries.push(format!("SELECT * FROM main.{quoted} ORDER BY {order}"));
                }
                let mut aggregate = ExpectedAggregate { rows: 0, bytes: 0 };
                queries
                    .iter()
                    .map(|sql| expected_rows(&mut connection.prepare(sql)?, bounds, &mut aggregate))
                    .collect()
            })
        }
        let old = rows(baseline, space, bounds)?;
        let new = rows(self, space, bounds)?;
        if old.len() != new.len() {
            return Err(JournalError::Invariant(
                "history extension complete catalog count",
            ));
        }
        compare_rows(&old[0], &new[0])?;
        for (old, new) in old.iter().zip(&new) {
            if old.columns != new.columns {
                return Err(JournalError::Invariant("history extension exact columns"));
            }
        }
        let old_planner = Journal::from_original_planning_memory(
            original_planning_memory(&old, bounds)?,
            std::path::Path::new("held-history-baseline"),
            bounds.max_entries,
        )?;
        let new_planner = Journal::from_original_planning_memory(
            original_planning_memory(&new, bounds)?,
            std::path::Path::new("held-history-final"),
            bounds.max_entries,
        )?;
        let old_audit = {
            let snapshot = old_planner.connection.unchecked_transaction()?;
            let audit = old_planner.read_view().audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            snapshot.rollback()?;
            audit
        };
        let new_audit = {
            let snapshot = new_planner.connection.unchecked_transaction()?;
            let audit = new_planner.read_view().audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            snapshot.rollback()?;
            audit
        };
        let _ = original_history_diff(&old_audit.rows, &new_audit.rows)?;
        Ok(())
    }
}

impl JournalBackupImage {
    /// Normalize exactly one private-session cell in an independent planning
    /// image after its current value is checked. No native file is changed.
    pub fn normalize_recovered_history_session(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        previous: &SpaceId,
        current: &SpaceId,
    ) -> Result<JournalBackupImage> {
        self.recovered_session_preserved_rows_digest(space, bounds, previous, current)?;
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(self.bytes()),
            self.bytes().len(),
            false,
        )?;
        if connection.execute("UPDATE main.local_state SET value=?1 WHERE key='original_recovery_session' AND value=?2",
            [previous.as_str(),current.as_str()])?!=1 {
            return Err(JournalError::Invariant("history chain exact single cell normalization"));
        }
        let bytes = connection.serialize(rusqlite::MAIN_DB)?.to_vec();
        JournalBackupImage::from_current_node_image(
            bytes.clone(),
            sync_extend_core_model::ContentId::hash(&bytes).as_str(),
            bytes.len(),
            space,
            bounds,
        )
    }
}

// Private Journal image audit, never a producer of native or cleanup rights.
#[derive(serde::Serialize)]
pub struct RecoveredImmutableHistoryInventory {
    pub baseline_image: sync_extend_core_model::ContentId,
    pub current_image: sync_extend_core_model::ContentId,
    pub retained_rows: usize,
    pub retained_logical_bytes: u64,
    pub retained_fingerprint: sync_extend_core_model::ContentId,
    pub immutable_operation_rows: usize,
    pub immutable_snapshot_rows: usize,
    pub immutable_snapshot_object_rows: usize,
    pub immutable_signed_provenance_rows: usize,
    pub immutable_owner_rows: usize,
    pub release_authority: bool,
    pub pending_attempt_resume_authority: bool,
}

impl JournalBackupImage {
    pub fn audit_recovered_immutable_history_inventory(
        &self,
        baseline: &JournalBackupImage,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<RecoveredImmutableHistoryInventory> {
        fn audited_image_rows(
            image: &JournalBackupImage,
            space: &SpaceId,
            bounds: NodeInspectionBounds,
        ) -> Result<Vec<crate::JournalStoredRow>> {
            image.with_audited_readonly(space, bounds, |connection| {
                // This private callback runs inside the deferred read snapshot
                // owned by with_audited_readonly. Its limits cover the complete
                // provenance audit; opening another transaction here would
                // issue a second BEGIN on the same connection.
                crate::JournalReadView { connection }
                    .audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)
                    .map(|audit| audit.rows)
            })
        }
        let old = audited_image_rows(baseline, space, bounds)?;
        let current = audited_image_rows(self, space, bounds)?;
        let mut indexed = std::collections::BTreeMap::new();
        for row in &current {
            let key = (row.table().to_owned(), row.primary_key().to_vec());
            if indexed.insert(key, row).is_some() {
                return Err(JournalError::Invariant("live immutable history current duplicate key"));
            }
        }
        let mut retained = 0usize;
        let mut bytes = 0u64;
        let mut count = [0usize; 5];
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(b"sync-extend.recovered-immutable-history.v1");
        for row in &old {
            // Only independent ordinary current/cursor cells evolve here.
            // Every old operation, snapshot, pin, signature and native attempt
            // remains byte exact; no native receipt is rewritten for this root.
            if matches!(row.table(), "current_manifests" | "receive_cursors") {
                continue;
            }
            let key = (row.table().to_owned(), row.primary_key().to_vec());
            if indexed.get(&key).is_none_or(|current| *current != row) {
                return Err(JournalError::Invariant("live immutable original history row changed"));
            }
            retained = retained.checked_add(1)
                .filter(|count| *count <= bounds.max_entries)
                .ok_or(JournalError::Invariant("live immutable history row budget"))?;
            bytes = bytes.checked_add(row.logical_bytes())
                .filter(|bytes| *bytes <= bounds.capacity.max_logical_bytes.min(256 * 1024 * 1024))
                .ok_or(JournalError::Invariant("live immutable history byte budget"))?;
            let encoded = serde_json::to_vec(row)?;
            fingerprint.update(&(encoded.len() as u64).to_le_bytes());
            fingerprint.update(&encoded);
            match row.table() {
                "operations" => count[0] += 1,
                "snapshots" => count[1] += 1,
                "snapshot_objects" => count[2] += 1,
                "original_operation_provenance" => count[3] += 1,
                _ if row.table().contains("native") || row.table().contains("attempt")
                    || row.table().contains("publication") || row.table().contains("restore")
                    || row.table().contains("pin") => count[4] += 1,
                _ => {}
            }
        }
        Ok(RecoveredImmutableHistoryInventory {
            baseline_image: sync_extend_core_model::ContentId::hash(baseline.bytes()),
            current_image: sync_extend_core_model::ContentId::hash(self.bytes()),
            retained_rows: retained,
            retained_logical_bytes: bytes,
            retained_fingerprint: sync_extend_core_model::ContentId::from_hasher(&fingerprint),
            immutable_operation_rows: count[0],
            immutable_snapshot_rows: count[1],
            immutable_snapshot_object_rows: count[2],
            immutable_signed_provenance_rows: count[3],
            immutable_owner_rows: count[4],
            release_authority: false,
            pending_attempt_resume_authority: false,
        })
    }
}
