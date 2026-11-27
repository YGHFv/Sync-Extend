//! One private Journal connection over the same consumed Unix original IO owner.
//! No public Connection, SQL callback, native issuer, or pathname reopen exists.
use crate::{
    Journal, JournalBackupImage, JournalError, JournalReadView, JournalStoredRow,
    NodeInspectionBounds, Result,
};
use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
    Transaction, TransactionBehavior,
};
use std::time::Instant;
use sync_extend_core_model::SpaceId;
use sync_extend_platform_fs::{
    ClosedUnixOriginalResources, FreshUnixNativeSqliteIo, FreshUnixNativeSqliteIoFailure,
};

struct OriginalInspectionCall<'a> {
    connection: &'a mut crate::journal_connection_owner::JournalConnectionOwner,
    started: Instant,
    duration: std::time::Duration,
    cleared: bool,
}
impl<'a> OriginalInspectionCall<'a> {
    fn begin(
        connection: &'a mut crate::journal_connection_owner::JournalConnectionOwner,
        bounds: NodeInspectionBounds,
    ) -> Result<Self> {
        let started = Instant::now();
        let duration = bounds.max_query_time;
        let mut remaining = bounds.max_vm_instructions;
        connection.progress_handler(
            1000,
            Some(move || {
                if remaining < 1000 || started.elapsed() >= duration {
                    true
                } else {
                    remaining -= 1000;
                    false
                }
            }),
        )?;
        Ok(Self {
            connection,
            started,
            duration,
            cleared: false,
        })
    }
    fn finish(mut self, result: Result<()>) -> Result<()> {
        let elapsed = self.started.elapsed();
        let clear = self.connection.progress_handler(0, None::<fn() -> bool>);
        self.cleared = clear.is_ok();
        match result {
            Err(error) => Err(error),
            Ok(()) => {
                clear?;
                if elapsed >= self.duration {
                    return Err(JournalError::Invariant(
                        "original Unix inspection deadline completed late",
                    ));
                }
                Ok(())
            }
        }
    }
}
impl Drop for OriginalInspectionCall<'_> {
    fn drop(&mut self) {
        if !self.cleared {
            let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
        }
    }
}

pub struct OriginalUnixRestoredJournal<'namespace> {
    journal: Option<Journal>,
    unprepared: Option<crate::journal_connection_owner::JournalConnectionOwner>,
    opening: Option<crate::raw_open::OriginalSqliteOpening>,
    io: Option<FreshUnixNativeSqliteIo<'namespace>>,
    space: SpaceId,
    expected: Vec<JournalStoredRow>,
    bounds: NodeInspectionBounds,
}

pub struct OriginalUnixRestoredJournalFailure<'namespace> {
    pub error: JournalError,
    original: Option<OriginalUnixRestoredJournal<'namespace>>,
    pub original_io: Option<FreshUnixNativeSqliteIoFailure<'namespace>>,
}

impl std::fmt::Debug for OriginalUnixRestoredJournalFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalUnixRestoredJournalFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .field("original_io_retained", &self.original_io.is_some())
            .finish()
    }
}

impl OriginalUnixRestoredJournalFailure<'_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self
                .original_io
                .as_ref()
                .is_some_and(FreshUnixNativeSqliteIoFailure::has_retained_originals)
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.take() {
            if let Err(mut later) = original.close_retaining() {
                self.original = later.original.take();
                self.original_io = later.original_io.take();
            }
        }
        if let Some(original) = self.original_io.take() {
            self.original_io = Some(original.close_remaining());
        }
        self
    }
}

fn restricted(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Transaction { .. }
        | AuthAction::Savepoint { .. }
        | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Pragma { pragma_name, .. }
            if matches!(
                pragma_name.to_ascii_lowercase().as_str(),
                "table_list"
                    | "table_info"
                    | "table_xinfo"
                    | "index_list"
                    | "index_info"
                    | "index_xinfo"
                    | "foreign_key_list"
            ) =>
        {
            // These introspection pragmas take a table/index name as their
            // argument; it is never a writable pragma value. The same fixed
            // catalog audit uses both scalar and table-valued spellings.
            Authorization::Allow
        }
        AuthAction::Pragma {
            pragma_name,
            pragma_value: None,
        } if matches!(
            pragma_name.to_ascii_lowercase().as_str(),
            "user_version"
                | "integrity_check"
                | "foreign_key_check"
                | "page_size"
                | "page_count"
                | "journal_mode"
                | "data_version"
                | "schema_version"
        ) =>
        {
            Authorization::Allow
        }
        _ => {
            #[cfg(feature = "fault-injection")]
            eprintln!(
                "original Unix Journal denied SQL action: {:?}",
                context.action
            );
            Authorization::Deny
        }
    }
}

impl<'namespace> OriginalUnixRestoredJournal<'namespace> {
    /// Consumes only a real platform IO owner and a complete audited source.
    /// Source mapping occurs before any creator effect, and every live stored
    /// row must remain identical to the validated immutable mapped image.
    pub fn open_original(
        io: FreshUnixNativeSqliteIo<'namespace>,
        image: &JournalBackupImage,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> std::result::Result<Self, OriginalUnixRestoredJournalFailure<'namespace>> {
        let mut original = Self {
            journal: None,
            unprepared: None,
            opening: None,
            io: Some(io),
            space: space.clone(),
            expected: Vec::new(),
            bounds,
        };
        let checked = (|| -> Result<()> {
            bounds.validate()?;
            original.expected = JournalBackupImage::inspect_current_node_image_with_audit_rows(
                image.bytes(),
                image.digest(),
                image.bytes().len(),
                space,
                bounds,
                |_, rows, _| Ok(rows.to_vec()),
            )?
            .1;
            let io = original.io.as_ref().expect("actual original Unix IO owner");
            io.verify()?;
            let scope = io.single_open_scope()?;
            let path = std::ffi::CString::new(scope.database_path()?)
                .map_err(|_| JournalError::Invariant("original Unix SQLite path encoding"))?;
            let name = std::ffi::CString::new(scope.vfs_name()?)
                .map_err(|_| JournalError::Invariant("original Unix SQLite VFS encoding"))?;
            let opened = crate::raw_open::open_retaining(&path, &name);
            drop(scope);
            match opened {
                Ok(connection) => original.unprepared = Some(connection.into()),
                Err(failure) => {
                    original.opening = failure.original;
                    return Err(failure.error.into());
                }
            }
            io.verify_connection_opened()?;
            let connection = original
                .unprepared
                .as_mut()
                .expect("same original connection");
            connection.execute_batch("PRAGMA temp_store=MEMORY;PRAGMA mmap_size=0;PRAGMA synchronous=FULL;PRAGMA locking_mode=EXCLUSIVE;PRAGMA journal_mode=WAL;PRAGMA trusted_schema=OFF;")?;
            let mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            if mode != "wal" {
                return Err(JournalError::Invariant(
                    "original Unix Journal WAL mode required",
                ));
            }
            for (category, maximum) in [
                (Limit::SQLITE_LIMIT_LENGTH, 32 * 1024 * 1024),
                (Limit::SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024),
                (Limit::SQLITE_LIMIT_ATTACHED, 0),
                (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            ] {
                connection.set_limit(category, maximum)?;
                if connection.limit(category)? > maximum {
                    return Err(JournalError::Invariant(
                        "original Unix SQL limit was not applied",
                    ));
                }
            }
            let path = std::path::Path::new(
                std::str::from_utf8(path.as_bytes())
                    .map_err(|_| JournalError::Invariant("actual Unix Journal path UTF8"))?,
            );
            // The constructor only validates/registers callbacks on this
            // original. Its complete schema preparation shares one bounded
            // operation; it never opens or initializes another database.
            let budget = crate::original_observation_budget::OriginalObservationBudget::new(bounds);
            let scope = budget.begin()?;
            connection.progress_handler(1_000, Some(move || budget.interrupt()))?;
            let connection = original
                .unprepared
                .take()
                .expect("same actual opened connection");
            match Journal::from_original_planning_connection_owner_retaining(
                connection,
                path,
                bounds.max_entries,
            ) {
                Ok(journal) => original.journal = Some(journal),
                Err((connection, error)) => {
                    original.unprepared = Some(connection);
                    return Err(error);
                }
            }
            let connection = &mut original
                .journal
                .as_mut()
                .expect("same original Journal")
                .connection;
            let bounded = scope.finish();
            let cleared = connection.progress_handler(0, None::<fn() -> bool>);
            bounded?;
            cleared?;
            connection.authorizer(Some(restricted))?;
            original.verify()
        })();
        match checked {
            Ok(()) => Ok(original),
            Err(error) => Err(OriginalUnixRestoredJournalFailure {
                error,
                original: Some(original),
                original_io: None,
            }),
        }
    }

    pub fn verify(&mut self) -> Result<()> {
        self.bounds.validate()?;
        let io = self
            .io
            .as_ref()
            .ok_or(JournalError::Invariant("original Unix Journal IO closed"))?;
        io.verify_connection_opened()?;
        let connection = &mut self
            .journal
            .as_mut()
            .ok_or(JournalError::Invariant(
                "original Unix Journal connection closed",
            ))?
            .connection;
        if !connection.is_autocommit() {
            return Err(JournalError::Invariant(
                "original Unix Journal caller transaction present",
            ));
        }
        let call = OriginalInspectionCall::begin(connection, self.bounds)?;
        let checked = (|| -> Result<()> {
            let connection = &*call.connection;
            if crate::backup_image::validate(connection)? != crate::SCHEMA_VERSION {
                return Err(JournalError::Invariant(
                    "original Unix Journal actual catalog version differs",
                ));
            }
            let transaction =
                Transaction::new_unchecked(connection, TransactionBehavior::Deferred)?;
            let view = JournalReadView {
                connection,
                dav_read_charge_cache: None,
            };
            let actual = view.audit_original_provenance_capacity(
                &self.space,
                self.bounds.max_entries,
                self.bounds.capacity,
            )?;
            if actual.rows.len() != self.expected.len()
                || actual
                    .rows
                    .iter()
                    .zip(&self.expected)
                    .any(|(a, b)| a.fingerprint() != b.fingerprint())
            {
                return Err(JournalError::Invariant(
                    "actual original Unix Journal mapped rows differ",
                ));
            }
            transaction.rollback()?;
            io.verify()?;
            Ok(())
        })();
        call.finish(checked)
    }

    pub fn close_retaining(
        mut self,
    ) -> std::result::Result<
        ClosedUnixOriginalResources,
        OriginalUnixRestoredJournalFailure<'namespace>,
    > {
        let first = self.verify().err();
        if let Some(journal) = self.journal.as_mut() {
            if let Err(error) = journal.connection.close_original_in_place() {
                return Err(OriginalUnixRestoredJournalFailure {
                    error: first.unwrap_or(error.into()),
                    original: Some(self),
                    original_io: None,
                });
            }
        }
        self.journal = None;
        if let Some(connection) = self.unprepared.take() {
            if let Err((connection, error)) = connection.close() {
                self.unprepared = Some(connection);
                return Err(OriginalUnixRestoredJournalFailure {
                    error: first.unwrap_or(error.into()),
                    original: Some(self),
                    original_io: None,
                });
            }
        }
        if let Some(opening) = self.opening.as_mut() {
            if let Err(error) = opening.close_original() {
                return Err(OriginalUnixRestoredJournalFailure {
                    error: first.unwrap_or(error.into()),
                    original: Some(self),
                    original_io: None,
                });
            }
        }
        self.opening = None;
        let io = self
            .io
            .take()
            .expect("original IO retained until connection terminal");
        match io.close_retaining() {
            Ok(closed) if first.is_none() => Ok(closed),
            Ok(_) => Err(OriginalUnixRestoredJournalFailure {
                error: first.expect("earlier original failure"),
                original: None,
                original_io: None,
            }),
            Err(original_io) => Err(OriginalUnixRestoredJournalFailure {
                error: first.unwrap_or_else(|| {
                    JournalError::Io(std::io::Error::other(original_io.error.to_string()))
                }),
                original: None,
                original_io: Some(original_io),
            }),
        }
    }
}

impl Drop for OriginalUnixRestoredJournal<'_> {
    fn drop(&mut self) {
        if let Some(journal) = self.journal.take() {
            let _ = Box::leak(Box::new(journal));
        }
        if let Some(connection) = self.unprepared.take() {
            let _ = Box::leak(Box::new(connection));
        }
        if let Some(opening) = self.opening.take() {
            let _ = Box::leak(Box::new(opening));
        }
        if let Some(io) = self.io.take() {
            let _ = Box::leak(Box::new(io));
        }
    }
}
