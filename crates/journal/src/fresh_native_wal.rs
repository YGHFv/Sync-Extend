//! High-level SQLite ownership over the original Windows VFS/handle capsule.
//! The only Connection is private to journal; platform owns its original IO.
use std::{
    io,
    path::{Path, PathBuf},
};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, FileKey, FreshExclusiveSqliteFile, FreshNativeRetentionLease,
    FreshNativeWalIo, FreshNativeWalIoCloseFailure, FreshNativeWalIoOpenFailure,
    WindowsOriginalCloseAttempt, WindowsOriginalResourceCloseFailure,
};

pub struct FreshNativeWalConnection {
    connection: Option<rusqlite::Connection>,
    opening_connection: Option<crate::raw_open::OriginalSqliteOpening>,
    io: Option<FreshNativeWalIo>,
    path: PathBuf,
    attempted: bool,
    original_terminal_error: Option<io::Error>,
}

pub struct FreshNativeWalOpenFailure {
    pub error: io::Error,
    pub original_resources: Option<FreshNativeWalCloseFailure>,
}
impl FreshNativeWalOpenFailure {
    pub fn retain_and_report(self) -> io::Error {
        if let Some(original) = self.original_resources {
            original.retain_until_process_exit();
        }
        self.error
    }
    fn from_io(failure: FreshNativeWalIoOpenFailure) -> Self {
        Self {
            error: failure.error,
            original_resources: failure.original_resources.map(|original| {
                FreshNativeWalCloseFailure {
                    error: copy_original_error(&original.error),
                    actual_closed_handles: original.actual_closed_handles,
                    original_owner: None,
                    original_resources: None,
                    original_io: Some(original),
                }
            }),
        }
    }
}

pub struct FreshNativeWalCloseFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original_owner: Option<FreshNativeWalConnection>,
    original_resources: Option<WindowsOriginalResourceCloseFailure>,
    original_io: Option<FreshNativeWalIoCloseFailure>,
}
impl std::fmt::Debug for FreshNativeWalCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FreshNativeWalCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field("originals_retained", &self.has_retained_originals())
            .finish()
    }
}
fn copy_original_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}
impl FreshNativeWalCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_owner
            .as_ref()
            .is_some_and(FreshNativeWalConnection::original_resources_remain)
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
            || self
                .original_io
                .as_ref()
                .is_some_and(FreshNativeWalIoCloseFailure::has_retained_originals)
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_io.take() {
            let original = original.close_remaining();
            self.actual_closed_handles = original.actual_closed_handles;
            self.original_io = Some(original);
            return self;
        }
        let mut attempt = WindowsOriginalCloseAttempt::new();
        // The original terminal always carries the actual witness or failure;
        // integer counts can never manufacture a closed-handle prefix.
        if let Some(original) = self.original_resources.take() {
            attempt.append_failure(original.close_remaining());
        } else {
            attempt.note_error(copy_original_error(&self.error));
        }
        if let Some(mut original) = self.original_owner.take() {
            original.close_original_into_attempt(&mut attempt);
            if original.original_resources_remain() {
                self.original_owner = Some(original);
            }
        }
        let original = match attempt.finish() {
            Err(original) => original,
            Ok(_) => unreachable!("original terminal failure cannot disappear"),
        };
        self.actual_closed_handles = original.actual_closed_handles;
        self.original_resources = Some(original);
        self
    }
    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}
impl FreshNativeWalConnection {
    fn io_ref(&self) -> &FreshNativeWalIo {
        self.io
            .as_ref()
            .expect("usable original SQLite retains its IO")
    }
    fn from_io(path: &Path, io: FreshNativeWalIo) -> Result<Self, FreshNativeWalOpenFailure> {
        let mut owner = Self {
            connection: None,
            opening_connection: None,
            io: Some(io),
            path: path.to_owned(),
            attempted: false,
            original_terminal_error: None,
        };
        let opened = (|| {
            let scope = owner
                .io
                .as_mut()
                .expect("original IO")
                .single_open_scope()
                .map_err(|error| crate::raw_open::OriginalSqliteOpenFailure {
                    error,
                    original: None,
                })?;
            crate::raw_open::open_retaining(scope.database_path(), scope.vfs_name())
        })();
        match opened {
            Ok(connection) => owner.connection = Some(connection),
            Err(failure) => {
                owner.opening_connection = failure.original;
                return Err(owner.reject_open(failure.error));
            }
        }
        let checked = owner
            .connection
            .as_ref()
            .expect("same opened connection")
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(io::Error::other)
            .and_then(|()| owner.io_ref().verify_connection_opened())
            .and_then(|()| owner.verify());
        if let Err(error) = checked {
            return Err(owner.reject_open(error));
        }
        Ok(owner)
    }
    pub fn open(
        path: &Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
    ) -> io::Result<Self> {
        Self::open_retaining(path, files, limits)
            .map_err(FreshNativeWalOpenFailure::retain_and_report)
    }
    pub fn open_retaining(
        path: &Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
    ) -> Result<Self, FreshNativeWalOpenFailure> {
        let io = FreshNativeWalIo::open_retaining(path, files, limits)
            .map_err(FreshNativeWalOpenFailure::from_io)?;
        Self::from_io(path, io)
    }
    pub fn open_after_explicit_shm_epoch(
        path: &Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
        expected_shm: (&str, &[u8]),
    ) -> io::Result<Self> {
        Self::open_after_explicit_shm_epoch_retaining(path, files, limits, expected_shm)
            .map_err(FreshNativeWalOpenFailure::retain_and_report)
    }
    pub fn open_after_explicit_shm_epoch_retaining(
        path: &Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
        expected_shm: (&str, &[u8]),
    ) -> Result<Self, FreshNativeWalOpenFailure> {
        let io = FreshNativeWalIo::open_after_explicit_shm_epoch_retaining(
            path,
            files,
            limits,
            expected_shm,
        )
        .map_err(FreshNativeWalOpenFailure::from_io)?;
        Self::from_io(path, io)
    }
    pub fn verify(&self) -> io::Result<()> {
        if self.connection.is_none() {
            return Err(io::Error::other("fresh native WAL SQLite uncertain"));
        }
        self.io_ref().verify_connection_opened()
    }
    pub fn keys(&self) -> io::Result<[FileKey; 3]> {
        self.verify()?;
        let keys = self.io_ref().all_native_keys()?;
        Ok([keys[0], keys[1], keys[2]])
    }
    pub fn all_native_keys(&self) -> io::Result<[FileKey; 4]> {
        self.io_ref().all_native_keys()
    }
    pub fn held_shm_bytes(&self) -> io::Result<Vec<u8>> {
        self.io_ref().held_shm_bytes()
    }
    pub fn exact_main_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        self.io_ref().exact_bytes(0)
    }
    pub fn shm_mapping_active(&self) -> io::Result<bool> {
        self.verify()?;
        self.io_ref().shm_mapping_active()
    }
    fn original_resources_remain(&self) -> bool {
        self.connection.is_some() || self.opening_connection.is_some() || self.io.is_some()
    }
    fn close_original_sqlite_connection(&mut self) -> io::Result<()> {
        let result = (|| {
            if let Some(connection) = self.connection.take() {
                if let Err((connection, error)) = connection.close() {
                    self.connection = Some(connection);
                    return Err(io::Error::other(error));
                }
            }
            if let Some(original) = self.opening_connection.as_mut() {
                original.close_original()?;
            }
            self.opening_connection = None;
            Ok(())
        })();
        if let Err(error) = &result {
            self.original_terminal_error
                .get_or_insert_with(|| copy_original_error(error));
        }
        result
    }
    fn close_original_shm_retaining(&mut self) -> io::Result<()> {
        self.io
            .as_mut()
            .expect("same original IO")
            .close_shm_retaining()
    }
    fn close_original_into_attempt(&mut self, attempt: &mut WindowsOriginalCloseAttempt) {
        if let Some(error) = self.original_terminal_error.take() {
            attempt.note_error(error);
        }
        if let Err(error) = self.close_original_sqlite_connection() {
            attempt.note_error(error);
            return;
        }
        if let Some(original) = self.io.as_mut() {
            original.close_into_original_attempt(attempt);
            if !original.original_resources_remain() {
                self.io = None;
            }
        }
    }
    pub fn verify_closed_native_objects(&self) -> io::Result<()> {
        if self.connection.is_some() || self.opening_connection.is_some() {
            return Err(io::Error::other(
                "fresh native WAL actual close not confirmed",
            ));
        }
        self.io_ref().verify_closed_native_objects()
    }
    pub fn exact_closed_main_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify_closed_native_objects()?;
        self.io_ref().exact_bytes(0)
    }
    pub fn exact_sidecar_bytes(&self, index: usize) -> io::Result<Vec<u8>> {
        if !(1..=3).contains(&index) {
            return Err(io::Error::other("actual WAL sidecar index"));
        }
        if self.connection.is_some() {
            self.verify()?;
        } else {
            self.verify_closed_native_objects()?;
        }
        self.io_ref().exact_bytes(index)
    }
    pub fn issue_retention_lease(&self, generation: u32) -> io::Result<FreshNativeRetentionLease> {
        self.verify()?;
        if !self.attempted {
            return Err(io::Error::other(
                "retention requires a committed live native session",
            ));
        }
        self.io_ref().issue_retention_lease(generation)
    }
    pub fn verify_retention_lease(&self, lease: &FreshNativeRetentionLease) -> io::Result<()> {
        self.verify()?;
        if !self.attempted {
            return Err(io::Error::other(
                "retention issuer requires committed live session",
            ));
        }
        self.io_ref().verify_retention_lease(lease)
    }
    fn reject_open(self, error: io::Error) -> FreshNativeWalOpenFailure {
        FreshNativeWalOpenFailure {
            error,
            original_resources: self.close_original_resources_retaining().err(),
        }
    }
    pub fn commit_fresh_session(&mut self, expected: &str, fresh: &str) -> io::Result<()> {
        self.verify()?;
        if self.attempted
            || expected.len() != 32
            || fresh.len() != 32
            || expected == fresh
            || !expected
                .bytes()
                .chain(fresh.bytes())
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(io::Error::other(
                "fresh session bounded single attempt required",
            ));
        }
        self.attempted = true;
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| io::Error::other("fresh WAL SQLite closed"))?;
        for (category, value) in [
            (rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024),
            (rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 65536),
        ] {
            connection
                .set_limit(category, value)
                .map_err(|error| io::Error::other(format!("first session limits: {error}")))?;
        }
        let started = std::time::Instant::now();
        let mut remaining = 100_000_000u64;
        connection
            .progress_handler(
                1000,
                Some(move || {
                    if remaining < 1000 || started.elapsed() > std::time::Duration::from_secs(60) {
                        return true;
                    }
                    remaining -= 1000;
                    false
                }),
            )
            .map_err(|error| io::Error::other(format!("first session vmguard: {error}")))?;
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|error| io::Error::other(format!("first session busy: {error}")))?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(|error| io::Error::other(format!("first session tempstore: {error}")))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| io::Error::other(format!("first session synchronous: {error}")))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| io::Error::other(format!("first session journalmode: {error}")))?;
        connection
            .pragma_update(None, "locking_mode", "NORMAL")
            .map_err(|error| io::Error::other(format!("first session lockingmode: {error}")))?;
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(|error| io::Error::other(format!("first session autocheckpoint: {error}")))?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| io::Error::other(format!("first session begin: {error}")))?;
        let result=connection.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='original_recovery_session' AND value=?2",
            [fresh,expected]);
        match result {
            Ok(1) => connection
                .execute_batch("COMMIT")
                .map_err(|error| io::Error::other(format!("first session commit: {error}")))?,
            result => {
                let _ = connection.execute_batch("ROLLBACK");
                self.io_ref().poison();
                return Err(io::Error::other(format!(
                    "fresh session exact CAS failed: {result:?}"
                )));
            }
        }
        self.verify()
    }
    pub fn close_original_resources_retaining(
        mut self,
    ) -> Result<sync_extend_platform_fs::ClosedWindowsOriginalResources, FreshNativeWalCloseFailure>
    {
        let mut attempt = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        self.close_original_into_attempt(&mut attempt);
        match attempt.finish() {
            Ok(closed) if !self.original_resources_remain() => Ok(closed),
            Ok(_) => unreachable!("a retained original native resource records a terminal error"),
            Err(original) => Err(FreshNativeWalCloseFailure {
                error: copy_original_error(&original.error),
                actual_closed_handles: original.actual_closed_handles,
                original_owner: if self.original_resources_remain() {
                    Some(self)
                } else {
                    None
                },
                original_resources: Some(original),
                original_io: None,
            }),
        }
    }
    pub fn close_actual_connection_after_failure(&mut self) -> io::Result<()> {
        self.io_ref().poison();
        self.close_original_sqlite_connection()?;
        self.close_original_shm_retaining()
    }
    pub fn close_connection_retaining_native_objects(&mut self) -> io::Result<()> {
        self.verify()?;
        if let Err(error) = self.close_original_sqlite_connection() {
            self.io_ref().poison();
            return Err(error);
        }
        self.close_original_shm_retaining()?;
        self.verify_closed_native_objects()
    }
    pub fn verification_change_counters(&self) -> io::Result<Option<(u64, u64)>> {
        let connection = match self.connection.as_ref() {
            Some(connection) => {
                self.verify()?;
                connection
            }
            None => {
                self.verify_closed_native_objects()?;
                return Ok(None);
            }
        };
        let data_version: i64 = connection
            .pragma_query_value(Some("main"), "data_version", |row| row.get(0))
            .map_err(|error| io::Error::other(format!("native WAL data_version: {error}")))?;
        let data_version = u64::try_from(data_version)
            .map_err(|_| io::Error::other("native WAL data_version negative"))?;
        Ok(Some((data_version, connection.total_changes())))
    }
    pub fn checkpoint_wal(&mut self) -> io::Result<()> {
        self.verify()?;
        let row: (i64, i64, i64) = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("actual WAL connection closed"))?
            .query_row("PRAGMA main.wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| io::Error::other(format!("native WAL checkpoint: {error}")))?;
        if row.0 != 0 || row.1 != row.2 || !self.io_ref().exact_bytes(1)?.is_empty() {
            self.io_ref().poison();
            return Err(io::Error::other("actual WAL checkpoint incomplete"));
        }
        self.verify()
    }
    pub fn checkpoint_to_standalone(&mut self) -> io::Result<()> {
        self.checkpoint_wal()?;
        let mode: String = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("actual WAL closed"))?
            .query_row("PRAGMA main.journal_mode=PERSIST", [], |row| row.get(0))
            .map_err(|error| io::Error::other(format!("native standalone mode: {error}")))?;
        if !mode.eq_ignore_ascii_case("persist")
            || self.io_ref().exact_bytes(0)?.get(18..20) != Some(&[1, 1])
            || !self.io_ref().exact_bytes(1)?.is_empty()
        {
            self.io_ref().poison();
            return Err(io::Error::other(
                "actual SQLite standalone checkpoint not confirmed",
            ));
        }
        // This budget belongs to the completed first session commit/checkpoint.
        // Leaving its elapsed wall clock attached would poison unrelated later
        // bounded history calls. Each history row/DML audit installs its own
        // original VM guard; remove this completed guard only after checkpoint.
        self.connection
            .as_mut()
            .ok_or_else(|| io::Error::other("checkpoint connection closed"))?
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(io::Error::other)?;
        self.verify()
    }
    pub fn execute_retention_metadata(
        &mut self,
        lease: &FreshNativeRetentionLease,
        statements: &[sync_extend_platform_fs::OriginalSqliteStatement],
        queries: &[sync_extend_platform_fs::OriginalSqliteQuery],
        before: &[sync_extend_platform_fs::OriginalSqliteRows],
        after: &[sync_extend_platform_fs::OriginalSqliteRows],
        budget: sync_extend_platform_fs::OriginalSqliteReadBudget,
        gc_mark: bool,
    ) -> io::Result<()> {
        self.verify_retention_lease(lease)?;
        if statements.len() > 1024
            || statements
                .iter()
                .try_fold(0usize, |n, s| {
                    n.checked_add(
                        s.sql.len()
                            + s.parameters
                                .iter()
                                .map(|v| match v {
                                    sync_extend_platform_fs::OriginalSqliteValue::Text(v) => {
                                        v.len()
                                    }
                                    sync_extend_platform_fs::OriginalSqliteValue::Blob(v) => {
                                        v.len()
                                    }
                                    _ => 8,
                                })
                                .sum::<usize>(),
                    )
                })
                .is_none_or(|n| n > 1024 * 1024)
        {
            return Err(io::Error::other(
                "retention complete metadata transition budget",
            ));
        }
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("retention connection closed"))?;
        let result = sync_extend_platform_fs::execute_fresh_retention_metadata(
            connection, statements, queries, before, after, budget, gc_mark,
        );
        if result.is_err() {
            self.io_ref().poison();
        }
        result?;
        self.checkpoint_to_standalone()?;
        self.verify_retention_lease(lease)
    }
    pub fn execute_planned_history(
        &mut self,
        statements: &[sync_extend_platform_fs::OriginalSqliteStatement],
        queries: &[sync_extend_platform_fs::OriginalSqliteQuery],
        before: &[sync_extend_platform_fs::OriginalSqliteRows],
        after: &[sync_extend_platform_fs::OriginalSqliteRows],
        budget: sync_extend_platform_fs::OriginalSqliteReadBudget,
    ) -> io::Result<()> {
        self.verify()?;
        if !self.attempted {
            return Err(io::Error::other("fresh history committed session required"));
        }
        let size = statements.iter().try_fold(0u64, |sum, row| {
            if row.sql.is_empty()
                || row.sql.len() > 65536
                || row.parameters.len() > 1024
                || row.sql.contains('\0')
            {
                return Err(io::Error::other("fresh history bounded SQL"));
            }
            row.parameters
                .iter()
                .try_fold(sum + row.sql.len() as u64, |sum, value| {
                    let size = match value {
                        sync_extend_platform_fs::OriginalSqliteValue::Null => 0,
                        sync_extend_platform_fs::OriginalSqliteValue::Integer(_)
                        | sync_extend_platform_fs::OriginalSqliteValue::Real(_) => 8,
                        sync_extend_platform_fs::OriginalSqliteValue::Text(s) => s.len(),
                        sync_extend_platform_fs::OriginalSqliteValue::Blob(b) => b.len(),
                    };
                    sum.checked_add(size as u64)
                        .ok_or_else(|| io::Error::other("fresh history SQL aggregate"))
                })
        })?;
        if size > 1024 * 1024 {
            return Err(io::Error::other("fresh history encoded transition budget"));
        }
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("fresh history connection closed"))?;
        // Existing private VFS already retains all native objects and denies
        // namespace deletion; the original authorizer restricts every DML family.
        let result = sync_extend_platform_fs::execute_fresh_planned_history(
            connection, statements, queries, before, after, budget,
        );
        if result.is_err() {
            self.io_ref().poison();
        }
        result?;
        self.checkpoint_to_standalone()?;
        self.verify()
    }
}
impl Drop for FreshNativeWalConnection {
    fn drop(&mut self) {
        if !self.original_resources_remain() {
            return;
        }
        let original = Self {
            connection: self.connection.take(),
            opening_connection: self.opening_connection.take(),
            io: self.io.take(),
            path: std::mem::take(&mut self.path),
            attempted: self.attempted,
            original_terminal_error: self.original_terminal_error.take(),
        };
        if let Err(original) = original.close_original_resources_retaining() {
            original.retain_until_process_exit();
        }
    }
}
