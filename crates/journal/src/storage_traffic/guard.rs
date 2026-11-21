use super::{LedgerConnection, StorageTrafficLedger};
use crate::{JournalError, Result};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use rusqlite::OpenFlags;
use rusqlite::{limits::Limit, Connection};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::fs::OpenOptions;
use std::{
    fs::File,
    path::{Component, Path},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sync_extend_core_model::{storage_node::StorageNodeConfig, DeviceId};

#[cfg(windows)]
use std::path::PathBuf;

pub(super) const FILE_NAME: &str = "storage-traffic.sqlite";
const MAX_SQL_BYTES: i32 = 65_536;
const MAX_VALUE_BYTES: i32 = 8 * 1024 * 1024 + 128 * 1024 + 4096;
const QUERY_TIME: Duration = Duration::from_secs(10);
type SchemaRow = (String, String, String, Option<String>);
pub(super) type QueryBudget = Arc<Mutex<(Instant, u64)>>;

pub(super) struct NativeTrafficFiles {
    pub(super) connection: LedgerConnection,
    pub(super) file: File,
    #[cfg(windows)]
    pub(super) parents: Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    #[cfg(windows)]
    pub(super) readonly_files: Vec<(PathBuf, sync_extend_platform_fs::GuardedReadFile)>,
    #[cfg(windows)]
    pub(super) absent_sidecars: Vec<PathBuf>,
}

pub(super) fn max_file_bytes(config: &StorageNodeConfig) -> Result<u64> {
    u64::try_from(config.max_metadata_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(4096))
        .and_then(|bytes| bytes.checked_add(1024 * 1024))
        .ok_or(JournalError::Invariant(
            "storage traffic file bound overflow",
        ))
}

fn instruction_limit(config: &StorageNodeConfig) -> Result<u64> {
    u64::try_from(config.max_metadata_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(4000))
        .and_then(|instructions| instructions.checked_add(1_000_000))
        .ok_or(JournalError::Invariant(
            "storage traffic query instruction bound overflow",
        ))
}

pub(super) fn require_path(
    path: &Path,
    config: &StorageNodeConfig,
    create: bool,
    read_only: bool,
) -> Result<()> {
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    return Err(JournalError::Invariant(
        "storage traffic ledger requires a supported retained native platform",
    ));
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        if path != config.data_dir.join(FILE_NAME)
            || !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || create && read_only
            || !create && !path.is_file()
            || create && path.try_exists()?
        {
            return Err(JournalError::Invariant(
                "fixed fresh storage traffic ledger or explicit reopen required",
            ));
        }
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
                        return Err(JournalError::Invariant(
                            "storage traffic path is not owned real storage",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
type ClosedReadOnlyFiles = (
    Vec<(PathBuf, sync_extend_platform_fs::GuardedReadFile)>,
    Vec<PathBuf>,
);

#[cfg(windows)]
fn closed_readonly_files(path: &Path) -> Result<ClosedReadOnlyFiles> {
    let main = sync_extend_platform_fs::GuardedReadFile::open(path)?;
    let mut files = vec![(path.to_path_buf(), main)];
    let mut absent = Vec::new();
    for suffix in ["-wal", "-journal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) => {
                if suffix == "-shm" || !metadata.is_file() || metadata.len() != 0 {
                    return Err(JournalError::Invariant(
                        "readonly storage traffic requires closed main without recovery",
                    ));
                }
                let held = sync_extend_platform_fs::GuardedReadFile::open(&sidecar)?;
                if held.reader().metadata()?.len() != 0 {
                    return Err(JournalError::Invariant(
                        "readonly storage traffic sidecar changed",
                    ));
                }
                files.push((sidecar, held));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => absent.push(sidecar),
            Err(error) => return Err(error.into()),
        }
    }
    Ok((files, absent))
}

pub(super) fn open_native(
    path: &Path,
    config: &StorageNodeConfig,
    create: bool,
    read_only: bool,
) -> Result<NativeTrafficFiles> {
    let maximum = max_file_bytes(config)?;
    #[cfg(windows)]
    let parents = {
        let parent = path
            .parent()
            .ok_or(JournalError::Invariant("storage ledger parent absent"))?;
        let mut result = Vec::new();
        for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let directory = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
            if !directory.matches_path(ancestor)? {
                return Err(JournalError::Invariant("storage ledger ancestor changed"));
            }
            result.push((ancestor.to_path_buf(), directory));
        }
        result
            .last()
            .ok_or(JournalError::Invariant("storage ledger root absent"))?
            .1
            .require_local_ntfs(parent)?;
        result
    };
    #[cfg(windows)]
    let (readonly_files, absent_sidecars) = if read_only {
        closed_readonly_files(path)?
    } else {
        (Vec::new(), Vec::new())
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let file = {
        #[cfg(windows)]
        if read_only {
            readonly_files[0].1.reader().try_clone()?
        } else {
            let mut options = OpenOptions::new();
            use std::os::windows::fs::OpenOptionsExt;
            options
                .read(true)
                .write(true)
                .create_new(create)
                .share_mode(3)
                .custom_flags(0x00200000);
            options.open(path)?
        }
        #[cfg(not(windows))]
        {
            let mut options = OpenOptions::new();
            options.read(true).write(!read_only).create_new(create);
            options.open(path)?
        }
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let backend = sync_extend_platform_fs::UnixSqliteLedger::open_storage_traffic(
        path, maximum, create, read_only,
    )?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let file = backend.main_file().try_clone()?;
    StorageTrafficLedger::verify_file(&file, path, maximum)?;
    #[cfg(windows)]
    let connection = if read_only {
        Connection::open_with_flags_and_vfs(
            crate::immutable_readonly_uri(path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            "win32-none",
        )?
    } else {
        Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let connection = backend.open_connection()?;
    StorageTrafficLedger::verify_file(&file, path, maximum)?;
    #[cfg(windows)]
    if sync_extend_platform_fs::sqlite_main_file_identity(&connection)?
        != sync_extend_platform_fs::FileKey::from_file(&file)?
    {
        return Err(JournalError::Invariant(
            "storage traffic actual SQLite main handle differs",
        ));
    }
    Ok(NativeTrafficFiles {
        connection,
        file,
        #[cfg(windows)]
        parents,
        #[cfg(windows)]
        readonly_files,
        #[cfg(windows)]
        absent_sidecars,
    })
}

pub(super) fn configure_limits(
    connection: &mut LedgerConnection,
    config: &StorageNodeConfig,
    read_only: bool,
) -> Result<QueryBudget> {
    for (category, limit) in [
        (Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_BYTES),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        (Limit::SQLITE_LIMIT_COLUMN, 64),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32),
    ] {
        connection.set_limit(category, limit)?;
        if connection.limit(category)? > limit {
            return Err(JournalError::Invariant(
                "storage traffic SQLite bound not applied",
            ));
        }
    }
    let budget = Arc::new(Mutex::new((Instant::now(), instruction_limit(config)?)));
    let observed = budget.clone();
    connection.progress_handler(
        1000,
        Some(move || {
            let Ok(mut budget) = observed.lock() else {
                return true;
            };
            if budget.1 < 1000 || budget.0.elapsed() >= QUERY_TIME {
                return true;
            }
            budget.1 -= 1000;
            false
        }),
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "cache_size", -4096i32)?;
    if read_only {
        connection.pragma_update(None, "query_only", true)?;
    } else {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1i32)?;
        let page_size: u64 = connection.query_row("PRAGMA page_size", [], |row| {
            super::sql_nonnegative(row.get::<_, i64>(0)?, 0)
        })?;
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(JournalError::Invariant(
                "storage traffic SQLite page size differs",
            ));
        }
        connection.pragma_update(
            None,
            "max_page_count",
            crate::sql_integer(max_file_bytes(config)? / page_size)?,
        )?;
        connection.pragma_update(None, "journal_size_limit", 1024 * 1024i64)?;
    }
    Ok(budget)
}

impl StorageTrafficLedger {
    pub(super) fn verify_native(&self) -> Result<()> {
        Self::verify_file(&self.file, &self.path, self.max_file_bytes)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.connection.verify()?;
        #[cfg(windows)]
        {
            for (path, parent) in &self.parents {
                if !parent.matches_path(path)? {
                    return Err(JournalError::Invariant(
                        "storage traffic retained ancestor differs",
                    ));
                }
            }
            if sync_extend_platform_fs::sqlite_main_file_identity(&self.connection)?
                != sync_extend_platform_fs::FileKey::from_file(&self.file)?
            {
                return Err(JournalError::Invariant(
                    "storage traffic actual SQLite identity changed",
                ));
            }
            for (path, file) in &self.readonly_files {
                file.verify_single_link()?;
                if !sync_extend_platform_fs::regular_file_matches_path(file.reader(), path)? {
                    return Err(JournalError::Invariant(
                        "storage traffic readonly native slot differs",
                    ));
                }
            }
            for path in &self.absent_sidecars {
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => {
                        return Err(JournalError::Invariant(
                            "storage traffic readonly absent sidecar appeared",
                        ))
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn require_work_remaining(&self) -> Result<()> {
        let budget = self.query_budget.lock().map_err(|_| {
            JournalError::Invariant("storage traffic query progress budget poisoned")
        })?;
        if budget.0.elapsed() >= QUERY_TIME || budget.1 < 1000 {
            return Err(JournalError::Invariant(
                "storage traffic bounded audit work exhausted",
            ));
        }
        Ok(())
    }

    pub(super) fn begin_query(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<usize> {
        config.validate()?;
        *self.query_budget.lock().map_err(|_| {
            JournalError::Invariant("storage traffic query progress budget poisoned")
        })? = (Instant::now(), instruction_limit(config)?);
        self.verify_native()?;
        fn schema(connection: &Connection, maximum: usize) -> Result<Vec<SchemaRow>> {
            let mut query = connection.prepare(
                "SELECT
                 CASE WHEN length(CAST(type AS BLOB))<=64 THEN type ELSE '' END,
                 CASE WHEN length(CAST(name AS BLOB))<=256 THEN name ELSE '' END,
                 CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name ELSE '' END,
                 CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql ELSE NULL END
                 FROM sqlite_schema ORDER BY type,name LIMIT ?1",
            )?;
            let rows = query.query_map([crate::sql_integer(maximum as u64)?], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        }
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(include_str!("../storage-traffic-schema.sql"))?;
        let expected_schema = schema(&expected, 65)?;
        if expected_schema.is_empty()
            || expected_schema.len() > 64
            || schema(&self.connection, expected_schema.len() + 1)? != expected_schema
            || self
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?
                != 1
        {
            return Err(JournalError::Invariant(
                "storage traffic exact schema changed",
            ));
        }
        let mut query = self.connection.prepare(
            "SELECT
             CASE WHEN length(CAST(space AS BLOB))<=64 THEN space ELSE '' END,
             CASE WHEN length(CAST(device AS BLOB))<=64 THEN device ELSE '' END,
             CASE WHEN length(CAST(policy AS BLOB))<=64 THEN policy ELSE '' END,
             max_bytes,expires FROM owner LIMIT 2",
        )?;
        let owners = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    super::sql_nonnegative(row.get::<_, i64>(3)?, 3)?,
                    super::sql_nonnegative(row.get::<_, i64>(4)?, 4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let expected = (
            config.space_id.to_string(),
            device.to_string(),
            config.fingerprint()?.to_string(),
            config.max_traffic_bytes,
            config.expires_at_ms,
        );
        if owners.as_slice() != std::slice::from_ref(&expected) {
            return Err(JournalError::Invariant(
                "storage traffic policy/owner changed",
            ));
        }
        let count = self.bounded_row_counts(config)?;
        let metadata_bytes: u64 = self.connection.query_row(
            "SELECT COALESCE(SUM(length(CAST(envelope AS BLOB))),0) FROM
             (SELECT envelope FROM pages UNION ALL SELECT envelope FROM snapshots)",
            [],
            |row| super::sql_nonnegative(row.get::<_, i64>(0)?, 0),
        )?;
        if metadata_bytes > config.max_metadata_entries as u64 * 1024 {
            return Err(JournalError::Invariant("storage aggregate metadata bounds"));
        }
        self.require_work_remaining()?;
        Ok(count)
    }

    pub(super) fn bounded_row_counts(&self, config: &StorageNodeConfig) -> Result<usize> {
        let maximum = config
            .max_metadata_entries
            .checked_add(1)
            .ok_or(JournalError::Invariant(
                "storage traffic row bound overflow",
            ))?;
        let limit = crate::sql_integer(maximum as u64)?;
        let mut total = 0usize;
        for sql in [
            "SELECT count(*) FROM (SELECT 1 FROM pages LIMIT ?1)",
            "SELECT count(*) FROM (SELECT 1 FROM snapshots LIMIT ?1)",
            "SELECT count(*) FROM (SELECT 1 FROM traffic LIMIT ?1)",
        ] {
            let count: u64 = self.connection.query_row(sql, [limit], |row| {
                super::sql_nonnegative(row.get::<_, i64>(0)?, 0)
            })?;
            total = total
                .checked_add(usize::try_from(count).map_err(|_| {
                    JournalError::Invariant("storage traffic retained row count overflow")
                })?)
                .ok_or(JournalError::Invariant(
                    "storage traffic aggregate row count overflow",
                ))?;
            if total > config.max_metadata_entries {
                return Err(JournalError::Invariant("storage traffic bounds exceeded"));
            }
        }
        self.require_work_remaining()?;
        Ok(total)
    }
}
