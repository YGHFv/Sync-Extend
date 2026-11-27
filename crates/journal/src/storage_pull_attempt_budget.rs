//! Explicit, independent reservations for each actual storage-pull block request.
//! Reserved payload is conservative admission accounting, never wire-byte billing.
use crate::{JournalError, Result};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use rusqlite::OpenFlags;
use rusqlite::{Connection, TransactionBehavior, limits::Limit, params};
use serde::{Deserialize, Serialize};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::fs::OpenOptions;
use std::{
    fs::File,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sync_extend_core_model::{
    Change, ChunkRef, ContentId, DeviceId, EntryId, SpaceId, storage_node::StorageNodeConfig,
};
use sync_extend_transport::{ForwardedSnapshotEnvelope, PeerIdentity, VerifiedForwardedPage};

const FILE_NAME: &str = "storage-pull-attempt-budget.sqlite";
const MAX_ENTRIES: u64 = 100_000;
const MAX_RECORD_BYTES: usize = 2048;
const MAX_POLICY_BYTES: usize = 16_384;
const SCHEMA: &str = journal_sql!("storage-pull-attempt-budget-schema.sql");

/// Every field is explicit; quota, period and route exemptions have no defaults.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePullAttemptPolicy {
    pub format_version: u32,
    pub budget_id: EntryId,
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub source_device: DeviceId,
    pub source_public_key: [u8; 32],
    pub storage_policy: ContentId,
    pub ledger_path: PathBuf,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub max_reserved_payload_bytes: u64,
    pub max_attempt_entries: u64,
    pub meter_unit: String,
    pub route_scope: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StoragePullAttemptStatus {
    pub budget_id: EntryId,
    pub policy_fingerprint: ContentId,
    pub meter_unit: String,
    pub route_scope: String,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub reserved_payload_bytes: u64,
    pub remaining_payload_bytes: u64,
    pub attempt_entries: u64,
    pub remaining_attempt_entries: u64,
    pub clock_high_water_ms: u64,
    pub actual_wire_bytes: Option<u64>,
    pub automatic_rollover: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    policy: ContentId,
    source: DeviceId,
    source_public_key: [u8; 32],
    channel_binding: ContentId,
    offer_kind: String,
    storage_id: ContentId,
    content_id: ContentId,
    payload_bytes: u64,
    at_ms: u64,
}

type Permit = (u64, String, String);
type QueryBudget = Arc<Mutex<(Instant, u64)>>;
#[cfg(any(target_os = "linux", target_os = "android"))]
type LedgerConnection = sync_extend_platform_fs::UnixSqliteLedgerConnection;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
type LedgerConnection = Connection;

pub struct StoragePullAttemptLedger {
    connection: LedgerConnection,
    gate: Arc<Mutex<Option<Permit>>>,
    policy: StoragePullAttemptPolicy,
    policy_json: String,
    fingerprint: ContentId,
    config: StorageNodeConfig,
    file: File,
    read_only: bool,
    query_budget: QueryBudget,
    #[cfg(windows)]
    parents: Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    #[cfg(windows)]
    readonly_files: Vec<(PathBuf, sync_extend_platform_fs::GuardedReadFile)>,
    #[cfg(windows)]
    absent_sidecars: Vec<PathBuf>,
}

impl StoragePullAttemptPolicy {
    pub fn fixed_ledger_path(config: &StorageNodeConfig) -> PathBuf {
        config.data_dir.join(FILE_NAME)
    }

    pub fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        require_attempt_platform()?;
        config.validate()?;
        let public: String = self
            .source_public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if self.format_version != 1
            || self.space_id != config.space_id
            || &self.storage_device != device
            || self.source_device == self.storage_device
            || DeviceId::from_public_key(&self.source_public_key) != self.source_device
            || config
                .approved_forwarders
                .get(&self.source_device)
                .map(ContentId::as_str)
                != Some(public.as_str())
            || self.storage_policy != config.fingerprint()?
            || self.ledger_path != Self::fixed_ledger_path(config)
            || !self.ledger_path.is_absolute()
            || self
                .ledger_path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || self.period_start_ms >= self.period_end_ms
            || self.period_end_ms > i64::MAX as u64
            || self.max_reserved_payload_bytes == 0
            || self.max_reserved_payload_bytes > i64::MAX as u64
            || self.max_attempt_entries == 0
            || self.max_attempt_entries > MAX_ENTRIES
            || self.meter_unit != "requested_block_payload_reserved_bytes"
            || self.route_scope != "all_paths"
            || serde_json::to_vec(self)?.len() > MAX_POLICY_BYTES
        {
            return Err(JournalError::Invariant(
                "explicit storage pull attempt policy differs",
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-storage-pull-attempt-budget-v1",
            self,
        ))?))
    }
}

// Supported platforms retain the actual SQLite objects for the whole connection.
fn require_attempt_platform() -> Result<()> {
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        Err(JournalError::Invariant(
            "storage pull attempt budget requires the certified Windows handle path",
        ))
    }
}

impl StoragePullAttemptLedger {
    /// Explicit fresh creation only. Existing state is never replaced or reset.
    pub fn init(
        config: &StorageNodeConfig,
        device: &DeviceId,
        policy: StoragePullAttemptPolicy,
        at_ms: u64,
    ) -> Result<Self> {
        if at_ms > i64::MAX as u64 {
            return Err(JournalError::Invariant(
                "storage pull attempt initialization clock",
            ));
        }
        Self::open_inner(config, device, policy, Some(at_ms), false)
    }

    /// Ordinary admission requires the already initialized, exact fixed ledger.
    pub fn open(
        config: &StorageNodeConfig,
        device: &DeviceId,
        policy: StoragePullAttemptPolicy,
    ) -> Result<Self> {
        Self::open_inner(config, device, policy, None, false)
    }

    /// Opens SQLite read-only and never inserts an attempt or advances the clock.
    pub fn read_status(
        config: &StorageNodeConfig,
        policy: StoragePullAttemptPolicy,
    ) -> Result<StoragePullAttemptStatus> {
        let device = policy.storage_device.clone();
        Self::open_inner(config, &device, policy, None, true)?.status()
    }

    fn max_file_bytes(policy: &StoragePullAttemptPolicy) -> Result<u64> {
        policy
            .max_attempt_entries
            .checked_mul(4096)
            .and_then(|bytes| bytes.checked_add(1024 * 1024))
            .ok_or(JournalError::Invariant(
                "storage pull attempt file bound overflow",
            ))
    }

    fn open_inner(
        config: &StorageNodeConfig,
        device: &DeviceId,
        policy: StoragePullAttemptPolicy,
        initialize: Option<u64>,
        read_only: bool,
    ) -> Result<Self> {
        policy.validate(config, device)?;
        let path = &policy.ledger_path;
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
                        return Err(JournalError::Invariant("storage pull attempt aliased path"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
                Err(error) => return Err(error.into()),
            }
        }
        #[cfg(windows)]
        let parents = {
            let parent = path
                .parent()
                .ok_or(JournalError::Invariant("attempt parent absent"))?;
            let mut held = Vec::new();
            for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
                let directory = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
                if !directory.matches_path(ancestor)? {
                    return Err(JournalError::Invariant(
                        "storage pull attempt ancestor changed",
                    ));
                }
                held.push((ancestor.to_path_buf(), directory));
            }
            held.last()
                .ok_or(JournalError::Invariant("attempt parent absent"))?
                .1
                .require_local_ntfs(parent)?;
            held
        };
        // Reuse the existing closed-main reader contract. Never make a stale
        // immutable view over committed WAL reservations or create SHM for status.
        #[cfg(windows)]
        let (readonly_files, absent_sidecars, wal_present) = if read_only {
            crate::ReadOnlyJournal::hold_closed_readonly_files(path)?
        } else {
            (Vec::new(), Vec::new(), false)
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true).write(!read_only);
            if initialize.is_some() {
                options.create_new(true);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.share_mode(3).custom_flags(0x00200000);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let unix_vfs = sync_extend_platform_fs::UnixSqliteLedger::open(
            path,
            Self::max_file_bytes(&policy)?,
            initialize.is_some(),
            read_only,
        )?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let file = unix_vfs.main_file().try_clone()?;
        Self::verify_file(&file, path, Self::max_file_bytes(&policy)?)?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        Self::guard_sidecars(path, Self::max_file_bytes(&policy)?, initialize.is_some())?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        #[cfg(windows)]
        let mut connection = if read_only {
            let flags = flags | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            if wal_present {
                let connection = Connection::open_with_flags_and_vfs(path, flags, "win32-none")?;
                connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
                connection
            } else {
                let uri = crate::immutable_readonly_uri(path)?;
                Connection::open_with_flags_and_vfs(uri, flags, "win32-none")?
            }
        } else {
            Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?
        };
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        let mut connection =
            Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut connection = unix_vfs.open_connection()?;
        Self::verify_file(&file, path, Self::max_file_bytes(&policy)?)?;
        #[cfg(windows)]
        if sync_extend_platform_fs::sqlite_main_file_identity(&connection)?
            != sync_extend_platform_fs::FileKey::from_file(&file)?
        {
            return Err(JournalError::Invariant(
                "storage pull attempt SQLite handle differs",
            ));
        }
        connection.busy_timeout(Duration::from_secs(5))?;
        let query_budget = Self::configure_limits(&mut connection, policy.max_attempt_entries)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "cache_size", -4096i32)?;
        if read_only {
            connection.pragma_update(None, "query_only", true)?;
        } else {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            connection.pragma_update(None, "wal_autocheckpoint", 1i32)?;
            let pages = Self::max_file_bytes(&policy)? / 4096;
            connection.pragma_update(None, "max_page_count", crate::sql_integer(pages)?)?;
            connection.pragma_update(None, "journal_size_limit", 1024 * 1024i64)?;
        }
        let gate = Arc::new(Mutex::new(None::<Permit>));
        let function = gate.clone();
        connection.create_scalar_function(
            "sync_storage_pull_attempt_issue",
            3,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let sequence = context.get::<i64>(0)?;
                let actual = (
                    u64::try_from(sequence).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    context.get::<String>(1)?,
                    context.get::<String>(2)?,
                );
                let mut held = function.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                if held.as_ref() == Some(&actual) {
                    *held = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        )?;
        let policy_json = serde_json::to_string(&policy)?;
        let fingerprint = policy.fingerprint()?;
        if let Some(at) = initialize {
            let tx =
                rusqlite::Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)?;
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO owner VALUES(1,?1,?2,?3)",
                params![policy_json, fingerprint.as_str(), crate::sql_integer(at)?],
            )?;
            tx.commit()?;
        }
        let result = Self {
            connection,
            gate,
            policy,
            policy_json,
            fingerprint,
            config: config.clone(),
            file,
            read_only,
            query_budget,
            #[cfg(windows)]
            parents,
            #[cfg(windows)]
            readonly_files,
            #[cfg(windows)]
            absent_sidecars,
        };
        result.status()?;
        Ok(result)
    }

    fn query_instruction_limit(entries: u64) -> Result<u64> {
        entries
            .checked_mul(2000)
            .and_then(|v| v.checked_add(1_000_000))
            .ok_or(JournalError::Invariant("attempt query bound overflow"))
    }

    fn configure_limits(connection: &mut LedgerConnection, entries: u64) -> Result<QueryBudget> {
        for (category, limit) in [
            (Limit::SQLITE_LIMIT_LENGTH, 65_536),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 65_536),
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        ] {
            connection.set_limit(category, limit)?;
            if connection.limit(category)? > limit {
                return Err(JournalError::Invariant("attempt SQL limit not applied"));
            }
        }
        let budget = Arc::new(Mutex::new((
            Instant::now(),
            Self::query_instruction_limit(entries)?,
        )));
        let observed = budget.clone();
        connection.progress_handler(
            1000,
            Some(move || {
                let Ok(mut budget) = observed.lock() else {
                    return true;
                };
                if budget.1 < 1000 || budget.0.elapsed() >= Duration::from_secs(10) {
                    return true;
                }
                budget.1 -= 1000;
                false
            }),
        )?;
        Ok(budget)
    }

    fn verify_file(file: &File, path: &Path, max_bytes: u64) -> Result<()> {
        let slot = std::fs::symlink_metadata(path)?;
        let held = file.metadata()?;
        if !slot.is_file()
            || slot.file_type().is_symlink()
            || !held.is_file()
            || held.len() > max_bytes
        {
            return Err(JournalError::Invariant(
                "storage pull attempt file/size differs",
            ));
        }
        #[cfg(windows)]
        if !sync_extend_platform_fs::regular_file_matches_path(file, path)? {
            return Err(JournalError::Invariant(
                "storage pull attempt native slot differs",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if slot.dev() != held.dev()
                || slot.ino() != held.ino()
                || held.nlink() != 1
                || held.mode() & 0o077 != 0
            {
                return Err(JournalError::Invariant(
                    "storage pull attempt inode/privacy differs",
                ));
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn guard_sidecars(path: &Path, max_bytes: u64, fresh: bool) -> Result<()> {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            match std::fs::symlink_metadata(&sidecar) {
                Ok(_) if fresh => {
                    return Err(JournalError::Invariant("fresh attempt sidecar exists"));
                }
                Ok(_) => {
                    let mut options = OpenOptions::new();
                    options.read(true);
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        options.share_mode(3).custom_flags(0x00200000);
                    }
                    let file = options.open(&sidecar)?;
                    Self::verify_file(&file, &sidecar, max_bytes)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn audit(&self) -> Result<(u64, u64, u64)> {
        *self
            .query_budget
            .lock()
            .map_err(|_| JournalError::Invariant("attempt query budget poisoned"))? = (
            Instant::now(),
            Self::query_instruction_limit(self.policy.max_attempt_entries)?,
        );
        Self::verify_file(
            &self.file,
            &self.policy.ledger_path,
            Self::max_file_bytes(&self.policy)?,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        Self::guard_sidecars(
            &self.policy.ledger_path,
            Self::max_file_bytes(&self.policy)?,
            false,
        )?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.connection.verify()?;
        #[cfg(windows)]
        {
            for (path, file) in &self.readonly_files {
                file.verify_single_link()?;
                if !sync_extend_platform_fs::regular_file_matches_path(file.reader(), path)? {
                    return Err(JournalError::Invariant(
                        "attempt readonly native slot differs",
                    ));
                }
            }
            for path in &self.absent_sidecars {
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => {
                        return Err(JournalError::Invariant(
                            "attempt readonly absent sidecar appeared",
                        ));
                    }
                }
            }
            for (path, parent) in &self.parents {
                if !parent.matches_path(path)? {
                    return Err(JournalError::Invariant("attempt retained ancestor differs"));
                }
            }
            if sync_extend_platform_fs::sqlite_main_file_identity(&self.connection)?
                != sync_extend_platform_fs::FileKey::from_file(&self.file)?
            {
                return Err(JournalError::Invariant(
                    "attempt actual SQLite identity differs",
                ));
            }
        }
        fn schema(connection: &Connection) -> Result<Vec<(String, String, String)>> {
            let mut query = connection.prepare(
                "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name LIMIT 17",
            )?;
            let rows = query
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        }
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(SCHEMA)?;
        if schema(&expected)? != schema(&self.connection)?
            || self
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?
                != 1
        {
            return Err(JournalError::Invariant(
                "storage pull attempt exact schema differs",
            ));
        }
        let mut owner_query = self
            .connection
            .prepare("SELECT slot,policy,fingerprint,initialized_at_ms FROM owner LIMIT 2")?;
        let owners = owner_query
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let [(1, policy, fingerprint, initialized)] = owners.as_slice() else {
            return Err(JournalError::Invariant(
                "storage pull attempt singleton owner differs",
            ));
        };
        if policy != &self.policy_json
            || fingerprint != self.fingerprint.as_str()
            || *initialized < 0
        {
            return Err(JournalError::Invariant(
                "storage pull attempt immutable policy/owner differs",
            ));
        }
        let mut clock = *initialized as u64;
        let mut count = 0u64;
        let mut bytes = 0u64;
        let mut query = self.connection.prepare(
            "SELECT sequence,attempt_id,record FROM attempts ORDER BY sequence LIMIT ?1",
        )?;
        let mut rows = query.query([crate::sql_integer(self.policy.max_attempt_entries + 1)?])?;
        while let Some(row) = rows.next()? {
            count = count
                .checked_add(1)
                .ok_or(JournalError::Invariant("attempt count overflow"))?;
            let sequence: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let _: EntryId = id.parse()?;
            let record: String = row.get(2)?;
            if record.len() > MAX_RECORD_BYTES
                || sequence != crate::sql_integer(count)?
                || count > self.policy.max_attempt_entries
            {
                return Err(JournalError::Invariant(
                    "storage pull attempt row bound differs",
                ));
            }
            let attempt: Attempt = serde_json::from_str(&record)?;
            if serde_json::to_string(&attempt)? != record
                || attempt.policy != self.fingerprint
                || attempt.source != self.policy.source_device
                || attempt.source_public_key != self.policy.source_public_key
                || !matches!(attempt.offer_kind.as_str(), "page" | "snapshot")
                || attempt.payload_bytes == 0
                || attempt.payload_bytes > self.config.max_request_bytes
                || attempt.at_ms < clock
                || attempt.at_ms < self.policy.period_start_ms
                || attempt.at_ms >= self.policy.period_end_ms
            {
                return Err(JournalError::Invariant(
                    "storage pull attempt record differs",
                ));
            }
            clock = attempt.at_ms;
            bytes = bytes
                .checked_add(attempt.payload_bytes)
                .ok_or(JournalError::Invariant("storage pull attempt sum overflow"))?;
            if bytes > self.policy.max_reserved_payload_bytes {
                return Err(JournalError::Invariant(
                    "storage pull attempt durable quota exceeded",
                ));
            }
        }
        Ok((bytes, count, clock))
    }

    pub fn status(&self) -> Result<StoragePullAttemptStatus> {
        let tx =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let (bytes, count, clock) = self.audit()?;
        tx.commit()?;
        Ok(StoragePullAttemptStatus {
            budget_id: self.policy.budget_id.clone(),
            policy_fingerprint: self.fingerprint.clone(),
            meter_unit: self.policy.meter_unit.clone(),
            route_scope: self.policy.route_scope.clone(),
            period_start_ms: self.policy.period_start_ms,
            period_end_ms: self.policy.period_end_ms,
            reserved_payload_bytes: bytes,
            remaining_payload_bytes: self
                .policy
                .max_reserved_payload_bytes
                .checked_sub(bytes)
                .ok_or(JournalError::Invariant("attempt remaining bytes overflow"))?,
            attempt_entries: count,
            remaining_attempt_entries: self.policy.max_attempt_entries.checked_sub(count).ok_or(
                JournalError::Invariant("attempt remaining entries overflow"),
            )?,
            clock_high_water_ms: clock,
            actual_wire_bytes: None,
            automatic_rollover: false,
        })
    }

    pub fn reserve_page(
        &self,
        page: &VerifiedForwardedPage,
        chunk: &ChunkRef,
        at_ms: u64,
    ) -> Result<EntryId> {
        let announced = page.page().operations.iter().any(|signed| {
            if let Change::Put { entry } = &signed.operation.payload.change {
                entry
                    .content
                    .as_ref()
                    .is_some_and(|file| file.chunks.contains(chunk))
            } else {
                false
            }
        });
        if !announced
            || page.receiver().device_id != self.policy.storage_device
            || page.receiver().space_id != self.policy.space_id
            || !self
                .config
                .approved_origins
                .contains_key(&page.origin().device_id)
        {
            return Err(JournalError::Invariant(
                "attempt exact verified page offer required",
            ));
        }
        let storage_id = page
            .storage_id()
            .map_err(|_| JournalError::Invariant("attempt page storage identity"))?;
        self.reserve(
            page.forwarder(),
            &page.page().channel_binding,
            "page",
            &storage_id,
            chunk,
            at_ms,
        )
    }

    pub fn reserve_snapshot(
        &self,
        envelope: &ForwardedSnapshotEnvelope,
        authenticated_source: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
        chunk: &ChunkRef,
        at_ms: u64,
    ) -> Result<EntryId> {
        envelope
            .verify(&envelope.origin, authenticated_source, receiver, binding)
            .map_err(|_| JournalError::Invariant("attempt verified snapshot channel required"))?;
        let public: String = envelope
            .origin
            .public_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let announced = envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .any(|file| file.chunks.contains(chunk));
        if !announced
            || receiver.device_id != self.policy.storage_device
            || receiver.space_id != self.policy.space_id
            || self
                .config
                .approved_origins
                .get(&envelope.origin.device_id)
                .map(ContentId::as_str)
                != Some(public.as_str())
        {
            return Err(JournalError::Invariant(
                "attempt exact verified snapshot offer required",
            ));
        }
        let storage_id = envelope
            .storage_id()
            .map_err(|_| JournalError::Invariant("attempt snapshot storage identity"))?;
        self.reserve(
            authenticated_source,
            binding,
            "snapshot",
            &storage_id,
            chunk,
            at_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve(
        &self,
        source: &PeerIdentity,
        binding: &ContentId,
        kind: &str,
        storage_id: &ContentId,
        chunk: &ChunkRef,
        at_ms: u64,
    ) -> Result<EntryId> {
        source
            .validate()
            .map_err(|_| JournalError::Invariant("attempt source identity invalid"))?;
        if self.read_only
            || source.device_id != self.policy.source_device
            || source.public_key != self.policy.source_public_key
            || source.space_id != self.policy.space_id
            || chunk.length == 0
            || u64::from(chunk.length) > self.config.max_request_bytes
            || at_ms > i64::MAX as u64
            || at_ms < self.policy.period_start_ms
            || at_ms >= self.policy.period_end_ms
        {
            return Err(JournalError::Invariant(
                "storage pull attempt source/window/length rejected",
            ));
        }
        let tx =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (bytes, count, clock) = self.audit()?;
        let next = count
            .checked_add(1)
            .ok_or(JournalError::Invariant("attempt count overflow"))?;
        if at_ms < clock
            || next > self.policy.max_attempt_entries
            || bytes
                .checked_add(u64::from(chunk.length))
                .is_none_or(|sum| sum > self.policy.max_reserved_payload_bytes)
        {
            return Err(JournalError::Invariant(
                "storage pull attempt clock/quota rejected",
            ));
        }
        // A fresh local random ID for every actual try; wire input cannot choose it.
        let id = EntryId::random()?;
        let record = serde_json::to_string(&Attempt {
            policy: self.fingerprint.clone(),
            source: source.device_id.clone(),
            source_public_key: source.public_key,
            channel_binding: binding.clone(),
            offer_kind: kind.to_owned(),
            storage_id: storage_id.clone(),
            content_id: chunk.content_id.clone(),
            payload_bytes: u64::from(chunk.length),
            at_ms,
        })?;
        if record.len() > MAX_RECORD_BYTES {
            return Err(JournalError::Invariant("attempt encoded record bound"));
        }
        *self
            .gate
            .lock()
            .map_err(|_| JournalError::Invariant("attempt issuance poisoned"))? =
            Some((next, id.to_string(), record.clone()));
        let inserted = tx.execute(
            "INSERT INTO attempts VALUES(?1,?2,?3)",
            params![crate::sql_integer(next)?, id.as_str(), record],
        );
        *self
            .gate
            .lock()
            .map_err(|_| JournalError::Invariant("attempt issuance poisoned"))? = None;
        if inserted? != 1 {
            return Err(JournalError::Invariant(
                "attempt reservation insertion differs",
            ));
        }
        let (actual, entries, observed_clock) = self.audit()?;
        if actual
            != bytes
                .checked_add(u64::from(chunk.length))
                .ok_or(JournalError::Invariant("attempt sum overflow"))?
            || entries != next
            || observed_clock != at_ms
        {
            return Err(JournalError::Invariant(
                "attempt reservation postcondition differs",
            ));
        }
        // Failed send, failed receive and process death retain this full reservation.
        tx.commit()?;
        Ok(id)
    }
}
