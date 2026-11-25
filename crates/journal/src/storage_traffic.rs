//! Storage-role traffic is an independent bounded durable ledger, with no worktree mutation.
mod guard;

use crate::{JournalError, Result};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use rusqlite::Connection;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use sync_extend_core_model::{ContentId, DeviceId, storage_node::StorageNodeConfig};
use sync_extend_transport::{ForwardedPageEnvelope, ForwardedSnapshotEnvelope};

type TrafficPermit = (String, String, String, u64, u64);
#[cfg(any(target_os = "linux", target_os = "android"))]
type LedgerConnection = sync_extend_platform_fs::UnixSqliteLedgerConnection;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
type LedgerConnection = Connection;

pub struct StorageTrafficLedger {
    connection: LedgerConnection,
    gate: Arc<Mutex<Option<TrafficPermit>>>,
    page_gate: Arc<Mutex<Option<(String, String, u64)>>>,
    path: PathBuf,
    file: File,
    max_file_bytes: u64,
    query_budget: guard::QueryBudget,
    #[cfg(windows)]
    parents: Vec<(PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    #[cfg(windows)]
    readonly_files: Vec<(PathBuf, sync_extend_platform_fs::GuardedReadFile)>,
    #[cfg(windows)]
    absent_sidecars: Vec<PathBuf>,
}

#[cfg(target_os = "linux")]
pub struct StorageTrafficLedgerClosed {
    ledger: sync_extend_platform_fs::UnixSqliteLedgerClosed,
    duplicate: sync_extend_platform_fs::LinuxStorageOutsideFileClosed,
}

#[cfg(target_os = "linux")]
impl StorageTrafficLedgerClosed {
    pub fn original(&self) -> &sync_extend_platform_fs::UnixSqliteLedgerObservation {
        self.ledger.original()
    }

    pub fn original_duplicate_identity(&self) -> sync_extend_platform_fs::UnixFileKey {
        self.duplicate.identity()
    }
}

fn sql_nonnegative(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

impl StorageTrafficLedger {
    /// Every retained writable traffic class has the same enforced future cap.
    /// This is capacity arithmetic, never a VFS, namespace or file authority.
    pub fn control_file_capacities(config: &StorageNodeConfig) -> Result<[(&'static str, u64); 3]> {
        config.validate()?;
        let maximum = guard::max_file_bytes(config)?;
        Ok([
            ("storage_traffic_main", maximum),
            ("storage_traffic_wal", maximum),
            ("storage_traffic_rollback_journal", maximum),
        ])
    }

    #[cfg(target_os = "linux")]
    pub fn linux_descriptor_inventory(
        &self,
    ) -> Result<sync_extend_platform_fs::UnixSqliteLedgerObservation> {
        self.connection.descriptor_inventory().map_err(Into::into)
    }

    /// Consume the actual traffic connection, VFS files/lineage, and duplicate
    /// main description. A failed audit or close grants no successful token.
    #[cfg(target_os = "linux")]
    pub fn close_linux_original(
        self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<StorageTrafficLedgerClosed> {
        use std::os::unix::fs::MetadataExt;
        let mut failure = self.audit(config, device).err();
        let expected = self
            .file
            .metadata()
            .map(|metadata| sync_extend_platform_fs::UnixFileKey {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        let Self {
            connection,
            file,
            max_file_bytes,
            ..
        } = self;
        let ledger = connection.close();
        if let Err(error) = &ledger {
            failure.get_or_insert_with(|| {
                JournalError::Io(std::io::Error::new(error.kind(), error.to_string()))
            });
        }
        let expected = match expected {
            Ok(expected) => expected,
            Err(error) => {
                failure.get_or_insert(JournalError::from(error));
                sync_extend_platform_fs::UnixFileKey {
                    device: 0,
                    inode: 0,
                }
            }
        };
        let duplicate =
            sync_extend_platform_fs::LinuxStorageCasCoordination::close_outside_regular_file(
                file,
                expected,
                max_file_bytes,
            );
        if let Err(error) = &duplicate {
            failure.get_or_insert_with(|| {
                JournalError::Io(std::io::Error::new(error.kind(), error.to_string()))
            });
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(StorageTrafficLedgerClosed {
            ledger: ledger?,
            duplicate: duplicate?,
        })
    }

    pub fn open(
        path: &Path,
        config: &StorageNodeConfig,
        device: &DeviceId,
        create: bool,
    ) -> Result<Self> {
        Self::open_inner(path, config, device, create, false)
    }

    /// Linux and Android observe a closed main through retained O_NOATIME descriptors.
    /// Active writers, WAL recovery and SHM are refused without advancing state.
    /// Other platforms return unsupported before any ledger I/O.
    pub fn read_charged_bytes(
        path: &Path,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<u64> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            Self::open_inner(path, config, device, false, true)?.charged_bytes(config, device)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (path, config, device);
            Err(JournalError::Invariant(
                "storage traffic zero-effect status requires retained Unix no-atime descriptors",
            ))
        }
    }

    fn open_inner(
        path: &Path,
        config: &StorageNodeConfig,
        device: &DeviceId,
        create: bool,
        read_only: bool,
    ) -> Result<Self> {
        config.validate()?;
        guard::require_path(path, config, create, read_only)?;
        let native = guard::open_native(path, config, create, read_only)?;
        let mut connection = native.connection;
        let query_budget = guard::configure_limits(&mut connection, config, read_only)?;
        let gate = Arc::new(Mutex::new(None::<(String, String, String, u64, u64)>));
        let function = gate.clone();
        connection.create_scalar_function(
            "sync_storage_traffic_issue",
            5,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let mut held = function.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                let actual = (
                    context.get::<String>(0)?,
                    context.get::<String>(1)?,
                    context.get::<String>(2)?,
                    sql_nonnegative(context.get::<i64>(3)?, 3)?,
                    sql_nonnegative(context.get::<i64>(4)?, 4)?,
                );
                if held.as_ref() == Some(&actual) {
                    *held = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        )?;
        let page_gate = Arc::new(Mutex::new(None::<(String, String, u64)>));
        let function = page_gate.clone();
        connection.create_scalar_function(
            "sync_storage_page_issue",
            3,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let mut held = function.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                let actual = (
                    context.get::<String>(0)?,
                    context.get::<String>(1)?,
                    sql_nonnegative(context.get::<i64>(2)?, 2)?,
                );
                if held.as_ref() == Some(&actual) {
                    *held = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        )?;
        if create {
            let tx = connection.unchecked_transaction()?;
            tx.execute_batch(include_str!("storage-traffic-schema.sql"))?;
            tx.execute(
                "INSERT INTO owner VALUES(?1,?2,?3,?4,?5)",
                params![
                    config.space_id.as_str(),
                    device.as_str(),
                    config.fingerprint()?.as_str(),
                    crate::sql_integer(config.max_traffic_bytes)?,
                    crate::sql_integer(config.expires_at_ms)?
                ],
            )?;
            tx.commit()?;
        }
        let result = Self {
            connection,
            gate,
            page_gate,
            path: path.to_path_buf(),
            file: native.file,
            max_file_bytes: guard::max_file_bytes(config)?,
            query_budget,
            #[cfg(windows)]
            parents: native.parents,
            #[cfg(windows)]
            readonly_files: native.readonly_files,
            #[cfg(windows)]
            absent_sidecars: native.absent_sidecars,
        };
        result.audit(config, device)?;
        Ok(result)
    }

    fn audit(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<(u64, usize)> {
        let expected_count = self.begin_query(config, device)?;
        let mut total = 0u64;
        let pages = self.pages_inner(config, device)?;
        let snapshots = self.snapshots_inner(config, device)?;
        let mut snapshot_requests = std::collections::BTreeMap::<
            ContentId,
            std::collections::BTreeMap<ContentId, u32>,
        >::new();
        for envelope in &snapshots {
            self.require_work_remaining()?;
            let request = envelope
                .storage_id()
                .map_err(|_| JournalError::Invariant("storage snapshot traffic owner identity"))?;
            let chunks = snapshot_requests.entry(request).or_default();
            for chunk in envelope
                .signed_report
                .report
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .flat_map(|file| &file.chunks)
            {
                self.require_work_remaining()?;
                if chunks
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|prior| prior != chunk.length)
                {
                    return Err(JournalError::Invariant(
                        "storage snapshot traffic chunk lengths",
                    ));
                }
            }
        }
        let mut count = pages.len() + snapshots.len();
        let mut statement = self.connection.prepare(
            "SELECT
             CASE WHEN length(CAST(request AS BLOB))<=64 THEN request ELSE '' END,
             CASE WHEN length(CAST(content AS BLOB))<=64 THEN content ELSE '' END,
             CASE WHEN length(CAST(direction AS BLOB))<=16 THEN direction ELSE '' END,
             bytes,at_ms FROM traffic ORDER BY request,content,direction",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            self.require_work_remaining()?;
            let request: String = row.get(0)?;
            let content: String = row.get(1)?;
            let direction: String = row.get(2)?;
            let bytes: u64 = sql_nonnegative(row.get::<_, i64>(3)?, 3)?;
            let at: u64 = sql_nonnegative(row.get::<_, i64>(4)?, 4)?;
            if request.parse::<ContentId>().is_err()
                || content.parse::<ContentId>().is_err()
                || !matches!(direction.as_str(), "ingress" | "egress")
                || bytes > config.max_request_bytes
                || (direction == "ingress" && at >= config.expires_at_ms)
            {
                return Err(JournalError::Invariant("storage traffic entry differs"));
            }
            // Snapshot charges use stable content ownership while report rows
            // preserve separate signed observation times. Page/standalone ledger
            // callers retain their existing exact charge contract.
            let request_id = request
                .parse::<ContentId>()
                .map_err(|_| JournalError::Invariant("storage traffic request encoding"))?;
            let content_id = content
                .parse::<ContentId>()
                .map_err(|_| JournalError::Invariant("storage traffic content encoding"))?;
            if let Some(chunks) = snapshot_requests.get(&request_id) {
                if chunks.get(&content_id).copied().map(u64::from) != Some(bytes) {
                    return Err(JournalError::Invariant(
                        "storage snapshot charge outside retained scope",
                    ));
                }
            }
            total = total
                .checked_add(bytes)
                .ok_or(JournalError::Invariant("storage traffic sum overflow"))?;
            count += 1;
            if total > config.max_traffic_bytes || count > config.max_metadata_entries {
                return Err(JournalError::Invariant("storage traffic bounds exceeded"));
            }
        }
        if count != expected_count {
            return Err(JournalError::Invariant(
                "storage traffic audited row count differs",
            ));
        }
        self.verify_native()?;
        self.require_work_remaining()?;
        Ok((total, count))
    }

    fn verify_file(file: &File, path: &Path, max_bytes: u64) -> Result<()> {
        let slot = std::fs::symlink_metadata(path)?;
        let held = file.metadata()?;
        if !slot.is_file()
            || !held.is_file()
            || slot.file_type().is_symlink()
            || held.len() > max_bytes
        {
            return Err(JournalError::Invariant("storage ledger slot differs"));
        }
        #[cfg(windows)]
        if !sync_extend_platform_fs::regular_file_matches_path(file, path)? {
            return Err(JournalError::Invariant(
                "storage ledger native slot differs",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if slot.dev() != held.dev()
                || slot.ino() != held.ino()
                || held.nlink() != 1
                || held.mode() & 0o077 != 0
                || slot.len() != held.len()
            {
                return Err(JournalError::Invariant(
                    "storage ledger inode/privacy differs",
                ));
            }
        }
        Ok(())
    }

    /// Charge before content I/O; failures retain charges and cannot reset budget on restart.
    /// Exact immutable-chunk retry is idempotent, so this is a logical delivery quota.
    // Keep policy, owner, request, object, direction, charge and time explicit at admission.
    #[allow(clippy::too_many_arguments)]
    pub fn charge(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
        request: &ContentId,
        chunk: &ContentId,
        direction: &str,
        bytes: u64,
        at: u64,
    ) -> Result<()> {
        config.validate()?;
        if !config.enabled
            || !matches!(direction, "ingress" | "egress")
            || (direction == "ingress" && at >= config.expires_at_ms)
            || bytes > config.max_request_bytes
        {
            return Err(JournalError::Invariant(
                "storage traffic expired/invalid charge",
            ));
        }
        let tx =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (before, count) = self.audit(config, device)?;
        let old: Option<u64> = tx
            .query_row(
                "SELECT bytes FROM traffic WHERE request=?1 AND content=?2 AND direction=?3",
                params![request.as_str(), chunk.as_str(), direction],
                |row| sql_nonnegative(row.get::<_, i64>(0)?, 0),
            )
            .optional()?;
        if let Some(old) = old {
            if old != bytes {
                return Err(JournalError::Invariant("traffic retry charge differs"));
            }
            tx.commit()?;
            return Ok(());
        }
        if count >= config.max_metadata_entries
            || before
                .checked_add(bytes)
                .is_none_or(|sum| sum > config.max_traffic_bytes)
        {
            return Err(JournalError::Invariant("storage traffic quota exhausted"));
        }
        *self
            .gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage traffic gate poisoned"))? = Some((
            request.to_string(),
            chunk.to_string(),
            direction.to_owned(),
            bytes,
            at,
        ));
        let outcome = tx.execute(
            "INSERT INTO traffic VALUES(?1,?2,?3,?4,?5)",
            params![
                request.as_str(),
                chunk.as_str(),
                direction,
                crate::sql_integer(bytes)?,
                crate::sql_integer(at)?
            ],
        );
        *self
            .gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage traffic gate poisoned"))? = None;
        if outcome? != 1 {
            return Err(JournalError::Invariant("storage traffic exact insert"));
        }
        let (after, rows) = self.audit(config, device)?;
        if after != before + bytes || rows != count + 1 {
            return Err(JournalError::Invariant(
                "storage traffic exact postwrite receipt",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn charged_bytes(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<u64> {
        self.audit(config, device).map(|(bytes, _)| bytes)
    }

    /// Retain the signed restart envelope before Journal receive or content I/O.
    pub fn retain_page(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
        envelope: &ForwardedPageEnvelope,
        at: u64,
    ) -> Result<ContentId> {
        config.admits(
            &envelope.origin.device_id,
            &envelope.forwarder.device_id,
            at,
        )?;
        Self::approved_envelope(config, device, envelope)?;
        let id = envelope
            .signed_page
            .page
            .storage_id()
            .map_err(|_| JournalError::Invariant("storage page stable identity"))?;
        let json = serde_json::to_string(envelope)?;
        if json.len() > 2 * 1024 * 1024 {
            return Err(JournalError::Invariant("storage page envelope bytes"));
        }
        let digest = ContentId::hash(json.as_bytes());
        let tx =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit(config, device)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT envelope FROM pages WHERE storage_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let prior: ForwardedPageEnvelope = serde_json::from_str(&old)?;
            // A new channel envelope must preserve the exact independently signed page.
            if prior
                .signed_page
                .page
                .storage_id()
                .map_err(|_| JournalError::Invariant("storage prior page identity"))?
                != id
                || prior.signed_page.page.operations != envelope.signed_page.page.operations
                || prior.origin.public_key != envelope.origin.public_key
                || prior.receiver.public_key != envelope.receiver.public_key
            {
                return Err(JournalError::Invariant("storage page collision"));
            }
            tx.commit()?;
            return Ok(id);
        }
        let (_, count) = self.audit(config, device)?;
        let bytes: u64 = tx.query_row(
            "SELECT COALESCE(SUM(length(CAST(envelope AS BLOB))),0) FROM
             (SELECT envelope FROM pages UNION ALL SELECT envelope FROM snapshots)",
            [],
            |row| sql_nonnegative(row.get::<_, i64>(0)?, 0),
        )?;
        if count >= config.max_metadata_entries
            || bytes
                .checked_add(json.len() as u64)
                .is_none_or(|sum| sum > config.max_metadata_entries as u64 * 1024)
        {
            return Err(JournalError::Invariant(
                "storage durable page metadata quota",
            ));
        }
        *self
            .page_gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage page gate poisoned"))? =
            Some((id.to_string(), digest.to_string(), at));
        let outcome = tx.execute(
            "INSERT INTO pages VALUES(?1,?2,?3,?4)",
            params![id.as_str(), json, digest.as_str(), crate::sql_integer(at)?],
        );
        *self
            .page_gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage page gate poisoned"))? = None;
        if outcome? != 1 {
            return Err(JournalError::Invariant("storage durable page exact insert"));
        }
        self.audit(config, device)?;
        tx.commit()?;
        Ok(id)
    }

    fn approved_envelope(
        config: &StorageNodeConfig,
        device: &DeviceId,
        envelope: &ForwardedPageEnvelope,
    ) -> Result<()> {
        envelope
            .validate()
            .map_err(|_| JournalError::Invariant("storage retained page signature"))?;
        let public = |bytes: &[u8; 32]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        if envelope.origin.space_id != config.space_id
            || &envelope.receiver.device_id != device
            || config
                .approved_origins
                .get(&envelope.origin.device_id)
                .map(ContentId::as_str)
                != Some(public(&envelope.origin.public_key).as_str())
            || config
                .approved_forwarders
                .get(&envelope.forwarder.device_id)
                .map(ContentId::as_str)
                != Some(public(&envelope.forwarder.public_key).as_str())
        {
            return Err(JournalError::Invariant(
                "storage retained page independent approval",
            ));
        }
        Ok(())
    }

    pub fn pages(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<Vec<ForwardedPageEnvelope>> {
        self.begin_query(config, device)?;
        self.pages_inner(config, device)
    }

    fn pages_inner(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<Vec<ForwardedPageEnvelope>> {
        let mut statement = self.connection.prepare(
            "SELECT CASE WHEN length(CAST(storage_id AS BLOB))<=64 THEN storage_id ELSE '' END,
             CASE WHEN length(CAST(envelope AS BLOB))<=2097152 THEN envelope ELSE '' END,
             CASE WHEN length(CAST(envelope_hash AS BLOB))<=64 THEN envelope_hash ELSE '' END,
             retained_at_ms FROM pages ORDER BY storage_id",
        )?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        let mut bytes = 0u64;
        while let Some(row) = rows.next()? {
            self.require_work_remaining()?;
            let id: String = row.get(0)?;
            let json: String = row.get(1)?;
            let digest: String = row.get(2)?;
            let at: u64 = sql_nonnegative(row.get::<_, i64>(3)?, 3)?;
            bytes = bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant("storage page byte sum"))?;
            if result.len() >= config.max_metadata_entries
                || bytes > config.max_metadata_entries as u64 * 1024
                || json.is_empty()
                || at >= config.expires_at_ms
                || ContentId::hash(json.as_bytes()).as_str() != digest
            {
                return Err(JournalError::Invariant("storage page ledger bounds/hash"));
            }
            let envelope: ForwardedPageEnvelope = serde_json::from_str(&json)?;
            Self::approved_envelope(config, device, &envelope)?;
            if envelope
                .signed_page
                .page
                .storage_id()
                .map_err(|_| JournalError::Invariant("storage durable page identity"))?
                .as_str()
                != id
            {
                return Err(JournalError::Invariant(
                    "storage durable page identity changed",
                ));
            }
            self.require_work_remaining()?;
            result.push(envelope);
        }
        self.verify_native()?;
        Ok(result)
    }

    /// Immutable last-reported manifests retain origin signatures independently of forwarder.
    pub fn retain_snapshot(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
        envelope: &ForwardedSnapshotEnvelope,
        at: u64,
    ) -> Result<ContentId> {
        config.admits(
            &envelope.origin.device_id,
            &envelope.forwarder.device_id,
            at,
        )?;
        Self::approved_snapshot(config, device, envelope)?;
        let id = envelope
            .report_id()
            .map_err(|_| JournalError::Invariant("storage snapshot durable identity"))?;
        let json = serde_json::to_string(envelope)?;
        if json.len() > 8 * 1024 * 1024 + 128 * 1024 {
            return Err(JournalError::Invariant("storage snapshot metadata bytes"));
        }
        let digest = ContentId::hash(json.as_bytes());
        let tx =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (_, count) = self.audit(config, device)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT envelope FROM snapshots WHERE storage_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let prior: ForwardedSnapshotEnvelope = serde_json::from_str(&old)?;
            if prior.signed_report != envelope.signed_report {
                return Err(JournalError::Invariant(
                    "storage snapshot identity collision",
                ));
            }
            tx.commit()?;
            return Ok(id);
        }
        let bytes: u64 = tx.query_row(
            "SELECT COALESCE(SUM(length(CAST(envelope AS BLOB))),0) FROM
             (SELECT envelope FROM pages UNION ALL SELECT envelope FROM snapshots)",
            [],
            |row| sql_nonnegative(row.get::<_, i64>(0)?, 0),
        )?;
        if count >= config.max_metadata_entries
            || bytes
                .checked_add(json.len() as u64)
                .is_none_or(|sum| sum > config.max_metadata_entries as u64 * 1024)
        {
            return Err(JournalError::Invariant(
                "storage snapshot aggregate metadata quota",
            ));
        }
        *self
            .page_gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage snapshot gate poisoned"))? =
            Some((id.to_string(), digest.to_string(), at));
        let outcome = tx.execute(
            "INSERT INTO snapshots VALUES(?1,?2,?3,?4)",
            params![id.as_str(), json, digest.as_str(), crate::sql_integer(at)?],
        );
        *self
            .page_gate
            .lock()
            .map_err(|_| JournalError::Invariant("storage snapshot gate poisoned"))? = None;
        if outcome? != 1 {
            return Err(JournalError::Invariant("storage snapshot exact insert"));
        }
        self.audit(config, device)?;
        tx.commit()?;
        Ok(id)
    }

    fn approved_snapshot(
        config: &StorageNodeConfig,
        device: &DeviceId,
        envelope: &ForwardedSnapshotEnvelope,
    ) -> Result<()> {
        envelope
            .verify(
                &envelope.origin,
                &envelope.forwarder,
                &envelope.receiver,
                &envelope.channel_binding,
            )
            .map_err(|_| JournalError::Invariant("storage retained snapshot signatures"))?;
        let public = |key: &[u8; 32]| {
            key.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        if envelope.origin.space_id != config.space_id
            || &envelope.receiver.device_id != device
            || config
                .approved_origins
                .get(&envelope.origin.device_id)
                .map(ContentId::as_str)
                != Some(public(&envelope.origin.public_key).as_str())
            || config
                .approved_forwarders
                .get(&envelope.forwarder.device_id)
                .map(ContentId::as_str)
                != Some(public(&envelope.forwarder.public_key).as_str())
        {
            return Err(JournalError::Invariant(
                "storage snapshot independent approval",
            ));
        }
        Ok(())
    }

    pub fn snapshots(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<Vec<ForwardedSnapshotEnvelope>> {
        self.begin_query(config, device)?;
        self.snapshots_inner(config, device)
    }

    fn snapshots_inner(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<Vec<ForwardedSnapshotEnvelope>> {
        let mut statement = self.connection.prepare(
            "SELECT CASE WHEN length(CAST(storage_id AS BLOB))<=64 THEN storage_id ELSE '' END,
             CASE WHEN length(CAST(envelope AS BLOB))<=8519680 THEN envelope ELSE '' END,
             CASE WHEN length(CAST(envelope_hash AS BLOB))<=64 THEN envelope_hash ELSE '' END,
             retained_at_ms
             FROM snapshots ORDER BY storage_id",
        )?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        let mut bytes = 0u64;
        while let Some(row) = rows.next()? {
            self.require_work_remaining()?;
            let id: String = row.get(0)?;
            let json: String = row.get(1)?;
            let digest: String = row.get(2)?;
            let at: u64 = sql_nonnegative(row.get::<_, i64>(3)?, 3)?;
            bytes = bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant("storage snapshot bytes sum"))?;
            if result.len() >= config.max_metadata_entries
                || bytes > config.max_metadata_entries as u64 * 1024
                || json.is_empty()
                || at >= config.expires_at_ms
                || ContentId::hash(json.as_bytes()).as_str() != digest
            {
                return Err(JournalError::Invariant(
                    "storage snapshot ledger bounds/hash",
                ));
            }
            let envelope: ForwardedSnapshotEnvelope = serde_json::from_str(&json)?;
            Self::approved_snapshot(config, device, &envelope)?;
            if envelope
                .report_id()
                .map_err(|_| JournalError::Invariant("storage snapshot durable ID"))?
                .as_str()
                != id
            {
                return Err(JournalError::Invariant(
                    "storage snapshot durable identity changed",
                ));
            }
            self.require_work_remaining()?;
            result.push(envelope);
        }
        self.verify_native()?;
        Ok(result)
    }
}
