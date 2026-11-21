//! Explicit Linux storage-only Journal owner. No worktree or native CAS action.
use crate::{ReconcileError, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt as UnixFileExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};
use sync_extend_core_model::{storage_node::StorageNodeConfig, ContentId, DeviceId};
use sync_extend_journal::{
    Journal, JournalError, StorageJournalBootstrapBudget, TreeRestoreInventoryLimits,
};
use sync_extend_platform_fs::{
    LinuxMetadataBudget, LinuxMetadataLimits, LinuxMetadataReceipt, LinuxNamespaceCapability,
    UnixFileKey,
};

const MAX_CONFIG_BYTES: usize = 65_536;
const NO_FOLLOW: i32 = 0x2_0000;
const DIRECTORY: i32 = 0x1_0000;
const NONBLOCK: i32 = 0x800;
const CLOSE_ON_EXEC: i32 = 0x8_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxStorageOwnerRole {
    StorageOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxStorageMetadataLimits {
    pub main: u64,
    pub wal: u64,
    pub shm: u64,
    pub rollback_journal: u64,
    pub owner_record: u64,
    pub total_physical: u64,
}

impl From<LinuxStorageMetadataLimits> for LinuxMetadataLimits {
    fn from(value: LinuxStorageMetadataLimits) -> Self {
        Self {
            main: value.main,
            wal: value.wal,
            shm: value.shm,
            rollback_journal: value.rollback_journal,
            owner_record: value.owner_record,
            total_physical: value.total_physical,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxStorageOwnerConfig {
    pub format_version: u32,
    pub owner_role: LinuxStorageOwnerRole,
    pub storage: StorageNodeConfig,
    pub backing_image: PathBuf,
    pub mount_root: PathBuf,
    pub expected_device: Option<DeviceId>,
    pub metadata_limits: LinuxStorageMetadataLimits,
}

fn absolute(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .ok_or(ReconcileError::Invariant("Linux storage path encoding"))?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.contains('\0')
        || text.contains("//")
        || text.split('/').any(|part| part == "." || part == "..")
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(ReconcileError::Invariant(
            "normalized absolute Linux storage paths required",
        ));
    }
    Ok(())
}

impl LinuxStorageOwnerConfig {
    pub fn validate(&self, initialize: bool) -> Result<()> {
        self.storage.validate()?;
        if self.format_version != 1
            || self.owner_role != LinuxStorageOwnerRole::StorageOnly
            || initialize != self.expected_device.is_none()
            || self.storage.max_metadata_entries < 3
        {
            return Err(ReconcileError::Invariant(
                "explicit storage-only role and init/reopen identity required",
            ));
        }
        for path in [
            &self.backing_image,
            &self.mount_root,
            &self.storage.data_dir,
        ] {
            absolute(path)?;
        }
        if self.mount_root.parent().is_none()
            || self.storage.data_dir.parent().is_none()
            || self.backing_image.starts_with(&self.mount_root)
            || self.backing_image.starts_with(&self.storage.data_dir)
            || self.storage.data_dir.starts_with(&self.mount_root)
            || self.mount_root.starts_with(&self.storage.data_dir)
        {
            return Err(ReconcileError::Invariant(
                "distinct outside metadata, image and acquired mount required",
            ));
        }
        let limits: LinuxMetadataLimits = self.metadata_limits.into();
        let capacities = [
            limits.main,
            limits.wal,
            limits.shm,
            limits.rollback_journal,
            limits.owner_record,
        ];
        let total = capacities.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or(ReconcileError::ResourceLimit("storage metadata aggregate"))
        })?;
        if capacities
            .iter()
            .any(|value| *value == 0 || *value > 256 * 1024 * 1024)
            || limits.shm < 32 * 1024
            || limits.shm % (32 * 1024) != 0
            || limits.owner_record < 4096
            || total > limits.total_physical
            || limits.total_physical > 5 * (6 * 256 * 1024 * 1024 + 4096)
        {
            return Err(ReconcileError::Invariant(
                "complete storage metadata class limits required",
            ));
        }
        let _ = limits.storage_only_physical_liabilities()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LinuxStorageObjectIdentity {
    pub device: u64,
    pub inode: u64,
}

impl From<UnixFileKey> for LinuxStorageObjectIdentity {
    fn from(value: UnixFileKey) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LinuxStorageMetadataFileObservation {
    pub class: &'static str,
    pub identity: LinuxStorageObjectIdentity,
    pub logical_bytes: u64,
    pub actual_file_bytes: u64,
    pub allocated_bytes: u64,
    pub capacity_bytes: u64,
    pub sealed_allocated_bytes: Option<u64>,
    pub physical_liability_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LinuxStorageMetadataObservation {
    pub current_owner_generation: [u8; 16],
    pub persistent_owner_generation: [u8; 16],
    pub parent: LinuxStorageObjectIdentity,
    pub total_allocated_bytes: u64,
    pub total_physical_budget: u64,
    pub total_physical_liability_bytes: Option<u64>,
    pub metadata_device: Option<u64>,
    pub block_identity: Option<LinuxStorageObjectIdentity>,
    pub superblock_uuid: Option<[u8; 16]>,
    pub ext4_features: Option<[u32; 3]>,
    pub kernel_contract: Option<&'static str>,
    pub active_sqlite_files: Option<u64>,
    pub disk_temp_files_allowed: bool,
    pub files: Vec<LinuxStorageMetadataFileObservation>,
}

fn metadata_observation(
    receipt: LinuxMetadataReceipt,
    persistent_owner_generation: [u8; 16],
) -> LinuxStorageMetadataObservation {
    LinuxStorageMetadataObservation {
        current_owner_generation: receipt.owner_generation,
        persistent_owner_generation,
        parent: receipt.parent.into(),
        total_allocated_bytes: receipt.total_allocated_bytes,
        total_physical_budget: receipt.total_physical_budget,
        total_physical_liability_bytes: receipt.total_physical_liability_bytes,
        metadata_device: receipt.storage_metadata_device,
        block_identity: receipt.storage_block_identity.map(Into::into),
        superblock_uuid: receipt.storage_superblock_uuid,
        ext4_features: receipt.storage_ext4_features,
        kernel_contract: receipt.storage_kernel_contract,
        active_sqlite_files: receipt.storage_active_sqlite_files,
        disk_temp_files_allowed: receipt.disk_temp_files_allowed,
        files: receipt
            .files
            .into_iter()
            .map(|file| LinuxStorageMetadataFileObservation {
                class: file.class,
                identity: file.identity.into(),
                logical_bytes: file.logical_bytes,
                actual_file_bytes: file.actual_file_bytes,
                allocated_bytes: file.allocated_bytes,
                capacity_bytes: file.capacity_bytes,
                sealed_allocated_bytes: file.sealed_allocated_bytes,
                physical_liability_bytes: file.physical_liability_bytes,
            })
            .collect(),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LinuxStorageOwnerObservation {
    pub format_version: u32,
    pub scope: &'static str,
    pub process_id: u32,
    pub process_start_ticks: u64,
    pub policy_fingerprint: ContentId,
    pub backing_image: LinuxStorageObjectIdentity,
    pub namespace: LinuxStorageObjectIdentity,
    pub mounted_root: LinuxStorageObjectIdentity,
    pub runtime_mount_id: u64,
    pub metadata: LinuxStorageMetadataObservation,
    pub bootstrap_budget: Option<StorageJournalBootstrapBudget>,
    pub native_inspection_authority: bool,
    pub marker_creation_authority: bool,
    pub payload_move_authority: bool,
    pub deletion_authority: bool,
    pub pending_resume_authority: bool,
    pub helpers_started: bool,
    pub worktree: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LinuxStorageOwnerClosed {
    pub format_version: u32,
    pub process_id: u32,
    pub process_start_ticks: u64,
    pub metadata: LinuxStorageMetadataObservation,
    pub all_sqlite_connections_closed: bool,
    pub original_mount_released: bool,
    pub original_loop_released: bool,
    pub helpers_started: bool,
    pub pending_resume_authority: bool,
}

/// Acquired live objects only. Its serialized observations cannot construct it.
pub struct LinuxStorageOwner {
    config: LinuxStorageOwnerConfig,
    owner: LinuxNamespaceCapability,
    budget: LinuxMetadataBudget,
    root: File,
    root_identity: LinuxStorageObjectIdentity,
    process_start_ticks: u64,
    initialize: bool,
    bootstrap_budget: Option<StorageJournalBootstrapBudget>,
}

fn identity(metadata: &Metadata) -> LinuxStorageObjectIdentity {
    LinuxStorageObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn private(metadata: &Metadata, directory: bool) -> Result<()> {
    // The native namespace contract requires a dedicated privileged UID 0 owner.
    if metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(ReconcileError::Invariant(
            "private root-owner original storage object required",
        ));
    }
    Ok(())
}

fn open_private(path: &Path, directory: bool) -> Result<File> {
    absolute(path)?;
    crate::check_ancestors(path)?;
    let before = fs::symlink_metadata(path)?;
    private(&before, directory)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW | CLOSE_ON_EXEC | NONBLOCK | if directory { DIRECTORY } else { 0 })
        .open(path)?;
    let opened = file.metadata()?;
    private(&opened, directory)?;
    if before.file_type().is_symlink() || identity(&before) != identity(&opened) {
        return Err(ReconcileError::Unstable);
    }
    Ok(file)
}

fn stable(before: &Metadata, after: &Metadata) -> bool {
    identity(before) == identity(after)
        && before.len() == after.len()
        && before.nlink() == after.nlink()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

/// All config bytes are read through one private, bounded, nonfollowing original.
pub fn read_linux_storage_owner_config(path: &Path) -> Result<LinuxStorageOwnerConfig> {
    let file = open_private(path, false)?;
    let before = file.metadata()?;
    if before.len() == 0 || before.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ReconcileError::ResourceLimit("Linux storage owner config"));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let named = fs::symlink_metadata(path)?;
    if bytes.len() > MAX_CONFIG_BYTES
        || !stable(&before, &file.metadata()?)
        || !stable(&before, &named)
        || named.file_type().is_symlink()
    {
        return Err(ReconcileError::Unstable);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn process_start_ticks() -> Result<u64> {
    let mut text = String::new();
    File::open("/proc/self/stat")?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(ReconcileError::ResourceLimit("storage owner process birth"));
    }
    let fields = text
        .rsplit_once(')')
        .ok_or(ReconcileError::Invariant("storage owner process stat"))?
        .1;
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|ticks| ticks.parse().ok())
        .filter(|ticks| *ticks != 0)
        .ok_or(ReconcileError::Invariant("storage owner process birth"))
}

fn root_names(path: &Path) -> Result<BTreeSet<std::ffi::OsString>> {
    Ok(fs::read_dir(path)?
        .take(13)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()?)
}

fn required_names() -> BTreeSet<std::ffi::OsString> {
    [
        "storage.lock",
        "device.secret",
        "journal.sqlite",
        "journal.sqlite-wal",
        "journal.sqlite-shm",
        "journal.sqlite-journal",
        "journal.sqlite.metadata-owner",
        "storage-traffic.sqlite",
        "cas",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect()
}

fn allowed_names() -> BTreeSet<std::ffi::OsString> {
    required_names()
        .into_iter()
        .chain(
            ["storage-traffic.sqlite-wal", "storage-traffic.sqlite-shm"]
                .into_iter()
                .map(std::ffi::OsString::from),
        )
        .collect()
}

fn layout(config: &LinuxStorageOwnerConfig, initialize: bool) -> Result<()> {
    let names = root_names(&config.storage.data_dir)?;
    if initialize {
        if !names.is_empty() {
            return Err(ReconcileError::Invariant(
                "fresh empty storage-only metadata directory required",
            ));
        }
        return Ok(());
    }
    let required = required_names();
    let allowed = allowed_names();
    if !required.is_subset(&names) || !names.is_subset(&allowed) {
        return Err(ReconcileError::Invariant(
            "complete original storage-only layout required; unknown slots refused",
        ));
    }
    for name in ["storage.lock", "device.secret", "storage-traffic.sqlite"] {
        drop(open_private(&config.storage.data_dir.join(name), false)?);
    }
    for name in ["storage-traffic.sqlite-wal", "storage-traffic.sqlite-shm"] {
        if names.contains(&std::ffi::OsString::from(name)) {
            let file = open_private(&config.storage.data_dir.join(name), false)?;
            if name == "storage-traffic.sqlite-wal" && file.metadata()?.len() != 0 {
                return Err(ReconcileError::Invariant(
                    "storage owner preflight requires the original closed traffic ledger",
                ));
            }
        }
    }
    // CAS is still ordinary managed storage in N06a. This check grants no
    // namespace mutation/inspection/quarantine/delete authority to its objects.
    for relative in ["cas", "cas/objects", "cas/tmp"] {
        let path = config.storage.data_dir.join(relative);
        crate::check_ancestors(&path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ReconcileError::Invariant("original storage CAS layout"));
        }
    }
    Ok(())
}

fn preflight_identity(config: &LinuxStorageOwnerConfig) -> Result<()> {
    let path = config.storage.data_dir.join("device.secret");
    let file = open_private(&path, false)?;
    let before = file.metadata()?;
    if before.len() != 32 {
        return Err(ReconcileError::Invariant(
            "original storage identity length",
        ));
    }
    let mut secret = [0u8; 32];
    file.read_exact_at(&mut secret, 0)?;
    if !stable(&before, &file.metadata()?) || !stable(&before, &fs::symlink_metadata(&path)?) {
        return Err(ReconcileError::Unstable);
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let device = DeviceId::from_public_key(key.verifying_key().as_bytes());
    if config.expected_device.as_ref() != Some(&device) {
        return Err(ReconcileError::Invariant(
            "original storage identity differs from explicit reopen device",
        ));
    }
    let traffic_path = config.storage.data_dir.join("storage-traffic.sqlite");
    let traffic = open_private(&traffic_path, false)?;
    let before = traffic.metadata()?;
    // immutable=1 reads an already closed traffic main without creating or
    // recovering WAL/SHM. A crash/hot ledger needs its separate ledger contract.
    let mut uri = String::from("file:");
    for byte in traffic_path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
            uri.push(*byte as char);
        } else {
            use std::fmt::Write;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_| ReconcileError::Invariant("storage traffic URI encoding"))?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let mut connection = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(JournalError::from)?;
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(JournalError::from)?;
    connection
        .set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 65_536)
        .map_err(JournalError::from)?;
    if connection
        .limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)
        .map_err(JournalError::from)?
        != 65_536
    {
        return Err(ReconcileError::Invariant(
            "original storage traffic row limit differs",
        ));
    }
    let began = std::time::Instant::now();
    let mut instructions = 0u64;
    connection
        .progress_handler(
            1000,
            Some(move || {
                instructions = instructions.saturating_add(1000);
                instructions > 1_000_000 || began.elapsed() > std::time::Duration::from_secs(5)
            }),
        )
        .map_err(JournalError::from)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(JournalError::from)?;
    let owner: (String, String, String, i64, i64) = connection
        .query_row(
            "SELECT space,device,policy,max_bytes,expires FROM owner",
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
        .map_err(JournalError::from)?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM owner", [], |row| row.get(0))
        .map_err(JournalError::from)?;
    if count != 1
        || owner.0 != config.storage.space_id.as_str()
        || owner.1 != device.as_str()
        || owner.2 != config.storage.fingerprint()?.as_str()
        || u64::try_from(owner.3).ok() != Some(config.storage.max_traffic_bytes)
        || u64::try_from(owner.4).ok() != Some(config.storage.expires_at_ms)
        || !stable(&before, &traffic.metadata()?)
        || !stable(&before, &fs::symlink_metadata(&traffic_path)?)
    {
        return Err(ReconcileError::Invariant(
            "original closed storage policy or identity differs",
        ));
    }
    Ok(())
}

impl LinuxStorageOwner {
    pub fn prepare_new(config: LinuxStorageOwnerConfig) -> Result<Self> {
        Self::prepare(config, true)
    }

    pub fn reopen_existing(config: LinuxStorageOwnerConfig) -> Result<Self> {
        Self::prepare(config, false)
    }

    fn prepare(config: LinuxStorageOwnerConfig, initialize: bool) -> Result<Self> {
        config.validate(initialize)?;
        let root = open_private(&config.storage.data_dir, true)?;
        // Cooperative opening serialization only. It prevents a second
        // storage preflight from opening a first owner's leased metadata.
        // The five mandatory leases and acquired namespace supply ownership.
        root.try_lock_exclusive()?;
        let root_identity = identity(&root.metadata()?);
        layout(&config, initialize)?;
        let bootstrap_budget = if initialize {
            let budget = Journal::storage_bootstrap_physical_budget(
                &config.storage.space_id,
                config.storage.max_metadata_entries,
            )?;
            let limits = config.metadata_limits;
            if limits.main < budget.main_bytes_minimum
                || limits.wal < budget.wal_bytes_minimum
                || limits.shm < budget.shm_bytes_minimum
                || limits.rollback_journal < budget.rollback_journal_bytes_minimum
                || limits.owner_record < budget.owner_record_bytes_minimum
                || limits.total_physical < budget.total_physical_bytes_minimum
            {
                return Err(ReconcileError::ResourceLimit(
                    "full storage bootstrap physical classes or aggregate; no originals created",
                ));
            }
            Some(budget)
        } else {
            None
        };
        // The final namespace acquisition opens and leases the one original
        // image descriptor before reading its full superblock and mounting it.
        // This read-only named identity supplies the expected original key;
        // the constructor refuses replacement before any namespace/loop effect.
        crate::check_ancestors(&config.backing_image)?;
        let image_metadata = fs::symlink_metadata(&config.backing_image)?;
        private(&image_metadata, false)?;
        if !(16 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&image_metadata.len()) {
            return Err(ReconcileError::Invariant(
                "bounded preformatted private storage image required",
            ));
        }
        let image_identity = UnixFileKey {
            device: image_metadata.dev(),
            inode: image_metadata.ino(),
        };
        if !initialize {
            preflight_identity(&config)?;
        }
        LinuxMetadataBudget::preflight_storage_only(
            &config.storage.data_dir,
            &root,
            image_identity,
            config.metadata_limits.into(),
            initialize,
        )?;
        let process_start_ticks = process_start_ticks()?;
        let owner = LinuxNamespaceCapability::acquire_storage_only_private_ext4_image(
            &config.backing_image,
            &config.mount_root,
            image_identity,
        )?;
        let prepared = if initialize {
            LinuxMetadataBudget::prepare_new_storage_only(
                &owner,
                &config.storage.data_dir,
                &root,
                config.metadata_limits.into(),
            )
        } else {
            LinuxMetadataBudget::reopen_storage_only(
                &owner,
                &config.storage.data_dir,
                &root,
                config.metadata_limits.into(),
            )
        };
        let budget = match prepared {
            Ok(budget) => budget,
            Err(error) => {
                if let Err(release) = owner.release_unarmed_mount() {
                    return Err(std::io::Error::other(format!(
                        "{error}; storage metadata preparation owner release refused: {release}"
                    ))
                    .into());
                }
                return Err(error.into());
            }
        };
        let result = Self {
            root_identity,
            config,
            owner,
            budget,
            root,
            process_start_ticks,
            initialize,
            bootstrap_budget,
        };
        if let Err(error) = result.verify() {
            let closed = result.finish();
            closed?;
            return Err(error);
        }
        Ok(result)
    }

    pub(crate) fn budget(&self) -> &LinuxMetadataBudget {
        &self.budget
    }

    pub(crate) fn verify_config(&self, config: &StorageNodeConfig, initialize: bool) -> Result<()> {
        self.verify()?;
        if config != &self.config.storage || initialize != self.initialize {
            return Err(ReconcileError::Invariant(
                "storage configuration or constructor differs from its live owner",
            ));
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.owner.verify()?;
        self.budget.validate_namespace_owner(&self.owner)?;
        private(&self.root.metadata()?, true)?;
        let named = fs::symlink_metadata(&self.config.storage.data_dir)?;
        if named.file_type().is_symlink()
            || self.root_identity != identity(&named)
            || self.root_identity != identity(&self.root.metadata()?)
            || process_start_ticks()? != self.process_start_ticks
            || !root_names(&self.config.storage.data_dir)?.is_subset(&allowed_names())
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }

    pub(crate) fn verify_journal(&self, journal: &Journal, device: &DeviceId) -> Result<()> {
        self.verify()?;
        if self
            .config
            .expected_device
            .as_ref()
            .is_some_and(|expected| expected != device)
            || journal.linux_metadata_receipt()?.is_none()
        {
            return Err(ReconcileError::Invariant(
                "storage Journal lacks its original full-FD owner or identity",
            ));
        }
        let max = self.config.storage.max_metadata_entries;
        let inventory = journal.storage_inventory(
            &self.config.storage.space_id,
            max,
            TreeRestoreInventoryLimits {
                max_rows: max,
                max_logical_bytes: (max as u64).saturating_mul(1024),
            },
        )?;
        let keys: BTreeSet<_> = inventory
            .rows()
            .iter()
            .filter(|row| row.table() == "local_state")
            .map(|row| row.primary_key().to_vec())
            .collect();
        let required: BTreeSet<_> = ["device_id", "space_id", "storage_role"]
            .into_iter()
            .map(|key| vec![key.to_owned()])
            .collect();
        if keys != required
            || journal.state("device_id")?.as_deref() != Some(device.as_str())
            || journal.state("space_id")?.as_deref() != Some(self.config.storage.space_id.as_str())
            || journal.state("storage_role")?.as_deref() != Some("storage-v1")
        {
            return Err(ReconcileError::Invariant(
                "storage-only Journal requires exactly its original three identity rows",
            ));
        }
        self.verify()
    }

    pub fn observation(&self) -> Result<LinuxStorageOwnerObservation> {
        self.verify()?;
        let volume = self.owner.volume().observation();
        Ok(LinuxStorageOwnerObservation {
            format_version: 1,
            scope: "linux-storage-only-full-journal-fd-v1",
            process_id: std::process::id(),
            process_start_ticks: self.process_start_ticks,
            policy_fingerprint: self.config.storage.fingerprint()?,
            backing_image: self.owner.backing_image_key().into(),
            namespace: self.owner.namespace_key().into(),
            mounted_root: volume.root_key.into(),
            runtime_mount_id: volume.runtime_mount_id,
            metadata: metadata_observation(
                self.budget.receipt()?,
                self.budget.persistent_owner_generation(),
            ),
            bootstrap_budget: self.bootstrap_budget.clone(),
            native_inspection_authority: false,
            marker_creation_authority: false,
            payload_move_authority: false,
            deletion_authority: false,
            pending_resume_authority: false,
            helpers_started: false,
            worktree: None,
        })
    }

    /// Call after dropping every StorageNode and its CAS/Journal callbacks.
    /// Never delete persistent files or unfamiliar residue during closure.
    pub fn finish(self) -> Result<LinuxStorageOwnerClosed> {
        let Self {
            owner,
            budget,
            process_start_ticks,
            root,
            ..
        } = self;
        let persistent = budget.persistent_owner_generation();
        let checkpoint = budget.checkpoint_closed();
        drop(budget);
        let release = owner.release_unarmed_mount();
        drop(root);
        let receipt = match (checkpoint, release) {
            (Ok(receipt), Ok(())) => receipt,
            (Err(error), Ok(())) => return Err(error.into()),
            (Ok(_), Err(error)) => return Err(error.into()),
            (Err(error), Err(release)) => {
                return Err(std::io::Error::other(format!(
                    "{error}; original storage owner release also refused: {release}"
                ))
                .into());
            }
        };
        let metadata = metadata_observation(receipt, persistent);
        Ok(LinuxStorageOwnerClosed {
            format_version: 1,
            process_id: std::process::id(),
            process_start_ticks,
            metadata,
            all_sqlite_connections_closed: true,
            original_mount_released: true,
            original_loop_released: true,
            helpers_started: false,
            pending_resume_authority: false,
        })
    }
}
