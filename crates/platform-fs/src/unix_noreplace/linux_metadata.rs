//! Physically reserved SQLite metadata files with an exact descriptor VFS.
//! Metadata budgets are checked before any named file is created. Ownership is
//! acquired through O_TMPFILE/AT_EMPTY_PATH, never adopted from a whitelist.
use super::{key, name, UnixDirectory, UnixFileKey};
use crate::{linux_write_lease::OriginalWriteLease, LinuxNamespaceCapability, LinuxNativeAttempt};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

mod abi;
mod callbacks;
mod owner_record;

const CLASSES: [&str; 5] = ["main", "wal", "shm", "rollback_journal", "owner_record"];
const MAX_FILE_CAPACITY: u64 = 256 * 1024 * 1024;
const STORAGE_BLOCK_BYTES: u64 = 4096;
// The accepted driver is the exact kernel whose extent-depth and xattr
// allocation contracts were retained with the storage-only acceptance record.
// An unverified driver/profile is refused before mount or original CREATE.
const STORAGE_EXT4_KERNEL: &str = "6.6.87.2-microsoft-standard-WSL2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxMetadataLimits {
    pub main: u64,
    pub wal: u64,
    pub shm: u64,
    pub rollback_journal: u64,
    pub owner_record: u64,
    pub total_physical: u64,
}

impl LinuxMetadataLimits {
    /// Conservative physical liability, distinct from data capacity and the
    /// later observed allocation. A 4-KiB ext4 extent tree has depth <= 5.
    /// Nonempty nodes at each level cannot outnumber its nonempty data extents,
    /// and each extent contains >= one data block. Without EA_INODE, an inode
    /// can additionally own at most one external 4-KiB xattr block.
    /// P(C) = rounded_data + 4096 * (5 * data_blocks + 1).
    /// This arithmetic grants no filesystem, owner, VFS or native authority.
    pub fn storage_only_physical_liabilities(self) -> io::Result<[u64; 5]> {
        let capacities = self.capacities(STORAGE_BLOCK_BYTES)?;
        let mut liabilities = [0u64; 5];
        let mut total = 0u64;
        for (index, capacity) in capacities.into_iter().enumerate() {
            let mapping_and_ea = (capacity / STORAGE_BLOCK_BYTES)
                .checked_mul(5)
                .and_then(|value| value.checked_add(1))
                .and_then(|value| value.checked_mul(STORAGE_BLOCK_BYTES))
                .ok_or_else(|| refuse("storage ext4 mapping/xattr liability overflow"))?;
            liabilities[index] = capacity
                .checked_add(mapping_and_ea)
                .ok_or_else(|| refuse("storage ext4 class liability overflow"))?;
            total = total
                .checked_add(liabilities[index])
                .ok_or_else(|| refuse("storage ext4 aggregate liability overflow"))?;
        }
        if total > self.total_physical {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "whole configured storage ext4 data/mapping/xattr liability refused",
            ));
        }
        Ok(liabilities)
    }

    fn capacities(self, block: u64) -> io::Result<[u64; 5]> {
        let mut capacities = [
            self.main,
            self.wal,
            self.shm,
            self.rollback_journal,
            self.owner_record,
        ];
        if block == 0 || !block.is_power_of_two() || block > 64 * 1024 {
            return Err(io::Error::other(
                "metadata filesystem block size is unsupported",
            ));
        }
        for capacity in &mut capacities {
            if *capacity == 0 || *capacity > MAX_FILE_CAPACITY {
                return Err(io::Error::other(
                    "metadata class capacity is outside its contract",
                ));
            }
            *capacity = capacity
                .checked_add(block - 1)
                .and_then(|value| value.checked_div(block))
                .and_then(|value| value.checked_mul(block))
                .ok_or_else(|| io::Error::other("metadata class allocation overflow"))?;
        }
        if capacities[2] < 32 * 1024 || capacities[2] % (32 * 1024) != 0 || capacities[4] < 4096 {
            return Err(io::Error::other(
                "SHM/owner record capacity alignment is invalid",
            ));
        }
        let total = capacities
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(*value))
            .ok_or_else(|| io::Error::other("whole metadata allocation overflow"))?;
        if total > self.total_physical {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "whole metadata physical budget refused",
            ));
        }
        Ok(capacities)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxMetadataFileReceipt {
    pub class: &'static str,
    pub identity: UnixFileKey,
    pub logical_bytes: u64,
    pub actual_file_bytes: u64,
    pub allocated_bytes: u64,
    pub capacity_bytes: u64,
    pub sealed_allocated_bytes: Option<u64>,
    pub physical_liability_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxMetadataReceipt {
    pub format_version: u32,
    pub owner_generation: [u8; 16],
    pub backing_image: UnixFileKey,
    pub namespace: UnixFileKey,
    pub parent: UnixFileKey,
    pub total_allocated_bytes: u64,
    pub total_physical_budget: u64,
    pub total_physical_liability_bytes: Option<u64>,
    pub storage_metadata_device: Option<u64>,
    pub storage_block_identity: Option<UnixFileKey>,
    pub storage_superblock_uuid: Option<[u8; 16]>,
    pub storage_ext4_features: Option<[u32; 3]>,
    pub storage_kernel_contract: Option<&'static str>,
    pub storage_active_sqlite_files: Option<u64>,
    pub disk_temp_files_allowed: bool,
    pub files: [LinuxMetadataFileReceipt; 5],
}

struct MetadataFile {
    file: File,
    identity: UnixFileKey,
    component: CString,
    path: CString,
    lease: OriginalWriteLease,
    capacity: u64,
    logical_bytes: AtomicU64,
}

struct SharedMemoryLock {
    exclusive: Option<u64>,
    shared: Vec<u64>,
}

#[derive(Clone, Copy)]
struct StorageExt4Profile {
    metadata_device: u64,
    block_identity: UnixFileKey,
    uuid: [u8; 16],
    features: [u32; 3],
}

struct State {
    directory: File,
    directory_path: PathBuf,
    directory_key: UnixFileKey,
    mount_id: u64,
    files: [MetadataFile; 5],
    owner_generation: [u8; 16],
    persistent_generation: [u8; 16],
    backing_image: UnixFileKey,
    namespace: UnixFileKey,
    owner_pid: u32,
    total_limit: u64,
    initial_allocated: u64,
    storage_sealed: Option<[u64; 5]>,
    storage_liabilities: Option<[u64; 5]>,
    storage_profile: Option<StorageExt4Profile>,
    next_connection: AtomicU64,
    active_files: AtomicU64,
    locks: Mutex<BTreeMap<u64, i32>>,
    shm_locks: Mutex<[SharedMemoryLock; 8]>,
    poisoned: AtomicBool,
    refusal: Mutex<Option<String>>,
    owner_record_lock: Mutex<()>,
}

fn refuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn file_blocks(file: &File) -> io::Result<u64> {
    file.metadata()?
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::other("metadata allocated block overflow"))
}

fn storage_superblock(file: &File) -> io::Result<([u8; 16], [u32; 3])> {
    let mut kernel = String::new();
    use std::io::Read;
    File::open("/proc/sys/kernel/osrelease")?
        .take(4097)
        .read_to_string(&mut kernel)?;
    if kernel.len() > 4096 || kernel.trim_end() != STORAGE_EXT4_KERNEL {
        return Err(refuse("storage-only ext4 kernel contract is unverified"));
    }
    let mut superblock = [0u8; 1024];
    file.read_exact_at(&mut superblock, 1024)?;
    let u32_at = |offset: usize| {
        u32::from_le_bytes(
            superblock[offset..offset + 4]
                .try_into()
                .expect("fixed ext4 superblock field"),
        )
    };
    let features = [u32_at(92), u32_at(96), u32_at(100)];
    let inode_bytes = u16::from_le_bytes(
        superblock[88..90]
            .try_into()
            .expect("fixed ext4 inode-size field"),
    );
    let mut checksum = u32::MAX;
    for byte in &superblock[..1020] {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            checksum = (checksum >> 1) ^ if checksum & 1 == 0 { 0 } else { 0x82f63b78 };
        }
    }
    // Only this ext4 extent geometry is accepted. In particular EA_INODE,
    // BIGALLOC, inline data, encryption, compression, verity and unreviewed
    // feature bits cannot change the per-inode physical liability.
    // RECOVER is the ordinary mounted-journal bit, not an extra file class.
    if superblock[56..58] != [0x53, 0xef]
        || u32_at(24) != 2
        || u32_at(28) != 2
        || u32_at(76) != 1
        || u32_at(20) != 0
        || u32_at(32) == 0
        || u32_at(32) > 32_768
        || u32_at(32) != u32_at(36)
        || inode_bytes < 128
        || !inode_bytes.is_power_of_two()
        || u64::from(inode_bytes) > STORAGE_BLOCK_BYTES
        || features[0] & !0x3c != 0
        || features[1] & !0x2c6 != 0
        || features[2] & !0x46b != 0
        || features[1] & 0x40 == 0
        || features[2] & 0x400 == 0
        || superblock[0x175] != 1
        || checksum != u32_at(1020)
        || superblock[104..120] == [0u8; 16]
    {
        return Err(refuse(
            "storage-only original ext4 data/mapping/xattr profile is unverified",
        ));
    }
    let metadata = file.metadata()?;
    if metadata.is_file() {
        let blocks = u64::from(u32_at(4)) | (u64::from(u32_at(0x150)) << 32);
        if blocks == 0
            || blocks
                .checked_mul(STORAGE_BLOCK_BYTES)
                .is_none_or(|bytes| bytes > metadata.len())
        {
            return Err(refuse("original storage ext4 geometry exceeds its image"));
        }
    }
    Ok((
        superblock[104..120]
            .try_into()
            .map_err(|_| refuse("storage ext4 UUID encoding"))?,
        features,
    ))
}

fn storage_profile(directory: &File) -> io::Result<StorageExt4Profile> {
    super::held_volume::private(directory, true)?;
    let directory_key = key(directory)?;
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: original retained directory and correctly sized statfs output.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the complete output.
    let status = unsafe { status.assume_init() };
    if status.f_type != 0xef53 || u64::try_from(status.f_bsize).ok() != Some(STORAGE_BLOCK_BYTES) {
        return Err(refuse("storage-only original metadata requires 4-KiB ext4"));
    }
    let device = directory.metadata()?.dev();
    let device_path = PathBuf::from(format!(
        "/dev/block/{}:{}",
        libc::major(device),
        libc::minor(device)
    ));
    let device_name = if std::fs::symlink_metadata(&device_path)?
        .file_type()
        .is_symlink()
    {
        let target = std::fs::read_link(&device_path)?;
        let text = target
            .to_str()
            .and_then(|text| text.strip_prefix("../"))
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= 255
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
            .ok_or_else(|| refuse("metadata original block node encoding is unsupported"))?;
        PathBuf::from("/dev").join(text)
    } else {
        device_path
    };
    let block = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(device_name)?;
    let block_metadata = block.metadata()?;
    if !block_metadata.file_type().is_block_device()
        || block_metadata.rdev() != device
        || key(directory)? != directory_key
    {
        return Err(refuse(
            "metadata original root FD and block FD device binding differs",
        ));
    }
    let (uuid, features) = storage_superblock(&block)?;
    if block.metadata()?.rdev() != directory.metadata()?.dev() || key(directory)? != directory_key {
        return Err(refuse("metadata original ext4 block binding changed"));
    }
    Ok(StorageExt4Profile {
        metadata_device: device,
        block_identity: key(&block)?,
        uuid,
        features,
    })
}

#[repr(C)]
#[derive(Default)]
struct StorageExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}

#[repr(C)]
struct StorageFiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extent: StorageExtent,
}

fn verify_materialized(file: &File, capacity: u64) -> io::Result<()> {
    let mut inode_flags: libc::c_long = 0;
    // SAFETY: exact original regular descriptor and initialized flags output.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            0x80086601 as libc::Ioctl,
            &mut inode_flags,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if inode_flags != 0x80000 || file.metadata()?.len() != capacity {
        return Err(refuse(
            "storage materialization inode/extent contract differs",
        ));
    }
    let mut cursor = 0u64;
    while cursor < capacity {
        let mut map = StorageFiemap {
            start: cursor,
            length: u64::MAX - cursor,
            flags: 0,
            mapped: 0,
            count: 1,
            reserved: 0,
            extent: StorageExtent::default(),
        };
        // SAFETY: bounded one-extent FIEMAP structure for this exact original FD.
        if unsafe { libc::ioctl(file.as_raw_fd(), 0xc020660b as libc::Ioctl, &mut map) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if map.mapped != 1
            || map.extent.logical != cursor
            || map.extent.physical == 0
            || map.extent.physical % STORAGE_BLOCK_BYTES != 0
            || map.extent.physical.checked_add(map.extent.length).is_none()
            || map.extent.length == 0
            || map.extent.length % STORAGE_BLOCK_BYTES != 0
            || map.extent.flags & !1 != 0
            || map
                .extent
                .logical
                .checked_add(map.extent.length)
                .is_none_or(|end| end > capacity)
            || (map.extent.logical + map.extent.length == capacity && map.extent.flags & 1 == 0)
        {
            return Err(refuse(
                "storage original capacity has holes, unwritten or unverified extents",
            ));
        }
        cursor += map.extent.length;
    }
    Ok(())
}

fn mount_identity(file: &File) -> io::Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    if text.len() > 4096 {
        return Err(refuse("metadata fdinfo exceeded bound"));
    }
    let mut records = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let value = records
        .next()
        .ok_or_else(|| refuse("metadata mount identity absent"))?
        .trim()
        .parse::<u64>()
        .map_err(|_| refuse("metadata mount identity invalid"))?;
    if value == 0 || records.next().is_some() {
        return Err(refuse("metadata mount identity ambiguous"));
    }
    Ok(value)
}

impl State {
    fn poison(&self, error: &io::Error) {
        self.poisoned.store(true, Ordering::Release);
        if let Ok(mut receipt) = self.refusal.lock() {
            if receipt.is_none() {
                *receipt = Some(error.to_string());
            }
        }
    }

    fn verify(&self) -> io::Result<()> {
        if self.poisoned.load(Ordering::Acquire) || self.owner_pid != std::process::id() {
            return Err(refuse(
                "metadata owner is poisoned or belongs to another process",
            ));
        }
        let current = File::open("/proc/self/ns/mnt")?;
        if key(&current)? != self.namespace
            || key(&self.directory)? != self.directory_key
            || mount_identity(&self.directory)? != self.mount_id
            || UnixDirectory::open(&self.directory_path)?.key()? != self.directory_key
        {
            return Err(refuse("metadata original parent/mount/namespace changed"));
        }
        let mut total = 0u64;
        for (index, slot) in self.files.iter().enumerate() {
            slot.lease.verify()?;
            let metadata = slot.file.metadata()?;
            // SAFETY: fixed uid query with no arguments or pointers.
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.len() > slot.capacity
                || (self.storage_sealed.is_some() && metadata.len() != slot.capacity)
                || key(&slot.file)? != slot.identity
                || mount_identity(&slot.file)? != self.mount_id
            {
                return Err(refuse("metadata exact original file contract changed"));
            }
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: held directory and bounded exact component, non-following identity check.
            if unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    slot.component.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fstatat initialized the full stat result.
            let status = unsafe { status.assume_init() };
            if status.st_dev != slot.identity.device
                || status.st_ino != slot.identity.inode
                || status.st_mode & libc::S_IFMT != libc::S_IFREG
                || status.st_nlink != 1
            {
                return Err(refuse(
                    "metadata named slot no longer matches its held original",
                ));
            }
            let allocated = file_blocks(&slot.file)?;
            if allocated < slot.capacity {
                return Err(refuse("metadata physical allocation was released"));
            }
            if self
                .storage_sealed
                .is_some_and(|sealed| allocated != sealed[index])
                || self
                    .storage_liabilities
                    .is_some_and(|liabilities| allocated > liabilities[index])
            {
                return Err(refuse(
                    "storage metadata sealed class allocation changed or exceeded liability",
                ));
            }
            total = total
                .checked_add(allocated)
                .ok_or_else(|| refuse("metadata physical total overflow"))?;
        }
        if total != self.initial_allocated || total > self.total_limit {
            return Err(refuse(
                "metadata physical aggregate changed or exceeded its budget",
            ));
        }
        self.verify_owner_record()?;
        Ok(())
    }

    fn snapshot(&self) -> io::Result<LinuxMetadataReceipt> {
        self.verify()?;
        let mut receipts = Vec::with_capacity(5);
        let mut total = 0u64;
        for (index, slot) in self.files.iter().enumerate() {
            let allocated = file_blocks(&slot.file)?;
            total = total
                .checked_add(allocated)
                .ok_or_else(|| refuse("metadata total overflow"))?;
            receipts.push(LinuxMetadataFileReceipt {
                class: CLASSES[index],
                identity: slot.identity,
                logical_bytes: slot.logical_bytes.load(Ordering::Acquire),
                actual_file_bytes: slot.file.metadata()?.len(),
                allocated_bytes: allocated,
                capacity_bytes: slot.capacity,
                sealed_allocated_bytes: self.storage_sealed.map(|sealed| sealed[index]),
                physical_liability_bytes: self
                    .storage_liabilities
                    .map(|liabilities| liabilities[index]),
            });
        }
        self.verify()?;
        Ok(LinuxMetadataReceipt {
            format_version: 1,
            owner_generation: self.owner_generation,
            backing_image: self.backing_image,
            namespace: self.namespace,
            parent: self.directory_key,
            total_allocated_bytes: total,
            total_physical_budget: self.total_limit,
            total_physical_liability_bytes: self
                .storage_liabilities
                .map(|liabilities| liabilities.into_iter().sum()),
            storage_metadata_device: self.storage_profile.map(|profile| profile.metadata_device),
            storage_block_identity: self.storage_profile.map(|profile| profile.block_identity),
            storage_superblock_uuid: self.storage_profile.map(|profile| profile.uuid),
            storage_ext4_features: self.storage_profile.map(|profile| profile.features),
            storage_kernel_contract: self.storage_profile.map(|_| STORAGE_EXT4_KERNEL),
            storage_active_sqlite_files: self
                .storage_profile
                .map(|_| self.active_files.load(Ordering::Acquire)),
            disk_temp_files_allowed: false,
            files: receipts
                .try_into()
                .map_err(|_| refuse("metadata receipt class count"))?,
        })
    }
}

/// Five exact original objects. Temporary/attached/super/sub journals cannot be
/// opened by its VFS; a caller cannot add a new path or derive ownership from JSON.
pub struct LinuxMetadataBudget {
    state: Arc<State>,
    storage_only: bool,
}

impl LinuxMetadataBudget {
    /// Fixed storage role; the complete original acquisition remains required.
    /// The role selects SQLite bootstrap accounting, never native authority.
    pub fn prepare_new_storage_only(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        original_directory: &File,
        limits: LinuxMetadataLimits,
    ) -> io::Result<Self> {
        Self::prepare_new_impl(
            owner,
            directory_path,
            "journal.sqlite",
            limits,
            Some(original_directory),
        )
    }

    pub fn reopen_storage_only(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        original_directory: &File,
        limits: LinuxMetadataLimits,
    ) -> io::Result<Self> {
        Self::reopen_existing_impl(
            owner,
            directory_path,
            "journal.sqlite",
            limits,
            Some(original_directory),
        )
    }

    pub fn is_storage_only(&self) -> bool {
        self.storage_only
    }

    /// Read-only structural preflight for the explicit storage-only role.
    /// This returns no original owner, lease, VFS, native attempt or authority.
    /// The caller serializes storage opening before touching these old slots;
    /// acquisition and every original lease are still required afterwards.
    pub fn preflight_storage_only(
        directory_path: &Path,
        original_directory: &File,
        backing_image: UnixFileKey,
        limits: LinuxMetadataLimits,
        initialize: bool,
    ) -> io::Result<()> {
        let directory = UnixDirectory::open(directory_path)?.file;
        if key(&directory)? != key(original_directory)?
            || mount_identity(&directory)? != mount_identity(original_directory)?
        {
            return Err(refuse("storage preflight original metadata parent differs"));
        }
        let _ = storage_profile(original_directory)?;
        let liabilities = limits.storage_only_physical_liabilities()?;
        super::held_volume::private(&directory, true)?;
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: retained directory and properly sized writable statfs output.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized output.
        let status = unsafe { status.assume_init() };
        if status.f_type != 0xef53 {
            return Err(refuse("storage-only metadata requires local ext4"));
        }
        let capacities = limits.capacities(
            u64::try_from(status.f_bsize).map_err(|_| refuse("metadata block size"))?,
        )?;
        let components = [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-shm",
            "journal.sqlite-journal",
            "journal.sqlite.metadata-owner",
        ];
        if initialize {
            for component in components {
                let component = name(component)?;
                let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: held original directory and fixed nonfollowing component.
                if unsafe {
                    libc::fstatat(
                        directory.as_raw_fd(),
                        component.as_ptr(),
                        status.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0
                {
                    return Err(refuse("storage metadata preflight found an occupied slot"));
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(io::Error::last_os_error());
                }
            }
            return Ok(());
        }
        let mut files = Vec::with_capacity(5);
        for component in components {
            let component = name(component)?;
            // SAFETY: fixed component, exact held parent, read-only/no-follow open.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat transferred this one read-only descriptor.
            let file = unsafe { File::from_raw_fd(descriptor) };
            super::held_volume::private(&file, false)?;
            files.push(file);
        }
        let record = owner_record::Record::read_storage_only(&files[4])?;
        if record.backing_image != backing_image
            || record.directory != key(&directory)?
            || record.capacities != capacities
            || record.total_limit != limits.total_physical
        {
            return Err(refuse(
                "storage preflight original image, parent or budget differs",
            ));
        }
        let mut physical = 0u64;
        for (index, file) in files.iter().enumerate() {
            if key(file)? != record.files[index]
                || file.metadata()?.len() != capacities[index]
                || file_blocks(file)? < capacities[index]
                || file_blocks(file)?
                    != record
                        .storage_sealed
                        .ok_or_else(|| refuse("storage preflight v3 seal is absent"))?[index]
                || file_blocks(file)? > liabilities[index]
                || mount_identity(file)? != mount_identity(&directory)?
            {
                return Err(refuse(
                    "storage preflight original metadata file was substituted",
                ));
            }
            verify_materialized(file, capacities[index])?;
            physical = physical
                .checked_add(file_blocks(file)?)
                .ok_or_else(|| refuse("storage preflight allocation overflow"))?;
        }
        if physical != record.allocated || physical > record.total_limit {
            return Err(refuse("storage preflight physical allocation differs"));
        }
        Ok(())
    }

    /// Validate only the final acquired original image descriptor. The
    /// namespace constructor invokes this before unshare/loop/mount and keeps
    /// that same descriptor for the mandatory lease and LOOP_CONFIGURE.
    pub fn preflight_storage_only_image(image: &File) -> io::Result<()> {
        super::held_volume::private(image, false)?;
        let before = image.metadata()?;
        if !(16 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&before.len()) {
            return Err(refuse("bounded original storage ext4 image required"));
        }
        let _ = storage_superblock(image)?;
        let after = image.metadata()?;
        if key(image)?
            != (UnixFileKey {
                device: before.dev(),
                inode: before.ino(),
            })
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(refuse("original storage image changed during preflight"));
        }
        Ok(())
    }

    pub fn prepare_new(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        database_component: &str,
        limits: LinuxMetadataLimits,
    ) -> io::Result<Self> {
        Self::prepare_new_impl(owner, directory_path, database_component, limits, None)
    }

    fn prepare_new_impl(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        database_component: &str,
        limits: LinuxMetadataLimits,
        original_directory: Option<&File>,
    ) -> io::Result<Self> {
        owner.verify()?;
        if directory_path.to_str().is_none() {
            return Err(refuse("metadata root requires UTF8 encoding"));
        }
        let named_directory = UnixDirectory::open(directory_path)?.file;
        let directory = if let Some(original) = original_directory {
            if key(&named_directory)? != key(original)? {
                return Err(refuse(
                    "storage original metadata directory changed before CREATE",
                ));
            }
            // unshare clones mount IDs. Keep the actual preflight original
            // outside-volume parent FD rather than adopting its new pathname
            // mount; every original is created/linked relative to this FD.
            original.try_clone()?
        } else {
            named_directory
        };
        let storage_profile = if let Some(original) = original_directory {
            if key(&directory)? != key(original)? {
                return Err(refuse(
                    "storage original metadata directory changed before CREATE",
                ));
            }
            Some(storage_profile(original)?)
        } else {
            None
        };
        let storage_liabilities = original_directory
            .map(|_| limits.storage_only_physical_liabilities())
            .transpose()?;
        let metadata = directory.metadata()?;
        // SAFETY: fixed uid query.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.dev() == owner.volume().observation().root_key.device
        {
            return Err(refuse(
                "metadata requires an owner-only outside-volume directory",
            ));
        }
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: retained directory fd and properly sized writable statfs output.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized output.
        let stat = unsafe { stat.assume_init() };
        if stat.f_type != 0xef53 {
            return Err(refuse("outside metadata must reside on local ext4"));
        }
        let capacities = limits
            .capacities(u64::try_from(stat.f_bsize).map_err(|_| refuse("metadata block size"))?)?;
        let _ = name(database_component)?;
        if database_component.starts_with('.') || database_component.len() > 220 {
            return Err(refuse(
                "metadata database component is outside its contract",
            ));
        }
        let components = [
            database_component.to_owned(),
            format!("{database_component}-wal"),
            format!("{database_component}-shm"),
            format!("{database_component}-journal"),
            format!("{database_component}.metadata-owner"),
        ];
        // Every original slot must be absent; no existing sidecar is adopted or deleted.
        for component in &components {
            let component = name(component)?;
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: exact held parent and bounded single component.
            let exists = unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if exists == 0 {
                return Err(refuse("metadata original named slot is already occupied"));
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(io::Error::last_os_error());
            }
        }
        let directory_key = key(&directory)?;
        let mount_id = mount_identity(&directory)?;
        let dot = CString::new(".").expect("fixed anonymous parent");
        let mut prepared = Vec::with_capacity(5);
        let mut physical = 0u64;
        let mut sealed = [0u64; 5];
        for (index, capacity) in capacities.into_iter().enumerate() {
            // SAFETY: O_TMPFILE creates an unnamed original with one owned descriptor.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    dot.as_ptr(),
                    libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                    0o600 as libc::mode_t,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat transferred one original fd.
            let file = unsafe { File::from_raw_fd(fd) };
            if storage_liabilities.is_some() {
                // Write every configured data block, including the owner file,
                // before recording any seal or linking any named original.
                // Fallocate unwritten extents are insufficient: their first
                // WAL write can allocate an additional mapping block.
                let zeroes = [0u8; 64 * 1024];
                let mut offset = 0u64;
                while offset < capacity {
                    let amount = (capacity - offset).min(zeroes.len() as u64) as usize;
                    file.write_all_at(&zeroes[..amount], offset)?;
                    offset += amount as u64;
                }
                file.sync_all()?;
                verify_materialized(&file, capacity)?;
            } else {
                // SAFETY: original generic role keeps KEEP_SIZE and its
                // original main/WAL physical and logical behavior.
                if unsafe {
                    libc::fallocate(
                        file.as_raw_fd(),
                        libc::FALLOC_FL_KEEP_SIZE,
                        0,
                        capacity as i64,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let allocated = file_blocks(&file)?;
            if allocated < capacity
                || storage_liabilities.is_some_and(|liability| allocated > liability[index])
            {
                return Err(refuse("metadata preallocation did not reserve all blocks"));
            }
            sealed[index] = allocated;
            physical = physical
                .checked_add(allocated)
                .ok_or_else(|| refuse("metadata actual allocation overflow"))?;
            prepared.push(file);
        }
        if physical > limits.total_physical {
            // All files are still unnamed, so failure leaves no named metadata or database effects.
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "actual whole metadata allocation refused",
            ));
        }
        owner.verify()?;
        // SHM's fixed mapping extent exists physically and logically for every allowed region.
        if storage_liabilities.is_none() {
            prepared[2].set_len(capacities[2])?;
        }
        let initial_logical = [0, 0, capacities[2], 0, owner_record::RECORD_BYTES as u64];
        let identities = prepared.iter().map(key).collect::<io::Result<Vec<_>>>()?;
        let owner_record = owner_record::Record {
            generation: owner.owner_generation(),
            backing_image: owner.backing_image_key(),
            directory: directory_key,
            capacities,
            files: identities
                .try_into()
                .map_err(|_| refuse("metadata original identity count"))?,
            allocated: physical,
            total_limit: limits.total_physical,
            logical: initial_logical,
            storage_sealed: storage_liabilities.map(|_| sealed),
        };
        if storage_liabilities.is_some() {
            prepared[4].write_all_at(&owner_record.encode()?, 0)?;
        } else {
            prepared[4].write_all(&owner_record.encode()?)?;
        }
        prepared[4].sync_all()?;
        if storage_liabilities.is_some() {
            for (index, file) in prepared.iter().enumerate() {
                if file_blocks(file)? != sealed[index] {
                    return Err(refuse(
                        "storage initialized owner-record write changed its seal",
                    ));
                }
            }
        }
        let empty = CString::new("").expect("fixed empty component");
        let mut files = Vec::with_capacity(5);
        for (index, file) in prepared.into_iter().enumerate() {
            owner.verify()?;
            let component = name(&components[index])?;
            // SAFETY: link only this original O_TMPFILE; AT_EMPTY_PATH never adopts an occupant.
            if unsafe {
                libc::linkat(
                    file.as_raw_fd(),
                    empty.as_ptr(),
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    libc::AT_EMPTY_PATH,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let identity = key(&file)?;
            let logical_bytes = if storage_liabilities.is_some() {
                initial_logical[index]
            } else {
                file.metadata()?.len()
            };
            let lease = OriginalWriteLease::acquire(&file)?;
            files.push(MetadataFile {
                file,
                identity,
                component,
                path: CString::new(
                    directory_path
                        .join(&components[index])
                        .as_os_str()
                        .as_encoded_bytes(),
                )
                .map_err(|_| refuse("metadata path contains NUL"))?,
                lease,
                capacity: capacities[index],
                logical_bytes: AtomicU64::new(logical_bytes),
            });
        }
        directory.sync_all()?;
        let state = Arc::new(State {
            directory,
            directory_path: directory_path.to_owned(),
            directory_key,
            mount_id,
            files: files
                .try_into()
                .map_err(|_| refuse("metadata original class count"))?,
            owner_generation: owner.owner_generation(),
            persistent_generation: owner.owner_generation(),
            backing_image: owner.backing_image_key(),
            namespace: owner.namespace_key(),
            owner_pid: std::process::id(),
            total_limit: limits.total_physical,
            initial_allocated: physical,
            storage_sealed: storage_liabilities.map(|_| sealed),
            storage_liabilities,
            storage_profile,
            next_connection: AtomicU64::new(1),
            active_files: AtomicU64::new(0),
            locks: Mutex::new(BTreeMap::new()),
            shm_locks: Mutex::new(std::array::from_fn(|_| SharedMemoryLock {
                exclusive: None,
                shared: Vec::new(),
            })),
            poisoned: AtomicBool::new(false),
            refusal: Mutex::new(None),
            owner_record_lock: Mutex::new(()),
        });
        state.verify()?;
        Ok(Self {
            state,
            storage_only: original_directory.is_some(),
        })
    }

    pub fn receipt(&self) -> io::Result<LinuxMetadataReceipt> {
        self.state.snapshot()
    }
    pub fn verify(&self) -> io::Result<()> {
        self.state.verify()
    }
    /// A replacement with equal bytes cannot satisfy the embedded original
    /// inode identities, including the identity of the record itself.
    /// All five kernel leases are reacquired before SHM recovery or SQLite I/O.
    pub fn reopen_existing(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        database_component: &str,
        limits: LinuxMetadataLimits,
    ) -> io::Result<Self> {
        Self::reopen_existing_impl(owner, directory_path, database_component, limits, None)
    }

    fn reopen_existing_impl(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        database_component: &str,
        limits: LinuxMetadataLimits,
        original_directory: Option<&File>,
    ) -> io::Result<Self> {
        owner.verify()?;
        if directory_path.to_str().is_none() {
            return Err(refuse("metadata root requires UTF8 encoding"));
        }
        let named_directory = UnixDirectory::open(directory_path)?.file;
        let directory = if let Some(original) = original_directory {
            if key(&named_directory)? != key(original)? {
                return Err(refuse(
                    "storage original metadata directory changed before reopen",
                ));
            }
            original.try_clone()?
        } else {
            named_directory
        };
        let storage_profile = if let Some(original) = original_directory {
            if key(&directory)? != key(original)? {
                return Err(refuse(
                    "storage original metadata directory changed before reopen",
                ));
            }
            Some(storage_profile(original)?)
        } else {
            None
        };
        let storage_liabilities = original_directory
            .map(|_| limits.storage_only_physical_liabilities())
            .transpose()?;
        let metadata = directory.metadata()?;
        // SAFETY: fixed uid query.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.dev() == owner.volume().observation().root_key.device
        {
            return Err(refuse(
                "metadata requires an owner-only outside-volume directory",
            ));
        }
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: exact held parent and properly sized writable statfs output.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized this output.
        let stat = unsafe { stat.assume_init() };
        if stat.f_type != 0xef53 {
            return Err(refuse("outside metadata must reside on local ext4"));
        }
        let capacities = limits
            .capacities(u64::try_from(stat.f_bsize).map_err(|_| refuse("metadata block size"))?)?;
        let _ = name(database_component)?;
        if database_component.starts_with('.') || database_component.len() > 220 {
            return Err(refuse(
                "metadata database component is outside its contract",
            ));
        }
        let components = [
            database_component.to_owned(),
            format!("{database_component}-wal"),
            format!("{database_component}-shm"),
            format!("{database_component}-journal"),
            format!("{database_component}.metadata-owner"),
        ];
        let open = |component: &str| -> io::Result<File> {
            let component = name(component)?;
            // SAFETY: exact held parent, bounded component and no-follow open.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat transferred this single descriptor.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        };
        let record_file = open(&components[4])?;
        super::held_volume::private(&record_file, false)?;
        let record_lease = OriginalWriteLease::acquire(&record_file)?;
        let record = if original_directory.is_some() {
            owner_record::Record::read_storage_only(&record_file)?
        } else {
            owner_record::Record::read(&record_file)?
        };
        let directory_key = key(&directory)?;
        if record.backing_image != owner.backing_image_key()
            || record.directory != directory_key
            || record.files[4] != key(&record_file)?
            || record.capacities != capacities
            || record.total_limit != limits.total_physical
        {
            return Err(refuse(
                "persistent metadata identity or requested budget differs",
            ));
        }
        let mount_id = mount_identity(&directory)?;
        let mut opened = Vec::with_capacity(5);
        for index in 0..4 {
            let file = open(&components[index])?;
            super::held_volume::private(&file, false)?;
            let allocated = file_blocks(&file)?;
            if key(&file)? != record.files[index]
                || file.metadata()?.len() > capacities[index]
                || (storage_liabilities.is_some() && file.metadata()?.len() != capacities[index])
                || allocated < capacities[index]
                || record
                    .storage_sealed
                    .is_some_and(|sealed| allocated != sealed[index])
                || storage_liabilities.is_some_and(|liability| allocated > liability[index])
                || mount_identity(&file)? != mount_id
            {
                return Err(refuse("persistent metadata original file was substituted"));
            }
            let lease = OriginalWriteLease::acquire(&file)?;
            opened.push((file, lease));
        }
        opened.push((record_file, record_lease));
        owner.verify()?;
        let mut files = Vec::with_capacity(5);
        let mut physical = 0u64;
        for (index, (file, lease)) in opened.into_iter().enumerate() {
            let allocated = file_blocks(&file)?;
            if record
                .storage_sealed
                .is_some_and(|sealed| allocated != sealed[index])
                || storage_liabilities.is_some_and(|liability| allocated > liability[index])
            {
                return Err(refuse(
                    "persistent storage class allocation differs from its v3 seal",
                ));
            }
            if storage_liabilities.is_some() {
                verify_materialized(&file, capacities[index])?;
            }
            physical = physical
                .checked_add(allocated)
                .ok_or_else(|| refuse("reopened metadata allocation overflow"))?;
            let mut logical = record.logical[index];
            if matches!(index, 1 | 3) && file.metadata()?.len() >= 32 {
                let mut header = [0u8; 32];
                file.read_exact_at(&mut header, 0)?;
                if header == [0u8; 32] {
                    logical = 0;
                }
            }
            if logical > file.metadata()?.len() {
                return Err(refuse("persistent metadata logical extent is absent"));
            }
            let component = name(&components[index])?;
            files.push(MetadataFile {
                identity: key(&file)?,
                file,
                lease,
                component,
                path: CString::new(
                    directory_path
                        .join(&components[index])
                        .as_os_str()
                        .as_encoded_bytes(),
                )
                .map_err(|_| refuse("metadata path contains NUL"))?,
                capacity: capacities[index],
                logical_bytes: AtomicU64::new(logical),
            });
        }
        if physical != record.allocated || physical > record.total_limit {
            return Err(refuse("persistent metadata physical allocation changed"));
        }
        let state = Arc::new(State {
            directory,
            directory_path: directory_path.to_owned(),
            directory_key,
            mount_id,
            files: files
                .try_into()
                .map_err(|_| refuse("metadata original class count"))?,
            owner_generation: owner.owner_generation(),
            persistent_generation: record.generation,
            backing_image: owner.backing_image_key(),
            namespace: owner.namespace_key(),
            owner_pid: std::process::id(),
            total_limit: limits.total_physical,
            initial_allocated: physical,
            storage_sealed: record.storage_sealed,
            storage_liabilities,
            storage_profile,
            next_connection: AtomicU64::new(1),
            active_files: AtomicU64::new(0),
            locks: Mutex::new(BTreeMap::new()),
            shm_locks: Mutex::new(std::array::from_fn(|_| SharedMemoryLock {
                exclusive: None,
                shared: Vec::new(),
            })),
            poisoned: AtomicBool::new(false),
            refusal: Mutex::new(None),
            owner_record_lock: Mutex::new(()),
        });
        state.verify()?;
        // WAL-index SHM is volatile. Its exact original held allocation is
        // cleared only after all original files and leases have been acquired.
        let zeroes = [0u8; 32 * 1024];
        for offset in (0..capacities[2]).step_by(zeroes.len()) {
            state.files[2].file.write_all_at(&zeroes, offset)?;
        }
        state.files[2].file.sync_all()?;
        state.persist_owner_record()?;
        state.verify()?;
        owner.verify()?;
        Ok(Self {
            state,
            storage_only: original_directory.is_some(),
        })
    }
    pub fn persistent_owner_generation(&self) -> [u8; 16] {
        self.state.persistent_generation
    }
    /// The connection holders must be fully closed before this durable terminal
    /// checkpoint. No ftruncate, unlink or allocation release is performed.
    pub fn checkpoint_closed(&self) -> io::Result<LinuxMetadataReceipt> {
        self.verify()?;
        if self.state.active_files.load(Ordering::Acquire) != 0 {
            return Err(refuse("metadata SQLite connections are still active"));
        }
        for slot in &self.state.files {
            slot.file.sync_all()?;
        }
        self.state.persist_owner_record()?;
        self.state.directory.sync_all()?;
        self.receipt()
    }
    /// Consume the five exact original leases and all retained descriptors
    /// after SQLite/VFS owners have ended. No pathname is deleted or recreated.
    /// Any failed prerequisite or close remains an error after every resource
    /// exclusively owned here has received its actual close attempt.
    pub fn close_original(self) -> io::Result<LinuxMetadataReceipt> {
        let checkpoint = self.checkpoint_closed();
        let mut failure = checkpoint
            .as_ref()
            .err()
            .map(|error| io::Error::new(error.kind(), error.to_string()));
        if self.state.active_files.load(Ordering::Acquire) != 0 {
            failure.get_or_insert_with(|| refuse("actual metadata SQLite files remain active"));
        }
        let state = match Arc::try_unwrap(self.state) {
            Ok(state) => state,
            Err(_state) => {
                return Err(failure.unwrap_or_else(|| {
                    refuse("actual metadata VFS/context loans still own original descriptors")
                }));
            }
        };
        let State {
            files, directory, ..
        } = state;
        for slot in files {
            let MetadataFile { file, lease, .. } = slot;
            if let Err(error) = file.sync_all() {
                failure.get_or_insert(error);
            }
            if let Err(error) = lease.close() {
                failure.get_or_insert(error);
            }
            // SAFETY: actual original FD remains open after its lease and
            // watcher duplicates have received their consuming closes.
            let actual = unsafe { libc::fcntl(file.as_raw_fd(), 1025) };
            if actual != libc::F_UNLCK {
                failure.get_or_insert_with(|| {
                    if actual < 0 {
                        io::Error::last_os_error()
                    } else {
                        refuse("original metadata kernel lease did not release")
                    }
                });
            }
            if let Err(error) = close_original_descriptor(file) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = directory.sync_all() {
            failure.get_or_insert(error);
        }
        if let Err(error) = close_original_descriptor(directory) {
            failure.get_or_insert(error);
        }
        match (failure, checkpoint) {
            (None, Ok(receipt)) => Ok(receipt),
            (Some(error), _) | (None, Err(error)) => Err(error),
        }
    }
    pub fn database_path(&self) -> &Path {
        Path::new(
            self.state.files[0]
                .path
                .to_str()
                .expect("validated metadata UTF8 path"),
        )
    }
    pub fn validate_native_attempt(&self, attempt: &LinuxNativeAttempt<'_>) -> io::Result<()> {
        attempt.verify()?;
        self.verify()?;
        let owner = attempt.owner();
        if owner.owner_generation() != self.state.owner_generation
            || owner.backing_image_key() != self.state.backing_image
            || owner.namespace_key() != self.state.namespace
        {
            return Err(refuse("metadata belongs to another native namespace owner"));
        }
        attempt.verify()
    }
    pub fn validate_namespace_owner(&self, owner: &LinuxNamespaceCapability) -> io::Result<()> {
        owner.verify()?;
        self.verify()?;
        if owner.owner_generation() != self.state.owner_generation
            || owner.backing_image_key() != self.state.backing_image
            || owner.namespace_key() != self.state.namespace
        {
            return Err(refuse(
                "metadata belongs to another acquired namespace owner",
            ));
        }
        owner.verify()
    }
    pub fn register_vfs(&self) -> io::Result<LinuxMetadataVfs> {
        self.verify()?;
        LinuxMetadataVfs::register(self.state.clone())
    }
    pub fn refusal(&self) -> Option<String> {
        self.state
            .refusal
            .lock()
            .ok()
            .and_then(|value| value.clone())
    }
}

/// Keep this registration alive until its SQLite connection is fully closed.
pub struct LinuxMetadataVfs {
    table: Option<Box<abi::Vfs>>,
    name: Option<CString>,
    state: Arc<State>,
}

// SAFETY: the registered table/name/app are stable heap allocations. All mutable
// callback state is atomic or mutex protected; moving never changes their addresses.
unsafe impl Send for LinuxMetadataVfs {}

impl LinuxMetadataVfs {
    fn register(state: Arc<State>) -> io::Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| refuse("VFS name randomness unavailable"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = CString::new(format!("sync-extend-held-metadata-{suffix}"))
            .map_err(|_| refuse("VFS name invalid"))?;
        let mut table = callbacks::vfs_table();
        table.name = name.as_ptr();
        table.app = Arc::as_ptr(&state).cast_mut().cast();
        // SAFETY: boxed table and all referenced state outlive every registered callback.
        if unsafe { abi::sqlite3_vfs_register(&mut *table, 0) } != abi::OK {
            return Err(refuse("SQLite refused the exact metadata VFS"));
        }
        Ok(Self {
            table: Some(table),
            name: Some(name),
            state,
        })
    }
    pub fn name(&self) -> &str {
        self.name
            .as_ref()
            .expect("retained VFS name")
            .to_str()
            .expect("ASCII VFS name")
    }
    pub fn verify(&self) -> io::Result<()> {
        self.state.verify()
    }
    pub fn receipt(&self) -> io::Result<LinuxMetadataReceipt> {
        self.state.snapshot()
    }
    pub fn close_original(mut self) -> io::Result<()> {
        let mut failure = self.verify().err();
        let active = self.state.active_files.load(Ordering::Acquire);
        if active != 0 {
            failure.get_or_insert_with(|| {
                refuse("actual metadata SQLite contexts remain active at VFS close")
            });
        }
        if let Some(mut table) = self.table.take() {
            // SAFETY: this owns the stable registration; SQLite close was
            // attempted first. Removing its name grants no replacement owner.
            let unregistered = unsafe { abi::sqlite3_vfs_unregister(&mut *table) };
            if unregistered != abi::OK {
                failure.get_or_insert_with(|| refuse("actual metadata VFS unregister failed"));
            }
            if active != 0 || unregistered != abi::OK {
                // Preserve all callback addresses on a violated lifetime.
                // This is an unresolved failure, never an all-closed receipt.
                std::mem::forget(self.state.clone());
                std::mem::forget(table);
                if let Some(name) = self.name.take() {
                    std::mem::forget(name);
                }
            }
        } else {
            failure.get_or_insert_with(|| refuse("original metadata VFS registration absent"));
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for LinuxMetadataVfs {
    fn drop(&mut self) {
        let Some(mut table) = self.table.take() else {
            return;
        };
        // SAFETY: owned boxed table remains alive during removal from SQLite's VFS registry.
        unsafe { abi::sqlite3_vfs_unregister(&mut *table) };
        if self.state.active_files.load(Ordering::Acquire) != 0 {
            // A violated close ordering cannot leave dangling VFS/app/name pointers.
            // Preserve their exact allocations until process exit; grant no new name.
            let retained = self.state.clone();
            std::mem::forget(retained);
            std::mem::forget(table);
            if let Some(name) = self.name.take() {
                std::mem::forget(name);
            }
        }
    }
}

fn close_original_descriptor(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: close this consumed original descriptor once. Never retry EINTR,
    // because the descriptor number may already have been closed and reused.
    if unsafe { libc::close(descriptor) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
