//! Physically reserved SQLite metadata files with an exact descriptor VFS.
//! Metadata budgets are checked before any named file is created. Ownership is
//! acquired through O_TMPFILE/AT_EMPTY_PATH, never adopted from a whitelist.
use super::{key, name, UnixDirectory, UnixFileKey};
use crate::{linux_write_lease::OriginalWriteLease, LinuxNamespaceCapability, LinuxNativeAttempt};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
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
        for slot in &self.files {
            slot.lease.verify()?;
            let metadata = slot.file.metadata()?;
            // SAFETY: fixed uid query with no arguments or pointers.
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.len() > slot.capacity
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
}

impl LinuxMetadataBudget {
    pub fn prepare_new(
        owner: &LinuxNamespaceCapability,
        directory_path: &Path,
        database_component: &str,
        limits: LinuxMetadataLimits,
    ) -> io::Result<Self> {
        owner.verify()?;
        if directory_path.to_str().is_none() {
            return Err(refuse("metadata root requires UTF8 encoding"));
        }
        let directory = UnixDirectory::open(directory_path)?.file;
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
        for capacity in capacities {
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
            // SAFETY: bounded checked length; KEEP_SIZE reserves physical blocks without padding main/WAL.
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
            let allocated = file_blocks(&file)?;
            if allocated < capacity {
                return Err(refuse("metadata preallocation did not reserve all blocks"));
            }
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
        prepared[2].set_len(capacities[2])?;
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
            logical: [0, 0, capacities[2], 0, owner_record::RECORD_BYTES as u64],
        };
        prepared[4].write_all(&owner_record.encode()?)?;
        prepared[4].sync_all()?;
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
            let logical_bytes = file.metadata()?.len();
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
        Ok(Self { state })
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
        owner.verify()?;
        if directory_path.to_str().is_none() {
            return Err(refuse("metadata root requires UTF8 encoding"));
        }
        let directory = UnixDirectory::open(directory_path)?.file;
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
        let record = owner_record::Record::read(&record_file)?;
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
            if key(&file)? != record.files[index]
                || file.metadata()?.len() > capacities[index]
                || file_blocks(&file)? < capacities[index]
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
        Ok(Self { state })
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
