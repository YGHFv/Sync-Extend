//! Closed private SQLite ledger kinds use retained local Unix descriptors.
//! SQLite never opens a pathname. A process-wide file lock serializes writers;
//! WAL/FULL remains responsible for durable commit and crash recovery.
use crate::UnixFileKey;
use rusqlite::{ffi, Connection, OpenFlags};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

mod callbacks;

#[derive(Clone, Copy)]
enum LedgerKind {
    StoragePullAttempt,
    StorageTraffic,
    TransportAttempt,
}

impl LedgerKind {
    fn basename(self) -> &'static str {
        match self {
            Self::StoragePullAttempt => "storage-pull-attempt-budget.sqlite",
            Self::StorageTraffic => "storage-traffic.sqlite",
            Self::TransportAttempt => "transport-attempt-budget.sqlite",
        }
    }

    fn maximum_file_bytes(self) -> u64 {
        match self {
            Self::StoragePullAttempt => 100_000 * 4096 + 1024 * 1024,
            Self::StorageTraffic => 1_000_000 * 4096 + 1024 * 1024,
            Self::TransportAttempt => 100_000 * 4096 + 1024 * 1024,
        }
    }

    fn registration(self) -> &'static str {
        match self {
            Self::StoragePullAttempt => "budget",
            Self::StorageTraffic => "storage-traffic",
            Self::TransportAttempt => "transport-attempt",
        }
    }
}
const MAX_PATH: usize = 4096;
const LOCK_WAIT: Duration = Duration::from_secs(5);
static NEXT_VFS: AtomicU64 = AtomicU64::new(1);

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn identity(file: &File) -> io::Result<UnixFileKey> {
    let metadata = file.metadata()?;
    if metadata.ino() == 0 {
        return Err(refused("Unix ledger inode unavailable"));
    }
    Ok(UnixFileKey {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn descriptor(value: libc::c_int) -> io::Result<File> {
    if value < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful open/openat transfers one owned descriptor.
    Ok(unsafe { File::from_raw_fd(value) })
}

fn component(bytes: &[u8]) -> io::Result<CString> {
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
    {
        return Err(refused("one normalized Unix ledger component required"));
    }
    CString::new(bytes).map_err(|_| refused("NUL in Unix ledger component"))
}

struct HeldDirectory {
    file: File,
    key: UnixFileKey,
    component: Option<CString>,
}

fn hold_directory(path: &Path) -> io::Result<Vec<HeldDirectory>> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_PATH {
        return Err(refused(
            "bounded absolute transport control directory required",
        ));
    }
    // SAFETY: terminated root path and non-following directory flags.
    let root = descriptor(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    })?;
    let mut directories = vec![HeldDirectory {
        key: identity(&root)?,
        file: root,
        component: None,
    }];
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(part) => {
                let name = component(part.as_bytes())?;
                // SAFETY: retained original parent and bounded terminated child.
                let file = descriptor(unsafe {
                    libc::openat(
                        directories.last().expect("parent").file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                })?;
                directories.push(HeldDirectory {
                    key: identity(&file)?,
                    file,
                    component: Some(name),
                });
            }
            _ => return Err(refused("normalized transport directory lineage required")),
        }
    }
    Ok(directories)
}

fn verify_directory_lineage(directories: &[HeldDirectory]) -> io::Result<()> {
    for (index, directory) in directories.iter().enumerate() {
        if !directory.file.metadata()?.is_dir() || identity(&directory.file)? != directory.key {
            return Err(refused("retained transport directory identity changed"));
        }
        let observed = if index == 0 {
            // SAFETY: terminated root path with non-following directory flags.
            descriptor(unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            })?
        } else {
            // SAFETY: retained predecessor and its acquired bounded component.
            descriptor(unsafe {
                libc::openat(
                    directories[index - 1].file.as_raw_fd(),
                    directory.component.as_ref().expect("child").as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            })?
        };
        if identity(&observed)? != directory.key {
            return Err(refused("transport directory slot was replaced"));
        }
    }
    Ok(())
}

fn metadata_owner_present(directory: &File) -> io::Result<bool> {
    let mut output = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained directory, terminated fixed marker, sized output.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c"journal.sqlite.metadata-owner".as_ptr(),
            output.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Read-only actual directory lineage, prepared before the private worker starts.
/// File/CString fields can move to that worker without moving any SQLite VFS.
/// No caller can manufacture this proof or extract a mutable directory handle.
pub struct UnixTransportAttemptRoots {
    data: Vec<HeldDirectory>,
    control: Vec<HeldDirectory>,
    control_path: PathBuf,
    owner: u32,
    process: u32,
}

impl UnixTransportAttemptRoots {
    pub fn verify(&self) -> io::Result<()> {
        // SAFETY: effective-uid query has no arguments or pointers.
        if self.owner != unsafe { libc::geteuid() } || self.process != std::process::id() {
            return Err(refused("transport directory owner/process changed"));
        }
        verify_directory_lineage(&self.data)?;
        verify_directory_lineage(&self.control)?;
        let data = self.data.last().expect("data root");
        let control = self.control.last().expect("control root");
        let metadata = control.file.metadata()?;
        if metadata.uid() != self.owner || metadata.mode() & 0o077 != 0 {
            return Err(refused("transport control root must remain owner-only"));
        }
        for directory in &self.control {
            if metadata_owner_present(&directory.file)? {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "transport control root cannot be owned metadata or its subtree",
                ));
            }
        }
        if metadata_owner_present(&data.file)?
            && self
                .control
                .iter()
                .any(|directory| directory.key == data.key)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport control directory aliases an owned data root",
            ));
        }
        Ok(())
    }
}

struct HeldFile {
    file: File,
    key: UnixFileKey,
}

struct State {
    kind: LedgerKind,
    directories: Vec<HeldDirectory>,
    files: [Option<HeldFile>; 3],
    main_path: PathBuf,
    names: [CString; 3],
    paths: [CString; 3],
    max_bytes: u64,
    read_only: bool,
    owner: u32,
    process: u32,
    poisoned: AtomicBool,
    transport_roots: Option<UnixTransportAttemptRoots>,
}

impl State {
    fn parent(&self) -> &File {
        &self.directories.last().expect("retained parent").file
    }

    fn file(&self, class: usize) -> io::Result<&HeldFile> {
        self.files
            .get(class)
            .and_then(Option::as_ref)
            .ok_or_else(|| refused("Unix ledger auxiliary descriptor unavailable"))
    }

    fn observe(&self, name: &CString) -> io::Result<Option<libc::stat>> {
        let mut output = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: retained directory, terminated single component, sized stat output.
        let result = unsafe {
            libc::fstatat(
                self.parent().as_raw_fd(),
                name.as_ptr(),
                output.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            // SAFETY: successful fstatat initialized the entire output.
            return Ok(Some(unsafe { output.assume_init() }));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn verify(&self) -> io::Result<()> {
        if let Some(roots) = &self.transport_roots {
            roots.verify()?;
        }
        // SAFETY: argument-free effective-uid query.
        let owner = unsafe { libc::geteuid() };
        if self.poisoned.load(Ordering::Acquire)
            || self.process != std::process::id()
            || self.owner != owner
        {
            return Err(refused("Unix ledger owner/registration is no longer live"));
        }
        for (index, directory) in self.directories.iter().enumerate() {
            if !directory.file.metadata()?.is_dir() || identity(&directory.file)? != directory.key {
                return Err(refused("Unix ledger retained ancestor changed"));
            }
            let observed = if index == 0 {
                // SAFETY: terminated root path and non-following directory open.
                descriptor(unsafe {
                    libc::open(
                        c"/".as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                })?
            } else {
                // SAFETY: retained predecessor and originally acquired component.
                descriptor(unsafe {
                    libc::openat(
                        self.directories[index - 1].file.as_raw_fd(),
                        directory.component.as_ref().expect("child name").as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                })?
            };
            if identity(&observed)? != directory.key {
                return Err(refused("Unix ledger ancestor slot was replaced"));
            }
        }
        let parent = self.parent().metadata()?;
        if parent.uid() != self.owner || parent.mode() & 0o077 != 0 {
            return Err(refused(
                "Unix ledger parent must remain private to its owner",
            ));
        }
        for (class, name) in self.names.iter().enumerate() {
            let observed = self.observe(name)?;
            let Some(held) = &self.files[class] else {
                if observed.is_some() {
                    return Err(refused("Unix ledger absent sidecar appeared"));
                }
                continue;
            };
            let metadata = held.file.metadata()?;
            let Some(slot) = observed else {
                return Err(refused("Unix ledger retained file lost its fixed slot"));
            };
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != self.owner
                || metadata.mode() & 0o077 != 0
                || metadata.len() > self.max_bytes
                || identity(&held.file)? != held.key
                || held.key.device != self.directories.last().expect("parent").key.device
                || u128::from(slot.st_dev) != u128::from(held.key.device)
                || u128::from(slot.st_ino) != u128::from(held.key.inode)
                || slot.st_mode & libc::S_IFMT != libc::S_IFREG
                || slot.st_nlink != 1
                || slot.st_uid != self.owner
                || slot.st_mode & 0o077 != 0
            {
                return Err(refused(
                    "Unix ledger inode, private owner, link or size changed",
                ));
            }
            if self.read_only && class != 0 && metadata.len() != 0 {
                return Err(refused(
                    "Unix ledger status requires a closed main without WAL",
                ));
            }
        }
        let shm = component(format!("{}-shm", self.kind.basename()).as_bytes())?;
        if self.observe(&shm)?.is_some() {
            return Err(refused(
                "Unix ledger SHM has no retained descriptor authority",
            ));
        }
        Ok(())
    }
}

/// Keep this owner alive until its single returned SQLite connection is closed.
/// Readers hold shared flock and cannot checkpoint or create/delete sidecars.
pub struct UnixSqliteLedger {
    registration: Box<ffi::sqlite3_vfs>,
    name: CString,
    state: Arc<State>,
    registered: bool,
}

#[derive(Clone, Debug)]
pub struct UnixSqliteLedgerFileObservation {
    pub class: &'static str,
    pub identity: UnixFileKey,
    pub actual_file_bytes: u64,
    pub allocated_bytes: u64,
    pub capacity_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct UnixSqliteLedgerObservation {
    pub parent: UnixFileKey,
    pub active_sqlite_files: usize,
    pub retained_directory_descriptors: usize,
    pub files: Vec<UnixSqliteLedgerFileObservation>,
}

/// Only an actual consuming close can produce this value. Its observations
/// cannot recreate a connection, VFS, descriptor, lock or owner.
pub struct UnixSqliteLedgerClosed {
    original: UnixSqliteLedgerObservation,
}

impl UnixSqliteLedgerClosed {
    pub fn original(&self) -> &UnixSqliteLedgerObservation {
        &self.original
    }
}

/// Field order closes SQLite before unregistering its VFS and releasing flock.
/// Only shared Connection access is exposed, so its owner cannot be extracted.
pub struct UnixSqliteLedgerConnection {
    connection: Connection,
    vfs: UnixSqliteLedger,
}

impl std::ops::Deref for UnixSqliteLedgerConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl UnixSqliteLedgerConnection {
    pub fn verify(&self) -> io::Result<()> {
        self.vfs.verify()
    }

    pub fn progress_handler<F>(&mut self, num_ops: i32, handler: Option<F>) -> rusqlite::Result<()>
    where
        F: FnMut() -> bool + Send + 'static,
    {
        self.connection.progress_handler(num_ops, handler)
    }

    pub fn descriptor_inventory(&self) -> io::Result<UnixSqliteLedgerObservation> {
        self.vfs.descriptor_inventory()
    }

    /// Close SQLite before its actual retained files. A first verification or
    /// SQLite-close error remains an error after all safely closable resources
    /// have been attempted; Drop never supplies a successful close receipt.
    pub fn close(self) -> io::Result<UnixSqliteLedgerClosed> {
        let mut failure = self.verify().err();
        let Self { connection, vfs } = self;
        if let Err((connection, error)) = connection.close() {
            failure.get_or_insert_with(|| io::Error::other(error));
            drop(connection);
        }
        let closed = vfs.close_original_descriptors();
        match (failure, closed) {
            (None, Ok(closed)) => Ok(closed),
            (Some(error), _) | (None, Err(error)) => Err(error),
        }
    }
}

impl UnixSqliteLedger {
    /// Budget issuance keeps its existing fixed basename and separate journal schema.
    pub fn open(path: &Path, max_bytes: u64, fresh: bool, read_only: bool) -> io::Result<Self> {
        Self::open_kind(
            LedgerKind::StoragePullAttempt,
            path,
            max_bytes,
            fresh,
            read_only,
            None,
        )
    }

    /// Ordinary logical traffic has only its own trusted fixed basename.
    /// Callers cannot supply arbitrary SQLite filenames or budget authority.
    pub fn open_storage_traffic(
        path: &Path,
        max_bytes: u64,
        fresh: bool,
        read_only: bool,
    ) -> io::Result<Self> {
        Self::open_kind(
            LedgerKind::StorageTraffic,
            path,
            max_bytes,
            fresh,
            read_only,
            None,
        )
    }

    /// Independently selected roots are retained and checked before worker spawn.
    pub fn hold_transport_attempt_roots(
        data_root: &Path,
        control_root: &Path,
    ) -> io::Result<UnixTransportAttemptRoots> {
        let data = hold_directory(data_root)?;
        let control = hold_directory(control_root)?;
        // SAFETY: argument-free effective owner query.
        let owner = unsafe { libc::geteuid() };
        let final_control = &control.last().expect("control root").file;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: retained actual control directory and sized statfs output.
        if unsafe { libc::fstatfs(final_control.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized the entire output.
        let filesystem = unsafe { filesystem.assume_init() };
        if !matches!(filesystem.f_type as u64, 0xef53 | 0xf2f52010) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport control directory requires local ext4 or F2FS",
            ));
        }
        let roots = UnixTransportAttemptRoots {
            data,
            control,
            control_path: control_root.to_path_buf(),
            owner,
            process: std::process::id(),
        };
        roots.verify()?;
        Ok(roots)
    }

    /// Only the separately proven transport roots can issue this closed basename.
    pub fn open_transport_attempt(
        roots: UnixTransportAttemptRoots,
        max_bytes: u64,
        fresh: bool,
        read_only: bool,
    ) -> io::Result<Self> {
        roots.verify()?;
        let path = roots
            .control_path
            .join(LedgerKind::TransportAttempt.basename());
        Self::open_kind(
            LedgerKind::TransportAttempt,
            &path,
            max_bytes,
            fresh,
            read_only,
            Some(roots),
        )
    }

    fn open_kind(
        kind: LedgerKind,
        path: &Path,
        max_bytes: u64,
        fresh: bool,
        read_only: bool,
        transport_roots: Option<UnixTransportAttemptRoots>,
    ) -> io::Result<Self> {
        let file_name = kind.basename();
        if matches!(kind, LedgerKind::TransportAttempt) != transport_roots.is_some() {
            return Err(refused(
                "transport ledger requires its independently retained roots",
            ));
        }
        if let Some(roots) = &transport_roots {
            roots.verify()?;
        }
        let raw = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || raw.len() > MAX_PATH
            || max_bytes == 0
            || max_bytes > kind.maximum_file_bytes()
            || fresh && read_only
            || path.file_name().map(OsStrExt::as_bytes) != Some(file_name.as_bytes())
        {
            return Err(refused(
                "fixed absolute private Unix ledger path and bound required",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| refused("Unix ledger parent absent"))?;
        // SAFETY: terminated root and flags that never follow a symlink.
        let root = descriptor(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        })?;
        let mut directories = vec![HeldDirectory {
            key: identity(&root)?,
            file: root,
            component: None,
        }];
        for part in parent.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(part) => {
                    let name = component(part.as_bytes())?;
                    // SAFETY: retained real parent and terminated bounded child name.
                    let file = descriptor(unsafe {
                        libc::openat(
                            directories.last().expect("parent").file.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        )
                    })?;
                    directories.push(HeldDirectory {
                        key: identity(&file)?,
                        file,
                        component: Some(name),
                    });
                }
                _ => return Err(refused("unsafe Unix ledger ancestor component")),
            }
        }
        // SAFETY: effective-uid query has no pointers or arguments.
        let owner = unsafe { libc::geteuid() };
        let parent_file = &directories.last().expect("parent").file;
        let metadata = parent_file.metadata()?;
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(refused("Unix ledger data parent must be owner-only"));
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: retained directory and properly sized statfs output.
        if unsafe { libc::fstatfs(parent_file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized the output.
        let filesystem = unsafe { filesystem.assume_init() };
        if !matches!(filesystem.f_type as u64, 0xef53 | 0xf2f52010) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix private ledger requires local ext4 or F2FS",
            ));
        }
        let names = [
            component(file_name.as_bytes())?,
            component(format!("{file_name}-wal").as_bytes())?,
            component(format!("{file_name}-journal").as_bytes())?,
        ];
        let path_name = |suffix: &[u8]| {
            let mut bytes = raw.to_vec();
            bytes.extend_from_slice(suffix);
            CString::new(bytes).map_err(|_| refused("NUL in Unix ledger path"))
        };
        let paths = [
            path_name(b"")?,
            path_name(b"-wal")?,
            path_name(b"-journal")?,
        ];
        let mut state = State {
            kind,
            directories,
            files: [None, None, None],
            main_path: path.to_path_buf(),
            names,
            paths,
            max_bytes,
            read_only,
            owner,
            process: std::process::id(),
            poisoned: AtomicBool::new(false),
            transport_roots,
        };
        let shm = component(format!("{file_name}-shm").as_bytes())?;
        if state.observe(&shm)?.is_some() {
            return Err(refused("Unix ledger SHM is not supported"));
        }
        if fresh
            && state
                .names
                .iter()
                .any(|name| !matches!(state.observe(name), Ok(None)))
        {
            return Err(refused("fresh Unix ledger or sidecar already exists"));
        }
        // Reject a preexisting foreign auxiliary object before creating any missing one.
        for name in &state.names {
            if let Some(slot) = state.observe(name)? {
                if slot.st_mode & libc::S_IFMT != libc::S_IFREG
                    || u128::from(slot.st_dev)
                        != u128::from(state.directories.last().expect("parent").key.device)
                    || slot.st_uid != owner
                    || slot.st_nlink != 1
                    || slot.st_mode & 0o077 != 0
                    || slot.st_size < 0
                    || slot.st_size as u64 > max_bytes
                {
                    return Err(refused("Unix ledger pre-open file contract rejected"));
                }
            }
        }
        for class in 0..3 {
            let present = state.observe(&state.names[class])?;
            if present.is_none() && (read_only || class == 0 && !fresh) {
                if class == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "initialized private Unix ledger missing",
                    ));
                }
                continue;
            }
            if let Some(slot) = &present {
                if slot.st_mode & libc::S_IFMT != libc::S_IFREG
                    || u128::from(slot.st_dev)
                        != u128::from(state.directories.last().expect("parent").key.device)
                    || slot.st_uid != owner
                    || slot.st_nlink != 1
                    || slot.st_mode & 0o077 != 0
                    || slot.st_size < 0
                    || slot.st_size as u64 > max_bytes
                {
                    return Err(refused("Unix ledger pre-open file contract rejected"));
                }
            }
            let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOATIME;
            flags |= if read_only {
                libc::O_RDONLY
            } else {
                libc::O_RDWR
            };
            if present.is_none() {
                flags |= libc::O_CREAT | libc::O_EXCL;
            }
            // SAFETY: retained directory and exact component; owner-only mode for O_CREAT.
            let file = descriptor(unsafe {
                libc::openat(
                    state.parent().as_raw_fd(),
                    state.names[class].as_ptr(),
                    flags,
                    0o600 as libc::mode_t,
                )
            })?;
            let key = identity(&file)?;
            if key.device != state.directories.last().expect("parent").key.device {
                return Err(refused(
                    "Unix ledger file crossed its retained parent filesystem",
                ));
            }
            if let Some(slot) = present {
                if u128::from(slot.st_dev) != u128::from(key.device)
                    || u128::from(slot.st_ino) != u128::from(key.inode)
                {
                    return Err(refused(
                        "Unix ledger file changed during descriptor acquisition",
                    ));
                }
            }
            if class == 0 {
                let operation = if read_only {
                    libc::LOCK_SH
                } else {
                    libc::LOCK_EX
                };
                let started = Instant::now();
                loop {
                    // SAFETY: retained main descriptor and a nonblocking advisory lock.
                    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
                        break;
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.kind() != io::ErrorKind::WouldBlock || started.elapsed() >= LOCK_WAIT {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            state.files[class] = Some(HeldFile { file, key });
        }
        state.verify()?;
        if !read_only {
            state.file(0)?.file.sync_all()?;
            state.parent().sync_all()?;
        }
        let state = Arc::new(state);
        let sequence = NEXT_VFS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    None
                } else {
                    current.checked_add(1)
                }
            })
            .map_err(|_| refused("Unix ledger VFS generation exhausted"))?;
        let name = CString::new(format!(
            "sync-{}-{}-{sequence}",
            kind.registration(),
            std::process::id()
        ))
        .map_err(|_| refused("Unix ledger VFS name"))?;
        let mut registration = callbacks::registration();
        registration.zName = name.as_ptr();
        registration.pAppData = Arc::as_ptr(&state).cast_mut().cast();
        // SAFETY: boxed table/name/state stay alive until unregister after connection close.
        if unsafe { ffi::sqlite3_vfs_register(&mut *registration, 0) } != ffi::SQLITE_OK {
            return Err(refused("Unix ledger VFS registration refused"));
        }
        Ok(Self {
            registration,
            name,
            state,
            registered: true,
        })
    }

    pub fn main_file(&self) -> &File {
        &self.state.files[0].as_ref().expect("retained main").file
    }

    pub fn verify(&self) -> io::Result<()> {
        self.state.verify()
    }

    fn descriptor_inventory(&self) -> io::Result<UnixSqliteLedgerObservation> {
        self.verify()?;
        let mut files = Vec::with_capacity(3);
        for (index, class) in ["main", "wal", "rollback_journal"].into_iter().enumerate() {
            if let Some(held) = &self.state.files[index] {
                let metadata = held.file.metadata()?;
                files.push(UnixSqliteLedgerFileObservation {
                    class,
                    identity: held.key,
                    actual_file_bytes: metadata.len(),
                    allocated_bytes: metadata
                        .blocks()
                        .checked_mul(512)
                        .ok_or_else(|| refused("Unix ledger allocation count overflow"))?,
                    capacity_bytes: self.state.max_bytes,
                });
            }
        }
        let retained_directory_descriptors = self.state.directories.len()
            + self
                .state
                .transport_roots
                .as_ref()
                .map_or(0, |roots| roots.data.len() + roots.control.len());
        self.verify()?;
        Ok(UnixSqliteLedgerObservation {
            parent: self.state.directories.last().expect("parent").key,
            // Every remaining strong reference is one original xOpen context.
            // IO callbacks are synchronous and have ended before this call.
            active_sqlite_files: Arc::strong_count(&self.state) - 1,
            retained_directory_descriptors,
            files,
        })
    }

    fn close_original_descriptors(mut self) -> io::Result<UnixSqliteLedgerClosed> {
        let original = self.descriptor_inventory();
        let mut failure = original
            .as_ref()
            .err()
            .map(|error| io::Error::new(error.kind(), error.to_string()));
        if Arc::strong_count(&self.state) != 1 {
            return Err(failure.unwrap_or_else(|| {
                refused("actual Unix ledger SQLite contexts remain active at descriptor close")
            }));
        }
        // SAFETY: actual SQLite close completed and this owns the registration.
        if unsafe { ffi::sqlite3_vfs_unregister(&mut *self.registration) } != ffi::SQLITE_OK {
            return Err(
                failure.unwrap_or_else(|| refused("actual Unix ledger VFS unregister failed"))
            );
        }
        self.registered = false;
        let state = Arc::get_mut(&mut self.state).expect("verified unique ledger state");
        if let Some(main) = &state.files[0] {
            // The duplicate main in the traffic ledger shares this description,
            // so actual unlock must precede every descriptor close.
            if unsafe { libc::flock(main.file.as_raw_fd(), libc::LOCK_UN) } != 0 {
                failure.get_or_insert_with(io::Error::last_os_error);
            }
        }
        for held in &mut state.files {
            if let Some(held) = held.take() {
                if !state.read_only {
                    if let Err(error) = held.file.sync_all() {
                        failure.get_or_insert(error);
                    }
                }
                if let Err(error) = close_descriptor(held.file) {
                    failure.get_or_insert(error);
                }
            }
        }
        for directory in state.directories.drain(..).rev() {
            if let Err(error) = close_descriptor(directory.file) {
                failure.get_or_insert(error);
            }
        }
        if let Some(mut roots) = state.transport_roots.take() {
            for directory in roots
                .control
                .drain(..)
                .rev()
                .chain(roots.data.drain(..).rev())
            {
                if let Err(error) = close_descriptor(directory.file) {
                    failure.get_or_insert(error);
                }
            }
        }
        match (failure, original) {
            (None, Ok(original)) => Ok(UnixSqliteLedgerClosed { original }),
            (Some(error), _) | (None, Err(error)) => Err(error),
        }
    }

    pub fn open_connection(self) -> rusqlite::Result<UnixSqliteLedgerConnection> {
        let flags = OpenFlags::SQLITE_OPEN_NO_MUTEX
            | if self.state.read_only {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI
            } else {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            };
        let connection = if self.state.read_only {
            let mut uri = String::from("file:");
            for byte in self.state.main_path.as_os_str().as_bytes() {
                use std::fmt::Write as _;
                if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
                    uri.push(char::from(*byte));
                } else {
                    write!(&mut uri, "%{byte:02X}").expect("String write");
                }
            }
            uri.push_str("?immutable=1");
            Connection::open_with_flags_and_vfs(uri, flags, self.name.to_str().expect("ASCII VFS"))?
        } else {
            let connection = Connection::open_with_flags_and_vfs(
                &self.state.main_path,
                flags,
                self.name.to_str().expect("ASCII VFS"),
            )?;
            // WAL's heap index is permitted only under our retained exclusive main flock.
            connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
            connection
        };
        connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        Ok(UnixSqliteLedgerConnection {
            connection,
            vfs: self,
        })
    }
}

impl Drop for UnixSqliteLedger {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        // SAFETY: the caller drops SQLite first; live IO contexts independently retain State.
        unsafe { ffi::sqlite3_vfs_unregister(&mut *self.registration) };
        // Descriptors and their flock remain until State and every IO context are dropped.
    }
}

fn close_descriptor(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: consume exactly this original descriptor once. Never retry
    // close(EINTR), because Linux may already have reused the descriptor number.
    if unsafe { libc::close(descriptor) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
