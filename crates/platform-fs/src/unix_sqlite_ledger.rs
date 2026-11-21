//! Private fixed-budget SQLite access through retained local Unix descriptors.
//! SQLite never opens a pathname. A process-wide file lock serializes writers;
//! WAL/FULL remains responsible for durable commit and crash recovery.
use crate::UnixFileKey;
use rusqlite::{ffi, Connection, OpenFlags};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
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

const FILE_NAME: &str = "storage-pull-attempt-budget.sqlite";
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

struct HeldFile {
    file: File,
    key: UnixFileKey,
}

struct State {
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
        let shm = component(format!("{FILE_NAME}-shm").as_bytes())?;
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
}

impl UnixSqliteLedger {
    pub fn open(path: &Path, max_bytes: u64, fresh: bool, read_only: bool) -> io::Result<Self> {
        let raw = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || raw.len() > MAX_PATH
            || max_bytes == 0
            || max_bytes > i64::MAX as u64
            || fresh && read_only
            || path.file_name().map(OsStrExt::as_bytes) != Some(FILE_NAME.as_bytes())
        {
            return Err(refused("fixed absolute Unix budget ledger path required"));
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
                "Unix budget ledger requires local ext4 or F2FS",
            ));
        }
        let names = [
            component(FILE_NAME.as_bytes())?,
            component(format!("{FILE_NAME}-wal").as_bytes())?,
            component(format!("{FILE_NAME}-journal").as_bytes())?,
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
        };
        let shm = component(format!("{FILE_NAME}-shm").as_bytes())?;
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
                        "initialized Unix budget ledger missing",
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
        let name = CString::new(format!("sync-budget-{}-{sequence}", std::process::id()))
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
        })
    }

    pub fn main_file(&self) -> &File {
        &self.state.files[0].as_ref().expect("retained main").file
    }

    pub fn verify(&self) -> io::Result<()> {
        self.state.verify()
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
        // SAFETY: the caller drops SQLite first; live IO contexts independently retain State.
        unsafe { ffi::sqlite3_vfs_unregister(&mut *self.registration) };
        // Descriptors and their flock remain until State and every IO context are dropped.
    }
}
