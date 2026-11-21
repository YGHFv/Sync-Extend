//! Existing closed-main Journal inputs for an inert, bounded memory reader.
//! No SQLite pathname opener, file creation, recovery or native write is provided.
use std::{
    ffi::{CString, OsStr},
    fs::{File, Metadata},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::FileExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CONTROL_INPUT_BYTES: u64 = 65_536;
const FILE_NAMES: [&str; 4] = [
    "writer.lock",
    "journal.sqlite",
    "journal.sqlite-wal",
    "journal.sqlite-journal",
];
const ABSENT_NAMES: [&str; 2] = ["journal.sqlite-shm", "journal.sqlite.metadata-owner"];

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn component(value: &OsStr) -> io::Result<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes.contains(&b'/')
        || matches!(bytes, b"." | b"..")
    {
        return Err(refused(
            "readonly Journal requires original path components",
        ));
    }
    CString::new(bytes).map_err(|_| refused("NUL in readonly Journal component"))
}

fn descriptor(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful open/openat returned this new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Observation {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    links: u64,
    length: u64,
    accessed: (i64, i64),
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Observation {
    fn metadata(value: &Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            owner: value.uid(),
            group: value.gid(),
            mode: value.mode(),
            links: value.nlink(),
            length: value.len(),
            accessed: (value.atime(), value.atime_nsec()),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }

    fn stat(value: &libc::stat) -> io::Result<Self> {
        Ok(Self {
            device: value.st_dev,
            inode: value.st_ino,
            owner: value.st_uid,
            group: value.st_gid,
            mode: value.st_mode,
            links: value.st_nlink,
            length: u64::try_from(value.st_size)
                .map_err(|_| refused("negative readonly Journal file length"))?,
            accessed: (value.st_atime, value.st_atime_nsec),
            modified: (value.st_mtime, value.st_mtime_nsec),
            changed: (value.st_ctime, value.st_ctime_nsec),
        })
    }
}

struct HeldDirectory {
    file: File,
    name: Option<CString>,
    before: Observation,
}

struct HeldFile {
    file: File,
    name: CString,
    before: Observation,
}

/// A real existing writer exclusion and retained original directory/file set.
/// This object supplies only read bytes and verification; it cannot open SQLite,
/// acquire native admission, change a timestamp or create a missing sidecar.
pub struct ReadOnlyJournalFiles {
    directories: Vec<HeldDirectory>,
    files: Vec<Option<HeldFile>>,
    absent: Vec<CString>,
    process: u32,
}

fn observe(parent: &File, name: &CString) -> io::Result<Option<Observation>> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained directory, terminated component and sized stat output.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    // SAFETY: successful fstatat initialized the whole output.
    Ok(Some(Observation::stat(unsafe { &value.assume_init() })?))
}

fn hold_directories(parent: &Path) -> io::Result<Vec<HeldDirectory>> {
    if !parent.is_absolute() || parent.as_os_str().as_bytes().len() > 4096 {
        return Err(refused("readonly input requires a bounded absolute parent"));
    }
    // O_PATH retains the original chain without reading directory entries or
    // following an intermediate alias. No canonicalize pathname is used.
    // SAFETY: terminated root and flags that cannot create or follow a link.
    let root = descriptor(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    })?;
    let mut directories = vec![HeldDirectory {
        before: Observation::metadata(&root.metadata()?),
        file: root,
        name: None,
    }];
    for part in parent.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(part) => {
                let name = component(part)?;
                // SAFETY: retained parent and a bounded terminated name.
                let file = descriptor(unsafe {
                    libc::openat(
                        directories
                            .last()
                            .expect("retained parent")
                            .file
                            .as_raw_fd(),
                        name.as_ptr(),
                        libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                })?;
                directories.push(HeldDirectory {
                    before: Observation::metadata(&file.metadata()?),
                    file,
                    name: Some(name),
                });
            }
            _ => return Err(refused("readonly input ancestor traversal rejected")),
        }
    }
    Ok(directories)
}

fn private_local_parent(directories: &[HeldDirectory]) -> io::Result<(u32, Observation)> {
    // SAFETY: effective uid query has no pointers or side effects.
    let owner = unsafe { libc::geteuid() };
    let parent = &directories.last().expect("retained parent").file;
    let before = Observation::metadata(&parent.metadata()?);
    if before.owner != owner || before.mode & 0o077 != 0 {
        return Err(refused("readonly input parent must be owner-only"));
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: retained directory and sized statfs output.
    if unsafe { libc::fstatfs(parent.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the output.
    let filesystem = unsafe { filesystem.assume_init() };
    if !matches!(filesystem.f_type as u64, 0xef53 | 0xf2f52010) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "readonly input requires local ext4 or F2FS",
        ));
    }
    Ok((owner, before))
}

fn verify_directories(directories: &[HeldDirectory]) -> io::Result<()> {
    for (index, directory) in directories.iter().enumerate() {
        if Observation::metadata(&directory.file.metadata()?) != directory.before {
            return Err(refused("readonly input retained ancestor metadata changed"));
        }
        if index != 0
            && observe(
                &directories[index - 1].file,
                directory.name.as_ref().expect("ancestor component"),
            )? != Some(directory.before)
        {
            return Err(refused("readonly input ancestor named slot changed"));
        }
    }
    Ok(())
}

fn read_original(file: &HeldFile) -> io::Result<Vec<u8>> {
    let length = usize::try_from(file.before.length)
        .map_err(|_| refused("readonly input does not fit memory bound"))?;
    let mut bytes = vec![0; length];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = file.file.read_at(&mut bytes[offset..], offset as u64)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "readonly original file shortened during copy",
            ));
        }
        offset += read;
    }
    Ok(bytes)
}

/// An existing bounded control input retained without aliases or access-time
/// changes. Its private fields cannot be reconstructed from serialized bytes.
pub struct ReadOnlyControlInput {
    directories: Vec<HeldDirectory>,
    file: HeldFile,
    process: u32,
    bytes: Vec<u8>,
}

impl ReadOnlyControlInput {
    pub fn open(path: &Path, source: &ReadOnlyJournalFiles) -> io::Result<Self> {
        if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
            return Err(refused(
                "readonly control input requires a bounded absolute path",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| refused("readonly control input parent required"))?;
        let name = component(
            path.file_name()
                .ok_or_else(|| refused("readonly control input original filename required"))?,
        )?;
        let directories = hold_directories(parent)?;
        let (owner, parent_before) = private_local_parent(&directories)?;
        let parent = &directories.last().expect("retained parent").file;
        let before = observe(parent, &name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "readonly control input must already exist",
            )
        })?;
        if before.mode & libc::S_IFMT != libc::S_IFREG
            || before.device != parent_before.device
            || before.owner != owner
            || before.links != 1
            || before.mode & 0o022 != 0
            || before.length > MAX_CONTROL_INPUT_BYTES
        {
            return Err(refused(
                "readonly control input requires an original owner regular file within 64 KiB",
            ));
        }
        // Exclude every original fixed source slot by physical identity before
        // a control descriptor can be opened or any bytes can reach JSON.
        source.reject_control_identity(&before)?;
        // SAFETY: retained private parent and exact original component. No
        // CREATE/write flags; O_NOATIME is mandatory with no ordinary fallback.
        let file = descriptor(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOATIME,
            )
        })?;
        let mut held = Self {
            directories,
            file: HeldFile { file, name, before },
            process: std::process::id(),
            bytes: Vec::new(),
        };
        held.verify_metadata()?;
        source.reject_control_identity(&held.file.before)?;
        held.bytes = read_original(&held.file)?;
        held.verify_metadata()?;
        source.verify()?;
        Ok(held)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn verify_metadata(&self) -> io::Result<()> {
        if std::process::id() != self.process {
            return Err(refused(
                "readonly control input descriptor owner process changed",
            ));
        }
        verify_directories(&self.directories)?;
        let parent = &self.directories.last().expect("retained parent").file;
        if Observation::metadata(&self.file.file.metadata()?) != self.file.before
            || observe(parent, &self.file.name)? != Some(self.file.before)
        {
            return Err(refused(
                "readonly control input original file or metadata changed",
            ));
        }
        Ok(())
    }

    /// Read the same retained descriptor again and compare its original raw
    /// bytes between complete process, name-chain and metadata checks.
    pub fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.verify_metadata()?;
        let bytes = read_original(&self.file)?;
        self.verify_metadata()?;
        if bytes != self.bytes {
            return Err(refused("readonly control input original bytes changed"));
        }
        Ok(bytes)
    }

    pub fn verify(&self) -> io::Result<()> {
        self.read_verified().map(|_| ())
    }
}

impl ReadOnlyJournalFiles {
    fn reject_control_identity(&self, input: &Observation) -> io::Result<()> {
        self.verify()?;
        if self.files.iter().flatten().any(|source| {
            source.before.device == input.device && source.before.inode == input.inode
        }) {
            return Err(refused(
                "readonly control input overlaps an original Journal source file",
            ));
        }
        Ok(())
    }

    /// Acquire only the fixed files of an already initialized, private, closed
    /// ordinary Journal. Unsupported physical metadata owners require their
    /// own live capability and are refused, even if main bytes appear readable.
    pub fn open(path: &Path, max_image_bytes: u64) -> io::Result<Self> {
        if !(4096..=MAX_IMAGE_BYTES).contains(&max_image_bytes) {
            return Err(refused("explicit readonly Journal image bound required"));
        }
        let files = Self::preflight(path)?;
        files.check_main_bound(max_image_bytes)?;
        Ok(files)
    }

    /// Retain the fixed original files and writer exclusion without reading
    /// main bytes. The typed caller bound is applied before the later copy.
    pub fn preflight(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > 4096
            || path.file_name() != Some(OsStr::new("journal.sqlite"))
        {
            return Err(refused(
                "fixed absolute readonly Journal path and bound required",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| refused("readonly Journal data directory required"))?;
        let directories = hold_directories(parent)?;
        let (owner, parent_before) = private_local_parent(&directories)?;
        let parent_file = &directories.last().expect("retained parent").file;
        let absent = ABSENT_NAMES
            .into_iter()
            .map(|name| component(OsStr::new(name)))
            .collect::<io::Result<Vec<_>>>()?;
        for name in &absent {
            if observe(parent_file, name)?.is_some() {
                return Err(refused(
                    "readonly Journal SHM or metadata-owner requires unavailable capability",
                ));
            }
        }
        let names = FILE_NAMES
            .into_iter()
            .map(|name| component(OsStr::new(name)))
            .collect::<io::Result<Vec<_>>>()?;
        let mut initial = Vec::with_capacity(names.len());
        // All class/length checks precede any file read or lock acquisition.
        for (class, name) in names.iter().enumerate() {
            let before = observe(parent_file, name)?;
            if let Some(before) = before {
                if before.mode & libc::S_IFMT != libc::S_IFREG
                    || before.device != parent_before.device
                    || before.owner != owner
                    || before.links != 1
                    // The retained owner-only parent also protects legacy
                    // ordinary files created with 0644. Reject foreign write
                    // permission and aliases rather than chmod-ing old inputs.
                    || before.mode & 0o022 != 0
                    || (class == 1 && !(512..=MAX_IMAGE_BYTES).contains(&before.length))
                    || (class != 1 && before.length != 0)
                {
                    return Err(refused(
                        "readonly Journal original file, private owner or closed-main bound rejected",
                    ));
                }
            } else if class < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "readonly Journal requires existing writer.lock and main database",
                ));
            }
            initial.push(before);
        }
        let mut files = Vec::with_capacity(names.len());
        for (class, (name, before)) in names.into_iter().zip(initial).enumerate() {
            let Some(before) = before else {
                files.push(None);
                continue;
            };
            // SAFETY: live parent and exact component; no CREATE or writable flags.
            // O_NOATIME is mandatory, with no fallback to an atime-changing read.
            let file = descriptor(unsafe {
                libc::openat(
                    parent_file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_NOATIME,
                )
            })?;
            if Observation::metadata(&file.metadata()?) != before
                || observe(parent_file, &name)? != Some(before)
            {
                return Err(refused("readonly Journal file changed during acquisition"));
            }
            if class == 0 {
                // This is the ordinary LocalSpace flock on its original existing
                // sentinel, not a second lock file or a serialized ownership flag.
                // SAFETY: retained original regular file and nonblocking flock flags.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            files.push(Some(HeldFile { file, name, before }));
        }
        let held = Self {
            directories,
            files,
            absent,
            process: std::process::id(),
        };
        held.verify()?;
        Ok(held)
    }

    /// Verify original identity, every observed metadata field and every fixed
    /// present/absent named slot. No directory enumeration or timestamp repair.
    pub fn verify(&self) -> io::Result<()> {
        if std::process::id() != self.process {
            return Err(refused("readonly Journal descriptor owner process changed"));
        }
        verify_directories(&self.directories)?;
        let parent = &self.directories.last().expect("retained parent").file;
        for (class, file) in self.files.iter().enumerate() {
            if let Some(file) = file {
                if Observation::metadata(&file.file.metadata()?) != file.before
                    || observe(parent, &file.name)? != Some(file.before)
                {
                    return Err(refused(
                        "readonly Journal retained file or metadata changed",
                    ));
                }
            } else if observe(parent, &component(OsStr::new(FILE_NAMES[class]))?)?.is_some() {
                return Err(refused("readonly Journal missing sidecar appeared"));
            }
        }
        for name in &self.absent {
            if observe(parent, name)?.is_some() {
                return Err(refused("readonly Journal unsupported sidecar appeared"));
            }
        }
        Ok(())
    }

    pub fn check_main_bound(&self, max_image_bytes: u64) -> io::Result<()> {
        self.verify()?;
        if !(4096..=MAX_IMAGE_BYTES).contains(&max_image_bytes)
            || self.files[1].as_ref().expect("retained main").before.length > max_image_bytes
        {
            return Err(refused(
                "readonly Journal physical main exceeds explicit byte bound",
            ));
        }
        Ok(())
    }

    /// Copy exactly the already bounded main bytes through the same retained
    /// O_NOATIME descriptor. No pathname reopen or source header conversion.
    pub fn read_main(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        let bytes = read_original(self.files[1].as_ref().expect("retained main"))?;
        self.verify()?;
        Ok(bytes)
    }
}
