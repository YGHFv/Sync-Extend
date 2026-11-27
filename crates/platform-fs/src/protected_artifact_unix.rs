//! Same-UID deployment artifacts through retained, nonfollowing original FDs.
//!
//! These observations grant no Journal, worktree, mutation or restart authority.
//! A failed CREATE/write keeps its real created file. No pathname deletion is
//! performed by this module or by a destructor.
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Write},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    os::unix::{ffi::OsStrExt, fs::FileExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

mod directory_entries;
mod mount_identity;
mod resource_close;
pub use resource_close::{
    ClosedUnixOriginalResources, UnixOriginalCloseAttempt, UnixOriginalResourceCloseFailure,
};

const MAX_COMPONENTS: usize = 128;
const MAX_PATH_BYTES: usize = 32_768;
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024 * 1024;

fn refuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UnixProtectedArtifactKey {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileObservation {
    key: UnixProtectedArtifactKey,
    mode: u32,
    links: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileObservation {
    fn from_stat(value: &libc::stat) -> io::Result<Self> {
        let bytes = u64::try_from(value.st_size)
            .map_err(|_| refuse("negative deployment artifact length"))?;
        Ok(Self {
            key: UnixProtectedArtifactKey {
                device: value.st_dev as u64,
                inode: value.st_ino as u64,
                uid: value.st_uid,
            },
            mode: value.st_mode,
            links: value.st_nlink as u64,
            bytes,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        })
    }

    fn same_object(self, other: Self) -> bool {
        self.key == other.key && self.mode == other.mode && self.links == other.links
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer arguments and returns the current kernel UID.
    unsafe { libc::geteuid() }
}

fn observe_fd(fd: RawFd) -> io::Result<FileObservation> {
    let mut value = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is borrowed from a live owned File. fstat initializes the
    // supplied stat object before a successful return.
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the preceding successful fstat initialized the entire stat value.
    FileObservation::from_stat(&unsafe { value.assume_init() })
}

fn observe_slot(parent: RawFd, name: &CString) -> io::Result<FileObservation> {
    let mut value = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is a retained live directory FD; name is NUL terminated.
    // AT_SYMLINK_NOFOLLOW observes the actual slot rather than a linked target.
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fstatat initialized the stat object.
    FileObservation::from_stat(&unsafe { value.assume_init() })
}

fn open_root() -> io::Result<File> {
    let name = CString::new("/").map_err(|_| refuse("root encoding"))?;
    // SAFETY: name is valid and NUL terminated. A successful open returns one
    // newly owned FD, transferred immediately to File.
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this successful open returned a fresh FD owned by this function.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_child(parent: RawFd, name: &CString, flags: i32) -> io::Result<File> {
    // SAFETY: parent remains live and name is valid. O_NOFOLLOW is mandatory;
    // a successful openat yields exactly one fresh FD owned by the result.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by the successful openat and is not shared.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn component(value: &OsStr) -> io::Result<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|byte| matches!(byte, b'/' | b'\\'))
    {
        return Err(refuse("bounded normal deployment path component required"));
    }
    CString::new(bytes).map_err(|_| refuse("deployment path contains NUL"))
}

fn normal_components(path: &Path) -> io::Result<Vec<CString>> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path == Path::new("/")
    {
        return Err(refuse("bounded absolute deployment path required"));
    }
    let mut result = Vec::new();
    for part in path.components() {
        match part {
            Component::RootDir if result.is_empty() => {}
            Component::Normal(value) => result.push(component(value)?),
            _ => return Err(refuse("deployment path is not component normalized")),
        }
    }
    if result.is_empty() || result.len() > MAX_COMPONENTS {
        return Err(refuse("deployment path component count"));
    }
    Ok(result)
}

fn verify_directory(value: FileObservation, private: bool) -> io::Result<()> {
    if value.mode & libc::S_IFMT != libc::S_IFDIR || value.links == 0 {
        return Err(refuse("original deployment directory required"));
    }
    let uid = current_uid();
    if private {
        if value.key.uid != uid || value.mode & 0o077 != 0 || value.mode & 0o700 != 0o700 {
            return Err(refuse("same-UID private deployment parent required"));
        }
    } else if value.key.uid != uid && value.key.uid != 0
        || value.mode & 0o022 != 0 && !(value.key.uid == 0 && value.mode & libc::S_ISVTX != 0)
    {
        return Err(refuse("deployment ancestor owner/write scope"));
    }
    Ok(())
}

fn verify_file(value: FileObservation, private: bool, maximum: usize) -> io::Result<()> {
    if maximum == 0
        || maximum > MAX_ARTIFACT_BYTES
        || value.mode & libc::S_IFMT != libc::S_IFREG
        || value.key.uid != current_uid()
        || value.links != 1
        || value.bytes > maximum as u64
        || value.mode & 0o022 != 0
        || private && value.mode & 0o077 != 0
    {
        return Err(refuse(
            "bounded same-UID original single-link artifact required",
        ));
    }
    Ok(())
}

struct DirectoryAnchor {
    file: File,
    key: UnixProtectedArtifactKey,
    mount_id: u64,
    component: Option<CString>,
}

struct AnchoredParent {
    path: PathBuf,
    directories: Vec<DirectoryAnchor>,
}

impl AnchoredParent {
    fn open(path: &Path) -> io::Result<Self> {
        let components = normal_components(path)?;
        let component_count = components.len();
        let mut pending = Some(open_root()?);
        let mut directories = Vec::new();
        let opened = (|| -> io::Result<()> {
            let root = pending.as_ref().expect("original root open");
            let observed = observe_fd(root.as_raw_fd())?;
            verify_directory(observed, false)?;
            directories.push(DirectoryAnchor {
                mount_id: mount_identity::mount_id(root.as_raw_fd())?,
                file: pending.take().expect("verified original root"),
                key: observed.key,
                component: None,
            });
            for (index, name) in components.into_iter().enumerate() {
                let parent = directories.last().ok_or_else(|| refuse("original root directory absent"))?;
                pending = Some(open_child(parent.file.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?);
                let file = pending.as_ref().expect("original ancestor open");
                let observed = observe_fd(file.as_raw_fd())?;
                let slot = observe_slot(parent.file.as_raw_fd(), &name)?;
                if !observed.same_object(slot) {
                    return Err(refuse("original deployment directory slot changed"));
                }
                let mount_id = mount_identity::mount_id(file.as_raw_fd())?;
                if mount_id != mount_identity::slot_mount_id(parent.file.as_raw_fd(), &name)? {
                    return Err(refuse("original deployment directory mount changed"));
                }
                verify_directory(observed, index + 1 == component_count)?;
                directories.push(DirectoryAnchor { mount_id, file: pending.take().expect("verified original ancestor"),
                    key: observed.key, component: Some(name) });
            }
            Ok(())
        })();
        if let Err(error) = opened {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            if let Some(file) = pending { close.close_file(file); }
            for directory in directories.into_iter().rev() { close.close_file(directory.file); }
            return Err(close.finish().err().expect("ancestor open first error retained").retain_and_report());
        }
        let result = Self {
            path: path.to_path_buf(),
            directories,
        };
        if let Err(error) = result.verify() {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            result.close_into_attempt(&mut close);
            return Err(close.finish().err().expect("ancestor verify first error retained").retain_and_report());
        }
        Ok(result)
    }

    fn fd(&self) -> io::Result<RawFd> {
        self.directories
            .last()
            .map(|directory| directory.file.as_raw_fd())
            .ok_or_else(|| refuse("original deployment parent closed"))
    }

    fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.directories
            .last()
            .map(|directory| directory.key)
            .ok_or_else(|| refuse("original deployment parent closed"))
    }

    fn verify(&self) -> io::Result<()> {
        if self.directories.is_empty() || self.directories.len() > MAX_COMPONENTS + 1 {
            return Err(refuse("original deployment ancestor count"));
        }
        for (index, directory) in self.directories.iter().enumerate() {
            let observed = observe_fd(directory.file.as_raw_fd())?;
            if observed.key != directory.key {
                return Err(refuse("retained deployment ancestor identity changed"));
            }
            if mount_identity::mount_id(directory.file.as_raw_fd())? != directory.mount_id {
                return Err(refuse("retained deployment ancestor mount changed"));
            }
            verify_directory(observed, index + 1 == self.directories.len())?;
            if index > 0 {
                let name = directory
                    .component
                    .as_ref()
                    .ok_or_else(|| refuse("original deployment component absent"))?;
                let parent = &self.directories[index - 1];
                let slot = observe_slot(parent.file.as_raw_fd(), name)?;
                if !observed.same_object(slot) {
                    return Err(refuse("retained deployment ancestor slot changed"));
                }
                if mount_identity::slot_mount_id(parent.file.as_raw_fd(), name)? != directory.mount_id {
                    return Err(refuse("retained deployment ancestor slot mount changed"));
                }
            }
        }
        Ok(())
    }

    fn close_into_attempt(self, attempt: &mut UnixOriginalCloseAttempt) {
        for directory in self.directories.into_iter().rev() {
            attempt.close_file(directory.file);
        }
    }
}

fn close_file(file: File) -> io::Result<()> {
    let fd = file.into_raw_fd();
    // SAFETY: into_raw_fd transferred ownership. This is the single close call
    // for that original FD; retrying close could close a reused descriptor.
    if unsafe { libc::close(fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Owns the original file and every original ancestor until explicit close.
/// No Debug, Serialize, Clone or path-only identity constructor is provided.
pub struct UnixProtectedArtifactSource {
    parent: AnchoredParent,
    component: CString,
    file: File,
    observed: FileObservation,
    private: bool,
    maximum: usize,
}

impl UnixProtectedArtifactSource {
    pub fn open_original(path: &Path, maximum: usize, private: bool) -> io::Result<Self> {
        let parts = normal_components(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| refuse("original deployment source parent"))?;
        let parent = AnchoredParent::open(parent_path)?;
        let name = parts
            .into_iter()
            .last()
            .ok_or_else(|| refuse("original deployment source component"))?;
        // A foreign FIFO must be rejected by fstat instead of blocking this
        // original-source acquisition before its regular-file check.
        let mut file = None;
        let checked = (|| {
            file = Some(open_child(parent.fd()?, &name, libc::O_RDONLY | libc::O_NONBLOCK)?);
            let observed = observe_fd(file.as_ref().expect("opened source descriptor").as_raw_fd())?;
            verify_file(observed, private, maximum)?;
            let slot = observe_slot(parent.fd()?, &name)?;
            if slot != observed {
                return Err(refuse("original deployment source slot changed during open"));
            }
            Ok(observed)
        })();
        let observed = match checked {
            Ok(observed) => observed,
            Err(error) => {
                let mut close = UnixOriginalCloseAttempt::new();
                close.note_error(error);
                if let Some(file) = file { close.close_file(file); }
                parent.close_into_attempt(&mut close);
                return Err(close.finish().err().expect("source open first error retained").retain_and_report());
            }
        };
        let result = Self {
            parent,
            component: name,
            file: file.expect("checked original source descriptor"),
            observed,
            private,
            maximum,
        };
        if let Err(error) = result.verify_original() {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            close.append_result(result.close_retaining());
            return Err(close.finish().err().expect("source verify first error retained").retain_and_report());
        }
        Ok(result)
    }

    pub fn key(&self) -> UnixProtectedArtifactKey {
        self.observed.key
    }

    pub fn bytes(&self) -> u64 {
        self.observed.bytes
    }

    pub fn verify_original(&self) -> io::Result<()> {
        self.parent.verify()?;
        let observed = observe_fd(self.file.as_raw_fd())?;
        verify_file(observed, self.private, self.maximum)?;
        let slot = observe_slot(self.parent.fd()?, &self.component)?;
        if observed != self.observed || slot != observed {
            return Err(refuse(
                "original deployment source identity/length/times changed",
            ));
        }
        if mount_identity::mount_id(self.file.as_raw_fd())?
            != mount_identity::slot_mount_id(self.parent.fd()?, &self.component)?
        {
            return Err(refuse("original deployment source slot mount changed"));
        }
        Ok(())
    }

    /// A caller hashes the returned bytes and, before capture completion,
    /// repeats this original-FD read and verifies exact byte equality.
    pub fn read_bounded(&self) -> io::Result<Vec<u8>> {
        self.verify_original()?;
        let length = usize::try_from(self.observed.bytes)
            .map_err(|_| refuse("deployment source length conversion"))?;
        let mut bytes = vec![0u8; length];
        self.file.read_exact_at(&mut bytes, 0)?;
        let mut extra = [0u8; 1];
        if self.file.read_at(&mut extra, self.observed.bytes)? != 0 {
            return Err(refuse("deployment source exceeded original length"));
        }
        self.verify_original()?;
        Ok(bytes)
    }

    pub fn close(self) -> io::Result<()> {
        self.close_retaining().map(|_| ()).map_err(UnixOriginalResourceCloseFailure::retain_and_report)
    }

    pub fn close_retaining(self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut attempt = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify_original() { attempt.note_error(error); }
        attempt.close_file(self.file);
        self.parent.close_into_attempt(&mut attempt);
        attempt.finish()
    }
}

/// A live original private parent; its key alone cannot mint this value.
pub struct UnixProtectedArtifactParent {
    original: Arc<AnchoredParent>,
}

/// A post-CREATE failure retains that exact original FD. Callers can record
/// its real prefix and close it explicitly without adopting a pathname.
pub struct UnixFailedArtifactCreation {
    parent: Arc<AnchoredParent>,
    component: CString,
    file: File,
}

impl UnixFailedArtifactCreation {
    pub fn observed_key(&self) -> io::Result<UnixProtectedArtifactKey> {
        Ok(observe_fd(self.file.as_raw_fd())?.key)
    }

    pub fn observed_bytes(&self) -> io::Result<u64> {
        Ok(observe_fd(self.file.as_raw_fd())?.bytes)
    }

    pub fn verify_original_slot(&self) -> io::Result<()> {
        self.parent.verify()?;
        let observed = observe_fd(self.file.as_raw_fd())?;
        if observe_slot(self.parent.fd()?, &self.component)? != observed {
            return Err(refuse("failed original deployment CREATE slot changed"));
        }
        if mount_identity::mount_id(self.file.as_raw_fd())?
            != mount_identity::slot_mount_id(self.parent.fd()?, &self.component)?
        {
            return Err(refuse("failed original deployment CREATE mount changed"));
        }
        Ok(())
    }

    pub fn close(self) -> io::Result<()> {
        self.close_retaining().map(|_| ()).map_err(UnixOriginalResourceCloseFailure::retain_and_report)
    }

    pub fn close_retaining(self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut attempt = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify_original_slot() { attempt.note_error(error); }
        attempt.close_file(self.file);
        if let Ok(parent) = Arc::try_unwrap(self.parent) { parent.close_into_attempt(&mut attempt); }
        attempt.finish()
    }
}

pub struct UnixProtectedArtifactCreateFailure {
    pub error: io::Error,
    pub original_created: Option<UnixFailedArtifactCreation>,
}

impl std::fmt::Debug for UnixProtectedArtifactCreateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixProtectedArtifactCreateFailure")
            .field("error_kind", &self.error.kind())
            .field("original_create_happened", &self.original_created.is_some())
            .finish()
    }
}

fn before_create_failure(error: io::Error) -> UnixProtectedArtifactCreateFailure {
    UnixProtectedArtifactCreateFailure {
        error,
        original_created: None,
    }
}

impl UnixProtectedArtifactParent {
    pub fn open_private(path: &Path) -> io::Result<Self> {
        Ok(Self {
            original: Arc::new(AnchoredParent::open(path)?),
        })
    }

    pub fn path(&self) -> &Path {
        &self.original.path
    }

    pub fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.original.verify()?;
        self.original.key()
    }

    pub fn verify_original(&self) -> io::Result<()> {
        self.original.verify()
    }

    pub fn available_space(&self) -> io::Result<(u64, u64)> {
        self.original.verify()?;
        let mut value = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: this is the retained original directory FD; successful
        // fstatvfs initializes the supplied structure.
        if unsafe { libc::fstatvfs(self.original.fd()?, value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful fstatvfs initialized the entire value.
        let value = unsafe { value.assume_init() };
        let unit = value.f_frsize as u64;
        let available = (value.f_bavail as u64)
            .checked_mul(unit)
            .filter(|_| unit != 0)
            .ok_or_else(|| refuse("deployment filesystem capacity overflow"))?;
        self.original.verify()?;
        Ok((available, unit))
    }

    pub fn require_absent(&self, name: &str) -> io::Result<()> {
        let name = component(OsStr::new(name))?;
        self.original.verify()?;
        match observe_slot(self.original.fd()?, &name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "deployment target slot is occupied",
            )),
        }
    }

    pub fn require_empty(&self) -> io::Result<()> {
        self.original.verify()?;
        directory_entries::require_empty(self.original.fd()?)?;
        self.original.verify()
    }

    pub fn create_new(
        &self,
        name: &str,
    ) -> std::result::Result<UnixProtectedArtifactCreator, UnixProtectedArtifactCreateFailure> {
        let name = component(OsStr::new(name)).map_err(before_create_failure)?;
        self.original.verify().map_err(before_create_failure)?;
        let parent_fd = self.original.fd().map_err(before_create_failure)?;
        // SAFETY: the parent is retained and verified; name is NUL terminated.
        // O_EXCL/O_NOFOLLOW creates only a genuinely absent leaf. The fresh FD
        // is transferred immediately to the creator, including failure paths.
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(before_create_failure(io::Error::last_os_error()));
        }
        // SAFETY: fd is the just-created, exclusively owned original FD.
        let file = unsafe { File::from_raw_fd(fd) };
        let pending = UnixFailedArtifactCreation {
            parent: Arc::clone(&self.original),
            component: name,
            file,
        };
        let checked = (|| -> io::Result<UnixProtectedArtifactKey> {
            // SAFETY: this is the actual newly created original file. fchmod
            // establishes 0600 on that FD, including restrictive umasks.
            if unsafe { libc::fchmod(pending.file.as_raw_fd(), 0o600) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let observed = observe_fd(pending.file.as_raw_fd())?;
            verify_file(observed, true, MAX_ARTIFACT_BYTES)?;
            if observed.bytes != 0
                || observe_slot(pending.parent.fd()?, &pending.component)? != observed
            {
                return Err(refuse("fresh deployment creator original slot differs"));
            }
            pending.parent.verify()?;
            Ok(observed.key)
        })();
        let key = match checked {
            Ok(key) => key,
            Err(error) => {
                return Err(UnixProtectedArtifactCreateFailure {
                    error,
                    original_created: Some(pending),
                });
            }
        };
        Ok(UnixProtectedArtifactCreator {
            parent: pending.parent,
            component: pending.component,
            file: pending.file,
            key,
            write_attempted: false,
        })
    }

    pub fn close(self) -> io::Result<()> {
        self.close_retaining().map(|_| ()).map_err(UnixOriginalResourceCloseFailure::retain_and_report)
    }

    pub fn close_retaining(self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut attempt = UnixOriginalCloseAttempt::new();
        attempt.close_artifact_parent(self);
        attempt.finish()
    }
}

/// Only this actual CREATE object can write its fresh leaf. A failed write
/// remains attempted; an implicit retry cannot turn its prefix into success.
pub struct UnixProtectedArtifactCreator {
    parent: Arc<AnchoredParent>,
    component: CString,
    file: File,
    key: UnixProtectedArtifactKey,
    write_attempted: bool,
}

pub struct UnixProtectedArtifactSealFailure {
    pub error: io::Error,
    pub original_creator: UnixProtectedArtifactCreator,
}

impl std::fmt::Debug for UnixProtectedArtifactSealFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixProtectedArtifactSealFailure")
            .field("error_kind", &self.error.kind())
            .field("original_creator_retained", &true)
            .finish()
    }
}

impl UnixProtectedArtifactCreator {
    pub fn key(&self) -> UnixProtectedArtifactKey {
        self.key
    }

    pub fn parent_key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.parent.verify()?;
        self.parent.key()
    }

    pub fn verify_original(&self) -> io::Result<()> {
        self.parent.verify()?;
        let observed = observe_fd(self.file.as_raw_fd())?;
        verify_file(observed, true, MAX_ARTIFACT_BYTES)?;
        if observed.key != self.key || observe_slot(self.parent.fd()?, &self.component)? != observed
        {
            return Err(refuse("original deployment CREATE slot identity changed"));
        }
        if mount_identity::mount_id(self.file.as_raw_fd())?
            != mount_identity::slot_mount_id(self.parent.fd()?, &self.component)?
        {
            return Err(refuse("original deployment CREATE slot mount changed"));
        }
        Ok(())
    }

    pub fn write_and_sync(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.verify_original()?;
        if self.write_attempted
            || bytes.is_empty()
            || bytes.len() > MAX_ARTIFACT_BYTES
            || observe_fd(self.file.as_raw_fd())?.bytes != 0
        {
            return Err(refuse(
                "one bounded write on the fresh original creator required",
            ));
        }
        self.write_attempted = true;
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        self.parent
            .directories
            .last()
            .ok_or_else(|| refuse("deployment creator parent closed"))?
            .file
            .sync_all()?;
        self.verify_bytes(bytes)
    }

    fn verify_bytes(&self, expected: &[u8]) -> io::Result<()> {
        self.verify_original()?;
        let observed = observe_fd(self.file.as_raw_fd())?;
        if observed.bytes != expected.len() as u64 {
            return Err(refuse("original deployment CREATE length differs"));
        }
        let mut actual = vec![0u8; expected.len()];
        self.file.read_exact_at(&mut actual, 0)?;
        if actual != expected {
            return Err(refuse("original deployment CREATE readback differs"));
        }
        if observe_fd(self.file.as_raw_fd())? != observed {
            return Err(refuse("original deployment CREATE changed during readback"));
        }
        self.verify_original()
    }

    pub fn seal(
        self,
        expected: &[u8],
    ) -> std::result::Result<SealedUnixProtectedArtifact, UnixProtectedArtifactSealFailure> {
        let checked = if !self.write_attempted {
            Err(refuse(
                "original deployment creator has no attempted content",
            ))
        } else {
            self.verify_bytes(expected)
        };
        if let Err(error) = checked {
            return Err(UnixProtectedArtifactSealFailure {
                error,
                original_creator: self,
            });
        }
        Ok(SealedUnixProtectedArtifact {
            original: self,
            bytes: expected.len(),
        })
    }

    pub fn close(self) -> io::Result<()> {
        self.close_retaining().map(|_| ()).map_err(UnixOriginalResourceCloseFailure::retain_and_report)
    }

    pub fn close_retaining(self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut attempt = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify_original() { attempt.note_error(error); }
        attempt.close_file(self.file);
        if let Ok(parent) = Arc::try_unwrap(self.parent) { parent.close_into_attempt(&mut attempt); }
        attempt.finish()
    }
}

/// Retains the actual creator but exposes no writable FD or mutation method.
pub struct SealedUnixProtectedArtifact {
    original: UnixProtectedArtifactCreator,
    bytes: usize,
}

impl SealedUnixProtectedArtifact {
    pub fn key(&self) -> UnixProtectedArtifactKey {
        self.original.key
    }

    pub fn parent_key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.original.parent_key()
    }

    pub fn verify_original(&self, expected: &[u8]) -> io::Result<()> {
        if expected.len() != self.bytes {
            return Err(refuse("sealed deployment artifact expected length differs"));
        }
        self.original.verify_bytes(expected)
    }

    pub fn close(self) -> io::Result<()> {
        self.original.close()
    }

    pub fn close_retaining(self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        self.original.close_retaining()
    }
}
