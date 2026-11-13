//! Descriptor-relative no-replace mechanism, not a durable publication protocol.
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixFileKey {
    pub device: u64,
    pub inode: u64,
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn name(value: &str) -> io::Result<CString> {
    if value.is_empty() || matches!(value, "." | "..") || value.len() > 255 || value.contains('/') {
        return Err(unsupported("one nonempty native component is required"));
    }
    CString::new(value).map_err(|_| unsupported("NUL in native component"))
}

fn owned_descriptor(descriptor: libc::c_int) -> io::Result<File> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open/openat returns one newly owned live descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_directory_at(parent: &File, component: &CString) -> io::Result<File> {
    // SAFETY: parent is live, component is terminated, no variadic mode is used.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    owned_descriptor(descriptor)
}

fn key(file: &File) -> io::Result<UnixFileKey> {
    let metadata = file.metadata()?;
    if metadata.ino() == 0 {
        return Err(unsupported("native inode unavailable"));
    }
    Ok(UnixFileKey {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Anonymous request staging with kernel lifetime cleanup. No named upload
/// exists, including during creation or after an actual process kill.
/// Unsupported filesystems fail before receiving bytes.
pub fn create_anonymous_upload(parent: &Path) -> io::Result<File> {
    use std::os::unix::fs::PermissionsExt;
    let directory = UnixDirectory::open(parent)?;
    let metadata = directory.file.metadata()?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(unsupported(
            "upload parent must have owner-only permissions",
        ));
    }
    let name = CString::new(".").expect("fixed native component");
    // SAFETY: retained parent and terminated fixed component; O_TMPFILE
    // requires the supplied owner-only mode and returns one owned descriptor.
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC | libc::O_EXCL,
            0o600 as libc::mode_t,
        )
    };
    let file = owned_descriptor(descriptor)?;
    if file.metadata()?.nlink() != 0 || !file.metadata()?.is_file() {
        return Err(unsupported("anonymous upload descriptor was linked"));
    }
    Ok(file)
}

/// Hold one exclusive owner on the exact state directory without creating a lock file.
pub fn acquire_sidecar_owner(parent: &Path) -> io::Result<File> {
    let directory = UnixDirectory::open(parent)?;
    // SAFETY: a retained real directory descriptor; nonblocking advisory lock has no pointers.
    if unsafe { libc::flock(directory.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(directory.file)
}

/// Retained real directory, with no symlinks followed at any component.
/// Linux does not stop a native process from renaming this directory or its
/// children; retaining a descriptor is not a namespace mutation lock.
struct UnixDirectory {
    file: File,
}

impl UnixDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(unsupported("absolute native parent required"));
        }
        let root = CString::new("/").expect("fixed component");
        // SAFETY: root is terminated and flags require a real directory.
        let descriptor = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        let mut file = owned_descriptor(descriptor)?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(component) => {
                    let component = CString::new(component.as_bytes())
                        .map_err(|_| unsupported("NUL in native parent"))?;
                    file = open_directory_at(&file, &component)?;
                }
                _ => return Err(unsupported("unsafe native parent component")),
            }
        }
        let directory = Self { file };
        directory.key()?;
        Ok(directory)
    }

    pub fn key(&self) -> io::Result<UnixFileKey> {
        if !self.file.metadata()?.is_dir() {
            return Err(unsupported("retained parent is not a directory"));
        }
        key(&self.file)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Fresh creator only; no reopening an existing slot as ownership.
    pub fn create_new_file(&self, component: &str) -> io::Result<UnixOwnedFile> {
        self.key()?;
        let component = name(component)?;
        let source_parent = self.file.try_clone()?;
        // SAFETY: retained parent and terminated component; O_CREAT supplies mode.
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::mode_t,
            )
        };
        let created = UnixOwnedFile {
            file: owned_descriptor(descriptor)?,
            source_parent,
            source_component: component,
        };
        created.verify_single_link()?;
        Ok(created)
    }
}

/// ORIGINAL creator descriptor; no Drop cleanup, pathname adoption or claims
/// of mandatory native writer exclusion. Callers persist provenance separately.
struct UnixOwnedFile {
    file: File,
    source_parent: File,
    source_component: CString,
}

impl UnixOwnedFile {
    pub fn key(&self) -> io::Result<UnixFileKey> {
        key(&self.file)
    }

    pub fn writer(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn verify_single_link(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(unsupported("creator must be a regular single-link file"));
        }
        self.key()?;
        Ok(())
    }

    /// Does not replace any destination. A successful rename is a transient
    /// native observation, NOT a durable completion/owned recovery receipt.
    /// Source-slot checking has a Linux native-writer race; this API must not be
    /// used for production publication without a stronger admitted owner scheme.
    pub fn rename_no_replace(
        &mut self,
        destination: &UnixDirectory,
        component: &str,
    ) -> io::Result<()> {
        self.verify_single_link()?;
        let target = name(component)?;
        if self.key()?.device != destination.key()?.device {
            return Err(unsupported("same filesystem publication required"));
        }
        // SAFETY: retained source parent and terminated component; O_NOFOLLOW.
        let source = unsafe {
            libc::openat(
                self.source_parent.as_raw_fd(),
                self.source_component.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        let source = owned_descriptor(source)?;
        let source_metadata = source.metadata()?;
        if !source_metadata.is_file()
            || source_metadata.nlink() != 1
            || key(&source)? != self.key()?
        {
            return Err(unsupported(
                "native source slot is not the original creator",
            ));
        }
        let destination_parent = destination.file.try_clone()?;
        // SAFETY: live parents, terminated names and kernel no-replace flag.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.source_parent.as_raw_fd(),
                self.source_component.as_ptr(),
                destination.file.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // Update the slot even if flushing fails after the native rename.
        let old_parent = std::mem::replace(&mut self.source_parent, destination_parent);
        self.source_component = target;
        self.verify_single_link()?;
        let published = open_regular_at(&self.source_parent, &self.source_component)?;
        if key(&published)? != self.key()? {
            return Err(unsupported("published slot differs from original creator"));
        }
        // These observations do not fence subsequent native namespace writers.
        old_parent.sync_all()?;
        destination.sync()?;
        Ok(())
    }
}

fn open_regular_at(parent: &File, component: &CString) -> io::Result<File> {
    // SAFETY: live parent and terminated name; nonblocking avoids a foreign FIFO.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    let file = owned_descriptor(descriptor)?;
    if !file.metadata()?.is_file() {
        return Err(unsupported("probe slot is not a regular file"));
    }
    Ok(file)
}

/// Observations from a fresh private throwaway directory, never apply authority.
/// All residues are preserved, including on unsupported filesystems or errors.
#[derive(Debug)]
pub struct NoReplaceProbeReport {
    pub probe_directory: PathBuf,
    pub parent_key: UnixFileKey,
    pub original_creator_key: Option<UnixFileKey>,
    pub observed_no_replace: bool,
    pub occupied_file_preserved: bool,
    pub occupied_directory_preserved: bool,
    pub occupied_symlink_preserved: bool,
    pub original_creator_verified: bool,
    pub directories_flushed: bool,
    pub failure: Option<String>,
}

impl NoReplaceProbeReport {
    pub fn observations_complete(&self) -> bool {
        self.failure.is_none()
            && self.observed_no_replace
            && self.occupied_file_preserved
            && self.occupied_directory_preserved
            && self.occupied_symlink_preserved
            && self.original_creator_verified
            && self.directories_flushed
    }
}

fn create_directory_at(parent: &UnixDirectory, component: &CString) -> io::Result<()> {
    // SAFETY: retained parent and terminated single name; mkdir never adopts.
    let result = unsafe { libc::mkdirat(parent.file.as_raw_fd(), component.as_ptr(), 0o700) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_slot(parent: &UnixDirectory, component: &str, creator: &UnixOwnedFile) -> io::Result<()> {
    creator.verify_single_link()?;
    let file = open_regular_at(&parent.file, &name(component)?)?;
    if key(&file)? != creator.key()? {
        return Err(unsupported("probe slot differs from original creator"));
    }
    Ok(())
}

fn occupied_refuses(
    creator: &mut UnixOwnedFile,
    parent: &UnixDirectory,
    target: &str,
) -> io::Result<()> {
    match creator.rename_no_replace(parent, target) {
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
        Err(error) => return Err(error),
        Ok(()) => return Err(unsupported("occupied probe destination unexpectedly moved")),
    }
    verify_slot(parent, "payload", creator)
}

fn run_probe(parent: &UnixDirectory, report: &mut NoReplaceProbeReport) -> io::Result<()> {
    use std::io::{Read, Write};
    const PAYLOAD: &[u8] = b"SyncExtend private no-replace probe\n";
    let mut creator = parent.create_new_file("payload")?;
    report.original_creator_key = Some(creator.key()?);
    creator.writer().write_all(PAYLOAD)?;
    creator.writer().sync_all()?;
    let mut foreign = parent.create_new_file("occupied-file")?;
    foreign.writer().write_all(b"preserved probe occupant")?;
    foreign.writer().sync_all()?;
    occupied_refuses(&mut creator, parent, "occupied-file")?;
    verify_slot(parent, "occupied-file", &foreign)?;
    report.occupied_file_preserved = true;

    let directory_name = name("occupied-directory")?;
    create_directory_at(parent, &directory_name)?;
    let occupied = open_directory_at(&parent.file, &directory_name)?;
    let directory_key = key(&occupied)?;
    occupied_refuses(&mut creator, parent, "occupied-directory")?;
    if key(&open_directory_at(&parent.file, &directory_name)?)? != directory_key {
        return Err(unsupported("occupied probe directory changed"));
    }
    report.occupied_directory_preserved = true;

    let link_name = name("occupied-symlink")?;
    let link_target = name("occupied-file")?;
    // SAFETY: terminated fixed single names and retained probe directory.
    let result = unsafe {
        libc::symlinkat(
            link_target.as_ptr(),
            parent.file.as_raw_fd(),
            link_name.as_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    occupied_refuses(&mut creator, parent, "occupied-symlink")?;
    let mut link_bytes = [0u8; 256];
    // SAFETY: live parent, terminated name, valid output buffer and its length.
    let length = unsafe {
        libc::readlinkat(
            parent.file.as_raw_fd(),
            link_name.as_ptr(),
            link_bytes.as_mut_ptr().cast(),
            link_bytes.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if &link_bytes[..length as usize] != b"occupied-file" {
        return Err(unsupported("occupied probe symlink changed"));
    }
    verify_slot(parent, "occupied-file", &foreign)?;
    report.occupied_symlink_preserved = true;

    creator.rename_no_replace(parent, "moved-payload")?;
    verify_slot(parent, "moved-payload", &creator)?;
    match open_regular_at(&parent.file, &name("payload")?) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(error) => return Err(error),
        Ok(_) => return Err(unsupported("probe source still occupied after rename")),
    }
    let moved = open_regular_at(&parent.file, &name("moved-payload")?)?;
    let mut bytes = Vec::new();
    (&moved)
        .take(PAYLOAD.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes != PAYLOAD {
        return Err(unsupported("probe content changed"));
    }
    report.observed_no_replace = true;
    report.original_creator_verified = true;
    parent.sync()?;
    Ok(())
}

/// Explicit opt-in mechanism probe. Creates one random, exclusive, mode-0700
/// child in an existing absolute no-follow parent; never removes any pathname.
/// A successful report does not establish source-slot exclusion, safe native
/// application, crash recovery, Android FUSE support or device certification.
pub fn probe_no_replace(parent: &Path) -> io::Result<NoReplaceProbeReport> {
    let directory = UnixDirectory::open(parent)?;
    let parent_key = directory.key()?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let component = format!(".sync-extend-noreplace-probe-{suffix}");
    let probe_directory = parent.join(&component);
    let mut report = NoReplaceProbeReport {
        probe_directory,
        parent_key,
        original_creator_key: None,
        observed_no_replace: false,
        occupied_file_preserved: false,
        occupied_directory_preserved: false,
        occupied_symlink_preserved: false,
        original_creator_verified: false,
        directories_flushed: false,
        failure: None,
    };
    let result = (|| {
        create_directory_at(&directory, &name(&component)?)?;
        let probe = UnixDirectory {
            file: open_directory_at(&directory.file, &name(&component)?)?,
        };
        if probe.key()?.device != parent_key.device {
            return Err(unsupported("probe filesystem changed"));
        }
        run_probe(&probe, &mut report)?;
        directory.sync()?;
        report.directories_flushed = true;
        Ok(())
    })();
    if let Err(error) = result {
        report.failure = Some(format!(
            "{error}; os_error={:?}; residues_preserved=true",
            error.raw_os_error()
        ));
    }
    Ok(report)
}
