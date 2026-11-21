//! Checked exact inode unlink and separate read-only absence observations.
//! Journal restart authorization is never supplied as a public boolean.
use super::super::{key, name, UnixDirectory, UnixFileKey};
use super::{mount_id, private, LinuxNamespaceCapability};
use crate::linux_write_lease::OriginalWriteLease;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};

enum Location {
    Outside,
    Retained,
}

pub struct LinuxOutsideCleanupBoundary<'a> {
    owner: &'a LinuxNamespaceCapability,
    parent: File,
    parent_key: UnixFileKey,
    component: CString,
    file: File,
    lease: OriginalWriteLease,
    original_key: UnixFileKey,
    exact_bytes: Vec<u8>,
}

/// This carries an actual held-parent ENOENT observation. It grants no unlink.
pub struct LinuxCleanupAbsenceObservation<'a> {
    owner: &'a LinuxNamespaceCapability,
    parent: File,
    parent_key: UnixFileKey,
    component: CString,
    original_key: UnixFileKey,
    absent_ancestor: Option<(CString, UnixFileKey)>,
}

fn parent(
    owner: &LinuxNamespaceCapability,
    path: &Path,
    expected: UnixFileKey,
    location: Location,
) -> io::Result<File> {
    owner.verify()?;
    let parent = UnixDirectory::open(path)?.file;
    private(&parent, true)?;
    if key(&parent)? != expected {
        return Err(super::super::unsupported("cleanup original parent differs"));
    }
    let volume = owner.volume().observation();
    match location {
        Location::Outside if expected.device == volume.root_key.device => {
            return Err(super::super::unsupported(
                "outside cleanup entered frozen volume",
            ))
        }
        Location::Retained
            if expected.device != volume.root_key.device
                || mount_id(&parent)? != volume.runtime_mount_id =>
        {
            return Err(super::super::unsupported(
                "retained cleanup crossed acquired original volume",
            ))
        }
        _ => {}
    }
    owner.verify()?;
    Ok(parent)
}

impl<'a> LinuxOutsideCleanupBoundary<'a> {
    pub fn acquire(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
        exact_bytes: &[u8],
    ) -> io::Result<Self> {
        Self::acquire_at(
            owner,
            parent_path,
            component,
            original_parent,
            original_file,
            exact_bytes,
            Location::Outside,
        )
    }
    pub fn acquire_retained(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
        exact_bytes: &[u8],
    ) -> io::Result<Self> {
        Self::acquire_at(
            owner,
            parent_path,
            component,
            original_parent,
            original_file,
            exact_bytes,
            Location::Retained,
        )
    }
    fn acquire_at(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
        exact_bytes: &[u8],
        location: Location,
    ) -> io::Result<Self> {
        if component.starts_with('.')
            || exact_bytes.len() > 64 * 1024 * 1024
            || original_file.device != original_parent.device
            || original_file.inode == 0
        {
            return Err(super::super::unsupported(
                "exact bounded cleanup component required",
            ));
        }
        if matches!(location, Location::Outside)
            && (exact_bytes.is_empty() || exact_bytes.len() > 16 * 1024 * 1024)
        {
            return Err(super::super::unsupported(
                "bounded outside intent bytes required",
            ));
        }
        let parent = parent(owner, parent_path, original_parent, location)?;
        let component = name(component)?;
        // SAFETY: exact retained no-follow parent and bounded single component.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat transferred one owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        private(&file, false)?;
        if key(&file)? != original_file || file.metadata()?.len() != exact_bytes.len() as u64 {
            return Err(super::super::unsupported(
                "cleanup intent or retained file was substituted",
            ));
        }
        let lease = OriginalWriteLease::acquire(&file)?;
        let boundary = Self {
            owner,
            parent,
            parent_key: original_parent,
            component,
            file,
            lease,
            original_key: original_file,
            exact_bytes: exact_bytes.to_vec(),
        };
        boundary.verify()?;
        Ok(boundary)
    }
    pub fn verify(&self) -> io::Result<()> {
        self.owner.verify()?;
        private(&self.parent, true)?;
        self.lease.verify()?;
        private(&self.file, false)?;
        let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: sized output, exact retained original parent and component.
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.component.as_ptr(),
                observed.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatat initialized this output.
        let observed = unsafe { observed.assume_init() };
        if key(&self.parent)? != self.parent_key
            || key(&self.file)? != self.original_key
            || observed.st_dev != self.original_key.device
            || observed.st_ino != self.original_key.inode
            || observed.st_nlink != 1
            || observed.st_mode & libc::S_IFMT != libc::S_IFREG
            || self.file.metadata()?.len() != self.exact_bytes.len() as u64
        {
            return Err(super::super::unsupported("cleanup original slot changed"));
        }
        let mut bytes = vec![0u8; self.exact_bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if bytes != self.exact_bytes {
            return Err(super::super::unsupported(
                "cleanup exact original bytes changed",
            ));
        }
        self.lease.verify()?;
        self.owner.verify()
    }
    pub(crate) fn verify_exact_retained_content(
        &self,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
        expected_bytes: &[u8],
    ) -> io::Result<()> {
        if self.parent_key != original_parent
            || self.original_key != original_file
            || self.exact_bytes != expected_bytes
            || self.component.to_bytes() != b"original"
        {
            return Err(super::super::unsupported(
                "held original retained content scope differs",
            ));
        }
        self.verify()
    }
    pub fn unlink_exact_original(self) -> io::Result<LinuxCleanupAbsenceObservation<'a>> {
        self.verify()?;
        // SAFETY: exact original inode and bytes were checked against this held slot.
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.component.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.parent.sync_all()?;
        self.lease.verify()?;
        if key(&self.file)? != self.original_key || self.file.metadata()?.nlink() != 0 {
            return Err(super::super::unsupported(
                "cleanup original unlink is uncertain",
            ));
        }
        let absent = LinuxCleanupAbsenceObservation {
            owner: self.owner,
            parent: self.parent,
            parent_key: self.parent_key,
            component: self.component,
            original_key: self.original_key,
            absent_ancestor: None,
        };
        absent.verify()?;
        Ok(absent)
    }
}

impl<'a> LinuxCleanupAbsenceObservation<'a> {
    pub fn observe_outside(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
    ) -> io::Result<Self> {
        Self::observe_at(
            owner,
            parent_path,
            component,
            original_parent,
            original_file,
            Location::Outside,
        )
    }
    pub fn observe_retained(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
    ) -> io::Result<Self> {
        Self::observe_at(
            owner,
            parent_path,
            component,
            original_parent,
            original_file,
            Location::Retained,
        )
    }
    fn observe_at(
        owner: &'a LinuxNamespaceCapability,
        parent_path: &Path,
        component: &str,
        original_parent: UnixFileKey,
        original_file: UnixFileKey,
        location: Location,
    ) -> io::Result<Self> {
        if component.starts_with('.')
            || original_file.device != original_parent.device
            || original_file.inode == 0
        {
            return Err(super::super::unsupported(
                "original absence component required",
            ));
        }
        let value = Self {
            owner,
            parent: parent(owner, parent_path, original_parent, location)?,
            parent_key: original_parent,
            component: name(component)?,
            original_key: original_file,
            absent_ancestor: None,
        };
        value.verify()?;
        Ok(value)
    }
    pub fn verify(&self) -> io::Result<()> {
        self.owner.verify()?;
        private(&self.parent, true)?;
        let (checked_component, checked_parent) = self
            .absent_ancestor
            .as_ref()
            .map_or((&self.component, self.parent_key), |(component, key)| {
                (component, *key)
            });
        if key(&self.parent)? != checked_parent {
            return Err(super::super::unsupported("absence parent changed"));
        }
        let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: sized output and exact held parent/component, without following links.
        let status = unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                checked_component.as_ptr(),
                observed.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(super::super::unsupported(
                "original cleanup slot is not absent",
            ));
        }
        self.owner.verify()
    }
    /// A child below an actually absent original transaction directory is
    /// unreachable. This observation derives from its sealed held-container
    /// ENOENT; it cannot create, reopen or remove a replacement parent.
    pub fn observe_child_of_original_absent_directory(
        absent_directory: &Self,
        component: &str,
        original_file: UnixFileKey,
    ) -> io::Result<Self> {
        absent_directory.verify()?;
        if absent_directory.absent_ancestor.is_some()
            || component.starts_with('.')
            || original_file.device != absent_directory.original_key.device
            || original_file.inode == 0
        {
            return Err(super::super::unsupported(
                "bounded original absent-directory child required",
            ));
        }
        let value = Self {
            owner: absent_directory.owner,
            parent: absent_directory.parent.try_clone()?,
            parent_key: absent_directory.original_key,
            component: name(component)?,
            original_key: original_file,
            absent_ancestor: Some((
                absent_directory.component.clone(),
                absent_directory.parent_key,
            )),
        };
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn retained_parent_descriptor(&self) -> i32 {
        self.parent.as_raw_fd()
    }

    pub fn original_parent_key(&self) -> UnixFileKey {
        self.parent_key
    }
    pub fn original_file_key(&self) -> UnixFileKey {
        self.original_key
    }
    pub fn component(&self) -> &str {
        self.component.to_str().expect("validated single component")
    }
    pub fn owner_generation(&self) -> [u8; 16] {
        self.owner.owner_generation()
    }
}
