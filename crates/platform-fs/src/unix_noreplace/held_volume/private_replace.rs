//! Hold the exact prior inode in one newly-created transaction directory.
use super::{key, name, open_directory_at, private, HeldPrivateDirectory, HeldPrivateOriginal};
use crate::UnixFileKey;
use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::FileExt},
};

pub struct OriginalRetainedVolumeFile<'a, 'v> {
    parent: &'a HeldPrivateDirectory<'v>,
    file: File,
    lease: Option<super::read_lease::ReadLease>,
    component: String,
    original_key: UnixFileKey,
    source_parent_key: UnixFileKey,
    retained_parent_key: UnixFileKey,
    exact_bytes: Vec<u8>,
}

impl<'v> HeldPrivateDirectory<'v> {
    pub fn original_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        key(self
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("held parent absent"))?)
    }

    /// Only the shared reserved container may preexist. Its exact no-follow
    /// inode is verified; the transaction child must be newly created.
    pub fn create_original_transaction_directory(
        &self,
        transaction: &str,
    ) -> io::Result<HeldPrivateDirectory<'v>> {
        self.verify()?;
        if transaction.starts_with('.') {
            return Err(super::super::unsupported(
                "original transaction component required",
            ));
        }
        let parent = self
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("held parent absent"))?;
        let container_name = name(".sync-tmp")?;
        // SAFETY: the retained original parent and one fixed reserved component.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), container_name.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error);
            }
        }
        let container = open_directory_at(parent, &container_name)?;
        private(&container, true)?;
        if key(&container)?.device != self.volume.observation.root_key.device {
            return Err(super::super::unsupported(
                "transaction container crossed original volume",
            ));
        }
        let transaction_name = name(transaction)?;
        // SAFETY: checked retained container; mkdir never adopts an existing child.
        if unsafe { libc::mkdirat(container.as_raw_fd(), transaction_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        container.sync_all()?;
        parent.sync_all()?;
        let mut relative = std::path::PathBuf::new();
        for part in &self.components {
            relative.push(part);
        }
        relative.push(".sync-tmp");
        relative.push(transaction);
        self.volume.directory(&relative)
    }

    /// Remove one empty original transaction directory. Extra entries or a
    /// substituted directory make the kernel operation refuse.
    pub fn remove_original_empty_child(
        &self,
        component: &str,
        expected: UnixFileKey,
    ) -> io::Result<()> {
        self.verify()?;
        let parent = self
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("held parent absent"))?;
        let component = name(component)?;
        let child = open_directory_at(parent, &component)?;
        private(&child, true)?;
        if key(&child)? != expected {
            return Err(super::super::unsupported(
                "cleanup transaction directory substituted",
            ));
        }
        let current = open_directory_at(parent, &component)?;
        if key(&current)? != expected {
            return Err(super::super::unsupported(
                "cleanup transaction slot substituted",
            ));
        }
        // SAFETY: the exact checked directory slot. AT_REMOVEDIR refuses contents.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        parent.sync_all()?;
        self.verify()
    }

    /// Before any outside unlink, prove that this transaction directory still
    /// contains exactly its retained `original` child.  The check is
    /// descriptor-relative and rejects an unfamiliar extra entry without
    /// mutating the namespace.
    pub fn verify_original_transaction_contents(
        &self,
        expected_file: UnixFileKey,
        expected_bytes: &[u8],
        retained: &super::LinuxOutsideCleanupBoundary<'_>,
    ) -> io::Result<()> {
        self.verify()?;
        if expected_bytes.len() > 64 * 1024 * 1024 {
            return Err(super::super::unsupported(
                "retained original bytes exceed bound",
            ));
        }
        // Use the already-held original file and its mandatory write lease.
        // Opening this inode again would itself break that original lease.
        retained.verify_exact_retained_content(self.original_key()?, expected_file, expected_bytes)?;

        let names = self.original_transaction_children()?;
        if names.len() != 1 || names[0] != "original" {
            return Err(super::super::unsupported(
                "retained transaction original child missing",
            ));
        }
        retained.verify_exact_retained_content(self.original_key()?, expected_file, expected_bytes)?;
        self.verify()
    }

    pub fn verify_original_empty_transaction(&self, expected: UnixFileKey) -> io::Result<()> {
        if self.original_key()? != expected || !self.original_transaction_children()?.is_empty() {
            return Err(super::super::unsupported(
                "original empty transaction changed or has unfamiliar children",
            ));
        }
        self.verify()
    }

    fn original_transaction_children(&self) -> io::Result<Vec<String>> {
        self.verify()?;
        // SAFETY: openat creates an independent directory stream, avoiding
        // shared dup offsets across repeated original directory observations.
        let duplicate = unsafe {
            libc::openat(
                self.parents
                    .last()
                    .ok_or_else(|| super::super::unsupported("held parent absent"))?
                    .as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: duplicate is a live directory descriptor and fdopendir takes ownership.
        let directory = unsafe { libc::fdopendir(duplicate) };
        if directory.is_null() {
            // SAFETY: fdopendir did not take ownership on failure.
            unsafe { libc::close(duplicate) };
            return Err(io::Error::last_os_error());
        }
        struct DirGuard(*mut libc::DIR);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                // SAFETY: this guard owns the fdopendir handle exactly once.
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let _guard = DirGuard(directory);
        let mut names = Vec::new();
        loop {
            // SAFETY: errno is thread-local storage provided by libc.
            unsafe {
                *libc::__errno_location() = 0;
            }
            // SAFETY: directory remains live under DirGuard; readdir returns a
            // borrowed entry valid until the next call.
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                if io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            // SAFETY: d_name is a NUL-terminated native directory component.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| super::super::unsupported("transaction child encoding"))?;
            if name != "." && name != ".." {
                names.push(name.to_owned());
                if names.len() > 1 {
                    return Err(super::super::unsupported(
                        "retained transaction contains unfamiliar child",
                    ));
                }
            }
        }
        self.verify()?;
        Ok(names)
    }
}

impl HeldPrivateOriginal<'_, '_> {
    pub fn retain_in_original_transaction<'a, 'v>(
        self,
        destination: &'a HeldPrivateDirectory<'v>,
        component: &str,
        expected_bytes: &[u8],
    ) -> io::Result<OriginalRetainedVolumeFile<'a, 'v>> {
        self.verify()?;
        destination.verify()?;
        if self.lease.is_none()
            || component.starts_with('.')
            || expected_bytes.len() > 64 * 1024 * 1024
            || self.file.metadata()?.len() != expected_bytes.len() as u64
        {
            return Err(super::super::unsupported(
                "exact excluded prior file required",
            ));
        }
        let source_parent = self
            .parent
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("source parent absent"))?;
        let destination_parent = destination
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("retained parent absent"))?;
        let original_key = key(&self.file)?;
        let source_parent_key = key(source_parent)?;
        let retained_parent_key = key(destination_parent)?;
        if original_key.device != retained_parent_key.device
            || self.parent.volume.observation != destination.volume.observation
        {
            return Err(super::super::unsupported(
                "retained prior file crossed original volume",
            ));
        }
        let mut bytes = vec![0u8; expected_bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if bytes != expected_bytes {
            return Err(super::super::unsupported("prior replacement bytes differ"));
        }
        self.verify()?;
        let source = name(&self.component)?;
        let target = name(component)?;
        // SAFETY: exact original source and destination parents; NOREPLACE
        // preserves an occupied transaction slot.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_parent.as_raw_fd(),
                source.as_ptr(),
                destination_parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        source_parent.sync_all()?;
        destination_parent.sync_all()?;
        let retained = OriginalRetainedVolumeFile {
            parent: destination,
            file: self.file,
            lease: self.lease,
            component: component.to_owned(),
            original_key,
            source_parent_key,
            retained_parent_key,
            exact_bytes: bytes,
        };
        retained.verify()?;
        Ok(retained)
    }
}

impl OriginalRetainedVolumeFile<'_, '_> {
    pub fn verify(&self) -> io::Result<()> {
        self.parent.verify()?;
        private(&self.file, false)?;
        self.lease
            .as_ref()
            .ok_or_else(|| super::super::unsupported("original retained lease absent"))?
            .verify()?;
        let parent = self
            .parent
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("retained parent absent"))?;
        let slot = super::super::open_regular_at(parent, &name(&self.component)?)?;
        if key(&self.file)? != self.original_key
            || key(&slot)? != self.original_key
            || key(parent)? != self.retained_parent_key
            || self.file.metadata()?.len() != self.exact_bytes.len() as u64
        {
            return Err(super::super::unsupported(
                "retained replacement inode or slot changed",
            ));
        }
        let mut bytes = vec![0u8; self.exact_bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if bytes != self.exact_bytes {
            return Err(super::super::unsupported("retained original bytes changed"));
        }
        self.lease
            .as_ref()
            .ok_or_else(|| super::super::unsupported("original retained lease absent"))?
            .verify()
    }
    pub fn original_key(&self) -> UnixFileKey {
        self.original_key
    }
    pub fn source_parent_key(&self) -> UnixFileKey {
        self.source_parent_key
    }
    pub fn retained_parent_key(&self) -> UnixFileKey {
        self.retained_parent_key
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}
