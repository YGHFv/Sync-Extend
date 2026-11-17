//! Original CREATE mechanism under a retained owner-only ext4 parent.
//! This does not fence namespace writers or issue Journal/cleanup authority.
use super::{ext4, mount_id, private, HeldPrivateDirectory};
use crate::UnixFileKey;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

pub struct OriginalPrivateVolumeFile<'a, 'v> {
    parent: &'a HeldPrivateDirectory<'v>,
    file: File,
    component: String,
    created_key: UnixFileKey,
    created_parent: UnixFileKey,
    current_component: String,
    bytes_written: u64,
    max_bytes: u64,
    poisoned: bool,
}

impl<'v> HeldPrivateDirectory<'v> {
    /// Caller persists its one-attempt intent before invoking this mechanism.
    /// O_EXCL never adopts an existing object; errors preserve all residues.
    pub fn create_original_file<'a>(
        &'a self,
        component: &str,
        max_bytes: u64,
    ) -> io::Result<OriginalPrivateVolumeFile<'a, 'v>> {
        self.verify()?;
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(super::super::unsupported("private CREATE byte budget"));
        }
        let name = super::super::name(component)?;
        if component.starts_with('.') {
            return Err(super::super::unsupported(
                "private CREATE reserved component",
            ));
        }
        let parent = self
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("private CREATE parent absent"))?;
        let parent_key = super::super::key(parent)?;
        // SAFETY: original retained parent, counted terminated single component
        // and explicit mode; CREATE|EXCL does not reopen or truncate an occupant.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat transferred one newly owned file descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file, false)?;
        ext4(&file)?;
        let created_key = super::super::key(&file)?;
        if created_key.device != parent_key.device
            || mount_id(&file)? != self.volume.observation.runtime_mount_id
        {
            return Err(super::super::unsupported("private CREATE cross mount"));
        }
        let created = OriginalPrivateVolumeFile {
            parent: self,
            file,
            component: component.into(),
            created_key,
            created_parent: parent_key,
            current_component: component.into(),
            bytes_written: 0,
            max_bytes,
            poisoned: false,
        };
        created.verify()?;
        Ok(created)
    }
}

impl OriginalPrivateVolumeFile<'_, '_> {
    pub fn verify(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(super::super::unsupported(
                "private CREATE effect remains uncertain",
            ));
        }
        self.parent.verify()?;
        private(&self.file, false)?;
        let parent = self
            .parent
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("private original parent absent"))?;
        let slot =
            super::super::open_regular_at(parent, &super::super::name(&self.current_component)?)?;
        if super::super::key(&self.file)? != self.created_key
            || super::super::key(parent)? != self.created_parent
            || super::super::key(&slot)? != self.created_key
            || mount_id(&self.file)? != self.parent.volume.observation.runtime_mount_id
            || self.file.metadata()?.len() != self.bytes_written
        {
            return Err(super::super::unsupported(
                "private original exact key parent slot length",
            ));
        }
        Ok(())
    }

    pub fn original_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.created_key)
    }

    pub fn original_parent_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.created_parent)
    }

    /// The CREATE name is historical after a rename.
    pub fn created_component(&self) -> &str {
        &self.component
    }

    pub fn write_all_bounded(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.verify()?;
        let total = self
            .bytes_written
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.max_bytes)
            .ok_or_else(|| super::super::unsupported("private original write budget"))?;
        self.poisoned = true;
        self.file.seek(SeekFrom::Start(self.bytes_written))?;
        self.file.write_all(bytes)?;
        self.bytes_written = total;
        self.poisoned = false;
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub fn sync_original_and_parents(&mut self) -> io::Result<()> {
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        self.poisoned = true;
        self.file.sync_all()?;
        self.parent.sync()?;
        self.poisoned = false;
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub fn exact_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        let mut reader = self.file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(self.bytes_written as usize);
        reader
            .take(self.bytes_written + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != self.bytes_written {
            return Err(super::super::unsupported(
                "private original exact read length",
            ));
        }
        self.verify()?;
        Ok(bytes)
    }

    /// Same retained parent no-replace. Native slot races remain unsupported
    /// for production publication until the transaction supplies its boundary.
    pub fn rename_in_same_parent_no_replace(&mut self, component: &str) -> io::Result<()> {
        self.verify()?;
        let target = super::super::name(component)?;
        if component.starts_with('.') {
            return Err(super::super::unsupported(
                "private rename reserved component",
            ));
        }
        let source = super::super::name(&self.current_component)?;
        let parent = self
            .parent
            .parents
            .last()
            .ok_or_else(|| super::super::unsupported("private rename parent absent"))?;
        // SAFETY: exact retained parent and bounded single components;
        // RENAME_NOREPLACE preserves every preexisting destination.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        self.poisoned = true;
        self.current_component = component.into();
        parent.sync_all()?;
        self.poisoned = false;
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub fn observed_single_link(&self) -> io::Result<bool> {
        self.verify()?;
        Ok(self.file.metadata()?.nlink() == 1)
    }
}

impl OriginalPrivateVolumeFile<'_, '_> {
    /// Exact current original CREATE parent/components. No reopened pathname
    /// is adopted; the native slot verification remains against retained handles.
    pub fn verify_original_slot(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.verify()?;
        let mut expected = self.parent.volume.path.clone();
        for component in &self.parent.components {
            expected.push(component);
        }
        expected.push(&self.current_component);
        if expected != path {
            return Err(super::super::unsupported(
                "original CREATE exact planned parent slot differs",
            ));
        }
        self.verify()
    }
}

mod original_absence;
pub use original_absence::OriginalCreateVacatedObservation;

mod original_preallocation;
pub use original_preallocation::OriginalCreateAllocationObservation;
