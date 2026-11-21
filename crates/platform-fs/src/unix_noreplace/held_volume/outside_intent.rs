//! Explicit outside-volume one-attempt intent, never native cleanup authority.
use super::super::{key, name, owned_descriptor, unsupported, UnixDirectory};
use super::{private, HeldPrivateVolume, PrivateVolumeObservation};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

pub struct OutsidePrivateIntentOwner {
    parent: UnixDirectory,
    parent_key: crate::UnixFileKey,
}

pub struct OriginalOutsideIntent {
    parent: File,
    file: File,
    component: String,
    parent_key: crate::UnixFileKey,
    file_key: crate::UnixFileKey,
    frozen_volume: PrivateVolumeObservation,
    exact_bytes: Vec<u8>,
}

impl OutsidePrivateIntentOwner {
    /// Explicit caller selection of a private outside directory. Path opening
    /// alone grants no native effects; exact O_EXCL intent CREATE follows.
    pub fn open(path: &Path, volume: &HeldPrivateVolume) -> io::Result<Self> {
        volume.verify()?;
        let parent = UnixDirectory::open(path)?;
        private(&parent.file, true)?;
        let parent_key = key(&parent.file)?;
        if parent_key.device == volume.observation().root_key.device {
            return Err(unsupported(
                "intent parent must remain outside frozen volume",
            ));
        }
        Ok(Self { parent, parent_key })
    }

    /// Read-only closure check; unfamiliar intents are retained and refuse a successor.
    pub fn verify_empty(&self, volume: &HeldPrivateVolume) -> io::Result<()> {
        volume.verify()?;
        private(&self.parent.file, true)?;
        if key(&self.parent.file)? != self.parent_key
            || std::fs::read_dir(format!("/proc/self/fd/{}", self.parent.file.as_raw_fd()))?
                .next()
                .is_some()
        {
            return Err(unsupported("outside intent inventory is not exactly empty"));
        }
        volume.verify()
    }

    /// The caller binds these exact bounded bytes to its full original plan
    /// before target effects. Existing intent occupants are never adopted.
    pub fn create_intent(
        &self,
        component: &str,
        bytes: &[u8],
        volume: &HeldPrivateVolume,
    ) -> io::Result<OriginalOutsideIntent> {
        volume.verify()?;
        private(&self.parent.file, true)?;
        if key(&self.parent.file)? != self.parent_key
            || self.parent_key.device == volume.observation().root_key.device
            || bytes.is_empty()
            || bytes.len() > 16 * 1024 * 1024
            || component.starts_with('.')
        {
            return Err(unsupported("bounded exact outside intent scope"));
        }
        let encoded = name(component)?;
        // SAFETY: exact held parent and terminated single component. O_EXCL
        // creates one new intent and never truncates or adopts an occupant.
        let descriptor = unsafe {
            libc::openat(
                self.parent.file.as_raw_fd(),
                encoded.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::mode_t,
            )
        };
        let mut file = owned_descriptor(descriptor)?;
        private(&file, false)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.parent.file.sync_all()?;
        let result = OriginalOutsideIntent {
            file_key: key(&file)?,
            parent_key: self.parent_key,
            parent: self.parent.file.try_clone()?,
            file,
            component: component.into(),
            frozen_volume: volume.observation(),
            exact_bytes: bytes.to_vec(),
        };
        result.verify(volume)?;
        Ok(result)
    }
}

impl OriginalOutsideIntent {
    pub fn verify(&self, volume: &HeldPrivateVolume) -> io::Result<()> {
        volume.verify()?;
        private(&self.parent, true)?;
        private(&self.file, false)?;
        let slot = super::super::open_regular_at(&self.parent, &name(&self.component)?)?;
        if key(&self.parent)? != self.parent_key
            || key(&self.file)? != self.file_key
            || key(&slot)? != self.file_key
            || self.frozen_volume != volume.observation()
            || self.file.metadata()?.len() != self.exact_bytes.len() as u64
            || self.file.metadata()?.nlink() != 1
        {
            return Err(unsupported(
                "original outside intent identity scope changed",
            ));
        }
        let mut reader = self.file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader
            .take(self.exact_bytes.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes != self.exact_bytes {
            return Err(unsupported("original outside intent exact bytes changed"));
        }
        Ok(())
    }

    /// Description only. No restart/native/cleanup permission is derived.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
    pub fn original_file_key(&self) -> crate::UnixFileKey {
        self.file_key
    }
    pub fn original_parent_key(&self) -> crate::UnixFileKey {
        self.parent_key
    }
    pub fn component(&self) -> &str {
        &self.component
    }
}
