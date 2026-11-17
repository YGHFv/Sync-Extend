//! Read-only held boundaries on an explicitly private local ext4 volume.
//! A directory flock is cooperative; this module supplies no mutation authority.
use super::{
    key, name, open_directory_at, open_regular_at, unsupported, UnixDirectory, UnixFileKey,
};
use std::{
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateVolumeObservation {
    pub root_key: UnixFileKey,
    /// Kernel mount identity for this retained invocation, not a reboot-stable ID.
    pub runtime_mount_id: u64,
}

pub struct HeldPrivateVolume {
    root: UnixDirectory,
    path: PathBuf,
    observation: PrivateVolumeObservation,
}

pub(super) fn private(file: &File, directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments or pointers and returns this process's UID.
    let owner = unsafe { libc::geteuid() };
    if metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(unsupported("private owner-only original object required"));
    }
    Ok(())
}

fn mount_id(file: &File) -> io::Result<u64> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    if info.len() > 4096 {
        return Err(unsupported("kernel descriptor info exceeds bound"));
    }
    let mut ids = info.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let id = ids
        .next()
        .ok_or_else(|| unsupported("kernel descriptor mount identity absent"))?
        .trim()
        .parse::<u64>()
        .map_err(|_| unsupported("kernel descriptor mount identity invalid"))?;
    if id == 0 || ids.next().is_some() {
        return Err(unsupported("kernel descriptor mount identity ambiguous"));
    }
    Ok(id)
}

fn ext4(file: &File) -> io::Result<()> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live retained descriptor and a writable properly sized statfs output.
    if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the full statfs output.
    let status = unsafe { status.assume_init() };
    if status.f_type != 0xef53 {
        return Err(unsupported("explicit local ext4 private volume required"));
    }
    Ok(())
}

impl HeldPrivateVolume {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(unsupported("normalized absolute private root required"));
        }
        let root = UnixDirectory::open(path)?;
        private(&root.file, true)?;
        ext4(&root.file)?;
        // SAFETY: live root directory descriptor; nonblocking flock has no pointers.
        if unsafe { libc::flock(root.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let observation = PrivateVolumeObservation {
            root_key: root.key()?,
            runtime_mount_id: mount_id(&root.file)?,
        };
        let held = Self {
            root,
            path: path.to_owned(),
            observation,
        };
        held.verify()?;
        Ok(held)
    }

    pub fn observation(&self) -> PrivateVolumeObservation {
        self.observation
    }

    /// Reopening is observation only; it never becomes an original object owner.
    pub fn verify(&self) -> io::Result<()> {
        private(&self.root.file, true)?;
        ext4(&self.root.file)?;
        let current = UnixDirectory::open(&self.path)?;
        if self.root.key()? != self.observation.root_key
            || current.key()? != self.observation.root_key
            || mount_id(&self.root.file)? != self.observation.runtime_mount_id
            || mount_id(&current.file)? != self.observation.runtime_mount_id
        {
            return Err(unsupported("held private root or runtime mount changed"));
        }
        Ok(())
    }

    pub fn directory<'a>(&'a self, relative: &Path) -> io::Result<HeldPrivateDirectory<'a>> {
        self.verify()?;
        if relative.is_absolute() {
            return Err(unsupported("relative held directory required"));
        }
        let mut parents = vec![self.root.file.try_clone()?];
        let mut components = Vec::new();
        for part in relative.components() {
            let Component::Normal(part) = part else {
                return Err(unsupported("normalized held directory components required"));
            };
            let text = part
                .to_str()
                .ok_or_else(|| unsupported("native directory encoding"))?;
            let next = open_directory_at(parents.last().unwrap(), &name(text)?)?;
            private(&next, true)?;
            if key(&next)?.device != self.observation.root_key.device
                || mount_id(&next)? != self.observation.runtime_mount_id
            {
                return Err(unsupported("held directory crosses runtime mount"));
            }
            parents.push(next);
            components.push(text.to_owned());
            if components.len() > 128 {
                return Err(unsupported("held directory depth exceeds bound"));
            }
        }
        Ok(HeldPrivateDirectory {
            volume: self,
            parents,
            components,
        })
    }
}

pub struct HeldPrivateDirectory<'a> {
    volume: &'a HeldPrivateVolume,
    parents: Vec<File>,
    components: Vec<String>,
}

impl<'v> HeldPrivateDirectory<'v> {
    pub fn verify(&self) -> io::Result<()> {
        self.volume.verify()?;
        for (index, component) in self.components.iter().enumerate() {
            private(&self.parents[index + 1], true)?;
            let current = open_directory_at(&self.parents[index], &name(component)?)?;
            if key(&current)? != key(&self.parents[index + 1])?
                || mount_id(&current)? != self.volume.observation.runtime_mount_id
            {
                return Err(unsupported("held private directory slot changed"));
            }
        }
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        self.verify()?;
        for parent in self.parents.iter().rev() {
            parent.sync_all()?;
        }
        self.verify()
    }

    /// Explicit single-original byte writer exclusion; namespace authority stays separate.
    pub fn writer_excluded_original<'a>(
        &'a self,
        component: &str,
    ) -> io::Result<HeldPrivateOriginal<'a, 'v>> {
        let mut original = self.original(component)?;
        original.lease = Some(read_lease::ReadLease::acquire(&original.file)?);
        original.verify()?;
        Ok(original)
    }

    pub fn original<'a>(&'a self, component: &str) -> io::Result<HeldPrivateOriginal<'a, 'v>> {
        self.verify()?;
        let file = open_regular_at(self.parents.last().unwrap(), &name(component)?)?;
        private(&file, false)?;
        if key(&file)?.device != self.volume.observation.root_key.device
            || mount_id(&file)? != self.volume.observation.runtime_mount_id
        {
            return Err(unsupported("original file crosses private runtime mount"));
        }
        let original = HeldPrivateOriginal {
            parent: self,
            file,
            component: component.to_owned(),
            lease: None,
        };
        original.verify()?;
        Ok(original)
    }
}

mod read_lease;
pub struct HeldPrivateOriginal<'a, 'v> {
    parent: &'a HeldPrivateDirectory<'v>,
    file: File,
    component: String,
    lease: Option<read_lease::ReadLease>,
}

impl HeldPrivateOriginal<'_, '_> {
    pub fn verify(&self) -> io::Result<()> {
        self.parent.verify()?;
        private(&self.file, false)?;
        if let Some(lease) = &self.lease {
            lease.verify()?;
        }
        let current =
            open_regular_at(self.parent.parents.last().unwrap(), &name(&self.component)?)?;
        if key(&current)? != key(&self.file)?
            || mount_id(&current)? != self.parent.volume.observation.runtime_mount_id
        {
            return Err(unsupported("held original private slot changed"));
        }
        if let Some(lease) = &self.lease {
            lease.verify()?;
        }
        Ok(())
    }

    /// A caller must verify before and after reading; no mandatory writer exclusion
    /// or stable content hash is inferred from this retained read-only descriptor.
    pub fn reader(&self) -> &File {
        &self.file
    }

    pub fn observation(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        key(&self.file)
    }
}

mod private_effects;
pub use private_effects::{OriginalCreateAllocationObservation, OriginalPrivateVolumeFile};

mod outside_intent;
pub use outside_intent::{OriginalOutsideIntent, OutsidePrivateIntentOwner};

mod outside_cleanup;
pub use outside_cleanup::{LinuxCleanupAbsenceObservation, LinuxOutsideCleanupBoundary};

mod private_replace;
pub use private_replace::OriginalRetainedVolumeFile;

mod frozen_binding;
pub use frozen_binding::{OriginalPairFrozenObservation, PreparedOriginalPairFreeze};

pub use private_effects::OriginalCreateVacatedObservation;

mod mount_observation;
pub use mount_observation::OriginalPrivateMountTopologyObservation;

mod exclusive_namespace;
pub use exclusive_namespace::{LinuxNamespaceCapability, LinuxNativeAttempt};
