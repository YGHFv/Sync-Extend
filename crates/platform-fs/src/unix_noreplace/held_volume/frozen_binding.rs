//! Retained original mount and pair diagnostic binding; no namespace certificate.
use super::{ext4, mount_id, private, HeldPrivateVolume, PrivateVolumeObservation};
use std::{fs::File, io, os::fd::AsRawFd};

pub struct PreparedOriginalPairFreeze<'v> {
    volume: &'v HeldPrivateVolume,
    original_mount: File,
}

pub struct OriginalPairFrozenObservation<'v> {
    volume: &'v HeldPrivateVolume,
    original_mount: File,
    observation: PrivateVolumeObservation,
}

impl HeldPrivateVolume {
    /// Duplicate the original root file object before original helper startup.
    pub fn prepare_original_pair_freeze(&self) -> io::Result<PreparedOriginalPairFreeze<'_>> {
        self.verify()?;
        let original_mount = self.root.file.try_clone()?;
        Ok(PreparedOriginalPairFreeze {
            volume: self,
            original_mount,
        })
    }
}

impl<'v> PreparedOriginalPairFreeze<'v> {
    pub fn original_mount(&self) -> &File {
        &self.original_mount
    }

    /// Diagnostic only. The original armed pair is verified before sync/freeze.
    /// No Drop thaw, restart adoption or native mutation permission is granted.
    pub fn freeze_for_original_pair_diagnostic(
        self,
        pair: &crate::OutsidePreparationPair,
    ) -> io::Result<OriginalPairFrozenObservation<'v>> {
        self.volume.verify()?;
        pair.verify_original_mount(&self.original_mount)?;
        private(&self.original_mount, true)?;
        ext4(&self.original_mount)?;
        // SAFETY: duplicate of original held local ext4 root, pointer-free syncfs.
        if unsafe { libc::syncfs(self.original_mount.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        pair.verify_original_mount(&self.original_mount)?;
        // SAFETY: original mount descriptor, fixed FIFREEZE request.
        if unsafe {
            libc::ioctl(
                self.original_mount.as_raw_fd(),
                0xc0045877_u32 as libc::Ioctl,
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let observation = self.volume.observation();
        let frozen = OriginalPairFrozenObservation {
            volume: self.volume,
            original_mount: self.original_mount,
            observation,
        };
        frozen.verify_original_binding(pair)?;
        Ok(frozen)
    }
}

impl OriginalPairFrozenObservation<'_> {
    pub fn verify_original_binding(&self, pair: &crate::OutsidePreparationPair) -> io::Result<()> {
        self.volume.verify()?;
        pair.verify_original_mount(&self.original_mount)?;
        if self.volume.observation() != self.observation
            || super::super::key(&self.original_mount)? != self.observation.root_key
            || mount_id(&self.original_mount)? != self.observation.runtime_mount_id
        {
            return Err(super::super::unsupported(
                "original frozen binding identity differs",
            ));
        }
        Ok(())
    }
    pub fn observation(&self) -> PrivateVolumeObservation {
        self.observation
    }
}
