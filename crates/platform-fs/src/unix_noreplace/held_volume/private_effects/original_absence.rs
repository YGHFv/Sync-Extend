//! Actual original CREATE source slot absence, descriptive evidence only.
use super::OriginalPrivateVolumeFile;
use crate::UnixFileKey;
use std::{io, os::fd::AsRawFd};

/// This borrows the exact original creator and retained parent.
/// No public constructor, Clone, Deserialize, unlink or cleanup method.
pub struct OriginalCreateVacatedObservation<'o, 'p, 'v> {
    creator: &'o OriginalPrivateVolumeFile<'p, 'v>,
    parent: UnixFileKey,
    original: UnixFileKey,
}

impl<'o, 'p, 'v> OriginalPrivateVolumeFile<'p, 'v> {
    pub fn observe_original_create_slot_absence(
        &'o self,
    ) -> io::Result<OriginalCreateVacatedObservation<'o, 'p, 'v>> {
        self.verify_created_slot_absent()?;
        Ok(OriginalCreateVacatedObservation {
            creator: self,
            parent: self.original_parent_key()?,
            original: self.original_key()?,
        })
    }

    fn verify_created_slot_absent(&self) -> io::Result<()> {
        self.verify()?;
        if self.created_component() == self.current_component {
            return Err(super::super::super::unsupported(
                "original CREATE name has not vacated",
            ));
        }
        let parent = self.parent.parents.last().ok_or_else(|| {
            super::super::super::unsupported("original vacated retained parent absent")
        })?;
        let component = super::super::super::name(self.created_component())?;
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: retained original directory, terminated bounded single name,
        // correctly sized writable stat output, no-follow inspects every type.
        let code = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                component.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if code == 0 {
            return Err(super::super::super::unsupported(
                "foreign occupant in original vacated slot",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error);
        }
        self.verify()
    }
}

impl OriginalCreateVacatedObservation<'_, '_, '_> {
    pub fn verify(&self) -> io::Result<()> {
        self.creator.verify_created_slot_absent()?;
        if self.creator.original_key()? != self.original
            || self.creator.original_parent_key()? != self.parent
        {
            return Err(super::super::super::unsupported(
                "original absence parent or CREATE key differs",
            ));
        }
        Ok(())
    }
    pub fn original_key(&self) -> UnixFileKey {
        self.original
    }
    pub fn parent_key(&self) -> UnixFileKey {
        self.parent
    }
}
