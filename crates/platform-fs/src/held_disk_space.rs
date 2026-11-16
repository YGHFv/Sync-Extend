//! Query actual local volume space while its original directory remains held.
use crate::LockedDirectory;
use std::{io, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDiskFreeSpaceW};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldDiskSpace {
    pub available_to_caller: u64,
    pub allocation_unit: u64,
}

pub fn held_disk_space(held: &LockedDirectory, path: &Path) -> io::Result<HeldDiskSpace> {
    if !path.is_absolute() || !held.matches_path(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original held disk-space root differs",
        ));
    }
    held.require_local_ntfs(path)?;
    let directory: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let root = path
        .ancestors()
        .last()
        .ok_or_else(|| io::Error::other("volume root missing"))?;
    let mut root: Vec<u16> = root.as_os_str().encode_wide().collect();
    if root.last() != Some(&(b'\\' as u16)) {
        root.push(b'\\' as u16);
    }
    root.push(0);
    let (mut available, mut total, mut free) = (0, 0, 0);
    let (mut sectors, mut bytes, mut free_clusters, mut total_clusters) = (0, 0, 0, 0);
    // SAFETY: both path buffers are NUL terminated and retained through each call;
    // output pointers reference initialized writable local integers of the required types.
    let space =
        unsafe { GetDiskFreeSpaceExW(directory.as_ptr(), &mut available, &mut total, &mut free) };
    if space == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the original local volume's absolute root buffer is NUL terminated;
    // all output parameters point to live writable u32 values.
    let geometry = unsafe {
        GetDiskFreeSpaceW(
            root.as_ptr(),
            &mut sectors,
            &mut bytes,
            &mut free_clusters,
            &mut total_clusters,
        )
    };
    if geometry == 0 {
        return Err(io::Error::last_os_error());
    }
    if !held.matches_path(path)? {
        return Err(io::Error::other("held volume root changed during query"));
    }
    let allocation_unit = u64::from(sectors)
        .checked_mul(u64::from(bytes))
        .filter(|unit| *unit != 0)
        .ok_or_else(|| io::Error::other("invalid actual volume allocation unit"))?;
    Ok(HeldDiskSpace {
        available_to_caller: available,
        allocation_unit,
    })
}
