//! Kernel mount identity observed through the actual descriptor, never a path.
use super::refuse;
use std::{ffi::CString, io, mem::MaybeUninit, os::fd::RawFd};

pub(super) fn mount_id(descriptor: RawFd) -> io::Result<u64> {
    let empty = CString::new("").expect("fixed empty descriptor path");
    observe(descriptor, &empty, libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)
}

pub(super) fn slot_mount_id(parent: RawFd, component: &std::ffi::CStr) -> io::Result<u64> {
    observe(parent, component, libc::AT_SYMLINK_NOFOLLOW)
}

fn observe(descriptor: RawFd, component: &std::ffi::CStr, flags: i32) -> io::Result<u64> {
    let mut observed = MaybeUninit::<libc::statx>::uninit();
    // SAFETY: descriptor is borrowed from an owned live FD. AT_EMPTY_PATH binds
    // the query to that FD; statx initializes the supplied structure on success.
    if unsafe { libc::statx(descriptor, component.as_ptr(), flags,
        libc::STATX_MNT_ID, observed.as_mut_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful statx call initialized the complete output.
    let observed = unsafe { observed.assume_init() };
    if observed.stx_mask & libc::STATX_MNT_ID == 0 || observed.stx_mnt_id == 0 {
        return Err(refuse("original Unix deployment mount identity unavailable"));
    }
    Ok(observed.stx_mnt_id)
}
