//! Inspect a new cursor derived from the already-held directory descriptor.
use super::{close_file, mount_identity::mount_id, observe_fd, open_child, refuse};
use std::{ffi::{CStr, CString}, io, os::fd::{AsRawFd, FromRawFd, IntoRawFd}};

pub(super) fn require_empty(original: libc::c_int) -> io::Result<()> {
    let before = observe_fd(original)?;
    let original_mount = mount_id(original)?;
    let dot = CString::new(".").expect("fixed directory cursor component");
    let cursor = open_child(original, &dot, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let checked = (|| {
        if !observe_fd(cursor.as_raw_fd())?.same_object(before)
            || mount_id(cursor.as_raw_fd())? != original_mount
        { return Err(refuse("original deployment directory cursor differs")); }
        Ok(())
    })();
    if let Err(error) = checked {
        return match close_file(cursor) {
            Ok(()) => Err(error),
            Err(closed) => Err(io::Error::other(format!("{error}; original directory cursor close uncertain: {closed}"))),
        };
    }
    let descriptor = cursor.into_raw_fd();
    // SAFETY: fdopendir consumes this fresh owned cursor only on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: failed fdopendir did not consume the descriptor.
        let closed = close_file(unsafe { std::fs::File::from_raw_fd(descriptor) });
        return match closed {
            Ok(()) => Err(error),
            Err(closed) => Err(io::Error::other(format!("{error}; original directory cursor close uncertain: {closed}"))),
        };
    }
    let observed = (|| {
        loop {
            // SAFETY: this thread owns stream and its errno. Clearing errno
            // distinguishes a complete directory from a failed readdir.
            unsafe { *libc::__errno_location() = 0; }
            // SAFETY: stream remains open and is never shared or concurrently read.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) { Ok(()) } else { Err(error) };
            }
            // SAFETY: readdir returns a live dirent whose d_name is NUL terminated
            // until the next call. Only this bounded name is inspected.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                    "deployment runtime directory is occupied"));
            }
        }
    })();
    // SAFETY: this is the single closedir call for the owned directory stream;
    // its descriptor is consumed and never closed again by an integer retry.
    let closed = if unsafe { libc::closedir(stream) } == 0 { Ok(()) }
        else { Err(io::Error::last_os_error()) };
    match (observed, closed) {
        (Err(error), Err(closed)) => return Err(io::Error::other(format!("{error}; original directory stream close uncertain: {closed}"))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    if !observe_fd(original)?.same_object(before) || mount_id(original)? != original_mount {
        return Err(refuse("original deployment directory changed during enumeration"));
    }
    Ok(())
}
