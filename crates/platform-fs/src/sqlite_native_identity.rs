//! Identify SQLite's actual main file handle; never infer it from a second path open.
use crate::FileKey;
use std::{fs::File, io, os::windows::io::FromRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE},
    System::Threading::GetCurrentProcess,
};

/// Safe wrapper belongs to the narrow platform crate, with an explicit Windows
/// rusqlite dependency. The original Connection owns the queried handle throughout.
/// The duplicate is observation only; it is not returned as a writable capability.
pub fn sqlite_main_file_identity(database: &rusqlite::Connection) -> io::Result<FileKey> {
    let mut borrowed: HANDLE = ptr::null_mut();
    // SAFETY: Connection is live and borrowed exclusively by this synchronous
    // call; the documented opcode interprets arg as a native HANDLE output.
    // No caller supplies a raw SQLite pointer and SQLite retains handle ownership.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            database.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            ptr::from_mut(&mut borrowed).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || borrowed.is_null() || borrowed == INVALID_HANDLE_VALUE
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "actual SQLite Windows main native handle unavailable",
        ));
    }
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: borrowed is the live database-owned handle just returned by SQLite.
    // DuplicateHandle creates one independent handle owned by this call; the
    // original Connection and its file object remain live until after key audit.
    let success = unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            borrowed,
            process,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SQLite duplicate handle absent",
        ));
    }
    // SAFETY: successful DuplicateHandle transferred exactly one new native handle.
    let actual = unsafe { File::from_raw_handle(duplicate) };
    super::verify_regular_file(&actual)?;
    FileKey::from_file(&actual)
}
