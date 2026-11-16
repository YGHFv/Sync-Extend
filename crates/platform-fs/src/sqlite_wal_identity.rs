//! Observe SQLite's actual WAL native object, never a same-name path reopened as ownership.
use crate::FileKey;
use std::{fs::File, io, os::windows::io::FromRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE},
    System::Threading::GetCurrentProcess,
};

/// Requires a currently open WAL owned by this live connection. A rollback
/// journal, absent methods or unavailable Windows opcode is an explicit refusal.
pub fn sqlite_wal_file_identity(database: &rusqlite::Connection) -> io::Result<FileKey> {
    let mode: String = database
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| io::Error::other("actual SQLite WAL mode unavailable"))?;
    if mode != "wal" {
        return Err(io::Error::other("actual WAL connection required"));
    }
    let mut journal: *mut rusqlite::ffi::sqlite3_file = ptr::null_mut();
    // SAFETY: live borrowed Connection, documented JOURNAL_POINTER output slot.
    // No caller supplies or receives a raw pointer; connection retains the file.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            database.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_JOURNAL_POINTER,
            ptr::from_mut(&mut journal).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || journal.is_null() {
        return Err(io::Error::other("actual SQLite WAL file unavailable"));
    }
    // SAFETY: successful file control returned a connection-owned sqlite3_file
    // valid for this synchronous borrow; pMethods may be null on unopened WAL.
    let methods = unsafe { (*journal).pMethods };
    if methods.is_null() {
        return Err(io::Error::other("actual SQLite WAL is not open"));
    }
    // SAFETY: this live SQLite file's methods table belongs to its installed VFS.
    let control = unsafe { (*methods).xFileControl }
        .ok_or_else(|| io::Error::other("actual WAL file control unavailable"))?;
    let mut borrowed: HANDLE = ptr::null_mut();
    // SAFETY: call this actual live WAL VFS method with documented Windows HANDLE
    // output. SQLITE_NOTFOUND refuses non-Windows/non-native VFS implementations.
    let status = unsafe {
        control(
            journal,
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            ptr::from_mut(&mut borrowed).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || borrowed.is_null() || borrowed == INVALID_HANDLE_VALUE
    {
        return Err(io::Error::other(
            "actual SQLite WAL native handle unavailable",
        ));
    }
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: SQLite retains the borrowed original for this whole call; create
    // one local owned duplicate solely for type/link/key observation.
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
        return Err(io::Error::other("actual WAL handle duplicate absent"));
    }
    // SAFETY: successful DuplicateHandle transfers one newly owned native handle.
    let file = unsafe { File::from_raw_handle(duplicate) };
    super::verify_regular_file(&file)?;
    FileKey::from_file(&file)
}
