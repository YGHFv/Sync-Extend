//! Exact main bytes read only from SQLite's currently held actual native file.
use crate::FileKey;
use std::{
    fs::File,
    io,
    os::windows::{fs::FileExt, io::FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE},
    System::Threading::GetCurrentProcess,
};

pub fn sqlite_main_exact_bytes(
    database: &rusqlite::Connection,
    max_bytes: u64,
) -> io::Result<(FileKey, Vec<u8>)> {
    if !(512..=256 * 1024 * 1024).contains(&max_bytes) {
        return Err(io::Error::other(
            "bounded actual SQLite main byte observation required",
        ));
    }
    let mut borrowed: HANDLE = ptr::null_mut();
    // SAFETY: documented output HANDLE for live exclusively borrowed connection.
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
        return Err(io::Error::other(
            "actual SQLite main native handle unavailable",
        ));
    }
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: actual connection owns borrowed for the entire synchronous call;
    // duplicate has exactly one local File owner and never escapes as capability.
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
        return Err(io::Error::other("actual main handle duplicate absent"));
    }
    // SAFETY: successful DuplicateHandle transfers one newly owned native handle.
    let file = unsafe { File::from_raw_handle(duplicate) };
    super::verify_regular_file(&file)?;
    let key = FileKey::from_file(&file)?;
    let length = file.metadata()?.len();
    if length < 512 || length > max_bytes {
        return Err(io::Error::other("actual main image byte bound"));
    }
    let mut bytes = vec![0u8; length as usize];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let count = file.seek_read(&mut bytes[offset..], offset as u64)?;
        if count == 0 {
            return Err(io::Error::other("actual main image short read"));
        }
        offset = offset
            .checked_add(count)
            .ok_or_else(|| io::Error::other("actual main read overflow"))?;
    }
    if FileKey::from_file(&file)? != key || file.metadata()?.len() != length {
        return Err(io::Error::other(
            "actual SQLite main changed during byte observation",
        ));
    }
    Ok((key, bytes))
}

/// Preserve this explicitly owned WAL on last connection close/checkpoint.
pub fn sqlite_retain_actual_wal(database: &rusqlite::Connection) -> io::Result<()> {
    let mut enabled: std::ffi::c_int = 1;
    // SAFETY: documented integer input/output opcode on this live main VFS file.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            database.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            ptr::from_mut(&mut enabled).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || enabled != 1 {
        return Err(io::Error::other(
            "actual persistent owned WAL setting refused",
        ));
    }
    Ok(())
}
