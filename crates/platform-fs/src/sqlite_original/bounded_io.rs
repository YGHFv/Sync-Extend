//! Per-file original SQLite IO adapter; every write/truncate respects pre-admitted physical bounds.
use rusqlite::ffi;
use std::{
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

#[repr(C)]
pub(super) struct OriginalIo {
    header: ffi::sqlite3_file,
    original: *mut ffi::sqlite3_file,
    methods: *const ffi::sqlite3_io_methods,
    limit: u64,
    poisoned: *const AtomicBool,
    retained_close: bool,
    original_logical_terminal: *const AtomicBool,
}

unsafe fn owner<'a>(file: *mut ffi::sqlite3_file) -> &'a OriginalIo {
    // SAFETY: only our xOpen installs METHODS on a correctly aligned OriginalIo.
    unsafe { &*file.cast::<OriginalIo>() }
}
unsafe fn fail(file: *mut ffi::sqlite3_file) -> i32 {
    // SAFETY: callback receives initialized OriginalIo with retained Policy atomic.
    let state = unsafe { owner(file) };
    // SAFETY: Policy outlives every open original IO file in this connection.
    unsafe {
        (*state.poisoned).store(true, Ordering::SeqCst);
    }
    ffi::SQLITE_FULL
}
pub(super) unsafe fn install(
    outer: *mut ffi::sqlite3_file,
    original: *mut ffi::sqlite3_file,
    limit: u64,
    poisoned: *const AtomicBool,
    retained_close: bool,
    original_logical_terminal: *const AtomicBool,
) {
    // SAFETY: caller allocated aligned outer storage sized OriginalIo and base
    // SQLite file and successfully initialized base's original method table.
    unsafe {
        ptr::write(
            outer.cast::<OriginalIo>(),
            OriginalIo {
                header: ffi::sqlite3_file { pMethods: &METHODS },
                original,
                methods: (*original).pMethods,
                limit,
                poisoned,
                retained_close,
                original_logical_terminal,
            },
        );
    }
}
unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> i32 {
    // SAFETY: live initialized original IO wrapper.
    let state = unsafe { owner(file) };
    if state.retained_close {
        // The exact builtin object is owned by Policy; logical SQLite close
        // cannot create a native sharing gap or free the owned filename.
        if !state.original_logical_terminal.is_null() {
            // SAFETY: the stable original owning IO retains this boxed atomic
            // until every SQLite wrapper has ended its original native loan.
            unsafe {
                (*state.original_logical_terminal).store(true, Ordering::SeqCst);
            }
        }
        return ffi::SQLITE_OK;
    }
    // SAFETY: retained base method table and original file initialized in xOpen.
    match unsafe { (*state.methods).xClose } {
        // SAFETY: this original base file is closed once by SQLite.
        Some(method) => unsafe { method(state.original) },
        None => ffi::SQLITE_IOERR_CLOSE,
    }
}
unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    out: *mut std::ffi::c_void,
    n: i32,
    offset: i64,
) -> i32 {
    if n < 0 || offset < 0 {
        return ffi::SQLITE_IOERR_READ;
    }
    // SAFETY: initialized SQLite original IO wrapper.
    let state = unsafe { owner(file) };
    if (offset as u64)
        .checked_add(n as u64)
        .is_none_or(|end| end > state.limit)
    {
        // SAFETY: SQLite output buffer is writable for exactly n bytes; short read contract zero-fills.
        unsafe {
            ptr::write_bytes(out.cast::<u8>(), 0, n as usize);
        }
        return ffi::SQLITE_IOERR_SHORT_READ;
    }
    // SAFETY: base table and file initialized by builtin xOpen.
    match unsafe { (*state.methods).xRead } {
        // SAFETY: unchanged SQLite read buffer/count/offset to actual retained original.
        Some(method) => unsafe { method(state.original, out, n, offset) },
        None => ffi::SQLITE_IOERR_READ,
    }
}
unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    input: *const std::ffi::c_void,
    n: i32,
    offset: i64,
) -> i32 {
    // SAFETY: initialized owned IO wrapper.
    let state = unsafe { owner(file) };
    if n < 0
        || offset < 0
        || (offset as u64)
            .checked_add(n as u64)
            .is_none_or(|end| end > state.limit)
    {
        // SAFETY: this live wrapper retains its policy atomic.
        return unsafe { fail(file) };
    }
    // SAFETY: retained base method table.
    match unsafe { (*state.methods).xWrite } {
        // SAFETY: original SQLite supplied write bytes forwarded only after before-IO bounds.
        Some(method) => unsafe { method(state.original, input, n, offset) },
        None => ffi::SQLITE_IOERR_WRITE,
    }
}
unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> i32 {
    // SAFETY: SQLite callback on initialized IO wrapper.
    let state = unsafe { owner(file) };
    if size < 0 || size as u64 > state.limit {
        // SAFETY: live wrapper owns retained policy atomic.
        return unsafe { fail(file) };
    }
    // SAFETY: builtin initialized base table.
    match unsafe { (*state.methods).xTruncate } {
        // SAFETY: only actual original file, size checked before effect.
        Some(method) => unsafe { method(state.original, size) },
        None => ffi::SQLITE_IOERR_TRUNCATE,
    }
}
unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, flags: i32) -> i32 {
    // SAFETY: initialized original IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: actual retained base table.
    match unsafe { (*state.methods).xSync } {
        // SAFETY: unchanged sync flags to real original file.
        Some(method) => unsafe { method(state.original, flags) },
        None => ffi::SQLITE_IOERR_FSYNC,
    }
}
unsafe extern "C" fn size(file: *mut ffi::sqlite3_file, out: *mut i64) -> i32 {
    // SAFETY: live IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: original base table.
    match unsafe { (*state.methods).xFileSize } {
        // SAFETY: unchanged SQLite sized output pointer.
        Some(method) => unsafe { method(state.original, out) },
        None => ffi::SQLITE_IOERR_FSTAT,
    }
}
unsafe extern "C" fn lock(file: *mut ffi::sqlite3_file, level: i32) -> i32 {
    // SAFETY: live initialized IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: actual base file method table.
    match unsafe { (*state.methods).xLock } {
        // SAFETY: unchanged original SQLite lock level.
        Some(method) => unsafe { method(state.original, level) },
        None => ffi::SQLITE_IOERR_LOCK,
    }
}
unsafe extern "C" fn unlock(file: *mut ffi::sqlite3_file, level: i32) -> i32 {
    // SAFETY: live IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: retained original method table.
    match unsafe { (*state.methods).xUnlock } {
        // SAFETY: original SQLite unlock request targets same native file.
        Some(method) => unsafe { method(state.original, level) },
        None => ffi::SQLITE_IOERR_UNLOCK,
    }
}
unsafe extern "C" fn reserved(file: *mut ffi::sqlite3_file, out: *mut i32) -> i32 {
    // SAFETY: initialized owned IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: builtin original table.
    match unsafe { (*state.methods).xCheckReservedLock } {
        // SAFETY: SQLite sized reserved-lock output.
        Some(method) => unsafe { method(state.original, out) },
        None => ffi::SQLITE_IOERR_CHECKRESERVEDLOCK,
    }
}
unsafe extern "C" fn control(
    file: *mut ffi::sqlite3_file,
    opcode: i32,
    arg: *mut std::ffi::c_void,
) -> i32 {
    // Hints and arbitrary VFS file controls may extend or remap a file outside xWrite.
    // Allow only documented non-mutating observations, configured persist-WAL,
    // and SQLite-owned phase notifications; all other controls explicitly refuse.
    if !matches!(
        opcode,
        ffi::SQLITE_FCNTL_WIN32_GET_HANDLE
            | ffi::SQLITE_FCNTL_PERSIST_WAL
            | ffi::SQLITE_FCNTL_LOCKSTATE
            | ffi::SQLITE_FCNTL_LAST_ERRNO
            | ffi::SQLITE_FCNTL_VFSNAME
            | ffi::SQLITE_FCNTL_PRAGMA
            | ffi::SQLITE_FCNTL_COMMIT_PHASETWO
    ) {
        return ffi::SQLITE_NOTFOUND;
    }
    // SAFETY: initialized original IO wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: actual retained base table.
    match unsafe { (*state.methods).xFileControl } {
        // SAFETY: documented opcode argument comes directly from SQLite.
        Some(method) => unsafe { method(state.original, opcode, arg) },
        None => ffi::SQLITE_NOTFOUND,
    }
}
unsafe extern "C" fn sector(file: *mut ffi::sqlite3_file) -> i32 {
    // SAFETY: initialized wrapper with retained original table.
    let state = unsafe { owner(file) };
    // SAFETY: base table owns this live file.
    match unsafe { (*state.methods).xSectorSize } {
        // SAFETY: pointer-free original sector observation.
        Some(method) => unsafe { method(state.original) },
        None => 512,
    }
}
unsafe extern "C" fn characteristics(file: *mut ffi::sqlite3_file) -> i32 {
    // SAFETY: initialized wrapper.
    let state = unsafe { owner(file) };
    // SAFETY: actual retained base table.
    match unsafe { (*state.methods).xDeviceCharacteristics } {
        // SAFETY: pointer-free actual device observation.
        Some(method) => unsafe { method(state.original) },
        None => 0,
    }
}
unsafe extern "C" fn shm_map(
    file: *mut ffi::sqlite3_file,
    _page: i32,
    _size: i32,
    _extend: i32,
    out: *mut *mut std::ffi::c_void,
) -> i32 {
    if !out.is_null() {
        // SAFETY: SQLite supplied one sized shared-memory pointer output.
        unsafe {
            *out = ptr::null_mut();
        }
    }
    // SAFETY: original IO callback retains its actual policy; reject SHM before mapping.
    unsafe { fail(file) };
    ffi::SQLITE_IOERR_SHMMAP
}
unsafe extern "C" fn shm_lock(
    file: *mut ffi::sqlite3_file,
    _offset: i32,
    _n: i32,
    _flags: i32,
) -> i32 {
    // SAFETY: initialized original IO wrapper, reject foreign shared-memory effects.
    unsafe { fail(file) };
    ffi::SQLITE_IOERR_SHMLOCK
}
unsafe extern "C" fn shm_barrier(_file: *mut ffi::sqlite3_file) {}
unsafe extern "C" fn shm_unmap(file: *mut ffi::sqlite3_file, _delete: i32) -> i32 {
    // SAFETY: initialized IO wrapper, no SHM object has ever been created.
    unsafe { fail(file) };
    ffi::SQLITE_IOERR_SHMOPEN
}

pub(super) static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(size),
    xLock: Some(lock),
    xUnlock: Some(unlock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(control),
    xSectorSize: Some(sector),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: Some(shm_map),
    xShmLock: Some(shm_lock),
    xShmBarrier: Some(shm_barrier),
    xShmUnmap: Some(shm_unmap),
    xFetch: None,
    xUnfetch: None,
};
