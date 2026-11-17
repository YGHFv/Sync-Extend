//! SQLite's public VFS ABI. This avoids a second SQLite dependency/instance.
use std::ffi::{c_char, c_int, c_void};

pub const OK: c_int = 0;
pub const ERROR: c_int = 1;
pub const BUSY: c_int = 5;
pub const IOERR: c_int = 10;
pub const NOTFOUND: c_int = 12;
pub const FULL: c_int = 13;
pub const CANTOPEN: c_int = 14;
pub const IOERR_SHORT_READ: c_int = IOERR | (2 << 8);
pub const IOERR_WRITE: c_int = IOERR | (3 << 8);
pub const IOERR_TRUNCATE: c_int = IOERR | (6 << 8);
pub const OPEN_READWRITE: c_int = 2;
pub const OPEN_DELETEONCLOSE: c_int = 8;
pub const OPEN_MAIN_DB: c_int = 0x100;
pub const OPEN_MAIN_JOURNAL: c_int = 0x800;
pub const OPEN_WAL: c_int = 0x80000;
pub const SHM_UNLOCK: c_int = 1;
pub const SHM_LOCK: c_int = 2;
pub const SHM_SHARED: c_int = 4;
pub const SHM_EXCLUSIVE: c_int = 8;

#[repr(C)]
pub struct SqliteFile {
    pub methods: *const IoMethods,
}

#[repr(C)]
pub struct IoMethods {
    pub version: c_int,
    pub close: Option<unsafe extern "C" fn(*mut SqliteFile) -> c_int>,
    pub read: Option<unsafe extern "C" fn(*mut SqliteFile, *mut c_void, c_int, i64) -> c_int>,
    pub write: Option<unsafe extern "C" fn(*mut SqliteFile, *const c_void, c_int, i64) -> c_int>,
    pub truncate: Option<unsafe extern "C" fn(*mut SqliteFile, i64) -> c_int>,
    pub sync: Option<unsafe extern "C" fn(*mut SqliteFile, c_int) -> c_int>,
    pub size: Option<unsafe extern "C" fn(*mut SqliteFile, *mut i64) -> c_int>,
    pub lock: Option<unsafe extern "C" fn(*mut SqliteFile, c_int) -> c_int>,
    pub unlock: Option<unsafe extern "C" fn(*mut SqliteFile, c_int) -> c_int>,
    pub reserved: Option<unsafe extern "C" fn(*mut SqliteFile, *mut c_int) -> c_int>,
    pub control: Option<unsafe extern "C" fn(*mut SqliteFile, c_int, *mut c_void) -> c_int>,
    pub sector: Option<unsafe extern "C" fn(*mut SqliteFile) -> c_int>,
    pub characteristics: Option<unsafe extern "C" fn(*mut SqliteFile) -> c_int>,
    pub shm_map: Option<
        unsafe extern "C" fn(*mut SqliteFile, c_int, c_int, c_int, *mut *mut c_void) -> c_int,
    >,
    pub shm_lock: Option<unsafe extern "C" fn(*mut SqliteFile, c_int, c_int, c_int) -> c_int>,
    pub shm_barrier: Option<unsafe extern "C" fn(*mut SqliteFile)>,
    pub shm_unmap: Option<unsafe extern "C" fn(*mut SqliteFile, c_int) -> c_int>,
    pub fetch: Option<unsafe extern "C" fn(*mut SqliteFile, i64, c_int, *mut *mut c_void) -> c_int>,
    pub unfetch: Option<unsafe extern "C" fn(*mut SqliteFile, i64, *mut c_void) -> c_int>,
}

#[repr(C)]
pub struct Vfs {
    pub version: c_int,
    pub file_size: c_int,
    pub max_path: c_int,
    pub next: *mut Vfs,
    pub name: *const c_char,
    pub app: *mut c_void,
    pub open: Option<
        unsafe extern "C" fn(*mut Vfs, *const c_char, *mut SqliteFile, c_int, *mut c_int) -> c_int,
    >,
    pub delete: Option<unsafe extern "C" fn(*mut Vfs, *const c_char, c_int) -> c_int>,
    pub access: Option<unsafe extern "C" fn(*mut Vfs, *const c_char, c_int, *mut c_int) -> c_int>,
    pub full_path:
        Option<unsafe extern "C" fn(*mut Vfs, *const c_char, c_int, *mut c_char) -> c_int>,
    pub dl_open: Option<unsafe extern "C" fn(*mut Vfs, *const c_char) -> *mut c_void>,
    pub dl_error: Option<unsafe extern "C" fn(*mut Vfs, c_int, *mut c_char)>,
    pub dl_sym: Option<
        unsafe extern "C" fn(
            *mut Vfs,
            *mut c_void,
            *const c_char,
        ) -> Option<unsafe extern "C" fn()>,
    >,
    pub dl_close: Option<unsafe extern "C" fn(*mut Vfs, *mut c_void)>,
    pub randomness: Option<unsafe extern "C" fn(*mut Vfs, c_int, *mut c_char) -> c_int>,
    pub sleep: Option<unsafe extern "C" fn(*mut Vfs, c_int) -> c_int>,
    pub current_time: Option<unsafe extern "C" fn(*mut Vfs, *mut f64) -> c_int>,
    pub last_error: Option<unsafe extern "C" fn(*mut Vfs, c_int, *mut c_char) -> c_int>,
    pub current_time_int64: Option<unsafe extern "C" fn(*mut Vfs, *mut i64) -> c_int>,
    pub set_system_call: *const c_void,
    pub get_system_call: *const c_void,
    pub next_system_call: *const c_void,
}

extern "C" {
    pub fn sqlite3_vfs_register(vfs: *mut Vfs, make_default: c_int) -> c_int;
    pub fn sqlite3_vfs_unregister(vfs: *mut Vfs) -> c_int;
}
