//! SQLite uses freshly acquired exclusive handles without any path reopen.
use super::{FileKey, FreshExclusiveSqliteFile};
use rusqlite::ffi;
use std::{
    ffi::{CStr, CString},
    io,
    os::windows::fs::FileExt,
    ptr,
    rc::Rc,
};

struct Policy {
    files: [FreshExclusiveSqliteFile; 4],
    names: [CString; 4],
    limits: [u64; 4],
    poisoned: std::cell::Cell<bool>,
    shm: std::cell::RefCell<Option<ShmMapping>>,
    shm_lock_bits: std::cell::Cell<u8>,
}
#[repr(C)]
struct NativeIo {
    header: ffi::sqlite3_file,
    policy: *const Policy,
    index: usize,
    readonly: bool,
}
unsafe fn state<'a>(file: *mut ffi::sqlite3_file) -> (&'a Policy, usize) {
    // SAFETY: only successful xOpen installs NativeIo in advertised sized storage.
    let value = unsafe { &*file.cast::<NativeIo>() };
    // SAFETY: registered owner retains policy until its connection closes.
    (unsafe { &*value.policy }, value.index)
}
unsafe fn policy<'a>(vfs: *mut ffi::sqlite3_vfs) -> &'a Policy {
    // SAFETY: our registered table stores the retained policy pointer.
    unsafe { &*((*vfs).pAppData.cast::<Policy>()) }
}
fn normalized(value: &CStr) -> Vec<u8> {
    value
        .to_bytes()
        .iter()
        .map(|byte| {
            if *byte == b'/' {
                b'\\'
            } else {
                byte.to_ascii_lowercase()
            }
        })
        .collect()
}
unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out: *mut i32,
) -> i32 {
    if vfs.is_null() || name.is_null() || file.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: callback table and terminated SQLite filename are live.
    let owner = unsafe { policy(vfs) };
    // SAFETY: SQLite supplies a terminated filename valid for the callback.
    let name = unsafe { CStr::from_ptr(name) };
    let kind =
        flags & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_MAIN_JOURNAL | ffi::SQLITE_OPEN_WAL);
    let index = if kind == ffi::SQLITE_OPEN_MAIN_DB {
        0
    } else if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL {
        2
    } else if kind == ffi::SQLITE_OPEN_WAL {
        1
    } else {
        owner.poisoned.set(true);
        return ffi::SQLITE_CANTOPEN;
    };
    if owner.poisoned.get()
        || normalized(name) != normalized(&owner.names[index])
        || flags & (ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_READONLY) == 0
        || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0
        || owner.files[index].verify().is_err()
    {
        owner.poisoned.set(true);
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: SQLite allocated advertised NativeIo size/alignment; the policy
    // remains live. No base xOpen, CREATE, path resolution or handle release occurs.
    unsafe {
        ptr::write(
            file.cast::<NativeIo>(),
            NativeIo {
                header: ffi::sqlite3_file { pMethods: &METHODS },
                policy: owner,
                index,
                readonly: flags & ffi::SQLITE_OPEN_READONLY != 0,
            },
        );
        if !out.is_null() {
            *out = flags & (ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_READONLY);
        }
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn close(_file: *mut ffi::sqlite3_file) -> i32 {
    ffi::SQLITE_OK
}
unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    out: *mut std::ffi::c_void,
    count: i32,
    offset: i64,
) -> i32 {
    if out.is_null() || count < 0 || offset < 0 {
        return ffi::SQLITE_IOERR_READ;
    }
    // SAFETY: live initialized NativeIo; SQLite output is writable for count bytes.
    let (owner, index) = unsafe { state(file) };
    // SAFETY: SQLite's output buffer length is exactly count.
    let bytes = unsafe { std::slice::from_raw_parts_mut(out.cast::<u8>(), count as usize) };
    if (offset as u64)
        .checked_add(count as u64)
        .is_none_or(|end| end > owner.limits[index])
    {
        bytes.fill(0);
        return ffi::SQLITE_IOERR_SHORT_READ;
    }
    let mut done = 0;
    while done < bytes.len() {
        match owner.files[index]
            .native_file()
            .seek_read(&mut bytes[done..], offset as u64 + done as u64)
        {
            Ok(0) => {
                bytes[done..].fill(0);
                return ffi::SQLITE_IOERR_SHORT_READ;
            }
            Ok(value) => done += value,
            Err(_) => return ffi::SQLITE_IOERR_READ,
        }
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    input: *const std::ffi::c_void,
    count: i32,
    offset: i64,
) -> i32 {
    if input.is_null() || count < 0 || offset < 0 {
        return ffi::SQLITE_IOERR_WRITE;
    }
    // SAFETY: initialized IO and SQLite input is readable for count bytes.
    let (owner, index) = unsafe { state(file) };
    // SAFETY: initialized NativeIo carries this logical SQLite open's access mode.
    if unsafe { &*file.cast::<NativeIo>() }.readonly {
        return ffi::SQLITE_READONLY;
    }
    if owner.poisoned.get()
        || (offset as u64)
            .checked_add(count as u64)
            .is_none_or(|end| end > owner.limits[index])
    {
        owner.poisoned.set(true);
        return ffi::SQLITE_FULL;
    }
    // SAFETY: SQLite provides exactly count bytes of input.
    let bytes = unsafe { std::slice::from_raw_parts(input.cast::<u8>(), count as usize) };
    let mut done = 0;
    while done < bytes.len() {
        match owner.files[index]
            .native_file()
            .seek_write(&bytes[done..], offset as u64 + done as u64)
        {
            Ok(0) => {
                owner.poisoned.set(true);
                return ffi::SQLITE_IOERR_WRITE;
            }
            Ok(value) => done += value,
            Err(error) => {
                owner.poisoned.set(true);
                return if matches!(error.raw_os_error(), Some(39 | 112)) {
                    ffi::SQLITE_FULL
                } else {
                    ffi::SQLITE_IOERR_WRITE
                };
            }
        }
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, length: i64) -> i32 {
    // SAFETY: initialized IO points at retained actual file.
    let (owner, index) = unsafe { state(file) };
    // SAFETY: initialized wrapper records the actual logical open mode.
    if unsafe { &*file.cast::<NativeIo>() }.readonly {
        return ffi::SQLITE_READONLY;
    }
    if length < 0 || length as u64 > owner.limits[index] {
        owner.poisoned.set(true);
        return ffi::SQLITE_FULL;
    }
    match owner.files[index].native_file().set_len(length as u64) {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            owner.poisoned.set(true);
            ffi::SQLITE_IOERR_TRUNCATE
        }
    }
}
unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _flags: i32) -> i32 {
    // SAFETY: initialized retained actual IO file.
    let (owner, index) = unsafe { state(file) };
    match owner.files[index].native_file().sync_all() {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            owner.poisoned.set(true);
            ffi::SQLITE_IOERR_FSYNC
        }
    }
}
unsafe extern "C" fn size(file: *mut ffi::sqlite3_file, out: *mut i64) -> i32 {
    if out.is_null() {
        return ffi::SQLITE_IOERR_FSTAT;
    }
    // SAFETY: initialized NativeIo.
    let (owner, index) = unsafe { state(file) };
    match owner.files[index].native_file().metadata() {
        Ok(metadata) if metadata.len() <= owner.limits[index] => {
            // SAFETY: SQLite supplied one writable int64.
            unsafe {
                *out = metadata.len() as i64;
            }
            ffi::SQLITE_OK
        }
        _ => ffi::SQLITE_IOERR_FSTAT,
    }
}
unsafe extern "C" fn lock(file: *mut ffi::sqlite3_file, _level: i32) -> i32 {
    // SAFETY: share0 native object remains continuously retained and verified.
    let (owner, index) = unsafe { state(file) };
    if owner.files[index].verify().is_ok() {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_LOCK
    }
}
unsafe extern "C" fn reserved(file: *mut ffi::sqlite3_file, out: *mut i32) -> i32 {
    if out.is_null() {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    // SAFETY: live NativeIo and writable scalar output.
    let (owner, index) = unsafe { state(file) };
    if owner.files[index].verify().is_err() {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    // SAFETY: native exclusivity already excludes other connections.
    unsafe {
        *out = 0;
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn control(
    _file: *mut ffi::sqlite3_file,
    _opcode: i32,
    _arg: *mut std::ffi::c_void,
) -> i32 {
    ffi::SQLITE_NOTFOUND
}
unsafe extern "C" fn sector(_file: *mut ffi::sqlite3_file) -> i32 {
    4096
}
unsafe extern "C" fn characteristics(_file: *mut ffi::sqlite3_file) -> i32 {
    0
}
static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(size),
    xLock: Some(lock),
    xUnlock: Some(lock),
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
unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    flags: i32,
    out: *mut i32,
) -> i32 {
    if vfs.is_null() || name.is_null() || out.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: registered policy and terminated filename are valid for callback.
    let owner = unsafe { policy(vfs) };
    // SAFETY: SQLite supplies a terminated filename.
    let name = unsafe { CStr::from_ptr(name) };
    let found = owner
        .names
        .iter()
        .position(|expected| normalized(name) == normalized(expected));
    // SAFETY: output points to one SQLite-owned int.
    let exists = match found {
        Some(index) => match owner.files[index].native_file().metadata() {
            Ok(metadata) => flags != ffi::SQLITE_ACCESS_EXISTS || metadata.len() != 0,
            Err(_) => return ffi::SQLITE_IOERR_ACCESS,
        },
        None => false,
    };
    // SAFETY: SQLite supplied one writable scalar; zero-size EXISTS follows the builtin Windows VFS.
    unsafe {
        *out = i32::from(exists);
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    _sync: i32,
) -> i32 {
    if vfs.is_null() || name.is_null() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SAFETY: registered policy and SQLite's terminated filename are live.
    let owner = unsafe { policy(vfs) };
    // SAFETY: SQLite supplies a terminated name valid for this callback.
    let name = unsafe { CStr::from_ptr(name) };
    let index = match owner
        .names
        .iter()
        .position(|expected| normalized(name) == normalized(expected))
    {
        Some(index @ (1 | 2)) => index,
        _ => {
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_DELETE;
        }
    };
    // Invalidate only held actual WAL/rollback objects, never delete namespace slots.
    match owner.files[index]
        .native_file()
        .set_len(0)
        .and_then(|()| owner.files[index].native_file().sync_all())
    {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            owner.poisoned.set(true);
            ffi::SQLITE_IOERR_DELETE
        }
    }
}
unsafe extern "C" fn full_path(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    count: i32,
    out: *mut std::ffi::c_char,
) -> i32 {
    if vfs.is_null() || name.is_null() || out.is_null() || count <= 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: callback owns valid policy and SQLite terminated filename.
    let owner = unsafe { policy(vfs) };
    // SAFETY: SQLite supplies valid terminated filename.
    let name = unsafe { CStr::from_ptr(name) };
    if normalized(name) != normalized(&owner.names[0])
        || name.to_bytes_with_nul().len() > count as usize
    {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: checked output capacity includes terminating null; buffers do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(name.as_ptr(), out, name.to_bytes_with_nul().len());
    }
    ffi::SQLITE_OK
}
pub struct FreshNativeWalConnection {
    connection: Option<rusqlite::Connection>,
    registration: Box<ffi::sqlite3_vfs>,
    name: CString,
    policy: Rc<Policy>,
    path: std::path::PathBuf,
    attempted: bool,
}

/// A live, non-serializable issuer retains the original four native handles.
/// Persisted file keys and readonly catalogues cannot construct this object.
pub struct FreshNativeRetentionLease {
    policy: Rc<Policy>,
    keys: [FileKey; 4],
    generation: u32,
}

impl FreshNativeRetentionLease {
    pub fn native_keys(&self) -> [FileKey; 4] {
        self.keys
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
}
impl FreshNativeWalConnection {
    pub fn open(
        path: &std::path::Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
    ) -> io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().and_then(|v| v.to_str()) != Some("journal.sqlite")
            || limits
                .iter()
                .any(|n| !(512..=256 * 1024 * 1024).contains(n))
            || limits.iter().sum::<u64>() > 512 * 1024 * 1024
            || limits[3] != 1024 * 1024
        {
            return Err(io::Error::other(
                "fresh native WAL SQLite exact path/bounds",
            ));
        }
        let text = path
            .to_str()
            .ok_or_else(|| io::Error::other("fresh native WAL SQLite path encoding"))?;
        let names = [
            CString::new(text),
            CString::new(format!("{text}-wal")),
            CString::new(format!("{text}-journal")),
            CString::new(format!("{text}-shm")),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
        let names: [CString; 4] = names
            .try_into()
            .map_err(|_| io::Error::other("fresh native WAL SQLite names"))?;
        for (index, file) in files.iter().enumerate() {
            file.verify()?;
            if !file.matches_path(std::path::Path::new(
                names[index].to_str().map_err(io::Error::other)?,
            ))? || file.parent_key()? != files[0].parent_key()?
                || file.exact_bytes(limits[index])?.len() as u64 > limits[index]
            {
                return Err(io::Error::other(
                    "fresh native WAL SQLite current file differs",
                ));
            }
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if id == u64::MAX {
            return Err(io::Error::other(
                "fresh native WAL SQLite registration exhausted",
            ));
        }
        let name = CString::new(format!("sync-fresh-native-{}-{id}", std::process::id()))
            .map_err(io::Error::other)?;
        // SAFETY: builtin VFS is process-lifetime; copying leaves time/randomness callbacks intact.
        let base = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
        if base.is_null() {
            return Err(io::Error::other("builtin VFS absent"));
        }
        // SAFETY: base points to SQLite's initialized process-lifetime VFS table.
        let mut registration = Box::new(unsafe { *base });
        let policy = Rc::new(Policy {
            files,
            names,
            limits,
            poisoned: std::cell::Cell::new(false),
            shm: std::cell::RefCell::new(None),
            shm_lock_bits: std::cell::Cell::new(0),
        });
        registration.pNext = ptr::null_mut();
        registration.zName = name.as_ptr();
        registration.pAppData = Rc::as_ptr(&policy).cast_mut().cast();
        registration.szOsFile = std::mem::size_of::<NativeIo>() as i32;
        registration.xOpen = Some(open);
        registration.xDelete = Some(delete);
        registration.xAccess = Some(access);
        registration.xFullPathname = Some(full_path);
        registration.xDlOpen = None;
        registration.xDlError = None;
        registration.xDlSym = None;
        registration.xDlClose = None;
        registration.xSetSystemCall = None;
        registration.xGetSystemCall = None;
        registration.xNextSystemCall = None;
        // SAFETY: owner below retains table/name/policy and does not change default VFS.
        if unsafe { ffi::sqlite3_vfs_register(&mut *registration, 0) } != ffi::SQLITE_OK {
            return Err(io::Error::other(
                "fresh native WAL SQLite registration failed",
            ));
        }
        let mut owner = Self {
            connection: None,
            registration,
            name,
            policy,
            path: path.to_owned(),
            attempted: false,
        };
        let connection = rusqlite::Connection::open_with_flags_and_vfs(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            owner.name.to_str().map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        owner.connection = Some(connection);
        owner.verify()?;
        Ok(owner)
    }
    pub fn verify(&self) -> io::Result<()> {
        if self.policy.poisoned.get() || self.connection.is_none() {
            return Err(io::Error::other("fresh native WAL SQLite uncertain"));
        }
        for file in &self.policy.files {
            file.verify()?;
        }
        if !self.policy.files[0].matches_path(&self.path)? {
            return Err(io::Error::other("fresh WAL SQLite target slot differs"));
        }
        Ok(())
    }
    pub fn keys(&self) -> io::Result<[FileKey; 3]> {
        self.verify()?;
        Ok([
            self.policy.files[0].key()?,
            self.policy.files[1].key()?,
            self.policy.files[2].key()?,
        ])
    }
    pub fn exact_main_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        self.policy.files[0].exact_bytes(self.policy.limits[0])
    }
    pub fn commit_fresh_session(&mut self, expected: &str, fresh: &str) -> io::Result<()> {
        self.verify()?;
        if self.attempted
            || expected.len() != 32
            || fresh.len() != 32
            || expected == fresh
            || !expected
                .bytes()
                .chain(fresh.bytes())
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(io::Error::other(
                "fresh session bounded single attempt required",
            ));
        }
        self.attempted = true;
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| io::Error::other("fresh WAL SQLite closed"))?;
        for (category, value) in [
            (rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024),
            (rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 65536),
        ] {
            connection
                .set_limit(category, value)
                .map_err(|error| io::Error::other(format!("first session limits: {error}")))?;
        }
        let started = std::time::Instant::now();
        let mut remaining = 100_000_000u64;
        connection
            .progress_handler(
                1000,
                Some(move || {
                    if remaining < 1000 || started.elapsed() > std::time::Duration::from_secs(60) {
                        return true;
                    }
                    remaining -= 1000;
                    false
                }),
            )
            .map_err(|error| io::Error::other(format!("first session vmguard: {error}")))?;
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|error| io::Error::other(format!("first session busy: {error}")))?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(|error| io::Error::other(format!("first session tempstore: {error}")))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| io::Error::other(format!("first session synchronous: {error}")))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| io::Error::other(format!("first session journalmode: {error}")))?;
        connection
            .pragma_update(None, "locking_mode", "NORMAL")
            .map_err(|error| io::Error::other(format!("first session lockingmode: {error}")))?;
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(|error| io::Error::other(format!("first session autocheckpoint: {error}")))?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| io::Error::other(format!("first session begin: {error}")))?;
        let result=connection.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='original_recovery_session' AND value=?2",
            [fresh,expected]);
        match result {
            Ok(1) => connection
                .execute_batch("COMMIT")
                .map_err(|error| io::Error::other(format!("first session commit: {error}")))?,
            result => {
                let _ = connection.execute_batch("ROLLBACK");
                self.policy.poisoned.set(true);
                return Err(io::Error::other(format!(
                    "fresh session exact CAS failed: {result:?}"
                )));
            }
        }
        eprintln!(
            "R03_DIAG commit_fresh_session autocommit={}",
            connection.is_autocommit()
        );
        self.verify()
    }
}
impl Drop for FreshNativeWalConnection {
    fn drop(&mut self) {
        self.connection.take();
        // SAFETY: connection closed before unregistering this owned private table.
        unsafe {
            ffi::sqlite3_vfs_unregister(&mut *self.registration);
        }
    }
}

// Confirm actual SQLite close while all native file objects remain held.
impl FreshNativeWalConnection {
    pub fn close_connection_retaining_native_objects(&mut self) -> io::Result<()> {
        self.verify()?;
        let connection = self
            .connection
            .take()
            .ok_or_else(|| io::Error::other("fresh native WAL connection already closed"))?;
        match connection.close() {
            Ok(()) => {
                self.policy.shm.borrow_mut().take();
                self.verify_closed_native_objects()
            }
            Err((connection, error)) => {
                self.connection = Some(connection);
                self.policy.poisoned.set(true);
                Err(io::Error::other(error))
            }
        }
    }
    pub fn verify_closed_native_objects(&self) -> io::Result<()> {
        if self.connection.is_some() || self.policy.poisoned.get() {
            return Err(io::Error::other(
                "fresh native WAL actual close not confirmed",
            ));
        }
        for (index, file) in self.policy.files.iter().enumerate() {
            file.verify()?;
            if !file.matches_path(std::path::Path::new(
                self.policy.names[index]
                    .to_str()
                    .map_err(io::Error::other)?,
            ))? {
                return Err(io::Error::other("fresh closed native file slot changed"));
            }
        }
        let rollback = self.policy.files[2].exact_bytes(self.policy.limits[2])?;
        if !self.policy.files[1]
            .exact_bytes(self.policy.limits[1])?
            .is_empty()
            || (!rollback.is_empty() && rollback.get(..8) != Some(&[0; 8]))
        {
            return Err(io::Error::other(
                "fresh actual close nonhot sidecars required",
            ));
        }
        Ok(())
    }
    pub fn exact_closed_main_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify_closed_native_objects()?;
        self.policy.files[0].exact_bytes(self.policy.limits[0])
    }
}

use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Storage::FileSystem::{
        LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    },
    System::{
        Memory::{
            CreateFileMappingW, FlushViewOfFile, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE,
            MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
        },
        IO::OVERLAPPED,
    },
};
struct ShmMapping {
    section: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}
impl Drop for ShmMapping {
    fn drop(&mut self) {
        // SAFETY: successful mapping owns exactly this view and section; SQLite
        // connection closes before Policy drops, so no callback retains pointers.
        unsafe {
            UnmapViewOfFile(self.view);
            CloseHandle(self.section);
        }
    }
}
unsafe extern "C" fn shm_map(
    file: *mut ffi::sqlite3_file,
    page: i32,
    size: i32,
    extend: i32,
    out: *mut *mut std::ffi::c_void,
) -> i32 {
    if out.is_null() {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    // SAFETY: SQLite provides one output pointer and initialized NativeIo.
    unsafe {
        *out = ptr::null_mut();
    }
    // SAFETY: callback lifetime keeps Policy and all acquired objects live.
    let (owner, index) = unsafe { state(file) };
    if index != 0
        || page < 0
        || size != 32768
        || page >= 32
        || extend < 0
        || owner.poisoned.get()
        || owner.files[3].verify().is_err()
    {
        owner.poisoned.set(true);
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    let mut mapping = owner.shm.borrow_mut();
    if mapping.is_none() {
        let current = match owner.files[3].native_file().metadata() {
            Ok(value) => value.len(),
            Err(_) => return ffi::SQLITE_IOERR_SHMSIZE,
        };
        if current == 0 && extend == 0 {
            return ffi::SQLITE_OK;
        }
        if current > owner.limits[3] || (current < owner.limits[3] && extend == 0) {
            return ffi::SQLITE_IOERR_SHMSIZE;
        }
        if current < owner.limits[3]
            && owner.files[3]
                .native_file()
                .set_len(owner.limits[3])
                .is_err()
        {
            owner.poisoned.set(true);
            return ffi::SQLITE_FULL;
        }
        // SAFETY: share0 acquired file remains held; mapping is unnamed and
        // bounded to this exact 1MiB object. No path resolution or reopen occurs.
        let section = unsafe {
            CreateFileMappingW(
                owner.files[3].native_file().as_raw_handle() as HANDLE,
                ptr::null(),
                PAGE_READWRITE,
                0,
                owner.limits[3] as u32,
                ptr::null(),
            )
        };
        if section.is_null() {
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        // SAFETY: live bounded section; full view starts at aligned offset zero.
        let view =
            unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, owner.limits[3] as usize) };
        if view.Value.is_null() {
            // SAFETY: only successful CreateFileMapping transferred this handle.
            unsafe {
                CloseHandle(section);
            }
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        *mapping = Some(ShmMapping { section, view });
    }
    let Some(value) = mapping.as_ref() else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // SAFETY: page is in 0..32, size fixed32768; pointer remains inside retained view.
    unsafe {
        *out = value
            .view
            .Value
            .cast::<u8>()
            .add(page as usize * 32768)
            .cast();
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: i32,
    count: i32,
    flags: i32,
) -> i32 {
    // SAFETY: initialized SQLite callback, Policy retains native SHM file.
    let (owner, index) = unsafe { state(file) };
    let valid = flags == (ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_SHARED)
        || flags == (ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE)
        || flags == (ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_SHARED)
        || flags == (ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_EXCLUSIVE);
    if index != 0
        || offset < 0
        || count < 1
        || offset.checked_add(count).is_none_or(|n| n > 8)
        || !valid
        || owner.poisoned.get()
        || owner.files[3].verify().is_err()
    {
        return ffi::SQLITE_IOERR_SHMLOCK;
    }
    let handle = owner.files[3].native_file().as_raw_handle() as HANDLE;
    for slot in offset..offset + count {
        let mut position = OVERLAPPED::default();
        // SAFETY: this union field is the synchronous low byte offset.
        position.Anonymous.Anonymous.Offset = 120 + slot as u32;
        let bit = 1u8 << slot;
        if flags & ffi::SQLITE_SHM_LOCK != 0 {
            if owner.shm_lock_bits.get() & bit != 0 {
                return ffi::SQLITE_IOERR_SHMLOCK;
            }
            let options = LOCKFILE_FAIL_IMMEDIATELY
                | if flags & ffi::SQLITE_SHM_EXCLUSIVE != 0 {
                    LOCKFILE_EXCLUSIVE_LOCK
                } else {
                    0
                };
            // SAFETY: live exact handle, one byte, synchronous sized OVERLAPPED.
            if unsafe { LockFileEx(handle, options, 0, 1, 0, &mut position) } == 0 {
                owner.poisoned.set(true);
                return ffi::SQLITE_BUSY;
            }
            owner.shm_lock_bits.set(owner.shm_lock_bits.get() | bit);
        } else {
            if owner.shm_lock_bits.get() & bit == 0 {
                return ffi::SQLITE_IOERR_SHMLOCK;
            }
            // SAFETY: exact byte lock previously acquired on this same handle.
            if unsafe { UnlockFileEx(handle, 0, 1, 0, &mut position) } == 0 {
                owner.poisoned.set(true);
                return ffi::SQLITE_IOERR_SHMLOCK;
            }
            owner.shm_lock_bits.set(owner.shm_lock_bits.get() & !bit);
        }
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn shm_barrier(_file: *mut ffi::sqlite3_file) {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}
unsafe extern "C" fn shm_unmap(file: *mut ffi::sqlite3_file, _delete: i32) -> i32 {
    // SAFETY: initialized main IO callback, actual mapping remains retained.
    let (owner, index) = unsafe { state(file) };
    if index != 0 || owner.files[3].verify().is_err() {
        return ffi::SQLITE_IOERR_SHMOPEN;
    }
    if let Some(mapping) = owner.shm.borrow().as_ref() {
        // SAFETY: retained view covers exactly the bounded mapped file.
        if unsafe { FlushViewOfFile(mapping.view.Value, owner.limits[3] as usize) } == 0 {
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_FSYNC;
        }
    }
    ffi::SQLITE_OK
}
impl FreshNativeWalConnection {
    /// Return counters from this same live SQLite connection.  A verification
    /// cache must bind these counters in addition to exact native file bytes;
    /// a stable main database hash alone does not prove that the live WAL
    /// connection has not changed.
    pub fn verification_change_counters(&self) -> io::Result<Option<(u64, u64)>> {
        let connection = match self.connection.as_ref() {
            Some(connection) => {
                self.verify()?;
                connection
            }
            None => {
                self.verify_closed_native_objects()?;
                return Ok(None);
            }
        };
        let data_version: i64 = connection
            .pragma_query_value(Some("main"), "data_version", |row| row.get(0))
            .map_err(|error| io::Error::other(format!("native WAL data_version: {error}")))?;
        let data_version = u64::try_from(data_version)
            .map_err(|_| io::Error::other("native WAL data_version negative"))?;
        Ok(Some((data_version, connection.total_changes())))
    }

    pub fn checkpoint_wal(&mut self) -> io::Result<()> {
        self.verify()?;
        let row: (i64, i64, i64) = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("actual WAL connection closed"))?
            .query_row("PRAGMA main.wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| io::Error::other(format!("native WAL checkpoint: {error}")))?;
        if row.0 != 0
            || row.1 != row.2
            || !self.policy.files[1]
                .exact_bytes(self.policy.limits[1])?
                .is_empty()
        {
            self.policy.poisoned.set(true);
            return Err(io::Error::other("actual WAL checkpoint incomplete"));
        }
        self.verify()
    }
    pub fn exact_sidecar_bytes(&self, index: usize) -> io::Result<Vec<u8>> {
        if !(1..=3).contains(&index) {
            return Err(io::Error::other("actual WAL sidecar index"));
        }
        if self.connection.is_some() {
            self.verify()?;
        } else {
            self.verify_closed_native_objects()?;
        }
        self.policy.files[index].exact_bytes(self.policy.limits[index])
    }
    pub fn shm_mapping_active(&self) -> io::Result<bool> {
        self.verify()?;
        Ok(self.policy.shm.borrow().is_some())
    }
}

impl FreshNativeWalConnection {
    /// SQLite itself switches a checkpointed actual main to standalone format.
    /// No header bytes are fabricated or normalized by the caller.
    pub fn checkpoint_to_standalone(&mut self) -> io::Result<()> {
        self.checkpoint_wal()?;
        let mode: String = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("actual WAL closed"))?
            .query_row("PRAGMA main.journal_mode=PERSIST", [], |row| row.get(0))
            .map_err(|error| io::Error::other(format!("native standalone mode: {error}")))?;
        if !mode.eq_ignore_ascii_case("persist")
            || self.policy.files[0]
                .exact_bytes(self.policy.limits[0])?
                .get(18..20)
                != Some(&[1, 1])
            || !self.policy.files[1]
                .exact_bytes(self.policy.limits[1])?
                .is_empty()
        {
            self.policy.poisoned.set(true);
            return Err(io::Error::other(
                "actual SQLite standalone checkpoint not confirmed",
            ));
        }
        // This budget belongs to the completed first session commit/checkpoint.
        // Leaving its elapsed wall clock attached would poison unrelated later
        // bounded history calls. Each history row/DML audit installs its own
        // original VM guard; remove this completed guard only after checkpoint.
        self.connection
            .as_mut()
            .ok_or_else(|| io::Error::other("checkpoint connection closed"))?
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(io::Error::other)?;
        self.verify()
    }
}

impl FreshNativeWalConnection {
    /// Start a new shared-memory index epoch only after exact prior terminal
    /// admission, fresh exclusive native acquisition, and durable new intent.
    /// The SHM native identity is retained. This is a new recorded native effect.
    pub fn open_after_explicit_shm_epoch(
        path: &std::path::Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
        expected_shm: (&str, &[u8]),
    ) -> io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().and_then(|n| n.to_str()) != Some("journal.sqlite")
            || limits
                .iter()
                .any(|n| !(512..=256 * 1024 * 1024).contains(n))
            || limits.iter().sum::<u64>() > 512 * 1024 * 1024
            || limits[3] != 1024 * 1024
        {
            return Err(io::Error::other("new SHM epoch exact bounded path"));
        }
        for (index, file) in files.iter().enumerate() {
            file.verify()?;
            let expected = path.with_file_name(
                [
                    "journal.sqlite",
                    "journal.sqlite-wal",
                    "journal.sqlite-journal",
                    "journal.sqlite-shm",
                ][index],
            );
            if !file.matches_path(&expected)? || file.parent_key()? != files[0].parent_key()? {
                return Err(io::Error::other("new SHM epoch exact four native slots"));
            }
            file.exact_bytes(limits[index])?;
        }
        if files[0].exact_bytes(limits[0])?.get(18..20) != Some(&[1, 1])
            || !files[1].exact_bytes(limits[1])?.is_empty()
        {
            return Err(io::Error::other(
                "new SHM epoch requires independently standalone checkpoint",
            ));
        }
        let shm = &files[3];
        if shm.key()?.to_string() != expected_shm.0
            || shm.exact_bytes(1024 * 1024)? != expected_shm.1
            || shm.native_file().metadata()?.len() != 1024 * 1024
            || !shm.matches_path(&path.with_file_name("journal.sqlite-shm"))?
            || shm.parent_key()? != files[0].parent_key()?
            || limits[3] != 1024 * 1024
        {
            return Err(io::Error::other(
                "new SHM epoch exact exclusive previous object required",
            ));
        }
        let zero = [0u8; 65536];
        for index in 0..16 {
            let mut offset = 0;
            while offset < zero.len() {
                let count = shm
                    .native_file()
                    .seek_write(&zero[offset..], index * 65536 + offset as u64)?;
                if count == 0 {
                    return Err(io::Error::other("new SHM epoch short native write"));
                }
                offset += count;
            }
        }
        shm.native_file().sync_all()?;
        shm.verify()?;
        if shm.exact_bytes(1024 * 1024)?.iter().any(|byte| *byte != 0) {
            return Err(io::Error::other(
                "new SHM epoch exact zero index confirmation",
            ));
        }
        Self::open(path, files, limits)
    }
}

impl FreshNativeWalConnection {
    pub fn held_shm_bytes(&self) -> io::Result<Vec<u8>> {
        self.policy.files[3].verify()?;
        self.policy.files[3].exact_bytes(1024 * 1024)
    }
    pub fn all_native_keys(&self) -> io::Result<[FileKey; 4]> {
        self.policy
            .files
            .each_ref()
            .map(|file| file.key())
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| io::Error::other("four held native keys"))
    }
}

impl FreshNativeWalConnection {
    pub fn issue_retention_lease(&self, generation: u32) -> io::Result<FreshNativeRetentionLease> {
        self.verify()?;
        if !self.attempted || self.connection.is_none() || generation >= 64 {
            return Err(io::Error::other(
                "retention requires a committed live native session",
            ));
        }
        Ok(FreshNativeRetentionLease {
            policy: Rc::clone(&self.policy),
            keys: self.all_native_keys()?,
            generation,
        })
    }

    pub fn verify_retention_lease(&self, lease: &FreshNativeRetentionLease) -> io::Result<()> {
        self.verify()?;
        if !self.attempted
            || self.connection.is_none()
            || !Rc::ptr_eq(&self.policy, &lease.policy)
            || self.all_native_keys()? != lease.keys
        {
            return Err(io::Error::other(
                "retention issuer is not this live native owner",
            ));
        }
        Ok(())
    }

    /// Only the fresh metadata adapter can widen the ordinary-history DML
    /// family. All complete before/after rows are compared in BEGIN IMMEDIATE.
    pub fn execute_retention_metadata(
        &mut self,
        lease: &FreshNativeRetentionLease,
        statements: &[super::OriginalSqliteStatement],
        queries: &[super::OriginalSqliteQuery],
        before: &[super::OriginalSqliteRows],
        after: &[super::OriginalSqliteRows],
        budget: super::OriginalSqliteReadBudget,
        gc_mark: bool,
    ) -> io::Result<()> {
        self.verify_retention_lease(lease)?;
        if statements.len() > 1024
            || statements
                .iter()
                .try_fold(0usize, |n, s| {
                    n.checked_add(
                        s.sql.len()
                            + s.parameters
                                .iter()
                                .map(|v| match v {
                                    super::OriginalSqliteValue::Text(v) => v.len(),
                                    super::OriginalSqliteValue::Blob(v) => v.len(),
                                    _ => 8,
                                })
                                .sum::<usize>(),
                    )
                })
                .is_none_or(|n| n > 1024 * 1024)
        {
            return Err(io::Error::other(
                "retention complete metadata transition budget",
            ));
        }
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("retention connection closed"))?;
        let result = super::sqlite_original::execute_fresh_retention_metadata(
            connection, statements, queries, before, after, budget, gc_mark,
        );
        if result.is_err() {
            self.policy.poisoned.set(true);
        }
        result?;
        self.checkpoint_to_standalone()?;
        self.verify_retention_lease(lease)
    }

    /// Exact whole-row transition; private native connection never escapes.
    pub fn execute_planned_history(
        &mut self,
        statements: &[super::OriginalSqliteStatement],
        queries: &[super::OriginalSqliteQuery],
        before: &[super::OriginalSqliteRows],
        after: &[super::OriginalSqliteRows],
        budget: super::OriginalSqliteReadBudget,
    ) -> io::Result<()> {
        self.verify()?;
        if !self.attempted {
            return Err(io::Error::other("fresh history committed session required"));
        }
        let size = statements.iter().try_fold(0u64, |sum, row| {
            if row.sql.is_empty()
                || row.sql.len() > 65536
                || row.parameters.len() > 1024
                || row.sql.contains('\0')
            {
                return Err(io::Error::other("fresh history bounded SQL"));
            }
            row.parameters
                .iter()
                .try_fold(sum + row.sql.len() as u64, |sum, value| {
                    let size = match value {
                        super::OriginalSqliteValue::Null => 0,
                        super::OriginalSqliteValue::Integer(_)
                        | super::OriginalSqliteValue::Real(_) => 8,
                        super::OriginalSqliteValue::Text(s) => s.len(),
                        super::OriginalSqliteValue::Blob(b) => b.len(),
                    };
                    sum.checked_add(size as u64)
                        .ok_or_else(|| io::Error::other("fresh history SQL aggregate"))
                })
        })?;
        if size > 1024 * 1024 {
            return Err(io::Error::other("fresh history encoded transition budget"));
        }
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("fresh history connection closed"))?;
        eprintln!(
            "R03_DIAG execute_planned_history before helper autocommit={}",
            connection.is_autocommit()
        );
        // Existing private VFS already retains all native objects and denies
        // namespace deletion; the original authorizer restricts every DML family.
        let result = super::sqlite_original::execute_fresh_planned_history(
            connection, statements, queries, before, after, budget,
        );
        if result.is_err() {
            self.policy.poisoned.set(true);
        }
        result?;
        self.checkpoint_to_standalone()?;
        self.verify()
    }
}
