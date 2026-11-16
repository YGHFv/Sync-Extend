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
    files: [FreshExclusiveSqliteFile; 3],
    names: [CString; 3],
    limits: [u64; 3],
    poisoned: std::cell::Cell<bool>,
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
    iVersion: 1,
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
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
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
    if normalized(name) != normalized(&owner.names[2]) {
        owner.poisoned.set(true);
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SQLite may invalidate only this retained rollback object; no namespace delete.
    match owner.files[2]
        .native_file()
        .set_len(0)
        .and_then(|()| owner.files[2].native_file().sync_all())
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
pub struct FreshNativeSqliteConnection {
    connection: Option<rusqlite::Connection>,
    registration: Box<ffi::sqlite3_vfs>,
    name: CString,
    policy: Rc<Policy>,
    path: std::path::PathBuf,
    attempted: bool,
}
impl FreshNativeSqliteConnection {
    pub fn open(
        path: &std::path::Path,
        files: [FreshExclusiveSqliteFile; 3],
        limits: [u64; 3],
    ) -> io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().and_then(|v| v.to_str()) != Some("journal.sqlite")
            || limits
                .iter()
                .any(|n| !(512..=256 * 1024 * 1024).contains(n))
            || limits.iter().sum::<u64>() > 512 * 1024 * 1024
        {
            return Err(io::Error::other("fresh native SQLite exact path/bounds"));
        }
        let text = path
            .to_str()
            .ok_or_else(|| io::Error::other("fresh native SQLite path encoding"))?;
        let names = [
            CString::new(text),
            CString::new(format!("{text}-wal")),
            CString::new(format!("{text}-journal")),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
        let names: [CString; 3] = names
            .try_into()
            .map_err(|_| io::Error::other("fresh native SQLite names"))?;
        for (index, file) in files.iter().enumerate() {
            file.verify()?;
            if !file.matches_path(std::path::Path::new(
                names[index].to_str().map_err(io::Error::other)?,
            ))? || file.parent_key()? != files[0].parent_key()?
                || file.exact_bytes(limits[index])?.len() as u64 > limits[index]
            {
                return Err(io::Error::other("fresh native SQLite current file differs"));
            }
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if id == u64::MAX {
            return Err(io::Error::other(
                "fresh native SQLite registration exhausted",
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
            return Err(io::Error::other("fresh native SQLite registration failed"));
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
            return Err(io::Error::other("fresh native SQLite uncertain"));
        }
        for file in &self.policy.files {
            file.verify()?;
        }
        if !self.policy.files[0].matches_path(&self.path)? {
            return Err(io::Error::other("fresh SQLite target slot differs"));
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
            .ok_or_else(|| io::Error::other("fresh SQLite closed"))?;
        for (category, value) in [
            (rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            (rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024),
            (rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 65536),
        ] {
            connection
                .set_limit(category, value)
                .map_err(io::Error::other)?;
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
            .map_err(io::Error::other)?;
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "journal_mode", "PERSIST")
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(io::Error::other)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(io::Error::other)?;
        let result=connection.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='original_recovery_session' AND value=?2",
            [fresh,expected]);
        match result {
            Ok(1) => connection
                .execute_batch("COMMIT")
                .map_err(io::Error::other)?,
            result => {
                let _ = connection.execute_batch("ROLLBACK");
                self.policy.poisoned.set(true);
                return Err(io::Error::other(format!(
                    "fresh session exact CAS failed: {result:?}"
                )));
            }
        }
        self.verify()
    }
}
impl Drop for FreshNativeSqliteConnection {
    fn drop(&mut self) {
        self.connection.take();
        // SAFETY: connection closed before unregistering this owned private table.
        unsafe {
            ffi::sqlite3_vfs_unregister(&mut *self.registration);
        }
    }
}

// Confirm actual SQLite close while all native file objects remain held.
impl FreshNativeSqliteConnection {
    pub fn close_connection_retaining_native_objects(&mut self) -> io::Result<()> {
        self.verify()?;
        let connection = self
            .connection
            .take()
            .ok_or_else(|| io::Error::other("fresh native connection already closed"))?;
        match connection.close() {
            Ok(()) => self.verify_closed_native_objects(),
            Err((connection, error)) => {
                self.connection = Some(connection);
                self.policy.poisoned.set(true);
                Err(io::Error::other(error))
            }
        }
    }
    pub fn verify_closed_native_objects(&self) -> io::Result<()> {
        if self.connection.is_some() || self.policy.poisoned.get() {
            return Err(io::Error::other("fresh native actual close not confirmed"));
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
        if !self.policy.files[1]
            .exact_bytes(self.policy.limits[1])?
            .is_empty()
            || self.policy.files[2]
                .exact_bytes(self.policy.limits[2])?
                .get(..8)
                != Some(&[0; 8])
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
