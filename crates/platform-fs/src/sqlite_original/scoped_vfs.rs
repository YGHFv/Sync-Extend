//! A unique living VFS opens only exact approved existing main/WAL objects.
//! Native handles are checked before SQLite can issue the first file IO.
use crate::FileKey;
use rusqlite::ffi;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::windows::io::FromRawHandle,
    ptr,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE},
    System::Threading::GetCurrentProcess,
};

struct ApprovedFiles {
    main_name: CString,
    wal_name: CString,
    journal_name: CString,
    main: FileKey,
    wal: FileKey,
    journal: FileKey,
    limits: [u64; 3],
}

struct Policy {
    base: *mut ffi::sqlite3_vfs,
    main_name: CString,
    wal_name: CString,
    journal_name: CString,
    main: FileKey,
    wal: FileKey,
    journal: FileKey,
    limits: [u64; 3],
    native_offset: usize,
    opened_rollback: std::cell::RefCell<Option<File>>,
    held_rollback: std::cell::RefCell<Option<HeldRollback>>,
    rollback_reset_authorized: std::cell::Cell<bool>,
    poisoned: std::sync::atomic::AtomicBool,
}

/// Registration owns its policy and name until its connection is fully closed.
/// This type has no Send/Sync implementation; callers retain it on the same thread.
struct OriginalSqliteVfs {
    table: Box<ffi::sqlite3_vfs>,
    name: CString,
    policy: Rc<Policy>,
}

fn normalized(path: &CStr) -> Vec<u8> {
    path.to_bytes()
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

fn error() -> i32 {
    ffi::SQLITE_CANTOPEN
}

unsafe fn policy<'a>(vfs: *mut ffi::sqlite3_vfs) -> &'a Policy {
    // SAFETY: our live registered table stores Rc::as_ptr from its retained owner.
    unsafe { &*((*vfs).pAppData.cast::<Policy>()) }
}

unsafe fn actual_file(file: *mut ffi::sqlite3_file) -> io::Result<File> {
    // SAFETY: base xOpen returned a sized initialized sqlite3_file.
    let methods = unsafe { (*file).pMethods };
    if methods.is_null() {
        return Err(io::Error::other("VFS opened file has no methods"));
    }
    // SAFETY: methods is the actual file's installed live VFS table.
    let control = unsafe { (*methods).xFileControl }
        .ok_or_else(|| io::Error::other("native VFS file control unavailable"))?;
    let mut borrowed: HANDLE = ptr::null_mut();
    // SAFETY: this initialized file's control method with Windows HANDLE output.
    let result = unsafe {
        control(
            file,
            ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            ptr::from_mut(&mut borrowed).cast(),
        )
    };
    if result != ffi::SQLITE_OK || borrowed.is_null() || borrowed == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("actual VFS native handle refused"));
    }
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: file owns borrowed through this synchronous callback; duplicate has one owner.
    let ok = unsafe {
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
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("VFS duplicate native handle absent"));
    }
    // SAFETY: successful DuplicateHandle transfers one new locally owned handle.
    let observed = unsafe { File::from_raw_handle(duplicate) };
    super::verify_regular_file(&observed)?;
    Ok(observed)
}

unsafe fn actual_identity(file: *mut ffi::sqlite3_file) -> io::Result<FileKey> {
    // SAFETY: caller supplies the actual initialized builtin file for this callback.
    FileKey::from_file(&unsafe { actual_file(file)? })
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out: *mut i32,
) -> i32 {
    if vfs.is_null() || name.is_null() || file.is_null() {
        return error();
    }
    // SAFETY: callback receives our live registered table and SQLite filename.
    let policy = unsafe { policy(vfs) };
    if policy.poisoned.load(Ordering::SeqCst) {
        return error();
    }
    // SAFETY: SQLite supplies a terminated filename valid for the callback.
    let name_bytes = unsafe { CStr::from_ptr(name) };
    if name_bytes.to_bytes().len() > 16_384 {
        return error();
    }
    let kind =
        flags & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL);
    let (expected, limit) = if kind == ffi::SQLITE_OPEN_MAIN_DB
        && normalized(name_bytes) == normalized(&policy.main_name)
    {
        (policy.main, policy.limits[0])
    } else if kind == ffi::SQLITE_OPEN_WAL && normalized(name_bytes) == normalized(&policy.wal_name)
    {
        (policy.wal, policy.limits[1])
    } else if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL
        && normalized(name_bytes) == normalized(&policy.journal_name)
    {
        (policy.journal, policy.limits[2])
    } else {
        // Rollback journal, temp files, anonymous names, attached DB and SHM opens
        // have no approved original object. Refuse them before any base syscall.
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    };
    if flags & ffi::SQLITE_OPEN_READWRITE == 0 || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0 {
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    }
    // Windows base must apply share0 to main. SQLite URI parameters are retained
    // alongside this filename; no string-built query or global default modifies it.
    // SAFETY: SQLite filename has the documented URI extra data representation.
    if kind == ffi::SQLITE_OPEN_MAIN_DB
        // SAFETY: SQLite supplies this callback filename and its documented URI data.
        && unsafe { ffi::sqlite3_uri_boolean(name, c"exclusive".as_ptr(), 0) } != 1
    {
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    }
    // SAFETY: retained base VFS is SQLite's builtin Windows VFS for this process.
    let base_open = unsafe { (*policy.base).xOpen };
    let Some(base_open) = base_open else {
        return error();
    };
    // Never create or delete via SQLite. Original creator and ledger precreate WAL.
    let flags = flags
        & !(ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_EXCLUSIVE | ffi::SQLITE_OPEN_DELETEONCLOSE);
    // SAFETY: pass SQLite's exact sized file storage/filename to the builtin VFS.
    // SAFETY: this VFS advertises outer aligned IO header plus builtin file size.
    let original = unsafe {
        file.cast::<u8>()
            .add(policy.native_offset)
            .cast::<ffi::sqlite3_file>()
    };
    // SAFETY: fresh outer storage is SQLite-owned; failure must not expose methods.
    unsafe {
        (*file).pMethods = ptr::null();
    }
    if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL {
        // SAFETY: original approved filename/kind/flags and sized outer storage
        // were validated above; this uses only the retained exact builtin object.
        return match unsafe { open_held_rollback(policy, file, flags, out) } {
            Ok(()) => ffi::SQLITE_OK,
            Err(_) => {
                policy.poisoned.store(true, Ordering::SeqCst);
                error()
            }
        };
    }
    // SAFETY: SQLite-owned storage contains exactly advertised native offset and base szOsFile.
    let result = unsafe { base_open(policy.base, name, original, flags, out) };
    if result != ffi::SQLITE_OK {
        return result;
    }
    // SAFETY: successful xOpen initialized this exact file. Check before first IO.
    if !matches!(unsafe{actual_identity(original)},Ok(key) if key==expected) {
        policy.poisoned.store(true, Ordering::SeqCst);
        // SAFETY: initialized file methods can close this exact newly opened file once.
        unsafe {
            let methods = (*original).pMethods;
            if !methods.is_null() {
                if let Some(close) = (*methods).xClose {
                    close(original);
                }
            }
            (*file).pMethods = ptr::null();
        }
        return error();
    }
    // SAFETY: base xOpen and exact identity succeeded; outer storage is aligned
    // and only this wrapper owns the original base file/methods and retained policy.
    unsafe {
        super::bounded_io::install(file, original, limit, &policy.poisoned, false);
    }
    result
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    _sync: i32,
) -> i32 {
    if vfs.is_null() || name.is_null() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SAFETY: SQLite calls our registered table with a terminated filename.
    let policy = unsafe { policy(vfs) };
    // SAFETY: SQLite owns this callback filename through the synchronous call.
    let name = unsafe { CStr::from_ptr(name) };
    if policy.poisoned.load(Ordering::SeqCst)
        || !policy.rollback_reset_authorized.get()
        || name.to_bytes().len() > 16_384
        || normalized(name) != normalized(&policy.journal_name)
    {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SQLite finalizes its rollback file after changing the main header to WAL.
    // Persist that exact original object by physically invalidating its contents.
    // No namespace deletion or pathname-issued write handle is ever granted.
    let reset = || -> io::Result<()> {
        let retained = policy.opened_rollback.borrow();
        let file = retained.as_ref().ok_or_else(|| {
            io::Error::other("rollback finalization lacks actual opened original")
        })?;
        super::verify_regular_file(file)?;
        if FileKey::from_file(file)? != policy.journal || file.metadata()?.len() > policy.limits[2]
        {
            return Err(io::Error::other(
                "rollback finalization original bound differs",
            ));
        }
        file.set_len(0)?;
        file.sync_all()?;
        super::verify_regular_file(file)?;
        if FileKey::from_file(file)? != policy.journal || file.metadata()?.len() != 0 {
            return Err(io::Error::other(
                "original rollback invalidation not complete",
            ));
        }
        Ok(())
    };
    match reset() {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            policy.poisoned.store(true, Ordering::SeqCst);
            ffi::SQLITE_IOERR_DELETE
        }
    }
}

unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    flags: i32,
    out: *mut i32,
) -> i32 {
    if vfs.is_null() || name.is_null() || out.is_null() {
        return error();
    }
    // SAFETY: our registered policy remains retained and filename is SQLite-owned.
    let policy = unsafe { policy(vfs) };
    // SAFETY: SQLite supplies a terminated filename for this callback.
    let name_bytes = unsafe { CStr::from_ptr(name) };
    if name_bytes.to_bytes().len() > 16_384 {
        return error();
    }
    if normalized(name_bytes) == normalized(&policy.main_name)
        || normalized(name_bytes) == normalized(&policy.wal_name)
    {
        // SAFETY: builtin base access callback handles these exact approved names.
        if let Some(access) = unsafe { (*policy.base).xAccess } {
            // SAFETY: unchanged SQLite filename and sized output to builtin VFS.
            return unsafe { access(policy.base, name, flags, out) };
        }
        return error();
    }
    // For discovery SQLite may ask whether a rollback/SHM name exists. Do not
    // conceal foreign files: let caller's explicit inventory and base access see it.
    // SAFETY: builtin base access only observes filename state, never creates/deletes.
    if let Some(access) = unsafe { (*policy.base).xAccess } {
        // SAFETY: unchanged SQLite callback arguments to builtin VFS.
        unsafe { access(policy.base, name, flags, out) }
    } else {
        error()
    }
}

impl OriginalSqliteVfs {
    /// Exact names/keys come from living original creator witnesses. Numeric
    /// observations alone must not be accepted by the private recovery issuer.
    fn register(approved: ApprovedFiles) -> io::Result<Self> {
        let ApprovedFiles {
            main_name,
            wal_name,
            journal_name,
            main,
            wal,
            journal,
            limits,
        } = approved;
        if limits
            .iter()
            .any(|value| *value < 512 || *value > 256 * 1024 * 1024)
            || limits
                .iter()
                .try_fold(0u64, |sum, value| sum.checked_add(*value))
                .is_none_or(|value| value > 512 * 1024 * 1024)
            || normalized(&main_name) == normalized(&journal_name)
            || normalized(&wal_name) == normalized(&journal_name)
            || journal_name.to_bytes().is_empty()
            || journal_name.to_bytes().len() > 16_384
        {
            return Err(io::Error::other(
                "admitted original SQLite names/aggregate bounds required",
            ));
        }
        if main_name.to_bytes().is_empty()
            || main_name.to_bytes().len() > 16_384
            || wal_name.to_bytes().len() > 16_384
            || normalized(&main_name) == normalized(&wal_name)
        {
            return Err(io::Error::other(
                "bounded distinct original VFS filenames required",
            ));
        }
        // SAFETY: SQLite initializes before returning its builtin named VFS.
        let base = unsafe { ffi::sqlite3_vfs_find(c"win32".as_ptr()) };
        if base.is_null() {
            return Err(io::Error::other("builtin Windows VFS required"));
        }
        // SAFETY: SQLite builtin VFS table has process lifetime and C-compatible layout.
        let mut table = Box::new(unsafe { *base });
        if table.szOsFile <= 0 || table.szOsFile > 64 * 1024 || table.iVersion < 2 {
            return Err(io::Error::other("bounded builtin Windows VFS ABI required"));
        }
        let alignment = std::mem::align_of::<super::bounded_io::OriginalIo>();
        let native_offset = std::mem::size_of::<super::bounded_io::OriginalIo>()
            .checked_add(alignment - 1)
            .ok_or_else(|| io::Error::other("SQLite native file alignment overflow"))?
            & !(alignment - 1);
        let size = native_offset
            .checked_add(table.szOsFile as usize)
            .ok_or_else(|| io::Error::other("SQLite wrapper file storage overflow"))?;
        table.szOsFile =
            i32::try_from(size).map_err(|_| io::Error::other("SQLite wrapper file size bound"))?;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            return Err(io::Error::other("original VFS registration exhausted"));
        }
        let name = CString::new(format!("sync-original-{}-{id}", std::process::id()))
            .map_err(|_| io::Error::other("private VFS name"))?;
        let policy = Rc::new(Policy {
            base,
            main_name,
            wal_name,
            journal_name,
            main,
            wal,
            journal,
            limits,
            native_offset,
            opened_rollback: std::cell::RefCell::new(None),
            held_rollback: std::cell::RefCell::new(None),
            rollback_reset_authorized: std::cell::Cell::new(false),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        });
        table.pNext = ptr::null_mut();
        table.zName = name.as_ptr();
        table.pAppData = Rc::as_ptr(&policy).cast_mut().cast();
        table.xOpen = Some(open);
        table.xDelete = Some(delete);
        table.xAccess = Some(access);
        table.xFullPathname = Some(full_path);
        table.xDlOpen = Some(dl_open);
        table.xDlError = Some(dl_error);
        table.xDlSym = Some(dl_symbol);
        table.xDlClose = Some(dl_close);
        table.xRandomness = Some(randomness);
        table.xSleep = Some(sleep);
        table.xCurrentTime = Some(current_time);
        table.xGetLastError = Some(last_error);
        table.xCurrentTimeInt64 = Some(current_time64);
        // Do not permit this private registration to replace process-wide syscalls.
        table.xSetSystemCall = None;
        table.xGetSystemCall = None;
        table.xNextSystemCall = None;

        // SAFETY: boxed table, CString and policy live in returned registration;
        // makeDefault=0 prevents changing any unrelated normal Journal connections.
        let result = unsafe { ffi::sqlite3_vfs_register(&mut *table, 0) };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other("private scoped VFS registration refused"));
        }
        Ok(Self {
            table,
            name,
            policy,
        })
    }
    fn name(&self) -> &CStr {
        &self.name
    }
    fn refused_effect(&self) -> bool {
        self.policy.poisoned.load(Ordering::SeqCst)
    }
}

impl Drop for OriginalSqliteVfs {
    fn drop(&mut self) {
        // SAFETY: owner must close its connection before registration drops.
        // Unregister only this unique private table, never builtin/default VFS.
        unsafe {
            ffi::sqlite3_vfs_unregister(&mut *self.table);
        }
    }
}

unsafe extern "C" fn full_path(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    n: i32,
    out: *mut std::ffi::c_char,
) -> i32 {
    // SAFETY: callback receives our registered table, policy/base has owner lifetime.
    let base = unsafe { policy(vfs).base };
    // SAFETY: builtin VFS table is live for process lifetime.
    let Some(method) = (unsafe { (*base).xFullPathname }) else {
        return error();
    };
    // SAFETY: forward unchanged SQLite arguments to its actual builtin base table.
    unsafe { method(base, name, n, out) }
}
unsafe extern "C" fn dl_open(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const std::ffi::c_char,
) -> *mut std::ffi::c_void {
    ptr::null_mut()
}
unsafe extern "C" fn dl_error(_vfs: *mut ffi::sqlite3_vfs, n: i32, out: *mut std::ffi::c_char) {
    if n > 0 && !out.is_null() {
        // SAFETY: SQLite gives an n-byte writable error buffer; terminate only first byte.
        unsafe {
            *out = 0;
        }
    }
}
unsafe extern "C" fn dl_symbol(
    _vfs: *mut ffi::sqlite3_vfs,
    _library: *mut std::ffi::c_void,
    _name: *const std::ffi::c_char,
) -> Option<
    unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut std::ffi::c_void, *const std::ffi::c_char),
> {
    None
}
unsafe extern "C" fn dl_close(_vfs: *mut ffi::sqlite3_vfs, _library: *mut std::ffi::c_void) {}
unsafe extern "C" fn randomness(
    vfs: *mut ffi::sqlite3_vfs,
    n: i32,
    out: *mut std::ffi::c_char,
) -> i32 {
    // SAFETY: our policy's base is retained builtin VFS.
    let base = unsafe { policy(vfs).base };
    // SAFETY: method table is builtin process-lifetime object.
    let Some(method) = (unsafe { (*base).xRandomness }) else {
        return 0;
    };
    // SAFETY: unchanged sized SQLite random output buffer forwarded to builtin.
    unsafe { method(base, n, out) }
}
unsafe extern "C" fn sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: i32) -> i32 {
    // SAFETY: registered callback table owns policy throughout this call.
    let base = unsafe { policy(vfs).base };
    // SAFETY: process-lifetime builtin method table.
    let Some(method) = (unsafe { (*base).xSleep }) else {
        return 0;
    };
    // SAFETY: pointer-free original builtin sleep receives bounded SQLite argument.
    unsafe { method(base, microseconds) }
}
unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> i32 {
    // SAFETY: retained policy/base valid for registered table callback.
    let base = unsafe { policy(vfs).base };
    // SAFETY: builtin process-lifetime method table.
    let Some(method) = (unsafe { (*base).xCurrentTime }) else {
        return ffi::SQLITE_ERROR;
    };
    // SAFETY: SQLite's sized f64 output forwarded unchanged.
    unsafe { method(base, out) }
}
unsafe extern "C" fn current_time64(
    vfs: *mut ffi::sqlite3_vfs,
    out: *mut ffi::sqlite3_int64,
) -> i32 {
    // SAFETY: registered policy and process-lifetime builtin base are live.
    let base = unsafe { policy(vfs).base };
    // SAFETY: builtin table live for this callback.
    let Some(method) = (unsafe { (*base).xCurrentTimeInt64 }) else {
        return ffi::SQLITE_ERROR;
    };
    // SAFETY: SQLite's sized int64 output forwarded unchanged.
    unsafe { method(base, out) }
}
unsafe extern "C" fn last_error(
    vfs: *mut ffi::sqlite3_vfs,
    n: i32,
    out: *mut std::ffi::c_char,
) -> i32 {
    // SAFETY: policy retained by the registered VFS owner.
    let base = unsafe { policy(vfs).base };
    // SAFETY: builtin process-lifetime method table.
    let Some(method) = (unsafe { (*base).xGetLastError }) else {
        return 0;
    };
    // SAFETY: unchanged SQLite sized output buffer forwarded to original base.
    unsafe { method(base, n, out) }
}

/// Connection drops before registration by field order. No public Connection
/// or VFS handle escapes; private Journal adapter must retain this whole owner.
pub(super) struct ScopedOriginalSqlite {
    connection: Option<rusqlite::Connection>,
    registration: OriginalSqliteVfs,
    main: crate::ReleasedOriginalFileIdentity,
    wal: crate::ReleasedOriginalFileIdentity,
    journal: crate::ReleasedOriginalFileIdentity,
    write_attempted: bool,
}

impl ScopedOriginalSqlite {
    pub(super) fn open(
        uri: &str,
        main_path: &std::path::Path,
        main: crate::ReleasedOriginalFileIdentity,
        wal: crate::ReleasedOriginalFileIdentity,
        journal: crate::ReleasedOriginalFileIdentity,
        limits: [u64; 3],
    ) -> Result<
        Self,
        Box<(
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
            io::Error,
        )>,
    > {
        let attempt = || -> io::Result<(rusqlite::Connection, OriginalSqliteVfs)> {
            main.verify()?;
            wal.verify()?;
            journal.verify()?;
            let mut wal_path = main_path.as_os_str().to_owned();
            wal_path.push("-wal");
            if !main_path.is_absolute()
                || !main.matches_path(main_path)?
                || !wal.matches_path(std::path::Path::new(&wal_path))?
                || main.parent_key()? != wal.parent_key()?
            {
                return Err(io::Error::other(
                    "scoped VFS original main/WAL lineage differs",
                ));
            }
            let main_name = CString::new(
                main_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("scoped VFS native path encoding"))?,
            )
            .map_err(|_| io::Error::other("scoped VFS main filename"))?;
            let mut name = main_name.as_bytes().to_vec();
            name.extend_from_slice(b"-wal");
            let wal_name =
                CString::new(name).map_err(|_| io::Error::other("scoped VFS WAL filename"))?;
            let mut journal_path = main_path.as_os_str().to_owned();
            journal_path.push("-journal");
            if !journal.matches_path(std::path::Path::new(&journal_path))?
                || journal.parent_key()? != main.parent_key()?
            {
                return Err(io::Error::other(
                    "actual precreated rollback Journal binding differs",
                ));
            }
            let journal_name = CString::new(
                journal_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("original rollback path encoding"))?,
            )
            .map_err(|_| io::Error::other("original rollback filename"))?;
            let registration = OriginalSqliteVfs::register(ApprovedFiles {
                main_name,
                wal_name,
                journal_name,
                main: main.key()?,
                wal: wal.key()?,
                journal: journal.key()?,
                limits,
            })?;
            let name = registration
                .name()
                .to_str()
                .map_err(|_| io::Error::other("private VFS name encoding"))?;
            let connection = rusqlite::Connection::open_with_flags_and_vfs(
                uri,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                name,
            )
            .map_err(|_| io::Error::other("scoped original VFS connection refused"))?;
            if registration.refused_effect()
                || crate::sqlite_main_file_identity(&connection)? != main.key()?
            {
                return Err(io::Error::other("scoped VFS main identity refused"));
            }
            Ok((connection, registration))
        };
        let (connection, registration) = match attempt() {
            Ok(value) => value,
            Err(error) => return Err(Box::new((main, wal, journal, error))),
        };
        Ok(Self {
            connection: Some(connection),
            registration,
            main,
            wal,
            journal,
            write_attempted: false,
        })
    }
    /// Only the crate's private recovery issuer calls this after all current
    /// roots/archive/ledger/content budgets have been re-established.
    pub(super) fn prepare_wal(&mut self, accepted: &[u8], version: u32) -> io::Result<()> {
        self.verify()?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite closed"))?;
        let (actual, bytes) = crate::sqlite_main_exact_bytes(connection, accepted.len() as u64)?;
        if actual != self.main.key()? || bytes != accepted || accepted.get(18..20) != Some(&[1, 1])
        {
            return Err(io::Error::other(
                "accepted standalone main differs before VFS effects",
            ));
        }
        // SAFETY: live same-thread connection; documented scalar limit.
        // Disabling ATTACH closes the in-memory bypass as well as file names.
        unsafe {
            ffi::sqlite3_limit(connection.handle(), ffi::SQLITE_LIMIT_ATTACHED, 0);
        }
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(io::Error::other)?;
        let actual_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(io::Error::other)?;
        if actual_version != version {
            return Err(io::Error::other("exact admitted original schema differs"));
        }
        connection
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(io::Error::other)?;
        // Persist the already-owned rollback file used for 1/1 -> WAL header change.
        connection
            .pragma_update(None, "journal_mode", "PERSIST")
            .map_err(io::Error::other)?;
        crate::sqlite_retain_actual_wal(connection)?;
        // Limit exact-object rollback invalidation to this admitted main-header
        // transition. Every other SQLite deletion request continues to refuse.
        self.registration.policy.rollback_reset_authorized.set(true);
        let change_mode = connection.pragma_update(None, "journal_mode", "WAL");
        self.registration
            .policy
            .rollback_reset_authorized
            .set(false);
        change_mode.map_err(io::Error::other)?;
        // The reset duplicate is needed only during the admitted WAL transition.
        // Relinquish its old SQLite share settings after successful invalidation;
        // the retained original identity and parent witnesses stay live.
        self.registration.policy.opened_rollback.borrow_mut().take();
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(io::Error::other)?;
        connection
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .map_err(io::Error::other)?;
        if crate::sqlite_wal_file_identity(connection)? != self.wal.key()? {
            return Err(io::Error::other("original WAL actual VFS handle differs"));
        }
        let (actual, current) = crate::sqlite_main_exact_bytes(connection, accepted.len() as u64)?;
        if actual != self.main.key()?
            || current.len() != accepted.len()
            || current.get(18..20) != Some(&[2, 2])
        {
            return Err(io::Error::other("actual WAL main header not established"));
        }
        // Header counters may change with SQLite's transaction; full typed row
        // equality must be audited independently by the Journal adapter.
        self.verify()
    }

    /// Exactly one originally admitted write attempt. On failure preserve the
    /// connection and actual native originals for explicit close/recovery.
    pub(super) fn one_write_attempt<T>(
        &mut self,
        operation: impl FnOnce(&rusqlite::Connection) -> io::Result<T>,
    ) -> io::Result<T> {
        self.verify()?;
        if self.write_attempted {
            return Err(io::Error::other(
                "single original write attempt already consumed",
            ));
        }
        self.write_attempted = true;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite closed"))?;
        // This consumes the private issuer once. The independent VFS policy still
        // permits only the exact precreated objects within their admitted bounds.
        let result = operation(connection);
        self.main.verify()?;
        self.wal.verify()?;
        self.journal.verify()?;
        if crate::sqlite_main_file_identity(connection)? != self.main.key()?
            || crate::sqlite_wal_file_identity(connection)? != self.wal.key()?
        {
            return Err(io::Error::other(
                "actual main/WAL changed during single write attempt",
            ));
        }
        result
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        if self.registration.refused_effect() {
            return Err(io::Error::other("unapproved SQLite VFS effect"));
        }
        self.main.verify()?;
        self.wal.verify()?;
        self.journal.verify()?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("scoped SQLite closed"))?;
        if crate::sqlite_main_file_identity(connection)? != self.main.key()? {
            return Err(io::Error::other("scoped original SQLite main changed"));
        }
        Ok(())
    }
}

impl ScopedOriginalSqlite {
    /// Close uncertainty returns the same actual connection, registration and
    /// original object witnesses. No drop/reopen path can invent completion.
    pub(super) fn close(
        mut self,
    ) -> Result<
        (
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
        ),
        (Box<Self>, io::Error),
    > {
        if let Err(error) = self
            .main
            .verify()
            .and_then(|_| self.wal.verify())
            .and_then(|_| self.journal.verify())
        {
            return Err((Box::new(self), error));
        }
        let finish = || -> io::Result<()> {
            if self.registration.refused_effect() {
                return Err(io::Error::other(
                    "refused original VFS cannot complete close",
                ));
            }
            let connection = self
                .connection
                .as_ref()
                .ok_or_else(|| io::Error::other("original SQLite connection already closed"))?;
            if !connection.is_autocommit() {
                return Err(io::Error::other(
                    "original SQLite close requires ended transaction",
                ));
            }
            // SQLite checkpoints the WAL while it still owns the exclusive
            // main handle, then uses the exact precreated rollback file for its
            // standalone-header transaction. PERSIST_WAL retains the original
            // WAL object, and PERSIST retains the original rollback object.
            let mode: String = connection
                .query_row("PRAGMA main.journal_mode=PERSIST", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            if mode != "persist" || !connection.is_autocommit() {
                return Err(io::Error::other("standalone original close format refused"));
            }
            let (key, bytes) =
                crate::sqlite_main_exact_bytes(connection, self.registration.policy.limits[0])?;
            if key != self.main.key()? || bytes.get(18..20) != Some(&[1, 1]) {
                return Err(io::Error::other("standalone original main header differs"));
            }
            self.main.verify()?;
            self.wal.verify()?;
            self.journal.verify()?;
            if self.registration.refused_effect() {
                return Err(io::Error::other("original close VFS effect refused"));
            }
            Ok(())
        };
        if let Err(error) = finish() {
            return Err((Box::new(self), error));
        }
        let Some(connection) = self.connection.take() else {
            return Err((
                Box::new(self),
                io::Error::other("original SQLite connection already closed"),
            ));
        };
        if let Err((connection, error)) = connection.close() {
            self.connection = Some(connection);
            return Err((Box::new(self), io::Error::other(error.to_string())));
        }
        let Self {
            connection: _,
            registration,
            main,
            wal,
            journal,
            write_attempted: _,
        } = self;
        // No Connection still owns a sqlite3_file referencing this private table.
        drop(registration);
        Ok((main, wal, journal))
    }
}

impl ScopedOriginalSqlite {
    pub(super) fn checkpoint(&mut self) -> io::Result<()> {
        self.verify()?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite closed"))?;
        let result = connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, i32>(1)?,
                row.get::<_, i32>(2)?,
            ))
        });
        let result = result.map_err(io::Error::other)?;
        if result.0 != 0 {
            return Err(io::Error::other("actual original WAL checkpoint busy"));
        }
        self.verify()
    }
}

/// This bridge owns the actual connection and unique registration together.
/// Caller-created numeric identity evidence can never construct it.
pub struct OriginalSqliteConnection {
    original: ScopedOriginalSqlite,
    write_bytes: u64,
    uncertain: std::cell::Cell<bool>,
}
pub enum OriginalSqliteOpenFailure {
    Prepared {
        main: Box<crate::OriginalSqliteMainHandoff>,
        wal: Box<crate::OriginalSqliteSidecarHandoff>,
        rollback: Box<crate::OriginalSqliteSidecarHandoff>,
        error: io::Error,
    },
    MainReleased {
        main: Box<crate::ReleasedOriginalFileIdentity>,
        wal: Box<crate::OriginalSqliteSidecarHandoff>,
        rollback: Box<crate::OriginalSqliteSidecarHandoff>,
        error: io::Error,
    },
    WalReleased {
        main: Box<crate::ReleasedOriginalFileIdentity>,
        wal: Box<crate::ReleasedOriginalFileIdentity>,
        rollback: Box<crate::OriginalSqliteSidecarHandoff>,
        error: io::Error,
    },
    Released {
        main: Box<crate::ReleasedOriginalFileIdentity>,
        wal: Box<crate::ReleasedOriginalFileIdentity>,
        rollback: Box<crate::ReleasedOriginalFileIdentity>,
        error: io::Error,
    },
    Open {
        original: Box<OriginalSqliteConnection>,
        error: io::Error,
    },
}
#[derive(Clone)]
pub enum OriginalSqliteValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}
impl OriginalSqliteValue {
    fn bytes(&self) -> io::Result<u64> {
        let size = match self {
            Self::Null => 0,
            Self::Integer(_) | Self::Real(_) => 8,
            Self::Text(value) => value.len() as u64,
            Self::Blob(value) => value.len() as u64,
        };
        if size > 16 * 1024 * 1024 {
            return Err(io::Error::other("original SQLite value byte budget"));
        }
        Ok(size)
    }
    fn owned(&self) -> rusqlite::types::Value {
        match self {
            Self::Null => rusqlite::types::Value::Null,
            Self::Integer(value) => rusqlite::types::Value::Integer(*value),
            Self::Real(value) => rusqlite::types::Value::Real(*value),
            Self::Text(value) => rusqlite::types::Value::Text(value.clone()),
            Self::Blob(value) => rusqlite::types::Value::Blob(value.clone()),
        }
    }
}
/// Exact single SQLite statement and owned values. No transaction-control,
/// ATTACH, PRAGMA, DDL, extension or file-system capability is authorized.
pub struct OriginalSqliteStatement {
    pub sql: String,
    pub parameters: Vec<OriginalSqliteValue>,
    pub expected_changed_rows: u64,
}

impl OriginalSqliteConnection {
    /// Consume all three original CREATE capabilities. Exact protected accepted
    /// bytes and limits are checked before releasing the main read protection.
    pub fn open(
        main: crate::OriginalSqliteMainHandoff,
        wal: crate::OriginalSqliteSidecarHandoff,
        rollback: crate::OriginalSqliteSidecarHandoff,
        accepted: &[u8],
        version: u32,
        limits: [u64; 3],
        max_write_bytes: u64,
    ) -> Result<Self, OriginalSqliteOpenFailure> {
        let before = || -> io::Result<std::path::PathBuf> {
            main.verify()?;
            wal.verify()?;
            rollback.verify()?;
            if !(512..=256 * 1024 * 1024).contains(&accepted.len())
                || accepted.get(..16) != Some(b"SQLite format 3\0")
                || accepted.get(18..20) != Some(&[1, 1])
                || main.exact_protected_bytes(accepted.len() as u64)? != accepted
                || max_write_bytes == 0
                || max_write_bytes > 16 * 1024 * 1024
                || limits
                    .iter()
                    .any(|value| *value < 512 || *value > 256 * 1024 * 1024)
                || limits
                    .iter()
                    .try_fold(0u64, |sum, value| sum.checked_add(*value))
                    .is_none_or(|sum| sum > 512 * 1024 * 1024)
                || accepted.len() as u64 > limits[0]
                || wal.parent_key()? != main.parent_key()?
                || rollback.parent_key()? != main.parent_key()?
            {
                return Err(io::Error::other(
                    "sealed original SQLite acceptance and aggregate bounds",
                ));
            }
            let path = main.path().to_owned();
            super::uri::original_sqlite_uri(&path)?;
            let mut expected = path.as_os_str().to_owned();
            expected.push("-wal");
            if wal.path() != std::path::Path::new(&expected) {
                return Err(io::Error::other("original WAL path binding"));
            }
            let mut expected = path.as_os_str().to_owned();
            expected.push("-journal");
            if rollback.path() != std::path::Path::new(&expected) {
                return Err(io::Error::other("original rollback path binding"));
            }
            let mut shm = path.as_os_str().to_owned();
            shm.push("-shm");
            match std::fs::symlink_metadata(std::path::Path::new(&shm)) {
                Ok(_) => {
                    return Err(io::Error::other(
                        "foreign SHM present before original SQLite effects",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            Ok(path)
        };
        let path = match before() {
            Ok(value) => value,
            Err(error) => {
                return Err(OriginalSqliteOpenFailure::Prepared {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                })
            }
        };
        let uri = match super::uri::original_sqlite_uri(&path) {
            Ok(value) => value,
            Err(error) => {
                return Err(OriginalSqliteOpenFailure::Prepared {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                })
            }
        };
        let main = match main.consume_for_vfs() {
            Ok(value) => value,
            Err((main, error)) => {
                let main = *main;
                return Err(OriginalSqliteOpenFailure::Prepared {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                });
            }
        };
        let parent = match main.parent_key() {
            Ok(value) => value,
            Err(error) => {
                return Err(OriginalSqliteOpenFailure::MainReleased {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                })
            }
        };
        let wal = match wal.consume_for_vfs(&path, crate::OriginalSqliteSidecarKind::Wal, parent) {
            Ok(value) => value,
            Err((wal, error)) => {
                let wal = *wal;
                return Err(OriginalSqliteOpenFailure::MainReleased {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                });
            }
        };
        let rollback = match rollback.consume_for_vfs(
            &path,
            crate::OriginalSqliteSidecarKind::Rollback,
            parent,
        ) {
            Ok(value) => value,
            Err((rollback, error)) => {
                let rollback = *rollback;
                return Err(OriginalSqliteOpenFailure::WalReleased {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                });
            }
        };
        let original = match ScopedOriginalSqlite::open(&uri, &path, main, wal, rollback, limits) {
            Ok(value) => value,
            Err(failed) => {
                let (main, wal, rollback, error) = *failed;
                return Err(OriginalSqliteOpenFailure::Released {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                });
            }
        };
        let mut owner = Self {
            original,
            write_bytes: max_write_bytes,
            uncertain: std::cell::Cell::new(false),
        };
        if let Err(error) = owner.original.prepare_wal(accepted, version) {
            return Err(OriginalSqliteOpenFailure::Open {
                original: Box::new(owner),
                error,
            });
        }
        Ok(owner)
    }
    pub fn verify(&self) -> io::Result<()> {
        if self.uncertain.get() {
            return Err(io::Error::other(
                "original SQLite terminal uncertainty closes issuance",
            ));
        }
        self.original.verify()
    }
    pub fn actual_native_keys(&self) -> io::Result<[FileKey; 3]> {
        self.verify()?;
        let connection = self
            .original
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite closed"))?;
        let main = crate::sqlite_main_file_identity(connection)?;
        let wal = crate::sqlite_wal_file_identity(connection)?;
        let rollback = self.original.journal.key()?;
        if main != self.original.main.key()? || wal != self.original.wal.key()? {
            return Err(io::Error::other(
                "actual sealed SQLite main/WAL objects changed",
            ));
        }
        Ok([main, wal, rollback])
    }
    /// One bounded DML transaction, one consume-attempt; failure never retries.
    /// SQL authorization is implemented below and denied before every statement.
    pub fn execute_one_transaction(
        &mut self,
        statements: &[OriginalSqliteStatement],
    ) -> io::Result<Vec<u64>> {
        if statements.is_empty() || statements.len() > 1024 {
            return Err(io::Error::other("original SQLite statement count budget"));
        }
        let bytes = statements.iter().try_fold(0u64, |sum, statement| {
            if statement.sql.is_empty()
                || statement.sql.len() > 64 * 1024
                || statement.sql.contains('\0')
                || statement.parameters.len() > 1024
            {
                return Err(io::Error::other("original SQLite statement bound"));
            }
            statement.parameters.iter().try_fold(
                sum.checked_add(statement.sql.len() as u64)
                    .ok_or_else(|| io::Error::other("original SQLite SQL byte overflow"))?,
                |sum, value| {
                    sum.checked_add(value.bytes()?)
                        .ok_or_else(|| io::Error::other("original SQLite parameter bytes overflow"))
                },
            )
        })?;
        if bytes > self.write_bytes {
            return Err(io::Error::other(
                "original SQLite transaction aggregate byte budget",
            ));
        }
        self.verify()?;
        if self.original.write_attempted {
            return Err(io::Error::other(
                "original SQLite single write issuance already consumed",
            ));
        }
        let result=self.original.one_write_attempt(|connection|{
            // Prepare and bind the whole exact list before BEGIN can create WAL
            // transaction effects. Every statement belongs to the same owner.
            let mut prepared=Vec::with_capacity(statements.len());
            {
                let _authorization=OriginalDmlAuthorization::install(connection)?;
                let _progress=OriginalVmBudget::install(connection,100_000_000,60)?;
                for item in statements {
                    let mut statement=connection.prepare(&item.sql).map_err(io::Error::other)?;
                    if statement.readonly() || statement.column_count()!=0
                        || statement.parameter_count()!=item.parameters.len() {
                        return Err(io::Error::other("original DML expected bound mutable statement"));
                    }
                    for (index,value) in item.parameters.iter().enumerate(){
                        statement.raw_bind_parameter(index+1,value.owned()).map_err(io::Error::other)?;
                    }
                    prepared.push(statement);
                }
            }
            connection.execute_batch("BEGIN IMMEDIATE").map_err(io::Error::other)?;
            let result=(||->io::Result<Vec<u64>> {
                let _authorization=OriginalDmlAuthorization::install(connection)?;
                let _progress=OriginalVmBudget::install(connection,100_000_000,60)?;
                let mut changed=Vec::with_capacity(statements.len());
                for (statement,item) in prepared.iter_mut().zip(statements) {
                    let count=statement.raw_execute().map_err(io::Error::other)?;
                    if count as u64!=item.expected_changed_rows{
                        return Err(io::Error::other("original SQLite expected changed-row count differs"));
                    }
                    changed.push(count as u64);
                }
                Ok(changed)
            })();
            drop(prepared);
            match result{
                Ok(changed)=>{
                    // Authorizer is released before SQLite transaction control.
                    let _progress=OriginalVmBudget::install(connection,100_000_000,60)?;
                    connection.execute_batch("COMMIT").map_err(io::Error::other)?;
                    Ok(changed)
                },
                Err(error)=>{
                    if let Err(rollback)=connection.execute_batch("ROLLBACK"){
                        return Err(io::Error::other(format!("original SQLite write refused: {error}; rollback uncertain: {rollback}")));
                    }
                    Err(error)
                }
            }
        });
        if result.is_err() {
            self.uncertain.set(true);
        }
        result
    }
    pub fn checkpoint(&mut self) -> io::Result<()> {
        self.verify()?;
        let result = self.original.checkpoint();
        if result.is_err() {
            self.uncertain.set(true);
        }
        result
    }
    pub fn close(self) -> Result<[crate::ReleasedOriginalFileIdentity; 3], (Box<Self>, io::Error)> {
        let Self {
            original,
            write_bytes,
            uncertain,
        } = self;
        match original.close() {
            Ok((main, wal, rollback)) => Ok([main, wal, rollback]),
            Err((original, error)) => Err((
                Box::new(Self {
                    original: *original,
                    write_bytes,
                    uncertain,
                }),
                error,
            )),
        }
    }
}

struct OriginalDmlAuthorization<'a> {
    connection: &'a rusqlite::Connection,
}
unsafe extern "C" fn authorize_dml(
    _data: *mut std::ffi::c_void,
    action: i32,
    _first: *const std::ffi::c_char,
    _second: *const std::ffi::c_char,
    database: *const std::ffi::c_char,
    _origin: *const std::ffi::c_char,
) -> i32 {
    // Reject unknown actions and all DDL, ATTACH/DETACH, PRAGMA, explicit
    // transaction controls, functions/extensions and non-main databases.
    if !matches!(
        action,
        ffi::SQLITE_INSERT
            | ffi::SQLITE_UPDATE
            | ffi::SQLITE_DELETE
            | ffi::SQLITE_READ
            | ffi::SQLITE_SELECT
            | ffi::SQLITE_RECURSIVE
    ) {
        return ffi::SQLITE_DENY;
    }
    if !database.is_null() {
        // SAFETY: SQLite's authorizer supplies terminated strings valid for callback.
        let name = unsafe { CStr::from_ptr(database) };
        if name.to_bytes() != b"main" {
            return ffi::SQLITE_DENY;
        }
    }
    ffi::SQLITE_OK
}
impl<'a> OriginalDmlAuthorization<'a> {
    fn install(connection: &'a rusqlite::Connection) -> io::Result<Self> {
        // SAFETY: connection is live, single-threaded and callback uses no user pointer.
        let result = unsafe {
            ffi::sqlite3_set_authorizer(connection.handle(), Some(authorize_dml), ptr::null_mut())
        };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other(
                "original DML authorization install refused",
            ));
        }
        Ok(Self { connection })
    }
}
impl Drop for OriginalDmlAuthorization<'_> {
    fn drop(&mut self) {
        // SAFETY: guard cannot outlive borrowed same-thread Connection; restore no authorizer.
        unsafe {
            ffi::sqlite3_set_authorizer(self.connection.handle(), None, ptr::null_mut());
        }
    }
}

#[derive(Clone, Copy)]
pub struct OriginalSqliteReadBudget {
    pub max_queries: usize,
    pub max_rows: usize,
    pub max_columns: usize,
    pub max_owned_bytes: u64,
    pub max_vm_instructions: u64,
    pub max_seconds: u64,
}
pub struct OriginalSqliteQuery {
    pub sql: String,
    pub parameters: Vec<OriginalSqliteValue>,
}
pub struct OriginalSqliteRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<OriginalSqliteValue>>,
}
impl OriginalSqliteConnection {
    /// Snapshot returns only bounded owned cell values. No Connection, Statement,
    /// Row, VFS, File or native handle is returned to application code.
    pub fn read_queries(
        &self,
        queries: &[OriginalSqliteQuery],
        budget: OriginalSqliteReadBudget,
    ) -> io::Result<Vec<OriginalSqliteRows>> {
        self.verify()?;
        if queries.is_empty()
            || budget.max_queries == 0
            || budget.max_queries > 1024
            || queries.len() > budget.max_queries
            || budget.max_rows == 0
            || budget.max_rows > 1_000_000
            || budget.max_columns == 0
            || budget.max_columns > 1024
            || budget.max_owned_bytes == 0
            || budget.max_owned_bytes > 256 * 1024 * 1024
            || budget.max_vm_instructions < 1000
            || budget.max_vm_instructions > 100_000_000
            || budget.max_seconds == 0
            || budget.max_seconds > 60
        {
            return Err(io::Error::other(
                "original SQLite read snapshot explicit bounds",
            ));
        }
        let connection = self
            .original
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite closed"))?;
        let mut owned = 0u64;
        let mut cells = 0usize;
        let mut count = 0usize;
        let mut output = Vec::with_capacity(queries.len());
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(io::Error::other)?;
        let result = (|| -> io::Result<()> {
            let _authorizer = OriginalReadAuthorization::install(connection)?;
            let _progress = OriginalVmBudget::install(
                connection,
                budget.max_vm_instructions,
                budget.max_seconds,
            )?;
            for query in queries {
                if query.sql.is_empty()
                    || query.sql.len() > 64 * 1024
                    || query.sql.contains('\0')
                    || query.parameters.len() > 1024
                {
                    return Err(io::Error::other("original SQLite read query bounds"));
                }
                owned = owned
                    .checked_add(query.sql.len() as u64)
                    .ok_or_else(|| io::Error::other("original read SQL bytes overflow"))?;
                for value in &query.parameters {
                    owned = owned.checked_add(value.bytes()?).ok_or_else(|| {
                        io::Error::other("original read parameter bytes overflow")
                    })?;
                }
                if owned > budget.max_owned_bytes {
                    return Err(io::Error::other("original read input byte bound"));
                }
                let values: Vec<_> = query
                    .parameters
                    .iter()
                    .map(OriginalSqliteValue::owned)
                    .collect();
                let mut statement = connection.prepare(&query.sql).map_err(io::Error::other)?;
                if !statement.readonly()
                    || statement.column_count() == 0
                    || statement.column_count() > budget.max_columns
                {
                    return Err(io::Error::other(
                        "original read query must be bounded readonly columns",
                    ));
                }
                let columns: Vec<_> = statement.column_names().map(str::to_owned).collect();
                for name in &columns {
                    owned = owned
                        .checked_add(name.len() as u64 + 32)
                        .ok_or_else(|| io::Error::other("original read column byte overflow"))?;
                }
                if owned > budget.max_owned_bytes {
                    return Err(io::Error::other("original read column byte bound"));
                }
                let mut rows = statement
                    .query(rusqlite::params_from_iter(values))
                    .map_err(io::Error::other)?;
                let mut current = Vec::new();
                while let Some(row) = rows.next().map_err(io::Error::other)? {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("original read row overflow"))?;
                    if count > budget.max_rows {
                        return Err(io::Error::other("original read row limit"));
                    }
                    let mut row_values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        let borrowed = row.get_ref(index).map_err(io::Error::other)?;
                        let bytes = match borrowed {
                            rusqlite::types::ValueRef::Null => 0,
                            rusqlite::types::ValueRef::Integer(_)
                            | rusqlite::types::ValueRef::Real(_) => 8,
                            rusqlite::types::ValueRef::Text(value)
                            | rusqlite::types::ValueRef::Blob(value) => value.len() as u64,
                        };
                        owned = owned
                            .checked_add(bytes + 32)
                            .ok_or_else(|| io::Error::other("original read cell byte overflow"))?;
                        cells = cells
                            .checked_add(1)
                            .ok_or_else(|| io::Error::other("original read cell count overflow"))?;
                        if owned > budget.max_owned_bytes {
                            return Err(io::Error::other(
                                "original read output byte bound before clone",
                            ));
                        }
                        let value = match borrowed {
                            rusqlite::types::ValueRef::Null => OriginalSqliteValue::Null,
                            rusqlite::types::ValueRef::Integer(value) => {
                                OriginalSqliteValue::Integer(value)
                            }
                            rusqlite::types::ValueRef::Real(value) if value.is_finite() => {
                                OriginalSqliteValue::Real(value)
                            }
                            rusqlite::types::ValueRef::Real(_) => {
                                return Err(io::Error::other("original read nonfinite real"))
                            }
                            rusqlite::types::ValueRef::Text(value) => OriginalSqliteValue::Text(
                                std::str::from_utf8(value)
                                    .map_err(io::Error::other)?
                                    .to_owned(),
                            ),
                            rusqlite::types::ValueRef::Blob(value) => {
                                OriginalSqliteValue::Blob(value.to_vec())
                            }
                        };
                        row_values.push(value);
                    }
                    current.push(row_values);
                }
                output.push(OriginalSqliteRows {
                    columns,
                    rows: current,
                });
            }
            Ok(())
        })();
        // All statements/rows and callbacks have been dropped before rollback.
        let rollback = connection
            .execute_batch("ROLLBACK")
            .map_err(io::Error::other);
        if let Err(error) = rollback {
            self.uncertain.set(true);
            return Err(io::Error::other(format!(
                "original read snapshot rollback uncertain: {error}"
            )));
        }
        result?;
        self.verify()?;
        let _ = cells;
        Ok(output)
    }
}
struct OriginalReadAuthorization<'a> {
    connection: &'a rusqlite::Connection,
}
unsafe extern "C" fn authorize_read(
    _data: *mut std::ffi::c_void,
    action: i32,
    _first: *const std::ffi::c_char,
    _second: *const std::ffi::c_char,
    database: *const std::ffi::c_char,
    _origin: *const std::ffi::c_char,
) -> i32 {
    if !matches!(
        action,
        ffi::SQLITE_READ | ffi::SQLITE_SELECT | ffi::SQLITE_RECURSIVE
    ) {
        return ffi::SQLITE_DENY;
    }
    if !database.is_null() {
        // SAFETY: SQLite authorizer owns terminated database text during callback.
        if unsafe { CStr::from_ptr(database) }.to_bytes() != b"main" {
            return ffi::SQLITE_DENY;
        }
    }
    ffi::SQLITE_OK
}
impl<'a> OriginalReadAuthorization<'a> {
    fn install(connection: &'a rusqlite::Connection) -> io::Result<Self> {
        // SAFETY: live single-threaded borrowed connection; no callback user data.
        let result = unsafe {
            ffi::sqlite3_set_authorizer(connection.handle(), Some(authorize_read), ptr::null_mut())
        };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other(
                "original readonly authorizer installation",
            ));
        }
        Ok(Self { connection })
    }
}
impl Drop for OriginalReadAuthorization<'_> {
    fn drop(&mut self) {
        // SAFETY: same live connection retained by guard's lifetime.
        unsafe {
            ffi::sqlite3_set_authorizer(self.connection.handle(), None, ptr::null_mut());
        }
    }
}
struct OriginalVmState {
    remaining: std::sync::atomic::AtomicU64,
    deadline: std::time::Instant,
}
struct OriginalVmBudget<'a> {
    connection: &'a rusqlite::Connection,
    state: Box<OriginalVmState>,
}
unsafe extern "C" fn original_progress(data: *mut std::ffi::c_void) -> i32 {
    if data.is_null() {
        return 1;
    }
    // SAFETY: guard owns stable boxed state for all callbacks; reset before drop.
    let state = unsafe { &*data.cast::<OriginalVmState>() };
    if std::time::Instant::now() >= state.deadline {
        return 1;
    }
    if state
        .remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_sub(1000)
        })
        .is_err()
    {
        return 1;
    }
    0
}
impl<'a> OriginalVmBudget<'a> {
    fn install(
        connection: &'a rusqlite::Connection,
        instructions: u64,
        seconds: u64,
    ) -> io::Result<Self> {
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(seconds))
            .ok_or_else(|| io::Error::other("original VM deadline overflow"))?;
        let mut state = Box::new(OriginalVmState {
            remaining: std::sync::atomic::AtomicU64::new(instructions),
            deadline,
        });
        // SAFETY: boxed state address stays stable in returned owner; synchronous
        // connection cannot outlive guard; only guard resets this dedicated hook.
        unsafe {
            ffi::sqlite3_progress_handler(
                connection.handle(),
                1000,
                Some(original_progress),
                ptr::from_mut(&mut *state).cast(),
            );
        }
        Ok(Self { connection, state })
    }
}
impl Drop for OriginalVmBudget<'_> {
    fn drop(&mut self) {
        // SAFETY: reset callback before releasing boxed state.
        unsafe {
            ffi::sqlite3_progress_handler(self.connection.handle(), 0, None, ptr::null_mut());
        }
        let _ = &self.state;
    }
}

impl OriginalSqliteConnection {
    /// An exact bounded whole-catalog transition generated by the private
    /// Journal planner. Existing single-write fixtures keep their contract.
    /// The actual native connection, VFS and original objects never escape.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_admitted_rows(
        &mut self,
        statements: &[OriginalSqliteStatement],
        queries: &[OriginalSqliteQuery],
        before: &[OriginalSqliteRows],
        after: &[OriginalSqliteRows],
        budget: OriginalSqliteReadBudget,
    ) -> io::Result<()> {
        self.verify()?;
        if !self.original.write_attempted
            || statements.is_empty()
            || statements.len() > 1024
            || queries.len() != before.len()
            || queries.len() != after.len()
            || queries.is_empty()
        {
            return Err(io::Error::other(
                "original continuous exact row transition bounds",
            ));
        }
        let bytes = statements.iter().try_fold(0u64, |sum, statement| {
            if statement.sql.is_empty()
                || statement.sql.len() > 64 * 1024
                || statement.parameters.len() > 1024
                || statement.sql.contains('\0')
            {
                return Err(io::Error::other("admitted original statement bounds"));
            }
            statement.parameters.iter().try_fold(
                sum.checked_add(statement.sql.len() as u64)
                    .ok_or_else(|| io::Error::other("admitted original SQL overflow"))?,
                |sum, value| {
                    sum.checked_add(value.bytes()?)
                        .ok_or_else(|| io::Error::other("admitted original parameter overflow"))
                },
            )
        })?;
        if bytes > self.write_bytes {
            return Err(io::Error::other(
                "original continuous cumulative write bytes",
            ));
        }
        // Every attempt consumes its complete encoded budget, including failure.
        self.write_bytes -= bytes;
        let connection = self
            .original
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("original actual connection closed"))?;
        for &name in original_ordinary_rejecting_callbacks() {
            if !name.starts_with("sync_")
                || name.len() > 128
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(io::Error::other("original rejecting function exact name"));
            }
            connection
                .create_scalar_function(
                    name,
                    -1,
                    rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                    |_| Ok(false),
                )
                .map_err(io::Error::other)?;
        }
        validate_ordinary_whole_catalog(connection, queries)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(io::Error::other)?;
        let result = (|| -> io::Result<()> {
            admitted_query_rows(connection, queries, before, budget)?;
            {
                let _progress = OriginalVmBudget::install(
                    connection,
                    budget.max_vm_instructions,
                    budget.max_seconds,
                )?;
                let _authorizer = AdmittedDmlAuthorization::install(connection)?;
                for item in statements {
                    let mut statement = connection.prepare(&item.sql).map_err(io::Error::other)?;
                    if statement.readonly()
                        || statement.column_count() != 0
                        || statement.parameter_count() != item.parameters.len()
                    {
                        return Err(io::Error::other("admitted original bounded DML required"));
                    }
                    let values: Vec<_> = item
                        .parameters
                        .iter()
                        .map(OriginalSqliteValue::owned)
                        .collect();
                    let changed = statement
                        .execute(rusqlite::params_from_iter(values))
                        .map_err(io::Error::other)?;
                    if changed as u64 != item.expected_changed_rows {
                        return Err(io::Error::other("admitted original exact changed rows"));
                    }
                }
            }
            admitted_query_rows(connection, queries, after, budget)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                if let Err(error) = connection.execute_batch("COMMIT") {
                    self.uncertain.set(true);
                    return Err(io::Error::other(error));
                }
                self.verify()?;
                Ok(())
            }
            Err(error) => {
                if connection.execute_batch("ROLLBACK").is_err() {
                    self.uncertain.set(true);
                    return Err(io::Error::other("admitted original rollback uncertain"));
                }
                // A failed actual native attempt closes further issuance.
                self.uncertain.set(true);
                Err(error)
            }
        }
    }
}

fn admitted_query_rows(
    connection: &rusqlite::Connection,
    queries: &[OriginalSqliteQuery],
    expected: &[OriginalSqliteRows],
    budget: OriginalSqliteReadBudget,
) -> io::Result<()> {
    if queries.len() != expected.len()
        || queries.len() > budget.max_queries
        || budget.max_queries == 0
        || budget.max_queries > 1024
        || budget.max_rows == 0
        || budget.max_rows > 1_000_000
        || budget.max_columns == 0
        || budget.max_columns > 1024
        || budget.max_owned_bytes == 0
        || budget.max_owned_bytes > 256 * 1024 * 1024
    {
        return Err(io::Error::other("admitted original whole row audit budget"));
    }
    let _progress =
        OriginalVmBudget::install(connection, budget.max_vm_instructions, budget.max_seconds)?;
    let _authorizer = OriginalReadAuthorization::install(connection)?;
    let mut bytes = 0u64;
    let mut rows = 0usize;
    for (query, expected) in queries.iter().zip(expected) {
        if query.sql.is_empty() || query.sql.len() > 64 * 1024 || query.parameters.len() > 1024 {
            return Err(io::Error::other("admitted original audit query bound"));
        }
        let mut statement = connection.prepare(&query.sql).map_err(io::Error::other)?;
        if !statement.readonly()
            || statement.column_count() == 0
            || statement.column_count() > budget.max_columns
            || statement.column_names().collect::<Vec<_>>()
                != expected
                    .columns
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
        {
            return Err(io::Error::other("admitted original audit columns"));
        }
        let values: Vec<_> = query
            .parameters
            .iter()
            .map(OriginalSqliteValue::owned)
            .collect();
        let mut actual = statement
            .query(rusqlite::params_from_iter(values))
            .map_err(io::Error::other)?;
        for expected_row in &expected.rows {
            let row = actual
                .next()
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other("admitted original missing row"))?;
            rows = rows
                .checked_add(1)
                .filter(|n| *n <= budget.max_rows)
                .ok_or_else(|| io::Error::other("admitted original audit rows"))?;
            if expected_row.len() != expected.columns.len() {
                return Err(io::Error::other("admitted original row columns"));
            }
            for (index, expected_cell) in expected_row.iter().enumerate() {
                bytes = bytes
                    .checked_add(expected_cell.bytes()? + 32)
                    .filter(|n| *n <= budget.max_owned_bytes)
                    .ok_or_else(|| io::Error::other("admitted original row bytes"))?;
                let value = row.get_ref(index).map_err(io::Error::other)?;
                let same = match (value, expected_cell) {
                    (rusqlite::types::ValueRef::Null, OriginalSqliteValue::Null) => true,
                    (rusqlite::types::ValueRef::Integer(a), OriginalSqliteValue::Integer(b)) => {
                        a == *b
                    }
                    (rusqlite::types::ValueRef::Real(a), OriginalSqliteValue::Real(b)) => {
                        a.to_bits() == b.to_bits()
                    }
                    (rusqlite::types::ValueRef::Text(a), OriginalSqliteValue::Text(b)) => {
                        a == b.as_bytes()
                    }
                    (rusqlite::types::ValueRef::Blob(a), OriginalSqliteValue::Blob(b)) => a == b,
                    _ => false,
                };
                if !same {
                    return Err(io::Error::other("admitted original changed exact cell"));
                }
            }
        }
        if actual.next().map_err(io::Error::other)?.is_some() {
            return Err(io::Error::other("admitted original extra row"));
        }
    }
    Ok(())
}
struct AdmittedDmlAuthorization<'a>(&'a rusqlite::Connection);
unsafe extern "C" fn admitted_dml(
    _data: *mut std::ffi::c_void,
    action: i32,
    first: *const std::ffi::c_char,
    second: *const std::ffi::c_char,
    database: *const std::ffi::c_char,
    origin: *const std::ffi::c_char,
) -> i32 {
    if action == ffi::SQLITE_FUNCTION && !second.is_null() {
        // SAFETY: SQLite supplies its terminated function name during this callback.
        let name = unsafe { CStr::from_ptr(second) }.to_bytes();
        if matches!(
            name,
            b"length"
                | b"json_extract"
                | b"json_valid"
                | b"json_array"
                | b"json_array_length"
                | b"json_type"
                | b"coalesce"
                | b"typeof"
                | b"json"
                | b"instr"
                | b"lower"
                | b"substr"
        ) || name.starts_with(b"sync_")
        {
            return ffi::SQLITE_OK;
        }
        return ffi::SQLITE_DENY;
    }
    // Restrict every direct or trigger write to the five ordinary history tables.
    // Direct DELETE and immutable UPDATE are denied; exact original triggers are audited below.
    if matches!(
        action,
        ffi::SQLITE_INSERT | ffi::SQLITE_UPDATE | ffi::SQLITE_DELETE
    ) {
        if first.is_null() {
            return ffi::SQLITE_DENY;
        }
        // SAFETY: SQLite supplies a terminated table identifier for this callback.
        let table = unsafe { CStr::from_ptr(first) }.to_bytes();
        let allowed = if action == ffi::SQLITE_INSERT {
            matches!(
                table,
                b"operations"
                    | b"receive_cursors"
                    | b"snapshots"
                    | b"snapshot_objects"
                    | b"current_manifests"
            )
        } else if action == ffi::SQLITE_UPDATE {
            matches!(table, b"receive_cursors" | b"current_manifests")
        } else {
            false
        };
        // SQLite prepares the original AFTER snapshot pin trigger even
        // when no mark exists. Permit only its precise invalidation insert.
        // Whole-table before/after CAS still rejects any unplanned row change.
        let snapshot_pin_trigger = action == ffi::SQLITE_INSERT && table == b"gc_invalidations"
            && !origin.is_null()
            // SAFETY: SQLite supplies the terminated original trigger name.
            && unsafe { CStr::from_ptr(origin) }.to_bytes() == b"gc_snapshot_pin_insert";
        // Existing current-change trigger always prepares its DELETE.
        // Only this exact trigger may invalidate original local observations;
        // direct DELETE and unexpected actual row removal remain rejected.
        let observation_trigger = action == ffi::SQLITE_DELETE && table == b"rename_observations"
            && !origin.is_null()
            // SAFETY: SQLite owns the terminated trigger name during authorization.
            && unsafe { CStr::from_ptr(origin) }.to_bytes() == b"rename_observation_current_update";
        if !allowed && !snapshot_pin_trigger && !observation_trigger {
            return ffi::SQLITE_DENY;
        }
    }
    // SAFETY: delegate unchanged SQLite authorizer strings to the original deny-first callback.
    unsafe { authorize_dml(ptr::null_mut(), action, first, second, database, origin) }
}
impl<'a> AdmittedDmlAuthorization<'a> {
    fn install(connection: &'a rusqlite::Connection) -> io::Result<Self> {
        // SAFETY: connection is retained on the same thread; callback owns no external data.
        let result = unsafe {
            ffi::sqlite3_set_authorizer(connection.handle(), Some(admitted_dml), ptr::null_mut())
        };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other("admitted original authorizer"));
        }
        Ok(Self(connection))
    }
}
impl Drop for AdmittedDmlAuthorization<'_> {
    fn drop(&mut self) {
        // SAFETY: guard retains the actual connection until its synchronous operation ends.
        unsafe {
            ffi::sqlite3_set_authorizer(self.0.handle(), None, ptr::null_mut());
        }
    }
}

fn original_ordinary_rejecting_callbacks() -> &'static [&'static str] {
    &[
        "sync_conflict_resolution_final",
        "sync_conflict_resolution_issue",
        "sync_forwarded_page_issue",
        "sync_native_publication_issue",
        "sync_original_operation_issue",
        "sync_original_page_issue",
        "sync_remote_delete_issue",
        "sync_remote_delete_write",
        "sync_remote_rename_issue",
        "sync_remote_rename_write",
        "sync_remote_replace_issue",
        "sync_remote_replace_write",
        "sync_storage_handoff_issue",
        "sync_storage_page_issue",
        "sync_storage_retirement_cancel",
        "sync_storage_retirement_disposal_issue",
        "sync_storage_retirement_issue",
        "sync_storage_retirement_owner_issue",
        "sync_storage_retirement_owner_receipt",
        "sync_storage_retirement_payload_issue",
        "sync_storage_retirement_terminal_issue",
        "sync_storage_traffic_issue",
        "sync_tree_native_issue",
        "sync_webdav_native_cancel_issue",
        "sync_webdav_native_description_issue",
        "sync_webdav_native_execution_admission_issue",
        "sync_webdav_native_execution_binding_issue",
        "sync_webdav_native_execution_manifest_issue",
        "sync_webdav_native_execution_receipt_issue",
        "sync_webdav_native_execution_record_issue",
        "sync_webdav_native_execution_template_issue",
        "sync_webdav_native_object_issue",
        "sync_webdav_original_final_row_issue",
    ]
}

fn validate_ordinary_whole_catalog(
    connection: &rusqlite::Connection,
    queries: &[OriginalSqliteQuery],
) -> io::Result<()> {
    let first = queries
        .first()
        .ok_or_else(|| io::Error::other("ordinary history complete catalog absent"))?;
    if first.sql != "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name"
        || queries.iter().any(|query| !query.parameters.is_empty())
    {
        return Err(io::Error::other(
            "ordinary history fixed full catalog queries",
        ));
    }
    let mut names = connection
        .prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")
        .map_err(io::Error::other)?;
    let mut rows = names.query([]).map_err(io::Error::other)?;
    let mut index = 1usize;
    while let Some(row) = rows.next().map_err(io::Error::other)? {
        if index >= queries.len() || index > 1023 {
            return Err(io::Error::other("ordinary history full table count"));
        }
        let name: String = row.get(0).map_err(io::Error::other)?;
        if name.len() > 255 || name.starts_with("sqlite_") {
            return Err(io::Error::other("ordinary history exact table name"));
        }
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        let columns = connection
            .prepare(&format!("SELECT * FROM main.{quoted} LIMIT 0"))
            .map_err(io::Error::other)?;
        let count = columns.column_count();
        if count == 0 || count > 1024 {
            return Err(io::Error::other("ordinary history exact table columns"));
        }
        let order = (1..=count)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        if queries[index].sql != format!("SELECT * FROM main.{quoted} ORDER BY {order}") {
            return Err(io::Error::other(
                "ordinary history complete canonical table query",
            ));
        }
        index += 1;
    }
    if index != queries.len() {
        return Err(io::Error::other(
            "ordinary history excess or omitted table query",
        ));
    }
    Ok(())
}

// Retain the exact builtin rollback file across SQLite's logical xClose/xOpen.
// Filename and aligned builtin storage live until after the connection closes.
struct HeldRollback {
    storage: Box<[usize]>,
    filename: ffi::sqlite3_filename,
    initialized: bool,
}
impl HeldRollback {
    fn file(&self) -> *mut ffi::sqlite3_file {
        self.storage.as_ptr().cast_mut().cast()
    }
    fn prepare(policy: &Policy) -> io::Result<Self> {
        let mut parameters = [c"exclusive".as_ptr(), c"1".as_ptr()];
        // SAFETY: all strings are retained Policy CStrings; SQLite copies them
        // into its owned filename layout with one exact URI key/value pair.
        let filename = unsafe {
            ffi::sqlite3_create_filename(
                policy.main_name.as_ptr(),
                policy.journal_name.as_ptr(),
                policy.wal_name.as_ptr(),
                1,
                parameters.as_mut_ptr(),
            )
        };
        if filename.is_null() {
            return Err(io::Error::other("original rollback filename allocation"));
        }
        // SAFETY: builtin VFS lives for the process and reports positive storage.
        let size = unsafe { (*policy.base).szOsFile };
        if size <= 0 || size > 1024 * 1024 {
            // SAFETY: this pointer is the exact successful create_filename result.
            unsafe {
                ffi::sqlite3_free_filename(filename);
            }
            return Err(io::Error::other("original builtin rollback storage bound"));
        }
        Ok(Self {
            storage: vec![0; (size as usize).div_ceil(std::mem::size_of::<usize>())]
                .into_boxed_slice(),
            filename,
            initialized: false,
        })
    }
}
impl Drop for HeldRollback {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: owned storage contains the one successful builtin xOpen;
            // Policy drops only after SQLite no longer owns an outer file.
            unsafe {
                let file = self.file();
                if !(*file).pMethods.is_null() {
                    if let Some(close) = (*(*file).pMethods).xClose {
                        close(file);
                    }
                }
            }
        }
        // SAFETY: filename is our exact allocation and is freed after xClose.
        unsafe {
            ffi::sqlite3_free_filename(self.filename);
        }
    }
}

unsafe fn open_held_rollback(
    policy: &Policy,
    outer: *mut ffi::sqlite3_file,
    flags: i32,
    out: *mut i32,
) -> io::Result<()> {
    let mut held = policy.held_rollback.borrow_mut();
    if held.is_none() {
        let mut value = HeldRollback::prepare(policy)?;
        // SAFETY: retained builtin VFS and owned SQLite filename layout; its
        // journal pointer preserves the exact exclusive URI share-zero setting.
        let name = unsafe { ffi::sqlite3_filename_journal(value.filename) };
        // SAFETY: process-lifetime builtin table reports its native xOpen.
        let open = unsafe { (*policy.base).xOpen }
            .ok_or_else(|| io::Error::other("builtin rollback xOpen absent"))?;
        // SAFETY: storage is aligned/sized for builtin file, filename remains
        // owned through actual xClose, CREATE/DELETE flags were already removed.
        let result = unsafe { open(policy.base, name, value.file(), flags, out) };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other("exact held rollback native xOpen refused"));
        }
        value.initialized = true;
        // SAFETY: successful builtin xOpen initialized value's exact file storage.
        if unsafe { actual_identity(value.file()) }? != policy.journal {
            return Err(io::Error::other("held original rollback key differs"));
        }
        // The reset duplicate derives only from this actual builtin original.
        // SAFETY: initialized retained native file control yields original handle.
        *policy.opened_rollback.borrow_mut() = Some(unsafe { actual_file(value.file()) }?);
        *held = Some(value);
    }
    let value = held
        .as_ref()
        .ok_or_else(|| io::Error::other("held rollback absent"))?;
    // SAFETY: stored builtin file remains open continuously until Policy drops.
    if unsafe { actual_identity(value.file()) }? != policy.journal {
        return Err(io::Error::other("reused original rollback key differs"));
    }
    if !out.is_null() {
        // SAFETY: SQLite supplies writable one-int output when nonnull.
        unsafe {
            *out = ffi::SQLITE_OPEN_READWRITE;
        }
    }
    // SAFETY: outer is SQLite-owned aligned wrapper storage; retained Policy
    // native file remains open after each logical xClose and through next xOpen.
    unsafe {
        super::bounded_io::install(
            outer,
            value.file(),
            policy.limits[2],
            &policy.poisoned,
            true,
        );
    }
    Ok(())
}

pub(in super::super) fn execute_fresh_planned_history(
    connection:&rusqlite::Connection,statements:&[OriginalSqliteStatement],
    queries:&[OriginalSqliteQuery],before:&[OriginalSqliteRows],after:&[OriginalSqliteRows],
    budget:OriginalSqliteReadBudget,
)->io::Result<()> {
    if statements.is_empty() || statements.len()>1024 || queries.len()!=before.len() || queries.len()!=after.len() {
        return Err(io::Error::other("fresh history exact complete transition bounds"));
    }
        for &name in original_ordinary_rejecting_callbacks() {
            if !name.starts_with("sync_")
                || name.len() > 128
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(io::Error::other("original rejecting function exact name"));
            }
            connection
                .create_scalar_function(
                    name,
                    -1,
                    rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                    |_| Ok(false),
                )
                .map_err(io::Error::other)?;
        }
        validate_ordinary_whole_catalog(connection, queries)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(io::Error::other)?;
        let result = (|| -> io::Result<()> {
            admitted_query_rows(connection, queries, before, budget).map_err(|error|io::Error::other(format!("fresh history before whole rows: {error}")))?;
            {
                let _progress = OriginalVmBudget::install(
                    connection,
                    budget.max_vm_instructions,
                    budget.max_seconds,
                )?;
                let _authorizer = AdmittedDmlAuthorization::install(connection)?;
                for item in statements {
                    let mut statement = connection.prepare(&item.sql).map_err(io::Error::other)?;
                    if statement.readonly()
                        || statement.column_count() != 0
                        || statement.parameter_count() != item.parameters.len()
                    {
                        return Err(io::Error::other("admitted original bounded DML required"));
                    }
                    let values: Vec<_> = item
                        .parameters
                        .iter()
                        .map(OriginalSqliteValue::owned)
                        .collect();
                    let changed = statement
                        .execute(rusqlite::params_from_iter(values))
                        .map_err(io::Error::other)?;
                    if changed as u64 != item.expected_changed_rows {
                        return Err(io::Error::other("admitted original exact changed rows"));
                    }
                }
            }
            admitted_query_rows(connection, queries, after, budget).map_err(|error|io::Error::other(format!("fresh history after whole rows: {error}")))?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                if let Err(error) = connection.execute_batch("COMMIT") {
                    
                    return Err(io::Error::other(error));
                }
                Ok(())
            }
            Err(error) => {
                if connection.execute_batch("ROLLBACK").is_err() {
                    
                    return Err(io::Error::other("admitted original rollback uncertain"));
                }
                // A failed actual native attempt closes further issuance.
                
                Err(error)
            }
        }
}

