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
    sync::atomic::Ordering,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE},
    System::Threading::GetCurrentProcess,
};

#[path = "scoped_vfs/callback_gate.rs"]
mod callback_gate;
use callback_gate::{callback_base, callback_policy, CallbackRegistration, OriginalCallbackScope};

struct ApprovedFiles {
    main_name: CString,
    wal_name: CString,
    journal_name: CString,
    main: FileKey,
    wal: FileKey,
    journal: FileKey,
    limits: [u64; 3],
    mode: OriginalSqliteVfsMode,
    wal_allowed: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalSqliteVfsMode {
    OriginalWritable,
    OriginalReadonly,
    StoppedCaptureReadonly,
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
    mode: OriginalSqliteVfsMode,
    wal_allowed: bool,
    opened_rollback: std::cell::RefCell<Option<File>>,
    held_main: std::cell::RefCell<Option<HeldRollback>>,
    held_wal: std::cell::RefCell<Option<HeldRollback>>,
    held_rollback: std::cell::RefCell<Option<HeldRollback>>,
    original_observation_closes: std::cell::RefCell<crate::WindowsOriginalCloseAttempt>,
    rollback_reset_authorized: std::cell::Cell<bool>,
    poisoned: std::sync::atomic::AtomicBool,
}

/// A private whole context owns its policy until its connection/native IO end.
/// Stable bounded global lookup slots never expose that policy to another DB.
pub(super) struct OriginalSqliteVfs {
    context: Option<OriginalSqliteVfsContext>,
}

struct OriginalSqliteVfsContext {
    callback: CallbackRegistration,
    policy: Rc<Policy>,
}

fn normalized(path: &CStr) -> Vec<u8> {
    path.to_bytes()
        .strip_prefix(b"\\\\?\\")
        .unwrap_or_else(|| path.to_bytes())
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

fn copy_original_terminal_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

unsafe fn actual_file(file: *mut ffi::sqlite3_file, policy: &Policy) -> io::Result<File> {
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
    if let Err(error) = super::verify_regular_file(&observed) {
        policy
            .original_observation_closes
            .borrow_mut()
            .close_file(observed);
        return Err(error);
    }
    Ok(observed)
}

unsafe fn actual_identity(file: *mut ffi::sqlite3_file, policy: &Policy) -> io::Result<FileKey> {
    // SAFETY: caller supplies the actual initialized builtin file for this callback.
    let observed = unsafe { actual_file(file, policy)? };
    let identity = FileKey::from_file(&observed);
    let mut terminal = policy.original_observation_closes.borrow_mut();
    terminal.close_file(observed);
    if let Some(error) = terminal.original_close_error() {
        policy.poisoned.store(true, Ordering::SeqCst);
        return Err(copy_original_terminal_error(error));
    }
    identity
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
    // A failed or foreign xOpen must never expose an initialized outer IO.
    // SAFETY: SQLite supplies fresh, correctly sized outer file storage.
    unsafe {
        (*file).pMethods = ptr::null();
    }
    let kind =
        flags & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL);
    if !matches!(
        kind,
        ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL
    ) {
        return error();
    }
    // SAFETY: the stable slot checks thread authority before any live Policy
    // dereference; the guard also prevents context destruction during callback.
    let Some(mut original) = (unsafe { callback_policy(vfs) }) else {
        return error();
    };
    if kind == ffi::SQLITE_OPEN_MAIN_DB && !original.take_single_main_open() {
        // Another safe Connection, including ATTACH from a foreign memory DB,
        // receives no original main loan and cannot poison the original owner.
        return error();
    }
    let policy = &*original;
    if policy.poisoned.load(Ordering::SeqCst) {
        return error();
    }
    // SAFETY: SQLite supplies a terminated filename valid for the callback.
    let name_bytes = unsafe { CStr::from_ptr(name) };
    if name_bytes.to_bytes().len() > 16_384 {
        return error();
    }
    let (expected, limit) = if kind == ffi::SQLITE_OPEN_MAIN_DB
        && normalized(name_bytes) == normalized(&policy.main_name)
    {
        (policy.main, policy.limits[0])
    } else if kind == ffi::SQLITE_OPEN_WAL
        && policy.wal_allowed
        && normalized(name_bytes) == normalized(&policy.wal_name)
    {
        (policy.wal, policy.limits[1])
    } else if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL
        && policy.mode == OriginalSqliteVfsMode::OriginalWritable
        && normalized(name_bytes) == normalized(&policy.journal_name)
    {
        (policy.journal, policy.limits[2])
    } else {
        // Rollback journal, temp files, anonymous names, attached DB and SHM opens
        // have no approved original object. Refuse them before any base syscall.
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    };
    let readonly = policy.mode != OriginalSqliteVfsMode::OriginalWritable;
    if (readonly
        && (flags & ffi::SQLITE_OPEN_READONLY == 0 || flags & ffi::SQLITE_OPEN_READWRITE != 0))
        || (!readonly && flags & ffi::SQLITE_OPEN_READWRITE == 0)
        || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0
    {
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    }
    // Windows base must apply share0 to main. SQLite URI parameters are retained
    // alongside this filename; no string-built query or global default modifies it.
    // SAFETY: SQLite filename has the documented URI extra data representation.
    if !readonly && kind == ffi::SQLITE_OPEN_MAIN_DB
        // SAFETY: SQLite supplies this callback filename and its documented URI data.
        && unsafe { ffi::sqlite3_uri_boolean(name, c"exclusive".as_ptr(), 0) } != 1
    {
        policy.poisoned.store(true, Ordering::SeqCst);
        return error();
    }
    // Never create or delete via SQLite. Original creator and ledger precreate WAL.
    let flags = flags
        & !(ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_EXCLUSIVE | ffi::SQLITE_OPEN_DELETEONCLOSE);
    // SAFETY: fresh outer storage is SQLite-owned; failure must not expose methods.
    unsafe {
        (*file).pMethods = ptr::null();
    }
    // Each actual builtin file is allocated and owned in the original Policy
    // before the first xOpen. SQLite's logical xClose leaves that same native
    // owner intact for the explicit, checked terminal after actual DB close.
    // SAFETY: exact approved kind, path, flags, and original outer storage were
    // admitted above. No replacement path or additional native open is used.
    match unsafe { open_held_original(policy, file, flags, out, kind, expected, limit) } {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            policy.poisoned.store(true, Ordering::SeqCst);
            error()
        }
    }
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    _sync: i32,
) -> i32 {
    if vfs.is_null() || name.is_null() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // Only the private original writable issuer scopes this exact reset. Foreign
    // memory/failed-open cleanup never accesses Rc or original rollback state.
    // SAFETY: stable slot and admitted same owner thread before Policy access.
    let Some(original) = (unsafe { callback_policy(vfs) }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    if !original.permits_rollback_reset() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    let policy = &*original;
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
    // Discovery uses the immutable builtin VFS and remains truthful even for a
    // foreign memory/empty/failed-open DB; no original Policy is borrowed.
    // SAFETY: this callback table's bounded slot and builtin base have process lifetime.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return error();
    }
    // SAFETY: SQLite supplies a terminated filename for this callback.
    let name_bytes = unsafe { CStr::from_ptr(name) };
    if name_bytes.to_bytes().len() > 16_384 {
        return error();
    }
    // For discovery SQLite may ask whether a rollback/SHM name exists. The
    // caller's explicit inventory and builtin access observe every actual path.
    // SAFETY: builtin base access only observes filename state, never creates/deletes.
    if let Some(access) = unsafe { (*base).xAccess } {
        // SAFETY: unchanged SQLite callback arguments to builtin VFS.
        unsafe { access(base, name, flags, out) }
    } else {
        error()
    }
}

impl OriginalSqliteVfs {
    pub(super) fn register_readonly(
        main_path: &std::path::Path,
        expected_main: FileKey,
        maximum_main_bytes: u64,
        existing_wal: Option<(FileKey, u64)>,
        stopped_capture: bool,
    ) -> io::Result<Self> {
        if !main_path.is_absolute() || (!stopped_capture && existing_wal.is_some()) {
            return Err(io::Error::other(
                "exact readonly original VFS purpose required",
            ));
        }
        let main_name = CString::new(
            main_path
                .to_str()
                .ok_or_else(|| io::Error::other("readonly original SQLite path encoding"))?,
        )
        .map_err(|_| io::Error::other("readonly original SQLite filename"))?;
        let mut wal_bytes = main_name.as_bytes().to_vec();
        wal_bytes.extend_from_slice(b"-wal");
        let mut journal_bytes = main_name.as_bytes().to_vec();
        journal_bytes.extend_from_slice(b"-journal");
        let (wal, wal_limit) = existing_wal.unwrap_or((expected_main, 512));
        Self::register(ApprovedFiles {
            main_name,
            wal_name: CString::new(wal_bytes)
                .map_err(|_| io::Error::other("readonly original WAL filename"))?,
            journal_name: CString::new(journal_bytes)
                .map_err(|_| io::Error::other("readonly original rollback filename"))?,
            main: expected_main,
            wal,
            journal: expected_main,
            limits: [maximum_main_bytes, wal_limit, 512],
            mode: if stopped_capture {
                OriginalSqliteVfsMode::StoppedCaptureReadonly
            } else {
                OriginalSqliteVfsMode::OriginalReadonly
            },
            wal_allowed: existing_wal.is_some(),
        })
    }

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
            mode,
            wal_allowed,
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
        let base = unsafe {
            ffi::sqlite3_vfs_find(
                if mode == OriginalSqliteVfsMode::StoppedCaptureReadonly {
                    c"win32-none"
                } else {
                    c"win32"
                }
                .as_ptr(),
            )
        };
        if base.is_null() {
            return Err(io::Error::other("builtin Windows VFS required"));
        }
        // SAFETY: zero initializes only C integers/pointers/nullable functions.
        // Copy immutable ABI integers individually: copying the full builtin
        // table would race SQLite's pNext mutations during other registrations.
        let mut table: ffi::sqlite3_vfs = unsafe { std::mem::zeroed() };
        // SAFETY: builtin immutable ABI fields have process lifetime.
        unsafe {
            table.iVersion = (*base).iVersion;
            table.szOsFile = (*base).szOsFile;
            table.mxPathname = (*base).mxPathname;
        }
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
        let policy = Rc::new(Policy {
            base,
            main_name,
            wal_name,
            journal_name,
            main,
            wal,
            journal,
            limits,
            mode,
            wal_allowed,
            opened_rollback: std::cell::RefCell::new(None),
            held_main: std::cell::RefCell::new(None),
            held_wal: std::cell::RefCell::new(None),
            held_rollback: std::cell::RefCell::new(None),
            original_observation_closes: std::cell::RefCell::new(
                crate::WindowsOriginalCloseAttempt::new(),
            ),
            rollback_reset_authorized: std::cell::Cell::new(false),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        });
        table.pNext = ptr::null_mut();
        table.zName = ptr::null();
        table.pAppData = ptr::null_mut();
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

        // SAFETY: this same private context owns Rc until the gate detaches after
        // actual logical/native close. The bounded global table/name stays
        // valid for foreign vfs_find pointers, without retaining Rc/native IO.
        let callback = unsafe { CallbackRegistration::register(table, base, Rc::as_ptr(&policy)) }?;
        Ok(Self {
            context: Some(OriginalSqliteVfsContext { callback, policy }),
        })
    }
    fn context_ref(&self) -> &OriginalSqliteVfsContext {
        self.context
            .as_ref()
            .expect("original registered VFS context retained")
    }
    pub(super) fn name(&self) -> &CStr {
        self.context_ref().callback.name()
    }

    pub(super) fn activate_current_thread(&self) -> io::Result<()> {
        self.context_ref().callback.activate_current_thread()
    }

    pub(super) fn begin_single_main_open(&self) -> io::Result<OriginalCallbackScope> {
        self.context_ref().callback.begin_single_main_open()
    }
    pub(super) fn refused_effect(&self) -> bool {
        self.context_ref().policy.poisoned.load(Ordering::SeqCst)
    }

    pub(super) fn has_original_context(&self) -> bool {
        self.context.is_some()
    }

    pub(super) fn original_logical_io_remains(&self) -> bool {
        self.context.as_ref().is_some_and(|context| {
            let slot = context.callback.slot();
            let Ok(_original) = context.callback.lock_owner_on_slot(&slot) else {
                return true;
            };
            [
                &context.policy.held_main,
                &context.policy.held_wal,
                &context.policy.held_rollback,
            ]
            .iter()
            .any(|original| {
                original.borrow().as_ref().is_some_and(|original| {
                    !original.original_logical_terminal.load(Ordering::SeqCst)
                })
            })
        })
    }

    pub(super) fn verify_readonly_original(&self) -> io::Result<()> {
        let context = self.context_ref();
        let slot = context.callback.slot();
        let _original = context.callback.lock_owner_on_slot(&slot)?;
        let policy = &context.policy;
        if policy.mode == OriginalSqliteVfsMode::OriginalWritable
            || policy.poisoned.load(Ordering::SeqCst)
        {
            return Err(io::Error::other("healthy original readonly VFS required"));
        }
        let held = policy.held_main.borrow();
        let main = held
            .as_ref()
            .ok_or_else(|| io::Error::other("original readonly main IO absent"))?;
        if !main.initialized || main.original_logical_terminal.load(Ordering::SeqCst) {
            return Err(io::Error::other("live original readonly main IO required"));
        }
        // SAFETY: the continuously retained owning builtin IO remains borrowed
        // by its original SQLite wrapper; observation closes its actual duplicate.
        if unsafe { actual_identity(main.file(), policy) }? != policy.main {
            return Err(io::Error::other("actual original readonly main differs"));
        }
        Ok(())
    }

    pub(super) fn close_original_into_attempt(
        &mut self,
        attempt: &mut crate::WindowsOriginalCloseAttempt,
    ) {
        let Some(context) = self.context.as_mut() else {
            return;
        };
        let slot = context.callback.slot();
        let mut original_callback = match context.callback.lock_owner_on_slot(&slot) {
            Ok(original) => original,
            Err(error) => {
                attempt.note_error(error);
                return;
            }
        };
        let policy = &context.policy;
        if [&policy.held_main, &policy.held_wal, &policy.held_rollback]
            .iter()
            .any(|original| {
                original.borrow().as_ref().is_some_and(|original| {
                    !original.original_logical_terminal.load(Ordering::SeqCst)
                })
            })
        {
            attempt.note_error(io::Error::new(
                io::ErrorKind::WouldBlock,
                "same original SQLite pager still borrows native IO",
            ));
            return;
        }
        let original_observations =
            std::mem::take(&mut *policy.original_observation_closes.borrow_mut());
        attempt.append_result(original_observations.finish());
        if let Some(original) = policy.opened_rollback.borrow_mut().take() {
            attempt.close_file(original);
        }
        for original in [&policy.held_main, &policy.held_wal, &policy.held_rollback] {
            let mut retained = original.borrow_mut();
            if let Some(original) = retained.as_mut() {
                original.close_original_into_attempt(attempt);
                if !original.original_resources_remain() {
                    retained.take();
                }
            }
        }
        if let Err(error) = context.callback.unregister() {
            attempt.note_error(error);
            return;
        }
        if [&policy.held_main, &policy.held_wal, &policy.held_rollback]
            .iter()
            .any(|original| original.borrow().is_some())
        {
            attempt.note_error(io::Error::other(
                "original SQLite native IO remains retained after terminal",
            ));
            return;
        }
        if Rc::strong_count(policy) != 1 {
            attempt.note_error(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original SQLite VFS has an outstanding original policy loan",
            ));
            return;
        }
        if let Err(error) = context.callback.detach(&mut original_callback) {
            attempt.note_error(error);
            return;
        }
        drop(original_callback);
        self.context.take();
    }
}

impl Drop for OriginalSqliteVfs {
    fn drop(&mut self) {
        if self.context.is_none() {
            return;
        }
        let mut original = Self {
            context: self.context.take(),
        };
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        original.close_original_into_attempt(&mut terminal);
        if original.context.is_some() {
            let _ = Box::leak(Box::new(original));
        }
        if let Err(original) = terminal.finish() {
            original.retain_until_process_exit();
        }
    }
}

unsafe extern "C" fn full_path(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    n: i32,
    out: *mut std::ffi::c_char,
) -> i32 {
    // SAFETY: the stable slot forwards without touching an active original Policy.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return error();
    }
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
    // SAFETY: immutable process-lifetime base; foreign memory DBs use no Policy.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return 0;
    }
    // SAFETY: method table is builtin process-lifetime object.
    let Some(method) = (unsafe { (*base).xRandomness }) else {
        return 0;
    };
    // SAFETY: unchanged sized SQLite random output buffer forwarded to builtin.
    unsafe { method(base, n, out) }
}
unsafe extern "C" fn sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: i32) -> i32 {
    // SAFETY: the bounded slot/base remains valid after original context close.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return 0;
    }
    // SAFETY: process-lifetime builtin method table.
    let Some(method) = (unsafe { (*base).xSleep }) else {
        return 0;
    };
    // SAFETY: pointer-free original builtin sleep receives bounded SQLite argument.
    unsafe { method(base, microseconds) }
}
unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> i32 {
    // SAFETY: pointer-free builtin clock uses the stable slot/base only.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return ffi::SQLITE_ERROR;
    }
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
    // SAFETY: immutable process-lifetime base, without an original Policy loan.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return ffi::SQLITE_ERROR;
    }
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
    // SAFETY: process-lifetime base serves foreign failed-open diagnostics too.
    let base = unsafe { callback_base(vfs) };
    if base.is_null() {
        return 0;
    }
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
    opening_connection: Option<*mut ffi::sqlite3>,
    registration: OriginalSqliteVfs,
    main: Option<crate::ReleasedOriginalFileIdentity>,
    wal: Option<crate::ReleasedOriginalFileIdentity>,
    journal: Option<crate::ReleasedOriginalFileIdentity>,
    write_attempted: bool,
    original_terminal_error: Option<io::Error>,
    original_resource_terminal: Option<crate::WindowsOriginalResourceCloseFailure>,
    actual_closed_handle_prefix: usize,
}

enum ScopedOriginalSqliteOpenFailure {
    Released(
        Box<(
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
            crate::ReleasedOriginalFileIdentity,
            io::Error,
        )>,
    ),
    Open(Box<ScopedOriginalSqlite>, io::Error),
}

impl ScopedOriginalSqlite {
    fn main_ref(&self) -> &crate::ReleasedOriginalFileIdentity {
        self.main
            .as_ref()
            .expect("original main identity remains retained")
    }
    fn wal_ref(&self) -> &crate::ReleasedOriginalFileIdentity {
        self.wal
            .as_ref()
            .expect("original WAL identity remains retained")
    }
    fn journal_ref(&self) -> &crate::ReleasedOriginalFileIdentity {
        self.journal
            .as_ref()
            .expect("original rollback identity remains retained")
    }

    fn open(
        uri: &str,
        main_path: &std::path::Path,
        main: crate::ReleasedOriginalFileIdentity,
        wal: crate::ReleasedOriginalFileIdentity,
        journal: crate::ReleasedOriginalFileIdentity,
        limits: [u64; 3],
    ) -> Result<Self, ScopedOriginalSqliteOpenFailure> {
        let attempt = || -> io::Result<OriginalSqliteVfs> {
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
            OriginalSqliteVfs::register(ApprovedFiles {
                main_name,
                wal_name,
                journal_name,
                main: main.key()?,
                wal: wal.key()?,
                journal: journal.key()?,
                limits,
                mode: OriginalSqliteVfsMode::OriginalWritable,
                wal_allowed: true,
            })
        };
        let registration = match attempt() {
            Ok(value) => value,
            Err(error) => {
                return Err(ScopedOriginalSqliteOpenFailure::Released(Box::new((
                    main, wal, journal, error,
                ))))
            }
        };
        let mut owner = Self {
            connection: None,
            opening_connection: None,
            registration,
            main: Some(main),
            wal: Some(wal),
            journal: Some(journal),
            write_attempted: false,
            original_terminal_error: None,
            original_resource_terminal: None,
            actual_closed_handle_prefix: 0,
        };
        let uri = match CString::new(uri) {
            Ok(uri) => uri,
            Err(error) => {
                return Err(ScopedOriginalSqliteOpenFailure::Open(
                    Box::new(owner),
                    io::Error::other(error),
                ))
            }
        };
        let _original_open = match owner.registration.begin_single_main_open() {
            Ok(original_open) => original_open,
            Err(error) => {
                return Err(ScopedOriginalSqliteOpenFailure::Open(
                    Box::new(owner),
                    error,
                ))
            }
        };
        let mut database = ptr::null_mut();
        // SAFETY: the one original registration owns names/policy/native IO.
        // Retain the actual returned DB even if this original open fails.
        let opened = unsafe {
            ffi::sqlite3_open_v2(
                uri.as_ptr(),
                &mut database,
                ffi::SQLITE_OPEN_READWRITE
                    | ffi::SQLITE_OPEN_URI
                    | ffi::SQLITE_OPEN_NOMUTEX
                    | ffi::SQLITE_OPEN_PRIVATECACHE,
                owner.registration.name().as_ptr(),
            )
        };
        if !database.is_null() {
            owner.opening_connection = Some(database);
        }
        if opened != ffi::SQLITE_OK || database.is_null() {
            let error = if database.is_null() {
                io::Error::other(format!(
                    "original scoped SQLite open returned {opened} without a database",
                ))
            } else {
                // SAFETY: the exact failed-open DB is still owned and live.
                let message = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(database)) }
                    .to_string_lossy()
                    .into_owned();
                io::Error::other(rusqlite::Error::SqliteFailure(
                    ffi::Error::new(opened),
                    Some(message),
                ))
            };
            return Err(ScopedOriginalSqliteOpenFailure::Open(
                Box::new(owner),
                error,
            ));
        }
        // SAFETY: ownership transfers once from the actual original open_v2 DB
        // to rusqlite. It does not open a database or register a replacement VFS.
        let connection = match unsafe { rusqlite::Connection::from_handle_owned(database) } {
            Ok(connection) => connection,
            Err(error) => {
                return Err(ScopedOriginalSqliteOpenFailure::Open(
                    Box::new(owner),
                    io::Error::other(error),
                ))
            }
        };
        owner.opening_connection = None;
        owner.connection = Some(connection);
        let checked = owner
            .connection
            .as_ref()
            .expect("original connection just retained")
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(io::Error::other)
            .and_then(|()| owner.verify());
        if let Err(error) = checked {
            return Err(ScopedOriginalSqliteOpenFailure::Open(
                Box::new(owner),
                error,
            ));
        }
        Ok(owner)
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
        if actual != self.main_ref().key()?
            || bytes != accepted
            || accepted.get(18..20) != Some(&[1, 1])
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
        let original_reset = self
            .registration
            .context_ref()
            .callback
            .begin_original_rollback_reset()?;
        self.registration
            .context_ref()
            .policy
            .rollback_reset_authorized
            .set(true);
        let change_mode = connection.pragma_update(None, "journal_mode", "WAL");
        self.registration
            .context_ref()
            .policy
            .rollback_reset_authorized
            .set(false);
        drop(original_reset);
        change_mode.map_err(io::Error::other)?;
        // The reset duplicate is needed only during the admitted WAL transition.
        // Relinquish its old SQLite share settings after successful invalidation;
        // the retained original identity and parent witnesses stay live.
        if let Some(original) = self
            .registration
            .context_ref()
            .policy
            .opened_rollback
            .borrow_mut()
            .take()
        {
            let policy = &self.registration.context_ref().policy;
            let mut terminal = policy.original_observation_closes.borrow_mut();
            terminal.close_file(original);
            if let Some(error) = terminal.original_close_error() {
                policy.poisoned.store(true, Ordering::SeqCst);
                return Err(copy_original_terminal_error(error));
            }
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(io::Error::other)?;
        connection
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .map_err(io::Error::other)?;
        if crate::sqlite_wal_file_identity(connection)? != self.wal_ref().key()? {
            return Err(io::Error::other("original WAL actual VFS handle differs"));
        }
        let (actual, current) = crate::sqlite_main_exact_bytes(connection, accepted.len() as u64)?;
        if actual != self.main_ref().key()?
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
        self.main_ref().verify()?;
        self.wal_ref().verify()?;
        self.journal_ref().verify()?;
        if crate::sqlite_main_file_identity(connection)? != self.main_ref().key()?
            || crate::sqlite_wal_file_identity(connection)? != self.wal_ref().key()?
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
        self.main_ref().verify()?;
        self.wal_ref().verify()?;
        self.journal_ref().verify()?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("scoped SQLite closed"))?;
        if crate::sqlite_main_file_identity(connection)? != self.main_ref().key()? {
            return Err(io::Error::other("scoped original SQLite main changed"));
        }
        Ok(())
    }
}

impl ScopedOriginalSqlite {
    fn original_resources_remain(&self) -> bool {
        self.connection.is_some()
            || self.opening_connection.is_some()
            || self.registration.context.is_some()
            || self.main.is_some()
            || self.wal.is_some()
            || self.journal.is_some()
            || self
                .original_resource_terminal
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    fn close_original_database_retaining(&mut self) -> io::Result<()> {
        if let Some(connection) = self.connection.take() {
            if let Err((connection, error)) = connection.close() {
                self.connection = Some(connection);
                let error = io::Error::other(error);
                self.original_terminal_error
                    .get_or_insert_with(|| copy_original_terminal_error(&error));
                return Err(error);
            }
        }
        if let Some(database) = self.opening_connection {
            // SAFETY: this is the actual failed-open DB retained from open_v2,
            // never transferred to another connection or new native owner.
            let closed = unsafe { ffi::sqlite3_close(database) };
            if closed != ffi::SQLITE_OK {
                // SAFETY: the failed close retains that same live database.
                let message = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(database)) }
                    .to_string_lossy()
                    .into_owned();
                let error = io::Error::other(rusqlite::Error::SqliteFailure(
                    ffi::Error::new(closed),
                    Some(message),
                ));
                self.original_terminal_error
                    .get_or_insert_with(|| copy_original_terminal_error(&error));
                return Err(error);
            }
            self.opening_connection = None;
        }
        Ok(())
    }

    fn close_original_into_attempt(&mut self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt
            .append_original_handle_prefix(std::mem::take(&mut self.actual_closed_handle_prefix));
        if let Some(error) = self.original_terminal_error.take() {
            attempt.note_error(error);
        }
        if let Some(original) = self.original_resource_terminal.take() {
            attempt.append_failure(original.close_remaining());
        }
        if let Err(error) = self.close_original_database_retaining() {
            attempt.note_error(error);
            return;
        }
        self.registration.close_original_into_attempt(attempt);
        if self.registration.context.is_some() || attempt.has_retained_originals() {
            return;
        }
        for original in [&mut self.main, &mut self.wal, &mut self.journal] {
            if let Some(original) = original.take() {
                original.close_into_attempt(attempt);
            }
        }
    }

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
            .main_ref()
            .verify()
            .and_then(|_| self.wal_ref().verify())
            .and_then(|_| self.journal_ref().verify())
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
            let (key, bytes) = crate::sqlite_main_exact_bytes(
                connection,
                self.registration.context_ref().policy.limits[0],
            )?;
            if key != self.main_ref().key()? || bytes.get(18..20) != Some(&[1, 1]) {
                return Err(io::Error::other("standalone original main header differs"));
            }
            self.main_ref().verify()?;
            self.wal_ref().verify()?;
            self.journal_ref().verify()?;
            if self.registration.refused_effect() {
                return Err(io::Error::other("original close VFS effect refused"));
            }
            Ok(())
        };
        if let Err(error) = finish() {
            return Err((Box::new(self), error));
        }
        if let Err(error) = self.close_original_database_retaining() {
            return Err((Box::new(self), error));
        }
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        self.registration.close_original_into_attempt(&mut terminal);
        match terminal.finish() {
            Ok(closed) => self.actual_closed_handle_prefix += closed.actual_closed_handles(),
            Err(original) => {
                let error = copy_original_terminal_error(&original.error);
                self.original_resource_terminal = Some(original);
                return Err((Box::new(self), error));
            }
        }
        let main = self.main.take().expect("verified original main retained");
        let wal = self.wal.take().expect("verified original WAL retained");
        let journal = self
            .journal
            .take()
            .expect("verified original rollback retained");
        Ok((main, wal, journal))
    }
}

impl Drop for ScopedOriginalSqlite {
    fn drop(&mut self) {
        if !self.original_resources_remain() {
            return;
        }
        let mut original = Self {
            connection: self.connection.take(),
            opening_connection: self.opening_connection.take(),
            registration: OriginalSqliteVfs {
                context: self.registration.context.take(),
            },
            main: self.main.take(),
            wal: self.wal.take(),
            journal: self.journal.take(),
            write_attempted: self.write_attempted,
            original_terminal_error: self.original_terminal_error.take(),
            original_resource_terminal: self.original_resource_terminal.take(),
            actual_closed_handle_prefix: std::mem::take(&mut self.actual_closed_handle_prefix),
        };
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        original.close_original_into_attempt(&mut terminal);
        if original.original_resources_remain() {
            let _ = Box::leak(Box::new(original));
        }
        if let Err(original) = terminal.finish() {
            original.retain_until_process_exit();
        }
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

/// Retains the same actual DB, VFS, aligned native IOs, identity witnesses, and
/// failed original HANDLEs. A terminal failure has no usable writer or restart.
pub struct OriginalSqliteResourceCloseFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original: Option<OriginalSqliteConnection>,
    original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for OriginalSqliteResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalSqliteResourceCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field(
                "whole_original_sqlite_owner_retained",
                &self.original.is_some(),
            )
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalSqliteResourceCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original
            .as_ref()
            .is_some_and(|original| original.original.original_resources_remain())
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    pub fn close_remaining(mut self) -> Self {
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        if let Some(original) = self.original_resources.take() {
            terminal.append_failure(original.close_remaining());
        } else {
            terminal.note_error(copy_original_terminal_error(&self.error));
            terminal.append_original_handle_prefix(self.actual_closed_handles);
        }
        if let Some(mut original) = self.original.take() {
            original.original.close_original_into_attempt(&mut terminal);
            if original.original.original_resources_remain() {
                self.original = Some(original);
            }
        }
        let original_resources = match terminal.finish() {
            Err(original) => original,
            Ok(_) => unreachable!("the original first terminal error remains recorded"),
        };
        self.actual_closed_handles = original_resources.actual_closed_handles;
        self.original_resources = Some(original_resources);
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl OriginalSqliteOpenFailure {
    /// Terminal all original open-prefix resources, including a failed actual
    /// partial DB. The original opening error never becomes clean completion.
    pub fn close_original_resources_retaining(
        self,
    ) -> Result<crate::ClosedWindowsOriginalResources, OriginalSqliteResourceCloseFailure> {
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        let mut original_owner = None;
        match self {
            Self::Prepared {
                main,
                wal,
                rollback,
                error,
            } => {
                terminal.note_error(error);
                main.close_into_attempt(&mut terminal);
                wal.close_into_attempt(&mut terminal);
                rollback.close_into_attempt(&mut terminal);
            }
            Self::MainReleased {
                main,
                wal,
                rollback,
                error,
            } => {
                terminal.note_error(error);
                main.close_into_attempt(&mut terminal);
                wal.close_into_attempt(&mut terminal);
                rollback.close_into_attempt(&mut terminal);
            }
            Self::WalReleased {
                main,
                wal,
                rollback,
                error,
            } => {
                terminal.note_error(error);
                main.close_into_attempt(&mut terminal);
                wal.close_into_attempt(&mut terminal);
                rollback.close_into_attempt(&mut terminal);
            }
            Self::Released {
                main,
                wal,
                rollback,
                error,
            } => {
                terminal.note_error(error);
                main.close_into_attempt(&mut terminal);
                wal.close_into_attempt(&mut terminal);
                rollback.close_into_attempt(&mut terminal);
            }
            Self::Open {
                mut original,
                error,
            } => {
                terminal.note_error(error);
                original.original.close_original_into_attempt(&mut terminal);
                if original.original.original_resources_remain() {
                    original_owner = Some(*original);
                }
            }
        }
        match terminal.finish() {
            Err(original_resources) => Err(OriginalSqliteResourceCloseFailure {
                error: copy_original_terminal_error(&original_resources.error),
                actual_closed_handles: original_resources.actual_closed_handles,
                original: original_owner,
                original_resources: Some(original_resources),
            }),
            Ok(_) => unreachable!("the original opening error remains recorded"),
        }
    }
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
            Err(ScopedOriginalSqliteOpenFailure::Released(failed)) => {
                let (main, wal, rollback, error) = *failed;
                return Err(OriginalSqliteOpenFailure::Released {
                    main: Box::new(main),
                    wal: Box::new(wal),
                    rollback: Box::new(rollback),
                    error,
                });
            }
            Err(ScopedOriginalSqliteOpenFailure::Open(original, error)) => {
                return Err(OriginalSqliteOpenFailure::Open {
                    original: Box::new(Self {
                        original: *original,
                        write_bytes: max_write_bytes,
                        uncertain: std::cell::Cell::new(true),
                    }),
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
        let rollback = self.original.journal_ref().key()?;
        if main != self.original.main_ref().key()? || wal != self.original.wal_ref().key()? {
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

    /// End this actual original DB/VFS/IO and metadata scope even after an
    /// earlier verification failure. It yields no writer, receipt, or restart.
    pub fn close_original_resources_retaining(
        mut self,
    ) -> Result<crate::ClosedWindowsOriginalResources, OriginalSqliteResourceCloseFailure> {
        self.uncertain.set(true);
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        self.original.close_original_into_attempt(&mut terminal);
        match terminal.finish() {
            Ok(closed) if !self.original.original_resources_remain() => Ok(closed),
            Ok(_) => unreachable!("a retained original SQLite resource records its terminal error"),
            Err(original_resources) => Err(OriginalSqliteResourceCloseFailure {
                error: copy_original_terminal_error(&original_resources.error),
                actual_closed_handles: original_resources.actual_closed_handles,
                original: if self.original.original_resources_remain() {
                    Some(self)
                } else {
                    None
                },
                original_resources: Some(original_resources),
            }),
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

// Retain each exact builtin file across SQLite's logical xClose/xOpen.
// Filename and aligned builtin storage live until after the connection closes.
struct HeldRollback {
    storage: Box<[usize]>,
    filename: ffi::sqlite3_filename,
    initialized: bool,
    original_logical_terminal: Box<std::sync::atomic::AtomicBool>,
}
impl HeldRollback {
    fn original_resources_remain(&self) -> bool {
        self.initialized || !self.filename.is_null()
    }

    fn close_original_into_attempt(&mut self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        if !self.original_logical_terminal.load(Ordering::SeqCst) {
            attempt.note_error(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original builtin SQLite IO still has its original pager loan",
            ));
            return;
        }
        if self.initialized {
            let file = self.file();
            // SAFETY: the original aligned Box still owns this one successful
            // builtin xOpen. Its connection has ended before terminal calls.
            let methods = unsafe { (*file).pMethods };
            let closed = if methods.is_null() {
                ffi::SQLITE_IOERR_CLOSE
            } else {
                // SAFETY: the exact original builtin method table is retained.
                match unsafe { (*methods).xClose } {
                    // SAFETY: call the terminal only on that same owning IO.
                    Some(close) => unsafe { close(file) },
                    None => ffi::SQLITE_IOERR_CLOSE,
                }
            };
            if closed != ffi::SQLITE_OK {
                attempt.note_error(io::Error::other(format!(
                    "original builtin SQLite native xClose returned {closed}",
                )));
                return;
            }
            self.initialized = false;
            // SAFETY: only actual successful xClose of this same owning IO
            // permits clearing its installed original method table.
            unsafe {
                (*file).pMethods = ptr::null();
            }
            attempt.note_actual_handle_closed();
        }
        if !self.filename.is_null() {
            // SAFETY: the exact create_filename allocation is no longer
            // borrowed by an actual native IO or an active SQLite wrapper.
            unsafe { ffi::sqlite3_free_filename(self.filename) };
            self.filename = ptr::null();
        }
    }

    fn file(&self) -> *mut ffi::sqlite3_file {
        self.storage.as_ptr().cast_mut().cast()
    }
    fn prepare(policy: &Policy) -> io::Result<Self> {
        let mut parameters = [
            c"exclusive".as_ptr(),
            if policy.mode == OriginalSqliteVfsMode::OriginalWritable {
                c"1"
            } else {
                c"0"
            }
            .as_ptr(),
        ];
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
            original_logical_terminal: Box::new(std::sync::atomic::AtomicBool::new(true)),
        })
    }
}
impl Drop for HeldRollback {
    fn drop(&mut self) {
        if !self.original_resources_remain() {
            return;
        }
        let mut original = Self {
            storage: std::mem::replace(&mut self.storage, Box::new([])),
            filename: std::mem::replace(&mut self.filename, ptr::null()),
            initialized: std::mem::take(&mut self.initialized),
            original_logical_terminal: std::mem::replace(
                &mut self.original_logical_terminal,
                Box::new(std::sync::atomic::AtomicBool::new(true)),
            ),
        };
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        original.close_original_into_attempt(&mut terminal);
        if original.original_resources_remain() {
            let _ = Box::leak(Box::new(original));
        }
        if let Err(original) = terminal.finish() {
            original.retain_until_process_exit();
        }
    }
}

unsafe fn open_held_original(
    policy: &Policy,
    outer: *mut ffi::sqlite3_file,
    flags: i32,
    out: *mut i32,
    kind: i32,
    expected: FileKey,
    limit: u64,
) -> io::Result<()> {
    let retained = match kind {
        ffi::SQLITE_OPEN_MAIN_DB => &policy.held_main,
        ffi::SQLITE_OPEN_WAL => &policy.held_wal,
        ffi::SQLITE_OPEN_MAIN_JOURNAL => &policy.held_rollback,
        _ => return Err(io::Error::other("original builtin IO kind refused")),
    };
    let mut held = retained.borrow_mut();
    if held.is_none() {
        let mut value = HeldRollback::prepare(policy)?;
        // SAFETY: the actual owning SQLite filename allocation preserves the
        // exact approved names and exclusive URI setting for these three IOs.
        let name = unsafe {
            match kind {
                ffi::SQLITE_OPEN_MAIN_DB => ffi::sqlite3_filename_database(value.filename),
                ffi::SQLITE_OPEN_WAL => ffi::sqlite3_filename_wal(value.filename),
                ffi::SQLITE_OPEN_MAIN_JOURNAL => ffi::sqlite3_filename_journal(value.filename),
                _ => unreachable!("the original kind was checked"),
            }
        };
        // SAFETY: process-lifetime builtin table reports its native xOpen.
        let open = unsafe { (*policy.base).xOpen }
            .ok_or_else(|| io::Error::other("builtin rollback xOpen absent"))?;
        // SAFETY: storage is aligned/sized for builtin file, filename remains
        // owned through actual xClose, CREATE/DELETE flags were already removed.
        let result = unsafe { open(policy.base, name, value.file(), flags, out) };
        // Retain the owning aligned original before any post-open error. A
        // failed builtin open with methods also remains available for terminal.
        // SAFETY: zeroed sized storage remains owned by value after base xOpen.
        value.initialized = unsafe { !(*value.file()).pMethods.is_null() };
        *held = Some(value);
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other(format!(
                "exact original builtin SQLite xOpen returned {result}",
            )));
        }
    }
    let value = held
        .as_ref()
        .ok_or_else(|| io::Error::other("held original builtin IO absent"))?;
    if !value.initialized {
        return Err(io::Error::other(
            "held original builtin IO lacks open methods",
        ));
    }
    if !value.original_logical_terminal.load(Ordering::SeqCst) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "same original builtin SQLite IO already has a live logical loan",
        ));
    }
    // SAFETY: stored builtin file remains open continuously until Policy drops.
    if unsafe { actual_identity(value.file(), policy) }? != expected {
        return Err(io::Error::other("held original builtin SQLite key differs"));
    }
    if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL && policy.opened_rollback.borrow().is_none() {
        // The reset observer derives only from this continuously owned actual
        // native IO and is retained before every later verification or effect.
        // SAFETY: initialized original file control yields this same HANDLE.
        *policy.opened_rollback.borrow_mut() = Some(unsafe { actual_file(value.file(), policy) }?);
    }
    if !out.is_null() {
        // SAFETY: SQLite supplies writable one-int output when nonnull.
        unsafe {
            *out = if policy.mode == OriginalSqliteVfsMode::OriginalWritable {
                ffi::SQLITE_OPEN_READWRITE
            } else {
                ffi::SQLITE_OPEN_READONLY
            };
        }
    }
    // SAFETY: outer is SQLite-owned aligned wrapper storage; retained Policy
    // native file remains open after each logical xClose and through next xOpen.
    unsafe {
        value
            .original_logical_terminal
            .store(false, Ordering::SeqCst);
        super::bounded_io::install(
            outer,
            value.file(),
            limit,
            &policy.poisoned,
            true,
            &*value.original_logical_terminal,
        );
    }
    Ok(())
}

pub fn execute_fresh_planned_history(
    connection: &rusqlite::Connection,
    statements: &[OriginalSqliteStatement],
    queries: &[OriginalSqliteQuery],
    before: &[OriginalSqliteRows],
    after: &[OriginalSqliteRows],
    budget: OriginalSqliteReadBudget,
) -> io::Result<()> {
    execute_fresh_metadata(connection, statements, queries, before, after, budget, None)
}

pub fn execute_fresh_retention_metadata(
    connection: &rusqlite::Connection,
    statements: &[OriginalSqliteStatement],
    queries: &[OriginalSqliteQuery],
    before: &[OriginalSqliteRows],
    after: &[OriginalSqliteRows],
    budget: OriginalSqliteReadBudget,
    gc_mark: bool,
) -> io::Result<()> {
    execute_fresh_metadata(
        connection,
        statements,
        queries,
        before,
        after,
        budget,
        Some(gc_mark),
    )
}

struct RetentionDmlAuthorization<'a>(&'a rusqlite::Connection);
unsafe extern "C" fn retention_dml(
    data: *mut std::ffi::c_void,
    action: i32,
    first: *const std::ffi::c_char,
    second: *const std::ffi::c_char,
    database: *const std::ffi::c_char,
    origin: *const std::ffi::c_char,
) -> i32 {
    if matches!(
        action,
        ffi::SQLITE_INSERT | ffi::SQLITE_UPDATE | ffi::SQLITE_DELETE
    ) {
        if first.is_null() || !origin.is_null() {
            return ffi::SQLITE_DENY;
        }
        // SAFETY: SQLite owns this terminated table identifier during authorization.
        let table = unsafe { CStr::from_ptr(first) }.to_bytes();
        let gc_mark = !data.is_null();
        let allowed = if gc_mark {
            (action == ffi::SQLITE_INSERT && matches!(table, b"gc_marks" | b"gc_clock"))
                || (action == ffi::SQLITE_UPDATE && table == b"gc_clock")
        } else {
            action == ffi::SQLITE_INSERT && table == b"local_state"
        };
        if !allowed {
            return ffi::SQLITE_DENY;
        }
    }
    // SAFETY: unchanged SQLite identifiers are passed to the original deny-first callback.
    unsafe { authorize_dml(ptr::null_mut(), action, first, second, database, origin) }
}
impl<'a> RetentionDmlAuthorization<'a> {
    fn install(connection: &'a rusqlite::Connection, gc_mark: bool) -> io::Result<Self> {
        let mode = if gc_mark {
            std::ptr::dangling_mut::<std::ffi::c_void>()
        } else {
            ptr::null_mut()
        };
        // SAFETY: callback uses data only as a mode bit and never dereferences it.
        let result =
            unsafe { ffi::sqlite3_set_authorizer(connection.handle(), Some(retention_dml), mode) };
        if result != ffi::SQLITE_OK {
            return Err(io::Error::other("retention metadata authorizer"));
        }
        Ok(Self(connection))
    }
}
impl Drop for RetentionDmlAuthorization<'_> {
    fn drop(&mut self) {
        // SAFETY: guard retains this connection for the full synchronous transition.
        unsafe {
            ffi::sqlite3_set_authorizer(self.0.handle(), None, ptr::null_mut());
        }
    }
}

fn execute_fresh_metadata(
    connection: &rusqlite::Connection,
    statements: &[OriginalSqliteStatement],
    queries: &[OriginalSqliteQuery],
    before: &[OriginalSqliteRows],
    after: &[OriginalSqliteRows],
    budget: OriginalSqliteReadBudget,
    metadata_mode: Option<bool>,
) -> io::Result<()> {
    if statements.is_empty()
        || statements.len() > 1024
        || queries.len() != before.len()
        || queries.len() != after.len()
    {
        return Err(io::Error::other(
            "fresh history exact complete transition bounds",
        ));
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
        admitted_query_rows(connection, queries, before, budget).map_err(|error| {
            io::Error::other(format!("fresh history before whole rows: {error}"))
        })?;
        {
            let _progress = OriginalVmBudget::install(
                connection,
                budget.max_vm_instructions,
                budget.max_seconds,
            )?;
            let _history_authorizer;
            let _metadata_authorizer;
            if let Some(gc_mark) = metadata_mode {
                _history_authorizer = None;
                _metadata_authorizer =
                    Some(RetentionDmlAuthorization::install(connection, gc_mark)?);
            } else {
                _history_authorizer = Some(AdmittedDmlAuthorization::install(connection)?);
                _metadata_authorizer = None;
            }
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
        admitted_query_rows(connection, queries, after, budget).map_err(|error| {
            io::Error::other(format!("fresh history after whole rows: {error}"))
        })?;
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
