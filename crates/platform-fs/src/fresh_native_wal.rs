//! SQLite uses freshly acquired exclusive handles without any path reopen.
use super::{FileKey, FreshExclusiveSqliteFile};
use crate::original_sqlite_dispatch::{reserve_registration, Dispatch, MAX_NAME_BYTES};
use rusqlite::ffi;
use std::{
    ffi::{CStr, CString},
    io,
    os::windows::fs::FileExt,
    ptr,
    rc::Rc,
};

/// The actual fixed SHM capacity admitted and mapped by this native engine.
/// Runtime allocation envelopes derive from this same gate.
pub const FRESH_NATIVE_WAL_SHM_CAPACITY: u64 = 1024 * 1024;

struct Policy {
    files: [FreshExclusiveSqliteFile; 4],
    names: [CString; 4],
    limits: [u64; 4],
    poisoned: std::cell::Cell<bool>,
    main_open_permitted: std::cell::Cell<bool>,
    main_opened: std::cell::Cell<bool>,
    main_active: std::cell::Cell<bool>,
    scope_issued: std::cell::Cell<bool>,
    active_io: std::cell::Cell<usize>,
    shm: std::cell::RefCell<Option<ShmMapping>>,
    shm_lock_bits: std::cell::Cell<u8>,
}
#[repr(C)]
struct NativeIo {
    header: ffi::sqlite3_file,
    dispatch: *const Dispatch,
    index: usize,
    readonly: bool,
}
unsafe fn state<'a>(file: *mut ffi::sqlite3_file) -> Option<(&'a Policy, usize)> {
    if file.is_null() {
        return None;
    }
    // SAFETY: a successful xOpen initialized this advertised file storage.
    // Read only the immutable permanent dispatch pointer before touching state.
    let dispatch = unsafe { (*file.cast::<NativeIo>()).dispatch };
    if dispatch.is_null() {
        return None;
    }
    // SAFETY: published dispatches are bounded permanent tombstones. The method
    // rejects foreign threads before any Rc/Cell-backed Policy is dereferenced.
    let original = unsafe { &*dispatch }.original_state()?;
    // SAFETY: only the owning thread can reach live state, and that same thread
    // clears dispatch after unregister before releasing the policy.
    let owner = unsafe { &*original.as_ptr().cast::<Policy>() };
    // SAFETY: now the original thread alone reads this initialized IO context.
    let index = unsafe { (*file.cast::<NativeIo>()).index };
    Some((owner, index))
}
unsafe fn policy<'a>(vfs: *mut ffi::sqlite3_vfs) -> Option<&'a Policy> {
    if vfs.is_null() {
        return None;
    }
    // SAFETY: this table and its dispatch remain permanently allocated once
    // published, including cached table lookups made before unregister.
    let dispatch = unsafe { (*vfs).pAppData.cast::<Dispatch>() };
    if dispatch.is_null() {
        return None;
    }
    // SAFETY: only the permanent atomic dispatch is read before its thread gate.
    let original = unsafe { &*dispatch }.original_state()?;
    // SAFETY: original_state grants only the original thread a live pointer.
    Some(unsafe { &*original.as_ptr().cast::<Policy>() })
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
    if !file.is_null() {
        // SAFETY: SQLite provides its advertised file storage for this open.
        // Every rejection exposes a null methods table, including a foreign
        // thread or a cached VFS whose original policy has already ended.
        unsafe {
            (*file).pMethods = ptr::null();
        }
    }
    if vfs.is_null() || name.is_null() || file.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: callback table and terminated SQLite filename are live.
    let Some(owner) = (unsafe { policy(vfs) }) else {
        return ffi::SQLITE_CANTOPEN;
    };
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
        || owner.active_io.get() >= 4
        || (index == 0 && (!owner.main_open_permitted.get() || owner.main_opened.get()))
        || (index != 0 && !owner.main_active.get())
        || normalized(name) != normalized(&owner.names[index])
        || flags & (ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_READONLY) == 0
        || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0
        || owner.files[index].verify().is_err()
    {
        owner.poisoned.set(true);
        return ffi::SQLITE_CANTOPEN;
    }
    if index == 0 {
        owner.main_opened.set(true);
        owner.main_active.set(true);
    }
    owner.active_io.set(owner.active_io.get() + 1);
    // SAFETY: SQLite allocated advertised NativeIo size/alignment; the policy
    // remains live. No base xOpen, CREATE, path resolution or handle release occurs.
    unsafe {
        ptr::write(
            file.cast::<NativeIo>(),
            NativeIo {
                header: ffi::sqlite3_file { pMethods: &METHODS },
                dispatch: (*vfs).pAppData.cast::<Dispatch>(),
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
unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> i32 {
    // SAFETY: SQLite closes only storage initialized by our successful xOpen;
    // the IO owner retains the policy while this active count is nonzero.
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_CLOSE;
    };
    let Some(remaining) = owner.active_io.get().checked_sub(1) else {
        owner.poisoned.set(true);
        return ffi::SQLITE_IOERR_CLOSE;
    };
    owner.active_io.set(remaining);
    if index == 0 {
        owner.main_active.set(false);
    }
    // SAFETY: SQLite owns this file storage through the end of xClose.
    unsafe {
        (*file).pMethods = ptr::null();
    }
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_READ;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_WRITE;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_TRUNCATE;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_FSYNC;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_FSTAT;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_LOCK;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    };
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
    let Some(owner) = (unsafe { policy(vfs) }) else {
        return ffi::SQLITE_IOERR_ACCESS;
    };
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
    let Some(owner) = (unsafe { policy(vfs) }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
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
    let Some(owner) = (unsafe { policy(vfs) }) else {
        return ffi::SQLITE_CANTOPEN;
    };
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
struct FreshNativeWalContext {
    registration: Box<ffi::sqlite3_vfs>,
    name: CString,
    policy: Rc<Policy>,
    dispatch: Box<Dispatch>,
    registered: bool,
    published: bool,
}

/// Owns only the original four native files and their one-use VFS registration.
/// It never owns, creates, or exposes a rusqlite Connection.
pub struct FreshNativeWalIo {
    context: Option<FreshNativeWalContext>,
    path: std::path::PathBuf,
    actual_closed_handle_prefix: usize,
    original_terminal_error: Option<io::Error>,
}

/// A short borrow permits exactly one MAIN xOpen from these actual names.
pub struct FreshNativeWalOpenScope<'owner> {
    owner: &'owner FreshNativeWalIo,
}
impl FreshNativeWalOpenScope<'_> {
    pub fn database_path(&self) -> &CStr {
        &self.owner.context_ref().policy.names[0]
    }
    pub fn vfs_name(&self) -> &CStr {
        &self.owner.context_ref().name
    }
}
impl Drop for FreshNativeWalOpenScope<'_> {
    fn drop(&mut self) {
        self.owner
            .context_ref()
            .policy
            .main_open_permitted
            .set(false);
    }
}
/// An open rejection has attempted the terminal of the original four files
/// and any actual partial database/registration/mapping acquired on the way.
pub struct FreshNativeWalIoOpenFailure {
    pub error: io::Error,
    pub original_resources: Option<FreshNativeWalIoCloseFailure>,
}

impl FreshNativeWalIoOpenFailure {
    pub fn retain_and_report(self) -> io::Error {
        if let Some(original) = self.original_resources {
            original.retain_until_process_exit();
        }
        self.error
    }
}

/// Owns every original native resource that failed to end. No decoder, clone,
/// restart, registration, or path-to-owner operation is available here.
pub struct FreshNativeWalIoCloseFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original_owner: Option<FreshNativeWalIo>,
    original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for FreshNativeWalIoCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FreshNativeWalIoCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field(
                "original_native_context_retained",
                &self.original_owner.is_some(),
            )
            .field(
                "original_handle_groups_retained",
                &self.original_resources.as_ref().map_or(
                    0,
                    crate::WindowsOriginalResourceCloseFailure::retained_resource_groups,
                ),
            )
            .finish()
    }
}

fn copy_original_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

fn reject_original_open_files(
    error: io::Error,
    files: [FreshExclusiveSqliteFile; 4],
) -> FreshNativeWalIoOpenFailure {
    let mut attempt = crate::WindowsOriginalCloseAttempt::new();
    for file in files {
        file.close_into_attempt(&mut attempt);
    }
    let original_resources = attempt
        .finish()
        .err()
        .map(|original| FreshNativeWalIoCloseFailure {
            error: copy_original_error(&original.error),
            actual_closed_handles: original.actual_closed_handles,
            original_owner: None,
            original_resources: Some(original),
        });
    FreshNativeWalIoOpenFailure {
        error,
        original_resources,
    }
}

impl FreshNativeWalIoCloseFailure {
    /// Pure inspection of resources retained by this terminal failure. It
    /// cannot confer a lease, original owner, native effect, or clean closure.
    pub fn has_retained_originals(&self) -> bool {
        self.original_owner
            .as_ref()
            .is_some_and(FreshNativeWalIo::original_resources_remain)
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    /// Retry only the terminal of these same originals. The first observed
    /// terminal error remains recorded even if every retry later succeeds.
    pub fn close_remaining(mut self) -> Self {
        let mut attempt = crate::WindowsOriginalCloseAttempt::new();
        if let Some(original) = self.original_resources.take() {
            let original = original.close_remaining();
            attempt.append_failure(original);
        } else {
            attempt.note_error(copy_original_error(&self.error));
            attempt.append_original_handle_prefix(self.actual_closed_handles);
        }
        if let Some(mut original) = self.original_owner.take() {
            original.close_original_into_attempt(&mut attempt);
            if original.original_resources_remain() {
                self.original_owner = Some(original);
            }
        }
        let original_resources = match attempt.finish() {
            Err(original) => original,
            Ok(_) => unreachable!("the first original native terminal error cannot disappear"),
        };
        self.actual_closed_handles = original_resources.actual_closed_handles;
        self.original_resources = Some(original_resources);
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
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

    /// Consume only the loan from the same native owner. This has no resource
    /// close witness and cannot issue another live lease or session.
    pub fn end_original_loan(self) {
        drop(self);
    }
}
impl FreshNativeWalIo {
    fn context_ref(&self) -> &FreshNativeWalContext {
        self.context
            .as_ref()
            .expect("a usable fresh native owner retains its original context")
    }
    pub fn open_retaining(
        path: &std::path::Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
    ) -> Result<Self, FreshNativeWalIoOpenFailure> {
        let id = match reserve_registration() {
            Ok(id) => id,
            Err(error) => return Err(reject_original_open_files(error, files)),
        };
        let prepared =
            (|| -> io::Result<([CString; 4], CString, Box<ffi::sqlite3_vfs>, Box<Dispatch>)> {
                if !path.is_absolute()
                    || path.file_name().and_then(|v| v.to_str()) != Some("journal.sqlite")
                    || limits
                        .iter()
                        .any(|n| !(512..=256 * 1024 * 1024).contains(n))
                    || limits.iter().sum::<u64>() > 512 * 1024 * 1024
                    || limits[3] != FRESH_NATIVE_WAL_SHM_CAPACITY
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
                let name = CString::new(format!("sync-fresh-native-{}-{id}", std::process::id()))
                    .map_err(io::Error::other)?;
                if name.to_bytes_with_nul().len() > MAX_NAME_BYTES {
                    return Err(io::Error::other("bounded original SQLite VFS name"));
                }
                let dispatch = Box::new(Dispatch::new()?);
                // SAFETY: the builtin VFS lives for the process. Its copied table
                // supplies only time/randomness while our actual IO stays private.
                let base = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
                if base.is_null() {
                    return Err(io::Error::other("builtin VFS absent"));
                }
                // SAFETY: base points to SQLite's initialized original VFS table.
                Ok((names, name, Box::new(unsafe { *base }), dispatch))
            })();
        let (names, name, mut registration, dispatch) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(reject_original_open_files(error, files)),
        };
        let policy = Rc::new(Policy {
            files,
            names,
            limits,
            poisoned: std::cell::Cell::new(false),
            main_open_permitted: std::cell::Cell::new(false),
            main_opened: std::cell::Cell::new(false),
            main_active: std::cell::Cell::new(false),
            scope_issued: std::cell::Cell::new(false),
            active_io: std::cell::Cell::new(0),
            shm: std::cell::RefCell::new(None),
            shm_lock_bits: std::cell::Cell::new(0),
        });
        registration.pNext = ptr::null_mut();
        registration.zName = name.as_ptr();
        dispatch.publish(Rc::as_ptr(&policy).cast_mut().cast());
        registration.pAppData = (&*dispatch as *const Dispatch).cast_mut().cast();
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
        let mut owner = Self {
            context: Some(FreshNativeWalContext {
                registration,
                name,
                policy,
                dispatch,
                registered: false,
                published: false,
            }),
            path: path.to_owned(),
            actual_closed_handle_prefix: 0,
            original_terminal_error: None,
        };
        let context = owner
            .context
            .as_mut()
            .expect("original context just prepared");
        // SAFETY: this owner retains the actual table/name/policy. The existing
        // registration is private and the default VFS is unchanged.
        context.published = true;
        let registered = unsafe { ffi::sqlite3_vfs_register(&mut *context.registration, 0) };
        if registered != ffi::SQLITE_OK {
            return Err(owner.reject_open(io::Error::other(format!(
                "fresh native WAL SQLite original registration returned {registered}",
            ))));
        }
        context.registered = true;
        Ok(owner)
    }
    pub fn verify(&self) -> io::Result<()> {
        if self.context_ref().policy.poisoned.get() {
            return Err(io::Error::other("fresh native WAL SQLite uncertain"));
        }
        for file in &self.context_ref().policy.files {
            file.verify()?;
        }
        if !self.context_ref().policy.files[0].matches_path(&self.path)? {
            return Err(io::Error::other("fresh WAL SQLite target slot differs"));
        }
        Ok(())
    }
    pub fn single_open_scope(&mut self) -> io::Result<FreshNativeWalOpenScope<'_>> {
        self.verify()?;
        let policy = &self.context_ref().policy;
        if policy.scope_issued.replace(true)
            || policy.main_opened.get()
            || policy.active_io.get() != 0
        {
            policy.poisoned.set(true);
            return Err(io::Error::other(
                "original native VFS opening scope already consumed",
            ));
        }
        policy.main_open_permitted.set(true);
        Ok(FreshNativeWalOpenScope { owner: self })
    }
    pub fn verify_connection_opened(&self) -> io::Result<()> {
        self.verify()?;
        let policy = &self.context_ref().policy;
        if !policy.main_opened.get()
            || !policy.main_active.get()
            || policy.main_open_permitted.get()
            || policy.active_io.get() == 0
        {
            return Err(io::Error::other(
                "original native VFS main opening not confirmed",
            ));
        }
        Ok(())
    }
    pub fn poison(&self) {
        self.context_ref().policy.poisoned.set(true);
    }
    pub fn original_resources_remain(&self) -> bool {
        self.context.is_some()
    }
    /// End only this capsule's actual resources, preserving any failed originals.
    pub fn close_into_original_attempt(
        &mut self,
        attempt: &mut crate::WindowsOriginalCloseAttempt,
    ) {
        self.close_original_into_attempt(attempt);
    }
    pub fn close_shm_retaining(&mut self) -> io::Result<()> {
        if self.context_ref().policy.active_io.get() != 0 {
            return Err(io::Error::other(
                "original SQLite IO still active before SHM terminal",
            ));
        }
        self.close_original_shm_retaining()
    }
    pub fn exact_bytes(&self, index: usize) -> io::Result<Vec<u8>> {
        let policy = &self.context_ref().policy;
        let file = policy
            .files
            .get(index)
            .ok_or_else(|| io::Error::other("original native file index"))?;
        file.verify()?;
        file.exact_bytes(policy.limits[index])
    }
    fn reject_open(self, error: io::Error) -> FreshNativeWalIoOpenFailure {
        FreshNativeWalIoOpenFailure {
            error,
            original_resources: self.close_original_resources_retaining().err(),
        }
    }
    fn close_original_shm_retaining(&mut self) -> io::Result<()> {
        let mut attempt = crate::WindowsOriginalCloseAttempt::new();
        let context = self.context_ref();
        {
            let mut retained = context.policy.shm.borrow_mut();
            if let Some(mapping) = retained.as_mut() {
                mapping.close_original_into_attempt(&mut attempt);
                if !mapping.original_resources_remain() {
                    retained.take();
                }
            }
        }
        match attempt.finish() {
            Ok(closed) => {
                self.actual_closed_handle_prefix += closed.actual_closed_handles();
                Ok(())
            }
            Err(original) => {
                self.actual_closed_handle_prefix += original.actual_closed_handles;
                let error = original.error;
                self.original_terminal_error
                    .get_or_insert_with(|| copy_original_error(&error));
                self.context_ref().policy.poisoned.set(true);
                Err(error)
            }
        }
    }
    fn close_original_into_attempt(&mut self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt
            .append_original_handle_prefix(std::mem::take(&mut self.actual_closed_handle_prefix));
        if let Some(error) = self.original_terminal_error.take() {
            attempt.note_error(error);
        }
        // Actual xClose callbacks, not a caller assertion, prove IO is idle.
        if self.context.as_ref().is_some_and(|context| {
            context.policy.active_io.get() != 0 || context.policy.main_open_permitted.get()
        }) {
            attempt.note_error(io::Error::other(
                "original native SQLite callbacks still live",
            ));
            return;
        }
        let Some(mut context) = self.context.take() else {
            return;
        };
        {
            let mut retained = context.policy.shm.borrow_mut();
            if let Some(mapping) = retained.as_mut() {
                mapping.close_original_into_attempt(attempt);
                if !mapping.original_resources_remain() {
                    retained.take();
                }
            }
        }
        if context.registered {
            // SAFETY: the actual DB is closed. Unregister this same retained
            // registration once; a failed call keeps its table/name/policy.
            let closed = unsafe { ffi::sqlite3_vfs_unregister(&mut *context.registration) };
            if closed != ffi::SQLITE_OK {
                attempt.note_error(io::Error::other(format!(
                    "fresh native WAL original VFS unregister returned {closed}",
                )));
                self.context = Some(context);
                return;
            }
            context.registered = false;
        }
        if context.policy.shm.borrow().is_some() {
            attempt.note_error(io::Error::other(
                "fresh native WAL original shared-memory view/section remains retained",
            ));
            self.context = Some(context);
            return;
        }
        if Rc::strong_count(&context.policy) != 1 {
            attempt.note_error(io::Error::new(
                io::ErrorKind::WouldBlock,
                "fresh native WAL terminal retains an outstanding original native loan",
            ));
            self.context = Some(context);
            return;
        }
        let FreshNativeWalContext {
            registration,
            name,
            policy,
            dispatch,
            registered,
            published,
        } = context;
        let policy = match Rc::try_unwrap(policy) {
            Ok(policy) => policy,
            Err(policy) => {
                attempt.note_error(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "fresh native WAL original policy loan remains held",
                ));
                self.context = Some(FreshNativeWalContext {
                    registration,
                    name,
                    policy,
                    dispatch,
                    registered,
                    published,
                });
                return;
            }
        };
        dispatch.clear();
        if published {
            // A foreign SQLite caller can cache the published VFS forever.
            // Keep only bounded inert dispatch/table/name, never live Policy.
            let _ = Box::leak(registration);
            let _ = Box::leak(dispatch);
            std::mem::forget(name);
        }
        for file in policy.files {
            file.close_into_attempt(attempt);
        }
    }
    pub fn close_original_resources_retaining(
        mut self,
    ) -> Result<crate::ClosedWindowsOriginalResources, FreshNativeWalIoCloseFailure> {
        let mut attempt = crate::WindowsOriginalCloseAttempt::new();
        self.close_original_into_attempt(&mut attempt);
        match attempt.finish() {
            Ok(closed) if !self.original_resources_remain() => Ok(closed),
            Ok(_) => unreachable!("a retained original native resource records a terminal error"),
            Err(original) => Err(FreshNativeWalIoCloseFailure {
                error: copy_original_error(&original.error),
                actual_closed_handles: original.actual_closed_handles,
                original_owner: if self.original_resources_remain() {
                    Some(self)
                } else {
                    None
                },
                original_resources: Some(original),
            }),
        }
    }
    pub fn verify_closed_native_objects(&self) -> io::Result<()> {
        if self.context_ref().policy.active_io.get() != 0
            || self.context_ref().policy.main_open_permitted.get()
            || self.context_ref().policy.shm.borrow().is_some()
            || self.context_ref().policy.poisoned.get()
        {
            return Err(io::Error::other(
                "fresh native WAL actual close not confirmed",
            ));
        }
        for (index, file) in self.context_ref().policy.files.iter().enumerate() {
            file.verify()?;
            if !file.matches_path(std::path::Path::new(
                self.context_ref().policy.names[index]
                    .to_str()
                    .map_err(io::Error::other)?,
            ))? {
                return Err(io::Error::other("fresh closed native file slot changed"));
            }
        }
        let rollback =
            self.context_ref().policy.files[2].exact_bytes(self.context_ref().policy.limits[2])?;
        if !self.context_ref().policy.files[1]
            .exact_bytes(self.context_ref().policy.limits[1])?
            .is_empty()
            || (!rollback.is_empty() && rollback.get(..8) != Some(&[0; 8]))
        {
            return Err(io::Error::other(
                "fresh actual close nonhot sidecars required",
            ));
        }
        Ok(())
    }
    pub fn held_shm_bytes(&self) -> io::Result<Vec<u8>> {
        self.context_ref().policy.files[3].verify()?;
        self.context_ref().policy.files[3].exact_bytes(FRESH_NATIVE_WAL_SHM_CAPACITY)
    }
    pub fn all_native_keys(&self) -> io::Result<[FileKey; 4]> {
        self.context_ref()
            .policy
            .files
            .each_ref()
            .map(|file| file.key())
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| io::Error::other("four held native keys"))
    }
    pub fn issue_retention_lease(&self, generation: u32) -> io::Result<FreshNativeRetentionLease> {
        self.verify()?;
        if self.context_ref().policy.active_io.get() == 0 || generation >= 64 {
            return Err(io::Error::other(
                "retention requires a committed live native session",
            ));
        }
        Ok(FreshNativeRetentionLease {
            policy: Rc::clone(&self.context_ref().policy),
            keys: self.all_native_keys()?,
            generation,
        })
    }
    pub fn verify_retention_lease(&self, lease: &FreshNativeRetentionLease) -> io::Result<()> {
        self.verify()?;
        if self.context_ref().policy.active_io.get() == 0
            || !Rc::ptr_eq(&self.context_ref().policy, &lease.policy)
            || self.all_native_keys()? != lease.keys
        {
            return Err(io::Error::other(
                "retention issuer is not this live native owner",
            ));
        }
        Ok(())
    }
    pub fn open_after_explicit_shm_epoch_retaining(
        path: &std::path::Path,
        files: [FreshExclusiveSqliteFile; 4],
        limits: [u64; 4],
        expected_shm: (&str, &[u8]),
    ) -> Result<Self, FreshNativeWalIoOpenFailure> {
        let checked = (|| -> io::Result<()> {
            if !path.is_absolute()
                || path.file_name().and_then(|n| n.to_str()) != Some("journal.sqlite")
                || limits
                    .iter()
                    .any(|n| !(512..=256 * 1024 * 1024).contains(n))
                || limits.iter().sum::<u64>() > 512 * 1024 * 1024
                || limits[3] != FRESH_NATIVE_WAL_SHM_CAPACITY
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
                || shm.exact_bytes(FRESH_NATIVE_WAL_SHM_CAPACITY)? != expected_shm.1
                || shm.native_file().metadata()?.len() != FRESH_NATIVE_WAL_SHM_CAPACITY
                || !shm.matches_path(&path.with_file_name("journal.sqlite-shm"))?
                || shm.parent_key()? != files[0].parent_key()?
                || limits[3] != FRESH_NATIVE_WAL_SHM_CAPACITY
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
            if shm
                .exact_bytes(FRESH_NATIVE_WAL_SHM_CAPACITY)?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(io::Error::other(
                    "new SHM epoch exact zero index confirmation",
                ));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(reject_original_open_files(error, files));
        }
        Self::open_retaining(path, files, limits)
    }
    pub fn shm_mapping_active(&self) -> io::Result<bool> {
        self.verify()?;
        Ok(self.context_ref().policy.shm.borrow().is_some())
    }
}
impl Drop for FreshNativeWalIo {
    fn drop(&mut self) {
        if !self.original_resources_remain() {
            return;
        }
        // Move the same original context, table, DB, mapping, and native files
        // into a terminal-only owner. No acquisition or registration occurs.
        let original = Self {
            context: self.context.take(),
            path: std::mem::take(&mut self.path),
            actual_closed_handle_prefix: std::mem::take(&mut self.actual_closed_handle_prefix),
            original_terminal_error: self.original_terminal_error.take(),
        };
        if let Err(original) = original.close_original_resources_retaining() {
            original.retain_until_process_exit();
        }
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
    section: Option<HANDLE>,
    view: Option<MEMORY_MAPPED_VIEW_ADDRESS>,
}
impl ShmMapping {
    fn original_resources_remain(&self) -> bool {
        self.section.is_some() || self.view.is_some()
    }

    fn close_original_into_attempt(&mut self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        if let Some(view) = self.view {
            // SAFETY: this is the exact original mapped view, retained after
            // its SQLite connection has closed. No replacement view is made.
            if unsafe { UnmapViewOfFile(view) } == 0 {
                attempt.note_error(io::Error::last_os_error());
            } else {
                self.view = None;
            }
        }
        if let Some(section) = self.section {
            // SAFETY: successful CreateFileMapping transferred this actual
            // original section. A failed close keeps that same owned HANDLE.
            if unsafe { CloseHandle(section) } == 0 {
                attempt.note_error(io::Error::last_os_error());
            } else {
                self.section = None;
                attempt.note_actual_handle_closed();
            }
        }
    }
}
impl Drop for ShmMapping {
    fn drop(&mut self) {
        if !self.original_resources_remain() {
            return;
        }
        let mut original = Self {
            section: self.section.take(),
            view: self.view.take(),
        };
        let mut attempt = crate::WindowsOriginalCloseAttempt::new();
        original.close_original_into_attempt(&mut attempt);
        if original.original_resources_remain() {
            let _ = Box::leak(Box::new(original));
        }
        // A fallback drop has no successful-close evidence. Any failed view or
        // section remains in the exact original terminal-only leaked owner.
        let _ = attempt.finish();
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
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
        // Retain the successful actual section before a subsequent mapping
        // attempt can fail. Terminal close is performed by its original owner.
        *mapping = Some(ShmMapping {
            section: Some(section),
            view: None,
        });
        // SAFETY: live bounded section; full view starts at aligned offset zero.
        let view =
            unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, owner.limits[3] as usize) };
        if view.Value.is_null() {
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        mapping.as_mut().expect("original section retained").view = Some(view);
    }
    let Some(value) = mapping.as_ref() else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    let Some(view) = value.view else {
        owner.poisoned.set(true);
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // SAFETY: page is in 0..32, size fixed32768; pointer remains inside retained view.
    unsafe {
        *out = view.Value.cast::<u8>().add(page as usize * 32768).cast();
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_SHMLOCK;
    };
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
    let Some((owner, index)) = (unsafe { state(file) }) else {
        return ffi::SQLITE_IOERR_SHMOPEN;
    };
    if index != 0 || owner.files[3].verify().is_err() {
        return ffi::SQLITE_IOERR_SHMOPEN;
    }
    if let Some(mapping) = owner.shm.borrow().as_ref() {
        let Some(view) = mapping.view else {
            return ffi::SQLITE_IOERR_SHMOPEN;
        };
        // SAFETY: retained view covers exactly the bounded mapped file.
        if unsafe { FlushViewOfFile(view.Value, owner.limits[3] as usize) } == 0 {
            owner.poisoned.set(true);
            return ffi::SQLITE_IOERR_FSYNC;
        }
    }
    ffi::SQLITE_OK
}
