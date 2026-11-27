//! No base VFS, pathname reopen, unlink, or numeric-descriptor reconstruction.
use super::super::super::refuse;
use super::{Dispatch, Mapping, State, SHM_REGION};
use rusqlite::ffi;
use std::{
    ffi::{c_char, c_int, c_void, CStr},
    io,
    os::fd::AsRawFd,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::atomic::{fence, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[repr(C)]
struct NativeFile {
    base: ffi::sqlite3_file,
    dispatch: *const Dispatch,
    state: *const State<'static>,
    class: usize,
    lock: c_int,
    opened: bool,
}

unsafe fn state<'a>(vfs: *mut ffi::sqlite3_vfs) -> Option<&'a State<'a>> {
    // SAFETY: published tables and their inert dispatches stay alive within the
    // permanent bounded pool, even after SQLite caches a global table lookup.
    let dispatch = unsafe { &*(*vfs).pAppData.cast::<Dispatch>() };
    let original = dispatch.original_state()?;
    // SAFETY: only the original owning thread can load/dereference live state.
    // That same thread nulls it after unregister before the state is released.
    Some(unsafe { &*original.as_ptr().cast::<State<'a>>() })
}

unsafe fn native<'a>(file: *mut ffi::sqlite3_file) -> io::Result<&'a mut NativeFile> {
    if file.is_null() {
        return Err(refuse("original Unix SQLite IO context absent"));
    }
    // SAFETY: successful xOpen initialized this advertised sized IO context.
    // Read only its stable dispatch pointer before creating a mutable context.
    let dispatch = unsafe { (*file.cast::<NativeFile>()).dispatch };
    if dispatch.is_null() {
        return Err(refuse("original Unix SQLite dispatch absent"));
    }
    // SAFETY: dispatch is retained permanently once published. Foreign threads
    // are rejected before touching mutable context or its Rc-backed state.
    if !unsafe { &*dispatch }.on_original_thread() {
        return Err(refuse("original Unix SQLite IO used from foreign thread"));
    }
    // SAFETY: the sole owning Connection serializes each native IO callback on
    // this original thread. No base VFS or second main connection is admitted.
    let file = unsafe { &mut *file.cast::<NativeFile>() };
    if !file.opened || file.state.is_null() {
        return Err(refuse("original Unix SQLite IO context closed"));
    }
    Ok(file)
}

fn guarded(state: &State<'_>, failure: c_int, action: impl FnOnce() -> io::Result<c_int>) -> c_int {
    if !state.on_original_thread() {
        return failure;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        state.verify()?;
        let result = action()?;
        state.verify()?;
        Ok::<_, io::Error>(result)
    })) {
        Ok(Ok(value)) => value,
        _ => {
            state.poisoned.set(true);
            failure
        }
    }
}

unsafe fn io(
    file: *mut ffi::sqlite3_file,
    failure: c_int,
    action: impl FnOnce(&mut NativeFile, &State<'_>) -> io::Result<c_int>,
) -> c_int {
    // SAFETY: callback receives the actual initialized IO object.
    let file = match unsafe { native(file) } {
        Ok(file) => file,
        Err(_) => return failure,
    };
    // SAFETY: original registration retains state past all active IO contexts.
    let owner = unsafe { &*file.state };
    guarded(owner, failure, || action(file, owner))
}

fn class(owner: &State<'_>, name: &CStr) -> io::Result<usize> {
    if name.to_bytes().len() > 32_768 {
        return Err(refuse("bounded original SQLite name"));
    }
    owner
        .paths
        .iter()
        .position(|path| path.as_c_str() == name)
        .ok_or_else(|| refuse("SQLite filename has no actual original creator"))
}

fn range(offset: i64, count: c_int, maximum: u64) -> io::Result<(u64, usize)> {
    let offset = u64::try_from(offset).map_err(|_| refuse("negative original SQLite IO offset"))?;
    let count = usize::try_from(count).map_err(|_| refuse("negative original SQLite IO count"))?;
    if offset
        .checked_add(count as u64)
        .is_none_or(|end| end > maximum)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "original Unix SQLite file capacity exceeded",
        ));
    }
    Ok((offset, count))
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    if vfs.is_null() || name.is_null() || file.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: SQLite's output is our advertised size; no methods on failed open.
    unsafe {
        (*file).pMethods = ptr::null();
    }
    // SAFETY: live registration with stable original state.
    let Some(owner) = (unsafe { state(vfs) }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    guarded(owner, ffi::SQLITE_CANTOPEN, || {
        // SAFETY: SQLite supplies its prepared, NUL-terminated filename.
        let name = unsafe { CStr::from_ptr(name) };
        let class = class(owner, name)?;
        let kind = flags
            & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL);
        if !matches!((class, kind), (0, ffi::SQLITE_OPEN_MAIN_DB) | (1, ffi::SQLITE_OPEN_WAL) | (2, ffi::SQLITE_OPEN_MAIN_JOURNAL))
            || flags & ffi::SQLITE_OPEN_READWRITE == 0
            || flags & (ffi::SQLITE_OPEN_DELETEONCLOSE | ffi::SQLITE_OPEN_MEMORY) != 0
            // SAFETY: xOpen receives SQLite's filename-plus-URI representation.
            || !unsafe { ffi::sqlite3_uri_key(name.as_ptr(), 0) }.is_null()
        {
            return Err(refuse("original SQLite class/access/URI differs"));
        }
        if class == 0 && (!owner.main_open_permitted.get() || owner.main_opened.replace(true)) {
            return Err(refuse(
                "original Unix SQLite main already acquired by its sole connection",
            ));
        }
        if class != 0 && !owner.main_active.get() {
            return Err(refuse("original Unix SQLite sidecar requires its active main"));
        }
        let count = owner
            .active_files
            .get()
            .checked_add(1)
            .filter(|count| *count <= 4)
            .ok_or_else(|| refuse("original Unix SQLite context bound"))?;
        // SAFETY: SQLite provides aligned sized storage. Its context points at
        // the stable retained owner and cannot outlive the registered owner.
        unsafe {
            ptr::write(
                file.cast::<NativeFile>(),
                NativeFile {
                    base: ffi::sqlite3_file { pMethods: &METHODS },
                    dispatch: (*vfs).pAppData.cast::<Dispatch>(),
                    state: (owner as *const State<'_>).cast(),
                    class,
                    lock: ffi::SQLITE_LOCK_NONE,
                    opened: true,
                },
            );
            if !out.is_null() {
                *out = ffi::SQLITE_OPEN_READWRITE;
            }
        }
        owner.active_files.set(count);
        if class == 0 {
            owner.main_active.set(true);
        }
        Ok(ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    // Cleanup must run even after an earlier verification poisoned the owner.
    // SAFETY: SQLite supplies the actual previously initialized IO object.
    let native = match unsafe { native(file) } {
        Ok(file) => file,
        Err(_) => return ffi::SQLITE_IOERR_CLOSE,
    };
    // SAFETY: retained owner remains alive through this last native callback.
    let owner = unsafe { &*native.state };
    if !owner.on_original_thread() {
        return ffi::SQLITE_IOERR_CLOSE;
    }
    let unmap = if native.class == 0 {
        owner.main_active.set(false);
        owner.unmap()
    } else {
        Ok(())
    };
    let count = owner.active_files.get();
    if count == 0 || unmap.is_err() {
        owner.poisoned.set(true);
    }
    owner.active_files.set(count.saturating_sub(1));
    native.opened = false;
    native.base.pMethods = ptr::null();
    native.state = ptr::null();
    if unmap.is_ok() && count > 0 {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_CLOSE
    }
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    count: c_int,
    offset: i64,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_READ;
    }
    // SAFETY: initialized original IO and SQLite's counted writable buffer.
    unsafe {
        io(file, ffi::SQLITE_IOERR_READ, |opened, owner| {
            let original = &owner.files[opened.class];
            let (offset, count) = range(offset, count, original.maximum)?;
            let output = std::slice::from_raw_parts_mut(output.cast::<u8>(), count);
            output.fill(0);
            let done =
                crate::unix_descriptor_io::read_until_eof(&original.original.file, output, offset)?;
            Ok(if done == count {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_IOERR_SHORT_READ
            })
        })
    }
}

unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    input: *const c_void,
    count: c_int,
    offset: i64,
) -> c_int {
    if input.is_null() {
        return ffi::SQLITE_IOERR_WRITE;
    }
    // SAFETY: initialized original IO and SQLite's counted readable input.
    unsafe {
        io(file, ffi::SQLITE_FULL, |opened, owner| {
            let original = &owner.files[opened.class];
            let (offset, count) = range(offset, count, original.maximum)?;
            let input = std::slice::from_raw_parts(input.cast::<u8>(), count);
            crate::unix_descriptor_io::write_all(&original.original.file, input, offset)?;
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    // SAFETY: actual initialized IO descriptor supplied by SQLite.
    unsafe {
        io(file, ffi::SQLITE_IOERR_TRUNCATE, |opened, owner| {
            let original = &owner.files[opened.class];
            let (size, _) = range(size, 0, original.maximum)?;
            original.original.file.set_len(size)?;
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    // SAFETY: actual initialized IO descriptor supplied by SQLite.
    unsafe {
        io(file, ffi::SQLITE_IOERR_FSYNC, |opened, owner| {
            owner.files[opened.class].original.file.sync_all()?;
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn size(file: *mut ffi::sqlite3_file, output: *mut i64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_FSTAT;
    }
    // SAFETY: actual initialized IO and one sized writable integer output.
    unsafe {
        io(file, ffi::SQLITE_IOERR_FSTAT, |opened, owner| {
            *output = i64::try_from(owner.files[opened.class].original.file.metadata()?.len())
                .map_err(|_| refuse("original SQLite file length overflow"))?;
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn lock(file: *mut ffi::sqlite3_file, wanted: c_int) -> c_int {
    // SAFETY: actual original IO. The sole connection is protected by the
    // original CAS flock; local SQLite lock state does not invent a new lock.
    unsafe {
        io(file, ffi::SQLITE_IOERR_LOCK, |opened, _| {
            if !(ffi::SQLITE_LOCK_SHARED..=ffi::SQLITE_LOCK_EXCLUSIVE).contains(&wanted) {
                return Err(refuse("original SQLite lock level invalid"));
            }
            opened.lock = opened.lock.max(wanted);
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn unlock(file: *mut ffi::sqlite3_file, wanted: c_int) -> c_int {
    // SAFETY: actual initialized IO supplied by SQLite.
    unsafe {
        io(file, ffi::SQLITE_IOERR_UNLOCK, |opened, _| {
            if !matches!(wanted, ffi::SQLITE_LOCK_NONE | ffi::SQLITE_LOCK_SHARED) {
                return Err(refuse("original SQLite unlock level invalid"));
            }
            opened.lock = wanted;
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn reserved(file: *mut ffi::sqlite3_file, output: *mut c_int) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    // SAFETY: actual original IO and one sized writable output integer.
    unsafe {
        io(file, ffi::SQLITE_IOERR_CHECKRESERVEDLOCK, |opened, _| {
            *output = i32::from(opened.lock >= ffi::SQLITE_LOCK_RESERVED);
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    output: *mut c_void,
) -> c_int {
    // SAFETY: SQLite supplies native IO; only recognized sized outputs are used.
    unsafe {
        io(file, ffi::SQLITE_IOERR, |opened, _| {
            if output.is_null() {
                return Ok(ffi::SQLITE_NOTFOUND);
            }
            match operation {
                ffi::SQLITE_FCNTL_LOCKSTATE => *output.cast::<c_int>() = opened.lock,
                ffi::SQLITE_FCNTL_HAS_MOVED => *output.cast::<c_int>() = 0,
                ffi::SQLITE_FCNTL_MMAP_SIZE => *output.cast::<i64>() = 0,
                _ => return Ok(ffi::SQLITE_NOTFOUND),
            }
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn sector(_: *mut ffi::sqlite3_file) -> c_int {
    4096
}
unsafe extern "C" fn characteristics(_: *mut ffi::sqlite3_file) -> c_int {
    0
}

unsafe extern "C" fn shm_map(
    file: *mut ffi::sqlite3_file,
    region: c_int,
    size: c_int,
    _: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    // SAFETY: SQLite supplies a writable pointer output and original IO context.
    unsafe {
        *output = ptr::null_mut();
        io(file, ffi::SQLITE_IOERR_SHMMAP, |opened, owner| {
            if opened.class != 0 || region < 0 || size != SHM_REGION as c_int {
                return Err(refuse("original SQLite SHM region contract"));
            }
            let offset = i64::from(region)
                .checked_mul(i64::from(size))
                .ok_or_else(|| refuse("original SQLite SHM offset overflow"))?;
            let _ = range(offset, size, owner.files[3].maximum)?;
            let mut mappings = owner
                .mappings
                .try_borrow_mut()
                .map_err(|_| refuse("original SHM already borrowed"))?;
            if let Some(map) = mappings.get(&region) {
                *output = map.address;
                return Ok(ffi::SQLITE_OK);
            }
            let address = libc::mmap(
                ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                owner.files[3].original.file.as_raw_fd(),
                offset,
            );
            if address == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            mappings.insert(
                region,
                Mapping {
                    address,
                    bytes: size as usize,
                },
            );
            *output = address;
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: actual initialized main IO supplied by SQLite under one connection.
    unsafe {
        io(file, ffi::SQLITE_IOERR_SHMLOCK, |opened, owner| {
            if opened.class != 0
                || offset < 0
                || count <= 0
                || offset.checked_add(count).is_none_or(|end| end > 8)
                || !matches!(flags, v if v == ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_SHARED
                || v == ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE
                || v == ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_SHARED
                || v == ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_EXCLUSIVE)
            {
                return Err(refuse("original SQLite SHM lock range/flags"));
            }
            let mask = (((1u16 << count) - 1) << offset) as u8;
            owner.shm_locks.set(if flags & ffi::SQLITE_SHM_UNLOCK != 0 {
                owner.shm_locks.get() & !mask
            } else {
                owner.shm_locks.get() | mask
            });
            Ok(ffi::SQLITE_OK)
        })
    }
}
unsafe extern "C" fn shm_barrier(_: *mut ffi::sqlite3_file) {
    fence(Ordering::SeqCst);
}
unsafe extern "C" fn shm_unmap(file: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    // SAFETY: cleanup is permitted for original contexts even after poisoning.
    let file = match unsafe { native(file) } {
        Ok(file) => file,
        Err(_) => return ffi::SQLITE_IOERR_SHMMAP,
    };
    // SAFETY: retained owner remains alive through all IO callbacks.
    let owner = unsafe { &*file.state };
    if !owner.on_original_thread() {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    match owner.unmap() {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => {
            owner.poisoned.set(true);
            ffi::SQLITE_IOERR_SHMMAP
        }
    }
}

unsafe extern "C" fn delete(vfs: *mut ffi::sqlite3_vfs, name: *const c_char, _: c_int) -> c_int {
    if vfs.is_null() || name.is_null() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SAFETY: actual registered owner and callback filename supplied by SQLite.
    let Some(owner) = (unsafe { state(vfs) }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    guarded(owner, ffi::SQLITE_IOERR_DELETE, || {
        // SAFETY: SQLite supplies a NUL-terminated name valid for this callback.
        let class = class(owner, unsafe { CStr::from_ptr(name) })?;
        if !matches!(class, 1 | 2) {
            return Err(refuse("original SQLite namespace deletion refused"));
        }
        let file = &owner.files[class].original.file;
        file.set_len(0)?;
        file.sync_all()?;
        Ok(ffi::SQLITE_OK)
    })
}
unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    if vfs.is_null() || name.is_null() || output.is_null() {
        return ffi::SQLITE_IOERR_ACCESS;
    }
    // SAFETY: actual registered owner supplied by SQLite.
    let Some(owner) = (unsafe { state(vfs) }) else {
        return ffi::SQLITE_IOERR_ACCESS;
    };
    guarded(owner, ffi::SQLITE_IOERR_ACCESS, || {
        // SAFETY: callback name and output are live sized SQLite allocations.
        let class = class(owner, unsafe { CStr::from_ptr(name) })?;
        if !matches!(
            flags,
            ffi::SQLITE_ACCESS_EXISTS | ffi::SQLITE_ACCESS_READ | ffi::SQLITE_ACCESS_READWRITE
        ) {
            return Err(refuse("original SQLite access flags invalid"));
        }
        let present = class == 0 || owner.files[class].original.file.metadata()?.len() != 0;
        // SAFETY: the nonnull integer output belongs to SQLite.
        unsafe {
            *output = i32::from(present);
        }
        Ok(ffi::SQLITE_OK)
    })
}
unsafe extern "C" fn full_path(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    if vfs.is_null() || name.is_null() || output.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: actual registered owner supplied by SQLite.
    let Some(owner) = (unsafe { state(vfs) }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    guarded(owner, ffi::SQLITE_CANTOPEN, || {
        // SAFETY: SQLite supplies a NUL-terminated filename for this callback.
        let name = unsafe { CStr::from_ptr(name) };
        let _ = class(owner, name)?;
        if size <= 0 || name.to_bytes_with_nul().len() > size as usize {
            return Err(refuse("original SQLite full path buffer"));
        }
        // SAFETY: exact terminated name fits the counted SQLite output buffer.
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), output, name.to_bytes_with_nul().len());
        }
        Ok(ffi::SQLITE_OK)
    })
}
unsafe extern "C" fn randomness(
    _: *mut ffi::sqlite3_vfs,
    count: c_int,
    output: *mut c_char,
) -> c_int {
    if output.is_null() || !(0..=1024 * 1024).contains(&count) {
        return 0;
    }
    // SAFETY: SQLite supplies this counted writable randomness allocation.
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), count as usize) };
    if getrandom::fill(bytes).is_ok() {
        count
    } else {
        bytes.fill(0);
        0
    }
}
unsafe extern "C" fn sleep(_: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    let micros = micros.clamp(0, 1_000_000);
    std::thread::sleep(Duration::from_micros(micros as u64));
    micros
}
unsafe extern "C" fn time_int64(_: *mut ffi::sqlite3_vfs, output: *mut i64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_millis()).ok())
        .and_then(|time| time.checked_add(210_866_760_000_000));
    if let Some(time) = time {
        // SAFETY: SQLite supplies a sized writable Julian-millisecond output.
        unsafe {
            *output = time;
        }
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_ERROR
    }
}
unsafe extern "C" fn time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let mut millis = 0;
    // SAFETY: wrapper supplies a valid local integer output.
    let result = unsafe { time_int64(vfs, &mut millis) };
    if result == ffi::SQLITE_OK {
        // SAFETY: caller's output is a sized writable double.
        unsafe {
            *output = millis as f64 / 86_400_000.0;
        }
    }
    result
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

pub(super) fn table() -> Box<ffi::sqlite3_vfs> {
    // SAFETY: SQLite's C table consists only of integers/pointers/nullable callbacks.
    let mut table = Box::new(unsafe { std::mem::zeroed::<ffi::sqlite3_vfs>() });
    table.iVersion = 2;
    table.szOsFile = std::mem::size_of::<NativeFile>() as c_int;
    table.mxPathname = 32_768;
    table.xOpen = Some(open);
    table.xDelete = Some(delete);
    table.xAccess = Some(access);
    table.xFullPathname = Some(full_path);
    table.xRandomness = Some(randomness);
    table.xSleep = Some(sleep);
    table.xCurrentTime = Some(time);
    table.xCurrentTimeInt64 = Some(time_int64);
    table
}
