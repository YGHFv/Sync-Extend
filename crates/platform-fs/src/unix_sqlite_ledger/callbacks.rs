use super::{refused, State, MAX_PATH};
use rusqlite::ffi;
use std::{
    ffi::{c_char, c_int, c_void, CStr},
    io,
    os::unix::fs::FileExt,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[repr(C)]
struct NativeFile {
    base: ffi::sqlite3_file,
    context: *mut OpenFile,
}

struct OpenFile {
    state: Arc<State>,
    class: usize,
    lock: c_int,
}

unsafe fn owner(vfs: *mut ffi::sqlite3_vfs) -> Arc<State> {
    // SAFETY: registration retains a strong owner for this callback.
    let pointer = unsafe { (*vfs).pAppData.cast::<State>() };
    // SAFETY: the retained registration proves this Arc pointer remains live.
    unsafe { Arc::increment_strong_count(pointer) };
    // SAFETY: the increment above transfers one independently owned strong reference.
    unsafe { Arc::from_raw(pointer) }
}

unsafe fn context<'a>(file: *mut ffi::sqlite3_file) -> io::Result<&'a mut OpenFile> {
    if file.is_null() {
        return Err(refused("Unix ledger SQLite file absent"));
    }
    // SAFETY: SQLite allocated our advertised repr(C) NativeFile size.
    let pointer = unsafe { (*file.cast::<NativeFile>()).context };
    if pointer.is_null() {
        return Err(refused("Unix ledger SQLite IO context absent"));
    }
    // SAFETY: xOpen installed this Box; SQLite serializes this file's IO.
    Ok(unsafe { &mut *pointer })
}

fn guarded(state: &State, failure: c_int, action: impl FnOnce() -> io::Result<c_int>) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        state.verify()?;
        let result = action()?;
        state.verify()?;
        Ok::<_, io::Error>(result)
    })) {
        Ok(Ok(result)) => result,
        _ => {
            state.poisoned.store(true, Ordering::Release);
            failure
        }
    }
}

unsafe fn io(
    file: *mut ffi::sqlite3_file,
    failure: c_int,
    action: impl FnOnce(&mut OpenFile) -> io::Result<c_int>,
) -> c_int {
    // SAFETY: every caller receives the actual initialized SQLite file.
    let opened = match unsafe { context(file) } {
        Ok(value) => value,
        Err(_) => return failure,
    };
    let state = opened.state.clone();
    guarded(&state, failure, || action(opened))
}

fn class(state: &State, filename: &CStr) -> io::Result<usize> {
    if filename.to_bytes().len() > MAX_PATH {
        return Err(refused("Unix ledger SQLite name exceeds bound"));
    }
    state
        .paths
        .iter()
        .position(|path| path.as_c_str() == filename)
        .ok_or_else(|| refused("Unix ledger SQLite filename is not retained"))
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    filename: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    if vfs.is_null() || file.is_null() || filename.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: SQLite owns the sized output; failed opens must expose no methods.
    unsafe {
        (*file).pMethods = ptr::null();
        (*file.cast::<NativeFile>()).context = ptr::null_mut();
    }
    // SAFETY: this callback receives our live registered VFS.
    let state = unsafe { owner(vfs) };
    guarded(&state, ffi::SQLITE_CANTOPEN, || {
        // SAFETY: SQLite supplies a terminated filename for this callback.
        let filename = unsafe { CStr::from_ptr(filename) };
        let class = class(&state, filename)?;
        let _ = state.file(class)?;
        // SQLite supplies the documented filename-plus-URI representation.
        // Only our readonly immutable=1 URI is admitted; writer URI options
        // cannot introduce a different locking, VFS, cache or namespace policy.
        // SAFETY: filename is SQLite's prepared sqlite3_filename for this xOpen.
        let first_key = unsafe { ffi::sqlite3_uri_key(filename.as_ptr(), 0) };
        if state.read_only {
            if first_key.is_null()
                // SAFETY: nonnull URI keys are terminated within SQLite's filename.
                || unsafe { CStr::from_ptr(first_key) }.to_bytes() != b"immutable"
                // SAFETY: this filename has SQLite's URI parameter representation.
                || unsafe { ffi::sqlite3_uri_boolean(filename.as_ptr(), c"immutable".as_ptr(), 0) }
                    != 1
                // SAFETY: SQLite bounds the URI key enumeration and returns null at its end.
                || !unsafe { ffi::sqlite3_uri_key(filename.as_ptr(), 1) }.is_null()
            {
                return Err(refused("Unix ledger readonly URI differs"));
            }
        } else if !first_key.is_null() {
            return Err(refused("Unix ledger writer URI parameters rejected"));
        }
        let kind = flags
            & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL);
        if !matches!(
            (class, kind),
            (0, ffi::SQLITE_OPEN_MAIN_DB)
                | (1, ffi::SQLITE_OPEN_WAL)
                | (2, ffi::SQLITE_OPEN_MAIN_JOURNAL)
        ) || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0
            || state.read_only
                && (class != 0
                    || flags & ffi::SQLITE_OPEN_READONLY == 0
                    || flags & (ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE) != 0)
            || !state.read_only && flags & ffi::SQLITE_OPEN_READWRITE == 0
        {
            return Err(refused("Unix ledger SQLite file class/flags rejected"));
        }
        let opened = Box::new(OpenFile {
            state: state.clone(),
            class,
            lock: ffi::SQLITE_LOCK_NONE,
        });
        // SAFETY: one owned context is transferred to SQLite and consumed by xClose.
        unsafe {
            (*file.cast::<NativeFile>()).context = Box::into_raw(opened);
            (*file).pMethods = &IO_METHODS;
            if !out_flags.is_null() {
                *out_flags = flags & (ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_READWRITE);
            }
        }
        Ok(ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    if file.is_null() {
        return ffi::SQLITE_IOERR_CLOSE;
    }
    // SAFETY: only xOpen creates this sized NativeFile.
    let native = unsafe { &mut *file.cast::<NativeFile>() };
    if !native.context.is_null() {
        // SAFETY: xOpen transferred one unique Box; this close consumes it once.
        unsafe { drop(Box::from_raw(native.context)) };
        native.context = ptr::null_mut();
    }
    native.base.pMethods = ptr::null();
    // No file modification, checkpoint, sidecar deletion or implicit lock release.
    ffi::SQLITE_OK
}

fn range(offset: i64, amount: c_int, maximum: u64) -> io::Result<(u64, usize)> {
    let offset =
        u64::try_from(offset).map_err(|_| refused("negative Unix ledger SQLite offset"))?;
    let amount =
        usize::try_from(amount).map_err(|_| refused("negative Unix ledger SQLite IO length"))?;
    if amount > 1024 * 1024
        || offset
            .checked_add(amount as u64)
            .is_none_or(|end| end > maximum)
    {
        return Err(refused("Unix ledger SQLite IO range exceeds bound"));
    }
    Ok((offset, amount))
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_READ;
    }
    // SAFETY: initialized IO context and SQLite's counted writable output.
    unsafe {
        io(file, ffi::SQLITE_IOERR_READ, |opened| {
            let (offset, amount) = range(offset, amount, opened.state.max_bytes)?;
            let file = &opened.state.file(opened.class)?.file;
            let output = std::slice::from_raw_parts_mut(output.cast::<u8>(), amount);
            output.fill(0);
            let mut count = 0;
            while count < amount {
                match file.read_at(&mut output[count..], offset + count as u64) {
                    Ok(0) => break,
                    Ok(read) => count += read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(if count == amount {
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
    amount: c_int,
    offset: i64,
) -> c_int {
    if input.is_null() {
        return ffi::SQLITE_IOERR_WRITE;
    }
    // SAFETY: initialized IO context and SQLite's counted readable input.
    unsafe {
        io(file, ffi::SQLITE_IOERR_WRITE, |opened| {
            if opened.state.read_only {
                return Err(refused("Unix ledger readonly SQLite write rejected"));
            }
            let (offset, amount) = range(offset, amount, opened.state.max_bytes)?;
            let file = &opened.state.file(opened.class)?.file;
            let input = std::slice::from_raw_parts(input.cast::<u8>(), amount);
            let mut count = 0;
            while count < amount {
                match file.write_at(&input[count..], offset + count as u64) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                    Ok(written) => count += written,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    // SAFETY: initialized file context from SQLite.
    unsafe {
        io(file, ffi::SQLITE_IOERR_TRUNCATE, |opened| {
            let size = u64::try_from(size).map_err(|_| refused("negative Unix ledger truncate"))?;
            if opened.state.read_only || size > opened.state.max_bytes {
                return Err(refused("Unix ledger truncate exceeds write authority"));
            }
            let file = &opened.state.file(opened.class)?.file;
            if file.metadata()?.len() != size {
                file.set_len(size)?;
            }
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    // SAFETY: initialized file context from SQLite.
    unsafe {
        io(file, ffi::SQLITE_IOERR_FSYNC, |opened| {
            if opened.state.read_only {
                return Err(refused("Unix ledger readonly sync rejected"));
            }
            opened.state.file(opened.class)?.file.sync_all()?;
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn size(file: *mut ffi::sqlite3_file, output: *mut i64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_FSTAT;
    }
    // SAFETY: initialized context and SQLite's sized file-length output.
    unsafe {
        io(file, ffi::SQLITE_IOERR_FSTAT, |opened| {
            let length = opened.state.file(opened.class)?.file.metadata()?.len();
            *output =
                i64::try_from(length).map_err(|_| refused("Unix ledger file length overflow"))?;
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn lock(file: *mut ffi::sqlite3_file, requested: c_int) -> c_int {
    // SAFETY: initialized context; the external retained flock excludes other connections.
    unsafe {
        io(file, ffi::SQLITE_IOERR_LOCK, |opened| {
            if !(ffi::SQLITE_LOCK_NONE..=ffi::SQLITE_LOCK_EXCLUSIVE).contains(&requested)
                || opened.state.read_only && requested > ffi::SQLITE_LOCK_SHARED
            {
                return Err(refused("Unix ledger SQLite lock exceeds authority"));
            }
            opened.lock = opened.lock.max(requested);
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn unlock(file: *mut ffi::sqlite3_file, requested: c_int) -> c_int {
    // SAFETY: initialized context; SQLite unlock does not release our lifecycle flock.
    unsafe {
        io(file, ffi::SQLITE_IOERR_UNLOCK, |opened| {
            if !(ffi::SQLITE_LOCK_NONE..=ffi::SQLITE_LOCK_EXCLUSIVE).contains(&requested) {
                return Err(refused("Unix ledger SQLite unlock state invalid"));
            }
            opened.lock = requested;
            Ok(ffi::SQLITE_OK)
        })
    }
}

unsafe extern "C" fn reserved(file: *mut ffi::sqlite3_file, output: *mut c_int) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    // SAFETY: initialized context and sized SQLite integer output.
    unsafe {
        io(file, ffi::SQLITE_IOERR_CHECKRESERVEDLOCK, |opened| {
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
    // SAFETY: initialized context; only recognized file-control output types are dereferenced.
    unsafe {
        io(file, ffi::SQLITE_IOERR, |opened| {
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

unsafe extern "C" fn characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: SQLite calls this only for an initialized IO file.
    match unsafe { context(file) } {
        Ok(opened) if opened.state.read_only => ffi::SQLITE_IOCAP_IMMUTABLE,
        _ => 0,
    }
}

unsafe extern "C" fn shm_map(
    _: *mut ffi::sqlite3_file,
    _: c_int,
    _: c_int,
    _: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if !output.is_null() {
        // SAFETY: SQLite supplies one writable mapping-pointer output.
        unsafe { *output = ptr::null_mut() };
    }
    ffi::SQLITE_IOERR_SHMMAP
}

unsafe extern "C" fn shm_lock(_: *mut ffi::sqlite3_file, _: c_int, _: c_int, _: c_int) -> c_int {
    ffi::SQLITE_IOERR_SHMLOCK
}

unsafe extern "C" fn shm_barrier(_: *mut ffi::sqlite3_file) {
    std::sync::atomic::fence(Ordering::SeqCst);
}

unsafe extern "C" fn shm_unmap(_: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    filename: *const c_char,
    _: c_int,
) -> c_int {
    if vfs.is_null() || filename.is_null() {
        return ffi::SQLITE_IOERR_DELETE;
    }
    // SAFETY: this callback receives our live registered VFS.
    let state = unsafe { owner(vfs) };
    guarded(&state, ffi::SQLITE_IOERR_DELETE, || {
        // SAFETY: SQLite supplies a terminated exact callback filename.
        let class = class(&state, unsafe { CStr::from_ptr(filename) })?;
        if state.read_only || class == 0 {
            return Err(refused("Unix ledger SQLite namespace deletion rejected"));
        }
        // Retained journals remain named zero-length objects; no pathname unlink.
        let file = &state.file(class)?.file;
        if file.metadata()?.len() != 0 {
            file.set_len(0)?;
        }
        file.sync_all()?;
        Ok(ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    filename: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    if vfs.is_null() || filename.is_null() || output.is_null() {
        return ffi::SQLITE_IOERR_ACCESS;
    }
    // SAFETY: our live registration and SQLite's sized integer output.
    let state = unsafe { owner(vfs) };
    guarded(&state, ffi::SQLITE_IOERR_ACCESS, || {
        // SAFETY: SQLite supplies a terminated callback name and one integer output.
        let name = unsafe { CStr::from_ptr(filename) };
        let class = class(&state, name)?;
        let present = if class == 0 {
            true
        } else {
            !state.read_only
                && state.files[class]
                    .as_ref()
                    .map(|file| file.file.metadata().map(|metadata| metadata.len() != 0))
                    .transpose()?
                    .unwrap_or(false)
        };
        // SAFETY: output was checked nonnull and belongs to SQLite.
        unsafe {
            *output =
                i32::from(present && (flags != ffi::SQLITE_ACCESS_READWRITE || !state.read_only));
        }
        Ok(ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn full_path(
    vfs: *mut ffi::sqlite3_vfs,
    filename: *const c_char,
    length: c_int,
    output: *mut c_char,
) -> c_int {
    if vfs.is_null() || filename.is_null() || output.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: our live registration.
    let state = unsafe { owner(vfs) };
    guarded(&state, ffi::SQLITE_CANTOPEN, || {
        // SAFETY: terminated input filename supplied by SQLite.
        let filename = unsafe { CStr::from_ptr(filename) };
        let _ = class(&state, filename)?;
        if length <= 0 || filename.to_bytes_with_nul().len() > length as usize {
            return Err(refused("Unix ledger SQLite full path output exceeds bound"));
        }
        // SAFETY: caller allocated length bytes; exact terminated name fits.
        unsafe {
            ptr::copy_nonoverlapping(
                filename.as_ptr(),
                output,
                filename.to_bytes_with_nul().len(),
            );
        }
        Ok(ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn randomness(
    _: *mut ffi::sqlite3_vfs,
    length: c_int,
    output: *mut c_char,
) -> c_int {
    if output.is_null() || !(0..=1024 * 1024).contains(&length) {
        return 0;
    }
    // SAFETY: SQLite allocated this counted writable randomness buffer.
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), length as usize) };
    if getrandom::fill(bytes).is_ok() {
        length
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

unsafe extern "C" fn current_time_int64(_: *mut ffi::sqlite3_vfs, output: *mut i64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_millis()).ok())
        .and_then(|millis| millis.checked_add(210_866_760_000_000));
    match value {
        Some(value) => {
            // SAFETY: SQLite supplies a writable signed Julian-millisecond output.
            unsafe { *output = value };
            ffi::SQLITE_OK
        }
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let mut millis = 0;
    // SAFETY: this wrapper passes a sized local integer output.
    let result = unsafe { current_time_int64(vfs, &mut millis) };
    if result == ffi::SQLITE_OK {
        // SAFETY: caller supplies the sized floating-point output.
        unsafe { *output = millis as f64 / 86_400_000.0 };
    }
    result
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
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

pub(super) fn registration() -> Box<ffi::sqlite3_vfs> {
    // SAFETY: this C table consists of integers, pointers and nullable function pointers.
    let mut table = Box::new(unsafe { std::mem::zeroed::<ffi::sqlite3_vfs>() });
    table.iVersion = 2;
    table.szOsFile = std::mem::size_of::<NativeFile>() as c_int;
    table.mxPathname = MAX_PATH as c_int;
    table.xOpen = Some(open);
    table.xDelete = Some(delete);
    table.xAccess = Some(access);
    table.xFullPathname = Some(full_path);
    table.xRandomness = Some(randomness);
    table.xSleep = Some(sleep);
    table.xCurrentTime = Some(current_time);
    table.xCurrentTimeInt64 = Some(current_time_int64);
    table
}
