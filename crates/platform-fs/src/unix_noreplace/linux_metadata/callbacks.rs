//! Descriptor-only VFS callbacks. No callback opens a pathname or frees allocation.
use super::{abi::*, refuse, State, VfsRegistration};
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr},
    io,
    os::{fd::AsRawFd, unix::fs::FileExt},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[repr(C)]
struct NativeFile {
    base: SqliteFile,
    context: *mut OpenFile,
}
struct OpenFile {
    state: Arc<State>,
    registration: Arc<VfsRegistration>,
    class: usize,
    connection: u64,
    mappings: BTreeMap<i32, (*mut c_void, usize)>,
}

unsafe fn registration(vfs: *mut Vfs) -> Arc<VfsRegistration> {
    // SAFETY: our registered table contains Arc::as_ptr from its live owner.
    let original = unsafe { (*vfs).app.cast::<VfsRegistration>() };
    // SAFETY: this table's live registration retains at least one strong reference.
    unsafe { Arc::increment_strong_count(original) };
    // SAFETY: the increment above transferred one independent strong reference.
    unsafe { Arc::from_raw(original) }
}
unsafe fn state(vfs: *mut Vfs) -> Arc<State> {
    // SAFETY: the live registration owns the same shared metadata budget.
    unsafe { registration(vfs) }.state.clone()
}
unsafe fn context<'a>(file: *mut SqliteFile) -> io::Result<&'a mut OpenFile> {
    if file.is_null() {
        return Err(refuse("SQLite original file pointer absent"));
    }
    // SAFETY: SQLite allocated szOsFile bytes for our repr(C) file structure.
    let file = unsafe { &mut *file.cast::<NativeFile>() };
    if file.context.is_null() {
        return Err(refuse("SQLite original context absent"));
    }
    // SAFETY: xOpen installed one live owned Box; SQLite serializes this file's callbacks.
    Ok(unsafe { &mut *file.context })
}

unsafe fn guarded(
    file: *mut SqliteFile,
    failure: c_int,
    action: impl FnOnce(&mut OpenFile) -> io::Result<c_int>,
) -> c_int {
    // SAFETY: actual initialized SQLite file supplied by this callback.
    let context = match unsafe { context(file) } {
        Ok(value) => value,
        Err(_) => return failure,
    };
    let state = context.state.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        state.verify()?;
        let result = action(context)?;
        state.verify()?;
        Ok::<_, io::Error>(result)
    }));
    match result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            state.poison(&error);
            failure
        }
        Err(_) => {
            state.poison(&io::Error::other("SQLite metadata callback panicked"));
            failure
        }
    }
}

unsafe extern "C" fn open(
    vfs: *mut Vfs,
    filename: *const c_char,
    file: *mut SqliteFile,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    if vfs.is_null() || file.is_null() || filename.is_null() {
        return CANTOPEN;
    }
    // SAFETY: allocated output file and registered table from SQLite.
    unsafe {
        (*file.cast::<NativeFile>()).context = ptr::null_mut();
        (*file).methods = ptr::null();
    }
    // SAFETY: live registration and terminated SQLite filename.
    let registration = unsafe { registration(vfs) };
    let state = registration.state.clone();
    let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
        state.verify()?;
        // SAFETY: SQLite supplies a terminated filename valid for this call.
        let filename = unsafe { CStr::from_ptr(filename) };
        if filename.to_bytes().len() > 4096
            || flags & OPEN_READWRITE == 0
            || flags & OPEN_DELETEONCLOSE != 0
        {
            return Err(refuse("SQLite metadata filename/open flags refused"));
        }
        let class = state
            .files
            .iter()
            .position(|slot| slot.path.as_c_str() == filename)
            .ok_or_else(|| {
                refuse("SQLite temp/attached/auxiliary filename has no owned allocation")
            })?;
        let kind = flags & (OPEN_MAIN_DB | OPEN_MAIN_JOURNAL | OPEN_WAL);
        if !matches!(
            (class, kind),
            (0, OPEN_MAIN_DB) | (1, OPEN_WAL) | (3, OPEN_MAIN_JOURNAL)
        ) {
            return Err(refuse("SQLite metadata class/filename mismatch"));
        }
        let connection = state.next_connection.fetch_add(1, Ordering::AcqRel);
        if connection == 0 || connection == u64::MAX {
            return Err(refuse("SQLite metadata connection generation overflow"));
        }
        let opened = Box::new(OpenFile {
            state: state.clone(),
            registration: registration.clone(),
            class,
            connection,
            mappings: BTreeMap::new(),
        });
        state
            .active_files
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| refuse("SQLite metadata active context count overflow"))?;
        if registration
            .active_files
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .is_err()
        {
            // Only this failed enrollment is removed; no original xOpen
            // context has been transferred to SQLite yet.
            state.active_files.fetch_sub(1, Ordering::AcqRel);
            return Err(refuse("SQLite VFS active context count overflow"));
        }
        // SAFETY: output file belongs to SQLite and the Box remains until xClose.
        unsafe {
            (*file.cast::<NativeFile>()).context = Box::into_raw(opened);
            (*file).methods = &IO_METHODS;
            if !out_flags.is_null() {
                *out_flags = flags;
            }
        }
        Ok(())
    }));
    match result {
        Ok(Ok(())) => OK,
        Ok(Err(error)) => {
            state.poison(&error);
            CANTOPEN
        }
        Err(_) => {
            state.poison(&io::Error::other("SQLite metadata open callback panicked"));
            CANTOPEN
        }
    }
}

unsafe extern "C" fn close(file: *mut SqliteFile) -> c_int {
    if file.is_null() {
        return IOERR;
    }
    // SAFETY: allocated repr(C) file from our xOpen.
    let native = unsafe { &mut *file.cast::<NativeFile>() };
    if native.context.is_null() {
        return OK;
    }
    // SAFETY: xOpen transferred this unique Box, consumed exactly once by xClose.
    let mut opened = unsafe { Box::from_raw(native.context) };
    native.context = ptr::null_mut();
    native.base.methods = ptr::null();
    let mut failure = None;
    for (slot, (address, length)) in std::mem::take(&mut opened.mappings) {
        // SAFETY: these exact mappings were acquired by this original xShmMap.
        if unsafe { libc::munmap(address, length) } != 0 {
            failure.get_or_insert_with(io::Error::last_os_error);
            opened.mappings.insert(slot, (address, length));
        }
    }
    match opened.state.locks.lock() {
        Ok(mut locks) => {
            locks.remove(&opened.connection);
        }
        Err(_) => {
            failure.get_or_insert_with(|| refuse("SQLite original file lock state poisoned"));
        }
    }
    match opened.state.shm_locks.lock() {
        Ok(mut locks) => {
            for lock in locks.iter_mut() {
                if lock.exclusive == Some(opened.connection) {
                    lock.exclusive = None;
                }
                lock.shared.retain(|id| *id != opened.connection);
            }
        }
        Err(_) => {
            failure.get_or_insert_with(|| refuse("SQLite original SHM lock state poisoned"));
        }
    }
    if failure.is_none()
        && opened
            .registration
            .active_files
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .is_err()
    {
        failure = Some(refuse("SQLite VFS actual close context count underflow"));
    }
    if failure.is_none()
        && opened
            .state
            .active_files
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .is_err()
    {
        // A failed global retirement cannot erase the local original context.
        opened
            .registration
            .active_files
            .fetch_add(1, Ordering::AcqRel);
        failure = Some(refuse(
            "SQLite metadata actual close context count underflow",
        ));
    }
    if let Some(error) = failure {
        opened
            .registration
            .close_failed
            .store(true, Ordering::Release);
        opened.state.poison(&error);
        // SQLite may release its native-file allocation after an xClose
        // error. Keep the exact context, any failed mappings, registration and
        // original descriptor scope alive; neither active count grants close.
        std::mem::forget(opened);
        IOERR
    } else {
        OK
    }
}

fn range(offset: i64, amount: c_int, capacity: u64) -> io::Result<(u64, usize)> {
    let offset = u64::try_from(offset).map_err(|_| refuse("negative SQLite metadata offset"))?;
    let amount = usize::try_from(amount).map_err(|_| refuse("negative SQLite metadata IO size"))?;
    if offset
        .checked_add(amount as u64)
        .is_none_or(|end| end > capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "SQLite metadata class growth refused",
        ));
    }
    Ok((offset, amount))
}
unsafe extern "C" fn read(
    file: *mut SqliteFile,
    output: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    if output.is_null() {
        return IOERR;
    }
    // SAFETY: actual original file, SQLite output allocation and counted read amount.
    unsafe {
        guarded(file, IOERR, |opened| {
            let slot = &opened.state.files[opened.class];
            let (offset, amount) = range(offset, amount, slot.capacity)?;
            // SAFETY: SQLite allocated this writable amount for the current xRead.
            let output = std::slice::from_raw_parts_mut(output.cast::<u8>(), amount);
            output.fill(0);
            let logical = slot.logical_bytes.load(Ordering::Acquire);
            let available = logical.saturating_sub(offset).min(amount as u64) as usize;
            let mut read = 0usize;
            while read < available {
                match slot
                    .file
                    .read_at(&mut output[read..available], offset + read as u64)
                {
                    Ok(0) => break,
                    Ok(count) => read += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(if read == amount { OK } else { IOERR_SHORT_READ })
        })
    }
}
unsafe extern "C" fn write(
    file: *mut SqliteFile,
    input: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    if input.is_null() {
        return IOERR_WRITE;
    }
    // SAFETY: initialized original file and SQLite's counted input allocation.
    unsafe {
        guarded(file, FULL, |opened| {
            let slot = &opened.state.files[opened.class];
            let (offset, amount) = range(offset, amount, slot.capacity)?;
            // SAFETY: SQLite supplies this readable counted xWrite input.
            let input = std::slice::from_raw_parts(input.cast::<u8>(), amount);
            let mut written = 0usize;
            while written < amount {
                match slot
                    .file
                    .write_at(&input[written..], offset + written as u64)
                {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "metadata write stopped",
                        ))
                    }
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            slot.logical_bytes
                .fetch_max(offset + amount as u64, Ordering::AcqRel);
            Ok(OK)
        })
    }
}
unsafe extern "C" fn truncate(file: *mut SqliteFile, size: i64) -> c_int {
    // SAFETY: SQLite supplies our live original file to xTruncate.
    unsafe {
        guarded(file, IOERR_TRUNCATE, |opened| {
            let slot = &opened.state.files[opened.class];
            let size =
                u64::try_from(size).map_err(|_| refuse("negative SQLite metadata truncate"))?;
            if size > slot.capacity {
                return Err(refuse("SQLite metadata truncate growth refused"));
            }
            let logical = slot.logical_bytes.load(Ordering::Acquire);
            if size < logical {
                if size != 0 || !matches!(opened.class, 1 | 3) {
                    return Err(refuse("SQLite metadata shrink would release reserved data"));
                }
                // WAL/rollback resets clear their validity header while retaining every
                // allocated block. No ftruncate/unlink ever releases the reservation.
                let bytes = slot.file.metadata()?.len().min(32) as usize;
                if bytes != 0 {
                    slot.file.write_all_at(&[0u8; 32][..bytes], 0)?;
                }
                slot.file.sync_all()?;
            } else if size > slot.file.metadata()?.len() {
                slot.file.set_len(size)?;
            }
            slot.logical_bytes.store(size, Ordering::Release);
            opened.state.persist_owner_record()?;
            Ok(OK)
        })
    }
}
unsafe extern "C" fn sync(file: *mut SqliteFile, _: c_int) -> c_int {
    // SAFETY: initialized original file supplied for its sync callback.
    unsafe {
        guarded(file, IOERR, |opened| {
            opened.state.files[opened.class].file.sync_all()?;
            opened.state.persist_owner_record()?;
            opened.state.directory.sync_all()?;
            Ok(OK)
        })
    }
}
unsafe extern "C" fn size(file: *mut SqliteFile, output: *mut i64) -> c_int {
    if output.is_null() {
        return IOERR;
    }
    // SAFETY: original file and writable SQLite size output.
    unsafe {
        guarded(file, IOERR, |opened| {
            *output = i64::try_from(
                opened.state.files[opened.class]
                    .logical_bytes
                    .load(Ordering::Acquire),
            )
            .map_err(|_| refuse("SQLite metadata logical size overflow"))?;
            Ok(OK)
        })
    }
}

unsafe extern "C" fn lock(file: *mut SqliteFile, requested: c_int) -> c_int {
    // SAFETY: original SQLite file callback; shared process lock state is mutex protected.
    unsafe {
        guarded(file, IOERR, |opened| {
            if opened.class != 0 || !(1..=4).contains(&requested) {
                return Ok(OK);
            }
            let mut locks = opened
                .state
                .locks
                .lock()
                .map_err(|_| refuse("metadata lock state poisoned"))?;
            let conflict = locks.iter().any(|(id, held)| {
                *id != opened.connection
                    && match requested {
                        1 => *held >= 3,
                        2 | 3 => *held >= 2,
                        4 => *held >= 1,
                        _ => true,
                    }
            });
            if conflict {
                return Ok(BUSY);
            }
            let held = locks.entry(opened.connection).or_insert(0);
            *held = (*held).max(requested);
            Ok(OK)
        })
    }
}
unsafe extern "C" fn unlock(file: *mut SqliteFile, requested: c_int) -> c_int {
    // SAFETY: original SQLite file callback with mutex-protected lock state.
    unsafe {
        guarded(file, IOERR, |opened| {
            let mut locks = opened
                .state
                .locks
                .lock()
                .map_err(|_| refuse("metadata unlock state poisoned"))?;
            if requested == 0 {
                locks.remove(&opened.connection);
            } else {
                locks.insert(opened.connection, requested);
            }
            Ok(OK)
        })
    }
}
unsafe extern "C" fn reserved(file: *mut SqliteFile, output: *mut c_int) -> c_int {
    if output.is_null() {
        return IOERR;
    }
    // SAFETY: original file and counted lock-state output.
    unsafe {
        guarded(file, IOERR, |opened| {
            let locks = opened
                .state
                .locks
                .lock()
                .map_err(|_| refuse("metadata reserve lock state poisoned"))?;
            *output = i32::from(locks.values().any(|held| *held >= 2));
            Ok(OK)
        })
    }
}
unsafe extern "C" fn control(file: *mut SqliteFile, operation: c_int, value: *mut c_void) -> c_int {
    // SAFETY: original SQLite file and operation-specific outputs specified by the public ABI.
    unsafe {
        guarded(file, IOERR, |opened| {
            match operation {
                1 if !value.is_null() => {
                    let locks = opened
                        .state
                        .locks
                        .lock()
                        .map_err(|_| refuse("metadata lock state poisoned"))?;
                    *value.cast::<c_int>() = *locks.get(&opened.connection).unwrap_or(&0);
                }
                5 if !value.is_null() => {
                    let desired = *value.cast::<i64>();
                    if desired < 0 || desired as u64 > opened.state.files[opened.class].capacity {
                        return Err(refuse(
                            "SQLite metadata size hint exceeded physical contract",
                        ));
                    }
                }
                6 => {}
                10 if !value.is_null() => {
                    *value.cast::<c_int>() = 1;
                }
                13 if !value.is_null() => {
                    *value.cast::<c_int>() = 0;
                }
                20 if !value.is_null() => {
                    *value.cast::<c_int>() = 0;
                }
                _ => return Ok(NOTFOUND),
            }
            Ok(OK)
        })
    }
}
unsafe extern "C" fn sector(_: *mut SqliteFile) -> c_int {
    4096
}
unsafe extern "C" fn characteristics(_: *mut SqliteFile) -> c_int {
    0
}

unsafe extern "C" fn shm_map(
    file: *mut SqliteFile,
    region: c_int,
    size: c_int,
    _: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if output.is_null() {
        return IOERR;
    }
    // SAFETY: original file and writable mapping-pointer output.
    unsafe {
        guarded(file, IOERR, |opened| {
            if opened.class != 0 || region < 0 || size != 32 * 1024 {
                return Err(refuse("SQLite SHM mapping class/region contract refused"));
            }
            if let Some((address, _)) = opened.mappings.get(&region) {
                *output = *address;
                return Ok(OK);
            }
            let offset = i64::from(region)
                .checked_mul(i64::from(size))
                .ok_or_else(|| refuse("SQLite SHM region overflow"))?;
            let slot = &opened.state.files[2];
            let _ = range(offset, size, slot.capacity)?;
            // SAFETY: fixed preallocated original SHM fd, checked aligned offset and counted length.
            let address = libc::mmap(
                ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                slot.file.as_raw_fd(),
                offset,
            );
            if address == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            opened.mappings.insert(region, (address, size as usize));
            *output = address;
            Ok(OK)
        })
    }
}
unsafe extern "C" fn shm_lock(
    file: *mut SqliteFile,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: SQLite SHM callback and mutex-protected exact eight WAL-index locks.
    unsafe {
        guarded(file, IOERR, |opened| {
            if opened.class != 0
                || offset < 0
                || count <= 0
                || offset.checked_add(count).is_none_or(|end| end > 8)
                || !matches!(flags,
                v if v == SHM_LOCK | SHM_SHARED || v == SHM_LOCK | SHM_EXCLUSIVE
                    || v == SHM_UNLOCK | SHM_SHARED || v == SHM_UNLOCK | SHM_EXCLUSIVE)
            {
                return Err(refuse("SQLite SHM lock range/flags refused"));
            }
            let mut locks = opened
                .state
                .shm_locks
                .lock()
                .map_err(|_| refuse("metadata SHM locks poisoned"))?;
            let selected = &mut locks[offset as usize..(offset + count) as usize];
            let unlocking = flags & SHM_UNLOCK != 0;
            let exclusive = flags & SHM_EXCLUSIVE != 0;
            if !unlocking
                && selected.iter().any(|lock| {
                    lock.exclusive.is_some_and(|id| id != opened.connection)
                        || (exclusive && lock.shared.iter().any(|id| *id != opened.connection))
                })
            {
                return Ok(BUSY);
            }
            for lock in selected {
                if unlocking {
                    if lock.exclusive == Some(opened.connection) {
                        lock.exclusive = None;
                    }
                    lock.shared.retain(|id| *id != opened.connection);
                } else if exclusive {
                    lock.exclusive = Some(opened.connection);
                } else if !lock.shared.contains(&opened.connection) {
                    lock.shared.push(opened.connection);
                }
            }
            Ok(OK)
        })
    }
}
unsafe extern "C" fn shm_barrier(_: *mut SqliteFile) {
    std::sync::atomic::fence(Ordering::SeqCst);
}
unsafe extern "C" fn shm_unmap(file: *mut SqliteFile, _: c_int) -> c_int {
    // SAFETY: original file mapping set; ownership remains retained after unmap.
    unsafe {
        guarded(file, IOERR, |opened| {
            for (_, (address, length)) in std::mem::take(&mut opened.mappings) {
                // SAFETY: exact original mappings recorded by xShmMap.
                if libc::munmap(address, length) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(OK)
        })
    }
}
unsafe extern "C" fn fetch(
    _: *mut SqliteFile,
    _: i64,
    _: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if output.is_null() {
        return IOERR;
    }
    // SAFETY: SQLite supplied writable optional mapping output; null disables direct mapping.
    unsafe {
        *output = ptr::null_mut();
    }
    OK
}
unsafe extern "C" fn unfetch(_: *mut SqliteFile, _: i64, _: *mut c_void) -> c_int {
    OK
}

unsafe extern "C" fn delete(vfs: *mut Vfs, filename: *const c_char, _: c_int) -> c_int {
    if vfs.is_null() || filename.is_null() {
        return IOERR;
    }
    // SAFETY: live VFS and terminated SQLite filename.
    let state = unsafe { state(vfs) };
    let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
        state.verify()?;
        // SAFETY: SQLite supplies a terminated filename for its delete operation.
        let filename = unsafe { CStr::from_ptr(filename) };
        // SQLite calls xDelete for both rollback journals and a WAL after a
        // successful checkpoint/close.  The reserved originals are retained:
        // reset only their validity header and logical length, never unlink or
        // release the physical allocation.  Main database deletion remains
        // refused.
        let class = state
            .files
            .iter()
            .position(|slot| slot.path.as_c_str() == filename)
            .ok_or_else(|| refuse("SQLite metadata deletion has no owned allocation"))?;
        if !matches!(class, 1 | 3) {
            return Err(refuse(
                "SQLite metadata deletion is outside the reset contract",
            ));
        }
        let slot = &state.files[class];
        let amount = slot.file.metadata()?.len().min(32) as usize;
        if amount != 0 {
            slot.file.write_all_at(&[0u8; 32][..amount], 0)?;
        }
        slot.file.sync_all()?;
        slot.logical_bytes.store(0, Ordering::Release);
        state.persist_owner_record()?;
        state.verify()
    }));
    match result {
        Ok(Ok(())) => OK,
        Ok(Err(error)) => {
            state.poison(&error);
            IOERR
        }
        Err(_) => {
            state.poison(&io::Error::other("metadata delete callback panicked"));
            IOERR
        }
    }
}
unsafe extern "C" fn access(
    vfs: *mut Vfs,
    filename: *const c_char,
    _: c_int,
    output: *mut c_int,
) -> c_int {
    if vfs.is_null() || filename.is_null() || output.is_null() {
        return IOERR;
    }
    // SAFETY: registered VFS, terminated input and writable output.
    let state = unsafe { state(vfs) };
    if let Err(error) = state.verify() {
        state.poison(&error);
        return IOERR;
    }
    // SAFETY: SQLite supplied terminated filename and writable access output.
    unsafe {
        let filename = CStr::from_ptr(filename);
        *output = i32::from(state.files.iter().enumerate().any(|(class, slot)| {
            slot.path.as_c_str() == filename
                && (class == 0 || slot.logical_bytes.load(Ordering::Acquire) != 0)
        }));
    }
    OK
}
unsafe extern "C" fn full_path(
    vfs: *mut Vfs,
    filename: *const c_char,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    if vfs.is_null() || filename.is_null() || output.is_null() || size <= 0 {
        return CANTOPEN;
    }
    // SAFETY: registered VFS and SQLite's terminated filename.
    let state = unsafe { state(vfs) };
    // SAFETY: terminated filename supplied by SQLite.
    let filename = unsafe { CStr::from_ptr(filename) };
    if !state
        .files
        .iter()
        .any(|slot| slot.path.as_c_str() == filename)
        || filename.to_bytes_with_nul().len() > size as usize
    {
        return CANTOPEN;
    }
    // SAFETY: counted terminated input fits the SQLite output allocation.
    unsafe {
        ptr::copy_nonoverlapping(
            filename.as_ptr(),
            output,
            filename.to_bytes_with_nul().len(),
        );
    }
    OK
}
unsafe extern "C" fn dl_open(_: *mut Vfs, _: *const c_char) -> *mut c_void {
    ptr::null_mut()
}
unsafe extern "C" fn dl_error(_: *mut Vfs, size: c_int, output: *mut c_char) {
    if size > 0 && !output.is_null() {
        // SAFETY: nonempty output allocated by SQLite.
        unsafe {
            *output = 0;
        }
    }
}
unsafe extern "C" fn dl_sym(
    _: *mut Vfs,
    _: *mut c_void,
    _: *const c_char,
) -> Option<unsafe extern "C" fn()> {
    None
}
unsafe extern "C" fn dl_close(_: *mut Vfs, _: *mut c_void) {}
unsafe extern "C" fn randomness(_: *mut Vfs, size: c_int, output: *mut c_char) -> c_int {
    if output.is_null() || !(1..=4096).contains(&size) {
        return 0;
    }
    // SAFETY: SQLite allocated this counted randomness output.
    let output = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), size as usize) };
    if getrandom::fill(output).is_ok() {
        size
    } else {
        0
    }
}
unsafe extern "C" fn sleep(_: *mut Vfs, micros: c_int) -> c_int {
    let micros = micros.clamp(0, 1_000_000);
    std::thread::sleep(Duration::from_micros(micros as u64));
    micros
}
unsafe extern "C" fn current_time_int64(_: *mut Vfs, output: *mut i64) -> c_int {
    if output.is_null() {
        return ERROR;
    }
    let value = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_millis(),
        Err(_) => return ERROR,
    };
    let value = match i64::try_from(value)
        .ok()
        .and_then(|v| v.checked_add(210_866_760_000_000))
    {
        Some(value) => value,
        None => return ERROR,
    };
    // SAFETY: SQLite supplies one writable int64 time output.
    unsafe {
        *output = value;
    }
    OK
}
unsafe extern "C" fn current_time(vfs: *mut Vfs, output: *mut f64) -> c_int {
    if output.is_null() {
        return ERROR;
    }
    let mut value = 0i64;
    // SAFETY: our time callback receives valid local writable int64 storage.
    let result = unsafe { current_time_int64(vfs, &mut value) };
    if result == OK {
        // SAFETY: SQLite supplies one writable double time output.
        unsafe {
            *output = value as f64 / 86_400_000.0;
        }
    }
    result
}
unsafe extern "C" fn last_error(_: *mut Vfs, size: c_int, output: *mut c_char) -> c_int {
    if size > 0 && !output.is_null() {
        // SAFETY: nonempty counted error output allocated by SQLite.
        unsafe {
            *output = 0;
        }
    }
    0
}

static IO_METHODS: IoMethods = IoMethods {
    version: 3,
    close: Some(close),
    read: Some(read),
    write: Some(write),
    truncate: Some(truncate),
    sync: Some(sync),
    size: Some(size),
    lock: Some(lock),
    unlock: Some(unlock),
    reserved: Some(reserved),
    control: Some(control),
    sector: Some(sector),
    characteristics: Some(characteristics),
    shm_map: Some(shm_map),
    shm_lock: Some(shm_lock),
    shm_barrier: Some(shm_barrier),
    shm_unmap: Some(shm_unmap),
    fetch: Some(fetch),
    unfetch: Some(unfetch),
};

pub(super) fn vfs_table() -> Box<Vfs> {
    Box::new(Vfs {
        version: 2,
        file_size: std::mem::size_of::<NativeFile>() as c_int,
        max_path: 4096,
        next: ptr::null_mut(),
        name: ptr::null(),
        app: ptr::null_mut(),
        open: Some(open),
        delete: Some(delete),
        access: Some(access),
        full_path: Some(full_path),
        dl_open: Some(dl_open),
        dl_error: Some(dl_error),
        dl_sym: Some(dl_sym),
        dl_close: Some(dl_close),
        randomness: Some(randomness),
        sleep: Some(sleep),
        current_time: Some(current_time),
        last_error: Some(last_error),
        current_time_int64: Some(current_time_int64),
        set_system_call: ptr::null(),
        get_system_call: ptr::null(),
        next_system_call: ptr::null(),
    })
}
