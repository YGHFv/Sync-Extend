//! Original FD/VFS resources only; the Journal crate owns its sole Connection.
use super::super::{
    refuse, ClosedUnixOriginalResources, UnixOriginalCloseAttempt, UnixOriginalResourceCloseFailure,
};
use super::{FreshUnixNativeFile, OriginalUnixCasSentinel};
use crate::original_sqlite_dispatch::{reserve_registration, Dispatch, MAX_NAME_BYTES};
use rusqlite::ffi;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
};

#[path = "sqlite_callbacks.rs"]
mod callbacks;
/// Permanent dispatch payloads are capped at 1024 * 512 bytes, excluding the
/// allocator's bookkeeping. Names never repeat; consumed slots are not reused.
pub const FRESH_UNIX_SQLITE_MAX_REGISTRATIONS: u64 = crate::original_sqlite_dispatch::MAX_REGISTRATIONS;
pub const FRESH_UNIX_SQLITE_MAX_DISPATCH_BYTES: usize = crate::original_sqlite_dispatch::MAX_DISPATCH_BYTES;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const SHM_REGION: usize = 32 * 1024;

struct Mapping {
    address: *mut std::ffi::c_void,
    bytes: usize,
}

struct State<'namespace> {
    files: [FreshUnixNativeFile<'namespace>; 4],
    coordination: OriginalUnixCasSentinel<'namespace>,
    paths: [CString; 4],
    poisoned: Cell<bool>,
    active_files: Cell<usize>,
    main_opened: Cell<bool>,
    main_active: Cell<bool>,
    main_open_permitted: Cell<bool>,
    mappings: RefCell<BTreeMap<i32, Mapping>>,
    shm_locks: Cell<u8>,
}

impl State<'_> {
    fn on_original_thread(&self) -> bool {
        self.files[0].namespace.on_original_thread()
    }
    fn verify(&self) -> io::Result<()> {
        if !self.on_original_thread() {
            return Err(refuse("original Unix SQLite used from foreign thread"));
        }
        if self.poisoned.get() {
            return Err(refuse("original Unix SQLite owner is poisoned"));
        }
        self.coordination.verify()?;
        for file in &self.files {
            file.verify()?;
        }
        Ok(())
    }

    fn unmap(&self) -> io::Result<()> {
        let mut maps = self
            .mappings
            .try_borrow_mut()
            .map_err(|_| refuse("original Unix SQLite mapping is borrowed"))?;
        let mut first = None;
        maps.retain(|_, map| {
            // SAFETY: these are exact owned mmap addresses/lengths. A successful
            // unmap removes that entry once; failed mappings remain retained.
            if unsafe { libc::munmap(map.address, map.bytes) } == 0 {
                false
            } else {
                first.get_or_insert_with(io::Error::last_os_error);
                true
            }
        });
        first.map_or(Ok(()), Err)
    }
}

struct Registration<'namespace> {
    state: Box<State<'namespace>>,
    table: Box<ffi::sqlite3_vfs>,
    name: CString,
    dispatch: Box<Dispatch>,
    registered: bool,
    published: bool,
}

/// Owns only actual original files and VFS state. No Connection is accepted or
/// returned; the higher-level Journal owner retains its single Connection.
pub struct FreshUnixNativeSqliteIo<'namespace> {
    registration: Option<Registration<'namespace>>,
}

pub struct FreshUnixNativeSqliteIoFailure<'namespace> {
    pub error: io::Error,
    original: Option<FreshUnixNativeSqliteIo<'namespace>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for FreshUnixNativeSqliteIoFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FreshUnixNativeSqliteIoFailure")
            .field("error", &self.error)
            .field("original_owner_retained", &self.original.is_some())
            .field("original_close_uncertain", &self.original_close.is_some())
            .finish()
    }
}

impl FreshUnixNativeSqliteIoFailure<'_> {
    pub fn retains_original_owner(&self) -> bool {
        self.original.is_some()
    }
    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self
                .original_close
                .as_ref()
                .is_some_and(|failure| failure.retained_parent_scopes() != 0)
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.take() {
            if let Err(mut later) = original.close_retaining() {
                self.original = later.original.take();
                if let Some(later) = later.original_close.take() {
                    let mut close = UnixOriginalCloseAttempt::new();
                    if let Some(previous) = self.original_close.take() {
                        close.append_result(Err(previous));
                    }
                    close.append_result(Err(later));
                    self.original_close = close.finish().err();
                }
            }
        }
        if let Some(original) = self.original_close.take() {
            self.original_close = Some(original.close_remaining());
        }
        self
    }
}

impl<'namespace> FreshUnixNativeSqliteIo<'namespace> {
    /// File order is main, WAL, rollback journal, SHM. Every value comes from an
    /// actual O_EXCL creator in one original parent and this exact namespace.
    pub fn acquire(
        files: [FreshUnixNativeFile<'namespace>; 4],
        coordination: OriginalUnixCasSentinel<'namespace>,
    ) -> Result<Self, FreshUnixNativeSqliteIoFailure<'namespace>> {
        // Each successful reservation is permanently consumed, even if a later
        // open fails. Admission occurs before any registration allocation.
        let reserved = reserve_registration();
        let mut random = [0u8; 16];
        let (number, dispatch) = match reserved.and_then(|number| {
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("Unix SQLite registration randomness unavailable"))?;
            Ok((number, Dispatch::new()?))
        }) {
            Ok(reserved) => reserved,
            Err(error) => {
                let mut close = UnixOriginalCloseAttempt::new();
                for file in files {
                    close.append_result(file.close_retaining());
                }
                close.append_result(coordination.close_retaining());
                return Err(FreshUnixNativeSqliteIoFailure {
                    error,
                    original: None,
                    original_close: close.finish().err(),
                });
            }
        };
        let paths = std::array::from_fn(|index| {
            let source = &files[index].original;
            // Components were bounded and NUL checked by the actual creator.
            CString::new(
                source
                    .parent
                    .path
                    .join(OsStr::from_bytes(source.component.as_bytes()))
                    .as_os_str()
                    .as_bytes(),
            )
            .expect("checked original Unix SQLite path")
        });
        let random = u128::from_ne_bytes(random);
        let name = CString::new(format!(
            "sync-fresh-unix-{}-{number}-{random:032x}",
            std::process::id()
        ))
        .expect("fixed Unix SQLite registration encoding");
        let state = Box::new(State {
            files,
            coordination,
            paths,
            poisoned: Cell::new(false),
            active_files: Cell::new(0),
            main_opened: Cell::new(false),
            main_active: Cell::new(false),
            main_open_permitted: Cell::new(false),
            mappings: RefCell::new(BTreeMap::new()),
            shm_locks: Cell::new(0),
        });
        let mut owner = Self {
            registration: Some(Registration {
                state,
                table: callbacks::table(),
                name,
                registered: false,
                published: false,
                dispatch: Box::new(dispatch),
            }),
        };
        let opened = (|| -> io::Result<()> {
            let reg = owner.registration.as_mut().expect("original registration");
            reg.state.verify()?;
            if number == 0 || number == u64::MAX {
                return Err(refuse("Unix SQLite registration generation exhausted"));
            }
            if reg.name.to_bytes_with_nul().len() > MAX_NAME_BYTES {
                return Err(refuse("bounded permanent Unix SQLite dispatch payload"));
            }
            let first = &reg.state.files[0];
            let parent = first.original.parent.key()?;
            let expected = [
                "journal.sqlite",
                "journal.sqlite-wal",
                "journal.sqlite-journal",
                "journal.sqlite-shm",
            ];
            for (index, file) in reg.state.files.iter().enumerate() {
                if !file.namespace.same_original(&first.namespace)
                    || file.original.parent.key()? != parent
                    || file.original.component.as_bytes() != expected[index].as_bytes()
                    || file.maximum > MAX_FILE
                    || index > 0 && file.original.file.metadata()?.len() != 0
                {
                    return Err(refuse("exact original Unix SQLite creator set required"));
                }
            }
            if !reg
                .state
                .coordination
                .original
                .namespace
                .same_original(&first.namespace)
                || reg.state.coordination.original.original.parent.key()? != parent
                || reg.state.files[3].maximum < SHM_REGION as u64
                || reg.state.files[3].maximum % SHM_REGION as u64 != 0
            {
                return Err(refuse("original Unix SQLite CAS/SHM owner scope differs"));
            }
            reg.state.files[3]
                .original
                .file
                .set_len(reg.state.files[3].maximum)?;
            reg.state.files[3].original.file.sync_all()?;
            reg.table.zName = reg.name.as_ptr();
            reg.dispatch.publish((&*reg.state as *const State<'_>).cast_mut().cast());
            reg.table.pAppData = (&*reg.dispatch as *const Dispatch).cast_mut().cast();
            reg.published = true;
            // SAFETY: table/name/state are stable boxed values retained until
            // the same connection and all its IO callbacks have closed.
            if unsafe { ffi::sqlite3_vfs_register(&mut *reg.table, 0) } != ffi::SQLITE_OK {
                return Err(io::Error::other(
                    "original Unix SQLite VFS registration refused",
                ));
            }
            reg.registered = true;
            owner.verify()
        })();
        match opened {
            Ok(()) => Ok(owner),
            Err(error) => Err(FreshUnixNativeSqliteIoFailure {
                error,
                original: Some(owner),
                original_close: None,
            }),
        }
    }

    pub fn verify(&self) -> io::Result<()> {
        self.registration
            .as_ref()
            .ok_or_else(|| refuse("original Unix SQLite registration closed"))?
            .state
            .verify()?;
        Ok(())
    }

    pub fn single_open_scope(&self) -> io::Result<FreshUnixSqliteOpenScope<'_, 'namespace>> {
        self.verify()?;
        let reg = self
            .registration
            .as_ref()
            .expect("actual original VFS registration");
        if reg.state.main_opened.get() || reg.state.main_open_permitted.replace(true) {
            return Err(refuse(
                "original Unix SQLite main open already permitted or consumed",
            ));
        }
        Ok(FreshUnixSqliteOpenScope { original: self })
    }

    pub fn verify_connection_opened(&self) -> io::Result<()> {
        self.verify()?;
        let state = &self
            .registration
            .as_ref()
            .expect("original VFS registration")
            .state;
        if !state.main_opened.get()
            || !state.main_active.get()
            || state.active_files.get() == 0
            || state.main_open_permitted.get()
        {
            return Err(refuse(
                "one completed original Unix SQLite main open required",
            ));
        }
        Ok(())
    }

    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedUnixOriginalResources, FreshUnixNativeSqliteIoFailure<'namespace>> {
        let mut first = self
            .registration
            .as_ref()
            .and_then(|reg| reg.state.verify().err());
        let reg = self
            .registration
            .as_mut()
            .expect("original registration retained until close");
        // Every IO callback must end before its owner can close the originals.
        // A recorded callback failure never becomes a successful witness.
        if let Err(error) = reg.state.verify() {
            first.get_or_insert(error);
        }
        if reg.state.active_files.get() != 0 || !reg.state.mappings.borrow().is_empty() {
            return Err(FreshUnixNativeSqliteIoFailure {
                error: first
                    .unwrap_or_else(|| refuse("original Unix SQLite IO/mapping remains live")),
                original: Some(self),
                original_close: None,
            });
        }
        if reg.registered {
            // SAFETY: the same connection is closed and no callback context or
            // mapping remains. Unregister precedes every descriptor terminal.
            if unsafe { ffi::sqlite3_vfs_unregister(&mut *reg.table) } != ffi::SQLITE_OK {
                return Err(FreshUnixNativeSqliteIoFailure {
                    error: first
                        .unwrap_or_else(|| refuse("original Unix SQLite VFS unregister failed")),
                    original: Some(self),
                    original_close: None,
                });
            }
            reg.registered = false;
        }
        let reg = self
            .registration
            .take()
            .expect("unregistered original resources");
        reg.dispatch.clear();
        let Registration {
            state,
            table,
            dispatch,
            name,
            published,
            ..
        } = reg;
        if published {
            // SQLite callers can retain a global table lookup past unregister.
            // Keep only this bounded inert table/name/dispatch, never live state.
            let _ = Box::leak(table);
            let _ = Box::leak(dispatch);
            std::mem::forget(name);
        }
        let State {
            files,
            coordination,
            ..
        } = *state;
        let mut close = UnixOriginalCloseAttempt::new();
        for file in files {
            close.append_result(file.close_retaining());
        }
        close.append_result(coordination.close_retaining());
        match close.finish() {
            Ok(closed) if first.is_none() => Ok(closed),
            Ok(_) => Err(FreshUnixNativeSqliteIoFailure {
                error: first.take().expect("earlier original failure"),
                original: None,
                original_close: None,
            }),
            Err(failure) => Err(FreshUnixNativeSqliteIoFailure {
                error: first.unwrap_or_else(|| io::Error::other(failure.error.to_string())),
                original: None,
                original_close: Some(failure),
            }),
        }
    }
}

impl Drop for FreshUnixNativeSqliteIo<'_> {
    fn drop(&mut self) {
        // Cancellation/implicit drop cannot close SQLite before proving its
        // callbacks ended. Preserve the actual objects until explicit terminal.
        if let Some(registration) = self.registration.take() {
            let _ = Box::leak(Box::new(registration));
        }
    }
}

use std::ffi::OsStr;

/// A short original owner loan permits one main xOpen. Strings only route that
/// open; neither they nor cached VFS pointers can reconstruct the owner scope.
pub struct FreshUnixSqliteOpenScope<'owner, 'namespace> {
    original: &'owner FreshUnixNativeSqliteIo<'namespace>,
}
impl FreshUnixSqliteOpenScope<'_, '_> {
    pub fn database_path(&self) -> io::Result<&str> {
        self.original.verify()?;
        self.original
            .registration
            .as_ref()
            .expect("actual registration")
            .state
            .paths[0]
            .to_str()
            .map_err(io::Error::other)
    }
    pub fn vfs_name(&self) -> io::Result<&str> {
        self.original.verify()?;
        self.original
            .registration
            .as_ref()
            .expect("actual registration")
            .name
            .to_str()
            .map_err(io::Error::other)
    }
}
impl Drop for FreshUnixSqliteOpenScope<'_, '_> {
    fn drop(&mut self) {
        if let Some(registration) = self.original.registration.as_ref() {
            registration.state.main_open_permitted.set(false);
        }
    }
}
