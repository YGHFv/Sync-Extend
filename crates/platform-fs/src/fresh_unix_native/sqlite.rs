//! Original FD/VFS resources only; the Journal crate owns its sole Connection.
use super::super::{
    refuse, ClosedUnixOriginalResources, UnixOriginalCloseAttempt, UnixOriginalResourceCloseFailure,
};
use super::sqlite_resources::{SqliteCoordination, SqliteOriginalFile};
use super::{
    FreshUnixNativeFile, OriginalUnixCasSentinel, ReacquiredUnixSqliteFile,
    ReacquiredUnixSqliteLock, SealedUnixNativeFile,
};
use crate::original_sqlite_dispatch::{reserve_registration, Dispatch, MAX_NAME_BYTES};
use rusqlite::ffi;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
    rc::{Rc, Weak},
};

#[path = "sqlite_callbacks.rs"]
mod callbacks;
/// Permanent dispatch payloads are capped at 1024 * 512 bytes, excluding the
/// allocator's bookkeeping. Names never repeat; consumed slots are not reused.
pub const FRESH_UNIX_SQLITE_MAX_REGISTRATIONS: u64 =
    crate::original_sqlite_dispatch::MAX_REGISTRATIONS;
pub const FRESH_UNIX_SQLITE_MAX_DISPATCH_BYTES: usize =
    crate::original_sqlite_dispatch::MAX_DISPATCH_BYTES;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const SHM_REGION: usize = 32 * 1024;

struct Mapping {
    address: *mut std::ffi::c_void,
    bytes: usize,
}

struct State<'namespace> {
    session: Rc<()>,
    files: [SqliteOriginalFile<'namespace>; 4],
    coordination: SqliteCoordination<'namespace>,
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
        self.files[0].namespace().on_original_thread()
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

/// An opaque identity issued by one actual live IO owner. Descriptive keys
/// cannot construct it, and it does not keep the IO or namespace alive.
pub struct OriginalUnixSqliteSessionBinding {
    session: Weak<()>,
}

/// Borrowed access to the already opened four originals and CAS lock. There is
/// no serialized form or constructor from paths, descriptors, keys or hashes.
pub struct OriginalUnixSqliteSessionLoan<'owner, 'namespace> {
    original: &'owner FreshUnixNativeSqliteIo<'namespace>,
}

impl OriginalUnixSqliteSessionLoan<'_, '_> {
    pub fn verify(&self) -> io::Result<()> {
        self.original.verify_connection_opened()
    }

    pub fn binding(&self) -> io::Result<OriginalUnixSqliteSessionBinding> {
        self.verify()?;
        Ok(OriginalUnixSqliteSessionBinding {
            session: Rc::downgrade(
                &self
                    .original
                    .registration
                    .as_ref()
                    .expect("actual original session")
                    .state
                    .session,
            ),
        })
    }

    pub fn verify_binding(&self, binding: &OriginalUnixSqliteSessionBinding) -> io::Result<()> {
        self.verify()?;
        let state = &self
            .original
            .registration
            .as_ref()
            .expect("actual original session")
            .state;
        if !binding.session.ptr_eq(&Rc::downgrade(&state.session)) {
            return Err(refuse("different original Unix SQLite session"));
        }
        Ok(())
    }

    /// Namespace, actual parent, main/WAL/rollback/SHM and CAS descriptors are
    /// observations only. They never recreate this loan or the session binding.
    pub fn observed_keys(&self) -> io::Result<[super::super::UnixProtectedArtifactKey; 7]> {
        self.verify()?;
        let state = &self
            .original
            .registration
            .as_ref()
            .expect("actual original session")
            .state;
        Ok([
            state.files[0].namespace().key()?,
            state.files[0].parent().key()?,
            state.files[0].key()?,
            state.files[1].key()?,
            state.files[2].key()?,
            state.files[3].key()?,
            state.coordination.key()?,
        ])
    }

    /// The complete intent must be durable on a sealed original creator in the
    /// same actual data parent and namespace before the Journal admits effects.
    pub fn verify_durable_intent(
        &self,
        file: &SealedUnixNativeFile<'_>,
        expected: &[u8],
    ) -> io::Result<()> {
        self.verify()?;
        let state = &self
            .original
            .registration
            .as_ref()
            .expect("actual original session")
            .state;
        file.verify_ordered_bytes(&[expected])?;
        if !state.files[0]
            .namespace()
            .same_original(&file.original.namespace)
            || state.files[0].parent().key()? != file.original.original.parent.key()?
            || state.files.iter().any(|native| {
                native
                    .key()
                    .is_ok_and(|key| key == file.original.original.key())
            })
            || state.coordination.key()? == file.original.original.key()
        {
            return Err(refuse("original Unix session intent scope differs"));
        }
        self.verify()
    }
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
        Self::acquire_resources(
            files.map(SqliteOriginalFile::Created),
            SqliteCoordination::Created(coordination),
            false,
        )
    }

    /// Consume independently acquired existing originals. These retain their
    /// distinct acquisition type throughout the shared native VFS protocol.
    pub fn reacquire(
        files: [ReacquiredUnixSqliteFile<'namespace>; 4],
        coordination: ReacquiredUnixSqliteLock<'namespace>,
    ) -> Result<Self, FreshUnixNativeSqliteIoFailure<'namespace>> {
        Self::acquire_resources(
            files.map(SqliteOriginalFile::Acquired),
            SqliteCoordination::Acquired(coordination),
            true,
        )
    }

    fn acquire_resources(
        files: [SqliteOriginalFile<'namespace>; 4],
        coordination: SqliteCoordination<'namespace>,
        existing: bool,
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
            let source = &files[index];
            // Components were bounded and NUL checked by the actual creator.
            CString::new(
                source
                    .parent()
                    .path
                    .join(OsStr::from_bytes(source.component().to_bytes()))
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
            session: Rc::new(()),
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
            let parent = first.parent().key()?;
            let expected = [
                "journal.sqlite",
                "journal.sqlite-wal",
                "journal.sqlite-journal",
                "journal.sqlite-shm",
            ];
            for (index, file) in reg.state.files.iter().enumerate() {
                if !file.namespace().same_original(first.namespace())
                    || file.parent().key()? != parent
                    || file.component().to_bytes() != expected[index].as_bytes()
                    || file.maximum() > MAX_FILE
                    || index > 0 && !existing && file.file().metadata()?.len() != 0
                {
                    return Err(refuse("exact original Unix SQLite creator set required"));
                }
            }
            if !reg
                .state
                .coordination
                .namespace()
                .same_original(first.namespace())
                || reg.state.coordination.parent().key()? != parent
                || reg.state.files[3].maximum() < SHM_REGION as u64
                || reg.state.files[3].maximum() % SHM_REGION as u64 != 0
            {
                return Err(refuse("original Unix SQLite CAS/SHM owner scope differs"));
            }
            if existing {
                if reg.state.files[3].file().metadata()?.len() != reg.state.files[3].maximum() {
                    return Err(refuse("existing Unix SHM original allocation differs"));
                }
            } else {
                reg.state.files[3]
                    .file()
                    .set_len(reg.state.files[3].maximum())?;
                reg.state.files[3].file().sync_all()?;
            }
            reg.table.zName = reg.name.as_ptr();
            reg.dispatch
                .publish((&*reg.state as *const State<'_>).cast_mut().cast());
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

    pub fn session_loan(&self) -> io::Result<OriginalUnixSqliteSessionLoan<'_, 'namespace>> {
        self.verify_connection_opened()?;
        Ok(OriginalUnixSqliteSessionLoan { original: self })
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
