//! One native SQLite connection over consumed O_EXCL creators and its CAS lock.
use super::super::{
    refuse, ClosedUnixOriginalResources, UnixOriginalCloseAttempt, UnixOriginalResourceCloseFailure,
};
use super::{FreshUnixNativeFile, OriginalUnixCasSentinel};
use rusqlite::{
    ffi,
    hooks::{AuthAction, AuthContext, Authorization},
    Connection, OpenFlags,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
};

#[path = "sqlite_callbacks.rs"]
mod callbacks;
static NEXT: AtomicU64 = AtomicU64::new(1);
static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);
thread_local! { static THREAD_TOKEN: u64 = NEXT_THREAD.fetch_add(1, Ordering::Relaxed); }
/// Permanent dispatch payloads are capped at 1024 * 512 bytes, excluding the
/// allocator's bookkeeping. Names never repeat; consumed slots are not reused.
pub const FRESH_UNIX_SQLITE_MAX_REGISTRATIONS: u64 = 1024;
pub const FRESH_UNIX_SQLITE_MAX_DISPATCH_BYTES: usize = 512;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const SHM_REGION: usize = 32 * 1024;

struct Dispatch {
    process: u32,
    thread_token: u64,
    state: AtomicPtr<std::ffi::c_void>,
}
impl Dispatch {
    fn on_original_thread(&self) -> bool {
        self.process == std::process::id() && THREAD_TOKEN.with(|token| *token == self.thread_token)
    }
}

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

/// No DerefMut or Connection extraction. The same acquired connection remains
/// alive through the caller's stages, until an explicit actual close succeeds.
pub struct FreshUnixNativeSqlite<'namespace> {
    connection: Option<Connection>,
    registration: Option<Registration<'namespace>>,
}

pub struct FreshUnixNativeSqliteFailure<'namespace> {
    pub error: io::Error,
    original: Option<FreshUnixNativeSqlite<'namespace>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for FreshUnixNativeSqliteFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FreshUnixNativeSqliteFailure")
            .field("error", &self.error)
            .field("original_owner_retained", &self.original.is_some())
            .field("original_close_uncertain", &self.original_close.is_some())
            .finish()
    }
}

impl FreshUnixNativeSqliteFailure<'_> {
    pub fn retains_original_owner(&self) -> bool {
        self.original.is_some()
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

impl<'namespace> FreshUnixNativeSqlite<'namespace> {
    /// File order is main, WAL, rollback journal, SHM. Every value comes from an
    /// actual O_EXCL creator in one original parent and this exact namespace.
    pub fn open(
        files: [FreshUnixNativeFile<'namespace>; 4],
        coordination: OriginalUnixCasSentinel<'namespace>,
    ) -> Result<Self, FreshUnixNativeSqliteFailure<'namespace>> {
        // Each successful reservation is permanently consumed, even if a later
        // open fails. Admission occurs before any registration allocation.
        let reserved = NEXT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                (next <= FRESH_UNIX_SQLITE_MAX_REGISTRATIONS).then_some(next + 1)
            })
            .map_err(|_| refuse("bounded permanent Unix SQLite callback registrations exhausted"));
        let mut random = [0u8; 16];
        let number = match reserved.and_then(|number| {
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("Unix SQLite registration randomness unavailable"))?;
            Ok(number)
        }) {
            Ok(number) => number,
            Err(error) => {
                let mut close = UnixOriginalCloseAttempt::new();
                for file in files {
                    close.append_result(file.close_retaining());
                }
                close.append_result(coordination.close_retaining());
                return Err(FreshUnixNativeSqliteFailure {
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
            mappings: RefCell::new(BTreeMap::new()),
            shm_locks: Cell::new(0),
        });
        let mut owner = Self {
            connection: None,
            registration: Some(Registration {
                state,
                table: callbacks::table(),
                name,
                registered: false,
                published: false,
                dispatch: Box::new(Dispatch {
                    process: std::process::id(),
                    thread_token: THREAD_TOKEN.with(|token| *token),
                    state: AtomicPtr::new(std::ptr::null_mut()),
                }),
            }),
        };
        let opened = (|| -> io::Result<()> {
            let reg = owner.registration.as_mut().expect("original registration");
            reg.state.verify()?;
            if number == 0 || number == u64::MAX {
                return Err(refuse("Unix SQLite registration generation exhausted"));
            }
            if reg.name.to_bytes_with_nul().len() > 96
                || std::mem::size_of::<ffi::sqlite3_vfs>()
                    + std::mem::size_of::<Dispatch>()
                    + std::mem::size_of::<CString>()
                    + 96
                    > FRESH_UNIX_SQLITE_MAX_DISPATCH_BYTES
            {
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
            reg.dispatch.state.store(
                (&*reg.state as *const State<'_>).cast_mut().cast(),
                Ordering::Release,
            );
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
            let path = reg.state.paths[0].to_str().map_err(io::Error::other)?;
            let connection = Connection::open_with_flags_and_vfs(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                reg.name.to_str().expect("fixed registration"),
            )
            .map_err(io::Error::other)?;
            owner.connection = Some(connection);
            let connection = owner.connection.as_mut().expect("same original connection");
            connection.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL;")
                .map_err(io::Error::other)?;
            let mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            if mode != "wal" {
                return Err(refuse("original Unix SQLite WAL mode required"));
            }
            connection
                .authorizer(Some(|context: AuthContext<'_>| match context.action {
                    AuthAction::Attach { .. }
                    | AuthAction::Detach { .. }
                    | AuthAction::Pragma {
                        pragma_value: Some(_),
                        ..
                    } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
                .map_err(io::Error::other)?;
            owner.verify()
        })();
        match opened {
            Ok(()) => Ok(owner),
            Err(error) => Err(FreshUnixNativeSqliteFailure {
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
        if self.connection.is_none() {
            return Err(refuse("original Unix SQLite connection closed"));
        }
        Ok(())
    }

    pub fn connection(&self) -> io::Result<&Connection> {
        self.verify()?;
        self.connection
            .as_ref()
            .ok_or_else(|| refuse("original Unix SQLite connection absent"))
    }

    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedUnixOriginalResources, FreshUnixNativeSqliteFailure<'namespace>> {
        let mut first = self
            .registration
            .as_ref()
            .and_then(|reg| reg.state.verify().err());
        if let Some(connection) = self.connection.take() {
            if let Err((connection, error)) = connection.close() {
                self.connection = Some(connection);
                return Err(FreshUnixNativeSqliteFailure {
                    error: first.unwrap_or_else(|| io::Error::other(error)),
                    original: Some(self),
                    original_close: None,
                });
            }
        }
        let reg = self
            .registration
            .as_mut()
            .expect("original registration retained until close");
        // SQLite may report successful sqlite3_close after an IO callback has
        // recorded uncertainty. That callback failure never becomes a witness.
        if let Err(error) = reg.state.verify() {
            first.get_or_insert(error);
        }
        if reg.state.active_files.get() != 0 || !reg.state.mappings.borrow().is_empty() {
            return Err(FreshUnixNativeSqliteFailure {
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
                return Err(FreshUnixNativeSqliteFailure {
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
        reg.dispatch
            .state
            .store(std::ptr::null_mut(), Ordering::Release);
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
            Ok(_) => Err(FreshUnixNativeSqliteFailure {
                error: first.take().expect("earlier original failure"),
                original: None,
                original_close: None,
            }),
            Err(failure) => Err(FreshUnixNativeSqliteFailure {
                error: first.unwrap_or_else(|| io::Error::other(failure.error.to_string())),
                original: None,
                original_close: Some(failure),
            }),
        }
    }
}

impl Drop for FreshUnixNativeSqlite<'_> {
    fn drop(&mut self) {
        // Cancellation/implicit drop cannot close SQLite before proving its
        // callbacks ended. Preserve the actual objects until explicit terminal.
        if let Some(connection) = self.connection.take() {
            let _ = Box::leak(Box::new(connection));
        }
        if let Some(registration) = self.registration.take() {
            let _ = Box::leak(Box::new(registration));
        }
    }
}

use std::ffi::OsStr;
