//! Keep the same readonly DB, original aligned owning IO, and callback context
//! in one opaque owner. A logical SQLite close never proves native IO closure.
use super::scoped_vfs::OriginalSqliteVfs;
use crate::{
    ClosedWindowsOriginalResources, FileKey, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};
use rusqlite::{ffi, Connection, Transaction, TransactionBehavior};
use std::{
    ffi::{CStr, CString},
    io,
    path::Path,
    ptr,
};

enum OriginalDatabase {
    /// The same Connection lives only inside OriginalReadonlySqliteConnection.
    ConnectionLoan(*mut ffi::sqlite3),
    /// A failed open_v2 returned this same partial DB without a rusqlite owner.
    FailedOpenOwner(*mut ffi::sqlite3),
}

/// This private component is neither Send nor independently transferable. All
/// access to its Rc/RefCell callback state follows the whole owner's DB borrow.
struct OriginalReadonlySqliteResources {
    registration: Option<OriginalSqliteVfs>,
    original_database: Option<OriginalDatabase>,
}

/// The same DB and every original callback/native allocation move together.
/// There is no Connection extraction, mutable dereference, or split operation.
/// A shared Connection borrow cannot cross threads because Connection is !Sync.
pub struct OriginalReadonlySqliteConnection {
    connection: Option<Connection>,
    original: OriginalReadonlySqliteResources,
}

// SAFETY: only this whole unique owner can move between threads. Its original
// DB, first VFS registration, aligned builtin IO, filenames, callback policy,
// and every partial native owner move together at stable allocations. Neither
// the Rc-bearing component nor a mutable Connection reference is exposed.
// SQLite uses NOMUTEX/PRIVATECACHE and all ordinary SQL borrows remain !Send.
// Controlled mutable methods cannot replace or transfer the Connection. The
// bounded global callback slot checks the current whole owner's thread before
// touching private Rc state; only this constructor scopes the single main open.
// A late foreign lookup retains a stable inert table, not any freed context.
// The same whole owner performs both consuming logical close and native close;
// a busy or native failure retains it intact for resource ending only.
unsafe impl Send for OriginalReadonlySqliteConnection {}

pub struct OriginalReadonlySqliteOpenFailure {
    pub error: io::Error,
    original: OriginalReadonlySqliteConnection,
    original_resource_terminal: Option<WindowsOriginalResourceCloseFailure>,
    pub actual_closed_handles: usize,
}

/// The initial failure and exact whole original owner survive every retry.
/// Successful retries end resources but never erase that initial failure.
pub struct OriginalReadonlySqliteCloseFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original: Option<OriginalReadonlySqliteConnection>,
    original_resource_terminal: Option<WindowsOriginalResourceCloseFailure>,
}

fn copy_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

impl std::fmt::Debug for OriginalReadonlySqliteOpenFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalReadonlySqliteOpenFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field("originals_retained", &self.has_retained_originals())
            .finish()
    }
}

impl std::fmt::Debug for OriginalReadonlySqliteCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalReadonlySqliteCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field("originals_retained", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalReadonlySqliteOpenFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original.has_retained_originals()
            || self
                .original_resource_terminal
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    pub fn close_remaining(mut self) -> Self {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        terminal.append_original_handle_prefix(self.actual_closed_handles);
        terminal.note_error(copy_error(&self.error));
        if let Some(original) = self.original_resource_terminal.take() {
            // Its successful prefix was already included above.
            let previous_closed = original.actual_closed_handles;
            let mut original = original.close_remaining();
            original.actual_closed_handles = original
                .actual_closed_handles
                .saturating_sub(previous_closed);
            terminal.append_failure(original);
        }
        if let Err(error) = self
            .original
            .close_original_resources_into_attempt(&mut terminal)
        {
            terminal.note_error(error);
        }
        match terminal.finish() {
            Err(original) => {
                self.actual_closed_handles = original.actual_closed_handles;
                self.original_resource_terminal = Some(original);
            }
            Ok(_) => unreachable!("the original preparation failure remains recorded"),
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> io::Error {
        let error = copy_error(&self.error);
        let original = self.close_remaining();
        if original.has_retained_originals() {
            original.retain_until_process_exit();
        }
        error
    }
}

impl OriginalReadonlySqliteConnection {
    /// Existing original standalone main. xAccess observes every actual
    /// sidecar; SQLite cannot acquire an unapproved sidecar through this VFS.
    pub fn open_original_main_retaining(
        path: &Path,
        expected_main: FileKey,
        maximum_main_bytes: u64,
    ) -> Result<Self, OriginalReadonlySqliteOpenFailure> {
        Self::open_retaining(path, expected_main, maximum_main_bytes, None, false)
    }

    /// A distinct stopped-source purpose, with the caller's original source
    /// locks and full sidecar hashes retained. Only its bounded original WAL
    /// can be read through the same owning IO; no named SHM is acquired.
    pub fn open_stopped_existing_retaining(
        path: &Path,
        expected_main: FileKey,
        maximum_main_bytes: u64,
        existing_wal: Option<(FileKey, u64)>,
    ) -> Result<Self, OriginalReadonlySqliteOpenFailure> {
        Self::open_retaining(path, expected_main, maximum_main_bytes, existing_wal, true)
    }

    fn open_retaining(
        path: &Path,
        expected_main: FileKey,
        maximum_main_bytes: u64,
        existing_wal: Option<(FileKey, u64)>,
        stopped_capture: bool,
    ) -> Result<Self, OriginalReadonlySqliteOpenFailure> {
        let mut original = Self {
            connection: None,
            original: OriginalReadonlySqliteResources {
                registration: None,
                original_database: None,
            },
        };
        let prepared = (|| -> io::Result<CString> {
            let filename = CString::new(
                path.to_str()
                    .ok_or_else(|| io::Error::other("readonly SQLite path encoding"))?,
            )
            .map_err(|_| io::Error::other("readonly SQLite path contains NUL"))?;
            original.original.registration = Some(OriginalSqliteVfs::register_readonly(
                path,
                expected_main,
                maximum_main_bytes,
                existing_wal,
                stopped_capture,
            )?);
            Ok(filename)
        })();
        let filename = match prepared {
            Ok(filename) => filename,
            Err(error) => {
                return Err(OriginalReadonlySqliteOpenFailure {
                    error,
                    original,
                    original_resource_terminal: None,
                    actual_closed_handles: 0,
                })
            }
        };
        let _original_open = match original
            .original
            .registration
            .as_ref()
            .expect("same original registration prepared")
            .begin_single_main_open()
        {
            Ok(original_open) => original_open,
            Err(error) => {
                return Err(OriginalReadonlySqliteOpenFailure {
                    error,
                    original,
                    original_resource_terminal: None,
                    actual_closed_handles: 0,
                })
            }
        };
        let mut database = ptr::null_mut();
        let flags =
            ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_NOMUTEX | ffi::SQLITE_OPEN_PRIVATECACHE;
        // SAFETY: the same first scoped registration and every exact filename
        // remain owned across this single original open_v2 call.
        let opened = unsafe {
            ffi::sqlite3_open_v2(
                filename.as_ptr(),
                &mut database,
                flags,
                original
                    .original
                    .registration
                    .as_ref()
                    .expect("first registration retained")
                    .name()
                    .as_ptr(),
            )
        };
        if !database.is_null() {
            original.original.original_database = Some(OriginalDatabase::FailedOpenOwner(database));
        }
        if opened != ffi::SQLITE_OK || database.is_null() {
            let error = if database.is_null() {
                io::Error::other(format!(
                    "original readonly SQLite open returned {opened} without a DB"
                ))
            } else {
                // SAFETY: this same partial DB returned by open_v2 is retained.
                let message = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(database)) }
                    .to_string_lossy()
                    .into_owned();
                io::Error::other(rusqlite::Error::SqliteFailure(
                    ffi::Error::new(opened),
                    Some(message),
                ))
            };
            return Err(OriginalReadonlySqliteOpenFailure {
                error,
                original,
                original_resource_terminal: None,
                actual_closed_handles: 0,
            });
        }
        // SAFETY: ownership transfers once from the same actual original DB.
        // No VFS, file, or replacement DB is opened by this transfer.
        let connection = match unsafe { Connection::from_handle_owned(database) } {
            Ok(connection) => connection,
            Err(error) => {
                return Err(OriginalReadonlySqliteOpenFailure {
                    error: io::Error::other(error),
                    original,
                    original_resource_terminal: None,
                    actual_closed_handles: 0,
                })
            }
        };
        original.connection = Some(connection);
        original.original.original_database = Some(OriginalDatabase::ConnectionLoan(database));
        Ok(original)
    }

    /// Ordinary SQL borrows only the same live DB. A terminal owner with no
    /// connection never exposes a replacement or a mutable Connection slot.
    pub fn connection(&self) -> Option<&Connection> {
        self.original
            .registration
            .as_ref()?
            .activate_current_thread()
            .ok()?;
        self.connection.as_ref()
    }

    pub fn verify_original_connection(&self) -> io::Result<()> {
        let Some(OriginalDatabase::ConnectionLoan(original)) = self.original.original_database
        else {
            return Err(io::Error::other("original readonly Connection is not live"));
        };
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| io::Error::other("same original readonly DB owner absent"))?;
        // SAFETY: the same Connection is privately owned and borrowed here.
        if unsafe { connection.handle() } != original {
            return Err(io::Error::other(
                "readonly Connection differs from its original owner",
            ));
        }
        self.original
            .registration
            .as_ref()
            .ok_or_else(|| io::Error::other("original readonly registration absent"))?
            .verify_readonly_original()
    }

    fn activate_original_thread_for_mutation(&self) -> rusqlite::Result<()> {
        self.original
            .registration
            .as_ref()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .activate_current_thread()
            .map_err(|error| {
                rusqlite::Error::SqliteFailure(
                    ffi::Error::new(ffi::SQLITE_MISUSE),
                    Some(error.to_string()),
                )
            })
    }

    /// Install a bounded hook without permitting Connection replacement or
    /// extraction. The callback's Send bound matches the original rusqlite API.
    pub fn progress_handler<F>(&mut self, num_ops: i32, handler: Option<F>) -> rusqlite::Result<()>
    where
        F: FnMut() -> bool + Send + 'static,
    {
        self.activate_original_thread_for_mutation()?;
        self.connection
            .as_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .progress_handler(num_ops, handler)
    }

    pub fn transaction(&mut self) -> rusqlite::Result<Transaction<'_>> {
        self.activate_original_thread_for_mutation()?;
        self.connection
            .as_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .transaction()
    }

    pub fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> rusqlite::Result<Transaction<'_>> {
        self.activate_original_thread_for_mutation()?;
        self.connection
            .as_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .transaction_with_behavior(behavior)
    }

    pub fn has_retained_originals(&self) -> bool {
        self.connection.is_some() || self.original.has_retained_originals()
    }

    /// Close this same DB before ending any owning builtin IO or callback
    /// state. Busy restores the same Connection inside this same whole pair.
    /// A successful logical close keeps this owner until actual native close.
    pub fn close_original_resources_into_attempt(
        &mut self,
        terminal: &mut WindowsOriginalCloseAttempt,
    ) -> io::Result<bool> {
        if let Some(registration) = &self.original.registration {
            // Move only the whole owner authority. The gate is released before
            // SQLite's logical close can call this same original VFS again.
            registration.activate_current_thread()?;
        } else if self.connection.is_some() || self.original.original_database.is_some() {
            return Err(io::Error::other(
                "same original readonly callback gate absent",
            ));
        }
        if let Some(connection) = self.connection.take() {
            let Some(OriginalDatabase::ConnectionLoan(original)) = self.original.original_database
            else {
                self.connection = Some(connection);
                return Err(io::Error::other("same original readonly DB close required"));
            };
            // SAFETY: only this opaque owner can own or consume the Connection.
            if unsafe { connection.handle() } != original {
                self.connection = Some(connection);
                return Err(io::Error::other(
                    "same original readonly DB identity differs",
                ));
            }
            match connection.close() {
                Ok(()) => self.original.original_database = None,
                Err((connection, error)) => {
                    self.connection = Some(connection);
                    return Err(io::Error::other(error));
                }
            }
        }
        self.original.close_original_io_into_attempt(terminal);
        Ok(!self.has_retained_originals())
    }

    pub fn close_original_resources_retaining(
        mut self,
    ) -> Result<ClosedWindowsOriginalResources, OriginalReadonlySqliteCloseFailure> {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        let complete = match self.close_original_resources_into_attempt(&mut terminal) {
            Ok(complete) => complete,
            Err(error) => {
                terminal.note_error(error);
                false
            }
        };
        if !complete && terminal.original_close_error().is_none() {
            terminal.note_error(io::Error::other(
                "original readonly native terminal incomplete",
            ));
        }
        match terminal.finish() {
            Ok(closed) => Ok(closed),
            Err(original_resources) => Err(OriginalReadonlySqliteCloseFailure {
                error: copy_error(&original_resources.error),
                actual_closed_handles: original_resources.actual_closed_handles,
                original: self.has_retained_originals().then_some(self),
                original_resource_terminal: Some(original_resources),
            }),
        }
    }
}

impl OriginalReadonlySqliteCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original
            .as_ref()
            .is_some_and(OriginalReadonlySqliteConnection::has_retained_originals)
            || self
                .original_resource_terminal
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    pub fn close_remaining(mut self) -> Self {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        terminal.note_error(copy_error(&self.error));
        if let Some(original) = self.original_resource_terminal.take() {
            terminal.append_failure(original.close_remaining());
        } else {
            terminal.append_original_handle_prefix(self.actual_closed_handles);
        }
        if let Some(original) = self.original.as_mut() {
            match original.close_original_resources_into_attempt(&mut terminal) {
                Ok(true) => {
                    self.original.take();
                }
                Ok(false) => (),
                Err(error) => terminal.note_error(error),
            }
        }
        match terminal.finish() {
            Err(original_resources) => {
                self.actual_closed_handles = original_resources.actual_closed_handles;
                self.original_resource_terminal = Some(original_resources);
            }
            Ok(_) => unreachable!("the initial original readonly close failure remains"),
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl OriginalReadonlySqliteResources {
    fn has_retained_originals(&self) -> bool {
        self.original_database.is_some()
            || self
                .registration
                .as_ref()
                .is_some_and(OriginalSqliteVfs::has_original_context)
    }

    fn close_original_io_into_attempt(&mut self, terminal: &mut WindowsOriginalCloseAttempt) {
        match self.original_database {
            Some(OriginalDatabase::ConnectionLoan(_)) => {
                terminal.note_error(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "same original readonly Connection still owns its pager loan",
                ));
                return;
            }
            Some(OriginalDatabase::FailedOpenOwner(database)) => {
                // SAFETY: only the opaque pair owns this partial open_v2 DB.
                let closed = unsafe { ffi::sqlite3_close(database) };
                if closed != ffi::SQLITE_OK {
                    // SAFETY: the failed close retained this same live DB.
                    let message = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(database)) }
                        .to_string_lossy()
                        .into_owned();
                    terminal.note_error(io::Error::other(rusqlite::Error::SqliteFailure(
                        ffi::Error::new(closed),
                        Some(message),
                    )));
                    return;
                }
                self.original_database = None;
            }
            None => (),
        }
        if let Some(registration) = &mut self.registration {
            registration.close_original_into_attempt(terminal);
            if !registration.has_original_context() {
                self.registration.take();
            }
        }
    }
}

impl Drop for OriginalReadonlySqliteConnection {
    fn drop(&mut self) {
        if !self.has_retained_originals() {
            return;
        }
        let original = Self {
            connection: self.connection.take(),
            original: OriginalReadonlySqliteResources {
                registration: self.original.registration.take(),
                original_database: self.original.original_database.take(),
            },
        };
        // Successful fallback ends actual native resources promptly. A refusal
        // retains the same whole pair; independent DB/resource Drop cannot run.
        if let Err(original) = original.close_original_resources_retaining() {
            original.close_remaining().retain_until_process_exit();
        }
    }
}
