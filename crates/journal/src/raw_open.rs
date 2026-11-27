//! The single audited SQLite handle ownership transfer for original native IO.
//!
//! Callers retain their platform IO owner and its one-use opening scope across
//! this call. They must close this connection (including a rejected partial
//! open) before releasing that same IO owner. No raw handle leaves this module.
use rusqlite::{Connection, ffi};
use std::{ffi::CStr, io, ptr};

pub(crate) struct OriginalSqliteOpenFailure {
    pub(crate) error: io::Error,
    pub(crate) original: Option<OriginalSqliteOpening>,
}

/// Only the actual nonnull database returned by sqlite3_open_v2 creates this
/// owner. Failure to close preserves it for another terminal attempt.
pub(crate) struct OriginalSqliteOpening {
    database: Option<std::ptr::NonNull<ffi::sqlite3>>,
}

impl OriginalSqliteOpening {
    pub(crate) fn is_open(&self) -> bool {
        self.database.is_some()
    }

    pub(crate) fn close_original(&mut self) -> io::Result<()> {
        let Some(database) = self.database else {
            return Ok(());
        };
        // SAFETY: this is the uniquely owned, untransferred original partial
        // database. The caller still owns every registered callback dependency.
        let result = unsafe { ffi::sqlite3_close(database.as_ptr()) };
        if result != ffi::SQLITE_OK {
            return Err(original_error(database.as_ptr(), result));
        }
        self.database = None;
        Ok(())
    }
}

fn original_error(database: *mut ffi::sqlite3, code: i32) -> io::Error {
    if database.is_null() {
        return io::Error::other(format!(
            "original SQLite open returned {code} without a database"
        ));
    }
    // SAFETY: only this module calls this function, with its still-owned live
    // database. Failed SQLite open/close retains a valid error string.
    let message = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(database)) }
        .to_string_lossy()
        .into_owned();
    io::Error::other(rusqlite::Error::SqliteFailure(
        ffi::Error::new(code),
        Some(message),
    ))
}

pub(crate) fn open_retaining(
    path: &CStr,
    vfs: &CStr,
) -> Result<Connection, OriginalSqliteOpenFailure> {
    let mut database = ptr::null_mut();
    // SAFETY: terminated names are live for this call. The caller retains its
    // original platform VFS and one-use opening scope. No CREATE/default VFS or
    // pathname fallback is enabled. Any returned nonnull database stays owned.
    let result = unsafe {
        ffi::sqlite3_open_v2(
            path.as_ptr(),
            &mut database,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_NOMUTEX,
            vfs.as_ptr(),
        )
    };
    let original = std::ptr::NonNull::new(database)
        .map(|database| OriginalSqliteOpening { database: Some(database) });
    if result != ffi::SQLITE_OK || original.is_none() {
        return Err(OriginalSqliteOpenFailure {
            error: original_error(database, result),
            original,
        });
    }
    // SAFETY: this is the unique successful database from the call above. The
    // rusqlite constructor performs no reopen and receives ownership once.
    match unsafe { Connection::from_handle_owned(database) } {
        Ok(connection) => Ok(connection),
        Err(error) => Err(OriginalSqliteOpenFailure {
            error: io::Error::other(error),
            original,
        }),
    }
}
