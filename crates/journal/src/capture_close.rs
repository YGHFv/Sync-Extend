//! Consuming actual SQLite close for an ordinary stopped capture connection.
use crate::{Journal, JournalError};

/// Created only after the actual ordinary capture connection closes. This
/// witness says nothing about a native owner's files, locks, or permissions.
pub struct ClosedJournalCaptureConnection {
    _private: (),
    #[cfg(windows)]
    _original_native: Option<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
}

#[cfg(windows)]
pub struct CasCaptureCloseFailure {
    pub error: JournalError,
    pub original_native_guard: Option<crate::CasAccessGuard>,
    pub original_resources: Option<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
}

#[cfg(windows)]
impl std::fmt::Debug for CasCaptureCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("CasCaptureCloseFailure")
            .field("error", &self.error)
            .field(
                "original_native_guard_retained",
                &self.original_native_guard.is_some(),
            )
            .field(
                "original_resources_retained",
                &self.original_resources.is_some(),
            )
            .finish()
    }
}

/// The exact connection whose stopped-source preparation failed. It provides
/// only terminal close; it cannot read, write, or become a live Journal.
#[cfg(windows)]
pub struct OriginalStoppedCaptureConnection {
    connection: Option<crate::original_readonly_close::JournalConnectionOwner>,
    failed_open: Option<sync_extend_platform_fs::OriginalReadonlySqliteOpenFailure>,
    files: Vec<(std::path::PathBuf, sync_extend_platform_fs::GuardedReadFile)>,
    absent: Vec<std::path::PathBuf>,
    native_failure: Option<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
    already_closed: Vec<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
    path: std::path::PathBuf,
    max_storage_entries: usize,
    first_terminal_error: Option<JournalError>,
}

#[cfg(windows)]
impl OriginalStoppedCaptureConnection {
    pub fn close_remaining(
        mut self,
    ) -> std::result::Result<ClosedJournalCaptureConnection, (Self, JournalError)> {
        if let Some(original) = self.failed_open.take() {
            let original = original.close_remaining();
            if original.has_retained_originals() {
                let error = JournalError::Io(std::io::Error::other(original.error.to_string()));
                self.failed_open = Some(original);
                return Err((self, error));
            }
            self.failed_open = Some(original);
        }
        let mut terminal = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        for closed in self.already_closed.drain(..) {
            terminal.append_result(Ok(closed));
        }
        if let Some(original) = self.native_failure.take() {
            terminal.append_failure(original.close_remaining());
        }
        if let Some(connection) = self.connection.as_mut() {
            let error = match connection.close_original_readonly_into_attempt(&mut terminal) {
                Ok(true) => None,
                Ok(false) => Some(JournalError::Invariant(
                    "stopped capture same owning pair terminal remains incomplete",
                )),
                Err(error) => Some(error),
            };
            if let Some(error) = error {
                self.first_terminal_error.get_or_insert_with(|| {
                    JournalError::Io(std::io::Error::other(error.to_string()))
                });
                terminal.note_error(std::io::Error::other(error.to_string()));
                match terminal.finish() {
                    Ok(closed) => self.already_closed.push(closed),
                    Err(original) => self.native_failure = Some(original),
                }
                return Err((self, error));
            }
            self.connection.take();
        }
        if terminal.has_retained_originals() {
            self.native_failure = terminal.finish().err();
            return Err((
                self,
                JournalError::Invariant("stopped capture original native prefix remains"),
            ));
        }
        for (_, original) in self.files.drain(..) {
            original.close_into_attempt(&mut terminal);
        }
        match terminal.finish() {
            Ok(closed) => {
                if let Some(original) = &self.failed_open {
                    let error = JournalError::Io(std::io::Error::other(original.error.to_string()));
                    self.already_closed.push(closed);
                    return Err((self, error));
                }
                if let Some(error) = &self.first_terminal_error {
                    let error = JournalError::Io(std::io::Error::other(error.to_string()));
                    self.already_closed.push(closed);
                    return Err((self, error));
                }
                Ok(ClosedJournalCaptureConnection {
                    _private: (),
                    _original_native: Some(closed),
                })
            }
            Err(original) => {
                let error = JournalError::Io(std::io::Error::other(original.error.to_string()));
                self.native_failure = Some(original);
                Err((self, error))
            }
        }
    }

    pub fn has_retained_originals(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|original| original.has_retained_originals())
            || self
                .failed_open
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
            || !self.files.is_empty()
            || self
                .native_failure
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }
}

#[cfg(windows)]
impl Drop for OriginalStoppedCaptureConnection {
    fn drop(&mut self) {
        if self.has_retained_originals() {
            let original = (
                self.connection.take(),
                self.failed_open.take(),
                std::mem::take(&mut self.files),
                std::mem::take(&mut self.absent),
                self.native_failure.take(),
                std::mem::take(&mut self.already_closed),
                self.path.clone(),
                self.max_storage_entries,
                self.first_terminal_error.take(),
            );
            let _ = Box::leak(Box::new(original));
        }
    }
}

/// A failed open retains the first preparation error and, once SQLite has
/// opened successfully, the same original connection until its actual close.
#[cfg(windows)]
pub struct StoppedCaptureJournalOpenFailure {
    pub error: JournalError,
    pub original_connection: Option<OriginalStoppedCaptureConnection>,
    pub close_error: Option<JournalError>,
}

#[cfg(windows)]
impl StoppedCaptureJournalOpenFailure {
    fn before_open(error: JournalError) -> Self {
        Self {
            error,
            original_connection: None,
            close_error: None,
        }
    }

    fn after_open(connection: OriginalStoppedCaptureConnection, error: JournalError) -> Self {
        Self {
            error,
            original_connection: Some(connection),
            close_error: None,
        }
    }

    /// Attempt actual terminal close while preserving the original first
    /// failure. A later close failure retains the same connection for retry.
    pub fn close_remaining(mut self) -> Self {
        if let Some(connection) = self.original_connection.take() {
            if let Err((connection, error)) = connection.close_remaining() {
                self.original_connection = Some(connection);
                self.close_error.get_or_insert(error);
            }
        }
        self
    }

    pub fn has_retained_originals(&self) -> bool {
        self.original_connection
            .as_ref()
            .is_some_and(OriginalStoppedCaptureConnection::has_retained_originals)
    }
}

#[cfg(windows)]
impl std::fmt::Debug for StoppedCaptureJournalOpenFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("StoppedCaptureJournalOpenFailure")
            .field("error", &self.error)
            .field(
                "original_connection_retained",
                &self.original_connection.is_some(),
            )
            .field("close_error", &self.close_error)
            .finish()
    }
}

impl Journal {
    /// Read the existing stopped Windows source without CREATE, migrations, or
    /// a named SHM. The caller retains the original writer/root capture locks.
    /// Every ordinary CAS session also requires its sentinel to exist already.
    #[cfg(windows)]
    pub fn open_stopped_capture_existing(
        path: &std::path::Path,
        max_storage_entries: usize,
    ) -> std::result::Result<Self, StoppedCaptureJournalOpenFailure> {
        crate::storage_policy::validate(max_storage_entries)
            .map_err(StoppedCaptureJournalOpenFailure::before_open)?;
        crate::guard_journal_open_path(path)
            .map_err(StoppedCaptureJournalOpenFailure::before_open)?;
        let mut original = OriginalStoppedCaptureConnection {
            connection: None,
            failed_open: None,
            files: Vec::new(),
            absent: Vec::new(),
            native_failure: None,
            already_closed: Vec::new(),
            path: path.to_owned(),
            max_storage_entries,
            first_terminal_error: None,
        };
        let prepared = (|| -> crate::Result<std::path::PathBuf> {
            use std::io::Read;
            let main = sync_extend_platform_fs::GuardedReadFile::open(path)?;
            original.files.push((path.to_owned(), main));
            let main = &original.files[0].1;
            let expected_main = main.key()?;
            let main_bytes = main.reader().metadata()?.len();
            if !(512..=256 * 1024 * 1024).contains(&main_bytes) {
                return Err(JournalError::Invariant(
                    "stopped capture original main byte bound",
                ));
            }
            let mut existing_wal = None;
            for suffix in ["-wal", "-journal", "-shm"] {
                let mut sidecar = path.as_os_str().to_owned();
                sidecar.push(suffix);
                let sidecar = std::path::PathBuf::from(sidecar);
                match std::fs::symlink_metadata(&sidecar) {
                    Ok(_) => {
                        let held = sync_extend_platform_fs::GuardedReadFile::open(&sidecar)?;
                        original.files.push((sidecar.clone(), held));
                        let held = &original
                            .files
                            .last()
                            .expect("same capture sidecar retained")
                            .1;
                        let length = held.reader().metadata()?.len();
                        if length > 256 * 1024 * 1024 {
                            return Err(JournalError::Invariant(
                                "stopped capture sidecar byte bound",
                            ));
                        }
                        // A zero-length WAL carries no frames. Treat it like an
                        // absent WAL so a stopped source can still be opened
                        // immutably; the empty file itself stays retained.
                        if suffix == "-wal" && length != 0 {
                            existing_wal = Some((held.key()?, length));
                        }
                        if suffix == "-journal" && length != 0 {
                            let mut header = [0; 8];
                            let mut reader = held.reader();
                            if length < 8
                                || reader.read_exact(&mut header).is_err()
                                || header != [0; 8]
                            {
                                return Err(JournalError::Invariant(
                                    "stopped capture hot rollback requires original owner recovery",
                                ));
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        original.absent.push(sidecar);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let connection = match
                sync_extend_platform_fs::OriginalReadonlySqliteConnection::open_stopped_existing_retaining(
                    path, expected_main, main_bytes, existing_wal,
                )
            {
                Ok(opened) => opened,
                Err(failed) => {
                    let error = JournalError::Io(std::io::Error::other(failed.error.to_string()));
                    original.failed_open = Some(failed);
                    return Err(error);
                }
            };
            original.connection = Some(
                crate::original_readonly_close::JournalConnectionOwner::from_original_readonly(
                    connection,
                ),
            );
            let connection = original
                .connection
                .as_ref()
                .expect("same original capture DB retained");
            connection.verify_original_readonly()?;
            connection.busy_timeout(std::time::Duration::from_secs(5))?;
            connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
            connection.pragma_update(None, "temp_store", "MEMORY")?;
            connection.pragma_update(None, "mmap_size", 0)?;
            connection.pragma_update(None, "foreign_keys", true)?;
            connection.pragma_update(None, "query_only", true)?;
            crate::storage_inventory::reader::validate_schema(
                &connection,
                &crate::storage_inventory::tables(),
                crate::storage_inventory::reader::Namespace::All,
            )?;
            Ok(std::fs::canonicalize(path)?)
        })();
        let path = match prepared {
            Ok(path) => path,
            Err(error) => {
                return Err(StoppedCaptureJournalOpenFailure::after_open(
                    original, error,
                ));
            }
        };
        let connection = original
            .connection
            .take()
            .expect("prepared same original capture DB");
        let mut journal = match Self::from_original_planning_connection_owner_retaining(
            connection,
            &path,
            max_storage_entries,
        ) {
            Ok(journal) => journal,
            Err((connection, error)) => {
                original.connection = Some(connection);
                return Err(StoppedCaptureJournalOpenFailure::after_open(
                    original, error,
                ));
            }
        };
        journal.original_stopped_capture_files = std::mem::take(&mut original.files);
        journal.original_stopped_capture_absent = std::mem::take(&mut original.absent);
        journal.stopped_capture_existing_only = true;
        Ok(journal)
    }

    #[cfg(windows)]
    pub fn close_stopped_capture_resources_retaining(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        crate::OriginalReadonlyJournalCloseFailure,
    > {
        self.close_original_readonly_resources_retaining()
    }

    /// End the ordinary capture database connection while preserving the same
    /// Journal on refusal or SQLite close failure. Restored and full-FD native
    /// connections must follow their own consuming owner close protocol.
    pub fn close_capture_connection(
        self,
    ) -> std::result::Result<ClosedJournalCaptureConnection, (Self, JournalError)> {
        #[cfg(target_os = "linux")]
        if self.linux_metadata_vfs.is_some() || self.original_linux_cas_coordination.is_some() {
            return Err((
                self,
                JournalError::Invariant("capture close requires an ordinary Journal connection"),
            ));
        }
        #[cfg(windows)]
        if self.original_restored_image.is_some()
            || self.connection.is_original_readonly()
            || self.original_read_protection.is_some()
            || self.original_coordination_observer
            || self.original_main_handoff.is_some()
            || self.original_cas_coordination.is_some()
        {
            return Err((
                self,
                JournalError::Invariant("capture close requires an ordinary Journal connection"),
            ));
        }
        match self.connection.close() {
            Ok(()) => Ok(ClosedJournalCaptureConnection {
                _private: (),
                #[cfg(windows)]
                _original_native: None,
            }),
            Err((connection, error)) => {
                Err((Self { connection, ..self }, JournalError::from(error)))
            }
        }
    }
}
