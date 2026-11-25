//! Bounded first-owning readonly Journal; no WAL, migration or CREATE.
use crate::{
    Journal, JournalError, NodeInspectionBounds, Result,
    original_readonly_close::JournalConnectionOwner,
};
use std::path::{Path, PathBuf};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, OriginalReadonlySqliteConnection,
    OriginalReadonlySqliteOpenFailure, OriginalSqliteMainHandoff, ReleasedOriginalCoordinationFile,
    ReleasedOriginalFileIdentity, ReleasedOriginalReadFile, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

struct OriginalReadonlyPreparation {
    connection: Option<JournalConnectionOwner>,
    failed_open: Option<OriginalReadonlySqliteOpenFailure>,
    protected: Option<ReleasedOriginalReadFile>,
    failed_observer: Option<ReleasedOriginalFileIdentity>,
    original: Option<ReleasedOriginalFileIdentity>,
    path: PathBuf,
    bounds: NodeInspectionBounds,
}

struct OriginalReadonlyFailedPreparation {
    preparation: Option<OriginalReadonlyPreparation>,
    journal: Option<Journal>,
    journal_failure: Option<crate::OriginalReadonlyJournalCloseFailure>,
    main: Option<OriginalSqliteMainHandoff>,
    sentinel: Option<ReleasedOriginalCoordinationFile>,
    native_failure: Option<WindowsOriginalResourceCloseFailure>,
    already_closed: Vec<ClosedWindowsOriginalResources>,
}

/// The same first preparation, callback owner, protected identity and enclosing
/// handoff inputs. Only resource ending remains available after this failure.
pub struct OriginalReadonlyJournalOpenFailure {
    pub error: JournalError,
    original: Option<Box<OriginalReadonlyFailedPreparation>>,
}

impl std::fmt::Debug for OriginalReadonlyJournalOpenFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalReadonlyJournalOpenFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalReadonlyPreparation {
    fn has_retained_originals(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(JournalConnectionOwner::has_retained_originals)
            || self
                .failed_open
                .as_ref()
                .is_some_and(OriginalReadonlySqliteOpenFailure::has_retained_originals)
            || self.protected.is_some()
            || self.failed_observer.is_some()
            || self.original.is_some()
    }

    fn close_native_into_attempt(&mut self, terminal: &mut WindowsOriginalCloseAttempt) -> bool {
        if let Some(original) = self.failed_open.take() {
            self.failed_open = Some(original.close_remaining());
        }
        if self
            .failed_open
            .as_ref()
            .is_some_and(OriginalReadonlySqliteOpenFailure::has_retained_originals)
        {
            return false;
        }
        if let Some(connection) = self.connection.as_mut() {
            match connection.close_original_readonly_into_attempt(terminal) {
                Ok(true) => (),
                Ok(false) => return false,
                Err(error) => {
                    terminal.note_error(std::io::Error::other(error.to_string()));
                    if connection.has_retained_originals() {
                        return false;
                    }
                }
            }
            self.connection.take();
        }
        !terminal.has_retained_originals()
    }

    fn close_protection_into_attempt(&mut self, terminal: &mut WindowsOriginalCloseAttempt) {
        if let Some(protected) = self.protected.take() {
            protected.close_into_attempt(terminal);
        }
        if let Some(original) = self.failed_observer.take() {
            original.close_into_attempt(terminal);
        }
        if let Some(original) = self.original.take() {
            original.close_into_attempt(terminal);
        }
        // The first bounded context and failed-open prefixes stay with the
        // recorded first failure after their actual resources have ended.
        let _ = (&self.path, &self.bounds, &self.failed_open);
    }
}

impl OriginalReadonlyFailedPreparation {
    fn has_retained_originals(&self) -> bool {
        self.preparation
            .as_ref()
            .is_some_and(OriginalReadonlyPreparation::has_retained_originals)
            || self.journal.is_some()
            || self
                .journal_failure
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
            || self.main.is_some()
            || self.sentinel.is_some()
            || self
                .native_failure
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    fn close_remaining(&mut self, first_error: &JournalError) {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        terminal.note_error(std::io::Error::other(first_error.to_string()));
        for closed in self.already_closed.drain(..) {
            terminal.append_result(Ok(closed));
        }
        if let Some(original) = self.native_failure.take() {
            terminal.append_failure(original.close_remaining());
        }
        if let Some(journal) = self.journal.take() {
            match journal.close_original_readonly_resources_retaining() {
                Ok(closed) => terminal.append_result(Ok(closed)),
                Err(original) => self.journal_failure = Some(original),
            }
        } else if let Some(original) = self.journal_failure.take() {
            self.journal_failure = Some(original.close_remaining());
        }
        let journal_retained = self
            .journal_failure
            .as_ref()
            .is_some_and(|original| original.has_retained_originals());
        let preparation_closed = if journal_retained {
            false
        } else if let Some(preparation) = self.preparation.as_mut() {
            preparation.close_native_into_attempt(&mut terminal)
        } else {
            !terminal.has_retained_originals()
        };
        if preparation_closed {
            if let Some(preparation) = self.preparation.as_mut() {
                preparation.close_protection_into_attempt(&mut terminal);
            }
            if let Some(original) = self.sentinel.take() {
                original.close_into_attempt(&mut terminal);
            }
            if let Some(original) = self.main.take() {
                original.close_into_attempt(&mut terminal);
            }
        }
        match terminal.finish() {
            Ok(closed) => self.already_closed.push(closed),
            Err(original) => self.native_failure = Some(original),
        }
    }
}

impl OriginalReadonlyJournalOpenFailure {
    fn from_preparation(preparation: OriginalReadonlyPreparation, error: JournalError) -> Self {
        let mut failed = Self::before_native(error);
        failed
            .original
            .as_mut()
            .expect("first failed preparation retained")
            .preparation = Some(preparation);
        failed
    }

    pub(crate) fn before_native(error: JournalError) -> Self {
        Self {
            error,
            original: Some(Box::new(OriginalReadonlyFailedPreparation {
                preparation: None,
                journal: None,
                journal_failure: None,
                main: None,
                sentinel: None,
                native_failure: None,
                already_closed: Vec::new(),
            })),
        }
    }

    pub(crate) fn from_failed_journal(journal: Journal, error: JournalError) -> Self {
        let mut failed = Self::before_native(error);
        failed
            .original
            .as_mut()
            .expect("first failed Journal retained")
            .journal = Some(journal);
        failed
    }

    pub(crate) fn retain_main(mut self, main: OriginalSqliteMainHandoff) -> Self {
        self.original
            .as_mut()
            .expect("first failed handoff retained")
            .main = Some(main);
        self
    }

    pub(crate) fn retain_sentinel(mut self, sentinel: ReleasedOriginalCoordinationFile) -> Self {
        self.original
            .as_mut()
            .expect("first failed coordination preparation retained")
            .sentinel = Some(sentinel);
        self
    }

    pub fn has_retained_originals(&self) -> bool {
        self.original
            .as_ref()
            .is_some_and(|original| original.has_retained_originals())
    }

    /// End the same resources only. The original first preparation error
    /// remains a failure even after every actual native resource has ended.
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.as_mut() {
            original.close_remaining(&self.error);
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> JournalError {
        let error = JournalError::Io(std::io::Error::other(self.error.to_string()));
        let original = self.close_remaining();
        if original.has_retained_originals() {
            original.retain_until_process_exit();
        }
        error
    }
}

impl Drop for OriginalReadonlyJournalOpenFailure {
    fn drop(&mut self) {
        if self.has_retained_originals() {
            if let Some(original) = self.original.take() {
                let _ = Box::leak(original);
            }
        }
    }
}

impl Journal {
    pub fn reopen_original_readonly_image(
        path: &Path,
        bounds: NodeInspectionBounds,
        original: ReleasedOriginalFileIdentity,
    ) -> std::result::Result<Self, OriginalReadonlyJournalOpenFailure> {
        let mut preparation = OriginalReadonlyPreparation {
            connection: None,
            failed_open: None,
            protected: None,
            failed_observer: None,
            original: Some(original),
            path: path.to_owned(),
            bounds,
        };
        let open = (|| -> Result<Self> {
            let original = preparation
                .original
                .as_ref()
                .expect("same original identity retained");
            original.verify()?;
            if !path.is_absolute() || !original.matches_path(path)? {
                return Err(JournalError::Invariant(
                    "readonly original Journal slot changed before open",
                ));
            }
            for suffix in ["-journal", "-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_owned();
                sidecar.push(suffix);
                match std::fs::symlink_metadata(Path::new(&sidecar)) {
                    Ok(_) => {
                        return Err(JournalError::Invariant(
                            "readonly original standalone Journal sidecar occupied",
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
            }
            let observer = original.retain_identity_observer()?;
            preparation.protected = Some(match observer.retain_read_after_creation() {
                Ok(protected) => protected,
                Err((observer, error)) => {
                    preparation.failed_observer = Some(observer);
                    return Err(error.into());
                }
            });
            let protected = preparation
                .protected
                .as_ref()
                .expect("original protection retained");
            protected.verify_identity()?;
            let original_bytes = protected.reader().metadata()?.len();
            if !(512..=256 * 1024 * 1024).contains(&original_bytes) {
                return Err(JournalError::Invariant(
                    "readonly original main image byte bound",
                ));
            }
            let connection = match OriginalReadonlySqliteConnection::open_original_main_retaining(
                path,
                original.key()?,
                original_bytes,
            ) {
                Ok(connection) => connection,
                Err(failed) => {
                    let error = JournalError::Io(std::io::Error::other(failed.error.to_string()));
                    preparation.failed_open = Some(failed);
                    return Err(error);
                }
            };
            preparation.connection =
                Some(JournalConnectionOwner::from_original_readonly(connection));
            let connection = preparation
                .connection
                .as_mut()
                .expect("first same-owner original DB retained");
            connection.verify_original_readonly()?;
            if sync_extend_platform_fs::sqlite_main_file_identity(connection)? != original.key()?
                || !original.matches_path(path)?
            {
                return Err(JournalError::Invariant(
                    "readonly SQLite opened foreign original main object",
                ));
            }
            bounds.configure_original_connection(connection)?;
            let database_path = std::fs::canonicalize(path)?;
            let connection = preparation
                .connection
                .take()
                .expect("prepared original DB owner");
            let mut journal = match Self::from_original_planning_connection_owner_retaining(
                connection,
                &database_path,
                bounds.max_entries,
            ) {
                Ok(journal) => journal,
                Err((connection, error)) => {
                    preparation.connection = Some(connection);
                    return Err(error);
                }
            };
            // All fallible SQL and identity work ended before this transfer.
            journal.original_read_protection = preparation.protected.take();
            journal.original_restored_image = preparation.original.take();
            Ok(journal)
        })();
        open.map_err(|error| {
            OriginalReadonlyJournalOpenFailure::from_preparation(preparation, error)
        })
    }
}
