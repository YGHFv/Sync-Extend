//! Keep the entire original Journal until its same DB, owning builtin IO,
//! callback states, protected readers, identities, and CAS parents actually end.
use crate::{Journal, JournalError};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{io, ops::Deref, path::Path};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, OriginalReadonlySqliteConnection, OriginalSqliteMainHandoff,
    ReleasedOriginalCoordinationFile, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

/// A private owning slot for the same actual connection. Only a terminal
/// failure keeps an empty slot; no substitute memory DB or native open exists.
pub(crate) struct JournalConnectionOwner {
    original: JournalConnectionKind,
    inspection_budget: Option<crate::original_observation_budget::OriginalObservationBudget>,
    observation_terminal: crate::original_observation_terminal::OriginalObservationTerminal,
}

enum JournalConnectionKind {
    Ordinary(Option<Connection>),
    Readonly(OriginalReadonlySqliteConnection),
}

impl From<Connection> for JournalConnectionOwner {
    fn from(original: Connection) -> Self {
        Self {
            original: JournalConnectionKind::Ordinary(Some(original)),
            inspection_budget: None,
            observation_terminal: Default::default(),
        }
    }
}

impl JournalConnectionOwner {
    pub(crate) fn is_present(&self) -> bool {
        self.original_ref().is_some()
    }

    pub(crate) fn original_ref(&self) -> Option<&Connection> {
        match &self.original {
            JournalConnectionKind::Ordinary(original) => original.as_ref(),
            JournalConnectionKind::Readonly(original) => original.connection(),
        }
    }

    pub(crate) fn from_original_readonly(original: OriginalReadonlySqliteConnection) -> Self {
        Self {
            original: JournalConnectionKind::Readonly(original),
            inspection_budget: None,
            observation_terminal: Default::default(),
        }
    }

    pub(crate) fn is_original_readonly(&self) -> bool {
        matches!(self.original, JournalConnectionKind::Readonly(_))
    }

    pub(crate) fn verify_original_readonly(&self) -> Result<(), JournalError> {
        match &self.original {
            JournalConnectionKind::Readonly(original) => original
                .verify_original_connection()
                .map_err(JournalError::from),
            JournalConnectionKind::Ordinary(_) => Err(JournalError::Invariant(
                "same opaque original readonly connection owner required",
            )),
        }
    }

    pub(crate) fn has_retained_originals(&self) -> bool {
        if self.observation_terminal.has_retained_originals() {
            return true;
        }
        match &self.original {
            JournalConnectionKind::Ordinary(original) => original.is_some(),
            JournalConnectionKind::Readonly(original) => original.has_retained_originals(),
        }
    }

    pub(crate) fn close_original_readonly_into_attempt(
        &mut self,
        terminal: &mut WindowsOriginalCloseAttempt,
    ) -> Result<bool, JournalError> {
        self.observation_terminal.append_to(terminal);
        match &mut self.original {
            JournalConnectionKind::Readonly(original) => original
                .close_original_resources_into_attempt(terminal)
                .map_err(JournalError::from),
            JournalConnectionKind::Ordinary(_) => Err(JournalError::Invariant(
                "full original readonly terminal requires its same opaque pair",
            )),
        }
    }

    /// No mutable Connection reference can escape this controlled operation.
    pub(crate) fn progress_handler<F>(
        &mut self,
        num_ops: i32,
        handler: Option<F>,
    ) -> rusqlite::Result<()>
    where
        F: FnMut() -> bool + Send + 'static,
    {
        // Any other hook invalidates this typed observation entry point.
        self.inspection_budget = None;
        match &mut self.original {
            JournalConnectionKind::Ordinary(original) => original
                .as_mut()
                .ok_or(rusqlite::Error::InvalidQuery)?
                .progress_handler(num_ops, handler),
            JournalConnectionKind::Readonly(original) => {
                original.progress_handler(num_ops, handler)
            }
        }
    }

    pub(crate) fn install_inspection_budget(
        &mut self,
        bounds: crate::NodeInspectionBounds,
    ) -> rusqlite::Result<()> {
        let budget = crate::original_observation_budget::OriginalObservationBudget::new(bounds);
        let callback = budget.clone();
        self.progress_handler(1_000, Some(move || callback.interrupt()))?;
        self.inspection_budget = Some(budget);
        Ok(())
    }

    pub(crate) fn begin_original_observation(
        &mut self,
    ) -> crate::Result<crate::original_observation_budget::OriginalObservationScope> {
        self.observation_terminal.require_available()?;
        if !self.is_original_readonly() || !self.is_present() || !self.is_autocommit() {
            return Err(JournalError::Invariant(
                "bounded observation requires the same idle original readonly connection",
            ));
        }
        self.inspection_budget
            .as_ref()
            .ok_or(JournalError::Invariant(
                "original observation requires its installed inspection budget",
            ))?
            .begin()
    }

    pub(crate) fn original_observation_terminal(
        &self,
    ) -> crate::original_observation_terminal::OriginalObservationTerminal {
        self.observation_terminal.clone()
    }

    pub(crate) fn transaction(&mut self) -> rusqlite::Result<Transaction<'_>> {
        match &mut self.original {
            JournalConnectionKind::Ordinary(original) => original
                .as_mut()
                .ok_or(rusqlite::Error::InvalidQuery)?
                .transaction(),
            JournalConnectionKind::Readonly(original) => original.transaction(),
        }
    }

    pub(crate) fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> rusqlite::Result<Transaction<'_>> {
        match &mut self.original {
            JournalConnectionKind::Ordinary(original) => original
                .as_mut()
                .ok_or(rusqlite::Error::InvalidQuery)?
                .transaction_with_behavior(behavior),
            JournalConnectionKind::Readonly(original) => {
                original.transaction_with_behavior(behavior)
            }
        }
    }

    pub(crate) fn take_original(&mut self) -> Option<Connection> {
        match &mut self.original {
            JournalConnectionKind::Ordinary(original) => original.take(),
            JournalConnectionKind::Readonly(_) => None,
        }
    }

    pub(crate) fn restore_original(&mut self, original: Connection) -> Result<(), Connection> {
        match &mut self.original {
            JournalConnectionKind::Ordinary(slot) if slot.is_none() => {
                *slot = Some(original);
                Ok(())
            }
            _ => Err(original),
        }
    }

    pub(crate) fn into_original(mut self) -> Result<Connection, Self> {
        match self.take_original() {
            Some(original) => Ok(original),
            None => Err(self),
        }
    }

    pub(crate) fn close(mut self) -> Result<(), (Self, rusqlite::Error)> {
        let Some(original) = self.take_original() else {
            return Err((self, rusqlite::Error::InvalidQuery));
        };
        match original.close() {
            Ok(()) => Ok(()),
            Err((original, error)) => {
                self.original = JournalConnectionKind::Ordinary(Some(original));
                Err((self, error))
            }
        }
    }
}

impl Deref for JournalConnectionOwner {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.original_ref()
            .expect("active Journal retains its same original connection")
    }
}

impl Drop for JournalConnectionOwner {
    fn drop(&mut self) {
        // Empty terminal keepers never dereference a connection. This fallback
        // attempts an actual close and retains the same owner on refusal.
        if let JournalConnectionKind::Ordinary(original) = &mut self.original {
            if let Some(original) = original.take() {
                if let Err((original, error)) = original.close() {
                    let _ = Box::leak(Box::new((original, error)));
                }
            }
        }
        // A readonly variant's Drop keeps its DB/native/context together and
        // attempts the same full terminal. It never splits the original pair.
    }
}

pub struct OriginalReadonlyJournalCloseFailure {
    pub error: JournalError,
    pub actual_closed_handles: usize,
    original: Option<Journal>,
    original_resource_terminal: Option<WindowsOriginalResourceCloseFailure>,
    original_io_terminal: bool,
}

/// The dedicated continuation after the original readonly reader has ended.
/// Its whole retired Journal is private: the empty connection owner cannot
/// enter an ordinary SQL API. CREATE capabilities, restored-image identities,
/// and callback gates stay in this exact scope until its consuming terminal.
pub struct OriginalReadonlyJournalWriteHandoff {
    original: Option<Journal>,
    original_reader_terminal: Option<ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for OriginalReadonlyJournalWriteHandoff {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalReadonlyJournalWriteHandoff")
            .field("original_context_retained", &self.original.is_some())
            .finish()
    }
}

impl std::fmt::Debug for OriginalReadonlyJournalCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalReadonlyJournalCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field("originals_retained", &self.has_retained_originals())
            .finish()
    }
}

fn error_copy(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

fn journal_error_for_terminal(error: &JournalError) -> io::Error {
    match error {
        JournalError::Io(error) => error_copy(error),
        _ => io::Error::other(error.to_string()),
    }
}

impl Journal {
    fn end_original_readonly_reader(
        &mut self,
        terminal: &mut WindowsOriginalCloseAttempt,
        original_io_terminal: &mut bool,
    ) -> Result<bool, JournalError> {
        if !*original_io_terminal {
            let complete = self
                .connection
                .close_original_readonly_into_attempt(terminal)?;
            if !complete || self.connection.has_retained_originals() {
                return Ok(false);
            }
            *original_io_terminal = true;
        }
        // No pager or native callback can use these fields after the actual
        // connection and its same owning IO have both reached their terminal.
        if let Some(original) = self.original_read_protection.take() {
            original.close_into_attempt(terminal);
        }
        for (_, original) in std::mem::take(&mut self.original_stopped_capture_files) {
            original.close_into_attempt(terminal);
        }
        if !terminal.has_retained_originals() {
            self.original_stopped_capture_absent.clear();
        }
        Ok(!terminal.has_retained_originals())
    }

    fn end_original_readonly_resources(
        &mut self,
        terminal: &mut WindowsOriginalCloseAttempt,
        original_io_terminal: &mut bool,
    ) -> Result<bool, JournalError> {
        let reader_complete = self.end_original_readonly_reader(terminal, original_io_terminal)?;
        if !*original_io_terminal {
            return Ok(false);
        }
        // The pager and its same native IO ended before these independent
        // original identity resources can be relinquished. A failed protected
        // reader close remains in the same terminal aggregate.
        if let Some(original) = self.original_main_handoff.take() {
            original.close_into_attempt(terminal);
        }
        if let Some(original) = self.original_restored_image.take() {
            original.close_into_attempt(terminal);
        }
        if let Some(original) = self.original_cas_coordination.take() {
            original.close_into_attempt(terminal);
        }
        self.original_coordination_observer = false;
        Ok(reader_complete && !terminal.has_retained_originals())
    }

    /// Consume the full readonly Journal, preserving all of it until its
    /// same actual SQLite DB and owning IO are closed. This grants no restart.
    pub fn close_original_readonly_resources_retaining(
        mut self,
    ) -> Result<ClosedWindowsOriginalResources, OriginalReadonlyJournalCloseFailure> {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        let mut original_io_terminal = false;
        let complete =
            match self.end_original_readonly_resources(&mut terminal, &mut original_io_terminal) {
                Ok(complete) => complete,
                Err(error) => {
                    return Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                        Some(self),
                        error,
                        terminal,
                        original_io_terminal,
                    ));
                }
            };
        match terminal.finish() {
            Ok(closed) if complete => Ok(closed),
            Ok(closed) => {
                let mut terminal = WindowsOriginalCloseAttempt::new();
                terminal.append_result(Ok(closed));
                Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                    Some(self),
                    JournalError::Invariant(
                        "original readonly Journal native terminal remains incomplete",
                    ),
                    terminal,
                    original_io_terminal,
                ))
            }
            Err(original_resources) => {
                let error = JournalError::from(error_copy(&original_resources.error));
                let actual_closed_handles = original_resources.actual_closed_handles;
                Err(OriginalReadonlyJournalCloseFailure {
                    error,
                    actual_closed_handles,
                    original: (!complete).then_some(self),
                    original_resource_terminal: Some(original_resources),
                    original_io_terminal,
                })
            }
        }
    }

    /// End the same original readonly DB, its first owning IO, and the
    /// protected read HANDLE while retaining the original CREATE-issued
    /// main, restored-image identity, CAS sentinel, and whole callback scope.
    /// This opaque continuation grants no ordinary Journal or SQL access.
    pub(crate) fn end_original_readonly_for_write_retaining(
        mut self,
    ) -> Result<OriginalReadonlyJournalWriteHandoff, OriginalReadonlyJournalCloseFailure> {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        let mut original_io_terminal = false;
        if self.original_main_handoff.is_none()
            || self.original_cas_coordination.is_none()
            || !self.connection.is_present()
        {
            return Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                Some(self),
                JournalError::Invariant(
                    "original readonly writer handoff requires its same live DB and CREATE capabilities",
                ),
                terminal,
                original_io_terminal,
            ));
        }
        let complete =
            match self.end_original_readonly_reader(&mut terminal, &mut original_io_terminal) {
                Ok(complete) => complete,
                Err(error) => {
                    return Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                        Some(self),
                        error,
                        terminal,
                        original_io_terminal,
                    ));
                }
            };
        match terminal.finish() {
            Ok(closed) if complete => Ok(OriginalReadonlyJournalWriteHandoff {
                original: Some(self),
                original_reader_terminal: Some(closed),
            }),
            Ok(closed) => {
                let mut terminal = WindowsOriginalCloseAttempt::new();
                terminal.append_result(Ok(closed));
                Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                    Some(self),
                    JournalError::Invariant(
                        "original readonly writer handoff native terminal remains incomplete",
                    ),
                    terminal,
                    original_io_terminal,
                ))
            }
            Err(original_resources) => Err(OriginalReadonlyJournalCloseFailure {
                error: JournalError::from(error_copy(&original_resources.error)),
                actual_closed_handles: original_resources.actual_closed_handles,
                original: Some(self),
                original_resource_terminal: Some(original_resources),
                original_io_terminal,
            }),
        }
    }
}

impl OriginalReadonlyJournalCloseFailure {
    fn from_attempt(
        original: Option<Journal>,
        error: JournalError,
        mut terminal: WindowsOriginalCloseAttempt,
        original_io_terminal: bool,
    ) -> Self {
        terminal.note_error(journal_error_for_terminal(&error));
        let original_resources = match terminal.finish() {
            Err(original_resources) => original_resources,
            Ok(_) => unreachable!("the original terminal error remains recorded"),
        };
        Self {
            error,
            actual_closed_handles: original_resources.actual_closed_handles,
            original,
            original_resource_terminal: Some(original_resources),
            original_io_terminal,
        }
    }

    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self
                .original_resource_terminal
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    /// Retry resource ending only. The initial failure always survives, and an
    /// empty terminal keeper never enters a Journal SQL API or Deref.
    pub fn close_remaining(mut self) -> Self {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        terminal.note_error(journal_error_for_terminal(&self.error));
        if let Some(original) = self.original_resource_terminal.take() {
            terminal.append_failure(original.close_remaining());
        }
        if let Some(original) = self.original.as_mut() {
            match original
                .end_original_readonly_resources(&mut terminal, &mut self.original_io_terminal)
            {
                Ok(true) => {
                    self.original.take();
                }
                Ok(false) => (),
                Err(error) => terminal.note_error(journal_error_for_terminal(&error)),
            }
        }
        match terminal.finish() {
            Err(original_resources) => {
                self.actual_closed_handles = original_resources.actual_closed_handles;
                self.original_resource_terminal = Some(original_resources);
            }
            Ok(_) => unreachable!("the first original readonly close error remains recorded"),
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl OriginalReadonlyJournalWriteHandoff {
    pub(crate) fn path(&self) -> &Path {
        &self
            .original
            .as_ref()
            .expect("dedicated original readonly handoff context retained")
            .database_path
    }

    pub(crate) fn max_storage_entries(&self) -> usize {
        self.original
            .as_ref()
            .expect("dedicated original readonly handoff context retained")
            .max_storage_entries
    }

    /// Transfer only the existing linear capabilities to the dedicated writer
    /// adapter. The same retired Journal and its restored-image identity stay
    /// in this opaque scope throughout acquisition and subsequent failures.
    pub(crate) fn take_original_write_inputs(
        &mut self,
    ) -> Result<(OriginalSqliteMainHandoff, ReleasedOriginalCoordinationFile), JournalError> {
        let original = self.original.as_mut().ok_or(JournalError::Invariant(
            "dedicated original readonly writer handoff context absent",
        ))?;
        if original.original_main_handoff.is_none() || original.original_cas_coordination.is_none()
        {
            return Err(JournalError::Invariant(
                "original readonly writer handoff capabilities already transferred",
            ));
        }
        let main = original
            .original_main_handoff
            .take()
            .expect("original main checked before linear transfer");
        let cas = original
            .original_cas_coordination
            .take()
            .expect("original CAS checked before linear transfer");
        Ok((main, cas))
    }

    /// End the same remaining context after its writer's original native
    /// owner ends. This exposes resource ending only, with no SQL or restart.
    pub fn close_original_resources_retaining(
        mut self,
    ) -> Result<ClosedWindowsOriginalResources, OriginalReadonlyJournalCloseFailure> {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        if let Some(closed) = self.original_reader_terminal.take() {
            terminal.append_result(Ok(closed));
        }
        let Some(mut original) = self.original.take() else {
            return Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                None,
                JournalError::Invariant("original readonly handoff was already consumed"),
                terminal,
                true,
            ));
        };
        let mut original_io_terminal = true;
        let complete = match original
            .end_original_readonly_resources(&mut terminal, &mut original_io_terminal)
        {
            Ok(complete) => complete,
            Err(error) => {
                return Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                    Some(original),
                    error,
                    terminal,
                    original_io_terminal,
                ));
            }
        };
        match terminal.finish() {
            Ok(closed) if complete => Ok(closed),
            Ok(closed) => {
                let mut terminal = WindowsOriginalCloseAttempt::new();
                terminal.append_result(Ok(closed));
                Err(OriginalReadonlyJournalCloseFailure::from_attempt(
                    Some(original),
                    JournalError::Invariant(
                        "original readonly handoff context terminal remains incomplete",
                    ),
                    terminal,
                    original_io_terminal,
                ))
            }
            Err(original_resources) => Err(OriginalReadonlyJournalCloseFailure {
                error: JournalError::from(error_copy(&original_resources.error)),
                actual_closed_handles: original_resources.actual_closed_handles,
                original: (!complete).then_some(original),
                original_resource_terminal: Some(original_resources),
                original_io_terminal,
            }),
        }
    }
}

impl Drop for OriginalReadonlyJournalWriteHandoff {
    fn drop(&mut self) {
        // Unexpected scope exit never drops a whole retired Journal's native
        // gates or identities separately. It attempts the same full terminal
        // and retains the exact failure owner when anything refuses.
        if self.original.is_none() {
            return;
        }
        let original = Self {
            original: self.original.take(),
            original_reader_terminal: self.original_reader_terminal.take(),
        };
        if let Err(original) = original.close_original_resources_retaining() {
            original.close_remaining().retain_until_process_exit();
        }
    }
}
