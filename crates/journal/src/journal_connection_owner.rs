//! Shared same-connection owning slot; no replacement DB or pathname reopen.
use crate::JournalError;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::ops::Deref;
#[cfg(windows)]
use sync_extend_platform_fs::{OriginalReadonlySqliteConnection, WindowsOriginalCloseAttempt};

/// A private owning slot for the same actual connection. Only a terminal
/// failure keeps an empty slot; no substitute memory DB or native open exists.
pub(crate) struct JournalConnectionOwner {
    original: JournalConnectionKind,
    inspection_budget: Option<crate::original_observation_budget::OriginalObservationBudget>,
    #[cfg(windows)]
    observation_terminal: crate::original_observation_terminal::OriginalObservationTerminal,
}

enum JournalConnectionKind {
    Ordinary(Option<Connection>),
    #[cfg(windows)]
    Readonly(OriginalReadonlySqliteConnection),
}

impl From<Connection> for JournalConnectionOwner {
    fn from(original: Connection) -> Self {
        Self {
            original: JournalConnectionKind::Ordinary(Some(original)),
            inspection_budget: None,
            #[cfg(windows)]
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
            #[cfg(windows)]
            JournalConnectionKind::Readonly(original) => original.connection(),
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_original_readonly(original: OriginalReadonlySqliteConnection) -> Self {
        Self {
            original: JournalConnectionKind::Readonly(original),
            inspection_budget: None,
            #[cfg(windows)]
            observation_terminal: Default::default(),
        }
    }

    #[cfg(windows)]
    pub(crate) fn is_original_readonly(&self) -> bool {
        matches!(self.original, JournalConnectionKind::Readonly(_))
    }

    #[cfg(windows)]
    pub(crate) fn verify_original_readonly(&self) -> Result<(), JournalError> {
        match &self.original {
            #[cfg(windows)]
            JournalConnectionKind::Readonly(original) => original
                .verify_original_connection()
                .map_err(JournalError::from),
            JournalConnectionKind::Ordinary(_) => Err(JournalError::Invariant(
                "same opaque original readonly connection owner required",
            )),
        }
    }

    pub(crate) fn has_retained_originals(&self) -> bool {
        #[cfg(windows)]
        if self.observation_terminal.has_retained_originals() {
            return true;
        }
        match &self.original {
            JournalConnectionKind::Ordinary(original) => original.is_some(),
            #[cfg(windows)]
            JournalConnectionKind::Readonly(original) => original.has_retained_originals(),
        }
    }

    #[cfg(windows)]
    pub(crate) fn close_original_readonly_into_attempt(
        &mut self,
        terminal: &mut WindowsOriginalCloseAttempt,
    ) -> Result<bool, JournalError> {
        self.observation_terminal.append_to(terminal);
        match &mut self.original {
            #[cfg(windows)]
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
            #[cfg(windows)]
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

    #[cfg(windows)]
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

    #[cfg(windows)]
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
            #[cfg(windows)]
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
            #[cfg(windows)]
            JournalConnectionKind::Readonly(original) => {
                original.transaction_with_behavior(behavior)
            }
        }
    }

    pub(crate) fn take_original(&mut self) -> Option<Connection> {
        match &mut self.original {
            JournalConnectionKind::Ordinary(original) => original.take(),
            #[cfg(windows)]
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
