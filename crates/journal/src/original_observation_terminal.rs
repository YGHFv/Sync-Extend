//! Rejected CAS guards end inside the same readonly connection's terminal.
use crate::{JournalError, Result};
use std::sync::{Arc, Mutex};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

#[derive(Clone, Default)]
pub(crate) struct OriginalObservationTerminal {
    state: Arc<Mutex<TerminalState>>,
}

#[derive(Default)]
struct TerminalState {
    terminal: WindowsOriginalCloseAttempt,
    failed: bool,
}

impl OriginalObservationTerminal {
    pub(crate) fn require_available(&self) -> Result<()> {
        let state = self.state.lock().map_err(|_| {
            JournalError::Invariant("original observation resource terminal was poisoned")
        })?;
        if state.failed {
            return Err(JournalError::Invariant(
                "original observation resource terminal already failed",
            ));
        }
        Ok(())
    }

    pub(crate) fn record(
        &self,
        terminal: std::result::Result<
            ClosedWindowsOriginalResources,
            WindowsOriginalResourceCloseFailure,
        >,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.failed = true;
            state.terminal.note_error(std::io::Error::other(
                "original observation resource terminal was poisoned",
            ));
            state
        });
        state.failed |= terminal.is_err();
        state.terminal.append_result(terminal);
    }

    pub(crate) fn has_retained_originals(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.terminal.has_retained_originals())
    }

    pub(crate) fn append_to(&self, terminal: &mut WindowsOriginalCloseAttempt) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.failed = true;
            state.terminal.note_error(std::io::Error::other(
                "original observation resource terminal was poisoned",
            ));
            state
        });
        terminal.append_result(std::mem::take(&mut state.terminal).finish());
        if state.failed {
            terminal.note_error(std::io::Error::other(
                "original observation resource terminal previously failed",
            ));
        }
    }
}

impl Drop for TerminalState {
    fn drop(&mut self) {
        // The explicit owner terminal drains this state. Unexpected owner Drop
        // still preserves any same HANDLEs and never certifies a close.
        if let Err(original) = std::mem::take(&mut self.terminal).finish() {
            original.retain_until_process_exit();
        }
    }
}
