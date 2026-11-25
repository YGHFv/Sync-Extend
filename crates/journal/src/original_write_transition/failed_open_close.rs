//! End every original transition-failure variant without reopening or issuing.
use super::{OriginalJournalTransitionFailure, OriginalJournalWriteTransition};
use crate::{
    Journal, JournalError, OriginalReadonlyJournalCloseFailure, OriginalReadonlyJournalWriteHandoff,
};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, OriginalSqliteMainHandoff, OriginalSqliteOpenFailure,
    OriginalSqliteResourceCloseFailure, OriginalSqliteSidecarHandoff,
    ReleasedOriginalCoordinationFile, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

enum OriginalTransitionNative {
    Read(Journal),
    Handoff(OriginalReadonlyJournalWriteHandoff),
    ReadFailure(OriginalReadonlyJournalCloseFailure),
    Write(OriginalJournalWriteTransition),
    WriteFailure(super::OriginalJournalWriteResourceCloseFailure),
    Opening(OriginalSqliteOpenFailure),
    NativeFailure(OriginalSqliteResourceCloseFailure),
}

/// Resource-only continuation of the exact failed native transition. Its
/// original first error and all unclosed external inputs remain together.
pub struct OriginalJournalTransitionResourceCloseFailure {
    pub error: JournalError,
    native: Vec<OriginalTransitionNative>,
    main: Vec<OriginalSqliteMainHandoff>,
    sidecars: Vec<OriginalSqliteSidecarHandoff>,
    cas: Vec<ReleasedOriginalCoordinationFile>,
    resources: Option<WindowsOriginalResourceCloseFailure>,
    actual_closed: Vec<ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for OriginalJournalTransitionResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalJournalTransitionResourceCloseFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

fn native_retained(original: &OriginalTransitionNative) -> bool {
    match original {
        OriginalTransitionNative::Read(_)
        | OriginalTransitionNative::Handoff(_)
        | OriginalTransitionNative::Write(_)
        | OriginalTransitionNative::Opening(_) => true,
        OriginalTransitionNative::ReadFailure(original) => original.has_retained_originals(),
        OriginalTransitionNative::WriteFailure(original) => original.has_retained_originals(),
        OriginalTransitionNative::NativeFailure(original) => original.has_retained_originals(),
    }
}

fn copy_journal_error(error: &JournalError) -> JournalError {
    match error {
        JournalError::Io(error) => match error.raw_os_error() {
            Some(code) => std::io::Error::from_raw_os_error(code).into(),
            None => std::io::Error::new(error.kind(), error.to_string()).into(),
        },
        _ => std::io::Error::other(error.to_string()).into(),
    }
}

impl OriginalJournalTransitionFailure {
    pub fn resource_error(&self) -> JournalError {
        match self {
            Self::ReadonlyClose { failed, .. } | Self::ReadonlyContextClose { failed, .. } => {
                copy_journal_error(&failed.error)
            }
            Self::ReadonlyHandoff { error, .. }
            | Self::InertClosed { error, .. }
            | Self::Read { error, .. }
            | Self::Closed { error, .. }
            | Self::Open { error, .. } => copy_journal_error(error),
            Self::Opening { failed, .. } => {
                let error = match failed.as_ref() {
                    OriginalSqliteOpenFailure::Prepared { error, .. }
                    | OriginalSqliteOpenFailure::MainReleased { error, .. }
                    | OriginalSqliteOpenFailure::WalReleased { error, .. }
                    | OriginalSqliteOpenFailure::Released { error, .. }
                    | OriginalSqliteOpenFailure::Open { error, .. } => error,
                };
                match error.raw_os_error() {
                    Some(code) => std::io::Error::from_raw_os_error(code).into(),
                    None => std::io::Error::new(error.kind(), error.to_string()).into(),
                }
            }
        }
    }

    pub fn close_original_resources_retaining(
        self,
    ) -> OriginalJournalTransitionResourceCloseFailure {
        let mut original = OriginalJournalTransitionResourceCloseFailure {
            error: self.resource_error(),
            native: Vec::new(),
            main: Vec::new(),
            sidecars: Vec::new(),
            cas: Vec::new(),
            resources: None,
            actual_closed: Vec::new(),
        };
        match self {
            Self::ReadonlyClose {
                failed,
                wal,
                rollback,
            } => {
                original
                    .native
                    .push(OriginalTransitionNative::ReadFailure(*failed));
                original.sidecars.extend([*wal, *rollback]);
            }
            Self::ReadonlyHandoff {
                handoff,
                wal,
                rollback,
                error,
            } => {
                original.error = error;
                original
                    .native
                    .push(OriginalTransitionNative::Handoff(*handoff));
                original.sidecars.extend([*wal, *rollback]);
            }
            Self::ReadonlyContextClose {
                failed,
                main,
                wal,
                rollback,
                cas,
            } => {
                original
                    .native
                    .push(OriginalTransitionNative::ReadFailure(*failed));
                original.main.push(*main);
                original.sidecars.extend([*wal, *rollback]);
                original.cas.push(*cas);
            }
            Self::InertClosed {
                journal,
                main,
                cas,
                wal,
                rollback,
                error,
            } => {
                original.error = error;
                original
                    .native
                    .push(OriginalTransitionNative::Read(*journal));
                if let Some(main) = *main {
                    original.main.push(main);
                }
                if let Some(cas) = *cas {
                    original.cas.push(cas);
                }
                original.sidecars.extend([*wal, *rollback]);
            }
            Self::Read {
                journal,
                wal,
                rollback,
                error,
            } => {
                original.error = error;
                original
                    .native
                    .push(OriginalTransitionNative::Read(*journal));
                original.sidecars.extend([*wal, *rollback]);
            }
            Self::Closed {
                main,
                wal,
                rollback,
                cas,
                error,
            } => {
                original.error = error;
                original.main.push(*main);
                original.sidecars.extend([*wal, *rollback]);
                original.cas.push(*cas);
            }
            Self::Opening {
                failed,
                cas,
                readonly_closed,
            } => {
                original
                    .native
                    .push(OriginalTransitionNative::Opening(*failed));
                original.cas.push(*cas);
                original.actual_closed.push(readonly_closed);
            }
            Self::Open { transition, error } => {
                original.error = error;
                original
                    .native
                    .push(OriginalTransitionNative::Write(*transition));
            }
        }
        original.close_remaining()
    }
}

impl OriginalJournalTransitionResourceCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.native.iter().any(native_retained)
            || !self.main.is_empty()
            || !self.sidecars.is_empty()
            || !self.cas.is_empty()
            || self
                .resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    pub fn close_remaining(mut self) -> Self {
        let mut remaining = Vec::new();
        for original in self.native.drain(..) {
            let failed = match original {
                OriginalTransitionNative::Read(original) => {
                    match original.close_original_readonly_resources_retaining() {
                        Ok(closed) => {
                            self.actual_closed.push(closed);
                            None
                        }
                        Err(original) => Some(OriginalTransitionNative::ReadFailure(original)),
                    }
                }
                OriginalTransitionNative::Handoff(original) => {
                    match original.close_original_resources_retaining() {
                        Ok(closed) => {
                            self.actual_closed.push(closed);
                            None
                        }
                        Err(original) => Some(OriginalTransitionNative::ReadFailure(original)),
                    }
                }
                OriginalTransitionNative::Write(original) => {
                    match original.close_original_resources_retaining() {
                        Ok(closed) => {
                            self.actual_closed.push(closed);
                            None
                        }
                        Err(original) => Some(OriginalTransitionNative::WriteFailure(original)),
                    }
                }
                OriginalTransitionNative::Opening(original) => {
                    match original.close_original_resources_retaining() {
                        Ok(closed) => {
                            self.actual_closed.push(closed);
                            None
                        }
                        Err(original) => Some(OriginalTransitionNative::NativeFailure(original)),
                    }
                }
                OriginalTransitionNative::ReadFailure(original) => Some(
                    OriginalTransitionNative::ReadFailure(original.close_remaining()),
                ),
                OriginalTransitionNative::WriteFailure(original) => Some(
                    OriginalTransitionNative::WriteFailure(original.close_remaining()),
                ),
                OriginalTransitionNative::NativeFailure(original) => Some(
                    OriginalTransitionNative::NativeFailure(original.close_remaining()),
                ),
            };
            if let Some(original) = failed {
                remaining.push(original);
            }
        }
        self.native = remaining;
        if self.native.iter().any(native_retained) {
            return self;
        }
        let mut attempt = WindowsOriginalCloseAttempt::new();
        if let Some(original) = self.resources.take() {
            attempt.append_failure(original.close_remaining());
        }
        for original in self.main.drain(..) {
            original.close_into_attempt(&mut attempt);
        }
        for original in self.sidecars.drain(..) {
            original.close_into_attempt(&mut attempt);
        }
        for original in self.cas.drain(..) {
            original.close_into_attempt(&mut attempt);
        }
        match attempt.finish() {
            Ok(closed) => self.actual_closed.push(closed),
            Err(original) => self.resources = Some(original),
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl Drop for OriginalJournalTransitionResourceCloseFailure {
    fn drop(&mut self) {
        if self.has_retained_originals() {
            let original = (
                std::mem::take(&mut self.native),
                std::mem::take(&mut self.main),
                std::mem::take(&mut self.sidecars),
                std::mem::take(&mut self.cas),
                self.resources.take(),
                std::mem::take(&mut self.actual_closed),
                self.error.to_string(),
            );
            let _ = Box::leak(Box::new(original));
        }
    }
}
