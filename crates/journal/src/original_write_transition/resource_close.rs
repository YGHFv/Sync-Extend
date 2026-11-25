//! Consuming terminal for the original writable SQLite owner and CAS sentinel.
use super::{JournalError, OriginalJournalWriteTransition};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, OriginalSqliteResourceCloseFailure,
    ReleasedOriginalCoordinationFile, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

pub struct OriginalJournalWriteResourceCloseFailure {
    pub error: JournalError,
    original_native: Option<OriginalSqliteResourceCloseFailure>,
    original_cas: Option<ReleasedOriginalCoordinationFile>,
    original_resources: Option<WindowsOriginalResourceCloseFailure>,
    original_context: OriginalJournalTerminalContext,
    already_closed: Vec<ClosedWindowsOriginalResources>,
}

#[allow(dead_code)]
struct OriginalJournalTerminalContext {
    path: std::path::PathBuf,
    space: sync_extend_core_model::SpaceId,
    max_entries: usize,
    complete_queries: Vec<sync_extend_platform_fs::OriginalSqliteQuery>,
    inspection: crate::NodeInspectionBounds,
}

impl std::fmt::Debug for OriginalJournalWriteResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalJournalWriteResourceCloseFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalJournalWriteResourceCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_cas.is_some()
            || self
                .original_native
                .as_ref()
                .is_some_and(OriginalSqliteResourceCloseFailure::has_retained_originals)
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_native.take() {
            self.original_native = Some(original.close_remaining());
        }
        // The surrounding sentinel stays held while the same native owner
        // still has an actual DB, IO, VFS, or original metadata resource.
        if self
            .original_native
            .as_ref()
            .is_none_or(|original| !original.has_retained_originals())
        {
            if let Some(original) = self.original_cas.take() {
                let mut attempt = WindowsOriginalCloseAttempt::new();
                original.close_into_attempt(&mut attempt);
                match attempt.finish() {
                    Ok(closed) => self.already_closed.push(closed),
                    Err(original) => self.original_resources = Some(original),
                }
            }
        }
        if let Some(original) = self.original_resources.take() {
            self.original_resources = Some(original.close_remaining());
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl OriginalJournalWriteTransition {
    pub fn close_original_resources_retaining(
        self,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalJournalWriteResourceCloseFailure>
    {
        let Self {
            original,
            cas,
            path,
            space,
            max_entries,
            complete_queries,
            inspection,
            readonly_closed,
        } = self;
        let original_context = OriginalJournalTerminalContext {
            path,
            space,
            max_entries,
            complete_queries,
            inspection,
        };
        let native_closed = match original.close_original_resources_retaining() {
            Ok(closed) => closed,
            Err(original_native) => {
                return Err(OriginalJournalWriteResourceCloseFailure {
                    error: copy_error(&original_native.error).into(),
                    original_native: Some(original_native),
                    original_cas: Some(cas),
                    original_resources: None,
                    original_context,
                    already_closed: vec![readonly_closed],
                });
            }
        };
        let mut attempt = WindowsOriginalCloseAttempt::new();
        attempt.append_result(Ok(readonly_closed));
        attempt.append_result(Ok(native_closed));
        cas.close_into_attempt(&mut attempt);
        match attempt.finish() {
            Ok(closed) => Ok(closed),
            Err(original_resources) => Err(OriginalJournalWriteResourceCloseFailure {
                error: copy_error(&original_resources.error).into(),
                original_native: None,
                original_cas: None,
                original_resources: Some(original_resources),
                original_context,
                already_closed: Vec::new(),
            }),
        }
    }
}

fn copy_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}
