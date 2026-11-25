//! Actual original restore resource ending, with the same failed HANDLEs retained.
use crate::ReconcileError;
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

// These private, inert contexts retain the exact original metadata and borrowed
// scope. They expose no observation, issuer, decoder, or native object recovery.
trait OriginalNodeTerminalContext {}
impl<T: ?Sized> OriginalNodeTerminalContext for T {}

/// Aggregate the actual independently owned groups of an initial restore.
/// Every owning type destructures all fields before entering this terminal.
pub struct OriginalNodeResourceCloseAttempt<'scope> {
    pub(super) native: WindowsOriginalCloseAttempt,
    contexts: Vec<Box<dyn OriginalNodeTerminalContext + 'scope>>,
}

impl Default for OriginalNodeResourceCloseAttempt<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'scope> OriginalNodeResourceCloseAttempt<'scope> {
    pub fn new() -> Self {
        Self {
            native: WindowsOriginalCloseAttempt::new(),
            contexts: Vec::new(),
        }
    }

    pub(super) fn keep_context<T: 'scope>(&mut self, original: T) {
        self.contexts.push(Box::new(original));
    }

    pub fn append_closed(&mut self, closed: ClosedWindowsOriginalResources) {
        self.native.append_result(Ok(closed));
    }

    pub fn append_failure(&mut self, mut failure: OriginalNodeResourceCloseFailure<'scope>) {
        self.native.append_failure(
            failure
                .original_resources
                .take()
                .expect("an original handle terminal failure owns its native result"),
        );
        self.contexts.append(&mut failure.contexts);
    }

    pub fn finish(
        self,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalNodeResourceCloseFailure<'scope>>
    {
        let Self { native, contexts } = self;
        match native.finish() {
            Ok(closed) => Ok(closed),
            Err(original_resources) => Err(OriginalNodeResourceCloseFailure {
                error: ReconcileError::Io(copy_io_error(&original_resources.error)),
                original_resources: Some(original_resources),
                contexts,
            }),
        }
    }
}

/// A failed actual resource terminal keeps its first error, every failed
/// original HANDLE, and the full inert context of every consumed original group.
pub struct OriginalNodeResourceCloseFailure<'scope> {
    pub error: ReconcileError,
    original_resources: Option<WindowsOriginalResourceCloseFailure>,
    contexts: Vec<Box<dyn OriginalNodeTerminalContext + 'scope>>,
}

impl std::fmt::Debug for OriginalNodeResourceCloseFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalNodeResourceCloseFailure")
            .field("error", &self.error)
            .field("original_contexts", &self.contexts.len())
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalNodeResourceCloseFailure<'_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original_resources
            .as_ref()
            .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    /// Resource-only retry on the same originals. It never yields a clean
    /// completion, history, checkpoint, native permission, or restart proof.
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_resources.take() {
            self.original_resources = Some(original.close_remaining());
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub(super) fn retain_and_report(self) -> ReconcileError {
        let reported = ReconcileError::Io(std::io::Error::other(self.error.to_string()));
        self.retain_until_process_exit();
        reported
    }
}

impl Drop for OriginalNodeResourceCloseFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original_resources.take() {
            if original.retained_resource_groups() != 0 {
                let contexts = std::mem::take(&mut self.contexts);
                let _ = Box::leak(Box::new((original, contexts)));
            }
        }
    }
}

fn copy_io_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}
