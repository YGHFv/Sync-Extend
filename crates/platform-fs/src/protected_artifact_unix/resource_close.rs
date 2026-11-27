//! End each actual Unix descriptor once; never retry a possibly reused number.
use super::{refuse, UnixProtectedArtifactParent};
use std::{fs::File, io, os::fd::IntoRawFd, sync::Arc};

/// Constructed only after successful native closure of every supplied original.
/// This is a resource witness, not a replacement owner or restart capability.
pub struct ClosedUnixOriginalResources {
    descriptors: usize,
}

impl ClosedUnixOriginalResources {
    pub fn actual_closed_descriptors(&self) -> usize {
        self.descriptors
    }
}

/// A first error stays visible even after all remaining resources are closed.
/// Linux close errors consume the attempted descriptor: its integer is never
/// retained or retried, because it may already identify an unrelated object.
pub struct UnixOriginalResourceCloseFailure {
    pub error: io::Error,
    pub actual_closed_descriptors: usize,
    pub uncertain_close_attempts: usize,
    original_parents: Vec<UnixProtectedArtifactParent>,
}

impl std::fmt::Debug for UnixOriginalResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("UnixOriginalResourceCloseFailure")
            .field("error_kind", &self.error.kind())
            .field("actual_closed_descriptors", &self.actual_closed_descriptors)
            .field("uncertain_close_attempts", &self.uncertain_close_attempts)
            .field("retained_parent_scopes", &self.original_parents.len())
            .finish()
    }
}

impl UnixOriginalResourceCloseFailure {
    pub fn retained_parent_scopes(&self) -> usize {
        self.original_parents.len()
    }

    pub fn close_remaining(mut self) -> Self {
        let mut attempt = UnixOriginalCloseAttempt::new();
        attempt.actual_closed_descriptors = self.actual_closed_descriptors;
        attempt.uncertain_close_attempts = self.uncertain_close_attempts;
        let error = std::mem::replace(&mut self.error, refuse("consumed Unix close failure"));
        attempt.note_error(error);
        for parent in std::mem::take(&mut self.original_parents) {
            attempt.close_artifact_parent(parent);
        }
        match attempt.finish() {
            Err(failure) => failure,
            Ok(_) => unreachable!("first Unix close error is never erased"),
        }
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> io::Error {
        let error = self.error.raw_os_error().map_or_else(
            || io::Error::new(self.error.kind(), self.error.to_string()),
            io::Error::from_raw_os_error,
        );
        if !self.original_parents.is_empty() {
            self.retain_until_process_exit();
        }
        error
    }
}

impl Drop for UnixOriginalResourceCloseFailure {
    fn drop(&mut self) {
        if !self.original_parents.is_empty() {
            let _ = Box::leak(Box::new(std::mem::take(&mut self.original_parents)));
        }
    }
}

/// Keeps outstanding parent loans and attempts every independent native close.
pub struct UnixOriginalCloseAttempt {
    first_error: Option<io::Error>,
    actual_closed_descriptors: usize,
    uncertain_close_attempts: usize,
    original_parents: Vec<UnixProtectedArtifactParent>,
}

impl Default for UnixOriginalCloseAttempt {
    fn default() -> Self { Self::new() }
}

impl UnixOriginalCloseAttempt {
    pub fn new() -> Self {
        Self { first_error: None, actual_closed_descriptors: 0,
            uncertain_close_attempts: 0, original_parents: Vec::new() }
    }

    pub fn note_error(&mut self, error: io::Error) {
        self.first_error.get_or_insert(error);
    }

    pub fn close_file(&mut self, file: File) {
        let descriptor = file.into_raw_fd();
        // SAFETY: this is the single close of the owned descriptor transferred
        // above. Even EINTR must not cause a second close of this integer.
        if unsafe { libc::close(descriptor) } == 0 {
            self.actual_closed_descriptors += 1;
        } else {
            self.uncertain_close_attempts += 1;
            self.note_error(io::Error::last_os_error());
        }
    }

    pub fn close_artifact_parent(&mut self, parent: UnixProtectedArtifactParent) {
        if let Err(error) = parent.verify_original() { self.note_error(error); }
        match Arc::try_unwrap(parent.original) {
            Ok(original) => original.close_into_attempt(self),
            Err(original) => {
                self.note_error(refuse("deployment parent still has original creator loans"));
                self.original_parents.push(UnixProtectedArtifactParent { original });
            }
        }
    }

    pub fn append_result(&mut self, result: Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure>) {
        match result {
            Ok(closed) => self.actual_closed_descriptors += closed.descriptors,
            Err(mut failure) => {
                self.actual_closed_descriptors += failure.actual_closed_descriptors;
                self.uncertain_close_attempts += failure.uncertain_close_attempts;
                self.note_error(std::mem::replace(&mut failure.error, refuse("consumed Unix close failure")));
                self.original_parents.append(&mut failure.original_parents);
            }
        }
    }

    pub fn finish(mut self) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        match self.first_error.take() {
            Some(error) => Err(UnixOriginalResourceCloseFailure { error,
                actual_closed_descriptors: self.actual_closed_descriptors,
                uncertain_close_attempts: self.uncertain_close_attempts,
                original_parents: std::mem::take(&mut self.original_parents) }),
            None => Ok(ClosedUnixOriginalResources { descriptors: self.actual_closed_descriptors }),
        }
    }
}

impl Drop for UnixOriginalCloseAttempt {
    fn drop(&mut self) {
        if !self.original_parents.is_empty() {
            let _ = Box::leak(Box::new(std::mem::take(&mut self.original_parents)));
        }
    }
}
