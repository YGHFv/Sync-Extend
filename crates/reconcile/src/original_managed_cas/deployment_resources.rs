//! The two original CAS readers have an explicit retained resource owner.
use crate::{ReconcileError, Result, SessionGuard};
use std::sync::{Arc, Mutex};
use sync_extend_cas::Cas;
use sync_extend_platform_fs::{ClosedWindowsOriginalResources, WindowsOriginalCloseAttempt};

pub(crate) struct OriginalManagedCasReadResources {
    readers: Arc<Mutex<OriginalCoordinationReaders>>,
}

struct OriginalCoordinationReaders {
    access: Option<sync_extend_journal::Journal>,
    session: Option<sync_extend_journal::Journal>,
    access_failure: Option<sync_extend_journal::OriginalReadonlyJournalCloseFailure>,
    session_failure: Option<sync_extend_journal::OriginalReadonlyJournalCloseFailure>,
    suspended: bool,
    first_error: Option<ReconcileError>,
    actual_closed: Vec<ClosedWindowsOriginalResources>,
}

/// Same reader owners, original failed native contexts and callback loan scope.
/// Only resource ending is exposed after failure; it grants no CAS access.
pub struct OriginalManagedCasResourceCloseFailure {
    pub error: ReconcileError,
    original_owner: Option<OriginalManagedCasReadResources>,
    original_readers: Option<OriginalCoordinationReaders>,
    already_closed: Vec<ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for OriginalManagedCasResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalManagedCasResourceCloseFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalCoordinationReaders {
    fn has_retained_originals(&self) -> bool {
        self.access.is_some()
            || self.session.is_some()
            || self
                .access_failure
                .as_ref()
                .is_some_and(|failure| failure.has_retained_originals())
            || self
                .session_failure
                .as_ref()
                .is_some_and(|failure| failure.has_retained_originals())
    }

    fn close_remaining(&mut self) {
        self.suspended = true;
        if let Some(original) = self.access.take() {
            match original.close_original_readonly_resources_retaining() {
                Ok(closed) => self.actual_closed.push(closed),
                Err(failure) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&failure.error));
                    self.access_failure = Some(failure);
                }
            }
        }
        if let Some(original) = self.session.take() {
            match original.close_original_readonly_resources_retaining() {
                Ok(closed) => self.actual_closed.push(closed),
                Err(failure) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&failure.error));
                    self.session_failure = Some(failure);
                }
            }
        }
        if let Some(original) = self.access_failure.take() {
            self.access_failure = Some(original.close_remaining());
        }
        if let Some(original) = self.session_failure.take() {
            self.session_failure = Some(original.close_remaining());
        }
    }

    fn suspension_result(&self) -> std::result::Result<(), String> {
        if let Some(error) = &self.first_error {
            return Err(error.to_string());
        }
        if self.has_retained_originals() {
            return Err("original CAS reader resource terminal remains incomplete".into());
        }
        Ok(())
    }
}

impl OriginalManagedCasReadResources {
    pub(crate) fn close_retaining(
        self,
    ) -> std::result::Result<ClosedWindowsOriginalResources, OriginalManagedCasResourceCloseFailure>
    {
        let original = match Arc::try_unwrap(self.readers) {
            Ok(original) => original,
            Err(readers) => {
                return Err(OriginalManagedCasResourceCloseFailure {
                    error: ReconcileError::Invariant(
                        "original CAS callback loans remain at resource terminal",
                    ),
                    original_owner: Some(Self { readers }),
                    original_readers: None,
                    already_closed: Vec::new(),
                });
            }
        };
        let mut state = match original.into_inner() {
            Ok(state) => state,
            Err(original) => {
                let mut state = original.into_inner();
                state.first_error.get_or_insert(ReconcileError::Invariant(
                    "original CAS reader owner was poisoned",
                ));
                state
            }
        };
        state.close_remaining();
        if let Some(error) = &state.first_error {
            return Err(OriginalManagedCasResourceCloseFailure {
                error: reported(error),
                original_owner: None,
                original_readers: Some(state),
                already_closed: Vec::new(),
            });
        }
        if state.has_retained_originals() {
            return Err(OriginalManagedCasResourceCloseFailure {
                error: ReconcileError::Invariant("original CAS readers remain after actual close"),
                original_owner: None,
                original_readers: Some(state),
                already_closed: Vec::new(),
            });
        }
        let OriginalCoordinationReaders {
            access,
            session,
            access_failure,
            session_failure,
            suspended,
            first_error,
            actual_closed,
        } = state;
        let _ = (
            access,
            session,
            access_failure,
            session_failure,
            suspended,
            first_error,
        );
        let mut attempt = WindowsOriginalCloseAttempt::new();
        for closed in actual_closed {
            attempt.append_result(Ok(closed));
        }
        Ok(attempt
            .finish()
            .expect("only actual successful original reader terminals"))
    }
}

impl OriginalManagedCasResourceCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_owner.is_some()
            || self
                .original_readers
                .as_ref()
                .is_some_and(OriginalCoordinationReaders::has_retained_originals)
    }

    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_owner.take() {
            match original.close_retaining() {
                Ok(closed) => self.already_closed.push(closed),
                Err(mut failure) => {
                    self.original_owner = failure.original_owner.take();
                    self.original_readers = failure.original_readers.take();
                    self.already_closed.append(&mut failure.already_closed);
                }
            }
        }
        if let Some(state) = &mut self.original_readers {
            state.close_remaining();
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl Drop for OriginalManagedCasResourceCloseFailure {
    fn drop(&mut self) {
        if self.has_retained_originals() {
            let original = (
                self.original_owner.take(),
                self.original_readers.take(),
                std::mem::take(&mut self.already_closed),
                self.error.to_string(),
            );
            let _ = Box::leak(Box::new(original));
        }
    }
}

fn reported(error: &impl std::fmt::Display) -> ReconcileError {
    ReconcileError::Io(std::io::Error::other(error.to_string()))
}

pub(crate) struct OriginalManagedCasReadPreparationFailure {
    pub(crate) error: ReconcileError,
    access: Option<sync_extend_journal::Journal>,
    access_failure: Option<sync_extend_journal::OriginalReadonlyJournalCloseFailure>,
    failed_open: Option<sync_extend_journal::OriginalReadonlyJournalOpenFailure>,
    readers: Option<OriginalManagedCasReadResources>,
    readers_failure: Option<OriginalManagedCasResourceCloseFailure>,
    actual_closed: Vec<ClosedWindowsOriginalResources>,
}

impl OriginalManagedCasReadPreparationFailure {
    fn new(error: ReconcileError) -> Self {
        Self {
            error,
            access: None,
            access_failure: None,
            failed_open: None,
            readers: None,
            readers_failure: None,
            actual_closed: Vec::new(),
        }
    }

    pub(crate) fn has_retained_originals(&self) -> bool {
        self.access.is_some()
            || self
                .access_failure
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
            || self
                .failed_open
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
            || self.readers.is_some()
            || self
                .readers_failure
                .as_ref()
                .is_some_and(OriginalManagedCasResourceCloseFailure::has_retained_originals)
    }

    pub(crate) fn close_remaining(mut self) -> Self {
        if let Some(original) = self.failed_open.take() {
            self.failed_open = Some(original.close_remaining());
        }
        if let Some(original) = self.access.take() {
            match original.close_original_readonly_resources_retaining() {
                Ok(closed) => self.actual_closed.push(closed),
                Err(original) => self.access_failure = Some(original),
            }
        } else if let Some(original) = self.access_failure.take() {
            self.access_failure = Some(original.close_remaining());
        }
        if let Some(original) = self.readers.take() {
            match original.close_retaining() {
                Ok(closed) => self.actual_closed.push(closed),
                Err(original) => self.readers_failure = Some(original),
            }
        } else if let Some(original) = self.readers_failure.take() {
            self.readers_failure = Some(original.close_remaining());
        }
        self
    }

    fn retain_and_report(self) -> ReconcileError {
        let reported = reported(&self.error);
        let original = self.close_remaining();
        if original.has_retained_originals() {
            let _ = Box::leak(Box::new(original));
        }
        reported
    }
}

impl Drop for OriginalManagedCasReadPreparationFailure {
    fn drop(&mut self) {
        if self.has_retained_originals() {
            let original = (
                self.access.take(),
                self.access_failure.take(),
                self.failed_open.take(),
                self.readers.take(),
                self.readers_failure.take(),
                std::mem::take(&mut self.actual_closed),
                self.error.to_string(),
            );
            let _ = Box::leak(Box::new(original));
        }
    }
}

pub(super) fn assemble(
    data_dir: &std::path::Path,
    journal: &sync_extend_journal::Journal,
) -> Result<(Cas, OriginalManagedCasReadResources)> {
    assemble_retaining(data_dir, journal).map_err(|original| original.retain_and_report())
}

pub(super) fn assemble_retaining(
    data_dir: &std::path::Path,
    journal: &sync_extend_journal::Journal,
) -> std::result::Result<
    (Cas, OriginalManagedCasReadResources),
    OriginalManagedCasReadPreparationFailure,
> {
    let access = match journal.open_original_coordination_connection_retaining() {
        Ok(access) => access,
        Err(original) => {
            let mut failure =
                OriginalManagedCasReadPreparationFailure::new(reported(&original.error));
            failure.failed_open = Some(original);
            return Err(failure);
        }
    };
    let session = match journal.open_original_coordination_connection_retaining() {
        Ok(session) => session,
        Err(original) => {
            let mut failure =
                OriginalManagedCasReadPreparationFailure::new(reported(&original.error));
            failure.access = Some(access);
            failure.failed_open = Some(original);
            return Err(failure);
        }
    };
    let readers = Arc::new(Mutex::new(OriginalCoordinationReaders {
        access: Some(access),
        session: Some(session),
        access_failure: None,
        session_failure: None,
        suspended: false,
        first_error: None,
        actual_closed: Vec::new(),
    }));
    let access_readers = Arc::clone(&readers);
    let session_readers = Arc::clone(&readers);
    let handoff_readers = Arc::clone(&readers);
    let cas = Cas::open_existing_session_coordinated_with_read_handoff(
        &data_dir.join("cas"),
        move |id| {
            let mut state = access_readers
                .lock()
                .map_err(|_| "original CAS readers poisoned")?;
            if state.suspended {
                return Err("original CAS read coordination has entered handoff".into());
            }
            let access = state
                .access
                .as_mut()
                .ok_or("original CAS access reader absent")?;
            access
                .acquire_original_cas_access_observed(id)
                .map(|guard| -> Box<dyn Send> {
                    crate::fault::checkpoint("after_cas_access_lock");
                    Box::new(guard)
                })
                .map_err(|error| error.to_string())
        },
        move || {
            let state = session_readers
                .lock()
                .map_err(|_| "original CAS readers poisoned")?;
            if state.suspended {
                return Err("original CAS read coordination has entered handoff".into());
            }
            let session = state
                .session
                .as_ref()
                .ok_or("original CAS session reader absent")?;
            session
                .verify_original_created_image()
                .map_err(|error| error.to_string())?;
            session
                .acquire_cas_session()
                .map(|guard| -> Box<dyn Send> {
                    crate::fault::checkpoint("after_cas_session_lock");
                    Box::new(SessionGuard { _guard: guard })
                })
                .map_err(|error| error.to_string())
        },
        move || {
            let mut state = handoff_readers
                .lock()
                .map_err(|_| "original CAS readers poisoned")?;
            if state.suspended {
                return Err("original CAS read handoff is already attempted".into());
            }
            state.close_remaining();
            state.suspension_result()
        },
    );
    let cas = match cas {
        Ok(cas) => cas,
        Err(error) => {
            // The failed constructor has consumed and ended its callback
            // loans. The independent same Arc owner verifies that gate and
            // closes both actual first-owning Journal readers explicitly.
            let mut failure = OriginalManagedCasReadPreparationFailure::new(error.into());
            failure.readers = Some(OriginalManagedCasReadResources { readers });
            return Err(failure);
        }
    };
    Ok((cas, OriginalManagedCasReadResources { readers }))
}
