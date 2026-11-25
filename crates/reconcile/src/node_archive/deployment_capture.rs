//! Private stopped-source composition has one readonly Journal and one complete
//! original CAS session during capture. It exposes no LocalSpace effects.
use crate::{
    check_ancestors, filesystem::PathIdentity, verified_existing_local_identity, ArchiveBounds,
    CapturedNodeArchive, LocalSpace, ReconcileError, Result,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use sync_extend_cas::Cas;
use sync_extend_core_model::limits::LocalLimits;
use sync_extend_journal::{
    CasCaptureCloseFailure, Journal, OriginalReadonlyJournalCloseFailure,
    StoppedCaptureJournalOpenFailure,
};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure, WriterCaptureCloseFailure, WriterOwner,
};

/// Its private fields can be created only after the same original source
/// connection, identity HANDLE and both ordinary writer locks have closed.
pub struct ClosedStoppedDeploymentCaptureSource {
    _database: Option<ClosedWindowsOriginalResources>,
    _data_owner: Option<ClosedWindowsOriginalResources>,
    _worktree_owner: Option<ClosedWindowsOriginalResources>,
    _identity_and_files: ClosedWindowsOriginalResources,
}

/// Preserves actual failed resources. It grants no reopen, cleanup or restart.
pub struct StoppedDeploymentCaptureCloseFailure {
    pub error: ReconcileError,
    pub original_database: Option<OriginalReadonlyJournalCloseFailure>,
    pub original_database_open_failures: Vec<StoppedCaptureJournalOpenFailure>,
    pub original_data_owner: Option<WriterCaptureCloseFailure>,
    pub original_worktree_owner: Option<WriterCaptureCloseFailure>,
    pub original_resources: Option<WindowsOriginalResourceCloseFailure>,
    pub original_cas_sessions: Vec<CasCaptureCloseFailure>,
    original_pending: Option<CaptureSourcePrefix>,
    original_closed_prefix: Vec<ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for StoppedDeploymentCaptureCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("StoppedDeploymentCaptureCloseFailure")
            .field("error", &self.error)
            .field(
                "original_database_retained",
                &self.original_database.is_some(),
            )
            .field(
                "original_database_open_failure_count",
                &self.original_database_open_failures.len(),
            )
            .field("original_data_owner", &self.original_data_owner)
            .field("original_worktree_owner", &self.original_worktree_owner)
            .field("original_resources", &self.original_resources)
            .field("original_cas_sessions", &self.original_cas_sessions)
            .field(
                "original_outer_scope_retained",
                &self.original_pending.is_some(),
            )
            .finish()
    }
}

impl StoppedDeploymentCaptureCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_pending.is_some()
            || self
                .original_database
                .as_ref()
                .is_some_and(OriginalReadonlyJournalCloseFailure::has_retained_originals)
            || self
                .original_database_open_failures
                .iter()
                .any(StoppedCaptureJournalOpenFailure::has_retained_originals)
            || self
                .original_data_owner
                .as_ref()
                .is_some_and(writer_failure_retained)
            || self
                .original_worktree_owner
                .as_ref()
                .is_some_and(writer_failure_retained)
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
            || self.original_cas_sessions.iter().any(cas_failure_retained)
    }

    /// Retry resource ending only, preserving the first error and the same
    /// surrounding source identities/locks while any original DB/CAS loan lives.
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_database.take() {
            self.original_database = Some(original.close_remaining());
        }
        self.original_database_open_failures =
            std::mem::take(&mut self.original_database_open_failures)
                .into_iter()
                .map(StoppedCaptureJournalOpenFailure::close_remaining)
                .collect();
        for original in &mut self.original_cas_sessions {
            retry_cas_failure(original, &mut self.original_closed_prefix);
        }
        let original_loans_remain = self
            .original_database
            .as_ref()
            .is_some_and(OriginalReadonlyJournalCloseFailure::has_retained_originals)
            || self
                .original_database_open_failures
                .iter()
                .any(StoppedCaptureJournalOpenFailure::has_retained_originals)
            || self.original_cas_sessions.iter().any(cas_failure_retained);
        if !original_loans_remain {
            if let Some(original) = self.original_pending.take() {
                match original.close(None) {
                    Ok(closed) => {
                        self.original_closed_prefix.extend(closed._database);
                        self.original_closed_prefix.extend(closed._data_owner);
                        self.original_closed_prefix.extend(closed._worktree_owner);
                        self.original_closed_prefix.push(closed._identity_and_files);
                    }
                    Err(mut later) => {
                        self.original_pending = later.original_pending.take();
                        self.original_closed_prefix
                            .append(&mut later.original_closed_prefix);
                        self.original_database =
                            later.original_database.take().or(self.original_database);
                        self.original_database_open_failures
                            .append(&mut later.original_database_open_failures);
                        self.original_data_owner = later.original_data_owner.take();
                        self.original_worktree_owner = later.original_worktree_owner.take();
                        self.original_cas_sessions
                            .append(&mut later.original_cas_sessions);
                        self.original_resources = merge_original_resource_failures(
                            self.original_resources.take(),
                            later.original_resources.take(),
                        );
                    }
                }
            }
            if let Some(original) = self.original_data_owner.as_mut() {
                retry_writer_failure(original, &mut self.original_closed_prefix);
            }
            if let Some(original) = self.original_worktree_owner.as_mut() {
                retry_writer_failure(original, &mut self.original_closed_prefix);
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

fn writer_failure_retained(original: &WriterCaptureCloseFailure) -> bool {
    original.original_native_owner.is_some()
        || original
            .original_resources
            .as_ref()
            .is_some_and(|original| original.retained_resource_groups() != 0)
}

fn cas_failure_retained(original: &CasCaptureCloseFailure) -> bool {
    original.original_native_guard.is_some()
        || original
            .original_resources
            .as_ref()
            .is_some_and(|original| original.retained_resource_groups() != 0)
}

fn merge_original_resource_failures(
    first: Option<WindowsOriginalResourceCloseFailure>,
    later: Option<WindowsOriginalResourceCloseFailure>,
) -> Option<WindowsOriginalResourceCloseFailure> {
    let mut terminal = WindowsOriginalCloseAttempt::new();
    if let Some(original) = first {
        terminal.append_failure(original);
    }
    if let Some(original) = later {
        terminal.append_failure(original);
    }
    terminal.finish().err()
}

fn retry_writer_failure(
    original: &mut WriterCaptureCloseFailure,
    closed: &mut Vec<ClosedWindowsOriginalResources>,
) {
    if let Some(owner) = original.original_native_owner.take() {
        match owner.close_ordinary_capture() {
            Ok(actual) => closed.push(actual),
            Err(mut later) => {
                original.original_native_owner = later.original_native_owner.take();
                original.original_resources = merge_original_resource_failures(
                    original.original_resources.take(),
                    later.original_resources.take(),
                );
            }
        }
    }
    if let Some(resources) = original.original_resources.take() {
        original.original_resources = Some(resources.close_remaining());
    }
}

fn retry_cas_failure(
    original: &mut CasCaptureCloseFailure,
    closed: &mut Vec<ClosedWindowsOriginalResources>,
) {
    if let Some(guard) = original.original_native_guard.take() {
        match guard.close_stopped_capture() {
            Ok(actual) => closed.push(actual),
            Err(mut later) => {
                original.original_native_guard = later.original_native_guard.take();
                original.original_resources = merge_original_resource_failures(
                    original.original_resources.take(),
                    later.original_resources.take(),
                );
            }
        }
    }
    if let Some(resources) = original.original_resources.take() {
        original.original_resources = Some(resources.close_remaining());
    }
}

#[derive(Default)]
struct CaptureSourcePrefix {
    journal: Option<Journal>,
    data_owner: Option<WriterOwner>,
    worktree_owner: Option<WriterOwner>,
    identity: Option<PathIdentity>,
    data_path: PathBuf,
    worktree_lock_path: PathBuf,
    failed_file_closes: Vec<WindowsOriginalResourceCloseFailure>,
    failed_cas_closes: Vec<CasCaptureCloseFailure>,
    failed_database_opens: Vec<StoppedCaptureJournalOpenFailure>,
    original_context: Option<CaptureSourceContext>,
}

#[allow(dead_code)]
struct CaptureSourceContext {
    space: sync_extend_core_model::SpaceId,
    device: sync_extend_core_model::DeviceId,
    worktree: PathBuf,
    data: PathBuf,
    cas: Cas,
    limits: LocalLimits,
}

impl CaptureSourcePrefix {
    fn close(
        mut self,
        mut first_error: Option<ReconcileError>,
    ) -> std::result::Result<
        ClosedStoppedDeploymentCaptureSource,
        StoppedDeploymentCaptureCloseFailure,
    > {
        let mut resources = WindowsOriginalCloseAttempt::new();
        let database_open_failures: Vec<_> = std::mem::take(&mut self.failed_database_opens)
            .into_iter()
            .map(StoppedCaptureJournalOpenFailure::close_remaining)
            .collect();
        if let Some(original) = database_open_failures.first() {
            first_error.get_or_insert_with(|| {
                ReconcileError::Io(std::io::Error::other(original.error.to_string()))
            });
        }
        for original in std::mem::take(&mut self.failed_file_closes) {
            resources.append_failure(original);
        }
        let mut failed_database = None;
        let database = self.journal.take().and_then(|journal| {
            match journal.close_stopped_capture_resources_retaining() {
                Ok(closed) => Some(closed),
                Err(original) => {
                    first_error.get_or_insert_with(|| {
                        ReconcileError::Io(std::io::Error::other(original.error.to_string()))
                    });
                    failed_database = Some(original);
                    None
                }
            }
        });
        let mut closed_prefix = Vec::new();
        let mut cas_failures = std::mem::take(&mut self.failed_cas_closes);
        for original in &mut cas_failures {
            retry_cas_failure(original, &mut closed_prefix);
            first_error.get_or_insert_with(|| {
                ReconcileError::Io(std::io::Error::other(original.error.to_string()))
            });
        }
        if failed_database
            .as_ref()
            .is_some_and(OriginalReadonlyJournalCloseFailure::has_retained_originals)
            || database_open_failures
                .iter()
                .any(StoppedCaptureJournalOpenFailure::has_retained_originals)
            || cas_failures.iter().any(cas_failure_retained)
        {
            closed_prefix.extend(database);
            let original_resources = match resources.finish() {
                Ok(closed) => {
                    closed_prefix.push(closed);
                    None
                }
                Err(original) => Some(original),
            };
            return Err(StoppedDeploymentCaptureCloseFailure {
                error: first_error.unwrap_or(ReconcileError::Invariant(
                    "same original stopped capture native loan remains",
                )),
                original_database: failed_database,
                original_database_open_failures: database_open_failures,
                original_data_owner: None,
                original_worktree_owner: None,
                original_resources,
                original_cas_sessions: cas_failures,
                original_pending: Some(self),
                original_closed_prefix: closed_prefix,
            });
        }
        if let Some(identity) = self.identity.take() {
            identity.close_stopped_capture(&mut resources);
        }
        let mut failed_data_owner = None;
        let data_owner =
            self.data_owner
                .take()
                .and_then(|owner| match owner.close_ordinary_capture() {
                    Ok(closed) => Some(closed),
                    Err(original) => {
                        first_error.get_or_insert_with(|| {
                            ReconcileError::Io(std::io::Error::new(
                                original.error.kind(),
                                original.error.to_string(),
                            ))
                        });
                        failed_data_owner = Some(original);
                        None
                    }
                });
        let mut failed_worktree_owner = None;
        let worktree_owner =
            self.worktree_owner
                .take()
                .and_then(|owner| match owner.close_ordinary_capture() {
                    Ok(closed) => Some(closed),
                    Err(original) => {
                        first_error.get_or_insert_with(|| {
                            ReconcileError::Io(std::io::Error::new(
                                original.error.kind(),
                                original.error.to_string(),
                            ))
                        });
                        failed_worktree_owner = Some(original);
                        None
                    }
                });
        let (closed_files, failed_files) = match resources.finish() {
            Ok(closed) => (Some(closed), None),
            Err(original) => {
                first_error.get_or_insert_with(|| {
                    ReconcileError::Io(std::io::Error::new(
                        original.error.kind(),
                        original.error.to_string(),
                    ))
                });
                (None, Some(original))
            }
        };
        match first_error {
            Some(error) => {
                closed_prefix.extend(database);
                closed_prefix.extend(data_owner);
                closed_prefix.extend(worktree_owner);
                closed_prefix.extend(closed_files);
                Err(StoppedDeploymentCaptureCloseFailure {
                    error,
                    original_database: failed_database,
                    original_database_open_failures: database_open_failures,
                    original_data_owner: failed_data_owner,
                    original_worktree_owner: failed_worktree_owner,
                    original_resources: failed_files,
                    original_cas_sessions: cas_failures,
                    original_pending: Some(self),
                    original_closed_prefix: closed_prefix,
                })
            }
            None => Ok(ClosedStoppedDeploymentCaptureSource {
                _database: database,
                _data_owner: data_owner,
                _worktree_owner: worktree_owner,
                _identity_and_files: closed_files
                    .expect("all actual original file closes succeeded"),
            }),
        }
    }
}

pub struct StoppedDeploymentCaptureSource {
    local: Option<LocalSpace>,
    failed_file_closes: Vec<WindowsOriginalResourceCloseFailure>,
    failed_cas_closes: Vec<CasCaptureCloseFailure>,
}

impl StoppedDeploymentCaptureSource {
    /// Existing readonly source only. No CREATE, migrations, recovery, scanner,
    /// CAS mutation callback or additional opaque Journal connection is used.
    pub fn open(
        data_dir: &Path,
        limits: LocalLimits,
    ) -> std::result::Result<Self, StoppedDeploymentCaptureCloseFailure> {
        let mut prefix = CaptureSourcePrefix::default();
        let prepared = (|| -> Result<LocalSpace> {
            limits.validate()?;
            check_ancestors(data_dir)?;
            let data_dir = fs::canonicalize(data_dir)?;
            prefix.data_path = data_dir.clone();
            prefix.data_owner = Some(
                WriterOwner::acquire_existing_stopped_capture(&data_dir).map_err(|failure| {
                    if let Some(original) = failure.original_resources {
                        prefix.failed_file_closes.push(original);
                    }
                    ReconcileError::Io(failure.error)
                })?,
            );
            prefix.journal = Some(
                Journal::open_stopped_capture_existing(
                    &data_dir.join("journal.sqlite"),
                    limits.max_storage_entries,
                )
                .map_err(|original| {
                    let error =
                        ReconcileError::Io(std::io::Error::other(original.error.to_string()));
                    prefix.failed_database_opens.push(original);
                    error
                })?,
            );
            let journal = prefix.journal.as_ref().ok_or(ReconcileError::Unstable)?;
            let (space_id, device_id, worktree) =
                verified_existing_local_identity(&data_dir, journal)?;
            let cas = Cas::open_existing_layout(&data_dir.join("cas"))?;
            prefix.worktree_lock_path = worktree.join(".sync-extend");
            prefix.worktree_owner = Some(
                WriterOwner::acquire_existing_stopped_capture(&prefix.worktree_lock_path).map_err(
                    |failure| {
                        if let Some(original) = failure.original_resources {
                            prefix.failed_file_closes.push(original);
                        }
                        ReconcileError::Io(failure.error)
                    },
                )?,
            );
            prefix.identity = Some(PathIdentity::capture(&worktree)?);
            let local = LocalSpace {
                space_id,
                device_id,
                worktree,
                data_dir,
                cas,
                limits,
                journal: prefix
                    .journal
                    .take()
                    .expect("original source Journal acquired"),
                root_identity: prefix
                    .identity
                    .take()
                    .expect("original root identity acquired"),
                _lock: prefix
                    .data_owner
                    .take()
                    .expect("original source lock acquired"),
                _worktree_lock: prefix
                    .worktree_owner
                    .take()
                    .expect("original worktree lock acquired"),
            };
            Ok(local)
        })();
        match prepared {
            Err(error) => Err(prefix
                .close(Some(error))
                .err()
                .expect("first failure remains")),
            Ok(local) => {
                let source = Self {
                    local: Some(local),
                    failed_file_closes: prefix.failed_file_closes,
                    failed_cas_closes: prefix.failed_cas_closes,
                };
                if let Err(error) = source.original_local().and_then(LocalSpace::verify_root) {
                    return Err(source.close_after_error(error));
                }
                Ok(source)
            }
        }
    }

    pub(super) fn original_local(&self) -> Result<&LocalSpace> {
        self.local.as_ref().ok_or(ReconcileError::Invariant(
            "stopped capture source already ended",
        ))
    }

    pub(super) fn capture_node_archive(
        &mut self,
        configs: &[(String, PathBuf)],
        bounds: ArchiveBounds,
    ) -> Result<CapturedNodeArchive> {
        match self
            .original_local()?
            .capture_node_archive_retaining(configs, bounds)
        {
            Ok(archive) => Ok(archive),
            Err(failure) => {
                if let Some(original) = failure.original_resources {
                    self.failed_file_closes.push(original);
                }
                if let Some(original) = failure.original_cas_session {
                    self.failed_cas_closes.push(original);
                }
                Err(failure.error)
            }
        }
    }

    fn take_prefix(&mut self) -> CaptureSourcePrefix {
        let mut prefix = CaptureSourcePrefix {
            failed_file_closes: std::mem::take(&mut self.failed_file_closes),
            failed_cas_closes: std::mem::take(&mut self.failed_cas_closes),
            ..CaptureSourcePrefix::default()
        };
        if let Some(local) = self.local.take() {
            let LocalSpace {
                journal,
                root_identity,
                _lock,
                _worktree_lock,
                data_dir,
                worktree,
                space_id,
                device_id,
                cas,
                limits,
            } = local;
            prefix.journal = Some(journal);
            prefix.identity = Some(root_identity);
            prefix.data_owner = Some(_lock);
            prefix.worktree_owner = Some(_worktree_lock);
            prefix.data_path = data_dir.clone();
            prefix.worktree_lock_path = worktree.join(".sync-extend");
            prefix.original_context = Some(CaptureSourceContext {
                space: space_id,
                device: device_id,
                worktree,
                data: data_dir,
                cas,
                limits,
            });
        }
        prefix
    }

    fn close_after_error(mut self, error: ReconcileError) -> StoppedDeploymentCaptureCloseFailure {
        self.take_prefix()
            .close(Some(error))
            .err()
            .expect("first failure remains")
    }

    pub fn close_retaining(
        mut self,
    ) -> std::result::Result<
        ClosedStoppedDeploymentCaptureSource,
        StoppedDeploymentCaptureCloseFailure,
    > {
        let verified = self
            .original_local()
            .and_then(LocalSpace::verify_root)
            .err();
        self.take_prefix().close(verified)
    }
}

impl Drop for StoppedDeploymentCaptureSource {
    fn drop(&mut self) {
        if self.local.is_some()
            || !self.failed_file_closes.is_empty()
            || !self.failed_cas_closes.is_empty()
        {
            if let Err(original) = self.take_prefix().close(None) {
                original.retain_until_process_exit();
            }
        }
    }
}
