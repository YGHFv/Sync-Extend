//! Consuming resource terminal for the actual recovered deployment session.
//! Original files and evidence stay in place; no pathname is opened or changed.
use super::{
    FreshRecoveredNodeWalV2Session, ReacquiredClosedNodeLockedReadScope,
    ReacquiredClosedNodeReadScope, ReacquiredExternalEvidence, ReacquiredFile,
    RecoveredFileProtection,
};
use crate::ReconcileError;
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, FreshNativeWalCloseFailure, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

/// No caller can recover a writer or restart from this failed terminal.
/// The same actual session, native callback scope and failed original HANDLEs
/// remain owned here until another resource-only close or process exit.
pub struct DeploymentFreshNodeResourceCloseFailure {
    pub error: ReconcileError,
    original_session: Option<FreshRecoveredNodeWalV2Session>,
    original_native: Option<FreshNativeWalCloseFailure>,
    original_pending_resources: Option<OriginalSessionResources>,
    original_resources: Option<WindowsOriginalResourceCloseFailure>,
    terminal_context: Option<OriginalSessionTerminalContext>,
    already_closed: Vec<ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for DeploymentFreshNodeResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("DeploymentFreshNodeResourceCloseFailure")
            .field("error", &self.error)
            .field(
                "whole_original_session_retained",
                &self.original_session.is_some(),
            )
            .field(
                "original_native_terminal_retained",
                &self.original_native.is_some(),
            )
            .field(
                "original_owner_scope_retained",
                &self.original_pending_resources.is_some(),
            )
            .field(
                "original_handle_terminal_retained",
                &self.original_resources.is_some(),
            )
            .finish()
    }
}

impl DeploymentFreshNodeResourceCloseFailure {
    /// Inspect only the owned terminal. This observation cannot issue history,
    /// restart, checkpoint, or any native permission.
    pub fn has_retained_originals(&self) -> bool {
        self.original_session.is_some()
            || self.original_pending_resources.is_some()
            || self
                .original_native
                .as_ref()
                .is_some_and(FreshNativeWalCloseFailure::has_retained_originals)
            || self
                .original_resources
                .as_ref()
                .is_some_and(|original| original.retained_resource_groups() != 0)
    }

    /// End only the same retained originals. The first failure remains recorded
    /// even when a later terminal succeeds; it never yields clean close evidence.
    pub fn close_remaining(mut self) -> Self {
        if let Some(session) = self.original_session.take() {
            match session.close_failed_deployment_original_resources() {
                Ok(closed) => self.already_closed.push(closed),
                Err(mut later) => {
                    self.original_session = later.original_session.take();
                    self.original_native = later.original_native.take();
                    self.original_pending_resources = later.original_pending_resources.take();
                    self.original_resources = later.original_resources.take();
                    if self.terminal_context.is_none() {
                        self.terminal_context = later.terminal_context.take();
                    }
                    self.already_closed.append(&mut later.already_closed);
                }
            }
        }
        if let Some(original) = self.original_native.take() {
            self.original_native = Some(original.close_remaining());
        }
        if self
            .original_native
            .as_ref()
            .is_none_or(|original| !original.has_retained_originals())
        {
            if let Some(original) = self.original_pending_resources.take() {
                match original.close(
                    self.terminal_context
                        .as_mut()
                        .expect("pending original resources retain their exact context"),
                ) {
                    Ok(closed) => self.already_closed.push(closed),
                    Err(original_resources) => self.original_resources = Some(original_resources),
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

/// Inert original metadata stays with a failed resource terminal. These values
/// preserve the complete session context and never reconstruct native objects.
#[allow(dead_code)]
struct OriginalSessionTerminalContext {
    archive: sync_extend_core_model::ContentId,
    space: sync_extend_core_model::SpaceId,
    previous: sync_extend_core_model::SpaceId,
    fresh: sync_extend_core_model::SpaceId,
    before_rows: sync_extend_core_model::ContentId,
    original_frames: sync_extend_core_model::ContentId,
    previous_record: sync_extend_core_model::ContentId,
    frames_path: std::path::PathBuf,
    bounds: sync_extend_journal::NodeInspectionBounds,
    separated_configs: Option<crate::SeparatedDeploymentNodeConfigs>,
    worktree: std::path::PathBuf,
    data: std::path::PathBuf,
    expected_membership:
        std::collections::BTreeMap<std::path::PathBuf, std::collections::BTreeSet<String>>,
    manifest: sync_extend_core_model::Manifest,
    rows: sync_extend_core_model::ContentId,
    native_keys: [String; 4],
    history_baseline: Vec<u8>,
    metadata_receipts: Vec<super::live_retention::RecoveredMetadataReceiptProof>,
    history_chain_parent: Option<super::HistoryRestartObject>,
    history_retained_originals: Vec<super::HistoryRetainedOriginal>,
    verified_main: std::cell::RefCell<Option<super::RecoveredVerificationKey>>,
    counters: (u32, u32, u32, u64, u64, usize, u64, u32, u64, usize),
    flags: (bool, bool, bool, bool, bool),
    predecessor: Option<sync_extend_core_model::ContentId>,
    file_context: Vec<OriginalTerminalFileContext>,
    directory_context: Vec<std::path::PathBuf>,
}

#[allow(dead_code)]
struct OriginalTerminalFileContext {
    path: std::path::PathBuf,
    digest: sync_extend_core_model::ContentId,
    bytes: u64,
}

struct OriginalSessionResources {
    directories: Vec<super::ReacquiredDirectory>,
    files: Vec<ReacquiredFile>,
    locks: Vec<sync_extend_platform_fs::ReacquiredNodeLock>,
    external: Vec<ReacquiredExternalEvidence>,
    frames: sync_extend_platform_fs::OwnedFileCreation,
    owner: sync_extend_platform_fs::OwnedFileCreation,
    retained_receipts: std::collections::BTreeMap<String, ReacquiredFile>,
    retained_history_evidence: Vec<ReacquiredFile>,
    retained_mutations: Vec<super::RecoveredRetainedMutation>,
    history_retained_directories:
        Vec<(std::path::PathBuf, sync_extend_platform_fs::LockedDirectory)>,
    new_cas_buckets: std::collections::BTreeMap<std::path::PathBuf, super::RecoveredCasBucket>,
    created_work_directories: std::collections::BTreeMap<
        std::path::PathBuf,
        sync_extend_platform_fs::LockedDirectoryMutation,
    >,
}

impl RecoveredFileProtection {
    fn close_into_attempt(self, attempt: &mut WindowsOriginalCloseAttempt) {
        match self {
            Self::Mutation(original) => original.close_into_attempt(attempt),
            Self::Created(original) => original.close_into_attempt(attempt),
            Self::Read(original) => original.close_into_attempt(attempt),
            Self::Sqlite(original) => original.close_into_attempt(attempt),
        }
    }
}

fn close_file(
    original: ReacquiredFile,
    attempt: &mut WindowsOriginalCloseAttempt,
    context: &mut OriginalSessionTerminalContext,
) {
    let ReacquiredFile {
        path,
        file,
        digest,
        bytes,
    } = original;
    context.file_context.push(OriginalTerminalFileContext {
        path,
        digest,
        bytes,
    });
    file.close_into_attempt(attempt);
}

impl FreshRecoveredNodeWalV2Session {
    /// Complete close evidence already requires actual SQLite close while all
    /// files remain held. This final consuming stage ends every actual HANDLE
    /// before the deployment wrapper can publish its closed runtime.
    pub(crate) fn close_deployment_original_resources(
        mut self,
    ) -> std::result::Result<ClosedWindowsOriginalResources, DeploymentFreshNodeResourceCloseFailure>
    {
        let first = if !self.closed || self.poisoned {
            Some(ReconcileError::Invariant(
                "deployment resource terminal requires actual healthy SQLite close",
            ))
        } else {
            self.verify_objects().err()
        };
        if let Some(error) = first {
            self.poisoned = true;
            return Err(DeploymentFreshNodeResourceCloseFailure {
                error,
                original_session: Some(self),
                original_native: None,
                original_pending_resources: None,
                original_resources: None,
                terminal_context: None,
                already_closed: Vec::new(),
            });
        }
        self.close_failed_deployment_original_resources()
    }

    /// Resource-only ending is also available to a poisoned owning child. It
    /// grants no clean history, checkpoint, native permission or restart proof.
    pub(crate) fn close_failed_deployment_original_resources(
        mut self,
    ) -> std::result::Result<ClosedWindowsOriginalResources, DeploymentFreshNodeResourceCloseFailure>
    {
        self.poisoned = true;
        // Every field is named so adding another owned resource requires this
        // terminal to account for it at compile time.
        let Self {
            separated_deployment_configs,
            read,
            native,
            frames,
            owner,
            path,
            bounds,
            space,
            previous,
            fresh,
            before_rows,
            archive,
            original_frames,
            next,
            previous_record,
            attempted,
            committed,
            closed,
            poisoned,
            predecessor,
            native_keys,
            history_count,
            metadata_count,
            retained_metadata_receipts,
            new_content_bytes,
            new_file_bytes,
            manifest_entry_limit,
            retained_receipts,
            retained_receipt_bytes,
            history_baseline,
            retained_history_evidence,
            history_chain_parent,
            history_chain_depth,
            history_retained_originals,
            history_retained_directories,
            retained_mutations,
            mutation_requested,
            created_work_directories,
            new_cas_bytes,
            new_cas_objects,
            new_cas_buckets,
            verified_main,
        } = self;
        let ReacquiredClosedNodeLockedReadScope {
            read,
            locks,
            external,
        } = read;
        let ReacquiredClosedNodeReadScope {
            directories,
            files,
            worktree,
            data,
            expected_membership,
            manifest,
            rows,
        } = read;
        let mut context = OriginalSessionTerminalContext {
            archive,
            space,
            previous,
            fresh,
            before_rows,
            original_frames,
            previous_record,
            frames_path: path,
            bounds,
            separated_configs: separated_deployment_configs,
            worktree,
            data,
            expected_membership,
            manifest,
            rows,
            native_keys,
            history_baseline,
            metadata_receipts: retained_metadata_receipts,
            history_chain_parent,
            history_retained_originals,
            verified_main,
            counters: (
                next,
                history_count,
                metadata_count,
                new_content_bytes,
                new_file_bytes,
                manifest_entry_limit,
                retained_receipt_bytes,
                history_chain_depth,
                new_cas_bytes,
                new_cas_objects,
            ),
            flags: (attempted, committed, closed, poisoned, mutation_requested),
            predecessor,
            file_context: Vec::new(),
            directory_context: Vec::new(),
        };
        let resources = OriginalSessionResources {
            directories,
            files,
            locks,
            external,
            frames,
            owner,
            retained_receipts,
            retained_history_evidence,
            retained_mutations,
            history_retained_directories,
            new_cas_buckets,
            created_work_directories,
        };
        // The native terminal must really finish before the original owner
        // locks and retained surrounding scope can be released.
        let native_closed = match native.close_original_resources_retaining() {
            Ok(closed) => closed,
            Err(original_native) => {
                return Err(DeploymentFreshNodeResourceCloseFailure {
                    error: ReconcileError::Io(copy_io_error(&original_native.error)),
                    original_session: None,
                    original_native: Some(original_native),
                    original_pending_resources: Some(resources),
                    original_resources: None,
                    terminal_context: Some(context),
                    already_closed: Vec::new(),
                });
            }
        };
        let other_result = resources.close(&mut context);
        let mut combined = WindowsOriginalCloseAttempt::new();
        combined.append_result(Ok(native_closed));
        combined.append_result(other_result);
        match combined.finish() {
            Ok(closed) => Ok(closed),
            Err(original_resources) => Err(DeploymentFreshNodeResourceCloseFailure {
                error: ReconcileError::Io(copy_io_error(&original_resources.error)),
                original_session: None,
                original_native: None,
                original_pending_resources: None,
                original_resources: Some(original_resources),
                terminal_context: Some(context),
                already_closed: Vec::new(),
            }),
        }
    }
}

impl OriginalSessionResources {
    fn close(
        self,
        context: &mut OriginalSessionTerminalContext,
    ) -> std::result::Result<ClosedWindowsOriginalResources, WindowsOriginalResourceCloseFailure>
    {
        let Self {
            directories,
            files,
            locks,
            external,
            frames,
            owner,
            retained_receipts,
            retained_history_evidence,
            retained_mutations,
            history_retained_directories,
            new_cas_buckets,
            created_work_directories,
        } = self;
        let mut attempt = WindowsOriginalCloseAttempt::new();
        for original in files {
            close_file(original, &mut attempt, context);
        }
        for ReacquiredExternalEvidence {
            path,
            file,
            digest,
            bytes,
        } in external
        {
            context.file_context.push(OriginalTerminalFileContext {
                path,
                digest,
                bytes,
            });
            file.close_into_attempt(&mut attempt);
        }
        for original in retained_receipts.into_values() {
            close_file(original, &mut attempt, context);
        }
        for original in retained_history_evidence {
            close_file(original, &mut attempt, context);
        }
        for original in retained_mutations {
            close_file(original.original, &mut attempt, context);
            context.directory_context.push(original.path);
            original.directory.close_into_attempt(&mut attempt);
        }
        for (path, original) in history_retained_directories.into_iter().rev() {
            context.directory_context.push(path);
            attempt.close_directory(original);
        }
        for (path, original) in new_cas_buckets.into_iter().rev() {
            context.directory_context.push(path);
            original.creator.close_into_attempt(&mut attempt);
        }
        for (path, original) in created_work_directories.into_iter().rev() {
            context.directory_context.push(path);
            original.close_into_attempt(&mut attempt);
        }
        for original in locks {
            original.close_into_attempt(&mut attempt);
        }
        frames.close_into_attempt(&mut attempt);
        owner.close_into_attempt(&mut attempt);
        for original in directories.into_iter().rev() {
            context.directory_context.push(original.path);
            attempt.close_directory(original.file);
        }
        attempt.finish()
    }
}

fn copy_io_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}
