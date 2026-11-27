//! Opaque recovered-local bridge for protected deployment runtime composition.
use crate::{ReconcileError, RecoveredLocalSpace, Result, VerifiedNodeStateArchive};
use serde::Serialize;
use std::path::{Path, PathBuf};
use sync_extend_core_model::{ContentId, PortablePath, SpaceId};

/// Only closing an actual deployment session constructs this owned evidence.
/// Serialization reports history; there is no receipt decoder or ID constructor.
#[derive(Serialize)]
pub struct DeploymentClosedNodeRuntime {
    archive_digest: ContentId,
    space_id: SpaceId,
    data_dir: PathBuf,
    worktree: PathBuf,
    fresh_session_id: SpaceId,
    history_chain: bool,
    evidence_path: PathBuf,
    #[serde(skip_serializing)]
    original_resources_closed: sync_extend_platform_fs::ClosedWindowsOriginalResources,
}

/// Verification or acquisition failure never consumes an acquired original
/// node merely to report an error. The owning child retains this actual value.
pub struct DeploymentNodeRuntimeOpenFailure {
    pub error: ReconcileError,
    pub original_node: Option<RecoveredLocalSpace>,
    pub native_acquisition_attempted: bool,
}

pub struct DeploymentNodeRuntimeCloseFailure {
    pub error: ReconcileError,
    pub original_node: Option<RecoveredLocalSpace>,
    pub original_resource_terminal: Option<crate::DeploymentFreshNodeResourceCloseFailure>,
    pub complete_native_close_verified: bool,
    original_closed_prefix: Vec<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
}

impl DeploymentNodeRuntimeCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_node.is_some()
            || self
                .original_resource_terminal
                .as_ref()
                .is_some_and(crate::DeploymentFreshNodeResourceCloseFailure::has_retained_originals)
    }

    /// The failed generation never becomes reusable closed history. Only the
    /// same retained native originals may be ended by this consuming retry.
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original_node.take() {
            match original.close_failed_deployment_runtime() {
                Ok(closed) => self.original_closed_prefix.push(closed),
                Err(mut later) => {
                    self.original_node = later.original_node.take();
                    self.original_resource_terminal = later.original_resource_terminal.take();
                    self.original_closed_prefix
                        .append(&mut later.original_closed_prefix);
                }
            }
        }
        if let Some(original) = self.original_resource_terminal.take() {
            self.original_resource_terminal = Some(original.close_remaining());
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl DeploymentClosedNodeRuntime {
    pub fn evidence_path(&self) -> &Path {
        &self.evidence_path
    }
}

impl RecoveredLocalSpace {
    pub(crate) fn request_deployment_native_mutations(&mut self) -> Result<()> {
        self.session.request_deployment_native_mutations()
    }
    pub(crate) fn deployment_polling_limits(&self) -> Option<serde_json::Value> {
        self.session.polling_limits()
    }
    pub(crate) fn enable_deployment_polling(&mut self, limits: sync_extend_core_model::limits::LocalLimits) -> Result<()> {
        self.session.enable_deployment_polling(limits)
    }
    pub(crate) fn scan_deployment_polling(&mut self, timestamp: u64) -> Result<crate::ScanResult> {
        self.session.scan_deployment_polling(timestamp)
    }
    pub(crate) fn release_polling_observation(&mut self) -> Result<()> {
        self.session.release_polling_observation()
    }
    /// Explicit resource terminal for an owned failed runtime. It grants no
    /// usable closure/history receipt or restart path, and changes no pathname.
    /// Failure leaves the same actual object with its owning child.
    pub fn close_failed_deployment_connection(&mut self) -> Result<()> {
        self.closed = true;
        self.session.close_failed_deployment_connection()
    }

    pub fn close_failed_deployment_runtime(
        mut self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        DeploymentNodeRuntimeCloseFailure,
    > {
        self.closed = true;
        match self.session.close_failed_deployment_original_resources() {
            Ok(closed) => Ok(closed),
            Err(original) => Err(DeploymentNodeRuntimeCloseFailure {
                error: ReconcileError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    original.error.to_string(),
                )),
                original_node: None,
                original_resource_terminal: Some(original),
                complete_native_close_verified: false,
                original_closed_prefix: Vec::new(),
            }),
        }
    }

    pub fn read_file_bytes(&self, path: &PortablePath, max_bytes: u64) -> Result<Vec<u8>> {
        self.verify()?;
        self.session.recovered_local_file_bytes(path, max_bytes)
    }

    pub(crate) fn deployment_runtime_binding(
        &self,
    ) -> Result<crate::node_archive::DeploymentFreshNodeBinding<'_>> {
        self.verify()?;
        self.session.deployment_runtime_binding()
    }

    pub fn close_deployment_runtime(
        mut self,
    ) -> std::result::Result<DeploymentClosedNodeRuntime, DeploymentNodeRuntimeCloseFailure> {
        let mut first_error = self.session.finish_deployment_polling().err();
        if first_error.is_none() { first_error = self.verify().err(); }
        let evidence = (|| -> Result<_> {
            let actual = self.session.deployment_runtime_binding()?;
            Ok((
                actual.archive_digest().clone(),
                actual.space_id().clone(),
                actual.data_dir().to_path_buf(),
                actual.worktree().to_path_buf(),
                actual.fresh_session_id().clone(),
            ))
        })();
        let evidence = match evidence {
            Ok(evidence) => Some(evidence),
            Err(error) => {
                first_error.get_or_insert(error);
                None
            }
        };
        // Even a first verification error does not skip the real close call.
        // A poisoned/changed core session may refuse; its original object is
        // then returned below, never reduced to a failed ID or silently dropped.
        let closed = self.session.close_deployment_runtime();
        let closed = match closed {
            Ok(closed) => {
                self.closed = true;
                if let Err(error) = self.session.verify() {
                    first_error.get_or_insert(error);
                }
                Some(closed)
            }
            Err(error) => {
                first_error.get_or_insert(error);
                None
            }
        };
        if evidence.is_none() || closed.is_none() {
            first_error.get_or_insert(ReconcileError::Invariant(
                "actual native close has no verified original deployment binding",
            ));
        }
        // A SQLite/history close alone is insufficient. Consume the complete
        // original native session and every surrounding owning resource before
        // constructing any reusable closed deployment generation.
        let terminal = if first_error.is_some() {
            self.session.close_failed_deployment_original_resources()
        } else {
            self.session.close_deployment_original_resources()
        };
        let original_resources_closed = match terminal {
            Ok(closed) => closed,
            Err(original) => {
                let error = first_error.unwrap_or_else(|| {
                    ReconcileError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        original.error.to_string(),
                    ))
                });
                return Err(DeploymentNodeRuntimeCloseFailure {
                    error,
                    original_node: None,
                    original_resource_terminal: Some(original),
                    complete_native_close_verified: false,
                    original_closed_prefix: Vec::new(),
                });
            }
        };
        if let Some(error) = first_error {
            return Err(DeploymentNodeRuntimeCloseFailure {
                error,
                original_node: None,
                original_resource_terminal: None,
                complete_native_close_verified: true,
                original_closed_prefix: vec![original_resources_closed],
            });
        }
        let (archive_digest, space_id, data_dir, worktree, fresh_session_id) =
            evidence.expect("the verified original binding was checked before terminal");
        let (history_chain, evidence_path) =
            closed.expect("the original history close was checked before terminal");
        Ok(DeploymentClosedNodeRuntime {
            archive_digest,
            space_id,
            data_dir,
            worktree,
            fresh_session_id,
            history_chain,
            evidence_path,
            original_resources_closed,
        })
    }
}

impl VerifiedNodeStateArchive {
    /// Every Run obtains a new complete native R06 acquisition. The retained
    /// files do not create this session and prior closed evidence never acts as
    /// live completion authority.
    #[allow(clippy::too_many_arguments)]
    pub fn open_deployment_runtime(
        &self,
        worktree: &Path,
        data: &Path,
        original_frames: &Path,
        restore_ledger: &Path,
        previous: Option<&DeploymentClosedNodeRuntime>,
        inspection: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: crate::LedgerBounds,
    ) -> std::result::Result<RecoveredLocalSpace, DeploymentNodeRuntimeOpenFailure> {
        self.open_deployment_runtime_inner(
            worktree,
            data,
            original_frames,
            restore_ledger,
            previous,
            inspection,
            ledger_bounds,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_deployment_runtime_with_configs(
        &self,
        worktree: &Path,
        data: &Path,
        original_frames: &Path,
        restore_ledger: &Path,
        previous: Option<&DeploymentClosedNodeRuntime>,
        inspection: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: crate::LedgerBounds,
        configs: crate::SeparatedDeploymentNodeConfigs,
    ) -> std::result::Result<RecoveredLocalSpace, DeploymentNodeRuntimeOpenFailure> {
        self.open_deployment_runtime_inner(
            worktree,
            data,
            original_frames,
            restore_ledger,
            previous,
            inspection,
            ledger_bounds,
            Some(configs),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_deployment_runtime_inner(
        &self,
        worktree: &Path,
        data: &Path,
        original_frames: &Path,
        restore_ledger: &Path,
        previous: Option<&DeploymentClosedNodeRuntime>,
        inspection: sync_extend_journal::NodeInspectionBounds,
        ledger_bounds: crate::LedgerBounds,
        configs: Option<crate::SeparatedDeploymentNodeConfigs>,
    ) -> std::result::Result<RecoveredLocalSpace, DeploymentNodeRuntimeOpenFailure> {
        if let Some(configs) = &configs {
            configs
                .verify_for_archive(self, worktree, data)
                .map_err(|error| DeploymentNodeRuntimeOpenFailure {
                    error,
                    original_node: None,
                    native_acquisition_attempted: false,
                })?;
        }
        if let Some(previous) = previous {
            if previous.archive_digest != *self.digest()
                || previous.space_id != *self.space()
                || previous.data_dir != data
                || previous.worktree != worktree
            {
                return Err(DeploymentNodeRuntimeOpenFailure {
                    error: ReconcileError::Invariant(
                        "original closed deployment runtime scope differs",
                    ),
                    original_node: None,
                    native_acquisition_attempted: false,
                });
            }
        }
        let session = if let Some(previous) = previous.filter(|previous| previous.history_chain) {
            match configs {
                Some(configs) => self.reacquire_closed_history_chain8_with_mutation_for_deployment(
                    worktree,
                    data,
                    original_frames,
                    restore_ledger,
                    &previous.evidence_path,
                    inspection,
                    ledger_bounds,
                    configs,
                ),
                None => self.reacquire_closed_history_chain8_with_mutation(
                    worktree,
                    data,
                    original_frames,
                    restore_ledger,
                    &previous.evidence_path,
                    inspection,
                    ledger_bounds,
                ),
            }
        } else {
            match (previous, configs) {
                (Some(previous), Some(configs)) => self
                    .reacquire_fresh_closed_node_wal_v2_session_for_deployment(
                        worktree,
                        data,
                        original_frames,
                        restore_ledger,
                        &previous.evidence_path,
                        inspection,
                        ledger_bounds,
                        configs,
                    ),
                (Some(previous), None) => self.reacquire_fresh_closed_node_wal_v2_session(
                    worktree,
                    data,
                    original_frames,
                    restore_ledger,
                    &previous.evidence_path,
                    inspection,
                    ledger_bounds,
                ),
                (None, Some(configs)) => self.reacquire_closed_node_wal_v2_session_for_deployment(
                    worktree,
                    data,
                    original_frames,
                    restore_ledger,
                    inspection,
                    ledger_bounds,
                    configs,
                ),
                (None, None) => self.reacquire_closed_node_wal_v2_session(
                    worktree,
                    data,
                    original_frames,
                    restore_ledger,
                    inspection,
                    ledger_bounds,
                ),
            }
        };
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                return Err(DeploymentNodeRuntimeOpenFailure {
                    error,
                    original_node: None,
                    native_acquisition_attempted: true,
                })
            }
        };
        // No fallible consuming conversion lies between acquisition and the
        // owner of its actual session. Every later error retains this value.
        let mut local = RecoveredLocalSpace {
            session,
            closed: false,
        };
        let committed = (|| -> Result<()> {
            local.session.commit_fresh_session()?;
            local.verify()?;
            let actual = local.deployment_runtime_binding()?;
            if previous
                .is_some_and(|previous| actual.fresh_session_id() == &previous.fresh_session_id)
            {
                return Err(ReconcileError::Invariant(
                    "deployment Run reused an old native session generation",
                ));
            }
            actual.verify()
        })();
        if let Err(error) = committed {
            return Err(DeploymentNodeRuntimeOpenFailure {
                error,
                original_node: Some(local),
                native_acquisition_attempted: true,
            });
        }
        Ok(local)
    }
}
