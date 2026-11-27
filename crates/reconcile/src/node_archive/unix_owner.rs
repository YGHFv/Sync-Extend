//! Actual private roots and independent same-UID provider retained as one scope.
//! No history, restore, publication or restart authority is reconstructed here.
use crate::{DeploymentProtectionProvider, ProtectionProviderKind, ProtectionScope, ReconcileError, Result};
use std::path::Path;
use sync_extend_platform_fs::{ClosedUnixOriginalResources, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure, UnixProtectedArtifactParent};

pub struct OriginalUnixDeploymentScope {
    provider: DeploymentProtectionProvider,
    data: UnixProtectedArtifactParent,
    worktree: UnixProtectedArtifactParent,
}

pub struct OriginalUnixDeploymentScopeOpenFailure {
    pub error: ReconcileError,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for OriginalUnixDeploymentScopeOpenFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalUnixDeploymentScopeOpenFailure")
            .field("error", &self.error)
            .field("original_close_uncertain", &self.original_close.is_some()).finish()
    }
}

/// A closed resource scope is not a node completion or a generation receipt.
pub struct ClosedOriginalUnixDeploymentScope {
    resources: ClosedUnixOriginalResources,
}

impl ClosedOriginalUnixDeploymentScope {
    pub fn actual_closed_descriptors(&self) -> usize {
        self.resources.actual_closed_descriptors()
    }
}

impl OriginalUnixDeploymentScope {
    pub fn acquire(
        data: &Path,
        worktree: &Path,
        independent_key: &Path,
    ) -> std::result::Result<Self, OriginalUnixDeploymentScopeOpenFailure> {
        let mut data_root = None;
        let mut worktree_root = None;
        let mut provider = None;
        let opened = (|| -> Result<()> {
            if !super::protected_artifact::normalized(data)
                || !super::protected_artifact::normalized(worktree)
                || !super::protected_artifact::normalized(independent_key)
                || data.starts_with(worktree) || worktree.starts_with(data)
                || independent_key.starts_with(data) || independent_key.starts_with(worktree)
            {
                return Err(ReconcileError::Invariant("independent Unix roots and provider key scope required"));
            }
            provider = Some(DeploymentProtectionProvider::open_original(independent_key)?);
            data_root = Some(UnixProtectedArtifactParent::open_private(data)?);
            worktree_root = Some(UnixProtectedArtifactParent::open_private(worktree)?);
            let data_key = data_root.as_ref().expect("original data root").key()?;
            let worktree_key = worktree_root.as_ref().expect("original worktree root").key()?;
            if data_key == worktree_key {
                return Err(ReconcileError::Invariant("Unix data and worktree cannot alias one original root"));
            }
            Ok(())
        })();
        if let Err(error) = opened {
            let mut close = UnixOriginalCloseAttempt::new();
            if let Some(worktree) = worktree_root { close.close_artifact_parent(worktree); }
            if let Some(data) = data_root { close.close_artifact_parent(data); }
            if let Some(provider) = provider { close.append_result(provider.close_retaining()); }
            return Err(OriginalUnixDeploymentScopeOpenFailure { error, original_close: close.finish().err() });
        }
        let result = Self { provider: provider.expect("acquired original provider"),
            data: data_root.expect("acquired original data"), worktree: worktree_root.expect("acquired original worktree") };
        if let Err(error) = result.verify() {
            return Err(OriginalUnixDeploymentScopeOpenFailure { error, original_close: result.close().err() });
        }
        Ok(result)
    }

    pub fn verify(&self) -> Result<()> {
        self.provider.verify_original()?;
        self.data.verify_original()?;
        self.worktree.verify_original()?;
        if self.provider.scope().provider != ProtectionProviderKind::UnixSameUidAead
            || self.provider.scope().independent_key_digest.is_none()
            || self.data.key()? == self.worktree.key()?
        {
            return Err(ReconcileError::Invariant("original Unix provider or independent root scope changed"));
        }
        Ok(())
    }

    pub fn provider_scope(&self) -> Result<&ProtectionScope> {
        self.verify()?;
        Ok(self.provider.scope())
    }

    pub fn require_empty_roots(&self) -> Result<()> {
        self.verify()?;
        self.data.require_empty()?;
        self.worktree.require_empty()?;
        self.verify()
    }

    pub fn close(self) -> std::result::Result<ClosedOriginalUnixDeploymentScope, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify() { close.note_error(std::io::Error::other(error.to_string())); }
        close.close_artifact_parent(self.worktree);
        close.close_artifact_parent(self.data);
        close.append_result(self.provider.close_retaining());
        close.finish().map(|resources| ClosedOriginalUnixDeploymentScope { resources })
    }
}
