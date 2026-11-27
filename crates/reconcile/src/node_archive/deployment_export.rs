//! Bounded bundle export retains real private CREATE lineage and failed objects.
use super::{
    deployment_bundle::VerifiedDeploymentBundle,
    deployment_install::{component, parent_key, sealed_key},
    protected_artifact::{normalized, DeploymentProtectionProvider},
    NativeCreator, NativeFailedCreate, NativeParent, NativeSealed,
};
use crate::{
    path_comparison::{path_equal, path_within},
    ReconcileError, Result,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use sync_extend_core_model::ContentId;

#[derive(Serialize)]
pub struct DeploymentBundleExportReceipt {
    pub format_version: u32,
    pub bundle_digest: ContentId,
    pub target: PathBuf,
    pub bytes: u64,
    pub original_private_create_happened: bool,
    pub original_key: Option<String>,
    pub original_parent_key: Option<String>,
    pub original_sync_readback_and_read_scope_verified: bool,
    pub services_started: bool,
}

pub struct OriginalDeploymentBundleExportAttempt {
    bundle: VerifiedDeploymentBundle,
    target: PathBuf,
    parent: Option<NativeParent>,
    failed_create: Option<NativeFailedCreate>,
    creator: Option<NativeCreator>,
    sealed: Option<NativeSealed>,
    complete: bool,
}

pub struct DeploymentBundleExportFailure {
    pub error: ReconcileError,
    pub original_attempt: OriginalDeploymentBundleExportAttempt,
}

pub struct ExportedDeploymentBundle {
    original: OriginalDeploymentBundleExportAttempt,
}

impl VerifiedDeploymentBundle {
    pub fn export_private(
        self,
        provider: &DeploymentProtectionProvider,
        target: &Path,
    ) -> std::result::Result<ExportedDeploymentBundle, DeploymentBundleExportFailure> {
        let mut attempt = OriginalDeploymentBundleExportAttempt {
            bundle: self,
            target: target.to_path_buf(),
            parent: None,
            failed_create: None,
            creator: None,
            sealed: None,
            complete: false,
        };
        let preflight = (|| -> Result<&str> {
            attempt.bundle.reverify_provider(provider)?;
            if !normalized(target)
                || attempt
                    .bundle
                    .graph()
                    .artifacts
                    .iter()
                    .any(|row| path_equal(&row.path, target))
                || attempt.bundle.graph().nodes.iter().any(|node| {
                    path_within(target, &node.data_dir) || path_within(target, &node.worktree)
                })
            {
                return Err(ReconcileError::Invariant("exact external new deployment bundle target"));
            }
            let name = component(target)?;
            attempt.parent = Some(NativeParent::open_private(target.parent()
                .ok_or(ReconcileError::Invariant("deployment bundle private parent"))?)?);
            let parent = attempt.parent.as_ref()
                .ok_or(ReconcileError::Invariant("actual bundle parent was not retained"))?;
            parent.require_absent(name)?;
            let (available, unit) = parent.available_space()?;
            let bytes = attempt.bundle.framing.bytes().len() as u64;
            attempt.bundle.bounds.memory([bytes, bytes, attempt.bundle.bounds.plaintext_bytes])?;
            let rounded = bytes.checked_add(unit.checked_sub(1)
                .ok_or(ReconcileError::Invariant("actual bundle allocation unit is zero"))?)
                .and_then(|bytes| bytes.checked_div(unit))
                .and_then(|count| count.checked_mul(unit))
                .ok_or(ReconcileError::ResourceLimit("deployment bundle allocation rounding"))?;
            if available < rounded {
                return Err(ReconcileError::ResourceLimit("actual bundle export available bytes"));
            }
            Ok(name)
        })();
        let name = match preflight {
            Ok(name) => name,
            Err(error) => return Err(DeploymentBundleExportFailure { error, original_attempt: attempt }),
        };
        let Some(parent) = attempt.parent.as_ref() else {
            return Err(DeploymentBundleExportFailure {
                error: ReconcileError::Invariant("preflight retained bundle parent absent"),
                original_attempt: attempt,
            });
        };
        let mut creator = match parent.create_new(name) {
            Ok(creator) => creator,
            Err(failure) => {
                attempt.failed_create = failure.original_created;
                return Err(DeploymentBundleExportFailure {
                    error: failure.error.into(), original_attempt: attempt,
                });
            }
        };
        if let Err(error) = creator.write_and_sync(attempt.bundle.framing.bytes()) {
            attempt.creator = Some(creator);
            return Err(DeploymentBundleExportFailure { error: error.into(), original_attempt: attempt });
        }
        let sealed = match creator.seal(attempt.bundle.framing.bytes()) {
            Ok(sealed) => sealed,
            Err(failure) => {
                attempt.creator = Some(failure.original_creator);
                return Err(DeploymentBundleExportFailure {
                    error: failure.error.into(), original_attempt: attempt,
                });
            }
        };
        attempt.sealed = Some(sealed);
        if let Err(error) = attempt.verify(provider) {
            return Err(DeploymentBundleExportFailure { error, original_attempt: attempt });
        }
        attempt.complete = true;
        Ok(ExportedDeploymentBundle { original: attempt })
    }
}

impl OriginalDeploymentBundleExportAttempt {
    fn verify(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.bundle.reverify_provider(provider)?;
        let parent = self.parent.as_ref()
            .ok_or(ReconcileError::Invariant("original bundle export parent absent"))?;
        parent.verify_original()?;
        let file = self.sealed.as_ref()
            .ok_or(ReconcileError::Invariant("original bundle export read scope absent"))?;
        file.verify_original(self.bundle.framing.bytes())?;
        self.bundle.reverify_provider(provider)
    }
    pub fn receipt(&self) -> DeploymentBundleExportReceipt {
        DeploymentBundleExportReceipt {
            format_version: 2,
            bundle_digest: self.bundle.digest().clone(),
            target: self.target.clone(),
            bytes: self.bundle.framing.bytes().len() as u64,
            original_private_create_happened:
                self.failed_create.is_some() || self.creator.is_some() || self.sealed.is_some(),
            original_key: self.sealed.as_ref().map(sealed_key),
            original_parent_key: self.parent.as_ref().and_then(|parent| parent_key(parent).ok()),
            original_sync_readback_and_read_scope_verified: self.complete,
            services_started: false,
        }
    }
    #[cfg(not(windows))]
    pub fn close(self) -> Result<DeploymentBundleExportReceipt> {
        let receipt = self.receipt();
        let Self { sealed, creator, failed_create, parent, .. } = self;
        let mut first_error = None;
        if let Some(file) = sealed {
            if let Err(error) = file.close() { first_error = Some(error); }
        }
        if let Some(file) = creator {
            if let Err(error) = file.close() { first_error.get_or_insert(error); }
        }
        if let Some(file) = failed_create {
            if let Err(error) = file.close() { first_error.get_or_insert(error); }
        }
        if let Some(parent) = parent {
            if let Err(error) = parent.close() { first_error.get_or_insert(error); }
        }
        if let Some(error) = first_error { return Err(error.into()); }
        Ok(receipt)
    }

    #[cfg(windows)]
    pub fn close(self) -> Result<DeploymentBundleExportReceipt> {
        self.close_retaining()
            .map_err(|original| ReconcileError::Io(original.retain_and_report()))
    }

    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        DeploymentBundleExportReceipt,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        let receipt = self.receipt();
        let Self { sealed, creator, failed_create, parent, mut bundle, .. } = self;
        let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        if let Some(original) = sealed {
            close.append_result(original.close_retaining());
        }
        if let Some(original) = creator {
            close.append_result(original.close_retaining());
        }
        if let Some(original) = failed_create {
            close.append_result(original.close_retaining());
        }
        if let Some(original) = parent {
            close.close_artifact_parent(original);
        }
        bundle.framing.close_original_sources_into(&mut close);
        close.finish()?;
        Ok(receipt)
    }
}

impl ExportedDeploymentBundle {
    pub fn receipt(&self) -> DeploymentBundleExportReceipt { self.original.receipt() }
    pub fn verify(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        if !self.original.complete {
            return Err(ReconcileError::Invariant("actual private bundle export incomplete"));
        }
        self.original.verify(provider)
    }
    pub fn close(self) -> Result<DeploymentBundleExportReceipt> { self.original.close() }
    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        DeploymentBundleExportReceipt,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        self.original.close_retaining()
    }
}
