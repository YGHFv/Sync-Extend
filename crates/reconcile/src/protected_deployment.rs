//! Version-2 protected deployments have an independent framing and authority
//! boundary. A decoded manifest never grants native node or service ownership.
#[path = "node_archive/deployment_bundle.rs"]
mod deployment_bundle;
#[path = "node_archive/deployment_install.rs"]
mod deployment_install;
#[path = "node_archive/deployment_export.rs"]
mod deployment_export;
#[cfg(windows)]
#[path = "node_archive/deployment_runtime.rs"]
mod deployment_runtime;
#[path = "node_archive/protected_artifact.rs"]
mod protected_artifact;
#[cfg(windows)]
#[path = "node_archive/deployment_capture.rs"]
mod deployment_capture;
#[cfg(windows)]
pub use deployment_capture::{
    ClosedStoppedDeploymentCaptureSource, StoppedDeploymentCaptureCloseFailure,
    StoppedDeploymentCaptureSource,
};

pub use deployment_bundle::{
    CapturedDeploymentNode, DeploymentArtifactDescriptor, DeploymentArtifactRole,
    DeploymentBundleBounds, DeploymentMapping, DeploymentNodeDescriptor, DeploymentNodeTarget,
    DeploymentReference, DeploymentReferenceTarget, DeploymentSelectedArtifact,
    DeploymentSelection, FramedDeploymentBundle, RestrictedDeploymentMapping,
    SelectedDeploymentGraph, VerifiedDeploymentBundle,
};
#[cfg(windows)]
pub use deployment_bundle::{
    DeploymentBundleCaptureFailure, DeploymentBundleVerificationFailure, DeploymentMappingFailure,
    DeploymentNodeRestoreInput,
    PreparedDeploymentNodeRestore, SeparatedDeploymentNodeConfigs,
};
pub use deployment_install::{
    CompleteDeploymentInstall, DeploymentFailedFileReceipt, DeploymentFileAttempt,
    DeploymentFileReceipt, DeploymentFileRetentionFailure, DeploymentInstallFailure,
    DeploymentInstallReceipt,
    DeploymentFilesystemLiability,
    DeploymentNodeCompletionReceipt, OriginalDeploymentInstallAttempt,
    OriginalDeploymentNodeCompletion, PreparedDeploymentInstall, PreparedDeploymentTargets,
    RetainedInstalledDeploymentFiles,
};
#[cfg(windows)]
pub use deployment_install::{
    DeploymentCompletionPreflightFailure, DeploymentTargetsPreflightFailure,
};
#[cfg(windows)]
pub use deployment_runtime::{
    DeploymentFreshRuntimeNodeReceipt, DeploymentRun, DeploymentRuntimeCloseFailure,
    DeploymentRuntimeStartFailure,
};
pub use deployment_export::{
    DeploymentBundleExportFailure, DeploymentBundleExportReceipt, ExportedDeploymentBundle,
    OriginalDeploymentBundleExportAttempt,
};
pub use protected_artifact::{
    DeploymentProtectionProvider, OriginalProtectedArtifact, ProtectedArtifactBinding,
    ProtectedArtifactRole, ProtectionProviderKind, ProtectionScope, VerifiedProtectedArtifact,
};
#[cfg(windows)]
pub use protected_artifact::OriginalProtectedArtifactOpenFailure;

#[cfg(windows)]
type NativeParent = sync_extend_platform_fs::WindowsProtectedArtifactParent;
#[cfg(target_os = "linux")]
type NativeParent = sync_extend_platform_fs::UnixProtectedArtifactParent;
#[cfg(windows)]
type NativeCreator = sync_extend_platform_fs::WindowsProtectedArtifactCreator;
#[cfg(target_os = "linux")]
type NativeCreator = sync_extend_platform_fs::UnixProtectedArtifactCreator;
#[cfg(windows)]
type NativeSealed = sync_extend_platform_fs::SealedWindowsProtectedArtifact;
#[cfg(target_os = "linux")]
type NativeSealed = sync_extend_platform_fs::SealedUnixProtectedArtifact;
#[cfg(windows)]
type NativeFailedCreate = sync_extend_platform_fs::WindowsFailedArtifactCreation;
#[cfg(target_os = "linux")]
type NativeFailedCreate = sync_extend_platform_fs::UnixFailedArtifactCreation;
