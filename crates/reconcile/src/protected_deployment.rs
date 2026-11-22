//! Version-2 protected deployments have an independent framing and authority
//! boundary. A decoded manifest never grants native node or service ownership.
#[path = "node_archive/deployment_bundle.rs"]
mod deployment_bundle;
#[path = "node_archive/deployment_install.rs"]
mod deployment_install;
#[path = "node_archive/protected_artifact.rs"]
mod protected_artifact;

pub use deployment_bundle::{
    CapturedDeploymentNode, DeploymentArtifactDescriptor, DeploymentArtifactRole,
    DeploymentBundleBounds, DeploymentMapping, DeploymentNodeDescriptor, DeploymentNodeTarget,
    DeploymentReference, DeploymentReferenceTarget, DeploymentSelectedArtifact,
    DeploymentSelection, FramedDeploymentBundle, RestrictedDeploymentMapping,
    SelectedDeploymentGraph, VerifiedDeploymentBundle,
};
pub use deployment_install::{
    CompleteDeploymentInstall, DeploymentFailedFileReceipt, DeploymentFileAttempt,
    DeploymentFileReceipt, DeploymentInstallFailure, DeploymentInstallReceipt,
    DeploymentNodeCompletionReceipt, OriginalDeploymentInstallAttempt,
    OriginalDeploymentNodeCompletion, PreparedDeploymentInstall,
};
pub use protected_artifact::{
    DeploymentProtectionProvider, OriginalProtectedArtifact, ProtectedArtifactBinding,
    ProtectedArtifactRole, ProtectionProviderKind, ProtectionScope, VerifiedProtectedArtifact,
};
