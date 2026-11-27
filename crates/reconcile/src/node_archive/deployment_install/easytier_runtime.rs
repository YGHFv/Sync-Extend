//! Same-installed-graph preparation for the node-free recovered sidecar role.
use super::super::deployment_bundle::DeploymentDocument;
use super::*;
use sync_extend_core_model::{deployment::DeploymentRole, easytier::EasyTierConfig};
use sync_extend_platform_fs::{PinnedProgram, SidecarConfig, WindowsOriginalResourceOpenFailure};

/// The whole installation and provider remain borrowed through actual shutdown.
/// Neither a path nor serialized configuration can construct this authority.
pub struct InstalledEasyTierRuntime<'installation> {
    files: &'installation RetainedInstalledDeploymentFiles,
    provider: &'installation DeploymentProtectionProvider,
    config: EasyTierConfig,
    seconds: u64,
    core: &'installation OriginalProtectedArtifact,
    cli: &'installation OriginalProtectedArtifact,
    state: &'installation NativeParent,
}

impl RetainedInstalledDeploymentFiles {
    pub fn prepare_installed_easytier<'installation>(
        &'installation self,
        provider: &'installation DeploymentProtectionProvider,
    ) -> Result<InstalledEasyTierRuntime<'installation>> {
        self.verify(provider)?;
        let root = self
            .mapping
            .mapped_documents
            .get(&self.mapping.mapped_graph.root_deployment);
        let Some(DeploymentDocument::Deployment(root)) = root else {
            return Err(ReconcileError::Invariant(
                "actual installed deployment absent",
            ));
        };
        let DeploymentRole::EasyTier {
            config: path,
            seconds,
        } = &root.role
        else {
            return Err(ReconcileError::Invariant(
                "installed EasyTier role required",
            ));
        };
        let artifact = self
            .mapping
            .mapped_graph
            .artifacts
            .iter()
            .find(|artifact| &artifact.path == path)
            .ok_or(ReconcileError::Invariant(
                "installed EasyTier config reference absent",
            ))?;
        let Some(DeploymentDocument::EasyTier(config)) =
            self.mapping.mapped_documents.get(&artifact.id)
        else {
            return Err(ReconcileError::Invariant(
                "installed EasyTier configuration absent",
            ));
        };
        config.validate()?;
        if !config.enabled
            || !(1..=86400).contains(seconds)
            || !self.mapping.mapped_graph.nodes.is_empty()
        {
            return Err(ReconcileError::Invariant(
                "explicit bounded node-free EasyTier deployment required",
            ));
        }
        let program = |path: &Path, digest: &ContentId| -> Result<&OriginalProtectedArtifact> {
            let original = self
                .pinned_programs
                .iter()
                .find(|program| program.source_path() == path && program.source_digest() == digest)
                .ok_or(ReconcileError::Invariant(
                    "same installed original executable pin absent",
                ))?;
            original.verify_original()?;
            Ok(original)
        };
        let core = program(&config.core_binary, &config.core_blake3)?;
        let cli = program(&config.cli_binary, &config.cli_blake3)?;
        let state = self
            .runtime_directories
            .iter()
            .find(|directory| directory.path() == config.state_dir)
            .ok_or(ReconcileError::Invariant(
                "same installed original state directory absent",
            ))?;
        state.verify_original()?;
        self.verify(provider)?;
        Ok(InstalledEasyTierRuntime {
            files: self,
            provider,
            config: config.clone(),
            seconds: *seconds,
            core,
            cli,
            state,
        })
    }
}

impl InstalledEasyTierRuntime<'_> {
    pub fn configuration(&self) -> &EasyTierConfig {
        &self.config
    }
    pub fn seconds(&self) -> u64 {
        self.seconds
    }
    pub fn verify(&self) -> Result<()> {
        self.files.verify(self.provider)?;
        self.state.verify_original()?;
        self.core.verify_original()?;
        self.cli.verify_original()
    }
    pub fn duplicate_core(
        &self,
    ) -> std::result::Result<PinnedProgram, WindowsOriginalResourceOpenFailure> {
        self.core.duplicate_pinned_program()
    }
    pub fn duplicate_cli(
        &self,
    ) -> std::result::Result<PinnedProgram, WindowsOriginalResourceOpenFailure> {
        self.cli.duplicate_pinned_program()
    }
    pub fn create_private_configuration(
        &self,
    ) -> std::result::Result<SidecarConfig, WindowsOriginalResourceOpenFailure> {
        self.verify()
            .map_err(|error| WindowsOriginalResourceOpenFailure {
                error: std::io::Error::other(error.to_string()),
                original_resources: None,
            })?;
        let bytes =
            self.config
                .native_config()
                .map_err(|error| WindowsOriginalResourceOpenFailure {
                    error: std::io::Error::other(error.to_string()),
                    original_resources: None,
                })?;
        let original = SidecarConfig::create_in_original_parent(
            self.state,
            self.config.instance_id.as_str(),
            bytes.as_bytes(),
        )?;
        if let Err(error) = self.verify() {
            let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
            original.close_into_attempt(&mut close);
            return Err(WindowsOriginalResourceOpenFailure {
                error: std::io::Error::other(error.to_string()),
                original_resources: close.finish().err(),
            });
        }
        Ok(original)
    }
}
