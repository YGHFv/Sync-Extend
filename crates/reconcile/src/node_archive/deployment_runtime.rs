//! Explicit runtime composition joins retained installed originals to actual
//! freshly acquired R06 nodes. Serialized installation history has no entry.
use super::{
    deployment_bundle::DeploymentDocument, deployment_install::RetainedInstalledDeploymentFiles,
    protected_artifact::DeploymentProtectionProvider,
};
use crate::{DeploymentClosedNodeRuntime, ReconcileError, RecoveredLocalSpace, Result};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};
use sync_extend_core_model::{
    deployment::{DeploymentConfig, DeploymentGatewayConfig, DeploymentRole},
    management::ManagementConfig,
    ContentId, DeviceId, Manifest, PortablePath, SpaceId,
};

#[path = "deployment_runtime/actors.rs"]
mod actors;

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DeploymentFreshRuntimeNodeReceipt {
    pub id: u32,
    pub archive_digest: ContentId,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub data_dir: PathBuf,
    pub worktree: PathBuf,
    pub data_key: String,
    pub worktree_key: String,
    pub fresh_session_id: SpaceId,
    pub native_journal_keys: [String; 4],
}

pub struct DeploymentRuntimeStartFailure {
    pub error: ReconcileError,
    pub original_nodes: Vec<(u32, RecoveredLocalSpace)>,
}

pub struct DeploymentRuntimeCloseFailure {
    pub error: ReconcileError,
    pub actual_closed_history: BTreeMap<u32, DeploymentClosedNodeRuntime>,
    pub failed_node_ids: Vec<u32>,
    pub original_failed_nodes: Vec<(u32, crate::DeploymentNodeRuntimeCloseFailure)>,
}

/// Both inputs are sealed live objects. No public constructor accepts an
/// installation receipt, descriptor, ordinary LocalSpace or path-only node.
pub struct DeploymentRun<'authority> {
    files: &'authority RetainedInstalledDeploymentFiles,
    provider: &'authority DeploymentProtectionProvider,
    nodes: BTreeMap<u32, RecoveredLocalSpace>,
    original_fresh_bindings: BTreeMap<u32, DeploymentFreshRuntimeNodeReceipt>,
    polling: BTreeMap<u32, std::time::Instant>,
    polling_interval: Option<std::time::Duration>,
}

fn original_fresh_binding(
    files: &RetainedInstalledDeploymentFiles,
    id: u32,
    local: &RecoveredLocalSpace,
) -> Result<DeploymentFreshRuntimeNodeReceipt> {
    let descriptor = files.mapping.original.graph.node(id)?;
    let installed = files
        .receipt
        .nodes
        .iter()
        .find(|node| node.id == id)
        .ok_or(ReconcileError::Invariant(
            "actual installed node completion binding absent",
        ))?;
    let target = files
        .mapping
        .mapping
        .node_roots
        .get(&id)
        .ok_or(ReconcileError::Invariant(
            "actual installed node mapping absent",
        ))?;
    let actual = local.deployment_runtime_binding()?;
    if actual.archive_digest() != &descriptor.archive_digest
        || actual.space_id() != &descriptor.space_id
        || actual.device_id()? != descriptor.device_id
        || actual.data_dir() != target.data_dir
        || actual.worktree() != target.worktree
        || actual.data_key()? != installed.data_key
        || actual.worktree_key()? != installed.worktree_key
    {
        return Err(ReconcileError::Invariant(
            "fresh runtime differs from actual original installation",
        ));
    }
    let receipt = DeploymentFreshRuntimeNodeReceipt {
        id,
        archive_digest: actual.archive_digest().clone(),
        space_id: actual.space_id().clone(),
        device_id: actual.device_id()?,
        data_dir: actual.data_dir().to_path_buf(),
        worktree: actual.worktree().to_path_buf(),
        data_key: actual.data_key()?,
        worktree_key: actual.worktree_key()?,
        fresh_session_id: actual.fresh_session_id().clone(),
        native_journal_keys: actual.native_journal_keys()?,
    };
    actual.verify()?;
    Ok(receipt)
}

impl RetainedInstalledDeploymentFiles {
    /// Values are obtained from the still-held verified installation. They
    /// permit role/TLS/credential checks before any fresh native node effect.
    pub fn deployment_configuration(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<DeploymentConfig> {
        self.verify(provider)?;
        let config = match self
            .mapping
            .mapped_documents
            .get(&self.mapping.mapped_graph.root_deployment)
        {
            Some(DeploymentDocument::Deployment(config)) => config.clone(),
            _ => {
                return Err(ReconcileError::Invariant(
                    "actual installed root deployment configuration absent",
                ))
            }
        };
        self.verify(provider)?;
        Ok(config)
    }

    pub fn gateway_configuration(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<DeploymentGatewayConfig> {
        let config = self.deployment_configuration(provider)?;
        let DeploymentRole::WebdavClient { gateway_config, .. } = &config.role else {
            return Err(ReconcileError::Invariant(
                "installed deployment does not select a recovered WebDAV runtime",
            ));
        };
        let artifact = self
            .mapping
            .mapped_graph
            .artifacts
            .iter()
            .find(|artifact| &artifact.path == gateway_config)
            .ok_or(ReconcileError::Invariant(
                "actual installed WebDAV reference absent",
            ))?;
        let gateway = match self.mapping.mapped_documents.get(&artifact.id) {
            Some(DeploymentDocument::Gateway(gateway)) => gateway.clone(),
            _ => {
                return Err(ReconcileError::Invariant(
                    "actual installed WebDAV configuration absent",
                ))
            }
        };
        self.verify(provider)?;
        Ok(gateway)
    }

    pub fn management_configuration(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Option<ManagementConfig>> {
        let config = self.deployment_configuration(provider)?;
        let Some(path) = &config.management else {
            return Ok(None);
        };
        let artifact = self
            .mapping
            .mapped_graph
            .artifacts
            .iter()
            .find(|artifact| &artifact.path == path)
            .ok_or(ReconcileError::Invariant(
                "actual installed management reference absent",
            ))?;
        let management = match self.mapping.mapped_documents.get(&artifact.id) {
            Some(DeploymentDocument::Management(management)) => management.clone(),
            _ => {
                return Err(ReconcileError::Invariant(
                    "actual installed management configuration absent",
                ))
            }
        };
        self.verify(provider)?;
        Ok(Some(management))
    }

    pub fn bind_fresh_runtime_nodes<'authority>(
        &'authority self,
        provider: &'authority DeploymentProtectionProvider,
        nodes: Vec<(u32, RecoveredLocalSpace)>,
    ) -> std::result::Result<DeploymentRun<'authority>, DeploymentRuntimeStartFailure> {
        let verified = (|| -> Result<BTreeMap<u32, DeploymentFreshRuntimeNodeReceipt>> {
            self.verify(provider)?;
            if nodes.len() != self.mapping.original.graph.nodes.len() || nodes.len() > 64 {
                return Err(ReconcileError::ResourceLimit(
                    "exact bounded actual fresh deployment node set",
                ));
            }
            let mut bindings = BTreeMap::new();
            for (id, local) in &nodes {
                if bindings
                    .insert(*id, original_fresh_binding(self, *id, local)?)
                    .is_some()
                {
                    return Err(ReconcileError::Invariant(
                        "duplicate actual fresh deployment node",
                    ));
                }
            }
            if bindings
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                != self
                    .mapping
                    .original
                    .graph
                    .nodes
                    .iter()
                    .map(|node| node.id)
                    .collect()
            {
                return Err(ReconcileError::Invariant(
                    "actual fresh deployment node membership differs",
                ));
            }
            self.verify(provider)?;
            Ok(bindings)
        })();
        match verified {
            Ok(original_fresh_bindings) => Ok(DeploymentRun {
                files: self,
                provider,
                nodes: nodes.into_iter().collect(),
                original_fresh_bindings,
                polling: BTreeMap::new(),
                polling_interval: None,
            }),
            Err(error) => Err(DeploymentRuntimeStartFailure {
                error,
                original_nodes: nodes,
            }),
        }
    }
}

impl DeploymentRun<'_> {
    /// This intent derives only from this generation's still-held installation.
    /// Actual WRITE/DELETE rights require fresh native acquisition on each actor
    /// path; every actor separately verifies the original account and target.
    pub fn start_configured_native_mutations(&mut self) -> Result<()> {
        self.verify()?;
        if !matches!(self.deployment_configuration()?.role, DeploymentRole::WebdavClient { .. }) {
            return Ok(());
        }
        let gateway = self.gateway_configuration()?;
        if !gateway.listener.enabled { return Ok(()); }
        let spaces = gateway.listener.exports.iter()
            .filter(|export| export.writable && export.allow_native_windows_writes
                && gateway.listener.accounts.iter().any(|account| account.writable_exports.contains(&export.name)))
            .map(|export| export.space_id.clone()).collect::<std::collections::BTreeSet<_>>();
        for space in spaces {
            let id = self.node_id(&space)?;
            self.nodes.get_mut(&id).ok_or(ReconcileError::Unstable)?.request_deployment_native_mutations()?;
        }
        self.verify()
    }

    /// Only the same retained configuration selects spaces and the interval.
    /// There is no public path/identity based polling capability constructor.
    pub fn start_configured_polling(&mut self, limits: sync_extend_core_model::limits::LocalLimits) -> Result<()> {
        self.verify()?;
        let config = self.deployment_configuration()?;
        let (interval, ids) = match config.role {
            DeploymentRole::LocalPolling { data_dir, scan_interval_secs } => {
                let ids = self.original_fresh_bindings.iter().filter(|(_, binding)| crate::node_archive::portable_source::path_equal(&binding.data_dir, &data_dir))
                    .map(|(id, _)| *id).collect::<Vec<_>>();
                if ids.len() != 1 { return Err(ReconcileError::Invariant("polling requires the exact configured node")); }
                (scan_interval_secs, ids)
            }
            DeploymentRole::WebdavClient { scan_interval_secs: Some(interval), .. } => {
                let gateway = self.gateway_configuration()?;
                let spaces: std::collections::BTreeSet<_> = gateway.listener.exports.iter().map(|export| &export.space_id).collect();
                let ids = spaces.into_iter().map(|space| self.node_id(space)).collect::<Result<Vec<_>>>()?;
                (interval, ids)
            }
            _ => return Ok(()),
        };
        if !(1..=86_400).contains(&interval) || self.polling_interval.is_some() { return Err(ReconcileError::Invariant("explicit finite original polling interval")); }
        self.polling_interval = Some(std::time::Duration::from_secs(interval));
        for id in ids {
            let node = self.nodes.get_mut(&id).ok_or(ReconcileError::Unstable)?;
            node.enable_deployment_polling(limits.clone())?;
            node.scan_deployment_polling(crate::now_ms()?)?;
            node.release_polling_observation()?;
            self.polling.insert(id, std::time::Instant::now().checked_add(std::time::Duration::from_secs(interval)).ok_or(ReconcileError::ResourceLimit("polling deadline overflow"))?);
        }
        self.verify()
    }
    /// At most one due space per owner turn. Scheduling starts after completion
    /// so a slow scan never accumulates catch-up bursts.
    pub fn poll_configured_space(&mut self) -> Result<Option<crate::ScanResult>> {
        let Some(interval) = self.polling_interval else { return Ok(None); };
        let now = std::time::Instant::now();
        let next = self.polling.iter().filter(|(_, due)| **due <= now).min_by_key(|(_, due)| **due).map(|(id, _)| *id);
        let Some(id) = next else { return Ok(None); };
        self.verify()?;
        let node = self.nodes.get_mut(&id).ok_or(ReconcileError::Unstable)?;
        let result = node.scan_deployment_polling(crate::now_ms()?)?;
        node.release_polling_observation()?;
        self.polling.insert(id, std::time::Instant::now().checked_add(interval).ok_or(ReconcileError::ResourceLimit("polling deadline overflow"))?);
        self.verify()?;
        Ok(Some(result))
    }
    pub fn prepare_gateway_observation(&mut self) -> Result<()> {
        let ids = self.polling.keys().copied().collect::<Vec<_>>();
        for id in ids { self.nodes.get_mut(&id).ok_or(ReconcileError::Unstable)?.scan_deployment_polling(crate::now_ms()?)?; }
        self.verify()
    }
    pub fn release_gateway_observation(&mut self) -> Result<()> {
        let ids = self.polling.keys().copied().collect::<Vec<_>>();
        for id in ids { self.nodes.get_mut(&id).ok_or(ReconcileError::Unstable)?.release_polling_observation()?; }
        self.verify()
    }
    pub fn verify(&self) -> Result<()> {
        self.files.verify(self.provider)?;
        if self.nodes.len() != self.original_fresh_bindings.len() {
            return Err(ReconcileError::Invariant(
                "fresh deployment runtime node membership changed",
            ));
        }
        for (id, local) in &self.nodes {
            let actual = original_fresh_binding(self.files, *id, local)?;
            if self.original_fresh_bindings.get(id) != Some(&actual) {
                return Err(ReconcileError::Invariant(
                    "actual deployment fresh session binding changed",
                ));
            }
        }
        self.files.verify(self.provider)
    }

    pub fn fresh_nodes(&self) -> Result<Vec<DeploymentFreshRuntimeNodeReceipt>> {
        self.verify()?;
        Ok(self.original_fresh_bindings.values().cloned().collect())
    }

    pub fn deployment_configuration(&self) -> Result<DeploymentConfig> {
        self.verify()?;
        let config = self.files.deployment_configuration(self.provider)?;
        self.verify()?;
        Ok(config)
    }

    pub fn gateway_configuration(&self) -> Result<DeploymentGatewayConfig> {
        self.verify()?;
        let gateway = self.files.gateway_configuration(self.provider)?;
        self.verify()?;
        Ok(gateway)
    }

    pub fn management_configuration(&self) -> Result<Option<ManagementConfig>> {
        self.verify()?;
        let management = self.files.management_configuration(self.provider)?;
        self.verify()?;
        Ok(management)
    }

    fn node_id(&self, space: &SpaceId) -> Result<u32> {
        self.original_fresh_bindings
            .values()
            .find(|node| &node.space_id == space)
            .map(|node| node.id)
            .ok_or(ReconcileError::Invariant(
                "space is outside the actual fresh deployment",
            ))
    }

    pub fn manifest(&self, space: &SpaceId) -> Result<Manifest> {
        self.verify()?;
        let value = self.nodes[&self.node_id(space)?].manifest()?;
        self.verify()?;
        Ok(value)
    }

    pub fn read_file_bytes(
        &self,
        space: &SpaceId,
        path: &PortablePath,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        self.verify()?;
        let bytes = self.nodes[&self.node_id(space)?].read_file_bytes(path, max_bytes)?;
        self.verify()?;
        Ok(bytes)
    }

    pub fn status(&self) -> Result<serde_json::Value> {
        self.verify()?;
        let mut nodes = Vec::new();
        for (id, local) in &self.nodes {
            nodes.push(serde_json::json!({
                "node_id": id,
                "fresh_session_id": self.original_fresh_bindings[id].fresh_session_id,
                "status": local.status()?,
                "polling_limits": local.deployment_polling_limits(),
            }));
        }
        self.verify()?;
        Ok(serde_json::json!({
            "actual_fresh_native_nodes_verified": true,
            "actual_original_installed_files_verified": true,
            "nodes": nodes,
        }))
    }

    /// The owner must close each real session and use its new closed history
    /// evidence for a subsequent fresh acquisition. Failure disables restart.
    pub fn close(
        self,
    ) -> std::result::Result<
        BTreeMap<u32, DeploymentClosedNodeRuntime>,
        DeploymentRuntimeCloseFailure,
    > {
        let mut first_error = self.verify().err();
        let mut actual_closed_history = BTreeMap::new();
        let mut failed_node_ids = Vec::new();
        let mut original_failed_nodes = Vec::new();
        for (id, local) in self.nodes {
            match local.close_deployment_runtime() {
                Ok(path) => {
                    actual_closed_history.insert(id, path);
                }
                Err(failure) => {
                    if first_error.is_none() {
                        first_error = Some(ReconcileError::Invariant(
                            "actual deployment node close failed; original object retained",
                        ));
                    }
                    failed_node_ids.push(id);
                    original_failed_nodes.push((id, failure));
                }
            }
        }
        match first_error {
            Some(error) => Err(DeploymentRuntimeCloseFailure {
                error,
                actual_closed_history,
                failed_node_ids,
                original_failed_nodes,
            }),
            None => Ok(actual_closed_history),
        }
    }
}
