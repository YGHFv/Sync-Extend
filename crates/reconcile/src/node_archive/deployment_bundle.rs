//! Independent v2 framing and a complete graph derived from strict original
//! documents. Neither framing nor a descriptive node graph grants CREATE,
//! node recovery, listener, credential, or namespace authority.
use super::protected_artifact::{
    normalized, DeploymentProtectionProvider, OriginalProtectedArtifact, ProtectedArtifactBinding,
    ProtectedArtifactRole, ProtectionScope, VerifiedProtectedArtifact,
};
use crate::{ReconcileError, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    config::Config,
    deployment::{DeploymentConfig, DeploymentGatewayConfig, DeploymentPlatform, DeploymentRole},
    easytier::EasyTierConfig,
    management::{ManagementConfig, TokenProtection},
    storage_node::StorageNodeConfig,
    ContentId, DeviceId, EntryId, SpaceId,
};
use sync_extend_transport::{PeerIdentity, SignedTransportAttemptPolicy};

const MAGIC: &[u8; 16] = b"SyncDeployV2\0\0\0\0";
const MAX_ARTIFACTS: usize = 1024;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const MAX_BUNDLE: u64 = 1024 * 1024 * 1024;
const MAX_MEMORY: u64 = 4 * MAX_BUNDLE;
const MAX_DOCUMENT: usize = 1024 * 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBundleBounds {
    pub artifacts: usize,
    pub metadata_bytes: usize,
    pub bundle_bytes: u64,
    pub plaintext_bytes: u64,
    /// Original payloads, envelopes, verification and restricted mapping are
    /// all charged. This is an explicit logical allocation ceiling.
    pub memory_bytes: u64,
}

impl DeploymentBundleBounds {
    pub fn validate(self) -> Result<()> {
        if self.artifacts == 0
            || self.artifacts > MAX_ARTIFACTS
            || self.metadata_bytes == 0
            || self.metadata_bytes > MAX_METADATA
            || self.bundle_bytes == 0
            || self.bundle_bytes > MAX_BUNDLE
            || self.plaintext_bytes == 0
            || self.plaintext_bytes > MAX_BUNDLE
            || self.memory_bytes == 0
            || self.memory_bytes > MAX_MEMORY
        {
            return Err(ReconcileError::ResourceLimit(
                "explicit v2 deployment bounds",
            ));
        }
        Ok(())
    }

    pub(crate) fn memory(self, sizes: impl IntoIterator<Item = u64>) -> Result<()> {
        let sum = sizes
            .into_iter()
            .try_fold(0u64, |sum, size| sum.checked_add(size))
            .ok_or(ReconcileError::ResourceLimit(
                "deployment allocation sum overflow",
            ))?;
        if sum > self.memory_bytes {
            return Err(ReconcileError::ResourceLimit(
                "deployment aggregate memory budget",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentArtifactRole {
    DeploymentConfig,
    NodeConfig,
    GatewayConfig,
    ManagementConfig,
    StorageConfig,
    StorageForwarder,
    TransportAttemptPolicy,
    WebdavCredential,
    ManagementCredential,
    TlsCertificate,
    TlsPrivateKey,
    NodeState,
    EasyTierConfig,
}

impl DeploymentArtifactRole {
    fn maximum(self) -> u64 {
        match self {
            Self::NodeState => MAX_BUNDLE,
            Self::WebdavCredential => 65_536,
            Self::ManagementCredential => 4096,
            Self::DeploymentConfig
            | Self::GatewayConfig
            | Self::ManagementConfig
            | Self::StorageConfig
            | Self::StorageForwarder
            | Self::TransportAttemptPolicy => 65_536,
            _ => MAX_DOCUMENT as u64,
        }
    }

    pub(crate) fn protected(self) -> Option<ProtectedArtifactRole> {
        match self {
            Self::WebdavCredential => Some(ProtectedArtifactRole::WebdavCredential),
            Self::ManagementCredential => Some(ProtectedArtifactRole::ManagementCredential),
            Self::TlsPrivateKey => Some(ProtectedArtifactRole::TlsPrivateKey),
            Self::NodeState => Some(ProtectedArtifactRole::NodeState),
            Self::EasyTierConfig => Some(ProtectedArtifactRole::EasyTierConfig),
            _ => None,
        }
    }

    pub(crate) fn installed(self) -> bool {
        self != Self::NodeState
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSelectedArtifact {
    pub id: u32,
    pub role: DeploymentArtifactRole,
    pub source_path: PathBuf,
    pub max_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSelection {
    pub format_version: u32,
    pub root_deployment: u32,
    pub artifacts: Vec<DeploymentSelectedArtifact>,
}

/// Values describe an actual captured archive. Deserializing these fields
/// cannot construct CapturedDeploymentNode or any installed-node completion.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentNodeDescriptor {
    pub id: u32,
    pub artifact_id: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub data_dir: PathBuf,
    pub worktree: PathBuf,
    pub archive_path: PathBuf,
    pub archive_bytes: u64,
    pub archive_digest: ContentId,
    pub source_schema: u32,
    pub captured_configs: BTreeMap<String, PathBuf>,
}

pub struct CapturedDeploymentNode {
    descriptor: DeploymentNodeDescriptor,
    #[cfg(windows)]
    archive: crate::CapturedNodeArchive,
}

impl CapturedDeploymentNode {
    #[cfg(windows)]
    pub fn capture(
        id: u32,
        artifact_id: u32,
        archive_path: &Path,
        local: &crate::LocalSpace,
        configs: &[(String, PathBuf)],
        archive_bounds: crate::ArchiveBounds,
        inspection: sync_extend_journal::NodeInspectionBounds,
        max_content_hash_bytes: u64,
    ) -> Result<Self> {
        if id == 0
            || artifact_id == 0
            || !normalized(archive_path)
            || archive_path.parent() != Some(local.data_dir.as_path())
            || configs.is_empty()
        {
            return Err(ReconcileError::Invariant(
                "actual selected deployment node scope",
            ));
        }
        let captured_configs: BTreeMap<_, _> = configs.iter().cloned().collect();
        if captured_configs.len() != configs.len() {
            return Err(ReconcileError::Invariant(
                "duplicate actual node config name",
            ));
        }
        let archive = local.capture_node_archive(configs, archive_bounds)?;
        let verified = crate::FramedNodeArchive::verify_framing(
            archive.bytes().to_vec(),
            archive.digest(),
            archive_bounds,
        )?
        .verify_node_state(archive_bounds, inspection, max_content_hash_bytes)?;
        if verified.space() != &local.space_id
            || verified.device() != &local.device_id
            || verified.original_worktree() != local.worktree_path()
            || verified.original_config_data() != Some(local.data_dir.as_path())
        {
            return Err(ReconcileError::Invariant(
                "actual captured node identity/root mismatch",
            ));
        }
        let descriptor = DeploymentNodeDescriptor {
            id,
            artifact_id,
            space_id: local.space_id.clone(),
            device_id: local.device_id.clone(),
            data_dir: local.data_dir.clone(),
            worktree: local.worktree_path().to_path_buf(),
            archive_path: archive_path.to_path_buf(),
            archive_bytes: archive.bytes().len() as u64,
            archive_digest: archive.digest().clone(),
            source_schema: verified.schema(),
            captured_configs,
        };
        Ok(Self {
            descriptor,
            archive,
        })
    }

    pub fn descriptor(&self) -> &DeploymentNodeDescriptor {
        &self.descriptor
    }

    fn original_bytes(&self) -> Result<&[u8]> {
        #[cfg(windows)]
        return Ok(self.archive.bytes());
        #[cfg(not(windows))]
        Err(ReconcileError::Invariant(
            "actual deployment node capture unavailable on this platform",
        ))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentArtifactDescriptor {
    pub id: u32,
    pub role: DeploymentArtifactRole,
    pub path: PathBuf,
    pub bytes: u64,
    pub digest: ContentId,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeploymentReferenceTarget {
    Artifact { id: u32 },
    NodeData { id: u32 },
    NodeWorktree { id: u32 },
    RuntimeDirectory { path: PathBuf },
    PinnedExecutable { path: PathBuf, digest: ContentId },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReference {
    pub owner: u32,
    pub field: String,
    pub target: DeploymentReferenceTarget,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedDeploymentGraph {
    pub format_version: u32,
    pub platform: DeploymentPlatform,
    pub root_deployment: u32,
    pub artifacts: Vec<DeploymentArtifactDescriptor>,
    pub nodes: Vec<DeploymentNodeDescriptor>,
    pub references: Vec<DeploymentReference>,
}

impl SelectedDeploymentGraph {
    pub fn digest(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }

    pub(crate) fn artifact(&self, id: u32) -> Result<&DeploymentArtifactDescriptor> {
        self.artifacts
            .iter()
            .find(|row| row.id == id)
            .ok_or(ReconcileError::Invariant(
                "selected deployment artifact absent",
            ))
    }

    pub(crate) fn node(&self, id: u32) -> Result<&DeploymentNodeDescriptor> {
        self.nodes
            .iter()
            .find(|row| row.id == id)
            .ok_or(ReconcileError::Invariant("selected deployment node absent"))
    }
}

pub(crate) fn decode_strict<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T> {
    Ok(sync_extend_core_model::deployment::decode_deployment_document(bytes, maximum)?)
}

pub(crate) enum DeploymentDocument {
    Deployment(DeploymentConfig),
    Node(Config),
    Gateway(DeploymentGatewayConfig),
    Management(ManagementConfig),
    Storage(StorageNodeConfig),
    Forwarder(PeerIdentity),
    TransportPolicy(SignedTransportAttemptPolicy),
    EasyTier(EasyTierConfig),
}

fn document(
    role: DeploymentArtifactRole,
    bytes: &[u8],
    platform: DeploymentPlatform,
) -> Result<Option<DeploymentDocument>> {
    let value = match role {
        DeploymentArtifactRole::DeploymentConfig => {
            let value: DeploymentConfig = decode_strict(bytes, 65_536)?;
            value.validate()?;
            DeploymentDocument::Deployment(value)
        }
        DeploymentArtifactRole::NodeConfig => {
            let value: Config = decode_strict(bytes, MAX_DOCUMENT)?;
            value.validate()?;
            DeploymentDocument::Node(value)
        }
        DeploymentArtifactRole::GatewayConfig => {
            let _: serde_json::Value = decode_strict(bytes, 65_536)?;
            DeploymentDocument::Gateway(DeploymentGatewayConfig::parse_for_platform(
                bytes, platform,
            )?)
        }
        DeploymentArtifactRole::ManagementConfig => {
            let value: ManagementConfig = decode_strict(bytes, 65_536)?;
            value.validate()?;
            if platform != DeploymentPlatform::Windows
                && value.token_protection == TokenProtection::WindowsUser
            {
                return Err(ReconcileError::Invariant(
                    "foreign management protection platform",
                ));
            }
            DeploymentDocument::Management(value)
        }
        DeploymentArtifactRole::StorageConfig => {
            let value: StorageNodeConfig = decode_strict(bytes, 65_536)?;
            value.validate()?;
            DeploymentDocument::Storage(value)
        }
        DeploymentArtifactRole::StorageForwarder => {
            let value: PeerIdentity = decode_strict(bytes, 65_536)?;
            value.validate()?;
            DeploymentDocument::Forwarder(value)
        }
        DeploymentArtifactRole::TransportAttemptPolicy => {
            let value: SignedTransportAttemptPolicy = decode_strict(bytes, 65_536)?;
            value.verify(&value.policy.data_root, &value.policy.control_root)?;
            DeploymentDocument::TransportPolicy(value)
        }
        DeploymentArtifactRole::EasyTierConfig => {
            let value: EasyTierConfig = decode_strict(bytes, MAX_DOCUMENT)?;
            value.validate()?;
            DeploymentDocument::EasyTier(value)
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

fn path_alias(path: &Path, platform: DeploymentPlatform) -> Result<String> {
    if !normalized(path) {
        return Err(ReconcileError::Invariant(
            "deployment normalized exact path",
        ));
    }
    let value = path
        .to_str()
        .ok_or(ReconcileError::Invariant("deployment path encoding"))?;
    Ok(if platform == DeploymentPlatform::Windows {
        value.replace('/', "\\").to_uppercase()
    } else {
        value.to_owned()
    })
}

pub(crate) fn derive_graph(
    mut graph: SelectedDeploymentGraph,
    payloads: &BTreeMap<u32, Vec<u8>>,
    bounds: DeploymentBundleBounds,
) -> Result<(SelectedDeploymentGraph, BTreeMap<u32, DeploymentDocument>)> {
    bounds.validate()?;
    if graph.format_version != 2
        || graph.artifacts.is_empty()
        || graph.artifacts.len() > bounds.artifacts
        || graph.nodes.len() > 64
    {
        return Err(ReconcileError::Invariant(
            "bounded complete selected deployment graph",
        ));
    }
    graph.artifacts.sort_by_key(|row| row.id);
    graph.nodes.sort_by_key(|row| row.id);
    let mut paths = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut total = 0u64;
    let mut documents = BTreeMap::new();
    for row in &graph.artifacts {
        let raw = payloads.get(&row.id).ok_or(ReconcileError::Invariant(
            "complete selected artifact payload missing",
        ))?;
        if row.id == 0
            || !ids.insert(row.id)
            || paths
                .insert(path_alias(&row.path, graph.platform)?, row.id)
                .is_some()
            || row.bytes == 0
            || row.bytes > row.role.maximum()
            || raw.len() as u64 != row.bytes
            || ContentId::hash(raw) != row.digest
        {
            return Err(ReconcileError::Invariant(
                "selected artifact alias/role/bytes/digest",
            ));
        }
        total = total
            .checked_add(row.bytes)
            .filter(|sum| *sum <= bounds.plaintext_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "complete deployment plaintext liability",
            ))?;
        if let Some(value) = document(row.role, raw, graph.platform)? {
            documents.insert(row.id, value);
        }
    }
    if payloads.len() != ids.len()
        || graph.artifact(graph.root_deployment)?.role != DeploymentArtifactRole::DeploymentConfig
    {
        return Err(ReconcileError::Invariant(
            "exact selected deployment root/payload membership",
        ));
    }
    bounds.memory([total, total])?;
    let mut node_ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    for node in &graph.nodes {
        let artifact = graph.artifact(node.artifact_id)?;
        if node.id == 0
            || !node_ids.insert(node.id)
            || artifact.role != DeploymentArtifactRole::NodeState
            || artifact.path != node.archive_path
            || artifact.digest != node.archive_digest
            || artifact.bytes != node.archive_bytes
            || node.source_schema == 0
            || node.data_dir.starts_with(&node.worktree)
            || node.worktree.starts_with(&node.data_dir)
            || !roots.insert(path_alias(&node.data_dir, graph.platform)?)
            || !roots.insert(path_alias(&node.worktree, graph.platform)?)
            || node.captured_configs.is_empty()
            || node.captured_configs.len() > 64
        {
            return Err(ReconcileError::Invariant(
                "actual node descriptor canonical source scope",
            ));
        }
        for config in node.captured_configs.values() {
            let selected = paths.get(&path_alias(config, graph.platform)?).ok_or(
                ReconcileError::Invariant("captured node config is unselected"),
            )?;
            if graph.artifact(*selected)?.role != DeploymentArtifactRole::NodeConfig {
                return Err(ReconcileError::Invariant(
                    "captured node config role differs",
                ));
            }
        }
    }
    let mut references = Vec::new();
    let mut artifact_ref = |owner, field: &str, path: &Path, role| -> Result<()> {
        let id =
            *paths
                .get(&path_alias(path, graph.platform)?)
                .ok_or(ReconcileError::Invariant(
                    "deployment dangling or unselected file reference",
                ))?;
        if graph.artifact(id)?.role != role || id == owner {
            return Err(ReconcileError::Invariant(
                "deployment typed reference/self alias",
            ));
        }
        references.push(DeploymentReference {
            owner,
            field: field.into(),
            target: DeploymentReferenceTarget::Artifact { id },
        });
        Ok(())
    };
    // File references are gathered first so no closure can accidentally accept
    // an undeclared directory as an artifact or a node-state envelope as config.
    for (owner, value) in &documents {
        match value {
            DeploymentDocument::Deployment(value) => {
                if let Some(path) = &value.management {
                    artifact_ref(
                        *owner,
                        "management",
                        path,
                        DeploymentArtifactRole::ManagementConfig,
                    )?;
                }
                if let Some(path) = &value.transport_attempt_policy {
                    artifact_ref(
                        *owner,
                        "transport_attempt_policy",
                        path,
                        DeploymentArtifactRole::TransportAttemptPolicy,
                    )?;
                }
                match &value.role {
                    DeploymentRole::Storage {
                        config, forwarder, ..
                    } => {
                        artifact_ref(
                            *owner,
                            "role.config",
                            config,
                            DeploymentArtifactRole::StorageConfig,
                        )?;
                        artifact_ref(
                            *owner,
                            "role.forwarder",
                            forwarder,
                            DeploymentArtifactRole::StorageForwarder,
                        )?;
                    }
                    DeploymentRole::WebdavClient { gateway_config, .. } => {
                        artifact_ref(
                            *owner,
                            "role.gateway_config",
                            gateway_config,
                            DeploymentArtifactRole::GatewayConfig,
                        )?;
                    }
                    DeploymentRole::EasyTier { config, .. } => {
                        artifact_ref(
                            *owner,
                            "role.config",
                            config,
                            DeploymentArtifactRole::EasyTierConfig,
                        )?;
                    }
                    _ => {}
                }
            }
            DeploymentDocument::Gateway(value) => {
                artifact_ref(
                    *owner,
                    "credentials",
                    &value.credentials,
                    DeploymentArtifactRole::WebdavCredential,
                )?;
                if let Some((certificate, key)) = value.tls_files() {
                    artifact_ref(
                        *owner,
                        "tls.certificate",
                        certificate,
                        DeploymentArtifactRole::TlsCertificate,
                    )?;
                    artifact_ref(
                        *owner,
                        "tls.private_key",
                        key,
                        DeploymentArtifactRole::TlsPrivateKey,
                    )?;
                }
            }
            DeploymentDocument::Management(value) => {
                artifact_ref(
                    *owner,
                    "token_file",
                    &value.token_file,
                    DeploymentArtifactRole::ManagementCredential,
                )?;
            }
            DeploymentDocument::Node(value) => {
                if let Some(path) = &value.webdav.credential_ref {
                    artifact_ref(
                        *owner,
                        "webdav.credential_ref",
                        Path::new(path),
                        DeploymentArtifactRole::WebdavCredential,
                    )?;
                }
                match (&value.webdav.tls_certificate, &value.webdav.tls_key) {
                    (Some(certificate), Some(key)) => {
                        artifact_ref(
                            *owner,
                            "webdav.tls_certificate",
                            certificate,
                            DeploymentArtifactRole::TlsCertificate,
                        )?;
                        artifact_ref(
                            *owner,
                            "webdav.tls_key",
                            key,
                            DeploymentArtifactRole::TlsPrivateKey,
                        )?;
                    }
                    (None, None) => {}
                    _ => {
                        return Err(ReconcileError::Invariant(
                            "deployment incomplete Config TLS pair",
                        ))
                    }
                }
            }
            _ => {}
        }
    }
    drop(artifact_ref);
    for (owner, value) in &documents {
        let mut directory = |field: &str, path: &Path| -> Result<()> {
            normalized_directory(path)?;
            if paths.contains_key(&path_alias(path, graph.platform)?) {
                return Err(ReconcileError::Invariant(
                    "runtime directory aliases selected artifact",
                ));
            }
            references.push(DeploymentReference {
                owner: *owner,
                field: field.into(),
                target: DeploymentReferenceTarget::RuntimeDirectory { path: path.into() },
            });
            Ok(())
        };
        match value {
            DeploymentDocument::Deployment(value) => {
                if let Some(path) = &value.transport_attempt_budget_dir {
                    directory("transport_attempt_budget_dir", path)?;
                }
            }
            DeploymentDocument::Gateway(value) => directory("uploads", &value.uploads)?,
            DeploymentDocument::EasyTier(value) => directory("state_dir", &value.state_dir)?,
            DeploymentDocument::TransportPolicy(value) => {
                directory("policy.control_root", &value.policy.control_root)?;
                if value.policy.ledger_path
                    != sync_extend_transport::TransportAttemptPolicy::fixed_ledger_path(
                        &value.policy.control_root,
                    )
                {
                    return Err(ReconcileError::Invariant(
                        "deployment exact signed policy ledger slot",
                    ));
                }
            }
            _ => {}
        }
    }
    let mut node_data = |owner, field: &str, data: &Path| -> Result<u32> {
        let matching: Vec<_> = graph
            .nodes
            .iter()
            .filter(|node| node.data_dir == data)
            .collect();
        if matching.len() != 1 {
            return Err(ReconcileError::Invariant(
                "deployment reference lacks one actual selected node",
            ));
        }
        let id = matching[0].id;
        references.push(DeploymentReference {
            owner,
            field: field.into(),
            target: DeploymentReferenceTarget::NodeData { id },
        });
        Ok(id)
    };
    let mut node_config_ids = Vec::new();
    for (owner, value) in &documents {
        match value {
            DeploymentDocument::Deployment(value) => match &value.role {
                DeploymentRole::LocalPolling { data_dir, .. }
                | DeploymentRole::MetadataClient { data_dir, .. }
                | DeploymentRole::MetadataServer { data_dir, .. } => {
                    node_data(*owner, "role.data_dir", data_dir)?;
                }
                _ => {}
            },
            DeploymentDocument::Node(value) => {
                let id = node_data(*owner, "data_dir", &value.data_dir)?;
                let node = graph.node(id)?;
                let config_path = &graph.artifact(*owner)?.path;
                if value.worktree.as_deref() != Some(node.worktree.as_path())
                    || !node
                        .captured_configs
                        .values()
                        .any(|path| path == config_path)
                {
                    return Err(ReconcileError::Invariant(
                        "selected Config original captured worktree scope",
                    ));
                }
                node_config_ids.push((*owner, id));
            }
            DeploymentDocument::Gateway(value) => {
                for (space, data) in &value.spaces {
                    let id = node_data(*owner, &format!("spaces.{space}"), data)?;
                    if graph.node(id)?.space_id != *space {
                        return Err(ReconcileError::Invariant(
                            "gateway selected space identity differs",
                        ));
                    }
                    if let Some(limits) = &value.collection_limits {
                        let node_config = documents
                            .values()
                            .find_map(|document| match document {
                                DeploymentDocument::Node(config) if &config.data_dir == data => {
                                    Some(config)
                                }
                                _ => None,
                            })
                            .ok_or(ReconcileError::Invariant(
                                "collection limits actual Config absent",
                            ))?;
                        limits.validate(&node_config.local_limits)?;
                    }
                }
            }
            DeploymentDocument::TransportPolicy(value) => {
                let id = node_data(*owner, "policy.data_root", &value.policy.data_root)?;
                if value.policy.owner.space_id != graph.node(id)?.space_id
                    || value.policy.owner.device_id != graph.node(id)?.device_id
                {
                    return Err(ReconcileError::Invariant(
                        "signed policy actual selected owner differs",
                    ));
                }
            }
            DeploymentDocument::Storage(_) => {
                // A storage-only Unix owner or plain descriptor is not a
                // complete node restore. R06 must issue its live completion.
                return Err(ReconcileError::Invariant(
                    "storage deployment requires actual R06 storage node completion",
                ));
            }
            _ => {}
        }
    }
    drop(node_data);
    for (owner, id) in node_config_ids {
        references.push(DeploymentReference {
            owner,
            field: "worktree".into(),
            target: DeploymentReferenceTarget::NodeWorktree { id },
        });
    }
    for node in &graph.nodes {
        for path in node.captured_configs.values() {
            let id = paths[&path_alias(path, graph.platform)?];
            references.push(DeploymentReference {
                owner: node.artifact_id,
                field: format!("captured_configs.{id}"),
                target: DeploymentReferenceTarget::Artifact { id },
            });
        }
    }
    for (owner, value) in &documents {
        if let DeploymentDocument::EasyTier(value) = value {
            for (field, path, digest) in [
                ("core_binary", &value.core_binary, &value.core_blake3),
                ("cli_binary", &value.cli_binary, &value.cli_blake3),
            ] {
                normalized_directory(path)?;
                references.push(DeploymentReference {
                    owner: *owner,
                    field: field.into(),
                    target: DeploymentReferenceTarget::PinnedExecutable {
                        path: path.clone(),
                        digest: digest.clone(),
                    },
                });
            }
        }
    }
    let mut keyed_references = references
        .into_iter()
        .map(|row| Ok((serde_json::to_vec(&row)?, row)))
        .collect::<Result<Vec<_>>>()?;
    keyed_references.sort_by(|left, right| left.0.cmp(&right.0));
    let references: Vec<_> = keyed_references.into_iter().map(|(_, row)| row).collect();
    if references.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReconcileError::Invariant(
            "duplicate canonical deployment reference",
        ));
    }
    let mut reached = BTreeSet::from([graph.root_deployment]);
    loop {
        let before = reached.len();
        for reference in &references {
            if reached.contains(&reference.owner) {
                match reference.target {
                    DeploymentReferenceTarget::Artifact { id } => {
                        reached.insert(id);
                    }
                    DeploymentReferenceTarget::NodeData { id }
                    | DeploymentReferenceTarget::NodeWorktree { id } => {
                        reached.insert(graph.node(id)?.artifact_id);
                    }
                    _ => {}
                }
            }
        }
        if reached.len() == before {
            break;
        }
    }
    if reached != ids {
        return Err(ReconcileError::Invariant(
            "unreachable extra deployment artifact/node",
        ));
    }
    graph.references = references;
    validate_cross_documents(&graph, &documents, payloads)?;
    Ok((graph, documents))
}

fn normalized_directory(path: &Path) -> Result<()> {
    if !normalized(path) {
        return Err(ReconcileError::Invariant(
            "explicit deployment referenced path",
        ));
    }
    Ok(())
}

fn validate_cross_documents(
    graph: &SelectedDeploymentGraph,
    documents: &BTreeMap<u32, DeploymentDocument>,
    payloads: &BTreeMap<u32, Vec<u8>>,
) -> Result<()> {
    for (owner, value) in documents {
        if let DeploymentDocument::Gateway(gateway) = value {
            let credential = graph
                .references
                .iter()
                .find_map(|reference| {
                    match (
                        &reference.target,
                        reference.owner == *owner && reference.field == "credentials",
                    ) {
                        (DeploymentReferenceTarget::Artifact { id }, true) => Some(*id),
                        _ => None,
                    }
                })
                .ok_or(ReconcileError::Invariant(
                    "exact gateway credential reference absent",
                ))?;
            let consumers = graph.references.iter().filter(|reference| {
                matches!(reference.target, DeploymentReferenceTarget::Artifact { id } if id == credential)
                    && reference.field == "credentials"
            }).count();
            if consumers != 1 {
                return Err(ReconcileError::Invariant(
                    "one exact credential listener binding required",
                ));
            }
            if graph.platform == DeploymentPlatform::Linux {
                validate_unix_webdav(payloads[&credential].as_slice(), &gateway.listener)?;
            }
            if let Some((certificate, key)) = gateway.tls_files() {
                let find = |path: &Path| -> Result<&[u8]> {
                    let id = graph
                        .artifacts
                        .iter()
                        .find(|row| row.path == path)
                        .ok_or(ReconcileError::Invariant("TLS graph artifact absent"))?
                        .id;
                    Ok(payloads[&id].as_slice())
                };
                sync_extend_transport::verify_deployment_tls_pair(find(certificate)?, find(key)?)?;
            }
        }
        if let DeploymentDocument::Management(config) = value {
            if config.token_protection == TokenProtection::Plain {
                let row = graph
                    .artifacts
                    .iter()
                    .find(|row| row.path == config.token_file)
                    .ok_or(ReconcileError::Invariant(
                        "management plain token selected path",
                    ))?;
                validate_plain_token(&payloads[&row.id])?;
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixWebdavPayload {
    format_version: u32,
    listener_id: EntryId,
    passwords: BTreeMap<String, String>,
}

pub(crate) fn validate_plain_token(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ReconcileError::Invariant(
            "existing exact local credential token format",
        ));
    }
    Ok(())
}

fn validate_unix_webdav(
    bytes: &[u8],
    listener: &sync_extend_core_model::webdav::WebDavListener,
) -> Result<UnixWebdavPayload> {
    listener.validate()?;
    let value: UnixWebdavPayload = decode_strict(bytes, 65_536)?;
    if value.format_version != 1
        || value.listener_id != listener.listener_id
        || value.passwords.keys().collect::<BTreeSet<_>>()
            != listener.accounts.iter().map(|row| &row.username).collect()
    {
        return Err(ReconcileError::Invariant(
            "original Unix credential listener account scope",
        ));
    }
    for password in value.passwords.values() {
        validate_plain_token(password.as_bytes())?;
    }
    Ok(value)
}

pub(crate) fn map_unix_webdav(
    bytes: &[u8],
    original: &sync_extend_core_model::webdav::WebDavListener,
    mapped: &sync_extend_core_model::webdav::WebDavListener,
) -> Result<Vec<u8>> {
    let mut expected = original.clone();
    expected.listener_id = mapped.listener_id.clone();
    if &expected != mapped {
        return Err(ReconcileError::Invariant(
            "Unix credential mapping changed public grants",
        ));
    }
    let mut payload = validate_unix_webdav(bytes, original)?;
    payload.listener_id = mapped.listener_id.clone();
    let result = serde_json::to_vec(&payload)?;
    validate_unix_webdav(&result, mapped)?;
    Ok(result)
}

fn consumer_digest(
    graph: &SelectedDeploymentGraph,
    documents: &BTreeMap<u32, DeploymentDocument>,
    artifact: &DeploymentArtifactDescriptor,
) -> Result<ContentId> {
    let sources: Vec<_> = graph.references.iter().filter(|reference| {
        matches!(reference.target, DeploymentReferenceTarget::Artifact { id } if id == artifact.id)
    }).collect();
    match artifact.role {
        DeploymentArtifactRole::WebdavCredential => {
            let gateways: Vec<_> = sources
                .iter()
                .filter_map(|reference| match documents.get(&reference.owner) {
                    Some(DeploymentDocument::Gateway(value))
                        if reference.field == "credentials" =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .collect();
            if gateways.len() != 1 {
                return Err(ReconcileError::Invariant(
                    "protected credential requires exact one gateway",
                ));
            }
            Ok(ContentId::hash(&serde_json::to_vec(&gateways[0].listener)?))
        }
        DeploymentArtifactRole::ManagementCredential => {
            let consumers: Vec<_> = sources
                .iter()
                .filter_map(|reference| match documents.get(&reference.owner) {
                    Some(DeploymentDocument::Management(value))
                        if reference.field == "token_file" =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .collect();
            if consumers.len() != 1 {
                return Err(ReconcileError::Invariant(
                    "protected token requires exact one management scope",
                ));
            }
            Ok(ContentId::hash(&serde_json::to_vec(consumers[0])?))
        }
        DeploymentArtifactRole::NodeState => {
            let node = graph
                .nodes
                .iter()
                .find(|node| node.artifact_id == artifact.id)
                .ok_or(ReconcileError::Invariant(
                    "protected node actual descriptor absent",
                ))?;
            Ok(ContentId::hash(&serde_json::to_vec(node)?))
        }
        DeploymentArtifactRole::EasyTierConfig => Ok(artifact.digest.clone()),
        _ => Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-deployment-consumers-v2",
            artifact.role,
            sources,
        ))?)),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FramedArtifact {
    id: u32,
    payload_bytes: u64,
    payload_digest: ContentId,
    binding: Option<ProtectedArtifactBinding>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FramedHeader {
    format_version: u32,
    graph: SelectedDeploymentGraph,
    graph_digest: ContentId,
    protection_scope: ProtectionScope,
    artifacts: Vec<FramedArtifact>,
}

pub struct FramedDeploymentBundle {
    bytes: Vec<u8>,
    digest: ContentId,
    header: FramedHeader,
    payloads: BTreeMap<u32, (usize, usize)>,
    // Native source provenance stays out of every serialized manifest.
    original_bundle: Option<OriginalProtectedArtifact>,
    original_artifacts: Vec<OriginalProtectedArtifact>,
    actual_node_capture: bool,
}

impl FramedDeploymentBundle {
    pub fn capture(
        selection: DeploymentSelection,
        nodes: Vec<CapturedDeploymentNode>,
        provider: &DeploymentProtectionProvider,
        bounds: DeploymentBundleBounds,
    ) -> Result<Self> {
        bounds.validate()?;
        provider.verify_original()?;
        if selection.format_version != 2 || selection.artifacts.len() > bounds.artifacts {
            return Err(ReconcileError::Invariant(
                "bounded original deployment selection",
            ));
        }
        let platform = actual_platform()?;
        let mut originals = Vec::new();
        let mut payloads = BTreeMap::new();
        let mut descriptors = Vec::new();
        let mut native_keys = BTreeSet::new();
        let mut total = 0u64;
        for selected in &selection.artifacts {
            if selected.id == 0
                || selected.max_bytes == 0
                || selected.max_bytes > selected.role.maximum()
                || selected.max_bytes > bounds.plaintext_bytes
                || payloads.contains_key(&selected.id)
            {
                return Err(ReconcileError::ResourceLimit(
                    "selected artifact role/count/byte liability",
                ));
            }
            let bytes = if selected.role == DeploymentArtifactRole::NodeState {
                let node = nodes
                    .iter()
                    .find(|node| node.descriptor.artifact_id == selected.id)
                    .ok_or(ReconcileError::Invariant(
                        "node-state bytes require actual node capture",
                    ))?;
                if node.descriptor.archive_path != selected.source_path {
                    return Err(ReconcileError::Invariant(
                        "actual node capture source label differs",
                    ));
                }
                node.original_bytes()?.to_vec()
            } else {
                let original = OriginalProtectedArtifact::capture(
                    &selected.source_path,
                    selected.max_bytes as usize,
                    selected.role.protected().is_some(),
                )?;
                if !native_keys.insert(original.native_identity()?) {
                    return Err(ReconcileError::Invariant(
                        "original deployment hardlink/native alias",
                    ));
                }
                let bytes = original.original_bytes().to_vec();
                originals.push(original);
                bytes
            };
            if bytes.len() as u64 > selected.max_bytes {
                return Err(ReconcileError::ResourceLimit(
                    "selected actual artifact length",
                ));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .filter(|sum| *sum <= bounds.plaintext_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "original deployment future plaintext liability",
                ))?;
            bounds.memory([total, total, total, bounds.metadata_bytes as u64])?;
            descriptors.push(DeploymentArtifactDescriptor {
                id: selected.id,
                role: selected.role,
                path: selected.source_path.clone(),
                bytes: bytes.len() as u64,
                digest: ContentId::hash(&bytes),
            });
            payloads.insert(selected.id, bytes);
        }
        let graph = SelectedDeploymentGraph {
            format_version: 2,
            platform,
            root_deployment: selection.root_deployment,
            artifacts: descriptors,
            nodes: nodes.iter().map(|node| node.descriptor.clone()).collect(),
            references: Vec::new(),
        };
        let (graph, documents) = derive_graph(graph, &payloads, bounds)?;
        let graph_digest = graph.digest()?;
        let mut framed_artifacts = Vec::new();
        let mut framed_payloads = BTreeMap::new();
        for row in &graph.artifacts {
            let binding = row
                .role
                .protected()
                .map(|role| -> Result<ProtectedArtifactBinding> {
                    Ok(ProtectedArtifactBinding {
                        format_version: 2,
                        artifact_id: row.id,
                        role,
                        source_path: row.path.clone(),
                        source_bytes: row.bytes,
                        source_digest: row.digest.clone(),
                        graph_digest: graph_digest.clone(),
                        consumer_digest: consumer_digest(&graph, &documents, row)?,
                        platform,
                    })
                })
                .transpose()?;
            let bytes = if let Some(binding) = &binding {
                if row.role == DeploymentArtifactRole::NodeState {
                    provider.protect_bytes(&payloads[&row.id], binding)?
                } else {
                    let original = originals
                        .iter()
                        .find(|source| source.source_path() == row.path)
                        .ok_or(ReconcileError::Invariant(
                            "retained actual protected source absent",
                        ))?;
                    provider.protect_original(original, binding)?
                }
            } else {
                payloads[&row.id].clone()
            };
            framed_artifacts.push(FramedArtifact {
                id: row.id,
                payload_bytes: bytes.len() as u64,
                payload_digest: ContentId::hash(&bytes),
                binding,
            });
            framed_payloads.insert(row.id, bytes);
        }
        for original in &originals {
            original.verify_original()?;
        }
        provider.verify_original()?;
        let header = FramedHeader {
            format_version: 2,
            graph,
            graph_digest,
            protection_scope: provider.scope().clone(),
            artifacts: framed_artifacts,
        };
        let mut result = Self::assemble(header, framed_payloads, bounds)?;
        result.original_artifacts = originals;
        result.actual_node_capture = true;
        Ok(result)
    }

    fn assemble(
        header: FramedHeader,
        payloads: BTreeMap<u32, Vec<u8>>,
        bounds: DeploymentBundleBounds,
    ) -> Result<Self> {
        let metadata = serde_json::to_vec(&header)?;
        if metadata.len() > bounds.metadata_bytes {
            return Err(ReconcileError::ResourceLimit(
                "deployment framing metadata bytes",
            ));
        }
        let total = header
            .artifacts
            .iter()
            .try_fold(20u64 + metadata.len() as u64, |sum, row| {
                sum.checked_add(row.payload_bytes)
            })
            .filter(|sum| *sum <= bounds.bundle_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "deployment complete framed byte liability",
            ))?;
        bounds.memory([total, total, bounds.plaintext_bytes])?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total as usize)
            .map_err(|_| ReconcileError::ResourceLimit("deployment framing allocation"))?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&metadata);
        for row in &header.artifacts {
            bytes.extend_from_slice(payloads.get(&row.id).ok_or(ReconcileError::Invariant(
                "complete framed deployment payload absent",
            ))?);
        }
        let digest = ContentId::hash(&bytes);
        Self::verify_framing(bytes, &digest, bounds)
    }

    pub fn from_original_file(
        path: &Path,
        expected: &ContentId,
        bounds: DeploymentBundleBounds,
    ) -> Result<Self> {
        bounds.validate()?;
        let source = OriginalProtectedArtifact::capture(path, bounds.bundle_bytes as usize, true)?;
        let mut framed = Self::verify_framing(source.original_bytes().to_vec(), expected, bounds)?;
        source.verify_original()?;
        framed.original_bundle = Some(source);
        Ok(framed)
    }

    pub fn verify_framing(
        bytes: Vec<u8>,
        expected: &ContentId,
        bounds: DeploymentBundleBounds,
    ) -> Result<Self> {
        bounds.validate()?;
        if bytes.len() < 21
            || bytes.len() as u64 > bounds.bundle_bytes
            || bytes.get(..16) != Some(MAGIC.as_slice())
            || ContentId::hash(&bytes) != *expected
        {
            return Err(ReconcileError::Invariant(
                "independent deployment v2 framing/digest",
            ));
        }
        let metadata_bytes = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("deployment metadata length encoding"))?,
        ) as usize;
        let start = 20usize
            .checked_add(metadata_bytes)
            .filter(|start| {
                metadata_bytes > 0
                    && metadata_bytes <= bounds.metadata_bytes
                    && *start < bytes.len()
            })
            .ok_or(ReconcileError::ResourceLimit(
                "deployment metadata bounded offset",
            ))?;
        let header: FramedHeader = decode_strict(&bytes[20..start], bounds.metadata_bytes)?;
        if header.format_version != 2
            || header.graph.format_version != 2
            || header.artifacts.is_empty()
            || header.artifacts.len() > bounds.artifacts
            || header.graph_digest != header.graph.digest()?
            || serde_json::to_vec(&header)? != bytes[20..start]
            || header
                .artifacts
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(ReconcileError::Invariant(
                "canonical deployment metadata/graph/role ordering",
            ));
        }
        let mut offset = start;
        let mut payloads = BTreeMap::new();
        for row in &header.artifacts {
            let end = offset
                .checked_add(usize::try_from(row.payload_bytes).map_err(|_| {
                    ReconcileError::ResourceLimit("deployment payload length encoding")
                })?)
                .filter(|end| row.payload_bytes > 0 && *end <= bytes.len())
                .ok_or(ReconcileError::ResourceLimit(
                    "deployment payload offset bound",
                ))?;
            let artifact = header.graph.artifact(row.id)?;
            if artifact.role.protected().is_some() != row.binding.is_some()
                || ContentId::hash(&bytes[offset..end]) != row.payload_digest
                || payloads.insert(row.id, (offset, end)).is_some()
            {
                return Err(ReconcileError::Invariant(
                    "deployment typed envelope/payload hash",
                ));
            }
            if let Some(binding) = &row.binding {
                if Some(binding.role) != artifact.role.protected()
                    || binding.artifact_id != artifact.id
                    || binding.source_path != artifact.path
                    || binding.source_bytes != artifact.bytes
                    || binding.source_digest != artifact.digest
                    || binding.graph_digest != header.graph_digest
                    || binding.platform != header.graph.platform
                {
                    return Err(ReconcileError::Invariant(
                        "deployment protected original graph role binding",
                    ));
                }
            }
            offset = end;
        }
        if offset != bytes.len() || payloads.len() != header.graph.artifacts.len() {
            return Err(ReconcileError::Invariant(
                "deployment trailing/missing selected bytes",
            ));
        }
        bounds.memory([bytes.len() as u64, bounds.plaintext_bytes])?;
        Ok(Self {
            bytes,
            digest: expected.clone(),
            header,
            payloads,
            original_bundle: None,
            original_artifacts: Vec::new(),
            actual_node_capture: false,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
    pub fn graph(&self) -> &SelectedDeploymentGraph {
        &self.header.graph
    }

    pub fn verify(
        self,
        provider: &DeploymentProtectionProvider,
        bounds: DeploymentBundleBounds,
        #[cfg(windows)] archive_bounds: crate::ArchiveBounds,
        #[cfg(windows)] inspection: sync_extend_journal::NodeInspectionBounds,
        #[cfg(windows)] max_content_hash_bytes: u64,
    ) -> Result<VerifiedDeploymentBundle> {
        bounds.validate()?;
        provider.verify_original()?;
        if &self.header.protection_scope != provider.scope()
            || self.header.graph.platform != actual_platform()?
        {
            return Err(ReconcileError::Invariant(
                "actual same-user deployment provider/platform",
            ));
        }
        let mut plaintext = BTreeMap::new();
        let mut protected = BTreeMap::new();
        let mut total = 0u64;
        for row in &self.header.artifacts {
            let (start, end) = self.payloads[&row.id];
            let bytes = if let Some(binding) = &row.binding {
                let actual = provider.verify_provider(&self.bytes[start..end], binding)?;
                let bytes = actual.original_bytes().to_vec();
                protected.insert(row.id, actual);
                bytes
            } else {
                self.bytes[start..end].to_vec()
            };
            total = total
                .checked_add(bytes.len() as u64)
                .filter(|sum| *sum <= bounds.plaintext_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "verified deployment plaintext liability",
                ))?;
            bounds.memory([self.bytes.len() as u64, total, total, total])?;
            plaintext.insert(row.id, bytes);
        }
        let (derived, documents) = derive_graph(self.header.graph.clone(), &plaintext, bounds)?;
        if derived != self.header.graph {
            return Err(ReconcileError::Invariant(
                "complete actual decoded deployment graph differs",
            ));
        }
        for row in &derived.artifacts {
            if let Some(actual) = protected.get(&row.id) {
                if actual.binding().consumer_digest != consumer_digest(&derived, &documents, row)? {
                    return Err(ReconcileError::Invariant(
                        "protected exact decoded consumer binding differs",
                    ));
                }
            }
        }
        #[cfg(windows)]
        let mut node_archives = BTreeMap::new();
        for node in &derived.nodes {
            #[cfg(windows)]
            {
                let archive = crate::FramedNodeArchive::verify_framing(
                    plaintext[&node.artifact_id].clone(),
                    &node.archive_digest,
                    archive_bounds,
                )?
                .verify_node_state(
                    archive_bounds,
                    inspection,
                    max_content_hash_bytes,
                )?;
                if archive.space() != &node.space_id
                    || archive.device() != &node.device_id
                    || archive.original_worktree() != node.worktree
                    || archive.original_config_data() != Some(node.data_dir.as_path())
                    || archive.schema() != node.source_schema
                {
                    return Err(ReconcileError::Invariant(
                        "actual authenticated node archive descriptor differs",
                    ));
                }
                node_archives.insert(node.id, archive);
            }
            #[cfg(not(windows))]
            {
                let _ = node;
                return Err(ReconcileError::Invariant(
                    "R06 complete node verification is not available on this platform",
                ));
            }
        }
        #[cfg(windows)]
        for (owner, document) in &documents {
            match document {
                DeploymentDocument::Gateway(gateway) => {
                    let id = derived
                        .artifacts
                        .iter()
                        .find(|row| row.path == gateway.credentials)
                        .ok_or(ReconcileError::Invariant(
                            "actual protected gateway credential absent",
                        ))?
                        .id;
                    crate::ExplicitWebDavCredentialMapping::from_verified_protected_artifact(
                        &protected[&id],
                        &gateway.listener,
                        &gateway.listener,
                        4 * 65_536,
                    )?;
                }
                DeploymentDocument::Management(config)
                    if config.token_protection == TokenProtection::WindowsUser =>
                {
                    let id = derived
                        .artifacts
                        .iter()
                        .find(|row| row.path == config.token_file)
                        .ok_or(ReconcileError::Invariant(
                            "actual protected management credential absent",
                        ))?
                        .id;
                    crate::ExplicitManagementCredentialMapping::from_verified_protected_artifact(
                        &protected[&id],
                        config,
                        config,
                        4 * 4096,
                    )?;
                }
                _ => {
                    let _ = owner;
                }
            }
        }
        provider.verify_original()?;
        let result = VerifiedDeploymentBundle {
            framing: self,
            graph: derived,
            documents,
            plaintext,
            protected,
            bounds,
            #[cfg(windows)]
            node_archives,
            #[cfg(windows)]
            archive_bounds,
        };
        result.verify_original_source()?;
        Ok(result)
    }
}

pub struct VerifiedDeploymentBundle {
    pub(crate) framing: FramedDeploymentBundle,
    pub(crate) graph: SelectedDeploymentGraph,
    pub(crate) documents: BTreeMap<u32, DeploymentDocument>,
    pub(crate) plaintext: BTreeMap<u32, Vec<u8>>,
    pub(crate) protected: BTreeMap<u32, VerifiedProtectedArtifact>,
    pub(crate) bounds: DeploymentBundleBounds,
    #[cfg(windows)]
    pub(crate) node_archives: BTreeMap<u32, crate::VerifiedNodeStateArchive>,
    #[cfg(windows)]
    archive_bounds: crate::ArchiveBounds,
}

impl VerifiedDeploymentBundle {
    pub fn graph(&self) -> &SelectedDeploymentGraph {
        &self.graph
    }
    pub fn digest(&self) -> &ContentId {
        self.framing.digest()
    }

    pub fn verify_original_source(&self) -> Result<()> {
        if let Some(source) = &self.framing.original_bundle {
            source.verify_original()?;
            if source.source_digest() != self.digest() {
                return Err(ReconcileError::Unstable);
            }
        }
        for source in &self.framing.original_artifacts {
            source.verify_original()?;
        }
        Ok(())
    }

    pub(crate) fn require_original_provenance(&self) -> Result<()> {
        if self.framing.original_bundle.is_none()
            && (!self.framing.actual_node_capture || self.framing.original_artifacts.is_empty())
        {
            return Err(ReconcileError::Invariant(
                "deployment install requires actual original bundle/capture",
            ));
        }
        self.verify_original_source()
    }

    pub(crate) fn reverify_provider(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.require_original_provenance()?;
        if provider.scope() != &self.framing.header.protection_scope {
            return Err(ReconcileError::Invariant(
                "retained deployment protection provider differs",
            ));
        }
        provider.verify_original()?;
        for row in &self.framing.header.artifacts {
            if let Some(binding) = &row.binding {
                let (start, end) = self.framing.payloads[&row.id];
                let actual = provider.verify_provider(&self.framing.bytes[start..end], binding)?;
                if actual.original_bytes() != self.plaintext[&row.id] {
                    return Err(ReconcileError::Invariant(
                        "actual original provider plaintext changed",
                    ));
                }
            }
        }
        self.verify_original_source()?;
        provider.verify_original()
    }
}

impl Drop for VerifiedDeploymentBundle {
    fn drop(&mut self) {
        for (id, bytes) in &mut self.plaintext {
            if self
                .graph
                .artifacts
                .iter()
                .any(|row| row.id == *id && row.role.protected().is_some())
            {
                bytes.fill(0);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentNodeTarget {
    pub data_dir: PathBuf,
    pub worktree: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMapping {
    pub format_version: u32,
    pub artifact_paths: BTreeMap<u32, PathBuf>,
    pub node_roots: BTreeMap<u32, DeploymentNodeTarget>,
    pub runtime_directories: BTreeMap<PathBuf, PathBuf>,
    /// Only the existing credential mapper's explicit listener-ID binding is
    /// allowed. Addresses, accounts, export grants and all limits are preserved.
    pub listener_ids: BTreeMap<u32, EntryId>,
}

pub(crate) struct MappedDeploymentArtifact {
    pub id: u32,
    pub role: DeploymentArtifactRole,
    pub target: PathBuf,
    pub bytes: Vec<u8>,
    pub digest: ContentId,
}

impl Drop for MappedDeploymentArtifact {
    fn drop(&mut self) {
        if self.role.protected().is_some() {
            self.bytes.fill(0);
        }
    }
}

pub struct RestrictedDeploymentMapping {
    pub(crate) original: VerifiedDeploymentBundle,
    pub(crate) mapping: DeploymentMapping,
    pub(crate) artifacts: Vec<MappedDeploymentArtifact>,
    pub(crate) mapped_documents: BTreeMap<u32, DeploymentDocument>,
    pub(crate) mapped_graph: SelectedDeploymentGraph,
    pub(crate) mapping_digest: ContentId,
}

impl VerifiedDeploymentBundle {
    pub fn map_restricted(self, mapping: DeploymentMapping) -> Result<RestrictedDeploymentMapping> {
        self.require_original_provenance()?;
        let original_graph = &self.graph;
        let file_ids: BTreeSet<_> = original_graph
            .artifacts
            .iter()
            .filter(|row| row.role.installed())
            .map(|row| row.id)
            .collect();
        let node_ids: BTreeSet<_> = original_graph.nodes.iter().map(|row| row.id).collect();
        let directory_paths: BTreeSet<_> = original_graph
            .references
            .iter()
            .filter_map(|row| match &row.target {
                DeploymentReferenceTarget::RuntimeDirectory { path } => Some(path.clone()),
                _ => None,
            })
            .collect();
        let gateways: BTreeSet<_> = self
            .documents
            .iter()
            .filter_map(|(id, value)| {
                matches!(value, DeploymentDocument::Gateway(_)).then_some(*id)
            })
            .collect();
        if mapping.format_version != 2
            || mapping
                .artifact_paths
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != file_ids
            || mapping.node_roots.keys().copied().collect::<BTreeSet<_>>() != node_ids
            || mapping
                .runtime_directories
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != directory_paths
            || !mapping.listener_ids.keys().all(|id| gateways.contains(id))
        {
            return Err(ReconcileError::Invariant(
                "exact restricted deployment mapping membership",
            ));
        }
        let mut slots = BTreeSet::new();
        let mut new_roots = Vec::new();
        for target in mapping.node_roots.values() {
            for path in [&target.data_dir, &target.worktree] {
                normalized_directory(path)?;
                let alias = path_alias(path, original_graph.platform)?;
                if !slots.insert(alias) {
                    return Err(ReconcileError::Invariant("mapped deployment root alias"));
                }
                new_roots.push(path.clone());
            }
        }
        if new_roots.iter().enumerate().any(|(index, path)| {
            new_roots
                .iter()
                .skip(index + 1)
                .any(|other| path.starts_with(other) || other.starts_with(path))
        }) {
            return Err(ReconcileError::Invariant("mapped deployment roots overlap"));
        }
        let mut directories = Vec::new();
        for path in mapping.runtime_directories.values() {
            normalized_directory(path)?;
            if !slots.insert(path_alias(path, original_graph.platform)?)
                || new_roots
                    .iter()
                    .any(|root| path.starts_with(root) || root.starts_with(path))
            {
                return Err(ReconcileError::Invariant(
                    "runtime directory aliases installed node roots",
                ));
            }
            directories.push(path);
        }
        for path in mapping.artifact_paths.values() {
            normalized_directory(path)?;
            if !slots.insert(path_alias(path, original_graph.platform)?)
                || new_roots
                    .iter()
                    .any(|root| path.starts_with(root) || root.starts_with(path))
                || directories
                    .iter()
                    .any(|directory| path.starts_with(directory) || directory.starts_with(path))
            {
                return Err(ReconcileError::Invariant(
                    "config/artifact slot aliases node/runtime membership",
                ));
            }
        }
        let mapper = RestrictedPathMapper {
            graph: original_graph,
            mapping: &mapping,
        };
        let mut mapped_documents = BTreeMap::new();
        let mut mapped_payloads = BTreeMap::new();
        for row in &original_graph.artifacts {
            if !row.role.installed() {
                mapped_payloads.insert(row.id, self.plaintext[&row.id].clone());
                continue;
            }
            let bytes = match self.documents.get(&row.id) {
                Some(DeploymentDocument::Deployment(original)) => {
                    let mut target = original.clone();
                    target.management = target
                        .management
                        .as_ref()
                        .map(|path| mapper.artifact(path, DeploymentArtifactRole::ManagementConfig))
                        .transpose()?;
                    target.transport_attempt_policy = target
                        .transport_attempt_policy
                        .as_ref()
                        .map(|path| {
                            mapper.artifact(path, DeploymentArtifactRole::TransportAttemptPolicy)
                        })
                        .transpose()?;
                    target.transport_attempt_budget_dir = target
                        .transport_attempt_budget_dir
                        .as_ref()
                        .map(|path| mapper.runtime(path))
                        .transpose()?;
                    match &mut target.role {
                        DeploymentRole::LocalPolling { data_dir, .. }
                        | DeploymentRole::MetadataClient { data_dir, .. }
                        | DeploymentRole::MetadataServer { data_dir, .. } => {
                            *data_dir = mapper.node_data(data_dir)?;
                        }
                        DeploymentRole::Storage {
                            config, forwarder, ..
                        } => {
                            *config =
                                mapper.artifact(config, DeploymentArtifactRole::StorageConfig)?;
                            *forwarder = mapper
                                .artifact(forwarder, DeploymentArtifactRole::StorageForwarder)?;
                        }
                        DeploymentRole::WebdavClient { gateway_config, .. } => {
                            *gateway_config = mapper
                                .artifact(gateway_config, DeploymentArtifactRole::GatewayConfig)?;
                        }
                        DeploymentRole::EasyTier { config, .. } => {
                            *config =
                                mapper.artifact(config, DeploymentArtifactRole::EasyTierConfig)?;
                        }
                    }
                    target.validate()?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::Node(original)) => {
                    let mut target = original.clone();
                    target.data_dir = mapper.node_data(&original.data_dir)?;
                    target.worktree = original
                        .worktree
                        .as_ref()
                        .map(|path| mapper.node_worktree(path))
                        .transpose()?;
                    target.webdav.credential_ref = original
                        .webdav
                        .credential_ref
                        .as_ref()
                        .map(|path| {
                            mapper
                                .artifact(
                                    Path::new(path),
                                    DeploymentArtifactRole::WebdavCredential,
                                )?
                                .to_str()
                                .map(str::to_owned)
                                .ok_or(ReconcileError::Invariant(
                                    "mapped credential Config path encoding",
                                ))
                        })
                        .transpose()?;
                    target.webdav.tls_certificate = original
                        .webdav
                        .tls_certificate
                        .as_ref()
                        .map(|path| mapper.artifact(path, DeploymentArtifactRole::TlsCertificate))
                        .transpose()?;
                    target.webdav.tls_key = original
                        .webdav
                        .tls_key
                        .as_ref()
                        .map(|path| mapper.artifact(path, DeploymentArtifactRole::TlsPrivateKey))
                        .transpose()?;
                    target.validate()?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::Gateway(original)) => {
                    let mut target = original.clone();
                    target.credentials = mapper.artifact(
                        &original.credentials,
                        DeploymentArtifactRole::WebdavCredential,
                    )?;
                    target.uploads = mapper.runtime(&original.uploads)?;
                    for data in target.spaces.values_mut() {
                        *data = mapper.node_data(data)?;
                    }
                    if let Some(listener_id) = mapping.listener_ids.get(&row.id) {
                        target.listener.listener_id = listener_id.clone();
                    }
                    if let Some(tls) = &mut target.host_loopback_tls {
                        tls.certificate = mapper
                            .artifact(&tls.certificate, DeploymentArtifactRole::TlsCertificate)?;
                        tls.private_key = mapper
                            .artifact(&tls.private_key, DeploymentArtifactRole::TlsPrivateKey)?;
                    }
                    if let Some(tls) = &mut target.listener_tls {
                        tls.certificate = mapper
                            .artifact(&tls.certificate, DeploymentArtifactRole::TlsCertificate)?;
                        tls.private_key = mapper
                            .artifact(&tls.private_key, DeploymentArtifactRole::TlsPrivateKey)?;
                    }
                    target.validate(original_graph.platform)?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::Management(original)) => {
                    let mut target = original.clone();
                    target.token_file = mapper.artifact(
                        &original.token_file,
                        DeploymentArtifactRole::ManagementCredential,
                    )?;
                    target.validate()?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::Storage(original)) => {
                    let mut target = original.clone();
                    target.data_dir = mapper.node_data(&original.data_dir)?;
                    target.validate()?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::Forwarder(original)) => serde_json::to_vec(original)?,
                Some(DeploymentDocument::EasyTier(original)) => {
                    let mut target = original.clone();
                    target.state_dir = mapper.runtime(&original.state_dir)?;
                    target.validate()?;
                    serde_json::to_vec(&target)?
                }
                Some(DeploymentDocument::TransportPolicy(original)) => {
                    let mut target = original.policy.clone();
                    target.data_root = mapper.node_data(&original.policy.data_root)?;
                    target.control_root = mapper.runtime(&original.policy.control_root)?;
                    target.ledger_path =
                        sync_extend_transport::TransportAttemptPolicy::fixed_ledger_path(
                            &target.control_root,
                        );
                    #[cfg(windows)]
                    {
                        let node = original_graph
                            .nodes
                            .iter()
                            .find(|node| node.data_dir == original.policy.data_root)
                            .ok_or(ReconcileError::Invariant(
                                "mapped signed policy actual source node",
                            ))?;
                        let archive = crate::FramedNodeArchive::verify_framing(
                            self.plaintext[&node.artifact_id].clone(),
                            &node.archive_digest,
                            self.archive_bounds,
                        )?;
                        let stored = archive.section(&crate::ArchiveRole::DeviceSecret).ok_or(
                            ReconcileError::Invariant("actual source signing identity section"),
                        )?;
                        let mut secret = crate::identity::decode_stored_backup(stored)?;
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
                        secret.fill(0);
                        let identity = sync_extend_transport::TransportIdentity::from_signing_key(
                            node.space_id.clone(),
                            signing_key,
                        )?;
                        let signed = SignedTransportAttemptPolicy::sign(
                            &identity,
                            &target.data_root,
                            &target.control_root,
                            target.clone(),
                        )?;
                        signed.verify(&target.data_root, &target.control_root)?;
                        serde_json::to_vec(&signed)?
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = target;
                        return Err(ReconcileError::Invariant(
                            "mapped policy requires actual R06 node identity",
                        ));
                    }
                }
                None => self.plaintext[&row.id].clone(),
            };
            if bytes.len() as u64 > row.role.maximum() {
                return Err(ReconcileError::ResourceLimit(
                    "restricted mapped document role limit",
                ));
            }
            if let Some(value) = document(row.role, &bytes, original_graph.platform)? {
                mapped_documents.insert(row.id, value);
            }
            mapped_payloads.insert(row.id, bytes);
        }
        // Credential consumers are all available only after every mapped public
        // descriptor is validated. The existing Windows DPAPI validators remain
        // the implementation of the established payload, account and token rules.
        for row in &original_graph.artifacts {
            match row.role {
                DeploymentArtifactRole::WebdavCredential => {
                    let (owner, original) = self
                        .documents
                        .iter()
                        .find_map(|(owner, document)| match document {
                            DeploymentDocument::Gateway(value) if value.credentials == row.path => {
                                Some((*owner, value))
                            }
                            _ => None,
                        })
                        .ok_or(ReconcileError::Invariant(
                            "original exact credential consumer",
                        ))?;
                    let mapped = match &mapped_documents[&owner] {
                        DeploymentDocument::Gateway(value) => value,
                        _ => {
                            return Err(ReconcileError::Invariant(
                                "mapped exact credential consumer",
                            ))
                        }
                    };
                    #[cfg(windows)]
                    let bytes =
                        crate::ExplicitWebDavCredentialMapping::from_verified_protected_artifact(
                            &self.protected[&row.id],
                            &original.listener,
                            &mapped.listener,
                            4 * 65_536,
                        )?
                        .protected_bytes_for_deployment()
                        .to_vec();
                    #[cfg(target_os = "linux")]
                    let bytes = map_unix_webdav(
                        &self.plaintext[&row.id],
                        &original.listener,
                        &mapped.listener,
                    )?;
                    #[cfg(not(any(windows, target_os = "linux")))]
                    return Err(ReconcileError::Invariant(
                        "deployment credential platform unavailable",
                    ));
                    #[cfg(any(windows, target_os = "linux"))]
                    mapped_payloads.insert(row.id, bytes);
                }
                DeploymentArtifactRole::ManagementCredential => {
                    let (owner, original) = self
                        .documents
                        .iter()
                        .find_map(|(owner, document)| match document {
                            DeploymentDocument::Management(value)
                                if value.token_file == row.path =>
                            {
                                Some((*owner, value))
                            }
                            _ => None,
                        })
                        .ok_or(ReconcileError::Invariant(
                            "original exact management credential consumer",
                        ))?;
                    let mapped = match &mapped_documents[&owner] {
                        DeploymentDocument::Management(value) => value,
                        _ => {
                            return Err(ReconcileError::Invariant(
                                "mapped exact management credential consumer",
                            ))
                        }
                    };
                    match original.token_protection {
                        TokenProtection::Plain => {
                            validate_plain_token(&self.plaintext[&row.id])?;
                        }
                        TokenProtection::WindowsUser => {
                            #[cfg(windows)]
                            {
                                let bytes = crate::ExplicitManagementCredentialMapping::from_verified_protected_artifact(
                                    &self.protected[&row.id], original, mapped, 4 * 4096,
                                )?.protected_bytes_for_deployment().to_vec();
                                mapped_payloads.insert(row.id, bytes);
                            }
                            #[cfg(not(windows))]
                            return Err(ReconcileError::Invariant(
                                "foreign management protection mapping",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        let mut mapped_graph = original_graph.clone();
        mapped_graph.references.clear();
        for row in &mut mapped_graph.artifacts {
            if row.role.installed() {
                row.path = mapping.artifact_paths[&row.id].clone();
                row.bytes = mapped_payloads[&row.id].len() as u64;
                row.digest = ContentId::hash(&mapped_payloads[&row.id]);
            }
        }
        for node in &mut mapped_graph.nodes {
            node.data_dir = mapping.node_roots[&node.id].data_dir.clone();
            node.worktree = mapping.node_roots[&node.id].worktree.clone();
            for path in node.captured_configs.values_mut() {
                *path = mapper.artifact(path, DeploymentArtifactRole::NodeConfig)?;
            }
        }
        let (mapped_graph, mapped_documents) =
            derive_graph(mapped_graph, &mapped_payloads, self.bounds)?;
        let mapping_digest = ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-restricted-original-deployment-mapping-v2",
            self.digest(),
            &mapping,
            &mapped_graph,
        ))?);
        let mut artifacts = Vec::new();
        let mut total = 0u64;
        for row in &mapped_graph.artifacts {
            if row.role.installed() {
                let bytes = mapped_payloads
                    .remove(&row.id)
                    .ok_or(ReconcileError::Invariant(
                        "restricted mapped installation payload",
                    ))?;
                total =
                    total
                        .checked_add(bytes.len() as u64)
                        .ok_or(ReconcileError::ResourceLimit(
                            "mapped deployment future file liability",
                        ))?;
                artifacts.push(MappedDeploymentArtifact {
                    id: row.id,
                    role: row.role,
                    target: row.path.clone(),
                    digest: ContentId::hash(&bytes),
                    bytes,
                });
            }
        }
        let original_total: u64 = self
            .plaintext
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum();
        self.bounds.memory([
            self.framing.bytes.len() as u64,
            original_total,
            original_total,
            original_total,
            total,
        ])?;
        self.verify_original_source()?;
        Ok(RestrictedDeploymentMapping {
            original: self,
            mapping,
            artifacts,
            mapped_documents,
            mapped_graph,
            mapping_digest,
        })
    }
}

struct RestrictedPathMapper<'a> {
    graph: &'a SelectedDeploymentGraph,
    mapping: &'a DeploymentMapping,
}
impl RestrictedPathMapper<'_> {
    fn artifact(&self, path: &Path, role: DeploymentArtifactRole) -> Result<PathBuf> {
        let row = self
            .graph
            .artifacts
            .iter()
            .find(|row| row.path == path && row.role == role)
            .ok_or(ReconcileError::Invariant(
                "restricted artifact exact original role/path",
            ))?;
        self.mapping
            .artifact_paths
            .get(&row.id)
            .cloned()
            .ok_or(ReconcileError::Invariant(
                "restricted artifact explicit destination absent",
            ))
    }
    fn node_data(&self, path: &Path) -> Result<PathBuf> {
        let node = self
            .graph
            .nodes
            .iter()
            .find(|node| node.data_dir == path)
            .ok_or(ReconcileError::Invariant(
                "restricted node original data root",
            ))?;
        Ok(self.mapping.node_roots[&node.id].data_dir.clone())
    }
    fn node_worktree(&self, path: &Path) -> Result<PathBuf> {
        let node = self
            .graph
            .nodes
            .iter()
            .find(|node| node.worktree == path)
            .ok_or(ReconcileError::Invariant(
                "restricted node original worktree root",
            ))?;
        Ok(self.mapping.node_roots[&node.id].worktree.clone())
    }
    fn runtime(&self, path: &Path) -> Result<PathBuf> {
        self.mapping
            .runtime_directories
            .get(path)
            .cloned()
            .ok_or(ReconcileError::Invariant(
                "restricted runtime explicit original directory",
            ))
    }
}

impl RestrictedDeploymentMapping {
    pub fn original_graph(&self) -> &SelectedDeploymentGraph {
        &self.original.graph
    }
    pub fn mapped_graph(&self) -> &SelectedDeploymentGraph {
        &self.mapped_graph
    }
    pub fn mapping_digest(&self) -> &ContentId {
        &self.mapping_digest
    }
    pub fn root_deployment_path(&self) -> &Path {
        &self.mapping.artifact_paths[&self.original.graph.root_deployment]
    }
    pub fn preview(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "format_version": 2,
            "original_bundle_digest": self.original.digest(),
            "mapping_digest": self.mapping_digest,
            "mapped_graph": self.mapped_graph,
            "files": self.artifacts.iter().map(|row| serde_json::json!({
                "id": row.id, "role": row.role, "path": row.target,
                "bytes": row.bytes.len(), "digest": row.digest,
            })).collect::<Vec<_>>(),
            "services_started": false,
            "installed_completion_issued": false,
        }))
    }
}

pub(crate) fn actual_platform() -> Result<DeploymentPlatform> {
    #[cfg(windows)]
    return Ok(DeploymentPlatform::Windows);
    #[cfg(target_os = "linux")]
    return Ok(DeploymentPlatform::Linux);
    #[cfg(not(any(windows, target_os = "linux")))]
    Err(ReconcileError::Invariant(
        "protected deployment platform unsupported",
    ))
}
