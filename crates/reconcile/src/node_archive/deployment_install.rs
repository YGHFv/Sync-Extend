//! Full preflight, original private CREATE and immutable per-file attempts.
//! Decoded receipts describe history; only retained original creators can issue
//! a living complete installation. Failed prefixes are kept, never rolled back.
use super::{
    deployment_bundle::{
        DeploymentArtifactRole, DeploymentNodeDescriptor, DeploymentNodeTarget,
        DeploymentReferenceTarget, RestrictedDeploymentMapping,
    },
    protected_artifact::{DeploymentProtectionProvider, OriginalProtectedArtifact},
};
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{ContentId, EntryId, PortablePath};

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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentNodeCompletionReceipt {
    pub id: u32,
    pub archive_digest: ContentId,
    pub data_dir: PathBuf,
    pub worktree: PathBuf,
    pub data_key: String,
    pub worktree_key: String,
    pub manifest_digest: ContentId,
}

/// This wrapper can only borrow a living R06 completion. Neither a node
/// descriptor, ordinary LocalSpace, JSON manifest nor reopened path can mint it.
pub struct OriginalDeploymentNodeCompletion<'proof, 'local, 'scope> {
    id: u32,
    #[cfg(windows)]
    original: &'proof crate::OriginalNodeCompletionObservation<'local, 'scope>,
    #[cfg(not(windows))]
    unavailable: std::marker::PhantomData<(&'proof (), &'local (), &'scope ())>,
}

impl<'proof, 'local, 'scope> OriginalDeploymentNodeCompletion<'proof, 'local, 'scope> {
    #[cfg(windows)]
    pub fn from_original(
        id: u32,
        original: &'proof crate::OriginalNodeCompletionObservation<'local, 'scope>,
    ) -> Result<Self> {
        if id == 0 {
            return Err(ReconcileError::Invariant(
                "actual deployment completion node id",
            ));
        }
        original.deployment_binding()?.verify()?;
        Ok(Self { id, original })
    }

    fn verify(
        &self,
        descriptor: &DeploymentNodeDescriptor,
        target: &DeploymentNodeTarget,
    ) -> Result<DeploymentNodeCompletionReceipt> {
        #[cfg(windows)]
        {
            let binding = self.original.deployment_binding()?;
            if self.id != descriptor.id
                || binding.archive_digest() != &descriptor.archive_digest
                || binding.data_dir() != target.data_dir
                || binding.worktree() != target.worktree
                || binding.space_id()? != descriptor.space_id
                || binding.device_id()? != descriptor.device_id
            {
                return Err(ReconcileError::Invariant(
                    "actual original deployment target completion differs",
                ));
            }
            let receipt = DeploymentNodeCompletionReceipt {
                id: self.id,
                archive_digest: binding.archive_digest().clone(),
                data_dir: binding.data_dir().to_path_buf(),
                worktree: binding.worktree().to_path_buf(),
                data_key: binding.data_key().to_owned(),
                worktree_key: binding.worktree_key().to_owned(),
                manifest_digest: binding.manifest_digest()?,
            };
            binding.verify()?;
            Ok(receipt)
        }
        #[cfg(not(windows))]
        {
            let _ = (descriptor, target);
            Err(ReconcileError::Invariant(
                "R06 actual complete node restoration is unavailable on this platform",
            ))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentFileAttempt {
    pub format_version: u32,
    pub attempt_id: EntryId,
    pub sequence: u32,
    pub artifact_id: u32,
    pub role: DeploymentArtifactRole,
    pub target: PathBuf,
    pub parent_key: String,
    pub expected_bytes: u64,
    pub expected_digest: ContentId,
    pub bundle_digest: ContentId,
    pub mapping_digest: ContentId,
    pub previous_receipt_digest: ContentId,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentFileReceipt {
    pub original_attempt: DeploymentFileAttempt,
    pub original_key: String,
    pub actual_bytes: u64,
    pub actual_digest: ContentId,
    pub original_private_create_verified: bool,
    pub original_file_sync_and_readback_verified: bool,
    pub original_parent_sync_verified: bool,
    pub original_sealed_read_scope_verified: bool,
    pub receipt_digest: ContentId,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentFailedFileReceipt {
    pub original_attempt: DeploymentFileAttempt,
    pub original_create_happened: bool,
    pub observed_original_key: Option<String>,
    pub observed_original_bytes: Option<u64>,
    /// Static operation class only. Secret data never enters an error record.
    pub operation: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentInstallReceipt {
    pub format_version: u32,
    pub attempt_id: Option<EntryId>,
    pub bundle_digest: ContentId,
    pub mapping_digest: ContentId,
    pub root_deployment: PathBuf,
    pub nodes: Vec<DeploymentNodeCompletionReceipt>,
    pub files: Vec<DeploymentFileReceipt>,
    pub failed_file: Option<DeploymentFailedFileReceipt>,
    pub full_graph_and_original_creators_verified: bool,
    pub root_deployment_written_last: bool,
    pub services_started: bool,
}

/// Every source/provider, actual completed target node, private parent, future
/// file byte charge and empty slot is checked before the first CREATE.
pub struct PreparedDeploymentInstall<'proof, 'local, 'scope> {
    mapping: RestrictedDeploymentMapping,
    completions: Vec<OriginalDeploymentNodeCompletion<'proof, 'local, 'scope>>,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
    node_receipts: Vec<DeploymentNodeCompletionReceipt>,
}

fn component(path: &Path) -> Result<&str> {
    let value =
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(ReconcileError::Invariant(
                "deployment target normal file component",
            ))?;
    let portable = PortablePath::new(value)?;
    if portable.as_str() != value || value.contains(['/', '\\']) || value.len() > 255 {
        return Err(ReconcileError::Invariant(
            "deployment target portable single component",
        ));
    }
    Ok(value)
}

#[cfg(windows)]
fn parent_key(parent: &NativeParent) -> Result<String> {
    Ok(parent.key()?.to_string())
}
#[cfg(target_os = "linux")]
fn parent_key(parent: &NativeParent) -> Result<String> {
    let key = parent.key()?;
    Ok(format!("unix:{}:{}:{}", key.device, key.inode, key.uid))
}
#[cfg(windows)]
fn creator_key(creator: &NativeCreator) -> String {
    creator.key().to_string()
}
#[cfg(target_os = "linux")]
fn creator_key(creator: &NativeCreator) -> String {
    let key = creator.key();
    format!("unix:{}:{}:{}", key.device, key.inode, key.uid)
}
#[cfg(windows)]
fn sealed_key(file: &NativeSealed) -> String {
    file.key().to_string()
}
#[cfg(target_os = "linux")]
fn sealed_key(file: &NativeSealed) -> String {
    let key = file.key();
    format!("unix:{}:{}:{}", key.device, key.inode, key.uid)
}
#[cfg(windows)]
fn failed_key(file: &NativeFailedCreate) -> Option<String> {
    file.observed_key().ok().map(|key| key.to_string())
}
#[cfg(target_os = "linux")]
fn failed_key(file: &NativeFailedCreate) -> Option<String> {
    file.observed_key()
        .ok()
        .map(|key| format!("unix:{}:{}:{}", key.device, key.inode, key.uid))
}

#[cfg(windows)]
fn filesystem_key(parent: &NativeParent) -> Result<String> {
    Ok(format!("windows-volume:{}", parent.key()?.volume))
}
#[cfg(target_os = "linux")]
fn filesystem_key(parent: &NativeParent) -> Result<String> {
    Ok(format!("unix-device:{}", parent.key()?.device))
}

impl<'proof, 'local, 'scope> PreparedDeploymentInstall<'proof, 'local, 'scope> {
    pub fn preflight(
        mapping: RestrictedDeploymentMapping,
        completions: Vec<OriginalDeploymentNodeCompletion<'proof, 'local, 'scope>>,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Self> {
        mapping.original.reverify_provider(provider)?;
        if mapping.artifacts.len() > mapping.original.bounds.artifacts
            || completions.len() != mapping.original.graph.nodes.len()
        {
            return Err(ReconcileError::ResourceLimit(
                "complete deployment installation membership",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut node_receipts = Vec::new();
        for completion in &completions {
            if !ids.insert(completion.id) {
                return Err(ReconcileError::Invariant(
                    "duplicate actual node completion loan",
                ));
            }
            let descriptor = mapping.original.graph.node(completion.id)?;
            node_receipts
                .push(completion.verify(descriptor, &mapping.mapping.node_roots[&completion.id])?);
        }
        node_receipts.sort_by_key(|receipt| receipt.id);
        if ids
            != mapping
                .original
                .graph
                .nodes
                .iter()
                .map(|node| node.id)
                .collect()
        {
            return Err(ReconcileError::Invariant(
                "missing actual target completion",
            ));
        }
        let mut parents = BTreeMap::new();
        let mut native_slots = BTreeSet::new();
        let mut future_bytes = 0u64;
        for artifact in &mapping.artifacts {
            let name = component(&artifact.target)?;
            let path = artifact.target.parent().ok_or(ReconcileError::Invariant(
                "deployment target retained parent",
            ))?;
            if !parents.contains_key(path) {
                parents.insert(path.to_path_buf(), NativeParent::open_private(path)?);
            }
            let parent = &parents[path];
            let key = parent_key(parent)?;
            let alias = if mapping.original.graph.platform
                == sync_extend_core_model::deployment::DeploymentPlatform::Windows
            {
                name.to_uppercase()
            } else {
                name.to_owned()
            };
            if !native_slots.insert((key, alias)) {
                return Err(ReconcileError::Invariant(
                    "actual target parent/component native alias",
                ));
            }
            parent.require_absent(name)?;
            if ContentId::hash(&artifact.bytes) != artifact.digest || artifact.bytes.is_empty() {
                return Err(ReconcileError::Invariant(
                    "mapped target immutable expected bytes",
                ));
            }
            future_bytes = future_bytes
                .checked_add(artifact.bytes.len() as u64)
                .filter(|bytes| *bytes <= mapping.original.bounds.plaintext_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "deployment complete future file byte liability",
                ))?;
        }
        let mut runtime_directories = Vec::new();
        let mut runtime_keys = BTreeSet::new();
        for path in mapping.mapping.runtime_directories.values() {
            let directory = NativeParent::open_private(path)?;
            directory.require_empty()?;
            if !runtime_keys.insert(parent_key(&directory)?) {
                return Err(ReconcileError::Invariant(
                    "actual runtime directory native alias",
                ));
            }
            runtime_directories.push(directory);
        }
        let mut pinned_programs = Vec::new();
        let mut programs = BTreeMap::new();
        for reference in &mapping.original.graph.references {
            if let DeploymentReferenceTarget::PinnedExecutable { path, digest } = &reference.target
            {
                if let Some(previous) = programs.insert(path.clone(), digest.clone()) {
                    if previous != *digest {
                        return Err(ReconcileError::Invariant(
                            "pinned executable has inconsistent selected digest",
                        ));
                    }
                }
            }
        }
        let mut known = mapping.original.framing.bytes().len() as u64 + future_bytes;
        let mut program_keys = BTreeSet::new();
        for (path, digest) in programs {
            let remaining = mapping
                .original
                .bounds
                .memory_bytes
                .checked_sub(known)
                .filter(|bytes| *bytes > 0)
                .ok_or(ReconcileError::ResourceLimit(
                    "pinned executable pre-CREATE memory liability",
                ))?;
            let original = OriginalProtectedArtifact::capture(
                &path,
                remaining.min(256 * 1024 * 1024) as usize,
                false,
            )?;
            if original.source_digest() != &digest
                || !program_keys.insert(original.native_identity()?)
            {
                return Err(ReconcileError::Invariant(
                    "actual original pinned executable digest/alias",
                ));
            }
            known = known.checked_add(original.source_bytes() as u64).ok_or(
                ReconcileError::ResourceLimit("pinned executable aggregate bytes"),
            )?;
            mapping.original.bounds.memory([known])?;
            pinned_programs.push(original);
        }
        let result = Self {
            mapping,
            completions,
            parents,
            runtime_directories,
            pinned_programs,
            node_receipts,
        };
        result.verify_preflight(provider)?;
        Ok(result)
    }

    pub fn preview(&self) -> Result<serde_json::Value> {
        let mut value = self.mapping.preview()?;
        value["actual_target_node_completions"] = serde_json::to_value(&self.node_receipts)?;
        value["all_target_slots_observed_empty_before_any_create"] = true.into();
        value["actual_private_parents"] = serde_json::to_value(
            self.parents
                .iter()
                .map(|(path, parent)| {
                    Ok(serde_json::json!({
                        "path": path, "key": parent_key(parent)?,
                    }))
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
        Ok(value)
    }

    fn verify_nodes(&self) -> Result<()> {
        for original in &self.completions {
            let descriptor = self.mapping.original.graph.node(original.id)?;
            let observed =
                original.verify(descriptor, &self.mapping.mapping.node_roots[&original.id])?;
            let expected = self
                .node_receipts
                .iter()
                .find(|row| row.id == original.id)
                .ok_or(ReconcileError::Invariant(
                    "actual deployment completed node binding absent",
                ))?;
            if serde_json::to_vec(&observed)? != serde_json::to_vec(expected)? {
                return Err(ReconcileError::Invariant(
                    "retained actual target completion changed",
                ));
            }
        }
        Ok(())
    }

    fn verify_scope(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.mapping.original.reverify_provider(provider)?;
        self.verify_nodes()?;
        for parent in self.parents.values() {
            parent.verify_original()?;
        }
        for directory in &self.runtime_directories {
            directory.verify_original()?;
        }
        for original in &self.pinned_programs {
            original.verify_original()?;
        }
        Ok(())
    }

    fn verify_preflight(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.verify_scope(provider)?;
        let mut available = BTreeMap::<String, u64>::new();
        let mut liabilities = BTreeMap::<String, u64>::new();
        for artifact in &self.mapping.artifacts {
            let parent = &self.parents[artifact
                .target
                .parent()
                .ok_or(ReconcileError::Invariant("deployment actual target parent"))?];
            parent.require_absent(component(&artifact.target)?)?;
            let filesystem = filesystem_key(parent)?;
            let (bytes, unit) = parent.available_space()?;
            available
                .entry(filesystem.clone())
                .and_modify(|previous| *previous = (*previous).min(bytes))
                .or_insert(bytes);
            let rounded = (artifact.bytes.len() as u64)
                .checked_add(unit - 1)
                .and_then(|bytes| bytes.checked_div(unit))
                .and_then(|units| units.checked_mul(unit))
                .ok_or(ReconcileError::ResourceLimit(
                    "deployment future allocation rounding",
                ))?;
            let prior = liabilities.entry(filesystem).or_default();
            *prior = prior
                .checked_add(rounded)
                .ok_or(ReconcileError::ResourceLimit(
                    "deployment complete filesystem byte liability",
                ))?;
        }
        if liabilities
            .iter()
            .any(|(filesystem, bytes)| available[filesystem] < *bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "deployment actual filesystem available bytes",
            ));
        }
        for directory in &self.runtime_directories {
            directory.require_empty()?;
        }
        Ok(())
    }

    pub fn install(
        self,
        provider: &DeploymentProtectionProvider,
    ) -> std::result::Result<
        CompleteDeploymentInstall<'proof, 'local, 'scope>,
        DeploymentInstallFailure<'proof, 'local, 'scope>,
    > {
        let attempt_id = match EntryId::random() {
            Ok(value) => value,
            Err(error) => return Err(DeploymentInstallFailure::before_create(self, error.into())),
        };
        if let Err(error) = self.verify_preflight(provider) {
            return Err(DeploymentInstallFailure::before_create_with_id(
                self, attempt_id, error,
            ));
        }
        let mut attempt = OriginalDeploymentInstallAttempt {
            prepared: self,
            attempt_id: Some(attempt_id),
            file_receipts: Vec::new(),
            files: Vec::new(),
            failed_file: None,
            failed_create: None,
            unsealed_creator: None,
            complete: false,
        };
        let mut order: Vec<_> = (0..attempt.prepared.mapping.artifacts.len()).collect();
        let root = attempt.prepared.mapping.original.graph.root_deployment;
        order.sort_by_key(|index| {
            let artifact = &attempt.prepared.mapping.artifacts[*index];
            (
                if artifact.id == root {
                    255
                } else {
                    installation_priority(artifact.role)
                },
                artifact.id,
            )
        });
        for index in order {
            let artifact = &attempt.prepared.mapping.artifacts[index];
            let parent_path = match artifact.target.parent() {
                Some(path) => path,
                None => {
                    return Err(DeploymentInstallFailure {
                        error: ReconcileError::Invariant(
                            "deployment original target parent absent",
                        ),
                        original_attempt: attempt,
                    })
                }
            };
            let parent = &attempt.prepared.parents[parent_path];
            let descriptor = match (|| -> Result<DeploymentFileAttempt> {
                provider.verify_original()?;
                parent.verify_original()?;
                parent.require_absent(component(&artifact.target)?)?;
                let previous_receipt_digest = attempt
                    .file_receipts
                    .last()
                    .map(|receipt: &DeploymentFileReceipt| receipt.receipt_digest.clone())
                    .unwrap_or_else(|| {
                        ContentId::hash(b"SyncExtend deployment original CREATE chain v2")
                    });
                Ok(DeploymentFileAttempt {
                    format_version: 2,
                    attempt_id: attempt
                        .attempt_id
                        .as_ref()
                        .ok_or(ReconcileError::Invariant(
                            "actual deployment attempt ID absent",
                        ))?
                        .clone(),
                    sequence: u32::try_from(attempt.file_receipts.len()).map_err(|_| {
                        ReconcileError::ResourceLimit("deployment attempt sequence")
                    })?,
                    artifact_id: artifact.id,
                    role: artifact.role,
                    target: artifact.target.clone(),
                    parent_key: parent_key(parent)?,
                    expected_bytes: artifact.bytes.len() as u64,
                    expected_digest: artifact.digest.clone(),
                    bundle_digest: attempt.prepared.mapping.original.digest().clone(),
                    mapping_digest: attempt.prepared.mapping.mapping_digest.clone(),
                    previous_receipt_digest,
                })
            })() {
                Ok(value) => value,
                Err(error) => {
                    return Err(DeploymentInstallFailure {
                        error,
                        original_attempt: attempt,
                    })
                }
            };
            let component = match component(&artifact.target) {
                Ok(component) => component,
                Err(error) => {
                    return Err(DeploymentInstallFailure {
                        error,
                        original_attempt: attempt,
                    })
                }
            };
            let mut creator = match parent.create_new(component) {
                Ok(value) => value,
                Err(failure) => {
                    attempt.failed_file = Some(DeploymentFailedFileReceipt {
                        original_attempt: descriptor,
                        original_create_happened: failure.original_created.is_some(),
                        observed_original_key: failure
                            .original_created
                            .as_ref()
                            .and_then(failed_key),
                        observed_original_bytes: failure
                            .original_created
                            .as_ref()
                            .and_then(|file| file.observed_bytes().ok()),
                        operation: "private_create_new".into(),
                    });
                    attempt.failed_create = failure.original_created;
                    return Err(DeploymentInstallFailure {
                        error: failure.error.into(),
                        original_attempt: attempt,
                    });
                }
            };
            let original_key = creator_key(&creator);
            if let Err(error) = creator.write_and_sync(&artifact.bytes) {
                attempt.failed_file = Some(DeploymentFailedFileReceipt {
                    original_attempt: descriptor,
                    original_create_happened: true,
                    observed_original_key: Some(original_key),
                    observed_original_bytes: None,
                    operation: "original_write_sync_readback".into(),
                });
                attempt.unsealed_creator = Some(creator);
                return Err(DeploymentInstallFailure {
                    error: error.into(),
                    original_attempt: attempt,
                });
            }
            let sealed = match creator.seal(&artifact.bytes) {
                Ok(value) => value,
                Err(failure) => {
                    attempt.failed_file = Some(DeploymentFailedFileReceipt {
                        original_attempt: descriptor,
                        original_create_happened: true,
                        observed_original_key: Some(original_key),
                        observed_original_bytes: Some(artifact.bytes.len() as u64),
                        operation: "original_read_seal".into(),
                    });
                    attempt.unsealed_creator = Some(failure.original_creator);
                    return Err(DeploymentInstallFailure {
                        error: failure.error.into(),
                        original_attempt: attempt,
                    });
                }
            };
            let checked = (|| -> Result<DeploymentFileReceipt> {
                sealed.verify_original(&artifact.bytes)?;
                if sealed_key(&sealed) != original_key {
                    return Err(ReconcileError::Invariant(
                        "sealed original deployment key changed",
                    ));
                }
                let receipt_digest = ContentId::hash(&serde_json::to_vec(&(
                    "sync-extend-deployment-original-file-receipt-v2",
                    &descriptor,
                    &original_key,
                    artifact.bytes.len() as u64,
                    &artifact.digest,
                ))?);
                Ok(DeploymentFileReceipt {
                    original_attempt: descriptor,
                    original_key,
                    actual_bytes: artifact.bytes.len() as u64,
                    actual_digest: artifact.digest.clone(),
                    original_private_create_verified: true,
                    original_file_sync_and_readback_verified: true,
                    original_parent_sync_verified: cfg!(target_os = "linux"),
                    original_sealed_read_scope_verified: true,
                    receipt_digest,
                })
            })();
            // Keep the actual sealed object even if the final audit fails.
            attempt.files.push((index, sealed));
            match checked {
                Ok(receipt) => attempt.file_receipts.push(receipt),
                Err(error) => {
                    return Err(DeploymentInstallFailure {
                        error,
                        original_attempt: attempt,
                    })
                }
            }
        }
        if let Err(error) = attempt.verify_complete(provider) {
            return Err(DeploymentInstallFailure {
                error,
                original_attempt: attempt,
            });
        }
        attempt.complete = true;
        Ok(CompleteDeploymentInstall {
            original_attempt: attempt,
        })
    }
}

fn installation_priority(role: DeploymentArtifactRole) -> u8 {
    match role {
        DeploymentArtifactRole::WebdavCredential
        | DeploymentArtifactRole::ManagementCredential
        | DeploymentArtifactRole::TlsPrivateKey => 0,
        DeploymentArtifactRole::EasyTierConfig => 1,
        DeploymentArtifactRole::TlsCertificate
        | DeploymentArtifactRole::StorageForwarder
        | DeploymentArtifactRole::TransportAttemptPolicy => 2,
        DeploymentArtifactRole::NodeConfig | DeploymentArtifactRole::StorageConfig => 3,
        DeploymentArtifactRole::GatewayConfig | DeploymentArtifactRole::ManagementConfig => 4,
        DeploymentArtifactRole::DeploymentConfig => 5,
        DeploymentArtifactRole::NodeState => 254,
    }
}

/// No public native creator view exists. The retained actual successful prefix
/// and failed original file are closed explicitly, and are never deleted here.
pub struct OriginalDeploymentInstallAttempt<'proof, 'local, 'scope> {
    prepared: PreparedDeploymentInstall<'proof, 'local, 'scope>,
    attempt_id: Option<EntryId>,
    file_receipts: Vec<DeploymentFileReceipt>,
    files: Vec<(usize, NativeSealed)>,
    failed_file: Option<DeploymentFailedFileReceipt>,
    failed_create: Option<NativeFailedCreate>,
    unsealed_creator: Option<NativeCreator>,
    complete: bool,
}

impl OriginalDeploymentInstallAttempt<'_, '_, '_> {
    pub fn receipt(&self) -> DeploymentInstallReceipt {
        let root = self.prepared.mapping.original.graph.root_deployment;
        DeploymentInstallReceipt {
            format_version: 2,
            attempt_id: self.attempt_id.clone(),
            bundle_digest: self.prepared.mapping.original.digest().clone(),
            mapping_digest: self.prepared.mapping.mapping_digest.clone(),
            root_deployment: self.prepared.mapping.root_deployment_path().into(),
            nodes: self.prepared.node_receipts.clone(),
            files: self.file_receipts.clone(),
            failed_file: self.failed_file.clone(),
            full_graph_and_original_creators_verified: self.complete,
            root_deployment_written_last: self
                .file_receipts
                .last()
                .is_some_and(|receipt| receipt.original_attempt.artifact_id == root),
            services_started: false,
        }
    }

    fn verify_complete(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.prepared.verify_scope(provider)?;
        if self.failed_file.is_some()
            || self.failed_create.is_some()
            || self.unsealed_creator.is_some()
            || self.files.len() != self.prepared.mapping.artifacts.len()
            || self.file_receipts.len() != self.files.len()
            || self.file_receipts.last().is_none_or(|receipt| {
                receipt.original_attempt.artifact_id
                    != self.prepared.mapping.original.graph.root_deployment
            })
        {
            return Err(ReconcileError::Invariant(
                "complete original deployment installation prefix",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut previous = ContentId::hash(b"SyncExtend deployment original CREATE chain v2");
        for ((index, file), receipt) in self.files.iter().zip(&self.file_receipts) {
            let artifact = &self.prepared.mapping.artifacts[*index];
            file.verify_original(&artifact.bytes)?;
            if receipt.original_attempt.artifact_id != artifact.id
                || receipt.original_attempt.expected_digest != artifact.digest
                || receipt.actual_digest != artifact.digest
                || receipt.actual_bytes != artifact.bytes.len() as u64
                || receipt.original_attempt.previous_receipt_digest != previous
                || receipt.original_key != sealed_key(file)
                || !ids.insert(artifact.id)
                || !keys.insert(receipt.original_key.clone())
                || receipt.receipt_digest
                    != ContentId::hash(&serde_json::to_vec(&(
                        "sync-extend-deployment-original-file-receipt-v2",
                        &receipt.original_attempt,
                        &receipt.original_key,
                        artifact.bytes.len() as u64,
                        &artifact.digest,
                    ))?)
            {
                return Err(ReconcileError::Invariant(
                    "complete installed graph original file/attempt/chain",
                ));
            }
            previous = receipt.receipt_digest.clone();
        }
        if ids
            != self
                .prepared
                .mapping
                .artifacts
                .iter()
                .map(|row| row.id)
                .collect()
        {
            return Err(ReconcileError::Invariant(
                "complete installed original artifact membership",
            ));
        }
        self.prepared.verify_scope(provider)
    }

    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        let receipt = self.receipt();
        let Self {
            files,
            failed_create,
            unsealed_creator,
            prepared,
            ..
        } = self;
        let mut first_error = None;
        for (_, file) in files {
            if let Err(error) = file.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(file) = failed_create {
            if let Err(error) = file.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(file) = unsealed_creator {
            if let Err(error) = file.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        for (_, parent) in prepared.parents {
            if let Err(error) = parent.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        for directory in prepared.runtime_directories {
            if let Err(error) = directory.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(receipt)
    }
}

pub struct DeploymentInstallFailure<'proof, 'local, 'scope> {
    pub error: ReconcileError,
    pub original_attempt: OriginalDeploymentInstallAttempt<'proof, 'local, 'scope>,
}
impl<'proof, 'local, 'scope> DeploymentInstallFailure<'proof, 'local, 'scope> {
    fn before_create(
        prepared: PreparedDeploymentInstall<'proof, 'local, 'scope>,
        error: ReconcileError,
    ) -> Self {
        Self {
            error,
            original_attempt: OriginalDeploymentInstallAttempt {
                prepared,
                attempt_id: None,
                file_receipts: Vec::new(),
                files: Vec::new(),
                failed_file: None,
                failed_create: None,
                unsealed_creator: None,
                complete: false,
            },
        }
    }
    fn before_create_with_id(
        prepared: PreparedDeploymentInstall<'proof, 'local, 'scope>,
        attempt_id: EntryId,
        error: ReconcileError,
    ) -> Self {
        Self {
            error,
            original_attempt: OriginalDeploymentInstallAttempt {
                prepared,
                attempt_id: Some(attempt_id),
                file_receipts: Vec::new(),
                files: Vec::new(),
                failed_file: None,
                failed_create: None,
                unsealed_creator: None,
                complete: false,
            },
        }
    }
}

/// Its constructor and originals are private. A serialized receipt cannot
/// create this value or cause a start; capture, mapping, install and run remain
/// separate operations.
pub struct CompleteDeploymentInstall<'proof, 'local, 'scope> {
    original_attempt: OriginalDeploymentInstallAttempt<'proof, 'local, 'scope>,
}
impl CompleteDeploymentInstall<'_, '_, '_> {
    pub fn receipt(&self) -> DeploymentInstallReceipt {
        self.original_attempt.receipt()
    }
    pub fn verify(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        if !self.original_attempt.complete {
            return Err(ReconcileError::Invariant(
                "living original deployment completion absent",
            ));
        }
        self.original_attempt.verify_complete(provider)
    }
    pub fn root_deployment_path(&self) -> &Path {
        self.original_attempt
            .prepared
            .mapping
            .root_deployment_path()
    }
    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        self.original_attempt.close()
    }
}
