//! Full preflight, original private CREATE and immutable per-file attempts.
//! Decoded receipts describe history; only retained original creators can issue
//! a living complete installation. Failed prefixes are kept, never rolled back.
use super::{
    deployment_bundle::{
        DeploymentArtifactRole, DeploymentNodeDescriptor, DeploymentNodeTarget,
        DeploymentReferenceTarget, RestrictedDeploymentMapping,
    },
    protected_artifact::{DeploymentProtectionProvider, OriginalProtectedArtifact},
    NativeCreator, NativeFailedCreate, NativeParent, NativeSealed,
};
use crate::{path_comparison::path_equal, ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{ContentId, EntryId, PortablePath};

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
pub struct OriginalDeploymentNodeCompletion<'proof> {
    id: u32,
    original: &'proof dyn ActualDeploymentNodeProof,
}

/// Only this crate implements the sealed proof. Erasing its internal local and
/// directory lifetimes permits several live node scopes to be borrowed together.
/// It does not expose a public receipt/proof constructor or LocalSpace.
trait ActualDeploymentNodeProof {
    fn verify_target(
        &self,
        id: u32,
        descriptor: &DeploymentNodeDescriptor,
        target: &DeploymentNodeTarget,
    ) -> Result<DeploymentNodeCompletionReceipt>;
}

impl<'proof> OriginalDeploymentNodeCompletion<'proof> {
    #[cfg(windows)]
    pub fn from_original<'local, 'scope>(
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

    /// Consume this borrow while retaining the same living sealed proof.
    pub fn into_shorter_borrow<'short>(self) -> OriginalDeploymentNodeCompletion<'short>
    where
        'proof: 'short,
    {
        self
    }

    fn verify(
        &self,
        descriptor: &DeploymentNodeDescriptor,
        target: &DeploymentNodeTarget,
    ) -> Result<DeploymentNodeCompletionReceipt> {
        self.original.verify_target(self.id, descriptor, target)
    }
}

#[cfg(windows)]
impl ActualDeploymentNodeProof for crate::OriginalNodeCompletionObservation<'_, '_> {
    fn verify_target(
        &self,
        id: u32,
        descriptor: &DeploymentNodeDescriptor,
        target: &DeploymentNodeTarget,
    ) -> Result<DeploymentNodeCompletionReceipt> {
            let binding = self.deployment_binding()?;
            if id != descriptor.id
                || binding.archive_digest() != &descriptor.archive_digest
                || !path_equal(binding.data_dir(), &target.data_dir)
                || !path_equal(binding.worktree(), &target.worktree)
                || binding.space_id()? != descriptor.space_id
                || binding.device_id()? != descriptor.device_id
            {
                return Err(ReconcileError::Invariant(
                    "actual original deployment target completion differs",
                ));
            }
            let receipt = DeploymentNodeCompletionReceipt {
                id,
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
pub struct PreparedDeploymentInstall<'proof> {
    mapping: RestrictedDeploymentMapping,
    completions: Vec<OriginalDeploymentNodeCompletion<'proof>>,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
    node_receipts: Vec<DeploymentNodeCompletionReceipt>,
}

/// All future private file slots, provider bytes, executable pins and runtime
/// parents can be retained before any selected node restore CREATE.
pub struct PreparedDeploymentTargets {
    mapping: RestrictedDeploymentMapping,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
}

#[cfg(windows)]
pub struct DeploymentTargetsPreflightFailure {
    pub error: ReconcileError,
    pub original_targets: PreparedDeploymentTargets,
    pub original_open_failures: Vec<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
}

#[cfg(windows)]
impl DeploymentTargetsPreflightFailure {
    pub fn close_retaining(self) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        close.append_result(self.original_targets.close_retaining());
        for original in self.original_open_failures {
            close.append_failure(original);
        }
        close.finish()
    }
}

#[cfg(windows)]
pub struct DeploymentCompletionPreflightFailure {
    pub error: ReconcileError,
    pub original_targets: PreparedDeploymentTargets,
}

#[derive(Serialize)]
pub struct DeploymentFilesystemLiability {
    pub filesystem: String,
    pub allocation_bytes: u64,
    pub available_bytes: u64,
    pub allocation_unit: u64,
}

pub(super) fn component(path: &Path) -> Result<&str> {
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
pub(super) fn parent_key(parent: &NativeParent) -> Result<String> {
    Ok(parent.key()?.to_string())
}
#[cfg(target_os = "linux")]
pub(super) fn parent_key(parent: &NativeParent) -> Result<String> {
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
pub(super) fn sealed_key(file: &NativeSealed) -> String {
    file.key().to_string()
}
#[cfg(target_os = "linux")]
pub(super) fn sealed_key(file: &NativeSealed) -> String {
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

fn verify_resource_scope(
    mapping: &RestrictedDeploymentMapping,
    parents: &BTreeMap<PathBuf, NativeParent>,
    runtime_directories: &[NativeParent],
    pinned_programs: &[OriginalProtectedArtifact],
    provider: &DeploymentProtectionProvider,
) -> Result<()> {
    mapping.original.reverify_provider(provider)?;
    for parent in parents.values() { parent.verify_original()?; }
    for directory in runtime_directories { directory.verify_original()?; }
    for original in pinned_programs { original.verify_original()?; }
    Ok(())
}

fn verify_preflight_resources(
    mapping: &RestrictedDeploymentMapping,
    parents: &BTreeMap<PathBuf, NativeParent>,
    runtime_directories: &[NativeParent],
    pinned_programs: &[OriginalProtectedArtifact],
    provider: &DeploymentProtectionProvider,
) -> Result<()> {
    verify_resource_scope(mapping, parents, runtime_directories, pinned_programs, provider)?;
    let mut available = BTreeMap::<String, u64>::new();
    let mut liabilities = BTreeMap::<String, u64>::new();
    for artifact in &mapping.artifacts {
        let parent = &parents[artifact.target.parent()
            .ok_or(ReconcileError::Invariant("deployment actual target parent"))?];
        parent.require_absent(component(&artifact.target)?)?;
        let filesystem = filesystem_key(parent)?;
        let (bytes, unit) = parent.available_space()?;
        available.entry(filesystem.clone())
            .and_modify(|previous| *previous = (*previous).min(bytes)).or_insert(bytes);
        let rounded = (artifact.bytes.len() as u64)
            .checked_add(unit.checked_sub(1)
                .ok_or(ReconcileError::Invariant("actual deployment allocation unit is zero"))?)
            .and_then(|bytes| bytes.checked_div(unit))
            .and_then(|units| units.checked_mul(unit))
            .ok_or(ReconcileError::ResourceLimit("deployment future allocation rounding"))?;
        let prior = liabilities.entry(filesystem).or_default();
        *prior = prior.checked_add(rounded)
            .ok_or(ReconcileError::ResourceLimit("deployment complete filesystem byte liability"))?;
    }
    if liabilities.iter().any(|(filesystem, bytes)| available[filesystem] < *bytes) {
        return Err(ReconcileError::ResourceLimit("deployment actual filesystem available bytes"));
    }
    for directory in runtime_directories { directory.require_empty()?; }
    Ok(())
}

impl PreparedDeploymentTargets {
    pub fn future_file_liabilities(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Vec<DeploymentFilesystemLiability>> {
        self.verify(provider)?;
        let mut result = Vec::new();
        for artifact in &self.mapping.artifacts {
            let parent = &self.parents[artifact.target.parent()
                .ok_or(ReconcileError::Invariant("actual deployment file parent absent"))?];
            let (available_bytes, allocation_unit) = parent.available_space()?;
            let allocation_bytes = (artifact.bytes.len() as u64)
                .checked_add(allocation_unit.checked_sub(1).ok_or(ReconcileError::Invariant(
                    "original deployment allocation unit is zero",
                ))?)
                .and_then(|bytes| bytes.checked_div(allocation_unit))
                .and_then(|units| units.checked_mul(allocation_unit))
                .ok_or(ReconcileError::ResourceLimit("original deployment file allocation bound"))?;
            result.push(DeploymentFilesystemLiability {
                filesystem: filesystem_key(parent)?, allocation_bytes,
                available_bytes, allocation_unit,
            });
        }
        self.verify(provider)?;
        Ok(result)
    }

    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        close_original_deployment_resources(
            self.mapping, Vec::new(), None, None, self.parents,
            self.runtime_directories, self.pinned_programs,
        )
    }

    #[cfg(windows)]
    pub fn node_restore_inputs(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Vec<super::deployment_bundle::DeploymentNodeRestoreInput>> {
        self.verify(provider)?;
        self.mapping.node_restore_inputs(provider)
    }

    pub fn preflight(
        mapping: RestrictedDeploymentMapping,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Self> {
        #[cfg(windows)]
        {
            return Self::preflight_retaining(mapping, provider).map_err(|failure| {
                let error = ReconcileError::Io(std::io::Error::other(failure.error.to_string()));
                if let Err(original) = failure.close_retaining() {
                    original.retain_until_process_exit();
                }
                error
            });
        }
        #[cfg(not(windows))]
        {
            let mut result = Self {
                mapping, parents: BTreeMap::new(), runtime_directories: Vec::new(),
                pinned_programs: Vec::new(),
            };
            Self::prepare_resource_scope(
                &result.mapping, provider, &mut result.parents,
                &mut result.runtime_directories, &mut result.pinned_programs,
            )?;
            Ok(result)
        }
    }

    #[cfg(windows)]
    pub fn preflight_retaining(
        mapping: RestrictedDeploymentMapping,
        provider: &DeploymentProtectionProvider,
    ) -> std::result::Result<Self, DeploymentTargetsPreflightFailure> {
        let mut original_targets = Self {
            mapping, parents: BTreeMap::new(), runtime_directories: Vec::new(),
            pinned_programs: Vec::new(),
        };
        let mut original_open_failures = Vec::new();
        if let Err(error) = Self::prepare_resource_scope(
            &original_targets.mapping, provider, &mut original_targets.parents,
            &mut original_targets.runtime_directories, &mut original_targets.pinned_programs,
            &mut original_open_failures,
        ) {
            return Err(DeploymentTargetsPreflightFailure {
                error, original_targets, original_open_failures,
            });
        }
        Ok(original_targets)
    }

    fn prepare_resource_scope(
        mapping: &RestrictedDeploymentMapping,
        provider: &DeploymentProtectionProvider,
        parents: &mut BTreeMap<PathBuf, NativeParent>,
        runtime_directories: &mut Vec<NativeParent>,
        pinned_programs: &mut Vec<OriginalProtectedArtifact>,
        #[cfg(windows)] original_open_failures:
            &mut Vec<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
    ) -> Result<()> {
        mapping.original.reverify_provider(provider)?;
        if mapping.artifacts.len() > mapping.original.bounds.artifacts {
            return Err(ReconcileError::ResourceLimit(
                "complete deployment installation membership",
            ));
        }
        let mut native_slots = BTreeSet::new();
        let mut future_bytes = 0u64;
        for artifact in &mapping.artifacts {
            let name = component(&artifact.target)?;
            let path = artifact.target.parent().ok_or(ReconcileError::Invariant(
                "deployment target retained parent",
            ))?;
            if !parents.contains_key(path) {
                #[cfg(windows)]
                let original = NativeParent::open_private_retaining(path).map_err(|failure| {
                    if let Some(resources) = failure.original_resources {
                        original_open_failures.push(resources);
                    }
                    ReconcileError::Io(failure.error)
                })?;
                #[cfg(not(windows))]
                let original = NativeParent::open_private(path)?;
                parents.insert(path.to_path_buf(), original);
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
        let mut runtime_keys = BTreeSet::new();
        for path in mapping.mapping.runtime_directories.values() {
            #[cfg(windows)]
            let directory = NativeParent::open_private_retaining(path).map_err(|failure| {
                if let Some(resources) = failure.original_resources {
                    original_open_failures.push(resources);
                }
                ReconcileError::Io(failure.error)
            })?;
            #[cfg(not(windows))]
            let directory = NativeParent::open_private(path)?;
            runtime_directories.push(directory);
            let directory = runtime_directories.last().ok_or(ReconcileError::Unstable)?;
            directory.require_empty()?;
            if !runtime_keys.insert(parent_key(&directory)?) {
                return Err(ReconcileError::Invariant(
                    "actual runtime directory native alias",
                ));
            }
        }
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
            #[cfg(windows)]
            let original = OriginalProtectedArtifact::capture_retaining(
                &path, remaining.min(256 * 1024 * 1024) as usize, false,
            ).map_err(|failure| {
                if let Some(resources) = failure.original_resources {
                    original_open_failures.push(resources);
                }
                failure.error
            })?;
            #[cfg(not(windows))]
            let original = OriginalProtectedArtifact::capture(
                &path,
                remaining.min(256 * 1024 * 1024) as usize,
                false,
            )?;
            pinned_programs.push(original);
            let original = pinned_programs.last().ok_or(ReconcileError::Unstable)?;
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
        }
        verify_preflight_resources(mapping, parents, runtime_directories, pinned_programs, provider)
    }

    pub fn with_original_completions<'proof>(
        self,
        completions: Vec<OriginalDeploymentNodeCompletion<'proof>>,
        provider: &DeploymentProtectionProvider,
    ) -> Result<PreparedDeploymentInstall<'proof>> {
        #[cfg(windows)]
        {
            return self.with_original_completions_retaining(completions, provider)
                .map_err(|failure| {
                    if let Err(original) = failure.original_targets.close_retaining() {
                        original.retain_until_process_exit();
                    }
                    failure.error
                });
        }
        #[cfg(not(windows))]
        {
            let node_receipts = self.checked_original_completions(&completions, provider)?;
            Ok(PreparedDeploymentInstall {
                mapping: self.mapping, completions, parents: self.parents,
                runtime_directories: self.runtime_directories, pinned_programs: self.pinned_programs,
                node_receipts,
            })
        }
    }

    #[cfg(windows)]
    pub fn with_original_completions_retaining<'proof>(
        self,
        completions: Vec<OriginalDeploymentNodeCompletion<'proof>>,
        provider: &DeploymentProtectionProvider,
    ) -> std::result::Result<PreparedDeploymentInstall<'proof>, DeploymentCompletionPreflightFailure> {
        let node_receipts = match self.checked_original_completions(&completions, provider) {
            Ok(receipts) => receipts,
            Err(error) => return Err(DeploymentCompletionPreflightFailure {
                error, original_targets: self,
            }),
        };
        Ok(PreparedDeploymentInstall {
            mapping: self.mapping, completions, parents: self.parents,
            runtime_directories: self.runtime_directories, pinned_programs: self.pinned_programs,
            node_receipts,
        })
    }

    fn checked_original_completions(
        &self,
        completions: &[OriginalDeploymentNodeCompletion<'_>],
        provider: &DeploymentProtectionProvider,
    ) -> Result<Vec<DeploymentNodeCompletionReceipt>> {
        if completions.len() != self.mapping.original.graph.nodes.len() {
            return Err(ReconcileError::Invariant("complete original node completion set required"));
        }
        let mut ids = BTreeSet::new();
        let mut node_receipts = Vec::new();
        for completion in completions {
            if !ids.insert(completion.id) {
                return Err(ReconcileError::Invariant("duplicate actual node completion loan"));
            }
            let descriptor = self.mapping.original.graph.node(completion.id)?;
            node_receipts.push(completion.verify(
                descriptor, &self.mapping.mapping.node_roots[&completion.id],
            )?);
        }
        node_receipts.sort_by_key(|receipt| receipt.id);
        if ids != self.mapping.original.graph.nodes.iter().map(|node| node.id).collect() {
            return Err(ReconcileError::Invariant("missing actual target completion"));
        }
        self.verify(provider)?;
        Ok(node_receipts)
    }

    pub fn verify(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        verify_preflight_resources(&self.mapping, &self.parents,
            &self.runtime_directories, &self.pinned_programs, provider)
    }

    pub fn preview(&self) -> Result<serde_json::Value> {
        let mut value = self.mapping.preview()?;
        value["all_future_slots_private_empty_and_retained_before_node_restore"] = true.into();
        value["node_completion_authority"] = false.into();
        Ok(value)
    }
}

impl<'proof> PreparedDeploymentInstall<'proof> {
    pub fn preflight(
        mapping: RestrictedDeploymentMapping,
        completions: Vec<OriginalDeploymentNodeCompletion<'proof>>,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Self> {
        PreparedDeploymentTargets::preflight(mapping, provider)?
            .with_original_completions(completions, provider)
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
        self.verify_nodes()?;
        verify_resource_scope(&self.mapping, &self.parents, &self.runtime_directories,
            &self.pinned_programs, provider)
    }

    fn verify_preflight(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        self.verify_nodes()?;
        verify_preflight_resources(&self.mapping, &self.parents,
            &self.runtime_directories, &self.pinned_programs, provider)
    }

    pub fn install(
        self,
        provider: &DeploymentProtectionProvider,
    ) -> std::result::Result<
        CompleteDeploymentInstall<'proof>,
        DeploymentInstallFailure<'proof>,
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
                    original_parent_sync_verified: ORIGINAL_PARENT_SYNC_VERIFIED,
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
pub struct OriginalDeploymentInstallAttempt<'proof> {
    prepared: PreparedDeploymentInstall<'proof>,
    attempt_id: Option<EntryId>,
    file_receipts: Vec<DeploymentFileReceipt>,
    files: Vec<(usize, NativeSealed)>,
    failed_file: Option<DeploymentFailedFileReceipt>,
    failed_create: Option<NativeFailedCreate>,
    unsealed_creator: Option<NativeCreator>,
    complete: bool,
}

/// The Linux creator fsyncs the retained parent directory as part of the
/// bounded write. The Windows creator has no native parent-directory sync
/// operation, so its receipts must not claim one. Pin both the receipt and the
/// audit to the same platform capability instead of demanding Linux semantics
/// everywhere.
const ORIGINAL_PARENT_SYNC_VERIFIED: bool = cfg!(target_os = "linux");

fn verify_original_installed_files(
    mapping: &RestrictedDeploymentMapping,
    parents: &BTreeMap<PathBuf, NativeParent>,
    files: &[(usize, NativeSealed)],
    receipts: &[DeploymentFileReceipt],
) -> Result<()> {
    if files.len() != mapping.artifacts.len()
        || receipts.len() != files.len()
        || receipts.last().is_none_or(|receipt| {
            receipt.original_attempt.artifact_id != mapping.original.graph.root_deployment
        })
    {
        return Err(ReconcileError::Invariant(
            "complete original deployment installation prefix",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut previous = ContentId::hash(b"SyncExtend deployment original CREATE chain v2");
    let attempt_id = &receipts[0].original_attempt.attempt_id;
    for (sequence, ((index, file), receipt)) in files.iter().zip(receipts).enumerate() {
        let artifact = mapping
            .artifacts
            .get(*index)
            .ok_or(ReconcileError::Invariant("installed artifact index absent"))?;
        let parent = parents
            .get(artifact.target.parent().ok_or(ReconcileError::Invariant(
                "installed original artifact parent absent",
            ))?)
            .ok_or(ReconcileError::Invariant(
                "installed original retained parent absent",
            ))?;
        parent.verify_original()?;
        file.verify_original(&artifact.bytes)?;
        let attempt = &receipt.original_attempt;
        if attempt.format_version != 2
            || &attempt.attempt_id != attempt_id
            || attempt.sequence as usize != sequence
            || attempt.artifact_id != artifact.id
            || attempt.role != artifact.role
            || attempt.target != artifact.target
            || attempt.parent_key != parent_key(parent)?
            || attempt.expected_bytes != artifact.bytes.len() as u64
            || attempt.expected_digest != artifact.digest
            || attempt.bundle_digest != *mapping.original.digest()
            || attempt.mapping_digest != mapping.mapping_digest
            || attempt.previous_receipt_digest != previous
            || receipt.actual_digest != artifact.digest
            || receipt.actual_bytes != artifact.bytes.len() as u64
            || !receipt.original_private_create_verified
            || !receipt.original_file_sync_and_readback_verified
            || receipt.original_parent_sync_verified != ORIGINAL_PARENT_SYNC_VERIFIED
            || !receipt.original_sealed_read_scope_verified
            || receipt.original_key != sealed_key(file)
            || !ids.insert(artifact.id)
            || !keys.insert(receipt.original_key.clone())
            || receipt.receipt_digest
                != ContentId::hash(&serde_json::to_vec(&(
                    "sync-extend-deployment-original-file-receipt-v2",
                    attempt,
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
    if ids != mapping.artifacts.iter().map(|row| row.id).collect() {
        return Err(ReconcileError::Invariant(
            "complete installed original artifact membership",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn close_original_deployment_resources(
    files: Vec<(usize, NativeSealed)>,
    failed_create: Option<NativeFailedCreate>,
    unsealed_creator: Option<NativeCreator>,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
) -> Result<()> {
    let mut first_error: Option<ReconcileError> = None;
    for (_, file) in files {
        if let Err(error) = file.close() {
            first_error.get_or_insert(error.into());
        }
    }
    if let Some(file) = failed_create {
        if let Err(error) = file.close() {
            first_error.get_or_insert(error.into());
        }
    }
    if let Some(file) = unsealed_creator {
        if let Err(error) = file.close() {
            first_error.get_or_insert(error.into());
        }
    }
    for (_, parent) in parents {
        if let Err(error) = parent.close() {
            first_error.get_or_insert(error.into());
        }
    }
    for directory in runtime_directories {
        if let Err(error) = directory.close() {
            first_error.get_or_insert(error.into());
        }
    }
    for original in pinned_programs {
        if let Err(error) = original.close() {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(windows)]
fn close_original_deployment_resources(
    mut mapping: RestrictedDeploymentMapping,
    files: Vec<(usize, NativeSealed)>,
    failed_create: Option<NativeFailedCreate>,
    unsealed_creator: Option<NativeCreator>,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
) -> std::result::Result<
    sync_extend_platform_fs::ClosedWindowsOriginalResources,
    sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
> {
    let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
    for (_, original) in files {
        close.append_result(original.close_retaining());
    }
    if let Some(original) = failed_create {
        close.append_result(original.close_retaining());
    }
    if let Some(original) = unsealed_creator {
        close.append_result(original.close_retaining());
    }
    for (_, parent) in parents {
        close.close_artifact_parent(parent);
    }
    for parent in runtime_directories {
        close.close_artifact_parent(parent);
    }
    for original in pinned_programs {
        close.append_result(original.close_retaining());
    }
    mapping.original.framing.close_original_sources_into(&mut close);
    close.finish()
}

impl OriginalDeploymentInstallAttempt<'_> {
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
        {
            return Err(ReconcileError::Invariant(
                "complete original deployment installation prefix",
            ));
        }
        verify_original_installed_files(
            &self.prepared.mapping,
            &self.prepared.parents,
            &self.files,
            &self.file_receipts,
        )?;
        self.prepared.verify_scope(provider)
    }

    #[cfg(not(windows))]
    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        let receipt = self.receipt();
        let Self {
            files,
            failed_create,
            unsealed_creator,
            prepared,
            ..
        } = self;
        close_original_deployment_resources(
            files,
            failed_create,
            unsealed_creator,
            prepared.parents,
            prepared.runtime_directories,
            prepared.pinned_programs,
        )?;
        Ok(receipt)
    }

    #[cfg(windows)]
    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        self.close_retaining()
            .map_err(|original| ReconcileError::Io(original.retain_and_report()))
    }

    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        DeploymentInstallReceipt,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        let receipt = self.receipt();
        let Self { files, failed_create, unsealed_creator, prepared, .. } = self;
        close_original_deployment_resources(
            prepared.mapping, files, failed_create, unsealed_creator,
            prepared.parents, prepared.runtime_directories, prepared.pinned_programs,
        )?;
        Ok(receipt)
    }
}

pub struct DeploymentInstallFailure<'proof> {
    pub error: ReconcileError,
    pub original_attempt: OriginalDeploymentInstallAttempt<'proof>,
}
impl<'proof> DeploymentInstallFailure<'proof> {
    fn before_create(
        prepared: PreparedDeploymentInstall<'proof>,
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
        prepared: PreparedDeploymentInstall<'proof>,
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
pub struct CompleteDeploymentInstall<'proof> {
    original_attempt: OriginalDeploymentInstallAttempt<'proof>,
}
impl<'proof> CompleteDeploymentInstall<'proof> {
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

    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        DeploymentInstallReceipt,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        self.original_attempt.close_retaining()
    }

    /// Transfers the actual original installed files after full completion
    /// verification. Node completion borrows end here. This owned value alone
    /// does not authorize any service or fresh recovered-node session.
    pub fn retain_files(
        self,
        provider: &DeploymentProtectionProvider,
    ) -> std::result::Result<
        RetainedInstalledDeploymentFiles,
        DeploymentFileRetentionFailure<'proof>,
    > {
        if let Err(error) = self.verify(provider) {
            return Err(DeploymentFileRetentionFailure {
                error,
                original_install: self,
            });
        }
        let receipt = self.receipt();
        let OriginalDeploymentInstallAttempt {
            prepared,
            files,
            failed_create,
            unsealed_creator,
            ..
        } = self.original_attempt;
        debug_assert!(failed_create.is_none() && unsealed_creator.is_none());
        let PreparedDeploymentInstall {
            mapping,
            completions,
            parents,
            runtime_directories,
            pinned_programs,
            ..
        } = prepared;
        drop(completions);
        Ok(RetainedInstalledDeploymentFiles {
            mapping,
            parents,
            runtime_directories,
            pinned_programs,
            files,
            receipt,
        })
    }
}

pub struct DeploymentFileRetentionFailure<'proof> {
    pub error: ReconcileError,
    pub original_install: CompleteDeploymentInstall<'proof>,
}

/// Private fields retain the real CREATE objects and original source graph.
/// No receipt, path reopening, deserializer or public constructor can mint it.
pub struct RetainedInstalledDeploymentFiles {
    pub(super) mapping: RestrictedDeploymentMapping,
    parents: BTreeMap<PathBuf, NativeParent>,
    runtime_directories: Vec<NativeParent>,
    pinned_programs: Vec<OriginalProtectedArtifact>,
    files: Vec<(usize, NativeSealed)>,
    pub(super) receipt: DeploymentInstallReceipt,
}

impl RetainedInstalledDeploymentFiles {
    #[cfg(windows)]
    pub fn fresh_node_restore_inputs(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Vec<super::deployment_bundle::DeploymentNodeRestoreInput>> {
        self.verify(provider)?;
        let inputs = self.mapping.node_restore_inputs(provider)?;
        self.verify(provider)?;
        Ok(inputs)
    }

    pub fn receipt(&self) -> DeploymentInstallReceipt {
        self.receipt.clone()
    }

    pub fn verify(&self, provider: &DeploymentProtectionProvider) -> Result<()> {
        verify_resource_scope(
            &self.mapping,
            &self.parents,
            &self.runtime_directories,
            &self.pinned_programs,
            provider,
        )?;
        if !self.receipt.full_graph_and_original_creators_verified
            || !self.receipt.root_deployment_written_last
            || self.receipt.failed_file.is_some()
            || self.receipt.services_started
        {
            return Err(ReconcileError::Invariant(
                "retained original installation is incomplete",
            ));
        }
        verify_original_installed_files(
            &self.mapping,
            &self.parents,
            &self.files,
            &self.receipt.files,
        )?;
        verify_resource_scope(
            &self.mapping,
            &self.parents,
            &self.runtime_directories,
            &self.pinned_programs,
            provider,
        )
    }

    pub fn root_deployment_path(&self) -> &Path {
        self.mapping.root_deployment_path()
    }

    #[cfg(not(windows))]
    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        let Self {
            files,
            parents,
            runtime_directories,
            pinned_programs,
            receipt,
            ..
        } = self;
        close_original_deployment_resources(
            files,
            None,
            None,
            parents,
            runtime_directories,
            pinned_programs,
        )?;
        Ok(receipt)
    }

    #[cfg(windows)]
    pub fn close(self) -> Result<DeploymentInstallReceipt> {
        self.close_retaining()
            .map_err(|original| ReconcileError::Io(original.retain_and_report()))
    }

    #[cfg(windows)]
    pub fn close_retaining(self) -> std::result::Result<
        DeploymentInstallReceipt,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        let Self { mapping, files, parents, runtime_directories, pinned_programs, receipt } = self;
        close_original_deployment_resources(
            mapping, files, None, None, parents, runtime_directories, pinned_programs,
        )?;
        Ok(receipt)
    }
}
