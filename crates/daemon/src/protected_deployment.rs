//! Explicit protected deployments retain the same original installation in
//! this child. JSON binds requests; only live native objects authorize work.
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use sync_extend_core_model::{
    deployment::{decode_deployment_document, DeploymentRole},
    limits::LocalLimits,
    ContentId,
};
use sync_extend_platform_fs::{
    OriginalDeploymentOwnerInput, WindowsOriginalCloseAttempt, WindowsOriginalResourceCloseFailure,
};
use sync_extend_reconcile::{
    ArchiveBounds, CapturedDeploymentNode, DeploymentBundleBounds, DeploymentClosedNodeRuntime,
    DeploymentMapping, DeploymentNodeRuntimeCloseFailure, DeploymentNodeRuntimeOpenFailure,
    DeploymentProtectionProvider, DeploymentRun, DeploymentSelection, FramedDeploymentBundle,
    OriginalProtectedArtifact, OriginalProtectedArtifactOpenFailure, RecoveredLocalSpace,
    RetainedInstalledDeploymentFiles, StoppedDeploymentCaptureSource, VerifiedDeploymentBundle,
};

#[path = "deployment_node_restore.rs"]
mod node_restore;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DOCUMENT_LIMIT: usize = 1024 * 1024;
const REQUEST_WIRE_LIMIT: usize = 4096;
const RESPONSE_LIMIT: usize = 1024 * 1024;
const OWNER_POLL: Duration = Duration::from_millis(25);

#[derive(Subcommand)]
pub enum Action {
    /// Capture explicitly selected stopped nodes and their complete references.
    Capture {
        #[arg(long)]
        output: PathBuf,
    },
    /// Authenticate and inspect the complete original bundle without effects.
    Inspect,
    /// Check a restricted mapping and every future private target; no CREATE.
    Map {
        #[arg(long)]
        mapping: PathBuf,
    },
    /// Install fresh private targets; services require Run in this same child.
    Install {
        #[arg(long)]
        mapping: PathBuf,
        #[arg(long)]
        wait_for_run: bool,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    pub format_version: u32,
    pub provider_anchor: PathBuf,
    pub bundle: Option<BundleInput>,
    pub bundle_bounds: DeploymentBundleBounds,
    pub archive_bounds: ArchiveBounds,
    pub inspection: super::recovery::InspectionDescriptor,
    pub max_content_hash_bytes: u64,
    pub capture: Option<CaptureDescriptor>,
    pub node_restores: Vec<NodeRestoreDescriptor>,
    pub owner: OwnerBounds,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleInput {
    pub path: PathBuf,
    pub digest: ContentId,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureDescriptor {
    pub selection: DeploymentSelection,
    pub nodes: Vec<NodeCaptureDescriptor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeCaptureDescriptor {
    pub id: u32,
    pub artifact_id: u32,
    pub source_data: PathBuf,
    pub archive_path: PathBuf,
    pub configs: BTreeMap<String, PathBuf>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeRestoreDescriptor {
    pub node_id: u32,
    pub ledger_directory: PathBuf,
    pub recovery: super::recovery::Descriptor,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBounds {
    pub max_lifetime_secs: u64,
    pub max_idle_secs: u64,
    pub max_input_frames: u32,
    pub max_output_frames: u32,
    pub max_output_bytes: u64,
    pub max_generations: u64,
}

impl OwnerBounds {
    fn validate(self) -> Result<()> {
        if !(1..=86_400).contains(&self.max_lifetime_secs)
            || self.max_idle_secs == 0
            || self.max_idle_secs > self.max_lifetime_secs
            || self.max_input_frames == 0
            || self.max_input_frames > 4094
            || self.max_output_frames < self.max_input_frames + 2
            || self.max_output_frames > 4096
            || !(2 * RESPONSE_LIMIT as u64..=64 * 1024 * 1024).contains(&self.max_output_bytes)
            || self.max_generations == 0
            || self.max_generations > u64::from(self.max_input_frames)
        {
            return Err("explicit finite protected deployment owner bounds".into());
        }
        Ok(())
    }
}

pub(crate) fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path.as_os_str().len() <= 32_768
        && path.components().count() <= 256
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

fn lowercase_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Descriptor {
    fn validate(&self) -> Result<()> {
        if self.format_version != 2
            || !normalized(&self.provider_anchor)
            || self.max_content_hash_bytes == 0
            || self.max_content_hash_bytes > 256 * 1024 * 1024
            || self.node_restores.len() > 64
        {
            return Err("bounded explicit protected deployment descriptor".into());
        }
        self.bundle_bounds.validate()?;
        self.archive_bounds.validate()?;
        self.owner.validate()?;
        self.inspection.bounds().validate()?;
        if let Some(bundle) = &self.bundle {
            if !normalized(&bundle.path)
                || bundle.path == self.provider_anchor
                || !lowercase_hex(&bundle.sha256, 32)
            {
                return Err("exact independent protected bundle input binding".into());
            }
        }
        let mut node_ids = BTreeSet::new();
        for node in &self.node_restores {
            if node.node_id == 0
                || !node_ids.insert(node.node_id)
                || !normalized(&node.ledger_directory)
            {
                return Err("exact independent deployment node restoration scope".into());
            }
            node.recovery.validate_paths()?;
            node.recovery.ledger().validate()?;
            node.recovery.inspection().validate()?;
        }
        if let Some(capture) = &self.capture {
            if capture.selection.format_version != 2
                || capture.selection.artifacts.is_empty()
                || capture.selection.artifacts.len() > self.bundle_bounds.artifacts
                || capture.nodes.is_empty()
                || capture.nodes.len() > 64
            {
                return Err("bounded complete explicit deployment capture selection".into());
            }
            let mut node_ids = BTreeSet::new();
            let mut artifacts = BTreeSet::new();
            for node in &capture.nodes {
                if node.id == 0
                    || node.artifact_id == 0
                    || !node_ids.insert(node.id)
                    || !artifacts.insert(node.artifact_id)
                    || !normalized(&node.source_data)
                    || !normalized(&node.archive_path)
                    || node.configs.is_empty()
                    || node.configs.len() > 64
                    || node.configs.values().any(|path| !normalized(path))
                {
                    return Err("exact original node capture config scope".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct InvocationResources {
    descriptor: Option<OriginalProtectedArtifact>,
    mapping: Option<OriginalProtectedArtifact>,
    provider: Option<DeploymentProtectionProvider>,
    input: Option<OriginalDeploymentOwnerInput>,
    files: Option<RetainedInstalledDeploymentFiles>,
    pub native_close_failures: Vec<WindowsOriginalResourceCloseFailure>,
    partial_receipt: Option<serde_json::Value>,
}

impl InvocationResources {
    fn close(
        mut self,
    ) -> (
        Option<serde_json::Value>,
        std::result::Result<(), WindowsOriginalResourceCloseFailure>,
    ) {
        let mut close = WindowsOriginalCloseAttempt::new();
        if let Some(files) = self.files.take() {
            match files.close_retaining() {
                Ok(_) => {}
                Err(original) => close.append_failure(original),
            }
        }
        if let Some(provider) = self.provider.take() {
            close.append_result(provider.close_retaining());
        }
        if let Some(original) = self.mapping.take() {
            close.append_result(original.close_retaining());
        }
        if let Some(original) = self.descriptor.take() {
            close.append_result(original.close_retaining());
        }
        if let Some(input) = self.input.take() {
            close.append_result(input.close_retaining());
        }
        for original in self.native_close_failures {
            close.append_failure(original);
        }
        (self.partial_receipt, close.finish().map(|_| ()))
    }
}

fn failed_open(
    failure: OriginalProtectedArtifactOpenFailure,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Box<dyn std::error::Error> {
    if let Some(original) = failure.original_resources {
        failures.push(original);
    }
    failure.error.into()
}

fn original_document(
    path: &Path,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Result<OriginalProtectedArtifact> {
    if !normalized(path) {
        return Err("normalized absolute original deployment document required".into());
    }
    OriginalProtectedArtifact::capture_retaining(path, DOCUMENT_LIMIT, false)
        .map_err(|failure| failed_open(failure, failures))
}

fn verified_bundle(
    descriptor: &Descriptor,
    provider: &DeploymentProtectionProvider,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Result<(VerifiedDeploymentBundle, String)> {
    let input = descriptor
        .bundle
        .as_ref()
        .ok_or("the descriptor must select its original bundle")?;
    let framed = FramedDeploymentBundle::from_original_file_retaining(
        &input.path,
        &input.digest,
        descriptor.bundle_bounds,
    )
    .map_err(|failure| failed_open(failure, failures))?;
    let raw_sha256 = sha256(framed.bytes());
    if raw_sha256 != input.sha256 {
        if let Err(original) = framed.close_retaining() {
            failures.push(original);
        }
        return Err("actual original bundle SHA256 differs".into());
    }
    let verified = match framed.verify_retaining(
        provider,
        descriptor.bundle_bounds,
        descriptor.archive_bounds,
        descriptor.inspection.bounds(),
        descriptor.max_content_hash_bytes,
    ) {
        Ok(verified) => verified,
        Err(failure) => {
            if let Err(original) = failure.original_framing.close_retaining() {
                failures.push(original);
            }
            return Err(failure.error.into());
        }
    };
    Ok((verified, raw_sha256))
}

fn capture(
    descriptor: &Descriptor,
    provider: &DeploymentProtectionProvider,
    output: &Path,
    limits: &LocalLimits,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Result<serde_json::Value> {
    if !normalized(output) || descriptor.bundle.is_some() {
        return Err("capture requires a normalized fresh output and original selection".into());
    }
    let capture = descriptor
        .capture
        .as_ref()
        .ok_or("the descriptor must select original capture inputs")?;
    let mut nodes = Vec::new();
    let mut archive_bytes = 0u64;
    for node in &capture.nodes {
        let mut source =
            match StoppedDeploymentCaptureSource::open(&node.source_data, limits.clone()) {
                Ok(source) => source,
                Err(failure) => {
                    let error = io::Error::other(failure.error.to_string());
                    failure.retain_until_process_exit();
                    return Err(error.into());
                }
            };
        let configs: Vec<_> = node
            .configs
            .iter()
            .map(|(name, path)| (name.clone(), path.clone()))
            .collect();
        let captured = CapturedDeploymentNode::capture_stopped(
            node.id,
            node.artifact_id,
            &node.archive_path,
            &mut source,
            &configs,
            descriptor.archive_bounds,
            descriptor.inspection.bounds(),
            descriptor.max_content_hash_bytes,
        );
        // Always close this same original source, including capture failure.
        let closed = source.close_retaining();
        let captured = match captured {
            Ok(captured) => captured,
            Err(error) => {
                if let Err(original) = closed {
                    original.retain_until_process_exit();
                }
                return Err(error.into());
            }
        };
        if let Err(original) = closed {
            let error = io::Error::other(original.error.to_string());
            original.retain_until_process_exit();
            return Err(error.into());
        }
        archive_bytes = archive_bytes
            .checked_add(captured.descriptor().archive_bytes)
            .filter(|bytes| *bytes <= descriptor.bundle_bounds.plaintext_bytes)
            .ok_or("complete deployment captured-node byte liability")?;
        if archive_bytes
            .checked_mul(3)
            .is_none_or(|bytes| bytes > descriptor.bundle_bounds.memory_bytes)
        {
            return Err("complete deployment captured-node allocation liability".into());
        }
        nodes.push(captured);
    }
    // The selection is descriptive; only the actual stopped captures above
    // can supply node-state payloads.
    let selection: DeploymentSelection =
        decode_deployment_document(&serde_json::to_vec(&capture.selection)?, DOCUMENT_LIMIT)?;
    let framed = match FramedDeploymentBundle::capture_retaining(
        selection,
        nodes,
        provider,
        descriptor.bundle_bounds,
    ) {
        Ok(framed) => framed,
        Err(failure) => {
            let (error, closed) = failure.close_preserving_error();
            if let Err(original) = closed {
                failures.push(original);
            }
            return Err(error.into());
        }
    };
    let raw_sha256 = sha256(framed.bytes());
    let verified = match framed.verify_retaining(
        provider,
        descriptor.bundle_bounds,
        descriptor.archive_bounds,
        descriptor.inspection.bounds(),
        descriptor.max_content_hash_bytes,
    ) {
        Ok(verified) => verified,
        Err(failure) => {
            if let Err(original) = failure.original_framing.close_retaining() {
                failures.push(original);
            }
            return Err(failure.error.into());
        }
    };
    let exported = match verified.export_private(provider, output) {
        Ok(exported) => exported,
        Err(failure) => {
            if let Err(original) = failure.original_attempt.close_retaining() {
                failures.push(original);
            }
            return Err(failure.error.into());
        }
    };
    let receipt = serde_json::to_value(exported.receipt());
    if let Err(original) = exported.close_retaining() {
        failures.push(original);
        return Err("actual original deployment export close failed".into());
    }
    Ok(serde_json::json!({
        "event": "captured",
        "format_version": 2,
        "bundle_sha256": raw_sha256,
        "target": output,
        "receipt": receipt?,
        "native_capture_sources_closed": true,
        "native_bundle_export_closed": true,
        "services_started": false,
    }))
}

struct ProtocolOutput {
    frames: u32,
    bytes: u64,
    bounds: OwnerBounds,
    failed: bool,
}

impl ProtocolOutput {
    fn new(bounds: OwnerBounds) -> Self {
        Self {
            frames: 0,
            bytes: 0,
            bounds,
            failed: false,
        }
    }

    fn send(&mut self, value: &serde_json::Value) -> Result<()> {
        if self.failed {
            return Err("original deployment output already failed".into());
        }
        let result = (|| -> Result<()> {
            let bytes = serde_json::to_vec(value)?;
            let wire_bytes = bytes
                .len()
                .checked_add(1)
                .ok_or("owner output byte overflow")?;
            let frames = self
                .frames
                .checked_add(1)
                .filter(|frames| *frames <= self.bounds.max_output_frames)
                .ok_or("owner output frame liability")?;
            let total = self
                .bytes
                .checked_add(wire_bytes as u64)
                .filter(|total| *total <= self.bounds.max_output_bytes)
                .ok_or("owner aggregate output byte liability")?;
            if bytes.len() > RESPONSE_LIMIT || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
                return Err("bounded LF deployment output frame".into());
            }
            let stdout = io::stdout();
            let mut original = stdout.lock();
            original.write_all(&bytes)?;
            original.write_all(b"\n")?;
            original.flush()?;
            self.frames = frames;
            self.bytes = total;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OwnerState {
    Installed,
    Running,
    Closed,
    Uncertain,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum OwnerCommand {
    Run,
    Status,
    Stop,
    Close,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRequest {
    format_version: u32,
    request_id: String,
    command: OwnerCommand,
    bundle_sha256: String,
    mapping_sha256: String,
}

#[allow(clippy::too_many_arguments)]
fn response(
    request: &OwnerRequest,
    state: OwnerState,
    accepted: bool,
    resources_ready: bool,
    services_started: bool,
    generation: u64,
    status: Option<serde_json::Value>,
    error: Option<&'static str>,
) -> serde_json::Value {
    serde_json::json!({
        "event": "response",
        "format_version": 2,
        "request_id": request.request_id,
        "command": request.command,
        "bundle_sha256": request.bundle_sha256,
        "mapping_sha256": request.mapping_sha256,
        "state": state,
        "accepted": accepted,
        "resources_ready": resources_ready,
        "services_started": services_started,
        "generation": generation,
        "status": status,
        "error": if accepted { None } else { error.or(Some("request_refused")) },
    })
}

#[derive(Default)]
struct OwnerFailures {
    nodes: Vec<(u32, DeploymentNodeRuntimeCloseFailure)>,
    gateway: Vec<super::webdav::RecoveredGatewayCloseFailure>,
    management: Vec<super::management::ManagementResourceCloseFailure>,
    original_closed_prefix: Vec<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
    failed_generation_closed_history: Vec<BTreeMap<u32, DeploymentClosedNodeRuntime>>,
}

impl OwnerFailures {
    fn any(&self) -> bool {
        !self.nodes.is_empty() || !self.gateway.is_empty() || !self.management.is_empty()
    }

    fn has_retained_originals(&self) -> bool {
        self.nodes
            .iter()
            .any(|(_, original)| original.has_retained_originals())
            || self
                .gateway
                .iter()
                .any(|original| original.has_retained_originals())
            || self
                .management
                .iter()
                .any(|original| original.has_retained_originals())
    }

    /// Retry same-object terminals while all original installed files,
    /// provider, input and descriptor scopes still remain with this child.
    fn retry_terminal_resources(&mut self) {
        self.gateway = std::mem::take(&mut self.gateway)
            .into_iter()
            .map(|original| original.close_remaining())
            .collect();
        self.management = std::mem::take(&mut self.management)
            .into_iter()
            .map(|original| original.close_remaining())
            .collect();
        self.nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|(id, original)| (id, original.close_remaining()))
            .collect();
    }

    fn retain_until_process_exit(self) {
        if self.any() {
            let _ = Box::leak(Box::new(self));
        }
    }
}

struct OwnerEnd {
    request: Option<OwnerRequest>,
    state: OwnerState,
    generation: u64,
    reason: &'static str,
    error: Option<&'static str>,
    uncertain: bool,
    failed: bool,
    failures: OwnerFailures,
}

/// The same child owns every actual actor and native node. A JSON frame
/// carries bindings only; each Run still acquires a fresh native R06 session.
struct DeploymentOwner<'authority> {
    files: &'authority RetainedInstalledDeploymentFiles,
    provider: &'authority DeploymentProtectionProvider,
    installed_nodes: &'authority [node_restore::InstalledNode],
    bundle_sha256: String,
    mapping_sha256: String,
    bounds: OwnerBounds,
    born: Instant,
    last_activity: Instant,
    limits: LocalLimits,
    state: OwnerState,
    generation: u64,
    input_frames: u32,
    request_ids: BTreeSet<String>,
    input_frame: Vec<u8>,
    run: Option<DeploymentRun<'authority>>,
    gateway: Option<super::webdav::ActiveRecoveredGateway>,
    management: Option<super::management::ManagementGuard>,
    closed_history: BTreeMap<u32, DeploymentClosedNodeRuntime>,
    failures: OwnerFailures,
}

enum OwnerStartFailure {
    BeforeAcquisition(&'static str),
    OriginalAcquisition(&'static str),
}

impl<'authority> DeploymentOwner<'authority> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        files: &'authority RetainedInstalledDeploymentFiles,
        provider: &'authority DeploymentProtectionProvider,
        installed_nodes: &'authority [node_restore::InstalledNode],
        bundle_sha256: String,
        mapping_sha256: String,
        bounds: OwnerBounds,
        born: Instant,
        limits: LocalLimits,
    ) -> Self {
        Self {
            files,
            provider,
            installed_nodes,
            bundle_sha256,
            mapping_sha256,
            bounds,
            born,
            last_activity: Instant::now(),
            limits,
            state: OwnerState::Installed,
            generation: 0,
            input_frames: 0,
            request_ids: BTreeSet::new(),
            input_frame: Vec::new(),
            run: None,
            gateway: None,
            management: None,
            closed_history: BTreeMap::new(),
            failures: OwnerFailures::default(),
        }
    }

    fn retain_failed_node(&mut self, id: u32, original: RecoveredLocalSpace) {
        match original.close_failed_deployment_runtime() {
            Ok(closed) => self.failures.original_closed_prefix.push(closed),
            Err(original) => self.failures.nodes.push((id, original)),
        }
    }

    fn deadline_expired(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.born).as_secs() >= self.bounds.max_lifetime_secs
            || now.duration_since(self.last_activity).as_secs() >= self.bounds.max_idle_secs
    }

    fn require_start_deadline(&mut self) -> std::result::Result<(), OwnerStartFailure> {
        if !self.deadline_expired() { return Ok(()); }
        // Ending a possibly acquired owner is mandatory; a deadline never
        // abandons native resources or fabricates a reusable closed generation.
        self.stop_runtime();
        Err(OwnerStartFailure::OriginalAcquisition("owner_timeout"))
    }

    fn start(&mut self) -> std::result::Result<(), OwnerStartFailure> {
        if self.state != OwnerState::Installed
            || self.run.is_some()
            || self.gateway.is_some()
            || self.management.is_some()
            || self.failures.any()
        {
            return Err(OwnerStartFailure::BeforeAcquisition(
                "runtime_state_refused",
            ));
        }
        if self.deadline_expired() {
            return Err(OwnerStartFailure::BeforeAcquisition("owner_timeout"));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= self.bounds.max_generations)
            .ok_or(OwnerStartFailure::BeforeAcquisition("generation_limit"))?;
        // Parse roles, all TLS choices and actual credentials before any
        // fresh native acquisition or listener effect.
        let (prepared_gateway, prepared_management, role_name, inputs) = (|| -> Result<_> {
            self.files.verify(self.provider)?;
            let config = self.files.deployment_configuration(self.provider)?;
            config.validate()?;
            let role_name = config.role_name();
            let gateway = match config.role {
                DeploymentRole::WebdavClient { scan_interval_secs, .. } => Some(
                    super::webdav::PreparedRecoveredGateway::new(
                        self.files.gateway_configuration(self.provider)?,
                        self.limits.clone(), scan_interval_secs,
                    )?),
                DeploymentRole::LocalPolling { .. } => None,
                _ => return Err("the selected recovered runtime role is unavailable".into()),
            };
            let management = self
                .files
                .management_configuration(self.provider)?
                .map(super::management::PreparedManagement::new)
                .transpose()?;
            let inputs = self.files.fresh_node_restore_inputs(self.provider)?;
            if inputs.len() != self.installed_nodes.len() || inputs.len() > 64 {
                return Err("complete actual installed native node set required".into());
            }
            let mut ids = BTreeSet::new();
            for input in &inputs {
                let node = input.node();
                let selected = self
                    .installed_nodes
                    .iter()
                    .find(|selected| selected.node_id == node.id)
                    .ok_or("same actual installed node descriptor absent")?;
                let target = input.target();
                if !ids.insert(node.id)
                    || node.archive_digest != selected.recovery.archive_digest
                    || target.data_dir != selected.recovery.data
                    || target.worktree != selected.recovery.worktree
                    || node.space_id != selected.recovery.expected_space
                    || node.device_id != selected.recovery.expected_device
                {
                    return Err("same actual installed node recovery binding required".into());
                }
                selected.recovery.validate_paths()?;
                selected.recovery.ledger().validate()?;
                selected.recovery.inspection().validate()?;
            }
            self.files.verify(self.provider)?;
            Ok((gateway, management, role_name, inputs))
        })()
        .map_err(|_| OwnerStartFailure::BeforeAcquisition("runtime_configuration_invalid"))?;

        let mut acquired = Vec::new();
        for input in inputs {
            let id = input.node().id;
            let selected = self
                .installed_nodes
                .iter()
                .find(|selected| selected.node_id == id)
                .expect("full original input set checked before acquisition");
            let opened = input.open_deployment_runtime(
                &selected.recovery.original_frames,
                &selected.recovery.restore_ledger,
                self.closed_history.get(&id),
                selected.recovery.inspection(),
                selected.recovery.ledger(),
            );
            match opened {
                Ok(original) => acquired.push((id, original)),
                Err(DeploymentNodeRuntimeOpenFailure {
                    error: _,
                    original_node,
                    ..
                }) => {
                    if let Some(original) = original_node {
                        self.retain_failed_node(id, original);
                    }
                    for (id, original) in acquired {
                        self.retain_failed_node(id, original);
                    }
                    self.state = OwnerState::Uncertain;
                    return Err(OwnerStartFailure::OriginalAcquisition(
                        "native_acquisition_failed",
                    ));
                }
            }
        }
        if self.deadline_expired() {
            for (id, original) in acquired { self.retain_failed_node(id, original); }
            return Err(OwnerStartFailure::OriginalAcquisition("owner_timeout"));
        }
        let run = match self.files.bind_fresh_runtime_nodes(self.provider, acquired) {
            Ok(run) => run,
            Err(original) => {
                for (id, node) in original.original_nodes {
                    self.retain_failed_node(id, node);
                }
                self.state = OwnerState::Uncertain;
                return Err(OwnerStartFailure::OriginalAcquisition(
                    "native_binding_failed",
                ));
            }
        };
        self.run = Some(run);
        self.generation = next_generation;
        self.require_start_deadline()?;
        super::management::reset_lifecycle_state();
        if let Some(prepared) = prepared_management {
            match prepared.start_retaining(role_name) {
                Ok(original) => self.management = Some(original),
                Err(original) => {
                    if let Some(original) = original.original_resources {
                        self.failures.management.push(original);
                    }
                    self.stop_runtime();
                    self.state = OwnerState::Uncertain;
                    return Err(OwnerStartFailure::OriginalAcquisition(
                        "management_start_failed",
                    ));
                }
            }
        }
        if self.run.as_mut().expect("same acquired native run retained")
            .start_configured_native_mutations().is_err() {
            self.stop_runtime();
            self.state = OwnerState::Uncertain;
            return Err(OwnerStartFailure::OriginalAcquisition("native_mutation_start_failed"));
        }
        if self.run.as_mut().expect("same acquired native run retained")
            .start_configured_polling(self.limits.clone()).is_err() {
            self.stop_runtime();
            self.state = OwnerState::Uncertain;
            return Err(OwnerStartFailure::OriginalAcquisition("polling_start_failed"));
        }
        self.require_start_deadline()?;
        if let Some(prepared_gateway) = prepared_gateway {
            let run = self.run.as_ref().expect("same acquired native run retained");
            match prepared_gateway.start(run) {
                Ok(original) => self.gateway = Some(original),
                Err(original) => {
                    self.gateway = original.original_gateway;
                    self.stop_runtime();
                    self.state = OwnerState::Uncertain;
                    return Err(OwnerStartFailure::OriginalAcquisition("gateway_start_failed"));
                }
            }
        }
        if self
            .run
            .as_ref()
            .expect("same native run retained")
            .verify()
            .is_err()
            || self
                .gateway
                .as_ref()
                .is_some_and(|gateway| gateway.status().is_err())
            || self
                .management
                .as_ref()
                .is_some_and(|original| original.finished())
            || super::management::control_stop_requested()
        {
            self.stop_runtime();
            self.state = OwnerState::Uncertain;
            return Err(OwnerStartFailure::OriginalAcquisition(
                "runtime_verification_failed",
            ));
        }
        self.require_start_deadline()?;
        self.state = OwnerState::Running;
        super::management::resources_ready();
        Ok(())
    }

    /// Continue all independent original terminal paths after the first error.
    /// Reusable closed history is kept only after every actual actor and
    /// native session completed its full terminal successfully.
    fn stop_runtime(&mut self) -> bool {
        if let Some(original) = self.gateway.take() {
            if let Err(original) = original.close() {
                self.failures.gateway.push(original);
            }
        }
        if let Some(original) = self.management.take() {
            if let Err(original) = original.close_retaining() {
                self.failures.management.push(original);
            }
        }
        let mut history = None;
        if let Some(original) = self.run.take() {
            match original.close() {
                Ok(closed) => history = Some(closed),
                Err(mut original) => {
                    self.failures
                        .nodes
                        .append(&mut original.original_failed_nodes);
                    self.failures
                        .failed_generation_closed_history
                        .push(original.actual_closed_history);
                    // A run-level verification failure can precede successful
                    // native closes of every node. It still forbids restart.
                    self.state = OwnerState::Uncertain;
                }
            }
        }
        super::management::reset_lifecycle_state();
        if self.failures.any() || self.state == OwnerState::Uncertain {
            if let Some(history) = history {
                self.failures.failed_generation_closed_history.push(history);
            }
            self.state = OwnerState::Uncertain;
            false
        } else {
            if let Some(history) = history {
                self.closed_history = history;
            }
            self.state = OwnerState::Installed;
            true
        }
    }

    fn status(&self) -> Result<serde_json::Value> {
        self.files.verify(self.provider)?;
        match (&self.run, &self.gateway, self.state) {
            (Some(run), Some(gateway), OwnerState::Running) => Ok(serde_json::json!({
                "runtime": run.status()?,
                "gateway": gateway.status()?,
            })),
            (Some(run), None, OwnerState::Running) => Ok(serde_json::json!({
                "runtime": run.status()?,
                "gateway": null,
            })),
            (None, None, OwnerState::Installed) => Ok(serde_json::json!({
                "root_deployment": self.files.root_deployment_path(),
                "native_files_verified": true,
                "completed_generations": self.generation,
            })),
            _ => Err("the same original deployment runtime is uncertain".into()),
        }
    }

    fn end(
        &mut self,
        reason: &'static str,
        request: Option<OwnerRequest>,
        error: Option<&'static str>,
        failed: bool,
    ) -> OwnerEnd {
        let complete = self.stop_runtime();
        self.failures.retry_terminal_resources();
        OwnerEnd {
            request,
            state: if complete {
                OwnerState::Closed
            } else {
                OwnerState::Uncertain
            },
            generation: self.generation,
            reason,
            error: error.or((!complete).then_some("native_close_failed")),
            uncertain: !complete,
            failed,
            failures: std::mem::take(&mut self.failures),
        }
    }

    fn decode_request(&mut self, bytes: &[u8]) -> Result<(OwnerRequest, bool)> {
        self.input_frames = self
            .input_frames
            .checked_add(1)
            .filter(|count| *count <= self.bounds.max_input_frames)
            .ok_or("original input frame limit")?;
        if bytes.is_empty()
            || bytes.len() >= REQUEST_WIRE_LIMIT
            || bytes.contains(&b'\r')
            || bytes.contains(&b'\n')
        {
            return Err("bounded LF UTF8 original input frame required".into());
        }
        let request: OwnerRequest = decode_deployment_document(bytes, REQUEST_WIRE_LIMIT - 1)?;
        if request.format_version != 2
            || !lowercase_hex(&request.request_id, 16)
            || !lowercase_hex(&request.bundle_sha256, 32)
            || !lowercase_hex(&request.mapping_sha256, 32)
            || !self.request_ids.insert(request.request_id.clone())
        {
            return Err("unique original request and exact installed bindings required".into());
        }
        self.last_activity = Instant::now();
        let binding_matches = request.bundle_sha256 == self.bundle_sha256
            && request.mapping_sha256 == self.mapping_sha256;
        Ok((request, binding_matches))
    }

    fn command(&mut self, request: OwnerRequest, output: &mut ProtocolOutput) -> Option<OwnerEnd> {
        match request.command {
            OwnerCommand::Close => Some(self.end("runtime_failed", Some(request), None, false)),
            OwnerCommand::Stop => {
                if !self.stop_runtime() {
                    return Some(self.end(
                        "runtime_failed",
                        Some(request),
                        Some("native_close_failed"),
                        true,
                    ));
                }
                if output
                    .send(&response(
                        &request,
                        self.state,
                        true,
                        false,
                        false,
                        self.generation,
                        None,
                        None,
                    ))
                    .is_err()
                {
                    return Some(self.end("runtime_failed", None, None, true));
                }
                None
            }
            OwnerCommand::Run => {
                let (accepted, error) = match self.start() {
                    Ok(()) => (true, None),
                    Err(OwnerStartFailure::BeforeAcquisition(error)) => (false, Some(error)),
                    Err(OwnerStartFailure::OriginalAcquisition(error)) => {
                        return Some(self.end("runtime_failed", Some(request), Some(error), true))
                    }
                };
                let running = self.state == OwnerState::Running;
                if output
                    .send(&response(
                        &request,
                        self.state,
                        accepted,
                        running,
                        running,
                        self.generation,
                        None,
                        error,
                    ))
                    .is_err()
                {
                    return Some(self.end("runtime_failed", None, None, true));
                }
                None
            }
            OwnerCommand::Status => {
                let status = match self.status() {
                    Ok(status) => status,
                    Err(_) => {
                        return Some(self.end(
                            "runtime_failed",
                            Some(request),
                            Some("runtime_failed"),
                            true,
                        ))
                    }
                };
                let running = self.state == OwnerState::Running;
                if output
                    .send(&response(
                        &request,
                        self.state,
                        true,
                        running,
                        running,
                        self.generation,
                        Some(status),
                        None,
                    ))
                    .is_err()
                {
                    return Some(self.end("runtime_failed", None, None, true));
                }
                None
            }
        }
    }

    fn control(
        &mut self,
        input: &mut OriginalDeploymentOwnerInput,
        output: &mut ProtocolOutput,
    ) -> OwnerEnd {
        let mut available = [0u8; REQUEST_WIRE_LIMIT];
        loop {
            if super::management::control_stop_requested() {
                return self.end("authenticated_management_stop", None, None, false);
            }
            if self.deadline_expired() {
                return self.end("owner_timeout", None, None, false);
            }
            if self.input_frames >= self.bounds.max_input_frames
                || self
                    .gateway
                    .as_ref()
                    .is_some_and(|original| original.exhausted())
                || self
                    .management
                    .as_ref()
                    .is_some_and(|original| original.finished())
            {
                return self.end("service_limit", None, None, false);
            }
            match input.read_available(&mut available) {
                Ok(Some(0)) if self.input_frame.is_empty() => {
                    return self.end("stdin_eof", None, None, false)
                }
                Ok(Some(0)) => return self.end("input_protocol_error", None, None, true),
                Ok(Some(count)) => {
                    for byte in &available[..count] {
                        if *byte == b'\n' {
                            let frame = std::mem::take(&mut self.input_frame);
                            let (request, binding_matches) = match self.decode_request(&frame) {
                                Ok(request) => request,
                                Err(_) => {
                                    return self.end("input_protocol_error", None, None, true)
                                }
                            };
                            if self.deadline_expired() {
                                return self.end("owner_timeout", Some(request), Some("owner_timeout"), false);
                            }
                            if binding_matches {
                                if let Some(ended) = self.command(request, output) {
                                    return ended;
                                }
                            } else {
                                let running = self.state == OwnerState::Running;
                                let mut refused = request;
                                refused.bundle_sha256 = self.bundle_sha256.clone();
                                refused.mapping_sha256 = self.mapping_sha256.clone();
                                if output
                                    .send(&response(
                                        &refused,
                                        self.state,
                                        false,
                                        running,
                                        running,
                                        self.generation,
                                        None,
                                        Some("stale_binding"),
                                    ))
                                    .is_err()
                                {
                                    return self.end("runtime_failed", None, None, true);
                                }
                            }
                        } else {
                            if *byte == b'\r' || self.input_frame.len() >= REQUEST_WIRE_LIMIT - 1 {
                                return self.end("input_protocol_error", None, None, true);
                            }
                            self.input_frame.push(*byte);
                        }
                    }
                }
                Ok(None) => (),
                Err(_) => return self.end("input_read_failed", None, None, true),
            }
            if self.deadline_expired() {
                return self.end("owner_timeout", None, None, false);
            }
            if let Some(run) = self.run.as_mut() {
                if run.poll_configured_space().is_err() {
                    return self.end("runtime_failed", None, Some("polling_failed"), true);
                }
                let now = Instant::now();
                if now.duration_since(self.born).as_secs() >= self.bounds.max_lifetime_secs
                    || now.duration_since(self.last_activity).as_secs() >= self.bounds.max_idle_secs
                {
                    return self.end("owner_timeout", None, None, false);
                }
                if let Some(gateway) = self.gateway.as_mut() {
                    if gateway.poll(run).is_err() {
                        return self.end("runtime_failed", None, Some("runtime_failed"), true);
                    }
                }
            }
            std::thread::sleep(OWNER_POLL);
        }
    }
}

enum InvocationOutcome {
    Single(serde_json::Value),
    Owner(OwnerEnd),
}

pub fn run(descriptor_path: &Path, action: Action, limits: LocalLimits) -> Result<()> {
    limits.validate()?;
    let born = Instant::now();
    let mut resources = InvocationResources::default();
    let mut output = None;
    let mut bindings: Option<(String, String)> = None;
    let mut result = (|| -> Result<InvocationOutcome> {
        resources.descriptor = Some(original_document(
            descriptor_path,
            &mut resources.native_close_failures,
        )?);
        let original = resources
            .descriptor
            .as_ref()
            .ok_or("actual descriptor input absent")?;
        let descriptor: Descriptor =
            decode_deployment_document(original.public_document_bytes()?, DOCUMENT_LIMIT)?;
        descriptor.validate()?;
        original.verify_original()?;
        output = Some(ProtocolOutput::new(descriptor.owner));
        resources.provider = Some(
            DeploymentProtectionProvider::open_original_retaining(&descriptor.provider_anchor)
                .map_err(|failure| failed_open(failure, &mut resources.native_close_failures))?,
        );
        let provider = resources
            .provider
            .as_ref()
            .ok_or("actual original provider absent")?;
        match action {
            Action::Capture { output: target } => {
                let value = capture(
                    &descriptor,
                    provider,
                    &target,
                    &limits,
                    &mut resources.native_close_failures,
                )?;
                Ok(InvocationOutcome::Single(value))
            }
            Action::Inspect => {
                if descriptor.capture.is_some() {
                    return Err(
                        "inspect selects an original bundle rather than capture inputs".into(),
                    );
                }
                let (verified, raw_sha256) =
                    verified_bundle(&descriptor, provider, &mut resources.native_close_failures)?;
                let value = serde_json::json!({
                    "event": "inspected", "format_version": 2,
                    "bundle_sha256": raw_sha256, "bundle_digest": verified.digest(),
                    "graph": verified.graph(), "protection_scope": provider.scope(),
                    "node_completion_authority": false, "services_started": false,
                });
                if let Err(original) = verified.close_retaining() {
                    resources.native_close_failures.push(original);
                    return Err("actual original inspected bundle close failed".into());
                }
                Ok(InvocationOutcome::Single(value))
            }
            Action::Map {
                mapping: mapping_path,
            } => prepare_or_install(
                &descriptor,
                provider,
                &mapping_path,
                false,
                false,
                born,
                &limits,
                &mut resources.mapping,
                &mut resources.files,
                &mut resources.input,
                &mut resources.native_close_failures,
                &mut resources.partial_receipt,
                output.as_mut().ok_or("original output absent")?,
                &mut bindings,
            ),
            Action::Install {
                mapping: mapping_path,
                wait_for_run,
            } => prepare_or_install(
                &descriptor,
                provider,
                &mapping_path,
                true,
                wait_for_run,
                born,
                &limits,
                &mut resources.mapping,
                &mut resources.files,
                &mut resources.input,
                &mut resources.native_close_failures,
                &mut resources.partial_receipt,
                output.as_mut().ok_or("original output absent")?,
                &mut bindings,
            ),
        }
    })();
    // Native/callback failures retry while the complete outer original scope
    // still lives. A refused same-object terminal retains that whole scope
    // together; no installed parent/provider is dropped behind a live loan.
    let retain_original_owner_scope = match result.as_mut() {
        Ok(InvocationOutcome::Owner(ended)) => {
            ended.failures.retry_terminal_resources();
            ended.failures.has_retained_originals()
        }
        _ => false,
    };
    let (partial_receipt, native_close_complete) = if retain_original_owner_scope {
        let partial_receipt = resources.partial_receipt.clone();
        let ended = match result.as_mut() {
            Ok(InvocationOutcome::Owner(ended)) => ended,
            _ => unreachable!("same retained owner failure was inspected above"),
        };
        ended.uncertain = true;
        ended.state = OwnerState::Uncertain;
        let failures = std::mem::take(&mut ended.failures);
        let _ = Box::leak(Box::new((resources, failures)));
        (partial_receipt, false)
    } else {
        // No return or output error skips an independent acquired original.
        let (partial_receipt, closed) = resources.close();
        let native_close_complete = closed.is_ok();
        if let Err(original) = closed {
            original.retain_until_process_exit();
        }
        (partial_receipt, native_close_complete)
    };
    let Some(mut output) = output else {
        return result.map(|_| ());
    };
    match result {
        Ok(InvocationOutcome::Single(mut value)) => {
            value["native_invocation_inputs_closed"] = native_close_complete.into();
            if !native_close_complete {
                return Err("actual original deployment input close failed".into());
            }
            output.send(&value)
        }
        Ok(InvocationOutcome::Owner(mut ended)) => {
            let owner_failed = ended.failures.any();
            ended.failures.retain_until_process_exit();
            ended.state = if native_close_complete && !owner_failed && !ended.uncertain {
                OwnerState::Closed
            } else {
                OwnerState::Uncertain
            };
            if output.failed {
                return Err(
                    "original deployment output failed after actual terminal attempts".into(),
                );
            }
            if let Some(request) = &ended.request {
                let accepted = ended.error.is_none() && ended.state == OwnerState::Closed;
                let error = ended.error.or((!accepted).then_some("native_close_failed"));
                output.send(&response(
                    request,
                    ended.state,
                    accepted,
                    false,
                    false,
                    ended.generation,
                    None,
                    error,
                ))?;
            } else {
                let (bundle_sha256, mapping_sha256) =
                    bindings.as_ref().ok_or("installed owner binding absent")?;
                output.send(&serde_json::json!({
                    "event": "state", "format_version": 2,
                    "bundle_sha256": bundle_sha256, "mapping_sha256": mapping_sha256,
                    "state": ended.state, "resources_ready": false, "services_started": false,
                    "generation": ended.generation, "status": null, "reason": ended.reason,
                }))?;
            }
            if ended.state == OwnerState::Uncertain || ended.failed {
                Err("original deployment owner ended without a restartable terminal".into())
            } else {
                Ok(())
            }
        }
        Err(error) => {
            if !output.failed {
                if let Some(receipt) = partial_receipt {
                    let _ = output.send(&serde_json::json!({
                        "event": "install_failed", "format_version": 2,
                        "receipt": receipt, "native_invocation_inputs_closed": native_close_complete,
                        "services_started": false, "error": "installation_failed",
                    }));
                }
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_or_install(
    descriptor: &Descriptor,
    provider: &DeploymentProtectionProvider,
    mapping_path: &Path,
    install: bool,
    wait_for_run: bool,
    born: Instant,
    limits: &LocalLimits,
    original_mapping: &mut Option<OriginalProtectedArtifact>,
    files: &mut Option<RetainedInstalledDeploymentFiles>,
    input: &mut Option<OriginalDeploymentOwnerInput>,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
    partial_receipt: &mut Option<serde_json::Value>,
    output: &mut ProtocolOutput,
    bindings: &mut Option<(String, String)>,
) -> Result<InvocationOutcome> {
    if descriptor.capture.is_some() {
        return Err("map/install selects the original bundle rather than capture inputs".into());
    }
    *original_mapping = Some(original_document(mapping_path, failures)?);
    let mapping_input = original_mapping
        .as_ref()
        .ok_or("actual original mapping absent")?;
    let raw_mapping_sha256 = sha256(mapping_input.public_document_bytes()?);
    let mapping: DeploymentMapping =
        decode_deployment_document(mapping_input.public_document_bytes()?, DOCUMENT_LIMIT)?;
    let (verified, raw_bundle_sha256) = verified_bundle(descriptor, provider, failures)?;
    let mapped = match verified.map_restricted_retaining(mapping) {
        Ok(mapped) => mapped,
        Err(failure) => {
            if let Err(original) = failure.original_bundle.close_retaining() {
                failures.push(original);
            }
            return Err(failure.error.into());
        }
    };
    let mut prepared = node_restore::prepare(descriptor, mapped, provider, failures)?;
    if !install {
        let preview = prepared.preview(provider);
        prepared.close_into(failures);
        let mut preview = preview?;
        preview["event"] = "mapped".into();
        preview["bundle_sha256"] = raw_bundle_sha256.into();
        preview["mapping_sha256"] = raw_mapping_sha256.into();
        return Ok(InvocationOutcome::Single(preview));
    }
    if wait_for_run {
        // Reject a missing/foreign input channel before the first native CREATE.
        match OriginalDeploymentOwnerInput::take_original_stdin_pipe() {
            Ok(original) => *input = Some(original),
            Err(error) => {
                prepared.close_into(failures);
                return Err(error.into());
            }
        }
    }
    let installed = prepared.install(provider, failures, partial_receipt)?;
    *files = Some(installed.files);
    let files = files
        .as_ref()
        .ok_or("actual retained deployment files absent")?;
    files.verify(provider)?;
    let receipt = serde_json::json!({
        "installation": files.receipt(),
        "original_node_restores": installed.receipts,
    });
    let installed_event = serde_json::json!({
        "event": "installed", "format_version": 2, "state": "installed",
        "bundle_sha256": raw_bundle_sha256, "mapping_sha256": raw_mapping_sha256,
        "root_deployment": files.root_deployment_path(),
        "native_files_verified": true, "native_node_restores_closed": true,
        "services_started": false, "receipt": receipt,
    });
    if !wait_for_run {
        return Ok(InvocationOutcome::Single(installed_event));
    }
    *bindings = Some((raw_bundle_sha256.clone(), raw_mapping_sha256.clone()));
    output.send(&installed_event)?;
    let input = input.as_mut().ok_or("actual original owner input absent")?;
    let mut owner = DeploymentOwner::new(
        files,
        provider,
        &installed.nodes,
        raw_bundle_sha256,
        raw_mapping_sha256,
        descriptor.owner,
        born,
        limits.clone(),
    );
    let ended = owner.control(input, output);
    Ok(InvocationOutcome::Owner(ended))
}
