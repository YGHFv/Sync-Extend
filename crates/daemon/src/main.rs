use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf, process::ExitCode, time::Duration};
use sync_extend_core_model::{
    config::{Config, HistoryPolicy},
    PortablePath,
};
use sync_extend_reconcile::{LocalSpace, ReadOnlyLocalSpace};
mod config_file;
mod deployment;
mod easytier;
#[cfg(target_os = "linux")]
mod linux_namespace;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod local_control;
mod management;
mod management_credentials;
#[cfg(windows)]
mod recovery;
mod shutdown;
mod storage;
mod storage_retirement_cli;
mod transport_budget;
mod webdav;
mod webdav_conditions;
mod webdav_credentials;
mod webdav_http;
mod webdav_locks;
mod webdav_upload;
mod webdav_xml;
mod restore_preview_cli;

#[derive(Parser)]
#[command(
    name = "syncd",
    version,
    about = "SyncExtend local alpha with explicit paired sync and opt-in authenticated local WebDAV"
)]
struct Cli {
    /// Apply a local limits JSON file to this invocation (not a retention/GC policy).
    #[arg(long, global = true)]
    limits: Option<PathBuf>,
    /// Select an independently owner-signed finite Sync QUIC frame-attempt policy.
    #[arg(long, global = true)]
    transport_attempt_policy: Option<PathBuf>,
    /// Existing private control directory; ordinary command data-dir is the explicit default.
    #[arg(long, global = true)]
    transport_attempt_budget_dir: Option<PathBuf>,
    /// Enable same-owner local lifecycle control using an existing private directory.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[arg(long, global = true)]
    control_directory: Option<PathBuf>,
    /// Hold an explicitly preformatted private Linux image and five metadata classes.
    #[cfg(target_os = "linux")]
    #[arg(long, global = true)]
    linux_namespace_config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign one explicit unsigned frame-attempt policy with the existing paired owner.
    TransportAttemptPolicySign {
        #[arg(
            long,
            required_unless_present = "storage_config",
            conflicts_with = "storage_config"
        )]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        storage_config: Option<PathBuf>,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Initialize one fresh fixed application-frame ledger; never resets existing state.
    TransportAttemptBudgetInit {
        #[arg(
            long,
            required_unless_present = "storage_config",
            conflicts_with = "storage_config"
        )]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        storage_config: Option<PathBuf>,
    },
    /// Audit the exact existing application-frame ledger without updating its clock.
    TransportAttemptBudgetStatus {
        #[arg(
            long,
            required_unless_present = "storage_config",
            conflicts_with = "storage_config"
        )]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        storage_config: Option<PathBuf>,
    },
    /// Query or stop the running same-owner daemon through kernel-authenticated control.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    LocalControl {
        #[arg(long)]
        directory: PathBuf,
        #[arg(value_enum)]
        action: LocalControlAction,
        /// Select an export from the live owner. Required for probe-webdav only.
        #[arg(long)]
        export: Option<String>,
    },
    /// Enter the native Windows SCM dispatcher with an existing deployment identity.
    #[cfg(windows)]
    WindowsService {
        #[arg(long)]
        name: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate one explicit deployment role without creating an identity or starting services.
    DeploymentCheck {
        #[arg(long)]
        config: PathBuf,
        /// Show only export names and loopback addresses from a private Windows or KSU configuration.
        #[arg(long)]
        describe_webdav: bool,
    },
    /// Run one preprovisioned role in this foreground process.
    DeploymentRun {
        #[arg(long)]
        config: PathBuf,
    },
    /// Query one separately authenticated local deployment health endpoint.
    ManagementHealth {
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate the listener configuration and private credential without starting it.
    ManagementCheck {
        #[arg(long)]
        config: PathBuf,
    },
    /// Get the authenticated state and generation of the current deployment owner.
    ManagementStatus {
        #[arg(long)]
        config: PathBuf,
    },
    /// Read the current owner's bounded dashboard without displaying its credential.
    ManagementDashboard {
        #[arg(long)]
        config: PathBuf,
    },
    /// Preview portable selected history through the authenticated live owner.
    ManagementRestorePreview {
        #[arg(
            long,
            required_unless_present = "deployment",
            conflicts_with = "deployment"
        )]
        config: Option<PathBuf>,
        #[arg(long, required_unless_present = "config", conflicts_with = "config")]
        deployment: Option<PathBuf>,
        #[arg(long, required_unless_present = "context", conflicts_with = "context")]
        request_hex: Option<String>,
        #[arg(
            long,
            required_unless_present = "request_hex",
            conflicts_with = "request_hex"
        )]
        context: bool,
        #[arg(long, requires = "context")]
        space_id: Option<sync_extend_core_model::SpaceId>,
    },
    /// Ask the exact authenticated foreground deployment owner to stop.
    ManagementStop {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        owner_generation: sync_extend_core_model::EntryId,
        #[arg(long)]
        request_id: sync_extend_core_model::EntryId,
    },
    /// Create a new listener-bound management credential file without displaying its token.
    ManagementCredentialsGenerate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Replace one exact snapshot owner using all explicit signed complete storage receipts.
    StorageSnapshotHandoff {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Inspect exact handed-off storage content without releasing pins or disposing CAS.
    StorageRetirementAssess {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        storage_id: String,
    },
    /// Inspect one exact retired storage chunk under retained readonly Windows handles.
    #[cfg(windows)]
    StorageRetirementInspect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        storage_id: String,
        #[arg(long)]
        content_id: String,
    },
    /// Persist one explicitly supplied exact retirement request; no physical disposal.
    StorageRetirementAdmit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Audit retained storage retirement requests and cancellation state.
    StorageRetirementAdmissions {
        #[arg(long)]
        config: PathBuf,
    },
    /// Cancel one exact durable fence before any physical owner activation.
    StorageRetirementCancel {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request_id: String,
    },
    /// Operate on one explicitly selected storage retirement request.
    StorageRetirementPhysical {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        action: storage_retirement_cli::Action,
    },
    /// Own only a Linux storage Journal using an explicit preformatted private image.
    #[cfg(target_os = "linux")]
    StorageLinuxOwner {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        action: storage_retirement_cli::LinuxOwnerAction,
    },
    /// Hand off one retained page owner using all explicitly required native target receipts.
    StorageRetentionHandoff {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Assess exact retained page delivery under an explicit local retention policy.
    StorageRetentionAssess {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Sign a forwarded applied receipt after complete fresh native and content observation.
    StorageClientReceipt {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        request: String,
    },
    /// Pull a bounded original page through an approved storage peer into this client.
    StorageClientPull {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        origin: PathBuf,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long)]
        after_sequence: u64,
    },
    /// Resume one exact forwarded operation with the existing native transaction driver.
    StorageClientApply {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        request: String,
        #[arg(long)]
        operation: String,
    },
    /// Forward retained individually signed originals from this paired client.
    StoragePush {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        origin: PathBuf,
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long)]
        after_sequence: u64,
        /// Retained report signed by the original device, never the forwarder.
        #[arg(long)]
        snapshot_report: Option<PathBuf>,
    },
    /// Sign this device's current audited manifest for later authenticated forwarding.
    StorageSnapshotReport {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Create a new explicit worktree-free storage identity and bounded quota ledger.
    StorageInit {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a fresh private storage identity before independently exchanging approvals.
    StorageProvision {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        space: String,
    },
    /// Initialize the exact provisioned identity with finalized local storage policy.
    StorageInitProvisioned {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_identity: PathBuf,
    },
    /// Report last-reported metadata/content completeness without applying files.
    StorageStatus {
        #[arg(long)]
        config: PathBuf,
    },
    /// Export only this storage device's public pairing identity.
    StorageIdentity {
        #[arg(long)]
        config: PathBuf,
    },
    /// Serve bounded consecutive authenticated sessions using one retained storage owner.
    StorageRun {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        forwarder: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000000))]
        max_sessions: u32,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        session_timeout_secs: u64,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
        between_sessions_secs: u64,
    },
    /// Serve one explicitly approved forwarding peer and one bounded QUIC page.
    StorageServe {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        forwarder: PathBuf,
    },
    /// Pull original signed data from an independently approved storage forwarder.
    StoragePull {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        origin: PathBuf,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long)]
        after_sequence: u64,
        /// Explicit initialized budget for each actual block request, on all paths.
        #[arg(long)]
        attempt_policy: Option<PathBuf>,
    },
    /// Create a fresh independent storage-pull attempt ledger; never resets one.
    StoragePullBudgetInit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Audit the existing attempt ledger read-only without advancing its clock.
    StoragePullBudgetStatus {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Verify both explicitly pinned local EasyTier binary hashes and versions.
    EasytierCheck {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the opted-in fixed-version sidecar for an explicit bounded interval.
    EasytierRun {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        seconds: u64,
    },
    /// Read actual peer routes without treating overlay peers as device identities.
    EasytierObserve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run an authenticated loopback gateway, optionally polling its local spaces.
    WebdavServe {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        scan_interval_secs: Option<u64>,
    },
    /// Check the gateway configuration and, when enabled, the local credential file.
    WebdavCheck {
        #[arg(long)]
        config: PathBuf,
    },
    /// Verify access to one configured export with an authenticated OPTIONS request.
    WebdavConnectionTest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
        #[arg(long)]
        export: String,
    },
    /// Create random per-listener local credentials without displaying secrets.
    WebdavCredentialsGenerate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Display one password explicitly; output must not enter diagnostic logs.
    WebdavCredentialShow {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
    },
    /// Audit TREE transactions and exact retained preparations without executing.
    TreeTransactions {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Preview retained history read-only with explicit selection and bounds.
    RestorePreview {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, conflicts_with_all = ["path", "select_path"])]
        directory: Option<String>,
        #[arg(long, conflicts_with_all = ["path", "directory"])]
        select_path: Vec<String>,
        #[arg(long)]
        destination_prefix: Option<String>,
        #[arg(long, value_parser = ["preserve", "replace-selected-scope"])]
        current_extra_policy: Option<String>,
        #[arg(long, value_parser = ["report-conflicts", "replace-files"])]
        occupied_target_policy: Option<String>,
        #[arg(long)]
        selection_v2: bool,
        #[arg(long)]
        budgets: PathBuf,
    },
    /// Prepare one bounded historical whole-tree restore, retaining input pins.
    TreePrepare {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        baseline: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        budgets: PathBuf,
    },
    /// Explicitly admit the same TREE preparation; cancellation becomes fenced.
    #[cfg(windows)]
    TreeAdmit {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        budgets: PathBuf,
        #[arg(long)]
        allow_irreversible_admission: bool,
    },
    /// Create and seal only the exact admitted TREE owner; user tree unchanged.
    #[cfg(windows)]
    TreeCreateOwner {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Execute admitted TREE actions and NEW Final, then scoped original cleanup.
    #[cfg(windows)]
    TreeExecute {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        allow_non_atomic_tree: bool,
    },
    /// Resume exact TREE lineage; unresolved native attempts remain refused.
    #[cfg(windows)]
    TreeResume {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        allow_non_atomic_tree: bool,
    },
    /// Run delayed paired original cycles; retained signed resolutions precede pages.
    #[cfg(windows)]
    RunOriginalCycle {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        attempts: u32,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=3600))]
        delay_seconds: u32,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        rounds: u32,
        #[arg(long)]
        resolve_file_conflicts_at_ms: Option<u64>,
    },
    /// Serve one explicit bounded two-way original content/application cycle.
    #[cfg(windows)]
    ServeOriginalCycle {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        max_rounds: u32,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        attempts: u32,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=3600))]
        delay_seconds: u32,
        #[arg(long)]
        allow_file_conflict_resolution: bool,
    },
    /// Exchange two-way originals and, only when opted in, one signed resolution.
    #[cfg(windows)]
    ExchangeOriginalCycle {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        rounds: u32,
        #[arg(long)]
        resolve_file_conflicts_at_ms: Option<u64>,
    },
    /// Serve one complete own-resolver admission over authenticated QUIC.
    #[cfg(windows)]
    ServeOriginalConflict {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
    /// Pull one exact foreign resolution, protecting content before native Final.
    #[cfg(windows)]
    PullOriginalConflict {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
    },
    /// Inspect complete signed originals; never synthesize foreign signatures.
    OriginalConflictBundle {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Sign a proposal over complete retained originals without reserving sequence.
    SignOriginalConflict {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        created_at_ms: u64,
    },
    /// Explicitly resolve complete retained flat-file originals through native gates.
    #[cfg(windows)]
    ResolveOriginalConflict {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        created_at_ms: u64,
    },
    /// Explicit bounded original file worker; one attempt, then delay, no bursts.
    #[cfg(windows)]
    RunOriginal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        attempts: u32,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=3600))]
        delay_seconds: u32,
        /// Opt in to exact complete flat-file conflict preservation; explicit display time.
        #[arg(long)]
        resolve_file_conflicts_at_ms: Option<u64>,
    },
    /// Resume one original durable signed page offline through existing drivers.
    #[cfg(windows)]
    ResumeOriginal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        request: String,
    },
    /// Serve a bounded number of explicitly paired original content/apply attempts.
    #[cfg(windows)]
    ServeOriginal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
        attempts: u32,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=3600))]
        delay_seconds: u32,
    },
    /// Pull one original signed page, then explicitly receive/apply eligible files.
    #[cfg(windows)]
    PullOriginal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 0)]
        after_sequence: u64,
    },
    /// Inspect exact durable signed pages with current approval and quota checks.
    OriginalInbox {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=64))]
        max_pages: u32,
    },
    /// Probe Linux/Android no-replace in a fresh private directory; preserve residues.
    ProbeNoReplace {
        #[arg(long)]
        parent: PathBuf,
    },
    /// Join an explicitly approved space; creates a new independent local identity.
    Join {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        space: String,
    },
    /// Export the public pairing identity only; never export device secrets.
    PeerIdentity {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly approve a peer identity after out-of-band public-key comparison.
    Pair {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer: PathBuf,
        #[arg(long)]
        expected_public_key: String,
    },
    /// Serve retained files to one explicitly paired peer over mutual TLS1.3 QUIC.
    ServeFiles {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
    /// Pull one file as a conflict-preserving local copy; not whole-space convergence.
    PullFile {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long)]
        path: String,
    },
    /// Serve only this device's signed log pages; no remote content or apply.
    ServeOperations {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
    /// Receive one authenticated log page; does not materialize the worktree.
    PullOperations {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 0)]
        after_sequence: u64,
    },
    /// Show bounded logical alternatives, not materialized or backed-up state.
    CausalFrontiers {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Replay an approved original signed operation read-only; never apply or receive.
    ReplayRemoteOperation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        signed_operation: PathBuf,
    },
    /// Apply one approved original signed file Rename without local reauthoring.
    #[cfg(windows)]
    ApplyRemoteRename {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        signed_operation: PathBuf,
    },
    /// Inspect original signed Rename receipts without native recovery.
    #[cfg(windows)]
    RemoteRenames {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Resume only one exact admitted original signed Rename.
    #[cfg(windows)]
    RecoverRemoteRename {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    #[cfg(windows)]
    ApplyRemoteDelete {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        signed_operation: PathBuf,
    },
    /// Inspect original signed Delete receipts without native recovery.
    #[cfg(windows)]
    RemoteDeletes {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Resume only one exact admitted original signed Delete.
    #[cfg(windows)]
    RecoverRemoteDelete {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    #[cfg(windows)]
    ApplyRemoteReplace {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        signed_operation: PathBuf,
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Pin every authenticated canonical conflict branch; never apply or release.
    PrepareConflictBranches {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        signed_resolution: PathBuf,
    },
    /// Reserve exact local signed resolution history; no native apply or release.
    AdmitConflictResolution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        signed_resolution: PathBuf,
    },
    /// Inspect durable prospective local conflict resolution owners.
    ConflictResolutions {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Inspect original signed Replace receipts without native recovery.
    #[cfg(windows)]
    RemoteReplaces {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Resume only one exact admitted original signed Replace.
    #[cfg(windows)]
    RecoverRemoteReplace {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Exchange bounded signed own-origin metadata in both directions; no file apply.
    ExchangeMetadata {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..=64))]
        rounds: u32,
    },
    /// Serve explicitly paired two-way metadata cycles; no automatic file sync.
    ServeMetadata {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..=64))]
        max_rounds: u32,
    },
    /// Repeat explicitly paired metadata-only cycles; does not apply remote files.
    RunMetadata {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..=64))]
        rounds: u32,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=86400))]
        interval_secs: u64,
    },
    /// Initialize a local space. Data must be outside the existing worktree.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        root: PathBuf,
    },
    /// Reconcile a stable full scan into immutable content and journal.
    Scan {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Show truthful local capability and index state.
    Status {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Audit the retained original Linux Final and exact outside-intent cleanup state.
    #[cfg(target_os = "linux")]
    LinuxNativeFinals {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Remove only one committed transaction's exact outside intent under a fresh owner.
    #[cfg(target_os = "linux")]
    CleanupLinuxNative {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Audit one bounded metadata snapshot; report implementation and certification gaps.
    Diagnostics {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Verify an explicit recovered node archive, or perform one bounded
    /// recovered-local mutation and emit an immutable next descriptor.
    #[cfg(windows)]
    RecoveredLocal {
        #[arg(long)]
        descriptor: PathBuf,
        #[command(subcommand)]
        action: recovery::Action,
    },
    /// Audit local storage and references without importing, recovering or deleting.
    StorageReport {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Reserve immutable expected content locally; no import, release or worker.
    ReserveContent {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        intent: PathBuf,
    },
    /// Audit durable worker content reservations without reading CAS or releasing pins.
    ReferenceReservations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Transfer download/restore pins to an exact retained local snapshot; no remote receipt.
    HandoffContent {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        snapshot: String,
    },
    /// Verify and ingest one exact reserved chunk; no snapshot/worker/remote completion.
    IngestReservedChunk {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        chunk: String,
        #[arg(long)]
        source: PathBuf,
    },
    /// Persist one verified unreferenced CAS observation; never authorize deletion.
    MarkGcObject {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long, default_value_t=86400, value_parser=clap::value_parser!(u64).range(1..=604800))]
        grace_secs: u64,
    },
    /// Audit persistent GC marks without touching content or advancing time.
    GcMarks {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Cancel only one GC mark; preserve every file and reference.
    CancelGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Recheck a GC observation after grace; the result never authorizes deletion.
    RevalidateGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Inspect one mark under transient database/file guards; never authorize deletion.
    PreflightGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Persist one guarded GC intent for a future executor; never delete.
    AuthorizeGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
        #[arg(long, default_value_t=300, value_parser=clap::value_parser!(u64).range(1..=3600))]
        ttl_secs: u64,
    },
    /// Audit GC authorization intents at the durable clock watermark.
    GcAuthorizations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Consume one explicit GC intent into a durable reference fence; never move/delete.
    AdmitGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// Audit durable single-use execution admissions and independent terminal states.
    GcExecutions {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly quarantine one admitted CAS object; preserve bytes, never sweep.
    QuarantineGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Audit bounded durable GC quarantine plans without physical recovery.
    GcQuarantines {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Persist one single-use pre-disposition record; never request deletion.
    PrepareGcDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Explicitly dispose one prepared quarantine; pending readers retain its fence.
    ExecuteGcDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Audit disposal preparation/restoration/deletion without executing physical recovery.
    GcDisposals {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Restore only the exact admitted quarantine object, without overwrite.
    RestoreGcQuarantine {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Abort a non-displacing execution fence; never restore/delete or reuse its intent.
    AbortGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Permanently revoke one GC intent without changing any file or pin.
    RevokeGcAuthorization {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// Recheck a durable GC intent under transient guards; no deletion.
    CheckGcAuthorization {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// List immutable snapshot audit metadata, including explicitly pruned non-restorable history.
    SnapshotAudit {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly retire one old snapshot's own pins, preserving audit metadata and all CAS files.
    PruneSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        baseline: String,
        #[arg(long, default_value_t = 0)]
        deleted_min_retention_days: u32,
    },
    /// Protect a retained materialized snapshot after validating its references and content.
    LockSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
    },
    /// Remove only the explicit user lock, never history or object pins.
    UnlockSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
    },
    /// Preview count/budget retention and blockers; never prune history or run GC.
    RetentionReport {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = HistoryPolicy::default().history_snapshots)]
        history_snapshots: u32,
        #[arg(long, default_value_t = HistoryPolicy::default().history_budget_bytes)]
        history_budget_bytes: u64,
        #[arg(long, default_value_t = 0)]
        deleted_min_retention_days: u32,
    },
    /// Set or lower the durable deletion-retention floor at an explicit policy revision.
    SetDeletionRetentionPolicy {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        days: u32,
        #[arg(long)]
        expected_revision: u64,
    },
    /// Persist exact retained-file read pins; does not release overdue leases.
    AcquireReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
        #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
        ttl_secs: u64,
    },
    /// Audit all read lease states without implicitly expiring their pins.
    ReadLeases {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Extend an active, unexpired lease without changing its fixed version.
    RenewReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
        ttl_secs: u64,
    },
    /// Release only this lease's pins; never delete content or history.
    ReleaseReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
    },
    /// Explicitly expire overdue read lease pins; never delete content.
    RecoverReadLeases {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Export the lease's fixed historical file outside worktree/data, never overwrite.
    ExportLeased {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare one committed Delete/Replace original; no native deletion occurs.
    PrepareOriginalDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Audit immutable original preparations without inspecting native bytes.
    OriginalDisposals {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly dispose ONE precommitted original; recovery never selects this.
    ExecuteOriginalDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Prepare exact committed Move marker cleanup without authorizing deletion.
    PrepareCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// List persistent marker cleanup plans and authorization/completion states.
    CleanupPlans {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Cancel a prepared marker cleanup; no file or history is removed.
    CancelCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Explicitly remove only the protected owner marker of a committed Move.
    ExecuteCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Resume authorized marker cleanups only; never authorize preparations.
    RecoverCleanups {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print the immutable current manifest (contains local filenames).
    Manifest {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print local operations (contains local filenames).
    Ops {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Check SQLite, snapshot roots and all retained file versions.
    Verify {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Export a verified current file outside the worktree; never overwrite.
    Export {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        path: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Publish a single local file without overwriting an existing destination.
    Publish {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        path: String,
    },
    /// Explicit Windows NTFS native local publication; not remote apply or sync.
    #[cfg(windows)]
    PublishNative {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        path: String,
    },
    /// Resume only exact durable native receipts; incomplete creators stay pending.
    #[cfg(windows)]
    RecoverNative {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Export one original own-origin signed operation; never sign a foreign origin.
    SignOperation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        operation: String,
    },
    /// Explicit paired original signed new-file Put apply; verified CAS required.
    #[cfg(windows)]
    ApplyRemotePut {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer_device: String,
        #[arg(long)]
        signed_operation: PathBuf,
        /// Optional downloaded local source, verified against the original signed content.
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Restore one retained file as a new local change; occupied paths keep a conflict copy.
    Restore {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
    },
    /// Resume authorized mutations/publications without rolling back newer writes.
    Recover {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// List retained snapshot IDs for single-file restore.
    Snapshots {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Persist a file mutation baseline only. No file is replaced, removed or moved.
    PrepareMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
        #[command(subcommand)]
        action: PrepareAction,
    },
    /// List local mutation preparations and cancellations (contains filenames).
    Mutations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Revalidate a preparation without executing any worktree mutation.
    CheckMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Cancel an unexecuted preparation, releasing only its journal references.
    CancelMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Explicitly execute a prepared Windows local NTFS single-file Delete, Move or Replace.
    ExecuteMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Resume authorized file mutations, never automatically authorize preparations.
    RecoverMutations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Validate configuration without starting any listener.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run local polling reconciliation only; no network listener is started.
    Run {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        scan_interval_secs: u64,
    },
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, clap::ValueEnum)]
enum LocalControlAction {
    Status,
    Stop,
    WaitStopped,
    #[value(name = "probe-webdav")]
    ProbeWebDav,
}

#[derive(Subcommand)]
enum PrepareAction {
    Replace {
        #[arg(long)]
        source: PathBuf,
    },
    Delete,
    Move {
        #[arg(long)]
        destination: String,
    },
}

fn print(value: &impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn main() -> ExitCode {
    let parsed = Cli::parse();
    if let Err(error) = restore_preview_cli::precheck(&parsed) {
        eprintln!("syncd: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = transport_budget::preflight(&parsed) {
        eprintln!("syncd: application budget startup refused: {error}");
        return ExitCode::FAILURE;
    }
    #[cfg(target_os = "linux")]
    if let Command::StorageLinuxOwner { config, action } = &parsed.command {
        // Route before ordinary namespace preparation, any watcher/helper
        // thread, deployment expansion or Tokio runtime.
        if parsed.linux_namespace_config.is_some()
            || parsed.limits.is_some()
            || parsed.control_directory.is_some()
        {
            eprintln!("syncd: storage-only owner uses only its explicit bounded configuration");
            return ExitCode::FAILURE;
        }
        return match storage_retirement_cli::run_linux_owner_before_threads(config, action) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("syncd: Linux storage-only owner refused: {error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "linux")]
    let linux_owner = match linux_namespace::prepare(&parsed) {
        Ok(owner) => owner,
        Err(error) => {
            eprintln!("syncd: Linux owner preparation failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(target_os = "linux")]
    return run_cli(parsed, linux_owner);
    #[cfg(not(target_os = "linux"))]
    {
        // Bounded scan/protocol futures exceed the default Windows main-thread stack
        // in debug builds. Use the same explicit bound on both delivery platforms.
        let runner = std::thread::Builder::new()
            .name("syncd-main".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                run_cli(
                    parsed,
                    #[cfg(target_os = "linux")]
                    linux_owner,
                )
            });
        match runner {
            Ok(runner) => runner.join().unwrap_or(ExitCode::FAILURE),
            Err(error) => {
                eprintln!("syncd: runtime thread failed: {error}");
                ExitCode::FAILURE
            }
        }
    }
}

#[inline(never)]
fn run_cli(
    parsed: Cli,
    #[cfg(target_os = "linux")] mut linux_owner: Option<linux_namespace::LinuxDaemonOwner>,
) -> ExitCode {
    #[cfg(windows)]
    if let Command::WindowsService { name, config } = &parsed.command {
        let name = name.clone();
        let config = config.clone();
        let limits = parsed.limits.clone();
        let transport_attempt_policy = parsed.transport_attempt_policy.clone();
        let transport_attempt_budget_dir = parsed.transport_attempt_budget_dir.clone();
        return match sync_extend_platform_fs::run_windows_service(&name, move |_reporter| {
            let (cli, _management) = deployment::prepare(Cli {
                limits,
                transport_attempt_policy,
                transport_attempt_budget_dir,
                command: Command::DeploymentRun { config },
            })
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime
                .block_on(Box::pin(execute(cli)))
                .map_err(|error| std::io::Error::other(error.to_string()))
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("syncd: native service failed: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let (cli, _management) = match deployment::prepare(parsed) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("syncd: deployment validation failed: {error}");
            #[cfg(target_os = "linux")]
            if let Some(owner) = linux_owner.take() {
                if let Err(terminal) = owner.finish() {
                    eprintln!("syncd: Linux validation terminal refused: {terminal}");
                }
            }
            return ExitCode::FAILURE;
        }
    };
    #[cfg(target_os = "linux")]
    if let (
        Some(owner),
        Command::Publish {
            data_dir,
            source,
            path,
        },
    ) = (linux_owner.as_mut(), &cli.command)
    {
        // No runtime/thread exists: open SQLite/CAS and retain the full native
        // plan, then launch original PREPARED helpers immediately before ARM.
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            if cli.control_directory.is_some() {
                return Err("local control requires an explicit foreground service command".into());
            }
            let limits = read_local_limits(cli.limits.as_deref())?;
            print(&owner.publish_before_runtime(
                data_dir,
                source,
                PortablePath::new(path.clone())?,
                limits,
            )?)?;
            Ok(())
        })();
        let outcome = match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("syncd: {error}");
                ExitCode::FAILURE
            }
        };
        if let Some(owner) = linux_owner {
            if let Err(error) = owner.finish() {
                eprintln!("syncd: Linux original owner terminal refused: {error}");
                return ExitCode::FAILURE;
            }
        }
        return outcome;
    }
    #[cfg(target_os = "linux")]
    let linux_owner = linux_owner.map(std::sync::Arc::new);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let outcome = match runtime {
        Ok(runtime) => match runtime.block_on(Box::pin(execute(
            cli,
            #[cfg(target_os = "linux")]
            linux_owner.clone(),
        ))) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("syncd: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("syncd: runtime failed: {error}");
            ExitCode::FAILURE
        }
    };
    #[cfg(target_os = "linux")]
    if let Some(owner) = linux_owner {
        let owner = match std::sync::Arc::try_unwrap(owner) {
            Ok(owner) => owner,
            Err(_) => {
                eprintln!("syncd: Linux listener retained an owner after shutdown");
                return ExitCode::FAILURE;
            }
        };
        if let Err(error) = owner.finish() {
            eprintln!("syncd: Linux original owner terminal refused: {error}");
            return ExitCode::FAILURE;
        }
    }
    outcome
}

fn read_tree_budgets(
    path: &std::path::Path,
) -> Result<sync_extend_reconcile::TreeRestoreBudgets, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("TREE budgets exceed 64 KiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_local_limits(
    path: Option<&std::path::Path>,
) -> Result<sync_extend_core_model::limits::LocalLimits, Box<dyn std::error::Error>> {
    let limits: sync_extend_core_model::limits::LocalLimits = if let Some(path) = path {
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err("limits configuration exceeds 64 KiB".into());
        }
        serde_json::from_slice(&bytes)?
    } else {
        Default::default()
    };
    limits.validate()?;
    Ok(limits)
}

async fn execute(
    cli: Cli,
    #[cfg(target_os = "linux")] linux_owner: Option<
        std::sync::Arc<linux_namespace::LinuxDaemonOwner>,
    >,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport_budget = transport_budget::Selection::from_cli(&cli)?;
    let limits = read_local_limits(cli.limits.as_deref())?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let local_control = if let Some(directory) = cli.control_directory {
        if !matches!(
            &cli.command,
            Command::Run { .. }
                | Command::DeploymentRun { .. }
                | Command::EasytierRun { .. }
                | Command::ServeFiles { .. }
                | Command::ServeMetadata { .. }
                | Command::RunMetadata { .. }
                | Command::ServeOperations { .. }
                | Command::WebdavServe { .. }
                | Command::StorageRun { .. }
        ) {
            return Err("local control requires an explicit foreground service command".into());
        }
        Some(local_control::LocalControl::start(&directory)?)
    } else {
        None
    };
    let open = |data: &std::path::Path| {
        #[cfg(target_os = "linux")]
        if let Some(owner) = linux_owner.as_ref() {
            return owner.open(data, limits.clone());
        }
        LocalSpace::open(data)?.with_limits(limits.clone())
    };
    match cli.command {
        Command::TransportAttemptPolicySign {
            storage_config,
            output,
            ..
        } => {
            transport_budget.sign(storage_config.as_deref(), &output)?;
        }
        Command::TransportAttemptBudgetInit { storage_config, .. } => {
            transport_budget.init(storage_config.as_deref())?;
        }
        Command::TransportAttemptBudgetStatus { .. } => {
            transport_budget.status()?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Command::LocalControl {
            directory,
            action,
            export,
        } => {
            if export.is_some() != matches!(action, LocalControlAction::ProbeWebDav) {
                return Err("--export is required only for probe-webdav".into());
            }
            let action = match action {
                LocalControlAction::Status => {
                    sync_extend_platform_fs::LocalControlOperation::Status
                }
                LocalControlAction::Stop => sync_extend_platform_fs::LocalControlOperation::Stop,
                LocalControlAction::ProbeWebDav => {
                    sync_extend_platform_fs::LocalControlOperation::ProbeWebDav(
                        export.ok_or("WebDAV export required")?,
                    )
                }
                LocalControlAction::WaitStopped => {
                    let owner = sync_extend_platform_fs::LocalControlListener::bind(&directory)?;
                    drop(owner);
                    print(&serde_json::json!({
                        "control_owner_terminal":true,
                        "stale_pid_adopted":false,
                    }))?;
                    return Ok(());
                }
            };
            print(&local_control::request(&directory, action)?)?;
        }
        #[cfg(windows)]
        Command::WindowsService { .. } => {
            return Err("SCM command must use native dispatcher".into())
        }
        Command::DeploymentCheck {
            config,
            describe_webdav,
        } => {
            print(&deployment::check(&config, describe_webdav)?)?;
        }
        Command::DeploymentRun { .. } => {
            return Err("deployment role was not expanded".into());
        }
        Command::ManagementHealth { config } => management::check(&config)?,
        Command::ManagementCheck { config } => management::check_config(&config)?,
        Command::ManagementStatus { config } => management::control_status(&config)?,
        Command::ManagementDashboard { config } => management::control_dashboard(&config)?,
        Command::ManagementRestorePreview {
            config,
            deployment,
            request_hex,
            context,
            space_id,
        } => {
            let path = if let Some(path) = config {
                path
            } else {
                deployment::load(&deployment.ok_or("preview deployment absent")?)?
                    .management
                    .ok_or("deployment management configuration absent")?
            };
            let _ = context;
            management::control_restore_preview(&path, request_hex.as_deref(), space_id.as_ref())?;
        }
        Command::ManagementStop {
            config,
            owner_generation,
            request_id,
        } => {
            management::control_stop(&config, &owner_generation, &request_id)?;
        }
        Command::ManagementCredentialsGenerate { config } => {
            management::generate_credentials(&config)?;
            println!(
                "{}",
                serde_json::json!({
                    "credentials_created": true,
                    "secrets_displayed": false,
                    "restart_required_for_activation": true
                })
            );
        }
        Command::StorageRetirementAssess { config, storage_id } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            print(&node.assess_retired_storage_content(&storage_id.parse()?)?)?;
        }
        #[cfg(windows)]
        Command::StorageRetirementInspect {
            config,
            storage_id,
            content_id,
        } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            let inspection =
                node.inspect_retired_storage_object(&storage_id.parse()?, &content_id.parse()?)?;
            print(inspection.observation())?;
        }
        Command::StorageRetirementAdmit { config, request } => {
            let request: sync_extend_core_model::storage_retirement::StorageRetirementRequest =
                storage::load(&request)?;
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            print(&node.admit_storage_retirement(&request)?)?;
        }
        Command::StorageRetirementAdmissions { config } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            print(&node.storage_retirement_admissions()?)?;
        }
        Command::StorageRetirementCancel { config, request_id } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            print(&node.cancel_storage_retirement(&request_id.parse()?)?)?;
        }
        #[cfg(target_os = "linux")]
        Command::StorageLinuxOwner { .. } => {
            return Err("storage-only owner must run before any runtime thread".into());
        }
        Command::StorageRetirementPhysical { config, action } => {
            storage_retirement_cli::run(&config, action)?;
        }
        Command::StoragePush {
            data_dir,
            origin,
            storage,
            address,
            after_sequence,
            snapshot_report,
        } => {
            let origin = storage::load(&origin)?;
            let peer = storage::load(&storage)?;
            if let Some(path) = snapshot_report {
                storage::push_with_snapshot(
                    data_dir,
                    origin,
                    peer,
                    address,
                    after_sequence,
                    Some(storage::load_snapshot_report(&path)?),
                    &transport_budget,
                )
                .await?;
            } else {
                storage::push(
                    data_dir,
                    origin,
                    peer,
                    address,
                    after_sequence,
                    &transport_budget,
                )
                .await?;
            }
        }
        Command::StorageSnapshotReport { data_dir } => {
            print(&open(&data_dir)?.signed_storage_snapshot_report()?)?;
        }
        Command::StorageInit { config } => {
            let config =
                storage::load::<sync_extend_core_model::storage_node::StorageNodeConfig>(&config)?;
            let node = sync_extend_reconcile::StorageNode::initialize(config)?;
            print(&node.status()?)?;
        }
        Command::StorageProvision { data_dir, space } => {
            print(&sync_extend_reconcile::StorageNode::provision_identity(
                &data_dir,
                space.parse()?,
            )?)?;
        }
        Command::StorageInitProvisioned {
            config,
            expected_identity,
        } => {
            let config = storage::load(&config)?;
            let expected = storage::load(&expected_identity)?;
            let node =
                sync_extend_reconcile::StorageNode::initialize_provisioned(config, &expected)?;
            print(&node.status()?)?;
        }
        Command::StorageStatus { config } => {
            let config =
                storage::load::<sync_extend_core_model::storage_node::StorageNodeConfig>(&config)?;
            print(&sync_extend_reconcile::StorageNode::open(config)?.status()?)?;
        }
        Command::StorageSnapshotHandoff {
            config,
            policy,
            evidence,
        } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            let policy = storage::load(&policy)?;
            let evidence = storage::load_snapshot_handoff_evidence(&evidence)?;
            print(&serde_json::json!({
                "handed_off": node.handoff_retained_snapshot_storage(&policy, &evidence)?,
                "physical_deletion_executed": false,
                "native_applied": false,
                "remote_backup_complete": false,
            }))?;
        }
        Command::StorageRetentionHandoff {
            config,
            policy,
            evidence,
        } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            let policy = storage::load(&policy)?;
            let evidence = storage::load_retention_evidence(&evidence)?;
            print(&serde_json::json!({
                "handed_off": node.handoff_retained_page_delivery(&policy, &evidence)?,
                "physical_deletion_executed": false,
            }))?;
        }
        Command::StorageRetentionAssess {
            config,
            policy,
            evidence,
        } => {
            let node = sync_extend_reconcile::StorageNode::open(storage::load(&config)?)?;
            let policy = storage::load(&policy)?;
            let evidence: Vec<sync_extend_transport::ForwardedAppliedEvidence> =
                storage::load_retention_evidence(&evidence)?;
            print(&node.assess_retained_page_delivery(&policy, &evidence)?)?;
        }
        Command::StorageClientReceipt { data_dir, request } => {
            #[cfg(windows)]
            {
                print(&open(&data_dir)?.forwarded_applied_receipt(&request.parse()?)?)?;
            }
            #[cfg(not(windows))]
            {
                let _ = (data_dir, request);
                return Err(
                    "forwarded actual applied receipt requires the certified native platform"
                        .into(),
                );
            }
        }
        Command::StorageClientPull {
            data_dir,
            source,
            origin,
            address,
            after_sequence,
        } => {
            storage::client_pull(
                data_dir,
                storage::load(&source)?,
                storage::load(&origin)?,
                address,
                after_sequence,
                &limits,
                &transport_budget,
            )
            .await?;
        }
        Command::StorageClientApply {
            data_dir,
            request,
            operation,
        } => {
            #[cfg(windows)]
            {
                let mut local = LocalSpace::open_with_limits(&data_dir, limits.clone())?;
                print(&local.apply_forwarded_operation(&request.parse()?, &operation.parse()?)?)?;
            }
            #[cfg(not(windows))]
            {
                let _ = (data_dir, request, operation);
                return Err(
                    "forwarded native client apply requires the certified platform driver".into(),
                );
            }
        }
        Command::StorageIdentity { config } => {
            let config =
                storage::load::<sync_extend_core_model::storage_node::StorageNodeConfig>(&config)?;
            let node = sync_extend_reconcile::StorageNode::open(config)?;
            print(node.transport_identity()?.peer_identity())?;
        }
        Command::StorageRun {
            config,
            forwarder,
            max_sessions,
            session_timeout_secs,
            between_sessions_secs,
        } => {
            storage::run(
                storage::load(&config)?,
                storage::load(&forwarder)?,
                max_sessions,
                session_timeout_secs,
                between_sessions_secs,
                &transport_budget,
            )
            .await?;
        }
        Command::StorageServe { config, forwarder } => {
            storage::serve(
                storage::load(&config)?,
                storage::load(&forwarder)?,
                &transport_budget,
            )
            .await?;
        }
        Command::StoragePull {
            config,
            source,
            origin,
            address,
            after_sequence,
            attempt_policy,
        } => {
            storage::pull(
                storage::load(&config)?,
                storage::load(&source)?,
                storage::load(&origin)?,
                address,
                after_sequence,
                attempt_policy.as_deref().map(storage::load).transpose()?,
                &transport_budget,
            )
            .await?;
        }
        Command::StoragePullBudgetInit { config, policy } => {
            storage::init_pull_budget(storage::load(&config)?, storage::load(&policy)?)?;
        }
        Command::StoragePullBudgetStatus { config, policy } => {
            storage::status_pull_budget(storage::load(&config)?, storage::load(&policy)?)?;
        }
        Command::EasytierCheck { config } => easytier::check(&easytier::load(&config)?)?,
        Command::EasytierObserve { config } => easytier::observe(&easytier::load(&config)?)?,
        Command::EasytierRun { config, seconds } => {
            let config = easytier::load(&config)?;
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_shutdown = shutdown.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                easytier::run(config, seconds, worker_shutdown).map_err(|error| error.to_string())
            });
            tokio::select! {
                result = &mut worker => { result?.map_err(std::io::Error::other)?; }
                result = shutdown::requested() => {
                    result?;
                    shutdown.store(true, std::sync::atomic::Ordering::Release);
                    worker.await?.map_err(std::io::Error::other)?;
                }
            }
        }
        Command::WebdavCredentialsGenerate { config } => {
            let runtime = webdav::load(&config)?;
            webdav_credentials::generate(&runtime.credentials, &runtime.listener)?;
            print(&serde_json::json!({
                "listener_id": runtime.listener.listener_id,
                "credentials_created": true,
                "accounts": runtime.listener.accounts.iter().map(|account|&account.username).collect::<Vec<_>>(),
                "listener_started": false,
            }))?;
        }
        Command::WebdavCredentialShow { config, username } => {
            let runtime = webdav::load(&config)?;
            let credentials =
                webdav_credentials::Credentials::load(&runtime.credentials, &runtime.listener)?;
            println!(
                "{}",
                credentials
                    .password(&username)
                    .ok_or("unknown local DAV account")?
            );
        }
        Command::WebdavCheck { config } => print(&webdav::check(&config)?)?,
        Command::WebdavConnectionTest {
            config,
            username,
            export,
        } => {
            print(&webdav::test_connection(&config, &username, &export)?)?;
        }
        Command::WebdavServe {
            config,
            scan_interval_secs,
        } => {
            let runtime = webdav::load(&config)?;
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_shutdown = shutdown.clone();
            let dav_limits = limits.clone();
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let gateway = local_control
                .as_ref()
                .map(local_control::LocalControl::gateway_slot);
            #[cfg(target_os = "linux")]
            let worker_owner = linux_owner.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                webdav::serve(
                    runtime,
                    dav_limits,
                    scan_interval_secs,
                    worker_shutdown,
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    gateway,
                    #[cfg(target_os = "linux")]
                    worker_owner,
                )
                .map_err(|error| error.to_string())
            });
            tokio::select! {
                result = &mut worker => { result?.map_err(std::io::Error::other)?; }
                result = shutdown::requested() => {
                    result?;
                    shutdown.store(true, std::sync::atomic::Ordering::Release);
                    worker.await?.map_err(std::io::Error::other)?;
                }
            }
        }
        Command::TreeTransactions { data_dir } => {
            print(&open(&data_dir)?.tree_restore_transactions()?)?;
        }
        Command::RestorePreview {
            data_dir,
            snapshot,
            baseline,
            path,
            directory,
            select_path,
            destination_prefix,
            current_extra_policy,
            occupied_target_policy,
            selection_v2,
            budgets,
        } => {
            restore_preview_cli::run_selection(
                &data_dir,
                &snapshot,
                baseline.as_deref(),
                path.as_deref(),
                directory.as_deref(),
                &select_path,
                destination_prefix.as_deref(),
                current_extra_policy.as_deref(),
                occupied_target_policy.as_deref(),
                selection_v2,
                &budgets,
            )?;
        }
        Command::TreePrepare {
            data_dir,
            baseline,
            target,
            transaction,
            budgets,
        } => {
            let budgets = read_tree_budgets(&budgets)?;
            print(&open(&data_dir)?.prepare_tree_restore_pipeline(
                &baseline.parse()?,
                &target.parse()?,
                transaction.parse()?,
                &budgets,
            )?)?;
        }
        #[cfg(windows)]
        Command::TreeAdmit {
            data_dir,
            transaction,
            budgets,
            allow_irreversible_admission,
        } => {
            if !allow_irreversible_admission {
                return Err("explicit irreversible TREE admission opt-in required".into());
            }
            print(&open(&data_dir)?.admit_tree_restore_pipeline(
                &transaction.parse()?,
                &read_tree_budgets(&budgets)?,
            )?)?;
        }
        #[cfg(windows)]
        Command::TreeCreateOwner {
            data_dir,
            transaction,
        } => {
            let local = open(&data_dir)?;
            let transaction = transaction.parse()?;
            let ready = local.seal_tree_owner(local.create_tree_owner(&transaction)?)?;
            print(
                &serde_json::json!({"transaction_id":transaction,"owner_ready":ready.owner_ready(),
                "whole_tree_completed":false,"tree_atomic":false,"remote_backup_complete":false}),
            )?;
        }
        #[cfg(windows)]
        Command::TreeExecute {
            data_dir,
            transaction,
            allow_non_atomic_tree,
        } => {
            if !allow_non_atomic_tree {
                return Err("explicit non-atomic TREE execution opt-in required".into());
            }
            print(&open(&data_dir)?.restore_tree_native(&transaction.parse()?)?)?;
        }
        #[cfg(windows)]
        Command::TreeResume {
            data_dir,
            transaction,
            allow_non_atomic_tree,
        } => {
            if !allow_non_atomic_tree {
                return Err("explicit non-atomic TREE resume opt-in required".into());
            }
            print(&open(&data_dir)?.resume_tree_native_restore(&transaction.parse()?)?)?;
        }
        Command::ProbeNoReplace { parent } => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let report = sync_extend_platform_fs::probe_no_replace(&parent)?;
                let key = |key: sync_extend_platform_fs::UnixFileKey| serde_json::json!({ "device": key.device, "inode": key.inode });
                print(&serde_json::json!({
                    "probe_directory": report.probe_directory,
                    "parent_key": key(report.parent_key),
                    "original_creator_key": report.original_creator_key.map(key),
                    "observations_complete": report.observations_complete(),
                    "observed_no_replace": report.observed_no_replace,
                    "occupied_file_preserved": report.occupied_file_preserved,
                    "occupied_directory_preserved": report.occupied_directory_preserved,
                    "occupied_symlink_preserved": report.occupied_symlink_preserved,
                    "original_creator_verified": report.original_creator_verified,
                    "directories_flushed": report.directories_flushed,
                    "failure": report.failure,
                    "residues_preserved": true,
                    "source_slot_exclusion": false,
                    "native_apply_enabled": false,
                    "android_device_certified": false,
                }))?;
                if !report.observations_complete() {
                    return Err("no-replace probe incomplete; residues preserved".into());
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                let _ = parent;
                return Err("no-replace probe is Linux/Android-only; no paths changed".into());
            }
        }
        Command::Join {
            data_dir,
            root,
            space,
        } => {
            let local = LocalSpace::join_space(&data_dir, &root, &space.parse()?, limits.clone())?;
            print(&local.status()?)?;
        }
        #[cfg(windows)]
        Command::ServeOriginalCycle {
            data_dir,
            peer_device,
            listen,
            max_rounds,
            attempts,
            delay_seconds,
            allow_file_conflict_resolution,
        } => {
            let mut local = open(&data_dir)?;
            let origin = peer_device.parse()?;
            let peer = local.read_transport_peer(&origin)?;
            let identity = local.transport_identity()?;
            local.resume_original_paired_native_lineage(&origin)?;
            local.scan_original_paired_worker()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            print(
                &serde_json::json!({"listening": listener.local_address()?, "max_original_rounds": max_rounds,
                    "bounded_original_attempts": attempts, "post_attempt_delay_seconds": delay_seconds}),
            )?;
            for attempt in 1..=attempts {
                if attempt > 1 {
                    local.resume_original_paired_native_lineage(&origin)?;
                    local.scan_original_paired_worker()?;
                }
                let current = local.read_transport_peer(&origin)?;
                let action = async {
                    let mut connection = listener.accept(&identity, &current).await?;
                    let result = local
                        .serve_original_paired_cycle(
                            &mut connection,
                            max_rounds,
                            allow_file_conflict_resolution,
                        )
                        .await?;
                    connection.finish().await?;
                    Ok::<_, sync_extend_reconcile::ReconcileError>(result)
                };
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    result = action => {
                        match result {
                            Ok(result) => print(&result)?,
                            Err(sync_extend_reconcile::ReconcileError::Transport(error))
                                if sync_extend_reconcile::original_worker_transport_retryable(&error) =>
                            {
                                eprintln!("syncd: paired original session disconnected; durable prefix retained: {error}");
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(delay_seconds))) => {}
                }
            }
        }
        #[cfg(windows)]
        Command::RunOriginalCycle {
            data_dir,
            peer_device,
            address,
            attempts,
            delay_seconds,
            rounds,
            resolve_file_conflicts_at_ms,
        } => {
            let budget = sync_extend_reconcile::OriginalPairedWorkerBudget {
                attempts,
                delay_seconds,
                rounds,
            };
            budget.validate()?;
            let mut local = open(&data_dir)?;
            let origin = peer_device.parse()?;
            for attempt in 1..=attempts {
                local.resume_original_paired_worker(&origin, resolve_file_conflicts_at_ms)?;
                local.scan_original_paired_worker()?;
                let peer = local.read_transport_peer(&origin)?;
                let identity = local.transport_identity()?;
                let action = async {
                    let mut connection = transport_budget
                        .connect(&data_dir, address, &identity, &peer)
                        .await?;
                    let result = local
                        .exchange_original_paired_cycle(
                            &mut connection,
                            rounds,
                            resolve_file_conflicts_at_ms,
                        )
                        .await?;
                    connection.finish().await?;
                    Ok::<_, sync_extend_reconcile::ReconcileError>(result)
                };
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    result = action => {
                        match result {
                            Ok(outcome) => {
                                let pending = outcome.pulled.iter().chain(&outcome.served).any(|r|
                                    r.received.is_some() && r.applied.is_none());
                                print(&serde_json::json!({"attempt": attempt, "outcome": outcome}))?;
                                if pending && resolve_file_conflicts_at_ms.is_none() {
                                    return Err("paired original worker native safety refusal; explicit resolution required".into());
                                }
                            }
                            Err(sync_extend_reconcile::ReconcileError::Transport(error))
                                if sync_extend_reconcile::original_worker_transport_retryable(&error) =>
                            {
                                eprintln!("syncd: paired original worker disconnected; durable prefix retained: {error}");
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(delay_seconds))) => {}
                }
            }
        }
        #[cfg(windows)]
        Command::ExchangeOriginalCycle {
            data_dir,
            peer_device,
            address,
            rounds,
            resolve_file_conflicts_at_ms,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let result = local
                .exchange_original_paired_cycle(
                    &mut connection,
                    rounds,
                    resolve_file_conflicts_at_ms,
                )
                .await?;
            connection.finish().await?;
            print(&result)?;
        }
        #[cfg(windows)]
        Command::ServeOriginalConflict {
            data_dir,
            peer_device,
            transaction,
            listen,
        } => {
            let local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            print(
                &serde_json::json!({"listening": listener.local_address()?, "bounded_conflict_attempts": 1}),
            )?;
            let mut connection = listener.accept(&identity, &peer).await?;
            let receipt = local
                .serve_original_conflict_resolution(&mut connection, &transaction.parse()?)
                .await?;
            connection.finish().await?;
            print(&receipt)?;
        }
        #[cfg(windows)]
        Command::PullOriginalConflict {
            data_dir,
            peer_device,
            address,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let receipt = local
                .pull_original_conflict_resolution(&mut connection)
                .await?;
            connection.finish().await?;
            print(&receipt)?;
        }
        Command::OriginalConflictBundle { data_dir } => {
            print(&open(&data_dir)?.retained_original_conflict_bundle(
                sync_extend_core_model::conflict_resolution::ResolutionLimits::default(),
            )?)?;
        }
        Command::SignOriginalConflict {
            data_dir,
            created_at_ms,
        } => {
            print(&open(&data_dir)?.sign_retained_original_file_resolution(
                created_at_ms,
                sync_extend_core_model::conflict_resolution::ResolutionLimits::default(),
            )?)?;
        }
        #[cfg(windows)]
        Command::ResolveOriginalConflict {
            data_dir,
            created_at_ms,
        } => {
            print(&open(&data_dir)?.apply_retained_original_file_conflict(
                created_at_ms,
                sync_extend_core_model::conflict_resolution::ResolutionLimits::default(),
            )?)?;
        }
        #[cfg(windows)]
        Command::RunOriginal {
            data_dir,
            peer_device,
            address,
            attempts,
            delay_seconds,
            resolve_file_conflicts_at_ms,
        } => {
            let mut local = open(&data_dir)?;
            let origin = peer_device.parse()?;
            let budget = sync_extend_reconcile::OriginalWorkerBudget {
                attempts,
                delay_seconds,
            };
            budget.validate()?;
            for attempt in 1..=attempts {
                local.resume_original_worker_page_with_conflicts(
                    &origin,
                    resolve_file_conflicts_at_ms,
                )?;
                if local.original_worker_has_pending_native()? {
                    return Err(
                        "original worker pending native lineage; explicit scoped recovery required"
                            .into(),
                    );
                }
                let peer = local.read_transport_peer(&origin)?;
                let identity = local.transport_identity()?;
                let after = local.original_worker_after(&origin)?;
                let action = async {
                    match transport_budget
                        .connect(&data_dir, address, &identity, &peer)
                        .await
                    {
                        Ok(mut connection) => {
                            // A local refusal is not retried as a transport problem.
                            let transfer = async {
                                let outcome =
                                    local.pull_original_exchange(&mut connection, after).await?;
                                connection.finish().await?;
                                Ok::<_, sync_extend_reconcile::ReconcileError>(outcome)
                            }
                            .await;
                            let outcome = match transfer {
                                Ok(outcome) => outcome,
                                Err(sync_extend_reconcile::ReconcileError::Transport(error))
                                    if sync_extend_reconcile::original_worker_transport_retryable(&error) =>
                                {
                                    eprintln!("syncd: original transfer disconnected; durable prefix retained: {error}");
                                    return Ok(());
                                }
                                Err(error) => return Err(error.into()),
                            };
                            print(
                                &serde_json::json!({"attempt": attempt, "after_applied": after, "outcome": outcome}),
                            )?;
                            if outcome.target_refusal.is_some() && outcome.received.is_some() {
                                if let Some(time) = resolve_file_conflicts_at_ms {
                                    let resolved = local.apply_retained_original_file_conflict(
                                        time,
                                        Default::default(),
                                    )?;
                                    print(&serde_json::json!({
                                        "attempt": attempt, "local_conflict_resolution": resolved,
                                        "peer_applied_acknowledged": false,
                                        "requires_signed_resolution_exchange": true,
                                    }))?;
                                    return Ok(());
                                }
                                return Err::<(), Box<dyn std::error::Error>>("original worker native safety refusal; explicit resolution required".into());
                            }
                            Ok(())
                        }
                        Err(error)
                            if sync_extend_reconcile::original_worker_transport_retryable(
                                &error,
                            ) =>
                        {
                            eprintln!("syncd: original worker connection unavailable: {error}");
                            Ok(())
                        }
                        Err(error) => Err(error.into()),
                    }
                };
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    result = action => { result?; }
                }
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(delay_seconds))) => {}
                }
            }
        }
        #[cfg(windows)]
        Command::ResumeOriginal { data_dir, request } => {
            let mut local = open(&data_dir)?;
            let request = request.parse()?;
            let envelope = local
                .original_content_inbox(64)?
                .into_iter()
                .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(&request))
                .ok_or("original inbox request not found")?;
            let received = local.receive_original_page(&request)?;
            let mut applied = Vec::new();
            for signed in &envelope.signed_page.page.operations {
                applied.push(local.apply_original_operation(&request, &signed.operation.op_id)?);
            }
            print(&serde_json::json!({
                "received": received,
                "operations": applied,
                "applied_receipt": local.original_applied_receipt(&request)?
            }))?;
        }
        Command::OriginalInbox {
            data_dir,
            max_pages,
        } => {
            print(&open(&data_dir)?.original_content_inbox(max_pages as usize)?)?;
        }
        #[cfg(windows)]
        Command::PullOriginal {
            data_dir,
            peer_device,
            address,
            after_sequence,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let outcome = local
                .pull_original_exchange(&mut connection, after_sequence)
                .await?;
            connection.finish().await?;
            print(&outcome)?;
        }
        #[cfg(windows)]
        Command::ServeOriginal {
            data_dir,
            peer_device,
            listen,
            attempts,
            delay_seconds,
        } => {
            let local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            print(&serde_json::json!({
                "listening": listener.local_address()?,
                "paired_device": peer.device_id,
                "bounded_original_attempts": attempts,
                "post_attempt_delay_seconds": delay_seconds,
                "unattended_worker": false,
                "remote_backup_complete": false
            }))?;
            for attempt in 1..=attempts {
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    accepted = listener.accept(&identity, &peer) => {
                        match accepted {
                            Ok(mut connection) => {
                                match local.serve_original_exchange(&mut connection).await {
                                    Ok(outcome) => {
                                        connection.finish().await?;
                                        print(&serde_json::json!({"attempt": attempt, "outcome": outcome}))?;
                                    }
                                    Err(error) => eprintln!("syncd: original exchange refused; retained state: {error}"),
                                }
                            }
                            Err(error) => eprintln!("syncd: original paired connection refused: {error}"),
                        }
                    }
                }
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(delay_seconds))) => {}
                }
            }
        }
        Command::PeerIdentity { data_dir } => {
            print(open(&data_dir)?.transport_identity()?.peer_identity())?;
        }
        Command::Pair {
            data_dir,
            peer,
            expected_public_key,
        } => {
            let file = std::fs::File::open(peer)?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err("peer identity exceeds 64 KiB".into());
            }
            let peer: sync_extend_transport::PeerIdentity = serde_json::from_slice(&bytes)?;
            open(&data_dir)?.approve_transport_peer(&peer, &expected_public_key.parse()?)?;
            print(
                &serde_json::json!({"paired_device": peer.device_id, "space_id": peer.space_id}),
            )?;
        }
        Command::ServeFiles {
            data_dir,
            peer_device,
            listen,
        } => {
            let mut local = open(&data_dir)?;
            let device = peer_device.parse()?;
            let peer = local.read_transport_peer(&device)?;
            let identity = local.transport_identity()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            shutdown::ready()?;
            print(&serde_json::json!({
                "listening": listener.local_address()?,
                "paired_device": device,
                "whole_space_convergence": false
            }))?;
            loop {
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    result = listener.accept(&identity, &peer) => {
                        match result {
                            Ok(mut connection) => {
                                if let Err(error) = local.serve_peer_file(&mut connection).await {
                                    eprintln!("syncd: file transfer refused: {error}");
                                } else if let Err(error) = connection.finish().await {
                                    eprintln!("syncd: file transfer finish failed: {error}");
                                }
                            }
                            Err(error) => eprintln!("syncd: unapproved connection refused: {error}"),
                        }
                    }
                }
            }
        }
        Command::PullFile {
            data_dir,
            peer_device,
            address,
            path,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let result = local
                .pull_peer_file(&mut connection, PortablePath::new(path)?)
                .await?;
            connection.finish().await?;
            print(&result)?;
        }
        Command::ServeOperations {
            data_dir,
            peer_device,
            listen,
        } => {
            let local = open(&data_dir)?;
            let device = peer_device.parse()?;
            let peer = local.read_transport_peer(&device)?;
            let identity = local.transport_identity()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            print(&serde_json::json!({
                "listening": listener.local_address()?,
                "paired_device": device,
                "own_origin_metadata_only": true,
                "whole_space_convergence": false
            }))?;
            loop {
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    result = listener.accept(&identity, &peer) => {
                        match result {
                            Ok(mut connection) => {
                                if let Err(error) = local.serve_peer_operations(&mut connection).await {
                                    eprintln!("syncd: operation metadata refused: {error}");
                                } else if let Err(error) = connection.finish().await {
                                    eprintln!("syncd: operation metadata finish failed: {error}");
                                }
                            }
                            Err(error) => eprintln!("syncd: unapproved connection refused: {error}"),
                        }
                    }
                }
            }
        }
        Command::PullOperations {
            data_dir,
            peer_device,
            address,
            after_sequence,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let result = local
                .pull_peer_operations(&mut connection, after_sequence)
                .await?;
            connection.finish().await?;
            print(&result)?;
        }
        Command::CausalFrontiers { data_dir } => {
            print(&open(&data_dir)?.causal_frontiers()?)?;
        }
        Command::ReplayRemoteOperation {
            data_dir,
            peer_device,
            signed_operation,
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(signed_operation)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("signed operation exceeds 16 MiB".into());
            }
            let signed = serde_json::from_slice(&bytes)?;
            let local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            print(&local.replay_signed_remote_operation(&peer, &signed)?)?;
        }
        #[cfg(windows)]
        Command::ApplyRemoteRename {
            data_dir,
            peer_device,
            signed_operation,
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(signed_operation)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("signed operation exceeds 16 MiB".into());
            }
            let signed = serde_json::from_slice(&bytes)?;
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            print(&local.apply_signed_remote_rename(&peer, &signed)?)?;
        }
        #[cfg(windows)]
        Command::RemoteRenames { data_dir } => {
            print(&open(&data_dir)?.remote_rename_receipts()?)?;
        }
        #[cfg(windows)]
        Command::RecoverRemoteRename {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.recover_remote_rename(&transaction.parse()?)?)?;
        }
        #[cfg(windows)]
        Command::ApplyRemoteDelete {
            data_dir,
            peer_device,
            signed_operation,
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(signed_operation)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("signed operation exceeds 16 MiB".into());
            }
            let signed = serde_json::from_slice(&bytes)?;
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            print(&local.apply_signed_remote_delete(&peer, &signed)?)?;
        }
        #[cfg(windows)]
        Command::RemoteDeletes { data_dir } => {
            print(&open(&data_dir)?.remote_delete_receipts()?)?;
        }
        #[cfg(windows)]
        Command::RecoverRemoteDelete {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.recover_remote_delete(&transaction.parse()?)?)?;
        }
        #[cfg(windows)]
        Command::ApplyRemoteReplace {
            data_dir,
            peer_device,
            signed_operation,
            source,
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(signed_operation)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("signed operation exceeds 16 MiB".into());
            }
            let signed = serde_json::from_slice(&bytes)?;
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            match source {
                Some(source) => {
                    print(&local.apply_signed_remote_replace_from_file(&peer, &signed, &source)?)?
                }
                None => print(&local.apply_signed_remote_replace(&peer, &signed)?)?,
            }
        }
        #[cfg(windows)]
        Command::RemoteReplaces { data_dir } => {
            print(&open(&data_dir)?.remote_replace_receipts()?)?;
        }
        #[cfg(windows)]
        Command::RecoverRemoteReplace {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.recover_remote_replace(&transaction.parse()?)?)?;
        }
        Command::PrepareConflictBranches {
            data_dir,
            signed_resolution,
        } => {
            let limits = sync_extend_core_model::conflict_resolution::ResolutionLimits::default();
            let mut bytes = Vec::new();
            std::fs::File::open(signed_resolution)?
                .take(limits.max_bytes as u64 + 1)
                .read_to_end(&mut bytes)?;
            let signed = sync_extend_transport::SignedFileResolution::from_slice(&bytes, limits)?;
            print(&open(&data_dir)?.prepare_signed_conflict_branches(&signed, limits)?)?;
        }
        Command::AdmitConflictResolution {
            data_dir,
            signed_resolution,
        } => {
            let limits = sync_extend_core_model::conflict_resolution::ResolutionLimits {
                max_bytes: 16 * 1024 * 1024,
                ..Default::default()
            };
            let mut bytes = Vec::new();
            std::fs::File::open(signed_resolution)?
                .take(limits.max_bytes as u64 + 1)
                .read_to_end(&mut bytes)?;
            let signed = sync_extend_transport::SignedFileResolution::from_slice(&bytes, limits)?;
            print(&open(&data_dir)?.admit_signed_file_resolution(&signed, limits)?)?;
        }
        Command::ConflictResolutions { data_dir } => {
            print(&open(&data_dir)?.conflict_resolution_admissions()?)?;
        }
        Command::ExchangeMetadata {
            data_dir,
            peer_device,
            address,
            rounds,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            local.scan()?;
            let mut connection = transport_budget
                .connect(&data_dir, address, &identity, &peer)
                .await?;
            let result = local
                .exchange_peer_metadata(&mut connection, rounds)
                .await?;
            connection.finish().await?;
            print(&result)?;
        }
        Command::ServeMetadata {
            data_dir,
            peer_device,
            listen,
            max_rounds,
        } => {
            let mut local = open(&data_dir)?;
            let device = peer_device.parse()?;
            let peer = local.read_transport_peer(&device)?;
            let identity = local.transport_identity()?;
            let listener = transport_budget.listener(&data_dir, listen, &identity, &peer)?;
            management::observe_local_space(&mut local);
            let mut preview_timer = tokio::time::interval(Duration::from_millis(100));
            preview_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            shutdown::ready()?;
            print(&serde_json::json!({
                "listening": listener.local_address()?,
                "paired_device": device,
                "max_rounds": max_rounds,
                "own_origin_metadata_only": true,
                "native_apply_enabled": false,
                "automatic_file_sync": false,
            }))?;
            loop {
                tokio::select! {
                    shutdown = shutdown::requested() => { shutdown?; break; }
                    _ = preview_timer.tick() => management::process_restore_preview(&mut local),
                    result = listener.accept(&identity, &peer) => {
                        match result {
                            Ok(mut connection) => {
                                let result = async {
                                    // Stable local scans author only native local changes.
                                    local.scan()?;
                                    management::observe_local_space(&mut local);
                                    local.serve_peer_metadata_cycle(&mut connection, max_rounds).await
                                }.await;
                                if let Err(error) = result {
                                    eprintln!("syncd: metadata cycle refused: {error}");
                                } else if let Err(error) = connection.finish().await {
                                    eprintln!("syncd: metadata cycle finish failed: {error}");
                                }
                            }
                            Err(error) => eprintln!("syncd: unapproved connection refused: {error}"),
                        }
                    }
                }
            }
        }
        Command::RunMetadata {
            data_dir,
            peer_device,
            address,
            rounds,
            interval_secs,
        } => {
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let identity = local.transport_identity()?;
            shutdown::ready()?;
            print(&serde_json::json!({
                "role": "metadata_client",
                "peer_device": peer.device_id,
                "address": address,
                "interval_secs": interval_secs,
                "rounds": rounds,
                "native_apply_enabled": false,
                "automatic_file_sync": false,
            }))?;
            let shutdown = shutdown::requested();
            tokio::pin!(shutdown);
            let mut preview_timer = tokio::time::interval(Duration::from_millis(100));
            preview_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            'metadata_attempts: loop {
                // A local safety failure stops this worker; only transport
                // failures retry. A settled native scan never applies remote rows.
                local = tokio::task::spawn_blocking(move || {
                    local.scan()?;
                    management::observe_local_space(&mut local);
                    Ok::<_, sync_extend_reconcile::ReconcileError>(local)
                })
                .await??;
                let cycle = async {
                    let mut connection = transport_budget
                        .connect(&data_dir, address, &identity, &peer)
                        .await?;
                    let receipt = local
                        .exchange_peer_metadata(&mut connection, rounds)
                        .await?;
                    connection.finish().await?;
                    Ok::<_, Box<dyn std::error::Error>>(receipt)
                };
                tokio::select! {
                    result = &mut shutdown => { result?; break; }
                    result = cycle => {
                        match result {
                            Ok(receipt) => print(&receipt)?,
                            Err(error) => {
                                if error.downcast_ref::<sync_extend_reconcile::ReconcileError>().is_some()
                                    || transport_budget::is_budget_failure(error.as_ref()) {
                                    return Err(error);
                                }
                                print(&serde_json::json!({
                                    "metadata_cycle_complete": false,
                                    "retry_after_secs": interval_secs,
                                    "error": error.to_string(),
                                    "durable_received_prefix_preserved": true,
                                    "native_apply_enabled": false,
                                    "automatic_file_sync": false,
                                }))?;
                            }
                        }
                    }
                }
                // Wait after each attempt; slow scans/peers never trigger
                // catch-up bursts or an unbounded busy-loop on offline devices.
                let retry_delay = tokio::time::sleep(Duration::from_secs(interval_secs));
                tokio::pin!(retry_delay);
                loop {
                    tokio::select! {
                        result = &mut shutdown => { result?; break 'metadata_attempts; }
                        _ = &mut retry_delay => break,
                        _ = preview_timer.tick() => management::process_restore_preview(&mut local),
                    }
                }
            }
        }
        Command::Init { data_dir, root } => {
            #[cfg(target_os = "linux")]
            if let Some(owner) = linux_owner.as_ref() {
                let local = owner.initialize(&data_dir, &root, limits.clone())?;
                print(&local.status()?)?;
                return Ok(());
            }
            let local = LocalSpace::initialize_with_limits(&data_dir, &root, limits.clone())?;
            print(&local.status()?)?;
        }
        Command::Scan { data_dir } => {
            print(&open(&data_dir)?.scan()?)?;
        }
        Command::Status { data_dir } => {
            print(&open(&data_dir)?.status()?)?;
        }
        #[cfg(target_os = "linux")]
        Command::LinuxNativeFinals { data_dir } => {
            print(&open(&data_dir)?.original_linux_native_finals()?)?;
        }
        #[cfg(target_os = "linux")]
        Command::CleanupLinuxNative {
            data_dir,
            transaction,
        } => {
            let owner = linux_owner
                .as_ref()
                .ok_or("explicit acquired Linux owner configuration is required")?;
            print(
                &open(&data_dir)?
                    .cleanup_original_linux_native(&owner.owner, &transaction.parse()?)?,
            )?;
        }
        Command::Diagnostics { data_dir } => {
            print(&open(&data_dir)?.diagnostics()?)?;
        }
        #[cfg(windows)]
        Command::RecoveredLocal { descriptor, action } => {
            recovery::run(&descriptor, action)?;
        }
        Command::StorageReport { data_dir } => {
            print(&open(&data_dir)?.storage_report()?)?;
        }
        Command::ReserveContent { data_dir, intent } => {
            let mut bytes = Vec::new();
            std::fs::File::open(intent)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("reservation intent exceeds 16 MiB".into());
            }
            let intent: sync_extend_reconcile::ReferenceReservationIntent =
                serde_json::from_slice(&bytes)?;
            print(&open(&data_dir)?.reserve_content(&intent)?)?;
        }
        Command::ReferenceReservations { data_dir } => {
            print(&open(&data_dir)?.reference_reservations()?)?;
        }
        Command::HandoffContent {
            data_dir,
            owner,
            snapshot,
        } => {
            print(&open(&data_dir)?.handoff_content(&owner.parse()?, &snapshot.parse()?)?)?;
        }
        Command::IngestReservedChunk {
            data_dir,
            owner,
            chunk,
            source,
        } => {
            print(&open(&data_dir)?.ingest_reserved_chunk(
                &owner.parse()?,
                &chunk.parse()?,
                &source,
            )?)?;
        }
        Command::MarkGcObject {
            data_dir,
            object,
            grace_secs,
        } => {
            print(&open(&data_dir)?.mark_gc_object(&object.parse()?, grace_secs)?)?;
        }
        Command::GcMarks { data_dir } => print(&open(&data_dir)?.gc_marks()?)?,
        Command::CancelGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.cancel_gc_mark(&mark.parse()?)?)?;
        }
        Command::RevalidateGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.revalidate_gc_mark(&mark.parse()?)?)?;
        }
        Command::PreflightGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.preflight_gc_mark(&mark.parse()?)?)?;
        }
        Command::AuthorizeGcMark {
            data_dir,
            mark,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.authorize_gc_mark(&mark.parse()?, ttl_secs)?)?;
        }
        Command::GcAuthorizations { data_dir } => print(&open(&data_dir)?.gc_authorizations()?)?,
        Command::AdmitGcExecution {
            data_dir,
            authorization,
        } => print(&open(&data_dir)?.admit_gc_execution(&authorization.parse()?)?)?,
        Command::GcExecutions { data_dir } => print(&open(&data_dir)?.gc_executions()?)?,
        Command::QuarantineGcExecution {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.quarantine_gc_execution(&execution.parse()?)?)?,
        Command::GcQuarantines { data_dir } => print(&open(&data_dir)?.gc_quarantines()?)?,
        Command::PrepareGcDisposal {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.prepare_gc_disposal(&execution.parse()?)?)?,
        Command::GcDisposals { data_dir } => print(&open(&data_dir)?.gc_disposals()?)?,
        Command::ExecuteGcDisposal {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.execute_gc_disposal(&execution.parse()?)?)?,
        Command::RestoreGcQuarantine {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.restore_gc_quarantine(&execution.parse()?)?)?,
        Command::AbortGcExecution {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.abort_gc_execution(&execution.parse()?)?)?,
        Command::RevokeGcAuthorization {
            data_dir,
            authorization,
        } => {
            print(&open(&data_dir)?.revoke_gc_authorization(&authorization.parse()?)?)?;
        }
        Command::CheckGcAuthorization {
            data_dir,
            authorization,
        } => {
            print(&open(&data_dir)?.check_gc_authorization(&authorization.parse()?)?)?;
        }
        Command::SnapshotAudit { data_dir } => print(&open(&data_dir)?.snapshot_audit()?)?,
        Command::PruneSnapshot {
            data_dir,
            snapshot,
            baseline,
            deleted_min_retention_days,
        } => {
            print(&open(&data_dir)?.prune_snapshot_with_minimum_days(
                &snapshot.parse()?,
                &baseline.parse()?,
                deleted_min_retention_days,
            )?)?;
        }
        Command::LockSnapshot { data_dir, snapshot } => {
            print(&open(&data_dir)?.lock_snapshot(&snapshot.parse()?)?)?;
        }
        Command::UnlockSnapshot { data_dir, snapshot } => {
            print(&open(&data_dir)?.unlock_snapshot(&snapshot.parse()?)?)?;
        }
        Command::RetentionReport {
            data_dir,
            history_snapshots,
            history_budget_bytes,
            deleted_min_retention_days,
        } => {
            let policy = HistoryPolicy {
                history_snapshots,
                history_budget_bytes,
                deleted_min_retention_days,
            };
            print(
                &ReadOnlyLocalSpace::open(&data_dir)?
                    .retention_report(policy, limits.max_storage_entries)?,
            )?;
        }
        Command::SetDeletionRetentionPolicy {
            data_dir,
            days,
            expected_revision,
        } => {
            print(&open(&data_dir)?.set_deletion_retention_policy(days, expected_revision)?)?;
        }
        Command::AcquireReadLease {
            data_dir,
            snapshot,
            path,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.acquire_read_lease(
                &snapshot.parse()?,
                &PortablePath::new(path)?,
                ttl_secs,
            )?)?;
        }
        Command::ReadLeases { data_dir } => print(&open(&data_dir)?.read_leases()?)?,
        Command::RenewReadLease {
            data_dir,
            lease,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.renew_read_lease(&lease.parse()?, ttl_secs)?)?;
        }
        Command::ReleaseReadLease { data_dir, lease } => {
            print(&open(&data_dir)?.release_read_lease(&lease.parse()?)?)?;
        }
        Command::RecoverReadLeases { data_dir } => print(&open(&data_dir)?.recover_read_leases()?)?,
        Command::ExportLeased {
            data_dir,
            lease,
            output,
        } => {
            print(&open(&data_dir)?.export_leased(&lease.parse()?, &output)?)?;
        }
        Command::PrepareOriginalDisposal {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.prepare_original_disposal(&transaction.parse()?)?)?;
        }
        Command::OriginalDisposals { data_dir } => {
            print(&open(&data_dir)?.original_disposals()?)?;
        }
        Command::ExecuteOriginalDisposal {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.execute_original_disposal(&transaction.parse()?)?)?;
        }
        Command::PrepareCleanup {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.prepare_cleanup(&transaction.parse()?)?)?;
        }
        Command::CleanupPlans { data_dir } => print(&open(&data_dir)?.cleanup_plans()?)?,
        Command::CancelCleanup {
            data_dir,
            transaction,
        } => {
            open(&data_dir)?.cancel_cleanup(&transaction.parse()?)?;
            print(&serde_json::json!({"cancelled": true, "worktree_modified": false}))?;
        }
        Command::ExecuteCleanup {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.execute_cleanup(&transaction.parse()?)?)?;
        }
        Command::RecoverCleanups { data_dir } => print(&open(&data_dir)?.recover_cleanups()?)?,
        Command::Manifest { data_dir } => {
            print(&ReadOnlyLocalSpace::open(&data_dir)?.manifest()?)?;
        }
        Command::Ops { data_dir } => {
            print(&ReadOnlyLocalSpace::open(&data_dir)?.operations()?)?;
        }
        Command::Verify { data_dir } => {
            let files = open(&data_dir)?.verify()?;
            print(&serde_json::json!({"verified_file_versions": files, "sqlite_integrity": "ok"}))?;
        }
        Command::Export {
            data_dir,
            path,
            output,
        } => {
            open(&data_dir)?.export_file(&PortablePath::new(path)?, &output)?;
            print(&serde_json::json!({"exported": true, "remote_backup_complete": false}))?;
        }
        Command::CheckConfig { config } => {
            let file = std::fs::File::open(config)?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err("configuration exceeds 1 MiB".into());
            }
            let config: Config = serde_json::from_slice(&bytes)?;
            config.validate()?;
            print(&serde_json::json!({"valid": true, "listener_started": false}))?;
        }
        Command::Publish {
            data_dir,
            source,
            path,
        } => {
            #[cfg(target_os = "linux")]
            if linux_owner.is_some() {
                return Err(
                    "explicit Linux Publish must complete on the original pre-runtime owner".into(),
                );
            }
            print(&open(&data_dir)?.publish_file(&source, PortablePath::new(path)?)?)?;
        }
        Command::Restore {
            data_dir,
            snapshot,
            path,
        } => {
            print(&open(&data_dir)?.restore_file(&snapshot.parse()?, PortablePath::new(path)?)?)?;
        }
        #[cfg(windows)]
        Command::PublishNative {
            data_dir,
            source,
            path,
        } => {
            print(&open(&data_dir)?.publish_native_file(&source, PortablePath::new(path)?)?)?;
        }
        #[cfg(windows)]
        Command::RecoverNative { data_dir } => {
            print(&open(&data_dir)?.recover_native_publications()?)?;
        }
        Command::SignOperation {
            data_dir,
            operation,
        } => {
            let local = open(&data_dir)?;
            let operation: sync_extend_core_model::OperationId = operation.parse()?;
            let original = local
                .operations()?
                .into_iter()
                .find(|op| op.op_id == operation)
                .ok_or("operation not found")?;
            print(&sync_extend_transport::SignedOperation::sign(
                &local.transport_identity()?,
                original,
            )?)?;
        }
        #[cfg(windows)]
        Command::ApplyRemotePut {
            data_dir,
            peer_device,
            signed_operation,
            source,
        } => {
            let file = std::fs::File::open(signed_operation)?;
            let mut bytes = Vec::new();
            file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("signed operation exceeds 16 MiB".into());
            }
            let signed: sync_extend_transport::SignedOperation = serde_json::from_slice(&bytes)?;
            let mut local = open(&data_dir)?;
            let peer = local.read_transport_peer(&peer_device.parse()?)?;
            let result = if let Some(source) = source {
                local.apply_signed_remote_put_from_file(&peer, &signed, &source)?
            } else {
                local.apply_signed_remote_put(&peer, &signed)?
            };
            print(&result)?;
        }
        Command::Recover { data_dir } => {
            print(&open(&data_dir)?.recover()?)?;
        }
        Command::Snapshots { data_dir } => {
            print(&open(&data_dir)?.snapshots()?)?;
        }
        Command::PrepareMutation {
            data_dir,
            snapshot,
            path,
            action,
        } => {
            let mut local = open(&data_dir)?;
            let snapshot = snapshot.parse()?;
            let path = PortablePath::new(path)?;
            let executor_available = cfg!(windows);
            let mutation = match action {
                PrepareAction::Replace { source } => {
                    local.prepare_replace(&snapshot, &path, &source)?
                }
                PrepareAction::Delete => local.prepare_delete(&snapshot, &path)?,
                PrepareAction::Move { destination } => {
                    local.prepare_move(&snapshot, &path, &PortablePath::new(destination)?)?
                }
            };
            print(&serde_json::json!({
                "mutation": mutation, "executor_available": executor_available,
                "worktree_modified": false, "remote_backup_complete": false,
            }))?;
        }
        Command::Mutations { data_dir } => print(&open(&data_dir)?.mutations()?)?,
        Command::CheckMutation {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.check_mutation(&transaction.parse()?)?)?;
        }
        Command::CancelMutation {
            data_dir,
            transaction,
        } => {
            open(&data_dir)?.cancel_mutation(&transaction.parse()?)?;
            print(&serde_json::json!({"cancelled": true, "worktree_modified": false}))?;
        }
        Command::ExecuteMutation {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.execute_mutation(&transaction.parse()?)?)?;
        }
        Command::RecoverMutations { data_dir } => print(&open(&data_dir)?.recover_mutations()?)?,
        Command::Run {
            data_dir,
            scan_interval_secs,
        } => {
            let mut local = open(&data_dir)?;
            let mut timer = tokio::time::interval(Duration::from_secs(scan_interval_secs));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut preview_timer = tokio::time::interval(Duration::from_millis(100));
            preview_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            shutdown::ready()?;
            management::resources_deferred();
            let shutdown = shutdown::requested();
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    result = &mut shutdown => { result?; break; }
                    _ = preview_timer.tick() => {
                        local = tokio::task::spawn_blocking(move || {
                            management::process_restore_preview(&mut local);
                            local
                        }).await?;
                    }
                    _ = timer.tick() => {
                        local = tokio::task::spawn_blocking(move || {
                            match local.scan() {
                                Ok(result) => {
                                    management::observe_local_space(&mut local);
                                    management::resources_ready();
                                    println!("{}", serde_json::to_string(&result).unwrap_or_default());
                                }
                                Err(error) => {
                                    management::resources_deferred();
                                    eprintln!("syncd: reconciliation deferred: {error}");
                                }
                            }
                            local
                        }).await?;
                    }
                }
            }
        }
    }
    Ok(())
}
