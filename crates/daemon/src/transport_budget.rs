//! One explicit invocation-wide application ledger; no unbudgeted peer fallback.
use super::{Cli, Command};
use std::{
    io::Write,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use sync_extend_core_model::{
    deployment::{DeploymentConfig, DeploymentRole},
    storage_node::StorageNodeConfig,
};
use sync_extend_reconcile::{LocalSpace, StorageNode};
use sync_extend_transport::{
    ApplicationBudget, Connection, Listener, PeerIdentity, SignedTransportAttemptPolicy,
    TransportAttemptPolicy, TransportError, TransportIdentity,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Sync,
    Sign,
    Init,
    Status,
    Unselected,
}

pub(crate) struct Selection {
    mode: Mode,
    data_root: Option<PathBuf>,
    control_root: Option<PathBuf>,
    signed: Option<SignedTransportAttemptPolicy>,
    unsigned: Option<TransportAttemptPolicy>,
    worker: Mutex<Option<Arc<ApplicationBudget>>>,
}

pub(crate) fn merge_path(cli: Option<PathBuf>, config: Option<PathBuf>) -> Result<Option<PathBuf>> {
    match (cli, config) {
        (Some(cli), Some(config)) if cli != config => {
            Err("CLI and deployment application-budget paths conflict".into())
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn exact_path(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .to_str()
            .is_some_and(|value| value.len() <= 4096 && !value.contains('\0'))
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

fn explicit_data_root(
    data_dir: &Option<PathBuf>,
    storage_config: &Option<PathBuf>,
) -> Result<PathBuf> {
    match (data_dir, storage_config) {
        (Some(data), None) => Ok(data.clone()),
        (None, Some(config)) => Ok(super::storage::load::<StorageNodeConfig>(config)?.data_dir),
        _ => Err("select exactly one explicit existing --data-dir or --storage-config".into()),
    }
}

fn deployment_data_root(config: &DeploymentConfig) -> Result<Option<PathBuf>> {
    match &config.role {
        DeploymentRole::MetadataClient { data_dir, .. }
        | DeploymentRole::MetadataServer { data_dir, .. } => Ok(Some(data_dir.clone())),
        DeploymentRole::Storage { config, .. } => Ok(Some(
            super::storage::load::<StorageNodeConfig>(config)?.data_dir,
        )),
        _ => Ok(None),
    }
}

fn command_data_root(command: &Command) -> Result<Option<PathBuf>> {
    match command {
        Command::ServeFiles { data_dir, .. }
        | Command::PullFile { data_dir, .. }
        | Command::ServeOperations { data_dir, .. }
        | Command::PullOperations { data_dir, .. }
        | Command::ExchangeMetadata { data_dir, .. }
        | Command::ServeMetadata { data_dir, .. }
        | Command::RunMetadata { data_dir, .. }
        | Command::StoragePush { data_dir, .. }
        | Command::StorageClientPull { data_dir, .. } => Ok(Some(data_dir.clone())),
        #[cfg(windows)]
        Command::RunOriginalCycle { data_dir, .. }
        | Command::ServeOriginalCycle { data_dir, .. }
        | Command::ExchangeOriginalCycle { data_dir, .. }
        | Command::ServeOriginalConflict { data_dir, .. }
        | Command::PullOriginalConflict { data_dir, .. }
        | Command::RunOriginal { data_dir, .. }
        | Command::ServeOriginal { data_dir, .. }
        | Command::PullOriginal { data_dir, .. } => Ok(Some(data_dir.clone())),
        Command::StorageRun { config, .. }
        | Command::StorageServe { config, .. }
        | Command::StoragePull { config, .. } => Ok(Some(
            super::storage::load::<StorageNodeConfig>(config)?.data_dir,
        )),
        Command::TransportAttemptPolicySign {
            data_dir,
            storage_config,
            ..
        }
        | Command::TransportAttemptBudgetInit {
            data_dir,
            storage_config,
        }
        | Command::TransportAttemptBudgetStatus {
            data_dir,
            storage_config,
        } => Ok(Some(explicit_data_root(data_dir, storage_config)?)),
        _ => Ok(None),
    }
}

impl Selection {
    pub(crate) fn from_cli(cli: &Cli) -> Result<Self> {
        // Windows ordinary readonly is unsupported before policy/config/root IO.
        if matches!(cli.command, Command::TransportAttemptBudgetStatus { .. }) {
            ApplicationBudget::require_readonly_platform()?;
        }
        let mut policy_path = cli.transport_attempt_policy.clone();
        let mut control_root = cli.transport_attempt_budget_dir.clone();
        let data_root = match &cli.command {
            Command::DeploymentRun { config } => {
                let config = super::deployment::load(config)?;
                policy_path = merge_path(policy_path, config.transport_attempt_policy.clone())?;
                control_root =
                    merge_path(control_root, config.transport_attempt_budget_dir.clone())?;
                deployment_data_root(&config)?
            }
            #[cfg(windows)]
            Command::WindowsService { config, .. } => {
                let config = super::deployment::load(config)?;
                policy_path = merge_path(policy_path, config.transport_attempt_policy.clone())?;
                control_root =
                    merge_path(control_root, config.transport_attempt_budget_dir.clone())?;
                deployment_data_root(&config)?
            }
            command => command_data_root(command)?,
        };
        let mode = match &cli.command {
            Command::TransportAttemptPolicySign { .. } => Mode::Sign,
            Command::TransportAttemptBudgetInit { .. } => Mode::Init,
            Command::TransportAttemptBudgetStatus { .. } => Mode::Status,
            _ if policy_path.is_some() => Mode::Sync,
            _ => Mode::Unselected,
        };
        if mode == Mode::Sign && policy_path.is_some() {
            return Err("policy-sign takes one unsigned --policy; a selected signed runtime policy conflicts".into());
        }
        if control_root.is_some() && policy_path.is_none() && mode != Mode::Sign {
            return Err(
                "--transport-attempt-budget-dir requires its explicit signed policy".into(),
            );
        }
        if matches!(mode, Mode::Init | Mode::Status) && policy_path.is_none() {
            return Err(
                "application budget init/status requires --transport-attempt-policy".into(),
            );
        }
        if (policy_path.is_some() || control_root.is_some() || mode == Mode::Sign)
            && data_root.is_none()
        {
            return Err(
                "application-frame policy is only supported by explicit Sync QUIC roles".into(),
            );
        }
        if data_root.as_ref().is_some_and(|path| !exact_path(path))
            || policy_path.as_ref().is_some_and(|path| !exact_path(path))
            || control_root.as_ref().is_some_and(|path| !exact_path(path))
        {
            return Err("application policy requires exact absolute selected paths".into());
        }
        if policy_path.is_some() || mode == Mode::Sign {
            // The command's data root is the only default input. Never derive a
            // writable root from the pathname or fields of an untrusted policy.
            control_root = Some(
                control_root.unwrap_or(
                    data_root
                        .clone()
                        .ok_or("explicit Sync data root required")?,
                ),
            );
        }
        let mut signed = None;
        let mut unsigned = None;
        if let Some(path) = policy_path {
            let value: SignedTransportAttemptPolicy =
                serde_json::from_slice(&super::config_file::read(&path, 69_632)?)?;
            value.verify(
                data_root.as_deref().ok_or("selected data root absent")?,
                control_root
                    .as_deref()
                    .ok_or("selected control root absent")?,
            )?;
            signed = Some(value);
        }
        if let Command::TransportAttemptPolicySign { policy, output, .. } = &cli.command {
            if !exact_path(output) {
                return Err(
                    "signed application-policy output requires an exact absolute path".into(),
                );
            }
            let value: TransportAttemptPolicy =
                serde_json::from_slice(&super::config_file::read(policy, 65_536)?)?;
            value.validate(
                data_root.as_deref().ok_or("sign data root absent")?,
                control_root.as_deref().ok_or("sign control root absent")?,
            )?;
            unsigned = Some(value);
        }
        #[cfg(target_os = "linux")]
        if cli.linux_namespace_config.is_some()
            && signed.is_some()
            && control_root
                .as_ref()
                .zip(data_root.as_ref())
                .is_some_and(|(control, data)| control.starts_with(data))
        {
            return Err("owned Linux metadata requires an independent explicit application control directory".into());
        }
        Ok(Self {
            mode,
            data_root,
            control_root,
            signed,
            unsigned,
            worker: Mutex::new(None),
        })
    }

    pub(crate) fn startup_check(&self) -> Result<()> {
        if let Some(signed) = &self.signed {
            ApplicationBudget::validate_roots(
                signed,
                self.data_root
                    .as_deref()
                    .ok_or("startup data root absent")?,
                self.control_root
                    .as_deref()
                    .ok_or("startup control root absent")?,
            )?;
        } else if self.mode == Mode::Unselected {
            if let Some(data) = &self.data_root {
                ApplicationBudget::require_unselected_ledger_absent(data)?;
            }
        }
        Ok(())
    }

    fn budget(
        &self,
        data_root: &Path,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Option<Arc<ApplicationBudget>>> {
        let Some(signed) = &self.signed else {
            ApplicationBudget::require_unselected_ledger_absent(data_root)?;
            return Ok(None);
        };
        if self.mode != Mode::Sync
            || self.data_root.as_deref() != Some(data_root)
            || &signed.policy.owner != identity.peer_identity()
            || &signed.policy.approved_peer != peer
        {
            return Err(
                "selected application budget refuses another owner/root/approved peer".into(),
            );
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| "application worker selection poisoned")?;
        if worker.is_none() {
            *worker = Some(ApplicationBudget::open(
                signed.clone(),
                data_root,
                self.control_root
                    .as_deref()
                    .ok_or("explicit control root absent")?,
            )?);
        }
        Ok(worker.clone())
    }

    pub(crate) fn listener(
        &self,
        data_root: &Path,
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> sync_extend_transport::Result<Listener> {
        Listener::bind_with_budget(
            address,
            identity,
            peer,
            self.budget(data_root, identity, peer)
                .map_err(|error| TransportError::Budget(error.to_string()))?,
        )
    }

    pub(crate) async fn connect(
        &self,
        data_root: &Path,
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> sync_extend_transport::Result<Connection> {
        Connection::connect_with_budget(
            address,
            identity,
            peer,
            self.budget(data_root, identity, peer)
                .map_err(|error| TransportError::Budget(error.to_string()))?,
        )
        .await
    }

    fn existing_identity(&self, storage_config: Option<&Path>) -> Result<TransportIdentity> {
        let peer = if let Some(signed) = &self.signed {
            &signed.policy.approved_peer
        } else {
            &self
                .unsigned
                .as_ref()
                .ok_or("unsigned policy absent")?
                .approved_peer
        };
        if let Some(path) = storage_config {
            let config: StorageNodeConfig = super::storage::load(path)?;
            if self.data_root.as_ref() != Some(&config.data_dir) {
                return Err("storage policy uses another independently selected data root".into());
            }
            let node = StorageNode::open(config)?;
            node.verify_forwarding_peer(peer)?;
            Ok(node.transport_identity()?)
        } else {
            let local = LocalSpace::open(
                self.data_root
                    .as_deref()
                    .ok_or("local policy data root absent")?,
            )?;
            if local.read_transport_peer(&peer.device_id)? != *peer {
                return Err("policy peer is not the independently paired exact identity".into());
            }
            Ok(local.transport_identity()?)
        }
    }

    pub(crate) fn sign(&self, storage_config: Option<&Path>, output: &Path) -> Result<()> {
        if self.mode != Mode::Sign {
            return Err("application policy-sign selection differs".into());
        }
        let identity = self.existing_identity(storage_config)?;
        let signed = SignedTransportAttemptPolicy::sign(
            &identity,
            self.data_root.as_deref().ok_or("sign data root absent")?,
            self.control_root
                .as_deref()
                .ok_or("sign control root absent")?,
            self.unsigned.clone().ok_or("unsigned policy absent")?,
        )?;
        let bytes = serde_json::to_vec(&signed)?;
        if bytes.len() > 69_632 {
            return Err("signed application policy bound".into());
        }
        #[cfg(windows)]
        {
            let parent = sync_extend_platform_fs::LockedDirectory::open(
                output.parent().ok_or("policy output parent absent")?,
            )?;
            let mut created = parent.create_new_current_user_file(
                output
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or("policy output filename absent")?,
            )?;
            created.original_creation()?.verify()?;
            created.writer().write_all(&bytes)?;
            created.writer().sync_all()?;
            created.seal_original()?.verify_original()?;
        }
        #[cfg(not(windows))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            for ancestor in output
                .parent()
                .ok_or("policy output parent absent")?
                .ancestors()
            {
                if std::fs::symlink_metadata(ancestor)?
                    .file_type()
                    .is_symlink()
                {
                    return Err("signed policy output symlink ancestor refused".into());
                }
            }
            let mut file = options.open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(output.parent().ok_or("policy output parent absent")?)?
                .sync_all()?;
        }
        super::print(&serde_json::json!({
            "signed_policy": output, "policy_fingerprint": signed.fingerprint()?,
            "owner": signed.policy.owner.device_id, "approved_peer": signed.policy.approved_peer.device_id,
            "ledger_created": false, "meter_unit": signed.policy.meter_unit,
        }))
    }

    pub(crate) fn init(&self, storage_config: Option<&Path>) -> Result<()> {
        if self.mode != Mode::Init {
            return Err("application init selection differs".into());
        }
        let signed = self.signed.clone().ok_or("selected signed policy absent")?;
        if self.existing_identity(storage_config)?.peer_identity() != &signed.policy.owner {
            return Err("application init owner differs from the preprovisioned identity".into());
        }
        let budget = ApplicationBudget::init(
            signed,
            self.data_root.as_deref().ok_or("init data root absent")?,
            self.control_root
                .as_deref()
                .ok_or("init control root absent")?,
        )?;
        super::print(&budget.status()?)
    }

    pub(crate) fn status(&self) -> Result<()> {
        ApplicationBudget::require_readonly_platform()?;
        if self.mode != Mode::Status {
            return Err("application readonly selection differs".into());
        }
        super::print(&ApplicationBudget::read_status(
            self.signed.clone().ok_or("selected signed policy absent")?,
            self.data_root.as_deref().ok_or("status data root absent")?,
            self.control_root
                .as_deref()
                .ok_or("status control root absent")?,
        )?)
    }
}

pub(crate) fn preflight(cli: &Cli) -> Result<()> {
    Selection::from_cli(cli)?.startup_check()
}

pub(crate) fn is_budget_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<TransportError>()
        .is_some_and(|error| matches!(error, TransportError::Budget(_)))
}
