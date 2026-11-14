//! Expand deployment configuration to one existing foreground command in the same process.
use super::{Cli, Command};
use std::path::Path;
use sync_extend_core_model::deployment::{DeploymentConfig, DeploymentRole};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn load(path: &Path) -> Result<DeploymentConfig> {
    let bytes = super::config_file::read(path, 65_536)?;
    let config: DeploymentConfig = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

pub fn prepare(cli: Cli) -> Result<(Cli, Option<super::management::ManagementGuard>)> {
    let Command::DeploymentRun { config } = &cli.command else {
        return Ok((cli, None));
    };
    let config = load(config)?;
    let management = config
        .management
        .as_ref()
        .map(|path| super::management::start(path, config.role_name()))
        .transpose()?;
    let command = match config.role {
        DeploymentRole::LocalPolling {
            data_dir,
            scan_interval_secs,
        } => Command::Run {
            data_dir,
            scan_interval_secs,
        },
        DeploymentRole::MetadataClient {
            data_dir,
            peer_device,
            address,
            rounds,
            interval_secs,
        } => Command::RunMetadata {
            data_dir,
            peer_device: peer_device.to_string(),
            address,
            rounds: u32::from(rounds),
            interval_secs,
        },
        DeploymentRole::MetadataServer {
            data_dir,
            peer_device,
            listen,
            max_rounds,
        } => Command::ServeMetadata {
            data_dir,
            peer_device: peer_device.to_string(),
            listen,
            max_rounds: u32::from(max_rounds),
        },
        DeploymentRole::Storage {
            config,
            forwarder,
            max_sessions,
            session_timeout_secs,
            between_sessions_secs,
        } => Command::StorageRun {
            config,
            forwarder,
            max_sessions,
            session_timeout_secs,
            between_sessions_secs,
        },
        DeploymentRole::WebdavClient { gateway_config } => Command::WebdavServe {
            config: gateway_config,
        },
    };
    Ok((
        Cli {
            limits: cli.limits,
            command,
        },
        management,
    ))
}
