//! Expand deployment configuration to one existing foreground command in the same process.
use super::{Cli, Command};
use std::path::{Component, Path};
use sync_extend_core_model::deployment::{
    decode_deployment_document, DeploymentConfig, DeploymentRole,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn load(path: &Path) -> Result<DeploymentConfig> {
    let bytes = super::config_file::read(path, 65_536)?;
    let config: DeploymentConfig = decode_deployment_document(&bytes, 65_536)?;
    config.validate()?;
    Ok(config)
}

/// Only describe a gateway config inside the same private deployment directory.
/// This does not open the gateway's credentials, uploads, worktree or service.
pub fn check(path: &Path, describe_webdav: bool) -> Result<serde_json::Value> {
    let config = load(path)?;
    if !describe_webdav {
        return Ok(serde_json::json!({
            "configuration_valid": true, "role": config.role_name(),
            "identity_created": false, "services_started": false,
        }));
    }
    let value = if let DeploymentRole::WebdavClient {
        gateway_config,
        scan_interval_secs,
    } = &config.role
    {
        let parent = path
            .parent()
            .ok_or("private deployment directory required")?;
        let relative = gateway_config
            .strip_prefix(parent)
            .map_err(|_| "WebDAV configuration must be inside the private deployment directory")?;
        if parent.parent().is_none()
            || relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("exact private WebDAV configuration path required".into());
        }
        let runtime = super::webdav::load(gateway_config)?;
        runtime.validate_polling(*scan_interval_secs)?;
        let listener = &runtime.listener;
        let mut summary = serde_json::json!({
            "enabled": listener.enabled,
            "exports": listener.exports.iter().map(|export| serde_json::json!({
                "name": export.name,
                "url": format!("{}://{}/{}/", runtime.scheme(), listener.address, export.name),
                "writable": export.writable,
            })).collect::<Vec<_>>(),
        });
        if let Some(interval) = scan_interval_secs {
            summary["scan_interval_secs"] = serde_json::json!(interval);
        }
        Some(summary)
    } else {
        None
    };
    Ok(serde_json::json!({ "format_version": 1, "webdav": value }))
}

pub fn prepare(cli: Cli) -> Result<(Cli, Option<super::management::ManagementGuard>)> {
    let Command::DeploymentRun { config } = &cli.command else {
        return Ok((cli, None));
    };
    let config = load(config)?;
    let transport_attempt_policy = super::transport_budget::merge_path(
        cli.transport_attempt_policy.clone(),
        config.transport_attempt_policy.clone(),
    )?;
    let transport_attempt_budget_dir = super::transport_budget::merge_path(
        cli.transport_attempt_budget_dir.clone(),
        config.transport_attempt_budget_dir.clone(),
    )?;
    // Conflict/role/root validation precedes the management listener thread too.
    super::transport_budget::preflight(&cli)?;
    let management_path = config.management.clone();
    let role_name = config.role_name();
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
        DeploymentRole::WebdavClient {
            gateway_config,
            scan_interval_secs,
        } => Command::WebdavServe {
            config: gateway_config,
            scan_interval_secs,
        },
        DeploymentRole::EasyTier { config, seconds } => Command::EasytierRun { config, seconds },
    };
    let expanded = Cli {
        limits: cli.limits,
        transport_attempt_policy,
        transport_attempt_budget_dir,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        control_directory: cli.control_directory,
        #[cfg(target_os = "linux")]
        linux_namespace_config: cli.linux_namespace_config,
        command,
    };
    super::transport_budget::preflight(&expanded)?;
    let management = management_path
        .as_ref()
        .map(|path| super::management::start(path, role_name))
        .transpose()?;
    Ok((expanded, management))
}
