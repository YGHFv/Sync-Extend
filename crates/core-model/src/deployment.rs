//! Explicit per-process deployment roles; existing identities must be provisioned first.
use crate::{DeviceId, ModelError, Result, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub format_version: u32,
    pub role: DeploymentRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeploymentRole {
    LocalPolling {
        data_dir: PathBuf,
        scan_interval_secs: u64,
    },
    MetadataClient {
        data_dir: PathBuf,
        peer_device: DeviceId,
        address: SocketAddr,
        rounds: u16,
        interval_secs: u64,
    },
    MetadataServer {
        data_dir: PathBuf,
        peer_device: DeviceId,
        listen: SocketAddr,
        max_rounds: u16,
    },
    Storage {
        config: PathBuf,
        forwarder: PathBuf,
        max_sessions: u32,
        session_timeout_secs: u64,
        between_sessions_secs: u64,
    },
    WebdavClient {
        gateway_config: PathBuf,
    },
}

fn path(value: &Path) -> bool {
    value.is_absolute()
        && value.parent().is_some()
        && !value
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}
impl DeploymentConfig {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(ModelError::InvalidConfig("deployment format version"));
        }
        if self.management.as_ref().is_some_and(|value| !path(value)) {
            return Err(ModelError::InvalidConfig("deployment management path"));
        }
        let valid = match &self.role {
            DeploymentRole::LocalPolling {
                data_dir,
                scan_interval_secs,
            } => path(data_dir) && (1..=86_400).contains(scan_interval_secs),
            DeploymentRole::MetadataClient {
                data_dir,
                address,
                rounds,
                interval_secs,
                ..
            } => {
                path(data_dir)
                    && address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast()
                    && (1..=64).contains(rounds)
                    && (1..=86_400).contains(interval_secs)
            }
            DeploymentRole::MetadataServer {
                data_dir,
                listen,
                max_rounds,
                ..
            } => {
                path(data_dir)
                    && listen.port() != 0
                    && !listen.ip().is_multicast()
                    && (1..=64).contains(max_rounds)
            }
            DeploymentRole::Storage {
                config,
                forwarder,
                max_sessions,
                session_timeout_secs,
                between_sessions_secs,
            } => {
                path(config)
                    && path(forwarder)
                    && config != forwarder
                    && (1..=1_000_000).contains(max_sessions)
                    && (1..=86_400).contains(session_timeout_secs)
                    && (1..=3_600).contains(between_sessions_secs)
            }
            DeploymentRole::WebdavClient { gateway_config } => path(gateway_config),
        };
        if !valid {
            return Err(ModelError::InvalidConfig(
                "explicit bounded deployment role",
            ));
        }
        Ok(())
    }

    pub fn role_name(&self) -> &'static str {
        match self.role {
            DeploymentRole::LocalPolling { .. } => "local_polling",
            DeploymentRole::MetadataClient { .. } => "metadata_client",
            DeploymentRole::MetadataServer { .. } => "metadata_server",
            DeploymentRole::Storage { .. } => "storage",
            DeploymentRole::WebdavClient { .. } => "webdav_client",
        }
    }
}
