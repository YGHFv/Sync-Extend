//! Explicit per-process deployment roles; existing identities must be provisioned first.
use crate::{
    limits::LocalLimits, webdav::WebDavListener, DeviceId, ModelError, Result, SpaceId,
    FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

#[path = "deployment_json.rs"]
mod document_json;
pub use document_json::decode_deployment_document;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub format_version: u32,
    pub role: DeploymentRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_attempt_policy: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_attempt_budget_dir: Option<PathBuf>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scan_interval_secs: Option<u64>,
    },
    EasyTier {
        config: PathBuf,
        seconds: u64,
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
        if self
            .transport_attempt_policy
            .as_ref()
            .is_some_and(|value| !path(value))
            || self
                .transport_attempt_budget_dir
                .as_ref()
                .is_some_and(|value| !path(value))
            || self.transport_attempt_budget_dir.is_some()
                && self.transport_attempt_policy.is_none()
            || self.transport_attempt_policy.is_some()
                && !matches!(
                    self.role,
                    DeploymentRole::MetadataClient { .. }
                        | DeploymentRole::MetadataServer { .. }
                        | DeploymentRole::Storage { .. }
                )
        {
            return Err(ModelError::InvalidConfig(
                "explicit Sync application-frame policy/control directory",
            ));
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
            DeploymentRole::WebdavClient {
                gateway_config,
                scan_interval_secs,
            } => {
                path(gateway_config)
                    && scan_interval_secs.is_none_or(|interval| (1..=86_400).contains(&interval))
            }
            DeploymentRole::EasyTier { config, seconds } => {
                path(config) && (1..=86_400).contains(seconds)
            }
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
            DeploymentRole::EasyTier { .. } => "easy_tier",
        }
    }
}

/// The platform is an observed capture/runtime scope, not a migration grant.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPlatform {
    Windows,
    Linux,
}

/// Existing private host HTTPS grants remain exact when only paths are mapped.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLoopbackTlsConfig {
    pub allow_remote: bool,
    pub bind: std::net::SocketAddrV4,
    pub allowed_source: std::net::Ipv4Addr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl HostLoopbackTlsConfig {
    pub fn validate(&self, authority: SocketAddr, platform: DeploymentPlatform) -> Result<()> {
        if platform != DeploymentPlatform::Linux
            || !self.allow_remote
            || authority.ip() != std::net::Ipv4Addr::LOCALHOST
            || self.bind.port() == 0
            || !self.bind.ip().is_private()
            || !self.allowed_source.is_private()
            || self.bind.ip() == &self.allowed_source
            || !path(&self.certificate)
            || !path(&self.private_key)
            || self.certificate == self.private_key
        {
            return Err(ModelError::InvalidConfig(
                "explicit existing Linux private host HTTPS policy",
            ));
        }
        Ok(())
    }
}

/// An independently selected v2 loopback HTTPS endpoint.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopbackTlsConfig {
    pub format_version: u32,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl LoopbackTlsConfig {
    pub fn validate(&self, authority: SocketAddr) -> Result<()> {
        if self.format_version != 2
            || !authority.ip().is_loopback()
            || authority.port() == 0
            || !path(&self.certificate)
            || !path(&self.private_key)
            || self.certificate == self.private_key
        {
            return Err(ModelError::InvalidConfig(
                "explicit v2 loopback HTTPS certificate/key slots",
            ));
        }
        Ok(())
    }
}

/// Shared contract for the existing Windows collection limits.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentCollectionLimits {
    pub max_entries: usize,
    pub max_operations: usize,
    pub max_handles: usize,
    pub max_actions: usize,
    pub max_templates: usize,
    pub max_binding_json: u64,
    pub max_manifest_json: u64,
    pub max_receipt_json: u64,
    pub max_execution_json: u64,
    pub max_metadata_bytes: u64,
    pub max_retained_bytes: u64,
    pub max_native_bytes: u64,
    pub max_failure_body_bytes: usize,
}

impl DeploymentCollectionLimits {
    pub fn validate(&self, local: &LocalLimits) -> Result<()> {
        let ceiling = crate::tree_restore_history::MAX_TREE_HISTORY_BYTES;
        if self.max_entries == 0
            || self.max_entries > local.max_scan_entries
            || self.max_operations == 0
            || self.max_operations > local.max_storage_entries
            || self.max_handles == 0
            || self.max_handles > local.max_storage_entries
            || self.max_actions == 0
            || self.max_actions > local.max_storage_entries
            || self.max_templates == 0
            || self.max_templates > local.max_storage_entries
            || self.max_binding_json == 0
            || self.max_binding_json > ceiling
            || self.max_manifest_json == 0
            || self.max_manifest_json > ceiling
            || self.max_receipt_json == 0
            || self.max_receipt_json > ceiling
            || self.max_execution_json == 0
            || self.max_execution_json > ceiling
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > local.max_scan_bytes
            || self.max_metadata_bytes > ceiling
            || self.max_retained_bytes > local.max_staging_bytes
            || self.max_native_bytes > local.max_staging_bytes
            || self.max_failure_body_bytes == 0
            || self.max_failure_body_bytes > 4 * 1024 * 1024
        {
            return Err(ModelError::InvalidConfig(
                "explicit bounded deployment collection policy",
            ));
        }
        Ok(())
    }
}

/// The gateway document shared by deployment capture and the daemon.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentGatewayConfig {
    pub listener: WebDavListener,
    pub credentials: PathBuf,
    pub uploads: PathBuf,
    pub spaces: std::collections::BTreeMap<SpaceId, PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_loopback_tls: Option<HostLoopbackTlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_tls: Option<LoopbackTlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_limits: Option<DeploymentCollectionLimits>,
}

impl DeploymentGatewayConfig {
    pub fn parse_for_platform(bytes: &[u8], platform: DeploymentPlatform) -> Result<Self> {
        let value: serde_json::Value = decode_deployment_document(bytes, 65_536)?;
        // Linux historically rejects this Windows field even when it is null.
        if platform != DeploymentPlatform::Windows
            && value
                .as_object()
                .is_some_and(|object| object.contains_key("collection_limits"))
        {
            return Err(ModelError::InvalidConfig(
                "Windows collection policy is not a Linux gateway field",
            ));
        }
        let document: Self = serde_json::from_value(value)?;
        document.validate(platform)?;
        Ok(document)
    }

    pub fn validate(&self, platform: DeploymentPlatform) -> Result<()> {
        self.listener.validate()?;
        if !path(&self.credentials)
            || !path(&self.uploads)
            || self.credentials == self.uploads
            || self.spaces.len() > 64
            || self.spaces.values().any(|value| !path(value))
            || self
                .listener
                .exports
                .iter()
                .any(|export| !self.spaces.contains_key(&export.space_id))
            || self.host_loopback_tls.is_some() && self.listener_tls.is_some()
            || platform != DeploymentPlatform::Windows && self.collection_limits.is_some()
        {
            return Err(ModelError::InvalidConfig(
                "explicit complete gateway paths/TLS/platform scope",
            ));
        }
        if let Some(policy) = &self.host_loopback_tls {
            policy.validate(self.listener.address, platform)?;
        }
        if let Some(policy) = &self.listener_tls {
            policy.validate(self.listener.address)?;
        }
        Ok(())
    }

    pub fn tls_files(&self) -> Option<(&Path, &Path)> {
        match (&self.host_loopback_tls, &self.listener_tls) {
            (Some(policy), None) => Some((&policy.certificate, &policy.private_key)),
            (None, Some(policy)) => Some((&policy.certificate, &policy.private_key)),
            _ => None,
        }
    }
}
