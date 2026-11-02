use crate::{ModelError, Result, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format_version: u32,
    pub data_dir: PathBuf,
    pub worktree: Option<PathBuf>,
    #[serde(default)]
    pub history: HistoryPolicy,
    #[serde(default)]
    pub webdav: WebDavConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryPolicy {
    pub history_snapshots: u32,
    pub history_budget_bytes: u64,
    pub deleted_min_retention_days: u32,
}

impl Default for HistoryPolicy {
    fn default() -> Self {
        Self {
            history_snapshots: 3,
            history_budget_bytes: 10 * 1024 * 1024 * 1024,
            deleted_min_retention_days: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebDavConfig {
    pub enabled: bool,
    pub bind: IpAddr,
    pub port: u16,
    pub auth_required: bool,
    pub allow_remote: bool,
    pub credential_ref: Option<String>,
    pub exports: Vec<String>,
    pub tls_certificate: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub allowed_sources: Vec<String>,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1".parse().expect("loopback literal"),
            port: 17840,
            auth_required: true,
            allow_remote: false,
            credential_ref: None,
            exports: Vec::new(),
            tls_certificate: None,
            tls_key: None,
            allowed_sources: Vec::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || !self.data_dir.is_absolute()
            || self
                .worktree
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
        {
            return Err(ModelError::InvalidConfig(
                "unsupported format or non-absolute root",
            ));
        }
        let w = &self.webdav;
        if !w.auth_required || w.port == 0 || (!w.allow_remote && !w.bind.is_loopback()) {
            return Err(ModelError::InvalidConfig("unsafe WebDAV listener"));
        }
        if w.enabled
            && (self.worktree.is_none()
                || w.exports.is_empty()
                || w.credential_ref
                    .as_ref()
                    .is_none_or(|s| s.trim().is_empty()))
        {
            return Err(ModelError::InvalidConfig(
                "WebDAV requires a client root, credentials and explicit exports",
            ));
        }
        if w.allow_remote
            && (w.tls_certificate.is_none() || w.tls_key.is_none() || w.allowed_sources.is_empty())
        {
            return Err(ModelError::InvalidConfig(
                "remote WebDAV requires TLS and source restrictions",
            ));
        }
        Ok(())
    }
}
