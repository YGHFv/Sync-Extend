//! Separate local lifecycle observations; credentials confer no synchronization grant.
use crate::{ModelError, Result, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Component, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenProtection {
    #[default]
    Plain,
    WindowsUser,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    pub format_version: u32,
    pub address: SocketAddr,
    pub token_file: PathBuf,
    #[serde(default)]
    pub token_protection: TokenProtection,
    pub request_timeout_secs: u64,
    pub max_connections: u64,
}

impl ManagementConfig {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || !self.address.ip().is_loopback()
            || self.address.port() == 0
            || !self.token_file.is_absolute()
            || self.token_file.parent().is_none()
            || self
                .token_file
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || !(1..=5).contains(&self.request_timeout_secs)
            || !(1..=1_000_000).contains(&self.max_connections)
        {
            return Err(ModelError::InvalidConfig(
                "bounded authenticated local management",
            ));
        }
        Ok(())
    }
}
