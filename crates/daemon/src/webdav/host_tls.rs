//! Explicit HTTPS publication through one private IPv4 gateway.
use rustls::ServerConfig;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use sync_extend_core_model::deployment::{
    DeploymentPlatform, HostLoopbackTlsConfig, LoopbackTlsConfig,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub(super) struct HostLoopbackTls(pub(super) HostLoopbackTlsConfig);

impl std::ops::Deref for HostLoopbackTls {
    type Target = HostLoopbackTlsConfig;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HostLoopbackTls {
    pub(super) fn validate(&self, authority: SocketAddr) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err("the existing host HTTPS policy requires Linux".into());
        }
        self.0.validate(authority, DeploymentPlatform::Linux)?;
        Ok(())
    }

    pub(super) fn permits(&self, ip: IpAddr) -> bool {
        ip == self.allowed_source
    }

    pub(super) fn server_config(&self) -> Result<Arc<ServerConfig>> {
        const MAX_PEM_BYTES: usize = 65_536;
        let bytes = crate::config_file::read(&self.certificate, MAX_PEM_BYTES)?;
        let key = crate::config_file::read(&self.private_key, MAX_PEM_BYTES)?;
        Ok(sync_extend_transport::deployment_server_config(
            &bytes, &key,
        )?)
    }
}

pub(super) fn loopback_server_config(
    policy: &LoopbackTlsConfig,
    authority: SocketAddr,
) -> Result<Arc<ServerConfig>> {
    policy.validate(authority)?;
    let certificate = crate::config_file::read(&policy.certificate, 65_536)?;
    let key = crate::config_file::read(&policy.private_key, 65_536)?;
    Ok(sync_extend_transport::deployment_server_config(
        &certificate,
        &key,
    )?)
}
