//! Explicit HTTPS publication through one private IPv4 gateway.
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostLoopbackTls {
    allow_remote: bool,
    pub(super) bind: SocketAddrV4,
    allowed_source: Ipv4Addr,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl HostLoopbackTls {
    pub(super) fn validate(&self, authority: SocketAddr) -> Result<()> {
        if !cfg!(target_os = "linux")
            || !self.allow_remote
            || authority.ip() != Ipv4Addr::LOCALHOST
            || self.bind.port() == 0
            || !self.bind.ip().is_private()
            || !self.allowed_source.is_private()
            || self.bind.ip() == &self.allowed_source
            || !self.certificate.is_absolute()
            || !self.private_key.is_absolute()
            || self.certificate == self.private_key
        {
            return Err(
                "host WebDAV HTTPS requires Linux, explicit remote opt-in, IPv4 loopback authority, one private bind and a distinct private gateway, and separate absolute TLS files"
                    .into(),
            );
        }
        Ok(())
    }

    pub(super) fn permits(&self, ip: IpAddr) -> bool {
        ip == self.allowed_source
    }

    pub(super) fn server_config(&self) -> Result<Arc<ServerConfig>> {
        const MAX_PEM_BYTES: usize = 65_536;
        let bytes = crate::config_file::read(&self.certificate, MAX_PEM_BYTES)?;
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .take(9)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !(1..=8).contains(&certificates.len()) {
            return Err("WebDAV TLS requires one to eight PEM certificates".into());
        }
        let key = crate::config_file::read(&self.private_key, MAX_PEM_BYTES)?;
        let mut keys = PrivateKeyDer::pem_slice_iter(&key);
        let private_key = keys.next().transpose()?.ok_or("WebDAV TLS key absent")?;
        if keys.next().is_some() {
            return Err("WebDAV TLS requires exactly one private key".into());
        }
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}
