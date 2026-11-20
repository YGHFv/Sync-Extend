//! Local gateway configuration and authentication checks without granting write access.
use super::{load, Credentials};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{net::TcpListener, sync::Arc};
use sync_extend_core_model::webdav::WebDavListener;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn check(path: &Path) -> Result<Value> {
    let runtime = load(path)?;
    let listener = &runtime.listener;
    if listener.enabled {
        Credentials::load(&runtime.credentials, listener)?;
        if let Some(policy) = &runtime.host_loopback_tls {
            policy.server_config()?;
        }
    }
    Ok(json!({
        "configuration_valid": true, "enabled": listener.enabled,
        "address": listener.address, "listener_id": listener.listener_id,
        "scheme": runtime.scheme(),
        "credential_file_checked": listener.enabled,
        "accounts": listener.accounts, "exports": listener.exports,
    }))
}

pub fn test_connection(path: &Path, username: &str, export: &str) -> Result<Value> {
    let runtime = load(path)?;
    if runtime.host_loopback_tls.is_some() {
        return Err("test the HTTPS export from the host with its trusted certificate".into());
    }
    let credentials = Credentials::load(&runtime.credentials, &runtime.listener)?;
    test_export(&runtime.listener, &credentials, username, export, 5)?;
    Ok(json!({
        "authenticated": true, "export_accessible": true,
        "url": format!("http://{}/{export}/", runtime.listener.address),
        "username": username, "export": export, "remote_backup_complete": false,
    }))
}

fn test_export(
    listener: &WebDavListener,
    credentials: &Credentials,
    username: &str,
    export: &str,
    max_timeout_secs: u64,
) -> Result<()> {
    let target = format!("/{export}/");
    let authorized = listener.authorize(username, &target, false)?;
    // Probe exactly the selected export root and never accept an arbitrary URL.
    if !authorized.export_root || authorized.export_name != export {
        return Err("exact configured DAV export required".into());
    }
    let password = credentials
        .password(username)
        .ok_or("unknown DAV account")?;
    let timeout = Duration::from_secs(listener.request_timeout_secs.min(max_timeout_secs));
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&listener.address, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    write!(stream, "OPTIONS {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        listener.address, encode_base64(format!("{username}:{password}").as_bytes()))?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || response.len() >= 4096 {
            return Err("DAV connection test exceeded its response bound".into());
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    let mut lines = std::str::from_utf8(&response)?.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") || !lines.any(|line| line == "DAV: 1, 2") {
        return Err("DAV listener did not authorize the selected export".into());
    }
    Ok(())
}

/// A same-owner probe uses the running gateway's credentials and keeps its
/// actual bound socket alive so a stale configuration cannot target a new owner.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct GatewayProbe {
    bound: Arc<TcpListener>,
    config: WebDavListener,
    credentials: Arc<Credentials>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl GatewayProbe {
    pub fn new(
        bound: Arc<TcpListener>,
        config: WebDavListener,
        credentials: Arc<Credentials>,
    ) -> Self {
        Self {
            bound,
            config,
            credentials,
        }
    }

    pub fn test(&self, export: &str) -> Result<String> {
        if self.bound.local_addr()? != self.config.address {
            return Err("live DAV listener authority differs".into());
        }
        let account = self
            .config
            .accounts
            .iter()
            .find(|account| account.exports.contains(export))
            .ok_or("unknown or ungranted live DAV export")?;
        test_export(
            &self.config,
            &self.credentials,
            &account.username,
            export,
            2,
        )?;
        Ok(format!("http://{}/{export}/", self.config.address))
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[(a >> 2) as usize]));
        encoded.push(char::from(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize]));
        encoded.push(if chunk.len() >= 2 {
            char::from(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() == 3 {
            char::from(ALPHABET[(c & 63) as usize])
        } else {
            '='
        });
    }
    encoded
}
