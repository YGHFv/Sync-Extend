//! Pinned sidecar configuration and observations; overlay IDs are not device identities.
use crate::{ContentId, EntryId, ModelError, Result, EASYTIER_VERSION};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EasyTierConfig {
    pub format_version: u32,
    pub enabled: bool,
    pub instance_id: EntryId,
    pub core_binary: PathBuf,
    pub cli_binary: PathBuf,
    pub core_blake3: ContentId,
    pub cli_blake3: ContentId,
    pub state_dir: PathBuf,
    pub ipv4: Ipv4Addr,
    pub prefix_len: u8,
    pub rpc_portal: SocketAddr,
    pub network_name: String,
    pub network_secret: String,
    pub peers: Vec<String>,
    pub listeners: Vec<String>,
    pub allow_tun: bool,
    pub allow_public_relay: bool,
    pub command_timeout_secs: u64,
    pub restart_delay_secs: u64,
    pub max_restarts: u32,
}

impl EasyTierConfig {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1
            || !self.core_binary.is_absolute()
            || !self.cli_binary.is_absolute()
            || !self.state_dir.is_absolute()
            || self.core_binary == self.cli_binary
            || !self.rpc_portal.ip().is_loopback()
            || self.rpc_portal.port() == 0
            || !(8..=30).contains(&self.prefix_len)
            || self.ipv4.is_unspecified()
            || self.ipv4.is_loopback()
            || self.ipv4.is_multicast()
            || self.ipv4.is_broadcast()
            || !random_hex(&self.network_name)
            || !random_hex(&self.network_secret)
            || self.network_name == self.network_secret
            || self.peers.len() > 32
            || self.listeners.len() > 16
            || !(1..=60).contains(&self.command_timeout_secs)
            || !(1..=3600).contains(&self.restart_delay_secs)
            || self.max_restarts > 16
        {
            return Err(ModelError::InvalidConfig(
                "bounded pinned EasyTier configuration required",
            ));
        }
        for endpoints in [&self.peers, &self.listeners] {
            let mut seen = BTreeSet::new();
            for endpoint in endpoints {
                if !valid_endpoint(endpoint) || !seen.insert(endpoint) {
                    return Err(ModelError::InvalidConfig(
                        "invalid or duplicated EasyTier endpoint",
                    ));
                }
            }
        }
        Ok(())
    }

    /// No RPC configuration or secret appears in child arguments.
    pub fn native_config(&self) -> Result<String> {
        self.validate()?;
        let id = self.instance_id.as_str();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &id[..8],
            &id[8..12],
            &id[12..16],
            &id[16..20],
            &id[20..]
        );
        let mut out = format!(
            "instance_name = \"SyncExtend-{}\"\ninstance_id = \"{uuid}\"\nipv4 = \"{}/{}\"\ndhcp = false\nlisteners = {}\n\n[network_identity]\nnetwork_name = \"{}\"\nnetwork_secret = \"{}\"\n",
            self.instance_id, self.ipv4, self.prefix_len, serde_json::to_string(&self.listeners)?,
            self.network_name, self.network_secret
        );
        for peer in &self.peers {
            out.push_str(&format!(
                "\n[[peer]]\nuri = {}\n",
                serde_json::to_string(peer)?
            ));
        }
        out.push_str(&format!(
            "\n[flags]\nno_tun = {}\nenable_encryption = true\nrelay_network_whitelist = \"\"\np2p_only = {}\n",
            !self.allow_tun, !self.allow_public_relay
        ));
        if out.len() > 65536 {
            return Err(ModelError::InvalidConfig("EasyTier generated config limit"));
        }
        Ok(out)
    }
}

fn random_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn valid_endpoint(value: &str) -> bool {
    if value.len() > 1024 || value.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return false;
    }
    let Some((scheme, authority)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "tcp" | "udp" | "ws" | "wss" | "quic")
        || authority.contains(['/', '?', '#', '@', '%', '\\', '"'])
    {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || port.parse::<u16>().ok().is_none_or(|port| port == 0) {
        return false;
    }
    if host.starts_with('[') {
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .and_then(|host| host.parse::<std::net::Ipv6Addr>().ok())
            .is_some()
    } else {
        host.len() <= 253
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
    }
}

/// Official builds include the release version and may append a clean git ID.
pub fn compatible_version(output: &str, program: &str) -> bool {
    let Some(value) = output
        .trim()
        .strip_prefix(program)
        .and_then(|value| value.strip_prefix(' '))
    else {
        return false;
    };
    if value == EASYTIER_VERSION {
        return true;
    }
    value
        .strip_prefix(EASYTIER_VERSION)
        .and_then(|value| value.strip_prefix('-'))
        .is_some_and(|suffix| {
            (7..=40).contains(&suffix.len()) && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EasyTierPath {
    Local,
    P2p,
    Relay { hops: u32 },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EasyTierPeerObservation {
    pub overlay_peer_id: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub path: EasyTierPath,
    pub observed_at_ms: u64,
    pub authenticated_sync_device: bool,
}

pub fn peer_observations(
    bytes: &[u8],
    observed_at_ms: u64,
) -> Result<Vec<EasyTierPeerObservation>> {
    if bytes.len() > 1024 * 1024 || observed_at_ms > i64::MAX as u64 {
        return Err(ModelError::InvalidData("EasyTier observation bounds"));
    }
    #[derive(Deserialize)]
    struct Peer {
        id: String,
        ipv4: String,
        cost: String,
        tunnel_proto: String,
        version: String,
    }
    let peers: Vec<Peer> = serde_json::from_slice(bytes)?;
    if peers.len() > 4096 {
        return Err(ModelError::InvalidData("EasyTier peer inventory bounds"));
    }
    let mut ids = BTreeSet::new();
    peers
        .into_iter()
        .map(|peer| {
            let id = peer
                .id
                .parse::<u32>()
                .map_err(|_| ModelError::InvalidData("EasyTier peer ID"))?;
            if !ids.insert(id)
                || peer.version.len() > 128
                || peer.cost.len() > 32
                || peer.tunnel_proto.len() > 128
            {
                return Err(ModelError::InvalidData("EasyTier peer fields"));
            }
            let path = match peer.cost.as_str() {
                "Local" => EasyTierPath::Local,
                "p2p" if !peer.tunnel_proto.is_empty() => EasyTierPath::P2p,
                value => value
                    .strip_prefix("relay(")
                    .and_then(|value| value.strip_suffix(')'))
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|hops| (2..=64).contains(hops))
                    .map_or(EasyTierPath::Unknown, |hops| EasyTierPath::Relay { hops }),
            };
            let ipv4 = if peer.ipv4.is_empty() {
                None
            } else {
                Some(
                    peer.ipv4
                        .parse()
                        .map_err(|_| ModelError::InvalidData("EasyTier IPv4"))?,
                )
            };
            Ok(EasyTierPeerObservation {
                overlay_peer_id: id,
                ipv4,
                path,
                observed_at_ms,
                authenticated_sync_device: false,
            })
        })
        .collect()
}
