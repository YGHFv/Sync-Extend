//! A small cache belonging to one exact managed EasyTier child generation.
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use sync_extend_core_model::{
    ContentId, EntryId,
    easytier::{EasyTierConfig, EasyTierPath, EasyTierPeerObservation},
};

pub(super) const MAX_PEERS: usize = 4;
const STALE_AFTER_MS: u64 = 10_000;
static COLLECTOR: Mutex<Weak<Collector>> = Mutex::new(Weak::new());
static INVALIDATED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Serialize)]
pub(crate) struct Observation {
    age_ms: u64,
    stale_after_ms: u64,
    current: bool,
    actual: Sample,
}

#[derive(Clone, Serialize)]
struct Peer {
    overlay_peer_id: u32,
    ipv4: Option<std::net::Ipv4Addr>,
    path: EasyTierPath,
}

#[derive(Clone, Serialize)]
struct Sample {
    observation_format_version: u32,
    sample_scope: &'static str,
    generation: EntryId,
    child_pid: u32,
    process_start: String,
    rpc_portal: SocketAddr,
    pinned_version: &'static str,
    core_pin: ContentId,
    cli_pin: ContentId,
    config_pin: ContentId,
    lifecycle: &'static str,
    owner_bound: bool,
    unavailable_reason: Option<&'static str>,
    peer_count: usize,
    peers_truncated: bool,
    peers: Vec<Peer>,
    authenticated_sync_device: bool,
    route_attribution: &'static str,
    outer_wire_bytes: Option<u64>,
    billing_bytes: Option<u64>,
}

struct Collector {
    live: AtomicBool,
    sample: Mutex<(Instant, Sample)>,
}

pub(super) struct Owner(Arc<Collector>);
#[derive(Clone)]
pub(super) struct Producer(Weak<Collector>);

impl Owner {
    pub(super) fn new(
        config: &EasyTierConfig,
        generation: EntryId,
        pid: u32,
        process_start: String,
        config_pin: ContentId,
    ) -> Option<Self> {
        if INVALIDATED.load(Ordering::Acquire) {
            return None;
        }
        let collector = Arc::new(Collector {
            live: AtomicBool::new(true),
            sample: Mutex::new((
                Instant::now(),
                Sample {
                    observation_format_version: 1,
                    sample_scope: "managed_easytier_peers",
                    generation,
                    child_pid: pid,
                    process_start,
                    rpc_portal: config.rpc_portal,
                    pinned_version: "2.6.4",
                    core_pin: config.core_blake3.clone(),
                    cli_pin: config.cli_blake3.clone(),
                    config_pin,
                    lifecycle: "unavailable",
                    owner_bound: false,
                    unavailable_reason: Some("rpc_not_observed"),
                    peer_count: 0,
                    peers_truncated: false,
                    peers: Vec::new(),
                    authenticated_sync_device: false,
                    route_attribution: "unassociated_with_sync_connection",
                    outer_wire_bytes: None,
                    billing_bytes: None,
                },
            )),
        });
        *COLLECTOR.lock().ok()? = Arc::downgrade(&collector);
        Some(Self(collector))
    }

    pub(super) fn producer(&self) -> Producer {
        Producer(Arc::downgrade(&self.0))
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.0.live.store(false, Ordering::Release);
    }
}

impl Producer {
    pub(super) fn invalidate(&self) {
        if let Some(collector) = self.0.upgrade() {
            collector.live.store(false, Ordering::Release);
        }
    }

    pub(super) fn record(
        &self,
        result: std::result::Result<Vec<EasyTierPeerObservation>, &'static str>,
    ) {
        let Some(collector) = self.0.upgrade() else {
            return;
        };
        if !collector.live.load(Ordering::Acquire) || INVALIDATED.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut cache) = collector.sample.lock() else {
            return;
        };
        if !collector.live.load(Ordering::Acquire) || INVALIDATED.load(Ordering::Acquire) {
            return;
        }
        cache.0 = Instant::now();
        let sample = &mut cache.1;
        sample.peers.clear();
        sample.peer_count = 0;
        sample.peers_truncated = false;
        match result {
            Ok(mut peers) => {
                peers.sort_unstable_by_key(|peer| peer.overlay_peer_id);
                sample.peer_count = peers.len();
                sample.peers_truncated = peers.len() > MAX_PEERS;
                sample.peers = peers
                    .into_iter()
                    .take(MAX_PEERS)
                    .map(|peer| Peer {
                        overlay_peer_id: peer.overlay_peer_id,
                        ipv4: peer.ipv4,
                        path: peer.path,
                    })
                    .collect();
                sample.lifecycle = "available";
                sample.owner_bound = true;
                sample.unavailable_reason = None;
            }
            Err(reason) => {
                sample.lifecycle = "unavailable";
                sample.owner_bound = false;
                sample.unavailable_reason = Some(reason);
            }
        }
    }
}

/// Stop invalidates the generation synchronously; late query output cannot revive it.
pub(crate) fn clear() {
    INVALIDATED.store(true, Ordering::Release);
    if let Some(collector) = COLLECTOR.try_lock().ok().and_then(|slot| slot.upgrade()) {
        collector.live.store(false, Ordering::Release);
    }
}

/// A control refresh performs no process, socket, configuration or CLI reads.
pub(crate) fn latest() -> Option<Observation> {
    let collector = COLLECTOR.try_lock().ok()?.upgrade()?;
    if !collector.live.load(Ordering::Acquire) || INVALIDATED.load(Ordering::Acquire) {
        return None;
    }
    let cache = collector.sample.try_lock().ok()?;
    let age_ms = cache.0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let current = age_ms <= STALE_AFTER_MS;
    let mut actual = cache.1.clone();
    if !current {
        actual.lifecycle = "stale";
        actual.owner_bound = false;
        actual.unavailable_reason = Some("sample_stale");
        actual.peers.clear();
        actual.peer_count = 0;
        actual.peers_truncated = false;
    }
    if !collector.live.load(Ordering::Acquire) || INVALIDATED.load(Ordering::Acquire) {
        return None;
    }
    Some(Observation {
        age_ms,
        stale_after_ms: STALE_AFTER_MS,
        current,
        actual,
    })
}
