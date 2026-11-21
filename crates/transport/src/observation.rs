//! Optional process-owned observations of the latest authenticated QUIC session.
//! These inner UDP payload counters are samples, never an admission or billing ledger.
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    time::Instant,
};
use sync_extend_core_model::{ContentId, DeviceId, SpaceId};

const ACTIVE: u8 = 0;
const FINISHED: u8 = 1;
const FAILED: u8 = 2;
const DROPPED: u8 = 3;
const STALE_AFTER_MS: u64 = 30_000;
static COLLECTOR: Mutex<Weak<Collector>> = Mutex::new(Weak::new());

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionObservation {
    pub age_ms: u64,
    pub stale_after_ms: u64,
    pub current: bool,
    pub actual: AuthenticatedConnectionSample,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticatedConnectionSample {
    pub observation_format_version: u32,
    pub sample_scope: &'static str,
    pub meter_unit: &'static str,
    pub peer_device: DeviceId,
    pub space_id: SpaceId,
    /// Hash of the TLS exporter already used by signed protocol messages, not key material.
    pub session_binding: ContentId,
    pub local_socket: Option<SocketAddr>,
    pub local_socket_scope: &'static str,
    pub remote_socket: SocketAddr,
    pub initiated: bool,
    pub lifecycle: &'static str,
    pub active: bool,
    pub udp_sent_bytes: u64,
    pub udp_received_bytes: u64,
    pub udp_sent_datagrams: u64,
    pub udp_received_datagrams: u64,
    pub rtt_us: u64,
    pub path_lost_packets: u64,
    pub path_lost_bytes: u64,
    pub route_attribution: &'static str,
    pub outer_wire_bytes: Option<u64>,
    pub billing_bytes: Option<u64>,
}

struct CachedSample {
    at: Instant,
    sample: AuthenticatedConnectionSample,
    lifecycle: Arc<AtomicU8>,
}

struct Collector {
    latest: Mutex<Option<CachedSample>>,
}

/// Only a retained process owner enables observations. Session producers hold
/// weak references, so dropping the final registration removes all cached data.
pub struct ConnectionObservationRegistration {
    _collector: Arc<Collector>,
}

pub fn register_connection_observations() -> Option<ConnectionObservationRegistration> {
    let mut registry = COLLECTOR.lock().ok()?;
    let collector = registry.upgrade().unwrap_or_else(|| {
        let collector = Arc::new(Collector {
            latest: Mutex::new(None),
        });
        *registry = Arc::downgrade(&collector);
        collector
    });
    Some(ConnectionObservationRegistration {
        _collector: collector,
    })
}

/// Copies the last cache entry without network, filesystem or database reads.
pub fn latest_connection_observation() -> Option<ConnectionObservation> {
    let collector = COLLECTOR.try_lock().ok()?.upgrade()?;
    let cache = collector.latest.try_lock().ok()?;
    let cached = cache.as_ref()?;
    let age_ms = cached.at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let current = age_ms <= STALE_AFTER_MS;
    let state = cached.lifecycle.load(Ordering::Acquire);
    let mut actual = cached.sample.clone();
    actual.active = state == ACTIVE && current;
    actual.lifecycle = match state {
        ACTIVE if current => "active",
        ACTIVE => "stale",
        FINISHED => "finished",
        FAILED => "failed",
        _ => "dropped",
    };
    Some(ConnectionObservation {
        age_ms,
        stale_after_ms: STALE_AFTER_MS,
        current,
        actual,
    })
}

/// Private producer: constructed only after the wrapper verified mTLS and SignedHello.
pub(crate) struct ObservedConnection {
    collector: Weak<Collector>,
    lifecycle: Arc<AtomicU8>,
}

impl ObservedConnection {
    pub(crate) fn authenticated() -> Option<Self> {
        let collector = COLLECTOR.try_lock().ok()?.upgrade()?;
        Some(Self {
            collector: Arc::downgrade(&collector),
            lifecycle: Arc::new(AtomicU8::new(ACTIVE)),
        })
    }

    pub(crate) fn failed(&self) {
        self.lifecycle.store(FAILED, Ordering::Release);
    }

    pub(crate) fn finished(&self) {
        let _ =
            self.lifecycle
                .compare_exchange(ACTIVE, FINISHED, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn dropped(&self) {
        let _ =
            self.lifecycle
                .compare_exchange(ACTIVE, DROPPED, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn record(
        &self,
        endpoint: &quinn::Endpoint,
        connection: &quinn::Connection,
        peer: &crate::PeerIdentity,
        binding: &ContentId,
        initiated: bool,
    ) {
        let Some(collector) = self.collector.upgrade() else {
            return;
        };
        let Ok(mut cache) = collector.latest.try_lock() else {
            return;
        };
        let stats = connection.stats();
        let local_ip = connection.local_ip();
        let local_socket = endpoint
            .local_addr()
            .ok()
            .map(|bound| SocketAddr::new(local_ip.unwrap_or(bound.ip()), bound.port()));
        *cache = Some(CachedSample {
            at: Instant::now(),
            lifecycle: Arc::clone(&self.lifecycle),
            sample: AuthenticatedConnectionSample {
                observation_format_version: 1,
                sample_scope: "latest_authenticated_connection",
                meter_unit: "inner_quic_udp_payload_bytes",
                peer_device: peer.device_id.clone(),
                space_id: peer.space_id.clone(),
                session_binding: binding.clone(),
                local_socket,
                local_socket_scope: if local_ip.is_some() {
                    "connection_local_ip"
                } else {
                    "endpoint_bind"
                },
                remote_socket: connection.remote_address(),
                initiated,
                lifecycle: "active",
                active: true,
                udp_sent_bytes: stats.udp_tx.bytes,
                udp_received_bytes: stats.udp_rx.bytes,
                udp_sent_datagrams: stats.udp_tx.datagrams,
                udp_received_datagrams: stats.udp_rx.datagrams,
                rtt_us: stats.path.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
                path_lost_packets: stats.path.lost_packets,
                path_lost_bytes: stats.path.lost_bytes,
                route_attribution: "unknown",
                outer_wire_bytes: None,
                billing_bytes: None,
            },
        });
    }
}
