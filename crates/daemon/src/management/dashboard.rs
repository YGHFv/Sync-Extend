//! Optional local dashboard, using cached observations from the real resource owner.
use super::{READY, Result};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::atomic::AtomicUsize;
use std::{
    io::Write,
    net::TcpStream,
    sync::{Mutex, atomic::Ordering},
    time::Instant,
};
use sync_extend_core_model::management::ManagementConfig;
use sync_extend_reconcile::LocalSpace;

const MAX_BODY: usize = 1024 * 1024;
pub(super) const MAX_RESPONSE: usize = MAX_BODY + 4096;
const MAX_OWNER_BODY: usize = MAX_BODY / 2;
static OBSERVATION: Mutex<Option<(Instant, Vec<u8>)>> = Mutex::new(None);
static STORAGE: Mutex<Option<(Instant, serde_json::Value)>> = Mutex::new(None);
static GATEWAY: Mutex<Option<serde_json::Value>> = Mutex::new(None);
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(any(target_os = "linux", target_os = "android"))]
static LOCAL_REGISTRATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(target_os = "linux", target_os = "android"))]
static LOCAL_OBSERVATION: Mutex<Option<(Instant, serde_json::Value)>> = Mutex::new(None);
#[cfg(any(target_os = "linux", target_os = "android"))]
static LOCAL_STORAGE: Mutex<Option<(Instant, serde_json::Value)>> = Mutex::new(None);
#[cfg(any(target_os = "linux", target_os = "android"))]
static LOCAL_GATEWAY: Mutex<Option<serde_json::Value>> = Mutex::new(None);
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const MAX_LOCAL_DASHBOARD: usize = 3072;
const UI: &str = include_str!("dashboard.html");

/// Local kernel-owner collection is independent of HTTP dashboard permission.
/// Registration never starts a listener or opens a second resource owner.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) struct LocalDashboardRegistration {
    _connections: Option<sync_extend_transport::ConnectionObservationRegistration>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn register_local_dashboard() -> LocalDashboardRegistration {
    if LOCAL_REGISTRATIONS.fetch_add(1, Ordering::AcqRel) == 0 {
        clear_local();
    }
    LocalDashboardRegistration {
        _connections: sync_extend_transport::register_connection_observations(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for LocalDashboardRegistration {
    fn drop(&mut self) {
        if LOCAL_REGISTRATIONS.fetch_sub(1, Ordering::AcqRel) == 1 {
            clear_local();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn collecting_local() -> bool {
    LOCAL_REGISTRATIONS.load(Ordering::Acquire) != 0
}

fn collecting() -> bool {
    let collecting = ENABLED.load(Ordering::Acquire);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let collecting = collecting || collecting_local();
    collecting
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clear_local() {
    if let Ok(mut slot) = LOCAL_OBSERVATION.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = LOCAL_STORAGE.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = LOCAL_GATEWAY.lock() {
        *slot = None;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sample(
    slot: &Mutex<Option<(Instant, serde_json::Value)>>,
    name: &str,
) -> Option<serde_json::Value> {
    slot.lock().ok()?.as_ref().map(|(at, value)| {
        let mut sample = serde_json::Map::new();
        sample.insert(
            "age_ms".to_owned(),
            serde_json::json!(at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
        );
        sample.insert(name.to_owned(), value.clone());
        serde_json::Value::Object(sample)
    })
}

/// Only copies the bounded summaries cached by the retained resource owner.
/// No inventory, credential, ledger or CAS reads occur in the control thread.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn local_dashboard() -> (Option<serde_json::Value>, &'static str) {
    let local = sample(&LOCAL_OBSERVATION, "local");
    let storage = sample(&LOCAL_STORAGE, "actual");
    let gateway = LOCAL_GATEWAY.lock().ok().and_then(|slot| slot.clone());
    let connection = sync_extend_transport::latest_connection_observation();
    let easytier = super::super::easytier::latest_observation();
    if local.is_none()
        && storage.is_none()
        && gateway.is_none()
        && connection.is_none()
        && easytier.is_none()
    {
        return (None, "no_observation");
    }
    let value = serde_json::json!({
        "dashboard_format_version": 1,
        "observation": local, "storage": storage, "webdav": gateway,
        "connection": connection, "easytier": easytier, "route": null, "traffic": null,
        "remote_backup_complete": false,
    });
    match serde_json::to_vec(&value) {
        Ok(bytes) if bytes.len() <= MAX_LOCAL_DASHBOARD => (Some(value), "available"),
        Ok(_) => (None, "over_limit"),
        Err(_) => (None, "unavailable"),
    }
}

pub fn configure(config: &ManagementConfig) -> Result<()> {
    ENABLED.store(
        config
            .control
            .as_ref()
            .is_some_and(|policy| policy.dashboard),
        Ordering::Release,
    );
    *OBSERVATION
        .lock()
        .map_err(|_| "dashboard observation unavailable")? = None;
    *STORAGE
        .lock()
        .map_err(|_| "storage observation unavailable")? = None;
    *GATEWAY
        .lock()
        .map_err(|_| "gateway observation unavailable")? = None;
    Ok(())
}

pub fn observe_gateway(
    listener: Option<&sync_extend_core_model::webdav::WebDavListener>,
    scheme: &str,
) {
    if !collecting() {
        return;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if collecting_local() {
        if let Ok(mut slot) = LOCAL_GATEWAY.lock() {
            *slot = listener.map(|listener| {
                serde_json::json!({
                    "address": listener.address, "scheme": scheme,
                    "listening": true, "authenticated": true,
                    "export_count": listener.exports.len(),
                })
            });
        }
    }
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    // Observe only a bounded inventory. Never cache a partial export list.
    let Some(listener) = listener.filter(|listener| listener.exports.len() <= 128) else {
        if let Ok(mut slot) = GATEWAY.lock() {
            *slot = None;
        }
        return;
    };
    let exports: Vec<_> = listener
        .exports
        .iter()
        .map(|export| {
            serde_json::json!({
                "name": export.name, "space_id": export.space_id,
                "subtree": export.subtree, "writable": export.writable,
                "url": format!("{scheme}://{}/{}/", listener.address, export.name),
                "max_upload_bytes": export.max_upload_bytes,
            })
        })
        .collect();
    if let Ok(mut slot) = GATEWAY.lock() {
        let value = serde_json::json!({
            "listener_id": listener.listener_id, "address": listener.address,
            "scheme": scheme,
            "listening": true, "authenticated": true, "exports": exports,
            "accounts": listener.accounts.iter().map(|account| &account.username).collect::<Vec<_>>(),
        });
        *slot = serde_json::to_vec(&value)
            .ok()
            .filter(|bytes| bytes.len() <= MAX_BODY / 4)
            .map(|_| value);
    }
}
pub fn observe_storage(node: &sync_extend_reconcile::StorageNode) {
    if !collecting() {
        return;
    }
    let observation = node.management_dashboard().ok();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if collecting_local() {
        if let Ok(mut slot) = LOCAL_STORAGE.lock() {
            *slot = observation.as_ref().map(|value| {
                (
                    Instant::now(),
                    serde_json::json!({
                        "space_id": value.space_id, "device_id": value.device_id,
                        "role": value.role,
                        "protected_chunks": value.protected_chunks,
                        "protected_bytes": value.protected_bytes,
                        "physical_cas_bytes": value.physical_cas_bytes,
                        "stored_byte_limit": value.stored_byte_limit,
                        "request_byte_limit": value.request_byte_limit,
                        "charged_logical_delivery_bytes": value.charged_logical_delivery_bytes,
                        "traffic_byte_limit": value.traffic_byte_limit,
                        "expired": value.expired,
                        "checked_chunks": value.checked_chunks,
                        "checked_bytes": value.checked_bytes,
                        "unavailable_chunks_count": value.unavailable_chunks.len(),
                        "all_protected_chunks_checked": value.all_protected_chunks_checked,
                        "total_snapshot_reports": value.total_snapshot_reports,
                        "snapshot_reports_truncated": value.snapshot_reports_truncated,
                        "journal_snapshot_consistent": value.journal_snapshot_consistent,
                        "cross_database_snapshot_consistent": value.cross_database_snapshot_consistent,
                        "content_complete_certified": false, "backup_complete": false,
                    }),
                )
            });
        }
    }
    let value = observation
        .filter(|_| ENABLED.load(Ordering::Acquire))
        .and_then(|value| serde_json::to_vec(&value).ok())
        .filter(|bytes| bytes.len() <= MAX_OWNER_BODY)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    if let Ok(mut slot) = STORAGE.lock() {
        *slot = value.map(|value| (Instant::now(), value));
    }
}

pub fn clear() {
    if let Ok(mut value) = STORAGE.lock() {
        *value = None;
    }
    if let Ok(mut value) = OBSERVATION.lock() {
        *value = None;
    }
    if let Ok(mut value) = GATEWAY.lock() {
        *value = None;
    }
}

/// Runs only in the resource owner's existing blocking worker.
pub fn observe_local_space(local: &LocalSpace) {
    if !collecting() {
        return;
    }
    let observation = local.management_dashboard().ok();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if collecting_local() {
        if let Ok(mut slot) = LOCAL_OBSERVATION.lock() {
            *slot = observation.as_ref().map(|value| {
                (
                    Instant::now(),
                    serde_json::json!({
                        "space_id": value.space_id, "device_id": value.device_id,
                        "total_entries": value.total_entries,
                        "total_snapshots": value.total_snapshots,
                        "outstanding_mutations": value.outstanding_mutations,
                        "outstanding_publications": value.outstanding_publications,
                        "entries_truncated": value.entries_truncated,
                        "snapshots_truncated": value.snapshots_truncated,
                        "conflict_admissions_count": value.conflict_admissions.len(),
                        "conflict_admissions_truncated": value.conflict_admissions_truncated,
                        "chunks": {
                            "checked_chunks": value.chunks.checked_chunks,
                            "checked_bytes": value.chunks.checked_bytes,
                            "total_current_chunks": value.chunks.total_current_chunks,
                            "unavailable_chunks_count": value.chunks.unavailable_chunks.len(),
                            "all_current_chunks_checked": value.chunks.all_current_chunks_checked,
                        },
                        "read_leases": value.read_leases,
                        "history_metadata": value.snapshots.iter().take(1).collect::<Vec<_>>(),
                        "history_metadata_limit": 1,
                        "history_metadata_truncated": value.total_snapshots > 1,
                        "recovery": {
                            "retained_snapshots": value.recovery.retained_snapshots,
                            "pruned_snapshots": value.recovery.pruned_snapshots,
                            "pruned_history": value.recovery.pruned_history.iter().take(1).collect::<Vec<_>>(),
                            "pruned_history_limit": 1,
                            "pruned_history_truncated": value.recovery.pruned_snapshots > 1,
                            "metadata_snapshot_consistent": value.recovery.metadata_snapshot_consistent,
                            "historical_content_hashes_verified": value.recovery.historical_content_hashes_verified,
                            "restore_command": value.recovery.restore_command,
                            "whole_tree_restore_command": value.recovery.whole_tree_restore_command,
                            "recovered_archive_command": value.recovery.recovered_archive_command,
                            "restoration_performed": value.recovery.restoration_performed,
                            "native_authority": value.recovery.native_authority,
                            "cleanup_authority": value.recovery.cleanup_authority,
                            "pending_resume_authority": value.recovery.pending_resume_authority,
                        },
                        "remote_backup_complete": false,
                    }),
                )
            });
        }
    }
    let value = observation
        .filter(|_| ENABLED.load(Ordering::Acquire))
        .and_then(|value| serde_json::to_vec(&value).ok())
        .filter(|bytes| bytes.len() <= MAX_OWNER_BODY);
    if let Ok(mut slot) = OBSERVATION.lock() {
        *slot = value.map(|bytes| (Instant::now(), bytes));
    }
}

fn browser_request(
    bytes: &[u8],
    config: &ManagementConfig,
    secret: &[u8],
    ui: bool,
    stop: bool,
) -> bool {
    if bytes.len() > 4096 || !bytes.ends_with(b"\r\n\r\n") {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text[..text.len() - 4].split("\r\n");
    let route = if stop {
        "POST /v1/control/stop HTTP/1.1"
    } else if ui {
        "GET /v1/ui HTTP/1.1"
    } else {
        "GET /v1/dashboard HTTP/1.1"
    };
    if lines.next() != Some(route) {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut authority = None;
    let mut supplied = None;
    for line in lines {
        let Some((name, value)) = line.split_once(": ") else {
            return false;
        };
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) || value.chars().any(char::is_control) {
            return false;
        }
        match name.as_str() {
            "host" => authority = Some(value),
            "authorization" => supplied = value.strip_prefix("Bearer ").map(str::as_bytes),
            "x-sync-owner" | "x-sync-request" if stop => {
                if value.parse::<sync_extend_core_model::EntryId>().is_err() {
                    return false;
                }
            }
            "origin" if stop && value == format!("http://{}", config.address) => {}
            "content-length" if value == "0" => {}
            "connection"
                if value.eq_ignore_ascii_case("close")
                    || value.eq_ignore_ascii_case("keep-alive") => {}
            "accept"
            | "accept-language"
            | "accept-encoding"
            | "user-agent"
            | "cache-control"
            | "pragma"
            | "sec-ch-ua"
            | "sec-ch-ua-mobile"
            | "sec-ch-ua-platform"
            | "upgrade-insecure-requests" => {}
            "sec-fetch-site" if value == "same-origin" || (ui && value == "none") => {}
            "sec-fetch-mode" if value == "same-origin" || (ui && value == "navigate") => {}
            "sec-fetch-dest" if value == "empty" || (ui && value == "document") => {}
            "sec-fetch-user" if ui && value == "?1" => {}
            "referer" if value == format!("http://{}/v1/ui", config.address) => {}
            _ => return false,
        }
    }
    if authority != Some(config.address.to_string().as_str()) || (stop && !seen.contains("origin"))
    {
        return false;
    }
    if ui {
        return supplied.is_none();
    }
    let Some(supplied) = supplied else {
        return false;
    };
    let mut mismatch = supplied.len() ^ secret.len();
    for (actual, expected) in supplied.iter().zip(secret) {
        mismatch |= usize::from(actual ^ expected);
    }
    mismatch == 0
}

/// Browser headers are checked before constructing the existing strict
/// bodyless control request. The same session decides permission and replay.
pub fn stop(
    stream: &mut TcpStream,
    bytes: &[u8],
    config: &ManagementConfig,
    secret: &[u8],
    session: Option<&mut sync_extend_core_model::management::ControlSession>,
) -> Result<()> {
    let accepted = if config
        .control
        .as_ref()
        .is_some_and(|policy| policy.dashboard && policy.stop)
        && browser_request(bytes, config, secret, false, true)
    {
        std::str::from_utf8(bytes).ok().and_then(|text| {
            let header = |wanted: &str| {
                text.split("\r\n")
                    .filter_map(|line| line.split_once(": "))
                    .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
                    .map(|(_, value)| value)
            };
            let generation = header("x-sync-owner")?;
            let request_id = header("x-sync-request")?;
            let credential = std::str::from_utf8(secret).ok()?;
            let canonical = format!(
                "POST /v1/control/stop HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\
                 X-Sync-Owner: {}\r\nX-Sync-Request: {}\r\nConnection: close\r\n\r\n",
                config.address, credential, generation, request_id
            );
            let request = sync_extend_core_model::management::authenticated_control_request(
                canonical.as_bytes(),
                config.address,
                secret,
            )
            .ok()?;
            let session = session?;
            let operation = session.accept(request).ok()?;
            (operation == sync_extend_core_model::management::ControlOperation::Stop)
                .then(|| session.generation().clone())
        })
    } else {
        None
    };
    let (status, body) = if let Some(generation) = accepted {
        super::request_stop();
        (
            "202 Accepted",
            serde_json::to_vec(&serde_json::json!({
                "owner_generation": generation, "stop_requested": true,
                "resources_ready": false, "process_exit_verified": false,
            }))?,
        )
    } else {
        (
            "403 Forbidden",
            b"{\"error\":\"local control refused\"}".to_vec(),
        )
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

pub fn serve(
    stream: &mut TcpStream,
    bytes: &[u8],
    config: &ManagementConfig,
    secret: &[u8],
    generation: Option<&sync_extend_core_model::EntryId>,
) -> Result<()> {
    let ui = bytes.starts_with(b"GET /v1/ui ");
    let allowed = config
        .control
        .as_ref()
        .is_some_and(|policy| policy.dashboard)
        && browser_request(bytes, config, secret, ui, false);
    let (status, content_type, body) = if !allowed {
        (
            "403 Forbidden",
            "application/json",
            b"{\"error\":\"dashboard refused\"}".to_vec(),
        )
    } else if ui {
        ("200 OK", "text/html; charset=utf-8", UI.as_bytes().to_vec())
    } else {
        let slot = OBSERVATION
            .lock()
            .map_err(|_| "dashboard observation unavailable")?;
        let observation = slot
            .as_ref()
            .map(|(time, bytes)| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "age_ms": time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    "local": serde_json::from_slice::<serde_json::Value>(bytes)?,
                }))
            })
            .transpose()?;

        let gateway = GATEWAY
            .lock()
            .map_err(|_| "gateway observation unavailable")?
            .clone();
        let storage = STORAGE
            .lock()
            .map_err(|_| "storage observation unavailable")?
            .as_ref()
            .map(|(at, value)| {
                serde_json::json!({
                    "age_ms": at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    "actual": value,
                })
            });
        let ready = READY.load(Ordering::Acquire) && !super::control_stop_requested();
        let connection = ready
            .then(sync_extend_transport::latest_connection_observation)
            .flatten();
        let easytier = (!super::control_stop_requested())
            .then(super::super::easytier::latest_observation)
            .flatten();
        let value = serde_json::json!({
            "dashboard_format_version": 1,
            "owner_generation": generation,
            "resources_ready": ready,
            "observation": observation, "storage": storage,
            "connection": connection, "easytier": easytier, "route": null, "traffic": null, "webdav": gateway,
            "stop_allowed": config.control.as_ref().is_some_and(|policy| policy.stop),
            "remote_backup_complete": false,
        });
        ("200 OK", "application/json", serde_json::to_vec(&value)?)
    };
    if body.len() > MAX_RESPONSE {
        return Err("dashboard response exceeds bound".into());
    }
    // The integration gate binds this SHA256 to the exact inline script bytes.
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; \
         script-src 'sha256-ICQotszEltO0BaHm+fqyw3R+cP3xSZOv7nGOGv2S51M='; style-src 'unsafe-inline'; \
         connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; \
         form-action 'none'\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}
