//! Optional local dashboard, using cached observations from the real resource owner.
use super::{Result, READY};
use std::{
    io::Write,
    net::TcpStream,
    sync::{atomic::Ordering, Mutex},
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
const UI: &str = include_str!("dashboard.html");

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

pub fn observe_gateway(listener: &sync_extend_core_model::webdav::WebDavListener) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    // Observe only a bounded inventory. Never cache a partial export list.
    if listener.exports.len() > 128 {
        if let Ok(mut slot) = GATEWAY.lock() {
            *slot = None;
        }
        return;
    }
    let exports: Vec<_> = listener
        .exports
        .iter()
        .map(|export| {
            serde_json::json!({
                "name": export.name, "space_id": export.space_id,
                "subtree": export.subtree, "writable": export.writable,
                "url": format!("http://{}/{}/", listener.address, export.name),
                "max_upload_bytes": export.max_upload_bytes,
            })
        })
        .collect();
    if let Ok(mut slot) = GATEWAY.lock() {
        let value = serde_json::json!({
            "listener_id": listener.listener_id, "address": listener.address,
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
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let value = node
        .management_dashboard()
        .ok()
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
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let value = local
        .management_dashboard()
        .ok()
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
        let value = serde_json::json!({
            "dashboard_format_version": 1,
            "owner_generation": generation,
            "resources_ready": READY.load(Ordering::Acquire),
            "observation": observation, "storage": storage,
            "connection": null, "route": null, "traffic": null, "webdav": gateway,
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
         script-src 'sha256-Qkl3NuWWYg01xbhOtXsYmWJ9oHh3x6VGjxVlD3BED8k='; style-src 'unsafe-inline'; \
         connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; \
         form-action 'none'\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}
