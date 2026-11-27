//! Local management client reuses configured private credential loading.
use super::{load, token, Result};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};
use sync_extend_core_model::{EntryId, SpaceId};

pub fn status(path: &Path) -> Result<()> {
    let value = exchange(path, Action::Status)?;
    if value["stop_requested"] != false {
        return Err("local management owner is stopping".into());
    }
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

pub fn stop(path: &Path, generation: &EntryId, request_id: &EntryId) -> Result<()> {
    let value = exchange(path, Action::Stop(generation, request_id))?;
    if value["owner_generation"] != generation.as_str()
        || value["stop_requested"] != true
        || value["resources_ready"] != false
    {
        return Err("local stop response binding differs".into());
    }
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

pub fn dashboard(path: &Path) -> Result<()> {
    let value = exchange(path, Action::Dashboard)?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[derive(Clone, Copy)]
enum Action<'a> {
    Status,
    Dashboard,
    Stop(&'a EntryId, &'a EntryId),
    RestorePreview(&'a OnlineRestorePreviewRequest, &'a [u8]),
    RestoreContext(Option<&'a SpaceId>),
}

fn exchange(path: &Path, action: Action<'_>) -> Result<serde_json::Value> {
    let config = load(path)?;
    let policy = config
        .control
        .as_ref()
        .ok_or("explicit local control policy absent")?;
    let allowed = match action {
        Action::Status => policy.status,
        Action::Dashboard | Action::RestorePreview(..) | Action::RestoreContext(..) => {
            policy.dashboard
        }
        Action::Stop(..) => policy.stop,
    };
    if !allowed {
        return Err("requested local control permission absent".into());
    }
    let secret = token(&config)?;
    let timeout = Duration::from_secs(config.request_timeout_secs);
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&config.address, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    let route = match action {
        Action::Status => "GET /v1/status",
        Action::Dashboard => "GET /v1/dashboard",
        Action::Stop(..) => "POST /v1/control/stop",
        Action::RestorePreview(..) => "POST /v2/restore-preview",
        Action::RestoreContext(..) => "GET /v2/restore-preview/context",
    };
    let mut request = format!(
        "{route} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n",
        config.address,
        std::str::from_utf8(&secret)?
    );
    if let Action::Stop(generation, request_id) = action {
        request.push_str(&format!(
            "X-Sync-Owner: {generation}\r\nX-Sync-Request: {request_id}\r\n"
        ));
    }
    if let Action::RestorePreview(_, body) = action {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    if let Action::RestoreContext(Some(space)) = action {
        request.push_str(&format!("X-Sync-Space: {space}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    if let Action::RestorePreview(_, body) = action {
        stream.write_all(body)?;
        // Close only this caller's write side after its complete body. The
        // server accepts standard Content-Length callers without requiring EOF.
        stream.shutdown(std::net::Shutdown::Write)?;
    }
    let dashboard = matches!(action, Action::Dashboard);
    let response_limit = if matches!(
        action,
        Action::RestorePreview(..) | Action::RestoreContext(..)
    ) {
        MAX_PREVIEW_RESPONSE + 4096
    } else if dashboard {
        super::dashboard::MAX_RESPONSE + 4096
    } else {
        8192
    };
    let mut response = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("local control response deadline reached".into());
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut buffer = [0u8; 1024];
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > response_limit {
            return Err("local control response exceeds bound".into());
        }
    }
    // Refusals do not print an untrusted server body or any reflected credential.
    let end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("local control response headers absent")?;
    let header = std::str::from_utf8(&response[..end])?;
    let mut lines = header.split("\r\n");
    let expected = if matches!(action, Action::Stop(..)) {
        "HTTP/1.1 202 Accepted"
    } else {
        "HTTP/1.1 200 OK"
    };
    if lines.next() != Some(expected) {
        return Err("local control request refused by owner".into());
    }
    let mut length = None;
    let mut content_type = false;
    let mut close = false;
    let mut no_store = false;
    for line in lines {
        let (name, value) = line
            .split_once(": ")
            .ok_or("local control response header")?;
        match name {
            "Content-Length" if length.is_none() => length = Some(value.parse::<usize>()?),
            "Content-Type" if !content_type && value == "application/json" => content_type = true,
            "Connection" if !close && value == "close" => close = true,
            "Cache-Control" if !no_store && value == "no-store" => no_store = true,
            "Content-Security-Policy" | "Referrer-Policy" | "X-Content-Type-Options"
                if dashboard => {}
            _ => return Err("local control response framing differs".into()),
        }
    }
    let body = &response[end + 4..];
    if length != Some(body.len()) || !content_type || !close || !no_store {
        return Err("local control response body framing differs".into());
    }
    if body.windows(secret.len()).any(|bytes| bytes == secret) {
        return Err("local control response reflected credential".into());
    }
    let value: serde_json::Value = serde_json::from_slice(body)?;
    if let Action::RestoreContext(space) = action {
        if value["preview_context_format_version"] != 2
            || !value["available"].is_boolean()
            || value["output_bytes_including_lf"].as_u64() != Some(body.len() as u64)
            || !body.ends_with(b"\n")
            || value["cache_max_age_ms"] != CONTEXT_MAX_AGE_MS
            || value["spaces_limit"] != MAX_PREVIEW_OWNER_SPACES
            || value["snapshots_limit"] != 128
            || !value["spaces"]
                .as_array()
                .is_some_and(|spaces| spaces.len() <= MAX_PREVIEW_OWNER_SPACES)
            || !value["snapshots"]
                .as_array()
                .is_some_and(|snapshots| snapshots.len() <= 128)
            || !value["spaces_truncated"].is_boolean()
            || !value["snapshots_truncated"].is_boolean()
            || [
                "restoration_performed",
                "native_authority",
                "cleanup_authority",
                "pending_resume_authority",
                "execution_available_from_preview",
            ]
            .iter()
            .any(|field| value[*field] != false)
            || space.is_some_and(|space| {
                value["available"] == true && value["space_id"] != space.as_str()
            })
        {
            return Err("local restore context response differs".into());
        }
        value["owner_generation"]
            .as_str()
            .ok_or("context owner absent")?
            .parse::<EntryId>()?;
        return Ok(value);
    }
    if let Action::RestorePreview(request, _) = action {
        if value["preview_format_version"] != 2
            || value["owner_generation"] != request.owner_generation.as_str()
            || value["space_id"] != request.request.space_id.as_str()
            || value["target"]["snapshot_id"] != request.request.snapshot.as_str()
            || value["selection"] != serde_json::to_value(&request.request.selection)?
            || value["destination_prefix"]
                != serde_json::to_value(&request.request.destination_prefix)?
            || value["current_extra_policy"]
                != serde_json::to_value(request.request.current_extra_policy)?
            || value["occupied_target_policy"]
                != serde_json::to_value(request.request.occupied_target_policy)?
            || value["source_interpretation"] != "live_owner_deferred_transaction"
            || !value["source_image_bytes"].is_null()
            || !value["source_image_digest"].is_null()
            || !value["memory_header_projected"].is_null()
            || value["output_bytes_including_lf"].as_u64() != Some(body.len() as u64)
            || value["output_byte_limit"].as_u64()
                != Some(request.request.limits.max_output_bytes as u64)
            || body.len() > request.request.limits.max_output_bytes
            || !body.ends_with(b"\n")
            || [
                "restoration_performed",
                "preparation_performed",
                "native_authority",
                "cleanup_authority",
                "pending_resume_authority",
                "execution_available_from_preview",
                "content_hashes_verified",
                "worktree_scanned",
                "native_conflicts_checked",
            ]
            .iter()
            .any(|field| value[*field] != false)
        {
            return Err("local restore preview response binding differs".into());
        }
        return Ok(value);
    }
    if dashboard {
        if value["dashboard_format_version"] != 1
            || value["remote_backup_complete"] != false
            || !value["resources_ready"].is_boolean()
            || !value["stop_allowed"].is_boolean()
        {
            return Err("local dashboard response schema differs".into());
        }
        value["owner_generation"]
            .as_str()
            .ok_or("dashboard owner generation absent")?
            .parse::<EntryId>()?;
        validate_dashboard_metadata_disclosure(&value)?;
        return Ok(value);
    }
    let object = value
        .as_object()
        .ok_or("local control response object absent")?;
    let expected_fields = [
        "role",
        "owner_generation",
        "resources_ready",
        "stop_requested",
        "authenticated_local_management",
        "synchronization_complete",
        "remote_backup_complete",
        "content_integrity_certified",
    ];
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
        || value["authenticated_local_management"] != true
        || value["synchronization_complete"] != false
        || value["remote_backup_complete"] != false
        || value["content_integrity_certified"] != false
        || !value["resources_ready"].is_boolean()
        || !value["stop_requested"].is_boolean()
    {
        return Err("local control response schema differs".into());
    }
    let generation = value["owner_generation"]
        .as_str()
        .ok_or("local control response generation absent")?;
    generation.parse::<EntryId>()?;
    let role = value["role"]
        .as_str()
        .ok_or("local control response role absent")?;
    if role.is_empty()
        || role.len() > 64
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("local control response role differs".into());
    }
    Ok(value)
}

const MAX_PREVIEW_BODY: usize = 65_536;
const MAX_PREVIEW_RESPONSE: usize = 262_144;
const MAX_PREVIEW_OWNER_SPACES: usize = 64;
const CONTEXT_MAX_AGE_MS: u64 = 10_000;
const CONTEXT_REFRESH_MS: u64 = 5_000;

const METADATA_STATES: [&str; 3] = ["supported", "unsupported", "unknown"];
const METADATA_UNSUPPORTED_REASONS: [&str; 4] = ["platform", "filesystem", "permission", "api"];
const METADATA_CERTIFICATIONS: [&str; 3] = [
    "windows_ntfs_actual_grouped_acceptance",
    "unix_implemented_not_verified_in_this_release",
    "unsupported_platform",
];

fn validate_metadata_capability(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or("local metadata capability object absent")?;
    if object.len() < 3 || object.len() > 7 {
        return Err("local metadata capability fields differ".into());
    }
    for key in object.keys() {
        if ![
            "format_version",
            "capture",
            "apply",
            "verify",
            "timestamp_precision_ns",
            "unsupported",
            "certification",
        ]
        .contains(&key.as_str())
        {
            return Err("local metadata capability field differs".into());
        }
    }
    if object
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err("local metadata capability version differs".into());
    }
    for phase in ["capture", "apply", "verify"] {
        let stage = object
            .get(phase)
            .and_then(serde_json::Value::as_object)
            .ok_or("local metadata capability stage absent")?;
        if stage.len() < 2 || stage.len() > 4 {
            return Err("local metadata capability stage fields differ".into());
        }
        for (name, state) in stage {
            if !["modified", "creation", "readonly", "unix_executable"].contains(&name.as_str())
                || !state
                    .as_str()
                    .is_some_and(|state| METADATA_STATES.contains(&state))
            {
                return Err("local metadata capability stage state differs".into());
            }
        }
        if !stage.contains_key("modified") || !stage.contains_key("readonly") {
            return Err("local metadata capability required field absent".into());
        }
    }
    match object.get("timestamp_precision_ns") {
        None | Some(serde_json::Value::Null) => {}
        Some(value) => {
            if !value
                .as_u64()
                .is_some_and(|precision| (1..=1_000_000_000).contains(&precision))
            {
                return Err("local metadata timestamp precision differs".into());
            }
        }
    }
    match object.get("unsupported") {
        None | Some(serde_json::Value::Null) => {}
        Some(value) => {
            let reasons = value
                .as_object()
                .ok_or("local metadata unsupported reasons absent")?;
            if reasons.len() > 2 {
                return Err("local metadata unsupported reasons exceed bound".into());
            }
            for (name, reason) in reasons {
                if !["creation", "unix_executable"].contains(&name.as_str())
                    || !reason
                        .as_str()
                        .is_some_and(|reason| METADATA_UNSUPPORTED_REASONS.contains(&reason))
                {
                    return Err("local metadata unsupported reason differs".into());
                }
            }
        }
    }
    match object.get("certification") {
        None | Some(serde_json::Value::Null) => {}
        Some(value) => {
            if !value
                .as_str()
                .is_some_and(|certification| METADATA_CERTIFICATIONS.contains(&certification))
            {
                return Err("local metadata certification differs".into());
            }
        }
    }
    Ok(())
}

fn validate_entry_metadata(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or("local entry metadata object absent")?;
    if object.len() != 3
        || !["format_version", "modified", "readonly"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err("local entry metadata fields differ".into());
    }
    if object["format_version"].as_u64() != Some(1) || !object["readonly"].is_boolean() {
        return Err("local entry metadata format differs".into());
    }
    let modified = object["modified"]
        .as_object()
        .ok_or("local entry modified timestamp absent")?;
    if modified.len() != 2
        || !["seconds", "nanoseconds"]
            .iter()
            .all(|field| modified.contains_key(*field))
    {
        return Err("local entry modified timestamp fields differ".into());
    }
    modified["seconds"]
        .as_i64()
        .ok_or("local entry modified seconds differ")?;
    if !modified["nanoseconds"]
        .as_u64()
        .is_some_and(|nanoseconds| nanoseconds < 1_000_000_000)
    {
        return Err("local entry modified nanoseconds differ".into());
    }
    Ok(())
}

fn validate_dashboard_metadata_disclosure(value: &serde_json::Value) -> Result<()> {
    let Some(local) = value["observation"]["local"].as_object() else {
        return Ok(());
    };
    if let Some(capabilities) = local.get("metadata_capabilities") {
        if !capabilities.is_null() {
            validate_metadata_capability(capabilities)?;
        }
    }
    let Some(entries) = local.get("entries") else {
        return Ok(());
    };
    let entries = entries.as_array().ok_or("local dashboard entries absent")?;
    if entries.len() > 128 {
        return Err("local dashboard entries exceed bound".into());
    }
    for entry in entries {
        if let Some(metadata) = entry.get("metadata") {
            if !metadata.is_null() {
                validate_entry_metadata(metadata)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlineRestorePreviewRequest {
    pub owner_generation: EntryId,
    pub request: sync_extend_reconcile::RestoreSelectionPreviewRequest,
}

#[derive(serde::Serialize)]
struct OnlineRestorePreviewResponse {
    owner_generation: EntryId,
    #[serde(flatten)]
    preview: sync_extend_reconcile::RestoreSelectionPreview,
}

type PreviewReply = std::result::Result<Vec<u8>, &'static str>;

struct PendingPreview {
    generation: EntryId,
    request: sync_extend_reconcile::RestoreSelectionPreviewRequest,
    deadline: Instant,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reply: std::sync::mpsc::SyncSender<PreviewReply>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PreviewQuotaPhase {
    Reading,
    Pending,
    Flight,
}

struct PreviewQuota {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    raw_bytes: usize,
    phase: PreviewQuotaPhase,
}

struct PreviewState {
    generation: EntryId,
    spaces: std::collections::BTreeMap<SpaceId, OwnerPreviewContext>,
    spaces_truncated: bool,
    cache_epoch: u64,
    pending: Option<PendingPreview>,
}

struct PreviewGlobal {
    owner: Option<PreviewState>,
    // The one raw-body charge outlives owner stop/token/generation changes.
    // Its exact token is transferred from reading to pending to the worker.
    quota: Option<PreviewQuota>,
}

struct OwnerPreviewContext {
    next_refresh: Instant,
    observed_at: Option<Instant>,
    metadata: Option<serde_json::Value>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

static PREVIEW_STATE: std::sync::Mutex<PreviewGlobal> = std::sync::Mutex::new(PreviewGlobal {
    owner: None,
    quota: None,
});

fn release_quota_locked(
    global: &mut PreviewGlobal,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    if global
        .quota
        .as_ref()
        .is_some_and(|quota| std::sync::Arc::ptr_eq(&quota.cancelled, cancelled))
    {
        global.quota = None;
    }
}

/// Reading failures and a finished worker release only their exact token,
/// regardless of which generation currently owns the registry.
struct PreviewQuotaLease {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    armed: bool,
}

impl Drop for PreviewQuotaLease {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut global) = PREVIEW_STATE.lock() {
                release_quota_locked(&mut global, &self.cancelled);
            }
        }
    }
}

fn reserve_preview_body(
    generation: &EntryId,
    raw_bytes: usize,
    deadline: Instant,
) -> std::result::Result<PreviewQuotaLease, &'static str> {
    let mut global = PREVIEW_STATE
        .lock()
        .map_err(|_| "preview owner unavailable")?;
    if !(1..=MAX_PREVIEW_BODY).contains(&raw_bytes)
        || global.quota.is_some()
        || !global
            .owner
            .as_ref()
            .is_some_and(|owner| owner.generation == *generation && owner.pending.is_none())
        || !super::READY.load(std::sync::atomic::Ordering::Acquire)
        || super::control_stop_requested()
        || Instant::now() >= deadline
    {
        return Err("preview body slot or owner unavailable");
    }
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    global.quota = Some(PreviewQuota {
        cancelled: cancelled.clone(),
        raw_bytes,
        phase: PreviewQuotaPhase::Reading,
    });
    Ok(PreviewQuotaLease {
        cancelled,
        armed: true,
    })
}

fn invalidate(global: &mut PreviewGlobal) {
    use std::sync::atomic::Ordering;
    if let Some(quota) = &global.quota {
        quota.cancelled.store(true, Ordering::Release);
    }
    if let Some(pending) = global.owner.as_mut().and_then(|owner| owner.pending.take()) {
        pending.cancelled.store(true, Ordering::Release);
        let _ = pending.reply.try_send(Err("owner preview invalidated"));
        let cancelled = pending.cancelled.clone();
        // Destroy the pending request before making its raw-body charge free.
        drop(pending);
        if global.quota.as_ref().is_some_and(|quota| {
            quota.phase == PreviewQuotaPhase::Pending
                && std::sync::Arc::ptr_eq(&quota.cancelled, &cancelled)
        }) {
            release_quota_locked(global, &cancelled);
        }
    }
    if let Some(owner) = global.owner.as_mut() {
        for context in owner.spaces.values_mut() {
            context.cancelled.store(true, Ordering::Release);
            context.metadata = None;
            context.observed_at = None;
            context.next_refresh = Instant::now();
        }
    }
}

pub fn configure_preview(generation: Option<&EntryId>) {
    if let Ok(mut global) = PREVIEW_STATE.lock() {
        invalidate(&mut global);
        global.owner = generation.map(|generation| PreviewState {
            generation: generation.clone(),
            spaces: std::collections::BTreeMap::new(),
            spaces_truncated: false,
            cache_epoch: 0,
            pending: None,
        });
    }
}

pub fn defer_preview() {
    if let Ok(mut global) = PREVIEW_STATE.lock() {
        invalidate(&mut global);
        if let Some(state) = global.owner.as_mut() {
            match state.cache_epoch.checked_add(1) {
                Some(epoch) => state.cache_epoch = epoch,
                None => global.owner = None,
            }
        }
    }
}

/// The existing management configuration explicitly supplied this generation.
/// Reading this gate never registers a space or opens a resource owner.
pub fn restore_preview_owner_configured() -> bool {
    PREVIEW_STATE
        .lock()
        .ok()
        .is_some_and(|global| global.owner.is_some())
}

/// Membership is limited to preview contexts, independently of the configured
/// deployment's existing resource and listener limits.
pub fn restore_preview_space_registered(space: &SpaceId) -> bool {
    PREVIEW_STATE.lock().ok().is_some_and(|global| {
        global
            .owner
            .as_ref()
            .is_some_and(|state| state.spaces.contains_key(space))
    })
}

/// Pure metadata initialization and refresh on the existing resource owner.
/// No management configuration means no registration or Journal query.
pub fn register_restore_preview_context(local: &mut sync_extend_reconcile::LocalSpace) {
    use std::sync::atomic::Ordering;
    let space = local.management_restore_preview_space().clone();
    let work = {
        let Ok(mut global) = PREVIEW_STATE.lock() else {
            return;
        };
        let quota_busy = global.quota.is_some();
        let Some(state) = global.owner.as_mut() else {
            return;
        };
        if !state.spaces.contains_key(&space) {
            if state.spaces.len() >= MAX_PREVIEW_OWNER_SPACES {
                state.spaces_truncated = true;
                return;
            }
            state.spaces.insert(
                space.clone(),
                OwnerPreviewContext {
                    next_refresh: Instant::now(),
                    observed_at: None,
                    metadata: None,
                    cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                },
            );
        }
        if quota_busy {
            return;
        }
        let Some(context) = state.spaces.get_mut(&space) else {
            return;
        };
        if Instant::now() < context.next_refresh {
            return;
        }
        context.next_refresh = Instant::now() + Duration::from_millis(CONTEXT_REFRESH_MS);
        context.cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            state.generation.clone(),
            state.cache_epoch,
            context.cancelled.clone(),
        )
    };
    let observed_at = Instant::now();
    let deadline = observed_at + Duration::from_millis(2_500);
    let metadata = local
        .management_restore_preview_context(
            default_preview_limits().source,
            deadline,
            work.2.clone(),
        )
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .filter(|value| {
            serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= MAX_PREVIEW_BODY)
        });
    if let Ok(mut global) = PREVIEW_STATE.lock() {
        if let Some(state) = global
            .owner
            .as_mut()
            .filter(|state| state.generation == work.0 && state.cache_epoch == work.1)
        {
            if let Some(context) = state.spaces.get_mut(&space) {
                if std::sync::Arc::ptr_eq(&context.cancelled, &work.2)
                    && !work.2.load(Ordering::Acquire)
                    && Instant::now() < deadline
                {
                    context.observed_at = metadata.as_ref().map(|_| observed_at);
                    context.metadata = metadata;
                }
            }
        }
    }
}

/// Called only with the actual live LocalSpace. Registry entries contain
/// portable space IDs; no cached manifest or result survives generation changes.
pub fn process_restore_preview(local: &mut sync_extend_reconcile::LocalSpace) {
    use std::sync::atomic::Ordering;
    register_restore_preview_context(local);
    let (pending, flight_lease) = {
        let Ok(mut global) = PREVIEW_STATE.lock() else {
            return;
        };
        let Some(state) = global.owner.as_ref() else {
            return;
        };
        let space = local.management_restore_preview_space();
        if !state.spaces.contains_key(space) {
            return;
        }
        if !super::READY.load(Ordering::Acquire) || super::control_stop_requested() {
            return;
        }
        let matching = state.pending.as_ref().is_some_and(|pending| {
            pending.generation == state.generation
                && pending.request.space_id == *space
                && global.quota.as_ref().is_some_and(|quota| {
                    quota.phase == PreviewQuotaPhase::Pending
                        && std::sync::Arc::ptr_eq(&quota.cancelled, &pending.cancelled)
                })
        });
        if !matching {
            return;
        }
        let Some(pending) = global.owner.as_mut().and_then(|state| state.pending.take()) else {
            return;
        };
        if let Some(quota) = global.quota.as_mut() {
            quota.phase = PreviewQuotaPhase::Flight;
        }
        let lease = PreviewQuotaLease {
            cancelled: pending.cancelled.clone(),
            armed: true,
        };
        (pending, lease)
    };
    let result = if Instant::now() >= pending.deadline || pending.cancelled.load(Ordering::Acquire)
    {
        Err("owner preview deadline reached")
    } else {
        local
            .management_restore_preview(
                &pending.request,
                pending.deadline,
                pending.cancelled.clone(),
            )
            .map_err(|_| "owner metadata preview refused")
            .and_then(|preview| encode_online_preview(pending.generation.clone(), preview))
    };
    let current = if let Ok(global) = PREVIEW_STATE.lock() {
        if let Some(state) = global.owner.as_ref() {
            let matching = state.generation == pending.generation
                && global.quota.as_ref().is_some_and(|quota| {
                    quota.phase == PreviewQuotaPhase::Flight
                        && std::sync::Arc::ptr_eq(&quota.cancelled, &pending.cancelled)
                });
            matching
                && !pending.cancelled.load(Ordering::Acquire)
                && Instant::now() < pending.deadline
                && super::READY.load(Ordering::Acquire)
                && !super::control_stop_requested()
        } else {
            false
        }
    } else {
        false
    };
    let _ = pending.reply.try_send(if current {
        result
    } else {
        Err("owner preview invalidated")
    });
    drop(pending);
    // The old job's request is gone before its quota becomes available. This
    // exact-token release also works after stop, token rotation or replacement.
    drop(flight_lease);
}

fn encode_online_preview(
    generation: EntryId,
    preview: sync_extend_reconcile::RestoreSelectionPreview,
) -> PreviewReply {
    let mut response = OnlineRestorePreviewResponse {
        owner_generation: generation,
        preview,
    };
    loop {
        let body = serde_json::to_vec(&response).map_err(|_| "preview response unavailable")?;
        response.preview.output_bytes_including_lf = body.len() + 1;
        let mut body = serde_json::to_vec(&response).map_err(|_| "preview response unavailable")?;
        let actual = body.len() + 1;
        if actual <= response.preview.output_byte_limit && actual <= MAX_PREVIEW_RESPONSE {
            if actual != response.preview.output_bytes_including_lf {
                continue;
            }
            body.push(b'\n');
            return Ok(body);
        }
        if !response.preview.cas_references.is_empty() {
            let length = response.preview.cas_references.len() / 2;
            response.preview.cas_references.truncate(length);
            response.preview.cas_references_truncated = true;
        } else if !response.preview.entries.is_empty() {
            let length = response.preview.entries.len() / 2;
            response.preview.entries.truncate(length);
            response.preview.entries_truncated = true;
        } else {
            return Err("preview fixed scope exceeds output budget");
        }
    }
}

fn preview_headers(
    bytes: &[u8],
    config: &sync_extend_core_model::management::ManagementConfig,
    secret: &[u8],
    context: bool,
) -> std::result::Result<(usize, Option<SpaceId>), &'static str> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\r\n\r\n") {
        return Err("preview request framing refused");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "preview request framing refused")?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let expected = if context {
        "GET /v2/restore-preview/context HTTP/1.1"
    } else {
        "POST /v2/restore-preview HTTP/1.1"
    };
    if lines.next() != Some(expected) {
        return Err("preview request framing refused");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut authority = None;
    let mut supplied = None;
    let mut length = None;
    let mut content_type = false;
    let mut space = None;
    for line in lines {
        let (name, value) = line
            .split_once(": ")
            .ok_or("preview request framing refused")?;
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) || value.chars().any(char::is_control) {
            return Err("preview request framing refused");
        }
        match name.as_str() {
            "host" => authority = Some(value),
            "authorization" => supplied = value.strip_prefix("Bearer ").map(str::as_bytes),
            "content-type" if value == "application/json" => content_type = true,
            "content-length"
                if !value.is_empty()
                    && value.len() <= 5
                    && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "preview body bound refused")?,
                )
            }
            "connection" if value == "close" || value == "keep-alive" => {}
            "x-sync-space" if context => {
                space = Some(value.parse().map_err(|_| "context space refused")?)
            }
            "accept" | "accept-encoding" | "accept-language" | "user-agent" | "cache-control"
            | "pragma" | "sec-ch-ua" | "sec-ch-ua-mobile" | "sec-ch-ua-platform" => {}
            "origin" if value == format!("http://{}", config.address) => {}
            "referer" if value == format!("http://{}/v1/ui", config.address) => {}
            "sec-fetch-site" if value == "same-origin" => {}
            "sec-fetch-mode" if value == "same-origin" || value == "cors" => {}
            "sec-fetch-dest" if value == "empty" => {}
            _ => return Err("preview request framing refused"),
        }
    }
    let supplied = supplied.ok_or("preview authentication refused")?;
    let mut mismatch = supplied.len() ^ secret.len();
    for (actual, expected) in supplied.iter().zip(secret) {
        mismatch |= usize::from(actual ^ expected);
    }
    if mismatch != 0
        || authority != Some(config.address.to_string().as_str())
        || !config
            .control
            .as_ref()
            .is_some_and(|policy| policy.dashboard)
    {
        return Err("preview authentication refused");
    }
    if !super::token(config).is_ok_and(|current| current == secret) {
        configure_preview(None);
        return Err("preview authentication refused");
    }
    if context {
        if length.is_some_and(|length| length != 0) {
            return Err("context body must be empty");
        }
        return Ok((0, space));
    }
    let length = length
        .filter(|length| (1..=MAX_PREVIEW_BODY).contains(length))
        .ok_or("preview body bound refused")?;
    if !content_type {
        return Err("preview request framing refused");
    }
    Ok((length, None))
}

fn cancel_preview(cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    cancelled.store(true, std::sync::atomic::Ordering::Release);
    if let Ok(mut global) = PREVIEW_STATE.lock() {
        let pending = global.owner.as_mut().and_then(|state| {
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| std::sync::Arc::ptr_eq(&pending.cancelled, cancelled))
            {
                state.pending.take()
            } else {
                None
            }
        });
        if let Some(pending) = pending {
            drop(pending);
            if global.quota.as_ref().is_some_and(|quota| {
                quota.phase == PreviewQuotaPhase::Pending
                    && std::sync::Arc::ptr_eq(&quota.cancelled, cancelled)
            }) {
                release_quota_locked(&mut global, cancelled);
            }
        }
        // Reading/flight memory remains charged until the corresponding exact
        // lease exits, including when this token belongs to a previous owner.
    }
}

pub fn serve_preview(
    stream: &mut TcpStream,
    bytes: &[u8],
    config: &sync_extend_core_model::management::ManagementConfig,
    secret: &[u8],
    generation: Option<&EntryId>,
    deadline: Instant,
) -> Result<()> {
    let admitted = (|| -> std::result::Result<_, &'static str> {
        let (length, _) = preview_headers(bytes, config, secret, false)?;
        let generation = generation.ok_or("preview owner unavailable")?;
        // Reserve the global raw-body charge before any allocation or read.
        // Every refusal while Reading drops this RAII lease after its buffer.
        let mut reading_lease = reserve_preview_body(generation, length, deadline)?;
        let mut body = vec![0u8; length];
        let mut received = 0;
        while received < body.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero()
                || reading_lease
                    .cancelled
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err("preview request deadline reached");
            }
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| "preview request unavailable")?;
            let count = stream
                .read(&mut body[received..])
                .map_err(|_| "preview request unavailable")?;
            if count == 0 {
                return Err("preview request incomplete");
            }
            received += count;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            || reading_lease
                .cancelled
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("preview request deadline reached");
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| "preview request unavailable")?;
        let mut tail = [0u8; 1];
        let tail_result = stream.peek(&mut tail);
        stream
            .set_nonblocking(false)
            .map_err(|_| "preview request unavailable")?;
        match tail_result {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => return Err("preview trailing request refused"),
            Err(_) => return Err("preview request unavailable"),
        }
        let value: OnlineRestorePreviewRequest =
            serde_json::from_slice(&body).map_err(|_| "preview typed request refused")?;
        value
            .request
            .validate()
            .map_err(|_| "preview bounds refused")?;
        if value.owner_generation != *generation
            || value.request.limits.max_output_bytes > MAX_PREVIEW_RESPONSE
        {
            return Err("preview owner or response bound refused");
        }
        drop(body);
        let cancelled = reading_lease.cancelled.clone();
        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        {
            let mut global = PREVIEW_STATE
                .lock()
                .map_err(|_| "preview owner unavailable")?;
            let state = global.owner.as_ref().ok_or("preview owner unavailable")?;
            if state.generation != *generation
                || !state.spaces.contains_key(&value.request.space_id)
                || state.pending.is_some()
                || !global.quota.as_ref().is_some_and(|quota| {
                    quota.phase == PreviewQuotaPhase::Reading
                        && quota.raw_bytes == length
                        && std::sync::Arc::ptr_eq(&quota.cancelled, &cancelled)
                })
                || cancelled.load(std::sync::atomic::Ordering::Acquire)
                || !super::READY.load(std::sync::atomic::Ordering::Acquire)
                || super::control_stop_requested()
                || Instant::now() >= deadline
            {
                return Err("preview owner binding or bounded queue refused");
            }
            let state = global.owner.as_mut().ok_or("preview owner unavailable")?;
            state.pending = Some(PendingPreview {
                generation: generation.clone(),
                request: value.request,
                deadline,
                cancelled: cancelled.clone(),
                reply,
            });
            if let Some(quota) = global.quota.as_mut() {
                quota.phase = PreviewQuotaPhase::Pending;
            }
            // Transfer the existing token and charge; never charge a second
            // request or free the Reading charge during the phase transition.
            reading_lease.armed = false;
        }
        let result = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match result {
            Ok(Ok(body)) => {
                let current = PREVIEW_STATE.lock().ok().is_some_and(|global| {
                    global
                        .owner
                        .as_ref()
                        .is_some_and(|state| state.generation == *generation)
                });
                if !current
                    || cancelled.load(std::sync::atomic::Ordering::Acquire)
                    || !super::READY.load(std::sync::atomic::Ordering::Acquire)
                    || super::control_stop_requested()
                    || Instant::now() >= deadline
                {
                    cancel_preview(&cancelled);
                    return Err("preview owner changed before response");
                }
                Ok(body)
            }
            _ => {
                cancel_preview(&cancelled);
                Err("preview result unavailable or timed out")
            }
        }
    })();
    let (status, body) = match admitted {
        Ok(body) => ("200 OK", body),
        Err(reason) => {
            let status = if reason == "preview authentication refused" {
                "403 Forbidden"
            } else {
                "409 Conflict"
            };
            let mut body = serde_json::to_vec(&serde_json::json!({
                "error": reason, "restoration_performed": false, "native_authority": false,
                "cleanup_authority": false, "pending_resume_authority": false,
                "execution_available_from_preview": false,
            }))?;
            body.push(b'\n');
            (status, body)
        }
    };
    stream.set_write_timeout(Some(Duration::from_secs(config.request_timeout_secs)))?;
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    Ok(())
}

pub fn restore_preview(
    path: &Path,
    request_hex: Option<&str>,
    space: Option<&SpaceId>,
) -> Result<()> {
    let value = if let Some(hex) = request_hex {
        if hex.is_empty()
            || hex.len() > MAX_PREVIEW_BODY * 2
            || hex.len() % 2 != 0
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("bounded lowercase restore request hex required".into());
        }
        let nibble = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        let body: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| nibble(pair[0]) * 16 + nibble(pair[1]))
            .collect();
        let request: OnlineRestorePreviewRequest = serde_json::from_slice(&body)?;
        request.request.validate()?;
        if request.request.limits.max_output_bytes > MAX_PREVIEW_RESPONSE {
            return Err("bounded online preview response required".into());
        }
        exchange(path, Action::RestorePreview(&request, &body))?
    } else {
        exchange(path, Action::RestoreContext(space))?
    };
    use std::io::Write;
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() + 1 > MAX_PREVIEW_RESPONSE {
        return Err("preview client response exceeds bound".into());
    }
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn default_preview_limits() -> sync_extend_reconcile::RestorePreviewLimits {
    sync_extend_reconcile::RestorePreviewLimits {
        source: sync_extend_journal::ReadOnlySnapshotPreviewLimits {
            max_journal_bytes: 64 * 1024 * 1024,
            max_manifest_bytes: 8 * 1024 * 1024,
            max_entries: 16_384,
            max_chunk_visits: 32_768,
            max_reference_rows: 32_768,
            max_vm_instructions: 5_000_000,
            max_query_millis: 2_500,
        },
        max_output_entries: 128,
        max_output_cas_references: 128,
        max_output_bytes: MAX_PREVIEW_RESPONSE,
        max_selected_logical_bytes: 1 << 40,
        max_resource_estimate_bytes: 1 << 50,
    }
}

pub fn serve_context(
    stream: &mut TcpStream,
    bytes: &[u8],
    config: &sync_extend_core_model::management::ManagementConfig,
    secret: &[u8],
    generation: Option<&EntryId>,
) -> Result<()> {
    let result = (|| -> std::result::Result<serde_json::Value, &'static str> {
        let (_, requested_space) = preview_headers(bytes, config, secret, true)?;
        let generation = generation.ok_or("context owner unavailable")?;
        stream
            .set_nonblocking(true)
            .map_err(|_| "context request unavailable")?;
        let mut byte = [0u8; 1];
        let tail = stream.peek(&mut byte);
        stream
            .set_nonblocking(false)
            .map_err(|_| "context request unavailable")?;
        match tail {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => return Err("context body or trailing request refused"),
            Err(_) => return Err("context request unavailable"),
        }
        let global = PREVIEW_STATE
            .lock()
            .map_err(|_| "context owner unavailable")?;
        let state = global
            .owner
            .as_ref()
            .filter(|state| state.generation == *generation)
            .ok_or("context owner unavailable")?;
        let selected = if let Some(space) = requested_space.as_ref() {
            state
                .spaces
                .get_key_value(space)
                .ok_or("context owner space refused")?
        } else {
            let Some(selected) = state.spaces.first_key_value() else {
                return Ok(context_value(generation, state, None));
            };
            selected
        };
        Ok(context_value(generation, state, Some(selected)))
    })();
    let (status, mut value) = match result {
        Ok(value) => ("200 OK", value),
        Err(reason) => (
            "403 Forbidden",
            serde_json::json!({
                "error": reason, "restoration_performed": false, "native_authority": false,
                "cleanup_authority": false, "pending_resume_authority": false,
                "execution_available_from_preview": false,
            }),
        ),
    };
    value["output_bytes_including_lf"] = 0.into();
    let body = loop {
        let length = serde_json::to_vec(&value)?.len() + 1;
        value["output_bytes_including_lf"] = length.into();
        let mut body = serde_json::to_vec(&value)?;
        if body.len() + 1 > MAX_PREVIEW_RESPONSE {
            return Err("context response exceeds bound".into());
        }
        if body.len() + 1 == length {
            body.push(b'\n');
            break body;
        }
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    Ok(())
}

fn context_value(
    generation: &EntryId,
    state: &PreviewState,
    selected: Option<(&SpaceId, &OwnerPreviewContext)>,
) -> serde_json::Value {
    let age = selected
        .and_then(|(_, context)| context.observed_at)
        .map(|at| at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
    let metadata = selected.and_then(|(_, context)| context.metadata.as_ref());
    let available = super::READY.load(std::sync::atomic::Ordering::Acquire)
        && !super::control_stop_requested()
        && age.is_some_and(|age| age <= CONTEXT_MAX_AGE_MS)
        && metadata.is_some_and(|value| {
            value["current_snapshot_id"].is_string()
                && value["snapshots"]
                    .as_array()
                    .is_some_and(|snapshots| !snapshots.is_empty())
        });
    serde_json::json!({
        "preview_context_format_version": 2, "owner_generation": generation,
        "context_source": "live_owner_bounded_metadata_observation",
        "cache_age_ms": age, "cache_max_age_ms": CONTEXT_MAX_AGE_MS,
        "space_id": selected.map(|(space, _)| space),
        "spaces": state.spaces.keys().collect::<Vec<_>>(),
        "spaces_limit": MAX_PREVIEW_OWNER_SPACES, "spaces_truncated": state.spaces_truncated,
        "current_snapshot_id": if available { metadata.map(|value| &value["current_snapshot_id"]) } else { None },
        "available": available,
        "snapshots": if available { metadata.map(|value| &value["snapshots"]).cloned().unwrap_or(serde_json::json!([])) }
            else { serde_json::json!([]) },
        "snapshots_limit": 128,
        "snapshots_truncated": available && metadata.is_some_and(|value| value["snapshots_truncated"] == true),
        "limits": default_preview_limits(), "content_availability": "unchecked",
        "restoration_performed": false, "native_authority": false, "cleanup_authority": false,
        "pending_resume_authority": false, "execution_available_from_preview": false,
    })
}
