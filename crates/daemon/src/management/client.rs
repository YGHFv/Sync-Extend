//! Local management client reuses configured private credential loading.
use super::{load, token, Result};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};
use sync_extend_core_model::EntryId;

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
}

fn exchange(path: &Path, action: Action<'_>) -> Result<serde_json::Value> {
    let config = load(path)?;
    let policy = config
        .control
        .as_ref()
        .ok_or("explicit local control policy absent")?;
    let allowed = match action {
        Action::Status => policy.status,
        Action::Dashboard => policy.dashboard,
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
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let dashboard = matches!(action, Action::Dashboard);
    let response_limit = if dashboard {
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
