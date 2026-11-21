//! Authenticated local lifecycle status, separate from worktree and pairing credentials.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use sync_extend_core_model::{
    management::{
        authenticated_control_request, ControlOperation, ControlSession, ManagementConfig,
    },
    EntryId,
};

mod client;
pub use client::{dashboard as control_dashboard, status as control_status, stop as control_stop};
mod dashboard;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use dashboard::{
    local_dashboard, register_local_dashboard, LocalDashboardRegistration, MAX_LOCAL_DASHBOARD,
};
pub use dashboard::{observe_gateway, observe_local_space, observe_storage};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static READY: AtomicBool = AtomicBool::new(false);
static CONTROL_STOP: AtomicBool = AtomicBool::new(false);

fn request_stop() {
    CONTROL_STOP.store(true, Ordering::Release);
    READY.store(false, Ordering::Release);
}

pub fn control_stop_requested() -> bool {
    CONTROL_STOP.load(Ordering::Acquire)
}

pub fn resources_ready() {
    READY.store(true, Ordering::Release);
    if control_stop_requested() {
        READY.store(false, Ordering::Release);
    }
}

pub fn resources_deferred() {
    READY.store(false, Ordering::Release);
}

pub struct ManagementGuard {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    _connections: Option<sync_extend_transport::ConnectionObservationRegistration>,
}

impl Drop for ManagementGuard {
    fn drop(&mut self) {
        READY.store(false, Ordering::Release);
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        dashboard::clear();
    }
}

fn load(path: &Path) -> Result<ManagementConfig> {
    let config: ManagementConfig =
        serde_json::from_slice(&super::config_file::read(path, 65_536)?)?;
    config.validate()?;
    if path == config.token_file {
        return Err("management token must use a separate private file".into());
    }
    Ok(config)
}

fn token(config: &ManagementConfig) -> Result<Vec<u8>> {
    super::management_credentials::load(config)
}

pub fn generate_credentials(path: &Path) -> Result<()> {
    let config = load(path)?;
    super::management_credentials::generate(&config)
}

pub fn check_config(path: &Path) -> Result<()> {
    let config = load(path)?;
    let _credential = token(&config)?;
    let policy = config.control.as_ref();
    println!(
        "{}",
        serde_json::json!({
            "configuration_valid": true, "private_credential_valid": true,
            "listener_started": false, "token_protection": config.token_protection,
            "status_allowed": policy.is_some_and(|value| value.status),
            "stop_allowed": policy.is_some_and(|value| value.stop),
            "dashboard_allowed": policy.is_some_and(|value| value.dashboard),
        })
    );
    Ok(())
}

pub fn start(path: &Path, role: &'static str) -> Result<ManagementGuard> {
    let config = load(path)?;
    let token = token(&config)?;
    let mut control = config
        .control
        .clone()
        .map(|policy| ControlSession::new(EntryId::random()?, policy))
        .transpose()?;
    let listener = TcpListener::bind(config.address)?;
    listener.set_nonblocking(true)?;
    dashboard::configure(&config)?;
    let connections = config
        .control
        .as_ref()
        .filter(|policy| policy.dashboard)
        .and_then(|_| sync_extend_transport::register_connection_observations());
    READY.store(false, Ordering::Release);
    CONTROL_STOP.store(false, Ordering::Release);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name("syncd-local-health".to_owned())
        .spawn(move || {
            let mut count = 0u64;
            while !thread_stop.load(Ordering::Acquire)
                && !control_stop_requested()
                && count < config.max_connections
            {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        count += 1;
                        // On Windows an accepted socket can inherit nonblocking mode.
                        if peer.ip().is_loopback() && stream.set_nonblocking(false).is_ok() {
                            let _ = serve(&mut stream, &config, &token, role, control.as_mut());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        })?;
    Ok(ManagementGuard {
        stop,
        thread: Some(thread),
        _connections: connections,
    })
}

fn request(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let deadline = Instant::now() + timeout;
    // Reading only one request prevents accepting trailing pipeline/body bytes
    // as a second authenticated operation.
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("management request deadline reached".into());
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0u8; 1];
        if stream.read(&mut byte)? == 0 {
            return Err("incomplete management request".into());
        }
        bytes.push(byte[0]);
        if bytes.len() > 4096 {
            return Err("management header exceeds bound".into());
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
}

fn authenticated(bytes: &[u8], config: &ManagementConfig, secret: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.split("\r\n");
    if lines.next() != Some("GET /v1/health HTTP/1.1") {
        return false;
    }
    let mut authority = None;
    let mut authorization = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(": ") else {
            return false;
        };
        if name.eq_ignore_ascii_case("host") {
            if authority.replace(value).is_some() {
                return false;
            }
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization.replace(value).is_some() {
                return false;
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if value != "0" {
                return false;
            }
        } else if !name.eq_ignore_ascii_case("connection") || !value.eq_ignore_ascii_case("close") {
            return false;
        }
    }
    let Some(value) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    let mut mismatch = value.len() ^ secret.len();
    for (actual, expected) in value.as_bytes().iter().zip(secret) {
        mismatch |= usize::from(actual ^ expected);
    }
    mismatch == 0 && authority == Some(config.address.to_string().as_str())
}

fn serve(
    stream: &mut TcpStream,
    config: &ManagementConfig,
    secret: &[u8],
    role: &str,
    mut control: Option<&mut ControlSession>,
) -> Result<()> {
    let timeout = Duration::from_secs(config.request_timeout_secs);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let bytes = request(stream, timeout)?;
    if bytes.starts_with(b"GET /v1/ui ") || bytes.starts_with(b"GET /v1/dashboard ") {
        return dashboard::serve(
            stream,
            &bytes,
            config,
            secret,
            control.as_deref().map(ControlSession::generation),
        );
    }
    let is_stop = bytes.starts_with(b"POST /v1/control/stop ");
    if is_stop
        && std::str::from_utf8(&bytes).is_ok_and(|text| {
            text.split("\r\n").any(|line| {
                line.split_once(": ")
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("sec-fetch-mode"))
            })
        })
    {
        return dashboard::stop(stream, &bytes, config, secret, control.take());
    }
    let (status, body) = if is_stop || bytes.starts_with(b"GET /v1/status ") {
        let admitted = control.and_then(|session| {
            let request = authenticated_control_request(&bytes, config.address, secret).ok()?;
            let operation = session.accept(request).ok()?;
            Some((
                operation,
                session.generation().clone(),
                session.stop_requested(),
            ))
        });
        match admitted {
            Some((operation, generation, stopping)) => {
                let accepted_stop = operation == ControlOperation::Stop;
                if accepted_stop {
                    request_stop();
                }
                (
                    if accepted_stop {
                        "202 Accepted"
                    } else {
                        "200 OK"
                    },
                    serde_json::to_vec(&serde_json::json!({
                        "role": role, "owner_generation": generation,
                        "resources_ready": READY.load(Ordering::Acquire),
                        "stop_requested": stopping, "authenticated_local_management": true,
                        "synchronization_complete": false, "remote_backup_complete": false,
                        "content_integrity_certified": false,
                    }))?,
                )
            }
            None => (
                "403 Forbidden",
                b"{\"error\":\"local control refused\"}".to_vec(),
            ),
        }
    } else if authenticated(&bytes, config, secret) {
        let ready = READY.load(Ordering::Acquire);
        (
            if ready {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            serde_json::to_vec(&serde_json::json!({
                "role": role, "resources_ready": ready, "authenticated_local_management": true,
                "synchronization_complete": false, "remote_backup_complete": false,
                "content_integrity_certified": false
            }))?,
        )
    } else {
        (
            "401 Unauthorized",
            b"{\"error\":\"authenticated health request required\"}".to_vec(),
        )
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    Ok(())
}

pub fn check(path: &Path) -> Result<()> {
    let config = load(path)?;
    let secret = token(&config)?;
    let timeout = Duration::from_secs(config.request_timeout_secs);
    let mut stream = TcpStream::connect_timeout(&config.address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(stream, "GET /v1/health HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
           config.address, std::str::from_utf8(&secret)?)?;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("management response deadline reached".into());
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut buffer = [0u8; 1024];
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 8192 {
            return Err("management response exceeds bound".into());
        }
    }
    if bytes.len() > 8192 || !bytes.starts_with(b"HTTP/1.1 200 OK\r\n") {
        return Err("management resources have not reported readiness".into());
    }
    let body = bytes
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("management response headers incomplete")?
        + 4;
    let value: serde_json::Value = serde_json::from_slice(&bytes[body..])?;
    if value["resources_ready"] != true || value["authenticated_local_management"] != true {
        return Err("management readiness response differs".into());
    }
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
