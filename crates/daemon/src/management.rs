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
use sync_extend_core_model::management::ManagementConfig;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static READY: AtomicBool = AtomicBool::new(false);

pub fn resources_ready() {
    READY.store(true, Ordering::Release);
}

pub fn resources_deferred() {
    READY.store(false, Ordering::Release);
}

pub struct ManagementGuard {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ManagementGuard {
    fn drop(&mut self) {
        READY.store(false, Ordering::Release);
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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

pub fn start(path: &Path, role: &'static str) -> Result<ManagementGuard> {
    let config = load(path)?;
    let token = token(&config)?;
    let listener = TcpListener::bind(config.address)?;
    listener.set_nonblocking(true)?;
    READY.store(false, Ordering::Release);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name("syncd-local-health".to_owned())
        .spawn(move || {
            let mut count = 0u64;
            while !thread_stop.load(Ordering::Acquire) && count < config.max_connections {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        count += 1;
                        if peer.ip().is_loopback() {
                            let _ = serve(&mut stream, &config, &token, role);
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
) -> Result<()> {
    let timeout = Duration::from_secs(config.request_timeout_secs);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let bytes = request(stream, timeout)?;
    let (status, body) = if authenticated(&bytes, config, secret) {
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
