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
pub use client::{
    dashboard as control_dashboard, process_restore_preview, register_restore_preview_context,
    restore_preview as control_restore_preview, restore_preview_owner_configured,
    restore_preview_space_registered, status as control_status, stop as control_stop,
};
mod dashboard;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use dashboard::{
    local_dashboard, register_local_dashboard, LocalDashboardRegistration, MAX_LOCAL_DASHBOARD,
};
pub use dashboard::{observe_gateway, observe_storage};

pub fn observe_local_space(local: &mut sync_extend_reconcile::LocalSpace) {
    client::process_restore_preview(local);
    dashboard::observe_local_space(local);
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static READY: AtomicBool = AtomicBool::new(false);
static CONTROL_STOP: AtomicBool = AtomicBool::new(false);

fn request_stop() {
    CONTROL_STOP.store(true, Ordering::Release);
    READY.store(false, Ordering::Release);
    client::configure_preview(None);
    super::easytier::clear_observations();
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
    client::defer_preview();
}

#[cfg(windows)]
type ManagementThreadResult =
    std::result::Result<ClosedManagementResources, ManagementResourceCloseFailure>;
#[cfg(not(windows))]
type ManagementThreadResult = ();

pub struct ManagementGuard {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<ManagementThreadResult>>,
    _connections: Option<sync_extend_transport::ConnectionObservationRegistration>,
    #[cfg(windows)]
    resources: Arc<std::sync::Mutex<ManagementNativeResources>>,
}

impl ManagementGuard {
    fn close_resources(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.thread.is_none() {
                return Ok(());
            }
            return self
                .close_native_resources()
                .map(|_| ())
                .map_err(|original| {
                    let error: Box<dyn std::error::Error> =
                        std::io::Error::new(original.error.kind(), original.error.to_string())
                            .into();
                    original.retain_until_process_exit();
                    error
                });
        }
        #[cfg(not(windows))]
        {
            READY.store(false, Ordering::Release);
            self.stop.store(true, Ordering::Release);
            client::configure_preview(None);
            let joined: Result<Option<()>> = self
                .thread
                .take()
                .map(|thread| {
                    thread
                        .join()
                        .map_err(|_| "management owner thread failed".into())
                })
                .transpose();
            self._connections.take();
            dashboard::clear();
            joined.map(|_| ())
        }
    }

    pub(crate) fn close(mut self) -> Result<()> {
        self.close_resources()
    }

    pub(crate) fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    #[cfg(windows)]
    pub(crate) fn close_retaining(mut self) -> ManagementThreadResult {
        self.close_native_resources()
    }

    #[cfg(windows)]
    fn close_native_resources(&mut self) -> ManagementThreadResult {
        READY.store(false, Ordering::Release);
        self.stop.store(true, Ordering::Release);
        client::configure_preview(None);
        let joined = match self.thread.take() {
            Some(thread) => match thread.join() {
                Ok(closed) => closed,
                Err(_) => {
                    let mut original = self
                        .resources
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    original.close_all(Some(std::io::Error::other(
                        "original management owner thread failed",
                    )))
        }
            },
            None => Err(ManagementResourceCloseFailure::without_resources(
                std::io::Error::other("original management thread close already consumed"),
            )),
        };
        self._connections.take();
        dashboard::clear();
        joined
    }
}

impl Drop for ManagementGuard {
    fn drop(&mut self) {
        let _ = self.close_resources();
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
    PreparedManagement::new(load(path)?)?.start(role)
}

/// Holds a parsed exact configuration and its actual credential before node
/// acquisition or listener effects. It contains no serialized start authority.
pub(crate) struct PreparedManagement {
    config: ManagementConfig,
    token: Vec<u8>,
}

impl Drop for PreparedManagement {
    fn drop(&mut self) {
        self.token.fill(0);
    }
}

impl PreparedManagement {
    pub(crate) fn new(config: ManagementConfig) -> Result<Self> {
        config.validate()?;
    let token = token(&config)?;
        Ok(Self { config, token })
    }

    pub(crate) fn start(mut self, role: &'static str) -> Result<ManagementGuard> {
        let config = self.config.clone();
        let token = std::mem::take(&mut self.token);
        start_prepared(config, token, role)
    }

    #[cfg(windows)]
    pub(crate) fn start_retaining(
        mut self,
        role: &'static str,
    ) -> std::result::Result<ManagementGuard, ManagementStartFailure> {
        let config = self.config.clone();
        let token = std::mem::take(&mut self.token);
        start_prepared_retaining(config, token, role)
    }
}

pub(crate) fn reset_lifecycle_state() {
    READY.store(false, Ordering::Release);
    CONTROL_STOP.store(false, Ordering::Release);
}

#[cfg(not(windows))]
fn start_prepared(
    config: ManagementConfig,
    token: Vec<u8>,
    role: &'static str,
) -> Result<ManagementGuard> {
    let mut control = config
        .control
        .clone()
        .map(|policy| ControlSession::new(EntryId::random()?, policy))
        .transpose()?;
    let listener = TcpListener::bind(config.address)?;
    listener.set_nonblocking(true)?;
    dashboard::configure(&config)?;
    client::configure_preview(
        control
            .as_ref()
            .filter(|_| {
                config
                    .control
                    .as_ref()
                    .is_some_and(|policy| policy.dashboard)
            })
            .map(ControlSession::generation),
    );
    let connections = config
        .control
        .as_ref()
        .filter(|policy| policy.dashboard)
        .and_then(|_| sync_extend_transport::register_connection_observations());
    reset_lifecycle_state();
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

#[cfg(windows)]
pub(crate) struct ClosedManagementResources {
    _actual_listener_close: sync_extend_platform_fs::ClosedWindowsOriginalSocket,
    pub(crate) actual_closed_connections: u64,
}

#[cfg(windows)]
pub(crate) struct ManagementResourceCloseFailure {
    pub(crate) error: std::io::Error,
    pub(crate) original_listener: Option<TcpListener>,
    pub(crate) original_connections: Vec<TcpStream>,
    pub(crate) actual_closed_connections: u64,
    _actual_listener_close: Option<sync_extend_platform_fs::ClosedWindowsOriginalSocket>,
}

#[cfg(windows)]
impl ManagementResourceCloseFailure {
    fn without_resources(error: std::io::Error) -> Self {
        Self {
            error,
            original_listener: None,
            original_connections: Vec::new(),
            actual_closed_connections: 0,
            _actual_listener_close: None,
        }
    }
    pub(crate) fn has_retained_originals(&self) -> bool {
        self.original_listener.is_some() || !self.original_connections.is_empty()
    }

    /// Retry only the actual original sockets. The first failure remains a
    /// failure after every successful later native terminal.
    pub(crate) fn close_remaining(mut self) -> Self {
        let mut remaining = Vec::new();
        for original in self.original_connections.drain(..) {
            match sync_extend_platform_fs::close_original_tcp_stream(original) {
                Ok(_) => self.actual_closed_connections += 1,
                Err((original, _later_error)) => remaining.push(original),
            }
        }
        self.original_connections = remaining;
        if let Some(original) = self.original_listener.take() {
            match sync_extend_platform_fs::close_original_tcp_listener(original) {
                Ok(closed) => self._actual_listener_close = Some(closed),
                Err((original, _later_error)) => self.original_listener = Some(original),
            }
        }
        self
    }

    pub(crate) fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

#[cfg(windows)]
pub(crate) struct ManagementStartFailure {
    pub(crate) error: Box<dyn std::error::Error>,
    pub(crate) original_resources: Option<ManagementResourceCloseFailure>,
}

#[cfg(windows)]
#[derive(Default)]
struct ManagementNativeResources {
    listener: Option<TcpListener>,
    active_stream: Option<TcpStream>,
    failed_streams: Vec<TcpStream>,
    first_close_error: Option<std::io::Error>,
    actual_closed_connections: u64,
}

#[cfg(windows)]
struct NativeManagementCredential(Vec<u8>);
#[cfg(windows)]
impl Drop for NativeManagementCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(windows)]
impl ManagementNativeResources {
    fn close_active_stream(&mut self) {
        if let Some(original) = self.active_stream.take() {
            match sync_extend_platform_fs::close_original_tcp_stream(original) {
                Ok(_) => self.actual_closed_connections += 1,
                Err((original, error)) => {
                    self.first_close_error.get_or_insert(error);
                    self.failed_streams.push(original);
                }
            }
        }
    }

    fn close_all(&mut self, first_error: Option<std::io::Error>) -> ManagementThreadResult {
        if self.first_close_error.is_none() {
            self.first_close_error = first_error;
        }
        self.close_active_stream();
        let mut original_connections = Vec::new();
        for original in self.failed_streams.drain(..) {
            match sync_extend_platform_fs::close_original_tcp_stream(original) {
                Ok(_) => self.actual_closed_connections += 1,
                Err((original, error)) => {
                    self.first_close_error.get_or_insert(error);
                    original_connections.push(original);
                }
            }
        }
        let mut original_listener = None;
        let closed_listener = self.listener.take().and_then(|original| {
            match sync_extend_platform_fs::close_original_tcp_listener(original) {
                Ok(closed) => Some(closed),
                Err((original, error)) => {
                    self.first_close_error.get_or_insert(error);
                    original_listener = Some(original);
                    None
                }
            }
        });
        match self.first_close_error.take() {
            Some(error) => Err(ManagementResourceCloseFailure {
                error,
                original_listener,
                original_connections,
                actual_closed_connections: self.actual_closed_connections,
                _actual_listener_close: closed_listener,
            }),
            None => match closed_listener {
                Some(closed) => Ok(ClosedManagementResources {
                    _actual_listener_close: closed,
                    actual_closed_connections: self.actual_closed_connections,
                }),
                None => Err(ManagementResourceCloseFailure::without_resources(
                    std::io::Error::other("actual original management listener close is absent"),
                )),
            },
        }
    }
}

#[cfg(windows)]
fn start_prepared(
    config: ManagementConfig,
    token: Vec<u8>,
    role: &'static str,
) -> Result<ManagementGuard> {
    start_prepared_retaining(config, token, role).map_err(|failure| {
        if let Some(original) = failure.original_resources {
            original.retain_until_process_exit();
        }
        failure.error
    })
}

#[cfg(windows)]
fn start_prepared_retaining(
    config: ManagementConfig,
    token: Vec<u8>,
    role: &'static str,
) -> std::result::Result<ManagementGuard, ManagementStartFailure> {
    let mut token = NativeManagementCredential(token);
    let mut control = config
        .control
        .clone()
        .map(|policy| ControlSession::new(EntryId::random()?, policy))
        .transpose()
        .map_err(|error| ManagementStartFailure {
            error: error.into(),
            original_resources: None,
        })?;
    let listener = TcpListener::bind(config.address).map_err(|error| ManagementStartFailure {
        error: error.into(),
        original_resources: None,
    })?;
    let resources = Arc::new(std::sync::Mutex::new(ManagementNativeResources {
        listener: Some(listener),
        ..ManagementNativeResources::default()
    }));
    let prepared = (|| -> Result<()> {
        {
            let original = resources
                .lock()
                .map_err(|_| "original management listener mutex failed")?;
            original
                .listener
                .as_ref()
                .ok_or("actual management listener absent")?
                .set_nonblocking(true)?;
        }
        dashboard::configure(&config)?;
        client::configure_preview(
            control
                .as_ref()
                .filter(|_| {
                    config
                        .control
                        .as_ref()
                        .is_some_and(|policy| policy.dashboard)
                })
                .map(ControlSession::generation),
        );
        Ok(())
    })();
    if let Err(error) = prepared {
        token.0.fill(0);
        READY.store(false, Ordering::Release);
        client::configure_preview(None);
        dashboard::clear();
        let mut original = resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let terminal = original.close_all(None).err();
        return Err(ManagementStartFailure {
            error,
            original_resources: terminal,
        });
    }
    let connections = config
        .control
        .as_ref()
        .filter(|policy| policy.dashboard)
        .and_then(|_| sync_extend_transport::register_connection_observations());
    reset_lifecycle_state();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread_resources = Arc::clone(&resources);
    let thread = std::thread::Builder::new()
        .name("syncd-local-health".to_owned())
        .spawn(move || {
            let mut count = 0u64;
            while !thread_stop.load(Ordering::Acquire)
                && !control_stop_requested()
                && count < config.max_connections
            {
                let accepted = {
                    let original = thread_resources
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match original.listener.as_ref() {
                        Some(listener) => listener.accept(),
                        None => break,
                    }
                };
                match accepted {
                    Ok((stream, peer)) => {
                        count += 1;
                        let mut original = thread_resources
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        original.active_stream = Some(stream);
                        if let Some(stream) = original.active_stream.as_mut() {
                            if peer.ip().is_loopback() && stream.set_nonblocking(false).is_ok() {
                                let _ = serve(stream, &config, &token.0, role, control.as_mut());
                            }
                        }
                        original.close_active_stream();
                        if original.first_close_error.is_some() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        let mut original = thread_resources
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        original.first_close_error.get_or_insert(error);
                        break;
                    }
                }
            }
            token.0.fill(0);
            let mut original = thread_resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            original.close_all(None)
        });
    match thread {
        Ok(thread) => Ok(ManagementGuard {
            stop,
            thread: Some(thread),
            _connections: connections,
            resources,
        }),
        Err(error) => {
            READY.store(false, Ordering::Release);
            client::configure_preview(None);
            dashboard::clear();
            drop(connections);
            let mut original = resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let terminal = original.close_all(None).err();
            Err(ManagementStartFailure {
                error: error.into(),
                original_resources: terminal,
            })
        }
    }
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
    let deadline = Instant::now() + timeout;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let bytes = request(stream, timeout)?;
    if bytes.starts_with(b"POST /v2/restore-preview ") {
        return client::serve_preview(
            stream,
            &bytes,
            config,
            secret,
            control.as_deref().map(ControlSession::generation),
            deadline,
        );
    }
    if bytes.starts_with(b"GET /v2/restore-preview/context ") {
        return client::serve_context(
            stream,
            &bytes,
            config,
            secret,
            control.as_deref().map(ControlSession::generation),
        );
    }
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
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
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
    write!(
        stream,
        "GET /v1/health HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        config.address,
        std::str::from_utf8(&secret)?
    )?;
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
