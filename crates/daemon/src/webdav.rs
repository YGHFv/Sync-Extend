//! Explicit listener-local WebDAV gateway; no synchronized credentials or paths.
use super::{
    webdav_conditions as conditions,
    webdav_credentials::Credentials,
    webdav_http::{self as http, Connection, Request},
    webdav_locks::Locks,
    webdav_upload::{ReceiveError, Upload},
    webdav_xml::{self, Properties},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use sync_extend_core_model::{
    deployment::{DeploymentGatewayConfig, DeploymentPlatform, LoopbackTlsConfig},
    limits::LocalLimits,
    webdav::{self, AuthorizedWebDavPath, WebDavListener},
    Entry, EntryKind, Manifest, PortablePath, SpaceId,
};
use sync_extend_reconcile::{LocalSpace, ReconcileError, WebDavBaseline, WebDavCommit};

mod diagnostics;
mod host_tls;
mod polling;
#[cfg(windows)]
mod recovered;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use diagnostics::GatewayProbe;
pub use diagnostics::{check, test_connection};
#[cfg(windows)]
pub(crate) use recovered::{
    ActiveRecoveredGateway, PreparedRecoveredGateway, RecoveredGatewayCloseFailure,
};

#[cfg(windows)]
#[path = "webdav_collections.rs"]
mod collections;

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub listener: WebDavListener,
    pub credentials: PathBuf,
    pub uploads: PathBuf,
    pub spaces: BTreeMap<SpaceId, PathBuf>,
    host_loopback_tls: Option<host_tls::HostLoopbackTls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listener_tls: Option<LoopbackTlsConfig>,
    #[cfg(windows)]
    collection_limits: Option<collections::CollectionLimits>,
}

impl Runtime {
    pub fn scheme(&self) -> &'static str {
        if self.host_loopback_tls.is_some() || self.listener_tls.is_some() {
            "https"
        } else {
            "http"
        }
    }

    pub(crate) fn deployment_document(
        &self,
    ) -> Result<DeploymentGatewayConfig, Box<dyn std::error::Error>> {
        let document = DeploymentGatewayConfig {
            listener: self.listener.clone(),
            credentials: self.credentials.clone(),
            uploads: self.uploads.clone(),
            spaces: self.spaces.clone(),
            host_loopback_tls: self
                .host_loopback_tls
                .as_ref()
                .map(|policy| policy.0.clone()),
            listener_tls: self.listener_tls.clone(),
            #[cfg(windows)]
            collection_limits: self.collection_limits.clone(),
            #[cfg(not(windows))]
            collection_limits: None,
        };
        document.validate(if cfg!(windows) {
            DeploymentPlatform::Windows
        } else {
            DeploymentPlatform::Linux
        })?;
        Ok(document)
    }

    fn selected_tls_config(
        &self,
    ) -> Result<Option<Arc<rustls::ServerConfig>>, Box<dyn std::error::Error>> {
        match (&self.host_loopback_tls, &self.listener_tls) {
            (Some(policy), None) => Ok(Some(policy.server_config()?)),
            (None, Some(policy)) => Ok(Some(host_tls::loopback_server_config(
                policy,
                self.listener.address,
            )?)),
            (None, None) => Ok(None),
            _ => Err("select one exact gateway TLS endpoint".into()),
        }
    }

    pub fn validate_polling(
        &self,
        interval_secs: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if interval_secs.is_some_and(|interval| {
            !(1..=86_400).contains(&interval)
                || self.spaces.is_empty()
                || self.spaces.len() > polling::MAX_SPACES
        }) {
            return Err(
                "WebDAV polling requires a 1–86400 second interval and 1–64 local spaces".into(),
            );
        }
        Ok(())
    }
}

pub fn load(path: &Path) -> Result<Runtime, Box<dyn std::error::Error>> {
    let bytes = super::config_file::read(path, 65_536)?;
    parse_original_bytes(&bytes)
}

pub(crate) fn parse_original_bytes(bytes: &[u8]) -> Result<Runtime, Box<dyn std::error::Error>> {
    let document = DeploymentGatewayConfig::parse_for_platform(
        bytes,
        if cfg!(windows) {
            DeploymentPlatform::Windows
        } else {
            DeploymentPlatform::Linux
        },
    )?;
    from_deployment_document(document)
}

fn from_deployment_document(
    document: DeploymentGatewayConfig,
) -> Result<Runtime, Box<dyn std::error::Error>> {
    document.validate(if cfg!(windows) {
        DeploymentPlatform::Windows
    } else {
        DeploymentPlatform::Linux
    })?;
    let runtime = Runtime {
        listener: document.listener,
        credentials: document.credentials,
        uploads: document.uploads,
        spaces: document.spaces,
        host_loopback_tls: document.host_loopback_tls.map(host_tls::HostLoopbackTls),
        listener_tls: document.listener_tls,
        #[cfg(windows)]
        collection_limits: document.collection_limits,
    };
    runtime.listener.validate()?;
    if let Some(policy) = &runtime.host_loopback_tls {
        policy.validate(runtime.listener.address)?;
    }
    if let Some(policy) = &runtime.listener_tls {
        policy.validate(runtime.listener.address)?;
    }
    if !runtime.credentials.is_absolute()
        || !runtime.uploads.is_absolute()
        || runtime.spaces.values().any(|path| !path.is_absolute())
        || runtime
            .listener
            .exports
            .iter()
            .any(|export| !runtime.spaces.contains_key(&export.space_id))
    {
        return Err("DAV requires explicit absolute local paths for all exports".into());
    }
    Ok(runtime)
}

pub fn serve(
    runtime: Runtime,
    limits: LocalLimits,
    scan_interval_secs: Option<u64>,
    shutdown: Arc<AtomicBool>,
    #[cfg(any(target_os = "linux", target_os = "android"))] control: Option<
        crate::local_control::GatewaySlot,
    >,
    #[cfg(target_os = "linux")] linux_owner: Option<
        std::sync::Arc<super::linux_namespace::LinuxDaemonOwner>,
    >,
) -> Result<(), Box<dyn std::error::Error>> {
    runtime.listener.validate()?;
    runtime.validate_polling(scan_interval_secs)?;
    if !runtime.listener.enabled && scan_interval_secs.is_none() {
        return Err("DAV listener disabled".into());
    }
    let tls = runtime
        .listener
        .enabled
        .then(|| runtime.selected_tls_config())
        .transpose()?
        .flatten();
    // Bind and authenticate before opening long-lived worktree owners, so a
    // rejected listener cannot initiate unattended recovery or scanning.
    let mut gateway = runtime
        .listener
        .enabled
        .then(|| Gateway::bind(&runtime))
        .transpose()?;
    // An explicitly configured preview owner or Linux publisher retains one
    // LocalSpace and Journal even without scanning. This loop is its actor.
    let shared_locals =
        scan_interval_secs.is_some() || super::management::restore_preview_owner_configured();
    #[cfg(target_os = "linux")]
    let shared_locals = shared_locals || linux_owner.is_some();
    let mut polling = if shared_locals {
        Some(polling::Polling::open(
            &runtime,
            &limits,
            scan_interval_secs,
            #[cfg(target_os = "linux")]
            linux_owner.as_deref(),
        )?)
    } else {
        None
    };
    let mut locks = Locks::default();
    let mut requests = 0u64;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let mut registration = gateway.as_ref().and_then(|active| {
        (tls.is_none()).then_some(())?;
        control.map(|slot| {
            crate::local_control::GatewayRegistration::register(
                slot,
                GatewayProbe::new(
                    Arc::clone(&active.listener),
                    runtime.listener.clone(),
                    Arc::clone(&active.credentials),
                ),
            )
        })
    });
    super::shutdown::started(scan_interval_secs.is_none())?;
    if let Some(active) = &gateway {
        super::management::observe_gateway(Some(&runtime.listener), runtime.scheme());
        println!(
            "{}",
            serde_json::json!({"webdav_listening":active.listener.local_addr()?,
            "listener_id":runtime.listener.listener_id,"authenticated":true,
            "scheme":runtime.scheme(),"authority":runtime.listener.address,
            "remote_backup_complete":false})
        );
    }
    while !shutdown.load(Ordering::Acquire) {
        if let Some(polling) = &mut polling {
            polling.scan_due(
                &shutdown,
                #[cfg(target_os = "linux")]
                linux_owner.as_deref(),
            );
            if shutdown.load(Ordering::Acquire) {
                break;
            }
        }
        let Some(active) = &gateway else {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        };
        let (stream, peer) = match active.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        handle_connection(
            &runtime,
            &limits,
            &mut locks,
            &active.credentials,
            polling.as_mut(),
            stream,
            peer,
            tls.as_ref(),
            #[cfg(target_os = "linux")]
            linux_owner.as_deref(),
        )?;
        requests += 1;
        if requests == runtime.listener.max_requests {
            if scan_interval_secs.is_none() {
                break;
            }
            // Preserve the explicit request bound without stopping local sync.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            drop(registration.take());
            gateway = None;
            super::management::observe_gateway(None, runtime.scheme());
        }
    }
    Ok(())
}

struct Gateway {
    listener: Arc<TcpListener>,
    credentials: Arc<Credentials>,
}

struct GatewayBindFailure {
    error: Box<dyn std::error::Error>,
    original_gateway: Option<Gateway>,
}

impl Gateway {
    fn prepare_credentials(
        runtime: &Runtime,
    ) -> Result<Arc<Credentials>, Box<dyn std::error::Error>> {
        private_upload_parent(&runtime.uploads)?;
        Ok(Arc::new(Credentials::load(
            &runtime.credentials,
            &runtime.listener,
        )?))
    }

    fn bind(runtime: &Runtime) -> Result<Self, Box<dyn std::error::Error>> {
        Self::bind_prepared(runtime, Self::prepare_credentials(runtime)?)
    }

    fn bind_prepared(
        runtime: &Runtime,
        credentials: Arc<Credentials>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::bind_retaining(runtime, credentials).map_err(|failure| failure.error)
    }

    fn bind_retaining(
        runtime: &Runtime,
        credentials: Arc<Credentials>,
    ) -> Result<Self, GatewayBindFailure> {
        let bind = runtime
            .host_loopback_tls
            .as_ref()
            .map_or(runtime.listener.address, |policy| policy.bind.into());
        let listener = TcpListener::bind(bind).map_err(|error| GatewayBindFailure {
            error: error.into(),
            original_gateway: None,
        })?;
        let gateway = Self {
            listener: Arc::new(listener),
            credentials,
        };
        if let Err(error) = gateway.listener.set_nonblocking(true) {
            return Err(GatewayBindFailure {
                error: error.into(),
                original_gateway: Some(gateway),
            });
        }
        Ok(gateway)
    }
}

fn handle_connection(
    runtime: &Runtime,
    limits: &LocalLimits,
    locks: &mut Locks,
    credentials: &Credentials,
    polling: Option<&mut polling::Polling>,
    stream: std::net::TcpStream,
    peer: SocketAddr,
    tls: Option<&Arc<rustls::ServerConfig>>,
    #[cfg(target_os = "linux")] linux_owner: Option<&super::linux_namespace::LinuxDaemonOwner>,
) -> std::io::Result<()> {
    with_authenticated_connection(
        runtime,
        credentials,
        stream,
        peer,
        tls,
        |account, request, connection| {
            dispatch(
                runtime,
                limits,
                locks,
                account,
                request,
                connection,
                polling,
                #[cfg(target_os = "linux")]
                linux_owner,
            )
        },
    )
}

/// Both ordinary and recovered owners use the same peer/TLS/framing/auth/Host
/// checks and refusal response; the callback selects the actual node owner.
fn with_authenticated_connection(
    runtime: &Runtime,
    credentials: &Credentials,
    stream: std::net::TcpStream,
    peer: SocketAddr,
    tls: Option<&Arc<rustls::ServerConfig>>,
    dispatch: impl FnOnce(&str, &Request, &mut Connection) -> Result<(), u16>,
) -> std::io::Result<()> {
    if !runtime.host_loopback_tls.as_ref().map_or_else(
        || peer.ip().is_loopback(),
        |policy| policy.permits(peer.ip()),
    ) {
        return Ok(());
    }
    // Accepted Windows sockets can inherit the nonblocking listener mode.
    // Request framing needs blocking reads with the connection deadline.
    stream.set_nonblocking(false)?;
    let Ok(mut connection) = Connection::new(stream, runtime.listener.request_timeout_secs, tls)
    else {
        // Reject a failed TLS handshake without taking down the listener.
        return Ok(());
    };
    authenticated_connection_protocol(runtime, credentials, &mut connection, dispatch)
}

fn authenticated_connection_protocol(
    runtime: &Runtime,
    credentials: &Credentials,
    connection: &mut Connection,
    dispatch: impl FnOnce(&str, &Request, &mut Connection) -> Result<(), u16>,
) -> std::io::Result<()> {
    let request = match Request::read(connection, runtime.listener.max_header_bytes) {
        Ok(request) => request,
        Err(_) => {
            let _ = http::response(connection, 400, b"invalid request", &[], false);
            return Ok(());
        }
    };
    let Some(account) = request
        .header("authorization")
        .and_then(|header| credentials.authenticate(header))
    else {
        let _ = http::response(
            connection,
            401,
            b"authentication required",
            &[(
                "WWW-Authenticate",
                format!(
                    "Basic realm=\"SyncExtend {}\"",
                    runtime.listener.listener_id
                ),
            )],
            request.method == "HEAD",
        );
        return Ok(());
    };
    if request.header("host") != Some(runtime.listener.address.to_string().as_str()) {
        let _ = http::response(connection, 400, b"listener authority differs", &[], false);
        return Ok(());
    }
    if let Err(status) = dispatch(account, &request, connection) {
        if !connection.response_started {
            let _ = http::response(
                connection,
                status,
                b"request refused; recheck resource state",
                &[],
                request.method == "HEAD",
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
struct OriginalAuthenticatedConnectionFailure {
    error: std::io::Error,
    close_error: Option<std::io::Error>,
    original_stream: Option<std::net::TcpStream>,
}

#[cfg(windows)]
fn copy_original_io_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}

#[cfg(windows)]
fn close_authenticated_original_stream(
    original: std::net::TcpStream,
    first_error: Option<std::io::Error>,
) -> Result<(), OriginalAuthenticatedConnectionFailure> {
    match sync_extend_platform_fs::close_original_tcp_stream(original) {
        Ok(_) => first_error.map_or(Ok(()), |error| {
            Err(OriginalAuthenticatedConnectionFailure {
                error,
                close_error: None,
                original_stream: None,
            })
        }),
        Err((original, error)) => Err(OriginalAuthenticatedConnectionFailure {
            error: first_error.unwrap_or_else(|| copy_original_io_error(&error)),
            close_error: Some(error),
            original_stream: Some(original),
        }),
    }
}

#[cfg(windows)]
fn with_authenticated_connection_retaining(
    runtime: &Runtime,
    credentials: &Credentials,
    stream: std::net::TcpStream,
    peer: SocketAddr,
    tls: Option<&Arc<rustls::ServerConfig>>,
    dispatch: impl FnOnce(&str, &Request, &mut Connection) -> Result<(), u16>,
) -> Result<(), OriginalAuthenticatedConnectionFailure> {
    if !runtime.host_loopback_tls.as_ref().map_or_else(
        || peer.ip().is_loopback(),
        |policy| policy.permits(peer.ip()),
    ) {
        return close_authenticated_original_stream(stream, None);
    }
    if let Err(error) = stream.set_nonblocking(false) {
        return close_authenticated_original_stream(stream, Some(error));
    }
    let mut connection =
        match Connection::new_retaining(stream, runtime.listener.request_timeout_secs, tls) {
            Ok(connection) => connection,
            Err(failure) => {
                // The original handshake refusal remains a per-request refusal.
                // Its original socket still has to close before returning.
                return close_authenticated_original_stream(failure.original_stream, None);
            }
        };
    let first_error =
        authenticated_connection_protocol(runtime, credentials, &mut connection, dispatch).err();
    match connection.close_retaining() {
        Ok(_) => first_error.map_or(Ok(()), |error| {
            Err(OriginalAuthenticatedConnectionFailure {
                error,
                close_error: None,
                original_stream: None,
            })
        }),
        Err((original, error)) => Err(OriginalAuthenticatedConnectionFailure {
            error: first_error.unwrap_or_else(|| copy_original_io_error(&error)),
            close_error: Some(error),
            original_stream: Some(original),
        }),
    }
}

fn private_upload_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("absolute private uploads required".into());
    }
    for ancestor in path
        .parent()
        .ok_or("upload parent absent")?
        .ancestors()
        .filter(|path| path.is_absolute())
    {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("upload parent symlink refused".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("upload parent reparse refused".into());
            }
        }
    }
    if !path.try_exists()? {
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("invalid upload directory".into());
    }
    #[cfg(windows)]
    {
        let _guard = sync_extend_platform_fs::LockedDirectory::open(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("upload directory must be owner only".into());
        }
    }
    Ok(())
}

fn dispatch(
    runtime: &Runtime,
    limits: &LocalLimits,
    locks: &mut Locks,
    account: &str,
    request: &Request,
    stream: &mut Connection,
    polling: Option<&mut polling::Polling>,
    #[cfg(target_os = "linux")] linux_owner: Option<&super::linux_namespace::LinuxDaemonOwner>,
) -> Result<(), u16> {
    let write = !matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "PROPFIND" | "OPTIONS"
    );
    let authorized = runtime
        .listener
        .authorize(account, &request.target, write)
        .map_err(|_| 403u16)?;
    let data = runtime.spaces.get(&authorized.space_id).ok_or(403u16)?;
    let native_write_supported = {
        #[cfg(windows)]
        {
            authorized.allow_native_windows_writes
        }
        #[cfg(target_os = "linux")]
        {
            linux_owner.is_some_and(|owner| owner.owns_metadata_root(data))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            false
        }
    };
    if matches!(
        request.method.as_str(),
        "PUT" | "DELETE" | "MOVE" | "COPY" | "MKCOL"
    ) && (!native_write_supported || (cfg!(target_os = "linux") && request.method != "PUT"))
    {
        return Err(501);
    }
    // Read and parse bounded XML metadata before opening LocalSpace.
    // Authentication and path authorization above still run first; this keeps
    // the original connection deadline from expiring during durable baseline work.
    let lock_xml = if request.method == "LOCK" && request.content_length != 0 {
        Some(body(request, stream)?)
    } else {
        None
    };
    if let Some(bytes) = lock_xml.as_deref() {
        webdav_xml::exclusive_write_lock(bytes).map_err(|_| 400u16)?;
    }
    let propfind_properties = if request.method == "PROPFIND" {
        let bytes = body(request, stream)?;
        Some(webdav_xml::properties(&bytes).map_err(|_| 400u16)?)
    } else {
        None
    };
    let mut transient;
    let local = if let Some(polling) = polling {
        polling.local(&authorized.space_id)?
    } else {
        transient = {
            #[cfg(target_os = "linux")]
            if let Some(owner) = linux_owner.filter(|owner| owner.owns_metadata_root(data)) {
                owner.open(data, limits.clone()).map_err(|_| 503u16)?
            } else {
                LocalSpace::open_with_limits(data, limits.clone()).map_err(|_| 503u16)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                LocalSpace::open_with_limits(data, limits.clone()).map_err(|_| 503u16)?
            }
        };
        &mut transient
    };
    if local.space_id != authorized.space_id {
        return Err(503);
    }
    let baseline = local.capture_webdav_baseline().map_err(core_status)?;
    super::management::observe_local_space(local);
    let entry = find(&baseline, authorized.path.as_ref());
    let Some(preconditions) = evaluate_resource_preconditions(
        runtime,
        locks,
        account,
        &authorized,
        baseline.manifest(),
        request,
        stream,
    )?
    else {
        return Ok(());
    };
    let ResourcePreconditions {
        tag,
        tokens,
        collection,
    } = preconditions;
    #[cfg(windows)]
    if matches!(
        request.method.as_str(),
        "MKCOL" | "DELETE" | "MOVE" | "COPY"
    ) {
        return collections::dispatch(
            runtime,
            limits,
            locks,
            account,
            &authorized,
            &tokens,
            request,
            local,
            baseline,
            stream,
        );
    }
    match request.method.as_str() {
        "OPTIONS" => {
            if request.content_length != 0 {
                return Err(400);
            }
            let writable = runtime
                .listener
                .authorize(account, &request.target, true)
                .is_ok();
            let allow = if writable && native_write_supported {
                #[cfg(windows)]
                {
                    "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MOVE, COPY, MKCOL, LOCK, UNLOCK"
                }
                #[cfg(target_os = "linux")]
                {
                    "OPTIONS, PROPFIND, GET, HEAD, PUT, LOCK, UNLOCK"
                }
                #[cfg(not(any(windows, target_os = "linux")))]
                {
                    "OPTIONS, PROPFIND, GET, HEAD, LOCK, UNLOCK"
                }
            } else if writable {
                "OPTIONS, PROPFIND, GET, HEAD, LOCK, UNLOCK"
            } else {
                "OPTIONS, PROPFIND, GET, HEAD"
            };
            http::response(
                stream,
                200,
                b"",
                &[("DAV", "1, 2".into()), ("Allow", allow.into())],
                false,
            )
            .map_err(|_| 500u16)
        }
        "GET" | "HEAD" => {
            let entry = entry.ok_or(404u16)?;
            let content = entry.content.as_ref().ok_or(405u16)?;
            let Some(reply) = prepare_read_reply(request, stream, content.length, tag)? else {
                return Ok(());
            };
            let read = local
                .acquire_webdav_read(&entry.path)
                .map_err(core_status)?;
            if request.method == "HEAD" || reply.length == 0 {
                local.finish_webdav_read(read).map_err(core_status)?;
                return http::head(stream, reply.status, reply.length, &reply.headers)
                    .map_err(|_| 500u16);
            }
            // Keep at most one byte in request memory. A client cannot finish
            // its Content-Length read before the lease terminal is durable.
            let mut writer = http::ReadTerminalWriter::new(stream);
            let outcome = (|| {
                http::head(
                    writer.connection(),
                    reply.status,
                    reply.length,
                    &reply.headers,
                )
                .map_err(|_| 500u16)?;
                local
                    .write_webdav_read(&read, reply.range, &mut writer)
                    .map_err(core_status)
            })();
            let release = local.finish_webdav_read(read).map_err(core_status);
            outcome.and(release)?;
            writer.finish().map_err(|_| 500u16)
        }
        "PROPFIND" => {
            let depth = match request.header("depth").unwrap_or("infinity") {
                "0" => 0,
                "1" => 1,
                "infinity" => return Err(403),
                _ => return Err(400),
            };
            if !collection && entry.is_none() {
                return Err(404);
            }
            let properties = propfind_properties.ok_or(400u16)?;
            let response = propfind(runtime, &authorized, &baseline, depth, &properties)?;
            http::response(
                stream,
                207,
                response.as_bytes(),
                &[("Content-Type", "application/xml; charset=utf-8".into())],
                false,
            )
            .map_err(|_| 500u16)
        }
        "PUT" => {
            if authorized.export_root || collection {
                return Err(405);
            }
            if !request.headers.contains_key("content-length") {
                return Err(411);
            }
            if request.header("content-range").is_some() {
                return Err(400);
            }
            if request.content_length > authorized.max_upload_bytes {
                return Err(413);
            }
            local
                .admit_webdav_upload(request.content_length)
                .map_err(core_status)?;
            #[cfg(target_os = "linux")]
            let native_request = {
                linux_owner
                    .ok_or(501u16)?
                    .require_publication_ready()
                    .map_err(core_status)?;
                let expected = baseline.snapshot_id().map_err(core_status)?;
                Some(
                    local
                        .admit_linux_native_webdav_put(
                            &expected,
                            authorized.path.as_ref().ok_or(405u16)?,
                        )
                        .map_err(core_status)?,
                )
            };
            // Start reception after all local capacity and baseline checks.
            // The configured ten-second body phase remains finite even when
            // native admission took longer than the header phase.
            stream.begin_body().map_err(|_| 400u16)?;
            if let Some(expect) = request.header("expect") {
                if !expect.eq_ignore_ascii_case("100-continue") {
                    return Err(417);
                }
                stream
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .map_err(|_| 400u16)?;
            }
            let upload = Upload::receive(stream, &runtime.uploads, request.content_length)
                .map_err(|error| match error {
                    ReceiveError::Body(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        408u16
                    }
                    ReceiveError::Body(_) => 400u16,
                    ReceiveError::Storage => 507u16,
                })?;
            upload.verify().map_err(|_| 409u16)?;
            let result = {
                #[cfg(target_os = "linux")]
                {
                    let owner = linux_owner.ok_or(501u16)?;
                    let request = native_request.ok_or(409u16)?;
                    let published =
                        match owner.commit_webdav_upload(local, request, upload.reader()) {
                            Ok(published) => published,
                            Err(failure) => {
                                if let Some(committed) = failure.committed {
                                    return committed_but_blocked(stream, &committed);
                                }
                                return Err(core_status(*failure.error));
                            }
                        };
                    WebDavCommit {
                        transaction_id: published.transaction_id,
                        snapshot_id: published.snapshot_id,
                        local_committed: published.local_committed,
                        remote_backup_complete: published.remote_backup_complete,
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    local
                        .commit_webdav_upload(
                            &baseline,
                            authorized.path.as_ref().ok_or(405u16)?,
                            upload.reader(),
                        )
                        .map_err(core_status)?
                }
            };
            #[cfg(target_os = "linux")]
            if upload.verify().is_err() {
                return committed_but_blocked(stream, &result);
            }
            #[cfg(not(target_os = "linux"))]
            upload.verify().map_err(|_| 409u16)?;
            committed(stream, if entry.is_some() { 204 } else { 201 }, &result)
        }
        "DELETE" => {
            if request.content_length != 0 {
                return Err(400);
            }
            if authorized.export_root {
                return Err(405);
            }
            if collection {
                return Err(501);
            }
            let path = &entry.ok_or(404u16)?.path;
            let result = local
                .delete_webdav_file(&baseline, path)
                .map_err(core_status)?;
            committed(stream, 204, &result)
        }
        "MOVE" | "COPY" => {
            if request.content_length != 0 {
                return Err(400);
            }
            if authorized.export_root || collection {
                return Err(501);
            }
            let source = entry.ok_or(404u16)?;
            let destination = resource(
                runtime,
                account,
                request.header("destination").ok_or(400u16)?,
                true,
            )?;
            if destination.export_name != authorized.export_name
                || destination.export_root
                || destination.space_id != authorized.space_id
            {
                return Err(403);
            }
            let destination_path = destination.path.as_ref().ok_or(405u16)?;
            if destination_path.collision_key() == source.path.collision_key() {
                return Err(403);
            }
            if !locks.allowed(account, &destination, &tokens, true) {
                return Err(423);
            }
            let overwrite = match request.header("overwrite").unwrap_or("T") {
                "T" => true,
                "F" => false,
                _ => return Err(400),
            };
            if find(&baseline, Some(destination_path)).is_some() {
                return Err(if overwrite { 501 } else { 412 });
            }
            if request
                .header("depth")
                .is_some_and(|depth| depth != "0" && depth != "infinity")
            {
                return Err(400);
            }
            let result = if request.method == "MOVE" {
                local.move_webdav_file(&baseline, &source.path, destination_path)
            } else {
                local.copy_webdav_file(&baseline, &source.path, destination_path)
            }
            .map_err(core_status)?;
            committed(stream, 201, &result)
        }
        "LOCK" => {
            if entry.is_none() && !collection {
                return Err(404);
            }
            let seconds = timeout(request.header("timeout"))?;
            let token = if request.content_length == 0 {
                if tokens.len() != 1 || !locks.refresh(account, &authorized, &tokens[0], seconds) {
                    return Err(412);
                }
                tokens[0].clone()
            } else {
                let recursive = match request.header("depth").unwrap_or("infinity") {
                    "0" => false,
                    "infinity" => true,
                    _ => return Err(400),
                };
                locks
                    .acquire(account, &authorized, recursive, seconds)
                    .ok_or(423u16)?
            };
            let xml=format!("<?xml version=\"1.0\"?><D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:timeout>Second-{seconds}</D:timeout><D:locktoken><D:href>{}</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>",http::xml(&token));
            http::response(
                stream,
                200,
                xml.as_bytes(),
                &[
                    ("Content-Type", "application/xml; charset=utf-8".into()),
                    ("Lock-Token", format!("<{token}>")),
                ],
                false,
            )
            .map_err(|_| 500u16)
        }
        "UNLOCK" => {
            if request.content_length != 0 {
                return Err(400);
            }
            let token = request
                .header("lock-token")
                .and_then(|value| value.strip_prefix('<'))
                .and_then(|value| value.strip_suffix('>'))
                .ok_or(400u16)?;
            if !super::webdav_locks::valid_token(token) {
                return Err(400);
            }
            if !locks.unlock(account, &authorized, token) {
                return Err(409);
            }
            http::response(stream, 204, b"", &[], false).map_err(|_| 500u16)
        }
        "MKCOL" => Err(501),
        _ => Err(405),
    }
}

fn find<'a>(baseline: &'a WebDavBaseline, path: Option<&PortablePath>) -> Option<&'a Entry> {
    find_manifest(baseline.manifest(), path)
}

fn find_manifest<'a>(manifest: &'a Manifest, path: Option<&PortablePath>) -> Option<&'a Entry> {
    let path = path?;
    manifest.entries.values().find(|entry| &entry.path == path)
}

struct ResourcePreconditions {
    tag: Option<String>,
    tokens: Vec<String>,
    collection: bool,
}

fn evaluate_resource_preconditions(
    runtime: &Runtime,
    locks: &mut Locks,
    account: &str,
    authorized: &AuthorizedWebDavPath,
    manifest: &Manifest,
    request: &Request,
    stream: &mut Connection,
) -> Result<Option<ResourcePreconditions>, u16> {
    let entry = find_manifest(manifest, authorized.path.as_ref());
    if authorized.export_root && authorized.path.is_some() && entry.is_none() {
        return Err(503);
    }
    let tag = entry
        .map(webdav::resource_etag)
        .transpose()
        .map_err(|_| 500u16)?;
    if !webdav::if_match(request.header("if-match"), tag.as_deref()).map_err(|_| 400u16)? {
        return Err(412);
    }
    if !webdav::if_none_match(request.header("if-none-match"), tag.as_deref())
        .map_err(|_| 400u16)?
    {
        if matches!(request.method.as_str(), "GET" | "HEAD") {
            http::head(stream, 304, 0, &[("ETag", tag.unwrap_or_default())]).map_err(|_| 500u16)?;
            return Ok(None);
        }
        return Err(412);
    }
    let tokens = evaluate_manifest_conditions(
        runtime,
        locks,
        account,
        authorized,
        manifest,
        request.header("if"),
    )?;
    let collection =
        entry.is_some_and(|entry| entry.kind == EntryKind::Directory) || authorized.path.is_none();
    let write = !matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "PROPFIND" | "OPTIONS"
    );
    if write
        && request.method != "UNLOCK"
        && !locks.allowed(account, authorized, &tokens, collection)
    {
        return Err(423);
    }
    Ok(Some(ResourcePreconditions {
        tag,
        tokens,
        collection,
    }))
}

struct ReadReply {
    range: Option<(u64, u64)>,
    length: u64,
    status: u16,
    headers: Vec<(&'static str, String)>,
}

fn prepare_read_reply(
    request: &Request,
    stream: &mut Connection,
    content_length: u64,
    tag: Option<String>,
) -> Result<Option<ReadReply>, u16> {
    if request.content_length != 0 {
        return Err(400);
    }
    let range_header = if request
        .header("if-range")
        .is_none_or(|value| Some(value) == tag.as_deref())
    {
        request.header("range")
    } else {
        None
    };
    let range = match webdav::byte_range(range_header, content_length) {
        Ok(range) => range,
        Err(_) => {
            http::response(
                stream,
                416,
                b"",
                &[("Content-Range", format!("bytes */{content_length}"))],
                false,
            )
            .map_err(|_| 500u16)?;
            return Ok(None);
        }
    };
    let mut headers = vec![
        ("ETag", tag.unwrap_or_default()),
        ("Accept-Ranges", "bytes".into()),
        ("Content-Type", "application/octet-stream".into()),
    ];
    let length = range.map_or(content_length, |(start, end)| end - start + 1);
    if let Some((start, end)) = range {
        headers.push((
            "Content-Range",
            format!("bytes {start}-{end}/{content_length}"),
        ));
    }
    Ok(Some(ReadReply {
        range,
        length,
        status: if range.is_some() { 206 } else { 200 },
        headers,
    }))
}

fn core_status(error: ReconcileError) -> u16 {
    match error {
        ReconcileError::ResourceLimit(_) => 507,
        ReconcileError::Unstable => 412,
        ReconcileError::Invariant(_)
        | ReconcileError::Journal(sync_extend_journal::JournalError::Invariant(_)) => 409,
        _ => 503,
    }
}
fn body(request: &Request, stream: &mut impl Read) -> Result<Vec<u8>, u16> {
    if request.content_length > 65536 {
        return Err(413);
    }
    let mut bytes = vec![0; request.content_length as usize];
    stream.read_exact(&mut bytes).map_err(|_| 400u16)?;
    Ok(bytes)
}
fn committed(stream: &mut Connection, status: u16, result: &WebDavCommit) -> Result<(), u16> {
    if !result.local_committed || result.remote_backup_complete {
        return Err(500);
    }
    http::response(
        stream,
        status,
        b"",
        &[
            (
                "X-SyncExtend-Transaction",
                result.transaction_id.to_string(),
            ),
            ("X-SyncExtend-Snapshot", result.snapshot_id.to_string()),
            ("X-SyncExtend-Local-Committed", "true".into()),
            ("X-SyncExtend-Remote-Backup-Complete", "false".into()),
        ],
        false,
    )
    .map_err(|_| 500u16)
}

#[cfg(target_os = "linux")]
fn committed_but_blocked(stream: &mut Connection, result: &WebDavCommit) -> Result<(), u16> {
    if !result.local_committed || result.remote_backup_complete {
        return Err(500);
    }
    http::response(
        stream,
        503,
        b"File committed locally; publication cleanup is blocked. Recheck the file before retrying.",
        &[
            ("X-SyncExtend-Transaction", result.transaction_id.to_string()),
            ("X-SyncExtend-Snapshot", result.snapshot_id.to_string()),
            ("X-SyncExtend-Local-Committed", "true".into()),
            ("X-SyncExtend-Remote-Backup-Complete", "false".into()),
            ("X-SyncExtend-Publication-Ready", "false".into()),
        ],
        false,
    )
    .map_err(|_| 500u16)
}
fn timeout(value: Option<&str>) -> Result<u64, u16> {
    match value.unwrap_or("Second-300") {
        "Infinite" => Ok(3600),
        value => {
            let seconds = value.strip_prefix("Second-").ok_or(400u16)?;
            if seconds.is_empty() || !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(400);
            }
            Ok(seconds.parse::<u64>().map_err(|_| 400u16)?.clamp(1, 3600))
        }
    }
}
fn resource(
    runtime: &Runtime,
    account: &str,
    value: &str,
    write: bool,
) -> Result<AuthorizedWebDavPath, u16> {
    let target = if value.starts_with('/') {
        value
    } else {
        let scheme_prefix = format!("{}://", runtime.scheme());
        let remainder = value.strip_prefix(&scheme_prefix).ok_or(403u16)?;
        let (authority, target) = remainder.split_once('/').ok_or(400u16)?;
        if authority != runtime.listener.address.to_string() {
            return Err(403);
        }
        // Preserve the slash with a borrowed slice of the original input.
        &value[value.len() - target.len() - 1..]
    };
    runtime
        .listener
        .authorize(account, target, write)
        .map_err(|_| 403u16)
}
fn evaluate_conditions(
    runtime: &Runtime,
    locks: &mut Locks,
    account: &str,
    requested: &AuthorizedWebDavPath,
    baseline: &WebDavBaseline,
    value: Option<&str>,
) -> Result<Vec<String>, u16> {
    evaluate_manifest_conditions(
        runtime,
        locks,
        account,
        requested,
        baseline.manifest(),
        value,
    )
}

fn evaluate_manifest_conditions(
    runtime: &Runtime,
    locks: &mut Locks,
    account: &str,
    requested: &AuthorizedWebDavPath,
    manifest: &Manifest,
    value: Option<&str>,
) -> Result<Vec<String>, u16> {
    let lists = conditions::parse(value).map_err(|_| 400u16)?;
    let mut groups: BTreeMap<String, Vec<&conditions::List>> = BTreeMap::new();
    for list in &lists {
        groups
            .entry(list.resource.clone().unwrap_or_default())
            .or_default()
            .push(list);
    }
    let mut tokens = Vec::new();
    for (name, lists) in groups {
        let path = if name.is_empty() {
            requested.clone()
        } else {
            resource(runtime, account, &name, false)?
        };
        if path.export_name != requested.export_name || path.space_id != requested.space_id {
            return Err(403);
        }
        let tag = find_manifest(manifest, path.path.as_ref())
            .map(webdav::resource_etag)
            .transpose()
            .map_err(|_| 500u16)?;
        let mut satisfied = false;
        for list in lists {
            let matches = list.conditions.iter().all(|condition| {
                let actual = if condition.etag {
                    tag.as_deref() == Some(condition.value.as_str())
                } else {
                    locks.token_matches(account, &path, &condition.value)
                };
                actual != condition.negated
            });
            if matches {
                satisfied = true;
                tokens.extend(
                    list.conditions
                        .iter()
                        .filter(|condition| !condition.negated && !condition.etag)
                        .map(|condition| condition.value.clone()),
                );
            }
        }
        if !satisfied {
            return Err(412);
        }
    }
    tokens.sort();
    tokens.dedup();
    Ok(tokens)
}

fn propfind(
    runtime: &Runtime,
    path: &AuthorizedWebDavPath,
    baseline: &WebDavBaseline,
    depth: u8,
    properties: &Properties,
) -> Result<String, u16> {
    propfind_manifest(runtime, path, baseline.manifest(), depth, properties)
}

fn propfind_manifest(
    runtime: &Runtime,
    path: &AuthorizedWebDavPath,
    manifest: &Manifest,
    depth: u8,
    properties: &Properties,
) -> Result<String, u16> {
    let export = runtime
        .listener
        .exports
        .iter()
        .find(|export| export.name == path.export_name)
        .ok_or(403u16)?;
    let mut rows = Vec::new();
    rows.push((
        path.path.as_ref(),
        find_manifest(manifest, path.path.as_ref()),
    ));
    if depth == 1 {
        let parent = path.path.as_ref().map_or("", |path| path.as_str());
        for entry in manifest.entries.values() {
            let (entry_parent, _) = entry
                .path
                .as_str()
                .rsplit_once('/')
                .unwrap_or(("", entry.path.as_str()));
            if entry_parent == parent {
                rows.push((Some(&entry.path), Some(entry)));
            }
            if rows.len() > 4096 {
                return Err(507);
            }
        }
    }
    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    for (path, entry) in rows {
        let tail = match (&export.subtree, path) {
            (Some(prefix), Some(path)) => path
                .as_str()
                .strip_prefix(prefix.as_str())
                .ok_or(403u16)?
                .trim_start_matches('/'),
            (None, Some(path)) => path.as_str(),
            (_, None) => "",
        };
        let collection = entry.is_none_or(|entry| entry.kind == EntryKind::Directory);
        let href = format!(
            "/{}/{}{}",
            export.name,
            http::href(tail),
            if collection && !tail.is_empty() {
                "/"
            } else {
                ""
            }
        );
        let default = [
            "displayname",
            "resourcetype",
            "getcontentlength",
            "getetag",
            "getcontenttype",
        ];
        let requested = match properties {
            Properties::All | Properties::Names => default
                .iter()
                .map(|name| ("DAV:".to_owned(), (*name).to_owned()))
                .collect::<Vec<_>>(),
            Properties::Selected(properties) => properties.clone(),
        };
        let mut ok = String::new();
        let mut missing = String::new();
        for (namespace, name) in requested {
            let value = match (namespace.as_str(), name.as_str()) {
                ("DAV:", "displayname") => Some(http::xml(
                    tail.rsplit('/')
                        .next()
                        .filter(|name| !name.is_empty())
                        .unwrap_or(&export.name),
                )),
                ("DAV:", "resourcetype") => Some(if collection {
                    "<D:collection/>".into()
                } else {
                    String::new()
                }),
                ("DAV:", "getcontentlength") => entry
                    .and_then(|entry| entry.content.as_ref())
                    .map(|content| content.length.to_string()),
                ("DAV:", "getetag") => entry
                    .map(webdav::resource_etag)
                    .transpose()
                    .map_err(|_| 500u16)?
                    .map(|value| http::xml(&value)),
                ("DAV:", "getcontenttype") => Some(if collection {
                    "httpd/unix-directory".into()
                } else {
                    "application/octet-stream".into()
                }),
                _ => None,
            };
            let element = format!("<P:{name} xmlns:P=\"{}\"", http::xml(&namespace));
            if let Some(value) = value {
                if matches!(properties, Properties::Names) {
                    ok.push_str(&format!("{element}/>"));
                } else {
                    ok.push_str(&format!("{element}>{value}</P:{name}>"));
                }
            } else {
                missing.push_str(&format!("{element}/>"));
            }
        }
        xml.push_str(&format!(
            "<D:response><D:href>{}</D:href>",
            http::xml(&href)
        ));
        for (status, properties) in [("200 OK", ok), ("404 Not Found", missing)] {
            if !properties.is_empty() {
                xml.push_str(&format!("<D:propstat><D:prop>{properties}</D:prop><D:status>HTTP/1.1 {status}</D:status></D:propstat>"));
            }
        }
        xml.push_str("</D:response>");
        if xml.len() > 4 * 1024 * 1024 {
            return Err(507);
        }
    }
    xml.push_str("</D:multistatus>");
    Ok(xml)
}
