//! The recovered gateway borrows only the actual fresh DeploymentRun.
//! Ordinary LocalSpace/polling constructors are absent from this actor.
use super::*;
use sync_extend_core_model::deployment::DeploymentGatewayConfig;
use sync_extend_reconcile::DeploymentRun;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct PreparedRecoveredGateway {
    runtime: Runtime,
    limits: LocalLimits,
    credentials: Arc<Credentials>,
    tls: Option<Arc<rustls::ServerConfig>>,
}

pub(crate) struct ActiveRecoveredGateway {
    runtime: Runtime,
    limits: LocalLimits,
    gateway: Gateway,
    tls: Option<Arc<rustls::ServerConfig>>,
    locks: Locks,
    requests: u64,
    failed_connections: Vec<std::net::TcpStream>,
    first_resource_close_error: Option<std::io::Error>,
}

pub(crate) struct RecoveredGatewayCloseFailure {
    pub error: Box<dyn std::error::Error>,
    pub original_listener: Option<Arc<TcpListener>>,
    pub original_connections: Vec<std::net::TcpStream>,
}

pub(crate) struct RecoveredGatewayStartFailure {
    pub error: Box<dyn std::error::Error>,
    pub original_gateway: Option<ActiveRecoveredGateway>,
}

impl RecoveredGatewayCloseFailure {
    pub(crate) fn has_retained_originals(&self) -> bool {
        self.original_listener.is_some() || !self.original_connections.is_empty()
    }

    /// Resource ending only: never bind a listener or acquire another node.
    /// The first error survives even when these same originals later close.
    pub(crate) fn close_remaining(mut self) -> Self {
        let mut remaining = Vec::new();
        for original in self.original_connections.drain(..) {
            if let Err((original, _later_error)) =
                sync_extend_platform_fs::close_original_tcp_stream(original)
            {
                remaining.push(original);
            }
        }
        self.original_connections = remaining;
        if let Some(original) = self.original_listener.take() {
            self.original_listener = match Arc::try_unwrap(original) {
                Ok(original) => {
                    match sync_extend_platform_fs::close_original_tcp_listener(original) {
                        Ok(_) => None,
                        Err((original, _later_error)) => Some(Arc::new(original)),
                    }
                }
                Err(original) => Some(original),
            };
        }
        self
    }

    pub(crate) fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}

impl PreparedRecoveredGateway {
    /// Every rejection here precedes fresh node/session or listener effects.
    pub(crate) fn new(
        document: DeploymentGatewayConfig,
        limits: LocalLimits,
        scan_interval_secs: Option<u64>,
    ) -> Result<Self> {
        limits.validate()?;
        let runtime = from_deployment_document(document)?;
        runtime.validate_polling(scan_interval_secs)?;
        if !runtime.listener.enabled {
            return Err("the recovered deployment listener is disabled".into());
        }
        if let Some(policy) = &runtime.collection_limits {
            policy.validate(&limits)?;
        }
        let credentials = Gateway::prepare_credentials(&runtime)?;
        let tls = runtime.selected_tls_config()?;
        Ok(Self {
            runtime,
            limits,
            credentials,
            tls,
        })
    }

    pub(crate) fn start(
        self,
        run: &DeploymentRun<'_>,
    ) -> std::result::Result<ActiveRecoveredGateway, RecoveredGatewayStartFailure> {
        run.verify().map_err(|error| RecoveredGatewayStartFailure {
            error: error.into(),
            original_gateway: None,
        })?;
        for export in &self.runtime.listener.exports {
            run.manifest(&export.space_id)
                .map_err(|error| RecoveredGatewayStartFailure {
                    error: error.into(),
                    original_gateway: None,
                })?;
        }
        let gateway = match Gateway::bind_retaining(&self.runtime, self.credentials) {
            Ok(gateway) => gateway,
            Err(failure) => {
                return Err(RecoveredGatewayStartFailure {
                    error: failure.error,
                    original_gateway: failure.original_gateway.map(|gateway| {
                        ActiveRecoveredGateway {
                            runtime: self.runtime,
                            limits: self.limits,
                            gateway,
                            tls: self.tls,
                            locks: Locks::default(),
                            requests: 0,
                            failed_connections: Vec::new(),
                            first_resource_close_error: None,
                        }
                    }),
                });
            }
        };
        let active = ActiveRecoveredGateway {
            runtime: self.runtime,
            limits: self.limits,
            gateway,
            tls: self.tls,
            locks: Locks::default(),
            requests: 0,
            failed_connections: Vec::new(),
            first_resource_close_error: None,
        };
        // Post-bind verification failure retains the actual listener for the
        // owner's same explicit close pipeline, including socket-close errors.
        if let Err(error) = run.verify() {
            return Err(RecoveredGatewayStartFailure {
                error: error.into(),
                original_gateway: Some(active),
            });
        }
        super::super::management::observe_gateway(
            Some(&active.runtime.listener),
            active.runtime.scheme(),
        );
        Ok(active)
    }
}

impl ActiveRecoveredGateway {
    pub(crate) fn exhausted(&self) -> bool {
        self.requests >= self.runtime.listener.max_requests
    }

    pub(crate) fn status(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "listener": self.gateway.listener.local_addr()?,
            "listener_id": self.runtime.listener.listener_id,
            "scheme": self.runtime.scheme(),
            "authenticated": true,
            "requests": self.requests,
            "max_requests": self.runtime.listener.max_requests,
            "exports": self.runtime.listener.exports.iter().map(|export| serde_json::json!({
                "name": export.name,
                "space_id": export.space_id,
                "writable": export.writable,
            })).collect::<Vec<_>>(),
            "ordinary_local_space_opened": false,
            "remote_backup_complete": false,
        }))
    }

    pub(crate) fn poll(&mut self, run: &mut DeploymentRun<'_>) -> Result<bool> {
        if self.exhausted() {
            return Ok(false);
        }
        let (stream, peer) = match self.gateway.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = run.verify() {
            if let Err((original, close_error)) =
                sync_extend_platform_fs::close_original_tcp_stream(stream)
            {
                self.first_resource_close_error.get_or_insert(close_error);
                self.failed_connections.push(original);
            }
            return Err(error.into());
        }
        let runtime = &self.runtime;
        let limits = &self.limits;
        let locks = &mut self.locks;
        if let Err(failure) = with_authenticated_connection_retaining(
            runtime,
            &self.gateway.credentials,
            stream,
            peer,
            self.tls.as_ref(),
            |account, request, connection| {
                run.prepare_gateway_observation().map_err(core_status)?;
                let response = dispatch_recovered(runtime, limits, locks, run, account, request, connection);
                let released = run.release_gateway_observation().map_err(core_status);
                response.and(released)
            },
        ) {
            if let Some(error) = failure.close_error {
                self.first_resource_close_error.get_or_insert(error);
            }
            if let Some(original) = failure.original_stream {
                self.failed_connections.push(original);
            }
            return Err(failure.error.into());
        }
        self.requests += 1;
        run.verify()?;
        Ok(true)
    }

    pub(crate) fn close(
        self,
    ) -> std::result::Result<serde_json::Value, RecoveredGatewayCloseFailure> {
        let Self {
            runtime,
            gateway,
            requests,
            failed_connections,
            first_resource_close_error,
            ..
        } = self;
        let mut first_error: Option<Box<dyn std::error::Error>> =
            first_resource_close_error.map(|error| error.into());
        let mut original_connections = Vec::new();
        for original in failed_connections {
            if let Err((original, error)) =
                sync_extend_platform_fs::close_original_tcp_stream(original)
            {
                first_error.get_or_insert(error.into());
                original_connections.push(original);
            }
        }
        let Gateway {
            listener,
            credentials,
        } = gateway;
        let listener = match Arc::try_unwrap(listener) {
            Ok(listener) => listener,
            Err(listener) => {
                return Err(RecoveredGatewayCloseFailure {
                    error: first_error.unwrap_or_else(|| {
                        "the actual recovered listener has an outstanding borrow".into()
                    }),
                    original_listener: Some(listener),
                    original_connections,
                });
            }
        };
        if let Err((listener, error)) =
            sync_extend_platform_fs::close_original_tcp_listener(listener)
        {
            return Err(RecoveredGatewayCloseFailure {
                error: first_error.unwrap_or_else(|| error.into()),
                original_listener: Some(Arc::new(listener)),
                original_connections,
            });
        }
        drop(credentials);
        super::super::management::observe_gateway(None, runtime.scheme());
        if let Some(error) = first_error {
            return Err(RecoveredGatewayCloseFailure {
                error,
                original_listener: None,
                original_connections,
            });
        }
        Ok(serde_json::json!({
            "actual_owned_listener_socket_close_succeeded": true,
            "completed_requests": requests,
            "services_started": false,
        }))
    }
}

fn dispatch_recovered(
    runtime: &Runtime,
    limits: &LocalLimits,
    locks: &mut Locks,
    run: &mut DeploymentRun<'_>,
    account: &str,
    request: &Request,
    stream: &mut Connection,
) -> std::result::Result<(), u16> {
    let write = !matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "PROPFIND" | "OPTIONS"
    );
    let authorized = runtime
        .listener
        .authorize(account, &request.target, write)
        .map_err(|_| 403u16)?;
    let native_write_supported = authorized.allow_native_windows_writes;
    if matches!(
        request.method.as_str(),
        "PUT" | "DELETE" | "MOVE" | "COPY" | "MKCOL"
    ) && !native_write_supported
    {
        return Err(501);
    }
    if !runtime.spaces.contains_key(&authorized.space_id) {
        return Err(403);
    }
    let lock_xml = if request.method == "LOCK" && request.content_length != 0 {
        Some(body(request, stream)?)
    } else {
        None
    };
    if let Some(bytes) = lock_xml.as_deref() {
        webdav_xml::exclusive_write_lock(bytes).map_err(|_| 400u16)?;
    }
    let properties = if request.method == "PROPFIND" {
        let bytes = body(request, stream)?;
        Some(webdav_xml::properties(&bytes).map_err(|_| 400u16)?)
    } else {
        None
    };
    let manifest = run.manifest(&authorized.space_id).map_err(core_status)?;
    let entry = find_manifest(&manifest, authorized.path.as_ref());
    let Some(preconditions) = evaluate_resource_preconditions(
        runtime,
        locks,
        account,
        &authorized,
        &manifest,
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
                "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MOVE, COPY, MKCOL, LOCK, UNLOCK"
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
            if request.method == "HEAD" || reply.length == 0 {
                run.verify().map_err(core_status)?;
                return http::head(stream, reply.status, reply.length, &reply.headers)
                    .map_err(|_| 500u16);
            }
            let bytes = run
                .read_file_bytes(&authorized.space_id, &entry.path, limits.max_file_bytes)
                .map_err(core_status)?;
            let (start, end) = reply.range.map_or((0, bytes.len()), |(start, end)| {
                (start as usize, end as usize + 1)
            });
            let bytes = bytes.get(start..end).ok_or(409u16)?;
            if bytes.len() as u64 != reply.length {
                return Err(409);
            }
            run.verify().map_err(core_status)?;
            http::head(stream, reply.status, reply.length, &reply.headers).map_err(|_| 500u16)?;
            stream.write_all(bytes).map_err(|_| 500u16)?;
            stream.flush().map_err(|_| 500u16)
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
            let response = propfind_manifest(
                runtime,
                &authorized,
                &manifest,
                depth,
                &properties.ok_or(400u16)?,
            )?;
            run.verify().map_err(core_status)?;
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
            if request.content_length > authorized.max_upload_bytes
                || request.content_length > limits.max_file_bytes
                || request.content_length > limits.max_staging_bytes
            {
                return Err(413);
            }
            let expected = manifest.root().map_err(|_| 500u16)?;
            run.verify().map_err(core_status)?;
            let bytes = receive_recovered_upload(request, stream)?;
            let committed = run
                .gateway_authorized_put(
                    account,
                    &request.target,
                    &expected,
                    &bytes,
                    mutation_timestamp()?,
                )
                .map_err(core_status)?;
            recovered_committed(stream, if entry.is_some() { 204 } else { 201 }, committed)
        }
        "MKCOL" => {
            if request.content_length != 0 {
                return Err(415);
            }
            if authorized.export_root {
                return Err(405);
            }
            if entry.is_some() {
                return Err(405);
            }
            let committed = run
                .gateway_authorized_mkdir(
                    account,
                    &request.target,
                    &manifest.root().map_err(|_| 500u16)?,
                    mutation_timestamp()?,
                )
                .map_err(core_status)?;
            recovered_committed(stream, 201, committed)
        }
        "DELETE" => {
            if request.content_length != 0 {
                return Err(400);
            }
            if authorized.export_root {
                return Err(405);
            }
            let entry = entry.ok_or(404u16)?;
            if request
                .header("depth")
                .is_some_and(|depth| depth != "infinity")
            {
                return Err(400);
            }
            if collection && manifest_has_children(&manifest, &entry.path) {
                return Err(501);
            }
            let committed = run
                .gateway_authorized_delete(
                    account,
                    &request.target,
                    &manifest.root().map_err(|_| 500u16)?,
                    mutation_timestamp()?,
                )
                .map_err(core_status)?;
            recovered_committed(stream, 204, committed)
        }
        "COPY" | "MOVE" => {
            if request.content_length != 0 {
                return Err(400);
            }
            if authorized.export_root {
                return Err(405);
            }
            let source = entry.ok_or(404u16)?;
            let destination_header = request.header("destination").ok_or(400u16)?;
            let destination = resource(runtime, account, destination_header, true)?;
            if destination.listener_id != authorized.listener_id
                || destination.export_name != authorized.export_name
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
            let destination_entry = find_manifest(&manifest, Some(destination_path));
            if !overwrite && destination_entry.is_some() {
                return Err(412);
            }
            if request.method == "MOVE" {
                if request
                    .header("depth")
                    .is_some_and(|depth| depth != "infinity")
                {
                    return Err(400);
                }
                if destination_entry.is_some()
                    || collection && manifest_has_children(&manifest, &source.path)
                {
                    return Err(501);
                }
            } else {
                if request
                    .header("depth")
                    .is_some_and(|depth| depth != "0" && depth != "infinity")
                {
                    return Err(400);
                }
                if collection {
                    return Err(501);
                }
                if destination_entry.is_some_and(|entry| entry.kind != EntryKind::File) {
                    return Err(409);
                }
            }
            let target = recovered_destination_target(runtime, destination_header)?;
            let expected = manifest.root().map_err(|_| 500u16)?;
            let timestamp = mutation_timestamp()?;
            let committed = if request.method == "MOVE" {
                run.gateway_authorized_move(account, &request.target, target, &expected, timestamp)
            } else {
                run.gateway_authorized_copy(
                    account,
                    &request.target,
                    target,
                    &expected,
                    overwrite,
                    timestamp,
                )
            }
            .map_err(core_status)?;
            recovered_committed(
                stream,
                if destination_entry.is_some() {
                    204
                } else {
                    201
                },
                committed,
            )
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
            let xml = format!("<?xml version=\"1.0\"?><D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:timeout>Second-{seconds}</D:timeout><D:locktoken><D:href>{}</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>", http::xml(&token));
            run.verify().map_err(core_status)?;
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
            if !super::super::webdav_locks::valid_token(token) {
                return Err(400);
            }
            if !locks.unlock(account, &authorized, token) {
                return Err(409);
            }
            run.verify().map_err(core_status)?;
            http::response(stream, 204, b"", &[], false).map_err(|_| 500u16)
        }
        _ => Err(405),
    }
}

fn receive_recovered_upload(
    request: &Request,
    stream: &mut Connection,
) -> std::result::Result<Vec<u8>, u16> {
    if request
        .header("expect")
        .is_some_and(|expect| !expect.eq_ignore_ascii_case("100-continue"))
    {
        return Err(417);
    }
    let length: usize = request.content_length.try_into().map_err(|_| 507u16)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| 507u16)?;
    bytes.resize(length, 0);
    stream.begin_body().map_err(|_| 400u16)?;
    if request.header("expect").is_some() {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| 400u16)?;
    }
    stream.read_exact(&mut bytes).map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            408u16
        } else {
            400u16
        }
    })?;
    Ok(bytes)
}

fn mutation_timestamp() -> std::result::Result<u64, u16> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| 500u16)?
        .as_millis()
        .try_into()
        .map_err(|_| 500u16)
}

fn recovered_destination_target<'a>(
    runtime: &Runtime,
    value: &'a str,
) -> std::result::Result<&'a str, u16> {
    if value.starts_with('/') {
        return Ok(value);
    }
    let prefix = format!("{}://", runtime.scheme());
    let (authority, target) = value
        .strip_prefix(&prefix)
        .ok_or(403u16)?
        .split_once('/')
        .ok_or(400u16)?;
    if authority != runtime.listener.address.to_string() {
        return Err(403);
    }
    Ok(&value[value.len() - target.len() - 1..])
}

fn manifest_has_children(manifest: &Manifest, path: &PortablePath) -> bool {
    let prefix = format!("{}/", path.as_str());
    manifest
        .entries
        .values()
        .any(|entry| entry.path.as_str().starts_with(&prefix))
}

fn recovered_committed(
    stream: &mut Connection,
    status: u16,
    snapshot: sync_extend_core_model::SnapshotId,
) -> std::result::Result<(), u16> {
    // The fresh node returns its actual committed root. Its history transaction
    // remains private; no unrelated HTTP ID substitutes for that native owner.
    http::response(
        stream,
        status,
        b"",
        &[
            ("X-SyncExtend-Snapshot", snapshot.to_string()),
            ("X-SyncExtend-Local-Committed", "true".into()),
            ("X-SyncExtend-Remote-Backup-Complete", "false".into()),
        ],
        false,
    )
    .map_err(|_| 500u16)
}
