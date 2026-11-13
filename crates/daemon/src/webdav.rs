//! Explicit listener-local WebDAV gateway; no synchronized credentials or paths.
use super::{
    webdav_conditions as conditions,
    webdav_credentials::Credentials,
    webdav_http::{self as http, Connection, Request},
    webdav_locks::Locks,
    webdav_upload::Upload,
    webdav_xml::{self, Properties},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    time::Duration,
};
use sync_extend_core_model::{
    webdav::{self, AuthorizedWebDavPath, WebDavListener},
    Entry, EntryKind, PortablePath, SpaceId,
};
use sync_extend_reconcile::{LocalSpace, ReconcileError, WebDavBaseline, WebDavCommit};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub listener: WebDavListener,
    pub credentials: PathBuf,
    pub uploads: PathBuf,
    pub spaces: BTreeMap<SpaceId, PathBuf>,
}

pub fn load(path: &Path) -> Result<Runtime, Box<dyn std::error::Error>> {
    let bytes = super::config_file::read(path, 65_536)?;
    let runtime: Runtime = serde_json::from_slice(&bytes)?;
    runtime.listener.validate()?;
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
    limits: sync_extend_core_model::limits::LocalLimits,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    runtime.listener.validate()?;
    if !runtime.listener.enabled {
        return Err("DAV listener disabled".into());
    }
    private_upload_parent(&runtime.uploads)?;
    let credentials = Credentials::load(&runtime.credentials, &runtime.listener)?;
    let listener = TcpListener::bind(runtime.listener.address)?;
    listener.set_nonblocking(true)?;
    super::shutdown::ready()?;
    println!(
        "{}",
        serde_json::json!({"webdav_listening":listener.local_addr()?,
        "listener_id":runtime.listener.listener_id,"authenticated":true,
        "remote_backup_complete":false})
    );
    let mut locks = Locks::default();
    let mut requests = 0u64;
    while requests < runtime.listener.max_requests
        && !shutdown.load(std::sync::atomic::Ordering::Acquire)
    {
        let (stream, peer) = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        requests += 1;
        if !peer.ip().is_loopback() {
            continue;
        }
        // Accepted Windows sockets can inherit the nonblocking listener mode.
        // Request framing needs blocking reads with the connection deadline.
        stream.set_nonblocking(false)?;
        let mut connection = Connection::new(stream, runtime.listener.request_timeout_secs);
        let request = match Request::read(&mut connection, runtime.listener.max_header_bytes) {
            Ok(request) => request,
            Err(_) => {
                let _ = http::response(&mut connection, 400, b"invalid request", &[], false);
                continue;
            }
        };
        let Some(account) = request
            .header("authorization")
            .and_then(|header| credentials.authenticate(header))
        else {
            let _ = http::response(
                &mut connection,
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
            continue;
        };
        if request.header("host") != Some(runtime.listener.address.to_string().as_str()) {
            let _ = http::response(
                &mut connection,
                400,
                b"listener authority differs",
                &[],
                false,
            );
            continue;
        }
        if let Err(status) = dispatch(
            &runtime,
            &limits,
            &mut locks,
            account,
            &request,
            &mut connection,
        ) {
            if !connection.response_started {
                let _ = http::response(
                    &mut connection,
                    status,
                    b"request refused; recheck resource state",
                    &[],
                    request.method == "HEAD",
                );
            }
        }
    }
    Ok(())
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
    limits: &sync_extend_core_model::limits::LocalLimits,
    locks: &mut Locks,
    account: &str,
    request: &Request,
    stream: &mut Connection,
) -> Result<(), u16> {
    let write = !matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "PROPFIND" | "OPTIONS"
    );
    let authorized = runtime
        .listener
        .authorize(account, &request.target, write)
        .map_err(|_| 403u16)?;
    if matches!(
        request.method.as_str(),
        "PUT" | "DELETE" | "MOVE" | "COPY" | "MKCOL"
    ) && (!cfg!(windows) || !authorized.allow_native_windows_writes)
    {
        return Err(501);
    }
    let data = runtime.spaces.get(&authorized.space_id).ok_or(403u16)?;
    let mut local = LocalSpace::open_with_limits(data, limits.clone()).map_err(|_| 503u16)?;
    if local.space_id != authorized.space_id {
        return Err(503);
    }
    local.recover_read_leases().map_err(core_status)?;
    let baseline = local.capture_webdav_baseline().map_err(core_status)?;
    let entry = find(&baseline, authorized.path.as_ref());
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
            return http::head(stream, 304, 0, &[("ETag", tag.unwrap_or_default())])
                .map_err(|_| 500u16);
        }
        return Err(412);
    }
    let tokens = evaluate_conditions(
        runtime,
        locks,
        account,
        &authorized,
        &baseline,
        request.header("if"),
    )?;
    let collection =
        entry.is_some_and(|entry| entry.kind == EntryKind::Directory) || authorized.path.is_none();
    if write
        && request.method != "UNLOCK"
        && !locks.allowed(account, &authorized, &tokens, collection)
    {
        return Err(423);
    }
    match request.method.as_str() {
        "OPTIONS" => {
            if request.content_length != 0 {
                return Err(400);
            }
            http::response(
                stream,
                200,
                b"",
                &[
                    ("DAV", "1, 2".into()),
                    (
                        "Allow",
                        "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MOVE, COPY, LOCK, UNLOCK"
                            .into(),
                    ),
                ],
                false,
            )
            .map_err(|_| 500u16)
        }
        "GET" | "HEAD" => {
            if request.content_length != 0 {
                return Err(400);
            }
            let entry = entry.ok_or(404u16)?;
            let content = entry.content.as_ref().ok_or(405u16)?;
            let range_header = if request
                .header("if-range")
                .is_none_or(|value| Some(value) == tag.as_deref())
            {
                request.header("range")
            } else {
                None
            };
            let range = match webdav::byte_range(range_header, content.length) {
                Ok(range) => range,
                Err(_) => {
                    return http::response(
                        stream,
                        416,
                        b"",
                        &[("Content-Range", format!("bytes */{}", content.length))],
                        false,
                    )
                    .map_err(|_| 500u16)
                }
            };
            let read = local
                .acquire_webdav_read(&entry.path)
                .map_err(core_status)?;
            let mut headers = vec![
                ("ETag", tag.unwrap_or_default()),
                ("Accept-Ranges", "bytes".into()),
                ("Content-Type", "application/octet-stream".into()),
            ];
            let length = range.map_or(content.length, |(start, end)| end - start + 1);
            if let Some((start, end)) = range {
                headers.push((
                    "Content-Range",
                    format!("bytes {start}-{end}/{}", content.length),
                ));
            }
            if request.method == "HEAD" || length == 0 {
                local.finish_webdav_read(read).map_err(core_status)?;
                return http::head(
                    stream,
                    if range.is_some() { 206 } else { 200 },
                    length,
                    &headers,
                )
                .map_err(|_| 500u16);
            }
            // Keep at most one byte in request memory. A client cannot finish
            // its Content-Length read before the lease terminal is durable.
            let mut writer = http::ReadTerminalWriter::new(stream);
            let outcome = (|| {
                http::head(
                    writer.connection(),
                    if range.is_some() { 206 } else { 200 },
                    length,
                    &headers,
                )
                .map_err(|_| 500u16)?;
                local
                    .write_webdav_read(&read, range, &mut writer)
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
            let body = body(request, stream)?;
            let properties = webdav_xml::properties(&body).map_err(|_| 400u16)?;
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
            if let Some(expect) = request.header("expect") {
                if !expect.eq_ignore_ascii_case("100-continue") {
                    return Err(417);
                }
                stream
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .map_err(|_| 400u16)?;
            }
            let upload = Upload::receive(stream, &runtime.uploads, request.content_length)
                .map_err(|_| 507u16)?;
            upload.verify().map_err(|_| 409u16)?;
            let result = local
                .commit_webdav_upload(
                    &baseline,
                    authorized.path.as_ref().ok_or(405u16)?,
                    upload.reader(),
                )
                .map_err(core_status)?;
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
                webdav_xml::exclusive_write_lock(&body(request, stream)?).map_err(|_| 400u16)?;
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
    let path = path?;
    baseline
        .manifest()
        .entries
        .values()
        .find(|entry| &entry.path == path)
}
fn core_status(error: ReconcileError) -> u16 {
    match error {
        ReconcileError::ResourceLimit(_) => 507,
        ReconcileError::Unstable => 412,
        ReconcileError::Invariant(_) => 409,
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
        let remainder = value.strip_prefix("http://").ok_or(403u16)?;
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
        let tag = find(baseline, path.path.as_ref())
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
    let export = runtime
        .listener
        .exports
        .iter()
        .find(|export| export.name == path.export_name)
        .ok_or(403u16)?;
    let mut rows = Vec::new();
    rows.push((path.path.as_ref(), find(baseline, path.path.as_ref())));
    if depth == 1 {
        let parent = path.path.as_ref().map_or("", |path| path.as_str());
        for entry in baseline.manifest().entries.values() {
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
