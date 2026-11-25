//! Bounded one-request HTTP transport; no ambiguous message framing.
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Connection {
    stream: Transport,
    timeout: Duration,
    body_started: bool,
    pub response_started: bool,
}

enum Transport {
    Plain(DeadlineSocket),
    Tls(Box<StreamOwned<ServerConnection, DeadlineSocket>>),
    Closed,
}

impl Transport {
    fn socket(&mut self) -> &mut DeadlineSocket {
        match self {
            Self::Plain(socket) => socket,
            Self::Tls(stream) => &mut stream.sock,
            Self::Closed => unreachable!("a consumed HTTP connection cannot be read"),
        }
    }
}

struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline"))
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Connection {
    pub fn new(
        stream: TcpStream,
        seconds: u64,
        tls: Option<&Arc<ServerConfig>>,
    ) -> io::Result<Self> {
        Self::new_retaining(stream, seconds, tls).map_err(|failure| {
            #[cfg(windows)]
            if let Err((original, _)) =
                sync_extend_platform_fs::close_original_tcp_stream(failure.original_stream)
            {
                let _ = Box::leak(Box::new(original));
            }
            failure.error
        })
    }

    pub(crate) fn new_retaining(
        stream: TcpStream,
        seconds: u64,
        tls: Option<&Arc<ServerConfig>>,
    ) -> Result<Self, ConnectionOpenFailure> {
        let timeout = Duration::from_secs(seconds);
        let mut socket = DeadlineSocket {
            stream,
            deadline: Instant::now() + timeout,
        };
        let stream = if let Some(config) = tls {
            let mut conn = match ServerConnection::new(Arc::clone(config)) {
                Ok(conn) => conn,
                Err(error) => return Err(ConnectionOpenFailure {
                    error: io::Error::other(error), original_stream: socket.stream,
                }),
            };
            while conn.is_handshaking() {
                if let Err(error) = conn.complete_io(&mut socket) {
                    return Err(ConnectionOpenFailure { error, original_stream: socket.stream });
                }
            }
            Transport::Tls(Box::new(StreamOwned::new(conn, socket)))
        } else {
            Transport::Plain(socket)
        };
        Ok(Self {
            stream,
            timeout,
            body_started: false,
            response_started: false,
        })
    }

    #[cfg(windows)]
    pub(crate) fn close_retaining(mut self) -> Result<
        sync_extend_platform_fs::ClosedWindowsOriginalSocket,
        (TcpStream, io::Error),
    > {
        self.finish_response_and_drain();
        let original = match std::mem::replace(&mut self.stream, Transport::Closed) {
            Transport::Plain(socket) => socket.stream,
            Transport::Tls(stream) => stream.sock.stream,
            Transport::Closed => unreachable!("original connection close is consuming"),
        };
        sync_extend_platform_fs::close_original_tcp_stream(original)
    }
    pub fn begin_body(&mut self) -> io::Result<()> {
        if self.body_started || self.response_started {
            return Err(io::Error::other("request body phase already started"));
        }
        // Local admission and durable baseline work do not consume network
        // reception time. Start exactly one bounded body phase after admission;
        // individual reads never extend this deadline.
        self.stream.socket().deadline = Instant::now() + self.timeout;
        self.body_started = true;
        Ok(())
    }
    fn begin_response(&mut self) {
        if !self.response_started {
            // Durable native commit is not network reception. Reserve one
            // bounded response phase so a committed write can return its receipt.
            self.stream.socket().deadline = Instant::now() + self.timeout;
            self.response_started = true;
        }
    }
    fn finish_response_and_drain(&mut self) {
        if matches!(self.stream, Transport::Closed) {
            return;
        }
        // Send FIN only after the complete response. An early refusal can leave
        // request bytes unread; bounded draining avoids discarding the response
        // with a reset while preserving the one-request byte/time limits.
        let socket = self.stream.socket();
        socket.deadline = socket
            .deadline
            .min(Instant::now() + Duration::from_millis(100));
        if let Transport::Tls(stream) = &mut self.stream {
            stream.conn.send_close_notify();
            let _ = stream.flush();
        }
        let socket = self.stream.socket();
        let _ = socket.stream.shutdown(Shutdown::Write);
        let mut remaining = 8192usize;
        let mut bytes = [0u8; 1024];
        while remaining != 0 {
            let capacity = remaining.min(bytes.len());
            match socket.read(&mut bytes[..capacity]) {
                Ok(0) | Err(_) => break,
                Ok(count) => remaining -= count,
            }
        }
    }
}

pub(crate) struct ConnectionOpenFailure {
    pub(crate) error: io::Error,
    pub(crate) original_stream: TcpStream,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.finish_response_and_drain();
    }
}
impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.socket().remaining()?;
        match &mut self.stream {
            Transport::Plain(stream) => stream.read(bytes),
            Transport::Tls(stream) => stream.read(bytes),
            Transport::Closed => Err(io::Error::new(io::ErrorKind::BrokenPipe, "HTTP connection closed")),
        }
    }
}
impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.socket().remaining()?;
        match &mut self.stream {
            Transport::Plain(stream) => stream.write(bytes),
            Transport::Tls(stream) => stream.write(bytes),
            Transport::Closed => Err(io::Error::new(io::ErrorKind::BrokenPipe, "HTTP connection closed")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            Transport::Plain(stream) => stream.flush(),
            Transport::Tls(stream) => stream.flush(),
            Transport::Closed => Err(io::Error::new(io::ErrorKind::BrokenPipe, "HTTP connection closed")),
        }
    }
}

/// Streams the fixed version while withholding only its last byte.
/// The last byte owns no CAS reference after the durable lease release.
pub struct ReadTerminalWriter<'a> {
    stream: &'a mut Connection,
    final_byte: Option<u8>,
}

impl<'a> ReadTerminalWriter<'a> {
    pub fn new(stream: &'a mut Connection) -> Self {
        Self {
            stream,
            final_byte: None,
        }
    }
    pub fn connection(&mut self) -> &mut Connection {
        self.stream
    }
    pub fn finish(mut self) -> io::Result<()> {
        if let Some(byte) = self.final_byte.take() {
            self.stream.write_all(&[byte])?;
        }
        Ok(())
    }
}
impl Write for ReadTerminalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some((&last, prefix)) = bytes.split_last() else {
            return Ok(0);
        };
        if let Some(byte) = self.final_byte.take() {
            self.stream.write_all(&[byte])?;
        }
        self.stream.write_all(prefix)?;
        self.final_byte = Some(last);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub content_length: u64,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub fn read(stream: &mut impl Read, max: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() >= max {
                return Err(io::Error::other("request header limit"));
            }
            let mut byte = [0u8];
            stream.read_exact(&mut byte)?;
            bytes.push(byte[0]);
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| io::Error::other("header UTF8 encoding"))?;
        let mut lines = text.split("\r\n");
        let first = lines
            .next()
            .ok_or_else(|| io::Error::other("request line"))?;
        let words: Vec<_> = first.split(' ').collect();
        if words.len() != 3
            || words[2] != "HTTP/1.1"
            || words[0].is_empty()
            || !words[0].bytes().all(|byte| byte.is_ascii_uppercase())
            || !words[1].starts_with('/')
        {
            return Err(io::Error::other("invalid request line"));
        }
        let mut headers = BTreeMap::new();
        for line in lines.take_while(|line| !line.is_empty()) {
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| io::Error::other("invalid header"))?;
            if headers.len() >= 64
                || key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && byte != b'\t')
            {
                return Err(io::Error::other("invalid header field"));
            }
            if headers
                .insert(key.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err(io::Error::other("duplicate request header"));
            }
        }
        let host = headers
            .get("host")
            .ok_or_else(|| io::Error::other("Host required"))?;
        if host.len() > 255
            || host.is_empty()
            || host.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(io::Error::other("invalid Host"));
        }
        if headers.contains_key("transfer-encoding") || headers.contains_key("content-encoding") {
            return Err(io::Error::other("unsupported request framing"));
        }
        let content_length = headers
            .get("content-length")
            .map(|value| {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(io::Error::other("invalid Content-Length"));
                }
                value
                    .parse::<u64>()
                    .map_err(|_| io::Error::other("Content-Length overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            method: words[0].into(),
            target: words[1].into(),
            headers,
            content_length,
        })
    }
}

pub fn head(
    stream: &mut Connection,
    status: u16,
    length: u64,
    headers: &[(&str, String)],
) -> io::Result<()> {
    let phrase = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        416 => "Range Not Satisfiable",
        423 => "Locked",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Error",
    };
    let mut response = format!("HTTP/1.1 {status} {phrase}\r\nContent-Length: {length}\r\nConnection: close\r\nCache-Control: no-store\r\n");
    for (name, value) in headers {
        if value.contains(['\r', '\n']) {
            return Err(io::Error::other("invalid response field"));
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    stream.begin_response();
    stream.write_all(response.as_bytes())
}

pub fn response(
    stream: &mut Connection,
    status: u16,
    body: &[u8],
    headers: &[(&str, String)],
    head_only: bool,
) -> io::Result<()> {
    head(stream, status, body.len() as u64, headers)?;
    if !head_only {
        stream.write_all(body)?;
    }
    Ok(())
}

pub fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn href(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}
