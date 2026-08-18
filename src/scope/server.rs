use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::orchestration_event::OrchestrationEvent;

use super::normalize::{StreamBatch, StreamCursor, StreamFilter};

const SCOPE_HTML: &str = include_str!("placeholder.html");
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const OVER_CAPACITY_IO_TIMEOUT: Duration = Duration::from_millis(100);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);
const STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 64;
const MAX_JSON_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STREAM_EVENTS_PER_SCAN: usize = 65_536;
const MAX_DECODED_ROUTE_SEGMENT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug)]
struct ServerConfig {
    max_connections: usize,
    max_json_response_bytes: usize,
    max_sse_event_bytes: usize,
    max_stream_events_per_scan: usize,
    connection_timeout: Duration,
    accept_poll_interval: Duration,
    stream_poll_interval: Duration,
    stream_heartbeat_interval: Duration,
}

impl ServerConfig {
    const fn production() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_json_response_bytes: MAX_JSON_RESPONSE_BYTES,
            max_sse_event_bytes: MAX_SSE_EVENT_BYTES,
            max_stream_events_per_scan: MAX_STREAM_EVENTS_PER_SCAN,
            connection_timeout: CONNECTION_TIMEOUT,
            accept_poll_interval: ACCEPT_POLL_INTERVAL,
            stream_poll_interval: STREAM_POLL_INTERVAL,
            stream_heartbeat_interval: STREAM_HEARTBEAT_INTERVAL,
        }
    }
}

pub(crate) trait ScopeDataSource: Send + Sync {
    fn projects(&self) -> Result<Value>;

    fn events(
        &self,
        repo_id: &str,
        family: &str,
        run_id: &str,
    ) -> Result<Option<Vec<OrchestrationEvent>>>;

    fn stream_events(
        &self,
        filter: &StreamFilter,
        cursor: StreamCursor,
        limit: usize,
    ) -> Result<StreamBatch>;
}

#[derive(Serialize)]
struct ScopeEventPayload<'a> {
    family: &'a str,
    #[serde(flatten)]
    event: &'a OrchestrationEvent,
}

pub(crate) fn validate_loopback_bind(bind: &str) -> Result<SocketAddr> {
    let address = bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid Scope bind address '{bind}'"))?;
    if !address.ip().is_loopback() {
        bail!("Scope bind address must use a loopback IP address");
    }
    Ok(address)
}

pub(crate) fn bind_and_serve(bind: &str, source: Arc<dyn ScopeDataSource>) -> Result<()> {
    let address = validate_loopback_bind(bind)?;
    let listener = TcpListener::bind(address)
        .with_context(|| format!("failed to bind Scope server to {address}"))?;
    let local_address = listener
        .local_addr()
        .context("failed to inspect Scope listener address")?;
    println!("MACO Scope listening on http://{local_address}");
    serve_listener(listener, source, Arc::new(AtomicBool::new(false)))
        .context("Scope server failed")
}

pub(crate) fn serve_listener(
    listener: TcpListener,
    source: Arc<dyn ScopeDataSource>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    serve_listener_with_config(listener, source, shutdown, ServerConfig::production())
}

fn serve_listener_with_config(
    listener: TcpListener,
    source: Arc<dyn ScopeDataSource>,
    shutdown: Arc<AtomicBool>,
    config: ServerConfig,
) -> io::Result<()> {
    if config.max_connections == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Scope connection limit must be positive",
        ));
    }
    let local_address = listener.local_addr()?;
    if !local_address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Scope listener must use a loopback IP address",
        ));
    }
    listener.set_nonblocking(true)?;
    let active_connections = Arc::new(AtomicUsize::new(0));

    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                let Some(permit) = ConnectionPermit::acquire(
                    Arc::clone(&active_connections),
                    config.max_connections,
                ) else {
                    let _ = write_over_capacity(&mut stream);
                    continue;
                };
                let source = Arc::clone(&source);
                let connection_shutdown = Arc::clone(&shutdown);
                thread::Builder::new()
                    .name("maco-scope-http".to_string())
                    .spawn(move || {
                        let _permit = permit;
                        let _ = handle_connection(stream, source, connection_shutdown, config);
                    })?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn acquire(active: Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let acquired = active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < limit).then_some(count + 1)
            })
            .is_ok();
        acquired.then_some(Self { active })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    source: Arc<dyn ScopeDataSource>,
    shutdown: Arc<AtomicBool>,
    config: ServerConfig,
) -> io::Result<()> {
    stream.set_read_timeout(Some(config.connection_timeout))?;
    stream.set_write_timeout(Some(config.connection_timeout))?;
    let Some(request) = read_request(&mut stream)? else {
        return Ok(());
    };

    if !request_host_is_loopback(request.host.as_deref()) {
        return write_json_response(
            &mut stream,
            "403 Forbidden",
            &json!({"error": "host not allowed"}),
            &[],
            config.max_json_response_bytes,
        );
    }

    if request.method != "GET" {
        return write_json_response(
            &mut stream,
            "405 Method Not Allowed",
            &json!({"error": "method not allowed"}),
            &["Allow: GET"],
            config.max_json_response_bytes,
        );
    }

    match request.path.as_str() {
        "/" => write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            SCOPE_HTML.as_bytes(),
            &[],
        ),
        "/api/projects" => match source.projects() {
            Ok(projects) => write_json_response(
                &mut stream,
                "200 OK",
                &projects,
                &[],
                config.max_json_response_bytes,
            ),
            Err(_) => write_internal_error(&mut stream),
        },
        "/api/stream" => {
            let stream_options = match parse_stream_options(&request) {
                Ok(options) => options,
                Err(message) => {
                    return write_json_response(
                        &mut stream,
                        "400 Bad Request",
                        &json!({"error": message}),
                        &[],
                        config.max_json_response_bytes,
                    );
                }
            };
            write_event_stream(&mut stream, source, shutdown, config, stream_options)
        }
        path => write_run_events_response(&mut stream, source.as_ref(), path, config),
    }
}

fn write_run_events_response(
    stream: &mut TcpStream,
    source: &dyn ScopeDataSource,
    path: &str,
    config: ServerConfig,
) -> io::Result<()> {
    let Some((repo_id, family, run_id)) = parse_run_events_path(path) else {
        return write_json_response(
            stream,
            "404 Not Found",
            &json!({"error": "not found"}),
            &[],
            config.max_json_response_bytes,
        );
    };

    match source.events(&repo_id, &family, &run_id) {
        Ok(Some(events)) => {
            let payloads = events
                .iter()
                .map(|event| ScopeEventPayload {
                    family: &family,
                    event,
                })
                .collect::<Vec<_>>();
            write_json_response(
                stream,
                "200 OK",
                &payloads,
                &[],
                config.max_json_response_bytes,
            )
        }
        Ok(None) => write_json_response(
            stream,
            "404 Not Found",
            &json!({"error": "run not found"}),
            &[],
            config.max_json_response_bytes,
        ),
        Err(_) => write_internal_error(stream),
    }
}

fn parse_run_events_path(path: &str) -> Option<(String, String, String)> {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 7
        || !parts[0].is_empty()
        || parts[1] != "api"
        || parts[2] != "runs"
        || parts[6] != "events"
    {
        return None;
    }
    Some((
        decode_route_segment(parts[3])?,
        decode_route_segment(parts[4])?,
        decode_route_segment(parts[5])?,
    ))
}

fn decode_route_segment(encoded: &str) -> Option<String> {
    let encoded = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len().min(MAX_DECODED_ROUTE_SEGMENT_BYTES));
    let mut index = 0;
    while index < encoded.len() {
        let byte = if encoded[index] == b'%' {
            let high = decode_hex(*encoded.get(index + 1)?)?;
            let low = decode_hex(*encoded.get(index + 2)?)?;
            index += 3;
            (high << 4) | low
        } else {
            let byte = encoded[index];
            index += 1;
            byte
        };
        if decoded.len() >= MAX_DECODED_ROUTE_SEGMENT_BYTES {
            return None;
        }
        decoded.push(byte);
    }

    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        None
    } else {
        Some(decoded)
    }
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_stream_options(request: &Request) -> std::result::Result<StreamOptions, String> {
    let mut repo = None;
    let mut family = None;
    let mut run = None;
    let mut since = None;
    let mut repo_seen = false;
    let mut family_seen = false;
    let mut run_seen = false;
    if let Some(query) = request.query.as_deref() {
        for field in query.split('&').filter(|field| !field.is_empty()) {
            let (encoded_name, encoded_value) = field.split_once('=').unwrap_or((field, ""));
            let name = decode_query_component(encoded_name)
                .ok_or_else(|| "invalid stream query encoding".to_string())?;
            let value = decode_query_component(encoded_value)
                .ok_or_else(|| "invalid stream query encoding".to_string())?;
            match name.as_str() {
                "repo" => set_stream_filter(&mut repo, &mut repo_seen, value, "repo")?,
                "family" => set_stream_filter(&mut family, &mut family_seen, value, "family")?,
                "run" => set_stream_filter(&mut run, &mut run_seen, value, "run")?,
                "since" => {
                    if since.replace(value).is_some() {
                        return Err("duplicate stream query parameter 'since'".to_string());
                    }
                }
                _ => return Err(format!("unknown stream query parameter '{name}'")),
            }
        }
    }

    let cursor = if let Some(last_event_id) = request
        .last_event_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        StreamCursor::After(parse_event_id(last_event_id, "Last-Event-ID")?)
    } else {
        match since.as_deref() {
            None | Some("") => StreamCursor::Beginning,
            Some("now") => StreamCursor::Live,
            Some(value) => StreamCursor::After(parse_event_id(value, "since")?),
        }
    };
    Ok(StreamOptions {
        filter: StreamFilter { repo, family, run },
        cursor,
    })
}

fn set_stream_filter(
    destination: &mut Option<String>,
    seen: &mut bool,
    value: String,
    name: &str,
) -> std::result::Result<(), String> {
    if *seen {
        return Err(format!("duplicate stream query parameter '{name}'"));
    }
    *seen = true;
    if !value.is_empty() {
        *destination = Some(value);
    }
    Ok(())
}

fn parse_event_id(value: &str, source: &str) -> std::result::Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{source} must be a decimal event id"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{source} event id is out of range"))
}

fn decode_query_component(encoded: &str) -> Option<String> {
    let encoded = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len().min(MAX_DECODED_ROUTE_SEGMENT_BYTES));
    let mut index = 0;
    while index < encoded.len() {
        let byte = match encoded[index] {
            b'%' => {
                let high = decode_hex(*encoded.get(index + 1)?)?;
                let low = decode_hex(*encoded.get(index + 2)?)?;
                index += 3;
                (high << 4) | low
            }
            b'+' => {
                index += 1;
                b' '
            }
            byte => {
                index += 1;
                byte
            }
        };
        if decoded.len() >= MAX_DECODED_ROUTE_SEGMENT_BYTES {
            return None;
        }
        decoded.push(byte);
    }
    let decoded = String::from_utf8(decoded).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}

/// `/api/stream` wire contract for the Scope UI.
///
/// `repo`, `family`, and `run` query values are optional exact-match UTF-8
/// filters. With no cursor, the response starts with the current matching
/// history for compatibility. `since=now` starts at the live edge, while a
/// decimal `since=<id>` resumes after that event. A non-empty decimal
/// `Last-Event-ID` header overrides `since`, which lets browser EventSource
/// reconnects resume a `since=now` request. Every data record carries an
/// `id: <decimal>` SSE field. IDs increase for the lifetime of the server
/// process; an ID beyond the current process range is clamped to the live edge.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamOptions {
    filter: StreamFilter,
    cursor: StreamCursor,
}

fn write_event_stream(
    stream: &mut TcpStream,
    source: Arc<dyn ScopeDataSource>,
    shutdown: Arc<AtomicBool>,
    config: ServerConfig,
    options: StreamOptions,
) -> io::Result<()> {
    stream.write_all(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: close\r\n",
            "X-Accel-Buffering: no\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    let mut cursor = options.cursor;
    let mut last_heartbeat = Instant::now();
    while !shutdown.load(Ordering::Acquire) {
        let mut more = false;
        match source.stream_events(&options.filter, cursor, config.max_stream_events_per_scan) {
            Ok(batch) => {
                for event in batch.events {
                    let payload = ScopeEventPayload {
                        family: &event.family,
                        event: &event.event,
                    };
                    let serialized =
                        match serialize_json_bounded(&payload, config.max_sse_event_bytes) {
                            Ok(serialized) => serialized,
                            Err(_) => {
                                stream.write_all(b": event exceeds serialization limit\n\n")?;
                                continue;
                            }
                        };
                    writeln!(stream, "id: {}", event.id)?;
                    stream.write_all(b"data: ")?;
                    stream.write_all(&serialized)?;
                    stream.write_all(b"\n\n")?;
                }
                cursor = StreamCursor::After(batch.cursor);
                more = batch.more;
            }
            Err(_) => {
                stream.write_all(b": scan error\n\n")?;
                stream.flush()?;
            }
        }
        stream.flush()?;

        if more {
            continue;
        }

        if last_heartbeat.elapsed() >= config.stream_heartbeat_interval {
            stream.write_all(b": heartbeat\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
        wait_for_stream_poll(&shutdown, config);
    }
    Ok(())
}

fn wait_for_stream_poll(shutdown: &AtomicBool, config: ServerConfig) {
    let deadline = Instant::now() + config.stream_poll_interval;
    while !shutdown.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep(
            config
                .accept_poll_interval
                .min(deadline.saturating_duration_since(now)),
        );
    }
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    query: Option<String>,
    host: Option<String>,
    last_event_id: Option<String>,
}

fn read_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > MAX_REQUEST_HEADER_BYTES {
            return write_request_too_large(stream);
        }
    }
    if bytes.len() > MAX_REQUEST_HEADER_BYTES {
        return write_request_too_large(stream);
    }

    let header = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP request"))?;
    let request_line = header
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP request line"))?;
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP request line",
        ));
    }
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    if !path.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request target must be an origin-form path",
        ));
    }
    let mut last_event_id = None;
    let mut last_event_id_seen = false;
    let mut host = None;
    let mut host_seen = false;
    for line in header.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("Last-Event-ID") {
            if last_event_id_seen {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Last-Event-ID header",
                ));
            }
            last_event_id_seen = true;
            last_event_id = Some(value.trim().to_string());
        } else if name.trim().eq_ignore_ascii_case("Host") {
            if host_seen {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Host header",
                ));
            }
            host_seen = true;
            host = Some(value.trim().to_string());
        }
    }
    Ok(Some(Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.map(str::to_string),
        host,
        last_event_id,
    }))
}

fn request_host_is_loopback(host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    matches!(
        hostname_from_host_header(host)
            .to_ascii_lowercase()
            .as_str(),
        "localhost" | "127.0.0.1" | "[::1]" | "::1"
    )
}

fn hostname_from_host_header(host: &str) -> &str {
    if host.eq_ignore_ascii_case("::1") {
        return host;
    }
    if let Some(end) = host.find(']') {
        return &host[..=end];
    }
    match host.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty()
                && !name.contains(':')
                && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            name
        }
        _ => host,
    }
}

fn write_request_too_large(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    write_json_response(
        stream,
        "431 Request Header Fields Too Large",
        &json!({"error": "request headers too large"}),
        &[],
        MAX_JSON_RESPONSE_BYTES,
    )?;
    Ok(None)
}

fn write_internal_error(stream: &mut TcpStream) -> io::Result<()> {
    write_json_response(
        stream,
        "500 Internal Server Error",
        &json!({"error": "failed to read Scope data"}),
        &[],
        MAX_JSON_RESPONSE_BYTES,
    )
}

fn write_json_response<T: Serialize + ?Sized>(
    stream: &mut TcpStream,
    status: &str,
    value: &T,
    extra_headers: &[&str],
    max_bytes: usize,
) -> io::Result<()> {
    let body = match serialize_json_bounded(value, max_bytes) {
        Ok(body) => body,
        Err(_) => {
            return write_response(
                stream,
                "500 Internal Server Error",
                "application/json; charset=utf-8",
                br#"{"error":"Scope response exceeds serialization limit"}"#,
                &[],
            );
        }
    };
    write_response(
        stream,
        status,
        "application/json; charset=utf-8",
        &body,
        extra_headers,
    )
}

fn write_over_capacity(stream: &mut TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(OVER_CAPACITY_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(OVER_CAPACITY_IO_TIMEOUT))?;
    drain_request_headers(stream);
    write_response(
        stream,
        "503 Service Unavailable",
        "application/json; charset=utf-8",
        br#"{"error":"Scope connection limit reached"}"#,
        &["Retry-After: 1"],
    )
}

fn drain_request_headers(stream: &mut TcpStream) {
    let mut total = 0;
    let mut tail = Vec::new();
    let mut buffer = [0_u8; 1024];
    while total <= MAX_REQUEST_HEADER_BYTES {
        let Ok(count) = stream.read(&mut buffer) else {
            break;
        };
        if count == 0 {
            break;
        }
        total += count;
        tail.extend_from_slice(&buffer[..count]);
        if tail.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if tail.len() > 3 {
            tail.drain(..tail.len() - 3);
        }
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &[&str],
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    for header in extra_headers {
        write!(stream, "{header}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}

fn serialize_json_bounded<T: Serialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut writer = BoundedJsonWriter::new(max_bytes);
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(writer.into_bytes())
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Scope JSON serialization limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    use crate::orchestration_event::{OrchestrationEventKind, OrchestrationRole};
    use crate::scope::normalize::{FamilyEvent, SequencedFamilyEvent};

    use super::*;

    struct TestDataSource {
        projects: Value,
        events: Mutex<Vec<SequencedFamilyEvent>>,
        expected_route: Option<(String, String, String)>,
    }

    impl TestDataSource {
        fn new(projects: Value, events: Vec<OrchestrationEvent>) -> Self {
            Self {
                projects,
                events: Mutex::new(sequence_events(
                    events
                        .into_iter()
                        .map(|event| family_event("o2", event))
                        .collect(),
                )),
                expected_route: None,
            }
        }

        fn with_route(mut self, repo_id: &str, family: &str, run_id: &str) -> Self {
            self.expected_route =
                Some((repo_id.to_string(), family.to_string(), run_id.to_string()));
            self
        }

        fn set_events(&self, events: Vec<OrchestrationEvent>) {
            *self.events.lock().expect("lock test events") = sequence_events(
                events
                    .into_iter()
                    .map(|event| family_event("o2", event))
                    .collect(),
            );
        }

        fn set_stream_events(&self, events: Vec<FamilyEvent>) {
            *self.events.lock().expect("lock test events") = sequence_events(events);
        }
    }

    impl ScopeDataSource for TestDataSource {
        fn projects(&self) -> Result<Value> {
            Ok(self.projects.clone())
        }

        fn events(
            &self,
            repo_id: &str,
            family: &str,
            run_id: &str,
        ) -> Result<Option<Vec<OrchestrationEvent>>> {
            if self.expected_route.as_ref().is_some_and(|expected| {
                expected.0 != repo_id || expected.1 != family || expected.2 != run_id
            }) {
                return Ok(None);
            }
            Ok(Some(
                self.events
                    .lock()
                    .expect("lock test events")
                    .iter()
                    .map(|event| event.event.clone())
                    .collect(),
            ))
        }

        fn stream_events(
            &self,
            filter: &StreamFilter,
            cursor: StreamCursor,
            limit: usize,
        ) -> Result<StreamBatch> {
            let events = self.events.lock().expect("lock test events");
            let latest = events.last().map(|event| event.id).unwrap_or_default();
            if cursor == StreamCursor::Live {
                return Ok(StreamBatch {
                    events: Vec::new(),
                    cursor: latest,
                    more: false,
                });
            }
            let after = match cursor {
                StreamCursor::Beginning => 0,
                StreamCursor::After(id) => id.min(latest),
                StreamCursor::Live => latest,
            };
            let mut selected = events
                .iter()
                .filter(|event| {
                    event.id > after
                        && filter
                            .repo
                            .as_ref()
                            .is_none_or(|repo| event.event.repo == *repo)
                        && filter
                            .family
                            .as_ref()
                            .is_none_or(|family| event.family == *family)
                        && filter
                            .run
                            .as_ref()
                            .is_none_or(|run| event.event.run == *run)
                })
                .take(limit.saturating_add(1))
                .cloned()
                .collect::<Vec<_>>();
            let more = selected.len() > limit;
            if more {
                selected.truncate(limit);
            }
            let cursor = if more {
                selected.last().map(|event| event.id).unwrap_or(after)
            } else {
                latest
            };
            Ok(StreamBatch {
                events: selected,
                cursor,
                more,
            })
        }
    }

    fn sequence_events(events: Vec<FamilyEvent>) -> Vec<SequencedFamilyEvent> {
        events
            .into_iter()
            .enumerate()
            .map(|(index, event)| SequencedFamilyEvent {
                id: u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
                family: event.family,
                event: event.event,
            })
            .collect()
    }

    struct TestServer {
        address: SocketAddr,
        shutdown: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl TestServer {
        fn start(source: Arc<dyn ScopeDataSource>, config: ServerConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
            let address = listener.local_addr().expect("test listener address");
            let shutdown = Arc::new(AtomicBool::new(false));
            let server_shutdown = Arc::clone(&shutdown);
            let thread = thread::spawn(move || {
                serve_listener_with_config(listener, source, server_shutdown, config)
            });
            Self {
                address,
                shutdown,
                thread: Some(thread),
            }
        }

        fn stop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .expect("join test server")
                    .expect("run test server");
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            max_connections: 4,
            max_json_response_bytes: 16 * 1024,
            max_sse_event_bytes: 16 * 1024,
            max_stream_events_per_scan: 32,
            connection_timeout: Duration::from_secs(1),
            accept_poll_interval: Duration::from_millis(1),
            stream_poll_interval: Duration::from_millis(5),
            stream_heartbeat_interval: Duration::from_millis(20),
        }
    }

    fn event(node: &str, payload: Value) -> OrchestrationEvent {
        OrchestrationEvent {
            ts: "2026-07-20T12:00:00Z".to_string(),
            repo: "repo".to_string(),
            run: "run-1".to_string(),
            node: node.to_string(),
            parent: None,
            role: OrchestrationRole::Worker,
            kind: OrchestrationEventKind::Status,
            payload,
        }
    }

    fn family_event(family: &str, event: OrchestrationEvent) -> FamilyEvent {
        FamilyEvent {
            family: family.to_string(),
            event,
        }
    }

    fn open_stream(address: SocketAddr, path: &str) -> TcpStream {
        open_stream_with_headers(address, path, &[])
    }

    fn open_stream_with_headers(address: SocketAddr, path: &str, headers: &[&str]) -> TcpStream {
        let mut stream = TcpStream::connect(address).expect("connect to test server");
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set test read timeout");
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n")
            .expect("write test request line");
        for header in headers {
            write!(stream, "{header}\r\n").expect("write test request header");
        }
        stream
            .write_all(b"Connection: close\r\n\r\n")
            .expect("finish test request");
        stream
    }

    fn read_until(stream: &mut TcpStream, response: &mut Vec<u8>, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buffer = [0_u8; 4096];
        while !String::from_utf8_lossy(response).contains(expected) && Instant::now() < deadline {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => response.extend_from_slice(&buffer[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("read test response: {error}"),
            }
        }
        assert!(
            String::from_utf8_lossy(response).contains(expected),
            "response did not contain {expected:?}: {}",
            String::from_utf8_lossy(response)
        );
    }

    fn http_get(address: SocketAddr, path: &str) -> String {
        let mut stream = open_stream(address, path);
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read test HTTP response");
        response
    }

    fn http_get_with_host(address: SocketAddr, path: &str, host: Option<&str>) -> String {
        let mut stream = TcpStream::connect(address).expect("connect to test server");
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set test read timeout");
        match host {
            Some(host) => write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            )
            .expect("write hosted request"),
            None => write!(stream, "GET {path} HTTP/1.1\r\nConnection: close\r\n\r\n")
                .expect("write hostless request"),
        }
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read hosted HTTP response");
        response
    }

    #[test]
    fn loopback_host_header_allows_only_local_names() {
        for host in [
            "localhost",
            "LocalHost",
            "localhost:7878",
            "127.0.0.1",
            "127.0.0.1:9",
            "[::1]",
            "[::1]:7878",
            "::1",
        ] {
            assert!(
                request_host_is_loopback(Some(host)),
                "rejected loopback host {host}"
            );
        }
        for host in [
            None,
            Some(""),
            Some("attacker.example"),
            Some("attacker.example:7878"),
            Some("192.0.2.1"),
            Some("[::]"),
            Some("localhost.attacker.example"),
            Some("127.0.0.1.nip.io"),
        ] {
            assert!(
                !request_host_is_loopback(host),
                "accepted non-loopback host {host:?}"
            );
        }
    }

    #[test]
    fn rejects_non_loopback_or_missing_host_headers() {
        let source: Arc<dyn ScopeDataSource> =
            Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        let mut server = TestServer::start(source, test_config());

        let allowed = http_get_with_host(server.address, "/api/projects", Some("127.0.0.1:7878"));
        assert!(
            allowed.starts_with("HTTP/1.1 200 OK"),
            "loopback host rejected: {allowed}"
        );

        for host in [None, Some("attacker.example"), Some("192.0.2.1:7878")] {
            let response = http_get_with_host(server.address, "/api/projects", host);
            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "unexpected response for host {host:?}: {response}"
            );
            assert!(response.contains("host not allowed"));
        }
        server.stop();
    }

    #[test]
    fn accepts_only_numeric_loopback_bind_addresses() {
        assert_eq!(
            validate_loopback_bind("127.0.0.1:7878").expect("IPv4 loopback"),
            "127.0.0.1:7878".parse().expect("socket address")
        );
        assert!(validate_loopback_bind("[::1]:7878").is_ok());
        for bind in [
            "0.0.0.0:7878",
            "192.0.2.1:7878",
            "[::]:7878",
            "localhost:7878",
        ] {
            assert!(validate_loopback_bind(bind).is_err(), "accepted {bind}");
        }
    }

    #[test]
    fn parses_only_exact_run_event_paths() {
        assert_eq!(
            parse_run_events_path("/api/runs/repo/o2/run-1/events"),
            Some(("repo".to_string(), "o2".to_string(), "run-1".to_string()))
        );
        assert_eq!(
            parse_run_events_path(
                "/api/runs/repo%20space/family%25+name/run-%E6%97%A5%E6%9C%AC%2Fpart/events"
            ),
            Some((
                "repo space".to_string(),
                "family%+name".to_string(),
                "run-日本/part".to_string()
            ))
        );
        for path in [
            "/api/runs/repo/o2/run-1/events/",
            "/api/runs//o2/run-1/events",
            "/api/runs/repo/o2/run-1/events/extra",
            "/api/runs/repo%/o2/run-1/events",
            "/api/runs/repo%2/o2/run-1/events",
            "/api/runs/repo%GG/o2/run-1/events",
            "/api/runs/repo%FF/o2/run-1/events",
            "/api/runs/repo%00/o2/run-1/events",
        ] {
            assert!(parse_run_events_path(path).is_none(), "accepted {path}");
        }
        let oversized = format!(
            "/api/runs/{}/o2/run-1/events",
            "a".repeat(MAX_DECODED_ROUTE_SEGMENT_BYTES + 1)
        );
        assert!(parse_run_events_path(&oversized).is_none());
    }

    #[test]
    fn parses_filtered_resumable_stream_contract() {
        let options = parse_stream_options(&Request {
            method: "GET".to_string(),
            path: "/api/stream".to_string(),
            query: Some("repo=repo+space&family=o2%2Dautopilot&run=run%2Fone&since=41".to_string()),
            host: Some("localhost".to_string()),
            last_event_id: None,
        })
        .expect("stream options");
        assert_eq!(options.filter.repo.as_deref(), Some("repo space"));
        assert_eq!(options.filter.family.as_deref(), Some("o2-autopilot"));
        assert_eq!(options.filter.run.as_deref(), Some("run/one"));
        assert_eq!(options.cursor, StreamCursor::After(41));

        let options = parse_stream_options(&Request {
            method: "GET".to_string(),
            path: "/api/stream".to_string(),
            query: Some("since=now".to_string()),
            host: Some("localhost".to_string()),
            last_event_id: Some("9".to_string()),
        })
        .expect("Last-Event-ID override");
        assert_eq!(options.cursor, StreamCursor::After(9));

        for query in [
            "unknown=value",
            "repo=one&repo=two",
            "since=not-a-number",
            "repo=%FF",
        ] {
            assert!(
                parse_stream_options(&Request {
                    method: "GET".to_string(),
                    path: "/api/stream".to_string(),
                    query: Some(query.to_string()),
                    host: Some("localhost".to_string()),
                    last_event_id: None,
                })
                .is_err(),
                "accepted {query}"
            );
        }
    }

    #[test]
    fn encoded_run_route_round_trips_exact_identifiers_and_rejects_malformed_encoding() {
        let source: Arc<dyn ScopeDataSource> = Arc::new(
            TestDataSource::new(
                json!({"projects": []}),
                vec![event("encoded-route", json!({"status": "ready"}))],
            )
            .with_route("repo space", "family%+name", "run-日本/part"),
        );
        let mut server = TestServer::start(source, test_config());

        let response = http_get(
            server.address,
            "/api/runs/repo%20space/family%25+name/run-%E6%97%A5%E6%9C%AC%2Fpart/events",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"family\":\"family%+name\""));
        assert!(response.contains("\"node\":\"encoded-route\""));

        for path in [
            "/api/runs/repo%/family%25+name/run-%E6%97%A5%E6%9C%AC%2Fpart/events",
            "/api/runs/repo%20space/family%FF/run-%E6%97%A5%E6%9C%AC%2Fpart/events",
            "/api/runs/repo%20space/family%25+name/run-%00/events",
        ] {
            let response = http_get(server.address, path);
            assert!(
                response.starts_with("HTTP/1.1 404 Not Found"),
                "unexpected response for {path}: {response}"
            );
        }
        server.stop();
    }

    #[test]
    fn root_serves_live_first_multi_project_frontend() {
        let source: Arc<dyn ScopeDataSource> =
            Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        let mut server = TestServer::start(source, test_config());

        let response = http_get(server.address, "/");

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("text/html; charset=utf-8"));
        assert!(response.contains("MACO_SCOPE_LIVE_MULTIPROJECT_UI"));

        for default_filter in [
            "<select id=\"projectSelect\"><option value=\"\" selected>All projects</option></select>",
            "<select id=\"familySelect\"><option value=\"\" selected>All families</option></select>",
            "<select id=\"runSelect\"><option value=\"\" selected>All runs</option></select>",
        ] {
            assert!(
                response.contains(default_filter),
                "missing default filter {default_filter:?}"
            );
        }
        for control in [
            "id=\"modeSelect\"",
            "id=\"viewSelect\"",
            "id=\"scrubber\"",
            "id=\"jumpToLive\"",
        ] {
            assert!(response.contains(control), "missing control {control:?}");
        }

        assert!(response.contains(
            "var streamUrl = \"/api/stream\" + (params.toString() ? \"?\" + params.toString() : \"\");"
        ));
        assert!(response
            .contains("if (state.selectedProject) params.set(\"repo\", state.selectedProject);"));
        assert!(response
            .contains("if (state.selectedFamily) params.set(\"family\", state.selectedFamily);"));
        assert!(response.contains("if (state.selectedRun) params.set(\"run\", state.selectedRun);"));
        assert!(response.contains(
            "var initialMode = initialParams.get(\"mode\") === \"archive\" ? \"archive\" : \"live\";"
        ));
        assert!(response.contains("if (state.mode === \"archive\") params.set(\"since\", \"0\");"));
        assert!(response.contains("appendEvent(event, message.lastEventId)"));
        assert!(response.contains("state.eventIds.has(normalizedId)"));
        assert!(!response.contains("if (!state.selectedProject || !state.selectedRun) return"));

        let scrubber_handler_start = response
            .find("elements.scrubber.addEventListener(\"input\"")
            .expect("scrubber input handler");
        let scrubber_handler_end = response[scrubber_handler_start..]
            .find("elements.speed.addEventListener")
            .map(|offset| scrubber_handler_start + offset)
            .expect("end of scrubber input handler");
        let scrubber_handler = &response[scrubber_handler_start..scrubber_handler_end];
        let cursor_capture = scrubber_handler
            .find("var requestedCursor = Number(elements.scrubber.value);")
            .expect("scrubber cursor capture");
        let playback_stop = scrubber_handler
            .find("stopPlayback();")
            .expect("scrubber playback stop");
        assert!(cursor_capture < playback_stop);

        assert!(response.contains("var projectionGroups = new Map()"));
        assert!(response.contains("state.view === \"repository\""));
        assert!(response.contains("state.view === \"combined\""));
        server.stop();
    }

    #[test]
    fn connection_limit_returns_service_unavailable() {
        let source: Arc<dyn ScopeDataSource> =
            Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        let mut config = test_config();
        config.max_connections = 1;
        let mut server = TestServer::start(source, config);

        let mut held_stream = open_stream(server.address, "/api/stream");
        let mut held_response = Vec::new();
        read_until(
            &mut held_stream,
            &mut held_response,
            "Content-Type: text/event-stream",
        );

        let refused = http_get(server.address, "/api/projects");
        assert!(refused.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(refused.contains("Scope connection limit reached"));

        server.stop();
        let mut remainder = Vec::new();
        held_stream
            .read_to_end(&mut remainder)
            .expect("close held stream");
    }

    #[test]
    fn response_and_stream_serialization_limits_fail_boundedly() {
        let source: Arc<dyn ScopeDataSource> = Arc::new(TestDataSource::new(
            json!({"projects": [{"payload": "x".repeat(1024)}]}),
            Vec::new(),
        ));
        let mut response_config = test_config();
        response_config.max_json_response_bytes = 64;
        let mut response_server = TestServer::start(source, response_config);
        let response = http_get(response_server.address, "/api/projects");
        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(response.contains("Scope response exceeds serialization limit"));
        response_server.stop();

        let oversized_event = event("large", json!({"payload": "x".repeat(1024)}));
        let source: Arc<dyn ScopeDataSource> = Arc::new(TestDataSource::new(
            json!({"projects": []}),
            vec![oversized_event],
        ));
        let mut stream_config = test_config();
        stream_config.max_sse_event_bytes = 64;
        let mut stream_server = TestServer::start(source, stream_config);
        let mut stream = open_stream(stream_server.address, "/api/stream");
        let mut stream_response = Vec::new();
        read_until(
            &mut stream,
            &mut stream_response,
            ": event exceeds serialization limit",
        );
        assert!(!String::from_utf8_lossy(&stream_response).contains("data: "));
        stream_server.stop();

        let source: Arc<dyn ScopeDataSource> = Arc::new(TestDataSource::new(
            json!({"projects": []}),
            vec![event("first", json!({})), event("second", json!({}))],
        ));
        let mut batch_config = test_config();
        batch_config.max_stream_events_per_scan = 1;
        let mut scan_server = TestServer::start(source, batch_config);
        let mut stream = open_stream(scan_server.address, "/api/stream");
        let mut scan_response = Vec::new();
        read_until(&mut stream, &mut scan_response, "\"node\":\"second\"");
        let scan_response = String::from_utf8(scan_response).expect("batched SSE UTF-8");
        assert_eq!(scan_response.matches("data: ").count(), 2);
        assert!(scan_response.contains("id: 1\n"));
        assert!(scan_response.contains("id: 2\n"));
        scan_server.stop();
    }

    #[test]
    fn stream_cursor_emits_each_event_once_and_sends_heartbeats() {
        let first = event("worker-1", json!({"status": "running"}));
        let second = event("worker-2", json!({"status": "ready"}));
        let source = Arc::new(TestDataSource::new(
            json!({"projects": []}),
            vec![first.clone()],
        ));
        let stream_source: Arc<dyn ScopeDataSource> = source.clone();
        let mut server = TestServer::start(stream_source, test_config());
        let mut stream = open_stream(server.address, "/api/stream");
        let mut response = Vec::new();

        read_until(&mut stream, &mut response, "\"node\":\"worker-1\"");
        read_until(&mut stream, &mut response, "\"family\":\"o2\"");
        read_until(&mut stream, &mut response, ": heartbeat");
        source.set_events(vec![first, second]);
        read_until(&mut stream, &mut response, "\"node\":\"worker-2\"");

        let response = String::from_utf8(response).expect("SSE response UTF-8");
        assert_eq!(response.matches("\"node\":\"worker-1\"").count(), 1);
        assert_eq!(response.matches("\"node\":\"worker-2\"").count(), 1);
        assert_eq!(response.matches("id: 1\n").count(), 1);
        assert_eq!(response.matches("id: 2\n").count(), 1);
        assert!(response.contains(": heartbeat\n\n"));
        server.stop();
    }

    #[test]
    fn queryless_stream_emits_current_events_across_repositories_and_runs() {
        let first = event("repo-a-worker", json!({"status": "running"}));
        let mut second = event("repo-b-worker", json!({"status": "ready"}));
        second.repo = "repo-b".to_string();
        second.run = "run-2".to_string();

        let source = Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        source.set_stream_events(vec![
            family_event("o2", first),
            family_event("autopilot", second),
        ]);
        let stream_source: Arc<dyn ScopeDataSource> = source;
        let mut server = TestServer::start(stream_source, test_config());
        let mut stream = open_stream(server.address, "/api/stream");
        let mut response = Vec::new();

        read_until(&mut stream, &mut response, "\"node\":\"repo-b-worker\"");

        let response = String::from_utf8(response).expect("query-less SSE response UTF-8");
        assert!(response.contains("\"repo\":\"repo\""));
        assert!(response.contains("\"run\":\"run-1\""));
        assert!(response.contains("\"family\":\"o2\""));
        assert!(response.contains("\"node\":\"repo-a-worker\""));
        assert!(response.contains("\"repo\":\"repo-b\""));
        assert!(response.contains("\"run\":\"run-2\""));
        assert!(response.contains("\"family\":\"autopilot\""));
        assert!(response.contains("id: 1\n"));
        assert!(response.contains("id: 2\n"));
        server.stop();
    }

    #[test]
    fn stream_filters_resumes_and_can_start_at_live_edge() {
        let first = event("first", json!({"status": "old"}));
        let mut other_run = event("other-run", json!({}));
        other_run.run = "run-2".to_string();
        let source = Arc::new(TestDataSource::new(
            json!({"projects": []}),
            vec![first.clone(), other_run.clone()],
        ));
        let stream_source: Arc<dyn ScopeDataSource> = source.clone();
        let mut server = TestServer::start(stream_source, test_config());

        let mut filtered = open_stream(
            server.address,
            "/api/stream?repo=repo&family=o2&run=run-1&since=0",
        );
        let mut filtered_response = Vec::new();
        read_until(&mut filtered, &mut filtered_response, "\"node\":\"first\"");
        let filtered_response = String::from_utf8(filtered_response).expect("filtered SSE UTF-8");
        assert!(!filtered_response.contains("other-run"));
        assert!(filtered_response.contains("id: 1\n"));

        let mut resumed = open_stream_with_headers(
            server.address,
            "/api/stream?since=now",
            &["Last-Event-ID: 1"],
        );
        let mut resumed_response = Vec::new();
        read_until(
            &mut resumed,
            &mut resumed_response,
            "\"node\":\"other-run\"",
        );
        let resumed_response = String::from_utf8(resumed_response).expect("resumed SSE UTF-8");
        assert!(!resumed_response.contains("\"node\":\"first\""));
        assert!(resumed_response.contains("id: 2\n"));

        let mut live = open_stream(server.address, "/api/stream?since=now");
        let mut live_response = Vec::new();
        read_until(
            &mut live,
            &mut live_response,
            "Content-Type: text/event-stream",
        );
        assert!(!String::from_utf8_lossy(&live_response).contains("data: "));
        read_until(&mut live, &mut live_response, ": heartbeat");
        let new_event = event("live", json!({"status": "new"}));
        source.set_events(vec![first, other_run, new_event]);
        read_until(&mut live, &mut live_response, "\"node\":\"live\"");
        let live_response = String::from_utf8(live_response).expect("live-edge SSE UTF-8");
        assert!(!live_response.contains("\"node\":\"first\""));
        assert!(!live_response.contains("\"node\":\"other-run\""));
        assert!(live_response.contains("id: 3\n"));
        server.stop();
    }

    #[test]
    fn stream_keeps_identical_events_from_distinct_families() {
        let duplicate = event("shared-worker", json!({"status": "running"}));
        let source = Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        source.set_stream_events(vec![
            family_event("autopilot", duplicate.clone()),
            family_event("o2", duplicate),
        ]);
        let stream_source: Arc<dyn ScopeDataSource> = source;
        let mut server = TestServer::start(stream_source, test_config());
        let mut stream = open_stream(server.address, "/api/stream");
        let mut response = Vec::new();

        read_until(&mut stream, &mut response, "\"family\":\"autopilot\"");
        read_until(&mut stream, &mut response, "\"family\":\"o2\"");

        let response = String::from_utf8(response).expect("SSE response UTF-8");
        assert_eq!(response.matches("\"node\":\"shared-worker\"").count(), 2);
        assert_eq!(response.matches("\"family\":\"autopilot\"").count(), 1);
        assert_eq!(response.matches("\"family\":\"o2\"").count(), 1);
        server.stop();
    }

    #[test]
    fn transport_payload_adds_family_without_changing_normalized_event_serialization() {
        let event = event("worker-1", json!({"status": "running"}));
        let normalized = serde_json::to_value(&event).expect("normalized event JSON");
        assert!(normalized.get("family").is_none());

        let payload = serde_json::to_value(ScopeEventPayload {
            family: "o2-autopilot",
            event: &event,
        })
        .expect("Scope transport event JSON");
        assert_eq!(payload["family"], "o2-autopilot");
        assert_eq!(payload["repo"], normalized["repo"]);
        assert_eq!(payload["run"], normalized["run"]);
        assert_eq!(payload["payload"], normalized["payload"]);
    }
}
