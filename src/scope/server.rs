use std::{
    collections::BTreeSet,
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

use crate::{artifacts::state_auth::sha256_hex, orchestration_event::OrchestrationEvent};

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

    fn stream_events(&self) -> Result<Vec<OrchestrationEvent>>;
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
        "/api/stream" => write_event_stream(&mut stream, source, shutdown, config),
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
        Ok(Some(events)) => write_json_response(
            stream,
            "200 OK",
            &events,
            &[],
            config.max_json_response_bytes,
        ),
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

fn write_event_stream(
    stream: &mut TcpStream,
    source: Arc<dyn ScopeDataSource>,
    shutdown: Arc<AtomicBool>,
    config: ServerConfig,
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

    let mut previous_scan = BTreeSet::new();
    let mut last_heartbeat = Instant::now();
    while !shutdown.load(Ordering::Acquire) {
        match source.stream_events() {
            Ok(events) => {
                if events.len() > config.max_stream_events_per_scan {
                    stream.write_all(b": event scan exceeds limit\n\n")?;
                } else {
                    let mut current_scan = BTreeSet::new();
                    for event in events {
                        let serialized =
                            match serialize_json_bounded(&event, config.max_sse_event_bytes) {
                                Ok(serialized) => serialized,
                                Err(_) => {
                                    stream.write_all(b": event exceeds serialization limit\n\n")?;
                                    continue;
                                }
                            };
                        let event_id = sha256_hex(&serialized);
                        let first_in_scan = current_scan.insert(event_id.clone());
                        if first_in_scan && !previous_scan.contains(&event_id) {
                            stream.write_all(b"data: ")?;
                            stream.write_all(&serialized)?;
                            stream.write_all(b"\n\n")?;
                        }
                    }
                    previous_scan = current_scan;
                }
            }
            Err(_) => {
                stream.write_all(b": scan error\n\n")?;
                stream.flush()?;
            }
        }
        stream.flush()?;

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
    let path = target.split('?').next().unwrap_or_default();
    if !path.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request target must be an origin-form path",
        ));
    }
    Ok(Some(Request {
        method: method.to_string(),
        path: path.to_string(),
    }))
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

    use super::*;

    struct TestDataSource {
        projects: Value,
        events: Mutex<Vec<OrchestrationEvent>>,
        expected_route: Option<(String, String, String)>,
    }

    impl TestDataSource {
        fn new(projects: Value, events: Vec<OrchestrationEvent>) -> Self {
            Self {
                projects,
                events: Mutex::new(events),
                expected_route: None,
            }
        }

        fn with_route(mut self, repo_id: &str, family: &str, run_id: &str) -> Self {
            self.expected_route =
                Some((repo_id.to_string(), family.to_string(), run_id.to_string()));
            self
        }

        fn set_events(&self, events: Vec<OrchestrationEvent>) {
            *self.events.lock().expect("lock test events") = events;
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
            Ok(Some(self.events.lock().expect("lock test events").clone()))
        }

        fn stream_events(&self) -> Result<Vec<OrchestrationEvent>> {
            Ok(self.events.lock().expect("lock test events").clone())
        }
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

    fn open_stream(address: SocketAddr, path: &str) -> TcpStream {
        let mut stream = TcpStream::connect(address).expect("connect to test server");
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set test read timeout");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .expect("write test request");
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
    fn root_serves_embedded_spawn_tree_frontend() {
        let source: Arc<dyn ScopeDataSource> =
            Arc::new(TestDataSource::new(json!({"projects": []}), Vec::new()));
        let mut server = TestServer::start(source, test_config());

        let response = http_get(server.address, "/");

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("text/html; charset=utf-8"));
        assert!(response.contains("MACO_SCOPE_SPAWN_TREE_UI"));
        assert!(response.contains("id=\"edgeSummary\""));
        assert!(response.contains("reviewed_worker_ids"));
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
        let mut scan_config = test_config();
        scan_config.max_stream_events_per_scan = 1;
        let mut scan_server = TestServer::start(source, scan_config);
        let mut stream = open_stream(scan_server.address, "/api/stream");
        let mut scan_response = Vec::new();
        read_until(
            &mut stream,
            &mut scan_response,
            ": event scan exceeds limit",
        );
        assert!(!String::from_utf8_lossy(&scan_response).contains("data: "));
        scan_server.stop();
    }

    #[test]
    fn stream_deduplicates_unchanged_events_emits_new_events_and_heartbeats() {
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
        read_until(&mut stream, &mut response, ": heartbeat");
        source.set_events(vec![first, second]);
        read_until(&mut stream, &mut response, "\"node\":\"worker-2\"");

        let response = String::from_utf8(response).expect("SSE response UTF-8");
        assert_eq!(response.matches("\"node\":\"worker-1\"").count(), 1);
        assert_eq!(response.matches("\"node\":\"worker-2\"").count(), 1);
        assert!(response.contains(": heartbeat\n\n"));
        server.stop();
    }
}
