use crate::steering::{
    plane::SteeringPlane,
    types::{SignedSteeringAckRequest, SignedSteeringRequest, SignedSteeringSweepRequest},
};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_CONNECTIONS: usize = 32;
const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SteeringServeOptions {
    pub repo: PathBuf,
    pub bind: String,
}

pub fn serve(options: SteeringServeOptions) -> Result<()> {
    let plane = SteeringPlane::open(&options.repo)?;
    bind_and_serve(&options.bind, plane)
}

pub fn bind_and_serve(bind: &str, plane: SteeringPlane) -> Result<()> {
    let address = validate_loopback_bind(bind)?;
    let listener = TcpListener::bind(address)
        .with_context(|| format!("failed to bind steering control plane to {address}"))?;
    let local_address = listener
        .local_addr()
        .context("failed to inspect steering listener address")?;
    println!("MACO steering control plane listening on http://{local_address}");
    serve_listener(listener, plane, Arc::new(AtomicBool::new(false)))
        .context("steering control plane failed")
}

pub fn serve_listener(
    listener: TcpListener,
    plane: SteeringPlane,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let local_address = listener.local_addr()?;
    if !local_address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "steering listener must use a loopback IP address",
        ));
    }
    listener.set_nonblocking(true)?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let current = active.fetch_add(1, Ordering::AcqRel);
                if current >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    let mut stream = stream;
                    let _ = write_json(
                        &mut stream,
                        "429 Too Many Requests",
                        &json!({"error": "over capacity"}),
                    );
                    continue;
                }
                let plane = plane.clone();
                let shutdown = Arc::clone(&shutdown);
                let active = Arc::clone(&active);
                let _ = thread::Builder::new()
                    .name("maco-steering-http".to_string())
                    .spawn(move || {
                        let _ = handle_connection(stream, plane, shutdown);
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn validate_loopback_bind(bind: &str) -> Result<SocketAddr> {
    let address = bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid steering bind address '{bind}'"))?;
    if !address.ip().is_loopback() {
        bail!("steering bind address must use a loopback IP address");
    }
    Ok(address)
}

fn handle_connection(
    mut stream: TcpStream,
    plane: SteeringPlane,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    if shutdown.load(Ordering::Acquire) {
        return Ok(());
    }
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let Some(request) = read_request(&mut stream)? else {
        return Ok(());
    };
    if !host_is_loopback(request.host.as_deref()) {
        return write_json(
            &mut stream,
            "403 Forbidden",
            &json!({"error": "host not allowed"}),
        );
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/steering/submit") => handle_submit(&mut stream, &plane, &request.body),
        ("POST", "/api/steering/ack") => handle_ack(&mut stream, &plane, &request.body),
        ("POST", "/api/steering/sweep") => handle_sweep(&mut stream, &plane, &request.body),
        ("GET", "/api/steering/evidence") => {
            handle_evidence(&mut stream, &plane, request.query.as_deref())
        }
        ("GET", "/api/steering/inbox") => {
            handle_inbox(&mut stream, &plane, request.query.as_deref())
        }
        ("GET", _) | ("POST", _) => {
            write_json(&mut stream, "404 Not Found", &json!({"error": "not found"}))
        }
        _ => write_json(
            &mut stream,
            "405 Method Not Allowed",
            &json!({"error": "method not allowed"}),
        ),
    }
}

fn handle_submit(stream: &mut TcpStream, plane: &SteeringPlane, body: &[u8]) -> io::Result<()> {
    let signed: SignedSteeringRequest = match serde_json::from_slice(body) {
        Ok(signed) => signed,
        Err(_) => {
            return write_json(
                stream,
                "400 Bad Request",
                &json!({"error": "ill_typed", "refusal": "ill_typed"}),
            );
        }
    };
    let now = match plane.current_unix_ms() {
        Ok(now) => now,
        Err(_) => {
            return write_json(
                stream,
                "500 Internal Server Error",
                &json!({"error": "clock"}),
            )
        }
    };
    match plane.submit_signed(signed, now) {
        Ok(decision) => {
            let ack = decision.ack();
            let status =
                if ack.refusal == Some(crate::steering::types::SteeringRefusal::Unauthenticated) {
                    "401 Unauthorized"
                } else if ack.refusal.is_some() {
                    "403 Forbidden"
                } else {
                    "200 OK"
                };
            write_json(stream, status, ack)
        }
        Err(_) => write_json(
            stream,
            "500 Internal Server Error",
            &json!({"error": "store"}),
        ),
    }
}

fn handle_ack(stream: &mut TcpStream, plane: &SteeringPlane, body: &[u8]) -> io::Result<()> {
    let signed: SignedSteeringAckRequest = match serde_json::from_slice(body) {
        Ok(signed) => signed,
        Err(_) => {
            return write_json(stream, "400 Bad Request", &json!({"error": "ill_typed"}));
        }
    };
    let now = match plane.current_unix_ms() {
        Ok(now) => now,
        Err(_) => {
            return write_json(
                stream,
                "500 Internal Server Error",
                &json!({"error": "clock"}),
            )
        }
    };
    if plane.verify_ack_mac(&signed).is_err() {
        return write_json(
            stream,
            "401 Unauthorized",
            &json!({"error": "unauthenticated", "refusal": "unauthenticated"}),
        );
    }
    match plane.acknowledge(
        &signed.run_id,
        &signed.assignment_id,
        &signed.action_id,
        now,
    ) {
        Ok(ack) => write_json(stream, "200 OK", &ack),
        Err(_) => write_json(stream, "400 Bad Request", &json!({"error": "ack_failed"})),
    }
}

fn handle_sweep(stream: &mut TcpStream, plane: &SteeringPlane, body: &[u8]) -> io::Result<()> {
    let signed: SignedSteeringSweepRequest = match serde_json::from_slice(body) {
        Ok(signed) => signed,
        Err(_) => {
            return write_json(stream, "400 Bad Request", &json!({"error": "ill_typed"}));
        }
    };
    let now = match plane.current_unix_ms() {
        Ok(now) => now,
        Err(_) => {
            return write_json(
                stream,
                "500 Internal Server Error",
                &json!({"error": "clock"}),
            )
        }
    };
    if plane.verify_sweep_mac(&signed).is_err() {
        return write_json(
            stream,
            "401 Unauthorized",
            &json!({"error": "unauthenticated", "refusal": "unauthenticated"}),
        );
    }
    match plane.sweep(&signed.run_id, now) {
        Ok(acks) => write_json(stream, "200 OK", &acks),
        Err(_) => write_json(stream, "400 Bad Request", &json!({"error": "sweep_failed"})),
    }
}

fn handle_evidence(
    stream: &mut TcpStream,
    plane: &SteeringPlane,
    query: Option<&str>,
) -> io::Result<()> {
    let Some(run_id) = query_param(query, "run") else {
        return write_json(stream, "400 Bad Request", &json!({"error": "missing run"}));
    };
    match plane.evidence(&run_id) {
        Ok(records) => write_json(stream, "200 OK", &records),
        Err(_) => write_json(
            stream,
            "400 Bad Request",
            &json!({"error": "evidence_failed"}),
        ),
    }
}

fn handle_inbox(
    stream: &mut TcpStream,
    plane: &SteeringPlane,
    query: Option<&str>,
) -> io::Result<()> {
    let Some(run_id) = query_param(query, "run") else {
        return write_json(stream, "400 Bad Request", &json!({"error": "missing run"}));
    };
    let Some(assignment_id) = query_param(query, "assignment") else {
        return write_json(
            stream,
            "400 Bad Request",
            &json!({"error": "missing assignment"}),
        );
    };
    match plane.inbox(&run_id, &assignment_id) {
        Ok(directives) => write_json(stream, "200 OK", &directives),
        Err(_) => write_json(stream, "400 Bad Request", &json!({"error": "inbox_failed"})),
    }
}

struct ParsedRequest {
    method: String,
    path: String,
    query: Option<String>,
    host: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> io::Result<Option<ParsedRequest>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > MAX_REQUEST_HEADER_BYTES + MAX_REQUEST_BODY_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "steering request exceeded its bound",
                    ));
                }
                if let Some(header_end) = find_header_end(&buffer) {
                    let (header, rest) = buffer.split_at(header_end);
                    let header_text = String::from_utf8_lossy(header);
                    let mut lines = header_text.split("\r\n");
                    let request_line = lines.next().unwrap_or("");
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let target = parts.next().unwrap_or("").to_string();
                    let (path, query) = match target.split_once('?') {
                        Some((path, query)) => (path.to_string(), Some(query.to_string())),
                        None => (target, None),
                    };
                    let mut host = None;
                    let mut content_length = 0_usize;
                    for line in lines {
                        if line.is_empty() {
                            continue;
                        }
                        if let Some(value) = line.strip_prefix("Host:") {
                            host = Some(value.trim().to_string());
                        }
                        if let Some(value) = line.strip_prefix("Content-Length:") {
                            content_length = match value.trim().parse() {
                                Ok(length) => length,
                                Err(_) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "steering Content-Length is ill-typed",
                                    ));
                                }
                            };
                        }
                    }
                    if content_length > MAX_REQUEST_BODY_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "steering request body exceeded its bound",
                        ));
                    }
                    let mut body = rest.to_vec();
                    while body.len() < content_length {
                        let read = stream.read(&mut chunk)?;
                        if read == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..read]);
                    }
                    body.truncate(content_length);
                    return Ok(Some(ParsedRequest {
                        method,
                        path,
                        query,
                        host,
                        body,
                    }));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn host_is_loopback(host: Option<&str>) -> bool {
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

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
        .filter(|value| !value.is_empty())
}

fn write_json<T: serde::Serialize>(
    stream: &mut TcpStream,
    status: &str,
    value: &T,
) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    if body.len() > MAX_JSON_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "steering response exceeded its bound",
        ));
    }
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}
