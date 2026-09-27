//! Loopback-only NDJSON transport for one admitted assignment's messaging IPC.
//!
//! Wire contract (one request line, one response line per TCP connection):
//! ```json
//! {"bearer":"<ephemeral-secret>","request":{"operation":"<name>", ...}}
//! ```
//! ```json
//! {"ok":true,"result":<value>}
//! {"ok":false,"error":"<message>"}
//! ```
//! Top-level fields are exactly `bearer` and `request`. The server verifies `bearer`
//! before invoking the bound handler with the inner `request` object only.

use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::artifacts::state_auth::random_identifier;

pub(crate) const ENV_MESSAGE_ENDPOINT: &str = "MACO_MESSAGE_ENDPOINT";
pub(crate) const ENV_MESSAGE_TOKEN: &str = "MACO_MESSAGE_TOKEN";
#[cfg(test)]
pub(crate) const MACO_MESSAGE_ENDPOINT_ENV: &str = ENV_MESSAGE_ENDPOINT;
pub(crate) const MACO_MESSAGE_TOKEN_ENV: &str = ENV_MESSAGE_TOKEN;

const LOOPBACK_BIND: &str = "127.0.0.1:0";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CONNECTION_BUDGET: Duration = Duration::from_secs(5);
const IO_SLICE_TIMEOUT: Duration = Duration::from_millis(200);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const READ_CHUNK_BYTES: usize = 4096;
const MIN_BEARER_BYTES: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    bearer: String,
    request: Value,
}

/// Child-launch material for one assignment-bound messaging endpoint.
///
/// Constructed only by [`AssignmentMessagingServer`]; not serializable.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AssignmentMessagingLaunch {
    endpoint: String,
    token: String,
    run_id: String,
    task_id: String,
}

impl AssignmentMessagingLaunch {
    fn new(endpoint: String, token: String, run_id: String, task_id: String) -> Self {
        Self {
            endpoint,
            token,
            run_id,
            task_id,
        }
    }

    /// Returns launch environment entries only when `run_id` and `task_id` match exactly.
    pub(crate) fn environment_for(
        &self,
        run_id: &str,
        task_id: &str,
    ) -> Result<Vec<(String, String)>> {
        if self.run_id != run_id || self.task_id != task_id {
            bail!("assignment messaging launch binding does not match the requested run and task");
        }
        Ok(vec![
            (ENV_MESSAGE_ENDPOINT.to_string(), self.endpoint.clone()),
            (ENV_MESSAGE_TOKEN.to_string(), self.token.clone()),
        ])
    }

    /// Forwards one sealed worker submit or status request to this launch's own loopback endpoint.
    ///
    /// The dial address and bearer always come from this launch. `request` may only be one of the
    /// two strict worker-request objects; run and task must match before any connection is opened.
    pub(crate) fn forward_worker_request(
        &self,
        run_id: &str,
        task_id: &str,
        request: &Value,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value> {
        if cancelled() {
            bail!("assignment messaging forward cancelled");
        }
        if self.run_id != run_id || self.task_id != task_id {
            bail!("assignment messaging launch binding does not match the requested run and task");
        }
        let request = seal_forwarded_worker_request(request)?;
        if cancelled() {
            bail!("assignment messaging forward cancelled");
        }
        let address = require_loopback_endpoint(&self.endpoint)?;
        let mut encoded = serde_json::to_vec(&json!({
            "bearer": &self.token,
            "request": request,
        }))
        .map_err(|_| {
            anyhow::anyhow!("assignment messaging forward request could not be encoded")
        })?;
        if encoded.len() > MAX_REQUEST_BYTES {
            bail!("assignment messaging forward request exceeded its bound");
        }
        encoded.push(b'\n');

        let shutdown = Arc::new(AtomicBool::new(false));
        let budget = ConnectionBudget::new(CONNECTION_BUDGET, shutdown, cancelled);
        let mut stream = connect_bounded(address, &budget).map_err(map_forward_io)?;
        let _ = stream.set_nodelay(true);
        write_all_bounded(&mut stream, &encoded, &budget).map_err(map_forward_io)?;
        let line = read_exact_ndjson_line(&mut stream, MAX_RESPONSE_BYTES, &budget)
            .map_err(map_forward_io)?
            .ok_or_else(|| anyhow::anyhow!("assignment messaging forward response was rejected"))?;
        accepted_forward_result(&line)
    }

    #[cfg(test)]
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl fmt::Debug for AssignmentMessagingLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssignmentMessagingLaunch")
            .field("endpoint", &self.endpoint)
            .field("token", &"[REDACTED]")
            .field("run_id", &self.run_id)
            .field("task_id", &self.task_id)
            .finish()
    }
}

/// RAII loopback listener for one assignment messaging session.
pub(crate) struct AssignmentMessagingServer {
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    launch: AssignmentMessagingLaunch,
    // Test-only notification after shutdown is requested, before joining the handler.
    #[cfg(test)]
    pub(crate) shutdown_observer: Option<std::sync::mpsc::Sender<()>>,
}

impl AssignmentMessagingServer {
    pub(crate) fn start(
        run_id: &str,
        task_id: &str,
        handler: impl Fn(Value) -> Result<Value> + Send + Sync + 'static,
    ) -> Result<Self> {
        let listener = TcpListener::bind(LOOPBACK_BIND)
            .context("failed to bind assignment messaging listener to loopback")?;
        let local_address = listener
            .local_addr()
            .context("failed to inspect assignment messaging listener address")?;
        if !local_address.ip().is_loopback() {
            bail!("assignment messaging listener must bind a loopback address");
        }
        listener
            .set_nonblocking(true)
            .context("failed to configure nonblocking assignment messaging accept")?;

        let bearer = generate_ephemeral_bearer()?;
        let launch = AssignmentMessagingLaunch::new(
            local_address.to_string(),
            bearer.clone(),
            run_id.to_string(),
            task_id.to_string(),
        );
        let expected_bearer = bearer;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::Builder::new()
            .name("maco-assignment-messaging".to_string())
            .spawn(move || {
                serve_listener(listener, expected_bearer, handler, worker_shutdown);
            })
            .context("failed to start assignment messaging accept thread")?;

        Ok(Self {
            shutdown,
            worker: Some(worker),
            launch,
            #[cfg(test)]
            shutdown_observer: None,
        })
    }

    pub(crate) fn launch(&self) -> AssignmentMessagingLaunch {
        self.launch.clone()
    }
}

impl fmt::Debug for AssignmentMessagingServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssignmentMessagingServer")
            .field("launch", &self.launch)
            .finish_non_exhaustive()
    }
}

impl Drop for AssignmentMessagingServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        #[cfg(test)]
        if let Some(observer) = &self.shutdown_observer {
            let _ = observer.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn generate_ephemeral_bearer() -> Result<String> {
    let bearer = random_identifier().context("failed to generate assignment messaging bearer")?;
    if bearer.len() < MIN_BEARER_BYTES {
        bail!("assignment messaging bearer is shorter than the required minimum");
    }
    Ok(bearer)
}

fn serve_listener(
    listener: TcpListener,
    expected_bearer: String,
    handler: impl Fn(Value) -> Result<Value> + Send + Sync,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                if !peer.ip().is_loopback() {
                    continue;
                }
                let _ =
                    handle_connection(stream, &expected_bearer, &handler, Arc::clone(&shutdown));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => break,
        }
    }
}

struct ConnectionBudget<'a> {
    deadline: Instant,
    shutdown: Arc<AtomicBool>,
    cancelled: &'a dyn Fn() -> bool,
}

fn never_cancelled() -> bool {
    false
}

impl<'a> ConnectionBudget<'a> {
    fn new(total: Duration, shutdown: Arc<AtomicBool>, cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            deadline: Instant::now() + total,
            shutdown,
            cancelled,
        }
    }

    fn check_continue(&self) -> io::Result<()> {
        if (self.cancelled)() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "assignment messaging forward cancelled",
            ));
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "assignment messaging connection interrupted by shutdown",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "assignment messaging connection exceeded its budget",
            ));
        }
        Ok(())
    }

    fn remaining(&self) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .min(CONNECTION_BUDGET)
    }

    fn configure_read_timeout(&self, stream: &TcpStream) -> io::Result<()> {
        let timeout = self.remaining().min(IO_SLICE_TIMEOUT);
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "assignment messaging connection exceeded its budget",
            ));
        }
        stream.set_read_timeout(Some(timeout))
    }

    fn configure_write_timeout(&self, stream: &TcpStream) -> io::Result<()> {
        let timeout = self.remaining().min(IO_SLICE_TIMEOUT);
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "assignment messaging connection exceeded its budget",
            ));
        }
        stream.set_write_timeout(Some(timeout))
    }
}

fn handle_connection(
    mut stream: TcpStream,
    expected_bearer: &str,
    handler: &dyn Fn(Value) -> Result<Value>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let budget = ConnectionBudget::new(CONNECTION_BUDGET, shutdown, &never_cancelled);

    let request_line = match read_ndjson_line(&mut stream, MAX_REQUEST_BYTES, &budget) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()),
        Err(_) => {
            let _ = write_response(&mut stream, error_response("malformed request"), &budget);
            return Ok(());
        }
    };

    let response = match parse_and_dispatch(&request_line, expected_bearer, handler) {
        Ok(value) => success_response(value),
        Err(error) => error_response(sanitize_error(&error.to_string(), expected_bearer)),
    };
    let _ = write_response(&mut stream, response, &budget);
    Ok(())
}

fn parse_and_dispatch(
    request_line: &[u8],
    expected_bearer: &str,
    handler: &dyn Fn(Value) -> Result<Value>,
) -> Result<Value> {
    let envelope: WireEnvelope =
        serde_json::from_slice(request_line).context("request is not valid JSON")?;
    if !secrets_equal(envelope.bearer.as_bytes(), expected_bearer.as_bytes()) {
        bail!("bearer is not authorized for this assignment messaging endpoint");
    }
    handler(envelope.request)
}

fn read_ndjson_line(
    stream: &mut TcpStream,
    max_bytes: usize,
    budget: &ConnectionBudget<'_>,
) -> io::Result<Option<Vec<u8>>> {
    read_ndjson_line_inner(stream, max_bytes, budget, false)
}

fn read_exact_ndjson_line(
    stream: &mut TcpStream,
    max_bytes: usize,
    budget: &ConnectionBudget<'_>,
) -> io::Result<Option<Vec<u8>>> {
    read_ndjson_line_inner(stream, max_bytes, budget, true)
}

fn read_ndjson_line_inner(
    stream: &mut TcpStream,
    max_bytes: usize,
    budget: &ConnectionBudget<'_>,
    reject_trailing: bool,
) -> io::Result<Option<Vec<u8>>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    while buffer.len() <= max_bytes {
        budget.check_continue()?;
        budget.configure_read_timeout(stream)?;
        match stream.read(&mut chunk) {
            Ok(0) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated NDJSON request",
                ));
            }
            Ok(read) => {
                if let Some(relative_newline) = chunk[..read].iter().position(|byte| *byte == b'\n')
                {
                    if reject_trailing && relative_newline + 1 < read {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailing data after NDJSON response",
                        ));
                    }
                    buffer.extend_from_slice(&chunk[..relative_newline]);
                    return Ok(Some(buffer));
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NDJSON request exceeded its bound",
                    ));
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                budget.check_continue()?;
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "NDJSON request exceeded its bound",
    ))
}

fn write_response(
    stream: &mut TcpStream,
    response: Value,
    budget: &ConnectionBudget<'_>,
) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to encode assignment messaging response: {error}"),
        )
    })?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "assignment messaging response exceeded its bound",
        ));
    }
    encoded.push(b'\n');
    write_all_bounded(stream, &encoded, budget)
}

fn write_all_bounded(
    stream: &mut TcpStream,
    payload: &[u8],
    budget: &ConnectionBudget<'_>,
) -> io::Result<()> {
    let mut offset = 0_usize;
    while offset < payload.len() {
        budget.check_continue()?;
        budget.configure_write_timeout(stream)?;
        match stream.write(&payload[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "assignment messaging write stalled",
                ));
            }
            Ok(written) => offset += written,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                budget.check_continue()?;
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn connect_bounded(address: SocketAddr, budget: &ConnectionBudget<'_>) -> io::Result<TcpStream> {
    loop {
        budget.check_continue()?;
        let timeout = budget.remaining().min(IO_SLICE_TIMEOUT);
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "assignment messaging connection exceeded its budget",
            ));
        }
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                budget.check_continue()?;
                continue;
            }
            Err(_) => {
                budget.check_continue()?;
                let pause = budget.remaining().min(Duration::from_millis(20));
                if pause.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "assignment messaging connection exceeded its budget",
                    ));
                }
                thread::sleep(pause);
            }
        }
    }
}

const MAX_FORWARD_ID_BYTES: usize = 128;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum SealedWorkerForward {
    SubmitWorkerRequest {
        request_id: String,
        worker_id: String,
    },
    WorkerRequestStatus {
        request_id: String,
    },
}

fn seal_forwarded_worker_request(request: &Value) -> Result<Value> {
    let sealed: SealedWorkerForward = serde_json::from_value(request.clone()).map_err(|_| {
        anyhow::anyhow!("assignment messaging forward request is not an allowed worker operation")
    })?;
    match &sealed {
        SealedWorkerForward::SubmitWorkerRequest {
            request_id,
            worker_id,
        } => {
            validate_forward_id(request_id)?;
            validate_forward_id(worker_id)?;
        }
        SealedWorkerForward::WorkerRequestStatus { request_id } => {
            validate_forward_id(request_id)?;
        }
    }
    serde_json::to_value(sealed)
        .map_err(|_| anyhow::anyhow!("assignment messaging forward request could not be encoded"))
}

/// Same canonical identifier rule as the supervisor worker-request inbox (`1..=128` ASCII).
fn validate_forward_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_FORWARD_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || id == "."
        || id == ".."
    {
        bail!("assignment messaging forward identifier is empty, malformed, or oversize");
    }
    Ok(())
}

fn require_loopback_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let address: SocketAddr = endpoint.parse().map_err(|_| {
        anyhow::anyhow!("assignment messaging endpoint is not a loopback socket address")
    })?;
    if !address.ip().is_loopback() {
        bail!("assignment messaging endpoint is not a loopback socket address");
    }
    Ok(address)
}

fn accepted_forward_result(line: &[u8]) -> Result<Value> {
    let response: Value = serde_json::from_slice(line)
        .map_err(|_| anyhow::anyhow!("assignment messaging forward response was rejected"))?;
    let Some(object) = response.as_object() else {
        bail!("assignment messaging forward response was rejected");
    };
    if object.len() == 2 && object.get("ok") == Some(&Value::Bool(true)) {
        if let Some(result) = object.get("result") {
            return Ok(result.clone());
        }
    }
    bail!("assignment messaging forward response was rejected");
}

fn map_forward_io(error: io::Error) -> anyhow::Error {
    match error.kind() {
        io::ErrorKind::Interrupted => anyhow::anyhow!("assignment messaging forward cancelled"),
        io::ErrorKind::TimedOut => anyhow::anyhow!("assignment messaging forward timed out"),
        _ => anyhow::anyhow!("assignment messaging forward failed"),
    }
}

fn success_response(result: Value) -> Value {
    json!({ "ok": true, "result": result })
}

fn error_response(message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": message.into() })
}

fn sanitize_error(message: &str, bearer: &str) -> String {
    if bearer.is_empty() {
        return message.to_string();
    }
    message.replace(bearer, "[REDACTED]")
}

fn secrets_equal(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

/// Serializes broker-facing operation results for the wire.
pub(crate) fn serialize_messaging_result<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).context("failed to serialize assignment messaging result")
}

/// Collects channel member/publisher lists into the broker's unique set type.
pub(crate) fn string_array_to_set(values: Vec<String>) -> BTreeSet<String> {
    values.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    fn echo_handler() -> impl Fn(Value) -> Result<Value> + Send + Sync + 'static {
        |request| Ok(request)
    }

    fn test_budget() -> ConnectionBudget<'static> {
        ConnectionBudget::new(
            CONNECTION_BUDGET,
            Arc::new(AtomicBool::new(false)),
            &never_cancelled,
        )
    }

    fn exchange(endpoint: &str, bearer: &str, request: Value) -> Result<Value> {
        let mut stream = TcpStream::connect(endpoint).context("connect to assignment messaging")?;
        let budget = test_budget();
        let envelope = json!({ "bearer": bearer, "request": request });
        write_response(&mut stream, envelope, &budget)?;
        let line = read_ndjson_line(&mut stream, MAX_RESPONSE_BYTES, &budget)
            .context("read assignment messaging response")?
            .context("assignment messaging response was empty")?;
        serde_json::from_slice(&line).context("assignment messaging response is not valid JSON")
    }

    #[test]
    fn launch_environment_requires_exact_run_and_task_binding() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", echo_handler())?;
        let launch = server.launch();
        let environment = launch.environment_for("run-a", "task-a")?;
        assert_eq!(environment.len(), 2);
        assert_eq!(environment[0].0, ENV_MESSAGE_ENDPOINT);
        assert_eq!(environment[0].1, launch.endpoint());
        assert_eq!(environment[1].0, ENV_MESSAGE_TOKEN);
        assert!(!environment[1].1.is_empty());
        assert!(launch.environment_for("run-b", "task-a").is_err());
        assert!(launch.environment_for("run-a", "task-b").is_err());
        Ok(())
    }

    #[test]
    fn launch_debug_redacts_token() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", echo_handler())?;
        let launch = server.launch();
        let token = launch
            .environment_for("run-a", "task-a")?
            .into_iter()
            .find(|(key, _)| key == ENV_MESSAGE_TOKEN)
            .map(|(_, value)| value)
            .expect("token");
        let debug = format!("{launch:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&token));
        Ok(())
    }

    #[test]
    fn wrong_bearer_is_rejected_without_invoking_handler() -> Result<()> {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&calls);
        let server = AssignmentMessagingServer::start("run-a", "task-a", move |_| {
            calls_for_handler.fetch_add(1, Ordering::AcqRel);
            Ok(json!({"seen": true}))
        })?;
        let launch = server.launch();
        let token = launch
            .environment_for("run-a", "task-a")?
            .into_iter()
            .find(|(key, _)| key == ENV_MESSAGE_TOKEN)
            .map(|(_, value)| value)
            .expect("token");

        let response = exchange(
            launch.endpoint(),
            "definitely-not-the-real-bearer-token-value",
            json!({"operation": "receive_next"}),
        )?;
        assert_eq!(
            response,
            json!({"ok": false, "error": "bearer is not authorized for this assignment messaging endpoint"})
        );
        assert!(!response.to_string().contains(&token));
        assert_eq!(calls.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_requests_fail_closed() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", echo_handler())?;
        let launch = server.launch();
        let (endpoint, bearer) = launch_environment(&launch, "run-a", "task-a")?;

        let budget = test_budget();
        let mut stream = TcpStream::connect(&endpoint)?;
        stream.write_all(b"{not-json\n")?;
        let line = read_ndjson_line(&mut stream, MAX_RESPONSE_BYTES, &budget)?
            .context("malformed request should still receive a response")?;
        let response = serde_json::from_slice::<Value>(&line)?;
        assert_eq!(response.get("ok"), Some(&Value::Bool(false)));

        let budget = test_budget();
        let mut stream = TcpStream::connect(&endpoint)?;
        stream.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])?;
        stream.write_all(b"\n")?;
        let line = read_ndjson_line(&mut stream, MAX_RESPONSE_BYTES, &budget)?
            .context("oversized request should still receive a response")?;
        let response = serde_json::from_slice::<Value>(&line)?;
        assert_eq!(response.get("ok"), Some(&Value::Bool(false)));

        let budget = test_budget();
        let mut stream = TcpStream::connect(&endpoint)?;
        let envelope = json!({
            "bearer": bearer,
            "request": {"operation": "receive_next"},
            "spoofed_run_id": "stolen"
        });
        write_response(&mut stream, envelope, &budget)?;
        let line = read_ndjson_line(&mut stream, MAX_RESPONSE_BYTES, &budget)?
            .context("unknown wire field should still receive a response")?;
        let response = serde_json::from_slice::<Value>(&line)?;
        assert_eq!(response.get("ok"), Some(&Value::Bool(false)));
        Ok(())
    }

    #[test]
    fn slow_drip_client_cannot_block_server_drop_beyond_connection_budget() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", echo_handler())?;
        let endpoint = server.launch().endpoint().to_string();
        let drip = thread::spawn(move || {
            let mut stream = TcpStream::connect(&endpoint).expect("connect for drip client");
            for _ in 0..200 {
                let _ = stream.write_all(b"a");
                thread::sleep(Duration::from_millis(40));
            }
        });
        let started = Instant::now();
        drop(server);
        let elapsed = started.elapsed();
        assert!(
            elapsed < CONNECTION_BUDGET + Duration::from_secs(2),
            "server drop joined after {:?}, expected <= {:?}",
            elapsed,
            CONNECTION_BUDGET + Duration::from_secs(2)
        );
        let _ = drip.join();
        Ok(())
    }

    #[test]
    fn normal_exchange_and_shutdown_are_bounded() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", echo_handler())?;
        let launch = server.launch();
        let (endpoint, bearer) = launch_environment(&launch, "run-a", "task-a")?;

        let response = exchange(
            &endpoint,
            &bearer,
            json!({"operation": "ping", "payload": {"bounded": true}}),
        )?;
        assert_eq!(
            response,
            json!({
                "ok": true,
                "result": {"operation": "ping", "payload": {"bounded": true}}
            })
        );

        drop(server);
        let connect_result = exchange(&endpoint, &bearer, json!({"operation": "after_shutdown"}));
        assert!(connect_result.is_err());
        Ok(())
    }

    fn not_cancelled() -> bool {
        false
    }

    #[test]
    fn forward_worker_request_submits_and_reads_status_on_loopback() -> Result<()> {
        let server = AssignmentMessagingServer::start("run-a", "task-a", |request| match request
            .get("operation")
            .and_then(Value::as_str)
        {
            Some("submit_worker_request") => Ok(json!({
                "request_id": request.get("request_id").cloned().unwrap_or(Value::Null),
                "worker_id": request.get("worker_id").cloned().unwrap_or(Value::Null),
                "status": "queued"
            })),
            Some("worker_request_status") => Ok(json!({
                "request_id": request.get("request_id").cloned().unwrap_or(Value::Null),
                "status": "queued"
            })),
            _ => bail!("unexpected operation"),
        })?;
        let launch = server.launch();
        let submitted = launch.forward_worker_request(
            "run-a",
            "task-a",
            &json!({
                "operation": "submit_worker_request",
                "request_id": "request.1",
                "worker_id": "worker_a"
            }),
            &not_cancelled,
        )?;
        assert_eq!(
            submitted,
            json!({"request_id": "request.1", "worker_id": "worker_a", "status": "queued"})
        );
        let status = launch.forward_worker_request(
            "run-a",
            "task-a",
            &json!({"operation": "worker_request_status", "request_id": "request.1"}),
            &not_cancelled,
        )?;
        assert_eq!(
            status,
            json!({"request_id": "request.1", "status": "queued"})
        );
        let replies = format!("{submitted} {status}");
        let debug = format!("{launch:?}");
        let token = launch
            .environment_for("run-a", "task-a")?
            .into_iter()
            .find(|(key, _)| key == ENV_MESSAGE_TOKEN)
            .map(|(_, value)| value)
            .expect("token");
        assert!(!replies.contains(&token));
        assert!(!debug.contains(&token));
        assert!(!replies.contains(launch.endpoint()));
        Ok(())
    }

    #[test]
    fn forward_worker_request_rejects_binding_shape_and_cancel_without_handler() -> Result<()> {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&calls);
        let server = AssignmentMessagingServer::start("run-a", "task-a", move |_| {
            calls_for_handler.fetch_add(1, Ordering::AcqRel);
            Ok(json!({"seen": true}))
        })?;
        let launch = server.launch();
        let valid = json!({"operation": "worker_request_status", "request_id": "request"});
        assert!(launch
            .forward_worker_request("run-b", "task-a", &valid, &not_cancelled)
            .is_err());
        assert!(launch
            .forward_worker_request("run-a", "task-b", &valid, &not_cancelled)
            .is_err());
        let oversize = "x".repeat(MAX_FORWARD_ID_BYTES + 1);
        let rejected = [
            json!({"operation": "worker_request_status", "request_id": "request", "worker_id": "worker"}),
            json!({"operation": "send_direct", "recipient_id": "peer", "payload": {}}),
            json!({"operation": "submit_worker_request", "request_id": "", "worker_id": "worker"}),
            json!({"operation": "submit_worker_request", "request_id": ".", "worker_id": "worker"}),
            json!({"operation": "submit_worker_request", "request_id": "..", "worker_id": "worker"}),
            json!({"operation": "submit_worker_request", "request_id": "../escape", "worker_id": "worker"}),
            json!({"operation": "submit_worker_request", "request_id": oversize, "worker_id": "worker"}),
            json!({"operation": "submit_worker_request", "request_id": "request"}),
            json!({"operation": "worker_request_status"}),
            json!("worker_request_status"),
        ];
        for request in &rejected {
            assert!(
                launch
                    .forward_worker_request("run-a", "task-a", request, &not_cancelled)
                    .is_err(),
                "accepted rejected request {request}"
            );
        }
        assert!(launch
            .forward_worker_request("run-a", "task-a", &valid, &|| true)
            .is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn forward_worker_request_denies_non_loopback_endpoint_without_dialing() {
        let token = "t".repeat(MIN_BEARER_BYTES);
        let launch = AssignmentMessagingLaunch::new(
            "192.0.2.1:9".to_string(),
            token.clone(),
            "run-a".to_string(),
            "task-a".to_string(),
        );
        let started = Instant::now();
        let error = launch
            .forward_worker_request(
                "run-a",
                "task-a",
                &json!({"operation": "worker_request_status", "request_id": "request"}),
                &not_cancelled,
            )
            .expect_err("non-loopback endpoint must be denied");
        assert!(started.elapsed() < Duration::from_secs(1));
        let message = error.to_string();
        assert!(!message.contains("192.0.2.1"));
        assert!(!message.contains(&token));
        let unparsed = AssignmentMessagingLaunch::new(
            "localhost:9".to_string(),
            token,
            "run-a".to_string(),
            "task-a".to_string(),
        );
        assert!(unparsed
            .forward_worker_request(
                "run-a",
                "task-a",
                &json!({"operation": "worker_request_status", "request_id": "request"}),
                &not_cancelled,
            )
            .is_err());
    }

    #[test]
    fn forward_worker_request_fails_closed_on_invalid_truncated_and_held_replies() -> Result<()> {
        let token = "s".repeat(MIN_BEARER_BYTES);
        let cases: Vec<Vec<u8>> = vec![
            b"not-json\n".to_vec(),
            br#"{"ok":true}"#.to_vec(),
            b"{\"ok\":true}\n".to_vec(),
            format!("{{\"ok\":false,\"error\":\"{token} at 127.0.0.1\"}}\n").into_bytes(),
            b"{\"ok\":true,\"result\":{\"status\":\"queued\"},\"extra\":1}\n".to_vec(),
            b"{\"ok\":true,\"result\":1}\n{\"ok\":true,\"result\":2}\n".to_vec(),
            b"{\"ok\":true,\"result\":".to_vec(),
        ];
        for payload in cases {
            let address = reply_once(payload, false);
            let launch = forwarded_launch(address, &token);
            let error = launch
                .forward_worker_request(
                    "run-a",
                    "task-a",
                    &json!({"operation": "worker_request_status", "request_id": "request"}),
                    &not_cancelled,
                )
                .expect_err("invalid reply must fail closed");
            let message = error.to_string();
            assert!(!message.contains(&token));
            assert!(!message.contains(launch.endpoint()));
            assert!(!message.contains("127.0.0.1"));
        }

        let address = reply_once(b"{".to_vec(), true);
        let launch = forwarded_launch(address, &token);
        let started = Instant::now();
        let error = launch
            .forward_worker_request(
                "run-a",
                "task-a",
                &json!({"operation": "worker_request_status", "request_id": "request"}),
                &not_cancelled,
            )
            .expect_err("held partial reply must time out");
        assert!(
            started.elapsed() < CONNECTION_BUDGET + Duration::from_secs(2),
            "held reply blocked for {:?}",
            started.elapsed()
        );
        let message = error.to_string();
        assert!(message.contains("timed out"));
        assert!(!message.contains(&token));
        assert!(!message.contains(launch.endpoint()));

        let address = reply_once(vec![b'a'; MAX_RESPONSE_BYTES + 1], false);
        let launch = forwarded_launch(address, &token);
        let started = Instant::now();
        assert!(launch
            .forward_worker_request(
                "run-a",
                "task-a",
                &json!({"operation": "worker_request_status", "request_id": "request"}),
                &not_cancelled,
            )
            .is_err());
        assert!(started.elapsed() < CONNECTION_BUDGET + Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn forward_worker_request_observes_cancel_while_waiting_for_reply() -> Result<()> {
        let listener = TcpListener::bind(LOOPBACK_BIND)?;
        let address = listener.local_addr()?.to_string();
        let launch = forwarded_launch(address, &"c".repeat(MIN_BEARER_BYTES));
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_later = Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            cancel_later.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let error = launch
            .forward_worker_request(
                "run-a",
                "task-a",
                &json!({"operation": "worker_request_status", "request_id": "request"}),
                &|| cancel.load(Ordering::Acquire),
            )
            .expect_err("cancel must fail the forward");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancel was observed only after {:?}",
            started.elapsed()
        );
        assert!(error.to_string().contains("cancelled"));
        drop(listener);
        Ok(())
    }

    fn forwarded_launch(endpoint: String, token: &str) -> AssignmentMessagingLaunch {
        AssignmentMessagingLaunch::new(
            endpoint,
            token.to_string(),
            "run-a".to_string(),
            "task-a".to_string(),
        )
    }

    fn reply_once(payload: Vec<u8>, hold_after_write: bool) -> String {
        let listener = TcpListener::bind(LOOPBACK_BIND).expect("bind reply server");
        let address = listener
            .local_addr()
            .expect("reply server address")
            .to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(&payload);
                if hold_after_write {
                    thread::sleep(CONNECTION_BUDGET + Duration::from_secs(2));
                }
            }
        });
        address
    }

    fn launch_environment(
        launch: &AssignmentMessagingLaunch,
        run_id: &str,
        task_id: &str,
    ) -> Result<(String, String)> {
        let mut endpoint = None;
        let mut bearer = None;
        for (key, value) in launch.environment_for(run_id, task_id)? {
            if key == ENV_MESSAGE_ENDPOINT {
                endpoint = Some(value);
            } else if key == ENV_MESSAGE_TOKEN {
                bearer = Some(value);
            }
        }
        Ok((
            endpoint.context("missing MACO_MESSAGE_ENDPOINT")?,
            bearer.context("missing MACO_MESSAGE_TOKEN")?,
        ))
    }
}
