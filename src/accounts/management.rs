//! Loopback-only, session-authorized account management, separate from Scope.

pub use super::state::ManualSelection;
use super::{protocol::MAX_FRAME_BYTES, state::SelectionStore, AccountClient, AccountError};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

// These HTTP admission bounds match the existing Scope server. Backend framing
// and the complete body deadline use the account capability service contract.
const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const OVER_CAPACITY_TIMEOUT: Duration = Duration::from_millis(100);
const ACCEPT_POLL: Duration = Duration::from_millis(25);
const MAX_CONNECTIONS: usize = 64;

struct Context {
    client: AccountClient,
    store: SelectionStore,
    authority: String,
    origin: String,
    secret: String,
}

/// A local server with no authority to execute models or change a running task.
pub struct ManagementServer {
    listener: TcpListener,
    context: Arc<Context>,
}

impl ManagementServer {
    pub fn bind(
        client: AccountClient,
        state_dir: &Path,
        address: SocketAddr,
    ) -> Result<Self, AccountError> {
        if !cfg!(target_os = "linux") {
            return Err(AccountError::UnsupportedPlatform);
        }
        if !address.ip().is_loopback() {
            return Err(AccountError::InvalidInput);
        }
        let store = SelectionStore::open(state_dir, client.endpoint_binding()?)?;
        let listener = TcpListener::bind(address).map_err(|_| AccountError::Unavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AccountError::Unavailable)?;
        let authority = listener
            .local_addr()
            .map_err(|_| AccountError::Unavailable)?
            .to_string();
        let secret = crate::artifacts::state_auth::random_identifier()
            .map_err(|_| AccountError::Unavailable)?;
        let context = Arc::new(Context {
            client,
            store,
            origin: format!("http://{authority}"),
            authority,
            secret,
        });
        Ok(Self { listener, context })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, AccountError> {
        self.listener
            .local_addr()
            .map_err(|_| AccountError::Unavailable)
    }

    /// Only the launching terminal receives this URL. The secret is never sent
    /// as an HTTP target, query parameter, cookie, or server-side log field.
    pub fn launch_url(&self) -> String {
        format!("{}/#{}", self.context.origin, self.context.secret)
    }

    pub fn serve(self, shutdown: Arc<AtomicBool>) -> Result<(), AccountError> {
        let active = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    if active
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < MAX_CONNECTIONS).then_some(count + 1)
                        })
                        .is_err()
                    {
                        let _ = stream.set_write_timeout(Some(OVER_CAPACITY_TIMEOUT));
                        let _ = respond(
                            &mut stream,
                            503,
                            "application/json",
                            br#"{"error":"unavailable"}"#,
                        );
                        continue;
                    }
                    let permit = ConnectionPermit(Arc::clone(&active));
                    let context = Arc::clone(&self.context);
                    // Dropping a failed spawn closure also releases its permit.
                    let _ = thread::Builder::new()
                        .name("account-management".into())
                        .spawn(move || {
                            let _permit = permit;
                            handle_connection(&mut stream, &context);
                        });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL)
                }
                Err(_) => return Err(AccountError::Unavailable),
            }
        }
        // In-flight explicit actions finish within the existing request bounds.
        while active.load(Ordering::Acquire) != 0 {
            thread::sleep(ACCEPT_POLL);
        }
        Ok(())
    }
}

struct ConnectionPermit(Arc<AtomicUsize>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
}

fn read_headers(stream: &mut TcpStream) -> Result<Request, ()> {
    let deadline = Instant::now() + HEADER_TIMEOUT;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(());
        }
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
        stream.set_read_timeout(Some(remaining)).map_err(|_| ())?;
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(|_| ())?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    if !text.is_ascii() {
        return Err(());
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut first = lines.next().ok_or(())?.split(' ');
    let method = first.next().ok_or(())?.to_owned();
    let target = first.next().ok_or(())?.to_owned();
    if first.next() != Some("HTTP/1.1") || first.next().is_some() {
        return Err(());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.bytes().any(|c| c.is_ascii_control())
        {
            return Err(());
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(());
        }
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return Err(());
    }
    Ok(Request {
        method,
        target,
        headers,
    })
}

fn handle_connection(stream: &mut TcpStream, context: &Context) {
    let _ = stream.set_write_timeout(Some(HEADER_TIMEOUT));
    let result = handle_request(stream, context);
    if let Err((status, error)) = result {
        let body =
            serde_json::to_vec(&json!({"schema_version":1,"error":error})).unwrap_or_default();
        let _ = respond(stream, status, "application/json", &body);
    }
    // A refusal can leave an already-sent body unread. Publish the response FIN
    // and discard only immediately available bytes within the request bound;
    // otherwise closing that socket can reset the complete refusal response.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if stream.set_nonblocking(true).is_ok() {
        let mut remaining = MAX_FRAME_BYTES;
        let mut discard = [0_u8; MAX_HEADER_BYTES];
        while remaining > 0 {
            let length = remaining.min(discard.len());
            match stream.read(&mut discard[..length]) {
                Ok(0) | Err(_) => break,
                Ok(read) => remaining -= read,
            }
        }
    }
}

fn handle_request(stream: &mut TcpStream, context: &Context) -> Result<(), (u16, AccountError)> {
    let request = read_headers(stream).map_err(|_| (400, AccountError::InvalidInput))?;
    // Authority and CSRF checks happen before body parsing or any Broker access.
    if request.headers.get("host") != Some(&context.authority)
        || request
            .headers
            .get("origin")
            .is_some_and(|origin| origin != &context.origin)
        || request
            .headers
            .get("sec-fetch-site")
            .is_some_and(|site| !matches!(site.as_str(), "same-origin" | "none"))
    {
        return Err((403, AccountError::Refused));
    }
    if request.method == "GET" {
        if request
            .headers
            .get("content-length")
            .is_some_and(|value| value != "0")
        {
            return Err((400, AccountError::InvalidInput));
        }
        let (mime, bytes): (&str, &[u8]) = match request.target.as_str() {
            "/" => (
                "text/html; charset=utf-8",
                include_bytes!("assets/index.html"),
            ),
            "/app.js" => (
                "text/javascript; charset=utf-8",
                include_bytes!("assets/app.js"),
            ),
            "/style.css" => (
                "text/css; charset=utf-8",
                include_bytes!("assets/style.css"),
            ),
            _ => return Err((404, AccountError::InvalidInput)),
        };
        return respond(stream, 200, mime, bytes).map_err(|_| (503, AccountError::Unavailable));
    }
    if request.method != "POST" || !request.target.starts_with("/api/") {
        return Err((405, AccountError::Refused));
    }
    let provided = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "));
    if request.headers.get("origin") != Some(&context.origin)
        || !provided.is_some_and(|secret| same_secret(secret, &context.secret))
    {
        return Err((403, AccountError::Refused));
    }
    if request.headers.get("content-type").map(String::as_str) != Some("application/json") {
        return Err((415, AccountError::InvalidInput));
    }
    let length = request
        .headers
        .get("content-length")
        .filter(|value| !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= MAX_FRAME_BYTES)
        .ok_or((400, AccountError::InvalidInput))?;
    let mut body = vec![0; length];
    let deadline = Instant::now() + Duration::from_secs(super::protocol::MAX_REQUEST_SECONDS);
    let mut offset = 0;
    while offset < length {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or((408, AccountError::Timeout))?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| (503, AccountError::Unavailable))?;
        let read = stream
            .read(&mut body[offset..])
            .map_err(|_| (408, AccountError::Timeout))?;
        if read == 0 {
            return Err((400, AccountError::InvalidInput));
        }
        offset += read;
    }
    let result = dispatch(context, &request.target, &body).map_err(|error| {
        (
            match error {
                AccountError::SelectionConflict => 409,
                AccountError::InvalidInput => 400,
                AccountError::Refused => 403,
                _ => 503,
            },
            error,
        )
    })?;
    let bytes = serde_json::to_vec(&result).map_err(|_| (503, AccountError::Protocol))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err((503, AccountError::Protocol));
    }
    respond(stream, 200, "application/json", &bytes).map_err(|_| (503, AccountError::Unavailable))
}

fn same_secret(provided: &str, expected: &str) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    provided
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionRequest {
    alias: String,
    expected_revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStartRequest {
    alias: String,
    request_nonce: String,
    replace_handle: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStatusRequest {
    alias: String,
    handle: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginCancelRequest {
    alias: String,
    handle: String,
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AccountError> {
    serde_json::from_slice(bytes).map_err(|_| AccountError::InvalidInput)
}

fn dispatch(context: &Context, route: &str, bytes: &[u8]) -> Result<Value, AccountError> {
    match route {
        "/api/list" => {
            let _: Empty = parse(bytes)?;
            Ok(
                json!({"schema_version":1,"inventory":context.client.list()?,"selection":context.store.read()?}),
            )
        }
        "/api/select" => {
            let input: SelectionRequest = parse(bytes)?;
            if !super::protocol::valid_alias(&input.alias) {
                return Err(AccountError::InvalidInput);
            }
            if !context
                .client
                .list()?
                .accounts
                .iter()
                .any(|account| account.alias == input.alias && account.enabled)
            {
                return Err(AccountError::Refused);
            }
            Ok(
                json!({"schema_version":1,"selection":context.store.select(&input.alias, input.expected_revision)?}),
            )
        }
        "/api/discover" => {
            let input: SelectionRequest = parse(bytes)?;
            let selected = context.store.read()?;
            if selected.revision != input.expected_revision
                || selected.selected_alias.as_deref() != Some(&input.alias)
            {
                return Err(AccountError::SelectionConflict);
            }
            let observation = context.client.discover(&input.alias)?;
            if context.store.read()? != selected {
                return Err(AccountError::SelectionConflict);
            }
            Ok(json!({"schema_version":1,"selection":selected,"observation":observation}))
        }
        "/api/login/start" => {
            let input: LoginStartRequest = parse(bytes)?;
            serde_json::to_value(context.client.login_start(
                &input.alias,
                &input.request_nonce,
                input.replace_handle.as_deref(),
            )?)
            .map_err(|_| AccountError::Protocol)
        }
        "/api/login/status" => {
            let input: LoginStatusRequest = parse(bytes)?;
            serde_json::to_value(
                context
                    .client
                    .login_status(&input.alias, input.handle.as_deref())?,
            )
            .map_err(|_| AccountError::Protocol)
        }
        "/api/login/cancel" => {
            let input: LoginCancelRequest = parse(bytes)?;
            serde_json::to_value(context.client.login_cancel(&input.alias, &input.handle)?)
                .map_err(|_| AccountError::Protocol)
        }
        _ => Err(AccountError::InvalidInput),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        _ => "Service Unavailable",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n", body.len())?;
    stream.write_all(body)
}
