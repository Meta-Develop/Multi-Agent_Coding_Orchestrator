//! Unix listener for the headless account-authority protocol.
//!
//! Bind/listen lives here. Path ancestry checks stay in [`super::socket_path`].
//! Windows has no TCP fallback: listen reports [`SocketPathError::UnsupportedPlatform`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use crate::account_authority::protocol::{
    decode_request, dispatch, AuthorityResponse, ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use crate::account_authority::protocol::{AuthorityContext, LoginPort};
use crate::account_authority::{SafeSocketPath, SocketPathError};
use crate::error::Error;
use crate::login::LoginService;
use crate::providers::claude_code::ClaudeCodeAdapter;
use crate::providers::codex_cli::CodexCliAdapter;
use crate::providers::gemini_cli::GeminiCliAdapter;

/// Operator configuration for one authority listener.
pub struct AuthorityServerConfig {
    pub context: AuthorityContext,
    pub peer_policy: PeerPolicy,
}

/// How accepted connections are authorized before any bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Require `uid == euid` via `SO_PEERCRED` / `getpeereid`.
    EffectiveUid,
    /// Treat every peer as unauthorized; for tests only.
    DenyAll,
}

impl AuthorityServerConfig {
    pub fn new(context: AuthorityContext) -> Result<Self, ListenError> {
        context
            .bounds
            .validate()
            .map_err(|_| ListenError::BoundExceedsCeiling)?;
        Ok(Self {
            context,
            peer_policy: PeerPolicy::EffectiveUid,
        })
    }

    pub fn with_gemini_login(mut self, service: LoginService, adapter: GeminiCliAdapter) -> Self {
        self.context = self.context.with_login(Arc::new(GeminiLoginPort::new(
            service,
            adapter,
            ClaudeCodeAdapter::default(),
        )));
        self
    }

    pub fn with_login_port(mut self, login: Arc<dyn LoginPort>) -> Self {
        self.context = self.context.with_login(login);
        self
    }

    pub fn with_peer_policy(mut self, peer_policy: PeerPolicy) -> Self {
        self.peer_policy = peer_policy;
        self
    }

    pub fn tighten_max_request_bytes(
        mut self,
        max_request_bytes: usize,
    ) -> Result<Self, ListenError> {
        self.context.bounds.max_request_bytes = max_request_bytes;
        self.context
            .bounds
            .validate()
            .map_err(|_| ListenError::BoundExceedsCeiling)?;
        Ok(self)
    }

    pub fn tighten_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, ListenError> {
        self.context.bounds.max_response_bytes = max_response_bytes;
        self.context
            .bounds
            .validate()
            .map_err(|_| ListenError::BoundExceedsCeiling)?;
        Ok(self)
    }

    pub fn tighten_request_io_deadline(
        mut self,
        request_io_deadline: Duration,
    ) -> Result<Self, ListenError> {
        self.context.bounds.request_io_deadline = request_io_deadline;
        self.context
            .bounds
            .validate()
            .map_err(|_| ListenError::BoundExceedsCeiling)?;
        Ok(self)
    }
}

/// Production login port that forwards to [`LoginService`].
pub struct GeminiLoginPort {
    service: LoginService,
    adapter: GeminiCliAdapter,
    claude: ClaudeCodeAdapter,
}

impl GeminiLoginPort {
    /// Construct the production port with explicit Gemini and Claude adapters.
    pub fn new(
        service: LoginService,
        adapter: GeminiCliAdapter,
        claude: ClaudeCodeAdapter,
    ) -> Self {
        Self {
            service,
            adapter,
            claude,
        }
    }
}

impl LoginPort for GeminiLoginPort {
    fn start(
        &self,
        request: crate::login::LoginStartRequest,
    ) -> crate::error::Result<crate::login::LoginStatus> {
        match request.provider_id.as_str() {
            "gemini-cli" => self.service.start(request, &self.adapter),
            "codex-cli" => self
                .service
                .start_pending_oauth(request, &CodexCliAdapter::default()),
            "claude-code" => self.service.start_pending_oauth(request, &self.claude),
            // cursor is allow-listed; PendingOAuthLogin is not implemented.
            _ => Err(Error::NotImplemented("login.start")),
        }
    }

    fn status(
        &self,
        handle: &crate::login::LoginHandle,
        binding: &crate::login::LoginAccountBinding,
    ) -> crate::error::Result<crate::login::LoginStatus> {
        self.service.status(handle, binding)
    }

    fn cancel(
        &self,
        handle: &crate::login::LoginHandle,
        binding: &crate::login::LoginAccountBinding,
    ) -> crate::error::Result<crate::login::LoginStatus> {
        self.service.cancel(handle, binding)
    }
}

/// Failure to bind the authority socket.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error(transparent)]
    SocketPath(#[from] SocketPathError),
    #[error("socket path leaf exists and is not a unix socket")]
    NotASocket,
    #[error("operator transport bound exceeds the compiled protocol ceiling")]
    BoundExceedsCeiling,
    #[error("failed to listen on the account authority socket")]
    Io(#[from] io::Error),
}

/// Bound Unix listener serving one request per connection.
pub struct AuthorityListener {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(unix)]
    config: Arc<AuthorityServerConfig>,
    #[cfg(not(unix))]
    #[allow(dead_code)]
    _private: (),
}

/// Listen on an already-checked [`SafeSocketPath`].
///
/// Non-Unix platforms return [`SocketPathError::UnsupportedPlatform`] and do
/// not open a TCP socket.
pub fn listen(
    path: SafeSocketPath,
    config: AuthorityServerConfig,
) -> Result<AuthorityListener, ListenError> {
    config
        .context
        .bounds
        .validate()
        .map_err(|_| ListenError::BoundExceedsCeiling)?;
    listen_inner(path, config)
}

#[cfg(not(unix))]
fn listen_inner(
    _path: SafeSocketPath,
    _config: AuthorityServerConfig,
) -> Result<AuthorityListener, ListenError> {
    Err(ListenError::SocketPath(
        SocketPathError::UnsupportedPlatform,
    ))
}

#[cfg(unix)]
fn listen_inner(
    path: SafeSocketPath,
    config: AuthorityServerConfig,
) -> Result<AuthorityListener, ListenError> {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    let socket_path = path.as_path().to_path_buf();
    match fs::symlink_metadata(&socket_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ListenError::Io(error)),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(ListenError::NotASocket);
            }
            fs::remove_file(&socket_path)?;
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let after = fs::symlink_metadata(&socket_path)?;
    if after.file_type().is_symlink() || !after.file_type().is_socket() {
        let _ = fs::remove_file(&socket_path);
        return Err(ListenError::NotASocket);
    }

    Ok(AuthorityListener {
        listener,
        path: socket_path,
        config: Arc::new(config),
    })
}

impl AuthorityListener {
    /// Absolute path of the bound socket.
    #[cfg(unix)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Accept and serve one connection. Unauthorized peers receive no bytes.
    #[cfg(unix)]
    pub fn accept_once(&self) -> io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        self.serve_connection(stream);
        Ok(())
    }

    #[cfg(unix)]
    fn serve_connection(&self, mut stream: std::os::unix::net::UnixStream) {
        use std::os::unix::io::AsRawFd;

        let authorized = match self.config.peer_policy {
            PeerPolicy::DenyAll => false,
            PeerPolicy::EffectiveUid => match super::peer::peer_credentials(stream.as_raw_fd()) {
                Ok(peer) => super::peer::authorize_peer(peer, super::peer::effective_uid()),
                Err(_) => false,
            },
        };
        if !authorized {
            return;
        }

        let deadline = std::time::Instant::now() + self.config.context.bounds.request_io_deadline;
        let request = match read_request(
            &mut stream,
            self.config.context.bounds.max_request_bytes,
            deadline,
        ) {
            Ok(bytes) => bytes,
            Err(ReadOutcome::IdleOrIo) => return,
            Err(ReadOutcome::Refused(response)) => {
                let _ = write_response(
                    &mut stream,
                    &response,
                    self.config.context.bounds.max_response_bytes,
                    deadline,
                );
                return;
            }
        };

        let response = match decode_request(&request) {
            Ok(decoded) => dispatch(&self.config.context, &decoded),
            Err(failure) => AuthorityResponse::from_failure(failure),
        };
        let _ = write_response(
            &mut stream,
            &response,
            self.config.context.bounds.max_response_bytes,
            deadline,
        );
    }
}

#[cfg(unix)]
impl Drop for AuthorityListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
enum ReadOutcome {
    IdleOrIo,
    Refused(AuthorityResponse),
}

#[cfg(unix)]
fn read_request(
    stream: &mut std::os::unix::net::UnixStream,
    max_request_bytes: usize,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, ReadOutcome> {
    let mut length_bytes = [0u8; 4];
    read_exact_deadline(stream, &mut length_bytes, deadline).map_err(|_| ReadOutcome::IdleOrIo)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max_request_bytes || length > MAX_REQUEST_BYTES {
        return Err(ReadOutcome::Refused(AuthorityResponse::error(
            "",
            ErrorCode::InvalidRequest,
            "request exceeds maxRequestBytes",
        )));
    }
    let mut body = vec![0u8; length];
    read_exact_deadline(stream, &mut body, deadline).map_err(|_| ReadOutcome::IdleOrIo)?;
    Ok(body)
}

#[cfg(unix)]
fn write_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &AuthorityResponse,
    max_response_bytes: usize,
    deadline: std::time::Instant,
) -> io::Result<()> {
    let encoded = match encode_response_bytes(response, max_response_bytes) {
        Ok(bytes) => bytes,
        Err(fallback) => encode_response_bytes(&fallback, max_response_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "response exceeds maxResponseBytes",
            )
        })?,
    };
    write_all_deadline(stream, &encoded, deadline)
}

#[cfg(unix)]
fn encode_response_bytes(
    response: &AuthorityResponse,
    max_response_bytes: usize,
) -> Result<Vec<u8>, AuthorityResponse> {
    let json = serde_json::to_vec(response).map_err(|error| {
        AuthorityResponse::error(
            response.request_id.clone(),
            ErrorCode::Unavailable,
            format!("response could not be encoded: {error}"),
        )
    })?;
    if json.len() > max_response_bytes || json.len() > MAX_RESPONSE_BYTES {
        return Err(AuthorityResponse::error(
            response.request_id.clone(),
            ErrorCode::Unavailable,
            "response exceeds maxResponseBytes",
        ));
    }
    let mut framed = Vec::with_capacity(4 + json.len());
    framed.extend_from_slice(&(json.len() as u32).to_be_bytes());
    framed.extend_from_slice(&json);
    Ok(framed)
}

#[cfg(unix)]
fn read_exact_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    buf: &mut [u8],
    deadline: std::time::Instant,
) -> io::Result<()> {
    use std::io::Read;
    apply_timeouts(stream, deadline)?;
    stream.read_exact(buf)
}

#[cfg(unix)]
fn write_all_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    buf: &[u8],
    deadline: std::time::Instant,
) -> io::Result<()> {
    use std::io::Write;
    apply_timeouts(stream, deadline)?;
    stream.write_all(buf)
}

#[cfg(unix)]
fn apply_timeouts(
    stream: &std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request I/O deadline elapsed",
        ));
    }
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    Ok(())
}
