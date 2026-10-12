//! Invocation-bound Claude Code managed-worker launch and raw stream custody.
//!
//! The static Claude capability row remains fail-closed.  This module proves
//! only one concrete, fresh launch and retains raw native message evidence for
//! the parent that actually held stdout. Bare API-key and managed OAuth
//! authorities remain distinct.

use super::{
    AdapterId, BlockingPreActionCallback, LaunchContext, ModelCatalogSource, OutputCaptureMode,
    RuntimeAdapterConfig, RuntimeCapabilities, SessionResume, SideEffectConfinement,
    UsageReporting, WorkspaceWritability,
};
use crate::llm::provider::Usage;
#[cfg(target_os = "linux")]
use coding_agent_manager_lib::relay::{
    CoreTranslator, RelayConfig, RelayServer, RelayTarget, RelayUpstreamAuth, WireFormat,
};
#[cfg(target_os = "linux")]
use coding_agent_manager_lib::storage::Secret;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::{
    ffi::OsStrExt,
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const CLAUDE_NATIVE_TOOLS: [&str; 5] = ["Read", "Glob", "Grep", "Edit", "Write"];
pub(crate) const CLAUDE_NATIVE_VERSION: &str = "2.1.137";
pub(crate) const CLAUDE_NATIVE_EXECUTABLE: &str =
    "/nix/store/325qy6bkl1lrwrhz6s1mzzqpdswzvz7g-claude-code-2.1.137/bin/.claude-wrapped";
pub(crate) const CLAUDE_NATIVE_SHA256: &str =
    "404ef447ddea09867ba29f6c5aecccafd3951b6fd6021f118a49295bbae90238";
const MAX_NATIVE_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_NATIVE_STREAM_LINES: usize = 100_000;
const MAX_NATIVE_MESSAGES: usize = 4_096;
const DUPLICATE_WIRE_KEY_ERROR: &str = "duplicate Claude native wire JSON object key";
const MAX_BROKER_HTTP_BYTES: usize = 8 * 1024 * 1024;
const MAX_BROKER_EXCHANGES: usize = 4_096;
const MAX_BROKER_SSE_EVENTS: usize = 100_000;
pub(crate) const CLAUDE_MANAGED_PRIMARY_MODEL: &str = "claude-sonnet-4-6";
pub(crate) const CLAUDE_MANAGED_AUXILIARY_MODEL: &str = "claude-haiku-4-5-20251001";
const LOCAL_HEAD_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
#[cfg(target_os = "linux")]
const HELPER_REGISTRATION_PREFIX: &str = "MACO-CLAUDE-HELPER-V1";

pub(crate) fn admitted_native_executable(path: &Path, sha256: &str) -> bool {
    path == Path::new(CLAUDE_NATIVE_EXECUTABLE) && sha256 == CLAUDE_NATIVE_SHA256
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeAuthMode {
    BareApiKey,
    ManagedOAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeManagedLaunchContract {
    auth_mode: ClaudeAuthMode,
}

impl ClaudeManagedLaunchContract {
    pub(crate) const fn auth_mode(self) -> ClaudeAuthMode {
        self.auth_mode
    }

    pub(crate) const fn capabilities(self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            blocking_pre_action_callback: BlockingPreActionCallback::None,
            writable_workspace: WorkspaceWritability::Partial,
            side_effect_confinement: SideEffectConfinement::Verified,
            model_catalog: ModelCatalogSource::OperatorDeclared,
            usage_reporting: UsageReporting::PerTurn,
            session_resume: SessionResume::Unsupported,
        }
    }
}

pub(crate) fn immutable_argument_template() -> Vec<String> {
    vec![
        "-p".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--include-partial-messages".into(),
        "--bare".into(),
        "--setting-sources".into(),
        String::new(),
        "--strict-mcp-config".into(),
        "--disable-slash-commands".into(),
        "--tools".into(),
        CLAUDE_NATIVE_TOOLS.join(","),
        "--allowedTools".into(),
        CLAUDE_NATIVE_TOOLS.join(","),
        "--model".into(),
        "{model}".into(),
        "--effort".into(),
        "{effort}".into(),
    ]
}

pub(crate) fn prove_managed_launch(
    config: &RuntimeAdapterConfig,
    context: &LaunchContext<'_>,
) -> Option<ClaudeManagedLaunchContract> {
    if !context.cwd.is_absolute()
        || context.model != Some(CLAUDE_MANAGED_PRIMARY_MODEL)
        || !matches!(
            context.effort,
            Some("low" | "medium" | "high" | "xhigh" | "max")
        )
        || !config.env_passthrough.is_empty()
        || config.working_dir_flag.is_some()
        || config.output_capture != OutputCaptureMode::Stdout
        || !config.feed_prompt_on_stdin
        || config.argument_template != immutable_argument_template()
        || config.binary.as_deref() != Some(Path::new(CLAUDE_NATIVE_EXECUTABLE))
    {
        return None;
    }
    let expected = RuntimeAdapterConfig::defaults_for(AdapterId::ClaudeCode);
    (config.render(context).ok()? == expected.render(context).ok()?).then_some(
        ClaudeManagedLaunchContract {
            auth_mode: ClaudeAuthMode::BareApiKey,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ClaudeCoverageFailure {
    CaptureTruncated,
    StreamTooLarge,
    TooManyLines,
    TooManyMessages,
    EmptyLine,
    MalformedJson,
    MissingSessionId,
    ConflictingSessionId,
    MissingMessageId,
    DuplicateMessage,
    MissingObservedModel,
    ConflictingObservedModel,
    MissingUsage,
    MissingCounter,
    InvalidCounter,
    DuplicateCounter,
    DuplicateWireKey,
    ConflictingCacheBuckets,
    AggregateCounterConflict,
    CounterOverflow,
    MessageDeltaWithoutStart,
    MessageStopWithoutStart,
    MessageNotStopped,
    AssistantWithoutRawMessage,
    AssistantModelConflict,
    MissingInit,
    DuplicateInit,
    EffectiveToolsConflict,
    EffectiveMcpConfiguration,
    MissingResult,
    MissingResultText,
    DuplicateResult,
    UnsuccessfulResult,
    ResultSessionConflict,
    TurnCountMissing,
    TurnCountConflict,
    ModelCoverageMissing,
    FallbackOrAuxiliaryModel,
    CompactionObserved,
    UnknownStreamEvent,
    NativeCoverageWitnessMissing,
    BrokerBindingMismatch,
    BrokerRequestCoverage,
    BrokerResponseCoverage,
    BrokerUnknownTraffic,
    Interrupted,
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJson(value)) = sequence.next_element::<UniqueJson>()? {
            values.push(value);
        }
        Ok(UniqueJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(<A::Error as de::Error>::custom(DUPLICATE_WIRE_KEY_ERROR));
            }
            let UniqueJson(value) = object.next_value::<UniqueJson>()?;
            values.insert(key, value);
        }
        Ok(UniqueJson(Value::Object(values)))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeCounterPresence {
    pub(crate) input_tokens: bool,
    pub(crate) cache_creation_input_tokens: bool,
    pub(crate) cache_read_input_tokens: bool,
    pub(crate) output_tokens: bool,
    pub(crate) cache_creation_5m_input_tokens: bool,
    pub(crate) cache_creation_1h_input_tokens: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeUsageCounters {
    pub(crate) input_tokens: u64,
    pub(crate) cache_creation_input_tokens: u64,
    pub(crate) cache_read_input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_creation_5m_input_tokens: u64,
    pub(crate) cache_creation_1h_input_tokens: u64,
    pub(crate) presence: ClaudeCounterPresence,
}

impl ClaudeUsageCounters {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            input_tokens: self.input_tokens.checked_add(other.input_tokens)?,
            cache_creation_input_tokens: self
                .cache_creation_input_tokens
                .checked_add(other.cache_creation_input_tokens)?,
            cache_read_input_tokens: self
                .cache_read_input_tokens
                .checked_add(other.cache_read_input_tokens)?,
            output_tokens: self.output_tokens.checked_add(other.output_tokens)?,
            cache_creation_5m_input_tokens: self
                .cache_creation_5m_input_tokens
                .checked_add(other.cache_creation_5m_input_tokens)?,
            cache_creation_1h_input_tokens: self
                .cache_creation_1h_input_tokens
                .checked_add(other.cache_creation_1h_input_tokens)?,
            presence: ClaudeCounterPresence {
                input_tokens: self.presence.input_tokens || other.presence.input_tokens,
                cache_creation_input_tokens: self.presence.cache_creation_input_tokens
                    || other.presence.cache_creation_input_tokens,
                cache_read_input_tokens: self.presence.cache_read_input_tokens
                    || other.presence.cache_read_input_tokens,
                output_tokens: self.presence.output_tokens || other.presence.output_tokens,
                cache_creation_5m_input_tokens: self.presence.cache_creation_5m_input_tokens
                    || other.presence.cache_creation_5m_input_tokens,
                cache_creation_1h_input_tokens: self.presence.cache_creation_1h_input_tokens
                    || other.presence.cache_creation_1h_input_tokens,
            },
        })
    }

    fn as_usage(self) -> Option<Usage> {
        let input_tokens = self
            .input_tokens
            .checked_add(self.cache_creation_input_tokens)?
            .checked_add(self.cache_read_input_tokens)?;
        let total_tokens = input_tokens.checked_add(self.output_tokens)?;
        Some(Usage {
            input_tokens: usize::try_from(input_tokens).ok()?,
            output_tokens: usize::try_from(self.output_tokens).ok()?,
            total_tokens: usize::try_from(total_tokens).ok()?,
        })
    }

    fn checked_componentwise_max(self, other: Self) -> (Self, bool) {
        let cache_creation_5m_input_tokens = self
            .cache_creation_5m_input_tokens
            .max(other.cache_creation_5m_input_tokens);
        let cache_creation_1h_input_tokens = self
            .cache_creation_1h_input_tokens
            .max(other.cache_creation_1h_input_tokens);
        let (cache_bucket_floor, overflowed) = cache_creation_5m_input_tokens
            .checked_add(cache_creation_1h_input_tokens)
            .map_or((u64::MAX, true), |floor| (floor, false));
        (
            Self {
                input_tokens: self.input_tokens.max(other.input_tokens),
                cache_creation_input_tokens: self
                    .cache_creation_input_tokens
                    .max(other.cache_creation_input_tokens)
                    .max(cache_bucket_floor),
                cache_read_input_tokens: self
                    .cache_read_input_tokens
                    .max(other.cache_read_input_tokens),
                output_tokens: self.output_tokens.max(other.output_tokens),
                cache_creation_5m_input_tokens,
                cache_creation_1h_input_tokens,
                presence: ClaudeCounterPresence {
                    input_tokens: self.presence.input_tokens || other.presence.input_tokens,
                    cache_creation_input_tokens: self.presence.cache_creation_input_tokens
                        || other.presence.cache_creation_input_tokens,
                    cache_read_input_tokens: self.presence.cache_read_input_tokens
                        || other.presence.cache_read_input_tokens,
                    output_tokens: self.presence.output_tokens || other.presence.output_tokens,
                    cache_creation_5m_input_tokens: self.presence.cache_creation_5m_input_tokens
                        || other.presence.cache_creation_5m_input_tokens,
                    cache_creation_1h_input_tokens: self.presence.cache_creation_1h_input_tokens
                        || other.presence.cache_creation_1h_input_tokens,
                },
            },
            overflowed,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeTransportAuthMode {
    #[cfg(test)]
    BareApiKey,
    OAuthBearer,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClaudeBrokerBinding {
    parent_nonce: String,
    launch_digest: String,
    account_binding: String,
    reservation_id: u64,
    deadline_unix_millis: u64,
    auth_mode: ClaudeTransportAuthMode,
}

impl fmt::Debug for ClaudeBrokerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeBrokerBinding")
            .field("parent_nonce", &"<redacted>")
            .field("launch_digest", &self.launch_digest)
            .field("account_binding", &"<redacted>")
            .field("reservation_id", &self.reservation_id)
            .field("deadline_unix_millis", &self.deadline_unix_millis)
            .field("auth_mode", &self.auth_mode)
            .finish()
    }
}

impl ClaudeBrokerBinding {
    pub(crate) fn new(
        parent_nonce: String,
        launch_digest: String,
        account_binding: String,
        reservation_id: u64,
        deadline_unix_millis: u64,
        auth_mode: ClaudeTransportAuthMode,
    ) -> Result<Self, String> {
        if parent_nonce.is_empty()
            || launch_digest.is_empty()
            || account_binding.is_empty()
            || reservation_id == 0
            || deadline_unix_millis == 0
        {
            return Err("Claude broker binding is incomplete".to_string());
        }
        Ok(Self {
            parent_nonce,
            launch_digest,
            account_binding,
            reservation_id,
            deadline_unix_millis,
            auth_mode,
        })
    }
}

pub(crate) struct ClaudeTransportCredentialGrant {
    binding: ClaudeBrokerBinding,
    secret: Vec<u8>,
}

impl fmt::Debug for ClaudeTransportCredentialGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeTransportCredentialGrant")
            .field("binding", &self.binding)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ClaudeTransportCredentialGrant {
    pub(crate) fn new(binding: ClaudeBrokerBinding, mut secret: Vec<u8>) -> Result<Self, String> {
        if secret.is_empty()
            || secret.contains(&0)
            || secret.contains(&b'\n')
            || secret.contains(&b'\r')
        {
            secret.fill(0);
            return Err("Claude transport credential grant is invalid".to_string());
        }
        let secret = match binding.auth_mode {
            #[cfg(test)]
            ClaudeTransportAuthMode::BareApiKey => secret,
            ClaudeTransportAuthMode::OAuthBearer => {
                let mut bearer = b"Bearer ".to_vec();
                bearer.extend_from_slice(&secret);
                secret.fill(0);
                bearer
            }
        };
        Ok(Self { binding, secret })
    }

    pub(crate) fn binding(&self) -> &ClaudeBrokerBinding {
        &self.binding
    }

    pub(crate) fn authorization_value(&self) -> &[u8] {
        &self.secret
    }
}

impl Drop for ClaudeTransportCredentialGrant {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeBrokerUpstreamResponse {
    pub(crate) status: u16,
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeBrokerRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    model: Option<String>,
    declared_tools: BTreeSet<String>,
}

struct ClaudeRequestAuthorization(Vec<u8>);

impl ClaudeRequestAuthorization {
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ClaudeRequestAuthorization {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct ParsedClaudeBrokerRequest {
    request: ClaudeBrokerRequest,
    authorization: Option<ClaudeRequestAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeBrokerCapture {
    request: ClaudeBrokerRequest,
    forwarded: bool,
    response: Option<ClaudeBrokerUpstreamResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeBrokerTerminalSeal {
    pub(crate) child_exit_observed: bool,
    pub(crate) listener_closed: bool,
    pub(crate) upstream_quiescent: bool,
    pub(crate) interrupted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeWholeCallWitness {
    binding: ClaudeBrokerBinding,
    captures: Vec<ClaudeBrokerCapture>,
    unclassified_requests: usize,
    seal: ClaudeBrokerTerminalSeal,
}

impl ClaudeWholeCallWitness {
    pub(crate) fn mark_interrupted(&mut self) {
        self.seal.interrupted = true;
    }
}

pub(crate) struct ClaudeParentBroker {
    grant: ClaudeTransportCredentialGrant,
    captures: Vec<ClaudeBrokerCapture>,
    unclassified_requests: usize,
}

impl fmt::Debug for ClaudeParentBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeParentBroker")
            .field("binding", self.grant.binding())
            .field("captures", &self.captures.len())
            .field("unclassified_requests", &self.unclassified_requests)
            .finish()
    }
}

impl ClaudeParentBroker {
    pub(crate) fn new(grant: ClaudeTransportCredentialGrant) -> Self {
        Self {
            grant,
            captures: Vec::new(),
            unclassified_requests: 0,
        }
    }

    pub(crate) fn handle_http<F>(
        &mut self,
        request_bytes: &[u8],
        forward: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce(&ClaudeBrokerUpstreamRequest<'_>) -> Result<ClaudeBrokerUpstreamResponse, String>,
    {
        if self.captures.len() >= MAX_BROKER_EXCHANGES {
            self.unclassified_requests = self.unclassified_requests.saturating_add(1);
            return Err("Claude broker exchange limit exceeded".to_string());
        }
        let parsed = match parse_broker_http_request(request_bytes) {
            Ok(request) => request,
            Err(error) => {
                self.unclassified_requests = self.unclassified_requests.saturating_add(1);
                return Err(error);
            }
        };
        let ParsedClaudeBrokerRequest {
            request,
            authorization,
        } = parsed;
        if request.method == "HEAD" && request.path == "/" && request.body.is_empty() {
            self.captures.push(ClaudeBrokerCapture {
                request,
                forwarded: false,
                response: None,
            });
            return Ok(LOCAL_HEAD_RESPONSE.to_vec());
        }
        if request.method != "POST" || request.path != "/v1/messages" {
            self.captures.push(ClaudeBrokerCapture {
                request,
                forwarded: false,
                response: None,
            });
            return Err("Claude broker refused unknown HTTP traffic".to_string());
        }
        let expected_authorization = self.grant.authorization_value();
        if !authorization
            .as_ref()
            .is_some_and(|actual| constant_time_equal(actual.expose(), expected_authorization))
        {
            self.captures.push(ClaudeBrokerCapture {
                request,
                forwarded: false,
                response: None,
            });
            return Err("Claude broker refused an unauthenticated local request".to_string());
        }
        let known_primary = request.model.as_deref() == Some(CLAUDE_MANAGED_PRIMARY_MODEL)
            && request
                .declared_tools
                .iter()
                .all(|tool| CLAUDE_NATIVE_TOOLS.contains(&tool.as_str()));
        let known_auxiliary = request.model.as_deref() == Some(CLAUDE_MANAGED_AUXILIARY_MODEL)
            && request.declared_tools.is_empty();
        if !known_primary && !known_auxiliary {
            self.captures.push(ClaudeBrokerCapture {
                request,
                forwarded: false,
                response: None,
            });
            return Err("Claude broker refused an unqualified model or tool set".to_string());
        }
        let upstream_request = ClaudeBrokerUpstreamRequest {
            request: &request,
            #[cfg(test)]
            grant: &self.grant,
        };
        let response = forward(&upstream_request);
        match response {
            Ok(response) => {
                let child_response = broker_child_response(&response);
                self.captures.push(ClaudeBrokerCapture {
                    request,
                    forwarded: true,
                    response: Some(response),
                });
                child_response
            }
            Err(error) => {
                self.captures.push(ClaudeBrokerCapture {
                    request,
                    forwarded: true,
                    response: None,
                });
                Err(error)
            }
        }
    }

    fn record_unclassified_request(&mut self) {
        self.unclassified_requests = self.unclassified_requests.saturating_add(1);
    }

    pub(crate) fn seal(self, seal: ClaudeBrokerTerminalSeal) -> ClaudeWholeCallWitness {
        ClaudeWholeCallWitness {
            binding: self.grant.binding.clone(),
            captures: self.captures,
            unclassified_requests: self.unclassified_requests,
            seal,
        }
    }
}

/// Live two-hop relay. The front listener is the only endpoint given to Claude;
/// the CAM relay owns TLS and substitutes the selected OAuth grant upstream.
#[cfg(target_os = "linux")]
pub(crate) struct ClaudeManagedRelay {
    socket_path: PathBuf,
    binding: ClaudeBrokerBinding,
    shutdown: Arc<AtomicBool>,
    front: Option<JoinHandle<(ClaudeParentBroker, Option<String>)>>,
    rear_stop: Option<mpsc::Sender<()>>,
    rear: Option<JoinHandle<Result<(), String>>>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeRelayHelperIdentity {
    pid: u32,
    start_ticks: u64,
    cgroup: String,
    unit: String,
}

#[cfg(target_os = "linux")]
pub(crate) struct ClaudeManagedRelayFinish {
    pub(crate) witness: ClaudeWholeCallWitness,
    pub(crate) error: Option<String>,
}

#[cfg(target_os = "linux")]
struct ClaudeRearStartupGuard {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<Result<(), String>>>,
    join_deadline: Instant,
}

#[cfg(target_os = "linux")]
impl ClaudeRearStartupGuard {
    fn new(
        stop: mpsc::Sender<()>,
        handle: JoinHandle<Result<(), String>>,
        startup_timeout: Duration,
    ) -> Self {
        Self {
            stop: Some(stop),
            handle: Some(handle),
            join_deadline: Instant::now() + startup_timeout,
        }
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        while !handle.is_finished() && Instant::now() < self.join_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !handle.is_finished() {
            eprintln!(
                "fatal: Claude credential relay remained live past its startup cleanup deadline; aborting rather than detaching"
            );
            std::process::abort();
        }
        handle.join().map_err(|_| {
            "Claude upstream relay thread panicked during startup cleanup".to_string()
        })?
    }

    fn fail(mut self, error: String) -> String {
        match self.stop_and_join() {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; {cleanup}"),
        }
    }

    fn release(mut self) -> (mpsc::Sender<()>, JoinHandle<Result<(), String>>) {
        (
            self.stop.take().expect("rear stop owner"),
            self.handle.take().expect("rear thread owner"),
        )
    }
}

#[cfg(target_os = "linux")]
impl Drop for ClaudeRearStartupGuard {
    fn drop(&mut self) {
        if self.handle.is_some() && self.stop_and_join().is_err() {
            eprintln!("fatal: Claude credential relay startup cleanup failed closed");
            std::process::abort();
        }
    }
}

#[cfg(target_os = "linux")]
impl ClaudeManagedRelay {
    pub(crate) fn start(
        binding: ClaudeBrokerBinding,
        child_oauth_secret: Secret,
        upstream_oauth_secret: Secret,
        helper_registration_nonce: String,
        containment_owner: crate::process_runner::ClaudeContainmentOwnerBinding,
        parent_socket: &Path,
    ) -> Result<Self, String> {
        if binding.auth_mode != ClaudeTransportAuthMode::OAuthBearer {
            return Err("Claude managed relay requires an OAuth broker binding".to_string());
        }
        let startup_timeout = binding
            .deadline_unix_millis
            .checked_sub(unix_millis_now()?)
            .filter(|remaining| *remaining != 0)
            .map(|remaining| Duration::from_millis(remaining.min(5_000)))
            .ok_or_else(|| "Claude managed relay deadline expired before startup".to_string())?;
        let broker_grant = ClaudeTransportCredentialGrant::new(
            binding.clone(),
            child_oauth_secret.expose().to_vec(),
        )?;
        let local_relay_token = binding.parent_nonce.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<u16, String>>(1);
        let (rear_stop_tx, rear_stop_rx) = mpsc::channel();
        let rear_token = local_relay_token.clone();
        let rear_deadline = binding.deadline_unix_millis;
        let rear = std::thread::Builder::new()
            .name("maco-claude-upstream-relay".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("Claude relay runtime failed: {error}"))?;
                runtime.block_on(async move {
                    let target = RelayTarget::new(
                        "https://api.anthropic.com/",
                        WireFormat::AnthropicMessages,
                    )
                    .and_then(|target| {
                        target.with_auth(RelayUpstreamAuth::bearer(upstream_oauth_secret))
                    })
                    .map_err(|error| format!("Claude upstream target failed: {error}"))?;
                    let server = RelayServer::start(
                        RelayConfig {
                            bind_address: "127.0.0.1".to_string(),
                            port: 0,
                            auth_token: Some(rear_token),
                        },
                        Some(target),
                        Arc::new(CoreTranslator),
                    )
                    .await
                    .map_err(|error| format!("Claude upstream relay failed to start: {error}"))?;
                    let status = server.status();
                    if ready_tx.send(Ok(status.port)).is_err() {
                        let stop_timeout = rear_deadline
                            .checked_sub(unix_millis_now()?)
                            .filter(|remaining| *remaining != 0)
                            .map(|remaining| Duration::from_millis(remaining.min(500)))
                            .unwrap_or_else(|| Duration::from_millis(1));
                        tokio::time::timeout(stop_timeout, server.stop())
                            .await
                            .map_err(|_| "Claude upstream relay stop timed out".to_string())?
                            .map_err(|error| {
                                format!("Claude upstream relay failed to stop: {error}")
                            })?;
                        return Err("Claude relay owner disappeared during startup".to_string());
                    }
                    loop {
                        match rear_stop_rx.try_recv() {
                            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                            Err(mpsc::TryRecvError::Empty) => {
                                if unix_millis_now()? >= rear_deadline {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            }
                        }
                    }
                    let stop_timeout = rear_deadline
                        .checked_sub(unix_millis_now()?)
                        .filter(|remaining| *remaining != 0)
                        .map(|remaining| Duration::from_millis(remaining.min(500)))
                        .unwrap_or_else(|| Duration::from_millis(1));
                    tokio::time::timeout(stop_timeout, server.stop())
                        .await
                        .map_err(|_| "Claude upstream relay stop timed out".to_string())?
                        .map(|_| ())
                        .map_err(|error| format!("Claude upstream relay failed to stop: {error}"))
                })
            })
            .map_err(|error| format!("Claude upstream relay thread failed: {error}"))?;
        let rear_guard = ClaudeRearStartupGuard::new(rear_stop_tx, rear, startup_timeout);
        let rear_port = match ready_rx.recv_timeout(startup_timeout) {
            Ok(Ok(port)) => port,
            Ok(Err(error)) => return Err(rear_guard.fail(error)),
            Err(_) => {
                return Err(rear_guard.fail("Claude upstream relay startup timed out".to_string()))
            }
        };

        if !parent_socket.is_absolute() {
            return Err(rear_guard.fail("Claude capture relay socket is not absolute".to_string()));
        }
        match std::fs::symlink_metadata(parent_socket) {
            Ok(_) => {
                return Err(
                    rear_guard.fail("Claude capture relay socket path already existed".to_string())
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(rear_guard.fail(format!(
                    "Claude capture relay socket path failed closed: {error}"
                )));
            }
        }
        let listener = (|| {
            let listener = UnixListener::bind(parent_socket)
                .map_err(|error| format!("Claude capture relay failed to bind: {error}"))?;
            std::fs::set_permissions(parent_socket, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("Claude capture relay permissions failed: {error}"))?;
            listener.set_nonblocking(true).map_err(|error| {
                format!("Claude capture relay could not become nonblocking: {error}")
            })?;
            Ok::<_, String>(listener)
        })();
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                let _ = std::fs::remove_file(parent_socket);
                return Err(rear_guard.fail(error));
            }
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let front_shutdown = Arc::clone(&shutdown);
        let front_containment_owner = containment_owner;
        let deadline = binding.deadline_unix_millis;
        let front = match std::thread::Builder::new()
            .name("maco-claude-capture-relay".to_string())
            .spawn(move || {
                let mut broker = ClaudeParentBroker::new(broker_grant);
                let mut helper_identity = None;
                while !front_shutdown.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if front_shutdown.load(Ordering::Acquire) {
                                break;
                            }
                            let peer = match unix_peer_credentials(&stream) {
                                Ok(peer) => peer,
                                Err(_) => {
                                    broker.record_unclassified_request();
                                    continue;
                                }
                            };
                            if let Some(identity) = helper_identity.as_ref() {
                                if let Err(_error) = verify_registered_helper_peer(peer, identity) {
                                    broker.record_unclassified_request();
                                    continue;
                                }
                            } else {
                                match register_helper_connection(
                                    &mut stream,
                                    peer,
                                    &helper_registration_nonce,
                                    &front_containment_owner,
                                    &front_shutdown,
                                    deadline,
                                ) {
                                    Ok(identity) => {
                                        helper_identity = Some(identity);
                                        continue;
                                    }
                                    Err(_error) => {
                                        broker.record_unclassified_request();
                                        continue;
                                    }
                                }
                            }
                            let response = match read_bounded_http_message(
                                &mut stream,
                                &front_shutdown,
                                deadline,
                            ) {
                                Ok(request) => broker.handle_http(&request, |request| {
                                    forward_to_cam_relay(
                                        request,
                                        rear_port,
                                        &local_relay_token,
                                        &front_shutdown,
                                        deadline,
                                    )
                                }),
                                Err(error) => {
                                    broker.record_unclassified_request();
                                    Err(error)
                                }
                            };
                            let bytes = response.unwrap_or_else(|_| {
                                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                            });
                            if stream
                                .set_write_timeout(Some(Duration::from_millis(100)))
                                .map_err(|error| error.to_string())
                                .and_then(|()| {
                                    write_with_shutdown(
                                        &mut stream,
                                        &bytes,
                                        &front_shutdown,
                                        deadline,
                                        "Claude local response",
                                    )
                                })
                                .is_err()
                            {
                                broker.record_unclassified_request();
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            return (
                                broker,
                                Some(format!("Claude capture relay accept failed: {error}")),
                            );
                        }
                    }
                }
                if helper_identity.is_none() {
                    broker.record_unclassified_request();
                }
                (broker, None)
            }) {
            Ok(front) => front,
            Err(error) => {
                let _ = std::fs::remove_file(parent_socket);
                return Err(rear_guard.fail(format!(
                    "Claude capture relay thread failed: {error}"
                )));
            }
        };
        let (rear_stop_tx, rear) = rear_guard.release();
        Ok(Self {
            socket_path: parent_socket.to_path_buf(),
            binding,
            shutdown,
            front: Some(front),
            rear_stop: Some(rear_stop_tx),
            rear: Some(rear),
        })
    }

    pub(crate) fn base_url(&self) -> &str {
        crate::process_runner::CLAUDE_CHILD_LOOPBACK_BASE_URL
    }

    pub(crate) fn binding(&self) -> &ClaudeBrokerBinding {
        &self.binding
    }

    pub(crate) fn finish(
        mut self,
        child_exit_observed: bool,
        interrupted: bool,
    ) -> Result<ClaudeManagedRelayFinish, String> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(stop) = self.rear_stop.take() {
            let _ = stop.send(());
        }
        let _ = wake_unix_listener(&self.socket_path);
        let front = self
            .front
            .take()
            .ok_or_else(|| "Claude capture relay owner was missing".to_string())?;
        let front_result = front
            .join()
            .map_err(|_| "Claude capture relay thread panicked".to_string());
        let socket_cleanup = std::fs::remove_file(&self.socket_path)
            .map_err(|error| format!("Claude capture relay socket cleanup failed: {error}"));
        let rear_result = self
            .rear
            .take()
            .ok_or_else(|| "Claude upstream relay owner was missing".to_string())?
            .join()
            .map_err(|_| "Claude upstream relay thread panicked".to_string())
            .and_then(|result| result);
        let (broker, front_error) = front_result?;
        let rear_error = rear_result.err();
        let listener_closed = front_error.is_none();
        let upstream_quiescent = rear_error.is_none();
        let error = front_error.or(rear_error).or(socket_cleanup.err());
        Ok(ClaudeManagedRelayFinish {
            witness: broker.seal(ClaudeBrokerTerminalSeal {
                child_exit_observed,
                listener_closed,
                upstream_quiescent,
                interrupted,
            }),
            error,
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for ClaudeManagedRelay {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(stop) = self.rear_stop.take() {
            let _ = stop.send(());
        }
        let _ = wake_unix_listener(&self.socket_path);
        if let Some(front) = self.front.take() {
            let _ = front.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(rear) = self.rear.take() {
            let _ = rear.join();
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct UnixPeerCredentials {
    pid: u32,
    uid: u32,
}

#[cfg(target_os = "linux")]
fn wake_unix_listener(path: &Path) -> Result<(), String> {
    let path_bytes = path.as_os_str().as_bytes();
    // SAFETY: zero is a valid initial representation before family/path initialization.
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    if path_bytes.is_empty()
        || path_bytes.contains(&0)
        || path_bytes.len() >= address.sun_path.len()
    {
        return Err("Claude capture relay wake path is invalid".to_string());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *target = *source as libc::c_char;
    }
    // SAFETY: socket has no Rust memory preconditions. Ownership is transferred immediately.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(format!(
            "Claude capture relay wake socket failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly-created owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let address_length =
        (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
    // SAFETY: address points to a fully initialized pathname sockaddr_un.
    let connected = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_length,
        )
    };
    if connected == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if !matches!(error.raw_os_error(), Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN)
    {
        return Err(format!("Claude capture relay wake failed: {error}"));
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        let mut descriptor = libc::pollfd {
            fd: owned.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the owned descriptor.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 50) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Claude capture relay wake poll failed: {error}"));
        }
        if ready == 0 {
            continue;
        }
        let mut socket_error = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: outputs are valid for SO_ERROR on this descriptor.
        if unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(format!(
                "Claude capture relay wake status failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        return if socket_error == 0 {
            Ok(())
        } else {
            Err(format!(
                "Claude capture relay wake failed: {}",
                std::io::Error::from_raw_os_error(socket_error)
            ))
        };
    }
    Err("Claude capture relay wake timed out".to_string())
}

#[cfg(target_os = "linux")]
fn unix_peer_credentials(stream: &UnixStream) -> Result<UnixPeerCredentials, String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor belongs to `stream`; the output points to a valid `ucred` and
    // `length` describes exactly that allocation.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err("Claude relay peer credentials are unavailable".to_string());
    }
    let pid = u32::try_from(credentials.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| "Claude relay peer PID is invalid".to_string())?;
    Ok(UnixPeerCredentials {
        pid,
        uid: credentials.uid,
    })
}

#[cfg(target_os = "linux")]
fn register_helper_connection(
    stream: &mut UnixStream,
    peer: UnixPeerCredentials,
    expected_nonce: &str,
    containment_owner: &crate::process_runner::ClaudeContainmentOwnerBinding,
    shutdown: &AtomicBool,
    deadline_unix_millis: u64,
) -> Result<ClaudeRelayHelperIdentity, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_millis(100))))
        .map_err(|error| format!("Claude helper registration timeout failed: {error}"))?;
    let mut bytes = Vec::new();
    loop {
        if shutdown.load(Ordering::Acquire) || unix_millis_now()? >= deadline_unix_millis {
            return Err("Claude helper registration was interrupted".to_string());
        }
        let mut chunk = [0u8; 512];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("Claude helper registration ended before newline".to_string()),
            Ok(read) => {
                if bytes.len().saturating_add(read) > 8192 {
                    return Err("Claude helper registration exceeded its bound".to_string());
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.last() == Some(&b'\n') {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("Claude helper registration read failed: {error}")),
        }
    }
    let line = std::str::from_utf8(&bytes)
        .map_err(|_| "Claude helper registration is not UTF-8".to_string())?
        .strip_suffix('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .ok_or_else(|| "Claude helper registration framing is invalid".to_string())?;
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() != 6
        || fields[0] != HELPER_REGISTRATION_PREFIX
        || !constant_time_equal(fields[1].as_bytes(), expected_nonce.as_bytes())
    {
        return Err("Claude helper registration binding is invalid".to_string());
    }
    let claimed_pid = fields[2]
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| "Claude helper registration PID is invalid".to_string())?;
    let claimed_start = fields[3]
        .parse::<u64>()
        .ok()
        .filter(|ticks| *ticks != 0)
        .ok_or_else(|| "Claude helper registration start time is invalid".to_string())?;
    let unit = fields[4];
    let cgroup = fields[5];
    let expected_owner = containment_owner
        .identity()
        .ok_or_else(|| "Claude containment owner was not bound before registration".to_string())?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if claimed_pid != peer.pid
        || peer.uid != effective_uid
        || unit.is_empty()
        || unit.len() > 255
        || unit.contains('/')
        || unit.chars().any(char::is_control)
        || cgroup.is_empty()
        || cgroup.len() > 4096
        || cgroup.chars().any(char::is_control)
        || unit != expected_owner.unit
        || cgroup != expected_owner.cgroup
    {
        return Err("Claude helper registration identity is malformed".to_string());
    }
    let identity = ClaudeRelayHelperIdentity {
        pid: peer.pid,
        start_ticks: claimed_start,
        cgroup: cgroup.to_string(),
        unit: unit.to_string(),
    };
    verify_registered_helper_peer(peer, &identity)?;
    write_with_shutdown(
        stream,
        b"MACO-CLAUDE-HELPER-ACK-V1\n",
        shutdown,
        deadline_unix_millis,
        "Claude helper registration acknowledgement",
    )?;
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn verify_registered_helper_peer(
    peer: UnixPeerCredentials,
    expected: &ClaudeRelayHelperIdentity,
) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if peer.uid != effective_uid || peer.pid != expected.pid {
        return Err("Claude relay connection did not come from the registered helper".to_string());
    }
    let start = process_start_ticks(peer.pid)?;
    let cgroup = process_cgroup(peer.pid)?;
    if start != expected.start_ticks || cgroup != expected.cgroup {
        return Err("Claude relay helper process identity changed".to_string());
    }
    let parent_program = std::fs::read_link("/proc/self/exe")
        .map_err(|error| format!("Claude parent executable is unavailable: {error}"))?;
    let helper_program = std::fs::read_link(format!("/proc/{}/exe", peer.pid))
        .map_err(|error| format!("Claude helper executable is unavailable: {error}"))?;
    if parent_program != helper_program {
        return Err("Claude relay helper executable differs from its parent".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_start_ticks(pid: u32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("Claude helper process stat failed: {error}"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| "Claude helper process stat is malformed".to_string())?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| "Claude helper process start time is unavailable".to_string())
}

#[cfg(target_os = "linux")]
fn process_cgroup(pid: u32) -> Result<String, String> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("Claude helper cgroup failed: {error}"))?;
    let mut lines = value.lines();
    let line = lines
        .next()
        .filter(|line| line.starts_with("0::/"))
        .ok_or_else(|| "Claude helper cgroup is malformed".to_string())?;
    if lines.next().is_some() || line.len() > 4099 || line.chars().any(char::is_control) {
        return Err("Claude helper cgroup is malformed".to_string());
    }
    Ok(line[3..].to_string())
}

#[cfg(target_os = "linux")]
fn write_with_shutdown(
    stream: &mut impl Write,
    bytes: &[u8],
    shutdown: &AtomicBool,
    deadline_unix_millis: u64,
    label: &str,
) -> Result<(), String> {
    let mut written = 0usize;
    while written < bytes.len() {
        if shutdown.load(Ordering::Acquire) || unix_millis_now()? >= deadline_unix_millis {
            return Err(format!("{label} was interrupted"));
        }
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(format!("{label} wrote zero bytes")),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("{label} failed: {error}")),
        }
    }
    if shutdown.load(Ordering::Acquire) || unix_millis_now()? >= deadline_unix_millis {
        return Err(format!("{label} was interrupted"));
    }
    stream
        .flush()
        .map_err(|error| format!("{label} failed: {error}"))
}

#[cfg(target_os = "linux")]
fn read_bounded_http_message(
    stream: &mut UnixStream,
    shutdown: &AtomicBool,
    deadline_unix_millis: u64,
) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|error| format!("Claude local request timeout failed: {error}"))?;
    let mut bytes = Vec::new();
    let mut target_length = None;
    loop {
        if shutdown.load(Ordering::Acquire) || unix_millis_now()? >= deadline_unix_millis {
            return Err("Claude local request was interrupted".to_string());
        }
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("Claude local request ended before framing completed".to_string()),
            Ok(read) => {
                if bytes.len().saturating_add(read) > MAX_BROKER_HTTP_BYTES {
                    return Err("Claude local request exceeded the bounded capture".to_string());
                }
                bytes.extend_from_slice(&chunk[..read]);
                if target_length.is_none() {
                    if let Some(split) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = std::str::from_utf8(&bytes[..split])
                            .map_err(|_| "Claude local request header is not UTF-8".to_string())?;
                        let content_length = http_content_length(head)?;
                        target_length = Some(split + 4 + content_length);
                    }
                }
                if target_length.is_some_and(|length| bytes.len() == length) {
                    return Ok(bytes);
                }
                if target_length.is_some_and(|length| bytes.len() > length) {
                    return Err("Claude local request contained trailing bytes".to_string());
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("Claude local request read failed: {error}")),
        }
    }
}

fn http_content_length(head: &str) -> Result<usize, String> {
    let mut length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err("Claude HTTP header is malformed".to_string());
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("Claude HTTP content length is duplicated".to_string());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "Claude HTTP content length is invalid".to_string())?,
            );
        }
    }
    Ok(length.unwrap_or(0))
}

#[cfg(target_os = "linux")]
fn forward_to_cam_relay(
    request: &ClaudeBrokerUpstreamRequest<'_>,
    rear_port: u16,
    local_relay_token: &str,
    shutdown: &AtomicBool,
    deadline_unix_millis: u64,
) -> Result<ClaudeBrokerUpstreamResponse, String> {
    if shutdown.load(Ordering::Acquire) {
        return Err("Claude upstream relay request was interrupted".to_string());
    }
    let connect_timeout = remaining_io_timeout(deadline_unix_millis)?;
    let mut stream = TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, rear_port).into(),
        connect_timeout,
    )
    .map_err(|error| format!("Claude upstream relay connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_millis(200))))
        .map_err(|error| format!("Claude upstream relay timeout failed: {error}"))?;
    let body = request.request_body();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{rear_port}\r\nAuthorization: Bearer {local_relay_token}\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    write_with_shutdown(
        &mut stream,
        head.as_bytes(),
        shutdown,
        deadline_unix_millis,
        "Claude upstream relay header write",
    )?;
    write_with_shutdown(
        &mut stream,
        body,
        shutdown,
        deadline_unix_millis,
        "Claude upstream relay body write",
    )?;
    let mut response = Vec::new();
    let mut response_truncated = false;
    loop {
        if shutdown.load(Ordering::Acquire) || unix_millis_now()? >= deadline_unix_millis {
            if response.is_empty() {
                return Err("Claude upstream relay request was interrupted".to_string());
            }
            response_truncated = true;
            break;
        }
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let capture_limit = MAX_BROKER_HTTP_BYTES + 64 * 1024;
                let remaining = capture_limit.saturating_sub(response.len());
                if read > remaining {
                    response.extend_from_slice(&chunk[..remaining]);
                    response_truncated = true;
                    break;
                }
                response.extend_from_slice(&chunk[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                if response.is_empty() {
                    return Err(format!("Claude upstream relay read failed: {error}"));
                }
                response_truncated = true;
                break;
            }
        }
    }
    parse_upstream_http_response(&response, response_truncated)
}

#[cfg(target_os = "linux")]
fn parse_upstream_http_response(
    bytes: &[u8],
    transport_truncated: bool,
) -> Result<ClaudeBrokerUpstreamResponse, String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Claude upstream relay response omitted its header".to_string())?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "Claude upstream relay response header is not UTF-8".to_string())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| "Claude upstream relay response status is invalid".to_string())?;
    let mut content_type = None;
    let mut content_length = None;
    let mut chunked = false;
    let mut seen = BTreeSet::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "Claude upstream relay response header is malformed".to_string())?;
        let name = name.trim().to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err("Claude upstream relay response header is duplicated".to_string());
        }
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = Some(value.to_string()),
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "Claude upstream response length is invalid".to_string())?,
                )
            }
            "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
            "transfer-encoding" => {
                return Err("Claude upstream transfer encoding is unsupported".to_string())
            }
            _ => {}
        }
    }
    if chunked && content_length.is_some() {
        return Err("Claude upstream response framing conflicts".to_string());
    }
    let framed = &bytes[split + 4..];
    let (body, framing_truncated) = if chunked {
        decode_http_chunks(framed, true)?
    } else if content_length == Some(framed.len()) {
        let retained = framed.len().min(MAX_BROKER_HTTP_BYTES);
        (
            framed[..retained].to_vec(),
            framed.len() > MAX_BROKER_HTTP_BYTES,
        )
    } else if content_length.is_some_and(|content_length| framed.len() < content_length) {
        let retained = framed.len().min(MAX_BROKER_HTTP_BYTES);
        (framed[..retained].to_vec(), true)
    } else {
        return Err("Claude upstream response framing is incomplete".to_string());
    };
    Ok(ClaudeBrokerUpstreamResponse {
        status,
        content_type: content_type
            .ok_or_else(|| "Claude upstream response content type is missing".to_string())?,
        body,
        truncated: transport_truncated || framing_truncated,
    })
}

#[cfg(target_os = "linux")]
fn decode_http_chunks(bytes: &[u8], allow_truncated: bool) -> Result<(Vec<u8>, bool), String> {
    let mut remaining = bytes;
    let mut body = Vec::new();
    loop {
        let Some(line_end) = remaining.windows(2).position(|window| window == b"\r\n") else {
            if allow_truncated {
                return Ok((body, true));
            }
            return Err("Claude upstream chunk header is incomplete".to_string());
        };
        let size_text = match std::str::from_utf8(&remaining[..line_end]) {
            Ok(size) => size,
            Err(_) if allow_truncated && !body.is_empty() => return Ok((body, true)),
            Err(_) => return Err("Claude upstream chunk size is not UTF-8".to_string()),
        };
        if size_text.contains(';') {
            if allow_truncated && !body.is_empty() {
                return Ok((body, true));
            }
            return Err("Claude upstream chunk extensions are unsupported".to_string());
        }
        let size = match usize::from_str_radix(size_text, 16) {
            Ok(size) => size,
            Err(_) if allow_truncated && !body.is_empty() => return Ok((body, true)),
            Err(_) => return Err("Claude upstream chunk size is invalid".to_string()),
        };
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            if remaining != b"\r\n" {
                if allow_truncated && remaining.len() < 2 {
                    return Ok((body, true));
                }
                if allow_truncated && !body.is_empty() {
                    return Ok((body, true));
                }
                return Err("Claude upstream chunk trailer is unsupported".to_string());
            }
            return Ok((body, false));
        }
        let framed_size = match size.checked_add(2) {
            Some(size) => size,
            None if allow_truncated && !body.is_empty() => return Ok((body, true)),
            None => return Err("Claude upstream chunk size overflowed".to_string()),
        };
        if remaining.len() < framed_size || &remaining[size..framed_size] != b"\r\n" {
            if allow_truncated && remaining.len() <= size + 1 {
                let available = MAX_BROKER_HTTP_BYTES.saturating_sub(body.len());
                let retained = remaining.len().min(size).min(available);
                body.extend_from_slice(&remaining[..retained]);
                return Ok((body, true));
            }
            if allow_truncated && !body.is_empty() {
                return Ok((body, true));
            }
            return Err("Claude upstream chunk body is incomplete".to_string());
        }
        if body.len().saturating_add(size) > MAX_BROKER_HTTP_BYTES {
            let available = MAX_BROKER_HTTP_BYTES.saturating_sub(body.len());
            body.extend_from_slice(&remaining[..available.min(size)]);
            return Ok((body, true));
        }
        body.extend_from_slice(&remaining[..size]);
        remaining = &remaining[framed_size..];
    }
}

#[cfg(target_os = "linux")]
fn unix_millis_now() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system clock does not fit Claude deadline".to_string())
}

#[cfg(target_os = "linux")]
fn remaining_io_timeout(deadline_unix_millis: u64) -> Result<Duration, String> {
    let remaining = deadline_unix_millis
        .checked_sub(unix_millis_now()?)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| "Claude relay deadline expired".to_string())?;
    Ok(Duration::from_millis(remaining.min(200)))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

pub(crate) struct ClaudeBrokerUpstreamRequest<'a> {
    request: &'a ClaudeBrokerRequest,
    #[cfg(test)]
    grant: &'a ClaudeTransportCredentialGrant,
}

impl ClaudeBrokerUpstreamRequest<'_> {
    pub(crate) fn request_body(&self) -> &[u8] {
        &self.request.body
    }

    #[cfg(test)]
    pub(crate) fn auth_mode(&self) -> ClaudeTransportAuthMode {
        self.grant.binding.auth_mode
    }

    #[cfg(test)]
    pub(crate) fn authorization_header_name(&self) -> &'static str {
        match self.grant.binding.auth_mode {
            ClaudeTransportAuthMode::BareApiKey => "x-api-key",
            ClaudeTransportAuthMode::OAuthBearer => "authorization",
        }
    }

    #[cfg(test)]
    pub(crate) fn authorization_value(&self) -> &[u8] {
        self.grant.authorization_value()
    }
}

#[derive(Debug)]
struct ClaudeBrokerSummary {
    messages: Vec<ClaudeBrokerMessageEvidence>,
    usage_by_model: BTreeMap<String, ClaudeUsageCounters>,
    models: BTreeSet<String>,
    failures: BTreeSet<ClaudeCoverageFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeBrokerMessageEvidence {
    message_id: String,
    observed_model: String,
    usage: ClaudeUsageCounters,
}

#[derive(Debug)]
struct ClaudeBrokerSseEvidence {
    message: Option<ClaudeBrokerMessageEvidence>,
    failures: BTreeSet<ClaudeCoverageFailure>,
}

fn broker_child_response(response: &ClaudeBrokerUpstreamResponse) -> Result<Vec<u8>, String> {
    if response.truncated {
        return Err("Claude broker upstream response was incomplete".to_string());
    }
    if response.body.len() > MAX_BROKER_HTTP_BYTES {
        return Err("Claude broker upstream response exceeds the bounded capture".to_string());
    }
    if response.content_type.contains(['\r', '\n']) {
        return Err("Claude broker upstream content type is invalid".to_string());
    }
    let reason = if response.status == 200 {
        "OK"
    } else {
        "Upstream"
    };
    let mut bytes = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(&response.body);
    Ok(bytes)
}

fn parse_broker_http_request(bytes: &[u8]) -> Result<ParsedClaudeBrokerRequest, String> {
    if bytes.len() > MAX_BROKER_HTTP_BYTES {
        return Err("Claude broker HTTP request exceeds the bounded capture".to_string());
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Claude broker HTTP request has no complete header".to_string())?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "Claude broker HTTP header is not UTF-8".to_string())?;
    let body = &bytes[split + 4..];
    let mut lines = head.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or_else(|| "Claude broker HTTP request line is missing".to_string())?
        .split_whitespace();
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default();
    let version = request_line.next().unwrap_or_default();
    if request_line.next().is_some()
        || !matches!(method, "HEAD" | "POST")
        || !path.starts_with('/')
        || path.contains(['?', '#'])
        || version != "HTTP/1.1"
    {
        return Err("Claude broker HTTP request line is unsupported".to_string());
    }
    let mut content_length = None;
    let mut content_type = None;
    let mut authorization = None;
    let mut api_key = None;
    let mut seen = BTreeSet::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "Claude broker HTTP header is malformed".to_string())?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty() || !seen.insert(name.clone()) {
            return Err("Claude broker HTTP header is empty or duplicated".to_string());
        }
        match name.as_str() {
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "Claude broker content length is invalid".to_string())?,
                );
            }
            "content-type" => content_type = Some(value.to_ascii_lowercase()),
            "authorization" => {
                authorization = Some(ClaudeRequestAuthorization(value.as_bytes().to_vec()))
            }
            "x-api-key" => api_key = Some(ClaudeRequestAuthorization(value.as_bytes().to_vec())),
            "transfer-encoding" => {
                return Err("Claude broker transfer encoding is unsupported".to_string());
            }
            _ => {}
        }
    }
    if content_length.unwrap_or(0) != body.len() {
        return Err("Claude broker HTTP body length does not match".to_string());
    }
    if authorization.is_some() && api_key.is_some() {
        return Err("Claude broker request mixed OAuth and API-key authorization".to_string());
    }
    let mut model = None;
    let mut declared_tools = BTreeSet::new();
    if method == "POST" {
        if !content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("application/json"))
        {
            return Err("Claude broker messages request is not JSON".to_string());
        }
        let UniqueJson(root) = serde_json::from_slice::<UniqueJson>(body)
            .map_err(|error| format!("Claude broker messages JSON is invalid: {error}"))?;
        let object = root
            .as_object()
            .ok_or_else(|| "Claude broker messages JSON is not an object".to_string())?;
        model = object
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if model.is_none()
            || object.get("stream").and_then(Value::as_bool) != Some(true)
            || object.get("max_tokens").and_then(Value::as_u64).is_none()
        {
            return Err("Claude broker messages request omitted its bound controls".to_string());
        }
        if let Some(tools) = object.get("tools") {
            let tools = tools
                .as_array()
                .ok_or_else(|| "Claude broker tools value is not an array".to_string())?;
            for tool in tools {
                let name = tool
                    .as_object()
                    .and_then(|tool| tool.get("name"))
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| "Claude broker tool has no name".to_string())?;
                if !declared_tools.insert(name.to_string()) {
                    return Err("Claude broker tool name is duplicated".to_string());
                }
            }
        }
    }
    Ok(ParsedClaudeBrokerRequest {
        request: ClaudeBrokerRequest {
            method: method.to_string(),
            path: path.to_string(),
            body: body.to_vec(),
            model,
            declared_tools,
        },
        authorization: authorization.or(api_key),
    })
}

impl ClaudeWholeCallWitness {
    fn summarize(&self, expected: &ClaudeBrokerBinding) -> ClaudeBrokerSummary {
        let mut failures = BTreeSet::new();
        if &self.binding != expected {
            failures.insert(ClaudeCoverageFailure::BrokerBindingMismatch);
        }
        if self.captures.len() > MAX_BROKER_EXCHANGES
            || self.unclassified_requests != 0
            || !self.seal.child_exit_observed
            || !self.seal.listener_closed
            || !self.seal.upstream_quiescent
            || self.seal.interrupted
        {
            failures.insert(ClaudeCoverageFailure::BrokerRequestCoverage);
        }
        let mut messages: Vec<ClaudeBrokerMessageEvidence> = Vec::new();
        let mut usage_by_model = BTreeMap::<String, ClaudeUsageCounters>::new();
        let mut models = BTreeSet::new();
        let mut message_indices = BTreeMap::<String, usize>::new();
        let mut local_head_seen = false;
        let mut primary_seen = false;
        for capture in &self.captures {
            if capture.request.method == "HEAD"
                && capture.request.path == "/"
                && capture.request.body.is_empty()
            {
                if capture.forwarded || capture.response.is_some() || local_head_seen {
                    failures.insert(ClaudeCoverageFailure::BrokerRequestCoverage);
                }
                local_head_seen = true;
                continue;
            }
            if capture.request.method != "POST" || capture.request.path != "/v1/messages" {
                failures.insert(ClaudeCoverageFailure::BrokerUnknownTraffic);
                continue;
            }
            let requested_model = capture.request.model.as_deref();
            let known_primary = requested_model == Some(CLAUDE_MANAGED_PRIMARY_MODEL);
            let known_auxiliary = requested_model == Some(CLAUDE_MANAGED_AUXILIARY_MODEL)
                && capture.request.declared_tools.is_empty();
            if known_primary {
                primary_seen |= capture.forwarded;
                if capture
                    .request
                    .declared_tools
                    .iter()
                    .any(|tool| !CLAUDE_NATIVE_TOOLS.contains(&tool.as_str()))
                {
                    failures.insert(ClaudeCoverageFailure::BrokerRequestCoverage);
                }
            } else if !known_auxiliary {
                failures.insert(ClaudeCoverageFailure::FallbackOrAuxiliaryModel);
            }
            if !capture.forwarded {
                failures.insert(ClaudeCoverageFailure::BrokerRequestCoverage);
                continue;
            }
            let Some(response) = capture.response.as_ref() else {
                failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
                continue;
            };
            if response.truncated {
                failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
            }
            if response.status != 200
                || !response
                    .content_type
                    .to_ascii_lowercase()
                    .starts_with("text/event-stream")
            {
                failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
                continue;
            }
            let parsed = parse_broker_sse(&response.body);
            failures.extend(parsed.failures);
            let Some(message) = parsed.message else {
                continue;
            };
            if requested_model != Some(message.observed_model.as_str()) {
                failures.insert(ClaudeCoverageFailure::ConflictingObservedModel);
            }
            if let Some(index) = message_indices.get(&message.message_id).copied() {
                failures.insert(ClaudeCoverageFailure::DuplicateMessage);
                let retained = &mut messages[index];
                if retained.observed_model != message.observed_model {
                    failures.insert(ClaudeCoverageFailure::ConflictingObservedModel);
                } else {
                    let (usage, overflowed) =
                        retained.usage.checked_componentwise_max(message.usage);
                    retained.usage = usage;
                    if overflowed {
                        failures.insert(ClaudeCoverageFailure::CounterOverflow);
                    }
                }
                continue;
            }
            message_indices.insert(message.message_id.clone(), messages.len());
            messages.push(message);
        }
        for message in &messages {
            models.insert(message.observed_model.clone());
            let model_usage = usage_by_model
                .entry(message.observed_model.clone())
                .or_default();
            match model_usage.checked_add(message.usage) {
                Some(total) => *model_usage = total,
                None => {
                    failures.insert(ClaudeCoverageFailure::CounterOverflow);
                }
            }
        }
        if !local_head_seen || !primary_seen || messages.is_empty() {
            failures.insert(ClaudeCoverageFailure::BrokerRequestCoverage);
        }
        ClaudeBrokerSummary {
            messages,
            usage_by_model,
            models,
            failures,
        }
    }
}

fn parse_broker_sse(body: &[u8]) -> ClaudeBrokerSseEvidence {
    let mut failures = BTreeSet::new();
    if body.len() > MAX_BROKER_HTTP_BYTES {
        failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
        return ClaudeBrokerSseEvidence {
            message: None,
            failures,
        };
    }
    let body = match std::str::from_utf8(body) {
        Ok(body) => body,
        Err(error) => {
            failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
            // Only the UTF-8 prefix is parsed; the invalid tail remains a coverage failure.
            std::str::from_utf8(&body[..error.valid_up_to()]).unwrap_or_default()
        }
    };
    let mut message_id = None;
    let mut model = None;
    let mut usage = None;
    let mut stopped = false;
    let mut events = 0usize;
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let Some(next_events) = events.checked_add(1) else {
            failures.insert(ClaudeCoverageFailure::CounterOverflow);
            break;
        };
        events = next_events;
        if events > MAX_BROKER_SSE_EVENTS {
            failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
            break;
        }
        let data = data.trim_start();
        if data == "[DONE]" {
            continue;
        }
        let UniqueJson(value) = match serde_json::from_str::<UniqueJson>(data) {
            Ok(value) => value,
            Err(error) => {
                failures.insert(if error.to_string().contains(DUPLICATE_WIRE_KEY_ERROR) {
                    ClaudeCoverageFailure::DuplicateWireKey
                } else {
                    ClaudeCoverageFailure::BrokerResponseCoverage
                });
                continue;
            }
        };
        let Some(event) = value.as_object() else {
            failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if message_id.is_some() || usage.is_some() {
                    failures.insert(ClaudeCoverageFailure::DuplicateMessage);
                    continue;
                }
                let Some(message) = event.get("message").and_then(Value::as_object) else {
                    failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
                    continue;
                };
                message_id = message
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                model = message
                    .get("model")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                let Some(counters) = message.get("usage").and_then(Value::as_object) else {
                    failures.insert(ClaudeCoverageFailure::MissingUsage);
                    continue;
                };
                let mut parse_failures = BTreeSet::new();
                let counters = parse_start_usage(counters, &mut parse_failures);
                failures.extend(parse_failures);
                usage = Some(counters);
            }
            Some("message_delta") => {
                let Some(counters) = event.get("usage").and_then(Value::as_object) else {
                    failures.insert(ClaudeCoverageFailure::MissingUsage);
                    continue;
                };
                let Some(usage) = usage.as_mut() else {
                    failures.insert(ClaudeCoverageFailure::MessageDeltaWithoutStart);
                    continue;
                };
                if usage.presence.output_tokens {
                    failures.insert(ClaudeCoverageFailure::DuplicateCounter);
                    continue;
                }
                let mut counter_failures = BTreeSet::new();
                let output = counter(counters, "output_tokens", &mut counter_failures, true);
                if counters
                    .keys()
                    .any(|key| key != "output_tokens" && key != "server_tool_use")
                {
                    counter_failures.insert(ClaudeCoverageFailure::DuplicateCounter);
                }
                failures.extend(counter_failures);
                if let Some(output) = output {
                    usage.output_tokens = output;
                    usage.presence.output_tokens = true;
                } else {
                    failures.insert(ClaudeCoverageFailure::MissingCounter);
                }
            }
            Some("message_stop") => {
                if stopped || usage.is_none() {
                    failures.insert(ClaudeCoverageFailure::MessageStopWithoutStart);
                    continue;
                }
                stopped = true;
            }
            Some("content_block_start" | "content_block_delta" | "content_block_stop" | "ping") => {
            }
            _ => {
                failures.insert(ClaudeCoverageFailure::BrokerResponseCoverage);
            }
        }
    }
    if usage.is_none() {
        failures.insert(ClaudeCoverageFailure::MissingUsage);
    }
    if !stopped || usage.is_some_and(|usage| !usage.presence.output_tokens) {
        failures.insert(ClaudeCoverageFailure::MessageNotStopped);
    }
    if message_id.is_none() {
        failures.insert(ClaudeCoverageFailure::MissingMessageId);
    }
    if model.is_none() {
        failures.insert(ClaudeCoverageFailure::MissingObservedModel);
    }
    let message = message_id
        .zip(model)
        .zip(usage)
        .map(
            |((message_id, observed_model), usage)| ClaudeBrokerMessageEvidence {
                message_id,
                observed_model,
                usage,
            },
        );
    ClaudeBrokerSseEvidence { message, failures }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeNativeMessageEvidence {
    pub(crate) session_id: String,
    pub(crate) message_id: String,
    pub(crate) observed_model: String,
    pub(crate) usage: ClaudeUsageCounters,
    pub(crate) stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeNativeEvidence {
    pub(crate) session_id: Option<String>,
    pub(crate) observed_model: Option<String>,
    pub(crate) messages: Vec<ClaudeNativeMessageEvidence>,
    pub(crate) failures: BTreeSet<ClaudeCoverageFailure>,
    pub(crate) result_text: Option<Vec<u8>>,
    reported_models: Option<BTreeSet<String>>,
    reported_model_usage: Option<BTreeMap<String, ClaudeUsageCounters>>,
    usage_lower_bound: Option<Usage>,
    complete: bool,
}

impl ClaudeNativeEvidence {
    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn complete_usage(&self) -> Option<Usage> {
        self.complete.then_some(self.usage_lower_bound).flatten()
    }

    pub(crate) fn usage_lower_bound(&self) -> Option<Usage> {
        self.usage_lower_bound
    }

    pub(crate) fn observed_model(&self) -> Option<&str> {
        (!self.failures.iter().any(|failure| {
            matches!(
                failure,
                ClaudeCoverageFailure::MissingObservedModel
                    | ClaudeCoverageFailure::ConflictingObservedModel
                    | ClaudeCoverageFailure::AssistantModelConflict
                    | ClaudeCoverageFailure::FallbackOrAuxiliaryModel
            )
        }))
        .then_some(self.observed_model.as_deref())
        .flatten()
    }

    pub(crate) fn mark_interrupted(&mut self) {
        self.failures.insert(ClaudeCoverageFailure::Interrupted);
        self.complete = false;
    }

    pub(crate) fn attach_whole_call_witness(
        &mut self,
        witness: &ClaudeWholeCallWitness,
        expected_binding: &ClaudeBrokerBinding,
    ) {
        let summary = witness.summarize(expected_binding);
        self.failures.extend(summary.failures.iter().copied());
        let native_messages_match = self.messages.iter().all(|native| {
            summary.messages.iter().any(|captured| {
                captured.message_id == native.message_id
                    && captured.observed_model == native.observed_model
                    && captured.usage == native.usage
            })
        });
        if !native_messages_match {
            self.failures
                .insert(ClaudeCoverageFailure::BrokerResponseCoverage);
        }
        let admitted_models = [
            CLAUDE_MANAGED_PRIMARY_MODEL.to_string(),
            CLAUDE_MANAGED_AUXILIARY_MODEL.to_string(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if summary.models.is_empty()
            || !summary.models.is_subset(&admitted_models)
            || !summary.models.contains(CLAUDE_MANAGED_PRIMARY_MODEL)
            || self.reported_models.as_ref() != Some(&summary.models)
        {
            self.failures
                .insert(ClaudeCoverageFailure::ModelCoverageMissing);
        }
        let reported_usage_matches = self.reported_model_usage.as_ref().is_some_and(|reported| {
            reported.len() == summary.usage_by_model.len()
                && reported.iter().all(|(model, usage)| {
                    summary
                        .usage_by_model
                        .get(model)
                        .is_some_and(|captured| same_four_usage_buckets(*usage, *captured))
                })
        });
        if !reported_usage_matches {
            self.failures
                .insert(ClaudeCoverageFailure::AggregateCounterConflict);
        }

        let mut observed_messages = BTreeMap::<String, (String, ClaudeUsageCounters)>::new();
        for native in &self.messages {
            observed_messages.insert(
                native.message_id.clone(),
                (native.observed_model.clone(), native.usage),
            );
        }
        if !summary
            .failures
            .contains(&ClaudeCoverageFailure::BrokerBindingMismatch)
        {
            for captured in &summary.messages {
                match observed_messages.get_mut(&captured.message_id) {
                    Some((model, usage)) => {
                        if model != &captured.observed_model || *usage != captured.usage {
                            self.failures
                                .insert(ClaudeCoverageFailure::BrokerResponseCoverage);
                            let (retained, overflowed) =
                                usage.checked_componentwise_max(captured.usage);
                            *usage = retained;
                            if overflowed {
                                self.failures.insert(ClaudeCoverageFailure::CounterOverflow);
                            }
                        }
                    }
                    None => {
                        observed_messages.insert(
                            captured.message_id.clone(),
                            (captured.observed_model.clone(), captured.usage),
                        );
                    }
                }
            }
        }
        let mut merged_usage = ClaudeUsageCounters::default();
        let mut merged_usage_observed = false;
        for (_, usage) in observed_messages.values() {
            match merged_usage.checked_add(*usage) {
                Some(next) => {
                    merged_usage = next;
                    merged_usage_observed = true;
                }
                None => {
                    self.failures.insert(ClaudeCoverageFailure::CounterOverflow);
                }
            }
        }
        if self.failures.iter().all(|failure| {
            matches!(
                failure,
                ClaudeCoverageFailure::NativeCoverageWitnessMissing
                    | ClaudeCoverageFailure::FallbackOrAuxiliaryModel
            )
        }) {
            self.failures
                .remove(&ClaudeCoverageFailure::NativeCoverageWitnessMissing);
            self.failures
                .remove(&ClaudeCoverageFailure::FallbackOrAuxiliaryModel);
        }
        if merged_usage_observed {
            match merged_usage.as_usage() {
                Some(usage) => self.usage_lower_bound = Some(usage),
                None => {
                    self.failures.insert(ClaudeCoverageFailure::CounterOverflow);
                }
            }
        }
        self.complete = self.failures.is_empty();
    }
}

#[derive(Debug, Default)]
struct NativeCollector {
    session_id: Option<String>,
    observed_model: Option<String>,
    messages: BTreeMap<String, ClaudeNativeMessageEvidence>,
    message_order: Vec<String>,
    active_by_session: BTreeMap<String, String>,
    assistant_messages: BTreeMap<String, String>,
    failures: BTreeSet<ClaudeCoverageFailure>,
    init_seen: bool,
    result_seen: bool,
    result_success: bool,
    result_turns: Option<u64>,
    result_models: Option<BTreeSet<String>>,
    result_model_usage: Option<BTreeMap<String, ClaudeUsageCounters>>,
    result_usage: Option<ClaudeUsageCounters>,
    result_text: Option<Vec<u8>>,
}

impl NativeCollector {
    fn fail(&mut self, failure: ClaudeCoverageFailure) {
        self.failures.insert(failure);
    }

    fn bind_session(&mut self, value: Option<&Value>) -> Option<String> {
        let Some(session) = value
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            self.fail(ClaudeCoverageFailure::MissingSessionId);
            return None;
        };
        if self
            .session_id
            .as_deref()
            .is_some_and(|known| known != session)
        {
            self.fail(ClaudeCoverageFailure::ConflictingSessionId);
        } else {
            self.session_id.get_or_insert_with(|| session.to_string());
        }
        Some(session.to_string())
    }

    fn bind_model(&mut self, model: Option<&Value>) -> Option<String> {
        let Some(model) = model
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            self.fail(ClaudeCoverageFailure::MissingObservedModel);
            return None;
        };
        if self
            .observed_model
            .as_deref()
            .is_some_and(|known| known != model)
        {
            self.fail(ClaudeCoverageFailure::ConflictingObservedModel);
        } else {
            self.observed_model.get_or_insert_with(|| model.to_string());
        }
        Some(model.to_string())
    }

    fn collect_start(&mut self, root: &Map<String, Value>, event: &Map<String, Value>) {
        let Some(session_id) = self.bind_session(root.get("session_id")) else {
            return;
        };
        let Some(message) = event.get("message").and_then(Value::as_object) else {
            self.fail(ClaudeCoverageFailure::MissingMessageId);
            return;
        };
        let Some(message_id) = message
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            self.fail(ClaudeCoverageFailure::MissingMessageId);
            return;
        };
        let Some(observed_model) = self.bind_model(message.get("model")) else {
            return;
        };
        if self.messages.contains_key(&message_id)
            || self.active_by_session.contains_key(&session_id)
            || self.messages.len() >= MAX_NATIVE_MESSAGES
        {
            self.fail(if self.messages.len() >= MAX_NATIVE_MESSAGES {
                ClaudeCoverageFailure::TooManyMessages
            } else {
                ClaudeCoverageFailure::DuplicateMessage
            });
            return;
        }
        let Some(usage) = message.get("usage").and_then(Value::as_object) else {
            self.fail(ClaudeCoverageFailure::MissingUsage);
            return;
        };
        let counters = parse_start_usage(usage, &mut self.failures);
        self.message_order.push(message_id.clone());
        self.active_by_session
            .insert(session_id.clone(), message_id.clone());
        self.messages.insert(
            message_id.clone(),
            ClaudeNativeMessageEvidence {
                session_id,
                message_id,
                observed_model,
                usage: counters,
                stopped: false,
            },
        );
    }

    fn collect_delta(&mut self, root: &Map<String, Value>, event: &Map<String, Value>) {
        let Some(session_id) = self.bind_session(root.get("session_id")) else {
            return;
        };
        let Some(message_id) = self.active_by_session.get(&session_id).cloned() else {
            self.fail(ClaudeCoverageFailure::MessageDeltaWithoutStart);
            return;
        };
        let Some(usage) = event.get("usage").and_then(Value::as_object) else {
            self.fail(ClaudeCoverageFailure::MissingUsage);
            return;
        };
        let output = counter(usage, "output_tokens", &mut self.failures, true);
        if usage
            .keys()
            .any(|key| key != "output_tokens" && key != "server_tool_use")
        {
            self.fail(ClaudeCoverageFailure::DuplicateCounter);
        }
        let Some(message) = self.messages.get_mut(&message_id) else {
            self.fail(ClaudeCoverageFailure::MessageDeltaWithoutStart);
            return;
        };
        if message.usage.presence.output_tokens {
            self.fail(ClaudeCoverageFailure::DuplicateCounter);
            return;
        }
        if let Some(output) = output {
            message.usage.output_tokens = output;
            message.usage.presence.output_tokens = true;
        }
    }

    fn collect_stop(&mut self, root: &Map<String, Value>) {
        let Some(session_id) = self.bind_session(root.get("session_id")) else {
            return;
        };
        let Some(message_id) = self.active_by_session.remove(&session_id) else {
            self.fail(ClaudeCoverageFailure::MessageStopWithoutStart);
            return;
        };
        let Some(message) = self.messages.get_mut(&message_id) else {
            self.fail(ClaudeCoverageFailure::MessageStopWithoutStart);
            return;
        };
        let missing_counter = !message.usage.presence.output_tokens;
        message.stopped = true;
        if missing_counter {
            self.fail(ClaudeCoverageFailure::MissingCounter);
        }
    }

    fn collect_assistant(&mut self, root: &Map<String, Value>) {
        let Some(session_id) = self.bind_session(root.get("session_id")) else {
            return;
        };
        let Some(message) = root.get("message").and_then(Value::as_object) else {
            self.fail(ClaudeCoverageFailure::AssistantWithoutRawMessage);
            return;
        };
        let Some(message_id) = message.get("id").and_then(Value::as_str) else {
            self.fail(ClaudeCoverageFailure::AssistantWithoutRawMessage);
            return;
        };
        if let Some(model) = message.get("model").and_then(Value::as_str) {
            if self
                .messages
                .get(message_id)
                .is_some_and(|raw| raw.observed_model != model)
            {
                self.fail(ClaudeCoverageFailure::AssistantModelConflict);
            }
        }
        if self
            .assistant_messages
            .insert(message_id.to_string(), session_id)
            .is_some()
        {
            self.fail(ClaudeCoverageFailure::DuplicateMessage);
        }
    }

    fn collect_init(&mut self, root: &Map<String, Value>) {
        self.bind_session(root.get("session_id"));
        if self.init_seen {
            self.fail(ClaudeCoverageFailure::DuplicateInit);
            return;
        }
        self.init_seen = true;
        let tools = root
            .get("tools")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if tools != CLAUDE_NATIVE_TOOLS.into_iter().collect::<BTreeSet<_>>() {
            self.fail(ClaudeCoverageFailure::EffectiveToolsConflict);
        }
        if root
            .get("mcp_servers")
            .is_some_and(|value| !empty_collection(value))
        {
            self.fail(ClaudeCoverageFailure::EffectiveMcpConfiguration);
        }
    }

    fn collect_result(&mut self, root: &Map<String, Value>) {
        let result_session = self.bind_session(root.get("session_id"));
        if self.result_seen {
            self.fail(ClaudeCoverageFailure::DuplicateResult);
            return;
        }
        self.result_seen = true;
        self.result_success = root.get("subtype").and_then(Value::as_str) == Some("success")
            && root.get("is_error").and_then(Value::as_bool) == Some(false);
        if !self.result_success {
            self.fail(ClaudeCoverageFailure::UnsuccessfulResult);
        }
        if result_session.as_deref() != self.session_id.as_deref() {
            self.fail(ClaudeCoverageFailure::ResultSessionConflict);
        }
        self.result_turns = root.get("num_turns").and_then(Value::as_u64);
        if self.result_turns.is_none() {
            self.fail(ClaudeCoverageFailure::TurnCountMissing);
        }
        self.result_models = root
            .get("modelUsage")
            .and_then(Value::as_object)
            .map(|models| models.keys().cloned().collect::<BTreeSet<_>>());
        if self.result_models.is_none() {
            self.fail(ClaudeCoverageFailure::ModelCoverageMissing);
        }
        self.result_model_usage = root
            .get("modelUsage")
            .and_then(Value::as_object)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|(model, usage)| {
                        usage.as_object().map(|usage| {
                            (model.clone(), parse_result_usage(usage, &mut self.failures))
                        })
                    })
                    .collect::<BTreeMap<_, _>>()
            });
        if self.result_model_usage.as_ref().is_some_and(|usage| {
            self.result_models
                .as_ref()
                .is_none_or(|models| usage.len() != models.len())
        }) {
            self.fail(ClaudeCoverageFailure::MissingUsage);
        }
        let result_usage = root
            .get("modelUsage")
            .and_then(Value::as_object)
            .filter(|models| models.len() == 1)
            .and_then(|models| models.values().next())
            .and_then(Value::as_object)
            .map(|usage| parse_result_usage(usage, &mut self.failures));
        self.result_usage = result_usage;
        if self
            .result_models
            .as_ref()
            .is_some_and(|models| models.len() == 1)
            && self.result_usage.is_none()
        {
            self.fail(ClaudeCoverageFailure::MissingUsage);
        }
        self.result_text = root
            .get("result")
            .and_then(Value::as_str)
            .map(|value| value.as_bytes().to_vec());
        if self.result_text.is_none() {
            self.fail(ClaudeCoverageFailure::MissingResultText);
        }
    }

    fn finish(mut self) -> ClaudeNativeEvidence {
        if !self.init_seen {
            self.fail(ClaudeCoverageFailure::MissingInit);
        }
        if !self.result_seen {
            self.fail(ClaudeCoverageFailure::MissingResult);
        }
        if !self.active_by_session.is_empty()
            || self.messages.values().any(|message| !message.stopped)
        {
            self.fail(ClaudeCoverageFailure::MessageNotStopped);
        }
        if self.messages.is_empty()
            || self.assistant_messages.len() != self.messages.len()
            || self
                .assistant_messages
                .keys()
                .any(|message_id| !self.messages.contains_key(message_id))
        {
            self.fail(ClaudeCoverageFailure::AssistantWithoutRawMessage);
        }
        if self
            .result_turns
            .is_some_and(|turns| usize::try_from(turns).ok() != Some(self.messages.len()))
        {
            self.fail(ClaudeCoverageFailure::TurnCountConflict);
        }
        if let Some(result_models) = &self.result_models {
            let observed = self.observed_model.iter().cloned().collect::<BTreeSet<_>>();
            if result_models != &observed {
                self.fail(ClaudeCoverageFailure::FallbackOrAuxiliaryModel);
            }
        }
        let mut total = ClaudeUsageCounters::default();
        let mut observed = false;
        let mut counter_overflow = false;
        for message in self.messages.values() {
            match total.checked_add(message.usage) {
                Some(next) => {
                    total = next;
                    observed = true;
                }
                None => counter_overflow = true,
            }
        }
        if counter_overflow {
            self.fail(ClaudeCoverageFailure::CounterOverflow);
        }
        let usage_lower_bound = observed.then(|| total.as_usage()).flatten();
        if observed && usage_lower_bound.is_none() {
            self.fail(ClaudeCoverageFailure::CounterOverflow);
        }
        if let Some(aggregate) = self.result_usage {
            if aggregate.input_tokens != total.input_tokens
                || aggregate.cache_creation_input_tokens != total.cache_creation_input_tokens
                || aggregate.cache_read_input_tokens != total.cache_read_input_tokens
                || aggregate.output_tokens != total.output_tokens
            {
                self.fail(ClaudeCoverageFailure::AggregateCounterConflict);
            }
        }
        // The pinned stdout protocol does not attest that every physical native call was
        // represented. Result/init/request aggregates are consistency guards only. Until a
        // separately source-bound whole-call witness is attached by this concrete launcher,
        // observed raw counters remain lower bounds and can never become complete accounting.
        self.fail(ClaudeCoverageFailure::NativeCoverageWitnessMissing);
        let messages = self
            .message_order
            .iter()
            .filter_map(|id| self.messages.get(id).cloned())
            .collect::<Vec<_>>();
        ClaudeNativeEvidence {
            session_id: self.session_id,
            observed_model: self.observed_model,
            messages,
            complete: self.failures.is_empty(),
            failures: self.failures,
            result_text: self.result_text,
            reported_models: self.result_models,
            reported_model_usage: self.result_model_usage,
            usage_lower_bound,
        }
    }
}

fn same_four_usage_buckets(left: ClaudeUsageCounters, right: ClaudeUsageCounters) -> bool {
    left.input_tokens == right.input_tokens
        && left.cache_creation_input_tokens == right.cache_creation_input_tokens
        && left.cache_read_input_tokens == right.cache_read_input_tokens
        && left.output_tokens == right.output_tokens
}

pub(crate) fn collect_native_stream(bytes: &[u8], capture_truncated: bool) -> ClaudeNativeEvidence {
    let mut collector = NativeCollector::default();
    if capture_truncated {
        collector.fail(ClaudeCoverageFailure::CaptureTruncated);
    }
    if bytes.len() > MAX_NATIVE_STREAM_BYTES {
        collector.fail(ClaudeCoverageFailure::StreamTooLarge);
    }
    let line_count = bytes.split(|byte| *byte == b'\n').count();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if index >= MAX_NATIVE_STREAM_LINES {
            collector.fail(ClaudeCoverageFailure::TooManyLines);
            break;
        }
        if line.is_empty() {
            if index + 1 != line_count {
                collector.fail(ClaudeCoverageFailure::EmptyLine);
            }
            continue;
        }
        let value = match serde_json::from_slice::<UniqueJson>(line) {
            Ok(UniqueJson(value)) => value,
            Err(error) if error.to_string().contains(DUPLICATE_WIRE_KEY_ERROR) => {
                collector.fail(ClaudeCoverageFailure::DuplicateWireKey);
                continue;
            }
            Err(_) => {
                collector.fail(ClaudeCoverageFailure::MalformedJson);
                continue;
            }
        };
        let Some(root) = value.as_object() else {
            collector.fail(ClaudeCoverageFailure::MalformedJson);
            continue;
        };
        let event_type = root.get("type").and_then(Value::as_str);
        let subtype = root.get("subtype").and_then(Value::as_str);
        if event_type.is_some_and(|value| value.contains("compact"))
            || subtype.is_some_and(|value| value.contains("compact"))
        {
            collector.fail(ClaudeCoverageFailure::CompactionObserved);
        }
        match event_type {
            Some("system") if subtype == Some("init") => collector.collect_init(root),
            Some("assistant") => collector.collect_assistant(root),
            Some("result") => collector.collect_result(root),
            Some("stream_event") => {
                let Some(event) = root.get("event").and_then(Value::as_object) else {
                    collector.fail(ClaudeCoverageFailure::UnknownStreamEvent);
                    continue;
                };
                match event.get("type").and_then(Value::as_str) {
                    Some("message_start") => collector.collect_start(root, event),
                    Some("message_delta") => collector.collect_delta(root, event),
                    Some("message_stop") => collector.collect_stop(root),
                    Some("content_block_start" | "content_block_delta" | "content_block_stop") => {}
                    Some(value) if value.contains("compact") => {
                        collector.fail(ClaudeCoverageFailure::CompactionObserved)
                    }
                    _ => collector.fail(ClaudeCoverageFailure::UnknownStreamEvent),
                }
            }
            Some("user" | "tool_progress" | "auth_status" | "rate_limit_event") => {
                collector.bind_session(root.get("session_id"));
            }
            _ => collector.fail(ClaudeCoverageFailure::UnknownStreamEvent),
        }
    }
    collector.finish()
}

fn counter(
    usage: &Map<String, Value>,
    name: &str,
    failures: &mut BTreeSet<ClaudeCoverageFailure>,
    required: bool,
) -> Option<u64> {
    match usage.get(name) {
        Some(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                failures.insert(ClaudeCoverageFailure::InvalidCounter);
                None
            }
        },
        None if required => {
            failures.insert(ClaudeCoverageFailure::MissingCounter);
            None
        }
        None => None,
    }
}

fn parse_start_usage(
    usage: &Map<String, Value>,
    failures: &mut BTreeSet<ClaudeCoverageFailure>,
) -> ClaudeUsageCounters {
    let input_tokens = counter(usage, "input_tokens", failures, true);
    let cache_creation_input_tokens = counter(usage, "cache_creation_input_tokens", failures, true);
    let cache_read_input_tokens = counter(usage, "cache_read_input_tokens", failures, true);
    let output_tokens = counter(usage, "output_tokens", failures, false);
    if output_tokens.is_some_and(|value| value != 0) {
        failures.insert(ClaudeCoverageFailure::DuplicateCounter);
    }
    let cache_creation = usage.get("cache_creation").and_then(Value::as_object);
    if cache_creation.is_none() {
        failures.insert(ClaudeCoverageFailure::MissingCounter);
    }
    let cache_creation_5m_input_tokens = cache_creation
        .and_then(|value| counter(value, "ephemeral_5m_input_tokens", failures, true));
    let cache_creation_1h_input_tokens = cache_creation
        .and_then(|value| counter(value, "ephemeral_1h_input_tokens", failures, true));
    if let (Some(total), Some(five), Some(one)) = (
        cache_creation_input_tokens,
        cache_creation_5m_input_tokens,
        cache_creation_1h_input_tokens,
    ) {
        if five.checked_add(one) != Some(total) {
            failures.insert(ClaudeCoverageFailure::ConflictingCacheBuckets);
        }
    }
    ClaudeUsageCounters {
        input_tokens: input_tokens.unwrap_or(0),
        cache_creation_input_tokens: cache_creation_input_tokens.unwrap_or(0),
        cache_read_input_tokens: cache_read_input_tokens.unwrap_or(0),
        output_tokens: 0,
        cache_creation_5m_input_tokens: cache_creation_5m_input_tokens.unwrap_or(0),
        cache_creation_1h_input_tokens: cache_creation_1h_input_tokens.unwrap_or(0),
        presence: ClaudeCounterPresence {
            input_tokens: input_tokens.is_some(),
            cache_creation_input_tokens: cache_creation_input_tokens.is_some(),
            cache_read_input_tokens: cache_read_input_tokens.is_some(),
            output_tokens: false,
            cache_creation_5m_input_tokens: cache_creation_5m_input_tokens.is_some(),
            cache_creation_1h_input_tokens: cache_creation_1h_input_tokens.is_some(),
        },
    }
}

fn parse_result_usage(
    usage: &Map<String, Value>,
    failures: &mut BTreeSet<ClaudeCoverageFailure>,
) -> ClaudeUsageCounters {
    let mut required = |name: &str| match usage.get(name).and_then(Value::as_u64) {
        Some(value) => value,
        None => {
            failures.insert(if usage.contains_key(name) {
                ClaudeCoverageFailure::InvalidCounter
            } else {
                ClaudeCoverageFailure::MissingCounter
            });
            0
        }
    };
    let input_tokens = required("inputTokens");
    let cache_creation_input_tokens = required("cacheCreationInputTokens");
    let cache_read_input_tokens = required("cacheReadInputTokens");
    let output_tokens = required("outputTokens");
    ClaudeUsageCounters {
        input_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
        output_tokens,
        cache_creation_5m_input_tokens: 0,
        cache_creation_1h_input_tokens: 0,
        presence: ClaudeCounterPresence::default(),
    }
}

fn empty_collection(value: &Value) -> bool {
    value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(Map::is_empty)
        || value.is_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn line(value: Value) -> String {
        serde_json::to_string(&value).unwrap()
    }

    fn exact_stream(extra: impl IntoIterator<Item = Value>) -> Vec<u8> {
        let mut events = vec![json!({
            "type":"system","subtype":"init","session_id":"session-1",
            "tools":["Read","Glob","Grep","Edit","Write"],"mcp_servers":[]
        })];
        events.extend(extra);
        events
            .into_iter()
            .map(line)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    fn message_events(id: &str, model: &str) -> Vec<Value> {
        vec![
            json!({"type":"stream_event","session_id":"session-1","event":{
            "type":"message_start","message":{"id":id,"model":model,"usage":{
                "input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,
                "output_tokens":0,"cache_creation":{"ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":3}
            }}}}),
            json!({"type":"stream_event","session_id":"session-1","event":{"type":"message_delta","usage":{"output_tokens":7}}}),
            json!({"type":"stream_event","session_id":"session-1","event":{"type":"message_stop"}}),
            json!({"type":"assistant","session_id":"session-1","message":{"id":id,"model":model}}),
        ]
    }

    #[test]
    fn exact_native_stream_retains_identity_ids_presence_and_disjoint_cache_totals() {
        let mut events = message_events("msg-1", "claude-sonnet-4-5");
        events.push(json!({"type":"result","subtype":"success","is_error":false,
            "session_id":"session-1","num_turns":1,"result":"done",
            "modelUsage":{"claude-sonnet-4-5":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}}}));
        let evidence = collect_native_stream(&exact_stream(events), false);
        assert!(!evidence.complete(), "{:?}", evidence.failures);
        assert!(evidence
            .failures
            .contains(&ClaudeCoverageFailure::NativeCoverageWitnessMissing));
        assert_eq!(evidence.session_id.as_deref(), Some("session-1"));
        assert_eq!(
            evidence.observed_model.as_deref(),
            Some("claude-sonnet-4-5")
        );
        assert_eq!(evidence.messages[0].message_id, "msg-1");
        assert!(
            evidence.messages[0]
                .usage
                .presence
                .cache_creation_5m_input_tokens
        );
        assert!(
            evidence.messages[0]
                .usage
                .presence
                .cache_creation_1h_input_tokens
        );
        assert!(evidence.complete_usage().is_none());
        assert_eq!(evidence.usage_lower_bound().unwrap().input_tokens, 18);
        assert_eq!(evidence.usage_lower_bound().unwrap().output_tokens, 7);
        assert_eq!(evidence.usage_lower_bound().unwrap().total_tokens, 25);
    }

    #[test]
    fn incomplete_native_streams_keep_lower_bounds_and_never_claim_complete_coverage() {
        for failure in [
            "truncated",
            "duplicate",
            "compaction",
            "fallback",
            "missing",
        ] {
            let mut events = message_events("msg-1", "claude-sonnet-4-5");
            match failure {
                "duplicate" => events.insert(1, events[0].clone()),
                "compaction" => events.push(
                    json!({"type":"system","subtype":"compact_boundary","session_id":"session-1"}),
                ),
                "missing" => {
                    events.pop();
                }
                _ => {}
            }
            events.push(json!({"type":"result","subtype":"success","is_error":false,
                "session_id":"session-1","num_turns":1,"result":"partial",
                "modelUsage": if failure == "fallback" {
                    json!({"claude-sonnet-4-5":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7},"claude-haiku-4-5":{"inputTokens":0,"cacheCreationInputTokens":0,"cacheReadInputTokens":0,"outputTokens":0}})
                } else { json!({"claude-sonnet-4-5":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}}) }}));
            let evidence = collect_native_stream(&exact_stream(events), failure == "truncated");
            assert!(!evidence.complete(), "{failure}: {:?}", evidence.failures);
            assert!(evidence.complete_usage().is_none(), "{failure}");
            assert!(evidence.usage_lower_bound().is_some(), "{failure}");
        }
    }

    #[test]
    fn malformed_conflicting_and_overflow_counters_fail_closed() {
        let mut conflict = message_events("msg-1", "claude-sonnet-4-5");
        conflict[0]["event"]["message"]["usage"]["cache_creation"]["ephemeral_1h_input_tokens"] =
            json!(4);
        conflict.push(json!({"type":"result","subtype":"success","is_error":false,"session_id":"session-1","num_turns":1,"result":"x","modelUsage":{"claude-sonnet-4-5":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}}}));
        let evidence = collect_native_stream(&exact_stream(conflict), false);
        assert!(evidence
            .failures
            .contains(&ClaudeCoverageFailure::ConflictingCacheBuckets));

        let mut aggregate_conflict = message_events("msg-1", "claude-sonnet-4-5");
        aggregate_conflict.push(json!({"type":"result","subtype":"success","is_error":false,"session_id":"session-1","num_turns":1,"result":"x","modelUsage":{"claude-sonnet-4-5":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":8}}}));
        let aggregate_conflict = collect_native_stream(&exact_stream(aggregate_conflict), false);
        assert!(aggregate_conflict
            .failures
            .contains(&ClaudeCoverageFailure::AggregateCounterConflict));
        assert!(aggregate_conflict.usage_lower_bound().is_some());

        let bytes = exact_stream([
            json!({"type":"stream_event","session_id":"session-1","event":{
            "type":"message_start","message":{"id":"msg-1","model":"claude-sonnet-4-5","usage":{
                "input_tokens":u64::MAX,"cache_creation_input_tokens":1,"cache_read_input_tokens":0,
                "cache_creation":{"ephemeral_5m_input_tokens":1,"ephemeral_1h_input_tokens":0}
            }}}}),
        ]);
        let overflow = collect_native_stream(&bytes, true);
        assert!(overflow
            .failures
            .contains(&ClaudeCoverageFailure::CounterOverflow));
        assert!(!overflow.complete());

        let duplicate_input_tokens = br#"{"type":"stream_event","session_id":"session-1","event":{"type":"message_start","message":{"id":"msg-1","model":"claude-sonnet-4-5","usage":{"input_tokens":99,"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}}"#;
        let duplicate_input_tokens = collect_native_stream(duplicate_input_tokens, false);
        assert!(duplicate_input_tokens
            .failures
            .contains(&ClaudeCoverageFailure::DuplicateWireKey));
        assert!(duplicate_input_tokens.messages.is_empty());
    }

    fn broker_binding() -> ClaudeBrokerBinding {
        ClaudeBrokerBinding::new(
            "parent-nonce-1".to_string(),
            "launch-digest-1".to_string(),
            "selected-account-binding-1".to_string(),
            41,
            9_999_999,
            ClaudeTransportAuthMode::BareApiKey,
        )
        .unwrap()
    }

    fn broker_request(model: &str, tools: &[&str]) -> Vec<u8> {
        let tools = tools
            .iter()
            .map(|name| json!({"name":name,"input_schema":{"type":"object"}}))
            .collect::<Vec<_>>();
        let body = serde_json::to_vec(&json!({
            "model":model,
            "max_tokens":256,
            "stream":true,
            "messages":[{"role":"user","content":"synthetic"}],
            "tools":tools
        }))
        .unwrap();
        let mut request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: fake-key\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        request
    }

    fn broker_sse(id: &str, model: &str) -> Vec<u8> {
        let start = json!({"type":"message_start","message":{
            "id":id,"model":model,"usage":{
                "input_tokens":10,"cache_creation_input_tokens":5,
                "cache_read_input_tokens":3,"output_tokens":0,
                "cache_creation":{"ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":3}
            }
        }});
        let delta = json!({"type":"message_delta","usage":{"output_tokens":7}});
        let stop = json!({"type":"message_stop"});
        format!(
            "event: message_start\ndata: {}\n\nevent: message_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
            line(start),
            line(delta),
            line(stop)
        )
        .into_bytes()
    }

    #[test]
    fn parent_broker_terminates_head_and_seals_known_auxiliary_plus_primary_calls() {
        let binding = broker_binding();
        let grant =
            ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec()).unwrap();
        let mut broker = ClaudeParentBroker::new(grant);
        let mut forwarded = 0usize;
        let head = broker
            .handle_http(
                b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                |_| -> Result<ClaudeBrokerUpstreamResponse, String> {
                    panic!("HEAD must terminate locally")
                },
            )
            .unwrap();
        assert_eq!(head, LOCAL_HEAD_RESPONSE);
        let calls = [
            ("msg-aux", CLAUDE_MANAGED_AUXILIARY_MODEL, Vec::new()),
            ("msg-main-1", CLAUDE_MANAGED_PRIMARY_MODEL, vec!["Read"]),
            (
                "msg-main-2",
                CLAUDE_MANAGED_PRIMARY_MODEL,
                vec!["Edit", "Read"],
            ),
            ("msg-main-3", CLAUDE_MANAGED_PRIMARY_MODEL, vec!["Read"]),
        ];
        for (id, model, tools) in &calls {
            let response = broker
                .handle_http(&broker_request(model, tools), |request| {
                    assert_eq!(request.auth_mode(), ClaudeTransportAuthMode::BareApiKey);
                    assert_eq!(request.authorization_header_name(), "x-api-key");
                    assert_eq!(request.authorization_value(), b"fake-key");
                    assert!(!request.request_body().is_empty());
                    forwarded += 1;
                    Ok(ClaudeBrokerUpstreamResponse {
                        status: 200,
                        content_type: "text/event-stream".to_string(),
                        body: broker_sse(id, model),
                        truncated: false,
                    })
                })
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        }
        assert_eq!(forwarded, 4);
        let witness = broker.seal(ClaudeBrokerTerminalSeal {
            child_exit_observed: true,
            listener_closed: true,
            upstream_quiescent: true,
            interrupted: false,
        });

        let mut events = Vec::new();
        for id in ["msg-main-1", "msg-main-2", "msg-main-3"] {
            events.extend(message_events(id, CLAUDE_MANAGED_PRIMARY_MODEL));
        }
        events.push(json!({"type":"result","subtype":"success","is_error":false,
            "session_id":"session-1","num_turns":3,"result":"done","modelUsage":{
                (CLAUDE_MANAGED_PRIMARY_MODEL):{"inputTokens":30,"cacheCreationInputTokens":15,"cacheReadInputTokens":9,"outputTokens":21},
                (CLAUDE_MANAGED_AUXILIARY_MODEL):{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}
            }}));
        let mut evidence = collect_native_stream(&exact_stream(events), false);
        assert!(evidence
            .failures
            .contains(&ClaudeCoverageFailure::FallbackOrAuxiliaryModel));
        evidence.attach_whole_call_witness(&witness, &binding);
        assert!(evidence.complete(), "{:?}", evidence.failures);
        assert_eq!(evidence.complete_usage().unwrap().input_tokens, 72);
        assert_eq!(evidence.complete_usage().unwrap().output_tokens, 28);
        assert_eq!(evidence.complete_usage().unwrap().total_tokens, 100);
    }

    #[test]
    fn oauth_broker_grant_is_bearer_bound_and_debug_redacted() {
        let binding = ClaudeBrokerBinding::new(
            "parent-nonce-1".to_string(),
            "launch-digest-1".to_string(),
            "selected-account-binding-1".to_string(),
            41,
            9_999_999,
            ClaudeTransportAuthMode::OAuthBearer,
        )
        .unwrap();
        let grant = ClaudeTransportCredentialGrant::new(
            binding,
            b"fake-child-oauth-grant-for-relay".to_vec(),
        )
        .unwrap();
        assert_eq!(
            grant.authorization_value(),
            b"Bearer fake-child-oauth-grant-for-relay"
        );
        let debug = format!("{grant:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fake-child-oauth-grant-for-relay"));
        assert!(!debug.contains("selected-account-binding-1"));
        assert!(!debug.contains("parent-nonce-1"));
    }

    #[test]
    fn incomplete_broker_coverage_keeps_auxiliary_and_primary_counter_floors() {
        let binding = broker_binding();
        let grant =
            ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec()).unwrap();
        let mut broker = ClaudeParentBroker::new(grant);
        broker
            .handle_http(
                b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                |_| -> Result<ClaudeBrokerUpstreamResponse, String> { unreachable!() },
            )
            .unwrap();
        broker
            .handle_http(&broker_request(CLAUDE_MANAGED_AUXILIARY_MODEL, &[]), |_| {
                Ok(ClaudeBrokerUpstreamResponse {
                    status: 200,
                    content_type: "text/event-stream".to_string(),
                    body: broker_sse("msg-aux", CLAUDE_MANAGED_AUXILIARY_MODEL),
                    truncated: false,
                })
            })
            .unwrap();
        let partial_start = json!({"type":"message_start","message":{
            "id":"msg-main-1","model":CLAUDE_MANAGED_PRIMARY_MODEL,"usage":{
                "input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,
                "output_tokens":0,"cache_creation":{
                    "ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":3
                }
            }
        }});
        let refusal = broker
            .handle_http(
                &broker_request(CLAUDE_MANAGED_PRIMARY_MODEL, &["Read"]),
                |_| {
                    Ok(ClaudeBrokerUpstreamResponse {
                        status: 200,
                        content_type: "text/event-stream".to_string(),
                        body: format!("data: {}\n\n", line(partial_start)).into_bytes(),
                        truncated: true,
                    })
                },
            )
            .unwrap_err();
        assert!(refusal.contains("upstream response was incomplete"));
        let witness = broker.seal(ClaudeBrokerTerminalSeal {
            child_exit_observed: true,
            listener_closed: true,
            upstream_quiescent: true,
            interrupted: false,
        });

        let mut events = message_events("msg-main-1", CLAUDE_MANAGED_PRIMARY_MODEL);
        events.push(json!({"type":"result","subtype":"success","is_error":false,
            "session_id":"session-1","num_turns":1,"result":"done","modelUsage":{
                (CLAUDE_MANAGED_PRIMARY_MODEL):{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7},
                (CLAUDE_MANAGED_AUXILIARY_MODEL):{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}
            }}));
        let mut evidence = collect_native_stream(&exact_stream(events), false);
        evidence.attach_whole_call_witness(&witness, &binding);

        assert!(!evidence.complete());
        assert!(evidence.complete_usage().is_none());
        assert!(evidence
            .failures
            .contains(&ClaudeCoverageFailure::BrokerResponseCoverage));
        let lower_bound = evidence.usage_lower_bound().unwrap();
        assert_eq!(lower_bound.input_tokens, 36);
        assert_eq!(lower_bound.output_tokens, 14);
        assert_eq!(lower_bound.total_tokens, 50);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn truncated_upstream_http_keeps_complete_sse_event_prefix_for_private_accounting() {
        let start = json!({"type":"message_start","message":{
            "id":"msg-partial","model":CLAUDE_MANAGED_PRIMARY_MODEL,"usage":{
                "input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,
                "output_tokens":0,"cache_creation":{
                    "ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":3
                }
            }
        }});
        let body = format!("data: {}\n\n", line(start)).into_bytes();
        let mut http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
            body.len() + 64
        )
        .into_bytes();
        http.extend_from_slice(&body);
        let response = parse_upstream_http_response(&http, false).unwrap();
        assert!(response.truncated);
        assert!(broker_child_response(&response).is_err());
        let parsed = parse_broker_sse(&response.body);
        assert!(parsed.message.is_some());
        assert!(parsed
            .failures
            .contains(&ClaudeCoverageFailure::MessageNotStopped));
        let message = parsed.message.unwrap();
        assert_eq!(message.usage.input_tokens, 10);
        assert_eq!(message.usage.cache_creation_input_tokens, 5);
        assert_eq!(message.usage.cache_read_input_tokens, 3);
        assert!(!message.usage.presence.output_tokens);
    }

    #[test]
    fn invalid_utf8_tail_keeps_complete_sse_message_floor_and_marks_incomplete() {
        let mut body = broker_sse("msg-prefix", CLAUDE_MANAGED_PRIMARY_MODEL);
        body.extend_from_slice(&[0xf0, 0x9f, 0x92]);
        let parsed = parse_broker_sse(&body);
        assert!(parsed
            .failures
            .contains(&ClaudeCoverageFailure::BrokerResponseCoverage));
        let message = parsed.message.expect("complete SSE prefix message");
        assert_eq!(message.message_id, "msg-prefix");
        assert_eq!(message.usage.input_tokens, 10);
        assert_eq!(message.usage.cache_creation_input_tokens, 5);
        assert_eq!(message.usage.cache_read_input_tokens, 3);
        assert_eq!(message.usage.output_tokens, 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_later_chunk_keeps_prior_complete_payload_and_marks_incomplete() {
        let body = broker_sse("msg-chunk-prefix", CLAUDE_MANAGED_PRIMARY_MODEL);
        let mut framed = format!("{:x}\r\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        framed.extend_from_slice(b"\r\nnot-a-chunk-size\r\n");
        let (retained, truncated) = decode_http_chunks(&framed, true).unwrap();
        assert_eq!(retained, body);
        assert!(truncated);
    }

    #[test]
    fn repeated_message_id_uses_component_floors_once_and_keeps_conflict() {
        let binding = broker_binding();
        let grant =
            ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec()).unwrap();
        let mut broker = ClaudeParentBroker::new(grant);
        broker
            .handle_http(
                b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                |_| -> Result<ClaudeBrokerUpstreamResponse, String> { unreachable!() },
            )
            .unwrap();
        broker
            .handle_http(
                &broker_request(CLAUDE_MANAGED_PRIMARY_MODEL, &["Read"]),
                |_| {
                    Ok(ClaudeBrokerUpstreamResponse {
                        status: 200,
                        content_type: "text/event-stream".to_string(),
                        body: broker_sse("msg-repeat", CLAUDE_MANAGED_PRIMARY_MODEL),
                        truncated: false,
                    })
                },
            )
            .unwrap();
        let start = json!({"type":"message_start","message":{
            "id":"msg-repeat","model":CLAUDE_MANAGED_PRIMARY_MODEL,"usage":{
                "input_tokens":12,"cache_creation_input_tokens":5,"cache_read_input_tokens":8,
                "output_tokens":0,"cache_creation":{
                    "ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":5
                }
            }
        }});
        let delta = json!({"type":"message_delta","usage":{"output_tokens":6}});
        let stop = json!({"type":"message_stop"});
        let second = format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\n",
            line(start),
            line(delta),
            line(stop)
        )
        .into_bytes();
        broker
            .handle_http(
                &broker_request(CLAUDE_MANAGED_PRIMARY_MODEL, &["Read"]),
                |_| {
                    Ok(ClaudeBrokerUpstreamResponse {
                        status: 200,
                        content_type: "text/event-stream".to_string(),
                        body: second,
                        truncated: false,
                    })
                },
            )
            .unwrap();
        let witness = broker.seal(ClaudeBrokerTerminalSeal {
            child_exit_observed: true,
            listener_closed: true,
            upstream_quiescent: true,
            interrupted: false,
        });
        let summary = witness.summarize(&binding);
        assert!(summary
            .failures
            .contains(&ClaudeCoverageFailure::DuplicateMessage));
        assert_eq!(summary.messages.len(), 1);
        let usage = summary
            .usage_by_model
            .get(CLAUDE_MANAGED_PRIMARY_MODEL)
            .expect("primary component floor");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.cache_creation_input_tokens, 7);
        assert_eq!(usage.cache_read_input_tokens, 8);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.cache_creation_5m_input_tokens, 2);
        assert_eq!(usage.cache_creation_1h_input_tokens, 5);
    }

    #[test]
    fn parent_broker_refuses_unknown_or_authoritative_auxiliary_traffic() {
        let binding = broker_binding();
        let grant =
            ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec()).unwrap();
        let mut broker = ClaudeParentBroker::new(grant);
        let error = broker
            .handle_http(
                b"GET /unknown HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                |_| -> Result<ClaudeBrokerUpstreamResponse, String> {
                    panic!("unknown traffic must not be forwarded")
                },
            )
            .unwrap_err();
        assert!(error.contains("unsupported"));
        let error = broker
            .handle_http(
                &broker_request(CLAUDE_MANAGED_AUXILIARY_MODEL, &["Read"]),
                |_request| -> Result<ClaudeBrokerUpstreamResponse, String> {
                    panic!("authoritative auxiliary traffic must not be forwarded")
                },
            )
            .unwrap_err();
        assert!(error.contains("unqualified model or tool set"));
        let mut mixed_auth = broker_request(CLAUDE_MANAGED_PRIMARY_MODEL, &["Read"]);
        let header_end = mixed_auth
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        mixed_auth.splice(
            header_end..header_end,
            b"\r\nAuthorization: Bearer fake-oauth".iter().copied(),
        );
        let error = broker
            .handle_http(
                &mixed_auth,
                |_request| -> Result<ClaudeBrokerUpstreamResponse, String> {
                    panic!("mixed authorization must not be forwarded")
                },
            )
            .unwrap_err();
        assert!(error.contains("mixed OAuth and API-key"));
        let error = broker
            .handle_http(
                &broker_request("claude-unqualified-model", &[]),
                |_request| -> Result<ClaudeBrokerUpstreamResponse, String> {
                    panic!("unknown model traffic must not be forwarded")
                },
            )
            .unwrap_err();
        assert!(error.contains("unqualified model or tool set"));
        let witness = broker.seal(ClaudeBrokerTerminalSeal {
            child_exit_observed: true,
            listener_closed: true,
            upstream_quiescent: true,
            interrupted: false,
        });
        let summary = witness.summarize(&binding);
        assert!(summary
            .failures
            .contains(&ClaudeCoverageFailure::BrokerRequestCoverage));
        assert!(summary
            .failures
            .contains(&ClaudeCoverageFailure::FallbackOrAuxiliaryModel));

        let grant =
            ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec()).unwrap();
        let mut broker = ClaudeParentBroker::new(grant);
        broker
            .handle_http(
                b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                |_| -> Result<ClaudeBrokerUpstreamResponse, String> { unreachable!() },
            )
            .unwrap();
        broker
            .handle_http(
                &broker_request(CLAUDE_MANAGED_PRIMARY_MODEL, &["Read"]),
                |_| {
                    Ok(ClaudeBrokerUpstreamResponse {
                        status: 200,
                        content_type: "text/event-stream".to_string(),
                        body: broker_sse("msg-conflict", CLAUDE_MANAGED_AUXILIARY_MODEL),
                        truncated: false,
                    })
                },
            )
            .unwrap();
        let witness = broker.seal(ClaudeBrokerTerminalSeal {
            child_exit_observed: true,
            listener_closed: false,
            upstream_quiescent: true,
            interrupted: false,
        });
        let summary = witness.summarize(&binding);
        assert!(summary
            .failures
            .contains(&ClaudeCoverageFailure::ConflictingObservedModel));
        assert!(summary
            .failures
            .contains(&ClaudeCoverageFailure::BrokerRequestCoverage));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relay_peer_identity_binds_pid_start_cgroup_uid_and_program() {
        let (peer_stream, _other) = UnixStream::pair().unwrap();
        let peer = unix_peer_credentials(&peer_stream).unwrap();
        let identity = ClaudeRelayHelperIdentity {
            pid: peer.pid,
            start_ticks: process_start_ticks(peer.pid).unwrap(),
            cgroup: process_cgroup(peer.pid).unwrap(),
            unit: "test-helper.service".to_string(),
        };
        verify_registered_helper_peer(peer, &identity).unwrap();

        let mut wrong_start = identity.clone();
        wrong_start.start_ticks = wrong_start.start_ticks.saturating_add(1);
        assert!(verify_registered_helper_peer(peer, &wrong_start).is_err());
        let mut wrong_cgroup = identity;
        wrong_cgroup.cgroup.push_str("-foreign");
        assert!(verify_registered_helper_peer(peer, &wrong_cgroup).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_registration_requires_actual_containment_owner_before_ack() {
        let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cgroup = process_cgroup(std::process::id()).unwrap();
        let owner = crate::process_runner::ClaudeContainmentOwnerBinding::new();
        owner
            .bind(crate::process_runner::ClaudeContainmentOwnerIdentity {
                unit: "maco-process-test.service".to_string(),
                cgroup: cgroup.clone(),
            })
            .unwrap();
        let shutdown = AtomicBool::new(false);

        let (mut parent, mut helper) = UnixStream::pair().unwrap();
        let peer = unix_peer_credentials(&parent).unwrap();
        let start = process_start_ticks(peer.pid).unwrap();
        writeln!(
            helper,
            "{HELPER_REGISTRATION_PREFIX}\t{nonce}\t{}\t{start}\tmaco-process-test.service\t{cgroup}",
            peer.pid
        )
        .unwrap();
        helper.shutdown(std::net::Shutdown::Write).unwrap();
        let identity = register_helper_connection(
            &mut parent,
            peer,
            nonce,
            &owner,
            &shutdown,
            unix_millis_now().unwrap().saturating_add(1_000),
        )
        .unwrap();
        assert_eq!(identity.pid, peer.pid);
        assert_eq!(identity.start_ticks, start);
        assert_eq!(identity.cgroup, cgroup);
        let expected_acknowledgement = b"MACO-CLAUDE-HELPER-ACK-V1\n";
        let mut acknowledgement = vec![0; expected_acknowledgement.len()];
        helper.read_exact(&mut acknowledgement).unwrap();
        assert_eq!(acknowledgement.as_slice(), expected_acknowledgement);

        let (mut parent, mut helper) = UnixStream::pair().unwrap();
        let peer = unix_peer_credentials(&parent).unwrap();
        writeln!(
            helper,
            "{HELPER_REGISTRATION_PREFIX}\t{nonce}\t{}\t{}\tmaco-process-test.service\t{cgroup}",
            peer.pid,
            start.saturating_add(1)
        )
        .unwrap();
        helper.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(register_helper_connection(
            &mut parent,
            peer,
            nonce,
            &owner,
            &shutdown,
            unix_millis_now().unwrap().saturating_add(1_000),
        )
        .is_err());
        helper.set_nonblocking(true).unwrap();
        let mut acknowledgement = [0u8; 1];
        assert!(matches!(
            helper.read(&mut acknowledgement).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));

        let (mut parent, mut helper) = UnixStream::pair().unwrap();
        let peer = unix_peer_credentials(&parent).unwrap();
        writeln!(
            helper,
            "{HELPER_REGISTRATION_PREFIX}\t{nonce}\t{}\t{}\tforeign.service\t{cgroup}",
            peer.pid, start
        )
        .unwrap();
        helper.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(register_helper_connection(
            &mut parent,
            peer,
            nonce,
            &owner,
            &shutdown,
            unix_millis_now().unwrap().saturating_add(1_000),
        )
        .is_err());
        helper.set_nonblocking(true).unwrap();
        let mut acknowledgement = [0u8; 1];
        assert!(matches!(
            helper.read(&mut acknowledgement).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rear_startup_guard_stops_and_joins_before_returning_failure() {
        let (stop_tx, stop_rx) = mpsc::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&stopped);
        let handle = std::thread::spawn(move || {
            stop_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            observed.store(true, Ordering::Release);
            Ok(())
        });
        let guard = ClaudeRearStartupGuard::new(stop_tx, handle, Duration::from_secs(1));
        assert_eq!(guard.fail("startup failed".to_string()), "startup failed");
        assert!(stopped.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relay_write_refuses_cancelled_parent_without_emitting_bytes() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .set_write_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        reader.set_nonblocking(true).unwrap();
        let shutdown = AtomicBool::new(true);
        assert!(write_with_shutdown(
            &mut writer,
            b"must-not-be-written",
            &shutdown,
            unix_millis_now().unwrap().saturating_add(1_000),
            "test relay write",
        )
        .is_err());
        let mut byte = [0u8; 1];
        assert!(matches!(
            reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn managed_launch_contract_is_exact_and_primary_capability_stays_refused() {
        let config = RuntimeAdapterConfig::defaults_for(AdapterId::ClaudeCode);
        assert_eq!(
            config.binary.as_deref(),
            Some(Path::new(CLAUDE_NATIVE_EXECUTABLE))
        );
        assert!(admitted_native_executable(
            Path::new(CLAUDE_NATIVE_EXECUTABLE),
            CLAUDE_NATIVE_SHA256
        ));
        assert!(!admitted_native_executable(
            Path::new("/tmp/operator-claude"),
            CLAUDE_NATIVE_SHA256
        ));
        assert!(!admitted_native_executable(
            Path::new(CLAUDE_NATIVE_EXECUTABLE),
            "operator-supplied-digest"
        ));
        let cwd = std::env::current_dir().unwrap();
        let context = LaunchContext {
            prompt: std::path::Path::new("prompt"),
            model: Some(CLAUDE_MANAGED_PRIMARY_MODEL),
            effort: Some("high"),
            cwd: &cwd,
            output: std::path::Path::new("output"),
        };
        let contract = prove_managed_launch(&config, &context).expect("exact contract");
        assert_eq!(contract.auth_mode(), ClaudeAuthMode::BareApiKey);
        assert!(contract.capabilities().admits_worktree_writable());
        assert_eq!(
            contract.capabilities().writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        let mut drifted = config;
        drifted.argument_template.push("--add-dir".to_string());
        assert!(prove_managed_launch(&drifted, &context).is_none());
    }
}
