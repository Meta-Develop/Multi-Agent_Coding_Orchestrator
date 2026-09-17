//! HTTP transport and lifecycle for the local relay.
//!
//! This module owns only the network boundary. Dialect translation is injected
//! through [`RelayTranslator`], so the HTTP server never depends on a provider
//! adapter and streaming events can be translated without buffering a complete
//! response.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, RETRY_AFTER,
    TRANSFER_ENCODING, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use futures_util::stream::{self, Stream};
use futures_util::StreamExt;
use serde_json::json;
use subtle::ConstantTimeEq;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::{
    translate_request, translate_response, RelayConfig, SourceEvent,
    StreamTranslator as CoreStreamTranslator, TranslatedEvent, TranslatedRequest,
    TranslationContext, WireFormat,
};
use crate::error::{Error, Result};
use crate::model::{
    ProviderQuotaList, QuotaListError, QuotaListErrorKind, QuotaListOutcome, RelayStatus, RouteRule,
};
use crate::providers;
use crate::router::{validate_rules, RouteAccount, RouteError, RouteSelection, RouterState};
use crate::storage::Secret;

const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STREAM_EVENT_BYTES: usize = 1024 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

const PREFIXES: [&str; 6] = [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/images/generations",
    "/v1/messages",
    "/v1beta/models/*:generateContent",
    "/v1beta/models/*:streamGenerateContent",
];

const UPSTREAM_URL_ENV: &str = "CODING_AGENT_MANAGER_RELAY_UPSTREAM_URL";
const UPSTREAM_DIALECT_ENV: &str = "CODING_AGENT_MANAGER_RELAY_UPSTREAM_DIALECT";
const UPSTREAM_MODEL_ENV: &str = "CODING_AGENT_MANAGER_RELAY_UPSTREAM_MODEL";
const UPSTREAM_AUTH_HEADER_ENV: &str = "CODING_AGENT_MANAGER_RELAY_UPSTREAM_AUTH_HEADER";
const UPSTREAM_AUTH_TOKEN_ENV: &str = "CODING_AGENT_MANAGER_RELAY_UPSTREAM_AUTH_TOKEN";
const ROUTED_TARGET_ENV_PREFIX: &str = "CODING_AGENT_MANAGER_RELAY_TARGET_";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const ROUTE_FALLBACK_THROTTLE: TimeDuration = TimeDuration::seconds(60);
/// Translates the three independent protocol surfaces used by the transport.
///
/// Streaming creates one bounded, metadata-only session per upstream response.
/// The HTTP layer owns SSE decoding/framing and the session translates decoded
/// source events into zero or more target events without buffering content.
pub trait RelayTranslator: Send + Sync + 'static {
    fn request(
        &self,
        from: WireFormat,
        to: WireFormat,
        context: TranslationContext<'_>,
        body: &[u8],
    ) -> Result<TranslatedRequest>;

    fn response(&self, from: WireFormat, to: WireFormat, body: &[u8]) -> Result<Vec<u8>>;

    fn stream(&self, from: WireFormat, to: WireFormat) -> Box<dyn RelayStreamTranslator>;
}

/// One metadata-only translator session per upstream response.
pub trait RelayStreamTranslator: Send + 'static {
    fn translate(&mut self, event: SourceEvent<'_>) -> Result<Vec<TranslatedEvent>>;
}

/// Built-in adapter to the relay core's pure body translators and bounded
/// per-response streaming translator.
pub struct CoreTranslator;

impl RelayTranslator for CoreTranslator {
    fn request(
        &self,
        from: WireFormat,
        to: WireFormat,
        context: TranslationContext<'_>,
        body: &[u8],
    ) -> Result<TranslatedRequest> {
        translate_request(from, to, context, body)
    }

    fn response(&self, from: WireFormat, to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
        translate_response(from, to, body)
    }

    fn stream(&self, from: WireFormat, to: WireFormat) -> Box<dyn RelayStreamTranslator> {
        Box::new(CoreStreamTranslator::new(from, to))
    }
}

impl RelayStreamTranslator for CoreStreamTranslator {
    fn translate(&mut self, event: SourceEvent<'_>) -> Result<Vec<TranslatedEvent>> {
        CoreStreamTranslator::translate(self, event)
    }
}

/// Credential attached to the configured upstream request.
///
/// Deliberately implements neither `Debug`, `Display`, `Serialize`, nor
/// `Clone`. The shared storage-layer [`Secret`] remains the one greppable
/// secret representation; the relay never calls a credential store directly.
pub enum RelayUpstreamAuth {
    Bearer(Secret),
    Header { name: HeaderName, value: Secret },
}

impl RelayUpstreamAuth {
    pub fn bearer(secret: Secret) -> Self {
        Self::Bearer(secret)
    }

    pub fn header(name: &str, secret: Secret) -> Result<Self> {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| relay_error("upstream credential header name is invalid"))?;
        if is_hop_by_hop(&name) || name == HOST || name == CONTENT_LENGTH {
            return Err(relay_error(
                "upstream credential header name is not allowed",
            ));
        }
        let auth = Self::Header {
            name,
            value: secret,
        };
        validate_upstream_auth(&auth)?;
        Ok(auth)
    }
}

/// Fixed upstream chosen by the core routing/account layer.
///
/// Only a fixed, explicitly configured base URL is accepted. The server appends
/// a path chosen from the target dialect; it never appends the inbound path or
/// query, so a client cannot turn the relay into an open proxy. This type is
/// intentionally not serializable or debuggable; its optional credential must
/// never cross IPC or enter diagnostics.
pub struct RelayTarget {
    base_url: reqwest::Url,
    dialect: WireFormat,
    target_model: Option<String>,
    auth: Option<RelayUpstreamAuth>,
}

impl RelayTarget {
    pub fn new(endpoint: &str, dialect: WireFormat) -> Result<Self> {
        let base_url = reqwest::Url::parse(endpoint)
            .map_err(|_| relay_error("relay upstream endpoint is invalid"))?;
        validate_upstream_endpoint(&base_url)?;
        Ok(Self {
            base_url,
            dialect,
            target_model: None,
            auth: None,
        })
    }

    pub fn with_target_model(mut self, target_model: impl Into<String>) -> Result<Self> {
        let target_model = target_model.into();
        if target_model.trim().is_empty() {
            return Err(relay_error("relay target model must be nonempty"));
        }
        self.target_model = Some(target_model);
        Ok(self)
    }

    pub fn with_auth(mut self, auth: RelayUpstreamAuth) -> Result<Self> {
        validate_upstream_auth(&auth)?;
        self.auth = Some(auth);
        Ok(self)
    }

    fn from_environment() -> Result<Option<Self>> {
        let endpoint = match std::env::var(UPSTREAM_URL_ENV) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) | Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(relay_error("relay upstream endpoint is not Unicode"));
            }
        };
        let dialect = match std::env::var(UPSTREAM_DIALECT_ENV) {
            Ok(value) => parse_dialect(&value)?,
            Err(std::env::VarError::NotPresent) => {
                return Err(relay_error("relay upstream dialect is not configured"));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(relay_error("relay upstream dialect is not Unicode"));
            }
        };
        let mut target = Self::new(&endpoint, dialect)?;
        match std::env::var(UPSTREAM_MODEL_ENV) {
            Ok(model) if !model.is_empty() => target = target.with_target_model(model)?,
            Ok(_) | Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(relay_error("relay upstream model is not Unicode"));
            }
        }
        let auth_header = optional_environment_value(UPSTREAM_AUTH_HEADER_ENV)?;
        let auth_token = optional_environment_value(UPSTREAM_AUTH_TOKEN_ENV)?;
        target = apply_environment_auth(target, auth_header, auth_token)?;
        Ok(Some(target))
    }
}

/// One explicitly configured account target available to routing rules.
///
/// The account identity is non-secret, but the target can contain a credential,
/// so this binding deliberately implements neither `Debug` nor `Serialize`.
/// A rule selects the provider, and the router requires exactly one binding for
/// that provider before any request can be sent.
pub struct RoutedRelayTarget {
    provider_id: String,
    account_id: String,
    target: Arc<RelayTarget>,
}

impl RoutedRelayTarget {
    pub fn new(
        provider_id: impl Into<String>,
        account_id: impl Into<String>,
        target: RelayTarget,
    ) -> Result<Self> {
        let provider_id = provider_id.into();
        let account_id = account_id.into();
        if provider_id.trim().is_empty() || account_id.trim().is_empty() {
            return Err(relay_error(
                "routed relay target provider and account ids must be nonempty",
            ));
        }
        Ok(Self {
            provider_id,
            account_id,
            target: Arc::new(target),
        })
    }
}

/// Supplies one secret-free M4 quota snapshot for a routed request.
///
/// Implementations must return provider outcomes rather than fabricate a
/// utilization when no signal exists. The relay calls this exactly once per
/// request and the router validates every numeric snapshot before using it.
pub trait RelayQuotaSource: Send + Sync + 'static {
    fn snapshot(&self) -> Vec<ProviderQuotaList>;
}

/// Production quota source backed by the compiled provider registry.
pub struct AdapterQuotaSource;

impl RelayQuotaSource for AdapterQuotaSource {
    fn snapshot(&self) -> Vec<ProviderQuotaList> {
        providers::registry()
            .into_iter()
            .map(|adapter| quota_listing(adapter.id(), adapter.quota()))
            .collect()
    }
}

fn quota_listing(
    provider_id: &str,
    result: Result<Vec<crate::model::QuotaSnapshot>>,
) -> ProviderQuotaList {
    match result {
        Ok(snapshots) => ProviderQuotaList {
            provider_id: provider_id.to_owned(),
            plan_label: None,
            outcome: if snapshots.is_empty() {
                QuotaListOutcome::NoSignal
            } else {
                QuotaListOutcome::Available
            },
            snapshots,
        },
        Err(_) => ProviderQuotaList {
            provider_id: provider_id.to_owned(),
            plan_label: None,
            snapshots: Vec::new(),
            outcome: QuotaListOutcome::Failed {
                error: QuotaListError {
                    kind: QuotaListErrorKind::Other,
                    path: None,
                    message: "provider quota collection failed".to_owned(),
                },
            },
        },
    }
}

fn optional_environment_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(relay_error(
            "relay upstream environment value is not Unicode",
        )),
    }
}

fn apply_environment_auth(
    target: RelayTarget,
    header: Option<String>,
    token: Option<String>,
) -> Result<RelayTarget> {
    let Some(token) = token else {
        return if header.is_some() {
            Err(relay_error(
                "relay upstream auth header is set without an auth token",
            ))
        } else {
            Ok(target)
        };
    };
    if token.is_empty() {
        return Err(relay_error("relay upstream auth token must be nonempty"));
    }
    let secret = Secret::new(token.into_bytes());
    let auth = match header.as_deref() {
        None => RelayUpstreamAuth::bearer(secret),
        Some(name) if name.eq_ignore_ascii_case("authorization") => {
            RelayUpstreamAuth::bearer(secret)
        }
        Some(name) => RelayUpstreamAuth::header(name, secret)?,
    };
    target.with_auth(auth)
}

fn validate_upstream_endpoint(endpoint: &reqwest::Url) -> Result<()> {
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.path().ends_with('/')
    {
        return Err(relay_error(
            "relay upstream base URL must end in `/` and contain no credentials, query, or fragment",
        ));
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if endpoint_host_is_loopback(endpoint) => Ok(()),
        _ => Err(relay_error(
            "relay upstream endpoint must use HTTPS (HTTP is allowed only on loopback)",
        )),
    }
}

fn endpoint_host_is_loopback(endpoint: &reqwest::Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn parse_dialect(value: &str) -> Result<WireFormat> {
    match value {
        "openai-chat-completions" => Ok(WireFormat::OpenAiChatCompletions),
        "openai-responses" => Ok(WireFormat::OpenAiResponses),
        "openai-images-generations" => Ok(WireFormat::OpenAiImagesGenerations),
        "anthropic-messages" => Ok(WireFormat::AnthropicMessages),
        "gemini-generate-content" => Ok(WireFormat::GeminiGenerateContent),
        _ => Err(relay_error("relay upstream dialect is unknown")),
    }
}

fn routed_targets_from_environment(rules: &[RouteRule]) -> Result<Vec<RoutedRelayTarget>> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    for rule in rules {
        if !seen.insert(rule.provider_id.as_str()) {
            continue;
        }
        let key = routed_environment_key(&rule.provider_id)?;
        let name = |suffix: &str| format!("{ROUTED_TARGET_ENV_PREFIX}{key}_{suffix}");
        let endpoint = optional_environment_value(&name("URL"))?;
        let dialect = optional_environment_value(&name("DIALECT"))?;
        let account_id = optional_environment_value(&name("ACCOUNT_ID"))?;
        let auth_header = optional_environment_value(&name("AUTH_HEADER"))?;
        let auth_token = optional_environment_value(&name("AUTH_TOKEN"))?;

        if endpoint.is_none()
            && dialect.is_none()
            && account_id.is_none()
            && auth_header.is_none()
            && auth_token.is_none()
        {
            continue;
        }
        let (Some(endpoint), Some(dialect), Some(account_id)) = (endpoint, dialect, account_id)
        else {
            return Err(relay_error(
                "routed relay target environment configuration is partial",
            ));
        };
        if endpoint.is_empty() || dialect.is_empty() || account_id.trim().is_empty() {
            return Err(relay_error(
                "routed relay target environment configuration is incomplete",
            ));
        }

        let target = RelayTarget::new(&endpoint, parse_dialect(&dialect)?)?;
        let target = apply_environment_auth(target, auth_header, auth_token)?;
        targets.push(RoutedRelayTarget::new(
            rule.provider_id.clone(),
            account_id,
            target,
        )?);
    }
    Ok(targets)
}

fn routed_environment_key(provider_id: &str) -> Result<String> {
    if provider_id.len() > 64
        || provider_id.is_empty()
        || !provider_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(relay_error(
            "routed relay provider id is not a supported environment key",
        ));
    }
    Ok(provider_id.to_ascii_uppercase().replace('-', "_"))
}

fn route_configuration_error(error: RouteError) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, error))
}

enum RelayRequestMode {
    Fixed(Option<RelayTarget>),
    Routed(RoutedServerState),
}

struct RoutedServerState {
    rules: Vec<RouteRule>,
    accounts: Vec<RouteAccount>,
    targets: HashMap<(String, String), Arc<RelayTarget>>,
    quota_source: Arc<dyn RelayQuotaSource>,
    router: Mutex<RouterState>,
}

impl RoutedServerState {
    fn new(
        rules: Vec<RouteRule>,
        targets: Vec<RoutedRelayTarget>,
        quota_source: Arc<dyn RelayQuotaSource>,
    ) -> Result<Self> {
        validate_rules(&rules).map_err(route_configuration_error)?;

        let mut providers = HashSet::new();
        let mut accounts = Vec::with_capacity(targets.len());
        let mut target_map = HashMap::with_capacity(targets.len());
        for binding in targets {
            if !providers.insert(binding.provider_id.clone()) {
                return Err(relay_error(
                    "routed relay target configuration is ambiguous",
                ));
            }
            let account = RouteAccount {
                provider_id: binding.provider_id,
                account_id: binding.account_id,
            };
            target_map.insert(
                (account.provider_id.clone(), account.account_id.clone()),
                binding.target,
            );
            accounts.push(account);
        }

        if rules
            .iter()
            .any(|rule| !providers.contains(&rule.provider_id))
        {
            return Err(relay_error(
                "a routed relay rule has no configured account target",
            ));
        }

        Ok(Self {
            rules,
            accounts,
            targets: target_map,
            quota_source,
            router: Mutex::new(RouterState::default()),
        })
    }

    fn target(&self, selection: &RouteSelection) -> Option<Arc<RelayTarget>> {
        self.targets
            .get(&(selection.provider_id.clone(), selection.account_id.clone()))
            .cloned()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayModeKind {
    Fixed,
    Routed,
}

struct ServerState {
    mode: RelayRequestMode,
    translator: Arc<dyn RelayTranslator>,
    client: reqwest::Client,
    relay_auth_token: Option<Secret>,
}

/// One independently owned listener. Tests use this directly with an
/// ephemeral port; the desktop-facing functions below own one global instance.
pub struct RelayServer {
    status: RelayStatus,
    mode: RelayModeKind,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl RelayServer {
    pub async fn start(
        config: RelayConfig,
        target: Option<RelayTarget>,
        translator: Arc<dyn RelayTranslator>,
    ) -> Result<Self> {
        Self::start_with_mode(
            config,
            RelayRequestMode::Fixed(target),
            RelayModeKind::Fixed,
            translator,
        )
        .await
    }

    /// Start a listener whose upstream attempts come only from explicit rules.
    ///
    /// Every provider named by a rule must resolve to exactly one identity-
    /// bearing target before the socket is bound. Extra targets are inert; they
    /// cannot become an implicit fallback.
    pub async fn start_routed(
        config: RelayConfig,
        rules: Vec<RouteRule>,
        targets: Vec<RoutedRelayTarget>,
        quota_source: Arc<dyn RelayQuotaSource>,
        translator: Arc<dyn RelayTranslator>,
    ) -> Result<Self> {
        let routed = RoutedServerState::new(rules, targets, quota_source)?;
        Self::start_with_mode(
            config,
            RelayRequestMode::Routed(routed),
            RelayModeKind::Routed,
            translator,
        )
        .await
    }

    async fn start_with_mode(
        config: RelayConfig,
        mode: RelayRequestMode,
        mode_kind: RelayModeKind,
        translator: Arc<dyn RelayTranslator>,
    ) -> Result<Self> {
        let bind_address = validate_listener_config(&config)?;
        let listener = TcpListener::bind((bind_address, config.port)).await?;
        let local_address = listener.local_addr()?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| relay_error("relay upstream client could not be initialized"))?;
        let state = Arc::new(ServerState {
            mode,
            translator,
            client,
            relay_auth_token: config.auth_token.map(String::into_bytes).map(Secret::new),
        });
        let app = Router::new()
            .fallback(any(handle_request))
            .with_state(state);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .map_err(|_| relay_error("relay listener stopped unexpectedly"))
        });
        Ok(Self {
            status: RelayStatus {
                running: true,
                bind_address: local_address.ip().to_string(),
                port: local_address.port(),
                prefixes: relay_prefixes(),
            },
            mode: mode_kind,
            shutdown: Some(shutdown),
            task,
        })
    }

    pub fn status(&self) -> RelayStatus {
        let mut status = self.status.clone();
        status.running = !self.task.is_finished();
        status
    }

    pub async fn stop(mut self) -> Result<RelayStatus> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let result = tokio::select! {
            joined = &mut self.task => joined,
            () = tokio::time::sleep(SHUTDOWN_GRACE) => {
                self.task.abort();
                (&mut self.task).await
            }
        };
        match result {
            Ok(server_result) => server_result?,
            Err(join_error) if join_error.is_cancelled() => {}
            Err(_) => return Err(relay_error("relay listener task failed")),
        }
        self.status.running = false;
        Ok(self.status.clone())
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

fn relay_instance() -> &'static Mutex<Option<RelayServer>> {
    static INSTANCE: OnceLock<Mutex<Option<RelayServer>>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new(None))
}

/// Start the desktop relay with the safe loopback default.
///
/// The optional upstream endpoint/dialect/model and runtime-only credential
/// come from process configuration. None is serialized into [`RelayStatus`].
/// If the target is absent, the listener starts but returns an explicit 503
/// instead of silently selecting an account or vendor.
pub async fn start_relay() -> Result<RelayStatus> {
    let mut relay = relay_instance().lock().await;
    if let Some(server) = relay.as_ref() {
        if !server.task.is_finished() {
            return if server.mode == RelayModeKind::Fixed {
                Ok(server.status())
            } else {
                Err(relay_error(
                    "the relay must be stopped before changing routing mode",
                ))
            };
        }
    }
    if let Some(stopped) = relay.take() {
        drop(stopped);
    }
    let target = RelayTarget::from_environment()?;
    let server =
        RelayServer::start(RelayConfig::default(), target, Arc::new(CoreTranslator)).await?;
    let status = server.status();
    *relay = Some(server);
    Ok(status)
}

/// Start the desktop-core relay in explicit rule-driven mode.
///
/// Targets are loaded only from provider-namespaced process environment
/// configuration. The legacy singleton target variables are intentionally not
/// consulted, so they can never become an implicit fallback.
pub async fn start_routed_relay(rules: Vec<RouteRule>) -> Result<RelayStatus> {
    let mut relay = relay_instance().lock().await;
    if let Some(server) = relay.as_ref() {
        if !server.task.is_finished() {
            return Err(relay_error(
                "the relay must be stopped before changing routed configuration",
            ));
        }
    }
    if let Some(stopped) = relay.take() {
        drop(stopped);
    }

    let targets = routed_targets_from_environment(&rules)?;
    let server = RelayServer::start_routed(
        RelayConfig::default(),
        rules,
        targets,
        Arc::new(AdapterQuotaSource),
        Arc::new(CoreTranslator),
    )
    .await?;
    let status = server.status();
    *relay = Some(server);
    Ok(status)
}

/// Stop the desktop relay. Repeated stops are harmless.
pub async fn stop_relay() -> Result<RelayStatus> {
    let server = relay_instance().lock().await.take();
    match server {
        Some(server) => server.stop().await,
        None => Ok(stopped_status()),
    }
}

/// Return only the listener state that is safe to serialize to the webview.
pub async fn relay_status() -> Result<RelayStatus> {
    let relay = relay_instance().lock().await;
    Ok(relay
        .as_ref()
        .map_or_else(stopped_status, RelayServer::status))
}

fn stopped_status() -> RelayStatus {
    let config = RelayConfig::default();
    RelayStatus {
        running: false,
        bind_address: config.bind_address,
        port: config.port,
        prefixes: relay_prefixes(),
    }
}

fn relay_prefixes() -> Vec<String> {
    PREFIXES
        .iter()
        .map(|prefix| (*prefix).to_string())
        .collect()
}

fn validate_listener_config(config: &RelayConfig) -> Result<IpAddr> {
    config.validate()?;
    let bind_address = config
        .bind_address
        .parse::<IpAddr>()
        .map_err(|_| relay_error("relay bind address must be an IP address"))?;
    let auth_token = config.auth_token.as_deref();
    if !bind_address.is_loopback() && auth_token.is_none_or(|token| token.trim().is_empty()) {
        return Err(Error::CredentialStoreUnavailable(
            "a non-loopback relay binding requires a nonempty auth token".to_string(),
        ));
    }
    if let Some(token) = auth_token {
        bearer_header_value(token)?;
    }
    Ok(bind_address)
}

async fn handle_request(State(state): State<Arc<ServerState>>, request: Request) -> Response<Body> {
    if !request_is_authorized(&state, request.headers()) {
        return unauthorized();
    }
    if request.method() != Method::POST {
        let mut response = json_error(StatusCode::METHOD_NOT_ALLOWED, "relay accepts POST only");
        response
            .headers_mut()
            .insert(axum::http::header::ALLOW, HeaderValue::from_static("POST"));
        return response;
    }
    let inbound = match route_for_path(request.uri().path()) {
        Some(route) => route,
        None => return json_error(StatusCode::NOT_FOUND, "unknown relay path"),
    };

    match &state.mode {
        RelayRequestMode::Fixed(target) => {
            handle_fixed_request(&state, request, inbound, target.as_ref()).await
        }
        RelayRequestMode::Routed(routed) => {
            handle_routed_request(&state, routed, request, inbound).await
        }
    }
}

async fn handle_fixed_request(
    state: &ServerState,
    request: Request,
    inbound: InboundRoute,
    target: Option<&RelayTarget>,
) -> Response<Body> {
    let Some(target) = target else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay target is not configured",
        );
    };

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "relay request body is too large",
            )
        }
    };
    let translated = match state.translator.request(
        inbound.dialect,
        target.dialect,
        TranslationContext {
            source_model: inbound.source_model.as_deref(),
            target_model: target.target_model.as_deref(),
            source_stream: inbound.source_stream,
        },
        &body,
    ) {
        Ok(translated) => translated,
        Err(error) => return translation_error(error),
    };
    let endpoint = match upstream_endpoint(
        target,
        translated.target_model.as_deref(),
        translated.stream,
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => return translation_error(error),
    };
    let mut outbound = state
        .client
        .request(parts.method, endpoint)
        .body(translated.body);
    let headers = outbound_headers(
        &parts.headers,
        state.relay_auth_token.is_some(),
        inbound.dialect,
        target,
    );
    outbound = outbound.headers(headers);
    let upstream = match outbound.send().await {
        Ok(response) => response,
        Err(_) => return json_error(StatusCode::BAD_GATEWAY, "relay upstream request failed"),
    };
    upstream_response(state, inbound.dialect, target.dialect, upstream).await
}

async fn handle_routed_request(
    state: &ServerState,
    routed: &RoutedServerState,
    request: Request,
    inbound: InboundRoute,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "relay request body is too large",
            )
        }
    };
    let inbound_model = match routed_inbound_model(&inbound, &body) {
        Ok(model) => model,
        Err(error) => return translation_error(error),
    };
    let quotas = routed.quota_source.snapshot();
    let mut start_index = 0;
    let mut last_rate_limit = None;

    loop {
        let now = OffsetDateTime::now_utc();
        let selection = {
            let mut router = routed.router.lock().await;
            router.select_next(
                &routed.rules,
                &routed.accounts,
                &quotas,
                &inbound_model,
                start_index,
                now,
            )
        };
        let selection = match selection {
            Ok(selection) => selection,
            Err(error) => {
                return last_rate_limit.unwrap_or_else(|| routed_selection_error(error));
            }
        };
        let Some(target) = routed.target(&selection) else {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "selected routing target is unavailable",
            );
        };

        let translated = match state.translator.request(
            inbound.dialect,
            target.dialect,
            TranslationContext {
                source_model: inbound.source_model.as_deref(),
                target_model: Some(&selection.target_model),
                source_stream: inbound.source_stream,
            },
            &body,
        ) {
            Ok(translated) => translated,
            Err(error) => return translation_error(error),
        };
        let endpoint = match upstream_endpoint(
            &target,
            translated.target_model.as_deref(),
            translated.stream,
        ) {
            Ok(endpoint) => endpoint,
            Err(error) => return translation_error(error),
        };
        let headers = routed_outbound_headers(&parts.headers, target.as_ref());
        let upstream = match state
            .client
            .request(parts.method.clone(), endpoint)
            .headers(headers)
            .body(translated.body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return json_error(StatusCode::BAD_GATEWAY, "relay upstream request failed"),
        };

        if upstream.status() != StatusCode::TOO_MANY_REQUESTS {
            return upstream_response(state, inbound.dialect, target.dialect, upstream).await;
        }

        let observed_at = OffsetDateTime::now_utc();
        let deadline = rate_limit_deadline(upstream.headers(), &selection, observed_at);
        let response = upstream_error(upstream.status(), upstream.headers());
        {
            let mut router = routed.router.lock().await;
            router.record_rate_limit(&selection, deadline);
        }
        start_index = selection.rule_index.saturating_add(1);
        last_rate_limit = Some(response);
    }
}

fn routed_inbound_model(inbound: &InboundRoute, body: &[u8]) -> Result<String> {
    if let Some(model) = inbound.source_model.as_deref() {
        if !model.trim().is_empty() {
            return Ok(model.to_owned());
        }
    } else if let Ok(serde_json::Value::Object(root)) = serde_json::from_slice(body) {
        if let Some(model) = root
            .get("model")
            .and_then(serde_json::Value::as_str)
            .filter(|model| !model.trim().is_empty())
        {
            return Ok(model.to_owned());
        }
    }
    Err(relay_error(
        "routed relay request must contain a nonempty model",
    ))
}

fn routed_selection_error(error: RouteError) -> Response<Body> {
    let status = if error == RouteError::UnmatchedModel {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json_error(status, &error.to_string())
}

fn request_is_authorized(state: &ServerState, headers: &HeaderMap) -> bool {
    state
        .relay_auth_token
        .as_ref()
        .is_none_or(|expected| bearer_matches(headers, expected.expose()))
}

fn bearer_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(actual) = headers.get(AUTHORIZATION).map(HeaderValue::as_bytes) else {
        return false;
    };
    let Some((scheme, token)) = actual.split_at_checked(6) else {
        return false;
    };
    scheme.eq_ignore_ascii_case(b"Bearer")
        && token.first() == Some(&b' ')
        && token[1..].ct_eq(expected).into()
}

#[derive(Debug, PartialEq, Eq)]
struct InboundRoute {
    dialect: WireFormat,
    source_model: Option<String>,
    source_stream: bool,
}

fn route_for_path(path: &str) -> Option<InboundRoute> {
    match path {
        "/v1/chat/completions" => Some(inbound_route(WireFormat::OpenAiChatCompletions)),
        "/v1/responses" => Some(inbound_route(WireFormat::OpenAiResponses)),
        "/v1/images/generations" => Some(inbound_route(WireFormat::OpenAiImagesGenerations)),
        "/v1/messages" => Some(inbound_route(WireFormat::AnthropicMessages)),
        _ => gemini_route_from_path(path).map(|(source_model, source_stream)| InboundRoute {
            dialect: WireFormat::GeminiGenerateContent,
            source_model: Some(source_model.to_string()),
            source_stream,
        }),
    }
}

fn inbound_route(dialect: WireFormat) -> InboundRoute {
    InboundRoute {
        dialect,
        source_model: None,
        source_stream: false,
    }
}

fn gemini_route_from_path(path: &str) -> Option<(&str, bool)> {
    let model_and_action = path.strip_prefix("/v1beta/models/")?;
    let (model, source_stream) = model_and_action
        .strip_suffix(":generateContent")
        .map(|model| (model, false))
        .or_else(|| {
            model_and_action
                .strip_suffix(":streamGenerateContent")
                .map(|model| (model, true))
        })?;
    (!model.is_empty()).then_some((model, source_stream))
}

fn upstream_endpoint(
    target: &RelayTarget,
    target_model: Option<&str>,
    stream: bool,
) -> Result<reqwest::Url> {
    let mut endpoint = target.base_url.clone();
    let mut segments = endpoint
        .path_segments_mut()
        .map_err(|_| relay_error("relay upstream base URL cannot be used for paths"))?;
    segments.pop_if_empty();
    match target.dialect {
        WireFormat::OpenAiChatCompletions => {
            segments.extend(["v1", "chat", "completions"]);
        }
        WireFormat::OpenAiResponses => {
            segments.extend(["v1", "responses"]);
        }
        WireFormat::OpenAiImagesGenerations => {
            segments.extend(["v1", "images", "generations"]);
        }
        WireFormat::AnthropicMessages => {
            segments.extend(["v1", "messages"]);
        }
        WireFormat::GeminiGenerateContent => {
            let model = target_model
                .filter(|model| !model.is_empty())
                .ok_or_else(|| relay_error("Gemini target model is missing after translation"))?;
            let action = if stream {
                "streamGenerateContent"
            } else {
                "generateContent"
            };
            let model_and_action = format!("{model}:{action}");
            segments.extend(["v1beta", "models", model_and_action.as_str()]);
        }
    };
    drop(segments);
    if target.dialect == WireFormat::GeminiGenerateContent && stream {
        endpoint.query_pairs_mut().append_pair("alt", "sse");
    }
    Ok(endpoint)
}

fn outbound_headers(
    inbound: &HeaderMap,
    relay_auth_used: bool,
    inbound_dialect: WireFormat,
    target: &RelayTarget,
) -> HeaderMap {
    let mut outbound = HeaderMap::new();
    for (name, value) in inbound {
        if is_hop_by_hop(name)
            || name == HOST
            || name == CONTENT_LENGTH
            || (relay_auth_used && name == AUTHORIZATION)
            || ((target.auth.is_some() || inbound_dialect != target.dialect)
                && is_vendor_auth_header(name))
        {
            continue;
        }
        outbound.append(name.clone(), value.clone());
    }
    if let Some(auth) = &target.auth {
        apply_upstream_auth(&mut outbound, auth);
    }
    outbound
        .entry(CONTENT_TYPE)
        .or_insert(HeaderValue::from_static("application/json"));
    if target.dialect == WireFormat::AnthropicMessages {
        outbound
            .entry(HeaderName::from_static("anthropic-version"))
            .or_insert(HeaderValue::from_static(ANTHROPIC_VERSION));
    }
    outbound
}

fn routed_outbound_headers(inbound: &HeaderMap, target: &RelayTarget) -> HeaderMap {
    let mut outbound = HeaderMap::new();
    for (name, value) in inbound {
        if is_hop_by_hop(name)
            || name == HOST
            || name == CONTENT_LENGTH
            || is_routed_account_selector(name)
        {
            continue;
        }
        outbound.append(name.clone(), value.clone());
    }
    if let Some(auth) = &target.auth {
        apply_upstream_auth(&mut outbound, auth);
    }
    outbound
        .entry(CONTENT_TYPE)
        .or_insert(HeaderValue::from_static("application/json"));
    if target.dialect == WireFormat::AnthropicMessages {
        outbound
            .entry(HeaderName::from_static("anthropic-version"))
            .or_insert(HeaderValue::from_static(ANTHROPIC_VERSION));
    }
    outbound
}

fn is_routed_account_selector(name: &HeaderName) -> bool {
    is_vendor_auth_header(name)
        || name == COOKIE
        || name == "openai-organization"
        || name == "openai-project"
        || name == "anthropic-organization"
        || name == "x-goog-user-project"
        || name == "x-goog-quota-user"
        || name == "x-goog-request-params"
        || name == "x-organization-id"
        || name == "x-project-id"
}

fn is_vendor_auth_header(name: &HeaderName) -> bool {
    name == AUTHORIZATION || name == "x-api-key" || name == "x-goog-api-key"
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == TRANSFER_ENCODING
        || name == "keep-alive"
        || name == "proxy-authenticate"
        || name == "proxy-authorization"
        || name == "te"
        || name == "trailer"
        || name == "upgrade"
}

fn validate_upstream_auth(auth: &RelayUpstreamAuth) -> Result<()> {
    match auth {
        RelayUpstreamAuth::Bearer(secret) => {
            let mut value = Zeroizing::new(Vec::with_capacity(7 + secret.expose().len()));
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(secret.expose());
            HeaderValue::from_bytes(&value)
                .map_err(|_| relay_error("upstream credential contains invalid header bytes"))?;
        }
        RelayUpstreamAuth::Header { value, .. } => {
            HeaderValue::from_bytes(value.expose())
                .map_err(|_| relay_error("upstream credential contains invalid header bytes"))?;
        }
    }
    Ok(())
}

fn apply_upstream_auth(headers: &mut HeaderMap, auth: &RelayUpstreamAuth) {
    match auth {
        RelayUpstreamAuth::Bearer(secret) => {
            let mut value = Zeroizing::new(Vec::with_capacity(7 + secret.expose().len()));
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(secret.expose());
            let value = HeaderValue::from_bytes(&value)
                .expect("RelayTarget validates upstream credential header values");
            headers.insert(AUTHORIZATION, value);
        }
        RelayUpstreamAuth::Header { name, value } => {
            let value = HeaderValue::from_bytes(value.expose())
                .expect("RelayTarget validates upstream credential header values");
            headers.insert(name.clone(), value);
        }
    }
}

async fn upstream_response(
    state: &ServerState,
    inbound: WireFormat,
    upstream_dialect: WireFormat,
    upstream: reqwest::Response,
) -> Response<Body> {
    let status = upstream.status();
    if !status.is_success() {
        return upstream_error(status, upstream.headers());
    }

    let headers = response_headers(upstream.headers());
    let is_event_stream = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));

    if inbound == upstream_dialect {
        let stream = upstream.bytes_stream().map(|item| {
            item.map_err(|_| io::Error::other("relay upstream response stream failed"))
        });
        return build_response(status, headers, Body::from_stream(stream));
    }

    if is_event_stream {
        let stream = translate_sse(
            upstream.bytes_stream(),
            upstream_dialect,
            state.translator.stream(upstream_dialect, inbound),
        );
        return build_response(status, headers, Body::from_stream(stream));
    }

    let body = match collect_limited(upstream.bytes_stream(), MAX_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return *error,
    };
    match state.translator.response(upstream_dialect, inbound, &body) {
        Ok(body) => build_response(status, headers, Body::from(body)),
        Err(error) => translation_error(error),
    }
}

async fn collect_limited<S>(
    stream: S,
    limit: usize,
) -> std::result::Result<Vec<u8>, Box<Response<Body>>>
where
    S: Stream<Item = std::result::Result<Bytes, reqwest::Error>>,
{
    let mut stream = Box::pin(stream);
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            Box::new(json_error(
                StatusCode::BAD_GATEWAY,
                "relay upstream response stream failed",
            ))
        })?;
        if output.len().saturating_add(chunk.len()) > limit {
            return Err(Box::new(json_error(
                StatusCode::BAD_GATEWAY,
                "relay upstream response body is too large to translate",
            )));
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

struct SseState<S> {
    upstream: Pin<Box<S>>,
    buffer: Vec<u8>,
    upstream_dialect: WireFormat,
    translator: Box<dyn RelayStreamTranslator>,
    pending: VecDeque<Bytes>,
    upstream_done: bool,
    terminal_seen: bool,
}

fn translate_sse<S>(
    upstream: S,
    upstream_dialect: WireFormat,
    translator: Box<dyn RelayStreamTranslator>,
) -> impl Stream<Item = std::result::Result<Bytes, io::Error>>
where
    S: Stream<Item = std::result::Result<Bytes, reqwest::Error>>,
{
    let state = SseState {
        upstream: Box::pin(upstream),
        buffer: Vec::new(),
        upstream_dialect,
        translator,
        pending: VecDeque::new(),
        upstream_done: false,
        terminal_seen: false,
    };
    stream::unfold(state, |mut state| async move {
        loop {
            if let Some(output) = state.pending.pop_front() {
                return Some((Ok(output), state));
            }
            if let Some(event) = take_sse_event(&mut state.buffer) {
                if let Some(source) = parse_sse_event(&event) {
                    state.terminal_seen |= source.terminal;
                    if let Err(error) = queue_translated_events(&mut state, &source) {
                        return Some((Err(error), state));
                    }
                } else {
                    state.pending.push_back(Bytes::from(event));
                }
                continue;
            }
            if state.upstream_done {
                if !state.buffer.is_empty() {
                    let event = std::mem::take(&mut state.buffer);
                    if let Some(source) = parse_sse_event(&event) {
                        state.terminal_seen |= source.terminal;
                        if let Err(error) = queue_translated_events(&mut state, &source) {
                            return Some((Err(error), state));
                        }
                    } else {
                        state.pending.push_back(Bytes::from(event));
                    }
                    continue;
                }
                if state.upstream_dialect == WireFormat::GeminiGenerateContent
                    && !state.terminal_seen
                {
                    state.terminal_seen = true;
                    let terminal = ParsedSseEvent {
                        event_name: None,
                        data: Vec::new(),
                        terminal: true,
                    };
                    if let Err(error) = queue_translated_events(&mut state, &terminal) {
                        return Some((Err(error), state));
                    }
                    continue;
                }
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    if state.buffer.len().saturating_add(chunk.len()) > MAX_STREAM_EVENT_BYTES {
                        return Some((
                            Err(io::Error::other("relay stream event is too large")),
                            state,
                        ));
                    }
                    state.buffer.extend_from_slice(&chunk);
                }
                Some(Err(_)) => {
                    return Some((
                        Err(io::Error::other("relay upstream response stream failed")),
                        state,
                    ));
                }
                None => state.upstream_done = true,
            }
        }
    })
}

fn queue_translated_events<S>(
    state: &mut SseState<S>,
    source: &ParsedSseEvent,
) -> std::result::Result<(), io::Error> {
    let translated = state
        .translator
        .translate(SourceEvent {
            event_name: source.event_name.as_deref(),
            data: &source.data,
            terminal: source.terminal,
        })
        .map_err(|_| io::Error::other("relay stream event translation failed"))?;
    state.pending.extend(
        translated
            .into_iter()
            .filter_map(frame_translated_event)
            .map(Bytes::from),
    );
    Ok(())
}

struct ParsedSseEvent {
    event_name: Option<String>,
    data: Vec<u8>,
    terminal: bool,
}

fn parse_sse_event(event: &[u8]) -> Option<ParsedSseEvent> {
    let normalized = String::from_utf8_lossy(event).replace("\r\n", "\n");
    let mut event_name = None;
    let mut data = Vec::new();
    for line in normalized.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_name = Some(value.strip_prefix(' ').unwrap_or(value).to_string());
            continue;
        }
        let Some(value) = line.strip_prefix("data:") else {
            continue;
        };
        if !data.is_empty() {
            data.push(b'\n');
        }
        data.extend_from_slice(value.strip_prefix(' ').unwrap_or(value).as_bytes());
    }
    if data.is_empty() {
        return None;
    }
    let terminal = data == b"[DONE]" || event_name.as_deref() == Some("message_stop");
    Some(ParsedSseEvent {
        event_name,
        data,
        terminal,
    })
}

fn frame_translated_event(event: TranslatedEvent) -> Option<Vec<u8>> {
    if event.terminal && event.data.is_empty() && event.event_name.is_none() {
        return None;
    }
    if event.data.is_empty() && event.event_name.is_none() {
        return None;
    }
    let mut framed = Vec::with_capacity(event.data.len() + 32);
    if let Some(event_name) = event.event_name {
        framed.extend_from_slice(b"event: ");
        framed.extend_from_slice(event_name.as_bytes());
        framed.push(b'\n');
    }
    for line in event.data.split(|byte| *byte == b'\n') {
        framed.extend_from_slice(b"data: ");
        framed.extend_from_slice(line);
        framed.push(b'\n');
    }
    framed.push(b'\n');
    Some(framed)
}

fn take_sse_event(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    // SSE permits LF and CRLF. Events are intentionally small and capped above;
    // a linear scan keeps this parser dependency-free.
    let (end, delimiter_len) = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (position, 4))
        .or_else(|| {
            buffer
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| (position, 2))
        })?;
    let rest = buffer.split_off(end + delimiter_len);
    Some(std::mem::replace(buffer, rest))
}

fn response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in upstream {
        if !is_hop_by_hop(name) && name != CONTENT_LENGTH {
            headers.append(name.clone(), value.clone());
        }
    }
    headers
}

fn upstream_error(status: StatusCode, upstream_headers: &HeaderMap) -> Response<Body> {
    let mut response = json_error(status, "relay upstream returned an error");
    if let Some(retry_after) = upstream_headers.get("retry-after").filter(|value| {
        let value = value.as_bytes();
        !value.is_empty() && value.len() <= 20 && value.iter().all(u8::is_ascii_digit)
    }) {
        response
            .headers_mut()
            .insert("retry-after", retry_after.clone());
    }
    response
}

fn rate_limit_deadline(
    headers: &HeaderMap,
    selection: &RouteSelection,
    observed_at: OffsetDateTime,
) -> OffsetDateTime {
    let retry_after = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| observed_at.checked_add(TimeDuration::seconds(seconds)));
    let quota_reset = selection
        .quota_resets_at
        .filter(|reset| *reset > observed_at);

    match (retry_after, quota_reset) {
        (Some(retry_after), Some(quota_reset)) => retry_after.max(quota_reset),
        (Some(retry_after), None) => retry_after,
        (None, Some(quota_reset)) => quota_reset,
        (None, None) => observed_at + ROUTE_FALLBACK_THROTTLE,
    }
}

fn build_response(status: StatusCode, headers: HeaderMap, body: Body) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn unauthorized() -> Response<Body> {
    let mut response = json_error(StatusCode::UNAUTHORIZED, "relay authentication required");
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn translation_error(error: Error) -> Response<Body> {
    json_error(StatusCode::BAD_REQUEST, &error.to_string())
}

fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::to_vec(&json!({ "error": { "message": message } }))
        .expect("static relay error envelope serializes");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn bearer_header_value(token: &str) -> Result<HeaderValue> {
    let mut value = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(token.as_bytes());
    HeaderValue::from_bytes(&value)
        .map_err(|_| relay_error("relay auth token contains invalid header bytes"))
}

fn relay_error(message: &'static str) -> Error {
    Error::Io(io::Error::other(message))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::http::Request as HttpRequest;
    use axum::routing::post;
    use tokio::sync::oneshot;

    use super::*;

    struct MarkerTranslator {
        stream_events: Arc<AtomicUsize>,
    }

    impl MarkerTranslator {
        fn new() -> Self {
            Self {
                stream_events: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl RelayTranslator for MarkerTranslator {
        fn request(
            &self,
            _from: WireFormat,
            _to: WireFormat,
            context: TranslationContext<'_>,
            body: &[u8],
        ) -> Result<TranslatedRequest> {
            let input: serde_json::Value = serde_json::from_slice(body)?;
            Ok(TranslatedRequest {
                body: serde_json::to_vec(&json!({
                    "translatedRequest": input,
                    "sourceModel": context.source_model,
                    "targetModel": context.target_model,
                }))?,
                target_model: context.target_model.map(str::to_string),
                stream: context.source_stream,
            })
        }

        fn response(&self, _from: WireFormat, _to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
            let input: serde_json::Value = serde_json::from_slice(body)?;
            Ok(serde_json::to_vec(&json!({ "translatedResponse": input }))?)
        }

        fn stream(&self, _from: WireFormat, _to: WireFormat) -> Box<dyn RelayStreamTranslator> {
            Box::new(MarkerStreamTranslator {
                stream_events: Arc::clone(&self.stream_events),
            })
        }
    }

    struct MarkerStreamTranslator {
        stream_events: Arc<AtomicUsize>,
    }

    impl RelayStreamTranslator for MarkerStreamTranslator {
        fn translate(&mut self, event: SourceEvent<'_>) -> Result<Vec<TranslatedEvent>> {
            let number = self.stream_events.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(vec![TranslatedEvent {
                event_name: Some("translated".to_string()),
                data: serde_json::to_vec(&json!({
                    "event": number,
                    "inputBytes": event.data.len(),
                }))?,
                terminal: event.terminal,
            }])
        }
    }

    #[test]
    fn only_documented_paths_select_a_dialect() {
        assert_eq!(
            route_for_path("/v1/chat/completions"),
            Some(inbound_route(WireFormat::OpenAiChatCompletions))
        );
        assert_eq!(
            route_for_path("/v1/responses"),
            Some(inbound_route(WireFormat::OpenAiResponses))
        );
        assert_eq!(
            route_for_path("/v1/images/generations"),
            Some(inbound_route(WireFormat::OpenAiImagesGenerations))
        );
        assert_eq!(
            route_for_path("/v1/messages"),
            Some(inbound_route(WireFormat::AnthropicMessages))
        );
        assert_eq!(
            route_for_path("/v1beta/models/gemini-2.5-pro:generateContent"),
            Some(InboundRoute {
                dialect: WireFormat::GeminiGenerateContent,
                source_model: Some("gemini-2.5-pro".to_string()),
                source_stream: false,
            })
        );
        assert_eq!(
            route_for_path("/v1beta/models/gemini-2.5-flash:streamGenerateContent"),
            Some(InboundRoute {
                dialect: WireFormat::GeminiGenerateContent,
                source_model: Some("gemini-2.5-flash".to_string()),
                source_stream: true,
            })
        );
        for unknown in [
            "/v1/chat/completions/",
            "/v1/messages/extra",
            "/v1/images/generations/",
            "/v1beta/models/:generateContent",
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent/",
        ] {
            assert_eq!(route_for_path(unknown), None, "accepted `{unknown}`");
        }
    }

    #[test]
    fn gemini_upstream_path_carries_model_stream_action_and_sse_query() {
        let target = RelayTarget::new(
            "https://relay-upstream.invalid/",
            WireFormat::GeminiGenerateContent,
        )
        .unwrap();
        let endpoint = upstream_endpoint(&target, Some("gemini-FAKE/model"), true).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://relay-upstream.invalid/v1beta/models/gemini-FAKE%2Fmodel:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn sse_done_sentinel_is_marked_terminal_without_losing_its_data() {
        let event = parse_sse_event(b"data: [DONE]\n\n").unwrap();
        assert!(event.terminal);
        assert_eq!(event.data, b"[DONE]");
    }

    #[test]
    fn invalid_environment_credential_error_never_contains_the_value() {
        let target = RelayTarget::new(
            "https://relay-upstream.invalid/",
            WireFormat::OpenAiResponses,
        )
        .unwrap();
        let secret = "FAKE-invalid\nupstream-token";
        let result = apply_environment_auth(target, None, Some(secret.to_string()));
        match result {
            Ok(_) => panic!("invalid credential header value was accepted"),
            Err(error) => assert!(!error.to_string().contains(secret)),
        }
    }

    #[test]
    fn routed_rate_limit_deadline_uses_later_known_reset_and_explicit_fallback() {
        let observed_at = OffsetDateTime::UNIX_EPOCH;
        let mut selection = RouteSelection {
            rule_index: 0,
            provider_id: "provider-FAKE".to_owned(),
            account_id: "account-FAKE".to_owned(),
            target_model: "model-FAKE".to_owned(),
            quota_resets_at: Some(observed_at + TimeDuration::seconds(90)),
        };
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("30"));
        assert_eq!(
            rate_limit_deadline(&headers, &selection, observed_at),
            observed_at + TimeDuration::seconds(90),
            "later M4 reset must win"
        );

        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(
            rate_limit_deadline(&headers, &selection, observed_at),
            observed_at + TimeDuration::seconds(120),
            "later Retry-After must win"
        );

        selection.quota_resets_at = None;
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-delay"));
        assert_eq!(
            rate_limit_deadline(&headers, &selection, observed_at),
            observed_at + TimeDuration::seconds(60),
            "unknown reset must use the documented conservative fallback"
        );
    }

    #[tokio::test]
    async fn exposed_listener_refuses_missing_or_empty_auth_before_bind() {
        for auth_token in [None, Some(String::new()), Some("   ".to_string())] {
            let result = RelayServer::start(
                RelayConfig {
                    bind_address: "0.0.0.0".to_string(),
                    port: 0,
                    auth_token,
                },
                None,
                Arc::new(CoreTranslator),
            )
            .await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn exposed_listener_enforces_bearer_token_on_every_request() {
        let token = "FAKE-relay-token";
        let server = RelayServer::start(
            RelayConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 0,
                auth_token: Some(token.to_string()),
            },
            None,
            Arc::new(CoreTranslator),
        )
        .await
        .unwrap();
        let endpoint = format!("http://127.0.0.1:{}/v1/messages", server.status().port);
        let client = reqwest::Client::new();

        let missing = client.post(&endpoint).body("{}").send().await.unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = client
            .post(&endpoint)
            .bearer_auth("FAKE-wrong-token")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert!(!wrong.text().await.unwrap().contains(token));
        let accepted = client
            .post(&endpoint)
            .bearer_auth(token)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::SERVICE_UNAVAILABLE);

        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn listener_starts_reports_paths_rejects_unknown_and_stops() {
        let server = RelayServer::start(ephemeral_loopback(), None, Arc::new(CoreTranslator))
            .await
            .unwrap();
        let running = server.status();
        assert!(running.running);
        assert_ne!(running.port, 0);
        assert_eq!(running.prefixes, relay_prefixes());
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/unknown", running.port))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response
            .text()
            .await
            .unwrap()
            .contains("unknown relay path"));
        let stopped = server.stop().await.unwrap();
        assert!(!stopped.running);
    }

    #[tokio::test]
    async fn fake_upstream_receives_translated_body_and_injected_credential() {
        let (received_tx, received_rx) = oneshot::channel();
        let (upstream_url, upstream_stop, upstream_task) = fake_upstream(received_tx).await;
        let target = RelayTarget::new(&upstream_url, WireFormat::AnthropicMessages)
            .unwrap()
            .with_target_model("claude-FAKE")
            .unwrap();
        let target = apply_environment_auth(
            target,
            Some("authorization".to_string()),
            Some("FAKE-upstream-token".to_string()),
        )
        .unwrap();
        let server = RelayServer::start(
            ephemeral_loopback(),
            Some(target),
            Arc::new(MarkerTranslator::new()),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                server.status().port
            ))
            .bearer_auth("FAKE-client-token")
            .header(CONTENT_TYPE, "application/json")
            .body(r#"{"prompt":"hello"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body: serde_json::Value =
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(
            response_body,
            json!({ "translatedResponse": { "upstream": "ok" } })
        );
        let received = received_rx.await.unwrap();
        assert_eq!(
            received.body,
            json!({
                "translatedRequest": { "prompt": "hello" },
                "sourceModel": null,
                "targetModel": "claude-FAKE",
            })
        );
        assert_eq!(received.authorization, "Bearer FAKE-upstream-token");
        assert_eq!(received.anthropic_version, ANTHROPIC_VERSION);
        assert_eq!(received.content_type, "application/json");

        server.stop().await.unwrap();
        let _ = upstream_stop.send(());
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn cross_dialect_request_does_not_forward_the_clients_credential() {
        let (received_tx, received_rx) = oneshot::channel();
        let (upstream_url, upstream_stop, upstream_task) = fake_upstream(received_tx).await;
        let target = RelayTarget::new(&upstream_url, WireFormat::AnthropicMessages).unwrap();
        let server = RelayServer::start(
            ephemeral_loopback(),
            Some(target),
            Arc::new(MarkerTranslator::new()),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                server.status().port
            ))
            .bearer_auth("FAKE-client-token-must-not-cross")
            .header(CONTENT_TYPE, "application/json")
            .body(r#"{"prompt":"hello"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(received_rx.await.unwrap().authorization.is_empty());

        server.stop().await.unwrap();
        let _ = upstream_stop.send(());
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn cross_dialect_rate_limit_preserves_status_without_echoing_vendor_body() {
        let upstream_body =
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#;
        let (upstream_url, upstream_stop, upstream_task) =
            fake_error_upstream(StatusCode::TOO_MANY_REQUESTS, upstream_body, None).await;
        let target = RelayTarget::new(&upstream_url, WireFormat::AnthropicMessages).unwrap();
        let server = RelayServer::start(
            ephemeral_loopback(),
            Some(target),
            Arc::new(MarkerTranslator::new()),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                server.status().port
            ))
            .header(CONTENT_TYPE, "application/json")
            .body(r#"{"prompt":"hello"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get("retry-after").unwrap(), "17");
        assert!(response.headers().get("x-upstream-request-id").is_none());
        let response_body = response.text().await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response_body).unwrap(),
            json!({ "error": { "message": "relay upstream returned an error" } })
        );
        assert!(!response_body.contains("slow down"));

        server.stop().await.unwrap();
        let _ = upstream_stop.send(());
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn same_dialect_vendor_error_cannot_echo_the_clients_credential() {
        let token = "FAKE-client-vendor-token";
        let upstream_body = r#"{"type":"invalid_request_error","echo":"FAKE-client-vendor-token"}"#;
        let (upstream_url, upstream_stop, upstream_task) =
            fake_error_upstream(StatusCode::BAD_REQUEST, upstream_body, Some(token)).await;
        let target = RelayTarget::new(&upstream_url, WireFormat::AnthropicMessages).unwrap();
        let server = RelayServer::start(
            ephemeral_loopback(),
            Some(target),
            Arc::new(MarkerTranslator::new()),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/v1/messages",
                server.status().port
            ))
            .header("x-api-key", token)
            .header(CONTENT_TYPE, "application/json")
            .body(r#"{"prompt":"hello"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("x-debug-credential").is_none());
        let response_body = response.text().await.unwrap();
        assert!(!response_body.contains(token));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response_body).unwrap(),
            json!({ "error": { "message": "relay upstream returned an error" } })
        );

        server.stop().await.unwrap();
        let _ = upstream_stop.send(());
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn sse_is_translated_one_event_at_a_time() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let app = Router::new().route(
            "/v1/messages",
            post(|| async {
                let chunks: [std::result::Result<Bytes, io::Error>; 2] = [
                    Ok(Bytes::from_static(b"event: first\ndata: 1\n\n")),
                    Ok(Bytes::from_static(b"event: second\ndata: 2\n\n")),
                ];
                Response::builder()
                    .header(CONTENT_TYPE, "text/event-stream; charset=utf-8")
                    .body(Body::from_stream(stream::iter(chunks)))
                    .unwrap()
            }),
        );
        let upstream_task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let translator = Arc::new(MarkerTranslator::new());
        let target =
            RelayTarget::new(&format!("http://{address}/"), WireFormat::AnthropicMessages).unwrap();
        let server = RelayServer::start(ephemeral_loopback(), Some(target), translator.clone())
            .await
            .unwrap();

        let response = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                server.status().port
            ))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.unwrap(),
            "event: translated\ndata: {\"event\":1,\"inputBytes\":1}\n\nevent: translated\ndata: {\"event\":2,\"inputBytes\":1}\n\n"
        );
        assert_eq!(translator.stream_events.load(Ordering::SeqCst), 2);

        server.stop().await.unwrap();
        let _ = shutdown.send(());
        upstream_task.await.unwrap();
    }

    struct ReceivedRequest {
        body: serde_json::Value,
        authorization: String,
        anthropic_version: String,
        content_type: String,
    }

    async fn non_stream_upstream(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<ReceivedRequest>>>>>,
        request: HttpRequest<Body>,
    ) -> Response<Body> {
        let authorization = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let anthropic_version = request
            .headers()
            .get("anthropic-version")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap();
        let body = serde_json::from_slice(&body).unwrap();
        if let Some(sender) = sender.lock().await.take() {
            let _ = sender.send(ReceivedRequest {
                body,
                authorization,
                anthropic_version,
                content_type,
            });
        }
        Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"upstream":"ok"}"#))
            .unwrap()
    }

    async fn fake_upstream(
        sender: oneshot::Sender<ReceivedRequest>,
    ) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(Some(sender)));
        let app = Router::new()
            .route("/v1/messages", post(non_stream_upstream))
            .with_state(state);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{address}/"), shutdown, task)
    }

    async fn fake_error_upstream(
        status: StatusCode,
        body: &'static str,
        echoed_credential: Option<&'static str>,
    ) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/messages",
            post(move || async move {
                let mut response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "application/json")
                    .header("x-upstream-request-id", "FAKE-request-id")
                    .header("retry-after", "17");
                if let Some(credential) = echoed_credential {
                    response = response.header("x-debug-credential", credential);
                }
                response.body(Body::from(body)).unwrap()
            }),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{address}/"), shutdown, task)
    }

    fn ephemeral_loopback() -> RelayConfig {
        RelayConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 0,
            auth_token: None,
        }
    }
}
