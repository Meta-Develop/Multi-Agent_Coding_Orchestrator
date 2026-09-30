//! Shared explicit login lifecycle for managed accounts (MACO integration §5).
//!
//! Gemini, Codex, Claude, and Grok OAuth share the handle / idempotency /
//! cancel path. Cursor and GitHub Copilot stay allow-listed on `login.start`
//! and `NotImplemented` at the production port. Legacy synchronous
//! `add_managed_account` remains unchanged.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::account_authority::PendingLoginLease;
use crate::error::{Error, Result};
use crate::model::{AuthKind, StoredAccountMetadata};
use crate::providers::{
    claude_code::ClaudeCodeAdapter, codex_cli::CodexCliAdapter, complete_managed_login_account,
    gemini_cli::GeminiCliAdapter, grok_cli::GrokCliAdapter, OAuthLoginRunError,
    PendingOAuthHomePlan, PreparedPendingOAuthHome, ProviderAdapter, StoredAccountRegistry,
    LOGIN_DEADLINE,
};

/// Adapter seams used by [`LoginService::start`]: identity, pending-home
/// prepare, task clone, finish, and the existing OAuth run helper.
pub(crate) trait PendingOAuthLogin: ProviderAdapter + Send + Sync + 'static {
    fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome>;
    fn clone_for_login_task(&self) -> Self
    where
        Self: Sized;
    fn finish_pending_oauth_login(&self, home: &Path) -> Result<()>;
    fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        cancel: tokio::sync::watch::Receiver<bool>,
        handoff: Option<LoginUrlHandoff>,
    ) -> impl std::future::Future<Output = std::result::Result<(), OAuthLoginRunError>> + Send;
}

impl PendingOAuthLogin for GeminiCliAdapter {
    fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        GeminiCliAdapter::prepare_pending_oauth_home(self, account)
    }

    fn clone_for_login_task(&self) -> Self {
        GeminiCliAdapter::clone_for_login_task(self)
    }

    fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        GeminiCliAdapter::finish_pending_oauth_login(self, home)
    }

    async fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        cancel: tokio::sync::watch::Receiver<bool>,
        handoff: Option<LoginUrlHandoff>,
    ) -> std::result::Result<(), OAuthLoginRunError> {
        match handoff {
            Some(handoff) => {
                self.run_pending_oauth_login_with_handoff(home, plan, cancel, handoff)
                    .await
            }
            None => GeminiCliAdapter::run_pending_oauth_login(self, home, plan, cancel).await,
        }
    }
}

impl PendingOAuthLogin for CodexCliAdapter {
    fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        CodexCliAdapter::prepare_pending_oauth_home(self, account)
    }

    fn clone_for_login_task(&self) -> Self {
        CodexCliAdapter::clone_for_login_task(self)
    }

    fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        CodexCliAdapter::finish_pending_oauth_login(self, home)
    }

    fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        cancel: tokio::sync::watch::Receiver<bool>,
        _handoff: Option<LoginUrlHandoff>,
    ) -> impl std::future::Future<Output = std::result::Result<(), OAuthLoginRunError>> + Send {
        CodexCliAdapter::run_pending_oauth_login(self, home, plan, cancel)
    }
}

impl PendingOAuthLogin for ClaudeCodeAdapter {
    fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        ClaudeCodeAdapter::prepare_pending_oauth_home(self, account)
    }

    fn clone_for_login_task(&self) -> Self {
        ClaudeCodeAdapter::clone_for_login_task(self)
    }

    fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        ClaudeCodeAdapter::finish_pending_oauth_login(self, home)
    }

    fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        cancel: tokio::sync::watch::Receiver<bool>,
        _handoff: Option<LoginUrlHandoff>,
    ) -> impl std::future::Future<Output = std::result::Result<(), OAuthLoginRunError>> + Send {
        ClaudeCodeAdapter::run_pending_oauth_login(self, home, plan, cancel)
    }
}

impl PendingOAuthLogin for GrokCliAdapter {
    fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        GrokCliAdapter::prepare_pending_oauth_home(self, account)
    }

    fn clone_for_login_task(&self) -> Self {
        GrokCliAdapter::clone_for_login_task(self)
    }

    fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        GrokCliAdapter::finish_pending_oauth_login(self, home)
    }

    fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        cancel: tokio::sync::watch::Receiver<bool>,
        _handoff: Option<LoginUrlHandoff>,
    ) -> impl std::future::Future<Output = std::result::Result<(), OAuthLoginRunError>> + Send {
        GrokCliAdapter::run_pending_oauth_login(self, home, plan, cancel)
    }
}

/// Opaque login handle. Never encodes provider or account identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LoginHandle(String);

/// Account binding returned with every handle and required on status/cancel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginAccountBinding {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
}

/// Closed login lifecycle states from MACO integration §5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginState {
    WaitingForUser,
    InProgress,
    Ready,
    Cancelled,
    Failed,
    Unknown,
}

/// Sanitized status for one login handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    pub handle: LoginHandle,
    pub binding: LoginAccountBinding,
    pub state: LoginState,
    /// Present only for terminal failure; never contains secrets or raw vendor output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Browser ownership for an explicit login. Existing callers remain automatic.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginBrowserMode {
    #[default]
    Automatic,
    CallerManaged,
}

/// Public authorization handoff, returned only for a live bound login.
/// The OAuth code, PKCE verifier and tokens never enter this value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginAuthorization {
    pub authorization_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

pub(crate) struct ActiveLoginAuthorization {
    pub public: LoginAuthorization,
    pub valid_until: Instant,
}

/// In-memory producer capability bound to one operation, never the registry.
pub(crate) struct LoginUrlHandoff {
    publish: Box<dyn Fn(Option<ActiveLoginAuthorization>) -> bool + Send + Sync>,
}

impl LoginUrlHandoff {
    pub(crate) fn new(
        publish: impl Fn(Option<ActiveLoginAuthorization>) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            publish: Box::new(publish),
        }
    }

    pub(crate) fn publish(&self, authorization: ActiveLoginAuthorization) -> bool {
        (self.publish)(Some(authorization))
    }

    pub(crate) fn invalidate(&self) {
        (self.publish)(None);
    }
}

impl Drop for LoginUrlHandoff {
    fn drop(&mut self) {
        self.invalidate();
    }
}

/// Input for starting a managed-account login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStartRequest {
    pub provider_id: String,
    pub account_id: String,
    pub label: String,
    pub auth_kind: AuthKind,
    pub idempotency_key: String,
}

/// Caller-owned login lifecycle service. On drop, active operations receive a
/// shutdown cancel signal; owned async work keeps its pending-login lease until
/// it settles and terminalizes state without aborting in-flight callbacks.
pub struct LoginService {
    registry: StoredAccountRegistry,
    runtime: Handle,
    operation_retain: Duration,
    inner: Mutex<LoginServiceInner>,
}

struct LoginServiceInner {
    operations: HashMap<LoginHandle, Arc<LoginOperation>>,
    idempotency: HashMap<String, IdempotencyRecord>,
    tasks: HashMap<LoginHandle, JoinHandle<()>>,
}

struct IdempotencyRecord {
    fingerprint: RequestFingerprint,
    handle: LoginHandle,
    binding: Option<LoginAccountBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestFingerprint {
    provider_id: String,
    account_id: String,
    label: String,
    auth_kind: AuthKind,
    browser_mode: LoginBrowserMode,
}

struct LoginOperation {
    binding: LoginAccountBinding,
    cancel_tx: tokio::sync::watch::Sender<bool>,
    expire_cancel_sent: AtomicBool,
    state: Mutex<OperationState>,
    started_at: Instant,
    browser_mode: LoginBrowserMode,
}

struct OperationState {
    public: LoginState,
    failure_reason: Option<String>,
    finished_at: Option<Instant>,
    authorization: Option<ActiveLoginAuthorization>,
}

/// Retain finished operations for status recovery. Bound follows the provider's
/// [`LOGIN_DEADLINE`] plus a short post-deadline recovery window.
const OPERATION_RETAIN: Duration = Duration::from_secs(LOGIN_DEADLINE.as_secs() + 120);

impl LoginService {
    pub fn new(registry: StoredAccountRegistry, runtime: Handle) -> Self {
        Self::with_operation_retain(registry, runtime, OPERATION_RETAIN)
    }

    /// Test-only control of in-memory status retention bounds.
    #[doc(hidden)]
    pub fn with_operation_retain(
        registry: StoredAccountRegistry,
        runtime: Handle,
        operation_retain: Duration,
    ) -> Self {
        Self {
            registry,
            runtime,
            operation_retain,
            inner: Mutex::new(LoginServiceInner {
                operations: HashMap::new(),
                idempotency: HashMap::new(),
                tasks: HashMap::new(),
            }),
        }
    }

    /// Begin Gemini, Codex, Claude, or Grok OAuth login for a new pending
    /// account, or replay an idempotent start request.
    pub fn start(
        &self,
        request: LoginStartRequest,
        adapter: &GeminiCliAdapter,
    ) -> Result<LoginStatus> {
        self.start_pending_oauth(request, adapter)
    }

    /// Explicit Gemini browser handoff; automatic remains the legacy default.
    pub fn start_with_browser_mode(
        &self,
        request: LoginStartRequest,
        adapter: &GeminiCliAdapter,
        browser_mode: LoginBrowserMode,
    ) -> Result<LoginStatus> {
        self.start_pending_oauth_with_browser_mode(request, adapter, browser_mode)
    }

    pub(crate) fn start_pending_oauth<A: PendingOAuthLogin>(
        &self,
        request: LoginStartRequest,
        adapter: &A,
    ) -> Result<LoginStatus> {
        self.start_pending_oauth_with_browser_mode(request, adapter, LoginBrowserMode::Automatic)
    }

    fn start_pending_oauth_with_browser_mode<A: PendingOAuthLogin>(
        &self,
        request: LoginStartRequest,
        adapter: &A,
        browser_mode: LoginBrowserMode,
    ) -> Result<LoginStatus> {
        validate_start_request(&request)?;
        if browser_mode == LoginBrowserMode::CallerManaged && request.provider_id != "gemini-cli" {
            return Err(Error::NotImplemented("caller-managed browser login"));
        }
        // github-copilot is allow-listed; PendingOAuthLogin is not implemented.
        if request.provider_id == "github-copilot" {
            return Err(Error::NotImplemented("login.start"));
        }
        if request.provider_id != adapter.id() {
            return Err(Error::UnknownProvider(request.provider_id));
        }
        if request.auth_kind != AuthKind::OAuth {
            return Err(login_refused(
                &request.provider_id,
                "only OAuth login is supported in this release",
            ));
        }
        let fingerprint = RequestFingerprint::from(&request, browser_mode);
        self.reap_expired();

        let replay = {
            let inner = self.inner.lock().expect("login lock");
            match inner.idempotency.get(&request.idempotency_key) {
                Some(record) if record.fingerprint != fingerprint => {
                    return Err(login_refused(
                        &request.provider_id,
                        "idempotency key was reused with a different login request",
                    ));
                }
                Some(record) => {
                    if let Some(binding) = record.binding.clone() {
                        Some((record.handle.clone(), binding))
                    } else {
                        return Err(Error::AccountAuthorityBusy {
                            reason: "login start is already in progress for this idempotency key"
                                .to_string(),
                        });
                    }
                }
                None => None,
            }
        };
        if let Some((handle, binding)) = replay {
            return self.status(&handle, &binding);
        }

        let plan = adapter
            .managed_account_plan_for(AuthKind::OAuth)
            .ok_or(Error::NotImplemented("login.start"))?;
        let handle = new_login_handle()?;
        {
            let mut inner = self.inner.lock().expect("login lock");
            if inner.idempotency.contains_key(&request.idempotency_key) {
                return Err(Error::AccountAuthorityBusy {
                    reason: "login start is already in progress for this idempotency key"
                        .to_string(),
                });
            }
            inner.idempotency.insert(
                request.idempotency_key.clone(),
                IdempotencyRecord {
                    fingerprint: fingerprint.clone(),
                    handle: handle.clone(),
                    binding: None,
                },
            );
        }

        let account = match self.registry.begin_add(
            &request.provider_id,
            &request.account_id,
            &request.label,
            plan.auth_kind,
            plan.material,
        ) {
            Ok(account) => account,
            Err(error) => {
                self.remove_idempotency_key(&request.idempotency_key);
                return Err(error);
            }
        };
        let binding = LoginAccountBinding {
            provider_id: account.provider_id.clone(),
            account_id: account.id.clone(),
            account_incarnation: account.account_incarnation.clone(),
        };

        let pending_lease = match self.registry.acquire_pending_login_lease(
            &account.provider_id,
            &account.id,
            &account.account_incarnation,
            account.auth_kind,
            account.material,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.remove_idempotency_key(&request.idempotency_key);
                return Err(error);
            }
        };

        let prepared = match adapter.prepare_pending_oauth_home(&account) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.remove_idempotency_key(&request.idempotency_key);
                return Err(error);
            }
        };
        let home = prepared.path;
        let oauth_plan = prepared.plan;

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let operation = Arc::new(LoginOperation {
            binding: binding.clone(),
            cancel_tx,
            expire_cancel_sent: AtomicBool::new(false),
            state: Mutex::new(OperationState {
                public: LoginState::WaitingForUser,
                failure_reason: None,
                finished_at: None,
                authorization: None,
            }),
            started_at: Instant::now(),
            browser_mode,
        });

        {
            let mut inner = self.inner.lock().expect("login lock");
            if let Some(record) = inner.idempotency.get_mut(&request.idempotency_key) {
                record.binding = Some(binding.clone());
            }
            inner
                .operations
                .insert(handle.clone(), Arc::clone(&operation));
        }

        let registry = StoredAccountRegistry::new(self.registry.metadata_path().to_path_buf());
        let adapter = adapter.clone_for_login_task();
        let op = Arc::clone(&operation);
        let task = self.runtime.spawn(async move {
            run_pending_oauth_task(
                registry,
                adapter,
                PreparedPendingOAuthHome {
                    path: home,
                    plan: oauth_plan,
                },
                account,
                cancel_rx,
                op,
                pending_lease,
            )
            .await;
        });

        {
            let mut inner = self.inner.lock().expect("login lock");
            inner.tasks.insert(handle.clone(), task);
        }

        Ok(LoginStatus {
            handle,
            binding,
            state: LoginState::WaitingForUser,
            failure_reason: None,
        })
    }

    pub fn status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginStatus> {
        self.reap_expired();
        let inner = self.inner.lock().expect("login lock");
        let Some(operation) = inner.operations.get(handle) else {
            return Ok(unknown_status(handle.clone(), binding.clone()));
        };
        if operation.binding != *binding {
            return Err(login_refused(
                &binding.provider_id,
                "login handle does not match the supplied account binding",
            ));
        }
        Ok(operation.status(handle))
    }

    pub fn cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginStatus> {
        self.reap_expired();
        let inner = self.inner.lock().expect("login lock");
        let Some(operation) = inner.operations.get(handle) else {
            return Ok(unknown_status(handle.clone(), binding.clone()));
        };
        if operation.binding != *binding {
            return Err(login_refused(
                &binding.provider_id,
                "login handle does not match the supplied account binding",
            ));
        }
        let already_terminal = {
            let state = operation.state.lock().expect("state lock");
            matches!(
                state.public,
                LoginState::Ready | LoginState::Failed | LoginState::Cancelled
            ) || (state.public == LoginState::Unknown && state.finished_at.is_some())
        };
        if already_terminal {
            return Ok(operation.status(handle));
        }
        let _ = operation.cancel_tx.send(true);
        operation.invalidate_authorization();
        Ok(operation.status(handle))
    }

    /// Read only the live URL belonging to the exact handle and incarnation.
    pub fn authorization(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<Option<LoginAuthorization>> {
        self.reap_expired();
        let inner = self.inner.lock().expect("login lock");
        let Some(operation) = inner.operations.get(handle) else {
            return Ok(None);
        };
        if operation.binding != *binding {
            return Err(login_refused(
                &binding.provider_id,
                "login handle does not match the supplied account binding",
            ));
        }
        let mut state = operation.state.lock().expect("state lock");
        if *operation.cancel_tx.borrow()
            || state.finished_at.is_some()
            || state
                .authorization
                .as_ref()
                .is_some_and(|url| Instant::now() >= url.valid_until)
        {
            state.authorization = None;
        }
        Ok(state.authorization.as_ref().map(|url| url.public.clone()))
    }

    fn remove_idempotency_key(&self, key: &str) {
        let mut inner = self.inner.lock().expect("login lock");
        inner.idempotency.remove(key);
    }

    fn shutdown_active_operations(&self) {
        let mut inner = self.inner.lock().expect("login lock");
        for operation in inner.operations.values() {
            let _ = operation.cancel_tx.send(true);
            operation.invalidate_authorization();
        }
        inner.tasks.clear();
    }

    fn reap_expired(&self) {
        let mut inner = self.inner.lock().expect("login lock");
        let mut settled_expired = Vec::new();
        for (handle, operation) in inner.operations.iter() {
            let state = operation.state.lock().expect("state lock");
            if let Some(at) = state.finished_at {
                if at.elapsed() > self.operation_retain {
                    settled_expired.push(handle.clone());
                }
                continue;
            }
            if operation.started_at.elapsed() > self.operation_retain
                && !operation.expire_cancel_sent.swap(true, Ordering::SeqCst)
            {
                let _ = operation.cancel_tx.send(true);
            }
        }
        for handle in settled_expired {
            inner.operations.remove(&handle);
            inner.tasks.remove(&handle);
            inner
                .idempotency
                .retain(|_, record| record.handle != handle);
        }
    }
}

impl Drop for LoginService {
    fn drop(&mut self) {
        self.shutdown_active_operations();
    }
}

impl LoginOperation {
    fn url_handoff(self: &Arc<Self>) -> LoginUrlHandoff {
        let weak = Arc::downgrade(self);
        LoginUrlHandoff::new(move |authorization| {
            let Some(operation) = weak.upgrade() else {
                return false;
            };
            let mut state = operation.state.lock().expect("state lock");
            if authorization.as_ref().is_some_and(|url| {
                operation.browser_mode != LoginBrowserMode::CallerManaged
                    || *operation.cancel_tx.borrow()
                    || state.finished_at.is_some()
                    || Instant::now() >= url.valid_until
            }) {
                return false;
            }
            state.authorization = authorization;
            true
        })
    }

    fn invalidate_authorization(&self) {
        self.state.lock().expect("state lock").authorization = None;
    }

    fn status(&self, handle: &LoginHandle) -> LoginStatus {
        let state = self.state.lock().expect("state lock");
        LoginStatus {
            handle: handle.clone(),
            binding: self.binding.clone(),
            state: state.public.clone(),
            failure_reason: state.failure_reason.clone(),
        }
    }

    fn mark_in_progress(&self) {
        let mut state = self.state.lock().expect("state lock");
        if matches!(
            state.public,
            LoginState::WaitingForUser | LoginState::InProgress
        ) {
            state.public = LoginState::InProgress;
        }
    }

    fn mark_ready(&self) {
        let mut state = self.state.lock().expect("state lock");
        state.authorization = None;
        state.public = LoginState::Ready;
        state.failure_reason = None;
        state.finished_at = Some(Instant::now());
    }

    fn mark_failed(&self, reason: String) {
        let mut state = self.state.lock().expect("state lock");
        state.authorization = None;
        if matches!(state.public, LoginState::Ready) {
            return;
        }
        state.public = LoginState::Failed;
        state.failure_reason = Some(reason);
        state.finished_at = Some(Instant::now());
    }

    fn mark_cancelled(&self) {
        let mut state = self.state.lock().expect("state lock");
        state.authorization = None;
        if matches!(state.public, LoginState::Ready) {
            return;
        }
        state.public = LoginState::Cancelled;
        state.failure_reason = None;
        state.finished_at = Some(Instant::now());
    }

    fn mark_commit_outcome_unknown(&self) {
        let mut state = self.state.lock().expect("state lock");
        state.authorization = None;
        if matches!(state.public, LoginState::Ready) {
            return;
        }
        state.public = LoginState::Unknown;
        state.failure_reason = Some(COMMIT_OUTCOME_UNKNOWN.to_string());
        state.finished_at = Some(Instant::now());
    }
}

const COMMIT_OUTCOME_UNKNOWN: &str = "account completion outcome is uncertain";
const FAILURE_LOGIN_CANCELLED: &str = "login was cancelled before it could finish";
const FAILURE_LOGIN_PROVISION: &str = "login provisioning failed";
const FAILURE_LOGIN_COMMIT: &str = "login finished but account completion failed";
const FAILURE_LOGIN_INTERNAL: &str = "login failed for an internal reason";

async fn run_pending_oauth_task<A: PendingOAuthLogin>(
    registry: StoredAccountRegistry,
    adapter: A,
    prepared: PreparedPendingOAuthHome,
    account: StoredAccountMetadata,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    operation: Arc<LoginOperation>,
    pending_lease: PendingLoginLease,
) {
    let PreparedPendingOAuthHome {
        path: home,
        plan: oauth_plan,
    } = prepared;
    operation.mark_in_progress();
    let handoff = (operation.browser_mode == LoginBrowserMode::CallerManaged)
        .then(|| operation.url_handoff());
    let oauth = adapter
        .run_pending_oauth_login(&home, oauth_plan, cancel_rx, handoff)
        .await;
    match oauth {
        Ok(()) => {
            if let Err(error) = adapter.finish_pending_oauth_login(&home) {
                drop(pending_lease);
                operation.mark_failed(sanitize_login_error(&error, FAILURE_LOGIN_PROVISION));
                return;
            }
            drop(pending_lease);
            match commit_managed_login_after_oauth(
                &registry,
                &adapter as &dyn ProviderAdapter,
                &home,
                &account,
            ) {
                ManagedLoginCommitOutcome::Ready => operation.mark_ready(),
                ManagedLoginCommitOutcome::OutcomeUnknown => {
                    operation.mark_commit_outcome_unknown();
                }
                ManagedLoginCommitOutcome::Failed(reason) => operation.mark_failed(reason),
            }
        }
        Err(OAuthLoginRunError::Cancelled) => {
            drop(pending_lease);
            operation.mark_cancelled();
        }
        Err(OAuthLoginRunError::Failed(error)) => {
            drop(pending_lease);
            operation.mark_failed(sanitize_login_error(&error, FAILURE_LOGIN_PROVISION));
        }
    }
}

fn oauth_material_present(provider_id: &str, home: &Path) -> bool {
    match provider_id {
        "gemini-cli" => home.join(".gemini/oauth_creds.json").is_file(),
        "codex-cli" => home.join("auth.json").is_file(),
        "claude-code" => home.join(".credentials.json").is_file(),
        "grok-cli" => home.join("auth.json").is_file(),
        _ => false,
    }
}

enum ManagedLoginCommitOutcome {
    Ready,
    OutcomeUnknown,
    Failed(String),
}

/// Fenced registry completion after OAuth material is present and the pending
/// login lease has been released. Callers must not hold the lease across this.
fn commit_managed_login_after_oauth(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    home: &Path,
    account: &StoredAccountMetadata,
) -> ManagedLoginCommitOutcome {
    match complete_managed_login_account(
        registry,
        adapter,
        &account.id,
        &account.account_incarnation,
        account.auth_kind,
        account.material,
    ) {
        Ok(()) => ManagedLoginCommitOutcome::Ready,
        Err(Error::StaleAccount { .. }) if oauth_material_present(&account.provider_id, home) => {
            ManagedLoginCommitOutcome::OutcomeUnknown
        }
        Err(Error::StaleAccount { account_id }) => {
            ManagedLoginCommitOutcome::Failed(sanitize_login_error(
                &Error::StaleAccount {
                    account_id: account_id.clone(),
                },
                FAILURE_LOGIN_COMMIT,
            ))
        }
        Err(_) if oauth_material_present(&account.provider_id, home) => {
            ManagedLoginCommitOutcome::OutcomeUnknown
        }
        Err(error) => {
            ManagedLoginCommitOutcome::Failed(sanitize_login_error(&error, FAILURE_LOGIN_COMMIT))
        }
    }
}

impl RequestFingerprint {
    fn from(request: &LoginStartRequest, browser_mode: LoginBrowserMode) -> Self {
        Self {
            provider_id: request.provider_id.clone(),
            account_id: request.account_id.clone(),
            label: request.label.clone(),
            auth_kind: request.auth_kind,
            browser_mode,
        }
    }
}

fn validate_start_request(request: &LoginStartRequest) -> Result<()> {
    if request.idempotency_key.is_empty() || request.idempotency_key.len() > 128 {
        return Err(login_refused(
            &request.provider_id,
            "idempotency key is missing or too long",
        ));
    }
    if ![
        "gemini-cli",
        "codex-cli",
        "claude-code",
        "grok-cli",
        "cursor",
        "github-copilot",
    ]
    .contains(&request.provider_id.as_str())
    {
        return Err(Error::NotImplemented("login.start"));
    }
    Ok(())
}

fn new_login_handle() -> Result<LoginHandle> {
    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| login_refused("account-metadata", "login handle entropy unavailable"))?;
    Ok(LoginHandle(URL_SAFE_NO_PAD.encode(bytes)))
}

fn unknown_status(handle: LoginHandle, binding: LoginAccountBinding) -> LoginStatus {
    LoginStatus {
        handle,
        binding,
        state: LoginState::Unknown,
        failure_reason: None,
    }
}

fn login_refused(provider: &str, reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: provider.to_string(),
        reason: reason.into(),
    }
}

fn sanitize_login_error(error: &Error, category: &'static str) -> String {
    let detail = match error {
        Error::ConfigWrite { reason, .. } | Error::ConfigRead { reason, .. } => reason.as_str(),
        Error::UnknownAccount(_) => "requested account is not available",
        Error::CredentialStoreUnavailable(_) => "credential storage is unavailable",
        Error::NotImplemented(_) => "requested login operation is not implemented",
        Error::AccountAuthorityBusy { reason } => reason.as_str(),
        Error::StaleSelection { .. }
        | Error::StaleAccount { .. }
        | Error::UnknownProvider(_)
        | Error::NoSelectedAccount(_)
        | Error::ProviderNotInstalled { .. } => category,
        Error::Io(_) => "a local I/O operation failed",
        Error::Serde(_) => "stored metadata could not be interpreted",
    };
    redact_sensitive_markers(&format!("{category}: {detail}"))
}

fn redact_sensitive_markers(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for token in text.split_whitespace() {
        let mut piece = token.to_string();
        if piece.contains("FAKE-") || piece.contains("GOCSPX-") || piece.contains("@") {
            piece = "<redacted>".to_string();
        }
        if piece.contains('/') || piece.contains('\\') {
            piece = "<path>".to_string();
        }
        if !sanitized.is_empty() {
            sanitized.push(' ');
        }
        sanitized.push_str(&piece);
    }
    if sanitized.is_empty() {
        category_fallback(text)
    } else {
        sanitized
    }
}

fn category_fallback(text: &str) -> String {
    if text.contains("cancel") {
        FAILURE_LOGIN_CANCELLED.to_string()
    } else {
        FAILURE_LOGIN_INTERNAL.to_string()
    }
}

#[cfg(test)]
mod tests;
