//! Coordinator-facing local and opt-in remote executor contracts.
//!
//! The compatibility [`AgentExecutor`] surface remains admission-shaped. New
//! callers that need process results, cancellation, usage, lifecycle events,
//! and recovery use the additive [`BoundedExecutor`] contract. Remote results
//! are candidate evidence only: this module has no claim, review, merge, or
//! publication authority.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod local;
mod ssh;

pub use ssh::{
    OpenSshTransport, RemoteExecutionReply, RemoteExecutionRequest, SshConfig, SshConfigInput,
    SshExecutor, SshTransport, TransportFailure, TransportFailureKind, TransportStage,
    WorkspaceEntry, WorkspaceEntryKind, WorkspaceManifest,
};

const MAX_OPAQUE_ID_BYTES: usize = 128;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ARGV_BYTES: usize = 16 * 1024;

/// Caller-selected limits for one local or remote execution.
///
/// There is intentionally no `Default`: transport, workspace, capture, and
/// cancellation bounds must be explicit at the opt-in call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorLimits {
    pub max_workspace_entries: usize,
    pub max_workspace_bytes: usize,
    pub max_file_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_event_count: usize,
    pub max_event_bytes: usize,
    pub max_request_bytes: usize,
    pub max_receipt_bytes: usize,
    pub connect_timeout_millis: u64,
    pub execution_timeout_millis: u64,
    pub cancellation_grace_millis: u64,
    pub poll_interval_millis: u64,
}

impl ExecutorLimits {
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("max_workspace_entries", self.max_workspace_entries),
            ("max_workspace_bytes", self.max_workspace_bytes),
            ("max_file_bytes", self.max_file_bytes),
            ("max_stdout_bytes", self.max_stdout_bytes),
            ("max_stderr_bytes", self.max_stderr_bytes),
            ("max_event_count", self.max_event_count),
            ("max_event_bytes", self.max_event_bytes),
            ("max_request_bytes", self.max_request_bytes),
            ("max_receipt_bytes", self.max_receipt_bytes),
        ] {
            if value == 0 {
                bail!("executor limit {field} must be greater than zero");
            }
        }
        for (field, value) in [
            ("connect_timeout_millis", self.connect_timeout_millis),
            ("execution_timeout_millis", self.execution_timeout_millis),
            ("cancellation_grace_millis", self.cancellation_grace_millis),
            ("poll_interval_millis", self.poll_interval_millis),
        ] {
            if value == 0 {
                bail!("executor limit {field} must be greater than zero");
            }
        }
        if self.poll_interval_millis > self.cancellation_grace_millis {
            bail!("executor poll interval cannot exceed its cancellation grace period");
        }
        if self.max_file_bytes > self.max_workspace_bytes {
            bail!("executor per-file limit cannot exceed its workspace byte limit");
        }
        if self.connect_timeout_millis > self.execution_timeout_millis {
            bail!("executor connect timeout cannot exceed its execution timeout");
        }
        validate_minimum_event_capacity(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorUsage {
    pub workspace_entries: usize,
    pub workspace_bytes: usize,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub event_count: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorLifecycleEvent {
    Validated,
    Staged,
    Launched,
    CancelRequested,
    TimeoutExpired,
    TermSent,
    KillSent,
    Collected,
    Reconciled,
    CleanupComplete,
    CleanupResidual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Exited {
        code: Option<i32>,
    },
    Cancelled,
    TimedOut,
    Failed {
        reason: String,
    },
    /// A local transport failure retaining its exact protocol stage and class.
    /// This is never accepted from an untrusted remote receipt.
    TransportFailed {
        stage: TransportStage,
        kind: TransportFailureKind,
        reason: String,
        /// Deterministic manual recovery evidence. Preflight failures have not
        /// crossed the remote side-effect boundary and therefore use `None`.
        recovery: Option<RecoveryTarget>,
    },
    Uncertain {
        reason: String,
        recovery: RecoveryTarget,
    },
}

/// Identity returned by an authenticated helper acknowledgement.
///
/// Automatic remote process operations are unavailable while this value is
/// absent. A deterministic host/run/workspace/digest tuple remains useful for
/// manual inspection, but is not proof that a particular process exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteProcessIdentity {
    pub session_id: String,
    pub pid: u32,
    pub pgid: u32,
    pub start_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryTarget {
    pub assignment_id: String,
    pub executor_run_id: String,
    pub host_id: String,
    /// Exact per-run workspace identifier to inspect or clean up. It is
    /// candidate recovery state, never local mutation authority.
    pub workspace: String,
    /// SHA-256 binding of the normalized staged workspace manifest.
    pub staged_input_digest: String,
    /// Process identity acknowledged inside the authenticated helper reply.
    /// It is absent for every locally synthesized pre-acknowledgement result.
    pub remote_process: Option<RemoteProcessIdentity>,
}

impl RecoveryTarget {
    /// Whether this target contains enough authenticated identity for a future
    /// control/reconciliation protocol. This executor intentionally performs
    /// no automatic remote operation when the identity is absent.
    pub fn has_authenticated_process_identity(&self) -> bool {
        self.remote_process.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateArtifactKind {
    File,
    Directory,
    Deleted,
}

/// Bounded candidate workspace evidence. Digests identify file bytes but do
/// not grant claim, review, merge, or publication authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifact {
    pub path: String,
    pub kind: CandidateArtifactKind,
    pub contents: Vec<u8>,
    pub executable: bool,
    pub digest: Option<String>,
}

impl CandidateArtifact {
    /// Construct file candidate evidence using the stable encoding
    /// `sha256:<64 lowercase hex characters>`.
    pub fn file(path: impl Into<String>, contents: Vec<u8>, executable: bool) -> Result<Self> {
        let digest = crate::artifacts::state_auth::sha256_hex(&contents);
        Ok(Self {
            path: path.into(),
            kind: CandidateArtifactKind::File,
            contents,
            executable,
            digest: Some(format!("sha256:{digest}")),
        })
    }

    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: CandidateArtifactKind::Directory,
            contents: Vec::new(),
            executable: false,
            digest: None,
        }
    }

    pub fn deleted(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: CandidateArtifactKind::Deleted,
            contents: Vec::new(),
            executable: false,
            digest: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectReconciliation {
    /// Output is candidate evidence and grants no coordinator authority.
    CandidateOnly {
        changed_paths: Vec<String>,
    },
    CandidateArtifacts {
        changed_paths: Vec<String>,
        artifacts: Vec<CandidateArtifact>,
    },
    Uncertain {
        recovery: RecoveryTarget,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Complete,
    Residual { recovery: RecoveryTarget },
    NotStarted,
}

/// Backend-neutral semantic result. Conformance compares this value unchanged
/// while [`ExecutionReport::kind`] keeps backend identity observable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSemantics {
    pub status: ExecutionStatus,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub usage: ExecutorUsage,
    pub events: Vec<ExecutorLifecycleEvent>,
    pub effects: EffectReconciliation,
    pub cleanup: CleanupStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub assignment_id: String,
    pub kind: ExecutorKind,
    pub semantics: ExecutionSemantics,
}

/// Cloneable cancellation signal shared by the coordinator and executor.
///
/// Cancellation is cooperative: transports check it before and during each
/// bounded lifecycle step and return a typed cancelled outcome.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Operator-selected executor kind. SSH remains explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    Local,
    Ssh,
}

/// Bounded assignment the coordinator is willing to hand to an executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorRequest {
    pub assignment_id: String,
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<PathBuf>,
}

/// Outcome of one executor admission or fail-closed refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorOutcome {
    pub assignment_id: String,
    pub kind: ExecutorKind,
    pub status: ExecutorStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorStatus {
    Admitted,
    Refused { reason: String },
}

/// Compatibility Local/SSH admission contract.
pub trait AgentExecutor: Send + Sync {
    fn kind(&self) -> ExecutorKind;
    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome>;
}

/// Rich, object-safe execution contract shared by local and SSH backends.
pub trait BoundedExecutor: Send + Sync {
    fn execute_bounded(
        &self,
        request: &ExecutorRequest,
        cancellation: &CancellationToken,
        limits: &ExecutorLimits,
    ) -> Result<ExecutionReport>;
}

/// Local compatibility executor. It validates a request and forwards a caller
/// runner; it does not reconstruct process launch, review, or merge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LocalExecutor;

impl LocalExecutor {
    pub fn run<R, T>(&self, request: &ExecutorRequest, runner: R) -> Result<T>
    where
        R: FnOnce(&ExecutorRequest) -> Result<T>,
    {
        validate_executor_request(request).context("LocalExecutor rejected the assignment")?;
        runner(request)
    }
}

impl AgentExecutor for LocalExecutor {
    fn kind(&self) -> ExecutorKind {
        ExecutorKind::Local
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        self.run(request, |request| {
            Ok(ExecutorOutcome {
                assignment_id: request.assignment_id.clone(),
                kind: ExecutorKind::Local,
                status: ExecutorStatus::Admitted,
            })
        })
    }
}

impl BoundedExecutor for LocalExecutor {
    fn execute_bounded(
        &self,
        request: &ExecutorRequest,
        cancellation: &CancellationToken,
        limits: &ExecutorLimits,
    ) -> Result<ExecutionReport> {
        local::execute(request, cancellation, limits)
    }
}

/// Owned handle used when the coordinator selects an executor by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorHandle {
    Local(LocalExecutor),
    Ssh(SshExecutor),
}

impl ExecutorHandle {
    pub fn local() -> Self {
        Self::Local(LocalExecutor)
    }

    pub fn ssh(host_id: impl Into<String>) -> Result<Self> {
        Ok(Self::Ssh(SshExecutor::new(host_id)?))
    }

    pub fn kind(&self) -> ExecutorKind {
        match self {
            Self::Local(_) => ExecutorKind::Local,
            Self::Ssh(_) => ExecutorKind::Ssh,
        }
    }
}

impl AgentExecutor for ExecutorHandle {
    fn kind(&self) -> ExecutorKind {
        match self {
            Self::Local(_) => ExecutorKind::Local,
            Self::Ssh(_) => ExecutorKind::Ssh,
        }
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        match self {
            Self::Local(executor) => executor.execute(request),
            Self::Ssh(executor) => executor.execute(request),
        }
    }
}

impl BoundedExecutor for ExecutorHandle {
    fn execute_bounded(
        &self,
        request: &ExecutorRequest,
        cancellation: &CancellationToken,
        limits: &ExecutorLimits,
    ) -> Result<ExecutionReport> {
        match self {
            Self::Local(executor) => executor.execute_bounded(request, cancellation, limits),
            Self::Ssh(executor) => executor.execute_bounded(request, cancellation, limits),
        }
    }
}

pub(crate) fn validate_executor_request(request: &ExecutorRequest) -> Result<()> {
    validate_opaque_id("assignment_id", &request.assignment_id)?;
    if request.argv.is_empty() {
        bail!("executor argv must contain at least one argument");
    }
    if request.argv.len() > MAX_ARG_COUNT {
        bail!(
            "executor argv contains {} arguments but at most {MAX_ARG_COUNT} are allowed",
            request.argv.len()
        );
    }
    let mut total_bytes = 0usize;
    for (index, argument) in request.argv.iter().enumerate() {
        if argument.is_empty() {
            bail!("executor argv[{index}] cannot be empty");
        }
        if argument.contains('\0') {
            bail!("executor argv[{index}] cannot contain NUL bytes");
        }
        if argument.len() > MAX_ARG_BYTES {
            bail!(
                "executor argv[{index}] contains {} bytes but at most {MAX_ARG_BYTES} are allowed",
                argument.len()
            );
        }
        total_bytes = total_bytes
            .checked_add(argument.len())
            .context("executor argv byte count overflowed")?;
        if total_bytes > MAX_ARGV_BYTES {
            bail!("executor argv exceeds its {MAX_ARGV_BYTES}-byte aggregate limit");
        }
    }
    if let Some(working_directory) = request.working_directory.as_deref() {
        validate_working_directory(working_directory)?;
    }
    Ok(())
}

fn validate_working_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("executor working_directory cannot be empty");
    }
    if !path.is_absolute() {
        bail!("executor working_directory must be an absolute path");
    }
    let text = path
        .to_str()
        .context("executor working_directory must be valid UTF-8")?;
    if text.contains('\0') {
        bail!("executor working_directory cannot contain NUL bytes");
    }
    Ok(())
}

pub(crate) fn validate_opaque_id(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("executor {field} cannot be empty");
    }
    if value.len() > MAX_OPAQUE_ID_BYTES {
        bail!("executor {field} is too long");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("executor {field} must contain only ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

pub(crate) fn validate_event_bounds(
    events: &[ExecutorLifecycleEvent],
    limits: &ExecutorLimits,
) -> Result<()> {
    if events.len() > limits.max_event_count {
        bail!("executor event count exceeds its configured limit");
    }
    let bytes = serde_json::to_vec(events).context("could not measure executor event stream")?;
    if bytes.len() > limits.max_event_bytes {
        bail!("executor event stream exceeds its configured byte limit");
    }
    Ok(())
}

fn validate_minimum_event_capacity(limits: &ExecutorLimits) -> Result<()> {
    // These are the longest realizable local/helper lifecycle paths. Requiring
    // both variants up front means cancellation, timeout, cleanup, and every
    // shorter synthesized failure can always be represented after side effects
    // begin; event-limit failure is therefore admission-only.
    let cancellation = [
        ExecutorLifecycleEvent::Validated,
        ExecutorLifecycleEvent::Staged,
        ExecutorLifecycleEvent::Launched,
        ExecutorLifecycleEvent::CancelRequested,
        ExecutorLifecycleEvent::TermSent,
        ExecutorLifecycleEvent::KillSent,
        ExecutorLifecycleEvent::Collected,
        ExecutorLifecycleEvent::Reconciled,
        ExecutorLifecycleEvent::CleanupComplete,
    ];
    let timeout = [
        ExecutorLifecycleEvent::Validated,
        ExecutorLifecycleEvent::Staged,
        ExecutorLifecycleEvent::Launched,
        ExecutorLifecycleEvent::TimeoutExpired,
        ExecutorLifecycleEvent::TermSent,
        ExecutorLifecycleEvent::KillSent,
        ExecutorLifecycleEvent::Collected,
        ExecutorLifecycleEvent::Reconciled,
        ExecutorLifecycleEvent::CleanupComplete,
    ];
    for required in [&cancellation[..], &timeout[..]] {
        validate_event_bounds(required, limits).context(
            "executor event limits cannot represent the required bounded terminal lifecycle",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn local_request() -> ExecutorRequest {
        ExecutorRequest {
            assignment_id: "assign-001".to_string(),
            argv: vec!["codex".to_string(), "exec".to_string()],
            working_directory: Some(PathBuf::from("/tmp/maco-local-executor")),
        }
    }

    #[test]
    fn local_executor_admits_and_forwards_a_valid_request() {
        let executor = LocalExecutor;
        let request = local_request();
        let calls = AtomicUsize::new(0);
        let forwarded = executor
            .run(&request, |received| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(received, &request);
                Ok(received.assignment_id.clone())
            })
            .expect("forward local request");
        assert_eq!(forwarded, "assign-001");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let outcome = executor.execute(&request).expect("admit local request");
        assert_eq!(outcome.kind, ExecutorKind::Local);
        assert_eq!(outcome.status, ExecutorStatus::Admitted);
        assert_eq!(outcome.assignment_id, "assign-001");
    }

    #[test]
    fn local_executor_rejects_invalid_requests() {
        let executor = LocalExecutor;
        let missing_id = ExecutorRequest {
            assignment_id: String::new(),
            argv: vec!["codex".to_string()],
            working_directory: None,
        };
        let error = executor
            .execute(&missing_id)
            .expect_err("empty assignment id");
        let message = format!("{error:#}");
        assert!(
            message.contains("assignment_id cannot be empty"),
            "{message}"
        );

        let relative = ExecutorRequest {
            assignment_id: "assign-001".to_string(),
            argv: vec!["codex".to_string()],
            working_directory: Some(PathBuf::from("relative/work")),
        };
        let error = executor
            .execute(&relative)
            .expect_err("relative working directory");
        let message = format!("{error:#}");
        assert!(
            message.contains("working_directory must be an absolute path"),
            "{message}"
        );
    }

    #[test]
    fn ssh_executor_host_only_constructor_stays_fail_closed() {
        let error = SshExecutor::new("").expect_err("empty host");
        assert!(error.to_string().contains("host_id cannot be empty"));

        let executor = SshExecutor::new("home-lxc-a").expect("typed ssh seam");
        assert_eq!(executor.host_id(), "home-lxc-a");
        assert_eq!(AgentExecutor::kind(&executor), ExecutorKind::Ssh);
        let error = executor
            .execute(&local_request())
            .expect_err("live SSH must stay closed");
        let message = error.to_string();
        assert!(message.contains("unconfigured"), "{message}");
        assert!(message.contains("host-key trust"), "{message}");
        assert!(!message.contains("ssh -"), "{message}");
    }

    #[test]
    fn executor_handle_selects_local_or_the_ssh_seam() {
        let local = ExecutorHandle::local();
        assert_eq!(local.kind(), ExecutorKind::Local);
        let object_safe: &dyn AgentExecutor = &local;
        let outcome = object_safe
            .execute(&local_request())
            .expect("local handle admits");
        assert_eq!(outcome.status, ExecutorStatus::Admitted);

        let ssh = ExecutorHandle::ssh("home-lxc-a").expect("ssh handle");
        assert_eq!(ssh.kind(), ExecutorKind::Ssh);
        let object_safe: &dyn AgentExecutor = &ssh;
        let error = object_safe
            .execute(&local_request())
            .expect_err("ssh handle stays closed");
        assert!(error.to_string().contains("unconfigured"));
    }
}
