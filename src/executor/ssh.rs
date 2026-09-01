use super::{
    AgentExecutor, BoundedExecutor, CancellationToken, CandidateArtifact, CandidateArtifactKind,
    CapturedOutput, CleanupStatus, EffectReconciliation, ExecutionReport, ExecutionSemantics,
    ExecutionStatus, ExecutorKind, ExecutorLifecycleEvent, ExecutorLimits, ExecutorOutcome,
    ExecutorRequest, ExecutorStatus, ExecutorUsage, RecoveryTarget,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const WIRE_PROTOCOL: &str = "maco-executor-v1";
const FRAME_PREFIX: &str = "MACO_EXECUTOR_V1";
const MAX_TRUST_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfigInput {
    pub host_id: String,
    pub host: String,
    pub user: String,
    pub port: u16,
    pub identity_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub remote_root: String,
    pub helper_path: String,
    pub limits: ExecutorLimits,
}

/// Fully explicit SSH endpoint, authentication, trust, workspace, helper, and
/// resource configuration. Construction performs local fail-closed checks;
/// no ambient SSH configuration or credential source is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    input: SshConfigInput,
}

impl SshConfig {
    pub fn new(input: SshConfigInput) -> Result<Self> {
        super::validate_opaque_id("host_id", &input.host_id)?;
        validate_host(&input.host)?;
        validate_user(&input.user)?;
        if input.port == 0 {
            bail!("SSH port must be greater than zero");
        }
        validate_trust_file("identity_file", &input.identity_file, true)?;
        validate_trust_file("known_hosts_file", &input.known_hosts_file, false)?;
        validate_remote_absolute_path("remote_root", &input.remote_root)?;
        validate_remote_absolute_path("helper_path", &input.helper_path)?;
        input
            .limits
            .validate()
            .context("invalid SSH executor limits")?;
        Ok(Self { input })
    }

    pub fn host_id(&self) -> &str {
        &self.input.host_id
    }

    pub fn host(&self) -> &str {
        &self.input.host
    }

    pub fn user(&self) -> &str {
        &self.input.user
    }

    pub fn port(&self) -> u16 {
        self.input.port
    }

    pub fn identity_file(&self) -> &Path {
        &self.input.identity_file
    }

    pub fn known_hosts_file(&self) -> &Path {
        &self.input.known_hosts_file
    }

    pub fn remote_root(&self) -> &str {
        &self.input.remote_root
    }

    pub fn helper_path(&self) -> &str {
        &self.input.helper_path
    }

    pub fn limits(&self) -> &ExecutorLimits {
        &self.input.limits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    pub path: String,
    pub kind: WorkspaceEntryKind,
    pub contents: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub entries: Vec<WorkspaceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteExecutionRequest {
    pub protocol: String,
    pub assignment_id: String,
    pub executor_run_id: String,
    pub host_id: String,
    pub remote_root: String,
    pub argv: Vec<String>,
    pub workspace: WorkspaceManifest,
    pub staged_input_digest: String,
    pub limits: ExecutorLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteExecutionReply {
    pub protocol: String,
    pub assignment_id: String,
    pub executor_run_id: String,
    pub host_id: String,
    pub semantics: ExecutionSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportStage {
    Preflight,
    Stage,
    Launch,
    Control,
    Collect,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailureKind {
    Authentication,
    HostKey,
    Io,
    Protocol,
    Cancelled,
    TimedOut,
    TransportRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportFailure {
    pub stage: TransportStage,
    pub kind: TransportFailureKind,
    pub reason: String,
}

impl TransportFailure {
    pub fn new(
        stage: TransportStage,
        kind: TransportFailureKind,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            kind,
            reason: reason.into(),
        }
    }
}

/// Testable transport boundary used unchanged by production OpenSSH and fakes.
pub trait SshTransport: Send + Sync {
    fn execute(
        &self,
        config: &SshConfig,
        request: &RemoteExecutionRequest,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteExecutionReply, TransportFailure>;
}

#[derive(Clone)]
struct ConfiguredTransport {
    config: SshConfig,
    transport: Arc<dyn SshTransport>,
}

/// Opt-in SSH executor. The compatibility [`SshExecutor::new`] constructor
/// records a host id but deliberately remains unconfigured and fail-closed.
#[derive(Clone)]
pub struct SshExecutor {
    host_id: String,
    configured: Option<Arc<ConfiguredTransport>>,
}

impl std::fmt::Debug for SshExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshExecutor")
            .field("host_id", &self.host_id)
            .field("configured", &self.configured.is_some())
            .finish()
    }
}

impl PartialEq for SshExecutor {
    fn eq(&self, other: &Self) -> bool {
        self.host_id == other.host_id
            && self.configured.as_ref().map(|value| &value.config)
                == other.configured.as_ref().map(|value| &value.config)
    }
}

impl Eq for SshExecutor {}

impl SshExecutor {
    pub fn new(host_id: impl Into<String>) -> Result<Self> {
        let host_id = host_id.into();
        super::validate_opaque_id("host_id", &host_id)?;
        Ok(Self {
            host_id,
            configured: None,
        })
    }

    pub fn with_openssh(config: SshConfig, ssh_binary: impl Into<PathBuf>) -> Result<Self> {
        let transport = Arc::new(OpenSshTransport::new(ssh_binary)?);
        Self::with_transport(config, transport)
    }

    pub fn with_transport(config: SshConfig, transport: Arc<dyn SshTransport>) -> Result<Self> {
        // Re-check files at executor construction so a stale deserialized or
        // long-held config cannot silently opt into replaced trust material.
        let config = SshConfig::new(config.input.clone())?;
        Ok(Self {
            host_id: config.host_id().to_string(),
            configured: Some(Arc::new(ConfiguredTransport { config, transport })),
        })
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn is_configured(&self) -> bool {
        self.configured.is_some()
    }
}

impl AgentExecutor for SshExecutor {
    fn kind(&self) -> ExecutorKind {
        ExecutorKind::Ssh
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        super::validate_executor_request(request).context("SshExecutor rejected the assignment")?;
        let configured = self.configured.as_ref().with_context(|| {
            format!(
                "SshExecutor host '{}' is unconfigured; explicit authentication and host-key trust are required",
                self.host_id
            )
        })?;
        let report = self.execute_bounded(
            request,
            &CancellationToken::new(),
            configured.config.limits(),
        )?;
        let status = match report.semantics.status {
            ExecutionStatus::Exited { .. } => ExecutorStatus::Admitted,
            ExecutionStatus::Cancelled => ExecutorStatus::Refused {
                reason: "remote execution was cancelled".to_string(),
            },
            ExecutionStatus::TimedOut => ExecutorStatus::Refused {
                reason: "remote execution timed out".to_string(),
            },
            ExecutionStatus::Failed { reason }
            | ExecutionStatus::TransportFailed { reason, .. }
            | ExecutionStatus::Uncertain { reason, .. } => ExecutorStatus::Refused { reason },
        };
        Ok(ExecutorOutcome {
            assignment_id: request.assignment_id.clone(),
            kind: ExecutorKind::Ssh,
            status,
        })
    }
}

impl BoundedExecutor for SshExecutor {
    fn execute_bounded(
        &self,
        request: &ExecutorRequest,
        cancellation: &CancellationToken,
        limits: &ExecutorLimits,
    ) -> Result<ExecutionReport> {
        super::validate_executor_request(request).context("SshExecutor rejected the assignment")?;
        limits
            .validate()
            .context("SshExecutor rejected its limits")?;
        let configured = self.configured.as_ref().with_context(|| {
            format!(
                "SshExecutor host '{}' is unconfigured; explicit authentication and host-key trust are required",
                self.host_id
            )
        })?;
        if limits != configured.config.limits() {
            bail!("SshExecutor call limits must exactly match its validated transport limits");
        }
        if cancellation.is_cancelled() {
            let report = cancelled_before_launch(request, ExecutorKind::Ssh);
            super::validate_event_bounds(&report.semantics.events, limits)
                .context("SshExecutor could not represent pre-launch events within bounds")?;
            return Ok(report);
        }

        let workspace = build_workspace_manifest(request.working_directory.as_deref(), limits)
            .context("SshExecutor could not stage the workspace manifest")?;
        let executor_run_id = new_run_id().context("SshExecutor could not create a run nonce")?;
        let staged_input_digest = staged_input_digest(&workspace)
            .context("SshExecutor could not bind the staged workspace")?;
        let remote_workspace = format!(
            "{}/{}",
            configured.config.remote_root().trim_end_matches('/'),
            executor_run_id
        );
        validate_remote_absolute_path("per-run remote workspace", &remote_workspace)?;
        let remote_request = RemoteExecutionRequest {
            protocol: WIRE_PROTOCOL.to_string(),
            assignment_id: request.assignment_id.clone(),
            executor_run_id: executor_run_id.clone(),
            host_id: self.host_id.clone(),
            remote_root: remote_workspace.clone(),
            argv: request.argv.clone(),
            workspace,
            staged_input_digest: staged_input_digest.clone(),
            limits: limits.clone(),
        };
        let request_bytes = serde_json::to_vec(&remote_request)
            .context("SshExecutor could not measure its remote request")?;
        if request_bytes.len() > limits.max_request_bytes {
            bail!("SshExecutor remote request exceeds its configured byte limit");
        }
        let recovery = RecoveryTarget {
            assignment_id: request.assignment_id.clone(),
            executor_run_id,
            host_id: self.host_id.clone(),
            workspace: remote_workspace,
            staged_input_digest,
            remote_process: None,
        };
        validate_failure_report_capacity(request, &recovery, limits).context(
            "SshExecutor receipt limit cannot represent a bounded transport-failure report",
        )?;

        match configured
            .transport
            .execute(&configured.config, &remote_request, cancellation)
        {
            Ok(reply) => match validate_reply(&remote_request, &reply, limits) {
                Ok(()) => Ok(ExecutionReport {
                    assignment_id: request.assignment_id.clone(),
                    kind: ExecutorKind::Ssh,
                    semantics: reply.semantics,
                }),
                Err(error) => Ok(uncertain_report(
                    request,
                    recovery,
                    format!("remote receipt validation failed: {error:#}"),
                    TransportStage::Collect,
                    TransportFailureKind::Protocol,
                    limits,
                )),
            },
            Err(failure) => Ok(failure_report(request, recovery, failure, limits)),
        }
    }
}

fn cancelled_before_launch(request: &ExecutorRequest, kind: ExecutorKind) -> ExecutionReport {
    let events = vec![
        ExecutorLifecycleEvent::Validated,
        ExecutorLifecycleEvent::CancelRequested,
    ];
    ExecutionReport {
        assignment_id: request.assignment_id.clone(),
        kind,
        semantics: ExecutionSemantics {
            status: ExecutionStatus::Cancelled,
            stdout: empty_capture(),
            stderr: empty_capture(),
            usage: ExecutorUsage {
                workspace_entries: 0,
                workspace_bytes: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
                event_count: events.len(),
                complete: true,
            },
            events,
            effects: EffectReconciliation::CandidateOnly {
                changed_paths: Vec::new(),
            },
            cleanup: CleanupStatus::NotStarted,
        },
    }
}

fn failure_report(
    request: &ExecutorRequest,
    recovery: RecoveryTarget,
    failure: TransportFailure,
    limits: &ExecutorLimits,
) -> ExecutionReport {
    if failure.stage == TransportStage::Preflight {
        let events = vec![ExecutorLifecycleEvent::Validated];
        let report = ExecutionReport {
            assignment_id: request.assignment_id.clone(),
            kind: ExecutorKind::Ssh,
            semantics: ExecutionSemantics {
                status: ExecutionStatus::TransportFailed {
                    stage: failure.stage,
                    kind: failure.kind,
                    reason: String::new(),
                    recovery: None,
                },
                stdout: empty_capture(),
                stderr: empty_capture(),
                usage: ExecutorUsage {
                    workspace_entries: 0,
                    workspace_bytes: 0,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    event_count: events.len(),
                    complete: true,
                },
                events,
                effects: EffectReconciliation::CandidateOnly {
                    changed_paths: Vec::new(),
                },
                cleanup: CleanupStatus::NotStarted,
            },
        };
        return finalize_transport_failure_report(
            report,
            &failure.reason,
            limits.max_receipt_bytes,
        );
    }
    uncertain_report(
        request,
        recovery,
        failure.reason,
        failure.stage,
        failure.kind,
        limits,
    )
}

fn uncertain_report(
    request: &ExecutorRequest,
    recovery: RecoveryTarget,
    reason: String,
    stage: TransportStage,
    kind: TransportFailureKind,
    limits: &ExecutorLimits,
) -> ExecutionReport {
    let mut events = vec![ExecutorLifecycleEvent::Validated];
    if stage != TransportStage::Preflight {
        events.push(ExecutorLifecycleEvent::Staged);
    }
    if matches!(
        stage,
        TransportStage::Launch
            | TransportStage::Control
            | TransportStage::Collect
            | TransportStage::Cleanup
    ) {
        events.push(ExecutorLifecycleEvent::Launched);
    }
    events.push(ExecutorLifecycleEvent::CleanupResidual);
    let report = ExecutionReport {
        assignment_id: request.assignment_id.clone(),
        kind: ExecutorKind::Ssh,
        semantics: ExecutionSemantics {
            status: ExecutionStatus::TransportFailed {
                stage,
                kind,
                reason: String::new(),
                recovery: Some(recovery.clone()),
            },
            stdout: empty_capture(),
            stderr: empty_capture(),
            usage: ExecutorUsage {
                workspace_entries: 0,
                workspace_bytes: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
                event_count: events.len(),
                complete: false,
            },
            events,
            effects: EffectReconciliation::Uncertain {
                recovery: recovery.clone(),
            },
            cleanup: CleanupStatus::Residual { recovery },
        },
    };
    finalize_transport_failure_report(report, &reason, limits.max_receipt_bytes)
}

fn validate_failure_report_capacity(
    request: &ExecutorRequest,
    recovery: &RecoveryTarget,
    limits: &ExecutorLimits,
) -> Result<()> {
    let reports = [
        failure_report(
            request,
            recovery.clone(),
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::TransportRejected,
                "",
            ),
            limits,
        ),
        uncertain_report(
            request,
            recovery.clone(),
            String::new(),
            TransportStage::Cleanup,
            TransportFailureKind::TransportRejected,
            limits,
        ),
    ];
    for report in reports {
        let bytes = serde_json::to_vec(&report)
            .context("could not measure synthesized transport-failure report")?;
        if bytes.len() > limits.max_receipt_bytes {
            bail!("synthesized transport-failure report exceeds max_receipt_bytes");
        }
    }
    Ok(())
}

fn finalize_transport_failure_report(
    mut report: ExecutionReport,
    reason: &str,
    serialized_limit: usize,
) -> ExecutionReport {
    let fixed_bytes = match serde_json::to_vec(&report) {
        Ok(bytes) => bytes.len(),
        Err(_) => serialized_limit,
    };
    let reason_budget = serialized_limit.saturating_sub(fixed_bytes);
    let reason = bounded_transport_failure_reason(reason, reason_budget);
    if let ExecutionStatus::TransportFailed {
        reason: report_reason,
        ..
    } = &mut report.semantics.status
    {
        *report_reason = reason;
    }
    report
}

fn bounded_transport_failure_reason(reason: &str, limit: usize) -> String {
    const TRUNCATED: &str = "[truncated]";
    let mut bounded = String::with_capacity(limit.min(reason.len()));
    let mut truncated = false;
    for character in reason.chars() {
        let safe = if character.is_ascii_graphic() && !matches!(character, '"' | '\\') {
            character
        } else if character == ' ' {
            ' '
        } else {
            '?'
        };
        if bounded.len().saturating_add(safe.len_utf8()) > limit {
            truncated = true;
            break;
        }
        bounded.push(safe);
    }
    if truncated {
        if limit >= TRUNCATED.len() {
            while bounded.len().saturating_add(TRUNCATED.len()) > limit {
                if bounded.pop().is_none() {
                    break;
                }
            }
            bounded.push_str(TRUNCATED);
        } else {
            bounded.clear();
            bounded.push_str(&TRUNCATED[..limit]);
        }
    }
    bounded
}

fn empty_capture() -> CapturedOutput {
    CapturedOutput {
        bytes: Vec::new(),
        truncated: false,
    }
}

fn validate_reply(
    request: &RemoteExecutionRequest,
    reply: &RemoteExecutionReply,
    limits: &ExecutorLimits,
) -> Result<()> {
    let receipt_bytes = serde_json::to_vec(reply).context("could not measure remote receipt")?;
    if receipt_bytes.len() > limits.max_receipt_bytes {
        bail!("remote receipt exceeds its configured byte limit");
    }
    if reply.protocol != WIRE_PROTOCOL {
        bail!("unexpected remote protocol version");
    }
    if reply.assignment_id != request.assignment_id
        || reply.executor_run_id != request.executor_run_id
        || reply.host_id != request.host_id
    {
        bail!("remote receipt identity does not match the submitted execution");
    }
    validate_capture("stdout", &reply.semantics.stdout, limits.max_stdout_bytes)?;
    validate_capture("stderr", &reply.semantics.stderr, limits.max_stderr_bytes)?;
    super::validate_event_bounds(&reply.semantics.events, limits)
        .context("remote lifecycle events exceeded their bounds")?;
    if reply.semantics.usage.stdout_bytes != reply.semantics.stdout.bytes.len()
        || reply.semantics.usage.stderr_bytes != reply.semantics.stderr.bytes.len()
        || reply.semantics.usage.event_count != reply.semantics.events.len()
    {
        bail!("remote usage does not reconcile with captured result fields");
    }
    if reply.semantics.usage.workspace_entries != request.workspace.entries.len() {
        bail!("remote workspace entry usage does not match the submitted manifest");
    }
    let workspace_bytes = request
        .workspace
        .entries
        .iter()
        .try_fold(0usize, |total, entry| {
            total.checked_add(entry.contents.len())
        })
        .context("workspace byte count overflowed while validating receipt")?;
    if reply.semantics.usage.workspace_bytes != workspace_bytes {
        bail!("remote workspace byte usage does not match the submitted manifest");
    }
    if staged_input_digest(&request.workspace)? != request.staged_input_digest {
        bail!("remote request staged-input digest does not bind its workspace manifest");
    }
    let expected_recovery = RecoveryTarget {
        assignment_id: request.assignment_id.clone(),
        executor_run_id: request.executor_run_id.clone(),
        host_id: request.host_id.clone(),
        workspace: request.remote_root.clone(),
        staged_input_digest: request.staged_input_digest.clone(),
        remote_process: None,
    };
    validate_semantic_coherence(
        &reply.semantics,
        &request.workspace,
        &expected_recovery,
        limits,
    )?;
    for path in changed_paths(&reply.semantics.effects) {
        validate_logical_path(path)?;
    }
    Ok(())
}

fn validate_semantic_coherence(
    semantics: &ExecutionSemantics,
    initial_workspace: &WorkspaceManifest,
    expected_recovery: &RecoveryTarget,
    limits: &ExecutorLimits,
) -> Result<()> {
    if matches!(semantics.status, ExecutionStatus::TransportFailed { .. }) {
        bail!("remote receipt cannot claim a local transport failure");
    }
    validate_event_sequence(semantics)?;
    let recovery_targets = [
        match &semantics.status {
            ExecutionStatus::Uncertain { recovery, .. } => Some(recovery),
            _ => None,
        },
        match &semantics.effects {
            EffectReconciliation::Uncertain { recovery } => Some(recovery),
            _ => None,
        },
        match &semantics.cleanup {
            CleanupStatus::Residual { recovery } => Some(recovery),
            _ => None,
        },
    ];
    let mut bound_recovery: Option<&RecoveryTarget> = None;
    for recovery in recovery_targets.into_iter().flatten() {
        validate_recovery_target(recovery, expected_recovery)?;
        if let Some(bound) = bound_recovery {
            if recovery != bound {
                bail!("remote recovery identities are inconsistent");
            }
        } else {
            bound_recovery = Some(recovery);
        }
    }

    validate_candidate_artifacts(
        &semantics.effects,
        initial_workspace,
        expected_recovery,
        &semantics.events,
        limits,
    )?;
    let status_uncertain = matches!(semantics.status, ExecutionStatus::Uncertain { .. });
    let status_timed_out = matches!(semantics.status, ExecutionStatus::TimedOut);
    let effects_uncertain = matches!(semantics.effects, EffectReconciliation::Uncertain { .. });
    let cleanup_residual = matches!(semantics.cleanup, CleanupStatus::Residual { .. });
    if status_uncertain != effects_uncertain || status_uncertain != cleanup_residual {
        bail!("remote uncertain status and effects require residual cleanup");
    }
    if matches!(semantics.cleanup, CleanupStatus::NotStarted) {
        bail!("remote receipt cannot report cleanup as not started");
    }

    let cleanup_complete_event = semantics
        .events
        .contains(&ExecutorLifecycleEvent::CleanupComplete);
    let cleanup_residual_event = semantics
        .events
        .contains(&ExecutorLifecycleEvent::CleanupResidual);
    match semantics.cleanup {
        CleanupStatus::Complete if !cleanup_complete_event || cleanup_residual_event => {
            bail!("remote complete cleanup lacks one unambiguous completion event");
        }
        CleanupStatus::Residual { .. } if !cleanup_residual_event || cleanup_complete_event => {
            bail!("remote residual cleanup lacks one unambiguous residual event");
        }
        CleanupStatus::NotStarted => unreachable!("rejected above"),
        _ => {}
    }

    let should_be_complete = !semantics.stdout.truncated
        && !semantics.stderr.truncated
        && !status_uncertain
        && !status_timed_out
        && !cleanup_residual;
    if semantics.usage.complete != should_be_complete {
        bail!("remote usage completeness does not match truncation or recovery state");
    }
    if status_timed_out
        && !semantics
            .events
            .contains(&ExecutorLifecycleEvent::TimeoutExpired)
    {
        bail!("remote timeout lacks a timeout lifecycle event");
    }
    Ok(())
}

fn validate_event_sequence(semantics: &ExecutionSemantics) -> Result<()> {
    let events = &semantics.events;
    for (index, event) in events.iter().enumerate() {
        if events[..index].contains(event) {
            bail!("remote lifecycle contains duplicate events");
        }
    }
    if events.get(..3)
        != Some(
            &[
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
            ][..],
        )
    {
        bail!("remote lifecycle must begin with validation, staging, and launch");
    }
    let expected_cleanup = match semantics.cleanup {
        CleanupStatus::Complete => ExecutorLifecycleEvent::CleanupComplete,
        CleanupStatus::Residual { .. } => ExecutorLifecycleEvent::CleanupResidual,
        CleanupStatus::NotStarted => bail!("remote receipt cannot omit terminal cleanup"),
    };
    if events.last() != Some(&expected_cleanup) {
        bail!("remote lifecycle must end with its declared cleanup state");
    }
    let terminal_index = events
        .len()
        .checked_sub(1)
        .context("remote lifecycle has no cleanup event")?;
    let mut cursor = 3usize;
    let trigger = events.get(cursor).copied().filter(|event| {
        matches!(
            event,
            ExecutorLifecycleEvent::CancelRequested | ExecutorLifecycleEvent::TimeoutExpired
        )
    });
    if trigger.is_some() {
        cursor += 1;
    }
    let term_sent = events.get(cursor) == Some(&ExecutorLifecycleEvent::TermSent);
    if term_sent {
        cursor += 1;
    }
    if events.get(cursor) == Some(&ExecutorLifecycleEvent::KillSent) {
        if !term_sent {
            bail!("remote KILL event lacks a preceding TERM event");
        }
        cursor += 1;
    }
    let collected = events.get(cursor) == Some(&ExecutorLifecycleEvent::Collected);
    if collected {
        cursor += 1;
    }
    let reconciled = events.get(cursor) == Some(&ExecutorLifecycleEvent::Reconciled);
    if reconciled {
        if !collected {
            bail!("remote reconciliation event lacks collection");
        }
        cursor += 1;
    }
    if cursor != terminal_index {
        bail!("remote lifecycle contains omitted, out-of-order, or invalid events");
    }

    let cancel_requested = trigger == Some(ExecutorLifecycleEvent::CancelRequested);
    let timed_out = trigger == Some(ExecutorLifecycleEvent::TimeoutExpired);
    match semantics.status {
        ExecutionStatus::Exited { .. } | ExecutionStatus::Failed { .. } => {
            if cancel_requested || timed_out || !collected || !reconciled {
                bail!("remote terminal status lacks an exact collected/reconciled lifecycle");
            }
        }
        ExecutionStatus::Cancelled => {
            if !cancel_requested || timed_out || !term_sent || !collected || !reconciled {
                bail!("remote cancellation lacks ordered request, TERM, collection, or reconciliation");
            }
        }
        ExecutionStatus::TimedOut => {
            if cancel_requested || !timed_out || !term_sent || !collected || !reconciled {
                bail!("remote timeout lacks ordered expiry, TERM, collection, or reconciliation");
            }
        }
        ExecutionStatus::Uncertain { .. } => {
            if reconciled || (trigger.is_some() && !term_sent) {
                bail!("remote uncertain lifecycle overclaims reconciliation or omits control");
            }
        }
        ExecutionStatus::TransportFailed { .. } => {
            bail!("remote receipt cannot contain a transport-failure lifecycle");
        }
    }
    Ok(())
}

fn validate_recovery_target(actual: &RecoveryTarget, expected: &RecoveryTarget) -> Result<()> {
    if actual.assignment_id != expected.assignment_id
        || actual.executor_run_id != expected.executor_run_id
        || actual.host_id != expected.host_id
        || actual.workspace != expected.workspace
        || actual.staged_input_digest != expected.staged_input_digest
    {
        bail!("remote recovery target does not match the submitted execution");
    }
    if let Some(identity) = &actual.remote_process {
        super::validate_opaque_id("remote session id", &identity.session_id)?;
        super::validate_opaque_id("remote process start token", &identity.start_token)?;
        if identity.pid == 0 || identity.pgid == 0 {
            bail!("remote process identity requires nonzero PID and process-group ID");
        }
    }
    Ok(())
}

fn changed_paths(effects: &EffectReconciliation) -> &[String] {
    match effects {
        EffectReconciliation::CandidateOnly { changed_paths } => changed_paths,
        EffectReconciliation::CandidateArtifacts { changed_paths, .. } => changed_paths,
        EffectReconciliation::Uncertain { .. } => &[],
    }
}

fn validate_candidate_artifacts(
    effects: &EffectReconciliation,
    initial_workspace: &WorkspaceManifest,
    expected_recovery: &RecoveryTarget,
    events: &[ExecutorLifecycleEvent],
    limits: &ExecutorLimits,
) -> Result<()> {
    validate_workspace_manifest(initial_workspace, limits)
        .context("submitted workspace manifest is invalid")?;
    match effects {
        EffectReconciliation::CandidateOnly { changed_paths } => {
            if !changed_paths.is_empty() {
                bail!("remote changed paths require typed candidate artifacts");
            }
        }
        EffectReconciliation::CandidateArtifacts {
            changed_paths,
            artifacts,
        } => {
            if changed_paths.is_empty() || artifacts.is_empty() {
                bail!("remote candidate artifacts cannot be empty");
            }
            validate_artifact_bounds(artifacts, limits)?;
            if !events.contains(&ExecutorLifecycleEvent::Collected)
                || !events.contains(&ExecutorLifecycleEvent::Reconciled)
            {
                bail!("remote candidate artifacts lack collection and reconciliation events");
            }
            let artifact_paths: Vec<&str> = artifacts
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect();
            let changed: Vec<&str> = changed_paths.iter().map(String::as_str).collect();
            if artifact_paths != changed {
                bail!("remote candidate artifact paths do not match changed paths in order");
            }
            if changed.windows(2).any(|pair| pair[0] >= pair[1]) {
                bail!("remote candidate artifact paths are not uniquely sorted");
            }
            let mut unique = BTreeSet::new();
            for artifact in artifacts {
                validate_logical_path(&artifact.path)?;
                if !unique.insert(artifact.path.as_str()) {
                    bail!("remote candidate artifact paths contain duplicates");
                }
                match artifact.kind {
                    CandidateArtifactKind::File => {
                        let expected = CandidateArtifact::file(
                            artifact.path.clone(),
                            artifact.contents.clone(),
                            artifact.executable,
                        )?;
                        if artifact.digest != expected.digest {
                            bail!("remote candidate artifact digest does not match its bytes");
                        }
                    }
                    CandidateArtifactKind::Directory | CandidateArtifactKind::Deleted => {
                        if !artifact.contents.is_empty()
                            || artifact.executable
                            || artifact.digest.is_some()
                        {
                            bail!("remote non-file candidate artifact carries file-only fields");
                        }
                    }
                }
            }
            validate_resulting_workspace(initial_workspace, artifacts, limits)?;
        }
        EffectReconciliation::Uncertain { recovery } => {
            validate_recovery_target(recovery, expected_recovery)
                .context("remote uncertain effect recovery target is mismatched")?;
        }
    }
    Ok(())
}

fn validate_resulting_workspace(
    initial: &WorkspaceManifest,
    artifacts: &[CandidateArtifact],
    limits: &ExecutorLimits,
) -> Result<()> {
    let mut resulting: BTreeMap<String, WorkspaceEntry> = initial
        .entries
        .iter()
        .cloned()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    for artifact in artifacts {
        match artifact.kind {
            CandidateArtifactKind::Deleted => {
                if resulting.remove(&artifact.path).is_none() {
                    bail!("remote deletion names an entry absent from the staged workspace");
                }
            }
            CandidateArtifactKind::File | CandidateArtifactKind::Directory => {
                let replacement = WorkspaceEntry {
                    path: artifact.path.clone(),
                    kind: match artifact.kind {
                        CandidateArtifactKind::File => WorkspaceEntryKind::File,
                        CandidateArtifactKind::Directory => WorkspaceEntryKind::Directory,
                        CandidateArtifactKind::Deleted => {
                            bail!("deleted candidate unexpectedly reached replacement handling")
                        }
                    },
                    contents: artifact.contents.clone(),
                    executable: artifact.executable,
                };
                if resulting.get(&artifact.path) == Some(&replacement) {
                    bail!("remote candidate artifact does not change the staged workspace");
                }
                resulting.insert(artifact.path.clone(), replacement);
            }
        }
    }
    let manifest = WorkspaceManifest {
        entries: resulting.into_values().collect(),
    };
    validate_workspace_manifest(&manifest, limits)
        .context("remote candidate artifacts produce an invalid resulting workspace")
}

fn validate_workspace_manifest(
    manifest: &WorkspaceManifest,
    limits: &ExecutorLimits,
) -> Result<()> {
    if manifest.entries.len() > limits.max_workspace_entries {
        bail!("workspace entry count exceeds its configured limit");
    }
    if manifest
        .entries
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        bail!("workspace manifest paths are not uniquely sorted");
    }
    let mut total_bytes = 0usize;
    let entries: BTreeMap<&str, &WorkspaceEntry> = manifest
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    if entries.len() != manifest.entries.len() {
        bail!("workspace manifest contains duplicate paths");
    }
    for entry in &manifest.entries {
        validate_logical_path(&entry.path)?;
        match entry.kind {
            WorkspaceEntryKind::Directory => {
                if !entry.contents.is_empty() || entry.executable {
                    bail!("workspace directory carries file-only fields");
                }
            }
            WorkspaceEntryKind::File => {
                if entry.contents.len() > limits.max_file_bytes {
                    bail!("workspace file exceeds its configured per-file limit");
                }
                total_bytes = total_bytes
                    .checked_add(entry.contents.len())
                    .context("workspace manifest byte count overflowed")?;
                if total_bytes > limits.max_workspace_bytes {
                    bail!("workspace bytes exceed their configured aggregate limit");
                }
            }
        }
        let mut descendant = entry.path.as_str();
        while let Some((parent, _)) = descendant.rsplit_once('/') {
            match entries.get(parent) {
                Some(parent_entry) if parent_entry.kind == WorkspaceEntryKind::Directory => {}
                Some(_) => bail!("workspace entry has a non-directory parent"),
                None => bail!("workspace entry has a missing parent directory"),
            }
            descendant = parent;
        }
    }
    Ok(())
}

pub(crate) fn reconcile_workspace(
    before: &WorkspaceManifest,
    after: &WorkspaceManifest,
    limits: &ExecutorLimits,
) -> Result<EffectReconciliation> {
    let before: BTreeMap<&str, &WorkspaceEntry> = before
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let after: BTreeMap<&str, &WorkspaceEntry> = after
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let paths: BTreeSet<&str> = before.keys().chain(after.keys()).copied().collect();
    let mut artifacts = Vec::new();
    for path in paths {
        let previous = before.get(path).copied();
        let current = after.get(path).copied();
        if previous == current {
            continue;
        }
        let artifact = match current {
            Some(entry) if entry.kind == WorkspaceEntryKind::File => CandidateArtifact::file(
                entry.path.clone(),
                entry.contents.clone(),
                entry.executable,
            )?,
            Some(entry) => CandidateArtifact::directory(entry.path.clone()),
            None => CandidateArtifact::deleted(path.to_string()),
        };
        artifacts.push(artifact);
    }
    if artifacts.is_empty() {
        return Ok(EffectReconciliation::CandidateOnly {
            changed_paths: Vec::new(),
        });
    }
    validate_artifact_bounds(&artifacts, limits)?;
    let changed_paths = artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect();
    Ok(EffectReconciliation::CandidateArtifacts {
        changed_paths,
        artifacts,
    })
}

fn validate_artifact_bounds(
    artifacts: &[CandidateArtifact],
    limits: &ExecutorLimits,
) -> Result<()> {
    if artifacts.len() > limits.max_workspace_entries {
        bail!("candidate artifact count exceeds its configured limit");
    }
    let mut total = 0usize;
    for artifact in artifacts {
        if artifact.contents.len() > limits.max_file_bytes {
            bail!("candidate artifact exceeds its configured per-file limit");
        }
        total = total
            .checked_add(artifact.contents.len())
            .context("candidate artifact byte count overflowed")?;
        if total > limits.max_workspace_bytes {
            bail!("candidate artifacts exceed their configured aggregate limit");
        }
    }
    Ok(())
}

fn validate_capture(field: &str, capture: &CapturedOutput, limit: usize) -> Result<()> {
    if capture.bytes.len() > limit {
        bail!("remote {field} exceeds its configured capture limit");
    }
    Ok(())
}

/// Installed OpenSSH client transport. The only remote command is the fixed,
/// validated helper path; every variable request value is length-framed JSON
/// on stdin and never enters a remote-shell command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSshTransport {
    ssh_binary: PathBuf,
}

impl OpenSshTransport {
    pub fn new(ssh_binary: impl Into<PathBuf>) -> Result<Self> {
        let ssh_binary = ssh_binary.into();
        validate_executable(&ssh_binary)?;
        Ok(Self { ssh_binary })
    }

    pub fn command_arguments(&self, config: &SshConfig) -> Vec<OsString> {
        self.command_arguments_with_trust(config, config.identity_file(), config.known_hosts_file())
    }

    fn command_arguments_with_trust(
        &self,
        config: &SshConfig,
        identity_file: &Path,
        known_hosts_file: &Path,
    ) -> Vec<OsString> {
        let connect_timeout_seconds = config.limits().connect_timeout_millis.div_ceil(1_000);
        let destination = if config.host().contains(':') {
            format!("{}@[{}]", config.user(), config.host())
        } else {
            format!("{}@{}", config.user(), config.host())
        };
        vec![
            "-F".into(),
            null_device().into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "IdentityAgent=none".into(),
            "-o".into(),
            "PasswordAuthentication=no".into(),
            "-o".into(),
            "KbdInteractiveAuthentication=no".into(),
            "-o".into(),
            "NumberOfPasswordPrompts=0".into(),
            "-o".into(),
            "ConnectionAttempts=1".into(),
            "-o".into(),
            OsString::from(format!("ConnectTimeout={connect_timeout_seconds}")),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            OsString::from(format!("UserKnownHostsFile={}", known_hosts_file.display())),
            "-o".into(),
            OsString::from(format!("GlobalKnownHostsFile={}", null_device())),
            "-o".into(),
            "VerifyHostKeyDNS=no".into(),
            "-o".into(),
            "ForwardAgent=no".into(),
            "-o".into(),
            "ClearAllForwardings=yes".into(),
            "-o".into(),
            "PermitLocalCommand=no".into(),
            "-o".into(),
            "ProxyCommand=none".into(),
            "-o".into(),
            "ProxyJump=none".into(),
            "-o".into(),
            "RequestTTY=no".into(),
            "-o".into(),
            "LogLevel=ERROR".into(),
            "-p".into(),
            config.port().to_string().into(),
            "-i".into(),
            identity_file.as_os_str().to_owned(),
            "--".into(),
            destination.into(),
            config.helper_path().into(),
        ]
    }

    fn spawn(&self, config: &SshConfig, trust: &TrustSnapshot) -> std::io::Result<Child> {
        let mut command = Command::new(&self.ssh_binary);
        command.args(self.command_arguments_with_trust(
            config,
            &trust.identity_file,
            &trust.known_hosts_file,
        ));
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("DISPLAY")
            .env("SSH_ASKPASS_REQUIRE", "never");
        configure_process_group(&mut command);
        command.spawn()
    }
}

impl SshTransport for OpenSshTransport {
    fn execute(
        &self,
        config: &SshConfig,
        request: &RemoteExecutionRequest,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteExecutionReply, TransportFailure> {
        if let Err(error) = validate_trust_file("identity_file", config.identity_file(), true) {
            return Err(TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Authentication,
                format!("SSH identity configuration changed or became invalid: {error:#}"),
            ));
        }
        if let Err(error) =
            validate_trust_file("known_hosts_file", config.known_hosts_file(), false)
        {
            return Err(TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::HostKey,
                format!("SSH host-key configuration changed or became invalid: {error:#}"),
            ));
        }
        if let Err(error) = SshConfig::new(config.input.clone()) {
            return Err(TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::TransportRejected,
                format!("SSH endpoint configuration changed or became invalid: {error:#}"),
            ));
        }
        let request_json = serde_json::to_vec(request).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Protocol,
                format!("could not encode SSH helper request: {error}"),
            )
        })?;
        let request_frame =
            encode_frame("REQUEST", &request_json, config.limits().max_request_bytes).map_err(
                |error| {
                    TransportFailure::new(
                        TransportStage::Preflight,
                        TransportFailureKind::Protocol,
                        format!("SSH helper request framing failed: {error:#}"),
                    )
                },
            )?;
        let control_json = serde_json::to_vec(&CancelControl {
            protocol: WIRE_PROTOCOL.to_string(),
            assignment_id: request.assignment_id.clone(),
            executor_run_id: request.executor_run_id.clone(),
            host_id: request.host_id.clone(),
        })
        .map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Protocol,
                format!("could not encode SSH cancellation control: {error}"),
            )
        })?;
        let control_frame =
            encode_frame("CANCEL", &control_json, config.limits().max_request_bytes).map_err(
                |error| {
                    TransportFailure::new(
                        TransportStage::Preflight,
                        TransportFailureKind::Protocol,
                        format!("SSH cancellation framing failed: {error:#}"),
                    )
                },
            )?;

        let receipt_limit = framed_read_limit("RECEIPT", config.limits().max_receipt_bytes)
            .map_err(|error| {
                TransportFailure::new(
                    TransportStage::Preflight,
                    TransportFailureKind::Protocol,
                    format!("SSH helper receipt bound is invalid: {error:#}"),
                )
            })?;

        let trust_snapshot = TrustSnapshot::new(config)?;
        let mut child = self.spawn(config, &trust_snapshot).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Io,
                format!("could not launch explicitly configured OpenSSH: {error}"),
            )
        })?;
        let Some(stdin) = child.stdin.take() else {
            return Err(cleanup_spawned_transport(
                &mut child,
                config.limits(),
                "OpenSSH stdin pipe is unavailable",
            ));
        };
        let Some(stdout) = child.stdout.take() else {
            drop(stdin);
            return Err(cleanup_spawned_transport(
                &mut child,
                config.limits(),
                "OpenSSH stdout pipe is unavailable",
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            drop(stdin);
            drop(stdout);
            return Err(cleanup_spawned_transport(
                &mut child,
                config.limits(),
                "OpenSSH stderr pipe is unavailable",
            ));
        };

        let done = Arc::new(AtomicBool::new(false));
        let writer_done = Arc::clone(&done);
        let writer_cancellation = cancellation.clone();
        let poll = Duration::from_millis(config.limits().poll_interval_millis);
        let writer = thread::spawn(move || {
            write_request_and_control(
                stdin,
                &request_frame,
                &control_frame,
                &writer_cancellation,
                &writer_done,
                poll,
            )
        });
        let stderr_limit = config.limits().max_stderr_bytes;
        let stdout_reader = thread::spawn(move || read_limited(stdout, receipt_limit));
        let stderr_reader = thread::spawn(move || read_limited(stderr, stderr_limit));

        let wait_result = wait_for_ssh(&mut child, cancellation, config.limits());
        done.store(true, Ordering::Release);
        let join_deadline =
            Instant::now() + Duration::from_millis(config.limits().cancellation_grace_millis);
        let writer_result = join_transport_writer_until(writer, join_deadline, poll);
        let stdout_result =
            join_transport_reader_until(stdout_reader, "receipt", join_deadline, poll);
        let stderr_result =
            join_transport_reader_until(stderr_reader, "diagnostics", join_deadline, poll);

        let mut thread_failures = Vec::new();
        match writer_result {
            Ok(Some(())) => {}
            Ok(None) => thread_failures.push("OpenSSH stdin writer did not terminate".to_string()),
            Err(error) => thread_failures.push(error),
        }
        let stdout = match stdout_result {
            Ok(Some(output)) => Some(output),
            Ok(None) => {
                thread_failures.push("OpenSSH receipt reader did not terminate".to_string());
                None
            }
            Err(error) => {
                thread_failures.push(error);
                None
            }
        };
        let stderr = match stderr_result {
            Ok(Some(output)) => Some(output),
            Ok(None) => {
                thread_failures.push("OpenSSH diagnostics reader did not terminate".to_string());
                None
            }
            Err(error) => {
                thread_failures.push(error);
                None
            }
        };

        let status = match wait_result {
            Ok(status) if thread_failures.is_empty() => status,
            Ok(_) => {
                return Err(TransportFailure::new(
                    TransportStage::Cleanup,
                    TransportFailureKind::Io,
                    format!(
                        "OpenSSH pipe cleanup is unproven: {}",
                        thread_failures.join("; ")
                    ),
                ));
            }
            Err(mut failure) => {
                if !thread_failures.is_empty() {
                    failure.reason = format!(
                        "{}; OpenSSH pipe cleanup is unproven: {}",
                        failure.reason,
                        thread_failures.join("; ")
                    );
                }
                return Err(failure);
            }
        };
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            return Err(TransportFailure::new(
                TransportStage::Cleanup,
                TransportFailureKind::Io,
                "OpenSSH pipe collection was unavailable after bounded cleanup",
            ));
        };
        if stdout.truncated {
            return Err(TransportFailure::new(
                TransportStage::Collect,
                TransportFailureKind::Protocol,
                "SSH helper receipt exceeded its pre-allocation limit",
            ));
        }
        if stderr.truncated {
            return Err(TransportFailure::new(
                TransportStage::Collect,
                TransportFailureKind::Protocol,
                "OpenSSH diagnostics exceeded its pre-allocation limit",
            ));
        }
        if !status.success() {
            let diagnostic = String::from_utf8_lossy(&stderr.bytes);
            let (stage, kind, class) = if status.code() == Some(255) {
                (
                    TransportStage::Launch,
                    TransportFailureKind::TransportRejected,
                    "OpenSSH transport",
                )
            } else {
                (
                    TransportStage::Collect,
                    TransportFailureKind::Protocol,
                    "SSH helper",
                )
            };
            return Err(TransportFailure::new(
                stage,
                kind,
                format!("{class} exited without a receipt: {diagnostic}"),
            ));
        }
        let body = decode_frame("RECEIPT", &stdout.bytes, config.limits().max_receipt_bytes)
            .map_err(|error| {
                TransportFailure::new(
                    TransportStage::Collect,
                    TransportFailureKind::Protocol,
                    format!("invalid SSH helper receipt framing: {error:#}"),
                )
            })?;
        serde_json::from_slice(body).map_err(|error| {
            TransportFailure::new(
                TransportStage::Collect,
                TransportFailureKind::Protocol,
                format!("invalid SSH helper receipt: {error}"),
            )
        })
    }
}

struct TrustSnapshot {
    _directory: tempfile::TempDir,
    identity_file: PathBuf,
    known_hosts_file: PathBuf,
}

impl TrustSnapshot {
    fn new(config: &SshConfig) -> std::result::Result<Self, TransportFailure> {
        let identity = read_trust_material("identity_file", config.identity_file(), true).map_err(
            |error| {
                TransportFailure::new(
                    TransportStage::Preflight,
                    TransportFailureKind::Authentication,
                    format!("could not pin SSH identity material: {error:#}"),
                )
            },
        )?;
        let known_hosts = read_trust_material("known_hosts_file", config.known_hosts_file(), false)
            .map_err(|error| {
                TransportFailure::new(
                    TransportStage::Preflight,
                    TransportFailureKind::HostKey,
                    format!("could not pin SSH known-host material: {error:#}"),
                )
            })?;
        let directory = tempfile::Builder::new()
            .prefix("maco-ssh-trust-")
            .tempdir()
            .map_err(|error| {
                TransportFailure::new(
                    TransportStage::Preflight,
                    TransportFailureKind::Io,
                    format!("could not create a private SSH trust directory: {error}"),
                )
            })?;
        let identity_file = directory.path().join("identity");
        let known_hosts_file = directory.path().join("known_hosts");
        validate_trust_path_tokens("identity snapshot", &identity_file).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Authentication,
                format!("SSH identity snapshot path is invalid: {error:#}"),
            )
        })?;
        validate_trust_path_tokens("known-hosts snapshot", &known_hosts_file).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::HostKey,
                format!("SSH known-host snapshot path is invalid: {error:#}"),
            )
        })?;
        write_private_snapshot(&identity_file, &identity).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Authentication,
                format!("could not snapshot the SSH identity: {error:#}"),
            )
        })?;
        write_private_snapshot(&known_hosts_file, &known_hosts).map_err(|error| {
            TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::HostKey,
                format!("could not snapshot SSH known-host data: {error:#}"),
            )
        })?;
        Ok(Self {
            _directory: directory,
            identity_file,
            known_hosts_file,
        })
    }
}

fn read_trust_material(field: &str, path: &Path, private: bool) -> Result<Vec<u8>> {
    validate_trust_file(field, path, private)?;
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect SSH {field} {}", path.display()))?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let mut file = options
        .open(path)
        .with_context(|| format!("could not open SSH {field} without following links"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("could not inspect opened SSH {field}"))?;
    ensure_same_file(&before, &opened)
        .with_context(|| format!("SSH {field} identity changed before snapshot"))?;
    let bounded = u64::try_from(MAX_TRUST_FILE_BYTES)
        .context("SSH trust-file bound does not fit u64")?
        .checked_add(1)
        .context("SSH trust-file bound overflowed")?;
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(bounded)
        .read_to_end(&mut contents)
        .with_context(|| format!("could not read SSH {field}"))?;
    if contents.len() > MAX_TRUST_FILE_BYTES {
        bail!("SSH {field} exceeds its hard byte limit");
    }
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("could not re-check SSH {field} {}", path.display()))?;
    ensure_same_file(&opened, &after)
        .with_context(|| format!("SSH {field} identity changed during snapshot"))?;
    Ok(contents)
}

fn write_private_snapshot(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    configure_private_create(&mut options);
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create private snapshot {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("could not write private snapshot {}", path.display()))?;
    file.flush()
        .with_context(|| format!("could not flush private snapshot {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("could not sync private snapshot {}", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct CancelControl {
    protocol: String,
    assignment_id: String,
    executor_run_id: String,
    host_id: String,
}

fn write_request_and_control(
    mut stdin: impl Write,
    request_frame: &[u8],
    control_frame: &[u8],
    cancellation: &CancellationToken,
    done: &AtomicBool,
    poll: Duration,
) -> std::io::Result<()> {
    stdin.write_all(request_frame)?;
    stdin.flush()?;
    while !done.load(Ordering::Acquire) {
        if cancellation.is_cancelled() {
            stdin.write_all(control_frame)?;
            stdin.flush()?;
            return Ok(());
        }
        thread::sleep(poll);
    }
    Ok(())
}

fn wait_for_ssh(
    child: &mut Child,
    cancellation: &CancellationToken,
    limits: &ExecutorLimits,
) -> std::result::Result<ExitStatus, TransportFailure> {
    let poll = Duration::from_millis(limits.poll_interval_millis);
    let mut cancellation_deadline = None;
    let execution_deadline =
        Instant::now() + Duration::from_millis(limits.execution_timeout_millis);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => match transport_group_is_present(child.id()) {
                Ok(false) => return Ok(status),
                Ok(true) => {
                    return Err(stop_transport_process_tree(
                        child,
                        limits,
                        TransportStage::Cleanup,
                        TransportFailureKind::Io,
                        "OpenSSH exited while descendants retained its process group",
                    ));
                }
                Err(error) => {
                    return Err(stop_transport_process_tree(
                        child,
                        limits,
                        TransportStage::Cleanup,
                        TransportFailureKind::Io,
                        &format!(
                            "could not prove OpenSSH process-group absence after exit: {error}"
                        ),
                    ));
                }
            },
            Ok(None) => {}
            Err(error) => {
                return Err(stop_transport_process_tree(
                    child,
                    limits,
                    TransportStage::Control,
                    TransportFailureKind::Io,
                    &format!("lost OpenSSH process state: {error}"),
                ));
            }
        }
        if cancellation.is_cancelled() && cancellation_deadline.is_none() {
            cancellation_deadline =
                Some(Instant::now() + Duration::from_millis(limits.cancellation_grace_millis));
        }
        let cancellation_expired =
            cancellation_deadline.is_some_and(|deadline| Instant::now() >= deadline);
        let execution_expired = Instant::now() >= execution_deadline;
        if cancellation_expired || execution_expired {
            let (kind, reason) = if cancellation_expired {
                (
                    TransportFailureKind::Cancelled,
                    "remote cancellation was not acknowledged; remote absence is uncertain",
                )
            } else {
                (
                    TransportFailureKind::TimedOut,
                    "remote execution exceeded its deadline; remote absence is uncertain",
                )
            };
            return Err(stop_transport_process_tree(
                child,
                limits,
                TransportStage::Control,
                kind,
                reason,
            ));
        }
        thread::sleep(poll);
    }
}

fn cleanup_spawned_transport(
    child: &mut Child,
    limits: &ExecutorLimits,
    reason: &str,
) -> TransportFailure {
    stop_transport_process_tree(
        child,
        limits,
        TransportStage::Launch,
        TransportFailureKind::Io,
        reason,
    )
}

fn stop_transport_process_tree(
    child: &mut Child,
    limits: &ExecutorLimits,
    stage: TransportStage,
    kind: TransportFailureKind,
    initial: &str,
) -> TransportFailure {
    let poll = Duration::from_millis(limits.poll_interval_millis);
    let process_group = child.id();
    let mut reasons = vec![initial.to_string()];
    if let Err(error) = terminate_transport(child) {
        reasons.push(format!("TERM failed: {error}"));
    }
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_transport_absence(child, process_group, deadline, poll) {
        Ok(true) => {
            reasons.push("transport process tree was reaped after TERM".to_string());
            return TransportFailure::new(stage, kind, reasons.join("; "));
        }
        Ok(false) => reasons.push("transport process tree remained after TERM".to_string()),
        Err(error) => reasons.push(format!("state after TERM was unavailable: {error}")),
    }
    if let Err(error) = kill_transport(child) {
        reasons.push(format!("KILL failed: {error}"));
    }
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_transport_absence(child, process_group, deadline, poll) {
        Ok(true) => reasons.push("transport process tree was reaped after KILL".to_string()),
        Ok(false) => reasons.push("transport process tree remained after KILL".to_string()),
        Err(error) => reasons.push(format!("state after KILL was unavailable: {error}")),
    }
    TransportFailure::new(stage, kind, reasons.join("; "))
}

fn wait_for_transport_absence(
    child: &mut Child,
    process_group: u32,
    deadline: Instant,
    poll: Duration,
) -> std::io::Result<bool> {
    loop {
        let child_exited = child.try_wait()?.is_some();
        let group_absent = !transport_group_is_present(process_group)?;
        if child_exited && group_absent {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(poll);
    }
}

fn encode_frame(kind: &str, body: &[u8], limit: usize) -> Result<Vec<u8>> {
    if body.len() > limit {
        bail!("{kind} body exceeds its configured frame limit");
    }
    let header = format!("{FRAME_PREFIX} {kind} {}\n", body.len());
    let capacity = header
        .len()
        .checked_add(body.len())
        .context("frame length overflowed")?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn framed_read_limit(kind: &str, body_limit: usize) -> Result<usize> {
    let header = format!("{FRAME_PREFIX} {kind} {body_limit}\n");
    header
        .len()
        .checked_add(body_limit)
        .context("framed read limit overflowed")
}

fn decode_frame<'a>(kind: &str, frame: &'a [u8], limit: usize) -> Result<&'a [u8]> {
    let newline = frame
        .iter()
        .position(|byte| *byte == b'\n')
        .context("frame header has no terminator")?;
    let header = std::str::from_utf8(&frame[..newline]).context("frame header is not UTF-8")?;
    let mut fields = header.split(' ');
    if fields.next() != Some(FRAME_PREFIX) || fields.next() != Some(kind) {
        bail!("unexpected frame prefix or kind");
    }
    let length: usize = fields
        .next()
        .context("frame header has no length")?
        .parse()
        .context("frame length is invalid")?;
    if fields.next().is_some() || length > limit {
        bail!("frame header is malformed or exceeds its limit");
    }
    let body = &frame[newline + 1..];
    if body.len() != length {
        bail!("frame body length does not match its header");
    }
    Ok(body)
}

fn read_limited<R: Read>(reader: R, limit: usize) -> Result<CapturedOutput> {
    let bounded = u64::try_from(limit)
        .context("transport read limit does not fit u64")?
        .checked_add(1)
        .context("transport read limit overflowed")?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .take(bounded)
        .read_to_end(&mut bytes)
        .context("could not read OpenSSH pipe")?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn join_transport_reader_until(
    handle: thread::JoinHandle<Result<CapturedOutput>>,
    stream: &str,
    deadline: Instant,
    poll: Duration,
) -> std::result::Result<Option<CapturedOutput>, String> {
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(poll);
    }
    if !handle.is_finished() {
        return Ok(None);
    }
    let output = handle
        .join()
        .map_err(|_| format!("OpenSSH {stream} reader panicked"))?
        .map_err(|error| format!("could not collect OpenSSH {stream}: {error:#}"))?;
    Ok(Some(output))
}

fn join_transport_writer_until(
    handle: thread::JoinHandle<std::io::Result<()>>,
    deadline: Instant,
    poll: Duration,
) -> std::result::Result<Option<()>, String> {
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(poll);
    }
    if !handle.is_finished() {
        return Ok(None);
    }
    handle
        .join()
        .map_err(|_| "OpenSSH stdin writer panicked".to_string())?
        .map_err(|error| format!("OpenSSH request/control write failed: {error}"))?;
    Ok(Some(()))
}

pub(crate) fn build_workspace_manifest(
    root: Option<&Path>,
    limits: &ExecutorLimits,
) -> Result<WorkspaceManifest> {
    let Some(root) = root else {
        return Ok(WorkspaceManifest {
            entries: Vec::new(),
        });
    };
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("could not inspect workspace root {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("executor workspace root must be a non-symlink directory");
    }
    #[cfg(target_os = "linux")]
    {
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let directory = open_workspace_directory(root, &metadata)?;
        walk_workspace_linux(&directory, "", limits, &mut entries, &mut bytes)?;
        let after = fs::symlink_metadata(root)
            .with_context(|| format!("could not re-check workspace root {}", root.display()))?;
        ensure_same_file(&metadata, &after)
            .context("workspace root identity changed while staging")?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(WorkspaceManifest { entries })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (metadata, limits);
        bail!(
            "working-directory workspace staging requires Linux fd-bound path traversal; refusing fallback traversal"
        )
    }
}

pub(crate) fn staged_input_digest(manifest: &WorkspaceManifest) -> Result<String> {
    let encoded =
        serde_json::to_vec(manifest).context("could not encode staged workspace manifest")?;
    Ok(format!(
        "sha256:{}",
        crate::artifacts::state_auth::sha256_hex(&encoded)
    ))
}

#[cfg(target_os = "linux")]
fn walk_workspace_linux(
    directory: &std::fs::File,
    logical_parent: &str,
    limits: &ExecutorLimits,
    entries: &mut Vec<WorkspaceEntry>,
    total_bytes: &mut usize,
) -> Result<()> {
    use std::os::fd::AsRawFd;

    let directory_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    for candidate in fs::read_dir(&directory_path)
        .with_context(|| format!("could not read bound workspace directory {logical_parent}"))?
    {
        let candidate = candidate.context("could not read workspace directory entry")?;
        let name = candidate
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("workspace paths must be valid UTF-8"))?;
        if name.is_empty() || name.contains(['/', '\\']) || matches!(name.as_str(), "." | "..") {
            bail!("workspace path component is invalid");
        }
        let logical = if logical_parent.is_empty() {
            name.clone()
        } else {
            format!("{logical_parent}/{name}")
        };
        validate_logical_path(&logical)?;
        if entries.len() >= limits.max_workspace_entries {
            bail!("workspace entry count exceeds its configured limit");
        }
        let path = directory_path.join(&name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("could not inspect workspace entry {logical}"))?;
        if metadata.file_type().is_symlink() {
            bail!("workspace entry {logical} is a symlink");
        }
        if metadata.is_dir() {
            let child = open_workspace_directory(&path, &metadata)
                .with_context(|| format!("could not bind workspace directory {logical}"))?;
            entries.push(WorkspaceEntry {
                path: logical.clone(),
                kind: WorkspaceEntryKind::Directory,
                contents: Vec::new(),
                executable: false,
            });
            walk_workspace_linux(&child, &logical, limits, entries, total_bytes)?;
            let after = fs::symlink_metadata(&path)
                .with_context(|| format!("could not re-check workspace directory {logical}"))?;
            let opened = child.metadata().with_context(|| {
                format!("could not inspect bound workspace directory {logical}")
            })?;
            ensure_same_file(&opened, &after)
                .with_context(|| format!("workspace directory {logical} changed while staging"))?;
        } else if metadata.is_file() {
            let (contents, executable) = read_workspace_file(&path, &metadata, limits)?;
            *total_bytes = total_bytes
                .checked_add(contents.len())
                .context("workspace byte count overflowed")?;
            if *total_bytes > limits.max_workspace_bytes {
                bail!("workspace bytes exceed their configured aggregate limit");
            }
            entries.push(WorkspaceEntry {
                path: logical,
                kind: WorkspaceEntryKind::File,
                contents,
                executable,
            });
        } else {
            bail!("workspace entry {logical} is not a regular file or directory");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_workspace_directory(path: &Path, before: &fs::Metadata) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(path).with_context(|| {
        format!(
            "could not open workspace directory {} without following links",
            path.display()
        )
    })?;
    let opened = directory
        .metadata()
        .context("could not inspect opened workspace directory")?;
    ensure_same_file(before, &opened)
        .context("workspace directory identity changed before open")?;
    Ok(directory)
}

fn read_workspace_file(
    path: &Path,
    before: &fs::Metadata,
    limits: &ExecutorLimits,
) -> Result<(Vec<u8>, bool)> {
    let declared =
        usize::try_from(before.len()).context("workspace file length does not fit usize")?;
    if declared > limits.max_file_bytes {
        bail!(
            "workspace file {} exceeds its configured limit",
            path.display()
        );
    }
    reject_hard_link(path, before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let mut file = options.open(path).with_context(|| {
        format!(
            "could not open workspace file {} without following links",
            path.display()
        )
    })?;
    let opened = file
        .metadata()
        .context("could not inspect opened workspace file")?;
    ensure_same_file(before, &opened)?;
    reject_hard_link(path, &opened)?;
    let bounded = u64::try_from(limits.max_file_bytes)
        .context("workspace file limit does not fit u64")?
        .checked_add(1)
        .context("workspace file limit overflowed")?;
    let mut contents = Vec::with_capacity(declared.min(limits.max_file_bytes));
    Read::by_ref(&mut file)
        .take(bounded)
        .read_to_end(&mut contents)
        .context("could not read workspace file")?;
    if contents.len() > limits.max_file_bytes {
        bail!("workspace file grew beyond its configured limit while staging");
    }
    let after_opened = file
        .metadata()
        .context("could not re-check opened workspace file")?;
    ensure_stable_file_contents(&opened, &after_opened)?;
    let after = fs::symlink_metadata(path).context("could not re-check workspace file")?;
    ensure_same_file(&opened, &after)?;
    ensure_stable_file_contents(&opened, &after)?;
    Ok((contents, is_executable(&opened)))
}

fn ensure_stable_file_contents(before: &fs::Metadata, after: &fs::Metadata) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        bail!("workspace file contents changed while staging");
    }
    Ok(())
}

fn validate_logical_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('-')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        bail!("remote logical path is not a normalized relative path");
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.starts_with('-')
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        bail!("SSH host must be a bounded literal hostname or address and cannot be option-shaped");
    }
    Ok(())
}

fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user.starts_with('-')
        || user.len() > 128
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("SSH user is invalid or option-shaped");
    }
    Ok(())
}

fn validate_remote_absolute_path(field: &str, path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path.len() > 4096
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'+')
        })
    {
        bail!("SSH {field} must be a normalized absolute path without shell metacharacters");
    }
    Ok(())
}

fn validate_trust_file(field: &str, path: &Path, private: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("SSH {field} must be an absolute path");
    }
    validate_trust_path_tokens(field, path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect SSH {field} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("SSH {field} must be a non-symlink regular file");
    }
    reject_hard_link(path, &metadata)
        .with_context(|| format!("SSH {field} must not be hard-linked"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("SSH {field} {} is not readable", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("could not inspect opened SSH {field}"))?;
    ensure_same_file(&metadata, &opened)
        .with_context(|| format!("SSH {field} identity changed while validating"))?;
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("could not re-check SSH {field} {}", path.display()))?;
    ensure_same_file(&opened, &after)
        .with_context(|| format!("SSH {field} identity changed while validating"))?;
    validate_private_mode(field, &opened, private)?;
    Ok(())
}

fn validate_trust_path_tokens(field: &str, path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .with_context(|| format!("SSH {field} path must be valid UTF-8"))?;
    if text.contains('%')
        || text
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
    {
        bail!("SSH {field} path cannot contain whitespace, control, or '%' expansion tokens");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("SSH {field} path must be normalized");
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("OpenSSH executable must be selected by absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect OpenSSH executable {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("OpenSSH executable must be a non-symlink regular file");
    }
    validate_executable_mode(&metadata)?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_mode(field: &str, metadata: &fs::Metadata, private: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("SSH {field} must be owned by the current user");
    }
    if private && metadata.mode() & 0o077 != 0 {
        bail!("SSH identity_file must not be accessible by group or other users");
    }
    if !private && metadata.mode() & 0o022 != 0 {
        bail!("SSH known_hosts_file must not be writable by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_mode(_field: &str, _metadata: &fs::Metadata, _private: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_executable_mode(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("OpenSSH executable has no executable bit");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_mode(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(not(unix))]
fn configure_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_CLOEXEC);
}

#[cfg(not(unix))]
fn configure_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn reject_hard_link(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        bail!("workspace file {} is hard-linked", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hard_link(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    bail!("race-resistant workspace staging is unavailable on this platform")
}

#[cfg(unix)]
fn ensure_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.file_type() != after.file_type()
    {
        bail!("workspace file identity changed while staging");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<()> {
    if before.len() != after.len() || before.file_type() != after.file_type() {
        bail!("workspace file identity changed while staging");
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

pub(crate) fn new_run_id() -> Result<String> {
    let mut random = [0_u8; 24];
    fill_os_random(&mut random)?;
    let mut encoded = String::with_capacity(4 + random.len() * 2);
    encoded.push_str("run-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").context("could not encode executor run nonce")?;
    }
    Ok(encoded)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        // SAFETY: the remaining mutable slice is valid for the supplied length,
        // and getrandom writes only within that slice.
        let result = unsafe {
            libc::getrandom(
                bytes[filled..].as_mut_ptr().cast(),
                bytes.len().saturating_sub(filled),
                0,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("OS getrandom failed for executor run nonce");
        }
        let read = usize::try_from(result).context("OS random byte count overflowed")?;
        if read == 0 {
            bail!("OS getrandom returned zero bytes for executor run nonce");
        }
        filled = filled
            .checked_add(read)
            .context("OS random fill count overflowed")?;
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    use std::os::unix::{fs::FileTypeExt, fs::OpenOptionsExt};
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .context("could not open OS random source")?;
    if !source
        .metadata()
        .context("could not inspect OS random source")?
        .file_type()
        .is_char_device()
    {
        bail!("OS random source is not a character device");
    }
    source
        .read_exact(bytes)
        .context("could not read executor run nonce from OS random source")
}

#[cfg(windows)]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = u32::try_from(bytes.len()).context("executor nonce exceeds Windows API limit")?;
    // SAFETY: the system-preferred RNG requires a null algorithm handle, and
    // `bytes` is valid for the checked length. NTSTATUS is checked below.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        bail!("BCryptGenRandom failed with NTSTATUS {status:#x}");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn fill_os_random(_bytes: &mut [u8]) -> Result<()> {
    bail!("executor run nonce generation is unsupported on this platform")
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_transport(child: &mut Child) -> std::io::Result<()> {
    signal_transport(child, libc::SIGTERM)
}

#[cfg(not(unix))]
fn terminate_transport(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn kill_transport(child: &mut Child) -> std::io::Result<()> {
    signal_transport(child, libc::SIGKILL)
}

#[cfg(not(unix))]
fn kill_transport(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn signal_transport(child: &Child, signal: i32) -> std::io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| std::io::Error::other("OpenSSH child id does not fit i32"))?;
    let process_id = process_group;
    // SAFETY: the child was created in a process group identified by its
    // observed child id; the negative id cannot target another group.
    let group_result = unsafe { libc::kill(-process_group, signal) };
    let group_error = if group_result == 0 {
        None
    } else {
        let error = std::io::Error::last_os_error();
        (error.raw_os_error() != Some(libc::ESRCH)).then_some(error)
    };
    // The direct child may have escaped its original group. Its PID cannot be
    // reused while this Child remains unreaped, so signal both bound targets.
    // SAFETY: `process_id` names the still-owned direct child.
    let child_result = unsafe { libc::kill(process_id, signal) };
    let child_error = if child_result == 0 {
        None
    } else {
        let error = std::io::Error::last_os_error();
        (error.raw_os_error() != Some(libc::ESRCH)).then_some(error)
    };
    match (group_error, child_error) {
        (None, None) => Ok(()),
        (Some(group), None) => Err(std::io::Error::other(format!(
            "process-group signal failed: {group}"
        ))),
        (None, Some(child)) => Err(std::io::Error::other(format!(
            "direct-child signal failed: {child}"
        ))),
        (Some(group), Some(child)) => Err(std::io::Error::other(format!(
            "process-group signal failed: {group}; direct-child signal failed: {child}"
        ))),
    }
}

#[cfg(unix)]
fn transport_group_is_present(process_group: u32) -> std::io::Result<bool> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| std::io::Error::other("OpenSSH child id does not fit i32"))?;
    // SAFETY: signal 0 only checks the bound process-group identity.
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error),
    }
}

#[cfg(not(unix))]
fn transport_group_is_present(_process_group: u32) -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(windows)]
fn null_device() -> &'static str {
    "NUL"
}

#[cfg(not(any(unix, windows)))]
fn null_device() -> &'static str {
    "/dev/null"
}
