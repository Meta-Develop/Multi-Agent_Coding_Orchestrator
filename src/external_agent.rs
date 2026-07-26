use crate::agent_lifecycle::AgentLaunchMetadata;
use crate::llm::provider::Usage;
use crate::process_runner::{
    read_bounded_regular_file_nofollow, run_process_cancellable, CapturedBytes, EnvironmentMode,
    ExternalCodexProfile, ProcessCancellation, ProcessOutput, ProcessRunError, ProcessSpec,
    ProcessTreeEvidence, SideEffectConfinementEvidence, SideEffectConfinementProfile, StdinMode,
    StreamCapture, StrictOfflineWorkspaceProfile, WorkspaceAccess,
};
use crate::secure_output::{ReservedOutputFile, SecureOutputRoot};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_CAPTURE_LIMIT_BYTES: usize = OUTPUT_CHAR_LIMIT * 4;
const OUTPUT_TEE_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = 1024 * 1024;
const CODEX_MINIMUM_VERSION: (u64, u64, u64) = (0, 138, 0);
const TRUSTED_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";
const OUTER_SYSTEMD_POLICY_ID: &str = "maco_external_codex_outer_systemd_v1";
const INNER_CODEX_POLICY_ID: &str = "maco_external_codex_inner_v1";
const PERMANENT_CONTROL_ROOTS: &[&str] = &[".maco", ".codex"];
const POLICY_CONTROL_ROOTS: &[&str] = &[".agents"];
const POLICY_CONTROL_FILES: &[&str] = &[".gitignore", ".gitattributes", "AGENTS.md", "CLAUDE.md"];
const MAX_WORKTREE_CONTROL_EXCEPTIONS: usize = 128;
const MAX_CODEX_JSONL_EVENT_BYTES: usize = 256 * 1024;
const MAX_CODEX_EVENT_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentCommand {
    pub invocation: ExternalAgentInvocation,
    pub program: PathBuf,
    pub cwd: PathBuf,
    pub prompt: PathBuf,
    pub json_log: PathBuf,
    pub output_last_message: PathBuf,
    pub output_schema: Option<PathBuf>,
    pub timeout: Duration,
    pub workspace_access: WorkspaceAccess,
    pub hidden_roots: Vec<PathBuf>,
    /// Optional model for the primary Codex process. Absence deliberately leaves model selection
    /// to the same runtime defaults used before this field existed.
    pub model: Option<String>,
    /// Optional reasoning effort for the primary Codex process.
    pub reasoning_effort: Option<String>,
    /// Optional lifecycle identity for the long-running provider process. `registry_repo` is the
    /// supervisor repository whose `.maco/agents` state operators inspect, which can differ from
    /// `cwd` when the provider runs inside a linked assignment worktree.
    pub agent_lifecycle: Option<ExternalAgentLifecycleIdentity>,
    /// Exact normalized workspace-relative exceptions to the default read-only policy controls.
    /// Linked-worktree Git metadata and MACO/Codex runtime roots are never writable exceptions.
    pub worktree_control_exceptions: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentLifecycleIdentity {
    pub registry_repo: PathBuf,
    pub role: String,
    pub run_id: String,
    pub task_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAgentInvocation {
    CodexSupervisor,
    CodexConsultant,
    ClaudeConsultant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProgramTrust {
    TrustedSystemCodex,
    ExplicitCustom,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CodexPermissionEvidence {
    pub codex_version: String,
    pub minimum_version: String,
    pub permission_profile: String,
    pub workspace_access: WorkspaceAccess,
    pub network_enabled: bool,
    pub argv_digest: String,
    pub executable_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialBoundary {
    OuterSystemd,
    InnerCodex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDeniedOperation {
    EstablishBoundary,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialRetryability {
    RequiresDeclaredException,
    NotRetryable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct SandboxDenialEvidence {
    pub boundary: SandboxDenialBoundary,
    pub policy_id: String,
    pub operation: SandboxDeniedOperation,
    /// A safe workspace-relative path. Absolute host paths and untrusted free-form paths are never
    /// copied into this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub retryability: SandboxDenialRetryability,
}

impl ExternalAgentCommand {
    pub fn codex(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexSupervisor,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            workspace_access: WorkspaceAccess::ReadWrite,
            hidden_roots: Vec::new(),
            model: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
        }
    }

    pub fn codex_read_only_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            workspace_access: WorkspaceAccess::ReadOnly,
            hidden_roots: Vec::new(),
            model: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
        }
    }

    pub fn claude_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::ClaudeConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            workspace_access: WorkspaceAccess::ReadOnly,
            hidden_roots: Vec::new(),
            model: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
        }
    }

    pub fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.hidden_roots.push(root.into());
        self
    }

    pub fn with_workspace_access(mut self, access: WorkspaceAccess) -> Self {
        self.workspace_access = access;
        self
    }

    pub fn with_model_selection(
        mut self,
        model: Option<String>,
        reasoning_effort: Option<String>,
    ) -> Self {
        self.model = model;
        self.reasoning_effort = reasoning_effort;
        self
    }

    pub fn with_agent_lifecycle(
        mut self,
        registry_repo: impl Into<PathBuf>,
        role: impl Into<String>,
        run_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        self.agent_lifecycle = Some(ExternalAgentLifecycleIdentity {
            registry_repo: registry_repo.into(),
            role: role.into(),
            run_id: run_id.into(),
            task_id: task_id.into(),
        });
        self
    }

    pub fn with_worktree_control_exception(mut self, relative: impl Into<PathBuf>) -> Self {
        self.worktree_control_exceptions.push(relative.into());
        self
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalAgentRun {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    /// Present only after the shared runner starts and closes the owned execution boundary.
    pub process_tree: Option<ProcessTreeEvidence>,
    pub side_effects: Option<SideEffectConfinementEvidence>,
    pub publishable: bool,
    pub program_trust: ExternalProgramTrust,
    pub codex_permissions: Option<CodexPermissionEvidence>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub error: Option<String>,
    /// Descriptor-captured final output. This is deliberately excluded from the public report
    /// surface so callers cannot confuse a tainted pathname with the held capability.
    pub(crate) output_last_message: Option<Vec<u8>>,
}

impl std::fmt::Debug for ExternalAgentRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held_output = self
            .output_last_message
            .as_ref()
            .map(|contents| RedactedByteCount(contents.len()));
        formatter
            .debug_struct("ExternalAgentRun")
            .field("command", &self.command)
            .field("cwd", &self.cwd)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("exit_code", &self.exit_code)
            .field("duration_ms", &self.duration_ms)
            .field("timed_out", &self.timed_out)
            .field("process_tree", &self.process_tree)
            .field("side_effects", &self.side_effects)
            .field("publishable", &self.publishable)
            .field("program_trust", &self.program_trust)
            .field("codex_permissions", &self.codex_permissions)
            .field("sandbox_denials", &self.sandbox_denials())
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("error", &self.error)
            .field("output_last_message", &held_output)
            .finish()
    }
}

struct RedactedByteCount(usize);

impl std::fmt::Debug for RedactedByteCount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "<redacted:{} bytes>", self.0)
    }
}

impl ExternalAgentRun {
    pub fn sandbox_denials(&self) -> &[SandboxDenialEvidence] {
        &self.stdout.run_metadata.sandbox_denials
    }

    pub fn safely_executed(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out
            && self.error.is_none()
            && self
                .process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && self
                .side_effects
                .is_some_and(SideEffectConfinementEvidence::is_verified)
            && self.codex_permissions.is_some()
    }

    pub fn succeeded(&self) -> bool {
        self.safely_executed() && self.publishable
    }

    pub(crate) fn simulation_succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.error.is_none() && !self.publishable
    }

    pub(crate) fn output_last_message(&self) -> Option<&[u8]> {
        self.output_last_message.as_deref()
    }

    /// Exact bounded prefix captured from the owned stdout pipe. The bytes are
    /// private held evidence and are deliberately excluded from serialization.
    pub(crate) fn stdout_bytes(&self) -> &[u8] {
        &self.stdout.bytes
    }

    /// Scratch output may be discarded only when the main target was never
    /// released or its owned process tree is proven empty.
    pub(crate) fn scratch_quiescence_verified(&self) -> bool {
        !self.stdout.target_launch_attempted
            || self
                .process_tree
                .as_ref()
                .is_some_and(|evidence| evidence.is_verified_empty())
    }
}

#[derive(Serialize)]
struct ExternalAgentRunWireRef<'a> {
    command: &'a [String],
    cwd: &'a Path,
    timeout_seconds: u64,
    exit_code: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_tree: &'a Option<ProcessTreeEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    side_effects: &'a Option<SideEffectConfinementEvidence>,
    publishable: bool,
    program_trust: ExternalProgramTrust,
    #[serde(skip_serializing_if = "Option::is_none")]
    codex_permissions: &'a Option<CodexPermissionEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sandbox_denials: &'a Vec<SandboxDenialEvidence>,
    stdout: &'a CapturedOutput,
    stderr: &'a CapturedOutput,
    error: &'a Option<String>,
}

#[derive(Deserialize)]
struct ExternalAgentRunWireOwned {
    command: Vec<String>,
    cwd: PathBuf,
    timeout_seconds: u64,
    exit_code: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    #[serde(default)]
    process_tree: Option<ProcessTreeEvidence>,
    #[serde(default)]
    side_effects: Option<SideEffectConfinementEvidence>,
    publishable: bool,
    program_trust: ExternalProgramTrust,
    #[serde(default)]
    codex_permissions: Option<CodexPermissionEvidence>,
    #[serde(default)]
    sandbox_denials: Vec<SandboxDenialEvidence>,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    error: Option<String>,
}

impl Serialize for ExternalAgentRun {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ExternalAgentRunWireRef {
            command: &self.command,
            cwd: &self.cwd,
            timeout_seconds: self.timeout_seconds,
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            timed_out: self.timed_out,
            process_tree: &self.process_tree,
            side_effects: &self.side_effects,
            publishable: self.publishable,
            program_trust: self.program_trust,
            codex_permissions: &self.codex_permissions,
            sandbox_denials: &self.stdout.run_metadata.sandbox_denials,
            stdout: &self.stdout,
            stderr: &self.stderr,
            error: &self.error,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExternalAgentRun {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ExternalAgentRunWireOwned::deserialize(deserializer)?;
        let mut stdout = wire.stdout;
        stdout.run_metadata.sandbox_denials = wire.sandbox_denials;
        Ok(Self {
            command: wire.command,
            cwd: wire.cwd,
            timeout_seconds: wire.timeout_seconds,
            exit_code: wire.exit_code,
            duration_ms: wire.duration_ms,
            timed_out: wire.timed_out,
            process_tree: wire.process_tree,
            side_effects: wire.side_effects,
            publishable: wire.publishable,
            program_trust: wire.program_trust,
            codex_permissions: wire.codex_permissions,
            stdout,
            stderr: wire.stderr,
            error: wire.error,
            output_last_message: None,
        })
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ExternalAgentRunMetadata {
    sandbox_denials: Vec<SandboxDenialEvidence>,
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapturedOutput {
    pub text: String,
    pub truncated: bool,
    #[serde(skip, default)]
    bytes: Vec<u8>,
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "default_target_launch_attempted"
    )]
    target_launch_attempted: bool,
    /// Private held metadata for the enclosing run. It is serialized only by
    /// `ExternalAgentRun` as the top-level `sandbox_denials` wire field.
    #[serde(skip, default)]
    run_metadata: ExternalAgentRunMetadata,
}

impl std::fmt::Debug for CapturedOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "CapturedOutput {{ text: {:?}, truncated: {:?}, bytes: <redacted:{} bytes> }}",
            self.text,
            self.truncated,
            self.bytes.len()
        )
    }
}

fn default_target_launch_attempted() -> bool {
    true
}

pub fn run_external_agent(spec: &ExternalAgentCommand) -> ExternalAgentRun {
    run_external_agent_cancellable(spec, &ProcessCancellation::new())
}

pub fn run_external_agent_cancellable(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
) -> ExternalAgentRun {
    run_external_agent_runtime(spec, ExternalExecutionRuntime::Verified, cancellation)
}

#[cfg(test)]
pub(crate) fn run_external_agent_nonpublishable_simulation(
    spec: &ExternalAgentCommand,
) -> ExternalAgentRun {
    run_external_agent_nonpublishable_simulation_cancellable(spec, &ProcessCancellation::new())
}

#[cfg(test)]
fn run_external_agent_nonpublishable_simulation_cancellable(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
) -> ExternalAgentRun {
    run_external_agent_runtime(
        spec,
        ExternalExecutionRuntime::NonpublishableSimulation,
        cancellation,
    )
}

fn run_external_agent_runtime(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
    cancellation: &ProcessCancellation,
) -> ExternalAgentRun {
    let started = Instant::now();
    if cancellation.is_cancelled() {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            "external agent was cancelled before executable preflight".to_string(),
        );
    }
    let program_trust = external_program_trust(spec);
    let resolved_program = match resolve_external_program(&spec.program, &spec.cwd) {
        Ok(program) => program,
        Err(error) => {
            return failed_external_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                format!(
                    "failed to resolve external agent executable {}: {error}",
                    spec.program.display()
                ),
            );
        }
    };
    let program_identity = match external_program_identity(&resolved_program) {
        Ok(identity) => identity,
        Err(error) => {
            return failed_external_run(
                spec,
                started,
                command_display(&resolved_program, &[]),
                false,
                format!("failed to capture external executable identity: {error}"),
            );
        }
    };
    if spec.workspace_access == WorkspaceAccess::ReadOnly
        && !spec.worktree_control_exceptions.is_empty()
    {
        return failed_external_run(
            spec,
            started,
            command_display(&resolved_program, &[]),
            false,
            "read-only external agents may not declare writable control exceptions".to_string(),
        );
    }
    let protected_controls = match protected_worktree_controls(spec) {
        Ok(controls) => controls,
        Err(error) => {
            return failed_external_run(
                spec,
                started,
                command_display(&resolved_program, &[]),
                false,
                format!("failed to validate protected worktree controls: {error}"),
            );
        }
    };
    let argv = command_argv_with_controls(spec, &protected_controls);
    let argv_digest = match argv_digest(&argv) {
        Ok(digest) => digest,
        Err(error) => {
            return failed_external_run(
                spec,
                started,
                command_display(&resolved_program, &argv),
                false,
                format!("failed to bind external-agent permission evidence to argv: {error}"),
            );
        }
    };

    let mut report = ExternalAgentRun {
        command: command_display(&resolved_program, &argv),
        cwd: spec.cwd.clone(),
        timeout_seconds: spec.timeout.as_secs(),
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust,
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
        output_last_message: None,
    };

    let codex_version = if runtime == ExternalExecutionRuntime::Verified
        && matches!(
            spec.invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        ) {
        let remaining = spec.timeout.saturating_sub(started.elapsed());
        match preflight_codex_version(&resolved_program, &spec.cwd, remaining, cancellation) {
            Ok(version) => Some(version),
            Err(failure) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.timed_out = failure.timed_out;
                report.error = Some(failure.message);
                return report;
            }
        }
    } else {
        None
    };

    if cancellation.is_cancelled() {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some("external agent was cancelled before target setup".to_string());
        return report;
    }

    if spec.invocation == ExternalAgentInvocation::ClaudeConsultant {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some(
            "external Claude runtime is refused because no enforceable inner read-only permission contract is available"
                .to_string(),
        );
        return report;
    }

    // An explicit executable is useful only as a bounded, strict-offline version diagnostic.
    // Never give it repository-write authority, provider network access, ambient API keys, or a
    // copied Codex auth file. Nonpublishable evidence is not a substitute for preventing the
    // side effect in the first place.
    if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::ExplicitCustom
    {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some(
            "explicit custom executables are limited to a strict-offline version diagnostic; the external target was not started"
                .to_string(),
        );
        return report;
    }

    let agent_lifecycle = match &spec.agent_lifecycle {
        Some(identity) => match AgentLaunchMetadata::new(
            &identity.registry_repo,
            &identity.role,
            &identity.run_id,
            &identity.task_id,
        ) {
            Ok(metadata) => Some(metadata),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!(
                    "failed to prepare external-agent lifecycle identity: {error:#}"
                ));
                return report;
            }
        },
        None => None,
    };

    if let Err(error) = ensure_existing_output_parent(&spec.json_log)
        .and_then(|_| ensure_existing_output_parent(&spec.output_last_message))
        .and_then(|_| match &spec.output_schema {
            Some(path) => ensure_safe_read_target(path),
            None => Ok(()),
        })
        .and_then(|_| ensure_safe_read_target(&spec.prompt))
    {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some(error.to_string());
        return report;
    }

    let output_reservation = match reserve_external_output(&spec.output_last_message) {
        Ok(reservation) => reservation,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(format!("failed to reserve external-agent output: {error}"));
            return report;
        }
    };

    let prompt = match read_bounded_regular_file_nofollow(&spec.prompt, MAX_PROMPT_BYTES) {
        Ok(prompt) => prompt,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(format!(
                "failed to read prompt file {}: {error}",
                spec.prompt.display()
            ));
            return report;
        }
    };

    let codex_auth = if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::TrustedSystemCodex
    {
        match ValidatedCodexAuth::load() {
            Ok(auth) => auth,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!("failed to validate Codex auth source: {error}"));
                return report;
            }
        }
    } else {
        None
    };

    let side_effect_profile = if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::TrustedSystemCodex
    {
        match external_side_effect_profile(
            spec,
            &resolved_program,
            program_trust,
            &protected_controls,
        ) {
            Ok(profile) => Some(profile),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!("failed to prepare external-agent sandbox: {error}"));
                return report;
            }
        }
    } else {
        None
    };
    if let Err(error) =
        validate_external_program_identity(&resolved_program, spec.program == Path::new("codex"))
            .and_then(|()| {
                let current = external_program_identity(&resolved_program)?;
                if current == program_identity {
                    Ok(())
                } else {
                    bail!("external executable identity changed after version preflight")
                }
            })
    {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some(format!(
            "external executable changed before target release: {error}"
        ));
        return report;
    }
    if let Some(auth) = &codex_auth {
        if let Err(error) = auth.verify_source_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(format!(
                "Codex auth source changed before unit setup: {error}"
            ));
            return report;
        }
    }

    let timeout = spec.timeout.saturating_sub(started.elapsed());
    let process_spec = ProcessSpec::direct(
        "external agent",
        &resolved_program,
        argv.clone(),
        &spec.cwd,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(allowed_env(
        spec.invocation,
        program_trust,
    )))
    .with_stdin(StdinMode::Bytes(prompt))
    .with_stdin_limit(MAX_PROMPT_BYTES)
    .with_timeout(Some(timeout))
    .with_stdout(
        StreamCapture::bounded(OUTPUT_CAPTURE_LIMIT_BYTES)
            .tee_to(&spec.json_log)
            .with_tee_limit(OUTPUT_TEE_LIMIT_BYTES),
    );
    let process_spec = match agent_lifecycle {
        Some(metadata) => process_spec.with_agent_lifecycle(metadata),
        None => process_spec,
    };
    let process_spec = match runtime {
        ExternalExecutionRuntime::Verified => {
            let Some(side_effect_profile) = side_effect_profile else {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(
                    "verified external-agent runtime did not prepare a side-effect profile"
                        .to_string(),
                );
                return report;
            };
            let mut verified = process_spec
                .with_private_runtime_home(true)
                .with_private_runtime_codex_home(true)
                .with_side_effect_confinement(side_effect_profile);
            #[cfg(target_os = "linux")]
            if let Some(auth) = codex_auth {
                verified = verified.with_private_runtime_file("auth.json", auth.bytes);
            }
            verified
        }
        #[cfg(test)]
        ExternalExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    };

    if cancellation.is_cancelled() {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some("external agent was cancelled before target start".to_string());
        return report;
    }

    report.stdout.target_launch_attempted = true;
    match run_process_cancellable(process_spec, cancellation) {
        Ok(output) => record_completed_target(
            &mut report,
            output,
            &output_reservation,
            CompletedTargetContext {
                runtime,
                codex_version,
                spec,
                protected_controls: &protected_controls,
                argv_digest: &argv_digest,
                program_identity: &program_identity,
            },
        ),
        Err(error) => {
            report.timed_out = matches!(&error, ProcessRunError::SetupTimeout { .. });
            let mut sandbox_denials = Vec::new();
            if let Some(denial) = sandbox_denial_from_process_error(&error) {
                sandbox_denials.push(denial);
            }
            if let Some(evidence) = error.cancellation_evidence() {
                sandbox_denials.extend(sandbox_denials_from_codex_jsonl(
                    &protected_controls,
                    evidence.stdout.as_bytes(),
                ));
                report.process_tree = Some(evidence.process_tree);
                report.side_effects = Some(evidence.side_effects);
                report.stdout = summarize_output(&evidence.stdout);
                report.stdout.target_launch_attempted = true;
                report.stderr = summarize_output(&evidence.stderr);
            }
            deduplicate_sandbox_denials(&mut sandbox_denials);
            report.stdout.run_metadata.sandbox_denials = sandbox_denials;
            report.error = Some(error.to_string());
        }
    }
    report.duration_ms = duration_millis(started.elapsed());
    report
}

struct CompletedTargetContext<'a> {
    runtime: ExternalExecutionRuntime,
    codex_version: Option<(u64, u64, u64)>,
    spec: &'a ExternalAgentCommand,
    protected_controls: &'a ProtectedWorktreeControls,
    argv_digest: &'a str,
    program_identity: &'a ExternalProgramIdentity,
}

fn record_completed_target(
    report: &mut ExternalAgentRun,
    output: ProcessOutput,
    output_reservation: &ReservedOutputFile,
    context: CompletedTargetContext<'_>,
) {
    let safety_verified = output.safety_evidence_verified();
    let mut sandbox_denials =
        sandbox_denials_from_codex_jsonl(context.protected_controls, output.stdout.as_bytes());
    deduplicate_sandbox_denials(&mut sandbox_denials);
    report.exit_code = output.status.and_then(|status| status.code());
    report.timed_out = output.timed_out;
    report.process_tree = Some(output.process_tree);
    report.side_effects = Some(output.side_effects);
    // Permission evidence describes the verified launch boundary, not the target's exit status.
    // Supervisors consume it as containment evidence even when the assignment itself fails.
    if context.runtime == ExternalExecutionRuntime::Verified
        && report.program_trust == ExternalProgramTrust::TrustedSystemCodex
        && safety_verified
    {
        report.codex_permissions = context.codex_version.map(|version| {
            codex_permission_evidence(
                version,
                context.spec,
                context.argv_digest,
                context.program_identity,
            )
        });
    }
    report.stdout = summarize_output(&output.stdout);
    report.stdout.target_launch_attempted = true;
    report.stdout.run_metadata.sandbox_denials = sandbox_denials;
    report.stderr = summarize_output(&output.stderr);
    report.error = append_external_error(output.stdin_error, output.process_error);
    if output.timed_out {
        report.error = append_external_error(
            report.error.take(),
            Some(format!(
                "external agent timed out after {} seconds",
                context.spec.timeout.as_secs()
            )),
        );
    } else if !output.status.is_some_and(|status| status.success()) {
        let status_error = match output.status.and_then(|status| status.code()) {
            Some(code) => format!("external agent exited with status {code}"),
            None => "external agent terminated without an exit code".to_string(),
        };
        report.error = append_external_error(report.error.take(), Some(status_error));
    }
    match output_reservation.read_bounded(OUTPUT_TEE_LIMIT_BYTES) {
        Ok(bytes) => report.output_last_message = Some(bytes),
        Err(error) => {
            report.error = append_external_error(
                report.error.take(),
                Some(format!(
                    "external-agent output reservation changed: {error}"
                )),
            );
        }
    }
    report.publishable = context.runtime == ExternalExecutionRuntime::Verified
        && safety_verified
        && report.program_trust == ExternalProgramTrust::TrustedSystemCodex
        && report.codex_permissions.is_some()
        && report.exit_code == Some(0)
        && !report.timed_out
        && report.error.is_none();
}

fn deduplicate_sandbox_denials(evidence: &mut Vec<SandboxDenialEvidence>) {
    evidence.sort();
    evidence.dedup();
}

fn failed_external_run(
    spec: &ExternalAgentCommand,
    started: Instant,
    command: Vec<String>,
    timed_out: bool,
    error: String,
) -> ExternalAgentRun {
    ExternalAgentRun {
        command,
        cwd: spec.cwd.clone(),
        timeout_seconds: spec.timeout.as_secs(),
        exit_code: None,
        duration_ms: duration_millis(started.elapsed()),
        timed_out,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: external_program_trust(spec),
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: Some(error),
        output_last_message: None,
    }
}

fn reserve_external_output(path: &Path) -> Result<ReservedOutputFile> {
    let parent = required_parent(path)?;
    let name = path
        .file_name()
        .with_context(|| format!("external output must have a file name: {}", path.display()))?;
    let root = SecureOutputRoot::open_or_create(parent)?;
    root.reserve(name)
}

#[derive(Debug)]
struct CodexPreflightFailure {
    message: String,
    timed_out: bool,
}

fn preflight_codex_version(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
) -> std::result::Result<(u64, u64, u64), CodexPreflightFailure> {
    let program_parent = program.parent().ok_or_else(|| CodexPreflightFailure {
        message: format!(
            "Codex executable has no parent directory: {}",
            program.display()
        ),
        timed_out: false,
    })?;
    let mut environment = BTreeMap::new();
    environment.insert("PATH".to_string(), TRUSTED_PATH.to_string());
    let output = run_process_cancellable(
        ProcessSpec::direct("Codex version preflight", program, ["--version"], cwd, 4096)
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_only(cwd)
                    .with_visible_read_only_root(program_parent),
            ))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(timeout)),
        cancellation,
    )
    .map_err(|error| CodexPreflightFailure {
        timed_out: matches!(error, ProcessRunError::SetupTimeout { .. }),
        message: format!("Codex version preflight failed before target execution: {error}"),
    })?;
    if !output.safety_sensitive_succeeded() {
        return Err(CodexPreflightFailure {
            timed_out: output.timed_out,
            message: format!(
                "Codex version preflight was not safely verified: exit={:?}, process_tree={:?}, side_effects={:?}, error={:?}",
                output.status.and_then(|status| status.code()),
                output.process_tree,
                output.side_effects,
                output.process_error
            ),
        });
    }
    let stdout = output.stdout.summarize_chars(4096).text;
    let stderr = output.stderr.summarize_chars(4096).text;
    let version_text = format!("{stdout}\n{stderr}");
    let version = parse_codex_version(&version_text).ok_or_else(|| CodexPreflightFailure {
        message:
            "Codex version preflight returned an unknown version; 0.138.0 or newer is required"
                .to_string(),
        timed_out: false,
    })?;
    if version < CODEX_MINIMUM_VERSION {
        return Err(CodexPreflightFailure {
            message: format!(
                "Codex {}.{}.{} is too old; 0.138.0 or newer custom permissions are required",
                version.0, version.1, version.2
            ),
            timed_out: false,
        });
    }
    Ok(version)
}

fn parse_codex_version(text: &str) -> Option<(u64, u64, u64)> {
    if !text.to_ascii_lowercase().contains("codex") {
        return None;
    }
    text.split_whitespace().find_map(|word| {
        let candidate =
            word.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        let mut components = candidate.split('.');
        let major = components.next()?.parse().ok()?;
        let minor = components.next()?.parse().ok()?;
        let patch = components.next()?.parse().ok()?;
        components.next().is_none().then_some((major, minor, patch))
    })
}

fn external_program_trust(spec: &ExternalAgentCommand) -> ExternalProgramTrust {
    if spec.program == Path::new("codex") {
        ExternalProgramTrust::TrustedSystemCodex
    } else {
        ExternalProgramTrust::ExplicitCustom
    }
}

fn codex_permission_evidence(
    version: (u64, u64, u64),
    spec: &ExternalAgentCommand,
    argv_digest: &str,
    identity: &ExternalProgramIdentity,
) -> CodexPermissionEvidence {
    CodexPermissionEvidence {
        codex_version: format!("{}.{}.{}", version.0, version.1, version.2),
        minimum_version: format!(
            "{}.{}.{}",
            CODEX_MINIMUM_VERSION.0, CODEX_MINIMUM_VERSION.1, CODEX_MINIMUM_VERSION.2
        ),
        permission_profile: "maco_external_codex".to_string(),
        workspace_access: spec.workspace_access,
        network_enabled: false,
        argv_digest: argv_digest.to_string(),
        executable_identity: identity.display(),
    }
}

fn argv_digest(argv: &[OsString]) -> Result<String> {
    let mut bytes = b"maco-external-agent-argv-v2\0".to_vec();
    let encoding = os_argument_encoding_tag();
    bytes.extend_from_slice(&(encoding.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoding);
    bytes.extend_from_slice(&(argv.len() as u64).to_be_bytes());
    for argument in argv {
        let argument = os_argument_bytes(argument.as_os_str());
        bytes.extend_from_slice(&(argument.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&argument);
    }
    git2::Oid::hash_object(git2::ObjectType::Blob, &bytes)
        .map(|oid| oid.to_string())
        .context("failed to hash external-agent argv")
}

#[cfg(unix)]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"unix-bytes"
}

#[cfg(target_os = "windows")]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"windows-utf16le"
}

#[cfg(not(any(unix, target_os = "windows")))]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"portable-lossy-utf8"
}

fn resolve_external_program(program: &Path, cwd: &Path) -> Result<PathBuf> {
    let require_root_owned = program == Path::new("codex");
    let candidate = if require_root_owned {
        [
            "/run/current-system/sw/bin/codex",
            "/usr/bin/codex",
            "/bin/codex",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
        .context("trusted Codex executable was not found at a fixed system path")?
    } else if program.is_absolute() {
        if fs::symlink_metadata(program)?.file_type().is_symlink() {
            bail!(
                "explicit external executable may not be a symlink: {}",
                program.display()
            );
        }
        program.to_path_buf()
    } else {
        bail!(
            "explicit external executable must be an absolute path; ambient PATH and relative resolution are refused (requested {} from {})",
            program.display(),
            cwd.display()
        );
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("failed to canonicalize {}", candidate.display()))?;
    validate_external_program_identity(&canonical, require_root_owned)?;
    Ok(canonical)
}

fn validate_external_program_identity(path: &Path, require_root_owned: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "external executable is not a non-symlink regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            bail!(
                "external executable must be executable and not group/world-writable: {}",
                path.display()
            );
        }
        if require_root_owned && metadata.uid() != 0 {
            bail!(
                "default Codex executable must be root-owned: {}",
                path.display()
            );
        }
        for ancestor in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor).with_context(|| {
                format!(
                    "failed to inspect executable ancestor {}",
                    ancestor.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "external executable ancestor may not be a symlink: {}",
                    ancestor.display()
                );
            }
            let mode = metadata.permissions().mode();
            let root_sticky_directory =
                metadata.uid() == 0 && metadata.is_dir() && mode & libc::S_ISVTX != 0;
            if (require_root_owned || !root_sticky_directory) && mode & 0o022 != 0 {
                bail!(
                    "external executable ancestor is group/world-writable: {}",
                    ancestor.display()
                );
            }
            if require_root_owned && metadata.uid() != 0 {
                bail!(
                    "default Codex executable ancestor is not root-owned: {}",
                    ancestor.display()
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalProgramIdentity {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ExternalProgramIdentity {
    fn display(&self) -> String {
        let modified = self
            .modified
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        #[cfg(unix)]
        {
            format!(
                "dev={};ino={};len={};mtime_ns={modified}",
                self.device, self.inode, self.length
            )
        }
        #[cfg(not(unix))]
        {
            format!("len={};mtime_ns={modified}", self.length)
        }
    }
}

fn external_program_identity(path: &Path) -> Result<ExternalProgramIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect executable identity {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("external executable identity is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(ExternalProgramIdentity {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(ExternalProgramIdentity {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProtectedWorktreeControls {
    read_only_roots: Vec<ProtectedWorktreeControl>,
    read_only_files: Vec<ProtectedWorktreeControl>,
    read_write_roots: Vec<ProtectedWorktreeControl>,
    read_write_files: Vec<ProtectedWorktreeControl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedWorktreeControl {
    absolute: PathBuf,
    relative: PathBuf,
    retryability: SandboxDenialRetryability,
}

impl ProtectedWorktreeControls {
    fn iter(&self) -> impl Iterator<Item = &ProtectedWorktreeControl> {
        self.read_only_roots
            .iter()
            .chain(&self.read_only_files)
            .chain(&self.read_write_roots)
            .chain(&self.read_write_files)
    }
}

fn protected_worktree_controls(spec: &ExternalAgentCommand) -> Result<ProtectedWorktreeControls> {
    protected_worktree_controls_for(&spec.cwd, &spec.worktree_control_exceptions)
}

fn protected_worktree_controls_for(
    workspace: &Path,
    declared_exceptions: &[PathBuf],
) -> Result<ProtectedWorktreeControls> {
    if declared_exceptions.len() > MAX_WORKTREE_CONTROL_EXCEPTIONS {
        bail!(
            "worktree control exception count exceeds the fail-closed limit of {MAX_WORKTREE_CONTROL_EXCEPTIONS}"
        );
    }
    let mut controls = ProtectedWorktreeControls::default();
    collect_protected_control(
        workspace,
        Path::new(".git"),
        SandboxDenialRetryability::NotRetryable,
        &mut controls,
    )?;
    for relative in PERMANENT_CONTROL_ROOTS {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::NotRetryable,
            &mut controls,
        )?;
    }
    for relative in POLICY_CONTROL_ROOTS {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::RequiresDeclaredException,
            &mut controls,
        )?;
    }
    for relative in POLICY_CONTROL_FILES {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::RequiresDeclaredException,
            &mut controls,
        )?;
    }

    let mut normalized_exceptions = Vec::with_capacity(declared_exceptions.len());
    for declared in declared_exceptions {
        let relative = normalize_control_exception(declared)?;
        validate_control_exception_target(workspace, &relative)?;
        if normalized_exceptions.iter().any(|existing: &PathBuf| {
            existing == &relative
                || existing.starts_with(&relative)
                || relative.starts_with(existing)
        }) {
            bail!(
                "worktree control exceptions may not duplicate or overlap: {}",
                relative.display()
            );
        }
        normalized_exceptions.push(relative);
    }
    for relative in normalized_exceptions {
        controls
            .read_only_roots
            .retain(|control| control.relative != relative);
        controls
            .read_only_files
            .retain(|control| control.relative != relative);
        collect_control_exception(workspace, &relative, &mut controls)?;
    }
    controls.read_only_roots.sort_by(control_path_order);
    controls.read_only_files.sort_by(control_path_order);
    controls.read_write_roots.sort_by(control_path_order);
    controls.read_write_files.sort_by(control_path_order);
    Ok(controls)
}

fn control_path_order(
    left: &ProtectedWorktreeControl,
    right: &ProtectedWorktreeControl,
) -> std::cmp::Ordering {
    left.absolute.cmp(&right.absolute)
}

fn collect_protected_control(
    workspace: &Path,
    relative: &Path,
    retryability: SandboxDenialRetryability,
    controls: &mut ProtectedWorktreeControls,
) -> Result<()> {
    let path = workspace.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect worktree control {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "protected worktree control may not be a symlink: {}",
            path.display()
        );
    }
    let control = ProtectedWorktreeControl {
        absolute: path,
        relative: relative.to_path_buf(),
        retryability,
    };
    if metadata.is_dir() {
        controls.read_only_roots.push(control);
    } else if metadata.is_file() {
        controls.read_only_files.push(control);
    } else {
        bail!(
            "protected worktree control is not a regular file or directory: {}",
            control.absolute.display()
        );
    }
    Ok(())
}

fn normalize_control_exception(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!(
            "worktree control exception must be a non-empty workspace-relative path: {}",
            path.display()
        );
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir => {
                bail!(
                    "worktree control exception must already be normalized: {}",
                    path.display()
                );
            }
            std::path::Component::ParentDir => {
                bail!(
                    "worktree control exception may not contain '..': {}",
                    path.display()
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!(
                    "worktree control exception must be workspace-relative: {}",
                    path.display()
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() || normalized == Path::new(".") {
        bail!("worktree control exception may not be empty or '.'");
    }
    if normalized.to_str().is_none() {
        bail!("worktree control exception must be valid UTF-8 for Codex permissions");
    }
    Ok(normalized)
}

fn validate_control_exception_target(workspace: &Path, relative: &Path) -> Result<()> {
    if relative.starts_with(".git")
        || PERMANENT_CONTROL_ROOTS
            .iter()
            .any(|root| relative.starts_with(root))
    {
        bail!(
            "worktree control is permanently read-only and cannot be excepted: {}",
            relative.display()
        );
    }
    let protected_policy_path = POLICY_CONTROL_ROOTS
        .iter()
        .any(|root| relative.starts_with(root))
        || POLICY_CONTROL_FILES
            .iter()
            .any(|file| relative == Path::new(file));
    if !protected_policy_path {
        bail!(
            "worktree control exception is outside the protected policy set: {}",
            relative.display()
        );
    }

    let mut current = workspace.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!(
                "worktree control exception is not normalized: {}",
                relative.display()
            );
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "worktree control exception must name an existing path: {}",
                relative.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "worktree control exception may not traverse or name a symlink: {}",
                relative.display()
            );
        }
    }
    let metadata = fs::symlink_metadata(&current)?;
    if !metadata.is_file() && !metadata.is_dir() {
        bail!(
            "worktree control exception must name a regular file or directory: {}",
            relative.display()
        );
    }
    Ok(())
}

fn collect_control_exception(
    workspace: &Path,
    relative: &Path,
    controls: &mut ProtectedWorktreeControls,
) -> Result<()> {
    let absolute = workspace.join(relative);
    let metadata = fs::symlink_metadata(&absolute)?;
    let control = ProtectedWorktreeControl {
        absolute,
        relative: relative.to_path_buf(),
        retryability: SandboxDenialRetryability::NotRetryable,
    };
    if metadata.is_dir() {
        controls.read_write_roots.push(control);
    } else {
        controls.read_write_files.push(control);
    }
    Ok(())
}

fn external_side_effect_profile(
    spec: &ExternalAgentCommand,
    program: &Path,
    program_trust: ExternalProgramTrust,
    protected_controls: &ProtectedWorktreeControls,
) -> Result<SideEffectConfinementProfile> {
    if program_trust != ExternalProgramTrust::TrustedSystemCodex {
        bail!("provider-network confinement is reserved for the trusted system Codex executable");
    }
    let program_parent = program
        .parent()
        .with_context(|| format!("executable has no parent: {}", program.display()))?;
    // The parent tee owns and holds `json_log`; the child never needs that directory writable.
    // Only the isolated incoming final-message directory is exposed as a child artifact root.
    let artifact_roots = [required_parent(&spec.output_last_message)?];
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant => {
            let mut profile = match spec.workspace_access {
                WorkspaceAccess::ReadOnly => ExternalCodexProfile::read_only(&spec.cwd),
                WorkspaceAccess::ReadWrite => ExternalCodexProfile::read_write(&spec.cwd),
            };
            for control in &protected_controls.read_only_roots {
                profile = profile.with_visible_read_only_root(&control.absolute);
            }
            for control in &protected_controls.read_only_files {
                profile = profile.with_visible_read_only_file(&control.absolute);
            }
            for control in &protected_controls.read_write_roots {
                profile = profile.with_visible_read_write_root(&control.absolute);
            }
            for control in &protected_controls.read_write_files {
                profile = profile.with_visible_read_write_file(&control.absolute);
            }
            let canonical_workspace = fs::canonicalize(&spec.cwd)?;
            if !program.starts_with(&canonical_workspace) {
                profile = profile.with_visible_read_only_root(program_parent);
            }
            if let Some(schema) = &spec.output_schema {
                profile = profile.with_visible_read_only_file(schema);
            }
            for root in artifact_roots {
                profile = profile.with_writable_artifact_root(root);
            }
            for root in &spec.hidden_roots {
                profile = profile.with_hidden_root(root);
            }
            Ok(SideEffectConfinementProfile::ExternalCodex(profile))
        }
        ExternalAgentInvocation::ClaudeConsultant => {
            bail!("Claude consultant has no enforceable fixed-network capability")
        }
    }
}

fn sandbox_denials_from_codex_jsonl(
    controls: &ProtectedWorktreeControls,
    jsonl: &[u8],
) -> Vec<SandboxDenialEvidence> {
    let mut evidence = BTreeSet::new();
    for line in jsonl.split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_CODEX_JSONL_EVENT_BYTES {
            continue;
        }
        let Ok(event) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let Some((command, output)) = failed_command_event_fields(&event) else {
            continue;
        };
        if !contains_sandbox_denial_marker(output) {
            continue;
        }
        let mut known = controls.iter().collect::<Vec<_>>();
        known.sort_by(|left, right| {
            right
                .relative
                .as_os_str()
                .len()
                .cmp(&left.relative.as_os_str().len())
        });
        for control in known {
            let Some(relative) = control.relative.to_str() else {
                continue;
            };
            let Some(absolute) = control.absolute.to_str() else {
                continue;
            };
            if [command, output].iter().any(|text| {
                contains_exact_path(text, relative) || contains_exact_path(text, absolute)
            }) {
                evidence.insert(SandboxDenialEvidence {
                    boundary: SandboxDenialBoundary::InnerCodex,
                    policy_id: INNER_CODEX_POLICY_ID.to_string(),
                    operation: SandboxDeniedOperation::Write,
                    path: Some(control.relative.clone()),
                    retryability: control.retryability,
                });
                break;
            }
        }
    }
    evidence.into_iter().collect()
}

fn failed_command_event_fields(event: &serde_json::Value) -> Option<(&str, &str)> {
    if event.get("type")?.as_str()? != "item.completed" {
        return None;
    }
    let item = event.get("item")?.as_object()?;
    if item.get("id")?.as_str()?.is_empty()
        || item.get("type")?.as_str()? != "command_execution"
        || item.get("status")?.as_str()? != "failed"
        || item.get("exit_code")?.as_i64()? == 0
    {
        return None;
    }
    let command = item.get("command")?.as_str()?;
    let output = item.get("aggregated_output")?.as_str()?;
    (command.len() <= MAX_CODEX_EVENT_TEXT_BYTES && output.len() <= MAX_CODEX_EVENT_TEXT_BYTES)
        .then_some((command, output))
}

fn contains_exact_path(text: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    text.match_indices(path).any(|(offset, matched)| {
        let before = text[..offset].chars().next_back();
        let after = text[offset + matched.len()..].chars().next();
        !before.is_some_and(is_path_character) && !after.is_some_and(is_path_character)
    })
}

fn is_path_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | '/' | '\\')
}

fn sandbox_denial_from_process_error(error: &ProcessRunError) -> Option<SandboxDenialEvidence> {
    matches!(
        error,
        ProcessRunError::ContainmentUnavailable { .. } | ProcessRunError::ProcessOwnership { .. }
    )
    .then(|| SandboxDenialEvidence {
        boundary: SandboxDenialBoundary::OuterSystemd,
        policy_id: OUTER_SYSTEMD_POLICY_ID.to_string(),
        operation: SandboxDeniedOperation::EstablishBoundary,
        path: None,
        retryability: SandboxDenialRetryability::NotRetryable,
    })
}

fn contains_sandbox_denial_marker(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "permission denied",
        "read-only file system",
        "operation not permitted",
        "sandbox denied",
        "sandbox_denied",
        "denied by sandbox",
        "denied by policy",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn required_parent(path: &Path) -> Result<&Path> {
    path.parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))
}

#[derive(Debug)]
struct ValidatedCodexAuth {
    path: PathBuf,
    bytes: Vec<u8>,
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ValidatedCodexAuth {
    fn load() -> Result<Option<Self>> {
        let Some(home) = env::var_os("CODEX_HOME").map(PathBuf::from).or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".codex"))
        }) else {
            return Ok(None);
        };
        Self::load_from_home(&home)
    }

    fn load_from_home(home: &Path) -> Result<Option<Self>> {
        if !home.is_absolute() {
            bail!("Codex auth home must be absolute: {}", home.display());
        }
        match fs::symlink_metadata(home) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!(
                    "Codex auth home must be a non-symlink directory: {}",
                    home.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("failed to inspect Codex auth home"),
        }
        ensure_existing_directory_without_symlinks(home)?;
        let path = home.join("auth.json");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("Codex auth file may not be a symlink: {}", path.display());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("failed to inspect Codex auth file"),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("failed to open Codex auth file {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_PROMPT_BYTES as u64 {
            bail!(
                "Codex auth file must be a bounded regular file: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                bail!(
                    "Codex auth file must be current-user-owned, single-link, and mode 0600 or stricter: {}",
                    path.display()
                );
            }
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take((MAX_PROMPT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PROMPT_BYTES {
            bail!("Codex auth file grew beyond the bounded read limit");
        }
        let after = file.metadata()?;
        if after.len() != metadata.len() || after.modified().ok() != metadata.modified().ok() {
            bail!("Codex auth file changed while it was read");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if after.dev() != metadata.dev() || after.ino() != metadata.ino() {
                bail!("Codex auth file identity changed while it was read");
            }
            Ok(Some(Self {
                path,
                bytes,
                length: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        #[cfg(not(unix))]
        {
            bail!("verified Codex auth injection is not implemented on this platform")
        }
    }

    fn verify_source_unchanged(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != self.length
            || metadata.modified().ok() != self.modified
        {
            bail!("Codex auth file metadata changed");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.nlink() != 1
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
            {
                bail!("Codex auth file ownership, links, mode, or inode changed");
            }
        }
        Ok(())
    }
}

fn ensure_safe_read_target(path: &Path) -> Result<()> {
    ensure_existing_output_parent(path)?;
    read_bounded_regular_file_nofollow(path, MAX_PROMPT_BYTES)
        .map(|_| ())
        .with_context(|| format!("unsafe external-agent input {}", path.display()))
}

fn append_external_error(existing: Option<String>, next: Option<String>) -> Option<String> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(format!("{existing}; {next}")),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

#[cfg(test)]
pub(crate) fn command_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let controls = protected_worktree_controls(spec).unwrap_or_default();
    command_argv_with_controls(spec, &controls)
}

fn command_argv_with_controls(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor => codex_supervisor_argv(spec, controls),
        ExternalAgentInvocation::CodexConsultant => codex_consultant_argv(spec, controls),
        ExternalAgentInvocation::ClaudeConsultant => claude_consultant_argv(),
    }
}

fn codex_supervisor_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    let mut argv = codex_hardened_argv(spec, controls);
    argv.extend([
        OsString::from("--enable"),
        OsString::from("goals"),
        OsString::from("--enable"),
        OsString::from("multi_agent"),
        OsString::from("--json"),
        OsString::from("--output-last-message"),
        spec.output_last_message.as_os_str().to_os_string(),
    ]);
    if let Some(schema) = &spec.output_schema {
        argv.push(OsString::from("--output-schema"));
        argv.push(schema.as_os_str().to_os_string());
    }
    argv.push(OsString::from("-"));
    argv
}

fn codex_consultant_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    let mut argv = codex_hardened_argv(spec, controls);
    argv.extend([
        OsString::from("--output-last-message"),
        spec.output_last_message.as_os_str().to_os_string(),
        OsString::from("-"),
    ]);
    argv
}

fn codex_hardened_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    let filesystem_permissions = codex_filesystem_permissions(spec, controls);
    let mut argv = vec![
        OsString::from("-a"),
        OsString::from("never"),
        OsString::from("exec"),
        OsString::from("--strict-config"),
        OsString::from("--ignore-user-config"),
        OsString::from("--ignore-rules"),
        OsString::from("--ephemeral"),
        OsString::from("--cd"),
        spec.cwd.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from("default_permissions=\"maco_external_codex\""),
        OsString::from("-c"),
        OsString::from("permissions.maco_external_codex.network={enabled=false}"),
        OsString::from("-c"),
        OsString::from(filesystem_permissions),
        OsString::from("-c"),
        OsString::from("shell_environment_policy.inherit=\"none\""),
        OsString::from("-c"),
        OsString::from(
            "shell_environment_policy.set={PATH=\"/run/current-system/sw/bin:/usr/bin:/bin\"}",
        ),
        OsString::from("-c"),
        OsString::from("web_search=\"disabled\""),
    ];
    for feature in [
        "apps",
        "plugins",
        "hooks",
        "in_app_browser",
        "browser_use",
        "browser_use_full_cdp_access",
        "browser_use_external",
        "computer_use",
        "image_generation",
    ] {
        argv.push(OsString::from("--disable"));
        argv.push(OsString::from(feature));
    }
    if let Some(model) = &spec.model {
        argv.push(OsString::from("-m"));
        argv.push(OsString::from(model));
    }
    if let Some(reasoning_effort) = &spec.reasoning_effort {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model_reasoning_effort={}",
            toml_basic_string(reasoning_effort)
        )));
    }
    argv
}

fn codex_filesystem_permissions(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> String {
    let mut path_permissions = BTreeMap::<String, &'static str>::new();
    for control in controls
        .read_only_roots
        .iter()
        .chain(&controls.read_only_files)
    {
        if let Some(relative) = control.relative.to_str() {
            path_permissions.insert(relative.to_string(), "read");
        }
    }
    for control in controls
        .read_write_roots
        .iter()
        .chain(&controls.read_write_files)
    {
        if let Some(relative) = control.relative.to_str() {
            path_permissions.insert(relative.to_string(), "write");
        }
    }
    if let Some(parent) = spec
        .output_last_message
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let permission_path = parent
            .strip_prefix(&spec.cwd)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or(parent);
        if let Some(path) = permission_path.to_str() {
            path_permissions.insert(path.to_string(), "write");
        }
    }

    let mut entries = vec!["\":minimal\"=\"read\"".to_string()];
    if spec.workspace_access == WorkspaceAccess::ReadWrite {
        entries.push("\":workspace_roots\"={\".\"=\"write\"}".to_string());
    }
    entries.extend(path_permissions.into_iter().map(|(path, access)| {
        format!("{}={}", toml_basic_string(&path), toml_basic_string(access))
    }));
    format!(
        "permissions.maco_external_codex.filesystem={{{}}}",
        entries.join(",")
    )
}

fn toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len().saturating_add(2));
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\u{0008}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\u{000c}' => escaped.push_str("\\f"),
            '\r' => escaped.push_str("\\r"),
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            character if character.is_control() && u32::from(character) <= 0xffff => {
                escaped.push_str(&format!("\\u{:04X}", u32::from(character)));
            }
            character if character.is_control() => {
                escaped.push_str(&format!("\\U{:08X}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

pub(crate) fn codex_usage_from_jsonl(bytes: &[u8]) -> Result<Option<Usage>> {
    let contents =
        std::str::from_utf8(bytes).context("Codex JSONL usage capture is not valid UTF-8")?;
    let mut aggregate = Usage::default();
    let mut observed = false;
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "Codex JSONL usage capture line {} is not valid JSON",
                index.saturating_add(1)
            )
        })?;
        if event.get("type").and_then(serde_json::Value::as_str) != Some("turn.completed") {
            continue;
        }
        let usage = event
            .get("usage")
            .and_then(serde_json::Value::as_object)
            .context("Codex turn.completed event omitted its usage object")?;
        let input_tokens = usage
            .get("input_tokens")
            .and_then(serde_json::Value::as_u64)
            .context("Codex turn.completed usage omitted input_tokens")?;
        let output_tokens = usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64)
            .context("Codex turn.completed usage omitted output_tokens")?;
        let usage = Usage {
            input_tokens: usize::try_from(input_tokens)
                .context("Codex input token count does not fit this platform")?,
            output_tokens: usize::try_from(output_tokens)
                .context("Codex output token count does not fit this platform")?,
            total_tokens: 0,
        };
        aggregate = aggregate.saturating_add(usage);
        observed = true;
    }
    Ok(observed.then_some(aggregate))
}

fn claude_consultant_argv() -> Vec<OsString> {
    vec![
        OsString::from("-p"),
        OsString::from("--output-format"),
        OsString::from("json"),
    ]
}

fn allowed_env(
    invocation: ExternalAgentInvocation,
    program_trust: ExternalProgramTrust,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ]);
    if program_trust == ExternalProgramTrust::TrustedSystemCodex
        && matches!(
            invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        )
    {
        for key in ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] {
            if let Ok(value) = env::var(key) {
                if !value.is_empty() && !value.contains(['\n', '\r', '\0']) {
                    environment.insert(key.to_string(), value);
                }
            }
        }
    }
    environment.insert("PATH".to_string(), TRUSTED_PATH.to_string());
    let trusted_ca = Path::new("/etc/ssl/certs/ca-bundle.crt");
    if trusted_ca.is_file() {
        environment.insert(
            "SSL_CERT_FILE".to_string(),
            trusted_ca.display().to_string(),
        );
        environment.insert(
            "NIX_SSL_CERT_FILE".to_string(),
            trusted_ca.display().to_string(),
        );
    }
    environment
}

fn command_display(program: &Path, argv: &[OsString]) -> Vec<String> {
    let mut command = Vec::with_capacity(argv.len() + 1);
    command.push(display_os_argument(program.as_os_str()));
    command.extend(
        argv.iter()
            .map(|argument| display_os_argument(argument.as_os_str())),
    );
    command
}

#[cfg(unix)]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    argument.as_bytes().to_vec()
}

#[cfg(target_os = "windows")]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    argument.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, target_os = "windows")))]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    argument.to_string_lossy().as_bytes().to_vec()
}

fn display_os_argument(argument: &OsStr) -> String {
    argument.to_str().map(str::to_string).unwrap_or_else(|| {
        let bytes = os_argument_bytes(argument);
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        format!("<non-unicode-argv:{encoded}>")
    })
}

fn ensure_existing_output_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "external-agent artifact path must be absolute: {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    ensure_existing_directory_without_symlinks(parent)
}

fn ensure_existing_directory_without_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                current.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!(
                    "external-agent path may not contain '..': {}",
                    path.display()
                );
            }
            std::path::Component::Normal(component) => {
                current.push(component);
                let metadata = fs::symlink_metadata(&current).with_context(|| {
                    format!("failed to inspect artifact ancestor {}", current.display())
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "external-agent artifact ancestor is not a non-symlink directory: {}",
                        current.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn summarize_output(output: &CapturedBytes) -> CapturedOutput {
    let summary = output.summarize_chars(OUTPUT_CHAR_LIMIT);
    CapturedOutput {
        text: summary.text,
        truncated: summary.truncated,
        bytes: output.as_bytes().to_vec(),
        target_launch_attempted: false,
        run_metadata: ExternalAgentRunMetadata::default(),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::agent_lifecycle::{AgentListFilter, AgentRegistry};
    use crate::process_runner::{ContainmentBackend, SideEffectConfinementProfileKind};

    #[test]
    fn absent_model_selection_preserves_the_exact_hardened_codex_argv() {
        let command = ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        );
        let actual = command_argv(&command)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let expected = vec![
            "-a",
            "never",
            "exec",
            "--strict-config",
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "--cd",
            "/workspace",
            "-c",
            "default_permissions=\"maco_external_codex\"",
            "-c",
            "permissions.maco_external_codex.network={enabled=false}",
            "-c",
            "permissions.maco_external_codex.filesystem={\":minimal\"=\"read\",\":workspace_roots\"={\".\"=\"write\"},\"/run\"=\"write\"}",
            "-c",
            "shell_environment_policy.inherit=\"none\"",
            "-c",
            "shell_environment_policy.set={PATH=\"/run/current-system/sw/bin:/usr/bin:/bin\"}",
            "-c",
            "web_search=\"disabled\"",
            "--disable",
            "apps",
            "--disable",
            "plugins",
            "--disable",
            "hooks",
            "--disable",
            "in_app_browser",
            "--disable",
            "browser_use",
            "--disable",
            "browser_use_full_cdp_access",
            "--disable",
            "browser_use_external",
            "--disable",
            "computer_use",
            "--disable",
            "image_generation",
            "--enable",
            "goals",
            "--enable",
            "multi_agent",
            "--json",
            "--output-last-message",
            "/run/report.json",
            "-",
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn codex_argv_applies_primary_model_selection_safely() {
        let command = ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
        .with_model_selection(
            Some("planner-model".to_string()),
            Some("high\"\nweb_search=\"live".to_string()),
        );
        let actual = command_argv(&command)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(actual
            .windows(2)
            .any(|arguments| arguments == ["-m", "planner-model"]));
        assert!(actual.windows(2).any(|arguments| {
            arguments
                == [
                    "-c",
                    "model_reasoning_effort=\"high\\\"\\nweb_search=\\\"live\"",
                ]
        }));
        assert!(!actual
            .iter()
            .any(|argument| argument == "web_search=\"live\""));
    }

    #[test]
    fn codex_usage_parser_sums_only_valid_completed_turns() -> Result<()> {
        let usage = codex_usage_from_jsonl(
            br#"{"type":"thread.started","thread_id":"thread-a"}
{"type":"turn.completed","usage":{"input_tokens":120,"cached_input_tokens":20,"output_tokens":30}}
{"type":"item.completed","item":{"type":"agent_message"}}
{"type":"turn.completed","usage":{"input_tokens":80,"cached_input_tokens":0,"output_tokens":20}}
"#,
        )?
        .context("completed usage")?;
        assert_eq!(
            usage,
            Usage {
                input_tokens: 200,
                output_tokens: 50,
                total_tokens: 250,
            }
        );
        assert!(codex_usage_from_jsonl(br#"{"type":"thread.started"}"#)?.is_none());
        assert!(codex_usage_from_jsonl(
            b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1}}\n"
        )
        .is_err());
        assert!(codex_usage_from_jsonl(b"{malformed}\n").is_err());
        Ok(())
    }

    #[test]
    fn external_errors_are_composed_and_success_requires_verified_empty_containment() {
        assert_eq!(
            append_external_error(
                Some("cleanup evidence".to_string()),
                Some("exit status 7".to_string())
            ),
            Some("cleanup evidence; exit status 7".to_string())
        );

        let mut report = ExternalAgentRun {
            command: vec!["fake".to_string()],
            cwd: PathBuf::from("."),
            timeout_seconds: 1,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: None,
            side_effects: None,
            publishable: false,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: None,
        };
        assert!(!report.succeeded());
        report.process_tree = Some(ProcessTreeEvidence::TrustedBestEffort(
            ContainmentBackend::UnixProcessGroup,
        ));
        assert!(!report.succeeded());
        report.process_tree = Some(ProcessTreeEvidence::Unverified(
            ContainmentBackend::SystemdUserService,
        ));
        assert!(!report.succeeded());
        report.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        report.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ));
        report.publishable = true;
        report.program_trust = ExternalProgramTrust::TrustedSystemCodex;
        report.codex_permissions = Some(CodexPermissionEvidence {
            codex_version: "0.142.3".to_string(),
            minimum_version: "0.138.0".to_string(),
            permission_profile: "maco_external_codex".to_string(),
            workspace_access: WorkspaceAccess::ReadWrite,
            network_enabled: false,
            argv_digest: "digest".to_string(),
            executable_identity: "identity".to_string(),
        });
        assert!(report.succeeded());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fake_provider_lifecycle_is_listed_in_supervisor_repo_and_gc_after_exit() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let supervisor_repo = temp.path().join("supervisor-repo");
        let child_repo = temp.path().join("child-worktree");
        git2::Repository::init(&supervisor_repo)?;
        git2::Repository::init(&child_repo)?;

        let provider = child_repo.join("fake-provider.sh");
        fs::write(
            &provider,
            "#!/bin/sh\nroot=${0%/*}\nprintf '%s\\n%s\\n' \"$MACO_RUN_ID\" \"$MACO_TASK_ID\" > \"$root/lifecycle-env\"\n: > \"$root/provider-started\"\nwhile [ ! -f \"$root/provider-release\" ]; do sleep 0.01; done\n",
        )?;
        fs::set_permissions(&provider, fs::Permissions::from_mode(0o700))?;
        let prompt = child_repo.join("prompt.md");
        fs::write(&prompt, "offline fake provider lifecycle test\n")?;
        let incoming = child_repo.join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;

        let command = ExternalAgentCommand::codex(
            &provider,
            &child_repo,
            &prompt,
            child_repo.join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::from_secs(10),
        )
        .with_agent_lifecycle(
            &supervisor_repo,
            "child_orchestrator",
            "supervise-run",
            "assignment-a",
        );
        let registry = AgentRegistry::open(&supervisor_repo)?;
        let runner =
            std::thread::spawn(move || run_external_agent_nonpublishable_simulation(&command));

        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = (|| -> Result<Option<_>> {
            loop {
                if let Some(record) = registry
                    .list(&AgentListFilter::default())?
                    .into_iter()
                    .next()
                {
                    return Ok(Some(record));
                }
                if runner.is_finished() || Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();

        fs::write(child_repo.join("provider-release"), b"")?;
        let report = runner
            .join()
            .map_err(|_| anyhow::anyhow!("fake provider runner thread panicked"))?;
        let record = observed?
            .context("fake provider lifecycle registration was not observable before exit")?;

        assert!(
            report.simulation_succeeded(),
            "unexpected report: {report:#?}"
        );
        assert_eq!(record.role, "child_orchestrator");
        assert_eq!(record.run_id, "supervise-run");
        assert_eq!(record.task_id, "assignment-a");
        assert_eq!(record.repo, supervisor_repo);
        assert!(record.argv.iter().any(|argument| argument == "exec"));
        assert_eq!(
            fs::read_to_string(child_repo.join("lifecycle-env"))?,
            "supervise-run\nassignment-a\n"
        );
        assert!(registry.list(&AgentListFilter::default())?.is_empty());
        assert!(registry.registry_path().is_file());
        assert!(!child_repo.join(".maco/agents/registry.json").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn verified_nonzero_target_retains_permission_and_containment_evidence() -> Result<()> {
        use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
        use std::process::ExitStatus;

        let temp = tempfile::tempdir()?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let prompt = temp.path().join("prompt.md");
        fs::write(&prompt, "run a failing child\n")?;
        let output_path = incoming.join("report.json");
        let command = ExternalAgentCommand::codex(
            "codex",
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            &output_path,
            Duration::from_secs(5),
        );
        let output_reservation = reserve_external_output(&output_path)?;
        let identity_path = temp.path().join("trusted-codex-identity");
        fs::write(&identity_path, b"identity")?;
        let program_identity = external_program_identity(&identity_path)?;
        let mut report = ExternalAgentRun {
            command: vec!["codex".to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: command.timeout.as_secs(),
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            process_tree: None,
            side_effects: None,
            publishable: false,
            program_trust: ExternalProgramTrust::TrustedSystemCodex,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: None,
        };
        let output = ProcessOutput {
            status: Some(ExitStatus::from_raw(7 << 8)),
            duration: Duration::from_millis(2),
            timed_out: false,
            process_tree: ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            ),
            side_effects: SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            stdout: CapturedBytes::default(),
            stderr: CapturedBytes::default(),
            process_error: None,
            stdin_error: None,
        };
        let protected_controls = protected_worktree_controls(&command)?;

        record_completed_target(
            &mut report,
            output,
            &output_reservation,
            CompletedTargetContext {
                runtime: ExternalExecutionRuntime::Verified,
                codex_version: Some((0, 142, 3)),
                spec: &command,
                protected_controls: &protected_controls,
                argv_digest: "verified-argv-digest",
                program_identity: &program_identity,
            },
        );

        assert_eq!(report.exit_code, Some(7));
        assert_eq!(
            report.process_tree,
            Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService
            ))
        );
        assert_eq!(
            report.side_effects,
            Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex
            ))
        );
        assert!(report.codex_permissions.is_some());
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("exited with status 7")));
        assert!(!report.publishable);
        assert!(!report.safely_executed());
        assert!(!report.succeeded());
        Ok(())
    }

    #[test]
    fn scratch_quiescence_distinguishes_preflight_refusal_from_unverified_launch() {
        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            vec!["codex".to_string()],
            false,
            "preflight refused".to_string(),
        );
        assert!(report.scratch_quiescence_verified());

        report.stdout.target_launch_attempted = true;
        assert!(!report.scratch_quiescence_verified());
        report.process_tree = Some(ProcessTreeEvidence::Unverified(
            ContainmentBackend::SystemdUserService,
        ));
        assert!(!report.scratch_quiescence_verified());
        report.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        assert!(report.scratch_quiescence_verified());
    }

    #[test]
    fn explicit_custom_environment_never_receives_provider_credentials() {
        let environment = allowed_env(
            ExternalAgentInvocation::CodexSupervisor,
            ExternalProgramTrust::ExplicitCustom,
        );
        for name in ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] {
            assert!(
                !environment.contains_key(name),
                "custom environment exposed {name}"
            );
        }
    }

    #[test]
    fn explicit_custom_cannot_construct_provider_network_profile() {
        let spec = ExternalAgentCommand::codex(
            "/tmp/custom-codex",
            "/tmp",
            "/tmp/prompt",
            "/tmp/log",
            "/tmp/report",
            Duration::from_secs(1),
        );
        let error = external_side_effect_profile(
            &spec,
            Path::new("/tmp/custom-codex"),
            ExternalProgramTrust::ExplicitCustom,
            &ProtectedWorktreeControls::default(),
        )
        .expect_err("custom program must not receive provider-network authority");
        assert!(error.to_string().contains("trusted system Codex"));
    }

    #[test]
    fn protected_worktree_controls_use_exact_descendant_exceptions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::write(
            workspace.join(".git"),
            "gitdir: ../primary/.git/worktrees/child\n",
        )?;
        for root in [".maco", ".codex", ".agents"] {
            fs::create_dir(workspace.join(root))?;
        }
        fs::create_dir(workspace.join(".agents/docs"))?;
        fs::write(workspace.join(".agents/docs/worker.md"), "worker policy\n")?;
        for file in [".gitignore", ".gitattributes", "AGENTS.md", "CLAUDE.md"] {
            fs::write(workspace.join(file), "protected\n")?;
        }
        let command = ExternalAgentCommand::codex(
            "codex",
            &workspace,
            workspace.join("prompt.md"),
            workspace.join("events.jsonl"),
            workspace.join("incoming/report.json"),
            Duration::from_secs(1),
        )
        .with_worktree_control_exception(".agents/docs/worker.md");

        let controls = protected_worktree_controls(&command)?;
        let roots = controls
            .read_only_roots
            .iter()
            .map(|control| control.relative.as_path())
            .collect::<BTreeSet<_>>();
        let files = controls
            .read_only_files
            .iter()
            .map(|control| control.relative.as_path())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            roots,
            BTreeSet::from([
                Path::new(".agents"),
                Path::new(".codex"),
                Path::new(".maco"),
            ])
        );
        assert_eq!(
            files,
            BTreeSet::from([
                Path::new(".git"),
                Path::new(".gitattributes"),
                Path::new(".gitignore"),
                Path::new("AGENTS.md"),
                Path::new("CLAUDE.md"),
            ])
        );
        assert_eq!(
            controls
                .read_write_files
                .iter()
                .map(|control| control.relative.as_path())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([Path::new(".agents/docs/worker.md")])
        );
        Ok(())
    }

    #[test]
    fn control_exceptions_reject_invalid_permanent_symlink_and_ambiguous_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace)?;
        for root in [".git", ".maco", ".codex", ".agents"] {
            fs::create_dir(workspace.join(root))?;
        }
        fs::create_dir(workspace.join(".agents/docs"))?;
        fs::write(workspace.join(".agents/docs/policy.md"), "policy\n")?;
        fs::write(workspace.join(".gitignore"), "target\n")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            workspace.join(".agents/docs"),
            workspace.join(".agents/link"),
        )?;

        for paths in [
            vec![PathBuf::from("/absolute")],
            vec![PathBuf::from("../AGENTS.md")],
            vec![PathBuf::from(".")],
            vec![PathBuf::from("src")],
            vec![PathBuf::from(".git")],
            vec![PathBuf::from(".maco")],
            vec![PathBuf::from(".codex")],
            vec![PathBuf::from(".agents/link")],
            vec![
                PathBuf::from(".agents/docs"),
                PathBuf::from(".agents/docs/policy.md"),
            ],
        ] {
            assert!(
                protected_worktree_controls_for(&workspace, &paths).is_err(),
                "invalid exception set was accepted: {paths:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn structured_failed_command_denials_are_typed_deduplicated_and_redacted() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::write(workspace.join("AGENTS.md"), "policy\n")?;
        let command = ExternalAgentCommand::codex(
            "codex",
            &workspace,
            workspace.join("prompt.md"),
            workspace.join("events.jsonl"),
            workspace.join("incoming/report.json"),
            Duration::from_secs(1),
        );
        let controls = protected_worktree_controls(&command)?;
        let absolute = workspace.join("AGENTS.md");
        let event = serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "item-1",
                "type": "command_execution",
                "command": format!("touch '{}'", absolute.display()),
                "aggregated_output": format!("touch: cannot touch '{}': Read-only file system", absolute.display()),
                "exit_code": 1,
                "status": "failed"
            }
        });
        let jsonl = format!("{event}\n{event}\n");
        let denials = sandbox_denials_from_codex_jsonl(&controls, jsonl.as_bytes());
        assert_eq!(
            denials,
            vec![SandboxDenialEvidence {
                boundary: SandboxDenialBoundary::InnerCodex,
                policy_id: INNER_CODEX_POLICY_ID.to_string(),
                operation: SandboxDeniedOperation::Write,
                path: Some(PathBuf::from("AGENTS.md")),
                retryability: SandboxDenialRetryability::RequiresDeclaredException,
            }]
        );
        let serialized = serde_json::to_string(&denials)?;
        assert!(!serialized.contains(&workspace.display().to_string()));

        for noise in [
            br#"{"type":"item.completed","item":{"id":"item-1","type":"agent_message","text":"AGENTS.md: permission denied"}}"#.as_slice(),
            br#"{"type":"item.completed","item":{"id":"item-1","type":"command_execution","command":"touch AGENTS.md","aggregated_output":"permission denied","exit_code":0,"status":"completed"}}"#.as_slice(),
            br#"arbitrary agent prose says AGENTS.md permission denied"#.as_slice(),
            br#"{"type":"item.completed","item":{"id":"item-1","type":"command_execution","command":"touch AGENTS.md.bak","aggregated_output":"permission denied","exit_code":1,"status":"failed"}}"#.as_slice(),
        ] {
            assert!(sandbox_denials_from_codex_jsonl(&controls, noise).is_empty());
        }
        Ok(())
    }

    #[test]
    fn codex_inner_permissions_keep_exact_reads_writes_and_toml_escaping() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        let incoming = temp.path().join("incoming");
        fs::create_dir(&workspace)?;
        fs::create_dir(&incoming)?;
        fs::write(
            workspace.join(".git"),
            "gitdir: ../primary/.git/worktrees/child\n",
        )?;
        for root in [".maco", ".codex", ".agents"] {
            fs::create_dir(workspace.join(root))?;
        }
        let exception = PathBuf::from(".agents/policy\"quoted.md");
        fs::write(workspace.join(&exception), "policy\n")?;
        fs::write(workspace.join(".gitattributes"), "* text=auto\n")?;
        let command = ExternalAgentCommand::codex(
            "codex",
            &workspace,
            workspace.join("prompt.md"),
            workspace.join("events.jsonl"),
            incoming.join("report.json"),
            Duration::from_secs(1),
        )
        .with_worktree_control_exception(&exception);
        let controls = protected_worktree_controls(&command)?;
        let permissions = codex_filesystem_permissions(&command, &controls);

        assert!(permissions.contains("\":minimal\"=\"read\""));
        assert!(permissions.contains("\":workspace_roots\"={\".\"=\"write\"}"));
        for path in [".git", ".maco", ".codex", ".agents", ".gitattributes"] {
            assert!(
                permissions.contains(&format!("{}=\"read\"", toml_basic_string(path))),
                "missing exact read entry for {path}: {permissions}"
            );
        }
        assert!(permissions.contains("\".agents/policy\\\"quoted.md\"=\"write\""));
        assert!(!permissions.contains("\".agents\"=\"write\""));
        assert!(permissions.contains(&format!(
            "{}=\"write\"",
            toml_basic_string(incoming.to_str().context("UTF-8 incoming path")?)
        )));
        Ok(())
    }

    #[test]
    fn stored_denial_evidence_round_trips_and_old_json_defaults_empty() -> Result<()> {
        let command = ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        );
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            vec!["codex".to_string()],
            false,
            "external agent exited with status 1".to_string(),
        );
        report.stdout.run_metadata.sandbox_denials = vec![SandboxDenialEvidence {
            boundary: SandboxDenialBoundary::InnerCodex,
            policy_id: INNER_CODEX_POLICY_ID.to_string(),
            operation: SandboxDeniedOperation::Write,
            path: Some(PathBuf::from("AGENTS.md")),
            retryability: SandboxDenialRetryability::RequiresDeclaredException,
        }];
        let value = serde_json::to_value(&report)?;
        let decoded: ExternalAgentRun = serde_json::from_value(value.clone())?;
        assert_eq!(decoded.sandbox_denials(), report.sandbox_denials());

        let mut old = value;
        old.as_object_mut()
            .context("run serialization must be an object")?
            .remove("sandbox_denials");
        let old_decoded: ExternalAgentRun = serde_json::from_value(old)?;
        assert!(old_decoded.sandbox_denials().is_empty());
        Ok(())
    }

    #[test]
    fn outer_denial_evidence_uses_only_typed_process_errors() {
        let typed = ProcessRunError::ContainmentUnavailable {
            label: "external agent".to_string(),
            command: "codex exec".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "systemd refused boundary",
            ),
        };
        assert_eq!(
            sandbox_denial_from_process_error(&typed),
            Some(SandboxDenialEvidence {
                boundary: SandboxDenialBoundary::OuterSystemd,
                policy_id: OUTER_SYSTEMD_POLICY_ID.to_string(),
                operation: SandboxDeniedOperation::EstablishBoundary,
                path: None,
                retryability: SandboxDenialRetryability::NotRetryable,
            })
        );
        let prose_only = ProcessRunError::Spawn {
            label: "external agent".to_string(),
            command: "codex exec".to_string(),
            current_dir: PathBuf::from("/workspace"),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "required process containment is unavailable",
            ),
        };
        assert_eq!(sandbox_denial_from_process_error(&prose_only), None);
    }

    #[test]
    fn external_profile_exposes_only_incoming_output_root_as_writable() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace)?;
        let container = temp.path().join("run");
        let trusted = container.join("trusted");
        let incoming = container.join("incoming");
        let spec = ExternalAgentCommand::codex(
            workspace.join("codex"),
            &workspace,
            trusted.join("prompt.md"),
            trusted.join("events.jsonl"),
            incoming.join("report.json"),
            Duration::from_secs(1),
        );
        let profile = external_side_effect_profile(
            &spec,
            &workspace.join("codex"),
            ExternalProgramTrust::TrustedSystemCodex,
            &protected_worktree_controls(&spec)?,
        )?;
        let SideEffectConfinementProfile::ExternalCodex(profile) = profile else {
            bail!("expected external Codex profile");
        };
        assert_eq!(profile.writable_artifact_roots(), &[incoming]);
        assert!(profile
            .writable_artifact_roots()
            .iter()
            .all(|root| !root.starts_with(&trusted)));
        Ok(())
    }

    #[test]
    fn descriptor_captured_output_is_never_serialized() -> Result<()> {
        let mut report = failed_external_run(
            &ExternalAgentCommand::codex(
                "codex",
                ".",
                "prompt",
                "log",
                "output",
                Duration::from_secs(1),
            ),
            Instant::now(),
            vec!["codex".to_string()],
            false,
            "failed".to_string(),
        );
        report.output_last_message = Some(b"DO_NOT_DEBUG_private_descriptor_bytes".to_vec());
        report.stdout.bytes = b"DO_NOT_DEBUG_private_stdout_bytes\0\xff".to_vec();
        let debug = format!("{report:?}");
        assert!(!debug.contains("DO_NOT_DEBUG_private_stdout_bytes"));
        assert!(!debug.contains("DO_NOT_DEBUG_private_descriptor_bytes"));
        assert!(!debug.contains("target_launch_attempted"));
        assert!(debug.contains(&format!(
            "bytes: <redacted:{} bytes>",
            report.stdout.bytes.len()
        )));
        assert!(debug.contains(&format!(
            "output_last_message: Some(<redacted:{} bytes>)",
            report.output_last_message().context("held output")?.len()
        )));
        let value = serde_json::to_value(&report)?;
        assert!(value.get("output_last_message").is_none());
        assert!(value
            .get("stdout")
            .and_then(|stdout| stdout.get("bytes"))
            .is_none());
        assert!(value
            .get("stdout")
            .and_then(|stdout| stdout.get("target_launch_attempted"))
            .is_none());
        let decoded: ExternalAgentRun = serde_json::from_value(value)?;
        assert_eq!(decoded.output_last_message(), None);
        assert_eq!(decoded.stdout_bytes(), b"");
        assert!(!decoded.scratch_quiescence_verified());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn codex_argv_and_digest_preserve_non_utf8_paths_without_collision() -> Result<()> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let raw_component = OsString::from_vec(b"repo-\xff".to_vec());
        let mut raw_root = PathBuf::from("/tmp");
        raw_root.push(raw_component);
        let replacement_root = PathBuf::from("/tmp/repo-\u{fffd}");
        let raw_report = raw_root.join("report-\u{fffd}.json");
        let raw_schema = raw_root.join(OsString::from_vec(b"schema-\xfe.json".to_vec()));
        let mut raw = ExternalAgentCommand::codex(
            "codex",
            &raw_root,
            raw_root.join("prompt.md"),
            raw_root.join("events.jsonl"),
            &raw_report,
            Duration::from_secs(1),
        );
        raw.output_schema = Some(raw_schema.clone());
        let replacement = ExternalAgentCommand::codex(
            "codex",
            &replacement_root,
            replacement_root.join("prompt.md"),
            replacement_root.join("events.jsonl"),
            replacement_root.join("report-\u{fffd}.json"),
            Duration::from_secs(1),
        );

        let raw_argv = command_argv(&raw);
        let replacement_argv = command_argv(&replacement);
        let cd_index = raw_argv
            .iter()
            .position(|argument| argument == "--cd")
            .context("--cd argument")?;
        assert_eq!(
            raw_argv[cd_index + 1].as_bytes(),
            raw_root.as_os_str().as_bytes()
        );
        assert!(raw_argv
            .iter()
            .any(|argument| argument.as_bytes() == raw_report.as_os_str().as_bytes()));
        assert!(raw_argv
            .iter()
            .any(|argument| argument.as_bytes() == raw_schema.as_os_str().as_bytes()));
        assert_ne!(argv_digest(&raw_argv)?, argv_digest(&replacement_argv)?);
        let rendered = command_display(Path::new("codex"), &raw_argv);
        assert!(rendered
            .iter()
            .any(|argument| argument.starts_with("<non-unicode-argv:")));
        assert!(!rendered
            .iter()
            .any(|argument| argument == &raw_root.to_string_lossy()));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn codex_auth_accepts_only_bounded_private_single_link_regular_file() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let home = temp.path().join("codex-home");
        fs::create_dir(&home)?;
        let auth = home.join("auth.json");
        fs::write(&auth, br#"{"token":"redacted"}"#)?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let validated =
            ValidatedCodexAuth::load_from_home(&home)?.context("validated auth source")?;
        assert_eq!(validated.bytes, br#"{"token":"redacted"}"#);
        validated.verify_source_unchanged()?;

        fs::set_permissions(&auth, fs::Permissions::from_mode(0o644))?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let alias = home.join("auth-alias");
        fs::hard_link(&auth, &alias)?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        fs::remove_file(&alias)?;
        fs::remove_file(&auth)?;
        std::os::unix::fs::symlink("missing-auth", &auth)?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn setup_timeout_is_reported_as_timed_out_without_starting_external_agent() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let marker = temp.path().join("must-not-run");
        let agent = temp.path().join("fake-agent.sh");
        fs::write(&agent, format!("#!/bin/sh\ntouch '{}'\n", marker.display()))?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "do not start\n")?;
        let spec = ExternalAgentCommand::codex(
            agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            temp.path().join("last-message.txt"),
            Duration::ZERO,
        );

        let report = run_external_agent(&spec);

        assert!(report.timed_out);
        assert_eq!(report.exit_code, None);
        assert_eq!(report.process_tree, None);
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out before command start")));
        assert!(!marker.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn explicit_custom_runs_at_most_version_diagnostic_and_never_target() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let marker = temp.path().join("actual-target-ran");
        let agent = temp.path().join("custom-codex.sh");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'codex-cli 0.142.3\\n'; exit 0; fi\ntouch '{}'\n",
                marker.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "never run custom target\n")?;
        let spec = ExternalAgentCommand::codex(
            agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            temp.path().join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent(&spec);

        assert!(!marker.exists());
        assert!(!report.publishable);
        assert_eq!(report.program_trust, ExternalProgramTrust::ExplicitCustom);
        assert_eq!(report.codex_permissions, None);
        if report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("strict-offline version diagnostic"))
        {
            assert_eq!(report.process_tree, None);
            assert_eq!(report.side_effects, None);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_external_agent_drains_large_stdout_and_stderr_while_child_runs() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'O'
    i=$((i + 1))
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'E' >&2
    i=$((i + 1))
done
printf '\n{"type":"done"}\n'
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert_eq!(report.exit_code, Some(0));
        assert!(
            !report.timed_out,
            "large output child should exit before timeout: {report:?}"
        );
        assert_eq!(report.error, None);
        assert!(report.simulation_succeeded());
        assert!(!report.succeeded());
        assert!(report.stdout.truncated);
        assert!(report.stderr.truncated);
        assert!(report.stdout.text.len() >= OUTPUT_CHAR_LIMIT);
        assert!(report.stderr.text.len() >= OUTPUT_CHAR_LIMIT);
        let exact_tee = fs::read(&spec.json_log)?;
        assert!(exact_tee.len() > OUTPUT_CAPTURE_LIMIT_BYTES);
        assert_eq!(report.stdout_bytes().len(), OUTPUT_CAPTURE_LIMIT_BYTES);
        assert_eq!(
            report.stdout_bytes(),
            &exact_tee[..OUTPUT_CAPTURE_LIMIT_BYTES]
        );

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_stdout_accessor_preserves_non_utf8_bytes() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
cat >/dev/null
printf 'A\377B\n'
"#,
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "read-only prompt\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.error, None);
        assert_eq!(report.stdout_bytes(), b"A\xffB\n");
        assert!(report.stdout.text.contains('\u{fffd}'));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_external_agent_finalizes_descendant_holding_output_pipes() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
(
    trap '' TERM
    printf 'descendant started\n'
    printf 'descendant stderr started\n' >&2
    while :; do
        sleep 1
    done
) &
printf 'parent exiting\n'
exit 0
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(1),
        );

        let started = Instant::now();
        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "process-tree finalization should return promptly instead of hanging: {report:?}"
        );
        assert!(
            !report.timed_out,
            "a normally exited parent should remain successful after descendant teardown: {report:?}"
        );
        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.error, None);
        assert!(report.simulation_succeeded());
        assert!(!report.succeeded());
        assert!(report.stdout.text.contains("parent exiting"));
        assert!(report.stdout.text.contains("descendant started"));
        assert!(report.stderr.text.contains("descendant stderr started"));

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_agent_cancellation_reaches_target_and_prevents_delayed_mutation() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::thread;

        let temp = tempfile::tempdir()?;
        let started = temp.path().join("started");
        let delayed = temp.path().join("delayed");
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\ncat >/dev/null\ntouch '{}'\n(sleep 0.3; touch '{}') &\ntrap '' TERM\nwhile :; do sleep 1; done\n",
                started.display(),
                delayed.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run until cancelled\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::from_secs(5),
        );
        let cancellation = ProcessCancellation::new();
        let worker_cancellation = cancellation.clone();
        let worker = thread::spawn(move || {
            run_external_agent_nonpublishable_simulation_cancellable(&spec, &worker_cancellation)
        });

        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !started.exists() {
            assert!(
                Instant::now() < ready_deadline,
                "external target did not reach ready gate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        cancellation.cancel();
        let report = worker
            .join()
            .unwrap_or_else(|_| panic!("external cancellation worker panicked"));

        assert!(!report.timed_out);
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("cancelled")));
        assert!(report.process_tree.is_some());
        thread::sleep(Duration::from_millis(400));
        assert!(!delayed.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_output_rebind_is_rejected_without_following_attacker_symlink() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, "untouched")?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            format!(
                r#"#!/bin/sh
set -eu
report=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    report=$1
  fi
  shift
done
printf '{{"ok":true}}\n' > "$report"
mv "$report" "$report.moved"
ln -s '{}' "$report"
"#,
                sentinel.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "test output identity\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            incoming.join("report.json"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert!(report.output_last_message().is_none());
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("reservation changed")));
        assert_eq!(fs::read(&sentinel)?, b"untouched");
        Ok(())
    }
}
