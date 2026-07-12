use crate::process_runner::{
    read_bounded_regular_file_nofollow, run_process, CapturedBytes, EnvironmentMode,
    ExternalCodexProfile, ProcessRunError, ProcessSpec, ProcessTreeEvidence,
    SideEffectConfinementEvidence, SideEffectConfinementProfile, StdinMode, StreamCapture,
    StrictOfflineWorkspaceProfile, WorkspaceAccess,
};
use crate::secure_output::{ReservedOutputFile, SecureOutputRoot};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExternalAgentRun {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    /// Present only after the shared runner starts and closes the owned execution boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_tree: Option<ProcessTreeEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effects: Option<SideEffectConfinementEvidence>,
    pub publishable: bool,
    pub program_trust: ExternalProgramTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_permissions: Option<CodexPermissionEvidence>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub error: Option<String>,
    /// Descriptor-captured final output. This is deliberately excluded from the public report
    /// surface so callers cannot confuse a tainted pathname with the held capability.
    #[serde(skip, default)]
    pub(crate) output_last_message: Option<Vec<u8>>,
}

impl ExternalAgentRun {
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapturedOutput {
    pub text: String,
    pub truncated: bool,
}

pub fn run_external_agent(spec: &ExternalAgentCommand) -> ExternalAgentRun {
    run_external_agent_runtime(spec, ExternalExecutionRuntime::Verified)
}

#[cfg(test)]
pub(crate) fn run_external_agent_nonpublishable_simulation(
    spec: &ExternalAgentCommand,
) -> ExternalAgentRun {
    run_external_agent_runtime(spec, ExternalExecutionRuntime::NonpublishableSimulation)
}

fn run_external_agent_runtime(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) -> ExternalAgentRun {
    let started = Instant::now();
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
    let argv = command_argv(spec);
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
        match preflight_codex_version(&resolved_program, &spec.cwd, remaining) {
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
        match external_side_effect_profile(spec, &resolved_program, program_trust) {
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

    match run_process(process_spec) {
        Ok(output) => {
            let safety_verified = output.safety_evidence_verified();
            report.exit_code = output.status.and_then(|status| status.code());
            report.timed_out = output.timed_out;
            report.process_tree = Some(output.process_tree);
            report.side_effects = Some(output.side_effects);
            if runtime == ExternalExecutionRuntime::Verified
                && program_trust == ExternalProgramTrust::TrustedSystemCodex
                && safety_verified
                && output.status.is_some_and(|status| status.success())
            {
                report.codex_permissions = codex_version.map(|version| {
                    codex_permission_evidence(version, spec, &argv_digest, &program_identity)
                });
            }
            report.stdout = summarize_output(&output.stdout);
            report.stderr = summarize_output(&output.stderr);
            report.error = append_external_error(output.stdin_error, output.process_error);
            if output.timed_out {
                report.error = append_external_error(
                    report.error.take(),
                    Some(format!(
                        "external agent timed out after {} seconds",
                        spec.timeout.as_secs()
                    )),
                );
            } else if !output.timed_out && !output.status.is_some_and(|status| status.success()) {
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
            report.publishable = runtime == ExternalExecutionRuntime::Verified
                && safety_verified
                && report.program_trust == ExternalProgramTrust::TrustedSystemCodex
                && report.codex_permissions.is_some()
                && report.error.is_none();
        }
        Err(error) => {
            report.timed_out = matches!(&error, ProcessRunError::SetupTimeout { .. });
            report.error = Some(error.to_string());
        }
    }
    report.duration_ms = duration_millis(started.elapsed());
    report
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
    let output = run_process(
        ProcessSpec::direct("Codex version preflight", program, ["--version"], cwd, 4096)
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_only(cwd)
                    .with_visible_read_only_root(program_parent),
            ))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(timeout)),
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

fn external_side_effect_profile(
    spec: &ExternalAgentCommand,
    program: &Path,
    program_trust: ExternalProgramTrust,
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

fn command_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor => codex_supervisor_argv(spec),
        ExternalAgentInvocation::CodexConsultant => codex_consultant_argv(spec),
        ExternalAgentInvocation::ClaudeConsultant => claude_consultant_argv(),
    }
}

fn codex_supervisor_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let mut argv = codex_hardened_argv(spec);
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

fn codex_consultant_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let mut argv = codex_hardened_argv(spec);
    argv.extend([
        OsString::from("--output-last-message"),
        spec.output_last_message.as_os_str().to_os_string(),
        OsString::from("-"),
    ]);
    argv
}

fn codex_hardened_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let filesystem_permissions = match spec.workspace_access {
        WorkspaceAccess::ReadOnly => {
            "permissions.maco_external_codex.filesystem={\":minimal\"=\"read\"}"
        }
        WorkspaceAccess::ReadWrite => {
            "permissions.maco_external_codex.filesystem={\":minimal\"=\"read\",\":workspace_roots\"={\".\"=\"write\"}}"
        }
    };
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
    argv
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
    use crate::process_runner::{ContainmentBackend, SideEffectConfinementProfileKind};

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
        )
        .expect_err("custom program must not receive provider-network authority");
        assert!(error.to_string().contains("trusted system Codex"));
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
        report.output_last_message = Some(b"private descriptor bytes".to_vec());
        let value = serde_json::to_value(&report)?;
        assert!(value.get("output_last_message").is_none());
        let decoded: ExternalAgentRun = serde_json::from_value(value)?;
        assert_eq!(decoded.output_last_message(), None);
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
        assert!(fs::metadata(&spec.json_log)?.len() > (OUTPUT_CHAR_LIMIT as u64 * 2));

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
