use crate::{
    artifacts::discover_repo_root,
    hierarchy_ledger::RoleCategory,
    mutation_taxonomy::{
        AssignmentProcessLaunchKind, ReservedMechanicalExecutorExecution,
        SealedMechanicalExecutorDuty, SealedMechanicalExecutorPhase, SealedMechanicalExecutorRole,
    },
    safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot},
    supervise::{
        authorize_known_executor_role_model, recorded_model_is_weak_mechanical,
        trusted_model_capability, validate_known_judgment_role_model, AgentRole,
        MechanicalTerminalDuty, ModelCapabilityClass, OrchestrationPhase,
    },
};
use anyhow::{bail, Context, Result};
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MACO_RUN_ID_ENV: &str = "MACO_RUN_ID";
pub const MACO_TASK_ID_ENV: &str = "MACO_TASK_ID";

const REGISTRY_VERSION: u32 = 1;
const REGISTRY_FILE: &str = "registry.json";
const REGISTRY_LOCK: &str = "registry.lock";
const MAX_REGISTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REGISTRY_RECORDS: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_ROLE_BYTES: usize = 128;
const MAX_ARGV_ENTRIES: usize = 4096;
const MAX_ARG_BYTES: usize = 64 * 1024;
const MAX_STOP_WAIT: Duration = Duration::from_secs(60);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);
const KILL_CONFIRMATION_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLaunchMetadata {
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub repo: PathBuf,
    pub parent: Option<String>,
}

impl AgentLaunchMetadata {
    pub fn new(
        repo: impl AsRef<Path>,
        role: impl Into<String>,
        run_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Result<Self> {
        let metadata = Self {
            role: role.into(),
            run_id: run_id.into(),
            task_id: task_id.into(),
            repo: discover_repo_root(repo)?,
            parent: None,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn with_parent(mut self, parent: impl Into<String>) -> Result<Self> {
        self.parent = Some(parent.into());
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_text_field("agent role", &self.role, MAX_ROLE_BYTES)?;
        validate_text_field("run id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", &self.task_id, MAX_IDENTIFIER_BYTES)?;
        if let Some(parent) = &self.parent {
            validate_text_field("parent agent id", parent, MAX_IDENTIFIER_BYTES)?;
        }
        if !self.repo.is_absolute() {
            bail!("agent lifecycle repository path must be absolute");
        }
        Ok(())
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MechanicalExecutorGrantKind {
    AssignmentChild,
}

/// Durable inspectable mechanical-executor evidence captured only from a
/// reserved consumed proof. This is not a live spawn capability.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MechanicalExecutorLaunchEvidence {
    pub grant_nonce: u64,
    pub kind: MechanicalExecutorGrantKind,
    pub role: String,
    pub phase: OrchestrationPhase,
    pub duty: MechanicalTerminalDuty,
    pub model: String,
    pub canonical_program: PathBuf,
    pub cwd: PathBuf,
    pub argv: Vec<String>,
    pub run_id: String,
    pub subject: String,
    pub attempt: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProcessRecord {
    pub pid: u32,
    pub process_start_time: String,
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub parent: Option<String>,
    pub repo: PathBuf,
    pub argv: Vec<String>,
    pub launch_timestamp_ms: u64,
    pub mechanical_executor: Option<MechanicalExecutorLaunchEvidence>,
}

/// Authority MACO derived from the declared lifecycle role and the exact
/// launched argv. This is deliberately not caller-authored lifecycle input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAuthorityBinding {
    pub category: RoleCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_capability: Option<ModelCapabilityClass>,
    pub may_delegate: bool,
    pub may_write: bool,
    pub may_judge_acceptance: bool,
    pub may_mutate_git_history: bool,
    pub probe_only: bool,
    pub source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentProcessRecordWire {
    pid: u32,
    process_start_time: String,
    role: String,
    run_id: String,
    task_id: String,
    #[serde(default)]
    parent: Option<String>,
    repo: PathBuf,
    argv: Vec<String>,
    launch_timestamp_ms: u64,
    #[serde(default)]
    launch_authority: Option<LaunchAuthorityBinding>,
    #[serde(default)]
    mechanical_executor: Option<MechanicalExecutorLaunchEvidence>,
}

impl AgentProcessRecord {
    fn validate(&self, expected_repo: &Path) -> Result<()> {
        if self.pid == 0 {
            bail!("agent registry record contains PID 0");
        }
        validate_text_field(
            "process start-time token",
            &self.process_start_time,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text_field("agent role", &self.role, MAX_ROLE_BYTES)?;
        validate_text_field("run id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", &self.task_id, MAX_IDENTIFIER_BYTES)?;
        if let Some(parent) = &self.parent {
            validate_text_field("parent agent id", parent, MAX_IDENTIFIER_BYTES)?;
        }
        if self.repo != expected_repo {
            bail!(
                "agent registry record repository {} does not match {}",
                self.repo.display(),
                expected_repo.display()
            );
        }
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV_ENTRIES {
            bail!("agent registry argv is empty or exceeds its entry bound");
        }
        for argument in &self.argv {
            if argument.len() > MAX_ARG_BYTES || argument.contains('\0') {
                bail!("agent registry argv entry exceeds its safety bound");
            }
        }
        self.launch_authority()?;
        Ok(())
    }

    /// Reconstruct and validate launch authority from immutable record fields.
    ///
    /// Version probes carry no authority. Actual coordinator and acceptance
    /// judge launches require an explicit model accepted by the model policy.
    /// Git mutation is never granted by lifecycle registration alone.
    /// Durable mechanical-executor evidence is historical inspect data: it
    /// cannot mint a reusable live proof.
    pub fn launch_authority(&self) -> Result<LaunchAuthorityBinding> {
        derive_launch_authority(&self.role, &self.argv, self.mechanical_executor.as_ref())
    }

    fn summary(&self) -> String {
        format!(
            "pid={} role={} run_id={} task_id={} parent={}",
            self.pid,
            self.role,
            self.run_id,
            self.task_id,
            self.parent.as_deref().unwrap_or("-")
        )
    }
}

impl Serialize for AgentProcessRecord {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let launch_authority = self.launch_authority().map_err(serde::ser::Error::custom)?;
        let mut field_count = 9;
        if self.parent.is_some() {
            field_count += 1;
        }
        if self.mechanical_executor.is_some() {
            field_count += 1;
        }
        let mut state = serializer.serialize_struct("AgentProcessRecord", field_count)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("process_start_time", &self.process_start_time)?;
        state.serialize_field("role", &self.role)?;
        state.serialize_field("run_id", &self.run_id)?;
        state.serialize_field("task_id", &self.task_id)?;
        if self.parent.is_some() {
            state.serialize_field("parent", &self.parent)?;
        }
        state.serialize_field("repo", &self.repo)?;
        state.serialize_field("argv", &self.argv)?;
        state.serialize_field("launch_timestamp_ms", &self.launch_timestamp_ms)?;
        state.serialize_field("launch_authority", &launch_authority)?;
        if let Some(evidence) = &self.mechanical_executor {
            state.serialize_field("mechanical_executor", evidence)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for AgentProcessRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentProcessRecordWire::deserialize(deserializer)?;
        let supplied_authority = wire.launch_authority;
        let record = Self {
            pid: wire.pid,
            process_start_time: wire.process_start_time,
            role: wire.role,
            run_id: wire.run_id,
            task_id: wire.task_id,
            parent: wire.parent,
            repo: wire.repo,
            argv: wire.argv,
            launch_timestamp_ms: wire.launch_timestamp_ms,
            mechanical_executor: wire.mechanical_executor,
        };
        if let Some(supplied_authority) = supplied_authority {
            let reconstructed = record
                .launch_authority()
                .map_err(serde::de::Error::custom)?;
            if supplied_authority != reconstructed {
                return Err(serde::de::Error::custom(
                    "agent launch authority does not match immutable role/argv evidence",
                ));
            }
        }
        Ok(record)
    }
}

fn derive_launch_authority(
    role: &str,
    argv: &[String],
    mechanical_executor: Option<&MechanicalExecutorLaunchEvidence>,
) -> Result<LaunchAuthorityBinding> {
    if let Some(evidence) = mechanical_executor {
        return derive_mechanical_executor_launch_authority(role, argv, evidence);
    }
    let category = lifecycle_role_category(role)?;
    if is_version_probe(argv) {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: false,
            may_write: false,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: true,
            source: "verified_version_probe".to_string(),
        });
    }
    if matches!(role, "supervise" | "autopilot") {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: true,
            may_write: true,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: false,
            source: "host_control_plane".to_string(),
        });
    }

    if !is_agent_runtime_program(&argv[0]) {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: false,
            may_write: false,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: false,
            source: "non_agent_simulation".to_string(),
        });
    }

    let model = configured_model_from_argv(argv)?;
    let policy_role = lifecycle_policy_role(role);
    match (role, policy_role, model.as_deref()) {
        ("researcher", None, Some(model)) => {
            validate_known_judgment_role_model(AgentRole::Worker, Some(model))?;
        }
        ("researcher", None, None) | (_, Some(AgentRole::Worker), None) => {}
        (_, Some(policy_role), model) => {
            validate_known_judgment_role_model(policy_role, model)?;
        }
        _ => bail!("agent lifecycle role {role:?} has no launch authority policy"),
    }
    let model_capability = model.as_deref().and_then(trusted_model_capability);
    Ok(LaunchAuthorityBinding {
        category,
        requested_model: model,
        model_capability,
        may_delegate: category == RoleCategory::DelegatingCoordinator,
        may_write: matches!(
            category,
            RoleCategory::DelegatingCoordinator | RoleCategory::NonDelegatingTerminalWorker
        ),
        may_judge_acceptance: category == RoleCategory::ReadOnlyReviewAuditor,
        may_mutate_git_history: false,
        probe_only: false,
        source: "role_and_exact_requested_argv".to_string(),
    })
}

fn derive_mechanical_executor_launch_authority(
    role: &str,
    argv: &[String],
    evidence: &MechanicalExecutorLaunchEvidence,
) -> Result<LaunchAuthorityBinding> {
    if role != "worker" || evidence.role != "worker" {
        bail!("mechanical executor evidence requires worker role");
    }
    if evidence.kind != MechanicalExecutorGrantKind::AssignmentChild {
        bail!("mechanical executor evidence requires assignment-child kind");
    }
    if evidence.phase != OrchestrationPhase::MechanicalTerminal {
        bail!("mechanical executor evidence requires mechanical_terminal phase");
    }
    if argv != evidence.argv.as_slice() {
        bail!("mechanical executor evidence does not match launched argv");
    }
    let Some(program) = argv.first() else {
        bail!("mechanical executor evidence requires a non-empty argv");
    };
    if Path::new(program) != evidence.canonical_program.as_path() {
        bail!("mechanical executor evidence does not match canonical program");
    }
    let model = configured_model_from_argv(argv)?;
    if model.as_deref() != Some(evidence.model.as_str()) {
        bail!("mechanical executor evidence does not match launched model");
    }
    authorize_known_executor_role_model(
        AgentRole::Worker,
        Some(evidence.model.as_str()),
        Some(evidence.duty),
    )?;
    let category = lifecycle_role_category(role)?;
    let model_capability = trusted_model_capability(&evidence.model);
    Ok(LaunchAuthorityBinding {
        category,
        requested_model: Some(evidence.model.clone()),
        model_capability,
        may_delegate: false,
        may_write: matches!(
            category,
            RoleCategory::DelegatingCoordinator | RoleCategory::NonDelegatingTerminalWorker
        ),
        may_judge_acceptance: false,
        may_mutate_git_history: false,
        probe_only: false,
        source: "role_argv_and_consumed_assignment_child_mechanical_executor".to_string(),
    })
}

pub(crate) fn model_requires_mechanical_executor_proof(model: &str) -> bool {
    recorded_model_is_weak_mechanical(model)
}

pub(crate) fn authorize_process_launch_before_spawn(
    metadata: &AgentLaunchMetadata,
    argv: &[String],
    current_dir: &Path,
    reserved: Option<&ReservedMechanicalExecutorExecution>,
) -> Result<()> {
    metadata.validate()?;
    if argv.is_empty() {
        bail!("agent lifecycle launch requires a non-empty argv");
    }
    if let Some(reserved) = reserved {
        verify_reserved_mechanical_executor(metadata, argv, current_dir, reserved)?;
        let evidence = evidence_from_reserved(reserved)?;
        derive_mechanical_executor_launch_authority(&metadata.role, argv, &evidence)?;
        return Ok(());
    }
    if !is_version_probe(argv) && is_agent_runtime_program(&argv[0]) {
        if let Some(model) = configured_model_from_argv(argv)? {
            if recorded_model_is_weak_mechanical(&model) {
                bail!(
                    "weak_mechanical launch requires consumed assignment-child mechanical executor proof"
                );
            }
        }
    }
    derive_launch_authority(&metadata.role, argv, None).map(|_| ())
}

fn verify_reserved_mechanical_executor(
    metadata: &AgentLaunchMetadata,
    argv: &[String],
    current_dir: &Path,
    reserved: &ReservedMechanicalExecutorExecution,
) -> Result<()> {
    if metadata.role != SealedMechanicalExecutorRole::Worker.as_str()
        || reserved.role() != SealedMechanicalExecutorRole::Worker
    {
        bail!("mechanical executor proof requires worker lifecycle role");
    }
    if metadata.run_id != reserved.run_id() || metadata.task_id != reserved.subject() {
        bail!("mechanical executor proof does not match lifecycle run identity");
    }
    if reserved.kind() != AssignmentProcessLaunchKind::AssignmentChild {
        bail!("mechanical executor proof requires assignment-child kind");
    }
    if reserved.phase() != SealedMechanicalExecutorPhase::MechanicalTerminal {
        bail!("mechanical executor proof requires mechanical_terminal phase");
    }
    if current_dir != reserved.cwd() {
        bail!("mechanical executor proof does not match launched cwd");
    }
    let expected = reserved_lifecycle_argv(reserved);
    if argv != expected.as_slice() {
        bail!("mechanical executor proof does not match launched argv");
    }
    Ok(())
}

fn reserved_lifecycle_argv(reserved: &ReservedMechanicalExecutorExecution) -> Vec<String> {
    let mut argv = Vec::with_capacity(reserved.argv().len().saturating_add(1));
    argv.push(reserved.canonical_program().to_string_lossy().into_owned());
    argv.extend(
        reserved
            .argv()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    argv
}

fn mechanical_terminal_duty_from_sealed(
    duty: SealedMechanicalExecutorDuty,
) -> MechanicalTerminalDuty {
    match duty {
        SealedMechanicalExecutorDuty::ApplyExplicitTextReplacement => {
            MechanicalTerminalDuty::ApplyExplicitTextReplacement
        }
        SealedMechanicalExecutorDuty::RunPreselectedCommand => {
            MechanicalTerminalDuty::RunPreselectedCommand
        }
        SealedMechanicalExecutorDuty::FormatPreselectedFiles => {
            MechanicalTerminalDuty::FormatPreselectedFiles
        }
        SealedMechanicalExecutorDuty::EnumerateDeclaredArtifacts => {
            MechanicalTerminalDuty::EnumerateDeclaredArtifacts
        }
        SealedMechanicalExecutorDuty::ValidateAgainstFixedSchema => {
            MechanicalTerminalDuty::ValidateAgainstFixedSchema
        }
    }
}

fn evidence_from_reserved(
    reserved: &ReservedMechanicalExecutorExecution,
) -> Result<MechanicalExecutorLaunchEvidence> {
    if reserved.kind() != AssignmentProcessLaunchKind::AssignmentChild {
        bail!("mechanical executor evidence requires assignment-child kind");
    }
    Ok(MechanicalExecutorLaunchEvidence {
        grant_nonce: reserved.nonce(),
        kind: MechanicalExecutorGrantKind::AssignmentChild,
        role: reserved.role().as_str().to_string(),
        phase: OrchestrationPhase::MechanicalTerminal,
        duty: mechanical_terminal_duty_from_sealed(reserved.duty()),
        model: reserved.model().to_string(),
        canonical_program: reserved.canonical_program().to_path_buf(),
        cwd: reserved.cwd().to_path_buf(),
        argv: reserved_lifecycle_argv(reserved),
        run_id: reserved.run_id().to_string(),
        subject: reserved.subject().to_string(),
        attempt: reserved.attempt(),
    })
}

fn is_agent_runtime_program(program: &str) -> bool {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "codex" | "claude" | "gemini"
            )
        })
}

fn lifecycle_role_category(role: &str) -> Result<RoleCategory> {
    match role {
        "supervise" | "autopilot" => Ok(RoleCategory::DelegatingCoordinator),
        other => RoleCategory::from_legacy_role(other),
    }
}

fn lifecycle_policy_role(role: &str) -> Option<AgentRole> {
    match role {
        "supervisor" => Some(AgentRole::Supervisor),
        "child_orchestrator" | "orchestrator" | "root" => Some(AgentRole::ChildOrchestrator),
        "worker" => Some(AgentRole::Worker),
        "gate_classifier" => Some(AgentRole::GateClassifier),
        "auditor" => Some(AgentRole::Auditor),
        _ => None,
    }
}

fn is_version_probe(argv: &[String]) -> bool {
    let args = argv.iter().skip(1).map(String::as_str).collect::<Vec<_>>();
    args.len() <= 3
        && args
            .iter()
            .any(|argument| matches!(*argument, "--version" | "-V" | "version"))
        && !args
            .iter()
            .any(|argument| matches!(*argument, "exec" | "app-server"))
}

fn configured_model_from_argv(argv: &[String]) -> Result<Option<String>> {
    let mut resolved = None;
    let mut index = 1;
    while index < argv.len() {
        let argument = argv[index].as_str();
        let candidate = if matches!(argument, "-m" | "--model") {
            index += 1;
            Some(
                argv.get(index)
                    .context("model option in agent argv is missing its value")?
                    .as_str(),
            )
        } else if let Some(model) = argument.strip_prefix("--model=") {
            Some(model)
        } else if matches!(argument, "-c" | "--config") {
            index += 1;
            argv.get(index)
                .context("config option in agent argv is missing its value")?
                .split_once('=')
                .filter(|(key, _)| key.trim() == "model")
                .map(|(_, value)| value.trim())
        } else {
            None
        };
        if let Some(candidate) = candidate {
            let candidate = candidate
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(candidate);
            if candidate.is_empty() {
                bail!("agent argv contains an empty model identity");
            }
            match &resolved {
                Some(existing) if existing != candidate => {
                    bail!("agent argv contains conflicting model identities")
                }
                Some(_) => {}
                None => resolved = Some(candidate.to_string()),
            }
        }
        index += 1;
    }
    Ok(resolved)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentityLiveness {
    Live,
    Stale,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentProcessInspection {
    pub process: AgentProcessRecord,
    pub identity: AgentIdentityLiveness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncertainty_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentListFilter {
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStopOutcome {
    Terminated,
    Killed,
    AlreadyExited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStopEntry {
    pub process: AgentProcessRecord,
    pub outcome: AgentStopOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStopFailureReason {
    Termination,
    RegistryUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStopFailure {
    pub process: AgentProcessRecord,
    pub reason: AgentStopFailureReason,
    /// Present when exit was confirmed but registry removal failed.
    pub outcome: Option<AgentStopOutcome>,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentStopReport {
    pub stopped: Vec<AgentStopEntry>,
    pub failures: Vec<AgentStopFailure>,
}

impl AgentStopReport {
    pub fn ensure_complete(&self) -> Result<()> {
        if !self.failures.is_empty() {
            let details = self
                .failures
                .iter()
                .map(|failure| {
                    format!(
                        "PID {} ({:?}): {}",
                        failure.process.pid, failure.reason, failure.error
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            bail!(
                "agent stop left {} unresolved target(s): {details}",
                self.failures.len()
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryState {
    version: u32,
    processes: Vec<AgentProcessRecord>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            processes: Vec::new(),
        }
    }
}

impl RegistryState {
    fn validate(&self, expected_repo: &Path) -> Result<()> {
        if self.version != REGISTRY_VERSION {
            bail!(
                "unsupported agent registry version {}; expected {}",
                self.version,
                REGISTRY_VERSION
            );
        }
        if self.processes.len() > MAX_REGISTRY_RECORDS {
            bail!("agent registry exceeds its record bound");
        }
        let mut identities = std::collections::BTreeSet::new();
        for process in &self.processes {
            process.validate(expected_repo)?;
            if !identities.insert((process.pid, process.process_start_time.as_str())) {
                bail!(
                    "agent registry contains a duplicate PID/start-time identity for PID {}",
                    process.pid
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AgentRegistry {
    repo: PathBuf,
}

impl AgentRegistry {
    pub fn open(repo: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            repo: discover_repo_root(repo)?,
        })
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn registry_path(&self) -> PathBuf {
        self.repo.join(".maco").join("agents").join(REGISTRY_FILE)
    }

    pub fn register(
        &self,
        metadata: &AgentLaunchMetadata,
        pid: u32,
        argv: Vec<String>,
    ) -> Result<AgentProcessRecord> {
        metadata.validate()?;
        if metadata.repo != self.repo {
            bail!(
                "agent launch repository {} does not match registry repository {}",
                metadata.repo.display(),
                self.repo.display()
            );
        }
        if argv.is_empty() {
            bail!("agent lifecycle registration requires a non-empty argv");
        }
        let record = AgentProcessRecord {
            pid,
            process_start_time: process_start_time(pid)
                .with_context(|| format!("failed to identify launched agent PID {pid}"))?,
            role: metadata.role.clone(),
            run_id: metadata.run_id.clone(),
            task_id: metadata.task_id.clone(),
            parent: metadata.parent.clone(),
            repo: self.repo.clone(),
            argv,
            launch_timestamp_ms: unix_timestamp_ms()?,
            mechanical_executor: None,
        };
        record.validate(&self.repo)?;
        self.update_state(|state| {
            state.processes.retain(|existing| existing.pid != pid);
            if state.processes.len() >= MAX_REGISTRY_RECORDS {
                bail!("agent registry is full");
            }
            state.processes.push(record.clone());
            state.processes.sort_by_key(|process| {
                (
                    process.launch_timestamp_ms,
                    process.pid,
                    process.process_start_time.clone(),
                )
            });
            Ok(())
        })?;
        Ok(record)
    }

    /// Register a launch whose mechanical-executor evidence comes only from a
    /// reserved consumed proof. Callers cannot pass deserialized evidence.
    pub(crate) fn register_reserved_mechanical_executor(
        &self,
        metadata: &AgentLaunchMetadata,
        pid: u32,
        argv: Vec<String>,
        current_dir: &Path,
        reserved: ReservedMechanicalExecutorExecution,
    ) -> Result<AgentProcessRecord> {
        metadata.validate()?;
        if metadata.repo != self.repo {
            bail!(
                "agent launch repository {} does not match registry repository {}",
                metadata.repo.display(),
                self.repo.display()
            );
        }
        if argv.is_empty() {
            bail!("agent lifecycle registration requires a non-empty argv");
        }
        authorize_process_launch_before_spawn(metadata, &argv, current_dir, Some(&reserved))?;
        let mechanical_executor = Some(evidence_from_reserved(&reserved)?);
        let record = AgentProcessRecord {
            pid,
            process_start_time: process_start_time(pid)
                .with_context(|| format!("failed to identify launched agent PID {pid}"))?,
            role: metadata.role.clone(),
            run_id: metadata.run_id.clone(),
            task_id: metadata.task_id.clone(),
            parent: metadata.parent.clone(),
            repo: self.repo.clone(),
            argv,
            launch_timestamp_ms: unix_timestamp_ms()?,
            mechanical_executor,
        };
        record.validate(&self.repo)?;
        self.update_state(|state| {
            state.processes.retain(|existing| existing.pid != pid);
            if state.processes.len() >= MAX_REGISTRY_RECORDS {
                bail!("agent registry is full");
            }
            state.processes.push(record.clone());
            state.processes.sort_by_key(|process| {
                (
                    process.launch_timestamp_ms,
                    process.pid,
                    process.process_start_time.clone(),
                )
            });
            Ok(())
        })?;
        Ok(record)
    }

    /// Inspect every durable registry record without pruning.
    ///
    /// Each record is classified as live, stale (gone or PID reuse), or uncertain.
    /// Process-enumeration failures are reported per record and never collapsed
    /// into an empty list.
    pub fn inspect(&self) -> Result<Vec<AgentProcessInspection>> {
        let records = self.snapshot_records()?;
        let mut inspections = Vec::with_capacity(records.len());
        for process in records {
            let (identity, uncertainty_reason) =
                match process_state(process.pid, &process.process_start_time) {
                    Ok(ProcessIdentityState::Live) => (AgentIdentityLiveness::Live, None),
                    Ok(ProcessIdentityState::Gone | ProcessIdentityState::Reused) => {
                        (AgentIdentityLiveness::Stale, None)
                    }
                    Err(error) => (AgentIdentityLiveness::Uncertain, Some(error.to_string())),
                };
            inspections.push(AgentProcessInspection {
                process,
                identity,
                uncertainty_reason,
            });
        }
        Ok(inspections)
    }

    pub fn unregister(&self, pid: u32, start_time: &str) -> Result<()> {
        self.remove_identity(pid, start_time)
    }

    pub fn list(&self, filter: &AgentListFilter) -> Result<Vec<AgentProcessRecord>> {
        if let Some(run_id) = &filter.run_id {
            validate_text_field("run id", run_id, MAX_IDENTIFIER_BYTES)?;
        }
        let mut live = Vec::new();
        self.update_state(|state| {
            let mut retained = Vec::with_capacity(state.processes.len());
            for record in std::mem::take(&mut state.processes) {
                match process_state(record.pid, &record.process_start_time)? {
                    ProcessIdentityState::Live => {
                        if filter
                            .run_id
                            .as_ref()
                            .is_none_or(|run_id| run_id == &record.run_id)
                        {
                            live.push(record.clone());
                        }
                        retained.push(record);
                    }
                    ProcessIdentityState::Gone | ProcessIdentityState::Reused => {}
                }
            }
            state.processes = retained;
            Ok(())
        })?;
        live.sort_by_key(|process| {
            (
                process.launch_timestamp_ms,
                process.pid,
                process.process_start_time.clone(),
            )
        });
        Ok(live)
    }

    pub fn stop_selector(&self, selector: &str, wait: Duration) -> Result<AgentStopReport> {
        validate_text_field("agent selector", selector, MAX_IDENTIFIER_BYTES)?;
        let matches = self
            .snapshot_records()?
            .into_iter()
            .filter(|process| {
                process.pid.to_string() == selector
                    || process.run_id == selector
                    || process.task_id == selector
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            bail!("no registered MACO agent matches selector '{selector}'");
        }
        let competing = competing_stop_records(&matches);
        if competing.len() > 1 {
            let details = competing
                .iter()
                .map(|process| process.summary())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "agent selector '{selector}' is ambiguous; {} matches: {details}",
                competing.len()
            );
        }
        self.stop_records(matches, wait)
    }

    pub fn stop_run(&self, run_id: &str, wait: Duration) -> Result<AgentStopReport> {
        validate_text_field("run id", run_id, MAX_IDENTIFIER_BYTES)?;
        let matches = self
            .snapshot_records()?
            .into_iter()
            .filter(|process| process.run_id == run_id)
            .collect();
        self.stop_records(matches, wait)
    }

    pub(crate) fn stop_assignment(
        &self,
        run_id: &str,
        task_id: &str,
        wait: Duration,
    ) -> Result<AgentStopReport> {
        validate_text_field("run id", run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", task_id, MAX_IDENTIFIER_BYTES)?;
        let matches = self
            .snapshot_records()?
            .into_iter()
            .filter(|process| process.run_id == run_id && process.task_id == task_id)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Ok(AgentStopReport::default());
        }
        let competing = competing_stop_records(&matches);
        if competing.len() > 1 {
            let details = competing
                .iter()
                .map(|process| process.summary())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "agent assignment ({run_id}, {task_id}) is ambiguous; {} matches: {details}",
                competing.len()
            );
        }
        let report = self.stop_records(matches, wait)?;
        report.ensure_complete()?;
        Ok(report)
    }

    fn stop_records(
        &self,
        records: Vec<AgentProcessRecord>,
        wait: Duration,
    ) -> Result<AgentStopReport> {
        self.stop_records_with_operations(records, wait, terminate_process, |process| {
            self.remove_identity(process.pid, &process.process_start_time)
        })
    }

    fn stop_records_with_operations(
        &self,
        records: Vec<AgentProcessRecord>,
        wait: Duration,
        mut terminate: impl FnMut(&AgentProcessRecord, Duration) -> Result<AgentStopOutcome>,
        mut remove: impl FnMut(&AgentProcessRecord) -> Result<()>,
    ) -> Result<AgentStopReport> {
        if wait > MAX_STOP_WAIT {
            bail!(
                "agent stop wait exceeds the maximum {} seconds",
                MAX_STOP_WAIT.as_secs()
            );
        }
        let mut report = AgentStopReport::default();
        for process in records {
            let outcome = match terminate(&process, wait) {
                Ok(outcome) => outcome,
                Err(error) => {
                    report.failures.push(AgentStopFailure {
                        process,
                        reason: AgentStopFailureReason::Termination,
                        outcome: None,
                        error: format!("{error:#}"),
                    });
                    continue;
                }
            };
            match remove(&process) {
                Ok(()) => report.stopped.push(AgentStopEntry { process, outcome }),
                Err(error) => report.failures.push(AgentStopFailure {
                    process,
                    reason: AgentStopFailureReason::RegistryUpdate,
                    outcome: Some(outcome),
                    error: format!("{error:#}"),
                }),
            }
        }
        Ok(report)
    }

    fn remove_identity(&self, pid: u32, start_time: &str) -> Result<()> {
        self.update_state(|state| {
            state.processes.retain(|process| {
                !(process.pid == pid && process.process_start_time == start_time)
            });
            Ok(())
        })
    }

    fn update_state(&self, operation: impl FnOnce(&mut RegistryState) -> Result<()>) -> Result<()> {
        let root = SafeRoot::open_or_create(self.repo.join(".maco").join("agents"))?;
        let lock = KernelStateLock::acquire_direct(&root, REGISTRY_LOCK)?;
        AtomicStateWriter::scavenge_direct_temps(&root, REGISTRY_FILE)?;
        let registry_existed = root.direct_child_exists(REGISTRY_FILE)?;
        let before = read_state(&root, &self.repo)?;
        let mut state = before.clone();
        operation(&mut state)?;
        state.validate(&self.repo)?;
        if registry_existed && state == before {
            lock.verify_direct_binding(&root)?;
            return Ok(());
        }
        let mut contents =
            serde_json::to_vec_pretty(&state).context("failed to serialize agent registry")?;
        contents.push(b'\n');
        AtomicStateWriter::write_direct_fenced(&root, REGISTRY_FILE, &contents, || {
            lock.verify_direct_binding(&root)
        })
        .context("failed to commit agent registry")
    }

    #[cfg(test)]
    fn replace_records(&self, records: Vec<AgentProcessRecord>) -> Result<()> {
        self.update_state(|state| {
            state.processes = records;
            Ok(())
        })
    }

    fn snapshot_records(&self) -> Result<Vec<AgentProcessRecord>> {
        let root = SafeRoot::open_or_create(self.repo.join(".maco").join("agents"))?;
        let _lock = KernelStateLock::acquire_direct(&root, REGISTRY_LOCK)?;
        Ok(read_state(&root, &self.repo)?.processes)
    }

    #[cfg(test)]
    fn snapshot_all(&self) -> Result<Vec<AgentProcessRecord>> {
        self.snapshot_records()
    }
}

fn competing_stop_records(records: &[AgentProcessRecord]) -> Vec<&AgentProcessRecord> {
    records
        .iter()
        .filter(|process| {
            !matches!(
                process_state(process.pid, &process.process_start_time),
                Ok(ProcessIdentityState::Gone | ProcessIdentityState::Reused)
            )
        })
        .collect()
}

fn read_state(root: &SafeRoot, repo: &Path) -> Result<RegistryState> {
    if !root.direct_child_exists(REGISTRY_FILE)? {
        return Ok(RegistryState::default());
    }
    let contents = BoundedRegularReader::read_direct(root, REGISTRY_FILE, MAX_REGISTRY_BYTES)
        .context("failed to read agent registry")?;
    let state: RegistryState =
        serde_json::from_slice(&contents).context("agent registry is not valid JSON")?;
    state.validate(repo)?;
    Ok(state)
}

fn validate_text_field(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("{label} is empty or exceeds its safety bound");
    }
    Ok(())
}

fn unix_timestamp_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("launch timestamp does not fit u64")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessIdentityState {
    Live,
    Gone,
    Reused,
}

fn process_state(pid: u32, expected_start_time: &str) -> Result<ProcessIdentityState> {
    process_state_with_probes(pid, expected_start_time, process_exists, process_identity)
}

fn process_state_with_probes(
    pid: u32,
    expected_start_time: &str,
    exists: impl FnOnce(u32) -> Result<bool>,
    identity: impl FnOnce(u32) -> Result<(char, String)>,
) -> Result<ProcessIdentityState> {
    if !supported_process_start_time(pid, expected_start_time) {
        bail!("recorded process incarnation is unsupported or malformed; liveness is uncertain");
    }
    if !exists(pid)? {
        return Ok(ProcessIdentityState::Gone);
    }
    match identity(pid) {
        Ok((state, observed)) => {
            if !supported_process_start_time(pid, &observed) {
                bail!("observed process incarnation is unsupported or malformed; liveness is uncertain");
            }
            if matches!(state, 'Z' | 'X') {
                Ok(ProcessIdentityState::Gone)
            } else if observed == expected_start_time {
                Ok(ProcessIdentityState::Live)
            } else {
                Ok(ProcessIdentityState::Reused)
            }
        }
        Err(error) if vanished_identity_error(&error) => Ok(ProcessIdentityState::Gone),
        Err(error) => Err(error),
    }
}

pub(crate) fn supported_process_start_time(pid: u32, token: &str) -> bool {
    if pid == 0 || token.len() > MAX_IDENTIFIER_BYTES || !token.is_ascii() {
        return false;
    }
    let mut parts = token.split(':');
    if parts.next() != Some("linux-v2") {
        return false;
    }
    let (Some(recorded_pid), Some(boot_id), Some(start_ticks), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    recorded_pid == pid.to_string()
        && canonical_linux_boot_id(boot_id)
        && start_ticks
            .parse::<u64>()
            .is_ok_and(|value| value.to_string() == start_ticks)
}

fn canonical_linux_boot_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
        && bytes
            .iter()
            .any(|byte| matches!(*byte, b'1'..=b'9' | b'a'..=b'f'))
}

fn vanished_identity_error(error: &anyhow::Error) -> bool {
    let Some(io) = error.downcast_ref::<std::io::Error>() else {
        return false;
    };
    if io.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    // Linux can report ESRCH, rather than ENOENT, when /proc/<pid>/stat vanishes
    // after the preceding kill(pid, 0) liveness probe.
    #[cfg(target_os = "linux")]
    if io.raw_os_error() == Some(libc::ESRCH) {
        return true;
    }
    false
}

#[cfg(unix)]
fn process_exists(pid: u32) -> Result<bool> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: signal 0 performs an existence/permission check and does not access Rust memory.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error).context("failed to probe process liveness"),
    }
}

#[cfg(not(unix))]
fn process_exists(_pid: u32) -> Result<bool> {
    bail!("agent process liveness checks are not implemented on this platform")
}

#[cfg(target_os = "linux")]
pub fn process_start_time(pid: u32) -> Result<String> {
    process_identity(pid).map(|(_, start_time)| start_time)
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Result<(char, String)> {
    process_identity_with_reader(pid, |path| Ok(std::fs::read_to_string(path)?))
}

#[cfg(target_os = "linux")]
fn process_identity_with_reader(
    pid: u32,
    mut read: impl FnMut(&Path) -> Result<String>,
) -> Result<(char, String)> {
    if pid == 0 {
        bail!("process identity requires a positive PID");
    }
    let path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let stat = read(&path)
        .with_context(|| format!("failed to read process identity {}", path.display()))?;
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .context("process stat identity is malformed")?;
    let mut fields = fields.split_ascii_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .context("process stat omits the state field")?;
    let token = fields
        .nth(18)
        .context("process stat omits the start-time field")?;
    let token = token
        .parse::<u64>()
        .context("process start-time field is not an integer")?;
    // A boot-source read failure is not evidence that /proc/<pid>/stat vanished.
    // Deliberately omit its I/O error chain so ENOENT/ESRCH cannot authorize cleanup.
    let boot_id = read(Path::new("/proc/sys/kernel/random/boot_id"))
        .map_err(|_| anyhow::anyhow!("Linux boot UUID identity is unavailable"))?;
    let boot_id = boot_id.strip_suffix('\n').unwrap_or(&boot_id);
    if !canonical_linux_boot_id(boot_id) {
        bail!("Linux boot UUID identity is malformed");
    }
    let incarnation = format!("linux-v2:{pid}:{boot_id}:{token}");
    if !supported_process_start_time(pid, &incarnation) {
        bail!("Linux process incarnation is malformed");
    }
    Ok((state, incarnation))
}

#[cfg(not(target_os = "linux"))]
fn process_identity(_pid: u32) -> Result<(char, String)> {
    bail!("PID start-time identity is not implemented on this platform")
}

#[cfg(not(target_os = "linux"))]
pub fn process_start_time(_pid: u32) -> Result<String> {
    bail!("PID start-time identity is not implemented on this platform")
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: libc::c_int) -> Result<bool> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: kill sends the caller-supplied valid signal to one positive PID and does not access
    // Rust memory.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error).context("failed to signal agent process")
    }
}

#[cfg(not(unix))]
fn signal_process(_pid: u32, _signal: libc::c_int) -> Result<bool> {
    bail!("agent process signals are not implemented on this platform")
}

#[cfg(target_os = "linux")]
enum LinuxSignalTarget {
    Pidfd(std::os::fd::OwnedFd),
    RawPid(u32),
}

#[cfg(target_os = "linux")]
enum PidfdOpen {
    Open(std::os::fd::OwnedFd),
    Gone,
    Unsupported,
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<PidfdOpen> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: pidfd_open only consumes a positive PID and flags; it does not access Rust memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(PidfdOpen::Gone),
            Some(libc::ENOSYS) => Ok(PidfdOpen::Unsupported),
            _ => Err(error).context("failed to open a pidfd for the recorded agent process"),
        };
    }
    let fd = i32::try_from(fd).context("pidfd did not fit a file descriptor")?;
    // SAFETY: pidfd_open returned a new owned file descriptor on success.
    Ok(PidfdOpen::Open(unsafe {
        std::os::fd::FromRawFd::from_raw_fd(fd)
    }))
}

#[cfg(target_os = "linux")]
fn bind_linux_signal_target(record: &AgentProcessRecord) -> Result<Option<LinuxSignalTarget>> {
    match process_state(record.pid, &record.process_start_time)? {
        ProcessIdentityState::Gone | ProcessIdentityState::Reused => return Ok(None),
        ProcessIdentityState::Live => {}
    }
    match open_pidfd(record.pid)? {
        PidfdOpen::Gone => Ok(None),
        PidfdOpen::Unsupported => Ok(Some(LinuxSignalTarget::RawPid(record.pid))),
        PidfdOpen::Open(pidfd) => match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Reused => Ok(None),
            ProcessIdentityState::Live | ProcessIdentityState::Gone => {
                Ok(Some(LinuxSignalTarget::Pidfd(pidfd)))
            }
        },
    }
}

#[cfg(target_os = "linux")]
fn signal_linux_target(target: &LinuxSignalTarget, signal: libc::c_int) -> Result<bool> {
    match target {
        LinuxSignalTarget::RawPid(pid) => signal_process(*pid, signal),
        LinuxSignalTarget::Pidfd(pidfd) => {
            use std::os::fd::AsRawFd;
            // SAFETY: pidfd is an owned pidfd; a null siginfo and zero flags request a
            // plain signal to that process instance, not a recycled PID.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::c_void>(),
                    0_u32,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else {
                Err(error).context("failed to signal agent process through its pidfd")
            }
        }
    }
}

fn terminate_process(record: &AgentProcessRecord, wait: Duration) -> Result<AgentStopOutcome> {
    #[cfg(target_os = "linux")]
    {
        let Some(target) = bind_linux_signal_target(record)? else {
            return Ok(AgentStopOutcome::AlreadyExited);
        };
        if !signal_linux_target(&target, libc::SIGTERM)? {
            return Ok(AgentStopOutcome::AlreadyExited);
        }
        if wait_until_identity_gone(record, wait)? {
            return Ok(AgentStopOutcome::Terminated);
        }
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::Terminated);
            }
            ProcessIdentityState::Live => {}
        }
        if !signal_linux_target(&target, libc::SIGKILL)? {
            return Ok(AgentStopOutcome::Killed);
        }
        if wait_until_identity_gone(record, KILL_CONFIRMATION_WAIT)? {
            Ok(AgentStopOutcome::Killed)
        } else {
            bail!("PID {} remained live after SIGKILL escalation", record.pid)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::AlreadyExited);
            }
            ProcessIdentityState::Live => {}
        }
        #[cfg(unix)]
        let term_signal = libc::SIGTERM;
        #[cfg(not(unix))]
        let term_signal = 0;
        if !signal_process(record.pid, term_signal)? {
            return Ok(AgentStopOutcome::AlreadyExited);
        }
        if wait_until_identity_gone(record, wait)? {
            return Ok(AgentStopOutcome::Terminated);
        }
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::Terminated);
            }
            ProcessIdentityState::Live => {}
        }
        #[cfg(unix)]
        let kill_signal = libc::SIGKILL;
        #[cfg(not(unix))]
        let kill_signal = 0;
        if !signal_process(record.pid, kill_signal)? {
            return Ok(AgentStopOutcome::Killed);
        }
        if wait_until_identity_gone(record, KILL_CONFIRMATION_WAIT)? {
            Ok(AgentStopOutcome::Killed)
        } else {
            bail!("PID {} remained live after SIGKILL escalation", record.pid)
        }
    }
}

fn wait_until_identity_gone(record: &AgentProcessRecord, duration: Duration) -> Result<bool> {
    let deadline = Instant::now()
        .checked_add(duration)
        .context("agent stop wait exceeds the platform Instant range")?;
    loop {
        if !matches!(
            process_state(record.pid, &record.process_start_time)?,
            ProcessIdentityState::Live
        ) {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(STOP_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository;
    use std::process::{Child, Command};
    use tempfile::TempDir;

    #[test]
    #[cfg(target_os = "linux")]
    fn vanished_process_between_liveness_probe_and_identity_read_is_gone() -> Result<()> {
        let missing_stat = std::io::Error::from_raw_os_error(libc::ESRCH);
        assert_ne!(missing_stat.kind(), std::io::ErrorKind::NotFound);
        let state = process_state_with_probes(
            77,
            "linux-v2:77:11111111-2222-3333-4444-555555555555:1",
            |_| Ok(true),
            |_| Err(anyhow::Error::new(missing_stat).context("failed to read /proc/77/stat")),
        )?;
        assert_eq!(state, ProcessIdentityState::Gone);
        Ok(())
    }

    #[test]
    fn identity_probe_preserves_permission_and_reused_pid_failures() -> Result<()> {
        let denied = process_state_with_probes(
            77,
            "linux-v2:77:11111111-2222-3333-4444-555555555555:1",
            |_| Ok(true),
            |_| {
                Err(
                    anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                        .context("failed to read /proc/77/stat"),
                )
            },
        );
        assert!(denied.is_err());
        let reused = process_state_with_probes(
            77,
            "linux-v2:77:11111111-2222-3333-4444-555555555555:1",
            |_| Ok(true),
            |_| {
                Ok((
                    'S',
                    "linux-v2:77:11111111-2222-3333-4444-555555555555:2".to_string(),
                ))
            },
        )?;
        assert_eq!(reused, ProcessIdentityState::Reused);
        Ok(())
    }

    struct SleepChild(Child);

    impl SleepChild {
        fn spawn() -> Result<Self> {
            let program = [
                "/run/current-system/sw/bin/sleep",
                "/usr/bin/sleep",
                "/bin/sleep",
            ]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .context("sleep executable")?;
            Ok(Self(
                Command::new(program)
                    .arg("60")
                    .spawn()
                    .context("spawn sleep")?,
            ))
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for SleepChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn registry() -> Result<(TempDir, AgentRegistry)> {
        let temp = TempDir::new().context("tempdir")?;
        Repository::init(temp.path()).context("init repository")?;
        let registry = AgentRegistry::open(temp.path())?;
        Ok((temp, registry))
    }

    fn metadata(
        registry: &AgentRegistry,
        run_id: &str,
        task_id: &str,
    ) -> Result<AgentLaunchMetadata> {
        AgentLaunchMetadata::new(registry.repo(), "worker", run_id, task_id)
    }

    #[test]
    fn registry_round_trip_preserves_process_record() -> Result<()> {
        let (_temp, registry) = registry()?;
        let child = SleepChild::spawn()?;
        let expected = registry.register(
            &metadata(&registry, "run-round-trip", "task-a")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        let listed = registry.list(&AgentListFilter::default())?;
        assert_eq!(listed, vec![expected]);
        Ok(())
    }

    #[test]
    fn stale_gc_removes_dead_and_reused_pid_records() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut dead = SleepChild::spawn()?;
        let dead_record = registry.register(
            &metadata(&registry, "run-stale", "dead")?,
            dead.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        dead.0.kill().context("kill dead fixture")?;
        dead.0.wait().context("wait dead fixture")?;

        let current_pid = std::process::id();
        let mut reused = AgentProcessRecord {
            pid: current_pid,
            process_start_time: process_start_time(current_pid)?,
            role: "worker".to_string(),
            run_id: "run-stale".to_string(),
            task_id: "reused".to_string(),
            parent: None,
            repo: registry.repo().to_path_buf(),
            argv: vec!["test".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
            mechanical_executor: None,
        };
        reused.process_start_time.push('0');
        registry.replace_records(vec![dead_record, reused])?;

        assert!(registry.list(&AgentListFilter::default())?.is_empty());
        assert!(registry.snapshot_all()?.is_empty());
        let reopened = AgentRegistry::open(registry.repo())?;
        assert!(reopened.snapshot_all()?.is_empty());
        Ok(())
    }

    #[test]
    fn first_list_initializes_absent_registry_file() -> Result<()> {
        let (_temp, registry) = registry()?;
        let path = registry.registry_path();
        assert!(!path.exists());
        assert!(registry.list(&AgentListFilter::default())?.is_empty());
        assert!(path.is_file());
        assert!(registry.snapshot_all()?.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unchanged_list_preserves_registry_file_identity_and_bytes() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let (_temp, registry) = registry()?;
        let child = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-noop-list", "task-noop")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let path = registry.registry_path();
        let handle = std::fs::File::open(&path).context("open registry for identity pinning")?;
        let before_meta = handle.metadata().context("registry metadata before list")?;
        let before_bytes = std::fs::read(&path).context("registry bytes before list")?;

        registry.list(&AgentListFilter::default())?;

        let after_meta = std::fs::metadata(&path).context("registry metadata after list")?;
        assert_eq!(before_meta.dev(), after_meta.dev());
        assert_eq!(before_meta.ino(), after_meta.ino());
        assert_eq!(std::fs::read(&path)?, before_bytes);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stale_prune_rewrites_registry_file() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let (_temp, registry) = registry()?;
        let mut dead = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-prune-write", "dead")?,
            dead.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let path = registry.registry_path();
        let handle = std::fs::File::open(&path).context("pin pre-prune registry inode")?;
        let before_ino = handle.metadata()?.ino();
        dead.0.kill().context("kill prune fixture")?;
        dead.0.wait().context("wait prune fixture")?;

        assert!(registry.list(&AgentListFilter::default())?.is_empty());
        let after_ino = std::fs::metadata(&path)?.ino();
        assert_ne!(before_ino, after_ino);
        let reopened = AgentRegistry::open(registry.repo())?;
        assert!(reopened.snapshot_all()?.is_empty());
        Ok(())
    }

    #[test]
    fn inspect_reports_live_and_stale_without_pruning() -> Result<()> {
        let (_temp, registry) = registry()?;
        let live = SleepChild::spawn()?;
        let live_record = registry.register(
            &metadata(&registry, "run-inspect", "live")?,
            live.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let mut dead = SleepChild::spawn()?;
        let dead_record = registry.register(
            &metadata(&registry, "run-inspect", "dead")?,
            dead.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        dead.0.kill().context("kill inspect fixture")?;
        dead.0.wait().context("wait inspect fixture")?;

        let inspections = registry.inspect()?;
        assert_eq!(inspections.len(), 2);
        let live_inspection = inspections
            .iter()
            .find(|inspection| inspection.process.pid == live_record.pid)
            .context("live inspection")?;
        let stale_inspection = inspections
            .iter()
            .find(|inspection| inspection.process.pid == dead_record.pid)
            .context("stale inspection")?;
        assert_eq!(live_inspection.identity, AgentIdentityLiveness::Live);
        assert_eq!(stale_inspection.identity, AgentIdentityLiveness::Stale);
        assert_eq!(registry.snapshot_all()?.len(), 2);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn identity_stat_fixture(ticks: u64) -> String {
        format!("77 (fixture name) S {} {ticks}", vec!["0"; 18].join(" "))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_identity_ignores_wall_boot_time_changes() -> Result<()> {
        let stat = identity_stat_fixture(456);
        let mut tokens = Vec::new();
        for wall_btime in [12345, 12347] {
            let mut reads = Vec::new();
            let (_, token) = process_identity_with_reader(77, |path| {
                reads.push(path.to_path_buf());
                match path.to_str() {
                    Some("/proc/77/stat") => Ok(stat.clone()),
                    Some("/proc/sys/kernel/random/boot_id") => {
                        Ok("11111111-2222-3333-4444-555555555555\n".into())
                    }
                    Some("/proc/stat") => Ok(format!("btime {wall_btime}\n")),
                    _ => bail!("unexpected identity source"),
                }
            })?;
            assert_eq!(
                reads,
                vec![
                    PathBuf::from("/proc/77/stat"),
                    PathBuf::from("/proc/sys/kernel/random/boot_id")
                ]
            );
            tokens.push(token);
        }
        assert_eq!(tokens[0], tokens[1]);
        assert!(supported_process_start_time(77, &tokens[0]));
        Ok(())
    }

    #[test]
    fn supported_incarnations_bind_pid_boot_and_full_start_ticks() -> Result<()> {
        let recorded = "linux-v2:77:11111111-2222-3333-4444-555555555555:456";
        assert!(supported_process_start_time(77, recorded));
        assert!(!supported_process_start_time(78, recorded));
        for observed in [
            "linux-v2:77:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:456",
            "linux-v2:77:11111111-2222-3333-4444-555555555555:457",
        ] {
            assert_eq!(
                process_state_with_probes(
                    77,
                    recorded,
                    |_| Ok(true),
                    |_| { Ok(('S', observed.into())) }
                )?,
                ProcessIdentityState::Reused
            );
        }
        assert_eq!(
            process_state_with_probes(
                77,
                recorded,
                |_| Ok(true),
                |_| { Ok(('S', recorded.into())) }
            )?,
            ProcessIdentityState::Live
        );
        for observed in [
            "123:456",
            "linux-v3:77:11111111-2222-3333-4444-555555555555:456",
            "linux-v2:78:11111111-2222-3333-4444-555555555555:456",
        ] {
            assert!(process_state_with_probes(
                77,
                recorded,
                |_| Ok(true),
                |_| { Ok(('S', observed.into())) }
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn unsupported_recorded_incarnations_refuse_before_process_probes() {
        for token in [
            "123:456",
            "linux-v2:0:11111111-2222-3333-4444-555555555555:456",
            "linux-v2:077:11111111-2222-3333-4444-555555555555:456",
            "linux-v2:77:00000000-0000-0000-0000-000000000000:456",
            "linux-v2:77:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE:456",
            "linux-v2:77:11111111-2222-3333-4444-555555555555:0456",
            "linux-v2:77:11111111-2222-3333-4444-555555555555:18446744073709551616",
            "linux-v2:77:11111111-2222-3333-4444-555555555555:456:extra",
        ] {
            assert!(process_state_with_probes(
                77,
                token,
                |_| panic!("unsupported record must not probe existence"),
                |_| panic!("unsupported record must not read identity")
            )
            .is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boot_source_failures_are_uncertain_but_missing_process_stat_is_gone() -> Result<()> {
        let recorded = "linux-v2:77:11111111-2222-3333-4444-555555555555:456";
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let error = process_identity_with_reader(77, |path| {
                if path == Path::new("/proc/77/stat") {
                    Ok(identity_stat_fixture(456))
                } else {
                    Err(std::io::Error::from(kind).into())
                }
            })
            .unwrap_err();
            assert!(!vanished_identity_error(&error));
            assert!(process_state_with_probes(77, recorded, |_| Ok(true), |_| Err(error)).is_err());
        }
        for boot in ["malformed", "00000000-0000-0000-0000-000000000000\n"] {
            assert!(process_identity_with_reader(77, |path| {
                if path == Path::new("/proc/77/stat") {
                    Ok(identity_stat_fixture(456))
                } else {
                    Ok(boot.into())
                }
            })
            .is_err());
        }
        for error in [
            std::io::Error::from(std::io::ErrorKind::NotFound),
            std::io::Error::from_raw_os_error(libc::ESRCH),
        ] {
            let mut error = Some(error);
            let identity = process_identity_with_reader(77, |_| {
                Err(error.take().expect("one process-stat read").into())
            });
            assert_eq!(
                process_state_with_probes(77, recorded, |_| Ok(true), |_| identity)?,
                ProcessIdentityState::Gone
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_registry_identity_stays_uncertain_without_pruning_or_signalling() -> Result<()> {
        let (_temp, registry) = registry()?;
        let record = AgentProcessRecord {
            pid: std::process::id(),
            process_start_time: "123:456".into(),
            role: "worker".into(),
            run_id: "run-legacy-identity".into(),
            task_id: "task-legacy-identity".into(),
            parent: None,
            repo: registry.repo().to_path_buf(),
            argv: vec!["fixture".into()],
            launch_timestamp_ms: 1,
            mechanical_executor: None,
        };
        registry.replace_records(vec![record.clone()])?;
        let registry_path = registry.repo().join(".maco/agents/registry.json");
        let before = std::fs::read(&registry_path)?;
        let inspections = registry.inspect()?;
        assert_eq!(inspections.len(), 1);
        assert_eq!(inspections[0].identity, AgentIdentityLiveness::Uncertain);
        assert!(registry.list(&AgentListFilter::default()).is_err());
        assert!(terminate_process(&record, Duration::from_millis(10)).is_err());
        assert!(registry
            .stop_assignment(&record.run_id, &record.task_id, Duration::from_millis(10))
            .is_err());
        assert_eq!(std::fs::read(&registry_path)?, before);
        assert_eq!(registry.snapshot_all()?, vec![record]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_start_time_is_boot_scoped() -> Result<()> {
        let token = process_start_time(std::process::id())?;
        assert!(supported_process_start_time(std::process::id(), &token));
        let parts = token.split(':').collect::<Vec<_>>();
        assert_eq!(parts[0], "linux-v2");
        assert_eq!(parts[1], std::process::id().to_string());
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        assert_eq!(parts[2], boot_id.strip_suffix('\n').unwrap_or(&boot_id));
        assert!(parts[3].parse::<u64>()? > 0);
        Ok(())
    }

    #[test]
    fn list_filters_by_run_id() -> Result<()> {
        let (_temp, registry) = registry()?;
        let first = SleepChild::spawn()?;
        let second = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-one", "task-one")?,
            first.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let expected = registry.register(
            &metadata(&registry, "run-two", "task-two")?,
            second.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        assert_eq!(
            registry.list(&AgentListFilter {
                run_id: Some("run-two".to_string())
            })?,
            vec![expected]
        );
        Ok(())
    }

    #[test]
    fn registry_preserves_parent_linkage() -> Result<()> {
        let (_temp, registry) = registry()?;
        let child = SleepChild::spawn()?;
        let expected = registry.register(
            &metadata(&registry, "run-parented", "task-child")?.with_parent("run-parented")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        assert_eq!(expected.parent.as_deref(), Some("run-parented"));
        assert_eq!(
            registry.list(&AgentListFilter {
                run_id: Some("run-parented".to_string())
            })?,
            vec![expected]
        );
        Ok(())
    }

    #[test]
    fn stop_refuses_ambiguous_selector_and_lists_matches() -> Result<()> {
        let (_temp, registry) = registry()?;
        let first = SleepChild::spawn()?;
        let second = SleepChild::spawn()?;
        for (task, child) in [("task-one", &first), ("task-two", &second)] {
            registry.register(
                &metadata(&registry, "shared-run", task)?,
                child.pid(),
                vec!["sleep".to_string(), "60".to_string()],
            )?;
        }

        let error = registry
            .stop_selector("shared-run", Duration::from_millis(50))
            .expect_err("selector must be ambiguous");
        let message = error.to_string();
        assert!(message.contains("ambiguous"));
        assert!(message.contains(&first.pid().to_string()));
        assert!(message.contains(&second.pid().to_string()));
        assert!(process_exists(first.pid())?);
        assert!(process_exists(second.pid())?);
        Ok(())
    }

    #[test]
    fn stop_assignment_refuses_ambiguous_same_run_and_task() -> Result<()> {
        let (_temp, registry) = registry()?;
        let first = SleepChild::spawn()?;
        let second = SleepChild::spawn()?;
        for child in [&first, &second] {
            registry.register(
                &metadata(&registry, "shared-run", "shared-task")?,
                child.pid(),
                vec!["sleep".to_string(), "60".to_string()],
            )?;
        }

        let error = registry
            .stop_assignment("shared-run", "shared-task", Duration::from_millis(50))
            .expect_err("assignment must be ambiguous");
        let message = error.to_string();
        assert!(message.contains("ambiguous"));
        assert!(message.contains(&first.pid().to_string()));
        assert!(message.contains(&second.pid().to_string()));
        assert!(process_exists(first.pid())?);
        assert!(process_exists(second.pid())?);
        Ok(())
    }

    #[test]
    fn stop_terminates_spawned_long_running_child() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut child = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-stop", "task-stop")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        let report = registry.stop_selector("task-stop", Duration::from_secs(1))?;
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].outcome, AgentStopOutcome::Terminated);
        let status = child.0.wait().context("wait stopped child")?;
        assert!(!status.success());
        assert!(registry.snapshot_all()?.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn single_target_stop_ignores_stale_siblings_and_removes_both_records() -> Result<()> {
        for assignment in [false, true] {
            for reused in [false, true] {
                let (_temp, registry) = registry()?;
                let mut stale_child = SleepChild::spawn()?;
                let mut live_child = SleepChild::spawn()?;
                let mut stale = registry.register(
                    &metadata(&registry, "restarted-run", "restarted-task")?,
                    stale_child.pid(),
                    vec!["sleep".into()],
                )?;
                let live = registry.register(
                    &metadata(&registry, "restarted-run", "restarted-task")?,
                    live_child.pid(),
                    vec!["sleep".into()],
                )?;
                if reused {
                    let (incarnation, ticks) = stale
                        .process_start_time
                        .rsplit_once(':')
                        .context("fixture incarnation")?;
                    stale.process_start_time =
                        format!("{incarnation}:{}", ticks.parse::<u64>()? ^ 1);
                    registry.replace_records(vec![stale.clone(), live.clone()])?;
                } else {
                    stale_child.0.kill()?;
                    stale_child.0.wait()?;
                }

                let report = if assignment {
                    registry.stop_assignment(
                        "restarted-run",
                        "restarted-task",
                        Duration::from_secs(1),
                    )?
                } else {
                    registry.stop_selector("restarted-task", Duration::from_secs(1))?
                };
                report.ensure_complete()?;
                assert_eq!(report.stopped.len(), 2);
                assert!(report.stopped.iter().any(|entry| {
                    entry.process == stale && entry.outcome == AgentStopOutcome::AlreadyExited
                }));
                assert!(report.stopped.iter().any(|entry| {
                    entry.process == live && entry.outcome == AgentStopOutcome::Terminated
                }));
                assert!(!live_child.0.wait()?.success());
                if reused {
                    assert!(stale_child.0.try_wait()?.is_none());
                }
                assert!(registry.snapshot_all()?.is_empty());
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn single_target_stop_keeps_uncertain_siblings_competing() -> Result<()> {
        for assignment in [false, true] {
            let (_temp, registry) = registry()?;
            let mut uncertain_child = SleepChild::spawn()?;
            let mut live_child = SleepChild::spawn()?;
            let mut uncertain = registry.register(
                &metadata(&registry, "uncertain-run", "uncertain-task")?,
                uncertain_child.pid(),
                vec!["sleep".into()],
            )?;
            let live = registry.register(
                &metadata(&registry, "uncertain-run", "uncertain-task")?,
                live_child.pid(),
                vec!["sleep".into()],
            )?;
            uncertain.process_start_time = "123:456".into();
            let records = vec![uncertain, live];
            registry.replace_records(records.clone())?;

            let result = if assignment {
                registry.stop_assignment("uncertain-run", "uncertain-task", Duration::from_secs(1))
            } else {
                registry.stop_selector("uncertain-task", Duration::from_secs(1))
            };
            let error = result.expect_err("uncertain and live rows must compete");
            let message = error.to_string();
            assert!(message.contains("ambiguous; 2 matches"));
            assert!(message.contains(&uncertain_child.pid().to_string()));
            assert!(message.contains(&live_child.pid().to_string()));
            assert!(uncertain_child.0.try_wait()?.is_none());
            assert!(live_child.0.try_wait()?.is_none());
            assert_eq!(registry.snapshot_all()?, records);
        }
        Ok(())
    }

    #[test]
    fn batch_stop_continues_after_target_and_bookkeeping_failures() -> Result<()> {
        for failed_index in [0, 1] {
            let (_temp, registry) = registry()?;
            let children = (0..4)
                .map(|_| SleepChild::spawn())
                .collect::<Result<Vec<_>>>()?;
            let records = children
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    registry.register(
                        &metadata(&registry, "run-batch", &format!("task-{index}"))?,
                        child.pid(),
                        vec!["sleep".into()],
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let mut attempted = Vec::new();
            let mut removals = Vec::new();
            let report = registry.stop_records_with_operations(
                records.clone(),
                Duration::from_millis(10),
                |process, _| {
                    attempted.push(process.pid);
                    if process == &records[failed_index] {
                        bail!("termination fixture refusal");
                    }
                    Ok(AgentStopOutcome::AlreadyExited)
                },
                |process| {
                    removals.push(process.pid);
                    if process == &records[2] {
                        bail!("registry fixture refusal");
                    }
                    registry.remove_identity(process.pid, &process.process_start_time)
                },
            )?;
            assert_eq!(attempted, records.iter().map(|p| p.pid).collect::<Vec<_>>());
            assert_eq!(removals.len(), 3);
            assert!(!removals.contains(&records[failed_index].pid));
            assert_eq!(report.stopped.len(), 2);
            assert_eq!(report.stopped.last().unwrap().process, records[3]);
            assert_eq!(report.failures.len(), 2);
            assert_eq!(report.failures[0].process, records[failed_index]);
            assert_eq!(
                report.failures[0].reason,
                AgentStopFailureReason::Termination
            );
            assert_eq!(report.failures[0].outcome, None);
            assert_eq!(report.failures[1].process, records[2]);
            assert_eq!(
                report.failures[1].reason,
                AgentStopFailureReason::RegistryUpdate
            );
            assert_eq!(
                report.failures[1].outcome,
                Some(AgentStopOutcome::AlreadyExited)
            );
            let error = report.ensure_complete().unwrap_err().to_string();
            assert!(error.contains(&format!("PID {} (Termination)", records[failed_index].pid)));
            assert!(error.contains("termination fixture refusal"));
            assert!(error.contains(&format!("PID {} (RegistryUpdate)", records[2].pid)));
            assert!(error.contains("registry fixture refusal"));
            let remaining = registry.snapshot_all()?;
            assert_eq!(remaining.len(), 2);
            assert!(remaining.contains(&records[failed_index]));
            assert!(remaining.contains(&records[2]));
        }
        Ok(())
    }

    #[test]
    fn batch_stop_retry_preserves_unresolved_identity() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut children = (0..3)
            .map(|_| SleepChild::spawn())
            .collect::<Result<Vec<_>>>()?;
        let records = children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                registry.register(
                    &metadata(&registry, "run-retry", &format!("task-{index}"))?,
                    child.pid(),
                    vec!["sleep".into()],
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let report = registry.stop_records_with_operations(
            records.clone(),
            Duration::from_secs(1),
            |process, wait| {
                if process == &records[0] {
                    bail!("termination fixture refusal");
                }
                terminate_process(process, wait)
            },
            |process| {
                if process == &records[1] {
                    bail!("registry fixture refusal");
                }
                registry.remove_identity(process.pid, &process.process_start_time)
            },
        )?;
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.failures.len(), 2);
        assert_eq!(registry.snapshot_all()?, records[..2]);
        assert!(children[0].0.try_wait()?.is_none());
        children[1].0.wait()?;
        children[2].0.wait()?;

        let retry = registry.stop_run("run-retry", Duration::from_secs(1))?;
        retry.ensure_complete()?;
        assert_eq!(retry.stopped.len(), 2);
        assert!(retry.stopped.iter().any(|entry| {
            entry.process == records[0] && entry.outcome == AgentStopOutcome::Terminated
        }));
        assert!(retry.stopped.iter().any(|entry| {
            entry.process == records[1] && entry.outcome == AgentStopOutcome::AlreadyExited
        }));
        children[0].0.wait()?;
        assert!(registry.snapshot_all()?.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batch_stop_reports_absent_reused_and_uncertain_identities() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut children = (0..5)
            .map(|_| SleepChild::spawn())
            .collect::<Result<Vec<_>>>()?;
        let mut records = children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                registry.register(
                    &metadata(&registry, "run-mixed", &format!("task-{index}"))?,
                    child.pid(),
                    vec!["sleep".into()],
                )
            })
            .collect::<Result<Vec<_>>>()?;
        records[0].process_start_time = "123:456".into();
        children[1].0.kill()?;
        children[1].0.wait()?;
        let (incarnation, ticks) = records[2]
            .process_start_time
            .rsplit_once(':')
            .context("fixture incarnation")?;
        records[2].process_start_time = format!("{incarnation}:{}", ticks.parse::<u64>()? ^ 1);
        records[4].run_id = "other-run".into();
        records[4].process_start_time = "123:456".into();
        registry.replace_records(records.clone())?;

        let report = registry.stop_run("run-mixed", Duration::from_secs(1))?;
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].process, records[0]);
        assert_eq!(
            report.failures[0].reason,
            AgentStopFailureReason::Termination
        );
        assert_eq!(report.stopped.len(), 3);
        for index in [1, 2] {
            assert!(report.stopped.iter().any(|entry| {
                entry.process == records[index] && entry.outcome == AgentStopOutcome::AlreadyExited
            }));
        }
        assert!(report.stopped.iter().any(|entry| {
            entry.process == records[3] && entry.outcome == AgentStopOutcome::Terminated
        }));
        children[3].0.wait()?;
        for index in [0, 2, 4] {
            assert!(children[index].0.try_wait()?.is_none());
        }
        let remaining = registry.snapshot_all()?;
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&records[0]));
        assert!(remaining.contains(&records[4]));
        let retry = registry.stop_run("run-mixed", Duration::from_secs(1))?;
        assert!(retry.stopped.is_empty());
        assert_eq!(retry.failures, report.failures);
        assert_eq!(registry.snapshot_all()?, remaining);
        Ok(())
    }

    #[test]
    fn terminate_process_does_not_signal_a_reused_pid() -> Result<()> {
        let current_pid = std::process::id();
        let token = process_start_time(current_pid)?;
        let (incarnation, ticks) = token
            .rsplit_once(':')
            .context("current incarnation ticks")?;
        let record = AgentProcessRecord {
            pid: current_pid,
            process_start_time: format!("{incarnation}:{}", ticks.parse::<u64>()? ^ 1),
            role: "worker".to_string(),
            run_id: "run-reused".to_string(),
            task_id: "reused".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-reused"),
            argv: vec!["test".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
            mechanical_executor: None,
        };
        let outcome = terminate_process(&record, Duration::from_millis(10))?;
        assert_eq!(outcome, AgentStopOutcome::AlreadyExited);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stop_binds_a_pidfd_for_the_recorded_start_time() -> Result<()> {
        let child = SleepChild::spawn()?;
        let record = AgentProcessRecord {
            pid: child.pid(),
            process_start_time: process_start_time(child.pid())?,
            role: "worker".to_string(),
            run_id: "run-pidfd".to_string(),
            task_id: "pidfd".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-pidfd"),
            argv: vec!["sleep".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
            mechanical_executor: None,
        };
        let target = bind_linux_signal_target(&record)?.context("live process must bind")?;
        assert!(matches!(target, LinuxSignalTarget::Pidfd(_)));
        Ok(())
    }

    #[test]
    fn legacy_record_json_without_mechanical_executor_still_loads() -> Result<()> {
        let json = r#"{
            "pid": 4242,
            "process_start_time": "1:2",
            "role": "worker",
            "run_id": "run-legacy",
            "task_id": "task-legacy",
            "repo": "/tmp/maco-agent-lifecycle-legacy",
            "argv": ["sleep", "60"],
            "launch_timestamp_ms": 1
        }"#;
        let record: AgentProcessRecord = serde_json::from_str(json)?;
        assert!(record.mechanical_executor.is_none());
        assert_eq!(record.launch_authority()?.source, "non_agent_simulation");
        Ok(())
    }

    #[test]
    fn worker_luna_argv_without_mechanical_evidence_keeps_legacy_authority() -> Result<()> {
        let record = AgentProcessRecord {
            pid: 4242,
            process_start_time: "1:2".to_string(),
            role: "worker".to_string(),
            run_id: "run-luna".to_string(),
            task_id: "task-luna".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-luna"),
            argv: vec![
                "/usr/bin/codex".to_string(),
                "exec".to_string(),
                "-m".to_string(),
                "gpt-5.6-luna".to_string(),
            ],
            launch_timestamp_ms: 1,
            mechanical_executor: None,
        };
        let authority = record.launch_authority()?;
        assert_eq!(authority.source, "role_and_exact_requested_argv");
        assert_eq!(authority.requested_model.as_deref(), Some("gpt-5.6-luna"));
        assert!(record.mechanical_executor.is_none());
        Ok(())
    }

    #[test]
    fn mechanical_executor_evidence_must_match_argv_and_cannot_mint_live_proof() -> Result<()> {
        let overlay = crate::supervise::install_test_fixture_models(&[(
            "fixture-weak-mechanical",
            crate::supervise::ModelCapabilityClass::WeakMechanical,
        )])?;
        let evidence = MechanicalExecutorLaunchEvidence {
            grant_nonce: 7,
            kind: MechanicalExecutorGrantKind::AssignmentChild,
            role: "worker".to_string(),
            phase: crate::supervise::OrchestrationPhase::MechanicalTerminal,
            duty: crate::supervise::MechanicalTerminalDuty::RunPreselectedCommand,
            model: "fixture-weak-mechanical".to_string(),
            canonical_program: PathBuf::from("/usr/bin/codex"),
            cwd: PathBuf::from("/work"),
            argv: vec![
                "/usr/bin/codex".to_string(),
                "exec".to_string(),
                "-m".to_string(),
                "fixture-weak-mechanical".to_string(),
            ],
            run_id: "run-evidence".to_string(),
            subject: "assignment-a".to_string(),
            attempt: 1,
        };
        let matching = AgentProcessRecord {
            pid: 4242,
            process_start_time: "1:2".to_string(),
            role: "worker".to_string(),
            run_id: "run-evidence".to_string(),
            task_id: "assignment-a".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-evidence"),
            argv: evidence.argv.clone(),
            launch_timestamp_ms: 1,
            mechanical_executor: Some(evidence.clone()),
        };
        let authority = matching.launch_authority()?;
        assert_eq!(
            authority.source,
            "role_argv_and_consumed_assignment_child_mechanical_executor"
        );
        assert_eq!(
            authority.model_capability,
            Some(crate::supervise::ModelCapabilityClass::WeakMechanical)
        );
        let encoded = serde_json::to_value(&matching)?;
        assert!(encoded.get("mechanical_executor").is_some());
        assert!(encoded.get("mechanical_executor_proof").is_none());
        let round_trip: AgentProcessRecord = serde_json::from_value(encoded)?;
        assert_eq!(round_trip.mechanical_executor, Some(evidence));

        let mut mismatched = matching;
        mismatched.argv.push("--tampered".to_string());
        assert!(mismatched.launch_authority().is_err());
        drop(overlay);
        Ok(())
    }
}
