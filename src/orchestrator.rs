use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            sensitive_state_root, AuthenticationDomain, AuthenticationTag, RepositoryAuthenticator,
        },
        validate_repository_authenticated_state,
    },
    checkpoint_wire::{
        decode_agent_checkpoint, decode_run_checkpoint, encode_agent_checkpoint,
        encode_run_checkpoint, LosslessPath,
    },
    merge::capture_worktree_diff_from_commit,
    process_runner::{
        run_process, trusted_system_executable, CapturedBytes, EnvironmentMode, ProcessRunError,
        ProcessSpec, Shell, SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
        WorkspaceAccess,
    },
    safe_state::BoundedRegularReader,
    secure_output::{ReservedOutputFile, SecureOutputRoot},
    semantic_coord::{
        SemanticConflict, SemanticCoordinationReport, SemanticIntent, SemanticIntentRequest,
        SemanticIntentStore, SemanticIntentToken,
    },
    state_journal::{JournalIdentity, StateJournal},
    sync::{normalize_repo_relative_path, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{
        normalize_agent_id, ManagedWorktreeWriteLease, WorktreeCreateOptions, WorktreeManager,
        WorktreeRecord,
    },
};
use anyhow::{bail, Context, Result};
use git2::{Delta, DiffOptions, Oid, Repository, ResetType};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{self, ExitStatus},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_CAPTURE_LIMIT_BYTES: usize = OUTPUT_CHAR_LIMIT * 4;
const CHECKPOINT_STATE_VERSION: u32 = 3;
const GIT_COMMAND_CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PATCH_OUTPUT_MAX_BYTES: usize = 64 * 1024 * 1024;
const CHECKPOINT_REFERENCE_MAX_BYTES: usize = 64 * 1024;
const CANDIDATE_BINDING_VERSION: u32 = 1;
const CANDIDATE_CAPTURE_ATTEMPTS: usize = 3;
const CANDIDATE_MAX_CHANGED_PATHS: usize = 8 * 1024;
const CANDIDATE_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const CANDIDATE_MAX_SINGLE_FILE_BYTES: usize = 16 * 1024 * 1024;
const COMBINED_CANDIDATE_MAX_PATCHES: usize = 256;
const COMBINED_CANDIDATE_MAX_BYTES: usize = 64 * 1024 * 1024;
const PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE: usize = 128;
const PLAN_MAX_TOTAL_VALIDATION_COMMANDS: usize = 4 * 1024;
const PLAN_MAX_DEPENDENCY_EDGES: usize = 4 * 1024;
const PLAN_MAX_BYTES: usize = 4 * 1024 * 1024;
const PLAN_MAX_COMMAND_BYTES: usize = 1024 * 1024;
const PLAN_MAX_STRING_BYTES: usize = 256 * 1024;
const PLAN_MAX_ID_BYTES: usize = 256;
const PLAN_MAX_ENV_KEY_BYTES: usize = 1024;
const PLAN_MAX_ENV_ENTRIES_PER_SCOPE: usize = 1024;
const PLAN_MAX_TOTAL_ENV_ENTRIES: usize = 16 * 1024;
const PLAN_MAX_TOTAL_PATHS: usize = 16 * 1024;
const PLAN_MAX_PATH_BYTES: usize = 4 * 1024;
const PLAN_MAX_PATH_COMPONENTS: usize = 256;
const PLAN_MAX_TOTAL_SEMANTIC_ITEMS: usize = 16 * 1024;
const PLAN_MAX_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const CHECKPOINT_REFERENCE_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0orchestration-checkpoint-reference\0v3\0");
const CHECKPOINT_SNAPSHOT_PHASE_PREFIX: &str = "snapshot_";
const PHASE_PLANNED: &str = "planned";
const PHASE_CLAIM_ACQUIRED: &str = "claim_acquired";
const PHASE_WORKTREE_PREPARED: &str = "worktree_prepared";
const PHASE_COMMAND_STARTED: &str = "command_started";
const PHASE_COMMAND_COMPLETED: &str = "command_completed";
const PHASE_CANDIDATE_CAPTURED: &str = "candidate_captured";
const PHASE_VALIDATION_STARTED: &str = "validation_started";
const PHASE_VALIDATED: &str = "validated";
const PHASE_REPO_VALIDATION_STARTED: &str = "repo_validation_started";
const PHASE_REPO_VALIDATED: &str = "repo_validated";
const PHASE_RELEASED: &str = "released";
const PHASE_FINAL: &str = "final";
static REPO_VALIDATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
struct CandidateBoundaryFailureHook {
    agent_id: String,
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static CANDIDATE_BOUNDARY_FAILURE_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<CandidateBoundaryFailureHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
#[derive(PartialEq, Eq)]
struct CheckpointEventFailureHook {
    run_id: String,
    phase: String,
}

#[cfg(test)]
static CHECKPOINT_EVENT_FAILURE_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Vec<CheckpointEventFailureHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
thread_local! {
    static READY_AGENT_SETUP_FAULT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    static READY_AGENT_POST_SPAWN_FAULT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_ready_agent_setup_fault(agent_id: impl Into<String>) {
    READY_AGENT_SETUP_FAULT.with(|slot| *slot.borrow_mut() = Some(agent_id.into()));
}

#[cfg(test)]
fn take_ready_agent_setup_fault(agent_id: &str) -> bool {
    READY_AGENT_SETUP_FAULT.with(|slot| {
        if slot.borrow().as_deref() == Some(agent_id) {
            slot.borrow_mut().take();
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn set_ready_agent_post_spawn_fault(agent_id: impl Into<String>) {
    READY_AGENT_POST_SPAWN_FAULT.with(|slot| *slot.borrow_mut() = Some(agent_id.into()));
}

#[cfg(test)]
fn fail_after_ready_agent_spawn(agent_id: &str) -> Result<()> {
    let triggered = READY_AGENT_POST_SPAWN_FAULT.with(|slot| {
        if slot.borrow().as_deref() == Some(agent_id) {
            slot.borrow_mut().take();
            true
        } else {
            false
        }
    });
    if triggered {
        bail!("injected ready-agent post-spawn setup failure for '{agent_id}'");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrchestrationExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestrationPlan {
    pub agents: Vec<AgentPlan>,
    pub repo_validation_commands: Vec<ValidationCommandPlan>,
    pub worktree_reuse_policy: WorktreeReusePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPlan {
    pub id: String,
    pub paths: Vec<PathBuf>,
    pub semantic_symbols: Vec<String>,
    pub semantic_modules: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<Duration>,
    pub command: String,
    pub depends_on: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub validation_commands: Vec<ValidationCommandPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCommandPlan {
    pub name: Option<String>,
    pub command: String,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<Duration>,
    pub working_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeReusePolicy {
    #[default]
    Clean,
    Required,
    Fresh,
    Reset,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCoordinationMode {
    #[default]
    Off,
    Warn,
    Block,
}

#[derive(Debug, Clone)]
pub struct OrchestrationRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub keep_claims: bool,
    pub jobs: usize,
    pub patch_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct OrchestrationRunControls {
    pub run_id: Option<RunId>,
    pub checkpoint_dir: Option<PathBuf>,
    pub worktree_reuse_policy: Option<WorktreeReusePolicy>,
    pub semantic_coordination: SemanticCoordinationMode,
}

#[derive(Debug, Clone)]
pub struct OrchestrationResumeOptions {
    pub checkpoint_file: PathBuf,
    pub repo: Option<PathBuf>,
    pub plan_file: Option<PathBuf>,
    pub jobs: usize,
    pub patch_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RunId(String);

impl RunId {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref().trim();
        if value.is_empty() {
            bail!("run id cannot be empty");
        }
        if matches!(value, "." | "..") {
            bail!("run id cannot be '.' or '..'");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!("run id may only contain ASCII letters, digits, '.', '_' and '-'");
        }

        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunCheckpointStage {
    WorktreesSelected,
    ClaimsAcquired,
    AgentsCompleted,
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RunCheckpoint {
    pub version: u32,
    pub run_id: RunId,
    pub stage: RunCheckpointStage,
    pub repo: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_head: Option<String>,
    pub plan_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_snapshot: Option<CheckpointPlanSnapshot>,
    pub keep_claims: bool,
    pub worktree_reuse_policy: WorktreeReusePolicy,
    #[serde(default)]
    pub semantic_coordination: SemanticCoordinationMode,
    pub success: bool,
    pub agents: Vec<AgentCheckpoint>,
    pub repo_validation: Vec<ValidationRunSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_validation_target: Option<RepoValidationTargetBinding>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
    #[serde(default)]
    pub released_semantic_intents: Vec<SemanticIntent>,
    #[serde(default)]
    pub semantic_release_errors: Vec<String>,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedCheckpointReference {
    version: u32,
    repository_hint: LosslessPath,
    journal: JournalIdentity,
    mac: AuthenticationTag,
}

#[derive(Serialize)]
struct CheckpointReferenceMacPayload<'a> {
    version: u32,
    repository_hint: &'a LosslessPath,
    journal: &'a JournalIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentCheckpoint {
    pub id: String,
    pub status: AgentRunStatus,
    pub worktree: Option<CheckpointWorktreeRecord>,
    pub claim: Option<PathClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_intent: Option<SemanticIntent>,
    #[serde(default)]
    pub semantic_conflicts: Vec<SemanticConflict>,
    pub changed_paths: Vec<PathBuf>,
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub validation: Vec<ValidationRunSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_binding: Option<AgentCandidateBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_completed_binding: Option<CompletedCommandStateBinding>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckpointWorktreeRecord {
    pub name: String,
    pub path: PathBuf,
    pub branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckpointPlanSnapshot {
    pub worktree_reuse_policy: WorktreeReusePolicy,
    pub repo_validation_commands: Vec<CheckpointValidationCommandSnapshot>,
    pub agents: Vec<CheckpointAgentPlanSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckpointAgentPlanSnapshot {
    pub id: String,
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub command: String,
    pub depends_on: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub validation_commands: Vec<CheckpointValidationCommandSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckpointValidationCommandSnapshot {
    pub name: Option<String>,
    pub command: String,
    pub env: BTreeMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub working_directory: Option<PathBuf>,
}

impl From<&OrchestrationPlan> for CheckpointPlanSnapshot {
    fn from(plan: &OrchestrationPlan) -> Self {
        Self {
            worktree_reuse_policy: plan.worktree_reuse_policy,
            repo_validation_commands: plan
                .repo_validation_commands
                .iter()
                .map(CheckpointValidationCommandSnapshot::from)
                .collect(),
            agents: plan
                .agents
                .iter()
                .map(CheckpointAgentPlanSnapshot::from)
                .collect(),
        }
    }
}

impl From<&AgentPlan> for CheckpointAgentPlanSnapshot {
    fn from(agent: &AgentPlan) -> Self {
        Self {
            id: agent.id.clone(),
            paths: agent.paths.clone(),
            semantic_symbols: agent.semantic_symbols.clone(),
            semantic_modules: agent.semantic_modules.clone(),
            env: agent.env.clone(),
            timeout_seconds: agent.timeout.map(|timeout| timeout.as_secs()),
            command: agent.command.clone(),
            depends_on: agent.depends_on.clone(),
            working_directory: agent.working_directory.clone(),
            validation_commands: agent
                .validation_commands
                .iter()
                .map(CheckpointValidationCommandSnapshot::from)
                .collect(),
        }
    }
}

impl From<&ValidationCommandPlan> for CheckpointValidationCommandSnapshot {
    fn from(validation: &ValidationCommandPlan) -> Self {
        Self {
            name: validation.name.clone(),
            command: validation.command.clone(),
            env: validation.env.clone(),
            timeout_seconds: validation.timeout.map(|timeout| timeout.as_secs()),
            working_directory: validation.working_directory.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrchestrationSummary {
    pub run_id: Option<RunId>,
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub keep_claims: bool,
    pub worktree_reuse_policy: WorktreeReusePolicy,
    pub semantic_coordination: SemanticCoordinationMode,
    pub success: bool,
    pub agents: Vec<AgentRunSummary>,
    pub repo_validation: Vec<ValidationRunSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_validation_target: Option<RepoValidationTargetBinding>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
    pub released_semantic_intents: Vec<SemanticIntent>,
    pub semantic_release_errors: Vec<String>,
}

impl OrchestrationSummary {
    pub fn first_failed_agent(&self) -> Option<&str> {
        self.agents
            .iter()
            .find(|agent| agent.status == AgentRunStatus::Failed)
            .map(|agent| agent.id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentRunSummary {
    pub id: String,
    pub paths: Vec<PathBuf>,
    pub depends_on: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub command: String,
    pub timeout_seconds: Option<u64>,
    pub worktree: Option<WorktreeRecord>,
    pub worktree_reused: bool,
    pub claim: Option<PathClaim>,
    pub semantic_intent: Option<SemanticIntent>,
    pub semantic_conflicts: Vec<SemanticConflict>,
    pub status: AgentRunStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub timed_out: bool,
    pub changed_paths: Vec<PathBuf>,
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub patch_path: Option<PathBuf>,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub validation: Vec<ValidationRunSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_binding: Option<AgentCandidateBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_completed_binding: Option<CompletedCommandStateBinding>,
    pub error: Option<String>,
}

impl AgentRunSummary {
    fn pending(agent: &AgentPlan) -> Self {
        Self {
            id: agent.id.clone(),
            paths: agent.paths.clone(),
            depends_on: agent.depends_on.clone(),
            working_directory: agent.working_directory.clone(),
            command: agent.command.clone(),
            timeout_seconds: agent.timeout.map(|timeout| timeout.as_secs()),
            worktree: None,
            worktree_reused: false,
            claim: None,
            semantic_intent: None,
            semantic_conflicts: Vec::new(),
            status: AgentRunStatus::Pending,
            exit_code: None,
            duration_ms: None,
            timed_out: false,
            changed_paths: Vec::new(),
            unclaimed_changed_paths: Vec::new(),
            patch_path: None,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            validation: Vec::new(),
            candidate_binding: None,
            command_completed_binding: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentCandidateBinding {
    pub version: u32,
    pub base_oid: String,
    pub head_oid: String,
    pub state_oid: String,
    pub diff_oid: String,
    pub changed_paths: Vec<PathBuf>,
    pub patch_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedCommandStateBinding {
    pub version: u32,
    pub base_oid: String,
    pub head_oid: String,
    pub state_oid: String,
    pub changed_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoValidationTargetKind {
    CombinedCandidate,
    BaseNoChanges,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RepoValidationTargetBinding {
    pub version: u32,
    pub kind: RepoValidationTargetKind,
    pub base_oid: String,
    pub combined_diff_oid: String,
    pub changed_paths: Vec<PathBuf>,
    pub candidate_count: usize,
    pub patch_count: usize,
    pub aggregate_patch_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateStateSnapshot {
    base_oid: Oid,
    head_oid: Oid,
    index_entries_oid: Oid,
    index_flags_oid: Oid,
    index_diff_oid: Oid,
    worktree_diff_oid: Oid,
    status_oid: Oid,
    untracked_oid: Oid,
    changed_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct CapturedCandidate {
    binding: AgentCandidateBinding,
    patch: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Pending,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationRunSummary {
    pub name: Option<String>,
    pub command: String,
    pub working_directory: Option<PathBuf>,
    pub timeout_seconds: Option<u64>,
    pub status: AgentRunStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub timed_out: bool,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlan {
    agents: Vec<RawAgentPlan>,
    #[serde(default)]
    default_timeout_seconds: Option<u64>,
    #[serde(default, alias = "repo_validations")]
    repo_validation_commands: Vec<RawValidationCommand>,
    #[serde(default)]
    worktree_reuse_policy: WorktreeReusePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentPlan {
    id: String,
    paths: Vec<PathBuf>,
    #[serde(default)]
    semantic_symbols: Vec<String>,
    #[serde(default)]
    semantic_modules: Vec<String>,
    command: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default, alias = "cwd")]
    working_directory: Option<PathBuf>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default, alias = "validations")]
    validation_commands: Vec<RawValidationCommand>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawValidationCommand {
    Shell(String),
    Detailed(RawValidationCommandDetails),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawValidationCommandDetails {
    #[serde(default)]
    name: Option<String>,
    command: String,
    #[serde(default, alias = "cwd")]
    working_directory: Option<PathBuf>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

pub fn load_plan(path: impl AsRef<Path>) -> Result<OrchestrationPlan> {
    let path = path.as_ref();
    let contents = BoundedRegularReader::read_tree_no_follow(path, PLAN_MAX_BYTES as u64)
        .with_context(|| format!("failed to read orchestration plan {}", path.display()))?;
    let raw: RawPlan = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse orchestration plan {}", path.display()))?;
    validate_raw_plan_bounds(&raw)?;
    validate_plan(raw)
}

fn validate_raw_plan_bounds(raw: &RawPlan) -> Result<()> {
    if raw.agents.len() > COMBINED_CANDIDATE_MAX_PATCHES {
        bail!(
            "orchestration plan exceeds the configured {} agent limit",
            COMBINED_CANDIDATE_MAX_PATCHES
        );
    }
    validate_bounded_timeout(raw.default_timeout_seconds, "default timeout")?;

    let mut total_string_bytes = 0_usize;
    let mut total_paths = 0_usize;
    let mut total_env_entries = 0_usize;
    let mut total_semantic_items = 0_usize;
    let mut total_dependency_edges = 0_usize;
    let mut total_validation_commands = raw.repo_validation_commands.len();
    if total_validation_commands > PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE {
        bail!(
            "repo validation exceeds the configured {} command limit",
            PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE
        );
    }
    for command in &raw.repo_validation_commands {
        validate_raw_validation_bounds(
            command,
            &mut total_string_bytes,
            &mut total_paths,
            &mut total_env_entries,
        )?;
    }

    for agent in &raw.agents {
        if agent.validation_commands.len() > PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE {
            bail!(
                "agent validation exceeds the configured {} command limit",
                PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE
            );
        }
        total_validation_commands = total_validation_commands
            .checked_add(agent.validation_commands.len())
            .context("orchestration validation command count overflowed")?;
        account_plan_string(
            &mut total_string_bytes,
            &agent.id,
            PLAN_MAX_ID_BYTES,
            "agent id",
        )?;
        account_plan_string(
            &mut total_string_bytes,
            &agent.command,
            PLAN_MAX_COMMAND_BYTES,
            "agent command",
        )?;
        total_paths = total_paths
            .checked_add(agent.paths.len())
            .context("orchestration plan path count overflowed")?;
        if let Some(path) = &agent.working_directory {
            total_paths = total_paths
                .checked_add(1)
                .context("orchestration plan path count overflowed")?;
            validate_bounded_plan_path(path, "agent working_directory")?;
        }
        for path in &agent.paths {
            validate_bounded_plan_path(path, "agent path")?;
        }
        total_semantic_items = total_semantic_items
            .checked_add(agent.semantic_symbols.len())
            .and_then(|total| total.checked_add(agent.semantic_modules.len()))
            .context("orchestration semantic item count overflowed")?;
        for item in agent
            .semantic_symbols
            .iter()
            .chain(agent.semantic_modules.iter())
        {
            account_plan_string(
                &mut total_string_bytes,
                item,
                PLAN_MAX_STRING_BYTES,
                "semantic item",
            )?;
        }
        total_dependency_edges = total_dependency_edges
            .checked_add(agent.depends_on.len())
            .context("orchestration dependency edge count overflowed")?;
        for dependency in &agent.depends_on {
            account_plan_string(
                &mut total_string_bytes,
                dependency,
                PLAN_MAX_ID_BYTES,
                "dependency id",
            )?;
        }
        validate_bounded_env(&agent.env, &mut total_string_bytes, &mut total_env_entries)?;
        validate_bounded_timeout(agent.timeout_seconds, "agent timeout")?;
        for command in &agent.validation_commands {
            validate_raw_validation_bounds(
                command,
                &mut total_string_bytes,
                &mut total_paths,
                &mut total_env_entries,
            )?;
        }
    }

    if total_paths > PLAN_MAX_TOTAL_PATHS {
        bail!(
            "orchestration plan exceeds the configured {} total path limit",
            PLAN_MAX_TOTAL_PATHS
        );
    }
    if total_env_entries > PLAN_MAX_TOTAL_ENV_ENTRIES {
        bail!(
            "orchestration plan exceeds the configured {} total environment-entry limit",
            PLAN_MAX_TOTAL_ENV_ENTRIES
        );
    }
    if total_semantic_items > PLAN_MAX_TOTAL_SEMANTIC_ITEMS {
        bail!(
            "orchestration plan exceeds the configured {} total semantic-item limit",
            PLAN_MAX_TOTAL_SEMANTIC_ITEMS
        );
    }
    if total_dependency_edges > PLAN_MAX_DEPENDENCY_EDGES {
        bail!(
            "orchestration plan exceeds the configured {} dependency-edge limit",
            PLAN_MAX_DEPENDENCY_EDGES
        );
    }
    if total_validation_commands > PLAN_MAX_TOTAL_VALIDATION_COMMANDS {
        bail!(
            "orchestration plan exceeds the configured {} total validation-command limit",
            PLAN_MAX_TOTAL_VALIDATION_COMMANDS
        );
    }
    Ok(())
}

fn validate_raw_validation_bounds(
    raw: &RawValidationCommand,
    total_string_bytes: &mut usize,
    total_paths: &mut usize,
    total_env_entries: &mut usize,
) -> Result<()> {
    match raw {
        RawValidationCommand::Shell(command) => account_plan_string(
            total_string_bytes,
            command,
            PLAN_MAX_COMMAND_BYTES,
            "validation command",
        ),
        RawValidationCommand::Detailed(details) => {
            if let Some(name) = &details.name {
                account_plan_string(
                    total_string_bytes,
                    name,
                    PLAN_MAX_STRING_BYTES,
                    "validation name",
                )?;
            }
            account_plan_string(
                total_string_bytes,
                &details.command,
                PLAN_MAX_COMMAND_BYTES,
                "validation command",
            )?;
            if let Some(path) = &details.working_directory {
                *total_paths = total_paths
                    .checked_add(1)
                    .context("orchestration plan path count overflowed")?;
                validate_bounded_plan_path(path, "validation working_directory")?;
            }
            validate_bounded_env(&details.env, total_string_bytes, total_env_entries)?;
            validate_bounded_timeout(details.timeout_seconds, "validation timeout")
        }
    }
}

fn validate_bounded_env(
    env: &BTreeMap<String, String>,
    total_string_bytes: &mut usize,
    total_env_entries: &mut usize,
) -> Result<()> {
    if env.len() > PLAN_MAX_ENV_ENTRIES_PER_SCOPE {
        bail!(
            "orchestration environment scope exceeds the configured {} entry limit",
            PLAN_MAX_ENV_ENTRIES_PER_SCOPE
        );
    }
    *total_env_entries = total_env_entries
        .checked_add(env.len())
        .context("orchestration environment-entry count overflowed")?;
    for (key, value) in env {
        account_plan_string(
            total_string_bytes,
            key,
            PLAN_MAX_ENV_KEY_BYTES,
            "environment key",
        )?;
        account_plan_string(
            total_string_bytes,
            value,
            PLAN_MAX_STRING_BYTES,
            "environment value",
        )?;
    }
    Ok(())
}

fn account_plan_string(
    total: &mut usize,
    value: &str,
    per_value_limit: usize,
    label: &str,
) -> Result<()> {
    if value.len() > per_value_limit {
        bail!("{label} exceeds the configured {per_value_limit} byte limit");
    }
    *total = total
        .checked_add(value.len())
        .context("orchestration plan total string bytes overflowed")?;
    if *total > PLAN_MAX_BYTES {
        bail!(
            "orchestration plan strings exceed the configured {} byte aggregate limit",
            PLAN_MAX_BYTES
        );
    }
    Ok(())
}

fn validate_bounded_plan_path(path: &Path, label: &str) -> Result<()> {
    if candidate_path_bytes(path).len() > PLAN_MAX_PATH_BYTES
        || path.components().count() > PLAN_MAX_PATH_COMPONENTS
    {
        bail!(
            "{label} exceeds the configured path byte or component limit: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_bounded_timeout(timeout: Option<u64>, label: &str) -> Result<()> {
    if timeout.is_some_and(|seconds| seconds == 0 || seconds > PLAN_MAX_TIMEOUT_SECONDS) {
        bail!(
            "{label} must be between 1 and {} seconds",
            PLAN_MAX_TIMEOUT_SECONDS
        );
    }
    Ok(())
}

pub fn run_plan_file(options: OrchestrationRunOptions) -> Result<OrchestrationSummary> {
    run_plan_file_with_controls(options, OrchestrationRunControls::default())
}

pub fn run_plan_file_with_controls(
    options: OrchestrationRunOptions,
    controls: OrchestrationRunControls,
) -> Result<OrchestrationSummary> {
    let plan = load_plan(&options.plan_file)?;
    run_plan_with_controls_runtime(
        plan,
        options,
        controls,
        OrchestrationExecutionRuntime::Verified,
    )
}

#[cfg(test)]
fn run_plan_file_with_controls_simulation(
    options: OrchestrationRunOptions,
    controls: OrchestrationRunControls,
) -> Result<OrchestrationSummary> {
    let plan = load_plan(&options.plan_file)?;
    run_plan_with_controls_runtime(
        plan,
        options,
        controls,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
}

#[cfg(test)]
fn run_plan_file_simulation(options: OrchestrationRunOptions) -> Result<OrchestrationSummary> {
    run_plan_file_with_controls_simulation(options, OrchestrationRunControls::default())
}

pub fn run_plan(
    plan: OrchestrationPlan,
    options: OrchestrationRunOptions,
) -> Result<OrchestrationSummary> {
    run_plan_with_controls(plan, options, OrchestrationRunControls::default())
}

pub fn run_plan_with_controls(
    plan: OrchestrationPlan,
    options: OrchestrationRunOptions,
    controls: OrchestrationRunControls,
) -> Result<OrchestrationSummary> {
    run_plan_with_controls_runtime(
        plan,
        options,
        controls,
        OrchestrationExecutionRuntime::Verified,
    )
}

fn run_plan_with_controls_runtime(
    plan: OrchestrationPlan,
    options: OrchestrationRunOptions,
    controls: OrchestrationRunControls,
    runtime: OrchestrationExecutionRuntime,
) -> Result<OrchestrationSummary> {
    if options.jobs == 0 {
        bail!("orchestration jobs must be at least 1");
    }

    let early_cleanup_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let cleanup_error_sink = early_cleanup_errors.clone();
    let result = (|| -> Result<OrchestrationSummary> {
        let repo = discover_repo_root(&options.repo)?;
        let run_id = resolve_run_id(&controls)?;
        let repo_head = current_head_oid(&repo)?;
        let worktree_reuse_policy = controls
            .worktree_reuse_policy
            .unwrap_or(plan.worktree_reuse_policy);
        let manager = WorktreeManager::new(&repo);
        let store = SyncStore::open(&repo)?;
        let semantic_store = SemanticIntentStore::open(&repo)?;
        let semantic_coordination = controls.semantic_coordination;
        let mut summaries = plan
            .agents
            .iter()
            .map(AgentRunSummary::pending)
            .collect::<Vec<_>>();
        let mut repo_validation = Vec::new();
        let mut repo_validation_target = None;
        let mut claim_cleanup = ClaimCleanupGuard::new(store.clone(), cleanup_error_sink.clone());
        let mut semantic_cleanup =
            SemanticCleanupGuard::new(semantic_store.clone(), cleanup_error_sink.clone());
        if options.keep_claims {
            claim_cleanup.disarm_keep();
            semantic_cleanup.disarm_keep();
        }
        let mut checkpoint_writer =
            prepare_run_checkpoint_writer(&controls, &run_id, &repo, &summaries)?;
        if let Some(writer) = checkpoint_writer.as_mut() {
            writer.event(
                PHASE_PLANNED,
                None,
                &serde_json::json!({
                    "repo_head": repo_head.to_string(),
                    "plan_recorded": true,
                }),
            )?;
        }

        let worktrees =
            select_worktrees(&manager, &store, &repo_head, &plan, worktree_reuse_policy)?;
        if let Some(writer) = checkpoint_writer.as_ref() {
            writer.reject_inside_worktrees(&worktrees)?;
        }
        for (summary, worktree) in summaries.iter_mut().zip(&worktrees) {
            summary.worktree_reused = worktree.reused;
            summary.worktree = Some(worktree.record().clone());
            if let Some(writer) = checkpoint_writer.as_mut() {
                writer.event(PHASE_WORKTREE_PREPARED, Some(&summary.id), &true)?;
            }
        }
        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::WorktreesSelected,
            &run_id,
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &options.plan_file,
                plan: &plan,
                keep_claims: options.keep_claims,
                worktree_reuse_policy,
                success: false,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &[],
                release_errors: &[],
                released_semantic_intents: &[],
                semantic_release_errors: &[],
            },
        )?;

        for (index, agent) in plan.agents.iter().enumerate() {
            match store.claim_paths(&agent.id, agent.paths.iter()) {
                Ok(claim) => {
                    claim_cleanup.track(claim.token);
                    summaries[index].claim = Some(claim);
                    if let Some(writer) = checkpoint_writer.as_mut() {
                        writer.event(PHASE_CLAIM_ACQUIRED, Some(&agent.id), &true)?;
                    }
                }
                Err(error) => {
                    fail_summary(
                        &mut summaries[index],
                        format!("failed to claim paths for agent '{}': {error}", agent.id),
                    );
                }
            }
        }
        if semantic_coordination != SemanticCoordinationMode::Off {
            coordinate_semantic_intents(
                &semantic_store,
                &plan,
                &mut summaries,
                semantic_coordination,
                semantic_cleanup.tokens_mut(),
            );
        }
        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::ClaimsAcquired,
            &run_id,
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &options.plan_file,
                plan: &plan,
                keep_claims: options.keep_claims,
                worktree_reuse_policy,
                success: false,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &[],
                release_errors: &[],
                released_semantic_intents: &[],
                semantic_release_errors: &[],
            },
        )?;

        let captured_candidates = run_agent_schedule_with_patch_dir(
            &AgentScheduleContext {
                manager: &manager,
                plan: &plan,
                worktrees: &worktrees,
                jobs: options.jobs,
                base_oid: &repo_head,
                runtime,
            },
            &mut summaries,
            options.patch_dir.as_deref(),
            checkpoint_writer.as_mut(),
        )?;
        if summaries
            .iter()
            .all(|summary| summary.status == AgentRunStatus::Succeeded)
        {
            if let Some(writer) = checkpoint_writer.as_mut() {
                writer.event(
                    PHASE_REPO_VALIDATION_STARTED,
                    None,
                    &serde_json::json!({ "agent_count": summaries.len() }),
                )?;
            }
            let outcome = run_repo_validation_commands(
                &plan,
                &repo,
                &manager,
                &worktrees,
                &repo_head,
                &captured_candidates,
                runtime,
            );
            repo_validation = outcome.summaries;
            repo_validation_target = outcome.target;
            if let Some(writer) = checkpoint_writer.as_mut() {
                writer.event(
                    PHASE_REPO_VALIDATED,
                    None,
                    &serde_json::json!({
                        "validation_count": repo_validation.len(),
                        "has_target": repo_validation_target.is_some(),
                    }),
                )?;
            }
        }
        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::AgentsCompleted,
            &run_id,
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &options.plan_file,
                plan: &plan,
                keep_claims: options.keep_claims,
                worktree_reuse_policy,
                success: false,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &[],
                release_errors: &[],
                released_semantic_intents: &[],
                semantic_release_errors: &[],
            },
        )?;

        let (released_claims, release_errors) = if options.keep_claims {
            claim_cleanup.disarm_keep();
            (Vec::new(), Vec::new())
        } else {
            claim_cleanup.release()
        };
        let (released_semantic_intents, semantic_release_errors) = if options.keep_claims {
            semantic_cleanup.disarm_keep();
            (Vec::new(), Vec::new())
        } else {
            semantic_cleanup.release()
        };
        if let Some(writer) = checkpoint_writer.as_mut() {
            writer.event(
                PHASE_RELEASED,
                None,
                &serde_json::json!({
                    "claim_count": released_claims.len(),
                    "claim_errors": &release_errors,
                    "semantic_intent_count": released_semantic_intents.len(),
                    "semantic_errors": &semantic_release_errors,
                    "kept": options.keep_claims,
                }),
            )?;
        }
        let success = release_errors.is_empty()
            && semantic_release_errors.is_empty()
            && repo_validation_target.is_some()
            && summaries
                .iter()
                .all(|summary| summary.status == AgentRunStatus::Succeeded)
            && repo_validation
                .iter()
                .all(|summary| summary.status == AgentRunStatus::Succeeded);
        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::Final,
            &run_id,
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &options.plan_file,
                plan: &plan,
                keep_claims: options.keep_claims,
                worktree_reuse_policy,
                success,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &released_claims,
                release_errors: &release_errors,
                released_semantic_intents: &released_semantic_intents,
                semantic_release_errors: &semantic_release_errors,
            },
        )?;

        Ok(OrchestrationSummary {
            run_id,
            repo,
            plan_file: options.plan_file,
            keep_claims: options.keep_claims,
            worktree_reuse_policy,
            semantic_coordination,
            success,
            agents: summaries,
            repo_validation,
            repo_validation_target,
            released_claims,
            release_errors,
            released_semantic_intents,
            semantic_release_errors,
        })
    })();
    finish_with_early_cleanup(result, &early_cleanup_errors)
}

pub fn resume_plan_file(options: OrchestrationResumeOptions) -> Result<OrchestrationSummary> {
    resume_plan_file_runtime(options, OrchestrationExecutionRuntime::Verified)
}

#[cfg(test)]
fn resume_plan_file_simulation(
    options: OrchestrationResumeOptions,
) -> Result<OrchestrationSummary> {
    resume_plan_file_runtime(
        options,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
}

fn resume_plan_file_runtime(
    options: OrchestrationResumeOptions,
    runtime: OrchestrationExecutionRuntime,
) -> Result<OrchestrationSummary> {
    if options.jobs == 0 {
        bail!("orchestration jobs must be at least 1");
    }

    let early_cleanup_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let cleanup_error_sink = early_cleanup_errors.clone();
    let result = (|| -> Result<OrchestrationSummary> {
        let OpenedRunCheckpoint {
            checkpoint,
            repo,
            writer,
        } = open_run_checkpoint(&options.checkpoint_file, options.repo.as_deref())?;
        let mut checkpoint_writer = Some(writer);
        let checkpoint_dir = options
            .checkpoint_file
            .parent()
            .map(Path::to_path_buf)
            .context("checkpoint file must have a parent directory")?;
        let repo_head = current_head_oid(&repo)?;
        let plan_file = options
            .plan_file
            .clone()
            .unwrap_or_else(|| checkpoint.plan_file.clone());
        let plan = load_plan(&plan_file)?;

        validate_checkpoint_for_resume(&checkpoint, &plan, &repo_head)?;
        let mut summaries = summaries_from_checkpoint(&plan, &checkpoint)?;
        if checkpoint.stage == RunCheckpointStage::Final {
            return Ok(summary_from_parts(SummaryParts {
                run_id: checkpoint.run_id,
                repo,
                plan_file,
                keep_claims: checkpoint.keep_claims,
                worktree_reuse_policy: checkpoint.worktree_reuse_policy,
                semantic_coordination: checkpoint.semantic_coordination,
                summaries,
                repo_validation: checkpoint.repo_validation,
                repo_validation_target: checkpoint.repo_validation_target,
                released_claims: checkpoint.released_claims,
                release_errors: checkpoint.release_errors,
                released_semantic_intents: checkpoint.released_semantic_intents,
                semantic_release_errors: checkpoint.semantic_release_errors,
            }));
        }

        let manager = WorktreeManager::new(&repo);
        let store = SyncStore::open(&repo)?;
        let semantic_store = SemanticIntentStore::open(&repo)?;
        let worktrees = validate_resume_worktrees(
            &manager,
            &plan,
            &checkpoint,
            &mut summaries,
            &repo_head,
            runtime,
        )?;
        if let Some(writer) = checkpoint_writer.as_ref() {
            writer.reject_inside_worktrees(&worktrees)?;
        }

        let controls = OrchestrationRunControls {
            run_id: Some(checkpoint.run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir),
            worktree_reuse_policy: Some(checkpoint.worktree_reuse_policy),
            semantic_coordination: checkpoint.semantic_coordination,
        };
        let mut claim_cleanup = ClaimCleanupGuard::new(store.clone(), cleanup_error_sink.clone());
        let mut semantic_cleanup =
            SemanticCleanupGuard::new(semantic_store.clone(), cleanup_error_sink.clone());
        if checkpoint.keep_claims {
            claim_cleanup.disarm_keep();
            semantic_cleanup.disarm_keep();
        }
        let acquired_tokens = acquire_resume_claims(&store, &plan, &mut summaries);
        claim_cleanup.set_tokens(acquired_tokens);
        if let Some(writer) = checkpoint_writer.as_mut() {
            for summary in &summaries {
                if summary.claim.is_some() {
                    writer.event(PHASE_CLAIM_ACQUIRED, Some(&summary.id), &true)?;
                }
            }
        }
        let (active_semantic_tokens, semantic_coordination_needed) =
            active_checkpoint_semantic_tokens(&semantic_store, &mut summaries)?;
        semantic_cleanup.set_tokens(active_semantic_tokens);
        let had_pending_agents = summaries
            .iter()
            .any(|summary| summary.status == AgentRunStatus::Pending);
        if checkpoint.semantic_coordination != SemanticCoordinationMode::Off
            && had_pending_agents
            && semantic_coordination_needed
        {
            coordinate_semantic_intents(
                &semantic_store,
                &plan,
                &mut summaries,
                checkpoint.semantic_coordination,
                semantic_cleanup.tokens_mut(),
            );
        }

        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::ClaimsAcquired,
            &Some(checkpoint.run_id.clone()),
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &plan_file,
                plan: &plan,
                keep_claims: checkpoint.keep_claims,
                worktree_reuse_policy: checkpoint.worktree_reuse_policy,
                success: false,
                agents: &summaries,
                repo_validation: &checkpoint.repo_validation,
                repo_validation_target: checkpoint.repo_validation_target.as_ref(),
                released_claims: &[],
                release_errors: &[],
                released_semantic_intents: &[],
                semantic_release_errors: &[],
            },
        )?;

        let captured_candidates = run_agent_schedule_with_patch_dir(
            &AgentScheduleContext {
                manager: &manager,
                plan: &plan,
                worktrees: &worktrees,
                jobs: options.jobs,
                base_oid: &repo_head,
                runtime,
            },
            &mut summaries,
            options.patch_dir.as_deref(),
            checkpoint_writer.as_mut(),
        )?;
        let (repo_validation, repo_validation_target) = if summaries
            .iter()
            .all(|summary| summary.status == AgentRunStatus::Succeeded)
        {
            if let Some(writer) = checkpoint_writer.as_mut() {
                writer.event(
                    PHASE_REPO_VALIDATION_STARTED,
                    None,
                    &serde_json::json!({ "agent_count": summaries.len() }),
                )?;
            }
            let outcome = run_repo_validation_commands(
                &plan,
                &repo,
                &manager,
                &worktrees,
                &repo_head,
                &captured_candidates,
                runtime,
            );
            if let Some(writer) = checkpoint_writer.as_mut() {
                writer.event(
                    PHASE_REPO_VALIDATED,
                    None,
                    &serde_json::json!({
                        "validation_count": outcome.summaries.len(),
                        "has_target": outcome.target.is_some(),
                    }),
                )?;
            }
            (outcome.summaries, outcome.target)
        } else {
            (
                checkpoint.repo_validation.clone(),
                checkpoint.repo_validation_target.clone(),
            )
        };

        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::AgentsCompleted,
            &Some(checkpoint.run_id.clone()),
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &plan_file,
                plan: &plan,
                keep_claims: checkpoint.keep_claims,
                worktree_reuse_policy: checkpoint.worktree_reuse_policy,
                success: false,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &[],
                release_errors: &[],
                released_semantic_intents: &[],
                semantic_release_errors: &[],
            },
        )?;

        let (released_claims, release_errors) = if checkpoint.keep_claims {
            claim_cleanup.disarm_keep();
            (Vec::new(), Vec::new())
        } else {
            claim_cleanup.release()
        };
        let (released_semantic_intents, semantic_release_errors) = if checkpoint.keep_claims {
            semantic_cleanup.disarm_keep();
            (Vec::new(), Vec::new())
        } else {
            semantic_cleanup.release()
        };
        if let Some(writer) = checkpoint_writer.as_mut() {
            writer.event(
                PHASE_RELEASED,
                None,
                &serde_json::json!({
                    "claim_count": released_claims.len(),
                    "claim_errors": &release_errors,
                    "semantic_intent_count": released_semantic_intents.len(),
                    "semantic_errors": &semantic_release_errors,
                    "kept": checkpoint.keep_claims,
                }),
            )?;
        }
        let success = release_errors.is_empty()
            && semantic_release_errors.is_empty()
            && repo_validation_target.is_some()
            && summaries
                .iter()
                .all(|summary| summary.status == AgentRunStatus::Succeeded)
            && repo_validation
                .iter()
                .all(|summary| summary.status == AgentRunStatus::Succeeded);

        write_checkpoint_if_configured(
            &controls,
            RunCheckpointStage::Final,
            &Some(checkpoint.run_id.clone()),
            checkpoint_writer.as_mut(),
            CheckpointView {
                repo: &repo,
                repo_head: &repo_head,
                plan_file: &plan_file,
                plan: &plan,
                keep_claims: checkpoint.keep_claims,
                worktree_reuse_policy: checkpoint.worktree_reuse_policy,
                success,
                agents: &summaries,
                repo_validation: &repo_validation,
                repo_validation_target: repo_validation_target.as_ref(),
                released_claims: &released_claims,
                release_errors: &release_errors,
                released_semantic_intents: &released_semantic_intents,
                semantic_release_errors: &semantic_release_errors,
            },
        )?;

        Ok(OrchestrationSummary {
            run_id: Some(checkpoint.run_id),
            repo,
            plan_file,
            keep_claims: checkpoint.keep_claims,
            worktree_reuse_policy: checkpoint.worktree_reuse_policy,
            semantic_coordination: checkpoint.semantic_coordination,
            success,
            agents: summaries,
            repo_validation,
            repo_validation_target,
            released_claims,
            release_errors,
            released_semantic_intents,
            semantic_release_errors,
        })
    })();
    finish_with_early_cleanup(result, &early_cleanup_errors)
}

fn validate_checkpoint_for_resume(
    checkpoint: &RunCheckpoint,
    plan: &OrchestrationPlan,
    repo_head: &Oid,
) -> Result<()> {
    let Some(checkpoint_head) = checkpoint.repo_head.as_deref() else {
        bail!(
            "checkpoint '{}' is missing repository HEAD metadata; start a new run to create a resumable checkpoint",
            checkpoint.run_id.as_str()
        );
    };
    if checkpoint_head != repo_head.to_string() {
        bail!(
            "checkpoint '{}' was created at primary HEAD {}, but the repository is now at {}; start a new run or restore the repository to the checkpoint base",
            checkpoint.run_id.as_str(),
            checkpoint_head,
            repo_head
        );
    }

    let current_snapshot = CheckpointPlanSnapshot::from(plan);
    let Some(checkpoint_snapshot) = checkpoint.plan_snapshot.as_ref() else {
        bail!(
            "checkpoint '{}' is missing plan metadata; start a new run to create a resumable checkpoint",
            checkpoint.run_id.as_str()
        );
    };
    if checkpoint_snapshot != &current_snapshot {
        bail!(
            "checkpoint '{}' does not match the current orchestration plan; use the matching plan file or start a new run",
            checkpoint.run_id.as_str()
        );
    }

    if checkpoint.agents.len() != plan.agents.len() {
        bail!(
            "checkpoint '{}' has {} agents but the plan has {}; use the matching plan file or start a new run",
            checkpoint.run_id.as_str(),
            checkpoint.agents.len(),
            plan.agents.len()
        );
    }

    for (agent, checkpoint_agent) in plan.agents.iter().zip(&checkpoint.agents) {
        if checkpoint_agent.id != agent.id {
            bail!(
                "checkpoint '{}' records agent '{}' where the plan expects '{}'; use the matching plan file or start a new run",
                checkpoint.run_id.as_str(),
                checkpoint_agent.id,
                agent.id
            );
        }
        match checkpoint_agent.status {
            AgentRunStatus::Pending | AgentRunStatus::Succeeded => {}
            AgentRunStatus::Failed | AgentRunStatus::Skipped
                if checkpoint.stage == RunCheckpointStage::Final => {}
            AgentRunStatus::Failed => {
                bail!(
                    "checkpoint '{}' contains failed agent '{}'; resume will not retry failed work automatically, start a new run after fixing the cause",
                    checkpoint.run_id.as_str(),
                    checkpoint_agent.id
                );
            }
            AgentRunStatus::Skipped => {
                bail!(
                    "checkpoint '{}' contains skipped agent '{}'; resume cannot infer whether it is safe to run, start a new run",
                    checkpoint.run_id.as_str(),
                    checkpoint_agent.id
                );
            }
        }
        if checkpoint_agent.status == AgentRunStatus::Succeeded
            && checkpoint_agent.candidate_binding.is_none()
            && checkpoint_agent.command_completed_binding.is_none()
        {
            bail!(
                "checkpoint '{}' completed agent '{}' is missing candidate validation binding metadata; start a new run",
                checkpoint.run_id.as_str(),
                checkpoint_agent.id
            );
        }
        if let Some(binding) = checkpoint_agent.candidate_binding.as_ref() {
            validate_serialized_agent_binding(binding, agent, repo_head)?;
            if checkpoint_agent.changed_paths != binding.changed_paths {
                bail!(
                    "checkpoint '{}' candidate paths for completed agent '{}' do not match its serialized binding",
                    checkpoint.run_id.as_str(),
                    checkpoint_agent.id
                );
            }
        }
        if let Some(binding) = checkpoint_agent.command_completed_binding.as_ref() {
            validate_serialized_completed_binding(binding, agent, repo_head)?;
            if checkpoint_agent.candidate_binding.is_none()
                && checkpoint_agent.changed_paths != binding.changed_paths
            {
                bail!(
                    "checkpoint '{}' completed-command paths for agent '{}' do not match its exact state binding",
                    checkpoint.run_id.as_str(),
                    checkpoint_agent.id
                );
            }
        }
    }

    if let Some(target) = checkpoint.repo_validation_target.as_ref() {
        validate_serialized_repo_validation_target(target, checkpoint, repo_head)?;
    } else if checkpoint.stage == RunCheckpointStage::Final
        && checkpoint
            .agents
            .iter()
            .all(|agent| agent.status == AgentRunStatus::Succeeded)
    {
        bail!(
            "checkpoint '{}' has successful candidates but no combined repo-validation target binding; start a new run",
            checkpoint.run_id.as_str()
        );
    }

    Ok(())
}

fn validate_serialized_agent_binding(
    binding: &AgentCandidateBinding,
    agent: &AgentPlan,
    repo_head: &Oid,
) -> Result<()> {
    if binding.version != CANDIDATE_BINDING_VERSION {
        bail!(
            "agent '{}' uses unsupported candidate binding version {}",
            agent.id,
            binding.version
        );
    }
    if binding.base_oid != repo_head.to_string() {
        bail!(
            "agent '{}' candidate binding was captured from a different run base",
            agent.id
        );
    }
    for (label, value) in [
        ("base", binding.base_oid.as_str()),
        ("head", binding.head_oid.as_str()),
        ("state", binding.state_oid.as_str()),
        ("diff", binding.diff_oid.as_str()),
    ] {
        let oid = Oid::from_str(value)
            .with_context(|| format!("agent '{}' candidate {label} OID is invalid", agent.id))?;
        if oid.to_string() != value {
            bail!(
                "agent '{}' candidate {label} OID is not canonical",
                agent.id
            );
        }
    }
    if binding.patch_bytes >= PATCH_OUTPUT_MAX_BYTES as u64 {
        bail!(
            "agent '{}' candidate patch reached the configured byte boundary",
            agent.id
        );
    }
    if binding.changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "agent '{}' candidate changed-path count exceeded its bound",
            agent.id
        );
    }
    for path in &binding.changed_paths {
        let normalized = normalize_repo_relative_path(path)?;
        if &normalized != path {
            bail!("agent '{}' candidate path is not normalized", agent.id);
        }
    }
    Ok(())
}

fn validate_serialized_completed_binding(
    binding: &CompletedCommandStateBinding,
    agent: &AgentPlan,
    repo_head: &Oid,
) -> Result<()> {
    if binding.version != CANDIDATE_BINDING_VERSION || binding.base_oid != repo_head.to_string() {
        bail!(
            "agent '{}' completed command uses an unsupported or stale state binding",
            agent.id
        );
    }
    for (label, value) in [
        ("base", binding.base_oid.as_str()),
        ("head", binding.head_oid.as_str()),
        ("state", binding.state_oid.as_str()),
    ] {
        let oid = Oid::from_str(value).with_context(|| {
            format!(
                "agent '{}' completed-command {label} OID is invalid",
                agent.id
            )
        })?;
        if oid.to_string() != value {
            bail!(
                "agent '{}' completed-command {label} OID is not canonical",
                agent.id
            );
        }
    }
    if binding.changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "agent '{}' completed-command changed-path count exceeded its bound",
            agent.id
        );
    }
    for path in &binding.changed_paths {
        if &normalize_repo_relative_path(path)? != path {
            bail!(
                "agent '{}' completed-command path is not normalized",
                agent.id
            );
        }
    }
    Ok(())
}

fn validate_serialized_repo_validation_target(
    target: &RepoValidationTargetBinding,
    checkpoint: &RunCheckpoint,
    repo_head: &Oid,
) -> Result<()> {
    if target.version != CANDIDATE_BINDING_VERSION || target.base_oid != repo_head.to_string() {
        bail!("checkpoint repo-validation target has an unsupported or stale binding");
    }
    let diff_oid = Oid::from_str(&target.combined_diff_oid)
        .context("checkpoint repo-validation combined diff OID is invalid")?;
    if diff_oid.to_string() != target.combined_diff_oid {
        bail!("checkpoint repo-validation combined diff OID is not canonical");
    }
    let successful = checkpoint
        .agents
        .iter()
        .filter(|agent| agent.status == AgentRunStatus::Succeeded)
        .collect::<Vec<_>>();
    let mut changed_paths = BTreeSet::new();
    let mut patch_count = 0_usize;
    let mut aggregate_patch_bytes = 0_u64;
    for agent in &successful {
        let binding = agent
            .candidate_binding
            .as_ref()
            .context("successful checkpoint agent is missing its candidate binding")?;
        if binding.patch_bytes > 0 {
            patch_count += 1;
        }
        aggregate_patch_bytes = aggregate_patch_bytes
            .checked_add(binding.patch_bytes)
            .context("checkpoint candidate byte count overflowed")?;
        changed_paths.extend(binding.changed_paths.iter().cloned());
    }
    let changed_paths = changed_paths.into_iter().collect::<Vec<_>>();
    let expected_kind = if changed_paths.is_empty() {
        RepoValidationTargetKind::BaseNoChanges
    } else {
        RepoValidationTargetKind::CombinedCandidate
    };
    if target.kind != expected_kind
        || target.candidate_count != successful.len()
        || target.patch_count != patch_count
        || target.aggregate_patch_bytes != aggregate_patch_bytes
        || target.changed_paths != changed_paths
        || target.aggregate_patch_bytes >= COMBINED_CANDIDATE_MAX_BYTES as u64
        || target.patch_count > COMBINED_CANDIDATE_MAX_PATCHES
    {
        bail!("checkpoint repo-validation target does not match its successful candidate set");
    }
    Ok(())
}

fn summaries_from_checkpoint(
    plan: &OrchestrationPlan,
    checkpoint: &RunCheckpoint,
) -> Result<Vec<AgentRunSummary>> {
    plan.agents
        .iter()
        .zip(&checkpoint.agents)
        .map(|(agent, checkpoint_agent)| {
            let mut summary = AgentRunSummary::pending(agent);
            summary.status = checkpoint_agent.status;
            summary.worktree = checkpoint_agent.worktree.as_ref().map(WorktreeRecord::from);
            summary.worktree_reused = summary.worktree.is_some();
            summary.claim = checkpoint_agent.claim.clone();
            summary.semantic_intent = checkpoint_agent.semantic_intent.clone();
            summary.semantic_conflicts = checkpoint_agent.semantic_conflicts.clone();
            summary.changed_paths = checkpoint_agent.changed_paths.clone();
            summary.unclaimed_changed_paths = checkpoint_agent.unclaimed_changed_paths.clone();
            summary.validation = checkpoint_agent.validation.clone();
            summary.candidate_binding = checkpoint_agent.candidate_binding.clone();
            summary.command_completed_binding = checkpoint_agent.command_completed_binding.clone();
            summary.error = checkpoint_agent.error.clone();
            Ok(summary)
        })
        .collect()
}

fn validate_resume_worktrees(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
    checkpoint: &RunCheckpoint,
    summaries: &mut [AgentRunSummary],
    repo_head: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<SelectedWorktree>> {
    let registered_names = manager
        .list()?
        .into_iter()
        .map(|record| record.name)
        .collect::<BTreeSet<_>>();
    let mut selected = Vec::with_capacity(plan.agents.len());

    for ((agent, checkpoint_agent), summary) in plan
        .agents
        .iter()
        .zip(&checkpoint.agents)
        .zip(summaries.iter_mut())
    {
        let Some(recorded) = checkpoint_agent.worktree.as_ref() else {
            bail!(
                "checkpoint '{}' is missing worktree metadata for agent '{}'; start a new run",
                checkpoint.run_id.as_str(),
                agent.id
            );
        };
        if !registered_names.contains(&recorded.name) {
            bail!(
                "checkpoint '{}' references missing worktree '{}' for agent '{}'; restore the worktree or start a new run",
                checkpoint.run_id.as_str(),
                recorded.name,
                agent.id
            );
        }
        let lease = manager
            .acquire_write_execution_lease(&recorded.name)
            .with_context(|| {
                format!(
                    "checkpoint '{}' could not reacquire the exclusive execution lease for worktree '{}'",
                    checkpoint.run_id.as_str(),
                    recorded.name
                )
            })?;
        let current = lease.record();
        if current.path != recorded.path || current.branch != recorded.branch {
            bail!(
                "checkpoint '{}' worktree metadata for agent '{}' is stale; expected {} on branch {}, found {} on branch {}",
                checkpoint.run_id.as_str(),
                agent.id,
                recorded.path.display(),
                recorded.branch,
                current.path.display(),
                current.branch
            );
        }

        let primary_verified = manager
            .get_managed_verified(&recorded.name)
            .with_context(|| {
                format!(
                    "checkpoint '{}' managed worktree binding for agent '{}' is invalid",
                    checkpoint.run_id.as_str(),
                    agent.id
                )
            })?;
        if &primary_verified != current {
            bail!(
                "checkpoint '{}' managed worktree record or Git backlink for agent '{}' changed while its write lease was held",
                checkpoint.run_id.as_str(),
                agent.id
            );
        }

        let worktree_repo = crate::git_repository::open(&current.path).with_context(|| {
            format!(
                "failed to inspect checkpoint worktree '{}' at {}",
                current.name,
                current.path.display()
            )
        })?;
        match checkpoint_agent.status {
            AgentRunStatus::Pending => {
                let worktree_head = head_oid(&worktree_repo).with_context(|| {
                    format!("failed to inspect HEAD for worktree '{}'", current.name)
                })?;
                if &worktree_head != repo_head {
                    bail!(
                        "checkpoint '{}' pending worktree '{}' is at {}, but primary HEAD is {}; start a new run or restore the checkpoint base",
                        checkpoint.run_id.as_str(),
                        current.name,
                        worktree_head,
                        repo_head
                    );
                }
                let changed_paths = collect_status_paths(&worktree_repo).with_context(|| {
                    format!(
                        "failed to inspect changes for checkpoint worktree '{}'",
                        current.name
                    )
                })?;
                if !changed_paths.is_empty() {
                    bail!(
                        "checkpoint '{}' marks agent '{}' as pending, but its worktree has changes; clean the worktree or start a new run",
                        checkpoint.run_id.as_str(),
                        agent.id
                    );
                }
            }
            AgentRunStatus::Succeeded => {
                ensure_worktree_descends_from_base(
                    &worktree_repo,
                    repo_head,
                    checkpoint.run_id.as_str(),
                    &current.name,
                )?;
                let changed_paths = collect_paths_changed_since_base(&worktree_repo, repo_head)
                    .with_context(|| {
                        format!(
                            "failed to inspect changes for checkpoint worktree '{}'",
                            current.name
                        )
                    })?;
                if changed_paths != checkpoint_agent.changed_paths {
                    bail!(
                        "checkpoint '{}' changed paths for completed agent '{}' no longer match the worktree; start a new run or restore the checkpoint state",
                        checkpoint.run_id.as_str(),
                        agent.id
                    );
                }
                let unclaimed_changed_paths = changed_paths
                    .iter()
                    .filter(|path| {
                        !agent
                            .paths
                            .iter()
                            .any(|claim| path_is_covered_by_claim(path, claim))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if !unclaimed_changed_paths.is_empty()
                    || !checkpoint_agent.unclaimed_changed_paths.is_empty()
                {
                    bail!(
                        "checkpoint '{}' completed agent '{}' has unclaimed changed paths; start a new run after resolving the claim boundary",
                        checkpoint.run_id.as_str(),
                        agent.id
                    );
                }
                let state = capture_consistent_candidate_state(&current.path, repo_head, runtime)
                    .with_context(|| {
                        format!(
                            "checkpoint '{}' completed agent '{}' candidate state could not be recaptured",
                            checkpoint.run_id.as_str(),
                            agent.id
                        )
                    })?;
                if let Some(binding) = checkpoint_agent.candidate_binding.as_ref() {
                    ensure_candidate_binding_matches_state(binding, &state).with_context(|| {
                        format!(
                            "checkpoint '{}' completed agent '{}' candidate binding drifted",
                            checkpoint.run_id.as_str(),
                            agent.id
                        )
                    })?;
                } else {
                    checkpoint_agent
                        .command_completed_binding
                        .as_ref()
                        .with_context(|| {
                            format!(
                                "checkpoint '{}' completed agent '{}' is missing all exact state binding evidence",
                                checkpoint.run_id.as_str(),
                                agent.id
                            )
                        })?
                        .verify_state(&state)
                        .with_context(|| {
                            format!(
                                "checkpoint '{}' completed agent '{}' command state binding drifted",
                                checkpoint.run_id.as_str(),
                                agent.id
                            )
                        })?;
                }
                let before_patch_capture = manager
                    .get_managed_verified(&recorded.name)
                    .with_context(|| {
                        format!(
                            "checkpoint '{}' managed worktree binding for agent '{}' changed before exact candidate recapture",
                            checkpoint.run_id.as_str(),
                            agent.id
                        )
                    })?;
                if &before_patch_capture != current {
                    bail!(
                        "checkpoint '{}' managed worktree record for agent '{}' drifted before exact candidate recapture",
                        checkpoint.run_id.as_str(),
                        agent.id
                    );
                }
                if let Some(binding) = checkpoint_agent.candidate_binding.as_ref() {
                    let captured = capture_bound_candidate(
                        &current.path,
                        repo_head,
                        &state,
                        runtime,
                    )
                    .with_context(|| {
                        format!(
                            "checkpoint '{}' completed agent '{}' exact candidate could not be recaptured",
                            checkpoint.run_id.as_str(),
                            agent.id
                        )
                    })?;
                    if &captured.binding != binding {
                        bail!(
                            "checkpoint '{}' completed agent '{}' exact candidate no longer matches its serialized binding",
                            checkpoint.run_id.as_str(),
                            agent.id
                        );
                    }
                }
            }
            AgentRunStatus::Failed | AgentRunStatus::Skipped => {}
        }
        let after_validation = manager
            .get_managed_verified(&recorded.name)
            .with_context(|| {
                format!(
                    "checkpoint '{}' managed worktree binding for agent '{}' changed during resume validation",
                    checkpoint.run_id.as_str(),
                    agent.id
                )
            })?;
        if &after_validation != current {
            bail!(
                "checkpoint '{}' managed worktree record for agent '{}' drifted during resume validation",
                checkpoint.run_id.as_str(),
                agent.id
            );
        }
        summary.worktree = Some(current.clone());
        summary.worktree_reused = true;
        selected.push(SelectedWorktree {
            lease,
            reused: true,
        });
    }

    Ok(selected)
}

fn ensure_worktree_descends_from_base(
    repo: &Repository,
    base_oid: &Oid,
    run_id: &str,
    worktree_name: &str,
) -> Result<()> {
    let worktree_head = head_oid(repo)
        .with_context(|| format!("failed to inspect HEAD for worktree '{worktree_name}'"))?;
    let merge_base = repo.merge_base(*base_oid, worktree_head).with_context(|| {
        format!("failed to verify base commit {base_oid} for checkpoint worktree '{worktree_name}'")
    })?;
    if merge_base != *base_oid {
        bail!(
            "checkpoint '{}' worktree '{}' does not descend from primary HEAD {}; start a new run or restore the checkpoint base",
            run_id,
            worktree_name,
            base_oid
        );
    }

    Ok(())
}

fn acquire_resume_claims(
    store: &SyncStore,
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
) -> Vec<ClaimToken> {
    let mut tokens = Vec::new();

    for (agent, summary) in plan.agents.iter().zip(summaries.iter_mut()) {
        match find_active_resume_claim(store, agent, summary.claim.as_ref()) {
            Ok(Some(active_claim)) => {
                summary.claim = Some(active_claim.clone());
                tokens.push(active_claim.token);
            }
            Ok(None) => match store.claim_paths(&agent.id, agent.paths.iter()) {
                Ok(claim) => {
                    tokens.push(claim.token);
                    summary.claim = Some(claim);
                }
                Err(error) => fail_summary(
                    summary,
                    format!(
                        "failed to acquire resume claim for agent '{}' on checkpoint paths: {error}",
                        agent.id
                    ),
                ),
            },
            Err(error) => fail_summary(
                summary,
                format!(
                    "failed to validate resume claim for agent '{}' on checkpoint paths: {error}",
                    agent.id
                ),
            ),
        }
    }

    tokens
}

fn find_active_resume_claim(
    store: &SyncStore,
    agent: &AgentPlan,
    checkpoint_claim: Option<&PathClaim>,
) -> Result<Option<PathClaim>> {
    for claim in store.snapshot()? {
        if !claims_overlap_paths(&claim, &agent.paths) {
            continue;
        }
        let same_checkpoint_claim = checkpoint_claim.is_some_and(|checkpoint_claim| {
            checkpoint_claim.token == claim.token
                && checkpoint_claim.agent_id == claim.agent_id
                && paths_match(&checkpoint_claim.paths, &claim.paths)
        });
        if same_checkpoint_claim {
            return Ok(Some(claim));
        }
        bail!(
            "cannot resume agent '{}' because path '{}' is actively claimed by agent '{}' with token {}; release the stale claim or use the matching checkpoint",
            agent.id,
            claim
                .paths
                .first()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            claim.agent_id,
            claim.token.get()
        );
    }

    Ok(None)
}

fn claims_overlap_paths(claim: &PathClaim, paths: &[PathBuf]) -> bool {
    claim
        .paths
        .iter()
        .any(|claimed| paths.iter().any(|path| paths_overlap(claimed, path)))
}

fn paths_match(left: &[PathBuf], right: &[PathBuf]) -> bool {
    left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

fn active_checkpoint_semantic_tokens(
    store: &SemanticIntentStore,
    summaries: &mut [AgentRunSummary],
) -> Result<(Vec<SemanticIntentToken>, bool)> {
    let active_intents = store.snapshot()?;
    let active_keys = active_intents
        .iter()
        .map(|intent| (intent.token, intent.agent_id.clone()))
        .collect::<BTreeSet<_>>();
    let tokens = summaries
        .iter()
        .filter_map(|summary| summary.semantic_intent.as_ref())
        .filter(|intent| active_keys.contains(&(intent.token, intent.agent_id.clone())))
        .map(|intent| intent.token)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut coordination_needed = false;
    for summary in summaries {
        if summary.status != AgentRunStatus::Pending {
            continue;
        }
        let active = summary
            .semantic_intent
            .as_ref()
            .is_some_and(|intent| active_keys.contains(&(intent.token, intent.agent_id.clone())));
        if !active {
            summary.semantic_intent = None;
            summary.semantic_conflicts.clear();
            coordination_needed = true;
        }
    }
    Ok((tokens, coordination_needed))
}

fn coordinate_semantic_intents(
    store: &SemanticIntentStore,
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    mode: SemanticCoordinationMode,
    acquired_tokens: &mut Vec<SemanticIntentToken>,
) {
    let mut planned_preview_intents = Vec::new();
    for (index, agent) in plan.agents.iter().enumerate() {
        if summaries[index].status != AgentRunStatus::Pending
            || summaries[index].semantic_intent.is_some()
        {
            continue;
        }
        let request = semantic_request_for_agent(agent);
        let report = match mode {
            SemanticCoordinationMode::Off => return,
            SemanticCoordinationMode::Warn => {
                store.preview_with_additional_active(request, &planned_preview_intents)
            }
            SemanticCoordinationMode::Block => store.claim(request),
        };
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                fail_summary(
                    &mut summaries[index],
                    format!("semantic coordination failed: {error}"),
                );
                continue;
            }
        };
        attach_semantic_report(&mut summaries[index], &report);
        if mode == SemanticCoordinationMode::Warn {
            planned_preview_intents.push(report.intent.clone());
        } else if report.persisted {
            acquired_tokens.push(report.intent.token);
        }
        if mode == SemanticCoordinationMode::Block && report.has_blocking_conflicts {
            fail_summary(
                &mut summaries[index],
                format!(
                    "semantic coordination blocked intent with {} blocking conflict(s)",
                    report.blocking_conflict_count
                ),
            );
        }
    }
}

fn semantic_request_for_agent(agent: &AgentPlan) -> SemanticIntentRequest {
    SemanticIntentRequest {
        agent_id: agent.id.clone(),
        paths: agent.paths.clone(),
        symbols: agent.semantic_symbols.clone(),
        modules: agent.semantic_modules.clone(),
        task_file: None,
        notes: Vec::new(),
    }
}

fn attach_semantic_report(summary: &mut AgentRunSummary, report: &SemanticCoordinationReport) {
    summary.semantic_intent = Some(report.intent.clone());
    summary.semantic_conflicts = report.conflicts.clone();
}

struct SummaryParts {
    run_id: RunId,
    repo: PathBuf,
    plan_file: PathBuf,
    keep_claims: bool,
    worktree_reuse_policy: WorktreeReusePolicy,
    semantic_coordination: SemanticCoordinationMode,
    summaries: Vec<AgentRunSummary>,
    repo_validation: Vec<ValidationRunSummary>,
    repo_validation_target: Option<RepoValidationTargetBinding>,
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
}

fn summary_from_parts(parts: SummaryParts) -> OrchestrationSummary {
    let SummaryParts {
        run_id,
        repo,
        plan_file,
        keep_claims,
        worktree_reuse_policy,
        semantic_coordination,
        summaries,
        repo_validation,
        repo_validation_target,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    } = parts;
    let success = release_errors.is_empty()
        && semantic_release_errors.is_empty()
        && repo_validation_target.is_some()
        && summaries
            .iter()
            .all(|summary| summary.status == AgentRunStatus::Succeeded)
        && repo_validation
            .iter()
            .all(|summary| summary.status == AgentRunStatus::Succeeded);

    OrchestrationSummary {
        run_id: Some(run_id),
        repo,
        plan_file,
        keep_claims,
        worktree_reuse_policy,
        semantic_coordination,
        success,
        agents: summaries,
        repo_validation,
        repo_validation_target,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    }
}

fn validate_plan(raw: RawPlan) -> Result<OrchestrationPlan> {
    if raw.agents.is_empty() {
        bail!("orchestration plan must include at least one agent");
    }
    if raw.agents.len() > COMBINED_CANDIDATE_MAX_PATCHES {
        bail!(
            "orchestration plan exceeds the configured {} agent limit",
            COMBINED_CANDIDATE_MAX_PATCHES
        );
    }
    if matches!(raw.default_timeout_seconds, Some(0)) {
        bail!("default timeout must be greater than zero seconds");
    }

    let repo_validation_commands = normalize_validation_commands(
        raw.repo_validation_commands,
        raw.default_timeout_seconds,
        "repo validation",
    )?;
    let mut seen_agents = BTreeSet::new();
    let mut claimed_paths = Vec::<PlanPathOwner>::new();
    let mut agents = Vec::with_capacity(raw.agents.len());

    for raw_agent in raw.agents {
        let id = normalize_agent_id(&raw_agent.id)?;
        if !seen_agents.insert(id.clone()) {
            bail!("orchestration plan contains duplicate agent id '{id}'");
        }

        let command = raw_agent.command.trim().to_string();
        if command.is_empty() {
            bail!("agent '{id}' command cannot be empty");
        }

        let timeout_seconds = raw_agent
            .timeout_seconds
            .or(raw.default_timeout_seconds)
            .map(validate_timeout_seconds)
            .transpose()
            .with_context(|| format!("agent '{id}' has invalid timeout"))?;
        let timeout = timeout_seconds.map(Duration::from_secs);

        let working_directory = normalize_working_directory(raw_agent.working_directory)
            .with_context(|| format!("agent '{id}' has invalid working_directory"))?;
        validate_env(&id, &raw_agent.env)?;
        let validation_commands = normalize_validation_commands(
            raw_agent.validation_commands,
            raw.default_timeout_seconds,
            &format!("agent '{id}' validation"),
        )?;

        let paths = normalize_plan_paths(raw_agent.paths)
            .with_context(|| format!("agent '{id}' has invalid path claims"))?;
        for path in &paths {
            if let Some(owner) = claimed_paths
                .iter()
                .find(|owner| paths_overlap(path, &owner.path))
            {
                bail!(
                    "path '{}' for agent '{}' overlaps path '{}' for agent '{}'",
                    path.display(),
                    id,
                    owner.path.display(),
                    owner.agent_id
                );
            }
        }
        claimed_paths.extend(paths.iter().cloned().map(|path| PlanPathOwner {
            agent_id: id.clone(),
            path,
        }));

        let depends_on = raw_agent
            .depends_on
            .into_iter()
            .map(|dependency| normalize_agent_id(&dependency))
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter()
            .collect::<Vec<_>>();

        agents.push(AgentPlan {
            id,
            paths,
            semantic_symbols: normalize_semantic_items(raw_agent.semantic_symbols),
            semantic_modules: normalize_semantic_items(raw_agent.semantic_modules),
            env: raw_agent.env,
            timeout,
            command,
            depends_on,
            working_directory,
            validation_commands,
        });
    }

    validate_dependencies(&agents, &seen_agents)?;
    let dependency_edges = agents.iter().try_fold(0_usize, |total, agent| {
        total
            .checked_add(agent.depends_on.len())
            .context("orchestration dependency edge count overflowed")
    })?;
    if dependency_edges > PLAN_MAX_DEPENDENCY_EDGES {
        bail!(
            "orchestration plan exceeds the configured {} dependency-edge limit",
            PLAN_MAX_DEPENDENCY_EDGES
        );
    }
    let total_validation_commands =
        agents
            .iter()
            .try_fold(repo_validation_commands.len(), |total, agent| {
                total
                    .checked_add(agent.validation_commands.len())
                    .context("orchestration validation command count overflowed")
            })?;
    if total_validation_commands > PLAN_MAX_TOTAL_VALIDATION_COMMANDS {
        bail!(
            "orchestration plan exceeds the configured {} total validation-command limit",
            PLAN_MAX_TOTAL_VALIDATION_COMMANDS
        );
    }

    Ok(OrchestrationPlan {
        agents,
        repo_validation_commands,
        worktree_reuse_policy: raw.worktree_reuse_policy,
    })
}

fn normalize_validation_commands(
    raw_commands: Vec<RawValidationCommand>,
    default_timeout_seconds: Option<u64>,
    context_label: &str,
) -> Result<Vec<ValidationCommandPlan>> {
    if raw_commands.len() > PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE {
        bail!(
            "{context_label} exceeds the configured {} command limit",
            PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE
        );
    }
    raw_commands
        .into_iter()
        .enumerate()
        .map(|(index, raw)| {
            normalize_validation_command(raw, default_timeout_seconds)
                .with_context(|| format!("{context_label} command {} is invalid", index + 1))
        })
        .collect()
}

fn normalize_validation_command(
    raw: RawValidationCommand,
    default_timeout_seconds: Option<u64>,
) -> Result<ValidationCommandPlan> {
    let (name, command, working_directory, env, timeout_seconds) = match raw {
        RawValidationCommand::Shell(command) => (
            None,
            command,
            None,
            BTreeMap::new(),
            default_timeout_seconds,
        ),
        RawValidationCommand::Detailed(details) => {
            validate_optional_name(details.name.as_deref())?;
            (
                details.name,
                details.command,
                normalize_working_directory(details.working_directory)?,
                details.env,
                details.timeout_seconds.or(default_timeout_seconds),
            )
        }
    };

    let command = command.trim().to_string();
    if command.is_empty() {
        bail!("validation command cannot be empty");
    }
    validate_env("validation", &env)?;
    let timeout = timeout_seconds
        .map(validate_timeout_seconds)
        .transpose()?
        .map(Duration::from_secs);

    Ok(ValidationCommandPlan {
        name,
        command,
        env,
        timeout,
        working_directory,
    })
}

fn validate_optional_name(name: Option<&str>) -> Result<()> {
    if name.is_some_and(|value| value.trim().is_empty()) {
        bail!("validation command name cannot be empty");
    }
    Ok(())
}

fn validate_timeout_seconds(seconds: u64) -> Result<u64> {
    if seconds == 0 || seconds > PLAN_MAX_TIMEOUT_SECONDS {
        bail!(
            "timeout must be between 1 and {} seconds",
            PLAN_MAX_TIMEOUT_SECONDS
        );
    }

    Ok(seconds)
}

fn validate_env(agent_id: &str, env: &BTreeMap<String, String>) -> Result<()> {
    for key in env.keys() {
        if key.trim().is_empty() {
            bail!("agent '{agent_id}' environment variable names cannot be empty");
        }
        if key.contains('=') {
            bail!("agent '{agent_id}' environment variable names cannot contain '='");
        }
    }

    Ok(())
}

fn normalize_working_directory(path: Option<PathBuf>) -> Result<Option<PathBuf>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if path == Path::new(".") {
        return Ok(None);
    }

    normalize_repo_relative_path(path)
        .map(Some)
        .map_err(Into::into)
}

fn validate_dependencies(agents: &[AgentPlan], seen_agents: &BTreeSet<String>) -> Result<()> {
    for agent in agents {
        for dependency in &agent.depends_on {
            if dependency == &agent.id {
                bail!("agent '{}' cannot depend on itself", agent.id);
            }
            if !seen_agents.contains(dependency) {
                bail!(
                    "agent '{}' depends on unknown agent '{}'",
                    agent.id,
                    dependency
                );
            }
        }
    }

    ensure_acyclic_dependencies(agents)
}

fn ensure_acyclic_dependencies(agents: &[AgentPlan]) -> Result<()> {
    let mut remaining = agents
        .iter()
        .map(|agent| agent.id.clone())
        .collect::<BTreeSet<_>>();
    let dependencies = agents
        .iter()
        .map(|agent| {
            (
                agent.id.clone(),
                agent.depends_on.iter().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .find(|agent_id| {
                dependencies
                    .get(*agent_id)
                    .map(|agent_dependencies| {
                        agent_dependencies
                            .iter()
                            .all(|dependency| !remaining.contains(dependency))
                    })
                    .unwrap_or(false)
            })
            .cloned();

        let Some(agent_id) = ready else {
            bail!("orchestration plan contains a dependency cycle");
        };
        remaining.remove(&agent_id);
    }

    Ok(())
}

fn normalize_plan_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;

    if paths.is_empty() {
        bail!("path claims cannot be empty");
    }

    Ok(collapse_covered_paths(paths))
}

fn normalize_semantic_items(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }

    collapsed
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[derive(Debug, Clone)]
struct PlanPathOwner {
    agent_id: String,
    path: PathBuf,
}

#[derive(Debug)]
struct SelectedWorktree {
    lease: ManagedWorktreeWriteLease,
    reused: bool,
}

impl SelectedWorktree {
    fn record(&self) -> &WorktreeRecord {
        self.lease.record()
    }

    fn path(&self) -> &Path {
        self.lease.path()
    }
}

fn select_worktrees(
    manager: &WorktreeManager,
    store: &SyncStore,
    primary_head: &Oid,
    plan: &OrchestrationPlan,
    policy: WorktreeReusePolicy,
) -> Result<Vec<SelectedWorktree>> {
    let mut existing = manager
        .list()?
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::with_capacity(plan.agents.len());

    for agent in &plan.agents {
        if let Some(discovered) = existing.remove(&agent.id) {
            if policy == WorktreeReusePolicy::Fresh {
                bail!(
                    "worktree reuse policy 'fresh' requires no existing worktree for agent '{}' at {}",
                    agent.id,
                    discovered.path.display()
                );
            }
            let lease = manager
                .acquire_write_execution_lease(&agent.id)
                .with_context(|| {
                    format!(
                        "failed to acquire exclusive execution lease for worktree '{}'",
                        agent.id
                    )
                })?;
            match policy {
                WorktreeReusePolicy::Reset => {
                    reset_reusable_worktree(store, agent, lease.record(), primary_head)?;
                }
                WorktreeReusePolicy::Clean | WorktreeReusePolicy::Required => {
                    ensure_reusable_worktree(lease.record(), primary_head)?;
                }
                WorktreeReusePolicy::Fresh => {}
            }
            selected.push(SelectedWorktree {
                lease,
                reused: true,
            });
            continue;
        }
        if policy == WorktreeReusePolicy::Required {
            bail!(
                "worktree reuse policy 'required' requires an existing clean worktree for agent '{}'",
                agent.id
            );
        }

        let create_options = WorktreeCreateOptions {
            agent_id: agent.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        };
        #[cfg(test)]
        manager.create_for_test(create_options)?;
        #[cfg(not(test))]
        {
            let cleanliness = manager.acquire_repository_cleanliness().context(
                "orchestration assignment creation requires a capability-bound \
                 repository cleanliness input; commit, stash, or remove pending \
                 changes in the primary repository, then rerun the orchestration",
            )?;
            manager.create_with_repository_cleanliness(create_options, &cleanliness)?;
        }
        let lease = manager
            .acquire_write_execution_lease(&agent.id)
            .with_context(|| {
                format!(
                    "failed to acquire exclusive execution lease for newly created worktree '{}'",
                    agent.id
                )
            })?;
        ensure_reusable_worktree(lease.record(), primary_head).with_context(|| {
            format!(
                "newly created worktree '{}' changed before its execution lease was acquired",
                agent.id
            )
        })?;
        selected.push(SelectedWorktree {
            lease,
            reused: false,
        });
    }

    Ok(selected)
}

fn ensure_reusable_worktree(record: &WorktreeRecord, primary_head: &Oid) -> Result<()> {
    let repo = crate::git_repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    let statuses = collect_status_paths(&repo)?;
    if !statuses.is_empty() {
        bail!(
            "refusing to reuse dirty worktree '{}' at {}; remove it or clean it before rerunning",
            record.name,
            record.path.display()
        );
    }

    let worktree_head = head_oid(&repo)
        .with_context(|| format!("failed to inspect HEAD for worktree '{}'", record.name))?;
    if &worktree_head != primary_head {
        bail!(
            "refusing to reuse stale worktree '{}' at {}; worktree HEAD {} does not match primary HEAD {}. Use --reuse reset to move a clean, unclaimed worktree to the current primary HEAD",
            record.name,
            record.path.display(),
            worktree_head,
            primary_head
        );
    }

    Ok(())
}

fn reset_reusable_worktree(
    store: &SyncStore,
    agent: &AgentPlan,
    record: &WorktreeRecord,
    primary_head: &Oid,
) -> Result<()> {
    ensure_no_active_reset_claims(store, agent)?;
    let repo = crate::git_repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    let statuses = collect_status_paths(&repo)?;
    if !statuses.is_empty() {
        bail!(
            "refusing to reset dirty or untracked worktree '{}' at {}; clean or remove changed paths before using --reuse reset",
            record.name,
            record.path.display()
        );
    }

    let worktree_head = head_oid(&repo)
        .with_context(|| format!("failed to inspect HEAD for worktree '{}'", record.name))?;
    if &worktree_head != primary_head {
        let target = repo
            .find_object(*primary_head, None)
            .with_context(|| format!("failed to find primary HEAD object {primary_head}"))?;
        repo.reset(&target, ResetType::Hard, None)
            .with_context(|| {
                format!(
                    "failed to reset worktree '{}' at {} to primary HEAD {}",
                    record.name,
                    record.path.display(),
                    primary_head
                )
            })?;
    }

    ensure_reusable_worktree(record, primary_head)
}

fn ensure_no_active_reset_claims(store: &SyncStore, agent: &AgentPlan) -> Result<()> {
    for claim in store.snapshot()? {
        if claim.agent_id == agent.id {
            bail!(
                "refusing to reset worktree '{}' because agent '{}' has active claim token {}",
                agent.id,
                agent.id,
                claim.token.get()
            );
        }
        for claimed_path in &claim.paths {
            if agent
                .paths
                .iter()
                .any(|agent_path| paths_overlap(claimed_path, agent_path))
            {
                bail!(
                    "refusing to reset worktree '{}' because path '{}' is actively claimed by agent '{}' with token {}",
                    agent.id,
                    claimed_path.display(),
                    claim.agent_id,
                    claim.token.get()
                );
            }
        }
    }

    Ok(())
}

fn prepare_patch_outputs(
    patch_dir: Option<&Path>,
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    worktrees: &[SelectedWorktree],
) -> Result<Vec<Option<ReservedOutputFile>>> {
    let mut outputs = (0..summaries.len()).map(|_| None).collect::<Vec<_>>();
    let Some(patch_dir) = patch_dir else {
        return Ok(outputs);
    };
    let root = SecureOutputRoot::open_or_create(patch_dir)?;
    for worktree in worktrees {
        root.reject_inside(worktree.path())?;
    }
    for (index, (agent, summary)) in plan.agents.iter().zip(summaries).enumerate() {
        if summary.status != AgentRunStatus::Pending {
            continue;
        }
        match root.reserve(OsString::from(format!("{}.patch", agent.id)).as_os_str()) {
            Ok(output) => outputs[index] = Some(output),
            Err(error) => {
                let cleanup = cleanup_unused_patch_outputs(outputs);
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error.context(format!(
                        "also failed to clean partially reserved patch outputs: {cleanup:#}"
                    ))),
                };
            }
        }
    }
    Ok(outputs)
}

fn cleanup_unused_patch_outputs(outputs: Vec<Option<ReservedOutputFile>>) -> Result<()> {
    let mut errors = Vec::new();
    for output in outputs.into_iter().flatten() {
        let path = output.path().to_path_buf();
        if let Err(error) = output.remove() {
            errors.push(format!(
                "failed to clean unused patch {}: {error:#}",
                path.display()
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

#[derive(Debug)]
struct PatchOutputGuard {
    output: Option<ReservedOutputFile>,
}

impl PatchOutputGuard {
    fn new(output: ReservedOutputFile) -> Self {
        Self {
            output: Some(output),
        }
    }

    fn take(&mut self) -> Option<ReservedOutputFile> {
        self.output.take()
    }
}

impl Drop for PatchOutputGuard {
    fn drop(&mut self) {
        if let Some(output) = self.output.take() {
            let _ = output.remove();
        }
    }
}

struct AgentScheduleContext<'a> {
    manager: &'a WorktreeManager,
    plan: &'a OrchestrationPlan,
    worktrees: &'a [SelectedWorktree],
    jobs: usize,
    base_oid: &'a Oid,
    runtime: OrchestrationExecutionRuntime,
}

fn run_agent_schedule_with_patch_dir(
    context: &AgentScheduleContext<'_>,
    summaries: &mut [AgentRunSummary],
    patch_dir: Option<&Path>,
    checkpoint_writer: Option<&mut RunCheckpointWriter>,
) -> Result<Vec<Option<CapturedCandidate>>> {
    let mut patch_outputs =
        prepare_patch_outputs(patch_dir, context.plan, summaries, context.worktrees)?;
    let mut captured_candidates = vec![None; summaries.len()];
    let schedule_result = run_agent_schedule(
        context,
        summaries,
        &mut patch_outputs,
        &mut captured_candidates,
        checkpoint_writer,
    );
    let cleanup_result = cleanup_unused_patch_outputs(patch_outputs);
    match (schedule_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(captured_candidates),
        (Err(schedule), Ok(())) => Err(schedule),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(schedule), Err(cleanup)) => Err(schedule.context(format!(
            "also failed to clean unused patch reservations: {cleanup:#}"
        ))),
    }
}

fn run_agent_schedule(
    context: &AgentScheduleContext<'_>,
    summaries: &mut [AgentRunSummary],
    patch_outputs: &mut [Option<ReservedOutputFile>],
    captured_candidates: &mut [Option<CapturedCandidate>],
    mut checkpoint_writer: Option<&mut RunCheckpointWriter>,
) -> Result<()> {
    if context.worktrees.len() != summaries.len()
        || context.worktrees.len() != context.plan.agents.len()
        || captured_candidates.len() != summaries.len()
    {
        bail!("selected worktree lease set does not match the orchestration plan");
    }
    for (index, worktree) in context.worktrees.iter().enumerate() {
        if worktree.record().name != context.plan.agents[index].id
            || summaries[index].worktree.as_ref() != Some(worktree.record())
        {
            bail!(
                "selected worktree lease for agent '{}' does not match its run summary",
                context.plan.agents[index].id
            );
        }
    }
    let jobs = context.jobs.max(1);
    let mut remaining = summaries
        .iter()
        .enumerate()
        .filter(|(_, summary)| summary.status == AgentRunStatus::Pending)
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();

    for index in 0..summaries.len() {
        if summaries[index].status != AgentRunStatus::Succeeded {
            continue;
        }
        let expected = capture_selected_candidate_state(
            context.manager,
            &context.plan.agents[index],
            &summaries[index],
            &context.worktrees[index],
            context.base_oid,
            context.runtime,
        )
        .with_context(|| {
            format!(
                "failed to recapture completed candidate for agent '{}'",
                summaries[index].id
            )
        })?;
        let candidate_binding = summaries[index].candidate_binding.clone();
        let completed_binding = summaries[index].command_completed_binding.clone();
        match (&candidate_binding, &completed_binding) {
            (Some(binding), _) => ensure_candidate_binding_matches_state(binding, &expected)?,
            (None, Some(binding)) => binding.verify_state(&expected)?,
            (None, None) => bail!(
                "completed agent '{}' is missing exact command or candidate state binding evidence",
                summaries[index].id
            ),
        }
        if let Some(writer) = checkpoint_writer.as_deref_mut() {
            writer.agent_event(
                PHASE_VALIDATION_STARTED,
                &summaries[index].id,
                &AgentCheckpoint::from(&summaries[index]),
            )?;
        }
        let state_intact = run_agent_validation_commands(
            &context.plan.agents[index],
            &mut summaries[index],
            &context.worktrees[index],
            context.manager,
            &expected,
            context.base_oid,
            context.runtime,
        );
        if let Some(writer) = checkpoint_writer.as_deref_mut() {
            writer.agent_event(
                PHASE_VALIDATED,
                &summaries[index].id,
                &AgentCheckpoint::from(&summaries[index]),
            )?;
        }
        if !state_intact || summaries[index].status != AgentRunStatus::Succeeded {
            bail!(
                "completed agent '{}' failed mandatory resume validation; start a new run after resolving the validation failure",
                summaries[index].id
            );
        }
        let captured = capture_selected_bound_candidate(
            context.manager,
            &context.plan.agents[index],
            &summaries[index],
            &context.worktrees[index],
            context.base_oid,
            &expected,
            context.runtime,
        )?;
        if let Some(binding) = candidate_binding.as_ref() {
            if &captured.binding != binding {
                bail!(
                    "completed agent '{}' candidate patch no longer matches its checkpoint binding",
                    summaries[index].id
                );
            }
        }
        summaries[index].changed_paths = captured.binding.changed_paths.clone();
        summaries[index].unclaimed_changed_paths = summaries[index]
            .changed_paths
            .iter()
            .filter(|path| {
                !context.plan.agents[index]
                    .paths
                    .iter()
                    .any(|claim| path_is_covered_by_claim(path, claim))
            })
            .cloned()
            .collect();
        if !summaries[index].unclaimed_changed_paths.is_empty() {
            bail!(
                "completed agent '{}' exact recovery contains unclaimed paths",
                summaries[index].id
            );
        }
        summaries[index].candidate_binding = Some(captured.binding.clone());
        if let Some(writer) = checkpoint_writer.as_deref_mut() {
            writer.agent_event(
                PHASE_CANDIDATE_CAPTURED,
                &summaries[index].id,
                &AgentCheckpoint::from(&summaries[index]),
            )?;
        }
        captured_candidates[index] = Some(captured);
    }

    while !remaining.is_empty() {
        propagate_dependency_failures(context.plan, summaries, &mut remaining);
        if remaining.is_empty() {
            break;
        }

        let ready = ready_agent_indices(context.plan, summaries, &remaining, jobs);

        if ready.is_empty() {
            for index in std::mem::take(&mut remaining) {
                let unresolved = dependency_statuses(context.plan, summaries, index)
                    .into_iter()
                    .filter(|(_, status)| *status != AgentRunStatus::Succeeded)
                    .map(|(dependency, status)| {
                        format!("'{dependency}' ({})", agent_status_label(status))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                summaries[index].status = AgentRunStatus::Skipped;
                summaries[index].error = Some(format!(
                    "skipped because the scheduler could not resolve dependencies: {unresolved}"
                ));
            }
            break;
        }

        for index in &ready {
            verify_selected_worktree_binding(
                context.manager,
                &context.plan.agents[*index],
                &summaries[*index],
                &context.worktrees[*index],
            )?;
            if let Some(writer) = checkpoint_writer.as_deref_mut() {
                writer.agent_event(
                    PHASE_COMMAND_STARTED,
                    &summaries[*index].id,
                    &AgentCheckpoint::from(&summaries[*index]),
                )?;
            }
        }
        let outcomes = run_ready_agents(
            context.manager,
            context.plan,
            summaries,
            context.worktrees,
            &ready,
            context.runtime,
        )?;

        for (index, run_result) in outcomes {
            apply_command_result(&mut summaries[index], run_result);
            let expected_state = capture_selected_candidate_state(
                context.manager,
                &context.plan.agents[index],
                &summaries[index],
                &context.worktrees[index],
                context.base_oid,
                context.runtime,
            );
            let expected_state = match expected_state {
                Ok(state) => {
                    summaries[index].changed_paths = state.changed_paths.clone();
                    summaries[index].unclaimed_changed_paths = state
                        .changed_paths
                        .iter()
                        .filter(|path| {
                            !context.plan.agents[index]
                                .paths
                                .iter()
                                .any(|claim| path_is_covered_by_claim(path, claim))
                        })
                        .cloned()
                        .collect();
                    summaries[index].command_completed_binding =
                        Some(CompletedCommandStateBinding::from_state(&state)?);
                    if let Some(writer) = checkpoint_writer.as_deref_mut() {
                        writer.agent_event(
                            PHASE_COMMAND_COMPLETED,
                            &summaries[index].id,
                            &AgentCheckpoint::from(&summaries[index]),
                        )?;
                    }
                    Some(state)
                }
                Err(error) => {
                    #[cfg(test)]
                    notify_candidate_boundary_failure(&context.plan.agents[index].id);
                    fail_summary(
                        &mut summaries[index],
                        format!("failed to bind candidate before validation: {error}"),
                    );
                    None
                }
            };
            let mut state_intact = expected_state.is_some();
            if summaries[index].status == AgentRunStatus::Succeeded {
                if let Some(expected_state) = expected_state.as_ref() {
                    if let Some(writer) = checkpoint_writer.as_deref_mut() {
                        writer.agent_event(
                            PHASE_VALIDATION_STARTED,
                            &summaries[index].id,
                            &AgentCheckpoint::from(&summaries[index]),
                        )?;
                    }
                    state_intact = run_agent_validation_commands(
                        &context.plan.agents[index],
                        &mut summaries[index],
                        &context.worktrees[index],
                        context.manager,
                        expected_state,
                        context.base_oid,
                        context.runtime,
                    );
                    if let Some(writer) = checkpoint_writer.as_deref_mut() {
                        writer.agent_event(
                            PHASE_VALIDATED,
                            &summaries[index].id,
                            &AgentCheckpoint::from(&summaries[index]),
                        )?;
                    }
                }
            }
            let patch_output = patch_outputs[index].take();
            let captured = if state_intact {
                expected_state.as_ref().and_then(|expected_state| {
                    match capture_selected_bound_candidate(
                        context.manager,
                        &context.plan.agents[index],
                        &summaries[index],
                        &context.worktrees[index],
                        context.base_oid,
                        expected_state,
                        context.runtime,
                    ) {
                        Ok(captured) => Some(captured),
                        Err(error) => {
                            fail_summary(
                                &mut summaries[index],
                                format!("failed to finalize bound candidate: {error}"),
                            );
                            None
                        }
                    }
                })
            } else {
                None
            };
            if let Some(captured) = captured {
                summaries[index].candidate_binding = Some(captured.binding.clone());
                inspect_captured_agent_changes(
                    &context.plan.agents[index],
                    &mut summaries[index],
                    &captured,
                    patch_output,
                );
                if let Some(writer) = checkpoint_writer.as_deref_mut() {
                    writer.agent_event(
                        PHASE_CANDIDATE_CAPTURED,
                        &summaries[index].id,
                        &AgentCheckpoint::from(&summaries[index]),
                    )?;
                }
                if summaries[index].status == AgentRunStatus::Succeeded {
                    captured_candidates[index] = Some(captured);
                }
            } else {
                inspect_agent_paths_without_patch(
                    &context.plan.agents[index],
                    &mut summaries[index],
                    context.manager,
                    &context.worktrees[index],
                    context.base_oid,
                    patch_output,
                );
            }
            remaining.remove(&index);
        }
    }

    Ok(())
}

fn verify_selected_worktree_binding(
    manager: &WorktreeManager,
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
) -> Result<()> {
    let recorded = summary
        .worktree
        .as_ref()
        .with_context(|| format!("agent '{}' has no selected worktree binding", agent.id))?;
    if recorded != worktree.record() || worktree.record().name != agent.id {
        bail!(
            "agent '{}' selected worktree does not match its held write lease",
            agent.id
        );
    }
    let verified = manager
        .get_managed_verified(&agent.id)
        .with_context(|| format!("agent '{}' managed worktree binding is invalid", agent.id))?;
    if &verified != worktree.record() {
        bail!(
            "agent '{}' managed worktree record or Git backlink changed while its write lease was held",
            agent.id
        );
    }
    Ok(())
}

fn revalidate_ready_agent(
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
) -> Result<crate::collect_revalidation::RevalidationGuard> {
    let claim = summary.claim.as_ref().with_context(|| {
        format!(
            "agent '{}' has no durable path claim for pre-mutation revalidation",
            agent.id
        )
    })?;
    crate::collect_revalidation::revalidate_claimed_worker(
        worktree.path(),
        &agent.id,
        claim.token,
        &claim.paths,
        worktree.record(),
    )
    .with_context(|| format!("pre-mutation revalidation failed for agent '{}'", agent.id))
}

#[cfg(test)]
fn install_candidate_boundary_failure_hook(
    agent_id: &str,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let hook = CANDIDATE_BOUNDARY_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    let mut slot = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        slot.is_none(),
        "candidate boundary failure hook already installed"
    );
    *slot = Some(CandidateBoundaryFailureHook {
        agent_id: agent_id.to_string(),
        reached: reached_tx,
        release: release_rx,
    });
    (reached_rx, release_tx)
}

#[cfg(test)]
fn notify_candidate_boundary_failure(agent_id: &str) {
    let hook = CANDIDATE_BOUNDARY_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    let selected = {
        let mut slot = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match slot.take() {
            Some(hook) if hook.agent_id == agent_id => Some(hook),
            Some(other) => {
                *slot = Some(other);
                None
            }
            None => None,
        }
    };
    if let Some(selected) = selected {
        let _ = selected.reached.send(());
        let _ = selected.release.recv_timeout(Duration::from_secs(15));
    }
}

fn capture_selected_candidate_state(
    manager: &WorktreeManager,
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CandidateStateSnapshot> {
    verify_selected_worktree_binding(manager, agent, summary, worktree)?;
    let state = capture_consistent_candidate_state(worktree.path(), base_oid, runtime)?;
    verify_selected_worktree_binding(manager, agent, summary, worktree)?;
    Ok(state)
}

fn capture_selected_bound_candidate(
    manager: &WorktreeManager,
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CapturedCandidate> {
    verify_selected_worktree_binding(manager, agent, summary, worktree)?;
    let captured = capture_bound_candidate(worktree.path(), base_oid, expected_state, runtime)?;
    verify_selected_worktree_binding(manager, agent, summary, worktree)?;
    Ok(captured)
}

fn propagate_dependency_failures(
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    remaining: &mut BTreeSet<usize>,
) {
    loop {
        let blocked = remaining
            .iter()
            .copied()
            .filter_map(|index| {
                let blockers = dependency_statuses(plan, summaries, index)
                    .into_iter()
                    .filter(|(_, status)| {
                        matches!(status, AgentRunStatus::Failed | AgentRunStatus::Skipped)
                    })
                    .collect::<Vec<_>>();
                (!blockers.is_empty()).then_some((index, blockers))
            })
            .collect::<Vec<_>>();
        if blocked.is_empty() {
            return;
        }

        for (index, blockers) in blocked {
            let detail = blockers
                .into_iter()
                .map(|(dependency, status)| {
                    format!("'{dependency}' ({})", agent_status_label(status))
                })
                .collect::<Vec<_>>()
                .join(", ");
            summaries[index].status = AgentRunStatus::Skipped;
            summaries[index].error = Some(format!(
                "skipped because dependencies did not succeed: {detail}"
            ));
            remaining.remove(&index);
        }
    }
}

fn ready_agent_indices(
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    remaining: &BTreeSet<usize>,
    jobs: usize,
) -> Vec<usize> {
    remaining
        .iter()
        .copied()
        .filter(|index| {
            plan.agents[*index].depends_on.iter().all(|dependency| {
                summary_status_by_id(summaries, dependency) == Some(AgentRunStatus::Succeeded)
            })
        })
        .take(jobs.max(1))
        .collect()
}

fn dependency_statuses<'a>(
    plan: &'a OrchestrationPlan,
    summaries: &[AgentRunSummary],
    index: usize,
) -> Vec<(&'a str, AgentRunStatus)> {
    plan.agents[index]
        .depends_on
        .iter()
        .map(|dependency| {
            (
                dependency.as_str(),
                summary_status_by_id(summaries, dependency).unwrap_or(AgentRunStatus::Pending),
            )
        })
        .collect()
}

include!("orchestrator/part2.rs");

#[cfg(test)]
mod tests;
