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
    collect_revalidation::{
        revalidate_for_collection, CollectRevalidationGuard, CollectRevalidationRequest,
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
    if runtime == OrchestrationExecutionRuntime::Verified {
        bail!(
            "orchestration assignment creation is temporarily unsupported because managed worktree creation requires a capability-bound repository cleanliness input"
        );
    }
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
                store: &store,
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
        let manager = WorktreeManager::new(&repo);
        let store = SyncStore::open(&repo)?;
        let semantic_store = SemanticIntentStore::open(&repo)?;
        let mut summaries = summaries_from_checkpoint(&plan, &checkpoint)?;
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
                store: &store,
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
        manager.create(create_options)?;
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
    store: &'a SyncStore,
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
        let captured = match capture_revalidated_selected_bound_candidate(
            context,
            index,
            &summaries[index],
            &expected,
        ) {
            Ok(captured) => captured,
            Err(error) => {
                fail_summary(
                    &mut summaries[index],
                    format!("pre-collection revalidation or candidate collection failed: {error}"),
                );
                continue;
            }
        };
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
                    match capture_revalidated_selected_bound_candidate(
                        context,
                        index,
                        &summaries[index],
                        expected_state,
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

fn capture_revalidated_selected_bound_candidate(
    context: &AgentScheduleContext<'_>,
    index: usize,
    summary: &AgentRunSummary,
    expected_state: &CandidateStateSnapshot,
) -> Result<CapturedCandidate> {
    let agent = &context.plan.agents[index];
    let worktree = &context.worktrees[index];
    let guard =
        revalidate_selected_collection(context.store, context.manager, agent, summary, worktree)?;
    let captured = capture_selected_bound_candidate(
        context.manager,
        agent,
        summary,
        worktree,
        context.base_oid,
        expected_state,
        context.runtime,
    )?;
    guard
        .verify()
        .context("authenticated claim binding changed during candidate collection")?;
    Ok(captured)
}

fn revalidate_selected_collection(
    store: &SyncStore,
    manager: &WorktreeManager,
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
) -> Result<CollectRevalidationGuard> {
    let claim = summary
        .claim
        .as_ref()
        .with_context(|| format!("agent '{}' has no claimed-path binding", agent.id))?;
    revalidate_for_collection(
        store,
        manager,
        CollectRevalidationRequest {
            agent_id: &agent.id,
            claim_token: claim.token,
            claimed_paths: &agent.paths,
            expected_worktree: worktree.record(),
            expected_branch: &worktree.record().branch,
        },
    )
    .map_err(Into::into)
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

fn summary_status_by_id(summaries: &[AgentRunSummary], agent_id: &str) -> Option<AgentRunStatus> {
    summaries
        .iter()
        .find(|summary| summary.id == agent_id)
        .map(|summary| summary.status)
}

fn agent_status_label(status: AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Pending => "pending",
        AgentRunStatus::Succeeded => "succeeded",
        AgentRunStatus::Failed => "failed",
        AgentRunStatus::Skipped => "skipped",
    }
}

fn run_ready_agents(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    worktrees: &[SelectedWorktree],
    ready: &[usize],
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<(usize, Result<CommandRunResult, ProcessRunError>)>> {
    if ready.len() == 1 {
        let index = ready[0];
        verify_selected_worktree_binding(
            manager,
            &plan.agents[index],
            &summaries[index],
            &worktrees[index],
        )?;
        let spec = command_spec(
            &plan.agents[index],
            &summaries[index],
            &worktrees[index],
            runtime,
        )?;
        return Ok(vec![(index, run_agent_command(spec))]);
    }

    let mut handles = Vec::with_capacity(ready.len());
    for index in ready {
        verify_selected_worktree_binding(
            manager,
            &plan.agents[*index],
            &summaries[*index],
            &worktrees[*index],
        )?;
        let spec = command_spec(
            &plan.agents[*index],
            &summaries[*index],
            &worktrees[*index],
            runtime,
        )?;
        let index = *index;
        handles.push((
            index,
            thread::spawn(move || (index, run_agent_command(spec))),
        ));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for (index, handle) in handles {
        let outcome = handle.join().unwrap_or_else(|_| {
            (
                index,
                Ok(CommandRunResult {
                    status: None,
                    duration_ms: 0,
                    timed_out: false,
                    stdout: OutputSummary::default(),
                    stderr: OutputSummary::default(),
                    process_error: Some("agent command runner panicked".to_string()),
                }),
            )
        });
        outcomes.push(outcome);
    }

    outcomes.sort_by_key(|(index, _)| *index);
    Ok(outcomes)
}

fn inspect_captured_agent_changes(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    captured: &CapturedCandidate,
    patch_output: Option<ReservedOutputFile>,
) {
    let mut patch_output = patch_output.map(PatchOutputGuard::new);
    if summary.worktree.is_none() {
        fail_summary(summary, "agent has no selected worktree");
        return;
    }
    summary.changed_paths = captured.binding.changed_paths.clone();
    summary.unclaimed_changed_paths = summary
        .changed_paths
        .iter()
        .filter(|path| {
            !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect::<Vec<_>>();

    if !summary.unclaimed_changed_paths.is_empty() {
        let paths = summary
            .unclaimed_changed_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        fail_summary(
            summary,
            format!("agent changed paths outside its claims: {paths}"),
        );
    }

    if let Some(patch_output) = patch_output.as_mut().and_then(PatchOutputGuard::take) {
        match write_captured_agent_patch(patch_output, &captured.patch) {
            Ok(Some(path)) => summary.patch_path = Some(path),
            Ok(None) => {}
            Err(error) => fail_summary(summary, format!("failed to write patch: {error}")),
        }
    }
}

fn inspect_agent_paths_without_patch(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    manager: &WorktreeManager,
    worktree: &SelectedWorktree,
    base_oid: &Oid,
    patch_output: Option<ReservedOutputFile>,
) {
    let _patch_output = patch_output.map(PatchOutputGuard::new);
    if let Err(error) = verify_selected_worktree_binding(manager, agent, summary, worktree) {
        fail_summary(
            summary,
            format!("refusing rejected-candidate inspection: {error}"),
        );
        return;
    }
    let repo = match crate::git_repository::open(worktree.path()) {
        Ok(repo) => repo,
        Err(error) => {
            fail_summary(
                summary,
                format!("failed to inspect rejected candidate: {error}"),
            );
            return;
        }
    };
    let changed_paths = match collect_paths_changed_since_base(&repo, base_oid) {
        Ok(paths) => paths,
        Err(error) => {
            fail_summary(
                summary,
                format!("failed to collect rejected candidate paths: {error}"),
            );
            return;
        }
    };
    if let Err(error) = verify_selected_worktree_binding(manager, agent, summary, worktree) {
        fail_summary(
            summary,
            format!("rejected candidate binding changed during inspection: {error}"),
        );
        return;
    }
    summary.changed_paths = changed_paths;
    summary.unclaimed_changed_paths = summary
        .changed_paths
        .iter()
        .filter(|path| {
            !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect();
}

fn fail_summary(summary: &mut AgentRunSummary, message: impl Into<String>) {
    summary.status = AgentRunStatus::Failed;
    let message = message.into();
    summary.error = match summary.error.take() {
        Some(existing) => Some(format!("{existing}; {message}")),
        None => Some(message),
    };
}

fn collect_status_paths(repo: &Repository) -> Result<Vec<PathBuf>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect git status")?;
    let mut paths = BTreeSet::new();
    for entry in statuses.iter() {
        let path = entry.path().context("git status path is not valid UTF-8")?;
        paths.insert(PathBuf::from(path));
    }
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn collect_paths_changed_since_base(repo: &Repository, base_oid: &Oid) -> Result<Vec<PathBuf>> {
    let base_commit = repo
        .find_commit(*base_oid)
        .with_context(|| format!("failed to find base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff worktree against base commit")?;
    let mut paths = BTreeSet::new();
    diff.foreach(
        &mut |delta, _| {
            collect_delta_paths(delta, &mut paths);
            true
        },
        None,
        None,
        None,
    )
    .context("failed to inspect changed paths")?;

    Ok(paths.into_iter().collect())
}

fn collect_delta_paths(delta: git2::DiffDelta<'_>, paths: &mut BTreeSet<PathBuf>) {
    match delta.status() {
        Delta::Deleted => {
            insert_delta_path(delta.old_file().path(), paths);
        }
        Delta::Renamed | Delta::Copied => {
            insert_delta_path(delta.old_file().path(), paths);
            insert_delta_path(delta.new_file().path(), paths);
        }
        _ => {
            insert_delta_path(delta.new_file().path(), paths);
        }
    }
}

fn capture_consistent_candidate_state(
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CandidateStateSnapshot> {
    for _ in 0..CANDIDATE_CAPTURE_ATTEMPTS {
        let first = capture_candidate_state_once(worktree_path, base_oid, runtime)?;
        let second = capture_candidate_state_once(worktree_path, base_oid, runtime)?;
        if first == second {
            return Ok(second);
        }
    }
    bail!(
        "candidate state changed while its validation binding was captured; retry after worktree activity stops"
    )
}

fn capture_candidate_state_once(
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CandidateStateSnapshot> {
    let repo =
        crate::git_repository::open(worktree_path).context("failed to open candidate worktree")?;
    let head_oid = head_oid(&repo).context("failed to capture candidate HEAD")?;
    let merge_base = repo
        .merge_base(*base_oid, head_oid)
        .context("failed to verify candidate ancestry from the captured run base")?;
    if merge_base != *base_oid {
        bail!("candidate HEAD no longer descends from the captured run base");
    }
    let base = base_oid.to_string();
    let index_entries = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--stage", "-z"],
        runtime,
        "candidate index entries",
    )?;
    let index_flags = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "-v", "-z"],
        runtime,
        "candidate index flags",
    )?;
    let index_diff = capture_fixed_git_stdout(
        worktree_path,
        [
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            base.as_str(),
        ],
        runtime,
        "candidate index diff",
    )?;
    let worktree_diff = capture_fixed_git_stdout(
        worktree_path,
        ["diff", "--no-ext-diff", "--no-textconv", "--binary"],
        runtime,
        "candidate worktree diff",
    )?;
    let status = capture_candidate_status(&repo)?;
    let untracked = capture_untracked_manifest(worktree_path, runtime)?;
    let changed_paths = collect_paths_changed_since_base(&repo, base_oid)?
        .into_iter()
        .map(|path| normalize_repo_relative_path(&path).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate changed-path count exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }

    Ok(CandidateStateSnapshot {
        base_oid: *base_oid,
        head_oid,
        index_entries_oid: hash_candidate_component(&index_entries)?,
        index_flags_oid: hash_candidate_component(&index_flags)?,
        index_diff_oid: hash_candidate_component(&index_diff)?,
        worktree_diff_oid: hash_candidate_component(&worktree_diff)?,
        status_oid: hash_candidate_component(&status)?,
        untracked_oid: hash_candidate_component(&untracked)?,
        changed_paths,
    })
}

fn capture_fixed_git_stdout(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<OsString>>,
    runtime: OrchestrationExecutionRuntime,
    label: &str,
) -> Result<Vec<u8>> {
    let output = run_fixed_git(worktree_path, args, WorkspaceAccess::ReadOnly, runtime)
        .with_context(|| format!("failed to capture {label}"))?;
    if !output.status.success() {
        bail!(
            "failed to capture {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn capture_candidate_status(repo: &Repository) -> Result<Vec<u8>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true)
        .include_unmodified(false);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to capture candidate status")?;
    if statuses.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate status exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }
    let mut records = statuses
        .iter()
        .map(|entry| (entry.path_bytes().to_vec(), entry.status().bits()))
        .collect::<Vec<_>>();
    records.sort();
    let mut encoded = Vec::new();
    for (path, status) in records {
        extend_bounded_candidate_bytes(&mut encoded, &status.to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut encoded, &(path.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut encoded, &path)?;
    }
    Ok(encoded)
}

fn capture_untracked_manifest(
    worktree_path: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<u8>> {
    let output = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        runtime,
        "candidate untracked paths",
    )?;
    let paths = output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    if paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate untracked-path count exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }

    let mut manifest = Vec::new();
    extend_bounded_candidate_bytes(&mut manifest, b"MACO\0untracked-manifest\0v2\0")?;
    let mut total_content_bytes = 0_usize;
    for raw_path in paths {
        let path = normalize_repo_relative_path(Path::new(&git_path_argument(raw_path)?))?;
        let absolute = worktree_path.join(&path);
        let metadata = fs::symlink_metadata(&absolute).with_context(|| {
            format!(
                "failed to inspect untracked candidate path {}",
                path.display()
            )
        })?;
        let (kind, git_mode, content) = if metadata.file_type().is_file() {
            let bytes = BoundedRegularReader::read_relative(
                worktree_path,
                &path,
                CANDIDATE_MAX_SINGLE_FILE_BYTES as u64,
            )?;
            (b'f', normalized_untracked_git_mode(&metadata)?, bytes)
        } else if metadata.file_type().is_symlink() {
            (
                b'l',
                0o120000_u32,
                read_candidate_symlink(&absolute, &metadata)?,
            )
        } else {
            bail!(
                "candidate untracked path is not a regular file or symlink: {}",
                path.display()
            );
        };
        if content.len() > CANDIDATE_MAX_SINGLE_FILE_BYTES {
            bail!(
                "candidate path '{}' exceeded the configured {} byte per-file limit",
                path.display(),
                CANDIDATE_MAX_SINGLE_FILE_BYTES
            );
        }
        total_content_bytes = total_content_bytes
            .checked_add(content.len())
            .context("candidate content byte count overflowed")?;
        if total_content_bytes > CANDIDATE_MAX_TOTAL_BYTES {
            bail!(
                "candidate untracked content exceeded the configured {} byte aggregate limit",
                CANDIDATE_MAX_TOTAL_BYTES
            );
        }
        let path_bytes = candidate_path_bytes(&path);
        let content_oid = hash_candidate_component(&content)?;
        extend_bounded_candidate_bytes(&mut manifest, &(path_bytes.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, &path_bytes)?;
        extend_bounded_candidate_bytes(&mut manifest, &[kind])?;
        extend_bounded_candidate_bytes(&mut manifest, &git_mode.to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, &(content.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, content_oid.as_bytes())?;
    }
    Ok(manifest)
}

#[cfg(unix)]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(if metadata.mode() & 0o111 == 0 {
        0o100644
    } else {
        0o100755
    })
}

#[cfg(windows)]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(0o100644)
}

#[cfg(not(any(unix, windows)))]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(0o100644)
}

fn read_candidate_symlink(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>> {
    let target = fs::read_link(path)
        .with_context(|| format!("failed to read candidate symlink {}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck candidate symlink {}", path.display()))?;
    if !same_candidate_file_identity(before, &after) || !after.file_type().is_symlink() {
        bail!("candidate symlink changed while it was captured");
    }
    Ok(candidate_path_bytes(&target))
}

#[cfg(unix)]
fn same_candidate_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_candidate_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type() && left.len() == right.len()
}

#[cfg(unix)]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn extend_bounded_candidate_bytes(target: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let next = target
        .len()
        .checked_add(bytes.len())
        .context("candidate binding byte count overflowed")?;
    if next > CANDIDATE_MAX_TOTAL_BYTES {
        bail!(
            "candidate binding exceeded the configured {} byte limit",
            CANDIDATE_MAX_TOTAL_BYTES
        );
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn hash_candidate_component(bytes: &[u8]) -> Result<Oid> {
    Oid::hash_object(git2::ObjectType::Blob, bytes)
        .context("failed to hash candidate binding component")
}

impl CandidateStateSnapshot {
    fn state_oid(&self) -> Result<Oid> {
        let mut binding = Vec::new();
        extend_bounded_candidate_bytes(&mut binding, b"MACO\0candidate-state\0v1\0")?;
        for oid in [
            self.base_oid,
            self.head_oid,
            self.index_entries_oid,
            self.index_flags_oid,
            self.index_diff_oid,
            self.worktree_diff_oid,
            self.status_oid,
            self.untracked_oid,
        ] {
            extend_bounded_candidate_bytes(&mut binding, oid.as_bytes())?;
        }
        for path in &self.changed_paths {
            let bytes = candidate_path_bytes(path);
            extend_bounded_candidate_bytes(&mut binding, &(bytes.len() as u64).to_le_bytes())?;
            extend_bounded_candidate_bytes(&mut binding, &bytes)?;
        }
        hash_candidate_component(&binding)
    }

    fn drift_from(&self, previous: &Self) -> Option<String> {
        let mut components = Vec::new();
        if self.head_oid != previous.head_oid {
            components.push("HEAD");
        }
        if self.index_entries_oid != previous.index_entries_oid
            || self.index_flags_oid != previous.index_flags_oid
            || self.index_diff_oid != previous.index_diff_oid
        {
            components.push("index");
        }
        if self.worktree_diff_oid != previous.worktree_diff_oid {
            components.push("tracked worktree content");
        }
        if self.untracked_oid != previous.untracked_oid {
            components.push("untracked content");
        }
        if self.status_oid != previous.status_oid || self.changed_paths != previous.changed_paths {
            components.push("changed paths/status");
        }
        (!components.is_empty()).then(|| {
            let before = previous
                .changed_paths
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let after = self.changed_paths.iter().cloned().collect::<BTreeSet<_>>();
            let path_detail = before
                .symmetric_difference(&after)
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            let path_detail = if path_detail.is_empty() {
                String::new()
            } else {
                format!("; affected paths: {}", path_detail.join(", "))
            };
            format!(
                "candidate-relevant state changed after the agent command: {}{path_detail}",
                components.join(", ")
            )
        })
    }
}

impl CompletedCommandStateBinding {
    fn from_state(state: &CandidateStateSnapshot) -> Result<Self> {
        Ok(Self {
            version: CANDIDATE_BINDING_VERSION,
            base_oid: state.base_oid.to_string(),
            head_oid: state.head_oid.to_string(),
            state_oid: state.state_oid()?.to_string(),
            changed_paths: state.changed_paths.clone(),
        })
    }

    fn verify_state(&self, state: &CandidateStateSnapshot) -> Result<()> {
        if self.version != CANDIDATE_BINDING_VERSION
            || self.base_oid != state.base_oid.to_string()
            || self.head_oid != state.head_oid.to_string()
            || self.state_oid != state.state_oid()?.to_string()
            || self.changed_paths != state.changed_paths
        {
            bail!("completed command state no longer matches its authenticated exact binding");
        }
        Ok(())
    }
}

fn capture_bound_candidate(
    worktree_path: &Path,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CapturedCandidate> {
    let before = capture_consistent_candidate_state(worktree_path, base_oid, runtime)?;
    if let Some(drift) = before.drift_from(expected_state) {
        bail!("{drift}");
    }
    let repo =
        crate::git_repository::open(worktree_path).context("failed to open candidate worktree")?;
    let (changed_paths, patch) = match runtime {
        OrchestrationExecutionRuntime::Verified => {
            capture_worktree_diff_from_commit(&repo, worktree_path, *base_oid)
                .context("failed to capture the exact bounded candidate patch")?
        }
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => {
            capture_simulation_candidate_patch(&repo, worktree_path, base_oid, runtime)?
        }
    };
    validate_patch_output_size(patch.len())?;
    let changed_paths = changed_paths
        .into_iter()
        .map(|path| normalize_repo_relative_path(&path).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if changed_paths != before.changed_paths {
        bail!("candidate patch paths did not match the bound candidate state");
    }
    let after = capture_consistent_candidate_state(worktree_path, base_oid, runtime)?;
    if let Some(drift) = after.drift_from(&before) {
        bail!("candidate changed while its exact patch was captured: {drift}");
    }
    let patch_bytes = u64::try_from(patch.len()).context("candidate patch length overflowed")?;
    let binding = AgentCandidateBinding {
        version: CANDIDATE_BINDING_VERSION,
        base_oid: base_oid.to_string(),
        head_oid: before.head_oid.to_string(),
        state_oid: before.state_oid()?.to_string(),
        diff_oid: hash_candidate_component(&patch)?.to_string(),
        changed_paths: before.changed_paths.clone(),
        patch_bytes,
    };
    Ok(CapturedCandidate { binding, patch })
}

#[cfg(test)]
fn capture_simulation_candidate_patch(
    repo: &Repository,
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<(Vec<PathBuf>, Vec<u8>)> {
    let base = base_oid.to_string();
    let mut patch = capture_fixed_git_stdout(
        worktree_path,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            base.as_str(),
        ],
        runtime,
        "simulation candidate tracked patch",
    )?;
    let untracked = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        runtime,
        "simulation candidate untracked paths",
    )?;
    for raw_path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = normalize_repo_relative_path(Path::new(&git_path_argument(raw_path)?))?;
        let _ = BoundedRegularReader::read_relative(
            worktree_path,
            &path,
            CANDIDATE_MAX_SINGLE_FILE_BYTES as u64,
        )?;
        let output = run_fixed_git(
            worktree_path,
            vec![
                OsString::from("diff"),
                OsString::from("--no-index"),
                OsString::from("--no-ext-diff"),
                OsString::from("--no-textconv"),
                OsString::from("--binary"),
                OsString::from("--"),
                OsString::from(git_null_device()),
                path.as_os_str().to_os_string(),
            ],
            WorkspaceAccess::ReadOnly,
            runtime,
        )
        .context("failed to capture simulation untracked patch")?;
        if output.status.code() != Some(1) && !output.status.success() {
            bail!("simulation untracked patch capture failed");
        }
        extend_bounded_candidate_bytes(&mut patch, &output.stdout)?;
    }
    let changed_paths = collect_paths_changed_since_base(repo, base_oid)?;
    Ok((changed_paths, patch))
}

fn ensure_candidate_binding_matches_state(
    binding: &AgentCandidateBinding,
    state: &CandidateStateSnapshot,
) -> Result<()> {
    if binding.version != CANDIDATE_BINDING_VERSION {
        bail!(
            "unsupported candidate binding version {}; start a new run",
            binding.version
        );
    }
    if binding.base_oid != state.base_oid.to_string()
        || binding.head_oid != state.head_oid.to_string()
        || binding.state_oid != state.state_oid()?.to_string()
        || binding.changed_paths != state.changed_paths
    {
        bail!("candidate state no longer matches its serialized validation binding");
    }
    Ok(())
}

fn insert_delta_path(path: Option<&Path>, paths: &mut BTreeSet<PathBuf>) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        paths.insert(path.to_path_buf());
    }
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn write_captured_agent_patch(
    mut patch_output: ReservedOutputFile,
    bytes: &[u8],
) -> Result<Option<PathBuf>> {
    if bytes.is_empty() {
        patch_output.remove()?;
        return Ok(None);
    }
    if let Err(error) = validate_patch_output_size(bytes.len()) {
        let patch_path = patch_output.path().to_path_buf();
        let cleanup = patch_output.remove();
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean reserved patch {}: {cleanup:#}",
                patch_path.display()
            ))),
        };
    }
    let patch_path = patch_output.path().to_path_buf();
    if let Err(error) = patch_output.write_bytes_atomic(bytes, PATCH_OUTPUT_MAX_BYTES) {
        let cleanup = patch_output.remove();
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean reserved patch {}: {cleanup:#}",
                patch_path.display()
            ))),
        };
    }
    Ok(Some(patch_path))
}

fn validate_patch_output_size(bytes: usize) -> Result<()> {
    if bytes >= PATCH_OUTPUT_MAX_BYTES {
        bail!(
            "patch output reached the configured {} byte capture boundary",
            PATCH_OUTPUT_MAX_BYTES
        );
    }
    Ok(())
}

#[cfg(unix)]
fn git_path_argument(path: &[u8]) -> Result<OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(path.to_vec()))
}

#[cfg(not(unix))]
fn git_path_argument(path: &[u8]) -> Result<OsString> {
    String::from_utf8(path.to_vec())
        .map(OsString::from)
        .context("Git returned a non-UTF-8 path that this platform cannot represent losslessly")
}

fn run_fixed_git(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    access: WorkspaceAccess,
    runtime: OrchestrationExecutionRuntime,
) -> Result<std::process::Output> {
    run_fixed_git_with_stdin(worktree_path, args, access, StdinMode::Null, runtime)
}

fn run_fixed_git_with_stdin(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    access: WorkspaceAccess,
    stdin: StdinMode,
    runtime: OrchestrationExecutionRuntime,
) -> Result<std::process::Output> {
    if let StdinMode::Bytes(bytes) = &stdin {
        if bytes.len() >= COMBINED_CANDIDATE_MAX_BYTES {
            bail!(
                "orchestrator Git stdin reached the configured {} byte boundary",
                COMBINED_CANDIDATE_MAX_BYTES
            );
        }
    }
    let git = trusted_system_executable(
        "git",
        &["/run/current-system/sw/bin/git", "/usr/bin/git", "/bin/git"],
    )?;
    let environment = BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        (
            "GIT_CONFIG_GLOBAL".to_string(),
            git_null_device().to_string(),
        ),
        ("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
    ]);
    let mut command_args = vec![
        std::ffi::OsString::from("--no-pager"),
        std::ffi::OsString::from("--no-optional-locks"),
        std::ffi::OsString::from("--literal-pathspecs"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.fsmonitor=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.untrackedCache=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.splitIndex=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.hooksPath=/dev/null"),
    ];
    command_args.extend(args.into_iter().map(Into::into));
    let process_spec = ProcessSpec::direct(
        "orchestrator Git command",
        git,
        command_args,
        worktree_path,
        GIT_COMMAND_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(stdin)
    .with_stdin_limit(COMBINED_CANDIDATE_MAX_BYTES)
    .with_timeout(Some(GIT_COMMAND_TIMEOUT));
    let run_result = run_process(match runtime {
        OrchestrationExecutionRuntime::Verified => {
            let profile = match access {
                WorkspaceAccess::ReadOnly => {
                    StrictOfflineWorkspaceProfile::read_only(worktree_path)
                }
                WorkspaceAccess::ReadWrite => {
                    StrictOfflineWorkspaceProfile::read_write(worktree_path)
                }
            };
            let repository = crate::git_repository::open(worktree_path)
                .context("failed to resolve Git administration roots for fixed command")?;
            let profile = profile
                .with_visible_read_only_root(repository.commondir())
                .with_hidden_root(sensitive_state_root(repository.commondir())?);
            process_spec
                .with_private_runtime_home(true)
                .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                    profile,
                ))
        }
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    });
    let output = run_result?;
    if output.timed_out
        || output.process_error.is_some()
        || output.stdin_error.is_some()
        || (runtime == OrchestrationExecutionRuntime::Verified
            && !output.safety_evidence_verified())
        || output.stdout.is_truncated()
        || output.stderr.is_truncated()
    {
        bail!(
            "orchestrator Git command was not safely bounded: process_tree={:?}; side_effects={:?}; process_error={:?}; stdin_error={:?}",
            output.process_tree,
            output.side_effects,
            output.process_error,
            output.stdin_error
        );
    }
    Ok(std::process::Output {
        status: output
            .status
            .context("orchestrator Git command terminated without status")?,
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
    })
}

#[cfg(target_os = "windows")]
fn git_null_device() -> &'static str {
    "NUL"
}

#[cfg(not(target_os = "windows"))]
fn git_null_device() -> &'static str {
    "/dev/null"
}

fn command_spec(
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CommandRunSpec> {
    let recorded = summary
        .worktree
        .as_ref()
        .with_context(|| format!("agent '{}' has no selected worktree", summary.id))?;
    if recorded != worktree.record() || worktree.record().name != agent.id {
        bail!(
            "agent '{}' selected worktree does not match its exclusive execution lease",
            agent.id
        );
    }
    let working_directory = agent
        .working_directory
        .as_ref()
        .map(|path| worktree.path().join(path))
        .unwrap_or_else(|| worktree.path().to_path_buf());
    let (git_common_root, sensitive_root) = orchestration_sandbox_roots(worktree.path())?;

    Ok(CommandRunSpec {
        command: agent.command.clone(),
        workspace_root: worktree.path().to_path_buf(),
        working_directory,
        env: agent.env.clone(),
        timeout: agent.timeout,
        visible_read_only_roots: vec![git_common_root],
        hidden_roots: vec![sensitive_root],
        runtime,
    })
}

fn orchestration_sandbox_roots(worktree: &Path) -> Result<(PathBuf, PathBuf)> {
    let repository = crate::git_repository::open(worktree).with_context(|| {
        format!(
            "failed to resolve the repository common directory for {}",
            worktree.display()
        )
    })?;
    let common_dir = repository.commondir().to_path_buf();
    let sensitive = sensitive_state_root(&common_dir)
        .context("repository sensitive state could not be bound for child-process masking")?;
    Ok((common_dir, sensitive))
}

fn run_agent_validation_commands(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    worktree: &SelectedWorktree,
    manager: &WorktreeManager,
    expected_state: &CandidateStateSnapshot,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> bool {
    let Some(recorded) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree for validation");
        return false;
    };
    if recorded != worktree.record() || worktree.record().name != agent.id {
        fail_summary(
            summary,
            format!(
                "agent '{}' selected worktree does not match its exclusive execution lease",
                agent.id
            ),
        );
        return false;
    }
    let worktree_path = worktree.path().to_path_buf();
    let mut state_intact = true;

    for validation in &agent.validation_commands {
        let (run_summary, binding_intact) = run_candidate_bound_validation_command(
            validation,
            &worktree_path,
            base_oid,
            expected_state,
            runtime,
            || verify_selected_worktree_binding(manager, agent, summary, worktree),
        );
        #[cfg(test)]
        if !binding_intact {
            notify_candidate_boundary_failure(&agent.id);
        }
        state_intact &= binding_intact;
        if run_summary.status != AgentRunStatus::Succeeded {
            fail_summary(
                summary,
                validation_failure_message("agent validation", &run_summary),
            );
        }
        summary.validation.push(run_summary);
        if summary.status != AgentRunStatus::Succeeded {
            break;
        }
    }
    state_intact
}

fn run_candidate_bound_validation_command(
    validation: &ValidationCommandPlan,
    root: &Path,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
    mut verify_binding: impl FnMut() -> Result<()>,
) -> (ValidationRunSummary, bool) {
    if let Err(error) = verify_binding() {
        return (
            internal_validation_failure(
                validation,
                format!("managed worktree binding is invalid before validation: {error}"),
            ),
            false,
        );
    }
    let mut run_summary = run_validation_command(validation, root, runtime);
    if let Err(error) = verify_binding() {
        append_validation_error(
            &mut run_summary,
            format!("managed worktree binding changed during validation: {error}"),
        );
        return (run_summary, false);
    }
    match capture_consistent_candidate_state(root, base_oid, runtime) {
        Ok(after) => {
            if let Some(drift) = after.drift_from(expected_state) {
                append_validation_error(&mut run_summary, drift);
                return (run_summary, false);
            }
        }
        Err(error) => {
            append_validation_error(
                &mut run_summary,
                format!("failed to verify candidate immutability: {error}"),
            );
            return (run_summary, false);
        }
    }
    if let Err(error) = verify_binding() {
        append_validation_error(
            &mut run_summary,
            format!("managed worktree binding changed after validation capture: {error}"),
        );
        return (run_summary, false);
    }
    (run_summary, true)
}

fn append_validation_error(summary: &mut ValidationRunSummary, message: String) {
    summary.status = AgentRunStatus::Failed;
    summary.error = Some(match summary.error.take() {
        Some(existing) => format!("{existing}; {message}"),
        None => message,
    });
}

fn internal_validation_failure(
    validation: &ValidationCommandPlan,
    message: String,
) -> ValidationRunSummary {
    ValidationRunSummary {
        name: validation.name.clone(),
        command: validation.command.clone(),
        working_directory: validation.working_directory.clone(),
        timeout_seconds: validation.timeout.map(|timeout| timeout.as_secs()),
        status: AgentRunStatus::Failed,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: Some(message),
    }
}

struct RepoValidationOutcome {
    summaries: Vec<ValidationRunSummary>,
    target: Option<RepoValidationTargetBinding>,
}

#[derive(Debug)]
struct CombinedCandidateStats {
    candidate_count: usize,
    patch_count: usize,
    aggregate_patch_bytes: usize,
    changed_paths: Vec<PathBuf>,
}

struct DisposableValidationWorktree<'a> {
    manager: &'a WorktreeManager,
    name: String,
    lease: Option<ManagedWorktreeWriteLease>,
    removed: bool,
}

impl<'a> DisposableValidationWorktree<'a> {
    fn create(manager: &'a WorktreeManager, base_oid: &Oid) -> Result<Self> {
        let sequence = REPO_VALIDATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = normalize_agent_id(&format!("repo-validation-{}-{sequence}", process::id()))?;
        let create_options = WorktreeCreateOptions {
            agent_id: name.clone(),
            branch: None,
            base: Some(base_oid.to_string()),
            worktree_root: None,
        };
        #[cfg(test)]
        manager
            .create_for_test(create_options)
            .context("combined candidate managed worktree creation failed")?;
        #[cfg(not(test))]
        manager
            .create(create_options)
            .context("combined candidate managed worktree creation failed")?;
        let lease = match manager.acquire_write_execution_lease(&name) {
            Ok(lease) => lease,
            Err(error) => {
                let cleanup = manager.remove(&name, true, true);
                return match cleanup {
                    Ok(_) => Err(error)
                        .context("combined candidate exclusive write lease acquisition failed"),
                    Err(_) => bail!(
                        "combined candidate exclusive write lease acquisition and cleanup failed"
                    ),
                };
            }
        };
        let mut guard = Self {
            manager,
            name,
            lease: Some(lease),
            removed: false,
        };
        let verification = (|| -> Result<()> {
            guard.verify_binding()?;
            let repo = crate::git_repository::open(guard.path()?)
                .context("combined candidate managed worktree could not be opened")?;
            let head =
                head_oid(&repo).context("combined candidate worktree HEAD capture failed")?;
            let dirty = collect_status_paths(&repo)
                .context("combined candidate initial cleanliness inspection failed")?;
            if &head != base_oid || !dirty.is_empty() {
                bail!("combined candidate worktree was not clean at the captured run base");
            }
            guard.verify_binding()?;
            Ok(())
        })();
        match verification {
            Ok(()) => Ok(guard),
            Err(error) => {
                let cleanup = guard.cleanup();
                match cleanup {
                    Ok(()) => Err(error),
                    Err(_) => Err(error.context("combined candidate verification cleanup failed")),
                }
            }
        }
    }

    fn path(&self) -> Result<&Path> {
        self.lease
            .as_ref()
            .map(ManagedWorktreeWriteLease::path)
            .context("combined candidate write lease was released too early")
    }

    fn verify_binding(&self) -> Result<()> {
        let lease = self
            .lease
            .as_ref()
            .context("combined candidate write lease was released too early")?;
        let verified = self
            .manager
            .get_managed_verified(&self.name)
            .context("combined candidate managed worktree binding is invalid")?;
        if &verified != lease.record() {
            bail!(
                "combined candidate managed worktree record or Git backlink changed while its write lease was held"
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        self.lease.take();
        self.manager
            .remove(&self.name, true, true)
            .context("combined candidate secure removal failed")?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for DisposableValidationWorktree<'_> {
    fn drop(&mut self) {
        if !self.removed {
            self.lease.take();
            let _ = self.manager.remove(&self.name, true, true);
        }
    }
}

fn run_repo_validation_commands(
    plan: &OrchestrationPlan,
    repo: &Path,
    manager: &WorktreeManager,
    worktrees: &[SelectedWorktree],
    base_oid: &Oid,
    candidates: &[Option<CapturedCandidate>],
    runtime: OrchestrationExecutionRuntime,
) -> RepoValidationOutcome {
    let primary_before = match capture_consistent_candidate_state(repo, base_oid, runtime) {
        Ok(state) => state,
        Err(_) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "primary boundary capture",
                    "could not bind the primary worktree before combined-candidate validation",
                )],
                target: None,
            }
        }
    };
    let stats = match validate_combined_candidate_set(plan, candidates, base_oid) {
        Ok(stats) => stats,
        Err(error) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "combined candidate bounds",
                    &error.to_string(),
                )],
                target: None,
            }
        }
    };
    let mut validation_worktree = match DisposableValidationWorktree::create(manager, base_oid) {
        Ok(worktree) => worktree,
        Err(error) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "combined candidate construction",
                    &error.to_string(),
                )],
                target: None,
            }
        }
    };

    let execution = execute_combined_candidate_validation(
        plan,
        &validation_worktree,
        base_oid,
        candidates,
        &stats,
        runtime,
    );
    let mut outcome = match execution {
        Ok(outcome) => outcome,
        Err(error) => RepoValidationOutcome {
            summaries: vec![internal_repo_validation_failure(
                "combined candidate construction",
                &error.to_string(),
            )],
            target: None,
        },
    };

    if validation_worktree.cleanup().is_err() {
        outcome.summaries.push(internal_repo_validation_failure(
            "combined candidate cleanup",
            "exclusive removal of the disposable validation target failed",
        ));
    }

    match capture_consistent_candidate_state(repo, base_oid, runtime) {
        Ok(after) => {
            if let Some(drift) = after.drift_from(&primary_before) {
                outcome.summaries.push(internal_repo_validation_failure(
                    "primary boundary verification",
                    &format!("primary worktree changed during repo validation: {drift}"),
                ));
            }
        }
        Err(_) => outcome.summaries.push(internal_repo_validation_failure(
            "primary boundary verification",
            "could not verify the primary worktree after repo validation",
        )),
    }
    verify_agent_worktrees_after_repo_validation(
        manager,
        plan,
        worktrees,
        candidates,
        base_oid,
        runtime,
        &mut outcome.summaries,
    );
    outcome
}

fn validate_combined_candidate_set(
    plan: &OrchestrationPlan,
    candidates: &[Option<CapturedCandidate>],
    base_oid: &Oid,
) -> Result<CombinedCandidateStats> {
    if candidates.len() != plan.agents.len() {
        bail!("combined candidate set does not match the orchestration plan");
    }
    if candidates.len() > COMBINED_CANDIDATE_MAX_PATCHES {
        bail!(
            "combined candidate count exceeded the configured {} limit",
            COMBINED_CANDIDATE_MAX_PATCHES
        );
    }
    let mut candidate_count = 0_usize;
    let mut patch_count = 0_usize;
    let mut aggregate_patch_bytes = 0_usize;
    let mut changed_paths = BTreeSet::new();
    for (agent, candidate) in plan.agents.iter().zip(candidates) {
        let candidate = candidate.as_ref().with_context(|| {
            format!("successful agent '{}' has no captured candidate", agent.id)
        })?;
        candidate_count += 1;
        if candidate.binding.version != CANDIDATE_BINDING_VERSION
            || candidate.binding.base_oid != base_oid.to_string()
            || candidate.binding.diff_oid != hash_candidate_component(&candidate.patch)?.to_string()
            || candidate.binding.patch_bytes != candidate.patch.len() as u64
        {
            bail!("candidate binding for agent '{}' drifted", agent.id);
        }
        if !candidate.patch.is_empty() {
            patch_count += 1;
        }
        aggregate_patch_bytes = aggregate_patch_bytes
            .checked_add(candidate.patch.len())
            .context("combined candidate patch bytes overflowed")?;
        if aggregate_patch_bytes >= COMBINED_CANDIDATE_MAX_BYTES {
            bail!(
                "combined candidate reached the configured {} byte aggregate boundary",
                COMBINED_CANDIDATE_MAX_BYTES
            );
        }
        for path in &candidate.binding.changed_paths {
            if !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
            {
                bail!(
                    "candidate for agent '{}' contains unclaimed path '{}'",
                    agent.id,
                    path.display()
                );
            }
            if !changed_paths.insert(path.clone()) {
                bail!(
                    "combined candidate contains duplicate changed path '{}'",
                    path.display()
                );
            }
        }
    }
    if changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "combined candidate changed-path count exceeded the configured {} limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }
    Ok(CombinedCandidateStats {
        candidate_count,
        patch_count,
        aggregate_patch_bytes,
        changed_paths: changed_paths.into_iter().collect(),
    })
}

fn execute_combined_candidate_validation(
    plan: &OrchestrationPlan,
    validation_worktree: &DisposableValidationWorktree<'_>,
    base_oid: &Oid,
    candidates: &[Option<CapturedCandidate>],
    stats: &CombinedCandidateStats,
    runtime: OrchestrationExecutionRuntime,
) -> Result<RepoValidationOutcome> {
    validation_worktree.verify_binding()?;
    let validation_path = validation_worktree.path()?;
    apply_captured_candidate_patches(plan, validation_path, candidates, runtime, || {
        validation_worktree.verify_binding()
    })?;

    validation_worktree.verify_binding()?;
    let combined_state = capture_consistent_candidate_state(validation_path, base_oid, runtime)
        .context("combined candidate binding capture failed")?;
    validation_worktree.verify_binding()?;
    if combined_state.changed_paths != stats.changed_paths {
        bail!("materialized combined candidate paths did not match the captured union");
    }
    let combined = capture_bound_candidate(validation_path, base_oid, &combined_state, runtime)
        .context("materialized combined candidate diff capture failed")?;
    validation_worktree.verify_binding()?;
    let target = repo_validation_target_binding(stats, base_oid, &combined);
    let summaries = run_bound_repo_validation_commands(
        plan,
        validation_worktree,
        base_oid,
        &combined_state,
        runtime,
    );
    Ok(RepoValidationOutcome {
        summaries,
        target: Some(target),
    })
}

fn apply_captured_candidate_patches(
    plan: &OrchestrationPlan,
    validation_path: &Path,
    candidates: &[Option<CapturedCandidate>],
    runtime: OrchestrationExecutionRuntime,
    mut verify_binding: impl FnMut() -> Result<()>,
) -> Result<()> {
    for (agent, candidate) in plan.agents.iter().zip(candidates) {
        let candidate = candidate
            .as_ref()
            .with_context(|| format!("candidate for agent '{}' disappeared", agent.id))?;
        if candidate.patch.is_empty() {
            continue;
        }
        verify_binding()?;
        let output = run_fixed_git_with_stdin(
            validation_path,
            ["apply", "--binary", "--whitespace=nowarn", "-"],
            WorkspaceAccess::ReadWrite,
            StdinMode::Bytes(candidate.patch.clone()),
            runtime,
        )
        .with_context(|| {
            format!(
                "combined candidate patch application failed for agent '{}'",
                agent.id
            )
        })?;
        if !output.status.success() {
            bail!(
                "combined candidate patch conflicted for agent '{}'",
                agent.id
            );
        }
        verify_binding()?;
    }
    Ok(())
}

fn repo_validation_target_binding(
    stats: &CombinedCandidateStats,
    base_oid: &Oid,
    combined: &CapturedCandidate,
) -> RepoValidationTargetBinding {
    RepoValidationTargetBinding {
        version: CANDIDATE_BINDING_VERSION,
        kind: if stats.changed_paths.is_empty() {
            RepoValidationTargetKind::BaseNoChanges
        } else {
            RepoValidationTargetKind::CombinedCandidate
        },
        base_oid: base_oid.to_string(),
        combined_diff_oid: combined.binding.diff_oid.clone(),
        changed_paths: stats.changed_paths.clone(),
        candidate_count: stats.candidate_count,
        patch_count: stats.patch_count,
        aggregate_patch_bytes: stats.aggregate_patch_bytes as u64,
    }
}

fn run_bound_repo_validation_commands(
    plan: &OrchestrationPlan,
    validation_worktree: &DisposableValidationWorktree<'_>,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
) -> Vec<ValidationRunSummary> {
    let mut summaries = Vec::new();
    let validation_path = match validation_worktree.path() {
        Ok(path) => path,
        Err(error) => {
            return vec![internal_repo_validation_failure(
                "combined candidate lease",
                &error.to_string(),
            )]
        }
    };
    for validation in &plan.repo_validation_commands {
        let (mut run_summary, binding_intact) = run_candidate_bound_validation_command(
            validation,
            validation_path,
            base_oid,
            expected_state,
            runtime,
            || validation_worktree.verify_binding(),
        );
        if !binding_intact
            && run_summary
                .error
                .as_deref()
                .is_some_and(|error| error.contains("candidate-relevant state changed"))
        {
            let drift = run_summary.error.take().unwrap_or_default();
            run_summary.error = Some(format!(
                "repo validation mutated the combined candidate: {drift}"
            ));
        }
        let failed = run_summary.status != AgentRunStatus::Succeeded;
        summaries.push(run_summary);
        if failed {
            break;
        }
    }
    summaries
}

fn verify_agent_worktrees_after_repo_validation(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
    worktrees: &[SelectedWorktree],
    candidates: &[Option<CapturedCandidate>],
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
    summaries: &mut Vec<ValidationRunSummary>,
) {
    if worktrees.len() != candidates.len() || worktrees.len() != plan.agents.len() {
        summaries.push(internal_repo_validation_failure(
            "agent candidate verification",
            "agent worktree lease set no longer matches the candidate set",
        ));
        return;
    }
    for ((agent, worktree), candidate) in plan.agents.iter().zip(worktrees).zip(candidates) {
        let Some(candidate) = candidate else {
            continue;
        };
        let verified = manager
            .get_managed_verified(&agent.id)
            .and_then(|record| {
                if &record != worktree.record() {
                    bail!("managed worktree record drifted");
                }
                Ok(())
            })
            .and_then(|()| capture_consistent_candidate_state(worktree.path(), base_oid, runtime))
            .and_then(|state| ensure_candidate_binding_matches_state(&candidate.binding, &state))
            .and_then(|()| {
                let record = manager.get_managed_verified(&agent.id)?;
                if &record != worktree.record() {
                    bail!("managed worktree record drifted after capture");
                }
                Ok(())
            });
        if verified.is_err() {
            summaries.push(internal_repo_validation_failure(
                "agent candidate verification",
                "an agent worktree changed while the combined candidate was validated",
            ));
            break;
        }
    }
}

fn internal_repo_validation_failure(name: &str, message: &str) -> ValidationRunSummary {
    ValidationRunSummary {
        name: Some(name.to_string()),
        command: "maco internal combined-candidate gate".to_string(),
        working_directory: None,
        timeout_seconds: None,
        status: AgentRunStatus::Failed,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: Some(message.to_string()),
    }
}

fn run_validation_command(
    validation: &ValidationCommandPlan,
    root: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> ValidationRunSummary {
    let working_directory = validation
        .working_directory
        .as_ref()
        .map(|path| root.join(path))
        .unwrap_or_else(|| root.to_path_buf());
    let (visible_read_only_roots, hidden_roots) = match orchestration_sandbox_roots(root) {
        Ok((common_dir, state_root)) => (vec![common_dir], vec![state_root]),
        Err(error) => {
            let mut summary = validation_summary_from_result(
                validation,
                Err(ProcessRunError::Spawn {
                    label: "validation state masking".to_string(),
                    command: validation.command.clone(),
                    current_dir: working_directory.clone(),
                    source: std::io::Error::other(error.to_string()),
                }),
            );
            summary.error = Some(format!(
                "failed to bind repository sensitive state before validation: {error:#}"
            ));
            return summary;
        }
    };
    let result = run_agent_command(CommandRunSpec {
        command: validation.command.clone(),
        workspace_root: root.to_path_buf(),
        working_directory,
        env: validation.env.clone(),
        timeout: validation.timeout,
        visible_read_only_roots,
        hidden_roots,
        runtime,
    });
    validation_summary_from_result(validation, result)
}

fn validation_summary_from_result(
    validation: &ValidationCommandPlan,
    result: Result<CommandRunResult, ProcessRunError>,
) -> ValidationRunSummary {
    let mut summary = ValidationRunSummary {
        name: validation.name.clone(),
        command: validation.command.clone(),
        working_directory: validation.working_directory.clone(),
        timeout_seconds: validation.timeout.map(|timeout| timeout.as_secs()),
        status: AgentRunStatus::Pending,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: None,
    };

    match result {
        Ok(result) => {
            summary.exit_code = result.status.and_then(|status| status.code());
            summary.duration_ms = Some(result.duration_ms);
            summary.timed_out = result.timed_out;
            summary.stdout = result.stdout;
            summary.stderr = result.stderr;
            if let Some(error) = result.process_error {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(error);
            } else if result.timed_out {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match summary.timeout_seconds {
                    Some(seconds) => {
                        format!("validation command timed out after {seconds} seconds")
                    }
                    None => "validation command timed out".to_string(),
                });
            } else if result.status.is_some_and(|status| status.success()) {
                summary.status = AgentRunStatus::Succeeded;
            } else {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("validation command exited with status {code}"),
                    None => "validation command terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            summary.status = AgentRunStatus::Failed;
            summary.error = Some(format!("failed to run validation command: {error}"));
        }
    }

    summary
}

fn validation_failure_message(scope: &str, summary: &ValidationRunSummary) -> String {
    let label = summary.name.as_deref().unwrap_or(summary.command.as_str());
    let reason = summary
        .error
        .as_deref()
        .unwrap_or("validation command failed");
    format!("{scope} '{label}' failed: {reason}")
}

#[derive(Debug, Clone)]
struct CommandRunSpec {
    command: String,
    workspace_root: PathBuf,
    working_directory: PathBuf,
    env: BTreeMap<String, String>,
    timeout: Option<Duration>,
    visible_read_only_roots: Vec<PathBuf>,
    hidden_roots: Vec<PathBuf>,
    runtime: OrchestrationExecutionRuntime,
}

fn strict_command_profile(spec: &CommandRunSpec) -> StrictOfflineWorkspaceProfile {
    let profile = spec.visible_read_only_roots.iter().fold(
        StrictOfflineWorkspaceProfile::read_write(&spec.workspace_root),
        |profile, visible| profile.with_visible_read_only_root(visible),
    );
    spec.hidden_roots
        .iter()
        .fold(profile, |profile, hidden| profile.with_hidden_root(hidden))
}

fn run_agent_command(spec: CommandRunSpec) -> Result<CommandRunResult, ProcessRunError> {
    let strict_profile = strict_command_profile(&spec);
    let mut environment = sandbox_environment();
    environment.extend(spec.env);
    let process_spec = ProcessSpec::shell(
        "agent command",
        Shell::for_current_platform(),
        spec.command,
        spec.working_directory,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_timeout(spec.timeout);
    let mut output = run_process(match spec.runtime {
        OrchestrationExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                strict_profile,
            )),
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })?;

    let safety_verified = output.safety_evidence_verified();
    let safety_evidence = (output.process_tree, output.side_effects);
    let mut process_error = output.process_error.take();
    if let Some(stdin_error) = output.stdin_error.take() {
        process_error = Some(match process_error {
            Some(existing) => format!("{existing}; {stdin_error}"),
            None => stdin_error,
        });
    }
    if spec.runtime == OrchestrationExecutionRuntime::Verified && !safety_verified {
        let safety_error = format!(
            "process safety evidence was not verified: process_tree={:?}; side_effects={:?}",
            safety_evidence.0, safety_evidence.1
        );
        process_error = Some(match process_error {
            Some(existing) => format!("{existing}; {safety_error}"),
            None => safety_error,
        });
    }

    Ok(CommandRunResult {
        status: output.status,
        duration_ms: output.duration_ms(),
        timed_out: output.timed_out,
        stdout: summarize_output(&output.stdout),
        stderr: summarize_output(&output.stderr),
        process_error,
    })
}

#[derive(Debug, Clone)]
struct CommandRunResult {
    status: Option<ExitStatus>,
    duration_ms: u64,
    timed_out: bool,
    stdout: OutputSummary,
    stderr: OutputSummary,
    process_error: Option<String>,
}

fn apply_command_result(
    summary: &mut AgentRunSummary,
    result: Result<CommandRunResult, ProcessRunError>,
) {
    match result {
        Ok(result) => {
            summary.exit_code = result.status.and_then(|status| status.code());
            summary.duration_ms = Some(result.duration_ms);
            summary.timed_out = result.timed_out;
            summary.stdout = result.stdout;
            summary.stderr = result.stderr;
            if let Some(error) = result.process_error {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(error);
            } else if result.timed_out {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match summary.timeout_seconds {
                    Some(seconds) => format!("command timed out after {seconds} seconds"),
                    None => "command timed out".to_string(),
                });
            } else if result.status.is_some_and(|status| status.success()) {
                summary.status = AgentRunStatus::Succeeded;
                summary.error = None;
            } else {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("command exited with status {code}"),
                    None => "command terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            summary.status = AgentRunStatus::Failed;
            summary.error = Some(format!("failed to run command: {error}"));
        }
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

fn summarize_output(output: &CapturedBytes) -> OutputSummary {
    let summary = output.summarize_chars(OUTPUT_CHAR_LIMIT);
    OutputSummary {
        text: summary.text,
        truncated: summary.truncated,
    }
}

fn sandbox_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ])
}

struct CheckpointView<'a> {
    repo: &'a Path,
    repo_head: &'a Oid,
    plan_file: &'a Path,
    plan: &'a OrchestrationPlan,
    keep_claims: bool,
    worktree_reuse_policy: WorktreeReusePolicy,
    success: bool,
    agents: &'a [AgentRunSummary],
    repo_validation: &'a [ValidationRunSummary],
    repo_validation_target: Option<&'a RepoValidationTargetBinding>,
    released_claims: &'a [PathClaim],
    release_errors: &'a [String],
    released_semantic_intents: &'a [SemanticIntent],
    semantic_release_errors: &'a [String],
}

struct RunCheckpointWriter {
    slot: ReservedOutputFile,
    reference: AuthenticatedCheckpointReference,
    journal: StateJournal,
}

struct CheckpointReferenceReservation {
    slot: Option<ReservedOutputFile>,
}

impl CheckpointReferenceReservation {
    fn new(slot: ReservedOutputFile) -> Self {
        Self { slot: Some(slot) }
    }

    fn slot_mut(&mut self) -> Result<&mut ReservedOutputFile> {
        self.slot
            .as_mut()
            .context("checkpoint reference reservation was consumed")
    }

    fn take(&mut self) -> Result<ReservedOutputFile> {
        self.slot
            .take()
            .context("checkpoint reference reservation was consumed")
    }

    fn cleanup(&mut self) -> Result<()> {
        match self.slot.take() {
            Some(slot) => slot.remove(),
            None => Ok(()),
        }
    }
}

impl Drop for CheckpointReferenceReservation {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl RunCheckpointWriter {
    fn write(&mut self, checkpoint: &RunCheckpoint) -> Result<()> {
        self.verify_external_reference()?;
        let phase = if checkpoint.stage == RunCheckpointStage::Final {
            PHASE_FINAL.to_string()
        } else {
            format!(
                "{CHECKPOINT_SNAPSHOT_PHASE_PREFIX}{}",
                checkpoint_stage_name(checkpoint.stage)
            )
        };
        self.journal
            .append(&phase, None, &encode_run_checkpoint(checkpoint)?)?;
        self.verify_external_reference()
    }

    fn agent_event(&mut self, phase: &str, subject: &str, agent: &AgentCheckpoint) -> Result<()> {
        self.event(phase, Some(subject), &encode_agent_checkpoint(agent)?)
    }

    fn event<T: Serialize>(
        &mut self,
        phase: &str,
        subject: Option<&str>,
        payload: &T,
    ) -> Result<()> {
        #[cfg(test)]
        if take_checkpoint_event_failure(&self.reference.journal.run_id, phase) {
            bail!("injected checkpoint event failure at phase '{phase}'");
        }
        self.verify_external_reference()?;
        self.journal.append(phase, subject, payload)?;
        #[cfg(test)]
        if take_checkpoint_event_failure(&self.reference.journal.run_id, &format!("after:{phase}"))
        {
            bail!("injected post-append checkpoint failure at phase '{phase}'");
        }
        self.verify_external_reference()
    }

    fn verify_external_reference(&self) -> Result<()> {
        let contents = self.slot.read_bounded(CHECKPOINT_REFERENCE_MAX_BYTES)?;
        let observed: AuthenticatedCheckpointReference = serde_json::from_slice(&contents)
            .with_context(|| {
                format!(
                    "failed to re-read authenticated checkpoint reference {}",
                    self.slot.path().display()
                )
            })?;
        if observed != self.reference {
            bail!("external checkpoint reference changed during the active run");
        }
        verify_checkpoint_reference(self.journal.authenticator(), &observed)
    }

    fn reject_inside_worktrees(&self, worktrees: &[SelectedWorktree]) -> Result<()> {
        let checkpoint_root = self
            .slot
            .path()
            .parent()
            .context("checkpoint reference has no parent directory")?
            .canonicalize()
            .context("failed to canonicalize checkpoint reference root")?;
        for worktree in worktrees {
            let worktree_root = worktree.path().canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize selected worktree {}",
                    worktree.path().display()
                )
            })?;
            if checkpoint_root.starts_with(&worktree_root) {
                bail!(
                    "checkpoint reference root {} must not be inside untrusted worktree {}",
                    checkpoint_root.display(),
                    worktree_root.display()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn install_checkpoint_event_failure(run_id: &str, phase: &str) {
    let hook = CHECKPOINT_EVENT_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut hooks = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        !hooks
            .iter()
            .any(|hook| hook.run_id == run_id && hook.phase == phase),
        "checkpoint event failure hook already installed"
    );
    hooks.push(CheckpointEventFailureHook {
        run_id: run_id.to_string(),
        phase: phase.to_string(),
    });
}

#[cfg(test)]
fn take_checkpoint_event_failure(run_id: &str, phase: &str) -> bool {
    let hook = CHECKPOINT_EVENT_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut hooks = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(position) = hooks
        .iter()
        .position(|hook| hook.run_id == run_id && hook.phase == phase)
    {
        hooks.remove(position);
        true
    } else {
        false
    }
}

fn prepare_run_checkpoint_writer(
    controls: &OrchestrationRunControls,
    run_id: &Option<RunId>,
    repo: &Path,
    summaries: &[AgentRunSummary],
) -> Result<Option<RunCheckpointWriter>> {
    let Some(directory) = controls.checkpoint_dir.as_deref() else {
        return Ok(None);
    };
    let run_id = run_id
        .as_ref()
        .context("checkpoint directory requires a resolved run id")?;
    let root = SecureOutputRoot::open_or_create(directory)?;
    for summary in summaries {
        if let Some(worktree) = &summary.worktree {
            root.reject_inside(&worktree.path)?;
        }
    }
    let name = checkpoint_file_name(run_id);
    let slot = root.reserve(OsStr::new(&name)).with_context(|| {
        format!(
            "checkpoint '{}' already exists or cannot be reserved for a fresh run; use `maco orchestrate resume --checkpoint {}` for an existing run",
            run_id.as_str(),
            root.path().join(&name).display()
        )
    })?;
    let mut reservation = CheckpointReferenceReservation::new(slot);
    let result = (|| -> Result<RunCheckpointWriter> {
        let auth = repository_auth_writer(repo)?.into_authenticator()?;
        let journal = StateJournal::create(auth, run_id.as_str())?;
        let reference =
            signed_checkpoint_reference(journal.authenticator(), repo, journal.identity())?;
        let reference_path = reservation
            .slot
            .as_ref()
            .map(|slot| slot.path().to_path_buf())
            .context("checkpoint reference reservation was consumed")?;
        reservation
            .slot_mut()?
            .write_json_atomic(&reference, CHECKPOINT_REFERENCE_MAX_BYTES)
            .with_context(|| {
                format!(
                    "failed to write authenticated checkpoint reference {}",
                    reference_path.display()
                )
            })?;
        let slot = reservation.take()?;
        let writer = RunCheckpointWriter {
            slot,
            reference,
            journal,
        };
        writer.verify_external_reference()?;
        Ok(writer)
    })();
    match result {
        Ok(writer) => Ok(Some(writer)),
        Err(error) => match reservation.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean checkpoint reference reservation: {cleanup:#}"
            ))),
        },
    }
}

pub fn write_run_checkpoint(directory: &Path, checkpoint: &RunCheckpoint) -> Result<PathBuf> {
    if checkpoint.version != CHECKPOINT_STATE_VERSION {
        bail!(
            "checkpoint version {} is not writable; create a new v{} run",
            checkpoint.version,
            CHECKPOINT_STATE_VERSION
        );
    }
    let controls = OrchestrationRunControls {
        run_id: Some(checkpoint.run_id.clone()),
        checkpoint_dir: Some(directory.to_path_buf()),
        worktree_reuse_policy: Some(checkpoint.worktree_reuse_policy),
        semantic_coordination: checkpoint.semantic_coordination,
    };
    let mut writer = prepare_run_checkpoint_writer(
        &controls,
        &Some(checkpoint.run_id.clone()),
        &checkpoint.repo,
        &[],
    )?
    .context("checkpoint writer was not prepared")?;
    writer.write(checkpoint)?;
    Ok(writer.slot.path().to_path_buf())
}

pub fn read_run_checkpoint(path: &Path) -> Result<RunCheckpoint> {
    let opened = open_run_checkpoint(path, None)?;
    Ok(opened.checkpoint)
}

struct OpenedRunCheckpoint {
    checkpoint: RunCheckpoint,
    repo: PathBuf,
    writer: RunCheckpointWriter,
}

fn open_run_checkpoint(path: &Path, repo_override: Option<&Path>) -> Result<OpenedRunCheckpoint> {
    let parent = path
        .parent()
        .with_context(|| format!("checkpoint must have a parent: {}", path.display()))?;
    let name = path
        .file_name()
        .with_context(|| format!("checkpoint must have a file name: {}", path.display()))?;
    let root = SecureOutputRoot::open_private(parent)?;
    let slot = root.open_existing_leaf(name)?;
    let contents = slot.read_bounded(CHECKPOINT_REFERENCE_MAX_BYTES)?;
    let value: serde_json::Value = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse checkpoint envelope {}", path.display()))?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(CHECKPOINT_STATE_VERSION)) {
        let observed = version
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_string());
        bail!(
            "checkpoint version {} in {} is unauthenticated or unsupported; start a new run using v{}",
            observed,
            path.display(),
            CHECKPOINT_STATE_VERSION
        );
    }
    let reference: AuthenticatedCheckpointReference = serde_json::from_value(value)
        .with_context(|| format!("invalid v3 checkpoint envelope {}", path.display()))?;
    validate_checkpoint_reference_bounds(&reference)?;

    // The repository hint is used only to locate a candidate key. No run id,
    // plan path, journal path, or checkpoint payload is authoritative yet.
    let hinted_repo = reference.repository_hint.to_path_buf()?;
    let repo = discover_repo_root(repo_override.unwrap_or(&hinted_repo))?;
    let authenticator = repository_authenticator_key_only(&repo)?;
    verify_checkpoint_reference(&authenticator, &reference)?;
    validate_repository_authenticated_state(&repo, &authenticator)?;
    let journal = StateJournal::open(authenticator, &reference.journal)?;
    let checkpoint = latest_authenticated_checkpoint(&journal)?;
    if checkpoint.run_id.as_str() != reference.journal.run_id {
        bail!("authenticated checkpoint snapshot run id does not match its journal");
    }
    let expected_path = checkpoint_path(parent, &checkpoint.run_id);
    if expected_path != path {
        bail!(
            "authenticated checkpoint file {} does not match run id '{}'; expected {}",
            path.display(),
            checkpoint.run_id.as_str(),
            expected_path.display()
        );
    }
    let signed_repo = discover_repo_root(&hinted_repo)?;
    if signed_repo != repo || checkpoint.repo != repo {
        bail!("authenticated checkpoint belongs to a different repository path");
    }
    let writer = RunCheckpointWriter {
        slot,
        reference,
        journal,
    };
    writer.verify_external_reference()?;
    Ok(OpenedRunCheckpoint {
        checkpoint,
        repo,
        writer,
    })
}

fn signed_checkpoint_reference(
    authenticator: &RepositoryAuthenticator,
    repo: &Path,
    journal: &JournalIdentity,
) -> Result<AuthenticatedCheckpointReference> {
    let repository_hint = LosslessPath::from_path(&discover_repo_root(repo)?)?;
    let mut reference = AuthenticatedCheckpointReference {
        version: CHECKPOINT_STATE_VERSION,
        repository_hint,
        journal: journal.clone(),
        mac: AuthenticationTag::zero(),
    };
    validate_checkpoint_reference_bounds(&reference)?;
    reference.mac = authenticator.sign(
        CHECKPOINT_REFERENCE_DOMAIN,
        &checkpoint_reference_mac_payload(&reference)?,
    )?;
    Ok(reference)
}

fn verify_checkpoint_reference(
    authenticator: &RepositoryAuthenticator,
    reference: &AuthenticatedCheckpointReference,
) -> Result<()> {
    validate_checkpoint_reference_bounds(reference)?;
    authenticator.verify_repository_binding(&reference.journal.repository)?;
    authenticator.verify_tag(
        CHECKPOINT_REFERENCE_DOMAIN,
        &checkpoint_reference_mac_payload(reference)?,
        &reference.mac,
    )
}

fn checkpoint_reference_mac_payload(
    reference: &AuthenticatedCheckpointReference,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&CheckpointReferenceMacPayload {
        version: reference.version,
        repository_hint: &reference.repository_hint,
        journal: &reference.journal,
    })
    .context("failed to encode checkpoint reference MAC payload")
}

fn validate_checkpoint_reference_bounds(
    reference: &AuthenticatedCheckpointReference,
) -> Result<()> {
    if reference.version != CHECKPOINT_STATE_VERSION {
        bail!("checkpoint reference exceeds its bounded canonical format");
    }
    let repository_hint = reference.repository_hint.to_path_buf()?;
    if reference.repository_hint.storage_bytes() > 4096
        || repository_hint.components().count() > 256
    {
        bail!("checkpoint reference exceeds its bounded canonical format");
    }
    reference.mac.validate()?;
    crate::state_journal::validate_journal_identity(&reference.journal)
}

fn latest_authenticated_checkpoint(journal: &StateJournal) -> Result<RunCheckpoint> {
    validate_command_phase_history(journal)?;
    let (snapshot_index, record) = journal
        .records()
        .iter()
        .enumerate()
        .rev()
        .find(|(_, record)| {
            record.phase == PHASE_FINAL
                || record.phase.starts_with(CHECKPOINT_SNAPSHOT_PHASE_PREFIX)
        })
        .context("authenticated checkpoint journal has no resumable snapshot; start a new run")?;
    let mut checkpoint = decode_run_checkpoint(record.payload.clone())
        .context("authenticated checkpoint snapshot is malformed")?;
    if checkpoint.version != CHECKPOINT_STATE_VERSION {
        bail!("authenticated checkpoint snapshot is not v3; start a new run");
    }
    for record in &journal.records()[snapshot_index.saturating_add(1)..] {
        if !matches!(
            record.phase.as_str(),
            PHASE_COMMAND_COMPLETED | PHASE_CANDIDATE_CAPTURED
        ) {
            continue;
        }
        let agent = decode_agent_checkpoint(record.payload.clone())
            .context("authenticated candidate checkpoint payload is malformed")?;
        let slot = checkpoint
            .agents
            .iter_mut()
            .find(|candidate| candidate.id == agent.id)
            .with_context(|| {
                format!(
                    "authenticated candidate event references unknown agent '{}'",
                    agent.id
                )
            })?;
        *slot = agent;
    }
    Ok(checkpoint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandJournalState {
    Started,
    Completed,
    CandidateCaptured,
}

fn validate_command_phase_history(journal: &StateJournal) -> Result<()> {
    let mut states = BTreeMap::<String, CommandJournalState>::new();
    for record in journal.records() {
        let Some(subject) = record.subject.as_ref() else {
            continue;
        };
        match record.phase.as_str() {
            PHASE_COMMAND_STARTED => {
                if states.contains_key(subject) {
                    bail!(
                        "checkpoint records a second command start for agent '{}'; refusing possible double execution",
                        subject
                    );
                }
                states.insert(subject.clone(), CommandJournalState::Started);
            }
            PHASE_COMMAND_COMPLETED => {
                if states.get(subject) != Some(&CommandJournalState::Started) {
                    bail!(
                        "checkpoint command completion for agent '{}' has no unique preceding start",
                        subject
                    );
                }
                let completed = decode_agent_checkpoint(record.payload.clone())
                    .context("authenticated command completion payload is malformed")?;
                if completed.id != *subject || completed.command_completed_binding.is_none() {
                    bail!(
                        "checkpoint command completion for agent '{}' lacks exact worktree state binding evidence",
                        subject
                    );
                }
                states.insert(subject.clone(), CommandJournalState::Completed);
            }
            PHASE_CANDIDATE_CAPTURED => match states.get(subject) {
                Some(CommandJournalState::Completed)
                | Some(CommandJournalState::CandidateCaptured) => {
                    states.insert(subject.clone(), CommandJournalState::CandidateCaptured);
                }
                None => {
                    // A completed candidate may be recaptured and revalidated during resume.
                }
                Some(CommandJournalState::Started) => {
                    bail!(
                        "checkpoint candidate for agent '{}' was captured without a completed command",
                        subject
                    );
                }
            },
            _ => {}
        }
    }
    for (agent, state) in states {
        match state {
            CommandJournalState::Started => bail!(
                "checkpoint shows command_started for agent '{}' without durable completion; execution outcome is uncertain and will not be rerun automatically, start a new run",
                agent
            ),
            CommandJournalState::Completed => {}
            CommandJournalState::CandidateCaptured => {}
        }
    }
    Ok(())
}

fn checkpoint_stage_name(stage: RunCheckpointStage) -> &'static str {
    match stage {
        RunCheckpointStage::WorktreesSelected => "worktrees_selected",
        RunCheckpointStage::ClaimsAcquired => "claims_acquired",
        RunCheckpointStage::AgentsCompleted => "agents_completed",
        RunCheckpointStage::Final => PHASE_FINAL,
    }
}

pub fn checkpoint_path(directory: &Path, run_id: &RunId) -> PathBuf {
    directory.join(checkpoint_file_name(run_id))
}

fn checkpoint_file_name(run_id: &RunId) -> String {
    format!("{}.json", run_id.as_str())
}

fn write_checkpoint_if_configured(
    controls: &OrchestrationRunControls,
    stage: RunCheckpointStage,
    run_id: &Option<RunId>,
    writer: Option<&mut RunCheckpointWriter>,
    view: CheckpointView<'_>,
) -> Result<()> {
    if controls.checkpoint_dir.is_none() {
        return Ok(());
    }
    let Some(run_id) = run_id.clone() else {
        return Ok(());
    };
    let writer = writer.context("checkpoint controls omitted a prepared secure writer")?;

    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id,
        stage,
        repo: view.repo.to_path_buf(),
        repo_head: Some(view.repo_head.to_string()),
        plan_file: view.plan_file.to_path_buf(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(view.plan)),
        keep_claims: view.keep_claims,
        worktree_reuse_policy: view.worktree_reuse_policy,
        semantic_coordination: controls.semantic_coordination,
        success: view.success,
        agents: view.agents.iter().map(AgentCheckpoint::from).collect(),
        repo_validation: view.repo_validation.to_vec(),
        repo_validation_target: view.repo_validation_target.cloned(),
        released_claims: view.released_claims.to_vec(),
        release_errors: view.release_errors.to_vec(),
        released_semantic_intents: view.released_semantic_intents.to_vec(),
        semantic_release_errors: view.semantic_release_errors.to_vec(),
        updated_unix_ms: unix_time_millis(),
    };
    writer.write(&checkpoint)
}

impl From<&AgentRunSummary> for AgentCheckpoint {
    fn from(summary: &AgentRunSummary) -> Self {
        Self {
            id: summary.id.clone(),
            status: summary.status,
            worktree: summary
                .worktree
                .as_ref()
                .map(CheckpointWorktreeRecord::from),
            claim: summary.claim.clone(),
            semantic_intent: summary.semantic_intent.clone(),
            semantic_conflicts: summary.semantic_conflicts.clone(),
            changed_paths: summary.changed_paths.clone(),
            unclaimed_changed_paths: summary.unclaimed_changed_paths.clone(),
            validation: summary.validation.clone(),
            candidate_binding: summary.candidate_binding.clone(),
            command_completed_binding: summary.command_completed_binding.clone(),
            error: summary.error.clone(),
        }
    }
}

impl From<&WorktreeRecord> for CheckpointWorktreeRecord {
    fn from(record: &WorktreeRecord) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            branch: record.branch.clone(),
        }
    }
}

impl From<&CheckpointWorktreeRecord> for WorktreeRecord {
    fn from(record: &CheckpointWorktreeRecord) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            branch: record.branch.clone(),
        }
    }
}

fn resolve_run_id(controls: &OrchestrationRunControls) -> Result<Option<RunId>> {
    match (&controls.run_id, &controls.checkpoint_dir) {
        (Some(run_id), _) => Ok(Some(run_id.clone())),
        (None, Some(_)) => generated_run_id().map(Some),
        (None, None) => Ok(None),
    }
}

fn generated_run_id() -> Result<RunId> {
    RunId::new(format!("run-{}-{}", unix_time_millis(), process::id()))
}

fn unix_time_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_millis(duration),
        Err(_) => 0,
    }
}

struct ClaimCleanupGuard {
    store: SyncStore,
    tokens: Vec<ClaimToken>,
    armed: bool,
    early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl ClaimCleanupGuard {
    fn new(store: SyncStore, early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self {
            store,
            tokens: Vec::new(),
            armed: true,
            early_errors,
        }
    }

    fn track(&mut self, token: ClaimToken) {
        self.tokens.push(token);
    }

    fn set_tokens(&mut self, tokens: Vec<ClaimToken>) {
        self.tokens = tokens;
    }

    fn release(&mut self) -> (Vec<PathClaim>, Vec<String>) {
        self.armed = false;
        release_claims(&self.store, std::mem::take(&mut self.tokens))
    }

    fn disarm_keep(&mut self) {
        self.armed = false;
        self.tokens.clear();
    }
}

impl Drop for ClaimCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (_, errors) = release_claims(&self.store, std::mem::take(&mut self.tokens));
        if !errors.is_empty() {
            let mut retained = self
                .early_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            retained.extend(errors);
        }
    }
}

struct SemanticCleanupGuard {
    store: SemanticIntentStore,
    tokens: Vec<SemanticIntentToken>,
    armed: bool,
    early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl SemanticCleanupGuard {
    fn new(
        store: SemanticIntentStore,
        early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            store,
            tokens: Vec::new(),
            armed: true,
            early_errors,
        }
    }

    fn tokens_mut(&mut self) -> &mut Vec<SemanticIntentToken> {
        &mut self.tokens
    }

    fn set_tokens(&mut self, tokens: Vec<SemanticIntentToken>) {
        self.tokens = tokens;
    }

    fn release(&mut self) -> (Vec<SemanticIntent>, Vec<String>) {
        self.armed = false;
        release_semantic_intents(&self.store, std::mem::take(&mut self.tokens))
    }

    fn disarm_keep(&mut self) {
        self.armed = false;
        self.tokens.clear();
    }
}

impl Drop for SemanticCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (_, errors) = release_semantic_intents(&self.store, std::mem::take(&mut self.tokens));
        if !errors.is_empty() {
            let mut retained = self
                .early_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            retained.extend(errors);
        }
    }
}

fn finish_with_early_cleanup<T>(
    result: Result<T>,
    errors: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> Result<T> {
    let retained = errors
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match (result, retained.is_empty()) {
        (Ok(value), true) => Ok(value),
        (Ok(_), false) => bail!(
            "early orchestration cleanup failed: {}",
            retained.join("; ")
        ),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(error.context(format!(
            "early orchestration cleanup also failed: {}",
            retained.join("; ")
        ))),
    }
}

fn release_claims(store: &SyncStore, tokens: Vec<ClaimToken>) -> (Vec<PathClaim>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();

    for token in tokens {
        match store.release(token) {
            Ok(claim) => released.push(claim),
            Err(error) => errors.push(format!("failed to release claim {}: {error}", token.get())),
        }
    }

    (released, errors)
}

fn release_semantic_intents(
    store: &SemanticIntentStore,
    tokens: Vec<SemanticIntentToken>,
) -> (Vec<SemanticIntent>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();

    for token in tokens {
        match store.release(token) {
            Ok(intent) => released.push(intent),
            Err(error) => errors.push(format!(
                "failed to release semantic intent {}: {error}",
                token.get()
            )),
        }
    }

    (released, errors)
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("orchestration requires a non-bare repository")
}

fn current_head_oid(repo_path: &Path) -> Result<Oid> {
    let repo = crate::git_repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    head_oid(&repo)
}

fn head_oid(repo: &Repository) -> Result<Oid> {
    let head = repo
        .head()
        .context("repository has no committed HEAD; create an initial commit first")?;
    let commit = head
        .peel_to_commit()
        .context("failed to peel HEAD to a commit")?;
    Ok(commit.id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_coord::{
        SemanticConflictKind, SemanticConflictSeverity, SemanticIntentRequest, SemanticIntentStore,
    };
    use crate::sync_store::SyncStore;
    use crate::worktree::WorktreeManager;
    use git2::{Oid, Repository, Signature};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn collect_status_paths_fails_closed_on_non_utf8_path() -> Result<()> {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = tempfile::tempdir()?;
        let repository = Repository::init(temp.path())?;
        fs::write(
            temp.path()
                .join(OsString::from_vec(vec![b'n', b'o', b'n', 0xff])),
            b"untracked",
        )?;

        let error = collect_status_paths(&repository).expect_err("non-UTF-8 status must fail");
        assert!(error
            .to_string()
            .contains("git status path is not valid UTF-8"));
        Ok(())
    }

    fn run_plan_file(options: OrchestrationRunOptions) -> Result<OrchestrationSummary> {
        super::run_plan_file_simulation(options)
    }

    fn run_plan_file_with_controls(
        options: OrchestrationRunOptions,
        controls: OrchestrationRunControls,
    ) -> Result<OrchestrationSummary> {
        super::run_plan_file_with_controls_simulation(options, controls)
    }

    fn resume_plan_file(options: OrchestrationResumeOptions) -> Result<OrchestrationSummary> {
        super::resume_plan_file_simulation(options)
    }

    fn test_candidate_binding(worktree_path: &Path, base_oid: Oid) -> AgentCandidateBinding {
        let state = capture_consistent_candidate_state(
            worktree_path,
            &base_oid,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture test candidate state");
        capture_bound_candidate(
            worktree_path,
            &base_oid,
            &state,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture test candidate")
        .binding
    }

    fn schedule_test_agent(id: &str, depends_on: &[&str]) -> AgentPlan {
        AgentPlan {
            id: id.to_string(),
            paths: vec![PathBuf::from(format!("{id}.txt"))],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            env: BTreeMap::new(),
            timeout: None,
            command: "true".to_string(),
            depends_on: depends_on.iter().map(|value| value.to_string()).collect(),
            working_directory: None,
            validation_commands: Vec::new(),
        }
    }

    fn schedule_test_plan(agents: Vec<AgentPlan>) -> OrchestrationPlan {
        OrchestrationPlan {
            agents,
            repo_validation_commands: Vec::new(),
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
        }
    }

    fn run_candidate_validation_test(command: &str) -> ValidationRunSummary {
        run_candidate_validation_test_with_setup(command, |_| {})
    }

    fn run_candidate_validation_test_with_setup(
        command: &str,
        setup: impl FnOnce(&Path),
    ) -> ValidationRunSummary {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        SyncStore::open(&repo_path).expect("create sensitive state root");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("claimed.txt"), "base\n").expect("write claimed");
        fs::write(repo_path.join("other.txt"), "base\n").expect("write other");
        let base_oid = commit_all(&repo, "initial commit").expect("commit");
        fs::write(repo_path.join("claimed.txt"), "candidate\n").expect("write candidate");
        setup(&repo_path);
        let expected = capture_consistent_candidate_state(
            &repo_path,
            &base_oid,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture expected candidate");
        let validation = ValidationCommandPlan {
            name: Some("binding check".to_string()),
            command: command.to_string(),
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(5)),
            working_directory: None,
        };
        run_candidate_bound_validation_command(
            &validation,
            &repo_path,
            &base_oid,
            &expected,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
            || Ok(()),
        )
        .0
    }

    fn clone_candidate(
        source: &Path,
        destination: &Path,
        base_oid: Oid,
        relative_path: Option<&str>,
        contents: &str,
    ) -> CapturedCandidate {
        Repository::clone(source.to_str().expect("source path utf8"), destination)
            .expect("clone candidate");
        if let Some(relative_path) = relative_path {
            fs::write(destination.join(relative_path), contents).expect("write candidate change");
        }
        let state = capture_consistent_candidate_state(
            destination,
            &base_oid,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture cloned candidate state");
        capture_bound_candidate(
            destination,
            &base_oid,
            &state,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture cloned candidate")
    }

    #[cfg(unix)]
    fn wait_for_test_marker(path: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn load_plan_normalizes_agent_ids_and_paths() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {
                  "id": " agent-a ",
                  "paths": ["src/../README.md", "src"],
                  "command": " echo ok "
                }
              ]
            }"#,
        )
        .expect("write plan");

        let plan = load_plan(&plan_path).expect("load plan");

        assert_eq!(plan.agents[0].id, "agent-a");
        assert_eq!(
            plan.agents[0].paths,
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );
        assert_eq!(plan.agents[0].command, "echo ok");
    }

    #[test]
    fn load_plan_rejects_agent_count_before_candidate_worktree_creation() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        let agents = (0..=COMBINED_CANDIDATE_MAX_PATCHES)
            .map(|index| {
                serde_json::json!({
                    "id": format!("agent-{index}"),
                    "paths": [format!("file-{index}.txt")],
                    "command": "true"
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            &plan_path,
            serde_json::to_vec(&serde_json::json!({"agents": agents})).expect("encode plan"),
        )
        .expect("write plan");

        let error = load_plan(&plan_path).expect_err("oversized plan must fail at load");
        assert!(error.to_string().contains("256 agent limit"));
    }

    #[test]
    fn load_plan_bounds_validation_commands_and_dependency_edges() {
        let temp = TempDir::new().expect("tempdir");
        let validation_plan = temp.path().join("validation-plan.json");
        let validations = (0..=PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE)
            .map(|_| serde_json::Value::String("true".to_string()))
            .collect::<Vec<_>>();
        fs::write(
            &validation_plan,
            serde_json::to_vec(&serde_json::json!({
                "repo_validation_commands": validations,
                "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true"}]
            }))
            .expect("encode validation plan"),
        )
        .expect("write validation plan");
        assert!(load_plan(&validation_plan)
            .expect_err("validation count must be bounded")
            .to_string()
            .contains("128 command limit"));

        let dependency_plan = temp.path().join("dependency-plan.json");
        let agents = (0..100)
            .map(|index| {
                let dependencies = (0..index)
                    .map(|dependency| format!("agent-{dependency}"))
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "id": format!("agent-{index}"),
                    "paths": [format!("file-{index}.txt")],
                    "command": "true",
                    "depends_on": dependencies
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            &dependency_plan,
            serde_json::to_vec(&serde_json::json!({"agents": agents}))
                .expect("encode dependency plan"),
        )
        .expect("write dependency plan");
        assert!(load_plan(&dependency_plan)
            .expect_err("dependency edge count must be bounded")
            .to_string()
            .contains("4096 dependency-edge limit"));
    }

    #[cfg(unix)]
    #[test]
    fn load_plan_refuses_symlink_leaf_and_ancestor_components() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("create real directory");
        let plan = real.join("plan.json");
        fs::write(
            &plan,
            r#"{"agents":[{"id":"agent-a","paths":["a.txt"],"command":"true"}]}"#,
        )
        .expect("write plan");
        let leaf_link = temp.path().join("plan-link.json");
        symlink(&plan, &leaf_link).expect("link plan leaf");
        let leaf_error = load_plan(&leaf_link).expect_err("plan leaf symlink must fail");
        assert!(format!("{leaf_error:#}").contains("without following links"));

        let ancestor_link = temp.path().join("linked-directory");
        symlink(&real, &ancestor_link).expect("link plan ancestor");
        let ancestor_error = load_plan(ancestor_link.join("plan.json"))
            .expect_err("plan ancestor symlink must fail");
        assert!(format!("{ancestor_error:#}").contains("without following links"));
    }

    #[test]
    fn load_plan_bounds_file_env_and_timeout_before_execution() {
        let temp = TempDir::new().expect("tempdir");
        let oversized = temp.path().join("oversized.json");
        fs::write(&oversized, vec![b' '; PLAN_MAX_BYTES + 1]).expect("write oversized plan");
        let oversized_error =
            load_plan(&oversized).expect_err("oversized plan must fail bounded read");
        assert!(format!("{oversized_error:#}").contains("bounded read limit"));

        let env_plan = temp.path().join("env.json");
        let env = (0..=PLAN_MAX_ENV_ENTRIES_PER_SCOPE)
            .map(|index| (format!("KEY_{index}"), "value".to_string()))
            .collect::<BTreeMap<_, _>>();
        fs::write(
            &env_plan,
            serde_json::to_vec(&serde_json::json!({
                "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true", "env": env}]
            }))
            .expect("encode env plan"),
        )
        .expect("write env plan");
        assert!(load_plan(&env_plan)
            .expect_err("nested env count must be bounded")
            .to_string()
            .contains("environment scope"));

        let timeout_plan = temp.path().join("timeout.json");
        fs::write(
            &timeout_plan,
            serde_json::to_vec(&serde_json::json!({
                "default_timeout_seconds": PLAN_MAX_TIMEOUT_SECONDS + 1,
                "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true"}]
            }))
            .expect("encode timeout plan"),
        )
        .expect("write timeout plan");
        assert!(load_plan(&timeout_plan)
            .expect_err("timeout upper bound must be enforced")
            .to_string()
            .contains("must be between 1"));
    }

    #[test]
    fn scheduler_failure_propagation_preserves_independent_fork_and_join_branch() {
        let plan = schedule_test_plan(vec![
            schedule_test_agent("root-fail", &[]),
            schedule_test_agent("failed-child", &["root-fail"]),
            schedule_test_agent("root-ok", &[]),
            schedule_test_agent("ok-child", &["root-ok"]),
            schedule_test_agent("join", &["failed-child", "ok-child"]),
        ]);
        let mut summaries = plan
            .agents
            .iter()
            .map(AgentRunSummary::pending)
            .collect::<Vec<_>>();
        let mut remaining = (0..summaries.len()).collect::<BTreeSet<_>>();

        assert_eq!(
            ready_agent_indices(&plan, &summaries, &remaining, 2),
            vec![0, 2]
        );
        summaries[0].status = AgentRunStatus::Failed;
        summaries[2].status = AgentRunStatus::Succeeded;
        remaining.remove(&0);
        remaining.remove(&2);
        propagate_dependency_failures(&plan, &mut summaries, &mut remaining);

        assert_eq!(summaries[1].status, AgentRunStatus::Skipped);
        assert_eq!(summaries[4].status, AgentRunStatus::Skipped);
        assert_eq!(summaries[3].status, AgentRunStatus::Pending);
        assert_eq!(
            ready_agent_indices(&plan, &summaries, &remaining, 2),
            vec![3]
        );
        assert!(summaries[1]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("'root-fail' (failed)")));
        assert!(summaries[4]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("'failed-child' (skipped)")));
    }

    #[test]
    fn scheduler_reports_all_same_wave_failed_dependencies_deterministically() {
        let plan = schedule_test_plan(vec![
            schedule_test_agent("fail-a", &[]),
            schedule_test_agent("fail-b", &[]),
            schedule_test_agent("dependent", &["fail-a", "fail-b"]),
            schedule_test_agent("independent", &[]),
        ]);
        let mut summaries = plan
            .agents
            .iter()
            .map(AgentRunSummary::pending)
            .collect::<Vec<_>>();
        summaries[0].status = AgentRunStatus::Failed;
        summaries[1].status = AgentRunStatus::Failed;
        let mut remaining = BTreeSet::from([2, 3]);

        propagate_dependency_failures(&plan, &mut summaries, &mut remaining);

        assert_eq!(summaries[2].status, AgentRunStatus::Skipped);
        assert_eq!(summaries[3].status, AgentRunStatus::Pending);
        assert_eq!(
            summaries[2].error.as_deref(),
            Some(
                "skipped because dependencies did not succeed: 'fail-a' (failed), 'fail-b' (failed)"
            )
        );
        assert_eq!(
            ready_agent_indices(&plan, &summaries, &remaining, 4),
            vec![3]
        );
    }

    #[test]
    fn scheduler_accepts_successful_checkpoint_summary_as_dependency() {
        let plan = schedule_test_plan(vec![
            schedule_test_agent("completed", &[]),
            schedule_test_agent("pending-dependent", &["completed"]),
        ]);
        let mut summaries = plan
            .agents
            .iter()
            .map(AgentRunSummary::pending)
            .collect::<Vec<_>>();
        summaries[0].status = AgentRunStatus::Succeeded;
        let remaining = BTreeSet::from([1]);

        assert_eq!(
            ready_agent_indices(&plan, &summaries, &remaining, 1),
            vec![1]
        );
    }

    #[test]
    fn resume_claim_failure_isolated_to_its_dependency_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open sync store");
        let blocker = store
            .claim_paths("external-blocker", ["blocked.txt"])
            .expect("create blocking claim");
        let mut blocked = schedule_test_agent("blocked", &[]);
        blocked.paths = vec![PathBuf::from("blocked.txt")];
        let mut independent = schedule_test_agent("independent", &[]);
        independent.paths = vec![PathBuf::from("independent.txt")];
        let plan = schedule_test_plan(vec![blocked, independent]);
        let mut summaries = plan
            .agents
            .iter()
            .map(AgentRunSummary::pending)
            .collect::<Vec<_>>();

        let acquired = acquire_resume_claims(&store, &plan, &mut summaries);

        assert_eq!(summaries[0].status, AgentRunStatus::Failed);
        assert_eq!(summaries[1].status, AgentRunStatus::Pending);
        assert_eq!(acquired.len(), 1);
        store.release(acquired[0]).expect("release acquired claim");
        store.release(blocker.token).expect("release blocker");
    }

    #[test]
    fn agent_validation_rejects_within_claim_content_mutation() {
        let summary = run_candidate_validation_test("printf 'changed\\n' > claimed.txt");
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(summary
            .error
            .as_deref()
            .is_some_and(|error| error.contains("tracked worktree content")));
    }

    #[test]
    fn agent_validation_rejects_unclaimed_untracked_mutation() {
        let summary = run_candidate_validation_test("printf 'new\\n' > unclaimed.txt");
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(summary.error.as_deref().is_some_and(|error| {
            error.contains("untracked content") && error.contains("changed paths/status")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn agent_validation_rejects_untracked_executable_mode_mutation() {
        let summary =
            run_candidate_validation_test_with_setup("chmod 755 scratch.sh", |repo_path| {
                fs::write(repo_path.join("scratch.sh"), "#!/bin/sh\n")
                    .expect("write untracked script");
                fs::set_permissions(
                    repo_path.join("scratch.sh"),
                    fs::Permissions::from_mode(0o644),
                )
                .expect("set initial untracked mode");
            });
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(
            summary
                .error
                .as_deref()
                .is_some_and(|error| error.contains("untracked content")),
            "{:?}",
            summary.error
        );
    }

    #[test]
    fn agent_validation_rejects_head_mutation() {
        let summary = run_candidate_validation_test(
            "git -c user.name=test -c user.email=test@example.invalid -c core.hooksPath=/dev/null commit --allow-empty -m validation",
        );
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(summary
            .error
            .as_deref()
            .is_some_and(|error| error.contains("HEAD")));
    }

    #[test]
    fn agent_validation_rejects_index_only_mutation() {
        let summary = run_candidate_validation_test("git add -- claimed.txt");
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(summary
            .error
            .as_deref()
            .is_some_and(|error| error.contains("index")));
    }

    #[test]
    fn agent_validation_accepts_exactly_unchanged_candidate() {
        let summary = run_candidate_validation_test("true");
        assert_eq!(summary.status, AgentRunStatus::Succeeded);
        assert!(summary.error.is_none());
    }

    #[test]
    fn repo_validation_materializes_exact_combined_candidate_and_not_primary() {
        let temp = TempDir::new().expect("tempdir");
        let primary = temp.path().join("primary");
        WorktreeManager::init_repository(&primary, "main").expect("init primary");
        let repo = crate::git_repository::open(&primary).expect("open primary");
        fs::write(primary.join("a.txt"), "base-a\n").expect("write a");
        fs::write(primary.join("b.txt"), "base-b\n").expect("write b");
        let base_oid = commit_all(&repo, "initial commit").expect("commit");
        let candidate_a = clone_candidate(
            &primary,
            &temp.path().join("candidate-a"),
            base_oid,
            Some("a.txt"),
            "candidate-a\n",
        );
        let candidate_b = clone_candidate(
            &primary,
            &temp.path().join("candidate-b"),
            base_oid,
            Some("b.txt"),
            "candidate-b\n",
        );
        let mut agent_a = schedule_test_agent("agent-a", &[]);
        agent_a.paths = vec![PathBuf::from("a.txt")];
        let mut agent_b = schedule_test_agent("agent-b", &[]);
        agent_b.paths = vec![PathBuf::from("b.txt")];
        let plan = schedule_test_plan(vec![agent_a, agent_b]);
        let candidates = vec![Some(candidate_a), Some(candidate_b)];
        let stats = validate_combined_candidate_set(&plan, &candidates, &base_oid)
            .expect("validate candidate union");
        let validation_path = temp.path().join("validation");
        let validation_repo =
            Repository::clone(primary.to_str().expect("primary utf8"), &validation_path)
                .expect("clone validation target");
        SyncStore::open(&validation_path).expect("create validation sensitive state root");
        let index_path = validation_repo.path().join("index");
        let index_before = fs::read(&index_path).expect("read validation index before apply");

        apply_captured_candidate_patches(
            &plan,
            &validation_path,
            &candidates,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
            || Ok(()),
        )
        .expect("apply exact union");
        assert_eq!(
            fs::read(&index_path).expect("read validation index after apply"),
            index_before,
            "combined materialization must not write shared Git administration"
        );
        let combined_state = capture_consistent_candidate_state(
            &validation_path,
            &base_oid,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture combined state");
        let combined = capture_bound_candidate(
            &validation_path,
            &base_oid,
            &combined_state,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture combined candidate");
        let target = repo_validation_target_binding(&stats, &base_oid, &combined);
        let validation = ValidationCommandPlan {
            name: Some("combined content".to_string()),
            command: "test \"$(cat a.txt)\" = candidate-a && test \"$(cat b.txt)\" = candidate-b"
                .to_string(),
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(5)),
            working_directory: None,
        };
        let (summary, intact) = run_candidate_bound_validation_command(
            &validation,
            &validation_path,
            &base_oid,
            &combined_state,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
            || Ok(()),
        );

        assert!(intact);
        assert_eq!(summary.status, AgentRunStatus::Succeeded);
        assert_eq!(target.kind, RepoValidationTargetKind::CombinedCandidate);
        assert_eq!(
            target.changed_paths,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
        );
        assert_eq!(
            fs::read_to_string(primary.join("a.txt")).expect("read primary a"),
            "base-a\n"
        );
        assert_eq!(
            fs::read_to_string(primary.join("b.txt")).expect("read primary b"),
            "base-b\n"
        );
        let serialized = serde_json::to_string(&target).expect("serialize target");
        assert!(!serialized.contains(temp.path().to_str().expect("temp utf8")));
    }

    #[test]
    fn repo_validation_zero_change_target_is_explicit() {
        let temp = TempDir::new().expect("tempdir");
        let primary = temp.path().join("primary");
        WorktreeManager::init_repository(&primary, "main").expect("init primary");
        let repo = crate::git_repository::open(&primary).expect("open primary");
        fs::write(primary.join("README.md"), "base\n").expect("write readme");
        let base_oid = commit_all(&repo, "initial commit").expect("commit");
        let candidate =
            clone_candidate(&primary, &temp.path().join("candidate"), base_oid, None, "");
        let plan = schedule_test_plan(vec![schedule_test_agent("agent-a", &[])]);
        let candidates = vec![Some(candidate)];
        let stats = validate_combined_candidate_set(&plan, &candidates, &base_oid)
            .expect("validate zero-change set");
        let target = repo_validation_target_binding(
            &stats,
            &base_oid,
            candidates[0].as_ref().expect("candidate"),
        );

        assert_eq!(target.kind, RepoValidationTargetKind::BaseNoChanges);
        assert_eq!(target.candidate_count, 1);
        assert_eq!(target.patch_count, 0);
        assert_eq!(target.aggregate_patch_bytes, 0);
        assert!(target.changed_paths.is_empty());
    }

    #[test]
    fn combined_candidate_rejects_duplicate_patch_paths_before_materialization() {
        let temp = TempDir::new().expect("tempdir");
        let primary = temp.path().join("primary");
        WorktreeManager::init_repository(&primary, "main").expect("init primary");
        let repo = crate::git_repository::open(&primary).expect("open primary");
        fs::write(primary.join("shared.txt"), "base\n").expect("write shared");
        let base_oid = commit_all(&repo, "initial commit").expect("commit");
        let first = clone_candidate(
            &primary,
            &temp.path().join("first"),
            base_oid,
            Some("shared.txt"),
            "first\n",
        );
        let second = clone_candidate(
            &primary,
            &temp.path().join("second"),
            base_oid,
            Some("shared.txt"),
            "second\n",
        );
        let mut first_agent = schedule_test_agent("first", &[]);
        first_agent.paths = vec![PathBuf::from("shared.txt")];
        let mut second_agent = schedule_test_agent("second", &[]);
        second_agent.paths = vec![PathBuf::from("shared.txt")];
        let plan = schedule_test_plan(vec![first_agent, second_agent]);

        let error = validate_combined_candidate_set(&plan, &[Some(first), Some(second)], &base_oid)
            .expect_err("duplicate candidate path must fail closed");
        assert!(error
            .to_string()
            .contains("duplicate changed path 'shared.txt'"));
    }

    #[test]
    fn repo_validation_mutation_never_preserves_a_success_status() {
        let summary = run_candidate_validation_test("printf 'repo mutation\\n' > claimed.txt");
        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(summary
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("candidate-relevant state changed") }));
    }

    #[test]
    fn load_plan_accepts_dependencies_env_working_directory_and_timeout() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "default_timeout_seconds": 30,
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {
                  "id": "agent-b",
                  "paths": ["README.md"],
                  "depends_on": ["agent-a"],
                  "working_directory": "src",
                  "env": {"MACO_TEST": "ok"},
                  "timeout_seconds": 5,
                  "command": "echo b"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let plan = load_plan(&plan_path).expect("load plan");

        assert_eq!(plan.agents[0].timeout, Some(Duration::from_secs(30)));
        assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Clean);
        assert!(plan.repo_validation_commands.is_empty());
        assert!(plan.agents[0].validation_commands.is_empty());
        assert_eq!(plan.agents[1].depends_on, vec!["agent-a"]);
        assert_eq!(plan.agents[1].working_directory, Some(PathBuf::from("src")));
        assert_eq!(
            plan.agents[1].env.get("MACO_TEST").map(String::as_str),
            Some("ok")
        );
        assert_eq!(plan.agents[1].timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn load_plan_accepts_validation_commands_and_reuse_policy() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "worktree_reuse_policy": "required",
              "repo_validation_commands": [
                "cargo fmt -- --check",
                {
                  "name": "unit tests",
                  "command": "cargo test",
                  "working_directory": "src",
                  "env": {"RUST_BACKTRACE": "1"},
                  "timeout_seconds": 20
                }
              ],
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["src"],
                  "command": "true",
                  "validation_commands": [
                    {"name": "agent check", "command": "cargo check", "timeout_seconds": 10}
                  ]
                }
              ]
            }"#,
        )
        .expect("write plan");

        let plan = load_plan(&plan_path).expect("load plan");

        assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Required);
        assert_eq!(plan.repo_validation_commands.len(), 2);
        assert_eq!(
            plan.repo_validation_commands[1].working_directory,
            Some(PathBuf::from("src"))
        );
        assert_eq!(
            plan.repo_validation_commands[1]
                .env
                .get("RUST_BACKTRACE")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            plan.agents[0].validation_commands[0].timeout,
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn worktree_reuse_policy_defaults_and_accepts_reset_policy() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"true"}]}"#,
        )
        .expect("write plan");
        let plan = load_plan(&plan_path).expect("load plan");
        assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Clean);

        fs::write(
            &plan_path,
            r#"{"worktree_reuse_policy":"reset","agents":[{"id":"agent-a","paths":["src"],"command":"true"}]}"#,
        )
        .expect("write reset plan");
        let plan = load_plan(&plan_path).expect("load reset plan");
        assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Reset);
    }

    #[test]
    fn load_plan_rejects_invalid_completion_criteria() {
        let cases = [
            (
                r#"{"agents":[]}"#,
                "orchestration plan must include at least one agent",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":[],"command":"echo a"}]}"#,
                "path claims cannot be empty",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"   "}]}"#,
                "command cannot be empty",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["/tmp"],"command":"echo a"}]}"#,
                "repository-relative",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["../src"],"command":"echo a"}]}"#,
                "escape repository",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"},{"id":"agent-a","paths":["README.md"],"command":"echo b"}]}"#,
                "duplicate agent id",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-missing"]}]}"#,
                "depends on unknown agent",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-a"]}]}"#,
                "cannot depend on itself",
            ),
            (
                r#"{"default_timeout_seconds":0,"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"}]}"#,
                "default timeout",
            ),
        ];

        for (contents, expected) in cases {
            let temp = TempDir::new().expect("tempdir");
            let plan_path = temp.path().join("plan.json");
            fs::write(&plan_path, contents).expect("write plan");

            let error = load_plan(&plan_path).expect_err("plan should fail");
            let rendered = format!("{error:#}");

            assert!(
                rendered.contains(expected),
                "expected '{expected}' in '{rendered}'"
            );
        }
    }

    #[test]
    fn load_plan_rejects_dependency_cycles() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a", "depends_on": ["agent-b"]},
                {"id": "agent-b", "paths": ["README.md"], "command": "echo b", "depends_on": ["agent-a"]}
              ]
            }"#,
        )
        .expect("write plan");

        let error = load_plan(&plan_path).expect_err("cycle should fail");

        assert!(error.to_string().contains("dependency cycle"));
    }

    #[test]
    fn load_plan_rejects_overlapping_agent_paths() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {"id": "agent-b", "paths": ["src/lib.rs"], "command": "echo b"}
              ]
            }"#,
        )
        .expect("write plan");

        let error = load_plan(&plan_path).expect_err("overlap should fail");

        assert!(error.to_string().contains("overlaps"));
    }

    #[test]
    fn run_plan_creates_worktree_runs_command_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["src"],
                  "command": "git rev-parse --is-inside-work-tree"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[0].stdout.text.trim(), "true");
        assert_eq!(summary.released_claims.len(), 1);
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
        let released = WorktreeManager::new(&repo_path)
            .acquire_write_execution_lease("agent-a")
            .expect("successful run releases write lease");
        drop(released);
    }

    #[cfg(unix)]
    #[test]
    fn orchestration_holds_write_lease_through_child_validation_and_finalization() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        commit_all(&repo, "initial commit").expect("commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let unrelated = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-b worktree");

        let child_ready = temp.path().join("child-ready");
        let child_release = temp.path().join("child-release");
        let validation_ready = temp.path().join("validation-ready");
        let validation_release = temp.path().join("validation-release");
        let child_command = format!(
            "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
            child_ready.display(),
            child_release.display()
        );
        let validation_command = format!(
            "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
            validation_ready.display(),
            validation_release.display()
        );
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            serde_json::to_vec_pretty(&serde_json::json!({
                "worktree_reuse_policy": "required",
                "agents": [{
                    "id": "agent-a",
                    "paths": ["README.md"],
                    "command": child_command,
                    "validation_commands": [validation_command]
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
        let run_repo = repo_path.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let runner = thread::spawn(move || {
            let result = run_plan_file(OrchestrationRunOptions {
                repo: run_repo,
                plan_file,
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            });
            done_tx.send(()).expect("signal runner return");
            result
        });

        wait_for_test_marker(&child_ready);
        let child_writer_blocked = manager.acquire_write_execution_lease("agent-a").is_err();
        let child_removal = manager.remove("agent-a", true, false);
        let unrelated_during_child = manager
            .acquire_write_execution_lease("agent-b")
            .map(|lease| lease.path().to_path_buf());
        fs::write(&child_release, "release\n").expect("release child");

        wait_for_test_marker(&validation_ready);
        let validation_writer_blocked = manager.acquire_write_execution_lease("agent-a").is_err();
        let validation_removal = manager.remove("agent-a", true, false);
        let unrelated_during_validation = manager
            .acquire_write_execution_lease("agent-b")
            .map(|lease| lease.path().to_path_buf());
        assert!(
            done_rx.try_recv().is_err(),
            "run returned before final release"
        );
        fs::write(&validation_release, "release\n").expect("release validation");

        let summary = runner.join().expect("join runner").expect("run plan");
        assert!(summary.success);
        assert!(child_writer_blocked);
        assert!(child_removal.is_err());
        assert_eq!(
            unrelated_during_child
                .expect("unrelated writer during child")
                .as_path(),
            unrelated.path
        );
        assert!(validation_writer_blocked);
        assert!(validation_removal.is_err());
        assert_eq!(
            unrelated_during_validation
                .expect("unrelated writer during validation")
                .as_path(),
            unrelated.path
        );
        let released = manager
            .acquire_write_execution_lease("agent-a")
            .expect("orchestration releases write lease after finalization");
        drop(released);
        let removed = manager
            .remove("agent-a", true, false)
            .expect("orchestration releases removal authority after finalization");
        assert!(!removed.path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn orchestration_releases_write_lease_after_timeout() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [{
                "id": "agent-timeout",
                "paths": ["README.md"],
                "command": "sleep 5",
                "timeout_seconds": 1
              }]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run timeout plan");
        assert!(!summary.success);
        assert!(summary.agents[0].timed_out);
        let manager = WorktreeManager::new(&repo_path);
        let released = manager
            .acquire_write_execution_lease("agent-timeout")
            .expect("timeout releases write lease");
        drop(released);
        let removed = manager
            .remove("agent-timeout", true, false)
            .expect("timeout releases removal authority");
        assert!(!removed.path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn redirected_git_marker_fails_before_candidate_open_and_holds_lease_through_refusal() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let manager = WorktreeManager::new(&repo_path);
        let record = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "git-marker-redirect".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        let original_marker = fs::read(record.path.join(".git")).expect("read marker");
        let foreign_path = temp.path().join("foreign");
        WorktreeManager::init_repository(&foreign_path, "main").expect("init foreign");
        fs::write(foreign_path.join("sentinel"), "untouched\n").expect("write sentinel");
        let command = format!(
            "printf 'gitdir: %s\\n' '{}' > .git",
            foreign_path.join(".git").display()
        );
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            serde_json::to_vec(&serde_json::json!({
                "worktree_reuse_policy": "required",
                "agents": [{
                    "id": "git-marker-redirect",
                    "paths": ["README.md"],
                    "command": command
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
        let (reached, release) = install_candidate_boundary_failure_hook("git-marker-redirect");
        let run_repo = repo_path.clone();
        let runner = thread::spawn(move || {
            run_plan_file(OrchestrationRunOptions {
                repo: run_repo,
                plan_file,
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            })
        });

        reached
            .recv_timeout(Duration::from_secs(10))
            .expect("candidate boundary failure hook");
        let competing_lease = manager.acquire_write_execution_lease("git-marker-redirect");
        let competing_removal = manager.remove("git-marker-redirect", true, false);
        release.send(()).expect("release refusal hook");
        assert!(competing_lease.is_err());
        assert!(competing_removal.is_err());
        let summary = runner.join().expect("join runner").expect("run summary");

        assert!(!summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert!(summary.agents[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("managed worktree binding is invalid")));
        assert!(summary.agents[0].candidate_binding.is_none());
        assert!(summary.agents[0].patch_path.is_none());
        assert_eq!(
            fs::read_to_string(foreign_path.join("sentinel")).expect("read sentinel"),
            "untouched\n"
        );

        fs::write(record.path.join(".git"), original_marker).expect("restore marker");
        manager
            .get_managed_verified("git-marker-redirect")
            .expect("restored binding");
        manager
            .remove("git-marker-redirect", true, true)
            .expect("remove restored worktree");
    }

    #[test]
    fn run_plan_reports_failed_command_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "false"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
        let manager = WorktreeManager::new(&repo_path);
        let released = manager
            .acquire_write_execution_lease("agent-a")
            .expect("failed command releases write lease");
        drop(released);
        let removed = manager
            .remove("agent-a", true, false)
            .expect("failed command releases removal authority");
        assert!(!removed.path.exists());
    }

    #[test]
    fn run_plan_reports_claim_conflict_as_summary() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        SyncStore::open(&repo_path)
            .expect("open store")
            .claim_paths("other-agent", ["README.md"])
            .expect("preclaim");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert!(summary.agents[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to claim paths"));
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .owner_of("README.md")
                .expect("owner")
                .owner,
            Some("other-agent".to_string())
        );
    }

    #[test]
    fn semantic_coordination_warn_compares_against_planned_preview_intents_without_persisting() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
        fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file,
                keep_claims: false,
                jobs: 2,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: None,
                checkpoint_dir: None,
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Warn,
            },
        )
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(
            summary.semantic_coordination,
            SemanticCoordinationMode::Warn
        );
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert!(summary.agents[0].semantic_conflicts.is_empty());
        assert_eq!(
            summary.agents[0]
                .semantic_intent
                .as_ref()
                .map(|intent| intent.token.get()),
            Some(1)
        );
        assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
        assert_eq!(
            summary.agents[1]
                .semantic_intent
                .as_ref()
                .map(|intent| intent.token.get()),
            Some(2)
        );
        assert!(summary.agents[1].semantic_conflicts.iter().any(|conflict| {
            conflict.severity == SemanticConflictSeverity::Blocking
                && conflict.kind == SemanticConflictKind::SymbolOverlap
                && conflict.active_agent_id.as_deref() == Some("agent-a")
        }));
        assert!(summary.released_semantic_intents.is_empty());
        assert_eq!(
            SemanticIntentStore::open(&repo_path)
                .expect("open semantic store")
                .status()
                .expect("semantic status"),
            Vec::new()
        );
    }

    #[test]
    fn semantic_coordination_block_reports_overlapping_symbols() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
        fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file,
                keep_claims: false,
                jobs: 2,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: None,
                checkpoint_dir: None,
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Block,
            },
        )
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(
            summary.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert_eq!(summary.first_failed_agent(), Some("agent-b"));
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Failed);
        assert!(summary.agents[1]
            .semantic_conflicts
            .iter()
            .any(|conflict| conflict.kind
                == crate::semantic_coord::SemanticConflictKind::SymbolOverlap));
        assert_eq!(summary.released_semantic_intents.len(), 1);
        assert_eq!(
            SemanticIntentStore::open(&repo_path)
                .expect("open semantic store")
                .status()
                .expect("semantic status"),
            Vec::new()
        );
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
    }

    #[test]
    fn semantic_coordination_block_unresolved_symbol_fails_summary_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Existing;\n").expect("write lib");
        fs::write(repo_path.join("owned.txt"), "owned\n").expect("write owned");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["owned.txt"],
                  "semantic_symbols": ["MissingSymbol"],
                  "command": "true"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file,
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: None,
                checkpoint_dir: None,
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Block,
            },
        )
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        let error = summary.agents[0].error.as_deref().unwrap_or_default();
        assert!(error.contains("unresolved semantic symbol"));
        assert!(error.contains("MissingSymbol"));
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
        assert_eq!(
            SemanticIntentStore::open(&repo_path)
                .expect("open semantic store")
                .snapshot()
                .expect("semantic snapshot"),
            Vec::new()
        );
    }

    #[test]
    fn semantic_coordination_block_allows_disjoint_intents() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Alpha;\npub struct Beta;\n",
        )
        .expect("write lib");
        fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Alpha"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Beta"],
                  "command": "true"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file,
                keep_claims: false,
                jobs: 2,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: None,
                checkpoint_dir: None,
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Block,
            },
        )
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(
            summary.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
        assert!(summary.agents.iter().all(|agent| agent
            .semantic_intent
            .as_ref()
            .is_some_and(|intent| !intent.symbols.is_empty())));
        assert_eq!(summary.released_semantic_intents.len(), 2);
        assert_eq!(
            SemanticIntentStore::open(&repo_path)
                .expect("open semantic store")
                .status()
                .expect("semantic status"),
            Vec::new()
        );
    }

    #[test]
    fn run_plan_reports_unclaimed_changes_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::write(repo_path.join("Cargo.toml"), "[package]\n").expect("write cargo");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf 'changed\n' > Cargo.toml"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert_eq!(
            summary.agents[0].unclaimed_changed_paths,
            vec![PathBuf::from("Cargo.toml")]
        );
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
    }

    #[test]
    fn run_plan_writes_patch_for_claimed_changes() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let patch_dir = temp.path().join("patches");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf '# Changed\n' > README.md"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: Some(patch_dir.clone()),
        })
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(
            summary.agents[0].changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert_eq!(
            summary.agents[0].patch_path,
            Some(patch_dir.join("agent-a.patch"))
        );
        let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).expect("read patch");
        assert!(patch.contains("# Changed"));
    }

    #[test]
    fn run_plan_times_out_and_skips_dependents() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "timeout_seconds": 1,
                  "command": "sleep 5"
                },
                {
                  "id": "agent-b",
                  "paths": ["src"],
                  "depends_on": ["agent-a"],
                  "command": "echo should-not-run"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 2,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert!(summary.agents[0].timed_out);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Skipped);
    }

    #[test]
    fn agent_validation_failure_is_reported_with_bounded_output() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "true",
                  "validation_commands": [
                    {"name": "check", "command": "printf 'validation failed' >&2; false"}
                  ]
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert_eq!(summary.agents[0].validation.len(), 1);
        assert_eq!(
            summary.agents[0].validation[0].status,
            AgentRunStatus::Failed
        );
        assert_eq!(
            summary.agents[0].validation[0].stderr.text,
            "validation failed"
        );
        assert!(!summary.agents[0].validation[0].stderr.truncated);
        assert!(summary.agents[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("agent validation 'check' failed"));
    }

    #[test]
    fn repo_validation_failure_is_reported_in_summary() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "repo_validation_commands": [
                {"name": "repo check", "command": "printf 'repo failed' >&2; false"}
              ],
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.repo_validation.len(), 1);
        assert_eq!(summary.repo_validation[0].status, AgentRunStatus::Failed);
        assert_eq!(summary.repo_validation[0].stderr.text, "repo failed");
    }

    #[test]
    fn resume_skips_completed_agent_and_runs_pending_dependent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");

        let manager = WorktreeManager::new(&repo_path);
        let agent_a_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-b worktree");
        fs::write(agent_a_worktree.path.join("a.txt"), "done\n").expect("write agent a output");

        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "command": "printf 'rerun\n' >> a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "depends_on": ["agent-a"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
        )
        .expect("write plan");
        let plan = load_plan(&plan_file).expect("load plan");
        let store = SyncStore::open(&repo_path).expect("open store");
        let claim_a = store
            .claim_paths("agent-a", ["a.txt"])
            .expect("claim agent a");
        let claim_b = store
            .claim_paths("agent-b", ["b.txt"])
            .expect("claim agent b");
        let base_oid = current_head_oid(&repo_path).expect("head");
        let agent_a_binding = test_candidate_binding(&agent_a_worktree.path, base_oid);
        let run_id = RunId::new("resume-skip").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::ClaimsAcquired,
            repo: repo_path.clone(),
            repo_head: Some(base_oid.to_string()),
            plan_file: plan_file.clone(),
            plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: vec![
                AgentCheckpoint {
                    id: "agent-a".to_string(),
                    status: AgentRunStatus::Succeeded,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                    claim: Some(claim_a),
                    semantic_intent: None,
                    semantic_conflicts: Vec::new(),
                    changed_paths: vec![PathBuf::from("a.txt")],
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: Some(agent_a_binding),
                    command_completed_binding: None,
                    error: None,
                },
                AgentCheckpoint {
                    id: "agent-b".to_string(),
                    status: AgentRunStatus::Pending,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                    claim: Some(claim_b),
                    semantic_intent: None,
                    semantic_conflicts: Vec::new(),
                    changed_paths: Vec::new(),
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: None,
                    command_completed_binding: None,
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_file =
            write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

        let summary = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume");

        assert!(summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
        assert_eq!(
            fs::read_to_string(agent_a_worktree.path.join("a.txt")).expect("read a"),
            "done\n"
        );
        assert_eq!(
            fs::read_to_string(agent_b_worktree.path.join("b.txt")).expect("read b"),
            "done\n"
        );
        assert_eq!(store.snapshot().expect("snapshot"), Vec::<PathClaim>::new());
        let final_checkpoint =
            read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
        assert_eq!(final_checkpoint.stage, RunCheckpointStage::Final);
        assert!(final_checkpoint.success);
    }

    #[cfg(unix)]
    #[test]
    fn resume_reacquires_fresh_write_lease_and_releases_it_on_every_return() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        commit_all(&repo, "initial commit").expect("commit");
        let manager = WorktreeManager::new(&repo_path);
        let worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-resume".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create resume worktree");

        let ready = temp.path().join("resume-ready");
        let release = temp.path().join("resume-release");
        let command = format!(
            "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
            ready.display(),
            release.display()
        );
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            serde_json::to_vec_pretty(&serde_json::json!({
                "agents": [{
                    "id": "agent-resume",
                    "paths": ["README.md"],
                    "command": command
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
        let plan = load_plan(&plan_file).expect("load plan");
        let run_id = RunId::new("resume-write-lease").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path.clone(),
            repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
            plan_file: plan_file.clone(),
            plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: vec![AgentCheckpoint {
                id: "agent-resume".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&worktree)),
                claim: None,
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            }],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_file =
            write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
        let run_checkpoint = checkpoint_file.clone();
        let run_repo = repo_path.clone();
        let run_plan = plan_file.clone();
        let runner = thread::spawn(move || {
            resume_plan_file(OrchestrationResumeOptions {
                checkpoint_file: run_checkpoint,
                repo: Some(run_repo),
                plan_file: Some(run_plan),
                jobs: 1,
                patch_dir: None,
            })
        });

        wait_for_test_marker(&ready);
        let writer_blocked = manager
            .acquire_write_execution_lease("agent-resume")
            .is_err();
        let removal_blocked = manager.remove("agent-resume", true, false).is_err();
        fs::write(&release, "release\n").expect("release resume command");
        let summary = runner.join().expect("join resume").expect("resume plan");
        assert!(summary.success);
        assert!(writer_blocked);
        assert!(removal_blocked);

        let external_writer = manager
            .acquire_write_execution_lease("agent-resume")
            .expect("first resume released its write lease");
        let reacquire_error = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: checkpoint_file.clone(),
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file.clone()),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("each resume must reacquire instead of reusing a stale handle");
        assert!(reacquire_error
            .to_string()
            .contains("could not reacquire the exclusive execution lease"));
        drop(external_writer);

        let replay = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume final checkpoint after releasing external writer");
        assert!(replay.success);
        let released = manager
            .acquire_write_execution_lease("agent-resume")
            .expect("final checkpoint resume releases its reacquired lease");
        drop(released);
        let removed = manager
            .remove("agent-resume", true, false)
            .expect("resume releases removal authority");
        assert!(!removed.path.exists());
    }

    #[test]
    fn resume_preserves_and_releases_checkpoint_semantic_intents() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Alpha;\npub struct Beta;\n",
        )
        .expect("write lib");
        fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");

        let manager = WorktreeManager::new(&repo_path);
        let agent_a_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-b worktree");
        fs::write(agent_a_worktree.path.join("a.txt"), "done\n").expect("write agent a output");

        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Alpha"],
                  "command": "printf 'rerun\n' >> a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Beta"],
                  "depends_on": ["agent-a"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
        )
        .expect("write plan");
        let plan = load_plan(&plan_file).expect("load plan");
        let store = SyncStore::open(&repo_path).expect("open store");
        let claim_a = store
            .claim_paths("agent-a", ["a.txt"])
            .expect("claim agent a");
        let claim_b = store
            .claim_paths("agent-b", ["b.txt"])
            .expect("claim agent b");
        let semantic_store = SemanticIntentStore::open(&repo_path).expect("open semantic store");
        let semantic_a = semantic_store
            .claim(SemanticIntentRequest {
                agent_id: "agent-a".to_string(),
                paths: vec![PathBuf::from("a.txt")],
                symbols: vec!["Alpha".to_string()],
                modules: Vec::new(),
                task_file: None,
                notes: Vec::new(),
            })
            .expect("claim semantic a");
        let semantic_b = semantic_store
            .claim(SemanticIntentRequest {
                agent_id: "agent-b".to_string(),
                paths: vec![PathBuf::from("b.txt")],
                symbols: vec!["Beta".to_string()],
                modules: Vec::new(),
                task_file: None,
                notes: Vec::new(),
            })
            .expect("claim semantic b");
        let base_oid = current_head_oid(&repo_path).expect("head");
        let agent_a_binding = test_candidate_binding(&agent_a_worktree.path, base_oid);
        let run_id = RunId::new("resume-semantic").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::ClaimsAcquired,
            repo: repo_path.clone(),
            repo_head: Some(base_oid.to_string()),
            plan_file: plan_file.clone(),
            plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Block,
            success: false,
            agents: vec![
                AgentCheckpoint {
                    id: "agent-a".to_string(),
                    status: AgentRunStatus::Succeeded,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                    claim: Some(claim_a),
                    semantic_intent: Some(semantic_a.intent.clone()),
                    semantic_conflicts: semantic_a.conflicts.clone(),
                    changed_paths: vec![PathBuf::from("a.txt")],
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: Some(agent_a_binding),
                    command_completed_binding: None,
                    error: None,
                },
                AgentCheckpoint {
                    id: "agent-b".to_string(),
                    status: AgentRunStatus::Pending,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                    claim: Some(claim_b),
                    semantic_intent: Some(semantic_b.intent.clone()),
                    semantic_conflicts: semantic_b.conflicts.clone(),
                    changed_paths: Vec::new(),
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: None,
                    command_completed_binding: None,
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_file =
            write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

        let summary = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume");

        assert!(summary.success);
        assert_eq!(
            summary.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert!(summary
            .agents
            .iter()
            .all(|agent| agent.semantic_intent.is_some()));
        assert_eq!(summary.released_semantic_intents.len(), 2);
        assert!(summary.semantic_release_errors.is_empty());
        assert_eq!(
            semantic_store.status().expect("semantic status"),
            Vec::new()
        );
        let final_checkpoint =
            read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
        assert_eq!(
            final_checkpoint.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert_eq!(final_checkpoint.released_semantic_intents.len(), 2);
        assert!(final_checkpoint.semantic_release_errors.is_empty());
    }

    #[test]
    fn resume_runs_missing_semantic_coordination_before_pending_agents() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
        fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");

        let manager = WorktreeManager::new(&repo_path);
        let agent_a_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-b worktree");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "printf 'done\n' > a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
        )
        .expect("write plan");
        let plan = load_plan(&plan_file).expect("load plan");
        let store = SyncStore::open(&repo_path).expect("open store");
        let claim_a = store
            .claim_paths("agent-a", ["a.txt"])
            .expect("claim agent a");
        let claim_b = store
            .claim_paths("agent-b", ["b.txt"])
            .expect("claim agent b");
        let run_id = RunId::new("resume-semantic-missing").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::ClaimsAcquired,
            repo: repo_path.clone(),
            repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
            plan_file: plan_file.clone(),
            plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Block,
            success: false,
            agents: vec![
                AgentCheckpoint {
                    id: "agent-a".to_string(),
                    status: AgentRunStatus::Pending,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                    claim: Some(claim_a),
                    semantic_intent: None,
                    semantic_conflicts: Vec::new(),
                    changed_paths: Vec::new(),
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: None,
                    command_completed_binding: None,
                    error: None,
                },
                AgentCheckpoint {
                    id: "agent-b".to_string(),
                    status: AgentRunStatus::Pending,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                    claim: Some(claim_b),
                    semantic_intent: None,
                    semantic_conflicts: Vec::new(),
                    changed_paths: Vec::new(),
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    candidate_binding: None,
                    command_completed_binding: None,
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_file =
            write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

        let summary = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume");

        assert!(!summary.success);
        assert_eq!(
            summary.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert_eq!(summary.first_failed_agent(), Some("agent-b"));
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Failed);
        assert_eq!(summary.released_semantic_intents.len(), 1);
        assert_eq!(
            SemanticIntentStore::open(&repo_path)
                .expect("open semantic store")
                .status()
                .expect("semantic status"),
            Vec::new()
        );
        let final_checkpoint =
            read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
        assert_eq!(final_checkpoint.stage, RunCheckpointStage::Final);
        assert_eq!(
            final_checkpoint.semantic_coordination,
            SemanticCoordinationMode::Block
        );
        assert_eq!(final_checkpoint.released_semantic_intents.len(), 1);
    }

    #[test]
    fn resume_refuses_changed_plan_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"true"}]}"#,
        )
        .expect("write plan");
        let plan = load_plan(&plan_file).expect("load plan");
        let run_id = RunId::new("changed-plan").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id,
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path.clone(),
            repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
            plan_file: plan_file.clone(),
            plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: vec![AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&worktree)),
                claim: None,
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            }],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_file =
            write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
        fs::write(
            &plan_file,
            r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"false"}]}"#,
        )
        .expect("rewrite plan");

        let error = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("resume should reject changed plan");

        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn reuse_reset_moves_clean_stale_worktree_to_current_head() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# v1\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        fs::write(repo_path.join("README.md"), "# v2\n").expect("update readme");
        let current_head = commit_all(&repo, "advance primary").expect("commit update");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "grep '# v2' README.md"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(summary.success);
        assert!(summary.agents[0].worktree_reused);
        let worktree_repo = crate::git_repository::open(worktree.path).expect("open worktree");
        assert_eq!(
            head_oid(&worktree_repo).expect("worktree head"),
            current_head
        );
    }

    #[test]
    fn reuse_reset_refuses_dirty_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        fs::write(worktree.path.join("scratch.txt"), "untracked\n").expect("write untracked");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
        )
        .expect("write plan");

        let error = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("reset should refuse dirty worktree");

        assert!(error.to_string().contains("dirty or untracked"));
    }

    #[test]
    fn reuse_reset_refuses_active_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        SyncStore::open(&repo_path)
            .expect("open store")
            .claim_paths("agent-a", ["README.md"])
            .expect("claim");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
        )
        .expect("write plan");

        let error = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("reset should refuse active claim");

        assert!(error.to_string().contains("active claim"));
    }

    #[test]
    fn completed_command_recovery_never_reruns_and_raii_cleans_faults() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Recovery;\n")
            .expect("write semantic source");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [{
                "id": "recover-once",
                "paths": ["README.md"],
                "semantic_symbols": ["Recovery"],
                "command": "printf 'once\\n' >> README.md"
              }]
            }"#,
        )
        .expect("write plan");
        let run_id = RunId::new("completed-recovery-raii").expect("run id");
        install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
        let first = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file: plan_file.clone(),
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(run_id.clone()),
                checkpoint_dir: Some(checkpoint_dir.clone()),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Block,
            },
        )
        .expect_err("inject post-command structural failure");
        assert!(first
            .to_string()
            .contains("injected checkpoint event failure"));
        assert!(SyncStore::open(&repo_path)
            .expect("sync store")
            .snapshot()
            .expect("claims")
            .is_empty());
        assert!(SemanticIntentStore::open(&repo_path)
            .expect("semantic store")
            .snapshot()
            .expect("semantic intents")
            .is_empty());
        let worktree = WorktreeManager::new(&repo_path)
            .list()
            .expect("list worktrees")
            .into_iter()
            .find(|record| record.name == "recover-once")
            .expect("recovery worktree");
        assert_eq!(
            fs::read_to_string(worktree.path.join("README.md"))
                .expect("read command output")
                .matches("once\n")
                .count(),
            1
        );

        let checkpoint_file = checkpoint_path(&checkpoint_dir, &run_id);
        install_checkpoint_event_failure(run_id.as_str(), PHASE_REPO_VALIDATION_STARTED);
        let second = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: checkpoint_file.clone(),
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file.clone()),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("inject resume structural failure");
        assert!(second
            .to_string()
            .contains("injected checkpoint event failure"));
        assert!(SyncStore::open(&repo_path)
            .expect("sync store")
            .snapshot()
            .expect("claims")
            .is_empty());
        assert_eq!(
            fs::read_to_string(worktree.path.join("README.md"))
                .expect("read recovered output")
                .matches("once\n")
                .count(),
            1
        );

        let summary = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume exact completed state");
        assert!(summary.success);
        assert_eq!(
            fs::read_to_string(worktree.path.join("README.md"))
                .expect("read final output")
                .matches("once\n")
                .count(),
            1,
            "resume reran a command whose exact completed state was journaled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resume_rejects_untracked_executable_mode_drift_after_command_completion() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{"agents":[{"id":"mode-drift","paths":["scratch.sh"],"command":"printf '#!/bin/sh\\n' > scratch.sh; chmod 644 scratch.sh"}]}"#,
        )
        .expect("write plan");
        let run_id = RunId::new("resume-untracked-mode-drift").expect("run id");
        install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
        run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file: plan_file.clone(),
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(run_id.clone()),
                checkpoint_dir: Some(checkpoint_dir.clone()),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Off,
            },
        )
        .expect_err("stop after durable command completion");
        let worktree = WorktreeManager::new(&repo_path)
            .list()
            .expect("list worktrees")
            .into_iter()
            .find(|record| record.name == "mode-drift")
            .expect("mode-drift worktree");
        fs::set_permissions(
            worktree.path.join("scratch.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("change executable mode");

        let error = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: checkpoint_path(&checkpoint_dir, &run_id),
            repo: Some(repo_path),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("mode-only drift must invalidate authenticated binding");
        assert!(error.to_string().contains("command state binding drifted"));
    }

    #[test]
    fn started_only_checkpoint_is_uncertain_and_never_runs_or_retries() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{"agents":[{"id":"uncertain","paths":["README.md"],"command":"printf 'ran\\n' >> README.md"}]}"#,
        )
        .expect("write plan");
        let run_id = RunId::new("started-only-uncertain").expect("run id");
        install_checkpoint_event_failure(
            run_id.as_str(),
            &format!("after:{PHASE_COMMAND_STARTED}"),
        );
        run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file: plan_file.clone(),
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(run_id.clone()),
                checkpoint_dir: Some(checkpoint_dir.clone()),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Off,
            },
        )
        .expect_err("inject crash after command_started");
        let worktree = WorktreeManager::new(&repo_path)
            .list()
            .expect("list worktrees")
            .into_iter()
            .find(|record| record.name == "uncertain")
            .expect("uncertain worktree");
        assert_eq!(
            fs::read_to_string(worktree.path.join("README.md")).expect("read worktree"),
            "base\n"
        );
        let error = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: checkpoint_path(&checkpoint_dir, &run_id),
            repo: Some(repo_path),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("started-only resume must fail closed");
        assert!(error.to_string().contains("execution outcome is uncertain"));
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_checkpoint_reference_tamper_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let run_id = RunId::new("reference-tamper").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path,
            repo_head: None,
            plan_file: PathBuf::from("untrusted-plan-must-not-be-read.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
        let malformed_run = temp
            .path()
            .join("repo/.maco/autopilot/runs/malformed-marker");
        fs::create_dir_all(&malformed_run).expect("create malformed marker run");
        for directory in [
            temp.path().join("repo/.maco"),
            temp.path().join("repo/.maco/autopilot"),
            temp.path().join("repo/.maco/autopilot/runs"),
            malformed_run.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private artifact directory");
        }
        let malformed_marker = malformed_run.join(".maco-artifact-final.json");
        fs::write(&malformed_marker, b"not-json").expect("write malformed marker");
        fs::set_permissions(&malformed_marker, fs::Permissions::from_mode(0o600))
            .expect("private malformed marker");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read envelope"))
                .expect("parse envelope");
        envelope["mac"] = serde_json::Value::String("0".repeat(64));
        fs::write(&path, serde_json::to_vec(&envelope).expect("encode tamper"))
            .expect("tamper envelope");
        let error = read_run_checkpoint(&path).expect_err("tampered envelope must fail");
        assert!(error
            .to_string()
            .contains("authentication tag verification failed"));
        assert!(!error.to_string().contains("finalization marker"));
        assert!(!error
            .to_string()
            .contains("untrusted-plan-must-not-be-read"));

        let missing_plan = temp.path().join("resume-must-not-read-this-plan.json");
        let resume_error = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: path,
            repo: Some(temp.path().join("repo")),
            plan_file: Some(missing_plan.clone()),
            jobs: 1,
            patch_dir: None,
        })
        .expect_err("resume must authenticate before loading a plan");
        assert!(resume_error
            .to_string()
            .contains("authentication tag verification failed"));
        assert!(!resume_error
            .to_string()
            .contains(&missing_plan.display().to_string()));
    }

    #[test]
    fn orchestration_profile_binds_git_common_and_hides_sensitive_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        SyncStore::open(&repo_path).expect("create repository state root");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "profile-binding".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        let (common, sensitive) =
            orchestration_sandbox_roots(&worktree.path).expect("resolve sandbox roots");
        let linked = crate::git_repository::open(&worktree.path).expect("open linked worktree");
        assert_eq!(common, linked.commondir());
        assert_eq!(sensitive, linked.commondir().join("maco/state"));
        let spec = CommandRunSpec {
            command: "true".to_string(),
            workspace_root: worktree.path.clone(),
            working_directory: worktree.path,
            env: BTreeMap::new(),
            timeout: None,
            visible_read_only_roots: vec![common.clone()],
            hidden_roots: vec![sensitive.clone()],
            runtime: OrchestrationExecutionRuntime::Verified,
        };
        let rendered = format!("{:?}", strict_command_profile(&spec));
        assert!(rendered.contains(&common.display().to_string()));
        assert!(rendered.contains(&sensitive.display().to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_run_fails_closed_before_child_can_read_repository_authentication_key() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        let key_name = crate::artifacts::state_auth::authentication_key_file_name();
        fs::write(
            &plan_file,
            serde_json::to_vec(&serde_json::json!({
                "agents": [{
                    "id": "key-isolation",
                    "paths": ["README.md"],
                    "command": format!(
                        "common=$(git rev-parse --path-format=absolute --git-common-dir) || exit 10; if cat \"$common/maco/state/{key_name}\"; then exit 91; else printf 'state-hidden\\n'; fi"
                    )
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
        let error = super::run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path,
                plan_file,
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(RunId::new("verified-key-isolation").expect("run id")),
                checkpoint_dir: Some(checkpoint_dir),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Off,
            },
        )
        .expect_err("verified assignment creation must fail closed");
        assert!(error
            .to_string()
            .contains("orchestration assignment creation is temporarily unsupported"));
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_writer_refuses_rekey_when_artifact_marker_exists() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let run = repo_path.join(".maco/autopilot/runs/legacy");
        fs::create_dir_all(&run).expect("create legacy artifact run");
        for directory in [
            repo_path.join(".maco"),
            repo_path.join(".maco/autopilot"),
            repo_path.join(".maco/autopilot/runs"),
            run.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private artifact directory");
        }
        let marker = run.join(".maco-artifact-final.json");
        fs::write(&marker, b"existing marker").expect("write marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("private marker");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: RunId::new("must-not-rekey").expect("run id"),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path.clone(),
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
            .expect_err("existing marker must block key creation");
        assert!(error.to_string().contains("existing final marker"));
        assert!(!checkpoint_path(&checkpoint_dir, &checkpoint.run_id).exists());
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        assert!(!repo
            .commondir()
            .join("maco/state")
            .join(crate::artifacts::state_auth::authentication_key_file_name())
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_writer_refuses_first_key_when_checkpoint_journals_exist() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let maco = repo.commondir().join("maco");
        let state = maco.join("state");
        let journals = state.join(crate::state_journal::JOURNAL_ROOT_NAME);
        fs::create_dir_all(&journals).expect("create prior journal root");
        for directory in [&maco, &state, &journals] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private journal directory");
        }
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: RunId::new("must-not-rekey-journal").expect("run id"),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path,
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
            .expect_err("prior checkpoint journals must block first key");
        assert!(error.to_string().contains("checkpoint journals exist"));
        assert!(!checkpoint_path(&checkpoint_dir, &checkpoint.run_id).exists());
        assert!(!state
            .join(crate::artifacts::state_auth::authentication_key_file_name())
            .exists());
    }

    #[test]
    fn missing_key_for_existing_epoch_is_never_regenerated() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        let checkpoint = |run_id: &str| RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: RunId::new(run_id).expect("run id"),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path.clone(),
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        drop(repository_auth_writer(&repo_path).expect("establish auth epoch"));
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let key = repo
            .commondir()
            .join("maco/state")
            .join(crate::artifacts::state_auth::authentication_key_file_name());
        fs::remove_file(&key).expect("remove key to simulate loss");
        let second = checkpoint("epoch-second");
        let error = write_run_checkpoint(&checkpoint_dir, &second)
            .expect_err("existing epoch must not be rekeyed");
        assert!(error.to_string().contains("existing authentication epoch"));
        assert!(!key.exists());
        assert!(!checkpoint_path(&checkpoint_dir, &second.run_id).exists());
    }

    #[test]
    fn checkpoint_helpers_round_trip_serialized_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let run_id = RunId::new("run-1").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::Final,
            repo: repo_path,
            repo_head: Some("0123456789012345678901234567890123456789".to_string()),
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: Some(CheckpointPlanSnapshot {
                worktree_reuse_policy: WorktreeReusePolicy::Clean,
                repo_validation_commands: Vec::new(),
                agents: vec![CheckpointAgentPlanSnapshot {
                    id: "agent-a".to_string(),
                    paths: vec![PathBuf::from("README.md")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    env: BTreeMap::new(),
                    timeout_seconds: None,
                    command: "true".to_string(),
                    depends_on: Vec::new(),
                    working_directory: None,
                    validation_commands: Vec::new(),
                }],
            }),
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Warn,
            success: true,
            agents: vec![AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Succeeded,
                worktree: Some(CheckpointWorktreeRecord {
                    name: "agent-a".to_string(),
                    path: PathBuf::from("worktrees/agent-a"),
                    branch: "maco/agent-a".to_string(),
                }),
                claim: None,
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: vec![PathBuf::from("README.md")],
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: Some(AgentCandidateBinding {
                    version: CANDIDATE_BINDING_VERSION,
                    base_oid: "0123456789012345678901234567890123456789".to_string(),
                    head_oid: "0123456789012345678901234567890123456789".to_string(),
                    state_oid: "1111111111111111111111111111111111111111".to_string(),
                    diff_oid: "2222222222222222222222222222222222222222".to_string(),
                    changed_paths: vec![PathBuf::from("README.md")],
                    patch_bytes: 1,
                }),
                command_completed_binding: None,
                error: None,
            }],
            repo_validation: Vec::new(),
            repo_validation_target: Some(RepoValidationTargetBinding {
                version: CANDIDATE_BINDING_VERSION,
                kind: RepoValidationTargetKind::CombinedCandidate,
                base_oid: "0123456789012345678901234567890123456789".to_string(),
                combined_diff_oid: "3333333333333333333333333333333333333333".to_string(),
                changed_paths: vec![PathBuf::from("README.md")],
                candidate_count: 1,
                patch_count: 1,
                aggregate_patch_bytes: 1,
            }),
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };

        let checkpoint_dir = temp.path().join("checkpoints");
        let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
        assert_eq!(path, checkpoint_path(&checkpoint_dir, &run_id));
        let loaded = read_run_checkpoint(&path).expect("read checkpoint");
        assert_eq!(loaded, checkpoint);
    }

    #[test]
    fn fresh_same_run_id_preserves_existing_checkpoint_and_guides_resume() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let run_id = RunId::new("fresh-collision").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path,
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("first checkpoint");
        let before = fs::read(&path).expect("read existing checkpoint");

        let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
            .expect_err("fresh run id collision must be refused");
        assert!(error.to_string().contains("orchestrate resume"));
        assert_eq!(fs::read(&path).expect("re-read checkpoint"), before);
        assert_eq!(
            read_run_checkpoint(&path).expect("existing remains valid"),
            checkpoint
        );
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_round_trips_non_utf8_repo_and_completed_candidate_paths() {
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"repo-\xff".to_vec()));
        Repository::init(&repo_path).expect("init non-UTF-8 repo");
        let candidate_path =
            PathBuf::from(std::ffi::OsString::from_vec(b"candidate-\xfe.sh".to_vec()));
        let plan_file = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"plan-\xfd.json".to_vec()));
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: RunId::new("lossless-command-completion").expect("run id"),
            stage: RunCheckpointStage::AgentsCompleted,
            repo: repo_path.clone(),
            repo_head: None,
            plan_file,
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: vec![AgentCheckpoint {
                id: "lossless".to_string(),
                status: AgentRunStatus::Succeeded,
                worktree: Some(CheckpointWorktreeRecord {
                    name: "lossless".to_string(),
                    path: repo_path.join(std::ffi::OsString::from_vec(b"worktree-\xfc".to_vec())),
                    branch: "maco/lossless".to_string(),
                }),
                claim: None,
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: vec![candidate_path.clone()],
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: Some(CompletedCommandStateBinding {
                    version: CANDIDATE_BINDING_VERSION,
                    base_oid: "0123456789012345678901234567890123456789".to_string(),
                    head_oid: "0123456789012345678901234567890123456789".to_string(),
                    state_oid: "1111111111111111111111111111111111111111".to_string(),
                    changed_paths: vec![candidate_path],
                }),
                error: None,
            }],
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
        let loaded = read_run_checkpoint(&path).expect("read checkpoint");
        assert_eq!(loaded, checkpoint);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_command_completed_wal_round_trips_through_resume() {
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            serde_json::to_vec(&serde_json::json!({
                "agents": [{
                    "id": "lossless-wal",
                    "paths": ["out"],
                    "command": r#"mkdir -p out; name=$(printf 'raw-\377.txt'); printf 'once\n' > "out/$name""#
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
        let run_id = RunId::new("lossless-command-completed-wal").expect("run id");
        install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
        let first_error = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path.clone(),
                plan_file: plan_file.clone(),
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(run_id.clone()),
                checkpoint_dir: Some(checkpoint_dir.clone()),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Off,
            },
        )
        .expect_err("stop after command_completed WAL append");
        assert!(
            first_error
                .to_string()
                .contains("injected checkpoint event failure"),
            "{first_error:#}"
        );

        let raw_path =
            PathBuf::from("out").join(std::ffi::OsString::from_vec(b"raw-\xff.txt".to_vec()));
        let checkpoint_file = checkpoint_path(&checkpoint_dir, &run_id);
        let recovered = read_run_checkpoint(&checkpoint_file).expect("decode command WAL");
        assert_eq!(recovered.repo, repo_path);
        assert!(recovered.agents[0]
            .command_completed_binding
            .as_ref()
            .expect("command completion binding")
            .changed_paths
            .contains(&raw_path));

        let summary = resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file,
            repo: Some(repo_path.clone()),
            plan_file: Some(plan_file),
            jobs: 1,
            patch_dir: None,
        })
        .expect("resume non-UTF-8 completed command");
        assert!(summary.success);
        assert!(summary.agents[0].changed_paths.contains(&raw_path));
        let worktree = WorktreeManager::new(&repo_path)
            .list()
            .expect("list worktrees")
            .into_iter()
            .find(|record| record.name == "lossless-wal")
            .expect("lossless worktree");
        assert_eq!(
            fs::read(worktree.path.join(raw_path)).expect("read non-UTF-8 candidate"),
            b"once\n"
        );
    }

    #[test]
    fn checkpoint_v1_v2_are_rejected_with_start_new_run_guidance() {
        for version in [1_u32, 2_u32] {
            let temp = TempDir::new().expect("tempdir");
            let checkpoint = RunCheckpoint {
                version,
                run_id: RunId::new(format!("legacy-v{version}")).expect("run id"),
                stage: RunCheckpointStage::WorktreesSelected,
                repo: PathBuf::from("repo"),
                repo_head: None,
                plan_file: PathBuf::from("plan.json"),
                plan_snapshot: None,
                keep_claims: false,
                worktree_reuse_policy: WorktreeReusePolicy::Clean,
                semantic_coordination: SemanticCoordinationMode::Off,
                success: false,
                agents: Vec::new(),
                repo_validation: Vec::new(),
                repo_validation_target: None,
                released_claims: Vec::new(),
                release_errors: Vec::new(),
                released_semantic_intents: Vec::new(),
                semantic_release_errors: Vec::new(),
                updated_unix_ms: 1,
            };
            let checkpoint_dir = temp.path().join("checkpoints");
            let root = SecureOutputRoot::create_new(&checkpoint_dir).expect("checkpoint root");
            let mut slot = root
                .reserve(OsStr::new(&format!("legacy-v{version}.json")))
                .expect("legacy slot");
            slot.write_json_atomic(&checkpoint, CHECKPOINT_REFERENCE_MAX_BYTES)
                .expect("write legacy checkpoint");
            let path = slot.path().to_path_buf();

            let error = read_run_checkpoint(&path).expect_err("legacy checkpoint must be rejected");
            assert!(error.to_string().contains(&format!("version {version}")));
            assert!(error.to_string().contains("v3"));
            assert!(error.to_string().contains("start a new run"));
        }
    }

    #[test]
    fn checkpoint_controls_write_final_run_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"true"}]}"#,
        )
        .expect("write plan");
        let run_id = RunId::new("checkpoint-test").expect("run id");

        let summary = run_plan_file_with_controls(
            OrchestrationRunOptions {
                repo: repo_path,
                plan_file,
                keep_claims: false,
                jobs: 1,
                patch_dir: None,
            },
            OrchestrationRunControls {
                run_id: Some(run_id.clone()),
                checkpoint_dir: Some(checkpoint_dir.clone()),
                worktree_reuse_policy: None,
                semantic_coordination: SemanticCoordinationMode::Off,
            },
        )
        .expect("run plan");

        assert!(summary.success);
        let checkpoint =
            read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
        assert_eq!(checkpoint.stage, RunCheckpointStage::Final);
        assert!(checkpoint.success);
        assert_eq!(checkpoint.agents[0].id, "agent-a");
    }

    #[cfg(unix)]
    #[test]
    fn agent_command_drains_large_output_before_timeout() {
        let temp = TempDir::new().expect("tempdir");
        let result = run_agent_command(CommandRunSpec {
            command: "i=0; while [ \"$i\" -lt 128 ]; do printf '%4096s' O; printf '%4096s' E >&2; i=$((i + 1)); done".to_string(),
            workspace_root: temp.path().to_path_buf(),
            working_directory: temp.path().to_path_buf(),
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(3)),
            visible_read_only_roots: Vec::new(),
            hidden_roots: Vec::new(),
            runtime: OrchestrationExecutionRuntime::NonpublishableSimulation,
        })
        .expect("run large-output agent command");

        assert!(result.status.is_some_and(|status| status.success()));
        assert!(!result.timed_out);
        assert!(result.stdout.truncated);
        assert!(result.stderr.truncated);
        assert_eq!(result.process_error, None);
    }

    #[cfg(unix)]
    #[test]
    fn candidate_capture_preserves_non_utf8_and_replacement_character_paths_without_index_writes() {
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# paths\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "lossless-path-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");
        let raw = b"raw-\xff.txt".to_vec();
        let replacement = "raw-\u{fffd}.txt";
        fs::write(worktree.path.join(OsString::from_vec(raw.clone())), "raw\n")
            .expect("write raw path");
        fs::write(worktree.path.join(replacement), "replacement\n")
            .expect("write replacement path");
        let base_oid = current_head_oid(&repo_path).expect("base");
        let state = capture_consistent_candidate_state(
            &worktree.path,
            &base_oid,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture both candidate paths");
        let captured = capture_bound_candidate(
            &worktree.path,
            &base_oid,
            &state,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture exact candidate patch");

        let worktree_repo =
            crate::git_repository::open(&worktree.path).expect("open worktree repo");
        let index = worktree_repo.index().expect("open linked index");
        let indexed = index
            .iter()
            .map(|entry| entry.path)
            .collect::<BTreeSet<_>>();
        assert!(!indexed.contains(&raw));
        assert!(!indexed.contains(replacement.as_bytes()));
        assert!(captured
            .binding
            .changed_paths
            .contains(&PathBuf::from(OsString::from_vec(raw))));
        assert!(captured
            .binding
            .changed_paths
            .contains(&PathBuf::from(replacement)));
        assert!(!captured.patch.is_empty());
    }

    #[test]
    fn patch_guard_cleans_unused_reservation_and_rejects_exact_capture_boundary() {
        let temp = TempDir::new().expect("tempdir");
        let root =
            SecureOutputRoot::create_new(&temp.path().join("patches")).expect("create patch root");
        let slot = root
            .reserve(OsStr::new("agent-a.patch"))
            .expect("reserve patch");
        let path = slot.path().to_path_buf();
        drop(PatchOutputGuard::new(slot));

        assert!(!path.exists(), "drop left an unused reserved patch leaf");
        assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES - 1).is_ok());
        assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn retained_checkpoint_writer_rejects_leaf_rebinding_without_clobbering_sentinel() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        let run_id = RunId::new("secure-checkpoint").expect("run id");
        let controls = OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        };
        let mut writer =
            prepare_run_checkpoint_writer(&controls, &Some(run_id.clone()), &repo_path, &[])
                .expect("prepare writer")
                .expect("configured writer");
        let path = writer.slot.path().to_path_buf();
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id,
            stage: RunCheckpointStage::WorktreesSelected,
            repo: repo_path,
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        writer.write(&checkpoint).expect("initial checkpoint write");
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, "untouched").expect("write sentinel");
        fs::remove_file(&path).expect("remove checkpoint leaf");
        symlink(&sentinel, &path).expect("rebind checkpoint leaf");

        assert!(writer.write(&checkpoint).is_err());
        assert_eq!(
            fs::read_to_string(&sentinel).expect("read sentinel"),
            "untouched"
        );
    }

    fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
        let mut index = repo.index().context("open index")?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .context("add all")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .context("commit")
    }
}
