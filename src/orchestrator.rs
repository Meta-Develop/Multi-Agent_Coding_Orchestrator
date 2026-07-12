use crate::{
    process_runner::{
        read_bounded_regular_file_nofollow, run_process, trusted_system_executable, CapturedBytes,
        EnvironmentMode, ProcessRunError, ProcessSpec, Shell, SideEffectConfinementProfile,
        StdinMode, StrictOfflineWorkspaceProfile, WorkspaceAccess,
    },
    secure_output::{ReservedOutputFile, SecureOutputRoot},
    semantic_coord::{
        SemanticConflict, SemanticCoordinationReport, SemanticIntent, SemanticIntentRequest,
        SemanticIntentStore, SemanticIntentToken,
    },
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
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_CAPTURE_LIMIT_BYTES: usize = OUTPUT_CHAR_LIMIT * 4;
const CHECKPOINT_STATE_VERSION: u32 = 1;
const GIT_COMMAND_CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_ADMIN_SNAPSHOT_MAX_ENTRIES: usize = 4096;
const GIT_ADMIN_SNAPSHOT_MAX_BYTES: usize = 64 * 1024 * 1024;
const PATCH_OUTPUT_MAX_BYTES: usize = 64 * 1024 * 1024;
const CHECKPOINT_OUTPUT_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitAdminSnapshotEntry {
    kind: &'static str,
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
    digest: Option<Oid>,
}

#[derive(Debug)]
struct LinkedGitAdminWriteGuard {
    directory: PathBuf,
    device: u64,
    inode: u64,
    snapshot: BTreeMap<PathBuf, GitAdminSnapshotEntry>,
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
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
    #[serde(default)]
    pub released_semantic_intents: Vec<SemanticIntent>,
    #[serde(default)]
    pub semantic_release_errors: Vec<String>,
    pub updated_unix_ms: u64,
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
            error: None,
        }
    }
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
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read orchestration plan {}", path.display()))?;
    let raw: RawPlan = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse orchestration plan {}", path.display()))?;

    validate_plan(raw)
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
    let mut acquired_tokens = Vec::new();
    let mut acquired_semantic_tokens = Vec::new();

    let worktrees = select_worktrees(&manager, &store, &repo_head, &plan, worktree_reuse_policy)?;
    for (summary, worktree) in summaries.iter_mut().zip(&worktrees) {
        summary.worktree_reused = worktree.reused;
        summary.worktree = Some(worktree.record().clone());
    }
    let mut checkpoint_writer =
        prepare_run_checkpoint_writer(&controls, &run_id, &summaries, false)?;
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
            released_claims: &[],
            release_errors: &[],
            released_semantic_intents: &[],
            semantic_release_errors: &[],
        },
    )?;

    for (index, agent) in plan.agents.iter().enumerate() {
        let claim = match store.claim_paths(&agent.id, agent.paths.iter()) {
            Ok(claim) => claim,
            Err(error) => {
                summaries[index].status = AgentRunStatus::Failed;
                summaries[index].error = Some(format!("failed to claim paths: {error}"));
                for (skipped_index, skipped) in summaries.iter_mut().enumerate() {
                    if skipped_index != index && skipped.status == AgentRunStatus::Pending {
                        skipped.status = AgentRunStatus::Skipped;
                        skipped.error = Some(format!(
                            "skipped because paths could not be claimed for agent '{}'",
                            agent.id
                        ));
                    }
                }
                let (released_claims, release_errors) = if options.keep_claims {
                    (Vec::new(), Vec::new())
                } else {
                    release_claims(&store, acquired_tokens)
                };
                let (released_semantic_intents, semantic_release_errors) = if options.keep_claims {
                    (Vec::new(), Vec::new())
                } else {
                    release_semantic_intents(&semantic_store, acquired_semantic_tokens)
                };
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
                        success: false,
                        agents: &summaries,
                        repo_validation: &repo_validation,
                        released_claims: &released_claims,
                        release_errors: &release_errors,
                        released_semantic_intents: &released_semantic_intents,
                        semantic_release_errors: &semantic_release_errors,
                    },
                )?;
                return Ok(OrchestrationSummary {
                    run_id,
                    repo,
                    plan_file: options.plan_file,
                    keep_claims: options.keep_claims,
                    worktree_reuse_policy,
                    semantic_coordination,
                    success: false,
                    agents: summaries,
                    repo_validation,
                    released_claims,
                    release_errors,
                    released_semantic_intents,
                    semantic_release_errors,
                });
            }
        };
        acquired_tokens.push(claim.token);
        summaries[index].claim = Some(claim);
    }
    if semantic_coordination != SemanticCoordinationMode::Off {
        if let Some(blocked_index) = coordinate_semantic_intents(
            &semantic_store,
            &plan,
            &mut summaries,
            semantic_coordination,
            &mut acquired_semantic_tokens,
        ) {
            let blocked_agent = summaries[blocked_index].id.clone();
            for (skipped_index, skipped) in summaries.iter_mut().enumerate() {
                if skipped_index != blocked_index && skipped.status == AgentRunStatus::Pending {
                    skipped.status = AgentRunStatus::Skipped;
                    skipped.error = Some(format!(
                        "skipped because semantic coordination failed for agent '{blocked_agent}'"
                    ));
                }
            }
            let (released_claims, release_errors) = if options.keep_claims {
                (Vec::new(), Vec::new())
            } else {
                release_claims(&store, acquired_tokens)
            };
            let (released_semantic_intents, semantic_release_errors) = if options.keep_claims {
                (Vec::new(), Vec::new())
            } else {
                release_semantic_intents(&semantic_store, acquired_semantic_tokens)
            };
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
                    success: false,
                    agents: &summaries,
                    repo_validation: &repo_validation,
                    released_claims: &released_claims,
                    release_errors: &release_errors,
                    released_semantic_intents: &released_semantic_intents,
                    semantic_release_errors: &semantic_release_errors,
                },
            )?;
            return Ok(OrchestrationSummary {
                run_id,
                repo,
                plan_file: options.plan_file,
                keep_claims: options.keep_claims,
                worktree_reuse_policy,
                semantic_coordination,
                success: false,
                agents: summaries,
                repo_validation,
                released_claims,
                release_errors,
                released_semantic_intents,
                semantic_release_errors,
            });
        }
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
            released_claims: &[],
            release_errors: &[],
            released_semantic_intents: &[],
            semantic_release_errors: &[],
        },
    )?;

    run_agent_schedule_with_patch_dir(
        &plan,
        &mut summaries,
        &worktrees,
        options.jobs,
        options.patch_dir.as_deref(),
        &repo_head,
        runtime,
    )?;
    if summaries
        .iter()
        .all(|summary| summary.status == AgentRunStatus::Succeeded)
    {
        repo_validation = run_repo_validation_commands(&plan, &repo, runtime);
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
            released_claims: &[],
            release_errors: &[],
            released_semantic_intents: &[],
            semantic_release_errors: &[],
        },
    )?;

    let (released_claims, release_errors) = if options.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_claims(&store, acquired_tokens)
    };
    let (released_semantic_intents, semantic_release_errors) = if options.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_semantic_intents(&semantic_store, acquired_semantic_tokens)
    };
    let success = release_errors.is_empty()
        && semantic_release_errors.is_empty()
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
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    })
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

    let checkpoint = read_run_checkpoint(&options.checkpoint_file)?;
    let checkpoint_dir = options
        .checkpoint_file
        .parent()
        .map(Path::to_path_buf)
        .context("checkpoint file must have a parent directory")?;
    let expected_checkpoint_path = checkpoint_path(&checkpoint_dir, &checkpoint.run_id);
    if expected_checkpoint_path != options.checkpoint_file {
        bail!(
            "checkpoint file {} does not match run id '{}'; expected {}",
            options.checkpoint_file.display(),
            checkpoint.run_id.as_str(),
            expected_checkpoint_path.display()
        );
    }

    let checkpoint_repo = discover_repo_root(&checkpoint.repo).with_context(|| {
        format!(
            "failed to validate checkpoint repository {}",
            checkpoint.repo.display()
        )
    })?;
    let repo = match options.repo.as_deref() {
        Some(repo) => {
            let repo = discover_repo_root(repo)?;
            if repo != checkpoint_repo {
                bail!(
                    "checkpoint belongs to repository {}, but resume was requested for {}",
                    checkpoint_repo.display(),
                    repo.display()
                );
            }
            repo
        }
        None => checkpoint_repo,
    };
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
    let worktrees =
        validate_resume_worktrees(&manager, &plan, &checkpoint, &mut summaries, &repo_head)?;

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
    let mut checkpoint_writer = prepare_run_checkpoint_writer(
        &controls,
        &Some(checkpoint.run_id.clone()),
        &summaries,
        true,
    )?;
    let acquired_tokens = acquire_resume_claims(&store, &plan, &mut summaries)?;
    let mut acquired_semantic_tokens =
        active_checkpoint_semantic_tokens(&semantic_store, &summaries)?;
    let had_pending_agents = summaries
        .iter()
        .any(|summary| summary.status == AgentRunStatus::Pending);
    let has_checkpoint_semantic_reports = summaries
        .iter()
        .any(|summary| summary.semantic_intent.is_some() || !summary.semantic_conflicts.is_empty());
    if checkpoint.semantic_coordination != SemanticCoordinationMode::Off
        && had_pending_agents
        && !has_checkpoint_semantic_reports
    {
        if let Some(blocked_index) = coordinate_semantic_intents(
            &semantic_store,
            &plan,
            &mut summaries,
            checkpoint.semantic_coordination,
            &mut acquired_semantic_tokens,
        ) {
            let blocked_agent = summaries[blocked_index].id.clone();
            for (skipped_index, skipped) in summaries.iter_mut().enumerate() {
                if skipped_index != blocked_index && skipped.status == AgentRunStatus::Pending {
                    skipped.status = AgentRunStatus::Skipped;
                    skipped.error = Some(format!(
                        "skipped because semantic coordination failed for agent '{blocked_agent}'"
                    ));
                }
            }
            let (released_claims, release_errors) = if checkpoint.keep_claims {
                (Vec::new(), Vec::new())
            } else {
                release_claims(&store, acquired_tokens)
            };
            let (released_semantic_intents, semantic_release_errors) = if checkpoint.keep_claims {
                (Vec::new(), Vec::new())
            } else {
                release_semantic_intents(&semantic_store, acquired_semantic_tokens)
            };
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
                    success: false,
                    agents: &summaries,
                    repo_validation: &checkpoint.repo_validation,
                    released_claims: &released_claims,
                    release_errors: &release_errors,
                    released_semantic_intents: &released_semantic_intents,
                    semantic_release_errors: &semantic_release_errors,
                },
            )?;
            return Ok(OrchestrationSummary {
                run_id: Some(checkpoint.run_id),
                repo,
                plan_file,
                keep_claims: checkpoint.keep_claims,
                worktree_reuse_policy: checkpoint.worktree_reuse_policy,
                semantic_coordination: checkpoint.semantic_coordination,
                success: false,
                agents: summaries,
                repo_validation: checkpoint.repo_validation,
                released_claims,
                release_errors,
                released_semantic_intents,
                semantic_release_errors,
            });
        }
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
            released_claims: &[],
            release_errors: &[],
            released_semantic_intents: &[],
            semantic_release_errors: &[],
        },
    )?;

    run_agent_schedule_with_patch_dir(
        &plan,
        &mut summaries,
        &worktrees,
        options.jobs,
        options.patch_dir.as_deref(),
        &repo_head,
        runtime,
    )?;
    let repo_validation = if summaries
        .iter()
        .all(|summary| summary.status == AgentRunStatus::Succeeded)
    {
        if had_pending_agents || checkpoint.repo_validation.is_empty() {
            run_repo_validation_commands(&plan, &repo, runtime)
        } else {
            checkpoint.repo_validation.clone()
        }
    } else {
        checkpoint.repo_validation.clone()
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
            released_claims: &[],
            release_errors: &[],
            released_semantic_intents: &[],
            semantic_release_errors: &[],
        },
    )?;

    let (released_claims, release_errors) = if checkpoint.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_claims(&store, acquired_tokens)
    };
    let (released_semantic_intents, semantic_release_errors) = if checkpoint.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_semantic_intents(&semantic_store, acquired_semantic_tokens)
    };
    let success = release_errors.is_empty()
        && semantic_release_errors.is_empty()
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
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    })
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

        let worktree_repo = Repository::open(&current.path).with_context(|| {
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
            }
            AgentRunStatus::Failed | AgentRunStatus::Skipped => {}
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
) -> Result<Vec<ClaimToken>> {
    let mut tokens = Vec::new();

    for (agent, summary) in plan.agents.iter().zip(summaries.iter_mut()) {
        if let Some(active_claim) = find_active_resume_claim(store, agent, summary.claim.as_ref())?
        {
            summary.claim = Some(active_claim.clone());
            tokens.push(active_claim.token);
            continue;
        }

        let claim = store
            .claim_paths(&agent.id, agent.paths.iter())
            .with_context(|| {
                format!(
                    "failed to acquire resume claim for agent '{}' on checkpoint paths",
                    agent.id
                )
            })?;
        tokens.push(claim.token);
        summary.claim = Some(claim);
    }

    Ok(tokens)
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
    summaries: &[AgentRunSummary],
) -> Result<Vec<SemanticIntentToken>> {
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
        .collect();
    Ok(tokens)
}

fn coordinate_semantic_intents(
    store: &SemanticIntentStore,
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    mode: SemanticCoordinationMode,
    acquired_tokens: &mut Vec<SemanticIntentToken>,
) -> Option<usize> {
    let mut planned_preview_intents = Vec::new();
    for (index, agent) in plan.agents.iter().enumerate() {
        let request = semantic_request_for_agent(agent);
        let report = match mode {
            SemanticCoordinationMode::Off => return None,
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
                return Some(index);
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
            return Some(index);
        }
    }

    None
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
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    } = parts;
    let success = release_errors.is_empty()
        && semantic_release_errors.is_empty()
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
    if seconds == 0 {
        bail!("timeout must be greater than zero seconds");
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

        manager.create(WorktreeCreateOptions {
            agent_id: agent.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        })?;
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
    let repo = Repository::open(&record.path).with_context(|| {
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
    let repo = Repository::open(&record.path).with_context(|| {
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

fn run_agent_schedule_with_patch_dir(
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    worktrees: &[SelectedWorktree],
    jobs: usize,
    patch_dir: Option<&Path>,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<()> {
    let mut patch_outputs = prepare_patch_outputs(patch_dir, plan, summaries, worktrees)?;
    let schedule_result = run_agent_schedule(
        plan,
        summaries,
        worktrees,
        jobs,
        &mut patch_outputs,
        base_oid,
        runtime,
    );
    let cleanup_result = cleanup_unused_patch_outputs(patch_outputs);
    match (schedule_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(schedule), Ok(())) => Err(schedule),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(schedule), Err(cleanup)) => Err(schedule.context(format!(
            "also failed to clean unused patch reservations: {cleanup:#}"
        ))),
    }
}

fn run_agent_schedule(
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    worktrees: &[SelectedWorktree],
    jobs: usize,
    patch_outputs: &mut [Option<ReservedOutputFile>],
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<()> {
    if worktrees.len() != summaries.len() || worktrees.len() != plan.agents.len() {
        bail!("selected worktree lease set does not match the orchestration plan");
    }
    for (index, worktree) in worktrees.iter().enumerate() {
        if worktree.record().name != plan.agents[index].id
            || summaries[index].worktree.as_ref() != Some(worktree.record())
        {
            bail!(
                "selected worktree lease for agent '{}' does not match its run summary",
                plan.agents[index].id
            );
        }
    }
    let jobs = jobs.max(1);
    let mut remaining = summaries
        .iter()
        .enumerate()
        .filter(|(_, summary)| summary.status == AgentRunStatus::Pending)
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    let mut succeeded = summaries
        .iter()
        .filter(|summary| summary.status == AgentRunStatus::Succeeded)
        .map(|summary| summary.id.clone())
        .collect::<BTreeSet<_>>();

    if let Some(failed_id) = summaries
        .iter()
        .find(|summary| summary.status == AgentRunStatus::Failed)
        .map(|summary| summary.id.clone())
    {
        for index in remaining {
            summaries[index].status = AgentRunStatus::Skipped;
            summaries[index].error = Some(format!("skipped because agent '{}' failed", failed_id));
        }
        return Ok(());
    }

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .copied()
            .filter(|index| {
                plan.agents[*index]
                    .depends_on
                    .iter()
                    .all(|dependency| succeeded.contains(dependency))
            })
            .take(jobs)
            .collect::<Vec<_>>();

        if ready.is_empty() {
            for index in remaining {
                summaries[index].status = AgentRunStatus::Skipped;
                summaries[index].error =
                    Some("skipped because dependencies could not be satisfied".to_string());
            }
            break;
        }

        let outcomes = run_ready_agents(plan, summaries, worktrees, &ready, runtime)?;
        let mut failed_agent = None;

        for (index, run_result) in outcomes {
            apply_command_result(&mut summaries[index], run_result);
            if summaries[index].status == AgentRunStatus::Succeeded {
                run_agent_validation_commands(
                    &plan.agents[index],
                    &mut summaries[index],
                    &worktrees[index],
                    runtime,
                );
            }
            inspect_agent_changes(
                &plan.agents[index],
                &mut summaries[index],
                &worktrees[index],
                patch_outputs[index].take(),
                base_oid,
                runtime,
            );
            remaining.remove(&index);

            if summaries[index].status == AgentRunStatus::Succeeded {
                succeeded.insert(summaries[index].id.clone());
            } else if failed_agent.is_none() {
                failed_agent = Some(summaries[index].id.clone());
            }
        }

        if let Some(failed_agent) = failed_agent {
            for index in remaining {
                summaries[index].status = AgentRunStatus::Skipped;
                summaries[index].error =
                    Some(format!("skipped because agent '{failed_agent}' failed"));
            }
            break;
        }
    }

    Ok(())
}

fn run_ready_agents(
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    worktrees: &[SelectedWorktree],
    ready: &[usize],
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<(usize, Result<CommandRunResult, ProcessRunError>)>> {
    if ready.len() == 1 {
        let index = ready[0];
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

fn inspect_agent_changes(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    worktree: &SelectedWorktree,
    patch_output: Option<ReservedOutputFile>,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) {
    inspect_agent_changes_at_path(
        agent,
        summary,
        worktree.path(),
        patch_output,
        base_oid,
        runtime,
    );
}

fn inspect_agent_changes_at_path(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    worktree_path: &Path,
    patch_output: Option<ReservedOutputFile>,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) {
    let mut patch_output = patch_output.map(PatchOutputGuard::new);
    if summary.worktree.is_none() {
        fail_summary(summary, "agent has no selected worktree");
        return;
    }
    let worktree_path = worktree_path.to_path_buf();

    let repo = match Repository::open(&worktree_path) {
        Ok(repo) => repo,
        Err(error) => {
            fail_summary(
                summary,
                format!(
                    "failed to inspect worktree changes at {}: {error}",
                    worktree_path.display()
                ),
            );
            return;
        }
    };

    let changed_paths = match collect_paths_changed_since_base(&repo, base_oid) {
        Ok(paths) => paths,
        Err(error) => {
            fail_summary(summary, format!("failed to collect changed paths: {error}"));
            return;
        }
    };
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

    summary.changed_paths = changed_paths;
    summary.unclaimed_changed_paths = unclaimed_changed_paths;

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
        match write_agent_patch(&worktree_path, patch_output, base_oid, runtime) {
            Ok(Some(path)) => summary.patch_path = Some(path),
            Ok(None) => {}
            Err(error) => fail_summary(summary, format!("failed to write patch: {error}")),
        }
    }
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
    let mut paths = statuses
        .iter()
        .filter_map(|entry| entry.path().map(PathBuf::from))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
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

fn insert_delta_path(path: Option<&Path>, paths: &mut BTreeSet<PathBuf>) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        paths.insert(path.to_path_buf());
    }
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn write_agent_patch(
    worktree_path: &Path,
    mut patch_output: ReservedOutputFile,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<Option<PathBuf>> {
    let result = (|| -> Result<Option<Vec<u8>>> {
        mark_untracked_intent_to_add(worktree_path, runtime)?;
        let output = run_fixed_git(
            worktree_path,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                &base_oid.to_string(),
            ],
            WorkspaceAccess::ReadOnly,
            runtime,
        )
        .with_context(|| format!("failed to run git diff in {}", worktree_path.display()))?;
        if !output.status.success() {
            bail!(
                "git diff failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok((!output.stdout.is_empty()).then_some(output.stdout))
    })();
    match result {
        Ok(Some(bytes)) => {
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
            if let Err(error) = patch_output.write_bytes_atomic(&bytes, PATCH_OUTPUT_MAX_BYTES) {
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
        Ok(None) => {
            patch_output.remove()?;
            Ok(None)
        }
        Err(error) => {
            let patch_path = patch_output.path().to_path_buf();
            match patch_output.remove() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(format!(
                    "also failed to clean reserved patch {}: {cleanup:#}",
                    patch_path.display()
                ))),
            }
        }
    }
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

fn mark_untracked_intent_to_add(
    worktree_path: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> Result<()> {
    let output = run_fixed_git(
        worktree_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        WorkspaceAccess::ReadOnly,
        runtime,
    )
    .with_context(|| {
        format!(
            "failed to list untracked files in {}",
            worktree_path.display()
        )
    })?;
    if !output.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(());
    }

    let mut arguments = vec![
        OsString::from("add"),
        OsString::from("-N"),
        OsString::from("--"),
    ];
    for path in paths {
        arguments.push(git_path_argument(path)?);
    }

    let output = run_fixed_git(
        worktree_path,
        arguments,
        WorkspaceAccess::ReadWrite,
        runtime,
    )
    .with_context(|| {
        format!(
            "failed to mark untracked files in {}",
            worktree_path.display()
        )
    })?;
    if !output.status.success() {
        bail!(
            "git add -N failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
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

impl LinkedGitAdminWriteGuard {
    fn capture(worktree_path: &Path) -> Result<Option<Self>> {
        let workspace = fs::canonicalize(worktree_path).with_context(|| {
            format!(
                "failed to canonicalize worktree before Git index write: {}",
                worktree_path.display()
            )
        })?;
        let repository = Repository::open(&workspace).with_context(|| {
            format!(
                "failed to open worktree before Git index write: {}",
                workspace.display()
            )
        })?;
        let directory = fs::canonicalize(repository.path()).with_context(|| {
            format!(
                "failed to canonicalize linked Git administrative directory: {}",
                repository.path().display()
            )
        })?;
        if directory.starts_with(&workspace) {
            return Ok(None);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let metadata = fs::symlink_metadata(&directory)?;
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o022 != 0
            {
                bail!(
                    "linked Git administrative directory is not an owner-controlled non-writable-by-others directory: {}",
                    directory.display()
                );
            }
            validate_git_index_file(&directory.join("index"), false)?;
            reject_git_index_lock(&directory.join("index.lock"))?;
            let snapshot = snapshot_linked_git_admin(&directory)?;
            Ok(Some(Self {
                directory,
                device: metadata.dev(),
                inode: metadata.ino(),
                snapshot,
            }))
        }
        #[cfg(not(unix))]
        {
            bail!("linked Git administrative index writes require Unix no-follow identity checks")
        }
    }

    fn verify(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let metadata = fs::symlink_metadata(&self.directory)?;
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
            {
                bail!(
                    "linked Git administrative directory identity changed during fixed index write: {}",
                    self.directory.display()
                );
            }
            reject_git_index_lock(&self.directory.join("index.lock"))?;
            validate_git_index_file(&self.directory.join("index"), true)?;
            let after = snapshot_linked_git_admin(&self.directory)?;
            if after != self.snapshot {
                bail!(
                    "fixed git add -N changed linked Git administration outside the authorized index file: {}",
                    self.directory.display()
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            bail!("linked Git administrative verification is unavailable on this platform")
        }
    }
}

#[cfg(unix)]
fn validate_git_index_file(path: &Path, required: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > GIT_ADMIN_SNAPSHOT_MAX_BYTES as u64
    {
        bail!(
            "unsafe linked Git index identity, ownership, links, mode, or size: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn reject_git_index_lock(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!(
            "linked Git index lock already exists or survived the fixed index write: {}",
            path.display()
        ),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn snapshot_linked_git_admin(directory: &Path) -> Result<BTreeMap<PathBuf, GitAdminSnapshotEntry>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut snapshot = BTreeMap::new();
    let mut pending = vec![(directory.to_path_buf(), PathBuf::new())];
    let mut remaining_entries = GIT_ADMIN_SNAPSHOT_MAX_ENTRIES;
    let mut remaining_bytes = GIT_ADMIN_SNAPSHOT_MAX_BYTES;
    while let Some((path, relative)) = pending.pop() {
        for entry in fs::read_dir(&path)
            .with_context(|| format!("failed to enumerate linked Git admin {}", path.display()))?
        {
            if remaining_entries == 0 {
                bail!(
                    "linked Git administrative snapshot exceeded {} entries",
                    GIT_ADMIN_SNAPSHOT_MAX_ENTRIES
                );
            }
            remaining_entries -= 1;
            let entry = entry?;
            let child = entry.path();
            let child_relative = relative.join(entry.file_name());
            if child_relative == Path::new("index") {
                continue;
            }
            if child_relative == Path::new("index.lock") {
                bail!("linked Git index lock exists: {}", child.display());
            }
            let metadata = fs::symlink_metadata(&child)?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "linked Git administrative snapshot refuses symlink: {}",
                    child.display()
                );
            }
            let (kind, digest) = if metadata.is_dir() {
                pending.push((child.clone(), child_relative.clone()));
                ("directory", None)
            } else if metadata.is_file() {
                let length = usize::try_from(metadata.len()).context("Git admin file too large")?;
                if length > remaining_bytes {
                    bail!(
                        "linked Git administrative snapshot exceeded {} bytes",
                        GIT_ADMIN_SNAPSHOT_MAX_BYTES
                    );
                }
                let bytes = read_bounded_regular_file_nofollow(&child, remaining_bytes)?;
                remaining_bytes -= bytes.len();
                (
                    "file",
                    Some(Oid::hash_object(git2::ObjectType::Blob, &bytes)?),
                )
            } else {
                bail!(
                    "linked Git administrative snapshot refuses special entry: {}",
                    child.display()
                );
            };
            snapshot.insert(
                child_relative,
                GitAdminSnapshotEntry {
                    kind,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    mode: metadata.permissions().mode(),
                    length: metadata.len(),
                    digest,
                },
            );
        }
    }
    Ok(snapshot)
}

fn run_fixed_git(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    access: WorkspaceAccess,
    runtime: OrchestrationExecutionRuntime,
) -> Result<std::process::Output> {
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
    let mut profile = match access {
        WorkspaceAccess::ReadOnly => StrictOfflineWorkspaceProfile::read_only(worktree_path),
        WorkspaceAccess::ReadWrite => StrictOfflineWorkspaceProfile::read_write(worktree_path),
    };
    let admin_guard = if access == WorkspaceAccess::ReadWrite {
        LinkedGitAdminWriteGuard::capture(worktree_path)?
    } else {
        None
    };
    if let Some(guard) = &admin_guard {
        profile = profile.with_writable_artifact_root(&guard.directory);
    }
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
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(GIT_COMMAND_TIMEOUT));
    let run_result = run_process(match runtime {
        OrchestrationExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                profile,
            )),
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    });
    let admin_verification = admin_guard.as_ref().map(LinkedGitAdminWriteGuard::verify);
    if let Some(verification) = admin_verification {
        verification?;
    }
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

    Ok(CommandRunSpec {
        command: agent.command.clone(),
        workspace_root: worktree.path().to_path_buf(),
        working_directory,
        env: agent.env.clone(),
        timeout: agent.timeout,
        runtime,
    })
}

fn run_agent_validation_commands(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    worktree: &SelectedWorktree,
    runtime: OrchestrationExecutionRuntime,
) {
    let Some(recorded) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree for validation");
        return;
    };
    if recorded != worktree.record() || worktree.record().name != agent.id {
        fail_summary(
            summary,
            format!(
                "agent '{}' selected worktree does not match its exclusive execution lease",
                agent.id
            ),
        );
        return;
    }
    let worktree_path = worktree.path().to_path_buf();

    for validation in &agent.validation_commands {
        let run_summary = run_validation_command(validation, &worktree_path, runtime);
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
}

fn run_repo_validation_commands(
    plan: &OrchestrationPlan,
    repo: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> Vec<ValidationRunSummary> {
    let mut summaries = Vec::new();
    for validation in &plan.repo_validation_commands {
        let run_summary = run_validation_command(validation, repo, runtime);
        let failed = run_summary.status != AgentRunStatus::Succeeded;
        summaries.push(run_summary);
        if failed {
            break;
        }
    }
    summaries
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
    let result = run_agent_command(CommandRunSpec {
        command: validation.command.clone(),
        workspace_root: root.to_path_buf(),
        working_directory,
        env: validation.env.clone(),
        timeout: validation.timeout,
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
    runtime: OrchestrationExecutionRuntime,
}

fn run_agent_command(spec: CommandRunSpec) -> Result<CommandRunResult, ProcessRunError> {
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
                StrictOfflineWorkspaceProfile::read_write(spec.workspace_root),
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
    released_claims: &'a [PathClaim],
    release_errors: &'a [String],
    released_semantic_intents: &'a [SemanticIntent],
    semantic_release_errors: &'a [String],
}

#[derive(Debug)]
struct RunCheckpointWriter {
    slot: ReservedOutputFile,
}

impl RunCheckpointWriter {
    fn write(&mut self, checkpoint: &RunCheckpoint) -> Result<()> {
        self.slot
            .write_json_atomic(checkpoint, CHECKPOINT_OUTPUT_MAX_BYTES)
            .with_context(|| format!("failed to write checkpoint {}", self.slot.path().display()))
    }
}

fn prepare_run_checkpoint_writer(
    controls: &OrchestrationRunControls,
    run_id: &Option<RunId>,
    summaries: &[AgentRunSummary],
    existing_only: bool,
) -> Result<Option<RunCheckpointWriter>> {
    let Some(directory) = controls.checkpoint_dir.as_deref() else {
        return Ok(None);
    };
    let run_id = run_id
        .as_ref()
        .context("checkpoint directory requires a resolved run id")?;
    let root = if existing_only {
        SecureOutputRoot::open_private(directory)?
    } else {
        SecureOutputRoot::open_or_create(directory)?
    };
    for summary in summaries {
        if let Some(worktree) = &summary.worktree {
            root.reject_inside(&worktree.path)?;
        }
    }
    let name = checkpoint_file_name(run_id);
    let slot = if existing_only {
        root.open_existing_leaf(OsStr::new(&name))?
    } else {
        root.open_or_reserve(OsStr::new(&name))?
    };
    Ok(Some(RunCheckpointWriter { slot }))
}

pub fn write_run_checkpoint(directory: &Path, checkpoint: &RunCheckpoint) -> Result<PathBuf> {
    let root = SecureOutputRoot::open_or_create(directory)?;
    let name = checkpoint_file_name(&checkpoint.run_id);
    let mut writer = RunCheckpointWriter {
        slot: root.open_or_reserve(OsStr::new(&name))?,
    };
    writer.write(checkpoint)?;
    Ok(writer.slot.path().to_path_buf())
}

pub fn read_run_checkpoint(path: &Path) -> Result<RunCheckpoint> {
    let parent = path
        .parent()
        .with_context(|| format!("checkpoint must have a parent: {}", path.display()))?;
    let name = path
        .file_name()
        .with_context(|| format!("checkpoint must have a file name: {}", path.display()))?;
    let root = SecureOutputRoot::open_private(parent)?;
    let slot = root.open_existing_leaf(name)?;
    let contents = slot.read_bounded(CHECKPOINT_OUTPUT_MAX_BYTES)?;
    let contents = std::str::from_utf8(&contents)
        .with_context(|| format!("checkpoint is not UTF-8: {}", path.display()))?;
    let checkpoint: RunCheckpoint = serde_json::from_str(contents)
        .with_context(|| format!("failed to parse checkpoint {}", path.display()))?;
    if checkpoint.version != CHECKPOINT_STATE_VERSION {
        bail!(
            "unsupported checkpoint version {} in {}",
            checkpoint.version,
            path.display()
        );
    }
    Ok(checkpoint)
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
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("orchestration requires a non-bare repository")
}

fn current_head_oid(repo_path: &Path) -> Result<Oid> {
    let repo = Repository::open(repo_path)
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
    use std::sync::mpsc;
    use tempfile::TempDir;

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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        commit_all(&repo, "initial commit").expect("commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let unrelated = manager
            .create(WorktreeCreateOptions {
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
        let repo = Repository::open(&repo_path).expect("open repo");
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

    #[test]
    fn run_plan_reports_failed_command_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        assert_eq!(summary.agents[0].status, AgentRunStatus::Skipped);
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");

        let manager = WorktreeManager::new(&repo_path);
        let agent_a_worktree = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create(WorktreeCreateOptions {
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
        let run_id = RunId::new("resume-skip").expect("run id");
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
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        commit_all(&repo, "initial commit").expect("commit");
        let manager = WorktreeManager::new(&repo_path);
        let worktree = manager
            .create(WorktreeCreateOptions {
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
                error: None,
            }],
            repo_validation: Vec::new(),
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create(WorktreeCreateOptions {
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
        let run_id = RunId::new("resume-semantic").expect("run id");
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
                    status: AgentRunStatus::Succeeded,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                    claim: Some(claim_a),
                    semantic_intent: Some(semantic_a.intent.clone()),
                    semantic_conflicts: semantic_a.conflicts.clone(),
                    changed_paths: vec![PathBuf::from("a.txt")],
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
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
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
        fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
        fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
        commit_all(&repo, "initial commit").expect("commit");

        let manager = WorktreeManager::new(&repo_path);
        let agent_a_worktree = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b_worktree = manager
            .create(WorktreeCreateOptions {
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
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
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
        assert_eq!(summary.agents[0].status, AgentRunStatus::Skipped);
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
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
                error: None,
            }],
            repo_validation: Vec::new(),
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# v1\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
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
        let worktree_repo = Repository::open(worktree.path).expect("open worktree");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
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
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
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
    fn checkpoint_helpers_round_trip_serialized_state() {
        let temp = TempDir::new().expect("tempdir");
        let run_id = RunId::new("run-1").expect("run id");
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id: run_id.clone(),
            stage: RunCheckpointStage::Final,
            repo: PathBuf::from("repo"),
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
                error: None,
            }],
            repo_validation: Vec::new(),
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
    fn checkpoint_controls_write_final_run_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let checkpoint_dir = temp.path().join("checkpoints");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
    fn linked_git_admin_guard_allows_only_safe_index_replacement() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# guarded\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
                agent_id: "guarded-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create worktree");

        let guard = LinkedGitAdminWriteGuard::capture(&worktree.path)
            .expect("capture linked admin")
            .expect("linked admin must be outside worktree");
        let index_path = guard.directory.join("index");
        let index = fs::read(&index_path).expect("read linked index");
        fs::remove_file(&index_path).expect("remove linked index");
        fs::write(&index_path, index).expect("replace linked index");
        guard.verify().expect("safe index replacement");

        let guard = LinkedGitAdminWriteGuard::capture(&worktree.path)
            .expect("recapture linked admin")
            .expect("linked admin must remain external");
        fs::write(guard.directory.join("HEAD"), "ref: refs/heads/tampered\n")
            .expect("tamper linked HEAD");
        assert!(guard.verify().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intent_to_add_preserves_non_utf8_and_replacement_character_paths_distinctly() {
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# paths\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create(WorktreeCreateOptions {
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

        mark_untracked_intent_to_add(
            &worktree.path,
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        )
        .expect("mark both paths intent-to-add");

        let worktree_repo = Repository::open(&worktree.path).expect("open worktree repo");
        let index = worktree_repo.index().expect("open linked index");
        let indexed = index
            .iter()
            .map(|entry| entry.path)
            .collect::<BTreeSet<_>>();
        assert!(indexed.contains(&raw));
        assert!(indexed.contains(replacement.as_bytes()));
    }

    #[test]
    fn patch_guard_cleans_early_inspection_failure_and_rejects_exact_capture_boundary() {
        let temp = TempDir::new().expect("tempdir");
        let root =
            SecureOutputRoot::create_new(&temp.path().join("patches")).expect("create patch root");
        let slot = root
            .reserve(OsStr::new("agent-a.patch"))
            .expect("reserve patch");
        let path = slot.path().to_path_buf();
        let agent = AgentPlan {
            id: "agent-a".to_string(),
            paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            env: BTreeMap::new(),
            timeout: None,
            command: "true".to_string(),
            depends_on: Vec::new(),
            working_directory: None,
            validation_commands: Vec::new(),
        };
        let mut summary = AgentRunSummary::pending(&agent);

        inspect_agent_changes_at_path(
            &agent,
            &mut summary,
            temp.path(),
            Some(slot),
            &Oid::zero(),
            OrchestrationExecutionRuntime::NonpublishableSimulation,
        );

        assert_eq!(summary.status, AgentRunStatus::Failed);
        assert!(!path.exists(), "early return left a reserved patch leaf");
        assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES - 1).is_ok());
        assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn retained_checkpoint_writer_rejects_leaf_rebinding_without_clobbering_sentinel() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let root = SecureOutputRoot::create_new(&temp.path().join("checkpoints"))
            .expect("create checkpoint root");
        let run_id = RunId::new("secure-checkpoint").expect("run id");
        let slot = root
            .reserve(OsStr::new("secure-checkpoint.json"))
            .expect("reserve checkpoint");
        let path = slot.path().to_path_buf();
        let mut writer = RunCheckpointWriter { slot };
        let checkpoint = RunCheckpoint {
            version: CHECKPOINT_STATE_VERSION,
            run_id,
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
