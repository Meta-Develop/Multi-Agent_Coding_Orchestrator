use crate::{
    sync::{normalize_repo_relative_path, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{normalize_agent_id, WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use git2::{Oid, Repository, ResetType};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{self, Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const CHECKPOINT_STATE_VERSION: u32 = 1;

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
    pub success: bool,
    pub agents: Vec<AgentCheckpoint>,
    pub repo_validation: Vec<ValidationRunSummary>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentCheckpoint {
    pub id: String,
    pub status: AgentRunStatus,
    pub worktree: Option<CheckpointWorktreeRecord>,
    pub claim: Option<PathClaim>,
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
    pub success: bool,
    pub agents: Vec<AgentRunSummary>,
    pub repo_validation: Vec<ValidationRunSummary>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
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
    run_plan_with_controls(plan, options, controls)
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
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();
    let mut repo_validation = Vec::new();
    let mut acquired_tokens = Vec::new();

    let worktrees = select_worktrees(&manager, &store, &repo_head, &plan, worktree_reuse_policy)?;
    for (summary, worktree) in summaries.iter_mut().zip(worktrees) {
        summary.worktree_reused = worktree.reused;
        summary.worktree = Some(worktree.record);
    }
    write_checkpoint_if_configured(
        &controls,
        RunCheckpointStage::WorktreesSelected,
        &run_id,
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
                write_checkpoint_if_configured(
                    &controls,
                    RunCheckpointStage::Final,
                    &run_id,
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
                    },
                )?;
                return Ok(OrchestrationSummary {
                    run_id,
                    repo,
                    plan_file: options.plan_file,
                    keep_claims: options.keep_claims,
                    worktree_reuse_policy,
                    success: false,
                    agents: summaries,
                    repo_validation,
                    released_claims,
                    release_errors,
                });
            }
        };
        acquired_tokens.push(claim.token);
        summaries[index].claim = Some(claim);
    }
    write_checkpoint_if_configured(
        &controls,
        RunCheckpointStage::ClaimsAcquired,
        &run_id,
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
        },
    )?;

    run_agent_schedule(
        &plan,
        &mut summaries,
        options.jobs,
        options.patch_dir.as_deref(),
    )?;
    if summaries
        .iter()
        .all(|summary| summary.status == AgentRunStatus::Succeeded)
    {
        repo_validation = run_repo_validation_commands(&plan, &repo);
    }
    write_checkpoint_if_configured(
        &controls,
        RunCheckpointStage::AgentsCompleted,
        &run_id,
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
        },
    )?;

    let (released_claims, release_errors) = if options.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_claims(&store, acquired_tokens)
    };
    let success = release_errors.is_empty()
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
        },
    )?;

    Ok(OrchestrationSummary {
        run_id,
        repo,
        plan_file: options.plan_file,
        keep_claims: options.keep_claims,
        worktree_reuse_policy,
        success,
        agents: summaries,
        repo_validation,
        released_claims,
        release_errors,
    })
}

pub fn resume_plan_file(options: OrchestrationResumeOptions) -> Result<OrchestrationSummary> {
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
    let mut summaries = summaries_from_checkpoint(&plan, &checkpoint)?;
    validate_resume_worktrees(&manager, &plan, &checkpoint, &mut summaries, &repo_head)?;

    if checkpoint.stage == RunCheckpointStage::Final {
        return Ok(summary_from_parts(SummaryParts {
            run_id: checkpoint.run_id,
            repo,
            plan_file,
            keep_claims: checkpoint.keep_claims,
            worktree_reuse_policy: checkpoint.worktree_reuse_policy,
            summaries,
            repo_validation: checkpoint.repo_validation,
            released_claims: checkpoint.released_claims,
            release_errors: checkpoint.release_errors,
        }));
    }

    let acquired_tokens = acquire_resume_claims(&store, &plan, &mut summaries)?;
    let controls = OrchestrationRunControls {
        run_id: Some(checkpoint.run_id.clone()),
        checkpoint_dir: Some(checkpoint_dir),
        worktree_reuse_policy: Some(checkpoint.worktree_reuse_policy),
    };

    write_checkpoint_if_configured(
        &controls,
        RunCheckpointStage::ClaimsAcquired,
        &Some(checkpoint.run_id.clone()),
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
        },
    )?;

    let had_pending_agents = summaries
        .iter()
        .any(|summary| summary.status == AgentRunStatus::Pending);
    run_agent_schedule(
        &plan,
        &mut summaries,
        options.jobs,
        options.patch_dir.as_deref(),
    )?;
    let repo_validation = if summaries
        .iter()
        .all(|summary| summary.status == AgentRunStatus::Succeeded)
    {
        if had_pending_agents || checkpoint.repo_validation.is_empty() {
            run_repo_validation_commands(&plan, &repo)
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
        },
    )?;

    let (released_claims, release_errors) = if checkpoint.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_claims(&store, acquired_tokens)
    };
    let success = release_errors.is_empty()
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
        },
    )?;

    Ok(OrchestrationSummary {
        run_id: Some(checkpoint.run_id),
        repo,
        plan_file,
        keep_claims: checkpoint.keep_claims,
        worktree_reuse_policy: checkpoint.worktree_reuse_policy,
        success,
        agents: summaries,
        repo_validation,
        released_claims,
        release_errors,
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
) -> Result<()> {
    let records = manager
        .list()?
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect::<BTreeMap<_, _>>();

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
        let Some(current) = records.get(&recorded.name) else {
            bail!(
                "checkpoint '{}' references missing worktree '{}' for agent '{}'; restore the worktree or start a new run",
                checkpoint.run_id.as_str(),
                recorded.name,
                agent.id
            );
        };
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
        let worktree_head = head_oid(&worktree_repo)
            .with_context(|| format!("failed to inspect HEAD for worktree '{}'", current.name))?;
        if &worktree_head != repo_head {
            bail!(
                "checkpoint '{}' worktree '{}' is based on {}, but primary HEAD is {}; start a new run or restore the checkpoint base",
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
        match checkpoint_agent.status {
            AgentRunStatus::Pending => {
                if !changed_paths.is_empty() {
                    bail!(
                        "checkpoint '{}' marks agent '{}' as pending, but its worktree has changes; clean the worktree or start a new run",
                        checkpoint.run_id.as_str(),
                        agent.id
                    );
                }
            }
            AgentRunStatus::Succeeded => {
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

struct SummaryParts {
    run_id: RunId,
    repo: PathBuf,
    plan_file: PathBuf,
    keep_claims: bool,
    worktree_reuse_policy: WorktreeReusePolicy,
    summaries: Vec<AgentRunSummary>,
    repo_validation: Vec<ValidationRunSummary>,
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
}

fn summary_from_parts(parts: SummaryParts) -> OrchestrationSummary {
    let SummaryParts {
        run_id,
        repo,
        plan_file,
        keep_claims,
        worktree_reuse_policy,
        summaries,
        repo_validation,
        released_claims,
        release_errors,
    } = parts;
    let success = release_errors.is_empty()
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
        success,
        agents: summaries,
        repo_validation,
        released_claims,
        release_errors,
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

#[derive(Debug, Clone)]
struct SelectedWorktree {
    record: WorktreeRecord,
    reused: bool,
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
        if let Some(record) = existing.remove(&agent.id) {
            if policy == WorktreeReusePolicy::Fresh {
                bail!(
                    "worktree reuse policy 'fresh' requires no existing worktree for agent '{}' at {}",
                    agent.id,
                    record.path.display()
                );
            }
            match policy {
                WorktreeReusePolicy::Reset => {
                    reset_reusable_worktree(store, agent, &record, primary_head)?;
                }
                WorktreeReusePolicy::Clean | WorktreeReusePolicy::Required => {
                    ensure_reusable_worktree(&record, primary_head)?;
                }
                WorktreeReusePolicy::Fresh => {}
            }
            selected.push(SelectedWorktree {
                record,
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

        let record = manager.create(WorktreeCreateOptions {
            agent_id: agent.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        })?;
        selected.push(SelectedWorktree {
            record,
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

fn run_agent_schedule(
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    jobs: usize,
    patch_dir: Option<&Path>,
) -> Result<()> {
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

        let outcomes = run_ready_agents(plan, summaries, &ready)?;
        let mut failed_agent = None;

        for (index, run_result) in outcomes {
            apply_command_result(&mut summaries[index], run_result);
            if summaries[index].status == AgentRunStatus::Succeeded {
                run_agent_validation_commands(&plan.agents[index], &mut summaries[index]);
            }
            inspect_agent_changes(&plan.agents[index], &mut summaries[index], patch_dir);
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
    ready: &[usize],
) -> Result<Vec<(usize, std::io::Result<CommandRunResult>)>> {
    if ready.len() == 1 {
        let index = ready[0];
        let spec = command_spec(&plan.agents[index], &summaries[index])?;
        return Ok(vec![(index, run_agent_command(spec))]);
    }

    let mut handles = Vec::with_capacity(ready.len());
    for index in ready {
        let spec = command_spec(&plan.agents[*index], &summaries[*index])?;
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
    patch_dir: Option<&Path>,
) {
    let Some(worktree) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree");
        return;
    };
    let worktree_path = worktree.path.clone();

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

    let changed_paths = match collect_status_paths(&repo) {
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

    if let Some(patch_dir) = patch_dir {
        match write_agent_patch(&worktree_path, &agent.id, patch_dir) {
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

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn write_agent_patch(
    worktree_path: &Path,
    agent_id: &str,
    patch_dir: &Path,
) -> Result<Option<PathBuf>> {
    fs::create_dir_all(patch_dir)
        .with_context(|| format!("failed to create patch directory {}", patch_dir.display()))?;
    mark_untracked_intent_to_add(worktree_path)?;

    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .arg("diff")
        .arg("--binary")
        .arg("HEAD")
        .output()
        .with_context(|| format!("failed to run git diff in {}", worktree_path.display()))?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.is_empty() {
        return Ok(None);
    }

    let patch_path = patch_dir.join(format!("{agent_id}.patch"));
    fs::write(&patch_path, output.stdout)
        .with_context(|| format!("failed to write patch {}", patch_path.display()))?;
    Ok(Some(patch_path))
}

fn mark_untracked_intent_to_add(worktree_path: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .arg("ls-files")
        .arg("--others")
        .arg("--exclude-standard")
        .arg("-z")
        .output()
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

    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(worktree_path)
        .arg("add")
        .arg("-N")
        .arg("--");
    for path in paths {
        command.arg(String::from_utf8_lossy(path).as_ref());
    }

    let output = command.output().with_context(|| {
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

fn command_spec(agent: &AgentPlan, summary: &AgentRunSummary) -> Result<CommandRunSpec> {
    let worktree = summary
        .worktree
        .as_ref()
        .with_context(|| format!("agent '{}' has no selected worktree", summary.id))?;
    let working_directory = agent
        .working_directory
        .as_ref()
        .map(|path| worktree.path.join(path))
        .unwrap_or_else(|| worktree.path.clone());

    Ok(CommandRunSpec {
        command: agent.command.clone(),
        working_directory,
        env: agent.env.clone(),
        timeout: agent.timeout,
    })
}

fn run_agent_validation_commands(agent: &AgentPlan, summary: &mut AgentRunSummary) {
    let Some(worktree) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree for validation");
        return;
    };
    let worktree_path = worktree.path.clone();

    for validation in &agent.validation_commands {
        let run_summary = run_validation_command(validation, &worktree_path);
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
) -> Vec<ValidationRunSummary> {
    let mut summaries = Vec::new();
    for validation in &plan.repo_validation_commands {
        let run_summary = run_validation_command(validation, repo);
        let failed = run_summary.status != AgentRunStatus::Succeeded;
        summaries.push(run_summary);
        if failed {
            break;
        }
    }
    summaries
}

fn run_validation_command(validation: &ValidationCommandPlan, root: &Path) -> ValidationRunSummary {
    let working_directory = validation
        .working_directory
        .as_ref()
        .map(|path| root.join(path))
        .unwrap_or_else(|| root.to_path_buf());
    let result = run_agent_command(CommandRunSpec {
        command: validation.command.clone(),
        working_directory,
        env: validation.env.clone(),
        timeout: validation.timeout,
    });
    validation_summary_from_result(validation, result)
}

fn validation_summary_from_result(
    validation: &ValidationCommandPlan,
    result: std::io::Result<CommandRunResult>,
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
    working_directory: PathBuf,
    env: BTreeMap<String, String>,
    timeout: Option<Duration>,
}

fn run_agent_command(spec: CommandRunSpec) -> std::io::Result<CommandRunResult> {
    let started = Instant::now();
    let mut command = shell_command(&spec.command);
    configure_timeout_process_control(&mut command);
    let mut child = command
        .current_dir(&spec.working_directory)
        .envs(&spec.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let output = if let Some(timeout) = spec.timeout {
        loop {
            if child.try_wait()?.is_some() {
                let output = child.wait_with_output()?;
                break TimedOutput {
                    status: Some(output.status),
                    timed_out: false,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error: None,
                };
            }

            if command_timed_out(started, timeout) {
                let process_error = terminate_child_on_timeout(&mut child);
                let output = child.wait_with_output()?;
                break TimedOutput {
                    status: Some(output.status),
                    timed_out: true,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error,
                };
            }

            thread::sleep(Duration::from_millis(25));
        }
    } else {
        let output = child.wait_with_output()?;
        TimedOutput {
            status: Some(output.status),
            timed_out: false,
            stdout: output.stdout,
            stderr: output.stderr,
            process_error: None,
        }
    };

    Ok(CommandRunResult {
        status: output.status,
        duration_ms: duration_millis(started.elapsed()),
        timed_out: output.timed_out,
        stdout: summarize_output(&output.stdout),
        stderr: summarize_output(&output.stderr),
        process_error: output.process_error,
    })
}

fn command_timed_out(started: Instant, timeout: Duration) -> bool {
    started.elapsed() >= timeout
}

fn configure_timeout_process_control(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

fn terminate_child_on_timeout(child: &mut Child) -> Option<String> {
    #[cfg(unix)]
    {
        terminate_unix_process_group(child)
    }

    #[cfg(not(unix))]
    {
        child
            .kill()
            .err()
            .map(|error| format!("command timed out but process kill failed: {error}"))
    }
}

#[cfg(unix)]
fn terminate_unix_process_group(child: &mut Child) -> Option<String> {
    let pid = child.id();
    let term_error = send_unix_process_group_signal(pid, "TERM").err();
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return term_error.map(|error| error.to_string()),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => return Some(format!("command timed out but wait failed: {error}")),
        }
    }

    let kill_result = send_unix_process_group_signal(pid, "KILL").or_else(|_| child.kill());
    kill_result.err().map(|error| {
        if let Some(term_error) = term_error {
            format!(
                "command timed out but process group termination failed: {term_error}; kill failed: {error}"
            )
        } else {
            format!("command timed out but process group kill failed: {error}")
        }
    })
}

#[cfg(unix)]
fn send_unix_process_group_signal(pid: u32, signal: &str) -> std::io::Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(unix_process_group_target(pid))
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "kill -{signal} {} exited with {status}",
            unix_process_group_target(pid)
        )))
    }
}

#[cfg(unix)]
fn unix_process_group_target(pid: u32) -> String {
    format!("-{pid}")
}

fn shell_command(command: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut shell = Command::new("cmd");
        shell.arg("/C").arg(command);
        shell
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut shell = Command::new("sh");
        shell.arg("-c").arg(command);
        shell
    }
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

#[derive(Debug)]
struct TimedOutput {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    process_error: Option<String>,
}

fn apply_command_result(summary: &mut AgentRunSummary, result: std::io::Result<CommandRunResult>) {
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

fn summarize_output(output: &[u8]) -> OutputSummary {
    let text = String::from_utf8_lossy(output);
    let mut chars = text.chars();
    let value = chars.by_ref().take(OUTPUT_CHAR_LIMIT).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
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
}

pub fn write_run_checkpoint(directory: &Path, checkpoint: &RunCheckpoint) -> Result<PathBuf> {
    fs::create_dir_all(directory).with_context(|| {
        format!(
            "failed to create checkpoint directory {}",
            directory.display()
        )
    })?;
    let path = checkpoint_path(directory, &checkpoint.run_id);
    let temp_path = temp_checkpoint_path(&path);
    let result = write_checkpoint_file(&temp_path, &path, checkpoint);
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    Ok(path)
}

pub fn read_run_checkpoint(path: &Path) -> Result<RunCheckpoint> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read checkpoint {}", path.display()))?;
    let checkpoint: RunCheckpoint = serde_json::from_str(&contents)
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
    directory.join(format!("{}.json", run_id.as_str()))
}

fn write_checkpoint_if_configured(
    controls: &OrchestrationRunControls,
    stage: RunCheckpointStage,
    run_id: &Option<RunId>,
    view: CheckpointView<'_>,
) -> Result<()> {
    let Some(directory) = controls.checkpoint_dir.as_deref() else {
        return Ok(());
    };
    let Some(run_id) = run_id.clone() else {
        return Ok(());
    };

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
        success: view.success,
        agents: view.agents.iter().map(AgentCheckpoint::from).collect(),
        repo_validation: view.repo_validation.to_vec(),
        released_claims: view.released_claims.to_vec(),
        release_errors: view.release_errors.to_vec(),
        updated_unix_ms: unix_time_millis(),
    };
    write_run_checkpoint(directory, &checkpoint)?;
    Ok(())
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

fn write_checkpoint_file(
    temp_path: &Path,
    checkpoint_path: &Path,
    checkpoint: &RunCheckpoint,
) -> Result<()> {
    let mut file = File::create(temp_path).with_context(|| {
        format!(
            "failed to create temporary checkpoint {}",
            temp_path.display()
        )
    })?;
    serde_json::to_writer_pretty(&mut file, checkpoint).with_context(|| {
        format!(
            "failed to write temporary checkpoint {}",
            temp_path.display()
        )
    })?;
    file.write_all(b"\n").with_context(|| {
        format!(
            "failed to finish temporary checkpoint {}",
            temp_path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "failed to flush temporary checkpoint {}",
            temp_path.display()
        )
    })?;
    drop(file);
    fs::rename(temp_path, checkpoint_path).with_context(|| {
        format!(
            "failed to replace checkpoint {} with {}",
            checkpoint_path.display(),
            temp_path.display()
        )
    })
}

fn temp_checkpoint_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("checkpoint.json");
    path.with_file_name(format!(".{file_name}.{}.tmp", process::id()))
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
    use crate::sync_store::SyncStore;
    use crate::worktree::WorktreeManager;
    use git2::{Oid, Repository, Signature};
    use tempfile::TempDir;

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
            success: false,
            agents: vec![
                AgentCheckpoint {
                    id: "agent-a".to_string(),
                    status: AgentRunStatus::Succeeded,
                    worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                    claim: Some(claim_a),
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
                    changed_paths: Vec::new(),
                    unclaimed_changed_paths: Vec::new(),
                    validation: Vec::new(),
                    error: None,
                },
            ],
            repo_validation: Vec::new(),
            released_claims: Vec::new(),
            release_errors: Vec::new(),
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
            success: false,
            agents: vec![AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&worktree)),
                claim: None,
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                error: None,
            }],
            repo_validation: Vec::new(),
            released_claims: Vec::new(),
            release_errors: Vec::new(),
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
                changed_paths: vec![PathBuf::from("README.md")],
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                error: None,
            }],
            repo_validation: Vec::new(),
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            updated_unix_ms: 1,
        };

        let path = write_run_checkpoint(temp.path(), &checkpoint).expect("write checkpoint");
        assert_eq!(path, checkpoint_path(temp.path(), &run_id));
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

    #[test]
    fn process_control_helpers_are_deterministic() {
        let started = Instant::now() - Duration::from_millis(5);
        assert!(command_timed_out(started, Duration::from_millis(1)));

        #[cfg(unix)]
        assert_eq!(unix_process_group_target(42), "-42");
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
