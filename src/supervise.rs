use crate::{
    artifacts::{self, RunArtifactFamily},
    external_agent::{run_external_agent, ExternalAgentCommand, ExternalAgentRun},
    orchestrator::{RunId, SemanticCoordinationMode},
    semantic_coord::{SemanticIntent, SemanticIntentRequest, SemanticIntentStore},
    sync::{normalize_repo_relative_path, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use git2::{Delta, DiffFindOptions, DiffOptions, Oid, Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 600;
const DEFAULT_MAX_CHILD_ASSIGNMENTS: usize = 4;
const SUPERVISOR_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct SupervisorRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub run_id: RunId,
    pub codex_bin: PathBuf,
    pub allow_dirty_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SupervisorPlan {
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub task: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_file: Option<PathBuf>,
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,
    #[serde(
        default = "default_max_child_assignments",
        alias = "max_child_processes"
    )]
    pub max_child_assignments: usize,
    #[serde(default = "default_child_timeout_seconds")]
    pub child_timeout_seconds: u64,
    #[serde(default)]
    pub semantic_coordination: SemanticCoordinationMode,
    #[serde(default)]
    pub assignments: Vec<OrchestratorAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OrchestratorAssignment {
    pub id: String,
    #[serde(default = "child_orchestrator_role")]
    pub role: AgentRole,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default)]
    pub worker_assignments: Vec<WorkerAssignment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerAssignment {
    pub id: String,
    #[serde(default = "worker_role")]
    pub role: AgentRole,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Supervisor,
    ChildOrchestrator,
    Worker,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerReport {
    pub id: String,
    pub role: AgentRole,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_intent_token: Option<u64>,
    #[serde(default)]
    pub commands_run: Vec<CommandRunRecord>,
    #[serde(default)]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_further_delegation: Option<bool>,
    pub accepted: bool,
    pub rejected: bool,
    pub status: ReviewStatus,
    #[serde(default)]
    pub remaining_risk: String,
    #[serde(default)]
    pub next_safe_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OrchestratorReviewReport {
    pub id: String,
    pub role: AgentRole,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_intent_token: Option<u64>,
    #[serde(default)]
    pub commands_run: Vec<CommandRunRecord>,
    #[serde(default)]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub worker_reports: Vec<WorkerReport>,
    pub accepted: bool,
    pub rejected: bool,
    pub status: ReviewStatus,
    #[serde(default)]
    pub remaining_risk: String,
    #[serde(default)]
    pub next_safe_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SupervisorFinalReport {
    pub version: u32,
    pub run_id: RunId,
    pub role: AgentRole,
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub run_dir: PathBuf,
    pub success: bool,
    pub accepted: bool,
    pub rejected: bool,
    pub status: ReviewStatus,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default)]
    pub claim_tokens: Vec<u64>,
    #[serde(default)]
    pub semantic_intent_tokens: Vec<u64>,
    #[serde(default)]
    pub commands_run: Vec<CommandRunRecord>,
    #[serde(default)]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub orchestrator_reports: Vec<OrchestratorReviewReport>,
    #[serde(default)]
    pub released_claims: Vec<PathClaim>,
    #[serde(default)]
    pub release_errors: Vec<String>,
    #[serde(default)]
    pub released_semantic_intents: Vec<SemanticIntent>,
    #[serde(default)]
    pub semantic_release_errors: Vec<String>,
    pub remaining_risk: String,
    pub next_safe_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommandRunRecord {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub status: ReviewStatus,
    pub timeout_seconds: u64,
    pub duration_ms: u64,
    pub timed_out: bool,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValidationResult {
    pub name: String,
    pub status: ReviewStatus,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub message: String,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Pending,
    Succeeded,
    Failed,
    Rejected,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupervisorStatusReport {
    pub run_id: RunId,
    pub repo: PathBuf,
    pub run_dir: PathBuf,
    pub final_report_path: PathBuf,
    pub final_report_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_report: Option<SupervisorFinalReport>,
}

#[derive(Debug, Clone, Copy)]
pub struct ChildPromptClaimContext<'a> {
    pub claim: &'a PathClaim,
    pub semantic_intent_token: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct ChildOrchestratorPromptContext<'a> {
    pub plan: &'a SupervisorPlan,
    pub assignment: &'a OrchestratorAssignment,
    pub run_dir: &'a Path,
    pub worktree: &'a WorktreeRecord,
    pub report_path: &'a Path,
    pub schema_path: &'a Path,
    pub worker_schema_path: &'a Path,
    pub claim_context: ChildPromptClaimContext<'a>,
}

pub fn supervisor_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<SupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let task = fs::read_to_string(task_file)
        .with_context(|| format!("failed to read task file {}", task_file.display()))?;
    if let Ok(plan) = serde_json::from_str::<SupervisorPlan>(&task) {
        return validate_supervisor_plan(plan);
    }

    Ok(SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task,
        task_file: Some(path_relative_to(&repo, task_file)),
        max_depth: default_max_depth(),
        max_child_assignments: DEFAULT_MAX_CHILD_ASSIGNMENTS,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        assignments: Vec::new(),
    })
}

pub fn load_supervisor_plan_file(path: impl AsRef<Path>) -> Result<SupervisorPlan> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read supervisor plan {}", path.display()))?;
    let plan: SupervisorPlan = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse supervisor plan {}", path.display()))?;
    validate_supervisor_plan(plan)
}

pub fn run_supervisor_plan_file(options: SupervisorRunOptions) -> Result<SupervisorFinalReport> {
    let plan = load_supervisor_plan_file(&options.plan_file)?;
    run_supervisor_plan(plan, options)
}

pub fn supervisor_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<SupervisorStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    let final_report = if final_report_path.exists() {
        Some(read_supervisor_final_report(&final_report_path)?)
    } else {
        None
    };
    Ok(SupervisorStatusReport {
        run_id,
        repo,
        run_dir,
        final_report_exists: final_report.is_some(),
        final_report_path,
        final_report,
    })
}

pub fn collect_supervisor_run(
    repo: impl AsRef<Path>,
    run_id: RunId,
) -> Result<SupervisorFinalReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    if final_report_path.exists() {
        return read_supervisor_final_report(&final_report_path);
    }

    Ok(SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id,
        role: AgentRole::Supervisor,
        repo,
        plan_file: PathBuf::new(),
        run_dir,
        success: false,
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        assigned_paths: Vec::new(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: Vec::new(),
        semantic_intent_tokens: Vec::new(),
        commands_run: Vec::new(),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: "supervisor final report is missing".to_string(),
            paths: vec![final_report_path],
        }],
        orchestrator_reports: Vec::new(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk: "run artifacts are incomplete".to_string(),
        next_safe_action: "rerun supervise run for this run id".to_string(),
    })
}

pub fn child_orchestrator_prompt(context: ChildOrchestratorPromptContext<'_>) -> Result<String> {
    let ChildOrchestratorPromptContext {
        plan,
        assignment,
        run_dir,
        worktree,
        report_path,
        schema_path,
        worker_schema_path,
        claim_context,
    } = context;
    let assignment_json = serde_json::to_string_pretty(assignment)
        .context("failed to serialize orchestrator assignment")?;
    let worker_prompts = assignment
        .worker_assignments
        .iter()
        .map(|worker| worker_prompt(plan, assignment, worker, run_dir, worker_schema_path))
        .collect::<Result<Vec<_>>>()?
        .join("\n\n--- worker prompt contract ---\n\n");
    Ok(format!(
        r#"ROLE: O1_CHILD_ORCHESTRATOR
You are a child orchestrator in an opt-in local Codex CLI supervisor run.
You are not the top supervisor. You are not alone in the repository.
Primary worktree mutation is forbidden. Work only in this assigned child worktree:
{worktree_path}

Ownership:
- Child orchestrator id: {child_id}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Path claim token: {claim_token}
- Semantic intent token: {semantic_intent_token}

Runtime hierarchy:
- Current supervise run contract: O2 supervisor -> O1 child orchestrator -> terminal worker/researcher.
- You are the O1 child orchestrator for this assignment.
- Workers and researchers are terminal: they must not launch further workers, delegate to another worker, or take over peer coordination.
- You must not spawn, impersonate, or take over a peer O2 supervisor.
- The top O2/supervisor may launch peer O2 supervisors as parallel scopes for newly discovered large cross-cutting problems. Report such escalation candidates in findings and remaining_risk instead of taking them over.

Required behavior:
- First, read and follow AGENTS.md and project-local .agents instructions in this worktree. When present, specifically read .agents/skills/agent-orchestration/SKILL.md and .agents/docs/AGENT_ORCHESTRATION.md before worker delegation or mutation.
- Use Codex native SubAgent/delegated-worker mechanisms for worker assignments when available, following AGENTS.md and .agents instructions.
- Do not force raw Codex CLI subprocess workers as the primary worker path.
- If no delegated-worker mechanism is available, stop before mutation and report the exact blocked worker task in your OrchestratorReviewReport findings and remaining_risk.
- Workers must return WorkerReport JSON matching the worker report contract and include "no_further_delegation": true.
- Review every WorkerReport before writing your own OrchestratorReviewReport.

Safety requirements:
- Do not edit outside the assigned paths, symbols, or modules.
- Do not mutate the primary worktree.
- Run validation commands when feasible. If validation cannot run, explain why in validation_results and remaining_risk.
- Write your final OrchestratorReviewReport as JSON to:
{report_path}
- The orchestrator review report schema path is:
{schema_path}
- Worker reports must use this schema path:
{worker_schema_path}

Supervisor task:
{task}

Orchestrator assignment JSON:
{assignment_json}

Worker prompt templates:
{worker_prompts}
"#,
        worktree_path = worktree.path.display(),
        child_id = assignment.id,
        assigned_paths = display_paths(&assignment.assigned_paths),
        semantic_symbols = assignment.semantic_symbols.join(", "),
        semantic_modules = assignment.semantic_modules.join(", "),
        claim_token = claim_context.claim.token.get(),
        semantic_intent_token = claim_context
            .semantic_intent_token
            .map(|token| token.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        report_path = report_path.display(),
        schema_path = schema_path.display(),
        worker_schema_path = worker_schema_path.display(),
        task = plan.task,
        assignment_json = assignment_json,
        worker_prompts = worker_prompts,
    ))
}

pub fn worker_prompt(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    worker: &WorkerAssignment,
    run_dir: &Path,
    schema_path: &Path,
) -> Result<String> {
    let worker_json =
        serde_json::to_string_pretty(worker).context("failed to serialize worker assignment")?;
    Ok(format!(
        r#"ROLE: TERMINAL_WORKER
You are a terminal worker/researcher in an opt-in local Codex CLI supervised run.
Current supervise run contract: O2 supervisor -> O1 child orchestrator -> terminal worker/researcher.
Your parent is child orchestrator `{orchestrator_id}`. You are not the supervisor.
Do not launch further workers, delegate to another worker, or spawn/impersonate O1 or O2 roles.

Ownership:
- Worker id: {worker_id}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}
- Explicit report path: {report_path}

Rules:
- Edit only inside your assigned worktree and only inside claimed paths.
- Do not mutate the primary worktree.
- Run validation or record why validation was not run.
- Return WorkerReport JSON in your final response with changed files, commands run, validation results, findings, remaining risk, and next safe action.
- Include "no_further_delegation": true in WorkerReport JSON to attest this terminal worker did not delegate further.
- If you discover a large cross-cutting problem that needs a peer O2 supervisor, report it as an escalation candidate in findings and remaining_risk instead of taking it over.
- Only write a report file when an explicit report_path is assigned.
- Use the worker report schema path: {schema_path}

Supervisor task:
{task}

Worker assignment JSON:
{worker_json}
"#,
        orchestrator_id = orchestrator.id,
        worker_id = worker.id,
        assigned_paths = display_paths(&worker.assigned_paths),
        semantic_symbols = worker.semantic_symbols.join(", "),
        semantic_modules = worker.semantic_modules.join(", "),
        run_dir = run_dir.display(),
        report_path = worker
            .report_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        schema_path = schema_path.display(),
        task = worker.task.as_deref().unwrap_or(&plan.task),
        worker_json = worker_json,
    ))
}

fn run_supervisor_plan(
    plan: SupervisorPlan,
    options: SupervisorRunOptions,
) -> Result<SupervisorFinalReport> {
    let repo = discover_repo_root(&options.repo)?;
    if !options.allow_dirty_primary {
        ensure_clean_primary(&repo)?;
    }
    let primary_head = current_head_oid(&repo)?;

    let run_dir = run_dir(&repo, &options.run_id);
    artifacts::ensure_run_dir_available(&repo, RunArtifactFamily::Supervise, &options.run_id)?;
    let dirs = RunDirs::create(&run_dir)?;
    let manager = WorktreeManager::new(&repo);
    let sync_store = SyncStore::open(&repo)?;
    let semantic_store = SemanticIntentStore::open(&repo)?;
    let mut acquired_claim_tokens = Vec::new();
    let mut acquired_semantic_tokens = Vec::new();
    let mut planned_semantic_intents = Vec::new();
    let mut command_records = Vec::new();
    let mut orchestrator_reports = Vec::new();
    let mut findings = Vec::new();

    let run_result = (|| -> Result<()> {
        write_plan_snapshot(&dirs.assignments.join("supervisor-plan.json"), &plan)?;
        write_orchestrator_schema(&dirs.schemas.join("orchestrator-review-report.schema.json"))?;
        write_worker_schema(&dirs.schemas.join("worker-report.schema.json"))?;

        let existing = manager
            .list()?
            .into_iter()
            .map(|record| (record.name.clone(), record))
            .collect::<BTreeMap<_, _>>();

        for assignment in &plan.assignments {
            let worktree = match existing.get(&assignment.id) {
                Some(record) => {
                    ensure_reusable_child_worktree(record, &primary_head)?;
                    record.clone()
                }
                None => manager.create(WorktreeCreateOptions {
                    agent_id: assignment.id.clone(),
                    branch: None,
                    base: None,
                    worktree_root: None,
                })?,
            };

            let claim = sync_store
                .claim_paths(&assignment.id, assignment.assigned_paths.iter())
                .with_context(|| format!("failed to claim paths for '{}'", assignment.id))?;
            acquired_claim_tokens.push(claim.token);

            let semantic_token = coordinate_semantic_assignment(
                &semantic_store,
                assignment,
                plan.semantic_coordination,
                &mut acquired_semantic_tokens,
                &mut planned_semantic_intents,
                &mut findings,
            )?;

            let report_path = dirs.reports.join(format!("{}.json", assignment.id));
            let prompt_path = dirs
                .assignments
                .join(format!("{}.prompt.md", assignment.id));
            let log_path = dirs.logs.join(format!("{}.jsonl", assignment.id));
            let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
            let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
            let prompt = child_orchestrator_prompt(ChildOrchestratorPromptContext {
                plan: &plan,
                assignment,
                run_dir: &run_dir,
                worktree: &worktree,
                report_path: &report_path,
                schema_path: &schema_path,
                worker_schema_path: &worker_schema_path,
                claim_context: ChildPromptClaimContext {
                    claim: &claim,
                    semantic_intent_token: semantic_token,
                },
            })?;
            fs::write(&prompt_path, prompt)
                .with_context(|| format!("failed to write prompt {}", prompt_path.display()))?;

            let mut command = ExternalAgentCommand::codex(
                &options.codex_bin,
                &worktree.path,
                &prompt_path,
                &log_path,
                &report_path,
                Duration::from_secs(plan.child_timeout_seconds),
            );
            command.output_schema = Some(schema_path);

            let external_run = run_external_agent(&command);
            command_records.push(command_record_from_external(&external_run));
            let child_report = collect_child_report(
                assignment,
                &report_path,
                &external_run,
                &worktree.path,
                &primary_head,
            );
            if child_report.status != ReviewStatus::Succeeded {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!("child orchestrator '{}' failed", assignment.id),
                    paths: vec![report_path.clone()],
                });
            }
            if child_report.worker_reports.iter().any(report_failed) {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "child orchestrator '{}' reported failed or rejected worker output",
                        assignment.id
                    ),
                    paths: child_report.files_changed.clone(),
                });
            }
            orchestrator_reports.push(child_report);
        }
        Ok(())
    })();

    if let Err(error) = &run_result {
        findings.push(Finding {
            severity: FindingSeverity::Error,
            message: error.to_string(),
            paths: Vec::new(),
        });
    }

    let (released_claims, release_errors) = release_claims(&sync_store, acquired_claim_tokens);
    let (released_semantic_intents, semantic_release_errors) =
        release_semantic_intents(&semantic_store, acquired_semantic_tokens);
    let failed = run_result.is_err()
        || !release_errors.is_empty()
        || !semantic_release_errors.is_empty()
        || orchestrator_reports.iter().any(report_failed);
    let success = !failed;
    let final_report = SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id: options.run_id,
        role: AgentRole::Supervisor,
        repo: repo.clone(),
        plan_file: options.plan_file,
        run_dir: run_dir.clone(),
        success,
        accepted: success,
        rejected: !success,
        status: if success {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        },
        assigned_paths: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_symbols: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_symbols.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_modules: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_modules.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        claim_tokens: released_claims
            .iter()
            .map(|claim| claim.token.get())
            .collect(),
        semantic_intent_tokens: released_semantic_intents
            .iter()
            .map(|intent| intent.token.get())
            .collect(),
        commands_run: command_records,
        files_changed: orchestrator_reports
            .iter()
            .flat_map(|report| report.files_changed.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        validation_results: orchestrator_reports
            .iter()
            .flat_map(|report| report.validation_results.iter().cloned())
            .collect(),
        findings,
        orchestrator_reports,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        remaining_risk: if success {
            "no failed child orchestrator reports; worker changes remain isolated in child worktrees"
                .to_string()
        } else {
            "one or more child or worker reports failed, were rejected, or were missing".to_string()
        },
        next_safe_action: if success {
            "review child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else {
            "inspect run reports and rerun failed child scopes after correcting the issue"
                .to_string()
        },
    };
    write_final_report(&run_dir, &final_report)?;
    Ok(final_report)
}

fn validate_supervisor_plan(mut plan: SupervisorPlan) -> Result<SupervisorPlan> {
    if plan.version != SUPERVISOR_SCHEMA_VERSION {
        bail!("unsupported supervisor plan version {}", plan.version);
    }
    if plan.max_depth != 2 {
        bail!("supervisor max_depth must be exactly 2");
    }
    if plan.max_child_assignments == 0 {
        bail!("max_child_assignments must be at least 1 (legacy max_child_processes is accepted as an alias)");
    }
    if plan.child_timeout_seconds == 0 {
        bail!("child_timeout_seconds must be greater than zero");
    }
    if plan.assignments.is_empty() {
        bail!("supervisor plan must include at least one orchestrator assignment");
    }
    if plan.assignments.len() > plan.max_child_assignments {
        bail!(
            "supervisor plan has {} child orchestrators but max_child_assignments is {}",
            plan.assignments.len(),
            plan.max_child_assignments
        );
    }

    let mut seen = BTreeSet::new();
    let mut path_owners = Vec::<PathOwner>::new();
    for assignment in &mut plan.assignments {
        assignment.id = normalize_agent_id(&assignment.id)?;
        if !seen.insert(assignment.id.clone()) {
            bail!("duplicate orchestrator assignment id '{}'", assignment.id);
        }
        if assignment.role != AgentRole::ChildOrchestrator {
            bail!(
                "assignment '{}' role must be child_orchestrator",
                assignment.id
            );
        }
        assignment.assigned_paths = normalize_paths(std::mem::take(&mut assignment.assigned_paths))
            .with_context(|| format!("assignment '{}' has invalid paths", assignment.id))?;
        if assignment.assigned_paths.is_empty() {
            bail!(
                "assignment '{}' must claim at least one path",
                assignment.id
            );
        }
        for path in &assignment.assigned_paths {
            if let Some(owner) = path_owners
                .iter()
                .find(|owner| paths_overlap(path, &owner.path))
            {
                bail!(
                    "path '{}' for assignment '{}' overlaps path '{}' for assignment '{}'",
                    path.display(),
                    assignment.id,
                    owner.path.display(),
                    owner.id
                );
            }
        }
        path_owners.extend(
            assignment
                .assigned_paths
                .iter()
                .cloned()
                .map(|path| PathOwner {
                    id: assignment.id.clone(),
                    path,
                }),
        );
        assignment.semantic_symbols = sorted_unique_strings(&assignment.semantic_symbols);
        assignment.semantic_modules = sorted_unique_strings(&assignment.semantic_modules);
        validate_worker_assignments(assignment)?;
    }

    Ok(plan)
}

fn validate_worker_assignments(assignment: &mut OrchestratorAssignment) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut path_owners = Vec::<PathOwner>::new();
    for worker in &mut assignment.worker_assignments {
        worker.id = normalize_agent_id(&worker.id)?;
        if !seen.insert(worker.id.clone()) {
            bail!(
                "assignment '{}' has duplicate worker id '{}'",
                assignment.id,
                worker.id
            );
        }
        if worker.role != AgentRole::Worker {
            bail!(
                "worker '{}' under assignment '{}' role must be worker",
                worker.id,
                assignment.id
            );
        }
        worker.assigned_paths = normalize_paths(std::mem::take(&mut worker.assigned_paths))
            .with_context(|| format!("worker '{}' has invalid paths", worker.id))?;
        for path in &worker.assigned_paths {
            if !assignment
                .assigned_paths
                .iter()
                .any(|assigned| path_is_covered_by_claim(path, assigned))
            {
                bail!(
                    "worker '{}' path '{}' is outside child assignment '{}'",
                    worker.id,
                    path.display(),
                    assignment.id
                );
            }
            if let Some(owner) = path_owners
                .iter()
                .find(|owner| paths_overlap(path, &owner.path))
            {
                bail!(
                    "worker '{}' path '{}' overlaps worker '{}' path '{}'",
                    worker.id,
                    path.display(),
                    owner.id,
                    owner.path.display()
                );
            }
        }
        path_owners.extend(worker.assigned_paths.iter().cloned().map(|path| PathOwner {
            id: worker.id.clone(),
            path,
        }));
        worker.semantic_symbols = sorted_unique_strings(&worker.semantic_symbols);
        worker.semantic_modules = sorted_unique_strings(&worker.semantic_modules);
    }
    Ok(())
}

fn coordinate_semantic_assignment(
    store: &SemanticIntentStore,
    assignment: &OrchestratorAssignment,
    mode: SemanticCoordinationMode,
    acquired_tokens: &mut Vec<crate::semantic_coord::SemanticIntentToken>,
    planned_preview_intents: &mut Vec<SemanticIntent>,
    findings: &mut Vec<Finding>,
) -> Result<Option<u64>> {
    if mode == SemanticCoordinationMode::Off {
        return Ok(None);
    }
    let request = SemanticIntentRequest {
        agent_id: assignment.id.clone(),
        paths: assignment.assigned_paths.clone(),
        symbols: assignment.semantic_symbols.clone(),
        modules: assignment.semantic_modules.clone(),
        task_file: None,
        notes: vec!["supervise child orchestrator assignment".to_string()],
    };
    let report = match mode {
        SemanticCoordinationMode::Off => return Ok(None),
        SemanticCoordinationMode::Warn => {
            store.preview_with_additional_active(request, planned_preview_intents)?
        }
        SemanticCoordinationMode::Block => store.claim(request)?,
    };
    if mode == SemanticCoordinationMode::Warn {
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    report
                        .blocking_conflict_count
                        .saturating_add(report.advisory_conflict_count)
                ),
                paths: assignment.assigned_paths.clone(),
            });
        }
        planned_preview_intents.push(report.intent.clone());
    }
    if mode == SemanticCoordinationMode::Block && report.has_blocking_conflicts {
        bail!(
            "semantic coordination blocked assignment '{}' with {} blocking conflict(s)",
            assignment.id,
            report.blocking_conflict_count
        );
    }
    if mode == SemanticCoordinationMode::Block && report.persisted {
        acquired_tokens.push(report.intent.token);
    }
    Ok(Some(report.intent.token.get()))
}

fn collect_child_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    worktree_path: &Path,
    primary_head: &Oid,
) -> OrchestratorReviewReport {
    let mut report = match read_child_report(report_path) {
        Ok(mut report) => {
            if report.id != assignment.id {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "report id '{}' does not match assignment '{}'",
                        report.id, assignment.id
                    ),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.role != AgentRole::ChildOrchestrator {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "orchestrator report role must be child_orchestrator".to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if !external_run.succeeded() && report.status == ReviewStatus::Succeeded {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "external child process failed despite report success".to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            report
        }
        Err(error) => {
            missing_child_report(assignment, report_path, external_run, error.to_string())
        }
    };
    validate_worker_report_delegation_attestations(assignment, report_path, &mut report);
    verify_child_report_paths(assignment, worktree_path, primary_head, &mut report);
    report
}

fn validate_worker_report_delegation_attestations(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let mut invalid_workers = Vec::new();
    let actual_worker_ids = report
        .worker_reports
        .iter()
        .map(|worker_report| worker_report.id.as_str())
        .collect::<BTreeSet<_>>();
    let missing_workers = assignment
        .worker_assignments
        .iter()
        .filter(|worker| !actual_worker_ids.contains(worker.id.as_str()))
        .map(|worker| worker.id.clone())
        .collect::<Vec<_>>();

    for worker_report in &mut report.worker_reports {
        if worker_report.no_further_delegation == Some(true) {
            continue;
        }
        let message = match worker_report.no_further_delegation {
            Some(false) => "worker report indicates further delegation".to_string(),
            None => "worker report omitted no_further_delegation terminal-worker attestation"
                .to_string(),
            Some(true) => continue,
        };
        worker_report.status = ReviewStatus::Failed;
        worker_report.accepted = false;
        worker_report.rejected = true;
        worker_report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message,
            paths: vec![report_path.to_path_buf()],
        });
        invalid_workers.push(worker_report.id.clone());
    }

    if invalid_workers.is_empty() && missing_workers.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;

    if !invalid_workers.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' included worker reports without terminal no-delegation attestation: {}",
                report.id,
                invalid_workers.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !missing_workers.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted required worker reports for assignment worker IDs: {}",
                report.id,
                missing_workers.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    report.remaining_risk = if missing_workers.is_empty() {
        "one or more worker reports indicate delegation beyond the terminal worker contract"
            .to_string()
    } else {
        "one or more required worker reports are missing terminal no-delegation attestations"
            .to_string()
    };
    report.next_safe_action =
        "inspect worker output and rerun the child scope with terminal workers only".to_string();
}

fn verify_child_report_paths(
    assignment: &OrchestratorAssignment,
    worktree_path: &Path,
    primary_head: &Oid,
    report: &mut OrchestratorReviewReport,
) {
    let reported_paths = normalize_paths(report.files_changed.clone());
    let actual_paths = match collect_paths_changed_since_base(worktree_path, primary_head) {
        Ok(paths) => paths,
        Err(error) => {
            report.status = ReviewStatus::Failed;
            report.accepted = false;
            report.rejected = true;
            report.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!("failed to inspect actual child worktree changes: {error}"),
                paths: Vec::new(),
            });
            return;
        }
    };

    let mismatch = match &reported_paths {
        Ok(paths) => paths != &actual_paths,
        Err(_) => true,
    };
    if mismatch {
        let mismatch_paths = match reported_paths {
            Ok(paths) => union_paths(&paths, &actual_paths),
            Err(_) => actual_paths.clone(),
        };
        report.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "child-reported files_changed does not match actual child worktree Git changes; using supervisor-inspected paths".to_string(),
            paths: mismatch_paths,
        });
    }

    report.files_changed = actual_paths.clone();

    let unauthorized_paths = actual_paths
        .iter()
        .filter(|path| {
            !assignment
                .assigned_paths
                .iter()
                .any(|assigned| path_is_covered_by_claim(path, assigned))
        })
        .cloned()
        .collect::<Vec<_>>();

    if unauthorized_paths.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "child orchestrator '{}' changed paths outside its assigned paths: {}",
            assignment.id,
            display_paths(&unauthorized_paths)
        ),
        paths: unauthorized_paths,
    });
    report.remaining_risk =
        "child worktree contains Git-visible changes outside the assigned paths".to_string();
    report.next_safe_action =
        "inspect the unauthorized child worktree changes before rerunning or collecting"
            .to_string();
}

fn read_child_report(path: &Path) -> Result<OrchestratorReviewReport> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read child report {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse child report {}", path.display()))
}

fn missing_child_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    error: String,
) -> OrchestratorReviewReport {
    OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: vec![command_record_from_external(external_run)],
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!("required child report is missing or invalid: {error}"),
            paths: vec![report_path.to_path_buf()],
        }],
        worker_reports: Vec::new(),
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        remaining_risk: "child orchestrator did not produce a usable report".to_string(),
        next_safe_action: "inspect child logs and rerun the failed assignment".to_string(),
    }
}

fn report_failed<T: ReportStatus>(report: &T) -> bool {
    !report.accepted() || report.rejected() || report.status() != ReviewStatus::Succeeded
}

trait ReportStatus {
    fn accepted(&self) -> bool;
    fn rejected(&self) -> bool;
    fn status(&self) -> ReviewStatus;
}

impl ReportStatus for OrchestratorReviewReport {
    fn accepted(&self) -> bool {
        self.accepted
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn status(&self) -> ReviewStatus {
        self.status
    }
}

impl ReportStatus for WorkerReport {
    fn accepted(&self) -> bool {
        self.accepted
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn status(&self) -> ReviewStatus {
        self.status
    }
}

fn command_record_from_external(run: &ExternalAgentRun) -> CommandRunRecord {
    CommandRunRecord {
        command: run.command.clone(),
        cwd: run.cwd.clone(),
        exit_code: run.exit_code,
        status: if run.succeeded() {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        },
        timeout_seconds: run.timeout_seconds,
        duration_ms: run.duration_ms,
        timed_out: run.timed_out,
        stdout: run.stdout.text.clone(),
        stderr: run.stderr.text.clone(),
        error: run.error.clone(),
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
    tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
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

fn ensure_clean_primary(repo: &Path) -> Result<()> {
    if primary_is_dirty(repo)? {
        bail!("refusing to run supervise with a dirty primary worktree; rerun with --allow-dirty-primary to override");
    }
    Ok(())
}

fn primary_is_dirty(repo: &Path) -> Result<bool> {
    let repo = Repository::open(repo)
        .with_context(|| format!("failed to open repository {}", repo.display()))?;
    repository_is_dirty(&repo, "failed to inspect primary worktree status")
}

fn ensure_reusable_child_worktree(record: &WorktreeRecord, primary_head: &Oid) -> Result<()> {
    let repo = Repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing child worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    if repository_is_dirty(&repo, "failed to inspect child worktree status")? {
        bail!(
            "refusing to reuse dirty child worktree '{}' at {}; clean it or use a new child id",
            record.name,
            record.path.display()
        );
    }

    let child_head = head_oid(&repo).with_context(|| {
        format!(
            "failed to inspect HEAD for child worktree '{}'",
            record.name
        )
    })?;
    if &child_head != primary_head {
        bail!(
            "refusing to reuse stale child worktree '{}' at {}; stale-base: child HEAD {} does not match current primary HEAD {}. Remove the child worktree or choose a new child id; supervise does not reset child worktrees",
            record.name,
            record.path.display(),
            child_head,
            primary_head
        );
    }

    Ok(())
}

fn repository_is_dirty(repo: &Repository, context: &'static str) -> Result<bool> {
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo.statuses(Some(&mut options)).context(context)?;
    Ok(!statuses.is_empty())
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

fn collect_paths_changed_since_base(worktree_path: &Path, base_oid: &Oid) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(worktree_path)
        .with_context(|| format!("failed to open child worktree {}", worktree_path.display()))?;
    let base_commit = repo
        .find_commit(*base_oid)
        .with_context(|| format!("failed to find primary base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for primary base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let mut diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff child worktree against primary base commit")?;
    let mut find_options = DiffFindOptions::new();
    find_options.renames(true);
    diff.find_similar(Some(&mut find_options))
        .context("failed to detect renamed child worktree paths")?;

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
    .context("failed to inspect child worktree changed paths")?;

    Ok(paths.into_iter().collect())
}

fn collect_delta_paths(delta: git2::DiffDelta<'_>, paths: &mut BTreeSet<PathBuf>) {
    match delta.status() {
        Delta::Deleted => insert_delta_path(delta.old_file().path(), paths),
        Delta::Renamed | Delta::Copied => {
            insert_delta_path(delta.old_file().path(), paths);
            insert_delta_path(delta.new_file().path(), paths);
        }
        _ => insert_delta_path(delta.new_file().path(), paths),
    }
}

fn insert_delta_path(path: Option<&Path>, paths: &mut BTreeSet<PathBuf>) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        paths.insert(path.to_path_buf());
    }
}

fn union_paths(left: &[PathBuf], right: &[PathBuf]) -> Vec<PathBuf> {
    left.iter()
        .chain(right)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn write_plan_snapshot(path: &Path, plan: &SupervisorPlan) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("failed to create plan snapshot {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, plan)
        .with_context(|| format!("failed to write plan snapshot {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish plan snapshot {}", path.display()))
}

fn write_orchestrator_schema(path: &Path) -> Result<()> {
    write_schema(
        path,
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "OrchestratorReviewReport",
            "type": "object",
            "required": ["id", "role", "accepted", "rejected", "status", "remaining_risk", "next_safe_action"],
            "properties": {
                "id": {"type": "string"},
                "role": {"const": "child_orchestrator"},
                "assigned_paths": {"type": "array", "items": {"type": "string"}},
                "semantic_symbols": {"type": "array", "items": {"type": "string"}},
                "semantic_modules": {"type": "array", "items": {"type": "string"}},
                "worker_reports": {"type": "array", "items": worker_report_schema_value()},
                "accepted": {"type": "boolean"},
                "rejected": {"type": "boolean"},
                "status": {"enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
                "remaining_risk": {"type": "string"},
                "next_safe_action": {"type": "string"}
            }
        }),
    )
}

fn write_worker_schema(path: &Path) -> Result<()> {
    write_schema(path, worker_report_schema_value())
}

fn worker_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "WorkerReport",
        "type": "object",
        "required": ["id", "role", "no_further_delegation", "accepted", "rejected", "status", "remaining_risk", "next_safe_action"],
        "properties": {
            "id": {"type": "string"},
            "role": {"const": "worker"},
            "assigned_paths": {"type": "array", "items": {"type": "string"}},
            "semantic_symbols": {"type": "array", "items": {"type": "string"}},
            "semantic_modules": {"type": "array", "items": {"type": "string"}},
            "commands_run": {"type": "array"},
            "files_changed": {"type": "array", "items": {"type": "string"}},
            "validation_results": {"type": "array"},
            "findings": {"type": "array"},
            "no_further_delegation": {"const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        }
    })
}

fn write_schema(path: &Path, schema: serde_json::Value) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("failed to create schema {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, &schema)
        .with_context(|| format!("failed to write schema {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish schema {}", path.display()))
}

fn write_final_report(run_dir: &Path, report: &SupervisorFinalReport) -> Result<()> {
    let path = supervisor_final_report_path(run_dir);
    let mut file = File::create(&path)
        .with_context(|| format!("failed to create final report {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, report)
        .with_context(|| format!("failed to write final report {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish final report {}", path.display()))
}

fn read_supervisor_final_report(path: &Path) -> Result<SupervisorFinalReport> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read supervisor final report {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse supervisor final report {}", path.display()))
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn run_dir(repo: &Path, run_id: &RunId) -> PathBuf {
    repo.join(".maco")
        .join("o2")
        .join("runs")
        .join(run_id.as_str())
}

fn supervisor_final_report_path(run_dir: &Path) -> PathBuf {
    run_dir.join("reports").join("supervisor-final.json")
}

#[derive(Debug)]
struct RunDirs {
    assignments: PathBuf,
    reports: PathBuf,
    logs: PathBuf,
    schemas: PathBuf,
}

impl RunDirs {
    fn create(run_dir: &Path) -> Result<Self> {
        let dirs = Self {
            assignments: run_dir.join("assignments"),
            reports: run_dir.join("reports"),
            logs: run_dir.join("logs"),
            schemas: run_dir.join("schemas"),
        };
        for dir in [&dirs.assignments, &dirs.reports, &dirs.logs, &dirs.schemas] {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create run directory {}", dir.display()))?;
        }
        Ok(dirs)
    }
}

fn normalize_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
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

fn normalize_agent_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("agent id cannot be empty");
    }
    if matches!(value, "." | "..") {
        bail!("agent id cannot be '.' or '..'");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    Ok(value.to_string())
}

fn sorted_unique_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn display_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "<none>".to_string();
    }
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn path_relative_to(repo: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn default_schema_version() -> u32 {
    SUPERVISOR_SCHEMA_VERSION
}

fn default_max_depth() -> u8 {
    2
}

fn default_max_child_assignments() -> usize {
    DEFAULT_MAX_CHILD_ASSIGNMENTS
}

fn default_child_timeout_seconds() -> u64 {
    DEFAULT_CHILD_TIMEOUT_SECONDS
}

fn child_orchestrator_role() -> AgentRole {
    AgentRole::ChildOrchestrator
}

fn worker_role() -> AgentRole {
    AgentRole::Worker
}

#[derive(Debug, Clone)]
struct PathOwner {
    id: String,
    path: PathBuf,
}

pub fn generated_run_id() -> Result<RunId> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    RunId::new(format!("o2-{now}"))
}
