use crate::{
    artifacts::{self, RunArtifactFamily},
    external_agent::{run_external_agent, ExternalAgentCommand, ExternalAgentRun},
    orchestrator::{RunId, SemanticCoordinationMode},
    semantic_coord::{SemanticIntent, SemanticIntentRequest, SemanticIntentStore},
    sync::{normalize_repo_relative_path, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use anyhow::{anyhow, bail, Context, Result};
use git2::{
    Delta, DiffFindOptions, DiffOptions, ErrorCode, IndexEntryExtendedFlag, IndexEntryFlag,
    ObjectType, Oid, Repository, Status, StatusOptions,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 600;
const DEFAULT_MAX_CHILD_ASSIGNMENTS: usize = 4;
const DEFAULT_MAX_CHILD_RETRIES: u8 = 0;
const MAX_CHILD_RETRIES_LIMIT: u8 = 2;
const SUPERVISOR_SCHEMA_VERSION: u32 = 1;
const LENIENT_JSON_EXTRACTION_WARNING: &str = "report required lenient JSON extraction";
const GITLINK_MODE: u32 = 0o160000;
const MAX_NESTED_REPOSITORY_DEPTH: usize = 8;
const LOCAL_RUNTIME_ROOTS: &[&[u8]] = &[
    b".maco",
    b".maco-cache",
    b".agents/temp",
    b".agents/storage",
    b".agents/live",
];

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
    #[serde(default = "default_max_child_retries")]
    pub max_child_retries: u8,
    #[serde(default = "default_child_timeout_seconds")]
    pub child_timeout_seconds: u64,
    #[serde(default)]
    pub semantic_coordination: SemanticCoordinationMode,
    #[serde(default)]
    pub assignments: Vec<OrchestratorAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SupervisorConsultantPlan {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_consultant_runtime")]
    pub runtime: String,
    #[serde(default = "default_max_consultations")]
    pub max_consultations: u32,
}

impl Default for SupervisorConsultantPlan {
    fn default() -> Self {
        Self {
            enabled: false,
            runtime: default_consultant_runtime(),
            max_consultations: default_max_consultations(),
        }
    }
}

impl SupervisorConsultantPlan {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedSupervisorPlan {
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
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
    Auditor,
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
pub struct AuditorReport {
    pub id: String,
    pub role: AgentRole,
    #[serde(default)]
    pub reviewed_worker_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_paths: Vec<PathBuf>,
    #[serde(default)]
    pub commands_run: Vec<CommandRunRecord>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_further_delegation: Option<bool>,
    #[serde(default)]
    pub read_only: bool,
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
    #[serde(default)]
    pub audit_reports: Vec<AuditorReport>,
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
    #[serde(default, serialize_with = "serialize_finding_paths")]
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
    pub auditor_schema_path: &'a Path,
    pub consultant: &'a SupervisorConsultantPlan,
    pub claim_context: ChildPromptClaimContext<'a>,
}

pub fn supervisor_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<SupervisorPlan> {
    Ok(supervisor_plan_and_consultant_from_task_file(repo, task_file)?.plan)
}

pub fn supervisor_plan_document_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<Value> {
    let loaded = supervisor_plan_and_consultant_from_task_file(repo, task_file)?;
    supervisor_plan_value(&loaded.plan, &loaded.consultant)
}

fn supervisor_plan_and_consultant_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let task = fs::read_to_string(task_file)
        .with_context(|| format!("failed to read task file {}", task_file.display()))?;
    if serde_json::from_str::<Value>(&task).is_ok() {
        return parse_supervisor_plan_with_consultant(&task)
            .with_context(|| format!("failed to parse supervisor plan {}", task_file.display()));
    }

    Ok(LoadedSupervisorPlan {
        plan: SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task,
            task_file: Some(path_relative_to(&repo, task_file)),
            max_depth: default_max_depth(),
            max_child_assignments: DEFAULT_MAX_CHILD_ASSIGNMENTS,
            max_child_retries: DEFAULT_MAX_CHILD_RETRIES,
            child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
            semantic_coordination: SemanticCoordinationMode::Off,
            assignments: Vec::new(),
        },
        consultant: SupervisorConsultantPlan::default(),
    })
}

pub fn load_supervisor_plan_file(path: impl AsRef<Path>) -> Result<SupervisorPlan> {
    Ok(load_supervisor_plan_file_with_consultant(path)?.plan)
}

fn load_supervisor_plan_file_with_consultant(
    path: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read supervisor plan {}", path.display()))?;
    parse_supervisor_plan_with_consultant(&contents)
        .with_context(|| format!("failed to parse supervisor plan {}", path.display()))
}

fn parse_supervisor_plan_with_consultant(contents: &str) -> Result<LoadedSupervisorPlan> {
    let value: Value = serde_json::from_str(contents).context("supervisor plan is not JSON")?;
    let consultant = consultant_from_plan_value(&value)?;
    let plan: SupervisorPlan =
        serde_json::from_value(value).context("supervisor plan fields are invalid")?;
    let plan = validate_supervisor_plan(plan)?;
    validate_consultant_plan(&consultant)?;
    Ok(LoadedSupervisorPlan { plan, consultant })
}

fn consultant_from_plan_value(value: &Value) -> Result<SupervisorConsultantPlan> {
    match value.get("consultant") {
        Some(consultant) => {
            serde_json::from_value(consultant.clone()).context("consultant plan field is invalid")
        }
        None => Ok(SupervisorConsultantPlan::default()),
    }
}

fn supervisor_plan_value(
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(plan).context("failed to serialize normalized supervisor plan")?;
    if !consultant.is_default() {
        let object = value
            .as_object_mut()
            .context("normalized supervisor plan did not serialize to an object")?;
        object.insert(
            "consultant".to_string(),
            serde_json::to_value(consultant)
                .context("failed to serialize consultant plan field")?,
        );
    }
    Ok(value)
}

pub fn run_supervisor_plan_file(options: SupervisorRunOptions) -> Result<SupervisorFinalReport> {
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    run_supervisor_plan(loaded.plan, loaded.consultant, options)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisePromptRole {
    O2TopSupervisor,
    O1ChildOrchestrator,
    TerminalWorker,
    Researcher,
    ReviewAuditor,
}

impl SupervisePromptRole {
    fn canonical_role(self) -> &'static str {
        match self {
            Self::O2TopSupervisor => "O2_TOP_SUPERVISOR",
            Self::O1ChildOrchestrator => "O1_CHILD_ORCHESTRATOR",
            Self::TerminalWorker => "TERMINAL_WORKER",
            Self::Researcher => "RESEARCHER",
            Self::ReviewAuditor => "REVIEW_AUDITOR",
        }
    }

    fn agent_kind(self) -> &'static str {
        match self {
            Self::O2TopSupervisor => "orchestrator",
            Self::O1ChildOrchestrator => "child_orchestrator",
            Self::TerminalWorker => "worker",
            Self::Researcher => "researcher",
            Self::ReviewAuditor => "auditor",
        }
    }

    fn thread_depth(self) -> u8 {
        match self {
            Self::O2TopSupervisor => 0,
            Self::O1ChildOrchestrator => 1,
            Self::TerminalWorker | Self::Researcher | Self::ReviewAuditor => 2,
        }
    }

    fn no_further_delegation(self) -> bool {
        match self {
            Self::O2TopSupervisor | Self::O1ChildOrchestrator => false,
            Self::TerminalWorker | Self::Researcher | Self::ReviewAuditor => true,
        }
    }
}

pub fn supervise_role_prefix(
    role: SupervisePromptRole,
    label: &str,
    parent_thread_id: Option<&str>,
) -> String {
    format!(
        "ROLE: {}\nAGENT_KIND: {}\nAGENT_LABEL: {}\nPARENT_THREAD_ID: {}\nTHREAD_DEPTH: {}\nNO_FURTHER_DELEGATION: {}\n",
        role.canonical_role(),
        role.agent_kind(),
        label,
        parent_thread_id.unwrap_or("none"),
        role.thread_depth(),
        role.no_further_delegation()
    )
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
        auditor_schema_path,
        consultant,
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
    let auditor_prompt = review_auditor_prompt(plan, assignment, run_dir, auditor_schema_path)?;
    let task = assignment_task(plan, assignment);
    let role_prefix = supervise_role_prefix(
        SupervisePromptRole::O1ChildOrchestrator,
        &assignment.id,
        None,
    );
    let consultation_section = consultation_prompt_section(consultant);
    Ok(format!(
        r#"{role_prefix}You are a child orchestrator in an opt-in local Codex CLI supervisor run.
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
- Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
- You are the O1 child orchestrator for this assignment.
- Workers, researchers, and review auditors are terminal: they must not launch further workers, delegate to another worker, or take over peer coordination.
- You must not use native SubAgent/delegated-worker mechanisms to bind, spawn, impersonate, or take over O1 or O2 roles.
- Durable role names are canonical. Runtime labels belong in runtime bridge metadata such as AGENT_LABEL, never in ROLE.
- You must not spawn, impersonate, or take over a peer O2 supervisor.
- O1 reports peer-O2 escalation candidates upward in findings and remaining_risk instead of taking them over.
- The user-root O2 or an autonomous O2 durable queue may launch bounded peer O2 supervisors through MACO/Codex CLI subprocess orchestration. Autonomous O2-to-O2 follow-up must go through durable queue state such as NEXT_O2_TASKS.tsv, not native SubAgent.

Runtime boundary:
- You were launched as a Codex CLI subprocess with this O1/O2 orchestration boundary:
  - --sandbox danger-full-access
  - --enable goals
  - --enable multi_agent
- Nested O2/O1 subprocess chains must preserve this boundary for orchestrator roles.
- Do not use workspace-write for O2/O1 subprocess chains because nested Codex state DB access can collide, corrupt, or fail under workspace-write style restrictions.

Required behavior:
- First, read and follow AGENTS.md and project-local .agents instructions in this worktree. When present, specifically read .agents/skills/agent-orchestration/SKILL.md and .agents/docs/AGENT_ORCHESTRATION.md before worker delegation or mutation.
- Use Codex native SubAgent/delegated-worker mechanisms only for lightweight terminal worker or researcher assignments when available, following AGENTS.md and .agents instructions.
- When launching a worker, use the generated worker prompt template verbatim and preserve its six-line TERMINAL_WORKER role-prefix block with no preamble.
- You may collect advisory child-side review-auditor evidence with the generated REVIEW_AUDITOR prompt template, but it is not an acceptance gate unless MACO/O2 collects it through the parent-enforced gate.
- When collecting advisory child-side review-auditor evidence, preserve its six-line REVIEW_AUDITOR role-prefix block with no preamble.
- Do not force raw Codex CLI subprocess workers as the primary worker path.
- If no delegated-worker mechanism is available, stop before mutation and report the exact blocked worker task in your OrchestratorReviewReport findings and remaining_risk.
- Workers must return WorkerReport JSON matching the worker report contract and include "no_further_delegation": true.
- Review auditors must return AuditorReport JSON matching the auditor report contract and include "no_further_delegation": true.
- Review auditors must include "read_only": true in AuditorReport JSON to attest they did not mutate files or repository state.
- Acceptance-gate review auditors are parent-launched MACO/Codex CLI subprocess roles; a child-launched review auditor is advisory child-side evidence unless MACO/O2 collects it through the parent-enforced acceptance gate.
- Review every WorkerReport before writing your own OrchestratorReviewReport.
- Include at least one accepted review-auditor report in audit_reports that covers all assigned worker ids; MACO rejects child reports with worker assignments that omit terminal audit evidence.
{consultation_section}

Safety requirements:
- Do not edit outside the assigned paths, symbols, or modules.
- Do not mutate the primary worktree.
- Run validation commands when feasible. If validation cannot run, explain why in validation_results and remaining_risk.
- Return your OrchestratorReviewReport JSON as your final response.
- Do not write the orchestrator report file yourself with tools; Codex CLI --output-last-message records your final response at this MACO collection target:
{report_path}
- The orchestrator review report schema path is:
{schema_path}
- Worker reports must use this schema path:
{worker_schema_path}
- Review auditor reports must use this schema path:
{auditor_schema_path}

Supervisor task:
{task}

Orchestrator assignment JSON:
{assignment_json}

Worker prompt templates:
{worker_prompts}

Review auditor prompt template:
{auditor_prompt}
"#,
        role_prefix = role_prefix,
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
        auditor_schema_path = auditor_schema_path.display(),
        task = task,
        assignment_json = assignment_json,
        worker_prompts = worker_prompts,
        auditor_prompt = auditor_prompt,
        consultation_section = consultation_section,
    ))
}

fn consultation_prompt_section(consultant: &SupervisorConsultantPlan) -> String {
    if !consultant.enabled {
        return String::new();
    }
    format!(
        r#"
CONSULTATION:
- If you are blocked after a genuine attempt, you may ask a terminal read-only CONSULTANT for a cross-runtime second opinion.
- Use `maco consult ask --runtime {runtime} --repo <this-child-worktree> --question <focused question> --context-path <repo-relative-path> ...`.
- The consultation path is advisory and read-only. It must not create worktrees, claims, patches, or repository mutations.
- Use at most {max_consultations} consultation(s) for this child assignment.
- Record each consultation in OrchestratorReviewReport findings with the question summary and whether it unblocked you.
- Consultant advice never overrides AGENTS.md, project rules, assigned ownership, validation requirements, or acceptance gates.
"#,
        runtime = consultant.runtime.as_str(),
        max_consultations = consultant.max_consultations
    )
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
    let role_prefix = supervise_role_prefix(SupervisePromptRole::TerminalWorker, &worker.id, None);
    let task = worker_task(plan, orchestrator, worker);
    Ok(format!(
        r#"{role_prefix}You are a terminal worker/researcher in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
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
- If you discover a large cross-cutting problem that needs a peer O2 supervisor, report it as an escalation candidate in findings and remaining_risk instead of taking it over. O2-to-O2 follow-up belongs to the user-root O2 or autonomous O2 durable queue, not this terminal role.
- Only write a report file when an explicit report_path is assigned.
- If the explicit report path is <none>, do not write any report file; only return WorkerReport JSON in your final response.
- Use the worker report schema path: {schema_path}

Supervisor task:
{task}

Worker assignment JSON:
{worker_json}
"#,
        role_prefix = role_prefix,
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
        task = task,
        worker_json = worker_json,
    ))
}

pub fn review_auditor_prompt(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    run_dir: &Path,
    schema_path: &Path,
) -> Result<String> {
    let worker_ids = orchestrator
        .worker_assignments
        .iter()
        .map(|worker| worker.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let auditor_id = format!("{}-review-auditor", orchestrator.id);
    let role_prefix = supervise_role_prefix(SupervisePromptRole::ReviewAuditor, &auditor_id, None);
    let task = assignment_task(plan, orchestrator);
    Ok(format!(
        r#"{role_prefix}You are a terminal read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
Your parent is child orchestrator `{orchestrator_id}`. You are not an O1 child orchestrator, O2 supervisor, worker, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, or spawn/impersonate O1 or O2 roles.

Ownership:
- Review auditor id: {auditor_id}
- Assigned worker ids to audit: {worker_ids}
- Assigned paths to review: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}

Rules:
- Stay read-only. Inspect worker reports, child diffs, validation evidence, findings, remaining risk, and claimed path boundaries.
- Do not edit files, create durable artifacts, apply patches, claim paths, or change Git state.
- Produce structured AuditorReport JSON in your final response with reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining risk, and next safe action.
- Include "no_further_delegation": true in AuditorReport JSON to attest this terminal auditor did not delegate further.
- Include "read_only": true in AuditorReport JSON to attest this audit stayed read-only.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Use the auditor report schema path: {schema_path}

Supervisor task:
{task}
"#,
        role_prefix = role_prefix,
        orchestrator_id = orchestrator.id,
        auditor_id = auditor_id,
        worker_ids = if worker_ids.is_empty() {
            "<none>".to_string()
        } else {
            worker_ids
        },
        assigned_paths = display_paths(&orchestrator.assigned_paths),
        semantic_symbols = orchestrator.semantic_symbols.join(", "),
        semantic_modules = orchestrator.semantic_modules.join(", "),
        run_dir = run_dir.display(),
        schema_path = schema_path.display(),
        task = task,
    ))
}

struct ParentReviewAuditorPromptContext<'a> {
    plan: &'a SupervisorPlan,
    assignment: &'a OrchestratorAssignment,
    run_dir: &'a Path,
    worktree_path: &'a Path,
    child_report_path: &'a Path,
    auditor_report_path: &'a Path,
    schema_path: &'a Path,
    child_report: &'a OrchestratorReviewReport,
}

fn parent_review_auditor_prompt(context: ParentReviewAuditorPromptContext<'_>) -> Result<String> {
    let ParentReviewAuditorPromptContext {
        plan,
        assignment,
        run_dir,
        worktree_path,
        child_report_path,
        auditor_report_path,
        schema_path,
        child_report,
    } = context;
    let auditor_id = parent_auditor_id(assignment);
    let role_prefix = supervise_role_prefix(SupervisePromptRole::ReviewAuditor, &auditor_id, None);
    let child_report_json = serde_json::to_string_pretty(child_report)
        .context("failed to serialize child report for auditor prompt")?;
    let task = assignment_task(plan, assignment);
    Ok(format!(
        r#"{role_prefix}You are the parent-launched read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher, plus this parent-enforced terminal REVIEW_AUDITOR gate.
Your parent is MACO/O2. You are not an O1 child orchestrator, worker, researcher, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, claim paths, apply patches, or change Git state.

Runtime boundary:
- MACO requested the Codex CLI read-only sandbox for this subprocess with --sandbox read-only.
- Stay read-only even if the local runtime cannot enforce stronger filesystem isolation.
- Return AuditorReport JSON as your final response. Codex CLI --output-last-message records that final response at the auditor report path.

Evidence to review:
- Supervisor task: {task}
- Child assignment id: {assignment_id}
- Child worktree path: {worktree_path}
- Run artifact root: {run_dir}
- Child report path: {child_report_path}
- Parent auditor report path: {auditor_report_path}
- Auditor report schema path: {schema_path}
- Assigned worker/review subject ids: {worker_ids}
- Assigned paths: {assigned_paths}
- Child-reported and supervisor-inspected changed paths: {changed_paths}

Review requirements:
- Review the child report, worker_reports, child worktree diff/changed paths, validation_results, findings, remaining_risk, assigned worker IDs, and assigned paths.
- Verify every assigned worker id has adequate WorkerReport coverage and terminal no-delegation evidence. When there are no assigned workers, verify reviewed_worker_ids covers the child orchestrator id for the changed child diff.
- Verify reviewed_paths covers the assigned paths and any changed paths relevant to this child scope.
- Set role="auditor", no_further_delegation=true, read_only=true.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Include reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining_risk, and next_safe_action.

Child report JSON:
{child_report_json}
"#,
        role_prefix = role_prefix,
        task = task,
        assignment_id = assignment.id,
        worktree_path = worktree_path.display(),
        run_dir = run_dir.display(),
        child_report_path = child_report_path.display(),
        auditor_report_path = auditor_report_path.display(),
        schema_path = schema_path.display(),
        worker_ids = display_strings(&required_auditor_prompt_subject_ids(
            assignment,
            child_report,
        )),
        assigned_paths = display_paths(&assignment.assigned_paths),
        changed_paths = display_paths(&child_report.files_changed),
        child_report_json = child_report_json,
    ))
}

fn assignment_task<'a>(
    plan: &'a SupervisorPlan,
    assignment: &'a OrchestratorAssignment,
) -> &'a str {
    assignment.task.as_deref().unwrap_or(&plan.task)
}

fn worker_task<'a>(
    plan: &'a SupervisorPlan,
    assignment: &'a OrchestratorAssignment,
    worker: &'a WorkerAssignment,
) -> &'a str {
    worker
        .task
        .as_deref()
        .or(assignment.task.as_deref())
        .unwrap_or(&plan.task)
}

#[derive(Debug, Clone)]
struct ChildAttemptArtifacts {
    prompt_path: PathBuf,
    report_path: PathBuf,
    log_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ChildAttemptHistory {
    attempt: usize,
    report_path: PathBuf,
    structural_problems: Vec<String>,
    corrective_retry_used: bool,
}

fn child_attempt_artifacts(
    dirs: &RunDirs,
    assignment_id: &str,
    attempt: usize,
    attempt_numbered: bool,
) -> ChildAttemptArtifacts {
    let stem = if attempt_numbered {
        format!("{assignment_id}.attempt-{attempt}")
    } else {
        assignment_id.to_string()
    };
    ChildAttemptArtifacts {
        prompt_path: dirs.assignments.join(format!("{stem}.prompt.md")),
        report_path: dirs.reports.join(format!("{stem}.json")),
        log_path: dirs.logs.join(format!("{stem}.jsonl")),
    }
}

fn prompt_with_corrective_feedback(prompt: &str, problems: &[String]) -> String {
    let problem_list = problems
        .iter()
        .map(|problem| format!("- {problem}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"{prompt}

CORRECTIVE FEEDBACK:
Your previous attempt had structural OrchestratorReviewReport problems:
{problem_list}

Return only a compliant OrchestratorReviewReport JSON final response matching the schema. Do not include Markdown fences, prose, or any non-JSON wrapper.
"#
    )
}

fn append_child_attempt_history(
    report: &mut OrchestratorReviewReport,
    histories: &[ChildAttemptHistory],
) {
    if histories.is_empty() {
        return;
    }
    for history in histories {
        let structural_problems = if history.structural_problems.is_empty() {
            "<none>".to_string()
        } else {
            history.structural_problems.join("; ")
        };
        report.findings.push(Finding {
            severity: FindingSeverity::Info,
            message: format!(
                "child attempt {} history: structural_problems={}; corrective_retry_used={}",
                history.attempt, structural_problems, history.corrective_retry_used
            ),
            paths: vec![history.report_path.clone()],
        });
    }
}

fn run_supervisor_plan(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
) -> Result<SupervisorFinalReport> {
    let repo = discover_repo_root(&options.repo)?;
    if !options.allow_dirty_primary {
        ensure_clean_primary(&repo)?;
    }

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
        write_plan_snapshot(
            &dirs.assignments.join("supervisor-plan.json"),
            &plan,
            &consultant,
        )?;
        write_orchestrator_schema(&dirs.schemas.join("orchestrator-review-report.schema.json"))?;
        write_worker_schema(&dirs.schemas.join("worker-report.schema.json"))?;
        write_auditor_schema(&dirs.schemas.join("auditor-report.schema.json"))?;

        let existing = manager
            .list()?
            .into_iter()
            .map(|record| (record.name.clone(), record))
            .collect::<BTreeMap<_, _>>();

        for assignment in &plan.assignments {
            let current_primary_head = current_head_oid(&repo)?;
            let worktree = match existing.get(&assignment.id) {
                Some(record) => {
                    ensure_reusable_child_worktree(record, &current_primary_head)?;
                    record.clone()
                }
                None => manager.create(WorktreeCreateOptions {
                    agent_id: assignment.id.clone(),
                    branch: None,
                    base: None,
                    worktree_root: None,
                })?,
            };
            let child_base_head = current_head_oid(&worktree.path).with_context(|| {
                format!(
                    "failed to capture base HEAD for child worktree '{}' at {}",
                    assignment.id,
                    worktree.path.display()
                )
            })?;

            let claim = match sync_store
                .claim_paths(&assignment.id, assignment.assigned_paths.iter())
            {
                Ok(claim) => claim,
                Err(error) => {
                    findings.push(claim_failure_finding(&sync_store, assignment, &error));
                    return Err(error)
                        .with_context(|| format!("failed to claim paths for '{}'", assignment.id));
                }
            };
            acquired_claim_tokens.push(claim.token);

            let semantic_token = coordinate_semantic_assignment(
                &semantic_store,
                assignment,
                plan.semantic_coordination,
                &mut acquired_semantic_tokens,
                &mut planned_semantic_intents,
                &mut findings,
            )?;

            let final_report_path = dirs.reports.join(format!("{}.json", assignment.id));
            let final_prompt_path = dirs
                .assignments
                .join(format!("{}.prompt.md", assignment.id));
            let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
            let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
            let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
            let prompt = child_orchestrator_prompt(ChildOrchestratorPromptContext {
                plan: &plan,
                assignment,
                run_dir: &run_dir,
                worktree: &worktree,
                report_path: &final_report_path,
                schema_path: &schema_path,
                worker_schema_path: &worker_schema_path,
                auditor_schema_path: &auditor_schema_path,
                consultant: &consultant,
                claim_context: ChildPromptClaimContext {
                    claim: &claim,
                    semantic_intent_token: semantic_token,
                },
            })?;
            fs::write(&final_prompt_path, &prompt).with_context(|| {
                format!("failed to write prompt {}", final_prompt_path.display())
            })?;

            let mut child_report = None;
            let mut retry_feedback: Option<Vec<String>> = None;
            let mut attempt_history = Vec::new();
            let max_attempts = usize::from(plan.max_child_retries).saturating_add(1);
            for attempt in 1..=max_attempts {
                let attempt_artifacts =
                    child_attempt_artifacts(&dirs, &assignment.id, attempt, max_attempts > 1);
                let corrective_retry_used = retry_feedback.is_some();
                let attempt_prompt = match &retry_feedback {
                    Some(problems) => prompt_with_corrective_feedback(&prompt, problems),
                    None => prompt.clone(),
                };
                fs::write(&attempt_artifacts.prompt_path, attempt_prompt).with_context(|| {
                    format!(
                        "failed to write prompt {}",
                        attempt_artifacts.prompt_path.display()
                    )
                })?;

                let primary_before = primary_worktree_snapshot(&repo)?;
                if let Some(error) = primary_before.inspection_problem() {
                    bail!("refusing to launch child without a complete primary integrity snapshot: {error}");
                }
                let mut command = ExternalAgentCommand::codex(
                    &options.codex_bin,
                    &worktree.path,
                    &attempt_artifacts.prompt_path,
                    &attempt_artifacts.log_path,
                    &attempt_artifacts.report_path,
                    Duration::from_secs(plan.child_timeout_seconds),
                );
                command.output_schema = Some(schema_path.clone());

                let external_run = run_external_agent(&command);
                command_records.push(command_record_from_external(&external_run));
                let primary_after = primary_worktree_snapshot(&repo)?;
                let primary_changes = primary_integrity_changes(&primary_before, &primary_after);
                let (mut attempt_report, report_shape_problems) = collect_child_report(
                    assignment,
                    &attempt_artifacts.report_path,
                    &external_run,
                    &worktree.path,
                    &child_base_head,
                );
                if !primary_changes.is_empty() {
                    mark_primary_integrity_violation(
                        assignment,
                        &primary_changes,
                        &mut attempt_report,
                    );
                }
                let retry_used = should_retry_child_report(
                    &attempt_report,
                    &report_shape_problems,
                    attempt,
                    plan.max_child_retries,
                );
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.report_path.clone(),
                    structural_problems: report_shape_problems.clone(),
                    corrective_retry_used,
                });
                if retry_used {
                    retry_feedback = Some(report_shape_problems);
                    continue;
                }
                if attempt > 1 {
                    attempt_report.findings.push(Finding {
                        severity: FindingSeverity::Warning,
                        message: format!(
                            "child report accepted after corrective retry attempt {attempt}"
                        ),
                        paths: vec![attempt_artifacts.report_path.clone()],
                    });
                }
                child_report = Some(attempt_report);
                break;
            }

            let mut child_report = child_report.with_context(|| {
                format!(
                    "child orchestrator '{}' did not produce a collected report after retries",
                    assignment.id
                )
            })?;

            if plan.max_child_retries > 0 {
                append_child_attempt_history(&mut child_report, &attempt_history);
            }
            write_child_report(&final_report_path, &child_report)?;

            if parent_auditor_required(assignment, &child_report) {
                let auditor_id = parent_auditor_id(assignment);
                let auditor_prompt_path = dirs.assignments.join(format!("{auditor_id}.prompt.md"));
                let auditor_report_path = dirs.reports.join(format!("{auditor_id}.json"));
                let auditor_log_path = dirs.logs.join(format!("{auditor_id}.jsonl"));
                let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
                let auditor_prompt =
                    parent_review_auditor_prompt(ParentReviewAuditorPromptContext {
                        plan: &plan,
                        assignment,
                        run_dir: &run_dir,
                        worktree_path: &worktree.path,
                        child_report_path: &final_report_path,
                        auditor_report_path: &auditor_report_path,
                        schema_path: &auditor_schema_path,
                        child_report: &child_report,
                    })?;
                fs::write(&auditor_prompt_path, auditor_prompt).with_context(|| {
                    format!(
                        "failed to write auditor prompt {}",
                        auditor_prompt_path.display()
                    )
                })?;

                let mut auditor_command = ExternalAgentCommand::codex(
                    &options.codex_bin,
                    &worktree.path,
                    &auditor_prompt_path,
                    &auditor_log_path,
                    &auditor_report_path,
                    Duration::from_secs(plan.child_timeout_seconds),
                );
                auditor_command.output_schema = Some(auditor_schema_path);
                auditor_command.sandbox_mode = "read-only".to_string();

                let auditor_run = run_external_agent(&auditor_command);
                let auditor_command_record = command_record_from_external(&auditor_run);
                command_records.push(auditor_command_record.clone());
                child_report.commands_run.push(auditor_command_record);
                let auditor_report =
                    collect_parent_auditor_report(assignment, &auditor_report_path, &auditor_run);
                child_report.audit_reports.push(auditor_report);
            }
            validate_auditor_reports(assignment, &final_report_path, &mut child_report);
            write_child_report(&final_report_path, &child_report)?;
            if child_report.status != ReviewStatus::Succeeded {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!("child orchestrator '{}' failed", assignment.id),
                    paths: vec![final_report_path.clone()],
                });
            }
            if child_report.audit_reports.iter().any(report_failed) {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "child orchestrator '{}' failed enforced parent review auditor gate",
                        assignment.id
                    ),
                    paths: vec![final_report_path.clone()],
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
    if plan.max_child_retries > MAX_CHILD_RETRIES_LIMIT {
        bail!(
            "max_child_retries must be at most {}",
            MAX_CHILD_RETRIES_LIMIT
        );
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

fn validate_consultant_plan(consultant: &SupervisorConsultantPlan) -> Result<()> {
    if !matches!(consultant.runtime.as_str(), "fake" | "codex" | "claude") {
        bail!("consultant.runtime must be one of: fake, codex, claude");
    }
    if consultant.enabled && consultant.max_consultations == 0 {
        bail!("consultant.max_consultations must be greater than zero when consultant is enabled");
    }
    Ok(())
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
    child_base_head: &Oid,
) -> (OrchestratorReviewReport, Vec<String>) {
    let mut report_shape_problems = Vec::new();
    let mut report = match read_child_report(report_path) {
        Ok(parsed) => {
            let mut report = parsed.report;
            if parsed.recovered {
                report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: LENIENT_JSON_EXTRACTION_WARNING.to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.id != assignment.id {
                let message = format!(
                    "report id '{}' does not match assignment '{}'",
                    report.id, assignment.id
                );
                report_shape_problems.push(message.clone());
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message,
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.role != AgentRole::ChildOrchestrator {
                let message = "orchestrator report role must be child_orchestrator".to_string();
                report_shape_problems.push(message.clone());
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message,
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
            let message = format!("required child report is missing or invalid: {error}");
            report_shape_problems.push(message);
            missing_child_report(assignment, report_path, external_run, error.to_string())
        }
    };
    validate_worker_report_delegation_attestations(assignment, report_path, &mut report);
    verify_child_report_paths(assignment, worktree_path, child_base_head, &mut report);
    validate_worker_report_evidence(assignment, report_path, &mut report);
    (report, report_shape_problems)
}

fn collect_parent_auditor_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
) -> AuditorReport {
    let expected_id = parent_auditor_id(assignment);
    let mut report = match read_auditor_report(report_path) {
        Ok(parsed) => {
            let mut report = parsed.report;
            if parsed.recovered {
                report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: LENIENT_JSON_EXTRACTION_WARNING.to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.id != expected_id {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "parent auditor report id '{}' does not match expected '{}'",
                        report.id, expected_id
                    ),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if !external_run.succeeded() && report.status == ReviewStatus::Succeeded {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "external parent review auditor process failed despite report success"
                        .to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            report
        }
        Err(error) => missing_parent_auditor_report(&expected_id, report_path, external_run, error),
    };
    report
        .commands_run
        .push(command_record_from_external(external_run));
    report
}

fn validate_auditor_reports(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let required_review_subject_ids = required_auditor_review_subject_ids(assignment, report);
    if required_review_subject_ids.is_empty() {
        return;
    }

    let required_parent_auditor_id = parent_auditor_id(assignment);
    let required_reviewed_paths = required_auditor_review_paths(assignment, report);
    let mut covered_review_subject_ids = BTreeSet::<String>::new();
    let mut parent_auditor_accepted = false;
    let mut invalid_auditors = Vec::new();

    for audit_report in &mut report.audit_reports {
        let mut valid = true;
        let mut messages = Vec::new();
        if audit_report.role != AgentRole::Auditor {
            valid = false;
            messages.push("auditor report role must be auditor".to_string());
        }
        if audit_report.no_further_delegation != Some(true) {
            valid = false;
            messages.push(match audit_report.no_further_delegation {
                Some(false) => "auditor report indicates further delegation".to_string(),
                None => "auditor report omitted no_further_delegation terminal-auditor attestation"
                    .to_string(),
                Some(true) => String::new(),
            });
        }
        if !audit_report.read_only {
            valid = false;
            messages.push("auditor report omitted read_only review-only attestation".to_string());
        }
        if audit_report.reviewed_worker_ids.is_empty() {
            valid = false;
            messages.push("auditor report omitted reviewed_worker_ids evidence".to_string());
        }
        if audit_report.reviewed_paths.is_empty() {
            valid = false;
            messages.push("auditor report omitted reviewed_paths evidence".to_string());
        }
        if audit_report.commands_run.is_empty() {
            valid = false;
            messages.push("auditor report omitted commands_run evidence".to_string());
        }
        if audit_report.validation_results.is_empty() {
            valid = false;
            messages.push("auditor report omitted validation_results evidence".to_string());
        }
        if audit_report.remaining_risk.trim().is_empty() {
            valid = false;
            messages.push("auditor report omitted remaining_risk evidence".to_string());
        }
        if audit_report.next_safe_action.trim().is_empty() {
            valid = false;
            messages.push("auditor report omitted next_safe_action evidence".to_string());
        }
        if !audit_report.accepted
            || audit_report.rejected
            || audit_report.status != ReviewStatus::Succeeded
        {
            valid = false;
            messages.push("auditor report was not accepted as succeeded".to_string());
        }
        if audit_report.id == required_parent_auditor_id {
            match missing_auditor_review_paths(audit_report, &required_reviewed_paths) {
                Ok(missing_paths) if missing_paths.is_empty() => {}
                Ok(missing_paths) => {
                    valid = false;
                    messages.push(format!(
                        "parent auditor reviewed_paths omitted required assignment/change path coverage for: {}",
                        display_paths(&missing_paths)
                    ));
                }
                Err(error) => {
                    valid = false;
                    messages.push(format!(
                        "auditor report reviewed_paths are invalid: {error}"
                    ));
                }
            }
        }

        if valid {
            if audit_report.id == required_parent_auditor_id {
                parent_auditor_accepted = true;
            }
            covered_review_subject_ids.extend(
                audit_report
                    .reviewed_worker_ids
                    .iter()
                    .filter(|id| required_review_subject_ids.contains(id.as_str()))
                    .cloned(),
            );
            continue;
        }

        audit_report.status = ReviewStatus::Failed;
        audit_report.accepted = false;
        audit_report.rejected = true;
        for message in messages.into_iter().filter(|message| !message.is_empty()) {
            audit_report.findings.push(Finding {
                severity: FindingSeverity::Error,
                message,
                paths: vec![report_path.to_path_buf()],
            });
        }
        invalid_auditors.push(audit_report.id.clone());
    }

    let missing_review_subject_ids = required_review_subject_ids
        .difference(&covered_review_subject_ids)
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();

    if invalid_auditors.is_empty()
        && missing_review_subject_ids.is_empty()
        && parent_auditor_accepted
    {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;

    if !assignment.worker_assignments.is_empty() && report.worker_reports.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' contained zero worker_reports despite assigned worker IDs: {}",
                report.id,
                display_strings(
                    &assignment
                        .worker_assignments
                        .iter()
                        .map(|worker| worker.id.clone())
                        .collect::<Vec<_>>()
                )
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if report.audit_reports.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted required review auditor report for worker assignments",
                report.id
            ),
            paths: vec![report_path.to_path_buf()],
        });
    } else if !missing_review_subject_ids.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted accepted review auditor coverage for review subject IDs: {}",
                report.id,
                missing_review_subject_ids.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !parent_auditor_accepted {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' lacks accepted parent-launched review auditor report '{}'",
                report.id, required_parent_auditor_id
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !invalid_auditors.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' included invalid review auditor reports: {}",
                report.id,
                invalid_auditors.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    report.remaining_risk =
        "required terminal review-auditor evidence is missing or invalid".to_string();
    report.next_safe_action =
        "rerun the child scope with a read-only review auditor before finalizing".to_string();
}

fn parent_auditor_required(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> bool {
    (!assignment.worker_assignments.is_empty() && !report.worker_reports.is_empty())
        || (assignment.worker_assignments.is_empty() && !report.files_changed.is_empty())
}

fn required_auditor_review_subject_ids(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> BTreeSet<String> {
    if assignment.worker_assignments.is_empty() {
        if report.files_changed.is_empty() {
            BTreeSet::new()
        } else {
            BTreeSet::from([report.id.clone()])
        }
    } else {
        assignment
            .worker_assignments
            .iter()
            .map(|worker| worker.id.clone())
            .collect()
    }
}

fn required_auditor_prompt_subject_ids(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> Vec<String> {
    required_auditor_review_subject_ids(assignment, report)
        .into_iter()
        .collect()
}

fn required_auditor_review_paths(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> Vec<PathBuf> {
    collapse_covered_paths(
        assignment
            .assigned_paths
            .iter()
            .chain(report.files_changed.iter())
            .cloned()
            .collect(),
    )
}

fn missing_auditor_review_paths(
    audit_report: &AuditorReport,
    required_paths: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let reviewed_paths = normalize_paths(audit_report.reviewed_paths.clone())
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(required_paths
        .iter()
        .filter(|required| {
            !reviewed_paths
                .iter()
                .any(|reviewed| path_is_covered_by_claim(required, reviewed))
        })
        .cloned()
        .collect())
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
    child_base_head: &Oid,
    report: &mut OrchestratorReviewReport,
) {
    let reported_paths = normalize_paths(report.files_changed.clone());
    let actual_paths = match collect_paths_changed_since_base(worktree_path, child_base_head) {
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

fn validate_worker_report_evidence(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    if report.worker_reports.is_empty() {
        return;
    }

    let workers_by_id = assignment
        .worker_assignments
        .iter()
        .map(|worker| (worker.id.as_str(), worker))
        .collect::<BTreeMap<_, _>>();
    let actual_paths = report.files_changed.clone();
    let actual_set = actual_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut reported_union = BTreeSet::<PathBuf>::new();
    let mut blocking_messages = Vec::new();

    for worker_report in &mut report.worker_reports {
        let normalized_files_changed = match normalize_paths(worker_report.files_changed.clone()) {
            Ok(paths) => {
                worker_report.files_changed = paths.clone();
                paths
            }
            Err(error) => {
                let message = format!(
                    "worker '{}' reported invalid files_changed paths: {error}",
                    worker_report.id
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![report_path.to_path_buf()],
                );
                blocking_messages.push((message, vec![report_path.to_path_buf()]));
                Vec::new()
            }
        };
        reported_union.extend(normalized_files_changed.iter().cloned());

        let allowed_paths = if let Some(worker) = workers_by_id.get(worker_report.id.as_str()) {
            worker.assigned_paths.clone()
        } else {
            let message = format!(
                "worker '{}' is not declared in assignment '{}' worker_assignments",
                worker_report.id, assignment.id
            );
            let paths = if normalized_files_changed.is_empty() {
                vec![report_path.to_path_buf()]
            } else {
                normalized_files_changed.clone()
            };
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                paths.clone(),
            );
            blocking_messages.push((message, paths));
            Vec::new()
        };
        let unauthorized_paths = normalized_files_changed
            .iter()
            .filter(|path| {
                !allowed_paths
                    .iter()
                    .any(|assigned| path_is_covered_by_claim(path, assigned))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unauthorized_paths.is_empty() {
            let message = format!(
                "worker '{}' reported files_changed outside its assigned_paths: {}",
                worker_report.id,
                display_paths(&unauthorized_paths)
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                unauthorized_paths.clone(),
            );
            blocking_messages.push((message, unauthorized_paths));
        }

        if worker_report.accepted
            && worker_report.status == ReviewStatus::Succeeded
            && worker_report
                .validation_results
                .iter()
                .any(validation_failed)
        {
            let failed_validation_paths = if normalized_files_changed.is_empty() {
                vec![report_path.to_path_buf()]
            } else {
                normalized_files_changed.clone()
            };
            let message = format!(
                "worker '{}' reports failed validation while accepted=true and status=succeeded",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                failed_validation_paths.clone(),
            );
            blocking_messages.push((message, failed_validation_paths));
        }
    }

    let reported_but_not_observed = reported_union
        .difference(&actual_set)
        .cloned()
        .collect::<Vec<_>>();
    let observed_but_not_reported = actual_set
        .difference(&reported_union)
        .cloned()
        .collect::<Vec<_>>();
    if !reported_but_not_observed.is_empty() || !observed_but_not_reported.is_empty() {
        let paths = union_paths(&reported_but_not_observed, &observed_but_not_reported);
        report.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: format!(
                "worker files_changed union differs from actual child worktree Git changes; reported-but-not-observed: {}; observed-but-not-reported: {}",
                display_paths(&reported_but_not_observed),
                display_paths(&observed_but_not_reported)
            ),
            paths,
        });
    }

    if blocking_messages.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    for (message, paths) in blocking_messages {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message,
            paths,
        });
    }
    report.remaining_risk =
        "one or more worker reports have structural evidence inconsistencies".to_string();
    report.next_safe_action =
        "inspect worker reports and rerun the child scope with corrected evidence".to_string();
}

fn mark_worker_report_structural_inconsistency(
    worker_report: &mut WorkerReport,
    message: String,
    paths: Vec<PathBuf>,
) {
    worker_report.status = ReviewStatus::Failed;
    worker_report.accepted = false;
    worker_report.rejected = true;
    worker_report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message,
        paths,
    });
}

fn should_retry_child_report(
    report: &OrchestratorReviewReport,
    report_shape_problems: &[String],
    attempt: usize,
    max_child_retries: u8,
) -> bool {
    if report_shape_problems.is_empty() || attempt > usize::from(max_child_retries) {
        return false;
    }
    if report.worker_reports.iter().any(report_failed)
        || report.validation_results.iter().any(validation_failed)
    {
        return false;
    }
    !report.findings.iter().any(|finding| {
        finding.severity == FindingSeverity::Error
            && !report_shape_problems
                .iter()
                .any(|problem| finding.message.contains(problem))
            && !retryable_cascaded_shape_message(&finding.message)
    })
}

fn retryable_cascaded_shape_message(message: &str) -> bool {
    message.contains("omitted required worker reports for assignment worker IDs")
        || message.contains("contained zero worker_reports despite assigned worker IDs")
}

fn validation_failed(result: &ValidationResult) -> bool {
    result.status != ReviewStatus::Succeeded
}

fn mark_primary_integrity_violation(
    assignment: &OrchestratorAssignment,
    changes: &PrimaryIntegrityChanges,
    report: &mut OrchestratorReviewReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "primary worktree integrity changed during child orchestrator '{}' run: {}",
            assignment.id,
            changes.details.join("; ")
        ),
        paths: changes.paths.clone(),
    });
    report.remaining_risk =
        "child run mutated primary HEAD/ref, index, tracked content, or non-runtime untracked content"
            .to_string();
    report.next_safe_action =
        "inspect and restore the primary worktree before rerunning supervise".to_string();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryWorktreeSnapshot {
    head: PrimaryHeadSnapshot,
    index: BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
    index_storage: PrimaryIndexStorageSnapshot,
    status: BTreeMap<Vec<u8>, Status>,
    worktree: BTreeMap<Vec<u8>, PrimaryPathState>,
    inspection_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryHeadSnapshot {
    detached: bool,
    reference_name: Option<Vec<u8>>,
    symbolic_target: Option<Vec<u8>>,
    target: Option<Oid>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrimaryIndexEntryKey {
    path: Vec<u8>,
    stage: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIndexEntryState {
    id: Oid,
    mode: u32,
    flags: u16,
    flags_extended: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIndexStorageSnapshot {
    worktree_index: IndexFileSnapshot,
    shared_index: Option<IndexFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IndexFileSnapshot {
    Missing,
    Present { bytes: u64, digest: Oid },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrimaryPathState {
    Missing,
    File {
        id: Oid,
        mode: u32,
    },
    Symlink {
        target: PathBuf,
        mode: u32,
    },
    Directory {
        nested_repository: Option<Box<PrimaryWorktreeSnapshot>>,
        mode: u32,
    },
    Other {
        mode: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIntegrityChanges {
    details: Vec<String>,
    paths: Vec<PathBuf>,
}

impl PrimaryIntegrityChanges {
    fn is_empty(&self) -> bool {
        self.details.is_empty()
    }
}

impl PrimaryWorktreeSnapshot {
    fn inspection_problem(&self) -> Option<String> {
        if let Some(error) = &self.inspection_error {
            return Some(error.clone());
        }
        self.worktree.iter().find_map(|(path, state)| {
            let PrimaryPathState::Directory {
                nested_repository: Some(nested),
                ..
            } = state
            else {
                return None;
            };
            nested.inspection_problem().map(|error| {
                format!(
                    "nested repository {}: {error}",
                    finding_path_from_git_bytes(path).display()
                )
            })
        })
    }
}

fn primary_worktree_snapshot(repo_path: &Path) -> Result<PrimaryWorktreeSnapshot> {
    primary_worktree_snapshot_at_depth(repo_path, 0)
}

fn primary_worktree_snapshot_at_depth(
    repo_path: &Path,
    depth: usize,
) -> Result<PrimaryWorktreeSnapshot> {
    if depth > MAX_NESTED_REPOSITORY_DEPTH {
        bail!(
            "primary integrity snapshot exceeded nested repository depth {} at {}",
            MAX_NESTED_REPOSITORY_DEPTH,
            repo_path.display()
        );
    }
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let workdir = repo
        .workdir()
        .context("primary integrity snapshot requires a non-bare repository")?;
    let head = primary_head_snapshot(&repo)?;
    let (status, index, inspection_error) =
        match repository_status_snapshot(&repo, "failed to inspect primary worktree status") {
            Ok(status) => match primary_index_snapshot(&repo) {
                Ok(index) => (status, index, None),
                Err(error) => (status, BTreeMap::new(), Some(error.to_string())),
            },
            Err(error) => (BTreeMap::new(), BTreeMap::new(), Some(error.to_string())),
        };
    let index_storage = primary_index_storage_snapshot(&repo)?;

    let gitlink_paths = index
        .iter()
        .filter(|(_, state)| state.mode == GITLINK_MODE)
        .map(|(key, _)| key.path.clone())
        .collect::<BTreeSet<_>>();
    let mut fingerprint_paths = status.keys().cloned().collect::<BTreeSet<_>>();
    fingerprint_paths.extend(gitlink_paths.iter().cloned());
    fingerprint_paths.extend(
        index
            .iter()
            .filter(|(_, state)| index_entry_requires_fingerprint(state))
            .map(|(key, _)| key.path.clone()),
    );

    let mut worktree = BTreeMap::new();
    for path in fingerprint_paths {
        let relative_path = repo_relative_path_from_git_bytes(&path);
        let state = primary_path_state(
            &workdir.join(&relative_path),
            gitlink_paths.contains(&path),
            depth,
        )
        .with_context(|| {
            format!(
                "failed to fingerprint primary worktree path {}",
                relative_path.display()
            )
        })?;
        worktree.insert(path, state);
    }

    Ok(PrimaryWorktreeSnapshot {
        head,
        index,
        index_storage,
        status,
        worktree,
        inspection_error,
    })
}

fn primary_head_snapshot(repo: &Repository) -> Result<PrimaryHeadSnapshot> {
    let detached = repo.head_detached().unwrap_or(false);
    match repo.head() {
        Ok(head) => Ok(PrimaryHeadSnapshot {
            detached,
            reference_name: Some(head.name_bytes().to_vec()),
            symbolic_target: head.symbolic_target_bytes().map(<[u8]>::to_vec),
            target: head.target(),
        }),
        Err(error) if matches!(error.code(), ErrorCode::NotFound | ErrorCode::UnbornBranch) => {
            Ok(PrimaryHeadSnapshot {
                detached,
                reference_name: None,
                symbolic_target: None,
                target: None,
            })
        }
        Err(error) => Err(error).context("failed to inspect primary HEAD/reference"),
    }
}

fn primary_index_snapshot(
    repo: &Repository,
) -> Result<BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>> {
    let index = repo.index().context("failed to inspect primary index")?;
    let mut entries = BTreeMap::new();
    for entry in index.iter() {
        let key = PrimaryIndexEntryKey {
            path: entry.path,
            stage: (entry.flags >> 12) & 0x3,
        };
        let state = PrimaryIndexEntryState {
            id: entry.id,
            mode: entry.mode,
            flags: entry.flags,
            flags_extended: entry.flags_extended,
        };
        entries.insert(key, state);
    }
    Ok(entries)
}

fn index_entry_requires_fingerprint(state: &PrimaryIndexEntryState) -> bool {
    IndexEntryFlag::from_bits_truncate(state.flags).contains(IndexEntryFlag::VALID)
        || IndexEntryExtendedFlag::from_bits_truncate(state.flags_extended)
            .contains(IndexEntryExtendedFlag::SKIP_WORKTREE)
}

fn primary_index_storage_snapshot(repo: &Repository) -> Result<PrimaryIndexStorageSnapshot> {
    let worktree_index = index_file_snapshot(&repo.path().join("index"))?;
    let shared_index = shared_index_path(repo)?
        .map(|path| index_file_snapshot(&path))
        .transpose()?;
    Ok(PrimaryIndexStorageSnapshot {
        worktree_index,
        shared_index,
    })
}

fn index_file_snapshot(path: &Path) -> Result<IndexFileSnapshot> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IndexFileSnapshot::Missing);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read index storage {}", path.display()));
        }
    };
    Ok(IndexFileSnapshot::Present {
        bytes: bytes.len().try_into().unwrap_or(u64::MAX),
        digest: Oid::hash_object(ObjectType::Blob, &bytes)
            .context("failed to digest index storage")?,
    })
}

fn shared_index_path(repo: &Repository) -> Result<Option<PathBuf>> {
    let workdir = repo
        .workdir()
        .context("shared-index discovery requires a non-bare repository")?;
    let output = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .args(["rev-parse", "--shared-index-path"])
        .output()
        .context("failed to inspect split-index dependency")?;
    if !output.status.success() {
        bail!(
            "failed to inspect split-index dependency: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut path = output.stdout;
    while path
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        path.pop();
    }
    if path.is_empty() {
        return Ok(None);
    }
    let path = repo_relative_path_from_git_bytes(&path);
    Ok(Some(if path.is_absolute() {
        path
    } else {
        workdir.join(path)
    }))
}

fn primary_path_state(
    path: &Path,
    capture_nested_repository: bool,
    depth: usize,
) -> Result<PrimaryPathState> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PrimaryPathState::Missing);
        }
        Err(error) => return Err(error.into()),
    };
    let mode = primary_path_mode(&metadata);
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Ok(PrimaryPathState::Symlink {
            target: fs::read_link(path)?,
            mode,
        });
    }
    if file_type.is_file() {
        return Ok(PrimaryPathState::File {
            id: Oid::hash_file(ObjectType::Blob, path)?,
            mode,
        });
    }
    if file_type.is_dir() {
        let nested_repository = if capture_nested_repository {
            match Repository::open(path) {
                Ok(_) => Some(Box::new(primary_worktree_snapshot_at_depth(
                    path,
                    depth.saturating_add(1),
                )?)),
                Err(error) if error.code() == ErrorCode::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect nested repository {}", path.display())
                    });
                }
            }
        } else {
            None
        };
        return Ok(PrimaryPathState::Directory {
            nested_repository,
            mode,
        });
    }
    Ok(PrimaryPathState::Other { mode })
}

#[cfg(unix)]
fn primary_path_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn primary_path_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn primary_integrity_changes(
    before: &PrimaryWorktreeSnapshot,
    after: &PrimaryWorktreeSnapshot,
) -> PrimaryIntegrityChanges {
    let mut details = Vec::new();
    let mut paths = BTreeSet::new();

    if before.head != after.head {
        details.push(format!(
            "HEAD/reference changed from {} to {}",
            display_primary_head(&before.head),
            display_primary_head(&after.head)
        ));
        paths.insert(PathBuf::from(".git/HEAD"));
    }

    let index_paths = changed_index_paths(&before.index, &after.index);
    if !index_paths.is_empty() {
        details.push(format!(
            "index changed for {}",
            display_git_paths(&index_paths)
        ));
        paths.extend(
            index_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    if before.index_storage != after.index_storage {
        details.push("raw worktree index or split-index storage changed".to_string());
        paths.insert(PathBuf::from(".git/index"));
    }

    if before.inspection_error != after.inspection_error {
        details.push("primary index/status inspectability changed".to_string());
        paths.insert(PathBuf::from(".git/index"));
    }

    let status_paths = changed_snapshot_paths(&before.status, &after.status);
    if !status_paths.is_empty() {
        details.push(format!(
            "Git status changed for {}",
            display_git_paths(&status_paths)
        ));
        paths.extend(
            status_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    let worktree_paths = changed_snapshot_paths(&before.worktree, &after.worktree);
    if !worktree_paths.is_empty() {
        details.push(format!(
            "worktree content/type changed for {}",
            display_git_paths(&worktree_paths)
        ));
        paths.extend(
            worktree_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    PrimaryIntegrityChanges {
        details,
        paths: paths.into_iter().collect(),
    }
}

fn changed_index_paths(
    before: &BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
    after: &BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
) -> BTreeSet<Vec<u8>> {
    before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| key.path.clone())
        .collect()
}

fn changed_snapshot_paths<T: PartialEq>(
    before: &BTreeMap<Vec<u8>, T>,
    after: &BTreeMap<Vec<u8>, T>,
) -> BTreeSet<Vec<u8>> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect()
}

fn display_primary_head(head: &PrimaryHeadSnapshot) -> String {
    let reference = head
        .reference_name
        .as_deref()
        .map(String::from_utf8_lossy)
        .map(|name| name.into_owned())
        .unwrap_or_else(|| "<missing>".to_string());
    let target = head
        .target
        .map(|target| target.to_string())
        .unwrap_or_else(|| "<missing>".to_string());
    let mode = if head.detached {
        "detached"
    } else {
        "attached"
    };
    format!("{reference}@{target} ({mode})")
}

fn display_git_paths(paths: &BTreeSet<Vec<u8>>) -> String {
    paths
        .iter()
        .map(|path| finding_path_from_git_bytes(path).display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn finding_path_from_git_bytes(path: &[u8]) -> PathBuf {
    match std::str::from_utf8(path) {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(format!("<non-utf8-git-path>/{}", hex_encode(path))),
    }
}

fn serialize_finding_paths<S>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| serializable_path(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn serializable_path(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }
    serializable_non_utf8_path(path)
}

#[cfg(unix)]
fn serializable_non_utf8_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    format!(
        "<non-utf8-git-path>/{}",
        hex_encode(path.as_os_str().as_bytes())
    )
}

#[cfg(target_os = "windows")]
fn serializable_non_utf8_path(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;
    format!(
        "<non-unicode-windows-path>/{}",
        path.as_os_str()
            .encode_wide()
            .map(|unit| format!("{unit:04x}"))
            .collect::<String>()
    )
}

#[cfg(not(any(unix, target_os = "windows")))]
fn serializable_non_utf8_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn claim_failure_finding(
    sync_store: &SyncStore,
    assignment: &OrchestratorAssignment,
    error: &anyhow::Error,
) -> Finding {
    let conflicts = claim_conflict_details(sync_store, &assignment.assigned_paths);
    let paths = conflicts
        .iter()
        .map(|conflict| conflict.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let detail = if conflicts.is_empty() {
        error.to_string()
    } else {
        conflicts
            .iter()
            .map(|conflict| {
                format!(
                    "{} currently claimed by {}",
                    conflict.path.display(),
                    conflict.owner
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    Finding {
        severity: FindingSeverity::Error,
        message: format!("failed to claim paths for '{}': {}", assignment.id, detail),
        paths,
    }
}

#[derive(Debug, Clone)]
struct ClaimConflictDetail {
    path: PathBuf,
    owner: String,
}

fn claim_conflict_details(
    sync_store: &SyncStore,
    requested_paths: &[PathBuf],
) -> Vec<ClaimConflictDetail> {
    match sync_store.snapshot() {
        Ok(claims) => claims
            .iter()
            .flat_map(|claim| {
                claim.paths.iter().filter_map(|claimed| {
                    requested_paths
                        .iter()
                        .find(|requested| paths_overlap(claimed, requested))
                        .map(|requested| ClaimConflictDetail {
                            path: requested.clone(),
                            owner: format!("{} (token {})", claim.agent_id, claim.token.get()),
                        })
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedReport<T> {
    report: T,
    recovered: bool,
}

fn read_child_report(path: &Path) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read child report {}", path.display()))?;
    parse_report_json(&contents)
        .with_context(|| format!("failed to parse child report {}", path.display()))
}

fn write_child_report(path: &Path, report: &OrchestratorReviewReport) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("failed to update child report {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, report)
        .with_context(|| format!("failed to write updated child report {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish updated child report {}", path.display()))
}

fn read_auditor_report(path: &Path) -> Result<ParsedReport<AuditorReport>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read auditor report {}", path.display()))?;
    parse_report_json(&contents)
        .with_context(|| format!("failed to parse auditor report {}", path.display()))
}

fn parse_report_json<T>(contents: &str) -> Result<ParsedReport<T>>
where
    T: DeserializeOwned,
{
    if let Ok(report) = serde_json::from_str(contents) {
        return Ok(ParsedReport {
            report,
            recovered: false,
        });
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Ok(report) = serde_json::from_str(stripped) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(object) = last_top_level_json_object(contents) {
        if let Ok(report) = serde_json::from_str(object) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Some(object) = last_top_level_json_object(stripped) {
            if let Ok(report) = serde_json::from_str(object) {
                return Ok(ParsedReport {
                    report,
                    recovered: true,
                });
            }
        }
    }

    Err(anyhow!(
        "report is not valid JSON and lenient JSON extraction failed"
    ))
}

fn strip_surrounding_markdown_fence(contents: &str) -> Option<&str> {
    let trimmed = contents.trim();
    if !trimmed.starts_with("```") || !trimmed.ends_with("```") {
        return None;
    }

    let first_newline = trimmed.find('\n')?;
    let (opening, body_with_closing) = trimmed.split_at(first_newline);
    let info = opening.trim_start_matches("```").trim();
    if !info.is_empty() && info != "json" {
        return None;
    }
    let body_with_closing = body_with_closing.trim_start_matches('\n');
    let closing_start = body_with_closing.rfind("```")?;
    Some(body_with_closing[..closing_start].trim())
}

fn last_top_level_json_object(contents: &str) -> Option<&str> {
    let mut depth = 0usize;
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut last_object = None;

    for (index, character) in contents.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match character {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth = depth.saturating_add(1);
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    if let Some(object_start) = start.take() {
                        let object_end = index + character.len_utf8();
                        last_object = contents.get(object_start..object_end);
                    }
                }
            }
            _ => {}
        }
    }

    last_object
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
        audit_reports: Vec::new(),
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        remaining_risk: "child orchestrator did not produce a usable report".to_string(),
        next_safe_action: "inspect child logs and rerun the failed assignment".to_string(),
    }
}

fn missing_parent_auditor_report(
    expected_id: &str,
    report_path: &Path,
    _external_run: &ExternalAgentRun,
    error: anyhow::Error,
) -> AuditorReport {
    AuditorReport {
        id: expected_id.to_string(),
        role: AgentRole::Auditor,
        reviewed_worker_ids: Vec::new(),
        reviewed_paths: Vec::new(),
        commands_run: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "required parent-launched auditor report is missing or invalid: {error}"
            ),
            paths: vec![report_path.to_path_buf()],
        }],
        no_further_delegation: Some(true),
        read_only: true,
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        remaining_risk: "parent-launched review auditor did not produce a usable report"
            .to_string(),
        next_safe_action: "inspect auditor logs and rerun the child scope".to_string(),
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

impl ReportStatus for AuditorReport {
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
    Ok(!repository_dirty_paths(repo, context)?.is_empty())
}

fn repository_dirty_paths(repo: &Repository, context: &'static str) -> Result<Vec<PathBuf>> {
    Ok(repository_status_snapshot(repo, context)?
        .keys()
        .map(|path| repo_relative_path_from_git_bytes(path))
        .collect())
}

fn repository_status_snapshot(
    repo: &Repository,
    context: &'static str,
) -> Result<BTreeMap<Vec<u8>, Status>> {
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo.statuses(Some(&mut options)).context(context)?;
    let mut paths = BTreeMap::new();
    for entry in statuses.iter() {
        let path = entry.path_bytes();
        let status = entry.status();
        if is_untracked_runtime_artifact(path, status) {
            continue;
        }
        paths
            .entry(path.to_vec())
            .and_modify(|existing| *existing |= status)
            .or_insert(status);
    }
    Ok(paths)
}

fn is_untracked_runtime_artifact(path: &[u8], status: Status) -> bool {
    status == Status::WT_NEW
        && LOCAL_RUNTIME_ROOTS
            .iter()
            .any(|root| path_is_at_or_below(path, root))
}

fn path_is_at_or_below(path: &[u8], root: &[u8]) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

#[cfg(unix)]
fn repo_relative_path_from_git_bytes(path: &[u8]) -> PathBuf {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    PathBuf::from(OsString::from_vec(path.to_vec()))
}

#[cfg(not(unix))]
fn repo_relative_path_from_git_bytes(path: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(path).into_owned())
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
        .with_context(|| format!("failed to find child base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for child base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let mut diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff child worktree against child base commit")?;
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

fn write_plan_snapshot(
    path: &Path,
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("failed to create plan snapshot {}", path.display()))?;
    let value = supervisor_plan_value(plan, consultant)?;
    serde_json::to_writer_pretty(&mut file, &value)
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
            "additionalProperties": false,
            "required": [
                "id",
                "role",
                "assigned_paths",
                "semantic_symbols",
                "semantic_modules",
                "claim_token",
                "semantic_intent_token",
                "commands_run",
                "files_changed",
                "validation_results",
                "findings",
                "worker_reports",
                "audit_reports",
                "accepted",
                "rejected",
                "status",
                "remaining_risk",
                "next_safe_action"
            ],
            "properties": {
                "id": {"type": "string"},
                "role": {"type": "string", "const": "child_orchestrator"},
                "assigned_paths": {"type": "array", "items": {"type": "string"}},
                "semantic_symbols": {"type": "array", "items": {"type": "string"}},
                "semantic_modules": {"type": "array", "items": {"type": "string"}},
                "claim_token": {"type": ["integer", "null"]},
                "semantic_intent_token": {"type": ["integer", "null"]},
                "commands_run": {"type": "array", "items": command_run_record_schema_value()},
                "files_changed": {"type": "array", "items": {"type": "string"}},
                "validation_results": {"type": "array", "items": validation_result_schema_value()},
                "findings": {"type": "array", "items": finding_schema_value()},
                "worker_reports": {"type": "array", "items": worker_report_schema_value()},
                "audit_reports": {"type": "array", "items": auditor_report_schema_value()},
                "accepted": {"type": "boolean"},
                "rejected": {"type": "boolean"},
                "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
                "remaining_risk": {"type": "string"},
                "next_safe_action": {"type": "string"}
            }
        }),
    )
}

fn write_worker_schema(path: &Path) -> Result<()> {
    write_schema(path, worker_report_schema_value())
}

fn write_auditor_schema(path: &Path) -> Result<()> {
    write_schema(path, auditor_report_schema_value())
}

fn auditor_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AuditorReport",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "role",
            "reviewed_worker_ids",
            "reviewed_paths",
            "commands_run",
            "validation_results",
            "findings",
            "no_further_delegation",
            "read_only",
            "accepted",
            "rejected",
            "status",
            "remaining_risk",
            "next_safe_action"
        ],
        "properties": {
            "id": {"type": "string"},
            "role": {"type": "string", "const": "auditor"},
            "reviewed_worker_ids": {"type": "array", "items": {"type": "string"}},
            "reviewed_paths": {"type": "array", "items": {"type": "string"}},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "no_further_delegation": {"type": "boolean", "const": true},
            "read_only": {"type": "boolean", "const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        }
    })
}

fn worker_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "WorkerReport",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "role",
            "assigned_paths",
            "semantic_symbols",
            "semantic_modules",
            "claim_token",
            "semantic_intent_token",
            "commands_run",
            "files_changed",
            "validation_results",
            "findings",
            "no_further_delegation",
            "accepted",
            "rejected",
            "status",
            "remaining_risk",
            "next_safe_action"
        ],
        "properties": {
            "id": {"type": "string"},
            "role": {"type": "string", "const": "worker"},
            "assigned_paths": {"type": "array", "items": {"type": "string"}},
            "semantic_symbols": {"type": "array", "items": {"type": "string"}},
            "semantic_modules": {"type": "array", "items": {"type": "string"}},
            "claim_token": {"type": ["integer", "null"]},
            "semantic_intent_token": {"type": ["integer", "null"]},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "files_changed": {"type": "array", "items": {"type": "string"}},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "no_further_delegation": {"type": "boolean", "const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        }
    })
}

fn command_run_record_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "command",
            "cwd",
            "exit_code",
            "status",
            "timeout_seconds",
            "duration_ms",
            "timed_out",
            "stdout",
            "stderr",
            "error"
        ],
        "properties": {
            "command": {"type": "array", "items": {"type": "string"}},
            "cwd": {"type": "string"},
            "exit_code": {"type": ["integer", "null"]},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "timeout_seconds": {"type": "integer"},
            "duration_ms": {"type": "integer"},
            "timed_out": {"type": "boolean"},
            "stdout": {"type": "string"},
            "stderr": {"type": "string"},
            "error": {"type": ["string", "null"]}
        }
    })
}

fn validation_result_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "status", "command", "message"],
        "properties": {
            "name": {"type": "string"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "command": {"type": "array", "items": {"type": "string"}},
            "message": {"type": ["string", "null"]}
        }
    })
}

fn finding_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["severity", "message", "paths"],
        "properties": {
            "severity": {"type": "string", "enum": ["info", "warning", "error"]},
            "message": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}}
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

fn parent_auditor_id(assignment: &OrchestratorAssignment) -> String {
    format!("{}-review-auditor", assignment.id)
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

fn display_strings(values: &[String]) -> String {
    if values.is_empty() {
        return "<none>".to_string();
    }
    values.join(", ")
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

fn default_max_child_retries() -> u8 {
    DEFAULT_MAX_CHILD_RETRIES
}

fn default_child_timeout_seconds() -> u64 {
    DEFAULT_CHILD_TIMEOUT_SECONDS
}

fn default_consultant_runtime() -> String {
    "fake".to_string()
}

fn default_max_consultations() -> u32 {
    2
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_child_report_json_without_recovery() {
        let parsed: ParsedReport<OrchestratorReviewReport> =
            parse_report_json(&sample_child_report_json("child-a"))
                .expect("clean child report should parse");
        assert_eq!(parsed.report.id, "child-a");
        assert!(!parsed.recovered);
    }

    #[test]
    fn parses_fenced_auditor_report_json_with_recovery() {
        let contents = format!("```json\n{}\n```", sample_auditor_report_json("auditor-a"));
        let parsed: ParsedReport<AuditorReport> =
            parse_report_json(&contents).expect("fenced auditor report should parse");
        assert_eq!(parsed.report.id, "auditor-a");
        assert!(parsed.recovered);
    }

    #[test]
    fn extracts_last_top_level_child_report_json_with_recovery() {
        let contents = format!(
            "summary before\n{{\"ignored\": true}}\n{}\ntrailing notes",
            sample_child_report_json("child-prose")
        );
        let parsed: ParsedReport<OrchestratorReviewReport> =
            parse_report_json(&contents).expect("prose-wrapped child report should parse");
        assert_eq!(parsed.report.id, "child-prose");
        assert!(parsed.recovered);
    }

    #[test]
    fn rejects_report_garbage_beyond_recovery() {
        let error = parse_report_json::<OrchestratorReviewReport>(
            "not json\n```text\nstill not json\n```\n{broken",
        )
        .expect_err("garbage should not parse");
        assert!(error.to_string().contains("lenient JSON extraction failed"));
    }

    #[cfg(unix)]
    #[test]
    fn finding_serialization_escapes_non_utf8_paths_reversibly() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let finding = Finding {
            severity: FindingSeverity::Error,
            message: "non-UTF8 evidence".to_string(),
            paths: vec![PathBuf::from(OsString::from_vec(vec![
                b'b', b'a', b'd', b'-', 0x80,
            ]))],
        };

        let value = serde_json::to_value(finding).expect("serialize finding");
        assert_eq!(value["paths"][0], "<non-utf8-git-path>/6261642d80");
    }

    #[test]
    fn supervise_role_prefixes_match_runtime_contract() {
        assert_eq!(
            supervise_role_prefix(SupervisePromptRole::O2TopSupervisor, "supervisor", None),
            "ROLE: O2_TOP_SUPERVISOR\nAGENT_KIND: orchestrator\nAGENT_LABEL: supervisor\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 0\nNO_FURTHER_DELEGATION: false\n"
        );
        assert_eq!(
            supervise_role_prefix(SupervisePromptRole::O1ChildOrchestrator, "child-a", None),
            "ROLE: O1_CHILD_ORCHESTRATOR\nAGENT_KIND: child_orchestrator\nAGENT_LABEL: child-a\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 1\nNO_FURTHER_DELEGATION: false\n"
        );
        assert_eq!(
            supervise_role_prefix(SupervisePromptRole::TerminalWorker, "worker-a", None),
            "ROLE: TERMINAL_WORKER\nAGENT_KIND: worker\nAGENT_LABEL: worker-a\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 2\nNO_FURTHER_DELEGATION: true\n"
        );
        assert_eq!(
            supervise_role_prefix(SupervisePromptRole::Researcher, "researcher-a", None),
            "ROLE: RESEARCHER\nAGENT_KIND: researcher\nAGENT_LABEL: researcher-a\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 2\nNO_FURTHER_DELEGATION: true\n"
        );
        assert_eq!(
            supervise_role_prefix(SupervisePromptRole::ReviewAuditor, "auditor-a", None),
            "ROLE: REVIEW_AUDITOR\nAGENT_KIND: auditor\nAGENT_LABEL: auditor-a\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 2\nNO_FURTHER_DELEGATION: true\n"
        );

        let runtime_labeled_worker =
            supervise_role_prefix(SupervisePromptRole::TerminalWorker, "expert-coder", None);
        assert!(runtime_labeled_worker.starts_with("ROLE: TERMINAL_WORKER\n"));
        assert!(runtime_labeled_worker.contains("AGENT_LABEL: expert-coder\n"));
        assert!(!runtime_labeled_worker.contains("ROLE: expert-coder"));
    }

    fn sample_child_report_json(id: &str) -> String {
        format!(
            r#"{{
  "id": "{id}",
  "role": "child_orchestrator",
  "assigned_paths": ["README.md"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "claim_token": null,
  "semantic_intent_token": null,
  "commands_run": [],
  "files_changed": [],
  "validation_results": [],
  "findings": [],
  "worker_reports": [],
  "audit_reports": [],
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review"
}}"#
        )
    }

    fn sample_auditor_report_json(id: &str) -> String {
        format!(
            r#"{{
  "id": "{id}",
  "role": "auditor",
  "reviewed_worker_ids": ["child-a"],
  "reviewed_paths": ["README.md"],
  "commands_run": [],
  "validation_results": [],
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review"
}}"#
        )
    }
}
