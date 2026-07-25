use crate::{
    artifacts::{
        repository_authenticator_key_only, ArtifactFileDisposition, ArtifactRunReader,
        ArtifactRunWriter, ArtifactScratchDirectory, RunArtifactFamily,
    },
    external_agent::{
        codex_usage_from_jsonl, run_external_agent_cancellable, ExternalAgentCommand,
        ExternalAgentRun, ExternalProgramTrust,
    },
    llm::provider::{ModelPricing, Usage},
    merge::{
        collect_agent_result_with_evidence_and_write_lease, CandidateValidationBinding,
        MergeCollectOptions, ValidationEvidenceBundle,
    },
    orchestration_event::{OrchestrationEventJournal, OrchestrationEventKind, OrchestrationRole},
    orchestrator::{RunId, SemanticCoordinationMode},
    process_runner::{
        read_bounded_regular_file_nofollow, run_process, trusted_system_executable,
        EnvironmentMode, ProcessCancellation, ProcessSpec, ProcessTreeEvidence,
        SideEffectConfinementEvidence, SideEffectConfinementProfile, StdinMode,
        StrictOfflineWorkspaceProfile, WorkspaceAccess,
    },
    safe_state::BoundedRegularReader,
    secure_output::SecureOutputRoot,
    semantic_coord::{SemanticIntent, SemanticIntentRequest, SemanticIntentStore},
    swarm_health::{
        AssignmentHealthOutcome, CircuitBreakerTransition, CircuitBreakerTrip,
        CircuitBreakerTripReason, SwarmHealthCircuitBreaker, SwarmHealthSignal,
        SwarmHealthSnapshot,
    },
    sync::{normalize_repo_relative_path, paths_overlap, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{
        ManagedWorktreeWriteLease, RepositoryCleanlinessCapability, WorktreeCreateOptions,
        WorktreeManager, WorktreeRecord,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use git2::{
    Delta, DiffFindOptions, DiffOptions, ErrorCode, ObjectType, Oid, Repository, Status,
    StatusOptions,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 600;
const DEFAULT_MAX_CHILD_ASSIGNMENTS: usize = 4;
const DEFAULT_MAX_CHILD_RETRIES: u8 = 0;
const MAX_CHILD_RETRIES_LIMIT: u8 = 2;
const MIN_SUPERVISOR_DEPTH: u8 = 2;
const MAX_SUPERVISOR_DEPTH: u8 = 32;
const SUPERVISOR_SCHEMA_VERSION: u32 = 1;
const LENIENT_JSON_EXTRACTION_WARNING: &str = "report required lenient JSON extraction";
const GITLINK_MODE: u32 = 0o160000;
const PRIMARY_INDEX_MAX_BYTES: usize = 64 * 1024 * 1024;
const SNAPSHOT_GIT_CAPTURE_MAX_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT_GIT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SUPERVISOR_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SUPERVISOR_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_SUPERVISOR_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SPEC_FRAGMENT_IDS: usize = 4096;
const MAX_SPEC_FRAGMENT_ID_BYTES: usize = 256;
const MAX_WORKER_EXECUTION_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_BLOATED_FILE_FLAGS_PER_WORKER: usize = 64;
const MAX_DECOMPOSITION_REPLACEMENT_PATHS: usize = 256;
const ARTIFACT_FINALIZATION_MARKER: &str = ".maco-artifact-final.json";
const SPARSE_DIRECTORY_MODE: u32 = 0o040000;
const MAX_NESTED_REPOSITORY_DEPTH: usize = 32;
const MAX_DIRECTORY_FINGERPRINT_DEPTH: usize = 256;
const BREAKER_RECOVERY_GUIDANCE: &str = "inspect the breaker window and child evidence, correct the repeated coordination failure, then start a new supervise run; pending assignments were not launched";
const LOCAL_RUNTIME_ROOTS: &[&[u8]] = &[
    b".maco",
    b".maco-cache",
    b".agents/temp",
    b".agents/storage",
    b".agents/live",
];

type CancellableExternalRunner<'a> =
    dyn Fn(&ExternalAgentCommand, &ProcessCancellation) -> ExternalAgentRun + Send + Sync + 'a;

#[derive(Debug, Clone)]
pub struct SupervisorRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub run_id: RunId,
    pub codex_bin: PathBuf,
    pub runtime: SupervisorRuntime,
    pub allow_dirty_primary: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorRuntime {
    #[default]
    Codex,
    Fake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SupervisorPlan {
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub task: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_path"
    )]
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_models: BTreeMap<AgentRole, RoleModelSelection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_pricing: BTreeMap<String, ModelPricing>,
    #[serde(default)]
    pub assignments: Vec<OrchestratorAssignment>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoleModelSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
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

#[derive(Debug, Clone, PartialEq)]
struct LoadedSupervisorPlan {
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    assignment_metadata: AssignmentMetadata,
    plan_metadata: SupervisorPlanMetadata,
}

type AssignmentMetadata = BTreeMap<(String, String), WorkerAssignmentMetadata>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SupervisorPlanMetadata {
    spec_fragment_ids: Vec<String>,
    spec_fragment_ids_by_assignment: BTreeMap<String, Vec<String>>,
    assignment_schedule: Vec<AssignmentScheduleEntry>,
    coverage_gaps: Vec<SupervisorCoverageGap>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
struct WorkerAssignmentMetadata {
    #[serde(default)]
    kind: AssignmentKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_path"
    )]
    target_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OrchestratorAssignment {
    pub id: String,
    #[serde(default = "child_orchestrator_role")]
    pub role: AgentRole,
    #[serde(default, serialize_with = "serialize_paths")]
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
pub struct AssignmentScheduleEntry {
    pub assignment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_assignment_id: Option<String>,
    pub depth: u8,
    pub flattened_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    UnassignedSpecFragment,
    MissingAssignmentReport,
    NoProducedChanges,
    MissingDiffBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SupervisorCoverageGap {
    pub kind: CoverageGapKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_fragment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AssignmentTraceability {
    pub assignment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_assignment_id: Option<String>,
    pub depth: u8,
    pub flattened_index: usize,
    #[serde(default)]
    pub spec_fragment_ids: Vec<String>,
    #[serde(default, serialize_with = "serialize_paths")]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default, serialize_with = "serialize_paths")]
    pub produced_changed_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_diff_binding: Option<CandidateValidationBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_status: Option<ReviewStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerAssignment {
    pub id: String,
    #[serde(default = "worker_role")]
    pub role: AgentRole,
    #[serde(default, serialize_with = "serialize_paths")]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_path"
    )]
    pub report_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Supervisor,
    ChildOrchestrator,
    Worker,
    Auditor,
}

impl AgentRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::ChildOrchestrator => "child_orchestrator",
            Self::Worker => "worker",
            Self::Auditor => "auditor",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentKind {
    #[default]
    Ordinary,
    MegafileDecomposition,
}

impl AssignmentKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::MegafileDecomposition => "megafile_decomposition",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct BloatedFileFlag {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct DecompositionCompletion {
    #[serde(serialize_with = "serialize_path")]
    pub target_path: PathBuf,
    #[serde(default, serialize_with = "serialize_paths")]
    pub replacement_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_candidate_binding: Option<CandidateValidationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedMegafileDecompositionEvidence {
    pub run_id: RunId,
    pub orchestrator_id: String,
    pub worker_id: String,
    #[serde(serialize_with = "serialize_path")]
    pub target_path: PathBuf,
    #[serde(serialize_with = "serialize_paths")]
    pub replacement_paths: Vec<PathBuf>,
    pub supervisor_candidate_binding: CandidateValidationBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerReport {
    pub id: String,
    pub role: AgentRole,
    #[serde(default)]
    pub assignment_kind: AssignmentKind,
    #[serde(default, serialize_with = "serialize_optional_path")]
    pub target_path: Option<PathBuf>,
    #[serde(default, serialize_with = "serialize_paths")]
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
    #[serde(default, serialize_with = "serialize_paths")]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub bloated_file_flags: Vec<BloatedFileFlag>,
    #[serde(default)]
    pub decomposition_completion: Option<DecompositionCompletion>,
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
    #[serde(default, serialize_with = "serialize_paths")]
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
    #[serde(default, serialize_with = "serialize_paths")]
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
    #[serde(default, serialize_with = "serialize_paths")]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub worker_reports: Vec<WorkerReport>,
    #[serde(default)]
    pub audit_reports: Vec<AuditorReport>,
    #[serde(default)]
    pub decomposition_completions: Vec<DecompositionCompletion>,
    pub accepted: bool,
    pub rejected: bool,
    pub status: ReviewStatus,
    #[serde(default)]
    pub remaining_risk: String,
    #[serde(default)]
    pub next_safe_action: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SupervisorFinalReport {
    pub version: u32,
    pub run_id: RunId,
    pub role: AgentRole,
    #[serde(serialize_with = "serialize_path")]
    pub repo: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub plan_file: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub run_dir: PathBuf,
    #[serde(default)]
    pub runtime: SupervisorRuntime,
    pub publishable: bool,
    pub success: bool,
    pub accepted: bool,
    pub rejected: bool,
    pub status: ReviewStatus,
    #[serde(default, serialize_with = "serialize_paths")]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default)]
    pub claim_tokens: Vec<u64>,
    #[serde(default)]
    pub semantic_intent_tokens: Vec<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost_usd: Option<f64>,
    /// True only when usage was observed for every MACO-launched child-orchestrator and auditor
    /// process. Nested workers are reported separately as not process-observable.
    #[serde(default)]
    pub usage_complete: bool,
    #[serde(default)]
    pub commands_run: Vec<CommandRunRecord>,
    #[serde(default, serialize_with = "serialize_paths")]
    pub files_changed: Vec<PathBuf>,
    #[serde(default)]
    pub validation_results: Vec<ValidationResult>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub bloated_file_flags: Vec<BloatedFileFlag>,
    #[serde(default)]
    pub decomposition_candidates: Vec<DecompositionCompletion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignment_traceability: Vec<AssignmentTraceability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_gaps: Vec<SupervisorCoverageGap>,
    #[serde(default)]
    pub breaker_trip: Option<SupervisorBreakerTrip>,
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RoleUsageReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub observation: RoleUsageObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleUsageObservation {
    #[default]
    ProcessObserved,
    SupervisorAggregate,
    NotProcessObservable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SupervisorBreakerTrip {
    pub reason: CircuitBreakerTripReason,
    pub window: SwarmHealthSnapshot,
    pub recovery_guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommandRunRecord {
    pub command: Vec<String>,
    #[serde(serialize_with = "serialize_path")]
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
    #[serde(default, serialize_with = "serialize_paths")]
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SupervisorStatusReport {
    pub run_id: RunId,
    #[serde(serialize_with = "serialize_path")]
    pub repo: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub run_dir: PathBuf,
    #[serde(serialize_with = "serialize_path")]
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
    supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

fn supervisor_plan_and_consultant_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let task = read_supervisor_input(task_file, "task file")?;
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
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            assignments: Vec::new(),
        },
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: SupervisorPlanMetadata::default(),
    })
}

pub fn load_supervisor_plan_file(path: impl AsRef<Path>) -> Result<SupervisorPlan> {
    Ok(load_supervisor_plan_file_with_consultant(path)?.plan)
}

fn load_supervisor_plan_file_with_consultant(
    path: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let path = path.as_ref();
    let contents = read_supervisor_input(path, "supervisor plan")?;
    parse_supervisor_plan_with_consultant(&contents)
        .with_context(|| format!("failed to parse supervisor plan {}", path.display()))
}

fn read_supervisor_input(path: &Path, label: &str) -> Result<String> {
    #[cfg(unix)]
    let bytes = BoundedRegularReader::read_tree_no_follow(path, MAX_SUPERVISOR_INPUT_BYTES);
    #[cfg(not(unix))]
    let bytes = BoundedRegularReader::read(path, MAX_SUPERVISOR_INPUT_BYTES);
    let bytes = bytes.with_context(|| format!("failed to read {label} {}", path.display()))?;
    String::from_utf8(bytes)
        .with_context(|| format!("{label} is not valid UTF-8: {}", path.display()))
}

fn parse_supervisor_plan_with_consultant(contents: &str) -> Result<LoadedSupervisorPlan> {
    let value: Value = serde_json::from_str(contents).context("supervisor plan is not JSON")?;
    let consultant = consultant_from_plan_value(&value)?;
    let mut plan: SupervisorPlan =
        serde_json::from_value(value.clone()).context("supervisor plan fields are invalid")?;
    let plan_metadata = supervisor_plan_metadata_from_value(&value, plan.max_depth)?;
    plan.assignments = assignments_from_plan_value(&value)?;
    let (plan, plan_metadata) = validate_supervisor_plan(plan, plan_metadata)?;
    let assignment_metadata = assignment_metadata_from_plan_value(&value, &plan)?;
    validate_consultant_plan(&consultant)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
    })
}

fn assignments_from_plan_value(value: &Value) -> Result<Vec<OrchestratorAssignment>> {
    let raw_assignments = value
        .get("assignments")
        .and_then(Value::as_array)
        .context("supervisor plan assignments must be an array")?;
    let mut assignments = Vec::new();
    flatten_assignments_from_value(raw_assignments, &mut assignments)?;
    Ok(assignments)
}

fn flatten_assignments_from_value(
    raw_assignments: &[Value],
    assignments: &mut Vec<OrchestratorAssignment>,
) -> Result<()> {
    for raw_assignment in raw_assignments {
        assignments.push(
            serde_json::from_value(raw_assignment.clone())
                .context("supervisor assignment fields are invalid")?,
        );
        let children = raw_assignment
            .get("child_assignments")
            .map(|children| {
                children
                    .as_array()
                    .context("child_assignments must be an array")
            })
            .transpose()?
            .map(Vec::as_slice)
            .unwrap_or_default();
        flatten_assignments_from_value(children, assignments)?;
    }
    Ok(())
}

fn supervisor_plan_metadata_from_value(
    value: &Value,
    max_depth: u8,
) -> Result<SupervisorPlanMetadata> {
    let spec_fragment_ids = optional_string_array(value, "spec_fragment_ids")?;
    let raw_assignments = value
        .get("assignments")
        .and_then(Value::as_array)
        .context("supervisor plan assignments must be an array")?;
    let mut metadata = SupervisorPlanMetadata {
        spec_fragment_ids,
        ..SupervisorPlanMetadata::default()
    };
    collect_assignment_plan_metadata(
        raw_assignments,
        None,
        MIN_SUPERVISOR_DEPTH,
        max_depth,
        &mut metadata,
    )?;
    if let Some(schedule_value) = value.get("assignment_schedule") {
        let supplied_schedule =
            serde_json::from_value::<Vec<AssignmentScheduleEntry>>(schedule_value.clone())
                .context("assignment_schedule is invalid")?;
        let supplied_schedule = validate_assignment_schedule(
            supplied_schedule,
            &metadata.assignment_schedule,
            max_depth,
        )?;
        if raw_assignment_tree_has_children(raw_assignments)
            && supplied_schedule != metadata.assignment_schedule
        {
            bail!("assignment_schedule does not match the recursive assignment tree");
        }
        metadata.assignment_schedule = supplied_schedule;
    }
    Ok(metadata)
}

fn validate_assignment_schedule(
    mut supplied: Vec<AssignmentScheduleEntry>,
    flattened_assignments: &[AssignmentScheduleEntry],
    max_depth: u8,
) -> Result<Vec<AssignmentScheduleEntry>> {
    if supplied.len() != flattened_assignments.len() {
        bail!("assignment_schedule must cover every flattened assignment exactly once");
    }
    let mut by_id = BTreeMap::<String, (usize, u8)>::new();
    for (index, entry) in supplied.iter_mut().enumerate() {
        entry.assignment_id = normalize_agent_id(&entry.assignment_id)?;
        entry.parent_assignment_id = entry
            .parent_assignment_id
            .take()
            .map(|parent| normalize_agent_id(&parent))
            .transpose()?;
        if entry.flattened_index != index {
            bail!(
                "assignment_schedule entry '{}' has flattened_index {} but expected {}",
                entry.assignment_id,
                entry.flattened_index,
                index
            );
        }
        if entry.assignment_id != flattened_assignments[index].assignment_id {
            bail!(
                "assignment_schedule entry {} names '{}' but flattened assignment is '{}'",
                index,
                entry.assignment_id,
                flattened_assignments[index].assignment_id
            );
        }
        if !(MIN_SUPERVISOR_DEPTH..=max_depth).contains(&entry.depth) {
            bail!(
                "assignment_schedule entry '{}' depth {} is outside configured range {}..={}",
                entry.assignment_id,
                entry.depth,
                MIN_SUPERVISOR_DEPTH,
                max_depth
            );
        }
        match entry.parent_assignment_id.as_deref() {
            None if entry.depth != MIN_SUPERVISOR_DEPTH => {
                bail!(
                    "root assignment_schedule entry '{}' must have depth {}",
                    entry.assignment_id,
                    MIN_SUPERVISOR_DEPTH
                )
            }
            None => {}
            Some(parent) => {
                let Some((parent_index, parent_depth)) = by_id.get(parent).copied() else {
                    bail!(
                        "assignment_schedule entry '{}' references parent '{}' that does not precede it",
                        entry.assignment_id,
                        parent
                    );
                };
                let expected_depth = parent_depth
                    .checked_add(1)
                    .context("assignment schedule depth overflowed")?;
                if entry.depth != expected_depth {
                    bail!(
                        "assignment_schedule entry '{}' depth {} does not follow parent '{}' at index {} depth {}",
                        entry.assignment_id,
                        entry.depth,
                        parent,
                        parent_index,
                        parent_depth
                    );
                }
            }
        }
        if by_id
            .insert(entry.assignment_id.clone(), (index, entry.depth))
            .is_some()
        {
            bail!(
                "assignment_schedule contains duplicate assignment id '{}'",
                entry.assignment_id
            );
        }
    }
    Ok(supplied)
}

fn raw_assignment_tree_has_children(assignments: &[Value]) -> bool {
    assignments.iter().any(|assignment| {
        assignment
            .get("child_assignments")
            .and_then(Value::as_array)
            .is_some_and(|children| {
                !children.is_empty() || raw_assignment_tree_has_children(children)
            })
    })
}

fn collect_assignment_plan_metadata(
    raw_assignments: &[Value],
    parent_assignment_id: Option<&str>,
    depth: u8,
    max_depth: u8,
    metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    for raw_assignment in raw_assignments {
        let assignment_id = normalize_agent_id(
            raw_assignment
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        if depth > max_depth {
            bail!(
                "assignment '{}' is at depth {} but supervisor max_depth is {}",
                assignment_id,
                depth,
                max_depth
            );
        }
        let flattened_index = metadata.assignment_schedule.len();
        metadata.assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: assignment_id.clone(),
            parent_assignment_id: parent_assignment_id.map(str::to_string),
            depth,
            flattened_index,
        });
        let fragments = optional_string_array(raw_assignment, "spec_fragment_ids")?;
        metadata
            .spec_fragment_ids_by_assignment
            .insert(assignment_id.clone(), fragments);
        let children = raw_assignment
            .get("child_assignments")
            .map(|children| {
                children
                    .as_array()
                    .context("child_assignments must be an array")
            })
            .transpose()?
            .map(Vec::as_slice)
            .unwrap_or_default();
        let child_depth = depth
            .checked_add(1)
            .context("assignment nesting depth overflowed")?;
        collect_assignment_plan_metadata(
            children,
            Some(&assignment_id),
            child_depth,
            max_depth,
            metadata,
        )?;
    }
    Ok(())
}

fn optional_string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .get(field)
        .map(|value| {
            serde_json::from_value::<Vec<String>>(value.clone())
                .with_context(|| format!("{field} must be an array of strings"))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn consultant_from_plan_value(value: &Value) -> Result<SupervisorConsultantPlan> {
    match value.get("consultant") {
        Some(consultant) => {
            serde_json::from_value(consultant.clone()).context("consultant plan field is invalid")
        }
        None => Ok(SupervisorConsultantPlan::default()),
    }
}

fn assignment_metadata_from_plan_value(
    value: &Value,
    plan: &SupervisorPlan,
) -> Result<AssignmentMetadata> {
    let raw_assignments = match value.get("assignments") {
        Some(assignments) => assignments
            .as_array()
            .context("supervisor plan assignments must be an array")?
            .as_slice(),
        None => &[],
    };
    let mut metadata_by_worker = AssignmentMetadata::new();
    let assignments_by_id = plan
        .assignments
        .iter()
        .map(|assignment| (assignment.id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    for raw_assignment in raw_assignments {
        collect_assignment_metadata(raw_assignment, &assignments_by_id, &mut metadata_by_worker)?;
    }
    Ok(metadata_by_worker)
}

fn collect_assignment_metadata(
    raw_assignment: &Value,
    assignments_by_id: &BTreeMap<&str, &OrchestratorAssignment>,
    metadata_by_worker: &mut AssignmentMetadata,
) -> Result<()> {
    let raw_id = raw_assignment
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let assignment = assignments_by_id.get(raw_id).copied();
    if let Some(assignment) = assignment {
        let workers_by_id = assignment
            .worker_assignments
            .iter()
            .map(|worker| (worker.id.as_str(), worker))
            .collect::<BTreeMap<_, _>>();
        let raw_workers = raw_assignment
            .get("worker_assignments")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for raw_worker in raw_workers {
            let raw_worker_id = raw_worker
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let Some(worker) = workers_by_id.get(raw_worker_id).copied() else {
                continue;
            };
            let mut metadata: WorkerAssignmentMetadata = serde_json::from_value(raw_worker.clone())
                .with_context(|| {
                    format!(
                        "worker assignment '{}' kind/target_path is invalid",
                        worker.id
                    )
                })?;
            metadata.target_path = match (metadata.kind, metadata.target_path.take()) {
                (AssignmentKind::Ordinary, None) => None,
                (AssignmentKind::Ordinary, Some(_)) => {
                    bail!(
                        "ordinary worker assignment '{}' must not declare target_path",
                        worker.id
                    )
                }
                (AssignmentKind::MegafileDecomposition, None) => {
                    bail!(
                        "megafile decomposition worker assignment '{}' must declare target_path",
                        worker.id
                    )
                }
                (AssignmentKind::MegafileDecomposition, Some(path)) => {
                    let normalized = normalize_repo_relative_path(&path).with_context(|| {
                        format!(
                            "megafile decomposition worker assignment '{}' has invalid target_path '{}'",
                            worker.id,
                            path.display()
                        )
                    })?;
                    if normalized.as_os_str().is_empty() {
                        bail!(
                            "megafile decomposition worker assignment '{}' target_path must name a repository file",
                            worker.id
                        );
                    }
                    if !worker
                        .assigned_paths
                        .iter()
                        .any(|assigned| path_is_covered_by_claim(&normalized, assigned))
                    {
                        bail!(
                            "megafile decomposition worker assignment '{}' target_path '{}' is outside assigned_paths",
                            worker.id,
                            normalized.display()
                        );
                    }
                    Some(normalized)
                }
            };
            metadata_by_worker.insert((assignment.id.clone(), worker.id.clone()), metadata);
        }
    }
    for child in raw_assignment
        .get("child_assignments")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        collect_assignment_metadata(child, assignments_by_id, metadata_by_worker)?;
    }
    Ok(())
}

fn supervisor_plan_value(
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(plan).context("failed to serialize normalized supervisor plan")?;
    let assignments = value
        .get_mut("assignments")
        .and_then(Value::as_array_mut)
        .context("normalized supervisor plan assignments did not serialize to an array")?;
    for (assignment_value, assignment) in assignments.iter_mut().zip(&plan.assignments) {
        let workers = assignment_value
            .get_mut("worker_assignments")
            .and_then(Value::as_array_mut)
            .context("normalized worker_assignments did not serialize to an array")?;
        for (worker_value, worker) in workers.iter_mut().zip(&assignment.worker_assignments) {
            let Some(metadata) =
                assignment_metadata.get(&(assignment.id.clone(), worker.id.clone()))
            else {
                continue;
            };
            let metadata_value = serde_json::to_value(metadata)
                .context("failed to serialize worker assignment metadata")?;
            let worker_object = worker_value
                .as_object_mut()
                .context("normalized worker assignment did not serialize to an object")?;
            let metadata_object = metadata_value
                .as_object()
                .context("worker assignment metadata did not serialize to an object")?;
            worker_object.extend(metadata_object.clone());
        }
        if let Some(fragments) = plan_metadata
            .spec_fragment_ids_by_assignment
            .get(&assignment.id)
            .filter(|fragments| !fragments.is_empty())
        {
            assignment_value
                .as_object_mut()
                .context("normalized assignment did not serialize to an object")?
                .insert(
                    "spec_fragment_ids".to_string(),
                    serde_json::to_value(fragments)
                        .context("failed to serialize assignment spec fragments")?,
                );
        }
    }
    let object = value
        .as_object_mut()
        .context("normalized supervisor plan did not serialize to an object")?;
    if !plan_metadata.spec_fragment_ids.is_empty() {
        object.insert(
            "spec_fragment_ids".to_string(),
            serde_json::to_value(&plan_metadata.spec_fragment_ids)
                .context("failed to serialize plan spec fragments")?,
        );
    }
    object.insert(
        "assignment_schedule".to_string(),
        serde_json::to_value(&plan_metadata.assignment_schedule)
            .context("failed to serialize assignment schedule")?,
    );
    if !plan_metadata.coverage_gaps.is_empty() {
        object.insert(
            "coverage_gaps".to_string(),
            serde_json::to_value(&plan_metadata.coverage_gaps)
                .context("failed to serialize plan coverage gaps")?,
        );
    }
    if !consultant.is_default() {
        object.insert(
            "consultant".to_string(),
            serde_json::to_value(consultant)
                .context("failed to serialize consultant plan field")?,
        );
    }
    Ok(value)
}

pub fn run_supervisor_plan_file(options: SupervisorRunOptions) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_file_with_max_concurrent_children(options, 1)
}

pub fn run_supervisor_plan_file_with_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
) -> Result<SupervisorFinalReport> {
    let external_runner = run_external_agent_cancellable;
    run_supervisor_plan_file_with_runner_and_max_concurrent_children(
        options,
        max_concurrent_children,
        &external_runner,
    )
}

#[cfg(test)]
fn run_supervisor_plan_file_with_runner(
    options: SupervisorRunOptions,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let serialized_runner = Mutex::new(external_runner);
    run_supervisor_plan_file_with_runner_and_max_concurrent_children(
        options,
        1,
        &|command, _cancellation| match serialized_runner.lock() {
            Ok(mut runner) => runner(command),
            Err(poisoned) => poisoned.into_inner()(command),
        },
    )
}

fn run_supervisor_plan_file_with_runner_and_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    validate_max_concurrent_children(max_concurrent_children)?;
    if options.runtime == SupervisorRuntime::Fake {
        bail!(
            "supervisor assignment creation is temporarily unsupported because managed worktree creation requires a capability-bound repository cleanliness input"
        );
    }
    let repo = discover_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(repo);
    let cleanliness = manager.acquire_repository_cleanliness()?;
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::Bound(&cleanliness),
        external_runner,
    )
}

pub fn supervisor_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<SupervisorStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    let final_report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?;
    Ok(SupervisorStatusReport {
        run_id,
        repo: PathBuf::from("."),
        run_dir: run_dir
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.run_root()),
        final_report_exists: final_report.is_some(),
        final_report_path: final_report_path
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.final_report_relative_path()),
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
    if let Some(report) = read_finalized_supervisor_report(&repo, &run_id, &run_dir)? {
        return Ok(report);
    }

    Ok(SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id,
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: PathBuf::new(),
        run_dir: run_dir
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.run_root()),
        runtime: SupervisorRuntime::Codex,
        publishable: false,
        success: false,
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        assigned_paths: Vec::new(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: Vec::new(),
        semantic_intent_tokens: Vec::new(),
        role_usage: BTreeMap::new(),
        total_usage: None,
        total_cost_usd: None,
        usage_complete: false,
        commands_run: Vec::new(),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: "supervisor final report is missing".to_string(),
            paths: vec![final_report_path],
        }],
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        breaker_trip: None,
        orchestrator_reports: Vec::new(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk: "run artifacts are incomplete".to_string(),
        next_safe_action: "rerun supervise run for this run id".to_string(),
    })
}

pub fn verified_megafile_decomposition_evidence(
    repo: impl AsRef<Path>,
    run_id: RunId,
    orchestrator_id: &str,
    target_path: &Path,
    candidate_changed_paths: &[PathBuf],
) -> Result<VerifiedMegafileDecompositionEvidence> {
    let repo = discover_repo_root(repo.as_ref())?;
    let normalized_target = normalize_report_target_path(
        Some(target_path.to_path_buf()),
        "megafile decomposition target",
    )?
    .context("megafile decomposition target is required")?;
    let normalized_candidate_paths =
        normalize_paths(candidate_changed_paths.to_vec()).context("candidate paths are invalid")?;
    if normalized_candidate_paths.is_empty() {
        bail!("candidate has no changed paths");
    }
    let run_dir = run_dir(&repo, &run_id);
    let report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?
        .with_context(|| format!("supervisor run '{}' is not finalized", run_id.as_str()))?;
    if report.run_id != run_id {
        bail!(
            "finalized supervisor report run id '{}' does not match requested run '{}'",
            report.run_id.as_str(),
            run_id.as_str()
        );
    }
    if report.runtime != SupervisorRuntime::Codex
        || !report.publishable
        || !report.success
        || !report.accepted
        || report.rejected
        || report.status != ReviewStatus::Succeeded
        || report.breaker_trip.is_some()
        || !report.release_errors.is_empty()
        || !report.semantic_release_errors.is_empty()
    {
        bail!(
            "supervisor run '{}' is not accepted successful publishable evidence",
            run_id.as_str()
        );
    }
    let normalized_supervisor_paths = normalize_paths(report.files_changed.clone())
        .context("supervisor files_changed invalid")?;
    if normalized_supervisor_paths != normalized_candidate_paths {
        bail!(
            "supervisor run '{}' files_changed does not exactly match the merge candidate",
            run_id.as_str()
        );
    }

    let matching_children = report
        .orchestrator_reports
        .iter()
        .filter(|child| child.id == orchestrator_id)
        .collect::<Vec<_>>();
    let child = match matching_children.as_slice() {
        [child] => *child,
        [] => bail!(
            "supervisor run '{}' has no child orchestrator report for merge candidate agent '{}'",
            run_id.as_str(),
            orchestrator_id
        ),
        _ => bail!(
            "supervisor run '{}' has ambiguous child orchestrator reports for merge candidate agent '{}'",
            run_id.as_str(),
            orchestrator_id
        ),
    };
    if child.role != AgentRole::ChildOrchestrator || report_failed(child) {
        bail!(
            "child orchestrator '{}' is not accepted successful evidence",
            orchestrator_id
        );
    }
    let normalized_child_paths =
        normalize_paths(child.files_changed.clone()).context("child files_changed invalid")?;
    if normalized_child_paths != normalized_candidate_paths {
        bail!(
            "child orchestrator '{}' files_changed does not exactly match the merge candidate",
            orchestrator_id
        );
    }

    let mut matching_workers = Vec::new();
    for worker in &child.worker_reports {
        if worker.assignment_kind != AssignmentKind::MegafileDecomposition {
            continue;
        }
        let worker_target =
            normalize_report_target_path(worker.target_path.clone(), "worker target_path")?;
        if worker_target.as_ref() == Some(&normalized_target) {
            matching_workers.push(worker);
        }
    }
    let worker = match matching_workers.as_slice() {
        [worker] => *worker,
        [] => bail!(
            "child orchestrator '{}' has no megafile_decomposition worker for exact target '{}'",
            orchestrator_id,
            normalized_target.display()
        ),
        _ => bail!(
            "child orchestrator '{}' has ambiguous megafile_decomposition workers for exact target '{}'",
            orchestrator_id,
            normalized_target.display()
        ),
    };
    if worker.role != AgentRole::Worker
        || report_failed(worker)
        || worker.no_further_delegation != Some(true)
    {
        bail!(
            "megafile_decomposition worker '{}' is not accepted successful terminal evidence",
            worker.id
        );
    }
    let completion = worker
        .decomposition_completion
        .clone()
        .map(normalize_decomposition_completion)
        .transpose()?
        .context("accepted megafile_decomposition worker omitted completion evidence")?;
    if completion.target_path != normalized_target {
        bail!("worker decomposition completion target does not match the merge target");
    }
    let supervisor_candidate_binding = completion
        .supervisor_candidate_binding
        .clone()
        .context(
            "accepted megafile_decomposition worker evidence is missing the supervisor-inspected candidate binding",
        )?;
    if supervisor_candidate_binding.agent_id != child.id {
        bail!(
            "supervisor-inspected decomposition candidate binding agent '{}' does not match child orchestrator '{}'",
            supervisor_candidate_binding.agent_id,
            child.id
        );
    }
    let worker_paths =
        normalize_paths(worker.files_changed.clone()).context("worker files_changed invalid")?;
    let expected_decomposition_paths = std::iter::once(completion.target_path.clone())
        .chain(completion.replacement_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if worker_paths != expected_decomposition_paths {
        bail!(
            "worker files_changed must exactly equal the decomposition target plus evidence-bound replacement paths"
        );
    }
    if normalized_candidate_paths != expected_decomposition_paths {
        bail!(
            "merge candidate changed paths must exactly equal the decomposition target plus evidence-bound replacement paths"
        );
    }

    let child_completions = child
        .decomposition_completions
        .iter()
        .cloned()
        .map(normalize_decomposition_completion)
        .collect::<Result<BTreeSet<_>>>()?;
    if !child_completions.contains(&completion) {
        bail!("child orchestrator omitted the accepted worker decomposition completion");
    }
    let final_completions = report
        .decomposition_candidates
        .iter()
        .cloned()
        .map(normalize_decomposition_completion)
        .collect::<Result<BTreeSet<_>>>()?;
    if !final_completions.contains(&completion) {
        bail!("supervisor final report omitted the accepted decomposition completion");
    }

    let expected_auditor_id = format!("{}-review-auditor", child.id);
    let audit = child
        .audit_reports
        .iter()
        .find(|audit| audit.id == expected_auditor_id)
        .context("accepted parent review-auditor evidence is missing")?;
    if audit.role != AgentRole::Auditor
        || report_failed(audit)
        || audit.no_further_delegation != Some(true)
        || !audit.read_only
        || audit.commands_run.is_empty()
        || audit.validation_results.is_empty()
        || audit.validation_results.iter().any(validation_failed)
        || !audit.reviewed_worker_ids.iter().any(|id| id == &worker.id)
    {
        bail!("parent review-auditor evidence does not accept the successful decomposition worker");
    }
    let reviewed_paths = audit
        .reviewed_paths
        .iter()
        .filter_map(|path| normalize_repo_relative_path(path).ok())
        .collect::<BTreeSet<_>>();
    let missing_audit_paths = normalized_candidate_paths
        .iter()
        .filter(|required| {
            !reviewed_paths
                .iter()
                .any(|reviewed| path_is_covered_by_claim(required, reviewed))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing_audit_paths.is_empty() {
        bail!(
            "parent review-auditor evidence does not cover exact candidate paths: {}",
            display_paths(&missing_audit_paths)
        );
    }

    Ok(VerifiedMegafileDecompositionEvidence {
        run_id,
        orchestrator_id: child.id.clone(),
        worker_id: worker.id.clone(),
        target_path: completion.target_path,
        replacement_paths: completion.replacement_paths,
        supervisor_candidate_binding,
    })
}

#[cfg(test)]
pub(crate) fn write_test_finalized_megafile_decomposition_evidence(
    repo: &Path,
    run_id: RunId,
    orchestrator_id: &str,
    worker_id: &str,
    target_path: PathBuf,
    replacement_paths: Vec<PathBuf>,
) -> Result<()> {
    write_test_finalized_megafile_decomposition_evidence_with_binding(
        repo,
        run_id,
        orchestrator_id,
        worker_id,
        target_path,
        replacement_paths,
        true,
    )
}

#[cfg(test)]
fn write_test_finalized_megafile_decomposition_evidence_with_binding(
    repo: &Path,
    run_id: RunId,
    orchestrator_id: &str,
    worker_id: &str,
    target_path: PathBuf,
    replacement_paths: Vec<PathBuf>,
    include_supervisor_binding: bool,
) -> Result<()> {
    let mut completion = normalize_decomposition_completion(DecompositionCompletion {
        target_path,
        replacement_paths,
        supervisor_candidate_binding: None,
    })?;
    let files_changed = std::iter::once(completion.target_path.clone())
        .chain(completion.replacement_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let candidate = crate::merge::collect_agent_result(MergeCollectOptions {
        repo: repo.to_path_buf(),
        agent_id: orchestrator_id.to_string(),
        claimed_paths: files_changed.clone(),
        include_full_diff: false,
        diff_summary_char_limit: 1,
        validations: Vec::new(),
    })
    .context("capture finalized test decomposition candidate")?;
    let candidate_paths =
        normalize_paths(candidate.changed_paths).context("test candidate paths invalid")?;
    if candidate_paths != files_changed {
        bail!("test decomposition candidate paths do not match finalized evidence");
    }
    if include_supervisor_binding {
        completion.supervisor_candidate_binding = Some(candidate.validation_binding);
    }
    let validation = ValidationResult {
        name: "test decomposition validation".to_string(),
        status: ReviewStatus::Succeeded,
        command: vec!["test-validation".to_string()],
        message: None,
    };
    let command = CommandRunRecord {
        command: vec!["test-command".to_string()],
        cwd: PathBuf::from("."),
        exit_code: Some(0),
        status: ReviewStatus::Succeeded,
        timeout_seconds: 1,
        duration_ms: 1,
        timed_out: false,
        stdout: String::new(),
        stderr: String::new(),
        error: None,
    };
    let worker = WorkerReport {
        id: worker_id.to_string(),
        role: AgentRole::Worker,
        assignment_kind: AssignmentKind::MegafileDecomposition,
        target_path: Some(completion.target_path.clone()),
        assigned_paths: files_changed.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: vec![command.clone()],
        files_changed: files_changed.clone(),
        validation_results: vec![validation.clone()],
        findings: Vec::new(),
        bloated_file_flags: Vec::new(),
        decomposition_completion: Some(completion.clone()),
        no_further_delegation: Some(true),
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "test evidence".to_string(),
        next_safe_action: "merge preview".to_string(),
    };
    let audit = AuditorReport {
        id: format!("{orchestrator_id}-review-auditor"),
        role: AgentRole::Auditor,
        reviewed_worker_ids: vec![worker_id.to_string()],
        reviewed_paths: files_changed.clone(),
        commands_run: vec![command.clone()],
        validation_results: vec![validation.clone()],
        findings: Vec::new(),
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "test evidence".to_string(),
        next_safe_action: "merge preview".to_string(),
    };
    let child = OrchestratorReviewReport {
        id: orchestrator_id.to_string(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: files_changed.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_token: Some(1),
        semantic_intent_token: None,
        commands_run: vec![command.clone()],
        files_changed: files_changed.clone(),
        validation_results: vec![validation.clone()],
        findings: Vec::new(),
        worker_reports: vec![worker],
        audit_reports: vec![audit],
        decomposition_completions: vec![completion.clone()],
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "test evidence".to_string(),
        next_safe_action: "merge preview".to_string(),
    };
    let report = SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id: run_id.clone(),
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: PathBuf::from("test-plan.json"),
        run_dir: RunArtifactFamily::Supervise
            .run_root()
            .join(run_id.as_str()),
        runtime: SupervisorRuntime::Codex,
        publishable: true,
        success: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        assigned_paths: files_changed.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: vec![1],
        semantic_intent_tokens: Vec::new(),
        role_usage: BTreeMap::new(),
        total_usage: None,
        total_cost_usd: None,
        usage_complete: true,
        commands_run: vec![command],
        files_changed,
        validation_results: vec![validation],
        findings: Vec::new(),
        bloated_file_flags: Vec::new(),
        decomposition_candidates: vec![completion],
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        breaker_trip: None,
        orchestrator_reports: vec![child],
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk: "test evidence".to_string(),
        next_safe_action: "merge preview".to_string(),
    };
    let mut writer = ArtifactRunWriter::reserve(
        repo,
        RunArtifactFamily::Supervise,
        run_id,
        "megafile-decomposition-test",
    )?;
    write_final_report(&mut writer, &report)?;
    writer.finalize(
        RunArtifactFamily::Supervise.final_report_relative_path(),
        true,
    )?;
    Ok(())
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
    let incoming_root = context.run_dir.join("incoming");
    child_orchestrator_prompt_with_incoming_root(
        context,
        &incoming_root,
        &AssignmentMetadata::new(),
    )
}

fn child_orchestrator_prompt_with_incoming_root(
    context: ChildOrchestratorPromptContext<'_>,
    incoming_root: &Path,
    assignment_metadata: &AssignmentMetadata,
) -> Result<String> {
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
    let assignment_json = serde_json::to_string_pretty(&orchestrator_assignment_value(
        assignment,
        assignment_metadata,
    )?)
    .context("failed to serialize orchestrator assignment")?;
    let worker_prompts = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            worker_prompt_with_incoming_root(
                plan,
                assignment,
                worker,
                &metadata,
                run_dir,
                incoming_root,
                worker_schema_path,
            )
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n\n--- worker prompt contract ---\n\n");
    let auditor_prompt = review_auditor_prompt_with_metadata(
        plan,
        assignment,
        assignment_metadata,
        run_dir,
        auditor_schema_path,
    )?;
    let task = assignment_task(plan, assignment);
    let role_prefix = supervise_role_prefix(
        SupervisePromptRole::O1ChildOrchestrator,
        &assignment.id,
        None,
    );
    let (child_model, child_reasoning_effort) =
        role_model_selection(plan, AgentRole::ChildOrchestrator);
    let (worker_model, worker_reasoning_effort) = role_model_selection(plan, AgentRole::Worker);
    let consultation_section = consultation_prompt_section(consultant);
    Ok(format!(
        r#"{role_prefix}You are a child orchestrator in an opt-in local Codex CLI supervisor run.
You are not the top supervisor. You are not alone in the repository.
Primary worktree mutation is forbidden. Work only in this assigned child worktree:
{worktree_path}

Ownership:
- Child orchestrator id: {child_id}
- Megafile decomposition worker targets: {decomposition_targets}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Path claim token: {claim_token}
- Semantic intent token: {semantic_intent_token}

Declared role selections:
- Child orchestrator model: {child_model}
- Child orchestrator reasoning effort: {child_reasoning_effort}
- Nested worker model: {worker_model}
- Nested worker reasoning effort: {worker_reasoning_effort}
- Worker values are declarative context for the generated worker prompts. MACO does not launch a separate worker process, so worker usage remains unavailable until runtime-side role-tagged usage reporting exists.

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
- MACO launched this Codex CLI with strict/ephemeral configuration, approval policy never, goals and multi-agent enabled, and the named maco_external_codex permission profile.
- The inner permission profile grants only minimal reads plus writes in this assigned workspace root; model-generated network access, user config/rules, web search, plugins, apps, hooks, browser/computer use, and inherited shell environment are disabled.
- An outer MACO systemd boundary separately verifies the exact workspace/artifact mounts, blocked host IPC sockets, resource limits, and empty owned cgroup before the result can be published.
- Never launch a raw Codex subprocess or request danger-full-access. Any nested role must go through a MACO-approved runner and a least-privilege profile whose process-tree and side-effect evidence is verified.
- If an approved nested runner/profile is unavailable, stop and report the blocked delegation instead of weakening this boundary.

Required behavior:
- First, read and follow AGENTS.md and project-local .agents instructions in this worktree. When present, specifically read .agents/skills/agent-orchestration/SKILL.md and .agents/docs/AGENT_ORCHESTRATION.md before worker delegation or mutation.
- Use Codex native SubAgent/delegated-worker mechanisms only for lightweight terminal worker or researcher assignments when available, following AGENTS.md and .agents instructions.
- When launching a worker, use the generated worker prompt template verbatim and preserve its six-line TERMINAL_WORKER role-prefix block with no preamble.
- You may collect advisory child-side review-auditor evidence with the generated REVIEW_AUDITOR prompt template, but it is not an acceptance gate unless MACO/O2 collects it through the parent-enforced gate.
- When collecting advisory child-side review-auditor evidence, preserve its six-line REVIEW_AUDITOR role-prefix block with no preamble.
- Do not force raw Codex CLI subprocess workers as the primary worker path.
- If no delegated-worker mechanism is available, stop before mutation and report the exact blocked worker task in your OrchestratorReviewReport findings and remaining_risk.
- Workers must return WorkerReport JSON matching the worker report contract and include "no_further_delegation": true.
- Each worker must also write its structured execution journal to the exact path in its worker prompt; that path is the only allowed non-source artifact write for a terminal worker. The journal is JSONL with one object per command containing command, cwd, start_timestamp, end_timestamp, and changed_paths. The parent acceptance gate imports these journals from incoming/worker-journals/ and rejects worker evidence that the journal or Git diff does not support.
- Review auditors must return AuditorReport JSON matching the auditor report contract and include "no_further_delegation": true.
- Review auditors must include "read_only": true in AuditorReport JSON to attest they did not mutate files or repository state.
- Acceptance-gate review auditors are parent-launched MACO/Codex CLI subprocess roles; a child-launched review auditor is advisory child-side evidence unless MACO/O2 collects it through the parent-enforced acceptance gate.
- Review every WorkerReport before writing your own OrchestratorReviewReport.
- Preserve each worker assignment_kind and target_path in WorkerReport. A successful megafile_decomposition worker must report the exact canonical target_path in files_changed and include decomposition_completion with that target plus at least one concrete canonical replacement_path also present in files_changed. OrchestratorReviewReport must aggregate the exact accepted worker evidence in decomposition_completions; this evidence does not bypass claims, journals, validation, audit, or later merge gates.
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
        decomposition_targets = display_decomposition_targets(assignment, assignment_metadata),
        assigned_paths = display_paths(&assignment.assigned_paths),
        semantic_symbols = assignment.semantic_symbols.join(", "),
        semantic_modules = assignment.semantic_modules.join(", "),
        claim_token = claim_context.claim.token.get(),
        semantic_intent_token = claim_context
            .semantic_intent_token
            .map(|token| token.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        child_model = child_model.as_deref().unwrap_or("<runtime default>"),
        child_reasoning_effort = child_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
        worker_model = worker_model.as_deref().unwrap_or("<runtime default>"),
        worker_reasoning_effort = worker_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
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
    let metadata = WorkerAssignmentMetadata::default();
    worker_prompt_with_incoming_root(
        plan,
        orchestrator,
        worker,
        &metadata,
        run_dir,
        &run_dir.join("incoming"),
        schema_path,
    )
}

fn worker_prompt_with_incoming_root(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    worker: &WorkerAssignment,
    metadata: &WorkerAssignmentMetadata,
    run_dir: &Path,
    incoming_root: &Path,
    schema_path: &Path,
) -> Result<String> {
    let worker_json = serde_json::to_string_pretty(&worker_assignment_value(worker, metadata)?)
        .context("failed to serialize worker assignment")?;
    let role_prefix = supervise_role_prefix(SupervisePromptRole::TerminalWorker, &worker.id, None);
    let task = worker_task(plan, orchestrator, worker);
    let journal_path = incoming_root.join(worker_execution_journal_incoming_relative(worker));
    let (worker_model, worker_reasoning_effort) = role_model_selection(plan, AgentRole::Worker);
    Ok(format!(
        r#"{role_prefix}You are a terminal worker/researcher in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
Your parent is child orchestrator `{orchestrator_id}`. You are not the supervisor.
Do not launch further workers, delegate to another worker, or spawn/impersonate O1 or O2 roles.

Ownership:
- Worker id: {worker_id}
- Assignment kind: {assignment_kind}
- Decomposition target path: {target_path}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}
- Execution journal path: {journal_path}
- Explicit report path: {report_path}

Declared role selection:
- Worker model: {worker_model}
- Worker reasoning effort: {worker_reasoning_effort}
- These values are declarative nested-worker context. MACO does not launch a separate worker process, so worker usage remains unavailable until runtime-side role-tagged usage reporting exists.

Rules:
- Edit only inside your assigned worktree and only inside claimed paths.
- Do not mutate the primary worktree.
- Before returning your WorkerReport, write a structured execution journal to the exact execution journal path above; this is the only allowed non-source artifact write for this worker. Create its parent directory if needed. Use JSONL: one JSON object per command, with fields "command" (array of strings), "cwd" (string), "start_timestamp" (string), "end_timestamp" (string), and "changed_paths" (array of repo-relative paths changed by that command, or [] when none). Do not write prose or Markdown to the journal.
- Run validation or record why validation was not run.
- Return WorkerReport JSON in your final response with assignment_kind, target_path, changed files, commands run, validation results, findings, bloated_file_flags, decomposition_completion, remaining risk, and next safe action.
- bloated_file_flags is bounded to at most {max_bloated_file_flags} unique objects of the form {{"path":"repo/relative/file"}}. Every path must be canonical, repository-relative, and inside this worker's assigned paths. Thresholds are intentionally not inferred by this report schema.
- For a successful megafile_decomposition, include the exact target and every concrete replacement in files_changed, then set decomposition_completion to {{"target_path":"the exact canonical target path","replacement_paths":["one or more canonical newly created files"]}}. Otherwise set it to null. Renames, unrelated edits, and no-op target reports are not decomposition completion evidence. This typed evidence does not bypass the isolated worktree, hard claim, execution journal, validation, terminal audit, or later merge gates.
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
        assignment_kind = metadata.kind.as_str(),
        target_path = metadata
            .target_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        assigned_paths = display_paths(&worker.assigned_paths),
        semantic_symbols = worker.semantic_symbols.join(", "),
        semantic_modules = worker.semantic_modules.join(", "),
        run_dir = run_dir.display(),
        journal_path = journal_path.display(),
        report_path = worker
            .report_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        worker_model = worker_model.as_deref().unwrap_or("<runtime default>"),
        worker_reasoning_effort = worker_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
        schema_path = schema_path.display(),
        max_bloated_file_flags = MAX_BLOATED_FILE_FLAGS_PER_WORKER,
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
    review_auditor_prompt_with_metadata(
        plan,
        orchestrator,
        &AssignmentMetadata::new(),
        run_dir,
        schema_path,
    )
}

fn review_auditor_prompt_with_metadata(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
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
- Megafile decomposition worker targets: {decomposition_targets}
- Assigned paths to review: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}

Rules:
- Stay read-only. Inspect worker reports, child diffs, validation evidence, findings, remaining risk, and claimed path boundaries.
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- Do not edit files, create durable artifacts, apply patches, claim paths, or change Git state.
- Produce structured AuditorReport JSON in your final response with reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining risk, and next safe action.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
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
        decomposition_targets = display_decomposition_targets(orchestrator, assignment_metadata),
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
    assignment_metadata: &'a AssignmentMetadata,
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
        assignment_metadata,
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
- MACO launched this Codex CLI with the read-only maco_external_codex permission profile, model-generated network disabled, and strict/ephemeral configuration.
- An outer MACO systemd boundary independently verifies the exact read-only workspace mount, writable report/log destinations, blocked host IPC sockets, resource limits, and empty owned cgroup.
- Never request danger-full-access or launch a raw nested Codex subprocess. Stay read-only and fail closed if either verified boundary is unavailable.
- Return AuditorReport JSON as your final response. Codex CLI --output-last-message records that final response at the auditor report path.

Evidence to review:
- Supervisor task: {task}
- Child assignment id: {assignment_id}
- Megafile decomposition worker targets: {decomposition_targets}
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
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
- Set role="auditor", no_further_delegation=true, read_only=true.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Include reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining_risk, and next_safe_action.

Child report JSON:
{child_report_json}
"#,
        role_prefix = role_prefix,
        task = task,
        assignment_id = assignment.id,
        decomposition_targets = display_decomposition_targets(assignment, assignment_metadata),
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

fn role_model_selection(
    plan: &SupervisorPlan,
    role: AgentRole,
) -> (Option<String>, Option<String>) {
    plan.role_models
        .get(&role)
        .map(|selection| (selection.model.clone(), selection.reasoning_effort.clone()))
        .unwrap_or((None, None))
}

fn apply_role_model_selection(
    command: ExternalAgentCommand,
    plan: &SupervisorPlan,
    role: AgentRole,
) -> ExternalAgentCommand {
    let (model, reasoning_effort) = role_model_selection(plan, role);
    command.with_model_selection(model, reasoning_effort)
}

#[derive(Debug, Clone)]
struct ChildAttemptArtifacts {
    prompt_path: PathBuf,
    report_path: PathBuf,
    log_path: PathBuf,
    raw_report_relative: PathBuf,
    raw_stdout_relative: PathBuf,
    command_record_relative: PathBuf,
}

struct ExternalAttemptEvidenceContext<'a> {
    incoming_scratch: &'a ArtifactScratchDirectory,
    capture_scratch: &'a ArtifactScratchDirectory,
    artifacts: &'a ChildAttemptArtifacts,
    external_run: &'a ExternalAgentRun,
    external_command: &'a ExternalAgentCommand,
    raw_report_validated: bool,
    runtime: SupervisorRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerExecutionJournalEvidence {
    incoming_relative_path: PathBuf,
    evidence_relative_path: PathBuf,
    status: WorkerExecutionJournalStatus,
}

type WorkerExecutionJournalEvidenceSet = BTreeMap<String, WorkerExecutionJournalEvidence>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerExecutionJournalStatus {
    Loaded(Vec<WorkerExecutionJournalEntry>),
    Missing,
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerExecutionJournalEntry {
    command: Vec<String>,
    cwd: PathBuf,
    start_timestamp: String,
    end_timestamp: String,
    changed_paths: Vec<PathBuf>,
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
    incoming_path: &Path,
    capture_path: &Path,
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
        report_path: incoming_path.join(format!("{stem}.json")),
        log_path: capture_path.join(format!("{stem}.jsonl")),
        raw_report_relative: PathBuf::from("evidence")
            .join("incoming")
            .join(format!("{stem}.json")),
        raw_stdout_relative: PathBuf::from("logs").join(format!("{stem}.jsonl")),
        command_record_relative: PathBuf::from("logs").join(format!("{stem}.summary.json")),
    }
}

fn worker_execution_journal_file_name(worker_id: &str) -> String {
    format!("{worker_id}.jsonl")
}

fn worker_execution_journal_incoming_relative(worker: &WorkerAssignment) -> PathBuf {
    PathBuf::from("worker-journals").join(worker_execution_journal_file_name(&worker.id))
}

fn worker_execution_journal_evidence_relative(assignment_id: &str, worker_id: &str) -> PathBuf {
    PathBuf::from("logs")
        .join("workers")
        .join(assignment_id)
        .join(worker_execution_journal_file_name(worker_id))
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

fn initialize_orchestration_event_journal(
    repo: &Path,
    run_id: &RunId,
) -> Option<OrchestrationEventJournal> {
    match repository_authenticator_key_only(repo) {
        Ok(authenticator) => Some(OrchestrationEventJournal::new(
            authenticator.binding().repository_id.clone(),
            run_id.as_str(),
        )),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "supervise orchestration event journal is unavailable"
            );
            None
        }
    }
}

fn record_orchestration_event(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    kind: OrchestrationEventKind,
    payload: Value,
) {
    let Some(active_journal) = journal.as_mut() else {
        return;
    };
    let append_error = active_journal
        .append(writer, node, parent, role, kind, payload)
        .err();
    if let Some(error) = append_error {
        tracing::warn!(
            error = %error,
            node,
            ?kind,
            "disabled supervise orchestration event journal after append failure"
        );
        *journal = None;
    }
}

fn lifecycle_event_payload(status: &str, attempt: Option<usize>, thread_id: Option<&str>) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("status".to_string(), Value::String(status.to_string()));
    if let Some(attempt) = attempt {
        payload.insert("attempt".to_string(), json!(attempt));
    }
    if let Some(thread_id) = thread_id {
        payload.insert(
            "thread_id".to_string(),
            Value::String(thread_id.to_string()),
        );
    }
    Value::Object(payload)
}

fn codex_thread_id_from_stdout(stdout: &[u8]) -> Option<String> {
    stdout
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|value| {
            value
                .get("thread_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .find(|thread_id| {
            !thread_id.is_empty()
                && thread_id.len() <= 256
                && !thread_id.chars().any(char::is_control)
        })
}

fn record_worker_journal_events(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    journals: &WorkerExecutionJournalEvidenceSet,
) {
    for (worker_id, evidence) in journals {
        let (status, entries, error) = match &evidence.status {
            WorkerExecutionJournalStatus::Loaded(entries) => ("loaded", Some(entries.len()), None),
            WorkerExecutionJournalStatus::Missing => ("missing", None, None),
            WorkerExecutionJournalStatus::Invalid(error) => ("invalid", None, Some(error.as_str())),
        };
        record_orchestration_event(
            journal,
            writer,
            worker_id,
            Some(&assignment.id),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Journal,
            json!({
                "status": status,
                "entries": entries,
                "error": error,
                "evidence_path": serializable_path(&evidence.evidence_relative_path),
            }),
        );
    }
}

fn record_final_report_decisions(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    run_id: &RunId,
    report: &OrchestratorReviewReport,
) {
    for worker in &report.worker_reports {
        record_orchestration_event(
            journal,
            writer,
            &worker.id,
            Some(&report.id),
            OrchestrationRole::Worker,
            if report_failed(worker) {
                OrchestrationEventKind::Reject
            } else {
                OrchestrationEventKind::Accept
            },
            json!({
                "status": worker.status,
                "accepted": worker.accepted,
                "rejected": worker.rejected,
            }),
        );
    }
    for auditor in &report.audit_reports {
        record_orchestration_event(
            journal,
            writer,
            &auditor.id,
            Some(&report.id),
            OrchestrationRole::Auditor,
            if report_failed(auditor) {
                OrchestrationEventKind::Reject
            } else {
                OrchestrationEventKind::Accept
            },
            json!({
                "status": auditor.status,
                "accepted": auditor.accepted,
                "rejected": auditor.rejected,
            }),
        );
    }
    record_orchestration_event(
        journal,
        writer,
        &report.id,
        Some(run_id.as_str()),
        OrchestrationRole::Orchestrator,
        if report_failed(report) {
            OrchestrationEventKind::Reject
        } else {
            OrchestrationEventKind::Accept
        },
        json!({
            "status": report.status,
            "accepted": report.accepted,
            "rejected": report.rejected,
        }),
    );
}

#[derive(Debug, Clone, Copy)]
enum SupervisorWorktreeCreation<'a> {
    Bound(&'a RepositoryCleanlinessCapability),
    #[cfg(test)]
    TestOnly,
}

struct SharedSupervisorArtifacts<'a> {
    writer: &'a mut ArtifactRunWriter,
    journal: &'a mut Option<OrchestrationEventJournal>,
}

fn with_supervisor_artifacts<T>(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    operation: impl FnOnce(&mut ArtifactRunWriter, &mut Option<OrchestrationEventJournal>) -> Result<T>,
) -> Result<T> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    let SharedSupervisorArtifacts { writer, journal } = &mut *guard;
    operation(writer, journal)
}

fn record_shared_orchestration_event(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    kind: OrchestrationEventKind,
    payload: Value,
) -> Result<()> {
    with_supervisor_artifacts(artifacts, |writer, journal| {
        record_orchestration_event(journal, writer, node, parent, role, kind, payload);
        Ok(())
    })
}

#[derive(Default)]
struct AssignmentExecutionOutcome {
    command_records: Vec<CommandRunRecord>,
    usage_samples: Vec<RoleUsageSample>,
    usage_incomplete: bool,
    report: Option<OrchestratorReviewReport>,
    findings: Vec<Finding>,
    claim_tokens: Vec<ClaimToken>,
    semantic_tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
    health_signals: Vec<SwarmHealthSignal>,
    assignment_failed: bool,
    external_containment_failed: bool,
    fatal_error: Option<String>,
}

fn release_concurrent_assignment(
    outcome: &mut AssignmentExecutionOutcome,
    sync_store: &SyncStore,
    semantic_store: &SemanticIntentStore,
) {
    let (released_claims, release_errors) =
        release_claims(sync_store, std::mem::take(&mut outcome.claim_tokens));
    let (released_semantic_intents, semantic_release_errors) =
        release_semantic_intents(semantic_store, std::mem::take(&mut outcome.semantic_tokens));
    outcome.released_claims = released_claims;
    outcome.release_errors = release_errors;
    outcome.released_semantic_intents = released_semantic_intents;
    outcome.semantic_release_errors = semantic_release_errors;
    if outcome.fatal_error.is_none()
        && (!outcome.release_errors.is_empty() || !outcome.semantic_release_errors.is_empty())
    {
        outcome.fatal_error = Some(
            "supervisor assignment cleanup failed; scheduling stopped after joining active assignments"
                .to_string(),
        );
    }
}

impl AssignmentExecutionOutcome {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            fatal_error: Some(message.into()),
            ..Self::default()
        }
    }

    fn requires_scheduler_abort(&self) -> bool {
        self.fatal_error.is_some()
            || self.external_containment_failed
            || !self.release_errors.is_empty()
            || !self.semantic_release_errors.is_empty()
    }
}

fn assignment_health_outcome(outcome: &AssignmentExecutionOutcome) -> AssignmentHealthOutcome {
    match outcome.report.as_ref() {
        Some(report)
            if report.rejected
                || report.status == ReviewStatus::Rejected
                || report.status == ReviewStatus::Missing =>
        {
            AssignmentHealthOutcome::Rejected
        }
        Some(report) if report_failed(report) => AssignmentHealthOutcome::Failed,
        Some(_) => AssignmentHealthOutcome::Accepted,
        None => AssignmentHealthOutcome::Failed,
    }
}

fn observe_assignment_health(
    breaker: &mut SwarmHealthCircuitBreaker,
    outcome: &AssignmentExecutionOutcome,
) -> Option<CircuitBreakerTrip> {
    let final_outcome = SwarmHealthSignal::AssignmentOutcome(assignment_health_outcome(outcome));
    outcome
        .health_signals
        .iter()
        .copied()
        .chain(std::iter::once(final_outcome))
        .find_map(|signal| match breaker.observe(signal) {
            Some(CircuitBreakerTransition::Opened(trip)) => Some(trip),
            Some(CircuitBreakerTransition::EnteredHalfOpen | CircuitBreakerTransition::Closed)
            | None => None,
        })
}

fn record_breaker_trip(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    run_id: &RunId,
    trip: &CircuitBreakerTrip,
) -> Result<()> {
    record_shared_orchestration_event(
        artifacts,
        run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "gate": "swarm_health_circuit_breaker",
            "transition": "closed_to_open",
            "trip": trip,
            "drain_policy": "finish_active_without_admitting_pending",
        }),
    )
}

fn record_assignment_spawn_failure(
    indexed_outcomes: &mut [Option<AssignmentExecutionOutcome>],
    stop_scheduling: &mut bool,
    index: usize,
    assignment_id: &str,
    error: &std::io::Error,
) -> Result<()> {
    *stop_scheduling = true;
    let slot = indexed_outcomes
        .get_mut(index)
        .context("spawn failure referenced an assignment outside the scheduler plan")?;
    *slot = Some(AssignmentExecutionOutcome::fatal(format!(
        "failed to spawn supervisor assignment '{assignment_id}' thread: {error}"
    )));
    Ok(())
}

struct AssignmentExecutionContext<'a, 'writer> {
    index: usize,
    concurrent_mode: bool,
    plan: &'a SupervisorPlan,
    consultant: &'a SupervisorConsultantPlan,
    assignment_metadata: &'a AssignmentMetadata,
    assignment: &'a OrchestratorAssignment,
    options: &'a SupervisorRunOptions,
    repo: &'a Path,
    run_dir: &'a Path,
    dirs: &'a RunDirs,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'a>,
    manager: &'a WorktreeManager,
    reused: bool,
    sync_store: &'a SyncStore,
    semantic_store: &'a SemanticIntentStore,
    prepared_semantic_token: Option<u64>,
    prepared_semantic_findings: &'a [Finding],
    prepared_semantic_signals: &'a [SwarmHealthSignal],
    prepared_semantic_failed: bool,
    serial_semantic_warn_intents: Option<&'a Mutex<Vec<SemanticIntent>>>,
    semantic_block_order: Option<usize>,
    semantic_block_gate: Option<&'a SemanticBlockGate>,
    artifacts: &'a Mutex<SharedSupervisorArtifacts<'writer>>,
    cancellation: ProcessCancellation,
    external_runner: &'a CancellableExternalRunner<'a>,
}

#[derive(Default)]
struct SemanticBlockGate {
    next_order: Mutex<usize>,
    changed: std::sync::Condvar,
}

struct SemanticBlockTurn<'a> {
    next_order: std::sync::MutexGuard<'a, usize>,
    gate: &'a SemanticBlockGate,
}

impl Drop for SemanticBlockTurn<'_> {
    fn drop(&mut self) {
        *self.next_order = self.next_order.saturating_add(1);
        self.gate.changed.notify_all();
    }
}

impl SemanticBlockGate {
    fn wait_for_turn(&self, order: usize) -> Result<SemanticBlockTurn<'_>> {
        let mut next_order = match self.next_order.lock() {
            Ok(next_order) => next_order,
            Err(poisoned) => poisoned.into_inner(),
        };
        while *next_order < order {
            next_order = match self.changed.wait(next_order) {
                Ok(next_order) => next_order,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        if *next_order != order {
            bail!(
                "semantic Block dispatch order {order} was already passed at {}",
                *next_order
            );
        }
        Ok(SemanticBlockTurn {
            next_order,
            gate: self,
        })
    }
}

fn record_isolated_assignment_failure(
    outcome: &mut AssignmentExecutionOutcome,
    assignment: &OrchestratorAssignment,
    stage: &str,
    error: &anyhow::Error,
) {
    outcome.assignment_failed = true;
    outcome.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor assignment '{}' failed during {stage}: {error:#}",
            assignment.id
        ),
        paths: assignment.assigned_paths.clone(),
    });
}

fn semantic_resolution_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.starts_with("unresolved semantic symbol:")
            || message.starts_with("ambiguous semantic symbol ")
            || message.starts_with("unresolved semantic module:")
            || message == "symbol query cannot be empty"
            || message == "module query cannot be empty"
    })
}

fn semantic_resolution_finding(
    assignment: &OrchestratorAssignment,
    error: &anyhow::Error,
) -> Finding {
    Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor assignment '{}' failed during semantic resolution: {error:#}",
            assignment.id
        ),
        paths: assignment.assigned_paths.clone(),
    }
}

struct CompletionSignal {
    index: usize,
    sender: mpsc::Sender<usize>,
}

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        let _ = self.sender.send(self.index);
    }
}

fn execute_supervisor_assignment(
    context: AssignmentExecutionContext<'_, '_>,
) -> AssignmentExecutionOutcome {
    let mut outcome = AssignmentExecutionOutcome::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_supervisor_assignment_inner(&context, &mut outcome)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            outcome.fatal_error = Some(format!(
                "supervisor assignment '{}' aborted: {error:#}",
                context.assignment.id
            ));
        }
        Err(_) => {
            outcome.fatal_error = Some(format!(
                "supervisor assignment '{}' panicked",
                context.assignment.id
            ));
        }
    }
    outcome
}

fn execute_supervisor_assignment_inner(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
) -> Result<()> {
    let AssignmentExecutionContext {
        index,
        concurrent_mode,
        plan,
        consultant,
        assignment_metadata,
        assignment,
        options,
        repo,
        run_dir,
        dirs,
        execution_runtime,
        worktree_creation,
        manager,
        reused,
        sync_store,
        semantic_store,
        prepared_semantic_token,
        prepared_semantic_findings,
        prepared_semantic_signals,
        prepared_semantic_failed,
        serial_semantic_warn_intents,
        semantic_block_order,
        semantic_block_gate,
        artifacts,
        cancellation,
        external_runner,
    } = context;
    outcome
        .findings
        .extend(prepared_semantic_findings.iter().cloned());
    outcome
        .health_signals
        .extend(prepared_semantic_signals.iter().copied());
    if *prepared_semantic_failed {
        outcome.assignment_failed = true;
        return Ok(());
    }
    let semantic_block_turn = match (semantic_block_gate, semantic_block_order) {
        (Some(gate), Some(order)) => Some(gate.wait_for_turn(*order)?),
        _ => None,
    };
    let current_primary_head = current_head_oid(repo)?;
    if !reused {
        let create_options = WorktreeCreateOptions {
            agent_id: assignment.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        };
        let create_result = match worktree_creation {
            SupervisorWorktreeCreation::Bound(cleanliness) => manager
                .create_with_repository_cleanliness(create_options, cleanliness)
                .with_context(|| {
                    format!(
                        "failed to create capability-bound child worktree '{}'",
                        assignment.id
                    )
                }),
            #[cfg(test)]
            SupervisorWorktreeCreation::TestOnly => manager.create_for_test(create_options),
        };
        if let Err(error) = create_result {
            record_isolated_assignment_failure(outcome, assignment, "worktree creation", &error);
            return Ok(());
        }
    }
    let worktree_write_lease = match manager
        .acquire_write_execution_lease(&assignment.id)
        .with_context(|| {
            format!(
                "failed to acquire exclusive execution lease for child worktree '{}'",
                assignment.id
            )
        }) {
        Ok(lease) => lease,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "worktree execution lease acquisition",
                &error,
            );
            return Ok(());
        }
    };
    let worktree = worktree_write_lease.record().clone();
    if *reused {
        if let Err(error) = ensure_reusable_child_worktree(&worktree, &current_primary_head) {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "reusable worktree validation",
                &error,
            );
            return Ok(());
        }
    }
    let child_base_head = match current_head_oid(&worktree.path).with_context(|| {
        format!(
            "failed to capture base HEAD for child worktree '{}' at {}",
            assignment.id,
            worktree.path.display()
        )
    }) {
        Ok(head) => head,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "worktree HEAD capture",
                &error,
            );
            return Ok(());
        }
    };
    let claim = match sync_store.claim_paths(&assignment.id, assignment.assigned_paths.iter()) {
        Ok(claim) => claim,
        Err(error) => {
            outcome.health_signals.push(
                if claim_conflict_details(sync_store, &assignment.assigned_paths).is_empty() {
                    SwarmHealthSignal::ClaimAcquisitionFailed
                } else {
                    SwarmHealthSignal::ClaimAcquisitionDenied
                },
            );
            outcome
                .findings
                .push(claim_failure_finding(sync_store, assignment, &error));
            outcome.assignment_failed = true;
            return Ok(());
        }
    };
    outcome.claim_tokens.push(claim.token);

    let semantic_token = if plan.semantic_coordination == SemanticCoordinationMode::Warn {
        if let Some(planned_intents) = serial_semantic_warn_intents {
            let coordination_result = {
                let mut planned_intents = match planned_intents.lock() {
                    Ok(planned_intents) => planned_intents,
                    Err(poisoned) => poisoned.into_inner(),
                };
                coordinate_semantic_assignment(
                    semantic_store,
                    assignment,
                    plan.semantic_coordination,
                    &mut outcome.semantic_tokens,
                    &mut planned_intents,
                    &mut outcome.findings,
                    &mut outcome.health_signals,
                )
            };
            let coordination = match coordination_result {
                Ok(coordination) => coordination,
                Err(error) if semantic_resolution_error(&error) => {
                    outcome.assignment_failed = true;
                    outcome
                        .findings
                        .push(semantic_resolution_finding(assignment, &error));
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match coordination {
                SemanticAssignmentCoordination::Ready(token) => token,
                SemanticAssignmentCoordination::Blocked(_) => {
                    bail!("warn-mode semantic preview unexpectedly blocked an assignment")
                }
            }
        } else {
            *prepared_semantic_token
        }
    } else {
        let mut planned_semantic_intents = Vec::new();
        let coordination_result = coordinate_semantic_assignment(
            semantic_store,
            assignment,
            plan.semantic_coordination,
            &mut outcome.semantic_tokens,
            &mut planned_semantic_intents,
            &mut outcome.findings,
            &mut outcome.health_signals,
        );
        drop(semantic_block_turn);
        let coordination = match coordination_result {
            Ok(coordination) => coordination,
            Err(error) if semantic_resolution_error(&error) => {
                outcome.assignment_failed = true;
                outcome
                    .findings
                    .push(semantic_resolution_finding(assignment, &error));
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match coordination {
            SemanticAssignmentCoordination::Ready(token) => token,
            SemanticAssignmentCoordination::Blocked(conflict_count) => {
                outcome.assignment_failed = true;
                outcome.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "semantic coordination blocked assignment '{}' with {conflict_count} blocking conflict(s)",
                        assignment.id
                    ),
                    paths: assignment.assigned_paths.clone(),
                });
                return Ok(());
            }
        }
    };

    let final_report_name = format!("{}.json", assignment.id);
    let final_report_relative = PathBuf::from("reports").join(&final_report_name);
    let final_report_path = dirs.reports.join(&final_report_name);
    let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
    let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
    let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");

    let mut child_report = None;
    let mut child_containment_verified = false;
    let mut retry_feedback: Option<Vec<String>> = None;
    let mut attempt_history = Vec::new();
    let max_attempts = usize::from(plan.max_child_retries).saturating_add(1);
    for attempt in 1..=max_attempts {
        let (incoming_name, capture_name) =
            invocation_scratch_names(*index, attempt, false, *concurrent_mode);
        let incoming_path = run_dir.join(&incoming_name);
        let capture_path = run_dir.join(&capture_name);
        let attempt_artifacts = child_attempt_artifacts(
            dirs,
            &incoming_path,
            &capture_path,
            &assignment.id,
            attempt,
            max_attempts > 1,
        );
        let corrective_retry_used = retry_feedback.is_some();
        let prompt = child_orchestrator_prompt_with_incoming_root(
            ChildOrchestratorPromptContext {
                plan,
                assignment,
                run_dir,
                worktree: &worktree,
                report_path: &attempt_artifacts.report_path,
                schema_path: &schema_path,
                worker_schema_path: &worker_schema_path,
                auditor_schema_path: &auditor_schema_path,
                consultant,
                claim_context: ChildPromptClaimContext {
                    claim: &claim,
                    semantic_intent_token: semantic_token,
                },
            },
            &incoming_path,
            assignment_metadata,
        )?;
        let attempt_prompt = match &retry_feedback {
            Some(problems) => prompt_with_corrective_feedback(&prompt, problems),
            None => prompt,
        };
        let prompt_relative = dirs.relative(&attempt_artifacts.prompt_path)?;
        with_supervisor_artifacts(artifacts, |writer, _| {
            write_private_prompt(writer, &prompt_relative, &attempt_prompt)
        })
        .with_context(|| {
            format!(
                "failed to write prompt {}",
                attempt_artifacts.prompt_path.display()
            )
        })?;

        let primary_before = primary_worktree_snapshot(repo, *execution_runtime)?;
        if let Some(error) = primary_before.inspection_problem() {
            bail!(
                "refusing to launch child without a complete primary integrity snapshot: {error}"
            );
        }
        let (incoming_scratch, capture_scratch) =
            with_supervisor_artifacts(artifacts, |writer, _| {
                create_named_invocation_scratches(writer, &incoming_name, &capture_name)
            })?;
        if incoming_scratch.path() != incoming_path || capture_scratch.path() != capture_path {
            with_supervisor_artifacts(artifacts, |writer, _| {
                discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
            })?;
            bail!("artifact scratch paths changed during child setup");
        }
        let incoming_output_root = match SecureOutputRoot::open_private(incoming_scratch.path()) {
            Ok(root) => root,
            Err(error) => {
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error).context("failed to bind child incoming scratch root");
            }
        };
        let capture_output_root = match SecureOutputRoot::open_private(capture_scratch.path()) {
            Ok(root) => root,
            Err(error) => {
                drop(incoming_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error).context("failed to bind parent capture scratch root");
            }
        };
        if incoming_output_root.path() != incoming_scratch.path()
            || capture_output_root.path() != capture_scratch.path()
        {
            drop(incoming_output_root);
            drop(capture_output_root);
            with_supervisor_artifacts(artifacts, |writer, _| {
                discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
            })?;
            bail!("descriptor-held invocation scratch roots changed during setup");
        }
        let mut command = ExternalAgentCommand::codex(
            &options.codex_bin,
            &worktree.path,
            &attempt_artifacts.prompt_path,
            &attempt_artifacts.log_path,
            &attempt_artifacts.report_path,
            Duration::from_secs(plan.child_timeout_seconds),
        );
        command = apply_role_model_selection(command, plan, assignment.role);
        command.output_schema = Some(schema_path.clone());
        command = command.with_hidden_root(repo).with_agent_lifecycle(
            repo,
            assignment.role.as_str(),
            options.run_id.as_str(),
            &assignment.id,
        );

        record_shared_orchestration_event(
            artifacts,
            &assignment.id,
            Some(options.run_id.as_str()),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Spawn,
            json!({
                "attempt": attempt,
                "corrective_retry": corrective_retry_used,
            }),
        )?;
        record_shared_orchestration_event(
            artifacts,
            &assignment.id,
            Some(options.run_id.as_str()),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Status,
            lifecycle_event_payload("running", Some(attempt), None),
        )?;

        // No scheduler, artifact-writer, or journal lock is held while the
        // independently contained external process runs.
        let external_run_result = match options.runtime {
            SupervisorRuntime::Codex => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    external_runner(&command, cancellation)
                })) {
                    Ok(run) => Ok(run),
                    Err(payload) => {
                        drop(incoming_output_root);
                        drop(capture_output_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &incoming_scratch,
                                &capture_scratch,
                            )
                        })?;
                        std::panic::resume_unwind(payload);
                    }
                }
            }
            SupervisorRuntime::Fake => deterministic_fake_child_run(
                &command,
                assignment,
                assignment_metadata,
                claim.token.get(),
                semantic_token,
            ),
        };
        let external_run = match external_run_result {
            Ok(run) => run,
            Err(error) => {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error).context("failed to produce deterministic child output");
            }
        };
        match complete_external_codex_usage(&external_run, &command) {
            Some(usage) => outcome.usage_samples.push(RoleUsageSample {
                role: assignment.role,
                model: command.model.clone(),
                usage,
            }),
            None => outcome.usage_incomplete = true,
        }
        drop(incoming_output_root);
        drop(capture_output_root);
        let child_thread_id = codex_thread_id_from_stdout(external_run.stdout_bytes());
        record_shared_orchestration_event(
            artifacts,
            &assignment.id,
            Some(options.run_id.as_str()),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Status,
            lifecycle_event_payload(
                if external_process_completed(&external_run) {
                    "completed"
                } else {
                    "failed"
                },
                Some(attempt),
                child_thread_id.as_deref(),
            ),
        )?;
        let attempt_containment_verified = external_safety_verified(&external_run, options.runtime);
        if !attempt_containment_verified {
            outcome.external_containment_failed = true;
            outcome.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "external child process containment was not verified empty for '{}' attempt {attempt}; evidence: {:?}; report: {}",
                    assignment.id,
                    (external_run.process_tree, external_run.side_effects),
                    attempt_artifacts.raw_report_relative.display()
                ),
                paths: vec![attempt_artifacts.raw_report_relative.clone()],
            });
        }
        outcome
            .command_records
            .push(command_record_from_external(&external_run, &command));
        let raw_report_validated = read_child_report(
            external_run.output_last_message(),
            &attempt_artifacts.raw_report_relative,
        )
        .is_ok();
        let worker_journal_evidence = with_supervisor_artifacts(artifacts, |writer, journal| {
            let evidence = import_worker_execution_journals(writer, assignment, &incoming_scratch)?;
            record_worker_journal_events(journal, writer, assignment, &evidence);
            Ok(evidence)
        })?;
        with_supervisor_artifacts(artifacts, |writer, _| {
            import_external_attempt_evidence(
                writer,
                ExternalAttemptEvidenceContext {
                    incoming_scratch: &incoming_scratch,
                    capture_scratch: &capture_scratch,
                    artifacts: &attempt_artifacts,
                    external_run: &external_run,
                    external_command: &command,
                    raw_report_validated,
                    runtime: options.runtime,
                },
            )
        })?;
        let primary_after = primary_worktree_snapshot(repo, *execution_runtime)?;
        let primary_changes = primary_integrity_changes(&primary_before, &primary_after);
        let (mut attempt_report, report_shape_problems) =
            collect_child_report(ChildReportCollectionContext {
                assignment,
                assignment_metadata,
                report_path: &attempt_artifacts.raw_report_relative,
                external_run: &external_run,
                external_command: &command,
                worktree_path: &worktree.path,
                child_base_head: &child_base_head,
                worker_journals: &worker_journal_evidence,
            });
        if !primary_changes.is_empty() {
            mark_primary_integrity_violation(assignment, &primary_changes, &mut attempt_report);
        }
        if !attempt_containment_verified {
            mark_child_containment_violation(
                assignment,
                &attempt_artifacts.raw_report_relative,
                external_run.process_tree,
                external_run.side_effects,
                &mut attempt_report,
            );
            attempt_history.push(ChildAttemptHistory {
                attempt,
                report_path: attempt_artifacts.raw_report_relative.clone(),
                structural_problems: report_shape_problems,
                corrective_retry_used,
            });
            child_report = Some(attempt_report);
            break;
        }
        let retry_used = should_retry_child_report(
            &attempt_report,
            &report_shape_problems,
            attempt,
            plan.max_child_retries,
        );
        attempt_history.push(ChildAttemptHistory {
            attempt,
            report_path: attempt_artifacts.raw_report_relative.clone(),
            structural_problems: report_shape_problems.clone(),
            corrective_retry_used,
        });
        if retry_used {
            outcome
                .health_signals
                .push(SwarmHealthSignal::AssignmentOutcome(
                    AssignmentHealthOutcome::Retried,
                ));
            record_shared_orchestration_event(
                artifacts,
                &assignment.id,
                Some(options.run_id.as_str()),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Reject,
                json!({
                    "scope": "attempt",
                    "attempt": attempt,
                    "reason": "structural report requires corrective retry",
                    "structural_problems": report_shape_problems,
                }),
            )?;
            record_shared_orchestration_event(
                artifacts,
                &assignment.id,
                Some(options.run_id.as_str()),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Status,
                lifecycle_event_payload("retrying", Some(attempt), None),
            )?;
            retry_feedback = Some(report_shape_problems);
            continue;
        }
        if attempt > 1 {
            attempt_report.findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!("child report accepted after corrective retry attempt {attempt}"),
                paths: vec![attempt_artifacts.raw_report_relative.clone()],
            });
        }
        child_containment_verified = true;
        child_report = Some(attempt_report);
        break;
    }

    let Some(mut child_report) = child_report else {
        let error = anyhow!(
            "child orchestrator '{}' did not produce a collected report after retries",
            assignment.id
        );
        record_isolated_assignment_failure(outcome, assignment, "child report collection", &error);
        return Ok(());
    };
    if plan.max_child_retries > 0 {
        append_child_attempt_history(&mut child_report, &attempt_history);
    }
    let pre_auditor_candidate = if child_containment_verified {
        match bind_supervisor_decomposition_candidate(
            repo,
            assignment,
            &mut child_report,
            &worktree_write_lease,
        ) {
            Ok(inspection) => inspection,
            Err(error) => {
                reject_supervisor_decomposition_binding(
                    &mut child_report,
                    &final_report_path,
                    &error,
                );
                None
            }
        }
    } else {
        None
    };
    with_supervisor_artifacts(artifacts, |writer, _| {
        write_child_report(writer, &final_report_relative, &child_report)
    })?;

    let mut assignment_containment_verified = child_containment_verified;
    if child_containment_verified && parent_auditor_required(assignment, &child_report) {
        let auditor_id = parent_auditor_id(assignment);
        let auditor_prompt_path = dirs.assignments.join(format!("{auditor_id}.prompt.md"));
        let (auditor_incoming_name, auditor_capture_name) =
            invocation_scratch_names(*index, 1, true, *concurrent_mode);
        let auditor_incoming_path = run_dir.join(&auditor_incoming_name);
        let auditor_capture_path = run_dir.join(&auditor_capture_name);
        let auditor_report_path = auditor_incoming_path.join(format!("{auditor_id}.json"));
        let auditor_log_path = auditor_capture_path.join(format!("{auditor_id}.jsonl"));
        let auditor_artifacts = ChildAttemptArtifacts {
            prompt_path: auditor_prompt_path.clone(),
            report_path: auditor_report_path.clone(),
            log_path: auditor_log_path.clone(),
            raw_report_relative: PathBuf::from("evidence")
                .join("incoming")
                .join(format!("{auditor_id}.json")),
            raw_stdout_relative: PathBuf::from("logs").join(format!("{auditor_id}.jsonl")),
            command_record_relative: PathBuf::from("logs")
                .join(format!("{auditor_id}.summary.json")),
        };
        let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
        let auditor_prompt = parent_review_auditor_prompt(ParentReviewAuditorPromptContext {
            plan,
            assignment,
            assignment_metadata,
            run_dir,
            worktree_path: &worktree.path,
            child_report_path: &final_report_path,
            auditor_report_path: &auditor_report_path,
            schema_path: &auditor_schema_path,
            child_report: &child_report,
        })?;
        let auditor_prompt_relative = dirs.relative(&auditor_prompt_path)?;
        with_supervisor_artifacts(artifacts, |writer, _| {
            write_private_prompt(writer, &auditor_prompt_relative, &auditor_prompt)
        })
        .with_context(|| {
            format!(
                "failed to write auditor prompt {}",
                auditor_prompt_path.display()
            )
        })?;

        let primary_before_auditor = primary_worktree_snapshot(repo, *execution_runtime)?;
        if let Some(error) = primary_before_auditor.inspection_problem() {
            bail!(
                "refusing to launch parent review auditor without a complete primary integrity snapshot: {error}"
            );
        }
        let (auditor_incoming_scratch, auditor_capture_scratch) =
            with_supervisor_artifacts(artifacts, |writer, _| {
                create_named_invocation_scratches(
                    writer,
                    &auditor_incoming_name,
                    &auditor_capture_name,
                )
            })?;
        if auditor_incoming_scratch.path() != auditor_incoming_path
            || auditor_capture_scratch.path() != auditor_capture_path
        {
            with_supervisor_artifacts(artifacts, |writer, _| {
                discard_invocation_scratches(
                    writer,
                    &auditor_incoming_scratch,
                    &auditor_capture_scratch,
                )
            })?;
            bail!("artifact scratch paths changed during parent auditor setup");
        }
        let auditor_incoming_root =
            match SecureOutputRoot::open_private(auditor_incoming_scratch.path()) {
                Ok(root) => root,
                Err(error) => {
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(
                            writer,
                            &auditor_incoming_scratch,
                            &auditor_capture_scratch,
                        )
                    })?;
                    return Err(error)
                        .context("failed to bind parent auditor incoming scratch root");
                }
            };
        let auditor_capture_root =
            match SecureOutputRoot::open_private(auditor_capture_scratch.path()) {
                Ok(root) => root,
                Err(error) => {
                    drop(auditor_incoming_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(
                            writer,
                            &auditor_incoming_scratch,
                            &auditor_capture_scratch,
                        )
                    })?;
                    return Err(error)
                        .context("failed to bind parent auditor capture scratch root");
                }
            };
        if auditor_incoming_root.path() != auditor_incoming_scratch.path()
            || auditor_capture_root.path() != auditor_capture_scratch.path()
        {
            drop(auditor_incoming_root);
            drop(auditor_capture_root);
            with_supervisor_artifacts(artifacts, |writer, _| {
                discard_invocation_scratches(
                    writer,
                    &auditor_incoming_scratch,
                    &auditor_capture_scratch,
                )
            })?;
            bail!("descriptor-held auditor scratch roots changed during setup");
        }

        let mut auditor_command = ExternalAgentCommand::codex(
            &options.codex_bin,
            &worktree.path,
            &auditor_prompt_path,
            &auditor_log_path,
            &auditor_report_path,
            Duration::from_secs(plan.child_timeout_seconds),
        );
        auditor_command = apply_role_model_selection(auditor_command, plan, AgentRole::Auditor);
        auditor_command.output_schema = Some(auditor_schema_path);
        auditor_command = auditor_command
            .with_workspace_access(WorkspaceAccess::ReadOnly)
            .with_hidden_root(repo)
            .with_agent_lifecycle(
                repo,
                AgentRole::Auditor.as_str(),
                options.run_id.as_str(),
                &auditor_id,
            );
        record_shared_orchestration_event(
            artifacts,
            &auditor_id,
            Some(&assignment.id),
            OrchestrationRole::Auditor,
            OrchestrationEventKind::Spawn,
            json!({"attempt": 1}),
        )?;
        record_shared_orchestration_event(
            artifacts,
            &auditor_id,
            Some(&assignment.id),
            OrchestrationRole::Auditor,
            OrchestrationEventKind::Status,
            lifecycle_event_payload("running", Some(1), None),
        )?;

        // The artifact and journal mutex is intentionally released before
        // entering the potentially long-running auditor process.
        let auditor_run_result = match options.runtime {
            SupervisorRuntime::Codex => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    external_runner(&auditor_command, cancellation)
                })) {
                    Ok(run) => Ok(run),
                    Err(payload) => {
                        drop(auditor_incoming_root);
                        drop(auditor_capture_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &auditor_incoming_scratch,
                                &auditor_capture_scratch,
                            )
                        })?;
                        std::panic::resume_unwind(payload);
                    }
                }
            }
            SupervisorRuntime::Fake => {
                deterministic_fake_auditor_run(&auditor_command, assignment, &child_report)
            }
        };
        let auditor_run = match auditor_run_result {
            Ok(run) => run,
            Err(error) => {
                drop(auditor_incoming_root);
                drop(auditor_capture_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(
                        writer,
                        &auditor_incoming_scratch,
                        &auditor_capture_scratch,
                    )
                })?;
                return Err(error).context("failed to produce deterministic parent auditor output");
            }
        };
        match complete_external_codex_usage(&auditor_run, &auditor_command) {
            Some(usage) => outcome.usage_samples.push(RoleUsageSample {
                role: AgentRole::Auditor,
                model: auditor_command.model.clone(),
                usage,
            }),
            None => outcome.usage_incomplete = true,
        }
        drop(auditor_incoming_root);
        drop(auditor_capture_root);
        let auditor_thread_id = codex_thread_id_from_stdout(auditor_run.stdout_bytes());
        record_shared_orchestration_event(
            artifacts,
            &auditor_id,
            Some(&assignment.id),
            OrchestrationRole::Auditor,
            OrchestrationEventKind::Status,
            lifecycle_event_payload(
                if external_process_completed(&auditor_run) {
                    "completed"
                } else {
                    "failed"
                },
                Some(1),
                auditor_thread_id.as_deref(),
            ),
        )?;
        let auditor_containment_verified = external_safety_verified(&auditor_run, options.runtime);
        if !auditor_containment_verified {
            assignment_containment_verified = false;
            outcome.external_containment_failed = true;
            outcome.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "external parent auditor process containment was not verified empty for '{}'; evidence: {:?}; report: {}",
                    auditor_id,
                    (auditor_run.process_tree, auditor_run.side_effects),
                    auditor_artifacts.raw_report_relative.display()
                ),
                paths: vec![auditor_artifacts.raw_report_relative.clone()],
            });
        }
        let auditor_command_record = command_record_from_external(&auditor_run, &auditor_command);
        outcome.command_records.push(auditor_command_record.clone());
        child_report.commands_run.push(auditor_command_record);
        let raw_auditor_validated = read_auditor_report(
            auditor_run.output_last_message(),
            &auditor_artifacts.raw_report_relative,
        )
        .is_ok();
        with_supervisor_artifacts(artifacts, |writer, _| {
            import_external_attempt_evidence(
                writer,
                ExternalAttemptEvidenceContext {
                    incoming_scratch: &auditor_incoming_scratch,
                    capture_scratch: &auditor_capture_scratch,
                    artifacts: &auditor_artifacts,
                    external_run: &auditor_run,
                    external_command: &auditor_command,
                    raw_report_validated: raw_auditor_validated,
                    runtime: options.runtime,
                },
            )
        })?;
        let primary_after_auditor = primary_worktree_snapshot(repo, *execution_runtime)?;
        let primary_auditor_changes =
            primary_integrity_changes(&primary_before_auditor, &primary_after_auditor);
        let mut auditor_report = collect_parent_auditor_report(
            assignment,
            &auditor_artifacts.raw_report_relative,
            &auditor_run,
            &auditor_command,
        );
        if !primary_auditor_changes.is_empty() {
            mark_auditor_primary_integrity_violation(
                assignment,
                &primary_auditor_changes,
                &mut auditor_report,
            );
        }
        child_report.audit_reports.push(auditor_report);
    }
    if child_containment_verified {
        validate_auditor_reports(assignment, &final_report_path, &mut child_report);
    }
    if !report_failed(&child_report) && !child_report.decomposition_completions.is_empty() {
        let post_auditor_candidate =
            inspect_supervisor_decomposition_candidate(repo, assignment, &worktree_write_lease);
        let stable = match (pre_auditor_candidate.as_ref(), post_auditor_candidate.as_ref()) {
            (Some(before), Ok(after)) if before == after => Ok(()),
            (Some(before), Ok(after)) => Err(anyhow!(
                "candidate content, paths, or base changed across parent auditor review: before={before:?}, after={after:?}"
            )),
            (Some(_), Err(error)) => Err(anyhow!(
                "failed to recapture decomposition candidate after parent auditor review: {error:#}"
            )),
            (None, _) => Err(anyhow!(
                "accepted decomposition evidence has no pre-auditor supervisor candidate binding"
            )),
        };
        if let Err(error) = stable {
            reject_supervisor_decomposition_binding(&mut child_report, &final_report_path, &error);
        }
    }
    with_supervisor_artifacts(artifacts, |writer, journal| {
        write_child_report(writer, &final_report_relative, &child_report)?;
        record_final_report_decisions(journal, writer, &options.run_id, &child_report);
        Ok(())
    })?;
    if child_report.status != ReviewStatus::Succeeded {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("child orchestrator '{}' failed", assignment.id),
            paths: vec![final_report_path.clone()],
        });
    }
    if child_report.audit_reports.iter().any(report_failed) {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' failed enforced parent review auditor gate",
                assignment.id
            ),
            paths: vec![final_report_path.clone()],
        });
    }
    if child_report.worker_reports.iter().any(report_failed) {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' reported failed or rejected worker output",
                assignment.id
            ),
            paths: child_report.files_changed.clone(),
        });
    }
    outcome.report = Some(child_report);
    if !assignment_containment_verified {
        outcome.external_containment_failed = true;
    }
    Ok(())
}

fn assignments_overlap(left: &OrchestratorAssignment, right: &OrchestratorAssignment) -> bool {
    left.assigned_paths.iter().any(|left_path| {
        right
            .assigned_paths
            .iter()
            .any(|right_path| paths_overlap(left_path, right_path))
    })
}

fn plan_has_overlapping_assignments(plan: &SupervisorPlan) -> bool {
    plan.assignments
        .iter()
        .enumerate()
        .any(|(left_index, left)| {
            plan.assignments
                .iter()
                .skip(left_index.saturating_add(1))
                .any(|right| assignments_overlap(left, right))
        })
}

#[derive(Default)]
struct PreparedSemanticAssignment {
    token: Option<u64>,
    findings: Vec<Finding>,
    health_signals: Vec<SwarmHealthSignal>,
    assignment_failed: bool,
}

fn prepare_semantic_warn_assignments(
    store: &SemanticIntentStore,
    plan: &SupervisorPlan,
) -> Result<Vec<PreparedSemanticAssignment>> {
    let mut prepared = plan
        .assignments
        .iter()
        .map(|_| PreparedSemanticAssignment::default())
        .collect::<Vec<_>>();
    if plan.semantic_coordination != SemanticCoordinationMode::Warn {
        return Ok(prepared);
    }

    let mut planned_preview_intents = Vec::new();
    for (index, assignment) in plan.assignments.iter().enumerate() {
        let report = match store.preview_with_additional_active(
            semantic_assignment_request(assignment),
            &planned_preview_intents,
        ) {
            Ok(report) => report,
            Err(error) if semantic_resolution_error(&error) => {
                prepared[index]
                    .findings
                    .push(semantic_resolution_finding(assignment, &error));
                prepared[index].assignment_failed = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            let conflict_count = report
                .blocking_conflict_count
                .saturating_add(report.advisory_conflict_count);
            prepared[index].findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    conflict_count
                ),
                paths: assignment.assigned_paths.clone(),
            });
            prepared[index]
                .health_signals
                .push(SwarmHealthSignal::SemanticConflictWarned {
                    conflicts: conflict_count,
                });
        }
        prepared[index].token = Some(report.intent.token.get());
        planned_preview_intents.push(report.intent);
    }
    Ok(prepared)
}

#[cfg(test)]
fn run_supervisor_plan_with_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let serialized_runner = Mutex::new(external_runner);
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        options,
        1,
        execution_runtime,
        SupervisorWorktreeCreation::TestOnly,
        &|command, _cancellation| match serialized_runner.lock() {
            Ok(mut runner) => runner(command),
            Err(poisoned) => poisoned.into_inner()(command),
        },
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_concurrent_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &(dyn Fn(&ExternalAgentCommand) -> ExternalAgentRun + Send + Sync),
) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        &|command, _cancellation| external_runner(command),
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_concurrent_cancellable_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        external_runner,
    )
}

fn run_supervisor_plan_with_runner_and_creation(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    let LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
    } = loaded;
    validate_max_concurrent_children(max_concurrent_children)?;
    match worktree_creation {
        SupervisorWorktreeCreation::Bound(_)
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("verified worktree creation capability requires the verified supervisor runtime")
        }
        #[cfg(test)]
        SupervisorWorktreeCreation::TestOnly
            if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation =>
        {
            bail!("test-only worktree creation requires the simulation supervisor runtime")
        }
        _ => {}
    }
    let runtime = options.runtime;
    let repo = discover_repo_root(&options.repo)?;

    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    let manager = WorktreeManager::new(&repo);
    let mut sync_store_slot = None;
    let mut semantic_store_slot = None;
    let mut orchestration_journal = None;
    let mut acquired_claim_tokens = Vec::new();
    let mut acquired_semantic_tokens = Vec::new();
    let mut concurrently_released_claims = Vec::new();
    let mut concurrent_release_errors = Vec::new();
    let mut concurrently_released_semantic_intents = Vec::new();
    let mut concurrent_semantic_release_errors = Vec::new();
    let mut command_records = Vec::new();
    let mut usage_samples = Vec::new();
    let mut usage_incomplete = false;
    let mut orchestrator_reports = Vec::new();
    let mut findings = Vec::new();
    if runtime == SupervisorRuntime::Fake {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message:
                "explicit fake supervisor runtime is simulation-only and cannot publish acceptance"
                    .to_string(),
            paths: Vec::new(),
        });
    }
    let mut primary_run_baseline = None;
    let mut assignment_execution_failed = false;
    let mut external_containment_failed = false;
    let mut circuit_breaker_trip = None;

    let run_result = (|| -> Result<()> {
        if !options.allow_dirty_primary {
            ensure_clean_primary(&repo, execution_runtime)?;
        }
        write_plan_snapshot(
            &mut artifact_writer,
            Path::new("assignments/supervisor-plan.json"),
            &plan,
            &consultant,
            &assignment_metadata,
            &plan_metadata,
        )?;
        write_orchestrator_schema(
            &mut artifact_writer,
            Path::new("schemas/orchestrator-review-report.schema.json"),
        )?;
        write_worker_schema(
            &mut artifact_writer,
            Path::new("schemas/worker-report.schema.json"),
        )?;
        write_auditor_schema(
            &mut artifact_writer,
            Path::new("schemas/auditor-report.schema.json"),
        )?;
        sync_store_slot = Some(SyncStore::open(&repo)?);
        semantic_store_slot = Some(SemanticIntentStore::open(&repo)?);
        orchestration_journal = initialize_orchestration_event_journal(&repo, &options.run_id);
        record_orchestration_event(
            &mut orchestration_journal,
            &mut artifact_writer,
            options.run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            OrchestrationEventKind::Status,
            lifecycle_event_payload("running", None, None),
        );
        let sync_store = sync_store_slot
            .as_ref()
            .context("supervisor sync store was not initialized")?;
        let semantic_store = semantic_store_slot
            .as_ref()
            .context("supervisor semantic store was not initialized")?;

        let baseline = primary_worktree_snapshot(&repo, execution_runtime)?;
        if let Some(error) = baseline.inspection_problem() {
            bail!(
                "refusing to launch supervised work without a complete primary integrity snapshot: {error}"
            );
        }
        primary_run_baseline = Some(baseline);

        let existing_ids = manager
            .list()?
            .into_iter()
            .map(|record| record.name)
            .collect::<BTreeSet<_>>();
        let release_per_assignment =
            max_concurrent_children > 1 || plan_has_overlapping_assignments(&plan);
        let prepared_semantic_assignments = if max_concurrent_children > 1 {
            prepare_semantic_warn_assignments(semantic_store, &plan)?
        } else {
            plan.assignments
                .iter()
                .map(|_| PreparedSemanticAssignment::default())
                .collect()
        };
        let (scheduler_result, indexed_outcomes) = {
            let cancellation = ProcessCancellation::new();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut orchestration_journal,
            });
            let mut indexed_outcomes = (0..plan.assignments.len())
                .map(|_| None)
                .collect::<Vec<Option<AssignmentExecutionOutcome>>>();
            let semantic_block_gate = SemanticBlockGate::default();
            let serial_semantic_warn_intents = Mutex::new(Vec::new());
            let mut health_breaker = SwarmHealthCircuitBreaker::default();

            let scheduler_result = if max_concurrent_children == 1 {
                for (index, assignment) in plan.assignments.iter().enumerate() {
                    if !health_breaker.permits_admission() {
                        break;
                    }
                    let outcome = execute_supervisor_assignment(AssignmentExecutionContext {
                        index,
                        concurrent_mode: false,
                        plan: &plan,
                        consultant: &consultant,
                        assignment_metadata: &assignment_metadata,
                        assignment,
                        options: &options,
                        repo: &repo,
                        run_dir: &run_dir,
                        dirs: &dirs,
                        execution_runtime,
                        worktree_creation,
                        manager: &manager,
                        reused: existing_ids.contains(&assignment.id),
                        sync_store,
                        semantic_store,
                        prepared_semantic_token: prepared_semantic_assignments[index].token,
                        prepared_semantic_findings: &prepared_semantic_assignments[index].findings,
                        prepared_semantic_signals: &prepared_semantic_assignments[index]
                            .health_signals,
                        prepared_semantic_failed: prepared_semantic_assignments[index]
                            .assignment_failed,
                        serial_semantic_warn_intents: Some(&serial_semantic_warn_intents),
                        semantic_block_order: None,
                        semantic_block_gate: None,
                        artifacts: &shared_artifacts,
                        cancellation: cancellation.clone(),
                        external_runner,
                    });
                    let mut outcome = outcome;
                    if release_per_assignment {
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                    }
                    if circuit_breaker_trip.is_none() {
                        if let Some(trip) = observe_assignment_health(&mut health_breaker, &outcome)
                        {
                            record_breaker_trip(&shared_artifacts, &options.run_id, &trip)?;
                            circuit_breaker_trip = Some(trip);
                        }
                    }
                    let abort = outcome.requires_scheduler_abort();
                    indexed_outcomes[index] = Some(outcome);
                    if abort {
                        break;
                    }
                }
                Ok(())
            } else {
                thread::scope(|scope| -> Result<()> {
                    let plan_ref = &plan;
                    let consultant_ref = &consultant;
                    let assignment_metadata_ref = &assignment_metadata;
                    let options_ref = &options;
                    let repo_ref = repo.as_path();
                    let run_dir_ref = run_dir.as_path();
                    let dirs_ref = &dirs;
                    let manager_ref = &manager;
                    let existing_ids_ref = &existing_ids;
                    let prepared_semantic_assignments_ref = &prepared_semantic_assignments;
                    let semantic_block_gate_ref = &semantic_block_gate;
                    let artifacts_ref = &shared_artifacts;
                    let (completion_sender, completion_receiver) = mpsc::channel::<usize>();
                    let mut pending = (0..plan.assignments.len()).collect::<BTreeSet<_>>();
                    let mut active = BTreeMap::new();
                    let mut stop_scheduling = false;
                    let mut next_semantic_block_order = 0usize;

                    while !pending.is_empty() || !active.is_empty() {
                        if !stop_scheduling {
                            while active.len() < max_concurrent_children {
                                if !health_breaker.permits_admission() {
                                    stop_scheduling = true;
                                    break;
                                }
                                let next = pending.iter().copied().find(|candidate| {
                                    active.keys().all(|active_index| {
                                        !assignments_overlap(
                                            &plan.assignments[*candidate],
                                            &plan.assignments[*active_index],
                                        )
                                    })
                                });
                                let Some(index) = next else {
                                    break;
                                };
                                pending.remove(&index);
                                let assignment = &plan_ref.assignments[index];
                                let semantic_block_order = (plan_ref.semantic_coordination
                                    == SemanticCoordinationMode::Block)
                                    .then(|| {
                                        let order = next_semantic_block_order;
                                        next_semantic_block_order =
                                            next_semantic_block_order.saturating_add(1);
                                        order
                                    });
                                let completion_sender = completion_sender.clone();
                                let assignment_cancellation = cancellation.clone();
                                let spawn_result =
                                    thread::Builder::new().spawn_scoped(scope, move || {
                                        let _completion = CompletionSignal {
                                            index,
                                            sender: completion_sender,
                                        };
                                        execute_supervisor_assignment(AssignmentExecutionContext {
                                            index,
                                            concurrent_mode: true,
                                            plan: plan_ref,
                                            consultant: consultant_ref,
                                            assignment_metadata: assignment_metadata_ref,
                                            assignment,
                                            options: options_ref,
                                            repo: repo_ref,
                                            run_dir: run_dir_ref,
                                            dirs: dirs_ref,
                                            execution_runtime,
                                            worktree_creation,
                                            manager: manager_ref,
                                            reused: existing_ids_ref.contains(&assignment.id),
                                            sync_store,
                                            semantic_store,
                                            prepared_semantic_token:
                                                prepared_semantic_assignments_ref[index].token,
                                            prepared_semantic_findings:
                                                &prepared_semantic_assignments_ref[index].findings,
                                            prepared_semantic_signals:
                                                &prepared_semantic_assignments_ref[index]
                                                    .health_signals,
                                            prepared_semantic_failed:
                                                prepared_semantic_assignments_ref[index]
                                                    .assignment_failed,
                                            serial_semantic_warn_intents: None,
                                            semantic_block_order,
                                            semantic_block_gate: semantic_block_order
                                                .map(|_| semantic_block_gate_ref),
                                            artifacts: artifacts_ref,
                                            cancellation: assignment_cancellation,
                                            external_runner,
                                        })
                                    });
                                match spawn_result {
                                    Ok(handle) => {
                                        active.insert(index, handle);
                                    }
                                    Err(error) => {
                                        cancellation.cancel();
                                        record_assignment_spawn_failure(
                                            &mut indexed_outcomes,
                                            &mut stop_scheduling,
                                            index,
                                            &assignment.id,
                                            &error,
                                        )?;
                                        break;
                                    }
                                }
                            }
                        }

                        if active.is_empty() {
                            if pending.is_empty() || stop_scheduling {
                                break;
                            }
                            cancellation.cancel();
                            bail!("supervisor scheduler could not select a pending assignment");
                        }

                        let completed_index = match completion_receiver.recv() {
                            Ok(index) => index,
                            Err(error) => {
                                cancellation.cancel();
                                return Err(error)
                                    .context("supervisor assignment completion channel closed");
                            }
                        };
                        let handle = match active.remove(&completed_index) {
                            Some(handle) => handle,
                            None => {
                                cancellation.cancel();
                                bail!("supervisor completion referenced an inactive assignment");
                            }
                        };
                        let mut outcome = match handle.join() {
                            Ok(outcome) => outcome,
                            Err(_) => AssignmentExecutionOutcome::fatal(format!(
                                "supervisor assignment '{}' thread panicked",
                                plan.assignments[completed_index].id
                            )),
                        };
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                        if outcome.requires_scheduler_abort() {
                            cancellation.cancel();
                            stop_scheduling = true;
                        } else if circuit_breaker_trip.is_none() {
                            if let Some(trip) =
                                observe_assignment_health(&mut health_breaker, &outcome)
                            {
                                record_breaker_trip(&shared_artifacts, &options.run_id, &trip)?;
                                circuit_breaker_trip = Some(trip);
                                // A breaker trip is a graceful scheduler stop: pending assignments
                                // are not admitted, while already-active children retain their
                                // existing cancellation tokens and are deterministically drained.
                                stop_scheduling = true;
                            }
                        }
                        indexed_outcomes[completed_index] = Some(outcome);
                    }

                    for (index, handle) in active {
                        let mut outcome = match handle.join() {
                            Ok(outcome) => outcome,
                            Err(_) => AssignmentExecutionOutcome::fatal(format!(
                                "supervisor assignment '{}' thread panicked",
                                plan.assignments[index].id
                            )),
                        };
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                        indexed_outcomes[index] = Some(outcome);
                    }
                    Ok(())
                })
            };
            (scheduler_result, indexed_outcomes)
        };

        let mut fatal_errors = Vec::new();
        for outcome in indexed_outcomes.into_iter().flatten() {
            command_records.extend(outcome.command_records);
            usage_samples.extend(outcome.usage_samples);
            usage_incomplete |= outcome.usage_incomplete;
            findings.extend(outcome.findings);
            assignment_execution_failed |= outcome.assignment_failed;
            external_containment_failed |= outcome.external_containment_failed;
            if !release_per_assignment {
                acquired_claim_tokens.extend(outcome.claim_tokens);
                acquired_semantic_tokens.extend(outcome.semantic_tokens);
            } else {
                concurrently_released_claims.extend(outcome.released_claims);
                concurrent_release_errors.extend(outcome.release_errors);
                concurrently_released_semantic_intents.extend(outcome.released_semantic_intents);
                concurrent_semantic_release_errors.extend(outcome.semantic_release_errors);
            }
            if let Some(report) = outcome.report {
                orchestrator_reports.push(report);
            }
            if let Some(error) = outcome.fatal_error {
                fatal_errors.push(error);
            }
        }
        scheduler_result?;
        if let Some(error) = fatal_errors.into_iter().next() {
            bail!("{error}");
        }
        Ok(())
    })();

    if let Err(error) = &run_result {
        findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("{error:#}"),
            paths: Vec::new(),
        });
    }
    let breaker_tripped = circuit_breaker_trip.is_some();
    let supervisor_breaker_trip = circuit_breaker_trip.map(|trip| SupervisorBreakerTrip {
        reason: trip.reason,
        window: trip.window,
        recovery_guidance: BREAKER_RECOVERY_GUIDANCE.to_string(),
    });
    if let Some(trip) = &supervisor_breaker_trip {
        findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "swarm-health circuit breaker opened and drained active assignments: {:?}",
                trip.reason
            ),
            paths: Vec::new(),
        });
    }

    let (mut released_claims, mut release_errors) = match sync_store_slot.as_ref() {
        Some(store) => release_claims(store, acquired_claim_tokens),
        None => (Vec::new(), Vec::new()),
    };
    released_claims.extend(concurrently_released_claims);
    release_errors.extend(concurrent_release_errors);
    let (mut released_semantic_intents, mut semantic_release_errors) =
        match semantic_store_slot.as_ref() {
            Some(store) => release_semantic_intents(store, acquired_semantic_tokens),
            None => (Vec::new(), Vec::new()),
        };
    released_semantic_intents.extend(concurrently_released_semantic_intents);
    semantic_release_errors.extend(concurrent_semantic_release_errors);
    let final_primary_integrity_failed = match primary_run_baseline.as_ref() {
        Some(baseline) => match primary_worktree_snapshot(&repo, execution_runtime) {
            Ok(final_snapshot) => {
                if let Some(error) = final_snapshot.inspection_problem() {
                    findings.push(Finding {
                        severity: FindingSeverity::Error,
                        message: format!(
                            "primary worktree final integrity snapshot was incomplete: {error}"
                        ),
                        paths: Vec::new(),
                    });
                    true
                } else {
                    let changes = primary_integrity_changes(baseline, &final_snapshot);
                    let integrity_failed = !changes.is_empty();
                    if integrity_failed {
                        findings.push(Finding {
                            severity: FindingSeverity::Error,
                            message: format!(
                                "primary worktree integrity differed from the supervise-run baseline during final acceptance: {}",
                                changes.details.join("; ")
                            ),
                            paths: changes.paths,
                        });
                    }
                    integrity_failed
                }
            }
            Err(error) => {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!("primary worktree final integrity check failed: {error}"),
                    paths: Vec::new(),
                });
                true
            }
        },
        None => true,
    };
    let nested_workers_present = plan
        .assignments
        .iter()
        .any(|assignment| !assignment.worker_assignments.is_empty());
    if nested_workers_present {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "worker usage is not process-observable because nested workers execute inside child Codex sessions; child-orchestrator and auditor process usage remains reportable, while runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let flattened_recursive_schedule = plan_metadata
        .assignment_schedule
        .iter()
        .any(|entry| entry.parent_assignment_id.is_some());
    if flattened_recursive_schedule {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "recursive assignment subtrees are executed as MACO-visible flattened O1 assignments in deterministic pre-order; parent_assignment_id and depth are traceability metadata, not a completion dependency or nested subprocess launch barrier"
                .to_string(),
            paths: Vec::new(),
        });
    }
    if usage_incomplete {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "process usage is incomplete because at least one external Codex JSONL capture was missing, truncated, or malformed"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let failed = run_result.is_err()
        || !release_errors.is_empty()
        || !semantic_release_errors.is_empty()
        || assignment_execution_failed
        || external_containment_failed
        || final_primary_integrity_failed
        || breaker_tripped
        || orchestrator_reports.iter().any(report_failed);
    let success = !failed;
    let publishable = success && runtime == SupervisorRuntime::Codex;
    let report_plan_file = options
        .plan_file
        .strip_prefix(&repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from("<external-plan>"));
    let report_run_dir = run_dir
        .strip_prefix(&repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            RunArtifactFamily::Supervise
                .run_root()
                .join(options.run_id.as_str())
        });
    let usage_complete = !usage_incomplete;
    let RoleUsageAggregation {
        reports: mut role_usage,
        total_usage,
        total_cost_usd: observed_total_cost_usd,
    } = role_usage_report(&plan, usage_samples)?;
    let total_cost_usd =
        finalize_supervisor_cost(usage_complete, &mut role_usage, observed_total_cost_usd);
    let bloated_file_flags = accepted_bloated_file_flags(&orchestrator_reports);
    let decomposition_candidates = accepted_decomposition_candidates(&orchestrator_reports);
    let (assignment_traceability, runtime_coverage_gaps) =
        supervisor_assignment_traceability(&plan, &plan_metadata, &orchestrator_reports);
    let mut coverage_gaps = plan_metadata.coverage_gaps.clone();
    coverage_gaps.extend(runtime_coverage_gaps);
    let final_report = SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id: options.run_id,
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: report_plan_file,
        run_dir: report_run_dir,
        runtime,
        publishable,
        success,
        accepted: publishable,
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
        role_usage,
        total_usage,
        total_cost_usd,
        usage_complete,
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
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps: coverage_gaps.clone(),
        breaker_trip: supervisor_breaker_trip,
        orchestrator_reports,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        remaining_risk: if success && !publishable {
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
                .to_string()
        } else if success && flattened_recursive_schedule && !coverage_gaps.is_empty() {
            format!(
                "flattened recursive scheduling does not enforce parent completion barriers, and {} spec-to-diff traceability coverage gap(s) remain; worker changes remain isolated in child worktrees",
                coverage_gaps.len()
            )
        } else if success && flattened_recursive_schedule {
            "recursive assignments ran through the flat O2 scheduler; parent/depth metadata does not enforce parent completion before child launch"
                .to_string()
        } else if success && !coverage_gaps.is_empty() {
            format!(
                "all child reports passed, but {} spec-to-diff traceability coverage gap(s) remain; worker changes remain isolated in child worktrees",
                coverage_gaps.len()
            )
        } else if success {
            "no failed child orchestrator reports; worker changes remain isolated in child worktrees"
                .to_string()
        } else if external_containment_failed {
            "one or more external agent process trees lacked verified-empty containment; delayed child activity cannot be ruled out"
                .to_string()
        } else if final_primary_integrity_failed {
            "primary worktree final integrity could not be established".to_string()
        } else if breaker_tripped {
            "the swarm-health circuit breaker stopped pending assignment admission after a repeated coordination failure"
                .to_string()
        } else {
            "one or more child or worker reports failed, were rejected, or were missing".to_string()
        },
        next_safe_action: if success && !publishable {
            "rerun with the trusted system Codex runtime before any real acceptance, merge, or publication"
                .to_string()
        } else if success && (flattened_recursive_schedule || !coverage_gaps.is_empty()) {
            "inspect traceability coverage_gaps and child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if success {
            "review child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if external_containment_failed {
            "do not trust or merge child outputs; restore the primary worktree if needed, fix host containment support, and rerun supervise"
                .to_string()
        } else if final_primary_integrity_failed {
            "inspect and restore the primary worktree before rerunning supervise".to_string()
        } else if breaker_tripped {
            BREAKER_RECOVERY_GUIDANCE.to_string()
        } else {
            "inspect run reports and rerun failed child scopes after correcting the issue"
                .to_string()
        },
    };
    record_orchestration_event(
        &mut orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "success": final_report.success,
            "publishable": final_report.publishable,
            "accepted": final_report.accepted,
            "rejected": final_report.rejected,
            "breaker_trip": final_report.breaker_trip,
        }),
    );
    record_orchestration_event(
        &mut orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        json!({
            "status": "final",
            "result": final_report.status,
            "success": final_report.success,
        }),
    );
    write_final_report(&mut artifact_writer, &final_report)?;
    artifact_writer.finalize(
        RunArtifactFamily::Supervise.final_report_relative_path(),
        publishable,
    )?;
    Ok(final_report)
}

fn supervisor_assignment_traceability(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
    reports: &[OrchestratorReviewReport],
) -> (Vec<AssignmentTraceability>, Vec<SupervisorCoverageGap>) {
    let fallback_schedule;
    let schedule = if metadata.assignment_schedule.is_empty() {
        fallback_schedule = plan
            .assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect::<Vec<_>>();
        &fallback_schedule
    } else {
        &metadata.assignment_schedule
    };
    let assignments = plan
        .assignments
        .iter()
        .map(|assignment| (assignment.id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    let reports = reports
        .iter()
        .map(|report| (report.id.as_str(), report))
        .collect::<BTreeMap<_, _>>();
    let mut traceability = Vec::with_capacity(schedule.len());
    let mut gaps = Vec::new();

    for schedule_entry in schedule {
        let Some(assignment) = assignments.get(schedule_entry.assignment_id.as_str()) else {
            append_assignment_coverage_gap(
                &mut gaps,
                &[],
                &schedule_entry.assignment_id,
                CoverageGapKind::MissingAssignmentReport,
                "assignment schedule references an assignment absent from the normalized plan",
            );
            continue;
        };
        let fragments = metadata
            .spec_fragment_ids_by_assignment
            .get(&assignment.id)
            .cloned()
            .unwrap_or_default();
        let report = reports.get(assignment.id.as_str()).copied();
        let produced_changed_paths = report
            .map(|report| report.files_changed.clone())
            .unwrap_or_default();
        let produced_diff_binding = report.and_then(|report| {
            report
                .decomposition_completions
                .iter()
                .find_map(|completion| completion.supervisor_candidate_binding.clone())
        });
        if report.is_none() {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::MissingAssignmentReport,
                "flattened assignment has no collected orchestrator report",
            );
        } else if produced_changed_paths.is_empty() && !fragments.is_empty() {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::NoProducedChanges,
                "assignment is mapped to a spec fragment but produced no changed paths",
            );
        } else if !produced_changed_paths.is_empty()
            && produced_diff_binding.is_none()
            && !fragments.is_empty()
        {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::MissingDiffBinding,
                "supervisor inspected changed paths but no content-addressed diff binding is available for this ordinary assignment",
            );
        }
        traceability.push(AssignmentTraceability {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: schedule_entry.parent_assignment_id.clone(),
            depth: schedule_entry.depth,
            flattened_index: schedule_entry.flattened_index,
            spec_fragment_ids: fragments,
            assigned_paths: assignment.assigned_paths.clone(),
            produced_changed_paths,
            produced_diff_binding,
            report_status: report.map(|report| report.status),
        });
    }
    (traceability, gaps)
}

fn append_assignment_coverage_gap(
    gaps: &mut Vec<SupervisorCoverageGap>,
    spec_fragment_ids: &[String],
    assignment_id: &str,
    kind: CoverageGapKind,
    message: &str,
) {
    if spec_fragment_ids.is_empty() {
        gaps.push(SupervisorCoverageGap {
            kind,
            spec_fragment_id: None,
            assignment_id: Some(assignment_id.to_string()),
            message: message.to_string(),
        });
        return;
    }
    gaps.extend(
        spec_fragment_ids
            .iter()
            .map(|spec_fragment_id| SupervisorCoverageGap {
                kind,
                spec_fragment_id: Some(spec_fragment_id.clone()),
                assignment_id: Some(assignment_id.to_string()),
                message: message.to_string(),
            }),
    );
}

#[cfg(test)]
fn validate_legacy_supervisor_plan(plan: SupervisorPlan) -> Result<SupervisorPlan> {
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: plan
            .assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.trim().to_string(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect(),
        ..SupervisorPlanMetadata::default()
    };
    validate_supervisor_plan(plan, metadata).map(|(plan, _)| plan)
}

fn validate_supervisor_plan(
    mut plan: SupervisorPlan,
    mut metadata: SupervisorPlanMetadata,
) -> Result<(SupervisorPlan, SupervisorPlanMetadata)> {
    if plan.version != SUPERVISOR_SCHEMA_VERSION {
        bail!("unsupported supervisor plan version {}", plan.version);
    }
    if !(MIN_SUPERVISOR_DEPTH..=MAX_SUPERVISOR_DEPTH).contains(&plan.max_depth) {
        bail!(
            "supervisor max_depth must be between {} and {}",
            MIN_SUPERVISOR_DEPTH,
            MAX_SUPERVISOR_DEPTH
        );
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
    for (role, selection) in &mut plan.role_models {
        selection.model = normalize_optional_model_field(
            selection.model.take(),
            &format!("role_models.{}.model", role.as_str()),
        )?;
        selection.reasoning_effort = normalize_optional_model_field(
            selection.reasoning_effort.take(),
            &format!("role_models.{}.reasoning_effort", role.as_str()),
        )?;
    }
    let mut normalized_pricing = BTreeMap::new();
    for (model, pricing) in std::mem::take(&mut plan.model_pricing) {
        let normalized_model = model.trim();
        if normalized_model.is_empty() {
            bail!("model_pricing model key cannot be empty");
        }
        if !pricing.is_valid() {
            bail!(
                "model_pricing for '{}' must contain finite, non-negative input and output prices",
                normalized_model
            );
        }
        if normalized_pricing
            .insert(normalized_model.to_string(), pricing)
            .is_some()
        {
            bail!(
                "model_pricing contains duplicate model '{}' after trimming",
                normalized_model
            );
        }
    }
    plan.model_pricing = normalized_pricing;

    if plan.assignments.len() > plan.max_child_assignments {
        bail!(
            "supervisor plan has {} flattened child orchestrators but max_child_assignments is {}",
            plan.assignments.len(),
            plan.max_child_assignments
        );
    }
    if metadata.assignment_schedule.len() != plan.assignments.len() {
        bail!("assignment schedule does not cover every flattened assignment");
    }
    let mut seen = BTreeSet::new();
    for (index, assignment) in plan.assignments.iter_mut().enumerate() {
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
        assignment.semantic_symbols = normalize_semantic_symbols(&assignment.semantic_symbols);
        assignment.semantic_modules = normalize_semantic_modules(&assignment.semantic_modules);
        validate_worker_assignments(assignment)?;

        let schedule = &mut metadata.assignment_schedule[index];
        schedule.assignment_id = assignment.id.clone();
        schedule.flattened_index = index;
        if !(MIN_SUPERVISOR_DEPTH..=plan.max_depth).contains(&schedule.depth) {
            bail!(
                "assignment '{}' has schedule depth {} outside configured range {}..={}",
                assignment.id,
                schedule.depth,
                MIN_SUPERVISOR_DEPTH,
                plan.max_depth
            );
        }
    }
    validate_orchestrator_assignment_collisions(&plan.assignments)?;

    metadata.spec_fragment_ids =
        normalize_spec_fragment_ids(std::mem::take(&mut metadata.spec_fragment_ids))?;
    for assignment in &plan.assignments {
        let fragments = metadata
            .spec_fragment_ids_by_assignment
            .remove(&assignment.id)
            .unwrap_or_default();
        metadata.spec_fragment_ids_by_assignment.insert(
            assignment.id.clone(),
            normalize_spec_fragment_ids(fragments).with_context(|| {
                format!("assignment '{}' has invalid spec fragments", assignment.id)
            })?,
        );
    }
    let referenced_fragments = metadata
        .spec_fragment_ids_by_assignment
        .values()
        .flat_map(|fragments| fragments.iter().cloned())
        .collect::<BTreeSet<_>>();
    if metadata.spec_fragment_ids.is_empty() {
        metadata.spec_fragment_ids = referenced_fragments.iter().cloned().collect();
    } else if let Some(unknown) = referenced_fragments
        .iter()
        .find(|fragment| !metadata.spec_fragment_ids.contains(fragment))
    {
        bail!(
            "assignment references undeclared spec fragment '{}'",
            unknown
        );
    }
    metadata.coverage_gaps = metadata
        .spec_fragment_ids
        .iter()
        .filter(|fragment| !referenced_fragments.contains(*fragment))
        .map(|fragment| SupervisorCoverageGap {
            kind: CoverageGapKind::UnassignedSpecFragment,
            spec_fragment_id: Some(fragment.clone()),
            assignment_id: None,
            message: format!("spec fragment '{fragment}' is not mapped to an assignment"),
        })
        .collect();

    Ok((plan, metadata))
}

fn validate_orchestrator_assignment_collisions(
    assignments: &[OrchestratorAssignment],
) -> Result<()> {
    for (left_index, left) in assignments.iter().enumerate() {
        for right in assignments.iter().skip(left_index.saturating_add(1)) {
            if let Some((left_path, right_path)) =
                left.assigned_paths.iter().find_map(|left_path| {
                    right
                        .assigned_paths
                        .iter()
                        .find(|right_path| paths_overlap(left_path, right_path))
                        .map(|right_path| (left_path, right_path))
                })
            {
                bail!(
                    "assignments '{}' path '{}' and '{}' path '{}' overlap after normalization",
                    left.id,
                    left_path.display(),
                    right.id,
                    right_path.display()
                );
            }
            validate_cross_assignment_semantic_collisions(left, right)?;
        }
    }
    Ok(())
}

fn validate_cross_assignment_semantic_collisions(
    left: &OrchestratorAssignment,
    right: &OrchestratorAssignment,
) -> Result<()> {
    let left_scopes = assignment_semantic_scopes(left);
    let right_scopes = assignment_semantic_scopes(right);
    for left_scope in &left_scopes {
        for right_scope in &right_scopes {
            if let Some(symbol) =
                first_shared_string(left_scope.semantic_symbols, right_scope.semantic_symbols)
            {
                bail!(
                    "{} and {} overlap semantic symbol '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    symbol
                );
            }
            if let Some(module) =
                first_shared_string(left_scope.semantic_modules, right_scope.semantic_modules)
            {
                bail!(
                    "{} and {} overlap semantic module '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    module
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct AssignmentSemanticScope<'a> {
    label: String,
    semantic_symbols: &'a [String],
    semantic_modules: &'a [String],
}

fn assignment_semantic_scopes(
    assignment: &OrchestratorAssignment,
) -> Vec<AssignmentSemanticScope<'_>> {
    let mut scopes = Vec::with_capacity(assignment.worker_assignments.len().saturating_add(1));
    scopes.push(AssignmentSemanticScope {
        label: format!("assignment '{}'", assignment.id),
        semantic_symbols: &assignment.semantic_symbols,
        semantic_modules: &assignment.semantic_modules,
    });
    scopes.extend(
        assignment
            .worker_assignments
            .iter()
            .map(|worker| AssignmentSemanticScope {
                label: format!(
                    "worker '{}' under assignment '{}'",
                    worker.id, assignment.id
                ),
                semantic_symbols: &worker.semantic_symbols,
                semantic_modules: &worker.semantic_modules,
            }),
    );
    scopes
}

fn first_shared_string<'a>(left: &'a [String], right: &[String]) -> Option<&'a str> {
    left.iter()
        .find(|value| right.binary_search(value).is_ok())
        .map(String::as_str)
}

fn normalize_optional_model_field(value: Option<String>, field: &str) -> Result<Option<String>> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                bail!("{field} cannot be empty when present");
            }
            Ok(value.to_string())
        })
        .transpose()
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
        worker.semantic_symbols = normalize_semantic_symbols(&worker.semantic_symbols);
        worker.semantic_modules = normalize_semantic_modules(&worker.semantic_modules);
    }
    for (left_index, left) in assignment.worker_assignments.iter().enumerate() {
        for right in assignment
            .worker_assignments
            .iter()
            .skip(left_index.saturating_add(1))
        {
            if let Some(symbol) =
                first_shared_string(&left.semantic_symbols, &right.semantic_symbols)
            {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic symbol '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    symbol
                );
            }
            if let Some(module) =
                first_shared_string(&left.semantic_modules, &right.semantic_modules)
            {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic module '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    module
                );
            }
        }
    }
    Ok(())
}

enum SemanticAssignmentCoordination {
    Ready(Option<u64>),
    Blocked(usize),
}

fn coordinate_semantic_assignment(
    store: &SemanticIntentStore,
    assignment: &OrchestratorAssignment,
    mode: SemanticCoordinationMode,
    acquired_tokens: &mut Vec<crate::semantic_coord::SemanticIntentToken>,
    planned_preview_intents: &mut Vec<SemanticIntent>,
    findings: &mut Vec<Finding>,
    health_signals: &mut Vec<SwarmHealthSignal>,
) -> Result<SemanticAssignmentCoordination> {
    if mode == SemanticCoordinationMode::Off {
        return Ok(SemanticAssignmentCoordination::Ready(None));
    }
    let request = semantic_assignment_request(assignment);
    let report = match mode {
        SemanticCoordinationMode::Off => {
            return Ok(SemanticAssignmentCoordination::Ready(None));
        }
        SemanticCoordinationMode::Warn => {
            store.preview_with_additional_active(request, planned_preview_intents)?
        }
        SemanticCoordinationMode::Block => store.claim(request)?,
    };
    if mode == SemanticCoordinationMode::Warn {
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            let conflict_count = report
                .blocking_conflict_count
                .saturating_add(report.advisory_conflict_count);
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    conflict_count
                ),
                paths: assignment.assigned_paths.clone(),
            });
            health_signals.push(SwarmHealthSignal::SemanticConflictWarned {
                conflicts: conflict_count,
            });
        }
        planned_preview_intents.push(report.intent.clone());
    }
    if mode == SemanticCoordinationMode::Block && report.has_blocking_conflicts {
        health_signals.push(SwarmHealthSignal::SemanticConflictBlocked {
            conflicts: report.blocking_conflict_count,
        });
        return Ok(SemanticAssignmentCoordination::Blocked(
            report.blocking_conflict_count,
        ));
    }
    if mode == SemanticCoordinationMode::Block && report.persisted {
        acquired_tokens.push(report.intent.token);
    }
    Ok(SemanticAssignmentCoordination::Ready(Some(
        report.intent.token.get(),
    )))
}

fn semantic_assignment_request(assignment: &OrchestratorAssignment) -> SemanticIntentRequest {
    SemanticIntentRequest {
        agent_id: assignment.id.clone(),
        paths: assignment.assigned_paths.clone(),
        symbols: assignment.semantic_symbols.clone(),
        modules: assignment.semantic_modules.clone(),
        task_file: None,
        notes: vec!["supervise child orchestrator assignment".to_string()],
    }
}

struct ChildReportCollectionContext<'a> {
    assignment: &'a OrchestratorAssignment,
    assignment_metadata: &'a AssignmentMetadata,
    report_path: &'a Path,
    external_run: &'a ExternalAgentRun,
    external_command: &'a ExternalAgentCommand,
    worktree_path: &'a Path,
    child_base_head: &'a Oid,
    worker_journals: &'a WorkerExecutionJournalEvidenceSet,
}

fn collect_child_report(
    context: ChildReportCollectionContext<'_>,
) -> (OrchestratorReviewReport, Vec<String>) {
    let ChildReportCollectionContext {
        assignment,
        assignment_metadata,
        report_path,
        external_run,
        external_command,
        worktree_path,
        child_base_head,
        worker_journals,
    } = context;
    let mut report_shape_problems = Vec::new();
    let mut report = match read_child_report(external_run.output_last_message(), report_path) {
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
            if !external_process_completed(external_run) && report.status == ReviewStatus::Succeeded
            {
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
            missing_child_report(
                assignment,
                report_path,
                external_run,
                external_command,
                error.to_string(),
            )
        }
    };
    validate_worker_report_delegation_attestations(assignment, report_path, &mut report);
    verify_child_report_paths(assignment, worktree_path, child_base_head, &mut report);
    validate_worker_report_evidence(assignment, assignment_metadata, report_path, &mut report);
    validate_assignment_report_plumbing(assignment, assignment_metadata, report_path, &mut report);
    validate_worker_execution_journal_evidence(
        assignment,
        report_path,
        worker_journals,
        &mut report,
    );
    (report, report_shape_problems)
}

fn collect_parent_auditor_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    external_command: &ExternalAgentCommand,
) -> AuditorReport {
    let expected_id = parent_auditor_id(assignment);
    let mut report = match read_auditor_report(external_run.output_last_message(), report_path) {
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
            if !external_process_completed(external_run) && report.status == ReviewStatus::Succeeded
            {
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
        .push(command_record_from_external(external_run, external_command));
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
            let coverage = auditor_review_path_coverage(audit_report, &required_reviewed_paths);
            if !coverage.excluded_paths.is_empty() {
                audit_report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "auditor reviewed_paths entries were retained as evidence but excluded from repository-relative coverage computation: {}",
                        display_paths(&coverage.excluded_paths)
                    ),
                    paths: coverage.excluded_paths,
                });
            }
            if !coverage.missing_paths.is_empty() {
                valid = false;
                messages.push(format!(
                    "parent auditor reviewed_paths omitted required assignment/change path coverage for: {}",
                    display_paths(&coverage.missing_paths)
                ));
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupervisorCandidateInspection {
    binding: CandidateValidationBinding,
    changed_paths: Vec<PathBuf>,
}

fn inspect_supervisor_decomposition_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    worktree_write_lease: &ManagedWorktreeWriteLease,
) -> Result<SupervisorCandidateInspection> {
    let candidate = collect_agent_result_with_evidence_and_write_lease(
        MergeCollectOptions {
            repo: repo.to_path_buf(),
            agent_id: assignment.id.clone(),
            claimed_paths: assignment.assigned_paths.clone(),
            include_full_diff: false,
            diff_summary_char_limit: 1,
            validations: Vec::new(),
        },
        ValidationEvidenceBundle::default(),
        worktree_write_lease,
    )
    .context("failed to capture supervisor-inspected decomposition candidate")?;
    Ok(SupervisorCandidateInspection {
        binding: candidate.validation_binding,
        changed_paths: normalize_paths(candidate.changed_paths)
            .context("supervisor-inspected decomposition candidate paths are invalid")?,
    })
}

fn bind_supervisor_decomposition_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    report: &mut OrchestratorReviewReport,
    worktree_write_lease: &ManagedWorktreeWriteLease,
) -> Result<Option<SupervisorCandidateInspection>> {
    if report_failed(report) || report.decomposition_completions.is_empty() {
        return Ok(None);
    }
    if report
        .decomposition_completions
        .iter()
        .any(|completion| completion.supervisor_candidate_binding.is_some())
        || report.worker_reports.iter().any(|worker| {
            worker
                .decomposition_completion
                .as_ref()
                .is_some_and(|completion| completion.supervisor_candidate_binding.is_some())
        })
    {
        bail!(
            "incoming worker or child decomposition evidence self-asserted supervisor_candidate_binding"
        );
    }

    let inspection =
        inspect_supervisor_decomposition_candidate(repo, assignment, worktree_write_lease)?;
    let report_paths =
        normalize_paths(report.files_changed.clone()).context("child files_changed invalid")?;
    if inspection.changed_paths != report_paths {
        bail!(
            "supervisor-inspected decomposition candidate paths changed after child report validation"
        );
    }

    for worker in &mut report.worker_reports {
        if report_failed(worker) {
            continue;
        }
        if let Some(completion) = &mut worker.decomposition_completion {
            completion.supervisor_candidate_binding = Some(inspection.binding.clone());
        }
    }
    for completion in &mut report.decomposition_completions {
        completion.supervisor_candidate_binding = Some(inspection.binding.clone());
    }
    Ok(Some(inspection))
}

fn reject_supervisor_decomposition_binding(
    report: &mut OrchestratorReviewReport,
    report_path: &Path,
    error: &anyhow::Error,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor could not bind the exact decomposition candidate reviewed by the parent auditor: {error:#}"
        ),
        paths: vec![report_path.to_path_buf()],
    });
    report.remaining_risk =
        "the finalized evidence does not bind the exact reviewed candidate content".to_string();
    report.next_safe_action =
        "rerun the child scope and parent auditor against one stable candidate snapshot"
            .to_string();
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

struct AuditorReviewPathCoverage {
    missing_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
}

fn auditor_review_path_coverage(
    audit_report: &AuditorReport,
    required_paths: &[PathBuf],
) -> AuditorReviewPathCoverage {
    let mut normalized_paths = BTreeSet::new();
    let mut excluded_paths = Vec::new();
    for path in &audit_report.reviewed_paths {
        match normalize_repo_relative_path(path) {
            Ok(path) => {
                normalized_paths.insert(path);
            }
            Err(_) => excluded_paths.push(path.clone()),
        }
    }
    let reviewed_paths = collapse_covered_paths(normalized_paths);
    let missing_paths = required_paths
        .iter()
        .filter(|required| {
            !reviewed_paths
                .iter()
                .any(|reviewed| path_is_covered_by_claim(required, reviewed))
        })
        .cloned()
        .collect();
    AuditorReviewPathCoverage {
        missing_paths,
        excluded_paths,
    }
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

fn validate_assignment_report_plumbing(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let result = (|| -> Result<()> {
        if report.decomposition_completions.len() > assignment.worker_assignments.len() {
            bail!("decomposition_completions exceeds the worker assignment count");
        }
        let mut normalized = BTreeSet::new();
        for completion in std::mem::take(&mut report.decomposition_completions) {
            normalized.insert(normalize_unbound_decomposition_completion(completion)?);
        }
        let expected = report
            .worker_reports
            .iter()
            .filter(|worker_report| !report_failed(*worker_report))
            .filter_map(|worker_report| worker_report.decomposition_completion.clone())
            .collect::<BTreeSet<_>>();
        let successful =
            report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded;
        if !successful && !normalized.is_empty() {
            bail!(
                "decomposition_completions cannot claim success on an unaccepted or unsuccessful child report"
            );
        }
        if successful && normalized != expected {
            bail!("decomposition_completions does not match accepted successful worker evidence");
        }
        for completion in &normalized {
            if !assignment.worker_assignments.iter().any(|worker| {
                let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
                metadata.kind == AssignmentKind::MegafileDecomposition
                    && metadata.target_path.as_ref() == Some(&completion.target_path)
            }) {
                bail!(
                    "decomposition completion target_path '{}' is not declared by a worker assignment",
                    completion.target_path.display()
                );
            }
        }
        report.decomposition_completions = normalized.into_iter().collect();
        Ok(())
    })();

    if let Err(error) = result {
        report.decomposition_completions.clear();
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' has invalid assignment/decomposition report plumbing: {error}",
                report.id
            ),
            paths: vec![report_path.to_path_buf()],
        });
        report.remaining_risk =
            "typed assignment or decomposition completion evidence is invalid".to_string();
        report.next_safe_action =
            "rerun the child scope with report fields matching the normalized assignment"
                .to_string();
    }
}

fn normalize_worker_report_plumbing(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    workers_by_id: &BTreeMap<&str, &WorkerAssignment>,
    report: &mut WorkerReport,
) -> Result<()> {
    let worker = workers_by_id
        .get(report.id.as_str())
        .context("worker is not declared in the assignment")?;
    let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
    if report.assignment_kind != metadata.kind {
        bail!(
            "assignment_kind '{}' does not match planned kind '{}'",
            report.assignment_kind.as_str(),
            metadata.kind.as_str()
        );
    }
    report.target_path = normalize_report_target_path(report.target_path.take(), "target_path")?;
    if report.target_path != metadata.target_path {
        bail!(
            "target_path '{}' does not match planned target_path '{}'",
            display_optional_path(report.target_path.as_deref()),
            display_optional_path(metadata.target_path.as_deref())
        );
    }

    match metadata.kind {
        AssignmentKind::Ordinary => {
            if report.decomposition_completion.is_some() {
                bail!("ordinary assignment must not report decomposition_completion");
            }
        }
        AssignmentKind::MegafileDecomposition => {
            let target_path = metadata
                .target_path
                .as_deref()
                .context("validated megafile decomposition assignment has no target_path")?;
            let completion = report
                .decomposition_completion
                .take()
                .map(normalize_unbound_decomposition_completion)
                .transpose()?;
            let successful =
                report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded;
            if successful && completion.is_none() {
                bail!(
                    "accepted successful megafile_decomposition worker omitted decomposition_completion"
                );
            }
            if completion.is_some() && !successful {
                bail!("decomposition_completion requires an accepted successful worker");
            }
            if completion.as_ref().map(|value| value.target_path.as_path()) != Some(target_path)
                && completion.is_some()
            {
                bail!("decomposition_completion target_path does not match the assignment");
            }
            if let Some(completion) = &completion {
                let files_changed = normalize_paths(report.files_changed.clone())
                    .context("megafile_decomposition worker files_changed is invalid")?;
                if !files_changed.iter().any(|path| path == target_path) {
                    bail!(
                        "accepted megafile_decomposition worker files_changed omits the exact target"
                    );
                }
                for replacement in &completion.replacement_paths {
                    if !files_changed.contains(replacement) {
                        bail!(
                            "decomposition replacement path '{}' is not reported in files_changed",
                            replacement.display()
                        );
                    }
                    if !worker
                        .assigned_paths
                        .iter()
                        .any(|assigned| path_is_covered_by_claim(replacement, assigned))
                    {
                        bail!(
                            "decomposition replacement path '{}' is outside assigned_paths",
                            replacement.display()
                        );
                    }
                }
            }
            report.decomposition_completion = completion;
        }
    }
    Ok(())
}

fn normalize_bloated_file_flags(
    report: &mut WorkerReport,
    workers_by_id: &BTreeMap<&str, &WorkerAssignment>,
) -> Result<()> {
    if report.bloated_file_flags.len() > MAX_BLOATED_FILE_FLAGS_PER_WORKER {
        bail!(
            "contains {} flags but at most {} are allowed",
            report.bloated_file_flags.len(),
            MAX_BLOATED_FILE_FLAGS_PER_WORKER
        );
    }
    let worker = workers_by_id
        .get(report.id.as_str())
        .context("worker is not declared in the assignment")?;
    let mut normalized = BTreeSet::new();
    for flag in std::mem::take(&mut report.bloated_file_flags) {
        let path = normalize_repo_relative_path(&flag.path)
            .with_context(|| format!("invalid path '{}'", flag.path.display()))?;
        if path.as_os_str().is_empty() {
            bail!("flag path must name a repository file");
        }
        if !worker
            .assigned_paths
            .iter()
            .any(|assigned| path_is_covered_by_claim(&path, assigned))
        {
            bail!("flag path '{}' is outside assigned_paths", path.display());
        }
        normalized.insert(BloatedFileFlag { path });
    }
    report.bloated_file_flags = normalized.into_iter().collect();
    Ok(())
}

fn normalize_report_target_path(value: Option<PathBuf>, field: &str) -> Result<Option<PathBuf>> {
    value
        .map(|path| {
            let normalized = normalize_repo_relative_path(&path)
                .with_context(|| format!("{field} '{}' is invalid", path.display()))?;
            if normalized.as_os_str().is_empty() {
                bail!("{field} must name a repository file");
            }
            Ok(normalized)
        })
        .transpose()
}

fn normalize_decomposition_completion(
    mut completion: DecompositionCompletion,
) -> Result<DecompositionCompletion> {
    completion.target_path = normalize_report_target_path(
        Some(completion.target_path),
        "decomposition_completion.target_path",
    )?
    .context("decomposition_completion.target_path is required")?;
    if completion.replacement_paths.len() > MAX_DECOMPOSITION_REPLACEMENT_PATHS {
        bail!(
            "decomposition_completion contains {} replacement paths but at most {} are allowed",
            completion.replacement_paths.len(),
            MAX_DECOMPOSITION_REPLACEMENT_PATHS
        );
    }
    completion.replacement_paths = normalize_paths(completion.replacement_paths)
        .context("decomposition_completion.replacement_paths is invalid")?;
    if completion.replacement_paths.is_empty() {
        bail!("decomposition_completion requires at least one replacement path");
    }
    if completion
        .replacement_paths
        .contains(&completion.target_path)
    {
        bail!("decomposition_completion replacement_paths must not include target_path");
    }
    completion.supervisor_candidate_binding = completion
        .supervisor_candidate_binding
        .map(CandidateValidationBinding::canonicalized)
        .transpose()
        .context("decomposition_completion supervisor candidate binding is invalid")?;
    Ok(completion)
}

fn normalize_unbound_decomposition_completion(
    completion: DecompositionCompletion,
) -> Result<DecompositionCompletion> {
    if completion.supervisor_candidate_binding.is_some() {
        bail!(
            "incoming worker or child decomposition evidence must not self-assert supervisor_candidate_binding"
        );
    }
    normalize_decomposition_completion(completion)
}

fn display_optional_path(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn worker_assignment_metadata(
    assignment_metadata: &AssignmentMetadata,
    assignment: &OrchestratorAssignment,
    worker: &WorkerAssignment,
) -> WorkerAssignmentMetadata {
    assignment_metadata
        .get(&(assignment.id.clone(), worker.id.clone()))
        .cloned()
        .unwrap_or_default()
}

fn worker_assignment_value(
    worker: &WorkerAssignment,
    metadata: &WorkerAssignmentMetadata,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(worker).context("failed to serialize worker assignment fields")?;
    let object = value
        .as_object_mut()
        .context("worker assignment did not serialize to an object")?;
    let metadata_value = serde_json::to_value(metadata)
        .context("failed to serialize worker assignment kind/target_path")?;
    let metadata_object = metadata_value
        .as_object()
        .context("worker assignment metadata did not serialize to an object")?;
    object.extend(metadata_object.clone());
    Ok(value)
}

fn orchestrator_assignment_value(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> Result<Value> {
    let mut value = serde_json::to_value(assignment)
        .context("failed to serialize orchestrator assignment fields")?;
    let workers = value
        .get_mut("worker_assignments")
        .and_then(Value::as_array_mut)
        .context("worker_assignments did not serialize to an array")?;
    for (worker_value, worker) in workers.iter_mut().zip(&assignment.worker_assignments) {
        let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
        *worker_value = worker_assignment_value(worker, &metadata)?;
    }
    Ok(value)
}

fn display_decomposition_targets(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> String {
    let targets = assignment
        .worker_assignments
        .iter()
        .filter_map(|worker| {
            worker_assignment_metadata(assignment_metadata, assignment, worker)
                .target_path
                .map(|path| format!("{}={}", worker.id, path.display()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        "<none>".to_string()
    } else {
        targets.join(", ")
    }
}

fn validate_worker_report_evidence(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
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
        if let Err(error) = normalize_worker_report_plumbing(
            assignment,
            assignment_metadata,
            &workers_by_id,
            worker_report,
        ) {
            let message = format!(
                "worker '{}' has invalid assignment/decomposition report plumbing: {error}",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
        }
        if let Err(error) = normalize_bloated_file_flags(worker_report, &workers_by_id) {
            let message = format!(
                "worker '{}' has invalid bloated_file_flags: {error}",
                worker_report.id
            );
            worker_report.bloated_file_flags.clear();
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
        }
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
        let message = format!(
            "worker files_changed union differs from actual child worktree Git changes; reported-but-not-observed: {}; observed-but-not-reported: {}",
            display_paths(&reported_but_not_observed),
            display_paths(&observed_but_not_reported)
        );
        blocking_messages.push((message, paths));
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

fn validate_worker_execution_journal_evidence(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    journals: &WorkerExecutionJournalEvidenceSet,
    report: &mut OrchestratorReviewReport,
) {
    if assignment.worker_assignments.is_empty() || report.worker_reports.is_empty() {
        return;
    }

    let workers_by_id = assignment
        .worker_assignments
        .iter()
        .map(|worker| (worker.id.as_str(), worker))
        .collect::<BTreeMap<_, _>>();
    let actual_set = report
        .files_changed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut blocking_messages = Vec::new();

    for worker_report in &mut report.worker_reports {
        let Some(worker_assignment) = workers_by_id.get(worker_report.id.as_str()) else {
            continue;
        };
        let Some(journal) = journals.get(&worker_report.id) else {
            let message = format!(
                "worker '{}' execution journal evidence was not imported by the supervisor gate",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
            continue;
        };

        let entries = match &journal.status {
            WorkerExecutionJournalStatus::Loaded(entries) => entries,
            WorkerExecutionJournalStatus::Missing => {
                let message = format!(
                    "worker '{}' execution journal is missing; expected {} imported as {}",
                    worker_report.id,
                    journal.incoming_relative_path.display(),
                    journal.evidence_relative_path.display()
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![journal.evidence_relative_path.clone()],
                );
                blocking_messages.push((message, vec![journal.evidence_relative_path.clone()]));
                continue;
            }
            WorkerExecutionJournalStatus::Invalid(error) => {
                let message = format!(
                    "worker '{}' execution journal {} is invalid: {}",
                    worker_report.id,
                    journal.evidence_relative_path.display(),
                    error
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![journal.evidence_relative_path.clone()],
                );
                blocking_messages.push((message, vec![journal.evidence_relative_path.clone()]));
                continue;
            }
        };

        let mut journal_paths = BTreeSet::<PathBuf>::new();
        let mut journal_unauthorized_paths = BTreeSet::<PathBuf>::new();
        for entry in entries {
            for path in &entry.changed_paths {
                journal_paths.insert(path.clone());
                if !worker_assignment
                    .assigned_paths
                    .iter()
                    .any(|assigned| path_is_covered_by_claim(path, assigned))
                {
                    journal_unauthorized_paths.insert(path.clone());
                }
            }
        }

        if !journal_unauthorized_paths.is_empty() {
            let paths = journal_unauthorized_paths.into_iter().collect::<Vec<_>>();
            let message = format!(
                "worker '{}' execution journal {} changed paths outside assigned_paths: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&paths)
            );
            let finding_paths = union_paths(
                &paths,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let journal_without_git = journal_paths
            .difference(&actual_set)
            .cloned()
            .collect::<Vec<_>>();
        if !journal_without_git.is_empty() {
            let message = format!(
                "worker '{}' execution journal {} changed paths are not supported by supervisor-inspected Git diff: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&journal_without_git)
            );
            let finding_paths = union_paths(
                &journal_without_git,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let journal_commands = entries
            .iter()
            .map(|entry| (entry.command.clone(), entry.cwd.clone()))
            .collect::<BTreeSet<_>>();
        let reported_commands_without_journal = worker_report
            .commands_run
            .iter()
            .filter(|record| {
                !journal_commands.contains(&(record.command.clone(), record.cwd.clone()))
            })
            .map(|record| (record.command.clone(), record.cwd.clone()))
            .collect::<Vec<_>>();
        if !reported_commands_without_journal.is_empty() {
            let message = format!(
                "worker '{}' commands_run entries are not supported by execution journal {}: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_command_identities(&reported_commands_without_journal)
            );
            let paths = vec![
                report_path.to_path_buf(),
                journal.evidence_relative_path.clone(),
            ];
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                paths.clone(),
            );
            blocking_messages.push((message, paths));
        }

        let reported_paths = worker_report
            .files_changed
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let report_without_journal = reported_paths
            .difference(&journal_paths)
            .cloned()
            .collect::<Vec<_>>();
        if !report_without_journal.is_empty() {
            let message = format!(
                "worker '{}' files_changed paths are not supported by execution journal {}: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&report_without_journal)
            );
            let finding_paths = union_paths(
                &report_without_journal,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let report_without_git = reported_paths
            .difference(&actual_set)
            .cloned()
            .collect::<Vec<_>>();
        if !report_without_git.is_empty() {
            let message = format!(
                "worker '{}' files_changed paths are not supported by supervisor-inspected Git diff: {}",
                worker_report.id,
                display_paths(&report_without_git)
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                report_without_git.clone(),
            );
            blocking_messages.push((message, report_without_git));
        }
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
        "one or more worker execution journals are missing, invalid, or inconsistent with reported evidence".to_string();
    report.next_safe_action =
        "inspect worker execution journals and rerun the child scope with corrected process evidence"
            .to_string();
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

fn mark_child_containment_violation(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    process_tree: Option<ProcessTreeEvidence>,
    side_effects: Option<SideEffectConfinementEvidence>,
    report: &mut OrchestratorReviewReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "child orchestrator '{}' process safety was not verified; process_tree={process_tree:?}; side_effects={side_effects:?}",
            assignment.id,
        ),
        paths: vec![report_path.to_path_buf()],
    });
    report.remaining_risk =
        "the child process tree may still be live, so no retry or parent auditor was launched"
            .to_string();
    report.next_safe_action =
        "restore the primary worktree if needed, fix host containment support, and rerun this child scope"
            .to_string();
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

fn mark_auditor_primary_integrity_violation(
    assignment: &OrchestratorAssignment,
    changes: &PrimaryIntegrityChanges,
    report: &mut AuditorReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.read_only = false;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "primary worktree integrity changed during parent review auditor '{}' run: {}",
            parent_auditor_id(assignment),
            changes.details.join("; ")
        ),
        paths: changes.paths.clone(),
    });
    report.remaining_risk =
        "parent auditor invocation mutated primary HEAD/ref, index, tracked content, or non-runtime untracked content"
            .to_string();
    report.next_safe_action =
        "inspect and restore the primary worktree before rerunning supervise".to_string();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryWorktreeSnapshot {
    head: PrimaryHeadSnapshot,
    index: BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
    index_storage: PrimaryIndexStorageSnapshot,
    status: BTreeMap<Vec<u8>, PrimaryStatusState>,
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
    tag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryStatusState {
    code: [u8; 2],
    original_path: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIndexStorageSnapshot {
    worktree_index: IndexFileSnapshot,
    shared_index: Option<SharedIndexFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedIndexFileSnapshot {
    path: PathBuf,
    storage: IndexFileSnapshot,
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
        contents_digest: Option<Oid>,
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

fn primary_worktree_snapshot(
    repo_path: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryWorktreeSnapshot> {
    let mut visited_gitdirs = BTreeSet::new();
    primary_worktree_snapshot_at_depth(repo_path, 0, &mut visited_gitdirs, runtime)
}

fn primary_worktree_snapshot_at_depth(
    repo_path: &Path,
    depth: usize,
    visited_gitdirs: &mut BTreeSet<PathBuf>,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryWorktreeSnapshot> {
    if depth > MAX_NESTED_REPOSITORY_DEPTH {
        bail!(
            "primary integrity snapshot exceeded the nested-repository safety limit of {} at {}",
            MAX_NESTED_REPOSITORY_DEPTH,
            repo_path.display()
        );
    }
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let gitdir_identity = fs::canonicalize(repo.path()).with_context(|| {
        format!(
            "failed to resolve canonical Git directory identity {}",
            repo.path().display()
        )
    })?;
    if !visited_gitdirs.insert(gitdir_identity.clone()) {
        bail!(
            "primary integrity snapshot detected a nested repository cycle at {} (Git directory {})",
            repo_path.display(),
            gitdir_identity.display()
        );
    }

    let result = (|| {
        let workdir = repo
            .workdir()
            .context("primary integrity snapshot requires a non-bare repository")?
            .to_path_buf();
        let head = primary_head_snapshot(&repo)?;
        let index_storage_before = primary_index_storage_snapshot(&repo, runtime)?;
        let status = primary_status_snapshot(&workdir, runtime)?;
        let index = primary_index_snapshot(&workdir, runtime)?;
        let index_storage = primary_index_storage_snapshot(&repo, runtime)?;
        let inspection_error = (index_storage_before != index_storage).then(|| {
            "primary index storage changed while the Git CLI integrity snapshot was being captured"
                .to_string()
        });

        let gitlink_paths = index
            .iter()
            .filter(|(_, state)| state.mode == GITLINK_MODE)
            .map(|(key, _)| key.path.clone())
            .collect::<BTreeSet<_>>();
        let sparse_directory_paths = index
            .iter()
            .filter(|(_, state)| state.mode == SPARSE_DIRECTORY_MODE)
            .map(|(key, _)| key.path.clone())
            .collect::<BTreeSet<_>>();
        let mut fingerprint_paths = status.keys().cloned().collect::<BTreeSet<_>>();
        fingerprint_paths.extend(
            status
                .values()
                .filter_map(|state| state.original_path.clone()),
        );
        fingerprint_paths.extend(gitlink_paths.iter().cloned());
        fingerprint_paths.extend(sparse_directory_paths.iter().cloned());
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
                sparse_directory_paths.contains(&path),
                depth,
                visited_gitdirs,
                runtime,
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
    })();
    visited_gitdirs.remove(&gitdir_identity);
    result
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

fn primary_status_snapshot(
    workdir: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<BTreeMap<Vec<u8>, PrimaryStatusState>> {
    let output = sanitized_git_output(
        workdir,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        runtime,
    )
    .context("failed to run Git CLI primary status snapshot")?;
    if !output.status.success() {
        bail!(
            "Git CLI primary status snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let records = output.stdout.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut entries = BTreeMap::new();
    let mut index = 0usize;
    while index < records.len() {
        let record = records[index];
        index = index.saturating_add(1);
        if record.is_empty() {
            continue;
        }
        if record.len() < 4 || record[2] != b' ' {
            bail!("Git CLI primary status returned a malformed porcelain record");
        }
        let code = [record[0], record[1]];
        let path = record[3..].to_vec();
        let renamed_or_copied = code.iter().any(|status| matches!(status, b'R' | b'C'));
        let original_path = if renamed_or_copied {
            let original = records
                .get(index)
                .filter(|path| !path.is_empty())
                .context("Git CLI primary status omitted a rename/copy source path")?;
            index = index.saturating_add(1);
            Some((*original).to_vec())
        } else {
            None
        };
        if code == *b"??" && is_untracked_runtime_artifact_bytes(&path) {
            continue;
        }
        entries.insert(
            path,
            PrimaryStatusState {
                code,
                original_path,
            },
        );
    }
    Ok(entries)
}

fn primary_index_snapshot(
    workdir: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>> {
    let output = sanitized_git_output(
        workdir,
        &["ls-files", "--stage", "-v", "-z", "--sparse"],
        runtime,
    )
    .context("failed to run Git CLI primary index snapshot")?;
    if !output.status.success() {
        bail!(
            "Git CLI primary index snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut entries = BTreeMap::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("Git CLI primary index returned a malformed entry without a path")?;
        let (header, path_with_separator) = record.split_at(separator);
        let path = &path_with_separator[1..];
        if header.len() < 3 || header[1] != b' ' {
            bail!("Git CLI primary index returned a malformed entry header");
        }
        let tag = header[0];
        let header = std::str::from_utf8(&header[2..])
            .context("Git CLI primary index returned a non-ASCII entry header")?;
        let mut fields = header.split_ascii_whitespace();
        let mode = u32::from_str_radix(
            fields.next().context("primary index entry omitted mode")?,
            8,
        )
        .context("primary index entry has invalid mode")?;
        let id = Oid::from_str(
            fields
                .next()
                .context("primary index entry omitted object id")?,
        )
        .context("primary index entry has invalid object id")?;
        let stage = fields
            .next()
            .context("primary index entry omitted stage")?
            .parse::<u16>()
            .context("primary index entry has invalid stage")?;
        if fields.next().is_some() {
            bail!("primary index entry has unexpected header fields");
        }
        let key = PrimaryIndexEntryKey {
            path: path.to_vec(),
            stage,
        };
        let state = PrimaryIndexEntryState { id, mode, tag };
        entries.insert(key, state);
    }
    Ok(entries)
}

fn index_entry_requires_fingerprint(state: &PrimaryIndexEntryState) -> bool {
    state.tag == b'S'
        || state.tag.is_ascii_lowercase()
        || matches!(state.mode, GITLINK_MODE | SPARSE_DIRECTORY_MODE)
}

fn primary_index_storage_snapshot(
    repo: &Repository,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryIndexStorageSnapshot> {
    let worktree_index = index_file_snapshot(&repo.path().join("index"))?;
    let shared_index = shared_index_path(repo, runtime)?
        .map(|path| {
            let storage = index_file_snapshot(&path)?;
            if storage == IndexFileSnapshot::Missing {
                bail!(
                    "Git reported split-index dependency {} but the file is missing",
                    path.display()
                );
            }
            Ok(SharedIndexFileSnapshot { path, storage })
        })
        .transpose()?;
    Ok(PrimaryIndexStorageSnapshot {
        worktree_index,
        shared_index,
    })
}

fn index_file_snapshot(path: &Path) -> Result<IndexFileSnapshot> {
    let bytes = match read_bounded_regular_file_nofollow(path, PRIMARY_INDEX_MAX_BYTES) {
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

fn shared_index_path(
    repo: &Repository,
    runtime: SupervisorExecutionRuntime,
) -> Result<Option<PathBuf>> {
    let workdir = repo
        .workdir()
        .context("shared-index discovery requires a non-bare repository")?;
    let output = sanitized_git_output(
        workdir,
        &["rev-parse", "--path-format=absolute", "--shared-index-path"],
        runtime,
    )
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
        repo.path().join(path)
    }))
}

fn sanitized_git_output(
    workdir: &Path,
    args: &[&str],
    runtime: SupervisorExecutionRuntime,
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
    let mut command_args = vec![
        "--no-pager".to_string(),
        "--no-optional-locks".to_string(),
        "-c".to_string(),
        "core.fsmonitor=false".to_string(),
        "-c".to_string(),
        "core.untrackedCache=false".to_string(),
    ];
    command_args.extend(args.iter().map(|arg| (*arg).to_string()));
    let process_spec = ProcessSpec::direct(
        "supervisor Git snapshot",
        git,
        command_args,
        workdir,
        SNAPSHOT_GIT_CAPTURE_MAX_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(SNAPSHOT_GIT_TIMEOUT));
    let output = run_process(match runtime {
        SupervisorExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_only(workdir),
            )),
        #[cfg(test)]
        SupervisorExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })?;
    if output.timed_out
        || output.process_error.is_some()
        || output.stdin_error.is_some()
        || (runtime == SupervisorExecutionRuntime::Verified && !output.safety_evidence_verified())
    {
        bail!(
            "supervisor Git snapshot was not safely verified: process_tree={:?}; side_effects={:?}; process_error={:?}; stdin_error={:?}",
            output.process_tree,
            output.side_effects,
            output.process_error,
            output.stdin_error
        );
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!(
            "supervisor Git snapshot output exceeded the {} byte limit",
            SNAPSHOT_GIT_CAPTURE_MAX_BYTES
        );
    }
    let status = output
        .status
        .context("supervisor Git snapshot terminated without status")?;
    Ok(std::process::Output {
        status,
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

fn primary_path_state(
    path: &Path,
    capture_nested_repository: bool,
    fingerprint_directory_contents: bool,
    depth: usize,
    visited_gitdirs: &mut BTreeSet<PathBuf>,
    runtime: SupervisorExecutionRuntime,
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
                    visited_gitdirs,
                    runtime,
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
        let contents_digest = fingerprint_directory_contents
            .then(|| directory_content_digest(path, 0))
            .transpose()?;
        return Ok(PrimaryPathState::Directory {
            nested_repository,
            contents_digest,
            mode,
        });
    }
    Ok(PrimaryPathState::Other { mode })
}

fn directory_content_digest(path: &Path, depth: usize) -> Result<Oid> {
    if depth > MAX_DIRECTORY_FINGERPRINT_DEPTH {
        bail!(
            "directory fingerprint exceeded the safety limit of {} at {}",
            MAX_DIRECTORY_FINGERPRINT_DEPTH,
            path.display()
        );
    }
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("failed to read sparse directory {}", path.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| snapshot_os_str_bytes(&entry.file_name()));

    let mut fingerprint = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let name_bytes = snapshot_os_str_bytes(&name);
        append_fingerprint_bytes(&mut fingerprint, &name_bytes);
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).with_context(|| {
            format!(
                "failed to inspect sparse directory entry {}",
                entry_path.display()
            )
        })?;
        fingerprint.extend_from_slice(&primary_path_mode(&metadata).to_le_bytes());
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            fingerprint.push(b'l');
            let target = fs::read_link(&entry_path)?;
            append_fingerprint_bytes(&mut fingerprint, &snapshot_os_str_bytes(target.as_os_str()));
        } else if file_type.is_file() {
            fingerprint.push(b'f');
            let id = Oid::hash_file(ObjectType::Blob, &entry_path)?;
            fingerprint.extend_from_slice(id.as_bytes());
        } else if file_type.is_dir() {
            fingerprint.push(b'd');
            if name == OsStr::new(".git") {
                fingerprint.extend_from_slice(b"git-metadata-directory");
            } else {
                let id = directory_content_digest(&entry_path, depth.saturating_add(1))?;
                fingerprint.extend_from_slice(id.as_bytes());
            }
        } else {
            fingerprint.push(b'o');
        }
    }
    Oid::hash_object(ObjectType::Blob, &fingerprint)
        .context("failed to digest sparse directory contents")
}

fn append_fingerprint_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

#[cfg(unix)]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(target_os = "windows")]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, target_os = "windows")))]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
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

fn serialize_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&serializable_path(path))
}

fn serialize_optional_path<S>(path: &Option<PathBuf>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    path.as_deref().map(serializable_path).serialize(serializer)
}

fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error>
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

fn read_child_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let contents =
        contents.context("external run did not capture a descriptor-held child report")?;
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held child report is not UTF-8: {}",
            display_path.display()
        )
    })?;
    parse_report_json(contents)
        .with_context(|| format!("failed to parse child report {}", display_path.display()))
}

fn write_child_report(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    report: &OrchestratorReviewReport,
) -> Result<()> {
    write_artifact_json(
        writer,
        relative,
        report,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| {
        format!(
            "failed to update normalized child report {}",
            relative.display()
        )
    })
}

fn read_auditor_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<AuditorReport>> {
    let contents =
        contents.context("external run did not capture a descriptor-held auditor report")?;
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held auditor report is not UTF-8: {}",
            display_path.display()
        )
    })?;
    parse_report_json(contents)
        .with_context(|| format!("failed to parse auditor report {}", display_path.display()))
}

fn import_worker_execution_journals(
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    incoming_scratch: &ArtifactScratchDirectory,
) -> Result<WorkerExecutionJournalEvidenceSet> {
    let mut journals = WorkerExecutionJournalEvidenceSet::new();
    for worker in &assignment.worker_assignments {
        let incoming_relative_path = worker_execution_journal_incoming_relative(worker);
        let scratch_path = incoming_scratch.path().join(&incoming_relative_path);
        let evidence_relative_path =
            worker_execution_journal_evidence_relative(&assignment.id, &worker.id);
        let status = match read_bounded_regular_file_nofollow(
            &scratch_path,
            MAX_WORKER_EXECUTION_JOURNAL_BYTES,
        ) {
            Ok(bytes) => {
                writer.write_bytes(
                    &evidence_relative_path,
                    &bytes,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
                match parse_worker_execution_journal(&bytes, &evidence_relative_path) {
                    Ok(entries) => WorkerExecutionJournalStatus::Loaded(entries),
                    Err(error) => WorkerExecutionJournalStatus::Invalid(error.to_string()),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                WorkerExecutionJournalStatus::Missing
            }
            Err(error) => WorkerExecutionJournalStatus::Invalid(format!(
                "failed to read incoming worker execution journal {}: {error}",
                incoming_relative_path.display()
            )),
        };
        journals.insert(
            worker.id.clone(),
            WorkerExecutionJournalEvidence {
                incoming_relative_path,
                evidence_relative_path,
                status,
            },
        );
    }
    Ok(journals)
}

fn parse_worker_execution_journal(
    bytes: &[u8],
    display_path: &Path,
) -> Result<Vec<WorkerExecutionJournalEntry>> {
    if bytes.len() > MAX_WORKER_EXECUTION_JOURNAL_BYTES {
        bail!(
            "worker execution journal {} exceeds its configured {} byte limit",
            display_path.display(),
            MAX_WORKER_EXECUTION_JOURNAL_BYTES
        );
    }
    let contents = std::str::from_utf8(bytes).with_context(|| {
        format!(
            "worker execution journal {} is not UTF-8",
            display_path.display()
        )
    })?;
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut entry: WorkerExecutionJournalEntry =
            serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "failed to parse worker execution journal {} line {}",
                    display_path.display(),
                    line_number
                )
            })?;
        if entry.command.is_empty() {
            bail!(
                "worker execution journal {} line {} omitted command",
                display_path.display(),
                line_number
            );
        }
        if entry.cwd.as_os_str().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted cwd",
                display_path.display(),
                line_number
            );
        }
        if entry.start_timestamp.trim().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted start_timestamp",
                display_path.display(),
                line_number
            );
        }
        if entry.end_timestamp.trim().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted end_timestamp",
                display_path.display(),
                line_number
            );
        }
        entry.changed_paths = normalize_paths(std::mem::take(&mut entry.changed_paths))
            .with_context(|| {
                format!(
                    "worker execution journal {} line {} has invalid changed_paths",
                    display_path.display(),
                    line_number
                )
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn import_external_attempt_evidence(
    writer: &mut ArtifactRunWriter,
    context: ExternalAttemptEvidenceContext<'_>,
) -> Result<()> {
    let ExternalAttemptEvidenceContext {
        incoming_scratch,
        capture_scratch,
        artifacts,
        external_run,
        external_command,
        raw_report_validated,
        runtime,
    } = context;
    let import_result = (|| -> Result<()> {
        if raw_report_validated {
            if let Some(contents) = external_run.output_last_message() {
                if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
                    bail!(
                        "descriptor-held external report exceeds its configured {} byte limit",
                        MAX_SUPERVISOR_REPORT_BYTES
                    );
                }
                writer.write_bytes(
                    &artifacts.raw_report_relative,
                    contents,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            }
        }
        let stdout_bytes = external_run.stdout_bytes();
        if stdout_bytes.len() > MAX_SUPERVISOR_REPORT_BYTES {
            bail!(
                "descriptor-held external stdout exceeds its configured {} byte limit",
                MAX_SUPERVISOR_REPORT_BYTES
            );
        }
        writer.write_bytes(
            &artifacts.raw_stdout_relative,
            stdout_bytes,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        let command_record = command_record_from_external(external_run, external_command);
        write_artifact_json(
            writer,
            &artifacts.command_record_relative,
            &command_record,
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    })();

    let discard_result = if external_process_quiescent_for_scratch(external_run, runtime) {
        discard_invocation_scratches(writer, incoming_scratch, capture_scratch)
    } else {
        bail!(
            "refusing to discard invocation artifact scratches without verified process quiescence: {}, {}",
            incoming_scratch.path().display(),
            capture_scratch.path().display()
        )
    };

    match (import_result, discard_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(discard_error)) => Err(error.context(format!(
            "artifact scratch cleanup also failed: {discard_error:#}"
        ))),
    }
}

#[cfg(test)]
fn create_invocation_scratches(
    writer: &mut ArtifactRunWriter,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    create_named_invocation_scratches(writer, Path::new("incoming"), Path::new("capture"))
}

fn create_named_invocation_scratches(
    writer: &mut ArtifactRunWriter,
    incoming_name: &Path,
    capture_name: &Path,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    let incoming = writer.create_scratch_dir(incoming_name)?;
    match writer.create_scratch_dir(capture_name) {
        Ok(capture) => Ok((incoming, capture)),
        Err(error) => {
            writer.discard_scratch(&incoming)?;
            Err(error).context("failed to reserve parent capture scratch")
        }
    }
}

fn invocation_scratch_names(
    assignment_index: usize,
    attempt: usize,
    auditor: bool,
    concurrent_mode: bool,
) -> (PathBuf, PathBuf) {
    if !concurrent_mode {
        return (PathBuf::from("incoming"), PathBuf::from("capture"));
    }
    let suffix = if auditor {
        format!("assignment-{assignment_index:04}-auditor")
    } else {
        format!("assignment-{assignment_index:04}-attempt-{attempt:02}")
    };
    (
        PathBuf::from(format!("incoming-{suffix}")),
        PathBuf::from(format!("capture-{suffix}")),
    )
}

fn discard_invocation_scratches(
    writer: &mut ArtifactRunWriter,
    incoming: &ArtifactScratchDirectory,
    capture: &ArtifactScratchDirectory,
) -> Result<()> {
    let incoming_result = writer.discard_scratch(incoming);
    let capture_result = writer.discard_scratch(capture);
    match (incoming_result, capture_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(capture_error)) => Err(error.context(format!(
            "capture scratch cleanup also failed: {capture_error:#}"
        ))),
    }
}

fn external_process_quiescent_for_scratch(
    run: &ExternalAgentRun,
    runtime: SupervisorRuntime,
) -> bool {
    match runtime {
        SupervisorRuntime::Codex => run.scratch_quiescence_verified(),
        // Fake mode is an in-process serializer and never launches a child.
        SupervisorRuntime::Fake => true,
    }
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
    external_command: &ExternalAgentCommand,
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
        commands_run: vec![command_record_from_external(external_run, external_command)],
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!("required child report is missing or invalid: {error}"),
            paths: vec![report_path.to_path_buf()],
        }],
        worker_reports: Vec::new(),
        audit_reports: Vec::new(),
        decomposition_completions: Vec::new(),
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

fn accepted_bloated_file_flags(reports: &[OrchestratorReviewReport]) -> Vec<BloatedFileFlag> {
    reports
        .iter()
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.worker_reports.iter())
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.bloated_file_flags.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn accepted_decomposition_candidates(
    reports: &[OrchestratorReviewReport],
) -> Vec<DecompositionCompletion> {
    reports
        .iter()
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.decomposition_completions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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

fn deterministic_fake_child_run(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    claim_token: u64,
    semantic_intent_token: Option<u64>,
) -> Result<ExternalAgentRun> {
    write_deterministic_fake_worker_journals(command, assignment)?;
    let worker_reports = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            WorkerReport {
                id: worker.id.clone(),
                role: AgentRole::Worker,
                assignment_kind: metadata.kind,
                target_path: metadata.target_path.clone(),
                assigned_paths: worker.assigned_paths.clone(),
                semantic_symbols: worker.semantic_symbols.clone(),
                semantic_modules: worker.semantic_modules.clone(),
                claim_token: None,
                semantic_intent_token: None,
                commands_run: Vec::new(),
                files_changed: Vec::new(),
                validation_results: vec![ValidationResult {
                    name: "deterministic fake worker validation".to_string(),
                    status: ReviewStatus::Succeeded,
                    command: Vec::new(),
                    message: None,
                }],
                findings: Vec::new(),
                bloated_file_flags: Vec::new(),
                decomposition_completion: metadata.target_path.map(|target_path| {
                    DecompositionCompletion {
                        target_path,
                        replacement_paths: Vec::new(),
                        supervisor_candidate_binding: None,
                    }
                }),
                no_further_delegation: Some(true),
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: "simulation-only evidence".to_string(),
                next_safe_action: "rerun with the verified Codex runtime".to_string(),
            }
        })
        .collect::<Vec<_>>();
    let decomposition_completions = worker_reports
        .iter()
        .filter_map(|report| report.decomposition_completion.clone())
        .collect();
    let report = OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: Some(claim_token),
        semantic_intent_token,
        commands_run: Vec::new(),
        files_changed: Vec::new(),
        validation_results: vec![ValidationResult {
            name: "deterministic fake child validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        worker_reports,
        audit_reports: Vec::new(),
        decomposition_completions,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "simulation-only evidence".to_string(),
        next_safe_action: "rerun with the verified Codex runtime".to_string(),
    };
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    Ok(deterministic_fake_run(command, output))
}

fn write_deterministic_fake_worker_journals(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
) -> Result<()> {
    let incoming_path = command
        .output_last_message
        .parent()
        .context("deterministic fake child report path has no parent directory")?;
    let journal_root = incoming_path.join("worker-journals");
    fs::create_dir_all(&journal_root).with_context(|| {
        format!(
            "failed to create deterministic fake worker journal directory {}",
            journal_root.display()
        )
    })?;
    for worker in &assignment.worker_assignments {
        let journal_path = journal_root.join(worker_execution_journal_file_name(&worker.id));
        fs::write(&journal_path, b"").with_context(|| {
            format!(
                "failed to write deterministic fake worker execution journal {}",
                journal_path.display()
            )
        })?;
    }
    Ok(())
}

fn deterministic_fake_auditor_run(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    child_report: &OrchestratorReviewReport,
) -> Result<ExternalAgentRun> {
    let report = AuditorReport {
        id: parent_auditor_id(assignment),
        role: AgentRole::Auditor,
        reviewed_worker_ids: required_auditor_prompt_subject_ids(assignment, child_report),
        reviewed_paths: required_auditor_review_paths(assignment, child_report),
        commands_run: Vec::new(),
        validation_results: vec![ValidationResult {
            name: "deterministic fake auditor validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "simulation-only evidence".to_string(),
        next_safe_action: "rerun with the verified Codex runtime".to_string(),
    };
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    Ok(deterministic_fake_run(command, output))
}

fn deterministic_fake_run(command: &ExternalAgentCommand, output: Vec<u8>) -> ExternalAgentRun {
    ExternalAgentRun {
        command: vec!["maco-internal-deterministic-fake".to_string()],
        cwd: command.cwd.clone(),
        timeout_seconds: command.timeout.as_secs(),
        exit_code: Some(0),
        duration_ms: 0,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: ExternalProgramTrust::ExplicitCustom,
        codex_permissions: None,
        stdout: crate::external_agent::CapturedOutput::default(),
        stderr: crate::external_agent::CapturedOutput::default(),
        error: None,
        output_last_message: Some(output),
    }
}

fn external_safety_verified(run: &ExternalAgentRun, runtime: SupervisorRuntime) -> bool {
    match runtime {
        SupervisorRuntime::Codex => {
            run.process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
                && run
                    .side_effects
                    .is_some_and(SideEffectConfinementEvidence::is_verified)
                && run.program_trust == ExternalProgramTrust::TrustedSystemCodex
                && run.codex_permissions.is_some()
        }
        SupervisorRuntime::Fake => {
            run.simulation_succeeded() && run.program_trust == ExternalProgramTrust::ExplicitCustom
        }
    }
}

fn external_process_completed(run: &ExternalAgentRun) -> bool {
    run.succeeded()
        || (run.simulation_succeeded() && run.program_trust == ExternalProgramTrust::ExplicitCustom)
}

fn complete_external_codex_usage(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> Option<Usage> {
    const MAX_USAGE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
    match read_bounded_regular_file_nofollow(&command.json_log, MAX_USAGE_CAPTURE_BYTES) {
        Ok(bytes) if bytes.len() < MAX_USAGE_CAPTURE_BYTES => {
            codex_usage_from_jsonl(&bytes).ok().flatten()
        }
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !run.stdout.truncated => {
            codex_usage_from_jsonl(run.stdout_bytes()).ok().flatten()
        }
        Err(_) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleUsageSample {
    role: AgentRole,
    model: Option<String>,
    usage: Usage,
}

struct RoleUsageAggregation {
    reports: BTreeMap<AgentRole, RoleUsageReport>,
    total_usage: Option<Usage>,
    total_cost_usd: Option<f64>,
}

fn role_usage_report(
    plan: &SupervisorPlan,
    samples: Vec<RoleUsageSample>,
) -> Result<RoleUsageAggregation> {
    let mut aggregates = BTreeMap::<AgentRole, (Usage, BTreeSet<String>, Option<f64>)>::new();
    let mut total_usage = Usage::default();
    let mut total_cost_usd = Some(0.0);
    for sample in samples {
        if !matches!(
            sample.role,
            AgentRole::ChildOrchestrator | AgentRole::Auditor
        ) {
            bail!(
                "{} usage is not directly process-observable",
                sample.role.as_str()
            );
        }
        total_usage = total_usage.saturating_add(sample.usage);
        let sample_cost_usd = sample
            .model
            .as_ref()
            .and_then(|model| plan.model_pricing.get(model))
            .map(|pricing| pricing.cost_usd(sample.usage))
            .filter(|cost| cost.is_finite());
        total_cost_usd = match (total_cost_usd, sample_cost_usd) {
            (Some(total), Some(cost)) => {
                let total = total + cost;
                total.is_finite().then_some(total)
            }
            _ => None,
        };
        let aggregate = aggregates
            .entry(sample.role)
            .or_insert_with(|| (Usage::default(), BTreeSet::new(), Some(0.0)));
        aggregate.0 = aggregate.0.saturating_add(sample.usage);
        if let Some(model) = sample.model {
            aggregate.1.insert(model);
        }
        aggregate.2 = match (aggregate.2, sample_cost_usd) {
            (Some(total), Some(cost)) => {
                let total = total + cost;
                total.is_finite().then_some(total)
            }
            _ => None,
        };
    }
    let has_observed_samples = !aggregates.is_empty();
    let reports = aggregates
        .into_iter()
        .map(|(role, (usage, models, cost_usd))| {
            (
                role,
                RoleUsageReport {
                    models: models.into_iter().collect(),
                    usage: Some(usage),
                    cost_usd,
                    observation: RoleUsageObservation::ProcessObserved,
                    unavailable_reason: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reports = reports;
    reports.insert(
        AgentRole::Worker,
        RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(
                "nested workers execute inside child Codex sessions and are not separate MACO-launched processes; runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                    .to_string(),
            ),
        },
    );
    if !has_observed_samples {
        total_cost_usd = None;
    }
    let total_usage = has_observed_samples.then_some(total_usage);
    reports.insert(
        AgentRole::Supervisor,
        RoleUsageReport {
            models: reports
                .values()
                .flat_map(|report| report.models.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            usage: total_usage,
            cost_usd: total_cost_usd,
            observation: RoleUsageObservation::SupervisorAggregate,
            unavailable_reason: total_usage.is_none().then(|| {
                "no MACO-launched child-orchestrator or auditor process usage was observed"
                    .to_string()
            }),
        },
    );
    Ok(RoleUsageAggregation {
        reports,
        total_usage,
        total_cost_usd,
    })
}

fn finalize_supervisor_cost(
    usage_complete: bool,
    role_usage: &mut BTreeMap<AgentRole, RoleUsageReport>,
    observed_total_cost_usd: Option<f64>,
) -> Option<f64> {
    if usage_complete {
        return observed_total_cost_usd;
    }
    if let Some(supervisor_usage) = role_usage.get_mut(&AgentRole::Supervisor) {
        supervisor_usage.cost_usd = None;
        supervisor_usage.unavailable_reason = Some(
            "supervisor aggregate cost is unavailable because at least one MACO-launched process usage sample is missing"
                .to_string(),
        );
    }
    None
}

fn command_record_from_external(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> CommandRunRecord {
    CommandRunRecord {
        command: serializable_external_command(&run.command, command),
        cwd: PathBuf::from("<child-worktree>"),
        exit_code: run.exit_code,
        status: if external_process_completed(run) {
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

fn serializable_external_command(
    rendered: &[String],
    command: &ExternalAgentCommand,
) -> Vec<String> {
    let path_replacements = [
        (&command.program, "<codex-executable>"),
        (&command.cwd, "<child-worktree>"),
        (&command.output_last_message, "<incoming-report>"),
        (&command.json_log, "<parent-capture>"),
        (&command.prompt, "<supervisor-prompt>"),
    ]
    .into_iter()
    .chain(
        command
            .output_schema
            .iter()
            .map(|path| (path, "<report-schema>")),
    )
    .map(|(path, replacement)| (path.display().to_string(), replacement.to_string()))
    .collect::<BTreeMap<_, _>>();
    rendered
        .iter()
        .map(|argument| {
            path_replacements
                .get(argument)
                .cloned()
                .unwrap_or_else(|| argument.clone())
        })
        .collect()
}

fn release_claims(store: &SyncStore, tokens: Vec<ClaimToken>) -> (Vec<PathClaim>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();
    for token in tokens {
        match store.release(token) {
            Ok(mut claim) => {
                sanitize_serialized_paths(&mut claim.paths);
                released.push(claim);
            }
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
            Ok(mut intent) => {
                sanitize_serialized_paths(&mut intent.paths);
                sanitize_serialized_paths(&mut intent.impacted_files);
                for symbol in &mut intent.symbols {
                    symbol.file = serializable_path_buf(&symbol.file);
                }
                released.push(intent);
            }
            Err(error) => errors.push(format!(
                "failed to release semantic intent {}: {error}",
                token.get()
            )),
        }
    }
    (released, errors)
}

fn sanitize_serialized_paths(paths: &mut [PathBuf]) {
    for path in paths {
        *path = serializable_path_buf(path);
    }
}

fn serializable_path_buf(path: &Path) -> PathBuf {
    PathBuf::from(serializable_path(path))
}

fn ensure_clean_primary(repo: &Path, runtime: SupervisorExecutionRuntime) -> Result<()> {
    if primary_is_dirty(repo, runtime)? {
        bail!("refusing to run supervise with a dirty primary worktree; rerun with --allow-dirty-primary to override");
    }
    Ok(())
}

fn primary_is_dirty(repo: &Path, runtime: SupervisorExecutionRuntime) -> Result<bool> {
    Ok(!primary_status_snapshot(repo, runtime)?.is_empty())
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
    status == Status::WT_NEW && is_untracked_runtime_artifact_bytes(path)
}

fn is_untracked_runtime_artifact_bytes(path: &[u8]) -> bool {
    LOCAL_RUNTIME_ROOTS
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
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    let value = supervisor_plan_value(plan, consultant, assignment_metadata, plan_metadata)?;
    write_artifact_json(
        writer,
        relative,
        &value,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| format!("failed to write plan snapshot {}", relative.display()))
}

fn write_orchestrator_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, orchestrator_report_schema_value())
}

fn orchestrator_report_schema_value() -> serde_json::Value {
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
            "decomposition_completions",
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
            "decomposition_completions": {
                "type": "array",
                "uniqueItems": true,
                "items": decomposition_completion_object_schema_value()
            },
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        }
    })
}

fn write_worker_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, worker_report_schema_value())
}

fn write_auditor_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, auditor_report_schema_value())
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
            "assignment_kind",
            "target_path",
            "assigned_paths",
            "semantic_symbols",
            "semantic_modules",
            "claim_token",
            "semantic_intent_token",
            "commands_run",
            "files_changed",
            "validation_results",
            "findings",
            "bloated_file_flags",
            "decomposition_completion",
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
            "assignment_kind": assignment_kind_schema_value(),
            "target_path": {"type": ["string", "null"]},
            "assigned_paths": {"type": "array", "items": {"type": "string"}},
            "semantic_symbols": {"type": "array", "items": {"type": "string"}},
            "semantic_modules": {"type": "array", "items": {"type": "string"}},
            "claim_token": {"type": ["integer", "null"]},
            "semantic_intent_token": {"type": ["integer", "null"]},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "files_changed": {"type": "array", "items": {"type": "string"}},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "bloated_file_flags": {
                "type": "array",
                "maxItems": MAX_BLOATED_FILE_FLAGS_PER_WORKER,
                "uniqueItems": true,
                "items": bloated_file_flag_schema_value()
            },
            "decomposition_completion": decomposition_completion_schema_value(),
            "no_further_delegation": {"type": "boolean", "const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        }
    })
}

fn assignment_kind_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["ordinary", "megafile_decomposition"]
    })
}

fn bloated_file_flag_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "minLength": 1}
        }
    })
}

fn decomposition_completion_schema_value() -> serde_json::Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": ["target_path", "replacement_paths"],
        "properties": {
            "target_path": {"type": "string", "minLength": 1},
            "replacement_paths": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_DECOMPOSITION_REPLACEMENT_PATHS,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1}
            }
        }
    })
}

fn decomposition_completion_object_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["target_path", "replacement_paths"],
        "properties": {
            "target_path": {"type": "string", "minLength": 1},
            "replacement_paths": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_DECOMPOSITION_REPLACEMENT_PATHS,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1}
            }
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

fn write_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    schema: serde_json::Value,
) -> Result<()> {
    write_artifact_json(
        writer,
        relative,
        &schema,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| format!("failed to write schema {}", relative.display()))
}

fn write_final_report(
    writer: &mut ArtifactRunWriter,
    report: &SupervisorFinalReport,
) -> Result<()> {
    write_artifact_json(
        writer,
        &RunArtifactFamily::Supervise.final_report_relative_path(),
        report,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .context("failed to write normalized supervisor final report")
}

fn read_supervisor_final_report(reader: &ArtifactRunReader) -> Result<SupervisorFinalReport> {
    let relative = RunArtifactFamily::Supervise.final_report_relative_path();
    let contents = reader.read(&relative).with_context(|| {
        format!(
            "failed to read supervisor final report {}",
            relative.display()
        )
    })?;
    if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
        bail!("supervisor final report exceeds its bounded size");
    }
    serde_json::from_slice(&contents).with_context(|| {
        format!(
            "failed to parse supervisor final report {}",
            relative.display()
        )
    })
}

fn read_finalized_supervisor_report(
    repo: &Path,
    run_id: &RunId,
    run_dir: &Path,
) -> Result<Option<SupervisorFinalReport>> {
    let run_metadata = match fs::symlink_metadata(run_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect supervisor run directory {}",
                    run_dir.display()
                )
            })
        }
    };
    validate_active_artifact_run_dir(run_dir, &run_metadata)?;
    let marker = run_dir.join(ARTIFACT_FINALIZATION_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, run_id)
                .with_context(|| {
                    format!(
                        "supervisor run '{}' is not a verified finalized artifact",
                        run_id.as_str()
                    )
                })?;
            Ok(Some(read_supervisor_final_report(&reader)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect supervisor finalization marker {}",
                marker.display()
            )
        }),
    }
}

fn validate_active_artifact_run_dir(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "supervisor run path is not a nofollow directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "supervisor run directory is not owned by the effective user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!(
                "supervisor run directory is not owner-private: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn write_artifact_json<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    value: &T,
    max_bytes: usize,
    disposition: ArtifactFileDisposition,
) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).context("failed to serialize supervise artifact JSON")?;
    bytes.push(b'\n');
    if bytes.len() > max_bytes {
        bail!(
            "supervise artifact {} exceeds its configured {} byte limit",
            relative.display(),
            max_bytes
        );
    }
    writer.write_bytes(relative, &bytes, disposition)?;
    Ok(())
}

fn write_private_prompt(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    prompt: &str,
) -> Result<()> {
    if prompt.len() > MAX_SUPERVISOR_PROMPT_BYTES {
        bail!(
            "supervise prompt {} exceeds its configured {} byte limit",
            relative.display(),
            MAX_SUPERVISOR_PROMPT_BYTES
        );
    }
    writer.write_bytes(
        relative,
        prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    Ok(())
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
    run_dir: PathBuf,
    assignments: PathBuf,
    schemas: PathBuf,
    reports: PathBuf,
}

impl RunDirs {
    fn for_writer(writer: &ArtifactRunWriter) -> Self {
        let run_dir = writer.run_dir().to_path_buf();
        Self {
            assignments: run_dir.join("assignments"),
            schemas: run_dir.join("schemas"),
            reports: run_dir.join("reports"),
            run_dir,
        }
    }

    fn relative(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.run_dir)
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "artifact path {} is outside supervise run {}",
                    path.display(),
                    self.run_dir.display()
                )
            })
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

fn normalize_semantic_symbols(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| canonical_semantic_path(value, false))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_semantic_modules(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| canonical_semantic_path(value, true))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical_semantic_path(value: &str, require_crate_root: bool) -> Option<String> {
    let mut parts = value
        .trim()
        .split("::")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }
    if require_crate_root && parts.first().is_some_and(|part| part != "crate") {
        parts.insert(0, "crate".to_string());
    }
    Some(parts.join("::"))
}

fn normalize_spec_fragment_ids(values: Vec<String>) -> Result<Vec<String>> {
    if values.len() > MAX_SPEC_FRAGMENT_IDS {
        bail!(
            "spec fragment id count {} exceeds limit {}",
            values.len(),
            MAX_SPEC_FRAGMENT_IDS
        );
    }
    values
        .into_iter()
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                bail!("spec fragment id cannot be empty");
            }
            if value.len() > MAX_SPEC_FRAGMENT_ID_BYTES {
                bail!(
                    "spec fragment id exceeds {} bytes",
                    MAX_SPEC_FRAGMENT_ID_BYTES
                );
            }
            if value.chars().any(char::is_control) {
                bail!("spec fragment id must not contain control characters");
            }
            Ok(value.to_string())
        })
        .collect::<Result<BTreeSet<_>>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

fn parent_auditor_id(assignment: &OrchestratorAssignment) -> String {
    format!("{}-review-auditor", assignment.id)
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

pub(crate) fn validate_max_concurrent_children(max_concurrent_children: usize) -> Result<()> {
    if max_concurrent_children == 0 {
        bail!("--max-concurrent-children must be at least 1");
    }
    Ok(())
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

fn display_command_identities(commands: &[(Vec<String>, PathBuf)]) -> String {
    if commands.is_empty() {
        return "<none>".to_string();
    }
    commands
        .iter()
        .map(|(command, cwd)| format!("{} @ {}", display_strings(command), cwd.display()))
        .collect::<Vec<_>>()
        .join("; ")
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
    use crate::{
        external_agent::{CapturedOutput, CodexPermissionEvidence},
        orchestration_event::{
            set_orchestration_event_append_fault, OrchestrationEvent, ORCHESTRATION_EVENT_PATH,
        },
        process_runner::{ContainmentBackend, SideEffectConfinementProfileKind},
    };
    use git2::Signature;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar,
    };
    use std::time::Instant;

    #[test]
    fn external_containment_gate_accepts_only_verified_empty_evidence() {
        assert!(
            ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
                .is_verified_empty()
        );
        assert!(
            !ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
                .is_verified_empty()
        );
        assert!(
            !ProcessTreeEvidence::Unverified(ContainmentBackend::WindowsJobObject)
                .is_verified_empty()
        );
    }

    fn bounded_loader_plan_json() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "task": "bounded loader",
            "max_depth": 2,
            "max_child_assignments": 1,
            "max_child_retries": 0,
            "child_timeout_seconds": 60,
            "assignments": [{
                "id": "child-a",
                "assigned_paths": ["README.md"],
                "worker_assignments": []
            }]
        }))
        .expect("serialize bounded loader plan")
    }

    #[test]
    fn old_and_new_supervisor_model_economics_schema_round_trip() {
        let old_json = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
            .expect("parse old plan fixture");
        let old = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&old_json).expect("serialize old plan"),
        )
        .expect("old plan remains valid");
        assert!(old.plan.role_models.is_empty());
        assert!(old.plan.model_pricing.is_empty());
        let old_round_trip = supervisor_plan_value(
            &old.plan,
            &old.consultant,
            &old.assignment_metadata,
            &old.plan_metadata,
        )
        .expect("serialize old plan");
        assert!(old_round_trip.get("role_models").is_none());
        assert!(old_round_trip.get("model_pricing").is_none());

        let mut new_json = old_json;
        let object = new_json.as_object_mut().expect("plan object");
        object.insert(
            "role_models".to_string(),
            json!({
                "supervisor": {
                    "model": "supervisor-model",
                    "reasoning_effort": "xhigh"
                },
                "child_orchestrator": {
                    "model": " planner-model ",
                    "reasoning_effort": " high "
                },
                "worker": {
                    "model": "worker-model",
                    "reasoning_effort": "low"
                },
                "auditor": {
                    "model": "auditor-model",
                    "reasoning_effort": "xhigh"
                }
            }),
        );
        object.insert(
            "model_pricing".to_string(),
            json!({
                "planner-model": {
                    "input_usd_per_million_tokens": 2.5,
                    "output_usd_per_million_tokens": 10.0
                },
                "worker-model": {
                    "input_usd_per_million_tokens": 0.25,
                    "output_usd_per_million_tokens": 1.0
                }
            }),
        );
        let new = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&new_json).expect("serialize new plan"),
        )
        .expect("new model economics plan");
        assert_eq!(
            new.plan.role_models[&AgentRole::Supervisor]
                .model
                .as_deref(),
            Some("supervisor-model")
        );
        assert_eq!(
            new.plan.role_models[&AgentRole::Supervisor]
                .reasoning_effort
                .as_deref(),
            Some("xhigh")
        );
        assert_eq!(new.plan.role_models.len(), 4);
        assert_eq!(
            new.plan.role_models[&AgentRole::ChildOrchestrator]
                .model
                .as_deref(),
            Some("planner-model")
        );
        assert_eq!(
            new.plan.role_models[&AgentRole::ChildOrchestrator]
                .reasoning_effort
                .as_deref(),
            Some("high")
        );
        let normalized = supervisor_plan_value(
            &new.plan,
            &new.consultant,
            &new.assignment_metadata,
            &new.plan_metadata,
        )
        .expect("serialize new plan");
        let reparsed = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&normalized).expect("serialize normalized new plan"),
        )
        .expect("reparse normalized new plan");
        assert_eq!(reparsed, new);

        let mut empty_model = new.plan.clone();
        empty_model
            .role_models
            .get_mut(&AgentRole::Worker)
            .expect("worker selection")
            .model = Some("  ".to_string());
        assert!(validate_legacy_supervisor_plan(empty_model)
            .expect_err("empty present model must fail")
            .to_string()
            .contains("role_models.worker.model cannot be empty"));

        let mut invalid_pricing = new.plan;
        invalid_pricing.model_pricing.insert(
            "bad-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: f64::INFINITY,
                output_usd_per_million_tokens: 1.0,
            },
        );
        assert!(validate_legacy_supervisor_plan(invalid_pricing)
            .expect_err("non-finite pricing must fail")
            .to_string()
            .contains("finite, non-negative"));
    }

    #[test]
    fn recursive_supervisor_plan_flattens_and_preserves_schedule_on_round_trip() {
        let source = json!({
            "version": 1,
            "task": "recursive plan",
            "max_depth": 3,
            "max_child_assignments": 2,
            "spec_fragment_ids": ["SPEC-root", "SPEC-child", "SPEC-gap"],
            "assignments": [{
                "id": "root-child",
                "assigned_paths": ["src/root.rs"],
                "spec_fragment_ids": ["SPEC-root"],
                "worker_assignments": [],
                "child_assignments": [{
                    "id": "nested-child",
                    "assigned_paths": ["src/nested.rs"],
                    "spec_fragment_ids": ["SPEC-child"],
                    "worker_assignments": []
                }]
            }]
        });
        let loaded = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize recursive source"),
        )
        .expect("parse recursive plan");
        assert_eq!(
            loaded
                .plan
                .assignments
                .iter()
                .map(|assignment| assignment.id.as_str())
                .collect::<Vec<_>>(),
            vec!["root-child", "nested-child"]
        );
        assert_eq!(
            loaded.plan_metadata.assignment_schedule,
            vec![
                AssignmentScheduleEntry {
                    assignment_id: "root-child".to_string(),
                    parent_assignment_id: None,
                    depth: 2,
                    flattened_index: 0,
                },
                AssignmentScheduleEntry {
                    assignment_id: "nested-child".to_string(),
                    parent_assignment_id: Some("root-child".to_string()),
                    depth: 3,
                    flattened_index: 1,
                },
            ]
        );
        assert_eq!(
            loaded.plan_metadata.coverage_gaps,
            vec![SupervisorCoverageGap {
                kind: CoverageGapKind::UnassignedSpecFragment,
                spec_fragment_id: Some("SPEC-gap".to_string()),
                assignment_id: None,
                message: "spec fragment 'SPEC-gap' is not mapped to an assignment".to_string(),
            }]
        );

        let normalized = supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )
        .expect("normalize recursive plan");
        assert_eq!(
            normalized["assignments"]
                .as_array()
                .expect("normalized assignments")
                .len(),
            2
        );
        assert!(normalized["assignments"][0]
            .get("child_assignments")
            .is_none());
        let reparsed = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&normalized).expect("serialize normalized plan"),
        )
        .expect("reparse normalized recursive plan");
        assert_eq!(reparsed, loaded);
    }

    #[test]
    fn supervisor_depth_bounds_are_configurable_and_enforced() {
        let recursive = |max_depth| {
            json!({
                "version": 1,
                "task": "depth bounds",
                "max_depth": max_depth,
                "max_child_assignments": 2,
                "assignments": [{
                    "id": "root-child",
                    "assigned_paths": ["src/root.rs"],
                    "child_assignments": [{
                        "id": "nested-child",
                        "assigned_paths": ["src/nested.rs"]
                    }]
                }]
            })
        };
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&recursive(3)).expect("serialize depth-three plan")
        )
        .is_ok());
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&recursive(2)).expect("serialize shallow plan")
        )
        .expect_err("nested assignment must exceed max depth two")
        .to_string()
        .contains("depth 3"));

        for invalid_depth in [1, MAX_SUPERVISOR_DEPTH.saturating_add(1)] {
            let source = json!({
                "version": 1,
                "task": "invalid depth",
                "max_depth": invalid_depth,
                "max_child_assignments": 1,
                "assignments": [{
                    "id": "child-a",
                    "assigned_paths": ["README.md"]
                }]
            });
            assert!(parse_supervisor_plan_with_consultant(
                &serde_json::to_string(&source).expect("serialize invalid depth")
            )
            .is_err());
        }
    }

    #[test]
    fn supervisor_rejects_normalized_path_symbol_and_module_collisions() {
        let collision_error = |left: Value, right: Value| {
            let source = json!({
                "version": 1,
                "task": "collision",
                "max_depth": 2,
                "max_child_assignments": 2,
                "assignments": [left, right]
            });
            parse_supervisor_plan_with_consultant(
                &serde_json::to_string(&source).expect("serialize collision plan"),
            )
            .expect_err("collision must fail before launch")
            .to_string()
        };
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src/generated/../lib.rs"]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/lib.rs"]
            }),
        )
        .contains("path 'src/lib.rs'"));
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src"]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/nested/lib.rs"]
            }),
        )
        .contains("overlap after normalization"));
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src/a.rs"],
                "semantic_symbols": [" crate :: SharedSymbol "]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/b.rs"],
                "semantic_symbols": ["crate::SharedSymbol"]
            }),
        )
        .contains("semantic symbol 'crate::SharedSymbol'"));
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src/a.rs"],
                "semantic_modules": [" shared "]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/b.rs"],
                "semantic_modules": ["crate :: shared"]
            }),
        )
        .contains("semantic module 'crate::shared'"));
    }

    #[test]
    fn supervisor_rejects_normalized_worker_semantic_collisions() {
        let worker_collision_error = |first: Value, second: Value| {
            let source = json!({
                "version": 1,
                "task": "worker collision",
                "max_depth": 2,
                "max_child_assignments": 1,
                "assignments": [{
                    "id": "child-a",
                    "assigned_paths": ["src"],
                    "worker_assignments": [first, second]
                }]
            });
            parse_supervisor_plan_with_consultant(
                &serde_json::to_string(&source).expect("serialize worker collision"),
            )
            .expect_err("worker collision must fail")
            .to_string()
        };
        assert!(worker_collision_error(
            json!({
                "id": "worker-a",
                "assigned_paths": ["src/a.rs"],
                "semantic_modules": [" shared "]
            }),
            json!({
                "id": "worker-b",
                "assigned_paths": ["src/b.rs"],
                "semantic_modules": ["crate :: shared"]
            }),
        )
        .contains("workers 'worker-a' and 'worker-b'"));
        assert!(worker_collision_error(
            json!({
                "id": "worker-a",
                "assigned_paths": ["src/a.rs"],
                "semantic_symbols": [" crate :: SharedSymbol "]
            }),
            json!({
                "id": "worker-b",
                "assigned_paths": ["src/b.rs"],
                "semantic_symbols": ["crate::SharedSymbol"]
            }),
        )
        .contains("semantic symbol 'crate::SharedSymbol'"));
        assert!(worker_collision_error(
            json!({
                "id": "worker-a",
                "assigned_paths": ["src/generated/../lib.rs"]
            }),
            json!({
                "id": "worker-b",
                "assigned_paths": ["src/lib.rs"]
            }),
        )
        .contains("overlaps worker"));
    }

    #[test]
    fn supervisor_rejects_cross_assignment_worker_semantic_collisions() {
        let collision_error = |left: Value, right: Value| {
            let source = json!({
                "version": 1,
                "task": "cross assignment worker collision",
                "max_depth": 2,
                "max_child_assignments": 2,
                "assignments": [left, right]
            });
            parse_supervisor_plan_with_consultant(
                &serde_json::to_string(&source).expect("serialize cross assignment collision"),
            )
            .expect_err("cross assignment worker semantics must fail")
            .to_string()
        };
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src/a"],
                "worker_assignments": [{
                    "id": "worker-a",
                    "assigned_paths": ["src/a/worker.rs"],
                    "semantic_symbols": [" crate :: SharedSymbol "]
                }]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/b"],
                "worker_assignments": [{
                    "id": "worker-b",
                    "assigned_paths": ["src/b/worker.rs"],
                    "semantic_symbols": ["crate::SharedSymbol"]
                }]
            }),
        )
        .contains("worker 'worker-a' under assignment 'child-a' and worker 'worker-b'"));
        assert!(collision_error(
            json!({
                "id": "child-a",
                "assigned_paths": ["src/a"],
                "semantic_modules": [" shared "]
            }),
            json!({
                "id": "child-b",
                "assigned_paths": ["src/b"],
                "worker_assignments": [{
                    "id": "worker-b",
                    "assigned_paths": ["src/b/worker.rs"],
                    "semantic_modules": ["crate :: shared"]
                }]
            }),
        )
        .contains("assignment 'child-a' and worker 'worker-b'"));
    }

    #[test]
    fn supervisor_traceability_reports_missing_changes_and_diff_binding() {
        let plan = injected_multi_plan(
            vec![
                injected_named_assignment("child-a", "src/a.rs"),
                injected_named_assignment("child-b", "src/b.rs"),
            ],
            0,
        );
        let metadata = SupervisorPlanMetadata {
            spec_fragment_ids: vec!["SPEC-a".to_string(), "SPEC-b".to_string()],
            spec_fragment_ids_by_assignment: BTreeMap::from([
                ("child-a".to_string(), vec!["SPEC-a".to_string()]),
                ("child-b".to_string(), vec!["SPEC-b".to_string()]),
            ]),
            assignment_schedule: vec![
                AssignmentScheduleEntry {
                    assignment_id: "child-a".to_string(),
                    parent_assignment_id: None,
                    depth: 2,
                    flattened_index: 0,
                },
                AssignmentScheduleEntry {
                    assignment_id: "child-b".to_string(),
                    parent_assignment_id: None,
                    depth: 2,
                    flattened_index: 1,
                },
            ],
            coverage_gaps: Vec::new(),
        };
        let mut report_a = injected_child_report(&plan.assignments[0]);
        report_a.files_changed = vec![PathBuf::from("src/a.rs")];
        let mut report_b = injected_child_report(&plan.assignments[1]);
        report_b.files_changed.clear();
        let (traceability, gaps) =
            supervisor_assignment_traceability(&plan, &metadata, &[report_a, report_b]);
        assert_eq!(traceability.len(), 2);
        assert_eq!(
            traceability[0].produced_changed_paths,
            vec![PathBuf::from("src/a.rs")]
        );
        assert!(traceability[0].produced_diff_binding.is_none());
        assert!(gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::MissingDiffBinding
                && gap.assignment_id.as_deref() == Some("child-a")
                && gap.spec_fragment_id.as_deref() == Some("SPEC-a")
        }));
        assert!(gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::NoProducedChanges
                && gap.assignment_id.as_deref() == Some("child-b")
                && gap.spec_fragment_id.as_deref() == Some("SPEC-b")
        }));
    }

    #[test]
    fn role_selection_produces_distinct_launched_role_argv() {
        let mut plan = parse_supervisor_plan_with_consultant(
            std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
        )
        .expect("base plan")
        .plan;
        plan.role_models = BTreeMap::from([
            (
                AgentRole::ChildOrchestrator,
                RoleModelSelection {
                    model: Some("planner-model".to_string()),
                    reasoning_effort: Some("high".to_string()),
                },
            ),
            (
                AgentRole::Worker,
                RoleModelSelection {
                    model: Some("worker-model".to_string()),
                    reasoning_effort: Some("low".to_string()),
                },
            ),
            (
                AgentRole::Auditor,
                RoleModelSelection {
                    model: Some("auditor-model".to_string()),
                    reasoning_effort: Some("xhigh".to_string()),
                },
            ),
        ]);
        let base_command = || {
            ExternalAgentCommand::codex(
                "codex",
                "/workspace",
                "/run/prompt.md",
                "/run/events.jsonl",
                "/run/report.json",
                Duration::from_secs(1),
            )
        };
        let child = apply_role_model_selection(base_command(), &plan, AgentRole::ChildOrchestrator);
        let auditor = apply_role_model_selection(base_command(), &plan, AgentRole::Auditor);
        let child_argv = crate::external_agent::command_argv(&child)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let auditor_argv = crate::external_agent::command_argv(&auditor)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(child_argv
            .windows(2)
            .any(|arguments| arguments == ["-m", "planner-model"]));
        assert!(child_argv
            .windows(2)
            .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"high\""] }));
        assert!(auditor_argv
            .windows(2)
            .any(|arguments| arguments == ["-m", "auditor-model"]));
        assert!(auditor_argv
            .windows(2)
            .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
        assert!(!child_argv
            .iter()
            .any(|argument| argument.contains("worker-model")));
        assert_ne!(child_argv, auditor_argv);
    }

    #[test]
    fn process_role_usage_aggregation_prices_children_and_auditors() {
        let mut plan = parse_supervisor_plan_with_consultant(
            std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
        )
        .expect("base plan")
        .plan;
        plan.model_pricing = BTreeMap::from([
            (
                "planner-model".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 2.0,
                    output_usd_per_million_tokens: 8.0,
                },
            ),
            (
                "auditor-model".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 1.0,
                    output_usd_per_million_tokens: 4.0,
                },
            ),
        ]);
        let samples = vec![
            RoleUsageSample {
                role: AgentRole::ChildOrchestrator,
                model: Some("planner-model".to_string()),
                usage: Usage {
                    input_tokens: 1_000,
                    output_tokens: 200,
                    total_tokens: 1_200,
                },
            },
            RoleUsageSample {
                role: AgentRole::ChildOrchestrator,
                model: Some("planner-model".to_string()),
                usage: Usage {
                    input_tokens: 500,
                    output_tokens: 100,
                    total_tokens: 600,
                },
            },
            RoleUsageSample {
                role: AgentRole::Auditor,
                model: Some("auditor-model".to_string()),
                usage: Usage {
                    input_tokens: 500,
                    output_tokens: 100,
                    total_tokens: 600,
                },
            },
            RoleUsageSample {
                role: AgentRole::Auditor,
                model: Some("auditor-model".to_string()),
                usage: Usage {
                    input_tokens: 250,
                    output_tokens: 50,
                    total_tokens: 300,
                },
            },
        ];
        let RoleUsageAggregation {
            reports: by_role,
            total_usage: total,
            total_cost_usd: cost,
        } = role_usage_report(&plan, samples.clone()).expect("aggregate process usage");
        assert_eq!(
            by_role[&AgentRole::ChildOrchestrator].usage,
            Some(Usage {
                input_tokens: 1_500,
                output_tokens: 300,
                total_tokens: 1_800,
            })
        );
        assert_eq!(
            total,
            Some(Usage {
                input_tokens: 2_250,
                output_tokens: 450,
                total_tokens: 2_700,
            })
        );
        let expected_cost = 0.0054 + 0.00135;
        assert!((cost.expect("fully priced total") - expected_cost).abs() < 1e-12);
        assert_eq!(
            by_role[&AgentRole::Worker].observation,
            RoleUsageObservation::NotProcessObservable
        );
        assert!(by_role[&AgentRole::Worker].usage.is_none());
        assert!(by_role[&AgentRole::Worker]
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
        let serialized_worker =
            serde_json::to_value(&by_role[&AgentRole::Worker]).expect("serialize worker marker");
        assert_eq!(serialized_worker["observation"], "not_process_observable");
        assert!(serialized_worker.get("usage").is_none());
        assert!(serialized_worker["unavailable_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
        assert_eq!(
            by_role[&AgentRole::Supervisor].observation,
            RoleUsageObservation::SupervisorAggregate
        );
        assert_eq!(by_role[&AgentRole::Supervisor].usage, total);

        plan.model_pricing.clear();
        let RoleUsageAggregation {
            reports: unpriced,
            total_usage: unpriced_total,
            total_cost_usd: unpriced_cost,
        } = role_usage_report(&plan, samples).expect("aggregate unpriced process usage");
        assert_eq!(unpriced_total, total);
        assert!(unpriced.values().all(|report| report.cost_usd.is_none()));
        assert!(unpriced_cost.is_none());

        let mut incomplete = by_role;
        assert!(finalize_supervisor_cost(false, &mut incomplete, cost).is_none());
        assert!(incomplete[&AgentRole::Supervisor].cost_usd.is_none());
        assert!(incomplete[&AgentRole::Supervisor]
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("at least one MACO-launched process")));
    }

    #[test]
    fn empty_process_usage_has_no_synthetic_supervisor_or_worker_totals() {
        let plan = parse_supervisor_plan_with_consultant(
            std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
        )
        .expect("base plan")
        .plan;
        let RoleUsageAggregation {
            reports: by_role,
            total_usage: total,
            total_cost_usd: cost,
        } = role_usage_report(&plan, Vec::new()).expect("empty process aggregation");
        assert!(total.is_none());
        assert!(cost.is_none());
        assert!(by_role[&AgentRole::Supervisor].usage.is_none());
        assert!(by_role[&AgentRole::Supervisor].cost_usd.is_none());
        assert!(by_role[&AgentRole::Worker].usage.is_none());
        assert_eq!(
            by_role[&AgentRole::Worker].observation,
            RoleUsageObservation::NotProcessObservable
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_input_loader_accepts_direct_regular_files_and_refuses_unsafe_inputs() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        Repository::init(&repo).expect("initialize repository");
        fs::write(repo.join("README.md"), "# test\n").expect("write readme");

        let plain = temp.path().join("task.txt");
        fs::write(&plain, "ordinary direct UTF-8 task\n").expect("write plain task");
        let task = supervisor_plan_from_task_file(&repo, &plain).expect("load plain task");
        assert_eq!(task.task, "ordinary direct UTF-8 task\n");

        let plan = temp.path().join("plan.json");
        fs::write(&plan, bounded_loader_plan_json()).expect("write plan");
        assert_eq!(
            load_supervisor_plan_file(&plan)
                .expect("load direct regular plan")
                .task,
            "bounded loader"
        );

        let invalid_utf8 = temp.path().join("invalid.json");
        fs::write(&invalid_utf8, [0xff, 0xfe]).expect("write invalid utf8");
        assert!(load_supervisor_plan_file(&invalid_utf8)
            .expect_err("invalid UTF-8 must fail")
            .to_string()
            .contains("not valid UTF-8"));

        let oversized = temp.path().join("oversized.json");
        fs::write(
            &oversized,
            vec![b' '; usize::try_from(MAX_SUPERVISOR_INPUT_BYTES).unwrap_or(usize::MAX) + 1],
        )
        .expect("write oversized input");
        assert!(load_supervisor_plan_file(&oversized).is_err());

        let symlinked = temp.path().join("symlinked.json");
        symlink(&plan, &symlinked).expect("create plan symlink");
        assert!(load_supervisor_plan_file(&symlinked).is_err());

        let hardlinked = temp.path().join("hardlinked.json");
        fs::hard_link(&plan, &hardlinked).expect("create plan hardlink");
        assert!(load_supervisor_plan_file(&hardlinked).is_err());

        let fifo = temp.path().join("plan.fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(load_supervisor_plan_file(&fifo).is_err());
    }

    #[test]
    fn supervise_writer_discards_reusable_invocation_scratches_and_finalizes_private_evidence() {
        let (_temp, repo_path) = injected_repository();
        let run_id = RunId::new("artifact-scratch-finalized").expect("valid run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise-test",
        )
        .expect("reserve supervise artifact run");
        let dirs = RunDirs::for_writer(&writer);
        let (incoming, capture) =
            create_invocation_scratches(&mut writer).expect("reserve invocation scratches");
        let artifacts =
            child_attempt_artifacts(&dirs, incoming.path(), capture.path(), "child-a", 1, false);
        let assignment = injected_assignment(false);
        let child_report = injected_child_report(&assignment);
        let mut child_bytes =
            serde_json::to_vec_pretty(&child_report).expect("serialize child report");
        child_bytes.push(b'\n');
        fs::write(&artifacts.report_path, &child_bytes).expect("write child scratch output");
        fs::write(&artifacts.log_path, b"private raw capture\n")
            .expect("write parent capture scratch");
        let command = ExternalAgentCommand::codex(
            "unused-codex",
            &repo_path,
            &artifacts.prompt_path,
            &artifacts.log_path,
            &artifacts.report_path,
            Duration::from_secs(1),
        );
        let external_run = deterministic_fake_run(&command, child_bytes.clone());
        import_external_attempt_evidence(
            &mut writer,
            ExternalAttemptEvidenceContext {
                incoming_scratch: &incoming,
                capture_scratch: &capture,
                artifacts: &artifacts,
                external_run: &external_run,
                external_command: &command,
                raw_report_validated: true,
                runtime: SupervisorRuntime::Fake,
            },
        )
        .expect("import held evidence and discard scratches");

        assert!(!dirs.run_dir.join("incoming").exists());
        assert!(!dirs.run_dir.join("capture").exists());
        assert!(dirs.run_dir.join("evidence/incoming/child-a.json").exists());
        assert!(dirs.run_dir.join("logs/child-a.jsonl").exists());
        assert!(dirs.run_dir.join("logs/child-a.summary.json").exists());

        let final_report = artifact_test_final_report(&run_id);
        write_final_report(&mut writer, &final_report).expect("write final report");
        let finalization = writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize supervise artifacts");
        assert!(!finalization.publishable);
        assert!(finalization
            .files
            .iter()
            .all(|file| file.disposition == ArtifactFileDisposition::PrivateEvidence));
        assert!(dirs.run_dir.join(ARTIFACT_FINALIZATION_MARKER).exists());
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized supervise artifacts");
        let restored = read_supervisor_final_report(&reader).expect("read finalized report");
        assert_eq!(restored.run_id, run_id);
    }

    #[test]
    fn attempted_unverified_target_preserves_both_scratches_and_has_no_marker() {
        let (_temp, repo_path) = injected_repository();
        let run_id = RunId::new("artifact-unverified-target").expect("valid run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            run_id,
            "supervise-test",
        )
        .expect("reserve supervise artifact run");
        let dirs = RunDirs::for_writer(&writer);
        let (incoming, capture) =
            create_invocation_scratches(&mut writer).expect("reserve invocation scratches");
        let artifacts = child_attempt_artifacts(
            &dirs,
            incoming.path(),
            capture.path(),
            "child-unverified",
            1,
            false,
        );
        let command = ExternalAgentCommand::codex(
            "unused-codex",
            &repo_path,
            &artifacts.prompt_path,
            &artifacts.log_path,
            &artifacts.report_path,
            Duration::from_secs(1),
        );
        let assignment = injected_assignment(false);
        let child_bytes =
            serde_json::to_vec(&injected_child_report(&assignment)).expect("serialize report");
        fs::write(&artifacts.report_path, &child_bytes).expect("write incoming report");
        fs::write(&artifacts.log_path, b"unverified capture\n").expect("write capture");
        let mut run = deterministic_fake_run(&command, child_bytes);
        run.program_trust = ExternalProgramTrust::TrustedSystemCodex;
        run.process_tree = Some(ProcessTreeEvidence::Unverified(
            ContainmentBackend::SystemdUserService,
        ));
        let run = injected_target_attempted(run);

        let error = import_external_attempt_evidence(
            &mut writer,
            ExternalAttemptEvidenceContext {
                incoming_scratch: &incoming,
                capture_scratch: &capture,
                artifacts: &artifacts,
                external_run: &run,
                external_command: &command,
                raw_report_validated: true,
                runtime: SupervisorRuntime::Codex,
            },
        )
        .expect_err("unverified launched target must keep scratch evidence");
        assert!(error.to_string().contains("verified process quiescence"));
        assert!(incoming.path().exists());
        assert!(capture.path().exists());
        assert!(!dirs.run_dir.join(ARTIFACT_FINALIZATION_MARKER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn supervise_scratch_rebind_is_refused_without_deleting_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, repo_path) = injected_repository();
        let run_id = RunId::new("artifact-scratch-rebind").expect("valid run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            run_id,
            "supervise-test",
        )
        .expect("reserve supervise artifact run");
        let (incoming, capture) =
            create_invocation_scratches(&mut writer).expect("reserve invocation scratches");
        let moved = writer.run_dir().join("moved-incoming");
        fs::rename(incoming.path(), &moved).expect("move bound incoming scratch");
        fs::create_dir(incoming.path()).expect("create replacement incoming scratch");
        fs::set_permissions(incoming.path(), fs::Permissions::from_mode(0o700))
            .expect("secure replacement permissions");
        let sentinel = incoming.path().join("sentinel.txt");
        fs::write(&sentinel, "preserve\n").expect("write replacement sentinel");

        let error = discard_invocation_scratches(&mut writer, &incoming, &capture)
            .expect_err("rebound scratch must be refused");
        assert!(error.to_string().contains("scratch") || error.to_string().contains("identity"));
        assert_eq!(
            fs::read_to_string(&sentinel).expect("read replacement sentinel"),
            "preserve\n"
        );
        assert!(!capture.path().exists());
        assert!(moved.exists());
    }

    #[test]
    fn supervise_status_distinguishes_absent_active_finalized_and_corrupt_runs() {
        let (_temp, repo_path) = injected_repository();
        let absent_id = RunId::new("artifact-status-absent").expect("valid absent id");
        let absent = supervisor_status(&repo_path, absent_id).expect("status absent run");
        assert!(!absent.final_report_exists);

        let run_id = RunId::new("artifact-status-lifecycle").expect("valid run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise-test",
        )
        .expect("reserve active run");
        let active = supervisor_status(&repo_path, run_id.clone()).expect("status active run");
        assert!(!active.final_report_exists);

        let final_report = artifact_test_final_report(&run_id);
        write_final_report(&mut writer, &final_report).expect("write final report");
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize run");
        let finalized = supervisor_status(&repo_path, run_id.clone()).expect("status finalized");
        assert!(finalized.final_report_exists);

        let report_path = repo_path
            .join(RunArtifactFamily::Supervise.run_root())
            .join(run_id.as_str())
            .join(RunArtifactFamily::Supervise.final_report_relative_path());
        fs::remove_file(&report_path).expect("remove manifested report");
        let error = supervisor_status(&repo_path, run_id)
            .expect_err("corrupt finalized run must not appear active");
        assert!(
            error.to_string().contains("verified finalized artifact")
                || error.to_string().contains("missing")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_run_entry_creates_and_materializes_assignment_worktree() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(false);
        let plan = injected_plan(assignment.clone(), 0);
        let mut options = injected_options(
            &repo_path,
            temp.path(),
            "verified-capability-assignment-create",
        );
        options.allow_dirty_primary = false;
        fs::write(
            &options.plan_file,
            serde_json::to_vec(&plan).expect("serialize verified supervisor plan"),
        )
        .expect("write verified supervisor plan");

        let mut launched = false;
        let mut runner = |command: &ExternalAgentCommand| {
            launched = true;
            assert_ne!(command.cwd, repo_path);
            assert_eq!(
                fs::read_to_string(command.cwd.join("README.md"))
                    .expect("read materialized assignment worktree"),
                "baseline\n"
            );
            write_injected_json(
                &command.output_last_message,
                &injected_child_report(&assignment),
            );
            injected_verified_run(command)
        };

        let report = run_supervisor_plan_file_with_runner(options, &mut runner)
            .expect("run verified supervisor entry with injected external boundary");

        assert!(launched, "runner was not launched; report: {report:#?}");
        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(report.orchestrator_reports.len(), 1);
        let records = WorktreeManager::new(&repo_path)
            .list_managed_verified()
            .expect("list verified assignment worktree");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "child-a");
        assert_eq!(records[0].branch, "maco/child-a");
        let primary_head = current_head_oid(&repo_path).expect("read primary HEAD");
        let child_head = current_head_oid(&records[0].path).expect("read assignment HEAD");
        assert_eq!(child_head, primary_head);
        let child_repo = Repository::open(&records[0].path).expect("open assignment worktree");
        assert!(
            !repository_is_dirty(&child_repo, "inspect materialized assignment cleanliness")
                .expect("inspect materialized assignment cleanliness")
        );
        let lease = WorktreeManager::new(&repo_path)
            .acquire_write_execution_lease("child-a")
            .expect("assignment write lease must be available after run");
        assert_eq!(lease.record().path, records[0].path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_run_entry_refuses_dirty_repository_before_assignment_creation() {
        let (temp, repo_path) = injected_repository();
        let plan = injected_plan(injected_assignment(false), 0);
        let mut options =
            injected_options(&repo_path, temp.path(), "verified-capability-dirty-primary");
        options.allow_dirty_primary = true;
        fs::write(
            &options.plan_file,
            serde_json::to_vec(&plan).expect("serialize dirty-primary supervisor plan"),
        )
        .expect("write dirty-primary supervisor plan");
        fs::write(repo_path.join("README.md"), "dirty\n").expect("dirty primary repository");

        let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
            panic!("dirty primary must be refused before an external child launch")
        };
        let error = run_supervisor_plan_file_with_runner(options, &mut runner)
            .expect_err("dirty primary must be refused at verified run entry");

        assert!(format!("{error:#}").contains("primary repository is dirty"));
        assert!(!repo_path
            .join(".maco/o2/runs/verified-capability-dirty-primary")
            .exists());
        assert!(!temp.path().join(".maco/worktrees/repo/child-a").exists());
        assert!(Repository::open(&repo_path)
            .expect("reopen dirty primary")
            .find_branch("maco/child-a", git2::BranchType::Local)
            .is_err());
    }

    #[test]
    fn dirty_primary_refusal_is_written_and_finalized_without_launching_a_child() {
        let (temp, repo_path) = injected_repository();
        fs::write(repo_path.join("README.md"), "dirty\n").expect("dirty primary");
        let mut plan = injected_plan(injected_assignment(false), 0);
        plan.assignments.clear();
        let mut options = injected_options(&repo_path, temp.path(), "dirty-primary-finalized");
        options.runtime = SupervisorRuntime::Fake;
        options.allow_dirty_primary = false;
        let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
            panic!("dirty-primary refusal must not launch an external child")
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("dirty-primary refusal should remain a finalized report");
        assert!(!report.success);
        assert!(!report.publishable);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("dirty primary worktree")));
        let run_id = RunId::new("dirty-primary-finalized").expect("valid run id");
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized dirty-primary refusal");
        assert!(!reader.finalization().publishable);
        let restored = read_supervisor_final_report(&reader).expect("read finalized refusal");
        assert!(!restored.success);
    }

    #[test]
    fn fake_supervise_run_finalizes_manifested_report_tree_events() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let run_id = RunId::new("fake-orchestration-events").expect("valid run id");
        let mut options = injected_options(&repo_path, temp.path(), run_id.as_str());
        options.runtime = SupervisorRuntime::Fake;
        let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
            panic!("fake runtime must not invoke the external runner")
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run fake supervise journal fixture");
        assert!(report.success, "unexpected failed report: {report:#?}");

        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized fake supervise run");
        let journal_record = reader
            .finalization()
            .files
            .iter()
            .find(|record| record.path == Path::new(ORCHESTRATION_EVENT_PATH))
            .expect("manifested orchestration journal");
        assert_eq!(
            journal_record.disposition,
            ArtifactFileDisposition::PrivateEvidence
        );
        let events = read_finalized_orchestration_events(&reader);
        assert!(!events.is_empty());
        let repository_id = repository_authenticator_key_only(&repo_path)
            .expect("open repository authenticator")
            .binding()
            .repository_id
            .clone();
        for event in &events {
            assert_eq!(event.repo, repository_id);
            assert_eq!(event.run, run_id.as_str());
            assert_eq!(event.ts.len(), 20);
            assert!(event.ts.ends_with('Z'));
        }

        assert!(events.iter().any(|event| {
            event.node == assignment.id
                && event.parent.as_deref() == Some(run_id.as_str())
                && event.role == OrchestrationRole::Orchestrator
                && event.kind == OrchestrationEventKind::Spawn
                && event.payload["attempt"] == 1
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a"
                && event.parent.as_deref() == Some(assignment.id.as_str())
                && event.role == OrchestrationRole::Worker
                && event.kind == OrchestrationEventKind::Journal
                && event.payload["status"] == "loaded"
        }));
        let expected_auditor_id = parent_auditor_id(&assignment);
        assert!(events.iter().any(|event| {
            event.node == expected_auditor_id
                && event.parent.as_deref() == Some(assignment.id.as_str())
                && event.role == OrchestrationRole::Auditor
                && event.kind == OrchestrationEventKind::Spawn
        }));

        for orchestrator in &report.orchestrator_reports {
            for worker in &orchestrator.worker_reports {
                assert_final_decision_event(
                    &events,
                    &worker.id,
                    &orchestrator.id,
                    OrchestrationRole::Worker,
                    worker,
                );
            }
            for auditor in &orchestrator.audit_reports {
                assert_final_decision_event(
                    &events,
                    &auditor.id,
                    &orchestrator.id,
                    OrchestrationRole::Auditor,
                    auditor,
                );
            }
            assert_final_decision_event(
                &events,
                &orchestrator.id,
                run_id.as_str(),
                OrchestrationRole::Orchestrator,
                orchestrator,
            );
        }
        assert!(events.iter().any(|event| {
            event.node == run_id.as_str()
                && event.parent.is_none()
                && event.role == OrchestrationRole::Supervisor
                && event.kind == OrchestrationEventKind::Gate
                && event.payload["success"] == report.success
        }));
        assert!(events.iter().any(|event| {
            event.node == run_id.as_str()
                && event.parent.is_none()
                && event.role == OrchestrationRole::Supervisor
                && event.kind == OrchestrationEventKind::Status
                && event.payload["status"] == "final"
        }));
    }

    #[test]
    fn journal_append_failure_does_not_block_fake_run_finalization() {
        let (temp, repo_path) = injected_repository();
        let mut plan = injected_plan(injected_assignment(false), 0);
        plan.assignments.clear();
        let run_id = RunId::new("journal-failure-isolated").expect("valid run id");
        let mut options = injected_options(&repo_path, temp.path(), run_id.as_str());
        options.runtime = SupervisorRuntime::Fake;
        let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
            panic!("empty fake plan must not invoke the external runner")
        };
        set_orchestration_event_append_fault();

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("journal failure must not abort supervise finalization");
        assert!(report.success, "unexpected failed report: {report:#?}");
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized run after journal failure");
        assert!(reader
            .read(ORCHESTRATION_EVENT_PATH)
            .expect_err("disabled journal must not create an unmanifested artifact")
            .to_string()
            .contains("not present in the finalized manifest"));
        assert!(
            read_supervisor_final_report(&reader)
                .expect("read finalized report after journal failure")
                .success
        );
    }

    #[test]
    fn unverified_child_attempt_launches_neither_retry_nor_parent_auditor() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let repo = Repository::init(temp.path()).expect("initialize repository");
        fs::write(temp.path().join("README.md"), "baseline\n").expect("write baseline");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage baseline");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("create signature");
        repo.commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit baseline");
        drop(tree);
        drop(repo);

        let assignment_id = "child-unverified";
        let worker_id = "worker-unverified";
        let plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "stop after unverified containment".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 1,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            assignments: vec![OrchestratorAssignment {
                id: assignment_id.to_string(),
                role: AgentRole::ChildOrchestrator,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                worker_assignments: vec![WorkerAssignment {
                    id: worker_id.to_string(),
                    role: AgentRole::Worker,
                    assigned_paths: vec![PathBuf::from("README.md")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    task: None,
                    report_path: None,
                }],
                notes: None,
            }],
        };
        let options = SupervisorRunOptions {
            repo: temp.path().to_path_buf(),
            plan_file: temp.path().join("plan.json"),
            run_id: RunId::new("unverified-containment-stops-followups").expect("valid run id"),
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
        };

        let child_report = |id: &str| OrchestratorReviewReport {
            id: id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            worker_reports: vec![WorkerReport {
                id: worker_id.to_string(),
                role: AgentRole::Worker,
                assignment_kind: AssignmentKind::Ordinary,
                target_path: None,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                claim_token: None,
                semantic_intent_token: None,
                commands_run: Vec::new(),
                files_changed: Vec::new(),
                validation_results: Vec::new(),
                findings: Vec::new(),
                bloated_file_flags: Vec::new(),
                decomposition_completion: None,
                no_further_delegation: Some(true),
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: "none".to_string(),
                next_safe_action: "review".to_string(),
            }],
            audit_reports: Vec::new(),
            decomposition_completions: Vec::new(),
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        };
        let auditor_report = AuditorReport {
            id: format!("{assignment_id}-review-auditor"),
            role: AgentRole::Auditor,
            reviewed_worker_ids: vec![worker_id.to_string()],
            reviewed_paths: vec![PathBuf::from("README.md")],
            commands_run: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            no_further_delegation: Some(true),
            read_only: true,
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        };
        let mut invocations = Vec::new();
        let error = {
            let mut runner = |command: &ExternalAgentCommand| {
                let report_name = command
                    .output_last_message
                    .file_name()
                    .and_then(OsStr::to_str)
                    .expect("UTF-8 report filename");
                invocations.push(report_name.to_string());
                let first_attempt = report_name.ends_with(".attempt-1.json");
                let contents = if report_name.contains("review-auditor") {
                    serde_json::to_vec(&auditor_report).expect("serialize auditor report")
                } else {
                    let id = if first_attempt {
                        "wrong-child-id"
                    } else {
                        assignment_id
                    };
                    serde_json::to_vec(&child_report(id)).expect("serialize child report")
                };
                fs::write(&command.output_last_message, &contents).expect("write injected report");
                let run = ExternalAgentRun {
                    command: vec!["injected-runner".to_string()],
                    cwd: command.cwd.clone(),
                    timeout_seconds: command.timeout.as_secs(),
                    exit_code: Some(0),
                    duration_ms: 1,
                    timed_out: false,
                    process_tree: Some(if first_attempt {
                        ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
                    } else {
                        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
                    }),
                    side_effects: Some(SideEffectConfinementEvidence::Verified(
                        SideEffectConfinementProfileKind::ExternalCodex,
                    )),
                    publishable: !first_attempt,
                    program_trust: ExternalProgramTrust::TrustedSystemCodex,
                    codex_permissions: (!first_attempt).then_some(CodexPermissionEvidence {
                        codex_version: "0.142.3".to_string(),
                        minimum_version: "0.138.0".to_string(),
                        permission_profile: "maco_external_codex".to_string(),
                        workspace_access: command.workspace_access,
                        network_enabled: false,
                        argv_digest: "digest".to_string(),
                        executable_identity: "identity".to_string(),
                    }),
                    stdout: CapturedOutput::default(),
                    stderr: CapturedOutput::default(),
                    error: None,
                    output_last_message: Some(contents),
                };
                injected_target_attempted(run)
            };

            run_supervisor_plan_with_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                SupervisorExecutionRuntime::NonpublishableSimulation,
                &mut runner,
            )
            .expect_err("unverified process quiescence must leave the run unfinalized")
        };

        assert_eq!(invocations.len(), 1, "unexpected external follow-up launch");
        assert_eq!(
            invocations
                .iter()
                .filter(|name| name.ends_with(".attempt-2.json"))
                .count(),
            0,
            "unverified attempt launched a corrective retry"
        );
        assert_eq!(
            invocations
                .iter()
                .filter(|name| name.contains("review-auditor"))
                .count(),
            0,
            "unverified attempt launched a parent auditor"
        );
        assert!(error.to_string().contains("outstanding scratch"));
        let run_root = temp
            .path()
            .join(".maco/o2/runs/unverified-containment-stops-followups");
        assert!(run_root.join("incoming").exists());
        assert!(run_root.join("capture").exists());
        assert!(!run_root.join(ARTIFACT_FINALIZATION_MARKER).exists());
        let report: SupervisorFinalReport = serde_json::from_slice(
            &fs::read(run_root.join("reports/supervisor-final.json"))
                .expect("read structured unfinalized supervisor report"),
        )
        .expect("parse structured unfinalized supervisor report");
        assert!(!report.success);
        assert!(!report.publishable);
        assert!(report.remaining_risk.contains("verified-empty containment"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("not verified empty")));
    }

    #[test]
    fn injected_report_validation_preserves_worker_and_auditor_failure_coverage() {
        let assignment = injected_assignment(true);

        let mut missing_worker = injected_child_report(&assignment);
        missing_worker.worker_reports.clear();
        validate_worker_report_delegation_attestations(
            &assignment,
            Path::new("missing-worker.json"),
            &mut missing_worker,
        );
        assert_eq!(missing_worker.status, ReviewStatus::Failed);
        assert!(finding_messages(&missing_worker).contains("omitted required worker reports"));

        let mut delegated = injected_child_report(&assignment);
        delegated.worker_reports[0].no_further_delegation = Some(false);
        validate_worker_report_delegation_attestations(
            &assignment,
            Path::new("delegated-worker.json"),
            &mut delegated,
        );
        assert_eq!(delegated.status, ReviewStatus::Failed);
        assert!(finding_messages(&delegated).contains("no-delegation attestation"));

        let mut unauthorized = injected_child_report(&assignment);
        unauthorized.files_changed = vec![PathBuf::from("Cargo.toml")];
        unauthorized.worker_reports[0].files_changed = vec![PathBuf::from("Cargo.toml")];
        validate_worker_report_evidence(
            &assignment,
            &AssignmentMetadata::new(),
            Path::new("unauthorized-worker.json"),
            &mut unauthorized,
        );
        assert_eq!(unauthorized.status, ReviewStatus::Failed);
        assert!(finding_messages(&unauthorized).contains("outside its assigned_paths"));

        let mut inconsistent_validation = injected_child_report(&assignment);
        inconsistent_validation.worker_reports[0].validation_results[0].status =
            ReviewStatus::Failed;
        validate_worker_report_evidence(
            &assignment,
            &AssignmentMetadata::new(),
            Path::new("failed-validation.json"),
            &mut inconsistent_validation,
        );
        assert_eq!(inconsistent_validation.status, ReviewStatus::Failed);
        assert!(finding_messages(&inconsistent_validation).contains("failed validation"));

        let mut missing_auditor = injected_child_report(&assignment);
        validate_auditor_reports(
            &assignment,
            Path::new("missing-auditor.json"),
            &mut missing_auditor,
        );
        assert_eq!(missing_auditor.status, ReviewStatus::Failed);
        assert!(finding_messages(&missing_auditor).contains("omitted required review auditor"));

        let mut bad_auditor = injected_child_report(&assignment);
        let mut auditor = injected_auditor_report(&assignment, &bad_auditor);
        auditor.reviewed_paths = vec![PathBuf::from("Cargo.toml")];
        auditor.commands_run.push(injected_command_record());
        bad_auditor.audit_reports.push(auditor);
        validate_auditor_reports(&assignment, Path::new("bad-auditor.json"), &mut bad_auditor);
        assert_eq!(bad_auditor.status, ReviewStatus::Failed);
        assert!(bad_auditor.audit_reports[0]
            .findings
            .iter()
            .any(|finding| finding.message.contains("reviewed_paths omitted")));
    }

    #[test]
    fn parent_auditor_coverage_ignores_non_repo_evidence_paths_without_voiding_report() {
        let assignment = injected_assignment(true);
        let mut child = injected_child_report(&assignment);
        let mut auditor = injected_auditor_report(&assignment, &child);
        let absolute_evidence_path = PathBuf::from("/tmp/evidence/log.txt");
        auditor.reviewed_paths.push(absolute_evidence_path.clone());
        auditor.commands_run.push(injected_command_record());
        child.audit_reports.push(auditor);

        validate_auditor_reports(&assignment, Path::new("absolute-evidence.json"), &mut child);

        assert_eq!(child.status, ReviewStatus::Succeeded);
        assert!(child.accepted);
        assert!(!child.rejected);
        assert!(child.audit_reports[0]
            .reviewed_paths
            .contains(&absolute_evidence_path));
        assert!(child.audit_reports[0].findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Warning
                && finding
                    .message
                    .contains("excluded from repository-relative coverage computation")
                && finding.paths == vec![absolute_evidence_path.clone()]
        }));
    }

    #[test]
    fn parent_auditor_coverage_rejects_only_non_repo_evidence_paths() {
        let assignment = injected_assignment(true);
        let mut child = injected_child_report(&assignment);
        let mut auditor = injected_auditor_report(&assignment, &child);
        auditor.reviewed_paths = vec![PathBuf::from("/tmp/evidence/log.txt")];
        auditor.commands_run.push(injected_command_record());
        child.audit_reports.push(auditor);

        validate_auditor_reports(
            &assignment,
            Path::new("absolute-only-evidence.json"),
            &mut child,
        );

        assert_eq!(child.status, ReviewStatus::Failed);
        assert!(child.audit_reports[0].findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Warning
                && finding
                    .message
                    .contains("excluded from repository-relative coverage computation")
        }));
        assert!(child.audit_reports[0].findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Error
                && finding.message.contains("reviewed_paths omitted")
        }));
    }

    #[test]
    fn injected_runner_retries_structural_report_once_then_runs_parent_auditor() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 1);
        let options = injected_options(&repo_path, temp.path(), "injected-retry");
        let mut invocations = Vec::new();
        let mut runner = |command: &ExternalAgentCommand| {
            assert_eq!(
                command
                    .output_last_message
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(OsStr::to_str),
                Some("incoming")
            );
            assert_eq!(
                command
                    .json_log
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(OsStr::to_str),
                Some("capture")
            );
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            invocations.push(name.clone());
            if name.contains("review-auditor") {
                let child = injected_child_report(&assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
            } else {
                let mut child = injected_child_report(&assignment);
                if name.ends_with("attempt-1.json") {
                    child.id = "wrong-id".to_string();
                }
                write_injected_json(&command.output_last_message, &child);
            }
            injected_verified_run(command)
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected retry");

        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(invocations.len(), 3);
        assert!(invocations
            .iter()
            .any(|name| name.ends_with("attempt-2.json")));
        assert!(invocations
            .iter()
            .any(|name| name.contains("review-auditor")));
        assert!(finding_messages(&report.orchestrator_reports[0])
            .contains("corrective retry attempt 2"));

        let run_root = repo_path.join(".maco/o2/runs/injected-retry");
        for relative in [
            "assignments/child-a.attempt-1.prompt.md",
            "assignments/child-a.attempt-2.prompt.md",
            "evidence/incoming/child-a.attempt-1.json",
            "evidence/incoming/child-a.attempt-2.json",
            "logs/workers/child-a/worker-a.jsonl",
            "reports/child-a.json",
            "reports/supervisor-final.json",
            ARTIFACT_FINALIZATION_MARKER,
        ] {
            assert!(run_root.join(relative).exists(), "missing {relative}");
        }
        assert!(!run_root.join("incoming").exists());
        assert!(!run_root.join("capture").exists());
        let corrective_prompt =
            fs::read_to_string(run_root.join("assignments/child-a.attempt-2.prompt.md"))
                .expect("read corrective prompt");
        assert!(corrective_prompt.contains("CORRECTIVE FEEDBACK:"));
        assert!(corrective_prompt.contains("does not match assignment"));
        let history = finding_messages(&report.orchestrator_reports[0]);
        assert!(history.contains("child attempt 1 history"));
        assert!(history.contains("child attempt 2 history"));
        assert!(history.contains("corrective_retry_used=true"));

        let run_id = RunId::new("injected-retry").expect("valid retry run id");
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized retry run");
        let events = read_finalized_orchestration_events(&reader);
        let attempts = events
            .iter()
            .filter(|event| {
                event.node == assignment.id
                    && event.role == OrchestrationRole::Orchestrator
                    && event.kind == OrchestrationEventKind::Spawn
            })
            .filter_map(|event| event.payload["attempt"].as_u64())
            .collect::<Vec<_>>();
        assert_eq!(attempts, vec![1, 2]);
        assert!(events.iter().any(|event| {
            event.node == assignment.id
                && event.kind == OrchestrationEventKind::Reject
                && event.payload["scope"] == "attempt"
                && event.payload["attempt"] == 1
        }));
    }

    #[test]
    fn concurrent_disjoint_assignments_make_progress_and_finalize_in_plan_order() {
        #[derive(Default)]
        struct GateState {
            started: BTreeSet<String>,
            child_b_finished: bool,
            scratch_roots: BTreeSet<PathBuf>,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "Cargo.toml"),
            injected_named_assignment("child-d", "RELEASE_NOTES.md"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-plan-order");
        let gate = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let runner = {
            let gate = Arc::clone(&gate);
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let active = in_flight.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                peak.fetch_max(active, Ordering::SeqCst);
                let (lock, condvar) = &*gate;
                let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                state.started.insert(id.clone());
                if let Some(root) = command.output_last_message.parent() {
                    state.scratch_roots.insert(root.to_path_buf());
                }
                condvar.notify_all();
                if id == "child-a" {
                    while !state.child_b_finished {
                        state = condvar
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else {
                    while !state.started.contains("child-a") {
                        state = condvar
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                drop(state);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                let run = injected_verified_run(command);
                in_flight.fetch_sub(1, Ordering::SeqCst);
                if id == "child-b" {
                    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.child_b_finished = true;
                    condvar.notify_all();
                }
                run
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("run two disjoint assignments");

        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b", "child-c", "child-d"]
        );
        assert_eq!(
            report
                .released_claims
                .iter()
                .map(|claim| claim.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b", "child-c", "child-d"]
        );
        assert_eq!(report.commands_run.len(), 4);

        let state = gate
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.scratch_roots.len(), 4);
        assert!(state.scratch_roots.iter().all(|path| {
            !path.ends_with("incoming")
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with("incoming-assignment-"))
        }));
        drop(state);

        let run_id = RunId::new("concurrent-plan-order").expect("valid run id");
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized concurrent artifacts");
        let journal = reader
            .read(ORCHESTRATION_EVENT_PATH)
            .expect("read synchronized event journal");
        assert!(journal.ends_with(b"\n"));
        for line in journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            serde_json::from_slice::<OrchestrationEvent>(line)
                .expect("event journal line must remain well formed");
        }
        let run_root = repo_path.join(".maco/o2/runs/concurrent-plan-order");
        for relative in [
            "evidence/incoming/child-a.json",
            "evidence/incoming/child-b.json",
            "evidence/incoming/child-c.json",
            "evidence/incoming/child-d.json",
            "reports/child-a.json",
            "reports/child-b.json",
            "reports/child-c.json",
            "reports/child-d.json",
        ] {
            assert!(run_root.join(relative).exists(), "missing {relative}");
        }
        assert!(fs::read_dir(&run_root)
            .expect("read finalized run root")
            .filter_map(std::result::Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with("incoming-") && !name.starts_with("capture-")
            }));
    }

    #[test]
    fn concurrent_scheduler_serializes_overlap_without_head_of_line_blocking() {
        #[derive(Default)]
        struct ScheduleState {
            events: Vec<String>,
            child_c_started: bool,
            child_a_finished: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "src"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-overlap-scan");
        let state = Arc::new((Mutex::new(ScheduleState::default()), Condvar::new()));
        let runner = {
            let state = Arc::clone(&state);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut schedule = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                schedule.events.push(format!("{id}-start"));
                if id == "child-c" {
                    schedule.child_c_started = true;
                    condvar.notify_all();
                }
                if id == "child-a" {
                    while !schedule.child_c_started {
                        schedule = condvar
                            .wait(schedule)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                if id == "child-b" {
                    assert!(schedule.child_a_finished);
                }
                drop(schedule);
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                let run = injected_verified_run(command);
                let mut schedule = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                schedule.events.push(format!("{id}-finish"));
                if id == "child-a" {
                    schedule.child_a_finished = true;
                    condvar.notify_all();
                }
                run
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("run overlap-aware scheduler");
        assert!(report.success, "unexpected failed report: {report:#?}");
        let schedule = state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let c_start = schedule
            .events
            .iter()
            .position(|event| event == "child-c-start")
            .expect("child C start");
        let a_finish = schedule
            .events
            .iter()
            .position(|event| event == "child-a-finish")
            .expect("child A finish");
        let b_start = schedule
            .events
            .iter()
            .position(|event| event == "child-b-start")
            .expect("child B start");
        assert!(c_start < a_finish, "{:?}", schedule.events);
        assert!(b_start > a_finish, "{:?}", schedule.events);
    }

    #[test]
    fn scoped_spawn_failure_records_fatal_index_and_stops_new_scheduling() {
        let mut indexed_outcomes = (0..3)
            .map(|_| None)
            .collect::<Vec<Option<AssignmentExecutionOutcome>>>();
        let mut stop_scheduling = false;
        record_assignment_spawn_failure(
            &mut indexed_outcomes,
            &mut stop_scheduling,
            1,
            "child-b",
            &std::io::Error::other("injected scoped spawn failure"),
        )
        .expect("record injected spawn failure");

        assert!(stop_scheduling);
        assert!(indexed_outcomes[0].is_none());
        assert!(indexed_outcomes[2].is_none());
        let outcome = indexed_outcomes[1]
            .as_ref()
            .expect("spawn failure outcome at plan index");
        assert!(outcome.requires_scheduler_abort());
        assert!(outcome
            .fatal_error
            .as_deref()
            .is_some_and(|message| message.contains("child-b")
                && message.contains("injected scoped spawn failure")));
    }

    #[test]
    fn serial_overlapping_assignments_release_between_slots_with_legacy_scratch_names() {
        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "src"),
            injected_named_assignment("child-b", "src/lib.rs"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "serial-overlap-release");
        let invocations = Arc::new(Mutex::new(Vec::new()));
        let runner = {
            let assignments = assignments.clone();
            let invocations = Arc::clone(&invocations);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                invocations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((
                        id.clone(),
                        command
                            .output_last_message
                            .parent()
                            .and_then(Path::file_name)
                            .and_then(OsStr::to_str)
                            .unwrap_or_default()
                            .to_string(),
                        command
                            .json_log
                            .parent()
                            .and_then(Path::file_name)
                            .and_then(OsStr::to_str)
                            .unwrap_or_default()
                            .to_string(),
                    ));
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            1,
            &runner,
        )
        .expect("run serial overlapping assignments");
        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b"]
        );
        assert_eq!(
            report
                .released_claims
                .iter()
                .map(|claim| claim.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b"]
        );
        assert_eq!(
            *invocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![
                (
                    "child-a".to_string(),
                    "incoming".to_string(),
                    "capture".to_string()
                ),
                (
                    "child-b".to_string(),
                    "incoming".to_string(),
                    "capture".to_string()
                ),
            ]
        );
    }

    #[test]
    fn semantic_warn_previews_are_plan_ordered_once_at_serial_and_concurrent_bounds() {
        for max_concurrent_children in [1usize, 2] {
            let (temp, repo_path) = injected_repository();
            fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
            fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
                .expect("write injected Rust source");
            commit_injected_repository(&repo_path, "add semantic fixture");
            let mut assignments = vec![
                injected_named_assignment("child-a", "README.md"),
                injected_named_assignment("child-b", "src/lib.rs"),
            ];
            for assignment in &mut assignments {
                assignment.semantic_symbols = vec!["Shared".to_string()];
            }
            let mut plan = injected_multi_plan(assignments.clone(), 0);
            plan.semantic_coordination = SemanticCoordinationMode::Warn;
            let run_id = format!("semantic-warn-plan-order-{max_concurrent_children}");
            let options = injected_options(&repo_path, temp.path(), &run_id);
            let runner = move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            };

            let report = run_supervisor_plan_with_concurrent_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                max_concurrent_children,
                &runner,
            )
            .expect("run deterministic semantic warn preview");
            assert!(report.success, "unexpected failed report: {report:#?}");
            let warnings = report
                .findings
                .iter()
                .filter(|finding| {
                    finding
                        .message
                        .contains("semantic coordination warn-mode preview")
                })
                .collect::<Vec<_>>();
            assert_eq!(warnings.len(), 1, "unexpected warnings: {warnings:#?}");
            assert!(warnings[0].message.contains("assignment 'child-b'"));
        }

        let (temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
            .expect("write injected Rust source");
        commit_injected_repository(&repo_path, "add serial warn failure fixture");
        let sync_store = SyncStore::open(&repo_path).expect("open injected sync store");
        let external_claim = sync_store
            .claim_paths("external-owner", [PathBuf::from("README.md")])
            .expect("reserve first serial assignment path");
        let mut assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
        ];
        for assignment in &mut assignments {
            assignment.semantic_symbols = vec!["Shared".to_string()];
        }
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Warn;
        let options = injected_options(&repo_path, temp.path(), "serial-warn-early-failure");
        let runner = move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        };
        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            1,
            &runner,
        )
        .expect("serial warn early failure remains reportable");
        sync_store
            .release(external_claim.token)
            .expect("release serial warn external claim");
        assert!(!report.success);
        assert!(report.findings.iter().all(|finding| !finding
            .message
            .contains("semantic coordination warn-mode preview")));
    }

    #[test]
    fn semantic_resolution_failure_does_not_stop_healthy_assignment_at_any_bound() {
        for (case, semantic_coordination, max_concurrent_children) in [
            ("warn-serial", SemanticCoordinationMode::Warn, 1usize),
            ("warn-concurrent", SemanticCoordinationMode::Warn, 2usize),
            ("block-concurrent", SemanticCoordinationMode::Block, 2usize),
        ] {
            let (temp, repo_path) = injected_repository();
            fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
            fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
                .expect("write injected Rust source");
            commit_injected_repository(&repo_path, "add semantic resolution fixture");
            let mut assignments = vec![
                injected_named_assignment("bad-semantic", "README.md"),
                injected_named_assignment("healthy-semantic", "src/lib.rs"),
            ];
            assignments[0].semantic_symbols = vec!["MissingSymbol".to_string()];
            assignments[1].semantic_symbols = vec!["Shared".to_string()];
            let mut plan = injected_multi_plan(assignments.clone(), 0);
            plan.semantic_coordination = semantic_coordination;
            let options = injected_options(
                &repo_path,
                temp.path(),
                &format!("semantic-resolution-isolation-{case}"),
            );
            let started = Arc::new(Mutex::new(Vec::new()));
            let runner = {
                let assignments = assignments.clone();
                let started = Arc::clone(&started);
                move |command: &ExternalAgentCommand| {
                    let id = injected_command_assignment_id(command);
                    started
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(id.clone());
                    let assignment = assignments
                        .iter()
                        .find(|assignment| assignment.id == id)
                        .unwrap_or_else(|| panic!("missing assignment {id}"));
                    write_injected_assignment_report(command, assignment);
                    injected_verified_run(command)
                }
            };

            let report = run_supervisor_plan_with_concurrent_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                max_concurrent_children,
                &runner,
            )
            .expect("semantic resolution failure remains assignment-local");
            assert!(!report.success);
            assert_eq!(
                *started
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
                vec!["healthy-semantic".to_string()],
                "case {case}"
            );
            assert_eq!(
                report
                    .orchestrator_reports
                    .iter()
                    .map(|item| item.id.as_str())
                    .collect::<Vec<_>>(),
                vec!["healthy-semantic"],
                "case {case}"
            );
            assert!(report.findings.iter().any(|finding| finding
                .message
                .contains("bad-semantic' failed during semantic resolution: unresolved semantic symbol: MissingSymbol")),
                "case {case}: {:?}", report.findings);
        }
    }

    #[test]
    fn semantic_block_claims_follow_actual_dispatch_order_with_overlap_scan_ahead() {
        #[derive(Default)]
        struct BlockState {
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Alpha;\npub struct Beta;\npub struct Gamma;\n",
        )
        .expect("write injected Rust source");
        commit_injected_repository(&repo_path, "add Block semantic fixture");
        let mut assignments = vec![
            injected_named_assignment("child-a", "src"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md"),
        ];
        assignments[0].semantic_symbols = vec!["Alpha".to_string()];
        assignments[1].semantic_symbols = vec!["Beta".to_string()];
        assignments[2].semantic_symbols = vec!["Gamma".to_string()];
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Block;
        let options = injected_options(&repo_path, temp.path(), "semantic-block-dispatch-order");
        let state = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut block = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-c" {
                    block.child_c_started = true;
                    condvar.notify_all();
                } else if id == "child-a" {
                    while !block.child_c_started {
                        block = condvar
                            .wait(block)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                drop(block);
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("run deterministic semantic Block scheduling");
        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(
            report
                .released_semantic_intents
                .iter()
                .map(|intent| (intent.agent_id.as_str(), intent.token.get()))
                .collect::<Vec<_>>(),
            vec![("child-a", 1), ("child-b", 3), ("child-c", 2)]
        );
    }

    #[test]
    fn claim_and_semantic_block_conflicts_fail_only_the_affected_assignment() {
        let (temp, repo_path) = injected_repository();
        let sync_store = SyncStore::open(&repo_path).expect("open injected sync store");
        let external_claim = sync_store
            .claim_paths("external-owner", [PathBuf::from("README.md")])
            .expect("reserve injected conflicting claim");
        let assignments = vec![
            injected_named_assignment("claim-blocked", "README.md"),
            injected_named_assignment("claim-healthy", "src/lib.rs"),
        ];
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Block;
        let options = injected_options(&repo_path, temp.path(), "claim-conflict-isolation");
        let started = Arc::new(Mutex::new(Vec::new()));
        let runner = {
            let assignments = assignments.clone();
            let started = Arc::clone(&started);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                started
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(id.clone());
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };
        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("claim conflict remains assignment-local");
        sync_store
            .release(external_claim.token)
            .expect("release injected external claim");
        assert!(!report.success);
        assert_eq!(
            *started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec!["claim-healthy".to_string()]
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("claim")));

        #[derive(Default)]
        struct SemanticConflictState {
            child_c_started: bool,
            blocked_runner_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Shared;\npub struct Gamma;\n",
        )
        .expect("write injected Rust source");
        commit_injected_repository(&repo_path, "add semantic conflict fixture");
        let mut assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "Cargo.toml"),
        ];
        assignments[0].semantic_symbols = vec!["Shared".to_string()];
        assignments[1].semantic_symbols = vec!["Shared".to_string()];
        assignments[2].semantic_symbols = vec!["Gamma".to_string()];
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Block;
        let options = injected_options(&repo_path, temp.path(), "semantic-block-isolation");
        let state = Arc::new((Mutex::new(SemanticConflictState::default()), Condvar::new()));
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut conflict = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-b" {
                    conflict.blocked_runner_started = true;
                } else if id == "child-c" {
                    conflict.child_c_started = true;
                    condvar.notify_all();
                } else if id == "child-a" {
                    while !conflict.child_c_started {
                        conflict = condvar
                            .wait(conflict)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                drop(conflict);
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };
        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("semantic Block conflict remains assignment-local");
        assert!(!report.success);
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-c"]
        );
        let conflict = state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(conflict.child_c_started);
        assert!(!conflict.blocked_runner_started);
        assert!(report.findings.iter().any(|finding| finding
            .message
            .contains("semantic coordination blocked assignment 'child-b'")));
    }

    #[test]
    fn concurrent_failure_isolated_and_retry_retains_assignment_slot() {
        #[derive(Default)]
        struct RetryState {
            events: Vec<String>,
            child_b_started: bool,
            child_a_retry_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "Cargo.toml"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 1);
        let options = injected_options(&repo_path, temp.path(), "concurrent-retry-slot");
        let state = Arc::new((Mutex::new(RetryState::default()), Condvar::new()));
        let runner = {
            let state = Arc::clone(&state);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let file_name = command
                    .output_last_message
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default();
                let attempt = if file_name.contains("attempt-2") {
                    2
                } else {
                    1
                };
                let (lock, condvar) = &*state;
                let mut retry = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                retry.events.push(format!("{id}-attempt-{attempt}"));
                if id == "child-b" {
                    retry.child_b_started = true;
                    condvar.notify_all();
                    while !retry.child_a_retry_started {
                        retry = condvar
                            .wait(retry)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                if id == "child-a" && attempt == 1 {
                    while !retry.child_b_started {
                        retry = condvar
                            .wait(retry)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                if id == "child-a" && attempt == 2 {
                    retry.child_a_retry_started = true;
                    condvar.notify_all();
                }
                if id == "child-c" {
                    assert!(retry.child_a_retry_started);
                }
                drop(retry);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                let mut report = injected_child_report(assignment);
                if id == "child-a" && attempt == 1 {
                    report.id = "wrong-id".to_string();
                }
                write_injected_json(&command.output_last_message, &report);
                injected_verified_run(command)
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("run retry slot scheduler");
        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b", "child-c"]
        );
        let retry = state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retry_start = retry
            .events
            .iter()
            .position(|event| event == "child-a-attempt-2")
            .expect("child A retry start");
        let child_c_start = retry
            .events
            .iter()
            .position(|event| event == "child-c-attempt-1")
            .expect("child C start");
        assert!(retry_start < child_c_start, "{:?}", retry.events);

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("failed-child", "README.md"),
            injected_named_assignment("healthy-child", "src/lib.rs"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-failure-isolation");
        let started = Arc::new(Mutex::new(BTreeSet::new()));
        let runner = {
            let started = Arc::clone(&started);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                started
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(id.clone());
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                let mut report = injected_child_report(assignment);
                if id == "failed-child" {
                    report.accepted = false;
                    report.rejected = true;
                    report.status = ReviewStatus::Failed;
                }
                write_injected_json(&command.output_last_message, &report);
                injected_verified_run(command)
            }
        };
        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("normal child failure remains a finalized report");
        assert!(!report.success);
        assert!(report.breaker_trip.is_none());
        assert_eq!(report.orchestrator_reports.len(), 2);
        assert_eq!(
            started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            2
        );
    }

    #[test]
    fn cascade_breaker_stops_admission_drains_active_and_releases_claims() {
        #[derive(Default)]
        struct BreakerState {
            started: BTreeSet<String>,
            release_child_d: bool,
            child_d_finished: bool,
            child_d_observed_cancellation: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "Cargo.toml"),
            injected_named_assignment("child-d", "RELEASE_NOTES.md"),
            injected_named_assignment("child-e", "SECURITY.md"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "circuit-breaker-cascade");
        let state = Arc::new((Mutex::new(BreakerState::default()), Condvar::new()));
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand, cancellation: &ProcessCancellation| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                breaker.started.insert(id.clone());
                condvar.notify_all();
                if id == "child-b" {
                    while !breaker.started.contains("child-c") {
                        breaker = condvar
                            .wait(breaker)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-c" {
                    while !breaker.started.contains("child-d") {
                        breaker = condvar
                            .wait(breaker)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-d" {
                    while !breaker.release_child_d {
                        breaker.child_d_observed_cancellation |= cancellation.is_cancelled();
                        breaker = condvar
                            .wait(breaker)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                drop(breaker);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                let mut report = injected_child_report(assignment);
                if matches!(id.as_str(), "child-a" | "child-b" | "child-c") {
                    report.accepted = false;
                    report.rejected = true;
                    report.status = ReviewStatus::Rejected;
                }
                write_injected_json(&command.output_last_message, &report);
                let run = injected_verified_run(command);
                if id == "child-d" {
                    let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    breaker.child_d_finished = true;
                    condvar.notify_all();
                }
                run
            }
        };

        let (done_sender, done_receiver) = mpsc::channel();
        let supervisor_thread = thread::spawn(move || {
            let result = run_supervisor_plan_with_concurrent_cancellable_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                2,
                &runner,
            );
            let _ = done_sender.send(result);
        });

        let event_path = repo_path
            .join(".maco/o2/runs/circuit-breaker-cascade")
            .join(ORCHESTRATION_EVENT_PATH);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let breaker_recorded = fs::read_to_string(&event_path)
                .is_ok_and(|events| events.contains("swarm_health_circuit_breaker"));
            if breaker_recorded {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "breaker transition was not journaled before the deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let (lock, condvar) = &*state;
        let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(breaker.started.contains("child-d"));
        assert!(!breaker.started.contains("child-e"));
        assert!(!breaker.child_d_finished);
        assert!(!breaker.child_d_observed_cancellation);
        assert!(matches!(
            done_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        breaker.release_child_d = true;
        condvar.notify_all();
        drop(breaker);

        let report = done_receiver
            .recv()
            .expect("supervisor breaker result after active child drain")
            .expect("breaker trip remains reportable");
        supervisor_thread
            .join()
            .unwrap_or_else(|_| panic!("supervisor test thread panicked"));

        assert!(!report.success);
        assert_eq!(report.orchestrator_reports.len(), 4);
        assert_eq!(report.commands_run.len(), 4);
        assert_eq!(report.released_claims.len(), 4);
        assert!(report.release_errors.is_empty());
        assert!(matches!(
            report.breaker_trip.as_ref().map(|trip| &trip.reason),
            Some(CircuitBreakerTripReason::RepeatedRejectionLoop {
                rejections: 3,
                retries: 0,
                threshold: 3,
            })
        ));
        assert!(report
            .breaker_trip
            .as_ref()
            .is_some_and(|trip| trip.window.repeated_rejections == 3
                && trip
                    .recovery_guidance
                    .contains("pending assignments were not launched")));
        let breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(breaker.child_d_finished);
        assert!(!breaker.child_d_observed_cancellation);
        assert!(!breaker.started.contains("child-e"));
        drop(breaker);
        assert!(SyncStore::open(&repo_path)
            .expect("open claims after breaker drain")
            .snapshot()
            .expect("snapshot claims after breaker drain")
            .is_empty());

        let run_id = RunId::new("circuit-breaker-cascade").expect("valid breaker run id");
        let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized breaker artifacts");
        let events = read_finalized_orchestration_events(&reader);
        assert!(events.iter().any(|event| {
            event.kind == OrchestrationEventKind::Gate
                && event.payload["gate"] == "swarm_health_circuit_breaker"
                && event.payload["transition"] == "closed_to_open"
                && event.payload["trip"]["reason"]["kind"] == "repeated_rejection_loop"
        }));
    }

    #[test]
    fn contained_nonzero_child_failure_does_not_stop_pending_unrelated_assignment() {
        #[derive(Default)]
        struct FailureState {
            child_b_started: bool,
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "Cargo.toml"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "contained-nonzero-isolation");
        let state = Arc::new((Mutex::new(FailureState::default()), Condvar::new()));
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut failure = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-b" {
                    failure.child_b_started = true;
                    condvar.notify_all();
                    while !failure.child_c_started {
                        failure = condvar
                            .wait(failure)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-a" {
                    while !failure.child_b_started {
                        failure = condvar
                            .wait(failure)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-c" {
                    failure.child_c_started = true;
                    condvar.notify_all();
                }
                drop(failure);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                if id == "child-a" {
                    let run = injected_verified_nonzero_run(command, 7);
                    assert!(external_safety_verified(&run, SupervisorRuntime::Codex));
                    assert!(run.codex_permissions.is_some());
                    assert!(!run.publishable);
                    assert!(!run.succeeded());
                    run
                } else {
                    injected_verified_run(command)
                }
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("contained child failure remains reportable");
        assert!(!report.success);
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["child-a", "child-b", "child-c"]
        );
        assert!(
            state
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .child_c_started
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.message.contains("containment was not verified")));
    }

    #[test]
    fn fatal_scheduler_abort_stops_new_starts_and_joins_active_assignment() {
        #[derive(Default)]
        struct AbortState {
            child_a_returned: bool,
            child_b_started: bool,
            release_child_b: bool,
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md/blocked-after-fatal"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-fatal-join");
        let state = Arc::new((Mutex::new(AbortState::default()), Condvar::new()));
        let runner = {
            let state = Arc::clone(&state);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-b" {
                    abort.child_b_started = true;
                    condvar.notify_all();
                    while !abort.release_child_b {
                        abort = condvar
                            .wait(abort)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-a" {
                    while !abort.child_b_started {
                        abort = condvar
                            .wait(abort)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-c" {
                    abort.child_c_started = true;
                }
                drop(abort);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                let mut run = injected_verified_run(command);
                if id == "child-a" {
                    run.process_tree = Some(ProcessTreeEvidence::Unverified(
                        ContainmentBackend::SystemdUserService,
                    ));
                    let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    abort.child_a_returned = true;
                    condvar.notify_all();
                }
                run
            }
        };
        let (done_sender, done_receiver) = mpsc::channel();
        let supervisor_thread = thread::spawn(move || {
            let result = run_supervisor_plan_with_concurrent_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                2,
                &runner,
            );
            let _ = done_sender.send(result);
        });

        let (lock, condvar) = &*state;
        let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !abort.child_a_returned {
            abort = condvar
                .wait(abort)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        assert!(!abort.child_c_started);
        assert!(matches!(
            done_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        abort.release_child_b = true;
        condvar.notify_all();
        drop(abort);

        let report = done_receiver
            .recv()
            .expect("supervisor result after active child release")
            .expect("fatal containment result remains reportable");
        supervisor_thread
            .join()
            .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
        assert!(!report.success);
        let abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!abort.child_c_started);
        assert_eq!(report.orchestrator_reports.len(), 2);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("containment")));
    }

    #[test]
    fn fatal_scheduler_abort_cancels_active_sibling_without_manual_release() {
        #[derive(Default)]
        struct AbortState {
            child_b_started: bool,
            child_b_observed_cancellation: bool,
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md/blocked-after-fatal"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-fatal-cancels-active");
        let state = Arc::new((Mutex::new(AbortState::default()), Condvar::new()));
        let runner = {
            let state = Arc::clone(&state);
            let assignments = assignments.clone();
            move |command: &ExternalAgentCommand, cancellation: &ProcessCancellation| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                if id == "child-b" {
                    {
                        let mut abort =
                            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        abort.child_b_started = true;
                        condvar.notify_all();
                    }
                    while !cancellation.is_cancelled() {
                        thread::sleep(Duration::from_millis(1));
                    }
                    lock.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .child_b_observed_cancellation = true;
                } else if id == "child-a" {
                    let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    while !abort.child_b_started {
                        abort = condvar
                            .wait(abort)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-c" {
                    lock.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .child_c_started = true;
                }

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                let mut run = injected_verified_run(command);
                if id == "child-a" {
                    run.process_tree = Some(ProcessTreeEvidence::Unverified(
                        ContainmentBackend::SystemdUserService,
                    ));
                } else if id == "child-b" {
                    run.exit_code = None;
                    run.error = Some("cancelled by scheduler".to_string());
                }
                run
            }
        };

        let report = run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        )
        .expect("fatal containment result remains reportable");

        assert!(!report.success);
        let abort = state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(abort.child_b_observed_cancellation);
        assert!(!abort.child_c_started);
        assert_eq!(report.orchestrator_reports.len(), 2);
    }

    #[test]
    fn concurrent_release_error_stops_new_starts_and_joins_active_assignment() {
        #[derive(Default)]
        struct ReleaseState {
            child_a_returned: bool,
            child_b_started: bool,
            release_child_b: bool,
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md/blocked-after-release-error"),
        ];
        let plan = injected_multi_plan(assignments.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "concurrent-release-error-abort");
        let state = Arc::new((Mutex::new(ReleaseState::default()), Condvar::new()));
        let runner_repo = repo_path.clone();
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-b" {
                    release.child_b_started = true;
                    condvar.notify_all();
                    while !release.release_child_b {
                        release = condvar
                            .wait(release)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-a" {
                    while !release.child_b_started {
                        release = condvar
                            .wait(release)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-c" {
                    release.child_c_started = true;
                }
                drop(release);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                let run = injected_verified_run(command);
                if id == "child-a" {
                    let store = SyncStore::open(&runner_repo).expect("open injected sync store");
                    let claim = store
                        .snapshot()
                        .expect("snapshot injected claims")
                        .into_iter()
                        .find(|claim| claim.agent_id == id)
                        .expect("find child A claim");
                    store
                        .release(claim.token)
                        .expect("inject scheduler release failure");
                    let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    release.child_a_returned = true;
                    condvar.notify_all();
                }
                run
            }
        };
        let (done_sender, done_receiver) = mpsc::channel();
        let supervisor_thread = thread::spawn(move || {
            let result = run_supervisor_plan_with_concurrent_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                2,
                &runner,
            );
            let _ = done_sender.send(result);
        });

        let (lock, condvar) = &*state;
        let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !release.child_a_returned {
            release = condvar
                .wait(release)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        assert!(!release.child_c_started);
        assert!(matches!(
            done_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.release_child_b = true;
        condvar.notify_all();
        drop(release);

        let report = done_receiver
            .recv()
            .expect("supervisor result after release-error join")
            .expect("release error remains reportable");
        supervisor_thread
            .join()
            .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
        assert!(!report.success);
        assert!(
            !lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .child_c_started
        );
        assert_eq!(report.orchestrator_reports.len(), 2);
        assert_eq!(report.release_errors.len(), 1);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("cleanup failed")));
        assert!(SyncStore::open(&repo_path)
            .expect("reopen sync store")
            .snapshot()
            .expect("snapshot released claims")
            .is_empty());
    }

    #[test]
    fn panic_after_claim_releases_tokens_stops_pending_and_joins_active_assignment() {
        #[derive(Default)]
        struct PanicState {
            child_a_panicking: bool,
            child_b_started: bool,
            release_child_b: bool,
            child_c_started: bool,
        }

        let (temp, repo_path) = injected_repository();
        let assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md/blocked-after-panic"),
        ];
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Block;
        let options = injected_options(&repo_path, temp.path(), "concurrent-panic-token-release");
        let state = Arc::new((Mutex::new(PanicState::default()), Condvar::new()));
        let runner = {
            let assignments = assignments.clone();
            let state = Arc::clone(&state);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                let (lock, condvar) = &*state;
                let mut panic_state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if id == "child-b" {
                    panic_state.child_b_started = true;
                    condvar.notify_all();
                    while !panic_state.release_child_b {
                        panic_state = condvar
                            .wait(panic_state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                } else if id == "child-a" {
                    while !panic_state.child_b_started {
                        panic_state = condvar
                            .wait(panic_state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    panic_state.child_a_panicking = true;
                    condvar.notify_all();
                    drop(panic_state);
                    panic!("injected panic after assignment claim");
                } else if id == "child-c" {
                    panic_state.child_c_started = true;
                }
                drop(panic_state);

                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };
        let (done_sender, done_receiver) = mpsc::channel();
        let supervisor_thread = thread::spawn(move || {
            let result = run_supervisor_plan_with_concurrent_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                2,
                &runner,
            );
            let _ = done_sender.send(result);
        });

        let (lock, condvar) = &*state;
        let mut panic_state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !panic_state.child_a_panicking {
            panic_state = condvar
                .wait(panic_state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        assert!(!panic_state.child_c_started);
        assert!(matches!(
            done_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        panic_state.release_child_b = true;
        condvar.notify_all();
        drop(panic_state);

        let report = done_receiver
            .recv()
            .expect("supervisor result after panic join")
            .expect("panic remains reportable");
        supervisor_thread
            .join()
            .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
        assert!(!report.success);
        assert!(
            !lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .child_c_started
        );
        assert_eq!(report.orchestrator_reports.len(), 1);
        assert!(report.findings.iter().any(|finding| finding
            .message
            .contains("supervisor assignment 'child-a' panicked")));
        assert!(SyncStore::open(&repo_path)
            .expect("reopen sync store")
            .snapshot()
            .expect("snapshot released panic claims")
            .is_empty());
        assert!(SemanticIntentStore::open(&repo_path)
            .expect("reopen semantic store")
            .snapshot()
            .expect("snapshot released panic semantic intents")
            .is_empty());
    }

    #[test]
    fn supervise_holds_exclusive_worktree_lease_through_child_and_parent_auditor() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "injected-write-lease");
        let competing_manager = WorktreeManager::new(&repo_path);
        let mut invocation_count = 0usize;
        let mut runner = |command: &ExternalAgentCommand| {
            invocation_count = invocation_count.saturating_add(1);
            let read_error = competing_manager
                .acquire_read_execution_lease(&assignment.id)
                .expect_err("supervise write lease must exclude a concurrent reader");
            assert!(read_error.to_string().contains("shared read lease"));
            let write_error = competing_manager
                .acquire_write_execution_lease(&assignment.id)
                .expect_err("supervise write lease must exclude a concurrent writer");
            assert!(write_error.to_string().contains("exclusive write lease"));
            let remove_error = competing_manager
                .remove(&assignment.id, true, false)
                .expect_err("supervise write lease must exclude managed removal");
            assert!(remove_error
                .to_string()
                .contains("active cooperative execution lease"));

            let output_name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let lifecycle = command
                .agent_lifecycle
                .as_ref()
                .expect("supervise provider command must carry lifecycle identity");
            assert_eq!(lifecycle.registry_repo, repo_path);
            assert_eq!(lifecycle.run_id, "injected-write-lease");
            if output_name.contains("review-auditor") {
                assert_eq!(lifecycle.role, "auditor");
                assert_eq!(lifecycle.task_id, parent_auditor_id(&assignment));
                let child = injected_child_report(&assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
            } else {
                assert_eq!(lifecycle.role, "child_orchestrator");
                assert_eq!(lifecycle.task_id, assignment.id);
                write_injected_json(
                    &command.output_last_message,
                    &injected_child_report(&assignment),
                );
            }
            injected_verified_run(command)
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run write-lease regression");
        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(invocation_count, 2, "child and parent auditor must run");
        let read_after = competing_manager
            .acquire_read_execution_lease(&assignment.id)
            .expect("read lease must be available after supervise lifecycle");
        assert_eq!(read_after.record().name, assignment.id);
    }

    #[test]
    fn injected_runner_path_violation_blocks_retry_and_primary_mutations_fail_integrity_gate() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(false);
        let plan = injected_plan(assignment.clone(), 1);
        let options = injected_options(&repo_path, temp.path(), "injected-path-violation");
        let mut invocations = Vec::new();
        let mut runner = |command: &ExternalAgentCommand| {
            invocations.push(
                command
                    .output_last_message
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            fs::write(command.cwd.join("outside.txt"), "unauthorized\n")
                .expect("write unauthorized child path");
            let mut child = injected_child_report(&assignment);
            child.id = "wrong-id".to_string();
            child.files_changed = vec![PathBuf::from("outside.txt")];
            write_injected_json(&command.output_last_message, &child);
            injected_verified_run(command)
        };
        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected path violation");
        assert!(!report.success);
        assert!(!invocations
            .iter()
            .any(|name| name.ends_with("attempt-2.json")));
        assert!(finding_messages(&report.orchestrator_reports[0])
            .contains("outside its assigned paths"));

        for scenario in ["tracked", "untracked", "index", "commit"] {
            let (temp, repo_path) = injected_repository();
            let assignment = injected_assignment(false);
            let plan = injected_plan(assignment.clone(), 0);
            let options = injected_options(
                &repo_path,
                temp.path(),
                &format!("injected-primary-{scenario}"),
            );
            let primary = repo_path.clone();
            let mut runner = |command: &ExternalAgentCommand| {
                write_injected_json(
                    &command.output_last_message,
                    &injected_child_report(&assignment),
                );
                match scenario {
                    "tracked" => fs::write(primary.join("README.md"), "mutated\n")
                        .expect("mutate tracked primary"),
                    "untracked" => fs::write(primary.join("rogue.txt"), "mutated\n")
                        .expect("mutate untracked primary"),
                    "index" => fs::write(primary.join(".git/index"), b"invalid-index")
                        .expect("mutate primary index"),
                    "commit" => {
                        fs::write(primary.join("README.md"), "committed mutation\n")
                            .expect("write commit mutation");
                        commit_injected_repository(&primary, "primary mutation");
                    }
                    _ => unreachable!(),
                }
                injected_verified_run(command)
            };
            let report = run_supervisor_plan_with_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                SupervisorExecutionRuntime::NonpublishableSimulation,
                &mut runner,
            )
            .expect("run injected primary mutation");
            assert!(
                !report.success,
                "scenario {scenario} escaped integrity gate"
            );
            assert!(report
                .findings
                .iter()
                .any(|finding| finding.message.contains("primary")));
            assert!(report.release_errors.is_empty());
        }
    }

    #[test]
    #[cfg(unix)]
    fn parent_report_slots_reject_child_time_symlink_rebinding_without_clobbering_sentinels() {
        use std::os::unix::fs::symlink;

        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(false);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "parent-report-rebind");
        let child_sentinel = temp.path().join("child-sentinel");
        let final_sentinel = temp.path().join("final-sentinel");
        fs::write(&child_sentinel, "child untouched").expect("write child sentinel");
        fs::write(&final_sentinel, "final untouched").expect("write final sentinel");

        let mut runner = |command: &ExternalAgentCommand| {
            let run_root = command
                .output_last_message
                .parent()
                .and_then(Path::parent)
                .expect("incoming path under run root");
            let normalized = run_root.join("reports/child-a.json");
            let supervisor_final = run_root.join("reports/supervisor-final.json");
            fs::create_dir_all(
                normalized
                    .parent()
                    .expect("normalized report has parent directory"),
            )
            .expect("create reports directory");
            fs::set_permissions(
                normalized
                    .parent()
                    .expect("normalized report has parent directory"),
                <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .expect("private reports directory");
            remove_report_slot_if_present(&normalized).expect("remove reserved normalized report");
            symlink(&child_sentinel, &normalized).expect("rebind normalized report");
            remove_report_slot_if_present(&supervisor_final).expect("remove reserved final report");
            symlink(&final_sentinel, &supervisor_final).expect("rebind final report");
            write_injected_json(
                &command.output_last_message,
                &injected_child_report(&assignment),
            );
            injected_verified_run(command)
        };

        let error = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect_err("rebound supervisor final slot must fail closed");

        assert!(error
            .to_string()
            .contains("failed to write normalized supervisor final report"));
        assert_eq!(
            fs::read_to_string(&child_sentinel).expect("read child sentinel"),
            "child untouched"
        );
        assert_eq!(
            fs::read_to_string(&final_sentinel).expect("read final sentinel"),
            "final untouched"
        );
    }

    #[test]
    fn injected_parent_auditor_primary_mutation_is_rejected() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "injected-auditor-mutation");
        let primary = repo_path.clone();
        let mut runner = |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let child = injected_child_report(&assignment);
            if name.contains("review-auditor") {
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
                fs::write(primary.join("README.md"), "auditor mutation\n")
                    .expect("mutate primary during auditor");
            } else {
                write_injected_json(&command.output_last_message, &child);
            }
            injected_verified_run(command)
        };
        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected auditor mutation");
        assert!(!report.success);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("primary")));
    }

    #[test]
    fn injected_missing_child_or_auditor_and_failed_child_propagate_final_failure() {
        for scenario in [
            "missing-child",
            "failed-child",
            "failed-worker",
            "missing-auditor",
        ] {
            let (temp, repo_path) = injected_repository();
            let with_worker = matches!(
                scenario,
                "missing-child" | "failed-worker" | "missing-auditor"
            );
            let assignment = injected_assignment(with_worker);
            let plan = injected_plan(assignment.clone(), 0);
            let options =
                injected_options(&repo_path, temp.path(), &format!("injected-{scenario}"));
            let mut invocations = Vec::new();
            let mut runner = |command: &ExternalAgentCommand| {
                let name = command
                    .output_last_message
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default()
                    .to_string();
                invocations.push(name.clone());
                match scenario {
                    "missing-child" => {}
                    "failed-child" => {
                        let mut child = injected_child_report(&assignment);
                        child.status = ReviewStatus::Failed;
                        child.accepted = false;
                        child.rejected = true;
                        child.remaining_risk = "injected child failure".to_string();
                        write_injected_json(&command.output_last_message, &child);
                    }
                    "failed-worker" if name.contains("review-auditor") => {
                        let child = injected_child_report(&assignment);
                        write_injected_json(
                            &command.output_last_message,
                            &injected_auditor_report(&assignment, &child),
                        );
                    }
                    "failed-worker" => {
                        let mut child = injected_child_report(&assignment);
                        child.status = ReviewStatus::Failed;
                        child.accepted = false;
                        child.rejected = true;
                        child.worker_reports[0].status = ReviewStatus::Failed;
                        child.worker_reports[0].accepted = false;
                        child.worker_reports[0].rejected = true;
                        child.remaining_risk = "injected worker failure".to_string();
                        write_injected_json(&command.output_last_message, &child);
                    }
                    "missing-auditor" if !name.contains("review-auditor") => {
                        write_injected_json(
                            &command.output_last_message,
                            &injected_child_report(&assignment),
                        );
                    }
                    "missing-auditor" => {}
                    _ => unreachable!(),
                }
                injected_verified_run(command)
            };

            let report = run_supervisor_plan_with_runner(
                plan,
                SupervisorConsultantPlan::default(),
                options,
                SupervisorExecutionRuntime::NonpublishableSimulation,
                &mut runner,
            )
            .expect("collect injected missing or failed report");

            assert!(
                !report.success,
                "scenario {scenario} unexpectedly succeeded"
            );
            assert!(!report.accepted);
            assert!(report.rejected);
            assert_eq!(report.status, ReviewStatus::Failed);
            assert_eq!(
                invocations
                    .iter()
                    .filter(|name| name.contains("review-auditor"))
                    .count(),
                usize::from(matches!(scenario, "failed-worker" | "missing-auditor")),
                "scenario {scenario} launched the wrong follow-ups"
            );
            if scenario == "missing-child" {
                assert!(finding_messages(&report.orchestrator_reports[0])
                    .contains("required child report is missing or invalid"));
            }
            if scenario == "missing-auditor" {
                assert!(report.orchestrator_reports[0]
                    .audit_reports
                    .iter()
                    .any(report_failed));
            }
        }
    }

    #[test]
    fn injected_diff_reconciliation_rejects_unattributed_worker_diff() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "injected-diff-reconciliation");
        let mut runner = |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let child = injected_child_report(&assignment);
            if name.contains("review-auditor") {
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
            } else {
                fs::write(command.cwd.join("README.md"), "child worktree edit\n")
                    .expect("write assigned child diff");
                write_injected_json(&command.output_last_message, &child);
            }
            injected_verified_run(command)
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected diff reconciliation");

        assert!(!report.success);
        assert_eq!(report.files_changed, vec![PathBuf::from("README.md")]);
        let child = &report.orchestrator_reports[0];
        assert_eq!(child.files_changed, vec![PathBuf::from("README.md")]);
        assert_eq!(child.status, ReviewStatus::Failed);
        let messages = finding_messages(child);
        assert!(messages.contains("child-reported files_changed does not match actual"));
        assert!(messages.contains("worker files_changed union differs from actual"));
        assert!(messages.contains("observed-but-not-reported: README.md"));
    }

    #[test]
    fn injected_runner_rejects_missing_worker_execution_journal() {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), "injected-missing-journal");
        let mut runner = |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            if name.contains("review-auditor") {
                let child = injected_child_report(&assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
                return injected_verified_run(command);
            }
            write_injected_json(
                &command.output_last_message,
                &injected_child_report(&assignment),
            );
            injected_verified_run_without_journals(command)
        };

        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected missing journal");

        assert!(!report.success);
        let child = &report.orchestrator_reports[0];
        assert_eq!(child.status, ReviewStatus::Failed);
        assert!(finding_messages(child).contains("execution journal is missing"));
    }

    #[test]
    fn injected_schema_and_evidence_matrix_rejects_missing_fields_and_extra_workers() {
        let assignment = injected_assignment(true);
        let mut extra_worker = injected_child_report(&assignment);
        let mut undeclared = extra_worker.worker_reports[0].clone();
        undeclared.id = "worker-extra".to_string();
        undeclared.files_changed = vec![PathBuf::from("README.md")];
        extra_worker.worker_reports.push(undeclared);
        validate_worker_report_evidence(
            &assignment,
            &AssignmentMetadata::new(),
            Path::new("extra-worker.json"),
            &mut extra_worker,
        );
        assert_eq!(extra_worker.status, ReviewStatus::Failed);
        assert!(finding_messages(&extra_worker).contains("is not declared in assignment"));

        for scenario in [
            "reviewed-worker-ids",
            "reviewed-paths",
            "commands",
            "validation",
            "terminal-attestation",
            "read-only",
            "remaining-risk",
            "next-action",
        ] {
            let mut child = injected_child_report(&assignment);
            let mut auditor = injected_auditor_report(&assignment, &child);
            auditor.commands_run.push(injected_command_record());
            match scenario {
                "reviewed-worker-ids" => auditor.reviewed_worker_ids.clear(),
                "reviewed-paths" => auditor.reviewed_paths.clear(),
                "commands" => auditor.commands_run.clear(),
                "validation" => auditor.validation_results.clear(),
                "terminal-attestation" => auditor.no_further_delegation = None,
                "read-only" => auditor.read_only = false,
                "remaining-risk" => auditor.remaining_risk.clear(),
                "next-action" => auditor.next_safe_action.clear(),
                _ => unreachable!(),
            }
            child.audit_reports.push(auditor);
            validate_auditor_reports(&assignment, Path::new("auditor-evidence.json"), &mut child);
            assert_eq!(
                child.status,
                ReviewStatus::Failed,
                "missing {scenario} evidence was accepted"
            );
            assert!(child.audit_reports[0].findings.iter().any(|finding| {
                finding.severity == FindingSeverity::Error && finding.message.contains("omitted")
            }));
        }

        for (label, schema, required) in [
            (
                "orchestrator",
                orchestrator_report_schema_value(),
                &[
                    "decomposition_completions",
                    "worker_reports",
                    "audit_reports",
                    "remaining_risk",
                    "next_safe_action",
                ][..],
            ),
            (
                "worker",
                worker_report_schema_value(),
                &[
                    "assignment_kind",
                    "target_path",
                    "bloated_file_flags",
                    "decomposition_completion",
                    "no_further_delegation",
                    "validation_results",
                    "remaining_risk",
                ][..],
            ),
            (
                "auditor",
                auditor_report_schema_value(),
                &[
                    "reviewed_worker_ids",
                    "reviewed_paths",
                    "commands_run",
                    "validation_results",
                    "no_further_delegation",
                    "read_only",
                    "remaining_risk",
                    "next_safe_action",
                ][..],
            ),
        ] {
            assert_eq!(schema["additionalProperties"], false, "{label} schema open");
            let required_fields = schema["required"]
                .as_array()
                .expect("schema required array");
            for field in required {
                assert!(
                    required_fields.iter().any(|value| value == field),
                    "{label} schema omitted required field {field}"
                );
            }
        }
    }

    #[test]
    fn typed_decomposition_prompt_report_and_final_evidence_remain_gated() {
        let mut assignment = injected_assignment(true);
        assignment
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        assignment.worker_assignments[0]
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        let worker = &assignment.worker_assignments[0];
        let metadata = WorkerAssignmentMetadata {
            kind: AssignmentKind::MegafileDecomposition,
            target_path: Some(PathBuf::from("README.md")),
        };
        let assignment_metadata =
            BTreeMap::from([((assignment.id.clone(), worker.id.clone()), metadata.clone())]);

        let worker_value =
            worker_assignment_value(worker, &metadata).expect("serialize typed worker assignment");
        assert_eq!(worker_value["kind"], "megafile_decomposition");
        assert_eq!(worker_value["target_path"], "README.md");
        let assignment_value = orchestrator_assignment_value(&assignment, &assignment_metadata)
            .expect("serialize typed orchestrator assignment");
        assert_eq!(
            assignment_value["worker_assignments"][0]["kind"],
            "megafile_decomposition"
        );
        assert_eq!(
            assignment_value["worker_assignments"][0]["target_path"],
            "README.md"
        );

        let plan = injected_plan(assignment.clone(), 0);
        let prompt = worker_prompt_with_incoming_root(
            &plan,
            &assignment,
            worker,
            &metadata,
            Path::new("/tmp/maco-run"),
            Path::new("/tmp/maco-run/incoming"),
            Path::new("/tmp/maco-run/schemas/worker-report.schema.json"),
        )
        .expect("render typed worker prompt");
        assert!(prompt.contains("Assignment kind: megafile_decomposition"));
        assert!(prompt.contains("Decomposition target path: README.md"));
        assert!(prompt.contains("\"kind\": \"megafile_decomposition\""));
        assert!(prompt.contains("\"target_path\": \"README.md\""));
        assert!(prompt.contains("does not bypass the isolated worktree, hard claim"));

        let mut child = injected_child_report(&assignment);
        child.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
        child.worker_reports[0].target_path = Some(PathBuf::from("./README.md"));
        child.worker_reports[0].files_changed = vec![
            PathBuf::from("./README.md"),
            PathBuf::from("./src/readme_part.md"),
        ];
        child.files_changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        child.worker_reports[0].bloated_file_flags = vec![
            BloatedFileFlag {
                path: PathBuf::from("./README.md"),
            },
            BloatedFileFlag {
                path: PathBuf::from("README.md"),
            },
        ];
        child.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
            target_path: PathBuf::from("./README.md"),
            replacement_paths: vec![PathBuf::from("./src/readme_part.md")],
            supervisor_candidate_binding: None,
        });
        child.decomposition_completions = vec![DecompositionCompletion {
            target_path: PathBuf::from("./README.md"),
            replacement_paths: vec![PathBuf::from("./src/readme_part.md")],
            supervisor_candidate_binding: None,
        }];
        validate_worker_report_evidence(
            &assignment,
            &assignment_metadata,
            Path::new("typed-worker.json"),
            &mut child,
        );
        validate_assignment_report_plumbing(
            &assignment,
            &assignment_metadata,
            Path::new("typed-child.json"),
            &mut child,
        );
        assert_eq!(child.status, ReviewStatus::Succeeded);
        assert_eq!(
            child.worker_reports[0].bloated_file_flags,
            vec![BloatedFileFlag {
                path: PathBuf::from("README.md")
            }]
        );
        assert_eq!(
            child.decomposition_completions,
            vec![DecompositionCompletion {
                target_path: PathBuf::from("README.md"),
                replacement_paths: vec![PathBuf::from("src/readme_part.md")],
                supervisor_candidate_binding: None,
            }]
        );

        let reports = vec![child.clone(), child];
        assert_eq!(
            accepted_bloated_file_flags(&reports),
            vec![BloatedFileFlag {
                path: PathBuf::from("README.md")
            }]
        );
        assert_eq!(
            accepted_decomposition_candidates(&reports),
            vec![DecompositionCompletion {
                target_path: PathBuf::from("README.md"),
                replacement_paths: vec![PathBuf::from("src/readme_part.md")],
                supervisor_candidate_binding: None,
            }]
        );
        let mut final_report =
            artifact_test_final_report(&RunId::new("typed-megafile-final").expect("run id"));
        final_report.bloated_file_flags = accepted_bloated_file_flags(&reports);
        final_report.decomposition_candidates = accepted_decomposition_candidates(&reports);
        let final_value = serde_json::to_value(final_report).expect("serialize final report");
        assert_eq!(final_value["bloated_file_flags"][0]["path"], "README.md");
        assert_eq!(
            final_value["decomposition_candidates"][0]["target_path"],
            "README.md"
        );
        assert!(final_value.get("successful_decompositions").is_none());
    }

    #[test]
    fn typed_decomposition_rejects_missing_target_replacements_and_ordinary_pseudo_evidence() {
        let mut assignment = injected_assignment(true);
        assignment
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        assignment.worker_assignments[0]
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        let worker = &assignment.worker_assignments[0];
        let metadata = WorkerAssignmentMetadata {
            kind: AssignmentKind::MegafileDecomposition,
            target_path: Some(PathBuf::from("README.md")),
        };
        let assignment_metadata =
            BTreeMap::from([((assignment.id.clone(), worker.id.clone()), metadata)]);

        let mut no_replacements = injected_child_report(&assignment);
        no_replacements.files_changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        no_replacements.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
        no_replacements.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
        no_replacements.worker_reports[0].files_changed = no_replacements.files_changed.clone();
        no_replacements.worker_reports[0].decomposition_completion =
            Some(DecompositionCompletion {
                target_path: PathBuf::from("README.md"),
                replacement_paths: Vec::new(),
                supervisor_candidate_binding: None,
            });
        validate_worker_report_evidence(
            &assignment,
            &assignment_metadata,
            Path::new("no-replacements.json"),
            &mut no_replacements,
        );
        assert_eq!(no_replacements.status, ReviewStatus::Failed);
        assert!(finding_messages(&no_replacements).contains("at least one replacement path"));

        let mut no_target_change = injected_child_report(&assignment);
        no_target_change.files_changed = vec![PathBuf::from("src/readme_part.md")];
        no_target_change.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
        no_target_change.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
        no_target_change.worker_reports[0].files_changed = no_target_change.files_changed.clone();
        no_target_change.worker_reports[0].decomposition_completion =
            Some(DecompositionCompletion {
                target_path: PathBuf::from("README.md"),
                replacement_paths: vec![PathBuf::from("src/readme_part.md")],
                supervisor_candidate_binding: None,
            });
        validate_worker_report_evidence(
            &assignment,
            &assignment_metadata,
            Path::new("no-target-change.json"),
            &mut no_target_change,
        );
        assert_eq!(no_target_change.status, ReviewStatus::Failed);
        assert!(
            finding_messages(&no_target_change).contains("files_changed omits the exact target")
        );

        let ordinary_metadata = AssignmentMetadata::new();
        let mut ordinary = injected_child_report(&assignment);
        ordinary.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
            target_path: PathBuf::from("README.md"),
            replacement_paths: vec![PathBuf::from("src/readme_part.md")],
            supervisor_candidate_binding: None,
        });
        validate_worker_report_evidence(
            &assignment,
            &ordinary_metadata,
            Path::new("ordinary-pseudo-decomposition.json"),
            &mut ordinary,
        );
        assert_eq!(ordinary.status, ReviewStatus::Failed);
        assert!(finding_messages(&ordinary)
            .contains("ordinary assignment must not report decomposition_completion"));

        let mut self_asserted = injected_child_report(&assignment);
        self_asserted.files_changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        self_asserted.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
        self_asserted.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
        self_asserted.worker_reports[0].files_changed = self_asserted.files_changed.clone();
        self_asserted.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
            target_path: PathBuf::from("README.md"),
            replacement_paths: vec![PathBuf::from("src/readme_part.md")],
            supervisor_candidate_binding: Some(CandidateValidationBinding {
                version: 1,
                agent_id: assignment.id.clone(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "0000000000000000000000000000000000000000".to_string(),
            }),
        });
        validate_worker_report_evidence(
            &assignment,
            &assignment_metadata,
            Path::new("worker-self-asserted-binding.json"),
            &mut self_asserted,
        );
        assert_eq!(self_asserted.status, ReviewStatus::Failed);
        assert!(finding_messages(&self_asserted)
            .contains("must not self-assert supervisor_candidate_binding"));
        assert!(decomposition_completion_schema_value()["properties"]
            .get("supervisor_candidate_binding")
            .is_none());
    }

    #[test]
    fn finalized_decomposition_evidence_binds_exact_candidate_and_exposes_chain_ids() {
        let (_temp, repo_path) = injected_repository();
        let manager = WorktreeManager::new(&repo_path);
        let agent = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create finalized-evidence agent worktree");
        fs::write(agent.path.join("README.md"), "x\n").expect("shrink test target");
        fs::create_dir_all(agent.path.join("src")).expect("create test replacement parent");
        fs::write(agent.path.join("src/readme_part.md"), "part\n").expect("write test replacement");
        let run_id = RunId::new("verified-decomposition-chain").expect("run id");
        write_test_finalized_megafile_decomposition_evidence(
            &repo_path,
            run_id.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("src/readme_part.md")],
        )
        .expect("write finalized decomposition evidence");
        let exact_paths = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        let evidence = verified_megafile_decomposition_evidence(
            &repo_path,
            run_id.clone(),
            "agent-a",
            Path::new("README.md"),
            &exact_paths,
        )
        .expect("verify exact finalized evidence");
        assert_eq!(evidence.run_id, run_id);
        assert_eq!(evidence.orchestrator_id, "agent-a");
        assert_eq!(evidence.worker_id, "worker-a");
        assert_eq!(evidence.target_path, PathBuf::from("README.md"));
        assert_eq!(
            evidence.replacement_paths,
            vec![PathBuf::from("src/readme_part.md")]
        );
        assert_eq!(evidence.supervisor_candidate_binding.agent_id, "agent-a");

        let missing_binding_run =
            RunId::new("missing-decomposition-content-binding").expect("missing binding run id");
        write_test_finalized_megafile_decomposition_evidence_with_binding(
            &repo_path,
            missing_binding_run.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("src/readme_part.md")],
            false,
        )
        .expect("write finalized evidence without supervisor binding");
        let missing_error = verified_megafile_decomposition_evidence(
            &repo_path,
            missing_binding_run,
            "agent-a",
            Path::new("README.md"),
            &exact_paths,
        )
        .expect_err("missing finalized content binding must fail closed");
        assert!(missing_error
            .to_string()
            .contains("missing the supervisor-inspected candidate binding"));

        let mut extra_paths = exact_paths;
        extra_paths.push(PathBuf::from("unrelated.txt"));
        let error = verified_megafile_decomposition_evidence(
            &repo_path,
            run_id,
            "agent-a",
            Path::new("README.md"),
            &extra_paths,
        )
        .expect_err("unrelated candidate path must break exact run binding");
        assert!(error
            .to_string()
            .contains("files_changed does not exactly match the merge candidate"));
    }

    #[test]
    fn supervisor_injects_binding_from_stable_candidate_and_detects_later_bytes() {
        let (_temp, repo_path) = injected_repository();
        let mut assignment = injected_assignment(true);
        assignment
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        assignment.worker_assignments[0]
            .assigned_paths
            .push(PathBuf::from("src/readme_part.md"));
        let metadata = WorkerAssignmentMetadata {
            kind: AssignmentKind::MegafileDecomposition,
            target_path: Some(PathBuf::from("README.md")),
        };
        let assignment_metadata = BTreeMap::from([(
            (
                assignment.id.clone(),
                assignment.worker_assignments[0].id.clone(),
            ),
            metadata,
        )]);

        let manager = WorktreeManager::new(&repo_path);
        let agent = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: assignment.id.clone(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create supervisor-inspection worktree");
        fs::write(agent.path.join("README.md"), "x\n").expect("shrink inspected target");
        fs::create_dir_all(agent.path.join("src")).expect("create inspected replacement parent");
        fs::write(agent.path.join("src/readme_part.md"), "reviewed\n")
            .expect("write inspected replacement");

        let mut child = injected_child_report(&assignment);
        child.files_changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        child.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
        child.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
        child.worker_reports[0].files_changed = child.files_changed.clone();
        let completion = DecompositionCompletion {
            target_path: PathBuf::from("README.md"),
            replacement_paths: vec![PathBuf::from("src/readme_part.md")],
            supervisor_candidate_binding: None,
        };
        child.worker_reports[0].decomposition_completion = Some(completion.clone());
        child.decomposition_completions = vec![completion];
        validate_worker_report_evidence(
            &assignment,
            &assignment_metadata,
            Path::new("stable-candidate-worker.json"),
            &mut child,
        );
        validate_assignment_report_plumbing(
            &assignment,
            &assignment_metadata,
            Path::new("stable-candidate-child.json"),
            &mut child,
        );
        assert_eq!(child.status, ReviewStatus::Succeeded);

        let lease = manager
            .acquire_write_execution_lease(&assignment.id)
            .expect("acquire supervisor candidate lease");
        let before =
            bind_supervisor_decomposition_candidate(&repo_path, &assignment, &mut child, &lease)
                .expect("bind supervisor candidate")
                .expect("typed decomposition inspection");
        assert_eq!(
            child.decomposition_completions[0].supervisor_candidate_binding,
            Some(before.binding.clone())
        );
        assert_eq!(
            child.worker_reports[0]
                .decomposition_completion
                .as_ref()
                .and_then(|completion| completion.supervisor_candidate_binding.clone()),
            Some(before.binding.clone())
        );

        fs::write(agent.path.join("src/readme_part.md"), "substituted\n")
            .expect("substitute inspected replacement bytes");
        let after = inspect_supervisor_decomposition_candidate(&repo_path, &assignment, &lease)
            .expect("recapture substituted candidate");
        assert_eq!(after.changed_paths, before.changed_paths);
        assert_ne!(after.binding, before.binding);
    }

    #[test]
    fn worker_bloated_file_flags_are_bounded_and_fail_closed() {
        let assignment = injected_assignment(true);
        let mut child = injected_child_report(&assignment);
        child.worker_reports[0].bloated_file_flags = (0..=MAX_BLOATED_FILE_FLAGS_PER_WORKER)
            .map(|_| BloatedFileFlag {
                path: PathBuf::from("README.md"),
            })
            .collect();
        validate_worker_report_evidence(
            &assignment,
            &AssignmentMetadata::new(),
            Path::new("too-many-flags.json"),
            &mut child,
        );
        assert_eq!(child.status, ReviewStatus::Failed);
        assert!(child.worker_reports[0].bloated_file_flags.is_empty());
        assert!(finding_messages(&child).contains("at most 64 are allowed"));

        let schema = worker_report_schema_value();
        assert_eq!(
            schema["properties"]["bloated_file_flags"]["maxItems"],
            MAX_BLOATED_FILE_FLAGS_PER_WORKER
        );
        assert_eq!(
            schema["properties"]["bloated_file_flags"]["items"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn injected_worker_execution_journals_reject_material_mismatches() {
        let assignment = injected_assignment(true);
        let report_path = Path::new("worker-journal-evidence.json");

        let mut missing = injected_child_report(&assignment);
        missing.files_changed = vec![PathBuf::from("README.md")];
        missing.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Missing),
            &mut missing,
        );
        assert_eq!(missing.status, ReviewStatus::Failed);
        assert!(finding_messages(&missing).contains("execution journal is missing"));

        let mut invalid = injected_child_report(&assignment);
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Invalid(
                "not JSONL".to_string(),
            )),
            &mut invalid,
        );
        assert_eq!(invalid.status, ReviewStatus::Failed);
        assert!(finding_messages(&invalid).contains("execution journal"));
        assert!(finding_messages(&invalid).contains("invalid"));

        let mut unsupported_by_journal = injected_child_report(&assignment);
        unsupported_by_journal.files_changed = vec![PathBuf::from("README.md")];
        unsupported_by_journal.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(Vec::new())),
            &mut unsupported_by_journal,
        );
        assert_eq!(unsupported_by_journal.status, ReviewStatus::Failed);
        assert!(finding_messages(&unsupported_by_journal)
            .contains("not supported by execution journal"));

        let mut unsupported_by_git = injected_child_report(&assignment);
        unsupported_by_git.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
                injected_journal_entry(vec![PathBuf::from("README.md")]),
            ])),
            &mut unsupported_by_git,
        );
        assert_eq!(unsupported_by_git.status, ReviewStatus::Failed);
        assert!(finding_messages(&unsupported_by_git)
            .contains("not supported by supervisor-inspected Git diff"));

        let mut outside_assigned = injected_child_report(&assignment);
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
                injected_journal_entry(vec![PathBuf::from("Cargo.toml")]),
            ])),
            &mut outside_assigned,
        );
        assert_eq!(outside_assigned.status, ReviewStatus::Failed);
        assert!(finding_messages(&outside_assigned).contains("outside assigned_paths"));

        let mut journal_claim_without_git = injected_child_report(&assignment);
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
                injected_journal_entry(vec![PathBuf::from("README.md")]),
            ])),
            &mut journal_claim_without_git,
        );
        assert_eq!(journal_claim_without_git.status, ReviewStatus::Failed);
        assert!(finding_messages(&journal_claim_without_git)
            .contains("changed paths are not supported by supervisor-inspected Git diff"));

        let mut command_claim_without_journal = injected_child_report(&assignment);
        command_claim_without_journal.worker_reports[0]
            .commands_run
            .push(injected_command_record());
        validate_worker_execution_journal_evidence(
            &assignment,
            report_path,
            &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(Vec::new())),
            &mut command_claim_without_journal,
        );
        assert_eq!(command_claim_without_journal.status, ReviewStatus::Failed);
        assert!(finding_messages(&command_claim_without_journal)
            .contains("commands_run entries are not supported by execution journal"));
    }

    #[test]
    fn primary_integrity_matrix_covers_index_flags_split_sparse_submodule_non_utf8_and_runtime_roots(
    ) {
        let base = injected_primary_snapshot();
        let replacement = injected_oid("replacement");
        let mut cases = Vec::new();

        for (name, tag) in [("assume-unchanged", b'h'), ("skip-worktree", b'S')] {
            let mut before = base.clone();
            before
                .index
                .get_mut(&injected_index_key("README.md"))
                .unwrap()
                .tag = tag;
            let mut after = before.clone();
            after.worktree.insert(
                b"README.md".to_vec(),
                PrimaryPathState::File {
                    id: replacement,
                    mode: 0o100644,
                },
            );
            cases.push((
                name,
                before,
                after,
                "worktree content/type changed",
                PathBuf::from("README.md"),
            ));
        }

        let before = base.clone();
        let mut after = before.clone();
        after.index_storage.worktree_index = IndexFileSnapshot::Present {
            bytes: 9,
            digest: replacement,
        };
        cases.push((
            "raw-index",
            before,
            after,
            "raw worktree index",
            PathBuf::from(".git/index"),
        ));

        let mut before = base.clone();
        before.index_storage.shared_index = Some(SharedIndexFileSnapshot {
            path: PathBuf::from(".git/sharedindex.test"),
            storage: IndexFileSnapshot::Present {
                bytes: 7,
                digest: injected_oid("shared"),
            },
        });
        let mut after = before.clone();
        after.index_storage.shared_index = None;
        cases.push((
            "split-index",
            before,
            after,
            "split-index storage changed",
            PathBuf::from(".git/index"),
        ));

        let mut before = base.clone();
        before.index.insert(
            injected_index_key("other"),
            PrimaryIndexEntryState {
                id: injected_oid("sparse-tree"),
                mode: SPARSE_DIRECTORY_MODE,
                tag: b'S',
            },
        );
        before.worktree.insert(
            b"other".to_vec(),
            PrimaryPathState::Directory {
                nested_repository: None,
                contents_digest: Some(injected_oid("sparse-before")),
                mode: 0o040755,
            },
        );
        let mut after = before.clone();
        after.worktree.insert(
            b"other".to_vec(),
            PrimaryPathState::Directory {
                nested_repository: None,
                contents_digest: Some(injected_oid("sparse-after")),
                mode: 0o040755,
            },
        );
        cases.push((
            "sparse-directory",
            before,
            after,
            "worktree content/type changed",
            PathBuf::from("other"),
        ));

        let nested_before = base.clone();
        let mut nested_after = nested_before.clone();
        nested_after.worktree.insert(
            b"README.md".to_vec(),
            PrimaryPathState::File {
                id: replacement,
                mode: 0o100644,
            },
        );
        let mut before = base.clone();
        before.index.insert(
            injected_index_key("deps/nested"),
            PrimaryIndexEntryState {
                id: injected_oid("gitlink"),
                mode: GITLINK_MODE,
                tag: b'H',
            },
        );
        before.worktree.insert(
            b"deps/nested".to_vec(),
            PrimaryPathState::Directory {
                nested_repository: Some(Box::new(nested_before)),
                contents_digest: None,
                mode: 0o040755,
            },
        );
        let mut after = before.clone();
        after.worktree.insert(
            b"deps/nested".to_vec(),
            PrimaryPathState::Directory {
                nested_repository: Some(Box::new(nested_after)),
                contents_digest: None,
                mode: 0o040755,
            },
        );
        cases.push((
            "submodule",
            before,
            after,
            "worktree content/type changed",
            PathBuf::from("deps/nested"),
        ));

        let non_utf8 = vec![b'o', b'p', b'-', 0x80];
        let before = base.clone();
        let mut after = before.clone();
        after.worktree.insert(
            non_utf8.clone(),
            PrimaryPathState::File {
                id: replacement,
                mode: 0o100644,
            },
        );
        cases.push((
            "non-utf8",
            before,
            after,
            "worktree content/type changed",
            finding_path_from_git_bytes(&non_utf8),
        ));

        let mut before = base.clone();
        before.status.insert(
            b".maco-cache/tracked.txt".to_vec(),
            PrimaryStatusState {
                code: *b" M",
                original_path: None,
            },
        );
        let mut after = before.clone();
        after
            .status
            .get_mut(b".maco-cache/tracked.txt".as_slice())
            .unwrap()
            .code = *b"MM";
        cases.push((
            "tracked-runtime-root",
            before,
            after,
            "Git status changed",
            PathBuf::from(".maco-cache/tracked.txt"),
        ));

        for (name, before, after, detail, path) in cases {
            let changes = primary_integrity_changes(&before, &after);
            assert!(!changes.is_empty(), "scenario {name} was not detected");
            assert!(
                changes.details.iter().any(|value| value.contains(detail)),
                "scenario {name} lacked detail {detail}: {:?}",
                changes.details
            );
            assert!(
                changes.paths.contains(&path),
                "scenario {name} lacked path {path:?}"
            );
        }

        let mut stable_flagged = base.clone();
        stable_flagged
            .index
            .get_mut(&injected_index_key("README.md"))
            .unwrap()
            .tag = b'h';
        assert!(primary_integrity_changes(&stable_flagged, &stable_flagged).is_empty());
        for path in [
            b".maco/run.json".as_slice(),
            b".maco-cache/state.json".as_slice(),
            b".agents/live/claims/test.md".as_slice(),
        ] {
            assert!(is_untracked_runtime_artifact_bytes(path));
        }
        assert!(!is_untracked_runtime_artifact_bytes(b".maco-visible"));
        assert!(!is_untracked_runtime_artifact_bytes(b".agents/config.json"));
    }

    #[test]
    fn primary_snapshot_captures_real_index_flags_split_storage_and_ignores_untracked_runtime() {
        let (_temp, repo_path) = injected_repository();
        run_injected_git(
            &repo_path,
            &["update-index", "--assume-unchanged", "README.md"],
        );
        let assumed = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot assume-unchanged index");
        assert!(assumed.index[&injected_index_key("README.md")]
            .tag
            .is_ascii_lowercase());

        run_injected_git(
            &repo_path,
            &["update-index", "--no-assume-unchanged", "README.md"],
        );
        run_injected_git(
            &repo_path,
            &["update-index", "--skip-worktree", "README.md"],
        );
        let skipped = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot skip-worktree index");
        assert_eq!(skipped.index[&injected_index_key("README.md")].tag, b'S');

        run_injected_git(
            &repo_path,
            &["update-index", "--no-skip-worktree", "README.md"],
        );
        let ordinary = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot ordinary index");
        run_injected_git(&repo_path, &["update-index", "--split-index"]);
        let split = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot split index");
        assert!(split.index_storage.shared_index.is_some());
        let split_changes = primary_integrity_changes(&ordinary, &split);
        assert!(split_changes
            .details
            .iter()
            .any(|detail| detail.contains("split-index storage changed")));
        let split_stable = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("repeat stable split-index snapshot");
        assert!(primary_integrity_changes(&split, &split_stable).is_empty());

        fs::create_dir_all(repo_path.join(".maco-cache")).expect("create runtime root");
        fs::write(repo_path.join(".maco-cache/runtime.json"), "{}\n")
            .expect("write runtime artifact");
        let runtime = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot runtime artifact");
        assert!(!runtime
            .status
            .contains_key(b".maco-cache/runtime.json".as_slice()));
    }

    #[test]
    fn primary_snapshot_detects_changes_to_preexisting_dirty_untracked_and_tracked_runtime_paths() {
        let (_temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join(".maco-cache")).expect("create tracked runtime root");
        fs::write(
            repo_path.join(".maco-cache/tracked.txt"),
            "tracked runtime\n",
        )
        .expect("write tracked runtime file");
        commit_injected_repository(&repo_path, "track runtime file");
        fs::write(repo_path.join("README.md"), "preexisting dirty\n")
            .expect("write dirty tracked path");
        fs::write(
            repo_path.join("operator-notes.txt"),
            "preexisting untracked\n",
        )
        .expect("write preexisting untracked path");

        let before = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot preexisting state");
        let unchanged = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("repeat unchanged preexisting snapshot");
        assert!(primary_integrity_changes(&before, &unchanged).is_empty());

        fs::write(repo_path.join("README.md"), "changed dirty path\n")
            .expect("mutate dirty tracked path");
        fs::write(
            repo_path.join("operator-notes.txt"),
            "changed untracked path\n",
        )
        .expect("mutate untracked path");
        fs::write(
            repo_path.join(".maco-cache/tracked.txt"),
            "changed tracked runtime\n",
        )
        .expect("mutate tracked runtime path");
        let after = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("snapshot changed preexisting state");
        let changes = primary_integrity_changes(&before, &after);
        for path in [
            PathBuf::from("README.md"),
            PathBuf::from("operator-notes.txt"),
            PathBuf::from(".maco-cache/tracked.txt"),
        ] {
            assert!(
                changes.paths.contains(&path),
                "missing changed path {path:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn primary_snapshot_supports_non_utf8_repository_root_without_lossy_git_arguments() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = tempfile::tempdir().expect("temporary non-UTF-8 root");
        let repo_path = temp.path().join(OsString::from_vec(b"repo-\x80".to_vec()));
        Repository::init(&repo_path).expect("initialize non-UTF-8 repository");
        fs::write(repo_path.join("README.md"), "baseline\n").expect("write baseline");
        commit_injected_repository(&repo_path, "baseline");

        let snapshot = primary_worktree_snapshot(
            &repo_path,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        )
        .expect("capture non-UTF-8 primary snapshot");
        assert!(snapshot.inspection_problem().is_none());
        let serialized = serializable_path(&repo_path);
        assert!(serialized.starts_with("<non-utf8-git-path>/"));
        assert!(serialized.is_ascii());
        assert!(!serialized.contains('\u{fffd}'));
    }

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

    #[test]
    fn thread_id_parser_uses_first_valid_id_in_bounded_stdout_jsonl() {
        let stdout = b"diagnostic prelude\n{\"type\":\"thread.started\",\"thread_id\":\"thread-first\"}\n{\"thread_id\":\"thread-later\"}\n";
        assert_eq!(
            codex_thread_id_from_stdout(stdout).as_deref(),
            Some("thread-first")
        );
        assert_eq!(
            codex_thread_id_from_stdout(
                b"{\"type\":\"turn.started\"}\n{\"thread_id\":\"thread-later\"}\n"
            )
            .as_deref(),
            Some("thread-later")
        );
        assert_eq!(
            codex_thread_id_from_stdout(
                b"{\"thread_id\":\"\"}\n{\"thread_id\":\"bad\\nthread\"}\n{\"thread_id\":\"thread-valid\"}\n"
            )
            .as_deref(),
            Some("thread-valid")
        );
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

    #[cfg(unix)]
    #[test]
    fn supervisor_required_optional_and_vector_paths_share_reversible_serialization() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = PathBuf::from(OsString::from_vec(vec![b'r', b'o', b'o', b't', 0x80]));
        let encoded = "<non-utf8-git-path>/726f6f7480";
        let plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "path serialization".to_string(),
            task_file: Some(path.clone()),
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            child_timeout_seconds: 1,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            assignments: vec![OrchestratorAssignment {
                id: "child-a".to_string(),
                role: AgentRole::ChildOrchestrator,
                assigned_paths: vec![path.clone()],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                worker_assignments: vec![WorkerAssignment {
                    id: "worker-a".to_string(),
                    role: AgentRole::Worker,
                    assigned_paths: vec![path.clone()],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    task: None,
                    report_path: Some(path.clone()),
                }],
                notes: None,
            }],
        };
        let value = serde_json::to_value(plan).expect("serialize plan paths");
        assert_eq!(value["task_file"], encoded);
        assert_eq!(value["assignments"][0]["assigned_paths"][0], encoded);
        assert_eq!(
            value["assignments"][0]["worker_assignments"][0]["report_path"],
            encoded
        );

        let record = CommandRunRecord {
            command: Vec::new(),
            cwd: path,
            exit_code: Some(0),
            status: ReviewStatus::Succeeded,
            timeout_seconds: 1,
            duration_ms: 0,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        };
        let value = serde_json::to_value(record).expect("serialize command cwd");
        assert_eq!(value["cwd"], encoded);
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

    #[test]
    fn worker_prompt_includes_execution_journal_contract() {
        let assignment = injected_assignment(true);
        let worker = &assignment.worker_assignments[0];
        let mut plan = injected_plan(assignment.clone(), 0);
        plan.role_models.insert(
            AgentRole::Worker,
            RoleModelSelection {
                model: Some("worker-model".to_string()),
                reasoning_effort: Some("low".to_string()),
            },
        );
        let prompt = worker_prompt(
            &plan,
            &assignment,
            worker,
            Path::new("/tmp/maco-run"),
            Path::new("/tmp/maco-run/schemas/worker-report.schema.json"),
        )
        .expect("render worker prompt");

        assert!(prompt.contains(
            "Execution journal path: /tmp/maco-run/incoming/worker-journals/worker-a.jsonl"
        ));
        assert!(prompt.contains("write a structured execution journal"));
        assert!(prompt.contains("\"start_timestamp\""));
        assert!(prompt.contains("\"changed_paths\""));
        assert!(prompt.contains("Worker model: worker-model"));
        assert!(prompt.contains("Worker reasoning effort: low"));
        assert!(prompt.contains("runtime-side role-tagged usage reporting"));
    }

    #[test]
    fn auditor_prompts_explain_repo_relative_coverage_and_absolute_evidence() {
        let assignment = injected_assignment(true);
        let plan = injected_plan(assignment.clone(), 0);
        let child = injected_child_report(&assignment);
        let child_prompt = review_auditor_prompt(
            &plan,
            &assignment,
            Path::new("/tmp/maco-run"),
            Path::new("/tmp/maco-run/schemas/auditor-report.schema.json"),
        )
        .expect("render child review auditor prompt");
        let parent_prompt = parent_review_auditor_prompt(ParentReviewAuditorPromptContext {
            plan: &plan,
            assignment: &assignment,
            assignment_metadata: &AssignmentMetadata::new(),
            run_dir: Path::new("/tmp/maco-run"),
            worktree_path: Path::new("/tmp/maco-worktree"),
            child_report_path: Path::new("/tmp/maco-run/reports/child-a.json"),
            auditor_report_path: Path::new("/tmp/maco-run/reports/child-a-review-auditor.json"),
            schema_path: Path::new("/tmp/maco-run/schemas/auditor-report.schema.json"),
            child_report: &child,
        })
        .expect("render parent review auditor prompt");

        for prompt in [child_prompt, parent_prompt] {
            assert!(prompt.contains(
                "reviewed_paths coverage is computed over repository-relative entries only"
            ));
            assert!(prompt.contains(
                "Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence"
            ));
            assert!(prompt.contains("excluded from coverage computation"));
        }
    }

    fn read_finalized_orchestration_events(reader: &ArtifactRunReader) -> Vec<OrchestrationEvent> {
        let contents = reader
            .read(ORCHESTRATION_EVENT_PATH)
            .expect("read finalized orchestration journal");
        std::str::from_utf8(&contents)
            .expect("UTF-8 orchestration journal")
            .lines()
            .map(|line| serde_json::from_str(line).expect("schema-conforming event record"))
            .collect()
    }

    fn assert_final_decision_event<T: ReportStatus>(
        events: &[OrchestrationEvent],
        node: &str,
        parent: &str,
        role: OrchestrationRole,
        report: &T,
    ) {
        let expected_kind = if report_failed(report) {
            OrchestrationEventKind::Reject
        } else {
            OrchestrationEventKind::Accept
        };
        let event = events
            .iter()
            .find(|event| {
                event.node == node
                    && event.parent.as_deref() == Some(parent)
                    && event.role == role
                    && event.kind == expected_kind
                    && event.payload.get("scope").is_none()
            })
            .unwrap_or_else(|| {
                panic!("missing final {expected_kind:?} event for {role:?} {node} under {parent}")
            });
        assert_eq!(event.payload["accepted"], report.accepted());
        assert_eq!(event.payload["rejected"], report.rejected());
        assert_eq!(
            event.payload["status"],
            serde_json::to_value(report.status()).expect("serialize report status")
        );
    }

    fn injected_repository() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temporary repository root");
        let path = temp.path().join("repo");
        Repository::init(&path).expect("initialize injected repository");
        fs::write(path.join("README.md"), "baseline\n").expect("write injected baseline");
        commit_injected_repository(&path, "baseline");
        (temp, path)
    }

    fn commit_injected_repository(path: &Path, message: &str) {
        let repo = Repository::open(path).expect("open injected repository");
        let mut index = repo.index().expect("open injected index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("stage injected repository");
        index.write().expect("write injected index");
        let tree_id = index.write_tree().expect("write injected tree");
        let tree = repo.find_tree(tree_id).expect("find injected tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
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
        .expect("commit injected repository");
    }

    fn run_injected_git(repo: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .expect("run injected Git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn injected_assignment(with_worker: bool) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: "child-a".to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: with_worker
                .then(|| WorkerAssignment {
                    id: "worker-a".to_string(),
                    role: AgentRole::Worker,
                    assigned_paths: vec![PathBuf::from("README.md")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    task: None,
                    report_path: None,
                })
                .into_iter()
                .collect(),
            notes: None,
        }
    }

    fn injected_named_assignment(id: &str, path: &str) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from(path)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            notes: None,
        }
    }

    fn injected_multi_plan(
        assignments: Vec<OrchestratorAssignment>,
        max_child_retries: u8,
    ) -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "injected concurrent supervisor fixture".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: assignments.len(),
            max_child_retries,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            assignments,
        }
    }

    fn injected_command_assignment_id(command: &ExternalAgentCommand) -> String {
        command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .trim_end_matches(".json")
            .split(".attempt-")
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn write_injected_assignment_report(
        command: &ExternalAgentCommand,
        assignment: &OrchestratorAssignment,
    ) {
        write_injected_json(
            &command.output_last_message,
            &injected_child_report(assignment),
        );
    }

    fn injected_plan(assignment: OrchestratorAssignment, max_child_retries: u8) -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "injected supervisor fixture".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            assignments: vec![assignment],
        }
    }

    fn injected_options(repo: &Path, root: &Path, run_id: &str) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: repo.to_path_buf(),
            plan_file: root.join(format!("{run_id}.json")),
            run_id: RunId::new(run_id).expect("valid injected run id"),
            codex_bin: PathBuf::from("unused-injected-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: true,
        }
    }

    fn artifact_test_final_report(run_id: &RunId) -> SupervisorFinalReport {
        SupervisorFinalReport {
            version: SUPERVISOR_SCHEMA_VERSION,
            run_id: run_id.clone(),
            role: AgentRole::Supervisor,
            repo: PathBuf::from("."),
            plan_file: PathBuf::from("plan.json"),
            run_dir: RunArtifactFamily::Supervise
                .run_root()
                .join(run_id.as_str()),
            runtime: SupervisorRuntime::Fake,
            publishable: false,
            success: true,
            accepted: false,
            rejected: false,
            status: ReviewStatus::Succeeded,
            assigned_paths: Vec::new(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_tokens: Vec::new(),
            semantic_intent_tokens: Vec::new(),
            role_usage: BTreeMap::new(),
            total_usage: None,
            total_cost_usd: None,
            usage_complete: false,
            commands_run: Vec::new(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            bloated_file_flags: Vec::new(),
            decomposition_candidates: Vec::new(),
            assignment_traceability: Vec::new(),
            coverage_gaps: Vec::new(),
            breaker_trip: None,
            orchestrator_reports: Vec::new(),
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            remaining_risk: "private test evidence".to_string(),
            next_safe_action: "none".to_string(),
        }
    }

    fn injected_child_report(assignment: &OrchestratorAssignment) -> OrchestratorReviewReport {
        let worker_reports = assignment
            .worker_assignments
            .iter()
            .map(|worker| WorkerReport {
                id: worker.id.clone(),
                role: AgentRole::Worker,
                assignment_kind: AssignmentKind::Ordinary,
                target_path: None,
                assigned_paths: worker.assigned_paths.clone(),
                semantic_symbols: worker.semantic_symbols.clone(),
                semantic_modules: worker.semantic_modules.clone(),
                claim_token: None,
                semantic_intent_token: None,
                commands_run: Vec::new(),
                files_changed: Vec::new(),
                validation_results: vec![ValidationResult {
                    name: "injected worker validation".to_string(),
                    status: ReviewStatus::Succeeded,
                    command: Vec::new(),
                    message: None,
                }],
                findings: Vec::new(),
                bloated_file_flags: Vec::new(),
                decomposition_completion: None,
                no_further_delegation: Some(true),
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: "none".to_string(),
                next_safe_action: "review".to_string(),
            })
            .collect();
        OrchestratorReviewReport {
            id: assignment.id.clone(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: assignment.assigned_paths.clone(),
            semantic_symbols: assignment.semantic_symbols.clone(),
            semantic_modules: assignment.semantic_modules.clone(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            files_changed: Vec::new(),
            validation_results: vec![ValidationResult {
                name: "injected child validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: None,
            }],
            findings: Vec::new(),
            worker_reports,
            audit_reports: Vec::new(),
            decomposition_completions: Vec::new(),
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        }
    }

    fn injected_auditor_report(
        assignment: &OrchestratorAssignment,
        child: &OrchestratorReviewReport,
    ) -> AuditorReport {
        AuditorReport {
            id: parent_auditor_id(assignment),
            role: AgentRole::Auditor,
            reviewed_worker_ids: required_auditor_prompt_subject_ids(assignment, child),
            reviewed_paths: required_auditor_review_paths(assignment, child),
            commands_run: Vec::new(),
            validation_results: vec![ValidationResult {
                name: "injected auditor validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: None,
            }],
            findings: Vec::new(),
            no_further_delegation: Some(true),
            read_only: true,
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        }
    }

    fn injected_worker_journal_evidence(
        status: WorkerExecutionJournalStatus,
    ) -> WorkerExecutionJournalEvidenceSet {
        WorkerExecutionJournalEvidenceSet::from([(
            "worker-a".to_string(),
            WorkerExecutionJournalEvidence {
                incoming_relative_path: PathBuf::from("worker-journals/worker-a.jsonl"),
                evidence_relative_path: worker_execution_journal_evidence_relative(
                    "child-a", "worker-a",
                ),
                status,
            },
        )])
    }

    fn injected_journal_entry(changed_paths: Vec<PathBuf>) -> WorkerExecutionJournalEntry {
        WorkerExecutionJournalEntry {
            command: vec!["injected-worker".to_string()],
            cwd: PathBuf::from("."),
            start_timestamp: "2026-01-01T00:00:00Z".to_string(),
            end_timestamp: "2026-01-01T00:00:01Z".to_string(),
            changed_paths,
        }
    }

    fn injected_oid(value: &str) -> Oid {
        Oid::hash_object(ObjectType::Blob, value.as_bytes()).expect("hash injected object")
    }

    fn injected_index_key(path: &str) -> PrimaryIndexEntryKey {
        PrimaryIndexEntryKey {
            path: path.as_bytes().to_vec(),
            stage: 0,
        }
    }

    fn injected_primary_snapshot() -> PrimaryWorktreeSnapshot {
        let baseline = injected_oid("baseline");
        PrimaryWorktreeSnapshot {
            head: PrimaryHeadSnapshot {
                detached: false,
                reference_name: Some(b"refs/heads/master".to_vec()),
                symbolic_target: None,
                target: Some(injected_oid("head")),
            },
            index: BTreeMap::from([(
                injected_index_key("README.md"),
                PrimaryIndexEntryState {
                    id: baseline,
                    mode: 0o100644,
                    tag: b'H',
                },
            )]),
            index_storage: PrimaryIndexStorageSnapshot {
                worktree_index: IndexFileSnapshot::Present {
                    bytes: 8,
                    digest: injected_oid("index"),
                },
                shared_index: None,
            },
            status: BTreeMap::new(),
            worktree: BTreeMap::from([(
                b"README.md".to_vec(),
                PrimaryPathState::File {
                    id: baseline,
                    mode: 0o100644,
                },
            )]),
            inspection_error: None,
        }
    }

    fn injected_target_attempted(run: ExternalAgentRun) -> ExternalAgentRun {
        let output_last_message = run.output_last_message.clone();
        let mut launched: ExternalAgentRun = serde_json::from_value(
            serde_json::to_value(&run).expect("serialize injected launched run"),
        )
        .expect("restore injected launched run");
        launched.output_last_message = output_last_message;
        launched
    }

    fn injected_verified_run(command: &ExternalAgentCommand) -> ExternalAgentRun {
        write_injected_worker_journals_from_report(command);
        injected_verified_run_without_journals(command)
    }

    fn injected_verified_nonzero_run(
        command: &ExternalAgentCommand,
        exit_code: i32,
    ) -> ExternalAgentRun {
        let mut run = injected_verified_run(command);
        run.exit_code = Some(exit_code);
        run.publishable = false;
        run.error = Some(format!("external agent exited with status {exit_code}"));
        run
    }

    fn injected_verified_run_without_journals(command: &ExternalAgentCommand) -> ExternalAgentRun {
        ExternalAgentRun {
            command: vec!["injected-runner".to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: command.timeout.as_secs(),
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            )),
            publishable: true,
            program_trust: ExternalProgramTrust::TrustedSystemCodex,
            codex_permissions: Some(CodexPermissionEvidence {
                codex_version: "0.142.3".to_string(),
                minimum_version: "0.138.0".to_string(),
                permission_profile: "maco_external_codex".to_string(),
                workspace_access: command.workspace_access,
                network_enabled: false,
                argv_digest: "injected-digest".to_string(),
                executable_identity: "injected-identity".to_string(),
            }),
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: fs::read(&command.output_last_message).ok(),
        }
    }

    fn write_injected_worker_journals_from_report(command: &ExternalAgentCommand) {
        let contents = match fs::read(&command.output_last_message) {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let report = match serde_json::from_slice::<OrchestratorReviewReport>(&contents) {
            Ok(report) => report,
            Err(_) => return,
        };
        let Some(incoming_root) = command.output_last_message.parent() else {
            return;
        };
        let journal_root = incoming_root.join("worker-journals");
        fs::create_dir_all(&journal_root).expect("create injected worker journal directory");
        for worker in &report.worker_reports {
            let journal_path = journal_root.join(worker_execution_journal_file_name(&worker.id));
            let journal = if worker.files_changed.is_empty() && worker.commands_run.is_empty() {
                String::new()
            } else {
                let entries = injected_worker_journal_entries(worker);
                entries
                    .iter()
                    .map(|entry| {
                        serde_json::to_string(entry)
                            .expect("serialize injected worker journal entry")
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            };
            fs::write(&journal_path, journal).expect("write injected worker journal");
        }
    }

    fn injected_worker_journal_entries(worker: &WorkerReport) -> Vec<WorkerExecutionJournalEntry> {
        if worker.commands_run.is_empty() {
            return vec![injected_journal_entry(worker.files_changed.clone())];
        }
        worker
            .commands_run
            .iter()
            .map(|record| WorkerExecutionJournalEntry {
                command: record.command.clone(),
                cwd: record.cwd.clone(),
                start_timestamp: "2026-01-01T00:00:00Z".to_string(),
                end_timestamp: "2026-01-01T00:00:01Z".to_string(),
                changed_paths: worker.files_changed.clone(),
            })
            .collect()
    }

    fn injected_command_record() -> CommandRunRecord {
        CommandRunRecord {
            command: vec!["injected-runner".to_string()],
            cwd: PathBuf::from("."),
            exit_code: Some(0),
            status: ReviewStatus::Succeeded,
            timeout_seconds: 1,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        }
    }

    fn write_injected_json(path: &Path, value: &impl Serialize) {
        fs::write(
            path,
            serde_json::to_vec(value).expect("serialize injected report"),
        )
        .expect("write injected report");
    }

    fn remove_report_slot_if_present(path: &Path) -> std::io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn finding_messages(report: &OrchestratorReviewReport) -> String {
        report
            .findings
            .iter()
            .map(|finding| finding.message.as_str())
            .collect::<Vec<_>>()
            .join("; ")
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
