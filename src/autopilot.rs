use crate::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily},
    gate_denial::{
        ApprovalReviewDenial, BudgetAdmissionDenial, GateCheckSource, GateDenial,
        GateDenialReason, VerifiedGateContext,
    },
    live_claim::{self, LiveClock},
    llm::{provider::ModelPricing, Redactor},
    machine_global::MachineGlobalRetentionBinding,
    merge::{
        ApplyBlocker, ApplyReadinessStatus, BoundValidationEvidenceBundle,
        CandidateValidationBinding, SafetyCheckStatus, ValidationEvidenceBundle, ValidationReport,
        ValidationStatus,
    },
    orchestrator::{RunId, SemanticCoordinationMode},
    planning,
    process_runner::{
        run_process, CapturedBytes, EnvironmentMode, ProcessCancellation, ProcessOutput,
        ProcessRunError, ProcessSpec, Shell, SideEffectConfinementProfile,
        StrictOfflineWorkspaceProfile,
    },
    publication::{
        self, ExternalSourceGuard, ForgeKind, PrPublicationOptions, PrPublicationReport,
        PrPublicationStatus,
    },
    review::{
        self, ReviewAggregationPolicy, ReviewLensBackendConfig, ReviewLensConfig, ReviewPrOptions,
        ReviewReport, ReviewReportStatus, ReviewerConfig, ReviewerMode,
    },
    safe_state::{
        BoundedRegularReader, BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction,
        BoundedTreeWalkLimits, BoundedTreeWalker, DirectoryBindingGuard,
    },
    semantic_coord::SemanticIntentStore,
    supervise::{
        self, AgentRole, CommandRunRecord, FindingSeverity, OrchestratorAssignment,
        ReviewLensUsageReport, ReviewStatus, RoleModelSelection, RoleUsageObservation,
        RoleUsageReport, SupervisorConcurrencyPolicy, SupervisorFinalReport, SupervisorPlan,
        SupervisorRunOptions, SupervisorRuntime, ValidationResult, WorkerAssignment,
    },
    sync::normalize_repo_relative_path,
    sync_store::SyncStore,
    worktree::{ManagedWorktreeWriteLease, WorktreeManager},
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};

const AUTOPILOT_SCHEMA_VERSION: u32 = 1;
pub const AUTOPILOT_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const AUTOPILOT_PROFILE_BINDING_SCHEMA_VERSION: u32 = 3;
const REVIEW_REPORT_SCHEMA_VERSION: u32 = 1;
const REVIEW_REQUEST_BINDING_HEX_LEN: usize = 64;
const EXTERNAL_REVIEWER_ID_PREFIX: &str = "external-program-";
const EXTERNAL_REVIEWER_BINDING_HEX_LEN: usize = 32;
const EXTERNAL_REVIEWER_MODEL: &str = "parent-bound-direct-program-v1";
const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 600;
const VALIDATION_OUTPUT_LIMIT: usize = 8 * 1024;
const VALIDATION_CAPTURE_LIMIT_BYTES: usize = VALIDATION_OUTPUT_LIMIT * 4;
const AUTOPILOT_MESSAGE_LIMIT_CHARS: usize = 8 * 1024;
const ARTIFACT_FINAL_MARKER: &str = ".maco-artifact-final.json";
const AUTOPILOT_PLAN_MAX_BYTES: u64 = 2 * 1024 * 1024;
const AUTOPILOT_TASK_MAX_BYTES: usize = 256 * 1024;
const AUTOPILOT_MAX_PATHS: usize = 4096;
const AUTOPILOT_MAX_SEMANTIC_ITEMS: usize = 4096;
const AUTOPILOT_MAX_VALIDATION_COMMANDS: usize = 128;
const AUTOPILOT_MAX_REPAIR_ATTEMPTS: usize = 2;
const AUTOPILOT_MAX_PATH_BYTES: usize = 4096;
const AUTOPILOT_MAX_PATH_COMPONENTS: usize = 256;
const AUTOPILOT_MAX_STRING_BYTES: usize = 256 * 1024;
const AUTOPILOT_MAX_REVIEWER_ARGS: usize = 256;
const AUTOPILOT_MAX_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const AUTOPILOT_STATUS_MAX_ENTRIES: usize = 100_000;
const AUTOPILOT_STATUS_MAX_PATH_BYTES: usize = 4096;
const AUTOPILOT_STATUS_MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
#[cfg(not(test))]
const AUTOPILOT_STATUS_MAX_DURATION: Duration = Duration::from_secs(30);
#[cfg(test)]
const AUTOPILOT_STATUS_MAX_DURATION: Duration = Duration::from_secs(120);
const AUTOPILOT_ACTIVE_ARTIFACT_MAX_ENTRIES: usize = 256;
const AUTOPILOT_ACTIVE_ARTIFACT_MAX_TOTAL_PATH_BYTES: usize = 1024 * 1024;
const AUTOPILOT_ACTIVE_ARTIFACT_MAX_DURATION: Duration = Duration::from_secs(2);
const AUTOPILOT_SPINE_MAX_DEPTH: &str = "2";
const AUTOPILOT_EFFECTFUL_UNAVAILABLE_MESSAGE: &str =
    "autopilot effectful execution is temporarily unsupported: the capability-bound supervisor input bridge is not implemented";

#[derive(Debug, Clone)]
pub struct AutopilotRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub run_id: RunId,
    pub codex_bin: Option<PathBuf>,
    pub reviewer_command: Option<String>,
    pub allow_dirty_primary: bool,
    /// Maximum supervisor-plan child dispatches admitted across the source plan and generated
    /// follow-up plans. `None` preserves the unbounded behavior of existing callers.
    pub max_child_dispatches: Option<usize>,
    /// Optional caller-owned whole-run cancellation signal. The caller keeps a clone and may
    /// request cooperative cancellation while this synchronous call is running.
    pub cancellation: Option<ProcessCancellation>,
}

/// Versioned execution configuration passed through unchanged to the live supervisor plan.
///
/// The fields deliberately reuse the supervisor's public configuration types. This manifest is a
/// binding envelope for the public autopilot entry, not a second role/model or review language.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutopilotProfile {
    pub version: u32,
    #[serde(default)]
    pub role_models: BTreeMap<AgentRole, RoleModelSelection>,
    #[serde(default)]
    pub model_pricing: BTreeMap<String, ModelPricing>,
    #[serde(default = "crate::supervise::default_supervisor_review_lenses")]
    pub review_lenses: Vec<ReviewLensConfig>,
    #[serde(default)]
    pub review_aggregation_policy: ReviewAggregationPolicy,
}

impl Default for AutopilotProfile {
    fn default() -> Self {
        Self {
            version: AUTOPILOT_PROFILE_SCHEMA_VERSION,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: crate::supervise::default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AutopilotPlan {
    #[serde(default = "default_autopilot_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub task: AutopilotTask,
    #[serde(default)]
    pub assigned_paths: Vec<PathBuf>,
    #[serde(
        default,
        skip_serializing_if = "crate::planning::TaskPathProposalDiagnostics::is_empty"
    )]
    pub path_proposal: planning::TaskPathProposalDiagnostics,
    #[serde(default)]
    pub semantic_symbols: Vec<String>,
    #[serde(default)]
    pub semantic_modules: Vec<String>,
    #[serde(default)]
    pub validation_commands: Vec<AutopilotValidationCommand>,
    #[serde(default = "default_max_repair_attempts")]
    pub max_repair_attempts: usize,
    #[serde(default, alias = "forge")]
    pub forge_mode: AutopilotForgeMode,
    #[serde(default)]
    pub reviewer: ReviewerConfig,
    #[serde(default)]
    pub publish_mode: AutopilotPublishMode,
    #[serde(default)]
    pub auto_merge: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_source: Option<ExternalSourceGuard>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct AutopilotTask {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotValidationCommand {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ValidationCommandInput {
    String(String),
    Object(ValidationCommandObject),
}

#[derive(Debug, Deserialize)]
struct ValidationCommandObject {
    #[serde(default)]
    name: Option<String>,
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

impl<'de> Deserialize<'de> for AutopilotValidationCommand {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match ValidationCommandInput::deserialize(deserializer)? {
            ValidationCommandInput::String(command) => Ok(Self {
                name: None,
                command,
                timeout_seconds: None,
            }),
            ValidationCommandInput::Object(object) => Ok(Self {
                name: object.name,
                command: object.command,
                timeout_seconds: object.timeout_seconds,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotForgeMode {
    #[default]
    Fake,
    Git,
    Github,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotPublishMode {
    #[default]
    DraftOnly,
    ReadyForReview,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AutopilotFinalReport {
    pub version: u32,
    pub run_id: RunId,
    pub status: AutopilotRunStatus,
    pub success: bool,
    pub attempt_count: usize,
    pub repair_attempts_used: usize,
    pub max_repair_attempts: usize,
    pub artifacts: AutopilotArtifactPaths,
    pub reports_created: AutopilotReportsCreated,
    pub plan: AutopilotPlanSummary,
    pub profile_binding: AutopilotProfileBindingReport,
    pub safety: AutopilotSafetyReport,
    #[serde(default)]
    pub gate_denials: Vec<GateDenial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorFinalReport>,
    pub primary_worktree_untouched: bool,
    pub validation: AutopilotValidationSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<SanitizedPrReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewReport>,
    pub attempts: Vec<AutopilotAttemptSummary>,
    pub ci_reaction_supported: bool,
    pub check_status: AutopilotCheckStatus,
    pub auto_merge_requested: bool,
    pub auto_merge_performed: bool,
    pub generated_follow_up_dispatch_performed: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotProfileBindingStatus {
    NotDispatched,
    Matched,
    Mismatch,
    Incomparable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotProfileBindingField {
    RoleModels,
    ModelPricing,
    ReviewLenses,
    ReviewAggregationPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotProfileBindingFailureKind {
    RequestedEffectiveMismatch,
    RequestedObservedSelectionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotProfileBindingFailure {
    pub kind: AutopilotProfileBindingFailureKind,
    pub mismatched_fields: Vec<AutopilotProfileBindingField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatched_roles: Vec<AgentRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatched_review_lens_ids: Vec<String>,
}

/// Dispatch-observed model evidence for one explicitly configured role override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotRoleModelExecutionBinding {
    pub role: AgentRole,
    pub requested: RoleModelSelection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_models: Vec<String>,
    pub observation: RoleUsageObservation,
    pub status: AutopilotProfileBindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Dispatch-observed model evidence for one configured review lens.
///
/// A `Mismatch` status is a defensive invariant-violation signal. Normal autopilot execution
/// first requires requested/effective lens equality, then derives the dispatched selection from
/// that effective lens. Fake or incomplete observations are `Incomparable`; a review-lens
/// mismatch means that the upstream binding or dispatch-construction invariant was bypassed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotReviewLensExecutionBinding {
    pub lens_id: String,
    pub requested_backend_id: String,
    pub requested_model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_reasoning_effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_backend_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_reasoning_effort: Option<String>,
    pub dispatch_count: usize,
    pub observation: RoleUsageObservation,
    pub status: AutopilotProfileBindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Post-resolution evidence from selections that reached observable supervisor dispatches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotProfileExecutionBindingReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_models: Vec<AutopilotRoleModelExecutionBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_lenses: Vec<AutopilotReviewLensExecutionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Configuration and execution evidence for the requested autopilot profile.
///
/// `effective` and `configuration_status` bind the reloaded supervisor plan. `status` is reserved
/// for post-resolution execution evidence and can be `matched` only when every requested model
/// selection was process-observed at dispatch.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AutopilotProfileBindingReport {
    pub version: u32,
    pub status: AutopilotProfileBindingStatus,
    pub configuration_status: AutopilotProfileBindingStatus,
    pub requested: AutopilotProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<AutopilotProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<AutopilotProfileExecutionBindingReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<AutopilotProfileBindingFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotRunStatus {
    Succeeded,
    Failed,
    Refused,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotArtifactPaths {
    pub plan: PathBuf,
    pub supervisor_report: PathBuf,
    pub pr_report: PathBuf,
    pub review_report: PathBuf,
    pub final_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotReportsCreated {
    pub plan: bool,
    pub supervisor_report: bool,
    pub pr_report: bool,
    pub review_report: bool,
    pub final_report: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotPlanSummary {
    pub title: String,
    pub assigned_paths: Vec<PathBuf>,
    #[serde(
        default,
        skip_serializing_if = "crate::planning::TaskPathProposalDiagnostics::is_empty"
    )]
    pub path_proposal: planning::TaskPathProposalDiagnostics,
    pub semantic_symbols: Vec<String>,
    pub semantic_modules: Vec<String>,
    pub forge_mode: AutopilotForgeMode,
    pub reviewer_mode: ReviewerMode,
    pub publish_mode: AutopilotPublishMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotSafetyReport {
    pub refused: bool,
    pub gate_denials: Vec<GateDenial>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotValidationSummary {
    pub status: AutopilotValidationStatus,
    pub reports: Vec<ValidationReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotValidationStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SanitizedPrReport {
    pub status: String,
    pub forge: String,
    pub draft: bool,
    pub created: bool,
    pub pushed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,
    pub changed_paths: Vec<PathBuf>,
    pub readiness: String,
    pub blockers: Vec<String>,
    pub validation_status: String,
    pub title: String,
    pub body_summary: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotAttemptSummary {
    pub attempt: usize,
    pub supervisor_run_id: String,
    pub agent_id: String,
    pub supervisor_status: String,
    pub validation_status: AutopilotValidationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_status: Option<ReviewReportStatus>,
    pub blocking_findings: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_candidate_binding: Option<CandidateValidationBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_candidate: Option<AutopilotReviewedCandidate>,
    #[serde(default)]
    pub publication_authorized: bool,
    #[serde(default)]
    pub publication_attempted: bool,
    #[serde(default)]
    pub publication_effect_observed: bool,
    pub prepublication_stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotReviewedCandidate {
    pub binding: CandidateValidationBinding,
    pub reviewer_mode: ReviewerMode,
    pub authoritative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotCheckStatus {
    pub ci_reaction_supported: bool,
    pub state: String,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotStatusReport {
    pub run_id: RunId,
    pub run_dir: PathBuf,
    pub artifacts: AutopilotArtifactStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotArtifactStatus {
    pub plan: bool,
    pub supervisor_report: bool,
    pub pr_report: bool,
    pub review_report: bool,
    pub final_report: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SanitizedSupervisorReport {
    version: u32,
    run_id: String,
    runtime: String,
    publishable: bool,
    success: bool,
    status: String,
    assigned_paths: Vec<PathBuf>,
    semantic_symbols: Vec<String>,
    semantic_modules: Vec<String>,
    files_changed: Vec<PathBuf>,
    validation_results: Vec<SanitizedSupervisorValidation>,
    findings: Vec<SanitizedSupervisorFinding>,
    orchestrator_count: usize,
    released_claim_count: usize,
    released_semantic_intent_count: usize,
    remaining_risk: String,
    next_safe_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SanitizedSupervisorValidation {
    name: String,
    status: String,
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SanitizedSupervisorFinding {
    severity: String,
    message: String,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SkippedStageReport {
    status: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FailedStageReport {
    status: String,
    reason: String,
    message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AutopilotInputShape {
    requested_max_depth: Option<String>,
    recursive_child_assignments: bool,
}

impl AutopilotInputShape {
    fn requests_permission_expansion(&self) -> bool {
        self.requested_max_depth
            .as_deref()
            .is_some_and(|depth| depth != AUTOPILOT_SPINE_MAX_DEPTH)
            || self.recursive_child_assignments
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedAutopilotPlan {
    plan: AutopilotPlan,
    input_shape: AutopilotInputShape,
    derived_supervisor_plan: Option<Value>,
}

pub fn autopilot_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<AutopilotPlan> {
    let loaded = load_autopilot_plan_from_task_file(repo, task_file)?;
    if loaded.input_shape.requests_permission_expansion() {
        bail!(
            "autopilot plan requests an unsupported supervisor shape; autopilot run supports exactly max_depth 2 and no recursive child_assignments"
        );
    }
    Ok(loaded.plan)
}

fn load_autopilot_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<LoadedAutopilotPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let contents =
        BoundedRegularReader::read_tree_no_follow_utf8(task_file, AUTOPILOT_PLAN_MAX_BYTES)
            .with_context(|| {
                format!("failed to read autopilot task file {}", task_file.display())
            })?;
    match serde_json::from_str::<Value>(&contents) {
        Ok(value) => {
            let input_shape = autopilot_input_shape(&value).with_context(|| {
                format!(
                    "failed to validate autopilot plan shape {}",
                    task_file.display()
                )
            })?;
            match serde_json::from_value::<AutopilotPlan>(value) {
                Ok(plan) => {
                    return Ok(LoadedAutopilotPlan {
                        plan: validate_autopilot_plan(&repo, plan)?,
                        input_shape,
                        derived_supervisor_plan: None,
                    });
                }
                Err(error)
                    if matches!(
                        contents.trim_start().as_bytes().first(),
                        Some(b'{') | Some(b'[')
                    ) =>
                {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to parse JSON-looking autopilot plan {}",
                            task_file.display()
                        )
                    });
                }
                Err(_) => {}
            }
        }
        Err(error)
            if matches!(
                contents.trim_start().as_bytes().first(),
                Some(b'{') | Some(b'[')
            ) =>
        {
            return Err(error).with_context(|| {
                format!(
                    "failed to parse JSON-looking autopilot plan {}",
                    task_file.display()
                )
            });
        }
        Err(_) => {}
    }

    Ok(LoadedAutopilotPlan {
        plan: validate_autopilot_plan(
            &repo,
            AutopilotPlan {
                version: AUTOPILOT_SCHEMA_VERSION,
                task: AutopilotTask {
                    title: title_from_plain_task(&contents),
                    body: contents,
                },
                assigned_paths: Vec::new(),
                path_proposal: planning::TaskPathProposalDiagnostics::default(),
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                validation_commands: Vec::new(),
                max_repair_attempts: default_max_repair_attempts(),
                forge_mode: AutopilotForgeMode::Fake,
                reviewer: ReviewerConfig::default(),
                publish_mode: AutopilotPublishMode::DraftOnly,
                auto_merge: false,
                external_source: None,
            },
        )?,
        input_shape: AutopilotInputShape::default(),
        derived_supervisor_plan: None,
    })
}

fn load_autopilot_plan_from_goal_spec(
    repo: &Path,
    goal: &str,
    spec: &str,
) -> Result<LoadedAutopilotPlan> {
    let (supervisor_plan, derived_supervisor_plan) =
        supervise::supervisor_plan_and_document_from_goal_spec(repo, goal, spec)?;
    let assigned_paths = supervisor_plan
        .assignments
        .iter()
        .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let semantic_symbols = supervisor_plan
        .assignments
        .iter()
        .flat_map(|assignment| assignment.semantic_symbols.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let semantic_modules = supervisor_plan
        .assignments
        .iter()
        .flat_map(|assignment| assignment.semantic_modules.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let plan = validate_autopilot_plan(
        repo,
        AutopilotPlan {
            version: AUTOPILOT_SCHEMA_VERSION,
            task: AutopilotTask {
                title: title_from_plain_task(&supervisor_plan.task),
                body: supervisor_plan.task,
            },
            assigned_paths,
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
            semantic_symbols,
            semantic_modules,
            validation_commands: Vec::new(),
            max_repair_attempts: default_max_repair_attempts(),
            forge_mode: AutopilotForgeMode::Fake,
            reviewer: ReviewerConfig::default(),
            publish_mode: AutopilotPublishMode::DraftOnly,
            auto_merge: false,
            external_source: None,
        },
    )?;
    Ok(LoadedAutopilotPlan {
        plan,
        input_shape: AutopilotInputShape::default(),
        derived_supervisor_plan: Some(derived_supervisor_plan),
    })
}

fn autopilot_input_shape(value: &Value) -> Result<AutopilotInputShape> {
    let requested_max_depth = value
        .get("max_depth")
        .map(|depth| {
            let number = depth
                .as_number()
                .context("autopilot max_depth must be an integer")?;
            if !number.is_i64() && !number.is_u64() {
                bail!("autopilot max_depth must be an integer");
            }
            Ok(number.to_string())
        })
        .transpose()?;
    let recursive_child_assignments = value
        .get("assignments")
        .map(recursive_child_assignments_requested)
        .transpose()?
        .unwrap_or(false);
    Ok(AutopilotInputShape {
        requested_max_depth,
        recursive_child_assignments,
    })
}

fn recursive_child_assignments_requested(assignments: &Value) -> Result<bool> {
    let assignments = assignments
        .as_array()
        .context("autopilot assignments must be an array when supplied")?;
    for assignment in assignments {
        let assignment = assignment
            .as_object()
            .context("autopilot assignment entries must be objects")?;
        let Some(children) = assignment.get("child_assignments") else {
            continue;
        };
        let children = children
            .as_array()
            .context("autopilot child_assignments must be an array")?;
        if !children.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn apply_autopilot_input_shape_gate(
    safety: &mut AutopilotSafetyReport,
    run_id: &RunId,
    assigned_paths: &[PathBuf],
    input_shape: &AutopilotInputShape,
) -> Result<()> {
    if !input_shape.requests_permission_expansion() {
        return Ok(());
    }
    let denial = GateDenial::from_approval_review(
        run_id.as_str(),
        "maco-autopilot",
        ApprovalReviewDenial::PermissionExpansion,
        assigned_paths,
    )?;
    safety.gate_denials.insert(0, denial);
    safety.refused = true;
    Ok(())
}

pub fn run_autopilot_plan_file(options: AutopilotRunOptions) -> Result<AutopilotFinalReport> {
    run_autopilot_plan_file_with_profile_and_retention(options, None, None)
}

pub fn run_autopilot_plan_file_with_retention(
    options: AutopilotRunOptions,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_plan_file_with_profile_and_retention(options, None, machine_global_retention)
}

pub fn autopilot_profile_from_file(profile_file: impl AsRef<Path>) -> Result<AutopilotProfile> {
    let profile_file = profile_file.as_ref();
    let contents =
        BoundedRegularReader::read_tree_no_follow_utf8(profile_file, AUTOPILOT_PLAN_MAX_BYTES)
            .with_context(|| {
                format!(
                    "failed to read bounded autopilot profile {}",
                    profile_file.display()
                )
            })?;
    let profile = serde_json::from_str::<AutopilotProfile>(&contents).with_context(|| {
        format!(
            "failed to parse autopilot profile {}",
            profile_file.display()
        )
    })?;
    validate_autopilot_profile(&profile)?;
    Ok(profile)
}

fn validate_autopilot_profile(profile: &AutopilotProfile) -> Result<()> {
    if profile.version != AUTOPILOT_PROFILE_SCHEMA_VERSION {
        bail!("unsupported autopilot profile version {}", profile.version);
    }
    review::validate_review_lens_set(&profile.review_lenses)
        .context("autopilot profile review_lenses are invalid")?;
    if profile
        .review_lenses
        .iter()
        .any(|lens| matches!(lens.backend, ReviewLensBackendConfig::Precomputed { .. }))
    {
        bail!("autopilot profile review_lenses must be executable model-backed lenses");
    }
    if let ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts } =
        profile.review_aggregation_policy
    {
        if minimum_accepts == 0 || minimum_accepts > profile.review_lenses.len() {
            bail!(
                "autopilot profile review_lenses validated quorum must be between 1 and the configured lens count"
            );
        }
    }
    for (model, pricing) in &profile.model_pricing {
        if model.trim().is_empty() {
            bail!("autopilot profile model_pricing model key cannot be empty");
        }
        if !pricing.is_valid() {
            bail!(
                "autopilot profile model_pricing for '{}' must contain finite, non-negative input and output prices",
                model.trim()
            );
        }
    }
    Ok(())
}

pub fn run_autopilot_plan_file_with_profile_and_retention(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_and_retention(
        options,
        profile,
        machine_global_retention,
        AutopilotRunSource::PlanFile,
    )
}

pub fn run_autopilot_goal_spec_with_profile_and_retention(
    options: AutopilotRunOptions,
    goal: &str,
    spec: &str,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_and_retention(
        options,
        profile,
        machine_global_retention,
        AutopilotRunSource::GoalSpec { goal, spec },
    )
}

enum AutopilotRunSource<'a> {
    PlanFile,
    GoalSpec { goal: &'a str, spec: &'a str },
}

enum AutopilotCascadeDispatch<'a> {
    Production(std::marker::PhantomData<&'a ()>),
    #[cfg(test)]
    Injected {
        supervisor_plan: Value,
        external_runner: &'a mut (dyn FnMut(
            &crate::external_agent::ExternalAgentCommand,
        ) -> crate::external_agent::ExternalAgentRun
                     + Send),
    },
}

fn run_autopilot_with_profile_and_retention(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
    source: AutopilotRunSource<'_>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_retention_and_dispatch(
        options,
        profile,
        machine_global_retention,
        source,
        AutopilotCascadeDispatch::Production(std::marker::PhantomData),
    )
}

#[cfg(test)]
fn run_autopilot_plan_file_with_injected_supervisor_and_runner(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: MachineGlobalRetentionBinding,
    supervisor_plan: Value,
    external_runner: &mut (dyn FnMut(
        &crate::external_agent::ExternalAgentCommand,
    ) -> crate::external_agent::ExternalAgentRun
              + Send),
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_retention_and_dispatch(
        options,
        profile,
        Some(machine_global_retention),
        AutopilotRunSource::PlanFile,
        AutopilotCascadeDispatch::Injected {
            supervisor_plan,
            external_runner,
        },
    )
}

fn run_autopilot_with_profile_retention_and_dispatch(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
    source: AutopilotRunSource<'_>,
    mut cascade_dispatch: AutopilotCascadeDispatch<'_>,
) -> Result<AutopilotFinalReport> {
    let machine_global_retention = machine_global_retention.context(
        "autopilot run requires --machine-global-config and \
         --machine-global-runtime-root-id for supervise output-staging cleanup",
    )?;
    if options.reviewer_command.is_some() {
        bail!(
            "--reviewer-command belongs to the disabled legacy publication loop and cannot be used by the supervise-backed autopilot spine"
        );
    }
    let requested_profile = profile.unwrap_or_default();
    validate_autopilot_profile(&requested_profile)?;
    let caller_cancellation = options.cancellation.clone();
    let max_child_dispatches = options.max_child_dispatches;

    let repo = discover_repo_root(&options.repo)?;
    let source_is_goal_derived = matches!(&source, AutopilotRunSource::GoalSpec { .. });
    let LoadedAutopilotPlan {
        plan,
        input_shape,
        mut derived_supervisor_plan,
    } = match source {
        AutopilotRunSource::PlanFile => {
            load_autopilot_plan_from_task_file(&repo, &options.plan_file)?
        }
        AutopilotRunSource::GoalSpec { goal, spec } => {
            load_autopilot_plan_from_goal_spec(&repo, goal, spec)?
        }
    };
    let (injected_supervisor_plan, injected_dispatch) = match &cascade_dispatch {
        AutopilotCascadeDispatch::Production(_) => (None, false),
        #[cfg(test)]
        AutopilotCascadeDispatch::Injected {
            supervisor_plan, ..
        } => (Some(supervisor_plan.clone()), true),
    };
    if let Some(injected_supervisor_plan) = injected_supervisor_plan {
        derived_supervisor_plan = Some(injected_supervisor_plan);
    }
    let goal_derived_supervisor_plan = source_is_goal_derived || injected_dispatch;
    if let Some(source) = &plan.external_source {
        publication::revalidate_external_source(&repo, source)
            .context("autopilot source changed immediately before supervised work")?;
    }
    let mut safety = safety_report(
        &repo,
        &options.run_id,
        options.allow_dirty_primary,
        &plan.assigned_paths,
    )?;
    apply_autopilot_input_shape_gate(
        &mut safety,
        &options.run_id,
        &plan.assigned_paths,
        &input_shape,
    )?;
    let repository_bindings = RepositoryPathBindings::bind(&repo)?;
    verify_after_autopilot_safety(&repository_bindings)?;

    let artifacts = artifact_paths();
    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        options.run_id.clone(),
        "autopilot",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    if let Some(derived_supervisor_plan) = &derived_supervisor_plan {
        write_private_json(
            &mut artifact_writer,
            &artifacts.plan,
            derived_supervisor_plan,
        )?;
    } else {
        write_private_json(&mut artifact_writer, &artifacts.plan, &plan)?;
    }

    if safety.refused {
        write_skipped_stage_reports(&mut artifact_writer, "typed_preflight_gate_denial")?;
        let gate_denials = safety.gate_denials.clone();
        let report = final_report(FinalReportInput {
            run_id: &options.run_id,
            status: AutopilotRunStatus::Refused,
            attempt_count: 0,
            max_repair_attempts: plan.max_repair_attempts,
            artifacts,
            plan: plan_summary(&plan),
            profile_binding: AutopilotProfileBindingReport::not_dispatched(
                requested_profile.clone(),
            ),
            safety,
            validation: skipped_autopilot_validation(),
            pr: None,
            review: None,
            attempts: Vec::new(),
            supervisor: None,
            gate_denials,
            primary_worktree_untouched: false,
            next_action: "correct the typed preflight denial, then start a new autopilot run",
            auto_merge_requested: plan.auto_merge,
            generated_follow_up_dispatch_performed: false,
        });
        write_private_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }

    // The first safety capture precedes artifact reservation. Recheck every
    // launch guard after those local writes so a concurrent claim or primary
    // change cannot hide in the preflight-to-dispatch window.
    let pre_dispatch_bindings = RepositoryPathBindings::bind(&repo)?;
    let pre_dispatch_safety = safety_report(
        &repo,
        &options.run_id,
        options.allow_dirty_primary,
        &plan.assigned_paths,
    )?;
    pre_dispatch_bindings
        .verify()
        .context("repository changed immediately before supervisor start")?;
    if pre_dispatch_safety.refused {
        write_skipped_stage_reports(&mut artifact_writer, "typed_pre_dispatch_gate_denial")?;
        let gate_denials = pre_dispatch_safety.gate_denials.clone();
        let report = final_report(FinalReportInput {
            run_id: &options.run_id,
            status: AutopilotRunStatus::Refused,
            attempt_count: 0,
            max_repair_attempts: plan.max_repair_attempts,
            artifacts,
            plan: plan_summary(&plan),
            profile_binding: AutopilotProfileBindingReport::not_dispatched(
                requested_profile.clone(),
            ),
            safety: pre_dispatch_safety,
            validation: skipped_autopilot_validation(),
            pr: None,
            review: None,
            attempts: Vec::new(),
            supervisor: None,
            gate_denials,
            primary_worktree_untouched: false,
            next_action:
                "correct the typed denial observed immediately before dispatch, then start a new autopilot run",
            auto_merge_requested: plan.auto_merge,
            generated_follow_up_dispatch_performed: false,
        });
        write_private_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }

    let agent_id = attempt_agent_id(&options.run_id, 1)?;
    let supervisor_run_id = RunId::new(format!("{}-supervise", options.run_id.as_str()))?;
    let supervisor_plan = match derived_supervisor_plan {
        Some(derived_supervisor_plan) => derived_supervisor_plan,
        None => serde_json::to_value(supervisor_plan_for_attempt(
            &plan,
            &requested_profile,
            &agent_id,
            1,
            &[],
        ))
        .context("failed to serialize the effective autopilot supervisor plan")?,
    };
    let supervisor_plan_relative = PathBuf::from("supervisor-plan.json");
    write_private_json(
        &mut artifact_writer,
        &supervisor_plan_relative,
        &supervisor_plan,
    )?;
    let supervisor_plan_path = run_dir.join(&supervisor_plan_relative);
    let effective_supervisor_plan = supervise::load_supervisor_plan_file(&supervisor_plan_path)
        .context("failed to verify the effective autopilot supervisor profile")?;
    let follow_up_requested_profile = requested_profile.clone();
    let mut profile_binding = AutopilotProfileBindingReport::from_effective(
        requested_profile,
        &effective_supervisor_plan,
    );
    if !profile_binding.permits_dispatch() {
        write_failed_report(
            &mut artifact_writer,
            "supervisor-report.json",
            "profile_binding_mismatch",
            "the effective supervisor profile did not match the requested autopilot profile",
        )?;
        write_skipped_report(
            &mut artifact_writer,
            "pr-report.json",
            "profile_binding_mismatch",
        )?;
        write_skipped_report(
            &mut artifact_writer,
            "review-report.json",
            "profile_binding_mismatch",
        )?;
        let report = final_report(FinalReportInput {
            run_id: &options.run_id,
            status: AutopilotRunStatus::Failed,
            attempt_count: 0,
            max_repair_attempts: plan.max_repair_attempts,
            artifacts,
            plan: plan_summary(&plan),
            profile_binding,
            safety: pre_dispatch_safety,
            validation: skipped_autopilot_validation(),
            pr: None,
            review: None,
            attempts: Vec::new(),
            supervisor: None,
            gate_denials: Vec::new(),
            primary_worktree_untouched: false,
            next_action: "correct the typed requested/effective profile mismatch; no supervisor dispatch, publication, merge, or follow-up dispatch was attempted",
            auto_merge_requested: plan.auto_merge,
            generated_follow_up_dispatch_performed: false,
        });
        write_private_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }
    let (codex_bin, runtime) = match options.codex_bin {
        Some(codex_bin) => (codex_bin, SupervisorRuntime::Codex),
        None => (PathBuf::from("codex-not-executed"), SupervisorRuntime::Fake),
    };
    let mut attempt = AutopilotAttemptSummary {
        attempt: 1,
        supervisor_run_id: supervisor_run_id.as_str().to_string(),
        agent_id,
        supervisor_status: "pending".to_string(),
        validation_status: AutopilotValidationStatus::Skipped,
        pr_status: None,
        review_status: None,
        blocking_findings: 0,
        prepared_candidate_binding: None,
        reviewed_candidate: None,
        publication_authorized: false,
        publication_attempted: false,
        publication_effect_observed: false,
        prepublication_stage: "not_dispatched_manual_integration".to_string(),
        repair_reason: None,
    };
    let supervisor_options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: supervisor_plan_path,
        run_id: supervisor_run_id,
        codex_bin,
        runtime,
        // Autopilot's own authenticated artifacts are local runtime state. The
        // outer typed dirty-primary gate already handled operator worktree state.
        allow_dirty_primary: true,
        machine_global_retention: Some(machine_global_retention),
    };
    // Goal decomposition can admit multiple independent planning roots. Capability-bound
    // worktree creation revalidates one shared repository-cleanliness capability before and after
    // each create, so overlapping creates can invalidate a peer's held Git-directory generation.
    // Keep only this trusted multi-root source serial until creation itself has a serialized
    // capability boundary; authored one-assignment Autopilot behavior remains unchanged.
    let cascade_concurrency_policy = if goal_derived_supervisor_plan {
        SupervisorConcurrencyPolicy::Fixed(NonZeroUsize::MIN)
    } else {
        SupervisorConcurrencyPolicy::default()
    };
    let mut follow_up_profile_refusal = None;
    let mut before_dispatch_denial = None;
    let mut admitted_child_dispatches = 0_usize;
    let error_evidence_source_plan_sha256 =
        supervise::normalized_supervisor_plan_file_sha256(&supervisor_options.plan_file)?;
    let command_primary_baseline = supervise::verified_whole_primary_snapshot_sha256(&repo)?;
    let error_evidence_source_run_id = supervisor_options.run_id.clone();
    let supervisor_result = {
        let mut follow_up_profile_gate = |effective: &SupervisorPlan| {
            #[cfg(test)]
            let effective_override = run_autopilot_profile_callsite_hook(effective);
            #[cfg(test)]
            let effective = effective_override.as_ref().unwrap_or(effective);
            let effective_paths = effective
                .assignments
                .iter()
                .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
                .collect::<Vec<_>>();
            let binding = AutopilotProfileBindingReport::from_effective(
                follow_up_requested_profile.clone(),
                effective,
            );
            let permitted = binding.permits_dispatch();
            if !permitted {
                follow_up_profile_refusal = Some(binding);
                let denial = GateDenial::from_approval_review(
                    options.run_id.as_str(),
                    "maco-autopilot",
                    ApprovalReviewDenial::InconsistentRequest,
                    effective_paths,
                )?;
                before_dispatch_denial = Some(denial.clone());
                return Ok(Some(denial));
            }
            if max_child_dispatches
                .is_some_and(|maximum| admitted_child_dispatches >= maximum)
            {
                let denial = GateDenial::new(
                    options.run_id.as_str(),
                    GateDenialReason::BudgetAdmission {
                        denial: BudgetAdmissionDenial::NewDispatchStopped,
                    },
                    VerifiedGateContext::new(
                        "maco-autopilot",
                        GateCheckSource::BudgetAdmission,
                        effective_paths,
                    )?,
                )?;
                before_dispatch_denial = Some(denial.clone());
                return Ok(Some(denial));
            }
            admitted_child_dispatches = admitted_child_dispatches
                .checked_add(1)
                .context("autopilot admitted child dispatch count overflowed")?;
            Ok(None)
        };
        match &mut cascade_dispatch {
            AutopilotCascadeDispatch::Production(_) => {
                supervise::run_supervisor_plan_file_cascade_for_autopilot(
                    supervisor_options,
                    cascade_concurrency_policy,
                    &options.run_id,
                    caller_cancellation.as_ref(),
                    &mut follow_up_profile_gate,
                )
            }
            #[cfg(test)]
            AutopilotCascadeDispatch::Injected {
                external_runner, ..
            } => supervise::run_supervisor_plan_file_cascade_with_runner_and_gate_for_autopilot(
                supervisor_options,
                &options.run_id,
                caller_cancellation.as_ref(),
                &mut follow_up_profile_gate,
                *external_runner,
            ),
        }
    };
    let command_primary_final = supervise::verified_whole_primary_snapshot_sha256(&repo)?;
    let command_primary_worktree_untouched = command_primary_final == command_primary_baseline;
    if let Some(refusal) = follow_up_profile_refusal.take() {
        profile_binding = refusal;
    }
    let cascade = match supervisor_result {
        Ok(cascade) => cascade,
        Err(error) => {
            let caller_cancelled = caller_cancellation
                .as_ref()
                .is_some_and(ProcessCancellation::is_cancelled);
            let source_dispatch_admitted = admitted_child_dispatches > 0;
            let profile_refused_before_source_dispatch =
                !source_dispatch_admitted && !profile_binding.permits_dispatch();
            let admission_refused_before_source_dispatch = !source_dispatch_admitted
                && before_dispatch_denial.as_ref().is_some_and(|denial| {
                    matches!(denial.reason, GateDenialReason::BudgetAdmission { .. })
                });
            let generated_follow_up_dispatch_performed = if !source_dispatch_admitted {
                false
            } else {
                let evidence =
                    match supervise::generated_follow_up_dispatch_evidence_after_cascade_error(
                        &repo,
                        &error_evidence_source_plan_sha256,
                        &error_evidence_source_run_id,
                        &options.run_id,
                    ) {
                        Ok(evidence) => evidence,
                        Err(evidence_error) => {
                            return Err(error.context(format!(
                            "generated follow-up dispatch is not_process_observable after the cascade error ({evidence_error:#}); refusing to finalize a false execution claim"
                        )));
                        }
                    };
                match evidence {
                    supervise::GeneratedFollowUpDispatchEvidence::NoDurableDispatchStart => false,
                    supervise::GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
                        observation: RoleUsageObservation::SupervisorAggregate,
                    } => true,
                    supervise::GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
                        observation: RoleUsageObservation::NotProcessObservable,
                    } => {
                        return Err(error.context(
                            "generated follow-up dispatch is not_process_observable after a durable dispatch marker; refusing to finalize a false execution claim",
                        ));
                    }
                    supervise::GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
                        observation,
                    } => {
                        return Err(error.context(format!(
                            "generated follow-up dispatch has {observation:?} evidence after a durable dispatch marker; refusing to finalize a false execution claim"
                        )));
                    }
                }
            };
            profile_binding.mark_execution_incomparable(
                "not_process_observable: supervisor dispatch returned no final report, so its resolved model selections cannot be verified",
            );
            attempt.supervisor_status = "failed".to_string();
            write_failed_report(
                &mut artifact_writer,
                "supervisor-report.json",
                "supervisor_entry_failed",
                &sanitize_text(&repo, &format!("{error:#}")),
            )?;
            write_skipped_report(
                &mut artifact_writer,
                "pr-report.json",
                "manual_integration_only",
            )?;
            write_skipped_report(
                &mut artifact_writer,
                "review-report.json",
                "manual_integration_only",
            )?;
            let report = final_report(FinalReportInput {
                run_id: &options.run_id,
                status: if caller_cancelled {
                    AutopilotRunStatus::Cancelled
                } else if admission_refused_before_source_dispatch {
                    AutopilotRunStatus::Refused
                } else {
                    AutopilotRunStatus::Failed
                },
                attempt_count: usize::from(source_dispatch_admitted),
                max_repair_attempts: plan.max_repair_attempts,
                artifacts,
                plan: plan_summary(&plan),
                profile_binding: profile_binding.clone(),
                safety: pre_dispatch_safety,
                validation: skipped_autopilot_validation(),
                pr: None,
                review: None,
                attempts: if source_dispatch_admitted {
                    vec![attempt]
                } else {
                    Vec::new()
                },
                supervisor: None,
                gate_denials: before_dispatch_denial.clone().into_iter().collect(),
                primary_worktree_untouched: command_primary_worktree_untouched,
                next_action: if caller_cancelled && source_dispatch_admitted {
                    "caller cancellation was observed during supervisor execution; inspect the finalized supervisor evidence and start a new run only if the remaining work is still required"
                } else if caller_cancelled {
                    "caller cancellation was observed before supervisor dispatch; start a new run only if the work is still required"
                } else if admission_refused_before_source_dispatch {
                    "review the configured child-dispatch maximum and start a new run with an adequate bound; no supervisor dispatch was attempted"
                } else if profile_refused_before_source_dispatch {
                    "correct the requested/effective profile mismatch; no supervisor, publication, merge, or follow-up dispatch was attempted"
                } else if generated_follow_up_dispatch_performed {
                    "inspect the authenticated generated follow-up queue and subordinate checkpoint: a generated child dispatch started before the cascade failure; no publication or merge was performed"
                } else {
                    "inspect the supervisor entry failure; no publication, merge, or follow-up dispatch was attempted"
                },
                auto_merge_requested: plan.auto_merge,
                generated_follow_up_dispatch_performed,
            });
            write_private_json(&mut artifact_writer, "final-report.json", &report)?;
            artifact_writer.finalize("final-report.json", false)?;
            return Ok(report);
        }
    };
    let generated_follow_up_dispatch_performed = cascade.generated_follow_up_dispatch_performed();
    let follow_up_cascade_success = cascade.follow_up_cascade_success;
    let follow_up_gate_denials = cascade.follow_up_gate_denials.clone();
    write_private_json(
        &mut artifact_writer,
        "follow-up-cascade-report.json",
        &cascade,
    )?;
    let supervisor = cascade.source_report;

    profile_binding.observe_execution(&supervisor);
    attempt.supervisor_status = review_status_label(supervisor.status).to_string();
    write_private_json(&mut artifact_writer, "supervisor-report.json", &supervisor)?;
    write_skipped_report(
        &mut artifact_writer,
        "pr-report.json",
        "manual_integration_only",
    )?;
    write_skipped_report(
        &mut artifact_writer,
        "review-report.json",
        "manual_integration_only",
    )?;
    let execution_profile_mismatch =
        profile_binding.status == AutopilotProfileBindingStatus::Mismatch;
    let caller_cancelled = caller_cancellation
        .as_ref()
        .is_some_and(ProcessCancellation::is_cancelled);
    let status = if caller_cancelled {
        AutopilotRunStatus::Cancelled
    } else if supervisor.success && follow_up_cascade_success && !execution_profile_mismatch {
        AutopilotRunStatus::Succeeded
    } else {
        AutopilotRunStatus::Failed
    };
    let mut gate_denials = supervisor.gate_denials.clone();
    gate_denials.extend(follow_up_gate_denials);
    // This is the observed whole-command interval: immediately before the
    // exact source-plan dispatch through completion of the bounded cascade.
    let primary_worktree_untouched = command_primary_worktree_untouched;
    let next_action = if caller_cancelled {
        "caller cancellation was observed and the supervised cleanup path completed; inspect the durable supervisor and queue evidence before starting a new run"
    } else if execution_profile_mismatch {
        "inspect the typed requested/observed profile mismatch; autopilot performed no publication, merge, or follow-up dispatch"
    } else if !follow_up_cascade_success {
        "inspect the generated follow-up cascade report, authenticated queue if present, typed denials or environment failures, and subordinate reports; no publication or merge was performed"
    } else if supervisor.success {
        "inspect the isolated supervise and bounded generated follow-up results, then use explicit human-approved arbitration or merge preview/apply; autopilot performed no publication or merge"
    } else {
        "inspect the typed supervisor denials and environment failures; autopilot performed no publication, merge, or follow-up dispatch"
    };
    let report = final_report(FinalReportInput {
        run_id: &options.run_id,
        status,
        attempt_count: 1,
        max_repair_attempts: plan.max_repair_attempts,
        artifacts,
        plan: plan_summary(&plan),
        profile_binding,
        safety: pre_dispatch_safety,
        validation: skipped_autopilot_validation(),
        pr: None,
        review: None,
        attempts: vec![attempt],
        supervisor: Some(supervisor),
        gate_denials,
        primary_worktree_untouched,
        next_action,
        auto_merge_requested: plan.auto_merge,
        generated_follow_up_dispatch_performed,
    });
    write_private_json(&mut artifact_writer, "final-report.json", &report)?;
    artifact_writer.finalize("final-report.json", false)?;
    Ok(report)
}

pub(crate) fn effectful_autopilot_unavailable_error() -> anyhow::Error {
    anyhow::anyhow!(AUTOPILOT_EFFECTFUL_UNAVAILABLE_MESSAGE)
}

#[allow(dead_code)]
fn run_autopilot_plan_file_disabled_legacy(
    options: AutopilotRunOptions,
) -> Result<AutopilotFinalReport> {
    let repo = discover_repo_root(&options.repo)?;
    let mut plan = autopilot_plan_from_task_file(&repo, &options.plan_file)?;
    if let Some(command) = options.reviewer_command.clone() {
        plan.reviewer.mode = ReviewerMode::ExternalCommand;
        plan.reviewer.command = Some(command);
    }
    if let Some(source) = &plan.external_source {
        publication::revalidate_external_source(&repo, source)
            .context("autopilot source changed immediately before local work")?;
    }
    let artifacts = artifact_paths();
    let real_runtime_requested = options.codex_bin.is_some();
    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        options.run_id.clone(),
        "autopilot",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    write_private_json(&mut artifact_writer, &artifacts.plan, &plan)?;

    let safety = safety_report(
        &repo,
        &options.run_id,
        options.allow_dirty_primary,
        &plan.assigned_paths,
    )?;
    let repository_bindings = RepositoryPathBindings::bind(&repo)?;
    verify_after_autopilot_safety(&repository_bindings)?;
    if safety.refused {
        write_skipped_stage_reports(&mut artifact_writer, "safety_refusal")?;
        let gate_denials = safety.gate_denials.clone();
        let validation = AutopilotValidationSummary {
            status: AutopilotValidationStatus::Skipped,
            reports: Vec::new(),
        };
        let report = final_report(FinalReportInput {
            run_id: &options.run_id,
            status: AutopilotRunStatus::Refused,
            attempt_count: 0,
            max_repair_attempts: plan.max_repair_attempts,
            artifacts,
            plan: plan_summary(&plan),
            profile_binding: AutopilotProfileBindingReport::not_dispatched(
                AutopilotProfile::default(),
            ),
            safety,
            validation,
            pr: None,
            review: None,
            attempts: Vec::new(),
            supervisor: None,
            gate_denials,
            primary_worktree_untouched: false,
            next_action:
                "resolve the safety refusal, then rerun autopilot; a human reviews and merges manually",
            auto_merge_requested: plan.auto_merge,
            generated_follow_up_dispatch_performed: false,
        });
        write_private_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }

    let max_attempts = plan.max_repair_attempts.saturating_add(1);
    let mut attempts = Vec::new();
    let mut repair_contexts = Vec::new();
    let mut last_pr = None;
    let mut last_review = None;
    let mut last_validation = AutopilotValidationSummary {
        status: AutopilotValidationStatus::Skipped,
        reports: Vec::new(),
    };
    let mut status = AutopilotRunStatus::Failed;
    let mut next_action =
        "inspect autopilot reports, repair failed work, and rerun; no automatic merge was performed"
            .to_string();

    for attempt in 1..=max_attempts {
        let agent_id = attempt_agent_id(&options.run_id, attempt)?;
        let supervisor_run_id =
            RunId::new(format!("{}-attempt-{}", options.run_id.as_str(), attempt))?;
        let supervisor_plan = supervisor_plan_for_attempt(
            &plan,
            &AutopilotProfile::default(),
            &agent_id,
            attempt,
            &repair_contexts,
        );
        let supervisor_plan_relative =
            PathBuf::from(format!("supervisor-plan-attempt-{attempt}.json"));
        write_private_json(
            &mut artifact_writer,
            &supervisor_plan_relative,
            &supervisor_plan,
        )?;
        let supervisor_plan_path = run_dir.join(&supervisor_plan_relative);
        let mut attempt_summary = AutopilotAttemptSummary {
            attempt,
            supervisor_run_id: supervisor_run_id.as_str().to_string(),
            agent_id: agent_id.clone(),
            supervisor_status: "pending".to_string(),
            validation_status: AutopilotValidationStatus::Skipped,
            pr_status: None,
            review_status: None,
            blocking_findings: 0,
            prepared_candidate_binding: None,
            reviewed_candidate: None,
            publication_authorized: false,
            publication_attempted: false,
            publication_effect_observed: false,
            prepublication_stage: "not_started".to_string(),
            repair_reason: None,
        };
        let (codex_bin, runtime) = match &options.codex_bin {
            Some(path) => (path.clone(), SupervisorRuntime::Codex),
            // The Fake supervisor never invokes its ExternalAgentCommand. Keep
            // the required option run-local and nonexistent instead of
            // manufacturing an executable artifact that finalization rejects.
            None => (
                run_dir.join("runtime").join("fake-codex-not-executed"),
                SupervisorRuntime::Fake,
            ),
        };
        if !options.allow_dirty_primary && !dirty_primary_paths(&repo)?.is_empty() {
            bail!("primary worktree changed after safety preflight and before supervisor start");
        }
        repository_bindings
            .verify()
            .context("repository changed immediately before supervisor start")?;
        let supervisor = match supervise::run_supervisor_plan_file(SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: supervisor_plan_path,
            run_id: supervisor_run_id.clone(),
            codex_bin,
            runtime,
            // Autopilot already ran the real primary-change preflight; nested
            // supervise should not reject autopilot's own runtime artifacts.
            allow_dirty_primary: true,
            // Autopilot run remains disabled under Issue #22. If that entrypoint
            // reaches supervise before it grows an explicit CLI binding, the
            // verified child preparation path must fail closed.
            machine_global_retention: None,
        }) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                write_failed_report(
                    &mut artifact_writer,
                    "supervisor-report.json",
                    "supervisor_failed",
                    &sanitize_text(&repo, &format!("{error:#}")),
                )?;
                write_skipped_report(&mut artifact_writer, "pr-report.json", "supervisor_failed")?;
                write_skipped_report(
                    &mut artifact_writer,
                    "review-report.json",
                    "supervisor_failed",
                )?;
                attempt_summary.supervisor_status = "failed".to_string();
                attempts.push(attempt_summary);
                next_action =
                    "inspect the supervisor failure report, repair the runtime, and rerun autopilot"
                        .to_string();
                break;
            }
        };
        let sanitized_supervisor = sanitize_supervisor_report(&repo, &supervisor);
        write_private_json(
            &mut artifact_writer,
            "supervisor-report.json",
            &sanitized_supervisor,
        )?;
        attempt_summary.supervisor_status = review_status_label(supervisor.status).to_string();

        if !supervisor.success || !supervisor.publishable {
            write_skipped_report(&mut artifact_writer, "pr-report.json", "supervisor_failed")?;
            write_skipped_report(
                &mut artifact_writer,
                "review-report.json",
                "supervisor_failed",
            )?;
            attempts.push(attempt_summary);
            next_action = if supervisor.success {
                "rerun with the trusted Codex runtime; fake supervisor evidence cannot be merged or published"
                    .to_string()
            } else {
                "inspect the supervisor report and rerun after correcting the child failure; a human reviews and merges manually"
                    .to_string()
            };
            break;
        }

        let worktree_manager = WorktreeManager::new(&repo);
        let worktree_lease = match acquire_autopilot_worktree_write_lease(
            &worktree_manager,
            &agent_id,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                write_failed_report(
                    &mut artifact_writer,
                    "pr-report.json",
                    "worktree_lease_failed",
                    &sanitize_text(&repo, &format!("{error:#}")),
                )?;
                write_skipped_report(
                    &mut artifact_writer,
                    "review-report.json",
                    "worktree_lease_failed",
                )?;
                attempts.push(attempt_summary);
                next_action = format!(
                    "release the conflicting managed-worktree lease for '{agent_id}', then rerun autopilot"
                );
                break;
            }
        };
        let mut hooks = PrepublicationHooks {
            prepare: |options| {
                publication::prepare_pr_candidate_with_write_lease(options, &worktree_lease)
            },
            validate: |worktree: PathBuf| run_validation_commands(&worktree, &plan),
            review: review::review_pr_for_publication,
            publish: |options, evidence| {
                publication::publish_prepared_pr_with_source_guard(
                    options,
                    &evidence,
                    &worktree_lease,
                    plan.external_source.clone(),
                )
            },
            candidate_clean: repository_worktree_is_clean,
        };
        let outcome = run_prepublication_attempt(
            &repo,
            &agent_id,
            attempt,
            &plan,
            &worktree_lease,
            &mut hooks,
        );
        last_validation = outcome.validation.clone();
        attempt_summary.validation_status = last_validation.status;
        attempt_summary.prepublication_stage = outcome.reason.clone();
        attempt_summary.prepared_candidate_binding = outcome.prepared_binding.clone();
        attempt_summary.reviewed_candidate = outcome.reviewed_candidate.clone();
        attempt_summary.publication_attempted = outcome.publication_attempted;
        attempt_summary.publication_effect_observed = outcome.publication_effect_observed;
        attempt_summary.publication_authorized = outcome.publication_attempted
            && matches!(
                plan.forge_mode,
                AutopilotForgeMode::Git | AutopilotForgeMode::Github
            )
            && outcome
                .reviewed_candidate
                .as_ref()
                .is_some_and(|reviewed| reviewed.authoritative);
        if let Some(review_report) = outcome.review.as_ref() {
            attempt_summary.review_status = Some(review_report.status);
            attempt_summary.blocking_findings = review_report.blocking_finding_count;
            let sanitized_review = sanitize_autopilot_review_report(&repo, review_report);
            write_private_json(
                &mut artifact_writer,
                "review-report.json",
                &sanitized_review,
            )?;
            last_review = Some(sanitized_review);
        } else {
            write_skipped_report(&mut artifact_writer, "review-report.json", &outcome.reason)?;
        }

        if outcome.disposition == PrepublicationDisposition::Published {
            let pr_report = outcome
                .publication
                .context("verified publication outcome lost its publication report")?;
            let sanitized_pr = sanitize_pr_report(&pr_report);
            attempt_summary.pr_status = Some(sanitized_pr.status.clone());
            write_private_json(&mut artifact_writer, "pr-report.json", &sanitized_pr)?;
            last_pr = Some(sanitized_pr);
            attempts.push(attempt_summary);
            status = AutopilotRunStatus::Succeeded;
            next_action = if plan.forge_mode == AutopilotForgeMode::Fake {
                "non-authoritative Fake publication simulation completed locally; no branch or pull request was pushed"
                    .to_string()
            } else {
                "independent pre-publication review passed; a human verifies the published draft and merges manually"
                    .to_string()
            };
            drop(worktree_lease);
            break;
        }

        if let Some(pr_report) = outcome.publication.as_ref() {
            if let Some(receipt) = pr_report.publication_receipt.as_ref() {
                write_private_json(
                    &mut artifact_writer,
                    PathBuf::from(format!("publication-receipt-attempt-{attempt}.json")),
                    receipt,
                )?;
            }
            if pr_report.status == PrPublicationStatus::Published {
                write_failed_report(
                    &mut artifact_writer,
                    "pr-report.json",
                    &outcome.reason,
                    &sanitize_text(&repo, &outcome.message),
                )?;
                attempt_summary.pr_status = Some("published_unverified".to_string());
            } else {
                let sanitized_pr = sanitize_pr_report(pr_report);
                attempt_summary.pr_status = Some(sanitized_pr.status.clone());
                write_private_json(&mut artifact_writer, "pr-report.json", &sanitized_pr)?;
            }
        } else if outcome.reason.contains("failed") {
            write_failed_report(
                &mut artifact_writer,
                "pr-report.json",
                &outcome.reason,
                &sanitize_text(&repo, &outcome.message),
            )?;
        } else {
            write_skipped_report(&mut artifact_writer, "pr-report.json", &outcome.reason)?;
        }
        let repair_message = sanitize_text(&repo, &outcome.message);
        if outcome.retryable && attempt < max_attempts {
            attempt_summary.repair_reason = Some(repair_message.clone());
            repair_contexts.push(RepairPromptContext::from_outcome(&outcome));
            attempts.push(attempt_summary);
            continue;
        }
        attempt_summary.repair_reason = Some(repair_message.clone());
        attempts.push(attempt_summary);
        next_action = if outcome.publication_effect_observed {
            format!(
                "{repair_message}; publication was attempted only after validation and independent review, so inspect the durable receipt and reconcile without starting a blind retry"
            )
        } else if outcome.publication_attempted {
            format!(
                "{repair_message}; the strict publish call ran after validation and review but no external effect was observed, so resolve its candidate or base blocker before retrying"
            )
        } else {
            format!(
                "{repair_message}; publication was not attempted, so repair the failed pre-publication gate before retrying"
            )
        };
        break;
    }

    let attempt_count = attempts.len();
    let report = final_report(FinalReportInput {
        run_id: &options.run_id,
        status,
        attempt_count,
        max_repair_attempts: plan.max_repair_attempts,
        artifacts,
        plan: plan_summary(&plan),
        profile_binding: AutopilotProfileBindingReport::not_dispatched(AutopilotProfile::default()),
        safety,
        validation: last_validation,
        pr: last_pr,
        review: last_review,
        attempts,
        supervisor: None,
        gate_denials: Vec::new(),
        primary_worktree_untouched: false,
        next_action: &next_action,
        auto_merge_requested: plan.auto_merge,
        generated_follow_up_dispatch_performed: false,
    });
    write_private_json(&mut artifact_writer, "final-report.json", &report)?;
    let publish_requested = publish_requested_for_audit(
        real_runtime_requested,
        plan.forge_mode,
        report
            .attempts
            .iter()
            .any(|attempt| attempt.publication_attempted),
    );
    artifact_writer.finalize("final-report.json", publish_requested)?;
    Ok(report)
}

pub fn autopilot_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<AutopilotStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let (artifacts, final_report) = match autopilot_artifact_run_state(&repo, &run_id)? {
        ArtifactRunState::Missing => (empty_artifact_status(), None),
        ArtifactRunState::Active(artifacts) => (artifacts, None),
        ArtifactRunState::Finalized(reader) => {
            let final_report = Some(read_artifact_json(&reader, "final-report.json")?);
            (artifact_status(&reader), final_report)
        }
    };
    Ok(AutopilotStatusReport {
        run_dir: public_run_dir().join(run_id.as_str()),
        run_id,
        artifacts,
        final_report,
    })
}

pub fn collect_autopilot_run(repo: impl AsRef<Path>, run_id: RunId) -> Result<Value> {
    let repo = discover_repo_root(repo.as_ref())?;
    match autopilot_artifact_run_state(&repo, &run_id)? {
        ArtifactRunState::Missing => Ok(serde_json::json!({
            "version": AUTOPILOT_SCHEMA_VERSION,
            "run_id": run_id,
            "status": "missing",
            "success": false,
            "next_action": "rerun maco autopilot run for this run id"
        })),
        ArtifactRunState::Active(_) => bail!(
            "autopilot run '{}' is active or unfinalized; collect requires a verified finalization marker",
            run_id.as_str()
        ),
        ArtifactRunState::Finalized(reader) => read_artifact_json(&reader, "final-report.json"),
    }
}

fn validate_autopilot_plan(repo: &Path, mut plan: AutopilotPlan) -> Result<AutopilotPlan> {
    if plan.version != AUTOPILOT_SCHEMA_VERSION {
        bail!("unsupported autopilot plan version {}", plan.version);
    }
    validate_autopilot_plan_bounds(&plan)?;
    plan.task.title = plan.task.title.trim().to_string();
    plan.task.body = plan.task.body.trim().to_string();
    if plan.task.title.is_empty() {
        plan.task.title = title_from_plain_task(&plan.task.body);
    }
    if plan.task.body.is_empty() {
        plan.task.body = plan.task.title.clone();
    }
    if let Some(source) = &plan.external_source {
        source
            .validate()
            .context("autopilot external source guard is invalid")?;
    }
    if plan.assigned_paths.is_empty() {
        let proposal =
            planning::propose_task_path_proposal(repo, &plan.task.title, &plan.task.body)
                .context("failed to propose autopilot assigned paths")?;
        plan.path_proposal = proposal.diagnostics;
        plan.assigned_paths = proposal.paths;
    }
    plan.assigned_paths = normalize_paths(std::mem::take(&mut plan.assigned_paths))
        .context("autopilot assigned paths are invalid")?;
    if plan.assigned_paths.is_empty() {
        bail!(
            "autopilot assigned paths are empty; provide assigned_paths or mention a concrete repository path or symbol"
        );
    }
    plan.semantic_symbols = sorted_unique_strings(std::mem::take(&mut plan.semantic_symbols));
    plan.semantic_modules = sorted_unique_strings(std::mem::take(&mut plan.semantic_modules));
    for (index, command) in plan.validation_commands.iter_mut().enumerate() {
        command.command = command.command.trim().to_string();
        if command.command.is_empty() {
            bail!("validation command {} cannot be empty", index + 1);
        }
        if matches!(command.timeout_seconds, Some(0)) {
            bail!(
                "validation command {} timeout_seconds must be greater than zero",
                index + 1
            );
        }
        command.timeout_seconds = Some(
            command
                .timeout_seconds
                .unwrap_or(DEFAULT_CHILD_TIMEOUT_SECONDS),
        );
        command.name = command
            .name
            .take()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
    }
    Ok(plan)
}

fn validate_autopilot_plan_bounds(plan: &AutopilotPlan) -> Result<()> {
    validate_autopilot_string(&plan.task.title, AUTOPILOT_TASK_MAX_BYTES, "task title")?;
    validate_autopilot_string(&plan.task.body, AUTOPILOT_TASK_MAX_BYTES, "task body")?;
    if plan.assigned_paths.len() > AUTOPILOT_MAX_PATHS {
        bail!("autopilot plan exceeds its assigned-path count limit");
    }
    for path in &plan.assigned_paths {
        validate_autopilot_path(path, "assigned path")?;
    }
    if plan.semantic_symbols.len() > AUTOPILOT_MAX_SEMANTIC_ITEMS
        || plan.semantic_modules.len() > AUTOPILOT_MAX_SEMANTIC_ITEMS
        || plan.path_proposal.notes.len() > AUTOPILOT_MAX_SEMANTIC_ITEMS
    {
        bail!("autopilot plan exceeds its semantic or diagnostic item limit");
    }
    for value in plan
        .semantic_symbols
        .iter()
        .chain(plan.semantic_modules.iter())
        .chain(plan.path_proposal.notes.iter())
    {
        validate_autopilot_string(value, AUTOPILOT_MAX_STRING_BYTES, "plan string")?;
    }
    if plan.validation_commands.len() > AUTOPILOT_MAX_VALIDATION_COMMANDS {
        bail!("autopilot plan exceeds its validation-command count limit");
    }
    for command in &plan.validation_commands {
        if let Some(name) = &command.name {
            validate_autopilot_string(name, AUTOPILOT_MAX_STRING_BYTES, "validation name")?;
        }
        validate_autopilot_string(
            &command.command,
            AUTOPILOT_MAX_STRING_BYTES,
            "validation command",
        )?;
        if command
            .timeout_seconds
            .is_some_and(|seconds| seconds == 0 || seconds > AUTOPILOT_MAX_TIMEOUT_SECONDS)
        {
            bail!("autopilot validation timeout exceeds its safety limit");
        }
    }
    if plan.max_repair_attempts > AUTOPILOT_MAX_REPAIR_ATTEMPTS {
        bail!(
            "autopilot max_repair_attempts exceeds its {AUTOPILOT_MAX_REPAIR_ATTEMPTS}-attempt limit"
        );
    }
    if plan.reviewer.blocking_attempts > AUTOPILOT_MAX_REPAIR_ATTEMPTS.saturating_add(1)
        || plan.reviewer.args.len() > AUTOPILOT_MAX_REVIEWER_ARGS
        || plan
            .reviewer
            .timeout_seconds
            .is_some_and(|seconds| seconds == 0 || seconds > AUTOPILOT_MAX_TIMEOUT_SECONDS)
    {
        bail!("autopilot reviewer configuration exceeds its safety limits");
    }
    if let Some(program) = &plan.reviewer.program {
        validate_autopilot_path_shape(program, "reviewer program")?;
    }
    if let Some(command) = &plan.reviewer.command {
        validate_autopilot_string(command, AUTOPILOT_MAX_STRING_BYTES, "reviewer command")?;
    }
    let mut reviewer_arg_bytes = 0_usize;
    for argument in &plan.reviewer.args {
        validate_autopilot_string(argument, AUTOPILOT_MAX_STRING_BYTES, "reviewer argument")?;
        reviewer_arg_bytes = reviewer_arg_bytes
            .checked_add(argument.len())
            .context("reviewer argument byte count overflowed")?;
        if reviewer_arg_bytes > AUTOPILOT_MAX_STRING_BYTES {
            bail!("autopilot reviewer arguments exceed their aggregate byte limit");
        }
    }
    if let Some(finding) = &plan.reviewer.finding {
        for (value, label) in [
            (&finding.severity, "review finding severity"),
            (&finding.summary, "review finding summary"),
            (&finding.suggested_fix, "review finding suggested fix"),
        ] {
            validate_autopilot_string(value, AUTOPILOT_MAX_STRING_BYTES, label)?;
        }
        if let Some(path) = &finding.path {
            validate_autopilot_path(path, "review finding path")?;
        }
    }
    Ok(())
}

fn validate_autopilot_string(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    if value.len() > max_bytes {
        bail!("autopilot {label} exceeds its {max_bytes}-byte limit");
    }
    Ok(())
}

fn validate_autopilot_path(path: &Path, label: &str) -> Result<()> {
    validate_autopilot_path_shape(path, label)?;
    normalize_repo_relative_path(path)
        .with_context(|| format!("autopilot {label} is not repository-relative"))?;
    Ok(())
}

fn validate_autopilot_path_shape(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().len() > AUTOPILOT_MAX_PATH_BYTES
        || path.components().count() > AUTOPILOT_MAX_PATH_COMPONENTS
    {
        bail!("autopilot {label} exceeds its path byte or component limit");
    }
    Ok(())
}

fn safety_report(
    repo: &Path,
    run_id: &RunId,
    allow_dirty_primary: bool,
    target_paths: &[PathBuf],
) -> Result<AutopilotSafetyReport> {
    let mut gate_denials = Vec::new();
    if !allow_dirty_primary {
        let dirty_paths = dirty_primary_paths(repo)?;
        if !dirty_paths.is_empty() {
            gate_denials.push(GateDenial::from_apply_blocker(
                run_id.as_str(),
                "maco-autopilot",
                GateCheckSource::PrimaryDrift,
                ApplyBlocker::DirtyPrimary,
                dirty_paths,
            )?);
        }
    }

    let sync_claims = SyncStore::open(repo)?.snapshot()?;
    let mut sync_paths = Vec::new();
    for claim in &sync_claims {
        for path in planning::any_path_overlaps(target_paths, &claim.paths) {
            sync_paths.push(path);
        }
    }
    if !sync_paths.is_empty() {
        gate_denials.push(GateDenial::from_claim_conflict(
            run_id.as_str(),
            "maco-autopilot",
            sorted_paths(sync_paths),
        )?);
    }

    let semantic_intents = SemanticIntentStore::open(repo)?.snapshot()?;
    let mut semantic_paths = Vec::new();
    for intent in &semantic_intents {
        let related_paths = intent
            .paths
            .iter()
            .chain(intent.impacted_files.iter())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for path in planning::any_path_overlaps(target_paths, &related_paths) {
            semantic_paths.push(path);
        }
    }
    if !semantic_paths.is_empty() {
        gate_denials.push(GateDenial::from_claim_conflict(
            run_id.as_str(),
            "maco-autopilot",
            sorted_paths(semantic_paths),
        )?);
    }

    let live = live_claim::status(repo, &LiveClock::now())?;
    let mut live_paths = Vec::new();
    for claim in live.claims.into_iter().filter(|claim| claim.is_lock) {
        for path in planning::any_path_overlaps(target_paths, &claim.owned_files) {
            live_paths.push(path);
        }
    }
    if !live_paths.is_empty() {
        gate_denials.push(GateDenial::from_claim_conflict(
            run_id.as_str(),
            "maco-autopilot",
            sorted_paths(live_paths),
        )?);
    }

    Ok(AutopilotSafetyReport {
        refused: !gate_denials.is_empty(),
        gate_denials,
    })
}

fn sorted_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn supervisor_plan_for_attempt(
    plan: &AutopilotPlan,
    profile: &AutopilotProfile,
    agent_id: &str,
    attempt: usize,
    repair_contexts: &[RepairPromptContext],
) -> SupervisorPlan {
    let task = supervisor_task(plan, attempt, repair_contexts);
    SupervisorPlan {
        version: 1,
        task: task.clone(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: profile.role_models.clone(),
        model_pricing: profile.model_pricing.clone(),
        review_lenses: profile.review_lenses.clone(),
        review_aggregation_policy: profile.review_aggregation_policy,
        assignments: vec![OrchestratorAssignment {
            id: agent_id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: plan.assigned_paths.clone(),
            semantic_symbols: plan.semantic_symbols.clone(),
            semantic_modules: plan.semantic_modules.clone(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: format!("{agent_id}-worker"),
                role: AgentRole::Worker,
                assigned_paths: plan.assigned_paths.clone(),
                semantic_symbols: plan.semantic_symbols.clone(),
                semantic_modules: plan.semantic_modules.clone(),
                task: Some(task),
                environment_requirements: Vec::new(),
                report_path: None,
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: Some(format!("autopilot attempt {attempt}")),
        }],
    }
}

fn supervisor_task(
    plan: &AutopilotPlan,
    attempt: usize,
    repair_contexts: &[RepairPromptContext],
) -> String {
    let mut task = format!(
        "{}\n\n{}\n\nAutopilot attempt: {attempt}\n",
        plan.task.title, plan.task.body
    );
    if !repair_contexts.is_empty() {
        task.push_str("\nRepair context from prior attempts:\n");
        for context in repair_contexts {
            task.push_str(&format!(
                "- reason_code={} blocking_findings={} severity_counts=critical:{},error:{},warning:{},info:{}\n",
                context.reason_code,
                context.blocking_findings,
                context.severity_counts.critical,
                context.severity_counts.error,
                context.severity_counts.warning,
                context.severity_counts.info,
            ));
        }
    }
    task
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReviewSeverityCounts {
    critical: usize,
    error: usize,
    warning: usize,
    info: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairPromptContext {
    reason_code: &'static str,
    blocking_findings: usize,
    severity_counts: ReviewSeverityCounts,
}

impl RepairPromptContext {
    fn from_outcome(outcome: &AutopilotPrepublicationOutcome) -> Self {
        let reason_code = canonical_repair_reason_code(&outcome.reason);
        let (blocking_findings, severity_counts) =
            if matches!(reason_code, "review_blocked" | "review_failed") {
                outcome
                    .review
                    .as_ref()
                    .and_then(validated_review_counts)
                    .unwrap_or_default()
            } else {
                (0, ReviewSeverityCounts::default())
            };
        Self {
            reason_code,
            blocking_findings,
            severity_counts,
        }
    }
}

fn canonical_repair_reason_code(reason: &str) -> &'static str {
    match reason {
        "preparation_failed" => "preparation_failed",
        "preparation_blocked" => "preparation_blocked",
        "preparation_invalid" => "preparation_invalid",
        "validation_execution_failed" => "validation_execution_failed",
        "validation_failed" => "validation_failed",
        "validation_evidence_invalid" => "validation_evidence_invalid",
        "reviewer_not_authoritative" => "reviewer_not_authoritative",
        "review_execution_failed" => "review_execution_failed",
        "review_evidence_invalid" => "review_evidence_invalid",
        "review_blocked" => "review_blocked",
        "review_failed" => "review_failed",
        "candidate_reverification_failed" => "candidate_reverification_failed",
        "candidate_reverification_blocked" => "candidate_reverification_blocked",
        "candidate_reverification_invalid" => "candidate_reverification_invalid",
        "candidate_binding_mismatch" => "candidate_binding_mismatch",
        "publication_failed" => "publication_failed",
        "publication_blocked" => "publication_blocked",
        "publication_receipt_invalid" => "publication_receipt_invalid",
        _ => "prepublication_gate_failed",
    }
}

fn validated_review_counts(review: &ReviewReport) -> Option<(usize, ReviewSeverityCounts)> {
    let actual_blocking = review
        .findings
        .iter()
        .filter(|finding| finding.blocking)
        .count();
    if actual_blocking != review.blocking_finding_count {
        return None;
    }
    let mut counts = ReviewSeverityCounts::default();
    for finding in &review.findings {
        let count = match finding.severity.as_str() {
            "critical" => &mut counts.critical,
            "error" => &mut counts.error,
            "warning" => &mut counts.warning,
            "info" => &mut counts.info,
            _ => return None,
        };
        *count = count.checked_add(1)?;
    }
    Some((actual_blocking, counts))
}

#[derive(Debug, Clone)]
struct PreparedAutopilotCandidate {
    binding: CandidateValidationBinding,
    head: String,
    changed_paths: Vec<PathBuf>,
    diff_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrepublicationDisposition {
    Published,
    Stopped,
}

struct AutopilotPrepublicationOutcome {
    disposition: PrepublicationDisposition,
    reason: String,
    message: String,
    retryable: bool,
    validation: AutopilotValidationSummary,
    review: Option<ReviewReport>,
    prepared_binding: Option<CandidateValidationBinding>,
    reviewed_candidate: Option<AutopilotReviewedCandidate>,
    publication: Option<PrPublicationReport>,
    publication_attempted: bool,
    publication_effect_observed: bool,
}

impl AutopilotPrepublicationOutcome {
    fn with_publication_audit(mut self, attempted: bool, effect_observed: bool) -> Self {
        self.publication_attempted = attempted;
        self.publication_effect_observed = effect_observed;
        self
    }
}

struct PrepublicationHooks<P, V, R, U, C> {
    prepare: P,
    validate: V,
    review: R,
    publish: U,
    candidate_clean: C,
}

#[allow(clippy::too_many_arguments)]
fn stopped_prepublication(
    reason: &str,
    message: impl Into<String>,
    retryable: bool,
    validation: AutopilotValidationSummary,
    review: Option<ReviewReport>,
    prepared_binding: Option<CandidateValidationBinding>,
    reviewed_candidate: Option<AutopilotReviewedCandidate>,
    publication: Option<PrPublicationReport>,
) -> AutopilotPrepublicationOutcome {
    AutopilotPrepublicationOutcome {
        disposition: PrepublicationDisposition::Stopped,
        reason: reason.to_string(),
        message: message.into(),
        retryable,
        validation,
        review,
        prepared_binding,
        reviewed_candidate,
        publication,
        publication_attempted: false,
        publication_effect_observed: false,
    }
}

fn run_prepublication_attempt<P, V, R, U, C>(
    repo: &Path,
    agent_id: &str,
    attempt: usize,
    plan: &AutopilotPlan,
    lease: &ManagedWorktreeWriteLease,
    hooks: &mut PrepublicationHooks<P, V, R, U, C>,
) -> AutopilotPrepublicationOutcome
where
    P: FnMut(PrPublicationOptions) -> Result<PrPublicationReport>,
    V: FnMut(PathBuf) -> Result<Vec<ValidationReport>>,
    R: FnMut(ReviewPrOptions) -> Result<review::PublicationReviewResult>,
    U: FnMut(PrPublicationOptions, BoundValidationEvidenceBundle) -> Result<PrPublicationReport>,
    C: FnMut(&Path) -> Result<bool>,
{
    let skipped_validation = || AutopilotValidationSummary {
        status: AutopilotValidationStatus::Skipped,
        reports: Vec::new(),
    };
    let forge = plan.forge_mode.into_publication_forge();
    let publication_options = || PrPublicationOptions {
        repo: repo.to_path_buf(),
        agent_id: agent_id.to_string(),
        claimed_paths: plan.assigned_paths.clone(),
        validations: Vec::new(),
        forge,
        draft: plan.publish_mode == AutopilotPublishMode::DraftOnly,
        from_branch: None,
        squash_onto: None,
        exclude_paths: Vec::new(),
    };

    let prepared_report = match (hooks.prepare)(publication_options()) {
        Ok(report) => report,
        Err(error) => {
            return stopped_prepublication(
                "preparation_failed",
                format!("candidate preparation failed: {error:#}"),
                true,
                skipped_validation(),
                None,
                None,
                None,
                None,
            )
        }
    };
    if prepared_report.status == PrPublicationStatus::Blocked {
        return stopped_prepublication(
            "preparation_blocked",
            "candidate preparation was blocked before validation",
            true,
            skipped_validation(),
            None,
            None,
            None,
            Some(prepared_report),
        );
    }
    let prepared = match prepared_candidate_from_report(
        &prepared_report,
        repo,
        agent_id,
        forge,
        lease,
        &mut hooks.candidate_clean,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return stopped_prepublication(
                "preparation_invalid",
                format!("candidate preparation did not return a clean exact preview: {error:#}"),
                true,
                skipped_validation(),
                None,
                None,
                None,
                Some(prepared_report),
            )
        }
    };
    let prepared_binding = prepared.binding.clone();

    let validation_reports = match (hooks.validate)(lease.path().to_path_buf()) {
        Ok(reports) => reports,
        Err(error) => {
            return stopped_prepublication(
                "validation_execution_failed",
                format!("validation execution failed: {error:#}"),
                true,
                skipped_validation(),
                None,
                Some(prepared_binding),
                None,
                None,
            )
        }
    };
    let validation = validation_summary(validation_reports.clone());
    if validation.status == AutopilotValidationStatus::Failed {
        return stopped_prepublication(
            "validation_failed",
            validation_repair_reason(&validation),
            true,
            validation,
            None,
            Some(prepared_binding),
            None,
            None,
        );
    }
    let bound_evidence =
        match ValidationEvidenceBundle::bound_to(prepared.binding.clone(), validation_reports) {
            Ok(evidence) => evidence,
            Err(error) => {
                return stopped_prepublication(
                    "validation_evidence_invalid",
                    format!("strict candidate-bound validation evidence was refused: {error:#}"),
                    false,
                    validation,
                    None,
                    Some(prepared_binding),
                    None,
                    None,
                )
            }
        };

    if let Err(outcome) = reverify_prepared_candidate(
        publication_options(),
        agent_id,
        &prepared.binding,
        lease,
        &mut hooks.prepare,
        &mut hooks.candidate_clean,
        "after validation",
        validation.clone(),
        None,
        None,
    ) {
        return *outcome;
    }

    let real_publication = matches!(forge, ForgeKind::Git | ForgeKind::Github);
    if !reviewer_config_may_authorize_publication(forge, &plan.reviewer) {
        return stopped_prepublication(
            "reviewer_not_authoritative",
            "real Git or GitHub publication requires a direct parent-bound ExternalCommand reviewer; Fake and legacy shell review are non-authoritative",
            false,
            validation,
            None,
            Some(prepared_binding),
            None,
            None,
        );
    }

    let review_target = format!("prepared-candidate:{agent_id}@{}", prepared.head);
    let review_paths = review::normalize_changed_paths(prepared.changed_paths.clone());
    let review_options = ReviewPrOptions {
        repo: lease.path().to_path_buf(),
        target: review_target.clone(),
        reviewer: plan.reviewer.clone(),
        attempt,
        changed_paths: review_paths.clone(),
        diff_summary: prepared.diff_summary.clone(),
    };
    let review_result = match (hooks.review)(review_options.clone()) {
        Ok(result) => result,
        Err(error) => {
            return stopped_prepublication(
                "review_execution_failed",
                format!("independent pre-publication review failed: {error:#}"),
                true,
                validation,
                None,
                Some(prepared_binding),
                None,
                None,
            )
        }
    };
    let exact_external_authority = review_result.has_exact_external_authority(&review_options);
    let review_report = review_result.into_report();
    let actual_blocking = review_report
        .findings
        .iter()
        .filter(|finding| finding.blocking)
        .count();
    let canonical_request_binding = is_lower_hex(
        &review_report.request_binding,
        REVIEW_REQUEST_BINDING_HEX_LEN,
    );
    let reviewer_identity_shape_valid = reviewer_identity_matches_mode(&review_report);
    let reviewer_binding_authoritative = plan.reviewer.mode == ReviewerMode::ExternalCommand
        && reviewer_config_has_direct_program_binding(&plan.reviewer)
        && review_report.reviewer.mode == ReviewerMode::ExternalCommand
        && reviewer_identity_shape_valid
        && exact_external_authority;
    let reviewer_authoritative = reviewer_binding_authoritative
        && review_report.status == ReviewReportStatus::Passed
        && review_report.success
        && actual_blocking == 0;
    let reviewed_candidate = AutopilotReviewedCandidate {
        binding: prepared.binding.clone(),
        reviewer_mode: review_report.reviewer.mode,
        authoritative: reviewer_authoritative,
    };
    if review_report.version != REVIEW_REPORT_SCHEMA_VERSION
        || !canonical_request_binding
        || !reviewer_identity_shape_valid
        || review_report.target != review_target
        || review_report.attempt != attempt
        || review_report.changed_paths != review_paths
        || review_report.blocking_finding_count != actual_blocking
        || review_report.reviewer.mode != plan.reviewer.mode
    {
        return stopped_prepublication(
            "review_evidence_invalid",
            "independent reviewer returned an unsupported report version or unbound evidence for a different candidate, attempt, path set, or reviewer program",
            true,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            None,
        );
    }
    if review_report.status == ReviewReportStatus::Blocked
        || review_report.blocking_finding_count > 0
    {
        let message = review_repair_reason(&review_report);
        return stopped_prepublication(
            "review_blocked",
            message,
            true,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            None,
        );
    }
    if review_report.status != ReviewReportStatus::Passed || !review_report.success {
        return stopped_prepublication(
            "review_failed",
            "independent reviewer did not return a successful Passed report",
            true,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            None,
        );
    }
    if real_publication && !reviewer_authoritative {
        return stopped_prepublication(
            "reviewer_not_authoritative",
            "real publication requires a successful Passed report with an exact request binding from the configured parent-bound external reviewer program",
            false,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            None,
        );
    }

    if let Err(outcome) = reverify_prepared_candidate(
        publication_options(),
        agent_id,
        &prepared.binding,
        lease,
        &mut hooks.prepare,
        &mut hooks.candidate_clean,
        "after independent review",
        validation.clone(),
        Some(review_report.clone()),
        Some(reviewed_candidate.clone()),
    ) {
        return *outcome;
    }

    let publication_report = match (hooks.publish)(publication_options(), bound_evidence) {
        Ok(report) => report,
        Err(error) => {
            let mut outcome = stopped_prepublication(
                "publication_failed",
                format!("strict prepared publication failed: {error:#}"),
                false,
                validation,
                Some(review_report),
                Some(prepared_binding),
                Some(reviewed_candidate),
                None,
            );
            outcome.publication_attempted = true;
            return outcome;
        }
    };
    let effect_observed = publication_effect_observed(&publication_report);
    let receipt_result =
        verify_publication_receipt(&publication_report, &prepared.binding, forge, agent_id);

    if publication_report.status != PrPublicationStatus::Published {
        let has_durable_receipt = publication_report.publication_receipt.is_some();
        return stopped_prepublication(
            "publication_blocked",
            "strict publication did not reach a verified Published state",
            false,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            Some(publication_report),
        )
        .with_publication_audit(true, effect_observed || has_durable_receipt);
    }
    if let Err(error) = receipt_result {
        return stopped_prepublication(
            "publication_receipt_invalid",
            format!("publication receipt did not verify: {error:#}"),
            false,
            validation,
            Some(review_report),
            Some(prepared_binding),
            Some(reviewed_candidate),
            Some(publication_report),
        )
        .with_publication_audit(true, effect_observed);
    }
    let final_candidate_result = reverify_prepared_candidate(
        publication_options(),
        agent_id,
        &prepared.binding,
        lease,
        &mut hooks.prepare,
        &mut hooks.candidate_clean,
        "after publication",
        validation.clone(),
        Some(review_report.clone()),
        Some(reviewed_candidate.clone()),
    );
    if let Err(mut outcome) = final_candidate_result {
        outcome.publication = Some(publication_report);
        outcome.retryable = false;
        outcome.publication_attempted = true;
        outcome.publication_effect_observed = effect_observed;
        return *outcome;
    }

    AutopilotPrepublicationOutcome {
        disposition: PrepublicationDisposition::Published,
        reason: "verified_published".to_string(),
        message: "prepared candidate passed validation, independent review, strict publication, receipt verification, and final candidate verification".to_string(),
        retryable: false,
        validation,
        review: Some(review_report),
        prepared_binding: Some(prepared.binding),
        reviewed_candidate: Some(reviewed_candidate),
        publication: Some(publication_report),
        publication_attempted: true,
        publication_effect_observed: effect_observed,
    }
}

#[allow(clippy::too_many_arguments)]
fn reverify_prepared_candidate<P, C>(
    options: PrPublicationOptions,
    agent_id: &str,
    expected_binding: &CandidateValidationBinding,
    lease: &ManagedWorktreeWriteLease,
    prepare: &mut P,
    candidate_clean: &mut C,
    phase: &str,
    validation: AutopilotValidationSummary,
    review: Option<ReviewReport>,
    reviewed_candidate: Option<AutopilotReviewedCandidate>,
) -> std::result::Result<(), Box<AutopilotPrepublicationOutcome>>
where
    P: FnMut(PrPublicationOptions) -> Result<PrPublicationReport>,
    C: FnMut(&Path) -> Result<bool>,
{
    let expected_repo = options.repo.clone();
    let expected_forge = options.forge;
    let report = match prepare(options) {
        Ok(report) => report,
        Err(error) => {
            return Err(Box::new(stopped_prepublication(
                "candidate_reverification_failed",
                format!("candidate reverification failed {phase}: {error:#}"),
                true,
                validation,
                review,
                Some(expected_binding.clone()),
                reviewed_candidate,
                None,
            )))
        }
    };
    if report.status == PrPublicationStatus::Blocked {
        return Err(Box::new(stopped_prepublication(
            "candidate_reverification_blocked",
            format!("candidate reverification was blocked {phase}"),
            true,
            validation,
            review,
            Some(expected_binding.clone()),
            reviewed_candidate,
            Some(report),
        )));
    }
    let current = match prepared_candidate_from_report(
        &report,
        &expected_repo,
        agent_id,
        expected_forge,
        lease,
        candidate_clean,
    ) {
        Ok(current) => current,
        Err(error) => {
            return Err(Box::new(stopped_prepublication(
                "candidate_reverification_invalid",
                format!("candidate reverification was invalid {phase}: {error:#}"),
                true,
                validation,
                review,
                Some(expected_binding.clone()),
                reviewed_candidate,
                Some(report),
            )))
        }
    };
    if &current.binding != expected_binding {
        return Err(Box::new(stopped_prepublication(
            "candidate_binding_mismatch",
            format!("candidate or primary binding changed {phase}"),
            true,
            validation,
            review,
            Some(expected_binding.clone()),
            reviewed_candidate,
            None,
        )));
    }
    Ok(())
}

fn prepared_candidate_from_report<C>(
    report: &PrPublicationReport,
    expected_repo: &Path,
    agent_id: &str,
    expected_forge: ForgeKind,
    lease: &ManagedWorktreeWriteLease,
    candidate_clean: &mut C,
) -> Result<PreparedAutopilotCandidate>
where
    C: FnMut(&Path) -> Result<bool>,
{
    if report.status != PrPublicationStatus::Preview
        || report.readiness == ApplyReadinessStatus::Blocked
    {
        bail!("prepared candidate must be a non-blocked Preview");
    }
    if report.forge != expected_forge {
        bail!("prepared candidate forge does not match the requested forge");
    }
    if report.agent_id != agent_id
        || report.preview.candidate.metadata.agent_id != agent_id
        || report.preview.candidate.validation_binding.agent_id != agent_id
    {
        bail!("prepared candidate belongs to a different agent");
    }
    if report.preview.candidate.metadata.worktree_path != lease.path() {
        bail!(
            "prepared candidate report names a different managed worktree than the retained lease"
        );
    }
    let expected_repo = discover_repo_root(expected_repo)?;
    if report.preview.candidate.metadata.primary_repo_root != expected_repo {
        bail!("prepared candidate report names a different primary repository");
    }
    WorktreeManager::new(&expected_repo).verify_write_execution_lease(agent_id, lease)?;
    if report.pushed
        || report.created
        || report.pr_url.is_some()
        || report.publication_receipt.is_some()
    {
        bail!("candidate preparation unexpectedly performed an external publication effect");
    }
    let binding = report.preview.candidate.validation_binding.clone();
    let head = binding
        .agent_head
        .clone()
        .context("prepared candidate binding has no agent HEAD")?;
    if report.commit_id.as_deref() != Some(&head)
        || report.head_id.as_deref() != Some(&head)
        || report.preview.candidate.metadata.agent_head.as_deref() != Some(&head)
        || report.base_head != binding.primary_head
        || report.preview.candidate.metadata.primary_head != binding.primary_head
        || report.preview.candidate.metadata.merge_base != binding.merge_base
    {
        bail!("prepared candidate report metadata disagrees with its exact validation binding");
    }
    if !(candidate_clean)(&report.preview.candidate.metadata.worktree_path)? {
        bail!("prepared candidate worktree is not clean");
    }
    Ok(PreparedAutopilotCandidate {
        binding,
        head,
        changed_paths: report.changed_paths.clone(),
        diff_summary: Some(report.preview.candidate.diff.summary.text.clone()),
    })
}

fn repository_worktree_is_clean(worktree: &Path) -> Result<bool> {
    Ok(bounded_repository_dirty_paths(worktree)?.is_empty())
}

fn verify_publication_receipt(
    report: &PrPublicationReport,
    binding: &CandidateValidationBinding,
    expected_forge: ForgeKind,
    expected_agent_id: &str,
) -> Result<()> {
    if report.status != PrPublicationStatus::Published
        || report.forge != expected_forge
        || report.agent_id != expected_agent_id
        || report.preview.candidate.validation_binding != *binding
        || report.preview.candidate.metadata.agent_id != expected_agent_id
        || report.base_head != binding.primary_head
        || report.preview.candidate.metadata.primary_head != binding.primary_head
        || report.preview.candidate.metadata.merge_base != binding.merge_base
    {
        bail!(
            "publication report forge, agent, base, or candidate does not match the reviewed binding"
        );
    }
    let expected_head = binding
        .agent_head
        .as_deref()
        .context("reviewed candidate binding has no agent HEAD")?;
    if report.head_id.as_deref() != Some(expected_head)
        || report.commit_id.as_deref() != Some(expected_head)
    {
        bail!("publication report HEAD does not match the reviewed candidate binding");
    }
    match report.forge {
        ForgeKind::Fake => {
            if report.pushed
                || !report.created
                || report.pr_url.is_none()
                || report.publication_receipt.is_some()
            {
                bail!("Fake publication must remain a receipt-free local simulation");
            }
        }
        ForgeKind::Git | ForgeKind::Github => {
            let receipt = report
                .publication_receipt
                .as_ref()
                .context("real publication has no durable receipt")?;
            if receipt.phase != publication::PublicationTransactionPhase::Completed
                || receipt.expected_oid != expected_head
                || receipt.expected_base_oid != binding.primary_head
                || receipt.push_observed_oid.as_deref() != Some(expected_head)
                || !report.pushed
            {
                bail!("real publication receipt does not prove the expected completed push");
            }
            match report.forge {
                ForgeKind::Github => {
                    if receipt.pr_head_oid.as_deref() != Some(expected_head)
                        || receipt.pr_url.as_deref() != report.pr_url.as_deref()
                        || receipt.pr_base.as_deref() != Some(report.base.as_str())
                        || report.pr_url.is_none()
                    {
                        bail!(
                            "GitHub publication receipt does not prove the expected pull request and base"
                        );
                    }
                }
                ForgeKind::Git => {
                    if report.created
                        || report.pr_url.is_some()
                        || receipt.pr_url.is_some()
                        || receipt.pr_head_oid.is_some()
                        || receipt.pr_base.is_some()
                    {
                        bail!("Git publication receipt unexpectedly claims a pull request effect");
                    }
                }
                ForgeKind::Fake => {
                    bail!("real publication receipt unexpectedly used the Fake forge")
                }
            }
        }
    }
    Ok(())
}

fn publication_effect_observed(report: &PrPublicationReport) -> bool {
    report.pushed
        || report.created
        || report.pr_url.is_some()
        || report.publication_receipt.as_ref().is_some_and(|receipt| {
            receipt.push_observed_oid.is_some()
                || receipt.pr_url.is_some()
                || receipt.pr_head_oid.is_some()
                || receipt.create_attempted
                || receipt.created_by_transaction
                || receipt.observed_existing_pr
        })
}

fn run_validation_commands(worktree: &Path, plan: &AutopilotPlan) -> Result<Vec<ValidationReport>> {
    let mut reports = Vec::new();
    for (index, validation) in plan.validation_commands.iter().enumerate() {
        let output = run_validation_process(
            worktree,
            &validation.command,
            validation.timeout_seconds.map(Duration::from_secs),
        )
        .with_context(|| format!("failed to run validation command {}", index + 1))?;
        let passed = output.safety_sensitive_succeeded();
        let mut message = validation_failure_message(&output, validation.timeout_seconds);
        if let Some(text) = message.as_mut() {
            *text = sanitize_validation_message(worktree, text);
        }
        reports.push(ValidationReport {
            name: validation
                .name
                .clone()
                .unwrap_or_else(|| format!("validation {}", index + 1)),
            status: if passed {
                ValidationStatus::Passed
            } else {
                ValidationStatus::Failed
            },
            message,
            paths: if passed {
                Vec::new()
            } else {
                plan.assigned_paths.clone()
            },
        });
    }
    Ok(reports)
}

fn acquire_autopilot_worktree_write_lease(
    manager: &WorktreeManager,
    agent_id: &str,
) -> Result<ManagedWorktreeWriteLease> {
    manager
        .acquire_write_execution_lease(agent_id)
        .with_context(|| {
            format!("failed to acquire exclusive autopilot execution lease for '{agent_id}'")
        })
}

fn run_validation_process(
    worktree: &Path,
    command_text: &str,
    timeout: Option<Duration>,
) -> Result<ProcessOutput, ProcessRunError> {
    run_process(
        ProcessSpec::shell(
            "validation command",
            Shell::for_current_platform(),
            command_text,
            worktree,
            VALIDATION_CAPTURE_LIMIT_BYTES,
        )
        .with_environment(EnvironmentMode::ClearAndSet(sandbox_environment()))
        .with_private_runtime_home(true)
        .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
            StrictOfflineWorkspaceProfile::read_write(worktree),
        ))
        .with_timeout(timeout),
    )
}

fn validation_failure_message(
    output: &ProcessOutput,
    timeout_seconds: Option<u64>,
) -> Option<String> {
    if !output.safety_evidence_verified() {
        return Some(format!(
            "validation safety evidence was not verified: process_tree={:?}; side_effects={:?}",
            output.process_tree, output.side_effects
        ));
    }
    if let Some(error) = &output.process_error {
        return Some(format!(
            "{error}; stdout: {}; stderr: {}",
            summarize_validation_output(&output.stdout),
            summarize_validation_output(&output.stderr)
        ));
    }
    if output.timed_out {
        let timeout = timeout_seconds
            .map(|seconds| format!(" after {seconds} seconds"))
            .unwrap_or_default();
        return Some(format!(
            "validation timed out{timeout}; stdout: {}; stderr: {}",
            summarize_validation_output(&output.stdout),
            summarize_validation_output(&output.stderr)
        ));
    }
    if output.status.is_some_and(|status| status.success()) {
        return None;
    }
    Some(format!(
        "validation exited with {}; stdout: {}; stderr: {}",
        output
            .status
            .and_then(|status| status.code())
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string()),
        summarize_validation_output(&output.stdout),
        summarize_validation_output(&output.stderr)
    ))
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

fn summarize_validation_output(output: &CapturedBytes) -> String {
    output.summarize_chars(VALIDATION_OUTPUT_LIMIT).text
}

impl AutopilotProfileBindingReport {
    fn not_dispatched(requested: AutopilotProfile) -> Self {
        Self {
            version: AUTOPILOT_PROFILE_BINDING_SCHEMA_VERSION,
            status: AutopilotProfileBindingStatus::NotDispatched,
            configuration_status: AutopilotProfileBindingStatus::NotDispatched,
            requested,
            effective: None,
            execution: None,
            failure: None,
        }
    }

    fn from_effective(requested: AutopilotProfile, plan: &SupervisorPlan) -> Self {
        let effective = AutopilotProfile {
            version: AUTOPILOT_PROFILE_SCHEMA_VERSION,
            role_models: plan.role_models.clone(),
            model_pricing: plan.model_pricing.clone(),
            review_lenses: plan.review_lenses.clone(),
            review_aggregation_policy: plan.review_aggregation_policy,
        };
        let mut mismatched_fields = Vec::new();
        if requested.role_models != effective.role_models {
            mismatched_fields.push(AutopilotProfileBindingField::RoleModels);
        }
        if requested.model_pricing != effective.model_pricing {
            mismatched_fields.push(AutopilotProfileBindingField::ModelPricing);
        }
        if requested.review_lenses != effective.review_lenses {
            mismatched_fields.push(AutopilotProfileBindingField::ReviewLenses);
        }
        if requested.review_aggregation_policy != effective.review_aggregation_policy {
            mismatched_fields.push(AutopilotProfileBindingField::ReviewAggregationPolicy);
        }
        let configuration_status = if mismatched_fields.is_empty() {
            AutopilotProfileBindingStatus::Matched
        } else {
            AutopilotProfileBindingStatus::Mismatch
        };
        let failure = (!mismatched_fields.is_empty()).then_some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedEffectiveMismatch,
            mismatched_fields,
            mismatched_roles: Vec::new(),
            mismatched_review_lens_ids: Vec::new(),
        });
        Self {
            version: AUTOPILOT_PROFILE_BINDING_SCHEMA_VERSION,
            status: if failure.is_some() {
                AutopilotProfileBindingStatus::Mismatch
            } else {
                AutopilotProfileBindingStatus::NotDispatched
            },
            configuration_status,
            requested,
            effective: Some(effective),
            execution: None,
            failure,
        }
    }

    fn permits_dispatch(&self) -> bool {
        self.configuration_status == AutopilotProfileBindingStatus::Matched
            && self.failure.is_none()
    }

    fn observe_execution(&mut self, supervisor: &SupervisorFinalReport) {
        self.observe_execution_reports(
            &supervisor.role_usage,
            &supervisor.review_lens_usage,
            &review_lens_dispatch_evidence(supervisor, self.requested.review_lenses.len()),
        );
    }

    fn observe_execution_reports(
        &mut self,
        role_usage: &BTreeMap<AgentRole, RoleUsageReport>,
        review_lens_usage: &[ReviewLensUsageReport],
        review_lens_dispatches: &[ReviewLensDispatchEvidence],
    ) {
        if !self.permits_dispatch() {
            return;
        }
        let execution = AutopilotProfileExecutionBindingReport::from_supervisor(
            &self.requested,
            role_usage,
            review_lens_usage,
            review_lens_dispatches,
        );
        let mismatched_roles = execution
            .role_models
            .iter()
            .filter(|binding| binding.status == AutopilotProfileBindingStatus::Mismatch)
            .map(|binding| binding.role)
            .collect::<Vec<_>>();
        let mismatched_review_lens_ids = execution
            .review_lenses
            .iter()
            .filter(|binding| binding.status == AutopilotProfileBindingStatus::Mismatch)
            .map(|binding| binding.lens_id.clone())
            .collect::<Vec<_>>();
        let mut mismatched_fields = Vec::new();
        if !mismatched_roles.is_empty() {
            mismatched_fields.push(AutopilotProfileBindingField::RoleModels);
        }
        if !mismatched_review_lens_ids.is_empty() {
            mismatched_fields.push(AutopilotProfileBindingField::ReviewLenses);
        }
        let has_mismatch = !mismatched_fields.is_empty();
        let has_incomparable = execution
            .role_models
            .iter()
            .any(|binding| binding.status == AutopilotProfileBindingStatus::Incomparable)
            || execution
                .review_lenses
                .iter()
                .any(|binding| binding.status == AutopilotProfileBindingStatus::Incomparable)
            || execution.unavailable_reason.is_some();
        self.status = if has_mismatch {
            AutopilotProfileBindingStatus::Mismatch
        } else if has_incomparable {
            AutopilotProfileBindingStatus::Incomparable
        } else {
            AutopilotProfileBindingStatus::Matched
        };
        self.failure = has_mismatch.then_some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedObservedSelectionMismatch,
            mismatched_fields,
            mismatched_roles,
            mismatched_review_lens_ids,
        });
        self.execution = Some(execution);
    }

    fn mark_execution_incomparable(&mut self, reason: impl Into<String>) {
        if !self.permits_dispatch() {
            return;
        }
        self.status = AutopilotProfileBindingStatus::Incomparable;
        self.execution = Some(AutopilotProfileExecutionBindingReport {
            role_models: Vec::new(),
            review_lenses: Vec::new(),
            unavailable_reason: Some(reason.into()),
        });
    }
}

impl AutopilotProfileExecutionBindingReport {
    fn from_supervisor(
        requested: &AutopilotProfile,
        role_usage: &BTreeMap<AgentRole, RoleUsageReport>,
        review_lens_usage: &[ReviewLensUsageReport],
        review_lens_dispatches: &[ReviewLensDispatchEvidence],
    ) -> Self {
        let role_models = requested
            .role_models
            .iter()
            .map(|(&role, selection)| {
                role_model_execution_binding(role, selection, role_usage.get(&role))
            })
            .collect::<Vec<_>>();
        let review_lenses = requested
            .review_lenses
            .iter()
            .enumerate()
            .map(|(lens_index, lens)| {
                review_lens_execution_binding(
                    lens,
                    review_lens_usage
                        .iter()
                        .find(|usage| usage.lens_id == lens.id),
                    review_lens_dispatches.get(lens_index),
                )
            })
            .collect::<Vec<_>>();
        let unavailable_reason = (role_models.is_empty() && review_lenses.is_empty()).then(|| {
            "not_process_observable: the requested profile contained no executable model selection"
                .to_string()
        });
        Self {
            role_models,
            review_lenses,
            unavailable_reason,
        }
    }
}

fn role_model_execution_binding(
    role: AgentRole,
    requested: &RoleModelSelection,
    usage: Option<&RoleUsageReport>,
) -> AutopilotRoleModelExecutionBinding {
    let observation = usage
        .map(|usage| usage.observation)
        .unwrap_or(RoleUsageObservation::NotProcessObservable);
    let observed_models = usage
        .filter(|usage| {
            usage.observation == RoleUsageObservation::ProcessObserved && usage.usage.is_some()
        })
        .map(|usage| usage.models.clone())
        .unwrap_or_default();
    let process_observed = observation == RoleUsageObservation::ProcessObserved
        && usage.is_some_and(|usage| usage.usage.is_some());
    let status = if !process_observed {
        AutopilotProfileBindingStatus::Incomparable
    } else if let Some(requested_model) = requested.model.as_deref() {
        if observed_models.is_empty() {
            AutopilotProfileBindingStatus::Incomparable
        } else if observed_models.len() == 1
            && observed_models.first().map(String::as_str) == Some(requested_model)
        {
            if requested.reasoning_effort.is_some() {
                AutopilotProfileBindingStatus::Incomparable
            } else {
                AutopilotProfileBindingStatus::Matched
            }
        } else {
            AutopilotProfileBindingStatus::Mismatch
        }
    } else {
        AutopilotProfileBindingStatus::Incomparable
    };
    let unavailable_reason = match status {
        AutopilotProfileBindingStatus::Incomparable => usage
            .and_then(|usage| usage.unavailable_reason.clone())
            .or_else(|| {
                requested.model.is_none().then(|| {
                    "not_process_observable: runtime_default dispatch omitted an explicit model, so the selected provider model is unknown"
                        .to_string()
                })
            })
            .or_else(|| {
                requested.reasoning_effort.is_some().then(|| {
                    "not_process_observable: process usage reports the dispatched model but not the resolved reasoning effort"
                        .to_string()
                })
            })
            .or_else(|| {
                Some(
                    "not_process_observable: no reliable dispatch-attributed model selection was reported for this role"
                        .to_string(),
                )
            }),
        _ => None,
    };
    AutopilotRoleModelExecutionBinding {
        role,
        requested: requested.clone(),
        observed_models,
        observation: if status == AutopilotProfileBindingStatus::Incomparable {
            RoleUsageObservation::NotProcessObservable
        } else {
            observation
        },
        status,
        unavailable_reason,
    }
}

fn review_lens_execution_binding(
    requested: &ReviewLensConfig,
    usage: Option<&ReviewLensUsageReport>,
    dispatch: Option<&ReviewLensDispatchEvidence>,
) -> AutopilotReviewLensExecutionBinding {
    let requested_backend_id = requested.backend.backend_id().to_string();
    let requested_model = requested.backend.model().to_string();
    let requested_reasoning_effort = requested.backend.reasoning_effort().map(str::to_string);
    let usage_is_process_observed = usage.is_some_and(|usage| {
        usage.observation == RoleUsageObservation::ProcessObserved && usage.usage.is_some()
    });
    let dispatches = dispatch
        .map(|dispatch| dispatch.selections.as_slice())
        .unwrap_or_default();
    let observed_backend_id =
        unique_dispatch_value(dispatches, |selection| selection.backend_id.as_deref());
    let observed_model = unique_dispatch_value(dispatches, |selection| selection.model.as_deref());
    let observed_reasoning_effort = unique_dispatch_value(dispatches, |selection| {
        selection.reasoning_effort.as_deref()
    });
    let selection_is_complete = !dispatches.is_empty()
        && dispatches.iter().all(|selection| {
            selection.backend_id.is_some()
                && selection.model.is_some()
                && (requested_reasoning_effort.is_none() || selection.reasoning_effort.is_some())
                && selection.unavailable_reason.is_none()
        });
    let status = if !usage_is_process_observed || !selection_is_complete {
        AutopilotProfileBindingStatus::Incomparable
    } else if dispatches.iter().any(|selection| {
        selection.backend_id.as_deref() != Some(requested_backend_id.as_str())
            || selection.model.as_deref() != Some(requested_model.as_str())
            || selection.reasoning_effort.as_deref() != requested_reasoning_effort.as_deref()
    }) {
        // Defensive only: requested/effective lens equality is checked before dispatch, and the
        // production command is built from that equality-gated effective lens.
        AutopilotProfileBindingStatus::Mismatch
    } else {
        AutopilotProfileBindingStatus::Matched
    };
    AutopilotReviewLensExecutionBinding {
        lens_id: requested.id.clone(),
        requested_backend_id,
        requested_model,
        requested_reasoning_effort,
        observed_backend_id,
        observed_model,
        observed_reasoning_effort,
        dispatch_count: dispatches.len(),
        observation: if status == AutopilotProfileBindingStatus::Incomparable {
            RoleUsageObservation::NotProcessObservable
        } else {
            RoleUsageObservation::ProcessObserved
        },
        status,
        unavailable_reason: (status == AutopilotProfileBindingStatus::Incomparable).then(|| {
            (!usage_is_process_observed)
                .then(|| {
                    usage
                        .and_then(|usage| usage.unavailable_reason.clone())
                        .unwrap_or_else(|| {
                            "not_process_observable: no reliable process-observable usage sample was attributed to this review lens"
                                .to_string()
                        })
                })
                .or_else(|| dispatch.and_then(|dispatch| dispatch.unavailable_reason.clone()))
                .or_else(|| {
                    dispatches
                        .iter()
                        .find_map(|selection| selection.unavailable_reason.clone())
                })
                .unwrap_or_else(|| {
                    "not_process_observable: the dispatched review-lens backend, model, or reasoning effort was unknown"
                        .to_string()
                })
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewLensDispatchSelection {
    backend_id: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
    unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReviewLensDispatchEvidence {
    selections: Vec<ReviewLensDispatchSelection>,
    unavailable_reason: Option<String>,
}

fn review_lens_dispatch_evidence(
    supervisor: &SupervisorFinalReport,
    lens_count: usize,
) -> Vec<ReviewLensDispatchEvidence> {
    review_lens_dispatch_evidence_from_records(
        supervisor
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.audit_reports.iter())
            // Supervisor collection appends its own sanitized command record after parsing the
            // runtime-authored report, so the last entry is parent evidence rather than a lens
            // claim about how it was launched.
            .map(|auditor| (auditor.id.as_str(), auditor.commands_run.last())),
        lens_count,
    )
}

fn review_lens_dispatch_evidence_from_records<'a>(
    auditors: impl IntoIterator<Item = (&'a str, Option<&'a CommandRunRecord>)>,
    lens_count: usize,
) -> Vec<ReviewLensDispatchEvidence> {
    let mut evidence = vec![ReviewLensDispatchEvidence::default(); lens_count];
    for (auditor_id, parent_recorded_command) in auditors {
        let Some(lens_index) = review_lens_auditor_index(auditor_id) else {
            continue;
        };
        let Some(lens_evidence) = evidence.get_mut(lens_index) else {
            continue;
        };
        let Some(parent_recorded_command) = parent_recorded_command else {
            lens_evidence.unavailable_reason = Some(
                "not_process_observable: the parent review-auditor report contained no dispatched command record"
                    .to_string(),
            );
            continue;
        };
        lens_evidence
            .selections
            .push(review_lens_selection_from_command(parent_recorded_command));
    }
    for lens_evidence in &mut evidence {
        if lens_evidence.selections.is_empty() && lens_evidence.unavailable_reason.is_none() {
            lens_evidence.unavailable_reason = Some(
                "not_process_observable: no parent-recorded review-lens dispatch was reported"
                    .to_string(),
            );
        }
    }
    evidence
}

fn review_lens_auditor_index(auditor_id: &str) -> Option<usize> {
    auditor_id
        .rsplit_once("-review-auditor-lens-")
        .and_then(|(_, index)| index.parse::<usize>().ok())
}

fn review_lens_selection_from_command(record: &CommandRunRecord) -> ReviewLensDispatchSelection {
    let model = unique_command_argument(&record.command, "-m");
    let backend_id = unique_codex_config_string(&record.command, "model_provider");
    let reasoning_effort = unique_codex_config_string(&record.command, "model_reasoning_effort");
    let unavailable_reason = model
        .as_ref()
        .err()
        .or_else(|| backend_id.as_ref().err())
        .or_else(|| reasoning_effort.as_ref().err())
        .cloned();
    ReviewLensDispatchSelection {
        backend_id: backend_id.unwrap_or_default(),
        model: model.unwrap_or_default(),
        reasoning_effort: reasoning_effort.unwrap_or_default(),
        unavailable_reason,
    }
}

fn unique_command_argument(
    command: &[String],
    flag: &str,
) -> std::result::Result<Option<String>, String> {
    let values = command
        .windows(2)
        .filter(|arguments| arguments[0] == flag)
        .map(|arguments| arguments[1].clone())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(format!(
            "not_process_observable: dispatched review-lens command contained multiple {flag} selections"
        )),
    }
}

fn unique_codex_config_string(
    command: &[String],
    key: &str,
) -> std::result::Result<Option<String>, String> {
    let prefix = format!("{key}=");
    let encoded = command
        .windows(2)
        .filter(|arguments| arguments[0] == "-c")
        .filter_map(|arguments| arguments[1].strip_prefix(&prefix))
        .collect::<Vec<_>>();
    let value = match encoded.as_slice() {
        [] => return Ok(None),
        [value] => *value,
        _ => {
            return Err(format!(
                "not_process_observable: dispatched review-lens command contained multiple {key} selections"
            ));
        }
    };
    serde_json::from_str::<String>(value).map(Some).map_err(|_| {
        format!(
            "not_process_observable: dispatched review-lens command contained an invalid {key} string"
        )
    })
}

fn unique_dispatch_value(
    dispatches: &[ReviewLensDispatchSelection],
    value: impl Fn(&ReviewLensDispatchSelection) -> Option<&str>,
) -> Option<String> {
    let values = dispatches.iter().filter_map(value).collect::<BTreeSet<_>>();
    if values.len() == 1 {
        values.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

struct FinalReportInput<'a> {
    run_id: &'a RunId,
    status: AutopilotRunStatus,
    attempt_count: usize,
    max_repair_attempts: usize,
    artifacts: AutopilotArtifactPaths,
    plan: AutopilotPlanSummary,
    profile_binding: AutopilotProfileBindingReport,
    safety: AutopilotSafetyReport,
    validation: AutopilotValidationSummary,
    pr: Option<SanitizedPrReport>,
    review: Option<ReviewReport>,
    attempts: Vec<AutopilotAttemptSummary>,
    supervisor: Option<SupervisorFinalReport>,
    gate_denials: Vec<GateDenial>,
    primary_worktree_untouched: bool,
    next_action: &'a str,
    auto_merge_requested: bool,
    generated_follow_up_dispatch_performed: bool,
}

fn final_report(input: FinalReportInput<'_>) -> AutopilotFinalReport {
    AutopilotFinalReport {
        version: AUTOPILOT_SCHEMA_VERSION,
        run_id: input.run_id.clone(),
        status: input.status,
        success: input.status == AutopilotRunStatus::Succeeded,
        attempt_count: input.attempt_count,
        repair_attempts_used: input.attempt_count.saturating_sub(1),
        max_repair_attempts: input.max_repair_attempts,
        reports_created: AutopilotReportsCreated {
            plan: true,
            supervisor_report: true,
            pr_report: true,
            review_report: true,
            final_report: true,
        },
        artifacts: input.artifacts,
        plan: input.plan,
        profile_binding: input.profile_binding,
        safety: input.safety,
        gate_denials: input.gate_denials,
        supervisor: input.supervisor,
        primary_worktree_untouched: input.primary_worktree_untouched,
        validation: input.validation,
        pr: input.pr,
        review: input.review,
        attempts: input.attempts,
        ci_reaction_supported: false,
        check_status: AutopilotCheckStatus {
            ci_reaction_supported: false,
            state: "not_supported".to_string(),
            details: "CI reaction and GitHub Actions polling are intentionally not implemented"
                .to_string(),
        },
        auto_merge_requested: input.auto_merge_requested,
        auto_merge_performed: false,
        generated_follow_up_dispatch_performed: input.generated_follow_up_dispatch_performed,
        next_action: input.next_action.to_string(),
    }
}

fn skipped_autopilot_validation() -> AutopilotValidationSummary {
    AutopilotValidationSummary {
        status: AutopilotValidationStatus::Skipped,
        reports: Vec::new(),
    }
}

fn sanitize_supervisor_report(
    repo: &Path,
    report: &SupervisorFinalReport,
) -> SanitizedSupervisorReport {
    SanitizedSupervisorReport {
        version: report.version,
        run_id: report.run_id.as_str().to_string(),
        runtime: match report.runtime {
            SupervisorRuntime::Codex => "codex",
            SupervisorRuntime::Fake => "fake",
        }
        .to_string(),
        publishable: report.publishable,
        success: report.success,
        status: review_status_label(report.status).to_string(),
        assigned_paths: report.assigned_paths.clone(),
        semantic_symbols: report.semantic_symbols.clone(),
        semantic_modules: report.semantic_modules.clone(),
        files_changed: report.files_changed.clone(),
        validation_results: report
            .validation_results
            .iter()
            .map(sanitize_supervisor_validation)
            .collect(),
        findings: report
            .findings
            .iter()
            .map(|finding| sanitize_supervisor_finding(repo, finding))
            .collect(),
        orchestrator_count: report.orchestrator_reports.len(),
        released_claim_count: report.released_claims.len(),
        released_semantic_intent_count: report.released_semantic_intents.len(),
        remaining_risk: sanitize_text(repo, &report.remaining_risk),
        next_safe_action: sanitize_text(repo, &report.next_safe_action),
    }
}

fn sanitize_supervisor_validation(validation: &ValidationResult) -> SanitizedSupervisorValidation {
    SanitizedSupervisorValidation {
        name: validation.name.clone(),
        status: review_status_label(validation.status).to_string(),
        message: validation.message.clone(),
    }
}

fn sanitize_supervisor_finding(
    repo: &Path,
    finding: &supervise::Finding,
) -> SanitizedSupervisorFinding {
    SanitizedSupervisorFinding {
        severity: finding_severity_label(finding.severity).to_string(),
        message: sanitize_text(repo, &finding.message),
        paths: finding
            .paths
            .iter()
            .filter_map(|path| public_report_path(repo, path))
            .collect(),
    }
}

fn sanitize_pr_report(report: &PrPublicationReport) -> SanitizedPrReport {
    SanitizedPrReport {
        status: pr_status_label(report.status).to_string(),
        forge: forge_label(report.forge).to_string(),
        draft: report.draft,
        created: report.created,
        pushed: report.pushed,
        pr_url: report.pr_url.clone(),
        changed_paths: report.changed_paths.clone(),
        readiness: readiness_label(report.readiness).to_string(),
        blockers: report
            .blockers
            .iter()
            .map(|blocker| blocker_label(*blocker).to_string())
            .collect(),
        validation_status: safety_status_label(report.validation_status).to_string(),
        title: report.title.clone(),
        body_summary: report.body_summary.text.clone(),
        body_truncated: report.body_summary.truncated,
    }
}

fn sanitize_autopilot_review_report(repo: &Path, report: &ReviewReport) -> ReviewReport {
    let mut sanitized = report.clone();
    sanitized.target = sanitize_text(repo, &sanitized.target);
    sanitized.reviewer.reviewer_id = sanitize_text(repo, &sanitized.reviewer.reviewer_id);
    sanitized.reviewer.model = sanitize_text(repo, &sanitized.reviewer.model);
    sanitized.changed_paths = sanitized
        .changed_paths
        .iter()
        .filter_map(|path| public_report_path(repo, path))
        .collect();
    for finding in &mut sanitized.findings {
        finding.path = finding
            .path
            .as_ref()
            .and_then(|path| public_report_path(repo, path));
        finding.severity = sanitize_text(repo, &finding.severity);
        finding.summary = sanitize_text(repo, &finding.summary);
        finding.suggested_fix = sanitize_text(repo, &finding.suggested_fix);
    }
    sanitized.diff_source = sanitize_text(repo, &sanitized.diff_source);
    sanitized.ci_reaction = sanitize_text(repo, &sanitized.ci_reaction);
    sanitized.next_action = sanitize_text(repo, &sanitized.next_action);
    if let Some(diagnostics) = sanitized.diagnostics.as_mut() {
        diagnostics.stdout.text = sanitize_text(repo, &diagnostics.stdout.text);
        diagnostics.stderr.text = sanitize_text(repo, &diagnostics.stderr.text);
        diagnostics.process_error = diagnostics
            .process_error
            .as_deref()
            .map(|message| sanitize_text(repo, message));
    }
    sanitized
}

fn validation_summary(reports: Vec<ValidationReport>) -> AutopilotValidationSummary {
    let status = if reports
        .iter()
        .any(|report| report.status == ValidationStatus::Failed)
    {
        AutopilotValidationStatus::Failed
    } else if reports
        .iter()
        .any(|report| report.status == ValidationStatus::Passed)
    {
        AutopilotValidationStatus::Passed
    } else {
        AutopilotValidationStatus::Skipped
    };
    AutopilotValidationSummary { status, reports }
}

fn plan_summary(plan: &AutopilotPlan) -> AutopilotPlanSummary {
    AutopilotPlanSummary {
        title: plan.task.title.clone(),
        assigned_paths: plan.assigned_paths.clone(),
        path_proposal: plan.path_proposal.clone(),
        semantic_symbols: plan.semantic_symbols.clone(),
        semantic_modules: plan.semantic_modules.clone(),
        forge_mode: plan.forge_mode,
        reviewer_mode: plan.reviewer.mode,
        publish_mode: plan.publish_mode,
    }
}

fn validation_repair_reason(validation: &AutopilotValidationSummary) -> String {
    let names = validation
        .reports
        .iter()
        .filter(|report| report.status == ValidationStatus::Failed)
        .map(|report| report.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    if names.is_empty() {
        "validation failed".to_string()
    } else {
        format!("validation failed: {names}")
    }
}

fn review_repair_reason(review: &ReviewReport) -> String {
    let summaries = review
        .findings
        .iter()
        .filter(|finding| finding.blocking)
        .map(|finding| finding.summary.clone())
        .collect::<Vec<_>>()
        .join("; ");
    if summaries.is_empty() {
        "review reported blocking findings".to_string()
    } else {
        format!("review blocking findings: {summaries}")
    }
}

fn artifact_paths() -> AutopilotArtifactPaths {
    AutopilotArtifactPaths {
        plan: PathBuf::from("plan.json"),
        supervisor_report: PathBuf::from("supervisor-report.json"),
        pr_report: PathBuf::from("pr-report.json"),
        review_report: PathBuf::from("review-report.json"),
        final_report: PathBuf::from("final-report.json"),
    }
}

fn artifact_status(reader: &ArtifactRunReader) -> AutopilotArtifactStatus {
    let contains = |path: &str| {
        reader
            .finalization()
            .files
            .iter()
            .any(|record| record.path == Path::new(path))
    };
    AutopilotArtifactStatus {
        plan: contains("plan.json"),
        supervisor_report: contains("supervisor-report.json"),
        pr_report: contains("pr-report.json"),
        review_report: contains("review-report.json"),
        final_report: contains("final-report.json"),
    }
}

enum ArtifactRunState {
    Missing,
    Active(AutopilotArtifactStatus),
    Finalized(Box<ArtifactRunReader>),
}

fn autopilot_artifact_run_state(repo: &Path, run_id: &RunId) -> Result<ArtifactRunState> {
    let run_dir = repo
        .join(".maco")
        .join("autopilot")
        .join("runs")
        .join(run_id.as_str());
    match fs::symlink_metadata(&run_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ArtifactRunState::Missing);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect artifact directory {}", run_dir.display())
            });
        }
        Ok(_) => {}
    }
    let inventory = BoundedTreeWalker::walk_with(
        &run_dir,
        BoundedTreeWalkLimits {
            max_depth: 2,
            max_entries: AUTOPILOT_ACTIVE_ARTIFACT_MAX_ENTRIES,
            max_path_bytes: AUTOPILOT_STATUS_MAX_PATH_BYTES,
            max_total_path_bytes: AUTOPILOT_ACTIVE_ARTIFACT_MAX_TOTAL_PATH_BYTES,
            max_duration: AUTOPILOT_ACTIVE_ARTIFACT_MAX_DURATION,
            same_device: true,
        },
        |_entry| Ok(BoundedTreeWalkAction::Record),
    )?;
    for entry in &inventory {
        if matches!(
            entry.kind,
            BoundedTreeEntryKind::Symlink | BoundedTreeEntryKind::Special
        ) || (entry.kind == BoundedTreeEntryKind::RegularFile && !entry.is_safe_regular_file())
        {
            bail!(
                "artifact entry is not a safe direct file or directory: {}",
                run_dir.join(&entry.relative_path).display()
            );
        }
    }
    let artifacts = artifact_status_from_inventory(&inventory)?;
    if !known_regular_file_exists(&inventory, ARTIFACT_FINAL_MARKER)? {
        return Ok(ArtifactRunState::Active(artifacts));
    }
    let reader =
        ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, run_id).with_context(|| {
            format!(
                "autopilot run '{}' has corrupt or unverifiable finalized artifacts",
                run_id.as_str()
            )
        })?;
    Ok(ArtifactRunState::Finalized(Box::new(reader)))
}

fn known_regular_file_exists(entries: &[BoundedTreeEntry], name: &str) -> Result<bool> {
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.relative_path == Path::new(name))
    else {
        return Ok(false);
    };
    if !entry.is_safe_regular_file() {
        bail!("artifact entry '{name}' is not a safe direct regular file");
    }
    Ok(true)
}

fn artifact_status_from_inventory(entries: &[BoundedTreeEntry]) -> Result<AutopilotArtifactStatus> {
    Ok(AutopilotArtifactStatus {
        plan: known_regular_file_exists(entries, "plan.json")?,
        supervisor_report: known_regular_file_exists(entries, "supervisor-report.json")?,
        pr_report: known_regular_file_exists(entries, "pr-report.json")?,
        review_report: known_regular_file_exists(entries, "review-report.json")?,
        final_report: known_regular_file_exists(entries, "final-report.json")?,
    })
}

fn empty_artifact_status() -> AutopilotArtifactStatus {
    AutopilotArtifactStatus {
        plan: false,
        supervisor_report: false,
        pr_report: false,
        review_report: false,
        final_report: false,
    }
}

fn write_skipped_stage_reports(writer: &mut ArtifactRunWriter, reason: &str) -> Result<()> {
    write_skipped_report(writer, "supervisor-report.json", reason)?;
    write_skipped_report(writer, "pr-report.json", reason)?;
    write_skipped_report(writer, "review-report.json", reason)
}

fn write_skipped_report(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    reason: &str,
) -> Result<()> {
    write_private_json(
        writer,
        relative,
        &SkippedStageReport {
            status: "skipped".to_string(),
            reason: reason.to_string(),
        },
    )
}

fn write_failed_report(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    reason: &str,
    message: &str,
) -> Result<()> {
    write_private_json(
        writer,
        relative,
        &FailedStageReport {
            status: "failed".to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
        },
    )
}

fn write_private_json<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    value: &T,
) -> Result<()> {
    writer.write_json(relative, value, ArtifactFileDisposition::PrivateEvidence)?;
    Ok(())
}

fn read_artifact_json(reader: &ArtifactRunReader, relative: impl AsRef<Path>) -> Result<Value> {
    let relative = relative.as_ref();
    let contents = reader.read(relative)?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse finalized artifact {}", relative.display()))
}

struct RepositoryPathBindings {
    worktree: DirectoryBindingGuard,
    git_dir: DirectoryBindingGuard,
    common_dir: DirectoryBindingGuard,
}

impl RepositoryPathBindings {
    fn bind(repo_path: &Path) -> Result<Self> {
        let repository = Repository::open(repo_path)
            .with_context(|| format!("failed to bind repository {}", repo_path.display()))?;
        let worktree = repository
            .workdir()
            .context("repository binding requires a non-bare worktree")?;
        let bindings = Self {
            worktree: DirectoryBindingGuard::bind(worktree)?,
            git_dir: DirectoryBindingGuard::bind(repository.path())?,
            common_dir: DirectoryBindingGuard::bind(repository.commondir())?,
        };
        bindings.verify()?;
        Ok(bindings)
    }

    fn verify(&self) -> Result<()> {
        self.worktree
            .verify()
            .context("repository worktree changed")?;
        self.git_dir
            .verify()
            .context("repository Git directory changed")?;
        self.common_dir
            .verify()
            .context("repository common directory changed")
    }
}

fn verify_after_autopilot_safety(bindings: &RepositoryPathBindings) -> Result<()> {
    #[cfg(test)]
    run_after_autopilot_safety_hook();
    bindings
        .verify()
        .context("repository changed after autopilot safety preflight")
}

#[cfg(test)]
type AutopilotProfileCallsiteHook = Box<dyn FnMut(&mut SupervisorPlan)>;

#[cfg(test)]
thread_local! {
    static AUTOPILOT_PROFILE_CALLSITE_HOOK: std::cell::RefCell<Option<AutopilotProfileCallsiteHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_autopilot_profile_callsite_hook(hook: impl FnMut(&mut SupervisorPlan) + 'static) {
    AUTOPILOT_PROFILE_CALLSITE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_autopilot_profile_callsite_hook(effective: &SupervisorPlan) -> Option<SupervisorPlan> {
    AUTOPILOT_PROFILE_CALLSITE_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            let mut overridden = effective.clone();
            hook(&mut overridden);
            Some(overridden)
        } else {
            None
        }
    })
}

#[cfg(test)]
thread_local! {
    static AFTER_AUTOPILOT_SAFETY_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_autopilot_safety_hook(hook: impl FnMut() + 'static) {
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_autopilot_safety_hook() {
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn dirty_primary_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    bounded_repository_dirty_paths(repo_path)
}

fn bounded_repository_dirty_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let mut dirty = crate::worktree::bounded_repository_status_paths(
        repo_path,
        AUTOPILOT_STATUS_MAX_ENTRIES,
        AUTOPILOT_STATUS_MAX_TOTAL_PATH_BYTES,
        AUTOPILOT_STATUS_MAX_DURATION,
    )?
    .into_iter()
    .map(|(path, _status)| normalize_repo_relative_path(path))
    .collect::<std::result::Result<Vec<_>, _>>()?;
    dirty.retain(|path| !is_local_runtime_path(path));
    dirty.sort();
    dirty.dedup();
    Ok(dirty)
}

fn is_local_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
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

fn sorted_unique_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn title_from_plain_task(task: &str) -> String {
    task.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Autopilot task")
        .to_string()
}

fn attempt_agent_id(run_id: &RunId, attempt: usize) -> Result<String> {
    crate::worktree::normalize_agent_id(&format!("autopilot-{}-a{attempt}", run_id.as_str()))
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn public_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("autopilot").join("runs")
}

fn public_report_path(repo: &Path, path: &Path) -> Option<PathBuf> {
    let relative = if path.is_absolute() {
        path.strip_prefix(repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.file_name().map(PathBuf::from).unwrap_or_default())
    } else {
        path.to_path_buf()
    };
    if relative.as_os_str().is_empty() {
        return None;
    }
    if relative.starts_with(".maco") || relative.starts_with(".agents") {
        return relative.file_name().map(PathBuf::from);
    }
    Some(relative)
}

fn sanitize_text(repo: &Path, text: &str) -> String {
    let mut redactor =
        Redactor::new().with_private_value("repository-path", repo.display().to_string());
    if let Some(parent) = repo.parent() {
        redactor = redactor.with_private_value("repository-parent", parent.display().to_string());
    }
    if let Ok(repository) = Repository::open(repo) {
        redactor = redactor
            .with_private_value("git-path", repository.path().display().to_string())
            .with_private_value(
                "git-common-path",
                repository.commondir().display().to_string(),
            );
        if let Some(primary_root) = repository.commondir().parent() {
            redactor = redactor.with_private_value(
                "primary-repository-path",
                primary_root.display().to_string(),
            );
        }
    }
    let without_controls = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();
    let redacted = redactor.redact(&without_controls).text;
    let mut bounded = redacted
        .chars()
        .take(AUTOPILOT_MESSAGE_LIMIT_CHARS)
        .collect::<String>();
    if redacted.chars().count() > AUTOPILOT_MESSAGE_LIMIT_CHARS {
        bounded.push_str("…<truncated>");
    }
    bounded
}

fn sanitize_validation_message(worktree: &Path, text: &str) -> String {
    sanitize_text(worktree, text)
}

fn default_autopilot_schema_version() -> u32 {
    AUTOPILOT_SCHEMA_VERSION
}

fn default_max_repair_attempts() -> usize {
    1
}

impl AutopilotForgeMode {
    fn into_publication_forge(self) -> ForgeKind {
        match self {
            Self::Fake => ForgeKind::Fake,
            Self::Git => ForgeKind::Git,
            Self::Github => ForgeKind::Github,
        }
    }
}

fn reviewer_config_may_authorize_publication(forge: ForgeKind, reviewer: &ReviewerConfig) -> bool {
    matches!(forge, ForgeKind::Fake) || reviewer_config_has_direct_program_binding(reviewer)
}

fn reviewer_config_has_direct_program_binding(reviewer: &ReviewerConfig) -> bool {
    reviewer.mode == ReviewerMode::ExternalCommand
        && reviewer.program.is_some()
        && reviewer.command.is_none()
}

fn reviewer_identity_matches_mode(report: &ReviewReport) -> bool {
    match report.reviewer.mode {
        ReviewerMode::Fake => {
            report.reviewer.reviewer_id == "autopilot-fake-reviewer"
                && report.reviewer.model == "deterministic-local-reviewer"
        }
        ReviewerMode::ExternalCommand => report
            .reviewer
            .reviewer_id
            .strip_prefix(EXTERNAL_REVIEWER_ID_PREFIX)
            .is_some_and(|binding| {
                is_lower_hex(binding, EXTERNAL_REVIEWER_BINDING_HEX_LEN)
                    && report.reviewer.model == EXTERNAL_REVIEWER_MODEL
            }),
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn publish_requested_for_audit(
    real_runtime_requested: bool,
    forge_mode: AutopilotForgeMode,
    publication_attempted: bool,
) -> bool {
    real_runtime_requested && forge_mode != AutopilotForgeMode::Fake && publication_attempted
}

fn pr_status_label(status: PrPublicationStatus) -> &'static str {
    match status {
        PrPublicationStatus::Preview => "preview",
        PrPublicationStatus::Blocked => "blocked",
        PrPublicationStatus::Published => "published",
    }
}

fn forge_label(forge: ForgeKind) -> &'static str {
    match forge {
        ForgeKind::Fake => "fake",
        ForgeKind::Git => "git",
        ForgeKind::Github => "github",
    }
}

fn readiness_label(status: ApplyReadinessStatus) -> &'static str {
    match status {
        ApplyReadinessStatus::Safe => "safe",
        ApplyReadinessStatus::Forced => "forced",
        ApplyReadinessStatus::Blocked => "blocked",
    }
}

fn safety_status_label(status: SafetyCheckStatus) -> &'static str {
    match status {
        SafetyCheckStatus::Passed => "passed",
        SafetyCheckStatus::Failed => "failed",
        SafetyCheckStatus::Skipped => "skipped",
    }
}

fn blocker_label(blocker: ApplyBlocker) -> &'static str {
    match blocker {
        ApplyBlocker::DirtyPrimary => "dirty_primary",
        ApplyBlocker::StaleBase => "stale_base",
        ApplyBlocker::ApplyCheckFailed => "apply_check_failed",
        ApplyBlocker::ExcludedReference => "excluded_reference",
        ApplyBlocker::UnclaimedEdits => "unclaimed_edits",
        ApplyBlocker::ValidationMissing => "validation_missing",
        ApplyBlocker::ValidationNotRun => "validation_not_run",
        ApplyBlocker::ValidationSkipped => "validation_skipped",
        ApplyBlocker::ValidationFailed => "validation_failed",
    }
}

fn review_status_label(status: ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Pending => "pending",
        ReviewStatus::Succeeded => "succeeded",
        ReviewStatus::Failed => "failed",
        ReviewStatus::Rejected => "rejected",
        ReviewStatus::Missing => "missing",
    }
}

fn finding_severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_agent::ExternalAgentCommand,
        gate_denial::GateDenialReason,
        supervise::{
            AuditorReport, Finding, LicensedBreakageDeclaration, LicensedBreakageDependentScope,
            OrchestratorReviewReport,
        },
        worktree::WorktreeCreateOptions,
    };
    use serde_json::json;
    use std::{
        cell::{Cell, RefCell},
        fs::File,
        rc::Rc,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard, OnceLock,
        },
    };

    // These fixtures each perform several bounded, strict-containment Git snapshots. Running them
    // concurrently only multiplies systemd-slot contention; it is not part of their gate semantics.
    static PREPUBLICATION_FIXTURE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_prepublication_fixture_test() -> MutexGuard<'static, ()> {
        PREPUBLICATION_FIXTURE_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn supervisor_profile_test_plan() -> AutopilotPlan {
        AutopilotPlan {
            version: AUTOPILOT_SCHEMA_VERSION,
            task: AutopilotTask {
                title: "Profile plumbing".to_string(),
                body: "Keep the supervisor profile bound to this attempt.".to_string(),
            },
            assigned_paths: vec![PathBuf::from("README.md")],
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            validation_commands: Vec::new(),
            max_repair_attempts: 1,
            forge_mode: AutopilotForgeMode::Fake,
            reviewer: ReviewerConfig::default(),
            publish_mode: AutopilotPublishMode::DraftOnly,
            auto_merge: false,
            external_source: None,
        }
    }

    fn nondefault_test_profile() -> AutopilotProfile {
        AutopilotProfile {
            version: AUTOPILOT_PROFILE_SCHEMA_VERSION,
            role_models: BTreeMap::from([(
                AgentRole::Worker,
                RoleModelSelection {
                    model: Some("profile-worker".to_string()),
                    reasoning_effort: Some("medium".to_string()),
                    unavailable_model_fallback:
                        crate::supervise::UnavailableModelFallback::LocalDeterministicFake,
                },
            )]),
            model_pricing: BTreeMap::from([(
                "profile-worker".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 1.25,
                    output_usd_per_million_tokens: 5.5,
                },
            )]),
            review_lenses: vec![ReviewLensConfig {
                id: "profile-review".to_string(),
                backend: ReviewLensBackendConfig::Model {
                    backend_id: "profile-provider".to_string(),
                    model: "profile-review-model".to_string(),
                    reasoning_effort: Some("high".to_string()),
                },
                information_scope: crate::review::ReviewInformationScope::DiffOnly,
            }],
            review_aggregation_policy: ReviewAggregationPolicy::ValidatedQuorum {
                minimum_accepts: 1,
            },
        }
    }

    #[test]
    fn omitted_profile_preserves_legacy_supervisor_plan_bytes() {
        let plan = supervisor_profile_test_plan();
        let profile = AutopilotProfile::default();
        let actual = supervisor_plan_for_attempt(&plan, &profile, "agent-a", 1, &[]);
        let task = supervisor_task(&plan, 1, &[]);
        let legacy = SupervisorPlan {
            version: 1,
            task: task.clone(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: crate::supervise::default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![OrchestratorAssignment {
                id: "agent-a".to_string(),
                role: AgentRole::ChildOrchestrator,
                assigned_paths: plan.assigned_paths.clone(),
                semantic_symbols: plan.semantic_symbols.clone(),
                semantic_modules: plan.semantic_modules.clone(),
                task: None,
                worker_assignments: vec![WorkerAssignment {
                    id: "agent-a-worker".to_string(),
                    role: AgentRole::Worker,
                    assigned_paths: plan.assigned_paths.clone(),
                    semantic_symbols: plan.semantic_symbols.clone(),
                    semantic_modules: plan.semantic_modules.clone(),
                    task: Some(task),
                    environment_requirements: Vec::new(),
                    report_path: None,
                }],
                environment_requirements: Vec::new(),
                licensed_breakage: None,
                notes: Some("autopilot attempt 1".to_string()),
            }],
        };

        assert_eq!(
            serde_json::to_vec(&actual).expect("serialize actual supervisor plan"),
            serde_json::to_vec(&legacy).expect("serialize legacy supervisor plan")
        );
    }

    #[test]
    fn requested_effective_profile_mismatch_is_typed_and_blocks_dispatch() {
        let plan = supervisor_profile_test_plan();
        let requested = nondefault_test_profile();
        let mut effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        effective.role_models.clear();
        effective.model_pricing.clear();
        effective.review_lenses = crate::supervise::default_supervisor_review_lenses();
        effective.review_aggregation_policy = ReviewAggregationPolicy::AllMustAccept;

        let binding = AutopilotProfileBindingReport::from_effective(requested, &effective);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
        assert_eq!(
            binding.configuration_status,
            AutopilotProfileBindingStatus::Mismatch
        );
        assert_eq!(
            binding.failure,
            Some(AutopilotProfileBindingFailure {
                kind: AutopilotProfileBindingFailureKind::RequestedEffectiveMismatch,
                mismatched_fields: vec![
                    AutopilotProfileBindingField::RoleModels,
                    AutopilotProfileBindingField::ModelPricing,
                    AutopilotProfileBindingField::ReviewLenses,
                    AutopilotProfileBindingField::ReviewAggregationPolicy,
                ],
                mismatched_roles: Vec::new(),
                mismatched_review_lens_ids: Vec::new(),
            })
        );
        assert!(!binding.permits_dispatch());
    }

    #[test]
    fn requested_effective_lens_mismatch_blocks_before_dispatch() {
        let plan = supervisor_profile_test_plan();
        let requested = nondefault_test_profile();
        let mut effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let ReviewLensBackendConfig::Model { backend_id, .. } =
            &mut effective.review_lenses[0].backend
        else {
            panic!("test profile lens must be model-backed");
        };
        *backend_id = "different-effective-provider".to_string();

        let binding = AutopilotProfileBindingReport::from_effective(requested, &effective);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
        assert_eq!(
            binding.configuration_status,
            AutopilotProfileBindingStatus::Mismatch
        );
        assert_eq!(
            binding.failure,
            Some(AutopilotProfileBindingFailure {
                kind: AutopilotProfileBindingFailureKind::RequestedEffectiveMismatch,
                mismatched_fields: vec![AutopilotProfileBindingField::ReviewLenses],
                mismatched_roles: Vec::new(),
                mismatched_review_lens_ids: Vec::new(),
            })
        );
        assert!(!binding.permits_dispatch());
    }

    fn process_observed_role_usage(models: Vec<&str>) -> RoleUsageReport {
        RoleUsageReport {
            models: models.into_iter().map(str::to_string).collect(),
            usage: Some(crate::llm::provider::Usage {
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
            }),
            cost_usd: None,
            observation: RoleUsageObservation::ProcessObserved,
            unavailable_reason: None,
        }
    }

    fn process_observed_lens_usage(lens: &ReviewLensConfig, model: &str) -> ReviewLensUsageReport {
        ReviewLensUsageReport {
            lens_id: lens.id.clone(),
            backend_id: lens.backend.backend_id().to_string(),
            model: model.to_string(),
            usage: Some(crate::llm::provider::Usage {
                input_tokens: 8,
                output_tokens: 4,
                total_tokens: 12,
            }),
            cost_usd: None,
            observation: RoleUsageObservation::ProcessObserved,
            unavailable_reason: None,
        }
    }

    fn synthetic_lens_dispatch_evidence(
        backend_id: Option<&str>,
        model: Option<&str>,
        reasoning_effort: Option<&str>,
    ) -> Vec<ReviewLensDispatchEvidence> {
        let command = crate::external_agent::ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt.md",
            "capture.jsonl",
            "report.json",
            Duration::from_secs(30),
        )
        .with_model_provider(backend_id.map(str::to_string))
        .with_model_selection(
            model.map(str::to_string),
            reasoning_effort.map(str::to_string),
        );
        let command = CommandRunRecord {
            command: crate::external_agent::command_argv(&command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect(),
            cwd: PathBuf::from("<child-worktree>"),
            exit_code: Some(0),
            status: ReviewStatus::Succeeded,
            timeout_seconds: 30,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            sandbox_denials: Vec::new(),
            environment_preflight_results: Vec::new(),
            environment_failures: Vec::new(),
            error: None,
        };
        review_lens_dispatch_evidence_from_records(
            [("agent-a-review-auditor-lens-0", Some(&command))],
            1,
        )
    }

    #[test]
    fn observed_requested_execution_profile_is_matched() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("profile-child".to_string()),
                reasoning_effort: None,
                unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
            },
        )]);
        let ReviewLensBackendConfig::Model {
            reasoning_effort, ..
        } = &mut requested.review_lenses[0].backend
        else {
            panic!("test profile lens must be model-backed");
        };
        *reasoning_effort = None;
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let role_usage = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            process_observed_role_usage(vec!["profile-child"]),
        )]);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];

        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("profile-provider"),
            Some("profile-review-model"),
            None,
        );
        binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Matched);
        assert_eq!(
            binding.configuration_status,
            AutopilotProfileBindingStatus::Matched
        );
        assert!(binding.failure.is_none());
        let execution = binding.execution.expect("execution binding");
        assert_eq!(
            execution.role_models[0].observed_models,
            vec!["profile-child"]
        );
        assert_eq!(
            execution.review_lenses[0].observed_model.as_deref(),
            Some("profile-review-model")
        );
    }

    #[test]
    fn observed_different_execution_profile_is_typed_mismatch() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("profile-child".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
            },
        )]);
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let role_usage = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            process_observed_role_usage(vec!["different-child"]),
        )]);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];

        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("profile-provider"),
            Some("profile-review-model"),
            Some("high"),
        );
        binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
        assert_eq!(
            binding.configuration_status,
            AutopilotProfileBindingStatus::Matched
        );
        assert_eq!(
            binding.failure,
            Some(AutopilotProfileBindingFailure {
                kind: AutopilotProfileBindingFailureKind::RequestedObservedSelectionMismatch,
                mismatched_fields: vec![AutopilotProfileBindingField::RoleModels],
                mismatched_roles: vec![AgentRole::ChildOrchestrator],
                mismatched_review_lens_ids: Vec::new(),
            })
        );
    }

    #[test]
    fn synthetic_complete_lens_dispatch_mismatch_is_a_defensive_signal() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models.clear();
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];
        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("different-synthetic-provider"),
            Some("profile-review-model"),
            Some("high"),
        );

        binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
        assert_eq!(
            binding.failure,
            Some(AutopilotProfileBindingFailure {
                kind: AutopilotProfileBindingFailureKind::RequestedObservedSelectionMismatch,
                mismatched_fields: vec![AutopilotProfileBindingField::ReviewLenses],
                mismatched_roles: Vec::new(),
                mismatched_review_lens_ids: vec!["profile-review".to_string()],
            })
        );
        let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
        assert_eq!(
            observed.observed_backend_id.as_deref(),
            Some("different-synthetic-provider")
        );
        assert_eq!(
            observed.observed_model.as_deref(),
            Some("profile-review-model")
        );
        assert_eq!(observed.observed_reasoning_effort.as_deref(), Some("high"));
        assert_eq!(observed.dispatch_count, 1);
    }

    #[test]
    fn incomplete_lens_dispatch_with_different_backend_is_incomparable() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models.clear();
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];
        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("different-synthetic-provider"),
            None,
            Some("high"),
        );

        binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        assert!(binding.failure.is_none());
        let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
        assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
        assert_eq!(
            observed.observed_backend_id.as_deref(),
            Some("different-synthetic-provider")
        );
        assert!(observed.observed_model.is_none());
        assert_eq!(
            observed.observation,
            RoleUsageObservation::NotProcessObservable
        );
    }

    #[test]
    fn complete_lens_dispatch_without_usage_is_incomparable() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models.clear();
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("profile-provider"),
            Some("profile-review-model"),
            Some("high"),
        );

        binding.observe_execution_reports(&BTreeMap::new(), &[], &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        assert!(binding.failure.is_none());
        let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
        assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
        assert_eq!(observed.dispatch_count, 1);
        assert_eq!(
            observed.observation,
            RoleUsageObservation::NotProcessObservable
        );
        assert!(observed
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not_process_observable")));
    }

    #[test]
    fn plan_echoed_lens_usage_without_dispatched_selection_is_incomparable() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models.clear();
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];
        let lens_dispatch = synthetic_lens_dispatch_evidence(None, None, None);

        binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        assert!(binding.failure.is_none());
        let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
        assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
        assert!(observed.observed_backend_id.is_none());
        assert!(observed.observed_model.is_none());
        assert_eq!(observed.dispatch_count, 1);
        assert!(observed
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not_process_observable")));
    }

    #[test]
    fn fake_worker_selection_is_incomparable_not_matched() {
        let plan = supervisor_profile_test_plan();
        let requested = nondefault_test_profile();
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let role_usage = BTreeMap::from([(
            AgentRole::Worker,
            RoleUsageReport {
                models: Vec::new(),
                usage: None,
                cost_usd: None,
                observation: RoleUsageObservation::NotProcessObservable,
                unavailable_reason: Some(
                    "nested fake worker usage is not process observable".to_string(),
                ),
            },
        )]);
        let lens_usage = vec![ReviewLensUsageReport {
            lens_id: requested.review_lenses[0].id.clone(),
            backend_id: requested.review_lenses[0].backend.backend_id().to_string(),
            model: requested.review_lenses[0].backend.model().to_string(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some("fake lens usage is not process observable".to_string()),
        }];

        let lens_dispatch = synthetic_lens_dispatch_evidence(None, None, None);
        binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        assert_eq!(
            binding.configuration_status,
            AutopilotProfileBindingStatus::Matched
        );
        assert!(binding.failure.is_none());
        let worker = &binding.execution.as_ref().expect("execution").role_models[0];
        assert_eq!(
            worker.observation,
            RoleUsageObservation::NotProcessObservable
        );
        assert_ne!(worker.status, AutopilotProfileBindingStatus::Matched);
    }

    #[test]
    fn runtime_default_without_explicit_model_is_incomparable() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: None,
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback:
                    crate::supervise::UnavailableModelFallback::RuntimeDefault,
            },
        )]);
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let role_usage = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            process_observed_role_usage(Vec::new()),
        )]);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];

        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("profile-provider"),
            Some("profile-review-model"),
            Some("high"),
        );
        binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        let role = &binding.execution.as_ref().expect("execution").role_models[0];
        assert_eq!(role.observation, RoleUsageObservation::NotProcessObservable);
        assert!(role
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("runtime_default")));
    }

    #[test]
    fn unobserved_reasoning_effort_keeps_matching_model_incomparable() {
        let plan = supervisor_profile_test_plan();
        let mut requested = nondefault_test_profile();
        requested.role_models = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("profile-child".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
            },
        )]);
        let ReviewLensBackendConfig::Model {
            reasoning_effort, ..
        } = &mut requested.review_lenses[0].backend
        else {
            panic!("test profile lens must be model-backed");
        };
        *reasoning_effort = None;
        let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
        let mut binding =
            AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
        let role_usage = BTreeMap::from([(
            AgentRole::ChildOrchestrator,
            process_observed_role_usage(vec!["profile-child"]),
        )]);
        let lens_usage = vec![process_observed_lens_usage(
            &requested.review_lenses[0],
            "profile-review-model",
        )];

        let lens_dispatch = synthetic_lens_dispatch_evidence(
            Some("profile-provider"),
            Some("profile-review-model"),
            None,
        );
        binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

        assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
        let role = &binding.execution.as_ref().expect("execution").role_models[0];
        assert_eq!(role.observation, RoleUsageObservation::NotProcessObservable);
        assert!(role
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("reasoning effort")));
    }

    fn create_committed_autopilot_repo(root: &Path) -> PathBuf {
        let repo_path = root.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        fs::write(repo_path.join(".gitignore"), ".maco/\n.agents/\n").expect("write gitignore");
        let repository = Repository::open(&repo_path).expect("open repository");
        let mut index = repository.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index
            .add_path(Path::new(".gitignore"))
            .expect("stage gitignore");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repository.find_tree(tree_id).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repository);
        repo_path
    }

    #[cfg(target_os = "linux")]
    fn secure_autopilot_machine_global_retention(
        root: &Path,
        correlation_id: &str,
    ) -> MachineGlobalRetentionBinding {
        use std::os::unix::fs::PermissionsExt;

        let runtime_root = crate::process_runner::trusted_linux_runtime_root()
            .expect("resolve trusted runtime root for injected Autopilot cascade");
        let state_root = root.join(format!("{correlation_id}-machine-global-state"));
        fs::create_dir(&state_root).expect("create injected Autopilot machine-global state");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("secure injected Autopilot machine-global state");
        let config = root.join(format!("{correlation_id}-machine-global.json"));
        fs::write(
            &config,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "state_root": state_root,
                "roots": [{
                    "id": "runtime",
                    "path": runtime_root,
                    "protected_paths": [],
                    "quarantine_grace_seconds": 60
                }]
            }))
            .expect("serialize injected Autopilot machine-global config"),
        )
        .expect("write injected Autopilot machine-global config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .expect("secure injected Autopilot machine-global config");
        MachineGlobalRetentionBinding {
            config,
            root_id: "runtime".to_string(),
            owner: "maco-autopilot-test".to_string(),
            correction_correlation_id: correlation_id.to_string(),
        }
    }

    fn licensed_autopilot_supervisor_plan() -> (Value, LicensedBreakageDeclaration, String) {
        let declaration = LicensedBreakageDeclaration {
            migration_rationale: "Rename callers to crate::api::new_name before dependent dispatch"
                .to_string(),
            dependents: vec![LicensedBreakageDependentScope {
                dependent_id: "client-a".to_string(),
                paths: vec![PathBuf::from("src/client.rs")],
                interfaces: vec!["crate::api::new_name".to_string()],
            }],
        };
        let declaration_sha256 = crate::artifacts::state_auth::sha256_hex(
            &serde_json::to_vec(&declaration).expect("serialize Autopilot license declaration"),
        );
        let plan = SupervisorPlan {
            version: 1,
            task: "perform licensed source change and bounded dependent update".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: crate::supervise::default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![OrchestratorAssignment {
                id: "child-a".to_string(),
                role: AgentRole::ChildOrchestrator,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: Some("apply licensed breaking source change".to_string()),
                worker_assignments: Vec::new(),
                environment_requirements: Vec::new(),
                licensed_breakage: Some(declaration.clone()),
                notes: None,
            }],
        };
        (
            serde_json::to_value(plan).expect("serialize licensed Autopilot supervisor plan"),
            declaration,
            declaration_sha256,
        )
    }

    fn injected_autopilot_child_report(
        id: &str,
        assigned_paths: Vec<PathBuf>,
        semantic_symbols: Vec<String>,
        files_changed: Vec<PathBuf>,
        licensed_failure: bool,
    ) -> OrchestratorReviewReport {
        let (validation_results, findings, accepted, rejected, status) = if licensed_failure {
            let signature =
                "error[E0425]: cannot find function crate::api::new_name in dependent client";
            (
                vec![ValidationResult {
                    name: "client-a".to_string(),
                    status: ReviewStatus::Failed,
                    command: vec!["cargo".to_string(), "check".to_string()],
                    message: Some(signature.to_string()),
                }],
                vec![Finding {
                    severity: FindingSeverity::Error,
                    message: signature.to_string(),
                    paths: vec![PathBuf::from("src/client.rs")],
                }],
                false,
                true,
                ReviewStatus::Failed,
            )
        } else {
            (
                vec![ValidationResult {
                    name: "injected generated validation".to_string(),
                    status: ReviewStatus::Succeeded,
                    command: Vec::new(),
                    message: None,
                }],
                Vec::new(),
                true,
                false,
                ReviewStatus::Succeeded,
            )
        };
        OrchestratorReviewReport {
            id: id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths,
            semantic_symbols,
            semantic_modules: Vec::new(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            files_changed,
            validation_results,
            findings,
            field_guide_entries: Vec::new(),
            worker_reports: Vec::new(),
            audit_reports: Vec::new(),
            review_lens_aggregate: None,
            decomposition_completions: Vec::new(),
            licensed_breakage_review: None,
            generated_follow_up_tasks: Vec::new(),
            gate_denials: Vec::new(),
            gate_correction_outcomes: Vec::new(),
            accepted,
            rejected,
            status,
            remaining_risk: if licensed_failure {
                "declared dependent update remains".to_string()
            } else {
                "none".to_string()
            },
            next_safe_action: "parent review".to_string(),
        }
    }

    fn injected_autopilot_auditor_report(
        assignment_id: &str,
        reviewed_paths: Vec<PathBuf>,
        declaration_sha256: Option<&str>,
    ) -> AuditorReport {
        let mut validation_results = vec![ValidationResult {
            name: "injected auditor validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }];
        if let Some(declaration_sha256) = declaration_sha256 {
            validation_results.push(ValidationResult {
                name: "licensed_breakage_declaration".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: Some(declaration_sha256.to_string()),
            });
        }
        AuditorReport {
            id: format!("{assignment_id}-review-auditor-lens-0"),
            role: AgentRole::Auditor,
            reviewed_worker_ids: vec![assignment_id.to_string()],
            reviewed_paths,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            validation_results,
            findings: Vec::new(),
            rejection_kind: None,
            no_further_delegation: Some(true),
            read_only: true,
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "parent acceptance".to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    fn injected_licensed_autopilot_runner(
        declaration_sha256: String,
        source_child_dispatches: Arc<AtomicUsize>,
        follow_up_child_dispatches: Arc<AtomicUsize>,
    ) -> impl FnMut(&ExternalAgentCommand) -> crate::external_agent::ExternalAgentRun + Send {
        move |command: &ExternalAgentCommand| {
            let output_path = command.output_last_message.to_string_lossy();
            let is_follow_up = output_path.contains("child-a-licensed-update-01");
            let is_auditor = output_path.contains("review-auditor");
            if is_auditor && is_follow_up {
                supervise::write_injected_json(
                    &command.output_last_message,
                    &injected_autopilot_auditor_report(
                        "child-a-licensed-update-01",
                        vec![PathBuf::from("src/client.rs")],
                        None,
                    ),
                );
            } else if is_auditor {
                supervise::write_injected_json(
                    &command.output_last_message,
                    &injected_autopilot_auditor_report(
                        "child-a",
                        vec![PathBuf::from("README.md")],
                        Some(&declaration_sha256),
                    ),
                );
            } else if is_follow_up {
                let count = follow_up_child_dispatches
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                assert_eq!(count, 1, "generated child reran");
                fs::create_dir_all(command.cwd.join("src"))
                    .expect("create injected Autopilot dependent dir");
                fs::write(
                    command.cwd.join("src/client.rs"),
                    "pub fn migrated_client() {}\n",
                )
                .expect("write injected Autopilot dependent update");
                supervise::write_injected_json(
                    &command.output_last_message,
                    &injected_autopilot_child_report(
                        "child-a-licensed-update-01",
                        vec![PathBuf::from("src/client.rs")],
                        vec!["crate::api::new_name".to_string()],
                        vec![PathBuf::from("src/client.rs")],
                        false,
                    ),
                );
            } else {
                let count = source_child_dispatches
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                assert_eq!(count, 1, "Autopilot source child reran");
                fs::write(command.cwd.join("README.md"), "licensed source change\n")
                    .expect("write injected Autopilot source candidate");
                supervise::write_injected_json(
                    &command.output_last_message,
                    &injected_autopilot_child_report(
                        "child-a",
                        vec![PathBuf::from("README.md")],
                        Vec::new(),
                        vec![PathBuf::from("README.md")],
                        true,
                    ),
                );
            }
            supervise::write_injected_usage(command, 0, 1);
            supervise::injected_verified_run(command)
        }
    }

    #[cfg(target_os = "linux")]
    fn run_injected_licensed_autopilot_cascade_result(
        temp_root: &Path,
        repo: &Path,
        run_name: &str,
    ) -> (Result<AutopilotFinalReport>, usize, usize) {
        let outer_plan = temp_root.join(format!("{run_name}-autopilot.json"));
        fs::write(
            &outer_plan,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "task": {
                    "title": "Licensed cascade",
                    "body": "Dispatch one bounded generated dependent update."
                },
                "assigned_paths": ["README.md"],
                "auto_merge": false
            }))
            .expect("serialize injected Autopilot outer plan"),
        )
        .expect("write injected Autopilot outer plan");
        let (supervisor_plan, _declaration, declaration_sha256) =
            licensed_autopilot_supervisor_plan();
        let source_child_dispatches = Arc::new(AtomicUsize::new(0));
        let follow_up_child_dispatches = Arc::new(AtomicUsize::new(0));
        let mut runner = injected_licensed_autopilot_runner(
            declaration_sha256,
            Arc::clone(&source_child_dispatches),
            Arc::clone(&follow_up_child_dispatches),
        );
        let report = run_autopilot_plan_file_with_injected_supervisor_and_runner(
            AutopilotRunOptions {
                repo: repo.to_path_buf(),
                plan_file: outer_plan,
                run_id: RunId::new(run_name).expect("injected Autopilot run id"),
                codex_bin: Some(PathBuf::from("unused-injected-codex")),
                reviewer_command: None,
                allow_dirty_primary: false,
            },
            None,
            secure_autopilot_machine_global_retention(temp_root, run_name),
            supervisor_plan,
            &mut runner,
        );
        (
            report,
            source_child_dispatches.load(Ordering::SeqCst),
            follow_up_child_dispatches.load(Ordering::SeqCst),
        )
    }

    #[cfg(target_os = "linux")]
    fn run_injected_licensed_autopilot_cascade(
        temp_root: &Path,
        repo: &Path,
        run_name: &str,
    ) -> (AutopilotFinalReport, usize) {
        let (report, source_child_dispatches, follow_up_child_dispatches) =
            run_injected_licensed_autopilot_cascade_result(temp_root, repo, run_name);
        assert_eq!(source_child_dispatches, 1);
        (
            report.expect("run injected licensed Autopilot cascade"),
            follow_up_child_dispatches,
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn autopilot_authenticated_follow_up_dispatch_sets_boolean_after_real_gates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let head_before = Repository::open(&repo)
            .expect("open injected Autopilot repository")
            .head()
            .expect("read injected Autopilot HEAD")
            .target()
            .expect("injected Autopilot HEAD oid");
        let (report, follow_up_child_dispatches) = run_injected_licensed_autopilot_cascade(
            temp.path(),
            &repo,
            "autopilot-licensed-follow-up-allowed",
        );

        assert_eq!(follow_up_child_dispatches, 1);
        assert_eq!(report.status, AutopilotRunStatus::Succeeded, "{report:#?}");
        assert!(report.success, "{report:#?}");
        assert!(report.generated_follow_up_dispatch_performed);
        assert!(report.primary_worktree_untouched);
        assert!(!report.auto_merge_requested);
        assert!(!report.auto_merge_performed);
        assert!(report.supervisor.as_ref().is_some_and(|source| {
            source.success && source.publishable && source.generated_follow_up_tasks.len() == 1
        }));
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &report.run_id)
            .expect("open injected Autopilot final artifacts");
        let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
            &reader
                .read(Path::new("follow-up-cascade-report.json"))
                .expect("read injected Autopilot cascade report"),
        )
        .expect("decode injected Autopilot cascade report");
        assert!(cascade.follow_up_cascade_success, "{cascade:#?}");
        assert_eq!(
            cascade
                .follow_up_queue
                .expect("injected Autopilot queue summary")
                .authenticated_child_dispatch_started_count,
            1
        );
        assert_eq!(
            Repository::open(&repo)
                .expect("reopen injected Autopilot repository")
                .head()
                .expect("reread injected Autopilot HEAD")
                .target()
                .expect("reread injected Autopilot HEAD oid"),
            head_before
        );
        assert!(!repo.join("src/client.rs").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn autopilot_cascade_error_after_authenticated_follow_up_start_never_reports_false() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let primary_before = supervise::verified_whole_primary_snapshot_sha256(&repo)
            .expect("capture primary before post-start failure");
        supervise::set_interrupt_after_authenticated_follow_up_child_start();

        let (report, source_child_dispatches, follow_up_child_dispatches) =
            run_injected_licensed_autopilot_cascade_result(
                temp.path(),
                &repo,
                "autopilot-post-authenticated-start-error",
            );
        let report = report.expect("return an honest failed Autopilot report");

        assert_eq!(source_child_dispatches, 1);
        assert_eq!(follow_up_child_dispatches, 1);
        assert_eq!(report.status, AutopilotRunStatus::Failed, "{report:#?}");
        assert!(!report.success);
        assert!(report.generated_follow_up_dispatch_performed);
        assert!(report.primary_worktree_untouched);
        assert!(!report.auto_merge_performed);
        assert!(report.next_action.contains("dispatch started"));
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &report.run_id)
            .expect("open finalized honest post-start Autopilot report");
        let final_report: Value = serde_json::from_slice(
            &reader
                .read(Path::new("final-report.json"))
                .expect("read honest post-start final report"),
        )
        .expect("decode honest post-start final report");
        assert_eq!(
            final_report["generated_follow_up_dispatch_performed"],
            Value::Bool(true)
        );
        assert_eq!(
            supervise::verified_whole_primary_snapshot_sha256(&repo)
                .expect("capture primary after post-start failure"),
            primary_before
        );
        assert!(!repo.join("src/client.rs").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn autopilot_marker_without_child_checkpoint_refuses_a_false_final_report() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let run_name = "autopilot-unobservable-generated-dispatch";
        let run_id = RunId::new(run_name).expect("unobservable Autopilot run id");
        let primary_before = supervise::verified_whole_primary_snapshot_sha256(&repo)
            .expect("capture primary before marker-only interruption");
        supervise::set_interrupt_after_follow_up_dispatch_started();

        let (report, source_child_dispatches, follow_up_child_dispatches) =
            run_injected_licensed_autopilot_cascade_result(temp.path(), &repo, run_name);
        let error = report.expect_err("marker-only dispatch state must not finalize false");

        assert_eq!(source_child_dispatches, 1);
        assert_eq!(follow_up_child_dispatches, 0);
        let message = format!("{error:#}");
        assert!(message.contains("not_process_observable"), "{message}");
        assert!(
            message.contains("refusing to finalize a false execution claim"),
            "{message}"
        );
        assert!(
            !crate::artifacts::final_report_path(&repo, RunArtifactFamily::Autopilot, &run_id,)
                .exists()
        );
        assert!(ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id).is_err());
        assert_eq!(
            supervise::verified_whole_primary_snapshot_sha256(&repo)
                .expect("capture primary after marker-only interruption"),
            primary_before
        );
        assert!(!repo.join("src/client.rs").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn autopilot_generated_plan_refusal_keeps_dispatch_boolean_false() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        supervise::set_before_generated_follow_up_plan_load_hook(|path| {
            let bytes = fs::read(path).expect("read persisted Autopilot generated plan");
            let mut value: Value =
                serde_json::from_slice(&bytes).expect("decode Autopilot generated plan");
            value["assignments"][0]["assigned_paths"] = json!(["src/client.rs", "src/expanded.rs"]);
            fs::write(
                path,
                serde_json::to_vec_pretty(&value).expect("encode drifted Autopilot generated plan"),
            )
            .expect("mutate persisted Autopilot generated plan");
        });

        let (report, follow_up_child_dispatches) = run_injected_licensed_autopilot_cascade(
            temp.path(),
            &repo,
            "autopilot-licensed-follow-up-refused",
        );

        assert_eq!(follow_up_child_dispatches, 0);
        assert_eq!(report.status, AutopilotRunStatus::Failed, "{report:#?}");
        assert!(!report.success);
        assert!(!report.generated_follow_up_dispatch_performed);
        assert!(report.primary_worktree_untouched);
        assert!(!report.auto_merge_performed);
        assert!(report.gate_denials.iter().any(|denial| {
            matches!(
                denial.reason,
                GateDenialReason::ApprovalReview {
                    denial: ApprovalReviewDenial::PermissionExpansion
                }
            )
        }));
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &report.run_id)
            .expect("open refused injected Autopilot artifacts");
        let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
            &reader
                .read(Path::new("follow-up-cascade-report.json"))
                .expect("read refused Autopilot cascade report"),
        )
        .expect("decode refused Autopilot cascade report");
        let queue = cascade.follow_up_queue.expect("refused Autopilot queue");
        assert_eq!(queue.pending_count, 1);
        assert_eq!(queue.dispatch_started_count, 0);
        assert_eq!(queue.acknowledged_terminal_count, 0);
        assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
        assert!(!repo.join("src/client.rs").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_autopilot_queue_resumes_through_supervise_without_duplicate_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let run_name = "autopilot-cross-entrypoint-resume";
        let outer_run_id = RunId::new(run_name).expect("cross-entrypoint Autopilot run id");
        let supervisor_run_id =
            RunId::new(format!("{run_name}-supervise")).expect("source supervisor run id");
        let outer_plan = temp.path().join(format!("{run_name}-autopilot.json"));
        fs::write(
            &outer_plan,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "task": {
                    "title": "Cross-entrypoint licensed cascade",
                    "body": "Resume the durable generated dependent through supervise run."
                },
                "assigned_paths": ["README.md"],
                "auto_merge": false
            }))
            .expect("serialize cross-entrypoint Autopilot plan"),
        )
        .expect("write cross-entrypoint Autopilot plan");
        let (supervisor_plan, _declaration, declaration_sha256) =
            licensed_autopilot_supervisor_plan();
        let retention = secure_autopilot_machine_global_retention(temp.path(), run_name);
        let source_child_dispatches = Arc::new(AtomicUsize::new(0));
        let follow_up_child_dispatches = Arc::new(AtomicUsize::new(0));
        let mut runner = injected_licensed_autopilot_runner(
            declaration_sha256,
            Arc::clone(&source_child_dispatches),
            Arc::clone(&follow_up_child_dispatches),
        );
        let observations = Rc::new(RefCell::new(Vec::new()));
        let observed = Rc::clone(&observations);
        supervise::set_generated_follow_up_queue_observer(move |observation| {
            observed.borrow_mut().push(observation);
        });
        let head_before = Repository::open(&repo)
            .expect("open cross-entrypoint repository")
            .head()
            .expect("read cross-entrypoint HEAD")
            .target()
            .expect("cross-entrypoint HEAD oid");
        let primary_before = supervise::verified_whole_primary_snapshot_sha256(&repo)
            .expect("capture cross-entrypoint primary baseline");

        supervise::set_interrupt_after_follow_up_enqueue();
        let interrupted = run_autopilot_plan_file_with_injected_supervisor_and_runner(
            AutopilotRunOptions {
                repo: repo.clone(),
                plan_file: outer_plan,
                run_id: outer_run_id.clone(),
                codex_bin: Some(PathBuf::from("unused-injected-codex")),
                reviewer_command: None,
                allow_dirty_primary: false,
            },
            None,
            retention.clone(),
            supervisor_plan,
            &mut runner,
        )
        .expect("return failed Autopilot report after injected enqueue interruption");
        assert_eq!(interrupted.status, AutopilotRunStatus::Failed);
        assert!(!interrupted.generated_follow_up_dispatch_performed);
        assert!(interrupted.primary_worktree_untouched);
        assert!(!interrupted.auto_merge_performed);
        assert_eq!(source_child_dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(follow_up_child_dispatches.load(Ordering::SeqCst), 0);
        let interrupted_queue = observations
            .borrow()
            .iter()
            .find(|observation| observation.label == "enqueued")
            .cloned()
            .expect("observe durable Autopilot-origin enqueue");
        assert_eq!(interrupted_queue.outer_entrypoint, "autopilot_run");
        assert_eq!(interrupted_queue.outer_command_run_id, run_name);
        assert_eq!(interrupted_queue.item_ids.len(), 1);
        assert!(interrupted_queue.subordinate_run_ids.is_empty());
        assert_eq!(interrupted_queue.pending_count, 1);
        assert_eq!(interrupted_queue.dispatch_started_count, 0);

        let supervisor_plan_file = repo
            .join(".maco/autopilot/runs")
            .join(run_name)
            .join("supervisor-plan.json");
        let resumed = supervise::resume_supervisor_plan_file_cascade_with_runner(
            SupervisorRunOptions {
                repo: repo.clone(),
                plan_file: supervisor_plan_file,
                run_id: supervisor_run_id.clone(),
                codex_bin: PathBuf::from("unused-injected-codex"),
                runtime: SupervisorRuntime::Codex,
                allow_dirty_primary: true,
                machine_global_retention: Some(retention),
            },
            &mut runner,
        )
        .expect("resume Autopilot-origin queue through direct supervise");
        supervise::clear_generated_follow_up_queue_observer();

        assert_eq!(resumed.source_report.run_id, supervisor_run_id);
        assert!(resumed.source_report.success, "{resumed:#?}");
        assert!(resumed.follow_up_cascade_success, "{resumed:#?}");
        assert!(resumed.generated_follow_up_dispatch_performed());
        assert_eq!(resumed.follow_up_primary_worktree_untouched, Some(true));
        assert_eq!(source_child_dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(follow_up_child_dispatches.load(Ordering::SeqCst), 1);
        let final_queue = resumed
            .follow_up_queue
            .expect("cross-entrypoint final queue summary");
        assert_eq!(
            final_queue.queue_instance_id,
            interrupted_queue.queue_instance_id
        );
        assert_eq!(final_queue.pending_count, 0);
        assert_eq!(final_queue.dispatch_started_count, 0);
        assert_eq!(final_queue.acknowledged_terminal_count, 1);
        assert_eq!(final_queue.authenticated_child_dispatch_started_count, 1);
        let observations = observations.borrow();
        let reopened = observations
            .iter()
            .filter(|observation| observation.label == "created_or_opened")
            .next_back()
            .expect("observe direct supervise queue reopen");
        let started = observations
            .iter()
            .find(|observation| observation.label == "dispatch_started")
            .expect("observe resumed subordinate dispatch start");
        let acknowledged = observations
            .iter()
            .find(|observation| observation.label == "acknowledged_terminal")
            .expect("observe resumed subordinate acknowledgement");
        for observation in [reopened, started, acknowledged] {
            assert_eq!(
                observation.queue_instance_id,
                interrupted_queue.queue_instance_id
            );
            assert_eq!(observation.outer_entrypoint, "autopilot_run");
            assert_eq!(observation.outer_command_run_id, run_name);
            assert_eq!(observation.item_ids, interrupted_queue.item_ids);
        }
        assert_eq!(started.subordinate_run_ids.len(), 1);
        assert_eq!(
            acknowledged.subordinate_run_ids,
            started.subordinate_run_ids
        );
        assert_eq!(
            supervise::verified_whole_primary_snapshot_sha256(&repo)
                .expect("capture cross-entrypoint final primary"),
            primary_before
        );
        assert_eq!(
            Repository::open(&repo)
                .expect("reopen cross-entrypoint repository")
                .head()
                .expect("reread cross-entrypoint HEAD")
                .target()
                .expect("reread cross-entrypoint HEAD oid"),
            head_before
        );
        assert!(!repo.join("src/client.rs").exists());
    }

    #[test]
    fn autopilot_missing_retention_binding_fails_before_any_repository_or_runtime_side_effect() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, b"unchanged").expect("write sentinel");
        let safety_hook_called = Rc::new(Cell::new(false));
        let observed = Rc::clone(&safety_hook_called);
        set_after_autopilot_safety_hook(move || observed.set(true));
        let before = fs::read_dir(temp.path())
            .expect("read temp before")
            .map(|entry| entry.expect("temp entry").file_name())
            .collect::<BTreeSet<_>>();

        let error = run_autopilot_plan_file(AutopilotRunOptions {
            repo: temp.path().join("repository-must-not-be-opened"),
            plan_file: temp.path().join("plan-must-not-be-read"),
            run_id: RunId::new("failclosed-no-effects").expect("run id"),
            codex_bin: Some(temp.path().join("worker-must-not-run")),
            reviewer_command: None,
            allow_dirty_primary: true,
        })
        .expect_err("autopilot must require the supervise retention binding");

        let after = fs::read_dir(temp.path())
            .expect("read temp after")
            .map(|entry| entry.expect("temp entry").file_name())
            .collect::<BTreeSet<_>>();
        AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| {
            slot.borrow_mut().take();
        });
        assert_eq!(before, after);
        assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"unchanged");
        assert!(!safety_hook_called.get());
        assert!(!temp.path().join(".maco").exists());
        assert!(format!("{error:#}").contains("--machine-global-config"));
    }

    #[cfg(unix)]
    #[test]
    fn repository_binding_rejects_root_swap_after_safety_preflight() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        let displaced = temp.path().join("repo-displaced");
        let replacement = repo.clone();
        let bindings = RepositoryPathBindings::bind(&repo).expect("bind repository");
        set_after_autopilot_safety_hook(move || {
            fs::rename(&replacement, &displaced).expect("displace repository root");
            fs::create_dir(&replacement).expect("create replacement root");
        });

        let error = verify_after_autopilot_safety(&bindings)
            .expect_err("repository root replacement must fail closed");

        assert!(format!("{error:#}").contains("repository"));
    }

    #[test]
    fn autopilot_rechecks_dirty_primary_immediately_before_supervisor_dispatch() {
        use crate::gate_denial::GateDenialReason;

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        fs::write(repo.join("README.md"), "baseline\n").expect("write README");
        let repository = Repository::open(&repo).expect("open repo");
        let mut index = repository.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repository.find_tree(tree_id).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit");
        drop(tree);
        drop(repository);
        let plan = temp.path().join("plan.json");
        fs::write(
            &plan,
            r#"{
              "version": 1,
              "task": {"title": "TOCTOU", "body": "Refuse drift before dispatch."},
              "assigned_paths": ["README.md"]
            }"#,
        )
        .expect("write plan");
        let primary = repo.clone();
        set_after_autopilot_safety_hook(move || {
            fs::write(primary.join("README.md"), "changed after preflight\n")
                .expect("change primary after first preflight");
        });

        let report = run_autopilot_plan_file_with_retention(
            AutopilotRunOptions {
                repo: repo.clone(),
                plan_file: plan,
                run_id: RunId::new("predispatch-primary-drift").expect("run id"),
                codex_bin: None,
                reviewer_command: None,
                allow_dirty_primary: false,
            },
            Some(MachineGlobalRetentionBinding {
                config: temp.path().join("must-not-open.json"),
                root_id: "runtime".to_string(),
                owner: "maco-autopilot".to_string(),
                correction_correlation_id: "predispatch-primary-drift".to_string(),
            }),
        )
        .expect("finalize typed pre-dispatch refusal");

        assert_eq!(report.status, AutopilotRunStatus::Refused);
        assert!(matches!(
            report.gate_denials.as_slice(),
            [GateDenial {
                reason: GateDenialReason::MergeRemediation {
                    blocker: ApplyBlocker::DirtyPrimary
                },
                ..
            }]
        ));
        assert!(!repo.join(".maco/o2").exists());
    }

    #[test]
    fn autopilot_reloads_effective_profile_at_call_site_before_starting_supervisor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "version": 1,
              "task": {"title": "Profile call site", "body": "Refuse persisted drift."},
              "assigned_paths": ["README.md"]
            }"#,
        )
        .expect("write plan");
        set_autopilot_profile_callsite_hook(|effective| {
            effective.role_models.clear();
        });

        let report = run_autopilot_plan_file_with_profile_and_retention(
            AutopilotRunOptions {
                repo: repo.clone(),
                plan_file: plan_path,
                run_id: RunId::new("effective-profile-callsite").expect("run id"),
                codex_bin: None,
                reviewer_command: None,
                allow_dirty_primary: false,
            },
            Some(nondefault_test_profile()),
            Some(MachineGlobalRetentionBinding {
                config: temp.path().join("must-not-open.json"),
                root_id: "runtime".to_string(),
                owner: "maco-autopilot".to_string(),
                correction_correlation_id: "effective-profile-callsite".to_string(),
            }),
        )
        .expect("finalize requested/effective call-site refusal");

        assert_eq!(report.status, AutopilotRunStatus::Failed);
        assert_eq!(report.attempt_count, 0);
        assert!(report.supervisor.is_none());
        assert_eq!(
            report.profile_binding.configuration_status,
            AutopilotProfileBindingStatus::Mismatch
        );
        assert!(!report.generated_follow_up_dispatch_performed);
        assert!(!repo.join(".maco/o2").exists());
    }

    #[test]
    fn autopilot_plan_input_is_bounded_nofollow_and_json_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");

        let malformed = temp.path().join("malformed.json");
        fs::write(&malformed, "{\"version\": 1,").expect("malformed plan");
        let error = autopilot_plan_from_task_file(&repo, &malformed)
            .expect_err("JSON-looking malformed plan must not become plain text");
        assert!(format!("{error:#}").contains("JSON-looking"));

        let oversized = temp.path().join("oversized.plan");
        File::create(&oversized)
            .expect("oversized file")
            .set_len(AUTOPILOT_PLAN_MAX_BYTES + 1)
            .expect("set oversized length");
        let error = autopilot_plan_from_task_file(&repo, &oversized)
            .expect_err("oversized plan must fail before parsing");
        assert!(format!("{error:#}").contains("bounded read limit"));
        assert!(!repo.join(".maco/autopilot").exists());
    }

    #[test]
    fn public_autopilot_plan_refuses_unsupported_or_malformed_depth_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let plan_path = temp.path().join("plan.json");
        let plan = |shape: &str| {
            format!(
                r#"{{
                  "version": 1,
                  "task": {{"title": "Depth contract", "body": "Keep depth bounded."}},
                  "assigned_paths": ["README.md"]
                  {shape}
                }}"#
            )
        };

        fs::write(&plan_path, plan(", \"max_depth\": 2")).expect("supported plan");
        autopilot_plan_from_task_file(&repo, &plan_path).expect("depth two remains supported");

        fs::write(&plan_path, plan(", \"max_depth\": 3")).expect("depth three plan");
        let error = autopilot_plan_from_task_file(&repo, &plan_path)
            .expect_err("depth three must not be normalized away");
        assert!(format!("{error:#}").contains("supports exactly max_depth 2"));

        fs::write(
            &plan_path,
            plan(
                r#", "max_depth": 2,
                  "assignments": [{
                    "id": "depth-two",
                    "child_assignments": [{"id": "depth-three"}]
                  }]"#,
            ),
        )
        .expect("recursive plan");
        let error = autopilot_plan_from_task_file(&repo, &plan_path)
            .expect_err("recursive assignments must not be normalized away");
        assert!(format!("{error:#}").contains("no recursive child_assignments"));

        fs::write(&plan_path, plan(", \"max_depth\": \"2\"")).expect("malformed plan");
        let error = autopilot_plan_from_task_file(&repo, &plan_path)
            .expect_err("a non-integer max_depth must be invalid");
        assert!(format!("{error:#}").contains("max_depth must be an integer"));
    }

    #[test]
    fn unsupported_depth_shapes_are_typed_preflight_permission_expansions() {
        use crate::gate_denial::{
            GateDenialReason, GateDenialRoute, GateRetryability, NextSafeOperation,
        };

        let cases = [
            ("depth-three-refusal", r#""max_depth": 3"#),
            (
                "recursive-depth-refusal",
                r#""max_depth": 2,
                    "assignments": [{
                      "id": "depth-two",
                      "child_assignments": [{"id": "depth-three"}]
                    }]"#,
            ),
        ];
        for (run_id, shape) in cases {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = create_committed_autopilot_repo(temp.path());
            let plan_path = temp.path().join("plan.json");
            fs::write(
                &plan_path,
                format!(
                    r#"{{
                      "version": 1,
                      "task": {{"title": "Depth refusal", "body": "Do not expand depth."}},
                      "assigned_paths": ["README.md"],
                      {shape}
                    }}"#
                ),
            )
            .expect("write unsupported plan");

            let report = run_autopilot_plan_file_with_retention(
                AutopilotRunOptions {
                    repo: repo.clone(),
                    plan_file: plan_path,
                    run_id: RunId::new(run_id).expect("run id"),
                    codex_bin: None,
                    reviewer_command: None,
                    allow_dirty_primary: false,
                },
                Some(MachineGlobalRetentionBinding {
                    config: temp.path().join("must-not-open.json"),
                    root_id: "runtime".to_string(),
                    owner: "maco-autopilot".to_string(),
                    correction_correlation_id: run_id.to_string(),
                }),
            )
            .expect("finalize typed depth refusal");

            assert_eq!(report.status, AutopilotRunStatus::Refused);
            assert!(!report.success);
            assert_eq!(report.attempt_count, 0);
            assert!(report.supervisor.is_none());
            assert!(matches!(
                report.gate_denials.as_slice(),
                [GateDenial {
                    reason: GateDenialReason::ApprovalReview {
                        denial: ApprovalReviewDenial::PermissionExpansion
                    },
                    retryability: GateRetryability::RetryAfterCorrection,
                    route: GateDenialRoute::ChildController,
                    next_safe_operation: NextSafeOperation::NarrowActionOrChooseAnotherTool,
                    ..
                }]
            ));
            assert!(!repo.join(".maco/o2").exists());
        }
    }

    #[test]
    fn autopilot_plan_bounds_attempts_and_defaults_validation_timeout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        fs::write(repo.join("README.md"), "# Test\n").expect("readme");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "version": 1,
              "task": {"title": "Test", "body": "Test"},
              "assigned_paths": ["README.md"],
              "validation_commands": ["true"],
              "max_repair_attempts": 2
            }"#,
        )
        .expect("plan");
        let plan = autopilot_plan_from_task_file(&repo, &plan_path).expect("bounded plan");
        assert_eq!(
            plan.validation_commands[0].timeout_seconds,
            Some(DEFAULT_CHILD_TIMEOUT_SECONDS)
        );

        fs::write(
            &plan_path,
            r#"{
              "version": 1,
              "task": {"title": "Test", "body": "Test"},
              "assigned_paths": ["README.md"],
              "max_repair_attempts": 3
            }"#,
        )
        .expect("excessive plan");
        let error = autopilot_plan_from_task_file(&repo, &plan_path)
            .expect_err("excessive repair attempts must fail");
        assert!(format!("{error:#}").contains("max_repair_attempts"));
        assert!(!repo.join(".maco/autopilot").exists());
    }

    #[cfg(unix)]
    #[test]
    fn autopilot_plan_input_refuses_symlink_leaf_and_ancestor() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        let input = temp.path().join("input");
        fs::create_dir_all(&input).expect("input directory");
        fs::write(input.join("task.md"), "Update README\n").expect("task");
        symlink(input.join("task.md"), temp.path().join("task-link.md")).expect("leaf link");
        symlink(&input, temp.path().join("input-link")).expect("ancestor link");

        for path in [
            temp.path().join("task-link.md"),
            temp.path().join("input-link/task.md"),
        ] {
            assert!(autopilot_plan_from_task_file(&repo, path).is_err());
        }
    }

    #[test]
    fn bounded_repository_status_detects_present_deleted_and_untracked_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo, _manager) = create_managed_worktree_fixture(temp.path(), "status-agent");
        assert!(bounded_repository_dirty_paths(&repo)
            .expect("clean status")
            .is_empty());

        fs::create_dir_all(repo.join(".maco/runtime")).expect("runtime dir");
        fs::write(repo.join(".maco/runtime/ignored"), "ignored\n").expect("runtime file");
        fs::write(repo.join("untracked.txt"), "untracked\n").expect("untracked");
        let dirty = bounded_repository_dirty_paths(&repo).expect("untracked status");
        assert_eq!(dirty, vec![PathBuf::from("untracked.txt")]);

        fs::remove_file(repo.join("untracked.txt")).expect("remove untracked");
        fs::hard_link(repo.join("README.md"), repo.join("linked-readme"))
            .expect("tracked-file hard link");
        let dirty = bounded_repository_dirty_paths(&repo).expect("hard-linked status");
        assert_eq!(dirty, vec![PathBuf::from("linked-readme")]);
        fs::remove_file(repo.join("linked-readme")).expect("remove hard link");

        fs::remove_file(repo.join("README.md")).expect("remove tracked");
        let dirty = bounded_repository_dirty_paths(&repo).expect("deleted status");
        assert_eq!(dirty, vec![PathBuf::from("README.md")]);
    }

    #[cfg(unix)]
    #[test]
    fn active_artifact_status_uses_nofollow_inventory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        let run_id = RunId::new("active-inventory").expect("run id");
        let run_dir = repo.join(".maco/autopilot/runs/active-inventory");
        fs::create_dir_all(&run_dir).expect("run dir");
        fs::write(run_dir.join("plan.json"), "{}\n").expect("plan");

        let status = autopilot_status(&repo, run_id.clone()).expect("active status");
        assert!(status.artifacts.plan);
        assert!(!status.artifacts.final_report);

        fs::remove_file(run_dir.join("plan.json")).expect("remove plan");
        let outside = temp.path().join("outside-plan");
        fs::write(&outside, "{}\n").expect("outside plan");
        symlink(&outside, run_dir.join("plan.json")).expect("plan link");
        assert!(autopilot_status(&repo, run_id).is_err());
    }

    fn create_managed_worktree_fixture(root: &Path, agent_id: &str) -> (PathBuf, WorktreeManager) {
        let repo_path = root.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        let repo = Repository::open(&repo_path).expect("open repository");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        repo.config()
            .expect("repo config")
            .set_str("user.name", "maco test")
            .expect("set user name");
        repo.config()
            .expect("repo config")
            .set_str("user.email", "maco-test@example.invalid")
            .expect("set user email");
        drop(tree);
        drop(repo);
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: agent_id.to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create managed worktree");
        (repo_path, manager)
    }

    #[cfg(target_os = "linux")]
    fn create_prepublication_fixture(
        root: &Path,
        agent_id: &str,
    ) -> (PathBuf, WorktreeManager, PathBuf) {
        let (repo, manager) = create_managed_worktree_fixture(root, agent_id);
        let record = manager
            .get_managed_verified(agent_id)
            .expect("verified managed worktree");
        fs::write(
            record.path.join("README.md"),
            format!("# Prepared candidate for {agent_id}\n"),
        )
        .expect("edit candidate README");
        (repo, manager, record.path)
    }

    #[cfg(target_os = "linux")]
    struct DeterministicPreparedCandidate {
        metadata: crate::merge::WorktreeMergeMetadata,
        binding: CandidateValidationBinding,
        raw_diff: Vec<u8>,
        snapshot_tree: git2::Oid,
    }

    #[cfg(target_os = "linux")]
    fn create_deterministic_prepublication_fixture(
        root: &Path,
        agent_id: &str,
    ) -> (PathBuf, WorktreeManager, DeterministicPreparedCandidate) {
        let (repo, manager) = create_managed_worktree_fixture(root, agent_id);
        let record = manager
            .get_managed_verified(agent_id)
            .expect("verified managed worktree");
        fs::write(
            record.path.join("README.md"),
            format!("# Prepared candidate for {agent_id}\n"),
        )
        .expect("edit candidate README");

        let candidate_repo = Repository::open(&record.path).expect("open candidate repository");
        let parent = candidate_repo
            .head()
            .expect("candidate HEAD")
            .peel_to_commit()
            .expect("candidate parent commit");
        let primary_head = parent.id();
        let mut index = candidate_repo.index().expect("open candidate index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage candidate README");
        index.write().expect("write candidate index");
        let snapshot_tree = index.write_tree().expect("write candidate tree");
        let tree = candidate_repo
            .find_tree(snapshot_tree)
            .expect("find candidate tree");
        let signature = git2::Signature::now("maco test", "maco-test@example.invalid")
            .expect("candidate signature");
        let agent_head = candidate_repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "prepared candidate",
                &tree,
                &[&parent],
            )
            .expect("commit prepared candidate");
        drop(tree);
        drop(parent);
        drop(candidate_repo);

        let metadata = crate::merge::WorktreeMergeMetadata {
            agent_id: agent_id.to_string(),
            worktree_path: record.path,
            branch: record.branch,
            primary_repo_root: repo.clone(),
            primary_head: Some(primary_head.to_string()),
            agent_head: Some(agent_head.to_string()),
            merge_base: Some(primary_head.to_string()),
            base_matches_primary: Some(true),
        };
        let raw_diff =
            format!("diff --git a/README.md b/README.md\n+Prepared candidate for {agent_id}\n")
                .into_bytes();
        let binding = crate::merge::candidate_validation_binding(&metadata, &raw_diff)
            .expect("deterministic candidate binding");
        (
            repo,
            manager,
            DeterministicPreparedCandidate {
                metadata,
                binding,
                raw_diff,
                snapshot_tree,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn passed_merge_safety_check() -> crate::merge::SafetyCheck {
        crate::merge::SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn deterministic_prepared_report(
        candidate: &DeterministicPreparedCandidate,
        forge: ForgeKind,
    ) -> PrPublicationReport {
        let changed_paths = vec![PathBuf::from("README.md")];
        let diff_summary = crate::merge::OutputSummary {
            text: String::from_utf8_lossy(&candidate.raw_diff).into_owned(),
            truncated: false,
        };
        let preview = crate::merge::MergeApplyPreview {
            candidate: crate::merge::MergeCandidate {
                metadata: candidate.metadata.clone(),
                claimed_paths: changed_paths.clone(),
                changed_paths: changed_paths.clone(),
                changes: vec![crate::merge::ChangedPath {
                    path: PathBuf::from("README.md"),
                    kind: crate::merge::ChangeKind::Modified,
                }],
                unclaimed_changed_paths: Vec::new(),
                diff: crate::merge::DiffOutput {
                    summary: diff_summary.clone(),
                    full: Some(diff_summary.text.clone()),
                },
                validations: Vec::new(),
                validation_binding: candidate.binding.clone(),
                validation_evidence: ValidationEvidenceBundle::default(),
                raw_diff: candidate.raw_diff.clone(),
                snapshot_tree: candidate.snapshot_tree,
            },
            safety: crate::merge::MergeApplySafety {
                primary_state_unchanged: passed_merge_safety_check(),
                dirty_primary: passed_merge_safety_check(),
                stale_base: passed_merge_safety_check(),
                apply_check: passed_merge_safety_check(),
                unclaimed_edits: passed_merge_safety_check(),
                validation: passed_merge_safety_check(),
                validation_evidence: crate::merge::ValidationEvidenceCheck {
                    status: SafetyCheckStatus::Passed,
                    binding_status: crate::merge::ValidationBindingStatus::NotRequired,
                    message: None,
                    paths: Vec::new(),
                },
                megafile: passed_merge_safety_check(),
                megafile_warnings: Vec::new(),
                megafile_decomposition_target: None,
                megafile_decomposition_evidence: None,
                megafile_blocking: false,
                validation_required: false,
                candidate_validation_commands: Vec::new(),
                force_options: crate::merge::MergeForceOptions::default(),
                apply_mode: crate::merge::ApplyMode::Direct,
                semantic_conflicts:
                    crate::merge_semantic::SemanticConflictClassification::no_conflict(),
                readiness: crate::merge::ApplyReadiness {
                    status: ApplyReadinessStatus::Safe,
                    blockers: Vec::new(),
                    forced: Vec::new(),
                    details: Vec::new(),
                },
            },
        };
        let agent_head = candidate
            .binding
            .agent_head
            .clone()
            .expect("deterministic candidate HEAD");
        PrPublicationReport {
            status: PrPublicationStatus::Preview,
            agent_id: candidate.metadata.agent_id.clone(),
            branch: candidate.metadata.branch.clone(),
            base: "main".to_string(),
            base_head: candidate.binding.primary_head.clone(),
            remote: None,
            forge,
            draft: true,
            title: "Prepared candidate".to_string(),
            body_summary: crate::merge::OutputSummary {
                text: "Prepared candidate".to_string(),
                truncated: false,
            },
            changed_paths,
            validation_status: SafetyCheckStatus::Passed,
            validation_required: false,
            readiness: ApplyReadinessStatus::Safe,
            blockers: Vec::new(),
            commit_id: Some(agent_head.clone()),
            head_id: Some(agent_head),
            pr_url: None,
            pushed: false,
            created: false,
            publication_receipt: None,
            next_action: "validate the deterministic candidate".to_string(),
            preview,
        }
    }

    #[cfg(target_os = "linux")]
    fn deterministic_fake_publication_report(
        candidate: &DeterministicPreparedCandidate,
    ) -> PrPublicationReport {
        let mut report = deterministic_prepared_report(candidate, ForgeKind::Fake);
        report.status = PrPublicationStatus::Published;
        report.created = true;
        report.pr_url = Some(format!(
            "https://example.invalid/fake/{}",
            candidate.metadata.agent_id
        ));
        report.next_action = "review the deterministic fake publication".to_string();
        report
    }

    #[cfg(target_os = "linux")]
    fn deterministic_candidate_is_clean(_: &Path) -> Result<bool> {
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    fn prepublication_test_plan(
        forge_mode: AutopilotForgeMode,
        reviewer_mode: ReviewerMode,
    ) -> AutopilotPlan {
        AutopilotPlan {
            version: AUTOPILOT_SCHEMA_VERSION,
            task: AutopilotTask {
                title: "Strict pre-publication test".to_string(),
                body: "Exercise the exact prepared candidate gate.".to_string(),
            },
            assigned_paths: vec![PathBuf::from("README.md")],
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            validation_commands: Vec::new(),
            max_repair_attempts: 1,
            forge_mode,
            reviewer: ReviewerConfig {
                mode: reviewer_mode,
                blocking_attempts: 0,
                finding: None,
                program: (reviewer_mode == ReviewerMode::ExternalCommand)
                    .then(|| PathBuf::from("/bin/true")),
                args: Vec::new(),
                command: None,
                timeout_seconds: None,
            },
            publish_mode: AutopilotPublishMode::DraftOnly,
            auto_merge: false,
            external_source: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn passed_prepublication_validation() -> Vec<ValidationReport> {
        vec![ValidationReport {
            name: "prepared-unit".to_string(),
            status: ValidationStatus::Passed,
            message: None,
            paths: vec![PathBuf::from("README.md")],
        }]
    }

    #[cfg(target_os = "linux")]
    fn injected_external_review(
        options: ReviewPrOptions,
        status: ReviewReportStatus,
    ) -> ReviewReport {
        let blocked = status == ReviewReportStatus::Blocked;
        let findings = if blocked {
            vec![review::ReviewFinding {
                severity: "error".to_string(),
                path: Some(PathBuf::from("README.md")),
                summary: "injected blocking finding".to_string(),
                suggested_fix: "repair before publication".to_string(),
                blocking: true,
            }]
        } else {
            Vec::new()
        };
        ReviewReport {
            version: REVIEW_REPORT_SCHEMA_VERSION,
            status,
            success: status == ReviewReportStatus::Passed,
            target: options.target,
            reviewer: review::ReviewerIdentity {
                mode: ReviewerMode::ExternalCommand,
                reviewer_id: format!("{EXTERNAL_REVIEWER_ID_PREFIX}{}", "b".repeat(32)),
                model: EXTERNAL_REVIEWER_MODEL.to_string(),
            },
            attempt: options.attempt,
            request_binding: "a".repeat(REVIEW_REQUEST_BINDING_HEX_LEN),
            blocking_finding_count: findings.len(),
            findings,
            changed_paths: options.changed_paths,
            diff_source: "sanitized_merge_candidate_summary".to_string(),
            ci_reaction_supported: false,
            ci_reaction: "unsupported".to_string(),
            diagnostics: None,
            next_action: "continue only after the strict gate".to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    fn injected_external_publication_review(
        options: ReviewPrOptions,
        status: ReviewReportStatus,
    ) -> review::PublicationReviewResult {
        let report = injected_external_review(options.clone(), status);
        review::PublicationReviewResult::issue_for_test(options, report, true)
    }

    #[cfg(target_os = "linux")]
    fn publication_transactions_path(repo: &Path) -> PathBuf {
        repo.join(".git/maco/state/publication-transactions")
    }

    #[cfg(target_os = "linux")]
    fn assert_no_remote_publication_state(repo: &Path) {
        assert!(!publication_transactions_path(repo).exists());
        let repository = Repository::open(repo).expect("open primary repository");
        let mut references = repository
            .references_glob("refs/remotes/*")
            .expect("list remote refs");
        assert!(references.next().is_none(), "unexpected remote reference");
    }

    #[test]
    fn validate_autopilot_plan_refuses_empty_path_proposal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::write(repo.join("src/lib.rs"), "pub fn unrelated() {}\n").expect("write src");

        let result = validate_autopilot_plan(
            repo,
            AutopilotPlan {
                version: AUTOPILOT_SCHEMA_VERSION,
                task: AutopilotTask {
                    title: "Unmatched task".to_string(),
                    body: "No concrete path or symbol appears here.".to_string(),
                },
                assigned_paths: Vec::new(),
                path_proposal: planning::TaskPathProposalDiagnostics::default(),
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                validation_commands: Vec::new(),
                max_repair_attempts: default_max_repair_attempts(),
                forge_mode: AutopilotForgeMode::Fake,
                reviewer: ReviewerConfig::default(),
                publish_mode: AutopilotPublishMode::DraftOnly,
                auto_merge: false,
                external_source: None,
            },
        );

        let error = result.expect_err("empty proposal must be refused");
        assert!(error.to_string().contains("assigned paths are empty"));
    }

    #[test]
    fn real_forges_require_external_reviewer_authority() {
        let direct = ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(PathBuf::from("reviewer")),
            ..ReviewerConfig::default()
        };
        assert!(reviewer_config_may_authorize_publication(
            ForgeKind::Git,
            &direct
        ));
        assert!(reviewer_config_may_authorize_publication(
            ForgeKind::Github,
            &direct
        ));

        let legacy = ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            command: Some("reviewer --legacy-shell".to_string()),
            ..ReviewerConfig::default()
        };
        assert!(!reviewer_config_may_authorize_publication(
            ForgeKind::Git,
            &legacy
        ));
        assert!(!reviewer_config_may_authorize_publication(
            ForgeKind::Github,
            &ReviewerConfig::default()
        ));
        assert!(reviewer_config_may_authorize_publication(
            ForgeKind::Fake,
            &ReviewerConfig::default()
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retry_prompt_excludes_external_review_text_diagnostics_and_paths() {
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let options = ReviewPrOptions {
            repo: PathBuf::from("/private/review-worktree"),
            target: "prepared-candidate:agent@1111111111111111111111111111111111111111".to_string(),
            reviewer: plan.reviewer.clone(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("private/external-path.rs")],
            diff_summary: Some("external diff summary sentinel".to_string()),
        };
        let mut report = injected_external_review(options, ReviewReportStatus::Blocked);
        report.findings[0].summary = "external summary sentinel".to_string();
        report.findings[0].suggested_fix = "external suggested fix sentinel".to_string();
        report.findings[0].path = Some(PathBuf::from("private/external-path.rs"));
        report.next_action = "external next action sentinel".to_string();
        report.diagnostics = Some(review::ReviewCommandDiagnostics {
            timed_out: false,
            timeout_seconds: Some(1),
            exit_code: Some(1),
            stdout: review::ReviewOutputSummary {
                text: "external stdout diagnostic sentinel".to_string(),
                truncated: false,
            },
            stderr: review::ReviewOutputSummary {
                text: "external stderr diagnostic sentinel".to_string(),
                truncated: false,
            },
            process_error: Some("external process diagnostic sentinel".to_string()),
        });
        let outcome = stopped_prepublication(
            "review_blocked",
            review_repair_reason(&report),
            true,
            AutopilotValidationSummary {
                status: AutopilotValidationStatus::Passed,
                reports: passed_prepublication_validation(),
            },
            Some(report),
            None,
            None,
            None,
        );

        let prompt = supervisor_task(&plan, 2, &[RepairPromptContext::from_outcome(&outcome)]);

        assert!(prompt.contains("reason_code=review_blocked"));
        assert!(prompt.contains("blocking_findings=1"));
        assert!(prompt.contains("severity_counts=critical:0,error:1,warning:0,info:0"));
        for untrusted in [
            "external summary sentinel",
            "external suggested fix sentinel",
            "external next action sentinel",
            "external stdout diagnostic sentinel",
            "external stderr diagnostic sentinel",
            "external process diagnostic sentinel",
            "private/external-path.rs",
            "external diff summary sentinel",
        ] {
            assert!(!prompt.contains(untrusted), "prompt leaked {untrusted}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_authority_requires_opaque_exact_review_receipt() {
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let options = ReviewPrOptions {
            repo: PathBuf::from("/bound/review-worktree"),
            target: "prepared-candidate:agent@1111111111111111111111111111111111111111".to_string(),
            reviewer: plan.reviewer,
            attempt: 1,
            changed_paths: vec![PathBuf::from("README.md")],
            diff_summary: Some("bound summary".to_string()),
        };
        let report = injected_external_review(options.clone(), ReviewReportStatus::Passed);
        let syntactic_only =
            review::PublicationReviewResult::issue_for_test(options.clone(), report.clone(), false);
        assert!(!syntactic_only.has_exact_external_authority(&options));

        let exact = review::PublicationReviewResult::issue_for_test(options.clone(), report, true);
        assert!(exact.has_exact_external_authority(&options));
        let mut different_args = options;
        different_args.reviewer.args.push("changed".to_string());
        assert!(!exact.has_exact_external_authority(&different_args));
    }

    #[test]
    fn publish_requested_records_failed_real_attempts_but_not_fake_simulation() {
        assert!(publish_requested_for_audit(
            true,
            AutopilotForgeMode::Github,
            true
        ));
        assert!(!publish_requested_for_audit(
            true,
            AutopilotForgeMode::Github,
            false
        ));
        assert!(!publish_requested_for_audit(
            true,
            AutopilotForgeMode::Fake,
            true
        ));
        assert!(!publish_requested_for_audit(
            false,
            AutopilotForgeMode::Git,
            true
        ));
    }

    #[test]
    fn autopilot_message_sanitization_redacts_paths_secrets_and_bounds_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("private-repo");
        Repository::init(&repo).expect("init repository");
        let secret = "autopilot-private-secret";
        let message = format!(
            "repo={}\nAPI_TOKEN={secret}\n{}\0",
            repo.display(),
            "x".repeat(AUTOPILOT_MESSAGE_LIMIT_CHARS * 2)
        );

        let sanitized = sanitize_text(&repo, &message);

        assert!(!sanitized.contains(&repo.display().to_string()));
        assert!(!sanitized.contains(secret));
        assert!(!sanitized.contains('\0'));
        assert!(sanitized.contains("<redacted:"));
        assert!(sanitized.ends_with("…<truncated>"));
        assert!(
            sanitized.chars().count()
                <= AUTOPILOT_MESSAGE_LIMIT_CHARS + "…<truncated>".chars().count()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_prepublication_orders_prepare_validate_review_publish_under_one_lease() {
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "order-agent";
        let (repo, manager, candidate) =
            create_deterministic_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan =
            prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::ExternalCommand);
        let trace = RefCell::new(Vec::new());
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options: PrPublicationOptions| {
                trace.borrow_mut().push("prepare");
                Ok(deterministic_prepared_report(&candidate, options.forge))
            },
            validate: |_| {
                trace.borrow_mut().push("validate");
                Ok(passed_prepublication_validation())
            },
            review: |options| {
                trace.borrow_mut().push("review");
                Ok(injected_external_publication_review(
                    options,
                    ReviewReportStatus::Passed,
                ))
            },
            publish: |_, _| {
                trace.borrow_mut().push("publish");
                publish_calls.set(publish_calls.get() + 1);
                Ok(deterministic_fake_publication_report(&candidate))
            },
            candidate_clean: deterministic_candidate_is_clean,
        };

        let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

        assert_eq!(
            trace.into_inner(),
            vec!["prepare", "validate", "prepare", "review", "prepare", "publish", "prepare"]
        );
        assert_eq!(publish_calls.get(), 1);
        assert_eq!(outcome.disposition, PrepublicationDisposition::Published);
        assert!(outcome.publication_attempted);
        assert!(outcome.publication_effect_observed);
        assert!(outcome
            .reviewed_candidate
            .as_ref()
            .is_some_and(|reviewed| reviewed.authoritative));
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_publication_rejects_fake_blocking_and_failed_review_before_publish() {
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "review-gate-agent";
        let (repo, manager, candidate) =
            create_deterministic_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let review_calls = Cell::new(0usize);
        let publish_calls = Cell::new(0usize);
        let prepare_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options: PrPublicationOptions| {
                prepare_calls.set(prepare_calls.get() + 1);
                Ok(deterministic_prepared_report(&candidate, options.forge))
            },
            validate: |_| Ok(passed_prepublication_validation()),
            review: |options: ReviewPrOptions| {
                review_calls.set(review_calls.get() + 1);
                let status = match options.reviewer.args.first().map(String::as_str) {
                    Some("blocked") => ReviewReportStatus::Blocked,
                    Some("failed") => ReviewReportStatus::Failed,
                    _ => ReviewReportStatus::Passed,
                };
                Ok(injected_external_publication_review(options, status))
            },
            publish: |_, _| {
                publish_calls.set(publish_calls.get() + 1);
                bail!("publish must not be called for rejected review")
            },
            candidate_clean: deterministic_candidate_is_clean,
        };

        let fake_plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::Fake);
        let fake = run_prepublication_attempt(&repo, agent_id, 1, &fake_plan, &lease, &mut hooks);
        assert_eq!(fake.reason, "reviewer_not_authoritative");
        assert!(!fake.publication_attempted);
        assert_eq!(review_calls.get(), 0);

        let mut blocked_plan =
            prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        blocked_plan.reviewer.args = vec!["blocked".to_string()];
        let blocked =
            run_prepublication_attempt(&repo, agent_id, 1, &blocked_plan, &lease, &mut hooks);
        assert_eq!(blocked.reason, "review_blocked");
        assert!(!blocked.publication_attempted);

        let mut failed_plan = blocked_plan;
        failed_plan.reviewer.args = vec!["failed".to_string()];
        let failed =
            run_prepublication_attempt(&repo, agent_id, 1, &failed_plan, &lease, &mut hooks);
        assert_eq!(failed.reason, "review_failed");
        assert!(!failed.publication_attempted);
        assert_eq!(review_calls.get(), 2);
        assert_eq!(publish_calls.get(), 0);
        assert_eq!(prepare_calls.get(), 6);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_validation_refuses_real_publication_before_review_or_publish() {
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "empty-validation-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let review_calls = Cell::new(0usize);
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(Vec::new()),
            review: |options| {
                review_calls.set(review_calls.get() + 1);
                Ok(injected_external_publication_review(
                    options,
                    ReviewReportStatus::Passed,
                ))
            },
            publish: |_, _| {
                publish_calls.set(publish_calls.get() + 1);
                bail!("empty validation must stop before publication")
            },
            candidate_clean: repository_worktree_is_clean,
        };

        let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

        assert_eq!(outcome.reason, "validation_evidence_invalid");
        assert!(!outcome.publication_attempted);
        assert_eq!(review_calls.get(), 0);
        assert_eq!(publish_calls.get(), 0);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_mutation_changes_binding_and_prevents_publication() {
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "review-mutation-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(passed_prepublication_validation()),
            review: |options: ReviewPrOptions| {
                fs::write(
                    options.repo.join("README.md"),
                    "# Mutated during independent review\n",
                )
                .expect("inject review mutation");
                Ok(injected_external_publication_review(
                    options,
                    ReviewReportStatus::Passed,
                ))
            },
            publish: |_, _| {
                publish_calls.set(publish_calls.get() + 1);
                bail!("mutated review candidate must not publish")
            },
            candidate_clean: repository_worktree_is_clean,
        };

        let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

        assert_eq!(outcome.reason, "candidate_binding_mismatch");
        assert!(!outcome.publication_attempted);
        assert_eq!(publish_calls.get(), 0);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fake_forge_with_fake_reviewer_is_local_and_non_authoritative() {
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "fake-local-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::Fake);
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(passed_prepublication_validation()),
            review: review::review_pr_for_publication,
            publish: |options, evidence| {
                publish_calls.set(publish_calls.get() + 1);
                publication::publish_prepared_pr_with_write_lease(options, &evidence, &lease)
            },
            candidate_clean: repository_worktree_is_clean,
        };

        let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

        assert_eq!(outcome.disposition, PrepublicationDisposition::Published);
        assert_eq!(publish_calls.get(), 1);
        assert!(outcome
            .reviewed_candidate
            .as_ref()
            .is_some_and(|reviewed| !reviewed.authoritative));
        assert_eq!(
            outcome.publication.as_ref().map(|report| report.forge),
            Some(ForgeKind::Fake)
        );
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepublication_retry_reuses_prepared_commit_without_duplicate_effect() {
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "retry-agent";
        let (repo, manager, candidate) =
            create_deterministic_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let mut plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::Fake);
        plan.reviewer.blocking_attempts = 1;
        let publish_calls = Cell::new(0usize);
        let prepare_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options: PrPublicationOptions| {
                prepare_calls.set(prepare_calls.get() + 1);
                Ok(deterministic_prepared_report(&candidate, options.forge))
            },
            validate: |_| Ok(passed_prepublication_validation()),
            review: review::review_pr_for_publication,
            publish: |_, _| {
                publish_calls.set(publish_calls.get() + 1);
                Ok(deterministic_fake_publication_report(&candidate))
            },
            candidate_clean: deterministic_candidate_is_clean,
        };

        let first = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);
        assert_eq!(first.reason, "review_blocked");
        assert!(!first.publication_attempted);
        assert_eq!(publish_calls.get(), 0);

        let second = run_prepublication_attempt(&repo, agent_id, 2, &plan, &lease, &mut hooks);
        assert_eq!(second.disposition, PrepublicationDisposition::Published);
        assert_eq!(publish_calls.get(), 1);
        assert_eq!(prepare_calls.get(), 6);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_hook_report_forge_and_base_mismatch_are_nonretryable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "hook-mismatch-agent";
        let (repo, manager, candidate) =
            create_deterministic_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let publish_calls = Cell::new(0usize);
        let prepare_calls = Cell::new(0usize);
        let return_base_mismatch = Cell::new(false);
        let mut hooks = PrepublicationHooks {
            prepare: |options: PrPublicationOptions| {
                prepare_calls.set(prepare_calls.get() + 1);
                Ok(deterministic_prepared_report(&candidate, options.forge))
            },
            validate: |_| Ok(passed_prepublication_validation()),
            review: |options| {
                Ok(injected_external_publication_review(
                    options,
                    ReviewReportStatus::Passed,
                ))
            },
            publish: |_: PrPublicationOptions, _: BoundValidationEvidenceBundle| {
                publish_calls.set(publish_calls.get() + 1);
                let mut report = deterministic_fake_publication_report(&candidate);
                if return_base_mismatch.get() {
                    let expected_head = candidate
                        .binding
                        .agent_head
                        .clone()
                        .context("bound evidence HEAD")?;
                    report.forge = ForgeKind::Git;
                    report.pushed = true;
                    report.created = false;
                    report.pr_url = None;
                    report.publication_receipt = Some(publication::PrPublicationReceipt {
                        version: 1,
                        transaction_id: "injected-receipt".to_string(),
                        sequence: 1,
                        phase: publication::PublicationTransactionPhase::Completed,
                        expected_oid: expected_head.clone(),
                        expected_base_oid: Some(
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                        ),
                        remote_ref: "refs/heads/injected".to_string(),
                        github_repository: None,
                        push_observed_oid: Some(expected_head),
                        pr_url: None,
                        pr_head_oid: None,
                        pr_base: None,
                        pr_state: None,
                        pr_is_draft: None,
                        create_attempted: false,
                        created_by_transaction: false,
                        observed_existing_pr: false,
                        last_error: None,
                    });
                }
                Ok(report)
            },
            candidate_clean: deterministic_candidate_is_clean,
        };

        let wrong_forge = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);
        assert_eq!(wrong_forge.reason, "publication_receipt_invalid");
        assert!(wrong_forge.publication_attempted);
        assert!(!wrong_forge.retryable);

        return_base_mismatch.set(true);
        let wrong_base = run_prepublication_attempt(&repo, agent_id, 2, &plan, &lease, &mut hooks);
        assert_eq!(wrong_base.reason, "publication_receipt_invalid");
        assert!(wrong_base.publication_attempted);
        assert!(wrong_base.publication_effect_observed);
        assert!(!wrong_base.retryable);
        assert_eq!(publish_calls.get(), 2);
        assert_eq!(prepare_calls.get(), 6);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn write_lease_excludes_competing_access_through_review_and_releases_on_error() {
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "review-lease-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let plan =
            prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::ExternalCommand);
        let publish_calls = Cell::new(0usize);
        let outcome = {
            let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
                .expect("autopilot write lease");
            let mut hooks = PrepublicationHooks {
                prepare: |options| {
                    publication::prepare_pr_candidate_with_write_lease(options, &lease)
                },
                validate: |_| Ok(passed_prepublication_validation()),
                review: |_: ReviewPrOptions| {
                    manager
                        .acquire_read_execution_lease(agent_id)
                        .expect_err("review retains writer against readers");
                    manager
                        .acquire_write_execution_lease(agent_id)
                        .expect_err("review retains writer against writers");
                    manager
                        .remove(agent_id, true, false)
                        .expect_err("review retains writer against removal");
                    bail!("injected independent review failure")
                },
                publish: |_, _| {
                    publish_calls.set(publish_calls.get() + 1);
                    bail!("review error must stop before publication")
                },
                candidate_clean: repository_worktree_is_clean,
            };
            run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks)
        };

        assert_eq!(outcome.reason, "review_execution_failed");
        assert!(!outcome.publication_attempted);
        assert_eq!(publish_calls.get(), 0);
        manager
            .remove(agent_id, true, false)
            .expect("error scope releases the retained write lease");
    }

    #[test]
    fn injected_autopilot_lease_barrier_blocks_removal_until_quiescence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_repo, manager) = create_managed_worktree_fixture(temp.path(), "barrier-agent");
        let lease = acquire_autopilot_worktree_write_lease(&manager, "barrier-agent")
            .expect("acquire autopilot write lease");
        let removal_error = manager
            .remove("barrier-agent", true, false)
            .expect_err("active autopilot write lease must exclude removal");
        assert!(removal_error
            .to_string()
            .contains("active cooperative execution lease"));
        let second_writer = acquire_autopilot_worktree_write_lease(&manager, "barrier-agent")
            .expect_err("active autopilot writer must exclude another writer");
        let second_writer = format!("{second_writer:#}");
        assert!(second_writer.contains("exclusive") && second_writer.contains("lease"));

        drop(lease);
        manager
            .remove("barrier-agent", true, false)
            .expect("removal succeeds after final quiescence");
    }

    #[test]
    fn injected_autopilot_error_path_releases_write_lease() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_repo, manager) = create_managed_worktree_fixture(temp.path(), "error-agent");
        let injected_error = (|| -> Result<()> {
            let _lease = acquire_autopilot_worktree_write_lease(&manager, "error-agent")?;
            bail!("injected post-acquisition failure")
        })();
        assert!(injected_error
            .expect_err("injected failure must escape")
            .to_string()
            .contains("injected post-acquisition failure"));
        manager
            .remove("error-agent", true, false)
            .expect("error return drops autopilot write lease");
    }
}
