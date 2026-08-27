use crate::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily},
    gate_denial::{
        ApprovalReviewDenial, BudgetAdmissionDenial, GateCheckSource, GateDenial, GateDenialReason,
        VerifiedGateContext,
    },
    hierarchy_ledger::{
        observe_hierarchy, ObservedHierarchyNode, RoleCategory as AuthorityRoleCategory,
    },
    live_claim::{self, LiveClock},
    llm::{provider::ModelPricing, Redactor},
    machine_global::MachineGlobalRetentionBinding,
    merge::{
        ApplyBlocker, ApplyReadinessStatus, BoundValidationEvidenceBundle,
        CandidateValidationBinding, SafetyCheckStatus, ValidationEvidenceBundle, ValidationReport,
        ValidationStatus,
    },
    mutation_taxonomy::{
        autonomous_decision_for_supervisor_child_dispatch, is_reviewed_taxonomy_gate_id,
    },
    orchestrator::{RunId, SemanticCoordinationMode},
    planning,
    process_runner::{
        run_process_cancellable, CapturedBytes, EnvironmentMode, ProcessCancellation,
        ProcessOutput, ProcessRunError, ProcessSpec, Shell, SideEffectConfinementProfile,
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
        self, trusted_model_capability, validate_known_judgment_role_model, AgentRole,
        AssignmentPhase, AssignmentScheduleEntry, CommandRunRecord, FindingSeverity,
        ModelCapabilityClass, OrchestratorAssignment, ReviewLensUsageReport, ReviewStatus,
        RoleModelSelection, RoleUsageObservation, RoleUsageReport, RunBudgetLimits,
        SupervisorConcurrencyPolicy, SupervisorFinalReport, SupervisorPlan, SupervisorRunOptions,
        SupervisorRuntime, ValidationResult, WorkerAssignment,
    },
    sync::normalize_repo_relative_path,
    sync_store::SyncStore,
    worktree::{ManagedWorktreeWriteLease, WorktreeManager},
};
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
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

#[derive(Debug, Clone)]
pub struct AutopilotRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub run_id: RunId,
    pub codex_bin: Option<PathBuf>,
    pub reviewer_command: Option<String>,
    pub allow_dirty_primary: bool,
    /// Launch-only override for a live same-repository supervise/autopilot
    /// collision. Grants no authority to kill, interrupt, revert, or discard
    /// another run.
    pub allow_live_run_collision: bool,
    /// Maximum supervisor-plan child dispatches admitted across the source plan and generated
    /// follow-up plans. `None` preserves the unbounded behavior of existing callers.
    pub max_child_dispatches: Option<usize>,
    /// Strict per-supervisor-run ceilings supplied by the CLI. These tighten any plan JSON
    /// budget and are propagated to generated follow-up supervise runs.
    pub budget_overrides: RunBudgetLimits,
    pub budget_max_duration_seconds: Option<u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_plan: Option<AutopilotAuthorityPlan>,
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

/// Effective category and topology output bound before supervisor dispatch.
///
/// This record is derived from the normalized supervisor plan. It is not a
/// caller-authored grant and it never grants Git history mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotAuthorityPlan {
    pub selection_source: String,
    pub caller_selected_category: bool,
    pub caller_selected_coordination_depth: bool,
    pub planned_max_depth: u8,
    pub derived_coordination_depth: u32,
    pub forge_mode: AutopilotForgeMode,
    pub git_history_mutation_granted: bool,
    pub permitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub assignments: Vec<AutopilotAuthorityAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotAuthorityAssignment {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub role: AgentRole,
    pub category: AuthorityRoleCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_capability: Option<ModelCapabilityClass>,
    pub may_delegate: bool,
    pub may_write: bool,
    pub may_judge_acceptance: bool,
    pub may_mutate_git_history: bool,
    pub authority_source: String,
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

fn persist_autopilot_launch_preflight(
    writer: &mut ArtifactRunWriter,
    repo: &Path,
    options: &AutopilotRunOptions,
    collision: &crate::run_ops::LiveRunCollisionReport,
) -> Result<()> {
    let runtime = if options.codex_bin.is_some() {
        "codex"
    } else {
        "fake"
    };
    let spec = crate::run_ops::LaunchPreflightSpec {
        family: RunArtifactFamily::Autopilot,
        run_id: options.run_id.clone(),
        runtime: runtime.to_string(),
        runtime_bin: options.codex_bin.clone(),
        allow_dirty_primary: options.allow_dirty_primary,
        allow_live_run_collision: options.allow_live_run_collision,
    };
    crate::run_ops::persist_launch_preflight(writer, repo, &spec, collision)?;
    Ok(())
}

fn finalize_autopilot_run_artifacts(
    mut writer: ArtifactRunWriter,
    report: &AutopilotFinalReport,
    publish_requested: bool,
) -> Result<()> {
    crate::run_ops::append_run_heartbeat_best_effort(
        &mut writer,
        "finalizing",
        None,
        if report.success { "ok" } else { "failed" },
        None,
    );
    crate::run_ops::write_operator_summary(
        &mut writer,
        &render_autopilot_operator_summary(report),
    )?;
    write_private_json(&mut writer, "final-report.json", report)?;
    writer.finalize("final-report.json", publish_requested)?;
    Ok(())
}

fn render_autopilot_operator_summary(report: &AutopilotFinalReport) -> String {
    let status = match report.status {
        AutopilotRunStatus::Succeeded => "succeeded",
        AutopilotRunStatus::Failed => "failed",
        AutopilotRunStatus::Refused => "refused",
        AutopilotRunStatus::Cancelled => "cancelled",
    };
    let supervisor = report.supervisor.as_ref().map(|supervisor| {
        format!(
            "- Supervisor `{}`: success={} accepted={} rejected={}",
            supervisor.run_id.as_str(),
            supervisor.success,
            supervisor.accepted,
            supervisor.rejected
        )
    });
    let mut lines = vec![
        format!("# Autopilot run {}", report.run_id.as_str()),
        String::new(),
        format!("- Status: {status}"),
        format!("- Success: {}", report.success),
        format!("- Attempts: {}", report.attempt_count),
        String::new(),
    ];
    if let Some(supervisor) = supervisor {
        lines.push("## Supervisor".to_string());
        lines.push(String::new());
        lines.push(supervisor);
        lines.push(String::new());
    }
    lines.push("## Next action".to_string());
    lines.push(String::new());
    lines.push(report.next_action.clone());
    lines.push(String::new());
    lines.join("\n")
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
    pub last_heartbeat: Option<crate::run_ops::HeartbeatRecord>,
    #[serde(default)]
    pub heartbeat_count: usize,
    #[serde(default)]
    pub operator_summary_exists: bool,
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

fn autopilot_authority_plan(
    plan: &AutopilotPlan,
    effective_plan_value: &Value,
    effective_plan: &SupervisorPlan,
    input_shape: &AutopilotInputShape,
    planner_derived: bool,
) -> Result<AutopilotAuthorityPlan> {
    let schedule = effective_plan_value
        .get("assignment_schedule")
        .cloned()
        .map(serde_json::from_value::<Vec<AssignmentScheduleEntry>>)
        .transpose()
        .context("effective supervisor assignment_schedule is invalid")?
        .unwrap_or_default();
    let parents = schedule
        .into_iter()
        .map(|entry| (entry.assignment_id, entry.parent_assignment_id))
        .collect::<BTreeMap<_, _>>();
    let mut assignments = Vec::new();
    let mut refusal_reason = None;

    for assignment in &effective_plan.assignments {
        let requested_model = effective_plan
            .role_models
            .get(&assignment.role)
            .and_then(|selection| selection.model.clone());
        if refusal_reason.is_none() {
            refusal_reason = role_model_refusal_reason(assignment.role, requested_model.as_deref());
        }
        assignments.push(authority_assignment(
            assignment.id.clone(),
            parents.get(&assignment.id).cloned().flatten(),
            assignment.role,
            requested_model,
            false,
        )?);
        for worker in &assignment.worker_assignments {
            let requested_model = effective_plan
                .role_models
                .get(&worker.role)
                .and_then(|selection| selection.model.clone());
            assignments.push(authority_assignment(
                worker.id.clone(),
                Some(assignment.id.clone()),
                worker.role,
                requested_model,
                false,
            )?);
        }
        for lens in &effective_plan.review_lenses {
            let requested_model = Some(lens.backend.model().to_string());
            if refusal_reason.is_none()
                && trusted_model_capability(lens.backend.model()).is_some()
                && validate_known_judgment_role_model(
                    AgentRole::Auditor,
                    Some(lens.backend.model()),
                )
                .is_err()
            {
                refusal_reason = Some("model_ineligible_for_review_auditor".to_string());
            }
            assignments.push(authority_assignment(
                format!("{}:review:{}", assignment.id, lens.id),
                Some(assignment.id.clone()),
                AgentRole::Auditor,
                requested_model,
                true,
            )?);
        }
    }

    let observed = observe_hierarchy(assignments.iter().map(|assignment| ObservedHierarchyNode {
        id: assignment.id.as_str(),
        parent: assignment.parent_id.as_deref(),
        coordinator: assignment.category == AuthorityRoleCategory::DelegatingCoordinator,
    }));
    Ok(AutopilotAuthorityPlan {
        selection_source: if planner_derived {
            "effective_planner_output"
        } else {
            "effective_autopilot_spine"
        }
        .to_string(),
        caller_selected_category: false,
        caller_selected_coordination_depth: input_shape.requested_max_depth.is_some(),
        planned_max_depth: effective_plan.max_depth,
        derived_coordination_depth: observed.coordination_depth,
        forge_mode: plan.forge_mode,
        git_history_mutation_granted: false,
        permitted: refusal_reason.is_none(),
        refusal_reason,
        assignments,
    })
}

fn authority_assignment(
    id: String,
    parent_id: Option<String>,
    role: AgentRole,
    requested_model: Option<String>,
    review_lens: bool,
) -> Result<AutopilotAuthorityAssignment> {
    let category = AuthorityRoleCategory::from_legacy_role(agent_role_label(role))?;
    let model_capability = requested_model
        .as_deref()
        .and_then(trusted_model_capability);
    let model_authoritative = requested_model.is_none()
        || model_capability.is_some_and(|capability| {
            validate_known_judgment_role_model(role, requested_model.as_deref()).is_ok()
                && capability >= minimum_authority_capability(role)
        });
    Ok(AutopilotAuthorityAssignment {
        id,
        parent_id,
        role,
        category,
        requested_model,
        model_capability,
        may_delegate: category == AuthorityRoleCategory::DelegatingCoordinator
            && model_authoritative,
        may_write: matches!(
            category,
            AuthorityRoleCategory::DelegatingCoordinator
                | AuthorityRoleCategory::NonDelegatingTerminalWorker
        ) && model_authoritative,
        may_judge_acceptance: category == AuthorityRoleCategory::ReadOnlyReviewAuditor
            && model_authoritative,
        may_mutate_git_history: false,
        authority_source: if review_lens {
            "effective_review_lens_role_mapping"
        } else {
            "effective_assignment_role_mapping"
        }
        .to_string(),
    })
}

fn role_model_refusal_reason(role: AgentRole, model: Option<&str>) -> Option<String> {
    let model = model?;
    let reason = match role {
        AgentRole::Supervisor | AgentRole::ChildOrchestrator => {
            "model_ineligible_for_delegating_coordinator"
        }
        AgentRole::Auditor | AgentRole::GateClassifier => "model_ineligible_for_review_auditor",
        AgentRole::Worker => return None,
    };
    validate_known_judgment_role_model(role, Some(model))
        .is_err()
        .then(|| reason.to_string())
}

fn minimum_authority_capability(role: AgentRole) -> ModelCapabilityClass {
    match role {
        AgentRole::Worker => ModelCapabilityClass::WeakMechanical,
        AgentRole::Supervisor | AgentRole::ChildOrchestrator => {
            ModelCapabilityClass::GeneralJudgment
        }
        AgentRole::Auditor | AgentRole::GateClassifier => ModelCapabilityClass::CriticalJudgment,
    }
}

fn agent_role_label(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Supervisor => "supervisor",
        AgentRole::ChildOrchestrator => "child_orchestrator",
        AgentRole::Worker => "worker",
        AgentRole::GateClassifier => "gate_classifier",
        AgentRole::Auditor => "auditor",
    }
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
        None,
    )
}

pub fn run_autopilot_plan_file_with_profile_retention_and_parent(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
    parent_node: Option<String>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_and_retention(
        options,
        profile,
        machine_global_retention,
        AutopilotRunSource::PlanFile,
        parent_node,
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
        None,
    )
}

pub fn run_autopilot_goal_spec_with_profile_retention_and_parent(
    options: AutopilotRunOptions,
    goal: &str,
    spec: &str,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
    parent_node: Option<String>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_and_retention(
        options,
        profile,
        machine_global_retention,
        AutopilotRunSource::GoalSpec { goal, spec },
        parent_node,
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
            &ProcessCancellation,
        ) -> crate::external_agent::ExternalAgentRun
                     + Send),
    },
}

fn run_autopilot_with_profile_and_retention(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: Option<MachineGlobalRetentionBinding>,
    source: AutopilotRunSource<'_>,
    parent_node: Option<String>,
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_retention_and_dispatch(
        options,
        profile,
        machine_global_retention,
        source,
        parent_node,
        AutopilotCascadeDispatch::Production(std::marker::PhantomData),
    )
}

fn supervisor_terminal_cleanup_completed(report: &SupervisorFinalReport) -> bool {
    let released_claim_tokens = report
        .released_claims
        .iter()
        .map(|claim| claim.token.get())
        .collect::<BTreeSet<_>>();
    let released_semantic_tokens = report
        .released_semantic_intents
        .iter()
        .map(|intent| intent.token.get())
        .collect::<BTreeSet<_>>();
    report.release_errors.is_empty()
        && report.semantic_release_errors.is_empty()
        && report.claim_tokens.iter().copied().collect::<BTreeSet<_>>() == released_claim_tokens
        && report
            .semantic_intent_tokens
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            == released_semantic_tokens
}

fn cancelled_cascade_cleanup_completed(
    repo: &Path,
    cascade: &supervise::SupervisorCascadeOutcome,
    primary_worktree_untouched: bool,
) -> Result<bool> {
    let no_pending_worktree_operations =
        WorktreeManager::new(repo).pending_operations()?.is_empty();
    let queue_cleanup_completed = cascade.follow_up_queue.as_ref().is_none_or(|queue| {
        queue.enqueue_committed
            && queue.claimed_count == 0
            && queue.dispatch_started_count == 0
            && queue.dispatch_observed_count == 0
            && queue.held_ambiguous_count == 0
            && queue
                .pending_count
                .checked_add(queue.acknowledged_terminal_count)
                == Some(queue.item_count)
    });
    Ok(primary_worktree_untouched
        && cascade.follow_up_primary_worktree_untouched != Some(false)
        && supervisor_terminal_cleanup_completed(&cascade.source_report)
        && cascade
            .follow_up_reports
            .iter()
            .all(supervisor_terminal_cleanup_completed)
        && queue_cleanup_completed
        && no_pending_worktree_operations)
}

fn cancelled_pre_dispatch_cleanup_completed(
    repo: &Path,
    primary_worktree_untouched: bool,
) -> Result<bool> {
    Ok(primary_worktree_untouched && WorktreeManager::new(repo).pending_operations()?.is_empty())
}

fn find_generated_follow_up_taxonomy_gate_id(
    cascade_denials: &[GateDenial],
    dispatched_subordinate_denials: &[&GateDenial],
) -> Option<String> {
    cascade_denials.iter().find_map(|denial| {
        // Finalized subordinate denials are folded into the cascade vector.
        // Exclude those exact records before interpreting a queue-local
        // pre-dispatch refusal as the generated plan's taxonomy outcome.
        let originated_in_dispatched_subordinate = dispatched_subordinate_denials.contains(&denial);
        (matches!(
            denial.reason,
            GateDenialReason::ApprovalReview {
                denial: ApprovalReviewDenial::HumanReviewRequired
            }
        ) && denial.context.source == GateCheckSource::FutureApprovalReview
            && is_reviewed_taxonomy_gate_id(&denial.context.owner)
            && !originated_in_dispatched_subordinate)
            .then(|| denial.context.owner.clone())
    })
}

#[cfg(test)]
fn run_autopilot_plan_file_with_injected_supervisor_and_runner(
    options: AutopilotRunOptions,
    profile: Option<AutopilotProfile>,
    machine_global_retention: MachineGlobalRetentionBinding,
    supervisor_plan: Value,
    external_runner: &mut (dyn FnMut(
        &crate::external_agent::ExternalAgentCommand,
        &ProcessCancellation,
    ) -> crate::external_agent::ExternalAgentRun
              + Send),
) -> Result<AutopilotFinalReport> {
    run_autopilot_with_profile_retention_and_dispatch(
        options,
        profile,
        Some(machine_global_retention),
        AutopilotRunSource::PlanFile,
        None,
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
    parent_node: Option<String>,
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
    let budget_overrides = options.budget_overrides;
    let budget_max_duration_seconds = options.budget_max_duration_seconds;
    let cancellation_observed = AtomicBool::new(false);
    let source_dispatch_started = AtomicBool::new(false);

    let repo = discover_repo_root(&options.repo)?;
    let collision = crate::run_ops::refuse_live_run_collision(
        &repo,
        RunArtifactFamily::Autopilot,
        &options.run_id,
        options.allow_live_run_collision,
    )?;
    let _process_registration =
        crate::run_ops::register_current_supervisor_process(&repo, "autopilot", &options.run_id)
            .ok()
            .flatten();
    let selected_supervisor_runtime = if options.codex_bin.is_some() {
        SupervisorRuntime::Codex
    } else {
        SupervisorRuntime::Fake
    };
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
        selected_supervisor_runtime,
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
    persist_autopilot_launch_preflight(&mut artifact_writer, &repo, &options, &collision)?;
    crate::run_ops::append_run_heartbeat_best_effort(
        &mut artifact_writer,
        "initialized",
        None,
        "ok",
        None,
    );
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
            authority_plan: None,
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
        finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
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
        selected_supervisor_runtime,
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
            authority_plan: None,
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
        finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
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
    let authority_plan = autopilot_authority_plan(
        &plan,
        &supervisor_plan,
        &effective_supervisor_plan,
        &input_shape,
        goal_derived_supervisor_plan,
    )?;
    write_private_json(&mut artifact_writer, "authority-plan.json", &authority_plan)?;
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
            authority_plan: Some(authority_plan),
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
        finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
        return Ok(report);
    }
    if authority_plan.refusal_reason.is_some() {
        let denial = GateDenial::from_approval_review(
            options.run_id.as_str(),
            "maco-autopilot",
            ApprovalReviewDenial::PermissionExpansion,
            &plan.assigned_paths,
        )?;
        let mut authority_safety = pre_dispatch_safety;
        authority_safety.gate_denials.insert(0, denial.clone());
        authority_safety.refused = true;
        write_skipped_stage_reports(&mut artifact_writer, "launch_authority_refused")?;
        let report = final_report(FinalReportInput {
            run_id: &options.run_id,
            status: AutopilotRunStatus::Refused,
            attempt_count: 0,
            max_repair_attempts: plan.max_repair_attempts,
            artifacts,
            plan: plan_summary(&plan),
            profile_binding,
            safety: authority_safety,
            authority_plan: Some(authority_plan),
            validation: skipped_autopilot_validation(),
            pr: None,
            review: None,
            attempts: Vec::new(),
            supervisor: None,
            gate_denials: vec![denial],
            primary_worktree_untouched: false,
            next_action: "remove the ineligible authority request or bind it to an eligible category/model before starting a new run",
            auto_merge_requested: plan.auto_merge,
            generated_follow_up_dispatch_performed: false,
        });
        finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
        return Ok(report);
    }
    let (codex_bin, runtime) = match options.codex_bin {
        Some(codex_bin) => (codex_bin, SupervisorRuntime::Codex),
        None => (PathBuf::from("codex-not-executed"), SupervisorRuntime::Fake),
    };
    debug_assert_eq!(runtime, selected_supervisor_runtime);
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
        parent_node,
        codex_bin,
        runtime,
        // Autopilot's own authenticated artifacts are local runtime state. The
        // outer typed dirty-primary gate already handled operator worktree state.
        allow_dirty_primary: true,
        allow_live_run_collision: options.allow_live_run_collision,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides,
        budget_max_duration_seconds,
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
    let mut taxonomy_gate_id = None::<String>;
    let mut admitted_child_dispatches = 0_usize;
    let error_evidence_source_plan_sha256 =
        supervise::normalized_supervisor_plan_file_sha256(&supervisor_options.plan_file)?;
    let command_primary_baseline = match runtime {
        SupervisorRuntime::Fake => {
            supervise::nonpublishable_simulation_whole_primary_snapshot_sha256(&repo)?
        }
        _ => supervise::verified_whole_primary_snapshot_sha256(&repo)?,
    };
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
            // Generated plans are checked at the central queue boundary after
            // authenticated reload. Only the initial source reaches this
            // admission check, so one dispatch consumes one decision.
            if !source_dispatch_started.load(Ordering::SeqCst) {
                let taxonomy_decision = autonomous_decision_for_supervisor_child_dispatch();
                if let Some(gate_id) = taxonomy_decision.gate_id() {
                    taxonomy_gate_id = Some(gate_id.to_string());
                    let denial = GateDenial::from_approval_review(
                        options.run_id.as_str(),
                        gate_id,
                        ApprovalReviewDenial::HumanReviewRequired,
                        effective_paths.clone(),
                    )?;
                    before_dispatch_denial = Some(denial.clone());
                    return Ok(Some(denial));
                }
            }
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
            if max_child_dispatches.is_some_and(|maximum| admitted_child_dispatches >= maximum) {
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
                    &cancellation_observed,
                    &source_dispatch_started,
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
                &cancellation_observed,
                &source_dispatch_started,
                &mut follow_up_profile_gate,
                *external_runner,
            ),
        }
    };
    let command_primary_final = match runtime {
        SupervisorRuntime::Fake => {
            supervise::nonpublishable_simulation_whole_primary_snapshot_sha256(&repo)?
        }
        _ => supervise::verified_whole_primary_snapshot_sha256(&repo)?,
    };
    let command_primary_worktree_untouched = command_primary_final == command_primary_baseline;
    if let Some(refusal) = follow_up_profile_refusal.take() {
        profile_binding = refusal;
    }
    let cascade = match supervisor_result {
        Ok(cascade) => cascade,
        Err(error) => {
            let cancellation_was_observed = cancellation_observed.load(Ordering::SeqCst);
            let source_dispatch_started = source_dispatch_started.load(Ordering::SeqCst);
            let cancellation_cleanup_completed = if cancellation_was_observed
                && !source_dispatch_started
            {
                cancelled_pre_dispatch_cleanup_completed(&repo, command_primary_worktree_untouched)
                    .unwrap_or_default()
            } else {
                false
            };
            let profile_refused_before_source_dispatch =
                !source_dispatch_started && !profile_binding.permits_dispatch();
            let admission_refused_before_source_dispatch = !source_dispatch_started
                && before_dispatch_denial.as_ref().is_some_and(|denial| {
                    matches!(denial.reason, GateDenialReason::BudgetAdmission { .. })
                });
            let taxonomy_refused_before_source_dispatch =
                !source_dispatch_started && taxonomy_gate_id.is_some();
            let taxonomy_refusal_next_action = taxonomy_gate_id.as_deref().map(|gate_id| {
                format!(
                    "the mutation taxonomy requires gate `{gate_id}`; the named gate, including taxonomy review for `taxonomy-review-required`, is required before retrying; no supervisor or generated follow-up dispatch occurred"
                )
            });
            let generated_follow_up_dispatch_performed = if !source_dispatch_started {
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
                status: if cancellation_cleanup_completed {
                    AutopilotRunStatus::Cancelled
                } else if taxonomy_refused_before_source_dispatch
                    || admission_refused_before_source_dispatch
                {
                    AutopilotRunStatus::Refused
                } else {
                    AutopilotRunStatus::Failed
                },
                attempt_count: usize::from(source_dispatch_started),
                max_repair_attempts: plan.max_repair_attempts,
                artifacts,
                plan: plan_summary(&plan),
                profile_binding: profile_binding.clone(),
                safety: pre_dispatch_safety,
                authority_plan: Some(authority_plan.clone()),
                validation: skipped_autopilot_validation(),
                pr: None,
                review: None,
                attempts: if source_dispatch_started {
                    vec![attempt]
                } else {
                    Vec::new()
                },
                supervisor: None,
                gate_denials: before_dispatch_denial.clone().into_iter().collect(),
                primary_worktree_untouched: command_primary_worktree_untouched,
                next_action: if cancellation_was_observed && source_dispatch_started {
                    "caller cancellation was requested after supervisor dispatch, but terminal cleanup or finalization returned an error; inspect the supervisor checkpoint, claims, worktrees, and process evidence before retrying"
                } else if cancellation_cleanup_completed {
                    "caller cancellation was observed before supervisor dispatch; start a new run only if the work is still required"
                } else if cancellation_was_observed {
                    "caller cancellation was observed before supervisor dispatch, but pending-worktree or primary-integrity cleanup evidence is incomplete; reconcile durable worktree operations before retrying"
                } else if let Some(next_action) = taxonomy_refusal_next_action.as_deref() {
                    next_action
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
            finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
            return Ok(report);
        }
    };
    let dispatched_subordinate_denials = cascade
        .follow_up_reports
        .iter()
        .flat_map(|report| report.gate_denials.iter())
        .collect::<Vec<_>>();
    let generated_follow_up_taxonomy_gate_id = find_generated_follow_up_taxonomy_gate_id(
        &cascade.follow_up_gate_denials,
        &dispatched_subordinate_denials,
    );
    let generated_follow_up_dispatch_performed = cascade.generated_follow_up_dispatch_performed();
    let follow_up_cascade_success = cascade.follow_up_cascade_success;
    let follow_up_gate_denials = cascade.follow_up_gate_denials.clone();
    let cancellation_was_observed = cancellation_observed.load(Ordering::SeqCst);
    let cancellation_cleanup_completed = if cancellation_was_observed {
        cancelled_cascade_cleanup_completed(&repo, &cascade, command_primary_worktree_untouched)
            .unwrap_or_default()
    } else {
        false
    };
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
    let taxonomy_refusal_gate_id = taxonomy_gate_id.or(generated_follow_up_taxonomy_gate_id);
    let taxonomy_refusal_next_action = taxonomy_refusal_gate_id.as_deref().map(|gate_id| {
        format!(
            "the mutation taxonomy requires gate `{gate_id}`; the named gate, including taxonomy review for `taxonomy-review-required`, is required before retrying; the taxonomy-refused generated follow-up was not dispatched"
        )
    });
    let child_dispatch_admission_refused = before_dispatch_denial
        .as_ref()
        .is_some_and(|denial| matches!(denial.reason, GateDenialReason::BudgetAdmission { .. }));
    let status = if cancellation_cleanup_completed {
        AutopilotRunStatus::Cancelled
    } else if cancellation_was_observed {
        AutopilotRunStatus::Failed
    } else if taxonomy_refusal_gate_id.is_some() || child_dispatch_admission_refused {
        AutopilotRunStatus::Refused
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
    let next_action = if cancellation_cleanup_completed {
        "caller cancellation was observed and the supervised cleanup path completed; inspect the durable supervisor and queue evidence before starting a new run"
    } else if cancellation_was_observed {
        "caller cancellation was observed but terminal cleanup evidence is incomplete; reconcile supervisor claims, semantic intents, worktrees, and the authenticated follow-up queue before retrying"
    } else if let Some(next_action) = taxonomy_refusal_next_action.as_deref() {
        next_action
    } else if child_dispatch_admission_refused {
        "review the configured child-dispatch maximum and start a new run with an adequate bound; the refused generated follow-up was not dispatched"
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
        authority_plan: Some(authority_plan),
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
    finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
    Ok(report)
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
    let selected_supervisor_runtime = if real_runtime_requested {
        SupervisorRuntime::Codex
    } else {
        SupervisorRuntime::Fake
    };
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
        selected_supervisor_runtime,
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
            authority_plan: None,
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
        finalize_autopilot_run_artifacts(artifact_writer, &report, false)?;
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
        if !options.allow_dirty_primary && !dirty_primary_paths(&repo, runtime)?.is_empty() {
            bail!("primary worktree changed after safety preflight and before supervisor start");
        }
        repository_bindings
            .verify()
            .context("repository changed immediately before supervisor start")?;
        let supervisor = match supervise::run_supervisor_plan_file(SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: supervisor_plan_path,
            run_id: supervisor_run_id.clone(),
            parent_node: None,
            codex_bin,
            runtime,
            // Autopilot already ran the real primary-change preflight; nested
            // supervise should not reject autopilot's own runtime artifacts.
            allow_dirty_primary: true,
            allow_live_run_collision: options.allow_live_run_collision,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: options.budget_overrides,
            budget_max_duration_seconds: options.budget_max_duration_seconds,
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
        let validation_cancellation = options.cancellation.clone().unwrap_or_default();
        let mut hooks = PrepublicationHooks {
            prepare: |options| {
                publication::prepare_pr_candidate_with_write_lease(options, &worktree_lease)
            },
            validate: |worktree: PathBuf| {
                run_validation_commands(&worktree, &plan, &validation_cancellation)
            },
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
        authority_plan: None,
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
    let publish_requested = publish_requested_for_audit(
        real_runtime_requested,
        plan.forge_mode,
        report
            .attempts
            .iter()
            .any(|attempt| attempt.publication_attempted),
    );
    finalize_autopilot_run_artifacts(artifact_writer, &report, publish_requested)?;
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
    let absolute_run_dir = repo
        .join(RunArtifactFamily::Autopilot.run_root())
        .join(run_id.as_str());
    let heartbeats = crate::run_ops::read_heartbeat_ledger(&absolute_run_dir).unwrap_or_default();
    Ok(AutopilotStatusReport {
        run_dir: public_run_dir().join(run_id.as_str()),
        run_id,
        artifacts,
        last_heartbeat: heartbeats.last().cloned(),
        heartbeat_count: heartbeats.len(),
        operator_summary_exists: crate::run_ops::operator_summary_exists(&absolute_run_dir),
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
    runtime: SupervisorRuntime,
) -> Result<AutopilotSafetyReport> {
    let mut gate_denials = Vec::new();
    if !allow_dirty_primary {
        let dirty_paths = dirty_primary_paths(repo, runtime)?;
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
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: plan.assigned_paths.clone(),
            semantic_symbols: plan.semantic_symbols.clone(),
            semantic_modules: plan.semantic_modules.clone(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: format!("{agent_id}-worker"),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
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

fn run_validation_commands(
    worktree: &Path,
    plan: &AutopilotPlan,
    cancellation: &ProcessCancellation,
) -> Result<Vec<ValidationReport>> {
    let mut reports = Vec::new();
    for (index, validation) in plan.validation_commands.iter().enumerate() {
        if cancellation.is_cancelled() {
            bail!(
                "autopilot validation cancelled before command {}",
                index + 1
            );
        }
        let output = run_validation_process(
            worktree,
            &validation.command,
            validation.timeout_seconds.map(Duration::from_secs),
            cancellation,
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
    cancellation: &ProcessCancellation,
) -> Result<ProcessOutput, ProcessRunError> {
    run_process_cancellable(
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
        cancellation,
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

include!("autopilot/part2.rs");

#[cfg(test)]
mod tests;
