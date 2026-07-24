use crate::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily},
    live_claim::{self, LiveClock},
    llm::Redactor,
    merge::{
        ApplyBlocker, ApplyReadinessStatus, BoundValidationEvidenceBundle,
        CandidateValidationBinding, SafetyCheckStatus, ValidationEvidenceBundle, ValidationReport,
        ValidationStatus,
    },
    orchestrator::{RunId, SemanticCoordinationMode},
    planning,
    process_runner::{
        run_process, CapturedBytes, EnvironmentMode, ProcessOutput, ProcessRunError, ProcessSpec,
        Shell, SideEffectConfinementProfile, StrictOfflineWorkspaceProfile,
    },
    publication::{
        self, ExternalSourceGuard, ForgeKind, PrPublicationOptions, PrPublicationReport,
        PrPublicationStatus,
    },
    review::{
        self, ReviewPrOptions, ReviewReport, ReviewReportStatus, ReviewerConfig, ReviewerMode,
    },
    safe_state::{
        BoundedRegularReader, BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction,
        BoundedTreeWalkLimits, BoundedTreeWalker, DirectoryBindingGuard,
    },
    semantic_coord::SemanticIntentStore,
    supervise::{
        self, AgentRole, FindingSeverity, OrchestratorAssignment, ReviewStatus,
        SupervisorFinalReport, SupervisorPlan, SupervisorRunOptions, SupervisorRuntime,
        ValidationResult, WorkerAssignment,
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
    path::{Path, PathBuf},
    time::Duration,
};

const AUTOPILOT_SCHEMA_VERSION: u32 = 1;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub safety: AutopilotSafetyReport,
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
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotRunStatus {
    Succeeded,
    Failed,
    Refused,
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
    pub refusals: Vec<AutopilotSafetyRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotSafetyRefusal {
    pub kind: String,
    pub message: String,
    pub paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_details: Vec<AutopilotLockRefusalDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutopilotLockRefusalDetail {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
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

pub fn autopilot_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<AutopilotPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let contents =
        BoundedRegularReader::read_tree_no_follow_utf8(task_file, AUTOPILOT_PLAN_MAX_BYTES)
            .with_context(|| {
                format!("failed to read autopilot task file {}", task_file.display())
            })?;
    match serde_json::from_str::<AutopilotPlan>(&contents) {
        Ok(plan) => return validate_autopilot_plan(&repo, plan),
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

    validate_autopilot_plan(
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
    )
}

pub fn run_autopilot_plan_file(_options: AutopilotRunOptions) -> Result<AutopilotFinalReport> {
    Err(effectful_autopilot_unavailable_error())
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

    let safety = safety_report(&repo, options.allow_dirty_primary, &plan.assigned_paths)?;
    let repository_bindings = RepositoryPathBindings::bind(&repo)?;
    verify_after_autopilot_safety(&repository_bindings)?;
    if safety.refused {
        write_skipped_stage_reports(&mut artifact_writer, "safety_refusal")?;
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
            safety,
            validation,
            pr: None,
            review: None,
            attempts: Vec::new(),
            next_action:
                "resolve the safety refusal, then rerun autopilot; a human reviews and merges manually",
            auto_merge_requested: plan.auto_merge,
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
        let supervisor_plan =
            supervisor_plan_for_attempt(&plan, &agent_id, attempt, &repair_contexts);
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
        safety,
        validation: last_validation,
        pr: last_pr,
        review: last_review,
        attempts,
        next_action: &next_action,
        auto_merge_requested: plan.auto_merge,
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
    allow_dirty_primary: bool,
    target_paths: &[PathBuf],
) -> Result<AutopilotSafetyReport> {
    let mut refusals = Vec::new();
    if !allow_dirty_primary {
        let dirty_paths = dirty_primary_paths(repo)?;
        if !dirty_paths.is_empty() {
            refusals.push(AutopilotSafetyRefusal {
                kind: "dirty_primary".to_string(),
                message: "primary worktree has local changes".to_string(),
                paths: dirty_paths,
                lock_details: Vec::new(),
            });
        }
    }

    let sync_claims = SyncStore::open(repo)?.snapshot()?;
    let mut sync_details = Vec::new();
    for claim in &sync_claims {
        for path in planning::any_path_overlaps(target_paths, &claim.paths) {
            sync_details.push(AutopilotLockRefusalDetail {
                path,
                owner: Some(claim.agent_id.clone()),
                token: Some(claim.token.get()),
                claim_id: None,
            });
        }
    }
    if !sync_details.is_empty() {
        refusals.push(AutopilotSafetyRefusal {
            kind: "active_sync_claims".to_string(),
            message: "active durable sync claims overlap autopilot target paths".to_string(),
            paths: detail_paths(&sync_details),
            lock_details: sync_details,
        });
    }

    let semantic_intents = SemanticIntentStore::open(repo)?.snapshot()?;
    let mut semantic_details = Vec::new();
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
            semantic_details.push(AutopilotLockRefusalDetail {
                path,
                owner: Some(intent.agent_id.clone()),
                token: Some(intent.token.get()),
                claim_id: None,
            });
        }
    }
    if !semantic_details.is_empty() {
        refusals.push(AutopilotSafetyRefusal {
            kind: "active_semantic_intents".to_string(),
            message: "active semantic coordination intents overlap autopilot target paths"
                .to_string(),
            paths: detail_paths(&semantic_details),
            lock_details: semantic_details,
        });
    }

    let live = live_claim::status(repo, &LiveClock::now())?;
    let mut live_details = Vec::new();
    for claim in live.claims.into_iter().filter(|claim| claim.is_lock) {
        for path in planning::any_path_overlaps(target_paths, &claim.owned_files) {
            live_details.push(AutopilotLockRefusalDetail {
                path,
                owner: claim.owner.clone(),
                token: None,
                claim_id: Some(claim.claim_id.clone()),
            });
        }
    }
    if !live_details.is_empty() {
        refusals.push(AutopilotSafetyRefusal {
            kind: "active_live_locks".to_string(),
            message: "active or blocked live claim locks overlap autopilot target paths"
                .to_string(),
            paths: detail_paths(&live_details),
            lock_details: live_details,
        });
    }

    Ok(AutopilotSafetyReport {
        refused: !refusals.is_empty(),
        refusals,
    })
}

fn detail_paths(details: &[AutopilotLockRefusalDetail]) -> Vec<PathBuf> {
    details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn supervisor_plan_for_attempt(
    plan: &AutopilotPlan,
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
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
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
                report_path: None,
            }],
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

struct PrepublicationHooks<P, V, R, U> {
    prepare: P,
    validate: V,
    review: R,
    publish: U,
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

fn run_prepublication_attempt<P, V, R, U>(
    repo: &Path,
    agent_id: &str,
    attempt: usize,
    plan: &AutopilotPlan,
    lease: &ManagedWorktreeWriteLease,
    hooks: &mut PrepublicationHooks<P, V, R, U>,
) -> AutopilotPrepublicationOutcome
where
    P: FnMut(PrPublicationOptions) -> Result<PrPublicationReport>,
    V: FnMut(PathBuf) -> Result<Vec<ValidationReport>>,
    R: FnMut(ReviewPrOptions) -> Result<review::PublicationReviewResult>,
    U: FnMut(PrPublicationOptions, BoundValidationEvidenceBundle) -> Result<PrPublicationReport>,
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
    let prepared =
        match prepared_candidate_from_report(&prepared_report, repo, agent_id, forge, lease) {
            Ok(prepared) => prepared,
            Err(error) => {
                return stopped_prepublication(
                    "preparation_invalid",
                    format!(
                        "candidate preparation did not return a clean exact preview: {error:#}"
                    ),
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
fn reverify_prepared_candidate<P>(
    options: PrPublicationOptions,
    agent_id: &str,
    expected_binding: &CandidateValidationBinding,
    lease: &ManagedWorktreeWriteLease,
    prepare: &mut P,
    phase: &str,
    validation: AutopilotValidationSummary,
    review: Option<ReviewReport>,
    reviewed_candidate: Option<AutopilotReviewedCandidate>,
) -> std::result::Result<(), Box<AutopilotPrepublicationOutcome>>
where
    P: FnMut(PrPublicationOptions) -> Result<PrPublicationReport>,
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

fn prepared_candidate_from_report(
    report: &PrPublicationReport,
    expected_repo: &Path,
    agent_id: &str,
    expected_forge: ForgeKind,
    lease: &ManagedWorktreeWriteLease,
) -> Result<PreparedAutopilotCandidate> {
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
    if !repository_worktree_is_clean(&report.preview.candidate.metadata.worktree_path)? {
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

struct FinalReportInput<'a> {
    run_id: &'a RunId,
    status: AutopilotRunStatus,
    attempt_count: usize,
    max_repair_attempts: usize,
    artifacts: AutopilotArtifactPaths,
    plan: AutopilotPlanSummary,
    safety: AutopilotSafetyReport,
    validation: AutopilotValidationSummary,
    pr: Option<SanitizedPrReport>,
    review: Option<ReviewReport>,
    attempts: Vec<AutopilotAttemptSummary>,
    next_action: &'a str,
    auto_merge_requested: bool,
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
        safety: input.safety,
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
        next_action: input.next_action.to_string(),
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
    use crate::worktree::WorktreeCreateOptions;
    use std::{
        cell::{Cell, RefCell},
        fs::File,
        rc::Rc,
        sync::{mpsc, Mutex, MutexGuard, OnceLock},
        thread,
        time::Duration,
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

    #[test]
    fn effectful_autopilot_fails_closed_before_any_repository_or_runtime_side_effect() {
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
            reviewer_command: Some("must-not-run".to_string()),
            allow_dirty_primary: true,
        })
        .expect_err("effectful autopilot must be unconditionally unavailable");

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
        assert!(format!("{error:#}").contains("capability-bound supervisor input bridge"));
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
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "order-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan =
            prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::ExternalCommand);
        let trace = RefCell::new(Vec::new());
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| {
                trace.borrow_mut().push("prepare");
                publication::prepare_pr_candidate_with_write_lease(options, &lease)
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
            publish: |options, evidence| {
                trace.borrow_mut().push("publish");
                publish_calls.set(publish_calls.get() + 1);
                publication::publish_prepared_pr_with_write_lease(options, &evidence, &lease)
            },
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
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "review-gate-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let review_calls = Cell::new(0usize);
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
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
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "retry-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let mut plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::Fake);
        plan.reviewer.blocking_attempts = 1;
        let publish_calls = Cell::new(0usize);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(passed_prepublication_validation()),
            review: review::review_pr_for_publication,
            publish: |options, evidence| {
                publish_calls.set(publish_calls.get() + 1);
                publication::publish_prepared_pr_with_write_lease(options, &evidence, &lease)
            },
        };

        let first = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);
        assert_eq!(first.reason, "review_blocked");
        assert!(!first.publication_attempted);
        assert_eq!(publish_calls.get(), 0);

        let second = run_prepublication_attempt(&repo, agent_id, 2, &plan, &lease, &mut hooks);
        assert_eq!(second.disposition, PrepublicationDisposition::Published);
        assert_eq!(publish_calls.get(), 1);
        assert_no_remote_publication_state(&repo);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_hook_report_forge_and_base_mismatch_are_nonretryable() {
        let _fixture_guard = lock_prepublication_fixture_test();
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_id = "hook-mismatch-agent";
        let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
        let publish_calls = Cell::new(0usize);
        let return_base_mismatch = Cell::new(false);
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(passed_prepublication_validation()),
            review: |options| {
                Ok(injected_external_publication_review(
                    options,
                    ReviewReportStatus::Passed,
                ))
            },
            publish: |mut options: PrPublicationOptions,
                      evidence: BoundValidationEvidenceBundle| {
                publish_calls.set(publish_calls.get() + 1);
                options.forge = ForgeKind::Fake;
                let mut report =
                    publication::publish_prepared_pr_with_write_lease(options, &evidence, &lease)?;
                if return_base_mismatch.get() {
                    let expected_head = evidence
                        .binding()
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
        let worker_manager = manager.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let lease = acquire_autopilot_worktree_write_lease(&worker_manager, "barrier-agent")
                .expect("acquire autopilot write lease");
            ready_tx.send(()).expect("publish lease barrier");
            release_rx.recv().expect("release lease barrier");
            drop(lease);
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("autopilot write lease barrier became ready");
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

        release_tx.send(()).expect("release autopilot writer");
        worker.join().expect("join lease barrier");
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
