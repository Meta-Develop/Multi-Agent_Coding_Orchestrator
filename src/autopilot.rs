use crate::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily},
    live_claim::{self, LiveClock},
    merge::{
        ApplyBlocker, ApplyReadinessStatus, SafetyCheckStatus, ValidationReport, ValidationStatus,
    },
    orchestrator::{RunId, SemanticCoordinationMode},
    planning,
    process_runner::{
        run_process, CapturedBytes, EnvironmentMode, ProcessOutput, ProcessRunError, ProcessSpec,
        Shell, SideEffectConfinementProfile, StrictOfflineWorkspaceProfile,
    },
    publication::{
        self, ForgeKind, PrPublicationOptions, PrPublicationReport, PrPublicationStatus,
    },
    review::{
        self, ReviewPrOptions, ReviewReport, ReviewReportStatus, ReviewerConfig, ReviewerMode,
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
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const AUTOPILOT_SCHEMA_VERSION: u32 = 1;
const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 600;
const VALIDATION_OUTPUT_LIMIT: usize = 8 * 1024;
const VALIDATION_CAPTURE_LIMIT_BYTES: usize = VALIDATION_OUTPUT_LIMIT * 4;
const ARTIFACT_FINAL_MARKER: &str = ".maco-artifact-final.json";

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
    pub repair_reason: Option<String>,
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
    let contents = fs::read_to_string(task_file)
        .with_context(|| format!("failed to read autopilot task file {}", task_file.display()))?;
    if let Ok(plan) = serde_json::from_str::<AutopilotPlan>(&contents) {
        return validate_autopilot_plan(&repo, plan);
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
        },
    )
}

pub fn run_autopilot_plan_file(options: AutopilotRunOptions) -> Result<AutopilotFinalReport> {
    let repo = discover_repo_root(&options.repo)?;
    let mut plan = autopilot_plan_from_task_file(&repo, &options.plan_file)?;
    if let Some(command) = options.reviewer_command.clone() {
        plan.reviewer.mode = ReviewerMode::ExternalCommand;
        plan.reviewer.command = Some(command);
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
    let mut repair_reasons = Vec::new();
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
            supervisor_plan_for_attempt(&plan, &agent_id, attempt, &repair_reasons);
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
            repair_reason: None,
        };
        let (codex_bin, runtime) = match &options.codex_bin {
            Some(path) => (path.clone(), SupervisorRuntime::Codex),
            None => match write_fake_codex(&mut artifact_writer, &plan, attempt) {
                Ok(path) => (path, SupervisorRuntime::Fake),
                Err(error) => {
                    write_failed_report(
                        &mut artifact_writer,
                        "supervisor-report.json",
                        "runtime_setup_failed",
                        &sanitize_text(&repo, &format!("{error:#}")),
                    )?;
                    write_skipped_report(
                        &mut artifact_writer,
                        "pr-report.json",
                        "runtime_setup_failed",
                    )?;
                    write_skipped_report(
                        &mut artifact_writer,
                        "review-report.json",
                        "runtime_setup_failed",
                    )?;
                    attempt_summary.supervisor_status = "failed".to_string();
                    attempts.push(attempt_summary);
                    next_action = "repair the local supervisor runtime setup, then rerun autopilot"
                        .to_string();
                    break;
                }
            },
        };
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
        let validation_reports = match run_validation_commands(worktree_lease.path(), &plan) {
            Ok(reports) => reports,
            Err(error) => {
                write_failed_report(
                    &mut artifact_writer,
                    "pr-report.json",
                    "validation_execution_failed",
                    &sanitize_text(&repo, &format!("{error:#}")),
                )?;
                write_skipped_report(
                    &mut artifact_writer,
                    "review-report.json",
                    "validation_execution_failed",
                )?;
                attempt_summary.repair_reason = Some("validation execution failed".to_string());
                attempts.push(attempt_summary);
                next_action =
                    "repair the validation runtime, then rerun autopilot before publication"
                        .to_string();
                break;
            }
        };
        last_validation = validation_summary(validation_reports.clone());
        attempt_summary.validation_status = last_validation.status;
        if last_validation.status == AutopilotValidationStatus::Failed {
            write_skipped_report(&mut artifact_writer, "pr-report.json", "validation_failed")?;
            write_skipped_report(
                &mut artifact_writer,
                "review-report.json",
                "validation_failed",
            )?;
            if attempt < max_attempts {
                let reason = validation_repair_reason(&last_validation);
                attempt_summary.repair_reason = Some(reason.clone());
                repair_reasons.push(reason);
                attempts.push(attempt_summary);
                continue;
            }
            attempts.push(attempt_summary);
            next_action =
                "fix failing validation, rerun autopilot, then have a human review and merge manually"
                    .to_string();
            break;
        }

        let pr_report = match publish_pr_holding_write_lease(
            &worktree_lease,
            PrPublicationOptions {
                repo: repo.clone(),
                agent_id: agent_id.clone(),
                claimed_paths: plan.assigned_paths.clone(),
                validations: validation_reports,
                forge: plan.forge_mode.into_publication_forge(),
                draft: plan.publish_mode == AutopilotPublishMode::DraftOnly,
            },
        ) {
            Ok(report) => report,
            Err(error) => {
                write_failed_report(
                    &mut artifact_writer,
                    "pr-report.json",
                    "publication_failed",
                    &sanitize_text(&repo, &format!("{error:#}")),
                )?;
                write_skipped_report(
                    &mut artifact_writer,
                    "review-report.json",
                    "publication_failed",
                )?;
                attempts.push(attempt_summary);
                next_action =
                    "inspect the publication failure, reconcile any durable receipt, and rerun"
                        .to_string();
                break;
            }
        };
        let sanitized_pr = sanitize_pr_report(&pr_report);
        attempt_summary.pr_status = Some(sanitized_pr.status.clone());
        write_private_json(&mut artifact_writer, "pr-report.json", &sanitized_pr)?;
        last_pr = Some(sanitized_pr);

        if pr_report.status == PrPublicationStatus::Blocked {
            write_skipped_report(
                &mut artifact_writer,
                "review-report.json",
                "pr_safety_blocked",
            )?;
            attempts.push(attempt_summary);
            next_action =
                "resolve PR safety blockers before review; no automatic merge was performed"
                    .to_string();
            break;
        }

        let review_report = match review::review_pr(ReviewPrOptions {
            repo: repo.clone(),
            target: pr_report
                .pr_url
                .clone()
                .unwrap_or_else(|| format!("agent-worktree:{agent_id}")),
            reviewer: plan.reviewer.clone(),
            attempt,
            changed_paths: review::normalize_changed_paths(pr_report.changed_paths.clone()),
            diff_summary: review::diff_summary_from_text(
                &pr_report.preview.candidate.diff.summary.text,
            ),
        }) {
            Ok(report) => report,
            Err(error) => {
                write_failed_report(
                    &mut artifact_writer,
                    "review-report.json",
                    "review_failed",
                    &sanitize_text(&repo, &format!("{error:#}")),
                )?;
                attempts.push(attempt_summary);
                next_action =
                    "repair the independent reviewer runtime, then rerun before manual merge"
                        .to_string();
                break;
            }
        };
        attempt_summary.review_status = Some(review_report.status);
        attempt_summary.blocking_findings = review_report.blocking_finding_count;
        write_private_json(&mut artifact_writer, "review-report.json", &review_report)?;
        last_review = Some(review_report.clone());

        if review_report.blocking_finding_count > 0 {
            if attempt < max_attempts {
                let reason = review_repair_reason(&review_report);
                attempt_summary.repair_reason = Some(reason.clone());
                repair_reasons.push(reason);
                attempts.push(attempt_summary);
                continue;
            }
            attempts.push(attempt_summary);
            next_action =
                "repair blocking review findings, rerun autopilot, then have a human merge manually"
                    .to_string();
            break;
        }

        attempts.push(attempt_summary);
        status = AutopilotRunStatus::Succeeded;
        next_action =
            "human reviews the draft pull request and merges manually; autopilot never auto-merges"
                .to_string();
        drop(worktree_lease);
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
    let publish_requested = report.success && real_runtime_requested;
    artifact_writer.finalize("final-report.json", publish_requested)?;
    Ok(report)
}

pub fn autopilot_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<AutopilotStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let (artifacts, final_report) = match autopilot_artifact_run_state(&repo, &run_id)? {
        ArtifactRunState::Missing => (empty_artifact_status(), None),
        ArtifactRunState::Active(run_dir) => (unfinalized_artifact_status(&run_dir)?, None),
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
    plan.task.title = plan.task.title.trim().to_string();
    plan.task.body = plan.task.body.trim().to_string();
    if plan.task.title.is_empty() {
        plan.task.title = title_from_plain_task(&plan.task.body);
    }
    if plan.task.body.is_empty() {
        plan.task.body = plan.task.title.clone();
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
        command.name = command
            .name
            .take()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
    }
    Ok(plan)
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
    repair_reasons: &[String],
) -> SupervisorPlan {
    let task = supervisor_task(plan, attempt, repair_reasons);
    SupervisorPlan {
        version: 1,
        task: task.clone(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
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

fn supervisor_task(plan: &AutopilotPlan, attempt: usize, repair_reasons: &[String]) -> String {
    let mut task = format!(
        "{}\n\n{}\n\nAutopilot attempt: {attempt}\n",
        plan.task.title, plan.task.body
    );
    if !repair_reasons.is_empty() {
        task.push_str("\nRepair context from prior attempts:\n");
        for reason in repair_reasons {
            task.push_str("- ");
            task.push_str(reason);
            task.push('\n');
        }
    }
    task
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
            *text = sanitize_validation_message(text);
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

/// Publication mutates and repeatedly snapshots the selected worktree. The
/// write lease is therefore an explicit argument even while the publication
/// module migrates to its borrowed-authority entrypoint. The lease must remain
/// live through publication, independent review, and final quiescence.
fn publish_pr_holding_write_lease(
    lease: &ManagedWorktreeWriteLease,
    options: PrPublicationOptions,
) -> Result<PrPublicationReport> {
    publication::publish_pr_with_write_lease(options, lease)
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

fn write_fake_codex(
    writer: &mut ArtifactRunWriter,
    plan: &AutopilotPlan,
    attempt: usize,
) -> Result<PathBuf> {
    let relative = PathBuf::from("runtime").join(format!("fake-codex-attempt-{attempt}"));
    let paths_text = plan
        .assigned_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let paths_json = serde_json::to_string(&plan.assigned_paths)
        .context("failed to serialize assigned paths")?;
    let script = format!(
        r#"#!/bin/sh
set -eu
report=
worktree=
json_seen=false
prompt_arg=
while [ "$#" -gt 0 ]; do
  case "$1" in
    exec)
      shift
      ;;
    --json)
      json_seen=true
      shift
      ;;
    --output-last-message)
      report="$2"
      shift 2
      ;;
    --output-schema|--sandbox|-c)
      shift 2
      ;;
    --cd)
      worktree="$2"
      shift 2
      ;;
    -*)
      prompt_arg="$1"
      shift
      ;;
    *)
      prompt_arg="$1"
      shift
      ;;
  esac
done
if [ "$json_seen" != "true" ]; then
  echo "missing --json flag" >&2
  exit 64
fi
if [ "$prompt_arg" != "-" ]; then
  echo "expected prompt from stdin marker '-'" >&2
  exit 64
fi
prompt_body="$(cat)"
case "$prompt_body" in
  *"Autopilot attempt:"*) prompt_from_stdin=true ;;
  *) prompt_from_stdin=false ;;
esac
mkdir -p "$(dirname "$report")"
printf '{{"event":"fake-autopilot-start","prompt_from_stdin":%s}}\n' "$prompt_from_stdin"
name="$(basename "$report" .json)"
assigned_paths_json="$(cat <<'JSONPATHS'
{paths_json}
JSONPATHS
)"
paths_file="$(dirname "$report")/$name.assigned-paths"
cat > "$paths_file" <<'PATHS'
{paths_text}
PATHS
if [ "${{name%-review-auditor}}" != "$name" ]; then
  case "$prompt_body" in
    "ROLE: REVIEW_AUDITOR"*)
      child_name="${{name%-review-auditor}}"
      cat > "$report" <<JSON
{{
  "id": "$name",
  "role": "auditor",
  "reviewed_worker_ids": ["$child_name-worker"],
  "reviewed_paths": $assigned_paths_json,
  "commands_run": [],
  "validation_results": [
    {{"name": "fake parent auditor validation", "status": "succeeded", "command": [], "message": null}}
  ],
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review fake autopilot diff"
}}
JSON
      exit 0
      ;;
  esac
fi
while IFS= read -r relpath; do
  [ -n "$relpath" ] || continue
  target="$worktree/$relpath"
  if [ -d "$target" ]; then
    target="$target/autopilot-fake.txt"
  fi
  mkdir -p "$(dirname "$target")"
  printf '\nautopilot fake attempt {attempt} from %s\n' "$name" >> "$target"
done < "$paths_file"
cat > "$report" <<JSON
{{
  "id": "$name",
  "role": "child_orchestrator",
  "assigned_paths": $assigned_paths_json,
  "semantic_symbols": [],
  "semantic_modules": [],
  "commands_run": [],
  "files_changed": $assigned_paths_json,
  "validation_results": [
    {{"name": "fake child validation", "status": "succeeded", "command": [], "message": null}}
  ],
  "findings": [],
  "worker_reports": [
    {{
      "id": "$name-worker",
      "role": "worker",
      "assigned_paths": $assigned_paths_json,
      "semantic_symbols": [],
      "semantic_modules": [],
      "commands_run": [],
      "files_changed": $assigned_paths_json,
      "validation_results": [
        {{"name": "fake worker validation", "status": "succeeded", "command": [], "message": null}}
      ],
      "findings": [],
      "no_further_delegation": true,
      "accepted": true,
      "rejected": false,
      "status": "succeeded",
      "remaining_risk": "none",
      "next_safe_action": "review fake autopilot diff"
    }}
  ],
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "publish through autopilot PR gate"
}}
JSON
"#,
        paths_json = paths_json,
        paths_text = paths_text,
        attempt = attempt
    );
    writer.write_bytes(
        &relative,
        script.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let path = writer.run_dir().join(&relative);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod fake codex {}", path.display()))?;
    }
    Ok(path)
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
    Active(PathBuf),
    Finalized(Box<ArtifactRunReader>),
}

fn autopilot_artifact_run_state(repo: &Path, run_id: &RunId) -> Result<ArtifactRunState> {
    let Some(run_dir) =
        verified_unfinalized_run_dir(repo, &[".maco", "autopilot", "runs", run_id.as_str()])?
    else {
        return Ok(ArtifactRunState::Missing);
    };
    if !known_regular_file_exists(&run_dir, ARTIFACT_FINAL_MARKER)? {
        return Ok(ArtifactRunState::Active(run_dir));
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

fn verified_unfinalized_run_dir(repo: &Path, components: &[&str]) -> Result<Option<PathBuf>> {
    let mut current = repo.to_path_buf();
    for component in components {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect artifact directory {}", current.display())
                })
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "artifact directory is not a direct non-link directory: {}",
                current.display()
            );
        }
    }
    Ok(Some(current))
}

fn known_regular_file_exists(run_dir: &Path, name: &str) -> Result<bool> {
    let path = run_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "artifact entry is not a direct regular file: {}",
                path.display()
            )
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect artifact file {}", path.display())),
    }
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

fn unfinalized_artifact_status(run_dir: &Path) -> Result<AutopilotArtifactStatus> {
    let status = AutopilotArtifactStatus {
        plan: known_regular_file_exists(run_dir, "plan.json")?,
        supervisor_report: known_regular_file_exists(run_dir, "supervisor-report.json")?,
        pr_report: known_regular_file_exists(run_dir, "pr-report.json")?,
        review_report: known_regular_file_exists(run_dir, "review-report.json")?,
        final_report: known_regular_file_exists(run_dir, "final-report.json")?,
    };
    if known_regular_file_exists(run_dir, ARTIFACT_FINAL_MARKER)? {
        bail!("artifact run finalized while active status was being inspected; retry status");
    }
    Ok(status)
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

fn dirty_primary_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect primary worktree status")?;
    let mut paths = statuses
        .iter()
        .filter_map(|entry| entry.path().map(PathBuf::from))
        .filter(|path| !is_local_runtime_path(path))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
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
    let mut sanitized = text.replace(&repo.display().to_string(), ".");
    if let Some(parent) = repo.parent() {
        sanitized = sanitized.replace(&parent.display().to_string(), "<repo-parent>");
    }
    sanitized
}

fn sanitize_validation_message(text: &str) -> String {
    text.replace('\0', "")
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
    use std::{sync::mpsc, thread, time::Duration};

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
        drop(tree);
        drop(repo);
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
                agent_id: agent_id.to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create managed worktree");
        (repo_path, manager)
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
            },
        );

        let error = result.expect_err("empty proposal must be refused");
        assert!(error.to_string().contains("assigned paths are empty"));
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
        assert!(second_writer.to_string().contains("exclusive write lease"));

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
