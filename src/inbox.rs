use crate::{
    artifacts::{self, RunArtifactFamily},
    autopilot::{
        self, AutopilotForgeMode, AutopilotPlan, AutopilotPublishMode, AutopilotRunOptions,
        AutopilotTask, AutopilotValidationCommand,
    },
    live_claim::{self, LiveClock},
    llm::{RedactionSummary, Redactor},
    orchestrator::RunId,
    planning,
    review::{ReviewerConfig, ReviewerMode},
    semantic_coord::SemanticIntentStore,
    sync::normalize_repo_relative_path,
    sync_store::SyncStore,
};
use anyhow::{bail, Context, Result};
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

const INBOX_SCHEMA_VERSION: u32 = 1;
const CONFIG_FILE: &str = "maco-inbox.json";
const DEFAULT_MAX_ITEMS: usize = 4;
const DEFAULT_BODY_LIMIT: usize = 12 * 1024;
const GH_OUTPUT_LIMIT: usize = 512 * 1024;
const GH_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const COMMENT_BODY_LIMIT: usize = 6 * 1024;

#[derive(Debug, Clone)]
pub struct InboxScanOptions {
    pub repo: PathBuf,
    pub github: bool,
    pub max_items: Option<usize>,
    pub action_policy_override: Option<InboxActionPolicy>,
}

#[derive(Debug, Clone)]
pub struct InboxRunOptions {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub github: bool,
    pub dry_run: bool,
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct InboxWatchOptions {
    pub repo: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub github: bool,
    pub dry_run: bool,
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxConfig {
    #[serde(default)]
    pub repository: InboxRepositoryConfig,
    #[serde(default)]
    pub selection: InboxSelectionConfig,
    #[serde(default)]
    pub action_policy: InboxActionPolicy,
    #[serde(default = "default_max_repair_attempts")]
    pub max_repair_attempts: usize,
    #[serde(default)]
    pub default_validation_commands: Vec<AutopilotValidationCommand>,
    #[serde(default = "default_assigned_paths")]
    pub default_assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub privacy: InboxPrivacyPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

impl Default for InboxConfig {
    fn default() -> Self {
        Self {
            repository: InboxRepositoryConfig::default(),
            selection: InboxSelectionConfig::default(),
            action_policy: InboxActionPolicy::default(),
            max_repair_attempts: default_max_repair_attempts(),
            default_validation_commands: Vec::new(),
            default_assigned_paths: default_assigned_paths(),
            privacy: InboxPrivacyPolicy::default(),
            timeout_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxRepositoryConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxSelectionConfig {
    #[serde(default = "default_true")]
    pub issues: bool,
    #[serde(default = "default_true", alias = "prs")]
    pub pull_requests: bool,
    #[serde(default = "default_max_items")]
    pub max_items: usize,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub include_draft_prs: bool,
}

impl Default for InboxSelectionConfig {
    fn default() -> Self {
        Self {
            issues: true,
            pull_requests: true,
            max_items: DEFAULT_MAX_ITEMS,
            labels: Vec::new(),
            include_draft_prs: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxActionPolicy {
    DryRun,
    #[default]
    Fake,
    Github,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxPrivacyPolicy {
    #[serde(default)]
    pub allow_private_bodies: bool,
    #[serde(default = "default_blocked_terms")]
    pub blocked_terms: Vec<String>,
    #[serde(default = "default_body_limit")]
    pub max_body_chars: usize,
}

impl Default for InboxPrivacyPolicy {
    fn default() -> Self {
        Self {
            allow_private_bodies: false,
            blocked_terms: default_blocked_terms(),
            max_body_chars: DEFAULT_BODY_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxScanReport {
    pub version: u32,
    pub repo: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    pub action_policy: InboxActionPolicy,
    pub github_enabled: bool,
    pub success: bool,
    pub refused: bool,
    pub refusals: Vec<InboxRefusal>,
    pub candidate_count: usize,
    pub selected_count: usize,
    pub items: Vec<InboxItem>,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRefusal {
    pub kind: String,
    pub message: String,
    pub paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_details: Vec<InboxLockRefusalDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxLockRefusalDetail {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxItem {
    pub item_id: String,
    pub source_key: String,
    pub kind: InboxItemKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue: Option<GithubIssueCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<GithubPrCandidate>,
    pub privacy: PrivacyScanResult,
    pub duplicate: DuplicateDetectionResult,
    pub selected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxItemKind {
    Issue,
    PullRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubIssueCandidate {
    pub number: u64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub body_summary: String,
    pub body_truncated: bool,
    pub assigned_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubPrCandidate {
    pub number: u64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    pub changed_files: Vec<PathBuf>,
    pub checks: Vec<GithubCheckSummary>,
    pub review_feedback: GithubReviewFeedbackSummary,
    pub body_summary: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubCheckSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubReviewFeedbackSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_decision: Option<String>,
    pub requested_changes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_thread_count: Option<usize>,
    pub reviewer_logins: Vec<String>,
    pub summaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivacyScanResult {
    pub safe: bool,
    pub reasons: Vec<String>,
    pub redactions: RedactionSummary,
    pub body_summary: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DuplicateDetectionResult {
    pub duplicate: bool,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRunReport {
    pub version: u32,
    pub run_id: RunId,
    pub repo: PathBuf,
    pub action_policy: InboxActionPolicy,
    pub github_enabled: bool,
    pub success: bool,
    pub status: InboxRunStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<InboxRefusal>,
    pub artifacts: InboxRunArtifacts,
    pub selected_item_count: usize,
    pub item_reports: Vec<InboxItemRunReport>,
    pub auto_merge_performed: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxRunStatus {
    Succeeded,
    Failed,
    Refused,
    DryRun,
    NoItems,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRunArtifacts {
    pub run_dir: PathBuf,
    pub scan_report: PathBuf,
    pub selected_items: PathBuf,
    pub final_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxItemRunReport {
    pub item_index: usize,
    pub item_id: String,
    pub kind: InboxItemKind,
    pub title: String,
    pub success: bool,
    pub status: String,
    pub plan_path: PathBuf,
    pub autopilot_run_id: String,
    pub autopilot_report_path: PathBuf,
    pub github_report_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autopilot_success: Option<bool>,
    pub github_success: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxGithubActionReport {
    pub mode: InboxActionPolicy,
    pub status: String,
    pub success: bool,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxStatusReport {
    pub run_id: RunId,
    pub run_dir: PathBuf,
    pub artifacts: InboxArtifactStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxArtifactStatus {
    pub scan_report: bool,
    pub selected_items: bool,
    pub final_report: bool,
    pub item_plan_count: usize,
    pub item_autopilot_report_count: usize,
    pub item_github_report_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWatchReport {
    pub repo: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub iteration_count: usize,
    pub runs: Vec<InboxRunReport>,
}

#[derive(Debug, Clone)]
struct LoadedConfig {
    config: InboxConfig,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct RawIssueCandidate {
    number: u64,
    title: String,
    body: String,
    url: Option<String>,
    author: Option<String>,
    labels: Vec<String>,
    updated_at: Option<String>,
    assigned_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct RawPrCandidate {
    number: u64,
    title: String,
    body: String,
    url: Option<String>,
    author: Option<String>,
    labels: Vec<String>,
    updated_at: Option<String>,
    head_ref: Option<String>,
    base_ref: Option<String>,
    changed_files: Vec<PathBuf>,
    checks: Vec<GithubCheckSummary>,
    review_feedback: GithubReviewFeedbackSummary,
}

pub fn scan_inbox(options: InboxScanOptions) -> Result<InboxScanReport> {
    let repo = discover_repo_root(&options.repo)?;
    let loaded =
        load_config_with_overrides(&repo, options.max_items, options.action_policy_override)?;
    let action_policy = effective_action_policy(loaded.config.action_policy, options.github);
    let github_enabled = action_policy == InboxActionPolicy::Github;
    let duplicate_keys = load_duplicate_keys(&repo)?;
    let mut items = Vec::new();
    if loaded.config.selection.issues {
        let issues = if github_enabled {
            github_issue_candidates(&repo, &loaded.config)?
        } else {
            fake_issue_candidates(&loaded.config)
        };
        for issue in issues {
            items.push(issue_item(issue, &loaded.config, &duplicate_keys)?);
        }
    }
    if loaded.config.selection.pull_requests {
        let pull_requests = if github_enabled {
            github_pr_candidates(&repo, &loaded.config)?
        } else {
            fake_pr_candidates(&loaded.config)
        };
        for pull_request in pull_requests {
            if !loaded.config.selection.include_draft_prs
                && pull_request
                    .review_feedback
                    .review_decision
                    .as_deref()
                    .is_some_and(|decision| decision.eq_ignore_ascii_case("DRAFT"))
            {
                continue;
            }
            items.push(pr_item(pull_request, &loaded.config, &duplicate_keys)?);
        }
    }
    items.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.item_id.cmp(&right.item_id))
    });
    apply_scan_decisions(&mut items, loaded.config.selection.max_items);

    let selected_count = items.iter().filter(|item| item.selected).count();
    let candidate_count = items.len();
    let target_paths = selected_target_paths(&items, &loaded.config)?;
    let refusals = preflight_refusals(&repo, &target_paths)?;
    if !refusals.is_empty() {
        return Ok(InboxScanReport {
            version: INBOX_SCHEMA_VERSION,
            repo: public_repo_path(),
            config_path: loaded.path,
            action_policy,
            github_enabled,
            success: false,
            refused: true,
            refusals,
            candidate_count,
            selected_count,
            items,
            next_action: "resolve inbox safety refusals, then scan again".to_string(),
        });
    }
    Ok(InboxScanReport {
        version: INBOX_SCHEMA_VERSION,
        repo: public_repo_path(),
        config_path: loaded.path,
        action_policy,
        github_enabled,
        success: true,
        refused: false,
        refusals: Vec::new(),
        candidate_count,
        selected_count,
        items,
        next_action: if selected_count == 0 {
            "no safe non-duplicate inbox items selected".to_string()
        } else {
            "run maco inbox run with a stable run id".to_string()
        },
    })
}

pub fn run_inbox(options: InboxRunOptions) -> Result<InboxRunReport> {
    let repo = discover_repo_root(&options.repo)?;
    let run_dir = inbox_run_dir(&repo, &options.run_id);
    artifacts::ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &options.run_id)?;
    fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create inbox run dir {}", run_dir.display()))?;
    let artifacts = run_artifacts(&options.run_id);
    let scan = scan_inbox(InboxScanOptions {
        repo: repo.clone(),
        github: options.github,
        max_items: options.max_items,
        action_policy_override: if options.dry_run {
            Some(InboxActionPolicy::DryRun)
        } else {
            None
        },
    })?;
    write_json_file(&run_dir.join("scan-report.json"), &scan)?;

    let selected_items = scan
        .items
        .iter()
        .filter(|item| item.selected)
        .cloned()
        .collect::<Vec<_>>();
    write_json_file(&run_dir.join("selected-items.json"), &selected_items)?;

    if scan.refused {
        let report = InboxRunReport {
            version: INBOX_SCHEMA_VERSION,
            run_id: options.run_id,
            repo: public_repo_path(),
            action_policy: scan.action_policy,
            github_enabled: scan.github_enabled,
            success: false,
            status: InboxRunStatus::Refused,
            refusals: scan.refusals,
            artifacts,
            selected_item_count: 0,
            item_reports: Vec::new(),
            auto_merge_performed: false,
            next_action: "resolve inbox safety refusals, then rerun".to_string(),
        };
        write_json_file(&run_dir.join("final-report.json"), &report)?;
        return Ok(report);
    }

    if selected_items.is_empty() {
        let report = InboxRunReport {
            version: INBOX_SCHEMA_VERSION,
            run_id: options.run_id,
            repo: public_repo_path(),
            action_policy: scan.action_policy,
            github_enabled: scan.github_enabled,
            success: true,
            status: InboxRunStatus::NoItems,
            refusals: Vec::new(),
            artifacts,
            selected_item_count: 0,
            item_reports: Vec::new(),
            auto_merge_performed: false,
            next_action: "no safe non-duplicate inbox items were available".to_string(),
        };
        write_json_file(&run_dir.join("final-report.json"), &report)?;
        return Ok(report);
    }

    let loaded = load_config_with_overrides(
        &repo,
        options.max_items,
        if options.dry_run {
            Some(InboxActionPolicy::DryRun)
        } else {
            None
        },
    )?;
    let action_policy = scan.action_policy;
    let mut item_reports = Vec::new();
    for (zero_index, item) in selected_items.iter().enumerate() {
        let item_index = zero_index.saturating_add(1);
        let item_report = run_inbox_item(
            &repo,
            &run_dir,
            &options.run_id,
            item_index,
            item,
            &loaded.config,
            action_policy,
        )?;
        item_reports.push(item_report);
    }

    let success = item_reports.iter().all(|report| report.success);
    let status = if action_policy == InboxActionPolicy::DryRun {
        InboxRunStatus::DryRun
    } else if success {
        InboxRunStatus::Succeeded
    } else {
        InboxRunStatus::Failed
    };
    let report = InboxRunReport {
        version: INBOX_SCHEMA_VERSION,
        run_id: options.run_id,
        repo: public_repo_path(),
        action_policy,
        github_enabled: scan.github_enabled,
        success,
        status,
        refusals: Vec::new(),
        artifacts,
        selected_item_count: selected_items.len(),
        item_reports,
        auto_merge_performed: false,
        next_action: if success {
            "review inbox item reports; no automatic merge was performed".to_string()
        } else {
            "inspect failed item reports and rerun after repair".to_string()
        },
    };
    write_json_file(&run_dir.join("final-report.json"), &report)?;
    Ok(report)
}

pub fn inbox_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<InboxStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = inbox_run_dir(&repo, &run_id);
    let final_path = run_dir.join("final-report.json");
    let final_report = if final_path.exists() {
        Some(read_json_value(&final_path)?)
    } else {
        None
    };
    Ok(InboxStatusReport {
        run_dir: public_run_dir().join(run_id.as_str()),
        run_id,
        artifacts: artifact_status(&run_dir)?,
        final_report,
    })
}

pub fn collect_inbox_run(repo: impl AsRef<Path>, run_id: RunId) -> Result<Value> {
    let repo = discover_repo_root(repo.as_ref())?;
    let final_path = inbox_run_dir(&repo, &run_id).join("final-report.json");
    if final_path.exists() {
        return read_json_value(&final_path);
    }
    Ok(json!({
        "version": INBOX_SCHEMA_VERSION,
        "run_id": run_id,
        "status": "missing",
        "success": false,
        "next_action": "rerun maco inbox run for this run id"
    }))
}

pub fn watch_inbox(options: InboxWatchOptions) -> Result<InboxWatchReport> {
    if options.poll_seconds == 0 {
        bail!("poll-seconds must be greater than zero");
    }
    let repo = discover_repo_root(&options.repo)?;
    let mut runs = Vec::new();
    let mut iteration = 0usize;
    loop {
        iteration = iteration.saturating_add(1);
        let run_id =
            artifacts::generate_run_id(&repo, RunArtifactFamily::Inbox).with_context(|| {
                format!("failed to generate inbox watch run id for iteration {iteration}")
            })?;
        let report = run_inbox(InboxRunOptions {
            repo: repo.clone(),
            run_id,
            github: options.github,
            dry_run: options.dry_run,
            max_items: options.max_items,
        })?;
        runs.push(report);
        if options.once {
            break;
        }
        thread::sleep(Duration::from_secs(options.poll_seconds));
    }
    Ok(InboxWatchReport {
        repo: public_repo_path(),
        poll_seconds: options.poll_seconds,
        once: options.once,
        iteration_count: runs.len(),
        runs,
    })
}

fn run_inbox_item(
    repo: &Path,
    run_dir: &Path,
    run_id: &RunId,
    item_index: usize,
    item: &InboxItem,
    config: &InboxConfig,
    action_policy: InboxActionPolicy,
) -> Result<InboxItemRunReport> {
    let plan = autopilot_plan_for_item(item, config, action_policy)?;
    let plan_path = run_dir.join(format!("item-{item_index}-plan.json"));
    write_json_file(&plan_path, &plan)?;
    let autopilot_report_path = run_dir.join(format!("item-{item_index}-autopilot-report.json"));
    let github_report_path = run_dir.join(format!("item-{item_index}-github-report.json"));
    let autopilot_run_id = RunId::new(format!("{}-item-{item_index}", run_id.as_str()))?;

    if action_policy == InboxActionPolicy::DryRun {
        write_json_file(
            &autopilot_report_path,
            &json!({
                "status": "skipped",
                "success": true,
                "reason": "dry_run action policy does not launch autopilot"
            }),
        )?;
        let github_report = InboxGithubActionReport {
            mode: action_policy,
            status: "skipped".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some("dry_run action policy does not comment or publish".to_string()),
        };
        write_json_file(&github_report_path, &github_report)?;
        return Ok(InboxItemRunReport {
            item_index,
            item_id: item.item_id.clone(),
            kind: item.kind,
            title: item.title.clone(),
            success: true,
            status: "dry_run".to_string(),
            plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
            autopilot_run_id: autopilot_run_id.as_str().to_string(),
            autopilot_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-autopilot-report.json"),
            ),
            github_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-github-report.json"),
            ),
            autopilot_success: None,
            github_success: true,
            next_action: "review the dry-run plan; no work was launched".to_string(),
        });
    }

    let autopilot_result = autopilot::run_autopilot_plan_file(AutopilotRunOptions {
        repo: repo.to_path_buf(),
        plan_file: plan_path.clone(),
        run_id: autopilot_run_id.clone(),
        codex_bin: None,
        reviewer_command: None,
        allow_dirty_primary: false,
    });
    let (autopilot_success, autopilot_message) = match autopilot_result {
        Ok(report) => {
            let success = report.success;
            let message = report.next_action.clone();
            write_json_file(&autopilot_report_path, &report)?;
            (success, Some(message))
        }
        Err(error) => {
            let message = sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text;
            write_json_file(
                &autopilot_report_path,
                &json!({
                    "status": "failed",
                    "success": false,
                    "error": message
                }),
            )?;
            (
                false,
                Some("autopilot failed before producing a final report".to_string()),
            )
        }
    };

    let github_report = github_action_for_item(
        repo,
        config,
        action_policy,
        item,
        autopilot_success,
        autopilot_message,
    );
    write_json_file(&github_report_path, &github_report)?;
    let success = autopilot_success && github_report.success;
    Ok(InboxItemRunReport {
        item_index,
        item_id: item.item_id.clone(),
        kind: item.kind,
        title: item.title.clone(),
        success,
        status: if success {
            "succeeded".to_string()
        } else {
            "failed".to_string()
        },
        plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
        autopilot_run_id: autopilot_run_id.as_str().to_string(),
        autopilot_report_path: public_item_path(
            run_id,
            &format!("item-{item_index}-autopilot-report.json"),
        ),
        github_report_path: public_item_path(
            run_id,
            &format!("item-{item_index}-github-report.json"),
        ),
        autopilot_success: Some(autopilot_success),
        github_success: github_report.success,
        next_action: if success {
            "review the generated autopilot and GitHub reports".to_string()
        } else {
            "inspect the item autopilot and GitHub reports before retrying".to_string()
        },
    })
}

fn autopilot_plan_for_item(
    item: &InboxItem,
    config: &InboxConfig,
    action_policy: InboxActionPolicy,
) -> Result<AutopilotPlan> {
    let assigned_paths = assigned_paths_for_item(item, config)?;
    let mut validation_commands = config.default_validation_commands.clone();
    for command in &mut validation_commands {
        if command.timeout_seconds.is_none() {
            command.timeout_seconds = config.timeout_seconds;
        }
    }
    Ok(AutopilotPlan {
        version: 1,
        task: AutopilotTask {
            title: format!("Inbox {}: {}", item_label(item.kind), item.title),
            body: task_body_for_item(item),
        },
        assigned_paths,
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        validation_commands,
        max_repair_attempts: config.max_repair_attempts,
        forge_mode: if action_policy == InboxActionPolicy::Github {
            AutopilotForgeMode::Github
        } else {
            AutopilotForgeMode::Fake
        },
        reviewer: ReviewerConfig {
            mode: ReviewerMode::Fake,
            timeout_seconds: config.timeout_seconds,
            ..ReviewerConfig::default()
        },
        publish_mode: AutopilotPublishMode::DraftOnly,
        auto_merge: false,
    })
}

fn task_body_for_item(item: &InboxItem) -> String {
    match (&item.issue, &item.pull_request) {
        (Some(issue), _) => format!(
            "React to GitHub issue #{}.\nURL: {}\n\nIssue body summary:\n{}\n\nCreate a focused repair or implementation plan for the assigned paths. Do not merge automatically.",
            issue.number,
            issue.url.as_deref().unwrap_or("unknown"),
            issue.body_summary
        ),
        (_, Some(pr)) => {
            let checks = pr
                .checks
                .iter()
                .map(|check| {
                    format!(
                        "- {} status={} conclusion={} summary={}",
                        check.name,
                        check.status.as_deref().unwrap_or("unknown"),
                        check.conclusion.as_deref().unwrap_or("unknown"),
                        check.summary
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let reviews = pr.review_feedback.summaries.join("\n");
            let failing_checks = pr
                .checks
                .iter()
                .filter(|check| {
                    check_failed(check.conclusion.as_deref(), check.status.as_deref())
                })
                .map(|check| check.name.clone())
                .collect::<Vec<_>>();
            let path_reasons = pr_path_reasons(pr, &failing_checks);
            let validation_expectation = pr_validation_expectation(&failing_checks);
            format!(
                "React to GitHub PR #{}.\nURL: {}\nHead: {}\nBase: {}\n\nChanged files:\n{}\n\nTarget paths and reasons:\n{}\n\nChecks:\n{}\n\nReview feedback:\n{}\n\nValidation expectation:\n{}\n\nRepair failing checks or requested changes in isolated autopilot work. Do not merge automatically.",
                pr.number,
                pr.url.as_deref().unwrap_or("unknown"),
                pr.head_ref.as_deref().unwrap_or("unknown"),
                pr.base_ref.as_deref().unwrap_or("unknown"),
                path_list(&pr.changed_files),
                path_reasons,
                if checks.is_empty() { "no failing check metadata" } else { &checks },
                if reviews.is_empty() { "no review summaries" } else { &reviews },
                validation_expectation
            )
        }
        _ => format!(
            "React to inbox item {}. Do not merge automatically.",
            item.item_id
        ),
    }
}

fn pr_path_reasons(pr: &GithubPrCandidate, failing_checks: &[String]) -> String {
    let check_reason = if failing_checks.is_empty() {
        "review feedback requested changes".to_string()
    } else {
        format!(
            "review feedback requested changes; failing checks: {}",
            failing_checks.join(", ")
        )
    };
    let paths = if pr.changed_files.is_empty() {
        vec![PathBuf::from("README.md")]
    } else {
        pr.changed_files.clone()
    };
    paths
        .iter()
        .map(|path| format!("- {}: {}", path.display(), check_reason))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pr_validation_expectation(failing_checks: &[String]) -> String {
    if failing_checks.is_empty() {
        "preserve configured validation and confirm requested review changes are addressed"
            .to_string()
    } else {
        format!(
            "run or preserve configured validation and address failing check context: {}",
            failing_checks.join(", ")
        )
    }
}

fn github_action_for_item(
    repo: &Path,
    config: &InboxConfig,
    action_policy: InboxActionPolicy,
    item: &InboxItem,
    autopilot_success: bool,
    autopilot_message: Option<String>,
) -> InboxGithubActionReport {
    if action_policy != InboxActionPolicy::Github {
        return InboxGithubActionReport {
            mode: action_policy,
            status: "local_report_only".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some("GitHub comments are disabled outside explicit github mode".to_string()),
        };
    }
    if !autopilot_success {
        return InboxGithubActionReport {
            mode: action_policy,
            status: "skipped".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some("autopilot did not succeed; GitHub comment skipped".to_string()),
        };
    }

    let Some(number) = item_number(item) else {
        return InboxGithubActionReport {
            mode: action_policy,
            status: "failed".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some("item has no GitHub number to comment on".to_string()),
        };
    };
    let body = sanitize_public_text(
        repo,
        &format!(
            "maco inbox processed this item in explicit GitHub mode.\n\nResult: succeeded\nNext action: {}",
            autopilot_message.unwrap_or_else(|| "review generated reports".to_string())
        ),
        COMMENT_BODY_LIMIT,
    )
    .text;
    let subcommand = match item.kind {
        InboxItemKind::Issue => "issue",
        InboxItemKind::PullRequest => "pr",
    };
    let mut args = vec![
        subcommand.to_string(),
        "comment".to_string(),
        number.to_string(),
    ];
    args.push("--body".to_string());
    args.push(body);
    match run_gh_text(repo, config, &args, "gh comment") {
        Ok(stdout) => InboxGithubActionReport {
            mode: action_policy,
            status: "commented".to_string(),
            success: true,
            target: item_target(item),
            comment_url: first_non_empty_line(&stdout.text),
            message: None,
        },
        Err(error) => InboxGithubActionReport {
            mode: action_policy,
            status: "failed".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some(sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text),
        },
    }
}

fn issue_item(
    raw: RawIssueCandidate,
    config: &InboxConfig,
    duplicates: &BTreeMap<String, String>,
) -> Result<InboxItem> {
    let source_key = format!("github_issue:{}", raw.number);
    let mut privacy = privacy_scan(&raw.body, &config.privacy);
    extend_privacy_reasons(&mut privacy, "title", &raw.title, &config.privacy);
    let duplicate = duplicate_result(&source_key, duplicates);
    let mut skip_reason = None;
    if !privacy.safe {
        skip_reason = Some("privacy_refused".to_string());
    } else if duplicate.duplicate {
        skip_reason = Some("duplicate".to_string());
    }
    let selected = skip_reason.is_none();
    let title = sanitize_public_field(&raw.title, 512);
    let url = raw
        .url
        .as_ref()
        .map(|value| sanitize_public_field(value, 1024));
    let author = raw
        .author
        .as_ref()
        .map(|value| sanitize_public_field(value, 256));
    let labels = sanitize_public_fields(&raw.labels, 128);
    Ok(InboxItem {
        item_id: format!("issue-{}", raw.number),
        source_key,
        kind: InboxItemKind::Issue,
        title: title.clone(),
        url: url.clone(),
        issue: Some(GithubIssueCandidate {
            number: raw.number,
            title,
            url,
            author,
            labels,
            updated_at: raw.updated_at,
            body_summary: privacy.body_summary.clone(),
            body_truncated: privacy.body_truncated,
            assigned_paths: normalize_or_default(raw.assigned_paths, config)?,
        }),
        pull_request: None,
        privacy,
        duplicate,
        selected,
        skip_reason,
    })
}

fn pr_item(
    raw: RawPrCandidate,
    config: &InboxConfig,
    duplicates: &BTreeMap<String, String>,
) -> Result<InboxItem> {
    let source_key = format!("github_pr:{}", raw.number);
    let mut privacy = privacy_scan(&raw.body, &config.privacy);
    extend_privacy_reasons(&mut privacy, "title", &raw.title, &config.privacy);
    let duplicate = duplicate_result(&source_key, duplicates);
    let needs_reaction = raw.review_feedback.requested_changes
        || raw
            .checks
            .iter()
            .any(|check| check_failed(check.conclusion.as_deref(), check.status.as_deref()));
    let mut skip_reason = None;
    if !privacy.safe {
        skip_reason = Some("privacy_refused".to_string());
    } else if duplicate.duplicate {
        skip_reason = Some("duplicate".to_string());
    } else if !needs_reaction {
        skip_reason = Some("no_requested_changes_or_failing_checks".to_string());
    }
    let selected = skip_reason.is_none();
    let title = sanitize_public_field(&raw.title, 512);
    let url = raw
        .url
        .as_ref()
        .map(|value| sanitize_public_field(value, 1024));
    let author = raw
        .author
        .as_ref()
        .map(|value| sanitize_public_field(value, 256));
    let labels = sanitize_public_fields(&raw.labels, 128);
    Ok(InboxItem {
        item_id: format!("pr-{}", raw.number),
        source_key,
        kind: InboxItemKind::PullRequest,
        title: title.clone(),
        url: url.clone(),
        issue: None,
        pull_request: Some(GithubPrCandidate {
            number: raw.number,
            title,
            url,
            author,
            labels,
            updated_at: raw.updated_at,
            head_ref: raw.head_ref,
            base_ref: raw.base_ref,
            changed_files: normalize_or_default(raw.changed_files, config)?,
            checks: raw.checks,
            review_feedback: raw.review_feedback,
            body_summary: privacy.body_summary.clone(),
            body_truncated: privacy.body_truncated,
        }),
        privacy,
        duplicate,
        selected,
        skip_reason,
    })
}

fn apply_scan_decisions(items: &mut [InboxItem], max_items: usize) {
    let mut selected_count = 0usize;
    let mut seen_source_keys = BTreeSet::new();
    for item in items {
        if !seen_source_keys.insert(item.source_key.clone()) {
            item.selected = false;
            item.skip_reason = Some("duplicate".to_string());
            item.duplicate.duplicate = true;
            if item.duplicate.reason.is_none() {
                item.duplicate.reason =
                    Some("duplicate inbox candidate in current scan".to_string());
            }
            continue;
        }

        if !item.selected {
            continue;
        }

        if selected_count >= max_items {
            item.selected = false;
            item.skip_reason = Some("selection_limit".to_string());
            continue;
        }

        selected_count = selected_count.saturating_add(1);
    }
}

fn fake_issue_candidates(config: &InboxConfig) -> Vec<RawIssueCandidate> {
    vec![
        RawIssueCandidate {
            number: 101,
            title: "Fake inbox issue: implement a focused local task".to_string(),
            body: "Implement the smallest safe code change for this deterministic fake issue."
                .to_string(),
            url: Some("fake://github/issues/101".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: Some("1970-01-01T00:00:00Z".to_string()),
            assigned_paths: config.default_assigned_paths.clone(),
        },
        RawIssueCandidate {
            number: 101,
            title: "Fake inbox issue: duplicate local task".to_string(),
            body: "Duplicate copy of the deterministic fake issue; it should be skipped."
                .to_string(),
            url: Some("fake://github/issues/101#duplicate".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: Some("1970-01-01T00:00:00Z".to_string()),
            assigned_paths: config.default_assigned_paths.clone(),
        },
        RawIssueCandidate {
            number: 303,
            title: "Fake inbox issue: unsafe private context".to_string(),
            body: "Do not publish local path /home/example/project or API_TOKEN=secret-value."
                .to_string(),
            url: Some("fake://github/issues/303".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: Some("1970-01-01T00:00:00Z".to_string()),
            assigned_paths: config.default_assigned_paths.clone(),
        },
    ]
}

fn fake_pr_candidates(config: &InboxConfig) -> Vec<RawPrCandidate> {
    vec![RawPrCandidate {
        number: 202,
        title: "Fake inbox PR: repair requested changes and failing checks".to_string(),
        body: "A deterministic fake pull request with requested changes and a failing check."
            .to_string(),
        url: Some("fake://github/pulls/202".to_string()),
        author: Some("maco-fake".to_string()),
        labels: config.selection.labels.clone(),
        updated_at: Some("1970-01-01T00:00:00Z".to_string()),
        head_ref: Some("fake/inbox-pr".to_string()),
        base_ref: config.repository.default_branch.clone(),
        changed_files: config.default_assigned_paths.clone(),
        checks: vec![GithubCheckSummary {
            name: "fake-ci".to_string(),
            status: Some("completed".to_string()),
            conclusion: Some("failure".to_string()),
            details_url: Some("fake://github/checks/fake-ci".to_string()),
            summary: "deterministic fake failing check; logs omitted".to_string(),
        }],
        review_feedback: GithubReviewFeedbackSummary {
            review_decision: Some("CHANGES_REQUESTED".to_string()),
            requested_changes: true,
            unresolved_thread_count: Some(1),
            reviewer_logins: vec!["maco-fake-reviewer".to_string()],
            summaries: vec!["deterministic fake requested change".to_string()],
        },
    }]
}

fn github_issue_candidates(repo: &Path, config: &InboxConfig) -> Result<Vec<RawIssueCandidate>> {
    let mut args = vec![
        "issue".to_string(),
        "list".to_string(),
        "--state".to_string(),
        "open".to_string(),
        "--json".to_string(),
        "number,title,body,labels,author,url,updatedAt".to_string(),
        "--limit".to_string(),
        config.selection.max_items.to_string(),
    ];
    for label in &config.selection.labels {
        args.push("--label".to_string());
        args.push(label.clone());
    }
    let output = run_gh_json(repo, config, &args, "gh issue list")?;
    let Some(values) = output.as_array() else {
        bail!("gh issue list did not return a JSON array");
    };
    Ok(values
        .iter()
        .filter_map(|value| raw_issue_from_value(value, config))
        .collect())
}

fn github_pr_candidates(repo: &Path, config: &InboxConfig) -> Result<Vec<RawPrCandidate>> {
    let mut args = vec![
        "pr".to_string(),
        "list".to_string(),
        "--state".to_string(),
        "open".to_string(),
        "--json".to_string(),
        "number,title,body,labels,author,url,updatedAt,headRefName,baseRefName,isDraft,files,reviewDecision,latestReviews,statusCheckRollup".to_string(),
        "--limit".to_string(),
        config.selection.max_items.to_string(),
    ];
    for label in &config.selection.labels {
        args.push("--label".to_string());
        args.push(label.clone());
    }
    let output = run_gh_json(repo, config, &args, "gh pr list")?;
    let Some(values) = output.as_array() else {
        bail!("gh pr list did not return a JSON array");
    };
    Ok(values
        .iter()
        .filter(|value| {
            config.selection.include_draft_prs || !value["isDraft"].as_bool().unwrap_or(false)
        })
        .filter_map(|value| raw_pr_from_value(value, config))
        .collect())
}

fn raw_issue_from_value(value: &Value, config: &InboxConfig) -> Option<RawIssueCandidate> {
    Some(RawIssueCandidate {
        number: value["number"].as_u64()?,
        title: value["title"]
            .as_str()
            .unwrap_or("untitled issue")
            .to_string(),
        body: value["body"].as_str().unwrap_or("").to_string(),
        url: value["url"].as_str().map(ToOwned::to_owned),
        author: value["author"]["login"].as_str().map(ToOwned::to_owned),
        labels: labels_from_value(&value["labels"]),
        updated_at: value["updatedAt"].as_str().map(ToOwned::to_owned),
        assigned_paths: config.default_assigned_paths.clone(),
    })
}

fn raw_pr_from_value(value: &Value, _config: &InboxConfig) -> Option<RawPrCandidate> {
    Some(RawPrCandidate {
        number: value["number"].as_u64()?,
        title: value["title"]
            .as_str()
            .unwrap_or("untitled pull request")
            .to_string(),
        body: value["body"].as_str().unwrap_or("").to_string(),
        url: value["url"].as_str().map(ToOwned::to_owned),
        author: value["author"]["login"].as_str().map(ToOwned::to_owned),
        labels: labels_from_value(&value["labels"]),
        updated_at: value["updatedAt"].as_str().map(ToOwned::to_owned),
        head_ref: value["headRefName"].as_str().map(ToOwned::to_owned),
        base_ref: value["baseRefName"].as_str().map(ToOwned::to_owned),
        changed_files: files_from_value(&value["files"]),
        checks: checks_from_value(&value["statusCheckRollup"]),
        review_feedback: review_feedback_from_value(value),
    })
}

fn labels_from_value(value: &Value) -> Vec<String> {
    let mut labels = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|label| label["name"].as_str())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    labels
}

fn files_from_value(value: &Value) -> Vec<PathBuf> {
    let mut files = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|file| file["path"].as_str())
        .filter_map(|path| normalize_repo_relative_path(path).ok())
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();
    files
}

fn checks_from_value(value: &Value) -> Vec<GithubCheckSummary> {
    let mut checks = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|check| {
            let name = first_string_field(check, &["name", "workflowName", "context"])
                .unwrap_or_else(|| "github-check".to_string());
            let status = first_string_field(check, &["status", "state"]);
            let conclusion = first_string_field(check, &["conclusion"]);
            GithubCheckSummary {
                summary: check_summary(&name, status.as_deref(), conclusion.as_deref()),
                name,
                status,
                conclusion,
                details_url: first_string_field(check, &["detailsUrl", "targetUrl", "url"]),
            }
        })
        .collect::<Vec<_>>();
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    checks
}

fn review_feedback_from_value(value: &Value) -> GithubReviewFeedbackSummary {
    let review_decision = value["reviewDecision"].as_str().map(ToOwned::to_owned);
    let mut reviewer_logins = Vec::new();
    let mut summaries = Vec::new();
    let mut requested_changes = review_decision
        .as_deref()
        .is_some_and(|decision| decision.eq_ignore_ascii_case("CHANGES_REQUESTED"));
    if let Some(reviews) = value["latestReviews"].as_array() {
        for review in reviews {
            if let Some(login) = review["author"]["login"].as_str() {
                reviewer_logins.push(login.to_string());
            }
            if review["state"]
                .as_str()
                .is_some_and(|state| state.eq_ignore_ascii_case("CHANGES_REQUESTED"))
            {
                requested_changes = true;
            }
            if let Some(body) = review["body"].as_str() {
                let summary = summarize_text(body, 512).text;
                if !summary.trim().is_empty() {
                    summaries.push(summary);
                }
            }
        }
    }
    reviewer_logins.sort();
    reviewer_logins.dedup();
    GithubReviewFeedbackSummary {
        review_decision,
        requested_changes,
        unresolved_thread_count: None,
        reviewer_logins,
        summaries,
    }
}

fn preflight_refusals(repo: &Path, target_paths: &[PathBuf]) -> Result<Vec<InboxRefusal>> {
    let mut refusals = Vec::new();
    let dirty_paths = dirty_primary_paths(repo)?;
    if !dirty_paths.is_empty() {
        refusals.push(InboxRefusal {
            kind: "dirty_primary".to_string(),
            message: "primary worktree has local changes outside ignored runtime paths".to_string(),
            paths: dirty_paths,
            lock_details: Vec::new(),
        });
    }

    let sync_claims = SyncStore::open(repo)?.snapshot()?;
    let mut sync_details = Vec::new();
    for claim in &sync_claims {
        for path in planning::any_path_overlaps(target_paths, &claim.paths) {
            sync_details.push(InboxLockRefusalDetail {
                path,
                owner: Some(claim.agent_id.clone()),
                token: Some(claim.token.get()),
                claim_id: None,
            });
        }
    }
    if !sync_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_sync_claims".to_string(),
            message: "active durable sync claims overlap selected inbox target paths".to_string(),
            paths: inbox_detail_paths(&sync_details),
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
            semantic_details.push(InboxLockRefusalDetail {
                path,
                owner: Some(intent.agent_id.clone()),
                token: Some(intent.token.get()),
                claim_id: None,
            });
        }
    }
    if !semantic_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_semantic_intents".to_string(),
            message: "active semantic coordination intents overlap selected inbox target paths"
                .to_string(),
            paths: inbox_detail_paths(&semantic_details),
            lock_details: semantic_details,
        });
    }

    let live = live_claim::status(repo, &LiveClock::now())?;
    let mut live_details = Vec::new();
    for claim in live.claims.into_iter().filter(|claim| claim.is_lock) {
        for path in planning::any_path_overlaps(target_paths, &claim.owned_files) {
            live_details.push(InboxLockRefusalDetail {
                path,
                owner: claim.owner.clone(),
                token: None,
                claim_id: Some(claim.claim_id.clone()),
            });
        }
    }
    if !live_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_live_locks".to_string(),
            message: "active or blocked live claim locks overlap selected inbox target paths"
                .to_string(),
            paths: inbox_detail_paths(&live_details),
            lock_details: live_details,
        });
    }

    Ok(refusals)
}

fn inbox_detail_paths(details: &[InboxLockRefusalDetail]) -> Vec<PathBuf> {
    details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
        .filter(|path| !is_ignored_runtime_path(path))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn load_config(repo: &Path) -> Result<LoadedConfig> {
    let path = repo.join(CONFIG_FILE);
    let (config, config_path) = if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        (
            serde_json::from_str::<InboxConfig>(&contents)
                .with_context(|| format!("failed to parse {}", path.display()))?,
            Some(PathBuf::from(CONFIG_FILE)),
        )
    } else {
        (InboxConfig::default(), None)
    };
    Ok(LoadedConfig {
        config: validate_config(config)?,
        path: config_path,
    })
}

fn load_config_with_overrides(
    repo: &Path,
    max_items: Option<usize>,
    action_policy_override: Option<InboxActionPolicy>,
) -> Result<LoadedConfig> {
    let mut loaded = load_config(repo)?;
    if let Some(max_items) = max_items {
        if max_items == 0 {
            bail!("inbox max-items must be greater than zero");
        }
        loaded.config.selection.max_items = max_items;
    }
    if let Some(action_policy) = action_policy_override {
        loaded.config.action_policy = action_policy;
    }
    Ok(loaded)
}

fn validate_config(mut config: InboxConfig) -> Result<InboxConfig> {
    if config.selection.max_items == 0 {
        bail!("inbox selection max_items must be greater than zero");
    }
    if matches!(config.timeout_seconds, Some(0)) {
        bail!("inbox timeout_seconds must be greater than zero when set");
    }
    config.selection.labels = sorted_unique_strings(std::mem::take(&mut config.selection.labels));
    config.privacy.blocked_terms =
        sorted_unique_strings(std::mem::take(&mut config.privacy.blocked_terms));
    if config.privacy.max_body_chars == 0 {
        config.privacy.max_body_chars = DEFAULT_BODY_LIMIT;
    }
    config.default_assigned_paths =
        normalize_or_default(std::mem::take(&mut config.default_assigned_paths), &config)?;
    for (index, command) in config.default_validation_commands.iter_mut().enumerate() {
        command.command = command.command.trim().to_string();
        if command.command.is_empty() {
            bail!("default validation command {} cannot be empty", index + 1);
        }
        if matches!(command.timeout_seconds, Some(0)) {
            bail!(
                "default validation command {} timeout_seconds must be greater than zero",
                index + 1
            );
        }
        if command.timeout_seconds.is_none() {
            command.timeout_seconds = config.timeout_seconds;
        }
    }
    Ok(config)
}

fn normalize_or_default(paths: Vec<PathBuf>, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let fallback = if config.default_assigned_paths.is_empty() {
        default_assigned_paths()
    } else {
        config.default_assigned_paths.clone()
    };
    let source = if paths.is_empty() { fallback } else { paths };
    let normalized = source
        .into_iter()
        .map(|path| normalize_repo_relative_path(&path))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(normalized.into_iter().collect())
}

fn assigned_paths_for_item(item: &InboxItem, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    match (&item.issue, &item.pull_request) {
        (Some(issue), _) => normalize_or_default(issue.assigned_paths.clone(), config),
        (_, Some(pr)) => normalize_or_default(pr.changed_files.clone(), config),
        _ => normalize_or_default(Vec::new(), config),
    }
}

fn selected_target_paths(items: &[InboxItem], config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for item in items.iter().filter(|item| item.selected) {
        paths.extend(assigned_paths_for_item(item, config)?);
    }
    Ok(paths.into_iter().collect())
}

fn privacy_scan(body: &str, policy: &InboxPrivacyPolicy) -> PrivacyScanResult {
    let redacted = Redactor::new().redact(body);
    let reasons = privacy_reasons(body, &redacted, policy);
    let public_body = sanitize_redacted_public_text(body, &redacted.text);
    let summary = summarize_text(&public_body, policy.max_body_chars);
    PrivacyScanResult {
        safe: reasons.is_empty() || policy.allow_private_bodies,
        reasons,
        redactions: redacted.summary,
        body_summary: summary.text,
        body_truncated: summary.truncated,
    }
}

fn extend_privacy_reasons(
    privacy: &mut PrivacyScanResult,
    label: &str,
    text: &str,
    policy: &InboxPrivacyPolicy,
) {
    let redacted = Redactor::new().redact(text);
    let mut field_reasons = privacy_reasons(text, &redacted, policy)
        .into_iter()
        .map(|reason| format!("{label}_{reason}"))
        .collect::<Vec<_>>();
    if field_reasons.is_empty() {
        return;
    }
    privacy.redactions.merge(redacted.summary);
    privacy.reasons.append(&mut field_reasons);
    privacy.reasons.sort();
    privacy.reasons.dedup();
    privacy.safe = privacy.reasons.is_empty() || policy.allow_private_bodies;
}

fn privacy_reasons(
    text: &str,
    redacted: &crate::llm::RedactedText,
    policy: &InboxPrivacyPolicy,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if redacted.summary.total_replacements > 0 {
        reasons.push("secret_like_content_redacted".to_string());
    }
    if contains_private_key_material(text) {
        reasons.push("private_key_material".to_string());
    }
    if contains_local_absolute_path(text) {
        reasons.push("local_absolute_path".to_string());
    }
    let lower = text.to_ascii_lowercase();
    for term in &policy.blocked_terms {
        let term = term.trim();
        if !term.is_empty() && lower.contains(&term.to_ascii_lowercase()) {
            reasons.push(format!("blocked_term:{term}"));
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn duplicate_result(key: &str, duplicates: &BTreeMap<String, String>) -> DuplicateDetectionResult {
    let matched_run_id = duplicates.get(key).cloned();
    DuplicateDetectionResult {
        duplicate: matched_run_id.is_some(),
        key: key.to_string(),
        reason: matched_run_id
            .as_ref()
            .map(|run_id| format!("already selected by inbox run {run_id}")),
        matched_run_id,
    }
}

fn load_duplicate_keys(repo: &Path) -> Result<BTreeMap<String, String>> {
    let runs_dir = repo.join(public_run_dir());
    let mut duplicates = BTreeMap::new();
    let entries = match fs::read_dir(&runs_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(duplicates),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read inbox runs {}", runs_dir.display()))
        }
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read {}", runs_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
        if !file_type.is_dir() {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().into_owned();
        let final_path = entry.path().join("final-report.json");
        if final_path.exists() {
            let final_report = read_json_value(&final_path)?;
            let completed_successfully = final_report
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let status = final_report.get("status").and_then(Value::as_str);
            if !completed_successfully || matches!(status, Some("dry_run" | "refused")) {
                continue;
            }
        }
        let selected_path = entry.path().join("selected-items.json");
        if !selected_path.exists() {
            continue;
        }
        let value = read_json_value(&selected_path)?;
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(key) = item["source_key"].as_str() {
                    duplicates.entry(key.to_string()).or_insert(run_id.clone());
                }
            }
        }
    }
    Ok(duplicates)
}

fn run_gh_json(repo: &Path, config: &InboxConfig, args: &[String], label: &str) -> Result<Value> {
    let output = run_gh_text(repo, config, args, label)?;
    serde_json::from_str(&output.text).with_context(|| format!("{label} returned invalid JSON"))
}

fn run_gh_text(
    repo: &Path,
    config: &InboxConfig,
    args: &[String],
    label: &str,
) -> Result<BoundedText> {
    let mut command = Command::new("gh");
    command.current_dir(repo).args(args);
    if let Some(repository) = github_repository_arg(config) {
        command.arg("-R").arg(repository);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    let stdout = sanitize_public_text(
        repo,
        &String::from_utf8_lossy(&output.stdout),
        GH_OUTPUT_LIMIT,
    );
    let stderr = sanitize_public_text(
        repo,
        &String::from_utf8_lossy(&output.stderr),
        GH_DIAGNOSTIC_LIMIT,
    );
    if !output.status.success() {
        bail!(
            "{label} failed: {}",
            if stderr.text.trim().is_empty() {
                "no stderr".to_string()
            } else {
                stderr.text
            }
        );
    }
    Ok(stdout)
}

fn github_repository_arg(config: &InboxConfig) -> Option<String> {
    match (&config.repository.owner, &config.repository.name) {
        (Some(owner), Some(name)) if !owner.trim().is_empty() && !name.trim().is_empty() => {
            Some(format!("{}/{}", owner.trim(), name.trim()))
        }
        _ => None,
    }
}

fn artifact_status(run_dir: &Path) -> Result<InboxArtifactStatus> {
    let mut item_plan_count = 0usize;
    let mut item_autopilot_report_count = 0usize;
    let mut item_github_report_count = 0usize;
    if run_dir.exists() {
        for entry in fs::read_dir(run_dir)
            .with_context(|| format!("failed to read inbox run dir {}", run_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("failed to inspect {}", run_dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("item-") && name.ends_with("-plan.json") {
                item_plan_count = item_plan_count.saturating_add(1);
            } else if name.starts_with("item-") && name.ends_with("-autopilot-report.json") {
                item_autopilot_report_count = item_autopilot_report_count.saturating_add(1);
            } else if name.starts_with("item-") && name.ends_with("-github-report.json") {
                item_github_report_count = item_github_report_count.saturating_add(1);
            }
        }
    }
    Ok(InboxArtifactStatus {
        scan_report: run_dir.join("scan-report.json").exists(),
        selected_items: run_dir.join("selected-items.json").exists(),
        final_report: run_dir.join("final-report.json").exists(),
        item_plan_count,
        item_autopilot_report_count,
        item_github_report_count,
    })
}

fn run_artifacts(run_id: &RunId) -> InboxRunArtifacts {
    InboxRunArtifacts {
        run_dir: public_run_dir().join(run_id.as_str()),
        scan_report: public_item_path(run_id, "scan-report.json"),
        selected_items: public_item_path(run_id, "selected-items.json"),
        final_report: public_item_path(run_id, "final-report.json"),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish {}", path.display()))
}

fn read_json_value(path: &Path) -> Result<Value> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn inbox_run_dir(repo: &Path, run_id: &RunId) -> PathBuf {
    repo.join(public_run_dir()).join(run_id.as_str())
}

fn public_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("inbox").join("runs")
}

fn public_repo_path() -> PathBuf {
    PathBuf::from(".")
}

fn public_item_path(run_id: &RunId, file_name: &str) -> PathBuf {
    public_run_dir().join(run_id.as_str()).join(file_name)
}

fn effective_action_policy(configured: InboxActionPolicy, github: bool) -> InboxActionPolicy {
    if github {
        InboxActionPolicy::Github
    } else {
        configured
    }
}

fn is_ignored_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
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

fn item_target(item: &InboxItem) -> String {
    match item.kind {
        InboxItemKind::Issue => item
            .issue
            .as_ref()
            .map(|issue| format!("issue #{}", issue.number))
            .unwrap_or_else(|| item.item_id.clone()),
        InboxItemKind::PullRequest => item
            .pull_request
            .as_ref()
            .map(|pr| format!("pr #{}", pr.number))
            .unwrap_or_else(|| item.item_id.clone()),
    }
}

fn item_number(item: &InboxItem) -> Option<u64> {
    item.issue
        .as_ref()
        .map(|issue| issue.number)
        .or_else(|| item.pull_request.as_ref().map(|pr| pr.number))
}

fn item_label(kind: InboxItemKind) -> &'static str {
    match kind {
        InboxItemKind::Issue => "issue",
        InboxItemKind::PullRequest => "pull request",
    }
}

fn path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "- no changed files".to_string();
    }
    paths
        .iter()
        .map(|path| format!("- {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_string_field(value: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| value[*field].as_str().map(ToOwned::to_owned))
}

fn check_summary(name: &str, status: Option<&str>, conclusion: Option<&str>) -> String {
    if check_failed(conclusion, status) {
        format!("{name} is failing or incomplete; full logs omitted")
    } else {
        format!("{name} check metadata fetched; full logs omitted")
    }
}

fn check_failed(conclusion: Option<&str>, status: Option<&str>) -> bool {
    conclusion.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    }) || status.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    })
}

fn first_non_empty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Debug, Clone)]
struct BoundedText {
    text: String,
    truncated: bool,
}

fn summarize_text(text: &str, limit: usize) -> BoundedText {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    BoundedText {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn sanitize_public_text(repo: &Path, text: &str, limit: usize) -> BoundedText {
    let mut sanitized = Redactor::new().redact(text).text;
    sanitized = sanitized.replace(&repo.display().to_string(), ".");
    if let Some(parent) = repo.parent() {
        sanitized = sanitized.replace(&parent.display().to_string(), "<repo-parent>");
    }
    sanitized = sanitize_redacted_public_text(text, &sanitized);
    summarize_text(&sanitized, limit)
}

fn sanitize_public_field(text: &str, limit: usize) -> String {
    let redacted = Redactor::new().redact(text);
    summarize_text(&sanitize_redacted_public_text(text, &redacted.text), limit).text
}

fn sanitize_public_fields(values: &[String], limit: usize) -> Vec<String> {
    values
        .iter()
        .map(|value| sanitize_public_field(value, limit))
        .collect()
}

fn sanitize_redacted_public_text(original: &str, redacted: &str) -> String {
    if contains_private_key_material(original) || contains_private_key_material(redacted) {
        return "<redacted:private-key-material>".to_string();
    }
    redact_token_like_words(&redact_local_absolute_paths(redacted))
}

fn contains_private_key_material(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("PRIVATE KEY") && (upper.contains("-----BEGIN") || upper.contains("BEGIN "))
}

fn contains_local_absolute_path(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains("/mnt/")
        || text.contains("/home/")
        || lower.contains("c:\\users\\")
        || lower.contains("c:/users/")
}

fn redact_local_absolute_paths(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut token = String::new();
    for character in text.chars() {
        if character.is_whitespace() {
            push_redacted_path_token(&mut output, &token);
            token.clear();
            output.push(character);
        } else {
            token.push(character);
        }
    }
    push_redacted_path_token(&mut output, &token);
    output
}

fn push_redacted_path_token(output: &mut String, token: &str) {
    if contains_local_absolute_path(token) {
        output.push_str("<redacted:local-path>");
    } else {
        output.push_str(token);
    }
}

fn redact_token_like_words(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            push_redacted_token(&mut output, &token);
            token.clear();
            output.push(character);
        }
    }
    push_redacted_token(&mut output, &token);
    output
}

fn push_redacted_token(output: &mut String, token: &str) {
    if token.len() >= 32
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && token.chars().any(|c| c.is_ascii_digit())
    {
        output.push_str("<redacted:token>");
    } else {
        output.push_str(token);
    }
}

fn default_true() -> bool {
    true
}

fn default_max_items() -> usize {
    DEFAULT_MAX_ITEMS
}

fn default_max_repair_attempts() -> usize {
    1
}

fn default_assigned_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("README.md")]
}

fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}

fn default_blocked_terms() -> Vec<String> {
    [
        "api key",
        "credential",
        "cve",
        "exploit",
        "password",
        "private key",
        "secret",
        "security",
        "ssn",
        "token",
        "vulnerability",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}
