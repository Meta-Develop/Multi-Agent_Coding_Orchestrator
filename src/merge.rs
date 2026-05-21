use crate::{
    sync::normalize_repo_relative_path,
    worktree::{normalize_agent_id, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use git2::{Delta, DiffOptions, ErrorCode, Oid, Repository, Status, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_DIFF_SUMMARY_CHAR_LIMIT: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeCollectOptions {
    pub repo: PathBuf,
    pub agent_id: String,
    pub claimed_paths: Vec<PathBuf>,
    pub include_full_diff: bool,
    pub diff_summary_char_limit: usize,
    pub validations: Vec<ValidationReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergePreviewOptions {
    pub collect: MergeCollectOptions,
    pub forces: MergeForceOptions,
    pub require_validation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeApplyOptions {
    pub preview: MergePreviewOptions,
    pub candidate_validation_commands: Vec<CandidateValidationCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateValidationCommand {
    pub command: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeForceOptions {
    pub allow_dirty_primary: bool,
    pub allow_stale_base: bool,
    pub allow_unclaimed_edits: bool,
    pub allow_validation_failures: bool,
    pub allow_apply_conflicts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeCandidate {
    pub metadata: WorktreeMergeMetadata,
    pub claimed_paths: Vec<PathBuf>,
    pub changed_paths: Vec<PathBuf>,
    pub changes: Vec<ChangedPath>,
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub diff: DiffOutput,
    pub validations: Vec<ValidationReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorktreeMergeMetadata {
    pub agent_id: String,
    pub worktree_path: PathBuf,
    pub branch: String,
    pub primary_repo_root: PathBuf,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub base_matches_primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedPath {
    pub path: PathBuf,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Typechange,
    Untracked,
    Conflicted,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiffOutput {
    pub summary: OutputSummary,
    pub full: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValidationReport {
    pub name: String,
    pub status: ValidationStatus,
    pub message: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    NotRun,
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyPreview {
    pub candidate: MergeCandidate,
    pub safety: MergeApplySafety,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplySafety {
    pub dirty_primary: SafetyCheck,
    pub stale_base: SafetyCheck,
    pub apply_check: SafetyCheck,
    pub unclaimed_edits: SafetyCheck,
    pub validation: SafetyCheck,
    pub validation_required: bool,
    pub candidate_validation_commands: Vec<String>,
    pub force_options: MergeForceOptions,
    pub apply_mode: ApplyMode,
    pub readiness: ApplyReadiness,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SafetyCheck {
    pub status: SafetyCheckStatus,
    pub message: Option<String>,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCheckStatus {
    Passed,
    Failed,
    #[default]
    Skipped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyMode {
    #[default]
    None,
    Direct,
    ThreeWay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReadiness {
    pub status: ApplyReadinessStatus,
    pub blockers: Vec<ApplyBlocker>,
    pub forced: Vec<ApplyBlocker>,
    pub details: Vec<ApplyBlockerDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyReadinessStatus {
    Safe,
    Forced,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyBlocker {
    DirtyPrimary,
    StaleBase,
    ApplyCheckFailed,
    UnclaimedEdits,
    ValidationMissing,
    ValidationNotRun,
    ValidationSkipped,
    ValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyBlockerDetail {
    pub kind: ApplyBlocker,
    pub disposition: ApplyBlockerDisposition,
    pub check_status: SafetyCheckStatus,
    pub paths: Vec<PathBuf>,
    pub message: Option<String>,
    pub validation_reports: Vec<ValidationReport>,
    pub validation_commands: Vec<String>,
    pub next_safe_operation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyBlockerDisposition {
    Blocked,
    Forced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyReport {
    pub preview: MergeApplyPreview,
    pub status: MergeApplyReportStatus,
    pub applied: bool,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeApplyReportStatus {
    Applied,
    NothingToApply,
    Blocked,
}

struct GitCommandOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub fn find_agent_worktree(
    manager: &WorktreeManager,
    agent_id: impl AsRef<str>,
) -> Result<WorktreeRecord> {
    let agent_id = normalize_agent_id(agent_id.as_ref())?;
    manager
        .list()?
        .into_iter()
        .find(|record| record.name == agent_id)
        .with_context(|| format!("worktree for agent '{agent_id}' is not registered"))
}

pub fn collect_agent_result(options: MergeCollectOptions) -> Result<MergeCandidate> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let record = find_agent_worktree(&manager, &options.agent_id)?;
    let primary_repo = Repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let agent_repo = Repository::open(&record.path)
        .with_context(|| format!("failed to open agent worktree {}", record.path.display()))?;

    let metadata = collect_metadata(&primary_repo, &agent_repo, &record, repo_root)?;
    let claimed_paths = normalize_claim_paths(options.claimed_paths)?;
    let diff_base = collection_base_oid(&metadata)?;
    let changes = collect_changed_paths(&agent_repo, diff_base)?;
    let changed_paths = changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    let unclaimed_changed_paths = unclaimed_paths(&changed_paths, &claimed_paths);
    let full_diff = collect_full_diff(&record.path, diff_base)?;
    let diff = DiffOutput {
        summary: summarize_text(&full_diff, options.diff_summary_char_limit),
        full: options.include_full_diff.then_some(full_diff),
    };

    Ok(MergeCandidate {
        metadata,
        claimed_paths,
        changed_paths,
        changes,
        unclaimed_changed_paths,
        diff,
        validations: options.validations,
    })
}

pub fn preview_merge_apply(options: MergePreviewOptions) -> Result<MergeApplyPreview> {
    let mut collect = options.collect;
    collect.include_full_diff = true;
    let candidate = collect_agent_result(collect)?;
    let patch = candidate.diff.full.as_deref().unwrap_or_default();
    let candidate_validation_commands = Vec::new();

    let dirty_primary = dirty_primary_check(&candidate.metadata.primary_repo_root)?;
    let stale_base = stale_base_check(&candidate.metadata);
    let unclaimed_edits = unclaimed_edits_check(&candidate.unclaimed_changed_paths);
    let validation = validation_check(&candidate.validations, options.require_validation);
    let (apply_check, apply_mode) = apply_check(
        &candidate.metadata.primary_repo_root,
        patch,
        options.forces.allow_apply_conflicts,
    )?;
    let checks = SafetyChecks {
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validations: &candidate.validations,
        require_validation: options.require_validation,
        validation_commands: &candidate_validation_commands,
        validation_related_paths: &candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &options.forces);

    Ok(MergeApplyPreview {
        candidate,
        safety: MergeApplySafety {
            dirty_primary,
            stale_base,
            apply_check,
            unclaimed_edits,
            validation,
            validation_required: options.require_validation,
            candidate_validation_commands,
            force_options: options.forces,
            apply_mode,
            readiness,
        },
    })
}

pub fn apply_merge_result(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let report = merge_apply_report(options)?;
    if report.status == MergeApplyReportStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&report.preview.safety.readiness.blockers)
        );
    }

    Ok(report)
}

pub fn merge_apply_report(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let mut preview_options = options.preview;
    let require_validation_after_candidate = preview_options.require_validation;
    if !options.candidate_validation_commands.is_empty() {
        preview_options.require_validation = false;
    }
    let preview = preview_merge_apply(preview_options)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        return Ok(blocked_merge_apply_report(preview));
    }

    apply_prechecked_merge_with_candidate_validation(
        preview,
        options.candidate_validation_commands,
        require_validation_after_candidate,
    )
}

pub fn blocked_merge_apply_report(preview: MergeApplyPreview) -> MergeApplyReport {
    let error = if preview.safety.readiness.blockers.is_empty() {
        None
    } else {
        Some(format!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        ))
    };

    MergeApplyReport {
        preview,
        status: MergeApplyReportStatus::Blocked,
        applied: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error,
    }
}

pub fn apply_prechecked_merge(preview: MergeApplyPreview) -> Result<MergeApplyReport> {
    apply_prechecked_merge_with_candidate_validation(preview, Vec::new(), false)
}

pub fn apply_prechecked_merge_with_candidate_validation(
    mut preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
) -> Result<MergeApplyReport> {
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        );
    }

    let patch = preview.candidate.diff.full.as_deref().unwrap_or_default();
    if patch.is_empty() {
        return Ok(MergeApplyReport {
            preview,
            status: MergeApplyReportStatus::NothingToApply,
            applied: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
        });
    }

    if preview.safety.apply_check.status != SafetyCheckStatus::Passed {
        bail!("merge apply refused: git apply check did not pass");
    }

    if !candidate_validation_commands.is_empty() {
        let command_labels = candidate_validation_commands
            .iter()
            .map(|command| command.command.clone())
            .collect::<Vec<_>>();
        let reports = run_candidate_validation_commands(&preview, &candidate_validation_commands)?;
        preview.candidate.validations.extend(reports);
        preview.safety.candidate_validation_commands = command_labels;
        preview.safety.validation_required = true;
        preview.safety.validation = validation_check(&preview.candidate.validations, true);
        let checks = SafetyChecks {
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validations: &preview.candidate.validations,
            require_validation: true,
            validation_commands: &preview.safety.candidate_validation_commands,
            validation_related_paths: &preview.candidate.changed_paths,
        };
        preview.safety.readiness = classify_apply_safety(checks, &preview.safety.force_options);
        if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
            return Ok(blocked_merge_apply_report(preview));
        }
    } else if require_validation_after_candidate {
        preview.safety.validation_required = true;
        preview.safety.validation = validation_check(&preview.candidate.validations, true);
        let checks = SafetyChecks {
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validations: &preview.candidate.validations,
            require_validation: true,
            validation_commands: &preview.safety.candidate_validation_commands,
            validation_related_paths: &preview.candidate.changed_paths,
        };
        preview.safety.readiness = classify_apply_safety(checks, &preview.safety.force_options);
        if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
            return Ok(blocked_merge_apply_report(preview));
        }
    }

    let args = match preview.safety.apply_mode {
        ApplyMode::Direct => vec!["apply", "--binary"],
        ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
        ApplyMode::None => Vec::new(),
    };
    if args.is_empty() {
        return Ok(MergeApplyReport {
            preview,
            status: MergeApplyReportStatus::NothingToApply,
            applied: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
        });
    }

    let output = run_git_with_input(&preview.candidate.metadata.primary_repo_root, &args, patch)
        .context("failed to run git apply")?;
    if !output.success {
        bail!(
            "git apply failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(MergeApplyReport {
        preview,
        status: MergeApplyReportStatus::Applied,
        applied: true,
        stdout: summarize_text(
            &String::from_utf8_lossy(&output.stdout),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        stderr: summarize_text(
            &String::from_utf8_lossy(&output.stderr),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        error: None,
    })
}

pub fn validation_reports_from_json(value: &Value) -> Result<Vec<ValidationReport>> {
    validation_reports_from_json_for_agent(value, None)
}

pub fn validation_reports_from_json_for_agent(
    value: &Value,
    agent_id: Option<&str>,
) -> Result<Vec<ValidationReport>> {
    if let Some(agents) = value.get("agents").and_then(Value::as_array) {
        let mut reports = Vec::new();
        let mut matched_agent = false;
        for agent in agents {
            let candidate_id = agent.get("id").and_then(Value::as_str);
            if agent_id.is_some() && candidate_id != agent_id {
                continue;
            }
            matched_agent = true;
            reports.extend(validation_reports_from_agent_json(agent).with_context(|| {
                match candidate_id {
                    Some(id) => format!("invalid validation reports for agent '{id}'"),
                    None => "invalid validation reports for summary agent".to_string(),
                }
            })?);
        }
        if agent_id.is_some() && !matched_agent {
            let id = agent_id.unwrap_or_default();
            bail!("validation report summary does not contain agent '{id}'");
        }
        sort_validation_reports(&mut reports);
        return Ok(reports);
    }

    let report_values = if let Some(validations) = value.get("validation").and_then(Value::as_array)
    {
        validations
    } else if let Some(validations) = value.get("validations").and_then(Value::as_array) {
        validations
    } else if let Some(reports) = value.get("reports").and_then(Value::as_array) {
        reports
    } else if let Some(array) = value.as_array() {
        array
    } else if value.as_object().is_some() {
        return Ok(vec![validation_report_from_json(value)?]);
    } else {
        bail!("validation report JSON must be an object or array");
    };

    let mut reports = report_values
        .iter()
        .map(validation_report_from_json)
        .collect::<Result<Vec<_>>>()?;
    sort_validation_reports(&mut reports);
    Ok(reports)
}

fn validation_reports_from_agent_json(agent: &Value) -> Result<Vec<ValidationReport>> {
    if agent.get("validation").is_some()
        || agent.get("validations").is_some()
        || agent.get("reports").is_some()
    {
        validation_reports_from_json(agent)
    } else {
        Ok(Vec::new())
    }
}

fn collect_metadata(
    primary_repo: &Repository,
    agent_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
) -> Result<WorktreeMergeMetadata> {
    let primary_head = head_oid(primary_repo).context("failed to read primary HEAD")?;
    let agent_head = head_oid(agent_repo).context("failed to read agent HEAD")?;
    let merge_base = match (primary_head, agent_head) {
        (Some(primary), Some(agent)) => merge_base_oid(primary_repo, primary, agent)?,
        _ => None,
    };
    let base_matches_primary = match (primary_head, merge_base) {
        (Some(primary), Some(base)) => Some(primary == base),
        _ => None,
    };

    Ok(WorktreeMergeMetadata {
        agent_id: record.name.clone(),
        worktree_path: record.path.clone(),
        branch: record.branch.clone(),
        primary_repo_root,
        primary_head: primary_head.map(|oid| oid.to_string()),
        agent_head: agent_head.map(|oid| oid.to_string()),
        merge_base: merge_base.map(|oid| oid.to_string()),
        base_matches_primary,
    })
}

fn collection_base_oid(metadata: &WorktreeMergeMetadata) -> Result<Option<Oid>> {
    metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref())
        .map(|oid| Oid::from_str(oid).context("failed to parse collection base oid"))
        .transpose()
}

fn collect_changed_paths(repo: &Repository, base_oid: Option<Oid>) -> Result<Vec<ChangedPath>> {
    if let Some(base_oid) = base_oid {
        return collect_changed_paths_since_base(repo, base_oid);
    }

    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect git status")?;
    let mut changes = BTreeMap::<PathBuf, ChangeKind>::new();

    for entry in statuses.iter() {
        if let Some(path) = entry.path() {
            changes.insert(PathBuf::from(path), classify_status(entry.status()));
        }
    }

    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn collect_changed_paths_since_base(repo: &Repository, base_oid: Oid) -> Result<Vec<ChangedPath>> {
    let base_commit = repo
        .find_commit(base_oid)
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
    let mut changes = BTreeMap::<PathBuf, ChangeKind>::new();
    diff.foreach(
        &mut |delta, _| {
            collect_delta_changes(delta, &mut changes);
            true
        },
        None,
        None,
        None,
    )
    .context("failed to inspect changed paths")?;

    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn collect_delta_changes(delta: git2::DiffDelta<'_>, changes: &mut BTreeMap<PathBuf, ChangeKind>) {
    let kind = classify_delta(delta.status());
    match delta.status() {
        Delta::Deleted => {
            insert_delta_change(delta.old_file().path(), kind, changes);
        }
        Delta::Renamed | Delta::Copied => {
            insert_delta_change(delta.old_file().path(), kind, changes);
            insert_delta_change(delta.new_file().path(), kind, changes);
        }
        _ => {
            insert_delta_change(delta.new_file().path(), kind, changes);
        }
    }
}

fn insert_delta_change(
    path: Option<&Path>,
    kind: ChangeKind,
    changes: &mut BTreeMap<PathBuf, ChangeKind>,
) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        changes.insert(path.to_path_buf(), kind);
    }
}

fn collect_full_diff(worktree_path: &Path, base_oid: Option<Oid>) -> Result<String> {
    let mut args = vec!["diff", "--binary"];
    let base_arg;
    if let Some(base_oid) = base_oid {
        base_arg = base_oid.to_string();
        args.push(base_arg.as_str());
    } else {
        args.push("HEAD");
    }

    let tracked = run_git_capture(worktree_path, &args).with_context(|| {
        format!(
            "failed to collect tracked diff in {}",
            worktree_path.display()
        )
    })?;
    if !tracked.success {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&tracked.stderr).trim()
        );
    }

    let mut diff = String::from_utf8_lossy(&tracked.stdout).into_owned();
    for path in collect_untracked_paths(worktree_path)? {
        let file_diff = run_git_capture_paths(
            worktree_path,
            &["diff", "--no-index", "--binary", "--"],
            &[Path::new("/dev/null"), &path],
        )
        .with_context(|| format!("failed to collect untracked diff for {}", path.display()))?;
        if !file_diff.success && !is_diff_exit(&file_diff) {
            bail!(
                "git diff --no-index failed for {}: {}",
                path.display(),
                String::from_utf8_lossy(&file_diff.stderr).trim()
            );
        }
        if !diff.is_empty() && !diff.ends_with('\n') {
            diff.push('\n');
        }
        diff.push_str(&String::from_utf8_lossy(&file_diff.stdout));
    }

    Ok(diff)
}

fn collect_untracked_paths(worktree_path: &Path) -> Result<Vec<PathBuf>> {
    let output = run_git_capture(
        worktree_path,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
    .with_context(|| {
        format!(
            "failed to list untracked files in {}",
            worktree_path.display()
        )
    })?;
    if !output.success {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(String::from_utf8_lossy(path).into_owned()))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn dirty_primary_check(repo_root: &Path) -> Result<SafetyCheck> {
    let repo = Repository::open(repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let paths = collect_changed_paths(&repo, None)?
        .into_iter()
        .map(|change| change.path)
        .filter(|path| !is_local_runtime_path(path))
        .collect::<Vec<_>>();

    if paths.is_empty() {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths,
        })
    } else {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("primary worktree has local changes".to_string()),
            paths,
        })
    }
}

fn is_local_runtime_path(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(std::path::Component::Normal(name))
            if name == OsStr::new(".maco") || name == OsStr::new(".maco-cache")
    )
}

fn stale_base_check(metadata: &WorktreeMergeMetadata) -> SafetyCheck {
    match metadata.base_matches_primary {
        Some(true) => SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        },
        Some(false) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent base is stale relative to primary HEAD".to_string()),
            paths: Vec::new(),
        },
        None => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn unclaimed_edits_check(paths: &[PathBuf]) -> SafetyCheck {
    if paths.is_empty() {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent changed paths outside its claims".to_string()),
            paths: paths.to_vec(),
        }
    }
}

fn validation_check(validations: &[ValidationReport], require_validation: bool) -> SafetyCheck {
    let failed = failed_validation_paths(validations);

    if !failed.is_empty() {
        return SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("one or more validation checks failed".to_string()),
            paths: failed,
        };
    }
    if require_validation {
        if validations.is_empty() {
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some("required validation evidence was not supplied".to_string()),
                paths: Vec::new(),
            };
        }
        if validations
            .iter()
            .all(|validation| validation.status != ValidationStatus::Passed)
        {
            let message = if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::NotRun)
            {
                "required validation evidence has not run"
            } else if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::Skipped)
            {
                "required validation evidence was skipped"
            } else {
                "required validation evidence has no passing checks"
            };
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(message.to_string()),
                paths: failed_validation_paths(validations),
            };
        }
    }
    if validations
        .iter()
        .any(|validation| validation.status == ValidationStatus::Passed)
    {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("no passing validation checks were supplied".to_string()),
            paths: Vec::new(),
        }
    }
}

fn failed_validation_paths(validations: &[ValidationReport]) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    let mut failed_without_paths = Vec::new();

    for validation in validations
        .iter()
        .filter(|validation| validation.status == ValidationStatus::Failed)
    {
        if validation.paths.is_empty() {
            failed_without_paths.push(PathBuf::from(&validation.name));
        } else {
            paths.extend(validation.paths.iter().cloned());
        }
    }

    if paths.is_empty() {
        failed_without_paths.sort();
        failed_without_paths.dedup();
        return failed_without_paths;
    }

    paths.into_iter().collect()
}

fn apply_check(
    repo_root: &Path,
    patch: &str,
    allow_apply_conflicts: bool,
) -> Result<(SafetyCheck, ApplyMode)> {
    if patch.is_empty() {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Skipped,
                message: Some("candidate has no diff to apply".to_string()),
                paths: Vec::new(),
            },
            ApplyMode::None,
        ));
    }

    let direct = run_git_with_input(repo_root, &["apply", "--check", "--binary"], patch)
        .context("failed to run git apply --check")?;
    let direct_stderr = git_stderr_text(&direct);
    let direct_paths = parse_git_apply_error_paths(&direct_stderr);
    if direct.success {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Passed,
                message: None,
                paths: Vec::new(),
            },
            ApplyMode::Direct,
        ));
    }

    if allow_apply_conflicts {
        let three_way = run_git_with_input(
            repo_root,
            &["apply", "--3way", "--check", "--binary"],
            patch,
        )
        .context("failed to run git apply --3way --check")?;
        let three_way_stderr = git_stderr_text(&three_way);
        let paths = merge_path_sets(
            &direct_paths,
            &parse_git_apply_error_paths(&three_way_stderr),
        );
        if three_way.success {
            return Ok((
                SafetyCheck {
                    status: SafetyCheckStatus::Passed,
                    message: Some(
                        "direct apply check failed; three-way apply check passed".to_string(),
                    ),
                    paths,
                },
                ApplyMode::ThreeWay,
            ));
        }

        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(format!(
                    "direct check failed: {}; three-way check failed: {}",
                    direct_stderr.trim(),
                    three_way_stderr.trim()
                )),
                paths,
            },
            ApplyMode::None,
        ));
    }

    Ok((
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(direct_stderr.trim().to_string()),
            paths: direct_paths,
        },
        ApplyMode::None,
    ))
}

fn run_candidate_validation_commands(
    preview: &MergeApplyPreview,
    commands: &[CandidateValidationCommand],
) -> Result<Vec<ValidationReport>> {
    let sandbox = CandidateValidationSandbox::create(preview)?;
    let mut reports = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        reports.push(run_candidate_validation_command(
            sandbox.path(),
            command,
            index,
            &preview.candidate.changed_paths,
        ));
    }
    Ok(reports)
}

struct CandidateValidationSandbox {
    primary_repo_root: PathBuf,
    path: PathBuf,
}

impl CandidateValidationSandbox {
    fn create(preview: &MergeApplyPreview) -> Result<Self> {
        let primary_repo_root = preview.candidate.metadata.primary_repo_root.clone();
        let path = candidate_validation_sandbox_path(&primary_repo_root)?;
        let add_output = Command::new("git")
            .arg("-C")
            .arg(&primary_repo_root)
            .args(["worktree", "add", "--detach", "--force"])
            .arg(&path)
            .arg("HEAD")
            .output()
            .with_context(|| {
                format!(
                    "failed to create candidate validation worktree {}",
                    path.display()
                )
            })?;
        if !add_output.status.success() {
            bail!(
                "failed to create candidate validation worktree: {}",
                String::from_utf8_lossy(&add_output.stderr).trim()
            );
        }

        let patch = preview.candidate.diff.full.as_deref().unwrap_or_default();
        let args = match preview.safety.apply_mode {
            ApplyMode::Direct => vec!["apply", "--binary"],
            ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
            ApplyMode::None => Vec::new(),
        };
        if !args.is_empty() {
            let apply_output = run_git_with_input(&path, &args, patch)
                .context("failed to apply candidate patch to validation worktree")?;
            if !apply_output.success {
                bail!(
                    "failed to apply candidate patch to validation worktree: {}",
                    String::from_utf8_lossy(&apply_output.stderr).trim()
                );
            }
        }

        Ok(Self {
            primary_repo_root,
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CandidateValidationSandbox {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.primary_repo_root)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .output();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn candidate_validation_sandbox_path(primary_repo_root: &Path) -> Result<PathBuf> {
    let repo_name = primary_repo_root
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("repo");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_nanos();
    Ok(env::temp_dir().join(format!(
        "maco-candidate-validation-{repo_name}-{}-{nanos}",
        std::process::id()
    )))
}

fn run_candidate_validation_command(
    worktree_path: &Path,
    validation: &CandidateValidationCommand,
    index: usize,
    changed_paths: &[PathBuf],
) -> ValidationReport {
    let output = shell_command(&validation.command)
        .current_dir(worktree_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) => {
            let passed = output.status.success();
            ValidationReport {
                name: format!("candidate validation {}", index + 1),
                status: if passed {
                    ValidationStatus::Passed
                } else {
                    ValidationStatus::Failed
                },
                message: candidate_validation_message(&output),
                paths: if passed {
                    Vec::new()
                } else {
                    changed_paths.to_vec()
                },
            }
        }
        Err(error) => ValidationReport {
            name: format!("candidate validation {}", index + 1),
            status: ValidationStatus::Failed,
            message: Some(format!("failed to run validation command: {error}")),
            paths: changed_paths.to_vec(),
        },
    }
}

fn candidate_validation_message(output: &std::process::Output) -> Option<String> {
    if output.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let text = if !stderr.trim().is_empty() {
        stderr.trim()
    } else if !stdout.trim().is_empty() {
        stdout.trim()
    } else {
        "candidate validation command failed"
    };
    let exit = output
        .status
        .code()
        .map(|code| format!("exited with status {code}"))
        .unwrap_or_else(|| "terminated without an exit code".to_string());
    Some(format!("{exit}: {}", summarize_text(text, 1024).text))
}

struct SafetyChecks<'a> {
    dirty_primary: &'a SafetyCheck,
    stale_base: &'a SafetyCheck,
    apply_check: &'a SafetyCheck,
    unclaimed_edits: &'a SafetyCheck,
    validation: &'a SafetyCheck,
    validations: &'a [ValidationReport],
    require_validation: bool,
    validation_commands: &'a [String],
    validation_related_paths: &'a [PathBuf],
}

fn classify_apply_safety(checks: SafetyChecks<'_>, forces: &MergeForceOptions) -> ApplyReadiness {
    let candidates = [
        (
            checks.dirty_primary,
            ApplyBlocker::DirtyPrimary,
            forces.allow_dirty_primary,
        ),
        (
            checks.stale_base,
            ApplyBlocker::StaleBase,
            forces.allow_stale_base,
        ),
        (checks.apply_check, ApplyBlocker::ApplyCheckFailed, false),
        (
            checks.unclaimed_edits,
            ApplyBlocker::UnclaimedEdits,
            forces.allow_unclaimed_edits,
        ),
    ];
    let mut blockers = Vec::new();
    let mut forced = Vec::new();
    let mut details = Vec::new();

    for (check, blocker, force_allowed) in candidates {
        if check.status != SafetyCheckStatus::Failed {
            continue;
        }
        let disposition = if force_allowed {
            forced.push(blocker);
            ApplyBlockerDisposition::Forced
        } else {
            blockers.push(blocker);
            ApplyBlockerDisposition::Blocked
        };
        details.push(ApplyBlockerDetail {
            kind: blocker,
            disposition,
            check_status: check.status,
            paths: check.paths.clone(),
            message: check.message.clone(),
            validation_reports: Vec::new(),
            validation_commands: Vec::new(),
            next_safe_operation: None,
        });
    }

    for detail in validation_blocker_details(&checks, forces) {
        match detail.disposition {
            ApplyBlockerDisposition::Blocked => blockers.push(detail.kind),
            ApplyBlockerDisposition::Forced => forced.push(detail.kind),
        }
        details.push(detail);
    }

    let status = if !blockers.is_empty() {
        ApplyReadinessStatus::Blocked
    } else if !forced.is_empty() {
        ApplyReadinessStatus::Forced
    } else {
        ApplyReadinessStatus::Safe
    };

    ApplyReadiness {
        status,
        blockers,
        forced,
        details,
    }
}

fn validation_blocker_details(
    checks: &SafetyChecks<'_>,
    forces: &MergeForceOptions,
) -> Vec<ApplyBlockerDetail> {
    if checks.validation.status != SafetyCheckStatus::Failed {
        return Vec::new();
    }

    let mut details = Vec::new();
    let failed = reports_with_status(checks.validations, ValidationStatus::Failed);
    if !failed.is_empty() {
        details.push(validation_blocker_detail(
            ApplyBlocker::ValidationFailed,
            checks,
            failed,
            !checks.require_validation && forces.allow_validation_failures,
            "run the failing validation command again after fixing the reported paths",
        ));
    }

    if checks.require_validation {
        if checks.validations.is_empty() {
            details.push(validation_blocker_detail(
                ApplyBlocker::ValidationMissing,
                checks,
                Vec::new(),
                false,
                "supply --validation-report with at least one passed check or run merge apply --validation-command <command>",
            ));
            return details;
        }

        if !checks
            .validations
            .iter()
            .any(|validation| validation.status == ValidationStatus::Passed)
        {
            let not_run = reports_with_status(checks.validations, ValidationStatus::NotRun);
            if !not_run.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationNotRun,
                    checks,
                    not_run,
                    false,
                    "run the pending validation command and provide a passed validation report",
                ));
            }
            let skipped = reports_with_status(checks.validations, ValidationStatus::Skipped);
            if !skipped.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationSkipped,
                    checks,
                    skipped,
                    false,
                    "run the skipped validation command and provide a passed validation report",
                ));
            }
            if details.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationMissing,
                    checks,
                    checks.validations.to_vec(),
                    false,
                    "provide at least one passed validation report",
                ));
            }
        }
    }

    details
}

fn validation_blocker_detail(
    kind: ApplyBlocker,
    checks: &SafetyChecks<'_>,
    reports: Vec<ValidationReport>,
    force_allowed: bool,
    next_safe_operation: &str,
) -> ApplyBlockerDetail {
    let paths = validation_detail_paths(&reports, checks.validation_related_paths);
    ApplyBlockerDetail {
        kind,
        disposition: if force_allowed {
            ApplyBlockerDisposition::Forced
        } else {
            ApplyBlockerDisposition::Blocked
        },
        check_status: checks.validation.status,
        paths,
        message: checks.validation.message.clone(),
        validation_reports: reports,
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    }
}

fn validation_detail_paths(
    reports: &[ValidationReport],
    validation_related_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut paths = reports
        .iter()
        .flat_map(|report| report.paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    if paths.is_empty() {
        paths.extend(validation_related_paths.iter().cloned());
    }
    paths.into_iter().collect()
}

fn reports_with_status(
    validations: &[ValidationReport],
    status: ValidationStatus,
) -> Vec<ValidationReport> {
    validations
        .iter()
        .filter(|validation| validation.status == status)
        .cloned()
        .collect()
}

fn unclaimed_paths(changed_paths: &[PathBuf], claimed_paths: &[PathBuf]) -> Vec<PathBuf> {
    changed_paths
        .iter()
        .filter(|path| {
            !claimed_paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect()
}

fn normalize_claim_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
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

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn classify_status(status: Status) -> ChangeKind {
    if status.contains(Status::CONFLICTED) {
        ChangeKind::Conflicted
    } else if status.contains(Status::WT_NEW) {
        ChangeKind::Untracked
    } else if status.contains(Status::INDEX_RENAMED) || status.contains(Status::WT_RENAMED) {
        ChangeKind::Renamed
    } else if status.contains(Status::INDEX_DELETED) || status.contains(Status::WT_DELETED) {
        ChangeKind::Deleted
    } else if status.contains(Status::INDEX_NEW) {
        ChangeKind::Added
    } else if status.contains(Status::INDEX_TYPECHANGE) || status.contains(Status::WT_TYPECHANGE) {
        ChangeKind::Typechange
    } else if status.contains(Status::INDEX_MODIFIED) || status.contains(Status::WT_MODIFIED) {
        ChangeKind::Modified
    } else {
        ChangeKind::Unknown
    }
}

fn classify_delta(delta: Delta) -> ChangeKind {
    match delta {
        Delta::Added => ChangeKind::Added,
        Delta::Modified => ChangeKind::Modified,
        Delta::Deleted => ChangeKind::Deleted,
        Delta::Renamed | Delta::Copied => ChangeKind::Renamed,
        Delta::Typechange => ChangeKind::Typechange,
        Delta::Untracked => ChangeKind::Untracked,
        Delta::Conflicted => ChangeKind::Conflicted,
        _ => ChangeKind::Unknown,
    }
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn head_oid(repo: &Repository) -> Result<Option<Oid>, git2::Error> {
    match repo.head() {
        Ok(head) => head.peel_to_commit().map(|commit| Some(commit.id())),
        Err(error) if error.code() == ErrorCode::UnbornBranch => Ok(None),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn merge_base_oid(repo: &Repository, primary: Oid, agent: Oid) -> Result<Option<Oid>> {
    match repo.merge_base(primary, agent) {
        Ok(oid) => Ok(Some(oid)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to compute merge base"),
    }
}

fn discover_primary_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("merge operations require a non-bare primary repository")
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Result<GitCommandOutput> {
    run_git_capture_paths(repo_root, args, &[])
}

fn run_git_capture_paths(
    repo_root: &Path,
    args: &[&str],
    path_args: &[&Path],
) -> Result<GitCommandOutput> {
    let mut command = git_command(repo_root, args);
    for path in path_args {
        command.arg(path);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run git in {}", repo_root.display()))?;

    Ok(GitCommandOutput {
        success: output.status.success(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn run_git_with_input(repo_root: &Path, args: &[&str], input: &str) -> Result<GitCommandOutput> {
    let mut child = git_command(repo_root, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start git in {}", repo_root.display()))?;

    let mut stdin = child
        .stdin
        .take()
        .context("failed to open git stdin for patch input")?;
    stdin
        .write_all(input.as_bytes())
        .context("failed to write patch to git stdin")?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .context("failed waiting for git command")?;
    Ok(GitCommandOutput {
        success: output.status.success(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn git_command(repo_root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo_root).args(args);
    command
}

fn shell_command(command_text: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(command_text);
        command
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(command_text);
        command
    }
}

fn is_diff_exit(output: &GitCommandOutput) -> bool {
    !output.stdout.is_empty()
}

fn format_blockers(blockers: &[ApplyBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| blocker_label(*blocker))
        .collect::<Vec<_>>()
        .join(", ")
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

fn git_stderr_text(output: &GitCommandOutput) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn merge_path_sets(left: &[PathBuf], right: &[PathBuf]) -> Vec<PathBuf> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_git_apply_error_paths(stderr: &str) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in stderr.lines().map(str::trim) {
        if let Some(path) = parse_patch_failed_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_error_suffix_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_quoted_error_path(line, "error: invalid path ") {
            paths.insert(path);
        }
    }
    paths.into_iter().collect()
}

fn parse_patch_failed_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: patch failed: ")?;
    let (path, line_number) = rest.rsplit_once(':')?;
    if line_number.chars().all(|c| c.is_ascii_digit()) && !path.is_empty() {
        Some(PathBuf::from(path))
    } else {
        None
    }
}

fn parse_error_suffix_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: ")?;
    const SUFFIXES: [&str; 8] = [
        ": patch does not apply",
        ": already exists in working directory",
        ": already exists in index",
        ": does not exist in index",
        ": No such file or directory",
        ": does not match index",
        ": cannot checkout",
        ": needs merge",
    ];
    SUFFIXES
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn parse_quoted_error_path(line: &str, prefix: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix(prefix)?;
    let path = rest.strip_prefix('\'')?.strip_suffix('\'')?;
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn validation_report_from_json(value: &Value) -> Result<ValidationReport> {
    let object = value
        .as_object()
        .context("validation report must be an object")?;
    let name = ["name", "command", "id"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .unwrap_or("validation")
        .to_string();
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map(parse_validation_status)
        .transpose()?
        .unwrap_or(ValidationStatus::NotRun);
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| object.get("error").and_then(Value::as_str))
        .or_else(|| {
            object
                .get("stderr")
                .and_then(|stderr| stderr.get("text"))
                .and_then(Value::as_str)
        })
        .filter(|message| !message.is_empty())
        .map(str::to_string);
    let paths = validation_paths_from_json(value)?;

    Ok(ValidationReport {
        name,
        status,
        message,
        paths,
    })
}

fn parse_validation_status(value: &str) -> Result<ValidationStatus> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "not_run" | "not-run" | "pending" => Ok(ValidationStatus::NotRun),
        "passed" | "pass" | "succeeded" | "success" => Ok(ValidationStatus::Passed),
        "failed" | "fail" | "failure" => Ok(ValidationStatus::Failed),
        "skipped" | "skip" => Ok(ValidationStatus::Skipped),
        other => bail!("unknown validation status '{other}'"),
    }
}

fn validation_paths_from_json(value: &Value) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    if let Some(path) = value.get("path").and_then(Value::as_str) {
        paths.insert(PathBuf::from(path));
    }
    if let Some(items) = value.get("paths").and_then(Value::as_array) {
        for item in items {
            let path = item
                .as_str()
                .context("validation report paths must be strings")?;
            paths.insert(PathBuf::from(path));
        }
    }

    Ok(paths.into_iter().collect())
}

fn sort_validation_reports(reports: &mut [ValidationReport]) {
    reports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.paths.cmp(&right.paths))
            .then_with(|| left.message.cmp(&right.message))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_unclaimed_paths_by_repo_relative_claim_coverage() {
        let changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src/nested/mod.rs"),
            PathBuf::from("tests/smoke.rs"),
        ];
        let claims = vec![PathBuf::from("README.md"), PathBuf::from("src")];

        assert_eq!(
            unclaimed_paths(&changed, &claims),
            vec![PathBuf::from("tests/smoke.rs")]
        );
    }

    #[test]
    fn normalizes_and_collapses_claim_paths() {
        let paths = normalize_claim_paths(vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src"),
            PathBuf::from("README.md"),
            PathBuf::from("src/../README.md"),
        ])
        .expect("normalize paths");

        assert_eq!(
            paths,
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );
    }

    #[test]
    fn safety_classification_blocks_unforced_failures() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: vec![PathBuf::from("README.md")],
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let checks = SafetyChecks {
            dirty_primary: &failed,
            stale_base: &passed,
            apply_check: &passed,
            unclaimed_edits: &failed,
            validation: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(checks, &MergeForceOptions::default());

        assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
        assert_eq!(
            readiness.blockers,
            vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::UnclaimedEdits]
        );
        assert!(readiness.forced.is_empty());
        assert_eq!(readiness.details.len(), 2);
        assert_eq!(readiness.details[0].kind, ApplyBlocker::DirtyPrimary);
        assert_eq!(
            readiness.details[0].disposition,
            ApplyBlockerDisposition::Blocked
        );
        assert_eq!(readiness.details[0].check_status, SafetyCheckStatus::Failed);
        assert_eq!(readiness.details[0].paths, vec![PathBuf::from("README.md")]);
    }

    #[test]
    fn safety_classification_marks_allowed_risks_as_forced() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: Vec::new(),
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let checks = SafetyChecks {
            dirty_primary: &failed,
            stale_base: &failed,
            apply_check: &passed,
            unclaimed_edits: &passed,
            validation: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(
            checks,
            &MergeForceOptions {
                allow_dirty_primary: true,
                allow_stale_base: true,
                ..MergeForceOptions::default()
            },
        );

        assert_eq!(readiness.status, ApplyReadinessStatus::Forced);
        assert!(readiness.blockers.is_empty());
        assert_eq!(
            readiness.forced,
            vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::StaleBase]
        );
        assert_eq!(
            readiness.details[0].disposition,
            ApplyBlockerDisposition::Forced
        );
    }

    #[test]
    fn apply_check_failures_are_not_forceable_by_policy_flags() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: Vec::new(),
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let checks = SafetyChecks {
            dirty_primary: &passed,
            stale_base: &passed,
            apply_check: &failed,
            unclaimed_edits: &passed,
            validation: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(
            checks,
            &MergeForceOptions {
                allow_apply_conflicts: true,
                ..MergeForceOptions::default()
            },
        );

        assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
        assert_eq!(readiness.blockers, vec![ApplyBlocker::ApplyCheckFailed]);
    }

    #[test]
    fn truncates_output_by_char_boundary() {
        let summary = summarize_text("aé日b", 3);

        assert_eq!(summary.text, "aé日");
        assert!(summary.truncated);

        let untruncated = summarize_text("abc", 3);
        assert_eq!(untruncated.text, "abc");
        assert!(!untruncated.truncated);
    }

    #[test]
    fn parses_git_apply_paths_from_standard_errors() {
        let stderr = "\
error: patch failed: README.md:1
error: README.md: patch does not apply
error: src/lib.rs: does not match index
";

        assert_eq!(
            parse_git_apply_error_paths(stderr),
            vec![PathBuf::from("README.md"), PathBuf::from("src/lib.rs")]
        );
    }

    #[test]
    fn validation_reports_accept_external_and_summary_shapes() {
        let value = serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "validation": [
                        {
                            "name": "unit",
                            "status": "failed",
                            "message": "tests failed",
                            "paths": ["src/lib.rs"]
                        }
                    ]
                },
                {
                    "id": "agent-b",
                    "validation": [
                        {"name": "fmt", "status": "succeeded"}
                    ]
                }
            ]
        });

        let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
            .expect("parse agent validation reports");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].name, "unit");
        assert_eq!(reports[0].status, ValidationStatus::Failed);
        assert_eq!(reports[0].message.as_deref(), Some("tests failed"));
        assert_eq!(reports[0].paths, vec![PathBuf::from("src/lib.rs")]);
    }

    #[test]
    fn validation_reports_do_not_treat_agent_summary_as_validation() {
        let value = serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "paths": ["README.md"],
                    "command": "cargo test",
                    "status": "succeeded"
                }
            ]
        });

        let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
            .expect("parse empty validation reports");

        assert!(reports.is_empty());
    }

    #[test]
    fn validation_check_uses_explicit_paths_for_failures() {
        let validation = validation_check(
            &[ValidationReport {
                name: "unit".to_string(),
                status: ValidationStatus::Failed,
                message: Some("failed".to_string()),
                paths: vec![PathBuf::from("src/lib.rs")],
            }],
            false,
        );

        assert_eq!(validation.status, SafetyCheckStatus::Failed);
        assert_eq!(validation.paths, vec![PathBuf::from("src/lib.rs")]);
    }
}
