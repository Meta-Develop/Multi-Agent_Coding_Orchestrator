use crate::{
    sync::normalize_repo_relative_path,
    worktree::{normalize_agent_id, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use git2::{ErrorCode, ObjectType, Oid, Repository, Status, StatusOptions};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fmt::Write as FmtWrite,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_DIFF_SUMMARY_CHAR_LIMIT: usize = 32 * 1024;
pub const VALIDATION_BINDING_VERSION: u32 = 1;
const CANDIDATE_CAPTURE_ATTEMPTS: usize = 3;
const LOCK_RECORD_VERSION: u32 = 3;
const REPOSITORY_MUTATION_LOCK_FILE: &str = "repository-mutation.lock";
const MAX_LOCK_RECORD_BYTES: u64 = 4 * 1024;
const VALIDATION_RAW_MAX_ENTRIES: usize = 8 * 1024;
const VALIDATION_RAW_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const VALIDATION_RAW_MAX_SINGLE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const VALIDATION_MARKER_MAX_BYTES: u64 = 64 * 1024;

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
    #[serde(serialize_with = "serialize_paths")]
    pub claimed_paths: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub changed_paths: Vec<PathBuf>,
    pub changes: Vec<ChangedPath>,
    #[serde(serialize_with = "serialize_paths")]
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub diff: DiffOutput,
    pub validations: Vec<ValidationReport>,
    pub validation_binding: CandidateValidationBinding,
    #[serde(skip_serializing)]
    pub validation_evidence: ValidationEvidenceBundle,
    #[serde(skip_serializing)]
    pub(crate) raw_diff: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorktreeMergeMetadata {
    pub agent_id: String,
    #[serde(serialize_with = "serialize_path")]
    pub worktree_path: PathBuf,
    pub branch: String,
    #[serde(serialize_with = "serialize_path")]
    pub primary_repo_root: PathBuf,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub base_matches_primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedPath {
    #[serde(serialize_with = "serialize_path")]
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
    #[serde(default, serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateValidationBinding {
    pub version: u32,
    pub agent_id: String,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub diff_oid: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationEvidenceBundle {
    groups: Vec<ValidationEvidenceGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationEvidenceGroup {
    binding: Option<CandidateValidationBinding>,
    reports: Vec<ValidationReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    NotRun,
    Passed,
    Failed,
    Skipped,
}

impl CandidateValidationBinding {
    fn canonicalized(mut self) -> Result<Self> {
        if self.version != VALIDATION_BINDING_VERSION {
            bail!(
                "unsupported validation binding version {}; expected {}",
                self.version,
                VALIDATION_BINDING_VERSION
            );
        }
        let normalized_agent = normalize_agent_id(&self.agent_id)
            .context("validation binding has an invalid agent_id")?;
        if normalized_agent != self.agent_id {
            bail!("validation binding agent_id must be canonical");
        }
        self.primary_head = canonical_optional_oid(self.primary_head, "primary_head")?;
        self.agent_head = canonical_optional_oid(self.agent_head, "agent_head")?;
        self.merge_base = canonical_optional_oid(self.merge_base, "merge_base")?;
        self.diff_oid = canonical_oid(&self.diff_oid, "diff_oid")?;
        Ok(self)
    }
}

impl ValidationEvidenceBundle {
    pub fn legacy(reports: Vec<ValidationReport>) -> Self {
        if reports.is_empty() {
            Self::default()
        } else {
            Self {
                groups: vec![ValidationEvidenceGroup {
                    binding: None,
                    reports,
                }],
            }
        }
    }

    pub fn reports(&self) -> Vec<ValidationReport> {
        let mut reports = self
            .groups
            .iter()
            .flat_map(|group| group.reports.iter().cloned())
            .collect::<Vec<_>>();
        sort_validation_reports(&mut reports);
        reports
    }

    pub fn extend(&mut self, mut other: Self) {
        self.groups.append(&mut other.groups);
    }

    fn push_bound_reports(
        &mut self,
        binding: CandidateValidationBinding,
        reports: Vec<ValidationReport>,
    ) {
        if reports.is_empty() {
            return;
        }
        self.groups.push(ValidationEvidenceGroup {
            binding: Some(binding),
            reports,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyPreview {
    pub candidate: MergeCandidate,
    pub safety: MergeApplySafety,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplySafety {
    pub primary_state_unchanged: SafetyCheck,
    pub dirty_primary: SafetyCheck,
    pub stale_base: SafetyCheck,
    pub apply_check: SafetyCheck,
    pub unclaimed_edits: SafetyCheck,
    pub validation: SafetyCheck,
    pub validation_evidence: ValidationEvidenceCheck,
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
    #[serde(serialize_with = "serialize_paths")]
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
pub struct ValidationEvidenceCheck {
    pub status: SafetyCheckStatus,
    pub binding_status: ValidationBindingStatus,
    pub message: Option<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationBindingStatus {
    NotRequired,
    NoPassedReport,
    Bound,
    Unbound,
    Mismatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyBlockerDetail {
    pub kind: ApplyBlocker,
    pub disposition: ApplyBlockerDisposition,
    pub check_status: SafetyCheckStatus,
    #[serde(serialize_with = "serialize_paths")]
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

pub(crate) struct RepoCommonLock {
    file: fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RepoLockOwner {
    version: u32,
    pid: u32,
    nonce: String,
    created_unix_seconds: u64,
    operation: String,
    process_start: Option<ProcessStartIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ProcessStartIdentity {
    #[cfg(target_os = "linux")]
    LinuxProcStartTicks(u64),
    #[cfg(target_os = "windows")]
    WindowsCreationFiletime(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateBoundaryState {
    primary_head: Option<Oid>,
    agent_head: Option<Oid>,
    index_digest: Option<Oid>,
    worktree_status: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateRepositorySnapshot {
    metadata: WorktreeMergeMetadata,
    index_digest: Option<Oid>,
    worktree_status: Vec<u8>,
    snapshot_tree: Oid,
    changes: Vec<ChangedPath>,
    raw_diff: Vec<u8>,
}

struct TemporaryIndex {
    directory: PathBuf,
    path: PathBuf,
    object_directory: PathBuf,
    alternate_object_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedWorktreeTree {
    oid: Oid,
    changes: Vec<ChangedPath>,
    raw_diff: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrimaryRepositoryState {
    head: Option<Oid>,
    index_digest: Option<Oid>,
    worktree_digest: Oid,
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
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    collect_agent_result_with_evidence(options, evidence)
}

fn collect_agent_result_with_evidence(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeCandidate> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let record = find_agent_worktree(&manager, &options.agent_id)?;
    let primary_repo = Repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let agent_repo = Repository::open(&record.path)
        .with_context(|| format!("failed to open agent worktree {}", record.path.display()))?;

    let claimed_paths = normalize_claim_paths(options.claimed_paths)?;
    let snapshot =
        capture_consistent_candidate_snapshot(&primary_repo, &agent_repo, &record, repo_root)?;
    let metadata = snapshot.metadata;
    let changes = snapshot.changes;
    let changed_paths = changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    let unclaimed_changed_paths = unclaimed_paths(&changed_paths, &claimed_paths);
    let raw_diff = snapshot.raw_diff;
    let presented_diff = patch_text_for_json(&raw_diff);
    let validation_binding = candidate_validation_binding(&metadata, &raw_diff)?;
    let validations = validation_evidence.reports();
    let diff = DiffOutput {
        summary: summarize_text(&presented_diff, options.diff_summary_char_limit),
        full: options.include_full_diff.then_some(presented_diff),
    };

    Ok(MergeCandidate {
        metadata,
        claimed_paths,
        changed_paths,
        changes,
        unclaimed_changed_paths,
        diff,
        validations,
        validation_binding,
        validation_evidence,
        raw_diff,
    })
}

pub fn preview_merge_apply(options: MergePreviewOptions) -> Result<MergeApplyPreview> {
    let evidence = ValidationEvidenceBundle::legacy(options.collect.validations.clone());
    preview_merge_apply_with_evidence(options, evidence)
}

pub fn preview_merge_apply_with_evidence(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyPreview> {
    let mut collect = options.collect;
    collect.include_full_diff = true;
    let candidate = collect_agent_result_with_evidence(collect, validation_evidence)?;
    let patch = candidate.raw_diff.as_slice();
    let candidate_validation_commands = Vec::new();

    let primary_state_unchanged = passed_safety_check();
    let dirty_primary = dirty_primary_check(&candidate.metadata.primary_repo_root)?;
    let stale_base = stale_base_check(&candidate.metadata);
    let unclaimed_edits = unclaimed_edits_check(&candidate.unclaimed_changed_paths);
    let validation = validation_check(&candidate.validations, options.require_validation);
    let validation_evidence = validation_evidence_check(
        &candidate.validation_evidence,
        &candidate.validation_binding,
        options.require_validation,
        &candidate.changed_paths,
    );
    let (apply_check, apply_mode) = apply_check(
        &candidate.metadata.primary_repo_root,
        patch,
        options.forces.allow_apply_conflicts,
    )?;
    let checks = SafetyChecks {
        primary_state_unchanged: &primary_state_unchanged,
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validation_evidence: &validation_evidence,
        validations: &candidate.validations,
        require_validation: options.require_validation,
        validation_commands: &candidate_validation_commands,
        validation_related_paths: &candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &options.forces);

    Ok(MergeApplyPreview {
        candidate,
        safety: MergeApplySafety {
            primary_state_unchanged,
            dirty_primary,
            stale_base,
            apply_check,
            unclaimed_edits,
            validation,
            validation_evidence,
            validation_required: options.require_validation,
            candidate_validation_commands,
            force_options: options.forces,
            apply_mode,
            readiness,
        },
    })
}

pub fn apply_merge_result(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.preview.collect.validations.clone());
    apply_merge_result_with_evidence(options, evidence)
}

pub fn apply_merge_result_with_evidence(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    let report = merge_apply_report_with_evidence(options, validation_evidence)?;
    if report.status == MergeApplyReportStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&report.preview.safety.readiness.blockers)
        );
    }

    Ok(report)
}

pub fn merge_apply_report(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.preview.collect.validations.clone());
    merge_apply_report_with_evidence(options, evidence)
}

pub fn merge_apply_report_with_evidence(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    let repo_root = discover_primary_repo_root(&options.preview.collect.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "merge-apply")?;
    let mut preview_options = options.preview;
    let require_validation_after_candidate = preview_options.require_validation;
    if !options.candidate_validation_commands.is_empty() {
        preview_options.require_validation = false;
    }
    let preview = preview_merge_apply_with_evidence(preview_options, validation_evidence)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        return Ok(blocked_merge_apply_report(preview));
    }
    let expected_primary_state = PrimaryRepositoryState::capture(&repo_root)?;

    apply_prechecked_merge_with_candidate_validation_locked(
        preview,
        options.candidate_validation_commands,
        require_validation_after_candidate,
        &expected_primary_state,
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
    preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
) -> Result<MergeApplyReport> {
    let repo_root = preview.candidate.metadata.primary_repo_root.clone();
    let _lock = RepoCommonLock::acquire(&repo_root, "merge-apply")?;
    let expected_primary_state = PrimaryRepositoryState::capture(&repo_root)?;
    apply_prechecked_merge_with_candidate_validation_locked(
        preview,
        candidate_validation_commands,
        require_validation_after_candidate,
        &expected_primary_state,
    )
}

fn apply_prechecked_merge_with_candidate_validation_locked(
    mut preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
    expected_primary_state: &PrimaryRepositoryState,
) -> Result<MergeApplyReport> {
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        );
    }

    let patch = preview.candidate.raw_diff.clone();
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
        preview.candidate.validation_evidence.push_bound_reports(
            preview.candidate.validation_binding.clone(),
            reports.clone(),
        );
        preview.candidate.validations.extend(reports);
        preview.safety.candidate_validation_commands = command_labels;
        preview.safety.validation_required = true;
        preview.safety.validation = validation_check(&preview.candidate.validations, true);
        preview.safety.validation_evidence = validation_evidence_check(
            &preview.candidate.validation_evidence,
            &preview.candidate.validation_binding,
            true,
            &preview.candidate.changed_paths,
        );
        let checks = SafetyChecks {
            primary_state_unchanged: &preview.safety.primary_state_unchanged,
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validation_evidence: &preview.safety.validation_evidence,
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
        preview.safety.validation_evidence = validation_evidence_check(
            &preview.candidate.validation_evidence,
            &preview.candidate.validation_binding,
            true,
            &preview.candidate.changed_paths,
        );
        let checks = SafetyChecks {
            primary_state_unchanged: &preview.safety.primary_state_unchanged,
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validation_evidence: &preview.safety.validation_evidence,
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

    refresh_apply_safety(&mut preview, expected_primary_state)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        return Ok(blocked_merge_apply_report(preview));
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

    let output = run_git_with_input(&preview.candidate.metadata.primary_repo_root, &args, &patch)
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
    validation_evidence_from_json(value).map(|evidence| evidence.reports())
}

pub fn validation_reports_from_json_for_agent(
    value: &Value,
    agent_id: Option<&str>,
) -> Result<Vec<ValidationReport>> {
    validation_evidence_from_json_for_agent(value, agent_id).map(|evidence| evidence.reports())
}

pub fn validation_evidence_from_json(value: &Value) -> Result<ValidationEvidenceBundle> {
    validation_evidence_from_json_for_agent(value, None)
}

pub fn validation_evidence_from_json_for_agent(
    value: &Value,
    agent_id: Option<&str>,
) -> Result<ValidationEvidenceBundle> {
    if let Some(agents) = value.get("agents").and_then(Value::as_array) {
        let mut evidence = ValidationEvidenceBundle::default();
        let mut matched_agent = false;
        for agent in agents {
            let candidate_id = agent.get("id").and_then(Value::as_str);
            if agent_id.is_some() && candidate_id != agent_id {
                continue;
            }
            matched_agent = true;
            evidence.extend(validation_evidence_from_agent_json(agent).with_context(|| {
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
        return Ok(evidence);
    }

    validation_evidence_group_from_json(value)
}

fn validation_evidence_group_from_json(value: &Value) -> Result<ValidationEvidenceBundle> {
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
        let binding = validation_binding_from_json(value)?;
        return Ok(ValidationEvidenceBundle {
            groups: vec![ValidationEvidenceGroup {
                binding,
                reports: vec![validation_report_from_json(value)?],
            }],
        });
    } else {
        bail!("validation report JSON must be an object or array");
    };

    let mut reports = report_values
        .iter()
        .map(validation_report_from_json)
        .collect::<Result<Vec<_>>>()?;
    sort_validation_reports(&mut reports);
    if reports.is_empty() {
        return Ok(ValidationEvidenceBundle::default());
    }
    Ok(ValidationEvidenceBundle {
        groups: vec![ValidationEvidenceGroup {
            binding: validation_binding_from_json(value)?,
            reports,
        }],
    })
}

fn validation_evidence_from_agent_json(agent: &Value) -> Result<ValidationEvidenceBundle> {
    if agent.get("validation").is_some()
        || agent.get("validations").is_some()
        || agent.get("reports").is_some()
    {
        validation_evidence_from_json(agent)
    } else {
        Ok(ValidationEvidenceBundle::default())
    }
}

fn capture_consistent_candidate_snapshot(
    primary_repo: &Repository,
    agent_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
) -> Result<CandidateRepositorySnapshot> {
    capture_two_matching(|| {
        capture_candidate_snapshot_once(primary_repo, agent_repo, record, primary_repo_root.clone())
    })
}

fn capture_two_matching<T, F>(mut capture: F) -> Result<T>
where
    T: PartialEq,
    F: FnMut() -> Result<Option<T>>,
{
    for _ in 0..CANDIDATE_CAPTURE_ATTEMPTS {
        let Some(first) = capture()? else {
            continue;
        };
        let Some(second) = capture()? else {
            continue;
        };
        if first == second {
            return Ok(second);
        }
    }
    bail!(
        "candidate repository state changed while it was being captured; retry after concurrent agent worktree activity stops"
    )
}

fn capture_candidate_snapshot_once(
    primary_repo: &Repository,
    agent_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
) -> Result<Option<CandidateRepositorySnapshot>> {
    let before = capture_candidate_boundary(primary_repo, agent_repo, &record.path)?;
    let metadata = metadata_from_heads(
        primary_repo,
        record,
        primary_repo_root,
        before.primary_head,
        before.agent_head,
    )?;
    let base_oid = collection_base_oid(&metadata)?;
    let mut captured = snapshot_worktree_candidate_from_base(
        agent_repo,
        &record.path,
        before.agent_head,
        base_oid,
    )?;
    preserve_untracked_change_kinds(&before.worktree_status, &mut captured.changes)?;
    let after = capture_candidate_boundary(primary_repo, agent_repo, &record.path)?;
    if before != after {
        return Ok(None);
    }

    Ok(Some(CandidateRepositorySnapshot {
        metadata,
        index_digest: after.index_digest,
        worktree_status: after.worktree_status,
        snapshot_tree: captured.oid,
        changes: captured.changes,
        raw_diff: captured.raw_diff,
    }))
}

fn preserve_untracked_change_kinds(porcelain_v2: &[u8], changes: &mut [ChangedPath]) -> Result<()> {
    let untracked = porcelain_v2
        .split(|byte| *byte == 0)
        .filter_map(|record| record.strip_prefix(b"? "))
        .map(path_buf_from_git_bytes)
        .collect::<Result<BTreeSet<_>>>()?;
    for change in changes {
        if change.kind == ChangeKind::Added && untracked.contains(&change.path) {
            change.kind = ChangeKind::Untracked;
        }
    }
    Ok(())
}

fn capture_candidate_boundary(
    primary_repo: &Repository,
    agent_repo: &Repository,
    worktree_path: &Path,
) -> Result<CandidateBoundaryState> {
    let primary_head = head_oid(primary_repo).context("failed to read primary HEAD")?;
    let agent_head = head_oid(agent_repo).context("failed to read agent HEAD")?;
    let index_digest = hash_optional_file(&agent_repo.path().join("index"))?;
    let status = run_git_capture(
        worktree_path,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    .context("failed to capture agent worktree status")?;
    if !status.success {
        bail!(
            "git status failed while capturing candidate: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    Ok(CandidateBoundaryState {
        primary_head,
        agent_head,
        index_digest,
        worktree_status: status.stdout,
    })
}

fn metadata_from_heads(
    primary_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
    primary_head: Option<Oid>,
    agent_head: Option<Oid>,
) -> Result<WorktreeMergeMetadata> {
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

fn candidate_validation_binding(
    metadata: &WorktreeMergeMetadata,
    full_diff: &[u8],
) -> Result<CandidateValidationBinding> {
    let diff_oid = Oid::hash_object(ObjectType::Blob, full_diff)
        .context("failed to hash merge candidate diff")?;
    CandidateValidationBinding {
        version: VALIDATION_BINDING_VERSION,
        agent_id: metadata.agent_id.clone(),
        primary_head: metadata.primary_head.clone(),
        agent_head: metadata.agent_head.clone(),
        merge_base: metadata.merge_base.clone(),
        diff_oid: diff_oid.to_string(),
    }
    .canonicalized()
}

fn canonical_optional_oid(value: Option<String>, field: &str) -> Result<Option<String>> {
    value.map(|value| canonical_oid(&value, field)).transpose()
}

fn canonical_oid(value: &str, field: &str) -> Result<String> {
    let oid = Oid::from_str(value)
        .with_context(|| format!("validation binding {field} must be a Git object id"))?;
    let canonical = oid.to_string();
    if canonical != value {
        bail!("validation binding {field} must use its canonical 40-character lowercase form");
    }
    Ok(canonical)
}

fn collection_base_oid(metadata: &WorktreeMergeMetadata) -> Result<Option<Oid>> {
    metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref())
        .map(|oid| Oid::from_str(oid).context("failed to parse collection base oid"))
        .transpose()
}

fn collect_changed_paths(repo: &Repository) -> Result<Vec<ChangedPath>> {
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
        let path = path_buf_from_git_bytes(entry.path_bytes())?;
        changes.insert(path, classify_status(entry.status()));
    }

    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn snapshot_worktree_candidate(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
) -> Result<CapturedWorktreeTree> {
    snapshot_worktree_candidate_from_base(repo, worktree_path, head, head)
}

fn snapshot_worktree_candidate_from_base(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
    base_commit: Option<Oid>,
) -> Result<CapturedWorktreeTree> {
    let index = TemporaryIndex::create(repo.commondir())?;
    let mut read_tree = git_command(worktree_path, &["read-tree"])?;
    index.configure_command(&mut read_tree);
    match head {
        Some(oid) => {
            read_tree.arg(oid.to_string());
        }
        None => {
            read_tree.arg("--empty");
        }
    }
    run_command_success(read_tree, "initialize candidate snapshot index")?;

    let mut add = git_command(worktree_path, &["add", "--all", "--", "."])?;
    index.configure_command(&mut add);
    run_command_success(add, "populate candidate snapshot index")?;

    let mut write_tree = git_command(worktree_path, &["write-tree"])?;
    index.configure_command(&mut write_tree);
    let output = write_tree
        .output()
        .context("failed to write candidate snapshot tree")?;
    if !output.status.success() {
        bail!(
            "failed to write candidate snapshot tree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let oid =
        String::from_utf8(output.stdout).context("candidate snapshot tree id was not UTF-8")?;
    let oid = Oid::from_str(oid.trim()).context("candidate snapshot tree id was invalid")?;
    let base_tree = temporary_base_tree_oid(repo, worktree_path, base_commit, &index)?;
    let changes = collect_snapshot_changes(worktree_path, base_tree, oid, &index)?;
    let raw_diff = collect_snapshot_diff(worktree_path, base_tree, oid, &index)?;
    Ok(CapturedWorktreeTree {
        oid,
        changes,
        raw_diff,
    })
}

fn temporary_base_tree_oid(
    repo: &Repository,
    worktree_path: &Path,
    base_commit: Option<Oid>,
    index: &TemporaryIndex,
) -> Result<Oid> {
    if let Some(commit) = base_commit {
        let tree_id = repo
            .find_commit(commit)
            .with_context(|| format!("failed to find base commit {commit}"))?
            .tree_id();
        return Ok(tree_id);
    }

    let mut command = git_command(worktree_path, &["mktree"])?;
    index.configure_command(&mut command);
    command.stdin(Stdio::null());
    let output = command
        .output()
        .context("failed to create empty base tree")?;
    if !output.status.success() {
        bail!(
            "failed to create empty base tree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let oid = String::from_utf8(output.stdout).context("empty tree id was not UTF-8")?;
    Oid::from_str(oid.trim()).context("empty tree id was invalid")
}

fn collect_snapshot_changes(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<ChangedPath>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let mut command = git_command(
        worktree_path,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            &base,
            &snapshot,
            "--",
        ],
    )?;
    index.configure_command(&mut command);
    let output = command
        .output()
        .context("failed to collect candidate snapshot paths")?;
    if !output.status.success() {
        bail!(
            "failed to collect candidate snapshot paths: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_name_status_z(&output.stdout)
}

fn parse_name_status_z(bytes: &[u8]) -> Result<Vec<ChangedPath>> {
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut changes = BTreeMap::new();
    while let Some(status) = fields.next() {
        let path = fields
            .next()
            .context("git diff --name-status returned a status without a path")?;
        let kind = match status.first().copied() {
            Some(b'A') => ChangeKind::Added,
            Some(b'M') => ChangeKind::Modified,
            Some(b'D') => ChangeKind::Deleted,
            Some(b'T') => ChangeKind::Typechange,
            Some(b'U') => ChangeKind::Conflicted,
            Some(_) => ChangeKind::Unknown,
            None => bail!("git diff --name-status returned an empty status"),
        };
        changes.insert(path_buf_from_git_bytes(path)?, kind);
    }
    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn collect_snapshot_diff(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<u8>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let mut command = git_command(
        worktree_path,
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            &base,
            &snapshot,
            "--",
        ],
    )?;
    index.configure_command(&mut command);
    let output = command
        .output()
        .context("failed to collect candidate snapshot diff")?;
    if !output.status.success() {
        bail!(
            "failed to collect candidate snapshot diff: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

impl TemporaryIndex {
    fn create(common_dir: &Path) -> Result<Self> {
        let runtime_root = trusted_runtime_root(common_dir)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?
            .as_nanos();
        for attempt in 0..32_u32 {
            let directory = runtime_root.join(format!(
                "maco-candidate-capture-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let object_directory = directory.join("objects");
                    if let Err(error) = fs::create_dir(&object_directory) {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error)
                            .context("failed to create temporary Git object directory");
                    }
                    return Ok(Self {
                        path: directory.join("index"),
                        object_directory,
                        alternate_object_directory: common_dir.join("objects"),
                        directory,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("failed to create candidate capture directory")
                }
            }
        }
        bail!("failed to reserve a unique candidate capture directory")
    }

    fn configure_command(&self, command: &mut Command) {
        command
            .env("GIT_INDEX_FILE", &self.path)
            .env("GIT_OBJECT_DIRECTORY", &self.object_directory)
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                &self.alternate_object_directory,
            );
    }
}

impl Drop for TemporaryIndex {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn run_command_success(mut command: Command, label: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to {label}"))?;
    if !output.status.success() {
        bail!(
            "failed to {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn hash_optional_file(path: &Path) -> Result<Option<Oid>> {
    match fs::read(path) {
        Ok(bytes) => Oid::hash_object(ObjectType::Blob, &bytes)
            .context("failed to hash repository state file")
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn passed_safety_check() -> SafetyCheck {
    SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    }
}

fn validation_evidence_check(
    evidence: &ValidationEvidenceBundle,
    expected: &CandidateValidationBinding,
    require_validation: bool,
    changed_paths: &[PathBuf],
) -> ValidationEvidenceCheck {
    if !require_validation {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NotRequired,
            message: Some("candidate-bound validation evidence was not required".to_string()),
            paths: Vec::new(),
        };
    }

    let passing_groups = evidence
        .groups
        .iter()
        .filter(|group| {
            group
                .reports
                .iter()
                .any(|report| report.status == ValidationStatus::Passed)
        })
        .collect::<Vec<_>>();
    if passing_groups.is_empty() {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NoPassedReport,
            message: Some("no passed validation report was available to bind".to_string()),
            paths: Vec::new(),
        };
    }
    if passing_groups
        .iter()
        .any(|group| group.binding.as_ref() == Some(expected))
    {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Passed,
            binding_status: ValidationBindingStatus::Bound,
            message: None,
            paths: Vec::new(),
        };
    }
    if passing_groups.iter().any(|group| group.binding.is_some()) {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Failed,
            binding_status: ValidationBindingStatus::Mismatched,
            message: Some(
                "passed validation evidence is bound to a different candidate; rerun validation for the current candidate.validation_binding"
                    .to_string(),
            ),
            paths: changed_paths.to_vec(),
        };
    }

    ValidationEvidenceCheck {
        status: SafetyCheckStatus::Failed,
        binding_status: ValidationBindingStatus::Unbound,
        message: Some(
            "passed validation evidence uses the legacy unbound format; include the current candidate.validation_binding in the validation report envelope"
                .to_string(),
        ),
        paths: changed_paths.to_vec(),
    }
}

fn dirty_primary_check(repo_root: &Path) -> Result<SafetyCheck> {
    let repo = Repository::open(repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let paths = collect_changed_paths(&repo)?
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

fn stale_base_check_for_current_head(
    metadata: &WorktreeMergeMetadata,
    current_head: Option<Oid>,
) -> SafetyCheck {
    let candidate_base = metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref());
    let current_head = current_head.map(|oid| oid.to_string());
    match (candidate_base, current_head.as_deref()) {
        (Some(base), Some(current)) if base == current => passed_safety_check(),
        (None, None) => passed_safety_check(),
        (Some(_), Some(_)) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "candidate base is stale relative to the current primary HEAD".to_string(),
            ),
            paths: Vec::new(),
        },
        _ => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn primary_state_check(
    expected: &PrimaryRepositoryState,
    current: &PrimaryRepositoryState,
) -> SafetyCheck {
    if expected == current {
        return passed_safety_check();
    }
    let mut changed = Vec::new();
    if expected.head != current.head {
        changed.push("HEAD");
    }
    if expected.index_digest != current.index_digest {
        changed.push("index");
    }
    if expected.worktree_digest != current.worktree_digest {
        changed.push("worktree");
    }
    SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: Some(format!(
            "primary repository state changed after the merge safety preview ({})",
            changed.join(", ")
        )),
        paths: Vec::new(),
    }
}

fn refresh_apply_safety(
    preview: &mut MergeApplyPreview,
    expected_primary_state: &PrimaryRepositoryState,
) -> Result<()> {
    let repo_root = &preview.candidate.metadata.primary_repo_root;
    let current_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let dirty_primary = dirty_primary_check(repo_root)?;
    let stale_base =
        stale_base_check_for_current_head(&preview.candidate.metadata, current_primary_state.head);
    let unclaimed_edits = unclaimed_edits_check(&preview.candidate.unclaimed_changed_paths);
    let validation_required = preview.safety.validation_required;
    let validation = validation_check(&preview.candidate.validations, validation_required);
    let validation_evidence = validation_evidence_check(
        &preview.candidate.validation_evidence,
        &preview.candidate.validation_binding,
        validation_required,
        &preview.candidate.changed_paths,
    );
    let patch = preview.candidate.raw_diff.clone();
    let (apply_check, apply_mode) = apply_check(
        repo_root,
        &patch,
        preview.safety.force_options.allow_apply_conflicts,
    )?;
    let verified_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let primary_state_unchanged = if current_primary_state == verified_primary_state {
        primary_state_check(expected_primary_state, &verified_primary_state)
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "primary repository state changed while apply-time safety checks were running"
                    .to_string(),
            ),
            paths: Vec::new(),
        }
    };
    let checks = SafetyChecks {
        primary_state_unchanged: &primary_state_unchanged,
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validation_evidence: &validation_evidence,
        validations: &preview.candidate.validations,
        require_validation: validation_required,
        validation_commands: &preview.safety.candidate_validation_commands,
        validation_related_paths: &preview.candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &preview.safety.force_options);

    preview.safety.primary_state_unchanged = primary_state_unchanged;
    preview.safety.dirty_primary = dirty_primary;
    preview.safety.stale_base = stale_base;
    preview.safety.apply_check = apply_check;
    preview.safety.unclaimed_edits = unclaimed_edits;
    preview.safety.validation = validation;
    preview.safety.validation_evidence = validation_evidence;
    preview.safety.apply_mode = apply_mode;
    preview.safety.readiness = readiness;
    Ok(())
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
    patch: &[u8],
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
    let mut reports = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        let sandbox = CandidateValidationSandbox::create(preview)?;
        let report = run_candidate_validation_command(
            sandbox.path(),
            command,
            index,
            &preview.candidate.changed_paths,
        );
        reports.push(sandbox.enforce_candidate_integrity(preview, report));
    }
    Ok(reports)
}

struct CandidateValidationSandbox {
    primary_repo_root: PathBuf,
    path: PathBuf,
    baseline_integrity: Option<CandidateValidationSandboxIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateValidationSandboxIntegrity {
    binding: CandidateValidationBinding,
    repository: ValidationRepositoryFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationRepositoryFingerprint {
    head: Option<Oid>,
    index_digest: Option<Oid>,
    status: Vec<u8>,
    snapshot_tree: Oid,
    submodules: Vec<ValidationSubmoduleFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationSubmoduleFingerprint {
    path: PathBuf,
    expected_gitlink: Oid,
    initialized: bool,
    filesystem: ValidationFilesystemFingerprint,
    repository: Option<Box<ValidationRepositoryFingerprint>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemFingerprint {
    exists: bool,
    entries: Vec<ValidationFilesystemEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemEntry {
    path: PathBuf,
    kind: ValidationFilesystemEntryKind,
    mode: u32,
    content_digest: Option<Oid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationFilesystemEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, thiserror::Error)]
enum ValidationFilesystemFingerprintError {
    #[error("validation submodule raw fingerprint exceeded the {limit}-entry limit at {path:?}")]
    EntryCountExceeded { path: PathBuf, limit: usize },
    #[error(
        "validation submodule raw fingerprint file {path:?} exceeded the {limit}-byte single-file limit"
    )]
    SingleFileTooLarge { path: PathBuf, limit: u64 },
    #[error(
        "validation submodule raw fingerprint exceeded the {limit}-byte total-content limit at {path:?}"
    )]
    TotalContentTooLarge { path: PathBuf, limit: u64 },
}

struct ValidationFilesystemBudget {
    entries: usize,
    total_bytes: u64,
    max_entries: usize,
    max_total_bytes: u64,
    max_single_file_bytes: u64,
}

impl CandidateValidationSandbox {
    fn create(preview: &MergeApplyPreview) -> Result<Self> {
        let primary_repo_root = preview.candidate.metadata.primary_repo_root.clone();
        let path = candidate_validation_sandbox_path(&primary_repo_root)?;
        let base_revision = preview
            .candidate
            .metadata
            .primary_head
            .as_deref()
            .unwrap_or("HEAD");
        let mut add_command = sanitized_git_command(&primary_repo_root)?;
        add_command
            .args(["worktree", "add", "--detach", "--force"])
            .arg(&path)
            .arg(base_revision);
        let add_output = add_command.output().with_context(|| {
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
        let mut sandbox = Self {
            primary_repo_root,
            path,
            baseline_integrity: None,
        };

        let patch = preview.candidate.raw_diff.as_slice();
        let args = match preview.safety.apply_mode {
            ApplyMode::Direct => vec!["apply", "--binary"],
            ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
            ApplyMode::None => Vec::new(),
        };
        if !args.is_empty() {
            let apply_output = run_git_with_input(&sandbox.path, &args, patch)
                .context("failed to apply candidate patch to validation worktree")?;
            if !apply_output.success {
                bail!(
                    "failed to apply candidate patch to validation worktree: {}",
                    String::from_utf8_lossy(&apply_output.stderr).trim()
                );
            }
        }

        sandbox.baseline_integrity = Some(sandbox.current_integrity(preview)?);

        Ok(sandbox)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn enforce_candidate_integrity(
        &self,
        preview: &MergeApplyPreview,
        mut report: ValidationReport,
    ) -> ValidationReport {
        let integrity = self.current_integrity(preview);
        match integrity {
            Ok(integrity) if Some(&integrity) == self.baseline_integrity.as_ref() => report,
            Ok(_) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    "validation command mutated tracked or non-ignored candidate state; its result was rejected",
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
            Err(error) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    &format!("failed to verify validation sandbox integrity: {error}"),
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
        }
    }

    fn current_integrity(
        &self,
        preview: &MergeApplyPreview,
    ) -> Result<CandidateValidationSandboxIntegrity> {
        let repo = Repository::open(&self.path).with_context(|| {
            format!("failed to open validation sandbox {}", self.path.display())
        })?;
        let base = collection_base_oid(&preview.candidate.metadata)?;
        capture_two_matching(|| {
            let head = head_oid(&repo).context("failed to read validation sandbox HEAD")?;
            let captured = snapshot_worktree_candidate_from_base(&repo, &self.path, head, base)?;
            let binding =
                candidate_validation_binding(&preview.candidate.metadata, &captured.raw_diff)?;
            let repository =
                validation_repository_fingerprint(&repo, &self.path, Some(captured.oid), 0)?;
            Ok(Some(CandidateValidationSandboxIntegrity {
                binding,
                repository,
            }))
        })
    }
}

fn validation_repository_fingerprint(
    repo: &Repository,
    worktree_path: &Path,
    known_snapshot_tree: Option<Oid>,
    depth: usize,
) -> Result<ValidationRepositoryFingerprint> {
    if depth > 32 {
        bail!("validation sandbox submodule nesting exceeded 32 levels");
    }
    let head = head_oid(repo).context("failed to read validation repository HEAD")?;
    let index_digest = hash_optional_file(&repo.path().join("index"))?;
    let status = run_git_capture(
        worktree_path,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    .context("failed to capture recursive validation repository status")?;
    if !status.success {
        bail!(
            "git status failed while fingerprinting validation repository: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    let snapshot_tree = match known_snapshot_tree {
        Some(snapshot_tree) => snapshot_tree,
        None => snapshot_worktree_candidate(repo, worktree_path, head)?.oid,
    };

    let mut submodules = Vec::new();
    for (path, expected_gitlink) in validation_gitlinks(worktree_path)? {
        let submodule_path = worktree_path.join(&path);
        let marker = submodule_path.join(".git");
        let marker_present = match fs::symlink_metadata(&marker) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect submodule marker {}", marker.display())
                })
            }
        };
        if !marker_present {
            let filesystem = validation_filesystem_fingerprint(&submodule_path)?;
            submodules.push(ValidationSubmoduleFingerprint {
                path,
                expected_gitlink,
                initialized: false,
                filesystem,
                repository: None,
            });
            continue;
        }
        let filesystem = validation_submodule_marker_fingerprint(&marker)?;
        let submodule_repo = Repository::open(&submodule_path).with_context(|| {
            format!(
                "initialized validation submodule {} could not be opened",
                path_json_text(&path)
            )
        })?;
        let repository =
            validation_repository_fingerprint(&submodule_repo, &submodule_path, None, depth + 1)?;
        submodules.push(ValidationSubmoduleFingerprint {
            path,
            expected_gitlink,
            initialized: true,
            filesystem,
            repository: Some(Box::new(repository)),
        });
    }

    Ok(ValidationRepositoryFingerprint {
        head,
        index_digest,
        status: status.stdout,
        snapshot_tree,
        submodules,
    })
}

fn validation_gitlinks(worktree_path: &Path) -> Result<Vec<(PathBuf, Oid)>> {
    let output = run_git_capture(worktree_path, &["ls-files", "--stage", "-z", "--"])
        .context("failed to enumerate validation repository gitlinks")?;
    if !output.success {
        bail!(
            "git ls-files failed while enumerating validation submodules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut gitlinks = BTreeMap::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .context("git ls-files stage record did not contain a path separator")?;
        let metadata = std::str::from_utf8(&entry[..tab])
            .context("git ls-files stage metadata was not ASCII")?;
        let mut fields = metadata.split_ascii_whitespace();
        let mode = fields.next().context("gitlink record missing mode")?;
        let oid = fields.next().context("gitlink record missing object id")?;
        let stage = fields.next().context("gitlink record missing stage")?;
        if fields.next().is_some() {
            bail!("gitlink record contained unexpected metadata fields");
        }
        if mode != "160000" {
            continue;
        }
        if stage != "0" {
            bail!(
                "validation repository contains a conflicted submodule gitlink; refusing incomplete integrity capture"
            );
        }
        let path = normalize_repo_relative_path(path_buf_from_git_bytes(&entry[tab + 1..])?)?;
        let oid = Oid::from_str(oid).context("gitlink object id was invalid")?;
        if gitlinks.insert(path.clone(), oid).is_some() {
            bail!(
                "validation repository reported duplicate gitlink {}",
                path_json_text(&path)
            );
        }
    }
    Ok(gitlinks.into_iter().collect())
}

fn validation_filesystem_fingerprint(root: &Path) -> Result<ValidationFilesystemFingerprint> {
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationFilesystemFingerprint {
                exists: false,
                entries: Vec::new(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect submodule filesystem {}", root.display())
            })
        }
    }
    let mut entries = Vec::new();
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: VALIDATION_RAW_MAX_ENTRIES,
        max_total_bytes: VALIDATION_RAW_MAX_TOTAL_BYTES,
        max_single_file_bytes: VALIDATION_RAW_MAX_SINGLE_FILE_BYTES,
    };
    collect_validation_filesystem_entries(root, root, &mut entries, &mut budget)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries,
    })
}

fn validation_submodule_marker_fingerprint(
    marker: &Path,
) -> Result<ValidationFilesystemFingerprint> {
    let metadata = fs::symlink_metadata(marker)
        .with_context(|| format!("failed to inspect submodule marker {}", marker.display()))?;
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: 1,
        max_total_bytes: VALIDATION_MARKER_MAX_BYTES,
        max_single_file_bytes: VALIDATION_MARKER_MAX_BYTES,
    };
    let entry = validation_filesystem_entry(marker, PathBuf::from(".git"), &metadata, &mut budget)?;
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries: vec![entry],
    })
}

fn collect_validation_filesystem_entries(
    root: &Path,
    path: &Path,
    entries: &mut Vec<ValidationFilesystemEntry>,
    budget: &mut ValidationFilesystemBudget,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect validation path {}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .context("validation filesystem path escaped submodule root")?
        .to_path_buf();
    let file_type = metadata.file_type();
    entries.push(validation_filesystem_entry(
        path, relative, &metadata, budget,
    )?);

    if file_type.is_dir() {
        let mut children = Vec::new();
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to list validation directory {}", path.display()))?
        {
            let child = entry
                .with_context(|| {
                    format!(
                        "failed to read validation directory entry in {}",
                        path.display()
                    )
                })?
                .path();
            if budget
                .entries
                .saturating_add(children.len())
                .saturating_add(1)
                > budget.max_entries
            {
                return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
                    path: child,
                    limit: budget.max_entries,
                }
                .into());
            }
            children.push(child);
        }
        children.sort();
        for child in children {
            collect_validation_filesystem_entries(root, &child, entries, budget)?;
        }
    }
    Ok(())
}

fn validation_filesystem_entry(
    path: &Path,
    relative: PathBuf,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<ValidationFilesystemEntry> {
    budget.entries = budget.entries.saturating_add(1);
    if budget.entries > budget.max_entries {
        return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
            path: relative,
            limit: budget.max_entries,
        }
        .into());
    }
    let file_type = metadata.file_type();
    let (kind, content_digest) = if file_type.is_dir() {
        (ValidationFilesystemEntryKind::Directory, None)
    } else if file_type.is_file() {
        (
            ValidationFilesystemEntryKind::File,
            Some(validation_file_content_digest(
                path, &relative, metadata, budget,
            )?),
        )
    } else if file_type.is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("failed to read validation symlink {}", path.display()))?;
        let target = raw_path_bytes(&target);
        budget.add_content_bytes(&relative, target.len() as u64)?;
        (
            ValidationFilesystemEntryKind::Symlink,
            Some(
                Oid::hash_object(ObjectType::Blob, &target)
                    .context("failed to hash validation symlink target")?,
            ),
        )
    } else {
        (ValidationFilesystemEntryKind::Other, None)
    };
    Ok(ValidationFilesystemEntry {
        path: relative,
        kind,
        mode: validation_file_mode(metadata),
        content_digest,
    })
}

fn validation_file_content_digest(
    path: &Path,
    relative: &Path,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<Oid> {
    if metadata.len() > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    let remaining_total = budget.max_total_bytes.saturating_sub(budget.total_bytes);
    let read_limit = budget
        .max_single_file_bytes
        .min(remaining_total)
        .saturating_add(1);
    let mut content = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open validation file {}", path.display()))?
        .take(read_limit)
        .read_to_end(&mut content)
        .with_context(|| format!("failed to read validation file {}", path.display()))?;
    let content_len = content.len() as u64;
    if content_len > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    budget.add_content_bytes(relative, content_len)?;
    Oid::hash_object(ObjectType::Blob, &content).context("failed to hash validation file content")
}

impl ValidationFilesystemBudget {
    fn add_content_bytes(&mut self, path: &Path, bytes: u64) -> Result<()> {
        if bytes > self.max_single_file_bytes {
            return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
                path: path.to_path_buf(),
                limit: self.max_single_file_bytes,
            }
            .into());
        }
        let Some(total) = self.total_bytes.checked_add(bytes) else {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        };
        if total > self.max_total_bytes {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        }
        self.total_bytes = total;
        Ok(())
    }
}

fn validation_file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

impl Drop for CandidateValidationSandbox {
    fn drop(&mut self) {
        if let Ok(mut command) = sanitized_git_command(&self.primary_repo_root) {
            let _ = command
                .args(["worktree", "remove", "--force"])
                .arg(&self.path)
                .output();
        }
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
    Ok(trusted_runtime_root(primary_repo_root)?.join(format!(
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
    let mut command = shell_command(&validation.command);
    sanitize_validation_command_environment(&mut command);
    let output = command
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

fn append_validation_message(existing: Option<String>, next: &str) -> Option<String> {
    Some(match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next.to_string(),
    })
}

struct SafetyChecks<'a> {
    primary_state_unchanged: &'a SafetyCheck,
    dirty_primary: &'a SafetyCheck,
    stale_base: &'a SafetyCheck,
    apply_check: &'a SafetyCheck,
    unclaimed_edits: &'a SafetyCheck,
    validation: &'a SafetyCheck,
    validation_evidence: &'a ValidationEvidenceCheck,
    validations: &'a [ValidationReport],
    require_validation: bool,
    validation_commands: &'a [String],
    validation_related_paths: &'a [PathBuf],
}

fn classify_apply_safety(checks: SafetyChecks<'_>, forces: &MergeForceOptions) -> ApplyReadiness {
    let candidates = [
        (
            checks.primary_state_unchanged,
            ApplyBlocker::ApplyCheckFailed,
            false,
        ),
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

    if let Some(detail) = validation_evidence_blocker_detail(&checks) {
        blockers.push(detail.kind);
        details.push(detail);
    }

    for detail in validation_blocker_details(&checks, forces) {
        match detail.disposition {
            ApplyBlockerDisposition::Blocked => blockers.push(detail.kind),
            ApplyBlockerDisposition::Forced => forced.push(detail.kind),
        }
        details.push(detail);
    }

    blockers.sort();
    blockers.dedup();
    forced.sort();
    forced.dedup();

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

fn validation_evidence_blocker_detail(checks: &SafetyChecks<'_>) -> Option<ApplyBlockerDetail> {
    if checks.validation_evidence.status != SafetyCheckStatus::Failed {
        return None;
    }
    let (kind, next_safe_operation) = match checks.validation_evidence.binding_status {
        ValidationBindingStatus::Unbound => (
            ApplyBlocker::ValidationMissing,
            "regenerate the validation report as an envelope containing the current candidate.validation_binding and its reports",
        ),
        ValidationBindingStatus::Mismatched => (
            ApplyBlocker::ValidationMissing,
            "rerun validation for the current candidate.validation_binding and replace stale evidence",
        ),
        _ => return None,
    };
    Some(ApplyBlockerDetail {
        kind,
        disposition: ApplyBlockerDisposition::Blocked,
        check_status: checks.validation_evidence.status,
        paths: checks.validation_evidence.paths.clone(),
        message: checks.validation_evidence.message.clone(),
        validation_reports: checks
            .validations
            .iter()
            .filter(|report| report.status == ValidationStatus::Passed)
            .cloned()
            .collect(),
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    })
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

fn serialize_path<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&path_json_text(path))
}

fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

pub(crate) fn path_json_text(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return escape_bytes_ascii(path.as_os_str().as_bytes());
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut escaped = String::new();
        for unit in path.as_os_str().encode_wide() {
            if matches!(unit, 0x20..=0x7e) && unit != u16::from(b'\\') {
                escaped.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
            } else {
                let _ = write!(&mut escaped, "\\u{unit:04X}");
            }
        }
        return escaped;
    }

    #[allow(unreachable_code)]
    "<non-unicode-path>".to_string()
}

pub(crate) fn raw_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return path.as_os_str().as_bytes().to_vec();
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        return path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
    }

    #[allow(unreachable_code)]
    path.as_os_str()
        .to_str()
        .map(str::as_bytes)
        .unwrap_or_default()
        .to_vec()
}

fn path_buf_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    #[cfg(not(unix))]
    {
        let path = String::from_utf8(bytes.to_vec())
            .context("Git returned a repository path that is not valid UTF-8 on this platform")?;
        Ok(PathBuf::from(path))
    }
}

fn patch_text_for_json(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|error| escape_bytes_ascii(error.as_bytes()))
}

fn escape_bytes_ascii(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for byte in bytes {
        match *byte {
            b'\n' => escaped.push('\n'),
            b'\r' => escaped.push('\r'),
            b'\t' => escaped.push('\t'),
            0x20..=0x7e if *byte != b'\\' => escaped.push(char::from(*byte)),
            b'\\' => escaped.push_str("\\\\"),
            _ => {
                let _ = write!(&mut escaped, "\\x{byte:02X}");
            }
        }
    }
    escaped
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

impl RepoCommonLock {
    pub(crate) fn acquire(repo_root: &Path, operation: &str) -> Result<Self> {
        if operation.is_empty()
            || !operation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("repository lock operation name is invalid");
        }
        let repo = Repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for {operation} lock {}",
                repo_root.display()
            )
        })?;
        let state_dir = ensure_repo_common_state_directory(&repo)
            .with_context(|| format!("failed to prepare {operation} lock directory"))?;
        let path = state_dir.join(REPOSITORY_MUTATION_LOCK_FILE);
        let mut file = open_repo_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return repository_lock_contention(&mut file, &path, operation)
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "{operation} could not acquire kernel repository mutation lock {}; refusing to continue",
                        path.display()
                    )
                })
            }
        }

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        let process_start = lock_owner_process_start_identity()?;
        let owner = RepoLockOwner {
            version: LOCK_RECORD_VERSION,
            pid: std::process::id(),
            nonce: format!("{}-{}", std::process::id(), duration.as_nanos()),
            created_unix_seconds: duration.as_secs(),
            operation: operation.to_string(),
            process_start,
        };
        let mut owner_bytes = serde_json::to_vec(&owner).context("failed to encode lock owner")?;
        owner_bytes.push(b'\n');
        write_lock_owner(&mut file, &path, operation, &owner_bytes)?;
        Ok(Self { file })
    }
}

fn open_repo_lock_file(path: &Path) -> Result<fs::File> {
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let (file, created) = match create_options.open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_lock_path(path)?;
            let mut existing_options = OpenOptions::new();
            existing_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing_options
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                existing_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            (
                existing_options.open(path).with_context(|| {
                    format!("failed to open repository lock {}", path.display())
                })?,
                false,
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create repository lock {}", path.display()))
        }
    };
    validate_open_lock_file(path, &file)?;
    if created {
        let parent = path
            .parent()
            .context("repository mutation lock has no parent directory")?;
        sync_managed_directory(parent)?;
    }
    Ok(file)
}

pub(crate) fn ensure_repo_common_state_directory(repo: &Repository) -> Result<PathBuf> {
    let common_dir = repo.commondir();
    validate_managed_directory(common_dir).with_context(|| {
        format!(
            "repository common directory {} is unsafe",
            common_dir.display()
        )
    })?;
    let maco = ensure_private_managed_directory(common_dir, "maco")?;
    ensure_private_managed_directory(&maco, "state")
}

pub(crate) fn ensure_private_managed_directory(parent: &Path, name: &str) -> Result<PathBuf> {
    validate_managed_directory(parent)?;
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("managed directory component is invalid");
    }
    let path = parent.join(name);
    let created = match fs::create_dir(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create managed directory {}", path.display()))
        }
    };
    validate_managed_directory(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure managed directory {}", path.display()))?;
        validate_managed_directory(&path)?;
    }
    sync_managed_directory(&path)?;
    if created {
        sync_managed_directory(parent)?;
    }
    Ok(path)
}

fn validate_managed_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect managed directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "managed directory {} is not a real directory; refusing symbolic links and non-directory paths",
            path.display()
        );
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn sync_managed_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("failed to open managed directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to persist managed directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_managed_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn reject_unsafe_lock_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
    {
        bail!(
            "repository mutation lock {} is not a regular file; refusing to follow it",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_open_lock_file(path: &Path, file: &fs::File) -> Result<()> {
    reject_unsafe_lock_path(path)?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect repository lock {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open repository lock {}", path.display()))?;
    if !file_metadata.file_type().is_file() || metadata_is_windows_reparse_point(&file_metadata) {
        bail!(
            "repository mutation lock {} changed type while being opened",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
            || file_metadata.nlink() != 1
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        let path_volume = path_metadata
            .volume_serial_number()
            .context("repository lock path omitted volume identity")?;
        let file_volume = file_metadata
            .volume_serial_number()
            .context("open repository lock omitted volume identity")?;
        let path_index = path_metadata
            .file_index()
            .context("repository lock path omitted file identity")?;
        let file_index = file_metadata
            .file_index()
            .context("open repository lock omitted file identity")?;
        if path_volume != file_volume
            || path_index != file_index
            || file_metadata.number_of_links() != Some(1)
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    Ok(())
}

fn write_lock_owner(
    file: &mut fs::File,
    path: &Path,
    operation: &str,
    owner_bytes: &[u8],
) -> Result<()> {
    file.set_len(0)
        .with_context(|| format!("failed to truncate {operation} lock owner record"))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek {operation} lock owner record"))?;
    file.write_all(owner_bytes)
        .with_context(|| format!("failed to record {operation} lock owner"))?;
    file.sync_all().with_context(|| {
        format!(
            "failed to persist {operation} lock owner record {}",
            path.display()
        )
    })
}

fn repository_lock_contention<T>(file: &mut fs::File, path: &Path, operation: &str) -> Result<T> {
    let current = read_lock_record(file, path)
        .and_then(|bytes| {
            serde_json::from_slice::<RepoLockOwner>(&bytes)
                .context("active repository lock owner JSON is malformed")
        })
        .and_then(|owner| {
            validate_lock_owner(&owner, operation)?;
            Ok(owner)
        });
    match current {
        Ok(owner) => bail!(
            "{operation} cannot acquire repository mutation lock: kernel lock is held for {} by pid {} (nonce {}, created {})",
            owner.operation,
            owner.pid,
            owner.nonce,
            owner.created_unix_seconds
        ),
        Err(error) => bail!(
            "{operation} cannot acquire repository mutation lock {}: an active kernel lock has an invalid owner record ({error:#})",
            path.display()
        ),
    }
}

fn validate_lock_owner(owner: &RepoLockOwner, operation: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch while validating repository lock")?
        .as_secs();
    if owner.version != LOCK_RECORD_VERSION
        || owner.pid == 0
        || owner.nonce.is_empty()
        || owner.nonce.len() > 128
        || !owner
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || owner.created_unix_seconds == 0
        || owner.created_unix_seconds > now.saturating_add(300)
        || owner.operation.is_empty()
        || owner.operation.len() > 64
        || !owner
            .operation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !valid_process_start_identity(owner.process_start.as_ref())
    {
        bail!(
            "{operation} repository mutation lock owner record is invalid and will not be reclaimed automatically"
        );
    }
    Ok(())
}

fn valid_process_start_identity(identity: Option<&ProcessStartIdentity>) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(identity, Some(ProcessStartIdentity::LinuxProcStartTicks(value)) if *value > 0)
    }
    #[cfg(target_os = "windows")]
    {
        matches!(identity, Some(ProcessStartIdentity::WindowsCreationFiletime(value)) if *value > 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        identity.is_none()
    }
}

fn read_lock_record(file: &mut fs::File, path: &Path) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if metadata.len() == 0 || metadata.len() > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record has an invalid size");
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek repository lock {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOCK_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read repository lock {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record changed size while being read");
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read process identity {}", path.display()))
        }
    };
    let closing_paren = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .context("Linux process stat did not contain a command terminator")?;
    let fields = bytes[closing_paren + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let start_ticks = fields
        .get(19)
        .context("Linux process stat did not contain starttime")?;
    let start_ticks = std::str::from_utf8(start_ticks)
        .context("Linux process starttime was not ASCII")?
        .parse::<u64>()
        .context("Linux process starttime was invalid")?;
    if start_ticks == 0 {
        bail!("Linux process starttime was zero");
    }
    Ok(Some(ProcessStartIdentity::LinuxProcStartTicks(start_ticks)))
}

#[cfg(target_os = "windows")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    windows_process_start_identity(pid)
}

fn lock_owner_process_start_identity() -> Result<Option<ProcessStartIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        process_start_identity(std::process::id())?
            .with_context(|| {
                "current process start identity disappeared while acquiring repository lock"
            })
            .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
fn windows_process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    // SAFETY: The Windows API calls use a PID-sized integer, checked null
    // handles, initialized FILETIME outputs, and close every acquired handle.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER) {
                Ok(None)
            } else {
                Err(error).context("failed to open process for creation-time identity")
            };
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let times_error = (result == 0).then(std::io::Error::last_os_error);
        let close_result = CloseHandle(handle);
        if let Some(error) = times_error {
            return Err(error).context("failed to read process creation-time identity");
        }
        if close_result == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to close process identity handle");
        }
        let value = (u64::from(creation.high) << 32) | u64::from(creation.low);
        if value == 0 {
            bail!("Windows process creation time was zero");
        }
        Ok(Some(ProcessStartIdentity::WindowsCreationFiletime(value)))
    }
}

impl Drop for RepoCommonLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl PrimaryRepositoryState {
    fn capture(repo_root: &Path) -> Result<Self> {
        let first = Self::capture_once(repo_root)?;
        let second = Self::capture_once(repo_root)?;
        if first != second {
            bail!(
                "primary repository state changed while it was being captured; retry merge apply after concurrent repository activity stops"
            );
        }
        Ok(second)
    }

    fn capture_once(repo_root: &Path) -> Result<Self> {
        let repo = Repository::open(repo_root).with_context(|| {
            format!("failed to open primary repository {}", repo_root.display())
        })?;
        let head = head_oid(&repo).context("failed to read primary HEAD for merge transaction")?;
        let index_digest = hash_optional_file(&repo.path().join("index"))?;
        let worktree_digest = snapshot_worktree_candidate(&repo, repo_root, head)?.oid;
        Ok(Self {
            head,
            index_digest,
            worktree_digest,
        })
    }
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Result<GitCommandOutput> {
    run_git_capture_paths(repo_root, args, &[])
}

fn run_git_capture_paths(
    repo_root: &Path,
    args: &[&str],
    path_args: &[&Path],
) -> Result<GitCommandOutput> {
    let mut command = git_command(repo_root, args)?;
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

fn run_git_with_input(repo_root: &Path, args: &[&str], input: &[u8]) -> Result<GitCommandOutput> {
    let mut child = git_command(repo_root, args)?
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
        .write_all(input)
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

fn git_command(repo_root: &Path, args: &[&str]) -> Result<Command> {
    let mut command = sanitized_git_command(repo_root)?;
    command.args(args);
    Ok(command)
}

pub(crate) fn sanitized_git_command(repo_root: &Path) -> Result<Command> {
    let mut command = Command::new(resolve_trusted_executable("git")?);
    let runtime_root = configure_capture_environment(&mut command, repo_root)?;
    command
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .arg("-c")
        .arg(format!(
            "core.hooksPath={}",
            disabled_git_path(&runtime_root, "hooks").display()
        ))
        .arg("-C")
        .arg(repo_root);
    Ok(command)
}

pub(crate) fn sanitized_git_push_command(repo_root: &Path) -> Result<Command> {
    let mut command = Command::new(resolve_trusted_executable("git")?);
    sanitize_network_command_environment(&mut command)?;
    let runtime_root = trusted_runtime_root(repo_root)?;
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            disabled_git_path(&runtime_root, "network-global-config"),
        )
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "core.fsmonitor=false"])
        .arg("-C")
        .arg(repo_root);
    Ok(command)
}

fn configure_capture_environment(command: &mut Command, repo_root: &Path) -> Result<PathBuf> {
    let allowed = [
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ];
    let preserved = allowed
        .iter()
        .filter_map(|key| env::var_os(key).map(|value| ((*key).to_string(), value)))
        .collect::<Vec<_>>();
    command.env_clear();
    command.envs(preserved);
    let runtime_root = trusted_runtime_root(repo_root)?;
    command
        .env("PATH", trusted_executable_search_path()?)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            disabled_git_path(&runtime_root, "global-config"),
        )
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("TMPDIR", &runtime_root)
        .env("TMP", &runtime_root)
        .env("TEMP", &runtime_root);
    Ok(runtime_root)
}

pub(crate) fn sanitize_validation_command_environment(command: &mut Command) {
    remove_git_injection_environment(command);
    command.env("GIT_OPTIONAL_LOCKS", "0");
}

pub(crate) fn sanitize_network_command_environment(command: &mut Command) -> Result<()> {
    remove_git_injection_environment(command);
    remove_dynamic_loader_environment(command);
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("PATH", trusted_executable_search_path()?);
    Ok(())
}

fn remove_git_injection_environment(command: &mut Command) {
    for (key, _) in env::vars_os() {
        let key_text = key.to_string_lossy();
        if is_git_injection_environment_key(&key_text) {
            command.env_remove(key);
        }
    }
}

fn remove_dynamic_loader_environment(command: &mut Command) {
    for (key, _) in env::vars_os() {
        let key_text = key.to_string_lossy();
        if key_text.starts_with("LD_") || key_text.starts_with("DYLD_") {
            command.env_remove(key);
        }
    }
}

fn is_git_injection_environment_key(key: &str) -> bool {
    matches!(
        key,
        "GIT_DIR"
            | "GIT_WORK_TREE"
            | "GIT_INDEX_FILE"
            | "GIT_COMMON_DIR"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
            | "GIT_REDIRECT_STDERR"
            | "GIT_EXEC_PATH"
            | "GIT_NAMESPACE"
            | "GIT_REPLACE_REF_BASE"
            | "GIT_SHALLOW_FILE"
            | "GIT_GRAFT_FILE"
            | "GIT_QUARANTINE_PATH"
            | "GIT_CEILING_DIRECTORIES"
            | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
            | "GIT_TEMPLATE_DIR"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_ASKPASS"
            | "SSH_ASKPASS"
            | "SSH_ASKPASS_REQUIRE"
            | "GIT_PROXY_COMMAND"
            | "GIT_ALLOW_PROTOCOL"
            | "GIT_PROTOCOL_FROM_USER"
            | "GIT_CURL_VERBOSE"
            | "GIT_SSL_NO_VERIFY"
    ) || key.starts_with("GIT_CONFIG_")
        || key.starts_with("GIT_TRACE")
}

pub(crate) fn resolve_trusted_executable(name: &str) -> Result<PathBuf> {
    if !matches!(name, "git" | "gh") {
        bail!("unsupported trusted executable name '{name}'");
    }
    #[cfg(target_os = "windows")]
    {
        let _ = name;
        bail!(
            "trusted Windows executable and ACL resolution is not implemented; refusing external command execution"
        );
    }
    #[cfg(unix)]
    {
        let mut inspected = BTreeSet::new();
        for candidate in trusted_executable_entry_candidates(name) {
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if !inspected.insert(canonical.clone()) {
                continue;
            }
            if validate_trusted_unix_executable(&canonical).is_ok() {
                return Ok(canonical);
            }
        }
        bail!(
            "no trusted root-owned, non-writable executable was found for '{name}' through a fixed system entry"
        );
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = name;
        bail!("trusted executable resolution is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_executable_entry_candidates(name: &str) -> [PathBuf; 3] {
    [
        Path::new("/run/current-system/sw/bin").join(name),
        Path::new("/usr/bin").join(name),
        Path::new("/bin").join(name),
    ]
}

#[cfg(unix)]
fn validate_trusted_unix_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect executable {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("trusted executable candidate is not a regular file");
    }
    let mode = metadata.permissions().mode();
    if metadata.uid() != 0 || mode & 0o022 != 0 || mode & 0o111 == 0 {
        bail!("trusted executable candidate has unsafe owner or mode");
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let directory_metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable ancestor {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && directory_metadata.uid() == 0
            && directory_metadata.permissions().mode() & 0o1000 != 0;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.uid() != 0
            || (!immutable_nix_store_root && directory_metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("trusted executable candidate has a writable or non-root ancestor");
        }
        ancestor = directory.parent();
    }
    let mut magic = [0_u8; 4];
    fs::File::open(path)
        .with_context(|| format!("failed to open executable {}", path.display()))?
        .read_exact(&mut magic)
        .with_context(|| format!("failed to inspect executable header {}", path.display()))?;
    if !is_native_executable_magic(magic) {
        if magic[..2] != *b"#!" {
            bail!("trusted executable candidate has an unsupported executable format");
        }
        validate_trusted_shebang(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_shebang(path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open executable script {}", path.display()))?
        .take(4096)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read executable script {}", path.display()))?;
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .context("trusted executable script omitted shebang")?;
    let interpreter = first_line
        .strip_prefix(b"#!")
        .context("trusted executable script omitted shebang marker")?;
    let interpreter = std::str::from_utf8(interpreter)
        .context("trusted executable script shebang was not UTF-8")?
        .trim()
        .split_ascii_whitespace()
        .next()
        .context("trusted executable script shebang omitted interpreter")?;
    let interpreter = Path::new(interpreter);
    if !interpreter.is_absolute() {
        bail!("trusted executable script shebang was not absolute");
    }
    let interpreter = fs::canonicalize(interpreter).with_context(|| {
        format!(
            "failed to resolve trusted script interpreter {}",
            interpreter.display()
        )
    })?;
    if interpreter == path {
        bail!("trusted executable script shebang referenced itself");
    }
    validate_trusted_unix_executable(&interpreter)
        .context("trusted executable script interpreter was unsafe")
}

fn is_native_executable_magic(magic: [u8; 4]) -> bool {
    magic == *b"\x7fELF"
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
        || magic[..2] == *b"MZ"
}

fn trusted_executable_search_path() -> Result<OsString> {
    #[cfg(unix)]
    {
        let directories = [
            PathBuf::from("/run/current-system/sw/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]
        .into_iter()
        .filter_map(|path| trusted_unix_search_directory(&path).ok())
        .collect::<Vec<_>>();
        if directories.is_empty() {
            bail!("no trusted system executable directories were available");
        }
        env::join_paths(directories).context("failed to build trusted executable PATH")
    }
    #[cfg(target_os = "windows")]
    {
        bail!("trusted Windows executable PATH is not implemented")
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        bail!("trusted executable PATH is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_unix_search_directory(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve executable directory {}", path.display()))?;
    let mut current = Some(canonical.as_path());
    while let Some(directory) = current {
        let metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable directory {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || (!immutable_nix_store_root && metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("executable search directory has unsafe owner or mode");
        }
        current = directory.parent();
    }
    Ok(canonical)
}

fn disabled_git_path(runtime_root: &Path, label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    runtime_root.join(format!(
        "maco-disabled-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn trusted_runtime_root(repo_root: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    let candidate = private_unix_runtime_root()?;
    #[cfg(target_os = "windows")]
    let candidate = windows_temp_path()?;
    #[cfg(not(any(unix, target_os = "windows")))]
    let candidate = env::temp_dir();

    let runtime_root = fs::canonicalize(&candidate).with_context(|| {
        format!(
            "failed to resolve trusted runtime directory {}",
            candidate.display()
        )
    })?;
    if !runtime_root.is_dir() {
        bail!(
            "trusted runtime path {} is not a directory",
            runtime_root.display()
        );
    }
    let repo_root = fs::canonicalize(repo_root)
        .with_context(|| format!("failed to resolve repository path {}", repo_root.display()))?;
    if runtime_root.starts_with(&repo_root) {
        bail!(
            "trusted runtime directory {} is inside repository {}; refusing capture-time writes",
            runtime_root.display(),
            repo_root.display()
        );
    }
    Ok(runtime_root)
}

#[cfg(unix)]
fn private_unix_runtime_root() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let uid = unsafe { libc::geteuid() };
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    let parent = match validate_private_unix_directory(&run_user, uid) {
        Ok(()) => run_user,
        Err(_) => {
            let temporary = PathBuf::from("/tmp");
            let metadata = fs::symlink_metadata(&temporary)
                .context("failed to inspect /tmp runtime fallback")?;
            let mode = metadata.permissions().mode();
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || mode & 0o1000 == 0
            {
                bail!("/tmp is not a root-owned sticky directory; refusing runtime fallback");
            }
            temporary
        }
    };
    let directory = parent.join(format!("maco-runtime-{uid}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to create private runtime {}", directory.display())
            })
        }
    }
    validate_private_unix_directory(&directory, uid)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_private_unix_directory(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!(
            "private runtime {} is not an owner-only real directory",
            path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_temp_path() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32;
    }

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: The buffer is writable for its declared length and the returned
    // length is checked before constructing the Windows path.
    let length = unsafe { GetTempPathW(buffer.len() as u32, buffer.as_mut_ptr()) };
    if length == 0 || length as usize >= buffer.len() {
        bail!("Windows GetTempPathW failed or returned an oversized path");
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
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

fn validation_binding_from_json(value: &Value) -> Result<Option<CandidateValidationBinding>> {
    let Some(binding) = value.get("validation_binding") else {
        return Ok(None);
    };
    let binding: CandidateValidationBinding = serde_json::from_value(binding.clone())
        .context("validation_binding must match the candidate validation binding schema")?;
    binding.canonicalized().map(Some)
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
    use git2::Signature;

    fn passed_validation_evidence_check() -> ValidationEvidenceCheck {
        ValidationEvidenceCheck {
            status: SafetyCheckStatus::Passed,
            binding_status: ValidationBindingStatus::Bound,
            message: None,
            paths: Vec::new(),
        }
    }

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
    fn candidate_capture_retries_until_two_complete_snapshots_match() {
        let mut captures = vec![Some(1_u8), Some(2), Some(3), Some(3)].into_iter();

        let captured = capture_two_matching(|| Ok(captures.next().flatten()))
            .expect("capture should stabilize");

        assert_eq!(captured, 3);
    }

    #[test]
    fn candidate_capture_fails_closed_after_bounded_instability() {
        let mut captures =
            vec![Some(1_u8), Some(2), Some(1), Some(2), Some(1), Some(2)].into_iter();

        let error = capture_two_matching(|| Ok(captures.next().flatten()))
            .expect_err("capture should remain unstable");

        assert!(error.to_string().contains("state changed"));
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
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &failed,
            stale_base: &passed,
            apply_check: &passed,
            unclaimed_edits: &failed,
            validation: &passed,
            validation_evidence: &evidence,
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
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &failed,
            stale_base: &failed,
            apply_check: &passed,
            unclaimed_edits: &passed,
            validation: &passed,
            validation_evidence: &evidence,
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
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &passed,
            stale_base: &passed,
            apply_check: &failed,
            unclaimed_edits: &passed,
            validation: &passed,
            validation_evidence: &evidence,
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
    fn repo_common_lock_persists_file_and_kernel_unlocks_on_drop() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let lock = RepoCommonLock::acquire(&repo_path, "merge-apply").expect("acquire lock");
        let path = repo_path
            .join(".git/maco/state")
            .join(REPOSITORY_MUTATION_LOCK_FILE);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open stable lock file");
        assert!(matches!(
            contender.try_lock().expect_err("kernel lock must contend"),
            fs::TryLockError::WouldBlock
        ));

        drop(lock);
        contender.try_lock().expect("kernel lock released on drop");
        contender.unlock().expect("unlock contender");

        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            for directory in [
                repo_path.join(".git/maco"),
                repo_path.join(".git/maco/state"),
            ] {
                assert_eq!(
                    fs::metadata(directory)
                        .expect("managed directory metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
        }
    }

    #[test]
    fn initialized_repository_fingerprint_ignores_ignored_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(temp.path()).expect("init repo");
        fs::write(temp.path().join(".gitignore"), "ignored/\n").expect("write ignore");
        fs::write(temp.path().join("tracked.txt"), "tracked\n").expect("write tracked");
        let mut index = repo.index().expect("open index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("add files");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit");

        let before = validation_repository_fingerprint(&repo, temp.path(), None, 0)
            .expect("baseline fingerprint");
        fs::create_dir(temp.path().join("ignored")).expect("create ignored output");
        fs::write(
            temp.path().join("ignored/build.bin"),
            vec![7_u8; 1024 * 1024],
        )
        .expect("write ignored output");
        let after = validation_repository_fingerprint(&repo, temp.path(), None, 0)
            .expect("updated fingerprint");

        assert_eq!(before, after);
    }

    #[test]
    fn initialized_submodule_marker_directory_is_not_recursively_hashed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join(".git");
        fs::create_dir(&marker).expect("create marker directory");
        let large = fs::File::create(marker.join("large-object")).expect("create large object");
        large
            .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
            .expect("size large object");

        let fingerprint = validation_submodule_marker_fingerprint(&marker)
            .expect("fingerprint marker identity only");

        assert_eq!(fingerprint.entries.len(), 1);
        assert_eq!(
            fingerprint.entries[0].kind,
            ValidationFilesystemEntryKind::Directory
        );
    }

    #[test]
    fn uninitialized_submodule_raw_fingerprint_fails_with_typed_size_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let large = fs::File::create(temp.path().join("large.bin")).expect("create large file");
        large
            .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
            .expect("size large file");

        let error = validation_filesystem_fingerprint(temp.path())
            .expect_err("oversized raw fallback must fail closed");

        assert!(matches!(
            error.downcast_ref::<ValidationFilesystemFingerprintError>(),
            Some(ValidationFilesystemFingerprintError::SingleFileTooLarge { .. })
        ));
    }

    #[test]
    fn candidate_validation_sandbox_is_removed_when_patch_apply_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir(&repo_path).expect("create repo dir");
        let repo = Repository::init(&repo_path).expect("init repo");
        fs::write(repo_path.join("README.md"), "# Smoke\n").expect("write readme");
        let mut index = repo.index().expect("open index");
        index.add_path(Path::new("README.md")).expect("add readme");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("create signature");
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial commit",
            &tree,
            &[],
        )
        .expect("commit");

        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let preview = MergeApplyPreview {
            candidate: MergeCandidate {
                metadata: WorktreeMergeMetadata {
                    agent_id: "agent-a".to_string(),
                    worktree_path: repo_path.clone(),
                    branch: "maco/agent-a".to_string(),
                    primary_repo_root: repo_path.clone(),
                    primary_head: None,
                    agent_head: None,
                    merge_base: None,
                    base_matches_primary: Some(true),
                },
                claimed_paths: vec![PathBuf::from("README.md")],
                changed_paths: vec![PathBuf::from("README.md")],
                changes: vec![ChangedPath {
                    path: PathBuf::from("README.md"),
                    kind: ChangeKind::Modified,
                }],
                unclaimed_changed_paths: Vec::new(),
                diff: DiffOutput {
                    summary: OutputSummary {
                        text: "invalid patch".to_string(),
                        truncated: false,
                    },
                    full: Some("this is not a patch\n".to_string()),
                },
                validations: Vec::new(),
                validation_binding: CandidateValidationBinding {
                    version: VALIDATION_BINDING_VERSION,
                    agent_id: "agent-a".to_string(),
                    primary_head: None,
                    agent_head: None,
                    merge_base: None,
                    diff_oid: Oid::hash_object(ObjectType::Blob, b"this is not a patch\n")
                        .expect("hash invalid patch")
                        .to_string(),
                },
                validation_evidence: ValidationEvidenceBundle::default(),
                raw_diff: b"this is not a patch\n".to_vec(),
            },
            safety: MergeApplySafety {
                primary_state_unchanged: passed.clone(),
                dirty_primary: passed.clone(),
                stale_base: passed.clone(),
                apply_check: passed.clone(),
                unclaimed_edits: passed.clone(),
                validation: passed,
                validation_evidence: passed_validation_evidence_check(),
                validation_required: false,
                candidate_validation_commands: Vec::new(),
                force_options: MergeForceOptions::default(),
                apply_mode: ApplyMode::Direct,
                readiness: ApplyReadiness {
                    status: ApplyReadinessStatus::Safe,
                    blockers: Vec::new(),
                    forced: Vec::new(),
                    details: Vec::new(),
                },
            },
        };

        let result = CandidateValidationSandbox::create(&preview);

        assert!(result.is_err());
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .expect("list worktrees");
        assert!(output.status.success());
        let worktrees = String::from_utf8_lossy(&output.stdout);
        assert!(
            !worktrees.contains("maco-candidate-validation-"),
            "{worktrees}"
        );
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
    fn native_executable_magic_accepts_thin_and_fat_macho() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            assert!(is_native_executable_magic(magic));
        }
        assert!(!is_native_executable_magic(*b"#!/b"));
    }

    #[test]
    fn network_environment_classifies_command_execution_overrides_as_injection() {
        for key in [
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_PROXY_COMMAND",
            "GIT_CURL_VERBOSE",
        ] {
            assert!(is_git_injection_environment_key(key), "missed {key}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_executable_validation_rejects_user_owned_path_shadow() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let shadow = temp.path().join("git");
        fs::write(&shadow, b"\x7fELFfake").expect("write shadow");
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o755)).expect("chmod shadow");

        assert!(validate_trusted_unix_executable(&shadow).is_err());
        assert!(resolve_trusted_executable("git").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_executable_candidates_exclude_direct_nix_store_path_entries() {
        let candidates = trusted_executable_entry_candidates("git");
        assert_eq!(
            candidates,
            [
                PathBuf::from("/run/current-system/sw/bin/git"),
                PathBuf::from("/usr/bin/git"),
                PathBuf::from("/bin/git"),
            ]
        );
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.starts_with("/nix/store")));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_runtime_is_owner_only_and_ignores_ambient_temp_paths() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().expect("repo tempdir");
        let runtime = trusted_runtime_root(temp.path()).expect("trusted runtime");
        let metadata = fs::symlink_metadata(&runtime).expect("runtime metadata");
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(!runtime.starts_with(temp.path()));
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
