use crate::{
    llm::{RedactionSummary, Redactor},
    merge::{
        self, ApplyBlocker, ApplyBlockerDetail, ApplyBlockerDisposition, ApplyReadinessStatus,
        MergeApplyPreview, MergeCollectOptions, MergeForceOptions, MergePreviewOptions,
        OutputSummary, RepoCommonLock, SafetyCheckStatus, ValidationEvidenceBundle,
        ValidationReport,
    },
    process_runner::StdinMode,
};
use anyhow::{bail, Context, Result};
use git2::{ObjectType, Oid, Repository};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const SUMMARY_LIMIT: usize = 12 * 1024;
const PUBLICATION_JOURNAL_VERSION: u32 = 2;
const REMOTE_BINDING_SECRET_FILE: &str = "publication-remote-binding.key";
const REMOTE_BINDING_SECRET_BYTES: usize = 32;
const GH_CAPTURE_LIMIT_BYTES: usize = 1024 * 1024;
const GH_STDIN_LIMIT_BYTES: usize = 1024 * 1024;
const PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES: usize = 96;
const PUBLICATION_JOURNAL_MAX_RECORDS: usize = 64;
const PUBLICATION_JOURNAL_MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationRemoteTransport {
    NonSsh,
    Ssh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeKind {
    Fake,
    Git,
    Github,
}

impl ForgeKind {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value {
            "fake" => Ok(Self::Fake),
            "git" => Ok(Self::Git),
            "github" => Ok(Self::Github),
            _ => Err("expected one of: fake, git, github".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrPublicationOptions {
    pub repo: PathBuf,
    pub agent_id: String,
    pub claimed_paths: Vec<PathBuf>,
    pub validations: Vec<ValidationReport>,
    pub forge: ForgeKind,
    pub draft: bool,
}

#[derive(Debug, Clone)]
pub struct IssuePublicationOptions {
    pub repo: PathBuf,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub forge: ForgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrPublicationStatus {
    Preview,
    Blocked,
    Published,
}

#[derive(Debug, Serialize)]
pub struct PrPublicationReport {
    pub status: PrPublicationStatus,
    pub agent_id: String,
    pub branch: String,
    pub base: String,
    pub base_head: Option<String>,
    pub remote: Option<String>,
    pub forge: ForgeKind,
    pub draft: bool,
    pub title: String,
    pub body_summary: OutputSummary,
    #[serde(serialize_with = "serialize_paths")]
    pub changed_paths: Vec<PathBuf>,
    pub validation_status: SafetyCheckStatus,
    pub validation_required: bool,
    pub readiness: ApplyReadinessStatus,
    pub blockers: Vec<ApplyBlocker>,
    pub commit_id: Option<String>,
    pub head_id: Option<String>,
    pub pr_url: Option<String>,
    pub pushed: bool,
    pub created: bool,
    pub publication_receipt: Option<PrPublicationReceipt>,
    pub next_action: String,
    pub preview: MergeApplyPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrPublicationReceipt {
    pub version: u32,
    pub transaction_id: String,
    pub sequence: u64,
    pub phase: PublicationTransactionPhase,
    pub expected_oid: String,
    pub expected_base_oid: Option<String>,
    pub remote_ref: String,
    pub github_repository: Option<String>,
    pub push_observed_oid: Option<String>,
    pub pr_url: Option<String>,
    pub pr_head_oid: Option<String>,
    pub pr_base: Option<String>,
    pub pr_state: Option<String>,
    pub pr_is_draft: Option<bool>,
    pub create_attempted: bool,
    pub created_by_transaction: bool,
    pub observed_existing_pr: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationTransactionPhase {
    Prepared,
    PushObserved,
    PrObserved,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationTransactionJournal {
    version: u32,
    transaction_id: String,
    sequence: u64,
    agent_id: String,
    forge: ForgeKind,
    expected_oid: String,
    expected_base_oid: Option<String>,
    remote_name: String,
    remote_binding_digest: String,
    remote_display: String,
    remote_ref: String,
    remote_branch: String,
    github_repository: Option<GithubRepositoryIdentity>,
    base: String,
    draft: bool,
    phase: PublicationTransactionPhase,
    push_observed_oid: Option<String>,
    pr_url: Option<String>,
    pr_head_oid: Option<String>,
    pr_base: Option<String>,
    pr_state: Option<String>,
    pr_is_draft: Option<bool>,
    pr_number: Option<u64>,
    create_attempted: bool,
    created_by_transaction: bool,
    observed_existing_pr: bool,
    last_error: Option<String>,
    updated_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GithubRepositoryIdentity {
    host: String,
    owner: String,
    name: String,
}

impl GithubRepositoryIdentity {
    fn selector(&self) -> String {
        format!("{}/{}/{}", self.host, self.owner, self.name)
    }
}

struct PublicationTransaction {
    directory: PathBuf,
    journal: PublicationTransactionJournal,
    remote_url: String,
    remote_private_values: Vec<String>,
}

struct PublicationGitContext {
    directory: PathBuf,
    _runtime_directory: merge::PrivateRuntimeDirectory,
    environment: BTreeMap<String, String>,
}

struct GhCommandContext {
    runtime_directory: merge::PrivateRuntimeDirectory,
    environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct IssuePublicationReport {
    pub title: String,
    pub redacted_body: String,
    pub redactions: RedactionSummary,
    pub labels: Vec<String>,
    pub forge: ForgeKind,
    pub url: Option<String>,
    pub created: bool,
    pub next_action: String,
}

#[derive(Debug, Clone)]
struct GithubPrResult {
    url: String,
    head_oid: String,
    base_oid: String,
    number: u64,
    base_ref_name: String,
    state: String,
    is_draft: bool,
    created: bool,
}

struct GithubCreateOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait GithubApi {
    fn list(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>>;

    fn view(
        &mut self,
        worktree_path: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult>;

    #[allow(clippy::too_many_arguments)]
    fn create(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubCreateOutput>;
}

struct CliGithubApi;

impl GithubApi for CliGithubApi {
    fn list(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>> {
        cli_github_pr_list(worktree_path, branch, repository)
    }

    fn view(
        &mut self,
        worktree_path: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult> {
        cli_github_pr_view(worktree_path, selector, repository)
    }

    fn create(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubCreateOutput> {
        cli_github_pr_create(worktree_path, branch, base, title, body, draft, repository)
    }
}

pub fn preview_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    preview_pr_with_validation_requirement(options, false)
}

pub fn preview_pr_with_validation_requirement(
    options: PrPublicationOptions,
    require_validation: bool,
) -> Result<PrPublicationReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    preview_pr_with_validation_evidence(options, require_validation, evidence)
}

pub fn preview_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    let preview = build_merge_preview(&options, require_validation, validation_evidence)?;
    let primary_repo = Repository::open(&preview.candidate.metadata.primary_repo_root)
        .context("failed to open primary repository")?;
    let base = current_branch_name(&primary_repo).unwrap_or_else(|| "HEAD".to_string());
    let body = pr_body(&preview);
    let status = if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        PrPublicationStatus::Blocked
    } else {
        PrPublicationStatus::Preview
    };
    let next_action = match status {
        PrPublicationStatus::Blocked => "resolve merge-preview blockers before publishing",
        PrPublicationStatus::Preview => "run pr publish with an explicit forge when ready",
        PrPublicationStatus::Published => "review the created pull request",
    }
    .to_string();

    Ok(PrPublicationReport {
        status,
        agent_id: options.agent_id,
        branch: preview.candidate.metadata.branch.clone(),
        base,
        base_head: preview.candidate.metadata.primary_head.clone(),
        remote: remote_url(&primary_repo, "origin")
            .ok()
            .map(|url| redact_remote_url(&url)),
        forge: options.forge,
        draft: options.draft,
        title: pr_title(&preview),
        body_summary: summarize_text(&body, SUMMARY_LIMIT),
        changed_paths: preview.candidate.changed_paths.clone(),
        validation_status: preview.safety.validation.status,
        validation_required: preview.safety.validation_required,
        readiness: preview.safety.readiness.status,
        blockers: preview.safety.readiness.blockers.clone(),
        commit_id: None,
        head_id: preview.candidate.metadata.agent_head.clone(),
        pr_url: None,
        pushed: false,
        created: false,
        publication_receipt: None,
        next_action,
        preview,
    })
}

pub fn publish_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    publish_pr_with_validation_requirement(options, false)
}

pub fn publish_pr_with_validation_requirement(
    options: PrPublicationOptions,
    require_validation: bool,
) -> Result<PrPublicationReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    publish_pr_with_validation_evidence(options, require_validation, evidence)
}

pub fn publish_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "pr-publish")?;
    let mut report = preview_pr_with_validation_evidence(
        options.clone(),
        require_validation,
        validation_evidence.clone(),
    )?;
    if report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(report);
    }

    let worktree_path = report.preview.candidate.metadata.worktree_path.clone();
    let needs_commit = has_uncommitted_changes(&worktree_path)?;
    if require_validation && needs_commit {
        return Ok(block_publication(
            report,
            ApplyBlocker::ValidationMissing,
            "candidate-bound publication requires a clean, committed agent candidate",
            "commit the candidate, rerun pr preview, validate that exact binding, create a bound envelope, then rerun pr publish",
        ));
    }

    let originally_reviewed = report.preview.candidate.validation_binding.clone();
    let mut local_commit = None;
    if needs_commit {
        report = preview_pr_with_validation_evidence(
            options.clone(),
            false,
            validation_evidence.clone(),
        )?;
        if report.readiness == ApplyReadinessStatus::Blocked {
            return Ok(report);
        }
        if has_uncommitted_changes(&worktree_path)? {
            let commit_id = commit_agent_changes(
                &worktree_path,
                &report.agent_id,
                &report.changed_paths,
                &report.preview,
            )?;
            local_commit = Some(commit_id.to_string());
            if has_uncommitted_changes(&worktree_path)? {
                let mut changed_during_commit = preview_pr_with_validation_evidence(
                    options.clone(),
                    false,
                    validation_evidence.clone(),
                )?;
                changed_during_commit.commit_id = local_commit.clone();
                changed_during_commit.head_id = changed_during_commit
                    .preview
                    .candidate
                    .metadata
                    .agent_head
                    .clone();
                return Ok(block_publication(
                    changed_during_commit,
                    ApplyBlocker::StaleBase,
                    "agent worktree changed while the local publication commit was being created",
                    "review and commit the remaining worktree changes, then rerun pr preview before publishing",
                ));
            }
        }
    }

    let mut after_local = preview_pr_with_validation_evidence(
        options.clone(),
        require_validation,
        validation_evidence.clone(),
    )?;
    if after_local.readiness == ApplyReadinessStatus::Blocked {
        after_local.commit_id = local_commit.clone();
        after_local.head_id = after_local.preview.candidate.metadata.agent_head.clone();
        return Ok(after_local);
    }
    if !needs_commit && after_local.preview.candidate.validation_binding != originally_reviewed {
        return Ok(block_publication(
            after_local,
            ApplyBlocker::StaleBase,
            "agent or primary candidate changed after the publication preview",
            "rerun pr preview and validation for the current committed candidate before publishing",
        ));
    }
    after_local.commit_id = local_commit.clone();
    after_local.head_id = after_local.preview.candidate.metadata.agent_head.clone();
    let reviewed_binding = after_local.preview.candidate.validation_binding.clone();

    let primary_repo = Repository::open(&repo_root).context("failed to open primary repository")?;
    let raw_remote_url = match after_local.forge {
        ForgeKind::Fake => None,
        ForgeKind::Git => Some(
            remote_url(&primary_repo, "origin")
                .context("Git publication requires an 'origin' remote")?,
        ),
        ForgeKind::Github => Some(
            remote_url(&primary_repo, "origin")
                .context("GitHub PR publication requires an 'origin' remote")?,
        ),
    };

    let mut final_report =
        preview_pr_with_validation_evidence(options, require_validation, validation_evidence)?;
    final_report.commit_id = local_commit;
    final_report.head_id = final_report.preview.candidate.metadata.agent_head.clone();
    final_report.remote = raw_remote_url.as_deref().map(redact_remote_url);
    if final_report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(final_report);
    }
    if final_report.preview.candidate.validation_binding != reviewed_binding {
        return Ok(block_publication(
            final_report,
            ApplyBlocker::StaleBase,
            "agent or primary candidate changed before external publication",
            "rerun pr preview and validation for the current committed candidate before publishing",
        ));
    }
    report = final_report;

    match report.forge {
        ForgeKind::Fake => {
            report.pr_url = Some(fake_pr_url(
                &report.agent_id,
                &report.branch,
                &report.changed_paths,
            ));
            report.created = true;
            report.next_action = "review the fake pull request report locally".to_string();
        }
        ForgeKind::Git => {
            let expected_head = report
                .head_id
                .as_deref()
                .context("validated publication candidate has no HEAD commit")?
                .to_string();
            let remote_url = raw_remote_url
                .as_deref()
                .context("Git publication report has no origin URL")?;
            let mut transaction = PublicationTransaction::open(
                &repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) = ensure_remote_expected_commit(&worktree_path, &mut transaction) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.pushed = true;
            report.created = false;
            report.pr_url = None;
            report.next_action = "open a pull request on your Git host manually".to_string();
            let previous = transaction.journal.clone();
            transaction.advance_phase(PublicationTransactionPhase::Completed);
            transaction.journal.last_error = None;
            if let Err(error) = transaction.persist_if_changed(&previous) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.publication_receipt = Some(transaction.receipt());
        }
        ForgeKind::Github => {
            let body = pr_body(&report.preview);
            merge::resolve_trusted_executable("gh")
                .context("GitHub publication requires a trusted gh executable")?;
            let expected_head = report
                .head_id
                .as_deref()
                .context("validated publication candidate has no HEAD commit")?
                .to_string();
            let remote_url = raw_remote_url
                .as_deref()
                .context("GitHub publication report has no origin URL")?;
            let mut transaction = PublicationTransaction::open(
                &repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) =
                ensure_github_remote_expected_commit(&worktree_path, &mut transaction)
            {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.pushed = true;
            report.publication_receipt = Some(transaction.receipt());
            let github =
                match reconcile_github_pr(&worktree_path, &mut transaction, &report.title, &body) {
                    Ok(github) => github,
                    Err(error) => {
                        return Ok(publication_transaction_failure(
                            report,
                            &mut transaction,
                            error,
                        ))
                    }
                };
            report.pr_url = Some(github.url);
            report.pushed = true;
            report.created = github.created;
            report.next_action = "review the draft pull request on GitHub".to_string();
            let previous = transaction.journal.clone();
            transaction.advance_phase(PublicationTransactionPhase::Completed);
            transaction.journal.last_error = None;
            if let Err(error) = transaction.persist_if_changed(&previous) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.publication_receipt = Some(transaction.receipt());
        }
    }

    report.status = PrPublicationStatus::Published;
    Ok(report)
}

fn block_publication(
    mut report: PrPublicationReport,
    blocker: ApplyBlocker,
    message: &str,
    next_action: &str,
) -> PrPublicationReport {
    let paths = report.preview.candidate.changed_paths.clone();
    report.preview.safety.readiness.blockers.push(blocker);
    report.preview.safety.readiness.blockers.sort();
    report.preview.safety.readiness.blockers.dedup();
    report
        .preview
        .safety
        .readiness
        .details
        .push(ApplyBlockerDetail {
            kind: blocker,
            disposition: ApplyBlockerDisposition::Blocked,
            check_status: SafetyCheckStatus::Failed,
            paths,
            message: Some(message.to_string()),
            validation_reports: report.preview.candidate.validations.clone(),
            validation_commands: report.preview.safety.candidate_validation_commands.clone(),
            next_safe_operation: Some(next_action.to_string()),
        });
    report.preview.safety.readiness.status = ApplyReadinessStatus::Blocked;
    report.status = PrPublicationStatus::Blocked;
    report.readiness = ApplyReadinessStatus::Blocked;
    report.blockers = report.preview.safety.readiness.blockers.clone();
    report.pushed = false;
    report.created = false;
    report.pr_url = None;
    report.next_action = next_action.to_string();
    report
}

fn publication_transaction_failure(
    mut report: PrPublicationReport,
    transaction: &mut PublicationTransaction,
    error: anyhow::Error,
) -> PrPublicationReport {
    let mut redactor = Redactor::new();
    for value in &transaction.remote_private_values {
        redactor = redactor.with_private_value("remote-credential", value.clone());
    }
    let mut message = redactor.redact(&format!("{error:#}")).text;
    transaction.journal.last_error = Some(message.clone());
    if let Err(journal_error) = transaction.persist() {
        message.push_str(&format!(
            "; additionally failed to persist the latest transaction error: {journal_error:#}"
        ));
        message = redactor.redact(&message).text;
        transaction.journal.last_error = Some(message.clone());
    }
    report.status = PrPublicationStatus::Blocked;
    // A failing attempt has no current end-to-end observation. The durable receipt retains the
    // last verified push OID, but the report must not present that historical observation as the
    // current attempt's success.
    report.pushed = false;
    report.pr_url = transaction.journal.pr_url.clone();
    report.created = transaction.journal.created_by_transaction;
    report.publication_receipt = Some(transaction.receipt());
    report.next_action = format!(
        "publication transaction is incomplete: {message}; rerun the same pr publish command to reconcile the durable receipt"
    );
    report
}

fn discover_primary_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("PR publication requires a non-bare primary repository")
}

pub fn preview_issue(options: IssuePublicationOptions) -> Result<IssuePublicationReport> {
    let (redacted_body, redactions) = redacted_body(&options.body);
    Ok(IssuePublicationReport {
        title: normalize_title(&options.title)?,
        redacted_body,
        redactions,
        labels: normalized_labels(options.labels),
        forge: options.forge,
        url: None,
        created: false,
        next_action: "run issue create with an explicit forge when ready".to_string(),
    })
}

pub fn create_issue(options: IssuePublicationOptions) -> Result<IssuePublicationReport> {
    let repo = options.repo.clone();
    let mut report = preview_issue(options)?;
    let url = match report.forge {
        ForgeKind::Fake => fake_issue_url(&report.title, &report.redacted_body, &report.labels),
        ForgeKind::Git => bail!("git forge does not create issues; use fake or github"),
        ForgeKind::Github => {
            create_github_issue(&repo, &report.title, &report.redacted_body, &report.labels)?
        }
    };
    report.url = Some(url);
    report.created = true;
    report.next_action = match report.forge {
        ForgeKind::Fake => "review the fake issue report locally",
        ForgeKind::Git => "use fake or github issue publication",
        ForgeKind::Github => "review the created GitHub issue",
    }
    .to_string();
    Ok(report)
}

fn build_merge_preview(
    options: &PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyPreview> {
    merge::preview_merge_apply_with_evidence(
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: options.repo.clone(),
                agent_id: options.agent_id.clone(),
                claimed_paths: options.claimed_paths.clone(),
                include_full_diff: true,
                diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            forces: MergeForceOptions::default(),
            require_validation,
        },
        validation_evidence,
    )
}

fn pr_title(preview: &MergeApplyPreview) -> String {
    format!("Agent {} changes", preview.candidate.metadata.agent_id)
}

fn pr_body(preview: &MergeApplyPreview) -> String {
    let changed = preview
        .candidate
        .changed_paths
        .iter()
        .map(|path| format!("- {}", merge::path_json_text(path)))
        .collect::<Vec<_>>()
        .join("\n");
    let changed = if changed.is_empty() {
        "- no changed paths".to_string()
    } else {
        changed
    };
    format!(
        "Agent: {}\nBranch: {}\nBase: {}\nReadiness: {:?}\n\nChanged paths:\n{}\n",
        preview.candidate.metadata.agent_id,
        preview.candidate.metadata.branch,
        preview
            .candidate
            .metadata
            .primary_head
            .as_deref()
            .unwrap_or("unknown"),
        preview.safety.readiness.status,
        changed
    )
}

fn has_uncommitted_changes(worktree_path: &Path) -> Result<bool> {
    let repo = Repository::open(worktree_path)
        .with_context(|| format!("failed to open agent worktree {}", worktree_path.display()))?;
    let mut options = git2::StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect agent worktree status")?;
    Ok(!statuses.is_empty())
}

fn commit_agent_changes(
    worktree_path: &Path,
    agent_id: &str,
    changed_paths: &[PathBuf],
    preview: &MergeApplyPreview,
) -> Result<Oid> {
    if changed_paths.is_empty() {
        bail!("agent worktree has local changes but merge preview found no changed paths");
    }

    let repo = Repository::open(worktree_path)
        .with_context(|| format!("failed to open agent worktree {}", worktree_path.display()))?;
    let signature = repo.signature().context(
        "git identity missing; configure user.name and user.email before publishing uncommitted agent changes",
    )?;
    let parent = repo
        .head()
        .context("agent worktree has no HEAD commit")?
        .peel_to_commit()
        .context("failed to read agent HEAD commit")?;
    let (captured_paths, raw_diff) =
        merge::capture_worktree_diff_from_commit(&repo, worktree_path, parent.id())?;
    let allowed = changed_paths.iter().collect::<BTreeSet<_>>();
    let unexpected = captured_paths
        .iter()
        .filter(|path| !allowed.contains(path))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        bail!(
            "agent worktree changed outside the reviewed publication paths during commit capture: {:?}",
            unexpected
        );
    }
    let diff = git2::Diff::from_buffer(&raw_diff)
        .context("failed to parse isolated publication commit diff")?;
    let parent_tree = parent.tree().context("failed to read agent parent tree")?;
    let mut index = repo
        .apply_to_tree(&parent_tree, &diff, None)
        .context("failed to apply isolated publication diff to parent tree")?;
    let tree_id = index
        .write_tree_to(&repo)
        .context("failed to write publication commit tree")?;
    let tree = repo
        .find_tree(tree_id)
        .context("failed to read publication commit tree")?;
    if parent.tree_id() == tree_id {
        return Ok(parent.id());
    }
    let parents = [&parent];
    let message = commit_message(agent_id, preview);
    let commit_id = repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            &message,
            &tree,
            &parents,
        )
        .context("failed to commit agent worktree changes")?;
    let mut worktree_index = repo
        .index()
        .context("failed to reopen publication worktree index")?;
    worktree_index
        .read_tree(&tree)
        .context("failed to align publication worktree index with committed tree")?;
    worktree_index
        .write()
        .context("failed to persist publication worktree index")?;
    Ok(commit_id)
}

fn commit_message(agent_id: &str, preview: &MergeApplyPreview) -> String {
    let paths = preview
        .candidate
        .changed_paths
        .iter()
        .map(|path| format!("- {}", merge::path_json_text(path)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "maco: publish {agent_id} changes\n\nGenerated by maco pr publish after merge-preview gates passed.\n\nChanged paths:\n{paths}\n"
    )
}

fn current_branch_name(repo: &Repository) -> Option<String> {
    repo.head()
        .ok()
        .and_then(|head| head.shorthand().map(ToOwned::to_owned))
}

fn remote_url(repo: &Repository, name: &str) -> Result<String> {
    let remote = repo
        .find_remote(name)
        .with_context(|| format!("remote '{name}' is not configured"))?;
    remote
        .url()
        .map(ToOwned::to_owned)
        .with_context(|| format!("remote '{name}' has no URL"))
}

fn redact_remote_url(url: &str) -> String {
    let query = url.find('?');
    let fragment = url.find('#');
    let identity_end = query.into_iter().chain(fragment).min().unwrap_or(url.len());
    let identity = &url[..identity_end];
    let mut redacted = if let Some(scheme_end) = identity.find("://") {
        let authority_start = scheme_end + 3;
        let authority_end = identity[authority_start..]
            .find('/')
            .map(|offset| authority_start + offset)
            .unwrap_or(identity.len());
        let authority = &identity[authority_start..authority_end];
        if let Some(at) = authority.rfind('@') {
            let host = &authority[at + 1..];
            format!(
                "{}<redacted>@{}{}",
                &identity[..authority_start],
                host,
                &identity[authority_end..]
            )
        } else {
            identity.to_string()
        }
    } else if let Some(at) = identity.find('@') {
        if identity[at + 1..].contains(':') {
            format!("<redacted>@{}", &identity[at + 1..])
        } else {
            identity.to_string()
        }
    } else {
        identity.to_string()
    };
    if query.is_some_and(|index| fragment.is_none_or(|fragment| index < fragment)) {
        redacted.push_str("?<redacted>");
    }
    if fragment.is_some() {
        redacted.push_str("#<redacted>");
    }
    redacted
}

fn remote_private_values(url: &str) -> Vec<String> {
    let mut values = vec![url.to_string()];
    if let Some(scheme_end) = url.find("://") {
        let authority_start = scheme_end + 3;
        let authority_end = url[authority_start..]
            .find(['/', '?', '#'])
            .map(|offset| authority_start + offset)
            .unwrap_or(url.len());
        let authority = &url[authority_start..authority_end];
        if let Some(at) = authority.rfind('@') {
            let userinfo = &authority[..at];
            if !userinfo.is_empty() {
                values.push(userinfo.to_string());
                if let Some((user, password)) = userinfo.split_once(':') {
                    if !user.is_empty() {
                        values.push(user.to_string());
                    }
                    if !password.is_empty() {
                        values.push(password.to_string());
                    }
                }
            }
        }
    }
    if let Some(query) = url.split_once('?').map(|(_, suffix)| suffix) {
        let query = query.split('#').next().unwrap_or(query);
        if !query.is_empty() {
            values.push(query.to_string());
            for item in query.split('&').filter(|item| !item.is_empty()) {
                values.push(item.to_string());
                if let Some((_, value)) = item.split_once('=') {
                    if !value.is_empty() {
                        values.push(value.to_string());
                    }
                }
            }
        }
    }
    if let Some((_, fragment)) = url.split_once('#') {
        if !fragment.is_empty() {
            values.push(fragment.to_string());
        }
    }
    sort_private_values(&mut values);
    values
}

fn publication_private_values(remote_url: &str) -> Vec<String> {
    let mut values = remote_private_values(remote_url);
    values.extend(network_auth_private_values());
    sort_private_values(&mut values);
    values
}

fn network_auth_private_values() -> Vec<String> {
    let mut values = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "SSH_AUTH_SOCK",
    ]
    .into_iter()
    .filter_map(|key| env::var(key).ok())
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>();
    sort_private_values(&mut values);
    values
}

fn sort_private_values(values: &mut Vec<String>) {
    values.retain(|value| !value.is_empty());
    values.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    values.dedup();
}

fn github_repository_identity(remote_url: &str) -> Result<GithubRepositoryIdentity> {
    let identity_end = remote_url.find(['?', '#']).unwrap_or(remote_url.len());
    let identity = remote_url[..identity_end].trim_end_matches('/');
    let (host, path) = if let Some((scheme, remainder)) = identity.split_once("://") {
        if !matches!(scheme, "https" | "ssh" | "git+ssh" | "ssh+git") {
            bail!(
                "GitHub publication requires an https://, ssh://, git+ssh://, or ssh+git:// origin URL"
            );
        }
        let slash = remainder
            .find('/')
            .context("GitHub origin URL omitted owner/repository path")?;
        let authority = &remainder[..slash];
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        (host, &remainder[slash + 1..])
    } else {
        let (authority, path) = identity.split_once(':').context(
            "GitHub publication requires a supported HTTPS, SSH, or SCP-style origin URL",
        )?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        (host, path)
    };
    let host = normalize_github_host(host)?;
    let mut components = path.split('/');
    let owner = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted owner")?;
    let raw_name = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted repository")?;
    if components.next().is_some() {
        bail!("GitHub origin URL must contain exactly owner/repository");
    }
    let name = raw_name.strip_suffix(".git").unwrap_or(raw_name);
    validate_github_slug(owner, "owner")?;
    validate_github_slug(name, "repository")?;
    Ok(GithubRepositoryIdentity {
        host,
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

fn normalize_github_host(host: &str) -> Result<String> {
    let (hostname, port) = host
        .rsplit_once(':')
        .map_or((host, None), |(hostname, port)| (hostname, Some(port)));
    if hostname.is_empty()
        || hostname.contains(':')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        bail!("GitHub origin URL host is invalid");
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("GitHub origin URL port is invalid");
        }
    }
    Ok(host.to_ascii_lowercase())
}

fn validate_github_slug(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("GitHub {label} component is invalid");
    }
    Ok(())
}

fn validate_github_receipt_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<()> {
    let identity_end = url.find(['?', '#']).unwrap_or(url.len());
    let identity = &url[..identity_end];
    let (scheme, remainder) = identity
        .split_once("://")
        .context("GitHub PR receipt URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub PR receipt URL was not HTTPS");
    }
    let slash = remainder
        .find('/')
        .context("GitHub PR receipt URL omitted repository path")?;
    let host = normalize_github_host(&remainder[..slash])?;
    let components = remainder[slash + 1..].split('/').collect::<Vec<_>>();
    if components.len() != 4
        || components[2] != "pull"
        || components[3].parse::<u64>().ok() != Some(expected_number)
    {
        bail!("GitHub PR receipt URL did not identify the expected pull request");
    }
    if host != expected.host
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub PR receipt URL did not match the bound forge repository");
    }
    Ok(())
}

fn publication_remote_binding_digest(
    secret: &[u8],
    remote_name: &str,
    remote_url: &str,
) -> Result<String> {
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!("publication remote binding secret has an invalid length");
    }
    let mut input = b"maco-publication-remote-binding-v1\0".to_vec();
    input.extend_from_slice(secret);
    input.push(0);
    input.extend_from_slice(remote_name.as_bytes());
    input.push(0);
    input.extend_from_slice(remote_url.as_bytes());
    Ok(Oid::hash_object(ObjectType::Blob, &input)
        .context("failed to digest publication remote binding")?
        .to_string())
}

fn load_or_create_remote_binding_secret(state_directory: &Path) -> Result<Vec<u8>> {
    let path = state_directory.join(REMOTE_BINDING_SECRET_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_remote_binding_secret(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect publication remote binding key {}",
                    path.display()
                )
            })
        }
    }
    refuse_missing_binding_key_with_existing_transactions(state_directory)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?;
    let temporary_path = state_directory.join(format!(
        ".{REMOTE_BINDING_SECRET_FILE}-{}-{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    ));
    let mut secret = vec![0_u8; REMOTE_BINDING_SECRET_BYTES];
    fill_os_random(&mut secret)?;
    let result = (|| -> Result<Vec<u8>> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary_path).with_context(|| {
            format!(
                "failed to create publication binding key temp file {}",
                temporary_path.display()
            )
        })?;
        file.write_all(&secret)
            .context("failed to write publication remote binding key")?;
        file.sync_all()
            .context("failed to persist publication remote binding key")?;
        match publish_remote_binding_secret_temp(&temporary_path, &path)? {
            RemoteBindingSecretPublish::Published { temp_is_link } => {
                sync_journal_directory(state_directory)?;
                if temp_is_link {
                    match fs::remove_file(&temporary_path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "failed to remove publication binding key temp file {}",
                                    temporary_path.display()
                                )
                            })
                        }
                    }
                    sync_journal_directory(state_directory)?;
                }
                read_remote_binding_secret(&path)
            }
            RemoteBindingSecretPublish::Existing => {
                fs::remove_file(&temporary_path).with_context(|| {
                    format!(
                        "failed to remove losing publication binding key temp file {}",
                        temporary_path.display()
                    )
                })?;
                read_remote_binding_secret(&path)
            }
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

enum RemoteBindingSecretPublish {
    Published { temp_is_link: bool },
    Existing,
}

#[cfg(unix)]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    match fs::hard_link(temporary_path, final_path) {
        Ok(()) => Ok(RemoteBindingSecretPublish::Published { temp_is_link: true }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(RemoteBindingSecretPublish::Existing)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        }),
    }
}

#[cfg(target_os = "windows")]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let existing = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let new = final_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: Both paths are NUL-terminated UTF-16 buffers that remain alive
    // for the call. MOVEFILE_REPLACE_EXISTING is deliberately not supplied.
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved != 0 {
        return Ok(RemoteBindingSecretPublish::Published {
            temp_is_link: false,
        });
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(ERROR_FILE_EXISTS) | Some(ERROR_ALREADY_EXISTS)
    ) {
        Ok(RemoteBindingSecretPublish::Existing)
    } else {
        Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        })
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn publish_remote_binding_secret_temp(
    _temporary_path: &Path,
    _final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    bail!("atomic publication remote binding key creation is unsupported on this platform")
}

fn refuse_missing_binding_key_with_existing_transactions(state_directory: &Path) -> Result<()> {
    let transactions = state_directory.join("publication-transactions");
    match fs::symlink_metadata(&transactions) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || publication_metadata_is_windows_reparse_point(&metadata)
                || !metadata.file_type().is_dir()
            {
                bail!(
                    "publication transaction root {} is unsafe while the remote binding key is missing",
                    transactions.display()
                );
            }
            let mut entries = fs::read_dir(&transactions).with_context(|| {
                format!(
                    "failed to inspect existing publication transactions {}",
                    transactions.display()
                )
            })?;
            if entries.next().transpose()?.is_some() {
                bail!(
                    "publication remote binding key is missing while prior transaction entries exist; refusing to generate a replacement key"
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect publication transaction root {}",
                transactions.display()
            )
        }),
    }
}

fn read_remote_binding_secret(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    recover_remote_binding_secret_temp_link(path)?;
    let path_metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    validate_remote_binding_secret_metadata(path, &path_metadata)?;
    let mut file = open_remote_binding_secret_file(path)
        .with_context(|| format!("failed to open publication binding key {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open binding key {}", path.display()))?;
    validate_remote_binding_secret_metadata(path, &file_metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        let path_volume = path_metadata
            .volume_serial_number()
            .context("publication binding key path omitted volume identity")?;
        let file_volume = file_metadata
            .volume_serial_number()
            .context("open publication binding key omitted volume identity")?;
        let path_index = path_metadata
            .file_index()
            .context("publication binding key path omitted file identity")?;
        let file_index = file_metadata
            .file_index()
            .context("open publication binding key omitted file identity")?;
        if path_volume != file_volume || path_index != file_index {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    let mut secret = Vec::new();
    Read::by_ref(&mut file)
        .take((REMOTE_BINDING_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut secret)
        .with_context(|| format!("failed to read publication binding key {}", path.display()))?;
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!(
            "publication remote binding key {} has invalid length {}; expected {}",
            path.display(),
            secret.len(),
            REMOTE_BINDING_SECRET_BYTES
        );
    }
    Ok(secret)
}

#[cfg(target_os = "windows")]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(unix)]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn recover_remote_binding_secret_temp_link(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() == 1
    {
        return Ok(());
    }
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let effective_uid = unsafe { geteuid() };
    if metadata.nlink() != 2
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != REMOTE_BINDING_SECRET_BYTES as u64
    {
        return Ok(());
    }
    let parent = path
        .parent()
        .context("publication remote binding key has no parent directory")?;
    let mut matching_temp = None;
    for entry in fs::read_dir(parent).with_context(|| {
        format!(
            "failed to inspect publication binding key directory {}",
            parent.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read publication binding key directory entry in {}",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_remote_binding_secret_temp_name(name) {
            continue;
        }
        let candidate = entry.path();
        let candidate_metadata = fs::symlink_metadata(&candidate).with_context(|| {
            format!(
                "failed to inspect publication binding key temp link {}",
                candidate.display()
            )
        })?;
        if candidate_metadata.file_type().is_file()
            && !candidate_metadata.file_type().is_symlink()
            && candidate_metadata.dev() == metadata.dev()
            && candidate_metadata.ino() == metadata.ino()
            && candidate_metadata.uid() == effective_uid
            && candidate_metadata.permissions().mode() & 0o777 == 0o600
            && candidate_metadata.len() == REMOTE_BINDING_SECRET_BYTES as u64
            && matching_temp.replace(candidate).is_some()
        {
            bail!(
                "publication remote binding key has multiple matching temp hard links; refusing recovery"
            );
        }
    }
    let Some(matching_temp) = matching_temp else {
        return Ok(());
    };
    fs::remove_file(&matching_temp).with_context(|| {
        format!(
            "failed to recover publication binding key temp link {}",
            matching_temp.display()
        )
    })?;
    sync_journal_directory(parent)?;
    let recovered = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to verify recovered publication binding key {}",
            path.display()
        )
    })?;
    if recovered.dev() != metadata.dev()
        || recovered.ino() != metadata.ino()
        || recovered.nlink() != 1
    {
        bail!(
            "publication remote binding key {} did not recover to one link",
            path.display()
        );
    }
    Ok(())
}

fn is_remote_binding_secret_temp_name(name: &str) -> bool {
    let prefix = format!(".{REMOTE_BINDING_SECRET_FILE}-");
    let Some(stem) = name
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nanos)) = stem.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !nanos.is_empty()
        && !nanos.contains('-')
        && pid.parse::<u32>().is_ok_and(|pid| pid > 0)
        && nanos.parse::<u128>().is_ok_and(|nanos| nanos > 0)
}

fn validate_remote_binding_secret_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication remote binding key {} is not a regular non-reparse file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let effective_uid = unsafe { geteuid() };
        if metadata.uid() != effective_uid {
            bail!(
                "publication remote binding key {} is not owned by the current effective user",
                path.display()
            );
        }
        if metadata.nlink() != 1 {
            bail!(
                "publication remote binding key {} has multiple hard links",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!(
                "publication remote binding key {} must have Unix mode 0600",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        if metadata.number_of_links() != Some(1) {
            bail!(
                "publication remote binding key {} must have exactly one hard link",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn publication_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn publication_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    fs::File::open("/dev/urandom")
        .context("failed to open operating-system random source")?
        .read_exact(destination)
        .context("failed to read operating-system random source")
}

#[cfg(target_os = "windows")]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    use std::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = u32::try_from(destination.len()).context("random buffer was too large")?;
    // SAFETY: destination is writable for `length` bytes, a null algorithm
    // handle is required with BCRYPT_USE_SYSTEM_PREFERRED_RNG, and NTSTATUS is checked.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            destination.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("Windows BCryptGenRandom failed with NTSTATUS {status:#x}");
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn fill_os_random(_destination: &mut [u8]) -> Result<()> {
    bail!("publication remote binding keys are unsupported on this platform")
}

impl PublicationTransaction {
    fn open(
        repo_root: &Path,
        report: &PrPublicationReport,
        remote_name: &str,
        remote_url: &str,
        expected_oid: &str,
    ) -> Result<Self> {
        Oid::from_str(expected_oid).context("publication expected OID was invalid")?;
        validate_publication_remote_url(remote_url)?;
        let expected_base_oid = report
            .base_head
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("publication expected base OID was invalid")?
            .map(|oid| oid.to_string());
        if report.forge == ForgeKind::Github && expected_base_oid.is_none() {
            bail!("GitHub publication requires an exact reviewed base OID");
        }
        let remote_branch = publication_remote_branch(&report.agent_id, expected_oid);
        let remote_ref = format!("refs/heads/{remote_branch}");
        let forge = match report.forge {
            ForgeKind::Git => "git",
            ForgeKind::Github => "github",
            ForgeKind::Fake => "fake",
        };
        let github_repository = match report.forge {
            ForgeKind::Github => Some(github_repository_identity(remote_url)?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let repo = Repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for publication journal {}",
                repo_root.display()
            )
        })?;
        let state = merge::ensure_repo_common_state_directory(&repo)?;
        let remote_binding_secret = load_or_create_remote_binding_secret(&state)?;
        let remote_display = redact_remote_url(remote_url);
        let remote_binding_digest =
            publication_remote_binding_digest(&remote_binding_secret, remote_name, remote_url)?;
        let identity = format!(
            "{}\n{forge}\n{expected_oid}\n{remote_name}\n{remote_binding_digest}\n{}\n{}",
            report.agent_id, report.base, report.draft,
        );
        let transaction_id = format!(
            "{}-{expected_oid}-{:016x}",
            sanitize_url_segment(&report.agent_id),
            stable_hash(identity.as_bytes())
        );
        let publication_transactions =
            merge::ensure_private_managed_directory(&state, "publication-transactions")?;
        let directory =
            merge::ensure_private_managed_directory(&publication_transactions, &transaction_id)?;
        if let Some(parent) = directory.parent() {
            sync_journal_directory(parent)?;
        }

        if let Some(journal) = load_latest_publication_journal(&directory)? {
            if journal.version != PUBLICATION_JOURNAL_VERSION
                || journal.transaction_id != transaction_id
                || journal.agent_id != report.agent_id
                || journal.forge != report.forge
                || journal.expected_oid != expected_oid
                || journal.expected_base_oid != expected_base_oid
                || journal.remote_name != remote_name
                || journal.remote_binding_digest != remote_binding_digest
                || journal.remote_display != remote_display
                || journal.remote_ref != remote_ref
                || journal.remote_branch != remote_branch
                || journal.github_repository != github_repository
                || journal.base != report.base
                || journal.draft != report.draft
            {
                bail!(
                    "publication transaction journal {} does not match the current reviewed publication",
                    transaction_id
                );
            }
            return Ok(Self {
                directory,
                journal,
                remote_url: remote_url.to_string(),
                remote_private_values: publication_private_values(remote_url),
            });
        }

        let mut transaction = Self {
            directory,
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id,
                sequence: 0,
                agent_id: report.agent_id.clone(),
                forge: report.forge,
                expected_oid: expected_oid.to_string(),
                expected_base_oid,
                remote_name: remote_name.to_string(),
                remote_binding_digest,
                remote_display,
                remote_ref,
                remote_branch,
                github_repository,
                base: report.base.clone(),
                draft: report.draft,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: remote_url.to_string(),
            remote_private_values: publication_private_values(remote_url),
        };
        transaction.persist()?;
        Ok(transaction)
    }

    fn persist(&mut self) -> Result<()> {
        self.journal.sequence = self
            .journal
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow")?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        self.journal.updated_unix_seconds = timestamp.as_secs();
        let final_path = self
            .directory
            .join(format!("{:020}.json", self.journal.sequence));
        let temporary_path = self.directory.join(format!(
            ".{:020}-{}-{}.tmp",
            self.journal.sequence,
            std::process::id(),
            timestamp.as_nanos()
        ));
        let mut bytes = serde_json::to_vec_pretty(&self.journal)
            .context("failed to encode publication transaction journal")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
            self.journal.sequence = self.journal.sequence.saturating_sub(1);
            bail!(
                "publication journal record exceeded the {}-byte safety limit",
                PUBLICATION_JOURNAL_MAX_RECORD_BYTES
            );
        }
        let mut published = false;
        let write_result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary_path).with_context(|| {
                format!(
                    "failed to create publication journal temp file {}",
                    temporary_path.display()
                )
            })?;
            file.write_all(&bytes)
                .context("failed to write publication transaction journal")?;
            file.sync_all()
                .context("failed to persist publication transaction journal")?;
            fs::hard_link(&temporary_path, &final_path).with_context(|| {
                format!(
                    "failed to atomically publish journal record {}",
                    final_path.display()
                )
            })?;
            published = true;
            sync_journal_directory(&self.directory)?;
            fs::remove_file(&temporary_path).with_context(|| {
                format!(
                    "failed to remove published journal temp file {}",
                    temporary_path.display()
                )
            })?;
            sync_journal_directory(&self.directory)?;
            prune_publication_journal(&self.directory, 32)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
            if !published {
                self.journal.sequence = self.journal.sequence.saturating_sub(1);
            }
        }
        write_result
    }

    fn persist_if_changed(&mut self, previous: &PublicationTransactionJournal) -> Result<()> {
        if &self.journal == previous {
            Ok(())
        } else {
            self.persist()
        }
    }

    fn advance_phase(&mut self, phase: PublicationTransactionPhase) {
        if phase > self.journal.phase {
            self.journal.phase = phase;
        }
    }

    fn receipt(&self) -> PrPublicationReceipt {
        PrPublicationReceipt {
            version: self.journal.version,
            transaction_id: self.journal.transaction_id.clone(),
            sequence: self.journal.sequence,
            phase: self.journal.phase,
            expected_oid: self.journal.expected_oid.clone(),
            expected_base_oid: self.journal.expected_base_oid.clone(),
            remote_ref: self.journal.remote_ref.clone(),
            github_repository: self
                .journal
                .github_repository
                .as_ref()
                .map(GithubRepositoryIdentity::selector),
            push_observed_oid: self.journal.push_observed_oid.clone(),
            pr_url: self.journal.pr_url.clone(),
            pr_head_oid: self.journal.pr_head_oid.clone(),
            pr_base: self.journal.pr_base.clone(),
            pr_state: self.journal.pr_state.clone(),
            pr_is_draft: self.journal.pr_is_draft,
            create_attempted: self.journal.create_attempted,
            created_by_transaction: self.journal.created_by_transaction,
            observed_existing_pr: self.journal.observed_existing_pr,
            last_error: self.journal.last_error.clone(),
        }
    }
}

fn load_latest_publication_journal(
    directory: &Path,
) -> Result<Option<PublicationTransactionJournal>> {
    let records = publication_journal_records(directory)?;
    let mut latest = None;
    for (sequence, path) in records {
        let bytes = read_publication_journal_record(&path)?;
        let journal: PublicationTransactionJournal = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid journal record {}", path.display()))?;
        if journal.sequence != sequence {
            bail!(
                "publication journal record {} has a mismatched sequence",
                path.display()
            );
        }
        validate_publication_journal(&journal)?;
        if let Some(previous) = latest.as_ref() {
            validate_publication_journal_transition(previous, &journal)?;
        }
        latest = Some(journal);
    }
    Ok(latest)
}

fn prune_publication_journal(directory: &Path, retain: usize) -> Result<()> {
    let records = publication_journal_records(directory)?;
    let remove_count = records.len().saturating_sub(retain.max(1));
    for (_, path) in records.into_iter().take(remove_count) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to prune journal record {}", path.display()))?;
    }
    if remove_count > 0 {
        sync_journal_directory(directory)?;
    }
    Ok(())
}

fn publication_journal_records(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let directory_metadata = validate_publication_journal_directory(directory)?;
    let mut paths = Vec::new();
    let mut entry_count = 0_usize;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to list journal directory {}", directory.display()))?
    {
        entry_count = entry_count
            .checked_add(1)
            .context("publication journal directory entry count overflow")?;
        if entry_count > PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
            bail!(
                "publication journal directory exceeded the {}-entry safety limit",
                PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "failed to read journal directory entry in {}",
                directory.display()
            )
        })?;
        paths.push(entry.path());
    }
    let listed = validate_publication_journal_directory(directory)?;
    if !publication_same_filesystem_identity(&directory_metadata, &listed) {
        bail!("publication journal directory changed identity while it was listed");
    }

    let mut records = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
        validate_publication_journal_record_metadata(&path, &metadata)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("publication journal filename was not UTF-8")?;
        if is_publication_journal_temp_name(name) {
            bail!(
                "publication journal contains incomplete temporary record {}",
                path.display()
            );
        }
        let sequence = name
            .strip_suffix(".json")
            .filter(|sequence| {
                sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
            })
            .context("publication journal JSON filename was not a canonical sequence")?
            .parse::<u64>()
            .context("publication journal sequence was invalid")?;
        records.push((sequence, path));
        if records.len() > PUBLICATION_JOURNAL_MAX_RECORDS {
            bail!(
                "publication journal exceeded the {}-record safety limit",
                PUBLICATION_JOURNAL_MAX_RECORDS
            );
        }
    }
    records.sort_by_key(|(sequence, _)| *sequence);
    let after = validate_publication_journal_directory(directory)?;
    if !publication_same_filesystem_identity(&directory_metadata, &after) {
        bail!("publication journal directory changed identity while records were inspected");
    }
    Ok(records)
}

fn is_publication_journal_temp_name(name: &str) -> bool {
    let Some(remainder) = name.strip_prefix('.') else {
        return false;
    };
    let Some(remainder) = remainder.strip_suffix(".tmp") else {
        return false;
    };
    let mut fields = remainder.split('-');
    fields.next().is_some_and(|sequence| {
        sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
    }) && fields
        .next()
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
        && fields.next().is_some_and(|nanos| {
            !nanos.is_empty() && nanos.bytes().all(|byte| byte.is_ascii_digit())
        })
        && fields.next().is_none()
}

fn validate_publication_journal_directory(directory: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "failed to inspect publication journal directory {}",
            directory.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "publication journal directory {} is not a real directory",
            directory.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "publication journal directory {} has a foreign owner or unsafe mode",
                directory.display()
            );
        }
    }
    Ok(metadata)
}

fn validate_publication_journal_record_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication journal record {} is not a real regular file",
            path.display()
        );
    }
    if metadata.len() == 0 || metadata.len() > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
        bail!(
            "publication journal record {} has an invalid size",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "publication journal record {} has a foreign owner, unsafe mode, or multiple links",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "publication journal record {} has multiple links",
                path.display()
            );
        }
    }
    Ok(())
}

fn read_publication_journal_record(path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open journal record {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &file_metadata)?;
    if !publication_same_filesystem_identity(&path_metadata, &file_metadata) {
        bail!(
            "publication journal record {} changed while it was opened",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read journal record {}", path.display()))?;
    if bytes.is_empty()
        || bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES
        || bytes.len() as u64 != file_metadata.len()
    {
        bail!(
            "publication journal record {} changed size while it was read",
            path.display()
        );
    }
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &after)?;
    if !publication_same_filesystem_identity(&file_metadata, &after)
        || after.len() != file_metadata.len()
    {
        bail!(
            "publication journal record {} changed after it was read",
            path.display()
        );
    }
    Ok(bytes)
}

fn publication_same_filesystem_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (left, right);
        false
    }
}

fn validate_publication_journal(journal: &PublicationTransactionJournal) -> Result<()> {
    if journal.version != PUBLICATION_JOURNAL_VERSION || journal.sequence == 0 {
        bail!("publication journal version or sequence was invalid");
    }
    Oid::from_str(&journal.expected_oid).context("publication journal expected OID was invalid")?;
    if let Some(oid) = journal.expected_base_oid.as_deref() {
        Oid::from_str(oid).context("publication journal expected base OID was invalid")?;
    }
    Oid::from_str(&journal.remote_binding_digest)
        .context("publication journal remote binding digest was invalid")?;
    if let Some(oid) = journal.push_observed_oid.as_deref() {
        Oid::from_str(oid).context("publication journal observed push OID was invalid")?;
    }
    if let Some(oid) = journal.pr_head_oid.as_deref() {
        Oid::from_str(oid).context("publication journal PR head OID was invalid")?;
    }
    if journal.phase >= PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.as_deref() != Some(journal.expected_oid.as_str())
    {
        bail!("publication journal push phase did not contain the expected observed OID");
    }
    if journal.phase < PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.is_some()
    {
        bail!("publication journal recorded a push receipt before the push phase");
    }
    if journal.forge == ForgeKind::Github {
        if journal.expected_base_oid.is_none() {
            bail!("GitHub publication journal omitted the exact reviewed base OID");
        }
        if journal.phase >= PublicationTransactionPhase::PrObserved {
            if journal.created_by_transaction == journal.observed_existing_pr {
                bail!(
                    "publication journal PR phase did not contain exactly one receipt provenance"
                );
            }
            let repository = journal
                .github_repository
                .as_ref()
                .context("GitHub publication journal omitted its bound repository")?;
            let url = journal
                .pr_url
                .as_deref()
                .context("publication journal PR phase omitted its URL")?;
            let head = journal
                .pr_head_oid
                .as_deref()
                .context("publication journal PR phase omitted its head OID")?;
            let base = journal
                .pr_base
                .as_deref()
                .context("publication journal PR phase omitted its base branch")?;
            let state = journal
                .pr_state
                .as_deref()
                .context("publication journal PR phase omitted its state")?;
            let is_draft = journal
                .pr_is_draft
                .context("publication journal PR phase omitted its draft state")?;
            let number = journal
                .pr_number
                .filter(|number| *number > 0)
                .context("publication journal PR phase omitted its number")?;
            if head != journal.expected_oid {
                bail!("publication journal PR head did not match the expected OID");
            }
            if base != journal.base {
                bail!("publication journal PR base did not match the requested base");
            }
            if state != "OPEN" {
                bail!("publication journal PR state was not OPEN");
            }
            if is_draft != journal.draft {
                bail!("publication journal PR draft state changed from the request");
            }
            validate_github_receipt_url(url, repository, number)?;
        } else if journal.pr_url.is_some()
            || journal.pr_head_oid.is_some()
            || journal.pr_base.is_some()
            || journal.pr_state.is_some()
            || journal.pr_is_draft.is_some()
            || journal.pr_number.is_some()
            || journal.created_by_transaction
            || journal.observed_existing_pr
        {
            bail!("publication journal recorded PR receipt fields before the PR phase");
        }
    } else if journal.pr_url.is_some()
        || journal.pr_head_oid.is_some()
        || journal.pr_base.is_some()
        || journal.pr_state.is_some()
        || journal.pr_is_draft.is_some()
        || journal.pr_number.is_some()
        || journal.create_attempted
        || journal.created_by_transaction
        || journal.observed_existing_pr
    {
        bail!("non-GitHub publication journal contained GitHub PR state");
    }
    if (journal.forge == ForgeKind::Github) != journal.github_repository.is_some() {
        bail!("publication journal forge repository binding was inconsistent");
    }
    if journal.created_by_transaction && !journal.create_attempted {
        bail!("publication journal attributed PR creation without a recorded create attempt");
    }
    if journal.created_by_transaction && journal.observed_existing_pr {
        bail!("publication journal contains contradictory PR creation provenance");
    }
    Ok(())
}

fn validate_publication_journal_transition(
    previous: &PublicationTransactionJournal,
    current: &PublicationTransactionJournal,
) -> Result<()> {
    if current.sequence
        != previous
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow while validating retained records")?
    {
        bail!("publication journal retained sequence was not contiguous");
    }
    if previous.version != current.version
        || previous.transaction_id != current.transaction_id
        || previous.agent_id != current.agent_id
        || previous.forge != current.forge
        || previous.expected_oid != current.expected_oid
        || previous.expected_base_oid != current.expected_base_oid
        || previous.remote_name != current.remote_name
        || previous.remote_binding_digest != current.remote_binding_digest
        || previous.remote_display != current.remote_display
        || previous.remote_ref != current.remote_ref
        || previous.remote_branch != current.remote_branch
        || previous.github_repository != current.github_repository
        || previous.base != current.base
        || previous.draft != current.draft
    {
        bail!("publication journal immutable transaction identity changed between records");
    }
    if current.phase < previous.phase {
        bail!("publication journal phase regressed between records");
    }
    if previous.push_observed_oid.is_some()
        && previous.push_observed_oid != current.push_observed_oid
    {
        bail!("publication journal push receipt changed between records");
    }
    if (previous.pr_url.is_some() && previous.pr_url != current.pr_url)
        || (previous.pr_head_oid.is_some() && previous.pr_head_oid != current.pr_head_oid)
        || (previous.pr_base.is_some() && previous.pr_base != current.pr_base)
        || (previous.pr_state.is_some() && previous.pr_state != current.pr_state)
        || (previous.pr_is_draft.is_some() && previous.pr_is_draft != current.pr_is_draft)
        || (previous.pr_number.is_some() && previous.pr_number != current.pr_number)
    {
        bail!("publication journal immutable PR receipt changed between records");
    }
    if (previous.create_attempted && !current.create_attempted)
        || (previous.created_by_transaction && !current.created_by_transaction)
        || (previous.observed_existing_pr && !current.observed_existing_pr)
    {
        bail!("publication journal PR provenance regressed between records");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_journal_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)
        .with_context(|| format!("failed to open journal directory {}", directory.display()))?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to persist journal directory {}",
                directory.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_journal_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

fn publication_remote_branch(agent_id: &str, expected_oid: &str) -> String {
    format!(
        "maco/review/{}/{}",
        sanitize_url_segment(agent_id),
        expected_oid
    )
}

impl PublicationGitContext {
    fn create(worktree_path: &Path, remote_url: &str) -> Result<Self> {
        validate_publication_remote_url(remote_url)?;
        let repo = Repository::open(worktree_path).with_context(|| {
            format!(
                "failed to open publication worktree {}",
                worktree_path.display()
            )
        })?;
        let runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::PublicationGit,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        let result = (|| -> Result<BTreeMap<String, String>> {
            let objects = directory.join("objects");
            merge::create_private_directory(&objects)?;
            merge::create_private_directory(&directory.join("refs"))?;
            merge::create_private_directory(&directory.join("refs/heads"))?;
            merge::create_private_directory(&directory.join("refs/tags"))?;
            merge::create_private_directory(&directory.join("disabled-hooks"))?;
            merge::write_git_alternates_file(&objects, &repo.commondir().join("objects"))?;
            merge::write_private_file(
                &directory.join("HEAD"),
                b"ref: refs/heads/maco-publication\n",
            )?;
            let config_path = directory.join("config");
            merge::write_private_file(&config_path, b"")?;
            let mut config = git2::Config::open(&config_path)
                .context("failed to open private publication Git config")?;
            config
                .set_i32("core.repositoryformatversion", 0)
                .context("failed to set publication repository version")?;
            config
                .set_bool("core.bare", true)
                .context("failed to set publication repository bare mode")?;
            config
                .set_bool("core.fsmonitor", false)
                .context("failed to disable publication fsmonitor")?;
            config
                .set_bool("core.untrackedcache", false)
                .context("failed to disable publication untracked cache")?;
            config
                .set_str(
                    "core.hookspath",
                    directory
                        .join("disabled-hooks")
                        .to_str()
                        .context("publication hooks path was not UTF-8")?,
                )
                .context("failed to disable publication hooks")?;
            config
                .set_str("protocol.ext.allow", "never")
                .context("failed to disable external publication protocol")?;
            let uses_ssh =
                publication_remote_transport(remote_url)? == PublicationRemoteTransport::Ssh;
            if uses_ssh {
                config
                    .set_str("core.sshcommand", &fixed_trusted_ssh_command()?)
                    .context("failed to bind trusted publication SSH command")?;
            }
            drop(config);
            let global_config = directory.join("disabled-global-config");
            merge::write_private_file(&global_config, b"")?;
            let mut environment = merge::minimal_network_environment(uses_ssh)?;
            environment.insert(
                "GIT_CONFIG_GLOBAL".to_string(),
                global_config
                    .to_str()
                    .context("publication global config path was not UTF-8")?
                    .to_string(),
            );
            environment.insert("GIT_CONFIG_COUNT".to_string(), "1".to_string());
            environment.insert(
                "GIT_CONFIG_KEY_0".to_string(),
                "remote.maco-publication.url".to_string(),
            );
            environment.insert("GIT_CONFIG_VALUE_0".to_string(), remote_url.to_string());
            Ok(environment)
        })();
        match result {
            Ok(environment) => Ok(Self {
                directory,
                _runtime_directory: runtime_directory,
                environment,
            }),
            Err(error) => Err(error),
        }
    }

    fn run(&self, label: &str, operation: Vec<OsString>) -> Result<merge::RequiredCommandOutput> {
        let args = self.command_args(operation);
        merge::run_required_direct(
            label,
            merge::resolve_trusted_executable("git")?,
            args,
            &self.directory,
            self.environment.clone(),
            StdinMode::Null,
            merge::NETWORK_PROCESS_TIMEOUT,
            GH_CAPTURE_LIMIT_BYTES,
            0,
        )
    }

    fn command_args(&self, operation: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--git-dir"),
            self.directory.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("core.fsmonitor=false"),
            OsString::from("-c"),
            OsString::from("core.untrackedCache=false"),
            OsString::from("-c"),
            OsString::from("protocol.ext.allow=never"),
        ];
        args.extend(operation);
        args
    }
}

fn validate_publication_remote_url(remote_url: &str) -> Result<()> {
    if remote_url.is_empty()
        || remote_url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("publication remote URL is empty or contains control bytes");
    }
    if remote_url.contains(['?', '#']) {
        bail!(
            "publication remote URLs containing query or fragment credentials are unsupported; use SSH agent authentication or URL userinfo without encoded secrets"
        );
    }
    let authority = if let Some((_, remainder)) = remote_url.split_once("://") {
        remainder
            .split_once('/')
            .map_or(remainder, |(authority, _)| authority)
    } else {
        remote_url
            .split_once(':')
            .map_or(remote_url, |(authority, _)| authority)
    };
    if authority.contains('@') && authority.contains('%') {
        bail!(
            "percent-encoded publication URL credentials are unsupported because safe error redaction cannot be guaranteed"
        );
    }
    publication_remote_transport(remote_url)?;
    Ok(())
}

fn publication_remote_transport(remote_url: &str) -> Result<PublicationRemoteTransport> {
    if let Some((scheme, remainder)) = remote_url.split_once("://") {
        if scheme != scheme.to_ascii_lowercase() {
            bail!("publication remote URL scheme must be lowercase");
        }
        return match scheme.to_ascii_lowercase().as_str() {
            "ssh" | "git+ssh" | "ssh+git" => {
                validate_ssh_url_remote(remainder)?;
                Ok(PublicationRemoteTransport::Ssh)
            }
            "https" | "http" | "git" => {
                validate_non_ssh_network_remote(remainder)?;
                Ok(PublicationRemoteTransport::NonSsh)
            }
            "file" => {
                if remainder.is_empty() {
                    bail!("file publication remote omitted a path");
                }
                Ok(PublicationRemoteTransport::NonSsh)
            }
            _ => bail!("publication remote uses an unsupported URL scheme"),
        };
    }

    if publication_remote_is_local_path(remote_url) {
        return Ok(PublicationRemoteTransport::NonSsh);
    }
    if remote_url.contains(':') {
        validate_scp_style_remote(remote_url)?;
        return Ok(PublicationRemoteTransport::Ssh);
    }
    Ok(PublicationRemoteTransport::NonSsh)
}

fn publication_remote_is_local_path(remote_url: &str) -> bool {
    remote_url.starts_with('/')
        || remote_url.starts_with('\\')
        || remote_url.starts_with("./")
        || remote_url.starts_with("../")
        || remote_url.starts_with("~/")
        || remote_url.as_bytes().get(1) == Some(&b':')
            && remote_url
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && remote_url
                .as_bytes()
                .get(2)
                .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
}

fn validate_non_ssh_network_remote(remainder: &str) -> Result<()> {
    let (authority, path) = remainder
        .split_once('/')
        .context("publication remote URL omitted a repository path")?;
    if authority.is_empty() || path.is_empty() {
        bail!("publication remote URL omitted an authority or repository path");
    }
    Ok(())
}

fn validate_ssh_url_remote(remainder: &str) -> Result<()> {
    let (authority, path) = remainder
        .split_once('/')
        .context("SSH publication remote omitted a repository path")?;
    if path.is_empty() {
        bail!("SSH publication remote omitted a repository path");
    }
    validate_ssh_authority(authority, true)
}

fn validate_scp_style_remote(remote_url: &str) -> Result<()> {
    let delimiter = if let Some(bracket_start) = remote_url.find('[') {
        let bracket_end = remote_url[bracket_start + 1..]
            .find(']')
            .map(|offset| bracket_start + 1 + offset)
            .context("SCP-style publication remote contained an unterminated IPv6 host")?;
        if remote_url[bracket_end + 1..].starts_with(':') {
            bracket_end + 1
        } else {
            bail!("SCP-style publication remote omitted ':' after its IPv6 host");
        }
    } else {
        remote_url
            .find(':')
            .context("SCP-style publication remote omitted ':'")?
    };
    let authority = &remote_url[..delimiter];
    let path = &remote_url[delimiter + 1..];
    if path.is_empty() || path.starts_with(':') {
        bail!("SCP-style publication remote omitted a repository path");
    }
    validate_ssh_authority(authority, false)
}

fn validate_ssh_authority(authority: &str, allow_port: bool) -> Result<()> {
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\'))
    {
        bail!("SSH publication remote authority is invalid");
    }
    let mut user_and_host = authority.split('@');
    let first = user_and_host
        .next()
        .context("SSH publication remote authority was empty")?;
    let (user, host_and_port) = match user_and_host.next() {
        Some(host) => (Some(first), host),
        None => (None, first),
    };
    if user_and_host.next().is_some()
        || user.is_some_and(|user| {
            user.is_empty()
                || !user.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
                })
        })
    {
        bail!("SSH publication remote user is invalid");
    }

    if let Some(host) = host_and_port.strip_prefix('[') {
        let close = host
            .find(']')
            .context("SSH publication remote contained an unterminated IPv6 host")?;
        let address = &host[..close];
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            bail!("SSH publication remote IPv6 host is invalid");
        }
        let suffix = &host[close + 1..];
        if suffix.is_empty() {
            return Ok(());
        }
        if !allow_port {
            bail!("SCP-style publication remote IPv6 authority contained unexpected data");
        }
        validate_ssh_port(suffix)
    } else {
        let (host, port) = if allow_port {
            host_and_port
                .split_once(':')
                .map_or((host_and_port, None), |(host, port)| (host, Some(port)))
        } else {
            (host_and_port, None)
        };
        if host.is_empty()
            || host.contains(':')
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            bail!("SSH publication remote host is invalid");
        }
        if let Some(port) = port {
            validate_ssh_port(&format!(":{port}"))?;
        }
        Ok(())
    }
}

fn validate_ssh_port(suffix: &str) -> Result<()> {
    let port = suffix
        .strip_prefix(':')
        .context("SSH publication remote port separator was invalid")?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("SSH publication remote port is invalid");
    }
    Ok(())
}

fn fixed_trusted_ssh_command() -> Result<String> {
    let ssh = merge::resolve_trusted_executable("ssh")?;
    let ssh = ssh
        .to_str()
        .context("trusted SSH executable path was not UTF-8")?;
    if !ssh.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.' | b'+')
    }) {
        bail!("trusted SSH executable path contained unsafe shell characters");
    }
    Ok(format!(
        "{ssh} -F /dev/null -o BatchMode=yes -o PermitLocalCommand=no -o ProxyCommand=none -o ClearAllForwardings=yes -o RequestTTY=no"
    ))
}

fn ensure_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    let git = PublicationGitContext::create(worktree_path, &transaction.remote_url)?;
    let previous = transaction.journal.clone();
    let before = observe_remote_ref(&git, &transaction.journal.remote_ref)?;
    if let Some(observed) = before {
        if observed != transaction.journal.expected_oid {
            bail!(
                "unique publication ref {} points to {}, expected {}; refusing overwrite",
                transaction.journal.remote_ref,
                observed,
                transaction.journal.expected_oid
            );
        }
        transaction.journal.push_observed_oid = Some(observed);
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }

    let push = push_git_commit_create_only(
        &git,
        &transaction.journal.remote_ref,
        &transaction.journal.expected_oid,
    )?;
    let after = observe_remote_ref(&git, &transaction.journal.remote_ref)?;
    if after.as_deref() == Some(transaction.journal.expected_oid.as_str()) {
        transaction.journal.push_observed_oid = after;
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&push.stderr).trim().to_string();
    if push.success {
        bail!(
            "git push returned success but remote ref {} was not bound to expected OID {}",
            transaction.journal.remote_ref,
            transaction.journal.expected_oid
        );
    }
    bail!(
        "git push failed and expected remote OID was not observed: {}",
        if stderr.is_empty() {
            "no stderr was returned"
        } else {
            &stderr
        }
    )
}

fn ensure_github_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    require_remote_expected_base(
        worktree_path,
        transaction,
        "before publication ref creation",
    )?;
    ensure_remote_expected_commit(worktree_path, transaction)
}

fn observe_remote_ref(context: &PublicationGitContext, remote_ref: &str) -> Result<Option<String>> {
    let output = context.run(
        "observe publication remote ref",
        vec![
            OsString::from("ls-remote"),
            OsString::from("--refs"),
            OsString::from("maco-publication"),
            OsString::from(remote_ref),
        ],
    )?;
    if !output.success {
        bail!(
            "git ls-remote failed for {}: {}",
            remote_ref,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut observed = None;
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let oid = fields.next().context("git ls-remote omitted object id")?;
        let reported_ref = fields.next().context("git ls-remote omitted ref name")?;
        if fields.any(|field| !field.is_empty()) {
            bail!("git ls-remote returned unexpected extra fields");
        }
        if reported_ref != remote_ref.as_bytes() {
            bail!("git ls-remote returned an unexpected ref");
        }
        let oid = std::str::from_utf8(oid).context("remote OID was not ASCII")?;
        let oid = Oid::from_str(oid)
            .context("remote OID was invalid")?
            .to_string();
        if observed.replace(oid).is_some() {
            bail!("git ls-remote returned duplicate publication refs");
        }
    }
    Ok(observed)
}

fn push_git_commit_create_only(
    context: &PublicationGitContext,
    remote_ref: &str,
    expected_oid: &str,
) -> Result<merge::RequiredCommandOutput> {
    let lease = format!("--force-with-lease={remote_ref}:");
    let refspec = format!("{expected_oid}:{remote_ref}");
    context.run(
        "create publication remote ref",
        vec![
            OsString::from("push"),
            OsString::from("--no-verify"),
            OsString::from(lease),
            OsString::from("maco-publication"),
            OsString::from(refspec),
        ],
    )
}

fn reconcile_github_pr(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    title: &str,
    body: &str,
) -> Result<GithubPrResult> {
    reconcile_github_pr_with_api(worktree_path, transaction, title, body, &mut CliGithubApi)
}

fn reconcile_github_pr_with_api(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    title: &str,
    body: &str,
    api: &mut impl GithubApi,
) -> Result<GithubPrResult> {
    let github_repository = transaction
        .journal
        .github_repository
        .clone()
        .context("GitHub publication transaction omitted forge repository binding")?;
    require_remote_expected(
        worktree_path,
        transaction,
        "before GitHub PR reconciliation",
    )?;

    if transaction.journal.pr_url.is_some() {
        let selector = transaction
            .journal
            .pr_number
            .map(|number| number.to_string())
            .unwrap_or_else(|| transaction.journal.remote_branch.clone());
        if let Ok(receipt) = api.view(worktree_path, &selector, &github_repository) {
            return verify_github_receipt(
                worktree_path,
                transaction,
                receipt,
                transaction.journal.created_by_transaction,
                transaction.journal.observed_existing_pr,
            );
        }
    }

    let existing = api.list(
        worktree_path,
        &transaction.journal.remote_branch,
        &github_repository,
    )?;
    if existing.len() > 1 {
        bail!(
            "multiple GitHub PRs exist for unique publication branch {}",
            transaction.journal.remote_branch
        );
    }
    if let Some(existing) = existing.into_iter().next() {
        let selector = existing.number.to_string();
        let receipt = api.view(worktree_path, &selector, &github_repository)?;
        let created_by_transaction = transaction.journal.created_by_transaction;
        return verify_github_receipt(
            worktree_path,
            transaction,
            receipt,
            created_by_transaction,
            !created_by_transaction,
        );
    }

    require_remote_expected(
        worktree_path,
        transaction,
        "immediately before gh pr create",
    )?;
    transaction.journal.create_attempted = true;
    transaction.persist()?;
    let create = api.create(
        worktree_path,
        &transaction.journal.remote_branch,
        &transaction.journal.base,
        title,
        body,
        transaction.journal.draft,
        &github_repository,
    )?;
    let create_succeeded = create.success;
    let hinted_url = first_non_empty_line(&String::from_utf8_lossy(&create.stdout));

    let receipt = if hinted_url.is_some() {
        api.view(
            worktree_path,
            &transaction.journal.remote_branch,
            &github_repository,
        )
        .ok()
    } else {
        None
    };
    let receipt = match receipt {
        Some(receipt) => receipt,
        None => {
            let recovered = api.list(
                worktree_path,
                &transaction.journal.remote_branch,
                &github_repository,
            )?;
            if recovered.len() > 1 {
                bail!("gh pr create outcome is ambiguous: multiple matching PRs were observed");
            }
            let Some(recovered) = recovered.into_iter().next() else {
                let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
                bail!(
                    "gh pr create outcome could not be reconciled: {}",
                    if stderr.is_empty() {
                        "no PR receipt was returned or discovered"
                    } else {
                        &stderr
                    }
                );
            };
            let selector = recovered.number.to_string();
            api.view(worktree_path, &selector, &github_repository)?
        }
    };
    verify_github_receipt(
        worktree_path,
        transaction,
        receipt,
        create_succeeded,
        !create_succeeded,
    )
}

fn verify_github_receipt(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    receipt: GithubPrResult,
    created_by_transaction: bool,
    observed_existing_pr: bool,
) -> Result<GithubPrResult> {
    validate_github_receipt_contract(&receipt, &transaction.journal)?;
    require_remote_expected(worktree_path, transaction, "after GitHub PR creation")?;
    let previous = transaction.journal.clone();
    transaction.journal.pr_url = Some(receipt.url.clone());
    transaction.journal.pr_head_oid = Some(receipt.head_oid.clone());
    transaction.journal.pr_base = Some(receipt.base_ref_name.clone());
    transaction.journal.pr_state = Some(receipt.state.clone());
    transaction.journal.pr_is_draft = Some(receipt.is_draft);
    transaction.journal.pr_number = Some(receipt.number);
    transaction.journal.created_by_transaction =
        transaction.journal.created_by_transaction || created_by_transaction;
    transaction.journal.observed_existing_pr = !transaction.journal.created_by_transaction
        && (transaction.journal.observed_existing_pr || observed_existing_pr);
    transaction.advance_phase(PublicationTransactionPhase::PrObserved);
    transaction.persist_if_changed(&previous)?;
    Ok(GithubPrResult {
        url: receipt.url,
        head_oid: receipt.head_oid,
        base_oid: receipt.base_oid,
        number: receipt.number,
        base_ref_name: receipt.base_ref_name,
        state: receipt.state,
        is_draft: receipt.is_draft,
        created: transaction.journal.created_by_transaction,
    })
}

fn validate_github_receipt_contract(
    receipt: &GithubPrResult,
    journal: &PublicationTransactionJournal,
) -> Result<()> {
    let github_repository = journal
        .github_repository
        .as_ref()
        .context("GitHub PR journal omitted forge repository binding")?;
    validate_github_receipt_url(&receipt.url, github_repository, receipt.number)?;
    if receipt.head_oid != journal.expected_oid {
        bail!(
            "GitHub PR receipt headRefOid {} does not match reviewed OID {}",
            receipt.head_oid,
            journal.expected_oid
        );
    }
    let expected_base_oid = journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    if receipt.base_oid != expected_base_oid {
        bail!(
            "GitHub PR receipt baseRefOid {} does not match reviewed base OID {}",
            receipt.base_oid,
            expected_base_oid
        );
    }
    if receipt.base_ref_name != journal.base {
        bail!(
            "GitHub PR receipt baseRefName {} does not match requested base {}",
            receipt.base_ref_name,
            journal.base
        );
    }
    if receipt.is_draft != journal.draft {
        bail!(
            "GitHub PR receipt draft state {} does not match requested draft state {}",
            receipt.is_draft,
            journal.draft
        );
    }
    if receipt.state != "OPEN" {
        bail!(
            "GitHub PR receipt state {} is not OPEN; the existing receipt is recorded but is not review-ready",
            receipt.state
        );
    }
    Ok(())
}

fn require_remote_expected(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let git = PublicationGitContext::create(worktree_path, &transaction.remote_url)?;
    let observed = observe_remote_ref(&git, &transaction.journal.remote_ref)?;
    if observed.as_deref() != Some(transaction.journal.expected_oid.as_str()) {
        bail!(
            "publication remote ref {} changed {stage}: observed {:?}, expected {}",
            transaction.journal.remote_ref,
            observed,
            transaction.journal.expected_oid
        );
    }
    require_remote_expected_base_with_context(&git, transaction, stage)?;
    Ok(())
}

fn require_remote_expected_base(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let git = PublicationGitContext::create(worktree_path, &transaction.remote_url)?;
    require_remote_expected_base_with_context(&git, transaction, stage)
}

fn require_remote_expected_base_with_context(
    git: &PublicationGitContext,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let expected_base_oid = transaction
        .journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    let base_ref = format!("refs/heads/{}", transaction.journal.base);
    let observed_base = observe_remote_ref(git, &base_ref)?;
    if observed_base.as_deref() != Some(expected_base_oid) {
        bail!(
            "publication base ref {} changed {stage}: observed {:?}, expected {}",
            base_ref,
            observed_base,
            expected_base_oid
        );
    }
    Ok(())
}

impl GhCommandContext {
    fn create(worktree_path: &Path) -> Result<Self> {
        let runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::GhConfig,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        let result = (|| -> Result<BTreeMap<String, String>> {
            let mut environment = merge::minimal_network_environment(false)?;
            for key in [
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ] {
                if let Ok(value) = env::var(key) {
                    if !value.is_empty() {
                        environment.insert(key.to_string(), value);
                    }
                }
            }
            environment.insert(
                "GH_CONFIG_DIR".to_string(),
                directory
                    .to_str()
                    .context("private gh config path was not UTF-8")?
                    .to_string(),
            );
            environment.insert("GH_PROMPT_DISABLED".to_string(), "1".to_string());
            Ok(environment)
        })();
        match result {
            Ok(environment) => Ok(Self {
                runtime_directory,
                environment,
            }),
            Err(error) => Err(error),
        }
    }

    fn run(
        &self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        self.runtime_directory
            .verify_identity()
            .context("private gh runtime changed before command execution")?;
        merge::run_required_direct(
            label,
            merge::resolve_trusted_executable("gh")?,
            args,
            self.runtime_directory.path(),
            self.environment.clone(),
            stdin,
            merge::NETWORK_PROCESS_TIMEOUT,
            GH_CAPTURE_LIMIT_BYTES,
            GH_STDIN_LIMIT_BYTES,
        )
    }
}

impl Drop for GhCommandContext {
    fn drop(&mut self) {
        self.environment.clear();
    }
}

fn cli_github_pr_list(
    worktree_path: &Path,
    branch: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubPrResult>> {
    let context = GhCommandContext::create(worktree_path)?;
    let output = context.run(
        "gh pr list",
        [
            "pr",
            "list",
            "--repo",
            &repository.selector(),
            "--head",
            branch,
            "--state",
            "all",
            "--json",
            "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr list")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr list did not return valid JSON")?;
    value
        .as_array()
        .context("gh pr list JSON was not an array")?
        .iter()
        .map(github_pr_receipt_from_json)
        .collect()
}

fn cli_github_pr_view(
    worktree_path: &Path,
    selector: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubPrResult> {
    let context = GhCommandContext::create(worktree_path)?;
    let output = context.run(
        "gh pr view",
        [
            "pr",
            "view",
            selector,
            "--repo",
            &repository.selector(),
            "--json",
            "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr view did not return valid JSON")?;
    github_pr_receipt_from_json(&value)
}

fn github_pr_receipt_from_json(value: &serde_json::Value) -> Result<GithubPrResult> {
    let url = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted url")?;
    let head_oid = value
        .get("headRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRefOid")?;
    let head_oid = Oid::from_str(head_oid)
        .context("GitHub PR receipt headRefOid was invalid")?
        .to_string();
    let base_oid = value
        .get("baseRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefOid")?;
    let base_oid = Oid::from_str(base_oid)
        .context("GitHub PR receipt baseRefOid was invalid")?
        .to_string();
    let number = value
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .context("GitHub PR receipt omitted number")?;
    let base_ref_name = value
        .get("baseRefName")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefName")?;
    let state = value
        .get("state")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted state")?;
    let is_draft = value
        .get("isDraft")
        .and_then(serde_json::Value::as_bool)
        .context("GitHub PR receipt omitted isDraft")?;
    Ok(GithubPrResult {
        url: redact_remote_url(url),
        head_oid,
        base_oid,
        number,
        base_ref_name: base_ref_name.to_string(),
        state: state.to_string(),
        is_draft,
        created: false,
    })
}

fn cli_github_pr_create(
    worktree_path: &Path,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
    draft: bool,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubCreateOutput> {
    let context = GhCommandContext::create(worktree_path)?;
    let mut args = [
        "pr",
        "create",
        "--repo",
        &repository.selector(),
        "--base",
        base,
        "--head",
        branch,
        "--title",
        title,
        "--body-file",
        "-",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if draft {
        args.push(OsString::from("--draft"));
    }
    let output = context.run(
        "gh pr create",
        args,
        StdinMode::Bytes(body.as_bytes().to_vec()),
    )?;
    Ok(GithubCreateOutput {
        success: output.success,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn create_github_issue(repo: &Path, title: &str, body: &str, labels: &[String]) -> Result<String> {
    let repository = Repository::discover(repo).with_context(|| {
        format!(
            "failed to discover issue repository from {}",
            repo.display()
        )
    })?;
    let remote_url = remote_url(&repository, "origin")
        .context("GitHub issue creation requires an 'origin' remote")?;
    let github_repository = github_repository_identity(&remote_url)?;
    let context = GhCommandContext::create(repo)?;
    let mut args = [
        "issue",
        "create",
        "--repo",
        &github_repository.selector(),
        "--title",
        title,
        "--body-file",
        "-",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    for label in labels {
        args.push(OsString::from("--label"));
        args.push(OsString::from(label));
    }
    let output = context.run(
        "gh issue create",
        args,
        StdinMode::Bytes(body.as_bytes().to_vec()),
    )?;
    let stdout = required_command_stdout(output, "gh issue create")?;
    Ok(first_non_empty_line(&stdout).unwrap_or_else(|| {
        format!(
            "https://{}/{}/{}/issues",
            github_repository.host, github_repository.owner, github_repository.name
        )
    }))
}

fn required_command_stdout(output: merge::RequiredCommandOutput, label: &str) -> Result<String> {
    if !output.success {
        let redactor = network_auth_private_values()
            .into_iter()
            .fold(Redactor::new(), |redactor, value| {
                redactor.with_private_value("network-auth", value)
            });
        let stderr = redactor
            .redact(String::from_utf8_lossy(&output.stderr).trim())
            .text;
        bail!("{label} failed: {}", stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_non_empty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn redacted_body(body: &str) -> (String, RedactionSummary) {
    let redacted = Redactor::new().redact(body);
    (redacted.text, redacted.summary)
}

fn normalize_title(title: &str) -> Result<String> {
    let title = title.trim();
    if title.is_empty() {
        bail!("issue title cannot be empty");
    }
    Ok(title.to_string())
}

fn normalized_labels(labels: Vec<String>) -> Vec<String> {
    labels
        .into_iter()
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fake_pr_url(agent_id: &str, branch: &str, changed_paths: &[PathBuf]) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(agent_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(branch.as_bytes());
    for path in changed_paths {
        input.push(b'\n');
        input.extend_from_slice(&merge::raw_path_bytes(path));
    }
    format!(
        "fake://pr/{}-{:016x}",
        sanitize_url_segment(agent_id),
        stable_hash(&input)
    )
}

fn fake_issue_url(title: &str, body: &str, labels: &[String]) -> String {
    let mut input = String::new();
    input.push_str(title);
    input.push('\n');
    input.push_str(body);
    for label in labels {
        input.push('\n');
        input.push_str(label);
    }
    format!(
        "fake://issue/{}-{:016x}",
        sanitize_url_segment(title),
        stable_hash(input.as_bytes())
    )
}

fn sanitize_url_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if segment.is_empty() {
        "item".to_string()
    } else {
        segment
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| merge::path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn completed_github_journal(sequence: u64) -> PublicationTransactionJournal {
        PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "completed-test-transaction".to_string(),
            sequence,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
            remote_display: "https://example.invalid/owner/repo.git".to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "example.invalid".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::Completed,
            push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
            pr_url: Some("https://example.invalid/owner/repo/pull/7".to_string()),
            pr_head_oid: Some("1111111111111111111111111111111111111111".to_string()),
            pr_base: Some("main".to_string()),
            pr_state: Some("OPEN".to_string()),
            pr_is_draft: Some(true),
            pr_number: Some(7),
            create_attempted: true,
            created_by_transaction: true,
            observed_existing_pr: false,
            last_error: None,
            updated_unix_seconds: sequence,
        }
    }

    fn write_test_journal_record(directory: &Path, journal: &PublicationTransactionJournal) {
        let mut bytes = serde_json::to_vec(journal).expect("serialize test journal");
        bytes.push(b'\n');
        merge::write_private_file(
            &directory.join(format!("{:020}.json", journal.sequence)),
            &bytes,
        )
        .expect("write private test journal");
    }

    struct LostResponseGithubApi {
        list_calls: usize,
        create_calls: usize,
        exists: bool,
        receipt: GithubPrResult,
    }

    impl GithubApi for LostResponseGithubApi {
        fn list(
            &mut self,
            _worktree_path: &Path,
            _branch: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<Vec<GithubPrResult>> {
            self.list_calls += 1;
            match self.list_calls {
                1 => Ok(Vec::new()),
                2 => bail!("temporary list failure after lost create response"),
                _ if self.exists => Ok(vec![self.receipt.clone()]),
                _ => Ok(Vec::new()),
            }
        }

        fn view(
            &mut self,
            _worktree_path: &Path,
            _selector: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<GithubPrResult> {
            Ok(self.receipt.clone())
        }

        fn create(
            &mut self,
            _worktree_path: &Path,
            _branch: &str,
            _base: &str,
            _title: &str,
            _body: &str,
            _draft: bool,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<GithubCreateOutput> {
            self.create_calls += 1;
            self.exists = true;
            Ok(GithubCreateOutput {
                success: false,
                stdout: Vec::new(),
                stderr: b"response lost after create".to_vec(),
            })
        }
    }

    #[test]
    fn publication_journal_retains_only_latest_32_of_100_retries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        let remote_display = "https://example.invalid/repo";
        let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
        let mut transaction = PublicationTransaction {
            directory: journal_directory.clone(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "test-transaction".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: "1111111111111111111111111111111111111111".to_string(),
                expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
                remote_name: "origin".to_string(),
                remote_binding_digest,
                remote_display: remote_display.to_string(),
                remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
                remote_branch: "maco/review/agent-a/test".to_string(),
                github_repository: Some(GithubRepositoryIdentity {
                    host: "example.invalid".to_string(),
                    owner: "owner".to_string(),
                    name: "repo".to_string(),
                }),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: "https://example.invalid/owner/repo.git".to_string(),
            remote_private_values: Vec::new(),
        };

        for retry in 0..100 {
            transaction.journal.last_error = Some(format!("retry {retry}"));
            transaction.persist().expect("persist retry");
        }

        let records = fs::read_dir(&journal_directory)
            .expect("read journal dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 32);
        let latest = load_latest_publication_journal(&journal_directory)
            .expect("load latest")
            .expect("journal exists");
        assert_eq!(latest.sequence, 100);
        assert_eq!(latest.last_error.as_deref(), Some("retry 99"));
        let mut previous = latest.clone();
        previous.phase = PublicationTransactionPhase::PushObserved;
        previous.push_observed_oid = Some(previous.expected_oid.clone());
        let mut regressed = previous.clone();
        regressed.sequence += 1;
        regressed.phase = PublicationTransactionPhase::Prepared;
        assert!(
            validate_publication_journal_transition(&previous, &regressed)
                .expect_err("phase regression must fail")
                .to_string()
                .contains("phase regressed")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for record in records {
                let mode = record
                    .metadata()
                    .expect("record metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    #[test]
    fn publication_journal_rejects_every_noncanonical_json_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        merge::write_private_file(&journal_directory.join("unexpected.json"), b"{}\n")
            .expect("write private unexpected JSON record");

        assert!(load_latest_publication_journal(&journal_directory)
            .expect_err("noncanonical JSON record must fail")
            .to_string()
            .contains("canonical sequence"));
    }

    #[test]
    fn publication_journal_rejects_oversized_hardlinked_and_excess_records() {
        let temp = tempfile::tempdir().expect("tempdir");

        let oversized_directory = temp.path().join("oversized");
        merge::create_private_directory(&oversized_directory)
            .expect("private oversized journal directory");
        let oversized_path = oversized_directory.join("00000000000000000001.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let oversized = options
            .open(&oversized_path)
            .expect("create oversized journal");
        oversized
            .set_len(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
            .expect("size oversized journal");
        assert!(load_latest_publication_journal(&oversized_directory)
            .expect_err("oversized journal must fail")
            .to_string()
            .contains("invalid size"));

        let linked_directory = temp.path().join("linked");
        merge::create_private_directory(&linked_directory)
            .expect("private linked journal directory");
        let linked_path = linked_directory.join("00000000000000000001.json");
        merge::write_private_file(&linked_path, b"{}\n").expect("write linked journal source");
        fs::hard_link(&linked_path, temp.path().join("journal-hardlink"))
            .expect("link journal record");
        assert!(load_latest_publication_journal(&linked_directory)
            .expect_err("hardlinked journal must fail")
            .to_string()
            .contains("multiple links"));

        let excess_directory = temp.path().join("excess");
        merge::create_private_directory(&excess_directory)
            .expect("private excess journal directory");
        for sequence in 1..=(PUBLICATION_JOURNAL_MAX_RECORDS as u64 + 1) {
            write_test_journal_record(&excess_directory, &completed_github_journal(sequence));
        }
        assert!(load_latest_publication_journal(&excess_directory)
            .expect_err("excess journal records must fail")
            .to_string()
            .contains("record safety limit"));

        let entry_directory = temp.path().join("entries");
        merge::create_private_directory(&entry_directory)
            .expect("private entry-bound journal directory");
        for entry in 0..=PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
            merge::write_private_file(&entry_directory.join(format!("entry-{entry}")), b"x")
                .expect("write bounded journal directory entry");
        }
        assert!(load_latest_publication_journal(&entry_directory)
            .expect_err("excess journal directory entries must fail")
            .to_string()
            .contains("entry safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn publication_journal_rejects_symlinked_and_exposed_records() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let symlink_directory = temp.path().join("symlink");
        merge::create_private_directory(&symlink_directory)
            .expect("private symlink journal directory");
        let target = temp.path().join("target.json");
        merge::write_private_file(&target, b"{}\n").expect("write journal target");
        symlink(&target, symlink_directory.join("00000000000000000001.json"))
            .expect("symlink journal record");
        assert!(load_latest_publication_journal(&symlink_directory)
            .expect_err("symlinked journal must fail")
            .to_string()
            .contains("real regular file"));

        let exposed_directory = temp.path().join("exposed");
        merge::create_private_directory(&exposed_directory)
            .expect("private exposed journal directory");
        let exposed = exposed_directory.join("00000000000000000001.json");
        merge::write_private_file(&exposed, b"{}\n").expect("write exposed journal");
        fs::set_permissions(&exposed, fs::Permissions::from_mode(0o644))
            .expect("expose journal mode");
        assert!(load_latest_publication_journal(&exposed_directory)
            .expect_err("exposed journal must fail")
            .to_string()
            .contains("unsafe mode"));
    }

    #[test]
    fn publication_journal_rejects_sequence_gaps_and_receipt_changes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        write_test_journal_record(&journal_directory, &completed_github_journal(1));
        write_test_journal_record(&journal_directory, &completed_github_journal(3));
        assert!(load_latest_publication_journal(&journal_directory)
            .expect_err("retained journal gap must fail")
            .to_string()
            .contains("not contiguous"));

        let previous = completed_github_journal(1);
        let mut changed = completed_github_journal(2);
        changed.pr_url = Some("https://example.invalid/owner/repo/pull/8".to_string());
        changed.pr_number = Some(8);
        validate_publication_journal(&changed).expect("changed receipt is independently valid");
        assert!(validate_publication_journal_transition(&previous, &changed)
            .expect_err("receipt identity change must fail")
            .to_string()
            .contains("immutable PR receipt"));
    }

    #[test]
    fn publication_journal_enforces_completed_github_receipt_contract() {
        let valid = completed_github_journal(1);
        validate_publication_journal(&valid).expect("valid completed receipt");

        let mut wrong_head = valid.clone();
        wrong_head.pr_head_oid = Some("4444444444444444444444444444444444444444".to_string());
        assert!(validate_publication_journal(&wrong_head)
            .expect_err("wrong persisted head must fail")
            .to_string()
            .contains("PR head"));

        let mut wrong_base = valid.clone();
        wrong_base.pr_base = Some("release".to_string());
        assert!(validate_publication_journal(&wrong_base)
            .expect_err("wrong persisted base must fail")
            .to_string()
            .contains("PR base"));

        let mut missing_number = valid.clone();
        missing_number.pr_number = None;
        assert!(validate_publication_journal(&missing_number)
            .expect_err("missing persisted PR number must fail")
            .to_string()
            .contains("number"));

        let mut wrong_draft = valid;
        wrong_draft.pr_is_draft = Some(false);
        assert!(validate_publication_journal(&wrong_draft)
            .expect_err("changed persisted draft state must fail")
            .to_string()
            .contains("draft state"));
    }

    #[test]
    fn github_receipt_requires_matching_base_and_open_state() {
        let remote_display = "https://example.invalid/repo";
        let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
        let journal = PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "receipt-contract".to_string(),
            sequence: 1,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest,
            remote_display: remote_display.to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "example.invalid".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::PrObserved,
            push_observed_oid: None,
            pr_url: None,
            pr_head_oid: None,
            pr_base: None,
            pr_state: None,
            pr_is_draft: None,
            pr_number: None,
            create_attempted: false,
            created_by_transaction: false,
            observed_existing_pr: true,
            last_error: None,
            updated_unix_seconds: 1,
        };
        let mut receipt = GithubPrResult {
            url: "https://example.invalid/owner/repo/pull/1".to_string(),
            head_oid: journal.expected_oid.clone(),
            base_oid: journal.expected_base_oid.clone().expect("base oid"),
            number: 1,
            base_ref_name: "release".to_string(),
            state: "OPEN".to_string(),
            is_draft: true,
            created: false,
        };
        assert!(validate_github_receipt_contract(&receipt, &journal)
            .expect_err("wrong base must fail")
            .to_string()
            .contains("baseRefName"));
        receipt.base_ref_name = "main".to_string();
        receipt.state = "CLOSED".to_string();
        assert!(validate_github_receipt_contract(&receipt, &journal)
            .expect_err("closed PR must fail")
            .to_string()
            .contains("not OPEN"));
    }

    #[test]
    fn publication_journal_remote_binding_is_keyed_and_does_not_serialize_credentials() {
        let raw = "https://user-one:super-secret@example.invalid/repo.git?token=query-secret#fragment-secret";
        let equivalent =
            "https://user-two:different-secret@example.invalid/repo.git?token=other#different";
        let display = redact_remote_url(raw);
        let equivalent_display = redact_remote_url(equivalent);
        assert_eq!(
            display,
            "https://<redacted>@example.invalid/repo.git?<redacted>#<redacted>"
        );
        assert_eq!(display, equivalent_display);
        let secret = [7_u8; REMOTE_BINDING_SECRET_BYTES];
        let other_secret = [8_u8; REMOTE_BINDING_SECRET_BYTES];
        let digest = publication_remote_binding_digest(&secret, "origin", raw)
            .expect("digest remote binding");
        let equivalent_digest = publication_remote_binding_digest(&secret, "origin", equivalent)
            .expect("digest equivalent remote binding");
        let other_key_digest = publication_remote_binding_digest(&other_secret, "origin", raw)
            .expect("digest remote binding with another key");
        assert_ne!(digest, equivalent_digest);
        assert_ne!(digest, other_key_digest);
        let serialized = serde_json::json!({
            "remote_binding_digest": digest,
            "remote_display": display,
        })
        .to_string();
        assert!(!serialized.contains("user-one"));
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains("query-secret"));
        assert!(!serialized.contains("fragment-secret"));
        assert!(serialized.contains("<redacted>"));

        let redactor = remote_private_values(raw)
            .into_iter()
            .fold(Redactor::new(), |redactor, value| {
                redactor.with_private_value("remote-credential", value)
            });
        let error = redactor
            .redact("push failed for super-secret query-secret fragment-secret")
            .text;
        assert!(!error.contains("super-secret"));
        assert!(!error.contains("query-secret"));
        assert!(!error.contains("fragment-secret"));
    }

    #[test]
    fn github_repository_binding_parses_supported_origins_and_rejects_local_paths() {
        let https = github_repository_identity(
            "https://user:secret@github.example/Owner/repo.git?token=secret#fragment",
        )
        .expect("parse HTTPS origin");
        let ssh = github_repository_identity("ssh://git@github.example/Owner/repo.git")
            .expect("parse SSH origin");
        let git_ssh = github_repository_identity("git+ssh://github.example/Owner/repo.git")
            .expect("parse git+ssh origin");
        let scp = github_repository_identity("git@github.example:Owner/repo.git")
            .expect("parse SCP origin");
        assert_eq!(https, ssh);
        assert_eq!(https, git_ssh);
        assert_eq!(https, scp);
        assert_eq!(https.selector(), "github.example/Owner/repo");
        assert!(github_repository_identity("/tmp/local-origin.git").is_err());
        assert!(github_repository_identity("https://github.example/group/owner/repo.git").is_err());
    }

    #[test]
    fn github_receipt_url_is_bound_to_repository_and_number() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        validate_github_receipt_url("https://github.example/owner/repo/pull/7", &repository, 7)
            .expect("matching receipt URL");
        assert!(validate_github_receipt_url(
            "https://github.example/other/repo/pull/7",
            &repository,
            7,
        )
        .expect_err("wrong repository must fail")
        .to_string()
        .contains("bound forge repository"));
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/8",
            &repository,
            7,
        )
        .is_err());
    }

    #[test]
    fn github_reconcile_lost_response_does_not_duplicate_or_overstate_creator() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let origin_path = temp.path().join("origin.git");
        let repo = Repository::init(&repo_path).expect("init repo");
        Repository::init_bare(&origin_path).expect("init bare origin");
        fs::write(repo_path.join("README.md"), "reviewed\n").expect("write candidate");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("add candidate");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco@example.invalid").expect("signature");
        let expected = repo
            .commit(Some("HEAD"), &signature, &signature, "reviewed", &tree, &[])
            .expect("commit reviewed")
            .to_string();
        repo.remote("origin", origin_path.to_str().expect("origin UTF-8"))
            .expect("configure origin");
        let remote_branch = format!("maco/review/agent-a/{expected}");
        let remote_ref = format!("refs/heads/{remote_branch}");
        let git = merge::resolve_trusted_executable("git").expect("trusted git");
        let push = Command::new(git)
            .arg("-C")
            .arg(&repo_path)
            .args([
                "push",
                "origin",
                &format!("{expected}:{remote_ref}"),
                &format!("{expected}:refs/heads/main"),
            ])
            .output()
            .expect("push reviewed ref");
        assert!(
            push.status.success(),
            "{}",
            String::from_utf8_lossy(&push.stderr)
        );

        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let mut transaction = PublicationTransaction {
            directory: journal_directory,
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "lost-response".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: expected.clone(),
                expected_base_oid: Some(expected.clone()),
                remote_name: "origin".to_string(),
                remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
                remote_display: "https://github.example/owner/repo.git".to_string(),
                remote_ref,
                remote_branch,
                github_repository: Some(repository),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::PushObserved,
                push_observed_oid: Some(expected.clone()),
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: origin_path.to_string_lossy().to_string(),
            remote_private_values: Vec::new(),
        };
        let mut api = LostResponseGithubApi {
            list_calls: 0,
            create_calls: 0,
            exists: false,
            receipt: GithubPrResult {
                url: "https://github.example/owner/repo/pull/11".to_string(),
                head_oid: expected.clone(),
                base_oid: expected,
                number: 11,
                base_ref_name: "main".to_string(),
                state: "OPEN".to_string(),
                is_draft: true,
                created: false,
            },
        };

        let first =
            reconcile_github_pr_with_api(&repo_path, &mut transaction, "title", "body", &mut api)
                .expect_err("lost response must remain incomplete");
        assert!(first.to_string().contains("temporary list failure"));
        assert!(transaction.journal.create_attempted);
        assert!(!transaction.journal.created_by_transaction);

        let second =
            reconcile_github_pr_with_api(&repo_path, &mut transaction, "title", "body", &mut api)
                .expect("reconcile existing PR");
        assert!(!second.created);
        assert_eq!(api.create_calls, 1);
        assert!(transaction.journal.observed_existing_pr);
        assert!(!transaction.journal.created_by_transaction);
    }

    #[test]
    fn github_base_mismatch_blocks_before_publication_ref_creation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let origin_path = temp.path().join("origin.git");
        let repo = Repository::init(&repo_path).expect("init repo");
        Repository::init_bare(&origin_path).expect("init bare origin");
        fs::write(repo_path.join("README.md"), "reviewed\n").expect("write reviewed file");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("add reviewed file");
        index.write().expect("write reviewed index");
        let reviewed_tree_id = index.write_tree().expect("write reviewed tree");
        let reviewed_tree = repo
            .find_tree(reviewed_tree_id)
            .expect("find reviewed tree");
        let signature =
            git2::Signature::now("maco test", "maco@example.invalid").expect("signature");
        let expected = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "reviewed",
                &reviewed_tree,
                &[],
            )
            .expect("commit reviewed")
            .to_string();
        drop(reviewed_tree);

        fs::write(repo_path.join("README.md"), "moved base\n").expect("write moved base");
        let mut index = repo.index().expect("reopen index");
        index
            .add_path(Path::new("README.md"))
            .expect("add moved base");
        index.write().expect("write moved base index");
        let moved_tree_id = index.write_tree().expect("write moved base tree");
        let moved_tree = repo.find_tree(moved_tree_id).expect("find moved base tree");
        let reviewed_parent = repo
            .find_commit(Oid::from_str(&expected).expect("expected oid"))
            .expect("find reviewed parent");
        let moved_base = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "moved base",
                &moved_tree,
                &[&reviewed_parent],
            )
            .expect("commit moved base")
            .to_string();
        repo.remote("origin", origin_path.to_str().expect("origin UTF-8"))
            .expect("configure origin");
        let git = merge::resolve_trusted_executable("git").expect("trusted git");
        let push = Command::new(git)
            .arg("-C")
            .arg(&repo_path)
            .args(["push", "origin", &format!("{moved_base}:refs/heads/main")])
            .output()
            .expect("push moved base");
        assert!(
            push.status.success(),
            "{}",
            String::from_utf8_lossy(&push.stderr)
        );

        let remote_branch = format!("maco/review/agent-a/{expected}");
        let remote_ref = format!("refs/heads/{remote_branch}");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        let mut transaction = PublicationTransaction {
            directory: journal_directory,
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "base-mismatch-before-push".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: expected.clone(),
                expected_base_oid: Some(expected.clone()),
                remote_name: "origin".to_string(),
                remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
                remote_display: "https://github.example/owner/repo.git".to_string(),
                remote_ref: remote_ref.clone(),
                remote_branch,
                github_repository: Some(GithubRepositoryIdentity {
                    host: "github.example".to_string(),
                    owner: "owner".to_string(),
                    name: "repo".to_string(),
                }),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: origin_path.to_string_lossy().to_string(),
            remote_private_values: Vec::new(),
        };

        let error = ensure_github_remote_expected_commit(&repo_path, &mut transaction)
            .expect_err("moved base must block before publication push");
        assert!(error
            .to_string()
            .contains("before publication ref creation"));
        assert!(transaction.journal.push_observed_oid.is_none());
        let origin = Repository::open_bare(&origin_path).expect("open bare origin");
        assert!(origin.find_reference(&remote_ref).is_err());
    }

    #[test]
    fn wrong_remote_oid_records_diagnostic_without_poisoning_recovery_journal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let origin_path = temp.path().join("origin.git");
        let repo = Repository::init(&repo_path).expect("init repo");
        Repository::init_bare(&origin_path).expect("init bare origin");
        fs::write(repo_path.join("README.md"), "reviewed\n").expect("write reviewed file");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("add reviewed file");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write reviewed tree");
        let tree = repo.find_tree(tree_id).expect("find reviewed tree");
        let signature =
            git2::Signature::now("maco test", "maco@example.invalid").expect("signature");
        let expected = repo
            .commit(Some("HEAD"), &signature, &signature, "reviewed", &tree, &[])
            .expect("commit reviewed")
            .to_string();
        drop(tree);
        fs::write(repo_path.join("README.md"), "unreviewed\n").expect("write attack file");
        let mut index = repo.index().expect("reopen index");
        index
            .add_path(Path::new("README.md"))
            .expect("add attack file");
        index.write().expect("write attack index");
        let attack_tree_id = index.write_tree().expect("write attack tree");
        let attack_tree = repo.find_tree(attack_tree_id).expect("find attack tree");
        let parent = repo
            .find_commit(Oid::from_str(&expected).expect("expected oid"))
            .expect("find reviewed parent");
        let attack = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "unreviewed",
                &attack_tree,
                &[&parent],
            )
            .expect("commit attack")
            .to_string();
        repo.remote("origin", origin_path.to_str().expect("origin UTF-8"))
            .expect("configure origin");
        let remote_ref = format!("refs/heads/maco/review/agent-a/{expected}");
        let git = merge::resolve_trusted_executable("git").expect("trusted git");
        let initial = Command::new(&git)
            .arg("-C")
            .arg(&repo_path)
            .args([
                "push",
                "origin",
                &format!("{expected}:{remote_ref}"),
                &format!("{expected}:refs/heads/main"),
            ])
            .output()
            .expect("push reviewed refs");
        assert!(
            initial.status.success(),
            "{}",
            String::from_utf8_lossy(&initial.stderr)
        );

        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        let mut transaction = PublicationTransaction {
            directory: journal_directory.clone(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "wrong-remote-recovery".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Git,
                expected_oid: expected.clone(),
                expected_base_oid: Some(expected.clone()),
                remote_name: "origin".to_string(),
                remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
                remote_display: origin_path.to_string_lossy().to_string(),
                remote_ref: remote_ref.clone(),
                remote_branch: remote_ref.trim_start_matches("refs/heads/").to_string(),
                github_repository: None,
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::Completed,
                push_observed_oid: Some(expected.clone()),
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: origin_path.to_string_lossy().to_string(),
            remote_private_values: Vec::new(),
        };
        transaction.persist().expect("persist initial receipt");
        let moved = Command::new(&git)
            .arg("-C")
            .arg(&repo_path)
            .args([
                "push",
                "--force",
                "origin",
                &format!("{attack}:{remote_ref}"),
            ])
            .output()
            .expect("move remote ref");
        assert!(moved.status.success());

        let error = ensure_remote_expected_commit(&repo_path, &mut transaction)
            .expect_err("wrong remote OID must block");
        assert_eq!(
            transaction.journal.push_observed_oid.as_deref(),
            Some(expected.as_str())
        );
        transaction.journal.last_error = Some(error.to_string());
        transaction.persist().expect("persist safe diagnostic");
        let loaded = load_latest_publication_journal(&journal_directory)
            .expect("load journal after wrong observation")
            .expect("journal exists");
        assert_eq!(loaded.push_observed_oid.as_deref(), Some(expected.as_str()));

        let restored = Command::new(&git)
            .arg("-C")
            .arg(&repo_path)
            .args([
                "push",
                "--force",
                "origin",
                &format!("{expected}:{remote_ref}"),
            ])
            .output()
            .expect("restore remote ref");
        assert!(restored.status.success());
        ensure_remote_expected_commit(&repo_path, &mut transaction)
            .expect("reconcile restored remote ref");
        assert!(transaction.journal.last_error.is_none());
    }

    #[test]
    fn invalid_github_receipt_is_not_persisted_before_contract_checks() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut transaction = PublicationTransaction {
            directory: temp.path().to_path_buf(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "invalid-receipt".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: "1111111111111111111111111111111111111111".to_string(),
                expected_base_oid: Some("2222222222222222222222222222222222222222".to_string()),
                remote_name: "origin".to_string(),
                remote_binding_digest: "3333333333333333333333333333333333333333".to_string(),
                remote_display: "https://github.example/owner/repo.git".to_string(),
                remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
                remote_branch: "maco/review/agent-a/test".to_string(),
                github_repository: Some(GithubRepositoryIdentity {
                    host: "github.example".to_string(),
                    owner: "owner".to_string(),
                    name: "repo".to_string(),
                }),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::PushObserved,
                push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                create_attempted: true,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: "https://github.example/owner/repo.git".to_string(),
            remote_private_values: Vec::new(),
        };
        let receipt = GithubPrResult {
            url: "https://github.example/owner/repo/pull/7".to_string(),
            head_oid: transaction.journal.expected_oid.clone(),
            base_oid: "4444444444444444444444444444444444444444".to_string(),
            number: 7,
            base_ref_name: "main".to_string(),
            state: "OPEN".to_string(),
            is_draft: true,
            created: false,
        };

        let error = verify_github_receipt(temp.path(), &mut transaction, receipt, true, false)
            .expect_err("wrong base receipt must fail before persistence");

        assert!(error.to_string().contains("baseRefOid"));
        assert_eq!(transaction.journal.sequence, 0);
        assert_eq!(
            transaction.journal.phase,
            PublicationTransactionPhase::PushObserved
        );
        assert!(transaction.journal.pr_url.is_none());
        assert_eq!(
            fs::read_dir(temp.path()).expect("read journal dir").count(),
            0
        );
    }

    #[test]
    fn github_command_environment_is_an_explicit_data_auth_allowlist() {
        let temp = tempfile::tempdir().expect("tempdir");
        let context = GhCommandContext::create(temp.path()).expect("create gh context");
        for key in [
            "GH_REPO",
            "GH_HOST",
            "GH_DEBUG",
            "GH_FORCE_TTY",
            "GH_PAGER",
            "HOME",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "GIT_SSL_CAINFO",
            "GIT_SSL_CAPATH",
        ] {
            assert!(
                !context.environment.contains_key(key),
                "unexpected inherited routing variable {key}"
            );
        }
        assert_eq!(
            context
                .environment
                .get("GH_PROMPT_DISABLED")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            context.environment.get("GH_CONFIG_DIR").map(String::as_str),
            context.runtime_directory.path().to_str()
        );
    }

    #[test]
    fn publication_git_keeps_remote_credentials_out_of_argv_and_disk_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let raw = "https://user:abcdef@example.invalid/owner/repo.git";
        let context =
            PublicationGitContext::create(&repo_path, raw).expect("create publication Git context");
        let args = context.command_args(vec![
            OsString::from("ls-remote"),
            OsString::from("--refs"),
            OsString::from("maco-publication"),
            OsString::from("refs/heads/test"),
        ]);
        let argv = args
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!argv.contains(raw));
        assert!(!argv.contains("abcdef"));
        assert_eq!(
            context
                .environment
                .get("GIT_CONFIG_VALUE_0")
                .map(String::as_str),
            Some(raw)
        );
        let config = fs::read(context.directory.join("config")).expect("read private config");
        assert!(!String::from_utf8_lossy(&config).contains("abcdef"));
    }

    #[test]
    fn publication_remote_rejects_ambiguous_encoded_query_and_fragment_credentials() {
        assert!(validate_publication_remote_url(
            "https://user:secret@example.invalid/repo.git?token=secret"
        )
        .is_err());
        assert!(validate_publication_remote_url(
            "https://user:secret@example.invalid/repo.git#secret"
        )
        .is_err());
        assert!(
            validate_publication_remote_url("https://user:abc%64ef@example.invalid/repo.git")
                .is_err()
        );
    }

    #[test]
    fn publication_remote_structurally_classifies_every_supported_ssh_form() {
        for remote in [
            "ssh://github.example/owner/repo.git",
            "ssh://git@github.example:2222/owner/repo.git",
            "git+ssh://github.example/owner/repo.git",
            "ssh+git://git@github.example/owner/repo.git",
            "github.example:owner/repo.git",
            "git@github.example:owner/repo.git",
            "[2001:db8::1]:owner/repo.git",
            "git@[2001:db8::1]:owner/repo.git",
        ] {
            assert_eq!(
                publication_remote_transport(remote).expect("classify supported SSH remote"),
                PublicationRemoteTransport::Ssh,
                "{remote}"
            );
        }
        for remote in [
            "https://github.example/owner/repo.git",
            "file:///tmp/repo.git",
            "/tmp/repo.git",
            "../repo.git",
            r"C:\\repo.git",
        ] {
            assert_eq!(
                publication_remote_transport(remote).expect("classify supported non-SSH remote"),
                PublicationRemoteTransport::NonSsh,
                "{remote}"
            );
        }
        for remote in [
            "ext://host/repo",
            "SSH://host/repo",
            "host::remote-helper",
            "ssh://user@@host/repo",
            "ssh://[2001:db8::1/repo",
            "host:",
        ] {
            assert!(
                publication_remote_transport(remote).is_err(),
                "ambiguous remote must fail: {remote}"
            );
        }
    }

    #[test]
    fn userless_scp_remote_is_bound_to_fixed_trusted_ssh_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let context = PublicationGitContext::create(&repo_path, "github.example:owner/repo.git")
            .expect("create userless SCP publication context");
        let config = git2::Config::open(&context.directory.join("config"))
            .expect("open private publication config");
        let command = config
            .get_string("core.sshcommand")
            .expect("fixed SSH command must be configured");
        assert!(command.contains(" -F /dev/null "));
        assert!(command.contains("ProxyCommand=none"));
        assert_eq!(
            context.environment.get("SSH_AUTH_SOCK"),
            env::var("SSH_AUTH_SOCK").ok().as_ref()
        );
    }

    #[cfg(unix)]
    #[test]
    fn gh_command_refuses_changed_private_runtime_before_spawn() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let context = GhCommandContext::create(temp.path()).expect("create gh context");
        assert_ne!(context.runtime_directory.path(), temp.path());
        fs::set_permissions(
            context.runtime_directory.path(),
            fs::Permissions::from_mode(0o755),
        )
        .expect("weaken gh runtime mode");
        let result = context.run(
            "gh identity test",
            vec![OsString::from("--version")],
            StdinMode::Null,
        );
        fs::set_permissions(
            context.runtime_directory.path(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore gh runtime mode for cleanup");
        let error = match result {
            Ok(_) => panic!("changed gh runtime must fail before command execution"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("private gh runtime changed"));
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_is_private_stable_and_fixed_length() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let state = tempfile::tempdir().expect("state dir");
        let first = load_or_create_remote_binding_secret(state.path()).expect("create key");
        let second = load_or_create_remote_binding_secret(state.path()).expect("reload key");
        assert_eq!(first, second);
        assert_eq!(first.len(), REMOTE_BINDING_SECRET_BYTES);
        let metadata =
            fs::metadata(state.path().join(REMOTE_BINDING_SECRET_FILE)).expect("key metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn publication_remote_binding_key_missing_with_prior_transaction_fails_closed() {
        let state = tempfile::tempdir().expect("state dir");
        fs::create_dir_all(state.path().join("publication-transactions/prior"))
            .expect("prior transaction");

        let error = load_or_create_remote_binding_secret(state.path())
            .expect_err("missing key with prior transaction must fail");

        assert!(error
            .to_string()
            .contains("prior transaction entries exist"));
        assert!(!state.path().join(REMOTE_BINDING_SECRET_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_rejects_corruption_permissions_and_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let corrupt = tempfile::tempdir().expect("corrupt state");
        let corrupt_path = corrupt.path().join(REMOTE_BINDING_SECRET_FILE);
        fs::write(&corrupt_path, b"short").expect("write corrupt key");
        fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600))
            .expect("chmod corrupt key");
        assert!(read_remote_binding_secret(&corrupt_path)
            .expect_err("corrupt key must fail")
            .to_string()
            .contains("invalid length"));

        let exposed = tempfile::tempdir().expect("exposed state");
        let exposed_path = exposed.path().join(REMOTE_BINDING_SECRET_FILE);
        fs::write(&exposed_path, [1_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write exposed key");
        fs::set_permissions(&exposed_path, fs::Permissions::from_mode(0o644))
            .expect("chmod exposed key");
        assert!(read_remote_binding_secret(&exposed_path)
            .expect_err("exposed key must fail")
            .to_string()
            .contains("mode 0600"));

        let replaced = tempfile::tempdir().expect("replaced state");
        let target = replaced.path().join("target");
        fs::write(&target, [2_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write key target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod key target");
        let replaced_path = replaced.path().join(REMOTE_BINDING_SECRET_FILE);
        symlink(&target, &replaced_path).expect("replace key with symlink");
        assert!(read_remote_binding_secret(&replaced_path)
            .expect_err("symlink key must fail")
            .to_string()
            .contains("non-reparse"));
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_recovers_only_known_crash_temp_link() {
        use std::os::unix::fs::MetadataExt;

        let state = tempfile::tempdir().expect("state dir");
        let secret = load_or_create_remote_binding_secret(state.path()).expect("create key");
        let key = state.path().join(REMOTE_BINDING_SECRET_FILE);
        let crash_temp = state
            .path()
            .join(format!(".{REMOTE_BINDING_SECRET_FILE}-123-456.tmp"));
        fs::hard_link(&key, &crash_temp).expect("simulate crash temp hard link");
        assert_eq!(fs::metadata(&key).expect("linked key metadata").nlink(), 2);

        let recovered = read_remote_binding_secret(&key).expect("recover known temp link");

        assert_eq!(recovered, secret);
        assert!(!crash_temp.exists());
        assert_eq!(
            fs::metadata(&key).expect("recovered key metadata").nlink(),
            1
        );

        let unknown = state.path().join("unknown-key-link");
        fs::hard_link(&key, &unknown).expect("create unknown key hard link");
        assert!(read_remote_binding_secret(&key)
            .expect_err("unknown hard link must fail")
            .to_string()
            .contains("multiple hard links"));
    }
}
