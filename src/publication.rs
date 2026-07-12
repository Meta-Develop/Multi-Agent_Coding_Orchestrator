use crate::{
    llm::{RedactionSummary, Redactor},
    merge::{
        self, ApplyBlocker, ApplyBlockerDetail, ApplyBlockerDisposition, ApplyReadinessStatus,
        MergeApplyPreview, MergeCollectOptions, MergeForceOptions, MergePreviewOptions,
        OutputSummary, RepoCommonLock, SafetyCheckStatus, ValidationEvidenceBundle,
        ValidationReport,
    },
};
use anyhow::{bail, Context, Result};
use git2::{ConfigLevel, ObjectType, Oid, Repository};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const SUMMARY_LIMIT: usize = 12 * 1024;
const PUBLICATION_JOURNAL_VERSION: u32 = 1;
const REMOTE_BINDING_SECRET_FILE: &str = "publication-remote-binding.key";
const REMOTE_BINDING_SECRET_BYTES: usize = 32;

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
            if let Err(error) = ensure_remote_expected_commit(&worktree_path, &mut transaction) {
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
    report.pushed = transaction.journal.push_observed_oid.as_deref()
        == Some(transaction.journal.expected_oid.as_str());
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
    git_add_all(worktree_path, changed_paths)?;

    let mut index = repo
        .index()
        .context("failed to open agent worktree index")?;
    index
        .write()
        .context("failed to write agent worktree index")?;
    let tree_id = index.write_tree().context("failed to write commit tree")?;
    let tree = repo
        .find_tree(tree_id)
        .context("failed to read staged commit tree")?;
    let parent = repo
        .head()
        .context("agent worktree has no HEAD commit")?
        .peel_to_commit()
        .context("failed to read agent HEAD commit")?;
    if parent.tree_id() == tree_id {
        return Ok(parent.id());
    }
    let parents = [&parent];
    let message = commit_message(agent_id, preview);
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        &message,
        &tree,
        &parents,
    )
    .context("failed to commit agent worktree changes")
}

fn git_add_all(worktree_path: &Path, changed_paths: &[PathBuf]) -> Result<()> {
    let mut command = merge::sanitized_git_command(worktree_path)?;
    command.args(["add", "--all", "--"]);
    for path in changed_paths {
        command.arg(path);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run git add in {}", worktree_path.display()))?;
    if !output.status.success() {
        bail!(
            "git add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
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
    values.sort();
    values.dedup();
    values
}

fn publication_private_values(remote_url: &str) -> Vec<String> {
    let mut values = remote_private_values(remote_url);
    values.extend(network_auth_private_values());
    values.sort();
    values.dedup();
    values
}

fn network_auth_private_values() -> Vec<String> {
    [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "SSH_AUTH_SOCK",
    ]
    .into_iter()
    .filter_map(|key| env::var(key).ok())
    .filter(|value| !value.is_empty())
    .collect()
}

fn github_repository_identity(remote_url: &str) -> Result<GithubRepositoryIdentity> {
    let identity_end = remote_url.find(['?', '#']).unwrap_or(remote_url.len());
    let identity = remote_url[..identity_end].trim_end_matches('/');
    let (host, path) = if let Some((scheme, remainder)) = identity.split_once("://") {
        if !matches!(scheme, "https" | "ssh") {
            bail!("GitHub publication requires an https:// or ssh:// origin URL");
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
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read journal record {}", path.display()))?;
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
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to list journal directory {}", directory.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read journal directory entry in {}",
                directory.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!(
                "publication journal record {} is not a regular file",
                path.display()
            );
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("publication journal JSON filename was not UTF-8")?;
        let sequence = name
            .strip_suffix(".json")
            .filter(|sequence| {
                sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
            })
            .context("publication journal JSON filename was not a canonical sequence")?
            .parse::<u64>()
            .context("publication journal sequence was invalid")?;
        records.push((sequence, path));
    }
    records.sort_by_key(|(sequence, _)| *sequence);
    Ok(records)
}

fn validate_publication_journal(journal: &PublicationTransactionJournal) -> Result<()> {
    Oid::from_str(&journal.expected_oid).context("publication journal expected OID was invalid")?;
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
    if journal.forge == ForgeKind::Github
        && journal.phase >= PublicationTransactionPhase::PrObserved
        && (journal.pr_url.is_none()
            || journal.pr_head_oid.is_none()
            || journal.pr_base.is_none()
            || journal.pr_state.is_none()
            || journal.pr_is_draft.is_none())
    {
        bail!("publication journal PR phase did not contain a complete GitHub receipt");
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
    if previous.version != current.version
        || previous.transaction_id != current.transaction_id
        || previous.agent_id != current.agent_id
        || previous.forge != current.forge
        || previous.expected_oid != current.expected_oid
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

fn ensure_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    validate_publication_git_config(worktree_path, &transaction.journal.remote_name)?;
    let previous = transaction.journal.clone();
    let before = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    transaction.journal.push_observed_oid = before.clone();
    if let Some(observed) = before {
        if observed != transaction.journal.expected_oid {
            bail!(
                "unique publication ref {} points to {}, expected {}; refusing overwrite",
                transaction.journal.remote_ref,
                observed,
                transaction.journal.expected_oid
            );
        }
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }

    let push = push_git_commit_create_only(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
        &transaction.journal.expected_oid,
    )?;
    let after = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    transaction.journal.push_observed_oid = after.clone();
    if after.as_deref() == Some(transaction.journal.expected_oid.as_str()) {
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&push.stderr).trim().to_string();
    if push.status.success() {
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

fn validate_publication_git_config(worktree_path: &Path, remote_name: &str) -> Result<()> {
    let repo = Repository::open(worktree_path).with_context(|| {
        format!(
            "failed to open publication worktree {} for config audit",
            worktree_path.display()
        )
    })?;
    let config = repo
        .config()
        .context("failed to open publication Git config")?;
    let local = config
        .open_level(ConfigLevel::Local)
        .context("failed to open repository-local publication Git config")?;
    let mut entries = local
        .entries(None)
        .context("failed to enumerate repository-local Git config")?;
    let remote_prefix = format!("remote.{}.", remote_name.to_ascii_lowercase());
    while let Some(entry) = entries.next() {
        let entry = entry.context("failed to read repository-local Git config entry")?;
        let Some(name) = entry.name() else {
            bail!("repository-local Git config contained a nameless entry");
        };
        let name = name.to_ascii_lowercase();
        let remote_execution_override = name.starts_with(&remote_prefix)
            && matches!(
                name.strip_prefix(&remote_prefix),
                Some("pushurl" | "receivepack" | "proxy")
            );
        let credential_helper = name == "credential.helper"
            || (name.starts_with("credential.") && name.ends_with(".helper"));
        let url_redirect = name.starts_with("url.")
            && (name.ends_with(".insteadof") || name.ends_with(".pushinsteadof"));
        if matches!(
            name.as_str(),
            "core.sshcommand" | "core.gitproxy" | "include.path"
        ) || name.starts_with("includeif.")
            || remote_execution_override
            || credential_helper
            || url_redirect
        {
            bail!(
                "repository-local Git config contains a key that can redirect or execute publication commands; refusing push"
            );
        }
    }
    Ok(())
}

fn observe_remote_ref(
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
) -> Result<Option<String>> {
    let mut command = merge::sanitized_git_push_command(worktree_path)?;
    command.args(["ls-remote", "--refs", remote_url, remote_ref]);
    let output = command
        .output()
        .with_context(|| format!("failed to observe publication remote ref {remote_ref}"))?;
    if !output.status.success() {
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
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
    expected_oid: &str,
) -> Result<std::process::Output> {
    let mut push = merge::sanitized_git_push_command(worktree_path)?;
    let lease = format!("--force-with-lease={remote_ref}:");
    let refspec = format!("{expected_oid}:{remote_ref}");
    push.args(["push", "--no-verify", &lease, remote_url, &refspec]);
    push.output()
        .context("failed to start create-only git push")
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
            return verify_github_receipt(worktree_path, transaction, receipt);
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
        if !transaction.journal.created_by_transaction {
            transaction.journal.observed_existing_pr = true;
        }
        return verify_github_receipt(worktree_path, transaction, receipt);
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
    if let Some(url) = hinted_url.clone() {
        transaction.journal.pr_url = Some(redact_remote_url(&url));
        transaction.journal.created_by_transaction = true;
        transaction.journal.observed_existing_pr = false;
        transaction.persist()?;
    }

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
            transaction.journal.created_by_transaction = create_succeeded;
            transaction.journal.observed_existing_pr = !create_succeeded;
            let selector = recovered.number.to_string();
            api.view(worktree_path, &selector, &github_repository)?
        }
    };
    verify_github_receipt(worktree_path, transaction, receipt)
}

fn verify_github_receipt(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    receipt: GithubPrResult,
) -> Result<GithubPrResult> {
    let previous = transaction.journal.clone();
    transaction.journal.pr_url = Some(receipt.url.clone());
    transaction.journal.pr_head_oid = Some(receipt.head_oid.clone());
    transaction.journal.pr_base = Some(receipt.base_ref_name.clone());
    transaction.journal.pr_state = Some(receipt.state.clone());
    transaction.journal.pr_is_draft = Some(receipt.is_draft);
    transaction.journal.pr_number = Some(receipt.number);
    transaction.advance_phase(PublicationTransactionPhase::PrObserved);
    transaction.persist_if_changed(&previous)?;
    validate_github_receipt_contract(&receipt, &transaction.journal)?;
    require_remote_expected(worktree_path, transaction, "after GitHub PR creation")?;
    Ok(GithubPrResult {
        url: receipt.url,
        head_oid: receipt.head_oid,
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
    validate_publication_git_config(worktree_path, &transaction.journal.remote_name)?;
    let observed = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if observed.as_deref() != Some(transaction.journal.expected_oid.as_str()) {
        bail!(
            "publication remote ref {} changed {stage}: observed {:?}, expected {}",
            transaction.journal.remote_ref,
            observed,
            transaction.journal.expected_oid
        );
    }
    Ok(())
}

fn cli_github_pr_list(
    worktree_path: &Path,
    branch: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubPrResult>> {
    let mut command = trusted_gh_command(worktree_path)?;
    command.current_dir(worktree_path).args([
        "pr",
        "list",
        "--repo",
        &repository.selector(),
        "--head",
        branch,
        "--state",
        "all",
        "--json",
        "url,headRefOid,number,baseRefName,state,isDraft",
    ]);
    let stdout = run_command(&mut command, "gh pr list")?;
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
    let mut command = trusted_gh_command(worktree_path)?;
    command.current_dir(worktree_path).args([
        "pr",
        "view",
        selector,
        "--repo",
        &repository.selector(),
        "--json",
        "url,headRefOid,number,baseRefName,state,isDraft",
    ]);
    let stdout = run_command(&mut command, "gh pr view")?;
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
    let mut command = trusted_gh_command(worktree_path)?;
    command
        .current_dir(worktree_path)
        .args([
            "pr",
            "create",
            "--repo",
            &repository.selector(),
            "--base",
            base,
            "--head",
            branch,
        ])
        .arg("--title")
        .arg(title)
        .arg("--body")
        .arg(body);
    if draft {
        command.arg("--draft");
    }
    let output = command.output().context("failed to run gh pr create")?;
    Ok(GithubCreateOutput {
        success: output.status.success(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn trusted_gh_command(worktree_path: &Path) -> Result<Command> {
    let mut command = Command::new(merge::resolve_trusted_executable("gh")?);
    configure_gh_command_environment(&mut command)?;
    command.current_dir(worktree_path);
    Ok(command)
}

fn configure_gh_command_environment(command: &mut Command) -> Result<()> {
    merge::sanitize_network_command_environment(command)?;
    command
        .env_remove("GH_REPO")
        .env_remove("GH_HOST")
        .env_remove("GH_CONFIG_DIR")
        .env_remove("GH_DEBUG")
        .env_remove("GH_FORCE_TTY")
        .env_remove("GH_PAGER")
        .env("GH_PROMPT_DISABLED", "1");
    Ok(())
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
    merge::resolve_trusted_executable("gh")
        .context("GitHub issue creation requires a trusted gh executable")?;
    let mut command = trusted_gh_command(repo)?;
    command
        .current_dir(repo)
        .args([
            "issue",
            "create",
            "--repo",
            &github_repository.selector(),
            "--title",
        ])
        .arg(title)
        .arg("--body")
        .arg(body);
    for label in labels {
        command.arg("--label").arg(label);
    }
    let stdout = run_command(&mut command, "gh issue create")?;
    Ok(first_non_empty_line(&stdout).unwrap_or_else(|| {
        format!(
            "https://{}/{}/{}/issues",
            github_repository.host, github_repository.owner, github_repository.name
        )
    }))
}

fn run_command(command: &mut Command, label: &str) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    if !output.status.success() {
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
        let remote_display = "https://example.invalid/repo";
        let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
        let mut transaction = PublicationTransaction {
            directory: temp.path().to_path_buf(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "test-transaction".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: "1111111111111111111111111111111111111111".to_string(),
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

        let records = fs::read_dir(temp.path())
            .expect("read journal dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 32);
        let latest = load_latest_publication_journal(temp.path())
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
        fs::write(temp.path().join("unexpected.json"), b"{}\n")
            .expect("write unexpected JSON record");

        assert!(load_latest_publication_journal(temp.path())
            .expect_err("noncanonical JSON record must fail")
            .to_string()
            .contains("canonical sequence"));
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
        let scp = github_repository_identity("git@github.example:Owner/repo.git")
            .expect("parse SCP origin");
        assert_eq!(https, ssh);
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
            .args(["push", "origin", &format!("{expected}:{remote_ref}")])
            .output()
            .expect("push reviewed ref");
        assert!(
            push.status.success(),
            "{}",
            String::from_utf8_lossy(&push.stderr)
        );

        let journal_directory = temp.path().join("journal");
        fs::create_dir(&journal_directory).expect("journal directory");
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
                head_oid: expected,
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
    fn github_command_environment_removes_ambient_repository_and_output_routing() {
        let mut command = Command::new("unused-gh");
        configure_gh_command_environment(&mut command).expect("configure gh environment");
        let removals = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().to_string())
            .collect::<BTreeSet<_>>();
        for key in [
            "GH_REPO",
            "GH_HOST",
            "GH_CONFIG_DIR",
            "GH_DEBUG",
            "GH_FORCE_TTY",
            "GH_PAGER",
        ] {
            assert!(removals.contains(key), "missing removal for {key}");
        }
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
