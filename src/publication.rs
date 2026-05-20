use crate::{
    llm::{RedactionSummary, Redactor},
    merge::{
        self, ApplyBlocker, ApplyReadinessStatus, MergeApplyPreview, MergeCollectOptions,
        MergeForceOptions, MergePreviewOptions, OutputSummary, SafetyCheckStatus, ValidationReport,
    },
};
use anyhow::{bail, Context, Result};
use git2::{ErrorCode, Oid, Repository};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

const SUMMARY_LIMIT: usize = 12 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeKind {
    Fake,
    Github,
}

impl ForgeKind {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value {
            "fake" => Ok(Self::Fake),
            "github" => Ok(Self::Github),
            _ => Err("expected one of: fake, github".to_string()),
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
    pub changed_paths: Vec<PathBuf>,
    pub validation_status: SafetyCheckStatus,
    pub readiness: ApplyReadinessStatus,
    pub blockers: Vec<ApplyBlocker>,
    pub commit_id: Option<String>,
    pub head_id: Option<String>,
    pub pr_url: Option<String>,
    pub pushed: bool,
    pub created: bool,
    pub next_action: String,
    pub preview: MergeApplyPreview,
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

struct GithubPrResult {
    url: String,
    pushed: bool,
    created: bool,
}

pub fn preview_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    let preview = build_merge_preview(&options)?;
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
        remote: remote_url(&primary_repo, "origin").ok(),
        forge: options.forge,
        draft: options.draft,
        title: pr_title(&preview),
        body_summary: summarize_text(&body, SUMMARY_LIMIT),
        changed_paths: preview.candidate.changed_paths.clone(),
        validation_status: preview.safety.validation.status,
        readiness: preview.safety.readiness.status,
        blockers: preview.safety.readiness.blockers.clone(),
        commit_id: None,
        head_id: preview.candidate.metadata.agent_head.clone(),
        pr_url: None,
        pushed: false,
        created: false,
        next_action,
        preview,
    })
}

pub fn publish_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    let mut report = preview_pr(options)?;
    if report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(report);
    }

    let primary_repo = Repository::open(&report.preview.candidate.metadata.primary_repo_root)
        .context("failed to open primary repository")?;
    if report.forge == ForgeKind::Github {
        report.remote = Some(
            remote_url(&primary_repo, "origin")
                .context("GitHub PR publication requires an 'origin' remote")?,
        );
    }

    let worktree_path = report.preview.candidate.metadata.worktree_path.clone();
    let needs_commit = has_uncommitted_changes(&worktree_path)?;
    if needs_commit {
        let commit_id = commit_agent_changes(
            &worktree_path,
            &report.agent_id,
            &report.changed_paths,
            &report.preview,
        )?;
        report.commit_id = Some(commit_id.to_string());
        report.head_id = Some(commit_id.to_string());
    } else {
        report.head_id = current_head_id(&worktree_path)?;
    }

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
        ForgeKind::Github => {
            let body = pr_body(&report.preview);
            let github = create_github_pr(
                &worktree_path,
                "origin",
                &report.branch,
                &report.base,
                &report.title,
                &body,
                report.draft,
            )?;
            report.pr_url = Some(github.url);
            report.pushed = github.pushed;
            report.created = github.created;
            report.next_action = "review the draft pull request on GitHub".to_string();
        }
    }

    report.status = PrPublicationStatus::Published;
    Ok(report)
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
        ForgeKind::Github => {
            create_github_issue(&repo, &report.title, &report.redacted_body, &report.labels)?
        }
    };
    report.url = Some(url);
    report.created = true;
    report.next_action = match report.forge {
        ForgeKind::Fake => "review the fake issue report locally",
        ForgeKind::Github => "review the created GitHub issue",
    }
    .to_string();
    Ok(report)
}

fn build_merge_preview(options: &PrPublicationOptions) -> Result<MergeApplyPreview> {
    merge::preview_merge_apply(MergePreviewOptions {
        collect: MergeCollectOptions {
            repo: options.repo.clone(),
            agent_id: options.agent_id.clone(),
            claimed_paths: options.claimed_paths.clone(),
            include_full_diff: true,
            diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations: options.validations.clone(),
        },
        forces: MergeForceOptions::default(),
    })
}

fn pr_title(preview: &MergeApplyPreview) -> String {
    format!("Agent {} changes", preview.candidate.metadata.agent_id)
}

fn pr_body(preview: &MergeApplyPreview) -> String {
    let changed = preview
        .candidate
        .changed_paths
        .iter()
        .map(|path| format!("- {}", path.display()))
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
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(worktree_path)
        .args(["add", "--all", "--"]);
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
        .map(|path| format!("- {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "maco: publish {agent_id} changes\n\nGenerated by maco pr publish after merge-preview gates passed.\n\nChanged paths:\n{paths}\n"
    )
}

fn current_head_id(worktree_path: &Path) -> Result<Option<String>> {
    let repo = Repository::open(worktree_path)
        .with_context(|| format!("failed to open repository {}", worktree_path.display()))?;
    let head = match repo.head() {
        Ok(head) => Ok(Some(
            head.peel_to_commit()
                .context("failed to peel HEAD to commit")?
                .id()
                .to_string(),
        )),
        Err(error) if error.code() == ErrorCode::UnbornBranch => Ok(None),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to read HEAD"),
    };
    head
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

fn create_github_pr(
    worktree_path: &Path,
    remote: &str,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
    draft: bool,
) -> Result<GithubPrResult> {
    let mut push = Command::new("git");
    push.arg("-C")
        .arg(worktree_path)
        .args(["push", "-u", remote, branch]);
    run_command(&mut push, "git push")?;

    let mut command = Command::new("gh");
    command
        .current_dir(worktree_path)
        .args(["pr", "create", "--base", base, "--head", branch])
        .arg("--title")
        .arg(title)
        .arg("--body")
        .arg(body);
    if draft {
        command.arg("--draft");
    }
    let stdout = run_command(&mut command, "gh pr create")?;
    let url = first_non_empty_line(&stdout)
        .unwrap_or_else(|| format!("https://github.com/pull/{branch}"));
    Ok(GithubPrResult {
        url,
        pushed: true,
        created: true,
    })
}

fn create_github_issue(repo: &Path, title: &str, body: &str, labels: &[String]) -> Result<String> {
    let mut command = Command::new("gh");
    command
        .current_dir(repo)
        .args(["issue", "create", "--title"])
        .arg(title)
        .arg("--body")
        .arg(body);
    for label in labels {
        command.arg("--label").arg(label);
    }
    let stdout = run_command(&mut command, "gh issue create")?;
    Ok(
        first_non_empty_line(&stdout)
            .unwrap_or_else(|| "https://github.com/issues/new".to_string()),
    )
}

fn run_command(command: &mut Command, label: &str) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    if !output.status.success() {
        bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
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
    let mut input = String::new();
    input.push_str(agent_id);
    input.push('\n');
    input.push_str(branch);
    for path in changed_paths {
        input.push('\n');
        input.push_str(&path.to_string_lossy());
    }
    format!(
        "fake://pr/{}-{:016x}",
        sanitize_url_segment(agent_id),
        stable_hash(input.as_bytes())
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

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}
