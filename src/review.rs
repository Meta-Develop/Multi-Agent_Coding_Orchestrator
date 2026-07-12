use crate::{
    llm::Redactor,
    process_runner::{
        read_bounded_regular_file_nofollow, run_process, EnvironmentMode, ProcessOutput,
        ProcessSpec, Shell, SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

const REVIEW_OUTPUT_LIMIT: usize = 8 * 1024;
const REVIEW_CAPTURE_LIMIT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone)]
pub struct ReviewPrOptions {
    pub repo: PathBuf,
    pub target: String,
    pub reviewer: ReviewerConfig,
    pub attempt: usize,
    pub changed_paths: Vec<PathBuf>,
    pub diff_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewerConfig {
    #[serde(default)]
    pub mode: ReviewerMode,
    #[serde(default)]
    pub blocking_attempts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<FakeReviewFindingTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

impl Default for ReviewerConfig {
    fn default() -> Self {
        Self {
            mode: ReviewerMode::Fake,
            blocking_attempts: 0,
            finding: None,
            command: None,
            timeout_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerMode {
    #[default]
    Fake,
    #[serde(alias = "external")]
    ExternalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FakeReviewFindingTemplate {
    #[serde(default = "default_review_severity")]
    pub severity: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_review_summary")]
    pub summary: String,
    #[serde(default = "default_suggested_fix")]
    pub suggested_fix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewReport {
    pub status: ReviewReportStatus,
    pub success: bool,
    pub target: String,
    pub reviewer: ReviewerIdentity,
    pub attempt: usize,
    pub findings: Vec<ReviewFinding>,
    pub blocking_finding_count: usize,
    pub changed_paths: Vec<PathBuf>,
    pub diff_source: String,
    pub ci_reaction_supported: bool,
    pub ci_reaction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ReviewCommandDiagnostics>,
    pub next_action: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewCommandDiagnostics {
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub stdout: ReviewOutputSummary,
    pub stderr: ReviewOutputSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewOutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportStatus {
    Passed,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewerIdentity {
    pub mode: ReviewerMode,
    pub reviewer_id: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewFinding {
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub summary: String,
    pub suggested_fix: String,
    pub blocking: bool,
}

pub fn review_pr(options: ReviewPrOptions) -> Result<ReviewReport> {
    match options.reviewer.mode {
        ReviewerMode::Fake => Ok(fake_review(options)),
        ReviewerMode::ExternalCommand => external_review(options),
    }
}

pub fn fake_review(options: ReviewPrOptions) -> ReviewReport {
    let should_block = options.reviewer.blocking_attempts > 0
        && options.attempt <= options.reviewer.blocking_attempts;
    let findings = if should_block {
        vec![fake_finding(&options)]
    } else {
        Vec::new()
    };
    let blocking_finding_count = findings.iter().filter(|finding| finding.blocking).count();
    let status = if blocking_finding_count == 0 {
        ReviewReportStatus::Passed
    } else {
        ReviewReportStatus::Blocked
    };
    ReviewReport {
        status,
        success: status == ReviewReportStatus::Passed,
        target: options.target,
        reviewer: ReviewerIdentity {
            mode: ReviewerMode::Fake,
            reviewer_id: "autopilot-fake-reviewer".to_string(),
            model: "deterministic-local-reviewer".to_string(),
        },
        attempt: options.attempt,
        findings,
        blocking_finding_count,
        changed_paths: options.changed_paths,
        diff_source: if options.diff_summary.is_some() {
            "sanitized_merge_candidate_summary".to_string()
        } else {
            "pr_target_only".to_string()
        },
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: None,
        next_action: if status == ReviewReportStatus::Passed {
            "human reviews the pull request and merges manually".to_string()
        } else {
            "repair blocking review findings before requesting another human review".to_string()
        },
    }
}

fn external_review(options: ReviewPrOptions) -> Result<ReviewReport> {
    external_review_runtime(options, ReviewExecutionRuntime::Verified)
}

#[cfg(test)]
fn external_review_simulation(options: ReviewPrOptions) -> Result<ReviewReport> {
    external_review_runtime(options, ReviewExecutionRuntime::NonpublishableSimulation)
}

fn external_review_runtime(
    options: ReviewPrOptions,
    runtime: ReviewExecutionRuntime,
) -> Result<ReviewReport> {
    let command = options
        .reviewer
        .command
        .as_deref()
        .filter(|command| !command.trim().is_empty())
        .context("external reviewer mode requires a reviewer command")?;
    if matches!(options.reviewer.timeout_seconds, Some(0)) {
        bail!("external reviewer timeout_seconds must be greater than zero when set");
    }
    let input = serde_json::to_vec(&ExternalReviewInput {
        target: &options.target,
        attempt: options.attempt,
        changed_paths: &options.changed_paths,
        diff_summary: options.diff_summary.as_deref(),
    })
    .context("failed to serialize external review input")?;
    let timeout = options.reviewer.timeout_seconds.map(Duration::from_secs);
    let before = review_repo_snapshot(&options.repo)?;
    let process_spec = ProcessSpec::shell(
        "external reviewer command",
        Shell::for_current_platform(),
        command,
        &options.repo,
        REVIEW_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(sandbox_environment()))
    .with_stdin(StdinMode::Bytes(input))
    .with_timeout(timeout);
    let output = run_process(match runtime {
        ReviewExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_only(&options.repo),
            )),
        #[cfg(test)]
        ReviewExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })
    .context("failed to run external reviewer command")?;
    let after = review_repo_snapshot(&options.repo)?;
    if let Some(error) = &output.stdin_error {
        bail!(error.clone());
    }
    let diagnostics =
        diagnostics_from_output(&options.repo, &output, options.reviewer.timeout_seconds);
    if after != before {
        return Ok(failed_external_review(
            options,
            "external reviewer changed repository state despite its read-only contract",
            diagnostics,
        ));
    }
    if output.timed_out {
        return Ok(failed_external_review(
            options,
            "external reviewer command timed out",
            diagnostics,
        ));
    }
    let command_succeeded = match runtime {
        ReviewExecutionRuntime::Verified => output.safety_sensitive_succeeded(),
        #[cfg(test)]
        ReviewExecutionRuntime::NonpublishableSimulation => {
            output.status.is_some_and(|status| status.success())
                && !output.timed_out
                && output.stdin_error.is_none()
                && output.process_error.is_none()
        }
    };
    if !command_succeeded {
        return Ok(failed_external_review(
            options,
            "external reviewer command failed",
            diagnostics,
        ));
    }
    if output.stdout.is_truncated() {
        bail!(
            "external reviewer command output exceeded the {} byte capture limit",
            REVIEW_CAPTURE_LIMIT_BYTES
        );
    }
    let mut report: ReviewReport = serde_json::from_slice(output.stdout.as_bytes())
        .context("external reviewer command must emit a review report JSON object")?;
    report.reviewer.mode = ReviewerMode::ExternalCommand;
    report.ci_reaction_supported = false;
    report.ci_reaction = "unsupported".to_string();
    Ok(report)
}

#[derive(Debug, PartialEq, Eq)]
struct ReviewRepoSnapshot {
    head: Option<git2::Oid>,
    index_digest: Option<git2::Oid>,
    statuses: Vec<(PathBuf, u32)>,
}

fn review_repo_snapshot(path: &Path) -> Result<ReviewRepoSnapshot> {
    let repo = git2::Repository::open(path)
        .with_context(|| format!("failed to snapshot review repository {}", path.display()))?;
    let head = repo.head().ok().and_then(|head| head.target());
    let index_path = repo.path().join("index");
    let index_digest = match read_bounded_regular_file_nofollow(&index_path, 64 * 1024 * 1024) {
        Ok(bytes) => Some(
            git2::Oid::hash_object(git2::ObjectType::Blob, &bytes)
                .context("failed to hash review index")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("failed to read bounded review index"),
    };
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false);
    let statuses = repo
        .statuses(Some(&mut options))?
        .iter()
        .filter_map(|entry| {
            entry
                .path()
                .map(|path| (PathBuf::from(path), entry.status().bits()))
        })
        .collect();
    Ok(ReviewRepoSnapshot {
        head,
        index_digest,
        statuses,
    })
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

fn failed_external_review(
    options: ReviewPrOptions,
    reason: &str,
    diagnostics: ReviewCommandDiagnostics,
) -> ReviewReport {
    ReviewReport {
        status: ReviewReportStatus::Failed,
        success: false,
        target: options.target,
        reviewer: ReviewerIdentity {
            mode: ReviewerMode::ExternalCommand,
            reviewer_id: "external-reviewer".to_string(),
            model: "external-command".to_string(),
        },
        attempt: options.attempt,
        findings: vec![ReviewFinding {
            severity: "error".to_string(),
            path: options.changed_paths.first().cloned(),
            summary: reason.to_string(),
            suggested_fix: "inspect reviewer diagnostics and rerun after fixing the command"
                .to_string(),
            blocking: true,
        }],
        blocking_finding_count: 1,
        changed_paths: options.changed_paths,
        diff_source: if options.diff_summary.is_some() {
            "sanitized_merge_candidate_summary".to_string()
        } else {
            "pr_target_only".to_string()
        },
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: Some(diagnostics),
        next_action: "repair or rerun the external reviewer command before proceeding".to_string(),
    }
}

fn diagnostics_from_output(
    repo: &Path,
    output: &ProcessOutput,
    timeout_seconds: Option<u64>,
) -> ReviewCommandDiagnostics {
    ReviewCommandDiagnostics {
        timed_out: output.timed_out,
        timeout_seconds,
        exit_code: output.status.and_then(|status| status.code()),
        stdout: sanitize_review_output(repo, output.stdout.as_bytes()),
        stderr: sanitize_review_output(repo, output.stderr.as_bytes()),
        process_error: output.process_error.clone(),
    }
}

fn sanitize_review_output(repo: &Path, output: &[u8]) -> ReviewOutputSummary {
    let text = String::from_utf8_lossy(output);
    let mut sanitized = Redactor::new().redact(&text).text;

    if let Ok(canonical_repo) = repo.canonicalize() {
        replace_nonempty_path(&mut sanitized, &canonical_repo, ".");
        if let Some(parent) = canonical_repo.parent() {
            replace_nonempty_path(&mut sanitized, parent, "<repo-parent>");
        }
    }
    replace_nonempty_path(&mut sanitized, repo, ".");
    if let Some(parent) = repo.parent() {
        replace_nonempty_path(&mut sanitized, parent, "<repo-parent>");
    }
    summarize_review_text(&redact_token_like_words(&sanitized), REVIEW_OUTPUT_LIMIT)
}

fn replace_nonempty_path(text: &mut String, path: &Path, replacement: &str) {
    let path = path.display().to_string();
    if !path.is_empty() {
        *text = text.replace(&path, replacement);
    }
}

fn summarize_review_text(text: &str, limit: usize) -> ReviewOutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    ReviewOutputSummary {
        text: value,
        truncated: chars.next().is_some(),
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

fn fake_finding(options: &ReviewPrOptions) -> ReviewFinding {
    if let Some(template) = &options.reviewer.finding {
        return ReviewFinding {
            severity: template.severity.clone(),
            path: template
                .path
                .clone()
                .or_else(|| options.changed_paths.first().cloned()),
            summary: template.summary.clone(),
            suggested_fix: template.suggested_fix.clone(),
            blocking: true,
        };
    }
    ReviewFinding {
        severity: "error".to_string(),
        path: options.changed_paths.first().cloned(),
        summary: format!(
            "deterministic fake blocker for review attempt {}",
            options.attempt
        ),
        suggested_fix: "rerun the worker with the review finding as repair context".to_string(),
        blocking: true,
    }
}

#[derive(Serialize)]
struct ExternalReviewInput<'a> {
    target: &'a str,
    attempt: usize,
    changed_paths: &'a [PathBuf],
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<&'a str>,
}

fn default_review_severity() -> String {
    "error".to_string()
}

fn default_review_summary() -> String {
    "deterministic fake blocker".to_string()
}

fn default_suggested_fix() -> String {
    "repair the reported issue".to_string()
}

pub fn target_label(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        "unknown".to_string()
    } else {
        target.to_string()
    }
}

pub fn target_from_pr_arg(arg: &str) -> Result<String> {
    let target = arg.trim();
    if target.is_empty() {
        bail!("pull request target cannot be empty");
    }
    if target.chars().all(|c| c.is_ascii_digit()) {
        return Ok(format!("#{target}"));
    }
    Ok(target.to_string())
}

pub fn diff_summary_from_text(text: impl AsRef<str>) -> Option<String> {
    let text = text.as_ref().trim();
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(32 * 1024).collect())
    }
}

pub fn normalize_changed_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

pub fn repo_path_for_review(repo: impl AsRef<Path>) -> PathBuf {
    repo.as_ref().to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_review_constructs_passed_report_with_deterministic_identity() {
        let report = fake_review(ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#42".to_string(),
            reviewer: ReviewerConfig::default(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: Some("changed src/review.rs".to_string()),
        });

        assert_eq!(report.status, ReviewReportStatus::Passed);
        assert!(report.success);
        assert_eq!(report.target, "#42");
        assert_eq!(report.reviewer.mode, ReviewerMode::Fake);
        assert_eq!(report.reviewer.reviewer_id, "autopilot-fake-reviewer");
        assert_eq!(report.reviewer.model, "deterministic-local-reviewer");
        assert_eq!(report.findings, Vec::<ReviewFinding>::new());
        assert_eq!(report.blocking_finding_count, 0);
        assert_eq!(report.diff_source, "sanitized_merge_candidate_summary");
        assert!(!report.ci_reaction_supported);
        assert_eq!(report.ci_reaction, "unsupported");
    }

    #[test]
    fn sanitize_review_output_with_dot_repo_does_not_expand_empty_parent() {
        let output = sanitize_review_output(Path::new("."), b"plain diagnostics");

        assert_eq!(output.text, "plain diagnostics");
        assert!(!output.truncated);
    }

    #[test]
    fn sanitize_review_output_redacts_canonical_repo_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let diagnostic = format!("failure in {}/src/review.rs", temp.path().display());

        let output = sanitize_review_output(temp.path(), diagnostic.as_bytes());

        assert_eq!(output.text, "failure in ./src/review.rs");
        Ok(())
    }

    #[test]
    fn fake_review_constructs_blocking_template_finding() {
        let report = fake_review(ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#43".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::Fake,
                blocking_attempts: 1,
                finding: Some(FakeReviewFindingTemplate {
                    severity: "warning".to_string(),
                    path: None,
                    summary: "deterministic template finding".to_string(),
                    suggested_fix: "apply the deterministic fix".to_string(),
                }),
                command: None,
                timeout_seconds: None,
            },
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: None,
        });

        assert_eq!(report.status, ReviewReportStatus::Blocked);
        assert!(!report.success);
        assert_eq!(report.blocking_finding_count, 1);
        assert_eq!(report.diff_source, "pr_target_only");
        assert_eq!(
            report.findings,
            vec![ReviewFinding {
                severity: "warning".to_string(),
                path: Some(PathBuf::from("src/review.rs")),
                summary: "deterministic template finding".to_string(),
                suggested_fix: "apply the deterministic fix".to_string(),
                blocking: true,
            }]
        );
        assert!(!report.ci_reaction_supported);
    }

    #[cfg(unix)]
    #[test]
    fn external_review_drains_large_output_before_timeout() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let report_path = temp.path().join("review.json");
        let expected = fake_review(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#44".to_string(),
            reviewer: ReviewerConfig::default(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: None,
        });
        std::fs::write(&report_path, serde_json::to_vec(&expected)?)?;
        let command = format!(
            "cat >/dev/null; i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' ' '; i=$((i + 1)); done; cat '{}'",
            report_path.display()
        );

        let report = external_review_simulation(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#44".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                command: Some(command),
                timeout_seconds: Some(3),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: None,
        })?;

        assert_eq!(report.status, ReviewReportStatus::Passed);
        assert!(report.success);
        assert_eq!(report.reviewer.mode, ReviewerMode::ExternalCommand);
        Ok(())
    }
}
