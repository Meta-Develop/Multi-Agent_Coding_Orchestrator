use crate::llm::Redactor;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const REVIEW_OUTPUT_LIMIT: usize = 8 * 1024;

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
    let mut command_process = Command::new("sh");
    command_process.arg("-c").arg(command);
    configure_timeout_process_control(&mut command_process);
    let mut child = command_process
        .current_dir(&options.repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn external reviewer command")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&input)
            .context("failed to write external review input")?;
    }
    let timeout = options.reviewer.timeout_seconds.map(Duration::from_secs);
    let output = wait_for_external_review(child, timeout)
        .context("failed to wait for external reviewer command")?;
    let diagnostics =
        diagnostics_from_output(&options.repo, &output, options.reviewer.timeout_seconds);
    if output.timed_out {
        return Ok(failed_external_review(
            options,
            "external reviewer command timed out",
            diagnostics,
        ));
    }
    if !output.status.is_some_and(|status| status.success()) {
        return Ok(failed_external_review(
            options,
            "external reviewer command failed",
            diagnostics,
        ));
    }
    let mut report: ReviewReport = serde_json::from_slice(&output.stdout)
        .context("external reviewer command must emit a review report JSON object")?;
    report.reviewer.mode = ReviewerMode::ExternalCommand;
    report.ci_reaction_supported = false;
    report.ci_reaction = "unsupported".to_string();
    Ok(report)
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

fn wait_for_external_review(
    mut child: Child,
    timeout: Option<Duration>,
) -> std::io::Result<ExternalTimedOutput> {
    let started = Instant::now();
    if let Some(timeout) = timeout {
        loop {
            if child.try_wait()?.is_some() {
                let output = child.wait_with_output()?;
                return Ok(ExternalTimedOutput {
                    status: Some(output.status),
                    timed_out: false,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error: None,
                });
            }

            if started.elapsed() >= timeout {
                let process_error = terminate_child_on_timeout(&mut child);
                let output = child.wait_with_output()?;
                return Ok(ExternalTimedOutput {
                    status: Some(output.status),
                    timed_out: true,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error,
                });
            }

            thread::sleep(Duration::from_millis(25));
        }
    }

    let output = child.wait_with_output()?;
    Ok(ExternalTimedOutput {
        status: Some(output.status),
        timed_out: false,
        stdout: output.stdout,
        stderr: output.stderr,
        process_error: None,
    })
}

#[derive(Debug)]
struct ExternalTimedOutput {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    process_error: Option<String>,
}

fn diagnostics_from_output(
    repo: &Path,
    output: &ExternalTimedOutput,
    timeout_seconds: Option<u64>,
) -> ReviewCommandDiagnostics {
    ReviewCommandDiagnostics {
        timed_out: output.timed_out,
        timeout_seconds,
        exit_code: output.status.and_then(|status| status.code()),
        stdout: sanitize_review_output(repo, &output.stdout),
        stderr: sanitize_review_output(repo, &output.stderr),
        process_error: output.process_error.clone(),
    }
}

fn sanitize_review_output(repo: &Path, output: &[u8]) -> ReviewOutputSummary {
    let text = String::from_utf8_lossy(output);
    let mut sanitized = Redactor::new().redact(&text).text;
    sanitized = sanitized.replace(&repo.display().to_string(), ".");
    if let Some(parent) = repo.parent() {
        sanitized = sanitized.replace(&parent.display().to_string(), "<repo-parent>");
    }
    summarize_review_text(&redact_token_like_words(&sanitized), REVIEW_OUTPUT_LIMIT)
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

fn configure_timeout_process_control(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

fn terminate_child_on_timeout(child: &mut Child) -> Option<String> {
    #[cfg(unix)]
    {
        terminate_unix_process_group(child)
    }

    #[cfg(not(unix))]
    {
        child
            .kill()
            .err()
            .map(|error| format!("external reviewer timed out but process kill failed: {error}"))
    }
}

#[cfg(unix)]
fn terminate_unix_process_group(child: &mut Child) -> Option<String> {
    let pid = child.id();
    let term_error = send_unix_process_group_signal(pid, "TERM").err();
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return term_error.map(|error| error.to_string()),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                return Some(format!(
                    "external reviewer timed out but process wait failed: {error}"
                ))
            }
        }
    }

    let kill_result = send_unix_process_group_signal(pid, "KILL").or_else(|_| child.kill());
    kill_result.err().map(|error| {
        if let Some(term_error) = term_error {
            format!(
                "external reviewer timed out but process group termination failed: {term_error}; kill failed: {error}"
            )
        } else {
            format!("external reviewer timed out but process group kill failed: {error}")
        }
    })
}

#[cfg(unix)]
fn send_unix_process_group_signal(pid: u32, signal: &str) -> std::io::Result<()> {
    let target = format!("-{pid}");
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(&target)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "kill -{signal} {target} exited with {status}"
        )))
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
