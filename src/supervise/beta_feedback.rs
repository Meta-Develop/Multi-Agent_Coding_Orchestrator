//! Privacy-safe defect feedback for a finished supervised run.
//!
//! The published issue is a neutral defect record. Chat, prompts, and person
//! attribution stay in the run directory.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::artifacts::{ArtifactRunReader, RunArtifactFamily};
use crate::build_identity::{ExecutableBuildIdentity, SourceState};
use crate::external_agent::EnvironmentFailure;
use crate::gate_denial::GateDenial;
use crate::orchestrator::RunId;
use crate::publication::{
    validate_feedback_marker, ForgeKind, IssuePublicationOptions, IssuePublicationReport,
};
use crate::safe_state::BoundedRegularReader;

use super::{
    AuditorReport, Finding, FindingSeverity, OrchestratorReviewReport, ReviewStatus,
    SupervisorCoverageGap, SupervisorFinalReport, SupervisorRunLifecycle, SupervisorRuntime,
    ValidationResult, WorkerReport, SELECTION_LEDGER_RELATIVE,
};

const FAKE_OPEN_ISSUES_RELATIVE: &str = ".maco/feedback/fake-open-issues.json";
const FAKE_FIXTURE_MAX_BYTES: u64 = 1024 * 1024;
const FINDING_LINE_CHARS: usize = 500;
const TITLE_CHARS: usize = 120;
const BETA_FEEDBACK_LABEL: &str = "beta-feedback";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackForge {
    Fake,
    Github,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackReason {
    RunSucceeded,
    Duplicate,
    DryRun,
}

impl FeedbackReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RunSucceeded => "run_succeeded",
            Self::Duplicate => "duplicate",
            Self::DryRun => "dry_run",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeedbackOptions {
    pub repo: PathBuf,
    pub run_id: String,
    pub forge: FeedbackForge,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FeedbackReport {
    pub created: bool,
    pub url: Option<String>,
    pub fingerprint: String,
    pub reason: Option<FeedbackReason>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct FeedbackRedactionContext {
    repo_root: PathBuf,
    home_dirs: Vec<PathBuf>,
    identities: Vec<IdentityRule>,
}

#[derive(Debug, Clone)]
struct IdentityRule {
    name: String,
    class: &'static str,
    replacement: &'static str,
}

#[derive(Debug, Clone)]
struct Cause {
    kind: String,
    gate: String,
    location: String,
    message: String,
    finding_line: String,
    extra: usize,
    status: String,
}

struct Found {
    severity: FindingSeverity,
    message: String,
    paths: Vec<PathBuf>,
}

/// File or preview a de-duplicated defect issue for a finished run.
pub fn supervise_feedback(options: FeedbackOptions) -> Result<FeedbackReport> {
    let repo_root = discover_repo_root(&options.repo)?;
    let run_id = RunId::new(&options.run_id)?;
    let run_dir = repo_root
        .join(".maco")
        .join("o2")
        .join("runs")
        .join(run_id.as_str());
    let Some(report) = super::read_finished_supervisor_report(&repo_root, &run_id, &run_dir)?
    else {
        bail!("supervise feedback refuses an unfinished run");
    };
    if report.run_lifecycle != SupervisorRunLifecycle::Finalized {
        bail!("supervise feedback refuses an unfinished run");
    }
    if run_succeeded(&report) {
        return Ok(FeedbackReport {
            created: false,
            url: None,
            fingerprint: String::new(),
            reason: Some(FeedbackReason::RunSucceeded),
            title: String::new(),
            body: None,
        });
    }

    let context = FeedbackRedactionContext::from_process(repo_root.clone());
    let cause = select_cause(&report);
    let fingerprint = fingerprint_for(&cause, &context);
    let title = cap_chars(
        &redact_feedback_text(
            &format!("Defect: {} at {}", cause.kind, cause.gate),
            &context,
        ),
        TITLE_CHARS,
    );
    let title = if title.trim().is_empty() {
        "Defect".to_string()
    } else {
        title.replace(['\n', '\r'], " ")
    };
    let body = render_body(&report, &run_id, &repo_root, &cause);
    let body = redact_feedback_text(&body, &context);
    ensure_redacted(&title, &context)?;
    ensure_redacted(&body, &context)?;
    let marker = format!("<!-- maco-feedback:{fingerprint} -->");
    validate_feedback_marker(&marker).context("supervise feedback fingerprint was malformed")?;
    let mut published = body;
    if !published.ends_with('\n') {
        published.push('\n');
    }
    published.push_str(&marker);
    published.push('\n');

    if let Some(url) = find_duplicate(&options, &repo_root, &marker)? {
        return Ok(FeedbackReport {
            created: false,
            url: Some(url),
            fingerprint,
            reason: Some(FeedbackReason::Duplicate),
            title,
            body: Some(published),
        });
    }
    if options.dry_run {
        return Ok(FeedbackReport {
            created: false,
            url: None,
            fingerprint,
            reason: Some(FeedbackReason::DryRun),
            title,
            body: Some(published),
        });
    }

    let created = create_feedback_issue(&repo_root, &title, &published, options.forge)?;
    Ok(FeedbackReport {
        created: created.created,
        url: created.url,
        fingerprint,
        reason: None,
        title,
        body: Some(published),
    })
}

pub(crate) fn redact_feedback_text(text: &str, ctx: &FeedbackRedactionContext) -> String {
    let text = redact_private_keys(text, "<redacted:private_key>");
    let text = redact_tokens(&text, "<redacted:token>");
    let text = redact_secret_assignments(&text, "<redacted:secret>");
    let text = redact_emails(&text, "<redacted:email>");
    let text = redact_ipv4(&text, "<redacted:ipv4>");
    let text = redact_ipv6(&text, "<redacted:ipv6>");
    let text = redact_paths(&text, ctx);
    let text = redact_accounts(&text, None);
    let text = redact_identities(&text, &ctx.identities);
    scrub_prose(&text)
}

pub(crate) fn ensure_redacted(text: &str, ctx: &FeedbackRedactionContext) -> Result<()> {
    if let Some(class) = residual_class(text, ctx) {
        bail!("supervise feedback refused residual {class}");
    }
    Ok(())
}

impl FeedbackRedactionContext {
    pub(crate) fn from_process(repo_root: PathBuf) -> Self {
        let mut identities = Vec::new();
        for key in ["USER", "LOGNAME"] {
            if let Some(name) = std::env::var_os(key).and_then(|value| value.into_string().ok()) {
                push_identity(&mut identities, &name, "user", "<redacted:user>");
            }
        }
        let mut home_dirs = Vec::new();
        if let Some(home) = std::env::var_os("HOME").and_then(|value| value.into_string().ok()) {
            let home = home.trim().trim_end_matches(['/', '\\']);
            if !home.is_empty() {
                if let Some(base) = Path::new(home).file_name().and_then(|name| name.to_str()) {
                    push_identity(&mut identities, base, "user", "<redacted:user>");
                }
                home_dirs.push(PathBuf::from(home));
            }
        }
        for identity in identities
            .iter()
            .filter(|identity| identity.class == "user")
            .map(|identity| identity.name.clone())
            .collect::<Vec<_>>()
        {
            home_dirs.push(PathBuf::from(format!("/home/{identity}")));
            home_dirs.push(PathBuf::from(format!("/Users/{identity}")));
        }
        if let Some(host) = current_host_name() {
            push_identity(&mut identities, &host, "host", "<redacted:host>");
        }
        home_dirs.sort_by_key(|path| std::cmp::Reverse(path.as_os_str().len()));
        home_dirs.dedup();
        Self {
            repo_root,
            home_dirs,
            identities,
        }
    }

    #[cfg(test)]
    fn explicit(repo_root: PathBuf, homes: &[&str], users: &[&str], hosts: &[&str]) -> Self {
        let mut identities = Vec::new();
        for user in users {
            push_identity(&mut identities, user, "user", "<redacted:user>");
        }
        for host in hosts {
            push_identity(&mut identities, host, "host", "<redacted:host>");
        }
        let mut home_dirs = homes.iter().map(PathBuf::from).collect::<Vec<_>>();
        home_dirs.sort_by_key(|path| std::cmp::Reverse(path.as_os_str().len()));
        Self {
            repo_root,
            home_dirs,
            identities,
        }
    }
}

fn push_identity(
    identities: &mut Vec<IdentityRule>,
    name: &str,
    class: &'static str,
    replacement: &'static str,
) {
    let name = name.trim();
    if name.chars().count() < 3
        || name
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
    {
        return;
    }
    if identities
        .iter()
        .any(|identity| identity.name.eq_ignore_ascii_case(name))
    {
        return;
    }
    identities.push(IdentityRule {
        name: name.to_string(),
        class,
        replacement,
    });
}

fn current_host_name() -> Option<String> {
    let name = host_name_from_platform()?;
    let name = name.trim();
    if name.chars().count() < 3 {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(unix)]
fn host_name_from_platform() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: `buffer` is a 256-byte writable NUL-terminated region owned by this
    // function. On success, libc writes a host name and a trailing NUL within it.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()) };
    if rc != 0 {
        return None;
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    std::str::from_utf8(&buffer[..end]).ok().map(str::to_string)
}

#[cfg(windows)]
fn host_name_from_platform() -> Option<String> {
    // libc has no `gethostname` on this target. COMPUTERNAME is the process-visible host name.
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(not(any(unix, windows)))]
fn host_name_from_platform() -> Option<String> {
    None
}

fn run_succeeded(report: &SupervisorFinalReport) -> bool {
    report.run_lifecycle == SupervisorRunLifecycle::Finalized
        && report.success
        && !report.rejected
        && report.status == ReviewStatus::Succeeded
}

fn select_cause(report: &SupervisorFinalReport) -> Cause {
    let findings = collect_findings(report);
    let gate = first_gate(report);
    if let Some(cause) = finding_cause(&findings, FindingSeverity::Error, gate.as_ref()) {
        return cause;
    }
    if let Some(denial) = gate {
        return denial_cause(&denial, wire(&report.status));
    }
    if let Some(cause) = finding_cause(&findings, FindingSeverity::Warning, None) {
        return cause;
    }
    if let Some(validation) = first_failed_validation(report) {
        return validation_cause(&validation, wire(&report.status));
    }
    if let Some(gap) = report.coverage_gaps.first() {
        return gap_cause(gap, wire(&report.status));
    }
    if let Some(failure) = first_environment_failure(report) {
        return environment_cause(&failure, wire(&report.status));
    }
    status_cause(report)
}

fn finding_cause(
    findings: &[Found],
    severity: FindingSeverity,
    gate: Option<&GateDenial>,
) -> Option<Cause> {
    let matching = findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .collect::<Vec<_>>();
    let first = matching.first()?;
    let location = first
        .paths
        .first()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let line = first.message.lines().next().unwrap_or("").to_string();
    Some(Cause {
        kind: wire(&severity),
        gate: gate
            .map(|denial| reason_family(&denial.reason))
            .unwrap_or_else(|| "finding".to_string()),
        location,
        message: first.message.clone(),
        finding_line: line,
        extra: matching.len().saturating_sub(1),
        status: String::new(),
    })
}

fn denial_cause(denial: &GateDenial, status: String) -> Cause {
    let family = reason_family(&denial.reason);
    let message = format!(
        "family={family} route={} next={}",
        wire(&denial.route),
        wire(&denial.next_safe_operation)
    );
    let location = denial
        .context
        .paths
        .first()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    Cause {
        kind: family.clone(),
        gate: family,
        location,
        finding_line: message.clone(),
        message,
        extra: 0,
        status,
    }
}

fn validation_cause(validation: &ValidationResult, status: String) -> Cause {
    let message = validation
        .message
        .clone()
        .filter(|message| !message.trim().is_empty())
        .unwrap_or_else(|| validation.name.clone());
    Cause {
        kind: "validation".to_string(),
        gate: if validation.name.trim().is_empty() {
            "validation".to_string()
        } else {
            validation.name.clone()
        },
        location: String::new(),
        finding_line: message.lines().next().unwrap_or("").to_string(),
        message,
        extra: 0,
        status,
    }
}

fn gap_cause(gap: &SupervisorCoverageGap, status: String) -> Cause {
    Cause {
        kind: wire(&gap.kind),
        gate: "coverage".to_string(),
        location: String::new(),
        finding_line: gap.message.lines().next().unwrap_or("").to_string(),
        message: gap.message.clone(),
        extra: 0,
        status,
    }
}

fn environment_cause(failure: &EnvironmentFailure, status: String) -> Cause {
    Cause {
        kind: wire(&failure.category),
        gate: "environment".to_string(),
        location: String::new(),
        finding_line: failure.summary.lines().next().unwrap_or("").to_string(),
        message: failure.summary.clone(),
        extra: 0,
        status,
    }
}

fn status_cause(report: &SupervisorFinalReport) -> Cause {
    let kind = wire(&report.status);
    Cause {
        kind: kind.clone(),
        gate: "status".to_string(),
        location: String::new(),
        message: if report.remaining_risk.trim().is_empty() {
            kind.clone()
        } else {
            format!("{kind}\n{}", report.remaining_risk)
        },
        finding_line: kind,
        extra: 0,
        status: wire(&report.status),
    }
}

fn collect_findings(report: &SupervisorFinalReport) -> Vec<Found> {
    let mut found = Vec::new();
    push_findings(&mut found, &report.findings);
    for orchestrator in &report.orchestrator_reports {
        push_orchestrator_findings(&mut found, orchestrator);
    }
    found
}

fn push_orchestrator_findings(found: &mut Vec<Found>, orchestrator: &OrchestratorReviewReport) {
    push_findings(found, &orchestrator.findings);
    for worker in &orchestrator.worker_reports {
        push_worker_findings(found, worker);
    }
    for auditor in &orchestrator.audit_reports {
        push_auditor_findings(found, auditor);
    }
}

fn push_worker_findings(found: &mut Vec<Found>, worker: &WorkerReport) {
    push_findings(found, &worker.findings);
}

fn push_auditor_findings(found: &mut Vec<Found>, auditor: &AuditorReport) {
    push_findings(found, &auditor.findings);
}

fn push_findings(found: &mut Vec<Found>, findings: &[Finding]) {
    for finding in findings {
        found.push(Found {
            severity: finding.severity,
            message: finding.message.clone(),
            paths: finding.paths.clone(),
        });
    }
}

fn first_gate(report: &SupervisorFinalReport) -> Option<GateDenial> {
    report.gate_denials.first().cloned().or_else(|| {
        report
            .orchestrator_reports
            .iter()
            .find_map(|orchestrator| orchestrator.gate_denials.first().cloned())
    })
}

fn first_failed_validation(report: &SupervisorFinalReport) -> Option<ValidationResult> {
    fn failed(results: &[ValidationResult]) -> Option<ValidationResult> {
        results
            .iter()
            .find(|result| matches!(result.status, ReviewStatus::Failed | ReviewStatus::Rejected))
            .cloned()
    }
    if let Some(result) = failed(&report.validation_results) {
        return Some(result);
    }
    for orchestrator in &report.orchestrator_reports {
        if let Some(result) = failed(&orchestrator.validation_results) {
            return Some(result);
        }
        for worker in &orchestrator.worker_reports {
            if let Some(result) = failed(&worker.validation_results) {
                return Some(result);
            }
        }
        for auditor in &orchestrator.audit_reports {
            if let Some(result) = failed(&auditor.validation_results) {
                return Some(result);
            }
        }
    }
    None
}

fn first_environment_failure(report: &SupervisorFinalReport) -> Option<EnvironmentFailure> {
    if let Some(failure) = report.environment_failures.first() {
        return Some(failure.clone());
    }
    for orchestrator in &report.orchestrator_reports {
        if let Some(failure) = orchestrator.environment_failures.first() {
            return Some(failure.clone());
        }
        for worker in &orchestrator.worker_reports {
            if let Some(failure) = worker.environment_failures.first() {
                return Some(failure.clone());
            }
        }
        for auditor in &orchestrator.audit_reports {
            if let Some(failure) = auditor.environment_failures.first() {
                return Some(failure.clone());
            }
        }
    }
    None
}

fn reason_family(reason: &crate::gate_denial::GateDenialReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| {
            value
                .get("family")
                .and_then(|family| family.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "gate".to_string())
}

fn wire<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        _ => "unknown".to_string(),
    }
}

fn render_body(
    report: &SupervisorFinalReport,
    run_id: &RunId,
    repo_root: &Path,
    cause: &Cause,
) -> String {
    let identity = report
        .executable
        .clone()
        .unwrap_or_else(ExecutableBuildIdentity::compiled);
    let status = if cause.status.is_empty() {
        wire(&report.status)
    } else {
        cause.status.clone()
    };
    let line = cap_chars(
        &cause.finding_line.replace(['\r', '\n'], " "),
        FINDING_LINE_CHARS,
    );
    let line = if line.trim().is_empty() {
        "none".to_string()
    } else {
        line
    };
    let location = if cause.location.trim().is_empty() {
        "none".to_string()
    } else {
        cause.location.clone()
    };
    let mut body = String::new();
    body.push_str("## Summary\n");
    body.push_str(&format!(
        "The finished run did not succeed. Failing gate or stage: {}. Finding kind: {}.\n",
        cause.gate, cause.kind
    ));
    if cause.extra > 0 {
        body.push_str(&format!("Additional findings: {}.\n", cause.extra));
    }
    body.push_str("\n## Expected behavior\n");
    body.push_str("The run finishes with a succeeded status and no failing gate or finding.\n");
    body.push_str("\n## Actual behavior\n");
    body.push_str(&format!("Status: {status}\n"));
    body.push_str(&format!("Finding kind: {}\n", cause.kind));
    body.push_str(&format!("Finding: {line}\n"));
    body.push_str("\n## Reproduction\n");
    body.push_str(&format!("Package version: {}\n", identity.package_version));
    body.push_str(&format!(
        "Source revision: {}\n",
        identity
            .source_revision
            .filter(|revision| !revision.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    body.push_str(&format!(
        "Source state: {}\n",
        source_state_label(identity.source_state)
    ));
    body.push_str("Plan shape:\n");
    for line in plan_lines(report) {
        body.push_str(&format!("- {line}\n"));
    }
    body.push_str("Usage:\n");
    for line in usage_lines(report) {
        body.push_str(&format!("- {line}\n"));
    }
    body.push_str("\n## Evidence\n");
    body.push_str("Report paths:\n");
    for path in evidence_paths(repo_root, run_id) {
        body.push_str(&format!("- {path}\n"));
    }
    body.push_str(&format!("Source location: {location}\n"));
    body.push_str("\n## Impact\n");
    body.push_str("The finished run did not succeed, so its result cannot be treated as ready.\n");
    body
}

fn source_state_label(state: SourceState) -> &'static str {
    match state {
        SourceState::Clean => "clean",
        SourceState::Dirty => "dirty",
        SourceState::Unknown => "unknown",
    }
}

fn plan_lines(report: &SupervisorFinalReport) -> Vec<String> {
    if let Some(profile) = report.role_economics_profile.as_ref() {
        if let Some(execution) = profile.execution.as_ref() {
            if !execution.assignment_selection_ledger.is_empty() {
                return execution
                    .assignment_selection_ledger
                    .iter()
                    .map(|entry| {
                        format!(
                            "role={} runtime={} model={} effort={}",
                            entry.role.as_str(),
                            display_opt(entry.selected_runtime.as_deref()),
                            display_opt(entry.selected_model.as_deref()),
                            display_opt(entry.selected_reasoning_effort.as_deref())
                        )
                    })
                    .collect();
            }
        }
        if !profile.role_models.is_empty() {
            let runtime = runtime_wire(report.runtime);
            return profile
                .role_models
                .iter()
                .map(|(role, selection)| {
                    format!(
                        "role={} runtime={runtime} model={} effort={}",
                        role.as_str(),
                        display_opt(selection.model.as_deref()),
                        display_opt(selection.reasoning_effort.as_deref())
                    )
                })
                .collect();
        }
    }
    vec![format!("runtime={}", runtime_wire(report.runtime))]
}

fn display_opt(value: Option<&str>) -> &str {
    match value {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => "unavailable",
    }
}

fn runtime_wire(runtime: SupervisorRuntime) -> String {
    let wire = wire(&runtime);
    if wire == "unknown" {
        "unavailable".to_string()
    } else {
        wire
    }
}

fn usage_lines(report: &SupervisorFinalReport) -> [String; 4] {
    match report.total_usage {
        Some(usage) => [
            format!("input count: {}", usage.input_tokens),
            format!("output count: {}", usage.output_tokens),
            format!("total count: {}", usage.total_tokens),
            format!("cost usd: {}", format_cost(report.total_cost_usd)),
        ],
        None => [
            "input count: unavailable".to_string(),
            "output count: unavailable".to_string(),
            "total count: unavailable".to_string(),
            "cost usd: unavailable".to_string(),
        ],
    }
}

fn format_cost(value: Option<f64>) -> String {
    let Some(value) = value.filter(|value| value.is_finite()) else {
        return "unavailable".to_string();
    };
    let text = format!("{value:.6}");
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn evidence_paths(repo_root: &Path, run_id: &RunId) -> Vec<String> {
    let mut paths = vec![format!(
        ".maco/o2/runs/{}/reports/supervisor-final.json",
        run_id.as_str()
    )];
    let Ok(reader) = ArtifactRunReader::open(repo_root, RunArtifactFamily::Supervise, run_id)
    else {
        return paths;
    };
    for relative in [
        "assignments/supervisor-plan.json",
        SELECTION_LEDGER_RELATIVE,
    ] {
        if reader.read(Path::new(relative)).is_ok() {
            paths.push(format!(".maco/o2/runs/{}/{relative}", run_id.as_str()));
        }
    }
    paths
}

fn fingerprint_for(cause: &Cause, ctx: &FeedbackRedactionContext) -> String {
    let kind = collapse_ws(&cause.kind).to_ascii_lowercase();
    let gate = collapse_ws(&cause.gate).to_ascii_lowercase();
    let location = normalize_fingerprint_piece(&cause.location, ctx);
    let message = normalize_fingerprint_piece(&cause.message, ctx);
    let material = format!("{kind}\n{gate}\n{location}\n{message}");
    crate::artifacts::state_auth::sha256_hex(material.as_bytes())
}

fn normalize_fingerprint_piece(text: &str, ctx: &FeedbackRedactionContext) -> String {
    let text = redact_private_keys(text, "<n>");
    let text = redact_tokens(&text, "<n>");
    let text = redact_secret_assignments(&text, "<n>");
    let text = redact_emails(&text, "<n>");
    let text = redact_ipv4(&text, "<n>");
    let text = redact_ipv6(&text, "<n>");
    let text = redact_paths(&text, ctx);
    let text = redact_accounts(&text, Some("<n>"));
    let text = replace_numbers(&text);
    collapse_ws(&text)
}

fn find_duplicate(
    options: &FeedbackOptions,
    repo_root: &Path,
    marker: &str,
) -> Result<Option<String>> {
    match options.forge {
        FeedbackForge::Fake => find_fake_duplicate(repo_root, marker),
        FeedbackForge::Github if !options.dry_run => {
            crate::publication::search_open_github_issues_for_feedback_marker(repo_root, marker)
        }
        FeedbackForge::Github => Ok(None),
    }
}

fn create_feedback_issue(
    repo_root: &Path,
    title: &str,
    body: &str,
    forge: FeedbackForge,
) -> Result<IssuePublicationReport> {
    crate::publication::create_issue(IssuePublicationOptions {
        repo: repo_root.to_path_buf(),
        title: title.to_string(),
        body: body.to_string(),
        labels: vec![BETA_FEEDBACK_LABEL.to_string()],
        forge: match forge {
            FeedbackForge::Fake => ForgeKind::Fake,
            FeedbackForge::Github => ForgeKind::Github,
        },
    })
}

fn find_fake_duplicate(repo_root: &Path, marker: &str) -> Result<Option<String>> {
    let path = repo_root.join(FAKE_OPEN_ISSUES_RELATIVE);
    let bytes = read_fake_fixture(&path)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let issues: Vec<FakeOpenIssue> = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("supervise feedback fake issue fixture is invalid"))?;
    let mut urls = Vec::new();
    for issue in issues {
        if issue.url.is_empty()
            || issue.url.len() > 2048
            || issue
                .url
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            bail!("supervise feedback fake issue fixture is invalid");
        }
        if issue.state.eq_ignore_ascii_case("open") && issue.body.contains(marker) {
            urls.push(issue.url);
        }
    }
    urls.sort();
    Ok(urls.into_iter().next())
}

#[derive(Debug, serde::Deserialize)]
struct FakeOpenIssue {
    url: String,
    #[serde(default)]
    body: String,
    #[serde(default = "default_open_state")]
    state: String,
}

fn default_open_state() -> String {
    "open".to_string()
}

fn read_fake_fixture(path: &Path) -> Result<Vec<u8>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => bail!("supervise feedback fake issue fixture could not be read"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("supervise feedback fake issue fixture is not a regular file")
        }
        Ok(_) => BoundedRegularReader::read_tree_no_follow(path, FAKE_FIXTURE_MAX_BYTES)
            .context("supervise feedback fake issue fixture could not be read"),
    }
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .context("failed to discover the feedback repository")?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("supervise feedback requires a non-bare repository")
}

fn cap_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect()
    }
}

fn collapse_ws(text: &str) -> String {
    let mut output = String::new();
    let mut pending = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending = !output.is_empty();
            continue;
        }
        if pending {
            output.push(' ');
            pending = false;
        }
        output.push(ch);
    }
    output
}

fn rewrite<F>(text: &str, mut matcher: F) -> String
where
    F: FnMut(&str, usize) -> Option<(usize, String)>,
{
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if let Some((end, replacement)) = matcher(text, index) {
            if end > index && text.is_char_boundary(end) {
                output.push_str(&replacement);
                index = end;
                continue;
            }
        }
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

fn residual_class(text: &str, ctx: &FeedbackRedactionContext) -> Option<&'static str> {
    if contains_private_key(text) {
        return Some("private_key");
    }
    if has_span(text, match_token) {
        return Some("token");
    }
    if has_raw_secret_assignment(text) {
        return Some("secret");
    }
    if has_span(text, match_email) {
        return Some("email");
    }
    if has_span(text, match_ipv4) {
        return Some("ipv4");
    }
    if has_span(text, match_ipv6) {
        return Some("ipv6");
    }
    if has_span(text, |value, index| {
        match_absolute_path(value, index, ctx).map(|(end, _)| end)
    }) {
        return Some("path");
    }
    if has_span(text, |value, index| {
        match_account(value, index).map(|(end, _)| end)
    }) {
        return Some("account_id");
    }
    if let Some(class) = residual_identity(text, &ctx.identities) {
        return Some(class);
    }
    None
}

fn has_span<F>(text: &str, mut matcher: F) -> bool
where
    F: FnMut(&str, usize) -> Option<usize>,
{
    let mut index = 0;
    while index < text.len() {
        if let Some(end) = matcher(text, index) {
            if end > index {
                return true;
            }
        }
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        index += ch.len_utf8();
    }
    false
}

fn redact_private_keys(text: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = find_ascii_ignore_case(rest, "-----BEGIN ") {
        let after_begin = start + "-----BEGIN ".len();
        let Some(header_end) = rest[after_begin..].find("-----") else {
            output.push_str(rest);
            return output;
        };
        let header = &rest[after_begin..after_begin + header_end];
        if !header.to_ascii_uppercase().contains("PRIVATE KEY") {
            output.push_str(&rest[..after_begin]);
            rest = &rest[after_begin..];
            continue;
        }
        let search_from = after_begin + header_end;
        let Some(end_rel) = find_ascii_ignore_case(&rest[search_from..], "-----END ") else {
            output.push_str(rest);
            return output;
        };
        let end_header = search_from + end_rel + "-----END ".len();
        let Some(end_close) = rest[end_header..].find("-----") else {
            output.push_str(rest);
            return output;
        };
        output.push_str(&rest[..start]);
        output.push_str(replacement);
        rest = &rest[end_header + end_close + 5..];
    }
    output.push_str(rest);
    output
}

fn contains_private_key(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY")
}

fn find_ascii_ignore_case(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn redact_tokens(text: &str, replacement: &str) -> String {
    let replacement = replacement.to_string();
    rewrite(text, |text, index| {
        match_token(text, index).map(|end| (end, replacement.clone()))
    })
}

fn match_token(text: &str, index: usize) -> Option<usize> {
    match_jwt(text, index)
        .or_else(|| match_aws_key(text, index))
        .or_else(|| match_bearer(text, index))
        .or_else(|| match_prefixed_token(text, index))
        .or_else(|| match_hex_secret(text, index))
        .or_else(|| match_mixed_secret(text, index))
}

fn match_jwt(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let rest = text.get(index..)?;
    if !rest.starts_with("eyJ") {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut cursor = 0;
    for segment in 0..3 {
        let start = cursor;
        while cursor < bytes.len() && is_base64url(bytes[cursor]) {
            cursor += 1;
        }
        if cursor - start < 3 {
            return None;
        }
        if segment < 2 {
            if cursor >= bytes.len() || bytes[cursor] != b'.' {
                return None;
            }
            cursor += 1;
        }
    }
    if cursor < 20 || !boundary_after(text, index + cursor) {
        return None;
    }
    Some(index + cursor)
}

fn match_aws_key(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let rest = text.get(index..)?;
    if !(rest.starts_with("AKIA") || rest.starts_with("ASIA")) {
        return None;
    }
    let bytes = rest.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if !bytes[4..20]
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    if !boundary_after(text, index + 20) {
        return None;
    }
    Some(index + 20)
}

fn match_bearer(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes().get(index..)?;
    if bytes.len() < 6 || !bytes[..6].eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    if !boundary_after(text, index + 6) {
        return None;
    }
    let mut cursor = 6;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let start = cursor;
    while cursor < bytes.len() && is_token_char(bytes[cursor]) {
        cursor += 1;
    }
    if cursor - start < 8 {
        return None;
    }
    Some(index + cursor)
}

fn match_prefixed_token(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    const PREFIXES: &[&str] = &[
        "github_pat_",
        "sk_live_",
        "sk_test_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "ya29.",
        "sk-",
        "AIza",
    ];
    let rest = text.get(index..)?;
    let prefix = PREFIXES.iter().find(|prefix| rest.starts_with(*prefix))?;
    let bytes = rest.as_bytes();
    let mut cursor = prefix.len();
    while cursor < bytes.len() && is_token_char(bytes[cursor]) {
        cursor += 1;
    }
    if cursor - prefix.len() < 8 || !boundary_after(text, index + cursor) {
        return None;
    }
    Some(index + cursor)
}

fn match_hex_secret(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut cursor = index;
    while cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() {
        cursor += 1;
    }
    let len = cursor - index;
    if len < 32 || !boundary_after(text, cursor) {
        return None;
    }
    if hex_is_recorded_source_revision(text, index, cursor) {
        return None;
    }
    Some(cursor)
}

/// A git digest is kept only when it is the entire recorded source-revision field.
fn hex_is_recorded_source_revision(text: &str, start: usize, end: usize) -> bool {
    const LABEL: &str = "Source revision: ";
    let label = LABEL.as_bytes();
    if start < label.len() || (end - start != 40 && end - start != 64) {
        return false;
    }
    let line_start = start - label.len();
    if text.as_bytes().get(line_start..start) != Some(label) {
        return false;
    }
    if line_start > 0 && text.as_bytes()[line_start - 1] != b'\n' {
        return false;
    }
    matches!(text.as_bytes().get(end), None | Some(b'\n' | b'\r'))
}

fn match_mixed_secret(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut cursor = index;
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    while cursor < bytes.len() && is_mixed_secret_char(bytes[cursor]) {
        let byte = bytes[cursor];
        upper |= byte.is_ascii_uppercase();
        lower |= byte.is_ascii_lowercase();
        digit |= byte.is_ascii_digit();
        cursor += 1;
    }
    let len = cursor - index;
    if len >= 32 && upper && lower && digit && boundary_after(text, cursor) {
        Some(cursor)
    } else {
        None
    }
}

fn redact_secret_assignments(text: &str, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'=' | b':') && is_secret_key(trailing_key(&text[..cursor])) {
            let mut value_start = cursor + 1;
            while value_start < bytes.len() && bytes[value_start] == b' ' {
                value_start += 1;
            }
            if value_start < bytes.len() && !bytes[value_start].is_ascii_whitespace() {
                let value_end = secret_value_end(bytes, value_start);
                let value = &text[value_start..value_end];
                if !value.starts_with("<redacted:") && value != "<n>" {
                    output.push_str(&text[cursor..value_start]);
                    output.push_str(replacement);
                    cursor = value_end;
                    continue;
                }
            }
        }
        let ch = text[cursor..].chars().next().unwrap_or('\0');
        if ch == '\0' {
            break;
        }
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output
}

fn has_raw_secret_assignment(text: &str) -> bool {
    redact_secret_assignments(text, "<redacted:secret>") != text
}

fn secret_value_end(bytes: &[u8], value_start: usize) -> usize {
    let quote = bytes[value_start];
    if quote == b'"' || quote == b'\'' {
        let mut end = value_start + 1;
        while end < bytes.len() && bytes[end] != quote {
            end += 1;
        }
        if end < bytes.len() {
            end + 1
        } else {
            end
        }
    } else {
        let mut end = value_start;
        while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
            end += 1;
        }
        end
    }
}

fn trailing_key(prefix: &str) -> &str {
    let trimmed = prefix.trim_end();
    let start = trimmed
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '"' | '\'')))
        .map(|index| {
            index
                + trimmed[index..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1)
        })
        .unwrap_or(0);
    &trimmed[start..]
}

fn is_secret_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let normalized = key
        .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch.is_whitespace())
        .to_ascii_uppercase()
        .replace('-', "_");
    [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PRIVATE_KEY",
        "API_KEY",
        "AUTHORIZATION",
        "BEARER",
    ]
    .iter()
    .any(|word| normalized.contains(word))
}

fn redact_emails(text: &str, replacement: &str) -> String {
    let replacement = replacement.to_string();
    rewrite(text, |text, index| {
        match_email(text, index).map(|end| (end, replacement.clone()))
    })
}

fn match_email(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut cursor = index;
    if cursor >= bytes.len() || !is_email_local(bytes[cursor]) {
        return None;
    }
    while cursor < bytes.len() && is_email_local(bytes[cursor]) {
        cursor += 1;
    }
    if cursor >= bytes.len() || bytes[cursor] != b'@' {
        return None;
    }
    cursor += 1;
    let mut dots = 0;
    let mut label_len = 0;
    let domain_start = cursor;
    while cursor < bytes.len() && is_email_domain(bytes[cursor]) {
        if bytes[cursor] == b'.' {
            let next = cursor + 1;
            if next >= bytes.len() || !is_email_label_char(bytes[next]) {
                break;
            }
            if label_len == 0 {
                return None;
            }
            dots += 1;
            label_len = 0;
        } else {
            label_len += 1;
        }
        cursor += 1;
    }
    if dots < 1 || label_len < 2 || cursor == domain_start || !boundary_after(text, cursor) {
        return None;
    }
    Some(cursor)
}

fn redact_ipv4(text: &str, replacement: &str) -> String {
    let replacement = replacement.to_string();
    rewrite(text, |text, index| {
        match_ipv4(text, index).map(|end| (end, replacement.clone()))
    })
}

fn match_ipv4(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes();
    if index >= bytes.len() || !bytes[index].is_ascii_digit() {
        return None;
    }
    let mut cursor = index;
    for part in 0..4 {
        if part > 0 {
            if cursor >= bytes.len() || bytes[cursor] != b'.' {
                return None;
            }
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() && cursor - start < 3 {
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        let value = text[start..cursor].parse::<u16>().ok()?;
        if value > 255 {
            return None;
        }
    }
    if cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
        return None;
    }
    if cursor < bytes.len()
        && bytes[cursor] == b'.'
        && bytes
            .get(cursor + 1)
            .is_some_and(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    if !boundary_after(text, cursor) {
        return None;
    }
    Some(cursor)
}

fn redact_ipv6(text: &str, replacement: &str) -> String {
    let replacement = replacement.to_string();
    rewrite(text, |text, index| {
        match_ipv6(text, index).map(|end| (end, replacement.clone()))
    })
}

fn match_ipv6(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    let bytes = text.as_bytes();
    if index >= bytes.len() || !(bytes[index].is_ascii_hexdigit() || bytes[index] == b':') {
        return None;
    }
    let mut cursor = index;
    let mut groups = 0usize;
    let mut saw_compression = false;
    let mut saw_letter = false;
    let mut saw_group = false;
    while cursor < bytes.len() {
        if bytes[cursor] == b':' {
            if cursor + 1 < bytes.len() && bytes[cursor + 1] == b':' {
                if saw_compression {
                    break;
                }
                saw_compression = true;
                saw_group = false;
                cursor += 2;
                continue;
            }
            if !saw_group {
                break;
            }
            saw_group = false;
            cursor += 1;
            continue;
        }
        if !bytes[cursor].is_ascii_hexdigit() {
            break;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() && cursor - start < 4 {
            if bytes[cursor].is_ascii_alphabetic() {
                saw_letter = true;
            }
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() {
            return None;
        }
        groups += 1;
        saw_group = true;
        if groups > 8 {
            return None;
        }
    }
    if cursor > index && bytes[cursor - 1] == b':' && !(cursor >= 2 && bytes[cursor - 2] == b':') {
        cursor -= 1;
    }
    if cursor <= index || !boundary_after(text, cursor) {
        return None;
    }
    let token = &text[index..cursor];
    let ipv6 = token.contains("::") || groups >= 6 || (groups >= 4 && saw_letter);
    if ipv6 {
        Some(cursor)
    } else {
        None
    }
}

fn redact_paths(text: &str, ctx: &FeedbackRedactionContext) -> String {
    rewrite(text, |text, index| match_absolute_path(text, index, ctx))
}

fn match_absolute_path(
    text: &str,
    index: usize,
    ctx: &FeedbackRedactionContext,
) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if index >= bytes.len() {
        return None;
    }
    if bytes[index] == b'~' {
        let mut cursor = index + 1;
        if cursor < bytes.len() && bytes[cursor] == b'/' {
            cursor += 1;
            while cursor < bytes.len() && is_path_char(bytes[cursor]) {
                cursor += 1;
            }
        }
        cursor = strip_trailing_dot(text, index, cursor);
        if cursor > index + 1 {
            return Some((cursor, "<path>".to_string()));
        }
        return None;
    }
    if bytes[index].is_ascii_alphabetic()
        && index + 2 < bytes.len()
        && bytes[index + 1] == b':'
        && matches!(bytes[index + 2], b'\\' | b'/')
        && boundary_before(text, index)
    {
        let mut cursor = index + 3;
        while cursor < bytes.len() && is_windows_path_char(bytes[cursor]) {
            cursor += 1;
        }
        return Some((cursor, "<path>".to_string()));
    }
    if bytes[index] == b'\\'
        && index + 1 < bytes.len()
        && bytes[index + 1] == b'\\'
        && boundary_before(text, index)
    {
        let mut cursor = index + 2;
        if cursor >= bytes.len() || !is_unc_name_char(bytes[cursor]) {
            return None;
        }
        while cursor < bytes.len() && is_windows_path_char(bytes[cursor]) {
            cursor += 1;
        }
        cursor = strip_trailing_dot(text, index, cursor);
        if cursor > index + 2 {
            return Some((cursor, "<path>".to_string()));
        }
        return None;
    }
    if bytes[index] != b'/' || slash_is_url(text, index) {
        return None;
    }
    if index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_') {
        return None;
    }
    let mut cursor = index + 1;
    if cursor >= bytes.len() || !is_path_char(bytes[cursor]) {
        return None;
    }
    while cursor < bytes.len() && is_path_char(bytes[cursor]) {
        cursor += 1;
    }
    cursor = strip_trailing_dot(text, index, cursor);
    if cursor <= index + 1 {
        return None;
    }
    let path = &text[index..cursor];
    let replacement = repo_relative(path, &ctx.repo_root)
        .or_else(|| home_path_replacement(path, &ctx.home_dirs))
        .unwrap_or_else(|| "<path>".to_string());
    Some((cursor, replacement))
}

fn home_path_replacement(path: &str, homes: &[PathBuf]) -> Option<String> {
    let matched = homes.iter().any(|home| {
        let Some(home) = home.to_str() else {
            return false;
        };
        let home = home.trim_end_matches(['/', '\\']);
        !home.is_empty()
            && (path == home
                || path.starts_with(&format!("{home}/"))
                || path.starts_with(&format!("{home}\\")))
    });
    if matched {
        Some("<path>".to_string())
    } else {
        None
    }
}

fn strip_trailing_dot(text: &str, start: usize, end: usize) -> usize {
    if end > start + 1 && text.as_bytes()[end - 1] == b'.' && text.as_bytes()[end - 2] != b'.' {
        end - 1
    } else {
        end
    }
}

fn slash_is_url(text: &str, index: usize) -> bool {
    let bytes = text.as_bytes();
    (index > 0 && bytes[index - 1] == b':')
        || (index >= 2 && bytes[index - 2] == b':' && bytes[index - 1] == b'/')
}

fn repo_relative(path: &str, repo_root: &Path) -> Option<String> {
    let repo = repo_root.to_str()?.trim_end_matches('/');
    if repo.is_empty() {
        return None;
    }
    if path == repo {
        return Some(".".to_string());
    }
    let rest = path.strip_prefix(repo)?.strip_prefix('/')?;
    if rest.is_empty() {
        Some(".".to_string())
    } else {
        Some(rest.to_string())
    }
}

fn redact_accounts(text: &str, fingerprint_replacement: Option<&str>) -> String {
    rewrite(text, |text, index| {
        match_account(text, index).map(|(end, label_len)| {
            let replacement = if let Some(replacement) = fingerprint_replacement {
                replacement.to_string()
            } else {
                let token_len = end - index;
                let label = account_label(&text[index..index + label_len]);
                format!("{label}({token_len})")
            };
            (end, replacement)
        })
    })
}

fn match_account(text: &str, index: usize) -> Option<(usize, usize)> {
    if !boundary_before(text, index) {
        return None;
    }
    const LABELS: &[&str] = &["account_id", "account-id", "accountid", "acct_id", "acct"];
    let rest = text.get(index..)?;
    let label = LABELS
        .iter()
        .find(|label| ascii_starts_with_ignore_case(rest, label))?;
    let label_len = label.len();
    let bytes = rest.as_bytes();
    if let Some(end) = match_account_assignment(bytes, label_len) {
        return Some((index + end, label_len));
    }
    if label_len >= bytes.len() || !is_account_char(bytes[label_len]) {
        return None;
    }
    let mut cursor = label_len;
    while cursor < bytes.len() && is_account_char(bytes[cursor]) {
        cursor += 1;
    }
    if !boundary_after(text, index + cursor) {
        return None;
    }
    Some((index + cursor, label_len))
}

fn match_account_assignment(bytes: &[u8], label_len: usize) -> Option<usize> {
    let mut cursor = label_len;
    while cursor < bytes.len() && bytes[cursor] == b' ' {
        cursor += 1;
    }
    if cursor < bytes.len() && matches!(bytes[cursor], b'"' | b'\'') {
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            cursor += 1;
        }
    }
    if cursor >= bytes.len() || !matches!(bytes[cursor], b'=' | b':') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() && bytes[cursor] == b' ' {
        cursor += 1;
    }
    if cursor < bytes.len() && matches!(bytes[cursor], b'"' | b'\'') {
        cursor += 1;
    }
    let value_start = cursor;
    while cursor < bytes.len() && is_account_char(bytes[cursor]) {
        cursor += 1;
    }
    if cursor == value_start {
        return None;
    }
    if cursor < bytes.len() && matches!(bytes[cursor], b'"' | b'\'') {
        cursor += 1;
    }
    Some(cursor)
}

fn ascii_starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    let bytes = text.as_bytes();
    let prefix = prefix.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn account_label(label: &str) -> &str {
    if label.eq_ignore_ascii_case("account_id") {
        "account_id"
    } else if label.eq_ignore_ascii_case("account-id") {
        "account-id"
    } else if label.eq_ignore_ascii_case("accountid") {
        "accountid"
    } else if label.eq_ignore_ascii_case("acct_id") {
        "acct_id"
    } else {
        "acct"
    }
}

fn redact_identities(text: &str, identities: &[IdentityRule]) -> String {
    let mut ordered = identities.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|identity| std::cmp::Reverse(identity.name.len()));
    rewrite(text, |text, index| {
        identity_at(text, index, &ordered)
            .map(|(end, identity)| (end, identity.replacement.to_string()))
    })
}

fn residual_identity(text: &str, identities: &[IdentityRule]) -> Option<&'static str> {
    let mut ordered = identities.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|identity| std::cmp::Reverse(identity.name.len()));
    let mut index = 0;
    while index < text.len() {
        if let Some((_, identity)) = identity_at(text, index, &ordered) {
            return Some(identity.class);
        }
        let ch = text[index..].chars().next()?;
        index += ch.len_utf8();
    }
    None
}

fn identity_at<'a>(
    text: &str,
    index: usize,
    identities: &[&'a IdentityRule],
) -> Option<(usize, &'a IdentityRule)> {
    if !boundary_before(text, index) || prev_is_dot(text, index) {
        return None;
    }
    for identity in identities {
        if is_ignored_identity(&identity.name) || identity.name.chars().count() < 3 {
            continue;
        }
        let Some(len) = prefix_eq_ignore_ascii_case(&text[index..], &identity.name) else {
            continue;
        };
        if boundary_after(text, index + len) {
            return Some((index + len, identity));
        }
    }
    None
}

fn prefix_eq_ignore_ascii_case(text: &str, name: &str) -> Option<usize> {
    let mut bytes = 0;
    let mut chars = text.chars();
    for expected in name.chars() {
        let actual = chars.next()?;
        if !actual.eq_ignore_ascii_case(&expected) {
            return None;
        }
        bytes += actual.len_utf8();
    }
    Some(bytes)
}

fn is_ignored_identity(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "actual",
        "additional",
        "assignment",
        "assignments",
        "auditor",
        "behavior",
        "cannot",
        "clean",
        "codex",
        "cost",
        "count",
        "cursor",
        "deepseek",
        "defect",
        "dirty",
        "effort",
        "email",
        "evidence",
        "expected",
        "failing",
        "fake",
        "feedback",
        "final",
        "finding",
        "findings",
        "finished",
        "gate",
        "grok",
        "host",
        "impact",
        "input",
        "json",
        "kind",
        "ledger",
        "location",
        "model",
        "none",
        "output",
        "package",
        "path",
        "paths",
        "plan",
        "ready",
        "redacted",
        "report",
        "reports",
        "reproduction",
        "researcher",
        "result",
        "revision",
        "role",
        "run",
        "runs",
        "selection",
        "shape",
        "source",
        "stage",
        "state",
        "status",
        "succeed",
        "succeeded",
        "supervisor",
        "system",
        "total",
        "treated",
        "unavailable",
        "unknown",
        "usage",
        "usd",
        "user",
        "version",
        "with",
        "worker",
    ];
    WORDS.iter().any(|word| word.eq_ignore_ascii_case(name))
}

fn scrub_prose(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphanumeric() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
                index += 1;
            }
            let word = &text[start..index];
            if word.eq_ignore_ascii_case("ai") {
                output.push_str("system");
            } else if word.eq_ignore_ascii_case("agent") || word.eq_ignore_ascii_case("agents") {
                output.push_str("worker");
            } else {
                output.push_str(word);
            }
        } else {
            let ch = text[index..].chars().next().unwrap_or('\0');
            if ch == '\0' {
                break;
            }
            output.push(ch);
            index += ch.len_utf8();
        }
    }
    output
}

fn replace_numbers(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = match_uuid(text, index) {
            output.push_str("<n>");
            index = end;
            continue;
        }
        if bytes[index].is_ascii_hexdigit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                index += 1;
            }
            let token = &text[start..index];
            if token.len() >= 8 || token.bytes().all(|byte| byte.is_ascii_digit()) {
                output.push_str("<n>");
            } else {
                output.push_str(token);
            }
            continue;
        }
        let ch = text[index..].chars().next().unwrap_or('\0');
        if ch == '\0' {
            break;
        }
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

fn match_uuid(text: &str, index: usize) -> Option<usize> {
    if !boundary_before(text, index) {
        return None;
    }
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = text.as_bytes();
    let mut cursor = index;
    for (group, len) in GROUPS.into_iter().enumerate() {
        if group > 0 {
            if bytes.get(cursor) != Some(&b'-') {
                return None;
            }
            cursor += 1;
        }
        let end = cursor + len;
        if end > bytes.len()
            || !bytes[cursor..end]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        cursor = end;
    }
    if boundary_after(text, cursor) {
        Some(cursor)
    } else {
        None
    }
}

fn boundary_before(text: &str, index: usize) -> bool {
    index == 0
        || !text
            .as_bytes()
            .get(index - 1)
            .is_some_and(|byte| is_word_byte(*byte))
}

fn boundary_after(text: &str, index: usize) -> bool {
    index >= text.len()
        || !text
            .as_bytes()
            .get(index)
            .is_some_and(|byte| is_word_byte(*byte))
}

fn prev_is_dot(text: &str, index: usize) -> bool {
    index > 0 && text.as_bytes()[index - 1] == b'.'
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_mixed_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_email_local(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn is_email_label_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn is_path_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~')
}

fn is_windows_path_char(byte: u8) -> bool {
    is_path_char(byte) || byte == b'\\'
}

fn is_unc_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn is_account_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{ArtifactFileDisposition, ArtifactRunWriter};
    use crate::gate_denial::GateDenial;
    use std::process::Command;

    fn context() -> FeedbackRedactionContext {
        FeedbackRedactionContext::explicit(
            PathBuf::from("/srv/repo"),
            &["/home/ada"],
            &["ada"],
            &["buildbox"],
        )
    }

    fn base_report(run_id: &str) -> SupervisorFinalReport {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "run_id": run_id,
            "role": "supervisor",
            "repo": ".",
            "plan_file": "plan.json",
            "run_dir": format!(".maco/o2/runs/{run_id}"),
            "runtime": "fake",
            "publishable": false,
            "success": false,
            "accepted": false,
            "rejected": false,
            "status": "failed",
            "run_lifecycle": "finalized",
            "remaining_risk": "CHAT TRANSCRIPT should stay private",
            "next_safe_action": "prompt: do not publish",
            "total_usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
            "total_cost_usd": 1.25,
            "executable": {
                "package_version": "9.9.9",
                "source_revision": "0123456789abcdef0123456789abcdef01234567",
                "source_state": "clean"
            },
            "role_economics_profile": {
                "name": "feedback-test",
                "evidence": "fixture",
                "evidence_notice": "fixture",
                "production_eligible": false,
                "role_models": {
                    "worker": {"model": "demo-model", "reasoning_effort": "low"}
                }
            }
        }))
        .expect("feedback fixture report")
    }

    fn init_repo() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temp repo");
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo).expect("init repo");
        fs::write(repo.join("README.md"), "baseline\n").expect("readme");
        let git = git2::Repository::open(&repo).expect("open repo");
        git.config()
            .expect("config")
            .set_str("user.name", "Fixture")
            .expect("name");
        git.config()
            .expect("config")
            .set_str("user.email", "fixture@example.invalid")
            .expect("email");
        Command::new("git")
            .current_dir(&repo)
            .args(["add", "README.md"])
            .status()
            .expect("git add");
        Command::new("git")
            .current_dir(&repo)
            .args(["commit", "-m", "baseline"])
            .status()
            .expect("git commit");
        let repo = repo.canonicalize().expect("canonical repo");
        (temp, repo)
    }

    fn finalize(repo: &Path, report: &SupervisorFinalReport) {
        let mut writer = ArtifactRunWriter::reserve(
            repo,
            RunArtifactFamily::Supervise,
            report.run_id.clone(),
            "feedback-test",
        )
        .expect("reserve run");
        let mut bytes = serde_json::to_vec_pretty(report).expect("serialize report");
        bytes.push(b'\n');
        writer
            .write_bytes(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &bytes,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write final report");
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize run");
    }

    fn failed_report(repo: &Path, run_id: &str, message: &str) -> SupervisorFinalReport {
        let mut report = base_report(run_id);
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: message.to_string(),
            paths: vec![repo.join("src/lib.rs")],
        });
        report.gate_denials.push(
            GateDenial::from_claim_conflict(
                "feedback-test",
                "stage-validation",
                [Path::new("src/lib.rs")],
            )
            .expect("claim conflict"),
        );
        report
    }

    fn feedback(repo: &Path, run_id: &str, forge: FeedbackForge, dry_run: bool) -> FeedbackReport {
        supervise_feedback(FeedbackOptions {
            repo: repo.to_path_buf(),
            run_id: run_id.to_string(),
            forge,
            dry_run,
        })
        .expect("feedback")
    }

    #[test]
    fn succeeded_run_is_a_noop() {
        let (_temp, repo) = init_repo();
        let mut report = base_report("feedback-ok");
        report.success = true;
        report.status = ReviewStatus::Succeeded;
        report.accepted = false;
        finalize(&repo, &report);
        let report = feedback(&repo, "feedback-ok", FeedbackForge::Fake, false);
        assert!(!report.created);
        assert_eq!(report.reason, Some(FeedbackReason::RunSucceeded));
        assert!(report.url.is_none());
        assert!(report.fingerprint.is_empty());
        assert!(report.title.is_empty());
        assert!(report.body.is_none());
    }

    #[test]
    fn unfinished_run_is_refused() {
        let (_temp, repo) = init_repo();
        let error = supervise_feedback(FeedbackOptions {
            repo: repo.clone(),
            run_id: "missing-run".to_string(),
            forge: FeedbackForge::Fake,
            dry_run: true,
        })
        .expect_err("missing run");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("unfinished"), "{rendered}");
        assert!(!rendered.contains("missing-run"), "{rendered}");

        let mut active = base_report("feedback-active");
        active.run_lifecycle = SupervisorRunLifecycle::Active;
        finalize(&repo, &active);
        let error = supervise_feedback(FeedbackOptions {
            repo,
            run_id: "feedback-active".to_string(),
            forge: FeedbackForge::Fake,
            dry_run: true,
        })
        .expect_err("active lifecycle");
        assert!(format!("{error:#}").contains("unfinished"));
    }

    #[test]
    fn failed_run_body_has_required_sections_and_survives_issue_redaction() {
        let (_temp, repo) = init_repo();
        let message = format!(
            "check failed at {}/src/lib.rs:12 id run-111\nCHAT TRANSCRIPT prompt: hidden",
            repo.display()
        );
        let report = failed_report(&repo, "feedback-failed", &message);
        finalize(&repo, &report);
        let report = feedback(&repo, "feedback-failed", FeedbackForge::Fake, true);
        assert!(!report.created);
        assert_eq!(report.reason, Some(FeedbackReason::DryRun));
        assert!(report.url.is_none());
        assert_eq!(report.fingerprint.len(), 64);
        let body = report.body.expect("body");
        for section in [
            "## Summary",
            "## Expected behavior",
            "## Actual behavior",
            "## Reproduction",
            "## Evidence",
            "## Impact",
        ] {
            assert!(body.contains(section), "{section} missing:\n{body}");
        }
        let positions = [
            "## Summary",
            "## Expected behavior",
            "## Actual behavior",
            "## Reproduction",
            "## Evidence",
            "## Impact",
        ]
        .into_iter()
        .map(|section| body.find(section).expect(section))
        .collect::<Vec<_>>();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(body.contains("claim_conflict"), "{body}");
        assert!(body.contains("Finding kind: error"), "{body}");
        assert!(body.contains("src/lib.rs:12"), "{body}");
        assert!(!body.contains(&repo.display().to_string()), "{body}");
        assert!(body.contains("Package version: 9.9.9"), "{body}");
        assert!(
            body.contains("0123456789abcdef0123456789abcdef01234567"),
            "{body}"
        );
        assert!(
            body.contains("role=worker runtime=fake model=demo-model effort=low"),
            "{body}"
        );
        assert!(body.contains("input count: 3"), "{body}");
        assert!(body.contains("output count: 4"), "{body}");
        assert!(body.contains("total count: 7"), "{body}");
        assert!(body.contains("cost usd: 1.25"), "{body}");
        assert!(body.contains(".maco/o2/runs/feedback-failed/reports/supervisor-final.json"));
        assert!(body.contains(
            "The finished run did not succeed, so its result cannot be treated as ready."
        ));
        assert!(body.contains(&format!("<!-- maco-feedback:{} -->", report.fingerprint)));
        let lower = body.to_ascii_lowercase();
        assert!(!lower.contains("agent"), "{body}");
        assert!(!body.contains("AI"), "{body}");
        assert!(!body.contains("CHAT TRANSCRIPT"), "{body}");
        assert!(!body.contains("prompt:"), "{body}");
        let redacted = crate::llm::Redactor::new().redact(&body);
        assert_eq!(redacted.text, body);
        assert_eq!(report.title, "Defect: error at claim_conflict");
    }

    #[test]
    fn redaction_covers_each_privacy_class() {
        let ctx = context();
        let cases = [
            (
                "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
                "<redacted:private_key>",
                "-----BEGIN PRIVATE KEY-----",
            ),
            (
                "prefix ghp_abcdefghijklmnopqrstuvwxyz012345 suffix",
                "<redacted:token>",
                "ghp_abcdefghijklmnopqrstuvwxyz012345",
            ),
            (
                "API_TOKEN=supersecretvalue next",
                "API_TOKEN=<redacted:secret> next",
                "supersecretvalue",
            ),
            (
                "mail ada@example.com today",
                "<redacted:email>",
                "ada@example.com",
            ),
            ("bind 203.0.113.9 now", "<redacted:ipv4>", "203.0.113.9"),
            ("bind 2001:db8::1 now", "<redacted:ipv6>", "2001:db8::1"),
            (
                "see /var/lib/secret-file now",
                "<path>",
                "/var/lib/secret-file",
            ),
            (
                "see /srv/repo/src/lib.rs now",
                "src/lib.rs",
                "/srv/repo/src/lib.rs",
            ),
            ("see /home/ada/notes now", "<path>", "/home/ada"),
            ("acct_ABCDEFGHIJKLMNOP", "acct(21)", "acct_ABCDEFGHIJKLMNOP"),
            ("operator ada ran", "<redacted:user>", "ada"),
            ("box buildbox ran", "<redacted:host>", "buildbox"),
        ];
        for (input, expected, absent) in cases {
            let redacted = redact_feedback_text(input, &ctx);
            assert!(
                redacted.contains(expected),
                "input {input:?} redacted to {redacted:?}, expected {expected:?}"
            );
            assert!(!redacted.contains(absent), "{redacted}");
            ensure_redacted(&redacted, &ctx).expect("redacted text");
        }
        let preserved = redact_feedback_text(
            "version 9.9.9 at 12:30:00 rev 0123456789abcdef0123456789abcdef01234567",
            &ctx,
        );
        assert!(preserved.contains("9.9.9"), "{preserved}");
        assert!(preserved.contains("12:30:00"), "{preserved}");
        assert!(
            !preserved.contains("0123456789abcdef0123456789abcdef01234567"),
            "{preserved}"
        );
        assert!(preserved.contains("<redacted:token>"), "{preserved}");
        let revision = redact_feedback_text(
            "Source revision: 0123456789abcdef0123456789abcdef01234567\n",
            &ctx,
        );
        assert!(
            revision.contains("Source revision: 0123456789abcdef0123456789abcdef01234567"),
            "{revision}"
        );
        ensure_redacted(&revision, &ctx).expect("recorded revision");
        let prose = redact_feedback_text("The AI agent and agents failed", &ctx);
        assert_eq!(prose, "The system worker and worker failed");
        let maco = FeedbackRedactionContext::explicit(
            PathBuf::from("/srv/repo"),
            &["/var/lib/maco"],
            &["maco"],
            &["maco-campaign"],
        );
        let path = redact_feedback_text(
            "path .maco/o2/runs/demo/reports/supervisor-final.json user maco host maco-campaign",
            &maco,
        );
        assert!(
            path.contains(".maco/o2/runs/demo/reports/supervisor-final.json"),
            "{path}"
        );
        assert!(path.contains("<redacted:user>"), "{path}");
        assert!(path.contains("<redacted:host>"), "{path}");
        assert!(!path.contains("maco-campaign"), "{path}");
    }

    #[test]
    fn residual_scan_refuses_each_class_without_echoing_it() {
        let ctx = context();
        let samples = [
            (
                "private_key",
                "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
            ),
            ("token", "ghp_abcdefghijklmnopqrstuvwxyz012345"),
            ("secret", "API_TOKEN=supersecretvalue"),
            ("email", "ada@example.com"),
            ("ipv4", "203.0.113.9"),
            ("ipv6", "2001:db8::1"),
            ("path", "/var/lib/secret-file"),
            ("account_id", "acct_ABCDEFGHIJKLMNOP"),
            ("user", "operator ada ran"),
            ("host", "box buildbox ran"),
        ];
        for (class, sample) in samples {
            let error = ensure_redacted(sample, &ctx).expect_err(class);
            let rendered = format!("{error:#}");
            assert!(rendered.contains(class), "{class}: {rendered}");
            assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
            assert!(!rendered.contains("ghp_"), "{rendered}");
            assert!(!rendered.contains("supersecretvalue"), "{rendered}");
            assert!(!rendered.contains("ada@example.com"), "{rendered}");
            assert!(!rendered.contains("203.0.113.9"), "{rendered}");
            assert!(!rendered.contains("2001:db8::1"), "{rendered}");
            assert!(!rendered.contains("/var/lib/secret-file"), "{rendered}");
            assert!(!rendered.contains("acct_ABCDEFGHIJKLMNOP"), "{rendered}");
            assert!(!rendered.contains("buildbox"), "{rendered}");
            let redacted = redact_feedback_text(sample, &ctx);
            ensure_redacted(&redacted, &ctx).unwrap_or_else(|error| {
                panic!("{class} still residual after redaction: {error:#} text={redacted}")
            });
        }
    }

    #[test]
    fn fingerprint_is_stable_across_ids_and_paths() {
        let (_temp_a, repo_a) = init_repo();
        let (_temp_b, repo_b) = init_repo();
        let message_a = format!(
            "failed at {}/src/lib.rs:12 id 111 hex abcdef0123456789",
            repo_a.display()
        );
        let message_b = format!(
            "failed at {}/src/lib.rs:99 id 333 hex 1234567890abcdef",
            repo_b.display()
        );
        let mut report_a = failed_report(&repo_a, "fp-stable-1", &message_a);
        report_a.gate_denials = vec![GateDenial::from_claim_conflict(
            "feedback-a",
            "stage-validation",
            [Path::new("src/lib.rs")],
        )
        .expect("denial a")];
        let mut report_b = failed_report(&repo_b, "fp-stable-2", &message_b);
        report_b.gate_denials = vec![GateDenial::from_claim_conflict(
            "feedback-b",
            "stage-validation",
            [Path::new("src/lib.rs")],
        )
        .expect("denial b")];
        finalize(&repo_a, &report_a);
        finalize(&repo_b, &report_b);
        let left = feedback(&repo_a, "fp-stable-1", FeedbackForge::Fake, true);
        let right = feedback(&repo_b, "fp-stable-2", FeedbackForge::Fake, true);
        assert_eq!(left.fingerprint, right.fingerprint);
        assert_ne!(left.body, right.body);
        assert_eq!(left.fingerprint.len(), 64);
    }

    #[test]
    fn fake_forge_creates_and_returns_an_open_duplicate() {
        let (_temp, repo) = init_repo();
        let report = failed_report(&repo, "feedback-create", "check failed at src/lib.rs");
        finalize(&repo, &report);
        let created = feedback(&repo, "feedback-create", FeedbackForge::Fake, false);
        let again = feedback(&repo, "feedback-create", FeedbackForge::Fake, false);
        assert!(created.created);
        assert!(created.reason.is_none());
        let url = created.url.clone().expect("url");
        assert!(url.starts_with("fake://issue/"), "{url}");
        assert_eq!(again.url.as_deref(), Some(url.as_str()));
        assert_eq!(created.fingerprint, again.fingerprint);

        let marker = format!("<!-- maco-feedback:{} -->", created.fingerprint);
        let fixture = repo.join(".maco/feedback/fake-open-issues.json");
        fs::create_dir_all(fixture.parent().expect("parent")).expect("fixture dir");
        let closed = serde_json::json!([
            {"url": "fake://issue/closed", "body": marker, "state": "closed"}
        ]);
        fs::write(&fixture, serde_json::to_vec(&closed).expect("json")).expect("write");
        let after_closed = feedback(&repo, "feedback-create", FeedbackForge::Fake, false);
        assert!(after_closed.created);
        assert_eq!(after_closed.url.as_deref(), Some(url.as_str()));

        let open = serde_json::json!([
            {"url": "fake://issue/zzz", "body": marker, "state": "open"},
            {"url": "fake://issue/aaa", "body": marker, "state": "OPEN"},
            {"url": "fake://issue/closed", "body": marker, "state": "closed"}
        ]);
        fs::write(&fixture, serde_json::to_vec(&open).expect("json")).expect("write");
        let duplicate = feedback(&repo, "feedback-create", FeedbackForge::Fake, true);
        assert!(!duplicate.created);
        assert_eq!(duplicate.reason, Some(FeedbackReason::Duplicate));
        assert_eq!(duplicate.url.as_deref(), Some("fake://issue/aaa"));
        assert_eq!(duplicate.fingerprint, created.fingerprint);

        fs::write(&fixture, b"{not-json ghp_abcdefghijklmnopqrstuvwxyz012345").expect("bad");
        let error = supervise_feedback(FeedbackOptions {
            repo: repo.clone(),
            run_id: "feedback-create".to_string(),
            forge: FeedbackForge::Fake,
            dry_run: true,
        })
        .expect_err("invalid fixture");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("invalid"), "{rendered}");
        assert!(!rendered.contains("ghp_"), "{rendered}");
    }

    #[test]
    fn github_dry_run_does_not_contact_a_forge() {
        let (_temp, repo) = init_repo();
        let report = failed_report(&repo, "feedback-github", "check failed at src/lib.rs");
        finalize(&repo, &report);
        let report = feedback(&repo, "feedback-github", FeedbackForge::Github, true);
        assert!(!report.created);
        assert!(report.url.is_none());
        assert_eq!(report.reason, Some(FeedbackReason::DryRun));
        assert!(report.body.expect("body").contains("## Summary"));
    }

    #[test]
    fn status_fallback_omits_remaining_risk_from_the_body() {
        let (_temp, repo) = init_repo();
        let report = base_report("feedback-status");
        finalize(&repo, &report);
        let report = feedback(&repo, "feedback-status", FeedbackForge::Fake, true);
        let body = report.body.expect("body");
        assert!(!body.contains("CHAT TRANSCRIPT"), "{body}");
        assert!(!body.contains("prompt:"), "{body}");
        assert!(body.contains("Finding: failed"), "{body}");
    }

    #[test]
    fn ledger_plan_shape_is_preferred() {
        let (_temp, repo) = init_repo();
        let mut report: SupervisorFinalReport = serde_json::from_str(
            r#"{
            "version": 1,
            "run_id": "feedback-ledger",
            "role": "supervisor",
            "repo": ".",
            "plan_file": "plan.json",
            "run_dir": ".maco/o2/runs/feedback-ledger",
            "runtime": "fake",
            "publishable": false,
            "success": false,
            "accepted": false,
            "rejected": false,
            "status": "failed",
            "run_lifecycle": "finalized",
            "remaining_risk": "none",
            "next_safe_action": "none",
            "findings": [{
                "severity": "error",
                "message": "ledger finding",
                "paths": ["src/lib.rs"]
            }],
            "role_economics_profile": {
                "name": "feedback-test",
                "evidence": "fixture",
                "evidence_notice": "fixture",
                "production_eligible": false,
                "role_models": {
                    "worker": {"model": "demo-model", "reasoning_effort": "low"}
                },
                "execution": {
                    "assignment_count": 1,
                    "started_assignment_count": 1,
                    "completed_assignment_count": 0,
                    "concurrency": {
                        "configured_max_concurrent_children": 1,
                        "policy_input_observation": "not_process_observable",
                        "achieved_max_concurrent_children": 0,
                        "achieved_mean_concurrent_children": null,
                        "achieved_mean_observation": "not_process_observable"
                    },
                    "role_bindings": {},
                    "usage": {
                        "total_usage": null,
                        "total_cost_usd": null,
                        "usage_complete": false,
                        "observation": "not_process_observable"
                    },
                    "assignment_selection_ledger": [{
                        "assignment_id": "worker-1",
                        "attempt": 1,
                        "role": "worker",
                        "selection_source": "legacy_fake",
                        "selected_runtime": "fake",
                        "selected_model": "ledger-model",
                        "selected_reasoning_effort": "high",
                        "catalog_source": "none",
                        "catalog_snapshot_digest": null,
                        "evidence_gap": null
                    }]
                }
            }
        }"#,
        )
        .expect("ledger report");
        report.findings[0].paths = vec![PathBuf::from("src/lib.rs")];
        finalize(&repo, &report);
        let body = feedback(&repo, "feedback-ledger", FeedbackForge::Fake, true)
            .body
            .expect("body");
        assert!(
            body.contains("role=worker runtime=fake model=ledger-model effort=high"),
            "{body}"
        );
        assert!(!body.contains("demo-model"), "{body}");
    }

    #[test]
    fn command_redacts_process_identity_and_planted_secrets() {
        let (_temp, repo) = init_repo();
        let user = std::env::var("USER").unwrap_or_default();
        let host = current_host_name().unwrap_or_default();
        let message = format!(
            "failed ghp_abcdefghijklmnopqrstuvwxyz012345 API_TOKEN=supersecretvalue ada@example.com 203.0.113.9 2001:db8::1 /var/lib/secret-file acct_ABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY----- ABC -----END PRIVATE KEY----- user {user} host {host} AI agent"
        );
        let report = failed_report(&repo, "feedback-secrets", &message);
        finalize(&repo, &report);
        let body = feedback(&repo, "feedback-secrets", FeedbackForge::Fake, true)
            .body
            .expect("body");
        for secret in [
            "ghp_abcdefghijklmnopqrstuvwxyz012345",
            "supersecretvalue",
            "ada@example.com",
            "203.0.113.9",
            "2001:db8::1",
            "/var/lib/secret-file",
            "acct_ABCDEFGHIJKLMNOP",
            "PRIVATE KEY",
        ] {
            assert!(!body.contains(secret), "{secret} leaked:\n{body}");
        }
        assert!(
            body.contains(".maco/o2/runs/feedback-secrets/reports/supervisor-final.json"),
            "{body}"
        );
        assert!(body.contains("<!-- maco-feedback:"));
        assert!(!body.to_ascii_lowercase().contains("agent"));
        if user.chars().count() >= 3 && !is_ignored_identity(&user) {
            assert!(!body.contains(&format!("user {user}")), "{body}");
            assert!(body.contains("<redacted:user>"), "{body}");
        }
        if host.chars().count() >= 3 && !is_ignored_identity(&host) {
            assert!(!body.contains(&host), "{body}");
        }
    }

    fn assert_redacted_and_published(message: &str, absent: &[&str], present: &[&str]) {
        let ctx = context();
        let redacted = redact_feedback_text(message, &ctx);
        for secret in absent {
            assert!(!redacted.contains(secret), "{secret} leaked in {redacted}");
        }
        ensure_redacted(&redacted, &ctx)
            .unwrap_or_else(|error| panic!("residual after redaction: {error:#} text={redacted}"));
        let (_temp, repo) = init_repo();
        let report = failed_report(&repo, "feedback-regression", message);
        finalize(&repo, &report);
        let published = feedback(&repo, "feedback-regression", FeedbackForge::Fake, false);
        assert!(published.created, "{published:?}");
        let body = published.body.expect("body");
        for secret in absent {
            assert!(!body.contains(secret), "{secret} leaked in body:\n{body}");
        }
        for marker in present {
            assert!(body.contains(marker), "{marker} missing:\n{body}");
        }
    }

    #[test]
    fn sentence_punctuation_does_not_keep_email_or_ipv4() {
        let message =
            "mail ada@example.com. bind 203.0.113.9. also ada@example.net! and 198.51.100.24?";
        assert_redacted_and_published(
            message,
            &[
                "ada@example.com",
                "ada@example.net",
                "203.0.113.9",
                "198.51.100.24",
            ],
            &["<redacted:email>", "<redacted:ipv4>"],
        );
    }

    #[test]
    fn labeled_account_assignment_is_redacted() {
        let message = "account_id=123456789012";
        let redacted = redact_feedback_text(message, &context());
        assert!(redacted.contains("account_id(23)"), "{redacted}");
        assert!(!redacted.contains("123456789012"), "{redacted}");
        assert_redacted_and_published(message, &["123456789012"], &["account_id("]);
    }

    #[test]
    fn unc_path_is_redacted() {
        let message = r"share \\fileserver\homes\private\notes.txt";
        assert_redacted_and_published(
            message,
            &["fileserver", "homes", "private", "notes.txt"],
            &["<path>"],
        );
        let error = ensure_redacted(message, &context()).expect_err("unc");
        assert!(format!("{error:#}").contains("path"), "{error:#}");
    }

    #[test]
    fn hex_secret_in_a_finding_is_redacted_and_source_revision_remains() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(secret.len(), 64);
        let mixed = "AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789";
        assert_eq!(mixed.len(), 64);
        let message = format!("digest {secret} mixed {mixed}");
        assert_redacted_and_published(
            &message,
            &[secret, mixed],
            &[
                "<redacted:token>",
                "Source revision: 0123456789abcdef0123456789abcdef01234567",
            ],
        );
    }

    #[test]
    fn quoted_api_key_is_redacted() {
        let message = r#"{"api_key":"lowercase-secret-value"}"#;
        assert_redacted_and_published(message, &["lowercase-secret-value"], &["<redacted:secret>"]);
    }

    #[test]
    fn unicode_finding_does_not_panic() {
        for sample in ["café", "abcd€", "bearer café", "acct café"] {
            assert!(match_account(sample, 0).is_none(), "{sample:?}");
            assert!(match_bearer(sample, 0).is_none(), "{sample:?}");
            let redacted = redact_feedback_text(sample, &context());
            ensure_redacted(&redacted, &context())
                .unwrap_or_else(|error| panic!("{sample:?} residual: {error:#}"));
        }
        assert_redacted_and_published("café abcd€", &[], &["café"]);
    }

    #[test]
    fn fingerprint_ignores_request_uuid() {
        let (_temp, repo) = init_repo();
        let first = "550e8400-e29b-41d4-a716-446655440000";
        let second = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        assert_eq!(
            replace_numbers(&format!("request {first}")),
            replace_numbers(&format!("request {second}"))
        );
        for (run_id, uuid) in [("feedback-uuid-a", first), ("feedback-uuid-b", second)] {
            let report = failed_report(&repo, run_id, &format!("check failed request {uuid}"));
            finalize(&repo, &report);
        }
        let left = feedback(&repo, "feedback-uuid-a", FeedbackForge::Fake, true);
        let right = feedback(&repo, "feedback-uuid-b", FeedbackForge::Fake, true);
        assert_eq!(left.fingerprint, right.fingerprint);
        assert_ne!(left.body, right.body);
        let left_body = left.body.expect("left");
        let right_body = right.body.expect("right");
        assert!(left_body.contains(first), "{left_body}");
        assert!(right_body.contains(second), "{right_body}");
    }
}
