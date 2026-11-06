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
    identities: Vec<String>,
}

#[derive(Debug, Clone)]
struct Cause {
    kind: String,
    gate: String,
    location: String,
    message: String,
    show_message: bool,
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

    let context = FeedbackRedactionContext::from_process();
    let cause = select_cause(&report).sanitized(&context);
    let fingerprint = fingerprint_for(&cause);
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
        collapse_ws(&title)
    };
    let mut body = render_body(&report, &run_id, &repo_root, &cause, &context);
    ensure_redacted(&title, &context)?;
    let marker = format!("<!-- maco-feedback:{fingerprint} -->");
    validate_feedback_marker(&marker).context("supervise feedback fingerprint was malformed")?;
    body.trusted(&format!("{marker}\n"));
    body.ensure_redacted(&context)?;
    let published = body.text;

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

const REDACTED: &str = "<redacted>";

/// Sanitize the complete input before selecting a display line or imposing a cap.
/// Unknown tokens are withheld; recognizing a particular secret format is unnecessary.
pub(crate) fn redact_feedback_text(text: &str, ctx: &FeedbackRedactionContext) -> String {
    let original = text;
    let text = remove_identities(text, &ctx.identities);
    // Removing an identity must not erase a key and expose its former value.
    if sensitive_key_count(original) > sensitive_key_count(&text) {
        return REDACTED.to_string();
    }
    let mut output = String::new();
    let mut previous_redacted = false;
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let key = sensitive_key_start(line);
        let prefix = key.map_or(line, |start| &line[..start]);
        let mut words = Vec::new();
        for token in prefix.split_whitespace().chain(key.map(|_| REDACTED)) {
            let token = scrub_prose(token);
            let token =
                if allowed_token(&token) && remove_identities(&token, &ctx.identities) == token {
                    token
                } else {
                    REDACTED.to_string()
                };
            if token == REDACTED && previous_redacted {
                continue;
            }
            previous_redacted = token == REDACTED;
            words.push(token);
        }
        output.push_str(&words.join(" "));
    }
    output.trim().to_string()
}

pub(crate) fn ensure_redacted(text: &str, ctx: &FeedbackRedactionContext) -> Result<()> {
    if redact_feedback_text(text, ctx) != text {
        bail!("supervise feedback refused residual free text");
    }
    Ok(())
}

/// The renderer records provenance as it appends fields. No rendered label or
/// diagnostic can create a trusted range. The final check covers every free-text
/// range as well as the complete body at the issue publisher's boundary.
#[derive(Default)]
struct FeedbackBody {
    text: String,
    free_text: Vec<std::ops::Range<usize>>,
}

impl FeedbackBody {
    fn trusted(&mut self, value: &str) {
        self.text.push_str(value);
    }

    fn sanitized(&mut self, value: &str) {
        let start = self.text.len();
        self.text.push_str(value);
        self.free_text.push(start..self.text.len());
    }

    fn ensure_redacted(&self, ctx: &FeedbackRedactionContext) -> Result<()> {
        for range in &self.free_text {
            ensure_redacted(&self.text[range.clone()], ctx)?;
        }
        if self.text.contains(['@', '\\']) || !self.text.is_ascii() {
            bail!("supervise feedback refused residual unsafe characters");
        }
        if crate::llm::Redactor::new().redact(&self.text).text != self.text {
            bail!("supervise feedback refused residual secret assignment");
        }
        Ok(())
    }
}

impl Cause {
    fn sanitized(mut self, ctx: &FeedbackRedactionContext) -> Self {
        self.kind = redact_feedback_text(&self.kind, ctx);
        self.gate = redact_feedback_text(&self.gate, ctx);
        self.location = redact_feedback_text(&self.location, ctx);
        self.message = redact_feedback_text(&self.message, ctx);
        self
    }
}

impl FeedbackRedactionContext {
    pub(crate) fn from_process() -> Self {
        Self::from_values(
            [
                "USER",
                "LOGNAME",
                "HOME",
                "USERNAME",
                "USERPROFILE",
                "COMPUTERNAME",
            ]
            .into_iter()
            .filter_map(|key| std::env::var_os(key).and_then(|value| value.into_string().ok()))
            .chain(host_name_from_platform()),
        )
    }

    fn from_values(values: impl IntoIterator<Item = String>) -> Self {
        let mut identities = Vec::new();
        for value in values {
            if value.is_empty() {
                continue;
            }
            identities.push(value.clone());
            // Both native and foreign-platform home paths occur in run data.
            if let Some(base) = value
                .trim_end_matches(['/', '\\'])
                .rsplit(['/', '\\'])
                .next()
            {
                if !base.is_empty() {
                    identities.push(base.to_string());
                }
            }
        }
        identities.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        identities.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        Self { identities }
    }

    #[cfg(test)]
    fn explicit(_repo_root: PathBuf, homes: &[&str], users: &[&str], hosts: &[&str]) -> Self {
        Self::from_values(
            homes
                .iter()
                .chain(users)
                .chain(hosts)
                .map(|value| value.to_string()),
        )
    }
}

fn remove_identities(text: &str, identities: &[String]) -> String {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < text.len() {
        // This fixed marker carries no run value, even when an identity happens
        // to be a substring of its spelling. Keep the filter idempotent.
        if text[cursor..].starts_with(REDACTED) {
            output.push_str(REDACTED);
            cursor += REDACTED.len();
            continue;
        }
        if let Some(identity) = identities.iter().find(|identity| {
            text.get(cursor..cursor + identity.len())
                .is_some_and(|value| value.eq_ignore_ascii_case(identity))
        }) {
            output.push_str(" <redacted> ");
            cursor += identity.len();
        } else {
            let ch = text[cursor..].chars().next().expect("character boundary");
            output.push(ch);
            cursor += ch.len_utf8();
        }
    }
    output
}

fn sensitive_key_start(line: &str) -> Option<usize> {
    let mut start = None;
    for (index, ch) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
            start.get_or_insert(index);
        } else if let Some(start) = start.take() {
            if is_sensitive_key(&line[start..index]) {
                // Drop the key too, so a later publisher cannot reinterpret it
                // together with neighboring text as another assignment.
                return Some(start);
            }
        }
    }
    None
}

fn sensitive_key_count(text: &str) -> usize {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        .filter(|key| is_sensitive_key(key))
        .count()
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase().replace('-', "_");
    matches!(key.as_str(), "KEY" | "AUTH" | "USER" | "OWNER")
        || key.ends_with("_ID")
        || [
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PASSWD",
            "CREDENTIAL",
            "PRIVATE",
            "API_KEY",
            "APIKEY",
            "ACCESS_KEY",
            "AUTHORIZATION",
            "BEARER",
            "ACCOUNT",
            "ACCT",
            "USERNAME",
            "USER_ID",
            "USERID",
            "LOGIN",
            "EMAIL",
            "TENANT",
            "CLIENT_ID",
            "CUSTOMER",
            "SUBSCRIPTION",
        ]
        .iter()
        .any(|part| key.contains(part))
}

fn allowed_token(token: &str) -> bool {
    if token == REDACTED {
        return true;
    }
    if !token.is_ascii() || token.contains(['@', '\\']) {
        return false;
    }
    // Remove prose wrappers without concealing a path prefix or an IP address.
    let unwrapped = token.trim_matches(|ch: char| {
        ch.is_ascii_punctuation() && !matches!(ch, '_' | '-' | '/' | '~' | '.' | ':' | '@')
    });
    if unwrapped.starts_with(['/', '~', '.'])
        || (unwrapped.as_bytes().get(1) == Some(&b':')
            && unwrapped.as_bytes()[0].is_ascii_alphabetic())
        || unwrapped
            .trim_end_matches('.')
            .parse::<std::net::IpAddr>()
            .is_ok()
    {
        return false;
    }
    let core = unwrapped.trim_end_matches(['.', ':']);
    if core.bytes().all(|byte| byte.is_ascii_digit()) {
        return !core.is_empty() && core.len() <= 4;
    }
    allowed_identifier(core) || allowed_source_location(unwrapped.trim_end_matches(['.', ':']))
}

fn allowed_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 24
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && value.bytes().filter(u8::is_ascii_digit).count() <= 4
        && !(value.len() >= 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && !(value.len() > 12
            && value.bytes().any(|byte| byte.is_ascii_digit())
            && value.bytes().any(|byte| byte.is_ascii_lowercase())
            && value.bytes().any(|byte| byte.is_ascii_uppercase()))
}

fn allowed_source_location(value: &str) -> bool {
    let Some((path, line)) = value.rsplit_once(':') else {
        return false;
    };
    if line.is_empty()
        || line.len() > 6
        || !line.bytes().all(|byte| byte.is_ascii_digit())
        || path.starts_with(['/', '\\', '~', '.'])
        || path.contains("..")
    {
        return false;
    }
    let Some((stem, extension)) = path.rsplit_once('.') else {
        return false;
    };
    if ![
        "rs", "c", "h", "cc", "cpp", "hpp", "go", "py", "js", "jsx", "ts", "tsx", "java", "kt",
        "swift", "sh",
    ]
    .contains(&extension)
    {
        return false;
    }
    stem.split('/')
        .all(|segment| segment.split('.').all(allowed_identifier))
}

#[cfg(unix)]
fn host_name_from_platform() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: buffer is writable for its full length; the result is read only
    // after success and is bounded even if the platform omits a terminating NUL.
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
    Some(Cause {
        kind: wire(&severity),
        gate: gate
            .map(|denial| reason_family(&denial.reason))
            .unwrap_or_else(|| "finding".to_string()),
        location,
        message: first.message.clone(),
        show_message: true,
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
        show_message: true,
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
        show_message: true,
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
        show_message: true,
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
        show_message: true,
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
        show_message: false,
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
    ctx: &FeedbackRedactionContext,
) -> FeedbackBody {
    let identity = report
        .executable
        .clone()
        .unwrap_or_else(ExecutableBuildIdentity::compiled);
    let status = if cause.status.is_empty() {
        wire(&report.status)
    } else {
        cause.status.clone()
    };
    let message = if cause.show_message {
        &cause.message
    } else {
        &cause.kind
    };
    let line = cap_chars(message.lines().next().unwrap_or("none"), FINDING_LINE_CHARS);
    let line = if line.trim().is_empty() {
        "none"
    } else {
        line.trim_end()
    };
    let location = if cause.location.is_empty() {
        "none"
    } else {
        &cause.location
    };
    let mut body = FeedbackBody::default();
    body.trusted("## Summary\nThe finished run did not succeed. Failing gate or stage: ");
    body.sanitized(&cause.gate);
    body.trusted(". Finding kind: ");
    body.sanitized(&cause.kind);
    body.trusted(".\n");
    if cause.extra > 0 {
        body.trusted(&format!("Additional findings: {}.\n", cause.extra));
    }
    body.trusted("\n## Expected behavior\nThe run finishes with a succeeded status and no failing gate or finding.\n");
    body.trusted("\n## Actual behavior\n");
    body.trusted(&format!("Status: {status}\n"));
    body.trusted("Finding kind: ");
    body.sanitized(&cause.kind);
    body.trusted("\nFinding: ");
    body.sanitized(line);
    body.trusted("\n\n## Reproduction\nPackage version: ");
    // A typed field can carry its documented format; arbitrary diagnostic text
    // never obtains this privilege by imitating the field's label.
    body.trusted(package_version(&identity.package_version));
    body.trusted("\nSource revision: ");
    body.trusted(
        identity
            .source_revision
            .as_deref()
            .filter(|revision| {
                matches!(revision.len(), 40 | 64)
                    && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .unwrap_or("unknown"),
    );
    body.trusted(&format!(
        "\nSource state: {}\nPlan shape:\n",
        source_state_label(identity.source_state)
    ));
    render_plan(report, ctx, &mut body);
    body.trusted("Usage:\n");
    for line in usage_lines(report) {
        body.trusted(&format!("- {line}\n"));
    }
    body.trusted("\n## Evidence\nReport paths:\n");
    let safe_run_id = redact_feedback_text(run_id.as_str(), ctx);
    for relative in evidence_paths(repo_root, run_id) {
        body.trusted("- .maco/o2/runs/");
        body.sanitized(&safe_run_id);
        body.trusted("/");
        body.trusted(relative);
        body.trusted("\n");
    }
    body.trusted("Source location: ");
    body.sanitized(location);
    body.trusted("\n\n## Impact\nThe finished run did not succeed, so its result cannot be treated as ready.\n");
    body
}

fn package_version(value: &str) -> &str {
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() == 3
        && components.iter().all(|part| {
            !part.is_empty() && part.len() <= 4 && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        value
    } else {
        "unknown"
    }
}

fn source_state_label(state: SourceState) -> &'static str {
    match state {
        SourceState::Clean => "clean",
        SourceState::Dirty => "dirty",
        SourceState::Unknown => "unknown",
    }
}

fn render_plan(
    report: &SupervisorFinalReport,
    ctx: &FeedbackRedactionContext,
    body: &mut FeedbackBody,
) {
    if let Some(profile) = report.role_economics_profile.as_ref() {
        if let Some(execution) = profile.execution.as_ref() {
            if !execution.assignment_selection_ledger.is_empty() {
                for entry in &execution.assignment_selection_ledger {
                    body.trusted(&format!("- role={} runtime=", entry.role.as_str()));
                    body.sanitized(&redact_feedback_text(
                        display_opt(entry.selected_runtime.as_deref()),
                        ctx,
                    ));
                    render_model(
                        body,
                        entry.selected_model.as_deref(),
                        entry.selected_reasoning_effort.as_deref(),
                        ctx,
                    );
                }
                return;
            }
        }
        if !profile.role_models.is_empty() {
            for (role, selection) in &profile.role_models {
                body.trusted(&format!(
                    "- role={} runtime={}",
                    role.as_str(),
                    runtime_wire(report.runtime)
                ));
                render_model(
                    body,
                    selection.model.as_deref(),
                    selection.reasoning_effort.as_deref(),
                    ctx,
                );
            }
            return;
        }
    }
    body.trusted(&format!("- runtime={}\n", runtime_wire(report.runtime)));
}

fn render_model(
    body: &mut FeedbackBody,
    model: Option<&str>,
    effort: Option<&str>,
    ctx: &FeedbackRedactionContext,
) {
    body.trusted(" model=");
    body.sanitized(&redact_feedback_text(display_opt(model), ctx));
    body.trusted(" effort=");
    body.sanitized(&redact_feedback_text(display_opt(effort), ctx));
    body.trusted("\n");
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

fn evidence_paths(repo_root: &Path, run_id: &RunId) -> Vec<&'static str> {
    let mut paths = vec!["reports/supervisor-final.json"];
    let Ok(reader) = ArtifactRunReader::open(repo_root, RunArtifactFamily::Supervise, run_id)
    else {
        return paths;
    };
    for relative in [
        "assignments/supervisor-plan.json",
        SELECTION_LEDGER_RELATIVE,
    ] {
        if reader.read(Path::new(relative)).is_ok() {
            paths.push(relative);
        }
    }
    paths
}

fn fingerprint_for(cause: &Cause) -> String {
    // Cause strings have already passed the same filter used by the renderer.
    // Normalize surviving small counters and source-line numbers as well.
    let pieces = [&cause.kind, &cause.gate, &cause.location, &cause.message]
        .map(|piece| collapse_ws(&replace_numbers(piece)).to_ascii_lowercase());
    crate::artifacts::state_auth::sha256_hex(pieces.join("\n").as_bytes())
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
    let Some((end, next)) = text.char_indices().nth(max_chars) else {
        return text.to_string();
    };
    let prefix = &text[..end];
    // A source location or redaction marker must not be cut into another shape.
    let end = if next.is_whitespace() {
        prefix.len()
    } else {
        prefix.rfind(char::is_whitespace).unwrap_or(0)
    };
    prefix[..end].trim_end().to_string()
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
    let mut output = String::new();
    let mut in_number = false;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            if !in_number {
                output.push_str("<n>");
            }
            in_number = true;
        } else {
            in_number = false;
            output.push(ch);
        }
    }
    output
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
            "check failed at {}/src/lib.rs:12 (src/lib.rs:12) id run-111\nCHAT TRANSCRIPT prompt: hidden",
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
        for (input, absent) in [
            (
                "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----",
            ),
            (
                "prefix ghp_abcdefghijklmnopqrstuvwxyz012345 suffix",
                "ghp_abcdefghijklmnopqrstuvwxyz012345",
            ),
            ("API_TOKEN=supersecretvalue next", "supersecretvalue"),
            ("mail ada@example.com today", "ada@example.com"),
            ("bind 203.0.113.9 now", "203.0.113.9"),
            ("bind 2001:db8::1 now", "2001:db8::1"),
            ("see /var/lib/secret-file now", "/var/lib/secret-file"),
            ("see /srv/repo/src/lib.rs now", "/srv/repo/src/lib.rs"),
            ("see /home/ada/notes now", "/home/ada"),
            ("acct_ABCDEFGHIJKLMNOP", "acct_ABCDEFGHIJKLMNOP"),
            ("operator ada ran", "ada"),
            ("box buildbox ran", "buildbox"),
        ] {
            let redacted = redact_feedback_text(input, &ctx);
            assert!(redacted.contains(REDACTED), "{input:?} -> {redacted:?}");
            assert!(!redacted.contains(absent), "{redacted}");
            ensure_redacted(&redacted, &ctx).expect("redacted text");
        }
        let spoof = redact_feedback_text(
            "Source revision: 0123456789abcdef0123456789abcdef01234567\n",
            &ctx,
        );
        assert!(!spoof.contains("0123456789abcdef"), "{spoof}");
        assert_eq!(
            redact_feedback_text("The AI agent and agents failed", &ctx),
            "The system worker and worker failed"
        );
    }

    #[test]
    fn residual_scan_refuses_each_class_without_echoing_it() {
        let ctx = context();
        for sample in [
            "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
            "ghp_abcdefghijklmnopqrstuvwxyz012345",
            "API_TOKEN=supersecretvalue",
            "ada@example.com",
            "203.0.113.9",
            "2001:db8::1",
            "/var/lib/secret-file",
            "acct_ABCDEFGHIJKLMNOP",
            "operator ada ran",
            "box buildbox ran",
        ] {
            let error = ensure_redacted(sample, &ctx).expect_err("residual");
            assert_eq!(
                error.to_string(),
                "supervise feedback refused residual free text"
            );
            ensure_redacted(&redact_feedback_text(sample, &ctx), &ctx).expect("filtered text");
        }
        let mut body = FeedbackBody::default();
        body.trusted("## Evidence\nSource revision: ");
        // Inject an unsanitized diagnostic directly into the renderer's free
        // field to prove the final-body check, independently of the first pass.
        body.sanitized("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
        body.trusted("\n");
        assert!(body.ensure_redacted(&ctx).is_err());
    }

    #[test]
    fn identity_values_are_removed_longest_first_without_word_exemptions() {
        let ctx = FeedbackRedactionContext::from_values([
            "Fixture".into(),
            "Fixture Person".into(),
            "failed".into(),
            "xy".into(),
            r"C:\Users\Other Person".into(),
        ]);
        let text = redact_feedback_text("Fixture Person failed xy Other Person", &ctx);
        assert_eq!(text, REDACTED);
        let ctx = FeedbackRedactionContext::from_values(["redacted".into(), "worker".into()]);
        let text = redact_feedback_text("agent <redacted>", &ctx);
        assert_eq!(text, REDACTED);
        ensure_redacted(&text, &ctx).expect("neutral prose and markers stay sanitized");
        let ctx = FeedbackRedactionContext::from_values(["api_key".into()]);
        let text = redact_feedback_text("check failed api_key: shortprivate", &ctx);
        assert!(!text.contains("shortprivate"));
        ensure_redacted(&text, &ctx).expect("identity removal cannot erase key context");
    }

    #[test]
    fn display_caps_keep_filtered_tokens_and_character_boundaries() {
        assert_eq!(cap_chars("check <redacted>", 12), "check");
        assert_eq!(cap_chars("éé test", 3), "éé");
        let message = format!("{}src/lib.rs:1234", "check ".repeat(82));
        assert_redacted_and_published(&message, &[], &["Finding: check"]);
    }

    #[test]
    fn default_deny_keeps_only_documented_token_shapes() {
        let ctx = context();
        for token in [
            "longopaquestringabcdefghijklmnopqrstuvwxyz",
            "a1b2c3d4",
            "123456789012",
            "AbCdEfGhIjKlMnOpQr12",
            "someone@example.invalid",
            "::1",
            "[::1].",
            "203.0.113.9.",
            "/src/lib.rs:12",
            "./src/lib.rs:12",
            "../src/lib.rs:12",
            "src/../lib.rs:12",
            "~/lib.rs:12",
            "C:/lib.rs:12",
            r"src\lib.rs:12",
            "src/lib.txt:12",
            "src/lib.rs",
            "café",
            "src/secret/",
            "C:",
        ] {
            assert_eq!(redact_feedback_text(token, &ctx), REDACTED, "{token}");
        }
        assert_eq!(
            redact_feedback_text("opaqueabcdefghijklmnopqrstuvwxyz café ::1", &ctx),
            REDACTED
        );
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
        let host = host_name_from_platform().unwrap_or_default();
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
            body.contains(".maco/o2/runs/<redacted>/reports/supervisor-final.json"),
            "{body}"
        );
        assert!(body.contains("<!-- maco-feedback:"));
        assert!(!body.to_ascii_lowercase().contains("agent"));
        if !user.is_empty() {
            assert!(!body.contains(&format!("user {user}")), "{body}");
            assert!(body.contains(REDACTED), "{body}");
        }
        if !host.is_empty() {
            assert!(!body.contains(&host), "{body}");
        }
    }

    fn assert_feedback_bodies(
        repo: &Path,
        run_id: &str,
        absent: &[&str],
        present: &[&str],
    ) -> String {
        let output = feedback(repo, run_id, FeedbackForge::Fake, false);
        assert!(output.created, "{output:?}");
        let returned = output.body.expect("returned body");
        let dry = feedback(repo, run_id, FeedbackForge::Fake, true)
            .body
            .expect("dry-run body");
        let created = create_feedback_issue(repo, &output.title, &returned, FeedbackForge::Fake)
            .expect("fake issue");
        assert!(created.created);
        assert_eq!(
            output.url, created.url,
            "the fake issue must use these exact bytes"
        );
        for body in [&returned, &dry, &created.redacted_body] {
            for secret in absent {
                assert!(!body.contains(secret), "{secret} leaked in body:\n{body}");
            }
            for marker in present {
                assert!(body.contains(marker), "{marker} missing:\n{body}");
            }
        }
        assert_eq!(returned, dry);
        assert_eq!(returned.as_bytes(), created.redacted_body.as_bytes());
        returned
    }

    fn assert_redacted_and_published(message: &str, absent: &[&str], present: &[&str]) {
        let ctx = context();
        let redacted = redact_feedback_text(message, &ctx);
        for secret in absent {
            assert!(!redacted.contains(secret), "{secret} leaked in {redacted}");
        }
        ensure_redacted(&redacted, &ctx).expect("filtered text");
        let (_temp, repo) = init_repo();
        let report = failed_report(&repo, "feedback-regression", message);
        finalize(&repo, &report);
        assert_feedback_bodies(&repo, "feedback-regression", absent, present);
    }

    // First review: seven independent regressions, including both address shapes.
    #[test]
    fn sentence_punctuation_does_not_keep_email_or_ipv4() {
        assert_redacted_and_published(
            "mail ada@example.com. bind 203.0.113.9. also ada@example.net! and 198.51.100.24?",
            &[
                "ada@example.com",
                "ada@example.net",
                "203.0.113.9",
                "198.51.100.24",
            ],
            &[REDACTED],
        );
    }

    #[test]
    fn labeled_account_assignment_is_redacted() {
        assert_redacted_and_published("account_id=123456789012", &["123456789012"], &[REDACTED]);
    }

    #[test]
    fn unc_path_is_redacted() {
        assert_redacted_and_published(
            r"share \\fileserver\homes\private\notes.txt",
            &["fileserver", "homes", "private", "notes.txt"],
            &[REDACTED],
        );
    }

    #[test]
    fn hex_secret_in_a_finding_is_redacted_and_source_revision_remains() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mixed = "AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789";
        assert_redacted_and_published(
            &format!("digest {secret} mixed {mixed}"),
            &[secret, mixed],
            &[
                REDACTED,
                "Source revision: 0123456789abcdef0123456789abcdef01234567",
            ],
        );
    }

    #[test]
    fn quoted_api_key_is_redacted() {
        assert_redacted_and_published(
            r#"{"api_key":"lowercase-secret-value"}"#,
            &["lowercase-secret-value"],
            &[REDACTED],
        );
    }

    #[test]
    fn unicode_finding_does_not_panic() {
        for sample in ["café", "abcd€", "bearer café", "acct café"] {
            assert_redacted_and_published(sample, &["café", "abcd€"], &[REDACTED]);
        }
    }

    #[test]
    fn fingerprint_ignores_request_uuid() {
        let (_temp, repo) = init_repo();
        let first = "550e8400-e29b-41d4-a716-446655440000";
        let second = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        for (run_id, uuid) in [("feedback-uuid-a", first), ("feedback-uuid-b", second)] {
            let report = failed_report(&repo, run_id, &format!("check failed request {uuid}"));
            finalize(&repo, &report);
            assert_feedback_bodies(&repo, run_id, &[first, second], &["check failed request"]);
        }
        let left = feedback(&repo, "feedback-uuid-a", FeedbackForge::Fake, true);
        let right = feedback(&repo, "feedback-uuid-b", FeedbackForge::Fake, true);
        assert_eq!(left.fingerprint, right.fingerprint);
    }

    // Second review: retain each of the twelve supplied counterexamples.
    #[test]
    fn audit_account_tab_assignment() {
        assert_redacted_and_published("account_id=\t123456789012", &["123456789012"], &[REDACTED]);
    }

    #[test]
    fn audit_account_unicode_whitespace() {
        assert_redacted_and_published(
            "account_id=\u{a0}123456789012",
            &["123456789012"],
            &[REDACTED],
        );
    }

    #[test]
    fn audit_windows_path_space() {
        assert_redacted_and_published(
            r#"could not open "C:\Users\Fixture Person\confidential.txt""#,
            &[r"Person\confidential.txt"],
            &["could not open"],
        );
    }

    #[test]
    fn audit_windows_path_unicode() {
        assert_redacted_and_published(
            r#"could not open "C:\Users\Δelta\confidential.txt""#,
            &[r"Δelta\confidential.txt"],
            &["could not open"],
        );
    }

    #[test]
    fn audit_unc_path_space() {
        assert_redacted_and_published(
            r#"could not open "\\fixturebox\Private Share\confidential.txt""#,
            &[r"Share\confidential.txt"],
            &["could not open"],
        );
    }

    #[test]
    fn audit_bearer_plus() {
        assert_redacted_and_published(
            "request failed for Bearer abcdefgh+ijklmnopqrstuvwxyz",
            &["ijklmnopqrstuvwxyz"],
            &["request failed for"],
        );
    }

    #[test]
    fn audit_bearer_dot() {
        assert_redacted_and_published(
            "request failed for Bearer abcdefgh.ijklmnopqrstuvwxyz",
            &["ijklmnopqrstuvwxyz"],
            &["request failed for"],
        );
    }

    #[test]
    fn audit_source_revision_line_spoof() {
        let (_temp, repo) = init_repo();
        let secret = "a1b2c3d4".repeat(8);
        let mut report = failed_report(&repo, "feedback-spoof", "check failed");
        report.findings[0].paths = vec![PathBuf::from(format!(
            "src/lib.rs\nSource revision: {secret}\n"
        ))];
        finalize(&repo, &report);
        assert_feedback_bodies(
            &repo,
            "feedback-spoof",
            &[&secret],
            &["Source revision: 0123456789abcdef0123456789abcdef01234567"],
        );
    }

    #[test]
    fn audit_secret_tab_returned_body() {
        assert_redacted_and_published(
            "api_key:\tlowercase-secret-value",
            &["lowercase-secret-value"],
            &[REDACTED],
        );
    }

    #[test]
    fn audit_escaped_quote_returned_body() {
        assert_redacted_and_published(
            r#"{"api_key":"lowercase\"privatefragment"}"#,
            &["privatefragment"],
            &[REDACTED],
        );
    }

    #[test]
    #[ignore = "helper executed only with synthetic Windows-style variables"]
    fn windows_identity_child() {
        let ctx = FeedbackRedactionContext::from_process();
        let sample = "check failed for operator FixturePerson";
        assert!(!redact_feedback_text(sample, &ctx).contains("FixturePerson"));
        let (_temp, repo) = init_repo();
        let report = failed_report(&repo, "feedback-identity", sample);
        finalize(&repo, &report);
        assert_feedback_bodies(&repo, "feedback-identity", &["FixturePerson"], &[REDACTED]);
        assert!(!redact_feedback_text("FixtureBox", &ctx).contains("FixtureBox"));
        assert!(!redact_feedback_text(r"C:\Users\FixturePerson", &ctx).contains("FixturePerson"));
    }

    #[test]
    fn audit_windows_username_environment() {
        let status = Command::new(std::env::current_exe().expect("test harness"))
            .env_clear()
            .env("USERNAME", "FixturePerson")
            .env("USERPROFILE", r"C:\Users\FixturePerson")
            .env("COMPUTERNAME", "FixtureBox")
            .args([
                "--exact",
                "supervise::beta_feedback::tests::windows_identity_child",
                "--ignored",
            ])
            .status()
            .expect("isolated identity test");
        assert!(status.success());
    }

    #[test]
    fn audit_truncation_precedes_secret_redaction() {
        let secret = "a1b2c3d4".repeat(8);
        assert_redacted_and_published(
            &format!("{} {secret}", "x".repeat(480)),
            &[&secret[..19]],
            &[REDACTED],
        );
    }

    #[test]
    fn normal_diagnostic_text_and_source_locations_survive() {
        assert_redacted_and_published(
            "type check failed with E0308 at src/lib.rs:12: expected 3 values, found 4.",
            &[],
            &["type check failed with E0308 at src/lib.rs:12: expected 3 values, found 4."],
        );
    }

    #[test]
    fn returned_dry_run_and_fake_created_bodies_are_identical() {
        assert_redacted_and_published(
            "check failed api_key:\tprivatefragment",
            &["privatefragment"],
            &["check failed"],
        );
    }
}
