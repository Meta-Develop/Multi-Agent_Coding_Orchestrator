use crate::{
    artifacts::{self, RunArtifactFamily},
    external_agent::{run_external_agent, ExternalAgentCommand, ExternalAgentRun},
    llm::Redactor,
    orchestrator::RunId,
    process_runner::resolve_existing_path_without_symlinks,
    secure_output::{ReservedOutputFile, SecureOutputRoot},
    sync::normalize_repo_relative_path,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

pub const DEFAULT_CONSULT_TIMEOUT_SECONDS: u64 = 600;
const CONSULTANT_REPORT_VERSION: u32 = 1;
const QUESTION_SUMMARY_LIMIT: usize = 1024;
const PROMPT_QUESTION_LIMIT: usize = 12 * 1024;
const ANSWER_LIMIT: usize = 16 * 1024;
const REFERENCE_LIMIT: usize = 512;
const CAVEAT_LIMIT: usize = 1024;
const CONSULTANT_THREAD_DEPTH: u8 = 2;
const MAX_CONSULT_ARTIFACT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ConsultAskOptions {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub runtime: ConsultantRuntime,
    pub consultant_bin: Option<PathBuf>,
    pub question: String,
    pub context_paths: Vec<PathBuf>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsultantRuntime {
    Fake,
    Codex,
    Claude,
}

impl ConsultantRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

impl FromStr for ConsultantRuntime {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "fake" => Ok(Self::Fake),
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            _ => Err("runtime must be one of: fake, codex, claude".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsultantConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsultantStatus {
    #[default]
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsultantExitInfo {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsultantReport {
    pub version: u32,
    pub run_id: RunId,
    pub runtime: ConsultantRuntime,
    pub question_summary: String,
    pub answer: String,
    pub confidence: ConsultantConfidence,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub caveats: Vec<String>,
    pub no_further_delegation: bool,
    pub read_only: bool,
    pub duration_ms: u64,
    pub exit_info: ConsultantExitInfo,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(default)]
    pub status: ConsultantStatus,
}

#[derive(Debug)]
struct ConsultantArtifacts {
    run_dir: PathBuf,
    question_path: PathBuf,
    incoming_report_path: PathBuf,
    raw_log_path: PathBuf,
    schema_path: PathBuf,
}

#[derive(Debug)]
struct PreparedQuestion {
    prompt_body: String,
    summary: String,
}

#[derive(Debug)]
struct ParsedReport<T> {
    report: T,
    recovered: bool,
}

pub fn ask_consultant(options: ConsultAskOptions) -> Result<ConsultantReport> {
    if options.timeout_seconds == 0 {
        bail!("timeout_seconds must be greater than zero");
    }
    let repo = artifacts::discover_repo_root(&options.repo)?;
    artifacts::ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &options.run_id)?;
    let context_paths = validate_context_paths(&repo, &options.context_paths)?;
    let prepared_question = prepare_question(&options.question)?;
    let artifacts = consultant_artifacts(&repo, &options.run_id);
    let run_container = SecureOutputRoot::create_new(&artifacts.run_dir)?;
    let trusted_root = run_container.create_child(OsStr::new("trusted"))?;
    let incoming_root = run_container.create_child(OsStr::new("incoming"))?;
    trusted_root.reject_overlap(&incoming_root)?;
    let schema_root = trusted_root.create_child(OsStr::new("schemas"))?;
    let mut schema = schema_root.reserve(OsStr::new("consultant-report.schema.json"))?;
    let mut question = trusted_root.reserve(OsStr::new("question.md"))?;
    let mut final_report = trusted_root.reserve(OsStr::new("consultant-report.json"))?;
    write_consultant_schema(&mut schema)?;
    let prompt = consultant_prompt(
        &options.run_id,
        &prepared_question.prompt_body,
        &context_paths,
        &artifacts.schema_path,
    )?;
    question
        .write_bytes_atomic(prompt.as_bytes(), MAX_CONSULT_ARTIFACT_BYTES)
        .with_context(|| format!("failed to write {}", question.path().display()))?;

    let report = match options.runtime {
        ConsultantRuntime::Fake => fake_consultant_report(
            &options.run_id,
            prepared_question.summary,
            &context_paths,
            &artifacts.raw_log_path,
        )?,
        ConsultantRuntime::Codex => {
            let consultant_bin = required_consultant_bin(&options)?;
            run_codex_consultant(
                &repo,
                &options.run_id,
                consultant_bin,
                &prepared_question.summary,
                &artifacts,
                Duration::from_secs(options.timeout_seconds),
            )?
        }
        ConsultantRuntime::Claude => {
            let consultant_bin = required_consultant_bin(&options)?;
            run_claude_consultant(
                &repo,
                &options.run_id,
                consultant_bin,
                &prepared_question.summary,
                &artifacts,
                Duration::from_secs(options.timeout_seconds),
            )?
        }
    };

    write_consultant_final_report(&mut final_report, &report)?;
    Ok(report)
}

pub fn consultant_prompt(
    run_id: &RunId,
    question: &str,
    context_paths: &[PathBuf],
    schema_path: &Path,
) -> Result<String> {
    let context_list = if context_paths.is_empty() {
        "- <none>".to_string()
    } else {
        context_paths
            .iter()
            .map(|path| format!("- {}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let role_prefix = consultant_role_prefix(run_id);
    Ok(format!(
        r#"{role_prefix}You are a terminal read-only CONSULTANT in a local MACO cross-runtime consultation.
Do not edit files, create worktrees, claim paths, apply patches, change Git state, or run mutating commands.
Do not launch further workers, delegate to another agent, or spawn/impersonate O1 or O2 roles.
Answer the question with concrete references to repository paths, commands, docs, or URLs when useful.
Return ConsultantReport JSON as the final response, matching this JSON schema:
{schema_path}

The final ConsultantReport JSON must include:
- "no_further_delegation": true
- "read_only": true
- "runtime": "fake", "codex", or "claude"
- "confidence": "low", "medium", or "high"

Repository context paths are listed only; their contents are not inlined here:
{context_list}

Question:
{question}
"#,
        role_prefix = role_prefix,
        schema_path = schema_path.display(),
        context_list = context_list,
        question = question,
    ))
}

fn consultant_role_prefix(run_id: &RunId) -> String {
    format!(
        "ROLE: CONSULTANT\nAGENT_KIND: consultant\nAGENT_LABEL: {}\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: {}\nNO_FURTHER_DELEGATION: true\n",
        run_id.as_str(),
        CONSULTANT_THREAD_DEPTH
    )
}

fn validate_context_paths(repo: &Path, paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut normalized_paths = BTreeSet::new();
    for path in paths {
        let normalized = normalize_repo_relative_path(path)
            .with_context(|| format!("invalid context path {}", path.display()))?;
        resolve_existing_path_without_symlinks(repo, &normalized).with_context(|| {
            format!(
                "context path '{}' must exist without symlink components under {}",
                normalized.display(),
                repo.display()
            )
        })?;
        normalized_paths.insert(normalized);
    }
    Ok(normalized_paths.into_iter().collect())
}

fn prepare_question(question: &str) -> Result<PreparedQuestion> {
    if contains_private_key_material(question) {
        bail!("consult question contains private key material and was refused");
    }
    let prompt_body = sanitize_public_text(question, PROMPT_QUESTION_LIMIT);
    let summary = sanitize_public_text(question, QUESTION_SUMMARY_LIMIT);
    Ok(PreparedQuestion {
        prompt_body: prompt_body.text,
        summary: summary.text,
    })
}

fn fake_consultant_report(
    run_id: &RunId,
    question_summary: String,
    context_paths: &[PathBuf],
    raw_log_path: &Path,
) -> Result<ConsultantReport> {
    write_text_file(
        raw_log_path,
        "fake consultant runtime: no subprocess launched\n",
    )?;
    Ok(ConsultantReport {
        version: CONSULTANT_REPORT_VERSION,
        run_id: run_id.clone(),
        runtime: ConsultantRuntime::Fake,
        question_summary,
        answer: "Deterministic fake consultant advice: inspect the listed context paths, keep the work read-only, and verify the proposed fix with the repository's documented validation commands.".to_string(),
        confidence: ConsultantConfidence::Medium,
        references: context_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        caveats: vec![
            "fake runtime does not inspect repository contents or call an external model"
                .to_string(),
        ],
        no_further_delegation: true,
        read_only: true,
        duration_ms: 0,
        exit_info: ConsultantExitInfo {
            command: Vec::new(),
            exit_code: Some(0),
            timed_out: false,
            error: None,
        },
        success: true,
        status: ConsultantStatus::Succeeded,
    })
}

fn run_codex_consultant(
    repo: &Path,
    run_id: &RunId,
    consultant_bin: &Path,
    question_summary: &str,
    artifacts: &ConsultantArtifacts,
    timeout: Duration,
) -> Result<ConsultantReport> {
    let command = ExternalAgentCommand::codex_read_only_consultant(
        consultant_bin,
        repo,
        &artifacts.question_path,
        &artifacts.raw_log_path,
        &artifacts.incoming_report_path,
        timeout,
    );
    let external_run = run_external_agent(&command);
    let report_text = match external_run.output_last_message() {
        Some(contents) => String::from_utf8_lossy(contents).into_owned(),
        None => "failed to capture Codex consultant report from reserved descriptor".to_string(),
    };
    Ok(report_from_external_text(
        ConsultantRuntime::Codex,
        run_id,
        question_summary,
        &external_run,
        &report_text,
    ))
}

fn run_claude_consultant(
    repo: &Path,
    run_id: &RunId,
    consultant_bin: &Path,
    question_summary: &str,
    artifacts: &ConsultantArtifacts,
    timeout: Duration,
) -> Result<ConsultantReport> {
    let command = ExternalAgentCommand::claude_consultant(
        consultant_bin,
        repo,
        &artifacts.question_path,
        &artifacts.raw_log_path,
        &artifacts.incoming_report_path,
        timeout,
    );
    let external_run = run_external_agent(&command);
    let raw_log = external_run.stdout.text.clone();
    match claude_result_text(&raw_log) {
        Ok(report_text) => Ok(report_from_external_text(
            ConsultantRuntime::Claude,
            run_id,
            question_summary,
            &external_run,
            &report_text,
        )),
        Err(error) => Ok(failed_report_from_external(
            ConsultantRuntime::Claude,
            run_id,
            question_summary,
            &external_run,
            &raw_log,
            format!("failed to parse Claude JSON envelope: {error}"),
        )),
    }
}

fn required_consultant_bin(options: &ConsultAskOptions) -> Result<&Path> {
    options.consultant_bin.as_deref().with_context(|| {
        format!(
            "--consultant-bin is required when --runtime {} is selected",
            options.runtime.as_str()
        )
    })
}

fn report_from_external_text(
    runtime: ConsultantRuntime,
    run_id: &RunId,
    question_summary: &str,
    external_run: &ExternalAgentRun,
    report_text: &str,
) -> ConsultantReport {
    match parse_report_json::<ConsultantReport>(report_text) {
        Ok(parsed) => normalize_report(
            parsed.report,
            parsed.recovered,
            runtime,
            run_id,
            question_summary,
            external_run,
        ),
        Err(error) => failed_report_from_external(
            runtime,
            run_id,
            question_summary,
            external_run,
            report_text,
            error.to_string(),
        ),
    }
}

fn normalize_report(
    mut report: ConsultantReport,
    recovered: bool,
    runtime: ConsultantRuntime,
    run_id: &RunId,
    question_summary: &str,
    external_run: &ExternalAgentRun,
) -> ConsultantReport {
    let mut caveats = sanitize_public_fields(&report.caveats, CAVEAT_LIMIT);
    if recovered {
        caveats.push("report required lenient JSON extraction".to_string());
    }
    if !external_run.succeeded() {
        caveats.push("consultant subprocess did not exit successfully".to_string());
    }
    if report.runtime != runtime {
        caveats.push(format!(
            "consultant reported runtime {}; MACO recorded runtime {}",
            report.runtime.as_str(),
            runtime.as_str()
        ));
    }
    if report.run_id != *run_id {
        caveats.push("consultant reported a different run_id; MACO normalized it".to_string());
    }
    if !report.no_further_delegation {
        caveats.push("consultant omitted terminal no-delegation attestation".to_string());
    }
    if !report.read_only {
        caveats.push("consultant omitted read-only attestation".to_string());
    }

    let status_success = matches!(report.status, ConsultantStatus::Succeeded);
    let success = external_run.succeeded() && report.success && status_success;
    report.version = CONSULTANT_REPORT_VERSION;
    report.run_id = run_id.clone();
    report.runtime = runtime;
    report.question_summary = question_summary.to_string();
    report.answer = sanitize_public_text(&report.answer, ANSWER_LIMIT).text;
    report.references = sanitize_public_fields(&report.references, REFERENCE_LIMIT);
    report.caveats = caveats;
    report.no_further_delegation = true;
    report.read_only = true;
    report.duration_ms = external_run.duration_ms;
    report.exit_info = exit_info_from_external(external_run);
    report.success = success;
    report.status = if success {
        ConsultantStatus::Succeeded
    } else {
        ConsultantStatus::Failed
    };
    report
}

fn failed_report_from_external(
    runtime: ConsultantRuntime,
    run_id: &RunId,
    question_summary: &str,
    external_run: &ExternalAgentRun,
    report_text: &str,
    parse_error: String,
) -> ConsultantReport {
    ConsultantReport {
        version: CONSULTANT_REPORT_VERSION,
        run_id: run_id.clone(),
        runtime,
        question_summary: question_summary.to_string(),
        answer: sanitize_public_text(report_text, ANSWER_LIMIT).text,
        confidence: ConsultantConfidence::Low,
        references: Vec::new(),
        caveats: vec![sanitize_public_text(&parse_error, CAVEAT_LIMIT).text],
        no_further_delegation: true,
        read_only: true,
        duration_ms: external_run.duration_ms,
        exit_info: exit_info_from_external(external_run),
        success: false,
        status: ConsultantStatus::Failed,
    }
}

fn exit_info_from_external(external_run: &ExternalAgentRun) -> ConsultantExitInfo {
    ConsultantExitInfo {
        command: external_run
            .command
            .iter()
            .map(|arg| sanitize_public_text(arg, REFERENCE_LIMIT).text)
            .collect(),
        exit_code: external_run.exit_code,
        timed_out: external_run.timed_out,
        error: external_run
            .error
            .as_ref()
            .map(|error| sanitize_public_text(error, CAVEAT_LIMIT).text),
    }
}

fn claude_result_text(raw_log: &str) -> Result<String> {
    let value: Value = serde_json::from_str(raw_log).context("Claude output was not valid JSON")?;
    match value.get("result") {
        Some(Value::String(text)) => Ok(text.clone()),
        Some(other) => serde_json::to_string(other).context("failed to serialize Claude result"),
        None => bail!("Claude JSON envelope did not contain a result field"),
    }
}

fn parse_report_json<T>(contents: &str) -> Result<ParsedReport<T>>
where
    T: DeserializeOwned,
{
    if let Ok(report) = serde_json::from_str(contents) {
        return Ok(ParsedReport {
            report,
            recovered: false,
        });
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Ok(report) = serde_json::from_str(stripped) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(object) = last_top_level_json_object(contents) {
        if let Ok(report) = serde_json::from_str(object) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Some(object) = last_top_level_json_object(stripped) {
            if let Ok(report) = serde_json::from_str(object) {
                return Ok(ParsedReport {
                    report,
                    recovered: true,
                });
            }
        }
    }

    Err(anyhow!(
        "report is not valid JSON and lenient JSON extraction failed"
    ))
}

fn strip_surrounding_markdown_fence(contents: &str) -> Option<&str> {
    let trimmed = contents.trim();
    if !trimmed.starts_with("```") || !trimmed.ends_with("```") {
        return None;
    }
    let first_newline = trimmed.find('\n')?;
    let (opening, body_with_closing) = trimmed.split_at(first_newline);
    let info = opening.trim_start_matches("```").trim();
    if !info.is_empty() && info != "json" {
        return None;
    }
    let body_with_closing = body_with_closing.trim_start_matches('\n');
    let closing_start = body_with_closing.rfind("```")?;
    Some(body_with_closing[..closing_start].trim())
}

fn last_top_level_json_object(contents: &str) -> Option<&str> {
    let mut depth = 0usize;
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut last_object = None;

    for (index, character) in contents.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match character {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth = depth.saturating_add(1);
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    if let Some(object_start) = start.take() {
                        let object_end = index + character.len_utf8();
                        last_object = contents.get(object_start..object_end);
                    }
                }
            }
            _ => {}
        }
    }

    last_object
}

fn consultant_artifacts(repo: &Path, run_id: &RunId) -> ConsultantArtifacts {
    let run_dir = artifacts::run_dir(repo, RunArtifactFamily::Consult, run_id);
    let trusted_dir = run_dir.join("trusted");
    ConsultantArtifacts {
        question_path: trusted_dir.join("question.md"),
        incoming_report_path: run_dir.join("incoming").join("consultant-report.json"),
        raw_log_path: trusted_dir.join("raw.log"),
        schema_path: trusted_dir
            .join("schemas")
            .join("consultant-report.schema.json"),
        run_dir,
    }
}

fn write_consultant_final_report(
    slot: &mut ReservedOutputFile,
    report: &ConsultantReport,
) -> Result<()> {
    slot.write_json_atomic(report, MAX_CONSULT_ARTIFACT_BYTES)
        .with_context(|| format!("failed to write {}", slot.path().display()))
}

fn write_consultant_schema(slot: &mut ReservedOutputFile) -> Result<()> {
    slot.write_json_atomic(
        &json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ConsultantReport",
            "type": "object",
            "additionalProperties": true,
            "required": [
                "version",
                "run_id",
                "runtime",
                "question_summary",
                "answer",
                "confidence",
                "references",
                "caveats",
                "no_further_delegation",
                "read_only",
                "duration_ms",
                "exit_info"
            ],
            "properties": {
                "version": {"type": "integer"},
                "run_id": {"type": "string"},
                "runtime": {"type": "string", "enum": ["fake", "codex", "claude"]},
                "question_summary": {"type": "string"},
                "answer": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "references": {"type": "array", "items": {"type": "string"}},
                "caveats": {"type": "array", "items": {"type": "string"}},
                "no_further_delegation": {"type": "boolean", "const": true},
                "read_only": {"type": "boolean", "const": true},
                "duration_ms": {"type": "integer"},
                "exit_info": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": ["timed_out"],
                    "properties": {
                        "command": {"type": "array", "items": {"type": "string"}},
                        "exit_code": {"type": ["integer", "null"]},
                        "timed_out": {"type": "boolean"},
                        "error": {"type": ["string", "null"]}
                    }
                },
                "success": {"type": "boolean"},
                "status": {"type": "string", "enum": ["succeeded", "failed"]}
            }
        }),
        MAX_CONSULT_ARTIFACT_BYTES,
    )
}

fn write_text_file(path: &Path, text: &str) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Debug, Clone)]
struct BoundedText {
    text: String,
}

fn sanitize_public_text(text: &str, limit: usize) -> BoundedText {
    let redacted = Redactor::new().redact(text);
    let sanitized = sanitize_redacted_public_text(text, &redacted.text);
    let mut chars = sanitized.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    BoundedText { text: value }
}

fn sanitize_public_fields(values: &[String], limit: usize) -> Vec<String> {
    values
        .iter()
        .map(|value| sanitize_public_text(value, limit).text)
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
    if token_contains_local_absolute_path(token) {
        output.push_str("<redacted:local-path>");
    } else {
        output.push_str(token);
    }
}

fn token_contains_local_absolute_path(token: &str) -> bool {
    contains_windows_home_path(token) || contains_unix_absolute_path(token)
}

fn contains_windows_home_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("c:\\users\\") || lower.contains("c:/users/")
}

fn contains_unix_absolute_path(token: &str) -> bool {
    if token.starts_with("//") {
        return false;
    }
    for (index, character) in token.char_indices() {
        if character == '/' && is_unix_absolute_path_start(token, index) {
            return true;
        }
    }
    false
}

fn is_unix_absolute_path_start(token: &str, index: usize) -> bool {
    if token[index..].starts_with("//") || token_url_prefix_start(token, index).is_some() {
        return false;
    }
    let Some(next) = token[index..].chars().nth(1) else {
        return false;
    };
    if !is_unix_path_component_char(next) {
        return false;
    }
    let previous = token[..index].chars().next_back();
    !previous.is_some_and(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
    })
}

fn token_url_prefix_start(token: &str, index: usize) -> Option<usize> {
    let marker = token.find("://")?;
    (index > marker).then_some(marker)
}

fn is_unix_path_component_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_token_like_values_and_local_paths_in_question_summary() -> Result<()> {
        let prepared = prepare_question(
            "token abcdefghijklmnopqrstuvwxyz1234567890 and path /home/example/project",
        )?;
        assert!(prepared.summary.contains("<redacted:token>"));
        assert!(prepared.summary.contains("<redacted:local-path>"));
        assert!(!prepared
            .summary
            .contains("abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(!prepared.summary.contains("/home/example/project"));
        Ok(())
    }

    #[test]
    fn refuses_private_key_material_in_question() {
        let error = prepare_question("-----BEGIN PRIVATE KEY-----\nsecret\n")
            .expect_err("private key material should be refused");
        assert!(error.to_string().contains("private key material"));
    }

    #[test]
    fn prompt_contract_starts_with_six_line_consultant_block() -> Result<()> {
        let run_id = RunId::new("consult-test")?;
        let prompt = consultant_prompt(
            &run_id,
            "Why is this failing?",
            &[PathBuf::from("README.md")],
            Path::new(".maco/consult/runs/consult-test/schemas/consultant-report.schema.json"),
        )?;
        assert!(prompt.starts_with(
            "ROLE: CONSULTANT\nAGENT_KIND: consultant\nAGENT_LABEL: consult-test\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 2\nNO_FURTHER_DELEGATION: true\n"
        ));
        assert!(prompt.contains("terminal read-only CONSULTANT"));
        assert!(prompt.contains("Do not edit files"));
        assert!(prompt.contains("Return ConsultantReport JSON"));
        assert!(prompt.contains("- README.md"));
        Ok(())
    }

    #[test]
    fn parses_fenced_report_json_with_recovery() -> Result<()> {
        let contents = format!("```json\n{}\n```", sample_report_json("consult-parse"));
        let parsed: ParsedReport<ConsultantReport> = parse_report_json(&contents)?;
        assert_eq!(parsed.report.run_id.as_str(), "consult-parse");
        assert!(parsed.recovered);
        Ok(())
    }

    #[test]
    fn extracts_last_embedded_report_json_with_recovery() -> Result<()> {
        let contents = format!(
            "notes before\n{{\"ignored\":true}}\n{}\ntrailing",
            sample_report_json("consult-embedded")
        );
        let parsed: ParsedReport<ConsultantReport> = parse_report_json(&contents)?;
        assert_eq!(parsed.report.run_id.as_str(), "consult-embedded");
        assert!(parsed.recovered);
        Ok(())
    }

    #[test]
    fn fake_adapter_report_is_deterministic() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let run_id = RunId::new("consult-fake")?;
        let first = fake_consultant_report(
            &run_id,
            "question".to_string(),
            &[PathBuf::from("README.md")],
            &temp.path().join("first.log"),
        )?;
        let second = fake_consultant_report(
            &run_id,
            "question".to_string(),
            &[PathBuf::from("README.md")],
            &temp.path().join("second.log"),
        )?;
        assert_eq!(first, second);
        assert_eq!(first.runtime, ConsultantRuntime::Fake);
        assert_eq!(first.duration_ms, 0);
        assert!(first.no_further_delegation);
        assert!(first.read_only);
        Ok(())
    }

    fn sample_report_json(run_id: &str) -> String {
        format!(
            r#"{{
  "version": 1,
  "run_id": "{run_id}",
  "runtime": "codex",
  "question_summary": "why",
  "answer": "because",
  "confidence": "medium",
  "references": ["README.md"],
  "caveats": [],
  "no_further_delegation": true,
  "read_only": true,
  "duration_ms": 1,
  "exit_info": {{"command": [], "exit_code": 0, "timed_out": false}},
  "success": true,
  "status": "succeeded"
}}"#
        )
    }
}
