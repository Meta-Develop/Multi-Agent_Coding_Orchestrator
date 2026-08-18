use crate::{
    artifacts::{
        self, ArtifactFileDisposition, ArtifactRunWriter, ArtifactScratchDirectory,
        RunArtifactFamily,
    },
    external_agent::{run_external_agent, ExternalAgentCommand, ExternalAgentRun},
    llm::Redactor,
    orchestrator::RunId,
    process_runner::resolve_existing_path_without_symlinks,
    sync::normalize_repo_relative_path,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
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
const MAX_CONSULT_RAW_BYTES: usize = 8 * 1024 * 1024;
const CONSULT_PRODUCER: &str = "consult";
const QUESTION_ARTIFACT: &str = "trusted/question.md";
const RAW_LOG_ARTIFACT: &str = "trusted/raw.log";
const SCHEMA_ARTIFACT: &str = "trusted/schemas/consultant-report.schema.json";
const FINAL_REPORT_ARTIFACT: &str = "trusted/consultant-report.json";
const EXTERNAL_INCOMING_SCRATCH: &str = "incoming";
const EXTERNAL_CAPTURE_SCRATCH: &str = "capture";

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
struct PreparedQuestion {
    prompt_body: String,
    summary: String,
}

#[derive(Debug)]
struct PreparedConsultation {
    question: PreparedQuestion,
    context_paths: Vec<PathBuf>,
    consultant_bin: Option<PathBuf>,
}

#[derive(Debug)]
struct ExternalConsultOutcome {
    report: ConsultantReport,
    raw_evidence: Vec<u8>,
}

#[derive(Debug)]
struct ParsedReport<T> {
    report: T,
    recovered: bool,
}

pub fn ask_consultant(options: ConsultAskOptions) -> Result<ConsultantReport> {
    ask_consultant_with_runner(options, run_external_agent)
}

fn ask_consultant_with_runner<F>(
    options: ConsultAskOptions,
    mut external_runner: F,
) -> Result<ConsultantReport>
where
    F: FnMut(&ExternalAgentCommand) -> ExternalAgentRun,
{
    let repo = artifacts::discover_repo_root(&options.repo)?;
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Consult,
        options.run_id.clone(),
        CONSULT_PRODUCER,
    )?;
    write_consultant_schema(&mut writer)?;

    let prepared = prepare_consultation(&options, &repo);
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return finalize_operational_failure(writer, &options, &error);
        }
    };

    let schema_prompt_path = RunArtifactFamily::Consult
        .run_root()
        .join(options.run_id.as_str())
        .join(SCHEMA_ARTIFACT);
    let prompt = match consultant_prompt(
        &options.run_id,
        &prepared.question.prompt_body,
        &prepared.context_paths,
        &schema_prompt_path,
    ) {
        Ok(prompt) => prompt,
        Err(error) => {
            return finalize_operational_failure(writer, &options, &error);
        }
    };
    writer.write_bytes(
        QUESTION_ARTIFACT,
        prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;

    let (report, raw_evidence) = match options.runtime {
        ConsultantRuntime::Fake => (
            fake_consultant_report(
                &options.run_id,
                prepared.question.summary,
                &prepared.context_paths,
            ),
            b"fake consultant runtime: no subprocess launched\n".to_vec(),
        ),
        ConsultantRuntime::Codex => {
            let consultant_bin = prepared
                .consultant_bin
                .as_deref()
                .context("prepared Codex consultant executable is missing")?;
            let outcome = run_codex_consultant(
                &repo,
                &options.run_id,
                consultant_bin,
                &prepared.question.summary,
                &mut writer,
                Duration::from_secs(options.timeout_seconds),
                &mut external_runner,
            )?;
            (outcome.report, outcome.raw_evidence)
        }
        ConsultantRuntime::Claude => {
            let consultant_bin = prepared
                .consultant_bin
                .as_deref()
                .context("prepared Claude consultant executable is missing")?;
            let outcome = run_claude_consultant(
                &repo,
                &options.run_id,
                consultant_bin,
                &prepared.question.summary,
                &mut writer,
                Duration::from_secs(options.timeout_seconds),
                &mut external_runner,
            )?;
            (outcome.report, outcome.raw_evidence)
        }
    };

    write_raw_evidence(&mut writer, &raw_evidence)?;
    finalize_consultant_report(writer, &report)?;
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

fn prepare_consultation(options: &ConsultAskOptions, repo: &Path) -> Result<PreparedConsultation> {
    let question = prepare_question(&options.question)?;
    if options.timeout_seconds == 0 {
        bail!("timeout_seconds must be greater than zero");
    }
    let context_paths = validate_context_paths(repo, &options.context_paths)?;
    let consultant_bin = match options.runtime {
        ConsultantRuntime::Fake => None,
        ConsultantRuntime::Codex | ConsultantRuntime::Claude => {
            Some(options.consultant_bin.clone().with_context(|| {
                format!(
                    "--consultant-bin is required when --runtime {} is selected",
                    options.runtime.as_str()
                )
            })?)
        }
    };
    Ok(PreparedConsultation {
        question,
        context_paths,
        consultant_bin,
    })
}

fn fake_consultant_report(
    run_id: &RunId,
    question_summary: String,
    context_paths: &[PathBuf],
) -> ConsultantReport {
    ConsultantReport {
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
    }
}

fn run_codex_consultant<F>(
    repo: &Path,
    run_id: &RunId,
    consultant_bin: &Path,
    question_summary: &str,
    writer: &mut ArtifactRunWriter,
    timeout: Duration,
    external_runner: &mut F,
) -> Result<ExternalConsultOutcome>
where
    F: FnMut(&ExternalAgentCommand) -> ExternalAgentRun,
{
    let (incoming, capture) = create_external_scratches(writer)?;
    let raw_log_path = capture.path().join("raw.log");
    let incoming_report_path = incoming.path().join("consultant-report.json");
    let command = ExternalAgentCommand::codex_read_only_consultant(
        consultant_bin,
        repo,
        writer.run_dir().join(QUESTION_ARTIFACT),
        &raw_log_path,
        &incoming_report_path,
        timeout,
    );
    let external_run = external_runner(&command);
    let report = match external_run.output_last_message() {
        Some(contents) => match std::str::from_utf8(contents) {
            Ok(report_text) => report_from_external_text(
                ConsultantRuntime::Codex,
                run_id,
                question_summary,
                &external_run,
                report_text,
            ),
            Err(error) => failed_report_from_external(
                ConsultantRuntime::Codex,
                run_id,
                question_summary,
                &external_run,
                &String::from_utf8_lossy(contents),
                format!("descriptor-captured Codex report was not valid UTF-8: {error}"),
            ),
        },
        None => failed_report_from_external(
            ConsultantRuntime::Codex,
            run_id,
            question_summary,
            &external_run,
            "",
            "failed to capture Codex consultant report from reserved descriptor".to_string(),
        ),
    };
    let raw_evidence = external_run.stdout_bytes().to_vec();
    drop(command);
    if !external_run.scratch_quiescence_verified() {
        bail!(
            "external Codex target scratch quiescence was not verified; leaving the run unfinalized for operator inspection"
        );
    }
    let raw_evidence = finish_external_scratches(
        raw_evidence,
        writer.discard_scratch(&capture),
        writer.discard_scratch(&incoming),
    )?;
    Ok(ExternalConsultOutcome {
        report,
        raw_evidence,
    })
}

fn run_claude_consultant<F>(
    repo: &Path,
    run_id: &RunId,
    consultant_bin: &Path,
    question_summary: &str,
    writer: &mut ArtifactRunWriter,
    timeout: Duration,
    external_runner: &mut F,
) -> Result<ExternalConsultOutcome>
where
    F: FnMut(&ExternalAgentCommand) -> ExternalAgentRun,
{
    let (incoming, capture) = create_external_scratches(writer)?;
    let raw_log_path = capture.path().join("raw.log");
    let incoming_report_path = incoming.path().join("consultant-report.json");
    let command = ExternalAgentCommand::claude_consultant(
        consultant_bin,
        repo,
        writer.run_dir().join(QUESTION_ARTIFACT),
        &raw_log_path,
        &incoming_report_path,
        timeout,
    );
    let external_run = external_runner(&command);
    let raw_evidence = external_run.stdout_bytes().to_vec();
    let report = match std::str::from_utf8(&raw_evidence) {
        Ok(raw_log) => match claude_result_text(raw_log) {
            Ok(report_text) => report_from_external_text(
                ConsultantRuntime::Claude,
                run_id,
                question_summary,
                &external_run,
                &report_text,
            ),
            Err(error) => failed_report_from_external(
                ConsultantRuntime::Claude,
                run_id,
                question_summary,
                &external_run,
                raw_log,
                format!("failed to parse Claude JSON envelope: {error}"),
            ),
        },
        Err(error) => failed_report_from_external(
            ConsultantRuntime::Claude,
            run_id,
            question_summary,
            &external_run,
            &String::from_utf8_lossy(&raw_evidence),
            format!("descriptor-captured Claude output was not valid UTF-8: {error}"),
        ),
    };
    drop(command);
    if !external_run.scratch_quiescence_verified() {
        bail!(
            "external Claude target scratch quiescence was not verified; leaving the run unfinalized for operator inspection"
        );
    }
    let raw_evidence = finish_external_scratches(
        raw_evidence,
        writer.discard_scratch(&capture),
        writer.discard_scratch(&incoming),
    )?;
    Ok(ExternalConsultOutcome {
        report,
        raw_evidence,
    })
}

fn create_external_scratches(
    writer: &mut ArtifactRunWriter,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    let incoming = writer.create_scratch_dir(EXTERNAL_INCOMING_SCRATCH)?;
    match writer.create_scratch_dir(EXTERNAL_CAPTURE_SCRATCH) {
        Ok(capture) => Ok((incoming, capture)),
        Err(error) => match writer.discard_scratch(&incoming) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.context(format!(
                "incoming artifact scratch cleanup also failed: {cleanup_error:#}"
            ))),
        },
    }
}

fn finish_external_scratches(
    raw_evidence: Vec<u8>,
    capture_cleanup: Result<()>,
    incoming_cleanup: Result<()>,
) -> Result<Vec<u8>> {
    let cleanup = match (capture_cleanup, incoming_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(incoming_error)) => Err(error.context(format!(
            "incoming artifact scratch cleanup also failed: {incoming_error:#}"
        ))),
    };
    cleanup?;
    Ok(raw_evidence)
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
    append_stdout_truncation_caveat(&mut caveats, external_run);
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
    let mut caveats = vec![sanitize_public_text(&parse_error, CAVEAT_LIMIT).text];
    append_stdout_truncation_caveat(&mut caveats, external_run);
    ConsultantReport {
        version: CONSULTANT_REPORT_VERSION,
        run_id: run_id.clone(),
        runtime,
        question_summary: question_summary.to_string(),
        answer: sanitize_public_text(report_text, ANSWER_LIMIT).text,
        confidence: ConsultantConfidence::Low,
        references: Vec::new(),
        caveats,
        no_further_delegation: true,
        read_only: true,
        duration_ms: external_run.duration_ms,
        exit_info: exit_info_from_external(external_run),
        success: false,
        status: ConsultantStatus::Failed,
    }
}

fn append_stdout_truncation_caveat(caveats: &mut Vec<String>, external_run: &ExternalAgentRun) {
    if external_run.stdout.truncated {
        caveats.push(format!(
            "stdout capture or public summary reached a configured bound; raw evidence contains {} descriptor-captured bytes",
            external_run.stdout_bytes().len()
        ));
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

fn finalize_consultant_report(
    mut writer: ArtifactRunWriter,
    report: &ConsultantReport,
) -> Result<()> {
    writer.write_json(
        FINAL_REPORT_ARTIFACT,
        report,
        ArtifactFileDisposition::Publishable,
    )?;
    let publish_requested = report.success && report.runtime != ConsultantRuntime::Fake;
    writer.finalize(FINAL_REPORT_ARTIFACT, publish_requested)?;
    Ok(())
}

fn write_raw_evidence(writer: &mut ArtifactRunWriter, contents: &[u8]) -> Result<()> {
    if contents.len() > MAX_CONSULT_RAW_BYTES {
        bail!(
            "consult raw evidence exceeds its {} byte limit",
            MAX_CONSULT_RAW_BYTES
        );
    }
    writer.write_bytes(
        RAW_LOG_ARTIFACT,
        contents,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    Ok(())
}

fn finalize_operational_failure(
    mut writer: ArtifactRunWriter,
    options: &ConsultAskOptions,
    error: &anyhow::Error,
) -> Result<ConsultantReport> {
    let refusal_prompt = format!(
        "{}Consult request refused before a question could be safely persisted.\n",
        consultant_role_prefix(&options.run_id)
    );
    writer.write_bytes(
        QUESTION_ARTIFACT,
        refusal_prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    write_raw_evidence(
        &mut writer,
        b"consult request refused before subprocess launch\n",
    )?;
    let safe_error = sanitize_public_text(&error.to_string(), CAVEAT_LIMIT).text;
    let report = ConsultantReport {
        version: CONSULTANT_REPORT_VERSION,
        run_id: options.run_id.clone(),
        runtime: options.runtime,
        question_summary: "<redacted:refused-question>".to_string(),
        answer: "Consult request was refused before subprocess launch.".to_string(),
        confidence: ConsultantConfidence::Low,
        references: Vec::new(),
        caveats: vec![safe_error.clone()],
        no_further_delegation: true,
        read_only: true,
        duration_ms: 0,
        exit_info: ConsultantExitInfo {
            command: Vec::new(),
            exit_code: None,
            timed_out: false,
            error: Some(safe_error),
        },
        success: false,
        status: ConsultantStatus::Failed,
    };
    finalize_consultant_report(writer, &report)?;
    Ok(report)
}

fn write_consultant_schema(writer: &mut ArtifactRunWriter) -> Result<()> {
    writer.write_json(
        SCHEMA_ARTIFACT,
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
        ArtifactFileDisposition::Publishable,
    )?;
    Ok(())
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
    use crate::external_agent::{
        run_external_agent_nonpublishable_simulation, CapturedOutput, ExternalProgramTrust,
    };
    use crate::process_runner::{
        ContainmentBackend, ProcessTreeEvidence, SideEffectConfinementEvidence,
        SideEffectConfinementProfileKind,
    };
    use std::fs;

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
        let run_id = RunId::new("consult-fake")?;
        let first = fake_consultant_report(
            &run_id,
            "question".to_string(),
            &[PathBuf::from("README.md")],
        );
        let second = fake_consultant_report(
            &run_id,
            "question".to_string(),
            &[PathBuf::from("README.md")],
        );
        assert_eq!(first, second);
        assert_eq!(first.runtime, ConsultantRuntime::Fake);
        assert_eq!(first.duration_ms, 0);
        assert!(first.no_further_delegation);
        assert!(first.read_only);
        Ok(())
    }

    #[test]
    fn failed_report_records_stdout_bound_without_exposing_private_bytes() -> Result<()> {
        let command = ExternalAgentCommand::codex(
            "/test-only/codex",
            ".",
            "prompt",
            "capture/raw.log",
            "incoming/report.json",
            Duration::from_secs(1),
        );
        let mut external = failed_test_external_run(&command, "synthetic failure");
        external.stdout.truncated = true;
        let report = failed_report_from_external(
            ConsultantRuntime::Codex,
            &RunId::new("consult-truncated")?,
            "question",
            &external,
            "",
            "missing report".to_string(),
        );
        assert!(report
            .caveats
            .iter()
            .any(|caveat| caveat
                .contains("stdout capture or public summary reached a configured bound")));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_failure_imports_exact_parent_capture_and_discards_both_scratches() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = create_test_repo(temp.path())?;
        let run_id = RunId::new("consult-external-failure")?;
        let raw_bytes = b"exact descriptor capture\0with binary\xffbytes\n".to_vec();
        let consultant_bin = write_test_external_program(
            temp.path(),
            "printf 'exact descriptor capture\\000with binary\\377bytes\\n'\nexit 7\n",
        )?;
        let options = ConsultAskOptions {
            repo: repo.clone(),
            run_id: run_id.clone(),
            runtime: ConsultantRuntime::Codex,
            consultant_bin: Some(consultant_bin),
            question: "What should be inspected?".to_string(),
            context_paths: Vec::new(),
            timeout_seconds: 1,
        };
        let report = ask_consultant_with_runner(options, |command| {
            assert_ne!(
                command.json_log.parent(),
                command.output_last_message.parent(),
                "parent-only capture and child-writable incoming roots must be separate"
            );
            assert_eq!(
                command.json_log.parent().and_then(Path::file_name),
                Some(std::ffi::OsStr::new(EXTERNAL_CAPTURE_SCRATCH))
            );
            assert_eq!(
                command
                    .output_last_message
                    .parent()
                    .and_then(Path::file_name),
                Some(std::ffi::OsStr::new(EXTERNAL_INCOMING_SCRATCH))
            );
            let mut run = run_external_agent_nonpublishable_simulation(command);
            run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            ));
            run.side_effects = Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ));
            assert!(run.scratch_quiescence_verified());
            run
        })?;

        assert!(!report.success);
        let run_dir = repo.join(".maco/consult/runs").join(run_id.as_str());
        assert_eq!(fs::read(run_dir.join(RAW_LOG_ARTIFACT))?, raw_bytes);
        assert!(!run_dir.join(EXTERNAL_CAPTURE_SCRATCH).exists());
        assert!(!run_dir.join(EXTERNAL_INCOMING_SCRATCH).exists());
        assert!(run_dir.join(".maco-artifact-final.json").exists());
        artifacts::ArtifactRunReader::open(&repo, RunArtifactFamily::Consult, &run_id)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn attempted_unverified_target_leaves_scratches_unfinalized() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = create_test_repo(temp.path())?;
        let run_id = RunId::new("consult-unverified-target")?;
        let consultant_bin = write_test_external_program(
            temp.path(),
            "printf 'unverified target output\\n'\nexit 7\n",
        )?;
        let options = ConsultAskOptions {
            repo: repo.clone(),
            run_id: run_id.clone(),
            runtime: ConsultantRuntime::Codex,
            consultant_bin: Some(consultant_bin),
            question: "What should be inspected?".to_string(),
            context_paths: Vec::new(),
            timeout_seconds: 1,
        };

        let error = ask_consultant_with_runner(options, |command| {
            let mut run = run_external_agent_nonpublishable_simulation(command);
            run.process_tree = Some(ProcessTreeEvidence::Unverified(
                ContainmentBackend::SystemdUserService,
            ));
            run
        })
        .expect_err("attempted target without verified-empty evidence must remain unfinalized");
        assert!(format!("{error:#}").contains("scratch quiescence was not verified"));

        let run_dir = repo.join(".maco/consult/runs").join(run_id.as_str());
        assert!(run_dir.join(EXTERNAL_CAPTURE_SCRATCH).exists());
        assert!(run_dir.join(EXTERNAL_INCOMING_SCRATCH).exists());
        assert!(!run_dir.join(RAW_LOG_ARTIFACT).exists());
        assert!(!run_dir.join(".maco-artifact-final.json").exists());
        Ok(())
    }

    #[test]
    fn preflight_refusal_discards_unused_scratches_and_finalizes_failure() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = create_test_repo(temp.path())?;
        let run_id = RunId::new("consult-preflight-refusal")?;
        let options = ConsultAskOptions {
            repo: repo.clone(),
            run_id: run_id.clone(),
            runtime: ConsultantRuntime::Codex,
            consultant_bin: Some(PathBuf::from("/test-only/codex")),
            question: "What should be inspected?".to_string(),
            context_paths: Vec::new(),
            timeout_seconds: 1,
        };

        let report = ask_consultant_with_runner(options, |command| {
            failed_test_external_run(command, "synthetic preflight refusal")
        })?;

        assert!(!report.success);
        let run_dir = repo.join(".maco/consult/runs").join(run_id.as_str());
        assert!(!run_dir.join(EXTERNAL_CAPTURE_SCRATCH).exists());
        assert!(!run_dir.join(EXTERNAL_INCOMING_SCRATCH).exists());
        assert_eq!(fs::read(run_dir.join(RAW_LOG_ARTIFACT))?, b"");
        artifacts::ArtifactRunReader::open(&repo, RunArtifactFamily::Consult, &run_id)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn incoming_scratch_rebind_blocks_finalization_and_preserves_replacement() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = create_test_repo(temp.path())?;
        let run_id = RunId::new("consult-scratch-rebind")?;
        let options = ConsultAskOptions {
            repo: repo.clone(),
            run_id: run_id.clone(),
            runtime: ConsultantRuntime::Codex,
            consultant_bin: Some(PathBuf::from("/test-only/codex")),
            question: "What should be inspected?".to_string(),
            context_paths: Vec::new(),
            timeout_seconds: 1,
        };
        let error = ask_consultant_with_runner(options, |command| {
            let incoming = command
                .output_last_message
                .parent()
                .expect("incoming parent");
            let moved = incoming.with_file_name("incoming-moved");
            fs::rename(incoming, &moved).expect("move original incoming scratch");
            fs::create_dir(incoming).expect("replace incoming scratch");
            fs::write(incoming.join("sentinel"), b"replacement survives")
                .expect("write replacement sentinel");
            failed_test_external_run(command, "synthetic scratch rebind")
        })
        .expect_err("scratch identity replacement must block finalization");
        let message = format!("{error:#}");
        assert!(
            message.contains("identity")
                || message.contains("replaced")
                || message.contains("opened inode"),
            "unexpected scratch rebind error: {message}"
        );

        let run_dir = repo.join(".maco/consult/runs").join(run_id.as_str());
        assert_eq!(
            fs::read(run_dir.join(EXTERNAL_INCOMING_SCRATCH).join("sentinel"))?,
            b"replacement survives"
        );
        assert!(run_dir.join("incoming-moved").exists());
        assert!(!run_dir.join(EXTERNAL_CAPTURE_SCRATCH).exists());
        assert!(!run_dir.join(".maco-artifact-final.json").exists());
        Ok(())
    }

    fn failed_test_external_run(command: &ExternalAgentCommand, error: &str) -> ExternalAgentRun {
        ExternalAgentRun {
            command: vec![command.program.display().to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: command.timeout.as_secs(),
            exit_code: None,
            duration_ms: 1,
            timed_out: false,
            process_tree: None,
            side_effects: None,
            publishable: false,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: Some(error.to_string()),
            output_last_message: None,
        }
    }

    fn create_test_repo(root: &Path) -> Result<PathBuf> {
        let repo = root.join("repo");
        fs::create_dir(&repo)?;
        git2::Repository::init(&repo)?;
        for control_root in [".maco", ".maco-cache", ".codex", ".agents"] {
            fs::create_dir(repo.join(control_root))?;
        }
        fs::write(repo.join("README.md"), "# Test repository\n")?;
        Ok(repo)
    }

    #[cfg(unix)]
    fn write_test_external_program(root: &Path, body: &str) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let program = root.join("test-external-agent");
        fs::write(&program, format!("#!/bin/sh\ncat >/dev/null\n{body}"))?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        Ok(program)
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
