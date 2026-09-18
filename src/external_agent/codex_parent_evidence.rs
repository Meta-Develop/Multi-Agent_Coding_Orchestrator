//! Parent-captured Codex model, effort, and usage evidence.
//!
//! `codex exec --json` never prints the model or reasoning effort it used. The only durable
//! record is the rollout Codex writes below `$CODEX_HOME/sessions/`, whose `turn_context`
//! payloads carry the client-resolved model slug and the configured effort. Supervisor launches
//! therefore run with a parent-owned Codex home (see `ExternalOutputStaging::stage_codex_home`)
//! and the parent reads that rollout after the unit exits.
//!
//! Everything here is derived by the parent from descriptor-held captures. Child reports may
//! never assert it; acceptance strips any child-provided value.

use crate::secure_output::{CollectLimits, CollectedRegularFile, SecureOutputRoot};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Rollout files live at `sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl`.
const CODEX_SESSIONS_DIR: &str = "sessions";
const CODEX_ROLLOUT_PREFIX: &str = "rollout-";
const CODEX_ROLLOUT_SUFFIX: &str = ".jsonl";
/// `YYYY-MM-DDTHH-MM-SS` as written by Codex in rollout file names.
const CODEX_ROLLOUT_TIMESTAMP_LEN: usize = 19;
const CODEX_SESSIONS_COLLECT_LIMITS: CollectLimits = CollectLimits {
    max_depth: 4,
    max_entries: 4096,
    max_files: 256,
    max_file_bytes: 64 * 1024 * 1024,
};
const CODEX_REROUTE_MESSAGE_PREFIX: &str = "model rerouted: ";
const CODEX_REROUTE_MESSAGE_ARROW: &str = " -> ";

/// Parent-owned Codex execution evidence (not child-reportable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CodexParentEvidence {
    /// Codex CLI version verified by the parent's fixed version probe.
    pub codex_version: Option<String>,
    /// `thread.started.thread_id` from the captured `codex exec --json` stream.
    pub thread_id: Option<String>,
    /// Model requested on the command line. Copied, never promoted to an observation.
    pub requested_model: Option<String>,
    /// Reasoning effort requested on the command line. Copied, never promoted.
    pub requested_effort: Option<String>,
    /// Client-resolved model slug from the rollout `turn_context` payloads.
    pub rollout_model: CodexParentResolvedField,
    /// Configured reasoning effort from the rollout `turn_context` payloads.
    pub rollout_effort: CodexParentResolvedField,
    /// Model the server actually served: the reroute target when Codex reported one, otherwise
    /// the rollout model.
    pub observed_model: CodexParentResolvedField,
    /// Effort actually in force; Codex reports no server-side effort change, so this is the
    /// rollout effort.
    pub observed_effort: CodexParentResolvedField,
    /// Server reroute reported through an `item.completed` error item.
    pub server_rerouted_model: Option<CodexServerRerouteEvidence>,
    /// `requested_model` is known, `observed_model` is known, and they differ.
    pub model_mismatch: bool,
    pub turn_usage: CodexParentTurnUsage,
    /// One of the `CodexParentResolutionStatus` labels.
    pub resolution_status: String,
}

/// Externally tagged: `{"known":"<value>"}` or the string `"unknown"` (the same wire shape
/// as `GrokAcpParentResolvedField`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexParentResolvedField {
    Known(String),
    Unknown,
}

impl CodexParentResolvedField {
    pub fn known(&self) -> Option<&str> {
        match self {
            Self::Known(value) => Some(value.as_str()),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CodexServerRerouteEvidence {
    pub from: String,
    pub to: String,
}

/// Cumulative usage from the final `turn.completed` event of the captured stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CodexParentTurnUsage {
    Known {
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        reasoning_output_tokens: u64,
    },
    Unknown {
        reason: String,
    },
}

/// Why parent evidence stopped short of `complete`. The highest-priority failure wins, in the
/// declaration order below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodexParentResolutionStatus {
    /// The captured `codex exec --json` stream or the rollout could not be parsed or lacked
    /// its mandatory structure.
    JsonlInvalid,
    /// The stream reported `turn.failed`.
    TurnFailed,
    /// No rollout was written below the parent-owned Codex home.
    RolloutMissing,
    /// No rollout (file name or `session_meta.id`) matched the stream's thread id.
    ThreadIdMismatch,
    /// The rollout cannot be attributed unambiguously: several rollouts matched, its cwd
    /// differs from the launch cwd, or its `turn_context` payloads disagree or omit effort.
    Ambiguous,
    /// `session_meta.cli_version` differs from the version verified by the parent's probe.
    VersionMismatch,
    /// The stream carried no usable `turn.completed` usage.
    UsageUnavailable,
    Complete,
}

impl CodexParentResolutionStatus {
    pub const LABELS: [&'static str; 8] = [
        "complete",
        "rollout_missing",
        "thread_id_mismatch",
        "ambiguous",
        "turn_failed",
        "usage_unavailable",
        "version_mismatch",
        "jsonl_invalid",
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::RolloutMissing => "rollout_missing",
            Self::ThreadIdMismatch => "thread_id_mismatch",
            Self::Ambiguous => "ambiguous",
            Self::TurnFailed => "turn_failed",
            Self::UsageUnavailable => "usage_unavailable",
            Self::VersionMismatch => "version_mismatch",
            Self::JsonlInvalid => "jsonl_invalid",
        }
    }
}

/// Launch facts the parent already holds before reading any child-written byte.
pub(crate) struct CodexParentEvidenceInputs<'a> {
    /// Version verified by the fixed version probe, when the probe ran.
    pub(crate) codex_version: Option<(u64, u64, u64)>,
    pub(crate) cwd: &'a Path,
    pub(crate) requested_model: Option<&'a str>,
    pub(crate) requested_effort: Option<&'a str>,
}

/// Derives the evidence from the captured stdout stream and the parent-owned Codex home.
/// `stdout` is `None` when the bounded capture was truncated and can no longer be trusted.
pub(crate) fn codex_parent_evidence_from_run(
    inputs: &CodexParentEvidenceInputs<'_>,
    stdout: Option<&[u8]>,
    codex_home: &SecureOutputRoot,
) -> CodexParentEvidence {
    let stream = stdout.ok_or(()).and_then(parse_exec_stream);
    let rollout = match &stream {
        Ok(stream) => match stream.thread_id.as_deref() {
            Some(thread_id) => {
                match codex_home.collect_regular_files(
                    Path::new(CODEX_SESSIONS_DIR),
                    CODEX_SESSIONS_COLLECT_LIMITS,
                ) {
                    Ok(files) => resolve_rollout(inputs, thread_id, &files),
                    Err(_) => {
                        RolloutResolution::failed(CodexParentResolutionStatus::RolloutMissing)
                    }
                }
            }
            None => RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid),
        },
        Err(()) => RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid),
    };
    assemble_evidence(inputs, stream, rollout)
}

fn assemble_evidence(
    inputs: &CodexParentEvidenceInputs<'_>,
    stream: Result<ExecStreamSummary, ()>,
    rollout: RolloutResolution,
) -> CodexParentEvidence {
    let mut status = CodexParentResolutionStatus::Complete;
    let mut note = |candidate: CodexParentResolutionStatus| {
        status = status.min(candidate);
    };

    let (thread_id, reroute, turn_usage) = match stream {
        Ok(stream) => {
            if stream.thread_started != 1 {
                note(CodexParentResolutionStatus::JsonlInvalid);
            }
            if stream.turn_failed > 0 {
                note(CodexParentResolutionStatus::TurnFailed);
            }
            let turn_usage = if stream.turn_failed > 0 {
                CodexParentTurnUsage::Unknown {
                    reason: "the Codex stream reported turn.failed".to_string(),
                }
            } else {
                match stream.last_usage {
                    None => CodexParentTurnUsage::Unknown {
                        reason: "the Codex stream carried no turn.completed usage".to_string(),
                    },
                    Some(usage) if usage.input_tokens == 0 && usage.output_tokens == 0 => {
                        CodexParentTurnUsage::Unknown {
                            reason:
                                "turn.completed usage was all zero (no token notification arrived)"
                                    .to_string(),
                        }
                    }
                    Some(usage) => CodexParentTurnUsage::Known {
                        input_tokens: usage.input_tokens,
                        output_tokens: usage.output_tokens,
                        cached_input_tokens: usage.cached_input_tokens,
                        reasoning_output_tokens: usage.reasoning_output_tokens,
                    },
                }
            };
            if matches!(turn_usage, CodexParentTurnUsage::Unknown { .. }) && stream.turn_failed == 0
            {
                note(CodexParentResolutionStatus::UsageUnavailable);
            }
            (stream.thread_id, stream.reroute, turn_usage)
        }
        Err(()) => {
            note(CodexParentResolutionStatus::JsonlInvalid);
            (
                None,
                None,
                CodexParentTurnUsage::Unknown {
                    reason: "the Codex stream was not valid JSONL".to_string(),
                },
            )
        }
    };
    if let Some(failure) = rollout.failure {
        note(failure);
    }

    let observed_model = match &reroute {
        Some(reroute) => CodexParentResolvedField::Known(reroute.to.clone()),
        None => rollout.model.clone(),
    };
    let observed_effort = rollout.effort.clone();
    let model_mismatch = matches!(
        (inputs.requested_model, observed_model.known()),
        (Some(requested), Some(observed)) if requested != observed
    );

    CodexParentEvidence {
        codex_version: inputs.codex_version.map(format_version),
        thread_id,
        requested_model: inputs.requested_model.map(str::to_string),
        requested_effort: inputs.requested_effort.map(str::to_string),
        rollout_model: rollout.model,
        rollout_effort: rollout.effort,
        observed_model,
        observed_effort,
        server_rerouted_model: reroute,
        model_mismatch,
        turn_usage,
        resolution_status: status.label().to_string(),
    }
}

fn format_version((major, minor, patch): (u64, u64, u64)) -> String {
    format!("{major}.{minor}.{patch}")
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct StreamUsage {
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    reasoning_output_tokens: u64,
}

#[derive(Debug, Default)]
struct ExecStreamSummary {
    thread_started: usize,
    thread_id: Option<String>,
    turn_failed: usize,
    /// Usage from the last `turn.completed`; Codex reports cumulative totals there.
    last_usage: Option<StreamUsage>,
    reroute: Option<CodexServerRerouteEvidence>,
}

/// Summarizes the `codex exec --json` stream. `Err(())` means the capture is not valid JSONL.
fn parse_exec_stream(stdout: &[u8]) -> Result<ExecStreamSummary, ()> {
    let contents = std::str::from_utf8(stdout).map_err(|_| ())?;
    let mut summary = ExecStreamSummary::default();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).map_err(|_| ())?;
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("thread.started") => {
                summary.thread_started = summary.thread_started.saturating_add(1);
                if summary.thread_id.is_none() {
                    summary.thread_id = event
                        .get("thread_id")
                        .and_then(serde_json::Value::as_str)
                        .filter(|id| !id.is_empty())
                        .map(str::to_string);
                }
            }
            Some("turn.failed") => {
                summary.turn_failed = summary.turn_failed.saturating_add(1);
            }
            Some("turn.completed") => {
                let usage = event.get("usage").ok_or(())?;
                let field = |name: &str| -> Result<u64, ()> {
                    match usage.get(name) {
                        None => Ok(0),
                        Some(value) => value.as_u64().ok_or(()),
                    }
                };
                summary.last_usage = Some(StreamUsage {
                    input_tokens: field("input_tokens")?,
                    output_tokens: field("output_tokens")?,
                    cached_input_tokens: field("cached_input_tokens")?,
                    reasoning_output_tokens: field("reasoning_output_tokens")?,
                });
            }
            Some("item.completed") => {
                let Some(item) = event.get("item") else {
                    continue;
                };
                if item.get("type").and_then(serde_json::Value::as_str) != Some("error") {
                    continue;
                }
                if let Some(reroute) = item
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .and_then(parse_reroute_message)
                {
                    summary.reroute = Some(reroute);
                }
            }
            _ => {}
        }
    }
    Ok(summary)
}

/// Parses `model rerouted: <from> -> <to> (...)`. Only the exact upstream shape is accepted.
fn parse_reroute_message(message: &str) -> Option<CodexServerRerouteEvidence> {
    let rest = message.strip_prefix(CODEX_REROUTE_MESSAGE_PREFIX)?;
    let (from, rest) = rest.split_once(CODEX_REROUTE_MESSAGE_ARROW)?;
    let to = rest
        .split([' ', '\n', '\r', '\t'])
        .next()
        .unwrap_or_default()
        .trim_end_matches(['.', ',', ';']);
    let from = from.trim();
    if from.is_empty() || to.is_empty() || from.contains(char::is_whitespace) {
        return None;
    }
    Some(CodexServerRerouteEvidence {
        from: from.to_string(),
        to: to.to_string(),
    })
}

#[derive(Debug)]
struct RolloutResolution {
    model: CodexParentResolvedField,
    effort: CodexParentResolvedField,
    failure: Option<CodexParentResolutionStatus>,
}

impl RolloutResolution {
    fn failed(status: CodexParentResolutionStatus) -> Self {
        Self {
            model: CodexParentResolvedField::Unknown,
            effort: CodexParentResolvedField::Unknown,
            failure: Some(status),
        }
    }
}

fn resolve_rollout(
    inputs: &CodexParentEvidenceInputs<'_>,
    thread_id: &str,
    files: &[CollectedRegularFile],
) -> RolloutResolution {
    let rollouts = files
        .iter()
        .filter(|file| rollout_file_thread_id(&file.relative_path).is_some())
        .collect::<Vec<_>>();
    if rollouts.is_empty() {
        return RolloutResolution::failed(CodexParentResolutionStatus::RolloutMissing);
    }
    let matching = rollouts
        .iter()
        .filter(|file| rollout_file_thread_id(&file.relative_path) == Some(thread_id))
        .collect::<Vec<_>>();
    let rollout = match matching.as_slice() {
        [] => return RolloutResolution::failed(CodexParentResolutionStatus::ThreadIdMismatch),
        [single] => **single,
        _ => return RolloutResolution::failed(CodexParentResolutionStatus::Ambiguous),
    };
    let Ok(parsed) = parse_rollout(&rollout.bytes) else {
        return RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid);
    };
    let Some(meta) = parsed.session_meta else {
        return RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid);
    };
    if meta.id.as_deref() != Some(thread_id) {
        return RolloutResolution::failed(CodexParentResolutionStatus::ThreadIdMismatch);
    }
    if meta.cwd.as_deref().map(Path::new) != Some(inputs.cwd) {
        return RolloutResolution::failed(CodexParentResolutionStatus::Ambiguous);
    }
    if parsed.turn_contexts.is_empty() {
        return RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid);
    }
    let model = uniform_value(
        parsed
            .turn_contexts
            .iter()
            .map(|turn| turn.model.as_deref()),
    );
    let effort = uniform_value(
        parsed
            .turn_contexts
            .iter()
            .map(|turn| turn.effort.as_deref()),
    );
    let mut failure = None;
    if model.known().is_none() || effort.known().is_none() {
        failure = Some(CodexParentResolutionStatus::Ambiguous);
    }
    if let (Some(expected), Some(actual)) = (inputs.codex_version, meta.cli_version.as_deref()) {
        if actual.trim().trim_start_matches('v') != format_version(expected) {
            failure = Some(failure.map_or(
                CodexParentResolutionStatus::VersionMismatch,
                |existing: CodexParentResolutionStatus| {
                    existing.min(CodexParentResolutionStatus::VersionMismatch)
                },
            ));
        }
    }
    RolloutResolution {
        model,
        effort,
        failure,
    }
}

/// Known only when every `turn_context` carries the same non-empty value.
fn uniform_value<'a>(values: impl Iterator<Item = Option<&'a str>>) -> CodexParentResolvedField {
    let mut uniform: Option<&str> = None;
    for value in values {
        match value {
            Some(value) if !value.is_empty() => match uniform {
                None => uniform = Some(value),
                Some(existing) if existing == value => {}
                Some(_) => return CodexParentResolvedField::Unknown,
            },
            _ => return CodexParentResolvedField::Unknown,
        }
    }
    uniform.map_or(CodexParentResolvedField::Unknown, |value| {
        CodexParentResolvedField::Known(value.to_string())
    })
}

/// Extracts `<thread_id>` from `rollout-<YYYY-MM-DDTHH-MM-SS>-<thread_id>.jsonl`.
fn rollout_file_thread_id(relative_path: &Path) -> Option<&str> {
    let name = relative_path.file_name()?.to_str()?;
    let stem = name
        .strip_prefix(CODEX_ROLLOUT_PREFIX)?
        .strip_suffix(CODEX_ROLLOUT_SUFFIX)?;
    if stem.len() <= CODEX_ROLLOUT_TIMESTAMP_LEN + 1
        || !stem.is_char_boundary(CODEX_ROLLOUT_TIMESTAMP_LEN)
    {
        return None;
    }
    let (timestamp, rest) = stem.split_at(CODEX_ROLLOUT_TIMESTAMP_LEN);
    let timestamp_shape = timestamp
        .bytes()
        .enumerate()
        .all(|(index, byte)| match index {
            4 | 7 | 13 | 16 => byte == b'-',
            10 => byte == b'T',
            _ => byte.is_ascii_digit(),
        });
    if !timestamp_shape {
        return None;
    }
    let thread_id = rest.strip_prefix('-')?;
    (!thread_id.is_empty()).then_some(thread_id)
}

#[derive(Debug, Default)]
struct RolloutSummary {
    session_meta: Option<RolloutSessionMeta>,
    turn_contexts: Vec<RolloutTurnContext>,
}

#[derive(Debug, Default)]
struct RolloutSessionMeta {
    id: Option<String>,
    cwd: Option<String>,
    cli_version: Option<String>,
}

#[derive(Debug, Default)]
struct RolloutTurnContext {
    model: Option<String>,
    effort: Option<String>,
}

/// Summarizes a rollout. Only `session_meta` and `turn_context` lines are interpreted; every
/// line must still be valid JSON so a truncated or corrupted rollout fails closed.
fn parse_rollout(bytes: &[u8]) -> Result<RolloutSummary, ()> {
    let contents = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut summary = RolloutSummary::default();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).map_err(|_| ())?;
        let payload = event.get("payload");
        let string_field = |name: &str| -> Option<String> {
            payload
                .and_then(|payload| payload.get(name))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("session_meta") => {
                if summary.session_meta.is_some() {
                    return Err(());
                }
                summary.session_meta = Some(RolloutSessionMeta {
                    id: string_field("id"),
                    cwd: string_field("cwd"),
                    cli_version: string_field("cli_version"),
                });
            }
            Some("turn_context") => {
                let model = string_field("model");
                if model.is_none() {
                    return Err(());
                }
                summary.turn_contexts.push(RolloutTurnContext {
                    model,
                    effort: string_field("effort"),
                });
            }
            _ => {}
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(cwd: &'a Path) -> CodexParentEvidenceInputs<'a> {
        CodexParentEvidenceInputs {
            codex_version: Some((0, 144, 4)),
            cwd,
            requested_model: Some("gpt-5-codex"),
            requested_effort: Some("high"),
        }
    }

    fn stream(lines: &[&str]) -> ExecStreamSummary {
        parse_exec_stream(lines.join("\n").as_bytes()).expect("valid stream")
    }

    fn rollout_file(name: &str, lines: &[&str]) -> CollectedRegularFile {
        CollectedRegularFile {
            relative_path: Path::new("sessions/2026/09/19").join(name),
            bytes: format!("{}\n", lines.join("\n")).into_bytes(),
        }
    }

    const THREAD: &str = "0199a4b3-7f1e-7c2a-9d0e-3f4a5b6c7d8e";
    const ROLLOUT_NAME: &str =
        "rollout-2026-09-19T07-00-00-0199a4b3-7f1e-7c2a-9d0e-3f4a5b6c7d8e.jsonl";

    fn session_meta(cwd: &Path) -> String {
        format!(
            r#"{{"timestamp":"2026-09-19T07:00:00.000Z","type":"session_meta","payload":{{"id":"{THREAD}","timestamp":"2026-09-19T07:00:00.000Z","cwd":"{}","originator":"codex_exec","cli_version":"0.144.4","source":"exec"}}}}"#,
            cwd.display()
        )
    }

    fn turn_context(cwd: &Path, model: &str, effort: Option<&str>) -> String {
        let effort = effort.map_or("null".to_string(), |effort| format!("\"{effort}\""));
        format!(
            r#"{{"timestamp":"2026-09-19T07:00:01.000Z","type":"turn_context","payload":{{"turn_id":"turn-1","cwd":"{}","approval_policy":"never","sandbox_policy":{{"type":"workspace-write"}},"model":"{model}","effort":{effort},"summary":"auto"}}}}"#,
            cwd.display()
        )
    }

    #[test]
    fn exec_stream_summary_reads_thread_usage_failures_and_reroutes() {
        let summary = stream(&[
            r#"{"type":"thread.started","thread_id":"t-1"}"#,
            r#"{"type":"turn.started"}"#,
            r#"{"type":"item.completed","item":{"id":"item_0","type":"error","message":"model rerouted: gpt-5-codex -> gpt-5-codex-mini (server capacity)"}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":6,"reasoning_output_tokens":2}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":30,"cached_input_tokens":8,"output_tokens":12,"reasoning_output_tokens":5}}"#,
        ]);
        assert_eq!(summary.thread_started, 1);
        assert_eq!(summary.thread_id.as_deref(), Some("t-1"));
        assert_eq!(summary.turn_failed, 0);
        assert_eq!(
            summary.last_usage,
            Some(StreamUsage {
                input_tokens: 30,
                output_tokens: 12,
                cached_input_tokens: 8,
                reasoning_output_tokens: 5,
            })
        );
        assert_eq!(
            summary.reroute,
            Some(CodexServerRerouteEvidence {
                from: "gpt-5-codex".to_string(),
                to: "gpt-5-codex-mini".to_string(),
            })
        );

        let failed = stream(&[
            r#"{"type":"thread.started","thread_id":"t-1"}"#,
            r#"{"type":"turn.failed","error":{"message":"boom"}}"#,
        ]);
        assert_eq!(failed.turn_failed, 1);
        assert!(parse_exec_stream(b"{\"type\":\"thread.started\"\n").is_err());
        assert!(parse_exec_stream(b"\xff\xfe").is_err());
        assert!(
            parse_exec_stream(br#"{"type":"turn.completed","usage":{"input_tokens":"ten"}}"#)
                .is_err()
        );
    }

    #[test]
    fn reroute_message_requires_the_exact_upstream_shape() {
        assert_eq!(
            parse_reroute_message("model rerouted: a -> b"),
            Some(CodexServerRerouteEvidence {
                from: "a".to_string(),
                to: "b".to_string(),
            })
        );
        assert_eq!(
            parse_reroute_message("model rerouted: a -> b (quota exhausted)."),
            Some(CodexServerRerouteEvidence {
                from: "a".to_string(),
                to: "b".to_string(),
            })
        );
        assert_eq!(parse_reroute_message("rerouted: a -> b"), None);
        assert_eq!(parse_reroute_message("model rerouted: a b -> c"), None);
        assert_eq!(parse_reroute_message("model rerouted: a -> "), None);
    }

    #[test]
    fn rollout_file_names_yield_their_thread_id() {
        assert_eq!(
            rollout_file_thread_id(Path::new(&format!("sessions/2026/09/19/{ROLLOUT_NAME}"))),
            Some(THREAD)
        );
        assert_eq!(
            rollout_file_thread_id(Path::new("rollout-2026-09-19T07-00-00-thread-1.jsonl")),
            Some("thread-1")
        );
        assert_eq!(
            rollout_file_thread_id(Path::new("rollout-2026-09-19T07-00-00-.jsonl")),
            None
        );
        assert_eq!(
            rollout_file_thread_id(Path::new("rollout-2026-09-19-07-00-00-thread.jsonl")),
            None
        );
        assert_eq!(rollout_file_thread_id(Path::new("history.jsonl")), None);
        assert_eq!(
            rollout_file_thread_id(Path::new("rollout-2026-09-19T07-00-00-thread.json")),
            None
        );
    }

    #[test]
    fn complete_evidence_requires_matching_rollout_and_nonzero_usage() {
        let cwd = Path::new("/work/tree");
        let inputs = inputs(cwd);
        let stream = stream(&[
            format!(r#"{{"type":"thread.started","thread_id":"{THREAD}"}}"#).as_str(),
            r#"{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":40,"output_tokens":20,"reasoning_output_tokens":7}}"#,
        ]);
        let files = vec![rollout_file(
            ROLLOUT_NAME,
            &[
                &session_meta(cwd),
                &turn_context(cwd, "gpt-5-codex", Some("high")),
                &turn_context(cwd, "gpt-5-codex", Some("high")),
            ],
        )];
        let rollout = resolve_rollout(&inputs, THREAD, &files);
        let evidence = assemble_evidence(&inputs, Ok(stream), rollout);
        assert_eq!(
            evidence,
            CodexParentEvidence {
                codex_version: Some("0.144.4".to_string()),
                thread_id: Some(THREAD.to_string()),
                requested_model: Some("gpt-5-codex".to_string()),
                requested_effort: Some("high".to_string()),
                rollout_model: CodexParentResolvedField::Known("gpt-5-codex".to_string()),
                rollout_effort: CodexParentResolvedField::Known("high".to_string()),
                observed_model: CodexParentResolvedField::Known("gpt-5-codex".to_string()),
                observed_effort: CodexParentResolvedField::Known("high".to_string()),
                server_rerouted_model: None,
                model_mismatch: false,
                turn_usage: CodexParentTurnUsage::Known {
                    input_tokens: 100,
                    output_tokens: 20,
                    cached_input_tokens: 40,
                    reasoning_output_tokens: 7,
                },
                resolution_status: "complete".to_string(),
            }
        );
    }

    #[test]
    fn rollout_resolution_reports_each_failure_with_unknown_fields() {
        let cwd = Path::new("/work/tree");
        let inputs = inputs(cwd);
        let good = |effort| turn_context(cwd, "gpt-5-codex", effort);

        let missing = resolve_rollout(&inputs, THREAD, &[]);
        assert_eq!(
            missing.failure,
            Some(CodexParentResolutionStatus::RolloutMissing)
        );
        assert_eq!(missing.model, CodexParentResolvedField::Unknown);

        let history_only = vec![CollectedRegularFile {
            relative_path: Path::new("sessions/history.jsonl").to_path_buf(),
            bytes: b"{}\n".to_vec(),
        }];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &history_only).failure,
            Some(CodexParentResolutionStatus::RolloutMissing)
        );

        let other_thread = vec![rollout_file(
            "rollout-2026-09-19T07-00-00-other-thread.jsonl",
            &[&session_meta(cwd), &good(Some("high"))],
        )];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &other_thread).failure,
            Some(CodexParentResolutionStatus::ThreadIdMismatch)
        );

        let duplicated = vec![
            rollout_file(ROLLOUT_NAME, &[&session_meta(cwd), &good(Some("high"))]),
            CollectedRegularFile {
                relative_path: Path::new("sessions/2026/09/18").join(ROLLOUT_NAME),
                bytes: format!("{}\n{}\n", session_meta(cwd), good(Some("high"))).into_bytes(),
            },
        ];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &duplicated).failure,
            Some(CodexParentResolutionStatus::Ambiguous)
        );

        let meta_mismatch = vec![rollout_file(
            ROLLOUT_NAME,
            &[
                &session_meta(cwd).replace(THREAD, "someone-else"),
                &good(Some("high")),
            ],
        )];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &meta_mismatch).failure,
            Some(CodexParentResolutionStatus::ThreadIdMismatch)
        );

        let foreign_cwd = vec![rollout_file(
            ROLLOUT_NAME,
            &[
                &session_meta(Path::new("/elsewhere")),
                &turn_context(Path::new("/elsewhere"), "gpt-5-codex", Some("high")),
            ],
        )];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &foreign_cwd).failure,
            Some(CodexParentResolutionStatus::Ambiguous)
        );

        let no_effort = resolve_rollout(
            &inputs,
            THREAD,
            &[rollout_file(
                ROLLOUT_NAME,
                &[&session_meta(cwd), &good(None)],
            )],
        );
        assert_eq!(
            no_effort.failure,
            Some(CodexParentResolutionStatus::Ambiguous)
        );
        assert_eq!(
            no_effort.model,
            CodexParentResolvedField::Known("gpt-5-codex".to_string())
        );
        assert_eq!(no_effort.effort, CodexParentResolvedField::Unknown);

        let two_models = resolve_rollout(
            &inputs,
            THREAD,
            &[rollout_file(
                ROLLOUT_NAME,
                &[
                    &session_meta(cwd),
                    &good(Some("high")),
                    &turn_context(cwd, "gpt-5-codex-mini", Some("high")),
                ],
            )],
        );
        assert_eq!(
            two_models.failure,
            Some(CodexParentResolutionStatus::Ambiguous)
        );
        assert_eq!(two_models.model, CodexParentResolvedField::Unknown);
        assert_eq!(
            two_models.effort,
            CodexParentResolvedField::Known("high".to_string())
        );

        let version_drift = resolve_rollout(
            &inputs,
            THREAD,
            &[rollout_file(
                ROLLOUT_NAME,
                &[
                    &session_meta(cwd).replace("0.144.4", "0.145.0"),
                    &good(Some("high")),
                ],
            )],
        );
        assert_eq!(
            version_drift.failure,
            Some(CodexParentResolutionStatus::VersionMismatch)
        );
        assert_eq!(
            version_drift.model,
            CodexParentResolvedField::Known("gpt-5-codex".to_string())
        );
        let unknown_probe = CodexParentEvidenceInputs {
            codex_version: None,
            ..inputs
        };
        assert_eq!(
            resolve_rollout(
                &unknown_probe,
                THREAD,
                &[rollout_file(
                    ROLLOUT_NAME,
                    &[
                        &session_meta(cwd).replace("0.144.4", "0.145.0"),
                        &good(Some("high")),
                    ],
                )],
            )
            .failure,
            None,
            "version comparison needs both sides known"
        );

        let no_session_meta = vec![rollout_file(ROLLOUT_NAME, &[&good(Some("high"))])];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &no_session_meta).failure,
            Some(CodexParentResolutionStatus::JsonlInvalid)
        );
        let no_turn_context = vec![rollout_file(ROLLOUT_NAME, &[&session_meta(cwd)])];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &no_turn_context).failure,
            Some(CodexParentResolutionStatus::JsonlInvalid)
        );
        let corrupt = vec![rollout_file(
            ROLLOUT_NAME,
            &[&session_meta(cwd), "{\"type\":\"turn_context\""],
        )];
        assert_eq!(
            resolve_rollout(&inputs, THREAD, &corrupt).failure,
            Some(CodexParentResolutionStatus::JsonlInvalid)
        );
    }

    #[test]
    fn stream_failures_take_priority_and_reroutes_define_the_observed_model() {
        let cwd = Path::new("/work/tree");
        let inputs = inputs(cwd);
        let rollout = || {
            resolve_rollout(
                &inputs,
                THREAD,
                &[rollout_file(
                    ROLLOUT_NAME,
                    &[
                        &session_meta(cwd),
                        &turn_context(cwd, "gpt-5-codex", Some("high")),
                    ],
                )],
            )
        };
        let started = format!(r#"{{"type":"thread.started","thread_id":"{THREAD}"}}"#);

        let failed = assemble_evidence(
            &inputs,
            Ok(stream(&[
                &started,
                r#"{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":5}}"#,
                r#"{"type":"turn.failed","error":{"message":"boom"}}"#,
            ])),
            rollout(),
        );
        assert_eq!(failed.resolution_status, "turn_failed");
        assert_eq!(
            failed.rollout_model,
            CodexParentResolvedField::Known("gpt-5-codex".to_string())
        );
        assert!(matches!(
            failed.turn_usage,
            CodexParentTurnUsage::Unknown { .. }
        ));

        let zero_usage = assemble_evidence(
            &inputs,
            Ok(stream(&[
                &started,
                r#"{"type":"turn.completed","usage":{"input_tokens":0,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}}"#,
            ])),
            rollout(),
        );
        assert_eq!(zero_usage.resolution_status, "usage_unavailable");
        assert!(matches!(
            zero_usage.turn_usage,
            CodexParentTurnUsage::Unknown { .. }
        ));
        assert_eq!(
            zero_usage.observed_effort,
            CodexParentResolvedField::Known("high".to_string())
        );

        let no_turn = assemble_evidence(&inputs, Ok(stream(&[&started])), rollout());
        assert_eq!(no_turn.resolution_status, "usage_unavailable");

        let two_threads = assemble_evidence(
            &inputs,
            Ok(stream(&[
                &started,
                &started,
                r#"{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":5}}"#,
            ])),
            rollout(),
        );
        assert_eq!(two_threads.resolution_status, "jsonl_invalid");

        let invalid = assemble_evidence(
            &inputs,
            Err(()),
            RolloutResolution::failed(CodexParentResolutionStatus::JsonlInvalid),
        );
        assert_eq!(invalid.resolution_status, "jsonl_invalid");
        assert_eq!(invalid.thread_id, None);
        assert_eq!(invalid.observed_model, CodexParentResolvedField::Unknown);
        assert!(!invalid.model_mismatch);

        let rerouted = assemble_evidence(
            &inputs,
            Ok(stream(&[
                &started,
                r#"{"type":"item.completed","item":{"id":"item_0","type":"error","message":"model rerouted: gpt-5-codex -> gpt-5-codex-mini (capacity)"}}"#,
                r#"{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":5}}"#,
            ])),
            rollout(),
        );
        assert_eq!(rerouted.resolution_status, "complete");
        assert_eq!(
            rerouted.rollout_model,
            CodexParentResolvedField::Known("gpt-5-codex".to_string())
        );
        assert_eq!(
            rerouted.observed_model,
            CodexParentResolvedField::Known("gpt-5-codex-mini".to_string())
        );
        assert_eq!(
            rerouted.server_rerouted_model,
            Some(CodexServerRerouteEvidence {
                from: "gpt-5-codex".to_string(),
                to: "gpt-5-codex-mini".to_string(),
            })
        );
        assert!(rerouted.model_mismatch);

        let rollout_gone = assemble_evidence(
            &inputs,
            Ok(stream(&[
                &started,
                r#"{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":5}}"#,
            ])),
            RolloutResolution::failed(CodexParentResolutionStatus::RolloutMissing),
        );
        assert_eq!(rollout_gone.resolution_status, "rollout_missing");
        assert_eq!(
            rollout_gone.observed_model,
            CodexParentResolvedField::Unknown
        );
        assert_eq!(
            rollout_gone.turn_usage,
            CodexParentTurnUsage::Known {
                input_tokens: 5,
                output_tokens: 5,
                cached_input_tokens: 0,
                reasoning_output_tokens: 0,
            }
        );
    }

    #[test]
    fn wire_round_trip_preserves_known_unknown_and_usage_variants() {
        let evidence = CodexParentEvidence {
            codex_version: None,
            thread_id: Some("t".to_string()),
            requested_model: None,
            requested_effort: Some("xhigh".to_string()),
            rollout_model: CodexParentResolvedField::Known("gpt-5-codex".to_string()),
            rollout_effort: CodexParentResolvedField::Unknown,
            observed_model: CodexParentResolvedField::Known("gpt-5-codex-mini".to_string()),
            observed_effort: CodexParentResolvedField::Unknown,
            server_rerouted_model: Some(CodexServerRerouteEvidence {
                from: "gpt-5-codex".to_string(),
                to: "gpt-5-codex-mini".to_string(),
            }),
            model_mismatch: false,
            turn_usage: CodexParentTurnUsage::Unknown {
                reason: "no usage".to_string(),
            },
            resolution_status: "ambiguous".to_string(),
        };
        let json = serde_json::to_value(&evidence).expect("serialize");
        assert_eq!(
            json["rollout_model"],
            serde_json::json!({"known": "gpt-5-codex"})
        );
        assert_eq!(json["rollout_effort"], serde_json::json!("unknown"));
        assert_eq!(
            json["turn_usage"],
            serde_json::json!({"status": "unknown", "reason": "no usage"})
        );
        let restored: CodexParentEvidence = serde_json::from_value(json).expect("deserialize");
        assert_eq!(restored, evidence);
        assert!(serde_json::from_str::<CodexParentEvidence>(
            r#"{"codex_version":null,"thread_id":null,"requested_model":null,"requested_effort":null,"rollout_model":"unknown","rollout_effort":"unknown","observed_model":"unknown","observed_effort":"unknown","server_rerouted_model":null,"model_mismatch":false,"turn_usage":{"status":"unknown","reason":"x"},"resolution_status":"complete","extra":1}"#
        )
        .is_err());
        for status in CodexParentResolutionStatus::LABELS {
            assert!(!status.is_empty());
        }
    }
}
