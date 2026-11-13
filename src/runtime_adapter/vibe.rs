//! Pure helpers for the Vibe CLI runtime adapter.
//!
//! This module owns only the immutable launch contract, the generated config
//! document, and the two bounded parsers the supervisor needs: the export
//! `usage` block and the final assistant message from the NDJSON stream. It
//! deliberately contains no process spawning, no environment access, and no
//! runtime selection; those live with the adapter that owns the enum.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Maximum accepted size of the export root document (4 MiB).
const MAX_USAGE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum accepted size of the NDJSON stream (8 MiB).
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum accepted number of NDJSON lines.
const MAX_STREAM_LINES: usize = 100_000;
/// Maximum accepted size of the joined final assistant text (256 KiB).
const MAX_FINAL_TEXT_BYTES: usize = 256 * 1024;
/// Maximum accepted length of a provider model id.
const MAX_MODEL_ID_LEN: usize = 256;
/// Maximum accepted length of the export `outcome` string.
const MAX_OUTCOME_BYTES: usize = 64;

/// Immutable argv template for a managed Vibe turn.
///
/// Placeholders are substituted by the caller: `{cwd}`, `{model}`,
/// `{vibe_output_dir}`, and `{prompt}`. Every `--enabled-tools` flag is
/// repeated once per tool because the CLI accumulates them.
pub(crate) fn immutable_argument_template() -> Vec<String> {
    [
        "--workdir",
        "{cwd}",
        "--trust",
        "--model",
        "{model}",
        "--agent",
        "auto-approve",
        "--auto-approve",
        "--enabled-tools",
        "bash",
        "--enabled-tools",
        "read_file",
        "--enabled-tools",
        "write_file",
        "--enabled-tools",
        "edit",
        "--max-turns",
        "200",
        "--max-tokens",
        "10000000",
        "--time-limit",
        "3600",
        "--output",
        "streaming",
        "--output-dir",
        "{vibe_output_dir}",
        "--prompt-file",
        "{prompt}",
    ]
    .iter()
    .map(|argument| (*argument).to_string())
    .collect()
}

/// Restrict already authenticated native argv for an automatic journal Worker.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn journaled_worker_arguments(arguments: &mut Vec<std::ffi::OsString>) {
    let mut index = 0;
    while index + 1 < arguments.len() {
        if arguments[index] == "--enabled-tools"
            && matches!(arguments[index + 1].to_str(), Some("write_file" | "edit"))
        {
            arguments.drain(index..index + 2);
        } else {
            index += 1;
        }
    }
}

/// The maximum equals the existing --time-limit 3600 of the Vibe argv template;
/// Vibe accepts a default above 300 only when both keys are set.
pub(crate) const JOURNALED_BASH_DEFAULT_TIMEOUT_SECONDS: u32 = 1800;
pub(crate) const JOURNALED_BASH_MAX_TIMEOUT_SECONDS: u32 = 3600;

/// Encode the held per-attempt shell path as TOML data, never shell source.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn journaled_config_document(model: &str, shell: &Path) -> Result<String> {
    let shell = shell
        .to_str()
        .context("Vibe journal shell requires a UTF-8 path")?;
    let quoted = serde_json::to_string(shell)?;
    Ok(format!(
        "{}
[tools.bash]
default_timeout = {}
max_timeout_seconds = {}
shell = {quoted}
",
        config_document(model)?,
        JOURNALED_BASH_DEFAULT_TIMEOUT_SECONDS,
        JOURNALED_BASH_MAX_TIMEOUT_SECONDS,
    ))
}

/// Directory the CLI writes its export into for a given output directory.
///
/// The export is a sibling of the output directory, named after it with a
/// `.vibe-export` suffix, so the parent is preserved.
pub(crate) fn export_directory(output: &Path) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".vibe-export");
    match output.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// Validate a provider model id before it is placed in argv or the config.
///
/// The id must be a non-empty, bounded, plain provider identifier: ASCII
/// alphanumerics plus `-`, `_`, `.`, and `/`. Traversal segments, wildcards,
/// and regex prefixes are rejected. Availability is not inferred here.
pub(crate) fn validate_model(model: Option<&str>) -> Result<&str> {
    let Some(model) = model else {
        bail!("vibe model id is required");
    };
    if model.is_empty() {
        bail!("vibe model id must not be empty");
    }
    if model.len() > MAX_MODEL_ID_LEN {
        bail!("vibe model id exceeds {MAX_MODEL_ID_LEN} bytes");
    }
    if !model
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        bail!("vibe model id contains unsupported characters: {model:?}");
    }
    if model.split('/').any(|segment| segment == "..") || model.contains("..") {
        bail!("vibe model id must not contain path traversal: {model:?}");
    }
    if model.starts_with('.') || model.starts_with('/') || model.ends_with('/') {
        bail!("vibe model id must be a relative identifier: {model:?}");
    }
    Ok(model)
}

/// Generated Vibe config document for a single managed model.
///
/// The document pins one model, disables every optional subsystem that could
/// reach the network or spawn background work, and routes utility models back
/// to the active model. It carries no credential and no cost field.
pub(crate) fn config_document(model: &str) -> Result<String> {
    let model = validate_model(Some(model))?;
    let quoted = serde_json::to_string(model).context("quote vibe model id")?;
    let document = format!(
        "\
active_model = {quoted}
allowed_models = [{quoted}]
enable_subagents = false
enable_mcp = false
enable_connectors = false
enable_telemetry = false
enable_otel = false
enable_update_checks = false
enable_auto_update = false
enable_background_processes = false
mcp_servers = []
connectors = []

[session_logging]
generate_titles = false

[utility_models]
title = \"active\"
smart_approve = \"active\"

[[models]]
name = {quoted}
alias = {quoted}
provider = \"mistral\"
"
    );
    Ok(document)
}

/// Token counters reported by the Vibe export.
///
/// `cached_input_tokens` is a subset of `input_tokens`; it is never added to
/// the totals. Export prices do not establish actual cost, which stays unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VibeUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Deserialize)]
struct UsageBlock {
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    total_tokens: u64,
}

#[derive(Deserialize)]
struct ExportRoot {
    usage: UsageBlock,
}

/// Parse the `usage` block out of the bounded export root document.
///
/// All four counters are required and must be non-negative integers. The
/// cached count must be a subset of the input count, and input plus output
/// must equal the reported total. Any `cost_usd` field is ignored: the value
/// is unknown to this adapter even when it is zero.
pub(crate) fn parse_usage(bytes: &[u8]) -> Result<VibeUsage> {
    if bytes.len() > MAX_USAGE_BYTES {
        bail!(
            "vibe export exceeds {MAX_USAGE_BYTES} bytes: {} bytes",
            bytes.len()
        );
    }
    let root: ExportRoot =
        serde_json::from_slice(bytes).context("parse vibe export root document")?;
    let usage = root.usage;
    if usage.cached_input_tokens > usage.input_tokens {
        bail!(
            "vibe export cached_input_tokens {} exceeds input_tokens {}",
            usage.cached_input_tokens,
            usage.input_tokens
        );
    }
    let expected_total = usage
        .input_tokens
        .checked_add(usage.output_tokens)
        .context("vibe export token counters overflow u64")?;
    if expected_total != usage.total_tokens {
        bail!(
            "vibe export total_tokens {} does not equal input_tokens {} + output_tokens {}",
            usage.total_tokens,
            usage.input_tokens,
            usage.output_tokens
        );
    }
    Ok(VibeUsage {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cached_input_tokens: usage.cached_input_tokens,
        total_tokens: usage.total_tokens,
    })
}

#[derive(Deserialize)]
struct OutcomeRoot {
    #[serde(default)]
    outcome: Option<String>,
}

/// Parse the top-level `outcome` string out of the bounded export root document.
///
/// Returns `Some` only when the document is within [`MAX_USAGE_BYTES`], parses,
/// and the outcome is a bounded string of ASCII lowercase letters and
/// underscores. Any other shape, including a missing or non-string outcome,
/// returns `None`; the caller then keeps its conservative handling.
pub(crate) fn parse_outcome(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_USAGE_BYTES {
        return None;
    }
    let root: OutcomeRoot = serde_json::from_slice(bytes).ok()?;
    let outcome = root.outcome?;
    if outcome.len() > MAX_OUTCOME_BYTES
        || !outcome
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return None;
    }
    Some(outcome)
}

/// The value that follows `flag` in the immutable argv template, if present.
fn template_argument(flag: &str) -> Option<String> {
    let template = immutable_argument_template();
    template
        .iter()
        .position(|argument| argument == flag)
        .and_then(|index| template.get(index + 1))
        .cloned()
}

/// Name the Vibe limit stop for the attempt's error.
///
/// Vibe ends a headless run on one of its own limits with process exit status
/// 3 while still writing its export; the seven outcomes below are those
/// limits. The launch numbers come from the immutable argv template instead of
/// duplicated literals. Any other outcome returns `None`.
pub(crate) fn stop_message(outcome: &str) -> Option<String> {
    if !matches!(
        outcome,
        "turn_limit"
            | "token_limit"
            | "price_limit"
            | "deadline"
            | "terminated"
            | "length"
            | "refusal"
    ) {
        return None;
    }
    let max_turns = template_argument("--max-turns")?;
    let max_tokens = template_argument("--max-tokens")?;
    let time_limit = template_argument("--time-limit")?;
    Some(format!(
        "Vibe stopped without finishing: run outcome {outcome}; MACO launches Vibe with --max-turns {max_turns}, --max-tokens {max_tokens} and --time-limit {time_limit}"
    ))
}

#[derive(Deserialize)]
struct StreamEntry {
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default, rename = "generationStatus")]
    generation_status: Option<String>,
    #[serde(default)]
    content: Option<Vec<ContentBlock>>,
    #[serde(default)]
    outcome: Option<Outcome>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct Outcome {
    #[serde(rename = "type")]
    outcome_type: String,
}

/// Extract the last completed assistant message from the NDJSON stream.
///
/// The stream must be newline-terminated so a truncated tail is rejected
/// rather than silently dropped. Every non-empty line must be a JSON object.
/// Only public `message` entries with role `assistant` and status `completed`
/// are considered; discarded outcomes, user turns, tool calls, effects, and
/// reasoning entries are ignored. Text blocks are joined with two newlines.
pub(crate) fn final_assistant_text(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_STREAM_BYTES {
        bail!(
            "vibe stream exceeds {MAX_STREAM_BYTES} bytes: {} bytes",
            bytes.len()
        );
    }
    if bytes.is_empty() {
        bail!("vibe stream is empty");
    }
    if !bytes.ends_with(b"\n") {
        bail!("vibe stream is not newline-terminated; output may be truncated");
    }

    let mut final_text: Option<String> = None;
    let mut line_count = 0usize;
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > MAX_STREAM_LINES {
            bail!("vibe stream exceeds {MAX_STREAM_LINES} lines");
        }
        let entry: StreamEntry = serde_json::from_slice(line)
            .with_context(|| format!("parse vibe stream line {}", index + 1))?;
        if entry.entry_type != "message" {
            continue;
        }
        if entry.role.as_deref() != Some("assistant") {
            continue;
        }
        if entry.generation_status.as_deref() != Some("completed") {
            continue;
        }
        if entry
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.outcome_type == "discarded")
        {
            continue;
        }
        let Some(content) = entry.content else {
            continue;
        };
        let mut blocks: Vec<&str> = Vec::new();
        for block in &content {
            if block.block_type != "text" {
                continue;
            }
            let Some(text) = block.text.as_deref() else {
                continue;
            };
            if text.is_empty() {
                continue;
            }
            blocks.push(text);
        }
        if blocks.is_empty() {
            continue;
        }
        final_text = Some(blocks.join("\n\n"));
    }

    let Some(text) = final_text else {
        bail!("vibe stream contains no completed assistant message");
    };
    if text.len() > MAX_FINAL_TEXT_BYTES {
        bail!(
            "vibe final assistant text exceeds {MAX_FINAL_TEXT_BYTES} bytes: {} bytes",
            text.len()
        );
    }
    Ok(text)
}

#[cfg(test)]
#[path = "vibe_tests.rs"]
mod tests;
