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
