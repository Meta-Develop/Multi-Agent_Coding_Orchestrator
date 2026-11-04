//! DeepSeek Harness (`dsh`) headless launch and NDJSON projection.
//!
//! Protocol pin: deepseek-harness **0.2.2-alpha.3** (master `apps/cli`
//! `package.json`, headless README, `docs/cli-help.md`, `json-stream.ts`,
//! `packages/bundle/base/cordis.patch.yml`, session-telemetry-otel,
//! session-log-deepseek, agent-default-model, and llm-deepseek). The published
//! npm package at the time of this contract is `@deepseek-ai/dsh@0.2.1-rc.5`.
//! Those two versions are not interchangeable; live qualification must record
//! `dsh --version` and refuse a headless help/flag mismatch.
//!
//! Integration surface is `dsh --profile headless --json`, not ACP. ACP help is
//! only "serve until the client disconnects" and has no permission or JSON
//! contract. Headless is the documented one-task supervisor contract: exit 0
//! and `final.reason.kind === "completed"`.
//!
//! Headless has no `--model` or `--effort` flag. Model and effort are bound by
//! a MACO-owned `--patch` overlay on `agent-default-model` (`provider:
//! deepseek-official`, the shipped route). Official adapter efforts are
//! `off|low|high|max`. Requested effort is the identity. A served model is
//! accepted only when an event reports one and it matches the request.

use super::{LaunchContext, OutputCaptureMode, RuntimeAdapterConfig};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Documented headless protocol this adapter renders and parses.
pub const PROTOCOL_VERSION: &str = "0.2.2-alpha.3";
/// Installable npm package observed separately from the protocol pin.
pub const PUBLISHED_NPM_VERSION: &str = "0.2.1-rc.5";
pub const PROVIDER_ROUTE: &str = "deepseek-official";

const LINE_MAX_BYTES: usize = 32 * 1024;
const STREAM_MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVENTS: usize = 16 * 1024;
const MAX_STRING_BYTES: usize = 8 * 1024;
const MAX_DEPTH: usize = 64;
const MIN_API_KEY_BYTES: usize = 16;
const MAX_API_KEY_BYTES: usize = 64 * 1024;

/// Stable refusal. The operator flag does not promote production writability.
pub const WRITABLE_ADMISSION_REFUSAL: &str = "writable_deepseek_headless_qualification_required";

/// Writable admission stays closed until `production_qualified` is promoted.
pub fn writable_admission_message(operator_flag_bound: bool, production_qualified: bool) -> String {
    format!(
        "{WRITABLE_ADMISSION_REFUSAL}: operator flag bound: {operator_flag_bound}; production_qualified: {production_qualified}"
    )
}

/// Official DeepSeek adapter efforts (`packages/llm/llm-deepseek`).
pub const EFFORTS: [&str; 4] = ["off", "low", "high", "max"];

pub fn immutable_argument_template() -> Vec<String> {
    [
        "--profile",
        "headless",
        "--patch",
        "{deepseek_patch}",
        "--json",
        "--permission-mode",
        "read-only",
        "--approval-policy",
        "never",
        "--session-id",
        "{session_id}",
        "-",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub fn launch_patch_path(prompt: &Path) -> PathBuf {
    let mut path = prompt.as_os_str().to_os_string();
    path.push(".dsh-launch.patch");
    PathBuf::from(path)
}

pub fn validate_model(model: Option<&str>) -> Result<&str> {
    let model = model.context("DeepSeek launch requires an explicit model id")?;
    let mut chars = model.chars();
    let Some(first) = chars.next() else {
        bail!("DeepSeek model id is empty");
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
        || model.len() > 128
    {
        bail!("DeepSeek model id is not a conservative provider slug");
    }
    Ok(model)
}

pub fn validate_effort(effort: Option<&str>) -> Result<&str> {
    let effort = effort.context("DeepSeek launch requires an explicit reasoning effort")?;
    if !EFFORTS.contains(&effort) {
        bail!(
            "DeepSeek reasoning effort must be one of off, low, high, max; requested {effort:?} is not an official adapter effort"
        );
    }
    Ok(effort)
}

fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty()
        || session_id.len() > 256
        || session_id.starts_with('-')
        || session_id.contains(['\n', '\r', '\0'])
    {
        bail!("DeepSeek --session-id is empty, oversized, or not a single argv element");
    }
    Ok(())
}

pub fn api_key_acceptable(value: &str) -> bool {
    (MIN_API_KEY_BYTES..=MAX_API_KEY_BYTES).contains(&value.len())
        && !value.contains(['\n', '\r', '\0'])
}

/// Privacy environment forced on every launch. The key comes only from the
/// supplied lookup (production passes the launch environment). A missing or
/// rejected key fails closed so headless cannot fall through to `<cwd>/.env`
/// or `$DSH_HOME/.env`.
pub fn privacy_environment(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(&'static str, String)>> {
    let key = lookup("DEEPSEEK_API_KEY").unwrap_or_default();
    if !api_key_acceptable(&key) {
        bail!(
            "DEEPSEEK_API_KEY is missing or rejected; the headless credential chain must not fall through to a workspace or DSH_HOME env file"
        );
    }
    Ok(vec![
        ("DSH_TELEMETRY_DISABLED", "1".to_string()),
        ("DSH_TELEMETRY_MODE", "DISABLED".to_string()),
        ("DEEPSEEK_API_KEY", key),
    ])
}

/// Patch overlay. A dsh patch replaces each targeted row's whole config.
/// Telemetry is disabled and the session-log upload contributor is turned off
/// on every launch. `settings.yaml` does not disable that contributor.
pub fn privacy_patch_document(model: &str, effort: &str) -> Result<String> {
    let model = validate_model(Some(model))?;
    let effort = validate_effort(Some(effort))?;
    let model = yaml_double_quoted(model);
    Ok(format!(
        r#"# MACO DeepSeek headless launch overlay.
# Protocol pin: deepseek-harness {PROTOCOL_VERSION}
# Published npm package is separate: @deepseek-ai/dsh@{PUBLISHED_NPM_VERSION}
- id: session-telemetry-otel
  disabled: true
  config:
    mode: DISABLED
- id: session-log-deepseek
  config:
    enabled: false
    maxBytes: 8388608
- id: agent-default-model
  config:
    provider: {PROVIDER_ROUTE}
    model: {model}
    reasoningEffort: {effort}
- id: permission
  config:
    defaultPreset: read-only
    presets:
      read-only:
        sandbox: read-only
        approval: never
        name: MACO read-only
        description: Sandbox read-only and reject calls that need human approval.
      workspace-write:
        sandbox: workspace-write
        approval: ask
      danger-full-access:
        sandbox: danger-full-access
        approval: never
"#
    ))
}

fn yaml_double_quoted(value: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

pub fn render_read_only_argv(prompt: &Path, session_id: Option<&str>) -> Result<Vec<String>> {
    substitute(&immutable_argument_template(), prompt, session_id)
}

pub(crate) fn substitute(
    template: &[String],
    prompt: &Path,
    session_id: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(session_id) = session_id {
        validate_session_id(session_id)?;
    }
    let patch = launch_patch_path(prompt);
    let patch = patch
        .to_str()
        .context("DeepSeek launch patch path must be UTF-8; lossy argv paths are refused")?
        .to_string();
    if patch.is_empty() {
        bail!("DeepSeek launch patch path is empty");
    }
    let mut argv = Vec::new();
    for token in template {
        match token.as_str() {
            "{deepseek_patch}" => argv.push(patch.clone()),
            "{session_id}" => {
                if let Some(session_id) = session_id {
                    argv.push(session_id.to_string());
                } else if argv.last().is_some_and(|flag| flag == "--session-id") {
                    argv.pop();
                }
            }
            _ => argv.push(token.clone()),
        }
    }
    if argv.iter().any(|arg| arg == "--add-dir") {
        bail!("DeepSeek read-only argv must not grant --add-dir");
    }
    let has_pair = |flag: &str, value: &str| {
        argv.windows(2)
            .any(|pair| pair[0] == flag && pair[1] == value)
    };
    if !has_pair("--patch", patch.as_str())
        || !has_pair("--permission-mode", "read-only")
        || !has_pair("--approval-policy", "never")
        || argv.last().map(String::as_str) != Some("-")
    {
        bail!("DeepSeek read-only argv lost its headless privacy and permission contract");
    }
    Ok(argv)
}

pub fn prepare_launch_patch(prompt: &Path, model: &str, effort: &str) -> Result<PathBuf> {
    let path = launch_patch_path(prompt);
    if !path.is_absolute() {
        bail!(
            "DeepSeek launch patch must be an absolute path under the prompt directory ({})",
            path.display()
        );
    }
    let parent = path
        .parent()
        .context("DeepSeek launch patch has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create DeepSeek launch patch directory {}",
            parent.display()
        )
    })?;
    let document = privacy_patch_document(model, effort)?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("failed to open DeepSeek launch patch {}", path.display()))?;
    file.write_all(document.as_bytes())?;
    file.sync_all()?;
    Ok(path)
}

/// Absolute non-symlink `MACO_DSH_BIN`. There is no PATH fallback and no Nix pin.
pub fn resolve_configured_executable(
    program_override: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    let Some(program) = program_override else {
        bail!(
            "MACO_DSH_BIN must be an absolute path to a non-symlink regular file; ambient PATH and the bare name dsh are refused"
        );
    };
    let program = PathBuf::from(program);
    if !program.is_absolute() {
        bail!(
            "MACO_DSH_BIN must be an absolute path; ambient PATH and relative resolution are refused (requested {})",
            program.display()
        );
    }
    let metadata = fs::symlink_metadata(&program)
        .with_context(|| format!("DeepSeek executable '{}' is missing", program.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "explicit DeepSeek executable may not be a symlink: {}",
            program.display()
        );
    }
    let canonical = fs::canonicalize(&program)
        .with_context(|| format!("DeepSeek executable '{}' is missing", program.display()))?;
    if !canonical.is_file() {
        bail!(
            "DeepSeek executable '{}' is not a regular file",
            canonical.display()
        );
    }
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlyContract {
    pub side_effect_confinement_verified: bool,
    pub session_resume_supported: bool,
    pub admits_worktree_writable: bool,
}

impl ReadOnlyContract {
    pub const fn proved(session_id: Option<&str>) -> Self {
        Self {
            side_effect_confinement_verified: true,
            session_resume_supported: session_id.is_some(),
            admits_worktree_writable: false,
        }
    }
}

pub fn prove_read_only_launch(
    config: &RuntimeAdapterConfig,
    context: &LaunchContext<'_>,
    session_id: Option<&str>,
) -> Result<ReadOnlyContract> {
    validate_model(context.model)?;
    validate_effort(context.effort)?;
    if !context.cwd.is_absolute() || !context.prompt.is_absolute() {
        bail!("DeepSeek read-only launch requires absolute cwd and prompt paths");
    }
    resolve_configured_executable(Some(config.binary_path().as_os_str()))?;
    if config.argument_template != immutable_argument_template()
        || !config.feed_prompt_on_stdin
        || config.output_capture != OutputCaptureMode::Stdout
        || !config.env_passthrough.is_empty()
        || config.working_dir_flag.is_some()
    {
        bail!("DeepSeek adapter contract is not the immutable headless read-only launch");
    }
    // Generic `LaunchContext` cannot carry a session id. Production assignments
    // start a fresh session and omit `--session-id`. Resume argv is proved by
    // `render_read_only_argv` when a caller supplies a session id.
    let rendered = config.render(context)?;
    let expected = render_read_only_argv(context.prompt, None)?;
    if rendered.argv != expected {
        bail!("DeepSeek rendered argv drifted from the read-only headless contract");
    }
    if session_id.is_some() {
        let _ = render_read_only_argv(context.prompt, session_id)?;
    }
    if !launch_patch_path(context.prompt).is_absolute() {
        bail!("DeepSeek launch patch path is not absolute");
    }
    Ok(ReadOnlyContract::proved(session_id))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRun {
    pub completed: bool,
    pub reason_kind: Option<String>,
    pub has_error: bool,
    pub has_final: bool,
    pub served_model: Option<String>,
    pub model_contradicted: bool,
    pub usage_complete: bool,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub final_text: Option<String>,
    pub cwd: Option<PathBuf>,
    /// Only the allowlisted native read tool, paired to an unambiguous successful result.
    pub successful_reads: Vec<PathBuf>,
}

pub fn parse_event_stream(bytes: &[u8], requested_model: Option<&str>) -> Result<ParsedRun> {
    if bytes.len() > STREAM_MAX_BYTES {
        bail!("DeepSeek event stream exceeds {STREAM_MAX_BYTES} bytes");
    }
    let mut events = 0_usize;
    let mut has_error = false;
    let mut finals = 0_usize;
    let mut reason_kind = None;
    let mut saw_session = false;
    let mut served_model = None;
    let mut model_contradicted = false;
    let mut usage_complete = true;
    let mut saw_step_end = false;
    let mut input_tokens = 0_u64;
    let mut output_tokens = 0_u64;
    let mut calls = BTreeMap::new();
    let mut results = BTreeSet::new();
    let mut successful_reads = Vec::new();
    let mut final_text = None;
    let mut session_id = None;
    let mut cwd = None;
    if bytes.is_empty() {
        usage_complete = false;
    }
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if finals > 0 {
            bail!("DeepSeek event follows the terminal final");
        }
        events += 1;
        if events > MAX_EVENTS {
            bail!("DeepSeek event stream exceeds {MAX_EVENTS} events");
        }
        let value: Value =
            serde_json::from_slice(line).context("DeepSeek event line is not a JSON object")?;
        if !value.is_object() {
            bail!("DeepSeek event line is not a JSON object");
        }
        if json_depth(&value) > MAX_DEPTH {
            bail!("DeepSeek event exceeds the documented nesting depth");
        }
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .context("DeepSeek event is missing type")?;
        let truncated = match value.get("truncated") {
            None | Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) if matches!(kind, "thinking" | "text") => true,
            _ => bail!(
                "DeepSeek truncated or ambiguous evidence cannot prove completion or inspection"
            ),
        };
        let is_final = kind == "final";
        if !is_final && line.len() + 1 > LINE_MAX_BYTES {
            bail!("DeepSeek non-final event line exceeds 32 KiB");
        }
        if is_final && line.len() > STREAM_MAX_BYTES {
            bail!("DeepSeek final event exceeds the stream bound");
        }
        if !is_final && !truncated {
            enforce_string_cap(&value)?;
        }
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            let contradicts_request = requested_model.is_some_and(|requested| requested != model);
            if contradicts_request || served_model.as_deref().is_some_and(|seen| seen != model) {
                model_contradicted = true;
                served_model = None;
            } else {
                served_model = Some(model.to_string());
            }
        }
        match kind {
            "session" => {
                if saw_session || events != 1 {
                    bail!("DeepSeek session must open the unique run");
                }
                session_id = Some(event_string(&value, "sessionId")?.to_string());
                let path = PathBuf::from(event_string(&value, "cwd")?);
                if !path.is_absolute() {
                    bail!("DeepSeek session cwd is not absolute");
                }
                cwd = Some(path);
                saw_session = true;
            }
            "error" => has_error = true,
            "tool_call" => {
                let id = event_string(&value, "callId")?.to_string();
                let tool = event_string(&value, "tool")?;
                let input = value
                    .get("input")
                    .context("DeepSeek tool call has no input")?;
                // Official tool-fs schema: read({file_path, offset?, limit?}).
                // Shell strings and unrelated tools never count as source reads.
                let path = (tool == "read")
                    .then(|| input.get("file_path").and_then(Value::as_str))
                    .flatten()
                    .filter(|path| !path.is_empty() && !path.chars().any(char::is_control))
                    // The Harness can change its session working directory. Only an
                    // absolute input binds inspection without replaying that mutable state.
                    .filter(|path| Path::new(path).is_absolute())
                    // Collapsing `..` lexically can disagree with a filesystem walk
                    // through a symlink, so such read inputs are ambiguous too.
                    .filter(|path| {
                        !Path::new(path)
                            .components()
                            .any(|part| matches!(part, std::path::Component::ParentDir))
                    })
                    .map(PathBuf::from);
                if calls.insert(id, path).is_some() {
                    bail!("DeepSeek duplicate tool call identity");
                }
            }
            "tool_result" => {
                let id = event_string(&value, "callId")?;
                let path = calls
                    .get(id)
                    .context("DeepSeek tool result has no matching call")?;
                if !results.insert(id.to_string()) {
                    bail!("DeepSeek duplicate tool result identity");
                }
                let status = event_string(&value, "status")?;
                if !matches!(status, "completed" | "error") {
                    bail!("DeepSeek tool result has unknown status");
                }
                let result = value
                    .get("result")
                    .and_then(Value::as_str)
                    .context("DeepSeek tool result has no complete text")?;
                if status == "completed"
                    && value.get("error").is_none_or(Value::is_null)
                    && !read_result_was_truncated(result)
                {
                    if let Some(path) = path {
                        successful_reads.push(path.clone());
                    }
                }
            }
            "status" if value.get("phase").and_then(Value::as_str) == Some("step_end") => {
                saw_step_end = true;
                match value.get("usage") {
                    Some(usage) => accumulate_usage(usage, &mut input_tokens, &mut output_tokens)?,
                    None => usage_complete = false,
                }
            }
            "final" => {
                finals += 1;
                if Some(event_string(&value, "sessionId")?) != session_id.as_deref() {
                    bail!("DeepSeek final session does not match the opening session");
                }
                final_text = Some(
                    value
                        .get("text")
                        .and_then(Value::as_str)
                        .context("DeepSeek final is missing text")?
                        .to_string(),
                );
                reason_kind = value
                    .get("reason")
                    .and_then(|reason| reason.get("kind"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            "status" | "thinking" | "text" => {}
            other => bail!("DeepSeek event type {other:?} is outside the documented projection"),
        }
    }
    if !saw_step_end {
        usage_complete = false;
    }
    let completed = saw_session
        && finals == 1
        && calls.len() == results.len()
        && !has_error
        && !model_contradicted
        && reason_kind.as_deref() == Some("completed");
    let (input_tokens, output_tokens, total_tokens) = if usage_complete {
        let total = input_tokens
            .checked_add(output_tokens)
            .context("DeepSeek usage total overflowed")?;
        (Some(input_tokens), Some(output_tokens), Some(total))
    } else {
        (None, None, None)
    };
    Ok(ParsedRun {
        completed,
        reason_kind,
        has_error,
        has_final: finals > 0,
        served_model: (!model_contradicted).then_some(served_model).flatten(),
        model_contradicted,
        usage_complete,
        input_tokens,
        output_tokens,
        total_tokens,
        final_text,
        cwd,
        successful_reads,
    })
}

fn event_string<'a>(event: &'a Value, field: &str) -> Result<&'a str> {
    event
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
        .with_context(|| format!("DeepSeek event is missing unambiguous {field}"))
}

fn read_result_was_truncated(result: &str) -> bool {
    // Native read renders numbered source lines followed by an unnumbered footer.
    // A requested page is a complete inspection window; byte/line truncation is not.
    // Marker text inside ordinary source content must not become a false refusal.
    result.lines().any(|line| {
        line.starts_with("(Output capped.")
            || line
                .rsplit_once("... (line truncated to ")
                .is_some_and(|(_, suffix)| {
                    suffix
                        .strip_suffix(" chars)")
                        .and_then(|number| number.parse::<usize>().ok())
                        .is_some_and(|number| number > 0)
                })
    })
}

/// Lexical normalization in the launch workspace, without filesystem or symlink lookup.
pub fn normalized_source_path(path: &Path, cwd: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !cwd.is_absolute() || path.as_os_str().is_empty() {
        bail!("DeepSeek source path or launch cwd is invalid");
    }
    let joined = cwd.join(path);
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("DeepSeek source path escapes its root");
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn accumulate_usage(usage: &Value, input: &mut u64, output: &mut u64) -> Result<()> {
    let step_input = required_token(usage, "inputTokens")?;
    let step_output = required_token(usage, "outputTokens")?;
    let cache_read = optional_token(usage, "cacheReadTokens")?;
    let cache_write = optional_token(usage, "cacheWriteTokens")?;
    let reasoning = optional_token(usage, "reasoningTokens")?;
    *input = input
        .checked_add(step_input)
        .and_then(|total| total.checked_add(cache_read))
        .and_then(|total| total.checked_add(cache_write))
        .context("DeepSeek input usage overflowed")?;
    *output = output
        .checked_add(step_output)
        .and_then(|total| total.checked_add(reasoning))
        .context("DeepSeek output usage overflowed")?;
    Ok(())
}

fn required_token(usage: &Value, field: &str) -> Result<u64> {
    usage
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("DeepSeek step usage is missing integer {field}"))
}

fn optional_token(usage: &Value, field: &str) -> Result<u64> {
    match usage.get(field) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .with_context(|| format!("DeepSeek step usage field {field} is not an integer")),
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn enforce_string_cap(value: &Value) -> Result<()> {
    match value {
        Value::String(text) if text.len() > MAX_STRING_BYTES => {
            bail!("DeepSeek non-final string exceeds 8 KiB without truncated:true")
        }
        Value::Array(items) => {
            for item in items {
                enforce_string_cap(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map {
                if key.len() > MAX_STRING_BYTES {
                    bail!("DeepSeek object key exceeds 8 KiB");
                }
                enforce_string_cap(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn run_completed(
    bytes: &[u8],
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
) -> bool {
    validate_effort(requested_effort).is_ok()
        && validate_model(requested_model).is_ok()
        && parse_event_stream(bytes, requested_model)
            .is_ok_and(|parsed| parsed.completed && !parsed.model_contradicted)
}

pub fn usage_tokens(bytes: &[u8]) -> Option<(u64, u64, u64)> {
    let parsed = parse_event_stream(bytes, None).ok()?;
    if !parsed.usage_complete {
        return None;
    }
    Some((
        parsed.input_tokens?,
        parsed.output_tokens?,
        parsed.total_tokens?,
    ))
}

pub fn served_model(bytes: &[u8], requested_model: Option<&str>) -> Option<String> {
    let parsed = parse_event_stream(bytes, requested_model).ok()?;
    if parsed.model_contradicted {
        return None;
    }
    parsed.served_model
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_adapter::{AdapterId, RuntimeAdapterConfig};

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/runtime_adapter/fixtures/deepseek")
            .join(name);
        let raw = fs::read_to_string(path).unwrap();
        let mut out = String::new();
        for line in raw.lines() {
            if line.starts_with('#') {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out.into_bytes()
    }

    #[test]
    fn completed_fixture_sums_complete_usage_and_ignores_tool_status() {
        let bytes = fixture("completed.ndjson");
        let parsed = parse_event_stream(&bytes, Some("deepseek-v4-pro")).unwrap();
        assert!(parsed.completed);
        assert_eq!(parsed.reason_kind.as_deref(), Some("completed"));
        assert!(parsed.usage_complete);
        assert_eq!(parsed.input_tokens, Some(14));
        assert_eq!(parsed.output_tokens, Some(9));
        assert_eq!(parsed.total_tokens, Some(23));
        assert!(parsed
            .successful_reads
            .iter()
            .any(|path| path == Path::new("/work/README.md")));
        assert!(run_completed(&bytes, Some("deepseek-v4-pro"), Some("high")));
    }

    #[test]
    fn deepseek_launch_patches_are_exclusive_per_assignment_attempt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = root.path().join("research-a.attempt-1.prompt.md");
        let second = root.path().join("research-b.attempt-1.prompt.md");
        let retry = root.path().join("research-a.attempt-2.prompt.md");
        let a = prepare_launch_patch(&first, "deepseek-v4-pro", "high")?;
        let original = fs::read(&a)?;
        let b = prepare_launch_patch(&second, "deepseek-flash", "low")?;
        let c = prepare_launch_patch(&retry, "deepseek-v4-pro", "max")?;
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(fs::read(&a)?, original);
        assert!(prepare_launch_patch(&first, "deepseek-flash", "off").is_err());
        assert_eq!(fs::read(a)?, original);
        Ok(())
    }

    #[test]
    fn negative_fixtures_do_not_count_tool_success_or_omitted_usage_as_zero() {
        let failed = parse_event_stream(&fixture("failed-final.ndjson"), None).unwrap();
        assert!(!failed.completed);
        assert_eq!(failed.reason_kind.as_deref(), Some("error"));
        assert!(failed.usage_complete);
        assert!(!failed.has_error);

        let runner = parse_event_stream(&fixture("runner-error.ndjson"), None).unwrap();
        assert!(runner.has_error);
        assert!(!runner.has_final);
        assert!(!runner.completed);
        assert!(!runner.usage_complete);
        assert!(runner.input_tokens.is_none());

        let tool = parse_event_stream(&fixture("tool-result-not-success.ndjson"), None).unwrap();
        assert_eq!(tool.reason_kind.as_deref(), Some("aborted"));
        assert!(!tool.completed);

        let omitted = parse_event_stream(&fixture("omitted-usage.ndjson"), None).unwrap();
        assert!(omitted.completed);
        assert!(!omitted.usage_complete);
        assert!(omitted.input_tokens.is_none());
        assert!(usage_tokens(&fixture("omitted-usage.ndjson")).is_none());
    }

    #[test]
    fn deepseek_inspection_requires_allowlisted_read_and_matching_successful_result() {
        let source = fixture("completed.ndjson");
        let events: Vec<Value> = source
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let call = events
            .iter()
            .position(|event| event["type"] == "tool_call")
            .unwrap();
        for case in [
            "valid",
            "bash-echo",
            "denied-read",
            "missing-result",
            "error-detail",
            "truncated-call",
            "truncated-result",
            "result-before-call",
            "duplicate-call",
            "duplicate-result",
            "partial-output",
            "truncated-line",
            "invalid-path-field",
            "relative-read",
            "parent-component",
            "truncated-progress",
            "paged-read",
            "marker-in-content",
        ] {
            let mut changed = events.clone();
            match case {
                "bash-echo" => {
                    changed[call]["tool"] = serde_json::json!("bash");
                    changed[call]["input"] = serde_json::json!({"command":"echo /work/README.md"});
                    changed[call + 1]["status"] = serde_json::json!("error");
                }
                "denied-read" => changed[call + 1]["status"] = serde_json::json!("error"),
                "error-detail" => changed[call + 1]["error"] = serde_json::json!({"code":"DENIED"}),
                "missing-result" => {
                    changed.remove(call + 1);
                }
                "truncated-call" => changed[call]["truncated"] = serde_json::json!(true),
                "truncated-result" => changed[call + 1]["truncated"] = serde_json::json!(true),
                "result-before-call" => changed.swap(call, call + 1),
                "duplicate-call" => changed.insert(call, changed[call].clone()),
                "duplicate-result" => changed.insert(call + 1, changed[call + 1].clone()),
                "partial-output" => {
                    changed[call + 1]["result"] =
                        serde_json::json!("(Output capped. Showing lines 1-10. Use offset=11 to continue.)")
                }
                "truncated-line" => {
                    changed[call + 1]["result"] =
                        serde_json::json!("1: ... (line truncated to 2000 chars)")
                }
                "invalid-path-field" => {
                    changed[call]["input"] = serde_json::json!({"command":"/work/README.md"})
                }
                "relative-read" => {
                    changed[call]["input"] = serde_json::json!({"file_path":"README.md"})
                }
                "parent-component" => {
                    changed[call]["input"] =
                        serde_json::json!({"file_path":"/work/sub/../README.md"})
                }
                "truncated-progress" => changed[call-1] = serde_json::json!({"type":"text","text":"bounded progress","truncated":true}),
                "paged-read" => changed[call+1]["result"] = serde_json::json!("(Showing lines 1-10 of 20. Use offset=11 to continue.)"),
                "marker-in-content" => changed[call+1]["result"] = serde_json::json!("1: a source line mentions (Output capped. and ... (line truncated to 2000 chars) in ordinary text\n\n(End of file - total 1 lines)\n</content>"),
                _ => {}
            }
            let bytes = changed
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let parsed = parse_event_stream(bytes.as_bytes(), None);
            if matches!(
                case,
                "valid" | "truncated-progress" | "paged-read" | "marker-in-content"
            ) {
                assert_eq!(
                    parsed.unwrap().successful_reads,
                    [PathBuf::from("/work/README.md")]
                );
            } else {
                assert!(
                    parsed.is_err() || parsed.unwrap().successful_reads.is_empty(),
                    "{case}"
                );
            }
        }
    }

    #[test]
    fn deepseek_source_paths_compare_exactly_after_workspace_normalization() {
        let cwd = Path::new("/work");
        let expected = normalized_source_path(Path::new("README.md"), cwd).unwrap();
        for same in ["./README.md", "/work/README.md", "sub/../README.md"] {
            assert_eq!(
                normalized_source_path(Path::new(same), cwd).unwrap(),
                expected
            );
        }
        for other in [
            "not-README.md",
            "README.md.backup",
            "other/README.md",
            "../README.md",
        ] {
            assert_ne!(
                normalized_source_path(Path::new(other), cwd).unwrap(),
                expected
            );
        }
        assert!(normalized_source_path(Path::new("/../../README.md"), cwd).is_err());
    }

    #[test]
    fn served_model_must_match_the_request_when_the_stream_reports_one() {
        let bytes = fixture("served-model.ndjson");
        let matched = parse_event_stream(&bytes, Some("deepseek-v4-pro")).unwrap();
        assert!(matched.completed);
        assert_eq!(matched.served_model.as_deref(), Some("deepseek-v4-pro"));
        let contradicted = parse_event_stream(&bytes, Some("deepseek-flash")).unwrap();
        assert!(contradicted.model_contradicted);
        assert!(!contradicted.completed);
        assert!(contradicted.served_model.is_none());
        assert!(served_model(&bytes, Some("deepseek-flash")).is_none());
    }

    #[test]
    fn malformed_lines_and_oversized_non_final_events_fail_closed() {
        assert!(parse_event_stream(b"not-json\n", None).is_err());
        assert!(parse_event_stream(b"{\"type\":\"surprise\"}\n", None).is_err());
        let mut long = br#"{"type":"text","text":""#.to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_STRING_BYTES + 8));
        long.extend(br#""}"#);
        long.push(b'\n');
        assert!(parse_event_stream(&long, None).is_err());
    }

    #[test]
    fn read_only_argv_always_carries_privacy_patch_and_never_add_dir() {
        let prompt = Path::new("/work/attempts/prompt.txt");
        let argv = render_read_only_argv(prompt, None).unwrap();
        assert_eq!(
            argv,
            vec![
                "--profile",
                "headless",
                "--patch",
                "/work/attempts/prompt.txt.dsh-launch.patch",
                "--json",
                "--permission-mode",
                "read-only",
                "--approval-policy",
                "never",
                "-",
            ]
        );
        let resumed = render_read_only_argv(prompt, Some("session-documented")).unwrap();
        assert!(resumed.windows(2).any(|pair| {
            pair.len() == 2 && pair[0] == "--session-id" && pair[1] == "session-documented"
        }));
        assert_eq!(resumed.last().map(String::as_str), Some("-"));
        assert!(render_read_only_argv(prompt, Some("-session")).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let invalid = Path::new(std::ffi::OsStr::from_bytes(b"/work/attempt-\xff.prompt.md"));
            assert!(render_read_only_argv(invalid, None).is_err());
        }
        let config = RuntimeAdapterConfig::defaults_for(AdapterId::DeepSeek);
        let rendered = config
            .render(&LaunchContext {
                prompt,
                model: Some("deepseek-v4-pro"),
                effort: Some("high"),
                cwd: Path::new("/work"),
                output: Path::new("/work/out.txt"),
            })
            .unwrap();
        assert_eq!(rendered.argv, argv);
        assert!(config.feed_prompt_on_stdin);
    }

    #[test]
    fn privacy_flags_are_unconditional_and_model_effort_are_bound_in_the_patch() {
        let missing = privacy_environment(|_| None);
        assert!(missing.is_err());
        let env =
            privacy_environment(|_| Some("deepseek-test-key-0123456789".to_string())).unwrap();
        assert!(env
            .iter()
            .any(|(key, value)| *key == "DSH_TELEMETRY_DISABLED" && value == "1"));
        assert!(env
            .iter()
            .any(|(key, value)| *key == "DSH_TELEMETRY_MODE" && value == "DISABLED"));
        assert!(env.iter().any(|(key, _)| *key == "DEEPSEEK_API_KEY"));
        let patch = privacy_patch_document("deepseek-v4-pro", "high").unwrap();
        assert!(patch.contains("mode: DISABLED"));
        assert!(patch.contains("disabled: true"));
        assert!(patch.contains("id: session-log-deepseek"));
        assert!(patch.contains("enabled: false"));
        assert!(patch.contains("provider: deepseek-official"));
        assert!(patch.contains("model: \"deepseek-v4-pro\""));
        assert!(patch.contains("reasoningEffort: high"));
        assert!(patch.contains("defaultPreset: read-only"));
        assert!(patch.contains("sandbox: read-only"));
        assert!(patch.contains("approval: never"));
        assert!(privacy_patch_document("deepseek-v4-pro", "medium").is_err());
        assert!(privacy_patch_document("deepseek-v4-pro", "xhigh").is_err());
        assert!(privacy_patch_document("has space", "low").is_err());
    }

    #[test]
    fn requested_effort_is_the_identity_and_aliases_are_refused() {
        for effort in EFFORTS {
            assert!(validate_effort(Some(effort)).is_ok());
        }
        for refused in ["none", "minimal", "medium", "xhigh", "ultra", "LOW", ""] {
            assert!(validate_effort(Some(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn executable_resolution_refuses_relative_paths_and_symlinks() {
        assert!(resolve_configured_executable(None).is_err());
        assert!(resolve_configured_executable(Some(std::ffi::OsStr::new("dsh"))).is_err());
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("dsh");
        fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        let resolved = resolve_configured_executable(Some(binary.as_os_str())).unwrap();
        assert_eq!(resolved, fs::canonicalize(&binary).unwrap());
        #[cfg(unix)]
        {
            let link = dir.path().join("dsh-link");
            std::os::unix::fs::symlink(&binary, &link).unwrap();
            assert!(resolve_configured_executable(Some(link.as_os_str())).is_err());
        }
    }

    #[test]
    fn proved_read_only_contract_does_not_admit_worktree_writes() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("dsh");
        fs::write(&binary, b"bin").unwrap();
        let prompt = dir.path().join("prompt.txt");
        fs::write(&prompt, b"inspect").unwrap();
        let mut config = RuntimeAdapterConfig::defaults_for(AdapterId::DeepSeek);
        config.binary = Some(binary);
        let context = LaunchContext {
            prompt: &prompt,
            model: Some("deepseek-v4-pro"),
            effort: Some("max"),
            cwd: dir.path(),
            output: &dir.path().join("out.txt"),
        };
        let proved = prove_read_only_launch(&config, &context, None).unwrap();
        assert!(proved.side_effect_confinement_verified);
        assert!(!proved.session_resume_supported);
        assert!(!proved.admits_worktree_writable);
        let resumed = prove_read_only_launch(&config, &context, Some("session-1")).unwrap();
        assert!(resumed.session_resume_supported);
        assert!(!resumed.admits_worktree_writable);
        config.argument_template = vec!["--profile".into(), "acp".into()];
        assert!(prove_read_only_launch(&config, &context, None).is_err());
    }
}
