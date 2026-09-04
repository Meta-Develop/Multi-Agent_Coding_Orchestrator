//! Pinned Grok launch/event protocol and runtime-advertised model discovery.
//!
//! The launch descriptor fixes headless output, tool approval, and the
//! inner-sandbox posture; the NDJSON parser accepts only bounded, terminally
//! complete event streams.
//! Catalog membership still comes only from one bounded `grok models`
//! observation or from the typed constructed-entry injection seam. Policy code
//! may classify returned slugs, but this adapter does not embed a live model
//! list or infer authority from a model name.

use super::AdapterId;
use crate::{
    artifacts::state_auth::sha256_hex,
    process_runner::{
        run_process, EnvironmentMode, ExternalGrokProfile, ProcessSpec, ProcessTreeEvidence,
        SideEffectConfinementEvidence, SideEffectConfinementProfile,
        SideEffectConfinementProfileKind, StdinMode,
    },
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    str,
    time::Duration,
};
#[cfg(target_os = "linux")]
use std::{
    fmt,
    fs::{File, OpenOptions},
    sync::Arc,
};

const GROK_EVENT_STREAM_MAX_BYTES: usize = 8 * 1024 * 1024;
const GROK_EVENT_LINE_MAX_BYTES: usize = 1024 * 1024;
const GROK_EVENT_STREAM_MAX_EVENTS: usize = 16 * 1024;
const GROK_EVENT_TYPE_MAX_BYTES: usize = 64;
const GROK_EVENT_METADATA_MAX_BYTES: usize = 512;
const GROK_EVENT_ERROR_MAX_BYTES: usize = 64 * 1024;
/// Keep one JSON Schema argv element below Linux's `MAX_ARG_STRLEN`, including
/// the terminating NUL byte added by the process launcher.
pub const GROK_OUTPUT_SCHEMA_MAX_BYTES: u64 = 131_072 - 1;
/// Match the external-agent output reservation and supervisor report bound.
pub const GROK_STRUCTURED_OUTPUT_MAX_BYTES: usize = 8 * 1024 * 1024;
const GROK_CATALOG_MAX_BYTES: usize = 256 * 1024;
const GROK_CATALOG_MAX_MODELS: usize = 512;
const GROK_MODEL_SLUG_MAX_BYTES: usize = 256;
const GROK_MODEL_DISPLAY_NAME_MAX_BYTES: usize = 768;
const GROK_LOGIN_PROVIDER_MAX_BYTES: usize = 253;
const GROK_CATALOG_TIMEOUT: Duration = Duration::from_secs(30);
const GROK_DIGEST_FRAMING_VERSION: &[u8] = b"maco.grok.advertised-catalog.v1\n";
const GROK_AUTH_FILE: &str = "auth.json";
const GROK_CONFIG_FILE: &str = "config.toml";

/// Fixed host entry point used when the operator does not set `MACO_GROK_BIN`.
///
/// The Nix system profile entry is expected to be a symlink. Resolution binds
/// its canonical store identity before either catalog observation or launch;
/// arbitrary explicit symlinks remain refused.
pub const TRUSTED_SYSTEM_GROK_EXECUTABLE: &str = "/run/current-system/sw/bin/grok";

pub const fn default_grok_executable() -> &'static str {
    TRUSTED_SYSTEM_GROK_EXECUTABLE
}

/// Validate the operator-controlled `MACO_GROK_BIN` value without consulting
/// ambient `PATH`. The screened catalog runner and launch preflight perform
/// the remaining filesystem identity checks before starting Grok.
pub fn explicit_grok_executable(program: &OsStr) -> Result<PathBuf> {
    let program = PathBuf::from(program);
    if !program.is_absolute() {
        bail!(
            "MACO_GROK_BIN must be an absolute path; ambient PATH and relative resolution are refused (requested {})",
            program.display()
        );
    }
    Ok(program)
}

/// Resolve the configured Grok executable to one canonical absolute identity.
///
/// The fixed Nix profile entry is trusted as a discovery location and may be
/// a symlink. An explicit override must already be absolute and may not itself
/// be a symlink, matching the external-agent executable preflight.
pub fn resolve_configured_grok_executable(program_override: Option<&OsStr>) -> Result<PathBuf> {
    let (candidate, trusted_system_entry) = match program_override {
        Some(program) => (explicit_grok_executable(program)?, false),
        None => (PathBuf::from(TRUSTED_SYSTEM_GROK_EXECUTABLE), true),
    };
    resolve_grok_executable_candidate(&candidate, trusted_system_entry)
}

fn resolve_grok_executable_candidate(
    candidate: &Path,
    trusted_system_entry: bool,
) -> Result<PathBuf> {
    if !candidate.is_absolute() {
        bail!(
            "Grok executable must be an absolute path; ambient PATH and relative resolution are refused (requested {})",
            candidate.display()
        );
    }
    if !trusted_system_entry
        && std::fs::symlink_metadata(candidate)
            .with_context(|| format!("Grok executable '{}' is missing", candidate.display()))?
            .file_type()
            .is_symlink()
    {
        bail!(
            "explicit Grok executable may not be a symlink: {}",
            candidate.display()
        );
    }
    let canonical = std::fs::canonicalize(candidate)
        .with_context(|| format!("Grok executable '{}' is missing", candidate.display()))?;
    if !canonical.is_file() {
        bail!(
            "Grok executable '{}' is not a regular file",
            canonical.display()
        );
    }
    Ok(canonical)
}

/// Immutable Grok headless protocol supported by this adapter.
///
/// Model and reasoning effort remain selector inputs. Every protocol, approval,
/// and confinement argument below is fixed by MACO and is not an operator
/// template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrokRuntimeDescriptor {
    executable: &'static str,
    output_format: &'static str,
    sandbox_profile: &'static str,
    headless_approval_flag: &'static str,
}

impl GrokRuntimeDescriptor {
    pub const fn executable(self) -> &'static str {
        self.executable
    }

    pub const fn output_format(self) -> &'static str {
        self.output_format
    }

    pub const fn sandbox_profile(self) -> &'static str {
        self.sandbox_profile
    }

    pub const fn headless_approval_flag(self) -> &'static str {
        self.headless_approval_flag
    }

    pub const fn subagents_disabled(self) -> bool {
        true
    }

    pub const fn memory_disabled(self) -> bool {
        true
    }

    pub const fn web_search_disabled(self) -> bool {
        true
    }

    /// Canonical argv template. Dynamic values occupy whole argv elements.
    pub fn immutable_argument_template(self) -> Vec<String> {
        [
            "--prompt-file",
            "{prompt}",
            "--model",
            "{model}",
            "--reasoning-effort",
            "{effort}",
            "--cwd",
            "{cwd}",
            "--output-format",
            self.output_format,
            "--sandbox",
            self.sandbox_profile,
            self.headless_approval_flag,
            "--disable-web-search",
            "--no-memory",
            "--no-subagents",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }
}

pub const GROK_RUNTIME_DESCRIPTOR: GrokRuntimeDescriptor = GrokRuntimeDescriptor {
    executable: "grok",
    output_format: "streaming-json",
    sandbox_profile: "strict",
    headless_approval_flag: "--always-approve",
};

/// One validated event from Grok's `streaming-json` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrokStreamEvent {
    Text(String),
    Thought(String),
    End(GrokEndEvent),
    Error(String),
    /// Forward-compatible non-terminal event advertised by Grok.
    Other {
        event_type: String,
    },
}

/// Successful terminal metadata from a Grok stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokEndEvent {
    stop_reason: String,
    session_id: String,
    request_id: String,
    structured_output: Option<Value>,
    structured_output_error: Option<Value>,
    usage_status: GrokUsageStatus,
}

impl GrokEndEvent {
    pub fn stop_reason(&self) -> &str {
        &self.stop_reason
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Grok Build attaches schema-validated output only to the terminal end
    /// event. Callers without an output schema deliberately ignore this value.
    pub fn structured_output(&self) -> Option<&Value> {
        self.structured_output.as_ref()
    }

    /// A terminal structured-output validation error. Its provider-controlled
    /// contents must not be reflected into public failure messages.
    pub fn structured_output_error(&self) -> Option<&Value> {
        self.structured_output_error.as_ref()
    }

    /// Exact native spend observation from this end event. This is never a
    /// Codex `turn.completed` mapping and never invents MACO `Usage` counts.
    pub fn usage_status(&self) -> &GrokUsageStatus {
        &self.usage_status
    }
}

/// Exact token fields from Grok's native `end.usage` object.
///
/// `input_tokens` is uncached prompt spend. Cache buckets stay on their native
/// names; they are not renamed to Codex `cached_input_tokens`. Missing totals
/// are left absent instead of being recomputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokNativeUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

impl GrokNativeUsage {
    pub fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    pub fn output_tokens(&self) -> u64 {
        self.output_tokens
    }

    pub fn cache_read_input_tokens(&self) -> Option<u64> {
        self.cache_read_input_tokens
    }

    pub fn cache_creation_input_tokens(&self) -> Option<u64> {
        self.cache_creation_input_tokens
    }

    pub fn reasoning_tokens(&self) -> Option<u64> {
        self.reasoning_tokens
    }

    pub fn total_tokens(&self) -> Option<u64> {
        self.total_tokens
    }
}

/// Honest adapter-boundary spend status for a bounded Grok stream.
///
/// Native `end` events may omit spend entirely, mark it incomplete, or carry
/// exact token fields. MACO does not convert those fields into Codex events or
/// `Usage` counts; the capability matrix remains `UsageReporting::None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrokUsageStatus {
    NotProcessObservable,
    Incomplete,
    Native(GrokNativeUsage),
}

impl GrokUsageStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotProcessObservable => "not_process_observable",
            Self::Incomplete => "incomplete",
            Self::Native(_) => "native",
        }
    }
}

/// Typed terminal outcome; an error event is evidence of failure, not success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrokStreamOutcome {
    Completed(GrokEndEvent),
    Failed { message: String },
}

/// Bounded, terminally complete Grok event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokParsedEventStream {
    events: Vec<GrokStreamEvent>,
    response_text: String,
    outcome: GrokStreamOutcome,
}

impl GrokParsedEventStream {
    pub fn events(&self) -> &[GrokStreamEvent] {
        &self.events
    }

    pub fn response_text(&self) -> &str {
        &self.response_text
    }

    pub fn outcome(&self) -> &GrokStreamOutcome {
        &self.outcome
    }

    pub const fn completed(&self) -> bool {
        matches!(self.outcome, GrokStreamOutcome::Completed(_))
    }

    /// Spend status for this bounded stream. Failed terminals stay
    /// not-process-observable even if an error event carried extra spend keys.
    pub fn usage_status(&self) -> GrokUsageStatus {
        match &self.outcome {
            GrokStreamOutcome::Completed(end) => end.usage_status().clone(),
            GrokStreamOutcome::Failed { .. } => GrokUsageStatus::NotProcessObservable,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawGrokStreamEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    data: Option<String>,
    #[serde(default, rename = "stopReason")]
    stop_reason: Option<String>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default, rename = "requestId")]
    request_id: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, rename = "structuredOutput")]
    structured_output: Option<Value>,
    #[serde(default, rename = "structuredOutputError")]
    structured_output_error: Option<Value>,
    #[serde(default)]
    usage: Option<RawGrokUsage>,
    #[serde(default, rename = "usage_is_incomplete")]
    usage_is_incomplete: Option<bool>,
    #[serde(flatten)]
    _other: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawGrokUsage {
    input_tokens: u64,
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    reasoning_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
}

/// Load one exact JSON Schema file into the bounded argv representation Grok
/// Build expects. The compact serialization is both validated JSON and one
/// indivisible argv value; the schema pathname is never passed to Grok.
pub fn load_grok_output_schema_argv(path: &Path) -> Result<String> {
    let text =
        crate::safe_state::BoundedRegularReader::read_utf8(path, GROK_OUTPUT_SCHEMA_MAX_BYTES)
            .with_context(|| {
                format!(
                    "failed to read bounded Grok output schema {}",
                    path.display()
                )
            })?;
    let schema: Value = serde_json::from_str(&text)
        .with_context(|| format!("Grok output schema {} is not valid JSON", path.display()))?;
    if !schema.is_object() {
        bail!("Grok output schema must be a JSON object");
    }
    let rendered = serde_json::to_string(&canonical_json_value(&schema))
        .context("failed to render Grok output schema")?;
    if rendered.len() > GROK_OUTPUT_SCHEMA_MAX_BYTES as usize {
        bail!(
            "rendered Grok output schema exceeds the {} byte argv limit",
            GROK_OUTPUT_SCHEMA_MAX_BYTES
        );
    }
    Ok(rendered)
}

/// Produce the canonical compact JSON that MACO may publish for a
/// schema-bound Grok command. Native schema validation is represented by the
/// terminal `structuredOutput` field; MACO additionally requires the report
/// envelope to be an object and independently enforces its publication bound.
pub fn canonical_grok_structured_output(value: &Value) -> Result<Vec<u8>> {
    if !value.is_object() {
        bail!("Grok terminal structuredOutput is not a JSON object");
    }
    let canonical = serde_json::to_vec(&canonical_json_value(value))
        .context("failed to serialize Grok terminal structuredOutput")?;
    if canonical.len() > GROK_STRUCTURED_OUTPUT_MAX_BYTES {
        bail!(
            "Grok terminal structuredOutput exceeds the {} byte limit",
            GROK_STRUCTURED_OUTPUT_MAX_BYTES
        );
    }
    Ok(canonical)
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(canonical_json_value).collect::<Vec<_>>())
        }
        Value::Object(values) => {
            let sorted = values.iter().collect::<BTreeMap<_, _>>();
            let mut canonical = serde_json::Map::new();
            for (key, value) in sorted {
                canonical.insert(key.as_str().to_string(), canonical_json_value(value));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

/// Parse Grok's bounded newline-delimited `streaming-json` protocol.
///
/// Unknown event types are preserved as non-terminal events because Grok's
/// documented event list is non-exhaustive. Exactly one final `end` or `error`
/// event is still required, and no data may follow it.
pub fn parse_grok_event_stream(bytes: &[u8]) -> Result<GrokParsedEventStream> {
    if bytes.is_empty() {
        bail!("Grok streaming-json output was empty");
    }
    if bytes.len() > GROK_EVENT_STREAM_MAX_BYTES {
        bail!(
            "Grok streaming-json output exceeds the {} byte limit",
            GROK_EVENT_STREAM_MAX_BYTES
        );
    }
    if !bytes.ends_with(b"\n") {
        bail!("Grok streaming-json output lacks its terminal newline and may be truncated");
    }
    if bytes.contains(&b'\r') {
        bail!("Grok streaming-json output contains a carriage return");
    }

    let mut events = Vec::new();
    let mut response_text = String::new();
    let mut outcome = None;
    for (index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            bail!("Grok streaming-json event {index} is empty");
        }
        if line.len() > GROK_EVENT_LINE_MAX_BYTES {
            bail!(
                "Grok streaming-json event {index} exceeds the {} byte line limit",
                GROK_EVENT_LINE_MAX_BYTES
            );
        }
        if events.len() >= GROK_EVENT_STREAM_MAX_EVENTS {
            bail!(
                "Grok streaming-json output exceeds the {} event limit",
                GROK_EVENT_STREAM_MAX_EVENTS
            );
        }
        if outcome.is_some() {
            bail!("Grok streaming-json output contains data after its terminal event");
        }

        let raw: RawGrokStreamEvent = serde_json::from_slice(line)
            .with_context(|| format!("Grok streaming-json event {index} is malformed"))?;
        validate_grok_event_type(&raw.event_type)
            .with_context(|| format!("Grok streaming-json event {index}"))?;
        if raw.event_type != "end"
            && (raw.structured_output.is_some() || raw.structured_output_error.is_some())
        {
            bail!(
                "Grok streaming-json event {index} places structured output outside the terminal end event"
            );
        }
        if matches!(raw.event_type.as_str(), "text" | "thought" | "error")
            && (raw.usage.is_some() || raw.usage_is_incomplete.is_some())
        {
            bail!("Grok streaming-json event {index} places usage outside the terminal end event");
        }
        let event = match raw.event_type.as_str() {
            "text" => {
                require_absent_grok_event_fields(
                    index,
                    &raw,
                    &[
                        raw.stop_reason.as_ref(),
                        raw.session_id.as_ref(),
                        raw.request_id.as_ref(),
                        raw.message.as_ref(),
                    ],
                )?;
                let data = raw
                    .data
                    .context("Grok streaming-json text event is missing data")?;
                let next_len = response_text
                    .len()
                    .checked_add(data.len())
                    .context("Grok streaming-json response length overflow")?;
                if next_len > GROK_EVENT_STREAM_MAX_BYTES {
                    bail!("Grok streaming-json response exceeds its bounded stream size");
                }
                response_text.push_str(&data);
                GrokStreamEvent::Text(data)
            }
            "thought" => {
                require_absent_grok_event_fields(
                    index,
                    &raw,
                    &[
                        raw.stop_reason.as_ref(),
                        raw.session_id.as_ref(),
                        raw.request_id.as_ref(),
                        raw.message.as_ref(),
                    ],
                )?;
                GrokStreamEvent::Thought(
                    raw.data
                        .context("Grok streaming-json thought event is missing data")?,
                )
            }
            "end" => {
                require_absent_grok_event_fields(
                    index,
                    &raw,
                    &[raw.data.as_ref(), raw.message.as_ref()],
                )?;
                let terminal = GrokEndEvent {
                    stop_reason: validate_grok_event_metadata("stopReason", raw.stop_reason)?,
                    session_id: validate_grok_event_metadata("sessionId", raw.session_id)?,
                    request_id: validate_grok_event_metadata("requestId", raw.request_id)?,
                    structured_output: raw.structured_output,
                    structured_output_error: raw.structured_output_error,
                    usage_status: grok_end_usage_status(raw.usage, raw.usage_is_incomplete),
                };
                outcome = Some(GrokStreamOutcome::Completed(terminal.clone()));
                GrokStreamEvent::End(terminal)
            }
            "error" => {
                require_absent_grok_event_fields(
                    index,
                    &raw,
                    &[
                        raw.data.as_ref(),
                        raw.stop_reason.as_ref(),
                        raw.session_id.as_ref(),
                        raw.request_id.as_ref(),
                    ],
                )?;
                let message = raw
                    .message
                    .filter(|message| {
                        !message.is_empty() && message.len() <= GROK_EVENT_ERROR_MAX_BYTES
                    })
                    .context(
                        "Grok streaming-json error event has a missing or oversized message",
                    )?;
                outcome = Some(GrokStreamOutcome::Failed {
                    message: message.clone(),
                });
                GrokStreamEvent::Error(message)
            }
            _ => GrokStreamEvent::Other {
                event_type: raw.event_type,
            },
        };
        events.push(event);
    }

    let outcome =
        outcome.context("Grok streaming-json output has no terminal end or error event")?;
    Ok(GrokParsedEventStream {
        events,
        response_text,
        outcome,
    })
}

fn require_absent_grok_event_fields(
    index: usize,
    _raw: &RawGrokStreamEvent,
    fields: &[Option<&String>],
) -> Result<()> {
    if fields.iter().any(Option::is_some) {
        bail!("Grok streaming-json event {index} mixes fields from incompatible event types");
    }
    Ok(())
}

fn grok_end_usage_status(
    usage: Option<RawGrokUsage>,
    usage_is_incomplete: Option<bool>,
) -> GrokUsageStatus {
    if usage_is_incomplete == Some(true) {
        return GrokUsageStatus::Incomplete;
    }
    match usage {
        None => GrokUsageStatus::NotProcessObservable,
        Some(usage) => GrokUsageStatus::Native(GrokNativeUsage {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_read_input_tokens: usage.cache_read_input_tokens,
            cache_creation_input_tokens: usage.cache_creation_input_tokens,
            reasoning_tokens: usage.reasoning_tokens,
            total_tokens: usage.total_tokens,
        }),
    }
}

fn validate_grok_event_type(event_type: &str) -> Result<()> {
    if event_type.is_empty()
        || event_type.len() > GROK_EVENT_TYPE_MAX_BYTES
        || !event_type.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        bail!("has an invalid event type");
    }
    Ok(())
}

fn validate_grok_event_metadata(label: &str, value: Option<String>) -> Result<String> {
    value
        .filter(|value| {
            !value.is_empty()
                && value.len() <= GROK_EVENT_METADATA_MAX_BYTES
                && !value.chars().any(char::is_control)
        })
        .with_context(|| format!("Grok streaming-json end event has invalid {label}"))
}

/// Exact bounded command request for Grok's account-visible catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokCatalogCommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: PathBuf,
    environment: BTreeMap<String, String>,
    capture_limit_bytes: usize,
    timeout: Duration,
}

impl GrokCatalogCommandSpec {
    /// Construct the stable catalog request `grok models`.
    pub fn new(current_dir: impl Into<PathBuf>) -> Self {
        Self {
            program: PathBuf::from(TRUSTED_SYSTEM_GROK_EXECUTABLE),
            args: vec![OsString::from("models")],
            current_dir: current_dir.into(),
            environment: BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ]),
            capture_limit_bytes: GROK_CATALOG_MAX_BYTES,
            timeout: GROK_CATALOG_TIMEOUT,
        }
    }

    /// Bind an already-resolved executable.
    ///
    /// Production callers resolve `grok` first. Tests bind a scripted stand-in
    /// so `cargo test` never starts a live `grok` process.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn current_dir(&self) -> &Path {
        &self.current_dir
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub const fn capture_limit_bytes(&self) -> usize {
        self.capture_limit_bytes
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Bounded command evidence returned by a production or hermetic runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokCatalogCommandOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub process_tree: ProcessTreeEvidence,
    pub side_effects: SideEffectConfinementEvidence,
}

/// Injectable command boundary.
///
/// Unit tests inject hermetic evidence without resolving or starting `grok`.
/// Tests may inject [`ScreenedGrokCatalogCommandRunner`]; Supervisor production
/// uses the capability-bound runner in `supervise::selection_bridge`.
pub trait GrokCatalogCommandRunner {
    fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput>;
}

/// Screened production runner for one bounded `grok models` observation.
///
/// The runner resolves the executable, screens the environment, requests
/// verified process-tree cleanup and a Grok-compatible side-effect profile,
/// and returns honest confinement evidence. It does not invent Verified
/// evidence after a failed or incomplete run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub struct ScreenedGrokCatalogCommandRunner;

#[cfg(test)]
impl GrokCatalogCommandRunner for ScreenedGrokCatalogCommandRunner {
    fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput> {
        run_screened_grok_catalog_command(spec)
    }
}

/// One constructed or observed Grok model and its human-facing label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokModelCatalogEntry {
    slug: String,
    display_name: String,
}

impl GrokModelCatalogEntry {
    pub fn new(slug: impl Into<String>, display_name: impl Into<String>) -> Result<Self> {
        let slug = slug.into();
        let display_name = display_name.into();
        validate_grok_model_slug(&slug).context("Grok constructed catalog entry")?;
        validate_grok_model_display_name(&display_name)
            .context("Grok constructed catalog entry")?;
        Ok(Self { slug, display_name })
    }

    pub fn slug(&self) -> &str {
        &self.slug
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Immutable snapshot of one Grok catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokModelCatalog {
    models: Vec<GrokModelCatalogEntry>,
}

impl GrokModelCatalog {
    pub fn from_injected_entries(
        entries: impl IntoIterator<Item = GrokModelCatalogEntry>,
    ) -> Result<Self> {
        let models = entries.into_iter().collect::<Vec<_>>();
        if models.is_empty() {
            bail!("Grok constructed catalog contains no models");
        }
        if models.len() > GROK_CATALOG_MAX_MODELS {
            bail!(
                "Grok constructed catalog contains {} models, exceeding the {} model limit",
                models.len(),
                GROK_CATALOG_MAX_MODELS
            );
        }
        let mut seen = BTreeSet::new();
        for entry in &models {
            if !seen.insert(entry.slug.as_str()) {
                bail!(
                    "Grok constructed catalog contains duplicate slug '{}'",
                    entry.slug
                );
            }
        }
        Ok(Self { models })
    }

    pub fn models(&self) -> &[GrokModelCatalogEntry] {
        &self.models
    }

    pub fn slugs(&self) -> impl Iterator<Item = &str> {
        self.models.iter().map(GrokModelCatalogEntry::slug)
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.models.iter().any(|model| model.slug == slug)
    }
}

/// One content-bound Grok catalog observation.
///
/// Runtime identity is fixed to this adapter's typed identity. Observation
/// time is supplied by the screened caller. Neither field confers capability
/// or authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokAdvertisedCatalogObservation {
    catalog: GrokModelCatalog,
    runtime: AdapterId,
    observed_at_unix_millis: u64,
    source_sha256: String,
}

impl GrokAdvertisedCatalogObservation {
    pub fn catalog(&self) -> &GrokModelCatalog {
        &self.catalog
    }

    pub const fn runtime(&self) -> AdapterId {
        self.runtime
    }

    pub const fn observed_at_unix_millis(&self) -> u64 {
        self.observed_at_unix_millis
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

/// Accept a constructed Grok catalog as an advertised observation.
///
/// The digest binds a canonical framing of runtime identity, constructed
/// entries, and the caller-supplied source bytes. It is not a listing-only
/// hash of `source_bytes`.
pub fn inject_grok_advertised_catalog(
    catalog: GrokModelCatalog,
    observed_at_unix_millis: Option<u64>,
    source_bytes: &[u8],
) -> Result<GrokAdvertisedCatalogObservation> {
    let observed_at_unix_millis = observed_at_unix_millis
        .filter(|observed_at| *observed_at != 0)
        .context("Grok runtime model catalog observation time is missing or zero")?;
    if source_bytes.is_empty() {
        bail!("Grok constructed catalog source bytes were empty");
    }
    Ok(GrokAdvertisedCatalogObservation {
        source_sha256: grok_catalog_source_digest(&catalog, source_bytes),
        catalog,
        runtime: AdapterId::Grok,
        observed_at_unix_millis,
    })
}

/// Run the supplied command seam and accept only complete successful evidence.
///
/// A successful observation is converted through
/// [`inject_grok_advertised_catalog`] so selector join keeps one typed seam.
pub fn discover_grok_model_catalog(
    runner: &dyn GrokCatalogCommandRunner,
    spec: &GrokCatalogCommandSpec,
    observed_at_unix_millis: Option<u64>,
) -> Result<GrokAdvertisedCatalogObservation> {
    let observed_at_unix_millis = observed_at_unix_millis
        .filter(|observed_at| *observed_at != 0)
        .context("Grok runtime model catalog observation time is missing or zero")?;
    let output = runner.run(spec)?;
    if output.timed_out {
        bail!("Grok runtime model catalog command timed out");
    }
    if output.stdout_truncated || output.stderr_truncated {
        bail!(
            "Grok runtime model catalog command output exceeded the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.stdout.len() > spec.capture_limit_bytes()
        || output.stderr.len() > spec.capture_limit_bytes()
    {
        bail!(
            "Grok runtime model catalog command returned output larger than the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.status != Some(0) {
        bail!(
            "Grok runtime model catalog command failed with exit status {:?}",
            output.status
        );
    }
    if !output.process_tree.is_verified_empty() {
        bail!("Grok runtime model catalog process ownership was not verified empty");
    }
    if !matches!(
        output.side_effects,
        SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace
                | SideEffectConfinementProfileKind::TrustedFixedNetwork
                | SideEffectConfinementProfileKind::ExternalGrok
        )
    ) {
        bail!(
            "Grok runtime model catalog side-effect confinement was not verified with a Grok-compatible profile"
        );
    }
    if !output.stderr.is_empty() {
        bail!("Grok runtime model catalog command emitted unexpected stderr");
    }
    let catalog = parse_grok_model_catalog(&output.stdout)?;
    inject_grok_advertised_catalog(catalog, Some(observed_at_unix_millis), &output.stdout)
}

/// Parse the strict plain-text grammar emitted by `grok models`.
pub fn parse_grok_model_catalog(bytes: &[u8]) -> Result<GrokModelCatalog> {
    if bytes.is_empty() {
        bail!("Grok runtime model catalog output was empty");
    }
    if bytes.len() > GROK_CATALOG_MAX_BYTES {
        bail!(
            "Grok runtime model catalog output exceeds the {} byte limit",
            GROK_CATALOG_MAX_BYTES
        );
    }
    let text = str::from_utf8(bytes).context("Grok runtime model catalog is not valid UTF-8")?;
    if !text.ends_with('\n') {
        bail!("Grok runtime model catalog lacks its terminal newline and may be truncated");
    }
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        bail!("Grok runtime model catalog contains a bare carriage return");
    }
    let lines = normalized
        .strip_suffix('\n')
        .unwrap_or(&normalized)
        .split('\n')
        .collect::<Vec<_>>();
    if lines.len() < 6 {
        bail!("Grok runtime model catalog has an invalid header");
    }
    validate_grok_login_line(lines[0])?;
    if !lines[1].is_empty() {
        bail!("Grok runtime model catalog has an invalid header");
    }
    let default_slug = lines[2]
        .strip_prefix("Default model: ")
        .context("Grok runtime model catalog has an invalid header")?;
    validate_grok_model_slug(default_slug).context("Grok runtime model catalog default model")?;
    if !lines[3].is_empty() || lines[4] != "Available models:" {
        bail!("Grok runtime model catalog has an invalid header");
    }

    let model_lines = &lines[5..];
    if model_lines.is_empty() {
        bail!("Grok runtime model catalog contains no models");
    }
    if model_lines.len() > GROK_CATALOG_MAX_MODELS {
        bail!(
            "Grok runtime model catalog contains {} models, exceeding the {} model limit",
            model_lines.len(),
            GROK_CATALOG_MAX_MODELS
        );
    }

    let mut seen = BTreeSet::new();
    let mut models = Vec::with_capacity(model_lines.len());
    let mut marked_default = None;
    for (index, line) in model_lines.iter().enumerate() {
        let (slug, is_default) = parse_grok_model_line(line)
            .with_context(|| format!("Grok runtime model catalog entry {index} is malformed"))?;
        validate_grok_model_slug(slug)
            .with_context(|| format!("Grok runtime model catalog entry {index}"))?;
        if !seen.insert(slug) {
            bail!("Grok runtime model catalog contains duplicate slug '{slug}'");
        }
        if is_default {
            if marked_default.is_some() {
                bail!("Grok runtime model catalog contains more than one default marker");
            }
            marked_default = Some(slug);
        }
        models.push(GrokModelCatalogEntry {
            slug: slug.to_string(),
            display_name: slug.to_string(),
        });
    }
    let marked_default =
        marked_default.context("Grok runtime model catalog is missing its default marker")?;
    if marked_default != default_slug {
        bail!(
            "Grok runtime model catalog default marker '{marked_default}' does not match header '{default_slug}'"
        );
    }
    Ok(GrokModelCatalog { models })
}

fn parse_grok_model_line(line: &str) -> Result<(&str, bool)> {
    if let Some(rest) = line.strip_prefix("  * ") {
        let slug = rest
            .strip_suffix(" (default)")
            .context("default marker must use '* <slug> (default)'")?;
        if slug.is_empty() || slug.contains(char::is_whitespace) {
            bail!("default marker is malformed");
        }
        return Ok((slug, true));
    }
    if let Some(slug) = line.strip_prefix("  - ") {
        if slug.is_empty() || slug.contains(char::is_whitespace) || slug.ends_with(" (default)") {
            bail!("non-default marker is malformed");
        }
        return Ok((slug, false));
    }
    bail!("line does not match a Grok model marker");
}

fn validate_grok_login_line(line: &str) -> Result<()> {
    let provider = line
        .strip_prefix("You are logged in with ")
        .and_then(|rest| rest.strip_suffix('.'))
        .context("Grok runtime model catalog has an invalid header")?;
    if provider.is_empty() || provider.len() > GROK_LOGIN_PROVIDER_MAX_BYTES {
        bail!("Grok runtime model catalog has an invalid login provider");
    }
    let mut bytes = provider.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        bail!("Grok runtime model catalog has an invalid login provider");
    }
    Ok(())
}

fn grok_catalog_source_digest(catalog: &GrokModelCatalog, source_bytes: &[u8]) -> String {
    let mut framed = Vec::new();
    framed.extend_from_slice(GROK_DIGEST_FRAMING_VERSION);
    framed.extend_from_slice(b"runtime=");
    framed.extend_from_slice(AdapterId::Grok.as_str().as_bytes());
    framed.push(b'\n');
    for entry in catalog.models() {
        framed.extend_from_slice(b"entry\t");
        framed.extend_from_slice(entry.slug().as_bytes());
        framed.push(b'\t');
        framed.extend_from_slice(entry.display_name().as_bytes());
        framed.push(b'\n');
    }
    framed.extend_from_slice(b"source\n");
    framed.extend_from_slice(source_bytes);
    sha256_hex(&framed)
}

fn validate_grok_model_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("contains an empty model slug");
    }
    if slug.len() > GROK_MODEL_SLUG_MAX_BYTES {
        bail!(
            "model slug exceeds the {} byte limit",
            GROK_MODEL_SLUG_MAX_BYTES
        );
    }
    let mut bytes = slug.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        bail!(
            "model slug must start with an ASCII alphanumeric character and contain only ASCII alphanumerics or - _ . / :"
        );
    }
    Ok(())
}

fn validate_grok_model_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty()
        || display_name.len() > GROK_MODEL_DISPLAY_NAME_MAX_BYTES
        || display_name.trim() != display_name
        || display_name.chars().any(char::is_control)
    {
        bail!("contains an invalid model display name");
    }
    Ok(())
}

#[cfg(test)]
fn run_screened_grok_catalog_command(
    spec: &GrokCatalogCommandSpec,
) -> Result<GrokCatalogCommandOutput> {
    let process_spec = screened_grok_catalog_process_spec(spec)?;
    let output = run_process(process_spec).context(
        "Grok runtime model catalog command failed before a verified result was available",
    )?;
    if output.process_error.is_some() || output.stdin_error.is_some() {
        bail!("Grok runtime model catalog process ownership cleanup was incomplete");
    }
    Ok(GrokCatalogCommandOutput {
        status: output.status.and_then(|status| status.code()),
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
        stdout_truncated: output.stdout.is_truncated(),
        stderr_truncated: output.stderr.is_truncated(),
        timed_out: output.timed_out,
        process_tree: output.process_tree,
        side_effects: output.side_effects,
    })
}

pub(crate) fn run_screened_grok_catalog_command_authorized(
    spec: &GrokCatalogCommandSpec,
    session: &crate::mutation_taxonomy::CatalogPreflightMutationSession,
    launch_evidence: &mut Option<crate::mutation_taxonomy::SupervisorProcessLaunchAuditEvidence>,
) -> Result<GrokCatalogCommandOutput> {
    let program = resolve_catalog_program(spec.program())?;
    let program_for_revalidation = program.clone();
    let metadata = std::fs::symlink_metadata(&program).with_context(|| {
        format!(
            "failed to inspect Grok catalog executable {}",
            program.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Grok catalog executable identity is not a regular file");
    }
    #[cfg(unix)]
    let program_identity = {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{};dev={};ino={};len={};mtime_ns={}",
            program.display(),
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_nanos().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        )
    };
    #[cfg(not(unix))]
    let program_identity = format!(
        "{};len={};mtime={:?}",
        program.display(),
        metadata.len(),
        metadata.modified().ok()
    );
    let (process_spec, credential_binding) =
        screened_grok_catalog_process_spec_for_program_with_binding(spec, program)?;
    let identity = crate::mutation_taxonomy::ExactSupervisorProcessLaunchIdentity {
        run_id: session.run_id().to_string(),
        subject_id: "catalog-grok".to_string(),
        attempt: 1,
        adapter: "grok".to_string(),
        model: None,
        reasoning_effort: None,
        program_identity,
        execution_mode: "verified-catalog-preflight".to_string(),
        delivery_identity: serde_json::to_string(&(
            spec.args(),
            spec.current_dir(),
            spec.environment(),
            spec.timeout().as_millis(),
            credential_binding,
        ))?,
        kind: crate::mutation_taxonomy::SupervisorProcessLaunchKind::CatalogGrokProbe,
    };
    let (evidence, authorization) = session.authorize_process_launch(identity.clone())?;
    let current_metadata =
        std::fs::symlink_metadata(&program_for_revalidation).with_context(|| {
            format!(
                "failed to revalidate Grok catalog executable {}",
                program_for_revalidation.display()
            )
        })?;
    if current_metadata.file_type().is_symlink()
        || !current_metadata.is_file()
        || current_metadata.len() != metadata.len()
        || current_metadata.modified().ok() != metadata.modified().ok()
    {
        bail!("Grok catalog executable changed after exact process admission");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if current_metadata.dev() != metadata.dev() || current_metadata.ino() != metadata.ino() {
            bail!("Grok catalog executable identity changed after exact process admission");
        }
    }
    authorization.consume()?;
    *launch_evidence = Some(evidence);
    let output = run_process(process_spec).context(
        "Grok runtime model catalog command failed before a verified result was available",
    )?;
    if output.process_error.is_some() || output.stdin_error.is_some() {
        bail!("Grok runtime model catalog process ownership cleanup was incomplete");
    }
    Ok(GrokCatalogCommandOutput {
        status: output.status.and_then(|status| status.code()),
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
        stdout_truncated: output.stdout.is_truncated(),
        stderr_truncated: output.stderr.is_truncated(),
        timed_out: output.timed_out,
        process_tree: output.process_tree,
        side_effects: output.side_effects,
    })
}

#[cfg(test)]
fn screened_grok_catalog_process_spec(spec: &GrokCatalogCommandSpec) -> Result<ProcessSpec> {
    let program = resolve_catalog_program(spec.program())?;
    screened_grok_catalog_process_spec_for_program(spec, program)
}

#[cfg(test)]
fn screened_grok_catalog_process_spec_for_program(
    spec: &GrokCatalogCommandSpec,
    program: PathBuf,
) -> Result<ProcessSpec> {
    screened_grok_catalog_process_spec_for_program_with_binding(spec, program)
        .map(|(process_spec, _)| process_spec)
}

fn screened_grok_catalog_process_spec_for_program_with_binding(
    spec: &GrokCatalogCommandSpec,
    program: PathBuf,
) -> Result<(ProcessSpec, String)> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = program;
        bail!("Grok catalog authentication confinement requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let sources = GrokCredentialSource::from_ambient_environment()?;
        let binding = sources.binding_identity();
        screened_grok_catalog_process_spec_with_credential_source(spec, program, &sources)
            .map(|process_spec| (process_spec, binding))
    }
}

/// Admitted host credential/configuration sources for one confined Grok process.
///
/// This capability owns read-only descriptors for the exact files selected by
/// `GROK_HOME`. It deliberately has no byte-reading or serialization API. A
/// caller may retain the normalized source value for preflight/redaction and
/// bind the held files to an [`ExternalGrokProfile`]. The process runner replaces
/// the target's `GROK_HOME` with its private runtime directory and performs
/// another pathname identity check before release.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct GrokCredentialSource {
    grok_home_environment: String,
    auth: GrokCredentialFile,
    config: Option<GrokCredentialFile>,
}

#[cfg(target_os = "linux")]
impl GrokCredentialSource {
    /// Admit the current process's Grok credential source without reading it.
    pub(crate) fn from_ambient_environment() -> Result<Self> {
        let ambient_home = env::var_os("HOME");
        let ambient_grok_home = env::var_os("GROK_HOME");
        Self::from_environment(ambient_home.as_deref(), ambient_grok_home.as_deref())
    }

    /// Derive and admit an absolute, lexically normalized `GROK_HOME`.
    ///
    /// `auth.json` is mandatory. `config.toml` is admitted only when present.
    /// Neither file is read; successful admission retains its descriptor and
    /// the device/inode identity observed through both descriptor and path.
    pub(crate) fn from_environment(
        ambient_home: Option<&OsStr>,
        ambient_grok_home: Option<&OsStr>,
    ) -> Result<Self> {
        let grok_home = match ambient_grok_home {
            Some(grok_home) => PathBuf::from(grok_home),
            None => PathBuf::from(ambient_home.ok_or(GrokCredentialSourceFailure::HomeMissing)?)
                .join(".grok"),
        };
        if !grok_home.is_absolute()
            || grok_home.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(GrokCredentialSourceFailure::HomeNotAbsoluteNormalized.into());
        }
        let grok_home = grok_home.components().collect::<PathBuf>();
        let grok_home_environment = grok_home
            .to_str()
            .ok_or(GrokCredentialSourceFailure::HomeNotUtf8)?
            .to_string();
        let auth = GrokCredentialFile::open(
            grok_home.join(GROK_AUTH_FILE),
            GrokCredentialFileKind::Authentication,
        )?
        .ok_or(GrokCredentialSourceFailure::AuthenticationMissing)?;
        let config = GrokCredentialFile::open(
            grok_home.join(GROK_CONFIG_FILE),
            GrokCredentialFileKind::Configuration,
        )?;
        Ok(Self {
            grok_home_environment,
            auth,
            config,
        })
    }

    /// The only environment value derived from this capability.
    pub(crate) fn grok_home_environment(&self) -> &str {
        &self.grok_home_environment
    }

    fn binding_identity(&self) -> String {
        fn file_identity(file: &GrokCredentialFile) -> String {
            format!(
                "{};dev={};ino={};uid={};mode={};links={}",
                file.path.display(),
                file.identity.device,
                file.identity.inode,
                file.identity.owner,
                file.identity.mode,
                file.identity.links,
            )
        }
        let config = self
            .config
            .as_ref()
            .map(file_identity)
            .unwrap_or_else(|| "none".to_string());
        format!(
            "home={};auth={};config={config}",
            self.grok_home_environment,
            file_identity(&self.auth),
        )
    }

    /// Bind the exact held sources into a Grok confinement profile.
    pub(crate) fn bind_to_profile(
        &self,
        profile: ExternalGrokProfile,
    ) -> Result<ExternalGrokProfile> {
        // Hide the ambient directory at its host pathname even when a caller selected a
        // GROK_HOME outside the roots replaced by ProtectHome/PrivateTmp. Only the held leaves
        // are projected into the run-private GROK_HOME below.
        let profile = profile.with_hidden_root(PathBuf::from(self.grok_home_environment.as_str()));
        let profile = self.auth.bind_to_profile(profile)?;
        match &self.config {
            Some(config) => config.bind_to_profile(profile),
            None => Ok(profile),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for GrokCredentialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrokCredentialSource")
            .field("authentication", &"held read-only source")
            .field("configuration_present", &self.config.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct GrokCredentialFile {
    kind: GrokCredentialFileKind,
    path: PathBuf,
    held_file: Arc<File>,
    identity: GrokCredentialFileIdentity,
}

#[cfg(target_os = "linux")]
impl GrokCredentialFile {
    fn open(path: PathBuf, kind: GrokCredentialFileKind) -> Result<Option<Self>> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error)
                if kind == GrokCredentialFileKind::Configuration
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error)
                if kind == GrokCredentialFileKind::Authentication
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(GrokCredentialSourceFailure::AuthenticationMissing.into());
            }
            Err(_) => return Err(kind.unavailable_failure().into()),
        };
        let identity = file
            .metadata()
            .ok()
            .and_then(|metadata| GrokCredentialFileIdentity::from_metadata(&metadata))
            .ok_or_else(|| anyhow::Error::from(kind.not_regular_failure()))?;
        let observed_identity = std::fs::symlink_metadata(&path)
            .ok()
            .and_then(|metadata| GrokCredentialFileIdentity::from_metadata(&metadata))
            .ok_or_else(|| anyhow::Error::from(kind.identity_changed_failure()))?;
        if observed_identity != identity {
            return Err(kind.identity_changed_failure().into());
        }
        Ok(Some(Self {
            kind,
            path,
            held_file: Arc::new(file),
            identity,
        }))
    }

    fn bind_to_profile(&self, profile: ExternalGrokProfile) -> Result<ExternalGrokProfile> {
        self.revalidate()?;
        profile
            .with_private_grok_home_file_capability(
                &self.path,
                self.kind.file_name(),
                Arc::clone(&self.held_file),
            )
            .map_err(|_| anyhow::Error::from(self.kind.identity_changed_failure()))
    }

    fn revalidate(&self) -> Result<()> {
        let held_identity = self
            .held_file
            .metadata()
            .ok()
            .and_then(|metadata| GrokCredentialFileIdentity::from_metadata(&metadata));
        let observed_identity = std::fs::symlink_metadata(&self.path)
            .ok()
            .and_then(|metadata| GrokCredentialFileIdentity::from_metadata(&metadata));
        if held_identity != Some(self.identity) || observed_identity != Some(self.identity) {
            return Err(self.kind.identity_changed_failure().into());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct GrokCredentialFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

#[cfg(target_os = "linux")]
impl GrokCredentialFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;

        metadata.is_file().then(|| Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrokCredentialFileKind {
    Authentication,
    Configuration,
}

#[cfg(target_os = "linux")]
impl GrokCredentialFileKind {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Authentication => GROK_AUTH_FILE,
            Self::Configuration => GROK_CONFIG_FILE,
        }
    }

    const fn unavailable_failure(self) -> GrokCredentialSourceFailure {
        match self {
            Self::Authentication => GrokCredentialSourceFailure::AuthenticationUnavailable,
            Self::Configuration => GrokCredentialSourceFailure::ConfigurationUnavailable,
        }
    }

    const fn not_regular_failure(self) -> GrokCredentialSourceFailure {
        match self {
            Self::Authentication => GrokCredentialSourceFailure::AuthenticationNotRegular,
            Self::Configuration => GrokCredentialSourceFailure::ConfigurationNotRegular,
        }
    }

    const fn identity_changed_failure(self) -> GrokCredentialSourceFailure {
        match self {
            Self::Authentication => GrokCredentialSourceFailure::AuthenticationIdentityChanged,
            Self::Configuration => GrokCredentialSourceFailure::ConfigurationIdentityChanged,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrokCredentialSourceFailure {
    HomeMissing,
    HomeNotAbsoluteNormalized,
    HomeNotUtf8,
    AuthenticationMissing,
    AuthenticationUnavailable,
    AuthenticationNotRegular,
    AuthenticationIdentityChanged,
    ConfigurationUnavailable,
    ConfigurationNotRegular,
    ConfigurationIdentityChanged,
}

#[cfg(target_os = "linux")]
impl fmt::Display for GrokCredentialSourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HomeMissing => "Grok credential source requires HOME or GROK_HOME",
            Self::HomeNotAbsoluteNormalized => {
                "Grok credential state home must be an absolute normalized path"
            }
            Self::HomeNotUtf8 => "Grok credential state home is not valid UTF-8",
            Self::AuthenticationMissing => "Grok authentication source auth.json is missing",
            Self::AuthenticationUnavailable => {
                "Grok authentication source auth.json is unavailable"
            }
            Self::AuthenticationNotRegular => {
                "Grok authentication source auth.json is not a regular file"
            }
            Self::AuthenticationIdentityChanged => {
                "Grok authentication source auth.json identity changed"
            }
            Self::ConfigurationUnavailable => {
                "Grok configuration source config.toml is unavailable"
            }
            Self::ConfigurationNotRegular => {
                "Grok configuration source config.toml is not a regular file"
            }
            Self::ConfigurationIdentityChanged => {
                "Grok configuration source config.toml identity changed"
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for GrokCredentialSourceFailure {}

#[cfg(all(target_os = "linux", test))]
fn screened_grok_catalog_process_spec_with_sources(
    spec: &GrokCatalogCommandSpec,
    program: PathBuf,
    ambient_home: Option<&OsStr>,
    ambient_grok_home: Option<&OsStr>,
) -> Result<ProcessSpec> {
    let sources = GrokCredentialSource::from_environment(ambient_home, ambient_grok_home)?;
    screened_grok_catalog_process_spec_with_credential_source(spec, program, &sources)
}

#[cfg(target_os = "linux")]
fn screened_grok_catalog_process_spec_with_credential_source(
    spec: &GrokCatalogCommandSpec,
    program: PathBuf,
    sources: &GrokCredentialSource,
) -> Result<ProcessSpec> {
    let mut environment = spec.environment().clone();
    environment.insert(
        "GROK_HOME".to_string(),
        sources.grok_home_environment().to_string(),
    );
    let profile = sources.bind_to_profile(ExternalGrokProfile::read_only(spec.current_dir()))?;
    Ok(ProcessSpec::direct(
        "Grok runtime model catalog",
        program,
        spec.args().iter().cloned(),
        spec.current_dir(),
        spec.capture_limit_bytes(),
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(spec.timeout()))
    .with_private_runtime_home(true)
    .with_private_runtime_grok_home(true)
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalGrok(profile)))
}

fn resolve_catalog_program(program: &Path) -> Result<PathBuf> {
    let program_override =
        (program != Path::new(TRUSTED_SYSTEM_GROK_EXECUTABLE)).then_some(program.as_os_str());
    resolve_configured_grok_executable(program_override).with_context(|| {
        format!(
            "Grok catalog executable '{}' is unavailable",
            program.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_runner::{ContainmentBackend, ProcessCommand};
    use std::{cell::RefCell, fs};

    const CAPTURED_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260821.txt"
    ));
    const HAND_AUTHORED_DUPLICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-duplicate.txt"
    ));
    const HAND_AUTHORED_MALFORMED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-malformed.txt"
    ));
    const HAND_AUTHORED_TRUNCATED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-truncated.txt"
    ));
    const HAND_AUTHORED_ADDED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-added.txt"
    ));
    const HAND_AUTHORED_WITHDRAWN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-withdrawn.txt"
    ));
    const CAPTURED_PROVENANCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260821.provenance.json"
    ));
    const WRITABLE_MANAGED_CHILD_STREAM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/writable-managed-child.streaming-json"
    ));
    const CAPTURED_AT_UNIX_MILLIS: u64 = 1_787_303_960_000;

    fn worker_entry() -> Result<GrokModelCatalogEntry> {
        GrokModelCatalogEntry::new("worker-stable", "Worker Stable")
    }

    #[derive(Debug)]
    struct FakeRunner {
        output: GrokCatalogCommandOutput,
        observed_specs: RefCell<Vec<GrokCatalogCommandSpec>>,
    }

    impl FakeRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: GrokCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: ProcessTreeEvidence::VerifiedEmpty(
                        ContainmentBackend::DirectChild,
                    ),
                    side_effects: SideEffectConfinementEvidence::Verified(
                        SideEffectConfinementProfileKind::ExternalGrok,
                    ),
                },
                observed_specs: RefCell::new(Vec::new()),
            }
        }
    }

    impl GrokCatalogCommandRunner for FakeRunner {
        fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput> {
            self.observed_specs.borrow_mut().push(spec.clone());
            Ok(self.output.clone())
        }
    }

    fn listing(default: &str, model_lines: &[String]) -> Vec<u8> {
        let mut text = format!(
            "You are logged in with grok.com.\n\nDefault model: {default}\n\nAvailable models:\n"
        );
        if !model_lines.is_empty() {
            text.push_str(&model_lines.join("\n"));
            text.push('\n');
        }
        text.into_bytes()
    }

    #[test]
    fn grok_headless_command_template_contract_is_exact() {
        assert_eq!(GROK_RUNTIME_DESCRIPTOR.executable(), "grok");
        assert_eq!(GROK_RUNTIME_DESCRIPTOR.output_format(), "streaming-json");
        assert_eq!(GROK_RUNTIME_DESCRIPTOR.sandbox_profile(), "strict");
        assert_eq!(
            GROK_RUNTIME_DESCRIPTOR.headless_approval_flag(),
            "--always-approve"
        );
        assert!(GROK_RUNTIME_DESCRIPTOR.subagents_disabled());
        assert!(GROK_RUNTIME_DESCRIPTOR.memory_disabled());
        assert!(GROK_RUNTIME_DESCRIPTOR.web_search_disabled());
        assert_eq!(
            GROK_RUNTIME_DESCRIPTOR.immutable_argument_template(),
            [
                "--prompt-file",
                "{prompt}",
                "--model",
                "{model}",
                "--reasoning-effort",
                "{effort}",
                "--cwd",
                "{cwd}",
                "--output-format",
                "streaming-json",
                "--sandbox",
                "strict",
                "--always-approve",
                "--disable-web-search",
                "--no-memory",
                "--no-subagents",
            ]
        );
    }

    #[test]
    fn grok_output_schema_loader_is_bounded_validated_and_compact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let schema = temp.path().join("worker-report.schema.json");
        fs::write(
            &schema,
            "{\n  \"type\": \"object\", \"properties\": {\"accepted\": {\"type\": \"boolean\"}}\n}\n",
        )?;
        assert_eq!(
            load_grok_output_schema_argv(&schema)?,
            r#"{"properties":{"accepted":{"type":"boolean"}},"type":"object"}"#
        );

        let non_object = temp.path().join("non-object.json");
        fs::write(&non_object, "[]")?;
        let error = load_grok_output_schema_argv(&non_object)
            .expect_err("non-object schema must fail closed")
            .to_string();
        assert!(error.contains("must be a JSON object"), "{error}");

        let oversized = temp.path().join("oversized.json");
        fs::write(
            &oversized,
            vec![b' '; GROK_OUTPUT_SCHEMA_MAX_BYTES as usize + 1],
        )?;
        let error = load_grok_output_schema_argv(&oversized)
            .expect_err("oversized schema must fail closed")
            .to_string();
        assert!(error.contains("bounded Grok output schema"), "{error}");
        Ok(())
    }

    #[test]
    fn terminal_end_event_alone_carries_structured_output() -> Result<()> {
        let parsed = parse_grok_event_stream(
            concat!(
                "{\"type\":\"text\",\"data\":\"ordinary progress\"}\n",
                "{\"type\":\"end\",\"stopReason\":\"EndTurn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\",\"structuredOutput\":{\"z\":1,\"a\":true}}\n",
            )
            .as_bytes(),
        )?;
        let GrokStreamOutcome::Completed(end) = parsed.outcome() else {
            panic!("structured stream did not complete");
        };
        assert_eq!(
            end.structured_output(),
            Some(&serde_json::json!({"a": true, "z": 1}))
        );
        assert!(end.structured_output_error().is_none());
        assert_eq!(parsed.usage_status(), GrokUsageStatus::NotProcessObservable);
        assert_eq!(
            canonical_grok_structured_output(end.structured_output().unwrap())?,
            br#"{"a":true,"z":1}"#.to_vec()
        );

        let misplaced = concat!(
            "{\"type\":\"text\",\"data\":\"progress\",\"structuredOutput\":{}}\n",
            "{\"type\":\"end\",\"stopReason\":\"EndTurn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
        );
        let error = parse_grok_event_stream(misplaced.as_bytes())
            .expect_err("non-terminal structured output must fail closed")
            .to_string();
        assert!(error.contains("outside the terminal end event"), "{error}");
        Ok(())
    }

    #[test]
    fn structured_output_must_be_an_object_within_the_publication_bound() {
        let non_object = canonical_grok_structured_output(&serde_json::json!(["report"]))
            .expect_err("array output must fail closed")
            .to_string();
        assert!(non_object.contains("not a JSON object"), "{non_object}");

        let oversized = serde_json::json!({
            "report": "x".repeat(GROK_STRUCTURED_OUTPUT_MAX_BYTES)
        });
        let error = canonical_grok_structured_output(&oversized)
            .expect_err("oversized structured output must fail closed")
            .to_string();
        assert!(error.contains("exceeds the 8388608 byte limit"), "{error}");
    }

    #[test]
    fn documented_streaming_json_contract_parses_to_one_completed_response() -> Result<()> {
        let bytes = concat!(
            "{\"type\":\"text\",\"data\":\"Here's\"}\n",
            "{\"type\":\"text\",\"data\":\" a summary\"}\n",
            "{\"type\":\"thought\",\"data\":\"Analyzing the directory structure...\"}\n",
            "{\"type\":\"end\",\"stopReason\":\"EndTurn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
        )
        .as_bytes();

        let parsed = parse_grok_event_stream(bytes)?;
        assert!(parsed.completed());
        assert_eq!(parsed.response_text(), "Here's a summary");
        assert_eq!(parsed.events().len(), 4);
        assert!(matches!(
            &parsed.events()[0],
            GrokStreamEvent::Text(data) if data == "Here's"
        ));
        assert!(matches!(
            &parsed.events()[2],
            GrokStreamEvent::Thought(data) if data == "Analyzing the directory structure..."
        ));
        let GrokStreamOutcome::Completed(end) = parsed.outcome() else {
            panic!("documented stream did not produce a completed outcome");
        };
        assert_eq!(end.stop_reason(), "EndTurn");
        assert_eq!(end.session_id(), "abc123");
        assert_eq!(end.request_id(), "xyz789");
        assert_eq!(parsed.usage_status(), GrokUsageStatus::NotProcessObservable);
        Ok(())
    }

    #[test]
    fn streaming_json_error_is_a_terminal_failed_outcome() -> Result<()> {
        let parsed = parse_grok_event_stream(
            b"{\"type\":\"error\",\"message\":\"Couldn't start session\"}\n",
        )?;
        assert!(!parsed.completed());
        assert!(parsed.response_text().is_empty());
        assert!(matches!(
            parsed.outcome(),
            GrokStreamOutcome::Failed { message } if message == "Couldn't start session"
        ));
        assert!(matches!(
            parsed.events(),
            [GrokStreamEvent::Error(message)] if message == "Couldn't start session"
        ));
        assert_eq!(parsed.usage_status(), GrokUsageStatus::NotProcessObservable);
        Ok(())
    }

    #[test]
    fn terminal_end_event_parses_only_exact_native_usage_fields() -> Result<()> {
        let parsed = parse_grok_event_stream(
            concat!(
                "{\"type\":\"usage\",\"messageId\":\"resp_1\",\"stopReason\":\"end_turn\",\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}\n",
                "{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\",\"usage\":{\"input_tokens\":12,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":0,\"output_tokens\":5,\"reasoning_tokens\":2,\"total_tokens\":21,\"cached_input_tokens\":99}}\n",
            )
            .as_bytes(),
        )?;
        assert!(matches!(
            &parsed.events()[0],
            GrokStreamEvent::Other { event_type } if event_type == "usage"
        ));
        let GrokUsageStatus::Native(usage) = parsed.usage_status() else {
            panic!("native end usage must be process-observable as exact Grok fields");
        };
        assert_eq!(usage.input_tokens(), 12);
        assert_eq!(usage.output_tokens(), 5);
        assert_eq!(usage.cache_read_input_tokens(), Some(4));
        assert_eq!(usage.cache_creation_input_tokens(), Some(0));
        assert_eq!(usage.reasoning_tokens(), Some(2));
        assert_eq!(usage.total_tokens(), Some(21));
        Ok(())
    }

    #[test]
    fn incomplete_or_omitted_native_spend_is_not_fabricated_into_counts() -> Result<()> {
        let omitted = parse_grok_event_stream(
            b"{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
        )?;
        assert_eq!(omitted.usage_status().as_str(), "not_process_observable");

        let incomplete = parse_grok_event_stream(
            concat!(
                "{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\",",
                "\"usage_is_incomplete\":true,\"usage\":{\"input_tokens\":8,\"output_tokens\":2}}\n",
            )
            .as_bytes(),
        )?;
        assert_eq!(incomplete.usage_status(), GrokUsageStatus::Incomplete);
        Ok(())
    }

    #[test]
    fn grok_parser_refuses_codex_usage_events_and_text_spend() {
        let error = parse_grok_event_stream(
            concat!(
                "{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}\n",
                "{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
            )
            .as_bytes(),
        )
        .expect_err("Codex turn.completed is not a Grok event");
        let codex = format!("{error:#}");
        assert!(codex.contains("invalid event type"), "{codex}");

        let misplaced = parse_grok_event_stream(
            concat!(
                "{\"type\":\"text\",\"data\":\"progress\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n",
                "{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
            )
            .as_bytes(),
        )
        .expect_err("text events may not carry spend")
        .to_string();
        assert!(
            misplaced.contains("places usage outside the terminal end event"),
            "{misplaced}"
        );
    }

    #[test]
    fn malformed_or_overflowing_native_usage_fails_closed() {
        let cases = [
            (
                "missing required output_tokens",
                b"{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":1}}\n".as_slice(),
            ),
            (
                "negative input_tokens",
                b"{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":-1,\"output_tokens\":1}}\n".as_slice(),
            ),
            (
                "overflowing output_tokens",
                b"{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":1,\"output_tokens\":18446744073709551616}}\n".as_slice(),
            ),
        ];

        for (label, bytes) in cases {
            let error = parse_grok_event_stream(bytes).expect_err(label).to_string();
            assert!(error.contains("is malformed"), "{label}: {error}");
        }
    }

    #[test]
    fn hermetic_managed_child_stream_fixture_is_schema_bound_native_usage() -> Result<()> {
        let parsed = parse_grok_event_stream(WRITABLE_MANAGED_CHILD_STREAM)?;
        assert!(parsed.completed());
        assert_eq!(parsed.response_text(), "claimed path written");
        let GrokStreamOutcome::Completed(end) = parsed.outcome() else {
            panic!("fixture stream must complete");
        };
        assert_eq!(
            end.structured_output(),
            Some(&serde_json::json!({"accepted": true, "path": "bounded-result.txt"}))
        );
        let GrokUsageStatus::Native(usage) = parsed.usage_status() else {
            panic!("fixture end event carries exact native usage");
        };
        assert_eq!(usage.input_tokens(), 12);
        assert_eq!(usage.output_tokens(), 4);
        assert_eq!(usage.total_tokens(), Some(16));
        assert!(!std::str::from_utf8(WRITABLE_MANAGED_CHILD_STREAM)?.contains("turn.completed"));
        Ok(())
    }

    #[test]
    fn streaming_json_parser_fails_closed_on_incomplete_or_mixed_streams() {
        let cases = [
            ("empty", b"".as_slice(), "output was empty"),
            (
                "missing terminal newline",
                b"{\"type\":\"error\",\"message\":\"failed\"}".as_slice(),
                "lacks its terminal newline",
            ),
            (
                "missing terminal event",
                b"{\"type\":\"text\",\"data\":\"partial\"}\n".as_slice(),
                "has no terminal",
            ),
            (
                "data after terminal event",
                concat!(
                    "{\"type\":\"end\",\"stopReason\":\"EndTurn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
                    "{\"type\":\"text\",\"data\":\"late\"}\n",
                )
                .as_bytes(),
                "contains data after",
            ),
            (
                "fields from incompatible event types",
                concat!(
                    "{\"type\":\"text\",\"data\":\"mixed\",\"message\":\"wrong\"}\n",
                    "{\"type\":\"end\",\"stopReason\":\"EndTurn\",\"sessionId\":\"abc123\",\"requestId\":\"xyz789\"}\n",
                )
                .as_bytes(),
                "mixes fields",
            ),
            (
                "malformed JSON",
                b"{\"type\":\"end\"\n".as_slice(),
                "is malformed",
            ),
        ];

        for (label, bytes, expected) in cases {
            let error = parse_grok_event_stream(bytes).expect_err(label).to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }

        let oversized = vec![b'x'; GROK_EVENT_STREAM_MAX_BYTES.saturating_add(1)];
        let error = parse_grok_event_stream(&oversized)
            .expect_err("oversized stream")
            .to_string();
        assert!(error.contains("exceeds the 8388608 byte limit"), "{error}");
    }

    #[test]
    fn constructed_catalog_rejects_empty_duplicate_and_overlong_membership() -> Result<()> {
        let error = GrokModelCatalog::from_injected_entries(Vec::new())
            .expect_err("empty catalog must fail closed")
            .to_string();
        assert!(error.contains("contains no models"), "{error}");

        let duplicate = GrokModelCatalog::from_injected_entries([
            worker_entry()?,
            GrokModelCatalogEntry::new("worker-stable", "Worker Stable Duplicate")?,
        ])
        .expect_err("duplicate catalog must fail closed")
        .to_string();
        assert!(duplicate.contains("duplicate slug"), "{duplicate}");

        let too_many = (0..=GROK_CATALOG_MAX_MODELS)
            .map(|index| {
                GrokModelCatalogEntry::new(format!("worker-{index}"), format!("Worker {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let overflow = GrokModelCatalog::from_injected_entries(too_many)
            .expect_err("overlong catalog must fail closed")
            .to_string();
        assert!(overflow.contains("513 models"), "{overflow}");
        Ok(())
    }

    #[test]
    fn entry_construction_validates_slug_and_display_name() {
        assert!(GrokModelCatalogEntry::new("", "Worker").is_err());
        assert!(GrokModelCatalogEntry::new("-leading", "Worker").is_err());
        assert!(GrokModelCatalogEntry::new("worker-stable", " leading").is_err());
        assert!(GrokModelCatalogEntry::new("worker-stable", "Worker Stable").is_ok());
    }

    #[test]
    fn missing_time_and_empty_source_fail_closed() -> Result<()> {
        let catalog = GrokModelCatalog::from_injected_entries([worker_entry()?])?;
        for observed_at in [None, Some(0)] {
            let error = inject_grok_advertised_catalog(catalog.clone(), observed_at, b"source")
                .expect_err("missing observation time must fail closed")
                .to_string();
            assert!(error.contains("missing or zero"), "{error}");
        }
        let error = inject_grok_advertised_catalog(catalog, Some(1), b"")
            .expect_err("empty source must fail closed")
            .to_string();
        assert!(error.contains("source bytes were empty"), "{error}");
        Ok(())
    }

    #[test]
    fn digest_binds_runtime_entries_and_source_bytes() -> Result<()> {
        let catalog = GrokModelCatalog::from_injected_entries([worker_entry()?])?;
        let observation =
            inject_grok_advertised_catalog(catalog.clone(), Some(1_787_240_463_000), b"alpha")?;
        assert_eq!(observation.runtime(), AdapterId::Grok);
        assert!(catalog.contains("worker-stable"));
        assert_ne!(observation.source_sha256(), sha256_hex(b"alpha"));

        let retargeted = inject_grok_advertised_catalog(catalog, Some(1_787_240_463_000), b"beta")?;
        assert_ne!(observation.source_sha256(), retargeted.source_sha256());

        let other = GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
            "worker-other",
            "Worker Other",
        )?])?;
        let other_observation =
            inject_grok_advertised_catalog(other, Some(1_787_240_463_000), b"alpha")?;
        assert_ne!(
            observation.source_sha256(),
            other_observation.source_sha256()
        );
        Ok(())
    }

    #[test]
    fn command_spec_is_exact_and_discovery_uses_only_the_injected_runner() -> Result<()> {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        assert_eq!(spec.program(), Path::new(default_grok_executable()));
        assert!(spec.program().is_absolute());
        assert_eq!(spec.args(), [OsString::from("models")]);
        assert_eq!(
            spec.environment(),
            &BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ])
        );
        assert_eq!(spec.current_dir(), Path::new("/workspace"));
        assert_eq!(spec.capture_limit_bytes(), GROK_CATALOG_MAX_BYTES);
        assert_eq!(spec.timeout(), GROK_CATALOG_TIMEOUT);

        let runner = FakeRunner::successful(CAPTURED_CATALOG);
        let observation =
            discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))?;
        assert_eq!(runner.observed_specs.into_inner(), [spec]);
        let catalog = observation.catalog();
        let parsed = parse_grok_model_catalog(CAPTURED_CATALOG)?;
        let injected = inject_grok_advertised_catalog(
            parsed,
            Some(CAPTURED_AT_UNIX_MILLIS),
            CAPTURED_CATALOG,
        )?;
        assert_eq!(observation, injected);
        assert_eq!(catalog.models().len(), 2);
        assert!(catalog.contains("grok-4.6"));
        assert!(catalog.contains("grok-4.5"));
        assert_eq!(observation.runtime(), AdapterId::Grok);
        assert_eq!(
            observation.observed_at_unix_millis(),
            CAPTURED_AT_UNIX_MILLIS
        );
        assert_ne!(observation.source_sha256(), sha256_hex(CAPTURED_CATALOG));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_grok_entry_resolves_to_one_canonical_absolute_identity() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let executable = temp.path().join("grok-real");
        fs::write(&executable, "fixture")?;
        let trusted_entry = temp.path().join("grok");
        symlink(&executable, &trusted_entry)?;
        let resolved = resolve_grok_executable_candidate(&trusted_entry, true)?;
        assert!(resolved.is_absolute());
        assert_eq!(resolved, std::fs::canonicalize(executable)?);
        assert!(!std::fs::symlink_metadata(&resolved)?
            .file_type()
            .is_symlink());
        Ok(())
    }

    #[test]
    fn relative_explicit_grok_override_fails_closed_without_path_search() {
        let error = resolve_configured_grok_executable(Some(OsStr::new("relative/grok")))
            .expect_err("relative MACO_GROK_BIN must fail closed")
            .to_string();
        assert!(
            error.contains("MACO_GROK_BIN must be an absolute path"),
            "{error}"
        );
        assert!(error.contains("ambient PATH"), "{error}");
    }

    #[test]
    fn captured_catalog_preserves_runtime_order_and_uses_slug_labels() -> Result<()> {
        let catalog = parse_grok_model_catalog(CAPTURED_CATALOG)?;
        assert_eq!(
            catalog
                .models()
                .iter()
                .map(|entry| (entry.slug(), entry.display_name()))
                .collect::<Vec<_>>(),
            [("grok-4.6", "grok-4.6"), ("grok-4.5", "grok-4.5")]
        );
        Ok(())
    }

    #[test]
    fn captured_fixture_provenance_is_adjacent_exact_and_content_bound() -> Result<()> {
        let provenance: serde_json::Value = serde_json::from_str(CAPTURED_PROVENANCE)?;
        assert_eq!(provenance["schema_version"], 1);
        assert_eq!(provenance["fixture"], "captured-minimal-20260821.txt");
        assert_eq!(provenance["classification"], "capture-derived-minimal");
        assert_eq!(provenance["captured_at_utc"], "2026-08-21T09:19:20Z");
        assert_eq!(provenance["cli"], "grok");
        assert_eq!(provenance["cli_version"], "0.2.93 (f00f96316d)");
        assert_eq!(provenance["argv"], serde_json::json!(["grok", "models"]));
        assert_eq!(provenance["environment"]["NO_COLOR"], "1");
        assert_eq!(provenance["environment"]["TERM"], "dumb");
        assert_eq!(provenance["exit_status"], 0);
        assert_eq!(provenance["redactions"], "none");
        assert_eq!(provenance["fixture_sha256"], sha256_hex(CAPTURED_CATALOG));
        assert_eq!(
            provenance["scope_note"],
            "This capture-derived minimal fixture is not a full unabridged archive."
        );
        Ok(())
    }

    #[test]
    fn catalog_addition_and_withdrawal_require_no_parser_change() -> Result<()> {
        let added = parse_grok_model_catalog(HAND_AUTHORED_ADDED)?;
        let withdrawn = parse_grok_model_catalog(HAND_AUTHORED_WITHDRAWN)?;
        assert!(added.contains("worker-new"));
        assert!(!withdrawn.contains("worker-new"));
        assert_eq!(withdrawn.slugs().collect::<Vec<_>>(), ["worker-stable"]);
        Ok(())
    }

    #[test]
    fn malformed_duplicate_empty_and_structurally_truncated_catalogs_fail_closed() {
        for (label, bytes, expected) in [
            ("malformed", HAND_AUTHORED_MALFORMED, "malformed"),
            ("duplicate", HAND_AUTHORED_DUPLICATE, "duplicate slug"),
            ("empty", b"".as_slice(), "output was empty"),
            (
                "truncated",
                HAND_AUTHORED_TRUNCATED,
                "lacks its terminal newline",
            ),
        ] {
            let error = parse_grok_model_catalog(bytes)
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn parser_limits_and_structural_edges_fail_closed_table() {
        let too_many_models = std::iter::once("  * worker-0 (default)".to_string())
            .chain((1..=GROK_CATALOG_MAX_MODELS).map(|index| format!("  - worker-{index}")))
            .collect::<Vec<_>>();
        let invalid_utf8 = [
            b"You are logged in with grok.com.\n\nDefault model: ".as_slice(),
            &[0xff],
            b"\n",
        ]
        .concat();
        let cases = vec![
            (
                "over catalog byte limit",
                vec![b'x'; GROK_CATALOG_MAX_BYTES.saturating_add(1)],
                "exceeds the 262144 byte limit",
            ),
            (
                "over model count limit",
                listing("worker-0", &too_many_models),
                "513 models",
            ),
            (
                "overlong slug",
                listing(
                    "worker",
                    &[format!(
                        "  * {} (default)",
                        "a".repeat(GROK_MODEL_SLUG_MAX_BYTES.saturating_add(1))
                    )],
                ),
                "model slug exceeds",
            ),
            ("invalid utf8", invalid_utf8, "not valid UTF-8"),
            (
                "bare carriage return",
                b"You are logged in with grok.com.\n\nDefault model: worker\rstable\n\nAvailable models:\n  * worker (default)\n".to_vec(),
                "bare carriage return",
            ),
            (
                "trailing footer content",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-stable (default)".to_string(),
                        String::new(),
                        "Tip: unexpected".to_string(),
                    ],
                ),
                "malformed",
            ),
            (
                "missing default marker",
                listing("worker-stable", &["  - worker-stable".to_string()]),
                "missing its default marker",
            ),
            (
                "default marker mismatch",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-other (default)".to_string(),
                        "  - worker-stable".to_string(),
                    ],
                ),
                "does not match header",
            ),
            (
                "two default markers",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-stable (default)".to_string(),
                        "  * worker-new (default)".to_string(),
                    ],
                ),
                "more than one default marker",
            ),
            (
                "invalid login provider",
                b"You are logged in with not a host.\n\nDefault model: worker-stable\n\nAvailable models:\n  * worker-stable (default)\n".to_vec(),
                "invalid login provider",
            ),
        ];

        for (label, bytes, expected) in cases {
            let error = parse_grok_model_catalog(&bytes).expect_err(label);
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn nonzero_timeout_and_truncation_command_evidence_fail_closed() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        type EvidenceMutation = fn(&mut GrokCatalogCommandOutput);
        let cases: [(&str, EvidenceMutation, &str); 5] = [
            (
                "nonzero",
                |output: &mut GrokCatalogCommandOutput| output.status = Some(7),
                "exit status Some(7)",
            ),
            (
                "timeout",
                |output: &mut GrokCatalogCommandOutput| output.timed_out = true,
                "timed out",
            ),
            (
                "stdout truncated",
                |output: &mut GrokCatalogCommandOutput| output.stdout_truncated = true,
                "exceeded",
            ),
            (
                "stderr truncated",
                |output: &mut GrokCatalogCommandOutput| output.stderr_truncated = true,
                "exceeded",
            ),
            (
                "successful command emitted stderr",
                |output: &mut GrokCatalogCommandOutput| {
                    output.stderr = b"unexpected warning".to_vec()
                },
                "unexpected stderr",
            ),
        ];
        for (label, mutate, expected) in cases {
            let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
            mutate(&mut runner.output);
            let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn unverified_process_and_side_effect_evidence_fail_closed_table() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        let cases = [
            (
                "best-effort process ownership",
                ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "process ownership was not verified empty",
            ),
            (
                "unverified process ownership",
                ProcessTreeEvidence::Unverified(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "process ownership was not verified empty",
            ),
            (
                "best-effort side effects",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::TrustedBestEffort(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "unverified side effects",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "compatibility profile cannot be promoted by a runner",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedCompatibility,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "Codex-specific profile is not Grok evidence",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                "side-effect confinement was not verified",
            ),
        ];

        for (label, process_tree, side_effects, expected) in cases {
            let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
            runner.output.process_tree = process_tree;
            runner.output.side_effects = side_effects;
            let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn missing_or_zero_observation_time_fails_before_runner_dispatch() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        for observed_at in [None, Some(0)] {
            let runner = FakeRunner::successful(CAPTURED_CATALOG);
            let error = discover_grok_model_catalog(&runner, &spec, observed_at)
                .expect_err("missing observation time must fail closed")
                .to_string();
            assert!(error.contains("missing or zero"), "{error}");
            assert!(runner.observed_specs.into_inner().is_empty());
        }
    }

    #[test]
    fn runner_cannot_clear_the_truncation_flag_on_oversized_evidence() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
        runner.output.stderr = vec![b'x'; spec.capture_limit_bytes().saturating_add(1)];

        let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
            .expect_err("oversized runner evidence must fail closed")
            .to_string();
        assert!(error.contains("larger than"), "{error}");
    }

    #[test]
    fn slug_and_marker_validation_fail_closed() {
        for invalid_line in [
            "  * -leading (default)",
            "  - bad slug",
            "  * worker-stable",
            "  - worker-stable (default)",
        ] {
            let fixture = listing("worker-stable", &[invalid_line.to_string()]);
            assert!(
                parse_grok_model_catalog(&fixture).is_err(),
                "{invalid_line}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn screened_process_spec_is_bounded_cleared_and_confined() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join("catalog-standin");
        fs::write(&program, "")?;
        let grok_home = dir.path().join("reviewed-grok-home");
        fs::create_dir(&grok_home)?;
        let auth = grok_home.join(GROK_AUTH_FILE);
        let config = grok_home.join(GROK_CONFIG_FILE);
        fs::write(&auth, "hermetic-auth-fixture")?;
        fs::write(&config, "hermetic-config-fixture")?;
        let spec = GrokCatalogCommandSpec::new(dir.path()).with_program(&program);
        let process = screened_grok_catalog_process_spec_with_sources(
            &spec,
            program.clone(),
            None,
            Some(grok_home.as_os_str()),
        )?;
        match &process.command {
            ProcessCommand::Direct {
                program: observed_program,
                args,
            } => {
                assert_eq!(observed_program, &program);
                assert_eq!(args, &spec.args());
            }
            other => panic!("expected a direct catalog command, got {other:?}"),
        }
        let EnvironmentMode::ClearAndSet(environment) = &process.environment else {
            panic!("screened catalog environment must be ClearAndSet");
        };
        assert_eq!(environment.get("NO_COLOR").map(String::as_str), Some("1"));
        assert_eq!(environment.get("TERM").map(String::as_str), Some("dumb"));
        assert!(!environment.contains_key("PATH"));
        assert!(!environment.contains_key("HOME"));
        assert!(!environment.contains_key("TMPDIR"));
        assert_eq!(
            environment.get("GROK_HOME").map(String::as_str),
            grok_home.to_str()
        );
        assert!(process.private_runtime_home);
        assert!(process.private_runtime_grok_home);
        let private_home = Path::new("/run/user/1000/maco-test-runtime");
        let EnvironmentMode::ClearAndSet(private_environment) =
            crate::process_runner::private_runtime_environment_for_test(&process, private_home)?
        else {
            panic!("screened catalog private environment must remain ClearAndSet");
        };
        for key in ["HOME", "TMPDIR", "GROK_HOME"] {
            assert_eq!(
                private_environment.get(key).map(String::as_str),
                private_home.to_str(),
                "{key} must use the per-launch writable runtime home"
            );
        }
        assert_eq!(process.stdin, StdinMode::Null);
        assert_eq!(process.timeout, Some(GROK_CATALOG_TIMEOUT));
        assert_eq!(process.stdout.max_bytes, GROK_CATALOG_MAX_BYTES);
        assert_eq!(process.stderr.max_bytes, GROK_CATALOG_MAX_BYTES);
        assert_eq!(
            process.side_effects.kind(),
            SideEffectConfinementProfileKind::ExternalGrok
        );
        let SideEffectConfinementProfile::ExternalGrok(profile) = &process.side_effects else {
            panic!("screened catalog must use ExternalGrok confinement");
        };
        assert_eq!(
            profile.workspace_access(),
            crate::process_runner::WorkspaceAccess::ReadOnly
        );
        assert!(profile.visible_read_only_roots().is_empty());
        assert_eq!(
            profile.visible_read_only_files(),
            &[auth.clone(), config.clone()],
            "only the exact reviewed identity/config leaves may escape ProtectHome=tmpfs"
        );
        assert!(profile.visible_read_write_roots().is_empty());
        assert!(profile.visible_read_write_files().is_empty());
        let properties = crate::process_runner::external_grok_systemd_properties_for_test(
            profile.clone(),
            &program,
            dir.path(),
        )?;
        assert!(properties.contains(&format!(
            "--property=InaccessiblePaths={}",
            grok_home.display()
        )));
        for (source, name) in [(&auth, GROK_AUTH_FILE), (&config, GROK_CONFIG_FILE)] {
            let target = private_home.join(name);
            assert!(properties.contains(&format!(
                "--property=BindReadOnlyPaths={}:{}",
                source.display(),
                target.display()
            )));
            assert!(properties.contains(&format!("--property=ReadOnlyPaths={}", target.display())));
            assert!(
                !properties.contains(&format!(
                    "--property=BindReadOnlyPaths={}",
                    source.display()
                )),
                "the ambient credential path must not be mounted at its host location"
            );
            assert!(
                !properties.contains(&format!("--property=ReadWritePaths={}", target.display())),
                "projected credential/config leaves must never become writable"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn screened_catalog_state_sources_fail_closed_when_missing_or_malformed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join("catalog-standin");
        fs::write(&program, "")?;
        let spec = GrokCatalogCommandSpec::new(dir.path()).with_program(&program);

        let missing_home = match GrokCredentialSource::from_environment(None, None) {
            Ok(_) => panic!("ambient home omission must fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(missing_home.contains("HOME or GROK_HOME"), "{missing_home}");

        let relative = match GrokCredentialSource::from_environment(
            None,
            Some(OsStr::new("relative/.grok")),
        ) {
            Ok(_) => panic!("relative state home must fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(relative.contains("absolute normalized"), "{relative}");

        let missing_auth_home = dir.path().join("missing-auth");
        fs::create_dir(&missing_auth_home)?;
        let missing_auth = screened_grok_catalog_process_spec_with_sources(
            &spec,
            program.clone(),
            None,
            Some(missing_auth_home.as_os_str()),
        )
        .expect_err("missing authentication source must fail closed")
        .to_string();
        assert!(missing_auth.contains(GROK_AUTH_FILE), "{missing_auth}");

        let malformed_config_home = dir.path().join("malformed-config");
        fs::create_dir(&malformed_config_home)?;
        fs::write(
            malformed_config_home.join(GROK_AUTH_FILE),
            "hermetic-auth-fixture",
        )?;
        fs::create_dir(malformed_config_home.join(GROK_CONFIG_FILE))?;
        let malformed_config = screened_grok_catalog_process_spec_with_sources(
            &spec,
            program,
            None,
            Some(malformed_config_home.as_os_str()),
        )
        .expect_err("non-file configuration source must fail closed");
        let malformed_config = format!("{malformed_config:#}");
        assert!(
            malformed_config.contains("not a regular file"),
            "{malformed_config}"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grok_credential_source_rejects_symlink_and_replaced_files() -> Result<()> {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir()?;
        let grok_home = dir.path().join("grok-home");
        fs::create_dir(&grok_home)?;
        let external = dir.path().join("external-secret-source");
        fs::write(&external, "synthetic-secret-fixture")?;
        let auth = grok_home.join(GROK_AUTH_FILE);
        let config = grok_home.join(GROK_CONFIG_FILE);

        symlink(&external, &auth)?;
        let auth_symlink =
            GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))
                .expect_err("a symlink authentication source must be refused")
                .to_string();
        assert!(auth_symlink.contains("auth.json is unavailable"));

        fs::remove_file(&auth)?;
        fs::write(&auth, "admitted-auth-fixture")?;
        symlink(&external, &config)?;
        let config_symlink =
            GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))
                .expect_err("a symlink configuration source must be refused")
                .to_string();
        assert!(config_symlink.contains("config.toml is unavailable"));

        fs::remove_file(&config)?;
        fs::write(&config, "admitted-config-fixture")?;
        let auth_source =
            GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))?;
        let replacement_auth = grok_home.join("replacement-auth");
        fs::write(&replacement_auth, "replacement-auth-fixture")?;
        fs::rename(&replacement_auth, &auth)?;
        let replaced_auth = auth_source
            .bind_to_profile(ExternalGrokProfile::read_only(dir.path()))
            .expect_err("a replaced authentication source must be refused")
            .to_string();
        assert!(replaced_auth.contains("auth.json identity changed"));

        let config_source =
            GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))?;
        let replacement_config = grok_home.join("replacement-config");
        fs::write(&replacement_config, "replacement-config-fixture")?;
        fs::rename(&replacement_config, &config)?;
        let replaced_config = config_source
            .bind_to_profile(ExternalGrokProfile::read_only(dir.path()))
            .expect_err("a replaced configuration source must be refused")
            .to_string();
        assert!(replaced_config.contains("config.toml identity changed"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grok_credential_source_holds_read_only_cloexec_descriptors() -> Result<()> {
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir()?;
        let grok_home = dir.path().join("grok-home");
        fs::create_dir(&grok_home)?;
        let auth = grok_home.join(GROK_AUTH_FILE);
        let config = grok_home.join(GROK_CONFIG_FILE);
        fs::write(&auth, "synthetic-auth-fixture")?;
        fs::write(&config, "synthetic-config-fixture")?;
        let source = GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))?;

        assert_eq!(source.grok_home_environment(), grok_home.to_str().unwrap());
        for admitted in [&source.auth, source.config.as_ref().unwrap()] {
            let descriptor = admitted.held_file.as_raw_fd();
            // SAFETY: both fcntl commands only inspect flags on a live held descriptor.
            let (descriptor_flags, status_flags) = unsafe {
                (
                    libc::fcntl(descriptor, libc::F_GETFD),
                    libc::fcntl(descriptor, libc::F_GETFL),
                )
            };
            assert!(descriptor_flags >= 0);
            assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
            assert!(status_flags >= 0);
            assert_eq!(status_flags & libc::O_ACCMODE, libc::O_RDONLY);
            assert!(
                GrokCredentialFileIdentity::from_metadata(&admitted.held_file.metadata()?)
                    == Some(admitted.identity)
            );
        }

        let profile = source.bind_to_profile(ExternalGrokProfile::read_only(dir.path()))?;
        assert_eq!(profile.visible_read_only_files(), &[auth, config]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grok_credential_source_debug_and_errors_are_secret_free() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let secret = "credential-fixture-secret-value";
        let grok_home = dir.path().join(secret);
        fs::create_dir(&grok_home)?;
        let auth = grok_home.join(GROK_AUTH_FILE);
        fs::write(&auth, secret)?;
        let source = GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))?;

        let debug = format!("{source:?}");
        assert!(!debug.contains(secret), "{debug}");
        assert!(!debug.contains(&grok_home.display().to_string()), "{debug}");

        let replacement = grok_home.join("replacement-auth");
        fs::write(&replacement, secret)?;
        fs::rename(&replacement, &auth)?;
        let error = source
            .bind_to_profile(ExternalGrokProfile::read_only(dir.path()))
            .expect_err("a replaced secret source must fail closed");
        let rendered = format!("{error:#?}");
        assert_eq!(
            error.to_string(),
            "Grok authentication source auth.json identity changed"
        );
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(
            !rendered.contains(&grok_home.display().to_string()),
            "{rendered}"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absent_optional_config_keeps_only_reviewed_auth_visible_and_home_private() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join("catalog-standin");
        fs::write(&program, "")?;
        let default_grok_home = dir.path().join(".grok");
        fs::create_dir(&default_grok_home)?;
        let auth = default_grok_home.join(GROK_AUTH_FILE);
        fs::write(&auth, "hermetic-auth-fixture")?;
        let spec = GrokCatalogCommandSpec::new(dir.path()).with_program(&program);

        let process = screened_grok_catalog_process_spec_with_sources(
            &spec,
            program,
            Some(dir.path().as_os_str()),
            None,
        )?;
        let EnvironmentMode::ClearAndSet(environment) = &process.environment else {
            panic!("screened catalog environment must be ClearAndSet");
        };
        assert_eq!(
            environment.get("GROK_HOME").map(String::as_str),
            default_grok_home.to_str()
        );
        assert!(!environment.contains_key("HOME"));
        assert!(process.private_runtime_home);
        assert!(process.private_runtime_grok_home);
        let SideEffectConfinementProfile::ExternalGrok(profile) = &process.side_effects else {
            panic!("screened catalog must use ExternalGrok confinement");
        };
        assert_eq!(profile.visible_read_only_files(), &[auth]);
        assert!(profile.visible_read_only_roots().is_empty());
        Ok(())
    }

    #[test]
    fn screened_runner_fails_closed_on_a_missing_program_without_starting_grok() {
        let spec = GrokCatalogCommandSpec::new("/workspace")
            .with_program("/maco-definitely-missing-grok-catalog");
        let error = ScreenedGrokCatalogCommandRunner
            .run(&spec)
            .expect_err("missing catalog executable must fail closed")
            .to_string();
        assert!(
            error.contains("maco-definitely-missing-grok-catalog"),
            "{error}"
        );
        assert!(error.contains("missing"), "{error}");
    }
}
