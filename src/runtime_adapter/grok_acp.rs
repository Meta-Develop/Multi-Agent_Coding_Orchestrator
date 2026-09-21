//! Bounded Grok ACP stdio client for runtime-resolved model + effort observation.
//!
//! Parent-owned evidence only: observed model/effort come from post-`session/set_model`
//! `x.ai/session_notification` `model_changed` (or equivalent `session/update`), never from
//! prompt text or pre-resolution init metadata. This module does not spawn processes; callers
//! run it inside [`crate::process_runner::run_process_interactive`] via
//! [`GrokAcpContainedTransport`].

use crate::{
    artifacts::state_auth::sha256_hex,
    process_runner::{ContainedProcessSession, InteractiveProcessRead},
    runtime_adapter::grok::GROK_OUTPUT_SCHEMA_MAX_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, Instant},
};
use thiserror::Error;

/// Pinned upstream `agent-client-protocol` 0.10.4 (grok-build root `Cargo.toml`).
const SUPPORTED_ACP_PROTOCOL_VERSION: u64 = 1;

/// `xai_grok_sampling_types::types::REASONING_EFFORT_META_KEY` at grok-build `482711333c`.
const REASONING_EFFORT_META_KEY: &str = "reasoningEffort";

/// `agent_client_protocol::AGENT_METHOD_NAMES.session_set_model` (xai-acp-lib message.rs).
const METHOD_SESSION_SET_MODEL: &str = "session/set_model";

/// Wire method for `ExtNotification::new("x.ai/session_notification", …)` — underscore-prefixed
/// extension notification per ACP v1 extensibility (`grok-pager-bin` `_x.ai/session/close` pattern).
const METHOD_XAI_SESSION_NOTIFICATION: &str = "_x.ai/session_notification";

// Output bounds aligned with `codex_app_server` (same crate process-interaction ceiling).
const INTERACTION_MAX_LINE_BYTES: usize = 8 * 1024 * 1024 + 256 * 1024;
const INTERACTION_HARD_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const INTERACTION_HARD_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const INTERACTION_HARD_MAX_MESSAGES: usize = 16_384;
const INTERACTION_DEFAULT_MAX_MESSAGES: usize = 8_192;
const HARD_MAX_PROMPT_BYTES: usize = 1024 * 1024;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

const METHOD_INITIALIZE: &str = "initialize";
const METHOD_SESSION_NEW: &str = "session/new";
const METHOD_SESSION_PROMPT: &str = "session/prompt";
const METHOD_SESSION_CANCEL: &str = "session/cancel";
const METHOD_SESSION_UPDATE: &str = "session/update";
const METHOD_SESSION_REQUEST_PERMISSION: &str = "session/request_permission";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrokAcpTransportRead {
    Line,
    Timeout,
    Eof,
}

pub(crate) trait GrokAcpJsonLineTransport {
    fn receive(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<GrokAcpTransportRead, String>;

    fn send(&mut self, line: &[u8]) -> Result<(), String>;
}

/// JSONL over a borrowed contained-process session (same seam as Codex app-server).
pub(crate) struct GrokAcpContainedTransport<'session, 'process> {
    session: &'session mut ContainedProcessSession<'process>,
}

impl<'session, 'process> GrokAcpContainedTransport<'session, 'process> {
    pub(crate) fn new(session: &'session mut ContainedProcessSession<'process>) -> Self {
        Self { session }
    }
}

impl GrokAcpJsonLineTransport for GrokAcpContainedTransport<'_, '_> {
    fn receive(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<GrokAcpTransportRead, String> {
        match self
            .session
            .receive_line(wait, max_line_bytes, destination)?
        {
            InteractiveProcessRead::Line => Ok(GrokAcpTransportRead::Line),
            InteractiveProcessRead::Timeout => Ok(GrokAcpTransportRead::Timeout),
            InteractiveProcessRead::Eof => Ok(GrokAcpTransportRead::Eof),
        }
    }

    fn send(&mut self, line: &[u8]) -> Result<(), String> {
        self.session.send_line(line)
    }
}

/// Parent-owned JSON Schema identity captured at ACP launch. Publication
/// validates against these bytes, never a later replacement of the schema file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrokAcpBoundOutputSchema {
    sha256: String,
    canonical: Value,
}

impl GrokAcpBoundOutputSchema {
    pub(crate) fn from_canonical_json(canonical: &str) -> Result<Self, GrokAcpError> {
        if canonical.is_empty() || canonical.len() > GROK_OUTPUT_SCHEMA_MAX_BYTES as usize {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp output schema is empty or exceeds its bound".to_string(),
            });
        }
        if canonical.contains('\0') {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp output schema contains a NUL byte".to_string(),
            });
        }
        let parsed: Value = serde_json::from_str(canonical).map_err(|error| {
            GrokAcpError::InvalidConfiguration {
                message: format!("grok acp output schema is not valid JSON: {error}"),
            }
        })?;
        if !parsed.is_object() {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp output schema must be a JSON object".to_string(),
            });
        }
        let canonical_value = canonical_json_value(&parsed);
        let rendered = serde_json::to_string(&canonical_value).map_err(|error| {
            GrokAcpError::InvalidConfiguration {
                message: format!("failed to render grok acp output schema: {error}"),
            }
        })?;
        if rendered.len() > GROK_OUTPUT_SCHEMA_MAX_BYTES as usize {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "rendered grok acp output schema exceeds its bound".to_string(),
            });
        }
        Ok(Self {
            sha256: sha256_hex(rendered.as_bytes()),
            canonical: canonical_value,
        })
    }

    #[cfg(test)]
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn canonical_value(&self) -> &Value {
        &self.canonical
    }

    pub(crate) fn validate_structured_output(&self, instance: &Value) -> Result<(), String> {
        json_schema_accepts_instance(&self.canonical, instance, 0).map_err(|keyword| {
            format!("Grok ACP structured output failed the admitted schema ({keyword})")
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrokAcpTurn {
    pub(crate) cwd: String,
    pub(crate) prompt: String,
    pub(crate) requested_model: Option<String>,
    pub(crate) requested_effort: Option<String>,
    pub(crate) output_schema: Option<GrokAcpBoundOutputSchema>,
}

impl GrokAcpTurn {
    fn validate(&self) -> Result<(), GrokAcpError> {
        if self.cwd.is_empty()
            || self.cwd.len() > 16 * 1024
            || self.cwd.contains(['\0', '\n', '\r'])
        {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp cwd is empty or malformed".to_string(),
            });
        }
        if self.prompt.len() > HARD_MAX_PROMPT_BYTES || self.prompt.contains('\0') {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp prompt is malformed or exceeds its bound".to_string(),
            });
        }
        if let Some(model) = &self.requested_model {
            validate_identifier(model, "requested model", 256)?;
        }
        if let Some(effort) = &self.requested_effort {
            validate_identifier(effort, "requested effort", 64)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GrokAcpLimits {
    /// Parent `ProcessSpec::timeout` (or equivalent authorized operation budget).
    pub(crate) operation_timeout: Duration,
    pub(crate) max_line_bytes: usize,
    pub(crate) max_total_bytes: usize,
    pub(crate) max_messages: usize,
}

impl GrokAcpLimits {
    pub(crate) fn from_parent_operation_timeout(
        operation_timeout: Duration,
    ) -> Result<Self, GrokAcpError> {
        if operation_timeout.is_zero() {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp requires a non-zero parent operation timeout".to_string(),
            });
        }
        Ok(Self {
            operation_timeout,
            max_line_bytes: INTERACTION_MAX_LINE_BYTES,
            max_total_bytes: INTERACTION_HARD_MAX_TOTAL_BYTES,
            max_messages: INTERACTION_DEFAULT_MAX_MESSAGES,
        })
    }

    #[cfg(test)]
    fn for_fixture_test() -> Self {
        Self::from_parent_operation_timeout(Duration::from_secs(60)).expect("fixture timeout")
    }

    fn validate(self) -> Result<Self, GrokAcpError> {
        if self.operation_timeout.is_zero() {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp operation timeout is zero".to_string(),
            });
        }
        if self.max_line_bytes == 0 || self.max_line_bytes > INTERACTION_HARD_MAX_LINE_BYTES {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp line bound is zero or exceeds the hard ceiling".to_string(),
            });
        }
        if self.max_total_bytes < self.max_line_bytes
            || self.max_total_bytes > INTERACTION_HARD_MAX_TOTAL_BYTES
        {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp aggregate bound is invalid".to_string(),
            });
        }
        if self.max_messages == 0 || self.max_messages > INTERACTION_HARD_MAX_MESSAGES {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "grok acp message bound is zero or exceeds the hard ceiling".to_string(),
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrokAcpCorrection {
    pub(crate) action_id: String,
    pub(crate) prompt: String,
    pub(crate) deadline: std::time::Instant,
}

pub(crate) trait GrokAcpSteering {
    fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String>;
    fn acknowledge(&mut self, action_id: &str) -> Result<(), String>;
}

impl GrokAcpSteering for () {
    fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
        Ok(None)
    }

    fn acknowledge(&mut self, _action_id: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Client-reported resolution status (not cryptographic backend proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrokAcpResolutionStatus {
    Complete,
    Incomplete,
    Truncated,
    AmbiguousModelChange,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrokAcpResolvedField {
    Known(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct GrokAcpRequestedModelEffort {
    pub(crate) model: Option<String>,
    pub(crate) effort: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct GrokAcpClientResolvedModelEffort {
    pub(crate) model: GrokAcpResolvedField,
    pub(crate) effort: GrokAcpResolvedField,
}

/// Parent-owned terminal usage projection bound to the same session/prompt turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct GrokAcpTerminalUsage {
    pub(crate) usage_is_incomplete: bool,
    pub(crate) cost_is_partial: bool,
    pub(crate) session_id: String,
    pub(crate) prompt_id: Option<String>,
    /// Reduced headless-shaped usage object when the server supplied trustworthy fields.
    pub(crate) projected: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct GrokAcpExecutionEvidence {
    pub(crate) runtime: &'static str,
    pub(crate) session_id: String,
    pub(crate) requested: GrokAcpRequestedModelEffort,
    pub(crate) client_resolved: GrokAcpClientResolvedModelEffort,
    pub(crate) resolution_status: GrokAcpResolutionStatus,
    pub(crate) terminal_usage: Option<GrokAcpTerminalUsage>,
    /// Prompt-response `_meta` from the correlated `session/prompt` result.
    pub(crate) prompt_result_meta: Option<Value>,
    pub(crate) final_text: Option<String>,
    pub(crate) stop_reason: Option<String>,
    pub(crate) permission_escalation_refused: bool,
    pub(crate) messages_received: usize,
    pub(crate) bytes_received: usize,
}

/// Parent-side ACP publication gate for exact admitted model/effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrokAcpIdentityPublicationStatus {
    Admitted,
    MissingEvidence,
    ConflictingEvidence,
    ModelMismatch,
    EffortMismatch,
}

impl GrokAcpIdentityPublicationStatus {
    pub(crate) fn refusal_message(self) -> Option<&'static str> {
        match self {
            Self::Admitted => None,
            Self::MissingEvidence => Some(
                "Grok ACP publication refused: resolved identity evidence is missing or incomplete",
            ),
            Self::ConflictingEvidence => {
                Some("Grok ACP publication refused: resolved identity evidence is conflicting")
            }
            Self::ModelMismatch => Some(
                "Grok ACP publication refused: resolved model does not match the admitted model",
            ),
            Self::EffortMismatch => Some(
                "Grok ACP publication refused: resolved effort does not match the admitted effort",
            ),
        }
    }
}

pub(crate) fn grok_acp_resolution_status_from_parent_label(label: &str) -> GrokAcpResolutionStatus {
    match label {
        "complete" => GrokAcpResolutionStatus::Complete,
        "incomplete" => GrokAcpResolutionStatus::Incomplete,
        "truncated" => GrokAcpResolutionStatus::Truncated,
        "ambiguous_model_change" => GrokAcpResolutionStatus::AmbiguousModelChange,
        _ => GrokAcpResolutionStatus::Unresolved,
    }
}

pub(crate) fn grok_acp_admitted_identity_publication_status(
    admitted_model: Option<&str>,
    admitted_effort: Option<&str>,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
    resolved_model: Option<&str>,
    resolved_effort: Option<&str>,
    resolution_status: GrokAcpResolutionStatus,
) -> GrokAcpIdentityPublicationStatus {
    let Some(admitted_model) = admitted_model.filter(|value| !value.is_empty()) else {
        return GrokAcpIdentityPublicationStatus::MissingEvidence;
    };
    let Some(admitted_effort) = admitted_effort.filter(|value| !value.is_empty()) else {
        return GrokAcpIdentityPublicationStatus::MissingEvidence;
    };
    if requested_model != Some(admitted_model) || requested_effort != Some(admitted_effort) {
        return GrokAcpIdentityPublicationStatus::ConflictingEvidence;
    }
    match resolution_status {
        GrokAcpResolutionStatus::AmbiguousModelChange => {
            return GrokAcpIdentityPublicationStatus::ConflictingEvidence;
        }
        GrokAcpResolutionStatus::Complete => {}
        GrokAcpResolutionStatus::Incomplete
        | GrokAcpResolutionStatus::Truncated
        | GrokAcpResolutionStatus::Unresolved => {
            return GrokAcpIdentityPublicationStatus::MissingEvidence;
        }
    }
    match resolved_model {
        Some(model) if model == admitted_model => {}
        Some(_) => return GrokAcpIdentityPublicationStatus::ModelMismatch,
        None => return GrokAcpIdentityPublicationStatus::MissingEvidence,
    }
    match resolved_effort {
        Some(effort) if effort == admitted_effort => {}
        Some(_) => return GrokAcpIdentityPublicationStatus::EffortMismatch,
        None => return GrokAcpIdentityPublicationStatus::MissingEvidence,
    }
    GrokAcpIdentityPublicationStatus::Admitted
}

#[cfg(test)]
pub(crate) fn grok_acp_execution_identity_publication_status(
    evidence: &GrokAcpExecutionEvidence,
) -> GrokAcpIdentityPublicationStatus {
    grok_acp_admitted_identity_publication_status(
        evidence.requested.model.as_deref(),
        evidence.requested.effort.as_deref(),
        evidence.requested.model.as_deref(),
        evidence.requested.effort.as_deref(),
        resolved_field_as_str(&evidence.client_resolved.model),
        resolved_field_as_str(&evidence.client_resolved.effort),
        evidence.resolution_status,
    )
}

#[cfg(test)]
fn resolved_field_as_str(field: &GrokAcpResolvedField) -> Option<&str> {
    match field {
        GrokAcpResolvedField::Known(value) => Some(value.as_str()),
        GrokAcpResolvedField::Unknown => None,
    }
}

const JSON_SCHEMA_MAX_DEPTH: usize = 32;

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(canonical_json_value).collect::<Vec<_>>())
        }
        Value::Object(values) => {
            let sorted = values.iter().collect::<BTreeMap<_, _>>();
            let mut canonical = Map::new();
            for (key, value) in sorted {
                canonical.insert(key.as_str().to_string(), canonical_json_value(value));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

fn json_schema_accepts_instance(
    schema: &Value,
    instance: &Value,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > JSON_SCHEMA_MAX_DEPTH {
        return Err("depth");
    }
    let Some(schema) = schema.as_object() else {
        return Err("schema");
    };
    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array) {
        if !any_of
            .iter()
            .any(|variant| json_schema_accepts_instance(variant, instance, depth + 1).is_ok())
        {
            return Err("anyOf");
        }
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|variant| json_schema_accepts_instance(variant, instance, depth + 1).is_ok())
            .count();
        if matches != 1 {
            return Err("oneOf");
        }
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for variant in all_of {
            json_schema_accepts_instance(variant, instance, depth + 1)?;
        }
    }
    if schema
        .get("const")
        .is_some_and(|expected| expected != instance)
    {
        return Err("const");
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(instance))
    {
        return Err("enum");
    }
    if let Some(schema_type) = schema.get("type") {
        let matches_type = |schema_type: &Value| match schema_type.as_str() {
            Some("null") => instance.is_null(),
            Some("boolean") => instance.is_boolean(),
            Some("integer") => instance.as_i64().is_some() || instance.as_u64().is_some(),
            Some("number") => instance.is_number(),
            Some("string") => instance.is_string(),
            Some("array") => instance.is_array(),
            Some("object") => instance.is_object(),
            _ => false,
        };
        let accepted_type = schema_type.as_array().map_or_else(
            || matches_type(schema_type),
            |types| types.iter().any(matches_type),
        );
        if !accepted_type {
            return Err("type");
        }
    }
    if let Some(object) = instance.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            if required
                .iter()
                .any(|name| name.as_str().is_none_or(|name| !object.contains_key(name)))
            {
                return Err("required");
            }
        }
        for (name, value) in object {
            match properties.and_then(|properties| properties.get(name)) {
                Some(property_schema) => {
                    json_schema_accepts_instance(property_schema, value, depth + 1)?;
                }
                None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    return Err("additionalProperties");
                }
                None => {
                    if let Some(additional) = schema
                        .get("additionalProperties")
                        .filter(|value| value.is_object())
                    {
                        json_schema_accepts_instance(additional, value, depth + 1)?;
                    }
                }
            }
        }
    }
    if let Some(array) = instance.as_array() {
        if let Some(items) = schema.get("items") {
            for value in array {
                json_schema_accepts_instance(items, value, depth + 1)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum GrokAcpError {
    #[error("{message}")]
    InvalidConfiguration { message: String },
    #[error("{message}")]
    Transport { message: String },
    #[error("grok acp protocol timed out during {phase}")]
    Timeout { phase: &'static str },
    #[error("grok acp protocol was cancelled during {phase}")]
    Cancelled { phase: &'static str },
    #[error("grok acp protocol stream ended during {phase}")]
    ProtocolLoss { phase: &'static str },
    #[error("malformed grok acp message during {phase}: {message}")]
    Malformed {
        phase: &'static str,
        message: String,
    },
    #[error("unexpected grok acp message during {phase}: {message}")]
    Unexpected {
        phase: &'static str,
        message: String,
    },
    #[error("duplicate grok acp message during {phase}: {message}")]
    Duplicate {
        phase: &'static str,
        message: String,
    },
    #[error("grok acp request failed during {phase}: {message}")]
    Remote {
        phase: &'static str,
        message: String,
    },
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RequestId {
    Number(u64),
    String(String),
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(value) => formatter.debug_tuple("Number").field(value).finish(),
            Self::String(_) => formatter.write_str("String(<opaque>)"),
        }
    }
}

impl RequestId {
    fn parse(value: &Value, phase: &'static str) -> Result<Self, GrokAcpError> {
        if let Some(number) = value.as_u64() {
            return Ok(Self::Number(number));
        }
        if let Some(text) = value.as_str() {
            validate_identifier(text, "request id", 128).map_err(|error| {
                GrokAcpError::Malformed {
                    phase,
                    message: error.to_string(),
                }
            })?;
            return Ok(Self::String(text.to_string()));
        }
        Err(GrokAcpError::Malformed {
            phase,
            message: "request id is neither an unsigned integer nor a bounded string".to_string(),
        })
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Number(value) => Value::from(*value),
            Self::String(value) => Value::from(value.clone()),
        }
    }
}

struct ProtocolState {
    limits: GrokAcpLimits,
    deadline: Instant,
    messages_received: usize,
    bytes_received: usize,
    bytes_sent: usize,
    response_ids: BTreeSet<RequestId>,
    server_request_ids: BTreeSet<RequestId>,
    next_request_id: u64,
}

impl ProtocolState {
    fn new(limits: GrokAcpLimits) -> Result<Self, GrokAcpError> {
        let deadline = Instant::now()
            .checked_add(limits.operation_timeout)
            .ok_or_else(|| GrokAcpError::InvalidConfiguration {
                message: "grok acp deadline overflowed".to_string(),
            })?;
        Ok(Self {
            limits,
            deadline,
            messages_received: 0,
            bytes_received: 0,
            bytes_sent: 0,
            response_ids: BTreeSet::new(),
            server_request_ids: BTreeSet::new(),
            next_request_id: 1,
        })
    }

    fn allocate_request_id(&mut self) -> Result<RequestId, GrokAcpError> {
        let id = self.next_request_id;
        self.next_request_id =
            self.next_request_id
                .checked_add(1)
                .ok_or_else(|| GrokAcpError::Unexpected {
                    phase: "request allocation",
                    message: "request id space exhausted".to_string(),
                })?;
        Ok(RequestId::Number(id))
    }

    fn correction_still_actionable(&self, correction_deadline: Instant) -> bool {
        let now = Instant::now();
        now < self.deadline && now < correction_deadline
    }

    fn send<T: GrokAcpJsonLineTransport>(
        &mut self,
        transport: &mut T,
        message: &Value,
    ) -> Result<(), GrokAcpError> {
        let encoded = serde_json::to_vec(message).map_err(|error| GrokAcpError::Malformed {
            phase: "client serialization",
            message: error.to_string(),
        })?;
        if encoded.len() > self.limits.max_line_bytes {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "client grok acp message exceeded the line bound".to_string(),
            });
        }
        self.bytes_sent = self.bytes_sent.saturating_add(encoded.len());
        if self.bytes_sent > self.limits.max_total_bytes {
            return Err(GrokAcpError::InvalidConfiguration {
                message: "client grok acp output exceeded the aggregate bound".to_string(),
            });
        }
        transport
            .send(&encoded)
            .map_err(|message| GrokAcpError::Transport { message })
    }

    fn receive_one_slice<T, C>(
        &mut self,
        transport: &mut T,
        phase: &'static str,
        cancelled: &C,
        line: &mut Vec<u8>,
        correction_deadline: Option<Instant>,
    ) -> Result<ReceiveOneSliceOutcome, GrokAcpError>
    where
        T: GrokAcpJsonLineTransport,
        C: Fn() -> bool,
    {
        if cancelled() {
            return Err(GrokAcpError::Cancelled { phase });
        }
        let now = Instant::now();
        let effective_deadline = match correction_deadline {
            Some(correction) => self.deadline.min(correction),
            None => self.deadline,
        };
        if now >= effective_deadline {
            let timed_out_phase = if correction_deadline.is_some_and(|correction| now >= correction)
            {
                "steering correction"
            } else {
                phase
            };
            return Err(GrokAcpError::Timeout {
                phase: timed_out_phase,
            });
        }
        let remaining = effective_deadline.saturating_duration_since(now);
        let wait = remaining.min(CANCELLATION_POLL_INTERVAL);
        line.clear();
        match transport
            .receive(wait, self.limits.max_line_bytes, line)
            .map_err(|message| GrokAcpError::Transport { message })?
        {
            GrokAcpTransportRead::Timeout if Instant::now() < effective_deadline => {
                return Ok(ReceiveOneSliceOutcome::Idle);
            }
            GrokAcpTransportRead::Timeout => {
                let timed_out_phase =
                    if correction_deadline.is_some_and(|correction| Instant::now() >= correction) {
                        "steering correction"
                    } else {
                        phase
                    };
                return Err(GrokAcpError::Timeout {
                    phase: timed_out_phase,
                });
            }
            GrokAcpTransportRead::Eof => return Err(GrokAcpError::ProtocolLoss { phase }),
            GrokAcpTransportRead::Line => {}
        }
        self.messages_received = self.messages_received.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(line.len());
        if self.messages_received > self.limits.max_messages
            || self.bytes_received > self.limits.max_total_bytes
        {
            return Err(GrokAcpError::Malformed {
                phase,
                message: "grok acp output exceeded its aggregate bound".to_string(),
            });
        }
        let message = serde_json::from_slice(line).map_err(|error| GrokAcpError::Malformed {
            phase,
            message: format!("invalid JSON: {error}"),
        })?;
        Ok(ReceiveOneSliceOutcome::Message(message))
    }

    fn receive<T, C>(
        &mut self,
        transport: &mut T,
        phase: &'static str,
        cancelled: &C,
    ) -> Result<Value, GrokAcpError>
    where
        T: GrokAcpJsonLineTransport,
        C: Fn() -> bool,
    {
        let mut line = Vec::new();
        loop {
            match self.receive_one_slice(transport, phase, cancelled, &mut line, None)? {
                ReceiveOneSliceOutcome::Idle => continue,
                ReceiveOneSliceOutcome::Message(message) => return Ok(message),
            }
        }
    }
}

enum ReceiveOneSliceOutcome {
    Message(Value),
    Idle,
}

#[derive(Clone, PartialEq, Eq)]
struct PendingModelNotification {
    model_id: String,
    effort: Option<String>,
}

enum ModelResolutionPhase {
    Idle,
    AwaitingSetModelAck {
        pending: Option<PendingModelNotification>,
    },
    Committed {
        model: String,
        effort: GrokAcpResolvedField,
    },
    Invalidated,
}

struct ModelResolutionTracker {
    phase: ModelResolutionPhase,
    ambiguous_during_prompt: bool,
}

impl ModelResolutionTracker {
    fn new() -> Self {
        Self {
            phase: ModelResolutionPhase::Idle,
            ambiguous_during_prompt: false,
        }
    }

    fn begin_set_model(&mut self) {
        if matches!(self.phase, ModelResolutionPhase::Idle) {
            self.phase = ModelResolutionPhase::AwaitingSetModelAck { pending: None };
        }
    }

    /// Pre-request `model_changed` notifications are unrelated session state; ignore.
    fn note_model_changed(&mut self, model_id: &str, effort: Option<&str>) {
        match &mut self.phase {
            ModelResolutionPhase::Idle => {}
            ModelResolutionPhase::AwaitingSetModelAck { pending } => {
                let next = PendingModelNotification {
                    model_id: model_id.to_string(),
                    effort: effort.map(str::to_string),
                };
                if let Some(existing) = pending.as_ref() {
                    if existing.model_id != next.model_id || existing.effort != next.effort {
                        *pending = Some(next);
                    }
                } else {
                    *pending = Some(next);
                }
            }
            ModelResolutionPhase::Committed {
                model: committed_model,
                effort: committed_effort,
            } => {
                let same_model = committed_model == model_id;
                let same_effort = match (committed_effort, effort) {
                    (GrokAcpResolvedField::Known(existing), Some(incoming)) => existing == incoming,
                    (GrokAcpResolvedField::Unknown, None) => true,
                    (GrokAcpResolvedField::Unknown, Some(_)) => false,
                    (GrokAcpResolvedField::Known(_), None) => false,
                };
                if !same_model || !same_effort {
                    self.ambiguous_during_prompt = true;
                }
            }
            ModelResolutionPhase::Invalidated => {}
        }
    }

    fn commit_set_model_ack(&mut self, response: &Value) -> Result<(), GrokAcpError> {
        let pending = match &self.phase {
            ModelResolutionPhase::AwaitingSetModelAck { pending } => pending.clone(),
            _ => {
                self.phase = ModelResolutionPhase::Invalidated;
                return Err(GrokAcpError::Unexpected {
                    phase: "session/set_model",
                    message: "set-model response without an in-flight request".to_string(),
                });
            }
        };
        let ack_model = response
            .pointer("/result/_meta/model")
            .and_then(Value::as_str);
        let (model, effort) = match pending {
            Some(notification) => {
                if let Some(ack) = ack_model {
                    if ack != notification.model_id {
                        self.phase = ModelResolutionPhase::Invalidated;
                        return Err(GrokAcpError::Unexpected {
                            phase: "session/set_model",
                            message: "set-model response model disagreed with pending notification"
                                .to_string(),
                        });
                    }
                }
                (
                    notification.model_id,
                    notification
                        .effort
                        .map(GrokAcpResolvedField::Known)
                        .unwrap_or(GrokAcpResolvedField::Unknown),
                )
            }
            None => {
                let model = ack_model.ok_or_else(|| {
                    self.phase = ModelResolutionPhase::Invalidated;
                    GrokAcpError::Malformed {
                        phase: "session/set_model",
                        message: "set-model ack missing pending notification and _meta.model"
                            .to_string(),
                    }
                })?;
                (model.to_string(), GrokAcpResolvedField::Unknown)
            }
        };
        self.phase = ModelResolutionPhase::Committed { model, effort };
        Ok(())
    }

    fn invalidate_set_model_ack(&mut self) {
        if matches!(self.phase, ModelResolutionPhase::AwaitingSetModelAck { .. }) {
            self.phase = ModelResolutionPhase::Invalidated;
        }
    }

    fn client_resolved(&self) -> GrokAcpClientResolvedModelEffort {
        match &self.phase {
            ModelResolutionPhase::Committed { model, effort } => GrokAcpClientResolvedModelEffort {
                model: GrokAcpResolvedField::Known(model.clone()),
                effort: effort.clone(),
            },
            _ => GrokAcpClientResolvedModelEffort {
                model: GrokAcpResolvedField::Unknown,
                effort: GrokAcpResolvedField::Unknown,
            },
        }
    }

    fn resolution_status(
        &self,
        prompt_acknowledged: bool,
        truncated: bool,
        usage_incomplete: bool,
    ) -> GrokAcpResolutionStatus {
        if truncated {
            return GrokAcpResolutionStatus::Truncated;
        }
        if self.ambiguous_during_prompt {
            return GrokAcpResolutionStatus::AmbiguousModelChange;
        }
        if matches!(self.phase, ModelResolutionPhase::Invalidated) {
            return GrokAcpResolutionStatus::Unresolved;
        }
        if !prompt_acknowledged || usage_incomplete {
            return GrokAcpResolutionStatus::Incomplete;
        }
        let resolved = self.client_resolved();
        if matches!(resolved.model, GrokAcpResolvedField::Known(_))
            && matches!(resolved.effort, GrokAcpResolvedField::Known(_))
        {
            GrokAcpResolutionStatus::Complete
        } else {
            GrokAcpResolutionStatus::Unresolved
        }
    }
}

fn session_prompt_params(
    session_id: &str,
    prompt: &str,
    schema: Option<&GrokAcpBoundOutputSchema>,
) -> Value {
    let mut params = json!({
        "sessionId": session_id,
        "prompt": [{"type": "text", "text": prompt}]
    });
    if let Some(schema) = schema {
        params.as_object_mut().expect("params object").insert(
            "_meta".into(),
            json!({ "jsonSchema": schema.canonical_value().clone() }),
        );
    }
    params
}

fn validate_initialize_response(response: &Value) -> Result<(), GrokAcpError> {
    let version = response
        .pointer("/result/protocolVersion")
        .and_then(Value::as_u64);
    if version != Some(SUPPORTED_ACP_PROTOCOL_VERSION) {
        return Err(GrokAcpError::Remote {
            phase: "initialize",
            message: format!(
                "agent protocolVersion {:?} is not supported (MACO requires {})",
                version, SUPPORTED_ACP_PROTOCOL_VERSION
            ),
        });
    }
    Ok(())
}

pub(crate) fn run_grok_acp_turn<T, C>(
    transport: &mut T,
    turn: &GrokAcpTurn,
    limits: GrokAcpLimits,
    cancelled: C,
) -> Result<GrokAcpExecutionEvidence, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    run_grok_acp_turn_with_steering(transport, turn, limits, cancelled, &mut ())
}

pub(crate) fn run_grok_acp_turn_with_steering<T, C, S>(
    transport: &mut T,
    turn: &GrokAcpTurn,
    limits: GrokAcpLimits,
    cancelled: C,
    steering: &mut S,
) -> Result<GrokAcpExecutionEvidence, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
    S: GrokAcpSteering,
{
    turn.validate()?;
    let limits = limits.validate()?;
    let mut state = ProtocolState::new(limits)?;
    let mut model_tracker = ModelResolutionTracker::new();
    let mut permission_escalation_refused = false;

    let initialize_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "id": initialize_id.to_value(),
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": SUPPORTED_ACP_PROTOCOL_VERSION,
                "clientInfo": {
                    "name": "maco",
                    "title": "Multi-Agent Coding Orchestrator",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "clientCapabilities": {}
            }
        }),
    )?;
    let initialize_response = wait_for_response(
        &mut state,
        transport,
        &initialize_id,
        "initialize",
        &cancelled,
    )?;
    validate_initialize_response(&initialize_response)?;

    let session_new_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "id": session_new_id.to_value(),
            "method": METHOD_SESSION_NEW,
            "params": {
                "cwd": turn.cwd,
                "mcpServers": []
            }
        }),
    )?;
    let session_response = wait_for_response(
        &mut state,
        transport,
        &session_new_id,
        "session/new",
        &cancelled,
    )?;
    let session_id = required_text(
        &session_response,
        &["result", "sessionId"],
        "session/new",
        "session id",
    )?
    .to_string();

    if turn.requested_model.is_some() || turn.requested_effort.is_some() {
        let set_model_id = state.allocate_request_id()?;
        let mut params = Map::new();
        params.insert("sessionId".into(), Value::from(session_id.clone()));
        if let Some(model) = &turn.requested_model {
            params.insert("modelId".into(), Value::from(model.clone()));
        }
        if let Some(effort) = &turn.requested_effort {
            let mut meta = Map::new();
            meta.insert(
                REASONING_EFFORT_META_KEY.into(),
                Value::from(effort.clone()),
            );
            params.insert("_meta".into(), Value::Object(meta));
        }
        state.send(
            transport,
            &json!({
                "jsonrpc": "2.0",
                "id": set_model_id.to_value(),
                "method": METHOD_SESSION_SET_MODEL,
                "params": params
            }),
        )?;
        model_tracker.begin_set_model();
        drain_until_response_or_model_changed(
            &mut state,
            transport,
            &set_model_id,
            &session_id,
            &mut model_tracker,
            &cancelled,
            &mut permission_escalation_refused,
        )?;
    }

    let prompt_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "id": prompt_id.to_value(),
            "method": METHOD_SESSION_PROMPT,
            "params": session_prompt_params(&session_id, &turn.prompt, turn.output_schema.as_ref())
        }),
    )?;

    let mut prompt_ctx = PromptSessionContext {
        session_id: &session_id,
        model_tracker: &mut model_tracker,
        permission_escalation_refused: &mut permission_escalation_refused,
        output_schema: turn.output_schema.as_ref(),
    };
    let prompt_outcome = drive_prompt(
        &mut state,
        transport,
        &mut prompt_ctx,
        &prompt_id,
        &cancelled,
        steering,
    );

    let PromptDriveOutcome {
        final_text,
        stop_reason,
        mut terminal_usage,
        prompt_result_meta,
        prompt_acknowledged,
        truncated,
        prior_prompts_interrupted,
    } = match prompt_outcome {
        Ok(value) => value,
        Err(error) => {
            let _ = best_effort_cancel(&mut state, transport, &session_id);
            return Err(error);
        }
    };

    let _ = best_effort_cancel(&mut state, transport, &session_id);

    if prior_prompts_interrupted {
        if let Some(usage) = terminal_usage.as_mut() {
            usage.usage_is_incomplete = true;
            usage.cost_is_partial = true;
            usage.projected = None;
        }
    }

    let usage_incomplete = prior_prompts_interrupted
        || terminal_usage
            .as_ref()
            .is_some_and(|usage| usage.usage_is_incomplete || usage.cost_is_partial);
    let resolution_status =
        model_tracker.resolution_status(prompt_acknowledged, truncated, usage_incomplete);
    let client_resolved = model_tracker.client_resolved();

    Ok(GrokAcpExecutionEvidence {
        runtime: "grok_acp_stdio",
        session_id,
        requested: GrokAcpRequestedModelEffort {
            model: turn.requested_model.clone(),
            effort: turn.requested_effort.clone(),
        },
        client_resolved,
        resolution_status,
        terminal_usage,
        prompt_result_meta,
        final_text,
        stop_reason,
        permission_escalation_refused,
        messages_received: state.messages_received,
        bytes_received: state.bytes_received,
    })
}

struct PromptDriveOutcome {
    final_text: Option<String>,
    stop_reason: Option<String>,
    terminal_usage: Option<GrokAcpTerminalUsage>,
    prompt_result_meta: Option<Value>,
    prompt_acknowledged: bool,
    truncated: bool,
    prior_prompts_interrupted: bool,
}

fn validate_steering_prompt(prompt: &str) -> Result<(), GrokAcpError> {
    if prompt.len() > HARD_MAX_PROMPT_BYTES || prompt.contains('\0') {
        return Err(GrokAcpError::InvalidConfiguration {
            message: "grok acp steering prompt is malformed or exceeds its bound".to_string(),
        });
    }
    Ok(())
}

fn superseded_prompt_drained(stop_reason: Option<&str>) -> bool {
    matches!(stop_reason, Some("cancelled") | Some("end_turn"))
}

#[derive(Default)]
struct PromptTurnAccumulators {
    final_text: Option<String>,
    stop_reason: Option<String>,
    terminal_usage: Option<GrokAcpTerminalUsage>,
    prompt_result_meta: Option<Value>,
    truncated: bool,
    prompt_acknowledged: bool,
}

struct SteeringApplication {
    prompt_request_id: RequestId,
    action_id: String,
    correction_deadline: Instant,
}

enum SupersededPromptState<'a> {
    Active { request_id: &'a RequestId },
    Completed,
}

struct PromptSessionContext<'a> {
    session_id: &'a str,
    model_tracker: &'a mut ModelResolutionTracker,
    permission_escalation_refused: &'a mut bool,
    output_schema: Option<&'a GrokAcpBoundOutputSchema>,
}

fn ensure_correction_actionable(
    state: &ProtocolState,
    correction_deadline: Instant,
) -> Result<(), GrokAcpError> {
    if !state.correction_still_actionable(correction_deadline) {
        return Err(GrokAcpError::Timeout {
            phase: "steering correction",
        });
    }
    Ok(())
}

fn send_session_cancel_notification<T: GrokAcpJsonLineTransport>(
    state: &mut ProtocolState,
    transport: &mut T,
    session_id: &str,
) -> Result<(), GrokAcpError> {
    state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "method": METHOD_SESSION_CANCEL,
            "params": {"sessionId": session_id}
        }),
    )
}

fn apply_steering_correction<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    superseded: SupersededPromptState<'_>,
    correction: &GrokAcpCorrection,
    cancelled: &C,
) -> Result<SteeringApplication, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    validate_steering_prompt(&correction.prompt)?;
    ensure_correction_actionable(state, correction.deadline)?;
    match superseded {
        SupersededPromptState::Active { request_id } => {
            send_session_cancel_notification(state, transport, prompt_ctx.session_id)?;
            drain_superseded_prompt(
                state,
                transport,
                prompt_ctx,
                request_id,
                correction.deadline,
                cancelled,
            )?;
            ensure_correction_actionable(state, correction.deadline)?;
        }
        SupersededPromptState::Completed => {}
    }
    ensure_correction_actionable(state, correction.deadline)?;
    let new_prompt_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "id": new_prompt_id.to_value(),
            "method": METHOD_SESSION_PROMPT,
            "params": session_prompt_params(
                prompt_ctx.session_id,
                &correction.prompt,
                prompt_ctx.output_schema,
            )
        }),
    )?;
    Ok(SteeringApplication {
        prompt_request_id: new_prompt_id,
        action_id: correction.action_id.clone(),
        correction_deadline: correction.deadline,
    })
}

fn try_poll_steering_correction<T, C, S>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    superseded: SupersededPromptState<'_>,
    cancelled: &C,
    steering: &mut S,
) -> Result<Option<SteeringApplication>, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
    S: GrokAcpSteering,
{
    let Some(correction) = steering
        .next_correction()
        .map_err(|message| GrokAcpError::Transport { message })?
    else {
        return Ok(None);
    };
    if !state.correction_still_actionable(correction.deadline) {
        return Err(GrokAcpError::Timeout {
            phase: "steering correction",
        });
    }
    Ok(Some(apply_steering_correction(
        state,
        transport,
        prompt_ctx,
        superseded,
        &correction,
        cancelled,
    )?))
}

fn drain_superseded_prompt<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    superseded_prompt_id: &RequestId,
    correction_deadline: Instant,
    cancelled: &C,
) -> Result<(), GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    let phase = "session/prompt drain";
    let mut line = Vec::new();
    loop {
        let message = match state.receive_one_slice(
            transport,
            phase,
            cancelled,
            &mut line,
            Some(correction_deadline),
        )? {
            ReceiveOneSliceOutcome::Idle => continue,
            ReceiveOneSliceOutcome::Message(message) => message,
        };
        if let Some(id) = message.get("id") {
            if message.get("method").is_some() {
                let method = required_text(&message, &["method"], phase, "method")?;
                refuse_server_request(
                    state,
                    transport,
                    &message,
                    method,
                    prompt_ctx.permission_escalation_refused,
                )?;
                continue;
            }
            let parsed = RequestId::parse(id, phase)?;
            if !state.response_ids.insert(parsed.clone()) {
                return Err(GrokAcpError::Duplicate {
                    phase,
                    message: "duplicate response id".to_string(),
                });
            }
            if &parsed != superseded_prompt_id {
                return Err(GrokAcpError::Unexpected {
                    phase,
                    message: "unexpected correlated response while draining superseded prompt"
                        .to_string(),
                });
            }
            if message.get("error").is_some() {
                return Err(GrokAcpError::Remote {
                    phase,
                    message: bounded_json_summary(message.get("error").unwrap_or(&Value::Null)),
                });
            }
            let stop_reason = message
                .pointer("/result/stopReason")
                .and_then(Value::as_str);
            if !superseded_prompt_drained(stop_reason) {
                return Err(GrokAcpError::Unexpected {
                    phase,
                    message:
                        "superseded prompt terminal reason did not authorize steering correction"
                            .to_string(),
                });
            }
            return Ok(());
        }
        dispatch_prompt_notification(state, transport, prompt_ctx, &message, phase, None)?;
    }
}

fn dispatch_prompt_notification<T: GrokAcpJsonLineTransport>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    message: &Value,
    phase: &'static str,
    supplement: Option<(&mut Option<String>, &mut Option<String>, &mut bool)>,
) -> Result<(), GrokAcpError> {
    if message.get("method").is_none() {
        return Err(GrokAcpError::Malformed {
            phase,
            message: "message lacks method and response id".to_string(),
        });
    }
    let method = required_text(message, &["method"], phase, "method")?;
    match method {
        METHOD_SESSION_UPDATE => {
            let params = required_object(message, &["params"], phase, "params")?;
            let wire_session = map_required_text(params, "sessionId", phase, "session id")?;
            if wire_session != prompt_ctx.session_id {
                return Err(GrokAcpError::Unexpected {
                    phase,
                    message: "session/update targeted a different session".to_string(),
                });
            }
            let update = params
                .get("update")
                .and_then(Value::as_object)
                .ok_or_else(|| GrokAcpError::Malformed {
                    phase,
                    message: "session/update update is not an object".to_string(),
                })?;
            if let Some(tag) = update.get("sessionUpdate").and_then(Value::as_str) {
                match tag {
                    "model_changed" => {
                        let model_id =
                            update
                                .get("model_id")
                                .and_then(Value::as_str)
                                .ok_or_else(|| GrokAcpError::Malformed {
                                    phase,
                                    message: "model_changed missing model_id".to_string(),
                                })?;
                        let effort = update.get("reasoning_effort").and_then(Value::as_str);
                        prompt_ctx
                            .model_tracker
                            .note_model_changed(model_id, effort);
                    }
                    "agent_message_chunk" => {
                        if let Some((final_text, _, _)) = supplement {
                            if let Some(text) = update
                                .get("content")
                                .and_then(|content| content.get("text"))
                                .and_then(Value::as_str)
                            {
                                let mut combined = final_text.take().unwrap_or_default();
                                combined.push_str(text);
                                *final_text = Some(combined);
                            }
                        }
                    }
                    "turn_completed" => {
                        if let Some((final_text, stop_reason, truncated)) = supplement {
                            apply_turn_completed_supplement(
                                update,
                                final_text,
                                stop_reason,
                                truncated,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        _ if method == METHOD_XAI_SESSION_NOTIFICATION => {
            handle_xai_session_notification(
                message,
                prompt_ctx.session_id,
                prompt_ctx.model_tracker,
                supplement,
            )?;
        }
        _ if method == METHOD_SESSION_REQUEST_PERMISSION || method.starts_with('_') => {
            refuse_server_request(
                state,
                transport,
                message,
                method,
                prompt_ctx.permission_escalation_refused,
            )?;
        }
        _ => {
            if is_escalation_method(method) {
                refuse_server_request(
                    state,
                    transport,
                    message,
                    method,
                    prompt_ctx.permission_escalation_refused,
                )?;
            }
        }
    }
    Ok(())
}

fn ingest_prompt_terminal_response(
    message: &Value,
    session_id: &str,
    turn: &mut PromptTurnAccumulators,
) {
    turn.prompt_acknowledged = true;
    if let Some(reason) = message
        .pointer("/result/stopReason")
        .and_then(Value::as_str)
    {
        turn.stop_reason = Some(reason.to_string());
    }
    turn.truncated = message
        .pointer("/result/error_kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.contains("truncation"));
    let usage_incomplete = message
        .pointer("/result/usage_is_incomplete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cost_partial = message
        .pointer("/result/cost_is_partial")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(usage) = message.pointer("/result/usage") {
        turn.terminal_usage = Some(project_terminal_usage_from_prompt(
            session_id,
            message.pointer("/result/promptId").and_then(Value::as_str),
            usage,
            usage_incomplete,
            cost_partial,
        ));
    }
    if let Some(meta) = message.pointer("/result/_meta") {
        turn.prompt_result_meta = Some(meta.clone());
        if turn.terminal_usage.is_none() {
            if let Some(usage) = meta.get("usage") {
                turn.terminal_usage = Some(project_terminal_usage_from_prompt(
                    session_id,
                    message.pointer("/result/promptId").and_then(Value::as_str),
                    usage,
                    usage_incomplete,
                    cost_partial,
                ));
            }
        }
    }
    if let Some(text) = message.pointer("/result/text").and_then(Value::as_str) {
        turn.final_text = Some(text.to_string());
    }
}

fn poll_active_steering_correction<T, C, S>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    prompt_request_id: &RequestId,
    cancelled: &C,
    steering: &mut S,
) -> Result<Option<SteeringApplication>, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
    S: GrokAcpSteering,
{
    try_poll_steering_correction(
        state,
        transport,
        prompt_ctx,
        SupersededPromptState::Active {
            request_id: prompt_request_id,
        },
        cancelled,
        steering,
    )
}

fn poll_completed_steering_correction<T, C, S>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    cancelled: &C,
    steering: &mut S,
) -> Result<Option<SteeringApplication>, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
    S: GrokAcpSteering,
{
    try_poll_steering_correction(
        state,
        transport,
        prompt_ctx,
        SupersededPromptState::Completed,
        cancelled,
        steering,
    )
}

fn drive_prompt<T, C, S>(
    state: &mut ProtocolState,
    transport: &mut T,
    prompt_ctx: &mut PromptSessionContext<'_>,
    initial_prompt_request_id: &RequestId,
    cancelled: &C,
    steering: &mut S,
) -> Result<PromptDriveOutcome, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
    S: GrokAcpSteering,
{
    let mut prompt_request_id = initial_prompt_request_id.clone();
    let mut prior_prompts_interrupted = false;
    let mut pending_ack: Option<SteeringApplication> = None;
    let mut line = Vec::new();

    let latest_terminal = loop {
        let mut turn = PromptTurnAccumulators::default();
        let mut restarted_for_steering = false;

        'receive: loop {
            if pending_ack.is_none() {
                if let Some(application) = poll_active_steering_correction(
                    state,
                    transport,
                    prompt_ctx,
                    &prompt_request_id,
                    cancelled,
                    steering,
                )? {
                    prior_prompts_interrupted = true;
                    prompt_request_id = application.prompt_request_id.clone();
                    pending_ack = Some(application);
                    restarted_for_steering = true;
                    break 'receive;
                }
            }

            let correction_deadline = pending_ack
                .as_ref()
                .map(|pending| pending.correction_deadline);
            match state.receive_one_slice(
                transport,
                "session/prompt",
                cancelled,
                &mut line,
                correction_deadline,
            )? {
                ReceiveOneSliceOutcome::Idle => continue,
                ReceiveOneSliceOutcome::Message(message) => {
                    if let Some(id) = message.get("id") {
                        if message.get("method").is_some() {
                            let method =
                                required_text(&message, &["method"], "session/prompt", "method")?;
                            refuse_server_request(
                                state,
                                transport,
                                &message,
                                method,
                                prompt_ctx.permission_escalation_refused,
                            )?;
                            continue;
                        }
                        let parsed = RequestId::parse(id, "session/prompt")?;
                        if !state.response_ids.insert(parsed.clone()) {
                            return Err(GrokAcpError::Duplicate {
                                phase: "session/prompt",
                                message: "duplicate response id".to_string(),
                            });
                        }
                        if parsed != prompt_request_id {
                            return Err(GrokAcpError::Unexpected {
                                phase: "session/prompt",
                                message: "unexpected correlated response during prompt".to_string(),
                            });
                        }
                        if message.get("error").is_some() {
                            return Err(GrokAcpError::Remote {
                                phase: "session/prompt",
                                message: bounded_json_summary(
                                    message.get("error").unwrap_or(&Value::Null),
                                ),
                            });
                        }
                        ingest_prompt_terminal_response(&message, prompt_ctx.session_id, &mut turn);
                        break 'receive;
                    }

                    dispatch_prompt_notification(
                        state,
                        transport,
                        prompt_ctx,
                        &message,
                        "session/prompt",
                        Some((
                            &mut turn.final_text,
                            &mut turn.stop_reason,
                            &mut turn.truncated,
                        )),
                    )?;

                    if pending_ack.is_none() {
                        if let Some(application) = poll_active_steering_correction(
                            state,
                            transport,
                            prompt_ctx,
                            &prompt_request_id,
                            cancelled,
                            steering,
                        )? {
                            prior_prompts_interrupted = true;
                            prompt_request_id = application.prompt_request_id.clone();
                            pending_ack = Some(application);
                            restarted_for_steering = true;
                            break 'receive;
                        }
                    }
                }
            }
        }

        if restarted_for_steering {
            continue;
        }

        if let Some(pending) = pending_ack.take() {
            ensure_correction_actionable(state, pending.correction_deadline)?;
            steering
                .acknowledge(&pending.action_id)
                .map_err(|message| GrokAcpError::Transport { message })?;
        }

        if let Some(application) =
            poll_completed_steering_correction(state, transport, prompt_ctx, cancelled, steering)?
        {
            prior_prompts_interrupted = true;
            prompt_request_id = application.prompt_request_id.clone();
            pending_ack = Some(application);
            continue;
        }
        break turn;
    };

    Ok(PromptDriveOutcome {
        final_text: latest_terminal.final_text,
        stop_reason: latest_terminal.stop_reason,
        terminal_usage: latest_terminal.terminal_usage,
        prompt_result_meta: latest_terminal.prompt_result_meta,
        prompt_acknowledged: latest_terminal.prompt_acknowledged,
        truncated: latest_terminal.truncated,
        prior_prompts_interrupted,
    })
}

fn drain_until_response_or_model_changed<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    expected_id: &RequestId,
    session_id: &str,
    model_tracker: &mut ModelResolutionTracker,
    cancelled: &C,
    permission_escalation_refused: &mut bool,
) -> Result<(), GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    let phase = METHOD_SESSION_SET_MODEL;
    let mut response_seen = false;
    while !response_seen {
        let message = state.receive(transport, phase, cancelled)?;
        if let Some(id) = message.get("id") {
            if message.get("method").is_some() {
                let method = required_text(&message, &["method"], phase, "method")?;
                refuse_server_request(
                    state,
                    transport,
                    &message,
                    method,
                    permission_escalation_refused,
                )?;
                continue;
            }
            let parsed = RequestId::parse(id, phase)?;
            if !state.response_ids.insert(parsed.clone()) {
                return Err(GrokAcpError::Duplicate {
                    phase,
                    message: "duplicate response id".to_string(),
                });
            }
            if &parsed != expected_id {
                return Err(GrokAcpError::Unexpected {
                    phase,
                    message: "response id did not match the pending set_model request".to_string(),
                });
            }
            if message.get("error").is_some() {
                model_tracker.invalidate_set_model_ack();
                return Err(GrokAcpError::Remote {
                    phase,
                    message: bounded_json_summary(message.get("error").unwrap_or(&Value::Null)),
                });
            }
            response_seen = true;
            model_tracker.commit_set_model_ack(&message)?;
            continue;
        }
        let method = required_text(&message, &["method"], phase, "method")?;
        match method {
            _ if method == METHOD_XAI_SESSION_NOTIFICATION => {
                handle_xai_session_notification(&message, session_id, model_tracker, None)?;
            }
            METHOD_SESSION_UPDATE => {
                let params = required_object(&message, &["params"], phase, "params")?;
                let wire_session = map_required_text(params, "sessionId", phase, "session id")?;
                if wire_session != session_id {
                    return Err(GrokAcpError::Unexpected {
                        phase,
                        message: "session/update targeted a different session".to_string(),
                    });
                }
                let update = params
                    .get("update")
                    .and_then(Value::as_object)
                    .ok_or_else(|| GrokAcpError::Malformed {
                        phase,
                        message: "session/update update is not an object".to_string(),
                    })?;
                if update.get("sessionUpdate").and_then(Value::as_str) == Some("model_changed") {
                    let model_id =
                        update
                            .get("model_id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| GrokAcpError::Malformed {
                                phase,
                                message: "model_changed missing model_id".to_string(),
                            })?;
                    let effort = update.get("reasoning_effort").and_then(Value::as_str);
                    model_tracker.note_model_changed(model_id, effort);
                }
            }
            _ if method == METHOD_SESSION_REQUEST_PERMISSION || method.starts_with('_') => {
                refuse_server_request(
                    state,
                    transport,
                    &message,
                    method,
                    permission_escalation_refused,
                )?;
            }
            _ => {
                if is_escalation_method(method) {
                    refuse_server_request(
                        state,
                        transport,
                        &message,
                        method,
                        permission_escalation_refused,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn handle_xai_session_notification(
    message: &Value,
    session_id: &str,
    model_tracker: &mut ModelResolutionTracker,
    supplement: Option<(&mut Option<String>, &mut Option<String>, &mut bool)>,
) -> Result<(), GrokAcpError> {
    let params = required_object(message, &["params"], "x.ai/session_notification", "params")?;
    let wire_session = map_required_text(
        params,
        "sessionId",
        "x.ai/session_notification",
        "session id",
    )?;
    if wire_session != session_id {
        return Err(GrokAcpError::Unexpected {
            phase: "x.ai/session_notification",
            message: "session_notification targeted a different session".to_string(),
        });
    }
    let update = params
        .get("update")
        .and_then(Value::as_object)
        .ok_or_else(|| GrokAcpError::Malformed {
            phase: "x.ai/session_notification",
            message: "session notification update is not an object".to_string(),
        })?;
    let tag = update
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .ok_or_else(|| GrokAcpError::Malformed {
            phase: "x.ai/session_notification",
            message: "session notification missing sessionUpdate".to_string(),
        })?;
    match tag {
        "model_changed" => {
            let model_id = update
                .get("model_id")
                .and_then(Value::as_str)
                .ok_or_else(|| GrokAcpError::Malformed {
                    phase: "x.ai/session_notification",
                    message: "model_changed missing model_id".to_string(),
                })?;
            let effort = update.get("reasoning_effort").and_then(Value::as_str);
            model_tracker.note_model_changed(model_id, effort);
        }
        "turn_completed" => {
            if let Some((final_text, stop_reason, truncated)) = supplement {
                apply_turn_completed_supplement(update, final_text, stop_reason, truncated);
            }
        }
        _ => {}
    }
    Ok(())
}

fn apply_turn_completed_supplement(
    update: &Map<String, Value>,
    final_text: &mut Option<String>,
    stop_reason: &mut Option<String>,
    truncated: &mut bool,
) {
    if stop_reason.is_none() {
        if let Some(reason) = update.get("stop_reason").and_then(Value::as_str) {
            *stop_reason = Some(reason.to_string());
        }
    }
    if final_text.is_none() {
        if let Some(result) = update.get("agent_result").and_then(Value::as_str) {
            *final_text = Some(result.to_string());
        }
    }
    if update
        .get("error_kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.contains("truncation"))
    {
        *truncated = true;
    }
}

fn project_terminal_usage_from_prompt(
    session_id: &str,
    prompt_id: Option<&str>,
    usage: &Value,
    usage_is_incomplete: bool,
    cost_is_partial: bool,
) -> GrokAcpTerminalUsage {
    let projected = if usage_is_incomplete || cost_is_partial {
        None
    } else {
        Some(usage.clone())
    };
    GrokAcpTerminalUsage {
        usage_is_incomplete,
        cost_is_partial,
        session_id: session_id.to_string(),
        prompt_id: prompt_id.map(str::to_string),
        projected,
    }
}

fn refuse_server_request<T: GrokAcpJsonLineTransport>(
    state: &mut ProtocolState,
    transport: &mut T,
    message: &Value,
    method: &str,
    permission_escalation_refused: &mut bool,
) -> Result<(), GrokAcpError> {
    *permission_escalation_refused = true;
    let request_id = message
        .get("id")
        .ok_or_else(|| GrokAcpError::Malformed {
            phase: "server request",
            message: "server request lacks id".to_string(),
        })
        .and_then(|value| RequestId::parse(value, "server request"))?;
    if !state.server_request_ids.insert(request_id.clone()) {
        return Err(GrokAcpError::Duplicate {
            phase: "server request",
            message: "duplicate server request id".to_string(),
        });
    }
    let result = if method == METHOD_SESSION_REQUEST_PERMISSION {
        json!({
            "jsonrpc": "2.0",
            "id": request_id.to_value(),
            "result": {
                "outcome": {"outcome": "cancelled"}
            }
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": request_id.to_value(),
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        })
    };
    state.send(transport, &result)?;
    Ok(())
}

fn is_escalation_method(method: &str) -> bool {
    matches!(
        method,
        "fs/read_text_file"
            | "fs/write_text_file"
            | "terminal/create"
            | "terminal/output"
            | "terminal/release"
            | "terminal/wait_for_exit"
            | "terminal/kill"
    )
}

fn best_effort_cancel<T: GrokAcpJsonLineTransport>(
    state: &mut ProtocolState,
    transport: &mut T,
    session_id: &str,
) -> Result<(), GrokAcpError> {
    let _ = state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "method": METHOD_SESSION_CANCEL,
            "params": {"sessionId": session_id}
        }),
    );
    Ok(())
}

fn wait_for_response<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    expected_id: &RequestId,
    phase: &'static str,
    cancelled: &C,
) -> Result<Value, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    let message = state.receive(transport, phase, cancelled)?;
    let object = message.as_object().ok_or_else(|| GrokAcpError::Malformed {
        phase,
        message: "top-level message is not an object".to_string(),
    })?;
    if object.contains_key("method") {
        return Err(GrokAcpError::Unexpected {
            phase,
            message: "notification or server request arrived before the correlated response"
                .to_string(),
        });
    }
    let id = object
        .get("id")
        .ok_or_else(|| GrokAcpError::Malformed {
            phase,
            message: "response has no id".to_string(),
        })
        .and_then(|value| RequestId::parse(value, phase))?;
    if !state.response_ids.insert(id.clone()) {
        return Err(GrokAcpError::Duplicate {
            phase,
            message: "response id was already completed".to_string(),
        });
    }
    if &id != expected_id {
        return Err(GrokAcpError::Unexpected {
            phase,
            message: "response id did not match the pending request".to_string(),
        });
    }
    if let Some(error) = object.get("error") {
        return Err(GrokAcpError::Remote {
            phase,
            message: bounded_json_summary(error),
        });
    }
    if !object.get("result").is_some_and(Value::is_object) {
        return Err(GrokAcpError::Malformed {
            phase,
            message: "response result is missing or is not an object".to_string(),
        });
    }
    Ok(message)
}

fn validate_identifier(value: &str, label: &str, max_len: usize) -> Result<(), GrokAcpError> {
    if value.is_empty() || value.len() > max_len || value.contains(['\0', '\n', '\r']) {
        return Err(GrokAcpError::InvalidConfiguration {
            message: format!("{label} is empty or malformed"),
        });
    }
    Ok(())
}

fn required_text<'a>(
    value: &'a Value,
    path: &[&str],
    phase: &'static str,
    label: &'static str,
) -> Result<&'a str, GrokAcpError> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or_else(|| GrokAcpError::Malformed {
                phase,
                message: format!("{label} path missing `{segment}`"),
            })?;
    }
    current.as_str().ok_or_else(|| GrokAcpError::Malformed {
        phase,
        message: format!("{label} is not a string"),
    })
}

fn map_required_text<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    phase: &'static str,
    label: &'static str,
) -> Result<&'a str, GrokAcpError> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| GrokAcpError::Malformed {
            phase,
            message: format!("{label} missing or not a string"),
        })
}

fn required_object<'a>(
    value: &'a Value,
    path: &[&str],
    phase: &'static str,
    label: &'static str,
) -> Result<&'a Map<String, Value>, GrokAcpError> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or_else(|| GrokAcpError::Malformed {
                phase,
                message: format!("{label} path missing `{segment}`"),
            })?;
    }
    current.as_object().ok_or_else(|| GrokAcpError::Malformed {
        phase,
        message: format!("{label} is not an object"),
    })
}

fn bounded_json_summary(value: &Value) -> String {
    let serialized = value.to_string();
    if serialized.len() > 512 {
        format!("{}…", serialized.chars().take(512).collect::<String>())
    } else {
        serialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptTransport {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
    }

    impl ScriptTransport {
        fn from_values(values: Vec<Value>) -> Self {
            let inbound: Vec<Vec<u8>> = values
                .into_iter()
                .map(|value| serde_json::to_vec(&value).expect("fixture json"))
                .map(|bytes| {
                    let mut line = bytes;
                    line.push(b'\n');
                    line
                })
                .collect();
            Self {
                inbound: VecDeque::from(inbound),
                outbound: Vec::new(),
            }
        }
    }

    impl GrokAcpJsonLineTransport for ScriptTransport {
        fn receive(
            &mut self,
            _wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            destination.clear();
            let line = self
                .inbound
                .pop_front()
                .ok_or_else(|| "fixture exhausted".to_string())?;
            if line.len() > max_line_bytes {
                return Err("fixture line exceeded bound".to_string());
            }
            destination.extend_from_slice(&line);
            Ok(GrokAcpTransportRead::Line)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            self.outbound.push(line.to_vec());
            Ok(())
        }
    }

    fn base_handshake(session_id: &str) -> Vec<Value> {
        vec![
            json!({"id": 1, "result": {"protocolVersion": 1}}),
            json!({"id": 2, "result": {"sessionId": session_id}}),
        ]
    }

    fn parse_outbound(transport: &ScriptTransport, index: usize) -> Value {
        let line = transport.outbound.get(index).expect("outbound frame");
        serde_json::from_slice(line).expect("outbound json")
    }

    fn model_changed_notification(session_id: &str, model: &str, effort: Option<&str>) -> Value {
        let mut update = json!({
            "sessionUpdate": "model_changed",
            "model_id": model
        });
        if let Some(effort) = effort {
            update
                .as_object_mut()
                .expect("update object")
                .insert("reasoning_effort".into(), Value::from(effort));
        }
        json!({
            "jsonrpc": "2.0",
            "method": METHOD_XAI_SESSION_NOTIFICATION,
            "params": {
                "sessionId": session_id,
                "update": update
            }
        })
    }

    fn set_model_ack(model: &str) -> Value {
        json!({"id": 3, "result": {"_meta": {"model": model}}})
    }

    fn prompt_ack(complete: bool) -> Value {
        json!({
            "id": 4,
            "result": {
                "stopReason": "end_turn",
                "text": "hello",
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
                "usage_is_incomplete": !complete,
                "cost_is_partial": false
            }
        })
    }

    fn successful_transcript(resolved_effort: &str) -> Vec<Value> {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification(
            "sess-1",
            "grok-4",
            Some(resolved_effort),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(true));
        messages
    }

    fn successful_transcript_with_prompt_meta(
        resolved_model: &str,
        resolved_effort: &str,
        prompt_result: Value,
    ) -> Vec<Value> {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification(
            "sess-1",
            resolved_model,
            Some(resolved_effort),
        ));
        messages.push(set_model_ack(resolved_model));
        messages.push(prompt_result);
        messages
    }

    fn prompt_ack_with_structured(structured: Value) -> Value {
        json!({
            "id": 4,
            "result": {
                "stopReason": "end_turn",
                "text": "hello",
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
                "usage_is_incomplete": false,
                "cost_is_partial": false,
                "_meta": {
                    "structuredOutput": structured
                }
            }
        })
    }

    fn prompt_ack_with_structured_error() -> Value {
        json!({
            "id": 4,
            "result": {
                "stopReason": "end_turn",
                "text": "hello",
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
                "usage_is_incomplete": false,
                "cost_is_partial": false,
                "_meta": {
                    "structuredOutputError": "terminal schema validation failed"
                }
            }
        })
    }

    fn publication_schema() -> GrokAcpBoundOutputSchema {
        GrokAcpBoundOutputSchema::from_canonical_json(
            r#"{"properties":{"accepted":{"type":"boolean"}},"required":["accepted"],"type":"object"}"#,
        )
        .expect("publication schema")
    }

    fn requested_turn(
        model: &str,
        effort: &str,
        schema: Option<GrokAcpBoundOutputSchema>,
    ) -> GrokAcpTurn {
        GrokAcpTurn {
            cwd: "/tmp".into(),
            prompt: "ping".into(),
            requested_model: Some(model.into()),
            requested_effort: Some(effort.into()),
            output_schema: schema,
        }
    }

    #[test]
    fn prompt_meta_usage_cost_projects_to_parent_microunits() {
        let mut messages = base_handshake("sess-cost");
        messages.push(model_changed_notification(
            "sess-cost",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(json!({
            "id": 4,
            "result": {
                "stopReason": "end_turn",
                "text": "hello",
                "usage_is_incomplete": false,
                "cost_is_partial": false,
                "_meta": {
                    "usage": {
                        "inputTokens": 10,
                        "outputTokens": 2,
                        "costUsdTicks": 20_000_000
                    }
                }
            }
        }));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn with meta usage");
        let parent =
            crate::runtime_adapter::grok::grok_acp_parent_evidence_from_execution(evidence);
        assert_eq!(
            parent.native_cost_equivalent_microunits,
            crate::runtime_adapter::grok::GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 20_000_000,
                microunits: 200,
            }
        );
    }

    #[test]
    fn outbound_initialize_includes_protocol_version() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn");
        let init = parse_outbound(&transport, 0);
        assert_eq!(init.get("method"), Some(&Value::from(METHOD_INITIALIZE)));
        assert_eq!(
            init.pointer("/params/protocolVersion"),
            Some(&Value::from(SUPPORTED_ACP_PROTOCOL_VERSION))
        );
        assert!(
            !transport.outbound.iter().any(|line| {
                serde_json::from_slice::<Value>(line)
                    .is_ok_and(|value| value.get("method") == Some(&Value::from("initialized")))
            }),
            "must not emit MCP-style initialized notification"
        );
    }

    #[test]
    fn outbound_set_model_uses_traced_meta_and_method() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn");
        let set_model = parse_outbound(&transport, 2);
        assert_eq!(
            set_model.get("method"),
            Some(&Value::from(METHOD_SESSION_SET_MODEL))
        );
        assert_eq!(
            set_model.pointer("/params/_meta/reasoningEffort"),
            Some(&Value::from("low"))
        );
    }

    #[test]
    fn resolved_effort_differs_from_requested() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("successful turn");
        assert_eq!(
            evidence.client_resolved.effort,
            GrokAcpResolvedField::Known("high".into())
        );
        assert_eq!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
        assert!(evidence
            .terminal_usage
            .as_ref()
            .is_some_and(|u| u.projected.is_some()));
    }

    #[test]
    fn model_changed_before_ack_commits_on_matching_response() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", Some("high")));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("notification before ack");
        assert_eq!(
            evidence.client_resolved,
            GrokAcpClientResolvedModelEffort {
                model: GrokAcpResolvedField::Known("grok-4".into()),
                effort: GrokAcpResolvedField::Known("high".into()),
            }
        );
    }

    #[test]
    fn spoofed_model_in_agent_text_does_not_set_metadata() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", None));
        messages.push(set_model_ack("grok-4"));
        messages.push(json!({
            "method": METHOD_SESSION_UPDATE,
            "params": {
                "sessionId": "sess-1",
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": "model_id: grok-spoofed"}
                }
            }
        }));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: None,
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn");
        assert_eq!(
            evidence.client_resolved.model,
            GrokAcpResolvedField::Known("grok-4".into())
        );
        assert_eq!(evidence.final_text.as_deref(), Some("hello"));
        assert_ne!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
    }

    #[test]
    fn incomplete_prompt_usage_never_yields_complete_observation() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", Some("high")));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(false));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn with incomplete usage");
        assert_ne!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
        assert!(evidence
            .terminal_usage
            .as_ref()
            .is_some_and(|u| u.projected.is_none()));
    }

    #[test]
    fn wrong_session_notification_is_rejected() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-other", "grok-4", None));
        let mut transport = ScriptTransport::from_values(messages);
        let error = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: None,
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect_err("wrong session");
        assert!(matches!(
            error,
            GrokAcpError::Unexpected {
                phase: "x.ai/session_notification",
                ..
            }
        ));
    }

    #[test]
    fn tool_permission_escalation_is_refused() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", Some("high")));
        messages.push(set_model_ack("grok-4"));
        messages.push(json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": METHOD_SESSION_REQUEST_PERMISSION,
            "params": {
                "sessionId": "sess-1",
                "toolCallUpdate": {"toolCallId": "tc-1"},
                "options": []
            }
        }));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("turn with permission");
        assert!(evidence.permission_escalation_refused);
        assert_eq!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
    }

    #[derive(Default)]
    struct SequenceFixtureState {
        idle_slices_returned: usize,
    }

    struct SequenceSteeringTransport {
        early: VecDeque<Vec<u8>>,
        late: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
        idle_before_correction: bool,
        prompt_sends: usize,
        idle_slices_returned: usize,
        shared: std::rc::Rc<std::cell::RefCell<SequenceFixtureState>>,
    }

    impl SequenceSteeringTransport {
        fn for_steering_turn(early_messages: Vec<Value>, late_messages: Vec<Value>) -> Self {
            let map_lines = |values: Vec<Value>| {
                values
                    .into_iter()
                    .map(|value| {
                        let mut line = serde_json::to_vec(&value).expect("fixture json");
                        line.push(b'\n');
                        line
                    })
                    .collect::<VecDeque<_>>()
            };
            Self {
                early: map_lines(early_messages),
                late: map_lines(late_messages),
                outbound: Vec::new(),
                idle_before_correction: false,
                prompt_sends: 0,
                idle_slices_returned: 0,
                shared: std::rc::Rc::new(std::cell::RefCell::new(SequenceFixtureState::default())),
            }
        }

        fn idle_slices_returned(&self) -> usize {
            self.idle_slices_returned
        }

        fn shared_fixture_state(&self) -> std::rc::Rc<std::cell::RefCell<SequenceFixtureState>> {
            self.shared.clone()
        }

        fn outbound_frames(&self) -> Vec<Value> {
            self.outbound
                .iter()
                .map(|line| serde_json::from_slice(line).expect("outbound json"))
                .collect()
        }

        fn record_idle_slice(&mut self) {
            self.idle_slices_returned = self.idle_slices_returned.saturating_add(1);
            self.shared.borrow_mut().idle_slices_returned = self.idle_slices_returned;
        }
    }

    impl GrokAcpJsonLineTransport for SequenceSteeringTransport {
        fn receive(
            &mut self,
            _wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            destination.clear();
            if let Some(line) = self.early.pop_front() {
                if line.len() > max_line_bytes {
                    return Err("fixture line exceeded bound".to_string());
                }
                destination.extend_from_slice(&line);
                return Ok(GrokAcpTransportRead::Line);
            }
            if self.idle_before_correction {
                self.idle_before_correction = false;
                self.record_idle_slice();
                return Ok(GrokAcpTransportRead::Timeout);
            }
            let Some(line) = self.late.pop_front() else {
                self.record_idle_slice();
                return Ok(GrokAcpTransportRead::Timeout);
            };
            if line.len() > max_line_bytes {
                return Err("fixture line exceeded bound".to_string());
            }
            destination.extend_from_slice(&line);
            Ok(GrokAcpTransportRead::Line)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            let value: Value = serde_json::from_slice(line).expect("outbound json");
            if value.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT))
                && self.early.is_empty()
            {
                self.prompt_sends = self.prompt_sends.saturating_add(1);
                if self.prompt_sends == 1 {
                    self.idle_before_correction = true;
                }
            }
            self.outbound.push(line.to_vec());
            Ok(())
        }
    }

    struct TimeAdvancingSequenceTransport {
        inner: SequenceSteeringTransport,
    }

    impl TimeAdvancingSequenceTransport {
        fn for_steering_turn(early_messages: Vec<Value>, late_messages: Vec<Value>) -> Self {
            Self {
                inner: SequenceSteeringTransport::for_steering_turn(early_messages, late_messages),
            }
        }

        fn outbound(&self) -> &[Vec<u8>] {
            &self.inner.outbound
        }
    }

    impl GrokAcpJsonLineTransport for TimeAdvancingSequenceTransport {
        fn receive(
            &mut self,
            wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            let outcome = self.inner.receive(wait, max_line_bytes, destination)?;
            if outcome == GrokAcpTransportRead::Timeout {
                std::thread::sleep(wait);
            }
            Ok(outcome)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            self.inner.send(line)
        }
    }

    struct CorrectiveCompletionDeadlineTransport {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
        corrective_prompt_sent: bool,
    }

    impl CorrectiveCompletionDeadlineTransport {
        fn from_values(values: Vec<Value>) -> Self {
            let inbound: Vec<Vec<u8>> = values
                .into_iter()
                .map(|value| {
                    let mut line = serde_json::to_vec(&value).expect("fixture json");
                    line.push(b'\n');
                    line
                })
                .collect();
            Self {
                inbound: VecDeque::from(inbound),
                outbound: Vec::new(),
                corrective_prompt_sent: false,
            }
        }

        fn outbound_frames(&self) -> Vec<Value> {
            self.outbound
                .iter()
                .map(|line| serde_json::from_slice(line).expect("outbound json"))
                .collect()
        }
    }

    impl GrokAcpJsonLineTransport for CorrectiveCompletionDeadlineTransport {
        fn receive(
            &mut self,
            wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            destination.clear();
            if let Some(line) = self.inbound.pop_front() {
                if line.len() > max_line_bytes {
                    return Err("fixture line exceeded bound".to_string());
                }
                destination.extend_from_slice(&line);
                return Ok(GrokAcpTransportRead::Line);
            }
            if self.corrective_prompt_sent {
                std::thread::sleep(wait);
            }
            Ok(GrokAcpTransportRead::Timeout)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            let value: Value = serde_json::from_slice(line).expect("outbound json");
            if value.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT))
                && value.get("id") == Some(&Value::from(5))
            {
                self.corrective_prompt_sent = true;
            }
            self.outbound.push(line.to_vec());
            Ok(())
        }
    }

    struct ObservedInboundScriptTransport {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
        original_prompt_terminal_delivered: std::rc::Rc<std::cell::RefCell<bool>>,
    }

    impl ObservedInboundScriptTransport {
        fn from_values(values: Vec<Value>) -> Self {
            let inbound: Vec<Vec<u8>> = values
                .into_iter()
                .map(|value| {
                    let mut line = serde_json::to_vec(&value).expect("fixture json");
                    line.push(b'\n');
                    line
                })
                .collect();
            Self {
                inbound: VecDeque::from(inbound),
                outbound: Vec::new(),
                original_prompt_terminal_delivered: std::rc::Rc::new(std::cell::RefCell::new(
                    false,
                )),
            }
        }

        fn original_prompt_terminal_gate(&self) -> std::rc::Rc<std::cell::RefCell<bool>> {
            self.original_prompt_terminal_delivered.clone()
        }

        fn outbound_frames(&self) -> Vec<Value> {
            self.outbound
                .iter()
                .map(|line| serde_json::from_slice(line).expect("outbound json"))
                .collect()
        }
    }

    impl GrokAcpJsonLineTransport for ObservedInboundScriptTransport {
        fn receive(
            &mut self,
            _wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            destination.clear();
            let line = self
                .inbound
                .pop_front()
                .ok_or_else(|| "fixture exhausted".to_string())?;
            if line.len() > max_line_bytes {
                return Err("fixture line exceeded bound".to_string());
            }
            if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                if value.get("id") == Some(&Value::from(4)) && value.get("result").is_some() {
                    *self.original_prompt_terminal_delivered.borrow_mut() = true;
                }
            }
            destination.extend_from_slice(&line);
            Ok(GrokAcpTransportRead::Line)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            self.outbound.push(line.to_vec());
            Ok(())
        }
    }

    struct ActiveCorrectiveLifecycleTransport {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
        corrective_prompt_sent: std::rc::Rc<std::cell::RefCell<bool>>,
    }

    impl ActiveCorrectiveLifecycleTransport {
        fn for_whole_task_cancel() -> Self {
            let mut messages = base_handshake("sess-cancel");
            messages.push(model_changed_notification(
                "sess-cancel",
                "grok-4",
                Some("high"),
            ));
            messages.push(set_model_ack("grok-4"));
            messages.push(agent_message_chunk("sess-cancel", "streaming"));
            messages.push(prompt_cancelled_response(4));
            Self::from_values(messages)
        }

        fn from_values(values: Vec<Value>) -> Self {
            let inbound: Vec<Vec<u8>> = values
                .into_iter()
                .map(|value| {
                    let mut line = serde_json::to_vec(&value).expect("fixture json");
                    line.push(b'\n');
                    line
                })
                .collect();
            Self {
                inbound: VecDeque::from(inbound),
                outbound: Vec::new(),
                corrective_prompt_sent: std::rc::Rc::new(std::cell::RefCell::new(false)),
            }
        }

        fn corrective_prompt_sent_flag(&self) -> std::rc::Rc<std::cell::RefCell<bool>> {
            self.corrective_prompt_sent.clone()
        }

        fn outbound_frames(&self) -> Vec<Value> {
            self.outbound
                .iter()
                .map(|line| serde_json::from_slice(line).expect("outbound json"))
                .collect()
        }
    }

    impl GrokAcpJsonLineTransport for ActiveCorrectiveLifecycleTransport {
        fn receive(
            &mut self,
            _wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<GrokAcpTransportRead, String> {
            destination.clear();
            let Some(line) = self.inbound.pop_front() else {
                return Ok(GrokAcpTransportRead::Timeout);
            };
            if line.len() > max_line_bytes {
                return Err("fixture line exceeded bound".to_string());
            }
            destination.extend_from_slice(&line);
            Ok(GrokAcpTransportRead::Line)
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            let value: Value = serde_json::from_slice(line).expect("outbound json");
            if value.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT))
                && value.get("id") == Some(&Value::from(5))
            {
                *self.corrective_prompt_sent.borrow_mut() = true;
            }
            self.outbound.push(line.to_vec());
            Ok(())
        }
    }

    fn outbound_prompt_ids(transport: &TimeAdvancingSequenceTransport) -> Vec<Value> {
        transport
            .outbound()
            .iter()
            .filter(|line| {
                serde_json::from_slice::<Value>(line).is_ok_and(|value| {
                    value.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT))
                })
            })
            .map(|line| {
                serde_json::from_slice::<Value>(line)
                    .expect("outbound json")
                    .get("id")
                    .cloned()
                    .expect("prompt request id")
            })
            .collect()
    }

    fn short_correction_deadline_from_now() -> Instant {
        Instant::now() + CANCELLATION_POLL_INTERVAL / 2
    }

    struct DeadlineAtFetchSteering {
        action_id: String,
        prompt: String,
        fetched: bool,
        acked: Vec<String>,
    }

    impl GrokAcpSteering for DeadlineAtFetchSteering {
        fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
            if self.fetched {
                return Ok(None);
            }
            self.fetched = true;
            Ok(Some(GrokAcpCorrection {
                action_id: self.action_id.clone(),
                prompt: self.prompt.clone(),
                deadline: short_correction_deadline_from_now(),
            }))
        }

        fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
            self.acked.push(action_id.to_string());
            Ok(())
        }
    }

    #[test]
    fn steering_correction_deadline_expires_during_old_prompt_drain_without_late_prompt_or_ack() {
        let early = steering_early_messages("sess-drain-exp");
        let late = Vec::new();
        let mut transport = TimeAdvancingSequenceTransport::for_steering_turn(early, late);
        let mut steering = DeadlineAtFetchSteering {
            action_id: "drain-expired".into(),
            prompt: "never sent".into(),
            fetched: false,
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("drain should hit steering correction deadline");
        assert!(matches!(
            error,
            GrokAcpError::Timeout {
                phase: "steering correction",
            }
        ));
        assert!(steering.acked.is_empty());
        assert_eq!(outbound_prompt_ids(&transport), vec![Value::from(4)]);
    }

    #[test]
    fn steering_correction_deadline_expires_during_corrective_completion_without_ack() {
        let mut messages = base_handshake("sess-corrective-exp");
        messages.push(model_changed_notification(
            "sess-corrective-exp",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(agent_message_chunk("sess-corrective-exp", "streaming"));
        messages.push(prompt_cancelled_response(4));
        let mut transport = CorrectiveCompletionDeadlineTransport::from_values(messages);
        let mut steering = DeadlineAtFetchSteering {
            action_id: "corrective-expired".into(),
            prompt: "corrective".into(),
            fetched: false,
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("corrective completion should hit steering correction deadline");
        assert!(matches!(
            error,
            GrokAcpError::Timeout {
                phase: "steering correction",
            }
        ));
        assert!(steering.acked.is_empty());
        let prompt_ids: Vec<_> = transport
            .outbound_frames()
            .iter()
            .filter(|frame| frame.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT)))
            .map(|frame| frame.get("id").cloned().expect("prompt id"))
            .collect();
        assert_eq!(prompt_ids, vec![Value::from(4), Value::from(5)]);
    }

    struct QueueSteering {
        corrections: VecDeque<GrokAcpCorrection>,
        acked: Vec<String>,
    }

    impl GrokAcpSteering for QueueSteering {
        fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
            Ok(self.corrections.pop_front())
        }

        fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
            self.acked.push(action_id.to_string());
            Ok(())
        }
    }

    struct IdleSliceGatedSteering {
        fixture: std::rc::Rc<std::cell::RefCell<SequenceFixtureState>>,
        correction: GrokAcpCorrection,
        offered: bool,
        acked: Vec<String>,
    }

    impl GrokAcpSteering for IdleSliceGatedSteering {
        fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
            if self.fixture.borrow().idle_slices_returned == 0 {
                return Ok(None);
            }
            if self.offered {
                return Ok(None);
            }
            self.offered = true;
            Ok(Some(self.correction.clone()))
        }

        fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
            self.acked.push(action_id.to_string());
            Ok(())
        }
    }

    struct QueuedAfterOriginalTerminalSteering {
        original_terminal_gate: std::rc::Rc<std::cell::RefCell<bool>>,
        correction: GrokAcpCorrection,
        offered: bool,
        acked: Vec<String>,
    }

    impl GrokAcpSteering for QueuedAfterOriginalTerminalSteering {
        fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
            if !*self.original_terminal_gate.borrow() {
                return Ok(None);
            }
            if self.offered {
                return Ok(None);
            }
            self.offered = true;
            Ok(Some(self.correction.clone()))
        }

        fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
            self.acked.push(action_id.to_string());
            Ok(())
        }
    }

    fn outbound_frames_from_script(transport: &ScriptTransport) -> Vec<Value> {
        transport
            .outbound
            .iter()
            .map(|line| serde_json::from_slice(line).expect("outbound json"))
            .collect()
    }

    fn prompt_frame_indices(frames: &[Value]) -> Vec<(usize, Value)> {
        frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT)))
            .map(|(index, frame)| (index, frame.get("id").cloned().expect("prompt id")))
            .collect()
    }

    fn cancel_frame_indices(frames: &[Value]) -> Vec<usize> {
        frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.get("method") == Some(&Value::from(METHOD_SESSION_CANCEL)))
            .map(|(index, _)| index)
            .collect()
    }

    fn assert_no_cancel_between_outbound_indices(frames: &[Value], start: usize, end: usize) {
        for (index, frame) in frames.iter().enumerate() {
            if index <= start || index >= end {
                continue;
            }
            assert_ne!(
                frame.get("method"),
                Some(&Value::from(METHOD_SESSION_CANCEL)),
                "unexpected session/cancel between outbound indices {start} and {end}"
            );
        }
    }

    fn assert_teardown_cancel_notification_last(frames: &[Value]) {
        let cancel_indices = cancel_frame_indices(frames);
        assert_eq!(
            cancel_indices.len(),
            1,
            "expected exactly one trailing teardown session/cancel notification"
        );
        assert_eq!(
            cancel_indices[0],
            frames.len() - 1,
            "teardown session/cancel must be the final outbound frame"
        );
        assert_session_cancel_notification(&frames[cancel_indices[0]]);
    }

    fn prompt_cancelled_response(id: u64) -> Value {
        json!({
            "id": id,
            "result": {"stopReason": "cancelled", "text": "discarded"}
        })
    }

    fn prompt_success_response(id: u64, text: &str) -> Value {
        json!({
            "id": id,
            "result": {
                "stopReason": "end_turn",
                "text": text,
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
                "usage_is_incomplete": false,
                "cost_is_partial": false
            }
        })
    }

    fn agent_message_chunk(session_id: &str, text: &str) -> Value {
        json!({
            "method": METHOD_SESSION_UPDATE,
            "params": {
                "sessionId": session_id,
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": text}
                }
            }
        })
    }

    fn assert_session_cancel_notification(frame: &Value) {
        assert_eq!(
            frame.get("method"),
            Some(&Value::from(METHOD_SESSION_CANCEL))
        );
        assert!(
            frame.get("id").is_none(),
            "session/cancel must be a notification without a request id"
        );
    }

    #[test]
    fn no_steering_wrapper_preserves_existing_turn_behavior() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("unsteered turn");
        assert_eq!(evidence.final_text.as_deref(), Some("hello"));
        let frames = outbound_frames_from_script(&transport);
        let prompts = prompt_frame_indices(&frames);
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].1, Value::from(4));
        assert_teardown_cancel_notification_last(&frames);
    }

    fn steering_early_messages(session_id: &str) -> Vec<Value> {
        let mut messages = base_handshake(session_id);
        messages.push(model_changed_notification(
            session_id,
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages
    }

    #[test]
    fn steering_applies_cancel_drain_then_same_session_prompt() {
        let early = steering_early_messages("sess-steer");
        let late = vec![
            prompt_cancelled_response(4),
            prompt_success_response(5, "corrected"),
        ];
        let mut transport = SequenceSteeringTransport::for_steering_turn(early, late);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut steering = QueueSteering {
            corrections: VecDeque::from([GrokAcpCorrection {
                action_id: "act-1".into(),
                prompt: "fix it".into(),
                deadline,
            }]),
            acked: Vec::new(),
        };
        let evidence = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect("steered turn");
        assert_eq!(evidence.final_text.as_deref(), Some("corrected"));
        assert_eq!(steering.acked, vec!["act-1".to_string()]);
        let outbound: Vec<Value> = transport
            .outbound
            .iter()
            .map(|line| serde_json::from_slice(line).expect("outbound json"))
            .collect();
        let cancel_frame = outbound
            .iter()
            .find(|frame| frame.get("method") == Some(&Value::from(METHOD_SESSION_CANCEL)))
            .expect("session/cancel notification");
        assert_session_cancel_notification(cancel_frame);
        let prompt_ids: Vec<_> = outbound
            .iter()
            .filter(|frame| frame.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT)))
            .map(|frame| frame.get("id").cloned().expect("prompt request id"))
            .collect();
        assert_eq!(prompt_ids, vec![Value::from(4), Value::from(5)]);
        let cancel_idx = outbound
            .iter()
            .position(|frame| frame.get("method") == Some(&Value::from(METHOD_SESSION_CANCEL)))
            .expect("cancel");
        let second_prompt_idx = outbound
            .iter()
            .rposition(|frame| frame.get("method") == Some(&Value::from(METHOD_SESSION_PROMPT)))
            .expect("second prompt");
        assert!(cancel_idx < second_prompt_idx);
        assert!(evidence
            .terminal_usage
            .as_ref()
            .is_some_and(|usage| usage.cost_is_partial && usage.usage_is_incomplete));
    }

    #[test]
    fn steering_polls_mailbox_on_no_output_timeout() {
        let early = steering_early_messages("sess-idle");
        let late = vec![
            prompt_cancelled_response(4),
            prompt_success_response(5, "after-idle"),
        ];
        let mut transport = SequenceSteeringTransport::for_steering_turn(early, late);
        let fixture = transport.shared_fixture_state();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut polled_on_idle_slice = false;
        let mut steering = IdleSliceGatedSteering {
            fixture: fixture.clone(),
            correction: GrokAcpCorrection {
                action_id: "act-idle".into(),
                prompt: "after idle".into(),
                deadline,
            },
            offered: false,
            acked: Vec::new(),
        };
        struct IdlePollProbe<'a> {
            inner: &'a mut IdleSliceGatedSteering,
            fixture: std::rc::Rc<std::cell::RefCell<SequenceFixtureState>>,
            polled_on_idle_slice: &'a mut bool,
        }
        impl GrokAcpSteering for IdlePollProbe<'_> {
            fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
                if self.fixture.borrow().idle_slices_returned == 0 {
                    return Ok(None);
                }
                *self.polled_on_idle_slice = true;
                self.inner.next_correction()
            }
            fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
                self.inner.acknowledge(action_id)
            }
        }
        let mut probe = IdlePollProbe {
            inner: &mut steering,
            fixture,
            polled_on_idle_slice: &mut polled_on_idle_slice,
        };
        run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "wait".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut probe,
        )
        .expect("idle poll turn");
        assert!(
            polled_on_idle_slice,
            "steering mailbox must be polled only after an idle receive slice"
        );
        assert!(transport.idle_slices_returned() > 0);
    }

    #[test]
    fn steering_polls_mailbox_while_output_keeps_flowing() {
        let mut messages = base_handshake("sess-stream");
        messages.push(model_changed_notification(
            "sess-stream",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(agent_message_chunk("sess-stream", "stale-chunk"));
        messages.push(prompt_cancelled_response(4));
        messages.push(prompt_success_response(5, "clean-final"));
        let mut transport = ScriptTransport::from_values(messages);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut polled = false;
        let mut steering = QueueSteering {
            corrections: VecDeque::from([GrokAcpCorrection {
                action_id: "stream-act".into(),
                prompt: "fix stream".into(),
                deadline,
            }]),
            acked: Vec::new(),
        };
        struct PollProbe<'a> {
            inner: &'a mut QueueSteering,
            polled: &'a mut bool,
        }
        impl GrokAcpSteering for PollProbe<'_> {
            fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
                *self.polled = true;
                self.inner.next_correction()
            }
            fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
                self.inner.acknowledge(action_id)
            }
        }
        let mut probe = PollProbe {
            inner: &mut steering,
            polled: &mut polled,
        };
        let evidence = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut probe,
        )
        .expect("streaming steering turn");
        assert!(polled);
        assert_eq!(evidence.final_text.as_deref(), Some("clean-final"));
        assert!(evidence
            .final_text
            .as_deref()
            .is_some_and(|text| !text.contains("stale-chunk")));
    }

    #[test]
    fn steering_queued_after_terminal_skips_cancel_and_drain() {
        let mut messages = base_handshake("sess-queue");
        messages.push(model_changed_notification(
            "sess-queue",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(true));
        messages.push(prompt_success_response(5, "queued-fix"));
        let mut transport = ObservedInboundScriptTransport::from_values(messages);
        let original_terminal_gate = transport.original_prompt_terminal_gate();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut steering = QueuedAfterOriginalTerminalSteering {
            original_terminal_gate,
            correction: GrokAcpCorrection {
                action_id: "queued".into(),
                prompt: "after terminal".into(),
                deadline,
            },
            offered: false,
            acked: Vec::new(),
        };
        let evidence = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect("queued correction turn");
        assert_eq!(evidence.final_text.as_deref(), Some("queued-fix"));
        assert_eq!(steering.acked, vec!["queued".to_string()]);
        let frames = transport.outbound_frames();
        let prompts = prompt_frame_indices(&frames);
        assert_eq!(
            prompts,
            vec![
                (prompts[0].0, Value::from(4)),
                (prompts[1].0, Value::from(5))
            ]
        );
        assert_no_cancel_between_outbound_indices(&frames, prompts[0].0, prompts[1].0);
        assert_teardown_cancel_notification_last(&frames);
    }

    #[test]
    fn steering_serial_second_correction_uses_completed_path() {
        let early = steering_early_messages("sess-serial");
        let late = vec![
            prompt_cancelled_response(4),
            prompt_success_response(5, "first-fix"),
            prompt_success_response(6, "second-fix"),
        ];
        let mut transport = SequenceSteeringTransport::for_steering_turn(early, late);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut steering = QueueSteering {
            corrections: VecDeque::from([
                GrokAcpCorrection {
                    action_id: "first".into(),
                    prompt: "first correction".into(),
                    deadline,
                },
                GrokAcpCorrection {
                    action_id: "second".into(),
                    prompt: "second correction".into(),
                    deadline,
                },
            ]),
            acked: Vec::new(),
        };
        let evidence = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect("serial corrections");
        assert_eq!(
            steering.acked,
            vec!["first".to_string(), "second".to_string()]
        );
        assert_eq!(evidence.final_text.as_deref(), Some("second-fix"));
        let outbound: Vec<Value> = transport.outbound_frames();
        let prompts = prompt_frame_indices(&outbound);
        assert_eq!(
            prompts,
            vec![
                (prompts[0].0, Value::from(4)),
                (prompts[1].0, Value::from(5)),
                (prompts[2].0, Value::from(6))
            ]
        );
        let cancels = cancel_frame_indices(&outbound);
        assert_eq!(cancels.len(), 2, "one steering cancel plus teardown cancel");
        assert!(
            cancels[0] > prompts[0].0 && cancels[0] < prompts[1].0,
            "steering session/cancel must occur between the original and first corrective prompts"
        );
        assert!(
            cancels[1] > prompts[2].0,
            "teardown session/cancel must follow the final corrective prompt"
        );
        assert_session_cancel_notification(&outbound[cancels[0]]);
        assert_session_cancel_notification(&outbound[cancels[1]]);
        assert_eq!(cancels[1], outbound.len() - 1);
    }

    #[test]
    fn steering_does_not_ack_when_correction_deadline_passed() {
        let mut messages = base_handshake("sess-exp");
        messages.push(model_changed_notification(
            "sess-exp",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let mut steering = QueueSteering {
            corrections: VecDeque::from([GrokAcpCorrection {
                action_id: "expired".into(),
                prompt: "late".into(),
                deadline: Instant::now() - Duration::from_secs(1),
            }]),
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("expired queued correction");
        assert!(matches!(
            error,
            GrokAcpError::Timeout {
                phase: "steering correction",
            }
        ));
        assert!(steering.acked.is_empty());
    }

    #[test]
    fn steering_does_not_ack_when_whole_task_cancelled() {
        let mut transport = ActiveCorrectiveLifecycleTransport::for_whole_task_cancel();
        let corrective_sent = transport.corrective_prompt_sent_flag();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut steering = QueueSteering {
            corrections: VecDeque::from([GrokAcpCorrection {
                action_id: "never-acked".into(),
                prompt: "fix".into(),
                deadline,
            }]),
            acked: Vec::new(),
        };
        let cancel_after_corrective = corrective_sent.clone();
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            move || *cancel_after_corrective.borrow(),
            &mut steering,
        )
        .expect_err("whole-task cancel");
        assert!(matches!(error, GrokAcpError::Cancelled { .. }));
        assert!(steering.acked.is_empty());
        assert!(*corrective_sent.borrow());
        let prompts = prompt_frame_indices(&transport.outbound_frames());
        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[1].1, Value::from(5));
    }

    #[test]
    fn steering_does_not_ack_on_protocol_loss_before_corrective_terminal() {
        let early = steering_early_messages("sess-loss");
        let late = vec![prompt_cancelled_response(4)];
        let mut transport = SequenceSteeringTransport::for_steering_turn(early, late);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut steering = QueueSteering {
            corrections: VecDeque::from([GrokAcpCorrection {
                action_id: "lost".into(),
                prompt: "fix".into(),
                deadline,
            }]),
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "original".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: Some("low".into()),
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("corrective prompt never terminalizes");
        assert!(matches!(
            error,
            GrokAcpError::Timeout { .. } | GrokAcpError::ProtocolLoss { .. }
        ));
        assert!(steering.acked.is_empty());
    }

    #[test]
    fn steering_rejects_unexpected_prompt_response_id() {
        let mut messages = base_handshake("sess-dup");
        messages.push(model_changed_notification(
            "sess-dup",
            "grok-4",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-4"));
        messages.push(json!({"id": 99, "result": {"stopReason": "end_turn", "text": "wrong"}}));
        let mut transport = ScriptTransport::from_values(messages);
        let mut steering = QueueSteering {
            corrections: VecDeque::new(),
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: None,
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("unexpected response id");
        assert!(matches!(
            error,
            GrokAcpError::Unexpected {
                phase: "session/prompt",
                ..
            }
        ));
    }

    #[test]
    fn steering_rejects_cross_session_notification_during_prompt() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", Some("high")));
        messages.push(set_model_ack("grok-4"));
        messages.push(model_changed_notification("sess-other", "grok-4", None));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let mut steering = QueueSteering {
            corrections: VecDeque::new(),
            acked: Vec::new(),
        };
        let error = run_grok_acp_turn_with_steering(
            &mut transport,
            &GrokAcpTurn {
                cwd: "/tmp".into(),
                prompt: "ping".into(),
                requested_model: Some("grok-4".into()),
                requested_effort: None,
                output_schema: None,
            },
            GrokAcpLimits::for_fixture_test(),
            || false,
            &mut steering,
        )
        .expect_err("cross session");
        assert!(matches!(
            error,
            GrokAcpError::Unexpected {
                phase: "x.ai/session_notification",
                ..
            }
        ));
    }

    #[test]
    fn matching_resolved_identity_is_admitted_for_publication() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", None),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("matching turn");
        assert_eq!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::Admitted
        );
    }

    #[test]
    fn wrong_resolved_model_refuses_publication() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification(
            "sess-1",
            "grok-other",
            Some("high"),
        ));
        messages.push(set_model_ack("grok-other"));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", None),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("wrong-model turn still records evidence");
        assert_eq!(
            evidence.client_resolved.model,
            GrokAcpResolvedField::Known("grok-other".into())
        );
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::ModelMismatch
        );
    }

    #[test]
    fn wrong_resolved_effort_refuses_publication() {
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "low", None),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("effort-mismatch turn");
        assert_eq!(
            evidence.client_resolved.effort,
            GrokAcpResolvedField::Known("high".into())
        );
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::EffortMismatch
        );
    }

    #[test]
    fn missing_resolved_effort_refuses_publication() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", None));
        messages.push(set_model_ack("grok-4"));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", None),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("missing-effort turn");
        assert_ne!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::Complete
        );
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::MissingEvidence
        );
    }

    #[test]
    fn conflicting_model_change_refuses_publication() {
        let mut messages = base_handshake("sess-1");
        messages.push(model_changed_notification("sess-1", "grok-4", Some("high")));
        messages.push(set_model_ack("grok-4"));
        messages.push(model_changed_notification(
            "sess-1",
            "grok-other",
            Some("high"),
        ));
        messages.push(prompt_ack(true));
        let mut transport = ScriptTransport::from_values(messages);
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", None),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("conflicting turn");
        assert_eq!(
            evidence.resolution_status,
            GrokAcpResolutionStatus::AmbiguousModelChange
        );
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::ConflictingEvidence
        );
    }

    #[test]
    fn requested_identity_disagreeing_with_admitted_is_conflicting() {
        assert_eq!(
            grok_acp_admitted_identity_publication_status(
                Some("grok-4.6"),
                Some("xhigh"),
                Some("grok-4"),
                Some("xhigh"),
                Some("grok-4.6"),
                Some("xhigh"),
                GrokAcpResolutionStatus::Complete,
            ),
            GrokAcpIdentityPublicationStatus::ConflictingEvidence
        );
    }

    #[test]
    fn outbound_prompt_carries_bound_json_schema() {
        let schema = publication_schema();
        let digest = schema.sha256().to_string();
        let mut transport = ScriptTransport::from_values(successful_transcript("high"));
        run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", Some(schema)),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("schema-bound turn");
        let prompt = parse_outbound(&transport, 3);
        assert_eq!(
            prompt.get("method"),
            Some(&Value::from(METHOD_SESSION_PROMPT))
        );
        assert_eq!(
            prompt.pointer("/params/_meta/jsonSchema/required/0"),
            Some(&Value::from("accepted"))
        );
        assert_eq!(
            prompt.pointer("/params/_meta/jsonSchema/properties/accepted/type"),
            Some(&Value::from("boolean"))
        );
        let rebound = GrokAcpBoundOutputSchema::from_canonical_json(
            &serde_json::to_string(prompt.pointer("/params/_meta/jsonSchema").expect("schema"))
                .expect("render"),
        )
        .expect("rebind");
        assert_eq!(rebound.sha256(), digest);
    }

    #[test]
    fn valid_schema_structured_output_is_accepted() {
        let schema = publication_schema();
        let mut transport = ScriptTransport::from_values(successful_transcript_with_prompt_meta(
            "grok-4",
            "high",
            prompt_ack_with_structured(json!({"accepted": true})),
        ));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", Some(schema.clone())),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("valid schema turn");
        let parent =
            crate::runtime_adapter::grok::grok_acp_parent_evidence_from_execution(evidence);
        schema
            .validate_structured_output(parent.structured_output.as_ref().expect("structured"))
            .expect("accepted boolean object");
    }

    #[test]
    fn wrong_structured_output_type_is_refused() {
        let schema = publication_schema();
        let mut transport = ScriptTransport::from_values(successful_transcript_with_prompt_meta(
            "grok-4",
            "high",
            prompt_ack_with_structured(json!({"accepted": "wrong"})),
        ));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", Some(schema.clone())),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("wrong-type turn");
        let parent =
            crate::runtime_adapter::grok::grok_acp_parent_evidence_from_execution(evidence);
        let error = schema
            .validate_structured_output(parent.structured_output.as_ref().expect("structured"))
            .expect_err("string is not boolean");
        assert!(error.contains("type"), "{error}");
        assert!(!error.contains("wrong"));
    }

    #[test]
    fn absent_required_structured_output_field_is_refused() {
        let schema = publication_schema();
        let mut transport = ScriptTransport::from_values(successful_transcript_with_prompt_meta(
            "grok-4",
            "high",
            prompt_ack_with_structured(json!({})),
        ));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", Some(schema.clone())),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("missing-field turn");
        let parent =
            crate::runtime_adapter::grok::grok_acp_parent_evidence_from_execution(evidence);
        let error = schema
            .validate_structured_output(parent.structured_output.as_ref().expect("structured"))
            .expect_err("required field missing");
        assert!(error.contains("required"), "{error}");
    }

    #[test]
    fn terminal_structured_output_error_is_recorded() {
        let schema = publication_schema();
        let mut transport = ScriptTransport::from_values(successful_transcript_with_prompt_meta(
            "grok-4",
            "high",
            prompt_ack_with_structured_error(),
        ));
        let evidence = run_grok_acp_turn(
            &mut transport,
            &requested_turn("grok-4", "high", Some(schema)),
            GrokAcpLimits::for_fixture_test(),
            || false,
        )
        .expect("terminal schema error turn");
        assert_eq!(
            grok_acp_execution_identity_publication_status(&evidence),
            GrokAcpIdentityPublicationStatus::Admitted
        );
        let parent =
            crate::runtime_adapter::grok::grok_acp_parent_evidence_from_execution(evidence);
        assert!(parent.structured_output.is_none());
        assert!(parent.structured_output_error.is_some());
    }
}
