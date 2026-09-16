//! Bounded Grok ACP stdio client for runtime-resolved model + effort observation.
//!
//! Parent-owned evidence only: observed model/effort come from post-`session/set_model`
//! `x.ai/session_notification` `model_changed` (or equivalent `session/update`), never from
//! prompt text or pre-resolution init metadata. This module does not spawn processes; callers
//! run it inside [`crate::process_runner::run_process_interactive`] via
//! [`GrokAcpContainedTransport`].

use crate::process_runner::{ContainedProcessSession, InteractiveProcessRead};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeSet,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrokAcpTurn {
    pub(crate) cwd: String,
    pub(crate) prompt: String,
    pub(crate) requested_model: Option<String>,
    pub(crate) requested_effort: Option<String>,
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
            if cancelled() {
                return Err(GrokAcpError::Cancelled { phase });
            }
            let now = Instant::now();
            if now >= self.deadline {
                return Err(GrokAcpError::Timeout { phase });
            }
            let remaining = self.deadline.saturating_duration_since(now);
            let wait = remaining.min(CANCELLATION_POLL_INTERVAL);
            match transport
                .receive(wait, self.limits.max_line_bytes, &mut line)
                .map_err(|message| GrokAcpError::Transport { message })?
            {
                GrokAcpTransportRead::Timeout if Instant::now() < self.deadline => continue,
                GrokAcpTransportRead::Timeout => return Err(GrokAcpError::Timeout { phase }),
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
            return serde_json::from_slice(&line).map_err(|error| GrokAcpError::Malformed {
                phase,
                message: format!("invalid JSON: {error}"),
            });
        }
    }
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
            "params": {
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": turn.prompt}]
            }
        }),
    )?;

    let prompt_outcome = drive_prompt(
        &mut state,
        transport,
        &session_id,
        &prompt_id,
        &mut model_tracker,
        &cancelled,
        &mut permission_escalation_refused,
    );

    let PromptDriveOutcome {
        final_text,
        stop_reason,
        terminal_usage,
        prompt_result_meta,
        prompt_acknowledged,
        truncated,
    } = match prompt_outcome {
        Ok(value) => value,
        Err(error) => {
            let _ = best_effort_cancel(&mut state, transport, &session_id);
            return Err(error);
        }
    };

    let _ = best_effort_cancel(&mut state, transport, &session_id);

    let usage_incomplete = terminal_usage
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
}

fn drive_prompt<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    session_id: &str,
    prompt_request_id: &RequestId,
    model_tracker: &mut ModelResolutionTracker,
    cancelled: &C,
    permission_escalation_refused: &mut bool,
) -> Result<PromptDriveOutcome, GrokAcpError>
where
    T: GrokAcpJsonLineTransport,
    C: Fn() -> bool,
{
    let mut final_text: Option<String> = None;
    let mut stop_reason: Option<String> = None;
    let mut terminal_usage: Option<GrokAcpTerminalUsage> = None;
    let mut prompt_result_meta: Option<Value> = None;
    let mut truncated = false;
    let prompt_acknowledged;
    let prompt_response_seen;

    loop {
        let message = state.receive(transport, "session/prompt", cancelled)?;
        if let Some(id) = message.get("id") {
            if message.get("method").is_some() {
                let method = required_text(&message, &["method"], "session/prompt", "method")?;
                refuse_server_request(
                    state,
                    transport,
                    &message,
                    method,
                    permission_escalation_refused,
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
            if &parsed == prompt_request_id {
                if message.get("error").is_some() {
                    return Err(GrokAcpError::Remote {
                        phase: "session/prompt",
                        message: bounded_json_summary(message.get("error").unwrap_or(&Value::Null)),
                    });
                }
                prompt_response_seen = true;
                prompt_acknowledged = true;
                if let Some(reason) = message
                    .pointer("/result/stopReason")
                    .and_then(Value::as_str)
                {
                    stop_reason = Some(reason.to_string());
                }
                truncated = message
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
                    terminal_usage = Some(project_terminal_usage_from_prompt(
                        session_id,
                        message.pointer("/result/promptId").and_then(Value::as_str),
                        usage,
                        usage_incomplete,
                        cost_partial,
                    ));
                }
                if let Some(meta) = message.pointer("/result/_meta") {
                    prompt_result_meta = Some(meta.clone());
                    if terminal_usage.is_none() {
                        if let Some(usage) = meta.get("usage") {
                            terminal_usage = Some(project_terminal_usage_from_prompt(
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
                    final_text = Some(text.to_string());
                }
                break;
            }
            return Err(GrokAcpError::Unexpected {
                phase: "session/prompt",
                message: "unexpected correlated response during prompt".to_string(),
            });
        }

        if message.get("method").is_none() {
            return Err(GrokAcpError::Malformed {
                phase: "session/prompt",
                message: "message lacks method and response id".to_string(),
            });
        }

        let method = required_text(&message, &["method"], "session/prompt", "method")?;
        match method {
            METHOD_SESSION_UPDATE => {
                let params = required_object(&message, &["params"], "session/prompt", "params")?;
                let wire_session =
                    map_required_text(params, "sessionId", "session/prompt", "session id")?;
                if wire_session != session_id {
                    return Err(GrokAcpError::Unexpected {
                        phase: "session/prompt",
                        message: "session/update targeted a different session".to_string(),
                    });
                }
                let update = params
                    .get("update")
                    .and_then(Value::as_object)
                    .ok_or_else(|| GrokAcpError::Malformed {
                        phase: "session/prompt",
                        message: "session/update update is not an object".to_string(),
                    })?;
                if let Some(tag) = update.get("sessionUpdate").and_then(Value::as_str) {
                    match tag {
                        "model_changed" => {
                            let model_id = update
                                .get("model_id")
                                .and_then(Value::as_str)
                                .ok_or_else(|| GrokAcpError::Malformed {
                                    phase: "session/prompt",
                                    message: "model_changed missing model_id".to_string(),
                                })?;
                            let effort = update.get("reasoning_effort").and_then(Value::as_str);
                            model_tracker.note_model_changed(model_id, effort);
                        }
                        "agent_message_chunk" => {
                            if let Some(text) = update
                                .get("content")
                                .and_then(|content| content.get("text"))
                                .and_then(Value::as_str)
                            {
                                let mut combined = final_text.unwrap_or_default();
                                combined.push_str(text);
                                final_text = Some(combined);
                            }
                        }
                        "turn_completed" => {
                            apply_turn_completed_supplement(
                                update,
                                &mut final_text,
                                &mut stop_reason,
                                &mut truncated,
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ if method == METHOD_XAI_SESSION_NOTIFICATION => {
                handle_xai_session_notification(
                    &message,
                    session_id,
                    model_tracker,
                    Some((&mut final_text, &mut stop_reason, &mut truncated)),
                )?;
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

    if !prompt_response_seen {
        return Err(GrokAcpError::ProtocolLoss {
            phase: "session/prompt",
        });
    }

    Ok(PromptDriveOutcome {
        final_text,
        stop_reason,
        terminal_usage,
        prompt_result_meta,
        prompt_acknowledged,
        truncated,
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
    let Ok(id) = state.allocate_request_id() else {
        return Ok(());
    };
    let _ = state.send(
        transport,
        &json!({
            "jsonrpc": "2.0",
            "id": id.to_value(),
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
}
