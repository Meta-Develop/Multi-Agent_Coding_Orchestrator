#![allow(dead_code)]

use crate::{
    gate_denial::GateDenial,
    process_runner::{ContainedProcessSession, InteractiveProcessRead},
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{BufRead, BufReader, Read, Write},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const OUTPUT_AGENT_MESSAGE_MAX_BYTES: usize = 8 * 1024 * 1024;
/// JSON envelope around a completed `agentMessage` so the advertised 8MB text
/// bound remains receivable as a single JSONL line.
const AGENT_MESSAGE_JSON_ENVELOPE_BYTES: usize = 256 * 1024;
const HARD_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_MESSAGES: usize = 16_384;
const HARD_MAX_PROMPT_BYTES: usize = 1024 * 1024;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const EXTERNAL_CODEX_PERMISSION_PROFILE: &str = "maco_external_codex";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportRead {
    Line,
    Timeout,
    Eof,
}

pub(crate) trait JsonLineTransport {
    fn receive(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<TransportRead, String>;

    fn send(&mut self, line: &[u8]) -> Result<(), String>;
}

/// App-server JSONL over the process runner's borrowed, already-contained session.
///
/// This adapter owns no child and no raw stdio handles. Its two lifetimes prevent the transport
/// from outliving either the handler call or the underlying contained process.
pub(crate) struct ContainedJsonLineTransport<'session, 'process> {
    session: &'session mut ContainedProcessSession<'process>,
}

impl<'session, 'process> ContainedJsonLineTransport<'session, 'process> {
    pub(crate) fn new(session: &'session mut ContainedProcessSession<'process>) -> Self {
        Self { session }
    }
}

impl JsonLineTransport for ContainedJsonLineTransport<'_, '_> {
    fn receive(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<TransportRead, String> {
        match self
            .session
            .receive_line(wait, max_line_bytes, destination)?
        {
            InteractiveProcessRead::Line => Ok(TransportRead::Line),
            InteractiveProcessRead::Timeout => Ok(TransportRead::Timeout),
            InteractiveProcessRead::Eof => Ok(TransportRead::Eof),
        }
    }

    fn send(&mut self, line: &[u8]) -> Result<(), String> {
        self.session.send_line(line)
    }
}

enum ReaderEvent {
    Line(Vec<u8>),
    Eof,
    Failed(String),
}

/// A JSONL stdio transport whose blocking reader is isolated from the protocol deadline.
///
/// The reader thread never allocates more than the hard line ceiling for a single message.
/// Dropping the transport closes the receiver; ownership and termination of the app-server
/// process remain with the caller's process runner.
pub(crate) struct ThreadedStdioTransport<W> {
    receiver: mpsc::Receiver<ReaderEvent>,
    writer: W,
}

impl<W> ThreadedStdioTransport<W>
where
    W: Write,
{
    pub(crate) fn new<R>(reader: R, writer: W) -> Result<Self, AppServerError>
    where
        R: Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(32);
        thread::Builder::new()
            .name("codex-app-server-jsonl".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(reader);
                loop {
                    match read_bounded_line(&mut reader) {
                        Ok(Some(line)) => {
                            if sender.send(ReaderEvent::Line(line)).is_err() {
                                return;
                            }
                        }
                        Ok(None) => {
                            let _ = sender.send(ReaderEvent::Eof);
                            return;
                        }
                        Err(error) => {
                            let _ = sender.send(ReaderEvent::Failed(error));
                            return;
                        }
                    }
                }
            })
            .map_err(|error| AppServerError::Transport {
                message: format!("failed to start bounded app-server reader: {error}"),
            })?;
        Ok(Self { receiver, writer })
    }
}

impl<W> JsonLineTransport for ThreadedStdioTransport<W>
where
    W: Write,
{
    fn receive(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<TransportRead, String> {
        destination.clear();
        match self.receiver.recv_timeout(wait) {
            Ok(ReaderEvent::Line(line)) => {
                if line.len() > max_line_bytes {
                    return Err("app-server message exceeded the configured line bound".to_string());
                }
                destination.extend_from_slice(&line);
                Ok(TransportRead::Line)
            }
            Ok(ReaderEvent::Eof) => Ok(TransportRead::Eof),
            Ok(ReaderEvent::Failed(message)) => Err(message),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(TransportRead::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(TransportRead::Eof),
        }
    }

    fn send(&mut self, line: &[u8]) -> Result<(), String> {
        self.writer
            .write_all(line)
            .and_then(|()| self.writer.write_all(b"\n"))
            .and_then(|()| self.writer.flush())
            .map_err(|error| format!("failed to write app-server JSONL: {error}"))
    }
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("failed to read app-server JSONL: {error}"))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index.saturating_add(1));
        if line.len().saturating_add(take) > HARD_MAX_LINE_BYTES.saturating_add(1) {
            return Err("app-server message exceeded the hard line bound".to_string());
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppServerLimits {
    pub(crate) max_line_bytes: usize,
    pub(crate) max_total_bytes: usize,
    pub(crate) max_messages: usize,
    pub(crate) turn_timeout: Duration,
    pub(crate) approval_timeout: Duration,
}

impl Default for AppServerLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: OUTPUT_AGENT_MESSAGE_MAX_BYTES
                .saturating_add(AGENT_MESSAGE_JSON_ENVELOPE_BYTES),
            max_total_bytes: HARD_MAX_TOTAL_BYTES,
            max_messages: 8_192,
            turn_timeout: Duration::from_secs(300),
            approval_timeout: Duration::from_secs(30),
        }
    }
}

impl AppServerLimits {
    fn validate(self) -> Result<Self, AppServerError> {
        if self.max_line_bytes == 0 || self.max_line_bytes > HARD_MAX_LINE_BYTES {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server line bound is zero or exceeds the hard ceiling".to_string(),
            });
        }
        if self.max_total_bytes < self.max_line_bytes || self.max_total_bytes > HARD_MAX_TOTAL_BYTES
        {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server aggregate bound is smaller than one line or exceeds the hard ceiling"
                    .to_string(),
            });
        }
        if self.max_messages == 0 || self.max_messages > HARD_MAX_MESSAGES {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server message bound is zero or exceeds the hard ceiling".to_string(),
            });
        }
        if self.turn_timeout.is_zero() || self.approval_timeout.is_zero() {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server deadlines must be non-zero".to_string(),
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerTurn {
    pub(crate) cwd: String,
    pub(crate) permission_profile: String,
    pub(crate) prompt: String,
    pub(crate) model: Option<String>,
}

impl AppServerTurn {
    fn validate(&self) -> Result<(), AppServerError> {
        validate_identifier(&self.permission_profile, "permission profile", 128)?;
        if self.permission_profile != EXTERNAL_CODEX_PERMISSION_PROFILE {
            return Err(AppServerError::InvalidConfiguration {
                message:
                    "app-server permission profile differs from the fixed external Codex ceiling"
                        .to_string(),
            });
        }
        if self.cwd.is_empty()
            || self.cwd.len() > 16 * 1024
            || self.cwd.contains(['\0', '\n', '\r'])
        {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server cwd is empty or malformed".to_string(),
            });
        }
        if self.prompt.len() > HARD_MAX_PROMPT_BYTES || self.prompt.contains('\0') {
            return Err(AppServerError::InvalidConfiguration {
                message: "app-server prompt is malformed or exceeds its bound".to_string(),
            });
        }
        if let Some(model) = &self.model {
            validate_identifier(model, "model", 256)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalKind {
    CommandExecution,
    FileChange,
    PermissionExpansion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalDecision {
    Accept,
    Decline,
    Cancel,
}

impl ApprovalDecision {
    fn protocol_value(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ApprovalRequest {
    pub(crate) kind: ApprovalKind,
    pub(crate) thread_id: String,
    pub(crate) turn_id: String,
    pub(crate) item_id: String,
    pub(crate) command: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) ceiling_expansion_requested: bool,
    pub(crate) item: Value,
    pub(crate) raw_params: Value,
}

pub(crate) trait ApprovalReviewer {
    fn review(&mut self, request: ApprovalRequest) -> Result<ApprovalReview, String>;
}

impl<F> ApprovalReviewer for F
where
    F: FnMut(ApprovalRequest) -> Result<ApprovalReview, String>,
{
    fn review(&mut self, request: ApprovalRequest) -> Result<ApprovalReview, String> {
        self(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalReview {
    pub(crate) decision: ApprovalDecision,
    pub(crate) denial: Option<GateDenial>,
}

impl ApprovalReview {
    pub(crate) fn accept() -> Self {
        Self {
            decision: ApprovalDecision::Accept,
            denial: None,
        }
    }

    pub(crate) fn decline(denial: GateDenial) -> Self {
        Self {
            decision: ApprovalDecision::Decline,
            denial: Some(denial),
        }
    }

    pub(crate) fn cancel(denial: Option<GateDenial>) -> Self {
        Self {
            decision: ApprovalDecision::Cancel,
            denial,
        }
    }

    fn validate(self) -> Result<Self, AppServerError> {
        let valid = match self.decision {
            ApprovalDecision::Accept => self.denial.is_none(),
            ApprovalDecision::Decline => self.denial.is_some(),
            ApprovalDecision::Cancel => true,
        };
        if valid {
            Ok(self)
        } else {
            Err(AppServerError::ApprovalReviewerLost)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AutoReviewEvidence {
    pub(crate) review_id: String,
    pub(crate) target_item_id: Option<String>,
    pub(crate) action_type: String,
    pub(crate) decision_source: String,
    pub(crate) status: String,
    pub(crate) rationale: Option<String>,
    pub(crate) risk_level: Option<String>,
    pub(crate) user_authorization: Option<String>,
    pub(crate) structured_policy_decision: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TurnTerminalStatus {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ItemOutcome {
    pub(crate) item_id: String,
    pub(crate) item_type: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerOutcome {
    pub(crate) thread_id: String,
    pub(crate) turn_id: String,
    pub(crate) status: TurnTerminalStatus,
    pub(crate) completed_items: usize,
    pub(crate) item_outcomes: Vec<ItemOutcome>,
    pub(crate) refused_ceiling_expansions: usize,
    pub(crate) gate_denials: Vec<GateDenial>,
    pub(crate) final_message: Option<String>,
    pub(crate) auto_reviews: Vec<AutoReviewEvidence>,
    pub(crate) duplex_fallback_required: bool,
    pub(crate) messages_received: usize,
    pub(crate) bytes_received: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum AppServerError {
    #[error("{message}")]
    InvalidConfiguration { message: String },
    #[error("{message}")]
    Transport { message: String },
    #[error("app-server protocol timed out during {phase}")]
    Timeout { phase: &'static str },
    #[error("app-server protocol was cancelled during {phase}")]
    Cancelled { phase: &'static str },
    #[error("app-server protocol stream ended during {phase}")]
    ProtocolLoss { phase: &'static str },
    #[error("malformed app-server message during {phase}: {message}")]
    Malformed {
        phase: &'static str,
        message: String,
    },
    #[error("unexpected app-server message during {phase}: {message}")]
    Unexpected {
        phase: &'static str,
        message: String,
    },
    #[error("duplicate app-server message during {phase}: {message}")]
    Duplicate {
        phase: &'static str,
        message: String,
    },
    #[error("app-server request failed during {phase}: {message}")]
    Remote {
        phase: &'static str,
        message: String,
    },
    #[error("approval reviewer timed out")]
    ApprovalTimeout,
    #[error("approval reviewer failed without a decision")]
    ApprovalReviewerLost,
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
    fn parse(value: &Value, phase: &'static str) -> Result<Self, AppServerError> {
        if let Some(number) = value.as_u64() {
            return Ok(Self::Number(number));
        }
        if let Some(text) = value.as_str() {
            validate_identifier(text, "request id", 128).map_err(|error| {
                AppServerError::Malformed {
                    phase,
                    message: error.to_string(),
                }
            })?;
            return Ok(Self::String(text.to_string()));
        }
        Err(AppServerError::Malformed {
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
    limits: AppServerLimits,
    deadline: Instant,
    messages_received: usize,
    bytes_received: usize,
    bytes_sent: usize,
    response_ids: BTreeSet<RequestId>,
    server_request_ids: BTreeSet<RequestId>,
    next_request_id: u64,
}

impl ProtocolState {
    fn new(limits: AppServerLimits) -> Result<Self, AppServerError> {
        let deadline = Instant::now()
            .checked_add(limits.turn_timeout)
            .ok_or_else(|| AppServerError::InvalidConfiguration {
                message: "app-server deadline overflowed".to_string(),
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

    fn allocate_request_id(&mut self) -> Result<RequestId, AppServerError> {
        let id = self.next_request_id;
        self.next_request_id =
            self.next_request_id
                .checked_add(1)
                .ok_or_else(|| AppServerError::Unexpected {
                    phase: "request allocation",
                    message: "request id space exhausted".to_string(),
                })?;
        Ok(RequestId::Number(id))
    }

    fn send<T: JsonLineTransport>(
        &mut self,
        transport: &mut T,
        message: &Value,
    ) -> Result<(), AppServerError> {
        let encoded = serde_json::to_vec(message).map_err(|error| AppServerError::Malformed {
            phase: "client serialization",
            message: error.to_string(),
        })?;
        if encoded.len() > self.limits.max_line_bytes {
            return Err(AppServerError::InvalidConfiguration {
                message: "client app-server message exceeded the line bound".to_string(),
            });
        }
        self.bytes_sent = self.bytes_sent.saturating_add(encoded.len());
        if self.bytes_sent > self.limits.max_total_bytes {
            return Err(AppServerError::InvalidConfiguration {
                message: "client app-server output exceeded the aggregate bound".to_string(),
            });
        }
        transport
            .send(&encoded)
            .map_err(|message| AppServerError::Transport { message })
    }

    fn receive<T, C>(
        &mut self,
        transport: &mut T,
        phase: &'static str,
        cancelled: &C,
    ) -> Result<Value, AppServerError>
    where
        T: JsonLineTransport,
        C: Fn() -> bool,
    {
        let mut line = Vec::new();
        loop {
            if cancelled() {
                return Err(AppServerError::Cancelled { phase });
            }
            let now = Instant::now();
            if now >= self.deadline {
                return Err(AppServerError::Timeout { phase });
            }
            let remaining = self.deadline.saturating_duration_since(now);
            let wait = remaining.min(CANCELLATION_POLL_INTERVAL);
            match transport
                .receive(wait, self.limits.max_line_bytes, &mut line)
                .map_err(|message| AppServerError::Transport { message })?
            {
                TransportRead::Timeout if Instant::now() < self.deadline => continue,
                TransportRead::Timeout => return Err(AppServerError::Timeout { phase }),
                TransportRead::Eof => return Err(AppServerError::ProtocolLoss { phase }),
                TransportRead::Line => {}
            }
            self.messages_received = self.messages_received.saturating_add(1);
            self.bytes_received = self.bytes_received.saturating_add(line.len());
            if self.messages_received > self.limits.max_messages
                || self.bytes_received > self.limits.max_total_bytes
            {
                return Err(AppServerError::Malformed {
                    phase,
                    message: "app-server output exceeded its aggregate bound".to_string(),
                });
            }
            return serde_json::from_slice(&line).map_err(|error| AppServerError::Malformed {
                phase,
                message: format!("invalid JSON: {error}"),
            });
        }
    }

    fn interrupt<T: JsonLineTransport>(
        &mut self,
        transport: &mut T,
        thread_id: &str,
        turn_id: &str,
    ) {
        let Ok(id) = self.allocate_request_id() else {
            return;
        };
        let _ = self.send(
            transport,
            &json!({
                "id": id.to_value(),
                "method": "turn/interrupt",
                "params": {"threadId": thread_id, "turnId": turn_id}
            }),
        );
    }
}

pub(crate) fn run_app_server_turn<T, C>(
    transport: &mut T,
    turn: &AppServerTurn,
    limits: AppServerLimits,
    reviewer: &mut dyn ApprovalReviewer,
    cancelled: C,
) -> Result<AppServerOutcome, AppServerError>
where
    T: JsonLineTransport,
    C: Fn() -> bool,
{
    turn.validate()?;
    let limits = limits.validate()?;
    let mut state = ProtocolState::new(limits)?;

    let initialize_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "id": initialize_id.to_value(),
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "maco",
                    "title": "Multi-Agent Coding Orchestrator",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {
                    "experimentalApi": true,
                    "optOutNotificationMethods": []
                }
            }
        }),
    )?;
    wait_for_response(
        &mut state,
        transport,
        &initialize_id,
        "initialize",
        &cancelled,
    )?;
    state.send(transport, &json!({"method": "initialized"}))?;

    let thread_start_id = state.allocate_request_id()?;
    let mut thread_params = Map::from_iter([
        ("cwd".to_string(), Value::from(turn.cwd.clone())),
        ("approvalPolicy".to_string(), Value::from("on-request")),
        // Production routes every surfaced request through the client-owned MACO callback.
        // Upstream auto_review remains experiment-only evidence because it does not review
        // actions already allowed inside the active sandbox.
        ("approvalsReviewer".to_string(), Value::from("user")),
        (
            "permissions".to_string(),
            Value::from(turn.permission_profile.clone()),
        ),
        ("ephemeral".to_string(), Value::from(true)),
        ("experimentalRawEvents".to_string(), Value::from(false)),
        ("dynamicTools".to_string(), Value::Array(Vec::new())),
        ("environments".to_string(), Value::Array(Vec::new())),
    ]);
    if let Some(model) = &turn.model {
        thread_params.insert("model".to_string(), Value::from(model.clone()));
    }
    state.send(
        transport,
        &json!({
            "id": thread_start_id.to_value(),
            "method": "thread/start",
            "params": thread_params
        }),
    )?;
    let thread_response = wait_for_response(
        &mut state,
        transport,
        &thread_start_id,
        "thread/start",
        &cancelled,
    )?;
    require_exact_text(
        &thread_response,
        &["result", "approvalPolicy"],
        "on-request",
        "thread/start",
    )?;
    require_exact_text(
        &thread_response,
        &["result", "approvalsReviewer"],
        "user",
        "thread/start",
    )?;
    require_exact_text(
        &thread_response,
        &["result", "activePermissionProfile", "id"],
        &turn.permission_profile,
        "thread/start",
    )?;
    require_exact_text(
        &thread_response,
        &["result", "cwd"],
        &turn.cwd,
        "thread/start",
    )?;
    let thread_id = required_text(
        &thread_response,
        &["result", "thread", "id"],
        "thread/start",
        "thread id",
    )?
    .to_string();

    let turn_start_id = state.allocate_request_id()?;
    state.send(
        transport,
        &json!({
            "id": turn_start_id.to_value(),
            "method": "turn/start",
            "params": {
                "threadId": thread_id,
                "input": [{"type": "text", "text": turn.prompt, "text_elements": []}],
                "approvalPolicy": "on-request",
                "approvalsReviewer": "user",
                "permissions": turn.permission_profile,
                "environments": []
            }
        }),
    )?;
    let turn_response = wait_for_response(
        &mut state,
        transport,
        &turn_start_id,
        "turn/start",
        &cancelled,
    )?;
    let turn_id = required_text(
        &turn_response,
        &["result", "turn", "id"],
        "turn/start",
        "turn id",
    )?
    .to_string();
    require_exact_text(
        &turn_response,
        &["result", "turn", "status"],
        "inProgress",
        "turn/start",
    )?;

    match drive_turn(
        &mut state, transport, &thread_id, &turn_id, reviewer, &cancelled,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            state.interrupt(transport, &thread_id, &turn_id);
            Err(error)
        }
    }
}

fn wait_for_response<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    expected_id: &RequestId,
    phase: &'static str,
    cancelled: &C,
) -> Result<Value, AppServerError>
where
    T: JsonLineTransport,
    C: Fn() -> bool,
{
    let message = state.receive(transport, phase, cancelled)?;
    let object = message
        .as_object()
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: "top-level message is not an object".to_string(),
        })?;
    if object.contains_key("method") {
        return Err(AppServerError::Unexpected {
            phase,
            message: "notification or server request arrived before the correlated response"
                .to_string(),
        });
    }
    let id = object
        .get("id")
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: "response has no id".to_string(),
        })
        .and_then(|value| RequestId::parse(value, phase))?;
    if !state.response_ids.insert(id.clone()) {
        return Err(AppServerError::Duplicate {
            phase,
            message: "response id was already completed".to_string(),
        });
    }
    if &id != expected_id {
        return Err(AppServerError::Unexpected {
            phase,
            message: "response id did not match the pending request".to_string(),
        });
    }
    if let Some(error) = object.get("error") {
        return Err(AppServerError::Remote {
            phase,
            message: bounded_json_summary(error),
        });
    }
    if !object.get("result").is_some_and(Value::is_object) {
        return Err(AppServerError::Malformed {
            phase,
            message: "response result is missing or is not an object".to_string(),
        });
    }
    Ok(message)
}

fn drive_turn<T, C>(
    state: &mut ProtocolState,
    transport: &mut T,
    thread_id: &str,
    turn_id: &str,
    reviewer: &mut dyn ApprovalReviewer,
    cancelled: &C,
) -> Result<AppServerOutcome, AppServerError>
where
    T: JsonLineTransport,
    C: Fn() -> bool,
{
    #[derive(Debug)]
    struct ActiveItem {
        item_type: String,
        raw: Value,
    }

    #[derive(Debug)]
    struct ActiveReview {
        target_item_id: Option<String>,
        action_type: String,
        target_correlated: bool,
    }

    let mut active_items = BTreeMap::<String, ActiveItem>::new();
    let mut completed_items = BTreeSet::<String>::new();
    let mut item_outcomes = Vec::new();
    let mut final_message = None;
    let mut active_reviews = BTreeMap::<String, ActiveReview>::new();
    let mut completed_reviews = BTreeSet::<String>::new();
    let mut auto_reviews = Vec::new();
    let mut gate_denials = Vec::new();
    let mut approval_request_items = BTreeSet::<String>::new();
    let mut pending_correction_responses = BTreeMap::<RequestId, String>::new();
    let mut refused_ceiling_expansions = 0usize;
    let mut thread_started_seen = false;
    let mut turn_started_seen = false;

    loop {
        let message = state.receive(transport, "turn", cancelled)?;
        let object = message
            .as_object()
            .ok_or_else(|| AppServerError::Malformed {
                phase: "turn",
                message: "top-level message is not an object".to_string(),
            })?;
        if object.contains_key("result") || object.contains_key("error") {
            let id = object
                .get("id")
                .ok_or_else(|| AppServerError::Malformed {
                    phase: "turn",
                    message: "response has no id".to_string(),
                })
                .and_then(|value| RequestId::parse(value, "turn"))?;
            if !state.response_ids.insert(id.clone()) {
                return Err(AppServerError::Duplicate {
                    phase: "turn",
                    message: "response id was already completed".to_string(),
                });
            }
            if pending_correction_responses.remove(&id).is_some() {
                if object.contains_key("error") {
                    return Err(AppServerError::Remote {
                        phase: "gate denial feedback",
                        message: "app-server rejected typed gate-denial feedback".to_string(),
                    });
                }
                continue;
            }
            return Err(AppServerError::Unexpected {
                phase: "turn",
                message: "response arrived with no pending request".to_string(),
            });
        }
        let method = required_text(&message, &["method"], "turn", "method")?;
        let params = required_object(&message, &["params"], "turn", "params")?;

        match method {
            "thread/started" => {
                if thread_started_seen {
                    return Err(AppServerError::Duplicate {
                        phase: "thread/started",
                        message: "thread lifecycle started more than once".to_string(),
                    });
                }
                require_exact_text(&message, &["params", "thread", "id"], thread_id, "turn")?;
                thread_started_seen = true;
            }
            "turn/started" => {
                if turn_started_seen {
                    return Err(AppServerError::Duplicate {
                        phase: "turn/started",
                        message: "turn lifecycle started more than once".to_string(),
                    });
                }
                validate_turn_correlation(params, thread_id, turn_id, "turn/started")?;
                require_exact_text(
                    &message,
                    &["params", "turn", "status"],
                    "inProgress",
                    "turn/started",
                )?;
                turn_started_seen = true;
            }
            "item/started" => {
                validate_turn_correlation(params, thread_id, turn_id, "item/started")?;
                let item_id = required_text(
                    &message,
                    &["params", "item", "id"],
                    "item/started",
                    "item id",
                )?;
                let item_type = required_text(
                    &message,
                    &["params", "item", "type"],
                    "item/started",
                    "item type",
                )?;
                validate_identifier(item_id, "item id", 256)?;
                if completed_items.contains(item_id)
                    || active_items
                        .insert(
                            item_id.to_string(),
                            ActiveItem {
                                item_type: item_type.to_string(),
                                raw: message.pointer("/params/item").cloned().ok_or_else(|| {
                                    AppServerError::Malformed {
                                        phase: "item/started",
                                        message: "item payload is missing".to_string(),
                                    }
                                })?,
                            },
                        )
                        .is_some()
                {
                    return Err(AppServerError::Duplicate {
                        phase: "item/started",
                        message: "item lifecycle started more than once".to_string(),
                    });
                }
            }
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                validate_turn_correlation(params, thread_id, turn_id, "approval")?;
                let request_id = object
                    .get("id")
                    .ok_or_else(|| AppServerError::Malformed {
                        phase: "approval",
                        message: "approval request has no id".to_string(),
                    })
                    .and_then(|value| RequestId::parse(value, "approval"))?;
                if !state.server_request_ids.insert(request_id.clone()) {
                    return Err(AppServerError::Duplicate {
                        phase: "approval",
                        message: "approval request id was reused".to_string(),
                    });
                }
                let item_id =
                    required_text(&message, &["params", "itemId"], "approval", "item id")?;
                if !approval_request_items.insert(item_id.to_string()) {
                    return Err(AppServerError::Duplicate {
                        phase: "approval",
                        message: "active item requested approval more than once".to_string(),
                    });
                }
                let expected_type = if method == "item/commandExecution/requestApproval" {
                    "commandExecution"
                } else {
                    "fileChange"
                };
                let active_item =
                    active_items
                        .get(item_id)
                        .ok_or_else(|| AppServerError::Unexpected {
                            phase: "approval",
                            message: "approval item has no active lifecycle".to_string(),
                        })?;
                if active_item.item_type != expected_type {
                    return Err(AppServerError::Unexpected {
                        phase: "approval",
                        message: "approval item is not the matching active lifecycle item"
                            .to_string(),
                    });
                }
                let request = parse_approval_request(method, params, active_item.raw.clone())?;
                let expansion = request.ceiling_expansion_requested;
                let review = match bounded_review(
                    reviewer,
                    request,
                    state.deadline,
                    state.limits.approval_timeout,
                    cancelled,
                ) {
                    Ok(review) => review,
                    Err(error @ AppServerError::ApprovalTimeout)
                    | Err(error @ AppServerError::ApprovalReviewerLost)
                    | Err(error @ AppServerError::Cancelled { .. }) => {
                        state.send(
                            transport,
                            &json!({
                                "id": request_id.to_value(),
                                "result": {
                                    "decision": ApprovalDecision::Cancel.protocol_value()
                                }
                            }),
                        )?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                if expansion {
                    refused_ceiling_expansions = refused_ceiling_expansions.saturating_add(1);
                    if review.decision == ApprovalDecision::Accept {
                        state.send(
                            transport,
                            &json!({
                                "id": request_id.to_value(),
                                "result": {
                                    "decision": ApprovalDecision::Cancel.protocol_value()
                                }
                            }),
                        )?;
                        return Err(AppServerError::ApprovalReviewerLost);
                    }
                }
                if let Some(denial) = review.denial.clone() {
                    let feedback_id = state.allocate_request_id()?;
                    let payload = serde_json::to_string(&denial).map_err(|error| {
                        AppServerError::Malformed {
                            phase: "gate denial feedback",
                            message: format!("failed to encode typed gate denial: {error}"),
                        }
                    })?;
                    state.send(
                        transport,
                        &json!({
                            "id": feedback_id.to_value(),
                            "method": "turn/steer",
                            "params": {
                                "threadId": thread_id,
                                "expectedTurnId": turn_id,
                                "input": [{
                                    "type": "text",
                                    "text": format!("MACO_GATE_DENIAL_V1\n{payload}"),
                                    "text_elements": []
                                }]
                            }
                        }),
                    )?;
                    pending_correction_responses.insert(feedback_id, item_id.to_string());
                    gate_denials.push(denial);
                }
                state.send(
                    transport,
                    &json!({
                        "id": request_id.to_value(),
                        "result": {"decision": review.decision.protocol_value()}
                    }),
                )?;
                if review.decision == ApprovalDecision::Cancel {
                    return Err(AppServerError::Cancelled { phase: "approval" });
                }
            }
            "item/permissions/requestApproval" => {
                validate_turn_correlation(params, thread_id, turn_id, "permission approval")?;
                let request_id = object
                    .get("id")
                    .ok_or_else(|| AppServerError::Malformed {
                        phase: "permission approval",
                        message: "permission request has no id".to_string(),
                    })
                    .and_then(|value| RequestId::parse(value, "permission approval"))?;
                if !state.server_request_ids.insert(request_id.clone()) {
                    return Err(AppServerError::Duplicate {
                        phase: "permission approval",
                        message: "permission request id was reused".to_string(),
                    });
                }
                let item_id = required_text(
                    &message,
                    &["params", "itemId"],
                    "permission approval",
                    "item id",
                )?;
                if !approval_request_items.insert(item_id.to_string()) {
                    return Err(AppServerError::Duplicate {
                        phase: "permission approval",
                        message: "active item requested approval more than once".to_string(),
                    });
                }
                let active_item =
                    active_items
                        .get(item_id)
                        .ok_or_else(|| AppServerError::Unexpected {
                            phase: "permission approval",
                            message: "permission approval item has no active lifecycle".to_string(),
                        })?;
                let request = ApprovalRequest {
                    kind: ApprovalKind::PermissionExpansion,
                    thread_id: required_map_text(params, "threadId", "permission approval")?
                        .to_string(),
                    turn_id: required_map_text(params, "turnId", "permission approval")?
                        .to_string(),
                    item_id: item_id.to_string(),
                    command: None,
                    cwd: optional_bounded_text(params.get("cwd"), "cwd", 16 * 1024)?,
                    reason: optional_bounded_text(params.get("reason"), "reason", 64 * 1024)?,
                    ceiling_expansion_requested: true,
                    item: active_item.raw.clone(),
                    raw_params: Value::Object(params.clone()),
                };
                refused_ceiling_expansions = refused_ceiling_expansions.saturating_add(1);
                let review = match bounded_review(
                    reviewer,
                    request,
                    state.deadline,
                    state.limits.approval_timeout,
                    cancelled,
                ) {
                    Ok(review) => review,
                    Err(error) => {
                        state.send(
                            transport,
                            &json!({
                                "id": request_id.to_value(),
                                "result": {
                                    "permissions": {},
                                    "scope": "turn",
                                    "strictAutoReview": true
                                }
                            }),
                        )?;
                        return Err(error);
                    }
                };
                if review.decision == ApprovalDecision::Accept {
                    state.send(
                        transport,
                        &json!({
                            "id": request_id.to_value(),
                            "result": {
                                "permissions": {},
                                "scope": "turn",
                                "strictAutoReview": true
                            }
                        }),
                    )?;
                    return Err(AppServerError::ApprovalReviewerLost);
                }
                if let Some(denial) = review.denial {
                    let feedback_id = state.allocate_request_id()?;
                    let payload = serde_json::to_string(&denial).map_err(|error| {
                        AppServerError::Malformed {
                            phase: "gate denial feedback",
                            message: format!("failed to encode typed gate denial: {error}"),
                        }
                    })?;
                    state.send(
                        transport,
                        &json!({
                            "id": feedback_id.to_value(),
                            "method": "turn/steer",
                            "params": {
                                "threadId": thread_id,
                                "expectedTurnId": turn_id,
                                "input": [{
                                    "type": "text",
                                    "text": format!("MACO_GATE_DENIAL_V1\n{payload}"),
                                    "text_elements": []
                                }]
                            }
                        }),
                    )?;
                    pending_correction_responses.insert(feedback_id, item_id.to_string());
                    gate_denials.push(denial);
                }
                state.send(
                    transport,
                    &json!({
                        "id": request_id.to_value(),
                        "result": {
                            "permissions": {},
                            "scope": "turn",
                            "strictAutoReview": true
                        }
                    }),
                )?;
                if review.decision == ApprovalDecision::Cancel {
                    return Err(AppServerError::Cancelled {
                        phase: "permission approval",
                    });
                }
            }
            "item/autoApprovalReview/started" => {
                validate_turn_correlation(params, thread_id, turn_id, "auto approval review")?;
                let review_id = required_text(
                    &message,
                    &["params", "reviewId"],
                    "auto approval review",
                    "review id",
                )?;
                validate_identifier(review_id, "review id", 256)?;
                let action_type = required_text(
                    &message,
                    &["params", "action", "type"],
                    "auto approval review",
                    "review action type",
                )?
                .to_string();
                let target_item_id = optional_bounded_text(
                    message.pointer("/params/targetItemId"),
                    "review target item id",
                    256,
                )?;
                let target_correlated = target_item_id
                    .as_deref()
                    .and_then(|item_id| active_items.get(item_id))
                    .is_some_and(|item| {
                        auto_review_action_matches_item_type(&action_type, &item.item_type)
                    });
                if completed_reviews.contains(review_id)
                    || active_reviews
                        .insert(
                            review_id.to_string(),
                            ActiveReview {
                                target_item_id,
                                action_type,
                                target_correlated,
                            },
                        )
                        .is_some()
                {
                    return Err(AppServerError::Duplicate {
                        phase: "auto approval review",
                        message: "review lifecycle started more than once".to_string(),
                    });
                }
            }
            "item/autoApprovalReview/completed" => {
                validate_turn_correlation(params, thread_id, turn_id, "auto approval review")?;
                let mut evidence = parse_auto_review(&message)?;
                let active_review =
                    active_reviews.remove(&evidence.review_id).ok_or_else(|| {
                        AppServerError::Unexpected {
                            phase: "auto approval review",
                            message: "review completed without one matching active lifecycle"
                                .to_string(),
                        }
                    })?;
                if !completed_reviews.insert(evidence.review_id.clone()) {
                    return Err(AppServerError::Duplicate {
                        phase: "auto approval review",
                        message: "review lifecycle completed more than once".to_string(),
                    });
                }
                evidence.structured_policy_decision &= active_review.target_correlated
                    && evidence.target_item_id == active_review.target_item_id
                    && evidence.action_type == active_review.action_type;
                auto_reviews.push(evidence);
            }
            "item/completed" => {
                validate_turn_correlation(params, thread_id, turn_id, "item/completed")?;
                let item_id = required_text(
                    &message,
                    &["params", "item", "id"],
                    "item/completed",
                    "item id",
                )?;
                if pending_correction_responses
                    .values()
                    .any(|pending_item_id| pending_item_id == item_id)
                {
                    return Err(AppServerError::Unexpected {
                        phase: "item/completed",
                        message:
                            "denied item terminalized before typed gate-denial feedback was acknowledged"
                                .to_string(),
                    });
                }
                let item_type = required_text(
                    &message,
                    &["params", "item", "type"],
                    "item/completed",
                    "item type",
                )?;
                let active_item =
                    active_items
                        .remove(item_id)
                        .ok_or_else(|| AppServerError::Unexpected {
                            phase: "item/completed",
                            message: "item completed without an active lifecycle".to_string(),
                        })?;
                if active_item.item_type != item_type {
                    return Err(AppServerError::Unexpected {
                        phase: "item/completed",
                        message: "item completed without one matching active lifecycle".to_string(),
                    });
                }
                if !completed_items.insert(item_id.to_string()) {
                    return Err(AppServerError::Duplicate {
                        phase: "item/completed",
                        message: "item completed more than once".to_string(),
                    });
                }
                let status = if matches!(item_type, "commandExecution" | "fileChange") {
                    let status = required_text(
                        &message,
                        &["params", "item", "status"],
                        "item/completed",
                        "item status",
                    )?;
                    if !matches!(status, "completed" | "failed" | "declined") {
                        return Err(AppServerError::Unexpected {
                            phase: "item/completed",
                            message: "terminal item notification carried a non-terminal status"
                                .to_string(),
                        });
                    }
                    status.to_string()
                } else {
                    message
                        .pointer("/params/item/status")
                        .and_then(Value::as_str)
                        .unwrap_or("completed")
                        .to_string()
                };
                if item_type == "agentMessage" {
                    final_message = optional_bounded_text(
                        message.pointer("/params/item/text"),
                        "completed agent message",
                        OUTPUT_AGENT_MESSAGE_MAX_BYTES,
                    )?;
                }
                item_outcomes.push(ItemOutcome {
                    item_id: item_id.to_string(),
                    item_type: item_type.to_string(),
                    status,
                });
            }
            "turn/completed" => {
                validate_turn_correlation(params, thread_id, turn_id, "turn/completed")?;
                if !pending_correction_responses.is_empty() {
                    return Err(AppServerError::Unexpected {
                        phase: "turn/completed",
                        message:
                            "turn terminalized before all typed gate-denial feedback was acknowledged"
                                .to_string(),
                    });
                }
                if !active_items.is_empty() || !active_reviews.is_empty() {
                    return Err(AppServerError::Unexpected {
                        phase: "turn/completed",
                        message: "turn completed with active item or review lifecycles".to_string(),
                    });
                }
                let status = required_text(
                    &message,
                    &["params", "turn", "status"],
                    "turn/completed",
                    "turn status",
                )?;
                let status = match status {
                    "completed" => TurnTerminalStatus::Completed,
                    "interrupted" => TurnTerminalStatus::Interrupted,
                    "failed" => TurnTerminalStatus::Failed,
                    _ => {
                        return Err(AppServerError::Unexpected {
                            phase: "turn/completed",
                            message: "turn completion carried a non-terminal status".to_string(),
                        });
                    }
                };
                let duplex_fallback_required = auto_reviews.is_empty()
                    || auto_reviews
                        .iter()
                        .any(|review| !review.structured_policy_decision)
                    || {
                        let adequate_review_targets = auto_reviews
                            .iter()
                            .filter(|review| review.structured_policy_decision)
                            .filter_map(|review| review.target_item_id.as_deref())
                            .collect::<BTreeSet<_>>();
                        !approval_request_items
                            .iter()
                            .all(|item_id| adequate_review_targets.contains(item_id.as_str()))
                    };
                return Ok(AppServerOutcome {
                    thread_id: thread_id.to_string(),
                    turn_id: turn_id.to_string(),
                    status,
                    completed_items: completed_items.len(),
                    item_outcomes,
                    refused_ceiling_expansions,
                    gate_denials,
                    final_message,
                    auto_reviews,
                    duplex_fallback_required,
                    messages_received: state.messages_received,
                    bytes_received: state.bytes_received,
                });
            }
            "error" => {
                return Err(AppServerError::Remote {
                    phase: "turn",
                    message: bounded_json_summary(&Value::Object(params.clone())),
                });
            }
            method if is_bounded_progress_notification(method) => {
                validate_turn_correlation(params, thread_id, turn_id, "turn progress")?;
                if let Some(item_id) = params.get("itemId").and_then(Value::as_str) {
                    if !active_items.contains_key(item_id) {
                        return Err(AppServerError::Unexpected {
                            phase: "turn progress",
                            message: "progress referenced an inactive item".to_string(),
                        });
                    }
                }
            }
            _ => {
                return Err(AppServerError::Unexpected {
                    phase: "turn",
                    message: format!("unsupported method {method}"),
                });
            }
        }
    }
}

fn parse_approval_request(
    method: &str,
    params: &Map<String, Value>,
    item: Value,
) -> Result<ApprovalRequest, AppServerError> {
    let kind = if method == "item/commandExecution/requestApproval" {
        ApprovalKind::CommandExecution
    } else {
        ApprovalKind::FileChange
    };
    Ok(ApprovalRequest {
        kind,
        thread_id: required_map_text(params, "threadId", "approval")?.to_string(),
        turn_id: required_map_text(params, "turnId", "approval")?.to_string(),
        item_id: required_map_text(params, "itemId", "approval")?.to_string(),
        command: optional_bounded_text(params.get("command"), "command", 256 * 1024)?,
        cwd: optional_bounded_text(params.get("cwd"), "cwd", 16 * 1024)?,
        reason: optional_bounded_text(params.get("reason"), "reason", 64 * 1024)?,
        ceiling_expansion_requested: approval_requests_ceiling_expansion(params),
        item,
        raw_params: Value::Object(params.clone()),
    })
}

fn approval_requests_ceiling_expansion(params: &Map<String, Value>) -> bool {
    params.get("grantRoot").is_some_and(non_null_value)
        || params
            .get("additionalPermissions")
            .is_some_and(non_null_value)
        || params
            .get("networkApprovalContext")
            .is_some_and(non_null_value)
        || params
            .get("proposedNetworkPolicyAmendments")
            .is_some_and(non_empty_array_or_value)
}

fn non_null_value(value: &Value) -> bool {
    !value.is_null()
}

fn non_empty_array_or_value(value: &Value) -> bool {
    value
        .as_array()
        .map_or_else(|| !value.is_null(), |values| !values.is_empty())
}

fn bounded_review(
    reviewer: &mut dyn ApprovalReviewer,
    request: ApprovalRequest,
    turn_deadline: Instant,
    approval_timeout: Duration,
    cancelled: &impl Fn() -> bool,
) -> Result<ApprovalReview, AppServerError> {
    let approval_deadline = Instant::now()
        .checked_add(approval_timeout)
        .map_or(turn_deadline, |deadline| deadline.min(turn_deadline));
    if cancelled() {
        return Err(AppServerError::Cancelled { phase: "approval" });
    }
    if Instant::now() >= approval_deadline {
        return Err(AppServerError::ApprovalTimeout);
    }
    // The callback is deliberately synchronous: a timed-out classifier or journal append must
    // not continue as a detached effect after the child has been cancelled. Trusted reviewers
    // receive the same deadline and are required to bound their own read-only classifier call.
    let review = reviewer
        .review(request)
        .map_err(|_| AppServerError::ApprovalReviewerLost)?
        .validate()?;
    if cancelled() {
        return Err(AppServerError::Cancelled { phase: "approval" });
    }
    if Instant::now() >= approval_deadline {
        return Err(AppServerError::ApprovalTimeout);
    }
    Ok(review)
}

#[cfg(test)]
fn reviewer_decline_for_test(label: &str) -> ApprovalReview {
    let denial = GateDenial::from_approval_review(
        format!("test-{label}"),
        "test-reviewer",
        crate::gate_denial::ApprovalReviewDenial::ClassifierDenied,
        std::iter::empty::<&str>(),
    );
    match denial {
        Ok(denial) => ApprovalReview::decline(denial),
        Err(_) => ApprovalReview::cancel(None),
    }
}

fn parse_auto_review(message: &Value) -> Result<AutoReviewEvidence, AppServerError> {
    let review_id = required_text(
        message,
        &["params", "reviewId"],
        "auto approval review",
        "review id",
    )?
    .to_string();
    let action_type = required_text(
        message,
        &["params", "action", "type"],
        "auto approval review",
        "review action type",
    )?
    .to_string();
    let decision_source = required_text(
        message,
        &["params", "decisionSource"],
        "auto approval review",
        "review decision source",
    )?
    .to_string();
    let status = required_text(
        message,
        &["params", "review", "status"],
        "auto approval review",
        "review status",
    )?
    .to_string();
    let rationale = optional_bounded_text(
        message.pointer("/params/review/rationale"),
        "review rationale",
        64 * 1024,
    )?;
    let risk_level = optional_bounded_text(
        message.pointer("/params/review/riskLevel"),
        "review risk level",
        128,
    )?;
    let user_authorization = optional_bounded_text(
        message.pointer("/params/review/userAuthorization"),
        "review user authorization",
        128,
    )?;
    let target_item_id = optional_bounded_text(
        message.pointer("/params/targetItemId"),
        "review target item id",
        256,
    )?;
    let structured_policy_decision = target_item_id.is_some()
        && matches!(status.as_str(), "approved" | "denied")
        && decision_source == "agent"
        && matches!(
            action_type.as_str(),
            "command"
                | "execve"
                | "applyPatch"
                | "networkAccess"
                | "mcpToolCall"
                | "requestPermissions"
        )
        && rationale
            .as_ref()
            .is_some_and(|text| !text.trim().is_empty())
        && risk_level
            .as_ref()
            .is_some_and(|text| matches!(text.as_str(), "low" | "medium" | "high" | "critical"))
        && user_authorization
            .as_ref()
            .is_some_and(|text| matches!(text.as_str(), "low" | "medium" | "high"));
    Ok(AutoReviewEvidence {
        review_id,
        target_item_id,
        action_type,
        decision_source,
        status,
        rationale,
        risk_level,
        user_authorization,
        structured_policy_decision,
    })
}

fn auto_review_action_matches_item_type(action_type: &str, item_type: &str) -> bool {
    matches!(
        (action_type, item_type),
        ("command" | "execve", "commandExecution")
            | ("applyPatch", "fileChange")
            | ("mcpToolCall", "mcpToolCall")
    )
}

fn validate_turn_correlation(
    params: &Map<String, Value>,
    thread_id: &str,
    turn_id: &str,
    phase: &'static str,
) -> Result<(), AppServerError> {
    if required_map_text(params, "threadId", phase)? != thread_id {
        return Err(AppServerError::Unexpected {
            phase,
            message: "thread id did not match the active thread".to_string(),
        });
    }
    let correlated_turn = params
        .get("turnId")
        .and_then(Value::as_str)
        .or_else(|| {
            params
                .get("turn")
                .and_then(Value::as_object)
                .and_then(|turn| turn.get("id"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: "turn id is missing".to_string(),
        })?;
    if correlated_turn != turn_id {
        return Err(AppServerError::Unexpected {
            phase,
            message: "turn id did not match the active turn".to_string(),
        });
    }
    Ok(())
}

fn is_bounded_progress_notification(method: &str) -> bool {
    matches!(
        method,
        "thread/tokenUsage/updated"
            | "turn/diff/updated"
            | "turn/plan/updated"
            | "item/agentMessage/delta"
            | "item/plan/delta"
            | "item/reasoning/summaryTextDelta"
            | "item/reasoning/textDelta"
            | "item/commandExecution/outputDelta"
            | "item/fileChange/outputDelta"
    )
}

fn required_object<'a>(
    value: &'a Value,
    path: &[&str],
    phase: &'static str,
    label: &str,
) -> Result<&'a Map<String, Value>, AppServerError> {
    value_at_path(value, path)
        .and_then(Value::as_object)
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: format!("{label} is missing or is not an object"),
        })
}

fn required_text<'a>(
    value: &'a Value,
    path: &[&str],
    phase: &'static str,
    label: &str,
) -> Result<&'a str, AppServerError> {
    let text = value_at_path(value, path)
        .and_then(Value::as_str)
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: format!("{label} is missing or is not text"),
        })?;
    validate_identifier(text, label, 256)?;
    Ok(text)
}

fn required_map_text<'a>(
    value: &'a Map<String, Value>,
    key: &str,
    phase: &'static str,
) -> Result<&'a str, AppServerError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AppServerError::Malformed {
            phase,
            message: format!("{key} is missing or is not text"),
        })
}

fn require_exact_text(
    value: &Value,
    path: &[&str],
    expected: &str,
    phase: &'static str,
) -> Result<(), AppServerError> {
    let actual = required_text(value, path, phase, "correlated value")?;
    if actual == expected {
        Ok(())
    } else {
        Err(AppServerError::Unexpected {
            phase,
            message: "server returned a value outside the requested ceiling".to_string(),
        })
    }
}

fn value_at_path<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for component in path {
        value = value.get(*component)?;
    }
    Some(value)
}

fn validate_identifier(value: &str, label: &str, max_bytes: usize) -> Result<(), AppServerError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains(['\0', '\n', '\r'])
        || value.chars().any(char::is_control)
    {
        return Err(AppServerError::InvalidConfiguration {
            message: format!("{label} is empty, malformed, or oversized"),
        });
    }
    Ok(())
}

fn optional_bounded_text(
    value: Option<&Value>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>, AppServerError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(|| AppServerError::Malformed {
        phase: "approval",
        message: format!("{label} is not text"),
    })?;
    if text.len() > max_bytes || text.contains('\0') {
        return Err(AppServerError::Malformed {
            phase: "approval",
            message: format!("{label} is malformed or oversized"),
        });
    }
    Ok(Some(text.to_string()))
}

fn bounded_json_summary(value: &Value) -> String {
    let rendered = value.to_string();
    rendered.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Default)]
    struct FakeTransport {
        incoming: Vec<ReaderEvent>,
        sent: Vec<Value>,
        reads: Option<Arc<AtomicUsize>>,
        force_timeout: bool,
    }

    impl FakeTransport {
        fn from_values(values: Vec<Value>) -> Self {
            Self {
                incoming: values
                    .into_iter()
                    .rev()
                    .map(|value| ReaderEvent::Line(value.to_string().into_bytes()))
                    .collect(),
                sent: Vec::new(),
                reads: None,
                force_timeout: false,
            }
        }
    }

    impl JsonLineTransport for FakeTransport {
        fn receive(
            &mut self,
            wait: Duration,
            max_line_bytes: usize,
            destination: &mut Vec<u8>,
        ) -> Result<TransportRead, String> {
            destination.clear();
            if let Some(reads) = &self.reads {
                reads.fetch_add(1, Ordering::SeqCst);
            }
            if self.force_timeout {
                thread::sleep(wait.min(Duration::from_millis(1)));
                return Ok(TransportRead::Timeout);
            }
            match self.incoming.pop() {
                Some(ReaderEvent::Line(line)) => {
                    if line.len() > max_line_bytes {
                        return Err("fake line too long".to_string());
                    }
                    destination.extend(line);
                    Ok(TransportRead::Line)
                }
                Some(ReaderEvent::Eof) | None => Ok(TransportRead::Eof),
                Some(ReaderEvent::Failed(message)) => Err(message),
            }
        }

        fn send(&mut self, line: &[u8]) -> Result<(), String> {
            let value = serde_json::from_slice(line)
                .map_err(|error| format!("invalid client JSON: {error}"))?;
            self.sent.push(value);
            Ok(())
        }
    }

    fn base_messages() -> Vec<Value> {
        vec![
            json!({"id": 1, "result": {}}),
            json!({
                "id": 2,
                "result": {
                    "thread": {"id": "thread-1"},
                    "approvalPolicy": "on-request",
                    "approvalsReviewer": "user",
                    "activePermissionProfile": {"id": "maco_external_codex"},
                    "cwd": "/workspace"
                }
            }),
            json!({
                "id": 3,
                "result": {"turn": {"id": "turn-1", "status": "inProgress"}}
            }),
            json!({
                "method": "turn/started",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "inProgress"}
                }
            }),
        ]
    }

    fn test_turn() -> AppServerTurn {
        AppServerTurn {
            cwd: "/workspace".to_string(),
            permission_profile: "maco_external_codex".to_string(),
            prompt: "perform the bounded task".to_string(),
            model: None,
        }
    }

    fn sent_interrupt(transport: &FakeTransport) -> bool {
        transport
            .sent
            .iter()
            .any(|message| message.get("method") == Some(&json!("turn/interrupt")))
    }

    fn approval_response(transport: &FakeTransport, id: u64) -> Option<&Value> {
        transport.sent.iter().find(|message| {
            message.get("id").and_then(Value::as_u64) == Some(id)
                && message.pointer("/result/decision").is_some()
        })
    }

    fn auto_review_messages(
        started_target: Option<&str>,
        completed_target: Option<&str>,
    ) -> Vec<Value> {
        let mut started = json!({
            "method": "item/autoApprovalReview/started",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "reviewId": "review-1",
                "startedAtMs": 2,
                "action": {"type": "command", "command": "cargo test"},
                "review": {"status": "inProgress"}
            }
        });
        if let Some(target) = started_target {
            started["params"]["targetItemId"] = Value::from(target);
        }
        let mut completed = json!({
            "method": "item/autoApprovalReview/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "reviewId": "review-1",
                "startedAtMs": 2,
                "completedAtMs": 3,
                "action": {"type": "command", "command": "cargo test"},
                "decisionSource": "agent",
                "review": {
                    "status": "approved",
                    "rationale": "bounded command",
                    "riskLevel": "low",
                    "userAuthorization": "low"
                }
            }
        });
        if let Some(target) = completed_target {
            completed["params"]["targetItemId"] = Value::from(target);
        }
        vec![
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "item-reviewed",
                        "type": "commandExecution",
                        "status": "inProgress"
                    }
                }
            }),
            started,
            completed,
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 4,
                    "item": {
                        "id": "item-reviewed",
                        "type": "commandExecution",
                        "status": "completed"
                    }
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]
    }

    fn run_auto_review_transcript(
        started_target: Option<&str>,
        completed_target: Option<&str>,
    ) -> AppServerOutcome {
        let mut messages = base_messages();
        messages.extend(auto_review_messages(started_target, completed_target));
        let mut transport = FakeTransport::from_values(messages);
        run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("auto-review")),
            || false,
        )
        .expect("auto review transcript")
    }

    fn auto_review_lifecycle(review_id: &str, target_item_id: &str, at_ms: u64) -> Vec<Value> {
        vec![
            json!({
                "method": "item/autoApprovalReview/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "reviewId": review_id,
                    "targetItemId": target_item_id,
                    "startedAtMs": at_ms,
                    "action": {"type": "command", "command": "cargo test"},
                    "review": {"status": "inProgress"}
                }
            }),
            json!({
                "method": "item/autoApprovalReview/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "reviewId": review_id,
                    "targetItemId": target_item_id,
                    "startedAtMs": at_ms,
                    "completedAtMs": at_ms.saturating_add(1),
                    "action": {"type": "command", "command": "cargo test"},
                    "decisionSource": "agent",
                    "review": {
                        "status": "approved",
                        "rationale": "bounded command",
                        "riskLevel": "low",
                        "userAuthorization": "low"
                    }
                }
            }),
        ]
    }

    fn run_two_approval_item_transcript(review_second_item: bool) -> AppServerOutcome {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-one", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 61,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-one",
                    "startedAtMs": 1,
                    "command": "cargo test one"
                }
            }),
        ]);
        messages.extend(auto_review_lifecycle("review-one", "item-one", 2));
        messages.extend([
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 4,
                    "item": {"id": "item-one", "type": "commandExecution", "status": "completed"}
                }
            }),
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-two", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 62,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-two",
                    "startedAtMs": 5,
                    "command": "cargo test two"
                }
            }),
        ]);
        if review_second_item {
            messages.extend(auto_review_lifecycle("review-two", "item-two", 6));
        }
        messages.extend([
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 8,
                    "item": {"id": "item-two", "type": "commandExecution", "status": "completed"}
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(ApprovalReview::accept()),
            || false,
        )
        .expect("two approval item transcript")
    }

    #[test]
    fn command_execution_approval_is_correlated_and_exact() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "item-1",
                        "type": "commandExecution",
                        "status": "inProgress"
                    }
                }
            }),
            json!({
                "id": "approval-1",
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-1",
                    "startedAtMs": 1,
                    "command": "cargo test",
                    "cwd": "/workspace"
                }
            }),
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 2,
                    "item": {
                        "id": "item-1",
                        "type": "commandExecution",
                        "status": "completed"
                    }
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let mut reviewer = |request: ApprovalRequest| {
            assert_eq!(request.item_id, "item-1");
            assert_eq!(request.kind, ApprovalKind::CommandExecution);
            Ok(ApprovalReview::accept())
        };

        let outcome = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut reviewer,
            || false,
        )
        .expect("command approval transcript");

        assert_eq!(outcome.completed_items, 1);
        assert!(outcome.duplex_fallback_required);
        let response = transport
            .sent
            .iter()
            .find(|message| message.get("id") == Some(&Value::from("approval-1")))
            .expect("approval response");
        assert_eq!(response.pointer("/result/decision"), Some(&json!("accept")));
    }

    #[test]
    fn file_change_approval_uses_only_single_request_decisions() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-2", "type": "fileChange", "status": "inProgress"}
                }
            }),
            json!({
                "id": 44,
                "method": "item/fileChange/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-2",
                    "startedAtMs": 1,
                    "reason": "update source"
                }
            }),
            json!({"id": 4, "result": {}}),
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 2,
                    "item": {"id": "item-2", "type": "fileChange", "status": "declined"}
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |request: ApprovalRequest| {
                assert_eq!(request.kind, ApprovalKind::FileChange);
                Ok(reviewer_decline_for_test("file-change"))
            },
            || false,
        )
        .expect("file approval transcript");
        assert_eq!(
            approval_response(&transport, 44).and_then(|value| value.pointer("/result/decision")),
            Some(&json!("decline"))
        );
        let steer_index = transport
            .sent
            .iter()
            .position(|message| message.get("method") == Some(&json!("turn/steer")))
            .expect("typed denial steer");
        let decline_index = transport
            .sent
            .iter()
            .position(|message| message.get("id") == Some(&json!(44)))
            .expect("decline response");
        assert!(steer_index < decline_index);
        assert_eq!(
            transport.sent[steer_index].pointer("/params/threadId"),
            Some(&json!("thread-1"))
        );
        assert_eq!(
            transport.sent[steer_index].pointer("/params/expectedTurnId"),
            Some(&json!("turn-1"))
        );
        assert!(
            transport.sent[steer_index]
                .pointer("/params/turnId")
                .is_none(),
            "TurnSteerParams must use expectedTurnId, not turnId"
        );
    }

    #[test]
    fn denied_item_cannot_terminalize_before_same_turn_feedback_ack() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "denied-item", "type": "fileChange", "status": "inProgress"}
                }
            }),
            json!({
                "id": 91,
                "method": "item/fileChange/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "denied-item",
                    "startedAtMs": 1,
                    "reason": "unsafe write"
                }
            }),
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 2,
                    "item": {"id": "denied-item", "type": "fileChange", "status": "declined"}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("item-before-ack")),
            || false,
        )
        .expect_err("terminal item before feedback ack");

        assert!(matches!(
            error,
            AppServerError::Unexpected {
                phase: "item/completed",
                ..
            }
        ));
        let steer = transport
            .sent
            .iter()
            .find(|message| message.get("method") == Some(&json!("turn/steer")))
            .expect("same-turn steer");
        assert_eq!(steer.pointer("/params/threadId"), Some(&json!("thread-1")));
        assert_eq!(
            steer.pointer("/params/expectedTurnId"),
            Some(&json!("turn-1"))
        );
    }

    #[test]
    fn turn_cannot_terminalize_with_unacknowledged_gate_feedback() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "denied-item", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 92,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "denied-item",
                    "startedAtMs": 1,
                    "command": "unsafe command"
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("turn-before-ack")),
            || false,
        )
        .expect_err("terminal turn before feedback ack");

        assert!(matches!(
            error,
            AppServerError::Unexpected {
                phase: "turn/completed",
                ..
            }
        ));
    }

    #[test]
    fn approval_callback_has_a_real_wall_clock_timeout() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-3", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 45,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-3",
                    "startedAtMs": 1,
                    "command": "sleep forever"
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let limits = AppServerLimits {
            approval_timeout: Duration::from_millis(10),
            ..AppServerLimits::default()
        };
        let started = Instant::now();
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            limits,
            &mut |_: ApprovalRequest| {
                thread::sleep(Duration::from_millis(20));
                Ok(ApprovalReview::accept())
            },
            || false,
        )
        .expect_err("approval timeout");
        assert_eq!(error, AppServerError::ApprovalTimeout);
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            approval_response(&transport, 45).and_then(|value| value.pointer("/result/decision")),
            Some(&json!("cancel"))
        );
        assert!(transport
            .sent
            .iter()
            .any(|message| message.get("method") == Some(&json!("turn/interrupt"))));
    }

    #[test]
    fn cancellation_is_polled_while_approval_callback_is_running() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-cancel", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 47,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-cancel",
                    "startedAtMs": 1,
                    "command": "sleep forever"
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let started = Instant::now();
        let cancellation_started = started;
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| {
                thread::sleep(Duration::from_millis(20));
                Ok(ApprovalReview::accept())
            },
            move || cancellation_started.elapsed() >= Duration::from_millis(10),
        )
        .expect_err("approval cancellation");
        assert_eq!(error, AppServerError::Cancelled { phase: "approval" });
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            approval_response(&transport, 47).and_then(|value| value.pointer("/result/decision")),
            Some(&json!("cancel"))
        );
        assert!(transport
            .sent
            .iter()
            .any(|message| message.get("method") == Some(&json!("turn/interrupt"))));
    }

    #[test]
    fn malformed_response_fails_closed() {
        let mut transport = FakeTransport {
            incoming: vec![ReaderEvent::Line(b"{malformed".to_vec())],
            sent: Vec::new(),
            reads: None,
            force_timeout: false,
        };
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("malformed")),
            || false,
        )
        .expect_err("malformed response");
        assert!(matches!(error, AppServerError::Malformed { .. }));
    }

    #[test]
    fn protocol_eof_is_reported_as_loss() {
        let mut transport = FakeTransport {
            incoming: vec![ReaderEvent::Eof],
            sent: Vec::new(),
            reads: None,
            force_timeout: false,
        };
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("protocol-loss")),
            || false,
        )
        .expect_err("protocol loss");
        assert_eq!(
            error,
            AppServerError::ProtocolLoss {
                phase: "initialize"
            }
        );
    }

    #[test]
    fn permission_expansion_is_refused_by_policy() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-4", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 46,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-4",
                    "startedAtMs": 1,
                    "command": "curl https://example.invalid",
                    "additionalPermissions": {"network": {"enabled": true}},
                    "networkApprovalContext": {
                        "host": "example.invalid",
                        "protocol": "https"
                    }
                }
            }),
            json!({"id": 4, "result": {}}),
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 2,
                    "item": {"id": "item-4", "type": "commandExecution", "status": "declined"}
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let mut transport = FakeTransport::from_values(messages);
        let mut reviewer = move |_: ApprovalRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(reviewer_decline_for_test("permission-expansion"))
        };
        let outcome = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut reviewer,
            || false,
        )
        .expect("expansion refusal transcript");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.refused_ceiling_expansions, 1);
        assert_eq!(
            approval_response(&transport, 46).and_then(|value| value.pointer("/result/decision")),
            Some(&json!("decline"))
        );
    }

    #[test]
    fn protocol_timeout_is_a_bounded_failure() {
        let mut transport = FakeTransport {
            incoming: Vec::new(),
            sent: Vec::new(),
            reads: None,
            force_timeout: true,
        };
        let limits = AppServerLimits {
            turn_timeout: Duration::from_millis(5),
            ..AppServerLimits::default()
        };
        let started = Instant::now();
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            limits,
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("protocol-timeout")),
            || false,
        )
        .expect_err("protocol timeout");
        assert_eq!(
            error,
            AppServerError::Timeout {
                phase: "initialize"
            }
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cancellation_after_turn_start_sends_interrupt() {
        let reads = Arc::new(AtomicUsize::new(0));
        let cancellation_reads = Arc::clone(&reads);
        let mut transport = FakeTransport::from_values(base_messages());
        transport.reads = Some(reads);
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("turn-cancel")),
            move || cancellation_reads.load(Ordering::SeqCst) >= 3,
        )
        .expect_err("turn cancellation");
        assert_eq!(error, AppServerError::Cancelled { phase: "turn" });
        assert!(sent_interrupt(&transport));
    }

    fn assert_mid_turn_fault_sends_interrupt(
        label: &str,
        extra: ReaderEvent,
        matches_error: impl Fn(&AppServerError) -> bool,
    ) {
        let mut incoming = FakeTransport::from_values(base_messages()).incoming;
        incoming.insert(0, extra);
        let mut transport = FakeTransport {
            incoming,
            sent: Vec::new(),
            reads: None,
            force_timeout: false,
        };
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test(label)),
            || false,
        )
        .expect_err(label);
        assert!(
            matches_error(&error),
            "{label} produced unexpected error: {error:?}"
        );
        assert!(
            sent_interrupt(&transport),
            "{label} must interrupt the in-flight turn"
        );
    }

    #[test]
    fn mid_turn_protocol_faults_send_interrupt_once_ids_are_known() {
        assert_mid_turn_fault_sends_interrupt(
            "unsupported method",
            ReaderEvent::Line(
                json!({
                    "method": "item/newVendorProgress",
                    "params": {"threadId": "thread-1", "turnId": "turn-1"}
                })
                .to_string()
                .into_bytes(),
            ),
            |error| {
                matches!(
                    error,
                    AppServerError::Unexpected { phase: "turn", message }
                        if message.contains("unsupported method")
                )
            },
        );
        assert_mid_turn_fault_sends_interrupt(
            "malformed JSON",
            ReaderEvent::Line(b"{not-json".to_vec()),
            |error| matches!(error, AppServerError::Malformed { phase: "turn", .. }),
        );
        assert_mid_turn_fault_sends_interrupt(
            "remote error",
            ReaderEvent::Line(
                json!({
                    "method": "error",
                    "params": {"message": "child exploded"}
                })
                .to_string()
                .into_bytes(),
            ),
            |error| matches!(error, AppServerError::Remote { phase: "turn", .. }),
        );
        assert_mid_turn_fault_sends_interrupt(
            "transport failure",
            ReaderEvent::Failed("pipe broken".to_string()),
            |error| {
                matches!(
                    error,
                    AppServerError::Transport { message } if message.contains("pipe broken")
                )
            },
        );
    }

    #[test]
    fn initialize_faults_do_not_send_interrupt_before_turn_ids() {
        let mut transport = FakeTransport {
            incoming: vec![ReaderEvent::Line(b"{malformed".to_vec())],
            sent: Vec::new(),
            reads: None,
            force_timeout: false,
        };
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("pre-turn")),
            || false,
        )
        .expect_err("initialize malformed");
        assert!(matches!(error, AppServerError::Malformed { .. }));
        assert!(!sent_interrupt(&transport));
    }

    #[test]
    fn default_line_bound_reaches_the_agent_message_ceiling() {
        let limits = AppServerLimits::default()
            .validate()
            .expect("default limits must be valid");
        assert!(
            limits.max_line_bytes >= OUTPUT_AGENT_MESSAGE_MAX_BYTES,
            "duplex default line bound must admit the advertised 8MB agent message"
        );
        assert!(
            limits.max_line_bytes <= HARD_MAX_LINE_BYTES,
            "default line bound must stay under the hard ceiling"
        );
        assert!(limits.max_total_bytes >= limits.max_line_bytes);
        assert!(AppServerLimits {
            max_line_bytes: OUTPUT_AGENT_MESSAGE_MAX_BYTES,
            max_total_bytes: HARD_MAX_TOTAL_BYTES,
            ..AppServerLimits::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn completed_agent_message_past_the_old_line_cap_is_received() {
        let text = "x".repeat(300 * 1024);
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "final-msg", "type": "agentMessage", "status": "inProgress"}
                }
            }),
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "completedAtMs": 2,
                    "item": {
                        "id": "final-msg",
                        "type": "agentMessage",
                        "status": "completed",
                        "text": text
                    }
                }
            }),
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "status": "completed", "items": []}
                }
            }),
        ]);
        let mut transport = FakeTransport::from_values(messages);
        let outcome = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("large-message")),
            || false,
        )
        .expect("300KiB completed agent message must be receivable");
        assert_eq!(outcome.final_message.as_deref(), Some(text.as_str()));
        assert_eq!(outcome.completed_items, 1);
    }

    #[test]
    fn approval_expansion_fields_are_rejected_across_method_shapes() {
        for params in [
            Map::from_iter([("grantRoot".to_string(), Value::from("/outside/workspace"))]),
            Map::from_iter([(
                "additionalPermissions".to_string(),
                json!({"network": {"enabled": true}}),
            )]),
            Map::from_iter([(
                "networkApprovalContext".to_string(),
                json!({"host": "example.invalid", "protocol": "https"}),
            )]),
            Map::from_iter([(
                "proposedNetworkPolicyAmendments".to_string(),
                json!([{"host": "example.invalid", "action": "allow"}]),
            )]),
        ] {
            assert!(approval_requests_ceiling_expansion(&params));
        }
    }

    #[test]
    fn fixed_permission_profile_cannot_be_replaced_by_a_caller() {
        let mut transport = FakeTransport::default();
        let mut turn = test_turn();
        turn.permission_profile = "broader_profile".to_string();
        let error = run_app_server_turn(
            &mut transport,
            &turn,
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("profile")),
            || false,
        )
        .expect_err("broader permission profile");
        assert!(matches!(error, AppServerError::InvalidConfiguration { .. }));
        assert!(transport.sent.is_empty());
    }

    #[test]
    fn duplicate_turn_started_notification_is_rejected() {
        let mut messages = base_messages();
        messages.push(json!({
            "method": "turn/started",
            "params": {
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "inProgress"}
            }
        }));
        let mut transport = FakeTransport::from_values(messages);
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut |_: ApprovalRequest| Ok(reviewer_decline_for_test("duplicate-start")),
            || false,
        )
        .expect_err("duplicate turn start");
        assert!(matches!(error, AppServerError::Duplicate { .. }));
    }

    #[test]
    fn exact_item_correlated_auto_review_can_avoid_fallback() {
        let outcome = run_auto_review_transcript(Some("item-reviewed"), Some("item-reviewed"));
        assert!(!outcome.duplex_fallback_required);
    }

    #[test]
    fn missing_auto_review_target_requires_fallback() {
        let outcome = run_auto_review_transcript(None, None);
        assert!(outcome.duplex_fallback_required);
    }

    #[test]
    fn wrong_auto_review_target_requires_fallback() {
        let outcome = run_auto_review_transcript(Some("item-other"), Some("item-other"));
        assert!(outcome.duplex_fallback_required);
    }

    #[test]
    fn mismatched_auto_review_lifecycle_target_requires_fallback() {
        let outcome = run_auto_review_transcript(Some("item-reviewed"), Some("item-other"));
        assert!(outcome.duplex_fallback_required);
    }

    #[test]
    fn every_approval_item_requires_adequate_review_coverage() {
        let outcome = run_two_approval_item_transcript(false);
        assert_eq!(outcome.completed_items, 2);
        assert!(outcome.duplex_fallback_required);
    }

    #[test]
    fn complete_approval_item_review_coverage_can_avoid_fallback() {
        let outcome = run_two_approval_item_transcript(true);
        assert_eq!(outcome.completed_items, 2);
        assert!(!outcome.duplex_fallback_required);
    }

    #[test]
    fn active_item_cannot_request_approval_twice() {
        let mut messages = base_messages();
        messages.extend([
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"id": "item-duplicate", "type": "commandExecution", "status": "inProgress"}
                }
            }),
            json!({
                "id": 71,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-duplicate",
                    "startedAtMs": 1,
                    "command": "cargo test"
                }
            }),
            json!({
                "id": 72,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-duplicate",
                    "startedAtMs": 2,
                    "command": "cargo test"
                }
            }),
        ]);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let mut transport = FakeTransport::from_values(messages);
        let mut reviewer = move |_: ApprovalRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ApprovalReview::accept())
        };
        let error = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            &mut reviewer,
            || false,
        )
        .expect_err("duplicate approval item");
        assert!(matches!(error, AppServerError::Duplicate { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_auto_review_requires_structured_decision_fields() {
        let message = json!({
            "params": {
                "reviewId": "review-1",
                "targetItemId": "item-1",
                "action": {"type": "command", "command": "cargo test"},
                "decisionSource": "agent",
                "review": {
                    "status": "approved",
                    "rationale": "bounded command",
                    "riskLevel": "low",
                    "userAuthorization": "low"
                }
            }
        });
        let evidence = parse_auto_review(&message).expect("auto review");
        assert!(evidence.structured_policy_decision);

        let inadequate = json!({
            "params": {
                "reviewId": "review-2",
                "action": {"type": "command", "command": "cargo test"},
                "decisionSource": "agent",
                "review": {
                    "status": "approved",
                    "rationale": null,
                    "riskLevel": null,
                    "userAuthorization": null
                }
            }
        });
        assert!(
            !parse_auto_review(&inadequate)
                .expect("inadequate auto review remains evidence")
                .structured_policy_decision
        );
    }
}
