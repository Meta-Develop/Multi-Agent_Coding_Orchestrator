#![allow(dead_code)]

use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{BufRead, BufReader, Read, Write},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const HARD_MAX_LINE_BYTES: usize = 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_MESSAGES: usize = 16_384;
const HARD_MAX_PROMPT_BYTES: usize = 1024 * 1024;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
            max_line_bytes: 256 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
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
    pub(crate) item: Value,
    pub(crate) raw_params: Value,
}

pub(crate) trait ApprovalReviewer: Send + Sync + 'static {
    fn review(&self, request: ApprovalRequest) -> ApprovalDecision;
}

impl<F> ApprovalReviewer for F
where
    F: Fn(ApprovalRequest) -> ApprovalDecision + Send + Sync + 'static,
{
    fn review(&self, request: ApprovalRequest) -> ApprovalDecision {
        self(request)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnTerminalStatus {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    reviewer: Arc<dyn ApprovalReviewer>,
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
        ("approvalsReviewer".to_string(), Value::from("auto_review")),
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
        "auto_review",
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
                "approvalsReviewer": "auto_review",
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
        Err(error @ AppServerError::Timeout { .. })
        | Err(error @ AppServerError::Cancelled { .. })
        | Err(error @ AppServerError::ApprovalTimeout) => {
            state.interrupt(transport, &thread_id, &turn_id);
            Err(error)
        }
        Err(error) => Err(error),
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
    reviewer: Arc<dyn ApprovalReviewer>,
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

    let mut active_items = BTreeMap::<String, ActiveItem>::new();
    let mut completed_items = BTreeSet::<String>::new();
    let mut item_outcomes = Vec::new();
    let mut active_reviews = BTreeSet::<String>::new();
    let mut completed_reviews = BTreeSet::<String>::new();
    let mut auto_reviews = Vec::new();
    let mut refused_ceiling_expansions = 0usize;

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
            if !state.response_ids.insert(id) {
                return Err(AppServerError::Duplicate {
                    phase: "turn",
                    message: "response id was already completed".to_string(),
                });
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
                require_exact_text(&message, &["params", "thread", "id"], thread_id, "turn")?;
            }
            "turn/started" => {
                validate_turn_correlation(params, thread_id, turn_id, "turn/started")?;
                require_exact_text(
                    &message,
                    &["params", "turn", "status"],
                    "inProgress",
                    "turn/started",
                )?;
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
                let expansion = approval_requests_ceiling_expansion(method, params);
                let decision = if expansion {
                    refused_ceiling_expansions = refused_ceiling_expansions.saturating_add(1);
                    ApprovalDecision::Decline
                } else {
                    let request = parse_approval_request(method, params, active_item.raw.clone())?;
                    match bounded_review(
                        Arc::clone(&reviewer),
                        request,
                        state.deadline,
                        state.limits.approval_timeout,
                    ) {
                        Ok(decision) => decision,
                        Err(error @ AppServerError::ApprovalTimeout)
                        | Err(error @ AppServerError::ApprovalReviewerLost) => {
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
                    }
                };
                state.send(
                    transport,
                    &json!({
                        "id": request_id.to_value(),
                        "result": {"decision": decision.protocol_value()}
                    }),
                )?;
                if decision == ApprovalDecision::Cancel {
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
                refused_ceiling_expansions = refused_ceiling_expansions.saturating_add(1);
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
                if completed_reviews.contains(review_id)
                    || !active_reviews.insert(review_id.to_string())
                {
                    return Err(AppServerError::Duplicate {
                        phase: "auto approval review",
                        message: "review lifecycle started more than once".to_string(),
                    });
                }
            }
            "item/autoApprovalReview/completed" => {
                validate_turn_correlation(params, thread_id, turn_id, "auto approval review")?;
                let evidence = parse_auto_review(&message)?;
                if !active_reviews.remove(&evidence.review_id)
                    || !completed_reviews.insert(evidence.review_id.clone())
                {
                    return Err(AppServerError::Unexpected {
                        phase: "auto approval review",
                        message: "review completed without one matching active lifecycle"
                            .to_string(),
                    });
                }
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
                item_outcomes.push(ItemOutcome {
                    item_id: item_id.to_string(),
                    item_type: item_type.to_string(),
                    status,
                });
            }
            "turn/completed" => {
                validate_turn_correlation(params, thread_id, turn_id, "turn/completed")?;
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
                        .any(|review| !review.structured_policy_decision);
                return Ok(AppServerOutcome {
                    thread_id: thread_id.to_string(),
                    turn_id: turn_id.to_string(),
                    status,
                    completed_items: completed_items.len(),
                    item_outcomes,
                    refused_ceiling_expansions,
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
        item,
        raw_params: Value::Object(params.clone()),
    })
}

fn approval_requests_ceiling_expansion(method: &str, params: &Map<String, Value>) -> bool {
    if method == "item/fileChange/requestApproval" {
        return params.get("grantRoot").is_some_and(non_null_value);
    }
    params
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
    reviewer: Arc<dyn ApprovalReviewer>,
    request: ApprovalRequest,
    turn_deadline: Instant,
    approval_timeout: Duration,
) -> Result<ApprovalDecision, AppServerError> {
    let now = Instant::now();
    if now >= turn_deadline {
        return Err(AppServerError::ApprovalTimeout);
    }
    let wait = turn_deadline
        .saturating_duration_since(now)
        .min(approval_timeout);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("maco-codex-approval-review".to_string())
        .spawn(move || {
            let decision = reviewer.review(request);
            let _ = sender.send(decision);
        })
        .map_err(|_| AppServerError::ApprovalReviewerLost)?;
    match receiver.recv_timeout(wait) {
        Ok(decision) => Ok(decision),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(AppServerError::ApprovalTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(AppServerError::ApprovalReviewerLost),
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
    let structured_policy_decision = matches!(status.as_str(), "approved" | "denied")
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
                    "approvalsReviewer": "auto_review",
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

    fn approval_response(transport: &FakeTransport, id: u64) -> Option<&Value> {
        transport.sent.iter().find(|message| {
            message.get("id").and_then(Value::as_u64) == Some(id)
                && message.pointer("/result/decision").is_some()
        })
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
        let reviewer = Arc::new(|request: ApprovalRequest| {
            assert_eq!(request.item_id, "item-1");
            assert_eq!(request.kind, ApprovalKind::CommandExecution);
            ApprovalDecision::Accept
        });

        let outcome = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            reviewer,
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
            Arc::new(|request: ApprovalRequest| {
                assert_eq!(request.kind, ApprovalKind::FileChange);
                ApprovalDecision::Decline
            }),
            || false,
        )
        .expect("file approval transcript");
        assert_eq!(
            approval_response(&transport, 44).and_then(|value| value.pointer("/result/decision")),
            Some(&json!("decline"))
        );
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
            Arc::new(|_: ApprovalRequest| {
                thread::sleep(Duration::from_secs(5));
                ApprovalDecision::Accept
            }),
            || false,
        )
        .expect_err("approval timeout");
        assert_eq!(error, AppServerError::ApprovalTimeout);
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
            Arc::new(|_: ApprovalRequest| ApprovalDecision::Decline),
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
            Arc::new(|_: ApprovalRequest| ApprovalDecision::Decline),
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
    fn permission_expansion_is_refused_without_calling_policy() {
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
        let outcome = run_app_server_turn(
            &mut transport,
            &test_turn(),
            AppServerLimits::default(),
            Arc::new(move |_: ApprovalRequest| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                ApprovalDecision::Accept
            }),
            || false,
        )
        .expect("expansion refusal transcript");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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
            Arc::new(|_: ApprovalRequest| ApprovalDecision::Decline),
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
            Arc::new(|_: ApprovalRequest| ApprovalDecision::Decline),
            move || cancellation_reads.load(Ordering::SeqCst) >= 3,
        )
        .expect_err("turn cancellation");
        assert_eq!(error, AppServerError::Cancelled { phase: "turn" });
        assert!(transport
            .sent
            .iter()
            .any(|message| message.get("method") == Some(&json!("turn/interrupt"))));
    }

    #[test]
    fn grant_root_is_always_a_ceiling_expansion() {
        let params = Map::from_iter([("grantRoot".to_string(), Value::from("/outside/workspace"))]);
        assert!(approval_requests_ceiling_expansion(
            "item/fileChange/requestApproval",
            &params
        ));
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
