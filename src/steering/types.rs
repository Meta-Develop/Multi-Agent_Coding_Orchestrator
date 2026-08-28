use crate::{hierarchy_ledger::RoleCategory, supervise::ModelCapabilityClass};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const STEERING_REQUEST_VERSION: u32 = 1;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_PATHS: usize = 32;
pub const MAX_PATH_BYTES: usize = 1_024;
pub const MAX_STEERING_DEADLINE_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentKind {
    Execution,
    ReviewGate,
    MergeGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentBinding {
    pub run_id: String,
    pub assignment_id: String,
    pub role_category: RoleCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_capability: Option<ModelCapabilityClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_id: Option<String>,
    pub kind: AssignmentKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SteeringActor {
    Operator {
        agent_id: String,
    },
    ParentCoordinator {
        agent_id: String,
        role_category: RoleCategory,
        model_capability: ModelCapabilityClass,
    },
}

impl SteeringActor {
    pub fn agent_id(&self) -> &str {
        match self {
            Self::Operator { agent_id } | Self::ParentCoordinator { agent_id, .. } => agent_id,
        }
    }

    pub fn model_capability(&self) -> Option<ModelCapabilityClass> {
        match self {
            Self::Operator { .. } => None,
            Self::ParentCoordinator {
                model_capability, ..
            } => Some(*model_capability),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitlDecisionKind {
    Approve,
    Edit,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SteeringAction {
    InjectCorrectiveInput {
        message: String,
    },
    Pause,
    Resume,
    NarrowScope {
        allowed_paths: Vec<String>,
    },
    CancelAssignment {
        reason: String,
    },
    HitlDecision {
        tool_call_id: String,
        decision: HitlDecisionKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replacement: Option<String>,
    },
}

impl SteeringAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::InjectCorrectiveInput { .. } => "inject_corrective_input",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::NarrowScope { .. } => "narrow_scope",
            Self::CancelAssignment { .. } => "cancel_assignment",
            Self::HitlDecision { .. } => "hitl_decision",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteeringRequest {
    pub version: u32,
    pub action_id: String,
    pub run_id: String,
    pub assignment_id: String,
    pub actor: SteeringActor,
    pub action: SteeringAction,
    pub deadline_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSteeringRequest {
    pub request: SteeringRequest,
    pub mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSteeringAckRequest {
    pub run_id: String,
    pub assignment_id: String,
    pub action_id: String,
    pub mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSteeringSweepRequest {
    pub run_id: String,
    pub mac: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringOutcome {
    Pending,
    Delivered,
    Acknowledged,
    Refused,
    TimedOut,
    LostChild,
}

impl SteeringOutcome {
    pub const fn is_steered(self) -> bool {
        matches!(self, Self::Acknowledged)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringRefusal {
    Unauthenticated,
    IllTyped,
    InsufficientAuthority,
    WeakModelCannotSteerCoordinator,
    UnknownTarget,
    MergeBypass,
    DuplicateAction,
    DeadlineExpired,
}

impl SteeringRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::IllTyped => "ill_typed",
            Self::InsufficientAuthority => "insufficient_authority",
            Self::WeakModelCannotSteerCoordinator => "weak_model_cannot_steer_coordinator",
            Self::UnknownTarget => "unknown_target",
            Self::MergeBypass => "merge_bypass",
            Self::DuplicateAction => "duplicate_action",
            Self::DeadlineExpired => "deadline_expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteeringAck {
    pub action_id: String,
    pub run_id: String,
    pub assignment_id: String,
    pub outcome: SteeringOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<SteeringRefusal>,
    pub steered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SteeringDecision {
    Accepted(SteeringAck),
    Refused(SteeringAck),
}

impl SteeringDecision {
    pub fn ack(&self) -> &SteeringAck {
        match self {
            Self::Accepted(ack) | Self::Refused(ack) => ack,
        }
    }

    pub fn refused(&self) -> Option<SteeringRefusal> {
        match self {
            Self::Refused(ack) => ack.refusal,
            Self::Accepted(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteeringDirective {
    pub action_id: String,
    pub action: SteeringAction,
    pub actor_id: String,
    pub deadline_unix_ms: u64,
    pub outcome: SteeringOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteeringEvidenceRecord {
    pub sequence: u64,
    pub action_id: String,
    pub assignment_id: String,
    pub event: String,
    pub outcome: SteeringOutcome,
    pub steered: bool,
    pub actor_id: String,
    pub action: String,
    pub recorded_at_unix_ms: u64,
}

pub(crate) fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} is not a bounded canonical identifier");
    }
    Ok(())
}

pub(crate) fn validate_message(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_MESSAGE_BYTES || value.contains('\0') {
        bail!("{field} exceeds its bound or is empty");
    }
    Ok(())
}

pub(crate) fn validate_request_shape(request: &SteeringRequest) -> Result<()> {
    if request.version != STEERING_REQUEST_VERSION {
        bail!("steering request version is unsupported");
    }
    validate_identifier("action id", &request.action_id)?;
    validate_identifier("run id", &request.run_id)?;
    validate_identifier("assignment id", &request.assignment_id)?;
    validate_identifier("actor id", request.actor.agent_id())?;
    match &request.action {
        SteeringAction::InjectCorrectiveInput { message }
        | SteeringAction::CancelAssignment { reason: message } => {
            validate_message("steering message", message)?;
        }
        SteeringAction::Pause | SteeringAction::Resume => {}
        SteeringAction::NarrowScope { allowed_paths } => {
            if allowed_paths.is_empty() || allowed_paths.len() > MAX_PATHS {
                bail!("narrowed scope must contain between 1 and {MAX_PATHS} paths");
            }
            for path in allowed_paths {
                if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
                    bail!("narrowed scope path exceeds its bound");
                }
            }
        }
        SteeringAction::HitlDecision {
            tool_call_id,
            decision,
            replacement,
        } => {
            validate_identifier("tool call id", tool_call_id)?;
            match (decision, replacement) {
                (HitlDecisionKind::Edit, None) => {
                    bail!("HITL edit requires a replacement payload");
                }
                (HitlDecisionKind::Edit, Some(replacement)) => {
                    validate_message("HITL replacement", replacement)?;
                }
                (HitlDecisionKind::Approve | HitlDecisionKind::Reject, Some(_)) => {
                    bail!("HITL approve/reject must not carry a replacement payload");
                }
                (HitlDecisionKind::Approve | HitlDecisionKind::Reject, None) => {}
            }
        }
    }
    Ok(())
}

pub(crate) fn refused_ack(request: &SteeringRequest, refusal: SteeringRefusal) -> SteeringDecision {
    SteeringDecision::Refused(SteeringAck {
        action_id: request.action_id.clone(),
        run_id: request.run_id.clone(),
        assignment_id: request.assignment_id.clone(),
        outcome: SteeringOutcome::Refused,
        refusal: Some(refusal),
        steered: false,
    })
}

pub(crate) fn accepted_ack(
    request: &SteeringRequest,
    outcome: SteeringOutcome,
) -> SteeringDecision {
    SteeringDecision::Accepted(SteeringAck {
        action_id: request.action_id.clone(),
        run_id: request.run_id.clone(),
        assignment_id: request.assignment_id.clone(),
        outcome,
        refusal: None,
        steered: outcome.is_steered(),
    })
}
