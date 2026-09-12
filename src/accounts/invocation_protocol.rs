//! Closed, account-bound proposal invocation. Metadata cannot authorize this lane.

use super::{
    protocol::{
        required_option, valid_alias, valid_identifier, valid_observation_id, ModelEffort,
        Provider, Runtime,
    },
    AccountClient, AccountError,
};
use crate::llm::{provider::CommandPurpose, ProposedCommand, ProposedPatch, WorkProposal};
use serde::{Deserialize, Serialize};

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

vocabulary!(InvocationState {
    Prepared,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
    Unknown
});
vocabulary!(InvocationEffect {
    NotDispatched,
    PossiblyDispatched,
    TerminalObserved
});
vocabulary!(InvocationFailure {
    AccountUnavailable,
    AuthenticationRequired,
    BindingStale,
    UnsafeConfiguration,
    ProviderUnavailable,
    RateLimited,
    Protocol,
    ModelMismatch,
    InvalidProposal,
    LimitExceeded,
    Timeout,
    Cancelled,
    ProviderFailure,
    BrokerRestarted,
    TransportLost
});
vocabulary!(InvocationRefusal {
    AccountUnavailable,
    IdentityUnverified,
    ModelNotApproved,
    EffortNotApproved,
    Busy,
    NonceConflict,
    UnknownAttempt,
    AttemptMismatch,
    UnsafeState,
    LimitExceeded
});
vocabulary!(InvocationUsageState {
    Unknown,
    Partial,
    Final
});
vocabulary!(InvocationUsageSource {
    CodexThreadTokenUsage
});

pub const WARMUP_PROMPT: &str =
    "Return exactly {\"summary\":\"\",\"commands\":[],\"patches\":[],\"notes\":[]}.";

// No Debug: a redacted task is still private task content, not an operational log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum InvocationInput {
    WorkProposal { prompt: String },
    QuotaWarmup {},
}

impl InvocationInput {
    fn kind(&self) -> &'static str {
        match self {
            Self::WorkProposal { .. } => "work_proposal",
            Self::QuotaWarmup {} => "quota_warmup",
        }
    }

    pub fn prompt(&self) -> &str {
        match self {
            Self::WorkProposal { prompt } => prompt,
            Self::QuotaWarmup {} => WARMUP_PROMPT,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    pub alias: String,
    pub selection_revision: u64,
    pub model: String,
    pub reasoning_effort: ModelEffort,
    pub policy_digest: String,
    pub input: InvocationInput,
}

impl InvocationRequest {
    pub fn validate(&self) -> Result<(), AccountError> {
        if !valid_alias(&self.alias)
            || self.selection_revision == 0
            || !valid_identifier(&self.model)
            || !valid_digest(&self.policy_digest)
            || self.input.prompt().is_empty()
        {
            return Err(AccountError::InvalidInput);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AccountError> {
        self.validate()?;
        fn text(bytes: &mut Vec<u8>, value: &str) -> Result<(), AccountError> {
            bytes.extend_from_slice(
                &u64::try_from(value.len())
                    .map_err(|_| AccountError::InvalidInput)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(value.as_bytes());
            Ok(())
        }
        let mut bytes = b"maco-broker-invocation-v1\0".to_vec();
        text(&mut bytes, &self.alias)?;
        bytes.extend_from_slice(&self.selection_revision.to_be_bytes());
        text(&mut bytes, &self.model)?;
        text(&mut bytes, effort_name(self.reasoning_effort))?;
        for pair in self.policy_digest.as_bytes()[7..].chunks_exact(2) {
            let value = std::str::from_utf8(pair).map_err(|_| AccountError::InvalidInput)?;
            bytes.push(u8::from_str_radix(value, 16).map_err(|_| AccountError::InvalidInput)?);
        }
        text(&mut bytes, self.input.kind())?;
        text(&mut bytes, self.input.prompt())?;
        Ok(digest(&bytes))
    }

    pub fn matches_binding(&self, binding: &InvocationBinding) -> Result<(), AccountError> {
        if binding.alias != self.alias
            || binding.selection_revision != self.selection_revision
            || binding.model != self.model
            || binding.reasoning_effort != self.reasoning_effort
            || binding.policy_digest != self.policy_digest
            || binding.prompt_digest != digest(self.input.prompt().as_bytes())
            || binding.request_digest != self.digest()?
        {
            return Err(AccountError::Protocol);
        }
        Ok(())
    }
}

pub fn effort_name(effort: ModelEffort) -> &'static str {
    match effort {
        ModelEffort::None => "none",
        ModelEffort::Minimal => "minimal",
        ModelEffort::Low => "low",
        ModelEffort::Medium => "medium",
        ModelEffort::High => "high",
        ModelEffort::Xhigh => "xhigh",
        ModelEffort::Max => "max",
        ModelEffort::Ultra => "ultra",
    }
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::artifacts::state_auth::sha256_hex(bytes))
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBinding {
    pub alias: String,
    pub provider: Provider,
    pub runtime: Runtime,
    /// Opaque account attribution, not a provider billing/quota-sharing claim.
    pub account_pool_id: String,
    pub credential_generation: String,
    pub selection_revision: u64,
    pub model: String,
    pub reasoning_effort: ModelEffort,
    pub policy_digest: String,
    pub prompt_digest: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationTokens {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationUsageSnapshot {
    pub source: InvocationUsageSource,
    pub total: InvocationTokens,
    pub last: InvocationTokens,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationUsage {
    pub state: InvocationUsageState,
    #[serde(deserialize_with = "required_option")]
    pub snapshot: Option<InvocationUsageSnapshot>,
}

impl InvocationUsage {
    pub fn unknown() -> Self {
        Self {
            state: InvocationUsageState::Unknown,
            snapshot: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationProposal {
    pub summary: String,
    pub commands: Vec<InvocationCommand>,
    pub patches: Vec<InvocationPatch>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCommand {
    pub command: String,
    #[serde(deserialize_with = "required_option")]
    pub working_directory: Option<String>,
    pub purpose: CommandPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationPatch {
    pub path: String,
    pub unified_diff: String,
}

impl From<InvocationProposal> for WorkProposal {
    fn from(value: InvocationProposal) -> Self {
        Self {
            summary: value.summary,
            notes: value.notes,
            commands: value
                .commands
                .into_iter()
                .map(|c| ProposedCommand {
                    command: c.command,
                    working_directory: c.working_directory.map(Into::into),
                    purpose: c.purpose,
                })
                .collect(),
            patches: value
                .patches
                .into_iter()
                .map(|p| ProposedPatch {
                    path: p.path.into(),
                    unified_diff: p.unified_diff,
                })
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationAttempt {
    pub attempt_id: String,
    pub request_nonce: String,
    pub binding: InvocationBinding,
    pub state: InvocationState,
    pub effect: InvocationEffect,
    pub prepared_at: u64,
    #[serde(deserialize_with = "required_option")]
    pub started_at: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub broker_deadline: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub finished_at: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub proposal: Option<InvocationProposal>,
    pub usage: InvocationUsage,
    #[serde(deserialize_with = "required_option")]
    pub failure: Option<InvocationFailure>,
}

impl InvocationState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Unknown
        )
    }
}

impl InvocationAttempt {
    pub fn validate(&self) -> Result<(), AccountError> {
        use InvocationEffect::{NotDispatched, PossiblyDispatched, TerminalObserved};
        use InvocationState::*;
        let binding = &self.binding;
        let admitted = self.started_at.is_some() && self.broker_deadline.is_some();
        let usage_valid = (self.usage.state == InvocationUsageState::Unknown)
            == self.usage.snapshot.is_none()
            && (self.usage.state != InvocationUsageState::Final || self.effect == TerminalObserved)
            && (self.effect != NotDispatched || self.usage.state == InvocationUsageState::Unknown);
        let state_valid = match self.state {
            Prepared => self.effect == NotDispatched && !admitted && self.started_at.is_none(),
            Running => admitted && matches!(self.effect, NotDispatched | PossiblyDispatched),
            Cancelling => admitted && self.effect == PossiblyDispatched,
            Completed => admitted && self.effect == TerminalObserved && self.proposal.is_some(),
            Failed => {
                matches!(self.effect, NotDispatched | TerminalObserved)
                    && (self.effect != TerminalObserved || admitted)
            }
            Cancelled => self.effect == NotDispatched,
            Unknown => admitted && self.effect == PossiblyDispatched,
        };
        let failure_valid = if matches!(self.state, Failed | Unknown) {
            self.failure.is_some()
        } else {
            self.failure.is_none()
        };
        if !valid_observation_id(&self.attempt_id)
            || !valid_observation_id(&self.request_nonce)
            || !valid_observation_id(&binding.account_pool_id)
            || !valid_observation_id(&binding.credential_generation)
            || !valid_alias(&binding.alias)
            || !valid_identifier(&binding.model)
            || binding.selection_revision == 0
            || !valid_digest(&binding.policy_digest)
            || !valid_digest(&binding.prompt_digest)
            || !valid_digest(&binding.request_digest)
            || self.started_at.is_some() != self.broker_deadline.is_some()
            || self
                .started_at
                .is_some_and(|start| start < self.prepared_at)
            || self
                .started_at
                .zip(self.broker_deadline)
                .is_some_and(|(start, deadline)| deadline <= start)
            || self
                .finished_at
                .is_some_and(|end| end < self.started_at.unwrap_or(self.prepared_at))
            || self.state.is_terminal() != self.finished_at.is_some()
            || (self.state == Completed) != self.proposal.is_some()
            || !usage_valid
            || !state_valid
            || !failure_valid
        {
            return Err(AccountError::Protocol);
        }
        Ok(())
    }

    /// A handle never permits rebinding, state rollback or changing a committed outcome.
    pub fn follows(&self, previous: &Self) -> Result<(), AccountError> {
        self.validate()?;
        if self.attempt_id != previous.attempt_id
            || self.request_nonce != previous.request_nonce
            || self.binding != previous.binding
            || self.prepared_at != previous.prepared_at
            || (previous.state.is_terminal() && self != previous)
            || (previous.started_at.is_some()
                && (self.started_at != previous.started_at
                    || self.broker_deadline != previous.broker_deadline))
            || (previous.effect != InvocationEffect::NotDispatched
                && self.effect == InvocationEffect::NotDispatched)
            || (previous.state != InvocationState::Prepared
                && self.state == InvocationState::Prepared)
            || (previous.state == InvocationState::Cancelling
                && !matches!(
                    self.state,
                    InvocationState::Cancelling | InvocationState::Unknown
                ))
        {
            return Err(AccountError::Protocol);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "outcome", rename_all = "snake_case")]
pub enum InvocationResult {
    Attempt {
        schema_version: u32,
        attempt: Box<InvocationAttempt>,
    },
    Refused {
        schema_version: u32,
        reason: InvocationRefusal,
    },
}

impl AccountClient {
    pub fn invocation_prepare(
        &self,
        nonce: &str,
        request: &InvocationRequest,
    ) -> Result<InvocationResult, AccountError> {
        request.validate()?;
        if !valid_observation_id(nonce) {
            return Err(AccountError::InvalidInput);
        }
        #[derive(Serialize)]
        struct Arguments<'a> {
            schema_version: u32,
            request_nonce: &'a str,
            request: &'a InvocationRequest,
        }
        let result = self.request(
            "accounts.invocation.prepare",
            Arguments {
                schema_version: 1,
                request_nonce: nonce,
                request,
            },
        )?;
        checked_result(result, nonce, request, None)
    }

    pub fn invocation_start(
        &self,
        nonce: &str,
        request: &InvocationRequest,
        attempt_id: &str,
    ) -> Result<InvocationResult, AccountError> {
        self.invocation_control(
            "accounts.invocation.start",
            nonce,
            request,
            Some(attempt_id),
        )
    }

    pub fn invocation_status(
        &self,
        nonce: &str,
        request: &InvocationRequest,
        attempt_id: Option<&str>,
    ) -> Result<InvocationResult, AccountError> {
        self.invocation_control("accounts.invocation.status", nonce, request, attempt_id)
    }

    pub fn invocation_cancel(
        &self,
        nonce: &str,
        request: &InvocationRequest,
        attempt_id: &str,
    ) -> Result<InvocationResult, AccountError> {
        self.invocation_control(
            "accounts.invocation.cancel",
            nonce,
            request,
            Some(attempt_id),
        )
    }

    fn invocation_control(
        &self,
        capability: &'static str,
        nonce: &str,
        request: &InvocationRequest,
        attempt_id: Option<&str>,
    ) -> Result<InvocationResult, AccountError> {
        if !valid_observation_id(nonce) || attempt_id.is_some_and(|id| !valid_observation_id(id)) {
            return Err(AccountError::InvalidInput);
        }
        #[derive(Serialize)]
        struct Arguments<'a> {
            schema_version: u32,
            alias: &'a str,
            request_nonce: &'a str,
            attempt_id: Option<&'a str>,
            request_digest: String,
        }
        let result = self.request(
            capability,
            Arguments {
                schema_version: 1,
                alias: &request.alias,
                request_nonce: nonce,
                attempt_id,
                request_digest: request.digest()?,
            },
        )?;
        checked_result(result, nonce, request, attempt_id)
    }
}

fn checked_result(
    result: InvocationResult,
    nonce: &str,
    request: &InvocationRequest,
    attempt_id: Option<&str>,
) -> Result<InvocationResult, AccountError> {
    match &result {
        InvocationResult::Attempt {
            schema_version,
            attempt,
        } => {
            attempt.validate()?;
            request.matches_binding(&attempt.binding)?;
            if *schema_version != 1
                || attempt.request_nonce != nonce
                || attempt_id.is_some_and(|id| id != attempt.attempt_id)
            {
                return Err(AccountError::Protocol);
            }
            if matches!(request.input, InvocationInput::QuotaWarmup {})
                && attempt.proposal.as_ref().is_some_and(|proposal| {
                    !proposal.summary.is_empty()
                        || !proposal.commands.is_empty()
                        || !proposal.patches.is_empty()
                        || !proposal.notes.is_empty()
                })
            {
                return Err(AccountError::Protocol);
            }
        }
        InvocationResult::Refused { schema_version, .. } if *schema_version != 1 => {
            return Err(AccountError::Protocol)
        }
        InvocationResult::Refused { .. } => {}
    }
    Ok(result)
}
