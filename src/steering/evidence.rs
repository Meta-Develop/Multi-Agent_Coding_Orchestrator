use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            AuthenticationDomain, AuthenticationTag, BoundStateLock, RepositoryAuthenticator,
        },
    },
    state_journal::{AuthenticatedStateJournal, JournalSpec},
    steering::types::{
        AssignmentBinding, SteeringEvidenceRecord, SteeringOutcome, SteeringRefusal,
        SteeringRequest,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const STEERING_STATE_NAMESPACE: &str = "authenticated-steering-state-v1";
pub(crate) const STEERING_ROOT_LOCK: &str = ".authenticated-steering.lock";
pub(crate) const STEERING_OPERATION_LOCK: &str = "steering-operation-v1.lock";

const STEERING_RECORD_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0authenticated-steering-record\0v1\0");
const STEERING_HEAD_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0authenticated-steering-head\0v1\0");
pub(crate) const STEERING_REQUEST_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0authenticated-steering-request\0v1\0");
pub(crate) const STEERING_COMMAND_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0authenticated-steering-command\0v1\0");

pub(crate) enum SteeringJournalSpec {}

impl JournalSpec for SteeringJournalSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_steering";
    const ROOT_NAME: &'static str = STEERING_STATE_NAMESPACE;
    const ROOT_LOCK_NAME: &'static str = STEERING_ROOT_LOCK;
    const INSTANCE_LOCK_NAME: &'static str = ".steering-run.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain = STEERING_RECORD_DOMAIN;
    const HEAD_DOMAIN: AuthenticationDomain = STEERING_HEAD_DOMAIN;
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = 256 * 1024;
    const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 128;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SteeringEventPayload {
    pub version: u32,
    pub event: String,
    pub action_id: String,
    pub assignment_id: String,
    pub actor_id: String,
    pub action: String,
    pub outcome: SteeringOutcome,
    pub steered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<SteeringRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<SteeringRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<AssignmentBinding>,
    pub recorded_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionState {
    pub request: SteeringRequest,
    pub outcome: SteeringOutcome,
    pub steered: bool,
    pub refusal: Option<SteeringRefusal>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct RunSteeringState {
    pub bindings: BTreeMap<String, AssignmentBinding>,
    pub actions: BTreeMap<String, ActionState>,
    pub evidence: Vec<SteeringEvidenceRecord>,
}

impl RunSteeringState {
    pub(crate) fn apply(&mut self, sequence: u64, payload: SteeringEventPayload) -> Result<()> {
        if payload.version != 1 {
            bail!("steering journal payload version is unsupported");
        }
        if let Some(binding) = payload.binding.clone() {
            self.bindings.insert(binding.assignment_id.clone(), binding);
        }
        if let Some(request) = payload.request.clone() {
            self.actions.insert(
                request.action_id.clone(),
                ActionState {
                    request,
                    outcome: payload.outcome,
                    steered: payload.steered,
                    refusal: payload.refusal,
                },
            );
        } else if let Some(existing) = self.actions.get_mut(&payload.action_id) {
            existing.outcome = payload.outcome;
            existing.steered = payload.steered;
            existing.refusal = payload.refusal;
        }
        self.evidence.push(SteeringEvidenceRecord {
            sequence,
            action_id: payload.action_id,
            assignment_id: payload.assignment_id,
            event: payload.event,
            outcome: payload.outcome,
            steered: payload.steered,
            actor_id: payload.actor_id,
            action: payload.action,
            recorded_at_unix_ms: payload.recorded_at_unix_ms,
        });
        Ok(())
    }

    pub(crate) fn pending_for(&self, assignment_id: &str) -> Vec<&ActionState> {
        self.actions
            .values()
            .filter(|action| {
                action.request.assignment_id == assignment_id
                    && matches!(
                        action.outcome,
                        SteeringOutcome::Pending | SteeringOutcome::Delivered
                    )
            })
            .collect()
    }
}

pub(crate) fn ensure_namespace(repo: &Path) -> Result<RepositoryAuthenticator> {
    let writer = repository_auth_writer(repo)?;
    let authenticator = writer.into_authenticator()?;
    AuthenticatedStateJournal::<SteeringJournalSpec>::create_root(&authenticator)?;
    Ok(authenticator)
}

pub(crate) fn canonical_request_bytes(request: &SteeringRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(request).context("failed to encode canonical steering request")
}

pub(crate) fn sign_request(
    authenticator: &RepositoryAuthenticator,
    request: &SteeringRequest,
) -> Result<AuthenticationTag> {
    let bytes = canonical_request_bytes(request)?;
    authenticator.sign(STEERING_REQUEST_DOMAIN, &bytes)
}

pub(crate) fn verify_request_mac(
    authenticator: &RepositoryAuthenticator,
    request: &SteeringRequest,
    mac: &str,
) -> Result<()> {
    let tag = AuthenticationTag::parse(mac).context("steering MAC is malformed")?;
    let bytes = canonical_request_bytes(request)?;
    authenticator.verify_tag(STEERING_REQUEST_DOMAIN, &bytes, &tag)
}

#[derive(Serialize)]
struct CommandMacPayload<'a> {
    kind: &'a str,
    run_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_id: Option<&'a str>,
}

pub(crate) fn canonical_command_bytes(
    kind: &str,
    run_id: &str,
    assignment_id: Option<&str>,
    action_id: Option<&str>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&CommandMacPayload {
        kind,
        run_id,
        assignment_id,
        action_id,
    })
    .context("failed to encode canonical steering command")
}

pub(crate) fn sign_command(
    authenticator: &RepositoryAuthenticator,
    kind: &str,
    run_id: &str,
    assignment_id: Option<&str>,
    action_id: Option<&str>,
) -> Result<AuthenticationTag> {
    let bytes = canonical_command_bytes(kind, run_id, assignment_id, action_id)?;
    authenticator.sign(STEERING_COMMAND_DOMAIN, &bytes)
}

pub(crate) fn verify_command_mac(
    authenticator: &RepositoryAuthenticator,
    kind: &str,
    run_id: &str,
    assignment_id: Option<&str>,
    action_id: Option<&str>,
    mac: &str,
) -> Result<()> {
    let tag = AuthenticationTag::parse(mac).context("steering command MAC is malformed")?;
    let bytes = canonical_command_bytes(kind, run_id, assignment_id, action_id)?;
    authenticator.verify_tag(STEERING_COMMAND_DOMAIN, &bytes, &tag)
}

pub(crate) fn with_run_journal<T>(
    repo: &Path,
    run_id: &str,
    body: impl FnOnce(&mut AuthenticatedStateJournal<SteeringJournalSpec>) -> Result<T>,
) -> Result<T> {
    let authenticator = ensure_namespace(repo)?;
    let state_root = authenticator.state_root().clone();
    let operation_lock = BoundStateLock::acquire(&state_root, STEERING_OPERATION_LOCK)?;
    let result = (|| {
        let mut journal = AuthenticatedStateJournal::<SteeringJournalSpec>::open_or_initialize(
            authenticator,
            run_id,
        )?;
        body(&mut journal)
    })();
    finish_operation(result, operation_lock.verify(&state_root))
}

pub(crate) fn load_run_state(repo: &Path, run_id: &str) -> Result<RunSteeringState> {
    let authenticator = match repository_authenticator_key_only(repo) {
        Ok(authenticator) => authenticator,
        Err(_) => return Ok(RunSteeringState::default()),
    };
    match AuthenticatedStateJournal::<SteeringJournalSpec>::existing_root(&authenticator) {
        Ok(root) => {
            if !root.direct_child_exists(run_id)? {
                return Ok(RunSteeringState::default());
            }
        }
        Err(_) => return Ok(RunSteeringState::default()),
    }
    with_run_journal(repo, run_id, |journal| reconstruct(journal))
}

pub(crate) fn reconstruct(
    journal: &AuthenticatedStateJournal<SteeringJournalSpec>,
) -> Result<RunSteeringState> {
    let mut state = RunSteeringState::default();
    for record in journal.records() {
        let payload: SteeringEventPayload = serde_json::from_value(record.payload.clone())
            .context("steering journal payload is ill-typed")?;
        state.apply(record.sequence, payload)?;
    }
    Ok(state)
}

pub(crate) fn append_event(
    journal: &mut AuthenticatedStateJournal<SteeringJournalSpec>,
    phase: &str,
    payload: &SteeringEventPayload,
) -> Result<()> {
    journal
        .append(phase, Some(payload.assignment_id.as_str()), payload)
        .map(|_| ())
        .context("failed to append authenticated steering evidence")
}

pub(crate) fn payload_for_request(
    event: &str,
    request: &SteeringRequest,
    outcome: SteeringOutcome,
    refusal: Option<SteeringRefusal>,
    binding: Option<AssignmentBinding>,
    recorded_at_unix_ms: u64,
) -> SteeringEventPayload {
    SteeringEventPayload {
        version: 1,
        event: event.to_string(),
        action_id: request.action_id.clone(),
        assignment_id: request.assignment_id.clone(),
        actor_id: request.actor.agent_id().to_string(),
        action: request.action.name().to_string(),
        outcome,
        steered: outcome.is_steered(),
        refusal,
        request: Some(request.clone()),
        binding,
        recorded_at_unix_ms,
    }
}

pub(crate) fn payload_for_action(
    event: &str,
    request: &SteeringRequest,
    outcome: SteeringOutcome,
    refusal: Option<SteeringRefusal>,
    recorded_at_unix_ms: u64,
) -> SteeringEventPayload {
    SteeringEventPayload {
        version: 1,
        event: event.to_string(),
        action_id: request.action_id.clone(),
        assignment_id: request.assignment_id.clone(),
        actor_id: request.actor.agent_id().to_string(),
        action: request.action.name().to_string(),
        outcome,
        steered: outcome.is_steered(),
        refusal,
        request: None,
        binding: None,
        recorded_at_unix_ms,
    }
}

fn finish_operation<T>(result: Result<T>, verification: Result<()>) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "steering operation also lost its stable lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
pub(crate) fn checkpoint_namespace_untouched(repo: &Path) -> Result<bool> {
    let authenticator = repository_authenticator_key_only(repo)?;
    let state_root = authenticator.state_root();
    Ok(!state_root.direct_child_exists("orchestration-checkpoints-v3")?)
}
