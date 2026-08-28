use crate::{
    agent_lifecycle::{AgentIdentityLiveness, AgentRegistry},
    artifacts::repository_authenticator_key_only,
    process_runner::ProcessCancellation,
    steering::{
        authority::authorize,
        evidence::{
            append_event, ensure_namespace, load_run_state, payload_for_action,
            payload_for_request, sign_command, sign_request, verify_command_mac,
            verify_request_mac, with_run_journal,
        },
        types::{
            accepted_ack, refused_ack, validate_identifier, validate_request_shape,
            AssignmentBinding, AssignmentKind, SignedSteeringAckRequest, SignedSteeringRequest,
            SignedSteeringSweepRequest, SteeringAck, SteeringAction, SteeringDecision,
            SteeringDirective, SteeringEvidenceRecord, SteeringOutcome, SteeringRefusal,
            SteeringRequest, MAX_STEERING_DEADLINE_MS,
        },
    },
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LiveKey {
    run_id: String,
    assignment_id: String,
}

#[derive(Clone)]
struct LiveSlot {
    binding: AssignmentBinding,
    cancellation: Option<ProcessCancellation>,
}

/// Authenticated steering control plane for one repository.
#[derive(Clone)]
pub struct SteeringPlane {
    repo: PathBuf,
    live: Arc<Mutex<BTreeMap<LiveKey, LiveSlot>>>,
}

impl SteeringPlane {
    pub fn open(repo: impl AsRef<Path>) -> Result<Self> {
        let repo = crate::git_repository::discover(repo.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo.as_ref().display()
            )
        })?;
        let repo = repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf();
        ensure_namespace(&repo)?;
        Ok(Self {
            repo,
            live: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn current_unix_ms(&self) -> Result<u64> {
        current_unix_ms()
    }

    pub fn register_assignment(&self, binding: AssignmentBinding) -> Result<()> {
        validate_identifier("run id", &binding.run_id)?;
        validate_identifier("assignment id", &binding.assignment_id)?;
        if let Some(parent) = &binding.parent_agent_id {
            validate_identifier("parent agent id", parent)?;
        }
        let recorded_at = current_unix_ms()?;
        with_run_journal(&self.repo, &binding.run_id, |journal| {
            let payload = crate::steering::evidence::SteeringEventPayload {
                version: 1,
                event: "bind".to_string(),
                action_id: format!("bind-{}", binding.assignment_id),
                assignment_id: binding.assignment_id.clone(),
                actor_id: "control_plane".to_string(),
                action: "bind".to_string(),
                outcome: SteeringOutcome::Pending,
                steered: false,
                refusal: None,
                request: None,
                binding: Some(binding.clone()),
                recorded_at_unix_ms: recorded_at,
            };
            append_event(journal, "bind", &payload)
        })?;
        self.upsert_live(LiveSlot {
            binding,
            cancellation: None,
        })?;
        Ok(())
    }

    pub fn register_live_cancellation(
        &self,
        run_id: &str,
        assignment_id: &str,
        cancellation: ProcessCancellation,
    ) -> Result<()> {
        let mut live = self.live_map()?;
        let key = LiveKey {
            run_id: run_id.to_string(),
            assignment_id: assignment_id.to_string(),
        };
        let slot = live
            .get_mut(&key)
            .ok_or_else(|| anyhow::anyhow!("steering assignment is not registered"))?;
        slot.cancellation = Some(cancellation);
        Ok(())
    }

    pub fn sign(&self, request: &SteeringRequest) -> Result<SignedSteeringRequest> {
        validate_request_shape(request)?;
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        let mac = sign_request(&authenticator, request)?;
        Ok(SignedSteeringRequest {
            request: request.clone(),
            mac: mac.as_str().to_string(),
        })
    }

    pub fn submit_signed(
        &self,
        signed: SignedSteeringRequest,
        now_unix_ms: u64,
    ) -> Result<SteeringDecision> {
        if validate_request_shape(&signed.request).is_err() {
            return Ok(refused_ack(&signed.request, SteeringRefusal::IllTyped));
        }
        match self.verify_request_mac_only(&signed) {
            Ok(()) => {}
            Err(_) => {
                return Ok(refused_ack(
                    &signed.request,
                    SteeringRefusal::Unauthenticated,
                ));
            }
        }
        self.submit_verified(signed.request, now_unix_ms)
    }

    pub fn sign_ack(
        &self,
        run_id: &str,
        assignment_id: &str,
        action_id: &str,
    ) -> Result<SignedSteeringAckRequest> {
        validate_identifier("run id", run_id)?;
        validate_identifier("assignment id", assignment_id)?;
        validate_identifier("action id", action_id)?;
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        let mac = sign_command(
            &authenticator,
            "ack",
            run_id,
            Some(assignment_id),
            Some(action_id),
        )?;
        Ok(SignedSteeringAckRequest {
            run_id: run_id.to_string(),
            assignment_id: assignment_id.to_string(),
            action_id: action_id.to_string(),
            mac: mac.as_str().to_string(),
        })
    }

    pub fn acknowledge_signed(
        &self,
        signed: SignedSteeringAckRequest,
        now_unix_ms: u64,
    ) -> Result<SteeringAck> {
        self.verify_ack_mac(&signed)?;
        self.acknowledge(
            &signed.run_id,
            &signed.assignment_id,
            &signed.action_id,
            now_unix_ms,
        )
    }

    pub fn sign_sweep(&self, run_id: &str) -> Result<SignedSteeringSweepRequest> {
        validate_identifier("run id", run_id)?;
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        let mac = sign_command(&authenticator, "sweep", run_id, None, None)?;
        Ok(SignedSteeringSweepRequest {
            run_id: run_id.to_string(),
            mac: mac.as_str().to_string(),
        })
    }

    pub fn sweep_signed(
        &self,
        signed: SignedSteeringSweepRequest,
        now_unix_ms: u64,
    ) -> Result<Vec<SteeringAck>> {
        self.verify_sweep_mac(&signed)?;
        self.sweep(&signed.run_id, now_unix_ms)
    }

    pub fn submit(&self, request: SteeringRequest, now_unix_ms: u64) -> Result<SteeringDecision> {
        let signed = match self.sign(&request) {
            Ok(signed) => signed,
            Err(_) => return Ok(refused_ack(&request, SteeringRefusal::IllTyped)),
        };
        self.submit_signed(signed, now_unix_ms)
    }

    pub fn inbox(&self, run_id: &str, assignment_id: &str) -> Result<Vec<SteeringDirective>> {
        validate_identifier("run id", run_id)?;
        validate_identifier("assignment id", assignment_id)?;
        let state = load_run_state(&self.repo, run_id)?;
        Ok(state
            .pending_for(assignment_id)
            .into_iter()
            .map(|action| SteeringDirective {
                action_id: action.request.action_id.clone(),
                action: action.request.action.clone(),
                actor_id: action.request.actor.agent_id().to_string(),
                deadline_unix_ms: action.request.deadline_unix_ms,
                outcome: action.outcome,
            })
            .collect())
    }

    pub fn acknowledge(
        &self,
        run_id: &str,
        assignment_id: &str,
        action_id: &str,
        now_unix_ms: u64,
    ) -> Result<SteeringAck> {
        validate_identifier("run id", run_id)?;
        validate_identifier("assignment id", assignment_id)?;
        validate_identifier("action id", action_id)?;
        with_run_journal(&self.repo, run_id, |journal| {
            let state = crate::steering::evidence::reconstruct(journal)?;
            let Some(existing) = state.actions.get(action_id).cloned() else {
                bail!("steering action {action_id} is not in run {run_id}");
            };
            if existing.request.assignment_id != assignment_id {
                bail!("steering action {action_id} does not belong to assignment {assignment_id}");
            }
            if existing.outcome.is_steered() {
                return Ok(accepted_ack(&existing.request, existing.outcome)
                    .ack()
                    .clone());
            }
            if matches!(
                existing.outcome,
                SteeringOutcome::TimedOut | SteeringOutcome::LostChild | SteeringOutcome::Refused
            ) {
                return Ok(SteeringAck {
                    action_id: existing.request.action_id,
                    run_id: existing.request.run_id,
                    assignment_id: existing.request.assignment_id,
                    outcome: existing.outcome,
                    refusal: existing.refusal,
                    steered: false,
                });
            }
            if now_unix_ms > existing.request.deadline_unix_ms {
                append_event(
                    journal,
                    "timeout",
                    &payload_for_action(
                        "timeout",
                        &existing.request,
                        SteeringOutcome::TimedOut,
                        None,
                        now_unix_ms,
                    ),
                )?;
                return Ok(SteeringAck {
                    action_id: action_id.to_string(),
                    run_id: run_id.to_string(),
                    assignment_id: assignment_id.to_string(),
                    outcome: SteeringOutcome::TimedOut,
                    refusal: None,
                    steered: false,
                });
            }
            append_event(
                journal,
                "ack",
                &payload_for_action(
                    "ack",
                    &existing.request,
                    SteeringOutcome::Acknowledged,
                    None,
                    now_unix_ms,
                ),
            )?;
            Ok(
                accepted_ack(&existing.request, SteeringOutcome::Acknowledged)
                    .ack()
                    .clone(),
            )
        })
    }

    pub fn sweep(&self, run_id: &str, now_unix_ms: u64) -> Result<Vec<SteeringAck>> {
        validate_identifier("run id", run_id)?;
        with_run_journal(&self.repo, run_id, |journal| {
            let state = crate::steering::evidence::reconstruct(journal)?;
            let mut reports = Vec::new();
            for action in state.actions.values() {
                if !matches!(
                    action.outcome,
                    SteeringOutcome::Pending | SteeringOutcome::Delivered
                ) {
                    continue;
                }
                let lost = self.assignment_lost(run_id, &action.request.assignment_id)?;
                let timed_out = now_unix_ms > action.request.deadline_unix_ms;
                if !lost && !timed_out {
                    continue;
                }
                let (phase, outcome) = if lost {
                    ("lost_child", SteeringOutcome::LostChild)
                } else {
                    ("timeout", SteeringOutcome::TimedOut)
                };
                append_event(
                    journal,
                    phase,
                    &payload_for_action(phase, &action.request, outcome, None, now_unix_ms),
                )?;
                reports.push(SteeringAck {
                    action_id: action.request.action_id.clone(),
                    run_id: action.request.run_id.clone(),
                    assignment_id: action.request.assignment_id.clone(),
                    outcome,
                    refusal: None,
                    steered: false,
                });
            }
            Ok(reports)
        })
    }

    pub fn evidence(&self, run_id: &str) -> Result<Vec<SteeringEvidenceRecord>> {
        validate_identifier("run id", run_id)?;
        Ok(load_run_state(&self.repo, run_id)?.evidence)
    }

    fn verify_request_mac_only(&self, signed: &SignedSteeringRequest) -> Result<()> {
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        verify_request_mac(&authenticator, &signed.request, &signed.mac)
    }

    pub(crate) fn verify_ack_mac(&self, signed: &SignedSteeringAckRequest) -> Result<()> {
        validate_identifier("run id", &signed.run_id)?;
        validate_identifier("assignment id", &signed.assignment_id)?;
        validate_identifier("action id", &signed.action_id)?;
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        verify_command_mac(
            &authenticator,
            "ack",
            &signed.run_id,
            Some(&signed.assignment_id),
            Some(&signed.action_id),
            &signed.mac,
        )
    }

    pub(crate) fn verify_sweep_mac(&self, signed: &SignedSteeringSweepRequest) -> Result<()> {
        validate_identifier("run id", &signed.run_id)?;
        let authenticator = repository_authenticator_key_only(&self.repo)?;
        verify_command_mac(
            &authenticator,
            "sweep",
            &signed.run_id,
            None,
            None,
            &signed.mac,
        )
    }

    fn submit_verified(
        &self,
        request: SteeringRequest,
        now_unix_ms: u64,
    ) -> Result<SteeringDecision> {
        if validate_request_shape(&request).is_err() {
            return Ok(refused_ack(&request, SteeringRefusal::IllTyped));
        }
        if now_unix_ms > request.deadline_unix_ms {
            return Ok(refused_ack(&request, SteeringRefusal::DeadlineExpired));
        }
        if request.deadline_unix_ms.saturating_sub(now_unix_ms) > MAX_STEERING_DEADLINE_MS {
            return Ok(refused_ack(&request, SteeringRefusal::IllTyped));
        }

        let Some(binding) = self.resolve_binding(&request)? else {
            return self.record_refusal(&request, SteeringRefusal::UnknownTarget, now_unix_ms);
        };
        if let Err(refusal) = authorize(&request, &binding) {
            return self.record_refusal(&request, refusal, now_unix_ms);
        }

        with_run_journal(&self.repo, &request.run_id, |journal| {
            let state = crate::steering::evidence::reconstruct(journal)?;
            if let Some(existing) = state.actions.get(&request.action_id) {
                if existing.request != request {
                    return Ok(refused_ack(&request, SteeringRefusal::DuplicateAction));
                }
                return Ok(match existing.refusal {
                    Some(refusal) => refused_ack(&request, refusal),
                    None => accepted_ack(&request, existing.outcome),
                });
            }

            append_event(
                journal,
                "submit",
                &payload_for_request(
                    "submit",
                    &request,
                    SteeringOutcome::Pending,
                    None,
                    None,
                    now_unix_ms,
                ),
            )?;

            let delivery = self.deliver_locked(&request)?;
            match delivery {
                DeliveryResult::LostChild => {
                    append_event(
                        journal,
                        "lost_child",
                        &payload_for_request(
                            "lost_child",
                            &request,
                            SteeringOutcome::LostChild,
                            None,
                            None,
                            now_unix_ms,
                        ),
                    )?;
                    Ok(accepted_ack(&request, SteeringOutcome::LostChild))
                }
                DeliveryResult::CancelledAndAcked => {
                    append_event(
                        journal,
                        "deliver",
                        &payload_for_request(
                            "deliver",
                            &request,
                            SteeringOutcome::Delivered,
                            None,
                            None,
                            now_unix_ms,
                        ),
                    )?;
                    append_event(
                        journal,
                        "ack",
                        &payload_for_request(
                            "ack",
                            &request,
                            SteeringOutcome::Acknowledged,
                            None,
                            None,
                            now_unix_ms,
                        ),
                    )?;
                    Ok(accepted_ack(&request, SteeringOutcome::Acknowledged))
                }
                DeliveryResult::Mailbox => {
                    append_event(
                        journal,
                        "deliver",
                        &payload_for_request(
                            "deliver",
                            &request,
                            SteeringOutcome::Delivered,
                            None,
                            None,
                            now_unix_ms,
                        ),
                    )?;
                    Ok(accepted_ack(&request, SteeringOutcome::Delivered))
                }
            }
        })
    }

    fn record_refusal(
        &self,
        request: &SteeringRequest,
        refusal: SteeringRefusal,
        now_unix_ms: u64,
    ) -> Result<SteeringDecision> {
        with_run_journal(&self.repo, &request.run_id, |journal| {
            append_event(
                journal,
                "refuse",
                &payload_for_request(
                    "refuse",
                    request,
                    SteeringOutcome::Refused,
                    Some(refusal),
                    None,
                    now_unix_ms,
                ),
            )?;
            Ok(refused_ack(request, refusal))
        })
    }

    fn resolve_binding(&self, request: &SteeringRequest) -> Result<Option<AssignmentBinding>> {
        if let Some(slot) = self.live_map()?.get(&LiveKey {
            run_id: request.run_id.clone(),
            assignment_id: request.assignment_id.clone(),
        }) {
            return Ok(Some(slot.binding.clone()));
        }
        let state = load_run_state(&self.repo, &request.run_id)?;
        if let Some(binding) = state.bindings.get(&request.assignment_id) {
            return Ok(Some(binding.clone()));
        }
        if let Some(binding) = binding_from_registry(&self.repo, request)? {
            return Ok(Some(binding));
        }
        Ok(None)
    }

    fn deliver_locked(&self, request: &SteeringRequest) -> Result<DeliveryResult> {
        if matches!(request.action, SteeringAction::CancelAssignment { .. }) {
            if let Some(cancellation) =
                self.live_cancellation(&request.run_id, &request.assignment_id)?
            {
                cancellation.cancel();
                return Ok(DeliveryResult::CancelledAndAcked);
            }
            // Inspect before AgentRegistry::list, which prunes stale children and
            // would otherwise turn a lost child into a mailbox ack.
            if self.assignment_lost(&request.run_id, &request.assignment_id)? {
                return Ok(DeliveryResult::LostChild);
            }
            match stop_launched_child(&self.repo, &request.run_id, &request.assignment_id) {
                Ok(StopResult::Terminated) => return Ok(DeliveryResult::CancelledAndAcked),
                Ok(StopResult::AlreadyGone) => return Ok(DeliveryResult::LostChild),
                Ok(StopResult::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(DeliveryResult::Mailbox)
    }

    fn live_cancellation(
        &self,
        run_id: &str,
        assignment_id: &str,
    ) -> Result<Option<ProcessCancellation>> {
        let live = self.live_map()?;
        Ok(live
            .get(&LiveKey {
                run_id: run_id.to_string(),
                assignment_id: assignment_id.to_string(),
            })
            .and_then(|slot| slot.cancellation.clone()))
    }

    fn assignment_lost(&self, run_id: &str, assignment_id: &str) -> Result<bool> {
        if self.live_cancellation(run_id, assignment_id)?.is_some() {
            return Ok(false);
        }
        let registry = AgentRegistry::open(&self.repo)?;
        let inspections = registry.inspect()?;
        let matches = inspections
            .iter()
            .filter(|inspection| {
                inspection.process.run_id == run_id && inspection.process.task_id == assignment_id
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Ok(false);
        }
        Ok(matches
            .iter()
            .all(|inspection| matches!(inspection.identity, AgentIdentityLiveness::Stale)))
    }

    fn upsert_live(&self, slot: LiveSlot) -> Result<()> {
        let mut live = self.live_map()?;
        live.insert(
            LiveKey {
                run_id: slot.binding.run_id.clone(),
                assignment_id: slot.binding.assignment_id.clone(),
            },
            slot,
        );
        Ok(())
    }

    fn live_map(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<LiveKey, LiveSlot>>> {
        self.live
            .lock()
            .map_err(|_| anyhow::anyhow!("steering live-session lock is poisoned"))
    }
}

enum DeliveryResult {
    Mailbox,
    CancelledAndAcked,
    LostChild,
}

enum StopResult {
    Terminated,
    AlreadyGone,
    NotFound,
}

fn stop_launched_child(repo: &Path, run_id: &str, assignment_id: &str) -> Result<StopResult> {
    let registry = AgentRegistry::open(repo)?;
    let live = registry.list(&crate::agent_lifecycle::AgentListFilter {
        run_id: Some(run_id.to_string()),
    })?;
    let matches = live
        .into_iter()
        .filter(|process| process.task_id == assignment_id)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Ok(StopResult::NotFound);
    }
    if matches.len() > 1 {
        bail!(
            "steering cancel selector for assignment {assignment_id} is ambiguous ({} live processes)",
            matches.len()
        );
    }
    let report = registry.stop_selector(assignment_id, Duration::from_secs(1))?;
    if report.stopped.iter().any(|stopped| {
        matches!(
            stopped.outcome,
            crate::agent_lifecycle::AgentStopOutcome::Terminated
        )
    }) {
        return Ok(StopResult::Terminated);
    }
    Ok(StopResult::AlreadyGone)
}

fn binding_from_registry(
    repo: &Path,
    request: &SteeringRequest,
) -> Result<Option<AssignmentBinding>> {
    let registry = AgentRegistry::open(repo)?;
    let live = registry.list(&crate::agent_lifecycle::AgentListFilter {
        run_id: Some(request.run_id.clone()),
    })?;
    let Some(process) = live
        .into_iter()
        .find(|process| process.task_id == request.assignment_id)
    else {
        return Ok(None);
    };
    let authority = process.launch_authority()?;
    Ok(Some(AssignmentBinding {
        run_id: process.run_id,
        assignment_id: process.task_id,
        role_category: authority.category,
        model_capability: authority.model_capability,
        parent_agent_id: process.parent,
        kind: AssignmentKind::Execution,
    }))
}

pub(crate) fn current_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?;
    u64::try_from(duration.as_millis()).context("timestamp overflowed")
}
