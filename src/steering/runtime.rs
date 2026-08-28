use crate::{
    llm::{
        fake::FakeProvider,
        prompt::{Prompt, PromptSection},
        provider::{LlmProvider, LlmRequest, LlmResponse, ProviderError},
    },
    steering::{
        plane::SteeringPlane,
        types::{HitlDecisionKind, SteeringAction, SteeringOutcome},
    },
};
use anyhow::{bail, Result};

/// Provider-neutral prompt patch used when a corrective steering message is
/// applied to an in-flight Fake completion.
pub fn apply_inject_to_prompt(mut prompt: Prompt, message: &str) -> Prompt {
    prompt.sections.push(PromptSection {
        title: "steering_corrective_input".to_string(),
        body: message.to_string(),
    });
    prompt
}

/// In-process Fake session that consumes the steering mailbox before each turn.
pub struct SteerableFakeSession {
    plane: SteeringPlane,
    run_id: String,
    assignment_id: String,
    provider: FakeProvider,
    cancelled: bool,
    paused: bool,
    allowed_paths: Option<Vec<String>>,
    injected: Vec<String>,
    hitl: Vec<(String, HitlDecisionKind)>,
}

impl SteerableFakeSession {
    pub fn new(
        plane: SteeringPlane,
        run_id: impl Into<String>,
        assignment_id: impl Into<String>,
        provider: FakeProvider,
    ) -> Self {
        Self {
            plane,
            run_id: run_id.into(),
            assignment_id: assignment_id.into(),
            provider,
            cancelled: false,
            paused: false,
            allowed_paths: None,
            injected: Vec::new(),
            hitl: Vec::new(),
        }
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    pub fn allowed_paths(&self) -> Option<&[String]> {
        self.allowed_paths.as_deref()
    }

    pub fn injected(&self) -> &[String] {
        &self.injected
    }

    pub fn hitl_decisions(&self) -> &[(String, HitlDecisionKind)] {
        &self.hitl
    }

    pub fn apply_inbox(&mut self, now_unix_ms: u64) -> Result<()> {
        let directives = self.plane.inbox(&self.run_id, &self.assignment_id)?;
        for directive in directives {
            match &directive.action {
                SteeringAction::CancelAssignment { .. } => self.cancelled = true,
                SteeringAction::Pause => self.paused = true,
                SteeringAction::Resume => self.paused = false,
                SteeringAction::NarrowScope { allowed_paths } => {
                    self.allowed_paths = Some(allowed_paths.clone());
                }
                SteeringAction::InjectCorrectiveInput { message } => {
                    self.injected.push(message.clone());
                }
                SteeringAction::HitlDecision {
                    tool_call_id,
                    decision,
                    ..
                } => {
                    self.hitl.push((tool_call_id.clone(), *decision));
                    match decision {
                        HitlDecisionKind::Reject => self.paused = true,
                        HitlDecisionKind::Approve | HitlDecisionKind::Edit => self.paused = false,
                    }
                }
            }
            let ack = self.plane.acknowledge(
                &self.run_id,
                &self.assignment_id,
                &directive.action_id,
                now_unix_ms,
            )?;
            if ack.outcome == SteeringOutcome::TimedOut {
                bail!(
                    "steering action {} timed out before acknowledgement",
                    directive.action_id
                );
            }
        }
        Ok(())
    }

    pub fn complete(
        &mut self,
        mut request: LlmRequest,
        now_unix_ms: u64,
    ) -> Result<LlmResponse, ProviderError> {
        self.apply_inbox(now_unix_ms)
            .map_err(|error| ProviderError::CannedFailure {
                request_id: request.request_id.clone(),
                message: error.to_string(),
            })?;
        if self.cancelled {
            return Err(ProviderError::CannedFailure {
                request_id: request.request_id,
                message: "assignment cancelled by steering control plane".to_string(),
            });
        }
        if self.paused {
            return Err(ProviderError::CannedFailure {
                request_id: request.request_id,
                message: "assignment is paused by steering control plane".to_string(),
            });
        }
        for message in &self.injected {
            request.prompt = apply_inject_to_prompt(request.prompt, message);
        }
        self.injected.clear();
        self.provider.complete(request)
    }
}
