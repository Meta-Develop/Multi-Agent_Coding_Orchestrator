use crate::llm::{
    provider::{
        validate_request, LlmProvider, LlmRequest, LlmResponse, ProviderCapabilities,
        ProviderError, Usage, WorkProposal,
    },
    transcript::{RedactionSummary, TurnRole},
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone)]
pub struct FakeProvider {
    provider_id: String,
    model: String,
    capabilities: ProviderCapabilities,
    budget_behavior: FakeBudgetBehavior,
    canned: BTreeMap<String, VecDeque<FakeOutcome>>,
    calls: Vec<LlmRequest>,
}

impl FakeProvider {
    pub fn new(provider_id: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            model: model.into(),
            capabilities: ProviderCapabilities::local_fake(),
            budget_behavior: FakeBudgetBehavior::Enforce,
            canned: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    pub fn with_capabilities(mut self, capabilities: ProviderCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_budget_behavior(mut self, budget_behavior: FakeBudgetBehavior) -> Self {
        self.budget_behavior = budget_behavior;
        self
    }

    pub fn push_response(
        &mut self,
        request_id: impl Into<String>,
        proposal: WorkProposal,
    ) -> &mut Self {
        self.push_outcome(request_id, FakeOutcome::Response { proposal })
    }

    pub fn push_json_response<T: Serialize>(
        &mut self,
        request_id: impl Into<String>,
        value: &T,
    ) -> Result<&mut Self, serde_json::Error> {
        let summary = serde_json::to_string(value)?;
        Ok(self.push_response(request_id, WorkProposal::summary(summary)))
    }

    pub fn push_failure(
        &mut self,
        request_id: impl Into<String>,
        message: impl Into<String>,
    ) -> &mut Self {
        let request_id = request_id.into();
        let message = message.into();
        self.push_outcome(
            request_id.clone(),
            FakeOutcome::Failure(ProviderError::CannedFailure {
                request_id,
                message,
            }),
        )
    }

    pub fn push_outcome(
        &mut self,
        request_id: impl Into<String>,
        outcome: FakeOutcome,
    ) -> &mut Self {
        self.canned
            .entry(request_id.into())
            .or_default()
            .push_back(outcome);
        self
    }

    pub fn calls(&self) -> &[LlmRequest] {
        &self.calls
    }

    fn next_outcome(&mut self, request_id: &str) -> Result<FakeOutcome, ProviderError> {
        let Some(queue) = self.canned.get_mut(request_id) else {
            return Err(ProviderError::MissingCannedResponse {
                request_id: request_id.to_string(),
            });
        };

        match queue.pop_front() {
            Some(outcome) => Ok(outcome),
            None => Err(ProviderError::MissingCannedResponse {
                request_id: request_id.to_string(),
            }),
        }
    }

    fn enforce_input_budget(&self, request: &LlmRequest) -> Result<usize, ProviderError> {
        let input_chars = request.prompt.render().chars().count();
        if self.budget_behavior == FakeBudgetBehavior::Ignore {
            return Ok(input_chars);
        }
        if input_chars > request.budget.max_input_chars {
            return Err(ProviderError::BudgetExceeded {
                field: "input_chars",
                used: input_chars,
                limit: request.budget.max_input_chars,
            });
        }

        Ok(input_chars)
    }

    fn enforce_output_budget(
        &self,
        proposal: &WorkProposal,
        input_chars: usize,
        request: &LlmRequest,
    ) -> Result<Usage, ProviderError> {
        let output_chars = proposal.render_for_transcript().chars().count();
        let usage = Usage::from_char_counts(input_chars, output_chars);

        if self.budget_behavior == FakeBudgetBehavior::Ignore {
            return Ok(usage);
        }
        if output_chars > request.budget.max_output_chars {
            return Err(ProviderError::BudgetExceeded {
                field: "output_chars",
                used: output_chars,
                limit: request.budget.max_output_chars,
            });
        }
        if usage.total_tokens > request.budget.max_total_tokens {
            return Err(ProviderError::BudgetExceeded {
                field: "total_tokens",
                used: usage.total_tokens,
                limit: request.budget.max_total_tokens,
            });
        }

        Ok(usage)
    }
}

impl LlmProvider for FakeProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }

    fn complete(&mut self, request: LlmRequest) -> Result<LlmResponse, ProviderError> {
        validate_request(&request)?;
        let input_chars = self.enforce_input_budget(&request)?;
        let outcome = self.next_outcome(&request.request_id)?;
        self.calls.push(request.clone());

        match outcome {
            FakeOutcome::Response { proposal } => {
                let usage = self.enforce_output_budget(&proposal, input_chars, &request)?;
                let proposal_text = proposal.render_for_transcript();
                let mut transcript = request.transcript.clone();
                transcript.push(TurnRole::User, request.prompt.render());
                transcript.push(TurnRole::Assistant, proposal_text);
                let mut redactions = RedactionSummary::default();
                redactions.merge(request.prompt.redactions.clone());

                Ok(LlmResponse {
                    request_id: request.request_id,
                    provider_id: self.provider_id.clone(),
                    model: self.model.clone(),
                    proposal,
                    usage,
                    transcript,
                    redactions,
                })
            }
            FakeOutcome::Failure(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeBudgetBehavior {
    Enforce,
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeOutcome {
    Response { proposal: WorkProposal },
    Failure(ProviderError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{prompt::PromptContext, provider::RequestBudget, transcript::Redactor};

    fn request(request_id: &str, task: &str) -> LlmRequest {
        let prompt = PromptContext::new(task, "agent-a").assemble_prompt(&Redactor::new());
        LlmRequest::new(request_id, "fake-model", prompt)
    }

    #[test]
    fn fake_provider_returns_canned_responses_in_order() {
        let mut provider = FakeProvider::new("fake", "fake-model");
        provider
            .push_response("req-1", WorkProposal::summary("first"))
            .push_response("req-1", WorkProposal::summary("second"));

        let first = provider.complete(request("req-1", "task")).expect("first");
        let second = provider.complete(request("req-1", "task")).expect("second");

        assert_eq!(first.proposal.summary, "first");
        assert_eq!(second.proposal.summary, "second");
        assert_eq!(provider.calls().len(), 2);
        assert_eq!(provider.calls()[0].request_id, "req-1");
    }

    #[test]
    fn fake_provider_scripts_typed_json_summaries() {
        let mut provider = FakeProvider::new("fake", "fake-model");
        provider
            .push_json_response("json", &serde_json::json!({"assignments": []}))
            .expect("script JSON response");

        let response = provider
            .complete(request("json", "task"))
            .expect("response");

        assert_eq!(response.proposal.summary, r#"{"assignments":[]}"#);
    }

    #[test]
    fn fake_provider_reports_missing_canned_response_and_failures() {
        let mut provider = FakeProvider::new("fake", "fake-model");

        let missing = provider
            .complete(request("missing", "task"))
            .expect_err("missing response");
        assert!(matches!(
            missing,
            ProviderError::MissingCannedResponse { request_id } if request_id == "missing"
        ));

        provider.push_failure("req-2", "planned failure");
        let failure = provider
            .complete(request("req-2", "task"))
            .expect_err("planned failure");
        assert!(matches!(
            failure,
            ProviderError::CannedFailure { request_id, message }
                if request_id == "req-2" && message == "planned failure"
        ));
    }

    #[test]
    fn fake_provider_enforces_input_output_and_token_budgets() {
        let mut provider = FakeProvider::new("fake", "fake-model");
        provider.push_response("tiny-input", WorkProposal::summary("ok"));
        let tiny_input =
            request("tiny-input", "task").with_budget(RequestBudget::new(1, 1024, 1024));
        let input_error = provider.complete(tiny_input).expect_err("input budget");
        assert!(matches!(
            input_error,
            ProviderError::BudgetExceeded {
                field: "input_chars",
                ..
            }
        ));

        provider.push_response("tiny-output", WorkProposal::summary("long output"));
        let tiny_output =
            request("tiny-output", "task").with_budget(RequestBudget::new(4096, 1, 1024));
        let output_error = provider.complete(tiny_output).expect_err("output budget");
        assert!(matches!(
            output_error,
            ProviderError::BudgetExceeded {
                field: "output_chars",
                ..
            }
        ));

        provider.push_response("tiny-tokens", WorkProposal::summary("long output"));
        let tiny_tokens =
            request("tiny-tokens", "task").with_budget(RequestBudget::new(4096, 4096, 1));
        let token_error = provider.complete(tiny_tokens).expect_err("token budget");
        assert!(matches!(
            token_error,
            ProviderError::BudgetExceeded {
                field: "total_tokens",
                ..
            }
        ));
    }

    #[test]
    fn fake_provider_can_ignore_budgets_for_specific_tests() {
        let mut provider = FakeProvider::new("fake", "fake-model")
            .with_budget_behavior(FakeBudgetBehavior::Ignore);
        provider.push_response("req-1", WorkProposal::summary("long output"));

        let response = provider
            .complete(request("req-1", "task").with_budget(RequestBudget::new(1, 1, 1)))
            .expect("budget ignored");

        assert_eq!(response.proposal.summary, "long output");
    }

    #[test]
    fn fake_provider_input_budget_counts_unicode_chars_not_bytes() {
        let mut provider = FakeProvider::new("fake", "fake-model");
        provider.push_response("unicode", WorkProposal::summary("ok"));

        let prompt = PromptContext::new("é", "agent-a").assemble_prompt(&Redactor::new());
        let rendered = prompt.render();
        let char_count = rendered.chars().count();
        let byte_count = rendered.len();
        assert!(
            byte_count > char_count,
            "fixture must use a multi-byte character so bytes and chars diverge"
        );

        let accepted = LlmRequest::new("unicode", "fake-model", prompt.clone())
            .with_budget(RequestBudget::new(char_count, 4096, 4096));
        provider
            .complete(accepted)
            .expect("char-count budget must accept a preview-approved non-ASCII prompt");

        provider.push_response("unicode-over", WorkProposal::summary("ok"));
        let rejected = LlmRequest::new("unicode-over", "fake-model", prompt)
            .with_budget(RequestBudget::new(char_count.saturating_sub(1), 4096, 4096));
        let error = provider
            .complete(rejected)
            .expect_err("one fewer char must exceed the char budget");
        assert_eq!(
            error,
            ProviderError::BudgetExceeded {
                field: "input_chars",
                used: char_count,
                limit: char_count.saturating_sub(1),
            }
        );
        assert_ne!(
            match error {
                ProviderError::BudgetExceeded { used, .. } => used,
                _ => 0,
            },
            byte_count,
            "BudgetExceeded.used must be a character count, not a UTF-8 byte count"
        );
    }
}
