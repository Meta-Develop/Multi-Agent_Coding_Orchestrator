//! Provider-neutral LLM request and response boundary.
//!
//! This module is intentionally local-first: providers return typed proposals,
//! commands, and patches for the orchestrator to review and route through
//! worktrees and path claims. Nothing in this boundary edits repository files.

pub mod fake;
pub mod prompt;
pub mod provider;
pub mod transcript;

pub use fake::{FakeBudgetBehavior, FakeOutcome, FakeProvider};
pub use prompt::{
    ClaimedPath, Prompt, PromptContext, PromptSection, RepoExcerpt, ValidationCommand,
};
pub use provider::{
    LlmProvider, LlmRequest, LlmResponse, ProposedCommand, ProposedPatch, ProviderCapabilities,
    ProviderError, RequestBudget, Usage, WorkProposal,
};
pub use transcript::{
    RedactedText, RedactionRule, RedactionSummary, Redactor, Transcript, TranscriptTurn, TurnRole,
};
