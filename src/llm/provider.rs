use crate::llm::{
    prompt::Prompt,
    transcript::{RedactionSummary, Transcript},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use thiserror::Error;

pub trait LlmProvider {
    fn provider_id(&self) -> &str;

    fn capabilities(&self) -> ProviderCapabilities;

    fn complete(&mut self, request: LlmRequest) -> Result<LlmResponse, ProviderError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LlmRequest {
    pub request_id: String,
    pub model: String,
    pub prompt: Prompt,
    pub budget: RequestBudget,
    pub transcript: Transcript,
    pub metadata: BTreeMap<String, String>,
}

impl LlmRequest {
    pub fn new(request_id: impl Into<String>, model: impl Into<String>, prompt: Prompt) -> Self {
        Self {
            request_id: request_id.into(),
            model: model.into(),
            prompt,
            budget: RequestBudget::default(),
            transcript: Transcript::default(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_budget(mut self, budget: RequestBudget) -> Self {
        self.budget = budget;
        self
    }

    pub fn with_transcript(mut self, transcript: Transcript) -> Self {
        self.transcript = transcript;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LlmResponse {
    pub request_id: String,
    pub provider_id: String,
    pub model: String,
    pub proposal: WorkProposal,
    pub usage: Usage,
    pub transcript: Transcript,
    pub redactions: RedactionSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkProposal {
    pub summary: String,
    pub commands: Vec<ProposedCommand>,
    pub patches: Vec<ProposedPatch>,
    pub notes: Vec<String>,
}

impl WorkProposal {
    pub fn summary(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            commands: Vec::new(),
            patches: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn with_command(mut self, command: ProposedCommand) -> Self {
        self.commands.push(command);
        self
    }

    pub fn with_patch(mut self, patch: ProposedPatch) -> Self {
        self.patches.push(patch);
        self
    }

    pub fn rendered_len(&self) -> usize {
        self.render_for_transcript().len()
    }

    pub fn render_for_transcript(&self) -> String {
        let mut rendered = String::new();
        rendered.push_str("summary:\n");
        rendered.push_str(&self.summary);
        rendered.push('\n');

        if !self.commands.is_empty() {
            rendered.push_str("commands:\n");
            for command in &self.commands {
                rendered.push_str("- ");
                rendered.push_str(&command.command);
                if let Some(cwd) = &command.working_directory {
                    rendered.push_str(" (cwd: ");
                    rendered.push_str(&cwd.display().to_string());
                    rendered.push(')');
                }
                rendered.push('\n');
            }
        }

        if !self.patches.is_empty() {
            rendered.push_str("patches:\n");
            for patch in &self.patches {
                rendered.push_str("- ");
                rendered.push_str(&patch.path.display().to_string());
                rendered.push('\n');
            }
        }

        if !self.notes.is_empty() {
            rendered.push_str("notes:\n");
            for note in &self.notes {
                rendered.push_str("- ");
                rendered.push_str(note);
                rendered.push('\n');
            }
        }

        rendered
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProposedCommand {
    pub command: String,
    pub working_directory: Option<PathBuf>,
    pub purpose: CommandPurpose,
}

impl ProposedCommand {
    pub fn new(command: impl Into<String>, purpose: CommandPurpose) -> Self {
        Self {
            command: command.into(),
            working_directory: None,
            purpose,
        }
    }

    pub fn with_working_directory(mut self, working_directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(working_directory.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandPurpose {
    Inspect,
    Implement,
    Validate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProposedPatch {
    pub path: PathBuf,
    pub unified_diff: String,
}

impl ProposedPatch {
    pub fn new(path: impl Into<PathBuf>, unified_diff: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            unified_diff: unified_diff.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct RequestBudget {
    pub max_input_chars: usize,
    pub max_output_chars: usize,
    pub max_total_tokens: usize,
}

impl RequestBudget {
    pub fn new(max_input_chars: usize, max_output_chars: usize, max_total_tokens: usize) -> Self {
        Self {
            max_input_chars,
            max_output_chars,
            max_total_tokens,
        }
    }
}

impl Default for RequestBudget {
    fn default() -> Self {
        Self {
            max_input_chars: 64 * 1024,
            max_output_chars: 32 * 1024,
            max_total_tokens: 24 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProviderCapabilities {
    pub max_context_tokens: usize,
    pub max_output_tokens: usize,
    pub supports_command_proposals: bool,
    pub supports_patch_proposals: bool,
    pub supports_transcripts: bool,
}

impl ProviderCapabilities {
    pub fn local_fake() -> Self {
        Self {
            max_context_tokens: usize::MAX,
            max_output_tokens: usize::MAX,
            supports_command_proposals: true,
            supports_patch_proposals: true,
            supports_transcripts: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Usage {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub total_tokens: usize,
}

impl Usage {
    pub fn from_char_counts(input_chars: usize, output_chars: usize) -> Self {
        let input_tokens = estimate_tokens(input_chars);
        let output_tokens = estimate_tokens(output_chars);
        Self {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens.saturating_add(output_tokens),
        }
    }

    pub fn saturating_add(self, other: Self) -> Self {
        let input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        let output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        Self {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens.saturating_add(output_tokens),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub struct ModelPricing {
    pub input_usd_per_million_tokens: f64,
    pub output_usd_per_million_tokens: f64,
}

impl ModelPricing {
    pub fn cost_usd(self, usage: Usage) -> f64 {
        const TOKENS_PER_MILLION: f64 = 1_000_000.0;
        (usage.input_tokens as f64 * self.input_usd_per_million_tokens
            + usage.output_tokens as f64 * self.output_usd_per_million_tokens)
            / TOKENS_PER_MILLION
    }

    pub fn is_valid(self) -> bool {
        self.input_usd_per_million_tokens.is_finite()
            && self.input_usd_per_million_tokens >= 0.0
            && self.output_usd_per_million_tokens.is_finite()
            && self.output_usd_per_million_tokens >= 0.0
    }
}

fn estimate_tokens(chars: usize) -> usize {
    chars.saturating_add(3) / 4
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderError {
    #[error("request id cannot be empty")]
    EmptyRequestId,
    #[error("model cannot be empty")]
    EmptyModel,
    #[error("missing canned response for request id '{request_id}'")]
    MissingCannedResponse { request_id: String },
    #[error("canned provider failure for request id '{request_id}': {message}")]
    CannedFailure { request_id: String, message: String },
    #[error("budget exceeded for {field}: used {used}, limit {limit}")]
    BudgetExceeded {
        field: &'static str,
        used: usize,
        limit: usize,
    },
    #[error("provider does not support requested capability: {0}")]
    UnsupportedCapability(String),
    #[error("provider rejected request: {0}")]
    InvalidRequest(String),
    #[error("provider authentication failed: {0}")]
    Authentication(String),
    #[error("provider rate limited request: {0}")]
    RateLimited(String),
    #[error("provider transport failed: {0}")]
    Transport(String),
    #[error("provider failed: {0}")]
    Provider(String),
}

pub fn validate_request(request: &LlmRequest) -> Result<(), ProviderError> {
    if request.request_id.trim().is_empty() {
        return Err(ProviderError::EmptyRequestId);
    }
    if request.model.trim().is_empty() {
        return Err(ProviderError::EmptyModel);
    }

    Ok(())
}
