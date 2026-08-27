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

pub const DEFAULT_MODEL_PRICING_CATALOG_ID: &str = "maco-policy-default";
pub const DEFAULT_MODEL_PRICING_CATALOG_VERSION: u32 = 1;
pub const DEFAULT_MODEL_PRICING_CATALOG_REVISION: &str = "2026-08-26";
pub const DEFAULT_MODEL_PRICING_CATALOG_EFFECTIVE_DATE: &str = "2026-08-26";
pub const DEFAULT_MODEL_PRICING_CATALOG_NOTICE: &str =
    "Project policy placeholder rates for offline admission and reporting. These are not vendor list prices.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPricingProvenance {
    ProjectPolicyDefault,
    PlanOverride,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ModelPricingCatalog {
    pub catalog_id: String,
    pub catalog_version: u32,
    pub revision: String,
    pub effective_date: String,
    pub content_sha256: String,
    pub provenance: ModelPricingProvenance,
    pub notice: String,
    pub entries: BTreeMap<String, ModelPricing>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedModelPricing {
    pub pricing: ModelPricing,
    pub provenance: ModelPricingProvenance,
}

pub fn default_model_pricing_catalog() -> ModelPricingCatalog {
    let placeholder = ModelPricing {
        input_usd_per_million_tokens: 0.0,
        output_usd_per_million_tokens: 0.0,
    };
    let entries = BTreeMap::from([
        ("fake".to_string(), placeholder),
        ("gpt-5.6-sol".to_string(), placeholder),
        ("gpt-5.6-luna".to_string(), placeholder),
    ]);
    let mut catalog = ModelPricingCatalog {
        catalog_id: DEFAULT_MODEL_PRICING_CATALOG_ID.to_string(),
        catalog_version: DEFAULT_MODEL_PRICING_CATALOG_VERSION,
        revision: DEFAULT_MODEL_PRICING_CATALOG_REVISION.to_string(),
        effective_date: DEFAULT_MODEL_PRICING_CATALOG_EFFECTIVE_DATE.to_string(),
        content_sha256: String::new(),
        provenance: ModelPricingProvenance::ProjectPolicyDefault,
        notice: DEFAULT_MODEL_PRICING_CATALOG_NOTICE.to_string(),
        entries,
    };
    catalog.content_sha256 = model_pricing_catalog_content_sha256(&catalog);
    catalog
}

pub fn resolve_model_pricing(
    plan_pricing: &BTreeMap<String, ModelPricing>,
    model: &str,
) -> Option<ResolvedModelPricing> {
    let normalized = model.trim();
    if normalized.is_empty() {
        return None;
    }
    if let Some(pricing) = plan_pricing.get(normalized).copied() {
        return pricing.is_valid().then_some(ResolvedModelPricing {
            pricing,
            provenance: ModelPricingProvenance::PlanOverride,
        });
    }
    default_model_pricing_catalog()
        .entries
        .get(normalized)
        .copied()
        .filter(|pricing| pricing.is_valid())
        .map(|pricing| ResolvedModelPricing {
            pricing,
            provenance: ModelPricingProvenance::ProjectPolicyDefault,
        })
}

fn model_pricing_catalog_content_sha256(catalog: &ModelPricingCatalog) -> String {
    let payload = serde_json::json!({
        "catalog_id": catalog.catalog_id,
        "catalog_version": catalog.catalog_version,
        "revision": catalog.revision,
        "effective_date": catalog.effective_date,
        "provenance": catalog.provenance,
        "notice": catalog.notice,
        "entries": catalog.entries,
    });
    crate::artifacts::state_auth::sha256_hex(payload.to_string().as_bytes())
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

#[cfg(test)]
mod pricing_catalog_tests {
    use super::*;

    #[test]
    fn default_catalog_is_versioned_policy_placeholder_not_vendor_prices() {
        let catalog = default_model_pricing_catalog();
        assert_eq!(catalog.catalog_id, DEFAULT_MODEL_PRICING_CATALOG_ID);
        assert_eq!(
            catalog.catalog_version,
            DEFAULT_MODEL_PRICING_CATALOG_VERSION
        );
        assert!(!catalog.content_sha256.is_empty());
        assert_eq!(
            catalog.provenance,
            ModelPricingProvenance::ProjectPolicyDefault
        );
        assert!(catalog.notice.contains("not vendor list prices"));
        let fake = catalog.entries.get("fake").expect("fake placeholder");
        assert_eq!(fake.input_usd_per_million_tokens, 0.0);
        assert_eq!(fake.output_usd_per_million_tokens, 0.0);
    }

    #[test]
    fn plan_override_beats_policy_default_and_unknown_models_stay_unpriced() {
        let override_pricing = ModelPricing {
            input_usd_per_million_tokens: 1.5,
            output_usd_per_million_tokens: 2.5,
        };
        let plan = BTreeMap::from([("fake".to_string(), override_pricing)]);
        let resolved = resolve_model_pricing(&plan, "fake").expect("plan override");
        assert_eq!(resolved.pricing, override_pricing);
        assert_eq!(resolved.provenance, ModelPricingProvenance::PlanOverride);

        let defaulted = resolve_model_pricing(&BTreeMap::new(), "fake").expect("policy default");
        assert_eq!(
            defaulted.provenance,
            ModelPricingProvenance::ProjectPolicyDefault
        );
        assert!(resolve_model_pricing(&BTreeMap::new(), "unknown-model").is_none());
    }
}
