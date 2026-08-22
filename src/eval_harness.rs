//! Local fake-provider-backed model-mix evaluation harness.
//!
//! First bounded Issue #26 slice: declare a planner/worker (and related) role
//! mix, complete each role through [`crate::llm::FakeProvider`], and record the
//! mix plus per-role outcomes to a versioned schema. Network and real-provider
//! execution are refused. [`crate::evaluation`] remains the synthetic fixture
//! generator and does not invoke a provider.

use crate::llm::{
    FakeProvider, LlmProvider, LlmRequest, PromptContext, Redactor, Usage, WorkProposal,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[cfg(test)]
mod tests;

pub const EVAL_HARNESS_MANIFEST_VERSION: u32 = 1;
pub const EVAL_HARNESS_RESULT_VERSION: u32 = 1;
pub const EVAL_HARNESS_RESULT_SCHEMA: &str = "eval_harness_result_v1";
pub const LOCAL_FAKE_PROVIDER_ID: &str = "local_fake";
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

const MAX_PROFILES: usize = 16;
const MAX_ROLES_PER_PROFILE: usize = 8;

/// Versioned input for a local fake-provider model-mix run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessManifest {
    pub version: u32,
    pub experiment_id: String,
    pub task: String,
    pub provider: EvalHarnessProviderKind,
    pub profiles: Vec<EvalHarnessProfile>,
}

/// A named role/model mix under test.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessProfile {
    pub id: String,
    pub mix: Vec<EvalHarnessRoleBinding>,
}

/// One role in a mix and the model it should dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessRoleBinding {
    pub role: MixRole,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripted_failure: Option<String>,
}

/// Roles the first-slice harness can bind in a mix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MixRole {
    Planner,
    Worker,
    Supervisor,
    Auditor,
}

impl MixRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Worker => "worker",
            Self::Supervisor => "supervisor",
            Self::Auditor => "auditor",
        }
    }
}

/// Provider kinds the harness understands. Only [`Self::LocalFake`] may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalHarnessProviderKind {
    LocalFake,
    RealProvider,
}

/// Machine-readable mix plus outcomes for one harness execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessResult {
    pub version: u32,
    pub schema: String,
    pub experiment_id: String,
    pub task: String,
    pub task_digest: String,
    pub provider: EvalHarnessProviderClaim,
    pub runs: Vec<EvalHarnessRun>,
}

/// Explicit claim that this document was produced without network providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessProviderClaim {
    pub kind: EvalHarnessProviderKind,
    pub network_providers: bool,
}

/// One profile's mix, per-role outcomes, and token totals.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessRun {
    pub profile_id: String,
    pub mix: Vec<EvalHarnessRecordedMix>,
    pub outcomes: Vec<EvalHarnessOutcome>,
    pub totals: Usage,
}

/// The mix that was actually dispatched for a run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessRecordedMix {
    pub role: MixRole,
    pub model: String,
}

/// Per-role fake-provider outcome.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessOutcome {
    pub role: MixRole,
    pub model: String,
    pub request_id: String,
    pub provider_id: String,
    pub status: OutcomeStatus,
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Completed,
    Failed,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvalHarnessError {
    #[error("unsupported eval harness manifest version {found}; supported version is {supported}")]
    UnsupportedManifestVersion { found: u32, supported: u32 },
    #[error("invalid eval harness manifest field '{field}': {message}")]
    InvalidManifest { field: String, message: String },
    #[error("failed to parse eval harness manifest: {message}")]
    ManifestParse { message: String },
    #[error(
        "eval harness refuses network or real-provider execution; use provider=local_fake and do not request a network provider"
    )]
    NetworkProviderRefused,
}

/// Parse and validate a versioned harness manifest.
pub fn parse_manifest(bytes: &[u8]) -> Result<EvalHarnessManifest, EvalHarnessError> {
    let manifest = serde_json::from_slice::<EvalHarnessManifest>(bytes).map_err(|error| {
        EvalHarnessError::ManifestParse {
            message: error.to_string(),
        }
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Run every declared mix through the local fake provider and record outcomes.
pub fn run_local_fake_harness(
    manifest: &EvalHarnessManifest,
) -> Result<EvalHarnessResult, EvalHarnessError> {
    manifest.validate()?;
    if manifest.provider != EvalHarnessProviderKind::LocalFake {
        return Err(EvalHarnessError::NetworkProviderRefused);
    }

    let mut runs = Vec::with_capacity(manifest.profiles.len());
    for profile in &manifest.profiles {
        runs.push(run_profile(manifest, profile)?);
    }

    Ok(EvalHarnessResult {
        version: EVAL_HARNESS_RESULT_VERSION,
        schema: EVAL_HARNESS_RESULT_SCHEMA.to_string(),
        experiment_id: manifest.experiment_id.clone(),
        task: manifest.task.clone(),
        task_digest: crate::artifacts::state_auth::sha256_hex(manifest.task.as_bytes()),
        provider: EvalHarnessProviderClaim {
            kind: EvalHarnessProviderKind::LocalFake,
            network_providers: false,
        },
        runs,
    })
}

impl EvalHarnessManifest {
    fn validate(&self) -> Result<(), EvalHarnessError> {
        if self.version != EVAL_HARNESS_MANIFEST_VERSION {
            return Err(EvalHarnessError::UnsupportedManifestVersion {
                found: self.version,
                supported: EVAL_HARNESS_MANIFEST_VERSION,
            });
        }
        require_nonempty("experiment_id", &self.experiment_id)?;
        require_nonempty("task", &self.task)?;
        if self.provider != EvalHarnessProviderKind::LocalFake {
            return Err(EvalHarnessError::NetworkProviderRefused);
        }
        if self.profiles.is_empty() {
            return Err(invalid_manifest(
                "profiles",
                "at least one profile is required",
            ));
        }
        if self.profiles.len() > MAX_PROFILES {
            return Err(invalid_manifest(
                "profiles",
                format!("at most {MAX_PROFILES} profiles are supported"),
            ));
        }

        let mut seen_ids = BTreeSet::new();
        for (index, profile) in self.profiles.iter().enumerate() {
            let field = format!("profiles[{index}].id");
            require_nonempty(&field, &profile.id)?;
            if !seen_ids.insert(profile.id.as_str()) {
                return Err(invalid_manifest(
                    "profiles",
                    format!("duplicate profile id '{}'", profile.id),
                ));
            }
            validate_mix(index, &profile.mix)?;
        }
        Ok(())
    }
}

fn validate_mix(
    profile_index: usize,
    mix: &[EvalHarnessRoleBinding],
) -> Result<(), EvalHarnessError> {
    if mix.is_empty() {
        return Err(invalid_manifest(
            format!("profiles[{profile_index}].mix"),
            "at least one role binding is required",
        ));
    }
    if mix.len() > MAX_ROLES_PER_PROFILE {
        return Err(invalid_manifest(
            format!("profiles[{profile_index}].mix"),
            format!("at most {MAX_ROLES_PER_PROFILE} role bindings are supported"),
        ));
    }

    let mut seen_roles = BTreeSet::new();
    for (index, binding) in mix.iter().enumerate() {
        if !seen_roles.insert(binding.role) {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].mix"),
                format!("duplicate role '{}'", binding.role.as_str()),
            ));
        }
        require_nonempty(
            &format!("profiles[{profile_index}].mix[{index}].model"),
            &binding.model,
        )?;
        if let Some(message) = &binding.scripted_failure {
            require_nonempty(
                &format!("profiles[{profile_index}].mix[{index}].scripted_failure"),
                message,
            )?;
        }
    }
    Ok(())
}

fn run_profile(
    manifest: &EvalHarnessManifest,
    profile: &EvalHarnessProfile,
) -> Result<EvalHarnessRun, EvalHarnessError> {
    let mix = profile
        .mix
        .iter()
        .map(|binding| EvalHarnessRecordedMix {
            role: binding.role,
            model: binding.model.clone(),
        })
        .collect();

    let mut outcomes = Vec::with_capacity(profile.mix.len());
    let mut totals = Usage::default();
    for binding in &profile.mix {
        let outcome = complete_role(&manifest.task, &profile.id, binding);
        totals = totals.saturating_add(outcome.usage);
        outcomes.push(outcome);
    }

    Ok(EvalHarnessRun {
        profile_id: profile.id.clone(),
        mix,
        outcomes,
        totals,
    })
}

fn complete_role(
    task: &str,
    profile_id: &str,
    binding: &EvalHarnessRoleBinding,
) -> EvalHarnessOutcome {
    let request_id = format!("{}:{}", profile_id, binding.role.as_str());
    let mut provider = FakeProvider::new(LOCAL_FAKE_PROVIDER_ID, binding.model.clone());
    match &binding.scripted_failure {
        Some(message) => {
            provider.push_failure(&request_id, message);
        }
        None => {
            provider.push_response(
                &request_id,
                WorkProposal::summary(format!(
                    "eval-harness local-fake role={} model={}",
                    binding.role.as_str(),
                    binding.model
                )),
            );
        }
    }

    let prompt = PromptContext::new(task, format!("eval-harness-{}", binding.role.as_str()))
        .assemble_prompt(&Redactor::new());
    let request = LlmRequest::new(request_id.clone(), binding.model.clone(), prompt);

    match provider.complete(request) {
        Ok(response) => EvalHarnessOutcome {
            role: binding.role,
            model: binding.model.clone(),
            request_id,
            provider_id: response.provider_id,
            status: OutcomeStatus::Completed,
            usage: response.usage,
            proposal_summary: Some(response.proposal.summary),
            error: None,
        },
        Err(error) => EvalHarnessOutcome {
            role: binding.role,
            model: binding.model.clone(),
            request_id,
            provider_id: LOCAL_FAKE_PROVIDER_ID.to_string(),
            status: OutcomeStatus::Failed,
            usage: Usage::default(),
            proposal_summary: None,
            error: Some(error.to_string()),
        },
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), EvalHarnessError> {
    if value.trim().is_empty() {
        return Err(invalid_manifest(field, "must be a non-empty string"));
    }
    Ok(())
}

fn invalid_manifest(field: impl Into<String>, message: impl Into<String>) -> EvalHarnessError {
    EvalHarnessError::InvalidManifest {
        field: field.into(),
        message: message.into(),
    }
}
