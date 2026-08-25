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
use crate::objective_profile::ResolvedObjectiveProfile;
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
pub const EVAL_HARNESS_MANIFEST_V2_VERSION: u32 = 2;
pub const EVAL_HARNESS_MANIFEST_V2_SCHEMA: &str = "eval_harness_manifest_v2";
pub const EVAL_HARNESS_RESULT_V2_VERSION: u32 = 2;
pub const EVAL_HARNESS_RESULT_V2_SCHEMA: &str = "eval_harness_result_v2";

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

/// Complete Issue #26 experiment binding, kept separate from the stable v1
/// fake-provider execution contract.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessManifestV2 {
    pub version: u32,
    pub experiment_id: String,
    pub spec: EvalHarnessContentBinding,
    pub goal: EvalHarnessContentBinding,
    pub repository_base: EvalHarnessRepositoryBase,
    pub limits: EvalHarnessLimits,
    pub held_out_validations: Vec<EvalHarnessHeldOutBinding>,
    pub repetition_count: u32,
    #[serde(default)]
    pub provider_request: EvalHarnessProviderRequest,
    pub profiles: Vec<EvalHarnessProfile>,
    pub objective_profile: ResolvedObjectiveProfile,
}

/// Immutable identity and content digest for a specification or goal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessContentBinding {
    pub id: String,
    pub content_digest: String,
}

/// Full immutable Git object id of the repository base snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessRepositoryBase {
    pub object_id: String,
}

/// Limits that every compared profile must share.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessLimits {
    pub wall_time_seconds: u64,
    pub dispatch_limit: u32,
}

/// Immutable held-out validation identity and content binding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessHeldOutBinding {
    pub id: String,
    pub content_digest: String,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvalHarnessProviderKind {
    #[default]
    LocalFake,
    RealProvider,
}

/// Provider request boundary for v2 experiments. Its default is deterministic
/// local fake execution; the real-provider branch never invokes an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessProviderRequest {
    #[serde(default)]
    pub kind: EvalHarnessProviderKind,
    #[serde(default)]
    pub allow_real_provider: bool,
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

/// Machine-readable v2 input binding. This does not claim an experiment ran.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessResultV2 {
    pub version: u32,
    pub schema: String,
    pub experiment_id: String,
    pub input_binding: EvalHarnessInputBinding,
    pub objective_profile: ResolvedObjectiveProfile,
    pub provider: EvalHarnessProviderClaim,
    pub eligibility: EvalHarnessEligibility,
}

/// Digest of the normalized, fully validated v2 manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessInputBinding {
    pub manifest_schema: String,
    pub manifest_version: u32,
    pub digest_algorithm: String,
    pub digest: String,
}

/// Explicit eligibility state for profile comparison and Pareto use.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessEligibility {
    pub status: EvalHarnessEligibilityStatus,
    pub limitations: Vec<EvalHarnessLimitation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalHarnessEligibilityStatus {
    Ineligible,
}

/// Evidence the binding-only v2 slice deliberately does not fabricate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalHarnessLimitation {
    EquivalentIsolatedStateNotObserved,
    GoalToIntegrationNotExecuted,
    RequiredPerProfileMetricsNotCaptured,
    ComparabilityNotEstablished,
    ParetoSummaryNotAvailable,
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

/// Errors exclusive to the separate v2 contract. Keeping these variants out
/// of [`EvalHarnessError`] preserves the public v1 error surface.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvalHarnessV2Error {
    #[error(transparent)]
    Manifest(#[from] EvalHarnessError),
    #[error("failed to parse eval harness v2 manifest: {message}")]
    ManifestParse { message: String },
    #[error("real-provider eval harness requests require allow_real_provider=true")]
    RealProviderOptInRequired,
    #[error(
        "real-provider eval harness execution is unavailable pending separate owner approval; no provider adapter was invoked"
    )]
    RealProviderUnavailable,
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

/// Parse and validate the complete v2 experiment binding without executing it.
pub fn parse_manifest_v2(bytes: &[u8]) -> Result<EvalHarnessManifestV2, EvalHarnessV2Error> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid_manifest(
            "manifest",
            format!("exceeds the {MAX_MANIFEST_BYTES}-byte limit"),
        )
        .into());
    }
    let manifest = serde_json::from_slice::<EvalHarnessManifestV2>(bytes).map_err(|error| {
        EvalHarnessV2Error::ManifestParse {
            message: error.to_string(),
        }
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Bind every normalized v2 input while explicitly refusing to claim that the
/// unowned goal-to-integration and evidence-capture paths ran.
pub fn bind_v2_experiment(
    manifest: &EvalHarnessManifestV2,
) -> Result<EvalHarnessResultV2, EvalHarnessV2Error> {
    manifest.validate()?;
    let normalized = serde_json::to_vec(manifest).map_err(|error| {
        EvalHarnessV2Error::Manifest(invalid_manifest(
            "manifest",
            format!("failed to serialize normalized v2 binding: {error}"),
        ))
    })?;

    Ok(EvalHarnessResultV2 {
        version: EVAL_HARNESS_RESULT_V2_VERSION,
        schema: EVAL_HARNESS_RESULT_V2_SCHEMA.to_string(),
        experiment_id: manifest.experiment_id.clone(),
        input_binding: EvalHarnessInputBinding {
            manifest_schema: EVAL_HARNESS_MANIFEST_V2_SCHEMA.to_string(),
            manifest_version: EVAL_HARNESS_MANIFEST_V2_VERSION,
            digest_algorithm: "sha256".to_string(),
            digest: crate::artifacts::state_auth::sha256_hex(&normalized),
        },
        objective_profile: manifest.objective_profile.clone(),
        provider: EvalHarnessProviderClaim {
            kind: EvalHarnessProviderKind::LocalFake,
            network_providers: false,
        },
        eligibility: EvalHarnessEligibility {
            status: EvalHarnessEligibilityStatus::Ineligible,
            limitations: vec![
                EvalHarnessLimitation::EquivalentIsolatedStateNotObserved,
                EvalHarnessLimitation::GoalToIntegrationNotExecuted,
                EvalHarnessLimitation::RequiredPerProfileMetricsNotCaptured,
                EvalHarnessLimitation::ComparabilityNotEstablished,
                EvalHarnessLimitation::ParetoSummaryNotAvailable,
            ],
        },
    })
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

impl EvalHarnessManifestV2 {
    fn validate(&self) -> Result<(), EvalHarnessV2Error> {
        if self.version != EVAL_HARNESS_MANIFEST_V2_VERSION {
            return Err(EvalHarnessError::UnsupportedManifestVersion {
                found: self.version,
                supported: EVAL_HARNESS_MANIFEST_V2_VERSION,
            }
            .into());
        }
        require_nonempty("experiment_id", &self.experiment_id)?;
        validate_content_binding("spec", &self.spec)?;
        validate_content_binding("goal", &self.goal)?;
        validate_repository_base(&self.repository_base)?;
        if self.limits.wall_time_seconds == 0 {
            return Err(
                invalid_manifest("limits.wall_time_seconds", "must be greater than zero").into(),
            );
        }
        if self.limits.dispatch_limit == 0 {
            return Err(
                invalid_manifest("limits.dispatch_limit", "must be greater than zero").into(),
            );
        }
        if self.held_out_validations.is_empty() {
            return Err(invalid_manifest(
                "held_out_validations",
                "at least one held-out validation is required",
            )
            .into());
        }
        if self.held_out_validations.len() > crate::evaluation::MAX_EVALUATION_HELD_OUT_VALIDATIONS
        {
            return Err(invalid_manifest(
                "held_out_validations",
                format!(
                    "at most {} bindings are supported",
                    crate::evaluation::MAX_EVALUATION_HELD_OUT_VALIDATIONS
                ),
            )
            .into());
        }
        let mut held_out_ids = BTreeSet::new();
        for (index, binding) in self.held_out_validations.iter().enumerate() {
            let prefix = format!("held_out_validations[{index}]");
            require_nonempty(&format!("{prefix}.id"), &binding.id)?;
            validate_sha256_digest(&format!("{prefix}.content_digest"), &binding.content_digest)?;
            if !held_out_ids.insert(binding.id.as_str()) {
                return Err(invalid_manifest(
                    "held_out_validations",
                    format!("duplicate held-out validation id '{}'", binding.id),
                )
                .into());
            }
        }
        if self.repetition_count == 0
            || self.repetition_count > crate::evaluation::MAX_EVALUATION_REPETITIONS
        {
            return Err(invalid_manifest(
                "repetition_count",
                format!(
                    "must be between 1 and {}",
                    crate::evaluation::MAX_EVALUATION_REPETITIONS
                ),
            )
            .into());
        }
        validate_profiles(&self.profiles)?;
        self.objective_profile.profile.validate().map_err(|error| {
            invalid_manifest("objective_profile", format!("invalid binding: {error}"))
        })?;
        validate_provider_request(&self.provider_request)
    }
}

/// Apply the provider safety gate without invoking any provider adapter.
pub fn validate_provider_request(
    request: &EvalHarnessProviderRequest,
) -> Result<(), EvalHarnessV2Error> {
    match (request.kind, request.allow_real_provider) {
        (EvalHarnessProviderKind::LocalFake, false) => Ok(()),
        (EvalHarnessProviderKind::LocalFake, true) => Err(invalid_manifest(
            "provider_request.allow_real_provider",
            "must remain false for local_fake",
        )
        .into()),
        (EvalHarnessProviderKind::RealProvider, false) => {
            Err(EvalHarnessV2Error::RealProviderOptInRequired)
        }
        (EvalHarnessProviderKind::RealProvider, true) => {
            Err(EvalHarnessV2Error::RealProviderUnavailable)
        }
    }
}

fn validate_profiles(profiles: &[EvalHarnessProfile]) -> Result<(), EvalHarnessError> {
    if profiles.is_empty() {
        return Err(invalid_manifest(
            "profiles",
            "at least one profile is required",
        ));
    }
    if profiles.len() > MAX_PROFILES {
        return Err(invalid_manifest(
            "profiles",
            format!("at most {MAX_PROFILES} profiles are supported"),
        ));
    }

    let mut seen_ids = BTreeSet::new();
    for (index, profile) in profiles.iter().enumerate() {
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

fn validate_content_binding(
    field: &str,
    binding: &EvalHarnessContentBinding,
) -> Result<(), EvalHarnessError> {
    require_nonempty(&format!("{field}.id"), &binding.id)?;
    validate_sha256_digest(&format!("{field}.content_digest"), &binding.content_digest)
}

fn validate_repository_base(base: &EvalHarnessRepositoryBase) -> Result<(), EvalHarnessError> {
    let valid_length = matches!(base.object_id.len(), 40 | 64);
    if !valid_length || !is_lowercase_hex(&base.object_id) {
        return Err(invalid_manifest(
            "repository_base.object_id",
            "must be a full lowercase 40- or 64-character Git object id",
        ));
    }
    Ok(())
}

fn validate_sha256_digest(field: &str, value: &str) -> Result<(), EvalHarnessError> {
    if value.len() != 64 || !is_lowercase_hex(value) {
        return Err(invalid_manifest(
            field,
            "must be a lowercase 64-character SHA-256 digest",
        ));
    }
    Ok(())
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
