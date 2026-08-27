use super::{
    bind_v2_experiment, EvalHarnessManifestV2, EvalHarnessProviderClaim, EvalHarnessProviderKind,
    EvalHarnessRoleBinding, MixRole, EVAL_HARNESS_MANIFEST_V2_SCHEMA,
    EVAL_HARNESS_RESULT_V2_VERSION, LOCAL_FAKE_PROVIDER_ID,
};
use crate::llm::{
    FakeProvider, LlmProvider, LlmRequest, PromptContext, Redactor, Usage, WorkProposal,
};
use crate::objective_profile::{
    select_from_frontier, FrontierAxes, ObjectiveProfileSource, ObjectiveSelection,
    ResolvedObjectiveProfile,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const EXECUTION_FIXTURE: &[u8] = include_bytes!("fixtures/issue26-execution-fixture-v1.json");
const RESULT_SCHEMA: &str = "eval_harness_comparable_fake_results_v2";
const FIXTURE_SCHEMA: &str = "eval_harness_fake_execution_fixture_v1";
const PRODUCTION_DEFAULT_REFUSAL: &str = "ineligible_to_justify_production_default";

#[derive(Debug, Error)]
pub enum EvalHarnessV2ExecutionError {
    #[error("invalid deterministic execution fixture: {0}")]
    Fixture(String),
    #[error("local Fake execution failed: {0}")]
    Execution(String),
    #[error("incomparable eval-harness evidence at '{field}': {message}")]
    Incomparable { field: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalHarnessV2ExecutionResults {
    pub version: u32,
    pub schema: String,
    pub experiment_id: String,
    pub manifest_schema: String,
    pub manifest_digest: String,
    pub fixture: V2FixtureProvenance,
    pub provider: EvalHarnessProviderClaim,
    pub objective_profile: ResolvedObjectiveProfile,
    pub objective_citation: V2ObjectiveCitation,
    pub runs: Vec<V2ExecutionRecord>,
    pub profile_summaries: Vec<V2ProfileSummary>,
    pub pareto_frontier: Vec<String>,
    pub objective_selection: ObjectiveSelection,
    pub comparability: V2Comparability,
    pub production_eligible: bool,
    pub production_default_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2FixtureProvenance {
    pub schema: String,
    pub version: u32,
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2ObjectiveCitation {
    pub id: String,
    pub version: u32,
    pub content_hash: String,
    pub source: ObjectiveProfileSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2ExecutionRecord {
    pub profile_id: String,
    pub repetition: u32,
    pub provenance: V2RunProvenance,
    pub mix: Vec<V2RecordedRole>,
    pub initial_state_fingerprint: String,
    pub final_state_fingerprint: String,
    pub stages: Vec<V2StageWitness>,
    pub roles: Vec<V2RoleObservation>,
    pub metrics: V2Metrics,
    pub integration_outcome: V2IntegrationOutcome,
    pub record_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2RunProvenance {
    pub manifest_digest: String,
    pub fixture_digest: String,
    pub fixture_version: u32,
    pub provider_id: String,
    pub deterministic_local_fake: bool,
    pub network_access: bool,
    pub real_provider_adapter_invoked: bool,
    pub mix_digest: String,
    pub objective_id: String,
    pub objective_hash: String,
    pub objective_source: ObjectiveProfileSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2RecordedRole {
    pub role: MixRole,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V2ExecutionStage {
    GoalBound,
    SupervisionComplete,
    IntegrationPreview,
    IntegrationApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2StageWitness {
    pub stage: V2ExecutionStage,
    pub input_fingerprint: String,
    pub output_fingerprint: String,
    pub logical_tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2RoleObservation {
    pub role: MixRole,
    pub model: String,
    pub request_id: String,
    pub provider_id: String,
    pub usage: Usage,
    pub cost_microusd: u64,
    pub cost_provenance: String,
    pub response_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Metrics {
    pub total_usage: Usage,
    pub total_cost_microusd: u64,
    pub deterministic_wall_time_ms: u64,
    pub wall_time_provenance: String,
    pub logical_time_ticks: u64,
    pub churn_count: u64,
    pub conflict_count: u64,
    pub loc_added: u64,
    pub loc_deleted: u64,
    pub diff_bytes: u64,
    pub held_out: Vec<V2HeldOutEvidence>,
    pub review: V2ReviewEvidence,
    pub quality: V2Quality,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2HeldOutEvidence {
    pub id: String,
    pub content_digest: String,
    pub executed: bool,
    pub assertions_run: u32,
    pub assertions_passed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2ReviewEvidence {
    pub findings: Vec<V2ReviewFinding>,
    pub breadth_checks_run: u32,
    pub breadth_checks_passed: u32,
    pub anti_shortcut_checks_run: u32,
    pub anti_shortcut_checks_passed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2ReviewFinding {
    pub id: String,
    pub severity: String,
    pub disposition: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Quality {
    pub held_out_basis_points: u32,
    pub breadth_basis_points: u32,
    pub anti_shortcut_basis_points: u32,
    pub overall_basis_points: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V2IntegrationOutcome {
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2ProfileSummary {
    pub profile_id: String,
    pub repetitions: u32,
    pub mean_cost_microusd: u64,
    pub mean_tokens: u64,
    pub mean_wall_time_ms: u64,
    pub mean_churn_count: u64,
    pub mean_review_findings: u64,
    pub quality: V2Quality,
    pub pareto_optimal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V2ComparabilityStatus {
    Comparable,
    Incomparable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Comparability {
    pub status: V2ComparabilityStatus,
    pub equivalent_initial_state_fingerprint: String,
    pub expected_run_count: usize,
    pub validated_run_count: usize,
    pub replay_verified: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FakeExecutionFixture {
    version: u32,
    schema: String,
    id: String,
    state_seed: String,
    logical_tick_ms: u64,
    input_token_cost_microusd: u64,
    output_token_cost_microusd: u64,
    models: Vec<FakeModelFixture>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FakeModelFixture {
    id: String,
    response_padding: String,
    held_out_basis_points: u32,
    breadth_basis_points: u32,
    anti_shortcut_basis_points: u32,
    churn_count: u64,
    conflict_count: u64,
    loc_added: u64,
    loc_deleted: u64,
    diff_bytes: u64,
}

pub fn execute_v2_local_fake(
    manifest: &EvalHarnessManifestV2,
) -> Result<EvalHarnessV2ExecutionResults, EvalHarnessV2ExecutionError> {
    let fixture = parse_fixture()?;
    validate_execution_manifest(manifest, &fixture)?;
    execute_validated(manifest, &fixture)
}

pub fn validate_v2_execution_results(
    manifest: &EvalHarnessManifestV2,
    results: &EvalHarnessV2ExecutionResults,
) -> Result<(), EvalHarnessV2ExecutionError> {
    let fixture = parse_fixture()?;
    validate_execution_manifest(manifest, &fixture)?;
    validate_structure(manifest, results)?;
    let expected = execute_validated(manifest, &fixture)?;
    if results != &expected {
        return Err(incomparable(
            "results.replay",
            "records do not equal a repeated deterministic execution",
        ));
    }
    Ok(())
}

fn parse_fixture() -> Result<FakeExecutionFixture, EvalHarnessV2ExecutionError> {
    let fixture: FakeExecutionFixture = serde_json::from_slice(EXECUTION_FIXTURE)
        .map_err(|error| EvalHarnessV2ExecutionError::Fixture(error.to_string()))?;
    if fixture.version != 1 || fixture.schema != FIXTURE_SCHEMA || fixture.logical_tick_ms == 0 {
        return Err(EvalHarnessV2ExecutionError::Fixture(
            "unsupported schema/version or zero logical tick".to_string(),
        ));
    }
    let mut ids = BTreeSet::new();
    for model in &fixture.models {
        if model.id.trim().is_empty()
            || !ids.insert(model.id.as_str())
            || model.held_out_basis_points > 10_000
            || model.breadth_basis_points > 10_000
            || model.anti_shortcut_basis_points > 10_000
        {
            return Err(EvalHarnessV2ExecutionError::Fixture(
                "model bindings must be unique, named, and use bounded quality evidence"
                    .to_string(),
            ));
        }
    }
    Ok(fixture)
}

fn validate_execution_manifest(
    manifest: &EvalHarnessManifestV2,
    fixture: &FakeExecutionFixture,
) -> Result<(), EvalHarnessV2ExecutionError> {
    bind_v2_experiment(manifest).map_err(|error| incomparable("manifest", error.to_string()))?;
    if manifest.provider_request.kind != EvalHarnessProviderKind::LocalFake
        || manifest.provider_request.allow_real_provider
    {
        return Err(incomparable(
            "provider_request",
            "comparable execution requires default local_fake with real-provider opt-in disabled",
        ));
    }
    if manifest.profiles.len() < 2 {
        return Err(incomparable(
            "profiles",
            "at least two distinct model mixes are required for comparison",
        ));
    }
    let required_roles = BTreeSet::from([
        MixRole::Planner,
        MixRole::Worker,
        MixRole::Supervisor,
        MixRole::Auditor,
    ]);
    let fixture_models = fixture
        .models
        .iter()
        .map(|model| model.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut mix_digests = BTreeSet::new();
    for profile in &manifest.profiles {
        let roles = profile
            .mix
            .iter()
            .map(|binding| binding.role)
            .collect::<BTreeSet<_>>();
        if roles != required_roles {
            return Err(incomparable(
                format!("profiles.{}.mix", profile.id),
                "planner, worker, supervisor, and auditor coverage is required",
            ));
        }
        if profile.mix.iter().any(|binding| {
            binding.scripted_failure.is_some() || !fixture_models.contains(binding.model.as_str())
        }) {
            return Err(incomparable(
                format!("profiles.{}.mix", profile.id),
                "all roles must resolve to successful committed Fake fixture models",
            ));
        }
        let digest = digest(&profile.mix)?;
        if !mix_digests.insert(digest) {
            return Err(incomparable(
                "profiles",
                "duplicate model mixes are not comparable",
            ));
        }
    }
    Ok(())
}

fn execute_validated(
    manifest: &EvalHarnessManifestV2,
    fixture: &FakeExecutionFixture,
) -> Result<EvalHarnessV2ExecutionResults, EvalHarnessV2ExecutionError> {
    let binding = bind_v2_experiment(manifest)
        .map_err(|error| incomparable("manifest", error.to_string()))?;
    let fixture_digest = digest(fixture)?;
    let initial = digest(&(
        &fixture.state_seed,
        &manifest.repository_base.object_id,
        &manifest.spec,
        &manifest.goal,
    ))?;
    let fixture_provenance = V2FixtureProvenance {
        schema: fixture.schema.clone(),
        version: fixture.version,
        id: fixture.id.clone(),
        digest: fixture_digest.clone(),
    };
    let citation = V2ObjectiveCitation {
        id: manifest.objective_profile.profile.id.clone(),
        version: manifest.objective_profile.profile.version,
        content_hash: manifest.objective_profile.profile.content_hash.clone(),
        source: manifest.objective_profile.source,
    };
    let mut runs = Vec::new();
    for profile in &manifest.profiles {
        for repetition in 1..=manifest.repetition_count {
            runs.push(execute_record(
                manifest,
                profile.id.as_str(),
                &profile.mix,
                repetition,
                fixture,
                &binding.input_binding.digest,
                &fixture_digest,
                &initial,
            )?);
        }
    }
    let mut summaries = summarize(manifest, &runs)?;
    let frontier = pareto_frontier(&summaries);
    for summary in &mut summaries {
        summary.pareto_optimal = frontier.contains(&summary.profile_id);
    }
    let max_cost = summaries
        .iter()
        .map(|item| item.mean_cost_microusd)
        .max()
        .unwrap_or(1);
    let max_tokens = summaries
        .iter()
        .map(|item| item.mean_tokens)
        .max()
        .unwrap_or(1);
    let max_time = summaries
        .iter()
        .map(|item| item.mean_wall_time_ms)
        .max()
        .unwrap_or(1);
    let max_churn = summaries
        .iter()
        .map(|item| item.mean_churn_count)
        .max()
        .unwrap_or(1);
    let max_review = summaries
        .iter()
        .map(|item| item.mean_review_findings)
        .max()
        .unwrap_or(1);
    let points = summaries
        .iter()
        .filter(|summary| frontier.contains(&summary.profile_id))
        .map(|summary| {
            (
                summary.profile_id.clone(),
                FrontierAxes {
                    held_out_quality_basis_points: summary.quality.held_out_basis_points,
                    breadth_quality_basis_points: summary.quality.breadth_basis_points,
                    anti_shortcut_quality_basis_points: summary.quality.anti_shortcut_basis_points,
                    monetary_cost: ratio(summary.mean_cost_microusd, max_cost),
                    quota_consumption: ratio(summary.mean_tokens, max_tokens),
                    latency: ratio(summary.mean_wall_time_ms, max_time),
                    retry_rework: ratio(summary.mean_churn_count, max_churn),
                    human_review: ratio(summary.mean_review_findings, max_review),
                },
            )
        })
        .collect::<Vec<_>>();
    let objective_selection = select_from_frontier(&manifest.objective_profile, &points)
        .map_err(|error| incomparable("objective_selection", error.to_string()))?
        .ok_or_else(|| incomparable("pareto_frontier", "frontier unexpectedly empty"))?;
    Ok(EvalHarnessV2ExecutionResults {
        version: EVAL_HARNESS_RESULT_V2_VERSION,
        schema: RESULT_SCHEMA.to_string(),
        experiment_id: manifest.experiment_id.clone(),
        manifest_schema: EVAL_HARNESS_MANIFEST_V2_SCHEMA.to_string(),
        manifest_digest: binding.input_binding.digest.clone(),
        fixture: fixture_provenance,
        provider: EvalHarnessProviderClaim {
            kind: EvalHarnessProviderKind::LocalFake,
            network_providers: false,
        },
        objective_profile: manifest.objective_profile.clone(),
        objective_citation: citation,
        runs,
        profile_summaries: summaries,
        pareto_frontier: frontier,
        objective_selection,
        comparability: V2Comparability {
            status: V2ComparabilityStatus::Comparable,
            equivalent_initial_state_fingerprint: initial,
            expected_run_count: manifest.profiles.len() * manifest.repetition_count as usize,
            validated_run_count: manifest.profiles.len() * manifest.repetition_count as usize,
            replay_verified: true,
        },
        production_eligible: false,
        production_default_claim: PRODUCTION_DEFAULT_REFUSAL.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_record(
    manifest: &EvalHarnessManifestV2,
    profile_id: &str,
    mix: &[EvalHarnessRoleBinding],
    repetition: u32,
    fixture: &FakeExecutionFixture,
    manifest_digest: &str,
    fixture_digest: &str,
    initial: &str,
) -> Result<V2ExecutionRecord, EvalHarnessV2ExecutionError> {
    let mix_digest = digest(&mix)?;
    let goal_state = digest(&(initial, &manifest.goal.id, &manifest.goal.content_digest))?;
    let mut observations = Vec::new();
    let mut total_usage = Usage::default();
    let mut total_cost = 0_u64;
    let mut qualities = Vec::new();
    for binding in mix {
        let model = fixture
            .models
            .iter()
            .find(|candidate| candidate.id == binding.model)
            .ok_or_else(|| incomparable("mix.model", "model absent from fixture"))?;
        let request_id = format!(
            "{}:{profile_id}:{repetition}:{}",
            manifest.experiment_id,
            binding.role.as_str()
        );
        let summary = format!(
            "local Fake lifecycle role={} model={} {}",
            binding.role.as_str(),
            binding.model,
            model.response_padding
        );
        let mut provider = FakeProvider::new(LOCAL_FAKE_PROVIDER_ID, binding.model.clone());
        provider.push_response(&request_id, WorkProposal::summary(summary));
        let prompt = PromptContext::new(
            &manifest.goal.id,
            format!("eval-harness-v2-{}", binding.role.as_str()),
        )
        .assemble_prompt(&Redactor::new());
        let response = provider
            .complete(LlmRequest::new(
                request_id.clone(),
                binding.model.clone(),
                prompt,
            ))
            .map_err(|error| EvalHarnessV2ExecutionError::Execution(error.to_string()))?;
        let cost = (response.usage.input_tokens as u64)
            .saturating_mul(fixture.input_token_cost_microusd)
            .saturating_add(
                (response.usage.output_tokens as u64)
                    .saturating_mul(fixture.output_token_cost_microusd),
            );
        total_usage = total_usage.saturating_add(response.usage);
        total_cost = total_cost.saturating_add(cost);
        qualities.push(model);
        observations.push(V2RoleObservation {
            role: binding.role,
            model: binding.model.clone(),
            request_id,
            provider_id: response.provider_id,
            usage: response.usage,
            cost_microusd: cost,
            cost_provenance: "committed_local_fake_price_schedule_v1".to_string(),
            response_digest: digest(&response.proposal)?,
        });
    }
    let supervised = digest(&(
        &goal_state,
        observations
            .iter()
            .map(|item| (&item.role, &item.model, &item.response_digest))
            .collect::<Vec<_>>(),
    ))?;
    let final_state = digest(&(&supervised, "integration-applied", &mix_digest))?;
    let stages = vec![
        V2StageWitness {
            stage: V2ExecutionStage::GoalBound,
            input_fingerprint: initial.to_string(),
            output_fingerprint: goal_state.clone(),
            logical_tick: 1,
        },
        V2StageWitness {
            stage: V2ExecutionStage::SupervisionComplete,
            input_fingerprint: goal_state,
            output_fingerprint: supervised.clone(),
            logical_tick: 2,
        },
        V2StageWitness {
            stage: V2ExecutionStage::IntegrationPreview,
            input_fingerprint: supervised.clone(),
            output_fingerprint: final_state.clone(),
            logical_tick: 3,
        },
        V2StageWitness {
            stage: V2ExecutionStage::IntegrationApplied,
            input_fingerprint: supervised,
            output_fingerprint: final_state.clone(),
            logical_tick: 4,
        },
    ];
    let average = |value: fn(&FakeModelFixture) -> u32| -> u32 {
        qualities
            .iter()
            .map(|item| u64::from(value(item)))
            .sum::<u64>() as u32
            / qualities.len() as u32
    };
    let held_out = average(|item| item.held_out_basis_points);
    let breadth = average(|item| item.breadth_basis_points);
    let anti_shortcut = average(|item| item.anti_shortcut_basis_points);
    let weights = &manifest.objective_profile.profile.quality;
    let overall = ((u64::from(held_out) * u64::from(weights.held_out_percent)
        + u64::from(breadth) * u64::from(weights.breadth_percent)
        + u64::from(anti_shortcut) * u64::from(weights.anti_shortcut_percent))
        / 100) as u32;
    let metrics = V2Metrics {
        total_usage,
        total_cost_microusd: total_cost,
        deterministic_wall_time_ms: fixture.logical_tick_ms.saturating_mul(4),
        wall_time_provenance: "committed_deterministic_fake_clock_v1".to_string(),
        logical_time_ticks: 4,
        churn_count: qualities.iter().map(|item| item.churn_count).sum(),
        conflict_count: qualities.iter().map(|item| item.conflict_count).sum(),
        loc_added: qualities.iter().map(|item| item.loc_added).sum(),
        loc_deleted: qualities.iter().map(|item| item.loc_deleted).sum(),
        diff_bytes: qualities.iter().map(|item| item.diff_bytes).sum(),
        held_out: manifest
            .held_out_validations
            .iter()
            .map(|binding| V2HeldOutEvidence {
                id: binding.id.clone(),
                content_digest: binding.content_digest.clone(),
                executed: true,
                assertions_run: 100,
                assertions_passed: held_out / 100,
            })
            .collect(),
        review: V2ReviewEvidence {
            findings: vec![V2ReviewFinding {
                id: format!("{profile_id}-fixture-review"),
                severity: "informational".to_string(),
                disposition: "accepted_fake_fixture_evidence".to_string(),
            }],
            breadth_checks_run: 100,
            breadth_checks_passed: breadth / 100,
            anti_shortcut_checks_run: 100,
            anti_shortcut_checks_passed: anti_shortcut / 100,
        },
        quality: V2Quality {
            held_out_basis_points: held_out,
            breadth_basis_points: breadth,
            anti_shortcut_basis_points: anti_shortcut,
            overall_basis_points: overall,
        },
    };
    let mix = mix
        .iter()
        .map(|binding| V2RecordedRole {
            role: binding.role,
            model: binding.model.clone(),
        })
        .collect::<Vec<_>>();
    let provenance = V2RunProvenance {
        manifest_digest: manifest_digest.to_string(),
        fixture_digest: fixture_digest.to_string(),
        fixture_version: fixture.version,
        provider_id: LOCAL_FAKE_PROVIDER_ID.to_string(),
        deterministic_local_fake: true,
        network_access: false,
        real_provider_adapter_invoked: false,
        mix_digest,
        objective_id: manifest.objective_profile.profile.id.clone(),
        objective_hash: manifest.objective_profile.profile.content_hash.clone(),
        objective_source: manifest.objective_profile.source,
    };
    let record_fingerprint = digest(&(
        profile_id,
        repetition,
        &provenance,
        &mix,
        initial,
        &final_state,
        &stages,
        &observations,
        &metrics,
    ))?;
    Ok(V2ExecutionRecord {
        profile_id: profile_id.to_string(),
        repetition,
        provenance,
        mix,
        initial_state_fingerprint: initial.to_string(),
        final_state_fingerprint: final_state,
        stages,
        roles: observations,
        metrics,
        integration_outcome: V2IntegrationOutcome::Applied,
        record_fingerprint,
    })
}

fn summarize(
    manifest: &EvalHarnessManifestV2,
    runs: &[V2ExecutionRecord],
) -> Result<Vec<V2ProfileSummary>, EvalHarnessV2ExecutionError> {
    manifest
        .profiles
        .iter()
        .map(|profile| {
            let selected = runs
                .iter()
                .filter(|run| run.profile_id == profile.id)
                .collect::<Vec<_>>();
            let count = selected.len() as u64;
            let first = selected
                .first()
                .ok_or_else(|| incomparable("runs", "profile coverage missing"))?;
            Ok(V2ProfileSummary {
                profile_id: profile.id.clone(),
                repetitions: selected.len() as u32,
                mean_cost_microusd: selected
                    .iter()
                    .map(|run| run.metrics.total_cost_microusd)
                    .sum::<u64>()
                    / count,
                mean_tokens: selected
                    .iter()
                    .map(|run| run.metrics.total_usage.total_tokens as u64)
                    .sum::<u64>()
                    / count,
                mean_wall_time_ms: selected
                    .iter()
                    .map(|run| run.metrics.deterministic_wall_time_ms)
                    .sum::<u64>()
                    / count,
                mean_churn_count: selected
                    .iter()
                    .map(|run| run.metrics.churn_count)
                    .sum::<u64>()
                    / count,
                mean_review_findings: selected
                    .iter()
                    .map(|run| run.metrics.review.findings.len() as u64)
                    .sum::<u64>()
                    / count,
                quality: first.metrics.quality,
                pareto_optimal: false,
            })
        })
        .collect()
}

fn pareto_frontier(summaries: &[V2ProfileSummary]) -> Vec<String> {
    summaries
        .iter()
        .filter(|candidate| {
            !summaries.iter().any(|other| {
                other.profile_id != candidate.profile_id
                    && other.mean_cost_microusd <= candidate.mean_cost_microusd
                    && other.quality.held_out_basis_points
                        >= candidate.quality.held_out_basis_points
                    && other.quality.breadth_basis_points >= candidate.quality.breadth_basis_points
                    && other.quality.anti_shortcut_basis_points
                        >= candidate.quality.anti_shortcut_basis_points
                    && (other.mean_cost_microusd < candidate.mean_cost_microusd
                        || other.quality != candidate.quality)
            })
        })
        .map(|summary| summary.profile_id.clone())
        .collect()
}

fn validate_structure(
    manifest: &EvalHarnessManifestV2,
    results: &EvalHarnessV2ExecutionResults,
) -> Result<(), EvalHarnessV2ExecutionError> {
    if results.comparability.status != V2ComparabilityStatus::Comparable
        || !results.comparability.replay_verified
        || results.production_eligible
        || results.production_default_claim != PRODUCTION_DEFAULT_REFUSAL
    {
        return Err(incomparable(
            "comparability",
            "explicit comparable Fake-only refusal state is required",
        ));
    }
    if results.manifest_digest.trim().is_empty()
        || results.fixture.digest.trim().is_empty()
        || results.objective_citation.id.trim().is_empty()
        || results.objective_citation.content_hash.trim().is_empty()
        || results
            .comparability
            .equivalent_initial_state_fingerprint
            .trim()
            .is_empty()
    {
        return Err(incomparable(
            "provenance",
            "required provenance is missing or empty",
        ));
    }
    if results.provider.kind != EvalHarnessProviderKind::LocalFake
        || results.provider.network_providers
    {
        return Err(incomparable(
            "provider",
            "only no-network local Fake results are comparable",
        ));
    }
    let expected_count = manifest.profiles.len() * manifest.repetition_count as usize;
    if results.runs.len() != expected_count {
        return Err(incomparable(
            "runs",
            "profile x repetition coverage is incomplete",
        ));
    }
    let mut keys = BTreeSet::new();
    for run in &results.runs {
        if !keys.insert((run.profile_id.as_str(), run.repetition)) {
            return Err(incomparable("runs", "duplicate profile/repetition record"));
        }
        if run.initial_state_fingerprint
            != results.comparability.equivalent_initial_state_fingerprint
        {
            return Err(incomparable(
                "runs.initial_state_fingerprint",
                "isolated initial states diverged",
            ));
        }
        if run.provenance.manifest_digest.trim().is_empty()
            || run.provenance.fixture_digest.trim().is_empty()
            || run.provenance.objective_hash.trim().is_empty()
            || !run.provenance.deterministic_local_fake
            || run.provenance.network_access
            || run.provenance.real_provider_adapter_invoked
        {
            return Err(incomparable(
                "runs.provenance",
                "run provenance is missing or unsafe",
            ));
        }
        if run.roles.len() != run.mix.len() || run.stages.len() != 4 {
            return Err(incomparable(
                "runs.coverage",
                "role, metric, or lifecycle stage coverage is incomplete",
            ));
        }
        if run.metrics.held_out.len() != manifest.held_out_validations.len()
            || run
                .metrics
                .held_out
                .iter()
                .any(|item| !item.executed || item.assertions_run == 0)
            || run.metrics.review.breadth_checks_run == 0
            || run.metrics.review.anti_shortcut_checks_run == 0
            || run.metrics.review.findings.is_empty()
        {
            return Err(incomparable(
                "runs.metrics",
                "held-out or review-quality evidence is incomplete",
            ));
        }
        let preview = run
            .stages
            .iter()
            .find(|item| item.stage == V2ExecutionStage::IntegrationPreview);
        let applied = run
            .stages
            .iter()
            .find(|item| item.stage == V2ExecutionStage::IntegrationApplied);
        if preview.zip(applied).is_none_or(|(preview, applied)| {
            preview.input_fingerprint != applied.input_fingerprint
                || preview.output_fingerprint != applied.output_fingerprint
                || applied.output_fingerprint != run.final_state_fingerprint
        }) {
            return Err(incomparable(
                "runs.stages",
                "integration preview/apply fingerprints diverged",
            ));
        }
    }
    for profile in &manifest.profiles {
        for repetition in 1..=manifest.repetition_count {
            if !keys.contains(&(profile.id.as_str(), repetition)) {
                return Err(incomparable(
                    "runs",
                    "missing exact profile/repetition record",
                ));
            }
        }
    }
    if !results.objective_selection.selected_score.is_finite()
        || results
            .objective_selection
            .scores
            .values()
            .any(|score| !score.is_finite())
    {
        return Err(incomparable(
            "objective_selection",
            "non-finite objective metric",
        ));
    }
    Ok(())
}

fn ratio(value: u64, maximum: u64) -> f64 {
    if maximum == 0 {
        0.0
    } else {
        value as f64 / maximum as f64
    }
}

fn digest<T: Serialize + ?Sized>(value: &T) -> Result<String, EvalHarnessV2ExecutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EvalHarnessV2ExecutionError::Execution(error.to_string()))?;
    Ok(crate::artifacts::state_auth::sha256_hex(&bytes))
}

fn incomparable(
    field: impl Into<String>,
    message: impl Into<String>,
) -> EvalHarnessV2ExecutionError {
    EvalHarnessV2ExecutionError::Incomparable {
        field: field.into(),
        message: message.into(),
    }
}
