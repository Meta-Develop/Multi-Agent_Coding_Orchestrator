use super::{
    bind_v2_experiment, parse_manifest, parse_manifest_v2, run_local_fake_harness,
    EvalHarnessEligibilityStatus, EvalHarnessError, EvalHarnessLimitation, EvalHarnessProviderKind,
    EvalHarnessProviderRequest, EvalHarnessV2Error, OutcomeStatus, EVAL_HARNESS_RESULT_SCHEMA,
    EVAL_HARNESS_RESULT_VERSION, LOCAL_FAKE_PROVIDER_ID,
};
use crate::objective_profile::{
    default_objective_profile, ObjectiveProfileSource, ResolvedObjectiveProfile,
};
use serde_json::{json, Value};

const FIXTURE_MANIFEST: &str = include_str!("../../tests/fixtures/eval_harness/manifest-v1.json");

fn fixture_manifest() -> super::EvalHarnessManifest {
    parse_manifest(FIXTURE_MANIFEST.as_bytes()).expect("committed eval harness manifest")
}

#[test]
fn local_fake_harness_records_mix_and_outcomes() {
    let manifest = fixture_manifest();
    let results = run_local_fake_harness(&manifest).expect("run local fake harness");

    assert_eq!(results.version, EVAL_HARNESS_RESULT_VERSION);
    assert_eq!(results.schema, EVAL_HARNESS_RESULT_SCHEMA);
    assert_eq!(results.experiment_id, manifest.experiment_id);
    assert_eq!(results.task, manifest.task);
    assert_eq!(results.provider.kind, EvalHarnessProviderKind::LocalFake);
    assert!(!results.provider.network_providers);
    assert_eq!(results.runs.len(), manifest.profiles.len());

    for (profile, run) in manifest.profiles.iter().zip(&results.runs) {
        assert_eq!(run.profile_id, profile.id);
        assert_eq!(run.mix.len(), profile.mix.len());
        assert_eq!(run.outcomes.len(), profile.mix.len());
        for (binding, (recorded, outcome)) in
            profile.mix.iter().zip(run.mix.iter().zip(&run.outcomes))
        {
            assert_eq!(recorded.role, binding.role);
            assert_eq!(recorded.model, binding.model);
            assert_eq!(outcome.role, binding.role);
            assert_eq!(outcome.model, binding.model);
            assert_eq!(
                outcome.request_id,
                format!("{}:{}", profile.id, binding.role.as_str())
            );
            assert_eq!(outcome.provider_id, LOCAL_FAKE_PROVIDER_ID);
            assert_eq!(outcome.status, OutcomeStatus::Completed);
            assert!(outcome.usage.total_tokens > 0);
            assert!(outcome
                .proposal_summary
                .as_deref()
                .is_some_and(|summary| summary.contains(binding.role.as_str())
                    && summary.contains(&binding.model)));
            assert!(outcome.error.is_none());
        }
        assert!(run.totals.total_tokens > 0);
    }
}

#[test]
fn local_fake_harness_is_reproducible() {
    let manifest = fixture_manifest();
    let first = run_local_fake_harness(&manifest).expect("first run");
    let second = run_local_fake_harness(&manifest).expect("second run");
    assert_eq!(first, second);
}

#[test]
fn local_fake_harness_refuses_real_provider() {
    let mut manifest = fixture_manifest();
    manifest.provider = EvalHarnessProviderKind::RealProvider;
    let error = run_local_fake_harness(&manifest).expect_err("real provider must be refused");
    assert_eq!(error, EvalHarnessError::NetworkProviderRefused);
}

#[test]
fn parse_manifest_refuses_unsupported_version_and_network_provider_json() {
    let version_error = parse_manifest(
        br#"{
            "version": 99,
            "experiment_id": "x",
            "task": "task",
            "provider": "local_fake",
            "profiles": [{"id": "p", "mix": [{"role": "planner", "model": "fake"}]}]
        }"#,
    )
    .expect_err("unsupported version");
    assert_eq!(
        version_error,
        EvalHarnessError::UnsupportedManifestVersion {
            found: 99,
            supported: 1
        }
    );

    let provider_error = parse_manifest(
        br#"{
            "version": 1,
            "experiment_id": "x",
            "task": "task",
            "provider": "real_provider",
            "profiles": [{"id": "p", "mix": [{"role": "planner", "model": "fake"}]}]
        }"#,
    )
    .expect_err("real provider JSON");
    assert_eq!(provider_error, EvalHarnessError::NetworkProviderRefused);
}

#[test]
fn parse_manifest_rejects_duplicate_profile_ids() {
    let error = parse_manifest(
        br#"{
            "version": 1,
            "experiment_id": "x",
            "task": "task",
            "provider": "local_fake",
            "profiles": [
                {"id": "dup", "mix": [{"role": "planner", "model": "fake"}]},
                {"id": "dup", "mix": [{"role": "worker", "model": "fake"}]}
            ]
        }"#,
    )
    .expect_err("duplicate profile ids");
    match error {
        EvalHarnessError::InvalidManifest { field, message } => {
            assert_eq!(field, "profiles");
            assert!(message.contains("duplicate profile id"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn harness_records_scripted_fake_failure_without_network() {
    let manifest = parse_manifest(
        br#"{
            "version": 1,
            "experiment_id": "scripted-failure",
            "task": "observe a planned local-fake failure",
            "provider": "local_fake",
            "profiles": [{
                "id": "planner-fails",
                "mix": [
                    {
                        "role": "planner",
                        "model": "fake-frontier",
                        "scripted_failure": "planned local-fake failure"
                    },
                    {"role": "worker", "model": "fake-fast"}
                ]
            }]
        }"#,
    )
    .expect("scripted failure manifest");
    let results = run_local_fake_harness(&manifest).expect("run with scripted failure");
    assert!(!results.provider.network_providers);
    assert_eq!(results.runs[0].outcomes[0].status, OutcomeStatus::Failed);
    assert!(results.runs[0].outcomes[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("planned local-fake failure")));
    assert_eq!(results.runs[0].outcomes[1].status, OutcomeStatus::Completed);
}

#[test]
fn serialized_result_matches_schema_document_invariants() {
    let results = run_local_fake_harness(&fixture_manifest()).expect("run");
    let value = serde_json::to_value(&results).expect("serialize result");
    assert_eq!(value["version"], 1);
    assert_eq!(value["schema"], EVAL_HARNESS_RESULT_SCHEMA);
    assert_eq!(value["provider"]["kind"], "local_fake");
    assert_eq!(value["provider"]["network_providers"], false);
    assert!(value["task_digest"].as_str().is_some_and(|digest| {
        digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit())
    }));

    let schema: Value = serde_json::from_str(include_str!(
        "../../schemas/eval-harness-result-v1.schema.json"
    ))
    .expect("parse result schema");
    assert_eq!(
        schema["$id"],
        "https://raw.githubusercontent.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/main/schemas/eval-harness-result-v1.schema.json"
    );
    for key in [
        "version",
        "schema",
        "experiment_id",
        "task",
        "task_digest",
        "provider",
        "runs",
    ] {
        assert!(
            schema["required"]
                .as_array()
                .expect("schema required")
                .iter()
                .any(|required| required == key),
            "schema omitted required {key}"
        );
        assert!(value.get(key).is_some(), "result omitted {key}");
    }
}

fn complete_v2_manifest(provider_request: Value) -> Value {
    let objective_profile = ResolvedObjectiveProfile {
        profile: default_objective_profile()
            .binding()
            .expect("built-in objective profile binding"),
        source: ObjectiveProfileSource::BuiltIn,
    };
    json!({
        "version": 2,
        "experiment_id": "issue-26-complete-binding",
        "spec": {
            "id": "issue-26",
            "content_digest": "1".repeat(64)
        },
        "goal": {
            "id": "goal-reproducible-model-mix",
            "content_digest": "2".repeat(64)
        },
        "repository_base": {
            "object_id": "0123456789abcdef0123456789abcdef01234567"
        },
        "limits": {
            "wall_time_seconds": 900,
            "dispatch_limit": 12
        },
        "held_out_validations": [{
            "id": "held-out-eval-harness",
            "content_digest": "3".repeat(64)
        }],
        "repetition_count": 3,
        "provider_request": provider_request,
        "profiles": [{
            "id": "balanced",
            "mix": [
                {"role": "planner", "model": "fake-planner"},
                {"role": "worker", "model": "fake-worker"},
                {"role": "auditor", "model": "fake-auditor"}
            ]
        }],
        "objective_profile": objective_profile
    })
}

#[test]
fn v2_manifest_binds_every_declared_input_and_shared_objective_profile() {
    let mut value = complete_v2_manifest(json!({}));
    value
        .as_object_mut()
        .expect("v2 fixture object")
        .remove("provider_request");
    let encoded = serde_json::to_vec(&value).expect("serialize v2 fixture");
    let manifest = parse_manifest_v2(&encoded).expect("parse complete v2 manifest");

    assert_eq!(
        manifest.provider_request,
        EvalHarnessProviderRequest::default()
    );
    assert_eq!(manifest.spec.id, "issue-26");
    assert_eq!(manifest.goal.id, "goal-reproducible-model-mix");
    assert_eq!(manifest.repository_base.object_id.len(), 40);
    assert_eq!(manifest.limits.wall_time_seconds, 900);
    assert_eq!(manifest.limits.dispatch_limit, 12);
    assert_eq!(manifest.held_out_validations.len(), 1);
    assert_eq!(manifest.repetition_count, 3);
    assert_eq!(manifest.profiles.len(), 1);
    assert_eq!(
        manifest.objective_profile.source,
        ObjectiveProfileSource::BuiltIn
    );

    let result = bind_v2_experiment(&manifest).expect("bind v2 experiment inputs");
    let expected_digest = crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(&manifest).expect("serialize validated v2 manifest"),
    );
    assert_eq!(result.input_binding.manifest_version, 2);
    assert_eq!(
        result.input_binding.manifest_schema,
        super::EVAL_HARNESS_MANIFEST_V2_SCHEMA
    );
    assert_eq!(result.input_binding.digest_algorithm, "sha256");
    assert_eq!(result.input_binding.digest, expected_digest);
    assert_eq!(result.objective_profile, manifest.objective_profile);
    assert_eq!(
        result.eligibility.status,
        EvalHarnessEligibilityStatus::Ineligible
    );
    for limitation in [
        EvalHarnessLimitation::GoalToIntegrationNotExecuted,
        EvalHarnessLimitation::RequiredPerProfileMetricsNotCaptured,
        EvalHarnessLimitation::ComparabilityNotEstablished,
        EvalHarnessLimitation::ParetoSummaryNotAvailable,
    ] {
        assert!(result.eligibility.limitations.contains(&limitation));
    }

    let repeated = bind_v2_experiment(&manifest).expect("repeat v2 binding");
    assert_eq!(result, repeated);

    let machine_readable = serde_json::to_value(&result).expect("serialize v2 result");
    assert_eq!(
        machine_readable["schema"],
        super::EVAL_HARNESS_RESULT_V2_SCHEMA
    );
    assert_eq!(machine_readable["eligibility"]["status"], "ineligible");
    assert_eq!(
        machine_readable["objective_profile"]["profile"]["content_hash"],
        manifest.objective_profile.profile.content_hash
    );
}

#[test]
fn v2_real_provider_requires_explicit_opt_in() {
    let value = complete_v2_manifest(json!({
        "kind": "real_provider"
    }));
    let encoded = serde_json::to_vec(&value).expect("serialize real-provider request");
    let error = parse_manifest_v2(&encoded).expect_err("real provider needs explicit opt-in");
    assert_eq!(error, EvalHarnessV2Error::RealProviderOptInRequired);
}

#[test]
fn v2_real_provider_stays_inert_after_opt_in() {
    let value = complete_v2_manifest(json!({
        "kind": "real_provider",
        "allow_real_provider": true
    }));
    let encoded = serde_json::to_vec(&value).expect("serialize opted-in real request");
    let error = parse_manifest_v2(&encoded).expect_err("real provider remains unavailable");
    assert_eq!(error, EvalHarnessV2Error::RealProviderUnavailable);
}
