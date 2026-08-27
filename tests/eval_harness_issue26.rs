use anyhow::{Context, Result};
use multi_agent_coding_orchestrator::eval_harness::{
    execute_v2_local_fake, parse_manifest_v2, validate_v2_execution_results,
    EvalHarnessV2ExecutionError, V2ComparabilityStatus,
};
use serde_json::json;

const MANIFEST: &[u8] = include_bytes!("../src/eval_harness/fixtures/issue26-manifest-v2.json");

const EXPECTED_PROJECTION: &str =
    include_str!("../src/eval_harness/fixtures/issue26-expected-projection-v2.json");

fn execute() -> Result<(
    multi_agent_coding_orchestrator::eval_harness::EvalHarnessManifestV2,
    multi_agent_coding_orchestrator::eval_harness::EvalHarnessV2ExecutionResults,
)> {
    let manifest = parse_manifest_v2(MANIFEST).context("parse committed issue #26 manifest")?;
    let results = execute_v2_local_fake(&manifest).context("execute deterministic fake harness")?;
    validate_v2_execution_results(&manifest, &results)
        .context("validate comparable issue #26 results")?;
    Ok((manifest, results))
}

#[test]
fn issue26_fake_execution_is_reproducible_and_comparable() -> Result<()> {
    let (manifest, first) = execute()?;
    let second = execute_v2_local_fake(&manifest).context("repeat deterministic harness")?;
    assert_eq!(first, second);
    assert_eq!(
        first.comparability.status,
        V2ComparabilityStatus::Comparable
    );
    assert!(first.comparability.replay_verified);
    assert!(!first.production_eligible);
    assert_eq!(first.pareto_frontier.len(), 2);
    assert_eq!(
        first.objective_selection.profile_id,
        manifest.objective_profile.profile.id
    );
    assert_eq!(
        first.objective_selection.profile_hash,
        manifest.objective_profile.profile.content_hash
    );
    assert!(first.runs.iter().all(|run| run.initial_state_fingerprint
        == first.comparability.equivalent_initial_state_fingerprint));
    Ok(())
}

#[test]
fn issue26_validator_refuses_incomparable_and_tampered_inputs() -> Result<()> {
    let (manifest, valid) = execute()?;
    let assert_refused = |candidate| {
        let error = validate_v2_execution_results(&manifest, &candidate)
            .expect_err("tampered evidence must fail closed");
        assert!(matches!(
            error,
            EvalHarnessV2ExecutionError::Incomparable { .. }
        ));
    };

    let mut nondeterministic = valid.clone();
    nondeterministic.runs[0].final_state_fingerprint = "f".repeat(64);
    assert_refused(nondeterministic);

    let mut incomplete = valid.clone();
    incomplete.runs[0].roles.pop();
    assert_refused(incomplete);

    let mut missing_provenance = valid.clone();
    missing_provenance.runs[0].provenance.fixture_digest.clear();
    assert_refused(missing_provenance);

    let mut state_divergent = valid.clone();
    state_divergent.runs[0].initial_state_fingerprint = "0".repeat(64);
    assert_refused(state_divergent);

    let mut incomparable = valid.clone();
    incomparable.comparability.status = V2ComparabilityStatus::Incomparable;
    assert_refused(incomparable);

    let mut mix_inconsistent = valid.clone();
    mix_inconsistent.runs[0].mix[0].model = "tampered-model".to_string();
    assert_refused(mix_inconsistent);

    let mut missing_run = valid.clone();
    missing_run.runs.pop();
    assert_refused(missing_run);

    let mut non_finite = valid;
    non_finite.objective_selection.selected_score = f64::NAN;
    assert_refused(non_finite);
    Ok(())
}

#[test]
#[ignore = "operator entrypoint: emits the committed deterministic Fake evidence"]
fn issue26_fake_operator_entrypoint_runs_end_to_end() -> Result<()> {
    let (manifest, results) = execute()?;
    let repeated = execute_v2_local_fake(&manifest).context("repeat operator execution")?;
    assert_eq!(
        results, repeated,
        "operator rerun must be byte-stable as data"
    );

    let projection = json!({
        "version": results.version,
        "schema": results.schema,
        "experiment_id": results.experiment_id,
        "manifest_digest": results.manifest_digest,
        "fixture_digest": results.fixture.digest,
        "objective_citation": results.objective_citation,
        "run_fingerprints": results
            .runs
            .iter()
            .map(|run| (&run.profile_id, run.repetition, &run.record_fingerprint))
            .collect::<Vec<_>>(),
        "equivalent_initial_state_fingerprint": results
            .comparability
            .equivalent_initial_state_fingerprint,
        "pareto_frontier": results.pareto_frontier,
        "objective_selection": results.objective_selection,
        "production_eligible": results.production_eligible,
        "production_default_claim": results.production_default_claim,
    });
    let expected: serde_json::Value = serde_json::from_str(EXPECTED_PROJECTION)
        .context("parse committed canonical output projection")?;
    assert_eq!(
        projection, expected,
        "canonical operator projection drifted"
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&results).context("serialize operator JSON")?
    );
    Ok(())
}
