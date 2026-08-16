use anyhow::{Context, Result};
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn evaluation_cli_runs_committed_fake_manifest_as_json_without_cwd_writes() -> Result<()> {
    let working = TempDir::new().context("create empty evaluation cwd")?;
    let manifest_path = fixture_path("manifest-v1.json");
    let plan_path = fixture_path("hand-authored-plan-v1.json");

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("evaluation")
        .arg("run")
        .arg(&manifest_path)
        .arg("--plan-file")
        .arg(&plan_path)
        .arg("--repo")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("--json")
        .output()
        .context("run deterministic fake evaluation")?;

    assert!(
        output.status.success(),
        "fake evaluation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_stdout =
        fs::read(fixture_path("runs-v1.json")).context("read committed evaluation snapshot")?;
    assert_eq!(
        output.stdout, expected_stdout,
        "CLI stdout must exactly match the committed snapshot, including its final newline"
    );
    let results: Value =
        serde_json::from_slice(&output.stdout).context("parse evaluation results JSON")?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("parse fixture manifest")?;

    assert_eq!(results["experiment_id"], manifest["experiment_id"]);
    assert_eq!(results["fake_seed"], 26);
    assert_eq!(results["evidence"]["real_provider_executed"], false);
    assert_eq!(results["dispatch_comparability_claim"]["scope"], "dispatch");
    assert_eq!(
        results["dispatch_comparability_claim"]["provider_execution_difference_established"],
        false
    );
    assert_eq!(
        results["pareto_conclusion"]["status"],
        "refused_incomparable_dispatch_evidence"
    );
    assert!(results["dispatch_comparisons"]
        .as_array()
        .context("dispatch comparisons array")?
        .iter()
        .all(|comparison| {
            comparison["comparability"] == "incomparable"
                && comparison["execution_telemetry_comparability"] == "incomparable"
                && comparison["unavailable_reason"]
                    .as_str()
                    .is_some_and(|reason| {
                        reason.contains("supervisor execution telemetry schema v2")
                    })
        }));
    assert!(results["pareto_frontier"]
        .as_array()
        .context("Pareto frontier array")?
        .is_empty());

    let profiles = manifest["profiles"]
        .as_array()
        .context("manifest profiles array")?;
    let repetitions = manifest["repetitions"]
        .as_u64()
        .context("manifest repetition count")?;
    let runs = results["runs"].as_array().context("results runs array")?;
    assert_eq!(runs.len() as u64, profiles.len() as u64 * repetitions);
    for profile in profiles {
        let profile_id = profile["id"].as_str().context("fixture profile id")?;
        for repetition in 0..repetitions {
            assert!(runs.iter().any(|run| {
                run["profile_id"] == profile_id && run["repetition"].as_u64() == Some(repetition)
            }));
        }
    }

    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect evaluation cwd")?
            .count(),
        0,
        "deterministic fake evaluation must not create cwd artifacts"
    );
    Ok(())
}

#[test]
fn evaluation_cli_refuses_opted_in_real_provider_before_state_artifacts() -> Result<()> {
    let working = TempDir::new().context("create empty evaluation cwd")?;
    let manifest_path = fixture_path("manifest-v1.json");
    let plan_path = fixture_path("hand-authored-plan-v1.json");

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("evaluation")
        .arg("run")
        .arg(&manifest_path)
        .arg("--plan-file")
        .arg(&plan_path)
        .arg("--repo")
        .arg(working.path())
        .arg("--execution")
        .arg("real-provider")
        .arg("--allow-real-provider")
        .arg("--json")
        .output()
        .context("run opted-in real-provider evaluation")?;

    assert!(
        !output.status.success(),
        "opted-in real-provider evaluation unexpectedly ran"
    );
    assert!(
        output.stdout.is_empty(),
        "refused real-provider evaluation emitted stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "real-provider evaluation is unavailable in phase A even with explicit opt-in; \
             use deterministic_fake or a later real-provider harness"
        ),
        "unexpected Phase-A refusal: {stderr}"
    );
    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect opted-in refusal cwd")?
            .count(),
        0,
        "opted-in real-provider refusal must happen before state artifacts"
    );
    Ok(())
}

#[test]
fn evaluation_cli_refuses_real_provider_without_opt_in_before_state_artifacts() -> Result<()> {
    let working = TempDir::new().context("create empty evaluation cwd")?;
    let manifest_path = fixture_path("manifest-v1.json");
    let plan_path = fixture_path("hand-authored-plan-v1.json");

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("evaluation")
        .arg("run")
        .arg(&manifest_path)
        .arg("--plan-file")
        .arg(&plan_path)
        .arg("--repo")
        .arg(working.path())
        .arg("--execution")
        .arg("real-provider")
        .arg("--json")
        .output()
        .context("run real-provider evaluation without opt-in")?;

    assert!(!output.status.success(), "missing opt-in unexpectedly ran");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow_real_provider=true"),
        "unexpected opt-in refusal: {stderr}"
    );
    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect refused evaluation cwd")?
            .count(),
        0,
        "real-provider refusal must happen before state artifacts"
    );
    Ok(())
}

#[test]
fn evaluation_cli_refuses_unknown_nested_manifest_field_before_execution() -> Result<()> {
    let working = TempDir::new().context("create empty evaluation cwd")?;
    let inputs = TempDir::new().context("create separate evaluation input directory")?;
    let fixture_manifest = fixture_path("manifest-v1.json");
    let plan_path = fixture_path("hand-authored-plan-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&fixture_manifest)?)
        .context("parse fixture manifest for strict-schema mutation")?;
    let first_profile = manifest
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .and_then(|profiles| profiles.first_mut())
        .and_then(Value::as_object_mut)
        .context("fixture manifest first profile object")?;
    first_profile.insert(
        "unexpected_nested_test_field".to_string(),
        Value::String("must be refused".to_string()),
    );
    let malformed_manifest_path = inputs.path().join("manifest-unknown-nested-field.json");
    fs::write(
        &malformed_manifest_path,
        serde_json::to_vec_pretty(&manifest).context("serialize malformed test manifest")?,
    )
    .context("write malformed test manifest outside execution cwd")?;

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("evaluation")
        .arg("run")
        .arg(&malformed_manifest_path)
        .arg("--plan-file")
        .arg(&plan_path)
        .arg("--repo")
        .arg(working.path())
        .arg("--json")
        .output()
        .context("run evaluation with unknown nested manifest field")?;

    assert!(
        !output.status.success(),
        "unknown nested manifest field unexpectedly passed"
    );
    assert!(
        output.stdout.is_empty(),
        "strict manifest refusal emitted stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to parse evaluation manifest")
            && stderr.contains("unknown field")
            && stderr.contains("unexpected_nested_test_field"),
        "unexpected strict-schema refusal: {stderr}"
    );
    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect strict-schema refusal cwd")?
            .count(),
        0,
        "strict manifest refusal must happen before output or state artifacts"
    );
    Ok(())
}

#[test]
fn evaluation_help_exposes_execution_and_real_provider_gate() -> Result<()> {
    let top_level_help = Command::new(BIN)
        .arg("--help")
        .output()
        .context("run top-level help")?;
    assert!(top_level_help.status.success());
    assert!(String::from_utf8(top_level_help.stdout)
        .context("decode top-level help")?
        .contains("Generate deterministic model-mix fixture results"));

    let family_help = Command::new(BIN)
        .args(["evaluation", "--help"])
        .output()
        .context("run evaluation help")?;
    assert!(family_help.status.success());
    let family_help = String::from_utf8(family_help.stdout).context("decode evaluation help")?;
    assert!(family_help.contains("run"));
    assert!(family_help.contains("Generate deterministic fixture output"));

    let run_help = Command::new(BIN)
        .args(["evaluation", "run", "--help"])
        .output()
        .context("run evaluation command help")?;
    assert!(run_help.status.success());
    let help = String::from_utf8(run_help.stdout).context("decode evaluation run help")?;
    for obligation in [
        "--plan-file",
        "--repo",
        "--execution",
        "--allow-real-provider",
        "--fake-seed",
        "--json",
    ] {
        assert!(
            help.contains(obligation),
            "help omitted {obligation}: {help}"
        );
    }
    for boundary in [
        "unused",
        "synthetic fixture runner",
        "refuses real-provider",
    ] {
        assert!(
            help.contains(boundary),
            "help omitted boundary '{boundary}': {help}"
        );
    }
    Ok(())
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation")
        .join(name)
}
