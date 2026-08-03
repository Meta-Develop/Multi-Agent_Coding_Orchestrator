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
    let results: Value =
        serde_json::from_slice(&output.stdout).context("parse evaluation results JSON")?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("parse fixture manifest")?;

    assert_eq!(results["experiment_id"], manifest["experiment_id"]);
    assert_eq!(results["fake_seed"], 26);
    assert_eq!(results["evidence"]["real_provider_executed"], false);

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
fn evaluation_help_exposes_execution_and_real_provider_gate() -> Result<()> {
    let family_help = Command::new(BIN)
        .args(["evaluation", "--help"])
        .output()
        .context("run evaluation help")?;
    assert!(family_help.status.success());
    assert!(String::from_utf8(family_help.stdout)
        .context("decode evaluation help")?
        .contains("run"));

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
    Ok(())
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation")
        .join(name)
}
