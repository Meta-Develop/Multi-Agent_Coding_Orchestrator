use anyhow::{Context, Result};
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn eval_harness_cli_runs_local_fake_manifest_as_json() -> Result<()> {
    let working = TempDir::new().context("create empty eval-harness cwd")?;
    let manifest_path = fixture_path("manifest-v1.json");

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("eval-harness")
        .arg("run")
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .context("run local fake eval harness")?;

    assert!(
        output.status.success(),
        "eval-harness run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let results: Value =
        serde_json::from_slice(&output.stdout).context("parse eval harness JSON")?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("parse fixture manifest")?;

    assert_eq!(results["version"], 1);
    assert_eq!(results["schema"], "eval_harness_result_v1");
    assert_eq!(results["experiment_id"], manifest["experiment_id"]);
    assert_eq!(results["provider"]["kind"], "local_fake");
    assert_eq!(results["provider"]["network_providers"], false);

    let profiles = manifest["profiles"]
        .as_array()
        .context("manifest profiles")?;
    let runs = results["runs"].as_array().context("result runs")?;
    assert_eq!(runs.len(), profiles.len());
    for profile in profiles {
        let profile_id = profile["id"].as_str().context("profile id")?;
        assert!(runs.iter().any(|run| {
            run["profile_id"] == profile_id
                && run["mix"].as_array().is_some_and(|mix| !mix.is_empty())
                && run["outcomes"]
                    .as_array()
                    .is_some_and(|outcomes| !outcomes.is_empty())
        }));
    }

    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect eval-harness cwd")?
            .count(),
        0,
        "local fake eval harness must not create cwd artifacts"
    );
    Ok(())
}

#[test]
fn eval_harness_cli_refuses_real_provider() -> Result<()> {
    let working = TempDir::new().context("create empty eval-harness cwd")?;
    let manifest_path = working.path().join("real-provider.json");
    fs::write(
        &manifest_path,
        r#"{
            "version": 1,
            "experiment_id": "must-refuse",
            "task": "must not reach a network provider",
            "provider": "real_provider",
            "profiles": [
                {"id": "p", "mix": [{"role": "planner", "model": "any"}]}
            ]
        }"#,
    )
    .context("write real-provider manifest")?;

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("eval-harness")
        .arg("run")
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .context("run refused real-provider eval harness")?;

    assert!(
        !output.status.success(),
        "real-provider eval harness unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refuses network or real-provider"),
        "stderr omitted refusal: {stderr}"
    );
    Ok(())
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/eval_harness")
        .join(name)
}
