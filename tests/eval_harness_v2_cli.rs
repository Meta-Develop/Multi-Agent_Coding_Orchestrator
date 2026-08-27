use anyhow::{Context, Result};
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn eval_harness_run_v2_emits_machine_readable_local_fake_json() -> Result<()> {
    let working = TempDir::new().context("create empty eval-harness cwd")?;
    let manifest_path = fixture_path("manifest-v2.json");

    for subcommand in ["run", "run-v2"] {
        let output = Command::new(BIN)
            .current_dir(working.path())
            .arg("eval-harness")
            .arg(subcommand)
            .arg(&manifest_path)
            .arg("--json")
            .output()
            .with_context(|| format!("run eval-harness {subcommand}"))?;

        assert!(
            output.status.success(),
            "eval-harness {subcommand} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let results: Value =
            serde_json::from_slice(&output.stdout).context("parse eval harness v2 JSON")?;
        assert_eq!(results["version"], 2);
        assert_eq!(results["schema"], "eval_harness_result_v2");
        assert_eq!(results["experiment_id"], "issue26-cli-operator-path-v2");
        assert_eq!(results["provider"]["kind"], "local_fake");
        assert_eq!(results["provider"]["network_providers"], false);
        assert_eq!(results["input_binding"]["manifest_version"], 2);
        assert_eq!(
            results["input_binding"]["manifest_schema"],
            "eval_harness_manifest_v2"
        );
        assert_eq!(results["input_binding"]["digest_algorithm"], "sha256");
        assert!(results["input_binding"]["digest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64));
        assert_eq!(
            results["objective_profile"]["profile"]["id"],
            "maco-default-objective-v2"
        );
    }

    assert_eq!(
        fs::read_dir(working.path())
            .context("inspect eval-harness cwd")?
            .count(),
        0,
        "eval-harness v2 must not create cwd artifacts"
    );
    Ok(())
}

#[test]
fn eval_harness_run_v2_refuses_incomplete_manifest() -> Result<()> {
    let working = TempDir::new().context("create empty eval-harness cwd")?;
    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("eval-harness")
        .arg("run-v2")
        .arg(fixture_path("manifest-v2-incomplete.json"))
        .arg("--json")
        .output()
        .context("run incomplete eval-harness v2")?;

    assert!(
        !output.status.success(),
        "incomplete v2 manifest unexpectedly succeeded: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("held_out_validations") || stderr.contains("invalid eval harness"),
        "stderr omitted parse cause: {stderr}"
    );
    Ok(())
}

#[test]
fn eval_harness_run_v2_refuses_real_provider() -> Result<()> {
    let working = TempDir::new().context("create empty eval-harness cwd")?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(fixture_path("manifest-v2.json"))?)
        .context("load valid v2 fixture")?;
    manifest["provider_request"] = serde_json::json!({
        "kind": "real_provider",
        "allow_real_provider": false
    });
    let manifest_path = working.path().join("real-provider-v2.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .context("write real-provider v2 manifest")?;

    let output = Command::new(BIN)
        .current_dir(working.path())
        .arg("eval-harness")
        .arg("run-v2")
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .context("run real-provider eval-harness v2")?;

    assert!(
        !output.status.success(),
        "real-provider v2 unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow_real_provider=true") || stderr.contains("real-provider"),
        "stderr omitted real-provider refusal: {stderr}"
    );
    Ok(())
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/eval_harness")
        .join(name)
}
