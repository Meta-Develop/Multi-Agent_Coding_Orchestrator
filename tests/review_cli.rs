use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn review_pr_json_reports_deterministic_fake_shape() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;

    let first = run_success_json(
        temp.path(),
        &["review", "pr", "123", "--repo", ".", "--json"],
    )?;
    let second = run_success_json(
        temp.path(),
        &["review", "pr", "456", "--repo", ".", "--json"],
    )?;

    assert_eq!(first["status"], "passed");
    assert_eq!(first["success"], true);
    assert_eq!(first["target"], "#123");
    assert_eq!(first["attempt"], 1);
    assert_eq!(first["reviewer"]["mode"], "fake");
    assert_eq!(first["reviewer"]["reviewer_id"], "autopilot-fake-reviewer");
    assert_eq!(first["reviewer"]["model"], "deterministic-local-reviewer");
    assert_eq!(first["reviewer"], second["reviewer"]);
    assert_eq!(second["target"], "#456");
    assert_eq!(first["ci_reaction_supported"], false);
    assert_eq!(first["ci_reaction"], "unsupported");
    assert_eq!(first["diff_source"], "pr_target_only");
    assert_eq!(first["changed_paths"], serde_json::json!([]));
    assert_eq!(first["blocking_finding_count"], 0);
    assert!(first["findings"]
        .as_array()
        .context("findings array")?
        .is_empty());
    assert!(first.get("diagnostics").is_none());

    Ok(())
}

fn run_success_json(cwd: &Path, args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN)
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("run {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse command JSON")
}
