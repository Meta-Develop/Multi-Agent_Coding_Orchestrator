use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{fs, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

fn run(dir: &std::path::Path, args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .context("run optimizer CLI")?;
    assert!(
        output.status.success(),
        "optimizer CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).context("parse optimizer JSON")
}

#[test]
fn optimizer_preference_cli_round_trips_gui_json_and_previews() -> Result<()> {
    let working = TempDir::new().context("tempdir")?;
    let store = working.path().join("prefs");
    fs::create_dir_all(&store)?;

    let library = Command::new(BIN)
        .current_dir(working.path())
        .args(["optimizer", "library", "list"])
        .output()
        .context("list library")?;
    assert!(library.status.success(), "library list failed");
    let stdout = String::from_utf8_lossy(&library.stdout);
    assert!(stdout.contains("frontier-direct"));
    assert!(stdout.contains("worker-delayed-precision-hedge"));

    let cost_first = working.path().join("cost-first.json");
    fs::write(
        &cost_first,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "cost-first",
            "version": 1,
            "latency_weight_bp": 1000,
            "cost_weight_bp": 9000
        }))?,
    )?;
    let latency_first = working.path().join("latency-first.json");
    fs::write(
        &latency_first,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "latency-first",
            "version": 1,
            "latency_weight_bp": 9000,
            "cost_weight_bp": 1000
        }))?,
    )?;

    run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "set",
            "--store",
            store.to_str().expect("store"),
            "--file",
            cost_first.to_str().expect("file"),
            "--default",
            "--json",
        ],
    )?;
    run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "set",
            "--store",
            store.to_str().expect("store"),
            "--file",
            latency_first.to_str().expect("file"),
            "--json",
        ],
    )?;

    let shown = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "show",
            "--store",
            store.to_str().expect("store"),
            "--id",
            "cost-first",
            "--json",
        ],
    )?;
    assert_eq!(shown["id"], "cost-first");
    assert_eq!(shown["cost_weight_bp"], 9000);

    let diff = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "diff",
            "--store",
            store.to_str().expect("store"),
            "--a",
            "cost-first",
            "--b",
            "latency-first",
            "--json",
        ],
    )?;
    assert!(diff["fields"]
        .as_array()
        .context("diff fields")?
        .iter()
        .any(|field| field["field"] == "cost_weight_bp"));

    let decision = working.path().join("decision.json");
    fs::write(
        &decision,
        serde_json::to_vec_pretty(&json!([
            {
                "policy_id": "cheap-slow",
                "provider": "local",
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 1000,
                "expected_latency_micros": 50000
            },
            {
                "policy_id": "dear-fast",
                "provider": "local",
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 20000,
                "expected_latency_micros": 1000
            }
        ]))?,
    )?;
    let html = working.path().join("prefs.html");
    let preview = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "preview",
            "--store",
            store.to_str().expect("store"),
            "--a",
            "cost-first",
            "--b",
            "latency-first",
            "--decision",
            decision.to_str().expect("decision"),
            "--html",
            html.to_str().expect("html"),
            "--json",
        ],
    )?;
    assert_eq!(preview["selected_a"], "cheap-slow");
    assert_eq!(preview["selected_b"], "dear-fast");
    assert_eq!(preview["selections_differ"], true);
    let page = fs::read_to_string(&html)?;
    assert!(page.contains("cheap-slow"));
    assert!(page.contains("dear-fast"));
    assert!(page.contains("Optimizer preference profiles"));
    Ok(())
}

#[test]
fn optimizer_preference_cli_rejects_quality_floor_relaxation() -> Result<()> {
    let working = TempDir::new().context("tempdir")?;
    let store = working.path().join("prefs");
    let bad = working.path().join("bad.json");
    fs::write(
        &bad,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "bad",
            "version": 1,
            "latency_weight_bp": 1,
            "cost_weight_bp": 1,
            "quality_lcb_threshold": 1
        }))?,
    )?;
    let output = Command::new(BIN)
        .current_dir(working.path())
        .args([
            "optimizer",
            "preference",
            "set",
            "--store",
            store.to_str().expect("store"),
            "--file",
            bad.to_str().expect("file"),
            "--json",
        ])
        .output()
        .context("set bad profile")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("quality floor"),
        "unexpected rejection: {stderr}"
    );
    Ok(())
}
