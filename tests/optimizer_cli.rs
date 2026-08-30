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
    assert!(preview["decision_a"]["candidate_scores"]
        .as_array()
        .context("legacy candidate scores")?
        .iter()
        .all(|candidate| candidate["admitted"].is_null()
            && candidate["effective_admission"] == true
            && candidate["eligible"] == true));
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

#[test]
fn optimizer_preference_select_emits_bound_scores_and_explicit_terminal_tie_break() -> Result<()> {
    let working = TempDir::new().context("tempdir")?;
    let store = working.path().join("prefs");
    fs::create_dir_all(&store)?;
    let profile_path = working.path().join("terminal.json");
    fs::write(
        &profile_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "terminal",
            "version": 1,
            "latency_weight_bp": 5000,
            "cost_weight_bp": 5000
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
            profile_path.to_str().expect("profile"),
            "--json",
        ],
    )?;

    let candidates_path = working.path().join("terminal-candidates.json");
    fs::write(
        &candidates_path,
        serde_json::to_vec_pretty(&json!([
            {
                "policy_id": "codex-peer",
                "provider": "openai",
                "runtime": "codex",
                "model": "gpt-5.6-sol",
                "effort": "xhigh",
                "admitted": true,
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 2000,
                "expected_latency_micros": 2000
            },
            {
                "policy_id": "grok-default",
                "provider": "xai",
                "runtime": "grok",
                "model": "grok-4.6",
                "effort": "xhigh",
                "admitted": true,
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 2000,
                "expected_latency_micros": 2000
            },
            {
                "policy_id": "authority-refused",
                "provider": "example",
                "runtime": "example",
                "model": "cheap",
                "effort": "low",
                "admitted": true,
                "authority_refusals": [
                    "terminal_leaf_authority_not_admitted",
                    "cross_role_authority_not_admitted",
                    "terminal_leaf_authority_not_admitted"
                ],
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 1,
                "expected_latency_micros": 1
            }
        ]))?,
    )?;

    let decision = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "select",
            "--store",
            store.to_str().expect("store"),
            "--id",
            "terminal",
            "--decision",
            candidates_path.to_str().expect("candidates"),
            "--json",
        ],
    )?;
    let replayed_decision = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "select",
            "--store",
            store.to_str().expect("store"),
            "--id",
            "terminal",
            "--decision",
            candidates_path.to_str().expect("candidates"),
            "--json",
        ],
    )?;
    assert_eq!(decision, replayed_decision);
    assert_eq!(decision["objective_profile"]["id"], "terminal");
    assert_eq!(
        decision["objective_profile_hash"]
            .as_str()
            .context("profile hash")?
            .len(),
        64
    );
    assert_eq!(
        decision["candidate_scores"]
            .as_array()
            .context("scores")?
            .len(),
        3
    );
    assert_eq!(decision["selected"]["runtime"], "grok");
    assert_eq!(decision["selected"]["model"], "grok-4.6");
    assert_eq!(decision["selected"]["effort"], "xhigh");
    assert_eq!(decision["runner_up"]["runtime"], "codex");
    assert_eq!(
        decision["authority_refusals"]
            .as_array()
            .context("refusals")?
            .len(),
        1
    );
    assert_eq!(
        decision["authority_refusals"][0]["reasons"],
        json!([
            "cross_role_authority_not_admitted",
            "terminal_leaf_authority_not_admitted"
        ])
    );
    Ok(())
}

#[test]
fn optimizer_preference_select_scores_before_default_and_requires_grok_admission() -> Result<()> {
    let working = TempDir::new().context("tempdir")?;
    let store = working.path().join("prefs");
    fs::create_dir_all(&store)?;
    let profile_path = working.path().join("cost.json");
    fs::write(
        &profile_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "cost",
            "version": 1,
            "latency_weight_bp": 0,
            "cost_weight_bp": 10000
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
            profile_path.to_str().expect("profile"),
            "--json",
        ],
    )?;
    let candidates_path = working.path().join("cost-candidates.json");
    fs::write(
        &candidates_path,
        serde_json::to_vec_pretty(&json!([
            {
                "policy_id": "grok-unadmitted", "provider": "xai",
                "runtime": "grok", "model": "grok-4.6", "effort": "xhigh",
                "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 1, "expected_latency_micros": 1
            },
            {
                "policy_id": "scored-winner", "provider": "openai",
                "runtime": "codex", "model": "gpt-5.6-sol", "effort": "high",
                "admitted": true, "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 100, "expected_latency_micros": 100
            },
            {
                "policy_id": "grok-expensive", "provider": "xai",
                "runtime": "grok", "model": "grok-4.6", "effort": "xhigh",
                "admitted": true, "certified": true,
                "quality_lower_confidence_bp": 9000,
                "expected_cost_micros": 1000, "expected_latency_micros": 1
            }
        ]))?,
    )?;
    let decision = run(
        working.path(),
        &[
            "optimizer",
            "preference",
            "select",
            "--store",
            store.to_str().expect("store"),
            "--id",
            "cost",
            "--decision",
            candidates_path.to_str().expect("candidates"),
            "--json",
        ],
    )?;
    assert_eq!(decision["selected"]["policy_id"], "scored-winner");
    assert_eq!(decision["runner_up"]["policy_id"], "grok-expensive");
    let unadmitted = decision["candidate_scores"]
        .as_array()
        .context("scores")?
        .iter()
        .find(|candidate| candidate["identity"]["policy_id"] == "grok-unadmitted")
        .context("unadmitted Grok score")?;
    assert_eq!(unadmitted["eligible"], false);
    assert!(unadmitted["admitted"].is_null());
    assert_eq!(unadmitted["effective_admission"], false);
    assert_eq!(unadmitted["default_terminal_preference"], false);
    assert!(unadmitted["rejection_reasons"]
        .as_array()
        .context("rejections")?
        .iter()
        .any(|reason| reason == "candidate_not_admitted"));

    let missing_profile = Command::new(BIN)
        .current_dir(working.path())
        .args([
            "optimizer",
            "preference",
            "select",
            "--store",
            store.to_str().expect("store"),
            "--id",
            "missing",
            "--decision",
            candidates_path.to_str().expect("candidates"),
            "--json",
        ])
        .output()
        .context("select with missing resolved profile")?;
    assert!(!missing_profile.status.success());
    assert!(
        String::from_utf8_lossy(&missing_profile.stderr)
            .contains("preference profile 'missing' is not in the store"),
        "resolved selection must not fall back to catalog order: {}",
        String::from_utf8_lossy(&missing_profile.stderr)
    );
    Ok(())
}
