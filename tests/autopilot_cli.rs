use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn autopilot_plan_json_normalizes_defaults_and_aliases() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("autopilot-plan.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "  Normalize me  ", "body": "  Body text  "},
          "assigned_paths": ["./README.md", "README.md"],
          "semantic_symbols": ["Thing", "Thing", " "],
          "semantic_modules": ["crate::a", "crate::a"],
          "validation_commands": [
            "true",
            {"name": " smoke ", "command": " true "}
          ],
          "forge": "git",
          "auto_merge": true
        }"#,
    )?;

    let plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert_eq!(plan["task"]["title"], "Normalize me");
    assert_eq!(plan["task"]["body"], "Body text");
    assert_eq!(plan["assigned_paths"], serde_json::json!(["README.md"]));
    assert_eq!(plan["semantic_symbols"], serde_json::json!(["Thing"]));
    assert_eq!(plan["semantic_modules"], serde_json::json!(["crate::a"]));
    assert_eq!(plan["max_repair_attempts"], 1);
    assert_eq!(plan["forge_mode"], "git");
    assert_eq!(plan["reviewer"]["mode"], "fake");
    assert_eq!(plan["publish_mode"], "draft_only");
    assert_eq!(plan["auto_merge"], true);
    assert_eq!(plan["validation_commands"][1]["name"], "smoke");

    Ok(())
}

#[test]
fn autopilot_plan_proposes_paths_from_plain_and_empty_tasks() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_file(&repo_path.join("src/inbox.rs"), "pub struct InboxRepair;\n")?;
    commit_all(&Repository::open(&repo_path)?, "add inbox module")?;

    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Update README.md and repair InboxRepair in src/inbox.rs.\n",
    )?;
    let plain_plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(
        plain_plan["assigned_paths"],
        serde_json::json!(["README.md", "src/inbox.rs"])
    );

    let plan_path = temp.path().join("empty-paths.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {
            "title": "Repair inbox command",
            "body": "Fix InboxRepair handling."
          },
          "assigned_paths": []
        }"#,
    )?;
    let json_plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(
        json_plan["assigned_paths"],
        serde_json::json!(["src/inbox.rs"])
    );

    Ok(())
}

#[test]
fn fake_autopilot_run_creates_durable_nonpublishable_reports() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Update the README through fake autopilot.\n")?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "durable",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["attempt_count"], 1);
    let run_dir = repo_path.join(".maco/autopilot/runs/durable");
    for artifact in [
        "plan.json",
        "supervisor-report.json",
        "pr-report.json",
        "review-report.json",
        "final-report.json",
    ] {
        assert!(run_dir.join(artifact).exists(), "missing {artifact}");
    }
    let child_report_path =
        repo_path.join(".maco/o2/runs/durable-attempt-1/reports/autopilot-durable-a1.json");
    let child_report: Value = serde_json::from_str(
        &fs::read_to_string(&child_report_path)
            .with_context(|| format!("read {}", child_report_path.display()))?,
    )
    .with_context(|| format!("parse {}", child_report_path.display()))?;
    assert_eq!(
        child_report["worker_reports"][0]["no_further_delegation"],
        true
    );

    let status = run_success_json(&[
        "autopilot",
        "status",
        "durable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["artifacts"]["final_report"], true);
    assert_eq!(status["final_report"]["success"], false);

    let collected = run_failure_json(&[
        "autopilot",
        "collect",
        "durable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(collected["run_id"], "durable");
    assert_eq!(collected["success"], false);

    Ok(())
}

#[test]
fn autopilot_generates_run_ids_refuses_reuse_and_reports_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Update the README through generated autopilot.\n",
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("autopilot-"));
    assert!(repo_path
        .join(".maco/autopilot/runs")
        .join(run_id)
        .join("final-report.json")
        .exists());

    let latest = run_success_json(&[
        "autopilot",
        "artifacts",
        "latest",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(latest["run"]["run_id"], run_id);
    assert_eq!(latest["run"]["final_report_status"], "failed");
    assert_eq!(latest["run"]["final_report_success"], false);

    let refused = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        run_id,
        "--json",
    ])?;
    assert_eq!(refused["status"], "refused");
    assert!(refused["message"]
        .as_str()
        .context("reuse message")?
        .contains("already exists"));

    let corrupt_dir = repo_path.join(".maco/autopilot/runs/zz-corrupt");
    fs::create_dir_all(&corrupt_dir).context("create corrupt run dir")?;
    write_file(&corrupt_dir.join("final-report.json"), "{not json")?;
    let listed = run_success_json(&[
        "autopilot",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let runs = listed["runs"].as_array().context("runs")?;
    let corrupt = runs
        .iter()
        .find(|run| run["run_id"] == "zz-corrupt")
        .context("corrupt run")?;
    assert_eq!(corrupt["final_report_exists"], true);
    assert_eq!(corrupt["final_report_status"], "malformed");
    assert_eq!(corrupt["final_report_corrupt"], true);

    let prune = run_success_json(&[
        "autopilot",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--dry-run",
        "--json",
    ])?;
    assert_eq!(prune["dry_run"], true);
    assert_eq!(prune["deleted_count"], 0);
    assert!(corrupt_dir.exists(), "dry-run prune must not delete");

    Ok(())
}

#[test]
fn autopilot_prune_deletes_only_finalized_runs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_file(&repo_path.join("README.md"), "# Smoke\n\nprimary dirty\n")?;
    for run_id in ["aa-prune", "zz-prune"] {
        let report = run_autopilot_refusal(&repo_path, temp.path(), run_id)?;
        assert_eq!(report["status"], "refused");
    }

    let prune = run_success_json(&[
        "autopilot",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["deleted_count"], 1);
    assert_eq!(prune["refused_unfinalized_count"], 0);
    assert!(!repo_path.join(".maco/autopilot/runs/aa-prune").exists());
    assert!(repo_path.join(".maco/autopilot/runs/zz-prune").exists());
    Ok(())
}

#[test]
fn fake_autopilot_nonpublishable_run_ignores_local_runtime_state_without_gitignore_entry(
) -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    let readme_before = fs::read_to_string(repo_path.join("README.md")).context("read readme")?;
    let lib_before = fs::read_to_string(repo_path.join("src/lib.rs")).context("read lib")?;
    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Run fake autopilot when runtime files are not ignored.\n",
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "unignored-runtime",
        "--json",
    ])?;

    assert_eq!(report["status"], "failed");
    assert_eq!(report["success"], false);
    assert_eq!(report["safety"]["refused"], false);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        readme_before
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("src/lib.rs")).context("read primary lib")?,
        lib_before
    );

    Ok(())
}

#[test]
fn fake_supervise_flow_is_nonpublishable_and_stops_before_pr_review() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Fake local flow", "body": "Change README only."},
          "assigned_paths": ["README.md"],
          "validation_commands": ["true"]
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "local-flow",
        "--json",
    ])?;

    assert_eq!(report["status"], "failed");
    assert_eq!(report["validation"]["status"], "skipped");
    assert_eq!(report["pr"], Value::Null);
    assert_eq!(report["review"], Value::Null);
    let supervisor: Value = serde_json::from_str(&fs::read_to_string(
        repo_path.join(".maco/autopilot/runs/local-flow/supervisor-report.json"),
    )?)?;
    assert_eq!(supervisor["runtime"], "fake");
    assert_eq!(supervisor["success"], true);
    assert_eq!(supervisor["publishable"], false);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    Ok(())
}

#[test]
fn fake_supervisor_stops_before_blocking_review_or_repair() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("blocking-review.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Repair review", "body": "Exercise fake review repair."},
          "assigned_paths": ["README.md"],
          "max_repair_attempts": 1,
          "reviewer": {
            "mode": "fake",
            "blocking_attempts": 1,
            "finding": {
              "severity": "error",
              "path": "README.md",
              "summary": "first attempt must be repaired",
              "suggested_fix": "rerun once"
            }
          }
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "review-repair",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["attempt_count"], 1);
    assert_eq!(report["repair_attempts_used"], 0);
    assert_eq!(report["attempts"][0]["blocking_findings"], 0);
    assert_eq!(report["attempts"][0]["review_status"], Value::Null);

    Ok(())
}

#[test]
fn fake_supervisor_stops_before_validation_repair_loop() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("validation-fails.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Fail validation", "body": "Validation never passes."},
          "assigned_paths": ["README.md"],
          "max_repair_attempts": 1,
          "validation_commands": [
            {"name": "always fails", "command": "false"}
          ]
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "validation-stop",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["attempt_count"], 1);
    assert_eq!(report["repair_attempts_used"], 0);
    assert_eq!(report["validation"]["status"], "skipped");
    assert_eq!(report["pr"], Value::Null);
    assert_eq!(report["auto_merge_performed"], false);

    Ok(())
}

#[test]
fn dirty_primary_refusal_emits_public_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Try autopilot with dirty primary.\n")?;
    write_file(&repo_path.join("README.md"), "# Smoke\n\nprimary dirty\n")?;
    write_file(
        &repo_path.join(".maco/autopilot/runs/preexisting/state.json"),
        "{}\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            repo_path.join(".maco/autopilot/runs"),
            fs::Permissions::from_mode(0o700),
        )
        .context("chmod preexisting artifact root")?;
    }
    write_file(&repo_path.join(".maco-cache/preflight/state.json"), "{}\n")?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "dirty",
        "--json",
    ])?;

    assert_eq!(report["status"], "refused");
    assert_eq!(report["safety"]["refused"], true);
    assert_eq!(report["safety"]["refusals"][0]["kind"], "dirty_primary");
    assert_eq!(
        report["safety"]["refusals"][0]["paths"],
        serde_json::json!(["README.md"])
    );
    assert_eq!(report["auto_merge_performed"], false);

    Ok(())
}

#[cfg(unix)]
#[test]
fn status_and_collect_require_verified_finalization_and_distinguish_active_runs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let missing = run_success_json(&[
        "autopilot",
        "status",
        "absent",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(missing["final_report"].is_null());
    assert_eq!(missing["artifacts"]["plan"], false);
    let missing_collect = run_failure_json(&[
        "autopilot",
        "collect",
        "absent",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(missing_collect["status"], "missing");

    write_file(&repo_path.join("README.md"), "# Smoke\n\nprimary dirty\n")?;
    for run_id in [
        "verified",
        "report-tamper",
        "hmac-tamper",
        "marker-malformed",
    ] {
        let report = run_autopilot_refusal(&repo_path, temp.path(), run_id)?;
        assert_eq!(report["status"], "refused");
    }

    let verified_dir = repo_path.join(".maco/autopilot/runs/verified");
    let marker: Value = serde_json::from_slice(
        &fs::read(verified_dir.join(".maco-artifact-final.json")).context("read marker")?,
    )
    .context("parse marker")?;
    assert_eq!(marker["publish_requested"], false);
    assert_eq!(marker["publishable"], false);
    assert!(marker["files"]
        .as_array()
        .context("marker files")?
        .iter()
        .all(|file| file["disposition"] == "private_evidence"));
    let verified = run_success_json(&[
        "autopilot",
        "status",
        "verified",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(verified["final_report"]["status"], "refused");

    let active_dir = repo_path.join(".maco/autopilot/runs/active");
    fs::create_dir(&active_dir).context("create active run")?;
    fs::set_permissions(&active_dir, fs::Permissions::from_mode(0o700))
        .context("chmod active run")?;
    write_file(&active_dir.join("plan.json"), "{}\n")?;
    let active = run_success_json(&[
        "autopilot",
        "status",
        "active",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(active["artifacts"]["plan"], true);
    assert_eq!(active["artifacts"]["final_report"], false);
    assert!(active["final_report"].is_null());
    let active_collect = run_failure_stderr(&[
        "autopilot",
        "collect",
        "active",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(active_collect.contains("active or unfinalized"));

    write_file(
        &repo_path.join(".maco/autopilot/runs/report-tamper/final-report.json"),
        "{\"status\":\"succeeded\",\"success\":true}\n",
    )?;
    assert_corrupt_autopilot_status(&repo_path, "report-tamper")?;

    let hmac_path = repo_path.join(".maco/autopilot/runs/hmac-tamper/.maco-artifact-final.json");
    let mut hmac_marker: Value =
        serde_json::from_slice(&fs::read(&hmac_path)?).context("parse hmac marker")?;
    hmac_marker["hmac_sha256"] = Value::String("00".repeat(32));
    write_file(
        &hmac_path,
        &format!("{}\n", serde_json::to_string_pretty(&hmac_marker)?),
    )?;
    assert_corrupt_autopilot_status(&repo_path, "hmac-tamper")?;

    write_file(
        &repo_path.join(".maco/autopilot/runs/marker-malformed/.maco-artifact-final.json"),
        "{not json\n",
    )?;
    assert_corrupt_autopilot_status(&repo_path, "marker-malformed")?;

    Ok(())
}

fn assert_corrupt_autopilot_status(repo: &Path, run_id: &str) -> Result<()> {
    let failure = run_failure_stderr(&[
        "autopilot",
        "status",
        run_id,
        "--repo",
        path_str(repo)?,
        "--json",
    ])?;
    assert!(failure.contains("corrupt or unverifiable"));
    Ok(())
}

#[test]
fn sync_semantic_and_live_locks_are_preflight_refusals() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;

    let sync_repo = create_committed_repo(&temp.path().join("sync"))?;
    run_success_json(&[
        "sync",
        "claim",
        "other-agent",
        "README.md",
        "--repo",
        path_str(&sync_repo)?,
        "--json",
    ])?;
    let sync_report = run_autopilot_refusal(&sync_repo, temp.path(), "sync-refusal")?;
    assert_refusal_kind(&sync_report, "active_sync_claims")?;
    let sync_refusal = refusal_by_kind(&sync_report, "active_sync_claims")?;
    assert_eq!(sync_refusal["paths"], serde_json::json!(["README.md"]));
    assert_eq!(sync_refusal["lock_details"][0]["owner"], "other-agent");
    assert_eq!(sync_refusal["lock_details"][0]["token"], 1);

    let semantic_repo = create_committed_repo(&temp.path().join("semantic"))?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-agent",
        "--path",
        "README.md",
        "--repo",
        path_str(&semantic_repo)?,
        "--json",
    ])?;
    let semantic_report = run_autopilot_refusal(&semantic_repo, temp.path(), "semantic-refusal")?;
    assert_refusal_kind(&semantic_report, "active_semantic_intents")?;
    let semantic_refusal = refusal_by_kind(&semantic_report, "active_semantic_intents")?;
    assert_eq!(semantic_refusal["paths"], serde_json::json!(["README.md"]));
    assert_eq!(
        semantic_refusal["lock_details"][0]["owner"],
        "semantic-agent"
    );
    assert_eq!(semantic_refusal["lock_details"][0]["token"], 1);

    let live_repo = create_committed_repo(&temp.path().join("live"))?;
    write_live_claim(&live_repo, "active-live", "active", "README.md")?;
    let live_report = run_autopilot_refusal(&live_repo, temp.path(), "live-refusal")?;
    assert_refusal_kind(&live_report, "active_live_locks")?;
    let live_refusal = refusal_by_kind(&live_report, "active_live_locks")?;
    assert_eq!(live_refusal["paths"], serde_json::json!(["README.md"]));
    assert_eq!(live_refusal["lock_details"][0]["owner"], "worker-a");
    assert_eq!(live_refusal["lock_details"][0]["claim_id"], "active-live");

    Ok(())
}

#[test]
fn non_overlapping_locks_do_not_refuse_nonpublishable_fake_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "sync",
        "claim",
        "other-agent",
        "src/lib.rs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-agent",
        "--path",
        "src/lib.rs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    write_live_claim(&repo_path, "active-live", "active", "src/lib.rs")?;
    commit_all(
        &Repository::open(&repo_path)?,
        "track non-overlapping live claim",
    )?;

    let task_path = temp.path().join("readme-task.md");
    write_file(&task_path, "Update README.md through fake autopilot.\n")?;
    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "non-overlap",
        "--json",
    ])?;

    assert_eq!(report["status"], "failed");
    assert_eq!(report["safety"]["refused"], false);
    assert_eq!(
        report["plan"]["assigned_paths"],
        serde_json::json!(["README.md"])
    );

    Ok(())
}

#[test]
fn auto_merge_request_is_recorded_but_never_performed() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("auto-merge.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "No auto merge", "body": "Record but do not merge."},
          "assigned_paths": ["README.md"],
          "auto_merge": true
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "no-auto-merge",
        "--json",
    ])?;

    assert_eq!(report["auto_merge_requested"], true);
    assert_eq!(report["auto_merge_performed"], false);
    assert!(report["next_action"]
        .as_str()
        .context("next action")?
        .contains("trusted Codex runtime"));
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    Ok(())
}

#[test]
fn public_json_shape_is_stable_and_sanitized() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Check public shape.\n")?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "shape",
        "--json",
    ])?;

    assert_eq!(report["version"], 1);
    assert_eq!(report["artifacts"]["plan"], "plan.json");
    assert_eq!(
        report["artifacts"]["supervisor_report"],
        "supervisor-report.json"
    );
    assert_eq!(report["reports_created"]["final_report"], true);
    assert_eq!(report["plan"]["forge_mode"], "fake");
    assert_eq!(report["status"], "failed");
    assert_eq!(report["pr"], Value::Null);
    assert_eq!(report["ci_reaction_supported"], false);
    assert_eq!(report["check_status"]["state"], "not_supported");
    let serialized = serde_json::to_string(&report).context("serialize report")?;
    assert!(!serialized.contains(&repo_path.display().to_string()));

    let review = run_success_json(&[
        "review",
        "pr",
        "123",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(review["target"], "#123");
    assert_eq!(review["status"], "passed");
    assert_eq!(review["ci_reaction_supported"], false);

    Ok(())
}

fn run_autopilot_refusal(repo: &Path, temp: &Path, run_id: &str) -> Result<Value> {
    let task_path = temp.join(format!("{run_id}.md"));
    write_file(&task_path, "Refuse autopilot on README.md.\n")?;
    run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(repo)?,
        "--run-id",
        run_id,
        "--json",
    ])
}

fn assert_refusal_kind(report: &Value, kind: &str) -> Result<()> {
    assert_eq!(report["status"], "refused");
    let refusals = report["safety"]["refusals"]
        .as_array()
        .context("refusals")?;
    if !refusals.iter().any(|refusal| refusal["kind"] == kind) {
        anyhow::bail!("expected refusal kind {kind}: {refusals:?}");
    }
    Ok(())
}

fn refusal_by_kind<'a>(report: &'a Value, kind: &str) -> Result<&'a Value> {
    report["safety"]["refusals"]
        .as_array()
        .context("refusals")?
        .iter()
        .find(|refusal| refusal["kind"] == kind)
        .with_context(|| format!("expected refusal kind {kind}"))
}

fn write_live_claim(repo: &Path, claim_id: &str, status: &str, path: &str) -> Result<()> {
    let claims_dir = repo.join(".agents/live/claims");
    fs::create_dir_all(&claims_dir).context("create live claims")?;
    write_file(
        &claims_dir.join(format!("{claim_id}.md")),
        &format!(
            r#"# Claim: {claim_id}

- Claim ID: `{claim_id}`
- Owner: `worker-a`
- Status: `{status}`
- Created: `2026-05-20T00:00:00Z`
- Updated: `2026-05-20T00:00:00Z`
- Heartbeat: `2026-05-20T00:00:00Z`
- Stale after minutes: `60`
- Owned files, regions, devices, or services:
  - `{path}`: test
"#
        ),
    )
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse failure json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_failure_stderr(args: &[&str]) -> Result<String> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, ".maco/\n")
}

fn create_committed_repo_without_maco_ignore(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, "# intentionally no maco runtime ignores\n")
}

fn create_committed_repo_with_gitignore(
    root: &Path,
    gitignore_contents: &str,
) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    write_file(&repo_path.join(".gitignore"), gitignore_contents)?;
    write_file(&repo_path.join("README.md"), "# Smoke\n")?;
    write_file(
        &repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let mut config = repo.config().context("repo config")?;
    config
        .set_str("user.name", "maco test")
        .context("set user name")?;
    config
        .set_str("user.email", "maco-test@example.invalid")
        .context("set user email")?;
    commit_all(&repo, "initial commit")?;

    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index().context("open index")?;
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .context("add all")?;
    index.write().context("write index")?;
    let tree_id = index.write_tree().context("write tree")?;
    let tree = repo.find_tree(tree_id).context("find tree")?;
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .context("commit")
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
