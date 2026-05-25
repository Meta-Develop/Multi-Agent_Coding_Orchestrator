use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn scan_emits_public_safe_fake_schema() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let scan = run_success_json(&["inbox", "scan", "--repo", path_str(&repo_path)?, "--json"])?;

    assert_eq!(scan["version"], 1);
    assert_eq!(scan["repo"], ".");
    assert_eq!(scan["action_policy"], "fake");
    assert_eq!(scan["github_enabled"], false);
    assert_eq!(scan["success"], true);
    assert_eq!(scan["refused"], false);
    assert_eq!(scan["candidate_count"], 4);
    assert_eq!(scan["selected_count"], 2);

    let items = scan["items"].as_array().context("items")?;
    assert_eq!(items.len(), 4);
    assert!(items
        .iter()
        .any(|item| item["kind"] == "issue" && item["selected"] == true));
    assert!(items
        .iter()
        .any(|item| item["kind"] == "pull_request" && item["selected"] == true));

    let duplicate = items
        .iter()
        .find(|item| item["skip_reason"] == "duplicate")
        .context("duplicate item")?;
    assert_eq!(duplicate["duplicate"]["duplicate"], true);
    assert_eq!(
        duplicate["duplicate"]["reason"],
        "duplicate inbox candidate in current scan"
    );

    let unsafe_item = items
        .iter()
        .find(|item| item["item_id"] == "issue-303")
        .context("unsafe item")?;
    assert_eq!(unsafe_item["selected"], false);
    assert_eq!(unsafe_item["skip_reason"], "privacy_refused");
    assert!(array_contains(
        &unsafe_item["privacy"]["reasons"],
        "local_absolute_path"
    )?);
    assert!(
        unsafe_item["privacy"]["redactions"]["total_replacements"]
            .as_u64()
            .context("redactions")?
            > 0
    );

    let serialized = serde_json::to_string(&scan).context("serialize scan")?;
    assert_public_json_is_sanitized(&serialized, &repo_path);
    assert!(!serialized.contains("secret-value"));
    assert!(!serialized.contains("/home/example"));

    Ok(())
}

#[test]
fn run_processes_default_fake_items_and_writes_expected_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "default-flow",
        "--json",
    ])?;

    assert_eq!(report["version"], 1);
    assert_eq!(report["run_id"], "default-flow");
    assert_eq!(report["repo"], ".");
    assert_eq!(report["action_policy"], "fake");
    assert_eq!(report["github_enabled"], false);
    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["success"], true);
    assert_eq!(report["selected_item_count"], 2);
    assert_eq!(report["auto_merge_performed"], false);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    let item_reports = report["item_reports"].as_array().context("item reports")?;
    assert_eq!(item_reports.len(), 2);
    assert_eq!(item_reports[0]["kind"], "issue");
    assert_eq!(item_reports[0]["success"], true);
    assert_eq!(item_reports[0]["autopilot_success"], true);
    assert_eq!(item_reports[0]["github_success"], true);
    assert_eq!(
        item_reports[0]["plan_path"],
        ".maco/inbox/runs/default-flow/item-1-plan.json"
    );
    assert_eq!(
        item_reports[0]["autopilot_report_path"],
        ".maco/inbox/runs/default-flow/item-1-autopilot-report.json"
    );
    assert_eq!(
        item_reports[0]["github_report_path"],
        ".maco/inbox/runs/default-flow/item-1-github-report.json"
    );

    let run_dir = repo_path.join(".maco/inbox/runs/default-flow");
    for artifact in [
        "scan-report.json",
        "selected-items.json",
        "item-1-plan.json",
        "item-1-autopilot-report.json",
        "item-1-github-report.json",
        "item-2-plan.json",
        "item-2-autopilot-report.json",
        "item-2-github-report.json",
        "final-report.json",
    ] {
        assert!(run_dir.join(artifact).exists(), "missing {artifact}");
    }

    let plan = read_json_file(&run_dir.join("item-1-plan.json"))?;
    assert_eq!(plan["version"], 1);
    assert_eq!(plan["forge_mode"], "fake");
    assert_eq!(plan["reviewer"]["mode"], "fake");
    assert_eq!(plan["publish_mode"], "draft_only");
    assert_eq!(plan["auto_merge"], false);

    let pr_plan = read_json_file(&run_dir.join("item-2-plan.json"))?;
    assert_eq!(pr_plan["assigned_paths"], json!(["README.md"]));
    let pr_body = pr_plan["task"]["body"].as_str().context("pr plan body")?;
    assert!(pr_body.contains("Target paths and reasons:"));
    assert!(pr_body.contains("- README.md:"));
    assert!(pr_body.contains("failing checks: fake-ci"));
    assert!(pr_body.contains("Validation expectation:"));
    assert!(pr_body.contains("address failing check context: fake-ci"));

    let autopilot = read_json_file(&run_dir.join("item-1-autopilot-report.json"))?;
    assert_eq!(autopilot["success"], true);
    assert_eq!(autopilot["auto_merge_performed"], false);
    assert_eq!(autopilot["check_status"]["ci_reaction_supported"], false);

    let github = read_json_file(&run_dir.join("item-2-github-report.json"))?;
    assert_eq!(github["mode"], "fake");
    assert_eq!(github["status"], "local_report_only");
    assert_eq!(github["success"], true);

    let serialized = serde_json::to_string(&report).context("serialize report")?;
    assert_public_json_is_sanitized(&serialized, &repo_path);

    Ok(())
}

#[test]
fn inbox_generates_run_ids_refuses_reuse_and_prunes_only_run_dirs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--dry-run",
        "--max-items",
        "1",
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("inbox-"));
    assert!(repo_path
        .join(".maco/inbox/runs")
        .join(run_id)
        .join("final-report.json")
        .exists());

    let refused = run_failure_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        run_id,
        "--dry-run",
        "--json",
    ])?;
    assert_eq!(refused["status"], "refused");
    assert!(refused["message"]
        .as_str()
        .context("reuse message")?
        .contains("already exists"));

    let old_dir = repo_path.join(".maco/inbox/runs/aa-old");
    let new_dir = repo_path.join(".maco/inbox/runs/zz-new");
    fs::create_dir_all(&old_dir).context("create old run")?;
    fs::create_dir_all(&new_dir).context("create new run")?;
    write_json_file(
        &old_dir.join("final-report.json"),
        &json!({"status": "failed", "success": false}),
    )?;
    write_json_file(
        &new_dir.join("final-report.json"),
        &json!({"status": "succeeded", "success": true}),
    )?;

    let latest = run_success_json(&[
        "inbox",
        "artifacts",
        "latest",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(latest["run"]["run_id"], "zz-new");
    assert_eq!(latest["run"]["final_report_status"], "succeeded");

    let prune = run_success_json(&[
        "inbox",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["dry_run"], false);
    assert_eq!(prune["deleted_count"], 2);
    assert!(new_dir.exists(), "latest run must be kept");
    assert!(!old_dir.exists(), "old run should be pruned");
    assert!(repo_path.join(".maco/inbox").exists());
    assert!(repo_path.join(".maco").exists());

    Ok(())
}

#[test]
fn status_and_collect_return_sanitized_repo_relative_reports() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "collectable",
        "--max-items",
        "1",
        "--json",
    ])?;

    let status = run_success_json(&[
        "inbox",
        "status",
        "collectable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["run_id"], "collectable");
    assert_eq!(status["run_dir"], ".maco/inbox/runs/collectable");
    assert_eq!(status["artifacts"]["scan_report"], true);
    assert_eq!(status["artifacts"]["selected_items"], true);
    assert_eq!(status["artifacts"]["final_report"], true);
    assert_eq!(status["artifacts"]["item_plan_count"], 1);
    assert_eq!(status["artifacts"]["item_autopilot_report_count"], 1);
    assert_eq!(status["artifacts"]["item_github_report_count"], 1);
    assert_eq!(status["final_report"]["repo"], ".");

    let collected = run_success_json(&[
        "inbox",
        "collect",
        "collectable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(collected["run_id"], "collectable");
    assert_eq!(collected["status"], "succeeded");
    assert_eq!(collected["repo"], ".");

    let serialized = serde_json::to_string(&(status, collected)).context("serialize")?;
    assert_public_json_is_sanitized(&serialized, &repo_path);

    Ok(())
}

#[test]
fn dry_run_cli_does_not_launch_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "dry",
        "--dry-run",
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(report["action_policy"], "dry_run");
    assert_eq!(report["status"], "dry_run");
    assert_eq!(report["success"], true);
    assert_eq!(report["selected_item_count"], 1);
    assert_eq!(report["item_reports"][0]["status"], "dry_run");
    assert_eq!(report["item_reports"][0]["autopilot_success"], Value::Null);
    assert!(!repo_path.join(".maco/autopilot/runs").exists());

    let skipped =
        read_json_file(&repo_path.join(".maco/inbox/runs/dry/item-1-autopilot-report.json"))?;
    assert_eq!(skipped["status"], "skipped");
    assert_eq!(
        skipped["reason"],
        "dry_run action policy does not launch autopilot"
    );

    Ok(())
}

#[test]
fn dry_run_config_does_not_require_cli_flag() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({
            "action_policy": "dry_run",
            "selection": {"max_items": 1}
        }),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox dry-run config")?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "dry-config",
        "--json",
    ])?;

    assert_eq!(report["action_policy"], "dry_run");
    assert_eq!(report["status"], "dry_run");
    assert_eq!(report["selected_item_count"], 1);
    assert!(!repo_path.join(".maco/autopilot/runs").exists());

    Ok(())
}

#[test]
fn permission_config_overrides_legacy_action_policy() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({
            "action_policy": "github",
            "permission_mode": "fake",
            "selection": {"max_items": 1}
        }),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox permission config")?;

    let scan = run_success_json(&["inbox", "scan", "--repo", path_str(&repo_path)?, "--json"])?;

    assert_eq!(scan["action_policy"], "fake");
    assert_eq!(scan["permission_mode"], "fake");
    assert_eq!(scan["github_enabled"], false);
    assert!(scan["items"]
        .as_array()
        .context("items")?
        .iter()
        .all(|item| item["url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("fake://")));

    Ok(())
}

#[test]
fn github_read_permission_plans_without_launching_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({"selection": {"pull_requests": false, "max_items": 1}}),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox github read config")?;
    let gh = write_fake_gh(temp.path())?;

    let report = run_success_json_with_path(
        &[
            "inbox",
            "run",
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "github-read",
            "--permission",
            "github-read",
            "--json",
        ],
        &gh.path_dir,
    )?;

    assert_eq!(report["action_policy"], "github");
    assert_eq!(report["permission_mode"], "github_read");
    assert_eq!(report["github_enabled"], true);
    assert_eq!(report["status"], "planned");
    assert_eq!(report["success"], true);
    assert_eq!(report["item_reports"][0]["status"], "planned");
    assert_eq!(report["item_reports"][0]["autopilot_success"], Value::Null);
    assert!(!repo_path.join(".maco/autopilot/runs").exists());

    let plan = read_json_file(&repo_path.join(".maco/inbox/runs/github-read/item-1-plan.json"))?;
    assert_eq!(plan["forge_mode"], "fake");
    let skipped = read_json_file(
        &repo_path.join(".maco/inbox/runs/github-read/item-1-autopilot-report.json"),
    )?;
    assert_eq!(skipped["status"], "skipped");
    assert_eq!(
        skipped["reason"],
        "permission mode does not launch autopilot"
    );
    let gh_log = fs::read_to_string(&gh.log_path).context("read gh log")?;
    assert!(gh_log.contains("issue list"));
    assert!(!gh_log.contains("comment"));
    assert!(!gh_log.contains("pr create"));

    Ok(())
}

#[test]
fn github_local_reads_live_github_but_publishes_and_comments_locally() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({"selection": {"pull_requests": false, "max_items": 1}}),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox github local config")?;
    let gh = write_fake_gh(temp.path())?;

    let report = run_success_json_with_path(
        &[
            "inbox",
            "run",
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "github-local",
            "--permission",
            "github_local",
            "--json",
        ],
        &gh.path_dir,
    )?;

    assert_eq!(report["permission_mode"], "github_local");
    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["success"], true);
    assert_eq!(report["item_reports"][0]["autopilot_success"], true);

    let plan = read_json_file(&repo_path.join(".maco/inbox/runs/github-local/item-1-plan.json"))?;
    assert_eq!(plan["forge_mode"], "fake");
    let github =
        read_json_file(&repo_path.join(".maco/inbox/runs/github-local/item-1-github-report.json"))?;
    assert_eq!(github["mode"], "github");
    assert_eq!(github["permission_mode"], "github_local");
    assert_eq!(github["status"], "local_report_only");

    let gh_log = fs::read_to_string(&gh.log_path).context("read gh log")?;
    assert!(gh_log.contains("issue list"));
    assert!(!gh_log.contains("comment"));
    assert!(!gh_log.contains("pr create"));

    Ok(())
}

#[test]
fn github_pr_permission_dry_run_plans_github_publish_without_commenting() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({"selection": {"pull_requests": false, "max_items": 1}}),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox github pr config")?;
    let gh = write_fake_gh(temp.path())?;

    let report = run_success_json_with_path(
        &[
            "inbox",
            "run",
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "github-pr-dry",
            "--permission",
            "github-pr",
            "--dry-run",
            "--json",
        ],
        &gh.path_dir,
    )?;

    assert_eq!(report["action_policy"], "dry_run");
    assert_eq!(report["permission_mode"], "github_pr");
    assert_eq!(report["status"], "dry_run");
    let plan = read_json_file(&repo_path.join(".maco/inbox/runs/github-pr-dry/item-1-plan.json"))?;
    assert_eq!(plan["forge_mode"], "github");
    let github = read_json_file(
        &repo_path.join(".maco/inbox/runs/github-pr-dry/item-1-github-report.json"),
    )?;
    assert_eq!(github["permission_mode"], "github_pr");
    assert_eq!(github["status"], "skipped");
    let gh_log = fs::read_to_string(&gh.log_path).context("read gh log")?;
    assert!(!gh_log.contains("comment"));

    Ok(())
}

#[test]
fn github_git_permission_dry_run_plans_git_publish_without_commenting() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({"selection": {"pull_requests": false, "max_items": 1}}),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox github git config")?;
    let gh = write_fake_gh(temp.path())?;

    let report = run_success_json_with_path(
        &[
            "inbox",
            "run",
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "github-git-dry",
            "--permission",
            "github-git",
            "--dry-run",
            "--json",
        ],
        &gh.path_dir,
    )?;

    assert_eq!(report["action_policy"], "dry_run");
    assert_eq!(report["permission_mode"], "github_git");
    assert_eq!(report["github_enabled"], true);
    assert_eq!(report["status"], "dry_run");
    let plan = read_json_file(&repo_path.join(".maco/inbox/runs/github-git-dry/item-1-plan.json"))?;
    assert_eq!(plan["forge_mode"], "git");
    let github = read_json_file(
        &repo_path.join(".maco/inbox/runs/github-git-dry/item-1-github-report.json"),
    )?;
    assert_eq!(github["permission_mode"], "github_git");
    assert_eq!(github["status"], "skipped");
    let gh_log = fs::read_to_string(&gh.log_path).context("read gh log")?;
    assert!(gh_log.contains("issue list"));
    assert!(!gh_log.contains("comment"));
    assert!(!gh_log.contains("pr create"));

    Ok(())
}

#[test]
fn run_passes_codex_bin_to_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let codex = write_fake_codex(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "codex-bin",
        "--max-items",
        "1",
        "--codex-bin",
        path_str(&codex.script_path)?,
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["success"], true);
    let codex_log = fs::read_to_string(&codex.log_path).context("read codex log")?;
    assert!(codex_log.contains("exec"));
    assert!(codex_log.contains("--output-last-message"));

    let serialized = serde_json::to_string(&report).context("serialize report")?;
    assert_public_json_is_sanitized(&serialized, &repo_path);
    assert!(!serialized.contains(path_str(&codex.script_path)?));

    Ok(())
}

#[test]
fn watch_once_passes_codex_bin_to_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let codex = write_fake_codex(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "watch",
        "--repo",
        path_str(&repo_path)?,
        "--poll-seconds",
        "1",
        "--once",
        "--max-items",
        "1",
        "--codex-bin",
        path_str(&codex.script_path)?,
        "--json",
    ])?;

    assert_eq!(report["iteration_count"], 1);
    assert_eq!(report["runs"][0]["status"], "succeeded");
    let codex_log = fs::read_to_string(&codex.log_path).context("read codex log")?;
    assert!(codex_log.contains("exec"));

    Ok(())
}

#[test]
fn max_items_limits_selected_items_without_hiding_skip_evidence() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let scan = run_success_json(&[
        "inbox",
        "scan",
        "--repo",
        path_str(&repo_path)?,
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(scan["candidate_count"], 4);
    assert_eq!(scan["selected_count"], 1);
    assert!(scan["items"]
        .as_array()
        .context("items")?
        .iter()
        .any(|item| item["skip_reason"] == "selection_limit"));
    assert!(scan["items"]
        .as_array()
        .context("items")?
        .iter()
        .any(|item| item["skip_reason"] == "duplicate"));

    Ok(())
}

#[test]
fn github_mode_is_disabled_by_default() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let scan = run_success_json(&["inbox", "scan", "--repo", path_str(&repo_path)?, "--json"])?;

    assert_eq!(scan["action_policy"], "fake");
    assert_eq!(scan["github_enabled"], false);
    assert!(scan["items"]
        .as_array()
        .context("items")?
        .iter()
        .all(|item| item["url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("fake://")));

    Ok(())
}

#[test]
fn watch_once_runs_one_poll_iteration() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "watch",
        "--repo",
        path_str(&repo_path)?,
        "--poll-seconds",
        "1",
        "--once",
        "--dry-run",
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(report["repo"], ".");
    assert_eq!(report["poll_seconds"], 1);
    assert_eq!(report["once"], true);
    assert_eq!(report["iteration_count"], 1);
    assert_eq!(report["runs"].as_array().context("runs")?.len(), 1);
    assert_eq!(report["runs"][0]["status"], "dry_run");

    Ok(())
}

#[test]
fn active_live_lock_refuses_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_live_claim(&repo_path, "active-live", "active", "README.md")?;

    let report = run_inbox_refusal(&repo_path, "live-lock")?;

    assert_refusal_kind(&report, "active_live_locks")?;
    let refusal = refusal_by_kind(&report, "active_live_locks")?;
    assert_eq!(refusal["paths"], json!(["README.md"]));
    assert_eq!(refusal["lock_details"][0]["owner"], "worker-c-test");
    assert_eq!(refusal["lock_details"][0]["claim_id"], "active-live");
    assert_eq!(report["selected_item_count"], 0);
    assert_eq!(report["item_reports"].as_array().context("items")?.len(), 0);

    Ok(())
}

#[test]
fn active_sync_claim_refuses_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "sync",
        "claim",
        "other-worker",
        "README.md",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    let report = run_inbox_refusal(&repo_path, "sync-lock")?;

    assert_refusal_kind(&report, "active_sync_claims")?;
    let refusal = refusal_by_kind(&report, "active_sync_claims")?;
    assert_eq!(refusal["paths"], json!(["README.md"]));
    assert_eq!(refusal["lock_details"][0]["owner"], "other-worker");
    assert_eq!(refusal["lock_details"][0]["token"], 1);
    assert_eq!(report["selected_item_count"], 0);

    Ok(())
}

#[test]
fn active_semantic_intent_refuses_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-worker",
        "--path",
        "README.md",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    let report = run_inbox_refusal(&repo_path, "semantic-lock")?;

    assert_refusal_kind(&report, "active_semantic_intents")?;
    let refusal = refusal_by_kind(&report, "active_semantic_intents")?;
    assert_eq!(refusal["paths"], json!(["README.md"]));
    assert_eq!(refusal["lock_details"][0]["owner"], "semantic-worker");
    assert_eq!(refusal["lock_details"][0]["token"], 1);
    assert_eq!(report["selected_item_count"], 0);

    Ok(())
}

#[test]
fn non_overlapping_locks_do_not_refuse_inbox_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "sync",
        "claim",
        "other-worker",
        "src/lib.rs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-worker",
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

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "non-overlap",
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["success"], true);
    assert_eq!(report["selected_item_count"], 1);
    assert!(
        report.get("refusals").is_none()
            || report["refusals"]
                .as_array()
                .is_some_and(|items| items.is_empty())
    );

    Ok(())
}

#[test]
fn dirty_primary_real_file_refuses_run_while_runtime_paths_are_ignored() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    write_file(
        &repo_path.join("README.md"),
        "# Smoke\n\nreal dirty change\n",
    )?;
    write_file(&repo_path.join(".maco/inbox/runs/old/state.json"), "{}\n")?;
    write_file(&repo_path.join(".maco-cache/inbox/state.json"), "{}\n")?;

    let report = run_inbox_refusal(&repo_path, "dirty-primary")?;

    assert_refusal_kind(&report, "dirty_primary")?;
    assert_eq!(report["repo"], ".");
    assert_eq!(
        report["item_reports"]
            .as_array()
            .context("item reports")?
            .len(),
        0
    );
    let refusals = report["artifacts"]["run_dir"]
        .as_str()
        .context("artifact root")?;
    assert_eq!(refusals, ".maco/inbox/runs/dirty-primary");

    let serialized = serde_json::to_string(&report).context("serialize report")?;
    assert_public_json_is_sanitized(&serialized, &repo_path);
    assert!(!serialized.contains(".maco-cache/inbox/state.json"));
    assert!(serialized.contains("README.md"));

    Ok(())
}

#[test]
fn maco_runtime_paths_do_not_self_block() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    write_file(&repo_path.join(".maco/inbox/runs/old/state.json"), "{}\n")?;
    write_file(&repo_path.join(".maco-cache/inbox/state.json"), "{}\n")?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "runtime-only",
        "--dry-run",
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(report["status"], "dry_run");
    assert_eq!(report["success"], true);
    assert_eq!(report["selected_item_count"], 1);

    Ok(())
}

#[test]
fn timeout_seconds_stops_hanging_validation_command() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_json_file(
        &repo_path.join("maco-inbox.json"),
        &json!({
            "selection": {"max_items": 1},
            "max_repair_attempts": 0,
            "timeout_seconds": 1,
            "default_validation_commands": [
                {"name": "hang", "command": "sleep 5", "timeout_seconds": 1}
            ]
        }),
    )?;
    commit_all(&Repository::open(&repo_path)?, "inbox timeout config")?;

    let report = run_failure_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "timeout",
        "--json",
    ])?;

    assert_eq!(report["status"], "failed");
    assert_eq!(report["success"], false);
    assert_eq!(report["selected_item_count"], 1);
    assert_eq!(report["item_reports"][0]["autopilot_success"], false);

    let autopilot =
        read_json_file(&repo_path.join(".maco/inbox/runs/timeout/item-1-autopilot-report.json"))?;
    assert_eq!(autopilot["validation"]["status"], "failed");
    assert_eq!(autopilot["validation"]["reports"][0]["name"], "hang");
    assert!(autopilot["validation"]["reports"][0]["message"]
        .as_str()
        .context("validation message")?
        .contains("timed out"));

    Ok(())
}

#[test]
fn auto_merge_is_never_performed() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let report = run_success_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "no-auto-merge",
        "--max-items",
        "1",
        "--json",
    ])?;

    assert_eq!(report["auto_merge_performed"], false);
    let autopilot = read_json_file(
        &repo_path.join(".maco/inbox/runs/no-auto-merge/item-1-autopilot-report.json"),
    )?;
    assert_eq!(autopilot["auto_merge_requested"], false);
    assert_eq!(autopilot["auto_merge_performed"], false);
    assert!(autopilot["next_action"]
        .as_str()
        .context("next action")?
        .contains("merge"));

    Ok(())
}

fn run_inbox_refusal(repo: &Path, run_id: &str) -> Result<Value> {
    run_failure_json(&[
        "inbox",
        "run",
        "--repo",
        path_str(repo)?,
        "--run-id",
        run_id,
        "--json",
    ])
}

fn assert_refusal_kind(report: &Value, kind: &str) -> Result<()> {
    assert_eq!(report["status"], "refused");
    assert_eq!(report["success"], false);
    let scan_path = report["artifacts"]["scan_report"]
        .as_str()
        .context("scan report path")?;
    let repo_path = report["artifacts"]["run_dir"].as_str().context("run dir")?;
    assert!(scan_path.starts_with(repo_path));
    let refusals = report["next_action"].as_str().context("next action")?;
    assert!(refusals.contains("resolve inbox safety refusals"));
    let refusal_items = report["refusals"].as_array().context("refusals")?;
    if !refusal_items.iter().any(|refusal| refusal["kind"] == kind) {
        anyhow::bail!("expected refusal kind {kind}: {refusal_items:?}");
    }
    Ok(())
}

fn refusal_by_kind<'a>(report: &'a Value, kind: &str) -> Result<&'a Value> {
    report["refusals"]
        .as_array()
        .context("refusals")?
        .iter()
        .find(|refusal| refusal["kind"] == kind)
        .with_context(|| format!("expected refusal kind {kind}"))
}

fn array_contains(value: &Value, expected: &str) -> Result<bool> {
    Ok(value
        .as_array()
        .context("array")?
        .iter()
        .any(|value| value.as_str() == Some(expected)))
}

fn assert_public_json_is_sanitized(serialized: &str, repo_path: &Path) {
    assert!(!serialized.contains(&repo_path.display().to_string()));
    assert!(!serialized.contains("/mnt/d/"));
    assert!(!serialized.contains("/home/"));
    assert!(!serialized.contains("C:\\Users\\"));
}

fn write_live_claim(repo: &Path, claim_id: &str, status: &str, path: &str) -> Result<()> {
    let claims_dir = repo.join(".agents/live/claims");
    fs::create_dir_all(&claims_dir).context("create live claims")?;
    write_file(
        &claims_dir.join(format!("{claim_id}.md")),
        &format!(
            r#"# Claim: {claim_id}

- Claim ID: `{claim_id}`
- Owner: `worker-c-test`
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
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse success json from stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn run_success_json_with_path(args: &[&str], path_dir: &Path) -> Result<Value> {
    let output = Command::new(BIN)
        .args(args)
        .env("PATH", path_with_prefix(path_dir)?)
        .output()
        .context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse success json from stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
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

struct FakeGh {
    path_dir: PathBuf,
    log_path: PathBuf,
}

struct FakeCodex {
    script_path: PathBuf,
    log_path: PathBuf,
}

fn write_fake_gh(root: &Path) -> Result<FakeGh> {
    let path_dir = root.join("bin");
    let script_path = path_dir.join("gh");
    let log_path = root.join("gh.log");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> '{}'
case "$1 $2" in
  "issue list")
    cat <<'JSON'
[{{"number":11,"title":"Live issue","body":"Please update the smoke README.","labels":[],"author":{{"login":"octo"}},"url":"https://github.test/acme/demo/issues/11","updatedAt":"2026-05-23T00:00:00Z"}}]
JSON
    ;;
  "pr list")
    printf '[]\n'
    ;;
  "issue comment"|"pr comment")
    printf 'https://github.test/acme/demo/comment/1\n'
    ;;
  "pr create")
    printf 'https://github.test/acme/demo/pull/1\n'
    ;;
  *)
    printf '[]\n'
    ;;
esac
"#,
        log_path.display()
    );
    write_executable(&script_path, &script)?;
    Ok(FakeGh { path_dir, log_path })
}

fn write_fake_codex(root: &Path) -> Result<FakeCodex> {
    let script_path = root.join("fake-codex");
    let log_path = root.join("codex.log");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> '{}'
report=
worktree=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-last-message)
      report="$2"
      shift 2
      ;;
    --cd)
      worktree="$2"
      shift 2
      ;;
    --output-schema|--sandbox|-c|--enable)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cat >/dev/null
mkdir -p "$(dirname "$report")"
printf '\ninbox fake codex repair\n' >> "$worktree/README.md"
name="$(basename "$report" .json)"
cat > "$report" <<JSON
{{
  "id": "$name",
  "role": "child_orchestrator",
  "assigned_paths": ["README.md"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "commands_run": [],
  "files_changed": ["README.md"],
  "validation_results": [
    {{"name": "fake codex validation", "status": "succeeded", "command": [], "message": null}}
  ],
  "findings": [],
  "worker_reports": [
    {{
      "id": "$name-worker",
      "role": "worker",
      "assigned_paths": ["README.md"],
      "semantic_symbols": [],
      "semantic_modules": [],
      "commands_run": [],
      "files_changed": ["README.md"],
      "validation_results": [
        {{"name": "fake worker validation", "status": "succeeded", "command": [], "message": null}}
      ],
      "findings": [],
      "no_further_delegation": true,
      "accepted": true,
      "rejected": false,
      "status": "succeeded",
      "remaining_risk": "none",
      "next_safe_action": "publish through autopilot PR gate"
    }}
  ],
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "publish through autopilot PR gate"
}}
JSON
"#,
        log_path.display()
    );
    write_executable(&script_path, &script)?;
    Ok(FakeCodex {
        script_path,
        log_path,
    })
}

fn write_executable(path: &Path, contents: &str) -> Result<()> {
    write_file(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

fn path_with_prefix(path_dir: &Path) -> Result<String> {
    let existing = std::env::var("PATH").unwrap_or_default();
    Ok(format!("{}:{existing}", path_str(path_dir)?))
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, ".maco/\n.maco-cache/\n")
}

fn create_committed_repo_without_maco_ignore(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, "# runtime paths intentionally unignored\n")
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

fn read_json_file(path: &Path) -> Result<Value> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))
}

fn write_json_file(path: &Path, value: &Value) -> Result<()> {
    let contents = serde_json::to_string_pretty(value).context("serialize json")?;
    write_file(path, &(contents + "\n"))
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
