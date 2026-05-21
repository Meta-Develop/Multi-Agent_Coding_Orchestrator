use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
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
