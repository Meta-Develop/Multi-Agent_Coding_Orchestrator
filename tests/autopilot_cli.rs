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
          "forge": "fake",
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
    assert_eq!(plan["forge_mode"], "fake");
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
fn fake_autopilot_run_creates_durable_reports() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Update the README through fake autopilot.\n")?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "durable",
        "--json",
    ])?;

    assert_eq!(report["success"], true);
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

    let status = run_success_json(&[
        "autopilot",
        "status",
        "durable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["artifacts"]["final_report"], true);
    assert_eq!(status["final_report"]["success"], true);

    let collected = run_success_json(&[
        "autopilot",
        "collect",
        "durable",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(collected["run_id"], "durable");
    assert_eq!(collected["success"], true);

    Ok(())
}

#[test]
fn fake_autopilot_run_ignores_local_runtime_state_without_gitignore_entry() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    let readme_before = fs::read_to_string(repo_path.join("README.md")).context("read readme")?;
    let lib_before = fs::read_to_string(repo_path.join("src/lib.rs")).context("read lib")?;
    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Run fake autopilot when runtime files are not ignored.\n",
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "unignored-runtime",
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["success"], true);
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
fn successful_fake_supervise_pr_review_flow_is_local_only() -> Result<()> {
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

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "local-flow",
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["validation"]["status"], "passed");
    assert_eq!(report["pr"]["status"], "published");
    assert_eq!(report["pr"]["forge"], "fake");
    assert_eq!(report["pr"]["created"], true);
    assert_eq!(report["pr"]["pushed"], false);
    assert_eq!(report["review"]["status"], "passed");
    assert_eq!(
        report["review"]["reviewer"]["reviewer_id"],
        "autopilot-fake-reviewer"
    );
    assert_eq!(report["review"]["ci_reaction_supported"], false);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    Ok(())
}

#[test]
fn blocking_fake_review_triggers_one_repair_attempt() -> Result<()> {
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

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "review-repair",
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["attempt_count"], 2);
    assert_eq!(report["repair_attempts_used"], 1);
    assert_eq!(report["attempts"][0]["blocking_findings"], 1);
    assert_eq!(
        report["attempts"][0]["repair_reason"],
        "review blocking findings: first attempt must be repaired"
    );
    assert_eq!(report["attempts"][1]["review_status"], "passed");

    Ok(())
}

#[test]
fn max_repair_attempts_stop_after_repeated_validation_failure() -> Result<()> {
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
    assert_eq!(report["attempt_count"], 2);
    assert_eq!(report["repair_attempts_used"], 1);
    assert_eq!(report["validation"]["status"], "failed");
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
fn non_overlapping_locks_do_not_refuse_autopilot() -> Result<()> {
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
    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "non-overlap",
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
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

    let report = run_success_json(&[
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
        .contains("never auto-merges"));
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

    let report = run_success_json(&[
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
    assert_eq!(report["pr"]["readiness"], "safe");
    assert!(report["pr"].get("preview").is_none());
    assert!(report["pr"].get("preview_path").is_none());
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
