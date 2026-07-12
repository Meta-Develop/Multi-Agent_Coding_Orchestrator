use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn cli_repo_map_orchestrate_and_sync_status_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {
              "id": "agent-a",
              "paths": ["src"],
              "command": "git rev-parse --is-inside-work-tree"
            }
          ]
        }"#,
    )
    .context("write plan")?;

    let map = run_success_json([
        "repo",
        "map",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert!(map["entries"].as_array().context("entries array")?.len() >= 2);

    let validation = run_success_json([
        "orchestrate",
        "validate",
        plan_path.to_str().context("plan path utf8")?,
        "--json",
    ])?;
    assert_eq!(validation["agent_count"], 1);

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        assert_orchestration_failed_closed(&summary)?;
        let status = run_success_json([
            "sync",
            "status",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])?;
        assert_eq!(status.as_array().context("status array")?.len(), 0);
        return Ok(());
    }
    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["stdout"]["text"], "true\n");

    let status = run_success_json([
        "sync",
        "status",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_orchestrate_failure_still_emits_json_summary() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "false"}
          ]
        }"#,
    )
    .context("write plan")?;

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("error string")?;
    assert!(
        error.contains("command exited") || error.contains("process-tree ownership"),
        "unexpected orchestration failure: {error}"
    );

    Ok(())
}

#[test]
fn cli_orchestrate_reports_committed_agent_change_and_patch() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    let patch_dir = temp.path().join("patches");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {
              "id": "agent-a",
              "paths": ["README.md"],
              "command": "printf '# Smoke\n\ncommitted\n' > README.md && git add README.md && git -c user.name='maco test' -c user.email='maco-test@example.invalid' commit -m agent-change"
            }
          ]
        }"#,
    )
    .context("write plan")?;

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--patch-dir",
        patch_dir.to_str().context("patch dir utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        assert_orchestration_failed_closed(&summary)?;
        assert!(!patch_dir.join("agent-a.patch").exists());
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))?,
            "# Smoke\n"
        );
        return Ok(());
    }

    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["changed_paths"][0], "README.md");
    assert_eq!(
        summary["agents"][0]["patch_path"],
        patch_dir.join("agent-a.patch").to_string_lossy().as_ref()
    );
    let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).context("read patch")?;
    assert!(patch.contains("committed"));

    Ok(())
}

#[test]
fn cli_claim_conflict_still_emits_json_summary() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    run_success_json([
        "sync",
        "claim",
        "other-agent",
        "README.md",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
          ]
        }"#,
    )
    .context("write plan")?;

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    assert!(summary["agents"][0]["error"]
        .as_str()
        .context("error string")?
        .contains("failed to claim paths"));

    Ok(())
}

#[test]
fn cli_worktree_diff_uses_active_claims_for_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;
    run_success_json([
        "sync",
        "claim",
        "agent-a",
        "README.md",
        "--repo",
        repo,
        "--json",
    ])?;

    let diff = run_success_json(["worktree", "diff", "agent-a", "--repo", repo, "--json"])?;

    assert_eq!(diff["metadata"]["agent_id"], "agent-a");
    assert_eq!(diff["claimed_paths"][0], "README.md");
    assert_eq!(diff["changed_paths"][0], "README.md");
    assert_eq!(
        diff["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    assert!(diff["diff"]["summary"]["text"]
        .as_str()
        .context("diff summary")?
        .contains("changed"));

    Ok(())
}

#[test]
fn cli_semantic_map_and_queries_emit_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Worker;\nimpl Worker { pub fn new() -> Self { Worker } }\n",
    )
    .context("write semantic lib")?;

    let map = run_success_json(["repo", "map", "--semantic", "--repo", repo, "--json"])?;
    assert!(map["symbols"]
        .as_array()
        .context("symbols array")?
        .iter()
        .any(|symbol| symbol["name"] == "Worker"));

    let symbol = run_success_json([
        "repo", "query", "symbol", "Worker", "--repo", repo, "--json",
    ])?;
    assert_eq!(symbol["matches"][0]["name"], "Worker");

    let path = run_success_json([
        "repo",
        "query",
        "path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(path["files"][0]["path"], "src/lib.rs");
    assert!(path["symbols"]
        .as_array()
        .context("path symbols")?
        .iter()
        .any(|symbol| symbol["name"] == "new"));

    Ok(())
}

#[test]
fn cli_semantic_coord_preview_claim_conflict_status_and_release_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Worker;\n")
        .context("write semantic lib")?;

    let preview = run_success_json([
        "coord",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(preview["persisted"], false);
    assert_eq!(preview["has_blocking_conflicts"], false);
    assert_eq!(preview["intent"]["symbols"][0]["name"], "Worker");

    let claim = run_success_json([
        "coord",
        "claim",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(claim["persisted"], true);
    let token = claim["intent"]["token"].as_u64().context("claim token")?;

    let output = Command::new(BIN)
        .args([
            "coord", "claim", "agent-b", "--repo", repo, "--symbol", "Worker", "--json",
        ])
        .output()
        .context("run conflicting claim")?;
    assert!(!output.status.success());
    let conflict: Value = serde_json::from_slice(&output.stdout).context("parse conflict json")?;
    assert_eq!(conflict["persisted"], false);
    assert_eq!(conflict["has_blocking_conflicts"], true);
    assert!(conflict["conflicts"]
        .as_array()
        .context("conflicts array")?
        .iter()
        .any(|conflict| conflict["kind"] == "symbol_overlap"));

    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 1);

    let token_arg = token.to_string();
    let released =
        run_success_json_args(&["coord", "release", &token_arg, "--repo", repo, "--json"])?;
    assert_eq!(released["agent_id"], "agent-a");
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_semantic_coord_release_agent_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\n",
    )
    .context("write semantic lib")?;

    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Alpha", "--json",
    ])?;
    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Beta", "--json",
    ])?;

    let released = run_success_json([
        "coord",
        "release-agent",
        "agent-a",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(released.as_array().context("released array")?.len(), 2);
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_merge_preview_blocks_unclaimed_edits_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;

    let preview = run_success_json([
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--json",
    ])?;

    assert_eq!(preview["safety"]["readiness"]["status"], "blocked");
    assert!(preview["safety"]["readiness"]["blockers"]
        .as_array()
        .context("blockers array")?
        .iter()
        .any(|blocker| blocker == "unclaimed_edits"));
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"][0],
        "README.md"
    );

    Ok(())
}

#[test]
fn cli_llm_providers_and_prompt_preview_are_network_free_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    fs::write(
        &task_path,
        "Implement local-only prompt preview.\nAPI_TOKEN=secret\n",
    )
    .context("write task")?;

    let providers = run_success_json(["llm", "providers", "--json"])?;
    assert_eq!(providers["network_providers_required"], false);
    assert_eq!(providers["providers"][0]["id"], "fake");
    assert_eq!(providers["providers"][0]["network_required"], false);

    let preview = run_success_json([
        "llm",
        "prompt-preview",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(preview["agent_id"], "agent-a");
    assert_eq!(preview["provider"]["network_required"], false);
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("<redacted:secret>"));
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("src/lib.rs"));

    Ok(())
}

fn run_success_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    run_success_json_args(&args)
}

fn run_success_json_args(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_json_regardless<const N: usize>(args: [&str; N]) -> Result<(Value, bool)> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    let report = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse orchestration json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((report, output.status.success()))
}

fn assert_orchestration_failed_closed(summary: &Value) -> Result<()> {
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("orchestration error")?;
    assert!(
        error.contains("process-tree ownership") || error.contains("containment"),
        "unexpected fail-closed error: {error}"
    );
    assert_eq!(
        summary["agents"][0]["changed_paths"]
            .as_array()
            .context("changed paths")?
            .len(),
        0
    );
    Ok(())
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args([
            "init",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n").context("write readme")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .context("write lib")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
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
    repo.commit(Some("HEAD"), &signature, &signature, message, &tree, &[])
        .context("commit")
}
