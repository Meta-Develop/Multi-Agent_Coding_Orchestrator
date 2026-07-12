use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn cli_agent_run_uses_fake_proposal_in_isolated_worktree() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    let proposal_path = temp.path().join("proposal.json");
    fs::write(&task_path, "Update the README through the fake provider.\n")
        .context("write task")?;
    fs::write(
        &proposal_path,
        r#"{
          "summary": "update README",
          "commands": [],
          "patches": [
            {
              "path": "README.md",
              "unified_diff": "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,3 @@\n # Smoke\n+\n+agent edit\n"
            }
          ],
          "notes": []
        }"#,
    )
    .context("write proposal")?;

    let (report, verified_backend_available) = run_agent_json([
        "agent",
        "run",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "README.md",
        "--fake-proposal",
        proposal_path.to_str().context("proposal path utf8")?,
        "--repo",
        repo,
        "--json",
    ])?;

    if !verified_backend_available {
        assert_agent_run_failed_closed(&report, &repo_path)?;
        let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
        assert_eq!(status.as_array().context("status array")?.len(), 0);
        return Ok(());
    }

    assert_eq!(report["success"], true);
    assert_eq!(report["provider_id"], "fake");
    assert_eq!(report["candidate"]["changed_paths"][0], "README.md");
    assert_eq!(
        report["candidate"]["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    let worktree_path = Path::new(
        report["worktree"]["path"]
            .as_str()
            .context("worktree path")?,
    );
    assert_ne!(worktree_path, repo_path.as_path());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    assert_eq!(
        fs::read_to_string(worktree_path.join("README.md"))?,
        "# Smoke\n\nagent edit\n"
    );

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_agent_run_rejects_unconfigured_real_provider_without_network() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    fs::write(&task_path, "Try a real provider.\n").context("write task")?;

    let output = Command::new(BIN)
        .args([
            "agent",
            "run",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "README.md",
            "--provider",
            "openai",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).context("parse failure json")?;
    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["provider_id"], "openai");
    assert!(report["error"]
        .as_str()
        .context("error string")?
        .contains("not configured"));

    Ok(())
}

#[test]
fn cli_agent_run_missing_fake_proposal_emits_json_failure() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    fs::write(&task_path, "No proposal.\n").context("write task")?;

    let output = Command::new(BIN)
        .args([
            "agent",
            "run",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "README.md",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).context("parse failure json")?;
    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert!(report["error"]
        .as_str()
        .context("error string")?
        .contains("requires --fake-proposal"));

    Ok(())
}

#[test]
fn cli_agent_run_disables_provider_commands_by_default_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    let proposal_path = temp.path().join("proposal.json");
    fs::write(&task_path, "Try to run a shell command.\n").context("write task")?;
    fs::write(
        &proposal_path,
        format!(
            r#"{{
          "summary": "attempt outside write",
          "commands": [
            {{
              "command": "printf hacked > {}",
              "working_directory": null,
              "purpose": "implement"
            }}
          ],
          "patches": [],
          "notes": []
        }}"#,
            repo_path.join("README.md").display()
        ),
    )
    .context("write proposal")?;

    let output = Command::new(BIN)
        .args([
            "agent",
            "run",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal_path.to_str().context("proposal path utf8")?,
            "--repo",
            repo,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).context("parse agent json")?;
    assert_eq!(report["success"], false);
    assert!(report["error"]
        .as_str()
        .context("error string")?
        .contains("disabled"));
    assert_eq!(
        report["command_results"][0]["success"], false,
        "provider command should be recorded as rejected"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_agent_run_failed_json_keep_claims_leaves_claim_active() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    let proposal_path = temp.path().join("proposal.json");
    fs::write(&task_path, "Try to run a disabled shell command.\n").context("write task")?;
    fs::write(
        &proposal_path,
        r#"{
          "summary": "attempt command",
          "commands": [
            {
              "command": "printf '# Smoke\n\nblocked command\n' > README.md",
              "working_directory": null,
              "purpose": "implement"
            }
          ],
          "patches": [],
          "notes": []
        }"#,
    )
    .context("write proposal")?;

    let output = Command::new(BIN)
        .args([
            "agent",
            "run",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal_path.to_str().context("proposal path utf8")?,
            "--keep-claims",
            "--repo",
            repo,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).context("parse agent json")?;
    assert_eq!(report["success"], false);
    assert!(report["error"]
        .as_str()
        .context("error string")?
        .contains("disabled"));
    assert_eq!(
        report["released_claims"]
            .as_array()
            .context("released claims array")?
            .len(),
        0
    );
    assert_eq!(
        report["release_errors"]
            .as_array()
            .context("release errors array")?
            .len(),
        0
    );

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    let claims = status.as_array().context("status array")?;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["agent_id"], "agent-a");
    assert_eq!(claims[0]["paths"][0], "README.md");

    Ok(())
}

#[test]
fn cli_agent_run_allows_provider_command_to_edit_claimed_path() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    let proposal_path = temp.path().join("proposal.json");
    fs::write(&task_path, "Run an implementation shell command.\n").context("write task")?;
    fs::write(
        &proposal_path,
        r#"{
          "summary": "edit README with command",
          "commands": [
            {
              "command": "printf '# Smoke\n\ncommand edit\n' > README.md",
              "working_directory": null,
              "purpose": "implement"
            }
          ],
          "patches": [],
          "notes": []
        }"#,
    )
    .context("write proposal")?;

    let (report, verified_backend_available) = run_agent_json([
        "agent",
        "run",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "README.md",
        "--fake-proposal",
        proposal_path.to_str().context("proposal path utf8")?,
        "--allow-provider-commands",
        "--repo",
        repo,
        "--json",
    ])?;

    if !verified_backend_available {
        assert_agent_run_failed_closed(&report, &repo_path)?;
        let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
        assert_eq!(status.as_array().context("status array")?.len(), 0);
        return Ok(());
    }

    assert_eq!(report["success"], true);
    assert_eq!(report["provider_id"], "fake");
    assert_eq!(report["provider_command_policy"], "allow_unsafe_shell");
    assert_eq!(report["command_results"][0]["success"], true);
    assert_eq!(report["command_results"][0]["purpose"], "implement");
    assert_eq!(report["command_results"][0]["exit_code"], 0);
    assert_eq!(report["command_results"][0]["error"], Value::Null);
    assert_eq!(report["candidate"]["changed_paths"][0], "README.md");
    assert_eq!(
        report["candidate"]["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    assert_eq!(
        report["released_claims"]
            .as_array()
            .context("released claims array")?
            .len(),
        1
    );
    assert_eq!(
        report["release_errors"]
            .as_array()
            .context("release errors array")?
            .len(),
        0
    );

    let worktree_path = Path::new(
        report["worktree"]["path"]
            .as_str()
            .context("worktree path")?,
    );
    assert_ne!(worktree_path, repo_path.as_path());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    assert_eq!(
        fs::read_to_string(worktree_path.join("README.md"))?,
        "# Smoke\n\ncommand edit\n"
    );

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

fn run_success_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_agent_json<const N: usize>(args: [&str; N]) -> Result<(Value, bool)> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    let report: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse agent json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((report, output.status.success()))
}

fn assert_agent_run_failed_closed(report: &Value, repo_path: &Path) -> Result<()> {
    assert_eq!(report["success"], false);
    let error = report["error"].as_str().context("agent error string")?;
    assert!(
        error.contains("containment")
            || error.contains("failed to establish process-tree ownership")
            || error.contains("failed to apply provider patch"),
        "unexpected fail-closed error: {error}"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    let worktree_path = Path::new(
        report["worktree"]["path"]
            .as_str()
            .context("failed run worktree path")?,
    );
    assert_eq!(
        fs::read_to_string(worktree_path.join("README.md"))?,
        "# Smoke\n"
    );
    assert_eq!(
        report["candidate"]["changed_paths"]
            .as_array()
            .context("failed run changed paths")?
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
