use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn orchestrate_resume_uses_checkpoint_defaults_and_reports_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let checkpoint_dir = temp.path().join("checkpoints");
    let run_id = "cli-resume-defaults";
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "true"}
          ]
        }"#,
    )
    .context("write plan")?;

    let unsupported = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo,
            "--checkpoint-dir",
            checkpoint_dir.to_str().context("checkpoint dir utf8")?,
            "--run-id",
            run_id,
            "--json",
        ])
        .output()
        .context("run unsupported orchestration")?;
    if !unsupported.status.success() {
        assert!(String::from_utf8_lossy(&unsupported.stderr)
            .contains("orchestration assignment creation is temporarily unsupported"));
        assert!(!checkpoint_dir.exists());
        return Ok(());
    }

    let (run_summary, verified_backend_available) = run_json_regardless(&[
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo,
        "--checkpoint-dir",
        checkpoint_dir.to_str().context("checkpoint dir utf8")?,
        "--run-id",
        run_id,
        "--json",
    ])?;
    assert_eq!(run_summary["run_id"], run_id);

    let checkpoint_path = checkpoint_dir.join(format!("{run_id}.json"));
    assert!(checkpoint_path.exists());
    let checkpoint: Value =
        serde_json::from_slice(&fs::read(&checkpoint_path)?).context("parse written checkpoint")?;
    assert_eq!(checkpoint["version"], 3);
    assert_eq!(checkpoint["journal"]["run_id"], run_id);
    assert_eq!(checkpoint["mac"].as_str().map(str::len), Some(64));
    assert!(checkpoint.get("plan_file").is_none());

    if !verified_backend_available {
        assert_eq!(run_summary["success"], false);
        assert_eq!(run_summary["agents"][0]["status"], "failed");
        let error = run_summary["agents"][0]["error"]
            .as_str()
            .context("orchestration error")?;
        assert!(
            error.contains("process-tree ownership") || error.contains("containment"),
            "unexpected fail-closed error: {error}"
        );
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))?,
            "# Smoke\n"
        );
        return Ok(());
    }

    assert_eq!(run_summary["success"], true);
    assert_eq!(run_summary["agents"][0]["candidate_binding"]["version"], 1);
    assert_eq!(
        run_summary["agents"][0]["candidate_binding"]["changed_paths"],
        serde_json::json!([])
    );
    assert_eq!(
        run_summary["repo_validation_target"]["kind"],
        "base_no_changes"
    );
    assert_eq!(run_summary["repo_validation_target"]["candidate_count"], 1);
    assert_eq!(run_summary["repo_validation_target"]["patch_count"], 0);

    let resume_summary = run_success_json(&[
        "orchestrate",
        "resume",
        checkpoint_path.to_str().context("checkpoint path utf8")?,
        "--json",
    ])?;
    assert_eq!(resume_summary["success"], true);
    assert_eq!(resume_summary["run_id"], run_id);
    let resumed_repo = resume_summary["repo"]
        .as_str()
        .context("resume repo string")?;
    assert_eq!(
        fs::canonicalize(resumed_repo)?,
        fs::canonicalize(&repo_path)?
    );
    assert_eq!(
        resume_summary["plan_file"],
        plan_path.to_str().context("plan path utf8")?
    );
    assert_eq!(resume_summary["agents"][0]["id"], "agent-a");
    assert_eq!(resume_summary["agents"][0]["status"], "succeeded");
    assert_eq!(
        resume_summary["agents"][0]["candidate_binding"],
        run_summary["agents"][0]["candidate_binding"]
    );
    assert_eq!(
        resume_summary["repo_validation_target"],
        run_summary["repo_validation_target"]
    );

    let renamed_checkpoint = checkpoint_dir.join("renamed.json");
    fs::copy(&checkpoint_path, &renamed_checkpoint).context("copy checkpoint")?;
    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "resume",
            renamed_checkpoint
                .to_str()
                .context("renamed checkpoint path utf8")?,
            "--json",
        ])
        .output()
        .context("run resume with renamed checkpoint")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match run id"));

    Ok(())
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

fn run_json_regardless(args: &[&str]) -> Result<(Value, bool)> {
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

    fs::write(repo_path.join("README.md"), "# Smoke\n").context("write readme")?;
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
