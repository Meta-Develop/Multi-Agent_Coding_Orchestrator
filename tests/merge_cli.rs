use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn merge_apply_accepts_external_validation_report_and_applies() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nagent change\n")
        .context("edit worktree")?;
    let validation_path = temp.path().join("validation.json");
    fs::write(
        &validation_path,
        r#"[{"name":"unit","status":"passed","paths":["README.md"]}]"#,
    )
    .context("write validation report")?;

    let report = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["status"], "applied");
    assert_eq!(report["applied"], true);
    assert_eq!(report["preview"]["safety"]["readiness"]["status"], "safe");
    assert_eq!(
        report["preview"]["candidate"]["validations"][0]["paths"][0],
        "README.md"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n\nagent change\n"
    );

    Ok(())
}

#[test]
fn merge_apply_required_validation_accepts_exact_candidate_binding() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nbound\n").context("edit worktree")?;
    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("bound-validation.json");
    write_bound_validation(
        &validation_path,
        &preview["candidate"]["validation_binding"],
    )?;

    let report = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--json",
    ])?;

    assert_eq!(report["status"], "applied");
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "bound"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n\nbound\n"
    );
    Ok(())
}

#[test]
fn merge_preview_required_validation_rejects_legacy_unbound_pass() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlegacy\n").context("edit worktree")?;
    let validation_path = temp.path().join("legacy-validation.json");
    fs::write(
        &validation_path,
        r#"[{"name":"unit","status":"passed","paths":["README.md"]}]"#,
    )
    .context("write legacy validation")?;

    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--json",
    ])?;

    assert_eq!(preview["safety"]["readiness"]["status"], "blocked");
    assert_eq!(
        preview["safety"]["validation_evidence"]["binding_status"],
        "unbound"
    );
    assert_contains(
        &preview["safety"]["readiness"]["blockers"],
        "validation_missing",
    )?;
    assert!(preview["safety"]["readiness"]["details"]
        .as_array()
        .context("details array")?
        .iter()
        .any(|detail| detail["message"]
            .as_str()
            .unwrap_or_default()
            .contains("legacy unbound")));
    Ok(())
}

#[test]
fn merge_apply_rejects_stale_binding_after_agent_candidate_changes() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nfirst\n")
        .context("edit first candidate")?;
    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("stale-validation.json");
    write_bound_validation(
        &validation_path,
        &preview["candidate"]["validation_binding"],
    )?;
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nsecond\n")
        .context("change candidate after validation")?;

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "mismatched"
    );
    assert_contains(
        &report["preview"]["safety"]["readiness"]["blockers"],
        "validation_missing",
    )?;
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn merge_apply_revalidates_clean_committed_primary_after_candidate_validation() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ncandidate\n")
        .context("edit worktree")?;
    let mutation_command = format!(
        "printf 'pub fn ok() -> bool {{ false }}\\n' > {} && git -C {} add src/lib.rs && git -C {} -c user.name='maco test' -c user.email='maco-test@example.invalid' commit -m concurrent-primary",
        repo_path.join("src/lib.rs").display(),
        repo_path.display(),
        repo_path.display()
    );

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        &mutation_command,
        "--force-stale-base",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(
        report["preview"]["safety"]["primary_state_unchanged"]["status"],
        "failed"
    );
    assert_contains(
        &report["preview"]["safety"]["readiness"]["blockers"],
        "apply_check_failed",
    )?;
    assert_contains(
        &report["preview"]["safety"]["readiness"]["forced"],
        "stale_base",
    )?;
    assert_eq!(
        report["preview"]["safety"]["dirty_primary"]["status"],
        "passed"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn merge_apply_refuses_when_repo_common_lock_is_held() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlocked\n").context("edit worktree")?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    fs::write(
        lock_dir.join("repository-mutation.lock"),
        format!(
            "{{\"version\":1,\"pid\":{},\"nonce\":\"held\",\"created_unix_seconds\":1,\"operation\":\"pr-publish\"}}\n",
            std::process::id()
        ),
    )
    .context("write held lock")?;

    let output = Command::new(BIN)
        .args([
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--json",
        ])
        .output()
        .context("run locked merge apply")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("by live pid"));
    assert!(stderr.contains("pr-publish"));
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn pr_publish_cannot_run_while_merge_apply_validates_candidate() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nvalidate lock\n",
    )
    .context("edit worktree")?;
    let ready = temp.path().join("validation-ready");
    let release = temp.path().join("validation-release");
    let validation_command = format!(
        "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.05; done",
        ready.display(),
        release.display()
    );

    let mut apply = Command::new(BIN)
        .args([
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--validation-command",
            &validation_command,
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start merge apply")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        if Instant::now() >= deadline {
            let _ = apply.kill();
            anyhow::bail!("merge validation command did not start before timeout");
        }
        thread::sleep(Duration::from_millis(20));
    }

    let publish = Command::new(BIN)
        .args([
            "pr",
            "publish",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--forge",
            "fake",
            "--json",
        ])
        .output()
        .context("run concurrent pr publish")?;
    fs::write(&release, "release\n").context("release validation")?;
    let applied = apply.wait_with_output().context("wait for merge apply")?;

    assert!(!publish.status.success());
    let publish_stderr = String::from_utf8_lossy(&publish.stderr);
    assert!(publish_stderr.contains("repository mutation lock"));
    assert!(publish_stderr.contains("merge-apply"));
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let report: Value = serde_json::from_slice(&applied.stdout).context("parse apply report")?;
    assert_eq!(report["status"], "applied");
    Ok(())
}

#[test]
fn merge_apply_refuses_malformed_repo_common_lock() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlocked\n").context("edit worktree")?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    fs::write(
        lock_dir.join("repository-mutation.lock"),
        "pid=test nonce=held\n",
    )
    .context("write malformed lock")?;

    let output = Command::new(BIN)
        .args([
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--json",
        ])
        .output()
        .context("run locked merge apply")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lock is malformed"));
    assert!(lock_dir.join("repository-mutation.lock").exists());
    Ok(())
}

#[test]
fn merge_apply_atomically_reclaims_lock_owned_by_absent_pid() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nstale lock\n")
        .context("edit worktree")?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    fs::write(
        lock_dir.join("repository-mutation.lock"),
        "{\"version\":1,\"pid\":99999999,\"nonce\":\"stale\",\"created_unix_seconds\":1,\"operation\":\"pr-publish\"}\n",
    )
    .context("write stale lock")?;

    let report = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;

    assert_eq!(report["status"], "applied");
    assert!(!lock_dir.join("repository-mutation.lock").exists());
    Ok(())
}

#[test]
fn merge_apply_json_reports_dirty_primary_blocker() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nagent change\n")
        .context("edit worktree")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { false }\n",
    )
    .context("dirty primary")?;

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["applied"], false);
    assert_contains(
        &report["preview"]["safety"]["readiness"]["blockers"],
        "dirty_primary",
    )?;
    assert_detail_path(
        &report["preview"]["safety"]["readiness"]["details"],
        "dirty_primary",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn merge_preview_reports_stale_base_and_apply_conflict_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Agent\n").context("edit agent readme")?;

    fs::write(repo_path.join("README.md"), "# Primary\n").context("edit primary readme")?;
    let primary_repo = Repository::open(&repo_path).context("open primary repo")?;
    commit_all(&primary_repo, "primary change").context("commit primary change")?;

    let stale_preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    assert_contains(
        &stale_preview["safety"]["readiness"]["blockers"],
        "stale_base",
    )?;

    let conflict_preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--force-stale-base",
        "--json",
    ])?;
    assert_contains(
        &conflict_preview["safety"]["readiness"]["blockers"],
        "apply_check_failed",
    )?;
    assert_contains(
        &conflict_preview["safety"]["readiness"]["forced"],
        "stale_base",
    )?;
    assert_eq!(
        conflict_preview["safety"]["apply_check"]["paths"][0],
        "README.md"
    );
    assert_detail_path(
        &conflict_preview["safety"]["readiness"]["details"],
        "apply_check_failed",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn merge_preview_reports_unclaimed_edits_with_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nagent change\n")
        .context("edit worktree")?;

    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--json",
    ])?;

    assert_contains(
        &preview["safety"]["readiness"]["blockers"],
        "unclaimed_edits",
    )?;
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"][0],
        "README.md"
    );
    assert_detail_path(
        &preview["safety"]["readiness"]["details"],
        "unclaimed_edits",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn merge_preview_reports_committed_worktree_change() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ncommitted\n")
        .context("edit worktree")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    commit_all(&agent_repo, "agent committed change").context("commit agent change")?;

    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;

    assert_eq!(preview["safety"]["readiness"]["status"], "safe");
    assert_eq!(preview["candidate"]["changed_paths"][0], "README.md");
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    assert!(preview["candidate"]["diff"]["full"]
        .as_str()
        .context("full diff")?
        .contains("committed"));

    Ok(())
}

#[test]
fn merge_validation_failure_blocks_and_force_only_forces_validation() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nagent change\n")
        .context("edit worktree")?;
    let validation_path = temp.path().join("validation.json");
    fs::write(
        &validation_path,
        r#"{"validation":[{"name":"unit","status":"failed","message":"unit failed","paths":["README.md"]}]}"#,
    )
    .context("write validation report")?;

    let blocked = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--json",
    ])?;
    assert_contains(
        &blocked["safety"]["readiness"]["blockers"],
        "validation_failed",
    )?;
    assert_detail_path(
        &blocked["safety"]["readiness"]["details"],
        "validation_failed",
        "README.md",
    )?;

    let forced_validation = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--force-validation-failures",
        "--json",
    ])?;
    assert_eq!(forced_validation["safety"]["readiness"]["status"], "forced");
    assert_contains(
        &forced_validation["safety"]["readiness"]["forced"],
        "validation_failed",
    )?;

    let unclaimed_still_blocked = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--force-validation-failures",
        "--json",
    ])?;
    assert_contains(
        &unclaimed_still_blocked["safety"]["readiness"]["blockers"],
        "unclaimed_edits",
    )?;
    assert_contains(
        &unclaimed_still_blocked["safety"]["readiness"]["forced"],
        "validation_failed",
    )?;

    Ok(())
}

#[test]
fn merge_preview_required_validation_blocks_missing_not_run_and_skipped_evidence() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nagent change\n")
        .context("edit worktree")?;

    let missing = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--require-validation",
        "--json",
    ])?;

    assert_eq!(missing["safety"]["readiness"]["status"], "blocked");
    assert_contains(
        &missing["safety"]["readiness"]["blockers"],
        "validation_missing",
    )?;
    assert_detail_path(
        &missing["safety"]["readiness"]["details"],
        "validation_missing",
        "README.md",
    )?;
    assert!(
        missing["safety"]["readiness"]["details"][0]["next_safe_operation"]
            .as_str()
            .unwrap_or_default()
            .contains("--validation-report")
    );

    let validation_path = temp.path().join("validation.json");
    fs::write(
        &validation_path,
        r#"[
            {"name":"unit","status":"not_run","paths":["README.md"]},
            {"name":"fmt","status":"skipped","paths":["src/lib.rs"]}
        ]"#,
    )
    .context("write validation report")?;
    let incomplete = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--json",
    ])?;

    assert_contains(
        &incomplete["safety"]["readiness"]["blockers"],
        "validation_not_run",
    )?;
    assert_contains(
        &incomplete["safety"]["readiness"]["blockers"],
        "validation_skipped",
    )?;
    assert_detail_path(
        &incomplete["safety"]["readiness"]["details"],
        "validation_not_run",
        "README.md",
    )?;
    assert_detail_path(
        &incomplete["safety"]["readiness"]["details"],
        "validation_skipped",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn merge_apply_candidate_validation_failure_blocks_before_primary_apply() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ncandidate\n")
        .context("edit worktree")?;

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        "grep -q candidate README.md && printf failed >&2 && false",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["applied"], false);
    assert_contains(
        &report["preview"]["safety"]["readiness"]["blockers"],
        "validation_failed",
    )?;
    assert_eq!(
        report["preview"]["candidate"]["validations"][0]["status"],
        "failed"
    );
    assert_eq!(
        report["preview"]["safety"]["candidate_validation_commands"][0],
        "grep -q candidate README.md && printf failed >&2 && false"
    );
    assert_detail_path(
        &report["preview"]["safety"]["readiness"]["details"],
        "validation_failed",
        "README.md",
    )?;
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    Ok(())
}

#[test]
fn merge_apply_rejects_successful_validation_that_mutates_candidate_sandbox() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ncandidate\n")
        .context("edit worktree")?;

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        "printf '# mutated by validation\\n' > README.md",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(
        report["preview"]["candidate"]["validations"][0]["status"],
        "failed"
    );
    assert!(report["preview"]["candidate"]["validations"][0]["message"]
        .as_str()
        .context("validation message")?
        .contains("mutated tracked or non-ignored"));
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn merge_preview_preserves_non_utf8_claimed_path_and_emits_ascii_json() -> Result<()> {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    let raw_name = std::ffi::OsString::from_vec(b"raw-\xff.txt".to_vec());
    fs::write(worktree_path.join(&raw_name), b"raw path\n").context("write raw path")?;

    let output = Command::new(BIN)
        .args(["merge", "preview", "agent-a", "--repo", repo, "--claim"])
        .arg(&raw_name)
        .args(["--json"])
        .output()
        .context("run non-UTF8 preview")?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_ascii());
    let preview: Value = serde_json::from_slice(&output.stdout).context("parse preview json")?;
    assert_eq!(preview["safety"]["readiness"]["status"], "safe");
    assert_eq!(preview["candidate"]["changed_paths"][0], "raw-\\xFF.txt");
    assert_eq!(preview["candidate"]["changes"][0]["kind"], "untracked");
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed paths")?
            .len(),
        0
    );

    let validation_path = temp.path().join("legacy-validation.json");
    fs::write(
        &validation_path,
        r#"[{"name":"unit","status":"passed","paths":[]}]"#,
    )
    .context("write legacy validation")?;
    let required = Command::new(BIN)
        .args(["merge", "preview", "agent-a", "--repo", repo, "--claim"])
        .arg(&raw_name)
        .args([
            "--validation-report",
            validation_path.to_str().context("validation path utf8")?,
            "--require-validation",
            "--json",
        ])
        .output()
        .context("run non-UTF8 required preview")?;
    assert!(required.status.success());
    assert!(required.stdout.is_ascii());
    let required: Value =
        serde_json::from_slice(&required.stdout).context("parse required preview")?;
    assert_eq!(
        required["safety"]["validation_evidence"]["paths"][0],
        "raw-\\xFF.txt"
    );
    Ok(())
}

#[test]
fn merge_preview_ignores_ambient_git_repository_and_index_overrides() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let decoy_path = create_committed_repo(&temp.path().join("decoy-root"))?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nenv safe\n").context("edit worktree")?;
    let decoy_git_dir = decoy_path.join(".git");
    let decoy_index = decoy_git_dir.join("index");

    let output = Command::new(BIN)
        .args([
            "merge",
            "preview",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--json",
        ])
        .env("GIT_DIR", &decoy_git_dir)
        .env("GIT_WORK_TREE", &decoy_path)
        .env("GIT_INDEX_FILE", &decoy_index)
        .output()
        .context("run preview with ambient Git overrides")?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: Value = serde_json::from_slice(&output.stdout).context("parse preview")?;
    assert_eq!(preview["candidate"]["changed_paths"][0], "README.md");
    assert!(preview["candidate"]["diff"]["full"]
        .as_str()
        .context("full diff")?
        .contains("env safe"));
    Ok(())
}

#[test]
fn merge_preview_candidate_capture_does_not_write_unreachable_real_objects() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\ntemporary objects\n",
    )
    .context("edit worktree")?;
    fs::write(worktree_path.join("new.txt"), "new object\n").context("write untracked")?;
    let before = git_count_objects(&repo_path)?;

    let _preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--claim",
        "new.txt",
        "--json",
    ])?;

    assert_eq!(git_count_objects(&repo_path)?, before);
    Ok(())
}

fn write_bound_validation(path: &Path, binding: &Value) -> Result<()> {
    let evidence = serde_json::json!({
        "validation_binding": binding,
        "reports": [
            {"name": "unit", "status": "passed", "paths": ["README.md"]}
        ]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&evidence).context("serialize evidence")?,
    )
    .context("write bound validation")
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
    serde_json::from_slice(&output.stdout).context("parse failure json")
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

fn git_count_objects(repo: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["count-objects", "-v"])
        .output()
        .context("git count-objects")?;
    if !output.status.success() {
        anyhow::bail!(
            "git count-objects failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn assert_contains(value: &Value, expected: &str) -> Result<()> {
    let contains = value
        .as_array()
        .context("expected array")?
        .iter()
        .any(|item| item == expected);
    if !contains {
        anyhow::bail!("expected array to contain {expected}: {value}");
    }
    Ok(())
}

fn assert_detail_path(details: &Value, kind: &str, expected_path: &str) -> Result<()> {
    let detail = details
        .as_array()
        .context("details array")?
        .iter()
        .find(|detail| detail["kind"] == kind)
        .with_context(|| format!("missing detail for {kind}"))?;
    assert_eq!(detail["check_status"], "failed");
    let has_path = detail["paths"]
        .as_array()
        .context("detail paths array")?
        .iter()
        .any(|path| path == expected_path);
    if !has_path {
        anyhow::bail!("expected detail {kind} to include path {expected_path}: {detail}");
    }
    Ok(())
}
