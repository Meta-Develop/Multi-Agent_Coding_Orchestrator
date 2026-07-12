use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    env, fs,
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

#[cfg(target_os = "linux")]
#[test]
fn merge_apply_refuses_when_repo_common_lock_is_held() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
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
        lock_record(
            std::process::id(),
            "pr-publish",
            process_start_ticks(std::process::id())?,
        ),
    )
    .context("write held lock")?;
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_dir.join("repository-mutation.lock"))
        .context("open held lock")?;
    lock_file.try_lock().context("hold kernel lock")?;
    let fake_bin = temp.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).context("create fake bin")?;
    let fake_kill = fake_bin.join("kill");
    let kill_log = temp.path().join("kill-called");
    fs::write(
        &fake_kill,
        format!(
            "#!/bin/sh\nprintf called > '{}'\nexit 1\n",
            kill_log.display()
        ),
    )
    .context("write fake kill")?;
    let mut permissions = fs::metadata(&fake_kill)
        .context("stat fake kill")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_kill, permissions).context("chmod fake kill")?;
    let path = path_with_prefix(&fake_bin)?;

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
        .env("PATH", path)
        .output()
        .context("run locked merge apply")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("kernel lock is held"));
    assert!(stderr.contains("by pid"));
    assert!(stderr.contains("pr-publish"));
    assert!(
        !kill_log.exists(),
        "lock liveness must not shell out to kill"
    );
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
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_dir.join("repository-mutation.lock"))
        .context("open malformed lock")?;
    lock_file.try_lock().context("hold malformed kernel lock")?;

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
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid owner record"));
    assert!(lock_dir.join("repository-mutation.lock").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn merge_apply_refuses_symlink_repository_lock_file() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nsymlink lock\n")
        .context("edit worktree")?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    let target = temp.path().join("lock-target");
    fs::write(&target, "do not touch\n").context("write lock target")?;
    symlink(&target, lock_dir.join("repository-mutation.lock")).context("create lock symlink")?;

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
        .context("run merge with symlink lock")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
    assert_eq!(fs::read_to_string(&target)?, "do not touch\n");
    Ok(())
}

#[cfg(unix)]
#[test]
fn merge_apply_refuses_symlink_repository_state_directory() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nsymlink state\n",
    )
    .context("edit worktree")?;
    let maco_dir = repo_path.join(".git/maco");
    fs::create_dir_all(&maco_dir).context("create maco dir")?;
    let state_dir = maco_dir.join("state");
    if state_dir.exists() {
        fs::remove_dir_all(&state_dir).context("remove prior state dir")?;
    }
    let target = temp.path().join("state-target");
    fs::create_dir(&target).context("create state target")?;
    symlink(&target, &state_dir).context("create state symlink")?;

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
        .context("run merge with symlink state")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing symbolic links"));
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    Ok(())
}

#[test]
fn merge_apply_overwrites_unlocked_stale_owner_record() -> Result<()> {
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
        lock_record(99_999_999, "pr-publish", 1),
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
    let owner: Value = serde_json::from_slice(
        &fs::read(lock_dir.join("repository-mutation.lock")).context("read stable lock owner")?,
    )
    .context("parse stable lock owner")?;
    assert_eq!(owner["version"], 3);
    assert_eq!(owner["operation"], "merge-apply");
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

#[cfg(target_os = "linux")]
#[test]
fn merge_apply_kills_setsid_validation_descendant_before_accepting_success() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nreviewed candidate\n",
    )
    .context("edit worktree")?;
    let escaped_marker = temp
        .path()
        .join("escaped-validation-descendant")
        .to_string_lossy()
        .replace('\'', "'\"'\"'");
    let validation = format!(
        "setsid sh -c 'sleep 0.5; printf delayed > README.md; printf escaped > '\"'\"'{escaped_marker}'\"'\"'' </dev/null >/dev/null 2>&1 &"
    );

    let report = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        &validation,
        "--json",
    ])?;

    assert_eq!(report["status"], "applied");
    assert_eq!(
        report["preview"]["candidate"]["validations"][0]["status"],
        "passed"
    );
    thread::sleep(Duration::from_secs(1));
    assert!(!temp.path().join("escaped-validation-descendant").exists());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n\nreviewed candidate\n"
    );
    Ok(())
}

#[test]
fn merge_apply_rejects_successful_validation_that_mutates_initialized_submodule() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let dependency_path = temp.path().join("dependency");
    fs::create_dir_all(&dependency_path).context("create dependency repo")?;
    let dependency = Repository::init(&dependency_path).context("init dependency repo")?;
    fs::write(dependency_path.join("tracked.txt"), "baseline\n")
        .context("write dependency file")?;
    commit_all(&dependency, "dependency initial")?;

    let repo_path = create_committed_repo(temp.path())?;
    run_git(&[
        "-C",
        repo_path.to_str().context("repo path utf8")?,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        dependency_path.to_str().context("dependency path utf8")?,
        "modules/dependency",
    ])?;
    let primary = Repository::open(&repo_path).context("open primary repo")?;
    commit_all(&primary, "add dependency submodule")?;

    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nsubmodule candidate\n",
    )
    .context("edit worktree")?;
    let marker_removed = "git -c protocol.file.allow=always submodule update --init --no-fetch modules/dependency && printf 'mutated\\n' > modules/dependency/tracked.txt && rm modules/dependency/.git";
    let checkout_removed = "git -c protocol.file.allow=always submodule update --init --no-fetch modules/dependency && rm -rf modules/dependency";

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        marker_removed,
        "--validation-command",
        checkout_removed,
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["applied"], false);
    for validation in report["preview"]["candidate"]["validations"]
        .as_array()
        .context("validation reports")?
    {
        assert_eq!(validation["status"], "failed");
        assert!(validation["message"]
            .as_str()
            .context("validation message")?
            .contains("mutated tracked or non-ignored candidate state"));
    }
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("modules/dependency/tracked.txt"))
            .context("read primary dependency")?,
        "baseline\n"
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
    let trace_path = temp.path().join("ambient-git-trace.log");
    let trace2_path = temp.path().join("ambient-git-trace2.log");
    let redirected_stderr = temp.path().join("ambient-git-stderr.log");

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
        .env("GIT_TRACE", &trace_path)
        .env("GIT_TRACE2_EVENT", &trace2_path)
        .env("GIT_REDIRECT_STDERR", &redirected_stderr)
        .env("TMPDIR", &repo_path)
        .env("TMP", &repo_path)
        .env("TEMP", &repo_path)
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
    assert!(!trace_path.exists());
    assert!(!trace2_path.exists());
    assert!(!redirected_stderr.exists());
    let unexpected_runtime_file = fs::read_dir(&repo_path)
        .context("list primary repo")?
        .filter_map(std::result::Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().starts_with("maco-"));
    assert!(!unexpected_runtime_file);
    assert_eq!(git_status_porcelain(&repo_path)?, "");
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

fn git_status_porcelain(repo: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["status", "--porcelain"])
        .output()
        .context("git status")?;
    if !output.status.success() {
        anyhow::bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("git status utf8")
}

fn run_git(args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).output().context("run git")?;
    if !output.status.success() {
        anyhow::bail!("git failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn lock_record(pid: u32, operation: &str, process_start_ticks: u64) -> String {
    format!(
        "{{\"version\":3,\"pid\":{pid},\"nonce\":\"held-{pid}\",\"created_unix_seconds\":1,\"operation\":\"{operation}\",\"process_start\":{{\"kind\":\"linux_proc_start_ticks\",\"value\":{process_start_ticks}}}}}\n"
    )
}

#[cfg(target_os = "linux")]
fn process_start_ticks(pid: u32) -> Result<u64> {
    let bytes = fs::read(format!("/proc/{pid}/stat")).context("read process stat")?;
    let closing = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .context("process stat command terminator")?;
    let fields = bytes[closing + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    std::str::from_utf8(fields.get(19).context("process starttime field")?)?
        .parse()
        .context("parse process starttime")
}

fn path_with_prefix(prefix: &Path) -> Result<std::ffi::OsString> {
    let original_path = env::var_os("PATH").unwrap_or_default();
    let mut entries = vec![prefix.to_path_buf()];
    entries.extend(env::split_paths(&original_path));
    env::join_paths(entries).context("join PATH")
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
