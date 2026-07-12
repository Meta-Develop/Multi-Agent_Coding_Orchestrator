use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    env,
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn pr_publish_help_describes_bound_two_stage_validation() -> Result<()> {
    let output = Command::new(BIN)
        .args(["pr", "publish", "--help"])
        .output()
        .context("run pr publish help")?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).context("help utf8")?;
    assert!(help.contains("clean committed candidate"));
    assert!(help.contains("legacy report arrays are unbound"));
    assert!(help.contains("bound exactly to its current preview binding"));
    Ok(())
}

#[test]
fn pr_preview_reports_safe_fake_preview_for_claimed_worktree_edit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\npreview\n").context("edit worktree")?;

    let preview = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;

    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["forge"], "fake");
    assert_eq!(preview["created"], false);
    assert_eq!(preview["pushed"], false);
    assert_eq!(preview["readiness"], "safe");
    assert_eq!(preview["preview"]["safety"]["readiness"]["status"], "safe");
    assert_eq!(preview["changed_paths"][0], "README.md");
    assert_eq!(
        preview["blockers"]
            .as_array()
            .context("blockers array")?
            .len(),
        0
    );

    Ok(())
}

#[test]
fn pr_publish_fake_commits_uncommitted_worktree_changes_without_pushing() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\npublish\n").context("edit worktree")?;

    let report = run_success_json(&[
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
    ])?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["forge"], "fake");
    assert_eq!(report["created"], true);
    assert_eq!(report["pushed"], false);
    assert_eq!(report["readiness"], "safe");
    assert_eq!(report["changed_paths"][0], "README.md");
    assert!(report["commit_id"].as_str().context("commit id")?.len() >= 12);
    assert_eq!(report["head_id"], report["commit_id"]);
    let branch = report["branch"].as_str().context("branch string")?;
    assert_eq!(
        report["pr_url"],
        fake_pr_url("agent-a", branch, &["README.md"])
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    assert_eq!(git_status_porcelain(worktree_path)?, "");

    Ok(())
}

#[test]
fn pr_publish_blocks_when_claimed_path_changes_during_internal_commit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nreviewed snapshot\n",
    )
    .context("edit worktree")?;

    let fake_bin = temp.path().join("bin");
    let wrapper = write_git_wrapper_that_mutates_after_real_add(&fake_bin)?;
    let path = path_with_prefix(&fake_bin)?;
    let real_git = find_command("git")?;
    let mutation_target = worktree_path.join("README.md");
    let report = run_failure_json_with_env(
        &[
            "pr",
            "publish",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--forge",
            "git",
            "--json",
        ],
        &[
            ("PATH", path.as_os_str()),
            ("MACO_REAL_GIT", real_git.as_os_str()),
            ("MACO_MUTATION_TARGET", mutation_target.as_os_str()),
        ],
    )?;

    assert!(wrapper.exists());
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["pushed"], false);
    assert_eq!(report["created"], false);
    assert_contains(&report["blockers"], "stale_base")?;
    assert!(
        report["commit_id"]
            .as_str()
            .context("local commit id")?
            .len()
            >= 12
    );
    assert_eq!(
        git_show_file(worktree_path, "HEAD:README.md")?,
        "# Smoke\n\nreviewed snapshot\n"
    );
    assert_eq!(
        fs::read_to_string(&mutation_target).context("read late mutation")?,
        "# Smoke\n\nlate mutation\n"
    );
    let branch = report["branch"].as_str().context("branch")?;
    assert!(!git_ref_exists(
        &origin_path,
        &format!("refs/heads/{branch}")
    )?);
    Ok(())
}

#[test]
fn pr_publish_git_pushes_agent_branch_without_calling_gh() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ngit push\n").context("edit worktree")?;
    let fake_bin = temp.path().join("bin");
    let gh_log = write_failing_gh(&fake_bin)?;
    let path = path_with_prefix(&fake_bin)?;

    let report = run_success_json_with_env(
        &[
            "pr",
            "publish",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--forge",
            "git",
            "--json",
        ],
        &[("PATH", path.as_os_str())],
    )?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["forge"], "git");
    assert_eq!(report["pushed"], true);
    assert_eq!(report["created"], false);
    assert_eq!(report["pr_url"], Value::Null);
    assert_eq!(
        report["next_action"],
        "open a pull request on your Git host manually"
    );
    assert!(report["commit_id"].as_str().context("commit id")?.len() >= 12);
    assert_eq!(report["head_id"], report["commit_id"]);

    let branch = report["branch"].as_str().context("branch string")?;
    let remote_head = git_rev_parse(&origin_path, &format!("refs/heads/{branch}"))?;
    assert_eq!(remote_head, report["head_id"].as_str().context("head id")?);
    assert_eq!(
        git_show_bare_file(&origin_path, &format!("{remote_head}:README.md"))?,
        "# Smoke\n\ngit push\n"
    );
    assert_eq!(git_status_porcelain(worktree_path)?, "");
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    assert!(
        !gh_log.exists(),
        "git forge must not call gh; log was {}",
        gh_log.display()
    );

    Ok(())
}

#[test]
fn pr_publish_github_sanitizes_git_environment_for_push_and_gh() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ngithub pr\n")
        .context("edit worktree")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    let committed = commit_all(&agent_repo, "github candidate").context("commit candidate")?;

    let fake_bin = temp.path().join("bin");
    let gh_env_path = temp.path().join("gh-pr-env.txt");
    fs::create_dir_all(&fake_bin).context("create fake bin dir")?;
    let gh_path = fake_bin.join("gh");
    fs::write(
        &gh_path,
        r#"#!/bin/sh
printf 'GIT_DIR=%s\n' "${GIT_DIR-unset}" > "$MACO_GH_ENV"
printf 'GIT_WORK_TREE=%s\n' "${GIT_WORK_TREE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_INDEX_FILE=%s\n' "${GIT_INDEX_FILE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_COMMON_DIR=%s\n' "${GIT_COMMON_DIR-unset}" >> "$MACO_GH_ENV"
printf 'GIT_OBJECT_DIRECTORY=%s\n' "${GIT_OBJECT_DIRECTORY-unset}" >> "$MACO_GH_ENV"
printf 'GIT_ALTERNATE_OBJECT_DIRECTORIES=%s\n' "${GIT_ALTERNATE_OBJECT_DIRECTORIES-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_COUNT=%s\n' "${GIT_CONFIG_COUNT-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_KEY_0=%s\n' "${GIT_CONFIG_KEY_0-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_VALUE_0=%s\n' "${GIT_CONFIG_VALUE_0-unset}" >> "$MACO_GH_ENV"
printf '%s\n' 'https://github.example/pull/7'
"#,
    )
    .context("write fake gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat fake gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod fake gh")?;
    let path = path_with_prefix(&fake_bin)?;

    let report = run_success_json_with_env(
        &[
            "pr",
            "publish",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--forge",
            "github",
            "--json",
        ],
        &[
            ("PATH", path.as_os_str()),
            ("MACO_GH_ENV", gh_env_path.as_os_str()),
            ("GIT_DIR", OsStr::new("/decoy/git-dir")),
            ("GIT_WORK_TREE", OsStr::new("/decoy/worktree")),
            ("GIT_INDEX_FILE", OsStr::new("/decoy/index")),
            ("GIT_COMMON_DIR", OsStr::new("/decoy/common")),
            ("GIT_OBJECT_DIRECTORY", OsStr::new("/decoy/objects")),
            (
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                OsStr::new("/decoy/alternates"),
            ),
            ("GIT_CONFIG_COUNT", OsStr::new("1")),
            ("GIT_CONFIG_KEY_0", OsStr::new("user.name")),
            ("GIT_CONFIG_VALUE_0", OsStr::new("decoy")),
        ],
    )?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["pushed"], true);
    assert_eq!(report["created"], true);
    assert_eq!(report["pr_url"], "https://github.example/pull/7");
    assert_eq!(report["head_id"], committed.to_string());
    let branch = report["branch"].as_str().context("branch")?;
    assert_eq!(
        git_rev_parse(&origin_path, &format!("refs/heads/{branch}"))?,
        committed.to_string()
    );
    assert_eq!(
        fs::read_to_string(&gh_env_path).context("read gh pr environment")?,
        "GIT_DIR=unset\nGIT_WORK_TREE=unset\nGIT_INDEX_FILE=unset\nGIT_COMMON_DIR=unset\nGIT_OBJECT_DIRECTORY=unset\nGIT_ALTERNATE_OBJECT_DIRECTORIES=unset\nGIT_CONFIG_COUNT=unset\nGIT_CONFIG_KEY_0=unset\nGIT_CONFIG_VALUE_0=unset\n"
    );
    Ok(())
}

#[test]
fn merge_apply_cannot_run_while_pr_publish_pushes_reviewed_commit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\npublish lock\n")
        .context("edit worktree")?;

    let fake_bin = temp.path().join("bin");
    write_git_wrapper_that_waits_before_push(&fake_bin)?;
    let path = path_with_prefix(&fake_bin)?;
    let real_git = find_command("git")?;
    let push_ready = temp.path().join("push-ready");
    let push_release = temp.path().join("push-release");
    let mut publish = Command::new(BIN);
    publish
        .args([
            "pr",
            "publish",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--forge",
            "git",
            "--json",
        ])
        .env("PATH", &path)
        .env("MACO_REAL_GIT", &real_git)
        .env("MACO_PUSH_READY", &push_ready)
        .env("MACO_PUSH_RELEASE", &push_release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut publish = publish.spawn().context("start pr publication")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !push_ready.exists() {
        if Instant::now() >= deadline {
            let _ = publish.kill();
            anyhow::bail!("publication did not reach push before timeout");
        }
        thread::sleep(Duration::from_millis(20));
    }

    let apply = Command::new(BIN)
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
        .context("run concurrent merge apply")?;
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nlate branch commit\n",
    )
    .context("write late branch change")?;
    let late_head = commit_all(
        &Repository::open(worktree_path).context("reopen agent repo")?,
        "late branch move",
    )
    .context("commit late branch move")?;
    fs::write(&push_release, "release\n").context("release push")?;
    let published = publish.wait_with_output().context("wait for publication")?;

    assert!(!apply.status.success());
    let apply_stderr = String::from_utf8_lossy(&apply.stderr);
    assert!(apply_stderr.contains("repository mutation lock"));
    assert!(apply_stderr.contains("pr-publish"));
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let report: Value = serde_json::from_slice(&published.stdout).context("parse publication")?;
    assert_eq!(report["status"], "published");
    let branch = report["branch"].as_str().context("branch")?;
    let reviewed_head = report["head_id"].as_str().context("head id")?;
    assert_ne!(reviewed_head, late_head.to_string());
    assert_eq!(
        git_rev_parse(&origin_path, &format!("refs/heads/{branch}"))?,
        reviewed_head
    );
    assert_eq!(
        git_show_bare_file(&origin_path, &format!("{reviewed_head}:README.md"))?,
        "# Smoke\n\npublish lock\n"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn pr_publish_fake_blocks_unclaimed_worktree_edits_with_json_report() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nblocked\n").context("edit worktree")?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["created"], false);
    assert_eq!(report["pushed"], false);
    assert_contains(&report["blockers"], "unclaimed_edits")?;
    assert_eq!(
        report["preview"]["candidate"]["unclaimed_changed_paths"][0],
        "README.md"
    );
    assert_eq!(git_status_porcelain(worktree_path)?, " M README.md\n");

    Ok(())
}

#[test]
fn pr_publish_required_validation_blocks_missing_evidence() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\npublish\n").context("edit worktree")?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--forge",
        "fake",
        "--require-validation",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["created"], false);
    assert_eq!(report["validation_required"], true);
    assert_contains(&report["blockers"], "validation_missing")?;
    assert_eq!(
        report["preview"]["safety"]["readiness"]["details"][0]["kind"],
        "validation_missing"
    );
    assert_eq!(
        report["preview"]["safety"]["readiness"]["details"][0]["paths"][0],
        "README.md"
    );
    assert_eq!(git_status_porcelain(worktree_path)?, " M README.md\n");

    Ok(())
}

#[test]
fn pr_publish_required_validation_accepts_exact_candidate_binding() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nbound pr\n").context("edit worktree")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    commit_all(&agent_repo, "committed candidate").context("commit candidate")?;
    let preview = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("bound-pr-validation.json");
    write_bound_validation(
        &validation_path,
        &preview["preview"]["candidate"]["validation_binding"],
    )?;

    let report = run_success_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["validation_required"], true);
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "bound"
    );
    assert_eq!(report["commit_id"], Value::Null);
    Ok(())
}

#[test]
fn pr_publish_required_validation_refuses_dirty_bound_candidate_before_commit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ndirty bound\n")
        .context("edit worktree")?;
    let preview = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("dirty-bound-validation.json");
    write_bound_validation(
        &validation_path,
        &preview["preview"]["candidate"]["validation_binding"],
    )?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["created"], false);
    assert_eq!(report["commit_id"], Value::Null);
    assert!(report["next_action"]
        .as_str()
        .context("next action")?
        .contains("commit the candidate"));
    assert_eq!(git_status_porcelain(worktree_path)?, " M README.md\n");
    Ok(())
}

#[test]
fn pr_publish_required_validation_rejects_legacy_unbound_pass() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlegacy pr\n")
        .context("edit worktree")?;
    let validation_path = temp.path().join("legacy-pr-validation.json");
    fs::write(
        &validation_path,
        r#"[{"name":"unit","status":"passed","paths":["README.md"]}]"#,
    )
    .context("write legacy validation")?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "unbound"
    );
    assert_contains(&report["blockers"], "validation_missing")?;
    assert_eq!(git_status_porcelain(worktree_path)?, " M README.md\n");
    Ok(())
}

#[test]
fn pr_preview_required_validation_rejects_mismatched_candidate_binding() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nfirst pr\n")
        .context("edit first candidate")?;
    let initial = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("stale-pr-validation.json");
    write_bound_validation(
        &validation_path,
        &initial["preview"]["candidate"]["validation_binding"],
    )?;
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nsecond pr\n")
        .context("change candidate")?;

    let report = run_success_json(&[
        "pr",
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

    assert_eq!(report["status"], "blocked");
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "mismatched"
    );
    assert_contains(&report["blockers"], "validation_missing")?;
    Ok(())
}

#[test]
fn pr_publish_refuses_live_repo_common_publication_lock() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nlocked publish\n",
    )
    .context("edit worktree")?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    fs::write(
        lock_dir.join("repository-mutation.lock"),
        format!(
            "{{\"version\":1,\"pid\":{},\"nonce\":\"held\",\"created_unix_seconds\":1,\"operation\":\"merge-apply\"}}\n",
            std::process::id()
        ),
    )
    .context("write publication lock")?;

    let output = Command::new(BIN)
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
        .context("run locked publication")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("by live pid"));
    assert!(stderr.contains("merge-apply"));
    assert_eq!(git_status_porcelain(worktree_path)?, " M README.md\n");
    Ok(())
}

#[test]
fn pr_publish_bound_evidence_rejects_later_same_path_commit_without_push() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nfirst commit\n")
        .context("edit first candidate")?;
    commit_all(&agent_repo, "first candidate").context("commit first candidate")?;
    let preview = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let validation_path = temp.path().join("first-binding.json");
    write_bound_validation(
        &validation_path,
        &preview["preview"]["candidate"]["validation_binding"],
    )?;
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nsecond commit\n",
    )
    .context("edit second candidate")?;
    let second = commit_all(&agent_repo, "second candidate").context("commit second candidate")?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--require-validation",
        "--forge",
        "git",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["pushed"], false);
    assert_eq!(report["created"], false);
    assert_eq!(git_status_porcelain(worktree_path)?, "");
    assert!(!git_ref_exists(
        &origin_path,
        &format!(
            "refs/heads/{}",
            report["branch"].as_str().context("branch")?
        )
    )?);
    assert_eq!(
        Repository::open(worktree_path)
            .context("reopen agent repo")?
            .head()
            .context("read agent head")?
            .target(),
        Some(second)
    );
    Ok(())
}

#[test]
fn issue_preview_redacts_body_and_does_not_create_issue() -> Result<()> {
    let report = run_success_json(&[
        "issue",
        "preview",
        "--title",
        "Secret leak",
        "--body",
        "API_TOKEN=secret",
        "--json",
    ])?;

    assert_eq!(report["title"], "Secret leak");
    assert_eq!(report["created"], false);
    assert_eq!(report["url"], Value::Null);
    assert_eq!(report["redacted_body"], "API_TOKEN=<redacted:secret>");
    assert_eq!(report["redactions"]["total_replacements"], 1);
    assert!(!serde_json::to_string(&report)
        .context("serialize report")?
        .contains("API_TOKEN=secret"));

    Ok(())
}

#[test]
fn issue_create_fake_returns_deterministic_local_issue_url() -> Result<()> {
    let report = run_success_json(&[
        "issue",
        "create",
        "--title",
        "Document fake forge",
        "--body",
        "No network",
        "--label",
        "docs",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["title"], "Document fake forge");
    assert_eq!(report["forge"], "fake");
    assert_eq!(report["created"], true);
    assert_eq!(
        report["url"],
        fake_issue_url("Document fake forge", "No network", &["docs"])
    );

    Ok(())
}

#[test]
fn issue_create_github_passes_redacted_body_to_gh() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    let fake_bin = temp.path().join("bin");
    let gh_args_path = temp.path().join("gh-args.txt");
    let gh_env_path = temp.path().join("gh-env.txt");
    fs::create_dir_all(&repo_path).context("create repo dir")?;
    fs::create_dir_all(&fake_bin).context("create fake bin dir")?;
    let gh_path = fake_bin.join("gh");
    fs::write(
        &gh_path,
        r#"#!/bin/sh
: > "$MACO_GH_ARGS"
for arg in "$@"; do
    printf '%s\n' "$arg" >> "$MACO_GH_ARGS"
done
printf 'GIT_DIR=%s\n' "${GIT_DIR-unset}" > "$MACO_GH_ENV"
printf 'GIT_WORK_TREE=%s\n' "${GIT_WORK_TREE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_INDEX_FILE=%s\n' "${GIT_INDEX_FILE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_COMMON_DIR=%s\n' "${GIT_COMMON_DIR-unset}" >> "$MACO_GH_ENV"
printf 'GIT_OBJECT_DIRECTORY=%s\n' "${GIT_OBJECT_DIRECTORY-unset}" >> "$MACO_GH_ENV"
printf 'GIT_ALTERNATE_OBJECT_DIRECTORIES=%s\n' "${GIT_ALTERNATE_OBJECT_DIRECTORIES-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_COUNT=%s\n' "${GIT_CONFIG_COUNT-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_KEY_0=%s\n' "${GIT_CONFIG_KEY_0-unset}" >> "$MACO_GH_ENV"
printf 'GIT_CONFIG_VALUE_0=%s\n' "${GIT_CONFIG_VALUE_0-unset}" >> "$MACO_GH_ENV"
printf '%s\n' 'https://github.example/issues/1'
"#,
    )
    .context("write fake gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat fake gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod fake gh")?;
    let original_path = env::var_os("PATH").unwrap_or_default();
    let mut path_entries = vec![fake_bin.clone()];
    path_entries.extend(env::split_paths(&original_path));
    let path = env::join_paths(path_entries).context("join PATH")?;

    let report = run_success_json_with_env(
        &[
            "issue",
            "create",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--title",
            "Secret leak",
            "--body",
            "API_TOKEN=secret",
            "--forge",
            "github",
            "--json",
        ],
        &[
            ("PATH", path.as_os_str()),
            ("MACO_GH_ARGS", gh_args_path.as_os_str()),
            ("MACO_GH_ENV", gh_env_path.as_os_str()),
            ("GIT_DIR", OsStr::new("/decoy/git-dir")),
            ("GIT_WORK_TREE", OsStr::new("/decoy/worktree")),
            ("GIT_INDEX_FILE", OsStr::new("/decoy/index")),
            ("GIT_COMMON_DIR", OsStr::new("/decoy/common")),
            ("GIT_OBJECT_DIRECTORY", OsStr::new("/decoy/objects")),
            (
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                OsStr::new("/decoy/alternates"),
            ),
            ("GIT_CONFIG_COUNT", OsStr::new("1")),
            ("GIT_CONFIG_KEY_0", OsStr::new("user.name")),
            ("GIT_CONFIG_VALUE_0", OsStr::new("decoy")),
        ],
    )?;

    assert_eq!(report["forge"], "github");
    assert_eq!(report["created"], true);
    assert_eq!(report["url"], "https://github.example/issues/1");
    assert_eq!(report["redacted_body"], "API_TOKEN=<redacted:secret>");
    let gh_args = fs::read_to_string(&gh_args_path).context("read fake gh args")?;
    assert!(gh_args.contains("--body\nAPI_TOKEN=<redacted:secret>\n"));
    assert!(!gh_args.contains("API_TOKEN=secret"));
    assert_eq!(
        fs::read_to_string(&gh_env_path).context("read fake gh environment")?,
        "GIT_DIR=unset\nGIT_WORK_TREE=unset\nGIT_INDEX_FILE=unset\nGIT_COMMON_DIR=unset\nGIT_OBJECT_DIRECTORY=unset\nGIT_ALTERNATE_OBJECT_DIRECTORIES=unset\nGIT_CONFIG_COUNT=unset\nGIT_CONFIG_KEY_0=unset\nGIT_CONFIG_VALUE_0=unset\n"
    );

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

fn run_success_json_with_env(args: &[&str], envs: &[(&str, &OsStr)]) -> Result<Value> {
    let mut command = Command::new(BIN);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().context("run maco")?;
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

fn run_failure_json_with_env(args: &[&str], envs: &[(&str, &OsStr)]) -> Result<Value> {
    let mut command = Command::new(BIN);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).context("parse failure json")
}

fn create_committed_repo(root: &Path) -> Result<PathBuf> {
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
    configure_test_identity(&repo)?;
    commit_all(&repo, "initial commit")?;

    Ok(repo_path)
}

fn configure_test_identity(repo: &Repository) -> Result<()> {
    let mut config = repo.config().context("open config")?;
    config
        .set_str("user.name", "maco test")
        .context("set user.name")?;
    config
        .set_str("user.email", "maco-test@example.invalid")
        .context("set user.email")?;
    Ok(())
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

fn init_bare_origin(root: &Path) -> Result<PathBuf> {
    let origin_path = root.join("origin.git");
    let output = Command::new("git")
        .args(["init", "--bare"])
        .arg(&origin_path)
        .output()
        .context("git init --bare")?;
    if !output.status.success() {
        anyhow::bail!(
            "git init --bare failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(origin_path)
}

fn write_failing_gh(path_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path_dir).context("create fake bin dir")?;
    let gh_path = path_dir.join("gh");
    let log_path = path_dir.join("gh-called.log");
    fs::write(
        &gh_path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 99\n",
            log_path.display()
        ),
    )
    .context("write fake gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat fake gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod fake gh")?;
    Ok(log_path)
}

fn write_git_wrapper_that_mutates_after_real_add(path_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path_dir).context("create fake bin dir")?;
    let git_path = path_dir.join("git");
    fs::write(
        &git_path,
        r#"#!/bin/sh
saw_add=false
for arg in "$@"; do
    if [ "$arg" = add ]; then
        saw_add=true
    fi
done
"$MACO_REAL_GIT" "$@"
status=$?
if [ "$status" -eq 0 ] && [ "$saw_add" = true ] && [ -z "${GIT_OBJECT_DIRECTORY+x}" ]; then
    printf '# Smoke\n\nlate mutation\n' > "$MACO_MUTATION_TARGET"
fi
exit "$status"
"#,
    )
    .context("write mutating git wrapper")?;
    let mut permissions = fs::metadata(&git_path)
        .context("stat mutating git wrapper")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git_path, permissions).context("chmod mutating git wrapper")?;
    Ok(git_path)
}

fn write_git_wrapper_that_waits_before_push(path_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path_dir).context("create fake bin dir")?;
    let git_path = path_dir.join("git");
    fs::write(
        &git_path,
        r#"#!/bin/sh
saw_push=false
for arg in "$@"; do
    if [ "$arg" = push ]; then
        saw_push=true
    fi
done
if [ "$saw_push" = true ]; then
    printf ready > "$MACO_PUSH_READY"
    while [ ! -f "$MACO_PUSH_RELEASE" ]; do
        sleep 0.05
    done
fi
exec "$MACO_REAL_GIT" "$@"
"#,
    )
    .context("write waiting git wrapper")?;
    let mut permissions = fs::metadata(&git_path)
        .context("stat waiting git wrapper")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git_path, permissions).context("chmod waiting git wrapper")?;
    Ok(git_path)
}

fn find_command(name: &str) -> Result<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v -- \"$1\"", "find-command", name])
        .output()
        .context("locate command")?;
    if !output.status.success() {
        anyhow::bail!("command not found: {name}");
    }
    Ok(PathBuf::from(
        String::from_utf8(output.stdout)
            .context("command path utf8")?
            .trim(),
    ))
}

fn path_with_prefix(prefix: &Path) -> Result<std::ffi::OsString> {
    let original_path = env::var_os("PATH").unwrap_or_default();
    let mut entries = vec![prefix.to_path_buf()];
    entries.extend(env::split_paths(&original_path));
    env::join_paths(entries).context("join PATH")
}

fn run_git(args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).output().context("run git")?;
    if !output.status.success() {
        anyhow::bail!("git failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn git_rev_parse(bare_repo: &Path, ref_name: &str) -> Result<String> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo)
        .args(["rev-parse", ref_name])
        .output()
        .context("git rev-parse")?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_ref_exists(bare_repo: &Path, ref_name: &str) -> Result<bool> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo)
        .args(["show-ref", "--verify", "--quiet", ref_name])
        .output()
        .context("git show-ref")?;
    Ok(output.status.success())
}

fn git_show_bare_file(bare_repo: &Path, revision: &str) -> Result<String> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo)
        .args(["show", revision])
        .output()
        .context("git show bare file")?;
    if !output.status.success() {
        anyhow::bail!(
            "git show bare file failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("bare file utf8")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn git_status_porcelain(worktree_path: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .args(["status", "--porcelain"])
        .output()
        .context("git status")?;
    if !output.status.success() {
        anyhow::bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn git_show_file(worktree_path: &Path, revision: &str) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .args(["show", revision])
        .output()
        .context("git show")?;
    if !output.status.success() {
        anyhow::bail!(
            "git show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("git show output utf8")
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

fn fake_pr_url(agent_id: &str, branch: &str, changed_paths: &[&str]) -> String {
    let mut input = String::new();
    input.push_str(agent_id);
    input.push('\n');
    input.push_str(branch);
    for path in changed_paths {
        input.push('\n');
        input.push_str(path);
    }
    format!(
        "fake://pr/{}-{:016x}",
        sanitize_url_segment(agent_id),
        stable_hash(input.as_bytes())
    )
}

fn fake_issue_url(title: &str, body: &str, labels: &[&str]) -> String {
    let mut input = String::new();
    input.push_str(title);
    input.push('\n');
    input.push_str(body);
    for label in labels {
        input.push('\n');
        input.push_str(label);
    }
    format!(
        "fake://issue/{}-{:016x}",
        sanitize_url_segment(title),
        stable_hash(input.as_bytes())
    )
}

fn sanitize_url_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if segment.is_empty() {
        "item".to_string()
    } else {
        segment
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
