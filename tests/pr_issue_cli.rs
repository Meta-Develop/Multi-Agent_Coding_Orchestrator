#![cfg(unix)]

mod support;

use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    env,
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
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
    assert!(help.contains("origin host/owner/repo"));
    assert!(help.contains("OID receipt"));
    assert!(help.contains("journals retry state"));
    assert!(help.contains("--from-branch"));
    assert!(help.contains("--squash-onto"));
    assert!(help.contains("--exclude"));
    Ok(())
}

#[test]
fn pr_preview_reports_safe_fake_preview_for_claimed_worktree_edit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
fn pr_preview_redacts_remote_url_userinfo_query_and_fragment() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        "https://user:super-secret@example.invalid/repo.git?token=query-secret#fragment-secret",
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nredacted remote\n",
    )
    .context("edit worktree")?;

    let preview = run_success_json(&[
        "pr",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--forge",
        "github",
        "--json",
    ])?;
    let serialized = serde_json::to_string(&preview).context("serialize preview")?;
    assert_eq!(
        preview["remote"],
        "https://<redacted>@example.invalid/repo.git?<redacted>#<redacted>"
    );
    assert!(!serialized.contains("user"));
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("query-secret"));
    assert!(!serialized.contains("fragment-secret"));
    Ok(())
}

#[test]
fn pr_publish_fake_commits_uncommitted_worktree_changes_without_pushing() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
fn pr_publish_fake_ignores_untrusted_git_path_shadow_during_internal_commit() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nreviewed snapshot\n",
    )
    .context("edit worktree")?;

    let fake_bin = temp.path().join("bin");
    let real_git = find_command("git")?;
    let mutation_target = worktree_path.join("README.md");
    let wrapper =
        write_git_wrapper_that_mutates_after_real_add(&fake_bin, &real_git, &mutation_target)?;
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
            "fake",
            "--json",
        ],
        &[("PATH", path.as_os_str())],
    )?;

    assert!(wrapper.exists());
    assert_eq!(report["status"], "published");
    assert_eq!(report["pushed"], false);
    assert_eq!(report["created"], true);
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
        "# Smoke\n\nreviewed snapshot\n"
    );
    Ok(())
}

#[test]
fn pr_publish_git_refuses_local_origin_without_calling_gh() -> Result<()> {
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ngit push\n").context("edit worktree")?;
    let fake_bin = temp.path().join("bin");
    let gh_log = write_failing_gh(&fake_bin)?;
    let path = path_with_prefix(&fake_bin)?;

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
            "git",
            "--json",
        ])
        .env("PATH", path)
        .output()
        .context("run Git publication with local origin")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    let reviewed_head = Repository::open(worktree_path)
        .context("reopen agent repo")?
        .head()
        .context("read reviewed HEAD")?
        .target()
        .context("reviewed HEAD target")?
        .to_string();
    let remote_ref = format!("refs/heads/maco/review/agent-a/{reviewed_head}");
    assert!(!git_ref_exists(&origin_path, &remote_ref)?);
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
fn pr_publish_git_refuses_local_origin_before_config_url_redirects_can_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    let attack_path = temp.path().join("attack.git");
    let local_attack_path = temp.path().join("local-attack.git");
    Repository::init_bare(&attack_path).context("init attack origin")?;
    Repository::init_bare(&local_attack_path).context("init local attack origin")?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let local_redirect_key = format!("url.{}.pushInsteadOf", path_str(&local_attack_path)?);
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "config",
        "--add",
        &local_redirect_key,
        path_str(&origin_path)?,
    ])?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "config",
        "extensions.worktreeConfig",
        "true",
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    let redirect_key = format!("url.{}.insteadOf", path_str(&attack_path)?);
    run_git(&[
        "-C",
        path_str(worktree_path)?,
        "config",
        "--worktree",
        "--add",
        &redirect_key,
        path_str(&origin_path)?,
    ])?;
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nredirect audit\n",
    )
    .context("edit worktree")?;

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
            "git",
            "--json",
        ])
        .output()
        .context("run Git publication with local redirected origin")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    let reviewed_head = Repository::open(worktree_path)
        .context("reopen agent repo")?
        .head()
        .context("read reviewed HEAD")?
        .target()
        .context("reviewed HEAD target")?
        .to_string();
    let remote_ref = format!("refs/heads/maco/review/agent-a/{reviewed_head}");
    assert!(!git_ref_exists(&origin_path, &remote_ref)?);
    assert!(!git_ref_exists(&attack_path, &remote_ref)?);
    assert!(!git_ref_exists(&local_attack_path, &remote_ref)?);
    Ok(())
}

#[test]
fn pr_publish_fake_does_not_execute_repository_filter_or_diff_driver() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let filter_marker = temp.path().join("filter-marker");
    let diff_marker = temp.path().join("diff-marker");
    let filter = temp.path().join("filter-driver");
    let diff = temp.path().join("diff-driver");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf invoked > {}\ncat\n",
            shell_quote_path(&filter_marker)
        ),
    )?;
    fs::write(
        &diff,
        format!(
            "#!/bin/sh\nprintf invoked > {}\nexit 0\n",
            shell_quote_path(&diff_marker)
        ),
    )?;
    for driver in [&filter, &diff] {
        let mut permissions = fs::metadata(driver)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(driver, permissions)?;
    }
    fs::write(
        repo_path.join(".gitattributes"),
        "README.md filter=attack diff=attack\n",
    )?;
    let repository = Repository::open(&repo_path)?;
    commit_all(&repository, "add hostile attributes")?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "config",
        "filter.attack.clean",
        path_str(&filter)?,
    ])?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "config",
        "diff.attack.command",
        path_str(&diff)?,
    ])?;
    let repo = path_str(&repo_path)?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    let _ = fs::remove_file(&filter_marker);
    let _ = fs::remove_file(&diff_marker);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nfilter isolation\n",
    )?;

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
    assert!(!filter_marker.exists());
    assert!(!diff_marker.exists());
    Ok(())
}

#[test]
fn pr_publish_git_refuses_ssh_without_running_home_repo_or_env_commands() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        "ssh://localhost:1/owner/repo.git",
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nssh env audit\n",
    )
    .context("edit worktree")?;
    let invoked = temp.path().join("custom-ssh-invoked");
    let fake_ssh = temp.path().join("fake-ssh");
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nprintf invoked > {}\nexit 1\n",
            shell_quote_path(&invoked)
        ),
    )
    .context("write fake SSH command")?;
    let mut permissions = fs::metadata(&fake_ssh)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_ssh, permissions)?;
    let home = temp.path().join("hostile-home");
    fs::create_dir_all(home.join(".ssh"))?;
    fs::write(
        home.join(".ssh/config"),
        format!(
            "Host *\n  ProxyCommand {}\n  PermitLocalCommand yes\n  LocalCommand {}\n",
            fake_ssh.display(),
            fake_ssh.display()
        ),
    )?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "config",
        "core.sshCommand",
        path_str(&fake_ssh)?,
    ])?;

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
            "git",
            "--json",
        ])
        .env("GIT_SSH_COMMAND", &fake_ssh)
        .env("HOME", &home)
        .output()
        .context("run publication with custom SSH injection")?;

    assert!(!output.status.success());
    assert!(!invoked.exists());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("publication supports only canonical HTTPS remotes"));
    Ok(())
}

#[test]
fn pr_publish_github_rejects_local_origin_and_untrusted_gh_shadow() -> Result<()> {
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ngithub pr\n")
        .context("edit worktree")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    let committed = commit_all(&agent_repo, "github candidate").context("commit candidate")?;
    let committed_text = committed.to_string();

    let fake_bin = temp.path().join("bin");
    let gh_env_path = temp.path().join("gh-pr-env.txt");
    let gh_state_path = temp.path().join("gh-pr-state");
    let git_trace_path = temp.path().join("github-trace.log");
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
printf 'GIT_TRACE=%s\n' "${GIT_TRACE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_TRACE2_EVENT=%s\n' "${GIT_TRACE2_EVENT-unset}" >> "$MACO_GH_ENV"
printf 'GIT_REDIRECT_STDERR=%s\n' "${GIT_REDIRECT_STDERR-unset}" >> "$MACO_GH_ENV"
if [ "$1 $2" = 'pr list' ]; then
    if [ -f "$MACO_GH_STATE" ]; then
        printf '[{"url":"https://github.example/pull/7","headRefOid":"%s","number":7,"baseRefName":"main","state":"OPEN","isDraft":true}]\n' "$MACO_EXPECTED_OID"
    else
        printf '[]\n'
    fi
elif [ "$1 $2" = 'pr create' ]; then
    printf created > "$MACO_GH_STATE"
    printf '%s\n' 'https://github.example/pull/7'
elif [ "$1 $2" = 'pr view' ]; then
    printf '{"url":"https://github.example/pull/7","headRefOid":"%s","number":7,"baseRefName":"main","state":"OPEN","isDraft":true}\n' "$MACO_EXPECTED_OID"
else
    exit 64
fi
"#,
    )
    .context("write fake gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat fake gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod fake gh")?;
    let path = path_with_prefix(&fake_bin)?;

    let mut command = Command::new(BIN);
    command
        .args([
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
        ])
        .env("PATH", &path)
        .env("MACO_GH_ENV", &gh_env_path)
        .env("MACO_GH_STATE", &gh_state_path)
        .env("MACO_EXPECTED_OID", &committed_text)
        .env("GH_REPO", "attacker/wrong-repo")
        .env("GH_HOST", "attacker.invalid")
        .env("GIT_SSH_COMMAND", &gh_path)
        .env("GIT_TRACE", &git_trace_path);
    let output = command
        .output()
        .context("run rejected GitHub publication")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    assert!(!gh_env_path.exists());
    assert!(!gh_state_path.exists());
    assert!(!git_trace_path.exists());
    Ok(())
}

#[test]
fn pr_publish_github_refuses_local_origin_before_untrusted_gh_can_move_remote_ref() -> Result<()> {
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("README.md"),
        "# Smoke\n\nreviewed github\n",
    )
    .context("edit candidate")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    let reviewed = commit_all(&agent_repo, "reviewed candidate")?;
    let attack = create_unreferenced_readme_commit(
        &agent_repo,
        reviewed,
        "# Smoke\n\nunreviewed remote move\n",
    )?;
    run_git(&[
        "-C",
        path_str(worktree_path)?,
        "push",
        "origin",
        &format!("{attack}:refs/heads/attack-source"),
    ])?;

    let fake_bin = temp.path().join("bin");
    let state = temp.path().join("attack-pr-state");
    fs::create_dir_all(&fake_bin).context("create fake bin")?;
    let gh_path = fake_bin.join("gh");
    fs::write(
        &gh_path,
        r#"#!/bin/sh
if [ "$1 $2" = 'pr list' ]; then
    if [ -f "$MACO_GH_STATE" ]; then
        printf '[{"url":"https://github.example/pull/9","headRefOid":"%s","number":9,"baseRefName":"main","state":"OPEN","isDraft":true}]\n' "$MACO_ATTACK_OID"
    else
        printf '[]\n'
    fi
elif [ "$1 $2" = 'pr create' ]; then
    head=
    while [ "$#" -gt 0 ]; do
        if [ "$1" = '--head' ]; then
            shift
            head=$1
            break
        fi
        shift
    done
    git --git-dir "$MACO_ORIGIN" update-ref "refs/heads/$head" "$MACO_ATTACK_OID" || exit 65
    printf created > "$MACO_GH_STATE"
    printf '%s\n' 'https://github.example/pull/9'
elif [ "$1 $2" = 'pr view' ]; then
    printf '{"url":"https://github.example/pull/9","headRefOid":"%s","number":9,"baseRefName":"main","state":"OPEN","isDraft":true}\n' "$MACO_ATTACK_OID"
else
    exit 64
fi
"#,
    )
    .context("write attacking gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat attacking gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod attacking gh")?;
    let path = path_with_prefix(&fake_bin)?;
    let attack_text = attack.to_string();

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
            "github",
            "--json",
        ])
        .env("PATH", path)
        .env("MACO_GH_STATE", &state)
        .env("MACO_ORIGIN", &origin_path)
        .env("MACO_ATTACK_OID", &attack_text)
        .output()
        .context("run publication with attacking gh shadow")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    assert!(!state.exists());
    assert!(!git_ref_exists(
        &origin_path,
        &format!("refs/heads/maco/review/agent-a/{reviewed}")
    )?);
    assert_eq!(
        git_rev_parse(&origin_path, "refs/heads/attack-source")?,
        attack.to_string()
    );
    Ok(())
}

#[test]
fn pr_publish_github_refuses_local_origin_before_untrusted_lost_response_shim() -> Result<()> {
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nreconcile pr\n")
        .context("edit candidate")?;
    let agent_repo = Repository::open(worktree_path).context("open agent repo")?;
    let reviewed = commit_all(&agent_repo, "reconcile candidate")?;

    let fake_bin = temp.path().join("bin");
    let pr_state = temp.path().join("reconcile-pr-state");
    let list_count = temp.path().join("reconcile-list-count");
    let create_count = temp.path().join("reconcile-create-count");
    fs::create_dir_all(&fake_bin).context("create fake bin")?;
    let gh_path = fake_bin.join("gh");
    fs::write(
        &gh_path,
        r#"#!/bin/sh
if [ "$1 $2" = 'pr list' ]; then
    count=0
    if [ -f "$MACO_LIST_COUNT" ]; then
        count=$(cat "$MACO_LIST_COUNT")
    fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$MACO_LIST_COUNT"
    if [ "$count" -eq 1 ]; then
        printf '[]\n'
    elif [ "$count" -eq 2 ]; then
        printf 'temporary list failure\n' >&2
        exit 70
    elif [ -f "$MACO_PR_STATE" ]; then
        printf '[{"url":"https://github.example/pull/11","headRefOid":"%s","number":11,"baseRefName":"main","state":"OPEN","isDraft":true}]\n' "$MACO_EXPECTED_OID"
    else
        printf '[]\n'
    fi
elif [ "$1 $2" = 'pr create' ]; then
    count=0
    if [ -f "$MACO_CREATE_COUNT" ]; then
        count=$(cat "$MACO_CREATE_COUNT")
    fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$MACO_CREATE_COUNT"
    printf created > "$MACO_PR_STATE"
    printf 'response lost after create\n' >&2
    exit 71
elif [ "$1 $2" = 'pr view' ]; then
    printf '{"url":"https://github.example/pull/11","headRefOid":"%s","number":11,"baseRefName":"main","state":"OPEN","isDraft":true}\n' "$MACO_EXPECTED_OID"
else
    exit 64
fi
"#,
    )
    .context("write reconciling gh")?;
    let mut permissions = fs::metadata(&gh_path)
        .context("stat reconciling gh")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh_path, permissions).context("chmod reconciling gh")?;
    let path = path_with_prefix(&fake_bin)?;
    let reviewed_text = reviewed.to_string();
    let args = [
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
    ];
    let output = Command::new(BIN)
        .args(args)
        .env("PATH", path)
        .env("MACO_PR_STATE", &pr_state)
        .env("MACO_LIST_COUNT", &list_count)
        .env("MACO_CREATE_COUNT", &create_count)
        .env("MACO_EXPECTED_OID", &reviewed_text)
        .output()
        .context("run publication with lost-response shim")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    assert!(!pr_state.exists());
    assert!(!list_count.exists());
    assert!(!create_count.exists());
    Ok(())
}

#[test]
fn pr_publish_git_refuses_local_origin_before_untrusted_path_shadow_can_push() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let origin_path = init_bare_origin(temp.path())?;
    let attack_path = temp.path().join("ambient-attack.git");
    Repository::init_bare(&attack_path).context("init ambient attack origin")?;
    let malicious_config = temp.path().join("ambient-gitconfig");
    let redirect_key = format!("url.{}.insteadOf", path_str(&attack_path)?);
    run_git(&[
        "config",
        "--file",
        path_str(&malicious_config)?,
        &redirect_key,
        path_str(&origin_path)?,
    ])?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "remote",
        "add",
        "origin",
        path_str(&origin_path)?,
    ])?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\npublish lock\n")
        .context("edit worktree")?;

    let fake_bin = temp.path().join("bin");
    let real_git = find_command("git")?;
    write_git_wrapper_that_waits_before_push(&fake_bin, &real_git)?;
    let path = path_with_prefix(&fake_bin)?;
    let push_ready = temp.path().join("push-ready");
    let push_release = temp.path().join("push-release");
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
            "git",
            "--json",
        ])
        .env("PATH", path)
        .env("MACO_PUSH_READY", &push_ready)
        .env("MACO_PUSH_RELEASE", &push_release)
        .env("GIT_CONFIG_GLOBAL", &malicious_config)
        .env("TMPDIR", &repo_path)
        .output()
        .context("run Git publication with local origin and untrusted path shadow")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local/file publication is disabled"));
    assert!(!push_ready.exists());
    assert!(!push_release.exists());
    let reviewed_head = Repository::open(worktree_path)
        .context("reopen agent repo")?
        .head()
        .context("read reviewed HEAD")?
        .target()
        .context("reviewed HEAD target")?
        .to_string();
    let remote_ref = format!("refs/heads/maco/review/agent-a/{reviewed_head}");
    assert!(!git_ref_exists(&origin_path, &remote_ref)?);
    assert!(!git_ref_exists(&attack_path, &remote_ref)?);
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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

#[cfg(target_os = "linux")]
#[test]
fn pr_publish_refuses_live_repo_common_publication_lock() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
        lock_record(
            std::process::id(),
            "merge-apply",
            process_start_ticks(std::process::id())?,
        ),
    )
    .context("write publication lock")?;
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_dir.join("repository-mutation.lock"))
        .context("open publication lock")?;
    lock_file
        .try_lock()
        .context("hold publication kernel lock")?;

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
    assert!(stderr.contains("kernel lock is held"));
    assert!(stderr.contains("by pid"));
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
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
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
fn pr_publish_from_branch_requires_and_accepts_bound_validation() -> Result<()> {
    support::require_containment!("pr_publish_from_branch_requires_and_accepts_bound_validation");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let base_branch = git_current_branch(&repo_path)?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", "-b", "task/docs"])?;
    fs::write(repo_path.join("README.md"), "# Smoke\n\nbranch publish\n")
        .context("edit task branch")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let task_head = commit_all(&repo, "task branch candidate").context("commit task branch")?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", &base_branch])?;

    let missing = run_failure_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/docs",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--require-validation",
        "--json",
    ])?;
    assert_eq!(missing["status"], "blocked");
    assert_contains(&missing["blockers"], "validation_missing")?;
    assert_eq!(missing["created"], false);

    let preview = run_success_json(&[
        "pr",
        "preview",
        "--from-branch",
        "task/docs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["branch"], "task/docs");
    assert_eq!(
        preview["preview"]["candidate"]["validation_binding"]["agent_head"],
        task_head.to_string()
    );
    let validation_path = temp.path().join("branch-validation.json");
    write_bound_validation(
        &validation_path,
        &preview["preview"]["candidate"]["validation_binding"],
    )?;

    let report = run_success_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/docs",
        "--repo",
        path_str(&repo_path)?,
        "--validation-report",
        path_str(&validation_path)?,
        "--require-validation",
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["validation_required"], true);
    assert_eq!(report["head_id"], task_head.to_string());
    assert_eq!(report["commit_id"], task_head.to_string());
    assert_eq!(report["changed_paths"][0], "README.md");
    assert_eq!(
        report["preview"]["safety"]["validation_evidence"]["binding_status"],
        "bound"
    );
    Ok(())
}

#[test]
fn pr_publish_squash_onto_builds_import_commit_on_disjoint_base() -> Result<()> {
    support::require_containment!("pr_publish_squash_onto_builds_import_commit_on_disjoint_base");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let base_branch = git_current_branch(&repo_path)?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", "-b", "task/squash"])?;
    fs::write(repo_path.join("README.md"), "# Smoke\n\nsquashed branch\n")
        .context("edit task branch")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let task_head = commit_all(&repo, "squashed task").context("commit task branch")?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", &base_branch])?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "checkout",
        "--orphan",
        "public-base",
    ])?;
    fs::write(repo_path.join("README.md"), "# Public snapshot\n").context("write public readme")?;
    let repo = Repository::open(&repo_path).context("reopen repo")?;
    let public_base = commit_all(&repo, "public base snapshot").context("commit public base")?;

    let preview = run_success_json(&[
        "pr",
        "preview",
        "--from-branch",
        "task/squash",
        "--squash-onto",
        "public-base",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;
    assert_eq!(preview["status"], "preview");
    let planned_import = Oid::from_str(preview["head_id"].as_str().context("preview head id")?)
        .context("parse planned import")?;
    assert!(repo.find_commit(planned_import).is_err());

    let report = run_success_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/squash",
        "--squash-onto",
        "public-base",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "published");
    assert_eq!(report["base"], "public-base");
    assert_ne!(report["head_id"], task_head.to_string());
    let import_head = Oid::from_str(report["head_id"].as_str().context("head id")?)
        .context("parse import head")?;
    assert_eq!(commit_parent(&repo_path, import_head)?, Some(public_base));
    assert_eq!(
        git_show_file(&repo_path, &format!("{import_head}:README.md"))?,
        "# Smoke\n\nsquashed branch\n"
    );
    Ok(())
}

#[test]
fn pr_publish_exclude_refuses_referenced_missing_path() -> Result<()> {
    support::require_containment!("pr_publish_exclude_refuses_referenced_missing_path");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let base_branch = git_current_branch(&repo_path)?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "checkout",
        "-b",
        "task/context",
    ])?;
    fs::create_dir_all(repo_path.join("agent-context")).context("create agent context")?;
    fs::write(
        repo_path.join("agent-context/context.json"),
        "{\"note\":true}\n",
    )
    .context("write context")?;
    fs::write(
        repo_path.join("Cargo.toml"),
        "[package]\nname = \"smoke\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[package.metadata]\nagent_context = \"agent-context/context.json\"\n",
    )
    .context("write cargo manifest reference")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "task context").context("commit task context")?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", &base_branch])?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/context",
        "--exclude",
        "agent-context",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["created"], false);
    assert_contains(&report["blockers"], "excluded_reference")?;
    assert!(report["next_action"]
        .as_str()
        .context("next action")?
        .contains("excluded path"));
    assert!(serde_json::to_string(&report)
        .context("serialize report")?
        .contains("agent-context"));
    Ok(())
}

#[test]
fn pr_publish_exclude_refuses_rust_path_attribute_reference() -> Result<()> {
    support::require_containment!("pr_publish_exclude_refuses_rust_path_attribute_reference");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let base_branch = git_current_branch(&repo_path)?;
    run_git(&[
        "-C",
        path_str(&repo_path)?,
        "checkout",
        "-b",
        "task/rust-exclude",
    ])?;
    fs::write(
        repo_path.join("src/secret.rs"),
        "pub fn hidden() -> bool { true }\n",
    )
    .context("write excluded rust module")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "#[path = \"secret.rs\"]\nmod generated;\n\npub fn ok() -> bool { generated::hidden() }\n",
    )
    .context("write rust path attribute reference")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "task rust excluded reference").context("commit rust excluded reference")?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", &base_branch])?;

    let report = run_failure_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/rust-exclude",
        "--exclude",
        "src/secret.rs",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_contains(&report["blockers"], "excluded_reference")?;
    assert!(serde_json::to_string(&report)
        .context("serialize report")?
        .contains("secret.rs"));
    Ok(())
}

#[test]
fn pr_publish_from_branch_blocks_dirty_primary_and_stale_base() -> Result<()> {
    support::require_containment!("pr_publish_from_branch_blocks_dirty_primary_and_stale_base");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let base_branch = git_current_branch(&repo_path)?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", "-b", "task/gates"])?;
    fs::write(repo_path.join("README.md"), "# Smoke\n\nbranch gate\n")
        .context("edit task branch")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "task gate branch").context("commit task gate branch")?;
    run_git(&["-C", path_str(&repo_path)?, "checkout", &base_branch])?;

    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { false }\n",
    )
    .context("dirty primary lib")?;
    let dirty = run_failure_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/gates",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;
    assert_eq!(dirty["status"], "blocked");
    assert_contains(&dirty["blockers"], "dirty_primary")?;

    let repo = Repository::open(&repo_path).context("reopen repo")?;
    commit_all(&repo, "advance base after task branch").context("advance base")?;
    let stale = run_failure_json(&[
        "pr",
        "publish",
        "--from-branch",
        "task/gates",
        "--repo",
        path_str(&repo_path)?,
        "--forge",
        "fake",
        "--json",
    ])?;
    assert_eq!(stale["status"], "blocked");
    assert_contains(&stale["blockers"], "stale_base")?;
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
fn issue_create_github_rejects_unbound_repo_before_untrusted_gh_shadow() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    let fake_bin = temp.path().join("bin");
    let gh_args_path = temp.path().join("gh-args.txt");
    let gh_env_path = temp.path().join("gh-env.txt");
    let gh_trace_path = temp.path().join("gh-trace.log");
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
printf 'GIT_TRACE=%s\n' "${GIT_TRACE-unset}" >> "$MACO_GH_ENV"
printf 'GIT_TRACE2_EVENT=%s\n' "${GIT_TRACE2_EVENT-unset}" >> "$MACO_GH_ENV"
printf 'GIT_REDIRECT_STDERR=%s\n' "${GIT_REDIRECT_STDERR-unset}" >> "$MACO_GH_ENV"
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

    let output = Command::new(BIN)
        .args([
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
        ])
        .env("PATH", path)
        .env("MACO_GH_ARGS", &gh_args_path)
        .env("MACO_GH_ENV", &gh_env_path)
        .env("GH_REPO", "attacker/wrong-repo")
        .env("GH_HOST", "attacker.invalid")
        .env("GIT_SSH_COMMAND", &gh_path)
        .env("GIT_TRACE", &gh_trace_path)
        .output()
        .context("run unbound issue creation")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to discover issue repository"));
    assert!(!gh_args_path.exists());
    assert!(!gh_env_path.exists());
    assert!(!gh_trace_path.exists());

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

fn assert_worktree_creation_unsupported(repo: &str) -> Result<bool> {
    let output = Command::new(BIN)
        .args(["worktree", "create", "agent-a", "--repo", repo, "--json"])
        .output()
        .context("run unsupported worktree create")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("managed worktree creation is unsupported")
            && stderr.contains("capability-bound"),
        "unexpected worktree-create refusal: {stderr}"
    );
    Ok(true)
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

fn create_unreferenced_readme_commit(
    repo: &Repository,
    parent_oid: Oid,
    readme: &str,
) -> Result<Oid> {
    let parent = repo.find_commit(parent_oid).context("find parent commit")?;
    let parent_tree = parent.tree().context("find parent tree")?;
    let mut builder = repo
        .treebuilder(Some(&parent_tree))
        .context("create tree builder")?;
    let blob = repo.blob(readme.as_bytes()).context("create README blob")?;
    builder
        .insert("README.md", blob, 0o100644)
        .context("insert README blob")?;
    let tree_id = builder.write().context("write attack tree")?;
    let tree = repo.find_tree(tree_id).context("find attack tree")?;
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
    repo.commit(
        None,
        &signature,
        &signature,
        "unreviewed remote commit",
        &tree,
        &[&parent],
    )
    .context("create unreferenced commit")
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

fn write_git_wrapper_that_mutates_after_real_add(
    path_dir: &Path,
    real_git: &Path,
    mutation_target: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(path_dir).context("create fake bin dir")?;
    let git_path = path_dir.join("git");
    fs::write(
        &git_path,
        format!(
            r#"#!/bin/sh
real_git={}
mutation_target={}
saw_add=false
for arg in "$@"; do
    if [ "$arg" = add ]; then
        saw_add=true
    fi
done
"$real_git" "$@"
status=$?
if [ "$status" -eq 0 ] && [ "$saw_add" = true ] && [ -z "${{GIT_OBJECT_DIRECTORY+x}}" ]; then
    printf '# Smoke\n\nlate mutation\n' > "$mutation_target"
fi
exit "$status"
"#,
            shell_quote_path(real_git),
            shell_quote_path(mutation_target),
        ),
    )
    .context("write mutating git wrapper")?;
    let mut permissions = fs::metadata(&git_path)
        .context("stat mutating git wrapper")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git_path, permissions).context("chmod mutating git wrapper")?;
    Ok(git_path)
}

fn write_git_wrapper_that_waits_before_push(path_dir: &Path, real_git: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path_dir).context("create fake bin dir")?;
    let git_path = path_dir.join("git");
    fs::write(
        &git_path,
        format!(
            r#"#!/bin/sh
real_git={}
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
exec "$real_git" "$@"
"#,
            shell_quote_path(real_git),
        ),
    )
    .context("write waiting git wrapper")?;
    let mut permissions = fs::metadata(&git_path)
        .context("stat waiting git wrapper")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git_path, permissions).context("chmod waiting git wrapper")?;
    Ok(git_path)
}

fn shell_quote_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
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

fn git_current_branch(repo_path: &Path) -> Result<String> {
    let repo = Repository::open(repo_path).context("open repo for branch name")?;
    let branch = repo
        .head()
        .context("read repo head")?
        .shorthand()
        .map(ToString::to_string)
        .context("current branch name was not UTF-8")?;
    Ok(branch)
}

fn commit_parent(repo_path: &Path, commit: Oid) -> Result<Option<Oid>> {
    let repo = Repository::open(repo_path).context("open repo for commit parent")?;
    let commit = repo.find_commit(commit).context("find commit")?;
    match commit.parent_count() {
        0 => Ok(None),
        1 => commit
            .parent_id(0)
            .map(Some)
            .context("read first commit parent"),
        count => anyhow::bail!("expected at most one parent, found {count}"),
    }
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
