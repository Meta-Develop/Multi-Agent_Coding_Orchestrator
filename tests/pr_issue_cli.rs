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
        ],
    )?;

    assert_eq!(report["forge"], "github");
    assert_eq!(report["created"], true);
    assert_eq!(report["url"], "https://github.example/issues/1");
    assert_eq!(report["redacted_body"], "API_TOKEN=<redacted:secret>");
    let gh_args = fs::read_to_string(&gh_args_path).context("read fake gh args")?;
    assert!(gh_args.contains("--body\nAPI_TOKEN=<redacted:secret>\n"));
    assert!(!gh_args.contains("API_TOKEN=secret"));

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
