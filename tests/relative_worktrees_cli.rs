use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn relative_worktree_cli_uses_the_selected_worktree() -> Result<()> {
    let fixture = RelativeWorktreeFixture::new()?;

    let primary_status = run_cli(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    let linked_status = run_cli(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    let primary_map = run_cli(&[
        "repo",
        "map",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    let linked_map = run_cli(&[
        "repo",
        "map",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;

    require_all_success(&[
        ("sync status (primary)", &primary_status),
        ("sync status (linked)", &linked_status),
        ("repo map (primary)", &primary_map),
        ("repo map (linked)", &linked_map),
    ])?;

    let primary_status = parse_json(&primary_status)?;
    let linked_status = parse_json(&linked_status)?;
    assert_eq!(primary_status, serde_json::json!([]));
    assert_eq!(linked_status, primary_status);

    assert_map_is_for_selected_worktree(
        &parse_json(&primary_map)?,
        &fixture.primary,
        "primary-only.txt",
        8,
        "linked-only.txt",
    )?;
    assert_map_is_for_selected_worktree(
        &parse_json(&linked_map)?,
        &fixture.linked,
        "linked-only.txt",
        7,
        "primary-only.txt",
    )?;

    run_git(&[
        "-C",
        path_str(&fixture.primary)?,
        "config",
        "extensions.macoUnsupported",
        "true",
    ])?;
    let unsupported = run_cli(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert!(!unsupported.status.success());
    let unsupported_stderr = String::from_utf8_lossy(&unsupported.stderr);
    assert!(unsupported_stderr.contains("unsupported extension name extensions.macounsupported"));
    assert!(!unsupported_stderr.contains("unsupported extension name extensions.relativeworktrees"));

    Ok(())
}

struct RelativeWorktreeFixture {
    _temp: TempDir,
    primary: PathBuf,
    linked: PathBuf,
}

impl RelativeWorktreeFixture {
    fn new() -> Result<Self> {
        let temp = TempDir::new().context("create relative-worktree fixture root")?;
        let primary = temp.path().join("repo");
        let linked = temp.path().join("linked");

        run_git(&["init", path_str(&primary)?])?;
        fs::create_dir_all(primary.join("src")).context("create fixture source directory")?;
        fs::write(primary.join("src/lib.rs"), "pub fn fixture() {}\n")
            .context("write tracked fixture source")?;
        run_git(&["-C", path_str(&primary)?, "add", "src/lib.rs"])?;
        run_git(&[
            "-C",
            path_str(&primary)?,
            "-c",
            "user.name=Example",
            "-c",
            "user.email=example@example.invalid",
            "commit",
            "-m",
            "init",
        ])?;
        run_git(&[
            "-C",
            path_str(&primary)?,
            "worktree",
            "add",
            "--relative-paths",
            "-b",
            "linked",
            path_str(&linked)?,
        ])?;

        assert_eq!(
            run_git_stdout(&[
                "-C",
                path_str(&primary)?,
                "config",
                "--get",
                "extensions.relativeWorktrees",
            ])?,
            "true"
        );

        let metadata_dir = primary.join(".git/worktrees/linked");
        let linked_git_file =
            fs::read_to_string(linked.join(".git")).context("read linked worktree .git file")?;
        let linked_gitdir = linked_git_file
            .trim()
            .strip_prefix("gitdir: ")
            .context("linked worktree .git file has gitdir prefix")?;
        assert!(Path::new(linked_gitdir).is_relative());
        assert_eq!(
            fs::canonicalize(linked.join(linked_gitdir))
                .context("resolve linked worktree gitdir")?,
            fs::canonicalize(&metadata_dir).context("canonicalize linked metadata directory")?
        );

        let metadata_gitdir = fs::read_to_string(metadata_dir.join("gitdir"))
            .context("read common worktree gitdir backlink")?;
        let metadata_gitdir = metadata_gitdir.trim();
        assert!(Path::new(metadata_gitdir).is_relative());
        assert_eq!(
            fs::canonicalize(metadata_dir.join(metadata_gitdir))
                .context("resolve common worktree gitdir backlink")?,
            fs::canonicalize(linked.join(".git")).context("canonicalize linked .git file")?
        );

        eprintln!("linked .git gitdir: {linked_gitdir}");
        eprintln!("common worktree gitdir: {metadata_gitdir}");

        fs::write(primary.join("primary-only.txt"), "primary\n")
            .context("write primary-only map sentinel")?;
        fs::write(linked.join("linked-only.txt"), "linked\n")
            .context("write linked-only map sentinel")?;

        Ok(Self {
            _temp: temp,
            primary,
            linked,
        })
    }
}

fn assert_map_is_for_selected_worktree(
    map: &Value,
    expected_root: &Path,
    present_sentinel: &str,
    expected_sentinel_bytes: u64,
    absent_sentinel: &str,
) -> Result<()> {
    let reported_root = map["root"]
        .as_str()
        .context("repository map root is not a string")?;
    assert_eq!(
        fs::canonicalize(reported_root).context("canonicalize reported map root")?,
        fs::canonicalize(expected_root).context("canonicalize expected map root")?
    );

    let entries = map["entries"]
        .as_array()
        .context("repository map entries")?;
    let sentinel = entries
        .iter()
        .find(|entry| entry["path"] == present_sentinel)
        .context("selected-worktree sentinel missing from repository map")?;
    assert_eq!(sentinel["kind"], "file");
    assert_eq!(sentinel["git_status"], "untracked");
    assert_eq!(sentinel["size_bytes"], expected_sentinel_bytes);
    assert!(!entries.iter().any(|entry| entry["path"] == absent_sentinel));

    Ok(())
}

fn require_all_success(commands: &[(&str, &Output)]) -> Result<()> {
    let failures = commands
        .iter()
        .filter(|(_, output)| !output.status.success())
        .map(|(label, output)| {
            format!(
                "{label}:\n{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        bail!(
            "relative worktree commands must succeed:\n{}",
            failures.join("\n")
        );
    }
    Ok(())
}

fn parse_json(output: &Output) -> Result<Value> {
    serde_json::from_slice(&output.stdout).context("parse MACO JSON")
}

fn run_cli(args: &[&str]) -> Result<Output> {
    Command::new(BIN)
        .env("RUST_BACKTRACE", "0")
        .args(args)
        .output()
        .context("run MACO")
}

fn run_git(args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).output().context("run git")?;
    if !output.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_git_stdout(args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).output().context("run git")?;
    if !output.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .context("git stdout is not UTF-8")
        .map(|stdout| stdout.trim().to_string())
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("path is not UTF-8")
}
