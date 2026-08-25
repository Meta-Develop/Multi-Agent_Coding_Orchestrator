mod support;

use anyhow::{bail, Context, Result};
use multi_agent_coding_orchestrator::sync_store::SyncStore;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_maco");
const ALTERNATE_BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn supervise_plan_entrypoint_accepts_relative_linked_worktree() -> Result<()> {
    let fixture = RelativeWorktreeFixture::new()?;
    let plan_path = fixture
        .primary
        .parent()
        .context("relative-worktree fixture parent")?
        .join("supervisor-plan.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "validate relative linked worktree",
            "assignments": [{
                "id": "child-a",
                "phase": "execution",
                "assigned_paths": ["./src/lib.rs"],
                "worker_assignments": []
            }]
        }))?,
    )
    .context("write supervisor plan")?;

    let plan = run_maco_success_json(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert_eq!(plan["task"], "validate relative linked worktree");
    assert_eq!(
        plan["assignments"][0]["assigned_paths"],
        serde_json::json!(["src/lib.rs"]),
        "ordinary plan validation must run after the linked repository opens"
    );
    Ok(())
}

#[test]
fn direct_sync_store_open_accepts_relative_linked_worktree() -> Result<()> {
    let fixture = RelativeWorktreeFixture::new()?;

    let store = SyncStore::open(&fixture.linked)?;

    assert_eq!(store.snapshot()?, Vec::new());
    assert_eq!(
        store.state_path(),
        fixture.primary.join(".git/maco/state/claims.json")
    );
    Ok(())
}

#[test]
fn relative_worktrees_share_exact_claim_state_and_map_the_selected_worktree() -> Result<()> {
    support::require_containment!(
        "relative_worktrees_share_exact_claim_state_and_map_the_selected_worktree"
    );
    let fixture = RelativeWorktreeFixture::new()?;

    let primary_status = run_maco_success_json(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    let linked_status = run_binary_success_json(
        ALTERNATE_BIN,
        &[
            "sync",
            "status",
            "--repo",
            path_str(&fixture.linked)?,
            "--json",
        ],
    )?;
    assert_eq!(primary_status, serde_json::json!([]));
    assert_eq!(linked_status, primary_status);

    // The issue's literal release command has no active token to release. It
    // must reach claim-state logic and preserve that domain error rather than
    // failing earlier during repository discovery.
    let absent_release = run_maco(&[
        "sync",
        "release",
        "1",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    assert!(!absent_release.status.success());
    let absent_release_error = String::from_utf8_lossy(&absent_release.stderr);
    assert!(absent_release_error.contains("claim token is not active: 1"));
    assert!(!absent_release_error.contains("extensions.relativeworktrees"));

    let claim = run_maco_success_json(&[
        "sync",
        "claim",
        "linked-agent",
        "src/lib.rs",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert_eq!(claim["token"], 1);
    assert_eq!(claim["agent_id"], "linked-agent");
    assert_eq!(claim["paths"], serde_json::json!(["src/lib.rs"]));
    assert!(fixture.primary.join(".git/maco/state").is_dir());
    assert!(!fixture.primary.join(".git/worktrees/linked/maco").exists());
    assert!(!fixture.linked.join(".maco").exists());

    let expected_claims = serde_json::json!([{
        "token": 1,
        "agent_id": "linked-agent",
        "paths": ["src/lib.rs"]
    }]);
    let primary_claims = run_maco_success_json(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    let linked_claims = run_maco_success_json(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert_eq!(primary_claims, expected_claims);
    assert_eq!(linked_claims, expected_claims);

    let primary_map = run_maco_success_json(&[
        "repo",
        "map",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    let linked_map = run_maco_success_json(&[
        "repo",
        "map",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert_map_is_for_selected_worktree(
        &primary_map,
        &fixture.primary,
        "primary-only.txt",
        8,
        "linked-only.txt",
    )?;
    assert_map_is_for_selected_worktree(
        &linked_map,
        &fixture.linked,
        "linked-only.txt",
        7,
        "primary-only.txt",
    )?;

    let released = run_maco_success_json(&[
        "sync",
        "release",
        "1",
        "--repo",
        path_str(&fixture.primary)?,
        "--json",
    ])?;
    assert_eq!(released, expected_claims[0]);
    let linked_after_release = run_maco_success_json(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert_eq!(linked_after_release, serde_json::json!([]));

    Ok(())
}

#[test]
fn relative_worktree_support_does_not_accept_an_unrelated_extension() -> Result<()> {
    let fixture = RelativeWorktreeFixture::new()?;
    run_git(&[
        "-C",
        path_str(&fixture.primary)?,
        "config",
        "extensions.macoUnsupported",
        "true",
    ])?;

    let direct_error = SyncStore::open(&fixture.linked)
        .expect_err("direct library open must reject an unrelated repository extension");
    assert!(format!("{direct_error:#}")
        .contains("unsupported extension name extensions.macounsupported"));

    let output = run_maco(&[
        "sync",
        "status",
        "--repo",
        path_str(&fixture.linked)?,
        "--json",
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported extension name extensions.macounsupported"));
    assert!(!stderr.contains("unsupported extension name extensions.relativeworktrees"));

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
        assert_eq!(
            PathBuf::from(run_git_stdout(&[
                "-C",
                path_str(&primary)?,
                "rev-parse",
                "--show-toplevel",
            ])?),
            fs::canonicalize(&primary).context("canonicalize primary worktree")?
        );
        assert_eq!(
            PathBuf::from(run_git_stdout(&[
                "-C",
                path_str(&linked)?,
                "rev-parse",
                "--show-toplevel",
            ])?),
            fs::canonicalize(&linked).context("canonicalize linked worktree")?
        );

        let metadata_dir = primary.join(".git/worktrees/linked");
        let linked_git_file =
            fs::read_to_string(linked.join(".git")).context("read linked worktree .git file")?;
        let linked_git_dir = linked_git_file
            .trim()
            .strip_prefix("gitdir: ")
            .context("linked worktree .git file has gitdir prefix")?;
        assert!(Path::new(linked_git_dir).is_relative());
        assert_eq!(
            fs::canonicalize(linked.join(linked_git_dir))
                .context("resolve linked worktree gitdir")?,
            fs::canonicalize(&metadata_dir).context("canonicalize linked metadata directory")?
        );

        let metadata_gitdir = fs::read_to_string(metadata_dir.join("gitdir"))
            .context("read common worktree gitdir backlink")?;
        assert!(Path::new(metadata_gitdir.trim()).is_relative());
        assert_eq!(
            fs::canonicalize(metadata_dir.join(metadata_gitdir.trim()))
                .context("resolve common worktree gitdir backlink")?,
            fs::canonicalize(linked.join(".git")).context("canonicalize linked .git file")?
        );

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
    let tracked = entries
        .iter()
        .find(|entry| entry["path"] == "src/lib.rs")
        .context("tracked source missing from repository map")?;
    assert_eq!(tracked["kind"], "file");
    assert_eq!(tracked["git_status"], "clean");
    let sentinel = entries
        .iter()
        .find(|entry| entry["path"] == present_sentinel)
        .context("selected-worktree sentinel missing from repository map")?;
    assert_eq!(sentinel["git_status"], "untracked");
    assert_eq!(sentinel["size_bytes"], expected_sentinel_bytes);
    assert!(!entries.iter().any(|entry| entry["path"] == absent_sentinel));
    Ok(())
}

fn run_maco(args: &[&str]) -> Result<Output> {
    Command::new(BIN).args(args).output().context("run maco")
}

fn run_maco_success_json(args: &[&str]) -> Result<Value> {
    run_binary_success_json(BIN, args)
}

fn run_binary_success_json(binary: &str, args: &[&str]) -> Result<Value> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .context("run MACO binary")?;
    if !output.status.success() {
        bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse maco JSON")
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
