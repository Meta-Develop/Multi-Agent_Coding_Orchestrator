mod support;

use anyhow::{Context, Result};
use git2::Repository;
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn repo_megafile_seed_is_explicit_language_agnostic_and_queryable() -> Result<()> {
    support::require_containment!("repo_megafile_seed_is_explicit_language_agnostic_and_queryable");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("assets")).context("create repository directories")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("README.md"), b"one\ntwo\n").context("write text")?;
    fs::write(repo_path.join("assets/blob.bin"), b"\0one\n\0two").context("write binary")?;
    let repo = path_str(&repo_path)?;

    let absent_query = run_success_json(&["repo", "megafile", "query", "--repo", repo, "--json"])?;
    assert_eq!(absent_query["initialized"], false);
    assert!(absent_query["telemetry"].is_null());
    assert!(
        !repo_path.join(".git/maco/state").exists(),
        "absent-state query must not initialize authentication or telemetry"
    );

    let map = run_success_json(&["repo", "map", "--repo", repo, "--json"])?;
    assert_eq!(map["entries"].as_array().context("map entries")?.len(), 3);
    assert!(
        !repo_path.join(".git/maco/state").exists(),
        "ordinary repo map must remain state-free"
    );

    let seed = run_success_json(&[
        "repo",
        "megafile",
        "seed",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert_eq!(seed["seeded_samples"], 2);
    assert_eq!(seed["sampled_bytes"], 17);
    assert_eq!(
        seed["assessments"]
            .as_array()
            .context("seed assessments")?
            .len(),
        2
    );
    assert!(seed["telemetry"].is_object());
    assert_eq!(seed["telemetry"]["thresholds"]["calibration"], "configured");
    assert_eq!(seed["telemetry"]["thresholds"]["file_bytes"], 1);
    assert_eq!(seed["assessments"][0]["is_megafile"], true);
    assert!(seed["assessments"][0]["signals"]
        .as_array()
        .context("signals")?
        .iter()
        .any(|signal| signal["kind"] == "file_bytes"));

    let seeded_next_sequence = seed["telemetry"]["next_record_sequence"].clone();
    let _map_after_seed = run_success_json(&["repo", "map", "--repo", repo, "--json"])?;
    let report = run_success_json(&["repo", "megafile", "query", "--repo", repo, "--json"])?;
    assert_eq!(report["initialized"], true);
    assert_eq!(
        report["telemetry"]["next_record_sequence"],
        seeded_next_sequence
    );
    let path = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "assets/blob.bin",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert_eq!(path["initialized"], true);
    assert_eq!(path["path"], "assets/blob.bin");
    assert_eq!(path["assessment"]["path"], "assets/blob.bin");
    assert_eq!(path["assessment"]["latest_sample"]["bytes"], 9);
    assert_eq!(path["assessment"]["latest_sample"]["lines"], 2);

    Ok(())
}

#[test]
fn sync_claim_json_surfaces_typed_telemetry_warnings() -> Result<()> {
    support::require_containment!("sync_claim_json_surfaces_typed_telemetry_warnings");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/lib.rs"), vec![b'x'; 524_288]).context("write source")?;
    let repo = path_str(&repo_path)?;

    let seed = run_success_json(&["repo", "megafile", "seed", "--repo", repo, "--json"])?;
    assert_eq!(seed["assessments"][0]["is_megafile"], true);

    let claim = run_success_json(&[
        "sync",
        "claim",
        "agent-a",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;

    assert_eq!(claim["token"], 1);
    assert_eq!(claim["agent_id"], "agent-a");
    assert_eq!(claim["paths"][0], "src/lib.rs");
    assert_eq!(claim["claim"]["agent_id"], "agent-a");
    assert_eq!(claim["claim"]["paths"][0], "src/lib.rs");
    let warnings = claim["warnings"].as_array().context("typed warnings")?;
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["version"], 1);
    assert_eq!(warnings[0]["path"], "src/lib.rs");
    assert_eq!(warnings[0]["assessment"]["is_megafile"], true);
    assert!(warnings[0]["assessment"]["signals"]
        .as_array()
        .context("warning signals")?
        .iter()
        .any(|signal| signal["kind"] == "file_bytes"));

    Ok(())
}

#[test]
fn sync_claim_threshold_overrides_are_applied_and_typed() -> Result<()> {
    support::require_containment!("sync_claim_threshold_overrides_are_applied_and_typed");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/lib.rs"), b"pub fn small() {}\n").context("write source")?;
    let repo = path_str(&repo_path)?;

    let seed = run_success_json(&["repo", "megafile", "seed", "--repo", repo, "--json"])?;
    assert_eq!(seed["assessments"][0]["is_megafile"], false);

    let claim = run_success_json(&[
        "sync",
        "claim",
        "configured-agent",
        "src/lib.rs",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;

    assert_eq!(claim["agent_id"], "configured-agent");
    assert_eq!(claim["claim"]["agent_id"], "configured-agent");
    let warnings = claim["warnings"].as_array().context("typed warnings")?;
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0]["assessment"]["signals"]
        .as_array()
        .context("warning signals")?
        .iter()
        .any(|signal| signal["kind"] == "file_bytes" && signal["threshold"] == 1));

    Ok(())
}

#[test]
fn sync_directory_claim_warns_for_seeded_files_in_deterministic_order() -> Result<()> {
    support::require_containment!(
        "sync_directory_claim_warns_for_seeded_files_in_deterministic_order"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src/empty")).context("create source directories")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/large.rs"), b"large\n").context("write large source")?;
    fs::write(repo_path.join("src/alpha.rs"), b"alpha\n").context("write alpha source")?;
    let repo = path_str(&repo_path)?;

    let seed = run_success_json(&[
        "repo",
        "megafile",
        "seed",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert!(seed["assessments"]
        .as_array()
        .context("seed assessments")?
        .iter()
        .any(|assessment| {
            assessment["path"] == "src/large.rs" && assessment["is_megafile"] == true
        }));

    let claim = run_success_json(&[
        "sync",
        "claim",
        "directory-agent",
        "src",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--claim-count",
        "1",
        "--json",
    ])?;
    assert_eq!(claim["claim"]["paths"][0], "src");
    let warnings = claim["warnings"].as_array().context("typed warnings")?;
    assert_eq!(warnings.len(), 2);
    assert_eq!(warnings[0]["path"], "src/alpha.rs");
    assert_eq!(warnings[1]["path"], "src/large.rs");
    assert_eq!(warnings[1]["assessment"]["claims_in_window"], 1);
    assert!(warnings[1]["assessment"]["signals"]
        .as_array()
        .context("large source warning signals")?
        .iter()
        .any(|signal| {
            signal["kind"] == "claim_count" && signal["observed"] == 1 && signal["threshold"] == 1
        }));

    let file = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "src/large.rs",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--claim-count",
        "1",
        "--json",
    ])?;
    assert_eq!(file["assessment"]["claims_in_window"], 1);
    let directory = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "src",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert!(
        directory["assessment"].is_null(),
        "a claimed directory must not become a source-file assessment"
    );

    run_success_json(&["sync", "release", "1", "--repo", repo, "--json"])?;
    let empty = run_success_json(&[
        "sync",
        "claim",
        "empty-directory-agent",
        "src/empty",
        "--repo",
        repo,
        "--claim-count",
        "1",
        "--json",
    ])?;
    assert!(empty["warnings"]
        .as_array()
        .context("empty directory warnings")?
        .is_empty());
    let empty_directory = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "src/empty",
        "--repo",
        repo,
        "--claim-count",
        "1",
        "--json",
    ])?;
    assert!(
        empty_directory["assessment"].is_null(),
        "an existing empty directory must not receive exact-file fallback"
    );

    Ok(())
}

#[test]
fn sync_directory_claim_frequency_crosses_threshold_across_releases() -> Result<()> {
    support::require_containment!(
        "sync_directory_claim_frequency_crosses_threshold_across_releases"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/large.rs"), b"small\n").context("write source")?;
    let repo = path_str(&repo_path)?;

    run_success_json(&["repo", "megafile", "seed", "--repo", repo, "--json"])?;
    let first = run_success_json(&[
        "sync",
        "claim",
        "first-agent",
        "src",
        "--repo",
        repo,
        "--claim-count",
        "2",
        "--json",
    ])?;
    assert!(first["warnings"]
        .as_array()
        .context("first warnings")?
        .is_empty());
    run_success_json(&["sync", "release", "1", "--repo", repo, "--json"])?;

    // Every CLI invocation reopens the authenticated claim and telemetry
    // stores, exercising accumulation across independent runs.
    let second = run_success_json(&[
        "sync",
        "claim",
        "second-agent",
        "src",
        "--repo",
        repo,
        "--claim-count",
        "2",
        "--json",
    ])?;
    let warnings = second["warnings"].as_array().context("second warnings")?;
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["path"], "src/large.rs");
    assert_eq!(warnings[0]["assessment"]["claims_in_window"], 2);
    assert!(warnings[0]["assessment"]["signals"]
        .as_array()
        .context("second warning signals")?
        .iter()
        .any(|signal| {
            signal["kind"] == "claim_count" && signal["observed"] == 2 && signal["threshold"] == 2
        }));

    let directory = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "src",
        "--repo",
        repo,
        "--claim-count",
        "2",
        "--json",
    ])?;
    assert!(directory["assessment"].is_null());

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
    serde_json::from_slice(&output.stdout).context("parse JSON")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("path is not UTF-8")
}
