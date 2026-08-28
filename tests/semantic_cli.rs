mod support;

use anyhow::{Context, Result};
use git2::Repository;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn cli_semantic_risk_report_emits_touched_symbols_and_dependency_impact() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub mod api;\npub use crate::api::endpoint;\n",
    )
    .context("write lib")?;
    fs::write(
        repo_path.join("src/api.rs"),
        "pub struct Api;\npub fn endpoint() {}\n",
    )
    .context("write api")?;

    let report = run_success_json([
        "repo",
        "query",
        "risk",
        "--path",
        "src/api.rs",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["changed_paths"][0], "src/api.rs");
    assert_eq!(report["impacted_files"][0], "src/lib.rs");
    assert!(report["touched_symbols"]
        .as_array()
        .context("touched symbols array")?
        .iter()
        .any(|symbol| symbol["name"] == "Api"));
    assert!(report["touched_symbols"]
        .as_array()
        .context("touched symbols array")?
        .iter()
        .any(|symbol| symbol["name"] == "endpoint"));
    assert!(report["dependency_impacts"]
        .as_array()
        .context("dependency impacts array")?
        .iter()
        .any(|impact| {
            impact["direction"] == "incoming"
                && impact["related_file"] == "src/lib.rs"
                && impact["dependency"]["kind"] == "module_declaration"
        }));
    assert!(report["dependency_impacts"]
        .as_array()
        .context("dependency impacts array")?
        .iter()
        .any(|impact| {
            impact["direction"] == "incoming"
                && impact["dependency"]["kind"] == "import"
                && impact["dependency"]["to"] == "crate::api::endpoint"
        }));
    assert_eq!(report["megafile_hotspots"], serde_json::json!([]));
    assert!(
        !repo_path.join(".git/maco/state").exists(),
        "absent telemetry query must not create repository state"
    );

    Ok(())
}

#[test]
fn cli_semantic_risk_enriches_only_touched_threshold_crossing_paths() -> Result<()> {
    support::require_containment!(
        "cli_semantic_risk_enriches_only_touched_threshold_crossing_paths"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/touched.rs"), "pub fn touched() {}\n")
        .context("write touched source")?;
    fs::write(
        repo_path.join("src/also_touched.rs"),
        "pub fn also_touched() {}\n",
    )
    .context("write second touched source")?;
    fs::write(
        repo_path.join("src/unrelated.rs"),
        "pub fn unrelated() {}\n",
    )
    .context("write unrelated source")?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let seeded = run_success_json([
        "repo",
        "megafile",
        "seed",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert!(seeded["assessments"]
        .as_array()
        .context("seed assessments")?
        .iter()
        .any(|assessment| {
            assessment["path"] == "src/unrelated.rs" && assessment["is_megafile"] == true
        }));

    let report = run_success_json([
        "repo",
        "query",
        "risk",
        "--path",
        "src/touched.rs",
        "--path",
        "src/also_touched.rs",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;

    let hotspots = report["megafile_hotspots"]
        .as_array()
        .context("megafile hotspots")?;
    assert_eq!(hotspots.len(), 2);
    assert_eq!(hotspots[0]["path"], "src/also_touched.rs");
    assert_eq!(hotspots[1]["path"], "src/touched.rs");
    assert_eq!(hotspots[0]["is_megafile"], true);
    assert!(hotspots
        .iter()
        .all(|assessment| assessment["signals"]
            .as_array()
            .is_some_and(|signals| signals.iter().any(|signal| {
                signal["kind"] == "file_bytes"
                    && signal["observed"].as_u64().is_some_and(|value| value > 1)
                    && signal["threshold"] == 1
            }))));
    assert!(!hotspots
        .iter()
        .any(|assessment| assessment["path"] == "src/unrelated.rs"));

    Ok(())
}

#[test]
fn cli_semantic_risk_excludes_sampled_path_that_is_now_a_directory() -> Result<()> {
    support::require_containment!(
        "cli_semantic_risk_excludes_sampled_path_that_is_now_a_directory"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/churn.rs"), "pub fn former_file() {}\n")
        .context("write former source file")?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let seeded = run_success_json([
        "repo",
        "megafile",
        "seed",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert!(seeded["assessments"]
        .as_array()
        .context("seed assessments")?
        .iter()
        .any(|assessment| {
            assessment["path"] == "src/churn.rs" && assessment["is_megafile"] == true
        }));

    fs::remove_file(repo_path.join("src/churn.rs")).context("remove former source file")?;
    fs::create_dir(repo_path.join("src/churn.rs")).context("replace file with directory")?;

    let telemetry = run_success_json([
        "repo",
        "megafile",
        "query",
        "src/churn.rs",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert!(telemetry["assessment"].is_null());

    let risk = run_success_json([
        "repo",
        "query",
        "risk",
        "--path",
        "src/churn.rs",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert_eq!(risk["megafile_hotspots"], serde_json::json!([]));

    Ok(())
}

#[test]
fn cli_semantic_risk_propagates_authenticated_megafile_read_failures() -> Result<()> {
    support::require_containment!(
        "cli_semantic_risk_propagates_authenticated_megafile_read_failures"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/lib.rs"), "pub fn touched() {}\n").context("write source")?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    run_success_json(["repo", "megafile", "seed", "--repo", repo, "--json"])?;
    let history_root = repo_path.join(".git/maco/state/authenticated-megafile-history-v1");
    let snapshot =
        newest_numeric_json(&history_root)?.context("authenticated megafile snapshot")?;
    fs::write(snapshot, b"{\"tampered\":true}\n").context("tamper authenticated snapshot")?;

    let output = Command::new(BIN)
        .args([
            "repo",
            "query",
            "risk",
            "--path",
            "src/lib.rs",
            "--repo",
            repo,
            "--json",
        ])
        .output()
        .context("run semantic risk query")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authenticated megafile telemetry")
            || stderr.contains("authenticated snapshot"),
        "unexpected authentication failure: {stderr}"
    );

    Ok(())
}

#[test]
fn cli_semantic_coord_symbol_only_preview_reports_impacted_active_path() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub mod api;\npub mod client;\n",
    )
    .context("write lib")?;
    fs::write(repo_path.join("src/api.rs"), "pub fn endpoint() {}\n").context("write api")?;
    fs::write(
        repo_path.join("src/client.rs"),
        "use crate::api::endpoint;\npub fn call() { endpoint(); }\n",
    )
    .context("write client")?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let claim = run_success_json([
        "coord",
        "claim",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/client.rs",
        "--json",
    ])?;
    assert_eq!(claim["persisted"], true);

    let preview = run_success_json([
        "coord", "preview", "agent-b", "--repo", repo, "--symbol", "endpoint", "--json",
    ])?;

    assert_eq!(preview["persisted"], false);
    assert_eq!(preview["intent"]["impacted_files"][0], "src/client.rs");
    assert_eq!(
        preview["conflicts"][0]["kind"],
        "impacted_file_overlaps_active_path"
    );
    assert_eq!(preview["conflicts"][0]["severity"], "advisory");
    assert_eq!(preview["has_blocking_conflicts"], false);
    assert_eq!(preview["has_advisory_conflicts"], true);

    Ok(())
}

#[test]
fn cli_semantic_risk_maps_python_and_marks_unknown_language_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::create_dir_all(repo_path.join("pkg")).context("create pkg")?;
    fs::create_dir_all(repo_path.join("web")).context("create web")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(repo_path.join("src/lib.rs"), "pub fn rust_entry() {}\n").context("write rust")?;
    fs::write(repo_path.join("pkg/util.py"), "def util():\n    return 1\n")
        .context("write python")?;
    fs::write(
        repo_path.join("web/app.ts"),
        "export function hidden() { return 1; }\n",
    )
    .context("write typescript")?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let report = run_success_json([
        "repo",
        "query",
        "risk",
        "--path",
        "src/lib.rs",
        "--path",
        "pkg/util.py",
        "--path",
        "web/app.ts",
        "--repo",
        repo,
        "--json",
    ])?;

    assert!(report["touched_symbols"]
        .as_array()
        .context("touched symbols")?
        .iter()
        .any(|symbol| symbol["name"] == "rust_entry"));
    assert!(report["touched_symbols"]
        .as_array()
        .context("touched symbols")?
        .iter()
        .any(|symbol| symbol["name"] == "util"));
    assert!(report["touched_symbols"]
        .as_array()
        .context("touched symbols")?
        .iter()
        .all(|symbol| symbol["span"]["signature_end_line"].is_number()));
    assert!(report["errors"]
        .as_array()
        .context("errors")?
        .iter()
        .any(|error| { error["file"] == "web/app.ts" && error["kind"] == "unsupported" }));

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

fn newest_numeric_json(root: &Path) -> Result<Option<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut candidates = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("read state directory {}", directory.display()))?
        {
            let entry = entry.context("read state entry")?;
            let path = entry.path();
            let file_type = entry.file_type().context("read state entry type")?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("json")
                && path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .is_some_and(|stem| {
                        !stem.is_empty() && stem.bytes().all(|byte| byte.is_ascii_digit())
                    })
            {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    Ok(candidates.pop())
}
