use anyhow::{Context, Result};
use git2::Repository;
use serde_json::Value;
use std::{fs, process::Command};
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
