//! Producer-backed coverage for published non-merge JSON contracts.

use anyhow::{bail, Context, Result};
use boon::{Compiler, Draft, SchemaIndex, Schemas};
use git2::Repository;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

struct Draft202012Schema {
    schemas: Schemas,
    index: SchemaIndex,
    name: String,
}

impl Draft202012Schema {
    fn load(name: &str) -> Result<Self> {
        let path = repo_root().join("schemas").join(name);
        let schema: Value = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        )
        .with_context(|| format!("parse {}", path.display()))?;
        let schema_id = schema
            .get("$id")
            .and_then(Value::as_str)
            .with_context(|| format!("{name} must declare a string $id"))?;

        let mut compiler = Compiler::new();
        compiler.set_default_draft(Draft::V2020_12);
        compiler
            .add_resource(schema_id, schema.clone())
            .map_err(|error| anyhow::anyhow!("register {name}: {error:#}"))?;
        let mut schemas = Schemas::new();
        let index = compiler
            .compile(schema_id, &mut schemas)
            .map_err(|error| anyhow::anyhow!("meta-validate and compile {name}: {error:#}"))?;

        Ok(Self {
            schemas,
            index,
            name: name.to_owned(),
        })
    }

    fn assert_valid(&self, instance: &Value) -> Result<()> {
        if let Err(error) = self.schemas.validate(instance, self.index) {
            bail!("production output failed {}: {error:#}", self.name);
        }
        Ok(())
    }

    fn assert_rejected(&self, instance: &Value, drift: &str) -> Result<()> {
        if self.schemas.validate(instance, self.index).is_ok() {
            bail!("{} accepted deliberate drift: {drift}", self.name);
        }
        Ok(())
    }
}

#[test]
fn repository_map_cli_output_validates_and_required_entry_drift_fails() -> Result<()> {
    let temp = TempDir::new().context("create repository-map fixture root")?;
    let repository = temp.path().join("repository");
    fs::create_dir_all(repository.join("src")).context("create repository src")?;
    Repository::init(&repository).context("initialize repository")?;
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )
    .context("write repository source")?;

    let output = run_json(["repo", "map", "--repo", path_text(&repository)?, "--json"])?;
    assert!(
        output["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "repository-map producer returned no entries: {output}"
    );

    let schema = Draft202012Schema::load("repository-map-v1.schema.json")?;
    schema.assert_valid(&output)?;

    let mut drifted = output.clone();
    let entry = drifted["entries"]
        .as_array_mut()
        .context("repository-map entries")?
        .iter_mut()
        .find(|entry| entry["kind"] == "file")
        .context("repository-map file entry")?;
    entry
        .as_object_mut()
        .context("repository-map entry object")?
        .remove("category");
    schema.assert_rejected(&drifted, "file entry omitted category")
}

#[cfg(unix)]
#[test]
fn supervise_collect_cli_advertises_and_validates_its_interrupted_contract() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("create supervise collect fixture root")?;
    let repository = temp.path().join("repository");
    Repository::init(&repository).context("initialize supervise collect repository")?;
    let run_id = "schema-collect-interrupted";
    let run_dir = repository.join(".maco/o2/runs").join(run_id);
    fs::create_dir_all(&run_dir).context("create interrupted supervise run directory")?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
        .context("secure interrupted supervise run directory")?;

    let output = run_json_refusal_in(
        &repository,
        [
            "supervise",
            "collect",
            run_id,
            "--repo",
            path_text(&repository)?,
            "--json",
        ],
    )?;
    assert_eq!(output["artifact_kind"], "supervisor_collect_report");
    assert_eq!(output["collection_state"], "interrupted");
    assert_eq!(output["run_lifecycle"], "interrupted");
    assert_eq!(output["final_report_available"], false);

    let schema = Draft202012Schema::load("supervisor-collect-report-v1.schema.json")?;
    assert_eq!(output["schema"], load_fixture_schema_id(&schema.name)?);
    schema.assert_valid(&output)
}

#[test]
fn semantic_risk_cli_output_validates_spans_and_signature_drift_fails() -> Result<()> {
    let temp = TempDir::new().context("create semantic-risk fixture root")?;
    let repository = temp.path().join("repository");
    fs::create_dir_all(repository.join("src")).context("create repository src")?;
    Repository::init(&repository).context("initialize repository")?;
    fs::write(
        repository.join("src/lib.rs"),
        "pub mod api;\npub use crate::api::endpoint;\n",
    )
    .context("write semantic dependency source")?;
    fs::write(
        repository.join("src/api.rs"),
        "pub struct Api;\npub fn endpoint(\n    value: u32,\n) -> u32 {\n    value\n}\n",
    )
    .context("write touched semantic source")?;

    let output = run_json([
        "repo",
        "query",
        "risk",
        "--path",
        "src/api.rs",
        "--repo",
        path_text(&repository)?,
        "--json",
    ])?;
    let symbols = output["touched_symbols"]
        .as_array()
        .context("touched_symbols array")?;
    let impacts = output["dependency_impacts"]
        .as_array()
        .context("dependency_impacts array")?;
    assert!(
        !symbols.is_empty(),
        "producer omitted touched symbols: {output}"
    );
    assert!(
        !impacts.is_empty(),
        "producer omitted dependency impacts: {output}"
    );
    assert!(
        symbols.iter().all(|symbol| {
            symbol["span"]["start_line"].as_u64().is_some()
                && symbol["span"]["end_line"].as_u64().is_some()
                && symbol["span"]["signature_end_line"].as_u64().is_some()
        }),
        "touched symbol spans are incomplete: {symbols:?}"
    );
    assert!(
        impacts.iter().all(|impact| {
            let span = &impact["dependency"]["span"];
            span["start_line"].as_u64().is_some()
                && span["end_line"].as_u64().is_some()
                && span["signature_end_line"].as_u64().is_some()
        }),
        "dependency spans are incomplete: {impacts:?}"
    );

    let schema = Draft202012Schema::load("semantic-risk-report-v1.schema.json")?;
    schema.assert_valid(&output)?;

    let mut drifted = output.clone();
    drifted["touched_symbols"]
        .as_array_mut()
        .context("drifted touched_symbols array")?
        .first_mut()
        .context("drifted touched symbol")?["span"]
        .as_object_mut()
        .context("drifted touched symbol span")?
        .remove("signature_end_line");
    schema.assert_rejected(&drifted, "touched symbol span omitted signature_end_line")
}

#[test]
fn eval_harness_v1_cli_output_validates_and_provider_drift_fails() -> Result<()> {
    let working = TempDir::new().context("create eval-harness v1 working directory")?;
    let manifest = repo_root().join("tests/fixtures/eval_harness/manifest-v1.json");
    let output = run_json_in(
        working.path(),
        ["eval-harness", "run", path_text(&manifest)?, "--json"],
    )?;
    assert!(
        output["runs"]
            .as_array()
            .is_some_and(|runs| !runs.is_empty()),
        "eval-harness v1 producer returned no runs: {output}"
    );

    let schema = Draft202012Schema::load("eval-harness-result-v1.schema.json")?;
    schema.assert_valid(&output)?;

    let mut drifted = output.clone();
    drifted
        .as_object_mut()
        .context("eval-harness v1 output object")?
        .remove("provider");
    schema.assert_rejected(&drifted, "top-level provider omitted")
}

#[test]
fn comparable_fake_v3_cli_output_validates_and_nested_drift_fails() -> Result<()> {
    let working = TempDir::new().context("create eval-harness v2 working directory")?;
    let manifest = repo_root().join("tests/fixtures/eval_harness/manifest-v2.json");
    let output = run_json_in(
        working.path(),
        ["eval-harness", "run-v2", path_text(&manifest)?, "--json"],
    )?;
    assert_eq!(output["version"], 3);
    assert_eq!(output["schema"], "eval_harness_comparable_fake_results_v3");
    let runs = output["runs"].as_array().context("v3 runs array")?;
    assert!(!runs.is_empty(), "v3 producer returned no runs: {output}");
    assert!(
        runs.iter().all(|run| {
            run.get("provenance").is_some()
                && run.get("mix").is_some()
                && run.get("stages").is_some()
                && run.get("roles").is_some()
                && run.get("metrics").is_some()
                && run.get("integration_outcome").is_some()
                && run.get("record_fingerprint").is_some()
        }),
        "v3 producer returned an incomplete run envelope: {runs:?}"
    );

    let schema = Draft202012Schema::load("eval-harness-comparable-fake-results-v3.schema.json")?;
    schema.assert_valid(&output)?;
    assert_eq!(
        output,
        load_fixture("eval-harness-comparable-fake-results-v3.valid.json")?,
        "committed v3 fixture must be actual production output"
    );

    let mut drifted = output.clone();
    drifted
        .as_object_mut()
        .context("eval-harness v3 output object")?
        .remove("comparability");
    schema.assert_rejected(&drifted, "top-level comparability omitted")?;

    let mut drifted = output.clone();
    drifted["objective_profile"]["profile"]
        .as_object_mut()
        .context("objective profile binding")?
        .insert("undocumented".to_owned(), Value::Bool(true));
    schema.assert_rejected(&drifted, "objective profile gained an unknown member")?;

    let mut drifted = output.clone();
    drifted["runs"][0]["roles"][0]["usage"]
        .as_object_mut()
        .context("role usage")?
        .insert("undocumented".to_owned(), Value::from(1));
    schema.assert_rejected(&drifted, "nested run usage gained an unknown member")?;

    let mut drifted = output.clone();
    drifted["profile_summaries"][0]
        .as_object_mut()
        .context("profile summary")?
        .remove("mean_tokens");
    schema.assert_rejected(&drifted, "profile summary omitted mean_tokens")?;

    let mut drifted = output;
    let score = drifted["objective_selection"]["scores"]
        .as_object_mut()
        .context("objective selection scores")?
        .values_mut()
        .next()
        .context("objective selection score")?;
    *score = Value::String("not-a-number".to_owned());
    schema.assert_rejected(&drifted, "objective score was not numeric")
}

#[test]
fn eval_harness_fixture_pairs_validate_and_reject_declared_invalids() -> Result<()> {
    for (schema_name, valid_name, invalid_name) in [
        (
            "eval-harness-result-v1.schema.json",
            "eval-harness-result-v1.valid.json",
            "eval-harness-result-v1.invalid.json",
        ),
        (
            "eval-harness-comparable-fake-results-v2.schema.json",
            "eval-harness-comparable-fake-results-v2.valid.json",
            "eval-harness-comparable-fake-results-v2.invalid.json",
        ),
        (
            "eval-harness-comparable-fake-results-v3.schema.json",
            "eval-harness-comparable-fake-results-v3.valid.json",
            "eval-harness-comparable-fake-results-v3.invalid.json",
        ),
    ] {
        let schema = Draft202012Schema::load(schema_name)?;
        schema.assert_valid(&load_fixture(valid_name)?)?;
        schema.assert_rejected(&load_fixture(invalid_name)?, "declared invalid fixture")?;
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_fixture(name: &str) -> Result<Value> {
    let path = repo_root().join("fixtures/schemas").join(name);
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}

fn run_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    run_json_in(&repo_root(), args)
}

fn run_json_in<const N: usize>(working: &Path, args: [&str; N]) -> Result<Value> {
    let output = Command::new(BIN)
        .current_dir(working)
        .args(args)
        .output()
        .context("run production CLI")?;
    if !output.status.success() {
        bail!(
            "production CLI failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse production CLI JSON")
}

fn run_json_refusal_in<const N: usize>(working: &Path, args: [&str; N]) -> Result<Value> {
    let output = Command::new(BIN)
        .current_dir(working)
        .args(args)
        .output()
        .context("run refusing production CLI")?;
    if output.status.success() {
        bail!("production CLI unexpectedly accepted an incomplete supervise run");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse refusing production CLI JSON; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn load_fixture_schema_id(name: &str) -> Result<Value> {
    let schema = serde_json::from_slice::<Value>(
        &fs::read(repo_root().join("schemas").join(name))
            .with_context(|| format!("read schema {name}"))?,
    )
    .with_context(|| format!("parse schema {name}"))?;
    Ok(schema["$id"].clone())
}
