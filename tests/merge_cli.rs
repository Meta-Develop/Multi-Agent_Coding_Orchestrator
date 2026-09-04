mod support;

use anyhow::{bail, Context, Result};
use boon::{Compiler, Draft, SchemaIndex, Schemas};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const PAUSED_CANDIDATE_VALIDATION_COMMAND: &str = "printf ready > validation-ready; while [ ! -f validation-release ]; do sleep 0.05; done; rm -f validation-ready validation-release";
const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Debug, PartialEq, Eq)]
struct PrimarySnapshot {
    primary_worktree: Vec<FileSystemSnapshotEntry>,
    primary_head: Vec<u8>,
    primary_index: Vec<u8>,
    primary_status: Vec<u8>,
    managed_registry_and_pending_operations: Vec<FileSystemSnapshotEntry>,
    managed_execution_leases: Vec<FileSystemSnapshotEntry>,
    candidate_worktree: Vec<FileSystemSnapshotEntry>,
    candidate_head: Vec<u8>,
    candidate_index: Vec<u8>,
    candidate_status: Vec<u8>,
    repository_mutation_lock: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
struct FileSystemSnapshotEntry {
    path: PathBuf,
    mode: u32,
    contents: FileSystemSnapshotContents,
}

#[derive(Debug, PartialEq, Eq)]
enum FileSystemSnapshotContents {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}

struct MergeV2Schemas {
    schemas: Schemas,
    preview: SchemaIndex,
    apply: SchemaIndex,
}

impl MergeV2Schemas {
    fn load() -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler.set_default_draft(Draft::V2020_12);
        let mut preview_id = None;
        let mut apply_id = None;

        for name in [
            "merge-preview-report-v1.schema.json",
            "merge-apply-report-v1.schema.json",
            "merge-preview-report-v2.schema.json",
            "merge-apply-report-v2.schema.json",
        ] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas")
                .join(name);
            let schema: Value = serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
            )
            .with_context(|| format!("parse {}", path.display()))?;
            if schema.get("$schema").and_then(Value::as_str) != Some(DRAFT_2020_12) {
                bail!("{name} does not declare JSON Schema Draft 2020-12");
            }
            let schema_id = schema
                .get("$id")
                .and_then(Value::as_str)
                .with_context(|| format!("{name} must declare a string $id"))?
                .to_owned();
            compiler
                .add_resource(&schema_id, schema)
                .map_err(|error| anyhow::anyhow!("register {name}: {error:#}"))?;
            match name {
                "merge-preview-report-v2.schema.json" => preview_id = Some(schema_id),
                "merge-apply-report-v2.schema.json" => apply_id = Some(schema_id),
                _ => {}
            }
        }

        let mut schemas = Schemas::new();
        let preview = compiler
            .compile(
                preview_id
                    .as_deref()
                    .context("missing merge preview v2 id")?,
                &mut schemas,
            )
            .map_err(|error| anyhow::anyhow!("compile merge preview v2 schema: {error:#}"))?;
        let apply = compiler
            .compile(
                apply_id.as_deref().context("missing merge apply v2 id")?,
                &mut schemas,
            )
            .map_err(|error| anyhow::anyhow!("compile merge apply v2 schema: {error:#}"))?;
        Ok(Self {
            schemas,
            preview,
            apply,
        })
    }

    fn assert_preview_valid(&self, instance: &Value) -> Result<()> {
        self.assert_valid(instance, self.preview, "merge preview v2")
    }

    fn assert_apply_valid(&self, instance: &Value) -> Result<()> {
        self.assert_valid(instance, self.apply, "merge apply v2")
    }

    fn assert_preview_rejected(&self, instance: &Value, drift: &str) -> Result<()> {
        if self.schemas.validate(instance, self.preview).is_ok() {
            bail!("merge preview v2 schema accepted deliberate live-output drift: {drift}");
        }
        Ok(())
    }

    fn assert_valid(&self, instance: &Value, index: SchemaIndex, label: &str) -> Result<()> {
        if let Err(error) = self.schemas.validate(instance, index) {
            bail!("live {label} output failed Draft 2020-12 validation: {error:#}");
        }
        Ok(())
    }
}

#[test]
fn merge_arbitrate_help_exposes_only_the_explicit_neutral_entrypoint() -> Result<()> {
    let output = Command::new(BIN)
        .args(["merge", "arbitrate", "--help"])
        .output()
        .context("run merge arbitrate help")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8(output.stdout).context("arbitrate help utf8")?;
    for expected in [
        "FIRST_SIDE",
        "SECOND_SIDE",
        "--arbiter-id",
        "--run-id",
        "--first-claim",
        "--second-claim",
        "--validation-command",
        "--approve",
        "--codex-bin",
        "--timeout-seconds",
        "--worktree-root",
    ] {
        assert!(help.contains(expected), "missing {expected} in:\n{help}");
    }
    assert!(help.contains("later ordinary merge apply is still required"));
    Ok(())
}

#[test]
fn merge_preview_and_apply_help_do_not_inherit_arbitration_options() -> Result<()> {
    for subcommand in ["preview", "apply"] {
        let output = Command::new(BIN)
            .args(["merge", subcommand, "--help"])
            .output()
            .with_context(|| format!("run merge {subcommand} help"))?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8(output.stdout).context("merge help utf8")?;
        for arbitration_only in [
            "--arbiter-id",
            "--run-id",
            "--first-claim",
            "--second-claim",
            "--approve",
            "--codex-bin",
            "--timeout-seconds",
            "--worktree-root",
            "--machine-global-config",
            "--machine-global-runtime-root-id",
        ] {
            assert!(
                !help.contains(arbitration_only),
                "merge {subcommand} unexpectedly exposes {arbitration_only}"
            );
        }
    }
    Ok(())
}

#[test]
fn merge_preview_v2_schema_validates_live_dependency_spans_and_rejects_drift() -> Result<()> {
    support::require_containment!(
        "merge_preview_v2_schema_validates_live_dependency_spans_and_rejects_drift"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub mod consumer;\npub mod shared;\n",
    )?;
    fs::write(
        repo_path.join("src/shared.rs"),
        "pub fn compute() -> i32 {\n    1\n}\n",
    )?;
    fs::write(
        repo_path.join("src/consumer.rs"),
        "use crate::shared::compute;\n\npub fn consume() -> i32 { compute() }\n",
    )?;
    let primary = Repository::open(&repo_path)?;
    commit_all(&primary, "add semantic dependency fixture")?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(
        worktree_path.join("src/shared.rs"),
        "pub fn compute() -> i32 {\n    2\n}\n",
    )?;
    fs::write(
        repo_path.join("src/shared.rs"),
        "pub fn compute() -> i32 {\n    3\n}\n",
    )?;
    commit_all(&primary, "change primary function")?;

    let preview = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/shared.rs",
        "--json",
    ])?;
    let dependency_impacts = preview["safety"]["semantic_conflicts"]["overlaps"][0]
        ["dependency_impacts"]
        .as_array()
        .context("live merge preview dependency impacts")?;
    assert!(
        !dependency_impacts.is_empty(),
        "live merge preview omitted dependency spans: {preview}"
    );
    assert!(dependency_impacts.iter().all(|impact| {
        impact["impact"]["dependency"]["span"]["signature_end_line"].is_number()
    }));

    let schemas = MergeV2Schemas::load()?;
    schemas.assert_preview_valid(&preview)?;
    let mut drifted = preview.clone();
    drifted["safety"]["semantic_conflicts"]["overlaps"][0]["dependency_impacts"][0]["impact"]
        ["dependency"]["span"]
        .as_object_mut()
        .context("live merge preview dependency span object")?
        .remove("signature_end_line");
    schemas.assert_preview_rejected(&drifted, "dependency span omitted signature_end_line")
}

#[test]
fn merge_arbitrate_refuses_primary_claim_before_repository_or_runner_access() -> Result<()> {
    let output = Command::new(BIN)
        .args([
            "merge",
            "arbitrate",
            "agent-a",
            "primary",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "primary-claim-refusal",
            "--second-claim",
            "src/lib.rs",
            "--validation-command",
            "cargo test",
            "--machine-global-config",
            "/definitely/not/a/config",
            "--machine-global-runtime-root-id",
            "runtime",
            "--repo",
            "/definitely/not/a/repository",
            "--json",
        ])
        .output()
        .context("run pre-repository arbitration refusal")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--second-claim is not applicable"));
    assert!(!stderr.contains("repository"));
    Ok(())
}

#[test]
fn merge_arbitrate_refuses_duplicate_sides_before_repository_or_runner_access() -> Result<()> {
    let output = Command::new(BIN)
        .args([
            "merge",
            "arbitrate",
            "agent-a",
            "agent-a",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "duplicate-side-refusal",
            "--validation-command",
            "cargo test",
            "--machine-global-config",
            "/definitely/not/a/config",
            "--machine-global-runtime-root-id",
            "runtime",
            "--repo",
            "/definitely/not/a/repository",
            "--json",
        ])
        .output()
        .context("run duplicate-side arbitration refusal")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("arbitration sides must be distinct"));
    assert!(!stderr.contains("failed to discover repository"));
    Ok(())
}

#[test]
fn merge_apply_without_reviewed_evidence_refuses_before_repository_mutation() -> Result<()> {
    support::require_containment!(
        "merge_apply_without_reviewed_evidence_refuses_before_repository_mutation"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# unreviewed\n").context("edit worktree")?;
    let before_apply = capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;

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
        .context("run unreviewed apply")?;
    assert!(!output.status.success());
    let refusal: Value = serde_json::from_slice(&output.stdout).context("parse refusal JSON")?;
    MergeV2Schemas::load()?.assert_apply_valid(&refusal)?;
    assert_eq!(refusal["version"], 2);
    assert_eq!(refusal["status"], "refused");
    assert_eq!(refusal["applied"], false);
    assert_eq!(refusal["review_bound"], false);
    assert_eq!(refusal["review_binding_status"], "missing");
    assert_eq!(refusal["refusal"]["kind"], "reviewed_preview_evidence");
    assert_eq!(refusal["refusal"]["axes"], serde_json::json!([]));
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_apply,
        "missing reviewed evidence mutated repository state"
    );
    Ok(())
}

#[test]
fn merge_apply_accepts_full_preview_and_nested_watermark_inputs() -> Result<()> {
    support::require_containment!("merge_apply_accepts_full_preview_and_nested_watermark_inputs");
    let schemas = MergeV2Schemas::load()?;
    for nested in [false, true] {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
        let expected_primary = format!("# reviewed {nested}\n");
        fs::write(worktree_path.join("README.md"), &expected_primary)?;
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
        schemas.assert_preview_valid(&preview)?;
        let evidence = if nested {
            serde_json::json!({"freshness_watermark": preview["freshness_watermark"].clone()})
        } else {
            preview
        };
        let evidence_path = write_json_value(temp.path(), "reviewed.json", &evidence)?;
        let report = run_success_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;
        schemas.assert_apply_valid(&report)?;
        assert_eq!(report["status"], "applied");
        assert_eq!(report["review_bound"], true);
        assert_eq!(report["review_binding_status"], "matched");
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))
                .context("read applied primary README")?,
            expected_primary,
            "{nested}-nested reviewed artifact did not apply its candidate contents"
        );
    }
    Ok(())
}

#[test]
fn merge_apply_review_binding_reports_source_and_target_drift_axes() -> Result<()> {
    support::require_containment!(
        "merge_apply_review_binding_reports_source_and_target_drift_axes"
    );
    let schemas = MergeV2Schemas::load()?;
    for (case, expected_status, expected_axis) in [
        ("source_dirty", "substituted", "candidate_diff"),
        ("source_head", "stale", "source_head"),
        ("target_head", "stale", "primary_head"),
        ("target_index", "stale", "primary_index"),
        ("target_worktree", "stale", "primary_worktree"),
    ] {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path =
            PathBuf::from(worktree["path"].as_str().context("worktree path string")?);
        fs::write(worktree_path.join("README.md"), "# candidate one\n")?;
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
        let evidence_path = write_json_value(temp.path(), "reviewed.json", &preview)?;

        match case {
            "source_dirty" => fs::write(worktree_path.join("README.md"), "# candidate two\n")?,
            "source_head" => {
                let source_repo = Repository::open(&worktree_path)?;
                commit_all(&source_repo, "advance source HEAD")?;
            }
            "target_head" => {
                fs::write(
                    repo_path.join("src/lib.rs"),
                    "pub fn ok() -> bool { false }\n",
                )?;
                let primary_repo = Repository::open(&repo_path)?;
                commit_all(&primary_repo, "advance primary HEAD")?;
            }
            "target_index" => run_git(&[
                "-C",
                repo,
                "update-index",
                "--assume-unchanged",
                "README.md",
            ])?,
            "target_worktree" => fs::write(repo_path.join("src/lib.rs"), "dirty target\n")?,
            _ => unreachable!(),
        }

        let before_apply =
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?;
        let refusal = run_failure_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;
        schemas.assert_apply_valid(&refusal)?;
        assert_eq!(refusal["version"], 2, "case {case}");
        assert_eq!(refusal["status"], "refused", "case {case}: {refusal}");
        assert_eq!(
            refusal["review_binding_status"], expected_status,
            "case {case}"
        );
        assert_contains(&refusal["refusal"]["axes"], expected_axis)?;
        let after_apply =
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?;
        assert_eq!(
            after_apply, before_apply,
            "case {case} mutated repository state"
        );
    }
    Ok(())
}

#[test]
fn merge_apply_refuses_independent_nested_watermark_identity_tampering() -> Result<()> {
    support::require_containment!(
        "merge_apply_refuses_independent_nested_watermark_identity_tampering"
    );
    let schemas = MergeV2Schemas::load()?;
    for (case, expected_axis) in [
        ("source_agent_id", "source_identity"),
        ("candidate_snapshot_tree", "candidate_snapshot"),
    ] {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path =
            PathBuf::from(worktree["path"].as_str().context("worktree path string")?);
        fs::write(worktree_path.join("README.md"), "# tamper candidate\n")?;
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
        schemas.assert_preview_valid(&preview)?;
        let mut watermark = preview["freshness_watermark"].clone();
        match case {
            "source_agent_id" => watermark["source"]["agent_id"] = serde_json::json!("agent-b"),
            "candidate_snapshot_tree" => {
                watermark["candidate"]["snapshot_tree"] =
                    serde_json::json!("1111111111111111111111111111111111111111")
            }
            _ => unreachable!(),
        }
        let evidence_path = write_json_value(
            temp.path(),
            &format!("{case}.json"),
            &serde_json::json!({"freshness_watermark": watermark}),
        )?;
        let before_apply =
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?;

        let refusal = run_failure_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;

        schemas.assert_apply_valid(&refusal)?;
        assert_eq!(refusal["version"], 2, "case {case}");
        assert_eq!(refusal["status"], "refused", "case {case}: {refusal}");
        assert_eq!(
            refusal["review_binding_status"], "substituted",
            "case {case}"
        );
        assert_eq!(
            refusal["refusal"]["axes"],
            serde_json::json!([expected_axis]),
            "case {case}"
        );
        assert_eq!(
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?,
            before_apply,
            "case {case} mutated repository state"
        );
    }
    Ok(())
}

#[test]
fn merge_apply_review_intent_binds_validation_and_lifecycle_options() -> Result<()> {
    support::require_containment!(
        "merge_apply_review_intent_binds_validation_and_lifecycle_options"
    );
    let schemas = MergeV2Schemas::load()?;

    {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path =
            PathBuf::from(worktree["path"].as_str().context("worktree path string")?);
        fs::write(worktree_path.join("README.md"), "# reviewed intent\n")?;
        let preview = run_success_json(&[
            "merge",
            "preview",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--validation-command",
            "test -f README.md",
            "--validation-command",
            "grep -q 'reviewed intent' README.md",
            "--require-validation",
            "--json",
        ])?;
        schemas.assert_preview_valid(&preview)?;
        assert_eq!(
            preview["review_intent"]["candidate_validation_commands"],
            serde_json::json!(["test -f README.md", "grep -q 'reviewed intent' README.md"])
        );
        assert_eq!(
            preview["review_intent"]["require_validation_after_candidate"],
            true
        );
        let evidence_path = write_json_value(temp.path(), "reviewed-intent.json", &preview)?;
        let report = run_success_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--validation-command",
            "test -f README.md",
            "--validation-command",
            "grep -q 'reviewed intent' README.md",
            "--require-validation",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;
        schemas.assert_apply_valid(&report)?;
        assert_eq!(report["status"], "applied");
        assert_eq!(report["review_binding_status"], "matched");
        assert_eq!(report["preview"]["review_intent"], preview["review_intent"]);
    }

    {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path =
            PathBuf::from(worktree["path"].as_str().context("worktree path string")?);
        fs::write(worktree_path.join("README.md"), "# intent mismatch\n")?;
        let preview = run_success_json(&[
            "merge",
            "preview",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--validation-command",
            "test -f README.md",
            "--validation-command",
            "test -f src/lib.rs",
            "--require-validation",
            "--json",
        ])?;
        schemas.assert_preview_valid(&preview)?;
        let evidence_path = write_json_value(temp.path(), "changed-intent.json", &preview)?;
        let before_apply =
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?;
        let refusal = run_failure_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--validation-command",
            "test -f README.md",
            "--validation-command",
            "test -s src/lib.rs",
            "--require-validation",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;
        schemas.assert_apply_valid(&refusal)?;
        assert_eq!(refusal["status"], "refused");
        assert_eq!(refusal["review_binding_status"], "substituted");
        assert_eq!(
            refusal["refusal"]["axes"],
            serde_json::json!(["base_preview"])
        );
        assert_eq!(
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?,
            before_apply,
            "changed validation command mutated repository state"
        );
    }

    {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let repo = repo_path.to_str().context("repo path utf8")?;
        let worktree =
            run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
        let worktree_path =
            PathBuf::from(worktree["path"].as_str().context("worktree path string")?);
        fs::write(worktree_path.join("README.md"), "# lifecycle intent\n")?;
        let preview = run_success_json(&[
            "merge",
            "preview",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--auto-reap-merged",
            "--trunk-ref",
            "main",
            "--apply-auto-reap",
            "--json",
        ])?;
        schemas.assert_preview_valid(&preview)?;
        assert_eq!(preview["review_intent"]["auto_reap_merged"], true);
        assert_eq!(preview["review_intent"]["trunk_ref"], "main");
        assert_eq!(preview["review_intent"]["apply_auto_reap"], true);
        let evidence_path = write_json_value(temp.path(), "reviewed-lifecycle.json", &preview)?;
        let before_apply =
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?;
        let refusal = run_failure_json(&[
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--reviewed-watermark",
            evidence_path.to_str().context("evidence path utf8")?,
            "--json",
        ])?;
        schemas.assert_apply_valid(&refusal)?;
        assert_eq!(refusal["status"], "refused");
        assert_eq!(refusal["review_binding_status"], "substituted");
        assert_eq!(
            refusal["refusal"]["axes"],
            serde_json::json!(["base_preview"])
        );
        assert_eq!(
            capture_primary_snapshot(&repo_path, &worktree_path, Path::new("README.md"))?,
            before_apply,
            "omitted lifecycle intent mutated or reaped reviewed state"
        );
        assert!(
            worktree_path.exists(),
            "omitted lifecycle intent reaped candidate lane"
        );
    }
    Ok(())
}

#[test]
fn merge_apply_refuses_preview_substitution_stale_reuse_and_bad_evidence() -> Result<()> {
    support::require_containment!(
        "merge_apply_refuses_preview_substitution_stale_reuse_and_bad_evidence"
    );
    let temp = TempDir::new().context("tempdir")?;
    let schemas = MergeV2Schemas::load()?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# exact candidate\n")?;
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
    schemas.assert_preview_valid(&preview)?;

    let mut substituted = preview.clone();
    substituted["safety"]["force_options"]["allow_dirty_primary"] = Value::Bool(true);
    let substituted_path = write_json_value(temp.path(), "substituted.json", &substituted)?;
    let before_substitution =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let refusal = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        substituted_path.to_str().context("path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&refusal)?;
    assert_eq!(refusal["review_binding_status"], "substituted");
    assert_eq!(
        refusal["refusal"]["axes"],
        serde_json::json!(["base_preview"])
    );
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_substitution,
        "substituted full preview mutated repository state"
    );

    let nested_path = write_json_value(
        temp.path(),
        "nested.json",
        &serde_json::json!({
            "freshness_watermark": preview["freshness_watermark"].clone()
        }),
    )?;
    let before_force_substitution =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let force_substitution = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--force-dirty-primary",
        "--reviewed-watermark",
        nested_path.to_str().context("nested path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&force_substitution)?;
    assert_eq!(force_substitution["review_binding_status"], "substituted");
    assert_contains(&force_substitution["refusal"]["axes"], "base_preview")?;
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_force_substitution,
        "force-option substitution mutated repository state"
    );

    let mut unsupported = preview["freshness_watermark"].clone();
    unsupported["version"] = serde_json::json!(1);
    let version_path = write_json_value(
        temp.path(),
        "version.json",
        &serde_json::json!({"freshness_watermark": unsupported}),
    )?;
    let before_unsupported =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let version_refusal = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        version_path.to_str().context("version path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&version_refusal)?;
    assert_eq!(
        version_refusal["review_binding_status"],
        "unsupported_version"
    );
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_unsupported,
        "unsupported watermark version mutated repository state"
    );

    let raw_top_level_path = write_json_value(
        temp.path(),
        "raw-top-level-watermark.json",
        &preview["freshness_watermark"],
    )?;
    let before_raw_top_level =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let raw_top_level_refusal = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        raw_top_level_path
            .to_str()
            .context("raw top-level path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&raw_top_level_refusal)?;
    assert_eq!(raw_top_level_refusal["review_binding_status"], "malformed");
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_raw_top_level,
        "raw top-level watermark mutated repository state"
    );

    let malformed_path = temp.path().join("malformed.json");
    fs::write(&malformed_path, b"{not-json")?;
    let before_malformed =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let malformed_refusal = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        malformed_path.to_str().context("malformed path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&malformed_refusal)?;
    assert_eq!(malformed_refusal["review_binding_status"], "malformed");
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_malformed,
        "malformed review evidence mutated repository state"
    );

    let exact_path = write_json_value(temp.path(), "exact.json", &preview)?;
    let applied = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        exact_path.to_str().context("exact path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&applied)?;
    assert_eq!(applied["status"], "applied");
    let before_stale_reuse =
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?;
    let stale = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--reviewed-watermark",
        exact_path.to_str().context("exact path utf8")?,
        "--json",
    ])?;
    schemas.assert_apply_valid(&stale)?;
    assert_eq!(stale["review_binding_status"], "stale");
    assert_contains(&stale["refusal"]["axes"], "primary_worktree")?;
    assert_eq!(
        capture_primary_snapshot(&repo_path, worktree_path, Path::new("README.md"))?,
        before_stale_reuse,
        "stale reviewed preview reuse mutated repository state"
    );
    Ok(())
}

#[test]
fn merge_apply_nothing_and_blocked_reports_remain_ordinary_matched_shapes() -> Result<()> {
    support::require_containment!(
        "merge_apply_nothing_and_blocked_reports_remain_ordinary_matched_shapes"
    );
    let schemas = MergeV2Schemas::load()?;
    let empty = TempDir::new().context("empty tempdir")?;
    let empty_repo_path = create_committed_repo(empty.path())?;
    let empty_repo = empty_repo_path.to_str().context("empty repo utf8")?;
    run_success_json(&[
        "worktree", "create", "agent-a", "--repo", empty_repo, "--json",
    ])?;
    let nothing = run_success_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        empty_repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    schemas.assert_apply_valid(&nothing)?;
    assert_eq!(nothing["status"], "nothing_to_apply");
    assert_eq!(nothing["review_bound"], true);
    assert_eq!(nothing["review_binding_status"], "matched");
    assert!(nothing.get("refusal").is_none());

    let blocked = TempDir::new().context("blocked tempdir")?;
    let blocked_repo_path = create_committed_repo(blocked.path())?;
    let blocked_repo = blocked_repo_path.to_str().context("blocked repo utf8")?;
    let worktree = run_success_json(&[
        "worktree",
        "create",
        "agent-a",
        "--repo",
        blocked_repo,
        "--json",
    ])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path")?);
    fs::write(worktree_path.join("README.md"), "# candidate\n")?;
    fs::write(blocked_repo_path.join("src/lib.rs"), "dirty primary\n")?;
    let blocked_report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        blocked_repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    schemas.assert_apply_valid(&blocked_report)?;
    assert_eq!(blocked_report["status"], "blocked");
    assert_eq!(blocked_report["review_bound"], true);
    assert_eq!(blocked_report["review_binding_status"], "matched");
    assert!(blocked_report.get("refusal").is_none());
    Ok(())
}

#[test]
fn merge_apply_accepts_external_validation_report_and_applies() -> Result<()> {
    support::require_containment!("merge_apply_accepts_external_validation_report_and_applies");
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
    assert_eq!(report["review_bound"], true);
    assert_eq!(report["review_binding_status"], "matched");
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
    support::require_containment!(
        "merge_apply_required_validation_accepts_exact_candidate_binding"
    );
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
    support::require_containment!("merge_preview_required_validation_rejects_legacy_unbound_pass");
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
    support::require_containment!(
        "merge_apply_rejects_stale_binding_after_agent_candidate_changes"
    );
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
    support::require_containment!(
        "merge_apply_revalidates_clean_committed_primary_after_candidate_validation"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\ncandidate\n")
        .context("edit worktree")?;
    let runtime_root = candidate_validation_runtime_root()?;
    let existing_runtime_entries = candidate_validation_runtime_entries(&runtime_root)?;
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        PAUSED_CANDIDATE_VALIDATION_COMMAND,
        "--force-stale-base",
        "--json",
    ])?;
    let mut apply = Command::new(BIN)
        .args(apply_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start merge apply")?;
    let validation_sandbox =
        wait_for_candidate_validation_ready(&mut apply, &runtime_root, &existing_runtime_entries)?;

    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { false }\n",
    )
    .context("edit primary during candidate validation")?;
    let primary = Repository::open(&repo_path).context("open primary repo")?;
    commit_all(&primary, "concurrent primary")?;
    fs::write(validation_sandbox.join("validation-release"), "release\n")
        .context("release validation")?;
    let applied = apply.wait_with_output().context("wait for merge apply")?;

    assert!(!applied.status.success());
    let report: Value = serde_json::from_slice(&applied.stdout).context("parse apply report")?;

    assert_eq!(report["status"], "refused");
    assert_eq!(report["review_bound"], false);
    assert_eq!(report["review_binding_status"], "stale");
    assert_contains(&report["refusal"]["axes"], "primary_head")?;
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn merge_apply_refuses_when_repo_common_lock_is_held() -> Result<()> {
    support::require_containment!("merge_apply_refuses_when_repo_common_lock_is_held");
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlocked\n").context("edit worktree")?;
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
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
        .args(apply_args)
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
    support::require_containment!("pr_publish_cannot_run_while_merge_apply_validates_candidate");
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
    let runtime_root = candidate_validation_runtime_root()?;
    let existing_runtime_entries = candidate_validation_runtime_entries(&runtime_root)?;

    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        PAUSED_CANDIDATE_VALIDATION_COMMAND,
        "--json",
    ])?;
    let mut apply = Command::new(BIN)
        .args(apply_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start merge apply")?;
    let validation_sandbox =
        wait_for_candidate_validation_ready(&mut apply, &runtime_root, &existing_runtime_entries)?;

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
    fs::write(validation_sandbox.join("validation-release"), "release\n")
        .context("release validation")?;
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
    support::require_containment!("merge_apply_refuses_malformed_repo_common_lock");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nlocked\n").context("edit worktree")?;
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
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
        .args(apply_args)
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
    support::require_containment!("merge_apply_refuses_symlink_repository_lock_file");
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nsymlink lock\n")
        .context("edit worktree")?;
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let lock_dir = repo_path.join(".git/maco/state");
    fs::create_dir_all(&lock_dir).context("create lock dir")?;
    let target = temp.path().join("lock-target");
    fs::write(&target, "do not touch\n").context("write lock target")?;
    symlink(&target, lock_dir.join("repository-mutation.lock")).context("create lock symlink")?;

    let output = Command::new(BIN)
        .args(apply_args)
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
    support::require_containment!("merge_apply_refuses_symlink_repository_state_directory");
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
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
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
        .args(apply_args)
        .output()
        .context("run merge with symlink state")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing symbolic links"));
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    Ok(())
}

#[test]
fn merge_apply_overwrites_unlocked_stale_owner_record() -> Result<()> {
    support::require_containment!("merge_apply_overwrites_unlocked_stale_owner_record");
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
    support::require_containment!("merge_apply_json_reports_dirty_primary_blocker");
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
    support::require_containment!("merge_preview_reports_stale_base_and_apply_conflict_paths");
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
    support::require_containment!("merge_preview_reports_unclaimed_edits_with_paths");
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
    support::require_containment!("merge_preview_reports_committed_worktree_change");
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
    support::require_containment!(
        "merge_validation_failure_blocks_and_force_only_forces_validation"
    );
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
    support::require_containment!(
        "merge_preview_required_validation_blocks_missing_not_run_and_skipped_evidence"
    );
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
    support::require_containment!(
        "merge_apply_candidate_validation_failure_blocks_before_primary_apply"
    );
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
    support::require_containment!(
        "merge_apply_rejects_successful_validation_that_mutates_candidate_sandbox"
    );
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
    support::require_containment!(
        "merge_apply_kills_setsid_validation_descendant_before_accepting_success"
    );
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
fn merge_apply_rejects_successful_validation_that_mutates_uninitialized_gitlink() -> Result<()> {
    support::require_containment!(
        "merge_apply_rejects_successful_validation_that_mutates_uninitialized_gitlink"
    );
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
    let created_file =
        "mkdir -p modules/dependency && printf 'mutated\\n' > modules/dependency/tracked.txt";
    let created_nested_file = "mkdir -p modules/dependency/nested && printf 'mutated\\n' > modules/dependency/nested/untracked.txt";

    let report = run_failure_json(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-command",
        created_file,
        "--validation-command",
        created_nested_file,
        "--json",
    ])?;

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["applied"], false);
    let validations = report["preview"]["candidate"]["validations"]
        .as_array()
        .context("validation reports")?;
    assert_eq!(validations.len(), 2);
    for validation in validations {
        assert_eq!(validation["status"], "failed");
        assert_eq!(
            validation["message"].as_str().context("validation message")?,
            "validation command mutated tracked or non-ignored candidate state; its result was rejected"
        );
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
    support::require_containment!(
        "merge_preview_preserves_non_utf8_claimed_path_and_emits_ascii_json"
    );
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
    support::require_containment!(
        "merge_preview_ignores_ambient_git_repository_and_index_overrides"
    );
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
    support::require_containment!(
        "merge_preview_candidate_capture_does_not_write_unreachable_real_objects"
    );
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

#[test]
fn megafile_merge_defaults_to_typed_warn_only_and_opt_in_blocking() -> Result<()> {
    support::require_containment!("megafile_merge_defaults_to_typed_warn_only_and_opt_in_blocking");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    run_success_json(&[
        "repo",
        "megafile",
        "seed",
        "--repo",
        repo,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nsplit me\n").context("edit worktree")?;
    let validation_path = temp.path().join("validation.json");
    fs::write(
        &validation_path,
        r#"[{"name":"megafile-unit","status":"passed","paths":["README.md"]}]"#,
    )
    .context("write validation report")?;

    let warning = run_success_json(&[
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--validation-report",
        validation_path.to_str().context("validation path utf8")?,
        "--file-bytes",
        "1",
        "--json",
    ])?;
    assert_eq!(warning["safety"]["readiness"]["status"], "safe");
    assert_eq!(warning["safety"]["megafile_blocking"], false);
    assert_eq!(warning["safety"]["megafile"]["status"], "passed");
    assert_eq!(
        warning["safety"]["megafile_warnings"][0]["path"],
        "README.md"
    );
    assert!(warning["safety"]["megafile"]["message"]
        .as_str()
        .context("warn-only message")?
        .contains("warn-only"));

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
        "--file-bytes",
        "1",
        "--block-megafiles",
        "--json",
    ])?;
    assert_eq!(blocked["safety"]["readiness"]["status"], "blocked");
    assert_contains(
        &blocked["safety"]["readiness"]["blockers"],
        "excluded_reference",
    )?;
    let detail = blocked["safety"]["readiness"]["details"]
        .as_array()
        .context("blocker details")?
        .iter()
        .find(|detail| detail["kind"] == "excluded_reference")
        .context("megafile policy detail")?;
    assert_eq!(detail["check_status"], "failed");
    assert_eq!(detail["paths"], serde_json::json!(["README.md"]));
    assert!(detail["message"]
        .as_str()
        .context("megafile blocker message")?
        .contains("threshold-crossing megafiles"));
    assert_eq!(detail["validation_reports"][0]["name"], "megafile-unit");
    assert_eq!(detail["validation_commands"], serde_json::json!([]));
    assert!(detail["next_safe_operation"]
        .as_str()
        .context("megafile next safe operation")?
        .contains("megafile_decomposition assignment"));
    Ok(())
}

#[test]
fn merge_apply_records_collision_history_at_the_blocked_decision() -> Result<()> {
    support::require_containment!("merge_apply_records_collision_history_at_the_blocked_decision");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# agent version\n")
        .context("edit agent worktree")?;
    fs::write(repo_path.join("README.md"), "# primary version\n").context("edit primary")?;

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
    assert_eq!(
        report["recorded_collision_paths"],
        serde_json::json!(["README.md"])
    );

    let telemetry = run_success_json(&[
        "repo",
        "megafile",
        "query",
        "README.md",
        "--repo",
        repo,
        "--collision-count",
        "1",
        "--json",
    ])?;
    assert_eq!(telemetry["initialized"], true);
    assert_eq!(telemetry["assessment"]["collisions_in_window"], 1);
    assert!(telemetry["assessment"]["signals"]
        .as_array()
        .context("collision signals")?
        .iter()
        .any(|signal| signal["kind"] == "collision_count"));
    Ok(())
}

#[test]
fn decomposition_cli_rejects_bare_target_and_unpaired_run_before_worktree_lookup() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let bare = Command::new(BIN)
        .args([
            "merge",
            "apply",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--block-megafiles",
            "--decomposition-target",
            "README.md",
            "--json",
        ])
        .output()
        .context("run bare decomposition target")?;
    assert!(!bare.status.success());
    assert!(
        String::from_utf8_lossy(&bare.stderr)
            .contains("--decomposition-target requires --decomposition-run-id"),
        "unexpected bare-target failure: {}",
        String::from_utf8_lossy(&bare.stderr)
    );

    let unpaired_run = Command::new(BIN)
        .args([
            "merge",
            "preview",
            "agent-a",
            "--repo",
            repo,
            "--claim",
            "README.md",
            "--decomposition-run-id",
            "finalized-run",
            "--json",
        ])
        .output()
        .context("run unpaired decomposition run id")?;
    assert!(!unpaired_run.status.success());
    assert!(
        String::from_utf8_lossy(&unpaired_run.stderr)
            .contains("--decomposition-run-id requires --decomposition-target"),
        "unexpected unpaired-run failure: {}",
        String::from_utf8_lossy(&unpaired_run.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read unchanged primary")?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn authenticated_megafile_read_failure_refuses_merge_before_primary_apply() -> Result<()> {
    support::require_containment!(
        "authenticated_megafile_read_failure_refuses_merge_before_primary_apply"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(&["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    run_success_json(&["repo", "megafile", "seed", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# candidate\n").context("edit candidate")?;
    let (apply_args, _review_directory) = bind_reviewed_preview_if_needed(&[
        "merge",
        "apply",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "README.md",
        "--json",
    ])?;
    let history_root = repo_path.join(".git/maco/state/authenticated-megafile-history-v1");
    let snapshot = newest_numeric_json(&history_root)?.context("authenticated snapshot")?;
    fs::write(&snapshot, b"{\"tampered\":true}\n").context("tamper authenticated snapshot")?;

    let output = Command::new(BIN)
        .args(apply_args)
        .output()
        .context("run merge against tampered telemetry")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authenticated megafile telemetry")
            || stderr.contains("authenticated snapshot"),
        "unexpected failure: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary")?,
        "# Smoke\n"
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

fn candidate_validation_runtime_root() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let uid = fs::metadata("/proc/self")?.uid();
        let user_runtime = PathBuf::from(format!("/run/user/{uid}"));
        let metadata = fs::symlink_metadata(&user_runtime)
            .with_context(|| format!("inspect trusted runtime {}", user_runtime.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!(
                "trusted per-user runtime {} is not an owner-only real directory",
                user_runtime.display()
            );
        }
        Ok(user_runtime.join(format!("maco-runtime-{uid}")))
    }

    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("candidate validation containment requires Linux")
}

fn candidate_validation_runtime_entries(runtime_root: &Path) -> Result<BTreeSet<OsString>> {
    let metadata = match fs::symlink_metadata(runtime_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect candidate validation runtime root {}",
                    runtime_root.display()
                )
            })
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "candidate validation runtime root {} is not a real directory",
            runtime_root.display()
        );
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let uid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "candidate validation runtime root {} is not owner-only",
                runtime_root.display()
            );
        }
    }
    let entries = fs::read_dir(runtime_root).with_context(|| {
        format!(
            "read candidate validation runtime root {}",
            runtime_root.display()
        )
    })?;
    entries
        .map(|entry| {
            Ok(entry
                .context("read candidate validation runtime entry")?
                .file_name())
        })
        .collect()
}

fn wait_for_candidate_validation_ready(
    apply: &mut Child,
    runtime_root: &Path,
    existing_runtime_entries: &BTreeSet<OsString>,
) -> Result<PathBuf> {
    let result = (|| {
        let prefix = format!("maco-candidate-validation-{}-", apply.id());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let mut matches = Vec::new();
            for name in candidate_validation_runtime_entries(runtime_root)? {
                if existing_runtime_entries.contains(&name)
                    || !name.to_str().is_some_and(|name| name.starts_with(&prefix))
                {
                    continue;
                }
                let path = runtime_root.join(&name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_dir() => matches.push(path),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("inspect candidate validation sandbox {}", path.display())
                        })
                    }
                }
            }
            if matches.len() > 1 {
                anyhow::bail!(
                    "found multiple fresh candidate validation sandboxes for apply pid {}",
                    apply.id()
                );
            }
            if let Some(sandbox) = matches.pop() {
                if fs::symlink_metadata(sandbox.join("validation-ready"))
                    .is_ok_and(|metadata| metadata.file_type().is_file())
                {
                    return Ok(sandbox);
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "candidate validation sandbox for apply pid {} did not become ready before timeout",
                    apply.id()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        let _ = apply.kill();
        let _ = apply.wait();
    }
    result
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let (args, _review_directory) = bind_reviewed_preview_if_needed(args)?;
    let output = Command::new(BIN).args(&args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let (args, _review_directory) = bind_reviewed_preview_if_needed(args)?;
    let output = Command::new(BIN).args(&args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).context("parse failure json")
}

fn write_json_value(root: &Path, name: &str, value: &Value) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(
        &path,
        serde_json::to_vec_pretty(value).context("serialize JSON value")?,
    )
    .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Test-only synthetic review authority for legacy apply-focused fixtures.
///
/// Production callers must obtain and review their own preview. This helper
/// forwards every apply option shared by preview and adds only the resulting
/// reviewed watermark to the apply invocation.
fn bind_reviewed_preview_if_needed(args: &[&str]) -> Result<(Vec<OsString>, Option<TempDir>)> {
    let is_merge_apply = args.first() == Some(&"merge") && args.get(1) == Some(&"apply");
    if !is_merge_apply || args.contains(&"--reviewed-watermark") {
        return Ok((args.iter().map(OsString::from).collect(), None));
    }

    let mut preview_args = vec![OsString::from("merge"), OsString::from("preview")];
    preview_args.extend(args.iter().skip(2).map(OsString::from));

    let preview_output = Command::new(BIN)
        .args(&preview_args)
        .output()
        .context("run mandatory reviewed merge preview")?;
    if !preview_output.status.success() {
        anyhow::bail!(
            "mandatory reviewed merge preview failed: {}",
            String::from_utf8_lossy(&preview_output.stderr)
        );
    }
    let directory = TempDir::new().context("reviewed preview tempdir")?;
    let path = directory.path().join("reviewed-preview.json");
    fs::write(&path, preview_output.stdout).context("write reviewed preview JSON")?;
    let mut apply_args = args.iter().map(OsString::from).collect::<Vec<_>>();
    apply_args.push(OsString::from("--reviewed-watermark"));
    apply_args.push(path.into_os_string());
    Ok((apply_args, Some(directory)))
}

fn capture_primary_snapshot(
    repo_path: &Path,
    candidate_worktree_path: &Path,
    _candidate_path: &Path,
) -> Result<PrimarySnapshot> {
    let repo = Repository::open(repo_path).context("open primary repository for snapshot")?;
    let candidate_repo = Repository::open(candidate_worktree_path)
        .context("open candidate repository for snapshot")?;
    let state_root = repo.commondir().join("maco/state");
    let lock_path = state_root.join("repository-mutation.lock");
    Ok(PrimarySnapshot {
        primary_worktree: capture_worktree_tree(repo_path)?,
        primary_head: git_output_bytes(repo_path, &["rev-parse", "--verify", "HEAD"])
            .context("capture primary HEAD")?,
        primary_index: fs::read(repo.path().join("index"))
            .context("capture primary index bytes")?,
        primary_status: git_output_bytes(
            repo_path,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )
        .context("capture porcelain-v1 -z primary status")?,
        managed_registry_and_pending_operations: capture_managed_registry_and_pending_operations(
            &state_root,
        )?,
        managed_execution_leases: capture_managed_execution_leases(&state_root)?,
        candidate_worktree: capture_worktree_tree(candidate_worktree_path)?,
        candidate_head: git_output_bytes(
            candidate_worktree_path,
            &["rev-parse", "--verify", "HEAD"],
        )
        .context("capture candidate HEAD")?,
        candidate_index: fs::read(candidate_repo.path().join("index"))
            .context("capture candidate index bytes")?,
        candidate_status: git_output_bytes(
            candidate_worktree_path,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )
        .context("capture porcelain-v1 -z candidate status")?,
        repository_mutation_lock: read_optional_bytes(&lock_path)?,
    })
}

fn capture_worktree_tree(root: &Path) -> Result<Vec<FileSystemSnapshotEntry>> {
    let mut snapshot = Vec::new();
    for entry in sorted_directory_entries(root)? {
        if entry.file_name() == OsStr::new(".git") {
            continue;
        }
        capture_file_system_entry(root, &entry.path(), &mut snapshot)?;
    }
    Ok(snapshot)
}

fn capture_managed_registry_and_pending_operations(
    state_root: &Path,
) -> Result<Vec<FileSystemSnapshotEntry>> {
    capture_selected_state_entries(state_root, |name| {
        matches!(
            name.to_str(),
            Some(
                "authenticated-managed-worktrees-v1"
                    | ".authenticated-managed-worktrees.lock"
                    | "managed_worktrees.json"
                    | "managed_worktrees.lock"
            )
        ) || name
            .to_str()
            .is_some_and(|name| name.starts_with(".managed_worktrees.json."))
    })
}

fn capture_managed_execution_leases(state_root: &Path) -> Result<Vec<FileSystemSnapshotEntry>> {
    capture_selected_state_entries(state_root, |name| {
        name.to_str().is_some_and(|name| {
            name.starts_with("managed-worktree-") && name.ends_with(".execution.lock")
        })
    })
}

fn capture_selected_state_entries(
    state_root: &Path,
    include: impl Fn(&OsStr) -> bool,
) -> Result<Vec<FileSystemSnapshotEntry>> {
    let mut snapshot = Vec::new();
    let entries = match sorted_directory_entries(state_root) {
        Ok(entries) => entries,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(snapshot)
        }
        Err(error) => return Err(error),
    };
    for entry in entries {
        if include(&entry.file_name()) {
            capture_file_system_entry(state_root, &entry.path(), &mut snapshot)?;
        }
    }
    Ok(snapshot)
}

fn capture_file_system_entry(
    root: &Path,
    path: &Path,
    snapshot: &mut Vec<FileSystemSnapshotEntry>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect snapshot entry {}", path.display()))?;
    let contents = if metadata.file_type().is_symlink() {
        FileSystemSnapshotContents::Symlink(
            fs::read_link(path)
                .with_context(|| format!("read snapshot symlink {}", path.display()))?,
        )
    } else if metadata.is_dir() {
        FileSystemSnapshotContents::Directory
    } else if metadata.is_file() {
        FileSystemSnapshotContents::File(
            fs::read(path).with_context(|| format!("read snapshot file {}", path.display()))?,
        )
    } else {
        bail!(
            "snapshot entry has unsupported file type: {}",
            path.display()
        );
    };
    snapshot.push(FileSystemSnapshotEntry {
        path: path
            .strip_prefix(root)
            .with_context(|| format!("make snapshot path relative to {}", root.display()))?
            .to_path_buf(),
        mode: snapshot_mode(&metadata),
        contents,
    });
    if metadata.is_dir() {
        for entry in sorted_directory_entries(path)? {
            capture_file_system_entry(root, &entry.path(), snapshot)?;
        }
    }
    Ok(())
}

fn sorted_directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("read snapshot directory {}", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("collect snapshot directory {}", path.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

#[cfg(unix)]
fn snapshot_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn snapshot_mode(metadata: &fs::Metadata) -> u32 {
    let readable = if metadata.is_dir() { 0o555 } else { 0o444 };
    if metadata.permissions().readonly() {
        readable
    } else {
        readable | 0o222
    }
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read optional file {}", path.display())),
    }
}

fn git_output_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .context("run git snapshot command")?;
    if !output.status.success() {
        bail!(
            "git snapshot command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn newest_numeric_json(root: &Path) -> Result<Option<std::path::PathBuf>> {
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
