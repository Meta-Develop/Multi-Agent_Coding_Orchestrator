//! Representative public CLI coverage for `supervise`.
//!
//! The former executable fake-Codex fixture cases were migrated to private injected unit tests so
//! production `--runtime fake` never becomes a shell-execution backdoor:
//! - worker/auditor omissions, delegation, path scope, validation contradictions, and schema
//!   evidence -> `supervise::tests::injected_report_validation_preserves_worker_and_auditor_failure_coverage`
//! - structural retry, corrective feedback, and parent-auditor lineage ->
//!   `supervise::tests::injected_runner_retries_structural_report_once_then_runs_parent_auditor`
//! - no retry after a path violation plus tracked, untracked, index, and HEAD integrity changes ->
//!   `supervise::tests::injected_runner_path_violation_blocks_retry_and_primary_mutations_fail_integrity_gate`
//! - mutation during the parent auditor ->
//!   `supervise::tests::injected_parent_auditor_primary_mutation_is_rejected`
//! - unverified containment stopping retries/auditors ->
//!   `supervise::tests::unverified_child_attempt_launches_neither_retry_nor_parent_auditor`
//! - setsid descendants, parent death, timeout, and delayed mutation mechanics -> the focused
//!   `process_runner::tests::required_containment_*` and guardian parent-death tests
//! - non-UTF-8 evidence serialization ->
//!   `supervise::tests::finding_serialization_escapes_non_utf8_paths_reversibly` and
//!   `supervisor_required_optional_and_vector_paths_share_reversible_serialization`

mod support;

use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use multi_agent_coding_orchestrator::supervise::FieldGuideEntrySuggestion;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn field_guide_suggestion_public_contract_accepts_content_only_and_rejects_provenance() -> Result<()>
{
    let suggestion: FieldGuideEntrySuggestion = serde_json::from_value(serde_json::json!({
        "finding": "bounded operational finding",
        "context": "bounded operational context"
    }))?;
    assert_eq!(suggestion.finding, "bounded operational finding");
    assert_eq!(suggestion.context, "bounded operational context");

    let forged = serde_json::from_value::<FieldGuideEntrySuggestion>(serde_json::json!({
        "finding": "bounded operational finding",
        "context": "bounded operational context",
        "date": "1999-01-01",
        "source_run": "agent-selected"
    }))
    .expect_err("agent-selected provenance must be rejected");
    assert!(forged.to_string().contains("unknown field"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn fake_runtime_never_executes_codex_bin_or_task_text_and_is_never_publishable() -> Result<()> {
    support::require_containment!(
        "fake_runtime_never_executes_codex_bin_or_task_text_and_is_never_publishable"
    );
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let head_before = repo.head()?.target().context("HEAD target")?;
    let index_path = repo.path().join("index");
    let index_before = fs::read(&index_path).context("read index")?;
    let scratch = repo_path.join(".maco/preexisting-runtime.txt");
    fs::create_dir_all(scratch.parent().context("runtime scratch parent")?)?;
    fs::write(&scratch, "preserve\n").context("write scratch")?;

    let script_marker = temp.path().join("malicious-script-ran");
    let network_marker = temp.path().join("malicious-network-attempted");
    let task_marker = temp.path().join("task-text-ran");
    let malicious = temp.path().join("malicious-codex");
    fs::write(
        &malicious,
        format!(
            "#!/bin/sh\ntouch '{}'\ntouch '{}'\nexit 0\n",
            script_marker.display(),
            network_marker.display()
        ),
    )?;
    let mut permissions = fs::metadata(&malicious)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&malicious, permissions)?;

    let plan_path = temp.path().join("deterministic-fake-plan.json");
    let plan = serde_json::json!({
        "version": 1,
        "task": format!("$(touch '{}'); touch '{}'", task_marker.display(), task_marker.display()),
        "assignments": [{
            "id": "deterministic-child",
            "phase": "execution",
            "assigned_paths": ["README.md"],
            "worker_assignments": []
        }]
    });
    fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?)?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "deterministic-fake-invariant",
        "--codex-bin",
        path_str(&malicious)?,
        "--runtime",
        "fake",
        "--allow-dirty-primary",
        "--json",
    ])?;
    assert_eq!(report["runtime"], "fake");
    assert_eq!(report["success"], true);
    assert_eq!(report["publishable"], false);
    assert!(!script_marker.exists());
    assert!(!network_marker.exists());
    assert!(!task_marker.exists());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    assert_eq!(fs::read_to_string(&scratch)?, "preserve\n");
    assert_eq!(fs::read(&index_path)?, index_before);
    assert_eq!(repo.head()?.target(), Some(head_before));
    assert!(repo_path
        .join(".maco/o2/runs/deterministic-fake-invariant")
        .exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn deterministic_fake_cli_emits_stable_shape_artifacts_and_cleans_claims() -> Result<()> {
    support::require_containment!(
        "deterministic_fake_cli_emits_stable_shape_artifacts_and_cleans_claims"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(
        repo_path.join("maco-objective-profiles.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "authored-v1",
                    "version": 1,
                    "quality": {
                        "held_out_percent": 50,
                        "breadth_percent": 25,
                        "anti_shortcut_percent": 25
                    },
                    "tradeoffs": {
                        "monetary_cost_percent": 80,
                        "quota_consumption_percent": 5,
                        "latency_percent": 5,
                        "retry_rework_percent": 5,
                        "human_review_percent": 5
                    }
                },
                {
                    "id": "cli-v1",
                    "version": 3,
                    "quality": {
                        "held_out_percent": 50,
                        "breadth_percent": 25,
                        "anti_shortcut_percent": 25
                    },
                    "tradeoffs": {
                        "monetary_cost_percent": 40,
                        "quota_consumption_percent": 10,
                        "latency_percent": 10,
                        "retry_rework_percent": 20,
                        "human_review_percent": 20
                    }
                }
            ]
        }))?,
    )?;
    commit_all(&Repository::open(&repo_path)?, "objective profile fixtures")?;
    let plan_path = temp.path().join("two-children.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "deterministic shape",
            "objective_profile": "authored-v1",
            "assignments": [
                {"id": "child-a", "phase": "execution", "assigned_paths": ["README.md"], "worker_assignments": []},
                {"id": "child-b", "phase": "execution", "assigned_paths": ["src/lib.rs"], "worker_assignments": []}
            ]
        }))?,
    )?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "deterministic-shape",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "1",
        "--objective-profile",
        "cli-v1",
        "--json",
    ])?;
    assert_eq!(report["runtime"], "fake");
    assert_eq!(report["success"], true);
    assert_eq!(report["publishable"], false);
    assert_eq!(
        report["role_economics_profile"]["resolved_objective_profile"]["profile"]["id"],
        "cli-v1"
    );
    assert_eq!(
        report["role_economics_profile"]["resolved_objective_profile"]["profile"]["version"],
        3
    );
    assert_eq!(
        report["role_economics_profile"]["resolved_objective_profile"]["source"],
        "repository_override"
    );
    assert_eq!(
        report["role_economics_profile"]["resolved_objective_profile"]["profile"]["tradeoffs"]
            ["human_review_percent"],
        20
    );
    assert_eq!(
        report["orchestrator_reports"].as_array().map(Vec::len),
        Some(2)
    );
    let final_report =
        repo_path.join(".maco/o2/runs/deterministic-shape/reports/supervisor-final.json");
    assert!(final_report.exists());
    let run_root = repo_path.join(".maco/o2/runs/deterministic-shape");
    assert!(run_root.exists());

    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims.as_array().context("claim status")?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn codex_runtime_custom_bin_fails_closed_and_cannot_mutate_primary() -> Result<()> {
    support::require_containment!(
        "codex_runtime_custom_bin_fails_closed_and_cannot_mutate_primary"
    );
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let private_bin = copy_cargo_built_cli(temp.path())?;
    let repo_path = create_committed_repo_with_bin(temp.path(), &private_bin)?;
    let marker = repo_path.join("must-not-be-created");
    let custom = temp.path().join("custom-codex");
    fs::write(
        &custom,
        format!(
            "#!/bin/sh\ncase \"$1\" in --version) printf 'codex-cli 0.142.3\\n';; *) touch '{}';; esac\n",
            marker.display()
        ),
    )?;
    let mut permissions = fs::metadata(&custom)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&custom, permissions)?;
    let plan_path = temp.path().join("codex-fail-closed.json");
    write_simple_plan(&plan_path, "codex-child")?;

    let output = command_with_test_machine_global_binding(
        &private_bin,
        &[
            "supervise",
            "run",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "codex-fail-closed",
            "--codex-bin",
            path_str(&custom)?,
            "--runtime",
            "codex",
            "--json",
        ],
    )
    .output()?;
    assert!(!output.status.success());
    if !output.stdout.is_empty() {
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["runtime"], "codex");
        assert_eq!(report["success"], false);
        assert_eq!(report["publishable"], false);
        assert_eq!(report["accepted"], false);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("process-tree ownership")
                || stderr.contains("containment guardian")
                || stderr.contains("verified writable external Codex execution is disabled"),
            "unexpected fail-closed stderr: {stderr}"
        );
    }
    assert!(!marker.exists());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn supervise_plan_normalizes_aliases_and_rejects_top_level_scope_conflicts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("aliases.json");
    fs::write(
        &plan_path,
        br#"{
          "version": 1,
          "task": "aliases",
          "max_child_processes": 2,
          "assignments": [
            {"id": "child-a", "phase": "execution", "role": "child_orchestrator", "assigned_paths": ["./README.md"]}
          ]
        }"#,
    )?;
    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(plan["max_child_assignments"], 2);
    assert_eq!(
        plan["assignments"][0]["assigned_paths"],
        serde_json::json!(["README.md"])
    );
    assert!(plan.get("objective_profile").is_none());
    let profile_override = run_success_json(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--objective-profile",
        "review-balanced-v2",
        "--json",
    ])?;
    assert_eq!(profile_override["objective_profile"], "review-balanced-v2");

    let overlap = temp.path().join("overlap.json");
    fs::write(
        &overlap,
        br#"{
          "version": 1,
          "task": "overlap",
          "assignments": [
            {"id": "child-a", "phase": "execution", "assigned_paths": ["src"]},
            {"id": "child-b", "phase": "execution", "assigned_paths": ["src/lib.rs"]}
          ]
        }"#,
    )?;
    let overlap_error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&overlap)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(
        overlap_error.contains(
            "assignments 'child-a' path 'src' and 'child-b' path 'src/lib.rs' overlap after normalization"
        ),
        "unexpected overlap error: {overlap_error}"
    );
    Ok(())
}

#[test]
fn primary_worktree_cli_requires_plan_and_flag_and_rejects_invalid_scope() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let primary_plan_path = temp.path().join("primary-worktree.json");
    fs::write(
        &primary_plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "bounded local deployment",
            "max_child_retries": 0,
            "max_gate_corrections": 0,
            "execution_target": {
                "kind": "primary_worktree",
                "claim_paths": ["local/deploy.txt"]
            },
            "assignments": [{
                "id": "primary-child",
                "phase": "execution",
                "assigned_paths": ["local/deploy.txt"],
                "worker_assignments": []
            }]
        }))?,
    )?;

    let normalized = run_success_json(&[
        "supervise",
        "plan",
        path_str(&primary_plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(normalized["execution_target"]["kind"], "primary_worktree");
    assert_eq!(
        normalized["execution_target"]["claim_paths"],
        serde_json::json!(["local/deploy.txt"])
    );

    let missing_flag = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&primary_plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "primary-cli-missing-flag",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert!(
        missing_flag.contains("execution_target.kind='primary_worktree'")
            && missing_flag.contains("--allow-primary-worktree"),
        "unexpected missing-flag refusal: {missing_flag}"
    );
    assert!(!repo_path
        .join(".maco/o2/runs/primary-cli-missing-flag")
        .exists());

    let ordinary_plan_path = temp.path().join("ordinary.json");
    write_simple_plan(&ordinary_plan_path, "ordinary-child")?;
    let missing_declaration = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&ordinary_plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "primary-cli-missing-declaration",
        "--runtime",
        "fake",
        "--allow-primary-worktree",
        "--json",
    ])?;
    assert!(
        missing_declaration.contains(
            "--allow-primary-worktree requires the supervisor plan declaration execution_target.kind='primary_worktree'"
        ),
        "unexpected missing-declaration refusal: {missing_declaration}"
    );
    assert!(!repo_path
        .join(".maco/o2/runs/primary-cli-missing-declaration")
        .exists());

    for (name, execution_target, expected) in [
        (
            "missing-scope",
            serde_json::json!({"kind": "primary_worktree"}),
            "missing field `claim_paths`",
        ),
        (
            "broad-scope",
            serde_json::json!({"kind": "primary_worktree", "claim_paths": ["."]}),
            "is over-broad",
        ),
        (
            "git-scope",
            serde_json::json!({"kind": "primary_worktree", "claim_paths": [".git/config"]}),
            "overlaps protected .git metadata",
        ),
    ] {
        let path = temp.path().join(format!("{name}.json"));
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "task": "invalid primary scope",
                "max_child_retries": 0,
                "max_gate_corrections": 0,
                "execution_target": execution_target,
                "assignments": [{
                    "id": "primary-child",
                    "phase": "execution",
                    "assigned_paths": ["local/deploy.txt"],
                    "worker_assignments": []
                }]
            }))?,
        )?;
        let error = run_failure_stderr(&[
            "supervise",
            "plan",
            path_str(&path)?,
            "--repo",
            path_str(&repo_path)?,
            "--json",
        ])?;
        assert!(
            error.contains(expected),
            "{name} did not fail with {expected:?}: {error}"
        );
    }
    Ok(())
}

#[test]
fn supervise_plan_from_goal_emits_nested_traceable_disjoint_workstreams() -> Result<()> {
    support::require_containment!(
        "supervise_plan_from_goal_emits_nested_traceable_disjoint_workstreams"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let goal_path = temp.path().join("goal.md");
    fs::write(
        &goal_path,
        "Coordinate independent child orchestrators.\n\
         - Update README.\n\
         - Clarify documentation in README.\n\
         - Update the ok function in src/lib.rs.\n\
         - Explain the unmatched frobnicator.\n",
    )?;

    let plan = run_success_json(&[
        "supervise",
        "plan",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert!(plan.get("task_file").is_none());
    assert_eq!(
        plan["spec_fragment_ids"],
        serde_json::json!([
            "fragment-001",
            "fragment-002",
            "fragment-003",
            "fragment-004",
            "fragment-005"
        ])
    );

    let string_array = |value: &Value, field: &str| -> Result<Vec<String>> {
        value[field]
            .as_array()
            .with_context(|| format!("{field} must be an array"))?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .with_context(|| format!("{field} entry must be a string"))
            })
            .collect()
    };
    let assignments = plan["assignments"].as_array().context("assignments")?;
    let assignments_by_id = assignments
        .iter()
        .map(|assignment| {
            let id = assignment["id"]
                .as_str()
                .context("assignment id must be a string")?;
            Ok((id.to_string(), assignment))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    assert_eq!(
        assignments_by_id.len(),
        assignments.len(),
        "planner assignment ids must be unique"
    );

    let max_depth = plan["max_depth"]
        .as_u64()
        .context("max_depth must be an integer")?;
    let max_child_assignments = plan["max_child_assignments"]
        .as_u64()
        .context("max_child_assignments must be an integer")?;
    let schedule = plan["assignment_schedule"]
        .as_array()
        .context("assignment schedule")?;
    assert_eq!(
        schedule.len(),
        assignments.len(),
        "the schedule must cover every MACO-visible assignment"
    );
    assert!(
        max_child_assignments >= schedule.len() as u64,
        "the generated fan-out bound must admit the whole flattened schedule"
    );

    let mut scheduled_depths = BTreeMap::<String, u64>::new();
    let mut root_ids = Vec::new();
    let mut nested_entry_count = 0usize;
    for (expected_index, entry) in schedule.iter().enumerate() {
        let assignment_id = entry["assignment_id"]
            .as_str()
            .context("scheduled assignment id must be a string")?;
        let depth = entry["depth"]
            .as_u64()
            .context("scheduled assignment depth must be an integer")?;
        assert_eq!(
            entry["flattened_index"].as_u64(),
            Some(expected_index as u64),
            "schedule order and flattened indexes must agree"
        );
        assert!(
            assignments_by_id.contains_key(assignment_id),
            "scheduled assignment {assignment_id} must be executable"
        );
        assert!(
            (2..=max_depth).contains(&depth),
            "scheduled depth must stay inside the declared plan bound"
        );

        if let Some(parent_id) = entry.get("parent_assignment_id").and_then(Value::as_str) {
            let parent_depth = scheduled_depths.get(parent_id).copied().with_context(|| {
                format!("nested assignment {assignment_id} must follow its parent {parent_id}")
            })?;
            assert_eq!(
                depth,
                parent_depth + 1,
                "nested assignment depth must be exactly one below its parent"
            );
            assert!(depth > 2, "nested assignments must be deeper than O1 roots");
            nested_entry_count += 1;
        } else {
            assert_eq!(
                depth, 2,
                "independent workstream roots must stay at depth 2"
            );
            root_ids.push(assignment_id.to_string());
        }

        assert!(
            scheduled_depths
                .insert(assignment_id.to_string(), depth)
                .is_none(),
            "each assignment must appear in the schedule exactly once"
        );
    }
    assert!(
        nested_entry_count > 0,
        "goal planning must emit at least one genuine parented assignment"
    );

    let mut root_paths = root_ids
        .iter()
        .map(|root_id| {
            let assignment = assignments_by_id
                .get(root_id)
                .with_context(|| format!("root assignment {root_id} must exist"))?;
            string_array(assignment, "assigned_paths")
        })
        .collect::<Result<Vec<_>>>()?;
    root_paths.sort();
    assert_eq!(
        root_paths,
        vec![
            vec!["README.md".to_string()],
            vec!["src/lib.rs".to_string()]
        ],
        "independent README and Rust workstreams must remain disjoint roots"
    );

    let mut readme_fragments = BTreeSet::new();
    let mut rust_fragments = BTreeSet::new();
    let mut rust_semantics = BTreeSet::new();
    let mut readme_worker_preserves_path = false;
    let mut rust_worker_preserves_path_and_semantics = false;
    for assignment in assignments {
        assert_eq!(assignment["role"], "child_orchestrator");
        let assigned_paths = string_array(assignment, "assigned_paths")?;
        let fragments = assignment
            .get("spec_fragment_ids")
            .map(|_| string_array(assignment, "spec_fragment_ids"))
            .transpose()?
            .unwrap_or_default();
        let workers = assignment["worker_assignments"]
            .as_array()
            .context("worker assignments must be an array")?;

        match assigned_paths.as_slice() {
            [path] if path == "README.md" => {
                readme_fragments.extend(fragments);
                readme_worker_preserves_path |= workers.iter().any(|worker| {
                    string_array(worker, "assigned_paths").is_ok_and(|paths| paths == ["README.md"])
                });
            }
            [path] if path == "src/lib.rs" => {
                rust_fragments.extend(fragments);
                rust_semantics.extend(string_array(assignment, "semantic_symbols")?);
                rust_worker_preserves_path_and_semantics |= workers.iter().any(|worker| {
                    string_array(worker, "assigned_paths")
                        .is_ok_and(|paths| paths == ["src/lib.rs"])
                        && string_array(worker, "semantic_symbols")
                            .is_ok_and(|symbols| symbols == ["crate::ok"])
                });
            }
            other => panic!("unexpected generated assignment scope: {other:?}"),
        }
    }
    assert_eq!(
        readme_fragments,
        BTreeSet::from(["fragment-002".to_string(), "fragment-003".to_string()])
    );
    assert_eq!(rust_fragments, BTreeSet::from(["fragment-004".to_string()]));
    assert_eq!(rust_semantics, BTreeSet::from(["crate::ok".to_string()]));
    assert!(
        readme_worker_preserves_path,
        "README execution must retain its worker path claim"
    );
    assert!(
        rust_worker_preserves_path_and_semantics,
        "Rust execution must retain its worker path and semantic traceability"
    );

    assert_eq!(
        plan["coverage_gaps"]
            .as_array()
            .context("coverage gaps")?
            .iter()
            .map(|gap| gap["spec_fragment_id"].as_str().context("gap fragment"))
            .collect::<Result<Vec<_>>>()?,
        vec!["fragment-001", "fragment-005"]
    );
    Ok(())
}

#[test]
fn supervise_run_from_goal_executes_the_same_validated_plan_and_preserves_primary() -> Result<()> {
    support::require_containment!(
        "supervise_run_from_goal_executes_the_same_validated_plan_and_preserves_primary"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let goal_path = temp.path().join("run-goal.md");
    fs::write(
        &goal_path,
        "Coordinate the requested repository work.\n\
         - Update README.md.\n\
         - Update the ok function in src/lib.rs.\n",
    )?;
    let expected_plan = run_success_json(&[
        "supervise",
        "plan",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let repo = Repository::open(&repo_path)?;
    let head_before = repo.head()?.target();
    let index_before = fs::read(repo.path().join("index"))?;
    let readme_before = fs::read(repo_path.join("README.md"))?;
    let lib_before = fs::read(repo_path.join("src/lib.rs"))?;

    let report = run_success_json(&[
        "supervise",
        "run",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "goal-derived-supervise",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "1",
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["publishable"], false);
    assert_eq!(report["plan_file"], "<external-plan>");
    assert_eq!(expected_plan["max_depth"], 3);
    assert!(expected_plan["assignment_schedule"]
        .as_array()
        .context("goal-derived assignment schedule")?
        .iter()
        .any(|entry| entry.get("parent_assignment_id").is_some()));
    assert_eq!(
        report["orchestrator_reports"].as_array().map(Vec::len),
        expected_plan["assignments"].as_array().map(Vec::len)
    );
    let executed_plan: Value = serde_json::from_slice(&fs::read(
        repo_path.join(".maco/o2/runs/goal-derived-supervise/assignments/supervisor-plan.json"),
    )?)?;
    assert_eq!(executed_plan, expected_plan);
    assert_eq!(Repository::open(&repo_path)?.head()?.target(), head_before);
    assert_eq!(fs::read(repo.path().join("index"))?, index_before);
    assert_eq!(fs::read(repo_path.join("README.md"))?, readme_before);
    assert_eq!(fs::read(repo_path.join("src/lib.rs"))?, lib_before);
    Ok(())
}

#[test]
fn supervise_plan_plain_text_without_actionable_workstreams_is_an_error() -> Result<()> {
    support::require_containment!(
        "supervise_plan_plain_text_without_actionable_workstreams_is_an_error"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("empty-plan-task.txt");
    fs::write(&task_path, "Explain the unmatched frobnicator.\n")?;

    let error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(error.contains("goal/spec produced no actionable workstreams"));
    assert!(error.contains("repository path, Rust module, or Rust symbol"));
    assert!(error.contains("documentation, policy, and script files are valid scopes"));
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_plain_text_policy_and_script_paths_emit_workstreams() -> Result<()> {
    support::require_containment!(
        "supervise_plan_plain_text_policy_and_script_paths_emit_workstreams"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::create_dir_all(repo_path.join(".agents/skills/agent-orchestration"))?;
    fs::create_dir_all(repo_path.join(".agents/scripts"))?;
    fs::write(
        repo_path.join(".agents/skills/agent-orchestration/SKILL.md"),
        "# Orchestration\n",
    )?;
    fs::write(
        repo_path.join(".agents/scripts/o2-autopilot"),
        "#!/bin/sh\n",
    )?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "add policy and script paths")?;
    let task_path = temp.path().join("policy-plan-task.md");
    fs::write(
        &task_path,
        "- Update `.agents/skills/agent-orchestration/SKILL.md`.\n\
         - Update `.agents/scripts/o2-autopilot`.\n",
    )?;

    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let assignments = plan["assignments"].as_array().context("assignments")?;
    assert_eq!(assignments.len(), 4);
    let scopes = assignments
        .iter()
        .map(|assignment| {
            assignment["assigned_paths"]
                .as_array()
                .context("assigned_paths")
                .and_then(|paths| {
                    paths
                        .iter()
                        .map(|path| {
                            path.as_str()
                                .map(str::to_string)
                                .context("assigned path must be a string")
                        })
                        .collect::<Result<Vec<_>>>()
                })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    assert_eq!(
        scopes,
        BTreeSet::from([
            vec![".agents/scripts/o2-autopilot".to_string()],
            vec![".agents/skills/agent-orchestration/SKILL.md".to_string()],
        ])
    );
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_plain_text_gitignored_policy_path_emits_workstream() -> Result<()> {
    support::require_containment!(
        "supervise_plan_plain_text_gitignored_policy_path_emits_workstream"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(repo_path.join(".gitignore"), ".agents/\n")?;
    fs::create_dir_all(repo_path.join(".agents/skills/agent-orchestration"))?;
    fs::write(
        repo_path.join(".agents/skills/agent-orchestration/SKILL.md"),
        "# Orchestration\n",
    )?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "ignore policy tree")?;
    let task_path = temp.path().join("gitignored-policy-plan-task.md");
    fs::write(
        &task_path,
        "- Update `.agents/skills/agent-orchestration/SKILL.md`.\n",
    )?;

    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let assignments = plan["assignments"].as_array().context("assignments")?;
    assert_eq!(assignments.len(), 2);
    let scopes = assignments
        .iter()
        .map(|assignment| {
            assignment["assigned_paths"]
                .as_array()
                .context("assigned_paths")
                .and_then(|paths| {
                    paths
                        .iter()
                        .map(|path| {
                            path.as_str()
                                .map(str::to_string)
                                .context("assigned path must be a string")
                        })
                        .collect::<Result<Vec<_>>>()
                })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    assert_eq!(
        scopes,
        BTreeSet::from([vec![
            ".agents/skills/agent-orchestration/SKILL.md".to_string()
        ]])
    );
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_treats_nested_repositories_as_opaque_outer_inventory_boundaries() -> Result<()> {
    support::require_containment!(
        "supervise_plan_treats_nested_repositories_as_opaque_outer_inventory_boundaries"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    for boundary in [
        "zeta/nested",
        "alpha/nested",
        "middle/nested",
        "beta/nested",
    ] {
        let nested_path = repo_path.join(boundary);
        fs::create_dir_all(nested_path.parent().context("nested repository parent")?)?;
        let nested = Repository::init(&nested_path)?;
        fs::create_dir_all(nested_path.join("src"))?;
        fs::write(
            nested_path.join("src/excluded.rs"),
            "pub fn nested_only() {}\n",
        )?;
        commit_all(&nested, "nested fixture")?;
    }
    let task_path = temp.path().join("nested-repository-task.md");
    fs::write(
        &task_path,
        "- Update `README.md`.\n- Update `src/lib.rs`.\n",
    )?;

    let args = [
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ];
    let first = run_success_json(&args)?;
    let second = run_success_json(&args)?;
    assert_eq!(
        first, second,
        "nested-boundary planning must be deterministic"
    );

    let mut assigned_paths = BTreeSet::new();
    for assignment in first["assignments"].as_array().context("assignments")? {
        for path in assignment["assigned_paths"]
            .as_array()
            .context("assigned_paths")?
        {
            assigned_paths.insert(
                path.as_str()
                    .context("assigned path must be a string")?
                    .to_string(),
            );
        }
    }
    assert_eq!(
        assigned_paths,
        BTreeSet::from(["README.md".to_string(), "src/lib.rs".to_string()])
    );
    assert!(first["assignments"]
        .as_array()
        .context("assignments")?
        .iter()
        .flat_map(|assignment| assignment["assigned_paths"]
            .as_array()
            .into_iter()
            .flatten())
        .all(|path| !path
            .as_str()
            .is_some_and(|path| path.contains("excluded.rs"))));
    assert_eq!(first["path_proposal"]["degraded"], false);
    let notes = first["path_proposal"]["notes"]
        .as_array()
        .context("path_proposal notes")?;
    assert!(
        notes.iter().any(|note| {
            note.as_str().is_some_and(|note| {
                note.contains("showing first 3 sorted paths")
                    && note.contains("alpha/nested")
                    && note.contains("beta/nested")
                    && note.contains("middle/nested")
                    && !note.contains("zeta/nested")
            })
        }),
        "JSON plan must keep sorted bounded nested-boundary notes: {notes:?}"
    );
    assert!(first["assignments"]
        .as_array()
        .context("assignments")?
        .iter()
        .filter_map(|assignment| assignment["task"].as_str())
        .all(|task| !task.contains("Planning inventory diagnostics:")));
    assert_eq!(first["path_proposal"], second["path_proposal"]);

    let human = command_with_test_machine_global_binding(
        BIN,
        &[
            "supervise",
            "plan",
            path_str(&task_path)?,
            "--repo",
            path_str(&repo_path)?,
        ],
    )
    .output()
    .context("run human nested-boundary plan")?;
    assert!(human.status.success(), "human nested plan failed");
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_stdout.contains("degraded: false") || human_stdout.contains("degraded: Bool(false)"),
        "human plan must surface degraded: false: {human_stdout}"
    );
    assert!(
        human_stdout.contains("showing first 3 sorted paths"),
        "human plan must surface sorted bounded nested-boundary notes: {human_stdout}"
    );
    assert!(!human_stdout.contains("Planning inventory diagnostics:"));
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_accepts_real_gitlink_and_root_gitmodules_without_nested_descent() -> Result<()> {
    support::require_containment!(
        "supervise_plan_accepts_real_gitlink_and_root_gitmodules_without_nested_descent"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let outer = Repository::open(&repo_path)?;
    fs::write(
        repo_path.join(".gitmodules"),
        "[submodule \"vendor/sdk\"]\n\tpath = vendor/sdk\n\turl = ../sdk\n",
    )?;

    let nested_path = repo_path.join("vendor/sdk");
    fs::create_dir_all(nested_path.parent().context("gitlink parent")?)?;
    let nested = Repository::init(&nested_path)?;
    fs::create_dir_all(nested_path.join("src"))?;
    fs::write(
        nested_path.join("src/excluded.rs"),
        "pub fn submodule_only() {}\n",
    )?;
    let nested_oid = commit_all(&nested, "submodule fixture")?;

    let mut index = outer.index()?;
    index.add_path(Path::new(".gitmodules"))?;
    index.add(&git2::IndexEntry {
        ctime: git2::IndexTime::new(0, 0),
        mtime: git2::IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: 0o160000,
        uid: 0,
        gid: 0,
        file_size: 0,
        id: nested_oid,
        flags: 0,
        flags_extended: 0,
        path: b"vendor/sdk".to_vec(),
    })?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = outer.find_tree(tree_id)?;
    let signature = Signature::now("maco test", "maco-test@example.invalid")?;
    let parent = outer.head()?.peel_to_commit()?;
    outer.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "add real gitlink fixture",
        &tree,
        &[&parent],
    )?;
    let gitlink = outer
        .index()?
        .get_path(Path::new("vendor/sdk"), 0)
        .context("gitlink index entry")?;
    assert_eq!(
        gitlink.mode, 0o160000,
        "fixture must contain a real gitlink"
    );

    let task_path = temp.path().join("gitlink-task.md");
    fs::write(
        &task_path,
        "- Update `.gitmodules`.\n- Update `README.md`.\n- Update `src/lib.rs`.\n",
    )?;
    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    let mut assigned_paths = BTreeSet::new();
    for assignment in plan["assignments"].as_array().context("assignments")? {
        for path in assignment["assigned_paths"]
            .as_array()
            .context("assigned_paths")?
        {
            assigned_paths.insert(
                path.as_str()
                    .context("assigned path must be a string")?
                    .to_string(),
            );
        }
    }
    assert_eq!(
        assigned_paths,
        BTreeSet::from([
            ".gitmodules".to_string(),
            "README.md".to_string(),
            "src/lib.rs".to_string(),
        ])
    );
    assert!(assigned_paths
        .iter()
        .all(|path| !path.starts_with("vendor/sdk")));
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_inventory_failure_is_strict_in_human_and_json_modes() -> Result<()> {
    support::require_containment!(
        "supervise_plan_inventory_failure_is_strict_in_human_and_json_modes"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = Repository::open(&repo_path)?;
    let alternates = repo.path().join("objects/info/alternates");
    fs::create_dir_all(alternates.parent().context("alternates parent")?)?;
    fs::write(&alternates, "/untrusted/object-store\n")?;
    let task_path = temp.path().join("failed-inventory-task.md");
    fs::write(&task_path, "Update README.md.\n")?;

    for json in [false, true] {
        let mut args = vec![
            "supervise",
            "plan",
            path_str(&task_path)?,
            "--repo",
            path_str(&repo_path)?,
        ];
        if json {
            args.push("--json");
        }
        let output = command_with_test_machine_global_binding(BIN, &args)
            .output()
            .context("run strict inventory-failure plan")?;
        assert!(
            !output.status.success(),
            "inventory failure unexpectedly emitted a successful {json:?} plan"
        );
        assert!(
            output.stdout.is_empty(),
            "inventory failure must not emit a clean-looking plan: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("repository inventory failed")
                && stderr.contains("bounded-status rejects Git object alternates"),
            "unexpected strict inventory-failure stderr: {stderr}"
        );
        assert!(
            !stderr.contains("using 1 explicitly named repository path(s)"),
            "strict default must not silently fall back to prose-named paths: {stderr}"
        );
    }
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_normalizes_typed_decomposition_and_defaults_legacy_workers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("typed-decomposition.json");
    fs::write(
        &plan_path,
        br#"{
          "version": 1,
          "task": "typed decomposition",
          "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["src"],
            "worker_assignments": [
              {"id": "ordinary-worker", "assigned_paths": ["src/lib.rs"]},
              {
                "id": "decomposition-worker",
                "kind": "megafile_decomposition",
                "target_path": "src/./supervise.rs",
                "assigned_paths": ["src/supervise.rs"]
              }
            ]
          }]
        }"#,
    )?;

    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][0]["kind"],
        "ordinary"
    );
    assert!(plan["assignments"][0]["worker_assignments"][0]
        .get("target_path")
        .is_none());
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][1]["kind"],
        "megafile_decomposition"
    );
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][1]["target_path"],
        "src/supervise.rs"
    );
    Ok(())
}

#[test]
fn supervise_plan_fails_closed_on_invalid_typed_decomposition_values() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    for (name, worker, expected) in [
        (
            "unknown-kind",
            serde_json::json!({
                "id": "worker-a",
                "kind": "decompose_maybe",
                "assigned_paths": ["src/lib.rs"]
            }),
            "kind/target_path is invalid",
        ),
        (
            "ordinary-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "ordinary",
                "target_path": "src/lib.rs",
                "assigned_paths": ["src/lib.rs"]
            }),
            "ordinary worker assignment 'worker-a' must not declare target_path",
        ),
        (
            "missing-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "megafile_decomposition",
                "assigned_paths": ["src/lib.rs"]
            }),
            "must declare target_path",
        ),
        (
            "outside-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "megafile_decomposition",
                "target_path": "README.md",
                "assigned_paths": ["src/lib.rs"]
            }),
            "is outside assigned_paths",
        ),
    ] {
        let plan_path = temp.path().join(format!("{name}.json"));
        fs::write(
            &plan_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "task": "invalid typed decomposition",
                "assignments": [{
                    "id": "child-a",
                    "phase": "execution",
                    "assigned_paths": ["README.md", "src"],
                    "worker_assignments": [worker]
                }]
            }))?,
        )?;
        let stderr = run_failure_stderr(&[
            "supervise",
            "plan",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--json",
        ])?;
        assert!(
            stderr.contains(expected),
            "{name} did not fail with {expected:?}: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn supervise_plan_still_rejects_overlapping_worker_siblings() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let overlap = temp.path().join("worker-overlap.json");
    fs::write(
        &overlap,
        br#"{
          "version": 1,
          "task": "worker overlap",
          "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["src"],
            "worker_assignments": [
              {"id": "worker-a", "assigned_paths": ["src/lib.rs"]},
              {"id": "worker-b", "assigned_paths": ["src"]}
            ]
          }]
        }"#,
    )?;
    let output = Command::new(BIN)
        .args([
            "supervise",
            "plan",
            path_str(&overlap)?,
            "--repo",
            path_str(&repo_path)?,
            "--json",
        ])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("worker 'worker-b'") && stderr.contains("overlaps worker 'worker-a'"));
    Ok(())
}

#[test]
fn supervise_run_help_documents_auto_concurrency_default() -> Result<()> {
    let output = Command::new(BIN)
        .args(["supervise", "run", "--help"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).context("UTF-8 supervise run help")?;
    assert!(stdout.contains("--max-concurrent-children <MAX_CONCURRENT_CHILDREN>"));
    assert!(stdout.contains("auto` uses the conservative network-bound default"));
    assert!(stdout.contains("[default: auto]"));
    Ok(())
}

#[test]
fn supervise_help_is_runtime_neutral() -> Result<()> {
    let top = Command::new(BIN).args(["--help"]).output()?;
    assert!(top.status.success());
    let top_stdout = String::from_utf8(top.stdout).context("UTF-8 maco help")?;
    assert!(top_stdout.contains("supervisor-of-orchestrators"));
    assert!(
        !top_stdout.contains("Codex CLI supervisor-of-orchestrators"),
        "top-level supervise help must not imply a Codex-only lane: {top_stdout}"
    );

    let run = Command::new(BIN)
        .args(["supervise", "run", "--help"])
        .output()?;
    assert!(run.status.success());
    let run_stdout = String::from_utf8(run.stdout).context("UTF-8 supervise run help")?;
    assert!(run_stdout.contains("child orchestrators"));
    assert!(
        !run_stdout.contains("child Codex CLI orchestrators"),
        "supervise run help must not imply Codex-only children: {run_stdout}"
    );
    Ok(())
}

#[test]
fn supervise_run_rejects_zero_bound_before_reserving_state_and_accepts_one() -> Result<()> {
    support::require_containment!(
        "supervise_run_rejects_zero_bound_before_reserving_state_and_accepts_one"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("bounded-run.json");
    write_simple_plan(&plan_path, "bounded-child")?;

    let zero_stderr = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-zero",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "0",
        "--json",
    ])?;
    assert!(zero_stderr.contains("--max-concurrent-children must be at least 1"));
    assert!(!repo_path.join(".maco/o2/runs/bounded-zero").exists());
    assert!(!temp
        .path()
        .join(".maco/worktrees/repo/bounded-child")
        .exists());
    let repo = Repository::open(&repo_path)?;
    assert!(repo
        .find_branch("maco/bounded-child", git2::BranchType::Local)
        .is_err());
    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims.as_array().context("claim status")?.is_empty());

    let one = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-one",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "1",
        "--json",
    ])?;
    assert_eq!(one["success"], true);
    assert_eq!(one["runtime"], "fake");
    assert!(repo_path.join(".maco/o2/runs/bounded-one").exists());
    Ok(())
}

#[test]
fn supervise_run_executes_fake_runtime_with_explicit_and_auto_concurrency() -> Result<()> {
    support::require_containment!(
        "supervise_run_executes_fake_runtime_with_explicit_and_auto_concurrency"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("concurrent-run.json");
    write_simple_plan(&plan_path, "concurrent-child")?;
    let explicit = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-two",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "2",
        "--json",
    ])?;
    assert_eq!(explicit["success"], true);
    assert!(repo_path.join(".maco/o2/runs/bounded-two").exists());

    let auto_plan_path = temp.path().join("auto-run.json");
    write_simple_plan(&auto_plan_path, "auto-child")?;
    let automatic = run_success_json(&[
        "supervise",
        "run",
        path_str(&auto_plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-auto",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "auto",
        "--json",
    ])?;
    assert_eq!(automatic["success"], true);
    assert!(repo_path.join(".maco/o2/runs/bounded-auto").exists());
    Ok(())
}

#[test]
fn supervise_run_id_reuse_is_refused_and_artifacts_remain_collectable() -> Result<()> {
    support::require_containment!(
        "supervise_run_id_reuse_is_refused_and_artifacts_remain_collectable"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("artifact-plan.json");
    write_simple_plan(&plan_path, "artifact-child")?;
    let args = [
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "artifact-run",
        "--runtime",
        "fake",
        "--json",
    ];
    let first = run_success_json(&args)?;
    assert_eq!(first["success"], true);
    let second = run_failure_stderr(&args)?;
    assert!(second.contains("already exists"));

    let status = run_success_json(&[
        "supervise",
        "status",
        "artifact-run",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["final_report_exists"], true);
    assert_eq!(status["repo"], ".");
    assert_eq!(status["run_dir"], ".maco/o2/runs/artifact-run");
    assert_eq!(status["final_report"]["success"], true);
    Ok(())
}

#[test]
fn fake_prompt_keeps_role_assignment_and_consultant_contract_as_data() -> Result<()> {
    support::require_containment!(
        "fake_prompt_keeps_role_assignment_and_consultant_contract_as_data"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("prompt-plan.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "parent task",
            "consultant": {"enabled": true, "runtime": "fake", "max_consultations": 1},
            "assignments": [{
                "id": "prompt-child",
                "phase": "execution",
                "assigned_paths": ["README.md"],
                "task": "child override $(touch must-not-run)",
                "worker_assignments": [{
                    "id": "prompt-worker",
                    "assigned_paths": ["README.md"],
                    "task": null
                }]
            }]
        }))?,
    )?;
    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "prompt-contract",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    let prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/prompt-contract/assignments/prompt-child.prompt.md"),
    )?;
    assert!(prompt.contains("child override $(touch must-not-run)"));
    assert!(prompt.contains("terminal worker/researcher"));
    assert!(prompt.contains("no_further_delegation"));
    assert!(!repo_path.join("must-not-run").exists());
    Ok(())
}

#[test]
fn supervise_generates_run_ids_refuses_reuse_and_lists_artifacts() -> Result<()> {
    support::require_containment!("supervise_generates_run_ids_refuses_reuse_and_lists_artifacts");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("generated-id.json");
    write_simple_plan(&plan_path, "generated-child")?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--runtime",
        "fake",
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("o2-"));

    let listed = run_success_json(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(listed["runs"].as_array().context("runs")?.len(), 1);
    Ok(())
}

#[test]
fn supervise_prune_deletes_only_finalized_old_runs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let prune = run_success_json(&[
        "supervise",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["delete_candidate_count"], 0);
    assert_eq!(prune["deleted_count"], 0);
    assert_eq!(prune["refused_unfinalized_count"], 0);

    let listed = run_success_json(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let runs = listed["runs"].as_array().context("listed supervise runs")?;
    assert!(runs.is_empty());
    Ok(())
}

#[test]
fn supervise_plan_rejects_cross_assignment_semantic_conflicts_even_in_warn_mode() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "semantic symbol")?;
    let plan_path = temp.path().join("semantic-warn.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "coordinate semantic overlap",
            "max_depth": 2,
            "max_child_assignments": 2,
            "semantic_coordination": "warn",
            "assignments": [
                {
                    "id": "child-a",
                    "phase": "execution",
                    "assigned_paths": ["README.md"],
                    "semantic_symbols": ["Shared"],
                    "worker_assignments": []
                },
                {
                    "id": "child-b",
                    "phase": "execution",
                    "assigned_paths": ["src/lib.rs"],
                    "semantic_symbols": ["Shared"],
                    "worker_assignments": []
                }
            ]
        }))?,
    )?;

    let error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(
        error.contains(
            "assignment 'child-a' and assignment 'child-b' overlap semantic symbol 'Shared' after normalization"
        ),
        "unexpected semantic conflict error: {error}"
    );
    Ok(())
}

#[test]
fn supervise_run_reports_sync_claim_conflict_owner_and_paths() -> Result<()> {
    support::require_containment!("supervise_run_reports_sync_claim_conflict_owner_and_paths");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("claim-conflict.json");
    write_simple_plan(&plan_path, "child-claim-conflict")?;
    let claim = run_success_json(&[
        "sync",
        "claim",
        "stale-agent",
        "README.md",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(claim["agent_id"], "stale-agent");

    let report = run_failure_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "claim-conflict",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["success"], false);
    assert_eq!(
        report["gate_denials"][0]["reason"]["family"],
        "claim_conflict"
    );
    assert_eq!(
        report["gate_denials"][0]["context"]["paths"],
        serde_json::json!(["README.md"])
    );
    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims
        .as_array()
        .context("claims")?
        .iter()
        .any(|claim| claim["agent_id"] == "stale-agent"));
    Ok(())
}

#[test]
fn supervise_run_refuses_clean_stale_reused_child_worktree_before_execution() -> Result<()> {
    support::require_containment!(
        "supervise_run_refuses_clean_stale_reused_child_worktree_before_execution"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("stale-worktree.json");
    write_simple_plan(&plan_path, "child-clean")?;
    let child = run_success_json(&[
        "worktree",
        "create",
        "child-clean",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(child["name"], "child-clean");
    let child_path = PathBuf::from(
        child["path"]
            .as_str()
            .context("managed child worktree path")?,
    );
    assert_eq!(
        child_path,
        temp.path().join(".maco/worktrees/repo/child-clean")
    );
    assert!(child_path.is_dir());
    fs::write(repo_path.join("README.md"), "# advanced\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "advance primary")?;

    let report = run_failure_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "clean-stale",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert!(serde_json::to_string(&report)?.contains("stale-base"));
    assert!(!repo_path
        .join(".maco/o2/runs/clean-stale/evidence/incoming/child-clean.json")
        .exists());
    Ok(())
}

#[test]
fn supervise_plan_enforces_depth_assignment_and_retry_bounds() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let cases = [
        (
            "bad-depth",
            serde_json::json!({
                "version": 1,
                "task": "bad depth",
                "max_depth": 33,
                "max_child_assignments": 1,
                "assignments": [{"id": "child-a", "phase": "execution", "assigned_paths": ["README.md"]}]
            }),
            "max_depth",
        ),
        (
            "bad-budget",
            serde_json::json!({
                "version": 1,
                "task": "bad budget",
                "max_depth": 2,
                "max_child_assignments": 1,
                "assignments": [
                    {"id": "child-a", "phase": "execution", "assigned_paths": ["README.md"]},
                    {"id": "child-b", "phase": "execution", "assigned_paths": ["src/lib.rs"]}
                ]
            }),
            "max_child_assignments",
        ),
        (
            "bad-retries",
            serde_json::json!({
                "version": 1,
                "task": "bad retries",
                "max_depth": 2,
                "max_child_assignments": 1,
                "max_child_retries": 3,
                "assignments": [{"id": "child-a", "phase": "execution", "assigned_paths": ["README.md"]}]
            }),
            "max_child_retries",
        ),
    ];
    for (run_id, plan, expected) in cases {
        let plan_path = temp.path().join(format!("{run_id}.json"));
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?)?;
        let output = Command::new(BIN)
            .args([
                "supervise",
                "plan",
                path_str(&plan_path)?,
                "--repo",
                path_str(&repo_path)?,
                "--json",
            ])
            .output()?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "missing {expected} in {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn supervise_primary_git_snapshots_ignore_ambient_repository_redirects() -> Result<()> {
    support::require_containment!(
        "supervise_primary_git_snapshots_ignore_ambient_repository_redirects"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let decoy_path = temp.path().join("decoy");
    Repository::init(&decoy_path)?;
    let plan_path = temp.path().join("ambient-git.json");
    write_simple_plan(&plan_path, "ambient-child")?;
    let trace = temp.path().join("git-trace.log");
    let trace2 = temp.path().join("git-trace2.json");
    let redirected = temp.path().join("git-stderr.log");
    let mut command = command_with_test_machine_global_binding(
        BIN,
        &[
            "supervise",
            "run",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "ambient-git",
            "--runtime",
            "fake",
            "--json",
        ],
    );
    let output = command
        .env("GIT_DIR", decoy_path.join(".git"))
        .env("GIT_WORK_TREE", &decoy_path)
        .env("GIT_INDEX_FILE", temp.path().join("ambient-index"))
        .env("GIT_COMMON_DIR", decoy_path.join(".git"))
        .env("GIT_TRACE", &trace)
        .env("GIT_TRACE2_EVENT", &trace2)
        .env("GIT_REDIRECT_STDERR", &redirected)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "unsafe-fsmonitor")
        .output()?;
    assert!(
        output.status.success(),
        "fake supervise run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!trace.exists());
    assert!(!trace2.exists());
    assert!(!redirected.exists());
    Ok(())
}

#[test]
fn security_document_describes_deterministic_fake_and_verified_codex_boundary() -> Result<()> {
    let security = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("SECURITY.md"))?;
    assert!(security.contains("Fake supervisor runtime is deterministic"));
    assert!(security.contains("does not execute `--codex-bin`"));
    assert!(security.contains("can never produce publishable acceptance"));
    assert!(security.contains("maco_external_codex"));
    assert!(security.contains("strict-offline `--version` diagnostic"));
    assert!(security.contains("sibling `trusted/` and `incoming/` roots"));
    assert!(security.contains("Version 1 and version 2 checkpoints are unauthenticated"));
    assert!(security.contains("legacy formats and are refused for resume"));
    assert!(security.contains("fixed known-hosts set is a later integration boundary")
        || security.contains("Destination allowlisting against a fixed known-hosts set is a later integration boundary"));
    Ok(())
}

fn write_simple_plan(path: &Path, id: &str) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "simple deterministic plan",
            "assignments": [{
                "id": id,
                "phase": "execution",
                "assigned_paths": ["README.md"],
                "worker_assignments": []
            }]
        }))?,
    )?;
    Ok(())
}

#[cfg(unix)]
fn copy_cargo_built_cli(root: &Path) -> Result<std::path::PathBuf> {
    let mut source = fs::File::open(BIN).context("open Cargo-built maco executable")?;
    let source_metadata = source
        .metadata()
        .context("inspect Cargo-built maco executable")?;
    let private_bin = root.join("maco-private-bin");
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_bin)
        .context("create private maco test executable")?;
    std::io::copy(&mut source, &mut destination).context("copy private maco test executable")?;
    destination
        .sync_all()
        .context("sync private maco test executable")?;
    fs::set_permissions(&private_bin, source_metadata.permissions())
        .context("preserve private maco test executable permissions")?;
    Ok(private_bin)
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(BIN, args)
        .output()
        .context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse success JSON")
}

fn run_failure_stderr(args: &[&str]) -> Result<String> {
    let output = command_with_test_machine_global_binding(BIN, args)
        .output()
        .context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(BIN, args)
        .output()
        .context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse failed-run JSON: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn command_with_test_machine_global_binding(bin: impl AsRef<Path>, args: &[&str]) -> Command {
    let mut command = Command::new(bin.as_ref());
    command.args(args);
    if args.first() == Some(&"supervise") && args.get(1) == Some(&"run") {
        let repo = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--repo").then_some(Path::new(pair[1])))
            .expect("supervise run test command must name --repo");
        let config = write_test_machine_global_config(repo)
            .expect("write supervise CLI machine-global config");
        command
            .arg("--machine-global-config")
            .arg(config)
            .args(["--machine-global-runtime-root-id", "runtime"]);
    }
    command
}

#[cfg(target_os = "linux")]
fn write_test_machine_global_config(repo: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture_root = repo.parent().context("test repository parent")?;
    let state_root = fixture_root.join("supervise-machine-global-state");
    fs::create_dir_all(&state_root)?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))?;
    let uid = fs::metadata("/proc/self")?.uid();
    let runtime_root = PathBuf::from(format!("/run/user/{uid}"));
    let config = fixture_root.join("supervise-machine-global.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))?,
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    Ok(config)
}

#[cfg(not(target_os = "linux"))]
fn write_test_machine_global_config(repo: &Path) -> Result<PathBuf> {
    Ok(repo.join("unsupported-machine-global-config"))
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_bin(root, Path::new(BIN))
}

fn create_committed_repo_with_bin(root: &Path, bin: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(bin)
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    fs::create_dir_all(repo_path.join("src"))?;
    fs::write(repo_path.join(".gitignore"), ".maco/\n")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "initial")?;
    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let signature = Signature::now("maco test", "maco-test@example.invalid")?;
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

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
