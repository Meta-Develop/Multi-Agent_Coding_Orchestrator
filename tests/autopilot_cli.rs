mod support;

use anyhow::{Context, Result};
use git2::{ObjectType, Oid, Repository, Signature};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const COMMAND_DIAGNOSTIC_LIMIT_CHARS: usize = 4096;
const BOUNDED_STATUS_RUNTIME_ROOT_ENV: &str = "MACO_BOUNDED_STATUS_RUNTIME_ROOT";
const TEST_CHILD_TMPDIR_NAME: &str = "autopilot-child-tmp";

#[test]
fn containment_gate_only_skips_without_a_delegated_user_manager() {
    use support::containment::delegated_user_manager_available;

    assert!(delegated_user_manager_available(
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/test.scope\n"
    ));
    assert!(!delegated_user_manager_available(
        "0::/system.slice/hosted-compute-agent.service\n"
    ));
    assert!(!delegated_user_manager_available(
        "0::/system.slice/not-user@1000.service/test.scope\n"
    ));
    assert!(!delegated_user_manager_available(
        "0::/system.slice/user@1000.service.scope/test.scope\n"
    ));
    assert!(!delegated_user_manager_available("1:name=systemd:/\n"));
}

#[test]
fn autopilot_run_cli_requires_machine_global_binding_before_effect_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let second_fixture = TempDir::new().context("second fixture tempdir")?;
    let second_repo = second_fixture.path().join("repo");

    let first = command_with_test_fixture_environment(&repo_path)?;
    let first_again = command_with_test_fixture_environment(&repo_path)?;
    let second = command_with_test_fixture_environment(&second_repo)?;
    let first_tmpdir = command_environment_path(&first, "TMPDIR")?;
    let first_tmpdir_again = command_environment_path(&first_again, "TMPDIR")?;
    let second_tmpdir = command_environment_path(&second, "TMPDIR")?;

    assert!(first_tmpdir.is_dir(), "child TMPDIR must exist");
    assert!(second_tmpdir.is_dir(), "child TMPDIR must exist");
    assert!(
        !first_tmpdir.starts_with(&repo_path),
        "child TMPDIR must remain outside the fixture repository"
    );
    assert!(
        !second_tmpdir.starts_with(&second_repo),
        "child TMPDIR must remain outside the fixture repository"
    );
    assert!(
        first_tmpdir == temp.path().join(TEST_CHILD_TMPDIR_NAME),
        "child TMPDIR must derive from the fixture parent"
    );
    assert!(
        second_tmpdir == second_fixture.path().join(TEST_CHILD_TMPDIR_NAME),
        "child TMPDIR must derive from the fixture parent"
    );
    assert!(
        first_tmpdir == first_tmpdir_again,
        "one fixture must retain one stable child TMPDIR"
    );
    assert!(
        first_tmpdir != second_tmpdir,
        "independent fixtures must not share a child TMPDIR"
    );
    if let Some(lane_tmpdir) = std::env::var_os("TMPDIR") {
        assert!(
            first_tmpdir != lane_tmpdir,
            "child TMPDIR must not inherit lane-global state"
        );
    }
    assert!(
        first.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new(BOUNDED_STATUS_RUNTIME_ROOT_ENV) && value.is_none()
        }),
        "an ambient explicit bounded-status root must not override fixture isolation"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for child_tmpdir in [&first_tmpdir, &second_tmpdir] {
            let metadata = fs::metadata(child_tmpdir).context("inspect child TMPDIR")?;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let process_uid = fs::metadata("/proc/self")
            .context("inspect current process owner")?
            .uid();
        for child_tmpdir in [&first_tmpdir, &second_tmpdir] {
            let metadata = fs::metadata(child_tmpdir).context("inspect child TMPDIR owner")?;
            assert_eq!(metadata.uid(), process_uid);
        }
    }
    let mut before = fs::read_dir(&repo_path)
        .context("read repository before refusal")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    before.sort();

    let plan = temp.path().join("plan-must-not-be-read");
    let config = temp.path().join("machine-global-must-not-be-opened.json");
    let cases = [
        (Vec::new(), "--machine-global-config"),
        (
            vec!["--machine-global-config", path_str(&config)?],
            "--machine-global-runtime-root-id",
        ),
        (
            vec!["--machine-global-runtime-root-id", "runtime"],
            "--machine-global-config",
        ),
    ];
    for (extra, missing_option) in cases {
        let output = command_with_test_fixture_environment(&repo_path)?
            .args([
                "autopilot",
                "run",
                path_str(&plan)?,
                "--repo",
                path_str(&repo_path)?,
                "--run-id",
                "failclosed-no-effects",
                "--json",
            ])
            .args(extra)
            .output()
            .context("run autopilot with an incomplete retention binding")?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(missing_option));
    }

    let mut after = fs::read_dir(&repo_path)
        .context("read repository after refusal")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    after.sort();
    assert_eq!(before, after);
    assert!(!repo_path.join(".maco/autopilot").exists());
    assert!(!repo_path.join(".maco/o2").exists());
    assert!(!repo_path.join(".agents/live").exists());
    Ok(())
}

#[test]
fn legacy_reviewer_command_refuses_before_autopilot_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let stderr = run_failure_stderr(&[
        "autopilot",
        "run",
        path_str(&temp.path().join("plan-must-not-be-read"))?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "disabled-reviewer-command",
        "--reviewer-command",
        "must-not-run",
        "--json",
    ])?;

    assert!(stderr.contains("disabled legacy publication loop"));
    assert!(!repo_path.join(".maco/autopilot").exists());
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn autopilot_profile_manifest_rejects_unsupported_version_before_effect_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let profile_path = temp.path().join("unsupported-profile.json");
    write_file(&profile_path, r#"{"version": 2}"#)?;

    let stderr = run_failure_stderr(&[
        "autopilot",
        "run",
        path_str(&temp.path().join("plan-must-not-be-read"))?,
        "--repo",
        path_str(&repo_path)?,
        "--profile",
        path_str(&profile_path)?,
        "--run-id",
        "unsupported-profile-version",
        "--json",
    ])?;

    assert!(stderr.contains("unsupported autopilot profile version 2"));
    assert!(!repo_path.join(".maco/autopilot").exists());
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn autopilot_plan_json_normalizes_defaults_and_aliases() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("autopilot-plan.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "  Normalize me  ", "body": "  Body text  "},
          "assigned_paths": ["./README.md", "README.md"],
          "semantic_symbols": ["Thing", "Thing", " "],
          "semantic_modules": ["crate::a", "crate::a"],
          "validation_commands": [
            "true",
            {"name": " smoke ", "command": " true "}
          ],
          "forge": "git",
          "auto_merge": true
        }"#,
    )?;

    let plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert_eq!(plan["task"]["title"], "Normalize me");
    assert_eq!(plan["task"]["body"], "Body text");
    assert_eq!(plan["assigned_paths"], serde_json::json!(["README.md"]));
    assert_eq!(plan["semantic_symbols"], serde_json::json!(["Thing"]));
    assert_eq!(plan["semantic_modules"], serde_json::json!(["crate::a"]));
    assert_eq!(plan["max_repair_attempts"], 1);
    assert_eq!(plan["forge_mode"], "git");
    assert_eq!(plan["reviewer"]["mode"], "fake");
    assert_eq!(plan["publish_mode"], "draft_only");
    assert_eq!(plan["auto_merge"], true);
    assert_eq!(plan["validation_commands"][1]["name"], "smoke");

    Ok(())
}

#[test]
fn autopilot_plan_proposes_paths_from_plain_and_empty_tasks() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    write_file(&repo_path.join("src/inbox.rs"), "pub struct InboxRepair;\n")?;
    commit_all(&Repository::open(&repo_path)?, "add inbox module")?;

    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Update README.md and repair InboxRepair in src/inbox.rs.\n",
    )?;
    let plain_plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(
        plain_plan["assigned_paths"],
        serde_json::json!(["README.md", "src/inbox.rs"])
    );

    let plan_path = temp.path().join("empty-paths.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {
            "title": "Repair inbox command",
            "body": "Fix InboxRepair handling."
          },
          "assigned_paths": []
        }"#,
    )?;
    let json_plan = run_success_json(&[
        "autopilot",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(
        json_plan["assigned_paths"],
        serde_json::json!(["src/inbox.rs"])
    );

    Ok(())
}

#[test]
fn fake_autopilot_depth_two_e2e_is_gated_durable_and_primary_untouched() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("autopilot-plan.json");
    write_file(
        &task_path,
        r#"{
          "version": 1,
          "task": {
            "title": "Depth two gated run",
            "body": "Exercise the full Fake supervise flow without applying to primary."
          },
          "max_depth": 2,
          "assigned_paths": ["README.md"],
          "auto_merge": false
        }"#,
    )?;
    let primary_before = primary_git_snapshot(&repo_path)?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "durable",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["attempt_count"], 1);
    assert_eq!(report["supervisor"]["runtime"], "fake");
    assert_eq!(report["supervisor"]["success"], true);
    assert_eq!(report["supervisor"]["publishable"], false);
    assert_eq!(report["primary_worktree_untouched"], true);
    assert_eq!(report["auto_merge_performed"], false);
    assert_eq!(report["generated_follow_up_dispatch_performed"], false);
    assert_eq!(
        report["supervisor"]["orchestrator_reports"][0]["worker_reports"][0]
            ["no_further_delegation"],
        true
    );
    assert_eq!(
        report["supervisor"]["orchestrator_reports"][0]["audit_reports"][0]["read_only"],
        true
    );
    assert!(report["supervisor"]["orchestrator_reports"][0]["review_lens_aggregate"].is_object());

    let run_dir = repo_path.join(".maco/autopilot/runs/durable");
    for artifact in [
        "plan.json",
        "supervisor-plan.json",
        "supervisor-report.json",
        "pr-report.json",
        "review-report.json",
        "final-report.json",
    ] {
        assert!(run_dir.join(artifact).exists(), "missing {artifact}");
    }
    let supervisor_plan: Value =
        serde_json::from_slice(&fs::read(run_dir.join("supervisor-plan.json"))?)?;
    assert_eq!(supervisor_plan["max_depth"], 2);
    assert_eq!(
        supervisor_plan["assignments"][0]["worker_assignments"][0]["role"],
        "worker"
    );
    assert!(repo_path.join(".maco/o2/runs/durable-supervise").exists());
    assert_eq!(primary_git_snapshot(&repo_path)?, primary_before);

    let machine_global_status = run_success_json(&[
        "machine-global",
        "status",
        "--config",
        path_str(&test_machine_global_config_path(&repo_path)?)?,
        "--json",
    ])?;
    let retention = machine_global_status["retention_operations"]
        .as_array()
        .context("retention operations")?;
    assert!(
        retention.is_empty(),
        "the in-process Fake runtime must not manufacture external output-staging cleanup"
    );

    Ok(())
}

#[test]
fn fake_autopilot_goal_run_dispatches_exact_derived_tree_and_preserves_primary() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let goal_path = temp.path().join("autopilot-goal.md");
    write_file(
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
    let primary_before = primary_git_snapshot(&repo_path)?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "goal-derived-autopilot",
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["supervisor"]["runtime"], "fake");
    assert_eq!(report["supervisor"]["publishable"], false);
    assert_eq!(report["primary_worktree_untouched"], true);
    assert_eq!(report["auto_merge_performed"], false);
    assert_eq!(report["generated_follow_up_dispatch_performed"], false);
    assert_eq!(report["profile_binding"]["configuration_status"], "matched");
    assert_eq!(expected_plan["max_depth"], 3);
    assert!(expected_plan["assignment_schedule"]
        .as_array()
        .context("goal-derived assignment schedule")?
        .iter()
        .any(|entry| entry.get("parent_assignment_id").is_some()));
    assert_eq!(
        report["supervisor"]["orchestrator_reports"]
            .as_array()
            .map(Vec::len),
        expected_plan["assignments"].as_array().map(Vec::len)
    );
    let run_dir = repo_path.join(".maco/autopilot/runs/goal-derived-autopilot");
    let recorded_goal_plan: Value = serde_json::from_slice(&fs::read(run_dir.join("plan.json"))?)?;
    let dispatched_plan: Value =
        serde_json::from_slice(&fs::read(run_dir.join("supervisor-plan.json"))?)?;
    let supervise_snapshot: Value = serde_json::from_slice(&fs::read(repo_path.join(
        ".maco/o2/runs/goal-derived-autopilot-supervise/assignments/supervisor-plan.json",
    ))?)?;
    assert_eq!(recorded_goal_plan, expected_plan);
    assert_eq!(dispatched_plan, expected_plan);
    assert_eq!(supervise_snapshot, expected_plan);
    assert_eq!(primary_git_snapshot(&repo_path)?, primary_before);
    Ok(())
}

#[test]
fn autopilot_goal_run_refuses_profile_that_would_mutate_the_derived_plan() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let goal_path = temp.path().join("profile-refusal-goal.md");
    write_file(&goal_path, "Update README.md.\n")?;
    let profile_path = temp.path().join("nondefault-profile.json");
    write_file(
        &profile_path,
        r#"{
          "version": 1,
          "role_models": {
            "worker": {"model": "would-mutate-derived-plan"}
          }
        }"#,
    )?;
    let primary_before = primary_git_snapshot(&repo_path)?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--profile",
        path_str(&profile_path)?,
        "--run-id",
        "goal-profile-refusal",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["attempt_count"], 0);
    assert_eq!(
        report["profile_binding"]["configuration_status"],
        "mismatch"
    );
    assert!(report.get("supervisor").is_none());
    assert!(!repo_path
        .join(".maco/o2/runs/goal-profile-refusal-supervise")
        .exists());
    assert_eq!(primary_git_snapshot(&repo_path)?, primary_before);
    Ok(())
}

#[test]
fn fake_autopilot_run_reports_configured_but_execution_incomparable_profile() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("profiled-plan.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {
            "title": "Profile-bound run",
            "body": "Exercise a non-default supervisor profile through autopilot."
          },
          "assigned_paths": ["README.md"]
        }"#,
    )?;
    let profile_path = temp.path().join("profile.json");
    write_file(
        &profile_path,
        r#"{
          "version": 1,
          "role_models": {
            "worker": {
              "model": "profile-worker-model",
              "reasoning_effort": "medium",
              "unavailable_model_fallback": "local_deterministic_fake"
            }
          },
          "model_pricing": {
            "profile-worker-model": {
              "input_usd_per_million_tokens": 1.25,
              "output_usd_per_million_tokens": 5.5
            },
            "profile-review-model": {
              "input_usd_per_million_tokens": 2.0,
              "output_usd_per_million_tokens": 8.0
            }
          },
          "review_lenses": [{
            "id": "profile-diff-review",
            "backend": {
              "kind": "model",
              "backend_id": "profile-provider",
              "model": "profile-review-model",
              "reasoning_effort": "high"
            },
            "information_scope": "diff_only"
          }],
          "review_aggregation_policy": {"kind": "all_must_accept"}
        }"#,
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--profile",
        path_str(&profile_path)?,
        "--run-id",
        "profile-bound",
        "--json",
    ])?;

    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["profile_binding"]["version"], 3);
    assert_eq!(report["profile_binding"]["status"], "incomparable");
    assert_eq!(report["profile_binding"]["configuration_status"], "matched");
    assert!(report["profile_binding"].get("failure").is_none());
    assert_eq!(
        report["profile_binding"]["requested"],
        report["profile_binding"]["effective"]
    );
    assert_eq!(
        report["profile_binding"]["effective"]["role_models"]["worker"]["model"],
        "profile-worker-model"
    );
    assert_eq!(
        report["profile_binding"]["effective"]["model_pricing"]["profile-review-model"]
            ["output_usd_per_million_tokens"],
        8.0
    );
    assert_eq!(
        report["profile_binding"]["effective"]["review_lenses"][0]["id"],
        "profile-diff-review"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["role_models"][0]["role"],
        "worker"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["role_models"][0]["status"],
        "incomparable"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["role_models"][0]["observation"],
        "not_process_observable"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["review_lenses"][0]["status"],
        "incomparable"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["review_lenses"][0]["observation"],
        "not_process_observable"
    );
    assert_eq!(
        report["profile_binding"]["execution"]["review_lenses"][0]["dispatch_count"],
        1
    );
    assert!(report["profile_binding"]["execution"]["review_lenses"][0]
        .get("observed_backend_id")
        .is_none());
    assert!(report["profile_binding"]["execution"]["review_lenses"][0]
        .get("observed_model")
        .is_none());
    assert_eq!(
        report["supervisor"]["role_economics_profile"]["overridden_roles"],
        serde_json::json!(["worker"])
    );
    assert_eq!(
        report["supervisor"]["role_economics_profile"]["role_models"]["worker"]["model"],
        "profile-worker-model"
    );
    let executed_lens = &report["supervisor"]["orchestrator_reports"][0]["review_lens_aggregate"]
        ["lens_verdicts"][0]["lens"];
    assert_eq!(executed_lens["id"], "profile-diff-review");
    assert_eq!(executed_lens["model"], "profile-review-model");

    let supervisor_plan: Value = serde_json::from_slice(&fs::read(
        repo_path.join(".maco/autopilot/runs/profile-bound/supervisor-plan.json"),
    )?)?;
    assert_eq!(
        supervisor_plan["role_models"],
        report["profile_binding"]["requested"]["role_models"]
    );
    assert_eq!(
        supervisor_plan["model_pricing"],
        report["profile_binding"]["requested"]["model_pricing"]
    );
    assert_eq!(
        supervisor_plan["review_lenses"],
        report["profile_binding"]["requested"]["review_lenses"]
    );
    assert_eq!(
        supervisor_plan["review_aggregation_policy"],
        report["profile_binding"]["requested"]["review_aggregation_policy"]
    );

    let alternate_profile = fs::read_to_string(&profile_path)?
        .replace("profile-provider", "alternate-profile-provider");
    write_file(&profile_path, &alternate_profile)?;
    let alternate = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--profile",
        path_str(&profile_path)?,
        "--run-id",
        "alternate-profile-bound",
        "--json",
    ])?;
    assert_ne!(
        report["profile_binding"]["requested"]["review_lenses"][0]["backend"]["backend_id"],
        alternate["profile_binding"]["requested"]["review_lenses"][0]["backend"]["backend_id"]
    );
    for profile_report in [&report, &alternate] {
        let lens = &profile_report["profile_binding"]["execution"]["review_lenses"][0];
        assert_eq!(lens["status"], "incomparable");
        assert_ne!(lens["status"], "matched");
        assert!(lens.get("observed_backend_id").is_none());
    }

    Ok(())
}

#[test]
fn autopilot_run_refuses_max_depth_three_with_typed_permission_expansion() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("depth-three.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Depth three", "body": "Request unsupported depth."},
          "max_depth": 3,
          "assigned_paths": ["README.md"]
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "depth-three-refusal",
        "--json",
    ])?;

    assert_depth_permission_expansion_refusal(&report);
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn autopilot_run_refuses_recursive_assignments_with_typed_permission_expansion() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("recursive-assignments.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Recursive plan", "body": "Request unsupported recursion."},
          "max_depth": 2,
          "assigned_paths": ["README.md"],
          "assignments": [{
            "id": "depth-two",
            "child_assignments": [{"id": "depth-three"}]
          }]
        }"#,
    )?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "recursive-depth-refusal",
        "--json",
    ])?;

    assert_depth_permission_expansion_refusal(&report);
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn primary_git_snapshot_detects_complete_state_drift() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let omitted_path = repo_path.join("otherwise-omitted.txt");
    write_file(&omitted_path, "baseline\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "add otherwise omitted path")?;
    let baseline = primary_git_snapshot(&repo_path)?;

    write_file(&omitted_path, "worktree content changed\n")?;
    let content_changed = primary_git_snapshot(&repo_path)?;
    assert_ne!(content_changed.worktree, baseline.worktree);
    assert_ne!(
        content_changed.status_porcelain_v2,
        baseline.status_porcelain_v2
    );
    write_file(&omitted_path, "baseline\n")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let original_mode = fs::symlink_metadata(&omitted_path)?.permissions().mode();
        let mut changed_permissions = fs::symlink_metadata(&omitted_path)?.permissions();
        changed_permissions.set_mode(original_mode ^ 0o100);
        fs::set_permissions(&omitted_path, changed_permissions)?;
        let mode_changed = primary_git_snapshot(&repo_path)?;
        assert_ne!(mode_changed.worktree, baseline.worktree);
        assert_ne!(
            mode_changed.status_porcelain_v2,
            baseline.status_porcelain_v2
        );
        let mut original_permissions = fs::symlink_metadata(&omitted_path)?.permissions();
        original_permissions.set_mode(original_mode);
        fs::set_permissions(&omitted_path, original_permissions)?;
    }

    write_file(&omitted_path, "index content changed\n")?;
    let mut index = repo.index()?;
    index.add_path(Path::new("otherwise-omitted.txt"))?;
    index.write()?;
    write_file(&omitted_path, "baseline\n")?;
    let index_changed = primary_git_snapshot(&repo_path)?;
    assert_ne!(index_changed.index_storage, baseline.index_storage);
    assert_ne!(index_changed.index_entries, baseline.index_entries);
    assert_ne!(
        index_changed.status_porcelain_v2,
        baseline.status_porcelain_v2
    );

    let head_fixture_root = temp.path().join("head-fixture");
    fs::create_dir_all(&head_fixture_root)?;
    let head_repo_path = create_committed_repo(&head_fixture_root)?;
    let head_repo = Repository::open(&head_repo_path)?;
    let head_before = primary_git_snapshot(&head_repo_path)?;
    write_file(
        &head_repo_path.join("new-head-tree-entry.txt"),
        "new tree\n",
    )?;
    commit_all(&head_repo, "change head tree")?;
    let head_changed = primary_git_snapshot(&head_repo_path)?;
    assert_ne!(head_changed.head, head_before.head);
    assert_ne!(head_changed.head_tree, head_before.head_tree);

    Ok(())
}

#[test]
fn autopilot_run_without_run_id_generates_finalized_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Update the README through generated autopilot.\n",
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("autopilot-"));
    assert!(repo_path
        .join(".maco/autopilot/runs")
        .join(run_id)
        .join(".maco-artifact-final.json")
        .exists());

    let corrupt_dir = repo_path.join(".maco/autopilot/runs/zz-corrupt");
    fs::create_dir_all(&corrupt_dir).context("create corrupt run dir")?;
    write_file(&corrupt_dir.join("final-report.json"), "{not json")?;
    let listed = run_success_json(&[
        "autopilot",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let runs = listed["runs"].as_array().context("runs")?;
    let corrupt = runs
        .iter()
        .find(|run| run["run_id"] == "zz-corrupt")
        .context("corrupt run")?;
    assert_eq!(corrupt["final_report_exists"], true);
    assert_eq!(corrupt["final_report_status"], "active");
    assert_eq!(corrupt["final_report_readable"], false);
    assert_eq!(corrupt["final_report_corrupt"], false);

    let prune = run_success_json(&[
        "autopilot",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--dry-run",
        "--json",
    ])?;
    assert_eq!(prune["dry_run"], true);
    assert_eq!(prune["deleted_count"], 0);
    assert!(corrupt_dir.exists(), "dry-run prune must not delete");

    Ok(())
}

#[test]
fn autopilot_prune_deletes_only_finalized_runs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    for run_id in ["aa-prune", "zz-prune"] {
        fs::create_dir_all(repo_path.join(".maco/autopilot/runs").join(run_id))
            .with_context(|| format!("create {run_id}"))?;
    }

    let prune = run_success_json(&[
        "autopilot",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["deleted_count"], 0);
    assert_eq!(prune["refused_unfinalized_count"], 1);
    assert!(repo_path.join(".maco/autopilot/runs/aa-prune").exists());
    assert!(repo_path.join(".maco/autopilot/runs/zz-prune").exists());
    Ok(())
}

#[test]
fn fake_autopilot_nonpublishable_run_ignores_local_runtime_state_without_gitignore_entry(
) -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    let readme_before = fs::read_to_string(repo_path.join("README.md")).context("read readme")?;
    let lib_before = fs::read_to_string(repo_path.join("src/lib.rs")).context("read lib")?;
    let task_path = temp.path().join("task.md");
    write_file(
        &task_path,
        "Run fake autopilot when runtime files are not ignored.\n",
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "unignored-runtime",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert_eq!(report["primary_worktree_untouched"], true);

    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        readme_before
    );
    assert_eq!(
        fs::read_to_string(repo_path.join("src/lib.rs")).context("read primary lib")?,
        lib_before
    );

    Ok(())
}

#[test]
fn fake_supervise_flow_completes_and_legacy_pr_review_stays_unreachable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Fake local flow", "body": "Change README only."},
          "assigned_paths": ["README.md"],
          "validation_commands": ["true"]
        }"#,
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "local-flow",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert_eq!(report["validation"]["status"], "skipped");
    assert!(report["pr"].is_null());
    assert!(report["review"].is_null());
    assert_eq!(report["attempts"][0]["publication_attempted"], false);
    assert_eq!(report["attempts"][0]["publication_authorized"], false);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).context("read primary readme")?,
        "# Smoke\n"
    );

    Ok(())
}

#[test]
fn legacy_blocking_review_configuration_cannot_start_an_outer_repair_loop() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("blocking-review.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Repair review", "body": "Exercise fake review repair."},
          "assigned_paths": ["README.md"],
          "max_repair_attempts": 1,
          "reviewer": {
            "mode": "fake",
            "blocking_attempts": 1,
            "finding": {
              "severity": "error",
              "path": "README.md",
              "summary": "first attempt must be repaired",
              "suggested_fix": "rerun once"
            }
          }
        }"#,
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "review-repair",
        "--json",
    ])?;
    assert_eq!(report["attempt_count"], 1);
    assert_eq!(report["repair_attempts_used"], 0);
    assert!(report["attempts"][0]["review_status"].is_null());
    assert_eq!(report["attempts"][0]["blocking_findings"], 0);

    Ok(())
}

#[test]
fn legacy_outer_validation_command_cannot_start_a_repair_loop() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("validation-fails.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "Fail validation", "body": "Validation never passes."},
          "assigned_paths": ["README.md"],
          "max_repair_attempts": 1,
          "validation_commands": [
            {"name": "always fails", "command": "false"}
          ]
        }"#,
    )?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "validation-stop",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert_eq!(report["attempt_count"], 1);
    assert_eq!(report["repair_attempts_used"], 0);
    assert_eq!(report["validation"]["status"], "skipped");
    assert_eq!(report["attempts"][0]["publication_attempted"], false);

    Ok(())
}

#[test]
fn dirty_primary_refusal_emits_public_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo_without_maco_ignore(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Try autopilot with dirty primary.\n")?;
    write_file(&repo_path.join("README.md"), "# Smoke\n\nprimary dirty\n")?;
    write_file(
        &repo_path.join(".maco/autopilot/runs/preexisting/state.json"),
        "{}\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            repo_path.join(".maco/autopilot/runs"),
            fs::Permissions::from_mode(0o700),
        )
        .context("chmod preexisting artifact root")?;
    }
    write_file(&repo_path.join(".maco-cache/preflight/state.json"), "{}\n")?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "dirty",
        "--json",
    ])?;
    assert_eq!(report["status"], "refused");
    assert_eq!(report["safety"]["refused"], true);
    assert_eq!(report["gate_denials"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        report["gate_denials"][0]["reason"]["family"],
        "merge_remediation"
    );
    assert_eq!(
        report["gate_denials"][0]["reason"]["blocker"],
        "dirty_primary"
    );
    assert_eq!(
        report["gate_denials"][0]["context"]["paths"],
        serde_json::json!(["README.md"])
    );
    assert_eq!(report["auto_merge_performed"], false);

    Ok(())
}

#[test]
fn runtime_catalog_failure_composes_typed_environment_failure_without_dispatch() -> Result<()> {
    support::require_containment!(
        "runtime_catalog_failure_composes_typed_environment_failure_without_dispatch"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("catalog-failure.json");
    write_file(
        &task_path,
        r#"{
          "version": 1,
          "task": {"title": "Catalog failure", "body": "Do not dispatch without a catalog."},
          "assigned_paths": ["README.md"]
        }"#,
    )?;
    let repo = Repository::open(&repo_path)?;
    let head_before = repo.head()?.target().context("primary HEAD")?;
    let index_before = fs::read(repo.path().join("index"))?;

    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "typed-catalog-failure",
        "--codex-bin",
        path_str(&temp.path().join("missing-codex"))?,
        "--json",
    ])?;

    assert_eq!(report["status"], "failed");
    assert_eq!(report["supervisor"]["success"], false);
    assert_eq!(
        report["supervisor"]["environment_failures"][0]["category"],
        "runtime_model_catalog_unavailable"
    );
    assert_eq!(report["attempts"][0]["publication_attempted"], false);
    assert_eq!(repo.head()?.target(), Some(head_before));
    assert_eq!(fs::read(repo.path().join("index"))?, index_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn status_and_collect_require_verified_finalization_and_distinguish_active_runs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let missing = run_success_json(&[
        "autopilot",
        "status",
        "absent",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(missing["final_report"].is_null());
    assert_eq!(missing["artifacts"]["plan"], false);
    let missing_collect = run_failure_json(&[
        "autopilot",
        "collect",
        "absent",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(missing_collect["status"], "missing");

    let active_dir = repo_path.join(".maco/autopilot/runs/active");
    fs::create_dir_all(&active_dir).context("create active run")?;
    fs::set_permissions(&active_dir, fs::Permissions::from_mode(0o700))
        .context("chmod active run")?;
    write_file(&active_dir.join("plan.json"), "{}\n")?;
    let active_secret = "autopilot-active-final-report-secret";
    write_file(
        &active_dir.join("final-report.json"),
        &format!("{{malformed:{active_secret}:{}\n", repo_path.display()),
    )?;
    let active = run_success_json(&[
        "autopilot",
        "status",
        "active",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(active["artifacts"]["plan"], true);
    assert_eq!(active["artifacts"]["final_report"], true);
    assert!(active["final_report"].is_null());
    let active_serialized = serde_json::to_string(&active).context("serialize active status")?;
    assert!(!active_serialized.contains(active_secret));
    assert!(!active_serialized.contains(&repo_path.display().to_string()));
    let active_collect = run_failure_stderr(&[
        "autopilot",
        "collect",
        "active",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(active_collect.contains("active or unfinalized"));

    Ok(())
}

#[test]
fn active_sync_claim_is_a_typed_preflight_refusal() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let sync_repo = create_committed_repo(temp.path())?;
    run_success_json(&[
        "sync",
        "claim",
        "other-agent",
        "README.md",
        "--repo",
        path_str(&sync_repo)?,
        "--json",
    ])?;
    let sync_task = temp.path().join("sync-refusal.md");
    write_file(&sync_task, "Refuse autopilot on README.md.\n")?;
    assert_typed_claim_refusal(&sync_repo, &sync_task, "sync-refusal")?;
    Ok(())
}

#[test]
fn active_semantic_intent_is_a_typed_preflight_refusal() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let semantic_repo = create_committed_repo(temp.path())?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-agent",
        "--path",
        "README.md",
        "--repo",
        path_str(&semantic_repo)?,
        "--json",
    ])?;
    let semantic_task = temp.path().join("semantic-refusal.md");
    write_file(&semantic_task, "Refuse autopilot on README.md.\n")?;
    assert_typed_claim_refusal(&semantic_repo, &semantic_task, "semantic-refusal")?;
    Ok(())
}

#[test]
fn active_live_lock_is_a_typed_preflight_refusal() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let live_repo = create_committed_repo(temp.path())?;
    write_live_claim(&live_repo, "active-live", "active", "README.md")?;
    let live_task = temp.path().join("live-refusal.md");
    write_file(&live_task, "Refuse autopilot on README.md.\n")?;
    assert_typed_claim_refusal(&live_repo, &live_task, "live-refusal")?;
    Ok(())
}

#[test]
fn non_overlapping_locks_do_not_refuse_nonpublishable_fake_autopilot() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "sync",
        "claim",
        "other-agent",
        "src/lib.rs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    run_success_json(&[
        "coord",
        "claim",
        "semantic-agent",
        "--path",
        "src/lib.rs",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    write_live_claim(&repo_path, "active-live", "active", "src/lib.rs")?;
    commit_all(
        &Repository::open(&repo_path)?,
        "track non-overlapping live claim",
    )?;

    let task_path = temp.path().join("readme-task.md");
    write_file(&task_path, "Update README.md through fake autopilot.\n")?;
    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "non-overlap",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert_eq!(report["safety"]["refused"], false);
    assert!(report["gate_denials"].as_array().is_some_and(Vec::is_empty));

    Ok(())
}

#[test]
fn auto_merge_request_is_recorded_but_never_performed() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("auto-merge.json");
    write_file(
        &plan_path,
        r#"{
          "version": 1,
          "task": {"title": "No auto merge", "body": "Record but do not merge."},
          "assigned_paths": ["README.md"],
          "auto_merge": true
        }"#,
    )?;
    let repo = Repository::open(&repo_path)?;
    let head_before = repo.head()?.target().context("primary HEAD")?;
    let index_before = fs::read(repo.path().join("index"))?;
    let readme_before = fs::read(repo_path.join("README.md"))?;
    let lib_before = fs::read(repo_path.join("src/lib.rs"))?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "no-auto-merge",
        "--json",
    ])?;
    assert_eq!(report["auto_merge_requested"], true);
    assert_eq!(report["auto_merge_performed"], false);
    assert_eq!(report["attempts"][0]["publication_attempted"], false);
    assert_eq!(report["generated_follow_up_dispatch_performed"], false);
    assert_eq!(repo.head()?.target(), Some(head_before));
    assert_eq!(fs::read(repo.path().join("index"))?, index_before);
    assert_eq!(fs::read(repo_path.join("README.md"))?, readme_before);
    assert_eq!(fs::read(repo_path.join("src/lib.rs"))?, lib_before);

    Ok(())
}

#[test]
fn public_json_shape_is_stable_and_sanitized() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    write_file(&task_path, "Check public shape.\n")?;

    let report = run_success_json(&[
        "autopilot",
        "run",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "shape",
        "--json",
    ])?;
    assert_eq!(report["supervisor"]["runtime"], "fake");
    assert!(report["supervisor"]["role_economics_profile"].is_object());
    assert_eq!(
        report["supervisor"]["autonomy_kpis"]["observation"],
        "supervisor_aggregate"
    );
    assert_eq!(
        report["supervisor"]["environment_failures"],
        serde_json::json!([])
    );
    assert_eq!(report["gate_denials"], serde_json::json!([]));
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains(&repo_path.display().to_string()));

    let review = run_success_json(&[
        "review",
        "pr",
        "123",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(review["target"], "#123");
    assert_eq!(review["status"], "passed");
    assert_eq!(review["ci_reaction_supported"], false);

    Ok(())
}

fn assert_typed_claim_refusal(repo: &Path, task: &Path, run_id: &str) -> Result<()> {
    let report = run_failure_json(&[
        "autopilot",
        "run",
        path_str(task)?,
        "--repo",
        path_str(repo)?,
        "--run-id",
        run_id,
        "--json",
    ])?;
    assert_eq!(report["status"], "refused");
    assert_eq!(report["safety"]["refused"], true);
    assert_eq!(report["gate_denials"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        report["gate_denials"][0]["reason"]["family"],
        "claim_conflict"
    );
    assert_eq!(
        report["gate_denials"][0]["context"]["paths"],
        serde_json::json!(["README.md"])
    );
    Ok(())
}

fn assert_depth_permission_expansion_refusal(report: &Value) {
    assert_eq!(report["status"], "refused");
    assert_eq!(report["success"], false);
    assert_eq!(report["attempt_count"], 0);
    assert!(report["supervisor"].is_null());
    assert_eq!(report["safety"]["refused"], true);
    assert_eq!(report["gate_denials"].as_array().map(Vec::len), Some(1));
    let denial = &report["gate_denials"][0];
    assert_eq!(denial["reason"]["family"], "approval_review");
    assert_eq!(denial["reason"]["denial"], "permission_expansion");
    assert_eq!(denial["retryability"], "retry_after_correction");
    assert_eq!(denial["context"]["source"], "future_approval_review");
    assert_eq!(denial["route"], "child_controller");
    assert_eq!(
        denial["next_safe_operation"],
        "narrow_action_or_choose_another_tool"
    );
}

fn write_live_claim(repo: &Path, claim_id: &str, status: &str, path: &str) -> Result<()> {
    let claims_dir = repo.join(".agents/live/claims");
    fs::create_dir_all(&claims_dir).context("create live claims")?;
    write_file(
        &claims_dir.join(format!("{claim_id}.md")),
        &format!(
            r#"# Claim: {claim_id}

- Claim ID: `{claim_id}`
- Owner: `worker-a`
- Status: `{status}`
- Created: `2026-05-20T00:00:00Z`
- Updated: `2026-05-20T00:00:00Z`
- Heartbeat: `2026-05-20T00:00:00Z`
- Stale after minutes: `60`
- Owned files, regions, devices, or services:
  - `{path}`: test
"#
        ),
    )
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(args)?
        .output()
        .context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            command_failure_diagnostics(args, &output)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse json")
}

fn command_failure_diagnostics(args: &[&str], output: &Output) -> String {
    let repo = option_value(args, "--repo").map(Path::new);
    let mut detail = format!(
        "status={}; stdout={}; stderr={}",
        output.status,
        bounded_diagnostic(&output.stdout, repo),
        bounded_diagnostic(&output.stderr, repo)
    );
    let public_run_id = serde_json::from_slice::<Value>(&output.stdout)
        .ok()
        .and_then(|report| report["run_id"].as_str().map(str::to_string));
    let run_id = option_value(args, "--run-id")
        .map(str::to_string)
        .or(public_run_id);
    let Some((repo, run_id)) = repo.zip(run_id) else {
        return detail;
    };
    if Path::new(&run_id)
        .file_name()
        .and_then(|name| name.to_str())
        != Some(run_id.as_str())
    {
        detail.push_str("; artifacts=<unsafe or unavailable run id>");
        return detail;
    }
    let nested_id = format!("{run_id}-supervise");
    let paths = [
        PathBuf::from(format!(
            ".maco/autopilot/runs/{run_id}/supervisor-report.json"
        )),
        PathBuf::from(format!(".maco/autopilot/runs/{run_id}/final-report.json")),
        PathBuf::from(format!(
            ".maco/o2/runs/{nested_id}/reports/supervisor-final.json"
        )),
        PathBuf::from(format!(
            ".git/maco/state/orchestration-checkpoints-v3/{nested_id}/.head.json"
        )),
    ];
    for path in paths {
        detail.push_str("; ");
        detail.push_str(&artifact_diagnostic(repo, &path));
    }
    detail
}

fn option_value<'a>(args: &'a [&str], option: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == option).then_some(pair[1]))
}

fn artifact_diagnostic(repo: &Path, relative: &Path) -> String {
    match fs::read(repo.join(relative)) {
        Ok(bytes) => format!(
            "{} exists=true readable=true content={}",
            relative.display(),
            bounded_diagnostic(&bytes, Some(repo))
        ),
        Err(error) => format!(
            "{} exists={} readable=false reason={}",
            relative.display(),
            error.kind() != std::io::ErrorKind::NotFound,
            error.kind()
        ),
    }
}

fn bounded_diagnostic(bytes: &[u8], repo: Option<&Path>) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if let Some(repo) = repo {
        for root in [Some(repo), repo.parent()].into_iter().flatten() {
            text = text.replace(root.to_string_lossy().as_ref(), "<private-root>");
        }
    }
    let mut bounded = text
        .chars()
        .take(COMMAND_DIAGNOSTIC_LIMIT_CHARS)
        .collect::<String>();
    if text.chars().count() > COMMAND_DIAGNOSTIC_LIMIT_CHARS {
        bounded.push_str("...<truncated>");
    }
    bounded
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(args)?
        .output()
        .context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse failure json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_failure_stderr(args: &[&str]) -> Result<String> {
    let output = command_with_test_machine_global_binding(args)?
        .output()
        .context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

fn command_with_test_machine_global_binding(args: &[&str]) -> Result<Command> {
    let repo = args
        .windows(2)
        .find_map(|pair| (pair[0] == "--repo").then_some(Path::new(pair[1])));
    let mut command = match repo {
        Some(repo) => command_with_test_fixture_environment(repo)?,
        None => Command::new(BIN),
    };
    command.args(args);
    if args.first() == Some(&"autopilot") && args.get(1) == Some(&"run") {
        let repo = repo.context("autopilot run test command must name --repo")?;
        let config = write_test_machine_global_config(repo)?;
        command
            .arg("--machine-global-config")
            .arg(config)
            .args(["--machine-global-runtime-root-id", "runtime"]);
    }
    Ok(command)
}

fn command_with_test_fixture_environment(repo: &Path) -> Result<Command> {
    let child_tmpdir = test_child_tmpdir(repo)?;
    let mut command = Command::new(BIN);
    command
        .env("TMPDIR", child_tmpdir)
        .env_remove(BOUNDED_STATUS_RUNTIME_ROOT_ENV);
    Ok(command)
}

fn command_environment_path(command: &Command, name: &str) -> Result<PathBuf> {
    command
        .get_envs()
        .find_map(|(candidate, value)| {
            (candidate == std::ffi::OsStr::new(name)).then(|| value.map(PathBuf::from))
        })
        .flatten()
        .with_context(|| format!("test command must set {name}"))
}

fn test_child_tmpdir(repo: &Path) -> Result<PathBuf> {
    let fixture_root = repo.parent().context("test repository parent")?;
    let child_tmpdir = fixture_root.join(TEST_CHILD_TMPDIR_NAME);
    match fs::create_dir(&child_tmpdir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create child TMPDIR"),
    }
    let metadata = fs::symlink_metadata(&child_tmpdir).context("inspect child TMPDIR type")?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "child TMPDIR must be a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&child_tmpdir, fs::Permissions::from_mode(0o700))
            .context("make child TMPDIR private")?;
    }
    Ok(child_tmpdir)
}

#[cfg(target_os = "linux")]
fn write_test_machine_global_config(repo: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture_root = repo.parent().context("test repository parent")?;
    let state_root = fixture_root.join("autopilot-machine-global-state");
    fs::create_dir_all(&state_root)?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))?;
    let uid = fs::metadata("/proc/self")?.uid();
    let runtime_root = PathBuf::from(format!("/run/user/{uid}"));
    let config = test_machine_global_config_path(repo)?;
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

fn test_machine_global_config_path(repo: &Path) -> Result<PathBuf> {
    Ok(repo
        .parent()
        .context("test repository parent")?
        .join("autopilot-machine-global.json"))
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, ".maco/\n")
}

fn create_committed_repo_without_maco_ignore(root: &Path) -> Result<std::path::PathBuf> {
    create_committed_repo_with_gitignore(root, "# intentionally no maco runtime ignores\n")
}

fn create_committed_repo_with_gitignore(
    root: &Path,
    gitignore_contents: &str,
) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = command_with_test_fixture_environment(&repo_path)?
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    write_file(&repo_path.join(".gitignore"), gitignore_contents)?;
    write_file(&repo_path.join("README.md"), "# Smoke\n")?;
    write_file(
        &repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let mut config = repo.config().context("repo config")?;
    config
        .set_str("user.name", "maco test")
        .context("set user name")?;
    config
        .set_str("user.email", "maco-test@example.invalid")
        .context("set user email")?;
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

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}

#[derive(Debug, PartialEq, Eq)]
struct PrimaryGitSnapshot {
    head: PrimaryHeadSnapshot,
    head_tree: Vec<u8>,
    index_storage: Vec<u8>,
    index_entries: Vec<u8>,
    worktree: BTreeMap<Vec<u8>, TrackedWorktreePathSnapshot>,
    status_porcelain_v2: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct PrimaryHeadSnapshot {
    detached: bool,
    reference_name: Option<Vec<u8>>,
    symbolic_target: Option<Vec<u8>>,
    target: Option<Oid>,
}

#[derive(Debug, PartialEq, Eq)]
enum TrackedWorktreePathSnapshot {
    Missing,
    File { mode: u32, id: Oid },
    Symlink { mode: u32, target: PathBuf },
    Directory { mode: u32 },
    Other { mode: u32 },
}

fn primary_git_snapshot(repo_path: &Path) -> Result<PrimaryGitSnapshot> {
    let repo = Repository::open(repo_path).context("open primary snapshot repository")?;
    let reference = repo.head().context("capture primary HEAD")?;
    let head = PrimaryHeadSnapshot {
        detached: repo
            .head_detached()
            .context("capture detached HEAD state")?,
        reference_name: Some(reference.name_bytes().to_vec()),
        symbolic_target: reference.symbolic_target_bytes().map(<[u8]>::to_vec),
        target: reference.target(),
    };
    let head_tree = primary_git_stdout(
        repo_path,
        &["ls-tree", "-r", "-t", "-z", "--full-tree", "HEAD"],
        "HEAD tree",
    )?;
    let head_paths = primary_git_stdout(
        repo_path,
        &["ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD"],
        "HEAD paths",
    )?;
    let index_entries = primary_git_stdout(
        repo_path,
        &["ls-files", "--stage", "-v", "-z", "--sparse"],
        "index entries",
    )?;
    let index_paths = primary_git_stdout(
        repo_path,
        &["ls-files", "--cached", "-z", "--sparse"],
        "index paths",
    )?;
    let status_porcelain_v2 = primary_git_stdout(
        repo_path,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--branch",
            "--untracked-files=all",
            "--ignored=no",
            "--ignore-submodules=none",
        ],
        "porcelain-v2 status",
    )?;
    let index_storage = fs::read(repo.path().join("index")).context("read exact index storage")?;

    let mut tracked_paths = BTreeSet::new();
    for output in [&head_paths, &index_paths] {
        tracked_paths.extend(
            output
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .map(<[u8]>::to_vec),
        );
    }
    let mut worktree = BTreeMap::new();
    for raw_path in tracked_paths {
        let relative_path = path_from_git_bytes(&raw_path)?;
        let absolute_path = repo_path.join(&relative_path);
        let state = match fs::symlink_metadata(&absolute_path) {
            Ok(metadata) => {
                let mode = primary_snapshot_mode(&metadata);
                let file_type = metadata.file_type();
                if file_type.is_symlink() {
                    TrackedWorktreePathSnapshot::Symlink {
                        mode,
                        target: fs::read_link(&absolute_path).with_context(|| {
                            format!("read tracked symlink {}", relative_path.display())
                        })?,
                    }
                } else if file_type.is_file() {
                    TrackedWorktreePathSnapshot::File {
                        mode,
                        id: Oid::hash_file(ObjectType::Blob, &absolute_path).with_context(
                            || format!("hash tracked file {}", relative_path.display()),
                        )?,
                    }
                } else if file_type.is_dir() {
                    TrackedWorktreePathSnapshot::Directory { mode }
                } else {
                    TrackedWorktreePathSnapshot::Other { mode }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                TrackedWorktreePathSnapshot::Missing
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect tracked path {}", relative_path.display()));
            }
        };
        worktree.insert(raw_path, state);
    }

    Ok(PrimaryGitSnapshot {
        head,
        head_tree,
        index_storage,
        index_entries,
        worktree,
        status_porcelain_v2,
    })
}

fn primary_git_stdout(repo_path: &Path, args: &[&str], label: &str) -> Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .current_dir(repo_path)
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
        ])
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    ] {
        command.env_remove(variable);
    }
    let output = command
        .output()
        .with_context(|| format!("capture primary {label}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "primary {label} capture failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(unix)]
fn path_from_git_bytes(path: &[u8]) -> Result<PathBuf> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    Ok(PathBuf::from(OsStr::from_bytes(path)))
}

#[cfg(not(unix))]
fn path_from_git_bytes(path: &[u8]) -> Result<PathBuf> {
    Ok(PathBuf::from(std::str::from_utf8(path).context(
        "tracked Git path is not UTF-8 on this platform",
    )?))
}

#[cfg(unix)]
fn primary_snapshot_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;

    metadata.mode()
}

#[cfg(not(unix))]
fn primary_snapshot_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}
