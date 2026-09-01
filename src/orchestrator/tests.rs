use super::*;
use crate::semantic_coord::{
    SemanticConflictKind, SemanticConflictSeverity, SemanticIntentRequest, SemanticIntentStore,
};
use crate::sync_store::SyncStore;
use crate::worktree::WorktreeManager;
use git2::{Oid, Repository, Signature};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn collect_status_paths_fails_closed_on_non_utf8_path() -> Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let temp = tempfile::tempdir()?;
    let repository = Repository::init(temp.path())?;
    fs::write(
        temp.path()
            .join(OsString::from_vec(vec![b'n', b'o', b'n', 0xff])),
        b"untracked",
    )?;

    let error = collect_status_paths(&repository).expect_err("non-UTF-8 status must fail");
    assert!(error
        .to_string()
        .contains("git status path is not valid UTF-8"));
    Ok(())
}

fn run_plan_file(options: OrchestrationRunOptions) -> Result<OrchestrationSummary> {
    super::run_plan_file_simulation(options)
}

fn run_plan_file_with_controls(
    options: OrchestrationRunOptions,
    controls: OrchestrationRunControls,
) -> Result<OrchestrationSummary> {
    super::run_plan_file_with_controls_simulation(options, controls)
}

fn resume_plan_file(options: OrchestrationResumeOptions) -> Result<OrchestrationSummary> {
    super::resume_plan_file_simulation(options)
}

fn test_candidate_binding(worktree_path: &Path, base_oid: Oid) -> AgentCandidateBinding {
    let state = capture_consistent_candidate_state(
        worktree_path,
        &base_oid,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture test candidate state");
    capture_bound_candidate(
        worktree_path,
        &base_oid,
        &state,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture test candidate")
    .binding
}

fn schedule_test_agent(id: &str, depends_on: &[&str]) -> AgentPlan {
    AgentPlan {
        id: id.to_string(),
        paths: vec![PathBuf::from(format!("{id}.txt"))],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        env: BTreeMap::new(),
        timeout: None,
        command: "true".to_string(),
        depends_on: depends_on.iter().map(|value| value.to_string()).collect(),
        working_directory: None,
        validation_commands: Vec::new(),
    }
}

fn schedule_test_plan(agents: Vec<AgentPlan>) -> OrchestrationPlan {
    OrchestrationPlan {
        agents,
        repo_validation_commands: Vec::new(),
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
    }
}

fn run_candidate_validation_test(command: &str) -> ValidationRunSummary {
    run_candidate_validation_test_with_setup(command, |_| {})
}

fn run_candidate_validation_test_with_setup(
    command: &str,
    setup: impl FnOnce(&Path),
) -> ValidationRunSummary {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    SyncStore::open(&repo_path).expect("create sensitive state root");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("claimed.txt"), "base\n").expect("write claimed");
    fs::write(repo_path.join("other.txt"), "base\n").expect("write other");
    let base_oid = commit_all(&repo, "initial commit").expect("commit");
    fs::write(repo_path.join("claimed.txt"), "candidate\n").expect("write candidate");
    setup(&repo_path);
    let expected = capture_consistent_candidate_state(
        &repo_path,
        &base_oid,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture expected candidate");
    let validation = ValidationCommandPlan {
        name: Some("binding check".to_string()),
        command: command.to_string(),
        env: BTreeMap::new(),
        timeout: Some(Duration::from_secs(5)),
        working_directory: None,
    };
    run_candidate_bound_validation_command(
        &validation,
        &repo_path,
        &base_oid,
        &expected,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
        || Ok(()),
    )
    .0
}

fn clone_candidate(
    source: &Path,
    destination: &Path,
    base_oid: Oid,
    relative_path: Option<&str>,
    contents: &str,
) -> CapturedCandidate {
    Repository::clone(source.to_str().expect("source path utf8"), destination)
        .expect("clone candidate");
    if let Some(relative_path) = relative_path {
        fs::write(destination.join(relative_path), contents).expect("write candidate change");
    }
    let state = capture_consistent_candidate_state(
        destination,
        &base_oid,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture cloned candidate state");
    capture_bound_candidate(
        destination,
        &base_oid,
        &state,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture cloned candidate")
}

#[cfg(unix)]
fn wait_for_test_marker(path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn load_plan_normalizes_agent_ids_and_paths() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "agents": [
                {
                  "id": " agent-a ",
                  "paths": ["src/../README.md", "src"],
                  "command": " echo ok "
                }
              ]
            }"#,
    )
    .expect("write plan");

    let plan = load_plan(&plan_path).expect("load plan");

    assert_eq!(plan.agents[0].id, "agent-a");
    assert_eq!(
        plan.agents[0].paths,
        vec![PathBuf::from("README.md"), PathBuf::from("src")]
    );
    assert_eq!(plan.agents[0].command, "echo ok");
}

#[test]
fn load_plan_rejects_agent_count_before_candidate_worktree_creation() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    let agents = (0..=COMBINED_CANDIDATE_MAX_PATCHES)
        .map(|index| {
            serde_json::json!({
                "id": format!("agent-{index}"),
                "paths": [format!("file-{index}.txt")],
                "command": "true"
            })
        })
        .collect::<Vec<_>>();
    fs::write(
        &plan_path,
        serde_json::to_vec(&serde_json::json!({"agents": agents})).expect("encode plan"),
    )
    .expect("write plan");

    let error = load_plan(&plan_path).expect_err("oversized plan must fail at load");
    assert!(error.to_string().contains("256 agent limit"));
}

#[test]
fn load_plan_bounds_validation_commands_and_dependency_edges() {
    let temp = TempDir::new().expect("tempdir");
    let validation_plan = temp.path().join("validation-plan.json");
    let validations = (0..=PLAN_MAX_VALIDATION_COMMANDS_PER_SCOPE)
        .map(|_| serde_json::Value::String("true".to_string()))
        .collect::<Vec<_>>();
    fs::write(
        &validation_plan,
        serde_json::to_vec(&serde_json::json!({
            "repo_validation_commands": validations,
            "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true"}]
        }))
        .expect("encode validation plan"),
    )
    .expect("write validation plan");
    assert!(load_plan(&validation_plan)
        .expect_err("validation count must be bounded")
        .to_string()
        .contains("128 command limit"));

    let dependency_plan = temp.path().join("dependency-plan.json");
    let agents = (0..100)
        .map(|index| {
            let dependencies = (0..index)
                .map(|dependency| format!("agent-{dependency}"))
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": format!("agent-{index}"),
                "paths": [format!("file-{index}.txt")],
                "command": "true",
                "depends_on": dependencies
            })
        })
        .collect::<Vec<_>>();
    fs::write(
        &dependency_plan,
        serde_json::to_vec(&serde_json::json!({"agents": agents})).expect("encode dependency plan"),
    )
    .expect("write dependency plan");
    assert!(load_plan(&dependency_plan)
        .expect_err("dependency edge count must be bounded")
        .to_string()
        .contains("4096 dependency-edge limit"));
}

#[cfg(unix)]
#[test]
fn load_plan_refuses_symlink_leaf_and_ancestor_components() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let real = temp.path().join("real");
    fs::create_dir(&real).expect("create real directory");
    let plan = real.join("plan.json");
    fs::write(
        &plan,
        r#"{"agents":[{"id":"agent-a","paths":["a.txt"],"command":"true"}]}"#,
    )
    .expect("write plan");
    let leaf_link = temp.path().join("plan-link.json");
    symlink(&plan, &leaf_link).expect("link plan leaf");
    let leaf_error = load_plan(&leaf_link).expect_err("plan leaf symlink must fail");
    assert!(format!("{leaf_error:#}").contains("without following links"));

    let ancestor_link = temp.path().join("linked-directory");
    symlink(&real, &ancestor_link).expect("link plan ancestor");
    let ancestor_error =
        load_plan(ancestor_link.join("plan.json")).expect_err("plan ancestor symlink must fail");
    assert!(format!("{ancestor_error:#}").contains("without following links"));
}

#[test]
fn load_plan_bounds_file_env_and_timeout_before_execution() {
    let temp = TempDir::new().expect("tempdir");
    let oversized = temp.path().join("oversized.json");
    fs::write(&oversized, vec![b' '; PLAN_MAX_BYTES + 1]).expect("write oversized plan");
    let oversized_error = load_plan(&oversized).expect_err("oversized plan must fail bounded read");
    assert!(format!("{oversized_error:#}").contains("bounded read limit"));

    let env_plan = temp.path().join("env.json");
    let env = (0..=PLAN_MAX_ENV_ENTRIES_PER_SCOPE)
        .map(|index| (format!("KEY_{index}"), "value".to_string()))
        .collect::<BTreeMap<_, _>>();
    fs::write(
        &env_plan,
        serde_json::to_vec(&serde_json::json!({
            "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true", "env": env}]
        }))
        .expect("encode env plan"),
    )
    .expect("write env plan");
    assert!(load_plan(&env_plan)
        .expect_err("nested env count must be bounded")
        .to_string()
        .contains("environment scope"));

    let timeout_plan = temp.path().join("timeout.json");
    fs::write(
        &timeout_plan,
        serde_json::to_vec(&serde_json::json!({
            "default_timeout_seconds": PLAN_MAX_TIMEOUT_SECONDS + 1,
            "agents": [{"id": "agent-a", "paths": ["a.txt"], "command": "true"}]
        }))
        .expect("encode timeout plan"),
    )
    .expect("write timeout plan");
    assert!(load_plan(&timeout_plan)
        .expect_err("timeout upper bound must be enforced")
        .to_string()
        .contains("must be between 1"));
}

#[test]
fn scheduler_failure_propagation_preserves_independent_fork_and_join_branch() {
    let plan = schedule_test_plan(vec![
        schedule_test_agent("root-fail", &[]),
        schedule_test_agent("failed-child", &["root-fail"]),
        schedule_test_agent("root-ok", &[]),
        schedule_test_agent("ok-child", &["root-ok"]),
        schedule_test_agent("join", &["failed-child", "ok-child"]),
    ]);
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();
    let mut remaining = (0..summaries.len()).collect::<BTreeSet<_>>();

    assert_eq!(
        ready_agent_indices(&plan, &summaries, &remaining, 2),
        vec![0, 2]
    );
    summaries[0].status = AgentRunStatus::Failed;
    summaries[2].status = AgentRunStatus::Succeeded;
    remaining.remove(&0);
    remaining.remove(&2);
    propagate_dependency_failures(&plan, &mut summaries, &mut remaining);

    assert_eq!(summaries[1].status, AgentRunStatus::Skipped);
    assert_eq!(summaries[4].status, AgentRunStatus::Skipped);
    assert_eq!(summaries[3].status, AgentRunStatus::Pending);
    assert_eq!(
        ready_agent_indices(&plan, &summaries, &remaining, 2),
        vec![3]
    );
    assert!(summaries[1]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("'root-fail' (failed)")));
    assert!(summaries[4]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("'failed-child' (skipped)")));
}

#[test]
fn scheduler_reports_all_same_wave_failed_dependencies_deterministically() {
    let plan = schedule_test_plan(vec![
        schedule_test_agent("fail-a", &[]),
        schedule_test_agent("fail-b", &[]),
        schedule_test_agent("dependent", &["fail-a", "fail-b"]),
        schedule_test_agent("independent", &[]),
    ]);
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();
    summaries[0].status = AgentRunStatus::Failed;
    summaries[1].status = AgentRunStatus::Failed;
    let mut remaining = BTreeSet::from([2, 3]);

    propagate_dependency_failures(&plan, &mut summaries, &mut remaining);

    assert_eq!(summaries[2].status, AgentRunStatus::Skipped);
    assert_eq!(summaries[3].status, AgentRunStatus::Pending);
    assert_eq!(
        summaries[2].error.as_deref(),
        Some("skipped because dependencies did not succeed: 'fail-a' (failed), 'fail-b' (failed)")
    );
    assert_eq!(
        ready_agent_indices(&plan, &summaries, &remaining, 4),
        vec![3]
    );
}

#[test]
fn scheduler_accepts_successful_checkpoint_summary_as_dependency() {
    let plan = schedule_test_plan(vec![
        schedule_test_agent("completed", &[]),
        schedule_test_agent("pending-dependent", &["completed"]),
    ]);
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();
    summaries[0].status = AgentRunStatus::Succeeded;
    let remaining = BTreeSet::from([1]);

    assert_eq!(
        ready_agent_indices(&plan, &summaries, &remaining, 1),
        vec![1]
    );
}

#[test]
fn resume_claim_failure_isolated_to_its_dependency_branch() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let store = SyncStore::open(&repo_path).expect("open sync store");
    let blocker = store
        .claim_paths("external-blocker", ["blocked.txt"])
        .expect("create blocking claim");
    let mut blocked = schedule_test_agent("blocked", &[]);
    blocked.paths = vec![PathBuf::from("blocked.txt")];
    let mut independent = schedule_test_agent("independent", &[]);
    independent.paths = vec![PathBuf::from("independent.txt")];
    let plan = schedule_test_plan(vec![blocked, independent]);
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();

    let acquired = acquire_resume_claims(&store, &plan, &mut summaries);

    assert_eq!(summaries[0].status, AgentRunStatus::Failed);
    assert_eq!(summaries[1].status, AgentRunStatus::Pending);
    assert_eq!(acquired.len(), 1);
    store.release(acquired[0]).expect("release acquired claim");
    store.release(blocker.token).expect("release blocker");
}

#[test]
fn agent_validation_rejects_within_claim_content_mutation() {
    let summary = run_candidate_validation_test("printf 'changed\\n' > claimed.txt");
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(summary
        .error
        .as_deref()
        .is_some_and(|error| error.contains("tracked worktree content")));
}

#[test]
fn agent_validation_rejects_unclaimed_untracked_mutation() {
    let summary = run_candidate_validation_test("printf 'new\\n' > unclaimed.txt");
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(summary.error.as_deref().is_some_and(|error| {
        error.contains("untracked content") && error.contains("changed paths/status")
    }));
}

#[cfg(unix)]
#[test]
fn agent_validation_rejects_untracked_executable_mode_mutation() {
    let summary = run_candidate_validation_test_with_setup("chmod 755 scratch.sh", |repo_path| {
        fs::write(repo_path.join("scratch.sh"), "#!/bin/sh\n").expect("write untracked script");
        fs::set_permissions(
            repo_path.join("scratch.sh"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("set initial untracked mode");
    });
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(
        summary
            .error
            .as_deref()
            .is_some_and(|error| error.contains("untracked content")),
        "{:?}",
        summary.error
    );
}

#[test]
fn agent_validation_rejects_head_mutation() {
    let summary = run_candidate_validation_test(
            "git -c user.name=test -c user.email=test@example.invalid -c core.hooksPath=/dev/null commit --allow-empty -m validation",
        );
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(summary
        .error
        .as_deref()
        .is_some_and(|error| error.contains("HEAD")));
}

#[test]
fn agent_validation_rejects_index_only_mutation() {
    let summary = run_candidate_validation_test("git add -- claimed.txt");
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(summary
        .error
        .as_deref()
        .is_some_and(|error| error.contains("index")));
}

#[test]
fn agent_validation_accepts_exactly_unchanged_candidate() {
    let summary = run_candidate_validation_test("true");
    assert_eq!(summary.status, AgentRunStatus::Succeeded);
    assert!(summary.error.is_none());
}

#[test]
fn repo_validation_materializes_exact_combined_candidate_and_not_primary() {
    let temp = TempDir::new().expect("tempdir");
    let primary = temp.path().join("primary");
    WorktreeManager::init_repository(&primary, "main").expect("init primary");
    let repo = crate::git_repository::open(&primary).expect("open primary");
    fs::write(primary.join("a.txt"), "base-a\n").expect("write a");
    fs::write(primary.join("b.txt"), "base-b\n").expect("write b");
    let base_oid = commit_all(&repo, "initial commit").expect("commit");
    let candidate_a = clone_candidate(
        &primary,
        &temp.path().join("candidate-a"),
        base_oid,
        Some("a.txt"),
        "candidate-a\n",
    );
    let candidate_b = clone_candidate(
        &primary,
        &temp.path().join("candidate-b"),
        base_oid,
        Some("b.txt"),
        "candidate-b\n",
    );
    let mut agent_a = schedule_test_agent("agent-a", &[]);
    agent_a.paths = vec![PathBuf::from("a.txt")];
    let mut agent_b = schedule_test_agent("agent-b", &[]);
    agent_b.paths = vec![PathBuf::from("b.txt")];
    let plan = schedule_test_plan(vec![agent_a, agent_b]);
    let candidates = vec![Some(candidate_a), Some(candidate_b)];
    let stats = validate_combined_candidate_set(&plan, &candidates, &base_oid)
        .expect("validate candidate union");
    let validation_path = temp.path().join("validation");
    let validation_repo =
        Repository::clone(primary.to_str().expect("primary utf8"), &validation_path)
            .expect("clone validation target");
    SyncStore::open(&validation_path).expect("create validation sensitive state root");
    let index_path = validation_repo.path().join("index");
    let index_before = fs::read(&index_path).expect("read validation index before apply");

    apply_captured_candidate_patches(
        &plan,
        &validation_path,
        &candidates,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
        || Ok(()),
    )
    .expect("apply exact union");
    assert_eq!(
        fs::read(&index_path).expect("read validation index after apply"),
        index_before,
        "combined materialization must not write shared Git administration"
    );
    let combined_state = capture_consistent_candidate_state(
        &validation_path,
        &base_oid,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture combined state");
    let combined = capture_bound_candidate(
        &validation_path,
        &base_oid,
        &combined_state,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture combined candidate");
    let target = repo_validation_target_binding(&stats, &base_oid, &combined);
    let validation = ValidationCommandPlan {
        name: Some("combined content".to_string()),
        command: "test \"$(cat a.txt)\" = candidate-a && test \"$(cat b.txt)\" = candidate-b"
            .to_string(),
        env: BTreeMap::new(),
        timeout: Some(Duration::from_secs(5)),
        working_directory: None,
    };
    let (summary, intact) = run_candidate_bound_validation_command(
        &validation,
        &validation_path,
        &base_oid,
        &combined_state,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
        || Ok(()),
    );

    assert!(intact);
    assert_eq!(summary.status, AgentRunStatus::Succeeded);
    assert_eq!(target.kind, RepoValidationTargetKind::CombinedCandidate);
    assert_eq!(
        target.changed_paths,
        vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
    );
    assert_eq!(
        fs::read_to_string(primary.join("a.txt")).expect("read primary a"),
        "base-a\n"
    );
    assert_eq!(
        fs::read_to_string(primary.join("b.txt")).expect("read primary b"),
        "base-b\n"
    );
    let serialized = serde_json::to_string(&target).expect("serialize target");
    assert!(!serialized.contains(temp.path().to_str().expect("temp utf8")));
}

#[test]
fn repo_validation_zero_change_target_is_explicit() {
    let temp = TempDir::new().expect("tempdir");
    let primary = temp.path().join("primary");
    WorktreeManager::init_repository(&primary, "main").expect("init primary");
    let repo = crate::git_repository::open(&primary).expect("open primary");
    fs::write(primary.join("README.md"), "base\n").expect("write readme");
    let base_oid = commit_all(&repo, "initial commit").expect("commit");
    let candidate = clone_candidate(&primary, &temp.path().join("candidate"), base_oid, None, "");
    let plan = schedule_test_plan(vec![schedule_test_agent("agent-a", &[])]);
    let candidates = vec![Some(candidate)];
    let stats = validate_combined_candidate_set(&plan, &candidates, &base_oid)
        .expect("validate zero-change set");
    let target = repo_validation_target_binding(
        &stats,
        &base_oid,
        candidates[0].as_ref().expect("candidate"),
    );

    assert_eq!(target.kind, RepoValidationTargetKind::BaseNoChanges);
    assert_eq!(target.candidate_count, 1);
    assert_eq!(target.patch_count, 0);
    assert_eq!(target.aggregate_patch_bytes, 0);
    assert!(target.changed_paths.is_empty());
}

#[test]
fn combined_candidate_rejects_duplicate_patch_paths_before_materialization() {
    let temp = TempDir::new().expect("tempdir");
    let primary = temp.path().join("primary");
    WorktreeManager::init_repository(&primary, "main").expect("init primary");
    let repo = crate::git_repository::open(&primary).expect("open primary");
    fs::write(primary.join("shared.txt"), "base\n").expect("write shared");
    let base_oid = commit_all(&repo, "initial commit").expect("commit");
    let first = clone_candidate(
        &primary,
        &temp.path().join("first"),
        base_oid,
        Some("shared.txt"),
        "first\n",
    );
    let second = clone_candidate(
        &primary,
        &temp.path().join("second"),
        base_oid,
        Some("shared.txt"),
        "second\n",
    );
    let mut first_agent = schedule_test_agent("first", &[]);
    first_agent.paths = vec![PathBuf::from("shared.txt")];
    let mut second_agent = schedule_test_agent("second", &[]);
    second_agent.paths = vec![PathBuf::from("shared.txt")];
    let plan = schedule_test_plan(vec![first_agent, second_agent]);

    let error = validate_combined_candidate_set(&plan, &[Some(first), Some(second)], &base_oid)
        .expect_err("duplicate candidate path must fail closed");
    assert!(error
        .to_string()
        .contains("duplicate changed path 'shared.txt'"));
}

#[test]
fn repo_validation_mutation_never_preserves_a_success_status() {
    let summary = run_candidate_validation_test("printf 'repo mutation\\n' > claimed.txt");
    assert_eq!(summary.status, AgentRunStatus::Failed);
    assert!(summary
        .error
        .as_deref()
        .is_some_and(|error| { error.contains("candidate-relevant state changed") }));
}

#[test]
fn load_plan_accepts_dependencies_env_working_directory_and_timeout() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "default_timeout_seconds": 30,
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {
                  "id": "agent-b",
                  "paths": ["README.md"],
                  "depends_on": ["agent-a"],
                  "working_directory": "src",
                  "env": {"MACO_TEST": "ok"},
                  "timeout_seconds": 5,
                  "command": "echo b"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let plan = load_plan(&plan_path).expect("load plan");

    assert_eq!(plan.agents[0].timeout, Some(Duration::from_secs(30)));
    assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Clean);
    assert!(plan.repo_validation_commands.is_empty());
    assert!(plan.agents[0].validation_commands.is_empty());
    assert_eq!(plan.agents[1].depends_on, vec!["agent-a"]);
    assert_eq!(plan.agents[1].working_directory, Some(PathBuf::from("src")));
    assert_eq!(
        plan.agents[1].env.get("MACO_TEST").map(String::as_str),
        Some("ok")
    );
    assert_eq!(plan.agents[1].timeout, Some(Duration::from_secs(5)));
}

#[test]
fn load_plan_accepts_validation_commands_and_reuse_policy() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "worktree_reuse_policy": "required",
              "repo_validation_commands": [
                "cargo fmt -- --check",
                {
                  "name": "unit tests",
                  "command": "cargo test",
                  "working_directory": "src",
                  "env": {"RUST_BACKTRACE": "1"},
                  "timeout_seconds": 20
                }
              ],
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["src"],
                  "command": "true",
                  "validation_commands": [
                    {"name": "agent check", "command": "cargo check", "timeout_seconds": 10}
                  ]
                }
              ]
            }"#,
    )
    .expect("write plan");

    let plan = load_plan(&plan_path).expect("load plan");

    assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Required);
    assert_eq!(plan.repo_validation_commands.len(), 2);
    assert_eq!(
        plan.repo_validation_commands[1].working_directory,
        Some(PathBuf::from("src"))
    );
    assert_eq!(
        plan.repo_validation_commands[1]
            .env
            .get("RUST_BACKTRACE")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        plan.agents[0].validation_commands[0].timeout,
        Some(Duration::from_secs(10))
    );
}

#[test]
fn worktree_reuse_policy_defaults_and_accepts_reset_policy() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"true"}]}"#,
    )
    .expect("write plan");
    let plan = load_plan(&plan_path).expect("load plan");
    assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Clean);

    fs::write(
            &plan_path,
            r#"{"worktree_reuse_policy":"reset","agents":[{"id":"agent-a","paths":["src"],"command":"true"}]}"#,
        )
        .expect("write reset plan");
    let plan = load_plan(&plan_path).expect("load reset plan");
    assert_eq!(plan.worktree_reuse_policy, WorktreeReusePolicy::Reset);
}

#[test]
fn load_plan_rejects_invalid_completion_criteria() {
    let cases = [
        (
            r#"{"agents":[]}"#,
            "orchestration plan must include at least one agent",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":[],"command":"echo a"}]}"#,
            "path claims cannot be empty",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"   "}]}"#,
            "command cannot be empty",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["/tmp"],"command":"echo a"}]}"#,
            "repository-relative",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["../src"],"command":"echo a"}]}"#,
            "escape repository",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"},{"id":"agent-a","paths":["README.md"],"command":"echo b"}]}"#,
            "duplicate agent id",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-missing"]}]}"#,
            "depends on unknown agent",
        ),
        (
            r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-a"]}]}"#,
            "cannot depend on itself",
        ),
        (
            r#"{"default_timeout_seconds":0,"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"}]}"#,
            "default timeout",
        ),
    ];

    for (contents, expected) in cases {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(&plan_path, contents).expect("write plan");

        let error = load_plan(&plan_path).expect_err("plan should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains(expected),
            "expected '{expected}' in '{rendered}'"
        );
    }
}

#[test]
fn load_plan_rejects_dependency_cycles() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
            &plan_path,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a", "depends_on": ["agent-b"]},
                {"id": "agent-b", "paths": ["README.md"], "command": "echo b", "depends_on": ["agent-a"]}
              ]
            }"#,
        )
        .expect("write plan");

    let error = load_plan(&plan_path).expect_err("cycle should fail");

    assert!(error.to_string().contains("dependency cycle"));
}

#[test]
fn load_plan_rejects_overlapping_agent_paths() {
    let temp = TempDir::new().expect("tempdir");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {"id": "agent-b", "paths": ["src/lib.rs"], "command": "echo b"}
              ]
            }"#,
    )
    .expect("write plan");

    let error = load_plan(&plan_path).expect_err("overlap should fail");

    assert!(error.to_string().contains("overlaps"));
}

#[test]
fn run_plan_creates_worktree_runs_command_and_releases_claims() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["src"],
                  "command": "git rev-parse --is-inside-work-tree"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.agents[0].stdout.text.trim(), "true");
    assert_eq!(summary.released_claims.len(), 1);
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
    let released = WorktreeManager::new(&repo_path)
        .acquire_write_execution_lease("agent-a")
        .expect("successful run releases write lease");
    drop(released);
}

#[cfg(unix)]
#[test]
fn mid_batch_setup_failure_does_not_spawn_earlier_agents() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");
    let marker = temp.path().join("agent-a-ran");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "paths": ["a.txt"],
                    "command": format!("printf ran > '{}'; sleep 30", marker.display())
                },
                {
                    "id": "agent-b",
                    "paths": ["b.txt"],
                    "command": "true"
                }
            ]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");

    set_ready_agent_setup_fault("agent-b");
    let error = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 2,
        patch_dir: None,
    })
    .expect_err("later setup failure must abort the batch");
    assert!(error
        .to_string()
        .contains("injected ready-agent setup failure"));
    assert!(
        !marker.exists(),
        "pre-validation must stop earlier agents from spawning"
    );
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
}

#[cfg(unix)]
#[test]
fn mid_batch_post_spawn_failure_joins_already_spawned_agents_before_return() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");
    let marker = temp.path().join("agent-a-ran");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "paths": ["a.txt"],
                    "command": format!("printf ran > '{}'", marker.display())
                },
                {
                    "id": "agent-b",
                    "paths": ["b.txt"],
                    "command": "true"
                }
            ]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");

    set_ready_agent_post_spawn_fault("agent-a");
    let error = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 2,
        patch_dir: None,
    })
    .expect_err("post-spawn setup failure must abort after joining");
    assert!(error
        .to_string()
        .contains("injected ready-agent post-spawn setup failure"));
    assert!(
        marker.exists(),
        "already-spawned agent must run to completion while its claims are still held"
    );
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
}

#[cfg(unix)]
#[test]
fn orchestration_holds_write_lease_through_child_validation_and_finalization() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    commit_all(&repo, "initial commit").expect("commit");
    let manager = WorktreeManager::new(&repo_path);
    manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-a worktree");
    let unrelated = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-b worktree");

    let child_ready = temp.path().join("child-ready");
    let child_release = temp.path().join("child-release");
    let validation_ready = temp.path().join("validation-ready");
    let validation_release = temp.path().join("validation-release");
    let child_command = format!(
        "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
        child_ready.display(),
        child_release.display()
    );
    let validation_command = format!(
        "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
        validation_ready.display(),
        validation_release.display()
    );
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "worktree_reuse_policy": "required",
            "agents": [{
                "id": "agent-a",
                "paths": ["README.md"],
                "command": child_command,
                "validation_commands": [validation_command]
            }]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");
    let run_repo = repo_path.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let runner = thread::spawn(move || {
        let result = run_plan_file(OrchestrationRunOptions {
            repo: run_repo,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        });
        done_tx.send(()).expect("signal runner return");
        result
    });

    wait_for_test_marker(&child_ready);
    let child_writer_blocked = manager.acquire_write_execution_lease("agent-a").is_err();
    let child_removal = manager.remove("agent-a", true, false);
    let unrelated_during_child = manager
        .acquire_write_execution_lease("agent-b")
        .map(|lease| lease.path().to_path_buf());
    fs::write(&child_release, "release\n").expect("release child");

    wait_for_test_marker(&validation_ready);
    let validation_writer_blocked = manager.acquire_write_execution_lease("agent-a").is_err();
    let validation_removal = manager.remove("agent-a", true, false);
    let unrelated_during_validation = manager
        .acquire_write_execution_lease("agent-b")
        .map(|lease| lease.path().to_path_buf());
    assert!(
        done_rx.try_recv().is_err(),
        "run returned before final release"
    );
    fs::write(&validation_release, "release\n").expect("release validation");

    let summary = runner.join().expect("join runner").expect("run plan");
    assert!(summary.success);
    assert!(child_writer_blocked);
    assert!(child_removal.is_err());
    assert_eq!(
        unrelated_during_child
            .expect("unrelated writer during child")
            .as_path(),
        unrelated.path
    );
    assert!(validation_writer_blocked);
    assert!(validation_removal.is_err());
    assert_eq!(
        unrelated_during_validation
            .expect("unrelated writer during validation")
            .as_path(),
        unrelated.path
    );
    let released = manager
        .acquire_write_execution_lease("agent-a")
        .expect("orchestration releases write lease after finalization");
    drop(released);
    let removed = manager
        .remove("agent-a", true, false)
        .expect("orchestration releases removal authority after finalization");
    assert!(!removed.path.exists());
}

#[cfg(unix)]
#[test]
fn orchestration_created_lane_removal_deletes_its_authenticated_branch() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "agents": [{
                "id": "orchestrated-delete",
                "paths": ["README.md"],
                "command": "true"
            }]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run orchestration");
    assert!(summary.success);

    let manager = WorktreeManager::new(&repo_path);
    let removed = manager
        .remove("orchestrated-delete", true, true)
        .expect("remove orchestration-created lane and branch");

    assert!(!removed.path.exists());
    assert!(repo
        .find_branch("maco/orchestrated-delete", git2::BranchType::Local)
        .is_err());
    assert!(manager.list().expect("list after removal").is_empty());
}

#[cfg(unix)]
#[test]
fn orchestration_releases_write_lease_after_timeout() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [{
                "id": "agent-timeout",
                "paths": ["README.md"],
                "command": "sleep 5",
                "timeout_seconds": 1
              }]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run timeout plan");
    assert!(!summary.success);
    assert!(summary.agents[0].timed_out);
    let manager = WorktreeManager::new(&repo_path);
    let released = manager
        .acquire_write_execution_lease("agent-timeout")
        .expect("timeout releases write lease");
    drop(released);
    let removed = manager
        .remove("agent-timeout", true, false)
        .expect("timeout releases removal authority");
    assert!(!removed.path.exists());
}

#[cfg(unix)]
#[test]
fn redirected_git_marker_fails_before_candidate_open_and_holds_lease_through_refusal() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let manager = WorktreeManager::new(&repo_path);
    let record = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "git-marker-redirect".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    let original_marker = fs::read(record.path.join(".git")).expect("read marker");
    let foreign_path = temp.path().join("foreign");
    WorktreeManager::init_repository(&foreign_path, "main").expect("init foreign");
    fs::write(foreign_path.join("sentinel"), "untouched\n").expect("write sentinel");
    let command = format!(
        "printf 'gitdir: %s\\n' '{}' > .git",
        foreign_path.join(".git").display()
    );
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec(&serde_json::json!({
            "worktree_reuse_policy": "required",
            "agents": [{
                "id": "git-marker-redirect",
                "paths": ["README.md"],
                "command": command
            }]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");
    let (reached, release) = install_candidate_boundary_failure_hook("git-marker-redirect");
    let run_repo = repo_path.clone();
    let runner = thread::spawn(move || {
        run_plan_file(OrchestrationRunOptions {
            repo: run_repo,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
    });

    reached
        .recv_timeout(Duration::from_secs(10))
        .expect("candidate boundary failure hook");
    let competing_lease = manager.acquire_write_execution_lease("git-marker-redirect");
    let competing_removal = manager.remove("git-marker-redirect", true, false);
    release.send(()).expect("release refusal hook");
    assert!(competing_lease.is_err());
    assert!(competing_removal.is_err());
    let summary = runner.join().expect("join runner").expect("run summary");

    assert!(!summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
    assert!(summary.agents[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("managed worktree binding is invalid")));
    assert!(summary.agents[0].candidate_binding.is_none());
    assert!(summary.agents[0].patch_path.is_none());
    assert_eq!(
        fs::read_to_string(foreign_path.join("sentinel")).expect("read sentinel"),
        "untouched\n"
    );

    fs::write(record.path.join(".git"), original_marker).expect("restore marker");
    manager
        .get_managed_verified("git-marker-redirect")
        .expect("restored binding");
    manager
        .remove("git-marker-redirect", true, true)
        .expect("remove restored worktree");
}

#[test]
fn run_plan_reports_failed_command_and_releases_claims() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "false"}
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.first_failed_agent(), Some("agent-a"));
    assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
    let manager = WorktreeManager::new(&repo_path);
    let released = manager
        .acquire_write_execution_lease("agent-a")
        .expect("failed command releases write lease");
    drop(released);
    let removed = manager
        .remove("agent-a", true, false)
        .expect("failed command releases removal authority");
    assert!(!removed.path.exists());
}

#[test]
fn run_plan_reports_claim_conflict_as_summary() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    SyncStore::open(&repo_path)
        .expect("open store")
        .claim_paths("other-agent", ["README.md"])
        .expect("preclaim");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.first_failed_agent(), Some("agent-a"));
    assert!(summary.agents[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("failed to claim paths"));
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .owner_of("README.md")
            .expect("owner")
            .owner,
        Some("other-agent".to_string())
    );
}

#[test]
fn semantic_coordination_warn_compares_against_planned_preview_intents_without_persisting() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
    fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 2,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: None,
            checkpoint_dir: None,
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Warn,
        },
    )
    .expect("run plan");

    assert!(summary.success);
    assert_eq!(
        summary.semantic_coordination,
        SemanticCoordinationMode::Warn
    );
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert!(summary.agents[0].semantic_conflicts.is_empty());
    assert_eq!(
        summary.agents[0]
            .semantic_intent
            .as_ref()
            .map(|intent| intent.token.get()),
        Some(1)
    );
    assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
    assert_eq!(
        summary.agents[1]
            .semantic_intent
            .as_ref()
            .map(|intent| intent.token.get()),
        Some(2)
    );
    assert!(summary.agents[1].semantic_conflicts.iter().any(|conflict| {
        conflict.severity == SemanticConflictSeverity::Blocking
            && conflict.kind == SemanticConflictKind::SymbolOverlap
            && conflict.active_agent_id.as_deref() == Some("agent-a")
    }));
    assert!(summary.released_semantic_intents.is_empty());
    assert_eq!(
        SemanticIntentStore::open(&repo_path)
            .expect("open semantic store")
            .status()
            .expect("semantic status"),
        Vec::new()
    );
}

#[test]
fn semantic_coordination_block_reports_overlapping_symbols() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
    fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "true"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 2,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: None,
            checkpoint_dir: None,
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Block,
        },
    )
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(
        summary.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert_eq!(summary.first_failed_agent(), Some("agent-b"));
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.agents[1].status, AgentRunStatus::Failed);
    assert!(summary.agents[1].semantic_conflicts.iter().any(
        |conflict| conflict.kind == crate::semantic_coord::SemanticConflictKind::SymbolOverlap
    ));
    assert_eq!(summary.released_semantic_intents.len(), 1);
    assert_eq!(
        SemanticIntentStore::open(&repo_path)
            .expect("open semantic store")
            .status()
            .expect("semantic status"),
        Vec::new()
    );
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
}

#[test]
fn semantic_coordination_block_unresolved_symbol_fails_summary_and_releases_claims() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Existing;\n").expect("write lib");
    fs::write(repo_path.join("owned.txt"), "owned\n").expect("write owned");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["owned.txt"],
                  "semantic_symbols": ["MissingSymbol"],
                  "command": "true"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: None,
            checkpoint_dir: None,
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Block,
        },
    )
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.first_failed_agent(), Some("agent-a"));
    assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
    let error = summary.agents[0].error.as_deref().unwrap_or_default();
    assert!(error.contains("unresolved semantic symbol"));
    assert!(error.contains("MissingSymbol"));
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
    assert_eq!(
        SemanticIntentStore::open(&repo_path)
            .expect("open semantic store")
            .snapshot()
            .expect("semantic snapshot"),
        Vec::new()
    );
}

#[test]
fn semantic_coordination_block_allows_disjoint_intents() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\n",
    )
    .expect("write lib");
    fs::write(repo_path.join("a.txt"), "a\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "b\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Alpha"],
                  "command": "true"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Beta"],
                  "command": "true"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 2,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: None,
            checkpoint_dir: None,
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Block,
        },
    )
    .expect("run plan");

    assert!(summary.success);
    assert_eq!(
        summary.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
    assert!(summary.agents.iter().all(|agent| agent
        .semantic_intent
        .as_ref()
        .is_some_and(|intent| !intent.symbols.is_empty())));
    assert_eq!(summary.released_semantic_intents.len(), 2);
    assert_eq!(
        SemanticIntentStore::open(&repo_path)
            .expect("open semantic store")
            .status()
            .expect("semantic status"),
        Vec::new()
    );
}

#[test]
fn run_plan_reports_unclaimed_changes_and_releases_claims() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    fs::write(repo_path.join("Cargo.toml"), "[package]\n").expect("write cargo");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf 'changed\n' > Cargo.toml"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path.clone(),
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.first_failed_agent(), Some("agent-a"));
    assert_eq!(
        summary.agents[0].unclaimed_changed_paths,
        vec![PathBuf::from("Cargo.toml")]
    );
    assert_eq!(
        SyncStore::open(&repo_path)
            .expect("open store")
            .snapshot()
            .expect("snapshot"),
        Vec::<PathClaim>::new()
    );
}

#[test]
fn run_plan_writes_patch_for_claimed_changes() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let patch_dir = temp.path().join("patches");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf '# Changed\n' > README.md"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: Some(patch_dir.clone()),
    })
    .expect("run plan");

    assert!(summary.success);
    assert_eq!(
        summary.agents[0].changed_paths,
        vec![PathBuf::from("README.md")]
    );
    assert_eq!(
        summary.agents[0].patch_path,
        Some(patch_dir.join("agent-a.patch"))
    );
    let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).expect("read patch");
    assert!(patch.contains("# Changed"));
}

#[test]
fn run_plan_times_out_and_skips_dependents() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "timeout_seconds": 1,
                  "command": "sleep 5"
                },
                {
                  "id": "agent-b",
                  "paths": ["src"],
                  "depends_on": ["agent-a"],
                  "command": "echo should-not-run"
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 2,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
    assert!(summary.agents[0].timed_out);
    assert_eq!(summary.agents[1].status, AgentRunStatus::Skipped);
}

#[test]
fn agent_validation_failure_is_reported_with_bounded_output() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "true",
                  "validation_commands": [
                    {"name": "check", "command": "printf 'validation failed' >&2; false"}
                  ]
                }
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
    assert_eq!(summary.agents[0].validation.len(), 1);
    assert_eq!(
        summary.agents[0].validation[0].status,
        AgentRunStatus::Failed
    );
    assert_eq!(
        summary.agents[0].validation[0].stderr.text,
        "validation failed"
    );
    assert!(!summary.agents[0].validation[0].stderr.truncated);
    assert!(summary.agents[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("agent validation 'check' failed"));
}

#[test]
fn repo_validation_failure_is_reported_in_summary() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "repo_validation_commands": [
                {"name": "repo check", "command": "printf 'repo failed' >&2; false"}
              ],
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(!summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.repo_validation.len(), 1);
    assert_eq!(summary.repo_validation[0].status, AgentRunStatus::Failed);
    assert_eq!(summary.repo_validation[0].stderr.text, "repo failed");
}

#[test]
fn resume_skips_completed_agent_and_runs_pending_dependent() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");

    let manager = WorktreeManager::new(&repo_path);
    let agent_a_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-a worktree");
    let agent_b_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-b worktree");
    fs::write(agent_a_worktree.path.join("a.txt"), "done\n").expect("write agent a output");

    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "command": "printf 'rerun\n' >> a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "depends_on": ["agent-a"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
    )
    .expect("write plan");
    let plan = load_plan(&plan_file).expect("load plan");
    let store = SyncStore::open(&repo_path).expect("open store");
    let claim_a = store
        .claim_paths("agent-a", ["a.txt"])
        .expect("claim agent a");
    let claim_b = store
        .claim_paths("agent-b", ["b.txt"])
        .expect("claim agent b");
    let base_oid = current_head_oid(&repo_path).expect("head");
    let agent_a_binding = test_candidate_binding(&agent_a_worktree.path, base_oid);
    let run_id = RunId::new("resume-skip").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::ClaimsAcquired,
        repo: repo_path.clone(),
        repo_head: Some(base_oid.to_string()),
        plan_file: plan_file.clone(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: vec![
            AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Succeeded,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                claim: Some(claim_a),
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: vec![PathBuf::from("a.txt")],
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: Some(agent_a_binding),
                command_completed_binding: None,
                error: None,
            },
            AgentCheckpoint {
                id: "agent-b".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                claim: Some(claim_b),
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            },
        ],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_file =
        write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

    let summary = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume");

    assert!(summary.success);
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.agents[1].status, AgentRunStatus::Succeeded);
    assert_eq!(
        fs::read_to_string(agent_a_worktree.path.join("a.txt")).expect("read a"),
        "done\n"
    );
    assert_eq!(
        fs::read_to_string(agent_b_worktree.path.join("b.txt")).expect("read b"),
        "done\n"
    );
    assert_eq!(store.snapshot().expect("snapshot"), Vec::<PathClaim>::new());
    let final_checkpoint =
        read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
    assert_eq!(final_checkpoint.stage, RunCheckpointStage::Final);
    assert!(final_checkpoint.success);
}

#[cfg(unix)]
#[test]
fn resume_reacquires_fresh_write_lease_and_releases_it_on_every_return() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    commit_all(&repo, "initial commit").expect("commit");
    let manager = WorktreeManager::new(&repo_path);
    let worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-resume".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create resume worktree");

    let ready = temp.path().join("resume-ready");
    let release = temp.path().join("resume-release");
    let command = format!(
        "printf ready > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done",
        ready.display(),
        release.display()
    );
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "agents": [{
                "id": "agent-resume",
                "paths": ["README.md"],
                "command": command
            }]
        }))
        .expect("encode plan"),
    )
    .expect("write plan");
    let plan = load_plan(&plan_file).expect("load plan");
    let run_id = RunId::new("resume-write-lease").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path.clone(),
        repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
        plan_file: plan_file.clone(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: vec![AgentCheckpoint {
            id: "agent-resume".to_string(),
            status: AgentRunStatus::Pending,
            worktree: Some(CheckpointWorktreeRecord::from(&worktree)),
            claim: None,
            semantic_intent: None,
            semantic_conflicts: Vec::new(),
            changed_paths: Vec::new(),
            unclaimed_changed_paths: Vec::new(),
            validation: Vec::new(),
            candidate_binding: None,
            command_completed_binding: None,
            error: None,
        }],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_file =
        write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
    let run_checkpoint = checkpoint_file.clone();
    let run_repo = repo_path.clone();
    let run_plan = plan_file.clone();
    let runner = thread::spawn(move || {
        resume_plan_file(OrchestrationResumeOptions {
            checkpoint_file: run_checkpoint,
            repo: Some(run_repo),
            plan_file: Some(run_plan),
            jobs: 1,
            patch_dir: None,
        })
    });

    wait_for_test_marker(&ready);
    let writer_blocked = manager
        .acquire_write_execution_lease("agent-resume")
        .is_err();
    let removal_blocked = manager.remove("agent-resume", true, false).is_err();
    fs::write(&release, "release\n").expect("release resume command");
    let summary = runner.join().expect("join resume").expect("resume plan");
    assert!(summary.success);
    assert!(writer_blocked);
    assert!(removal_blocked);

    let external_writer = manager
        .acquire_write_execution_lease("agent-resume")
        .expect("first resume released its write lease");
    let reacquire_error = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file: checkpoint_file.clone(),
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file.clone()),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("each resume must reacquire instead of reusing a stale handle");
    assert!(reacquire_error
        .to_string()
        .contains("could not reacquire the exclusive execution lease"));
    drop(external_writer);

    let replay = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume final checkpoint after releasing external writer");
    assert!(replay.success);
    let released = manager
        .acquire_write_execution_lease("agent-resume")
        .expect("final checkpoint resume releases its reacquired lease");
    drop(released);
    let removed = manager
        .remove("agent-resume", true, false)
        .expect("resume releases removal authority");
    assert!(!removed.path.exists());
}

#[test]
fn resume_preserves_and_releases_checkpoint_semantic_intents() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\n",
    )
    .expect("write lib");
    fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");

    let manager = WorktreeManager::new(&repo_path);
    let agent_a_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-a worktree");
    let agent_b_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-b worktree");
    fs::write(agent_a_worktree.path.join("a.txt"), "done\n").expect("write agent a output");

    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Alpha"],
                  "command": "printf 'rerun\n' >> a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Beta"],
                  "depends_on": ["agent-a"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
    )
    .expect("write plan");
    let plan = load_plan(&plan_file).expect("load plan");
    let store = SyncStore::open(&repo_path).expect("open store");
    let claim_a = store
        .claim_paths("agent-a", ["a.txt"])
        .expect("claim agent a");
    let claim_b = store
        .claim_paths("agent-b", ["b.txt"])
        .expect("claim agent b");
    let semantic_store = SemanticIntentStore::open(&repo_path).expect("open semantic store");
    let semantic_a = semantic_store
        .claim(SemanticIntentRequest {
            agent_id: "agent-a".to_string(),
            paths: vec![PathBuf::from("a.txt")],
            symbols: vec!["Alpha".to_string()],
            modules: Vec::new(),
            task_file: None,
            notes: Vec::new(),
        })
        .expect("claim semantic a");
    let semantic_b = semantic_store
        .claim(SemanticIntentRequest {
            agent_id: "agent-b".to_string(),
            paths: vec![PathBuf::from("b.txt")],
            symbols: vec!["Beta".to_string()],
            modules: Vec::new(),
            task_file: None,
            notes: Vec::new(),
        })
        .expect("claim semantic b");
    let base_oid = current_head_oid(&repo_path).expect("head");
    let agent_a_binding = test_candidate_binding(&agent_a_worktree.path, base_oid);
    let run_id = RunId::new("resume-semantic").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::ClaimsAcquired,
        repo: repo_path.clone(),
        repo_head: Some(base_oid.to_string()),
        plan_file: plan_file.clone(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Block,
        success: false,
        agents: vec![
            AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Succeeded,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                claim: Some(claim_a),
                semantic_intent: Some(semantic_a.intent.clone()),
                semantic_conflicts: semantic_a.conflicts.clone(),
                changed_paths: vec![PathBuf::from("a.txt")],
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: Some(agent_a_binding),
                command_completed_binding: None,
                error: None,
            },
            AgentCheckpoint {
                id: "agent-b".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                claim: Some(claim_b),
                semantic_intent: Some(semantic_b.intent.clone()),
                semantic_conflicts: semantic_b.conflicts.clone(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            },
        ],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_file =
        write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

    let summary = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume");

    assert!(summary.success);
    assert_eq!(
        summary.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert!(summary
        .agents
        .iter()
        .all(|agent| agent.semantic_intent.is_some()));
    assert_eq!(summary.released_semantic_intents.len(), 2);
    assert!(summary.semantic_release_errors.is_empty());
    assert_eq!(
        semantic_store.status().expect("semantic status"),
        Vec::new()
    );
    let final_checkpoint =
        read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
    assert_eq!(
        final_checkpoint.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert_eq!(final_checkpoint.released_semantic_intents.len(), 2);
    assert!(final_checkpoint.semantic_release_errors.is_empty());
}

#[test]
fn resume_runs_missing_semantic_coordination_before_pending_agents() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n").expect("write lib");
    fs::write(repo_path.join("a.txt"), "start\n").expect("write a");
    fs::write(repo_path.join("b.txt"), "start\n").expect("write b");
    commit_all(&repo, "initial commit").expect("commit");

    let manager = WorktreeManager::new(&repo_path);
    let agent_a_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-a worktree");
    let agent_b_worktree = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-b worktree");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["a.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "printf 'done\n' > a.txt"
                },
                {
                  "id": "agent-b",
                  "paths": ["b.txt"],
                  "semantic_symbols": ["Shared"],
                  "command": "printf 'done\n' > b.txt"
                }
              ]
            }"#,
    )
    .expect("write plan");
    let plan = load_plan(&plan_file).expect("load plan");
    let store = SyncStore::open(&repo_path).expect("open store");
    let claim_a = store
        .claim_paths("agent-a", ["a.txt"])
        .expect("claim agent a");
    let claim_b = store
        .claim_paths("agent-b", ["b.txt"])
        .expect("claim agent b");
    let run_id = RunId::new("resume-semantic-missing").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::ClaimsAcquired,
        repo: repo_path.clone(),
        repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
        plan_file: plan_file.clone(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Block,
        success: false,
        agents: vec![
            AgentCheckpoint {
                id: "agent-a".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_a_worktree)),
                claim: Some(claim_a),
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            },
            AgentCheckpoint {
                id: "agent-b".to_string(),
                status: AgentRunStatus::Pending,
                worktree: Some(CheckpointWorktreeRecord::from(&agent_b_worktree)),
                claim: Some(claim_b),
                semantic_intent: None,
                semantic_conflicts: Vec::new(),
                changed_paths: Vec::new(),
                unclaimed_changed_paths: Vec::new(),
                validation: Vec::new(),
                candidate_binding: None,
                command_completed_binding: None,
                error: None,
            },
        ],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_file =
        write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");

    let summary = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume");

    assert!(!summary.success);
    assert_eq!(
        summary.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert_eq!(summary.first_failed_agent(), Some("agent-b"));
    assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
    assert_eq!(summary.agents[1].status, AgentRunStatus::Failed);
    assert_eq!(summary.released_semantic_intents.len(), 1);
    assert_eq!(
        SemanticIntentStore::open(&repo_path)
            .expect("open semantic store")
            .status()
            .expect("semantic status"),
        Vec::new()
    );
    let final_checkpoint =
        read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
    assert_eq!(final_checkpoint.stage, RunCheckpointStage::Final);
    assert_eq!(
        final_checkpoint.semantic_coordination,
        SemanticCoordinationMode::Block
    );
    assert_eq!(final_checkpoint.released_semantic_intents.len(), 1);
}

#[test]
fn resume_refuses_changed_plan_snapshot() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"true"}]}"#,
    )
    .expect("write plan");
    let plan = load_plan(&plan_file).expect("load plan");
    let run_id = RunId::new("changed-plan").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id,
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path.clone(),
        repo_head: Some(current_head_oid(&repo_path).expect("head").to_string()),
        plan_file: plan_file.clone(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(&plan)),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: vec![AgentCheckpoint {
            id: "agent-a".to_string(),
            status: AgentRunStatus::Pending,
            worktree: Some(CheckpointWorktreeRecord::from(&worktree)),
            claim: None,
            semantic_intent: None,
            semantic_conflicts: Vec::new(),
            changed_paths: Vec::new(),
            unclaimed_changed_paths: Vec::new(),
            validation: Vec::new(),
            candidate_binding: None,
            command_completed_binding: None,
            error: None,
        }],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_file =
        write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
    fs::write(
        &plan_file,
        r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"false"}]}"#,
    )
    .expect("rewrite plan");

    let error = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("resume should reject changed plan");

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn reuse_reset_moves_clean_stale_worktree_to_current_head() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# v1\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    fs::write(repo_path.join("README.md"), "# v2\n").expect("update readme");
    let current_head = commit_all(&repo, "advance primary").expect("commit update");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "grep '# v2' README.md"}
              ]
            }"#,
    )
    .expect("write plan");

    let summary = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect("run plan");

    assert!(summary.success);
    assert!(summary.agents[0].worktree_reused);
    let worktree_repo = crate::git_repository::open(worktree.path).expect("open worktree");
    assert_eq!(
        head_oid(&worktree_repo).expect("worktree head"),
        current_head
    );
}

#[test]
fn reuse_reset_refuses_dirty_worktree() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    fs::write(worktree.path.join("scratch.txt"), "untracked\n").expect("write untracked");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
    )
    .expect("write plan");

    let error = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("reset should refuse dirty worktree");

    assert!(error.to_string().contains("dirty or untracked"));
}

#[test]
fn reuse_reset_refuses_active_claims() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    SyncStore::open(&repo_path)
        .expect("open store")
        .claim_paths("agent-a", ["README.md"])
        .expect("claim");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "worktree_reuse_policy": "reset",
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "true"}
              ]
            }"#,
    )
    .expect("write plan");

    let error = run_plan_file(OrchestrationRunOptions {
        repo: repo_path,
        plan_file,
        keep_claims: false,
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("reset should refuse active claim");

    assert!(error.to_string().contains("active claim"));
}

#[test]
fn completed_command_recovery_never_reruns_and_raii_cleans_faults() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Recovery;\n")
        .expect("write semantic source");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{
              "agents": [{
                "id": "recover-once",
                "paths": ["README.md"],
                "semantic_symbols": ["Recovery"],
                "command": "printf 'once\\n' >> README.md"
              }]
            }"#,
    )
    .expect("write plan");
    let run_id = RunId::new("completed-recovery-raii").expect("run id");
    install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
    let first = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file: plan_file.clone(),
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Block,
        },
    )
    .expect_err("inject post-command structural failure");
    assert!(first
        .to_string()
        .contains("injected checkpoint event failure"));
    assert!(SyncStore::open(&repo_path)
        .expect("sync store")
        .snapshot()
        .expect("claims")
        .is_empty());
    assert!(SemanticIntentStore::open(&repo_path)
        .expect("semantic store")
        .snapshot()
        .expect("semantic intents")
        .is_empty());
    let worktree = WorktreeManager::new(&repo_path)
        .list()
        .expect("list worktrees")
        .into_iter()
        .find(|record| record.name == "recover-once")
        .expect("recovery worktree");
    assert_eq!(
        fs::read_to_string(worktree.path.join("README.md"))
            .expect("read command output")
            .matches("once\n")
            .count(),
        1
    );

    let checkpoint_file = checkpoint_path(&checkpoint_dir, &run_id);
    install_checkpoint_event_failure(run_id.as_str(), PHASE_REPO_VALIDATION_STARTED);
    let second = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file: checkpoint_file.clone(),
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file.clone()),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("inject resume structural failure");
    assert!(second
        .to_string()
        .contains("injected checkpoint event failure"));
    assert!(SyncStore::open(&repo_path)
        .expect("sync store")
        .snapshot()
        .expect("claims")
        .is_empty());
    assert_eq!(
        fs::read_to_string(worktree.path.join("README.md"))
            .expect("read recovered output")
            .matches("once\n")
            .count(),
        1
    );

    let summary = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume exact completed state");
    assert!(summary.success);
    assert_eq!(
        fs::read_to_string(worktree.path.join("README.md"))
            .expect("read final output")
            .matches("once\n")
            .count(),
        1,
        "resume reran a command whose exact completed state was journaled"
    );
}

#[cfg(unix)]
#[test]
fn resume_rejects_untracked_executable_mode_drift_after_command_completion() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
            &plan_file,
            r#"{"agents":[{"id":"mode-drift","paths":["scratch.sh"],"command":"printf '#!/bin/sh\\n' > scratch.sh; chmod 644 scratch.sh"}]}"#,
        )
        .expect("write plan");
    let run_id = RunId::new("resume-untracked-mode-drift").expect("run id");
    install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
    run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file: plan_file.clone(),
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        },
    )
    .expect_err("stop after durable command completion");
    let worktree = WorktreeManager::new(&repo_path)
        .list()
        .expect("list worktrees")
        .into_iter()
        .find(|record| record.name == "mode-drift")
        .expect("mode-drift worktree");
    fs::set_permissions(
        worktree.path.join("scratch.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("change executable mode");

    let error = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file: checkpoint_path(&checkpoint_dir, &run_id),
        repo: Some(repo_path),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("mode-only drift must invalidate authenticated binding");
    assert!(error.to_string().contains("command state binding drifted"));
}

#[test]
fn started_only_checkpoint_is_uncertain_and_never_runs_or_retries() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
            &plan_file,
            r#"{"agents":[{"id":"uncertain","paths":["README.md"],"command":"printf 'ran\\n' >> README.md"}]}"#,
        )
        .expect("write plan");
    let run_id = RunId::new("started-only-uncertain").expect("run id");
    install_checkpoint_event_failure(run_id.as_str(), &format!("after:{PHASE_COMMAND_STARTED}"));
    run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file: plan_file.clone(),
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        },
    )
    .expect_err("inject crash after command_started");
    let worktree = WorktreeManager::new(&repo_path)
        .list()
        .expect("list worktrees")
        .into_iter()
        .find(|record| record.name == "uncertain")
        .expect("uncertain worktree");
    assert_eq!(
        fs::read_to_string(worktree.path.join("README.md")).expect("read worktree"),
        "base\n"
    );
    let error = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file: checkpoint_path(&checkpoint_dir, &run_id),
        repo: Some(repo_path),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("started-only resume must fail closed");
    assert!(error.to_string().contains("execution outcome is uncertain"));
}

#[cfg(unix)]
#[test]
fn authenticated_checkpoint_reference_tamper_is_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let run_id = RunId::new("reference-tamper").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path,
        repo_head: None,
        plan_file: PathBuf::from("untrusted-plan-must-not-be-read.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_dir = temp.path().join("checkpoints");
    let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
    let malformed_run = temp
        .path()
        .join("repo/.maco/autopilot/runs/malformed-marker");
    fs::create_dir_all(&malformed_run).expect("create malformed marker run");
    for directory in [
        temp.path().join("repo/.maco"),
        temp.path().join("repo/.maco/autopilot"),
        temp.path().join("repo/.maco/autopilot/runs"),
        malformed_run.clone(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("private artifact directory");
    }
    let malformed_marker = malformed_run.join(".maco-artifact-final.json");
    fs::write(&malformed_marker, b"not-json").expect("write malformed marker");
    fs::set_permissions(&malformed_marker, fs::Permissions::from_mode(0o600))
        .expect("private malformed marker");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read envelope")).expect("parse envelope");
    envelope["mac"] = serde_json::Value::String("0".repeat(64));
    fs::write(&path, serde_json::to_vec(&envelope).expect("encode tamper"))
        .expect("tamper envelope");
    let error = read_run_checkpoint(&path).expect_err("tampered envelope must fail");
    assert!(error
        .to_string()
        .contains("authentication tag verification failed"));
    assert!(!error.to_string().contains("finalization marker"));
    assert!(!error
        .to_string()
        .contains("untrusted-plan-must-not-be-read"));

    let missing_plan = temp.path().join("resume-must-not-read-this-plan.json");
    let resume_error = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file: path,
        repo: Some(temp.path().join("repo")),
        plan_file: Some(missing_plan.clone()),
        jobs: 1,
        patch_dir: None,
    })
    .expect_err("resume must authenticate before loading a plan");
    assert!(resume_error
        .to_string()
        .contains("authentication tag verification failed"));
    assert!(!resume_error
        .to_string()
        .contains(&missing_plan.display().to_string()));
}

#[test]
fn orchestration_profile_binds_git_common_and_hides_sensitive_state() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    SyncStore::open(&repo_path).expect("create repository state root");
    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "profile-binding".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    let (common, sensitive) =
        orchestration_sandbox_roots(&worktree.path).expect("resolve sandbox roots");
    let linked = crate::git_repository::open(&worktree.path).expect("open linked worktree");
    assert_eq!(common, linked.commondir());
    assert_eq!(sensitive, linked.commondir().join("maco/state"));
    let spec = CommandRunSpec {
        command: "true".to_string(),
        workspace_root: worktree.path.clone(),
        working_directory: worktree.path,
        env: BTreeMap::new(),
        timeout: None,
        visible_read_only_roots: Vec::new(),
        visible_read_write_roots: vec![common.clone()],
        hidden_roots: vec![sensitive.clone()],
        runtime: OrchestrationExecutionRuntime::Verified,
    };
    let profile = strict_command_profile(&spec);
    assert!(
        profile.visible_read_write_roots().contains(&common),
        "orchestrate agent commands must write the linked Git common dir so commits can persist objects and refs"
    );
    assert!(
        profile.hidden_roots().contains(&sensitive),
        "orchestrate agent commands must hide repository sensitive state"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn verified_run_fails_closed_before_child_can_read_repository_authentication_key() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    let key_name = crate::artifacts::state_auth::authentication_key_file_name();
    fs::write(
            &plan_file,
            serde_json::to_vec(&serde_json::json!({
                "agents": [{
                    "id": "key-isolation",
                    "paths": ["README.md"],
                    "command": format!(
                        "common=$(git rev-parse --path-format=absolute --git-common-dir) || exit 10; if cat \"$common/maco/state/{key_name}\"; then exit 91; else printf 'state-hidden\\n'; fi"
                    )
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
    let summary = super::run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(RunId::new("verified-key-isolation").expect("run id")),
            checkpoint_dir: Some(checkpoint_dir),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        },
    )
    .expect("verified run must report a per-agent outcome");
    let agent = &summary.agents[0];
    assert_ne!(
        agent.exit_code,
        Some(91),
        "verified child observed the repository authentication key"
    );
    match agent.status {
        AgentRunStatus::Succeeded => {
            assert!(
                agent.stdout.text.contains("state-hidden"),
                "verified child must observe the key as hidden: {}",
                agent.stdout.text
            );
        }
        // Hosts without the strict containment backend fail closed before the
        // child command runs; the key stays unread either way.
        AgentRunStatus::Failed => {}
        other => panic!("unexpected verified agent status {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn checkpoint_writer_refuses_rekey_when_artifact_marker_exists() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let run = repo_path.join(".maco/autopilot/runs/legacy");
    fs::create_dir_all(&run).expect("create legacy artifact run");
    for directory in [
        repo_path.join(".maco"),
        repo_path.join(".maco/autopilot"),
        repo_path.join(".maco/autopilot/runs"),
        run.clone(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("private artifact directory");
    }
    let marker = run.join(".maco-artifact-final.json");
    fs::write(&marker, b"existing marker").expect("write marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("private marker");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: RunId::new("must-not-rekey").expect("run id"),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path.clone(),
        repo_head: None,
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_dir = temp.path().join("checkpoints");
    let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
        .expect_err("existing marker must block key creation");
    assert!(error.to_string().contains("existing final marker"));
    assert!(!checkpoint_path(&checkpoint_dir, &checkpoint.run_id).exists());
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    assert!(!repo
        .commondir()
        .join("maco/state")
        .join(crate::artifacts::state_auth::authentication_key_file_name())
        .exists());
}

#[cfg(unix)]
#[test]
fn checkpoint_writer_refuses_first_key_when_checkpoint_journals_exist() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let maco = repo.commondir().join("maco");
    let state = maco.join("state");
    let journals = state.join(crate::state_journal::JOURNAL_ROOT_NAME);
    fs::create_dir_all(&journals).expect("create prior journal root");
    for directory in [&maco, &state, &journals] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("private journal directory");
    }
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: RunId::new("must-not-rekey-journal").expect("run id"),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path,
        repo_head: None,
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_dir = temp.path().join("checkpoints");
    let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
        .expect_err("prior checkpoint journals must block first key");
    assert!(error.to_string().contains("checkpoint journals exist"));
    assert!(!checkpoint_path(&checkpoint_dir, &checkpoint.run_id).exists());
    assert!(!state
        .join(crate::artifacts::state_auth::authentication_key_file_name())
        .exists());
}

#[test]
fn missing_key_for_existing_epoch_is_never_regenerated() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    let checkpoint = |run_id: &str| RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: RunId::new(run_id).expect("run id"),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path.clone(),
        repo_head: None,
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    drop(repository_auth_writer(&repo_path).expect("establish auth epoch"));
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let key = repo
        .commondir()
        .join("maco/state")
        .join(crate::artifacts::state_auth::authentication_key_file_name());
    fs::remove_file(&key).expect("remove key to simulate loss");
    let second = checkpoint("epoch-second");
    let error = write_run_checkpoint(&checkpoint_dir, &second)
        .expect_err("existing epoch must not be rekeyed");
    assert!(error.to_string().contains("existing authentication epoch"));
    assert!(!key.exists());
    assert!(!checkpoint_path(&checkpoint_dir, &second.run_id).exists());
}

#[test]
fn checkpoint_helpers_round_trip_serialized_state() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let run_id = RunId::new("run-1").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::Final,
        repo: repo_path,
        repo_head: Some("0123456789012345678901234567890123456789".to_string()),
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: Some(CheckpointPlanSnapshot {
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            repo_validation_commands: Vec::new(),
            agents: vec![CheckpointAgentPlanSnapshot {
                id: "agent-a".to_string(),
                paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                env: BTreeMap::new(),
                timeout_seconds: None,
                command: "true".to_string(),
                depends_on: Vec::new(),
                working_directory: None,
                validation_commands: Vec::new(),
            }],
        }),
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Warn,
        success: true,
        agents: vec![AgentCheckpoint {
            id: "agent-a".to_string(),
            status: AgentRunStatus::Succeeded,
            worktree: Some(CheckpointWorktreeRecord {
                name: "agent-a".to_string(),
                path: PathBuf::from("worktrees/agent-a"),
                branch: "maco/agent-a".to_string(),
            }),
            claim: None,
            semantic_intent: None,
            semantic_conflicts: Vec::new(),
            changed_paths: vec![PathBuf::from("README.md")],
            unclaimed_changed_paths: Vec::new(),
            validation: Vec::new(),
            candidate_binding: Some(AgentCandidateBinding {
                version: CANDIDATE_BINDING_VERSION,
                base_oid: "0123456789012345678901234567890123456789".to_string(),
                head_oid: "0123456789012345678901234567890123456789".to_string(),
                state_oid: "1111111111111111111111111111111111111111".to_string(),
                diff_oid: "2222222222222222222222222222222222222222".to_string(),
                changed_paths: vec![PathBuf::from("README.md")],
                patch_bytes: 1,
            }),
            command_completed_binding: None,
            error: None,
        }],
        repo_validation: Vec::new(),
        repo_validation_target: Some(RepoValidationTargetBinding {
            version: CANDIDATE_BINDING_VERSION,
            kind: RepoValidationTargetKind::CombinedCandidate,
            base_oid: "0123456789012345678901234567890123456789".to_string(),
            combined_diff_oid: "3333333333333333333333333333333333333333".to_string(),
            changed_paths: vec![PathBuf::from("README.md")],
            candidate_count: 1,
            patch_count: 1,
            aggregate_patch_bytes: 1,
        }),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };

    let checkpoint_dir = temp.path().join("checkpoints");
    let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
    assert_eq!(path, checkpoint_path(&checkpoint_dir, &run_id));
    let loaded = read_run_checkpoint(&path).expect("read checkpoint");
    assert_eq!(loaded, checkpoint);
}

#[test]
fn fresh_same_run_id_preserves_existing_checkpoint_and_guides_resume() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let run_id = RunId::new("fresh-collision").expect("run id");
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: run_id.clone(),
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path,
        repo_head: None,
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_dir = temp.path().join("checkpoints");
    let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("first checkpoint");
    let before = fs::read(&path).expect("read existing checkpoint");

    let error = write_run_checkpoint(&checkpoint_dir, &checkpoint)
        .expect_err("fresh run id collision must be refused");
    assert!(error.to_string().contains("orchestrate resume"));
    assert_eq!(fs::read(&path).expect("re-read checkpoint"), before);
    assert_eq!(
        read_run_checkpoint(&path).expect("existing remains valid"),
        checkpoint
    );
}

#[cfg(unix)]
#[test]
fn checkpoint_round_trips_non_utf8_repo_and_completed_candidate_paths() {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"repo-\xff".to_vec()));
    Repository::init(&repo_path).expect("init non-UTF-8 repo");
    let candidate_path = PathBuf::from(std::ffi::OsString::from_vec(b"candidate-\xfe.sh".to_vec()));
    let plan_file = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"plan-\xfd.json".to_vec()));
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id: RunId::new("lossless-command-completion").expect("run id"),
        stage: RunCheckpointStage::AgentsCompleted,
        repo: repo_path.clone(),
        repo_head: None,
        plan_file,
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: vec![AgentCheckpoint {
            id: "lossless".to_string(),
            status: AgentRunStatus::Succeeded,
            worktree: Some(CheckpointWorktreeRecord {
                name: "lossless".to_string(),
                path: repo_path.join(std::ffi::OsString::from_vec(b"worktree-\xfc".to_vec())),
                branch: "maco/lossless".to_string(),
            }),
            claim: None,
            semantic_intent: None,
            semantic_conflicts: Vec::new(),
            changed_paths: vec![candidate_path.clone()],
            unclaimed_changed_paths: Vec::new(),
            validation: Vec::new(),
            candidate_binding: None,
            command_completed_binding: Some(CompletedCommandStateBinding {
                version: CANDIDATE_BINDING_VERSION,
                base_oid: "0123456789012345678901234567890123456789".to_string(),
                head_oid: "0123456789012345678901234567890123456789".to_string(),
                state_oid: "1111111111111111111111111111111111111111".to_string(),
                changed_paths: vec![candidate_path],
            }),
            error: None,
        }],
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    let checkpoint_dir = temp.path().join("checkpoints");
    let path = write_run_checkpoint(&checkpoint_dir, &checkpoint).expect("write checkpoint");
    let loaded = read_run_checkpoint(&path).expect("read checkpoint");
    assert_eq!(loaded, checkpoint);
}

#[cfg(unix)]
#[test]
fn non_utf8_command_completed_wal_round_trips_through_resume() {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "base\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
            &plan_file,
            serde_json::to_vec(&serde_json::json!({
                "agents": [{
                    "id": "lossless-wal",
                    "paths": ["out"],
                    "command": r#"mkdir -p out; name=$(printf 'raw-\377.txt'); printf 'once\n' > "out/$name""#
                }]
            }))
            .expect("encode plan"),
        )
        .expect("write plan");
    let run_id = RunId::new("lossless-command-completed-wal").expect("run id");
    install_checkpoint_event_failure(run_id.as_str(), PHASE_VALIDATION_STARTED);
    let first_error = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file: plan_file.clone(),
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        },
    )
    .expect_err("stop after command_completed WAL append");
    assert!(
        first_error
            .to_string()
            .contains("injected checkpoint event failure"),
        "{first_error:#}"
    );

    let raw_path =
        PathBuf::from("out").join(std::ffi::OsString::from_vec(b"raw-\xff.txt".to_vec()));
    let checkpoint_file = checkpoint_path(&checkpoint_dir, &run_id);
    let recovered = read_run_checkpoint(&checkpoint_file).expect("decode command WAL");
    assert_eq!(recovered.repo, repo_path);
    assert!(recovered.agents[0]
        .command_completed_binding
        .as_ref()
        .expect("command completion binding")
        .changed_paths
        .contains(&raw_path));

    let summary = resume_plan_file(OrchestrationResumeOptions {
        checkpoint_file,
        repo: Some(repo_path.clone()),
        plan_file: Some(plan_file),
        jobs: 1,
        patch_dir: None,
    })
    .expect("resume non-UTF-8 completed command");
    assert!(summary.success);
    assert!(summary.agents[0].changed_paths.contains(&raw_path));
    let worktree = WorktreeManager::new(&repo_path)
        .list()
        .expect("list worktrees")
        .into_iter()
        .find(|record| record.name == "lossless-wal")
        .expect("lossless worktree");
    assert_eq!(
        fs::read(worktree.path.join(raw_path)).expect("read non-UTF-8 candidate"),
        b"once\n"
    );
}

#[test]
fn checkpoint_v1_v2_are_rejected_with_start_new_run_guidance() {
    for version in [1_u32, 2_u32] {
        let temp = TempDir::new().expect("tempdir");
        let checkpoint = RunCheckpoint {
            version,
            run_id: RunId::new(format!("legacy-v{version}")).expect("run id"),
            stage: RunCheckpointStage::WorktreesSelected,
            repo: PathBuf::from("repo"),
            repo_head: None,
            plan_file: PathBuf::from("plan.json"),
            plan_snapshot: None,
            keep_claims: false,
            worktree_reuse_policy: WorktreeReusePolicy::Clean,
            semantic_coordination: SemanticCoordinationMode::Off,
            success: false,
            agents: Vec::new(),
            repo_validation: Vec::new(),
            repo_validation_target: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            updated_unix_ms: 1,
        };
        let checkpoint_dir = temp.path().join("checkpoints");
        let root = SecureOutputRoot::create_new(&checkpoint_dir).expect("checkpoint root");
        let mut slot = root
            .reserve(OsStr::new(&format!("legacy-v{version}.json")))
            .expect("legacy slot");
        slot.write_json_atomic(&checkpoint, CHECKPOINT_REFERENCE_MAX_BYTES)
            .expect("write legacy checkpoint");
        let path = slot.path().to_path_buf();

        let error = read_run_checkpoint(&path).expect_err("legacy checkpoint must be rejected");
        assert!(error.to_string().contains(&format!("version {version}")));
        assert!(error.to_string().contains("v3"));
        assert!(error.to_string().contains("start a new run"));
    }
}

#[test]
fn checkpoint_controls_write_final_run_state() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let plan_file = temp.path().join("plan.json");
    fs::write(
        &plan_file,
        r#"{"agents":[{"id":"agent-a","paths":["README.md"],"command":"true"}]}"#,
    )
    .expect("write plan");
    let run_id = RunId::new("checkpoint-test").expect("run id");

    let summary = run_plan_file_with_controls(
        OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        },
        OrchestrationRunControls {
            run_id: Some(run_id.clone()),
            checkpoint_dir: Some(checkpoint_dir.clone()),
            worktree_reuse_policy: None,
            semantic_coordination: SemanticCoordinationMode::Off,
        },
    )
    .expect("run plan");

    assert!(summary.success);
    let checkpoint =
        read_run_checkpoint(&checkpoint_path(&checkpoint_dir, &run_id)).expect("checkpoint");
    assert_eq!(checkpoint.stage, RunCheckpointStage::Final);
    assert!(checkpoint.success);
    assert_eq!(checkpoint.agents[0].id, "agent-a");
}

#[cfg(unix)]
#[test]
fn agent_command_drains_large_output_before_timeout() {
    let temp = TempDir::new().expect("tempdir");
    let result = run_agent_command(CommandRunSpec {
            command: "i=0; while [ \"$i\" -lt 128 ]; do printf '%4096s' O; printf '%4096s' E >&2; i=$((i + 1)); done".to_string(),
            workspace_root: temp.path().to_path_buf(),
            working_directory: temp.path().to_path_buf(),
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(3)),
            visible_read_only_roots: Vec::new(),
            visible_read_write_roots: Vec::new(),
            hidden_roots: Vec::new(),
            runtime: OrchestrationExecutionRuntime::NonpublishableSimulation,
        })
        .expect("run large-output agent command");

    assert!(result.status.is_some_and(|status| status.success()));
    assert!(!result.timed_out);
    assert!(result.stdout.truncated);
    assert!(result.stderr.truncated);
    assert_eq!(result.process_error, None);
}

#[cfg(unix)]
#[test]
fn candidate_capture_preserves_non_utf8_and_replacement_character_paths_without_index_writes() {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::write(repo_path.join("README.md"), "# paths\n").expect("write readme");
    commit_all(&repo, "initial commit").expect("commit");
    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "lossless-path-agent".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create worktree");
    let raw = b"raw-\xff.txt".to_vec();
    let replacement = "raw-\u{fffd}.txt";
    fs::write(worktree.path.join(OsString::from_vec(raw.clone())), "raw\n")
        .expect("write raw path");
    fs::write(worktree.path.join(replacement), "replacement\n").expect("write replacement path");
    let base_oid = current_head_oid(&repo_path).expect("base");
    let state = capture_consistent_candidate_state(
        &worktree.path,
        &base_oid,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture both candidate paths");
    let captured = capture_bound_candidate(
        &worktree.path,
        &base_oid,
        &state,
        OrchestrationExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture exact candidate patch");

    let worktree_repo = crate::git_repository::open(&worktree.path).expect("open worktree repo");
    let index = worktree_repo.index().expect("open linked index");
    let indexed = index
        .iter()
        .map(|entry| entry.path)
        .collect::<BTreeSet<_>>();
    assert!(!indexed.contains(&raw));
    assert!(!indexed.contains(replacement.as_bytes()));
    assert!(captured
        .binding
        .changed_paths
        .contains(&PathBuf::from(OsString::from_vec(raw))));
    assert!(captured
        .binding
        .changed_paths
        .contains(&PathBuf::from(replacement)));
    assert!(!captured.patch.is_empty());
}

#[test]
fn patch_guard_cleans_unused_reservation_and_rejects_exact_capture_boundary() {
    let temp = TempDir::new().expect("tempdir");
    let root =
        SecureOutputRoot::create_new(&temp.path().join("patches")).expect("create patch root");
    let slot = root
        .reserve(OsStr::new("agent-a.patch"))
        .expect("reserve patch");
    let path = slot.path().to_path_buf();
    drop(PatchOutputGuard::new(slot));

    assert!(!path.exists(), "drop left an unused reserved patch leaf");
    assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES - 1).is_ok());
    assert!(validate_patch_output_size(PATCH_OUTPUT_MAX_BYTES).is_err());
}

#[test]
#[cfg(unix)]
fn retained_checkpoint_writer_rejects_leaf_rebinding_without_clobbering_sentinel() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let checkpoint_dir = temp.path().join("checkpoints");
    let run_id = RunId::new("secure-checkpoint").expect("run id");
    let controls = OrchestrationRunControls {
        run_id: Some(run_id.clone()),
        checkpoint_dir: Some(checkpoint_dir.clone()),
        worktree_reuse_policy: None,
        semantic_coordination: SemanticCoordinationMode::Off,
    };
    let mut writer =
        prepare_run_checkpoint_writer(&controls, &Some(run_id.clone()), &repo_path, &[])
            .expect("prepare writer")
            .expect("configured writer");
    let path = writer.slot.path().to_path_buf();
    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id,
        stage: RunCheckpointStage::WorktreesSelected,
        repo: repo_path,
        repo_head: None,
        plan_file: PathBuf::from("plan.json"),
        plan_snapshot: None,
        keep_claims: false,
        worktree_reuse_policy: WorktreeReusePolicy::Clean,
        semantic_coordination: SemanticCoordinationMode::Off,
        success: false,
        agents: Vec::new(),
        repo_validation: Vec::new(),
        repo_validation_target: None,
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        updated_unix_ms: 1,
    };
    writer.write(&checkpoint).expect("initial checkpoint write");
    let sentinel = temp.path().join("sentinel");
    fs::write(&sentinel, "untouched").expect("write sentinel");
    fs::remove_file(&path).expect("remove checkpoint leaf");
    symlink(&sentinel, &path).expect("rebind checkpoint leaf");

    assert!(writer.write(&checkpoint).is_err());
    assert_eq!(
        fs::read_to_string(&sentinel).expect("read sentinel"),
        "untouched"
    );
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
