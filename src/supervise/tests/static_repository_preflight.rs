use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[cfg(unix)]
fn init_repo(identity: bool) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("temporary repository");
    let repo = temp.path().join("repo");
    let repository = git2::Repository::init(&repo).expect("initialize repository");
    if identity {
        let mut local =
            git2::Config::open(&repository.path().join("config")).expect("local config");
        local.set_str("user.name", "maco test").expect("user.name");
        local
            .set_str("user.email", "maco-test@example.invalid")
            .expect("user.email");
    }
    std::fs::write(repo.join("README.md"), "baseline\n").expect("write baseline");
    clear_group_world_write(&repo);
    clear_group_world_write(&repo.join(".git"));
    (temp, repo)
}

#[cfg(unix)]
fn clear_group_world_write(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & !0o022))
        .expect("clear group/world write");
}

#[cfg(unix)]
fn metadata_for(plan: &SupervisorPlan) -> SupervisorPlanMetadata {
    SupervisorPlanMetadata {
        assignment_schedule: plan
            .assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect(),
        ..SupervisorPlanMetadata::default()
    }
}

#[cfg(unix)]
fn writable_plan() -> SupervisorPlan {
    injected_plan(injected_assignment(true), 0)
}

#[cfg(unix)]
fn read_only_plan() -> SupervisorPlan {
    let mut assignment = injected_assignment(false);
    assignment.phase = AssignmentPhase::Planning;
    injected_plan(assignment, 0)
}

#[cfg(unix)]
fn execution_read_only_plan() -> SupervisorPlan {
    let mut assignment = injected_assignment(false);
    assignment.phase = AssignmentPhase::Execution;
    assignment.role = AgentRole::Researcher;
    assignment.role_category = Some(RoleCategory::ReadOnlyResearcher);
    injected_plan(assignment, 0)
}

#[cfg(unix)]
fn add_object_hardlink(repo: &std::path::Path) {
    let object = repo.join(".git/objects/aa/static-preflight-object");
    std::fs::create_dir_all(object.parent().expect("object parent")).expect("object dir");
    std::fs::write(&object, b"object-bytes").expect("object");
    std::fs::hard_link(&object, repo.join(".git/static-preflight-object-alias")).expect("alias");
}

#[cfg(unix)]
fn make_group_world_writable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).expect("chmod");
}

#[cfg(unix)]
fn write_stale_private_config(repo: &std::path::Path) {
    let private = repo.join(".git/worktrees/prior/maco-private-git-v1");
    std::fs::create_dir_all(&private).expect("retained private dir");
    std::fs::write(private.join("config"), b"not-the-fixed-policy\n").expect("stale config");
}

#[cfg(unix)]
fn set_repository_hooks_path(repo: &std::path::Path) {
    let mut local = git2::Config::open(&repo.join(".git/config")).expect("local config");
    local
        .set_str("core.hooksPath", "alternate-hooks")
        .expect("hooksPath");
}

#[cfg(unix)]
fn add_refs_hardlink(repo: &std::path::Path) {
    let reference = repo.join(".git/refs/heads/main");
    std::fs::create_dir_all(reference.parent().expect("refs parent")).expect("refs dir");
    std::fs::write(&reference, b"ref\n").expect("ref");
    std::fs::hard_link(&reference, repo.join(".git/static-preflight-ref-alias"))
        .expect("ref alias");
}

#[cfg(unix)]
fn add_active_hook_hardlink(repo: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let hook = repo.join(".git/hooks/commit-msg");
    std::fs::create_dir_all(hook.parent().expect("hooks parent")).expect("hooks dir");
    std::fs::write(&hook, b"#!/bin/sh\nexit 0\n").expect("hook");
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("hook mode");
    std::fs::hard_link(&hook, repo.join(".git/hooks/commit-msg-alias")).expect("hook alias");
}

#[cfg(unix)]
fn add_packed_refs_hardlink(repo: &std::path::Path) {
    let packed = repo.join(".git/packed-refs");
    std::fs::write(&packed, b"# pack-refs\n").expect("packed-refs");
    std::fs::hard_link(
        &packed,
        repo.join(".git/static-preflight-packed-refs-alias"),
    )
    .expect("packed-refs alias");
}

#[cfg(unix)]
fn add_exclude_hardlink(repo: &std::path::Path) {
    let exclude = repo.join(".git/info/exclude");
    std::fs::create_dir_all(exclude.parent().expect("exclude parent")).expect("exclude dir");
    std::fs::write(&exclude, b"# exclude\n").expect("exclude");
    std::fs::hard_link(&exclude, repo.join(".git/static-preflight-exclude-alias"))
        .expect("exclude alias");
}

#[cfg(unix)]
fn add_shallow_hardlink(repo: &std::path::Path) {
    let shallow = repo.join(".git/shallow");
    std::fs::write(&shallow, b"0123456789abcdef0123456789abcdef01234567\n").expect("shallow");
    std::fs::hard_link(&shallow, repo.join(".git/static-preflight-shallow-alias"))
        .expect("shallow alias");
}

#[cfg(unix)]
fn assert_offline_and_before_preparation(repo: &std::path::Path, needles: &[&str]) {
    assert_shared_validation_independent(repo);
    assert_refused_before_reservation(repo, 1, needles);
    let error = command_refusal(repo);
    let causes = supervisor_plan_error_envelope(&error).causes;
    assert_eq!(causes.len(), 1, "{causes:?}\n{error:#}");
    for needle in needles {
        assert!(
            causes.iter().any(|cause| cause.contains(needle)),
            "{needle} missing from {causes:?}"
        );
    }
}

#[cfg(unix)]
fn assert_shared_validation_independent(repo: &std::path::Path) {
    plan_validation::validate_supervisor_plan_in_repo(
        writable_plan(),
        metadata_for(&writable_plan()),
        Some(repo),
    )
    .expect("shared validation does not apply static repository conditions");
}

#[cfg(unix)]
fn command_refusal(repo: &std::path::Path) -> anyhow::Error {
    refuse_writable_plan_static_repository_conditions(&writable_plan(), repo)
        .expect_err("supervise plan command refuses static repository conditions")
}

#[cfg(unix)]
fn assert_refused_before_reservation(
    repo: &std::path::Path,
    expected_findings: usize,
    needles: &[&str],
) {
    let calls = AtomicUsize::new(0);
    let root = tempfile::tempdir().expect("options root");
    let mut options = injected_options(repo, root.path(), "static-repository-preflight");
    options.runtime = SupervisorRuntime::Fake;
    let result = run_supervisor_plan_with_runner(
        writable_plan(),
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut |_command| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("provider dispatch is forbidden before static repository preflight");
        },
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "provider calls");
    let error = result.expect_err("static conditions refuse before dispatch");
    let envelope = supervisor_plan_error_envelope(&error);
    assert_eq!(
        envelope.causes.len(),
        expected_findings,
        "one finding per condition: {envelope:?}\n{error:#}"
    );
    for needle in needles {
        assert!(
            envelope.causes.iter().any(|cause| cause.contains(needle)),
            "{needle} missing from {envelope:?}"
        );
    }
    let run_dir = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join("static-repository-preflight");
    assert!(
        !run_dir.exists(),
        "preflight returns before the run budget ledger exists, so reserved tokens are zero"
    );
}

#[cfg(unix)]
#[test]
fn missing_identity_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(false);
    assert_shared_validation_independent(&repo);
    let plan_file = repo.join("plan.json");
    std::fs::write(
        &plan_file,
        r#"{
            "version": 1,
            "task": "sniff fixture",
            "assignments": [{
                "id": "child-a",
                "phase": "execution",
                "assigned_paths": ["README.md"],
                "worker_assignments": []
            }]
        }"#,
    )
    .expect("write loadable plan");
    load_supervisor_plan_file_in_repo(&plan_file, &repo)
        .expect("loading a plan does not require repository-local identity");
    let error = command_refusal(&repo);
    let envelope = supervisor_plan_error_envelope(&error);
    assert!(envelope
        .causes
        .iter()
        .any(|cause| cause.contains("user.name") && cause.contains("user.email")));
    assert!(envelope
        .causes
        .iter()
        .any(|cause| { cause.contains("Preserve the repository attribution and hook policy") }));
    assert_refused_before_reservation(
        &repo,
        1,
        &[
            "user.name",
            "Preserve the repository attribution and hook policy",
        ],
    );
}

#[cfg(unix)]
#[test]
fn object_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_object_hardlink(&repo);
    assert_shared_validation_independent(&repo);
    assert_refused_before_reservation(&repo, 1, &["--no-hardlinks"]);
    let error = command_refusal(&repo);
    assert!(supervisor_plan_error_envelope(&error)
        .causes
        .iter()
        .any(|cause| cause.contains("--no-hardlinks")));
}

#[cfg(unix)]
#[test]
fn group_world_writable_directory_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    make_group_world_writable(&repo);
    assert_shared_validation_independent(&repo);
    assert_refused_before_reservation(&repo, 1, &["group/world-writable"]);
    let error = command_refusal(&repo);
    assert!(supervisor_plan_error_envelope(&error)
        .causes
        .iter()
        .any(|cause| cause.contains("group/world-writable")));
}

#[cfg(unix)]
#[test]
fn stale_retained_private_config_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    write_stale_private_config(&repo);
    assert_refused_before_reservation(
        &repo,
        1,
        &[
            "changed from its fixed policy",
            "retained from a prior run is stale",
            "maco-private-git-v1",
        ],
    );
    assert_shared_validation_independent(&repo);
    let error = command_refusal(&repo);
    let causes = supervisor_plan_error_envelope(&error).causes;
    assert!(causes.iter().any(|cause| {
        cause.contains("changed from its fixed policy")
            && cause.contains("retained from a prior run is stale")
            && cause.contains("maco-private-git-v1")
    }));
}

#[cfg(unix)]
#[test]
fn clean_repository_passes_static_conditions() {
    let (_temp, repo) = init_repo(true);
    let findings = crate::external_agent::static_repository_conditions(&repo)
        .expect("clean repository can be inspected");
    assert!(findings.is_empty(), "{findings:?}");
    let plan = writable_plan();
    plan_validation::validate_supervisor_plan_in_repo(
        plan.clone(),
        metadata_for(&plan),
        Some(&repo),
    )
    .expect("clean writable plan passes shared validation");
    refuse_writable_plan_static_repository_conditions(&plan, &repo)
        .expect("clean repository passes the supervise plan command check");

    let calls = AtomicUsize::new(0);
    let root = tempfile::tempdir().expect("options root");
    let mut options = injected_options(&repo, root.path(), "static-repository-clean");
    options.runtime = SupervisorRuntime::Fake;
    let result = run_supervisor_plan_with_runner(
        writable_plan(),
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut |_command| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("clean preflight must not be the reason a provider runs");
        },
    );
    if let Err(error) = result {
        assert!(
            error.chain().all(|cause| !cause
                .to_string()
                .contains("static repository conditions refuse")),
            "clean repository must pass static preflight: {error:#}"
        );
    }
    let _ = calls;
}

#[cfg(unix)]
fn assert_plan_skips_identity_check(plan: SupervisorPlan) {
    let (_temp, repo) = init_repo(false);
    assert!(!plan_validation::plan_has_writable_worker_or_assignment(
        &plan
    ));
    plan_validation::validate_supervisor_plan_in_repo(
        plan.clone(),
        metadata_for(&plan),
        Some(&repo),
    )
    .expect("read-only plan passes shared validation without local identity");
    refuse_writable_plan_static_repository_conditions(&plan, &repo)
        .expect("read-only plan skips static repository conditions");

    let calls = AtomicUsize::new(0);
    let root = tempfile::tempdir().expect("options root");
    let mut options = injected_options(&repo, root.path(), "static-repository-readonly");
    options.runtime = SupervisorRuntime::Fake;
    let result = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut |_command| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("read-only preflight must not dispatch");
        },
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "provider calls");
    if let Err(error) = result {
        assert!(
            error.chain().all(|cause| {
                !cause.to_string().contains("user.name")
                    && !cause
                        .to_string()
                        .contains("static repository conditions refuse")
            }),
            "read-only plan must not refuse for missing identity: {error:#}"
        );
    }
}

#[cfg(unix)]
#[test]
fn read_only_plan_skips_identity_check() {
    let planning = read_only_plan();
    assert_eq!(planning.assignments[0].phase, AssignmentPhase::Planning);
    assert_plan_skips_identity_check(planning);

    let execution = execution_read_only_plan();
    assert_eq!(
        execution.assignments[0].phase,
        AssignmentPhase::Execution,
        "execution-phase read-only authority is a separate case from planning"
    );
    assert!(!execution.assignments[0]
        .effective_role_category()
        .may_write());
    assert!(execution.assignments[0].worker_assignments.is_empty());
    assert_plan_skips_identity_check(execution);
}

#[cfg(unix)]
#[test]
fn absent_repository_skips_static_conditions() {
    let plan = writable_plan();
    plan_validation::validate_supervisor_plan_in_repo(plan, metadata_for(&writable_plan()), None)
        .expect("validation without a repository does not inspect one");
}

#[cfg(unix)]
#[test]
fn hooks_path_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    set_repository_hooks_path(&repo);
    assert_offline_and_before_preparation(
        &repo,
        &["core.hooksPath", "default Git hooks directory"],
    );
}

#[cfg(unix)]
#[test]
fn refs_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_refs_hardlink(&repo);
    assert_offline_and_before_preparation(&repo, &["Git refs", "hard-link aliases"]);
}

#[cfg(unix)]
#[test]
fn active_hook_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_active_hook_hardlink(&repo);
    assert_offline_and_before_preparation(
        &repo,
        &["Git commit-msg hook", "reinstall the repository hook"],
    );
}

#[cfg(unix)]
#[test]
fn packed_refs_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_packed_refs_hardlink(&repo);
    assert_offline_and_before_preparation(&repo, &["Git packed refs", "--no-hardlinks"]);
}

#[cfg(unix)]
#[test]
fn exclude_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_exclude_hardlink(&repo);
    assert_offline_and_before_preparation(&repo, &["Git exclude file", "--no-hardlinks"]);
}

#[cfg(unix)]
#[test]
fn shallow_hardlink_refuses_before_dispatch_and_reservation() {
    let (_temp, repo) = init_repo(true);
    add_shallow_hardlink(&repo);
    assert_offline_and_before_preparation(&repo, &["Git shallow boundary", "--no-hardlinks"]);
}

#[cfg(unix)]
#[test]
fn subdirectory_input_discovers_repository_root_before_refusal() {
    let (_temp, repo) = init_repo(false);
    let nested = repo.join("nested");
    std::fs::create_dir(&nested).expect("worktree subdirectory");
    assert_refused_before_reservation(&nested, 1, &["user.name", "user.email"]);
}
