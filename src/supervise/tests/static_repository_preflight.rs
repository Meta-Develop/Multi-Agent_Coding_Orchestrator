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
    let plan = writable_plan();
    let error = plan_validation::validate_supervisor_plan_in_repo(
        plan,
        metadata_for(&writable_plan()),
        Some(&repo),
    )
    .expect_err("offline validation refuses missing identity");
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
    assert_refused_before_reservation(&repo, 1, &["--no-hardlinks"]);
    let error = plan_validation::validate_supervisor_plan_in_repo(
        writable_plan(),
        metadata_for(&writable_plan()),
        Some(&repo),
    )
    .expect_err("offline validation refuses object hardlinks");
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
    assert_refused_before_reservation(&repo, 1, &["group/world-writable"]);
    let error = plan_validation::validate_supervisor_plan_in_repo(
        writable_plan(),
        metadata_for(&writable_plan()),
        Some(&repo),
    )
    .expect_err("offline validation refuses group/world-writable directories");
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
    let error = plan_validation::validate_supervisor_plan_in_repo(
        writable_plan(),
        metadata_for(&writable_plan()),
        Some(&repo),
    )
    .expect_err("offline validation refuses stale retained private config");
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
        plan,
        metadata_for(&writable_plan()),
        Some(&repo),
    )
    .expect("clean writable plan passes offline validation");

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
#[test]
fn read_only_plan_skips_identity_check() {
    let (_temp, repo) = init_repo(false);
    let plan = read_only_plan();
    assert!(!plan_validation::plan_has_writable_worker_or_assignment(
        &plan
    ));
    plan_validation::validate_supervisor_plan_in_repo(
        plan,
        metadata_for(&read_only_plan()),
        Some(&repo),
    )
    .expect("read-only plan skips repository-local identity");

    let calls = AtomicUsize::new(0);
    let root = tempfile::tempdir().expect("options root");
    let mut options = injected_options(&repo, root.path(), "static-repository-readonly");
    options.runtime = SupervisorRuntime::Fake;
    let result = run_supervisor_plan_with_runner(
        read_only_plan(),
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
fn absent_repository_skips_static_conditions() {
    let plan = writable_plan();
    plan_validation::validate_supervisor_plan_in_repo(plan, metadata_for(&writable_plan()), None)
        .expect("validation without a repository does not inspect one");
}
