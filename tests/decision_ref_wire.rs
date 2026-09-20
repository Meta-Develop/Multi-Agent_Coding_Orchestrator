use git2::Repository;
use multi_agent_coding_orchestrator::{
    decision_ref::{parse_decision_ref_cli, DecisionRef, DecisionRefError},
    decision_store::DecisionStore,
    merge::check_merge_arbitration_decision_refs,
    supervise::supervisor_plan_from_task_file,
};
use std::{fs, path::Path};

fn init_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("temporary repository");
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join("src")).expect("src");
    fs::write(repo.join("README.md"), "hello\n").expect("readme");
    Repository::init(&repo).expect("initialize repository");
    (temp, repo)
}

fn plan_json(decision_refs_json: Option<&str>) -> String {
    let refs = match decision_refs_json {
        Some(refs) => format!(r#", "decision_refs": {refs}"#),
        None => String::new(),
    };
    format!(
        r#"{{
            "version": 1,
            "task": "decision-ref wire fixture",
            "max_depth": 2,
            "max_child_assignments": 1,
            "assignments": [{{
                "id": "child-a",
                "phase": "execution",
                "role": "child_orchestrator",
                "assigned_paths": ["README.md"],
                "worker_assignments": []
                {refs}
            }}],
            "assignment_schedule": [{{
                "assignment_id": "child-a",
                "depth": 2,
                "flattened_index": 0
            }}]
        }}"#
    )
}

fn write_plan(repo: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = repo.join(name);
    fs::write(&path, contents).expect("write plan");
    path
}

fn git_common_maco_exists(repo: &Path) -> bool {
    repo.join(".git").join("maco").exists()
}

#[test]
fn plan_without_refs_validates_without_creating_a_store() {
    let (_temp, repo) = init_repo();
    let plan = write_plan(&repo, "plan.json", &plan_json(None));

    supervisor_plan_from_task_file(&repo, &plan).expect("plan without refs must load");
    assert!(DecisionStore::open_existing(&repo)
        .expect("read-only query")
        .is_none());
    assert!(
        !git_common_maco_exists(&repo),
        "plan admission without refs must not create Git-common decision-store state"
    );
}

#[test]
fn plan_with_refs_and_missing_store_fails_closed() {
    let (_temp, repo) = init_repo();
    let plan = write_plan(
        &repo,
        "plan-refs.json",
        &plan_json(Some(
            r#"[{ "question_key": "api.transport", "expected_resolution": "Use HTTP" }]"#,
        )),
    );

    let error =
        supervisor_plan_from_task_file(&repo, &plan).expect_err("missing store must fail closed");
    assert!(
        error.to_string().contains("decision store is missing")
            || format!("{error:#}").contains("decision store is missing"),
        "missing-store refusal must be fail-closed: {error:#}"
    );
    assert!(
        !git_common_maco_exists(&repo),
        "fail-closed plan admission must not create Git-common decision-store state"
    );
}

#[test]
fn merge_without_refs_does_not_create_a_store() {
    let (_temp, repo) = init_repo();

    check_merge_arbitration_decision_refs(&repo, &[])
        .expect("merge without refs must not require a store");
    assert!(DecisionStore::open_existing(&repo)
        .expect("read-only query")
        .is_none());
    assert!(
        !git_common_maco_exists(&repo),
        "merge without refs must not create Git-common decision-store state"
    );
}

#[test]
fn merge_decision_ref_flag_fails_closed_when_store_is_missing() {
    let (_temp, repo) = init_repo();
    let reference = parse_decision_ref_cli("api.transport=Use HTTP").expect("valid citation");

    let error = check_merge_arbitration_decision_refs(&repo, &[reference])
        .expect_err("missing store must fail closed");
    assert!(
        error
            .downcast_ref::<DecisionRefError>()
            .is_some_and(|error| *error == DecisionRefError::StoreMissing)
            || error.to_string().contains("decision store is missing"),
        "merge --decision-ref must fail closed on a missing store: {error:#}"
    );
    assert!(
        !git_common_maco_exists(&repo),
        "merge fail-closed must not create Git-common decision-store state"
    );
}

#[test]
fn assignment_decision_refs_deserialize_via_decision_ref_new() {
    let reference: DecisionRef = serde_json::from_value(serde_json::json!({
        "question_key": "  api.transport  ",
        "expected_resolution": "  Use HTTP  "
    }))
    .expect("serde helper constructs DecisionRef");
    assert_eq!(reference.question_key(), "api.transport");
    assert_eq!(reference.expected_resolution(), Some("Use HTTP"));
}
