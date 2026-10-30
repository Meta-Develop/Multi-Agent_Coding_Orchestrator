use super::*;
use crate::selection::{
    routing_policy::{
        bind_routing_policy, captured_selected_authorizations, current_routing_policy,
        load_routing_policy, seal_selected_candidate, RoutingPolicyReceipt, TaskRoutingFeatures,
    },
    select_with_loaded_routing_policy, selection_test_base_input, CandidateKey, DecisionStatus,
    ReasoningEffort, SelectionProvenance,
};
use git2::Repository;
use tempfile::TempDir;

fn selected_candidate(role: AgentRole) -> Result<SelectionProvenance> {
    selected_candidate_for_model(role, "gpt-6.1-sol")
}

fn selected_candidate_for_model(role: AgentRole, model: &str) -> Result<SelectionProvenance> {
    let receipt = RoutingPolicyReceipt {
        frozen: current_routing_policy().context("active test policy")?,
        role: role.as_str().into(),
        features: TaskRoutingFeatures {
            scope_paths: 1,
            scope_modules: 1,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 0,
            independent_groups: 1,
            evidence: vec!["bounded test scope".into()],
        },
    };
    let mut input = selection_test_base_input();
    input.catalogs.truncate(1);
    input.catalogs[0].models.truncate(1);
    input.catalogs[0].models[0].model = model.into();
    input.catalogs[0].models[0].supported_efforts = vec![ReasoningEffort::Xhigh];
    input.pools.truncate(1);
    let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert_eq!(decision.status, DecisionStatus::Selected);
    assert_eq!(
        decision
            .choice
            .as_ref()
            .context("selected candidate")?
            .candidate,
        CandidateKey {
            runtime: "codex".into(),
            model: model.into(),
            effort: ReasoningEffort::Xhigh,
        }
    );
    Ok(decision)
}

fn metadata(repo: &Path, role: AgentRole) -> Result<AgentLaunchMetadata> {
    AgentLaunchMetadata::new(repo, role.as_str(), "selector-authority", "assignment")
}

fn argv() -> Vec<String> {
    [
        "codex",
        "exec",
        "--model",
        "gpt-6.1-sol",
        "-c",
        "model_reasoning_effort=\"xhigh\"",
    ]
    .map(str::to_string)
    .into()
}

fn assert_selector_refusal(result: Result<()>) {
    let error = result.expect_err("missing exact role/model selection must refuse launch");
    assert!(
        error
            .to_string()
            .contains("selector-authorized loaded-policy binding"),
        "{error:#}"
    );
}

#[test]
fn researcher_launch_accepts_own_selector_authorization_without_worker_binding() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    let decision = selected_candidate(AgentRole::Researcher)?;
    seal_selected_candidate("researcher", &decision)?;
    let authorizations = captured_selected_authorizations();
    assert_eq!(authorizations.len(), 1);
    assert!(authorizations.contains_key("researcher"));
    assert!(!authorizations.contains_key("worker"));

    authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &argv(),
        temp.path(),
        None,
    )?;
    let authority = derive_launch_authority("researcher", &argv(), None)?;
    assert_eq!(authority.category, RoleCategory::ReadOnlyResearcher);
    assert_eq!(authority.requested_model.as_deref(), Some("gpt-6.1-sol"));
    assert_eq!(authority.source, "role_and_exact_requested_argv");
    assert!(!authority.may_delegate);
    assert!(!authority.may_write);
    assert!(!authority.may_judge_acceptance);
    assert!(!authority.may_mutate_git_history);
    assert!(!authority.probe_only);
    Ok(())
}

#[test]
fn researcher_launch_requires_own_selector_authorization() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    let _unsealed = selected_candidate(AgentRole::Researcher)?;
    assert!(captured_selected_authorizations().is_empty());
    assert_selector_refusal(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &argv(),
        temp.path(),
        None,
    ));
    let missing_model = ["codex".into(), "exec".into()];
    assert!(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &missing_model,
        temp.path(),
        None,
    )
    .is_err());
    Ok(())
}

#[test]
fn worker_and_researcher_selector_authorizations_do_not_cross_authorize() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    for (selected, refused) in [
        (AgentRole::Worker, AgentRole::Researcher),
        (AgentRole::Researcher, AgentRole::Worker),
    ] {
        let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
        seal_selected_candidate(selected.as_str(), &selected_candidate(selected)?)?;
        assert_eq!(captured_selected_authorizations().len(), 1);
        assert_selector_refusal(authorize_process_launch_before_spawn(
            &metadata(temp.path(), refused)?,
            &argv(),
            temp.path(),
            None,
        ));
    }
    Ok(())
}

#[test]
fn researcher_launch_rejects_model_outside_own_selector_authorization() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    seal_selected_candidate("researcher", &selected_candidate(AgentRole::Researcher)?)?;
    seal_selected_candidate(
        "worker",
        &selected_candidate_for_model(AgentRole::Worker, "unselected-model")?,
    )?;
    assert_eq!(captured_selected_authorizations().len(), 2);
    let mut changed = argv();
    changed[3] = "unselected-model".into();
    authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Worker)?,
        &changed,
        temp.path(),
        None,
    )?;
    assert_selector_refusal(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &changed,
        temp.path(),
        None,
    ));
    Ok(())
}
