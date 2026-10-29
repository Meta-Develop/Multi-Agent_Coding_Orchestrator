use super::*;
use crate::selection;
use selection_bridge::tests::{bind_fixture_routing_policy, frozen_preflight_fixture};

fn plan() -> Result<SupervisorPlan> {
    Ok(serde_json::from_value(json!({
        "task": "inspect bounded source input", "assignments": [{
            "id": "inspect", "phase": "execution", "role": "researcher", "role_category": "read_only_researcher",
            "assigned_paths": ["src/lib.rs"], "worker_assignments": []
        }],
        "role_models": {
            "researcher": {"model": "gpt-6.1-sol", "reasoning_effort": "high"},
            "auditor": {"model": "gpt-6.1-sol", "reasoning_effort": "high"}
        },
        "review_lenses": [{"id": "authored", "information_scope": "full_child_transcript",
            "backend": {"kind": "model", "backend_id": "codex", "model": "gpt-6.1-sol", "reasoning_effort": "high"}}]
    }))?)
}

#[test]
fn collects_researcher_auditor_and_lens_rejections_from_one_snapshot() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let plan = plan()?;
    let before = plan.clone();
    let seals = crate::selection::routing_policy::captured_selected_authorizations();
    let inputs = frozen_preflight_fixture(&plan)?;
    let report = evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs)?;
    assert!(!report.compatible);
    for (role, lens) in [
        (AgentRole::Researcher, None),
        (AgentRole::Auditor, None),
        (AgentRole::Auditor, Some("authored")),
    ] {
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|entry| entry.role == role && entry.lens_id.as_deref() == lens)
            .context("diagnostic")?;
        assert_eq!(
            diagnostic.status,
            SelectionPreflightStatus::Rejected,
            "{diagnostic:?}"
        );
        assert_eq!(
            diagnostic.rejection,
            Some(SelectionPreflightRejection::EffortIncompatible)
        );
        assert!(diagnostic
            .eligible_efforts
            .as_ref()
            .is_some_and(|efforts| efforts.contains(&selection::ReasoningEffort::Xhigh)));
        assert!(diagnostic.task.is_some());
        assert!(diagnostic
            .decision
            .as_ref()
            .is_some_and(|decision| !decision.input_digests.priors.value.is_empty()));
    }
    assert_eq!(plan, before);
    let mut dispatch_plan = plan.clone();
    let resolution = selection_bridge::tests::initialize_preflight_fixture(&mut dispatch_plan)?;
    let failure = resolution
        .selection_preflight_failure
        .context("aggregate refusal")?;
    assert!(failure.message.contains("researcher"));
    assert!(failure.message.contains("auditor"));
    assert!(failure.message.contains("authored"));
    assert_eq!(dispatch_plan, before);
    assert_eq!(
        seals,
        crate::selection::routing_policy::captured_selected_authorizations()
    );
    Ok(())
}

#[test]
fn unknown_catalog_does_not_launch_or_invent_efforts() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let plan = plan()?;
    let mut inputs = frozen_preflight_fixture(&plan)?;
    let mut unknown_catalog = inputs.clone();
    unknown_catalog
        .roles
        .get_mut(&AgentRole::Researcher)
        .context("researcher")?
        .input
        .catalogs
        .clear();
    let unknown =
        evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, unknown_catalog)?;
    let researcher = unknown
        .diagnostics
        .iter()
        .find(|entry| entry.role == AgentRole::Researcher)
        .context("researcher")?;
    assert_eq!(researcher.status, SelectionPreflightStatus::Unknown);
    assert!(researcher.eligible_efforts.is_none());
    inputs.roles.clear();
    let report = evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs)?;
    assert!(!report.compatible);
    assert!(report
        .diagnostics
        .iter()
        .all(|entry| entry.status == SelectionPreflightStatus::Unknown
            && entry.eligible_efforts.is_none()
            && entry.decision.is_none()));
    assert!(crate::selection::routing_policy::captured_selected_authorizations().is_empty());
    Ok(())
}

#[test]
fn compatible_selection_preserves_exact_choice_and_reachability() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let mut plan = plan()?;
    for value in plan.role_models.values_mut() {
        value.reasoning_effort = Some("xhigh".to_string());
    }
    if let ReviewLensBackendConfig::Model {
        reasoning_effort, ..
    } = &mut plan.review_lenses[0].backend
    {
        *reasoning_effort = Some("xhigh".to_string());
    }
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("unavailable".to_string()),
            reasoning_effort: Some("low".to_string()),
            ..Default::default()
        },
    );
    let inputs = frozen_preflight_fixture(&plan)?;
    let report = evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs)?;
    assert!(report.compatible, "{:?}", report.diagnostics);
    assert!(!report
        .diagnostics
        .iter()
        .any(|entry| entry.role == AgentRole::Worker));
    for diagnostic in &report.diagnostics {
        if let Some(requested) = &diagnostic.requested {
            let choice = &diagnostic
                .decision
                .as_ref()
                .context("decision")?
                .choice
                .as_ref()
                .context("choice")?
                .candidate;
            assert_eq!(requested.model.as_deref(), Some(choice.model.as_str()));
            assert_eq!(requested.runtime, choice.runtime);
            assert_eq!(requested.effort.as_deref(), Some(choice.effort.as_str()));
        }
    }
    plan.role_models.clear();
    let automatic = evaluate_supervisor_selection_preflight(
        &plan,
        SupervisorRuntime::Codex,
        frozen_preflight_fixture(&plan)?,
    )?;
    assert!(automatic.compatible, "{:?}", automatic.diagnostics);
    assert!(crate::selection::routing_policy::captured_selected_authorizations().is_empty());
    Ok(())
}

#[test]
fn distinguishes_model_availability_and_authority_rejection() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let mut plan = plan()?;
    plan.role_models
        .get_mut(&AgentRole::Researcher)
        .context("researcher")?
        .model = Some("absent-model".to_string());
    let mut inputs = frozen_preflight_fixture(&plan)?;
    let auditor = inputs
        .roles
        .get_mut(&AgentRole::Auditor)
        .context("auditor")?;
    let model = auditor
        .input
        .catalogs
        .iter_mut()
        .flat_map(|catalog| &mut catalog.models)
        .find(|model| model.model == "gpt-6.1-sol")
        .context("model")?;
    model
        .supported_efforts
        .push(selection::ReasoningEffort::High);
    for entry in inputs.roles.values_mut() {
        entry
            .input
            .priors
            .models
            .iter_mut()
            .find(|prior| prior.model == "gpt-6.1-sol")
            .context("model prior")?
            .prohibited_authority_roles
            .insert(selection::AuthorityRole::ReviewAuditor);
    }
    let report = evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs)?;
    assert_eq!(
        report
            .diagnostics
            .iter()
            .find(|entry| entry.role == AgentRole::Researcher)
            .context("researcher")?
            .rejection,
        Some(SelectionPreflightRejection::ModelUnavailable)
    );
    let auditor = report
        .diagnostics
        .iter()
        .find(|entry| entry.role == AgentRole::Auditor)
        .context("auditor")?;
    assert_eq!(
        auditor.rejection,
        Some(SelectionPreflightRejection::Eligibility)
    );
    assert!(auditor
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == selection::IneligibilityCode::PolicyProhibited));
    Ok(())
}

#[test]
fn refuses_mixed_snapshot_revisions_and_plan_drift() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let plan = plan()?;
    let mut inputs = frozen_preflight_fixture(&plan)?;
    let original = inputs.clone();
    inputs
        .roles
        .get_mut(&AgentRole::Researcher)
        .context("researcher")?
        .input
        .priors
        .revision
        .push_str("-changed");
    assert!(
        evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs).is_err()
    );
    let mut changed = plan.clone();
    changed.task.push_str(" changed");
    assert!(
        evaluate_supervisor_selection_preflight(&changed, SupervisorRuntime::Codex, original)
            .is_err()
    );
    Ok(())
}

#[test]
fn unobserved_auxiliary_catalog_preserves_observed_primary_selection() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let mut plan = plan()?;
    plan.role_models.clear();
    plan.review_lenses = default_supervisor_review_lenses();
    let mut inputs = frozen_preflight_fixture(&plan)?;
    for entry in inputs.roles.values_mut() {
        entry
            .switch_cost_evidence
            .retain(|evidence| evidence.candidate.runtime != "grok");
        entry
            .input
            .catalogs
            .retain(|catalog| catalog.runtime != "grok");
        entry.input.catalogs.push(selection::RuntimeCatalog {
            runtime: "grok".to_string(),
            revision: format!(
                "account-observe-models-unobserved-sha256:{}",
                "a".repeat(64)
            ),
            advertised_at: "2026-10-29T00:00:00Z".to_string(),
            models: Vec::new(),
        });
        if !entry.input.pools.iter().any(|pool| pool.runtime == "grok") {
            let mut pool = entry.input.pools[0].clone();
            pool.runtime = "grok".to_string();
            entry.input.pools.push(pool);
        }
        entry
            .input
            .constraints
            .allowed_runtimes
            .insert("grok".to_string());
    }
    let report = evaluate_supervisor_selection_preflight(&plan, SupervisorRuntime::Codex, inputs)?;
    assert!(report.compatible);
    for diagnostic in &report.diagnostics {
        assert_eq!(diagnostic.status, SelectionPreflightStatus::Compatible);
        let decision = diagnostic.decision.as_ref().context("selector decision")?;
        assert_eq!(decision.status, selection::DecisionStatus::Selected);
        assert_eq!(
            decision
                .choice
                .as_ref()
                .context("choice")?
                .candidate
                .runtime,
            "codex"
        );
        assert!(decision
            .normalized_input
            .catalogs
            .iter()
            .any(|catalog| { catalog.runtime == "grok" && catalog.models.is_empty() }));
    }
    assert!(crate::selection::routing_policy::captured_selected_authorizations().is_empty());
    Ok(())
}

#[test]
fn failed_preflight_retains_selected_decisions_without_sealing_them() -> Result<()> {
    use super::scheduler::seal_successful_preflight_decisions;
    let _policy = bind_fixture_routing_policy()?;
    let mut plan = plan()?;
    let resolution = selection_bridge::tests::initialize_preflight_fixture(&mut plan)?;
    assert!(resolution.selection_preflight_failure.is_some());
    assert!(resolution
        .decisions
        .iter()
        .any(|event| event.provenance.status == selection::DecisionStatus::Selected));
    assert!(resolution
        .decisions
        .iter()
        .any(|event| event.provenance.status == selection::DecisionStatus::FailClosed));
    let before = crate::selection::routing_policy::captured_selected_authorizations();
    seal_successful_preflight_decisions(
        &resolution.decisions,
        resolution.selection_preflight_failure.as_ref(),
    )?;
    assert_eq!(
        before,
        crate::selection::routing_policy::captured_selected_authorizations()
    );

    plan.role_models.clear();
    plan.review_lenses = default_supervisor_review_lenses();
    let report = evaluate_supervisor_selection_preflight(
        &plan,
        SupervisorRuntime::Codex,
        frozen_preflight_fixture(&plan)?,
    )?;
    assert!(report.compatible);
    let decisions: Vec<_> = report
        .diagnostics
        .into_iter()
        .map(|entry| {
            Ok(SupervisorSelectionEvent {
                assignment_id: None,
                attempt: 0,
                role: entry.role,
                primary_cause: SupervisorSelectionEventCause::Initial,
                provenance: entry.decision.context("selected decision")?,
            })
        })
        .collect::<Result<_>>()?;
    seal_successful_preflight_decisions(&decisions, None)?;
    let authorizations = crate::selection::routing_policy::captured_selected_authorizations();
    assert_eq!(authorizations.len(), decisions.len());
    for event in decisions {
        assert_eq!(
            authorizations.get(event.role.as_str()),
            event
                .provenance
                .choice
                .as_ref()
                .map(|choice| &choice.candidate)
        );
    }
    Ok(())
}

#[test]
fn override_mismatch_fails_closed_without_runtime_mismatch_classification() -> Result<()> {
    use selection_bridge::selection_preflight::selected_choice_rejection;
    let _policy = bind_fixture_routing_policy()?;
    let mut plan = plan()?;
    plan.role_models.clear();
    plan.review_lenses = default_supervisor_review_lenses();
    let report = evaluate_supervisor_selection_preflight(
        &plan,
        SupervisorRuntime::Codex,
        frozen_preflight_fixture(&plan)?,
    )?;
    let mut decision = report
        .diagnostics
        .into_iter()
        .find_map(|entry| entry.decision)
        .context("selected decision")?;
    let candidate = decision
        .choice
        .as_ref()
        .context("choice")?
        .candidate
        .clone();
    decision.normalized_input.debug_override = Some(selection::DebugOverride {
        candidate,
        requested_by: "test".to_string(),
        reason: "exact authored override".to_string(),
    });
    assert_eq!(selected_choice_rejection(&decision), None);
    decision.choice.as_mut().context("choice")?.candidate.model = "different-model".to_string();
    assert_eq!(
        selected_choice_rejection(&decision),
        Some(SelectionPreflightRejection::InvalidContract)
    );
    decision
        .choice
        .as_mut()
        .context("choice")?
        .candidate
        .runtime = "unexecutable-runtime".to_string();
    assert_eq!(
        selected_choice_rejection(&decision),
        Some(SelectionPreflightRejection::UnexecutableRuntime)
    );
    decision.choice = None;
    assert_eq!(
        selected_choice_rejection(&decision),
        Some(SelectionPreflightRejection::InvalidContract)
    );
    Ok(())
}
