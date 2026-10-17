use super::*;
use crate::hierarchy_ledger::{RoleCategory, RoleTransitionDecision};

#[test]
fn selected_supervise_run_emits_granted_role_transition_ledger_record() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    // Promotion requires a known model sealed by the loaded-policy selector.
    // The selected fixture supplies account/catalog evidence and runs normal
    // selection; a legacy Fake run supplies no selector authorization.
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let run_id = RunId::new("selected-role-transition-ledger").expect("valid run id");
    let options = injected_options(&repo_path, temp.path(), run_id.as_str());
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    let mut runner = |command: &ExternalAgentCommand| {
        assert_eq!(command.model.as_deref(), Some(FRONTIER_PROFILE_MODEL));
        if command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .contains("review-auditor")
        {
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            validate_known_judgment_role_model(
                AgentRole::ChildOrchestrator,
                Some(FRONTIER_PROFILE_MODEL),
            )
            .expect("subject model must have a selector-sealed coordinator binding");
            write_injected_assignment_report(command, &assignment);
        }
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_selected_nested_review_fixture(
        plan,
        SupervisorConsultantPlan::default(),
        SupervisorBudgetConfig::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Some(catalog),
        &temp,
        &mut runner,
    )
    .expect("run selected supervise role-transition fixture");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert!(report
        .orchestrator_reports
        .iter()
        .any(|child| child.accepted && !child.audit_reports.is_empty()));

    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized selected supervise run");
    let events = read_finalized_orchestration_events(&reader);
    assert!(events.iter().any(|event| {
        event.node == assignment.id
            && event.parent.as_deref() == Some(run_id.as_str())
            && event.kind == OrchestrationEventKind::Journal
            && event.payload[ROLE_TRANSITION_FIELD]["agent_id"] == assignment.id
            && event.payload[ROLE_TRANSITION_FIELD]["from_category"]
                == "non_delegating_terminal_worker"
            && event.payload[ROLE_TRANSITION_FIELD]["to_category"] == "delegating_coordinator"
            && event.payload[ROLE_TRANSITION_FIELD]["requester_agent_id"] == run_id.as_str()
            && event.payload[ROLE_TRANSITION_FIELD]["decision"] == "granted"
            && event.payload[ROLE_TRANSITION_FIELD]["reason"] == "granted_promotion"
    }));
    let hierarchy = reconstruct_hierarchy_ledger(&events).expect("reconstruct hierarchy ledger");
    assert!(
        hierarchy.role_transitions.iter().any(|record| {
            record.agent_id == assignment.id
                && record.from_category == RoleCategory::NonDelegatingTerminalWorker
                && record.to_category == RoleCategory::DelegatingCoordinator
                && record.decision == RoleTransitionDecision::Granted
                && record.reason == "granted_promotion"
        }),
        "supervise run must emit a reconstructable Granted promotion record: {:#?}",
        hierarchy.role_transitions
    );
}
