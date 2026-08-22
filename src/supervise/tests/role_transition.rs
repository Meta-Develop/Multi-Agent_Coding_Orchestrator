use super::*;
use crate::hierarchy_ledger::{RoleCategory, RoleTransitionDecision};

#[test]
fn fake_supervise_run_emits_granted_role_transition_ledger_record() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let run_id = RunId::new("fake-role-transition-ledger").expect("valid run id");
    let mut options = injected_options(&repo_path, temp.path(), run_id.as_str());
    options.runtime = SupervisorRuntime::Fake;
    let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
        panic!("fake runtime must not invoke the external runner")
    };

    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run fake supervise role-transition fixture");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert!(report
        .orchestrator_reports
        .iter()
        .any(|child| child.accepted && !child.audit_reports.is_empty()));

    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized fake supervise run");
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
