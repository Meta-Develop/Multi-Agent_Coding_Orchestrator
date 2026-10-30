use super::*;
use crate::external_agent::record_claude_completion_for_test;

#[test]
fn managed_claude_identity_refusal_preserves_reliable_settlement() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (command, run) =
        record_claude_completion_for_test(temp.path(), WorkspaceAccess::ReadWrite)?;
    assert!(command.uses_live_claude_managed_worker_budget());
    assert!(run.authenticated_claude_usage_complete());
    assert_eq!(run.authenticated_claude_model(), command.model.as_deref());
    assert_eq!(run.authenticated_claude_effort(), None);
    assert_eq!(run.exit_code, Some(0));
    assert!(run.error.is_none(), "{:?}", run.error);
    assert!(!run.publishable);
    assert!(!external_process_completed(
        &run,
        SupervisorRuntime::ClaudeCode
    ));
    assert!(external_safety_verified(
        &run,
        SupervisorRuntime::ClaudeCode
    ));

    let ledger = RunBudgetLedger::new(crate::supervise_budget::RunBudgetLimits {
        hard_tokens: Some(100),
        ..Default::default()
    })?;
    let reserved = ledger.reserve(BudgetReservationRequest {
        role: AgentRole::Worker,
        tokens: 10,
        cost_usd: None,
    })?;
    let mut reservation = DispatchBudgetReservation {
        ledger: &ledger,
        reservation: reserved.reservation().expect("admitted").clone(),
        pricing: None,
        pricing_model: None,
        state: DispatchBudgetReservationState::Reserved(SupervisorRuntime::ClaudeCode),
    };
    reservation.mark_invoked_for_runtime(SupervisorRuntime::ClaudeCode)?;
    let settlement = reservation.settle_bound_runtime(&run, &command)?;
    assert_eq!(settlement.reliability, DispatchUsageReliability::Reliable);
    assert_eq!(settlement.observed_usage, run.authenticated_claude_usage());
    let budget = ledger.report()?;
    assert_eq!(budget.consumed.tokens, 25);
    assert_eq!(budget.reserved.tokens, 0);
    assert!(budget.usage_complete && budget.new_dispatch_allowed);
    Ok(())
}

#[test]
fn claude_unknown_effort_preserves_readonly_auditor_completion_only() -> Result<()> {
    let readonly_root = tempfile::tempdir()?;
    let (command, readonly) =
        record_claude_completion_for_test(readonly_root.path(), WorkspaceAccess::ReadOnly)?;
    assert_eq!(
        command.agent_lifecycle.as_ref().unwrap().role,
        AgentRole::Auditor.as_str()
    );
    assert!(readonly.authenticated_claude_usage_complete());
    assert_eq!(
        readonly.authenticated_claude_model(),
        command.model.as_deref()
    );
    assert_eq!(readonly.authenticated_claude_effort(), None);
    assert!(readonly.error.is_none(), "{:?}", readonly.error);
    assert!(readonly.publishable);
    assert!(external_process_completed(
        &readonly,
        SupervisorRuntime::ClaudeCode
    ));

    let writable_root = tempfile::tempdir()?;
    let (_, mut writable) =
        record_claude_completion_for_test(writable_root.path(), WorkspaceAccess::ReadWrite)?;
    assert!(writable.authenticated_claude_usage_complete());
    assert_eq!(writable.authenticated_claude_effort(), None);
    assert!(writable.error.is_none(), "{:?}", writable.error);
    assert!(!writable.publishable);
    assert!(!external_process_completed(
        &writable,
        SupervisorRuntime::ClaudeCode
    ));
    // Isolate the completion call site from the independently enforced publication gate.
    writable.publishable = true;
    assert!(!external_process_completed(
        &writable,
        SupervisorRuntime::ClaudeCode
    ));
    Ok(())
}
