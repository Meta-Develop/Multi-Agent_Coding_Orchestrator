//! Execute third-party-judged role promotion/demotion and emit ledger records.
//!
//! This is the #221 execution slice: a judge verdict is accepted only from an
//! Auditor / read-only review-auditor, promotion to a delegating coordinator
//! is fail-closed, and a granted demotion strips delegation immediately. The
//! resulting [`RoleTransitionRecord`] is written onto the hierarchy ledger.

use super::*;
use crate::hierarchy_ledger::{
    RoleCategory as LedgerRoleCategory, RoleTransitionDecision as LedgerDecision,
    RoleTransitionEvidenceRecord as LedgerEvidence, RoleTransitionRecord,
};

/// Third-party verdict that may authorize a role transition.
///
/// The judge must be an Auditor / read-only review-auditor. Self-judgment is
/// refused and recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RoleTransitionJudgeVerdict {
    pub judge_agent_id: String,
    pub judge_role: AgentRole,
    pub judge_capability: ModelCapabilityClass,
    pub accepted: bool,
    pub uncertain: bool,
}

/// Outcome of a judged transition, including the ledger record to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutedRoleTransition {
    pub record: RoleTransitionRecord,
    pub kind: RoleTransitionKind,
    pub granted: bool,
    pub effective_category: RoleCategory,
    pub delegation_stripped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ResolvedModelAuthority<'a> {
    pub model: Option<&'a str>,
    pub capability: ModelCapabilityClass,
}

pub(super) fn model_capability_or_weak(model: Option<&str>) -> ResolvedModelAuthority<'_> {
    ResolvedModelAuthority {
        model,
        capability: model
            .and_then(trusted_model_capability)
            .unwrap_or(ModelCapabilityClass::WeakMechanical),
    }
}

/// Fail-closed execution of one judged promotion or demotion.
pub(super) fn execute_judged_role_transition(
    agent_id: &str,
    from: RoleCategory,
    to: RoleCategory,
    requester_agent_id: &str,
    parent_agent_id: &str,
    subject: ResolvedModelAuthority<'_>,
    verdict: &RoleTransitionJudgeVerdict,
) -> Result<ExecutedRoleTransition> {
    let promoting = grants_authority(from, to);
    let evidence = RoleTransitionEvidence {
        acceptance_grade: verdict.accepted && !verdict.uncertain,
        recorded: true,
        uncertain: verdict.uncertain,
    };
    if verdict.judge_agent_id == agent_id {
        return finish_transition(
            agent_id,
            from,
            to,
            requester_agent_id,
            &verdict.judge_agent_id,
            if promoting {
                RoleTransitionKind::Promotion
            } else {
                RoleTransitionKind::Demotion
            },
            false,
            "self_judged",
            evidence,
        );
    }
    if promoting && requester_agent_id == agent_id {
        return finish_transition(
            agent_id,
            from,
            to,
            requester_agent_id,
            &verdict.judge_agent_id,
            RoleTransitionKind::Promotion,
            false,
            "self_promotion",
            evidence,
        );
    }
    if promoting && !is_review_auditor_role(verdict.judge_role) {
        return finish_transition(
            agent_id,
            from,
            to,
            requester_agent_id,
            &verdict.judge_agent_id,
            RoleTransitionKind::Promotion,
            false,
            "judge_not_auditor",
            evidence,
        );
    }

    let request = RoleTransitionRequest {
        agent_id: agent_id.to_string(),
        from,
        to,
        requester_agent_id: requester_agent_id.to_string(),
        parent_agent_id: parent_agent_id.to_string(),
        judge_agent_id: verdict.judge_agent_id.clone(),
        judge_category: verdict.judge_role.authority_category(),
        judge_capability: verdict.judge_capability,
        subject_capability: subject.capability,
        evidence,
        reason: "assignment_role_transition".to_string(),
    };
    let decision = evaluate_role_transition(&request)?;
    let initially_granted = decision.decision == RoleTransitionDecisionKind::Granted;
    let subject_model_eligible = !initially_granted
        || to != RoleCategory::DelegatingCoordinator
        || validate_known_judgment_role_model(AgentRole::ChildOrchestrator, subject.model).is_ok();
    let granted = initially_granted && subject_model_eligible;
    let reason = if initially_granted && !subject_model_eligible {
        "subject_model_ineligible_for_coordinator"
    } else {
        ledger_reason_token(&decision)
    };
    finish_transition(
        agent_id,
        from,
        to,
        requester_agent_id,
        &verdict.judge_agent_id,
        decision.kind,
        granted,
        reason,
        evidence,
    )
}

/// Apply the parent-auditor verdict to a completed assignment and produce the
/// ledger record a supervise run should emit.
pub(super) fn consider_assignment_role_transition(
    assignment: &OrchestratorAssignment,
    parent_agent_id: &str,
    child_report: &OrchestratorReviewReport,
    subject: ResolvedModelAuthority<'_>,
    auditor_capability: ModelCapabilityClass,
) -> Result<Option<ExecutedRoleTransition>> {
    let held = assignment.role.authority_category();
    let verdict = extract_assignment_judge(assignment, child_report, auditor_capability);
    if held.may_delegate() {
        if verdict.accepted && !verdict.uncertain {
            return execute_judged_role_transition(
                &assignment.id,
                RoleCategory::NonDelegatingTerminalWorker,
                RoleCategory::DelegatingCoordinator,
                parent_agent_id,
                parent_agent_id,
                subject,
                &verdict,
            )
            .map(Some);
        }
        return execute_judged_role_transition(
            &assignment.id,
            RoleCategory::DelegatingCoordinator,
            RoleCategory::NonDelegatingTerminalWorker,
            parent_agent_id,
            parent_agent_id,
            subject,
            &verdict,
        )
        .map(Some);
    }
    if assignment.worker_assignments.is_empty() {
        return Ok(None);
    }
    execute_judged_role_transition(
        &assignment.id,
        RoleCategory::NonDelegatingTerminalWorker,
        RoleCategory::DelegatingCoordinator,
        parent_agent_id,
        parent_agent_id,
        subject,
        &verdict,
    )
    .map(Some)
}

fn extract_assignment_judge(
    assignment: &OrchestratorAssignment,
    child_report: &OrchestratorReviewReport,
    auditor_capability: ModelCapabilityClass,
) -> RoleTransitionJudgeVerdict {
    if let Some(report) = child_report
        .audit_reports
        .iter()
        .find(|report| is_parent_auditor_id(assignment, &report.id))
    {
        let accepted = match &child_report.review_lens_aggregate {
            Some(aggregate) => {
                aggregate.decision == ReviewAggregationDecision::Accept
                    && report.accepted
                    && !report_failed(report)
            }
            None => report.accepted && !report_failed(report),
        };
        return RoleTransitionJudgeVerdict {
            judge_agent_id: report.id.clone(),
            judge_role: report.role,
            judge_capability: auditor_capability,
            accepted,
            uncertain: false,
        };
    }
    RoleTransitionJudgeVerdict {
        judge_agent_id: review_lens_auditor_id(assignment, 0),
        judge_role: AgentRole::Auditor,
        judge_capability: auditor_capability,
        accepted: false,
        uncertain: true,
    }
}

fn is_review_auditor_role(role: AgentRole) -> bool {
    matches!(role, AgentRole::Auditor | AgentRole::GateClassifier)
}

fn grants_authority(from: RoleCategory, to: RoleCategory) -> bool {
    (to.may_delegate() && !from.may_delegate())
        || (to.may_write() && !from.may_write())
        || (to.may_judge_acceptance() && !from.may_judge_acceptance())
}

fn to_ledger_category(category: RoleCategory) -> LedgerRoleCategory {
    match category {
        RoleCategory::DelegatingCoordinator => LedgerRoleCategory::DelegatingCoordinator,
        RoleCategory::NonDelegatingTerminalWorker => {
            LedgerRoleCategory::NonDelegatingTerminalWorker
        }
        RoleCategory::ReadOnlyResearcher => LedgerRoleCategory::ReadOnlyResearcher,
        RoleCategory::ReadOnlyReviewAuditor => LedgerRoleCategory::ReadOnlyReviewAuditor,
    }
}

fn ledger_reason_token(decision: &RoleTransitionDecision) -> &'static str {
    if decision.decision == RoleTransitionDecisionKind::Granted {
        return match decision.kind {
            RoleTransitionKind::Promotion => "granted_promotion",
            RoleTransitionKind::Demotion => "granted_demotion",
        };
    }
    let reason = decision.reason.as_str();
    if reason.contains("self-judged") {
        "self_judged"
    } else if reason.contains("judged by the requester") {
        "requester_judged"
    } else if reason.contains("direct parent") {
        "direct_parent_judged"
    } else if reason.contains("read-only review-auditor") {
        "judge_not_auditor"
    } else if reason.contains("weak-model") || reason.contains("critical-judgment") {
        "weak_model_judge"
    } else if reason.contains("acceptance-grade") {
        "insufficient_gate_evidence"
    } else if reason.contains("capability floor") {
        "weak_model_cannot_delegate"
    } else if reason.contains("uncertain") {
        "uncertain_evidence"
    } else if reason.contains("recorded") {
        "unrecorded_evidence"
    } else {
        "refused_role_transition"
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_transition(
    agent_id: &str,
    from: RoleCategory,
    to: RoleCategory,
    requester_agent_id: &str,
    judge_agent_id: &str,
    kind: RoleTransitionKind,
    granted: bool,
    reason: &'static str,
    evidence: RoleTransitionEvidence,
) -> Result<ExecutedRoleTransition> {
    let record = RoleTransitionRecord {
        agent_id: agent_id.to_string(),
        from_category: to_ledger_category(from),
        to_category: to_ledger_category(to),
        requester_agent_id: requester_agent_id.to_string(),
        judge_agent_id: judge_agent_id.to_string(),
        evidence: LedgerEvidence {
            acceptance_grade: evidence.acceptance_grade,
            recorded: evidence.recorded,
            uncertain: evidence.uncertain,
        },
        decision: if granted {
            LedgerDecision::Granted
        } else {
            LedgerDecision::Refused
        },
        reason: reason.to_string(),
    };
    record.validate()?;
    let effective_category = if granted { to } else { from };
    let delegation_stripped = granted
        && kind == RoleTransitionKind::Demotion
        && from.may_delegate()
        && !to.may_delegate();
    Ok(ExecutedRoleTransition {
        record,
        kind,
        granted,
        effective_category,
        delegation_stripped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy_ledger::{
        reconstruct_hierarchy_ledger, role_transition_payload, RoleTransitionDecision,
        ROLE_TRANSITION_FIELD,
    };
    use crate::orchestration_event::{
        OrchestrationEvent, OrchestrationEventKind, OrchestrationRole,
    };

    fn auditor_verdict(accepted: bool) -> RoleTransitionJudgeVerdict {
        RoleTransitionJudgeVerdict {
            judge_agent_id: "child-a-review-auditor-lens-0".into(),
            judge_role: AgentRole::Auditor,
            judge_capability: ModelCapabilityClass::CriticalJudgment,
            accepted,
            uncertain: false,
        }
    }

    fn ledger_event(record: &RoleTransitionRecord) -> OrchestrationEvent {
        OrchestrationEvent {
            ts: "2026-08-23T00:00:00Z".to_string(),
            repo: "repo-id".to_string(),
            run: "run-1".to_string(),
            node: record.agent_id.clone(),
            parent: Some("run-1".to_string()),
            role: OrchestrationRole::Orchestrator,
            kind: OrchestrationEventKind::Journal,
            payload: role_transition_payload(record).expect("valid role-transition payload"),
        }
    }

    #[test]
    fn grant_records_third_party_promotion_on_the_hierarchy_ledger() -> Result<()> {
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(true),
        )?;
        assert!(executed.granted);
        assert_eq!(executed.kind, RoleTransitionKind::Promotion);
        assert!(!executed.delegation_stripped);
        assert_eq!(
            executed.effective_category,
            RoleCategory::DelegatingCoordinator
        );
        assert_eq!(executed.record.decision, RoleTransitionDecision::Granted);
        assert_eq!(executed.record.reason, "granted_promotion");
        assert_eq!(
            executed.record.judge_agent_id,
            "child-a-review-auditor-lens-0"
        );
        let snapshot = reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
        assert_eq!(snapshot.role_transitions.len(), 1);
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Granted
        );
        Ok(())
    }

    #[test]
    fn refuse_records_insufficient_acceptance_grade_evidence() -> Result<()> {
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(false),
        )?;
        assert!(!executed.granted);
        assert_eq!(executed.kind, RoleTransitionKind::Promotion);
        assert_eq!(executed.record.decision, RoleTransitionDecision::Refused);
        assert_eq!(executed.record.reason, "insufficient_gate_evidence");
        let snapshot = reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Refused
        );
        Ok(())
    }

    #[test]
    fn self_judge_and_child_self_grant_are_refused_and_recorded() -> Result<()> {
        let mut self_judge = auditor_verdict(true);
        self_judge.judge_agent_id = "worker-a".into();
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &self_judge,
        )?;
        assert!(!executed.granted);
        assert_eq!(executed.record.reason, "self_judged");
        reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;

        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "worker-a",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(true),
        )?;
        assert!(!executed.granted);
        assert_eq!(executed.record.reason, "self_promotion");
        reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
        Ok(())
    }

    #[test]
    fn weak_model_cannot_be_promoted_to_coordinator() -> Result<()> {
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(None),
            &auditor_verdict(true),
        )?;
        assert!(!executed.granted);
        assert_eq!(executed.kind, RoleTransitionKind::Promotion);
        assert_eq!(executed.record.reason, "weak_model_cannot_delegate");
        assert_eq!(
            executed.effective_category,
            RoleCategory::NonDelegatingTerminalWorker
        );
        reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
        Ok(())
    }

    #[test]
    fn resolved_luna_cannot_be_promoted_to_coordinator() -> Result<()> {
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-luna")),
            &auditor_verdict(true),
        )?;
        assert!(!executed.granted);
        assert_eq!(
            executed.record.reason,
            "subject_model_ineligible_for_coordinator"
        );
        Ok(())
    }

    #[test]
    fn transition_ledger_round_trip_retains_typed_evidence() -> Result<()> {
        let granted = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(true),
        )?;
        let refused = execute_judged_role_transition(
            "worker-b",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(false),
        )?;

        for (executed, acceptance_grade) in [(granted, true), (refused, false)] {
            let payload = role_transition_payload(&executed.record)?;
            let evidence = payload
                .get(ROLE_TRANSITION_FIELD)
                .and_then(|transition| transition.get("evidence"))
                .context("transition payload omitted typed evidence")?;
            assert_eq!(
                evidence,
                &serde_json::json!({
                    "acceptance_grade": acceptance_grade,
                    "recorded": true,
                    "uncertain": false,
                })
            );

            let snapshot = reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
            assert_eq!(snapshot.role_transitions.len(), 1);
            assert_eq!(
                role_transition_payload(&snapshot.role_transitions[0])?,
                payload
            );
        }
        Ok(())
    }

    #[test]
    fn demotion_strips_delegation_immediately_and_is_recorded() -> Result<()> {
        let executed = execute_judged_role_transition(
            "child-a",
            RoleCategory::DelegatingCoordinator,
            RoleCategory::NonDelegatingTerminalWorker,
            "run-1",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &auditor_verdict(false),
        )?;
        assert!(executed.granted);
        assert_eq!(executed.kind, RoleTransitionKind::Demotion);
        assert!(executed.delegation_stripped);
        assert_eq!(
            executed.effective_category,
            RoleCategory::NonDelegatingTerminalWorker
        );
        assert!(!executed.effective_category.may_delegate());
        assert_eq!(executed.record.reason, "granted_demotion");
        let snapshot = reconstruct_hierarchy_ledger(&[ledger_event(&executed.record)])?;
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Granted
        );
        Ok(())
    }

    #[test]
    fn non_auditor_cannot_grant_coordinator_promotion() -> Result<()> {
        let mut parent = auditor_verdict(true);
        parent.judge_agent_id = "run-1".into();
        parent.judge_role = AgentRole::Supervisor;
        parent.judge_capability = ModelCapabilityClass::GeneralJudgment;
        let executed = execute_judged_role_transition(
            "worker-a",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "other-req",
            "run-1",
            model_capability_or_weak(Some("gpt-5.6-sol")),
            &parent,
        )?;
        assert!(!executed.granted);
        assert_eq!(executed.record.reason, "judge_not_auditor");
        Ok(())
    }
}
