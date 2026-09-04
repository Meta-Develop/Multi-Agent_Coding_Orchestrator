use super::*;
use crate::{
    gate_denial::ApprovalReviewDenial,
    pre_action_review::{
        ActionKind, BlastRadius, CommandClass, DecisionSource, RedactedClassifierAction,
        RedactedClassifierRequest,
    },
};

fn approval_denial(correlation_id: &str, reason: ApprovalReviewDenial) -> GateDenial {
    GateDenial::from_approval_review(
        correlation_id,
        "child-a",
        reason,
        std::iter::empty::<&Path>(),
    )
    .expect("construct typed approval denial")
}

fn review_decision_event(
    request_id: &str,
    allowed: bool,
    denial: Option<GateDenial>,
    rationale: PreActionJournalRationale,
) -> PreActionJournalRecord {
    PreActionJournalRecord {
        version: 1,
        run_id: "autonomy-kpi-run".to_string(),
        review_session_id: "autonomy-kpi-review-session".to_string(),
        phase: PreActionJournalPhase::ReviewDecision,
        thread_id: Some("thread-a".to_string()),
        turn_id: Some("turn-a".to_string()),
        item_id: Some(request_id.to_string()),
        request: Some(RedactedClassifierRequest {
            version: 1,
            run_id: "autonomy-kpi-run".to_string(),
            request_id: request_id.to_string(),
            owner: "child-a".to_string(),
            intent_summary: "redacted test intent".to_string(),
            claims: Vec::new(),
            sensitive_paths: Vec::new(),
            action: RedactedClassifierAction {
                kind: ActionKind::FileChange,
                program: None,
                arguments: Vec::new(),
                command_class: CommandClass::WorkspaceMutation,
                blast_radius: BlastRadius::SingleClaimedPath,
                accesses: Vec::new(),
                access_manifest_complete: false,
            },
        }),
        decision_source: Some(if allowed {
            DecisionSource::DeterministicAllow
        } else {
            DecisionSource::DeterministicDeny
        }),
        decision_latency_ms: Some(1),
        rationale,
        allowed: Some(allowed),
        denial,
        turn_status: None,
        item_outcomes: Vec::new(),
        process_exit_code: None,
        process_tree: None,
        side_effects: None,
    }
}

#[test]
fn interrupted_typed_gate_events_keep_counters_without_confident_rates() {
    let corrected = approval_denial(
        "correction-reviewed-denial",
        ApprovalReviewDenial::ClassifierDenied,
    );
    let human = approval_denial(
        "correction-human-denial",
        ApprovalReviewDenial::HumanReviewRequired,
    );
    let mut collector = AutonomyKpiCollector::default();
    collector.observe_pre_action_event(&review_decision_event(
        "request-allowed",
        true,
        None,
        PreActionJournalRationale::DeterministicPolicyAllow,
    ));
    collector.observe_pre_action_event(&review_decision_event(
        "request-corrected",
        false,
        Some(corrected.clone()),
        PreActionJournalRationale::DeterministicPolicyDeny,
    ));
    collector.observe_pre_action_event(&review_decision_event(
        "request-human",
        false,
        Some(human.clone()),
        PreActionJournalRationale::HumanInterventionRequired,
    ));
    collector.observe_gate_correction_event(&corrected, GateCorrectionJournalState::Blocked, None);
    collector.observe_gate_correction_event(
        &corrected,
        GateCorrectionJournalState::CorrectionAttempt,
        Some(1),
    );
    collector.observe_gate_correction_event(
        &corrected,
        GateCorrectionJournalState::Terminal(GateCorrectionTerminalClass::SelfCorrected),
        Some(1),
    );
    collector.observe_gate_correction_event(&human, GateCorrectionJournalState::Blocked, None);
    collector.observe_gate_correction_event(
        &human,
        GateCorrectionJournalState::Terminal(GateCorrectionTerminalClass::Escalated),
        Some(0),
    );

    let report = collector.report(true);
    assert_eq!(
        report.observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(
        report.population,
        AutonomyKpiPopulation::ReviewedGateActions
    );
    assert_eq!(
        report.coverage.review_decisions.observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(
        report
            .coverage
            .reviewed_denial_terminal_lifecycles
            .observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(
        report.coverage.human_follow_up_responses.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(
        report
            .coverage
            .scheduler_budget_denial_lifecycles
            .observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(report.actions_reviewed, Some(3));
    assert_eq!(report.denials, Some(2));
    assert_eq!(report.self_corrections, Some(1));
    assert_eq!(report.human_escalations, Some(1));
    assert_eq!(report.interrupted, Some(true));
    assert_eq!(
        report.coverage.rate_denominators.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(report
        .coverage
        .rate_denominators
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("interrupted by required human intervention")));
    assert_eq!(report.denial_rate, None);
    assert_eq!(report.self_correction_rate, None);
    assert_eq!(report.interruption_rate, None);
    let human_action = report
        .reviewed_actions
        .iter()
        .find(|action| action.action_gate_id == "request-human")
        .expect("human-targeted reviewed action");
    assert_eq!(
        human_action.human_intervention,
        Some(HumanInterventionRecord {
            target: HumanInterventionTarget::Human,
            outcome: HumanInterventionOutcome::InterventionRequired,
        })
    );
    assert!(report
        .reviewed_actions
        .iter()
        .filter(|action| action.action_gate_id != "request-human")
        .all(|action| action.human_intervention.is_none()));
    assert_eq!(report.gate_lifecycles.len(), 2);
    assert!(report.gate_lifecycles.iter().any(|lifecycle| {
        lifecycle.denial_id == corrected.denial_id.as_str()
            && lifecycle.correction_correlation_id == corrected.correction_correlation_id.as_str()
            && lifecycle.correction_attempts == 1
            && lifecycle.terminal_outcome == Some(GateCorrectionTerminalClass::SelfCorrected)
    }));
}

#[test]
fn completed_typed_gate_events_report_explicit_denominators() {
    let corrected = approval_denial(
        "completed-correction-reviewed-denial",
        ApprovalReviewDenial::ClassifierDenied,
    );
    let mut collector = AutonomyKpiCollector::default();
    collector.observe_pre_action_event(&review_decision_event(
        "completed-request-allowed",
        true,
        None,
        PreActionJournalRationale::DeterministicPolicyAllow,
    ));
    collector.observe_pre_action_event(&review_decision_event(
        "completed-request-corrected",
        false,
        Some(corrected.clone()),
        PreActionJournalRationale::DeterministicPolicyDeny,
    ));
    collector.observe_gate_correction_event(
        &corrected,
        GateCorrectionJournalState::Terminal(GateCorrectionTerminalClass::SelfCorrected),
        Some(1),
    );

    let report = collector.report(true);
    assert_eq!(report.actions_reviewed, Some(2));
    assert_eq!(report.denials, Some(1));
    assert_eq!(report.self_corrections, Some(1));
    assert_eq!(report.human_escalations, Some(0));
    assert_eq!(report.interrupted, Some(false));
    assert_eq!(
        report.coverage.rate_denominators.observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(
        report.denial_rate,
        Some(RatioMetric {
            numerator: 1,
            denominator: 2,
        })
    );
    assert_eq!(
        report.self_correction_rate,
        Some(RatioMetric {
            numerator: 1,
            denominator: 1,
        })
    );
    assert_eq!(
        report.interruption_rate,
        Some(RatioMetric {
            numerator: 0,
            denominator: 1,
        })
    );
}

#[test]
fn disabled_journal_reports_unmeasured_instead_of_zero() {
    let mut collector = AutonomyKpiCollector::default();
    collector.observe_pre_action_event(&review_decision_event(
        "request-observed-before-disable",
        true,
        None,
        PreActionJournalRationale::DeterministicPolicyAllow,
    ));

    let report = collector.report(false);
    assert_eq!(report, AutonomyKpiReport::default());
    assert_eq!(
        report.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(report.actions_reviewed, None);
    assert_eq!(report.denials, None);
    assert_eq!(report.self_corrections, None);
    assert_eq!(report.human_escalations, None);
    assert_eq!(report.interrupted, None);
    assert_eq!(
        report.coverage.review_decisions.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(
        report
            .coverage
            .reviewed_denial_terminal_lifecycles
            .observation,
        RoleUsageObservation::NotProcessObservable
    );
}

#[test]
fn human_intervention_cancellation_producer_path_suppresses_partial_run_rates() {
    let (_temp, repo_path) = injected_repository();
    let run_id = RunId::new("human-cancellation-rate-gap").expect("valid cancellation run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo_path,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "human-cancellation-rate-gap-test",
    )
    .expect("reserve cancellation artifact run");
    let mut journal = Some(OrchestrationEventJournal::new(
        "human-cancellation-test-repository",
        run_id.as_str(),
    ));
    let mut collector = AutonomyKpiCollector::default();
    let corrected = approval_denial(
        "producer-completed-before-human",
        ApprovalReviewDenial::ClassifierDenied,
    );
    let human = approval_denial(
        "producer-human-cancellation",
        ApprovalReviewDenial::HumanReviewRequired,
    );
    let mutation_session = SupervisorRunMutationSession::local_for_test(run_id.as_str());

    {
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut collector,
            checkpoint: None,
            mutation_session: &mutation_session,
        });
        let mut review_sink = SupervisorPreActionJournalSink {
            artifacts: &artifacts,
            node: "child-a",
            parent: Some(run_id.as_str()),
        };
        review_sink
            .append(&review_decision_event(
                "producer-completed-request",
                false,
                Some(corrected.clone()),
                PreActionJournalRationale::DeterministicPolicyDeny,
            ))
            .expect("produce completed reviewed denial through strict journal sink");
        let mut tracker = GateCorrectionTracker::new(1);
        let mut health_signals = Vec::new();
        assert!(tracker
            .authorize(
                corrected,
                &artifacts,
                "child-a",
                run_id.as_str(),
                &mut health_signals,
            )
            .expect("produce correction lifecycle through gate tracker")
            .is_some());
        tracker
            .self_corrected(&artifacts, "child-a", run_id.as_str())
            .expect("produce self-corrected terminal lifecycle");

        // external_agent emits this exact typed rationale when it returns
        // ApprovalReview::cancel for a required human intervention.
        review_sink
            .append(&review_decision_event(
                "producer-human-request",
                false,
                Some(human),
                PreActionJournalRationale::HumanInterventionRequired,
            ))
            .expect("produce human-intervention cancellation through strict journal sink");
    }

    let report = collector.report(true);
    assert_eq!(report.actions_reviewed, Some(2));
    assert_eq!(report.denials, Some(2));
    assert_eq!(report.self_corrections, Some(1));
    assert_eq!(report.human_escalations, Some(1));
    assert_eq!(report.interrupted, Some(true));
    assert_eq!(report.denial_rate, None);
    assert_eq!(report.self_correction_rate, None);
    assert_eq!(report.interruption_rate, None);
    assert_eq!(
        report.coverage.rate_denominators.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(report
        .coverage
        .rate_denominators
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("interrupted by required human intervention")));
}

#[test]
fn legacy_autonomy_kpi_report_defaults_new_population_and_coverage_fields() {
    let report = serde_json::from_value::<AutonomyKpiReport>(json!({
        "observation": "supervisor_aggregate",
        "actions_reviewed": 1,
        "denials": 0,
        "self_corrections": 0,
        "human_escalations": 0,
        "interrupted": false
    }))
    .expect("deserialize pre-coverage autonomy KPI report");

    assert_eq!(
        report.population,
        AutonomyKpiPopulation::ReviewedGateActions
    );
    assert_eq!(
        report.coverage.review_decisions.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(
        report
            .coverage
            .scheduler_budget_denial_lifecycles
            .observation,
        RoleUsageObservation::NotProcessObservable
    );

    let legacy_nested_coverage = serde_json::from_value::<AutonomyKpiReport>(json!({
        "observation": "supervisor_aggregate",
        "population": "reviewed_gate_actions",
        "coverage": {
            "review_decisions": {"observation": "supervisor_aggregate"},
            "reviewed_denial_terminal_lifecycles": {
                "observation": "supervisor_aggregate"
            },
            "human_follow_up_responses": {
                "observation": "not_process_observable",
                "unavailable_reason": "legacy gap"
            },
            "scheduler_budget_denial_lifecycles": {
                "observation": "not_process_observable",
                "unavailable_reason": "legacy gap"
            }
        },
        "actions_reviewed": 1,
        "denials": 0,
        "self_corrections": 0,
        "human_escalations": 0,
        "interrupted": false
    }))
    .expect("deserialize report with pre-rate-denominator coverage");
    assert_eq!(
        legacy_nested_coverage
            .coverage
            .rate_denominators
            .observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(legacy_nested_coverage
        .coverage
        .rate_denominators
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not recorded by this report version")));
}

fn producer_path_join_report(
    unreviewed_first: bool,
) -> (AutonomyKpiReport, GateDenial, GateDenial) {
    let (_temp, repo_path) = injected_repository();
    let run_id = RunId::new(if unreviewed_first {
        "autonomy-kpi-producer-reverse"
    } else {
        "autonomy-kpi-producer-forward"
    })
    .expect("valid producer-path run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo_path,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "autonomy-kpi-producer-join-test",
    )
    .expect("reserve producer-path artifact run");
    let mut journal = Some(OrchestrationEventJournal::new(
        "autonomy-kpi-producer-repository",
        run_id.as_str(),
    ));
    let mut collector = AutonomyKpiCollector::default();
    let reviewed = approval_denial(
        "producer-reviewed-correlation",
        ApprovalReviewDenial::ClassifierDenied,
    );
    let unreviewed = approval_denial(
        "producer-unreviewed-correlation",
        ApprovalReviewDenial::ClassifierDenied,
    );
    let mutation_session = SupervisorRunMutationSession::local_for_test(run_id.as_str());

    {
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut collector,
            checkpoint: None,
            mutation_session: &mutation_session,
        });
        let mut review_sink = SupervisorPreActionJournalSink {
            artifacts: &artifacts,
            node: "child-a",
            parent: Some(run_id.as_str()),
        };
        review_sink
            .append(&review_decision_event(
                "producer-reviewed-request",
                false,
                Some(reviewed.clone()),
                PreActionJournalRationale::DeterministicPolicyDeny,
            ))
            .expect("produce reviewed denial through strict journal sink");

        let lifecycle_order = if unreviewed_first {
            [unreviewed.clone(), reviewed.clone()]
        } else {
            [reviewed.clone(), unreviewed.clone()]
        };
        let mut tracker = GateCorrectionTracker::new(2);
        let mut health_signals = Vec::new();
        for denial in lifecycle_order {
            assert!(tracker
                .authorize(
                    denial,
                    &artifacts,
                    "child-a",
                    run_id.as_str(),
                    &mut health_signals,
                )
                .expect("authorize correction through gate tracker")
                .is_some());
            tracker
                .self_corrected(&artifacts, "child-a", run_id.as_str())
                .expect("terminalize correction through gate tracker");
        }
    }

    (collector.report(true), reviewed, unreviewed)
}

#[test]
fn producer_paths_join_terminal_lifecycles_only_to_reviewed_denials() {
    let (report, reviewed, unreviewed) = producer_path_join_report(false);
    assert_eq!(reviewed.denial_id, unreviewed.denial_id);
    assert_ne!(
        reviewed.correction_correlation_id,
        unreviewed.correction_correlation_id
    );
    assert_eq!(report.denials, Some(1));
    assert_eq!(report.self_corrections, Some(1));
    assert_eq!(
        report.self_correction_rate,
        Some(RatioMetric {
            numerator: 1,
            denominator: 1,
        })
    );
    assert_eq!(report.gate_lifecycles.len(), 1);
    assert_eq!(
        report.gate_lifecycles[0].denial_id,
        reviewed.denial_id.as_str()
    );
    assert_eq!(
        report.gate_lifecycles[0].correction_correlation_id,
        reviewed.correction_correlation_id.as_str()
    );
}

#[test]
fn producer_paths_reverse_order_join_is_full_identity_and_order_independent() {
    let (reverse_report, reviewed, unreviewed) = producer_path_join_report(true);
    let (forward_report, _, _) = producer_path_join_report(false);

    assert_eq!(reviewed.denial_id, unreviewed.denial_id);
    assert_ne!(
        reviewed.correction_correlation_id,
        unreviewed.correction_correlation_id
    );
    assert_eq!(reverse_report.denials, Some(1));
    assert_eq!(reverse_report.self_corrections, Some(1));
    assert_eq!(reverse_report.denials, forward_report.denials);
    assert_eq!(
        reverse_report.self_corrections,
        forward_report.self_corrections
    );
    assert_eq!(
        reverse_report.self_correction_rate,
        forward_report.self_correction_rate
    );
    assert_eq!(
        reverse_report.gate_lifecycles,
        forward_report.gate_lifecycles
    );
    assert_eq!(reverse_report.gate_lifecycles.len(), 1);
    assert_eq!(
        reverse_report.gate_lifecycles[0].correction_correlation_id,
        reviewed.correction_correlation_id.as_str()
    );
}

#[test]
fn terminal_and_peer_routing_events_do_not_count_as_reviewed_human_actions() {
    let (_temp, repo_path) = injected_repository();
    let run_id = RunId::new("peer-routing-not-human").expect("valid peer-routing run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo_path,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "peer-routing-kpi-test",
    )
    .expect("reserve peer-routing artifact run");
    let mut journal = Some(OrchestrationEventJournal::new(
        "peer-routing-test-repository",
        run_id.as_str(),
    ));
    let mut collector = AutonomyKpiCollector::default();
    let mut terminal = review_decision_event(
        "request-terminal",
        false,
        None,
        PreActionJournalRationale::TerminalEvidence,
    );
    terminal.phase = PreActionJournalPhase::ProcessTerminal;
    terminal.request = None;
    terminal.allowed = None;
    collector.observe_pre_action_event(&terminal);
    let mutation_session = SupervisorRunMutationSession::local_for_test(run_id.as_str());

    {
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut collector,
            checkpoint: None,
            mutation_session: &mutation_session,
        });
        record_shared_orchestration_event(
            &artifacts,
            "peer-o2",
            Some(run_id.as_str()),
            OrchestrationRole::Supervisor,
            OrchestrationEventKind::Escalate,
            json!({
                "origin": "child-a",
                "target": "peer_o2",
                "outcome": "routed",
            }),
        )
        .expect("append generic peer-routing escalation");
    }

    // Only a typed ReviewDecision with HumanInterventionRequired can increment the human
    // counters, so terminal evidence and the generic peer-routing event leave them at zero.
    let report = collector.report(true);
    assert_eq!(report.actions_reviewed, Some(0));
    assert_eq!(report.denials, Some(0));
    assert_eq!(report.human_escalations, Some(0));
    assert_eq!(report.interrupted, Some(false));
    assert_eq!(report.denial_rate, None);
    assert_eq!(report.interruption_rate, None);
}
