use super::*;

fn configured_plan_document(
    max_gate_corrections: u8,
    threshold: u8,
    max_low_severity: &str,
) -> serde_json::Value {
    let mut document = serde_json::to_value(injected_plan(injected_assignment(false), 0))
        .expect("serialize review-loop plan fixture");
    document["max_gate_corrections"] = json!(max_gate_corrections);
    document["review_loop_guard"] = json!({
        "max_low_severity": max_low_severity,
        "consecutive_low_severity_cycles": threshold
    });
    document
}

fn generated_follow_up_fixture(
    review_loop_guard: Option<ReviewLoopGuardConfig>,
) -> GeneratedFollowUpSupervisorPlan {
    let mut ordinary = injected_plan(injected_assignment(false), 0);
    ordinary.max_gate_corrections = 2;
    let assignment_id = ordinary.assignments[0].id.clone();
    GeneratedFollowUpSupervisorPlan {
        version: ordinary.version,
        task: ordinary.task.clone(),
        task_file: ordinary.task_file.clone(),
        max_depth: ordinary.max_depth,
        max_child_assignments: ordinary.max_child_assignments,
        max_child_retries: ordinary.max_child_retries,
        max_gate_corrections: ordinary.max_gate_corrections,
        child_timeout_seconds: ordinary.child_timeout_seconds,
        semantic_coordination: ordinary.semantic_coordination,
        role_models: ordinary.role_models.clone(),
        model_pricing: ordinary.model_pricing.clone(),
        review_lenses: ordinary.review_lenses.clone(),
        review_aggregation_policy: ordinary.review_aggregation_policy,
        assignments: ordinary.assignments.clone(),
        spec_fragment_ids: Vec::new(),
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id,
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        run_budget: derived_generated_follow_up_budget(
            &ordinary,
            &injected_run_budget(None, None, None, None, 100, 100),
        )
        .expect("derive generated review-loop budget"),
        consultant: SupervisorConsultantPlan::default(),
        generated_follow_up: GeneratedFollowUpPlanContext {
            breaking_assignment_id: "source-assignment".to_string(),
            breaking_change: CandidateValidationBinding {
                version: 1,
                agent_id: "source-assignment".to_string(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "1111111111111111111111111111111111111111".to_string(),
            },
            declaration_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            failure_signature: "review-loop generated follow-up fixture".to_string(),
            migration_rationale: "exercise review-loop compatibility".to_string(),
            cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff: "deferred fixture handoff".to_string(),
            operator_defaults: generated_follow_up_operator_defaults_with_review_loop_guard(
                review_loop_guard,
            ),
        },
    }
}

fn review_auditor_with_finding(
    assignment: &OrchestratorAssignment,
    severity: FindingSeverity,
) -> AuditorReport {
    let child = injected_child_report(assignment);
    let mut auditor = injected_auditor_report(assignment, &child);
    auditor.findings.push(Finding {
        severity,
        message: format!("injected {severity:?} review finding"),
        paths: assignment.assigned_paths.clone(),
    });
    auditor.accepted = false;
    auditor.rejected = true;
    auditor.status = ReviewStatus::Failed;
    auditor.rejection_kind = Some(AuditorRejectionKind::ImplementationDefect);
    auditor
}

#[test]
fn review_loop_guard_plan_document_is_strict_bounded_and_round_trips() {
    let document = configured_plan_document(2, 2, "warning");
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&document).expect("serialize configured review-loop plan"),
    )
    .expect("parse configured review-loop plan");
    let expected = ReviewLoopGuardConfig {
        max_low_severity: ReviewLoopLowSeverity::Warning,
        consecutive_low_severity_cycles: 2,
    };
    assert_eq!(loaded.plan_metadata.review_loop_guard, Some(expected));

    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize configured review-loop plan");
    assert_eq!(
        normalized["review_loop_guard"],
        document["review_loop_guard"]
    );
    let resumed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("persist normalized review-loop plan"),
    )
    .expect("resume normalized review-loop plan document");
    assert_eq!(resumed.plan_metadata.review_loop_guard, Some(expected));

    let plan_only_json =
        serde_json::to_value(&resumed.plan).expect("serialize intentionally lossy plan-only model");
    assert!(plan_only_json.get("review_loop_guard").is_none());

    let mut legacy = document.clone();
    legacy
        .as_object_mut()
        .expect("legacy plan object")
        .remove("review_loop_guard");
    let legacy = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&legacy).expect("serialize legacy review-loop plan"),
    )
    .expect("historical plan without review-loop guard remains readable");
    assert_eq!(legacy.plan_metadata.review_loop_guard, None);
    let legacy_normalized = supervisor_plan_value(
        &legacy.plan,
        &legacy.consultant,
        &legacy.assignment_metadata,
        &legacy.plan_metadata,
    )
    .expect("normalize historical plan without guard");
    assert!(legacy_normalized.get("review_loop_guard").is_none());

    for (document, expected_message) in [
        (
            configured_plan_document(2, 0, "warning"),
            "must be between 1",
        ),
        (
            configured_plan_document(
                MAX_GATE_CORRECTIONS_LIMIT,
                MAX_GATE_CORRECTIONS_LIMIT.saturating_add(2),
                "warning",
            ),
            "must be between 1",
        ),
        (
            configured_plan_document(1, 3, "warning"),
            "must be at most max_gate_corrections + 1",
        ),
    ] {
        let error = parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&document).expect("serialize invalid review-loop plan"),
        )
        .expect_err("invalid review-loop threshold must fail closed");
        assert!(format!("{error:#}").contains(expected_message));
    }

    for invalid_guard in [
        json!({
            "max_low_severity": "error",
            "consecutive_low_severity_cycles": 1
        }),
        json!({
            "max_low_severity": "warning",
            "consecutive_low_severity_cycles": 1,
            "unexpected": true
        }),
    ] {
        let mut invalid = configured_plan_document(2, 1, "warning");
        invalid["review_loop_guard"] = invalid_guard;
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&invalid).expect("serialize strict review-loop plan")
        )
        .is_err());
    }
}

#[test]
fn generated_follow_up_and_evidence_schemas_preserve_review_loop_state() {
    let config = ReviewLoopGuardConfig {
        max_low_severity: ReviewLoopLowSeverity::Info,
        consecutive_low_severity_cycles: 2,
    };
    let generated = generated_follow_up_fixture(Some(config));
    validate_generated_follow_up_plan_document(&generated)
        .expect("generated follow-up accepts bounded review-loop guard");
    let bytes = serde_json::to_vec(&generated).expect("serialize generated review-loop plan");
    let reloaded = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bytes).expect("generated plan is UTF-8"),
    )
    .expect("cascade loader consumes generated review-loop plan");
    assert_eq!(reloaded.plan_metadata.review_loop_guard, Some(config));

    let historical_json = serde_json::to_value(generated_follow_up_fixture(None))
        .expect("serialize historical generated plan");
    let historical: GeneratedFollowUpSupervisorPlan = serde_json::from_value(historical_json)
        .expect("historical generated plan without review-loop guard remains readable");
    assert_eq!(
        generated_follow_up_review_loop_guard(&historical.generated_follow_up)
            .expect("decode historical generated plan defaults"),
        None
    );
    validate_generated_follow_up_plan_document(&historical)
        .expect("historical generated plan remains dispatchable");

    let evidence = ReviewLoopGuardEvidence {
        config,
        cycles: vec![ReviewLoopCycleRecord {
            cycle_ordinal: 1,
            highest_severity: None,
            low_severity: true,
            consecutive_low_severity_cycles: 1,
        }],
        stop_disposition: ReviewLoopStopDisposition::ThresholdNotReached,
        retry_suppressed: false,
        final_validation_floor: ReviewLoopValidationFloor::Passed,
        locked_review_accepted: true,
    };
    let evidence_json = serde_json::to_value(&evidence).expect("serialize review-loop evidence");
    let decoded: ReviewLoopGuardEvidence =
        serde_json::from_value(evidence_json).expect("round-trip strict review-loop evidence");
    assert_eq!(decoded, evidence);
    let mut invalid_evidence = serde_json::to_value(&evidence)
        .expect("serialize review-loop evidence for strictness check");
    invalid_evidence["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ReviewLoopGuardEvidence>(invalid_evidence).is_err());

    let config_schema = review_loop_guard_config_schema_value();
    assert_eq!(config_schema["additionalProperties"], false);
    assert_eq!(
        config_schema["properties"]["max_low_severity"]["enum"],
        json!(["info", "warning"])
    );
    assert_eq!(
        config_schema["properties"]["consecutive_low_severity_cycles"]["maximum"],
        MAX_REVIEW_LOOP_GUARD_CYCLES
    );
    let evidence_schema = review_loop_guard_evidence_schema_value();
    assert_eq!(evidence_schema["additionalProperties"], false);
    assert_eq!(
        evidence_schema["properties"]["cycles"]["maxItems"],
        MAX_REVIEW_LOOP_GUARD_CYCLES
    );
    let generated_json = serde_json::to_value(generated)
        .expect("serialize generated plan without widening its public schema");
    assert!(generated_json.get("review_loop_guard").is_none());

    let event = ReviewLoopGuardJournalEvent::CycleObserved {
        version: REVIEW_LOOP_GUARD_EVENT_VERSION,
        config,
        cycle: evidence.cycles[0].clone(),
    };
    let event_json = serde_json::to_value(&event).expect("serialize strict review-loop event");
    let decoded_event: ReviewLoopGuardJournalEvent =
        serde_json::from_value(event_json.clone()).expect("round-trip strict review-loop event");
    assert_eq!(decoded_event, event);
    let mut invalid_event = event_json;
    invalid_event["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ReviewLoopGuardJournalEvent>(invalid_event).is_err());
}

#[test]
fn generated_follow_up_review_loop_defaults_reject_partial_duplicate_and_malformed_state() {
    let config = ReviewLoopGuardConfig {
        max_low_severity: ReviewLoopLowSeverity::Warning,
        consecutive_low_severity_cycles: 2,
    };
    let valid = generated_follow_up_fixture(Some(config));

    let mut partial = valid.clone();
    partial.generated_follow_up.operator_defaults.pop();
    assert!(validate_generated_follow_up_plan_document(&partial).is_err());

    let mut duplicate = valid.clone();
    duplicate
        .generated_follow_up
        .operator_defaults
        .push(duplicate.generated_follow_up.operator_defaults[3].clone());
    assert!(validate_generated_follow_up_plan_document(&duplicate).is_err());

    let mut malformed = valid;
    malformed.generated_follow_up.operator_defaults[2].value = "error".to_string();
    assert!(validate_generated_follow_up_plan_document(&malformed).is_err());
}

#[test]
fn low_severity_threshold_durably_suppresses_retry_without_spending_correction_budget() {
    let (_temp, repo) = injected_repository();
    let run_id = RunId::new("review-loop-low-stop").expect("valid review-loop run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "review-loop-low-stop-test",
    )
    .expect("reserve review-loop artifacts");
    let run_dir = writer.run_dir().to_path_buf();
    let mut journal = Some(OrchestrationEventJournal::new(
        "review-loop-repo",
        run_id.as_str(),
    ));
    let mut autonomy_kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut writer,
        journal: &mut journal,
        autonomy_kpis: &mut autonomy_kpis,
        checkpoint: None,
    });
    let assignment = injected_assignment(false);
    let config = ReviewLoopGuardConfig {
        max_low_severity: ReviewLoopLowSeverity::Warning,
        consecutive_low_severity_cycles: 1,
    };
    let mut tracker = ReviewLoopGuardTracker::new(config);
    let warning = review_auditor_with_finding(&assignment, FindingSeverity::Warning);
    assert!(tracker
        .observe_real_parent_review(&artifacts, &assignment, "review-loop-parent", &[warning])
        .expect("observe low-severity review cycle"));

    let denial = GateDenial::new(
        gate_correlation_id(&assignment.id, 1),
        GateDenialReason::AuditorRepair {
            rejection: AuditorRejectionKind::ImplementationDefect,
        },
        VerifiedGateContext::new(
            &assignment.id,
            GateCheckSource::Auditor,
            &assignment.assigned_paths,
        )
        .expect("verified review-loop gate context"),
    )
    .expect("review-loop auditor denial");
    let mut outcome = AssignmentExecutionOutcome {
        gate_tracker: Some(GateCorrectionTracker::new(2)),
        ..AssignmentExecutionOutcome::default()
    };
    let mut locked_rejection = injected_child_report(&assignment);
    let plan = injected_plan(assignment.clone(), 0);
    attach_parent_computed_review_lens_aggregate(&plan, &assignment, &mut locked_rejection);
    locked_rejection
        .review_lens_aggregate
        .as_mut()
        .expect("locked review aggregate")
        .decision = ReviewAggregationDecision::Reject;
    locked_rejection.status = ReviewStatus::Failed;
    locked_rejection.accepted = false;
    locked_rejection.rejected = true;
    let locked_status_before = (
        locked_rejection.status,
        locked_rejection.accepted,
        locked_rejection.rejected,
        locked_rejection
            .review_lens_aggregate
            .as_ref()
            .expect("locked review aggregate")
            .decision,
    );
    assert!(suppress_review_loop_retry_if_threshold(
        true,
        Some(&mut tracker),
        &mut outcome,
        &artifacts,
        &assignment,
        "review-loop-parent",
        &denial,
    )
    .expect("durably suppress low-severity correction retry"));
    assert_eq!(
        (
            locked_rejection.status,
            locked_rejection.accepted,
            locked_rejection.rejected,
            locked_rejection
                .review_lens_aggregate
                .as_ref()
                .expect("locked review aggregate")
                .decision,
        ),
        locked_status_before
    );
    assert!(!tracker.evidence(&locked_rejection).locked_review_accepted);
    let gate_tracker = outcome
        .gate_tracker
        .as_ref()
        .expect("gate tracker remains available");
    assert_eq!(gate_tracker.used, 0);
    assert_eq!(gate_tracker.denials.len(), 1);
    assert_eq!(gate_tracker.outcomes.len(), 1);
    assert_eq!(
        gate_tracker.outcomes[0].terminal_class,
        GateCorrectionTerminalClass::Escalated
    );

    let evidence = tracker.evidence(&injected_child_report(&assignment));
    assert!(evidence.retry_suppressed);
    assert_eq!(
        evidence.stop_disposition,
        ReviewLoopStopDisposition::CorrectionRetrySuppressed
    );
    drop(artifacts);
    let journal = fs::read_to_string(run_dir.join(ORCHESTRATION_EVENT_PATH))
        .expect("read durable review-loop journal");
    let events = journal
        .lines()
        .map(|line| serde_json::from_str::<OrchestrationEvent>(line).expect("strict event JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].payload["state"], "cycle_observed");
    assert_eq!(events[1].payload["state"], "correction_retry_suppressed");
    assert_eq!(events[2].payload["state"], "blocked");
    assert_eq!(events[3].payload["state"], "escalated");
}

#[test]
fn high_severity_resets_streak_and_validation_failure_survives_guard_stop() {
    let (_temp, repo) = injected_repository();
    let run_id = RunId::new("review-loop-reset-floor").expect("valid review-loop run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "review-loop-reset-floor-test",
    )
    .expect("reserve review-loop artifacts");
    let run_dir = writer.run_dir().to_path_buf();
    let mut journal = Some(OrchestrationEventJournal::new(
        "review-loop-repo",
        run_id.as_str(),
    ));
    let mut autonomy_kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut writer,
        journal: &mut journal,
        autonomy_kpis: &mut autonomy_kpis,
        checkpoint: None,
    });
    let assignment = injected_assignment(false);
    let mut tracker = ReviewLoopGuardTracker::new(ReviewLoopGuardConfig {
        max_low_severity: ReviewLoopLowSeverity::Warning,
        consecutive_low_severity_cycles: 2,
    });
    let mut advisory = injected_auditor_report(&assignment, &injected_child_report(&assignment));
    advisory.id = "advisory-review-only".to_string();
    assert!(!tracker
        .observe_real_parent_review(&artifacts, &assignment, "review-loop-parent", &[advisory],)
        .expect("ignore non-parent advisory report"));
    assert!(tracker.cycles.is_empty());

    let empty_parent = injected_auditor_report(&assignment, &injected_child_report(&assignment));
    assert!(!tracker
        .observe_real_parent_review(
            &artifacts,
            &assignment,
            "review-loop-parent",
            &[empty_parent],
        )
        .expect("count finding-free parent review as low severity"));
    assert_eq!(tracker.cycles.len(), 1);
    assert_eq!(tracker.cycles[0].highest_severity, None);
    assert!(tracker.cycles[0].low_severity);

    for (severity, threshold_reached) in [
        (FindingSeverity::Error, false),
        (FindingSeverity::Info, false),
        (FindingSeverity::Warning, true),
    ] {
        let auditor = review_auditor_with_finding(&assignment, severity);
        assert_eq!(
            tracker
                .observe_real_parent_review(
                    &artifacts,
                    &assignment,
                    "review-loop-parent",
                    &[auditor],
                )
                .expect("observe review-loop severity cycle"),
            threshold_reached
        );
    }
    assert_eq!(
        tracker
            .cycles
            .iter()
            .map(|cycle| cycle.consecutive_low_severity_cycles)
            .collect::<Vec<_>>(),
        vec![1, 0, 1, 2]
    );
    tracker
        .suppress_correction_retry(&artifacts, &assignment, "review-loop-parent")
        .expect("record durable review-loop stop");

    let mut child_report = injected_child_report(&assignment);
    child_report.validation_results[0].status = ReviewStatus::Failed;
    child_report.status = ReviewStatus::Failed;
    child_report.accepted = false;
    child_report.rejected = true;
    finalize_review_loop_guard_evidence(&tracker, &artifacts, &assignment, &mut child_report)
        .expect("finalize review-loop validation-floor evidence");
    assert!(report_failed(&child_report));
    assert_eq!(tracker.cycles.len(), 4);
    assert_eq!(
        child_report
            .findings
            .last()
            .expect("post-scoring evidence pointer")
            .severity,
        FindingSeverity::Info
    );
    drop(artifacts);

    let evidence_path = run_dir
        .join("reports")
        .join("review-loop-guard")
        .join(format!("{}.json", assignment.id));
    let evidence: ReviewLoopGuardEvidence = serde_json::from_slice(
        &fs::read(&evidence_path).expect("read authenticated review-loop evidence"),
    )
    .expect("parse strict review-loop evidence");
    assert_eq!(
        evidence.final_validation_floor,
        ReviewLoopValidationFloor::Failed
    );
    assert!(!evidence.locked_review_accepted);
    assert!(evidence.retry_suppressed);
}
