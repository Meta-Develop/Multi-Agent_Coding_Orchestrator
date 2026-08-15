use super::*;

fn suitability_test_plan(assignments: serde_json::Value, max_depth: u8) -> serde_json::Value {
    json!({
        "version": SUPERVISOR_SCHEMA_VERSION,
        "task": "exercise the pre-claim assignment suitability gate",
        "max_depth": max_depth,
        "max_child_assignments": 4,
        "max_child_retries": 0,
        "max_gate_corrections": 0,
        "child_timeout_seconds": 60,
        "assignments": assignments
    })
}

fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        let mut entries = entries
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                collect(root, &path, snapshot);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(path.as_path())
                    .to_path_buf();
                snapshot.insert(relative, fs::read(&path).unwrap_or_default());
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    collect(root, root, &mut snapshot);
    snapshot
}

fn relative_regular_files(root: &Path) -> BTreeSet<PathBuf> {
    snapshot_regular_files(root).into_keys().collect()
}

#[test]
fn parked_assignment_is_classified_before_claim_worktree_checkpoint_or_dispatch() {
    let (temp, repo) = injected_repository();
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&suitability_test_plan(
            json!([{
                "id": "parked-parent",
                "assigned_paths": ["README.md"],
                "suitability": {
                    "classification": "unclear",
                    "bounded_scope": true,
                    "max_scope_paths": 8,
                    "verification_path": "supervisor_validation_floor",
                    "autonomous_completion": true,
                    "rationale": "operator decision is required before this assignment may claim resources"
                },
                "child_assignments": [{
                    "id": "suppressed-descendant",
                    "assigned_paths": ["README.md"]
                }]
            }]),
            3,
        ))
        .expect("serialize parked suitability plan"),
    )
    .expect("parse parked suitability plan");

    let sync_store = SyncStore::open(&repo).expect("initialize authenticated claims state");
    let semantic_store =
        SemanticIntentStore::open(&repo).expect("initialize authenticated semantic state");
    assert!(sync_store
        .snapshot()
        .expect("initial claims snapshot")
        .is_empty());
    assert!(semantic_store
        .snapshot()
        .expect("initial semantic snapshot")
        .is_empty());
    let claims_root = sync_store
        .state_path()
        .parent()
        .expect("claims state parent")
        .join("authenticated-claims-state-v1");
    let semantic_root = semantic_store
        .state_path()
        .parent()
        .expect("semantic state parent")
        .join("authenticated-semantic-state-v1");
    let claims_before = snapshot_regular_files(&claims_root);
    let semantic_before = snapshot_regular_files(&semantic_root);
    drop(sync_store);
    drop(semantic_store);

    let manager = WorktreeManager::new(&repo);
    assert!(manager
        .list()
        .expect("initial managed worktrees")
        .is_empty());
    let git = crate::git_repository::open(&repo).expect("open injected Git repository");
    let head_before = current_head_oid(&repo).expect("capture initial HEAD");
    let index_before = fs::read(git.path().join("index")).expect("capture initial index bytes");
    let readme_before = fs::read(repo.join("README.md")).expect("capture initial tracked file");
    let primary_before = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture initial whole-primary digest");

    let runner_calls = AtomicUsize::new(0);
    let mut runner = |_command: &ExternalAgentCommand, _review: bool| {
        runner_calls.fetch_add(1, Ordering::SeqCst);
        panic!("a parked assignment must never reach the child or auditor runner")
    };
    let run_id = RunId::new("preclaim-suitability-parked").expect("valid run id");
    let report = run_loaded_supervisor_plan_with_runner(
        loaded,
        injected_options(&repo, temp.path(), run_id.as_str()),
        &mut runner,
    )
    .expect("finalize parked suitability outcome");

    assert!(!report.success);
    assert!(report
        .next_safe_action
        .contains("assignment_suitability_outcomes"));
    assert_eq!(runner_calls.load(Ordering::SeqCst), 0);
    let parked = report
        .assignment_suitability_outcomes
        .iter()
        .filter(|outcome| outcome.disposition == AssignmentSuitabilityDisposition::Parked)
        .collect::<Vec<_>>();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].assignment_id, "parked-parent");
    assert_eq!(
        parked[0].reasons,
        vec![AssignmentSuitabilityReason::ClassificationUnclear]
    );
    assert!(report.orchestrator_reports.is_empty());
    assert!(report.commands_run.is_empty());
    assert!(report.claim_tokens.is_empty());
    assert!(report.semantic_intent_tokens.is_empty());
    assert!(report.released_claims.is_empty());
    assert!(report.released_semantic_intents.is_empty());
    assert!(report.release_errors.is_empty());
    assert!(report.semantic_release_errors.is_empty());
    assert!(report.breaker_trip.is_none());
    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("scheduler execution telemetry");
    assert_eq!(execution.started_assignment_count, 0);
    assert_eq!(execution.completed_assignment_count, 0);

    assert_eq!(
        SyncStore::open(&repo)
            .expect("reopen claims after parked run")
            .snapshot()
            .expect("claims after parked run"),
        Vec::new()
    );
    assert_eq!(
        SemanticIntentStore::open(&repo)
            .expect("reopen semantic state after parked run")
            .snapshot()
            .expect("semantic state after parked run"),
        Vec::new()
    );
    assert_eq!(snapshot_regular_files(&claims_root), claims_before);
    assert_eq!(snapshot_regular_files(&semantic_root), semantic_before);
    assert!(manager
        .list()
        .expect("managed worktrees after parked run")
        .is_empty());
    assert!(git
        .find_branch("maco/parked-parent", git2::BranchType::Local)
        .is_err());
    assert!(git
        .find_branch("maco/suppressed-descendant", git2::BranchType::Local)
        .is_err());
    assert_eq!(
        current_head_oid(&repo).expect("HEAD after parked run"),
        head_before
    );
    assert_eq!(
        fs::read(git.path().join("index")).expect("index bytes after parked run"),
        index_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("tracked file after parked run"),
        readme_before
    );
    assert_eq!(
        verified_whole_primary_snapshot_sha256(&repo)
            .expect("whole-primary digest after parked run"),
        primary_before
    );

    let authenticator =
        repository_authenticator_key_only(&repo).expect("open checkpoint authenticator");
    let checkpoint =
        crate::state_journal::StateJournal::open_instance(authenticator, run_id.as_str())
            .expect("authenticate finalized checkpoint records");
    assert!(!checkpoint.records().iter().any(|record| {
        matches!(
            record.phase.as_str(),
            "assignment_started" | "child_dispatch_started" | "auditor_dispatch_started"
        )
    }));
    let scheduler_closed = checkpoint
        .records()
        .iter()
        .find(|record| record.phase == "scheduler_closed")
        .expect("durable scheduler closure");
    assert_eq!(
        scheduler_closed.payload["pending_assignments"],
        json!(["parked-parent", "suppressed-descendant"])
    );

    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open parked run artifacts");
    let events = read_finalized_orchestration_events(&reader);
    assert!(events.iter().any(|event| {
        event.kind == OrchestrationEventKind::Gate
            && event.node == "parked-parent"
            && event.payload["gate"] == "assignment_suitability"
            && event.payload["outcome"]["disposition"] == "parked"
    }));
    assert!(events.iter().any(|event| {
        event.kind == OrchestrationEventKind::Reject
            && event.node == "suppressed-descendant"
            && event.payload["status"] == "suppressed"
            && event.payload["parent_assignment_id"] == "parked-parent"
    }));
    assert!(!events.iter().any(|event| {
        matches!(
            event.kind,
            OrchestrationEventKind::Spawn | OrchestrationEventKind::Claim
        )
    }));
    let artifact_files = relative_regular_files(&repo.join(".maco/o2/runs").join(run_id.as_str()));
    assert!(!artifact_files.iter().any(|path| {
        let path = path.to_string_lossy();
        path.contains("assignments/") && path.ends_with(".prompt.md")
    }));
    assert!(!artifact_files.iter().any(|path| {
        let path = path.to_string_lossy();
        path.starts_with("evidence/incoming/") && path.ends_with(".json")
    }));
}

#[test]
fn suitability_legacy_default_recursive_roundtrip_and_bounds_are_strict() {
    let legacy_value = suitability_test_plan(
        json!([{"id": "legacy", "assigned_paths": ["README.md"]}]),
        2,
    );
    let legacy = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&legacy_value).expect("serialize legacy plan"),
    )
    .expect("historical plan without suitability remains readable");
    assert_eq!(
        legacy.assignment_metadata.suitability("legacy"),
        AssignmentSuitabilityConfig::default()
    );

    let configured_value = suitability_test_plan(
        json!([{
            "id": "root",
            "assigned_paths": ["README.md"],
            "suitability": {
                "classification": "viable",
                "bounded_scope": true,
                "max_scope_paths": 8,
                "verification_path": "supervisor_validation_floor",
                "autonomous_completion": true
            },
            "child_assignments": [{
                "id": "child",
                "assigned_paths": ["README.md"],
                "suitability": {
                    "classification": "needs_decision",
                    "bounded_scope": true,
                    "max_scope_paths": 4,
                    "verification_path": "supervisor_validation_floor",
                    "autonomous_completion": true,
                    "rationale": "operator must resolve the dependent decision"
                }
            }]
        }]),
        3,
    );
    let configured = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&configured_value).expect("serialize configured plan"),
    )
    .expect("parse recursively configured suitability plan");
    let normalized = supervisor_plan_value(
        &configured.plan,
        &configured.consultant,
        &configured.assignment_metadata,
        &configured.plan_metadata,
    )
    .expect("normalize configured suitability plan");
    let reloaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized suitability plan"),
    )
    .expect("reload normalized suitability plan");
    assert_eq!(
        reloaded.assignment_metadata.suitability,
        configured.assignment_metadata.suitability
    );
    assert_eq!(
        reloaded
            .assignment_metadata
            .suitability("child")
            .classification,
        AssignmentSuitabilityClassification::NeedsDecision
    );

    for invalid in [0, MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS + 1] {
        let value = suitability_test_plan(
            json!([{
                "id": "invalid-bound",
                "assigned_paths": ["README.md"],
                "suitability": {
                    "classification": "viable",
                    "bounded_scope": true,
                    "max_scope_paths": invalid,
                    "verification_path": "supervisor_validation_floor",
                    "autonomous_completion": true
                }
            }]),
            2,
        );
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&value).expect("serialize invalid bound")
        )
        .is_err());
    }
    let unknown = suitability_test_plan(
        json!([{
            "id": "unknown-field",
            "assigned_paths": ["README.md"],
            "suitability": {
                "classification": "viable",
                "bounded_scope": true,
                "max_scope_paths": 8,
                "verification_path": "supervisor_validation_floor",
                "autonomous_completion": true,
                "hidden_handoff_fragment": "must not be accepted"
            }
        }]),
        2,
    );
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&unknown).expect("serialize unknown field plan")
    )
    .is_err());

    let over_limit_paths = (0..=MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS)
        .map(|index| format!("scope/{index}.rs"))
        .collect::<Vec<_>>();
    let over_limit = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&suitability_test_plan(
            json!([{"id": "legacy-over-limit", "assigned_paths": over_limit_paths}]),
            2,
        ))
        .expect("serialize over-limit legacy plan"),
    )
    .expect("legacy over-limit scope is classified at runtime, not rejected by decoding");
    let outcome = over_limit
        .assignment_metadata
        .suitability("legacy-over-limit")
        .outcome(
            "legacy-over-limit",
            over_limit.plan.assignments[0].assigned_paths.len(),
        );
    assert_eq!(
        outcome.disposition,
        AssignmentSuitabilityDisposition::Parked
    );
    assert_eq!(
        outcome.reasons,
        vec![AssignmentSuitabilityReason::ScopeNotBounded]
    );
    assert!(!outcome.axes.within_scope_path_limit);

    let refused = AssignmentSuitabilityConfig {
        classification: AssignmentSuitabilityClassification::Duplicate,
        rationale: Some("operator triage identified a duplicate assignment".to_string()),
        ..AssignmentSuitabilityConfig::default()
    }
    .outcome("duplicate", 1);
    assert_eq!(
        refused.disposition,
        AssignmentSuitabilityDisposition::Refused
    );
    assert_eq!(
        refused.reasons,
        vec![AssignmentSuitabilityReason::ClassificationDuplicate]
    );
}

#[test]
fn suitability_schema_is_strict_bounded_and_report_field_is_backward_readable() {
    let schema = supervisor_final_report_schema_value();
    assert!(schema["required"]
        .as_array()
        .is_some_and(|required| required
            .iter()
            .any(|field| field == "assignment_suitability_outcomes")));
    let outcome = &schema["properties"]["assignment_suitability_outcomes"]["items"];
    assert_eq!(outcome["additionalProperties"], false);
    assert_eq!(
        outcome["properties"]["reasons"]["maxItems"],
        MAX_ASSIGNMENT_SUITABILITY_REASONS
    );
    assert!(
        outcome["properties"]["axes"]["properties"]["scope_path_count"]
            .get("maximum")
            .is_none()
    );
    assert_eq!(
        outcome["properties"]["axes"]["properties"]["max_scope_paths"]["maximum"],
        MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS
    );
    let generated_plan_schema = &schema["properties"]["generated_follow_up_tasks"]["items"]
        ["properties"]["supervisor_plan"];
    assert!(generated_plan_schema["required"]
        .as_array()
        .is_some_and(|required| required
            .iter()
            .all(|field| field != "assignment_suitability")));
    assert!(generated_plan_schema["properties"]
        .get("assignment_suitability")
        .is_none());

    let ordinary = injected_plan(injected_assignment(false), 0);
    let assignment_id = ordinary.assignments[0].id.clone();
    let source_budget = injected_run_budget(None, None, None, None, 100, 100);
    let generated_budget = derived_generated_follow_up_budget(&ordinary, &source_budget)
        .expect("derive closed generated follow-up budget");
    let generated = GeneratedFollowUpSupervisorPlan {
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
            assignment_id: assignment_id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        run_budget: generated_budget,
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
            failure_signature: "historical generated plan fixture".to_string(),
            migration_rationale: "exercise compatibility decoding".to_string(),
            cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff: "deferred fixture handoff".to_string(),
            operator_defaults: generated_follow_up_operator_defaults(),
        },
    };
    let generated_json = serde_json::to_value(&generated).expect("serialize generated plan");
    assert!(generated_json.get("assignment_suitability").is_none());
    validate_generated_follow_up_plan_document(&generated)
        .expect("generated plan reloads through the ordinary loader's typed default");
    assert_eq!(
        generated.effective_assignment_suitability(),
        BTreeMap::from([(assignment_id, AssignmentSuitabilityConfig::default())])
    );

    let run_id = RunId::new("legacy-suitability-report").expect("valid legacy report id");
    let mut legacy_report = serde_json::to_value(artifact_test_final_report(&run_id))
        .expect("serialize final report fixture");
    legacy_report
        .as_object_mut()
        .expect("final report object")
        .remove("assignment_suitability_outcomes");
    let decoded: SupervisorFinalReport =
        serde_json::from_value(legacy_report).expect("read historical final report");
    assert!(decoded.assignment_suitability_outcomes.is_empty());
}
