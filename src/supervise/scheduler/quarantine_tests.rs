use super::*;

pub(in crate::supervise) fn exercise(
    assignment: &AssignmentExecutionContext<'_, '_>,
    width: usize,
    release_per_assignment: bool,
    nested_uncertainty: bool,
) -> Result<()> {
    let mut plan = assignment.plan.clone();
    let mut schedule = assignment.assignment_schedule.to_vec();
    if release_per_assignment {
        // An overlapping pending assignment forces per-assignment serial cleanup
        // and must never be admitted after this parent's containment refusal.
        let mut pending = assignment.assignment.clone();
        pending.id = "pending-after-quarantine".into();
        pending.role = AgentRole::Worker;
        pending.worker_assignments.clear();
        schedule.push(AssignmentScheduleEntry {
            assignment_id: pending.id.clone(),
            flattened_index: 1,
            ..schedule[0].clone()
        });
        plan.assignments.push(pending);
    }
    assert_eq!(
        release_assignment_resources_after_completion(&plan, &schedule, width),
        release_per_assignment
    );
    let prepared = (0..plan.assignments.len())
        .map(|_| PreparedSemanticAssignment::default())
        .collect::<Vec<_>>();
    let existing = BTreeSet::from([assignment.assignment.id.clone()]);
    let context = AssignmentSchedulerContext {
        plan: &plan,
        requested_plan: &plan,
        budget_config: assignment.budget_config,
        consultant: assignment.consultant,
        assignment_metadata: assignment.assignment_metadata,
        evidence_only_reaudit: None,
        options: assignment.options,
        repo: assignment.repo,
        run_dir: assignment.run_dir,
        dirs: assignment.dirs,
        execution_runtime: assignment.execution_runtime,
        execution_target: None,
        worktree_creation: assignment.worktree_creation,
        manager: assignment.manager,
        existing_ids: &existing,
        sync_store: assignment.sync_store,
        semantic_store: assignment.semantic_store,
        prepared_semantic_assignments: &prepared,
        assignment_schedule: &schedule,
        field_guide: assignment.field_guide,
        artifacts: assignment.artifacts,
        budget_ledger: assignment.budget_ledger,
        runtime_model_catalog: assignment.runtime_model_catalog,
        external_runner: assignment.external_runner,
        release_per_assignment,
    };
    let mut progress = SchedulerProgress::new(plan.assignments.len(), width);
    progress.budget_degradation.policy = assignment.budget_policy.clone();
    // The offline runner supplies execution observations. Use the existing
    // synthetic viability evidence as well; claim, semantic, lease, controller
    // and cleanup ownership below all go through production preparation.
    let evidence = PreclaimRunEvidence::acquire(
        assignment.repo,
        assignment.options.runtime,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .with_assignment_metadata(assignment.assignment_metadata);
    let decisions = plan
        .assignments
        .iter()
        .map(|subject| {
            preclaim_assignment(assignment.artifacts, subject, &plan.assignments, &evidence)
        })
        .collect::<Result<Vec<_>>>()?;
    assert!(
        decisions.iter().all(PreclaimDecision::allows_path_claim),
        "{decisions:?}"
    );
    progress.install_preclaim_decisions(decisions)?;
    if width == 1 {
        run_serial_assignment_schedule(
            &context,
            &mut progress,
            &assignment.cancellation,
            &Mutex::new(Vec::new()),
        )?;
    } else {
        run_concurrent_assignment_schedule(
            &context,
            &mut progress,
            &assignment.cancellation,
            &SemanticBlockGate::default(),
        )?;
    }
    let outcome = progress.indexed_outcomes[0]
        .as_ref()
        .context("parent did not run")?;
    assert!(
        outcome.external_containment_failed,
        "{:?}; {:?}",
        outcome.fatal_error, outcome.findings
    );
    assert_eq!(outcome.nested_quiescence_unknown, nested_uncertainty);
    assert!(outcome.requires_scheduler_abort());
    assert!(progress
        .indexed_outcomes
        .iter()
        .skip(1)
        .all(Option::is_none));
    assert!(outcome.claim_tokens.is_empty());
    assert!(outcome.semantic_tokens.is_empty());
    assert_eq!(outcome.quarantined_authority.claim_tokens.len(), 1);
    assert_eq!(outcome.quarantined_authority.semantic_tokens.len(), 1);
    assert!(outcome.released_claims.is_empty());
    assert!(outcome.released_semantic_intents.is_empty());
    let claims = assignment.sync_store.snapshot()?;
    let semantics = assignment.semantic_store.snapshot()?;
    assert_eq!(claims.len(), 1);
    assert_eq!(semantics.len(), 1);
    assert_eq!(
        outcome.quarantined_authority.claim_tokens,
        [claims[0].token]
    );
    assert_eq!(
        outcome.quarantined_authority.semantic_tokens,
        [semantics[0].token]
    );
    assert!(assignment
        .manager
        .acquire_write_execution_lease(&assignment.assignment.id)
        .is_err());

    // Exercise exactly the normal and degraded terminal release plan/operation.
    // Quarantine must survive collection even when deferred serial cleanup owns
    // all ordinary tokens until this boundary. Repeated cleanup must be harmless.
    let mut collected = CollectedAssignmentOutcomes::default();
    collect_indexed_assignment_outcomes(
        progress.indexed_outcomes,
        release_per_assignment,
        &mut collected,
    );
    assert_eq!(collected.quarantined_authority.claim_tokens.len(), 1);
    assert_eq!(collected.quarantined_authority.semantic_tokens.len(), 1);
    let mut resources = CollectedSchedulerResources::take_from(&mut collected);
    let planned = planned_collected_scheduler_resources(
        Some(assignment.sync_store),
        Some(assignment.semantic_store),
        &resources,
    )?;
    assert!(planned.released_claims.is_empty());
    assert!(planned.released_semantic_intents.is_empty());
    for _ in 0..2 {
        assert_eq!(
            release_collected_scheduler_resources(
                Some(assignment.sync_store),
                Some(assignment.semantic_store),
                &mut resources
            ),
            planned
        );
    }
    drop(resources);
    drop(collected);
    // Reopen durable stores after every local cleanup owner has gone away. Path
    // authority and semantic authority independently block a different writer.
    let sync = SyncStore::open(assignment.repo)?;
    let semantic = SemanticIntentStore::open(assignment.repo)?;
    assert_eq!(sync.snapshot()?, claims);
    assert_eq!(semantic.snapshot()?, semantics);
    assert!(sync
        .claim_paths("other-assignment", &assignment.assignment.assigned_paths)
        .is_err());
    let mut request = crate::semantic_coord::SemanticIntentRequest::new("other-assignment");
    request.paths = vec!["unrelated.rs".into()];
    request.modules = assignment.assignment.semantic_modules.clone();
    let refused = semantic.claim(request)?;
    assert!(refused.has_blocking_conflicts);
    assert!(!refused.persisted);
    Ok(())
}
