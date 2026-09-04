use super::*;

pub(super) fn validate_assignment_phase_contract(plan: &SupervisorPlan) -> Result<()> {
    for assignment in &plan.assignments {
        if assignment.phase != AssignmentPhase::Planning {
            continue;
        }
        if !assignment.worker_assignments.is_empty() {
            bail!(
                "planning assignment '{}' may not declare terminal worker assignments",
                assignment.id
            );
        }
        if assignment.licensed_breakage.is_some() {
            bail!(
                "planning assignment '{}' may not carry licensed breakage execution authority",
                assignment.id
            );
        }
    }
    Ok(())
}

pub(super) fn supervisor_assignment_traceability(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
    reports: &[OrchestratorReviewReport],
    candidate_inspections: &BTreeMap<String, SupervisorCandidateInspection>,
) -> (Vec<AssignmentTraceability>, Vec<SupervisorCoverageGap>) {
    let fallback_schedule;
    let schedule = if metadata.assignment_schedule.is_empty() {
        fallback_schedule = plan
            .assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect::<Vec<_>>();
        &fallback_schedule
    } else {
        &metadata.assignment_schedule
    };
    let assignments = plan
        .assignments
        .iter()
        .map(|assignment| (assignment.id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    let reports = reports
        .iter()
        .map(|report| (report.id.as_str(), report))
        .collect::<BTreeMap<_, _>>();
    let mut traceability = Vec::with_capacity(schedule.len());
    let mut gaps = Vec::new();

    for schedule_entry in schedule {
        let Some(assignment) = assignments.get(schedule_entry.assignment_id.as_str()) else {
            append_assignment_coverage_gap(
                &mut gaps,
                &[],
                &schedule_entry.assignment_id,
                CoverageGapKind::MissingAssignmentReport,
                "assignment schedule references an assignment absent from the normalized plan",
            );
            continue;
        };
        let fragments = metadata
            .spec_fragment_ids_by_assignment
            .get(&assignment.id)
            .cloned()
            .unwrap_or_default();
        let report = reports.get(assignment.id.as_str()).copied();
        let inspection = candidate_inspections.get(&assignment.id);
        let produced_changed_paths = inspection
            .map(|inspection| inspection.changed_paths.clone())
            .or_else(|| report.map(|report| report.files_changed.clone()))
            .unwrap_or_default();
        let produced_diff_binding = inspection
            .map(|inspection| inspection.binding.clone())
            .or_else(|| {
                report.and_then(|report| {
                    report
                        .decomposition_completions
                        .iter()
                        .find_map(|completion| completion.supervisor_candidate_binding.clone())
                })
            });
        if report.is_none() {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::MissingAssignmentReport,
                "flattened assignment has no collected orchestrator report",
            );
        } else if produced_changed_paths.is_empty() && !fragments.is_empty() {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::NoProducedChanges,
                "assignment is mapped to a spec fragment but produced no changed paths",
            );
        } else if !produced_changed_paths.is_empty()
            && produced_diff_binding.is_none()
            && !fragments.is_empty()
        {
            append_assignment_coverage_gap(
                &mut gaps,
                &fragments,
                &assignment.id,
                CoverageGapKind::MissingDiffBinding,
                "supervisor inspected changed paths but no content-addressed diff binding is available for this ordinary assignment",
            );
        }
        traceability.push(AssignmentTraceability {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: schedule_entry.parent_assignment_id.clone(),
            depth: schedule_entry.depth,
            flattened_index: schedule_entry.flattened_index,
            spec_fragment_ids: fragments,
            assigned_paths: assignment.assigned_paths.clone(),
            produced_changed_paths,
            produced_diff_binding,
            report_status: report.map(|report| report.status),
        });
    }
    (traceability, gaps)
}

fn append_assignment_coverage_gap(
    gaps: &mut Vec<SupervisorCoverageGap>,
    spec_fragment_ids: &[String],
    assignment_id: &str,
    kind: CoverageGapKind,
    message: &str,
) {
    if spec_fragment_ids.is_empty() {
        gaps.push(SupervisorCoverageGap {
            kind,
            spec_fragment_id: None,
            assignment_id: Some(assignment_id.to_string()),
            message: message.to_string(),
        });
        return;
    }
    gaps.extend(
        spec_fragment_ids
            .iter()
            .map(|spec_fragment_id| SupervisorCoverageGap {
                kind,
                spec_fragment_id: Some(spec_fragment_id.clone()),
                assignment_id: Some(assignment_id.to_string()),
                message: message.to_string(),
            }),
    );
}

pub(super) fn supervisor_plan_fan_out_width_warning(
    plan: &SupervisorPlan,
) -> Option<planning::FanOutWidthWarning> {
    let independent_scope_count = plan
        .assignments
        .iter()
        .map(|assignment| {
            assignment
                .assigned_paths
                .len()
                .max(assignment.worker_assignments.len())
                .max(1)
        })
        .sum();
    planning::fan_out_width_warning(plan.max_child_assignments, independent_scope_count)
}

pub(super) fn validate_supervisor_plan(
    mut plan: SupervisorPlan,
    mut metadata: SupervisorPlanMetadata,
) -> Result<(SupervisorPlan, SupervisorPlanMetadata)> {
    if plan.version != SUPERVISOR_SCHEMA_VERSION {
        bail!("unsupported supervisor plan version {}", plan.version);
    }
    if !(MIN_SUPERVISOR_DEPTH..=MAX_SUPERVISOR_DEPTH).contains(&plan.max_depth) {
        bail!(
            "supervisor max_depth must be between {} and {}",
            MIN_SUPERVISOR_DEPTH,
            MAX_SUPERVISOR_DEPTH
        );
    }
    if plan.max_child_assignments == 0 {
        bail!("max_child_assignments must be at least 1 (legacy max_child_processes is accepted as an alias)");
    }
    if plan.max_child_retries > MAX_CHILD_RETRIES_LIMIT {
        bail!(
            "max_child_retries must be at most {}",
            MAX_CHILD_RETRIES_LIMIT
        );
    }
    if plan.max_gate_corrections > MAX_GATE_CORRECTIONS_LIMIT {
        bail!(
            "max_gate_corrections must be at most {}",
            MAX_GATE_CORRECTIONS_LIMIT
        );
    }
    if plan.child_timeout_seconds == 0 {
        bail!("child_timeout_seconds must be greater than zero");
    }
    if plan.assignments.is_empty() {
        bail!("supervisor plan must include at least one orchestrator assignment");
    }
    validate_assignment_phase_contract(&plan)?;
    validate_primary_worktree_execution_target(&plan, &mut metadata)?;
    validate_review_lens_set(&plan.review_lenses)
        .context("supervisor review_lenses are invalid")?;
    if plan
        .review_lenses
        .iter()
        .any(|lens| matches!(lens.backend, ReviewLensBackendConfig::Precomputed { .. }))
    {
        bail!("supervisor review_lenses must be executable model-backed lenses");
    }
    if let ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts } =
        plan.review_aggregation_policy
    {
        if minimum_accepts == 0 || minimum_accepts > plan.review_lenses.len() {
            bail!(
                "supervisor review_lenses validated quorum must be between 1 and the configured lens count"
            );
        }
    }
    for (role, selection) in &mut plan.role_models {
        selection.model = normalize_optional_model_field(
            selection.model.take(),
            &format!("role_models.{}.model", role.as_str()),
        )?;
        selection.reasoning_effort = normalize_optional_model_field(
            selection.reasoning_effort.take(),
            &format!("role_models.{}.reasoning_effort", role.as_str()),
        )?;
    }
    let mut normalized_pricing = BTreeMap::new();
    for (model, pricing) in std::mem::take(&mut plan.model_pricing) {
        let normalized_model = model.trim();
        if normalized_model.is_empty() {
            bail!("model_pricing model key cannot be empty");
        }
        if !pricing.is_valid() {
            bail!(
                "model_pricing for '{}' must contain finite, non-negative input and output prices",
                normalized_model
            );
        }
        if normalized_pricing
            .insert(normalized_model.to_string(), pricing)
            .is_some()
        {
            bail!(
                "model_pricing contains duplicate model '{}' after trimming",
                normalized_model
            );
        }
    }
    plan.model_pricing = normalized_pricing;
    metadata.run_budget.limits = metadata
        .run_budget
        .limits
        .validate()
        .context("supervisor run_budget limits are invalid")?;
    for (role, tokens) in &metadata.run_budget.role_token_reservations {
        if *tokens == 0 {
            bail!(
                "run_budget.role_token_reservations.{} must be greater than zero",
                role.as_str()
            );
        }
    }
    if metadata.run_budget.limits.has_any_ceiling() {
        for role in [AgentRole::ChildOrchestrator, AgentRole::Auditor] {
            if !metadata
                .run_budget
                .role_token_reservations
                .contains_key(&role)
            {
                bail!(
                    "run_budget with an enforcement ceiling requires a positive '{}' role_token_reservations entry",
                    role.as_str()
                );
            }
        }
    }

    if plan.assignments.len() > plan.max_child_assignments {
        bail!(
            "supervisor plan has {} flattened child orchestrators but max_child_assignments is {}",
            plan.assignments.len(),
            plan.max_child_assignments
        );
    }
    if metadata.assignment_schedule.len() != plan.assignments.len() {
        bail!("assignment schedule does not cover every flattened assignment");
    }
    let mut seen = BTreeSet::new();
    for (index, assignment) in plan.assignments.iter_mut().enumerate() {
        assignment.id = normalize_agent_id(&assignment.id)?;
        if !seen.insert(assignment.id.clone()) {
            bail!("duplicate orchestrator assignment id '{}'", assignment.id);
        }
        match assignment.role {
            AgentRole::ChildOrchestrator => {}
            AgentRole::Worker => {
                if assignment.role_category != Some(RoleCategory::NonDelegatingTerminalWorker) {
                    bail!(
                        "direct worker assignment '{}' must explicitly declare role_category non_delegating_terminal_worker",
                        assignment.id
                    );
                }
                if !assignment.worker_assignments.is_empty() {
                    bail!(
                        "direct worker assignment '{}' may not declare nested worker assignments",
                        assignment.id
                    );
                }
            }
            _ => {
                bail!(
                    "assignment '{}' role must be child_orchestrator or an explicitly declared direct worker",
                    assignment.id
                );
            }
        }
        assignment.assigned_paths = normalize_paths(std::mem::take(&mut assignment.assigned_paths))
            .with_context(|| format!("assignment '{}' has invalid paths", assignment.id))?;
        if assignment.assigned_paths.is_empty() {
            bail!(
                "assignment '{}' must claim at least one path",
                assignment.id
            );
        }
        assignment.semantic_symbols = normalize_semantic_symbols(&assignment.semantic_symbols);
        assignment.semantic_modules = normalize_semantic_modules(&assignment.semantic_modules);
        validate_environment_requirements(&assignment.environment_requirements).with_context(
            || {
                format!(
                    "assignment '{}' has invalid environment requirements",
                    assignment.id
                )
            },
        )?;
        validate_licensed_breakage_declaration(assignment)?;
        if assignment.licensed_breakage.is_some()
            && plan
                .review_lenses
                .iter()
                .any(|lens| lens.information_scope == ReviewInformationScope::DiffOnly)
        {
            bail!(
                "assignment '{}' licensed_breakage requires every auditor lens to receive the output report containing the declaration",
                assignment.id
            );
        }
        validate_worker_assignments(assignment)?;
        canonical_environment_requirements(assignment)?;

        let schedule = &mut metadata.assignment_schedule[index];
        schedule.assignment_id = assignment.id.clone();
        schedule.flattened_index = index;
        if !(MIN_SUPERVISOR_DEPTH..=plan.max_depth).contains(&schedule.depth) {
            bail!(
                "assignment '{}' has schedule depth {} outside configured range {}..={}",
                assignment.id,
                schedule.depth,
                MIN_SUPERVISOR_DEPTH,
                plan.max_depth
            );
        }
    }
    if let Some(warning) = supervisor_plan_fan_out_width_warning(&plan) {
        tracing::warn!(
            code = warning.code,
            configured_max_child_assignments = warning.configured_max_child_assignments,
            independent_scope_count = warning.independent_scope_count,
            "{}",
            warning.message
        );
    }
    if let Some(operation) = metadata.evidence_only_reaudit.as_mut() {
        if plan.assignments.len() != 1 {
            bail!("evidence_only_reaudit must contain exactly one assignment");
        }
        operation.assignment_id = normalize_agent_id(&operation.assignment_id)
            .context("evidence_only_reaudit assignment_id is invalid")?;
        if operation.assignment_id != plan.assignments[0].id {
            bail!("evidence_only_reaudit assignment_id must match the sole assignment");
        }
        if operation.attempt == 0 || operation.attempt > MAX_EVIDENCE_ONLY_REAUDITS {
            bail!(
                "evidence_only_reaudit attempt must be between 1 and {}",
                MAX_EVIDENCE_ONLY_REAUDITS
            );
        }
        operation.preserved_candidate_binding = operation
            .preserved_candidate_binding
            .clone()
            .canonicalized()
            .context("evidence_only_reaudit preserved candidate binding is invalid")?;
        if operation.preserved_candidate_binding.agent_id != operation.assignment_id {
            bail!("evidence_only_reaudit preserved candidate binding names a different assignment");
        }
        if plan.max_child_retries != 0 || plan.max_gate_corrections != 0 {
            bail!("evidence_only_reaudit does not permit child retries or in-run gate corrections");
        }
    }
    validate_generated_follow_up_plan(&plan, &mut metadata)?;
    validate_orchestrator_assignment_collisions(&plan.assignments, &metadata.assignment_schedule)?;

    metadata.spec_fragment_ids =
        normalize_spec_fragment_ids(std::mem::take(&mut metadata.spec_fragment_ids))?;
    for assignment in &plan.assignments {
        let fragments = metadata
            .spec_fragment_ids_by_assignment
            .remove(&assignment.id)
            .unwrap_or_default();
        metadata.spec_fragment_ids_by_assignment.insert(
            assignment.id.clone(),
            normalize_spec_fragment_ids(fragments).with_context(|| {
                format!("assignment '{}' has invalid spec fragments", assignment.id)
            })?,
        );
    }
    let referenced_fragments = metadata
        .spec_fragment_ids_by_assignment
        .values()
        .flat_map(|fragments| fragments.iter().cloned())
        .collect::<BTreeSet<_>>();
    if metadata.spec_fragment_ids.is_empty() {
        metadata.spec_fragment_ids = referenced_fragments.iter().cloned().collect();
    } else if let Some(unknown) = referenced_fragments
        .iter()
        .find(|fragment| !metadata.spec_fragment_ids.contains(fragment))
    {
        bail!(
            "assignment references undeclared spec fragment '{}'",
            unknown
        );
    }
    metadata.coverage_gaps = metadata
        .spec_fragment_ids
        .iter()
        .filter(|fragment| !referenced_fragments.contains(*fragment))
        .map(|fragment| SupervisorCoverageGap {
            kind: CoverageGapKind::UnassignedSpecFragment,
            spec_fragment_id: Some(fragment.clone()),
            assignment_id: None,
            message: format!("spec fragment '{fragment}' is not mapped to an assignment"),
        })
        .collect();

    Ok((plan, metadata))
}

fn validate_primary_worktree_execution_target(
    plan: &SupervisorPlan,
    metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    let Some(target) = metadata.execution_target.as_mut() else {
        return Ok(());
    };
    let claim_paths = target.claim_paths_mut();
    if claim_paths.is_empty() || claim_paths.len() > MAX_PRIMARY_WORKTREE_CLAIM_PATHS {
        bail!(
            "execution_target.kind='primary_worktree' requires between 1 and {} claim_paths",
            MAX_PRIMARY_WORKTREE_CLAIM_PATHS
        );
    }
    for path in claim_paths.iter() {
        if path.as_os_str().is_empty() || path == Path::new(".") {
            bail!(
                "execution_target.kind='primary_worktree' claim path '{}' is over-broad; name an exact file below a top-level directory",
                path.display()
            );
        }
    }
    *claim_paths = normalize_paths(std::mem::take(claim_paths))
        .context("execution_target.kind='primary_worktree' claim_paths are invalid")?;
    for path in claim_paths.iter() {
        if path.as_os_str().is_empty() || path == Path::new(".") || path.components().count() < 2 {
            bail!(
                "execution_target.kind='primary_worktree' claim path '{}' is over-broad; name an exact file below a top-level directory",
                path.display()
            );
        }
        if path == Path::new(".git")
            || path.starts_with(".git")
            || Path::new(".git").starts_with(path)
        {
            bail!(
                "execution_target.kind='primary_worktree' claim path '{}' overlaps protected .git metadata",
                path.display()
            );
        }
        if path.starts_with(".maco")
            || path.starts_with(".codex")
            || path == Path::new(".agents")
            || path == Path::new("AGENTS.md")
        {
            bail!(
                "execution_target.kind='primary_worktree' claim path '{}' overlaps a protected orchestration or policy control",
                path.display()
            );
        }
    }
    for (index, path) in claim_paths.iter().enumerate() {
        if let Some(overlap) = claim_paths
            .iter()
            .skip(index.saturating_add(1))
            .find(|candidate| paths_overlap(path, candidate))
        {
            bail!(
                "execution_target.kind='primary_worktree' claim paths '{}' and '{}' overlap; declare disjoint exact files",
                path.display(),
                overlap.display()
            );
        }
    }
    if plan.assignments.len() != 1 {
        bail!(
            "execution_target.kind='primary_worktree' requires exactly one orchestrator assignment"
        );
    }
    let assignment = plan
        .assignments
        .first()
        .context("primary-worktree plan lost its sole assignment")?;
    let normalized_assignment_paths = normalize_paths(assignment.assigned_paths.clone())
        .context("primary-worktree assignment paths are invalid")?;
    if normalized_assignment_paths != *claim_paths {
        bail!(
            "execution_target.kind='primary_worktree' claim_paths must exactly equal the sole assignment assigned_paths"
        );
    }
    if plan.max_child_retries != 0 || plan.max_gate_corrections != 0 {
        bail!(
            "execution_target.kind='primary_worktree' requires max_child_retries=0 and max_gate_corrections=0 because failed in-place attempts cannot be discarded as isolated candidates"
        );
    }
    if assignment.licensed_breakage.is_some()
        || metadata.evidence_only_reaudit.is_some()
        || metadata.generated_follow_up.is_some()
    {
        bail!(
            "execution_target.kind='primary_worktree' does not support licensed breakage, evidence-only re-audit, or generated follow-up execution"
        );
    }
    Ok(())
}

pub(super) fn validate_execution_target_opt_in(
    execution_target: Option<&SupervisorExecutionTarget>,
    allow_primary_worktree: bool,
) -> Result<()> {
    match (execution_target, allow_primary_worktree) {
        (Some(SupervisorExecutionTarget::PrimaryWorktree { .. }), true) | (None, false) => Ok(()),
        (Some(SupervisorExecutionTarget::PrimaryWorktree { .. }), false) => {
            Err(SupervisorExecutionTargetOptInError::MissingCliAcknowledgement.into())
        }
        (None, true) => Err(SupervisorExecutionTargetOptInError::MissingPlanDeclaration.into()),
    }
}

pub(super) fn generated_follow_up_operator_defaults() -> Vec<GeneratedFollowUpOperatorDefault> {
    vec![
        GeneratedFollowUpOperatorDefault {
            field: "task_file".to_string(),
            value: "null".to_string(),
            rationale: "the journaled generated plan document is the authoritative inline task source"
                .to_string(),
        },
        GeneratedFollowUpOperatorDefault {
            field: "spec_fragment_ids".to_string(),
            value: "[]".to_string(),
            rationale: "the dependent failure and breaking candidate binding provide traceability; no operator-authored spec fragment mapping exists"
                .to_string(),
        },
    ]
}

pub(super) fn derived_generated_follow_up_budget(
    plan: &SupervisorPlan,
    source: &SupervisorBudgetConfig,
) -> Result<SupervisorBudgetConfig> {
    let child_tokens = source
        .reservation_tokens(AgentRole::ChildOrchestrator)
        .context("source run budget has no child_orchestrator token reservation")?;
    let auditor_tokens = source
        .reservation_tokens(AgentRole::Auditor)
        .context("source run budget has no auditor token reservation")?;
    let attempts = usize::from(plan.max_child_retries)
        .checked_add(usize::from(plan.max_gate_corrections))
        .and_then(|count| count.checked_add(1))
        .context("generated follow-up maximum attempt count overflowed")?;
    let auditor_dispatches = attempts
        .checked_mul(plan.review_lenses.len())
        .context("generated follow-up auditor dispatch count overflowed")?;
    let child_budget = attempts
        .checked_mul(child_tokens)
        .context("generated follow-up child token closure overflowed")?;
    let auditor_budget = auditor_dispatches
        .checked_mul(auditor_tokens)
        .context("generated follow-up auditor token closure overflowed")?;
    let token_closure = child_budget
        .checked_add(auditor_budget)
        .context("generated follow-up token closure overflowed")?;
    Ok(SupervisorBudgetConfig {
        limits: RunBudgetLimits {
            soft_tokens: Some(token_closure),
            hard_tokens: Some(token_closure),
            // Token ceilings close over this generated plan's exact dispatch
            // shape. Cost ceilings cannot be recomputed without assuming
            // provider usage, so preserve the source run's safety envelope.
            soft_cost_usd: source.limits.soft_cost_usd,
            hard_cost_usd: source.limits.hard_cost_usd,
        },
        role_token_reservations: BTreeMap::from([
            (AgentRole::ChildOrchestrator, child_tokens),
            (AgentRole::Auditor, auditor_tokens),
        ]),
    })
}

fn validate_generated_follow_up_plan(
    plan: &SupervisorPlan,
    metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    let Some(context) = metadata.generated_follow_up.as_mut() else {
        return Ok(());
    };
    if metadata.evidence_only_reaudit.is_some() {
        bail!("generated_follow_up and evidence_only_reaudit cannot share one supervisor plan");
    }
    if plan.assignments.len() != 1 {
        bail!("generated_follow_up supervisor plan must contain exactly one assignment");
    }
    let assignment = plan
        .assignments
        .first()
        .context("generated_follow_up supervisor plan has no assignment")?;
    if assignment.licensed_breakage.is_some() {
        bail!("generated_follow_up assignment cannot carry a new licensed_breakage declaration");
    }
    if metadata.assignment_schedule.len() != 1
        || metadata.assignment_schedule[0].assignment_id != assignment.id
        || metadata.assignment_schedule[0]
            .parent_assignment_id
            .is_some()
        || metadata.assignment_schedule[0].depth != MIN_SUPERVISOR_DEPTH
        || metadata.assignment_schedule[0].flattened_index != 0
    {
        bail!("generated_follow_up assignment_schedule must contain its sole assignment as one root entry");
    }
    if plan.task_file.is_some() || !metadata.spec_fragment_ids.is_empty() {
        bail!("generated_follow_up operator defaults require null task_file and empty spec_fragment_ids");
    }
    if context.operator_defaults != generated_follow_up_operator_defaults() {
        bail!("generated_follow_up operator defaults are incomplete or undocumented");
    }
    context.breaking_assignment_id = normalize_agent_id(&context.breaking_assignment_id)
        .context("generated_follow_up breaking_assignment_id is invalid")?;
    if context.breaking_assignment_id == assignment.id {
        bail!("generated_follow_up assignment cannot be its own breaking assignment");
    }
    context.breaking_change = context
        .breaking_change
        .clone()
        .canonicalized()
        .context("generated_follow_up breaking_change is invalid")?;
    if context.breaking_change.agent_id != context.breaking_assignment_id
        || context.breaking_change.diff_oid.is_empty()
    {
        bail!("generated_follow_up breaking_change does not identify its breaking assignment");
    }
    if context.declaration_sha256.len() != 64
        || !context
            .declaration_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("generated_follow_up declaration_sha256 is not canonical lowercase SHA-256");
    }
    for (field, value, limit) in [
        (
            "failure_signature",
            context.failure_signature.as_str(),
            MAX_LICENSED_BREAKAGE_FAILURE_SIGNATURE_BYTES,
        ),
        (
            "migration_rationale",
            context.migration_rationale.as_str(),
            MAX_LICENSED_BREAKAGE_RATIONALE_BYTES,
        ),
        ("handoff", context.handoff.as_str(), 8 * 1024),
    ] {
        if value.is_empty()
            || value.trim() != value
            || value.len() > limit
            || value.chars().any(char::is_control)
        {
            bail!("generated_follow_up {field} must be bounded printable text");
        }
    }
    if context.cascade_depth != LICENSED_BREAKAGE_CASCADE_DEPTH
        || context.dispatch_status != GeneratedFollowUpDispatchStatus::DeferredForPlannedRun
    {
        bail!("generated_follow_up cascade depth or dispatch status is invalid");
    }
    let expected_budget = derived_generated_follow_up_budget(plan, &metadata.run_budget)?;
    if metadata.run_budget != expected_budget {
        bail!("generated_follow_up run_budget does not close its maximum child and auditor dispatches");
    }
    Ok(())
}

pub(super) fn licensed_breakage_declaration_sha256(
    declaration: &LicensedBreakageDeclaration,
) -> Result<String> {
    let bytes = serde_json::to_vec(declaration)
        .context("failed to serialize licensed breakage declaration")?;
    Ok(crate::artifacts::state_auth::sha256_hex(&bytes))
}

fn validate_licensed_breakage_declaration(assignment: &mut OrchestratorAssignment) -> Result<()> {
    let Some(declaration) = assignment.licensed_breakage.as_mut() else {
        return Ok(());
    };
    let rationale = declaration.migration_rationale.trim();
    if rationale.is_empty() {
        bail!(
            "assignment '{}' licensed_breakage requires a migration_rationale",
            assignment.id
        );
    }
    if rationale != declaration.migration_rationale {
        bail!(
            "assignment '{}' licensed_breakage migration_rationale must not have surrounding whitespace",
            assignment.id
        );
    }
    if rationale.len() > MAX_LICENSED_BREAKAGE_RATIONALE_BYTES
        || rationale.chars().any(char::is_control)
    {
        bail!(
            "assignment '{}' licensed_breakage migration_rationale is not bounded printable text",
            assignment.id
        );
    }
    if declaration.dependents.is_empty()
        || declaration.dependents.len() > MAX_LICENSED_BREAKAGE_DEPENDENTS
    {
        bail!(
            "assignment '{}' licensed_breakage must name between 1 and {} dependents",
            assignment.id,
            MAX_LICENSED_BREAKAGE_DEPENDENTS
        );
    }

    let mut dependent_ids = BTreeSet::new();
    let mut licensed_paths = Vec::<(String, PathBuf)>::new();
    for dependent in &mut declaration.dependents {
        dependent.dependent_id =
            normalize_agent_id(&dependent.dependent_id).with_context(|| {
                format!(
                    "assignment '{}' licensed_breakage dependent id is invalid",
                    assignment.id
                )
            })?;
        if dependent.dependent_id == assignment.id {
            bail!(
                "assignment '{}' cannot license breakage attributed to itself",
                assignment.id
            );
        }
        if !dependent_ids.insert(dependent.dependent_id.clone()) {
            bail!(
                "assignment '{}' licensed_breakage repeats dependent '{}'",
                assignment.id,
                dependent.dependent_id
            );
        }
        if dependent.paths.is_empty()
            || dependent.paths.len() > MAX_LICENSED_BREAKAGE_PATHS_PER_DEPENDENT
        {
            bail!(
                "assignment '{}' licensed dependent '{}' must name between 1 and {} paths",
                assignment.id,
                dependent.dependent_id,
                MAX_LICENSED_BREAKAGE_PATHS_PER_DEPENDENT
            );
        }
        if let Some(path) = dependent.paths.iter().find(|path| {
            path.as_os_str().is_empty()
                || path.as_path() == Path::new(".")
                || path.components().count() < 2
        }) {
            bail!(
                "assignment '{}' licensed dependent '{}' path '{}' is over-broad; name a repository subtree or file below a top-level directory",
                assignment.id,
                dependent.dependent_id,
                path.display()
            );
        }
        dependent.paths =
            normalize_paths(std::mem::take(&mut dependent.paths)).with_context(|| {
                format!(
                    "assignment '{}' licensed dependent '{}' has invalid paths",
                    assignment.id, dependent.dependent_id
                )
            })?;
        for path in &dependent.paths {
            if assignment
                .assigned_paths
                .iter()
                .any(|assigned| paths_overlap(path, assigned))
            {
                bail!(
                    "assignment '{}' licensed dependent '{}' path '{}' overlaps the breaking assignment scope",
                    assignment.id,
                    dependent.dependent_id,
                    path.display()
                );
            }
            if let Some((owner, existing)) = licensed_paths
                .iter()
                .find(|(_, existing)| paths_overlap(path, existing))
            {
                bail!(
                    "assignment '{}' licensed dependent '{}' path '{}' overlaps dependent '{}' path '{}'",
                    assignment.id,
                    dependent.dependent_id,
                    path.display(),
                    owner,
                    existing.display()
                );
            }
            licensed_paths.push((dependent.dependent_id.clone(), path.clone()));
        }
        if dependent.interfaces.is_empty()
            || dependent.interfaces.len() > MAX_LICENSED_BREAKAGE_INTERFACES_PER_DEPENDENT
        {
            bail!(
                "assignment '{}' licensed dependent '{}' must name between 1 and {} interfaces",
                assignment.id,
                dependent.dependent_id,
                MAX_LICENSED_BREAKAGE_INTERFACES_PER_DEPENDENT
            );
        }
        dependent.interfaces = normalize_semantic_symbols(&dependent.interfaces);
        if dependent.interfaces.is_empty() {
            bail!(
                "assignment '{}' licensed dependent '{}' has no canonical interface names",
                assignment.id,
                dependent.dependent_id
            );
        }
        if let Some(interface) = dependent.interfaces.iter().find(|interface| {
            !interface.contains("::")
                || interface.len() > 512
                || interface.split("::").any(|segment| {
                    segment.is_empty()
                        || !segment
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '_')
                })
        }) {
            bail!(
                "assignment '{}' licensed dependent '{}' interface '{}' must be a bounded qualified identifier without wildcards",
                assignment.id,
                dependent.dependent_id,
                interface
            );
        }
    }
    declaration
        .dependents
        .sort_by(|left, right| left.dependent_id.cmp(&right.dependent_id));
    let digest = licensed_breakage_declaration_sha256(declaration)?;
    if digest.len() != 64 {
        bail!(
            "assignment '{}' licensed_breakage declaration digest is not canonical",
            assignment.id
        );
    }
    Ok(())
}

fn validate_orchestrator_assignment_collisions(
    assignments: &[OrchestratorAssignment],
    schedule: &[AssignmentScheduleEntry],
) -> Result<()> {
    for (left_index, left) in assignments.iter().enumerate() {
        for (right_index, right) in assignments
            .iter()
            .enumerate()
            .skip(left_index.saturating_add(1))
        {
            if schedule_entries_share_strict_lineage(schedule, left_index, right_index) {
                continue;
            }
            if let Some((left_path, right_path)) =
                left.assigned_paths.iter().find_map(|left_path| {
                    right
                        .assigned_paths
                        .iter()
                        .find(|right_path| paths_overlap(left_path, right_path))
                        .map(|right_path| (left_path, right_path))
                })
            {
                bail!(
                    "assignments '{}' path '{}' and '{}' path '{}' overlap after normalization",
                    left.id,
                    left_path.display(),
                    right.id,
                    right_path.display()
                );
            }
            validate_cross_assignment_semantic_collisions(left, right)?;
        }
    }
    Ok(())
}

pub(super) fn schedule_entries_share_strict_lineage(
    schedule: &[AssignmentScheduleEntry],
    left_index: usize,
    right_index: usize,
) -> bool {
    schedule_entry_is_strict_ancestor(schedule, left_index, right_index)
        || schedule_entry_is_strict_ancestor(schedule, right_index, left_index)
}

fn schedule_entry_is_strict_ancestor(
    schedule: &[AssignmentScheduleEntry],
    ancestor_index: usize,
    descendant_index: usize,
) -> bool {
    if ancestor_index == descendant_index {
        return false;
    }
    let Some(ancestor) = schedule.get(ancestor_index) else {
        return false;
    };
    let mut parent_id = schedule
        .get(descendant_index)
        .and_then(|entry| entry.parent_assignment_id.as_deref());
    let mut remaining = schedule.len();
    while let Some(parent) = parent_id {
        if parent == ancestor.assignment_id {
            return true;
        }
        if remaining == 0 {
            return false;
        }
        remaining = remaining.saturating_sub(1);
        parent_id = schedule
            .iter()
            .find(|entry| entry.assignment_id == parent)
            .and_then(|entry| entry.parent_assignment_id.as_deref());
    }
    false
}

fn validate_cross_assignment_semantic_collisions(
    left: &OrchestratorAssignment,
    right: &OrchestratorAssignment,
) -> Result<()> {
    let left_scopes = assignment_semantic_scopes(left);
    let right_scopes = assignment_semantic_scopes(right);
    for left_scope in &left_scopes {
        for right_scope in &right_scopes {
            if let Some(symbol) =
                first_shared_string(left_scope.semantic_symbols, right_scope.semantic_symbols)
            {
                bail!(
                    "{} and {} overlap semantic symbol '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    symbol
                );
            }
            if let Some(module) =
                first_shared_string(left_scope.semantic_modules, right_scope.semantic_modules)
            {
                bail!(
                    "{} and {} overlap semantic module '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    module
                );
            }
            if let Some((left_module, right_module)) = first_semantic_module_hierarchy_overlap(
                left_scope.semantic_modules,
                right_scope.semantic_modules,
            ) {
                bail!(
                    "{} and {} overlap semantic module hierarchy '{}' and '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    left_module,
                    right_module
                );
            }
            if let Some((module, symbol)) = first_semantic_module_symbol_overlap(
                left_scope.semantic_modules,
                right_scope.semantic_symbols,
            )
            .or_else(|| {
                first_semantic_module_symbol_overlap(
                    right_scope.semantic_modules,
                    left_scope.semantic_symbols,
                )
            }) {
                bail!(
                    "{} and {} overlap semantic module '{}' and symbol '{}' after normalization",
                    left_scope.label,
                    right_scope.label,
                    module,
                    symbol
                );
            }
        }
    }
    Ok(())
}

fn assignment_semantic_scopes(
    assignment: &OrchestratorAssignment,
) -> Vec<AssignmentSemanticScope<'_>> {
    let mut scopes = Vec::with_capacity(assignment.worker_assignments.len().saturating_add(1));
    scopes.push(AssignmentSemanticScope {
        label: format!("assignment '{}'", assignment.id),
        semantic_symbols: &assignment.semantic_symbols,
        semantic_modules: &assignment.semantic_modules,
    });
    scopes.extend(
        assignment
            .worker_assignments
            .iter()
            .map(|worker| AssignmentSemanticScope {
                label: format!(
                    "worker '{}' under assignment '{}'",
                    worker.id, assignment.id
                ),
                semantic_symbols: &worker.semantic_symbols,
                semantic_modules: &worker.semantic_modules,
            }),
    );
    scopes
}

fn first_shared_string<'a>(left: &'a [String], right: &[String]) -> Option<&'a str> {
    left.iter()
        .find(|value| right.binary_search(value).is_ok())
        .map(String::as_str)
}

fn first_semantic_module_hierarchy_overlap<'a>(
    left: &'a [String],
    right: &'a [String],
) -> Option<(&'a str, &'a str)> {
    left.iter().find_map(|left_module| {
        right
            .iter()
            .find(|right_module| {
                left_module != *right_module && semantic_path_is_ancestor(left_module, right_module)
            })
            .map(|right_module| (left_module.as_str(), right_module.as_str()))
    })
}

fn first_semantic_module_symbol_overlap<'a>(
    modules: &'a [String],
    symbols: &'a [String],
) -> Option<(&'a str, &'a str)> {
    modules.iter().find_map(|module| {
        symbols
            .iter()
            .find(|symbol| semantic_path_contains(module, symbol))
            .map(|symbol| (module.as_str(), symbol.as_str()))
    })
}

fn semantic_path_is_ancestor(left: &str, right: &str) -> bool {
    semantic_path_contains(left, right) || semantic_path_contains(right, left)
}

fn semantic_path_contains(parent: &str, child: &str) -> bool {
    let parent = parent.split("::").collect::<Vec<_>>();
    let child = child.split("::").collect::<Vec<_>>();
    child.len() >= parent.len() && child.starts_with(&parent)
}

fn normalize_optional_model_field(value: Option<String>, field: &str) -> Result<Option<String>> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                bail!("{field} cannot be empty when present");
            }
            Ok(value.to_string())
        })
        .transpose()
}

pub(super) fn validate_consultant_plan(consultant: &SupervisorConsultantPlan) -> Result<()> {
    if !matches!(consultant.runtime.as_str(), "fake" | "codex" | "claude") {
        bail!("consultant.runtime must be one of: fake, codex, claude");
    }
    if consultant.enabled && consultant.max_consultations == 0 {
        bail!("consultant.max_consultations must be greater than zero when consultant is enabled");
    }
    Ok(())
}

pub(super) fn canonical_environment_requirements(
    assignment: &OrchestratorAssignment,
) -> Result<Vec<EnvironmentRequirement>> {
    let requirements = assignment
        .environment_requirements
        .iter()
        .chain(
            assignment
                .worker_assignments
                .iter()
                .flat_map(|worker| worker.environment_requirements.iter()),
        )
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    validate_environment_requirements(&requirements).with_context(|| {
        format!(
            "assignment '{}' has conflicting aggregate environment requirements",
            assignment.id
        )
    })?;
    Ok(requirements)
}

fn validate_worker_assignments(assignment: &mut OrchestratorAssignment) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut path_owners = Vec::<PathOwner>::new();
    for worker in &mut assignment.worker_assignments {
        worker.id = normalize_agent_id(&worker.id)?;
        if !seen.insert(worker.id.clone()) {
            bail!(
                "assignment '{}' has duplicate worker id '{}'",
                assignment.id,
                worker.id
            );
        }
        if worker.role != AgentRole::Worker {
            bail!(
                "worker '{}' under assignment '{}' role must be worker",
                worker.id,
                assignment.id
            );
        }
        worker.assigned_paths = normalize_paths(std::mem::take(&mut worker.assigned_paths))
            .with_context(|| format!("worker '{}' has invalid paths", worker.id))?;
        for path in &worker.assigned_paths {
            if !assignment
                .assigned_paths
                .iter()
                .any(|assigned| path_is_covered_by_claim(path, assigned))
            {
                bail!(
                    "worker '{}' path '{}' is outside child assignment '{}'",
                    worker.id,
                    path.display(),
                    assignment.id
                );
            }
            if let Some(owner) = path_owners
                .iter()
                .find(|owner| paths_overlap(path, &owner.path))
            {
                bail!(
                    "worker '{}' path '{}' overlaps worker '{}' path '{}'",
                    worker.id,
                    path.display(),
                    owner.id,
                    owner.path.display()
                );
            }
        }
        path_owners.extend(worker.assigned_paths.iter().cloned().map(|path| PathOwner {
            id: worker.id.clone(),
            path,
        }));
        worker.semantic_symbols = normalize_semantic_symbols(&worker.semantic_symbols);
        worker.semantic_modules = normalize_semantic_modules(&worker.semantic_modules);
        validate_environment_requirements(&worker.environment_requirements).with_context(|| {
            format!(
                "worker '{}' under assignment '{}' has invalid environment requirements",
                worker.id, assignment.id
            )
        })?;
    }
    for (left_index, left) in assignment.worker_assignments.iter().enumerate() {
        for right in assignment
            .worker_assignments
            .iter()
            .skip(left_index.saturating_add(1))
        {
            if let Some(symbol) =
                first_shared_string(&left.semantic_symbols, &right.semantic_symbols)
            {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic symbol '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    symbol
                );
            }
            if let Some(module) =
                first_shared_string(&left.semantic_modules, &right.semantic_modules)
            {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic module '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    module
                );
            }
            if let Some((left_module, right_module)) = first_semantic_module_hierarchy_overlap(
                &left.semantic_modules,
                &right.semantic_modules,
            ) {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic module hierarchy '{}' and '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    left_module,
                    right_module
                );
            }
            if let Some((module, symbol)) = first_semantic_module_symbol_overlap(
                &left.semantic_modules,
                &right.semantic_symbols,
            )
            .or_else(|| {
                first_semantic_module_symbol_overlap(
                    &right.semantic_modules,
                    &left.semantic_symbols,
                )
            }) {
                bail!(
                    "workers '{}' and '{}' under assignment '{}' overlap semantic module '{}' and symbol '{}' after normalization",
                    left.id,
                    right.id,
                    assignment.id,
                    module,
                    symbol
                );
            }
        }
    }
    Ok(())
}

pub(super) fn coordinate_semantic_assignment(
    store: &SemanticIntentStore,
    assignment: &OrchestratorAssignment,
    mode: SemanticCoordinationMode,
    permit: &SupervisorOperationPermit<'_>,
    acquired_tokens: &mut Vec<crate::semantic_coord::SemanticIntentToken>,
    planned_preview_intents: &mut Vec<SemanticIntent>,
    findings: &mut Vec<Finding>,
    health_signals: &mut Vec<SwarmHealthSignal>,
) -> Result<SemanticAssignmentCoordination> {
    permit
        .verify(MutationOperation::SemanticIntentAcquire)
        .map_err(anyhow::Error::from)?;
    if mode == SemanticCoordinationMode::Off {
        return Ok(SemanticAssignmentCoordination::Ready(None));
    }
    let request = semantic_assignment_request(assignment);
    let report = match mode {
        SemanticCoordinationMode::Off => {
            return Ok(SemanticAssignmentCoordination::Ready(None));
        }
        SemanticCoordinationMode::Warn => {
            store.preview_with_additional_active(request, planned_preview_intents)?
        }
        SemanticCoordinationMode::Block => store.claim(request)?,
    };
    if mode == SemanticCoordinationMode::Warn {
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            let conflict_count = report
                .blocking_conflict_count
                .saturating_add(report.advisory_conflict_count);
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    conflict_count
                ),
                paths: assignment.assigned_paths.clone(),
            });
            health_signals.push(SwarmHealthSignal::SemanticConflictWarned {
                conflicts: conflict_count,
            });
        }
        planned_preview_intents.push(report.intent.clone());
    }
    if mode == SemanticCoordinationMode::Block && report.has_blocking_conflicts {
        health_signals.push(SwarmHealthSignal::SemanticConflictBlocked {
            conflicts: report.blocking_conflict_count,
        });
        return Ok(SemanticAssignmentCoordination::Blocked(
            report.blocking_conflict_count,
        ));
    }
    if mode == SemanticCoordinationMode::Block && report.persisted {
        acquired_tokens.push(report.intent.token);
    }
    Ok(SemanticAssignmentCoordination::Ready(Some(
        report.intent.token.get(),
    )))
}

pub(super) fn semantic_assignment_request(
    assignment: &OrchestratorAssignment,
) -> SemanticIntentRequest {
    SemanticIntentRequest {
        agent_id: assignment.id.clone(),
        paths: assignment.assigned_paths.clone(),
        symbols: assignment.semantic_symbols.clone(),
        modules: assignment.semantic_modules.clone(),
        task_file: None,
        notes: vec!["supervise child orchestrator assignment".to_string()],
    }
}
