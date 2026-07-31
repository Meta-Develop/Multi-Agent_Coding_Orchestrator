use super::*;

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
        if assignment.role != AgentRole::ChildOrchestrator {
            bail!(
                "assignment '{}' role must be child_orchestrator",
                assignment.id
            );
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
    acquired_tokens: &mut Vec<crate::semantic_coord::SemanticIntentToken>,
    planned_preview_intents: &mut Vec<SemanticIntent>,
    findings: &mut Vec<Finding>,
    health_signals: &mut Vec<SwarmHealthSignal>,
) -> Result<SemanticAssignmentCoordination> {
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

pub(super) fn semantic_assignment_request(assignment: &OrchestratorAssignment) -> SemanticIntentRequest {
    SemanticIntentRequest {
        agent_id: assignment.id.clone(),
        paths: assignment.assigned_paths.clone(),
        symbols: assignment.semantic_symbols.clone(),
        modules: assignment.semantic_modules.clone(),
        task_file: None,
        notes: vec!["supervise child orchestrator assignment".to_string()],
    }
}
