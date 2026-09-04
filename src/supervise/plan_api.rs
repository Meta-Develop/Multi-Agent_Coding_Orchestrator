use super::*;
use crate::follow_up_queue::GeneratedFollowUpQueueEntrypoint;
use crate::hierarchy_ledger::{observe_hierarchy, ObservedHierarchyNode};

/// Planner/executor coordination-depth output. Depth is derived from the
/// assignment graph; it is not an operator-selected input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoordinationTopology {
    pub derived_coordination_depth: u32,
    pub caller_selected_coordination_depth: bool,
    pub planned_max_depth: u8,
}

pub fn coordination_topology_from_plan(
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
) -> CoordinationTopology {
    let observed = observe_hierarchy(schedule.iter().filter_map(|entry| {
        let assignment = plan
            .assignments
            .iter()
            .find(|assignment| assignment.id == entry.assignment_id)?;
        Some(ObservedHierarchyNode {
            id: assignment.id.as_str(),
            parent: entry.parent_assignment_id.as_deref(),
            coordinator: assignment.effective_role_category()
                == RoleCategory::DelegatingCoordinator,
        })
    }));
    let schedule_max = schedule.iter().map(|entry| entry.depth).max().unwrap_or(0);
    CoordinationTopology {
        derived_coordination_depth: observed.coordination_depth,
        caller_selected_coordination_depth: plan.max_depth != schedule_max,
        planned_max_depth: plan.max_depth,
    }
}

fn apply_objective_profile_override(
    loaded: &mut LoadedSupervisorPlan,
    objective_profile_override: Option<&str>,
) {
    if let Some(objective_profile_override) = objective_profile_override {
        loaded.plan_metadata.objective_profile = Some(objective_profile_override.to_string());
    }
}

fn validate_execution_target_pre_dispatch(
    loaded: &LoadedSupervisorPlan,
    allow_primary_worktree: bool,
) -> Result<Option<PrimaryWorktreeOptInCapability>> {
    validate_execution_target_opt_in(
        loaded.plan_metadata.execution_target.as_ref(),
        allow_primary_worktree,
    )?;
    Ok(loaded
        .plan_metadata
        .execution_target
        .as_ref()
        .cloned()
        .map(|execution_target| PrimaryWorktreeOptInCapability { execution_target }))
}

#[derive(Debug)]
pub(super) struct PrimaryWorktreeOptInCapability {
    execution_target: SupervisorExecutionTarget,
}

impl PrimaryWorktreeOptInCapability {
    pub(super) fn matches(&self, execution_target: &SupervisorExecutionTarget) -> bool {
        &self.execution_target == execution_target
    }
}

#[cfg(test)]
pub(super) fn primary_worktree_opt_in_for_test(
    execution_target: &SupervisorExecutionTarget,
) -> PrimaryWorktreeOptInCapability {
    PrimaryWorktreeOptInCapability {
        execution_target: execution_target.clone(),
    }
}

pub fn supervisor_plan_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<SupervisorPlan> {
    Ok(supervisor_plan_and_consultant_from_task_file(repo, task_file)?.plan)
}

pub fn supervisor_plan_from_goal_spec(
    repo: impl AsRef<Path>,
    goal: &str,
    spec: &str,
) -> Result<SupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    Ok(supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?.plan)
}

pub fn supervisor_plan_document_from_goal_spec(
    repo: impl AsRef<Path>,
    goal: &str,
    spec: &str,
) -> Result<Value> {
    Ok(supervisor_plan_and_document_from_goal_spec(repo, goal, spec)?.1)
}

pub(crate) fn supervisor_plan_and_document_from_goal_spec(
    repo: impl AsRef<Path>,
    goal: &str,
    spec: &str,
) -> Result<(SupervisorPlan, Value)> {
    let repo = discover_repo_root(repo.as_ref())?;
    let loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    let document = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )?;
    Ok((loaded.plan, document))
}

pub fn supervisor_plan_document_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<Value> {
    let loaded = supervisor_plan_and_consultant_from_task_file(repo, task_file)?;
    supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

/// Machine-readable failure envelope for `supervise plan --json`.
///
/// The CLI still prints the full error chain on stderr and exits nonzero.
/// This envelope is the stdout payload for inventory and other planning
/// failures; it does not recover or fall back to a degraded plan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SupervisorPlanErrorEnvelope {
    pub success: bool,
    pub status: &'static str,
    pub error: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<String>,
}

pub fn supervisor_plan_error_envelope(error: &anyhow::Error) -> SupervisorPlanErrorEnvelope {
    SupervisorPlanErrorEnvelope {
        success: false,
        status: "error",
        error: error.to_string(),
        causes: error
            .chain()
            .skip(1)
            .map(|cause| cause.to_string())
            .collect(),
    }
}

pub(super) fn supervisor_plan_and_consultant_from_task_file(
    repo: impl AsRef<Path>,
    task_file: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    let task_file = task_file.as_ref();
    let task = read_supervisor_input(task_file, "task file")?;
    if serde_json::from_str::<Value>(&task).is_ok() {
        return parse_supervisor_plan_with_consultant(&task)
            .with_context(|| format!("failed to parse supervisor plan {}", task_file.display()));
    }

    supervisor_plan_and_consultant_from_goal_spec(
        &repo,
        "",
        &task,
        Some(path_relative_to(&repo, task_file)),
    )
    .map_err(|error| {
        error.context(format!(
            "failed to plan plain-text task specification {}",
            task_file.display()
        ))
    })
}

fn supervisor_plan_and_consultant_from_goal_spec(
    repo: &Path,
    goal: &str,
    spec: &str,
    task_file: Option<PathBuf>,
) -> Result<LoadedSupervisorPlan> {
    let proposal = planning::propose_task_decomposition(repo, goal, spec)
        .context("failed to decompose goal/spec into repository workstreams")?;
    supervisor_plan_and_consultant_from_goal_spec_proposal(goal, spec, task_file, proposal)
}

/// Lowers an already validated planning session into the ordinary supervisor
/// plan type without invoking a provider or reading repository state.
///
/// Heuristic sessions retain the established read-only planning-root plus
/// execution-child shape. Provider sessions retain the provider's validated
/// recursive assignment forest.
pub fn supervisor_plan_from_task_planning_session(
    goal: &str,
    spec: &str,
    session: &planning::TaskPlanningSession,
) -> Result<SupervisorPlan> {
    Ok(supervisor_plan_and_consultant_from_task_planning_session(goal, spec, None, session)?.plan)
}

/// Applies the heuristic feedback re-plan hook and lowers the revised remaining
/// work into an ordinary supervisor plan. This does not invoke a planner model.
pub fn supervisor_plan_from_feedback_replan(
    repo: impl AsRef<Path>,
    goal: &str,
    spec: &str,
    session: &mut planning::TaskPlanningSession,
    feedback: &planning::TaskExecutionFeedback,
) -> Result<SupervisorPlan> {
    let repo = discover_repo_root(repo.as_ref())?;
    planning::replan_task_decomposition_from_feedback(&repo, session, feedback)
        .context("failed to re-plan remaining work from execution feedback")?;
    supervisor_plan_from_task_planning_session(goal, spec, session)
        .context("failed to lower the feedback re-plan into a supervisor plan")
}

/// Lowers an already validated planning session into the normalized,
/// round-trippable supervisor plan document used by the file-entry APIs.
pub fn supervisor_plan_document_from_task_planning_session(
    goal: &str,
    spec: &str,
    session: &planning::TaskPlanningSession,
) -> Result<Value> {
    let loaded =
        supervisor_plan_and_consultant_from_task_planning_session(goal, spec, None, session)?;
    supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

fn supervisor_plan_and_consultant_from_task_planning_session(
    goal: &str,
    spec: &str,
    task_file: Option<PathBuf>,
    session: &planning::TaskPlanningSession,
) -> Result<LoadedSupervisorPlan> {
    match session.source() {
        planning::TaskPlanningSource::Heuristic => {
            if !session.provider_assignment_tree().is_empty() {
                bail!("heuristic planning session unexpectedly carries a provider assignment tree");
            }
            supervisor_plan_and_consultant_from_goal_spec_proposal(
                goal,
                spec,
                task_file,
                session.proposal().clone(),
            )
        }
        planning::TaskPlanningSource::Provider => {
            supervisor_plan_and_consultant_from_provider_session(goal, spec, task_file, session)
        }
    }
}

fn supervisor_plan_and_consultant_from_goal_spec_proposal(
    goal: &str,
    spec: &str,
    task_file: Option<PathBuf>,
    proposal: planning::TaskDecompositionProposal,
) -> Result<LoadedSupervisorPlan> {
    if proposal.assignments.is_empty() {
        bail!("{}", empty_goal_spec_workstream_message(&proposal));
    }
    planning::validate_task_assignment_disjointness(&proposal.assignments)
        .context("goal/spec workstreams are not independently assignable")?;

    let explicit_new_file_workstream = authoritative_new_file_workstream_id(&proposal);
    let explicit_existing_file_edit_workstream =
        authoritative_existing_file_edit_workstream_id(&proposal);

    let spec_fragment_ids = proposal
        .fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .collect::<Vec<_>>();
    let mut spec_fragment_ids_by_assignment = BTreeMap::new();
    let mut assignment_metadata = AssignmentMetadata::new();
    let workstream_count = proposal.assignments.len();
    let assignment_capacity = workstream_count
        .checked_mul(2)
        .context("goal/spec workstream count overflowed the assignment capacity")?;
    let mut assignments = Vec::with_capacity(assignment_capacity);
    let mut assignment_schedule = Vec::with_capacity(assignment_capacity);
    for assignment in proposal.assignments {
        let planning_id = format!("{}-planning", assignment.id);
        let planning_task = format!(
            "Read-only planning gate for workstream '{}'. Review the proposed scope and implementation task without editing files or delegating implementation. Confirm whether the execution child can proceed safely.\n\nExecution task:\n{}",
            assignment.id, assignment.task
        );
        let is_explicit_new_file_workstream =
            explicit_new_file_workstream.as_deref() == Some(assignment.id.as_str());
        let is_explicit_existing_file_edit_workstream =
            explicit_existing_file_edit_workstream.as_deref() == Some(assignment.id.as_str());
        let generated_preclaim_notes = if is_explicit_new_file_workstream {
            Some(explicit_new_file_preclaim_directive(
                &assignment,
                &planning_id,
                &planning_task,
            )?)
        } else if is_explicit_existing_file_edit_workstream {
            Some(explicit_existing_file_edit_preclaim_directive(
                &assignment,
                &planning_id,
                &planning_task,
            )?)
        } else {
            None
        };
        let planning_index = assignments.len();
        assignments.push(OrchestratorAssignment {
            id: planning_id.clone(),
            phase: AssignmentPhase::Planning,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: Some(AgentRole::ChildOrchestrator.authority_category()),
            selection_source: None,
            assigned_paths: assignment.assigned_paths.clone(),
            semantic_symbols: assignment.semantic_symbols.clone(),
            semantic_modules: assignment.semantic_modules.clone(),
            task: Some(planning_task),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: generated_preclaim_notes.clone().or_else(|| {
                Some(
                    "MACO-visible read-only planning root; its execution child is parent-gated"
                        .to_string(),
                )
            }),
        });
        assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: planning_id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: planning_index,
        });

        spec_fragment_ids_by_assignment
            .insert(assignment.id.clone(), assignment.fragment_ids.clone());
        let (execution_role, execution_role_category, worker_assignments) =
            if is_explicit_new_file_workstream || is_explicit_existing_file_edit_workstream {
                (
                    AgentRole::Worker,
                    AgentRole::Worker.authority_category(),
                    Vec::new(),
                )
            } else {
                let worker = WorkerAssignment {
                    id: format!("{}-worker", assignment.id),
                    role: AgentRole::Worker,
                    role_category: Some(AgentRole::Worker.authority_category()),
                    selection_source: None,
                    assigned_paths: assignment.assigned_paths.clone(),
                    semantic_symbols: assignment.semantic_symbols.clone(),
                    semantic_modules: assignment.semantic_modules.clone(),
                    task: Some(assignment.task.clone()),
                    environment_requirements: Vec::new(),
                    report_path: None,
                };
                assignment_metadata.insert(
                    (assignment.id.clone(), worker.id.clone()),
                    WorkerAssignmentMetadata::default(),
                );
                (
                    AgentRole::ChildOrchestrator,
                    AgentRole::ChildOrchestrator.authority_category(),
                    vec![worker],
                )
            };
        let execution_index = assignments.len();
        assignments.push(OrchestratorAssignment {
            id: assignment.id.clone(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: execution_role,
            role_category: Some(execution_role_category),
            selection_source: None,
            assigned_paths: assignment.assigned_paths,
            semantic_symbols: assignment.semantic_symbols,
            semantic_modules: assignment.semantic_modules,
            task: Some(assignment.task),
            worker_assignments,
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: generated_preclaim_notes.or_else(|| {
                Some(format!(
                    "Execution child admitted only after read-only planning root '{planning_id}' succeeds"
                ))
            }),
        });
        assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: assignment.id,
            parent_assignment_id: Some(planning_id),
            depth: MIN_SUPERVISOR_DEPTH.saturating_add(1),
            flattened_index: execution_index,
        });
    }
    let task = combined_goal_spec(goal, spec);
    let plan = SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task,
        task_file,
        max_depth: MIN_SUPERVISOR_DEPTH.saturating_add(1),
        max_child_assignments: assignment_capacity.max(DEFAULT_MAX_CHILD_ASSIGNMENTS),
        max_child_retries: DEFAULT_MAX_CHILD_RETRIES,
        max_gate_corrections: DEFAULT_MAX_GATE_CORRECTIONS,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments,
    };
    let metadata = SupervisorPlanMetadata {
        objective_profile: None,
        resolved_objective_profile: None,
        execution_target: None,
        spec_fragment_ids,
        spec_fragment_ids_by_assignment,
        assignment_schedule,
        coverage_gaps: Vec::new(),
        run_budget: conservative_generated_role_budget(),
        run_budget_max_duration_seconds: None,
        admission: SupervisorAdmissionConfig::default(),
        evidence_only_reaudit: None,
        generated_follow_up: None,
        path_proposal: proposal.diagnostics.clone(),
        router: SupervisorRouterConfig::default(),
    };
    let (plan, plan_metadata) = validate_supervisor_plan(plan, metadata)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata,
        plan_metadata,
    })
}

const AUTHORITATIVE_NEW_FILE_DIAGNOSTIC: &str =
    "an explicit safe new-file creation directive bounded the task before semantic inference";
const GENERATED_PRECLAIM_DIRECTIVE_PREFIX: &str = "maco-preclaim-v1:";

fn authoritative_new_file_workstream_id(
    proposal: &planning::TaskDecompositionProposal,
) -> Option<String> {
    let [assignment] = proposal.assignments.as_slice() else {
        return None;
    };
    let [_assigned_path] = assignment.assigned_paths.as_slice() else {
        return None;
    };
    let authoritative_diagnostic_count = proposal
        .diagnostics
        .notes
        .iter()
        .filter(|note| note.as_str() == AUTHORITATIVE_NEW_FILE_DIAGNOSTIC)
        .count();
    (authoritative_diagnostic_count == 1
        && proposal.coverage_gaps.is_empty()
        && proposal.disjointness.disjoint
        && proposal.disjointness.conflicts.is_empty()
        && assignment.semantic_symbols.is_empty()
        && assignment.semantic_modules.is_empty())
    .then(|| assignment.id.clone())
}

fn authoritative_existing_file_edit_workstream_id(
    proposal: &planning::TaskDecompositionProposal,
) -> Option<String> {
    let [assignment] = proposal.assignments.as_slice() else {
        return None;
    };
    let [assigned_path] = assignment.assigned_paths.as_slice() else {
        return None;
    };
    let fragment_ids = proposal
        .fragments
        .iter()
        .map(|fragment| fragment.id.as_str())
        .collect::<Vec<_>>();
    let assignment_fragment_ids = assignment
        .fragment_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    (!proposal.diagnostics.degraded
        && proposal.coverage_gaps.is_empty()
        && proposal.disjointness.disjoint
        && proposal.disjointness.conflicts.is_empty()
        && !proposal.disjointness.conflicts_truncated
        && assignment_fragment_ids == fragment_ids
        && assignment.semantic_symbols.is_empty()
        && assignment.semantic_modules.is_empty()
        && explicit_existing_file_edit_verification_task(&assignment.task, assigned_path))
    .then(|| assignment.id.clone())
}

pub(super) fn explicit_existing_file_edit_verification_task(task: &str, target: &Path) -> bool {
    if explicit_existing_file_rust_test_contract_task(task, target) {
        return true;
    }
    let Some(target) = target.to_str() else {
        return false;
    };
    if target.is_empty() {
        return false;
    }
    let normalized = task
        .to_ascii_lowercase()
        .replace(['`', '\'', '"'], "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    let target = target.to_ascii_lowercase();
    let verification_clauses = [
        format!(
            ". verify the result with git diff --check and confirm {target} contains exactly that line"
        ),
        format!(
            ". verify the result with git diff --check and confirm that {target} contains exactly that line"
        ),
    ];
    if normalized.matches("git diff --check").count() != 1
        || normalized.matches("contains exactly that line").count() != 1
    {
        return false;
    }
    let mut matching_verification_clauses = verification_clauses
        .iter()
        .filter_map(|clause| normalized.strip_suffix(clause.as_str()));
    let Some(edit_clause) = matching_verification_clauses.next() else {
        return false;
    };
    if matching_verification_clauses.next().is_some() {
        return false;
    }

    let edit_prefixes = [format!("in {target}, "), format!("in {target} ")];
    let mut matching_edit_prefixes = edit_prefixes
        .iter()
        .filter_map(|prefix| edit_clause.strip_prefix(prefix.as_str()));
    let Some(replacement_directive) = matching_edit_prefixes.next() else {
        return false;
    };
    if matching_edit_prefixes.next().is_some() {
        return false;
    }

    let exact_replacement_markers = ["with exactly:", "with exactly one line:"];
    if exact_replacement_markers
        .iter()
        .map(|marker| replacement_directive.matches(*marker).count())
        .sum::<usize>()
        != 1
    {
        return false;
    }

    if let Some(payload) =
        replacement_directive.strip_prefix("replace the entire contents with exactly one line:")
    {
        return !payload.trim().is_empty();
    }

    let Some(replacement) = replacement_directive.strip_prefix("replace ") else {
        return false;
    };
    let Some((replaced_text, payload)) = replacement.split_once(" with exactly:") else {
        return false;
    };
    !replaced_text.trim().is_empty() && !payload.trim().is_empty()
}

fn explicit_existing_file_rust_test_contract_task(task: &str, target: &Path) -> bool {
    let Ok(target) = normalize_repo_relative_path(target) else {
        return false;
    };
    let Some(clauses) = existing_file_task_clauses(task) else {
        return false;
    };
    let Some(task_paths) = existing_file_task_paths(&clauses) else {
        return false;
    };
    if task_paths.len() != 1 || task_paths[0] != target {
        return false;
    }

    if clauses.iter().any(|clause| {
        clause_has_fail_closed_marker(clause)
            && (path_bearing_edit_clause(clause) || verification_related_clause(clause))
    }) {
        return false;
    }

    let mut path_bearing_edit_clauses = clauses
        .iter()
        .enumerate()
        .filter(|(_, clause)| path_bearing_edit_clause(clause));
    let Some((edit_clause_index, edit_clause)) = path_bearing_edit_clauses.next() else {
        return false;
    };
    if path_bearing_edit_clauses.next().is_some() {
        return false;
    }
    if !explicit_positive_existing_file_edit_clause(edit_clause, &target) {
        return false;
    }

    let mut contract_clauses = clauses
        .iter()
        .enumerate()
        .filter(|(_, clause)| verification_contract_language(clause));
    let Some((contract_clause_index, contract_clause)) = contract_clauses.next() else {
        return false;
    };
    if contract_clauses.next().is_some() {
        return false;
    }
    rust_test_verification_contract(contract_clause).is_some()
        && edit_clause_index != contract_clause_index
}

fn existing_file_task_clauses(task: &str) -> Option<Vec<&str>> {
    let mut clauses = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut chars = task.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match quote {
            Some(expected) if ch == expected => quote = None,
            Some(_) => continue,
            None if matches!(ch, '`' | '\'' | '"') => {
                quote = Some(ch);
                continue;
            }
            None => {}
        }

        let sentence_period =
            ch == '.' && chars.peek().is_none_or(|(_, next)| next.is_whitespace());
        if sentence_period || matches!(ch, '\n' | ';' | '!' | '?') {
            let clause = task[start..index].trim();
            if !clause.is_empty() {
                clauses.push(clause);
            }
            start = index + ch.len_utf8();
        }
    }
    if quote.is_some() {
        return None;
    }
    let clause = task[start..].trim();
    if !clause.is_empty() {
        clauses.push(clause);
    }
    Some(clauses)
}

fn existing_file_task_paths(clauses: &[&str]) -> Option<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for clause in clauses {
        let tokens = existing_file_clause_tokens(clause)?;
        let extensionless_operands = extensionless_edit_operand_indices(&tokens);
        for (index, raw) in tokens.iter().enumerate() {
            let token = trimmed_existing_file_task_token(raw);
            let path_like = looks_like_existing_file_task_path(token)
                || looks_like_unambiguous_extensionless_filename(token)
                || (extensionless_operands.contains(&index)
                    && looks_like_extensionless_edit_operand(token));
            if path_like {
                paths.push(normalize_repo_relative_path(token).ok()?);
            }
        }
    }
    Some(paths)
}

fn existing_file_clause_tokens(clause: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in clause.chars() {
        match quote {
            Some(expected) if ch == expected => quote = None,
            Some(_) => current.push(ch),
            None if matches!(ch, '`' | '\'' | '"') => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Some(tokens)
}

fn extensionless_edit_operand_indices(tokens: &[String]) -> Vec<usize> {
    const OPERAND_MODIFIERS: &[&str] = &[
        "just",
        "only",
        "the",
        "an",
        "a",
        "existing",
        "repository",
        "repo",
        "root",
        "file",
        "filename",
    ];

    structurally_plausible_edit_verb_indices(tokens)
        .into_iter()
        .filter_map(|verb_index| {
            ((verb_index + 1)..tokens.len()).find(|index| {
                !OPERAND_MODIFIERS.iter().any(|modifier| {
                    trimmed_clause_word(&tokens[*index]).eq_ignore_ascii_case(modifier)
                })
            })
        })
        .collect()
}

fn structurally_plausible_edit_verb_indices(tokens: &[String]) -> Vec<usize> {
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| is_path_bearing_edit_verb(trimmed_clause_word(token)))
        .filter(|(verb_index, _)| plausible_edit_directive_prefix(&tokens[..*verb_index]))
        .map(|(verb_index, _)| verb_index)
        .collect()
}

fn plausible_edit_directive_prefix(prefix: &[String]) -> bool {
    const PREFIX_WORDS: &str = concat!(
        "also appropriate be can could do dont don't ever if is it may maybe might must ",
        "need needs necessary needed never no not only optionally please practical ready ",
        "required shall should skip then to unless when will without we you",
    );
    let segment_start = prefix
        .iter()
        .rposition(|token| {
            token.ends_with(',')
                || token.ends_with(':')
                || matches!(
                    trimmed_clause_word(token).to_ascii_lowercase().as_str(),
                    "and" | "but" | "then"
                )
        })
        .map_or(0, |index| index + 1);
    prefix[segment_start..].iter().all(|token| {
        PREFIX_WORDS
            .split_ascii_whitespace()
            .any(|prefix_word| trimmed_clause_word(token).eq_ignore_ascii_case(prefix_word))
    })
}

fn trimmed_clause_word(raw: &str) -> &str {
    raw.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
}

fn trimmed_existing_file_task_token(raw: &str) -> &str {
    raw.trim()
        .trim_start_matches(|ch: char| {
            matches!(
                ch,
                ',' | ';' | ':' | ')' | '(' | '[' | ']' | '{' | '}' | '!' | '?'
            )
        })
        .trim_end_matches(|ch: char| {
            matches!(
                ch,
                ',' | ';' | ':' | ')' | '(' | '[' | ']' | '{' | '}' | '!' | '?' | '.'
            )
        })
}

fn looks_like_existing_file_task_path(token: &str) -> bool {
    if token.is_empty()
        || token == "."
        || token == ".."
        || token.contains("://")
        || token.contains("::")
    {
        return false;
    }
    token.contains('/')
        || token.starts_with('.')
        || Path::new(token)
            .extension()
            .is_some_and(|extension| !extension.is_empty())
}

fn looks_like_extensionless_edit_operand(token: &str) -> bool {
    if token.is_empty()
        || token.contains(['/', '.', ':', '_'])
        || !token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '+'))
    {
        return false;
    }
    !matches!(
        token.to_ascii_lowercase().as_str(),
        "anything"
            | "nothing"
            | "something"
            | "it"
            | "this"
            | "that"
            | "these"
            | "those"
            | "code"
            | "behavior"
            | "behaviour"
            | "logic"
            | "semantics"
    )
}

fn looks_like_unambiguous_extensionless_filename(token: &str) -> bool {
    if token.len() < 2 || !token.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return false;
    }
    let lowercase = token.to_ascii_lowercase();
    (lowercase != "file" && lowercase.ends_with("file"))
        || token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
}

fn path_bearing_edit_clause(clause: &str) -> bool {
    let Some(tokens) = existing_file_clause_tokens(clause) else {
        return true;
    };
    let Some(paths) = existing_file_task_paths(&[clause]) else {
        return true;
    };
    !paths.is_empty() && !structurally_plausible_edit_verb_indices(&tokens).is_empty()
}

fn explicit_positive_existing_file_edit_clause(clause: &str, target: &Path) -> bool {
    let words = clause_words(clause);
    let Some(first) = words.first() else {
        return false;
    };
    let edit_verbs = words
        .iter()
        .filter(|word| is_path_bearing_edit_verb(word))
        .collect::<Vec<_>>();
    matches!(
        first.to_ascii_lowercase().as_str(),
        "edit" | "change" | "update"
    ) && edit_verbs.len() == 1
        && matches!(
            edit_verbs[0].to_ascii_lowercase().as_str(),
            "edit" | "change" | "update"
        )
        && existing_file_task_paths(&[clause])
            .is_some_and(|paths| paths.len() == 1 && paths[0].as_path() == target)
}

fn is_path_bearing_edit_verb(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "edit" | "change" | "update" | "modify" | "alter" | "touch" | "patch" | "rewrite"
    )
}

fn clause_has_fail_closed_marker(clause: &str) -> bool {
    let words = clause_words(clause);
    words.iter().enumerate().any(|(index, word)| {
        let word = word.to_ascii_lowercase();
        let cfg_not_test = word == "not"
            && index > 0
            && index + 1 < words.len()
            && words[index - 1].eq_ignore_ascii_case("cfg")
            && words[index + 1].eq_ignore_ascii_case("test");
        !cfg_not_test
            && matches!(
                word.as_str(),
                "dont"
                    | "not"
                    | "no"
                    | "never"
                    | "without"
                    | "skip"
                    | "if"
                    | "unless"
                    | "when"
                    | "maybe"
                    | "optionally"
                    | "may"
                    | "might"
                    | "could"
            )
    }) || words.windows(2).any(|pair| {
        (pair[0].eq_ignore_ascii_case("do") && pair[1].eq_ignore_ascii_case("not"))
            || (pair[0].eq_ignore_ascii_case("don") && pair[1].eq_ignore_ascii_case("t"))
    })
}

fn verification_related_clause(clause: &str) -> bool {
    clause_words(clause).iter().any(|word| {
        matches!(
            word.to_ascii_lowercase().as_str(),
            "verify"
                | "verification"
                | "contract"
                | "cargo"
                | "git"
                | "run"
                | "running"
                | "execute"
                | "executing"
                | "command"
                | "commands"
                | "test"
                | "tests"
        )
    })
}

fn verification_contract_language(clause: &str) -> bool {
    clause_words(clause).iter().any(|word| {
        matches!(
            word.to_ascii_lowercase().as_str(),
            "verification" | "contract"
        )
    })
}

fn rust_test_verification_contract(clause: &str) -> Option<&str> {
    if clause_words(clause).iter().any(|word| {
        matches!(
            word.to_ascii_lowercase().as_str(),
            "cargo" | "git" | "run" | "running" | "execute" | "executing" | "command" | "commands"
        )
    }) {
        return None;
    }

    let words = clause.split_whitespace().collect::<Vec<_>>();
    let lowered = words
        .iter()
        .map(|word| {
            word.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();
    let test_index = if lowered.ends_with(&[
        "is".to_string(),
        "the".to_string(),
        "verification".to_string(),
        "contract".to_string(),
    ]) {
        words.len().checked_sub(5)?
    } else if lowered.ends_with(&[
        "is".to_string(),
        "the".to_string(),
        "exact".to_string(),
        "verification".to_string(),
        "contract".to_string(),
    ]) {
        words.len().checked_sub(6)?
    } else {
        return None;
    };
    let test_path = words[test_index].trim_matches(['`', '\'', '"']);
    syntactically_valid_rust_test_path(test_path).then_some(test_path)
}

fn syntactically_valid_rust_test_path(test_path: &str) -> bool {
    let Ok(path) = syn::parse_str::<syn::Path>(test_path) else {
        return false;
    };
    path.leading_colon.is_none()
        && path.segments.len() >= 2
        && path
            .segments
            .iter()
            .all(|segment| matches!(&segment.arguments, syn::PathArguments::None))
}

fn clause_words(clause: &str) -> Vec<&str> {
    clause
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|word| !word.is_empty())
        .collect()
}

fn explicit_new_file_preclaim_directive(
    assignment: &planning::TaskAssignmentProposal,
    planning_id: &str,
    planning_task: &str,
) -> Result<String> {
    let [assigned_path] = assignment.assigned_paths.as_slice() else {
        bail!(
            "explicit new-file workstream '{}' lost its single-path binding",
            assignment.id
        );
    };
    let assigned_path = assigned_path.to_str().with_context(|| {
        format!(
            "explicit new-file workstream '{}' path is not UTF-8",
            assignment.id
        )
    })?;
    let payload = serde_json::json!({
        "verification_contract": {
            "kind": "explicit_new_file_creation",
            "assigned_path": assigned_path,
            "planning_assignment": {
                "id": planning_id,
                "phase": AssignmentPhase::Planning,
                "role": AgentRole::ChildOrchestrator,
                "role_category": AgentRole::ChildOrchestrator.authority_category(),
                "task_sha256": crate::artifacts::state_auth::sha256_hex(planning_task.as_bytes()),
            },
            "execution_assignment": {
                "id": assignment.id,
                "phase": AssignmentPhase::Execution,
                "role": AgentRole::Worker,
                "role_category": AgentRole::Worker.authority_category(),
                "task_sha256": crate::artifacts::state_auth::sha256_hex(assignment.task.as_bytes()),
            }
        }
    });
    Ok(format!(
        "{GENERATED_PRECLAIM_DIRECTIVE_PREFIX}{}",
        serde_json::to_string(&payload)
            .context("failed to serialize explicit new-file pre-claim contract")?
    ))
}

fn explicit_existing_file_edit_preclaim_directive(
    assignment: &planning::TaskAssignmentProposal,
    planning_id: &str,
    planning_task: &str,
) -> Result<String> {
    let [assigned_path] = assignment.assigned_paths.as_slice() else {
        bail!(
            "explicit existing-file workstream '{}' lost its single-path binding",
            assignment.id
        );
    };
    let assigned_path = assigned_path.to_str().with_context(|| {
        format!(
            "explicit existing-file workstream '{}' path is not UTF-8",
            assignment.id
        )
    })?;
    let payload = serde_json::json!({
        "verification_contract": {
            "kind": "existing_git_visible_regular_file_edit",
            "assigned_path": assigned_path,
            "planning_assignment": {
                "id": planning_id,
                "phase": AssignmentPhase::Planning,
                "role": AgentRole::ChildOrchestrator,
                "role_category": AgentRole::ChildOrchestrator.authority_category(),
                "task_sha256": crate::artifacts::state_auth::sha256_hex(planning_task.as_bytes()),
            },
            "execution_assignment": {
                "id": assignment.id,
                "phase": AssignmentPhase::Execution,
                "role": AgentRole::Worker,
                "role_category": AgentRole::Worker.authority_category(),
                "task_sha256": crate::artifacts::state_auth::sha256_hex(assignment.task.as_bytes()),
            }
        }
    });
    Ok(format!(
        "{GENERATED_PRECLAIM_DIRECTIVE_PREFIX}{}",
        serde_json::to_string(&payload)
            .context("failed to serialize explicit existing-file pre-claim contract")?
    ))
}

const CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS: usize = 1_024;

fn conservative_generated_role_budget() -> SupervisorBudgetConfig {
    SupervisorBudgetConfig {
        limits: RunBudgetLimits::default(),
        role_token_reservations: BTreeMap::from([
            (
                AgentRole::ChildOrchestrator,
                CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS,
            ),
            (
                AgentRole::Worker,
                CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS,
            ),
            (
                AgentRole::Auditor,
                CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS,
            ),
            (
                AgentRole::GateClassifier,
                CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS,
            ),
        ]),
    }
}

fn supervisor_plan_and_consultant_from_provider_session(
    goal: &str,
    spec: &str,
    task_file: Option<PathBuf>,
    session: &planning::TaskPlanningSession,
) -> Result<LoadedSupervisorPlan> {
    let roots = session.provider_assignment_tree();
    if roots.is_empty() {
        bail!("provider planning session has no validated provider assignment tree");
    }

    let mut assignments = Vec::new();
    let mut assignment_schedule = Vec::new();
    let mut assignment_metadata = AssignmentMetadata::new();
    let mut spec_fragment_ids_by_assignment = BTreeMap::new();
    let mut current_fragment_ids = BTreeSet::new();
    let mut actual_max_depth = MIN_SUPERVISOR_DEPTH;
    for root in roots {
        lower_provider_assignment_tree(
            root,
            None,
            MIN_SUPERVISOR_DEPTH,
            &mut assignments,
            &mut assignment_schedule,
            &mut assignment_metadata,
            &mut spec_fragment_ids_by_assignment,
            &mut current_fragment_ids,
            &mut actual_max_depth,
        )?;
    }
    if assignments.is_empty() || current_fragment_ids.is_empty() {
        bail!("provider planning session has no executable remaining work");
    }
    let actual_assignment_count = assignments.len();
    let task = combined_goal_spec(goal, spec);
    let plan = SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task,
        task_file,
        max_depth: actual_max_depth,
        max_child_assignments: actual_assignment_count,
        max_child_retries: DEFAULT_MAX_CHILD_RETRIES,
        max_gate_corrections: DEFAULT_MAX_GATE_CORRECTIONS,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments,
    };
    let metadata = SupervisorPlanMetadata {
        objective_profile: None,
        resolved_objective_profile: None,
        execution_target: None,
        spec_fragment_ids: current_fragment_ids.into_iter().collect(),
        spec_fragment_ids_by_assignment,
        assignment_schedule,
        coverage_gaps: Vec::new(),
        run_budget: conservative_generated_role_budget(),
        run_budget_max_duration_seconds: None,
        admission: SupervisorAdmissionConfig::default(),
        evidence_only_reaudit: None,
        generated_follow_up: None,
        path_proposal: session.proposal().diagnostics.clone(),
        router: SupervisorRouterConfig::default(),
    };
    let (plan, plan_metadata) = validate_supervisor_plan(plan, metadata)
        .context("validated provider planning session could not be lowered safely")?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata,
        plan_metadata,
    })
}

#[allow(clippy::too_many_arguments)]
fn lower_provider_assignment_tree(
    node: &planning::ProviderTaskAssignmentTree,
    parent_assignment_id: Option<&str>,
    depth: u8,
    assignments: &mut Vec<OrchestratorAssignment>,
    assignment_schedule: &mut Vec<AssignmentScheduleEntry>,
    assignment_metadata: &mut AssignmentMetadata,
    spec_fragment_ids_by_assignment: &mut BTreeMap<String, Vec<String>>,
    current_fragment_ids: &mut BTreeSet<String>,
    actual_max_depth: &mut u8,
) -> Result<()> {
    if depth > MAX_SUPERVISOR_DEPTH {
        bail!(
            "provider assignment '{}' translates to supervisor depth {} above maximum {}",
            node.id,
            depth,
            MAX_SUPERVISOR_DEPTH
        );
    }
    *actual_max_depth = (*actual_max_depth).max(depth);
    let is_leaf = node.child_assignments.is_empty();
    let worker_assignments = if is_leaf {
        let worker = WorkerAssignment {
            id: format!("{}-worker", node.id),
            role: AgentRole::Worker,
            role_category: Some(AgentRole::Worker.authority_category()),
            selection_source: None,
            assigned_paths: node.assigned_paths.clone(),
            semantic_symbols: node.semantic_symbols.clone(),
            semantic_modules: node.semantic_modules.clone(),
            task: Some(node.task.clone()),
            environment_requirements: Vec::new(),
            report_path: None,
        };
        assignment_metadata.insert(
            (node.id.clone(), worker.id.clone()),
            WorkerAssignmentMetadata::default(),
        );
        for fragment_id in &node.fragment_ids {
            current_fragment_ids.insert(fragment_id.clone());
        }
        spec_fragment_ids_by_assignment.insert(node.id.clone(), node.fragment_ids.clone());
        vec![worker]
    } else {
        spec_fragment_ids_by_assignment.insert(node.id.clone(), Vec::new());
        Vec::new()
    };

    let flattened_index = assignments.len();
    assignments.push(OrchestratorAssignment {
        id: node.id.clone(),
        phase: if is_leaf {
            AssignmentPhase::Execution
        } else {
            AssignmentPhase::Planning
        },
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: Some(AgentRole::ChildOrchestrator.authority_category()),
        selection_source: None,
        assigned_paths: node.assigned_paths.clone(),
        semantic_symbols: node.semantic_symbols.clone(),
        semantic_modules: node.semantic_modules.clone(),
        task: Some(node.task.clone()),
        worker_assignments,
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
    });
    assignment_schedule.push(AssignmentScheduleEntry {
        assignment_id: node.id.clone(),
        parent_assignment_id: parent_assignment_id.map(str::to_string),
        depth,
        flattened_index,
    });

    let child_depth = depth.checked_add(1).with_context(|| {
        format!(
            "provider assignment '{}' overflows supervisor depth",
            node.id
        )
    })?;
    for child in &node.child_assignments {
        lower_provider_assignment_tree(
            child,
            Some(&node.id),
            child_depth,
            assignments,
            assignment_schedule,
            assignment_metadata,
            spec_fragment_ids_by_assignment,
            current_fragment_ids,
            actual_max_depth,
        )?;
    }
    Ok(())
}

fn combined_goal_spec(goal: &str, spec: &str) -> String {
    match (goal.is_empty(), spec.is_empty()) {
        (false, false) => format!("{goal}\n\n{spec}"),
        (false, true) => goal.to_string(),
        (true, _) => spec.to_string(),
    }
}

fn empty_goal_spec_workstream_message(proposal: &planning::TaskDecompositionProposal) -> String {
    let mut message = String::from(
        "goal/spec produced no actionable workstreams; name at least one repository path, Rust module, or Rust symbol to change; documentation, policy, and script files are valid scopes",
    );
    if let Some(gap) = proposal.coverage_gaps.first() {
        message.push_str("; ");
        message.push_str(&gap.message);
    }
    if let Some(note) = proposal.diagnostics.notes.first() {
        message.push_str("; ");
        message.push_str(note);
    }
    message
}

/// Opaque authority tying one validated provider planning session and its
/// exact normalized supervisor plan to one caller-selected supervisor run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSupervisorExecutionBinding {
    run_id: RunId,
    session_plan_sha256: String,
}

impl ProviderSupervisorExecutionBinding {
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
}

/// The typed plan/document pair and opaque execution binding produced from one
/// validated provider planning session.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundProviderSupervisorPlan {
    pub plan: SupervisorPlan,
    pub document: Value,
    pub execution_binding: ProviderSupervisorExecutionBinding,
}

/// Lowers and binds a validated provider planning session to an exact future
/// supervisor run without invoking the provider or performing scheduler work.
pub fn bind_provider_task_planning_session_to_supervisor_run(
    goal: &str,
    spec: &str,
    session: &planning::TaskPlanningSession,
    run_id: RunId,
) -> Result<BoundProviderSupervisorPlan> {
    if session.source() != planning::TaskPlanningSource::Provider
        || session.provider_assignment_tree().is_empty()
    {
        bail!("supervisor execution binding requires a provider planning session and tree");
    }
    let loaded =
        supervisor_plan_and_consultant_from_task_planning_session(goal, spec, None, session)?;
    let document = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )?;
    let session_plan_sha256 = provider_session_plan_sha256(session, &document)?;
    Ok(BoundProviderSupervisorPlan {
        plan: loaded.plan,
        document,
        execution_binding: ProviderSupervisorExecutionBinding {
            run_id,
            session_plan_sha256,
        },
    })
}

/// Loads the binding's exact finalized supervisor run through authenticated
/// artifact state, verifies its persisted normalized plan and run identity,
/// and returns bounded provider re-planning feedback.
pub fn task_execution_feedback_from_authenticated_supervisor_run(
    repo: impl AsRef<Path>,
    goal: &str,
    spec: &str,
    session: &planning::TaskPlanningSession,
    binding: &ProviderSupervisorExecutionBinding,
) -> Result<planning::TaskExecutionFeedback> {
    let current = bind_provider_task_planning_session_to_supervisor_run(
        goal,
        spec,
        session,
        binding.run_id.clone(),
    )?;
    if current.execution_binding.session_plan_sha256 != binding.session_plan_sha256 {
        bail!("provider supervisor execution binding does not match the current session and normalized plan");
    }

    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &binding.run_id);
    let report =
        read_finalized_supervisor_report(&repo, &binding.run_id, &run_dir)?.with_context(|| {
            format!(
                "provider supervisor run '{}' is not an authenticated finalized artifact",
                binding.run_id.as_str()
            )
        })?;
    if report.run_id != binding.run_id {
        bail!(
            "authenticated supervisor report run id '{}' does not match bound run '{}'",
            report.run_id.as_str(),
            binding.run_id.as_str()
        );
    }

    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &binding.run_id)
        .context("failed to reopen authenticated provider supervisor run")?;
    let plan_bytes = reader
        .read("assignments/supervisor-plan.json")
        .context("authenticated provider supervisor run has no normalized supervisor plan")?;
    let plan_text = String::from_utf8(plan_bytes)
        .context("authenticated provider supervisor plan is not UTF-8")?;
    let persisted = parse_supervisor_plan_with_consultant(&plan_text)
        .context("authenticated provider supervisor plan is invalid")?;
    let persisted_document = supervisor_plan_value(
        &persisted.plan,
        &persisted.consultant,
        &persisted.assignment_metadata,
        &persisted.plan_metadata,
    )?;
    if persisted_document != current.document {
        bail!("authenticated supervisor run normalized plan does not match its provider execution binding");
    }

    normalize_task_execution_feedback_from_supervisor_final_report(session, &report)
}

fn provider_session_plan_sha256(
    session: &planning::TaskPlanningSession,
    normalized_document: &Value,
) -> Result<String> {
    let payload = serde_json::to_vec(&json!({
        "version": 1,
        "planning_source": session.source(),
        "proposal": session.proposal(),
        "provider_assignment_tree": session.provider_assignment_tree(),
        "normalized_supervisor_plan": normalized_document,
    }))
    .context("failed to serialize provider supervisor execution binding")?;
    Ok(crate::artifacts::state_auth::sha256_hex(&payload))
}

fn normalize_task_execution_feedback_from_supervisor_final_report(
    session: &planning::TaskPlanningSession,
    report: &SupervisorFinalReport,
) -> Result<planning::TaskExecutionFeedback> {
    if session.source() != planning::TaskPlanningSource::Provider
        || session.provider_assignment_tree().is_empty()
    {
        bail!("supervisor execution feedback requires a provider planning session and tree");
    }
    if report.run_lifecycle != SupervisorRunLifecycle::Finalized {
        bail!("supervisor execution feedback requires a finalized report");
    }

    let mut assignments = BTreeMap::new();
    let mut flattened_index = 0usize;
    for root in session.provider_assignment_tree() {
        collect_provider_feedback_assignments(
            root,
            None,
            MIN_SUPERVISOR_DEPTH,
            &mut flattened_index,
            &mut assignments,
        )?;
    }
    let expected_assigned_paths = assignments
        .values()
        .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let expected_semantic_symbols = assignments
        .values()
        .flat_map(|assignment| assignment.semantic_symbols.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let expected_semantic_modules = assignments
        .values()
        .flat_map(|assignment| assignment.semantic_modules.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if report.assigned_paths != expected_assigned_paths
        || report.semantic_symbols != expected_semantic_symbols
        || report.semantic_modules != expected_semantic_modules
    {
        bail!("supervisor execution report aggregate path or semantic scope does not match the current provider tree");
    }
    let executable_ids = assignments
        .iter()
        .filter_map(|(id, assignment)| assignment.executable.then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    let proposal_assignments = session
        .proposal()
        .assignments
        .iter()
        .map(|assignment| (assignment.id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    if proposal_assignments.len() != executable_ids.len()
        || executable_ids
            .iter()
            .any(|id| !proposal_assignments.contains_key(id.as_str()))
    {
        bail!("provider planning session leaf tree and executable proposal disagree");
    }
    for id in &executable_ids {
        let proposal = proposal_assignments
            .get(id.as_str())
            .copied()
            .context("provider executable proposal disappeared during feedback validation")?;
        let proposal_fragments = proposal
            .fragment_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let tree_fragments = &assignments
            .get(id)
            .context("provider executable tree node disappeared during feedback validation")?
            .fragment_ids;
        if &proposal_fragments != tree_fragments {
            bail!(
                "provider planning session leaf '{}' fragment mapping disagrees with its executable proposal",
                id
            );
        }
    }

    let current_fragment_ids = executable_ids
        .iter()
        .filter_map(|id| assignments.get(id))
        .flat_map(|assignment| assignment.fragment_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut traceability_by_id = BTreeMap::new();
    for trace in &report.assignment_traceability {
        let assignment_id = trace.assignment_id.trim();
        let Some(provider_assignment) = assignments.get(assignment_id) else {
            bail!(
                "supervisor execution report references unknown provider assignment '{}'",
                trace.assignment_id
            );
        };
        if traceability_by_id
            .insert(assignment_id.to_string(), trace)
            .is_some()
        {
            bail!(
                "supervisor execution report repeats provider assignment '{}'",
                assignment_id
            );
        }
        if trace.parent_assignment_id != provider_assignment.parent_assignment_id
            || trace.depth != provider_assignment.depth
            || trace.flattened_index != provider_assignment.flattened_index
            || trace.assigned_paths != provider_assignment.assigned_paths
        {
            bail!(
                "supervisor execution report traceability for '{}' does not match the current provider schedule and scope",
                assignment_id
            );
        }
        let trace_fragments = normalized_report_fragment_ids(
            &trace.spec_fragment_ids,
            &current_fragment_ids,
            "assignment traceability",
        )?;
        if provider_assignment.executable {
            if trace_fragments != provider_assignment.fragment_ids {
                bail!(
                    "supervisor execution report fragment mapping for leaf '{}' does not match the current provider tree",
                    assignment_id
                );
            }
        } else if !trace_fragments.is_empty() {
            bail!(
                "supervisor execution report attributes spec fragments to internal provider assignment '{}'",
                assignment_id
            );
        }
    }

    for (assignment_id, provider_assignment) in &assignments {
        let trace = traceability_by_id.get(assignment_id).with_context(|| {
            format!(
                "supervisor execution report has no traceability row for provider tree node '{}'",
                assignment_id
            )
        })?;
        if !provider_assignment.executable && trace.report_status != Some(ReviewStatus::Succeeded) {
            bail!(
                "supervisor execution report internal provider node '{}' is not terminal succeeded",
                assignment_id
            );
        }
    }

    let mut completed_assignment_ids = BTreeSet::new();
    let mut failed_assignment_ids = BTreeSet::new();
    let mut completed_fragment_ids = BTreeSet::new();
    for assignment_id in &executable_ids {
        let trace = traceability_by_id.get(assignment_id).with_context(|| {
            format!(
                "supervisor execution report has no traceability row for provider leaf '{}'",
                assignment_id
            )
        })?;
        match trace.report_status {
            Some(ReviewStatus::Pending) => bail!(
                "supervisor execution report leaf '{}' is still pending",
                assignment_id
            ),
            Some(ReviewStatus::Succeeded) => {
                completed_assignment_ids.insert(assignment_id.clone());
                if let Some(assignment) = assignments.get(assignment_id) {
                    completed_fragment_ids.extend(assignment.fragment_ids.iter().cloned());
                }
            }
            Some(ReviewStatus::Failed | ReviewStatus::Rejected | ReviewStatus::Missing) | None => {
                failed_assignment_ids.insert(assignment_id.clone());
            }
        }
    }

    let mut coverage_gap_fragment_ids = BTreeSet::new();
    for gap in &report.coverage_gaps {
        let provider_assignment = if let Some(assignment_id) = gap.assignment_id.as_deref() {
            let assignment_id = assignment_id.trim();
            Some(assignments.get(assignment_id).with_context(|| {
                format!(
                    "supervisor execution coverage gap references unknown provider assignment '{}'",
                    assignment_id
                )
            })?)
        } else {
            None
        };
        let Some(fragment_id) = gap.spec_fragment_id.as_deref() else {
            bail!("supervisor execution report contains a fragmentless coverage gap that cannot be normalized safely");
        };
        let fragment_id = fragment_id.trim();
        if fragment_id.is_empty() || !current_fragment_ids.contains(fragment_id) {
            bail!(
                "supervisor execution coverage gap references unknown current fragment '{}'",
                fragment_id
            );
        }
        if let Some(provider_assignment) = provider_assignment {
            if !provider_assignment.executable
                || !provider_assignment.fragment_ids.contains(fragment_id)
            {
                bail!(
                    "supervisor execution coverage gap fragment '{}' does not belong to its provider leaf",
                    fragment_id
                );
            }
        }
        coverage_gap_fragment_ids.insert(fragment_id.to_string());
    }
    if let Some(contradiction) = completed_fragment_ids
        .intersection(&coverage_gap_fragment_ids)
        .next()
    {
        bail!(
            "supervisor execution report marks succeeded fragment '{}' as a coverage gap",
            contradiction
        );
    }

    Ok(planning::TaskExecutionFeedback {
        completed_assignment_ids: completed_assignment_ids.into_iter().collect(),
        failed_assignment_ids: failed_assignment_ids.into_iter().collect(),
        coverage_gap_fragment_ids: coverage_gap_fragment_ids.into_iter().collect(),
        notes: Vec::new(),
    })
}

struct ProviderFeedbackAssignment {
    parent_assignment_id: Option<String>,
    depth: u8,
    flattened_index: usize,
    assigned_paths: Vec<PathBuf>,
    semantic_symbols: Vec<String>,
    semantic_modules: Vec<String>,
    fragment_ids: BTreeSet<String>,
    executable: bool,
}

fn collect_provider_feedback_assignments(
    node: &planning::ProviderTaskAssignmentTree,
    parent_assignment_id: Option<&str>,
    depth: u8,
    flattened_index: &mut usize,
    assignments: &mut BTreeMap<String, ProviderFeedbackAssignment>,
) -> Result<()> {
    let assignment = ProviderFeedbackAssignment {
        parent_assignment_id: parent_assignment_id.map(str::to_string),
        depth,
        flattened_index: *flattened_index,
        assigned_paths: node.assigned_paths.clone(),
        semantic_symbols: node.semantic_symbols.clone(),
        semantic_modules: node.semantic_modules.clone(),
        fragment_ids: node.fragment_ids.iter().cloned().collect(),
        executable: node.child_assignments.is_empty(),
    };
    if assignments.insert(node.id.clone(), assignment).is_some() {
        bail!(
            "provider planning session repeats assignment id '{}'",
            node.id
        );
    }
    *flattened_index = flattened_index
        .checked_add(1)
        .context("provider feedback assignment index overflowed")?;
    let child_depth = depth
        .checked_add(1)
        .context("provider feedback assignment depth overflowed")?;
    for child in &node.child_assignments {
        collect_provider_feedback_assignments(
            child,
            Some(&node.id),
            child_depth,
            flattened_index,
            assignments,
        )?;
    }
    Ok(())
}

fn normalized_report_fragment_ids(
    fragment_ids: &[String],
    current_fragment_ids: &BTreeSet<String>,
    source: &str,
) -> Result<BTreeSet<String>> {
    let mut normalized = BTreeSet::new();
    for fragment_id in fragment_ids {
        let fragment_id = fragment_id.trim();
        if fragment_id.is_empty() || !current_fragment_ids.contains(fragment_id) {
            bail!(
                "supervisor execution {source} references unknown current fragment '{}'",
                fragment_id
            );
        }
        if !normalized.insert(fragment_id.to_string()) {
            bail!(
                "supervisor execution {source} repeats fragment '{}'",
                fragment_id
            );
        }
    }
    Ok(normalized)
}

pub fn load_supervisor_plan_file(path: impl AsRef<Path>) -> Result<SupervisorPlan> {
    Ok(load_supervisor_plan_file_with_consultant(path)?.plan)
}

pub(super) fn load_supervisor_plan_file_with_consultant(
    path: impl AsRef<Path>,
) -> Result<LoadedSupervisorPlan> {
    let path = path.as_ref();
    let contents = read_supervisor_input(path, "supervisor plan")?;
    parse_supervisor_plan_with_consultant(&contents)
        .with_context(|| format!("failed to parse supervisor plan {}", path.display()))
}

fn read_supervisor_input(path: &Path, label: &str) -> Result<String> {
    #[cfg(unix)]
    let bytes = BoundedRegularReader::read_tree_no_follow(path, MAX_SUPERVISOR_INPUT_BYTES);
    #[cfg(not(unix))]
    let bytes = BoundedRegularReader::read(path, MAX_SUPERVISOR_INPUT_BYTES);
    let bytes = bytes.with_context(|| format!("failed to read {label} {}", path.display()))?;
    String::from_utf8(bytes)
        .with_context(|| format!("{label} is not valid UTF-8: {}", path.display()))
}

pub(super) fn parse_supervisor_plan_with_consultant(
    contents: &str,
) -> Result<LoadedSupervisorPlan> {
    let value: Value = serde_json::from_str(contents).context("supervisor plan is not JSON")?;
    let consultant = consultant_from_plan_value(&value)?;
    let mut plan: SupervisorPlan =
        serde_json::from_value(value.clone()).context("supervisor plan fields are invalid")?;
    for (role, selection) in &plan.role_models {
        selection
            .validate_model_fallback()
            .with_context(|| format!("role_models.{} fallback is invalid", role.as_str()))?;
    }
    let plan_metadata = supervisor_plan_metadata_from_value(&value, plan.max_depth)?;
    plan.assignments = assignments_from_plan_value(&value)?;
    let (mut plan, plan_metadata) = validate_supervisor_plan(plan, plan_metadata)?;
    bind_assignment_role_categories(&mut plan);
    let assignment_metadata = assignment_metadata_from_plan_value(&value, &plan)?;
    validate_consultant_plan(&consultant)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
    })
}

pub(crate) fn validate_generated_follow_up_plan_document(
    generated: &GeneratedFollowUpSupervisorPlan,
) -> Result<SupervisorPlan> {
    let serialized =
        serde_json::to_string(generated).context("failed to serialize generated follow-up plan")?;
    let loaded = parse_supervisor_plan_with_consultant(&serialized)
        .context("generated follow-up plan failed the ordinary full-document loader")?;
    if loaded.plan != generated.ordinary_plan()
        || loaded.consultant != generated.consultant
        || loaded.plan_metadata.assignment_schedule != generated.assignment_schedule
        || loaded.plan_metadata.run_budget != generated.run_budget
        || loaded.plan_metadata.generated_follow_up != Some(generated.generated_follow_up.clone())
        || !loaded.plan_metadata.spec_fragment_ids.is_empty()
    {
        bail!("ordinary full-document loader changed generated follow-up authority");
    }
    Ok(loaded.plan)
}

fn assignments_from_plan_value(value: &Value) -> Result<Vec<OrchestratorAssignment>> {
    let raw_assignments = value
        .get("assignments")
        .and_then(Value::as_array)
        .context("supervisor plan assignments must be an array")?;
    let mut assignments = Vec::new();
    flatten_assignments_from_value(raw_assignments, &mut assignments)?;
    Ok(assignments)
}

fn bind_assignment_role_categories(plan: &mut SupervisorPlan) {
    plan.bind_assignment_role_categories();
}

fn flatten_assignments_from_value(
    raw_assignments: &[Value],
    assignments: &mut Vec<OrchestratorAssignment>,
) -> Result<()> {
    for raw_assignment in raw_assignments {
        assignments.push(
            serde_json::from_value(raw_assignment.clone())
                .context("supervisor assignment fields are invalid")?,
        );
        let children = raw_assignment
            .get("child_assignments")
            .map(|children| {
                children
                    .as_array()
                    .context("child_assignments must be an array")
            })
            .transpose()?
            .map(Vec::as_slice)
            .unwrap_or_default();
        flatten_assignments_from_value(children, assignments)?;
    }
    Ok(())
}

fn supervisor_plan_metadata_from_value(
    value: &Value,
    max_depth: u8,
) -> Result<SupervisorPlanMetadata> {
    let objective_profile = value
        .get("objective_profile")
        .map(|profile| {
            profile
                .as_str()
                .context("objective_profile must be a string")
                .map(str::to_string)
        })
        .transpose()?;
    let spec_fragment_ids = optional_string_array(value, "spec_fragment_ids")?;
    let (run_budget, run_budget_max_duration_seconds) = value
        .get("run_budget")
        .map(|budget| -> Result<(SupervisorBudgetConfig, Option<u64>)> {
            let mut budget = budget
                .as_object()
                .context("run_budget must be an object")?
                .clone();
            let max_duration_seconds = budget
                .remove("max_duration_seconds")
                .map(|duration| -> Result<u64> {
                    let duration = serde_json::from_value::<u64>(duration)
                        .context("run_budget.max_duration_seconds must be a positive integer")?;
                    if duration == 0 {
                        bail!("run_budget.max_duration_seconds must be greater than zero");
                    }
                    Ok(duration)
                })
                .transpose()?;
            let config = serde_json::from_value::<SupervisorBudgetConfig>(Value::Object(budget))
                .context("run_budget is invalid")?;
            Ok((config, max_duration_seconds))
        })
        .transpose()?
        .unwrap_or_default();
    let admission = value
        .get("concurrency")
        .map(|concurrency| {
            serde_json::from_value::<SupervisorAdmissionConfig>(concurrency.clone())
                .context("concurrency is invalid")?
                .validate()
        })
        .transpose()?
        .unwrap_or_default();
    let evidence_only_reaudit = value
        .get("evidence_only_reaudit")
        .map(|operation| {
            serde_json::from_value::<EvidenceOnlyReauditPlan>(operation.clone())
                .context("evidence_only_reaudit is invalid")
        })
        .transpose()?;
    let generated_follow_up = value
        .get("generated_follow_up")
        .map(|context| {
            validate_generated_follow_up_document_sections(value)?;
            serde_json::from_value::<GeneratedFollowUpPlanContext>(context.clone())
                .context("generated_follow_up is invalid")
        })
        .transpose()?;
    let execution_target = value
        .get("execution_target")
        .map(|target| {
            serde_json::from_value::<SupervisorExecutionTarget>(target.clone())
                .context("execution_target is invalid")
        })
        .transpose()?;
    let path_proposal = value
        .get("path_proposal")
        .map(|diagnostics| {
            serde_json::from_value::<planning::TaskPathProposalDiagnostics>(diagnostics.clone())
                .context("path_proposal is invalid")
        })
        .transpose()?
        .unwrap_or_default();
    let router = value
        .get("router")
        .map(|config| {
            serde_json::from_value::<SupervisorRouterConfig>(config.clone())
                .context("router is invalid")
        })
        .transpose()?
        .unwrap_or_default();
    let raw_assignments = value
        .get("assignments")
        .and_then(Value::as_array)
        .context("supervisor plan assignments must be an array")?;
    let mut metadata = SupervisorPlanMetadata {
        objective_profile,
        spec_fragment_ids,
        run_budget,
        run_budget_max_duration_seconds,
        admission,
        evidence_only_reaudit,
        generated_follow_up,
        execution_target,
        path_proposal,
        router,
        ..SupervisorPlanMetadata::default()
    };
    bind_live_router_config(metadata.router.clone());
    collect_assignment_plan_metadata(
        raw_assignments,
        None,
        MIN_SUPERVISOR_DEPTH,
        max_depth,
        &mut metadata,
    )?;
    if let Some(schedule_value) = value.get("assignment_schedule") {
        let supplied_schedule =
            serde_json::from_value::<Vec<AssignmentScheduleEntry>>(schedule_value.clone())
                .context("assignment_schedule is invalid")?;
        let supplied_schedule = validate_assignment_schedule(
            supplied_schedule,
            &metadata.assignment_schedule,
            max_depth,
        )?;
        if raw_assignment_tree_has_children(raw_assignments)
            && supplied_schedule != metadata.assignment_schedule
        {
            bail!("assignment_schedule does not match the recursive assignment tree");
        }
        metadata.assignment_schedule = supplied_schedule;
    }
    Ok(metadata)
}

fn validate_generated_follow_up_document_sections(value: &Value) -> Result<()> {
    for field in [
        "version",
        "task",
        "task_file",
        "max_depth",
        "max_child_assignments",
        "max_child_retries",
        "max_gate_corrections",
        "child_timeout_seconds",
        "semantic_coordination",
        "role_models",
        "model_pricing",
        "review_lenses",
        "review_aggregation_policy",
        "assignments",
        "spec_fragment_ids",
        "assignment_schedule",
        "run_budget",
        "consultant",
    ] {
        if value.get(field).is_none() {
            bail!("generated follow-up supervisor plan requires explicit '{field}' section");
        }
    }
    Ok(())
}

pub(super) fn validate_assignment_schedule(
    mut supplied: Vec<AssignmentScheduleEntry>,
    flattened_assignments: &[AssignmentScheduleEntry],
    max_depth: u8,
) -> Result<Vec<AssignmentScheduleEntry>> {
    if supplied.len() != flattened_assignments.len() {
        bail!("assignment_schedule must cover every flattened assignment exactly once");
    }
    let mut by_id = BTreeMap::<String, (usize, u8)>::new();
    for (index, entry) in supplied.iter_mut().enumerate() {
        entry.assignment_id = normalize_agent_id(&entry.assignment_id)?;
        entry.parent_assignment_id = entry
            .parent_assignment_id
            .take()
            .map(|parent| normalize_agent_id(&parent))
            .transpose()?;
        if entry.flattened_index != index {
            bail!(
                "assignment_schedule entry '{}' has flattened_index {} but expected {}",
                entry.assignment_id,
                entry.flattened_index,
                index
            );
        }
        if entry.assignment_id != flattened_assignments[index].assignment_id {
            bail!(
                "assignment_schedule entry {} names '{}' but flattened assignment is '{}'",
                index,
                entry.assignment_id,
                flattened_assignments[index].assignment_id
            );
        }
        if !(MIN_SUPERVISOR_DEPTH..=max_depth).contains(&entry.depth) {
            bail!(
                "assignment_schedule entry '{}' depth {} is outside configured range {}..={}",
                entry.assignment_id,
                entry.depth,
                MIN_SUPERVISOR_DEPTH,
                max_depth
            );
        }
        match entry.parent_assignment_id.as_deref() {
            None if entry.depth != MIN_SUPERVISOR_DEPTH => {
                bail!(
                    "root assignment_schedule entry '{}' must have depth {}",
                    entry.assignment_id,
                    MIN_SUPERVISOR_DEPTH
                )
            }
            None => {}
            Some(parent) => {
                let Some((parent_index, parent_depth)) = by_id.get(parent).copied() else {
                    bail!(
                        "assignment_schedule entry '{}' references parent '{}' that does not precede it",
                        entry.assignment_id,
                        parent
                    );
                };
                let expected_depth = parent_depth
                    .checked_add(1)
                    .context("assignment schedule depth overflowed")?;
                if entry.depth != expected_depth {
                    bail!(
                        "assignment_schedule entry '{}' depth {} does not follow parent '{}' at index {} depth {}",
                        entry.assignment_id,
                        entry.depth,
                        parent,
                        parent_index,
                        parent_depth
                    );
                }
            }
        }
        if by_id
            .insert(entry.assignment_id.clone(), (index, entry.depth))
            .is_some()
        {
            bail!(
                "assignment_schedule contains duplicate assignment id '{}'",
                entry.assignment_id
            );
        }
    }
    Ok(supplied)
}

fn raw_assignment_tree_has_children(assignments: &[Value]) -> bool {
    assignments.iter().any(|assignment| {
        assignment
            .get("child_assignments")
            .and_then(Value::as_array)
            .is_some_and(|children| {
                !children.is_empty() || raw_assignment_tree_has_children(children)
            })
    })
}

fn collect_assignment_plan_metadata(
    raw_assignments: &[Value],
    parent_assignment_id: Option<&str>,
    depth: u8,
    max_depth: u8,
    metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    for raw_assignment in raw_assignments {
        let assignment_id = normalize_agent_id(
            raw_assignment
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        if depth > max_depth {
            bail!(
                "assignment '{}' is at depth {} but supervisor max_depth is {}",
                assignment_id,
                depth,
                max_depth
            );
        }
        let flattened_index = metadata.assignment_schedule.len();
        metadata.assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: assignment_id.clone(),
            parent_assignment_id: parent_assignment_id.map(str::to_string),
            depth,
            flattened_index,
        });
        let fragments = optional_string_array(raw_assignment, "spec_fragment_ids")?;
        metadata
            .spec_fragment_ids_by_assignment
            .insert(assignment_id.clone(), fragments);
        let children = raw_assignment
            .get("child_assignments")
            .map(|children| {
                children
                    .as_array()
                    .context("child_assignments must be an array")
            })
            .transpose()?
            .map(Vec::as_slice)
            .unwrap_or_default();
        let child_depth = depth
            .checked_add(1)
            .context("assignment nesting depth overflowed")?;
        collect_assignment_plan_metadata(
            children,
            Some(&assignment_id),
            child_depth,
            max_depth,
            metadata,
        )?;
    }
    Ok(())
}

fn optional_string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .get(field)
        .map(|value| {
            serde_json::from_value::<Vec<String>>(value.clone())
                .with_context(|| format!("{field} must be an array of strings"))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn consultant_from_plan_value(value: &Value) -> Result<SupervisorConsultantPlan> {
    match value.get("consultant") {
        Some(consultant) => {
            serde_json::from_value(consultant.clone()).context("consultant plan field is invalid")
        }
        None => Ok(SupervisorConsultantPlan::default()),
    }
}

fn assignment_metadata_from_plan_value(
    value: &Value,
    plan: &SupervisorPlan,
) -> Result<AssignmentMetadata> {
    let raw_assignments = match value.get("assignments") {
        Some(assignments) => assignments
            .as_array()
            .context("supervisor plan assignments must be an array")?
            .as_slice(),
        None => &[],
    };
    let mut metadata_by_worker = AssignmentMetadata::new();
    let assignments_by_id = plan
        .assignments
        .iter()
        .map(|assignment| (assignment.id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    for raw_assignment in raw_assignments {
        collect_assignment_metadata(raw_assignment, &assignments_by_id, &mut metadata_by_worker)?;
    }
    Ok(metadata_by_worker)
}

fn collect_assignment_metadata(
    raw_assignment: &Value,
    assignments_by_id: &BTreeMap<&str, &OrchestratorAssignment>,
    metadata_by_worker: &mut AssignmentMetadata,
) -> Result<()> {
    let raw_id = raw_assignment
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let assignment = assignments_by_id.get(raw_id).copied();
    if let Some(assignment) = assignment {
        if let Some(effort) = raw_assignment.get("reasoning_effort") {
            let effort =
                serde_json::from_value::<ReasoningEffort>(effort.clone()).with_context(|| {
                    format!("assignment '{}' reasoning_effort is invalid", assignment.id)
                })?;
            metadata_by_worker.insert_reasoning_effort(assignment.id.clone(), effort);
        }
        let workers_by_id = assignment
            .worker_assignments
            .iter()
            .map(|worker| (worker.id.as_str(), worker))
            .collect::<BTreeMap<_, _>>();
        let raw_workers = raw_assignment
            .get("worker_assignments")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for raw_worker in raw_workers {
            let raw_worker_id = raw_worker
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let Some(worker) = workers_by_id.get(raw_worker_id).copied() else {
                continue;
            };
            let mut metadata: WorkerAssignmentMetadata = serde_json::from_value(raw_worker.clone())
                .with_context(|| {
                    format!(
                        "worker assignment '{}' kind/target_path is invalid",
                        worker.id
                    )
                })?;
            metadata.target_path = match (metadata.kind, metadata.target_path.take()) {
                (AssignmentKind::Ordinary, None) => None,
                (AssignmentKind::Ordinary, Some(_)) => {
                    bail!(
                        "ordinary worker assignment '{}' must not declare target_path",
                        worker.id
                    )
                }
                (AssignmentKind::MegafileDecomposition, None) => {
                    bail!(
                        "megafile decomposition worker assignment '{}' must declare target_path",
                        worker.id
                    )
                }
                (AssignmentKind::MegafileDecomposition, Some(path)) => {
                    let normalized = normalize_repo_relative_path(&path).with_context(|| {
                        format!(
                            "megafile decomposition worker assignment '{}' has invalid target_path '{}'",
                            worker.id,
                            path.display()
                        )
                    })?;
                    if normalized.as_os_str().is_empty() {
                        bail!(
                            "megafile decomposition worker assignment '{}' target_path must name a repository file",
                            worker.id
                        );
                    }
                    if !worker
                        .assigned_paths
                        .iter()
                        .any(|assigned| path_is_covered_by_claim(&normalized, assigned))
                    {
                        bail!(
                            "megafile decomposition worker assignment '{}' target_path '{}' is outside assigned_paths",
                            worker.id,
                            normalized.display()
                        );
                    }
                    Some(normalized)
                }
            };
            metadata_by_worker.insert((assignment.id.clone(), worker.id.clone()), metadata);
        }
    }
    for child in raw_assignment
        .get("child_assignments")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        collect_assignment_metadata(child, assignments_by_id, metadata_by_worker)?;
    }
    Ok(())
}

pub(super) fn supervisor_plan_value(
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(plan).context("failed to serialize normalized supervisor plan")?;
    let assignments = value
        .get_mut("assignments")
        .and_then(Value::as_array_mut)
        .context("normalized supervisor plan assignments did not serialize to an array")?;
    for (assignment_value, assignment) in assignments.iter_mut().zip(&plan.assignments) {
        if let Some(effort) = assignment_metadata.reasoning_effort(&assignment.id) {
            assignment_value
                .as_object_mut()
                .context("normalized assignment did not serialize to an object")?
                .insert(
                    "reasoning_effort".to_string(),
                    serde_json::to_value(effort)
                        .context("failed to serialize assignment reasoning effort")?,
                );
        }
        let workers = assignment_value
            .get_mut("worker_assignments")
            .and_then(Value::as_array_mut)
            .context("normalized worker_assignments did not serialize to an array")?;
        for (worker_value, worker) in workers.iter_mut().zip(&assignment.worker_assignments) {
            let Some(metadata) =
                assignment_metadata.get(&(assignment.id.clone(), worker.id.clone()))
            else {
                continue;
            };
            let metadata_value = serde_json::to_value(metadata)
                .context("failed to serialize worker assignment metadata")?;
            let worker_object = worker_value
                .as_object_mut()
                .context("normalized worker assignment did not serialize to an object")?;
            let metadata_object = metadata_value
                .as_object()
                .context("worker assignment metadata did not serialize to an object")?;
            worker_object.extend(metadata_object.clone());
        }
        if let Some(fragments) = plan_metadata
            .spec_fragment_ids_by_assignment
            .get(&assignment.id)
            .filter(|fragments| !fragments.is_empty())
        {
            assignment_value
                .as_object_mut()
                .context("normalized assignment did not serialize to an object")?
                .insert(
                    "spec_fragment_ids".to_string(),
                    serde_json::to_value(fragments)
                        .context("failed to serialize assignment spec fragments")?,
                );
        }
    }
    let object = value
        .as_object_mut()
        .context("normalized supervisor plan did not serialize to an object")?;
    if let Some(objective_profile) = &plan_metadata.objective_profile {
        object.insert(
            "objective_profile".to_string(),
            Value::String(objective_profile.clone()),
        );
    }
    if !plan_metadata.spec_fragment_ids.is_empty() || plan_metadata.generated_follow_up.is_some() {
        object.insert(
            "spec_fragment_ids".to_string(),
            serde_json::to_value(&plan_metadata.spec_fragment_ids)
                .context("failed to serialize plan spec fragments")?,
        );
    }
    object.insert(
        "assignment_schedule".to_string(),
        serde_json::to_value(&plan_metadata.assignment_schedule)
            .context("failed to serialize assignment schedule")?,
    );
    object.insert(
        "coordination_topology".to_string(),
        serde_json::to_value(coordination_topology_from_plan(
            plan,
            &plan_metadata.assignment_schedule,
        ))
        .context("failed to serialize coordination topology")?,
    );
    if !plan_metadata.coverage_gaps.is_empty() {
        object.insert(
            "coverage_gaps".to_string(),
            serde_json::to_value(&plan_metadata.coverage_gaps)
                .context("failed to serialize plan coverage gaps")?,
        );
    }
    if !plan_metadata.run_budget.is_unconfigured()
        || plan_metadata.run_budget_max_duration_seconds.is_some()
    {
        object.insert(
            "run_budget".to_string(),
            supervisor_run_budget_value(
                &plan_metadata.run_budget,
                plan_metadata.run_budget_max_duration_seconds,
            )?,
        );
    }
    if !plan_metadata.admission.is_unconfigured() {
        object.insert(
            "concurrency".to_string(),
            serde_json::to_value(plan_metadata.admission)
                .context("failed to serialize concurrency plan field")?,
        );
    }
    if let Some(execution_target) = &plan_metadata.execution_target {
        object.insert(
            "execution_target".to_string(),
            serde_json::to_value(execution_target)
                .context("failed to serialize execution_target plan field")?,
        );
    }
    if !plan_metadata.path_proposal.is_empty() {
        object.insert(
            "path_proposal".to_string(),
            serde_json::to_value(&plan_metadata.path_proposal)
                .context("failed to serialize path_proposal plan field")?,
        );
    }
    if !plan_metadata.router.is_default() {
        object.insert(
            "router".to_string(),
            serde_json::to_value(&plan_metadata.router)
                .context("failed to serialize router plan field")?,
        );
    }
    if let Some(operation) = &plan_metadata.evidence_only_reaudit {
        object.insert(
            "evidence_only_reaudit".to_string(),
            serde_json::to_value(operation)
                .context("failed to serialize evidence_only_reaudit plan field")?,
        );
    }
    if let Some(context) = &plan_metadata.generated_follow_up {
        object.insert("task_file".to_string(), Value::Null);
        object
            .entry("role_models".to_string())
            .or_insert_with(|| json!({}));
        object
            .entry("model_pricing".to_string())
            .or_insert_with(|| json!({}));
        object.insert(
            "generated_follow_up".to_string(),
            serde_json::to_value(context)
                .context("failed to serialize generated_follow_up plan field")?,
        );
        object.insert(
            "run_budget".to_string(),
            supervisor_run_budget_value(
                &plan_metadata.run_budget,
                plan_metadata.run_budget_max_duration_seconds,
            )?,
        );
    }
    if !consultant.is_default() || plan_metadata.generated_follow_up.is_some() {
        object.insert(
            "consultant".to_string(),
            serde_json::to_value(consultant)
                .context("failed to serialize consultant plan field")?,
        );
    }
    Ok(value)
}

fn supervisor_run_budget_value(
    run_budget: &SupervisorBudgetConfig,
    max_duration_seconds: Option<u64>,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(run_budget).context("failed to serialize run_budget plan field")?;
    if let Some(max_duration_seconds) = max_duration_seconds {
        value
            .as_object_mut()
            .context("serialized run_budget must be an object")?
            .insert(
                "max_duration_seconds".to_string(),
                Value::from(max_duration_seconds),
            );
    }
    Ok(value)
}

pub fn run_supervisor_plan_file(options: SupervisorRunOptions) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_file_with_concurrency_policy(
        options,
        SupervisorConcurrencyPolicy::default(),
    )
}

/// Runs a Fake plan-file experiment through the nonpublishable-simulation
/// worktree path. This test wrapper verifies the same production seam used by
/// Fake autopilot while keeping direct Fake plan-file execution unavailable.
#[cfg(test)]
pub(crate) fn run_fake_supervisor_plan_file_for_test(
    options: SupervisorRunOptions,
) -> Result<SupervisorFinalReport> {
    if options.runtime != SupervisorRuntime::Fake {
        bail!("hermetic test plan-file execution requires the Fake runtime");
    }
    validate_max_concurrent_children(1)?;
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    let runtime_model_catalog = test_runtime_model_catalog(&loaded.plan, options.runtime)?;
    let no_external_runner = |_command: &ExternalAgentCommand,
                              _cancellation: &ProcessCancellation,
                              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
                              _authorization: SupervisorProcessLaunchAuthorization|
     -> ExternalAgentRun {
        panic!("hermetic Fake plan-file execution must not launch an external process")
    };
    authorize_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::NonpublishableSimulation,
        Ok(runtime_model_catalog),
        &no_external_runner,
    )
}

pub fn run_supervisor_plan_file_with_concurrency_policy(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorFinalReport> {
    let max_concurrent_children = concurrency_policy.resolve(HostProcessCapacity::measured());
    run_supervisor_plan_file_with_max_concurrent_children(options, max_concurrent_children)
}

pub fn run_supervisor_goal_spec_with_concurrency_policy(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorFinalReport> {
    let max_concurrent_children = concurrency_policy.resolve(HostProcessCapacity::measured());
    run_supervisor_goal_spec_with_max_concurrent_children(
        options,
        goal,
        spec,
        max_concurrent_children,
    )
}

pub fn run_supervisor_plan_file_cascade_with_concurrency_policy(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorCascadeOutcome> {
    run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
        options,
        concurrency_policy,
        false,
    )
}

pub fn run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
    allow_primary_worktree: bool,
) -> Result<SupervisorCascadeOutcome> {
    run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
        options,
        concurrency_policy,
        allow_primary_worktree,
        None,
    )
}

pub fn run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
    allow_primary_worktree: bool,
    objective_profile_override: Option<String>,
) -> Result<SupervisorCascadeOutcome> {
    let outer_run_id = options.run_id.clone();
    let mut permit = |_plan: &SupervisorPlan| Ok(None);
    let cancellation_observed = AtomicBool::new(false);
    run_supervisor_plan_file_cascade_with_gate(
        SupervisorPlanFileCascadeRequest {
            options,
            concurrency_policy,
            outer_entrypoint: GeneratedFollowUpQueueEntrypoint::SuperviseRun,
            outer_command_run_id: &outer_run_id,
            caller_cancellation: None,
            cancellation_observed: &cancellation_observed,
            source_dispatch_started: None,
            allow_primary_worktree,
            objective_profile_override: objective_profile_override.as_deref(),
        },
        &mut permit,
        &run_external_agent_cancellable_reviewed_authorized,
    )
}

pub fn run_supervisor_goal_spec_cascade_with_concurrency_policy(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorCascadeOutcome> {
    run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
        options,
        goal,
        spec,
        concurrency_policy,
        false,
    )
}

pub fn run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    concurrency_policy: SupervisorConcurrencyPolicy,
    allow_primary_worktree: bool,
) -> Result<SupervisorCascadeOutcome> {
    run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
        options,
        goal,
        spec,
        concurrency_policy,
        allow_primary_worktree,
        None,
    )
}

pub fn run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    concurrency_policy: SupervisorConcurrencyPolicy,
    allow_primary_worktree: bool,
    objective_profile_override: Option<String>,
) -> Result<SupervisorCascadeOutcome> {
    let max_concurrent_children = concurrency_policy.resolve(HostProcessCapacity::measured());
    validate_max_concurrent_children(max_concurrent_children)?;
    let outer_run_id = options.run_id.clone();
    let repo = discover_repo_root(&options.repo)?;
    let mut loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    apply_objective_profile_override(&mut loaded, objective_profile_override.as_deref());
    let primary_worktree_opt_in =
        validate_execution_target_pre_dispatch(&loaded, allow_primary_worktree)?;
    let source_loaded = loaded.clone();
    let template = options.clone();
    let source_report = if template.runtime == SupervisorRuntime::Fake {
        if source_loaded.plan_metadata.execution_target.is_some() {
            bail!("nonpublishable Fake cascade cannot use primary-worktree execution");
        }
        let no_external_runner = |_command: &ExternalAgentCommand,
                                  _cancellation: &ProcessCancellation,
                                  _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
                                  _authorization: SupervisorProcessLaunchAuthorization|
         -> ExternalAgentRun {
            panic!("nonpublishable Fake cascade must not launch an external process")
        };
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::NonpublishableSimulation,
            None,
            &no_external_runner,
        )?
    } else if source_loaded.plan_metadata.execution_target.is_some() {
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::PrimaryWorktree(
                primary_worktree_opt_in
                    .as_ref()
                    .context("primary worktree dispatch lost its validated double opt-in")?,
            ),
            None,
            &run_external_agent_cancellable_reviewed_authorized,
        )?
    } else {
        let manager = WorktreeManager::new(&repo);
        let cleanliness = manager.acquire_repository_cleanliness()?;
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::Bound(&cleanliness),
            None,
            &run_external_agent_cancellable_reviewed_authorized,
        )?
    };
    let mut permit = |_plan: &SupervisorPlan| Ok(None);
    let cancellation_observed = AtomicBool::new(false);
    run_generated_follow_up_cascade(
        &repo,
        &source_loaded,
        source_report,
        &template,
        FollowUpCascadeInvocation {
            outer_entrypoint: GeneratedFollowUpQueueEntrypoint::SuperviseRun,
            outer_command_run_id: &outer_run_id,
            concurrency_policy,
            runtime_catalog: FollowUpRuntimeCatalog::Production,
        },
        None,
        &cancellation_observed,
        &mut permit,
        &run_external_agent_cancellable_reviewed_authorized,
    )
}

pub fn resume_supervisor_plan_file_cascade_with_concurrency_policy(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorCascadeOutcome> {
    let repo = discover_repo_root(&options.repo)?;
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    resume_generated_follow_up_cascade(repo, loaded, options, concurrency_policy)
}

pub fn resume_supervisor_goal_spec_cascade_with_concurrency_policy(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorCascadeOutcome> {
    let repo = discover_repo_root(&options.repo)?;
    let loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    resume_generated_follow_up_cascade(repo, loaded, options, concurrency_policy)
}

fn resume_generated_follow_up_cascade(
    repo: PathBuf,
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorCascadeOutcome> {
    let run_id = options.run_id.clone();
    let status = supervisor_status(&repo, run_id.clone())?;
    let (source_report, source_was_finalized) = match status.lifecycle {
        SupervisorRunLifecycle::Finalized => (
            status
                .final_report
                .context("finalized supervise cascade source report is missing")?,
            true,
        ),
        SupervisorRunLifecycle::Resumable => (
            resume_supervisor_run(&repo, run_id.clone())?
                .final_report
                .context("resumed supervise cascade source report is missing")?,
            false,
        ),
        SupervisorRunLifecycle::Active => {
            bail!("cannot resume generated follow-up cascade while its source run is active")
        }
        SupervisorRunLifecycle::Uncertain => {
            bail!("cannot resume generated follow-up cascade from an uncertain source run")
        }
        SupervisorRunLifecycle::Interrupted => {
            bail!("cannot resume generated follow-up cascade from an interrupted source run")
        }
    };
    if source_was_finalized {
        ensure_generated_follow_up_cascade_needs_resume(&repo, &loaded, &source_report)?;
    }
    let mut permit = |_plan: &SupervisorPlan| Ok(None);
    let cancellation_observed = AtomicBool::new(false);
    run_generated_follow_up_cascade(
        &repo,
        &loaded,
        source_report,
        &options,
        FollowUpCascadeInvocation {
            outer_entrypoint: GeneratedFollowUpQueueEntrypoint::SuperviseRun,
            outer_command_run_id: &run_id,
            concurrency_policy,
            runtime_catalog: FollowUpRuntimeCatalog::Production,
        },
        None,
        &cancellation_observed,
        &mut permit,
        &run_external_agent_cancellable_reviewed_authorized,
    )
}

pub(crate) struct AutopilotSupervisorCascadeRequest<'a> {
    pub(crate) options: SupervisorRunOptions,
    pub(crate) concurrency_policy: SupervisorConcurrencyPolicy,
    pub(crate) outer_command_run_id: &'a RunId,
    pub(crate) caller_cancellation: Option<&'a ProcessCancellation>,
    pub(crate) cancellation_observed: &'a AtomicBool,
    pub(crate) source_dispatch_started: &'a AtomicBool,
}

pub(crate) fn run_supervisor_plan_file_cascade_for_autopilot(
    request: AutopilotSupervisorCascadeRequest<'_>,
    before_dispatch: &mut dyn FnMut(&SupervisorPlan) -> Result<Option<GateDenial>>,
) -> Result<SupervisorCascadeOutcome> {
    let AutopilotSupervisorCascadeRequest {
        options,
        concurrency_policy,
        outer_command_run_id,
        caller_cancellation,
        cancellation_observed,
        source_dispatch_started,
    } = request;
    match caller_cancellation {
        Some(caller_cancellation) => {
            let external_runner =
                |command: &ExternalAgentCommand,
                 scheduler_cancellation: &ProcessCancellation,
                 review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
                 authorization: SupervisorProcessLaunchAuthorization| {
                    run_with_caller_process_cancellation(
                        caller_cancellation,
                        scheduler_cancellation,
                        cancellation_observed,
                        || {
                            run_external_agent_cancellable_reviewed_authorized(
                                command,
                                scheduler_cancellation,
                                review_runtime,
                                authorization,
                            )
                        },
                    )
                };
            run_supervisor_plan_file_cascade_with_gate(
                SupervisorPlanFileCascadeRequest {
                    options,
                    concurrency_policy,
                    outer_entrypoint: GeneratedFollowUpQueueEntrypoint::AutopilotRun,
                    outer_command_run_id,
                    caller_cancellation: Some(caller_cancellation),
                    cancellation_observed,
                    source_dispatch_started: Some(source_dispatch_started),
                    allow_primary_worktree: false,
                    objective_profile_override: None,
                },
                before_dispatch,
                &external_runner,
            )
        }
        None => run_supervisor_plan_file_cascade_with_gate(
            SupervisorPlanFileCascadeRequest {
                options,
                concurrency_policy,
                outer_entrypoint: GeneratedFollowUpQueueEntrypoint::AutopilotRun,
                outer_command_run_id,
                caller_cancellation: None,
                cancellation_observed,
                source_dispatch_started: Some(source_dispatch_started),
                allow_primary_worktree: false,
                objective_profile_override: None,
            },
            before_dispatch,
            &run_external_agent_cancellable_reviewed_authorized,
        ),
    }
}

struct SupervisorPlanFileCascadeRequest<'a> {
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
    outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    outer_command_run_id: &'a RunId,
    caller_cancellation: Option<&'a ProcessCancellation>,
    cancellation_observed: &'a AtomicBool,
    source_dispatch_started: Option<&'a AtomicBool>,
    allow_primary_worktree: bool,
    objective_profile_override: Option<&'a str>,
}

fn run_supervisor_plan_file_cascade_with_gate(
    request: SupervisorPlanFileCascadeRequest<'_>,
    before_dispatch: &mut dyn FnMut(&SupervisorPlan) -> Result<Option<GateDenial>>,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorCascadeOutcome> {
    let SupervisorPlanFileCascadeRequest {
        options,
        concurrency_policy,
        outer_entrypoint,
        outer_command_run_id,
        caller_cancellation,
        cancellation_observed,
        source_dispatch_started,
        allow_primary_worktree,
        objective_profile_override,
    } = request;
    let max_concurrent_children = concurrency_policy.resolve(HostProcessCapacity::measured());
    validate_max_concurrent_children(max_concurrent_children)?;
    let repo = discover_repo_root(&options.repo)?;
    let mut loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    apply_objective_profile_override(&mut loaded, objective_profile_override);
    let primary_worktree_opt_in =
        validate_execution_target_pre_dispatch(&loaded, allow_primary_worktree)?;
    if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
        bail!("autopilot caller cancelled before exact loaded-plan dispatch");
    }
    if let Some(denial) = before_dispatch(&loaded.plan)? {
        bail!(
            "effective supervisor plan was refused before exact loaded-plan dispatch by denial '{}'",
            denial.denial_id.as_str()
        );
    }
    if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
        bail!("autopilot caller cancelled after gate before exact loaded-plan dispatch");
    }
    let source_loaded = loaded.clone();
    let template = options.clone();
    let source_report = if template.runtime == SupervisorRuntime::Fake {
        if source_loaded.plan_metadata.execution_target.is_some() {
            bail!("nonpublishable Fake cascade cannot use primary-worktree execution");
        }
        let no_external_runner = |_command: &ExternalAgentCommand,
                                  _cancellation: &ProcessCancellation,
                                  _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
                                  _authorization: SupervisorProcessLaunchAuthorization|
         -> ExternalAgentRun {
            panic!("nonpublishable Fake cascade must not launch an external process")
        };
        if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
            bail!("autopilot caller cancelled before admitted runtime catalog resolution");
        }
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::NonpublishableSimulation,
            source_dispatch_started,
            &no_external_runner,
        )?
    } else if source_loaded.plan_metadata.execution_target.is_some() {
        if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
            bail!("autopilot caller cancelled before admitted runtime catalog resolution");
        }
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::PrimaryWorktree(
                primary_worktree_opt_in
                    .as_ref()
                    .context("primary worktree dispatch lost its validated double opt-in")?,
            ),
            source_dispatch_started,
            external_runner,
        )?
    } else {
        let manager = WorktreeManager::new(&repo);
        let cleanliness = manager.acquire_repository_cleanliness()?;
        if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
            bail!("autopilot caller cancelled before admitted runtime catalog resolution");
        }
        authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
            loaded,
            options,
            max_concurrent_children,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::Bound(&cleanliness),
            source_dispatch_started,
            external_runner,
        )?
    };
    run_generated_follow_up_cascade(
        &repo,
        &source_loaded,
        source_report,
        &template,
        FollowUpCascadeInvocation {
            outer_entrypoint,
            outer_command_run_id,
            concurrency_policy,
            runtime_catalog: FollowUpRuntimeCatalog::Production,
        },
        caller_cancellation,
        cancellation_observed,
        before_dispatch,
        external_runner,
    )
}

fn run_supervisor_goal_spec_with_max_concurrent_children(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    max_concurrent_children: usize,
) -> Result<SupervisorFinalReport> {
    validate_max_concurrent_children(max_concurrent_children)?;
    let repo = discover_repo_root(&options.repo)?;
    let loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    let manager = WorktreeManager::new(&repo);
    let cleanliness = manager.acquire_repository_cleanliness()?;
    authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::Bound(&cleanliness),
        None,
        &run_external_agent_cancellable_reviewed_authorized,
    )
}

#[cfg(test)]
pub(super) fn run_supervisor_goal_spec_with_runner_for_test(
    options: SupervisorRunOptions,
    goal: &str,
    spec: &str,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let repo = discover_repo_root(&options.repo)?;
    let loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    let manager = WorktreeManager::new(&repo);
    let cleanliness = manager.acquire_repository_cleanliness()?;
    let runtime_model_catalog = test_runtime_model_catalog(&loaded.plan, options.runtime)?;
    let serialized_runner = Mutex::new(external_runner);
    authorize_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::Bound(&cleanliness),
        Ok(runtime_model_catalog),
        &|command, _cancellation, _review_runtime, _authorization| match serialized_runner.lock() {
            Ok(mut runner) => runner(command),
            Err(poisoned) => poisoned.into_inner()(command),
        },
    )
}

pub fn run_supervisor_plan_file_with_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
) -> Result<SupervisorFinalReport> {
    let external_runner = run_external_agent_cancellable_reviewed_authorized;
    run_supervisor_plan_file_with_runner_and_max_concurrent_children(
        options,
        max_concurrent_children,
        &external_runner,
    )
}

pub fn reaudit_supervisor_assignment(
    request: SupervisorEvidenceOnlyReauditOptions,
) -> Result<SupervisorEvidenceOnlyReauditReport> {
    if request.source_run_id == request.run_id {
        bail!("evidence-only re-audit source and destination run ids must differ");
    }
    let repo = discover_repo_root(&request.repo)?;
    let assignment_id = normalize_agent_id(&request.assignment_id)
        .context("evidence-only re-audit assignment id is invalid")?;
    let source_denial =
        source_auditor_repair_denial(&repo, &request.source_run_id, &assignment_id)?;
    if matches!(
        source_denial.reason,
        GateDenialReason::AuditorRepair {
            rejection: AuditorRejectionKind::ImplementationDefect
        }
    ) {
        return Ok(SupervisorEvidenceOnlyReauditReport {
            source_run_id: request.source_run_id,
            assignment_id,
            run_id: request.run_id,
            success: false,
            gate_denial: Some(source_denial),
            final_report: None,
        });
    }
    let loaded =
        evidence_only_reaudit_plan_from_source(&repo, &request.source_run_id, &assignment_id)?;
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: PathBuf::from("evidence-only-reaudit"),
        run_id: request.run_id,
        parent_node: None,
        codex_bin: request.codex_bin,
        runtime: request.runtime,
        allow_dirty_primary: request.allow_dirty_primary,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: request.machine_global_retention,
    };
    let final_report = authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::ExistingOnly,
        None,
        &run_external_agent_cancellable_reviewed_authorized,
    )?;
    Ok(SupervisorEvidenceOnlyReauditReport {
        source_run_id: request.source_run_id,
        assignment_id,
        run_id: final_report.run_id.clone(),
        success: final_report.success,
        gate_denial: final_report.gate_denials.last().cloned(),
        final_report: Some(final_report),
    })
}

fn source_auditor_repair_denial(
    repo: &Path,
    source_run_id: &RunId,
    assignment_id: &str,
) -> Result<GateDenial> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, source_run_id)
        .context("evidence-only re-audit source is not an authenticated finalized run")?;
    let report = read_supervisor_final_report(&reader)?;
    let child = report
        .orchestrator_reports
        .iter()
        .find(|child| child.id == assignment_id)
        .with_context(|| {
            format!(
                "authenticated source run has no report for assignment '{}'",
                assignment_id
            )
        })?;
    let denials = child
        .gate_denials
        .iter()
        .filter(|denial| {
            denial.context.owner == assignment_id
                && matches!(denial.reason, GateDenialReason::AuditorRepair { .. })
        })
        .collect::<Vec<_>>();
    denials
        .iter()
        .copied()
        .find(|denial| {
            matches!(
                denial.reason,
                GateDenialReason::AuditorRepair {
                    rejection: AuditorRejectionKind::ImplementationDefect
                }
            )
        })
        .or_else(|| denials.first().copied())
        .cloned()
        .context("source assignment has no typed parent-auditor rejection")
}

pub(super) fn evidence_only_reaudit_plan_from_source(
    repo: &Path,
    source_run_id: &RunId,
    assignment_id: &str,
) -> Result<LoadedSupervisorPlan> {
    let assignment_id = normalize_agent_id(assignment_id)
        .context("evidence-only re-audit assignment id is invalid")?;
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, source_run_id)
        .context("evidence-only re-audit source is not an authenticated finalized run")?;
    let source_report = read_supervisor_final_report(&reader)?;
    let source_plan_bytes = reader
        .read("assignments/supervisor-plan.json")
        .context("authenticated source run has no normalized supervisor plan")?;
    let source_plan_text = String::from_utf8(source_plan_bytes)
        .context("authenticated source supervisor plan is not UTF-8")?;
    let source_loaded = parse_supervisor_plan_with_consultant(&source_plan_text)?;
    let source_assignment = source_loaded
        .plan
        .assignments
        .iter()
        .find(|assignment| assignment.id == assignment_id)
        .cloned()
        .with_context(|| {
            format!(
                "authenticated source plan has no assignment '{}'",
                assignment_id
            )
        })?;
    let attempt = source_report
        .evidence_only_reaudit
        .as_ref()
        .map(|record| record.attempt.saturating_add(1))
        .unwrap_or(1);
    let binding = source_report
        .assignment_traceability
        .iter()
        .find(|trace| trace.assignment_id == assignment_id)
        .and_then(|trace| trace.produced_diff_binding.clone())
        .context("evidence-only re-audit source has no preserved candidate binding")?;
    let operation = EvidenceOnlyReauditPlan {
        source_run_id: source_run_id.clone(),
        assignment_id: assignment_id.clone(),
        attempt,
        preserved_candidate_binding: binding,
    };
    verify_evidence_only_reaudit_source(repo, &operation, &source_assignment)?;

    let mut plan = source_loaded.plan;
    plan.task = format!(
        "Evidence-only re-audit of assignment '{}' from authenticated run '{}'",
        assignment_id,
        source_run_id.as_str()
    );
    plan.task_file = None;
    plan.max_child_assignments = 1;
    plan.max_child_retries = 0;
    plan.max_gate_corrections = 0;
    plan.assignments = vec![source_assignment.clone()];
    let mut assignment_metadata = source_loaded.assignment_metadata;
    assignment_metadata.retain_assignment(&assignment_id);
    let fragments = source_loaded
        .plan_metadata
        .spec_fragment_ids_by_assignment
        .get(&assignment_id)
        .cloned()
        .unwrap_or_default();
    let mut fragments_by_assignment = BTreeMap::new();
    fragments_by_assignment.insert(assignment_id.clone(), fragments.clone());
    let plan_metadata = SupervisorPlanMetadata {
        objective_profile: source_loaded.plan_metadata.objective_profile,
        resolved_objective_profile: source_report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.resolved_objective_profile.clone()),
        spec_fragment_ids: fragments,
        spec_fragment_ids_by_assignment: fragments_by_assignment,
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id,
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        coverage_gaps: Vec::new(),
        run_budget: source_loaded.plan_metadata.run_budget,
        run_budget_max_duration_seconds: source_loaded
            .plan_metadata
            .run_budget_max_duration_seconds,
        admission: source_loaded.plan_metadata.admission,
        evidence_only_reaudit: Some(operation),
        generated_follow_up: None,
        execution_target: None,
        path_proposal: source_loaded.plan_metadata.path_proposal.clone(),
        router: source_loaded.plan_metadata.router.clone(),
    };
    let (plan, plan_metadata) = validate_supervisor_plan(plan, plan_metadata)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata,
        plan_metadata,
    })
}

pub(super) fn verify_evidence_only_reaudit_source(
    repo: &Path,
    operation: &EvidenceOnlyReauditPlan,
    expected_assignment: &OrchestratorAssignment,
) -> Result<EvidenceOnlyReauditSource> {
    let reader =
        ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, &operation.source_run_id)
            .context("evidence-only re-audit source is not an authenticated finalized run")?;
    let source_report = read_supervisor_final_report(&reader)?;
    let source_plan_bytes = reader
        .read("assignments/supervisor-plan.json")
        .context("authenticated source run has no normalized supervisor plan")?;
    let source_plan_text = String::from_utf8(source_plan_bytes)
        .context("authenticated source supervisor plan is not UTF-8")?;
    let source_loaded = parse_supervisor_plan_with_consultant(&source_plan_text)?;
    let source_assignment = source_loaded
        .plan
        .assignments
        .iter()
        .find(|assignment| assignment.id == operation.assignment_id)
        .context("authenticated source plan does not contain the re-audit assignment")?;
    if source_assignment != expected_assignment {
        bail!("evidence-only re-audit assignment differs from its authenticated source plan");
    }
    let source_child = source_report
        .orchestrator_reports
        .iter()
        .find(|report| report.id == operation.assignment_id)
        .cloned()
        .context("authenticated source run has no report for the re-audit assignment")?;
    if !report_failed(&source_child) {
        bail!("evidence-only re-audit source assignment was not rejected");
    }
    let implementation_defect_denial = source_child.gate_denials.iter().any(|denial| {
        denial.context.owner == operation.assignment_id
            && matches!(
                denial.reason,
                GateDenialReason::AuditorRepair {
                    rejection: AuditorRejectionKind::ImplementationDefect
                }
            )
    });
    if implementation_defect_denial {
        bail!("evidence-only re-audit refused: source includes an implementation-defect rejection");
    }
    let evidence_denial = source_child.gate_denials.iter().any(|denial| {
        denial.context.owner == operation.assignment_id
            && matches!(
                denial.reason,
                GateDenialReason::AuditorRepair {
                    rejection: AuditorRejectionKind::EvidenceQuality
                }
            )
    });
    if !evidence_denial {
        bail!("evidence-only re-audit refused: source rejection is not typed as evidence quality");
    }
    let source_attempt = source_report
        .evidence_only_reaudit
        .as_ref()
        .map(|record| {
            if record.assignment_id != operation.assignment_id
                || record.source_run_id == operation.source_run_id
                || record.preserved_candidate_binding != operation.preserved_candidate_binding
                || record.accepted
            {
                bail!("authenticated source re-audit lineage is inconsistent");
            }
            Ok(record.attempt)
        })
        .transpose()?
        .unwrap_or(0);
    if operation.attempt != source_attempt.saturating_add(1)
        || operation.attempt == 0
        || operation.attempt > MAX_EVIDENCE_ONLY_REAUDITS
    {
        bail!("evidence-only re-audit attempt does not extend the authenticated bounded lineage");
    }
    let source_binding = source_report
        .assignment_traceability
        .iter()
        .find(|trace| trace.assignment_id == operation.assignment_id)
        .and_then(|trace| trace.produced_diff_binding.as_ref())
        .context("authenticated source assignment has no preserved candidate binding")?;
    if source_binding != &operation.preserved_candidate_binding {
        bail!("evidence-only re-audit candidate binding differs from its authenticated source");
    }
    Ok(EvidenceOnlyReauditSource {
        operation: operation.clone(),
        report: source_child,
    })
}

fn run_supervisor_plan_file_with_runner_and_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    validate_max_concurrent_children(max_concurrent_children)?;
    let repo = discover_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo);
    let cleanliness = manager.acquire_repository_cleanliness()?;
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    validate_execution_target_pre_dispatch(&loaded, false)?;
    authorize_acquire_catalog_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::Bound(&cleanliness),
        None,
        external_runner,
    )
}

fn open_resume_coordination_store_authorized(
    repo: &Path,
    permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<SyncStore> {
    permit
        .verify(MutationOperation::SupervisorCoordinationStoreBootstrap)
        .map_err(anyhow::Error::from)?;
    SyncStore::open(repo)
}

fn open_resume_semantic_store_authorized(
    repo: &Path,
    permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<SemanticIntentStore> {
    permit
        .verify(MutationOperation::SupervisorCoordinationStoreBootstrap)
        .map_err(anyhow::Error::from)?;
    SemanticIntentStore::open(repo)
}

fn complete_planned_scheduler_resource_release_authorized(
    sync_store: &SyncStore,
    semantic_store: &SemanticIntentStore,
    report: &SupervisorFinalReport,
    claim_permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
    semantic_permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<()> {
    claim_permit
        .verify(MutationOperation::ClaimRelease)
        .map_err(anyhow::Error::from)?;
    semantic_permit
        .verify(MutationOperation::SemanticIntentRelease)
        .map_err(anyhow::Error::from)?;
    complete_planned_scheduler_resource_release(
        sync_store,
        semantic_store,
        report,
        claim_permit,
        semantic_permit,
    )
}

fn reopen_resume_artifacts_authorized(
    repo: &Path,
    binding: &ArtifactRunResumeBinding,
    recovery: Option<&[ArtifactRecoveryFile<'_>]>,
    permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<ArtifactRunWriter> {
    permit
        .verify(MutationOperation::SupervisorRunArtifactWriteAppend)
        .map_err(anyhow::Error::from)?;
    match recovery {
        Some(recovery) => {
            ArtifactRunWriter::reopen_unfinalized_with_recovery(repo, binding, recovery)
        }
        None => ArtifactRunWriter::reopen_unfinalized(repo, binding),
    }
}

fn finalize_resume_artifacts_authorized(
    writer: ArtifactRunWriter,
    report_path: &Path,
    publish_requested: bool,
    permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<()> {
    finalize_supervisor_artifact_run(writer, report_path, publish_requested, permit)
}

pub fn resume_supervisor_run(
    repo: impl AsRef<Path>,
    run_id: RunId,
) -> Result<SupervisorResumeReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    if let Some(report) = read_finalized_supervisor_report(&repo, &run_id, &run_dir)? {
        return Ok(SupervisorResumeReport {
            run_id,
            repo: PathBuf::from("."),
            lifecycle: SupervisorRunLifecycle::Finalized,
            success: true,
            resumed: false,
            budget_reconciled_from_checkpoint: false,
            run_budget: report.run_budget.clone(),
            completed_assignments: report
                .orchestrator_reports
                .iter()
                .map(|child| child.id.clone())
                .collect(),
            pending_assignments: Vec::new(),
            uncertain_assignments: Vec::new(),
            gate_denial: None,
            final_report: Some(report),
        });
    }

    let read_snapshot = match read_supervisor_checkpoint(&repo, &run_id) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let denial = unsupported_checkpoint_version_denial(&error)
                .unwrap_or(ResumeCheckpointDenial::IntegrityFailure);
            return resume_refusal(
                &run_id,
                SupervisorRunLifecycle::Interrupted,
                denial,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Some(format!("{error:#}")),
            );
        }
    };
    if !read_snapshot.uncertain_assignments.is_empty() {
        let denial = GateDenial::new(
            run_id.as_str(),
            GateDenialReason::ExternalSideEffect {
                state: ExternalSideEffectState::Ambiguous,
            },
            VerifiedGateContext::new(
                run_id.as_str(),
                GateCheckSource::ExternalSideEffect,
                std::iter::empty::<&Path>(),
            )?,
        )?;
        return Ok(SupervisorResumeReport {
            run_id,
            repo: PathBuf::from("."),
            lifecycle: SupervisorRunLifecycle::Uncertain,
            success: false,
            resumed: false,
            budget_reconciled_from_checkpoint: false,
            run_budget: None,
            completed_assignments: read_snapshot.completed_assignments,
            pending_assignments: read_snapshot.pending_assignments,
            uncertain_assignments: read_snapshot.uncertain_assignments,
            gate_denial: Some(denial),
            final_report: None,
        });
    }
    let Some(plan) = read_snapshot.final_report.as_ref() else {
        return resume_refusal(
            &run_id,
            SupervisorRunLifecycle::Interrupted,
            ResumeCheckpointDenial::UnsupportedLifecycle,
            read_snapshot.completed_assignments,
            read_snapshot.pending_assignments,
            read_snapshot.uncertain_assignments,
            None,
        );
    };
    if read_snapshot.finalized {
        return resume_refusal(
            &run_id,
            SupervisorRunLifecycle::Interrupted,
            ResumeCheckpointDenial::IntegrityFailure,
            read_snapshot.completed_assignments,
            read_snapshot.pending_assignments,
            read_snapshot.uncertain_assignments,
            Some(
                "checkpoint claims finalization but the authenticated artifact marker is missing"
                    .to_string(),
            ),
        );
    }
    let manager = WorktreeManager::new(&repo);
    let _primary_cleanliness = match read_snapshot.verify_primary_binding(&repo, &manager) {
        Ok(cleanliness) => cleanliness,
        Err(error) => {
            return resume_refusal(
                &run_id,
                SupervisorRunLifecycle::Interrupted,
                ResumeCheckpointDenial::IntegrityFailure,
                read_snapshot.completed_assignments,
                read_snapshot.pending_assignments,
                read_snapshot.uncertain_assignments,
                Some(format!("{error:#}")),
            )
        }
    };
    if let Err(error) = read_snapshot.verify_completed_worktrees(&manager) {
        return resume_refusal(
            &run_id,
            SupervisorRunLifecycle::Interrupted,
            ResumeCheckpointDenial::IntegrityFailure,
            read_snapshot.completed_assignments,
            read_snapshot.pending_assignments,
            read_snapshot.uncertain_assignments,
            Some(format!("{error:#}")),
        );
    }
    let artifact_binding_sha256 = crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(&plan.artifact)
            .context("failed to encode authenticated resume artifact binding")?,
    );
    let primary_baseline_sha256 = if plan.report.runtime == SupervisorRuntime::Fake {
        nonpublishable_simulation_whole_primary_snapshot_sha256(&repo)?
    } else {
        verified_whole_primary_snapshot_sha256(&repo)?
    };
    let queue_item_sha256 = matches!(
        read_snapshot.dispatch_identity(),
        EffectiveSupervisorDispatchIdentity::GeneratedFollowUpSubordinate { .. }
    )
    .then(|| generated_follow_up_item_id_from_subordinate_run_id(run_id.as_str()))
    .transpose()?;
    let repository_identity = effective_repository_identity(&repo)?;
    let resume_manifest = EffectiveSupervisorMutationManifest::resume_recovery(
        EffectiveResumeRecoveryManifestInput {
            identity: EffectiveSupervisorMutationIdentityInput {
                run_id: run_id.as_str().to_string(),
                parent_node: read_snapshot.parent_node().map(str::to_string),
                normalized_plan_sha256: read_snapshot.normalized_plan_sha256().to_string(),
                dispatch_identity: read_snapshot.dispatch_identity().clone(),
                execution_runtime: if plan.report.runtime == SupervisorRuntime::Fake {
                    EffectiveSupervisorExecutionRuntime::NonpublishableSimulation
                } else {
                    EffectiveSupervisorExecutionRuntime::Verified
                },
                worktree_mode: EffectiveSupervisorWorktreeMode::NotApplicable,
                runtime_adapter: Some(
                    crate::runtime_adapter::AdapterId::from_runtime(plan.report.runtime)
                        .as_str()
                        .to_string(),
                ),
                repository_identity,
                artifact_family: "supervise".to_string(),
                delivery_identity: artifact_binding_sha256,
                machine_global_retention_sha256: None,
                queue_item_sha256,
                task_batch_sha256: None,
                primary_baseline_sha256: Some(primary_baseline_sha256),
                outer_entrypoint: None,
                outer_run_id: None,
            },
        },
    );
    let authorized_resume = authorize_effective_supervisor_manifest(resume_manifest)?;
    let (resume_evidence, resume_session) = authorized_resume.into_resume_recovery()?;
    if resume_session.canonical_manifest_sha256() != resume_evidence.canonical_manifest_sha256() {
        bail!("resume recovery session is bound to different audit evidence");
    }
    let (mut checkpoint, snapshot) =
        open_supervisor_checkpoint_authorized(&repo, &run_id, &resume_session)?;
    if snapshot.normalized_plan_sha256() != read_snapshot.normalized_plan_sha256()
        || snapshot.parent_node() != read_snapshot.parent_node()
        || snapshot.dispatch_identity() != read_snapshot.dispatch_identity()
        || snapshot.primary_base() != read_snapshot.primary_base()
    {
        bail!("supervisor checkpoint identity changed during admitted recovery open");
    }
    let messaging_permit =
        resume_session.permit(MutationOperation::SupervisorMessagingJournalLifecycle)?;
    messaging_bridge::recover_supervisor_messaging_session_authorized(&run_dir, &messaging_permit)
        .context("supervisor messaging resume recovery failed")?;
    let coordination_permit =
        resume_session.permit(MutationOperation::SupervisorCoordinationStoreBootstrap)?;
    let sync_store = open_resume_coordination_store_authorized(&repo, &coordination_permit)?;
    let claim_disposition = (|| -> Result<()> {
        snapshot.verify_claim_disposition(&sync_store, &plan.report, !plan.artifact_committed)?;
        if !plan.artifact_committed {
            let claim_release_permit = resume_session.permit(MutationOperation::ClaimRelease)?;
            let semantic_release_permit =
                resume_session.permit(MutationOperation::SemanticIntentRelease)?;
            let semantic_store =
                open_resume_semantic_store_authorized(&repo, &coordination_permit)?;
            complete_planned_scheduler_resource_release_authorized(
                &sync_store,
                &semantic_store,
                &plan.report,
                &claim_release_permit,
                &semantic_release_permit,
            )?;
            snapshot.verify_claim_disposition(&sync_store, &plan.report, false)?;
        }
        Ok(())
    })();
    if let Err(error) = claim_disposition {
        return resume_refusal(
            &run_id,
            SupervisorRunLifecycle::Interrupted,
            ResumeCheckpointDenial::IntegrityFailure,
            snapshot.completed_assignments,
            snapshot.pending_assignments,
            snapshot.uncertain_assignments,
            Some(format!("{error:#}")),
        );
    }

    let report_path = RunArtifactFamily::Supervise.final_report_relative_path();
    let artifact_write_permit =
        resume_session.permit(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    let artifact_writer_result = if plan.artifact_committed {
        reopen_resume_artifacts_authorized(&repo, &plan.artifact, None, &artifact_write_permit)
    } else {
        let recovery = ArtifactRecoveryFile {
            relative: &report_path,
            contents: &plan.report_bytes,
            disposition: ArtifactFileDisposition::PrivateEvidence,
        };
        reopen_resume_artifacts_authorized(
            &repo,
            &plan.artifact,
            Some(&[recovery]),
            &artifact_write_permit,
        )
    };
    let mut artifact_writer = match artifact_writer_result {
        Ok(writer) => writer,
        Err(error) => {
            return resume_refusal(
                &run_id,
                SupervisorRunLifecycle::Interrupted,
                ResumeCheckpointDenial::IntegrityFailure,
                snapshot.completed_assignments,
                snapshot.pending_assignments,
                snapshot.uncertain_assignments,
                Some(format!("{error:#}")),
            )
        }
    };
    write_artifact_json(
        &mut artifact_writer,
        Path::new("resume-effective-mutation-manifest.json"),
        &resume_evidence,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    if !plan.artifact_committed {
        resume_session
            .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
            .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
        checkpoint.final_report_committed(
            &plan.report,
            &plan.report_bytes,
            artifact_writer.resume_binding()?,
        )?;
    }
    if !snapshot.finalization_started {
        resume_session
            .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
            .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
        checkpoint.finalization_started(&plan.report, &plan.report_bytes)?;
    }
    let artifact_finalize_permit =
        resume_session.permit(MutationOperation::SupervisorRunArtifactAuthenticatedFinalize)?;
    finalize_resume_artifacts_authorized(
        artifact_writer,
        &report_path,
        plan.publish_requested,
        &artifact_finalize_permit,
    )?;
    resume_session
        .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
        .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
    checkpoint.finalized(&plan.report, &plan.report_bytes)?;
    let report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?
        .context("resumed supervise finalization did not publish a verified final report")?;
    if report != plan.report {
        bail!("resumed finalized report differs from its authenticated checkpoint plan");
    }
    Ok(SupervisorResumeReport {
        run_id,
        repo: PathBuf::from("."),
        lifecycle: SupervisorRunLifecycle::Finalized,
        success: true,
        resumed: true,
        budget_reconciled_from_checkpoint: true,
        run_budget: report.run_budget.clone(),
        completed_assignments: snapshot.completed_assignments,
        pending_assignments: snapshot.pending_assignments,
        uncertain_assignments: snapshot.uncertain_assignments,
        gate_denial: None,
        final_report: Some(report),
    })
}

fn resume_refusal(
    run_id: &RunId,
    lifecycle: SupervisorRunLifecycle,
    denial: ResumeCheckpointDenial,
    completed_assignments: Vec<String>,
    pending_assignments: Vec<String>,
    uncertain_assignments: Vec<String>,
    diagnostic: Option<String>,
) -> Result<SupervisorResumeReport> {
    let gate_denial = GateDenial::new(
        run_id.as_str(),
        GateDenialReason::ResumeCheckpoint { denial },
        VerifiedGateContext::new(
            run_id.as_str(),
            GateCheckSource::AuthenticatedCheckpoint,
            std::iter::empty::<&Path>(),
        )?,
    )?;
    let _ = diagnostic;
    Ok(SupervisorResumeReport {
        run_id: run_id.clone(),
        repo: PathBuf::from("."),
        lifecycle,
        success: false,
        resumed: false,
        budget_reconciled_from_checkpoint: false,
        run_budget: None,
        completed_assignments,
        pending_assignments,
        uncertain_assignments,
        gate_denial: Some(gate_denial),
        final_report: None,
    })
}

pub fn supervisor_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<SupervisorStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    let final_report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?;
    let (lifecycle, resume_gate_denial) = if final_report.is_some() {
        (SupervisorRunLifecycle::Finalized, None)
    } else {
        match read_supervisor_checkpoint(&repo, &run_id) {
            Ok(snapshot) if !snapshot.uncertain_assignments.is_empty() => {
                let denial = GateDenial::new(
                    run_id.as_str(),
                    GateDenialReason::ExternalSideEffect {
                        state: ExternalSideEffectState::Ambiguous,
                    },
                    VerifiedGateContext::new(
                        run_id.as_str(),
                        GateCheckSource::ExternalSideEffect,
                        std::iter::empty::<&Path>(),
                    )?,
                )?;
                (SupervisorRunLifecycle::Uncertain, Some(denial))
            }
            Ok(snapshot) if snapshot.final_report.is_some() => {
                (SupervisorRunLifecycle::Resumable, None)
            }
            Ok(_snapshot) => {
                let refusal = resume_refusal(
                    &run_id,
                    SupervisorRunLifecycle::Interrupted,
                    ResumeCheckpointDenial::UnsupportedLifecycle,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                )?;
                (SupervisorRunLifecycle::Interrupted, refusal.gate_denial)
            }
            Err(error) => {
                let denial = unsupported_checkpoint_version_denial(&error)
                    .unwrap_or(ResumeCheckpointDenial::IntegrityFailure);
                let refusal = resume_refusal(
                    &run_id,
                    SupervisorRunLifecycle::Interrupted,
                    denial,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                )?;
                (SupervisorRunLifecycle::Interrupted, refusal.gate_denial)
            }
        }
    };
    let heartbeats = crate::run_ops::read_heartbeat_ledger(&run_dir).unwrap_or_default();
    Ok(SupervisorStatusReport {
        run_id,
        repo: PathBuf::from("."),
        run_dir: run_dir
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.run_root()),
        final_report_exists: final_report.is_some(),
        lifecycle,
        resume_gate_denial,
        last_heartbeat: heartbeats.last().cloned(),
        heartbeat_count: heartbeats.len(),
        operator_summary_exists: crate::run_ops::operator_summary_exists(&run_dir),
        final_report_path: final_report_path
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.final_report_relative_path()),
        final_report,
    })
}

pub fn collect_supervisor_run(
    repo: impl AsRef<Path>,
    run_id: RunId,
) -> Result<SupervisorFinalReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    if let Some(report) = read_finalized_supervisor_report(&repo, &run_id, &run_dir)? {
        return Ok(report);
    }
    let status = supervisor_status(&repo, run_id.clone())?;
    let lifecycle = status.lifecycle;
    let gate_denials = status.resume_gate_denial.into_iter().collect::<Vec<_>>();
    let (remaining_risk, next_safe_action) = match lifecycle {
        SupervisorRunLifecycle::Active => (
            "the supervise scheduler is still active and no finalized report exists".to_string(),
            "wait for the active scheduler or inspect status without starting a second run"
                .to_string(),
        ),
        SupervisorRunLifecycle::Resumable => (
            "the authenticated checkpoint can safely resume artifact finalization only".to_string(),
            format!("run `maco supervise resume {}`", run_id.as_str()),
        ),
        SupervisorRunLifecycle::Uncertain => (
            "an authenticated dispatch start lacks durable completion; repeating it could duplicate side effects".to_string(),
            "reconcile or explicitly abandon the uncertain attempt under a new identity; do not rerun it blindly".to_string(),
        ),
        SupervisorRunLifecycle::Interrupted => (
            "run artifacts are incomplete and the authenticated lifecycle is not safely resumable".to_string(),
            "inspect the typed checkpoint gate denial and start a new run only after reconciliation".to_string(),
        ),
        SupervisorRunLifecycle::Finalized => (
            "the finalized marker and report disagree".to_string(),
            "inspect authenticated artifact integrity before proceeding".to_string(),
        ),
    };

    Ok(SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id,
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: PathBuf::new(),
        run_dir: run_dir
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.run_root()),
        runtime: SupervisorRuntime::Codex,
        publishable: false,
        success: false,
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        run_lifecycle: lifecycle,
        evidence_only_reaudit: None,
        assigned_paths: Vec::new(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: Vec::new(),
        semantic_intent_tokens: Vec::new(),
        role_economics_profile: None,
        run_budget: None,
        role_usage: BTreeMap::new(),
        review_lens_usage: Vec::new(),
        review_lens_total_usage: None,
        review_lens_total_cost_usd: None,
        total_usage: None,
        total_cost_usd: None,
        usage_complete: false,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        sandbox_denials: Vec::new(),
        gate_denials,
        pre_action_review_metrics: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        autonomy_kpis: AutonomyKpiReport::default(),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: "supervisor final report is missing".to_string(),
            paths: vec![final_report_path],
        }],
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        generated_follow_up_tasks: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        breaker_trip: None,
        orchestrator_reports: Vec::new(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk,
        next_safe_action,
    })
}

pub fn verified_megafile_decomposition_evidence(
    repo: impl AsRef<Path>,
    run_id: RunId,
    orchestrator_id: &str,
    target_path: &Path,
    candidate_changed_paths: &[PathBuf],
) -> Result<VerifiedMegafileDecompositionEvidence> {
    let repo = discover_repo_root(repo.as_ref())?;
    let normalized_target = normalize_report_target_path(
        Some(target_path.to_path_buf()),
        "megafile decomposition target",
    )?
    .context("megafile decomposition target is required")?;
    let normalized_candidate_paths =
        normalize_paths(candidate_changed_paths.to_vec()).context("candidate paths are invalid")?;
    if normalized_candidate_paths.is_empty() {
        bail!("candidate has no changed paths");
    }
    let run_dir = run_dir(&repo, &run_id);
    let report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?
        .with_context(|| format!("supervisor run '{}' is not finalized", run_id.as_str()))?;
    if report.run_id != run_id {
        bail!(
            "finalized supervisor report run id '{}' does not match requested run '{}'",
            report.run_id.as_str(),
            run_id.as_str()
        );
    }
    if report.runtime != SupervisorRuntime::Codex
        || !report.publishable
        || !report.success
        || !report.accepted
        || report.rejected
        || report.status != ReviewStatus::Succeeded
        || report.breaker_trip.is_some()
        || !report.release_errors.is_empty()
        || !report.semantic_release_errors.is_empty()
    {
        bail!(
            "supervisor run '{}' is not accepted successful publishable evidence",
            run_id.as_str()
        );
    }
    let normalized_supervisor_paths = normalize_paths(report.files_changed.clone())
        .context("supervisor files_changed invalid")?;
    if normalized_supervisor_paths != normalized_candidate_paths {
        bail!(
            "supervisor run '{}' files_changed does not exactly match the merge candidate",
            run_id.as_str()
        );
    }

    let matching_children = report
        .orchestrator_reports
        .iter()
        .filter(|child| child.id == orchestrator_id)
        .collect::<Vec<_>>();
    let child = match matching_children.as_slice() {
        [child] => *child,
        [] => bail!(
            "supervisor run '{}' has no child orchestrator report for merge candidate agent '{}'",
            run_id.as_str(),
            orchestrator_id
        ),
        _ => bail!(
            "supervisor run '{}' has ambiguous child orchestrator reports for merge candidate agent '{}'",
            run_id.as_str(),
            orchestrator_id
        ),
    };
    if child.role != AgentRole::ChildOrchestrator || report_failed(child) {
        bail!(
            "child orchestrator '{}' is not accepted successful evidence",
            orchestrator_id
        );
    }
    let normalized_child_paths =
        normalize_paths(child.files_changed.clone()).context("child files_changed invalid")?;
    if normalized_child_paths != normalized_candidate_paths {
        bail!(
            "child orchestrator '{}' files_changed does not exactly match the merge candidate",
            orchestrator_id
        );
    }

    let mut matching_workers = Vec::new();
    for worker in &child.worker_reports {
        if worker.assignment_kind != AssignmentKind::MegafileDecomposition {
            continue;
        }
        let worker_target =
            normalize_report_target_path(worker.target_path.clone(), "worker target_path")?;
        if worker_target.as_ref() == Some(&normalized_target) {
            matching_workers.push(worker);
        }
    }
    let worker = match matching_workers.as_slice() {
        [worker] => *worker,
        [] => bail!(
            "child orchestrator '{}' has no megafile_decomposition worker for exact target '{}'",
            orchestrator_id,
            normalized_target.display()
        ),
        _ => bail!(
            "child orchestrator '{}' has ambiguous megafile_decomposition workers for exact target '{}'",
            orchestrator_id,
            normalized_target.display()
        ),
    };
    if worker.role != AgentRole::Worker
        || report_failed(worker)
        || worker.no_further_delegation != Some(true)
    {
        bail!(
            "megafile_decomposition worker '{}' is not accepted successful terminal evidence",
            worker.id
        );
    }
    let completion = worker
        .decomposition_completion
        .clone()
        .map(normalize_decomposition_completion)
        .transpose()?
        .context("accepted megafile_decomposition worker omitted completion evidence")?;
    if completion.target_path != normalized_target {
        bail!("worker decomposition completion target does not match the merge target");
    }
    let supervisor_candidate_binding = completion
        .supervisor_candidate_binding
        .clone()
        .context(
            "accepted megafile_decomposition worker evidence is missing the supervisor-inspected candidate binding",
        )?;
    if supervisor_candidate_binding.agent_id != child.id {
        bail!(
            "supervisor-inspected decomposition candidate binding agent '{}' does not match child orchestrator '{}'",
            supervisor_candidate_binding.agent_id,
            child.id
        );
    }
    let worker_paths =
        normalize_paths(worker.files_changed.clone()).context("worker files_changed invalid")?;
    let expected_decomposition_paths = std::iter::once(completion.target_path.clone())
        .chain(completion.replacement_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if worker_paths != expected_decomposition_paths {
        bail!(
            "worker files_changed must exactly equal the decomposition target plus evidence-bound replacement paths"
        );
    }
    if normalized_candidate_paths != expected_decomposition_paths {
        bail!(
            "merge candidate changed paths must exactly equal the decomposition target plus evidence-bound replacement paths"
        );
    }

    let child_completions = child
        .decomposition_completions
        .iter()
        .cloned()
        .map(normalize_decomposition_completion)
        .collect::<Result<BTreeSet<_>>>()?;
    if !child_completions.contains(&completion) {
        bail!("child orchestrator omitted the accepted worker decomposition completion");
    }
    let final_completions = report
        .decomposition_candidates
        .iter()
        .cloned()
        .map(normalize_decomposition_completion)
        .collect::<Result<BTreeSet<_>>>()?;
    if !final_completions.contains(&completion) {
        bail!("supervisor final report omitted the accepted decomposition completion");
    }

    let expected_auditor_id = format!("{}-review-auditor", child.id);
    let expected_lens_auditor_prefix = format!("{}-review-auditor-lens-", child.id);
    let audit = child
        .audit_reports
        .iter()
        .find(|audit| {
            (audit.id == expected_auditor_id || audit.id.starts_with(&expected_lens_auditor_prefix))
                && audit.role == AgentRole::Auditor
                && !report_failed(*audit)
                && audit.no_further_delegation == Some(true)
                && audit.read_only
                && !audit.commands_run.is_empty()
                && !audit.validation_results.is_empty()
                && !audit.validation_results.iter().any(validation_failed)
                && audit.reviewed_worker_ids.iter().any(|id| id == &worker.id)
        })
        .context("accepted parent review-auditor evidence is missing")?;
    let reviewed_paths = audit
        .reviewed_paths
        .iter()
        .filter_map(|path| normalize_repo_relative_path(path).ok())
        .collect::<BTreeSet<_>>();
    let missing_audit_paths = normalized_candidate_paths
        .iter()
        .filter(|required| {
            !reviewed_paths
                .iter()
                .any(|reviewed| path_is_covered_by_claim(required, reviewed))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing_audit_paths.is_empty() {
        bail!(
            "parent review-auditor evidence does not cover exact candidate paths: {}",
            display_paths(&missing_audit_paths)
        );
    }

    Ok(VerifiedMegafileDecompositionEvidence {
        run_id,
        orchestrator_id: child.id.clone(),
        worker_id: worker.id.clone(),
        target_path: completion.target_path,
        replacement_paths: completion.replacement_paths,
        supervisor_candidate_binding,
    })
}

#[cfg(test)]
mod diagnostics_emission_tests {
    use super::*;
    use git2::Signature;
    use tempfile::TempDir;

    fn commit_all(repo: &git2::Repository, message: &str) {
        let mut index = repo.index().expect("index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("stage");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature = Signature::now("maco test", "maco-test@example.invalid").expect("sig");
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .expect("commit");
    }

    fn nested_planning_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir_all(repo_path.join("src")).expect("src");
        fs::write(repo_path.join("README.md"), "hello\n").expect("readme");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("lib");
        let repo = git2::Repository::init(&repo_path).expect("init");
        commit_all(&repo, "outer");
        for boundary in [
            "zeta/nested",
            "alpha/nested",
            "middle/nested",
            "beta/nested",
        ] {
            let nested_path = repo_path.join(boundary);
            fs::create_dir_all(nested_path.join("src")).expect("nested src");
            fs::write(
                nested_path.join("src/excluded.rs"),
                "pub fn nested_only() {}\n",
            )
            .expect("excluded");
            let nested = git2::Repository::init(&nested_path).expect("nested init");
            commit_all(&nested, "nested");
        }
        (temp, repo_path)
    }

    #[test]
    fn existing_file_edit_verification_task_parser_is_exact_and_unambiguous() {
        let target = Path::new("README.md");
        for exact_literal_edit in [
            "In README.md, replace the old line with exactly: replacement. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In `README.md`, replace the entire contents with exactly one line: replacement. Verify the result with git diff --check and confirm that `README.md` contains exactly that line.",
        ] {
            assert!(
                explicit_existing_file_edit_verification_task(exact_literal_edit, target),
                "failed to recognize exact literal edit: {exact_literal_edit}"
            );
        }

        for untrusted_or_ambiguous in [
            "Update README.md.",
            "In README.md, replace the old line and confirm README.md contains exactly that line.",
            "In README.md, replace something. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the old line with exactly: . Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the entire contents with exactly one line: ``. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the old line with exactly: first, then replace it with exactly: second. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the entire contents with exactly one line: first, then replace the old line with exactly: second. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the old line. Verify with git diff --check.",
            "In OTHER.md, replace the old line. Verify with git diff --check and confirm OTHER.md contains exactly that line.",
            "In OTHER.md, replace the old line with exactly: replacement. Verify the result with git diff --check and confirm README.md contains exactly that line.",
            "In README.md, replace the old line with exactly: replacement. Verify the result with git diff --check and confirm OTHER.md contains exactly that line.",
            "In README.md, replace the old line. Run git diff --check twice: git diff --check, then confirm README.md contains exactly that line.",
            "In README.md, replace the old line with exactly: replacement. Verify the result with git diff --check and confirm README.md contains exactly that line, then confirm README.md contains exactly that line.",
            "In README.md, replace the old line with exactly: replacement. Verify the result with git diff --check and confirm README.md contains exactly that line. Verify the result with git diff --check and confirm README.md contains exactly that line.",
        ] {
            assert!(
                !explicit_existing_file_edit_verification_task(untrusted_or_ambiguous, target),
                "unexpectedly recognized: {untrusted_or_ambiguous}"
            );
        }
    }

    #[test]
    fn existing_file_edit_rust_test_contract_fallback_is_fail_closed() {
        const TARGET: &str = "src/process_runner/part3.rs";
        const TEST_PATH: &str =
            "process_runner::tests::stuck_owned_io_thread_aborts_instead_of_detaching";
        let target = Path::new(TARGET);
        let edit_task = format!(
            "Edit only the existing file {TARGET}. Change OwnedIoThread::finish so cfg(test) uses \
             TestIoFinalizationClock and cfg(not(test)) uses RealIoThreadClock, matching \
             finish_child_io. Do not alter THREAD_JOIN_GRACE, production behavior, or any other \
             file. "
        );
        let accepted = format!(
            "{edit_task}The existing exact test {TEST_PATH} is the verification contract. Run \
             that exact test, commit the one-file change, and report the commit."
        );

        assert_eq!(
            existing_file_task_paths(&[
                "Run that exact test, commit the one-file change, and report the commit"
            ]),
            Some(Vec::new()),
            "noun change in the final clause must not create a path"
        );

        for positive_directive in ["Edit", "Change", "Update"] {
            let task = accepted.replacen("Edit", positive_directive, 1);
            assert!(
                explicit_existing_file_edit_verification_task(&task, target),
                "failed to recognize positive {positive_directive} directive"
            );
        }

        for appended in [
            "Update Makefile.",
            "Also inspect Makefile.",
            "Also inspect `Dockerfile`.",
            "Do not modify src/process_runner/part3.rs.",
            "Modify src/process_runner/part3.rs when needed.",
            "Never run the test.",
            "Also inspect src/other.rs.",
            "Also inspect `src/other.rs`.",
            "Also inspect README.md.",
            "Also inspect \"README.md\".",
            "Also inspect src/process_runner/part3.rs.",
        ] {
            let task = format!("{accepted} {appended}");
            assert!(
                !explicit_existing_file_edit_verification_task(&task, target),
                "unexpectedly accepted appended clause: {appended}"
            );
        }

        for alternate_edit_verb in ["Modify", "Alter", "Touch", "Patch", "Rewrite"] {
            let task = accepted.replacen("Edit", alternate_edit_verb, 1);
            assert!(
                !explicit_existing_file_edit_verification_task(&task, target),
                "unexpectedly accepted {alternate_edit_verb} as the positive directive"
            );
        }

        for rejected_verification_clause in [
            "Do not run the test.",
            "Dont run the test.",
            "Not running the test is acceptable.",
            "No test execution is required.",
            "Never run the test.",
            "Verify without running the test.",
            "Skip the test.",
            "If needed, run the test.",
            "Unless convenient, skip the test.",
            "When practical, run the test.",
            "Maybe run the test.",
            "Optionally run the test.",
            "You may run the test.",
            "You might run the test.",
            "You could run the test.",
        ] {
            let task = format!("{accepted} {rejected_verification_clause}");
            assert!(
                !explicit_existing_file_edit_verification_task(&task, target),
                "unexpectedly accepted qualified verification: {rejected_verification_clause}"
            );
        }

        for generic_contract in [
            "Cargo test is the verification contract.",
            "Git status is the verification contract.",
            "Run tests is the verification contract.",
            "Execute tests is the verification contract.",
            "A command is the verification contract.",
        ] {
            let task = format!("{edit_task}{generic_contract}");
            assert!(
                !explicit_existing_file_edit_verification_task(&task, target),
                "unexpectedly accepted generic contract: {generic_contract}"
            );
        }

        assert!(
            !explicit_existing_file_edit_verification_task(&edit_task, target),
            "accepted a task with no verification contract"
        );
        let same_clause = format!(
            "Edit only the existing file {TARGET} and {TEST_PATH} is the verification contract."
        );
        assert!(
            !explicit_existing_file_edit_verification_task(&same_clause, target),
            "accepted an edit and contract in the same clause"
        );
        let unbalanced_quote = format!("{accepted} Also inspect \"src/other.rs.");
        assert!(
            !explicit_existing_file_edit_verification_task(&unbalanced_quote, target),
            "accepted an unbalanced quoted path"
        );

        for malformed_test_path in [
            "process_runner",
            "process_runner::tests::",
            "process_runner:tests::stuck_owned_io_thread",
            "process_runner::tests::stuck-owned-io-thread",
            "process_runner::tests::stuck_owned_io_thread()",
            "::process_runner::tests::stuck_owned_io_thread",
            "process_runner::tests::<stuck_owned_io_thread>",
        ] {
            let task = format!(
                "{edit_task}The existing exact test {malformed_test_path} is the exact \
                 verification contract."
            );
            assert!(
                !explicit_existing_file_edit_verification_task(&task, target),
                "unexpectedly accepted malformed Rust test path: {malformed_test_path}"
            );
        }
    }

    #[test]
    fn goal_derived_plan_preserves_sorted_nested_boundary_diagnostics() {
        let (_temp, repo_path) = nested_planning_repo();
        let document = supervisor_plan_document_from_goal_spec(
            &repo_path,
            "Update README.md",
            "Keep src/lib.rs working.",
        )
        .expect("plan nested repository");
        let diagnostics = document
            .get("path_proposal")
            .expect("path_proposal must be first-class");
        assert_eq!(diagnostics["degraded"], false);
        let notes = diagnostics["notes"]
            .as_array()
            .expect("notes")
            .iter()
            .map(|note| note.as_str().expect("note").to_string())
            .collect::<Vec<_>>();
        assert!(
            notes.iter().any(|note| {
                note.contains("showing first 3 sorted paths")
                    && note.contains("alpha/nested")
                    && note.contains("beta/nested")
                    && note.contains("middle/nested")
                    && !note.contains("zeta/nested")
            }),
            "sorted bounded notes missing: {notes:?}"
        );
        let assignment_tasks = document["assignments"]
            .as_array()
            .expect("assignments")
            .iter()
            .filter_map(|assignment| assignment["task"].as_str())
            .collect::<Vec<_>>();
        assert!(assignment_tasks
            .iter()
            .all(|task| !task.contains("Planning inventory diagnostics:")));

        let serialized = serde_json::to_string(&document).expect("serialize");
        let reloaded = parse_supervisor_plan_with_consultant(&serialized).expect("reload");
        let round_trip = supervisor_plan_value(
            &reloaded.plan,
            &reloaded.consultant,
            &reloaded.assignment_metadata,
            &reloaded.plan_metadata,
        )
        .expect("re-emit");
        assert_eq!(round_trip["path_proposal"], document["path_proposal"]);
        assert_eq!(round_trip["path_proposal"]["degraded"], false);
        assert_eq!(round_trip["assignments"], document["assignments"]);
        assert_eq!(
            document["run_budget"]["role_token_reservations"]["child_orchestrator"],
            CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS
        );
        assert_eq!(
            document["run_budget"]["role_token_reservations"]["worker"],
            CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS
        );
        assert_eq!(
            document["run_budget"]["role_token_reservations"]["auditor"],
            CONSERVATIVE_GENERATED_ROLE_RESERVATION_TOKENS
        );
    }

    #[test]
    fn inventory_failure_envelope_keeps_error_chain() {
        let error = anyhow::anyhow!("bounded-status rejects Git object alternates")
            .context("repository inventory failed");
        let envelope = supervisor_plan_error_envelope(&error);
        assert!(!envelope.success);
        assert_eq!(envelope.status, "error");
        assert!(envelope.error.contains("repository inventory failed"));
        assert!(envelope
            .causes
            .iter()
            .any(|cause| cause.contains("bounded-status rejects Git object alternates")));
        let value = serde_json::to_value(&envelope).expect("serialize envelope");
        assert_eq!(value["success"], false);
        assert_eq!(value["status"], "error");
    }

    fn fixture_plan_json(role_category: &str, selection_source: Option<&str>) -> String {
        let selection = match selection_source {
            Some(source) => format!(r#", "selection_source": "{source}""#),
            None => String::new(),
        };
        format!(
            r#"{{
                "version": 1,
                "task": "fixture",
                "max_depth": 2,
                "max_child_assignments": 1,
                "assignments": [{{
                    "id": "child-a",
                    "phase": "execution",
                    "role": "child_orchestrator",
                    "role_category": "{role_category}"{selection},
                    "assigned_paths": ["README.md"],
                    "worker_assignments": [{{
                        "id": "child-a-worker",
                        "role": "worker",
                        "assigned_paths": ["README.md"]
                    }}]
                }}],
                "assignment_schedule": [{{
                    "assignment_id": "child-a",
                    "depth": 2,
                    "flattened_index": 0
                }}]
            }}"#
        )
    }

    #[test]
    fn plan_api_records_operator_category_override_and_keeps_automatic_default() {
        let automatic = parse_supervisor_plan_with_consultant(&fixture_plan_json(
            "delegating_coordinator",
            None,
        ))
        .expect("automatic plan");
        let assignment = &automatic.plan.assignments[0];
        assert_eq!(
            assignment.effective_role_category(),
            RoleCategory::DelegatingCoordinator
        );
        assert_ne!(
            assignment.selection_source,
            Some(AssignmentSelectionSource::OperatorOverride)
        );
        assert!(!assignment.category_is_operator_override());
        assert_eq!(
            assignment.worker_assignments[0].effective_role_category(),
            RoleCategory::NonDelegatingTerminalWorker
        );

        let overridden = parse_supervisor_plan_with_consultant(&fixture_plan_json(
            "read_only_researcher",
            Some("operator_override"),
        ))
        .expect("override plan");
        let assignment = &overridden.plan.assignments[0];
        assert_eq!(
            assignment.effective_role_category(),
            RoleCategory::ReadOnlyResearcher
        );
        assert_eq!(
            assignment.selection_source,
            Some(AssignmentSelectionSource::OperatorOverride)
        );
        assert!(assignment.category_is_operator_override());

        let implied = parse_supervisor_plan_with_consultant(&fixture_plan_json(
            "non_delegating_terminal_worker",
            None,
        ))
        .expect("implied override");
        let assignment = &implied.plan.assignments[0];
        assert_eq!(
            assignment.effective_role_category(),
            RoleCategory::NonDelegatingTerminalWorker
        );
        assert_eq!(
            assignment.selection_source,
            Some(AssignmentSelectionSource::OperatorOverride)
        );
    }

    #[test]
    fn plan_api_emits_non_default_coordination_depth_as_planner_output() {
        let document = r#"{
            "version": 1,
            "task": "three-layer topology",
            "max_depth": 4,
            "max_child_assignments": 3,
            "assignments": [{
                "id": "layer-0",
                "phase": "planning",
                "role": "child_orchestrator",
                "assigned_paths": ["README.md"],
                "worker_assignments": [],
                "child_assignments": [{
                    "id": "layer-1",
                    "phase": "execution",
                    "role": "child_orchestrator",
                    "assigned_paths": ["README.md"],
                    "worker_assignments": [],
                    "child_assignments": [{
                        "id": "layer-2",
                        "phase": "execution",
                        "role": "child_orchestrator",
                        "assigned_paths": ["src/lib.rs"],
                        "worker_assignments": []
                    }]
                }]
            }]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("three-layer plan");
        let topology = coordination_topology_from_plan(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
        );
        assert_eq!(topology.derived_coordination_depth, 3);
        assert_eq!(topology.planned_max_depth, 4);
        assert!(
            topology.derived_coordination_depth > 2,
            "fixture must be a non-default coordination depth, got {topology:?}"
        );

        let emitted = supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )
        .expect("emit topology");
        assert_eq!(
            emitted["coordination_topology"]["derived_coordination_depth"],
            3
        );
        assert_eq!(
            emitted["coordination_topology"]["caller_selected_coordination_depth"],
            topology.caller_selected_coordination_depth
        );
        assert_ne!(
            emitted["coordination_topology"]["derived_coordination_depth"], emitted["max_depth"],
            "derived depth is planner output, not a copy of operator max_depth"
        );
    }
}
