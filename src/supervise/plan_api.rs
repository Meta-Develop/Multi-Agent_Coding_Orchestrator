use super::*;

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
    let repo = discover_repo_root(repo.as_ref())?;
    let loaded = supervisor_plan_and_consultant_from_goal_spec(&repo, goal, spec, None)?;
    supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
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
        anyhow!(
            "failed to plan plain-text task specification {}: {error}",
            task_file.display()
        )
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
    if proposal.assignments.is_empty() {
        bail!(
            "goal/spec produced no actionable workstreams; name at least one repository path, Rust module, or Rust symbol to change"
        );
    }
    planning::validate_task_assignment_disjointness(&proposal.assignments)
        .context("goal/spec workstreams are not independently assignable")?;

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
        let planning_index = assignments.len();
        assignments.push(OrchestratorAssignment {
            id: planning_id.clone(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: assignment.assigned_paths.clone(),
            semantic_symbols: assignment.semantic_symbols.clone(),
            semantic_modules: assignment.semantic_modules.clone(),
            task: Some(format!(
                "Read-only planning gate for workstream '{}'. Review the proposed scope and implementation task without editing files or delegating implementation. Confirm whether the execution child can proceed safely.\n\nExecution task:\n{}",
                assignment.id, assignment.task
            )),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            notes: Some(
                "MACO-visible read-only planning root; its execution child is parent-gated"
                    .to_string(),
            ),
        });
        assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: planning_id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: planning_index,
        });

        spec_fragment_ids_by_assignment
            .insert(assignment.id.clone(), assignment.fragment_ids.clone());
        let worker = WorkerAssignment {
            id: format!("{}-worker", assignment.id),
            role: AgentRole::Worker,
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
        let execution_index = assignments.len();
        assignments.push(OrchestratorAssignment {
            id: assignment.id.clone(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: assignment.assigned_paths,
            semantic_symbols: assignment.semantic_symbols,
            semantic_modules: assignment.semantic_modules,
            task: Some(assignment.task),
            worker_assignments: vec![worker],
            environment_requirements: Vec::new(),
            notes: Some(format!(
                "Execution child admitted only after read-only planning root '{planning_id}' succeeds"
            )),
        });
        assignment_schedule.push(AssignmentScheduleEntry {
            assignment_id: assignment.id,
            parent_assignment_id: Some(planning_id),
            depth: MIN_SUPERVISOR_DEPTH.saturating_add(1),
            flattened_index: execution_index,
        });
    }
    let task = match (goal.is_empty(), spec.is_empty()) {
        (false, false) => format!("{goal}\n\n{spec}"),
        (false, true) => goal.to_string(),
        (true, _) => spec.to_string(),
    };
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
        spec_fragment_ids,
        spec_fragment_ids_by_assignment,
        assignment_schedule,
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
    };
    let (plan, plan_metadata) = validate_supervisor_plan(plan, metadata)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata,
        plan_metadata,
    })
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
    let plan_metadata = supervisor_plan_metadata_from_value(&value, plan.max_depth)?;
    plan.assignments = assignments_from_plan_value(&value)?;
    let (plan, plan_metadata) = validate_supervisor_plan(plan, plan_metadata)?;
    let assignment_metadata = assignment_metadata_from_plan_value(&value, &plan)?;
    validate_consultant_plan(&consultant)?;
    Ok(LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
    })
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
    let spec_fragment_ids = optional_string_array(value, "spec_fragment_ids")?;
    let run_budget = value
        .get("run_budget")
        .map(|budget| {
            serde_json::from_value::<SupervisorBudgetConfig>(budget.clone())
                .context("run_budget is invalid")
        })
        .transpose()?
        .unwrap_or_default();
    let raw_assignments = value
        .get("assignments")
        .and_then(Value::as_array)
        .context("supervisor plan assignments must be an array")?;
    let mut metadata = SupervisorPlanMetadata {
        spec_fragment_ids,
        run_budget,
        ..SupervisorPlanMetadata::default()
    };
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
    if !plan_metadata.spec_fragment_ids.is_empty() {
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
    if !plan_metadata.coverage_gaps.is_empty() {
        object.insert(
            "coverage_gaps".to_string(),
            serde_json::to_value(&plan_metadata.coverage_gaps)
                .context("failed to serialize plan coverage gaps")?,
        );
    }
    if !plan_metadata.run_budget.is_unconfigured() {
        object.insert(
            "run_budget".to_string(),
            serde_json::to_value(&plan_metadata.run_budget)
                .context("failed to serialize run_budget plan field")?,
        );
    }
    if !consultant.is_default() {
        object.insert(
            "consultant".to_string(),
            serde_json::to_value(consultant)
                .context("failed to serialize consultant plan field")?,
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

pub fn run_supervisor_plan_file_with_concurrency_policy(
    options: SupervisorRunOptions,
    concurrency_policy: SupervisorConcurrencyPolicy,
) -> Result<SupervisorFinalReport> {
    let max_concurrent_children = concurrency_policy.resolve(HostProcessCapacity::measured());
    run_supervisor_plan_file_with_max_concurrent_children(options, max_concurrent_children)
}

pub fn run_supervisor_plan_file_with_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
) -> Result<SupervisorFinalReport> {
    let external_runner = run_external_agent_cancellable_reviewed;
    run_supervisor_plan_file_with_runner_and_max_concurrent_children(
        options,
        max_concurrent_children,
        &external_runner,
    )
}

fn run_supervisor_plan_file_with_runner_and_max_concurrent_children(
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    validate_max_concurrent_children(max_concurrent_children)?;
    if options.runtime == SupervisorRuntime::Fake {
        bail!(
            "supervisor assignment creation is temporarily unsupported because managed worktree creation requires a capability-bound repository cleanliness input"
        );
    }
    let repo = discover_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo);
    let cleanliness = manager.acquire_repository_cleanliness()?;
    let loaded = load_supervisor_plan_file_with_consultant(&options.plan_file)?;
    let runtime_model_catalog = RuntimeModelCatalog::for_supervisor(&options, &repo);
    run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::Bound(&cleanliness),
        runtime_model_catalog,
        external_runner,
    )
}

pub fn supervisor_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<SupervisorStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let run_dir = run_dir(&repo, &run_id);
    let final_report_path = supervisor_final_report_path(&run_dir);
    let final_report = read_finalized_supervisor_report(&repo, &run_id, &run_dir)?;
    Ok(SupervisorStatusReport {
        run_id,
        repo: PathBuf::from("."),
        run_dir: run_dir
            .strip_prefix(&repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| RunArtifactFamily::Supervise.run_root()),
        final_report_exists: final_report.is_some(),
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
        gate_denials: Vec::new(),
        pre_action_review_metrics: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: "supervisor final report is missing".to_string(),
            paths: vec![final_report_path],
        }],
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        breaker_trip: None,
        orchestrator_reports: Vec::new(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk: "run artifacts are incomplete".to_string(),
        next_safe_action: "rerun supervise run for this run id".to_string(),
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
