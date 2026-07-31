use super::*;

pub(super) fn fresh_field_guide_frame_nonce(
    entries: &[DecodedFieldGuidePromptEntry],
    nonce_source: &mut dyn FnMut() -> Result<String>,
) -> Result<String> {
    loop {
        let nonce = nonce_source().context("failed to generate field-guide frame nonce")?;
        let (opening_token, closing_token) = field_guide_frame_tokens(&nonce);
        if entries.iter().all(|entry| {
            entry.decoded_payloads().iter().all(|payload| {
                !payload.contains(&opening_token) && !payload.contains(&closing_token)
            })
        }) {
            return Ok(nonce);
        }
    }
}

pub(super) fn field_guide_frame_tokens(nonce: &str) -> (String, String) {
    (
        format!("{FIELD_GUIDE_FRAME_BEGIN_PREFIX}{nonce}"),
        format!("{FIELD_GUIDE_FRAME_END_PREFIX}{nonce}"),
    )
}

pub(super) fn field_guide_prompt_section(
    entries_newest_first: &[DecodedFieldGuidePromptEntry],
    nonce: &str,
) -> Result<String> {
    let (opening_token, closing_token) = field_guide_frame_tokens(nonce);
    let mut section = String::from(FIELD_GUIDE_SECTION_NOTICE);
    section.push('\n');
    section.push_str(&opening_token);
    for entry in entries_newest_first.iter().rev() {
        section.push('\n');
        section.push_str(FIELD_GUIDE_READABLE_ENTRY_PREFIX);
        section.push_str("finding=");
        section.push_str(
            &serde_json::to_string(entry.finding())
                .context("failed to render readable field-guide finding")?,
        );
        section.push_str("|context=");
        section.push_str(
            &serde_json::to_string(entry.context())
                .context("failed to render readable field-guide context")?,
        );
        section.push_str("|date=");
        section.push_str(entry.date());
        section.push_str("|source_run=");
        section.push_str(entry.source_run());
    }
    section.push('\n');
    section.push_str(&closing_token);
    Ok(section)
}

pub fn supervise_role_prefix(
    role: SupervisePromptRole,
    label: &str,
    parent_thread_id: Option<&str>,
) -> String {
    format!(
        "ROLE: {}\nAGENT_KIND: {}\nAGENT_LABEL: {}\nPARENT_THREAD_ID: {}\nTHREAD_DEPTH: {}\nNO_FURTHER_DELEGATION: {}\n",
        role.canonical_role(),
        role.agent_kind(),
        label,
        parent_thread_id.unwrap_or("none"),
        role.thread_depth(),
        role.no_further_delegation()
    )
}

pub fn child_orchestrator_prompt(context: ChildOrchestratorPromptContext<'_>) -> Result<String> {
    let incoming_root = context.run_dir.join("incoming");
    child_orchestrator_prompt_with_incoming_root(
        context,
        &incoming_root,
        &AssignmentMetadata::new(),
    )
}

fn child_orchestrator_prompt_with_incoming_root(
    context: ChildOrchestratorPromptContext<'_>,
    incoming_root: &Path,
    assignment_metadata: &AssignmentMetadata,
) -> Result<String> {
    let field_guide = SupervisorFieldGuidePrompt::empty()?;
    child_orchestrator_prompt_with_incoming_root_and_field_guide(
        context,
        incoming_root,
        assignment_metadata,
        &field_guide,
    )
}

pub(super) fn child_orchestrator_prompt_with_incoming_root_and_field_guide(
    context: ChildOrchestratorPromptContext<'_>,
    incoming_root: &Path,
    assignment_metadata: &AssignmentMetadata,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<String> {
    let ChildOrchestratorPromptContext {
        plan,
        assignment,
        run_dir,
        worktree,
        report_path,
        schema_path,
        worker_schema_path,
        auditor_schema_path,
        consultant,
        claim_context,
    } = context;
    let assignment_json = serde_json::to_string_pretty(&orchestrator_assignment_value(
        assignment,
        assignment_metadata,
    )?)
    .context("failed to serialize orchestrator assignment")?;
    let worker_prompts = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            worker_prompt_with_field_guide(
                WorkerPromptRenderContext {
                    plan,
                    orchestrator: assignment,
                    worker,
                    metadata: &metadata,
                    run_dir,
                    incoming_root,
                    schema_path: worker_schema_path,
                },
                field_guide,
            )
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n\n--- worker prompt contract ---\n\n");
    let auditor_prompt = review_auditor_prompt_with_metadata_and_field_guide(
        plan,
        assignment,
        assignment_metadata,
        run_dir,
        auditor_schema_path,
        field_guide,
    )?;
    let task = assignment_task(plan, assignment);
    let role_prefix = supervise_role_prefix(
        SupervisePromptRole::O1ChildOrchestrator,
        &assignment.id,
        None,
    );
    let (child_model, child_reasoning_effort) =
        role_model_selection(plan, AgentRole::ChildOrchestrator);
    let (worker_model, worker_reasoning_effort) = role_model_selection(plan, AgentRole::Worker);
    let consultation_section = consultation_prompt_section(consultant);
    Ok(format!(
        r#"{role_prefix}{field_guide_section}
You are a child orchestrator in an opt-in local Codex CLI supervisor run.
You are not the top supervisor. You are not alone in the repository.
Primary worktree mutation is forbidden. Work only in this assigned child worktree:
{worktree_path}

Ownership:
- Child orchestrator id: {child_id}
- Megafile decomposition worker targets: {decomposition_targets}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Path claim token: {claim_token}
- Semantic intent token: {semantic_intent_token}

Declared role selections:
- Child orchestrator model: {child_model}
- Child orchestrator reasoning effort: {child_reasoning_effort}
- Nested worker model: {worker_model}
- Nested worker reasoning effort: {worker_reasoning_effort}
- Worker values are declarative context for the generated worker prompts. MACO does not launch a separate worker process, so worker usage remains unavailable until runtime-side role-tagged usage reporting exists.

Runtime hierarchy:
- Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
- You are the O1 child orchestrator for this assignment.
- Workers, researchers, and review auditors are terminal: they must not launch further workers, delegate to another worker, or take over peer coordination.
- You must not use native SubAgent/delegated-worker mechanisms to bind, spawn, impersonate, or take over O1 or O2 roles.
- Durable role names are canonical. Runtime labels belong in runtime bridge metadata such as AGENT_LABEL, never in ROLE.
- You must not spawn, impersonate, or take over a peer O2 supervisor.
- O1 reports peer-O2 escalation candidates upward in findings and remaining_risk instead of taking them over.
- The user-root O2 or an autonomous O2 durable queue may launch bounded peer O2 supervisors through MACO/Codex CLI subprocess orchestration. Autonomous O2-to-O2 follow-up must go through durable queue state such as NEXT_O2_TASKS.tsv, not native SubAgent.

Runtime boundary:
- MACO launched this Codex CLI with strict/ephemeral configuration, approval policy never, goals and multi-agent enabled, and the named maco_external_codex permission profile.
- The inner permission profile grants only minimal reads plus writes in this assigned workspace root; model-generated network access, user config/rules, web search, plugins, apps, hooks, browser/computer use, and inherited shell environment are disabled.
- An outer MACO systemd boundary separately verifies the exact workspace/artifact mounts, blocked host IPC sockets, resource limits, and empty owned cgroup before the result can be published.
- Never launch a raw Codex subprocess or request danger-full-access. Any nested role must go through a MACO-approved runner and a least-privilege profile whose process-tree and side-effect evidence is verified.
- If an approved nested runner/profile is unavailable, stop and report the blocked delegation instead of weakening this boundary.

Required behavior:
- First, read and follow AGENTS.md and project-local .agents instructions in this worktree. When present, specifically read .agents/skills/agent-orchestration/SKILL.md and .agents/docs/AGENT_ORCHESTRATION.md before worker delegation or mutation.
- Use Codex native SubAgent/delegated-worker mechanisms only for lightweight terminal worker or researcher assignments when available, following AGENTS.md and .agents instructions.
- When launching a worker, use the generated worker prompt template verbatim and preserve its six-line TERMINAL_WORKER role-prefix block with no preamble.
- You may collect advisory child-side review-auditor evidence with the generated REVIEW_AUDITOR prompt template, but it is not an acceptance gate unless MACO/O2 collects it through the parent-enforced gate.
- When collecting advisory child-side review-auditor evidence, preserve its six-line REVIEW_AUDITOR role-prefix block with no preamble.
- Do not force raw Codex CLI subprocess workers as the primary worker path.
- If no delegated-worker mechanism is available, stop before mutation and report the exact blocked worker task in your OrchestratorReviewReport findings and remaining_risk.
- Workers must return WorkerReport JSON matching the worker report contract and include "no_further_delegation": true.
- WorkerReport, AuditorReport, and OrchestratorReviewReport must include environment_failures. Use [] when no typed failure occurred. A nonempty environment_failures list requires accepted=false, rejected=true, and status=failed; never include credential or secret values.
- Workers may propose bounded field_guide_entries containing finding and context only. They must never add date, source_run, or other provenance; the trusted parent stamps provenance only after acceptance and audit.
- Each worker must also write its structured execution journal to the exact path in its worker prompt; that path is the only allowed non-source artifact write for a terminal worker. The journal is JSONL with one object per command containing command, cwd, start_timestamp, end_timestamp, and changed_paths. The parent acceptance gate imports these journals from incoming/worker-journals/ and rejects worker evidence that the journal or Git diff does not support.
- Review auditors must return AuditorReport JSON matching the auditor report contract and include "no_further_delegation": true.
- Review auditors must include "read_only": true in AuditorReport JSON to attest they did not mutate files or repository state.
- Acceptance-gate review auditors are parent-launched MACO/Codex CLI subprocess roles; a child-launched review auditor is advisory child-side evidence unless MACO/O2 collects it through the parent-enforced acceptance gate.
- Review every WorkerReport before writing your own OrchestratorReviewReport.
- OrchestratorReviewReport may also propose bounded field_guide_entries containing finding and context only. Do not copy unreviewed or rejected worker suggestions into this field.
- Preserve each worker assignment_kind and target_path in WorkerReport. A successful megafile_decomposition worker must report the exact canonical target_path in files_changed and include decomposition_completion with that target plus at least one concrete canonical replacement_path also present in files_changed. OrchestratorReviewReport must aggregate the exact accepted worker evidence in decomposition_completions; this evidence does not bypass claims, journals, validation, audit, or later merge gates.
- Include at least one accepted review-auditor report in audit_reports that covers all assigned worker ids; MACO rejects child reports with worker assignments that omit terminal audit evidence.
{consultation_section}

Safety requirements:
- Do not edit outside the assigned paths, symbols, or modules.
- Do not mutate the primary worktree.
- Run validation commands when feasible. If validation cannot run, explain why in validation_results and remaining_risk.
- Return your OrchestratorReviewReport JSON as your final response.
- Do not write the orchestrator report file yourself with tools; Codex CLI --output-last-message records your final response at this MACO collection target:
{report_path}
- The orchestrator review report schema path is:
{schema_path}
- Worker reports must use this schema path:
{worker_schema_path}
- Review auditor reports must use this schema path:
{auditor_schema_path}

Supervisor task:
{task}

Orchestrator assignment JSON:
{assignment_json}

Worker prompt templates:
{worker_prompts}

Review auditor prompt template:
{auditor_prompt}
"#,
        role_prefix = role_prefix,
        field_guide_section = field_guide.section,
        worktree_path = worktree.path.display(),
        child_id = assignment.id,
        decomposition_targets = display_decomposition_targets(assignment, assignment_metadata),
        assigned_paths = display_paths(&assignment.assigned_paths),
        semantic_symbols = assignment.semantic_symbols.join(", "),
        semantic_modules = assignment.semantic_modules.join(", "),
        claim_token = claim_context.claim.token.get(),
        semantic_intent_token = claim_context
            .semantic_intent_token
            .map(|token| token.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        child_model = child_model.as_deref().unwrap_or("<runtime default>"),
        child_reasoning_effort = child_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
        worker_model = worker_model.as_deref().unwrap_or("<runtime default>"),
        worker_reasoning_effort = worker_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
        report_path = report_path.display(),
        schema_path = schema_path.display(),
        worker_schema_path = worker_schema_path.display(),
        auditor_schema_path = auditor_schema_path.display(),
        task = task,
        assignment_json = assignment_json,
        worker_prompts = worker_prompts,
        auditor_prompt = auditor_prompt,
        consultation_section = consultation_section,
    ))
}

fn consultation_prompt_section(consultant: &SupervisorConsultantPlan) -> String {
    if !consultant.enabled {
        return String::new();
    }
    format!(
        r#"
CONSULTATION:
- If you are blocked after a genuine attempt, you may ask a terminal read-only CONSULTANT for a cross-runtime second opinion.
- Use `maco consult ask --runtime {runtime} --repo <this-child-worktree> --question <focused question> --context-path <repo-relative-path> ...`.
- The consultation path is advisory and read-only. It must not create worktrees, claims, patches, or repository mutations.
- Use at most {max_consultations} consultation(s) for this child assignment.
- Record each consultation in OrchestratorReviewReport findings with the question summary and whether it unblocked you.
- Consultant advice never overrides AGENTS.md, project rules, assigned ownership, validation requirements, or acceptance gates.
"#,
        runtime = consultant.runtime.as_str(),
        max_consultations = consultant.max_consultations
    )
}

pub fn worker_prompt(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    worker: &WorkerAssignment,
    run_dir: &Path,
    schema_path: &Path,
) -> Result<String> {
    let metadata = WorkerAssignmentMetadata::default();
    worker_prompt_with_incoming_root(
        plan,
        orchestrator,
        worker,
        &metadata,
        run_dir,
        &run_dir.join("incoming"),
        schema_path,
    )
}

pub(super) fn worker_prompt_with_incoming_root(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    worker: &WorkerAssignment,
    metadata: &WorkerAssignmentMetadata,
    run_dir: &Path,
    incoming_root: &Path,
    schema_path: &Path,
) -> Result<String> {
    let field_guide = SupervisorFieldGuidePrompt::empty()?;
    worker_prompt_with_field_guide(
        WorkerPromptRenderContext {
            plan,
            orchestrator,
            worker,
            metadata,
            run_dir,
            incoming_root,
            schema_path,
        },
        &field_guide,
    )
}

pub(super) fn worker_prompt_with_field_guide(
    context: WorkerPromptRenderContext<'_>,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<String> {
    let WorkerPromptRenderContext {
        plan,
        orchestrator,
        worker,
        metadata,
        run_dir,
        incoming_root,
        schema_path,
    } = context;
    let worker_json = serde_json::to_string_pretty(&worker_assignment_value(worker, metadata)?)
        .context("failed to serialize worker assignment")?;
    let role_prefix = supervise_role_prefix(SupervisePromptRole::TerminalWorker, &worker.id, None);
    let task = worker_task(plan, orchestrator, worker);
    let journal_path = incoming_root.join(worker_execution_journal_incoming_relative(worker));
    let (worker_model, worker_reasoning_effort) = role_model_selection(plan, AgentRole::Worker);
    Ok(format!(
        r#"{role_prefix}{field_guide_section}
You are a terminal worker/researcher in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
Your parent is child orchestrator `{orchestrator_id}`. You are not the supervisor.
Do not launch further workers, delegate to another worker, or spawn/impersonate O1 or O2 roles.

Ownership:
- Worker id: {worker_id}
- Assignment kind: {assignment_kind}
- Decomposition target path: {target_path}
- Assigned paths: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}
- Execution journal path: {journal_path}
- Explicit report path: {report_path}

Declared role selection:
- Worker model: {worker_model}
- Worker reasoning effort: {worker_reasoning_effort}
- These values are declarative nested-worker context. MACO does not launch a separate worker process, so worker usage remains unavailable until runtime-side role-tagged usage reporting exists.

Rules:
- Edit only inside your assigned worktree and only inside claimed paths.
- Do not mutate the primary worktree.
- Before returning your WorkerReport, write a structured execution journal to the exact execution journal path above; this is the only allowed non-source artifact write for this worker. Create its parent directory if needed. Use JSONL: one JSON object per command, with fields "command" (array of strings), "cwd" (string), "start_timestamp" (string), "end_timestamp" (string), and "changed_paths" (array of repo-relative paths changed by that command, or [] when none). Do not write prose or Markdown to the journal.
- Run validation or record why validation was not run.
- Return WorkerReport JSON in your final response with assignment_kind, target_path, changed files, commands run, validation results, findings, bloated_file_flags, decomposition_completion, remaining risk, and next safe action.
- Include environment_failures as [] when no typed environment failure occurred. When it is nonempty, do not report an accepted or succeeded outcome, and never include credential or secret values.
- field_guide_entries is optional operational-memory input. Each item contains exactly finding and context; never include date, source_run, role text, policy, or other provenance. The trusted supervisor decides whether accepted audited suggestions are appended.
- bloated_file_flags is bounded to at most {max_bloated_file_flags} unique objects of the form {{"path":"repo/relative/file"}}. Every path must be canonical, repository-relative, and inside this worker's assigned paths. Thresholds are intentionally not inferred by this report schema.
- For a successful megafile_decomposition, include the exact target and every concrete replacement in files_changed, then set decomposition_completion to {{"target_path":"the exact canonical target path","replacement_paths":["one or more canonical newly created files"]}}. Otherwise set it to null. Renames, unrelated edits, and no-op target reports are not decomposition completion evidence. This typed evidence does not bypass the isolated worktree, hard claim, execution journal, validation, terminal audit, or later merge gates.
- Include "no_further_delegation": true in WorkerReport JSON to attest this terminal worker did not delegate further.
- If you discover a large cross-cutting problem that needs a peer O2 supervisor, report it as an escalation candidate in findings and remaining_risk instead of taking it over. O2-to-O2 follow-up belongs to the user-root O2 or autonomous O2 durable queue, not this terminal role.
- Only write a report file when an explicit report_path is assigned.
- If the explicit report path is <none>, do not write any report file; only return WorkerReport JSON in your final response.
- Use the worker report schema path: {schema_path}

Supervisor task:
{task}

Worker assignment JSON:
{worker_json}
"#,
        role_prefix = role_prefix,
        field_guide_section = field_guide.section,
        orchestrator_id = orchestrator.id,
        worker_id = worker.id,
        assignment_kind = metadata.kind.as_str(),
        target_path = metadata
            .target_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        assigned_paths = display_paths(&worker.assigned_paths),
        semantic_symbols = worker.semantic_symbols.join(", "),
        semantic_modules = worker.semantic_modules.join(", "),
        run_dir = run_dir.display(),
        journal_path = journal_path.display(),
        report_path = worker
            .report_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        worker_model = worker_model.as_deref().unwrap_or("<runtime default>"),
        worker_reasoning_effort = worker_reasoning_effort
            .as_deref()
            .unwrap_or("<runtime default>"),
        schema_path = schema_path.display(),
        max_bloated_file_flags = MAX_BLOATED_FILE_FLAGS_PER_WORKER,
        task = task,
        worker_json = worker_json,
    ))
}

pub fn review_auditor_prompt(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    run_dir: &Path,
    schema_path: &Path,
) -> Result<String> {
    review_auditor_prompt_with_metadata(
        plan,
        orchestrator,
        &AssignmentMetadata::new(),
        run_dir,
        schema_path,
    )
}

fn review_auditor_prompt_with_metadata(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    run_dir: &Path,
    schema_path: &Path,
) -> Result<String> {
    let field_guide = SupervisorFieldGuidePrompt::empty()?;
    review_auditor_prompt_with_metadata_and_field_guide(
        plan,
        orchestrator,
        assignment_metadata,
        run_dir,
        schema_path,
        &field_guide,
    )
}

pub(super) fn review_auditor_prompt_with_metadata_and_field_guide(
    plan: &SupervisorPlan,
    orchestrator: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    run_dir: &Path,
    schema_path: &Path,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<String> {
    let worker_ids = orchestrator
        .worker_assignments
        .iter()
        .map(|worker| worker.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let auditor_id = format!("{}-review-auditor", orchestrator.id);
    let role_prefix = supervise_role_prefix(SupervisePromptRole::ReviewAuditor, &auditor_id, None);
    let task = assignment_task(plan, orchestrator);
    Ok(format!(
        r#"{role_prefix}{field_guide_section}
You are a terminal read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
Your parent is child orchestrator `{orchestrator_id}`. You are not an O1 child orchestrator, O2 supervisor, worker, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, or spawn/impersonate O1 or O2 roles.

Ownership:
- Review auditor id: {auditor_id}
- Assigned worker ids to audit: {worker_ids}
- Megafile decomposition worker targets: {decomposition_targets}
- Assigned paths to review: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}

Rules:
- Stay read-only. Inspect worker reports, child diffs, validation evidence, findings, remaining risk, and claimed path boundaries.
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- Do not edit files, create durable artifacts, apply patches, claim paths, or change Git state.
- Produce structured AuditorReport JSON in your final response with reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining risk, and next safe action.
- Include environment_failures as [] when no typed environment failure occurred. When it is nonempty, do not report an accepted or succeeded outcome, and never include credential or secret values.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
- Include "no_further_delegation": true in AuditorReport JSON to attest this terminal auditor did not delegate further.
- Include "read_only": true in AuditorReport JSON to attest this audit stayed read-only.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Use the auditor report schema path: {schema_path}

Supervisor task:
{task}
"#,
        role_prefix = role_prefix,
        field_guide_section = field_guide.section,
        orchestrator_id = orchestrator.id,
        auditor_id = auditor_id,
        worker_ids = if worker_ids.is_empty() {
            "<none>".to_string()
        } else {
            worker_ids
        },
        decomposition_targets = display_decomposition_targets(orchestrator, assignment_metadata),
        assigned_paths = display_paths(&orchestrator.assigned_paths),
        semantic_symbols = orchestrator.semantic_symbols.join(", "),
        semantic_modules = orchestrator.semantic_modules.join(", "),
        run_dir = run_dir.display(),
        schema_path = schema_path.display(),
        task = task,
    ))
}

pub(super) fn parent_review_auditor_prompt_with_field_guide(
    context: ParentReviewAuditorPromptContext<'_>,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<String> {
    let ParentReviewAuditorPromptContext {
        plan,
        assignment,
        assignment_metadata,
        run_dir,
        worktree_path,
        child_report_path,
        auditor_report_path,
        schema_path,
        child_report,
    } = context;
    let auditor_id = parent_auditor_id(assignment);
    let role_prefix = supervise_role_prefix(SupervisePromptRole::ReviewAuditor, &auditor_id, None);
    let child_field_guide_entry_count = child_report.field_guide_entries.len();
    let worker_field_guide_entry_counts = child_report
        .worker_reports
        .iter()
        .map(|worker| (worker.id.clone(), worker.field_guide_entries.len()))
        .collect::<BTreeMap<_, _>>();
    let mut redacted_child_report = child_report.clone();
    enforce_orchestrator_environment_failure_outcome(&mut redacted_child_report);
    redacted_child_report.field_guide_entries.clear();
    for worker in &mut redacted_child_report.worker_reports {
        worker.field_guide_entries.clear();
    }
    let child_report_json = serde_json::to_string_pretty(&redacted_child_report)
        .context("failed to serialize child report for auditor prompt")?;
    let field_guide_suggestion_metadata = serde_json::to_string_pretty(&json!({
        "child_entry_count": child_field_guide_entry_count,
        "worker_entry_counts": worker_field_guide_entry_counts,
        "raw_text_omitted": true,
    }))
    .context("failed to serialize redacted field-guide suggestion metadata")?;
    let task = assignment_task(plan, assignment);
    Ok(format!(
        r#"{role_prefix}{field_guide_section}
You are the parent-launched read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher, plus this parent-enforced terminal REVIEW_AUDITOR gate.
Your parent is MACO/O2. You are not an O1 child orchestrator, worker, researcher, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, claim paths, apply patches, or change Git state.

Runtime boundary:
- MACO launched this Codex CLI with the read-only maco_external_codex permission profile, model-generated network disabled, and strict/ephemeral configuration.
- An outer MACO systemd boundary independently verifies the exact read-only workspace mount, writable report/log destinations, blocked host IPC sockets, resource limits, and empty owned cgroup.
- Never request danger-full-access or launch a raw nested Codex subprocess. Stay read-only and fail closed if either verified boundary is unavailable.
- Return AuditorReport JSON as your final response. Codex CLI --output-last-message records that final response at the auditor report path.

Evidence to review:
- Supervisor task: {task}
- Child assignment id: {assignment_id}
- Megafile decomposition worker targets: {decomposition_targets}
- Child worktree path: {worktree_path}
- Run artifact root: {run_dir}
- Child report path: {child_report_path}
- Parent auditor report path: {auditor_report_path}
- Auditor report schema path: {schema_path}
- Assigned worker/review subject ids: {worker_ids}
- Assigned paths: {assigned_paths}
- Child-reported and supervisor-inspected changed paths: {changed_paths}
- Field-guide suggestion metadata (raw agent-authored text deliberately omitted): {field_guide_suggestion_metadata}

Review requirements:
- Review the child report, worker_reports, child worktree diff/changed paths, validation_results, findings, remaining_risk, assigned worker IDs, and assigned paths.
- Verify every assigned worker id has adequate WorkerReport coverage and terminal no-delegation evidence. When there are no assigned workers, verify reviewed_worker_ids covers the child orchestrator id for the changed child diff.
- Verify reviewed_paths covers the assigned paths and any changed paths relevant to this child scope.
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
- Set role="auditor", no_further_delegation=true, read_only=true.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Include reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining_risk, and next_safe_action.
- Include environment_failures as [] when no typed environment failure occurred. When it is nonempty, do not report an accepted or succeeded outcome, and never include credential or secret values.

Child report JSON:
{child_report_json}
"#,
        role_prefix = role_prefix,
        field_guide_section = field_guide.section,
        task = task,
        assignment_id = assignment.id,
        decomposition_targets = display_decomposition_targets(assignment, assignment_metadata),
        worktree_path = worktree_path.display(),
        run_dir = run_dir.display(),
        child_report_path = child_report_path.display(),
        auditor_report_path = auditor_report_path.display(),
        schema_path = schema_path.display(),
        worker_ids = display_strings(&required_auditor_prompt_subject_ids(
            assignment,
            child_report,
        )),
        assigned_paths = display_paths(&assignment.assigned_paths),
        changed_paths = display_paths(&child_report.files_changed),
        field_guide_suggestion_metadata = field_guide_suggestion_metadata,
        child_report_json = child_report_json,
    ))
}

fn assignment_task<'a>(
    plan: &'a SupervisorPlan,
    assignment: &'a OrchestratorAssignment,
) -> &'a str {
    assignment.task.as_deref().unwrap_or(&plan.task)
}

fn worker_task<'a>(
    plan: &'a SupervisorPlan,
    assignment: &'a OrchestratorAssignment,
    worker: &'a WorkerAssignment,
) -> &'a str {
    worker
        .task
        .as_deref()
        .or(assignment.task.as_deref())
        .unwrap_or(&plan.task)
}

fn role_model_selection(
    plan: &SupervisorPlan,
    role: AgentRole,
) -> (Option<String>, Option<String>) {
    let selection = effective_role_model_selection(plan, role);
    (selection.model, selection.reasoning_effort)
}

pub(super) fn provisional_default_role_model_selection(role: AgentRole) -> RoleModelSelection {
    let reasoning_effort = match role {
        AgentRole::Worker => "medium",
        AgentRole::GateClassifier => "high",
        AgentRole::Supervisor | AgentRole::ChildOrchestrator | AgentRole::Auditor => "xhigh",
    };
    RoleModelSelection {
        model: Some(DEFAULT_PROFILE_MODEL.to_string()),
        reasoning_effort: Some(reasoning_effort.to_string()),
        unavailable_model_fallback: match role {
            AgentRole::GateClassifier => UnavailableModelFallback::LocalDeterministicFake,
            AgentRole::Supervisor
            | AgentRole::ChildOrchestrator
            | AgentRole::Worker
            | AgentRole::Auditor => UnavailableModelFallback::RuntimeDefault,
        },
    }
}

pub(super) fn provisional_default_role_models() -> BTreeMap<AgentRole, RoleModelSelection> {
    [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]
    .into_iter()
    .map(|role| (role, provisional_default_role_model_selection(role)))
    .collect()
}

pub(super) fn effective_role_model_selection(
    plan: &SupervisorPlan,
    role: AgentRole,
) -> RoleModelSelection {
    plan.role_models
        .get(&role)
        .cloned()
        .unwrap_or_else(|| provisional_default_role_model_selection(role))
}

pub(super) fn apply_role_model_selection(
    command: ExternalAgentCommand,
    plan: &SupervisorPlan,
    role: AgentRole,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
) -> Result<ExternalAgentCommand> {
    let configured = effective_role_model_selection(plan, role);
    let availability = catalog.availability(configured.model.as_deref(), runtime)?;
    let selection = configured.resolve_for_availability(availability, runtime)?;
    Ok(command.with_model_selection(selection.model, selection.reasoning_effort))
}

pub(super) fn apply_canonical_environment_requirements(
    command: ExternalAgentCommand,
    requirements: &[EnvironmentRequirement],
) -> ExternalAgentCommand {
    command.with_environment_requirements(requirements.iter().cloned())
}
