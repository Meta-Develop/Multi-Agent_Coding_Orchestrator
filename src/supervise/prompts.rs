use super::*;

// Cost decision: 6 KiB gives the fixed worker fixture bounded maintenance headroom without
// hiding another large contract paragraph; raising it is a deliberate prompt-cost decision.
const WORKER_PROMPT_FIXTURE_CEILING_BYTES: usize = 6 * 1024;
// Cost decision: 20 KiB covers the fixed child fixture plus its embedded worker/auditor templates;
// raising it is a deliberate prompt-cost decision about the multiplied worker-template cost.
const CHILD_ORCHESTRATOR_PROMPT_FIXTURE_CEILING_BYTES: usize = 20 * 1024;
// Cost decision: 4 KiB permits the advisory child-side audit contract and a small fixed margin;
// raising it is a deliberate prompt-cost decision, never an automatic fixture update.
const REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES: usize = 4 * 1024;
// Cost decision: 8 KiB bounds the distinct parent acceptance-gate contract and its fixed margin;
// raising it is a deliberate prompt-cost decision independent of the child-side auditor ceiling.
const PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES: usize = 8 * 1024;
pub(super) const PROMPT_MEASUREMENTS_SCHEMA_VERSION: u32 = 1;
const WORKER_TEMPLATE_EMBEDDING_LEVELS: usize = 2;
const TOOL_CALL_BATCHING_GUIDANCE: &str = "\
Tool-call batching:
- Batch independent, side-effect-free inspections in one tool call when the runtime supports it.
- Keep dependent steps, approval-sensitive actions, and mutations ordered. Batching never relaxes ownership, journaling, validation, or audit requirements.";

fn enforce_rendered_prompt_ceiling(role: &str, rendered: &str, ceiling: usize) -> Result<()> {
    if rendered.len() > ceiling {
        bail!(
            "rendered {role} prompt grew to {} bytes, above its declared {ceiling}-byte fixture ceiling",
            rendered.len()
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PromptMeasurementRole {
    O1ChildOrchestrator,
    TerminalWorker,
    ChildSideReviewAuditor,
    ParentAcceptanceAuditor,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct PromptByteMeasurement {
    pub role: PromptMeasurementRole,
    pub agent_label: String,
    pub full_bytes: usize,
    pub invariant_bytes: usize,
    pub variable_bytes: usize,
    pub fixture_ceiling_bytes: usize,
}

impl PromptByteMeasurement {
    fn new(
        role: PromptMeasurementRole,
        agent_label: impl Into<String>,
        rendered: &str,
        invariant_prefix: &str,
        fixture_ceiling_bytes: usize,
    ) -> Result<Self> {
        if !rendered.starts_with(invariant_prefix) {
            bail!("rendered prompt does not start with its declared invariant prefix");
        }
        Ok(Self {
            role,
            agent_label: agent_label.into(),
            full_bytes: rendered.len(),
            invariant_bytes: invariant_prefix.len(),
            variable_bytes: rendered.len() - invariant_prefix.len(),
            fixture_ceiling_bytes,
        })
    }

    fn record_final_rendered_bytes(&mut self, rendered: &str) -> Result<()> {
        if rendered.len() < self.invariant_bytes {
            bail!("final rendered prompt is shorter than its measured invariant prefix");
        }
        self.full_bytes = rendered.len();
        self.variable_bytes = rendered.len() - self.invariant_bytes;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct WorkerPromptEmbeddingMultiplier {
    pub worker_roles_per_run: usize,
    pub levels_that_embed_template: usize,
    pub total_worker_template_embeddings: usize,
}

impl WorkerPromptEmbeddingMultiplier {
    fn for_plan(plan: &SupervisorPlan) -> Result<Self> {
        let worker_roles_per_run =
            plan.assignments
                .iter()
                .try_fold(0usize, |total, assignment| {
                    total
                        .checked_add(assignment.worker_assignments.len())
                        .context("run-wide worker role count overflowed")
                })?;
        let total_worker_template_embeddings = worker_roles_per_run
            .checked_mul(WORKER_TEMPLATE_EMBEDDING_LEVELS)
            .context("worker prompt embedding multiplier overflowed")?;
        Ok(Self {
            worker_roles_per_run,
            levels_that_embed_template: WORKER_TEMPLATE_EMBEDDING_LEVELS,
            total_worker_template_embeddings,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct OuterRoundTripMeasurement {
    pub observation: RoleUsageObservation,
    pub unavailable_reason: String,
    pub method: String,
    pub prerequisites: Vec<String>,
}

impl OuterRoundTripMeasurement {
    fn not_process_observable() -> Self {
        Self {
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: "worker execution journals record commands and timestamps but no model-turn or tool-batch identifier; command entries are not model turns".to_string(),
            method: "compare before/after outer model round trips by correlating provider model-turn and tool-batch identifiers with worker execution journal entries".to_string(),
            prerequisites: vec![
                "a fixed comparable read-heavy worker-journal fixture".to_string(),
                "the same model, reasoning effort, and runtime for both conditions".to_string(),
                "durable outer-turn and tool-batch identifiers correlated with worker journal entries"
                    .to_string(),
                "repeated before/after runs of the same fixture".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct PromptMeasurementsArtifact {
    pub schema_version: u32,
    pub prompts: Vec<PromptByteMeasurement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_embedding_multiplier: Option<WorkerPromptEmbeddingMultiplier>,
    pub outer_round_trip_measurement: OuterRoundTripMeasurement,
}

impl PromptMeasurementsArtifact {
    fn new(
        prompts: Vec<PromptByteMeasurement>,
        worker_embedding_multiplier: Option<WorkerPromptEmbeddingMultiplier>,
    ) -> Self {
        Self {
            schema_version: PROMPT_MEASUREMENTS_SCHEMA_VERSION,
            prompts,
            worker_embedding_multiplier,
            outer_round_trip_measurement: OuterRoundTripMeasurement::not_process_observable(),
        }
    }

    pub(super) fn record_final_launch_prompt_bytes(&mut self, rendered: &str) -> Result<()> {
        let launch = self
            .prompts
            .first_mut()
            .context("prompt measurement artifact omitted its launch prompt")?;
        launch.record_final_rendered_bytes(rendered)
    }
}

pub(super) struct RenderedPromptWithMeasurements {
    pub prompt: String,
    pub measurements: PromptMeasurementsArtifact,
}

pub(super) fn prompt_measurements_relative(prompt_relative: &Path) -> PathBuf {
    let mut measurement_path = prompt_relative.as_os_str().to_os_string();
    measurement_path.push(".measurements.json");
    PathBuf::from(measurement_path)
}

pub(super) fn child_orchestrator_cacheable_prefix() -> String {
    format!(
        r#"You are a child orchestrator in an opt-in local Codex CLI supervisor run.
You are not the top supervisor. You are not alone in the repository.
Primary worktree mutation is forbidden. Work only in the assigned child worktree identified in the assignment-specific context below.

{tool_call_batching_guidance}

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
- When launching a worker, use the generated worker prompt template verbatim and preserve its trusted shared prefix followed by its six-line TERMINAL_WORKER role metadata block.
- You may collect advisory child-side review-auditor evidence with the generated REVIEW_AUDITOR prompt template, but it is not an acceptance gate unless MACO/O2 collects it through the parent-enforced gate.
- When collecting advisory child-side review-auditor evidence, preserve its trusted shared prefix followed by its six-line REVIEW_AUDITOR role metadata block.
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

Safety requirements:
- Do not edit outside the assigned paths, symbols, or modules.
- Do not mutate the primary worktree.
- Run validation commands when feasible. If validation cannot run, explain why in validation_results and remaining_risk.
- Return your OrchestratorReviewReport JSON as your final response.
"#,
        tool_call_batching_guidance = TOOL_CALL_BATCHING_GUIDANCE
    )
}

pub(super) fn worker_cacheable_prefix() -> String {
    format!(
        r#"You are a terminal worker/researcher in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
You are not the supervisor. Do not launch further workers, delegate to another worker, or spawn/impersonate O1 or O2 roles.

{tool_call_batching_guidance}

Rules:
- Edit only inside your assigned worktree and only inside claimed paths.
- Do not mutate the primary worktree.
- Before returning your WorkerReport, write a structured execution journal to the exact execution journal path in the assignment-specific context below; this is the only allowed non-source artifact write for this worker. Create its parent directory if needed. Use JSONL: one JSON object per command, with fields "command" (array of strings), "cwd" (string), "start_timestamp" (string), "end_timestamp" (string), and "changed_paths" (array of repo-relative paths changed by that command, or [] when none). Do not write prose or Markdown to the journal.
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
"#,
        tool_call_batching_guidance = TOOL_CALL_BATCHING_GUIDANCE,
        max_bloated_file_flags = MAX_BLOATED_FILE_FLAGS_PER_WORKER,
    )
}

pub(super) fn review_auditor_cacheable_prefix() -> String {
    format!(
        r#"You are a terminal read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor.
You are not an O1 child orchestrator, O2 supervisor, worker, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, or spawn/impersonate O1 or O2 roles.

{tool_call_batching_guidance}

Rules:
- Stay read-only. Inspect worker reports, child diffs, validation evidence, findings, remaining risk, and claimed path boundaries.
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- Do not edit files, create durable artifacts, apply patches, claim paths, or change Git state.
- Produce structured AuditorReport JSON in your final response with reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining risk, and next safe action.
- Include environment_failures as [] when no typed environment failure occurred. When it is nonempty, do not report an accepted or succeeded outcome, and never include credential or secret values.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
- Include "no_further_delegation": true in AuditorReport JSON to attest this terminal auditor did not delegate further.
- Include "read_only": true in AuditorReport JSON to attest this audit stayed read-only.
- Set rejection_kind=null for acceptance. For every rejection, set rejection_kind="implementation_defect" when the implementation must change, or rejection_kind="evidence_quality" only when validation/report evidence alone must be corrected.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
"#,
        tool_call_batching_guidance = TOOL_CALL_BATCHING_GUIDANCE
    )
}

pub(super) fn parent_review_auditor_cacheable_prefix() -> String {
    format!(
        r#"You are the parent-launched read-only review auditor in an opt-in local Codex CLI supervised run.
Current supervise run contract: user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher, plus this parent-enforced terminal REVIEW_AUDITOR gate.
Your parent is MACO/O2. You are not an O1 child orchestrator, worker, researcher, or peer coordinator.
Do not launch further workers, delegate, mutate files, run mutating commands, claim paths, apply patches, or change Git state.

{tool_call_batching_guidance}

Runtime boundary:
- MACO launched this Codex CLI with the read-only maco_external_codex permission profile, model-generated network disabled, and strict/ephemeral configuration.
- An outer MACO systemd boundary independently verifies the exact read-only workspace mount, writable report/log destinations, blocked host IPC sockets, resource limits, and empty owned cgroup.
- Never request danger-full-access or launch a raw nested Codex subprocess. Stay read-only and fail closed if either verified boundary is unavailable.
- Return AuditorReport JSON as your final response. Codex CLI --output-last-message records that final response at the auditor report path.

Review requirements:
- Review the child report, worker_reports, child worktree diff/changed paths, validation_results, findings, remaining_risk, assigned worker IDs, and assigned paths.
- Verify every assigned worker id has adequate WorkerReport coverage and terminal no-delegation evidence. When there are no assigned workers, verify reviewed_worker_ids covers the child orchestrator id for the changed child diff.
- Verify reviewed_paths covers the assigned paths and any changed paths relevant to this child scope.
- For megafile_decomposition, verify the worker and child completion evidence names the exact target_path and is supported by the normal claim, journal, validation, and diff evidence.
- reviewed_paths coverage is computed over repository-relative entries only. Absolute out-of-repo evidence paths are allowed and retained verbatim as evidence, but excluded from coverage computation.
- Set role="auditor", no_further_delegation=true, read_only=true.
- Set rejection_kind=null for acceptance. For every rejection, set rejection_kind="implementation_defect" when the preserved implementation must change, or rejection_kind="evidence_quality" only when the implementation is sound and validation/report evidence alone must be corrected.
- Set accepted=false or status=failed/rejected if worker evidence is missing, validation is insufficient, diffs exceed assigned scope, or remaining risk is underreported.
- Include reviewed_worker_ids, reviewed_paths, commands_run, validation_results, findings, remaining_risk, and next_safe_action.
- Include environment_failures as [] when no typed environment failure occurred. When it is nonempty, do not report an accepted or succeeded outcome, and never include credential or secret values.
"#,
        tool_call_batching_guidance = TOOL_CALL_BATCHING_GUIDANCE
    )
}

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
    Ok(
        render_child_orchestrator_prompt_with_incoming_root_and_field_guide(
            context,
            incoming_root,
            assignment_metadata,
            field_guide,
        )?
        .prompt,
    )
}

pub(super) fn render_evidence_only_reaudit_prompt(
    assignment: &OrchestratorAssignment,
    worktree: &WorktreeRecord,
    report_path: &Path,
    schema_path: &Path,
    source: &EvidenceOnlyReauditSource,
    diff: &str,
) -> Result<RenderedPromptWithMeasurements> {
    let cacheable_prefix = r#"You are the evidence-only report stage for an assignment-scoped MACO re-audit.
The implementation candidate is immutable for this operation. Do not edit repository content, apply patches, commit, reset, clean, delegate, launch workers, or change Git state.
Run only validation and inspection needed to correct the report evidence. Every tool action remains subject to the supervisor pre-action review boundary.
Return one OrchestratorReviewReport JSON value through the configured output-last-message path.
"#;
    let role_prefix = supervise_role_prefix(
        SupervisePromptRole::O1ChildOrchestrator,
        &assignment.id,
        None,
    );
    let source_report = serde_json::to_string_pretty(&source.report)
        .context("failed to serialize authenticated source report for evidence-only re-audit")?;
    let binding = serde_json::to_string_pretty(&source.operation.preserved_candidate_binding)
        .context("failed to serialize preserved candidate binding")?;
    let prompt = format!(
        r#"{cacheable_prefix}{role_prefix}
Evidence-only operation:
- Source run id: {source_run_id}
- Re-audit attempt: {attempt}
- Assignment id: {assignment_id}
- Preserved managed worktree: {worktree_path}
- Assigned paths: {assigned_paths}
- Output report path: {report_path}
- Orchestrator report schema: {schema_path}
- Required candidate binding: {binding}

Report contract:
- Preserve assigned_paths, semantic_symbols, semantic_modules, files_changed, field_guide_entries, worker_reports, and decomposition_completions exactly from the authenticated source report.
- Set audit_reports=[], review_lens_aggregate=null, gate_denials=[], and gate_correction_outcomes=[]; these are supervisor-owned.
- Update only commands_run, validation_results, findings, environment_failures, accepted/rejected/status, remaining_risk, next_safe_action, and current claim/semantic tokens as supported by evidence you actually observe.
- Do not claim timings, counts, versions, disk state, lock history, or side effects unless the evidence in this operation establishes them.
- Acceptance requires sufficient accurate validation evidence for the exact preserved diff below. If validation remains insufficient, reject the report honestly.

Authenticated source report JSON:
{source_report}

Exact preserved diff presented for validation:
{diff}
"#,
        source_run_id = source.operation.source_run_id.as_str(),
        attempt = source.operation.attempt,
        assignment_id = assignment.id,
        worktree_path = worktree.path.display(),
        assigned_paths = display_paths(&assignment.assigned_paths),
        report_path = report_path.display(),
        schema_path = schema_path.display(),
        binding = binding,
        source_report = source_report,
        diff = diff,
    );
    let measurement = PromptByteMeasurement::new(
        PromptMeasurementRole::O1ChildOrchestrator,
        &assignment.id,
        &prompt,
        cacheable_prefix,
        CHILD_ORCHESTRATOR_PROMPT_FIXTURE_CEILING_BYTES,
    )?;
    Ok(RenderedPromptWithMeasurements {
        prompt,
        measurements: PromptMeasurementsArtifact::new(vec![measurement], None),
    })
}

pub(super) fn render_child_orchestrator_prompt_with_incoming_root_and_field_guide(
    context: ChildOrchestratorPromptContext<'_>,
    incoming_root: &Path,
    assignment_metadata: &AssignmentMetadata,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<RenderedPromptWithMeasurements> {
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
    let worker_prompt_renders = assignment
        .worker_assignments
        .iter()
        .map(|worker| -> Result<(String, PromptByteMeasurement)> {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            let rendered = worker_prompt_with_field_guide(
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
            )?;
            let invariant_prefix = worker_cacheable_prefix();
            let measurement = PromptByteMeasurement::new(
                PromptMeasurementRole::TerminalWorker,
                &worker.id,
                &rendered,
                &invariant_prefix,
                WORKER_PROMPT_FIXTURE_CEILING_BYTES,
            )?;
            Ok((rendered, measurement))
        })
        .collect::<Result<Vec<_>>>()?;
    let worker_prompts = worker_prompt_renders
        .iter()
        .map(|(rendered, _)| rendered.as_str())
        .collect::<Vec<_>>()
        .join("\n\n--- worker prompt contract ---\n\n");
    let auditor_prompt = review_auditor_prompt_with_metadata_and_field_guide(
        plan,
        assignment,
        assignment_metadata,
        run_dir,
        auditor_schema_path,
        field_guide,
    )?;
    let auditor_prefix = review_auditor_cacheable_prefix();
    let auditor_id = format!("{}-review-auditor", assignment.id);
    let auditor_measurement = PromptByteMeasurement::new(
        PromptMeasurementRole::ChildSideReviewAuditor,
        auditor_id,
        &auditor_prompt,
        &auditor_prefix,
        REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
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
    let cacheable_prefix = child_orchestrator_cacheable_prefix();
    let prompt = format!(
        r#"{cacheable_prefix}{role_prefix}{field_guide_section}

Assignment-specific context:
- Assigned child worktree: {worktree_path}
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
{consultation_section}

Collection targets:
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
        cacheable_prefix = cacheable_prefix,
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
    );
    let mut prompt_measurements = Vec::with_capacity(worker_prompt_renders.len() + 2);
    prompt_measurements.push(PromptByteMeasurement::new(
        PromptMeasurementRole::O1ChildOrchestrator,
        &assignment.id,
        &prompt,
        &cacheable_prefix,
        CHILD_ORCHESTRATOR_PROMPT_FIXTURE_CEILING_BYTES,
    )?);
    prompt_measurements.extend(
        worker_prompt_renders
            .into_iter()
            .map(|(_, measurement)| measurement),
    );
    prompt_measurements.push(auditor_measurement);
    Ok(RenderedPromptWithMeasurements {
        prompt,
        measurements: PromptMeasurementsArtifact::new(
            prompt_measurements,
            Some(WorkerPromptEmbeddingMultiplier::for_plan(plan)?),
        ),
    })
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
        r#"{cacheable_prefix}{role_prefix}{field_guide_section}

Assignment-specific context:
- Parent child orchestrator: {orchestrator_id}
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

- Use the worker report schema path: {schema_path}

Supervisor task:
{task}

Worker assignment JSON:
{worker_json}
"#,
        cacheable_prefix = worker_cacheable_prefix(),
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
        r#"{cacheable_prefix}{role_prefix}{field_guide_section}

Assignment-specific context:
- Parent child orchestrator: {orchestrator_id}
- Review auditor id: {auditor_id}
- Assigned worker ids to audit: {worker_ids}
- Megafile decomposition worker targets: {decomposition_targets}
- Assigned paths to review: {assigned_paths}
- Semantic symbols: {semantic_symbols}
- Semantic modules: {semantic_modules}
- Run artifact root: {run_dir}

- Use the auditor report schema path: {schema_path}

Supervisor task:
{task}
"#,
        cacheable_prefix = review_auditor_cacheable_prefix(),
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

#[cfg(test)]
pub(super) fn parent_review_auditor_prompt_with_field_guide(
    context: ParentReviewAuditorPromptContext<'_>,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<String> {
    Ok(render_parent_review_auditor_prompt_with_field_guide(context, field_guide)?.prompt)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn render_parent_review_auditor_prompt_with_field_guide(
    context: ParentReviewAuditorPromptContext<'_>,
    field_guide: &SupervisorFieldGuidePrompt,
) -> Result<RenderedPromptWithMeasurements> {
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
    let cacheable_prefix = parent_review_auditor_cacheable_prefix();
    let prompt = format!(
        r#"{cacheable_prefix}{role_prefix}{field_guide_section}

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

Child report JSON:
{child_report_json}
"#,
        cacheable_prefix = cacheable_prefix,
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
    );
    let measurement = PromptByteMeasurement::new(
        PromptMeasurementRole::ParentAcceptanceAuditor,
        auditor_id,
        &prompt,
        &cacheable_prefix,
        PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
    )?;
    Ok(RenderedPromptWithMeasurements {
        prompt,
        measurements: PromptMeasurementsArtifact::new(vec![measurement], None),
    })
}

pub(super) fn render_review_lens_auditor_prompt(
    context: ReviewLensAuditorPromptContext<'_>,
    lens_index: usize,
) -> Result<RenderedPromptWithMeasurements> {
    let ReviewLensAuditorPromptContext {
        assignment,
        lens,
        request,
        required_coverage,
    } = context;
    let auditor_id = review_lens_auditor_id(assignment, lens_index);
    let cacheable_prefix = parent_review_auditor_cacheable_prefix();
    let role_prefix = supervise_role_prefix(SupervisePromptRole::ReviewAuditor, &auditor_id, None);
    let request_json = serde_json::to_string(request)
        .context("failed to serialize the parent-built review lens request")?;
    let coverage_json = serde_json::to_string(required_coverage)
        .context("failed to serialize supervisor-derived review coverage")?;
    let prompt = format!(
        r#"{cacheable_prefix}{role_prefix}

Review-lens execution contract:
- Lens id: {lens_id}
- Backend id: {backend_id}
- Model: {model}
- Reasoning effort: {reasoning_effort}
- Treat REVIEW_LENS_REQUEST_JSON as the complete review-information boundary.
- Do not attempt to discover omitted child information, repository state, worktree state, artifacts, or ambient files.
- Report reviewed_worker_ids and reviewed_paths for every entry in REQUIRED_COVERAGE_JSON.
- Return only an AuditorReport JSON matching the runtime-supplied output schema.

REQUIRED_COVERAGE_JSON:
{coverage_json}

REVIEW_LENS_REQUEST_JSON:
{request_json}
"#,
        lens_id = lens.id,
        backend_id = lens.backend.backend_id(),
        model = lens.backend.model(),
        reasoning_effort = lens
            .backend
            .reasoning_effort()
            .unwrap_or("<runtime-default>"),
    );
    enforce_rendered_prompt_ceiling(
        "parent acceptance auditor review lens",
        &prompt,
        PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
    )?;
    let measurement = PromptByteMeasurement::new(
        PromptMeasurementRole::ParentAcceptanceAuditor,
        auditor_id,
        &prompt,
        &cacheable_prefix,
        PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
    )?;
    Ok(RenderedPromptWithMeasurements {
        prompt,
        measurements: PromptMeasurementsArtifact::new(vec![measurement], None),
    })
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

pub(super) fn apply_review_lens_model_selection(
    command: ExternalAgentCommand,
    lens: &ReviewLensConfig,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
) -> Result<ExternalAgentCommand> {
    let ReviewLensBackendConfig::Model {
        backend_id,
        model,
        reasoning_effort,
        ..
    } = &lens.backend
    else {
        bail!("precomputed review lenses cannot be dispatched as model processes");
    };
    validate_review_lens_runtime_selection(lens, runtime, catalog)?;
    if runtime == SupervisorRuntime::Fake {
        return Ok(command
            .with_model_provider(None)
            .with_model_selection(None, None));
    }
    Ok(command
        .with_model_provider(Some(backend_id.clone()))
        .with_model_selection(Some(model.clone()), reasoning_effort.clone()))
}

pub(super) fn validate_review_lens_runtime_selection(
    lens: &ReviewLensConfig,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
) -> Result<()> {
    let ReviewLensBackendConfig::Model { model, .. } = &lens.backend else {
        bail!("precomputed review lenses cannot be dispatched as model processes");
    };
    if runtime != SupervisorRuntime::Fake
        && catalog.availability(Some(model), runtime)? != RoleModelAvailability::Available
    {
        bail!(
            "configured model '{}' for review lens '{}' is unavailable; lens dispatch fails closed",
            model,
            lens.id
        );
    }
    Ok(())
}

pub(super) fn apply_canonical_environment_requirements(
    command: ExternalAgentCommand,
    requirements: &[EnvironmentRequirement],
) -> ExternalAgentCommand {
    command.with_environment_requirements(requirements.iter().cloned())
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    fn fixed_prompt_fixture() -> Result<(String, String, String, String)> {
        fixed_prompt_fixture_with_ids("child-a", "worker-a", "src/supervise/prompts.rs")
    }

    fn fixed_prompt_fixture_with_ids(
        child_id: &str,
        worker_id: &str,
        assigned_path: &str,
    ) -> Result<(String, String, String, String)> {
        let worker = WorkerAssignment {
            id: worker_id.to_string(),
            role: AgentRole::Worker,
            assigned_paths: vec![PathBuf::from(assigned_path)],
            semantic_symbols: vec!["worker_prompt_with_field_guide".to_string()],
            semantic_modules: vec!["supervise::prompts".to_string()],
            task: Some("implement the assigned prompt change".to_string()),
            environment_requirements: Vec::new(),
            report_path: None,
        };
        let assignment = OrchestratorAssignment {
            id: child_id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from(assigned_path)],
            semantic_symbols: vec!["worker_prompt_with_field_guide".to_string()],
            semantic_modules: vec!["supervise::prompts".to_string()],
            task: Some("complete the bounded prompt-chain assignment".to_string()),
            worker_assignments: vec![worker],
            environment_requirements: Vec::new(),
            notes: None,
        };
        let plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "fixed rendered-prompt regression fixture".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 60,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![assignment.clone()],
        };
        let run_dir = Path::new("/tmp/maco-prompt-regression");
        let incoming_root = run_dir.join("incoming");
        let worker_schema_path = run_dir.join("schemas/worker-report.schema.json");
        let auditor_schema_path = run_dir.join("schemas/auditor-report.schema.json");
        let field_guide = SupervisorFieldGuidePrompt::empty()?;
        let assignment_metadata = AssignmentMetadata::new();
        let worker_metadata = WorkerAssignmentMetadata::default();
        let worker_prompt = worker_prompt_with_field_guide(
            WorkerPromptRenderContext {
                plan: &plan,
                orchestrator: &assignment,
                worker: &assignment.worker_assignments[0],
                metadata: &worker_metadata,
                run_dir,
                incoming_root: &incoming_root,
                schema_path: &worker_schema_path,
            },
            &field_guide,
        )?;
        let auditor_prompt = review_auditor_prompt_with_metadata_and_field_guide(
            &plan,
            &assignment,
            &assignment_metadata,
            run_dir,
            &auditor_schema_path,
            &field_guide,
        )?;
        let worktree = WorktreeRecord {
            name: assignment.id.clone(),
            path: PathBuf::from("/tmp/maco-prompt-regression/worktree"),
            branch: "maco/prompt-regression-child".to_string(),
        };
        let claim = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: assignment.id.clone(),
            paths: assignment.assigned_paths.clone(),
        };
        let consultant = SupervisorConsultantPlan::default();
        let child_report_path = incoming_root.join(format!("{child_id}.json"));
        let child_prompt = child_orchestrator_prompt_with_incoming_root_and_field_guide(
            ChildOrchestratorPromptContext {
                plan: &plan,
                assignment: &assignment,
                run_dir,
                worktree: &worktree,
                report_path: &child_report_path,
                schema_path: &run_dir.join("schemas/orchestrator-review-report.schema.json"),
                worker_schema_path: &worker_schema_path,
                auditor_schema_path: &auditor_schema_path,
                consultant: &consultant,
                claim_context: ChildPromptClaimContext {
                    claim: &claim,
                    semantic_intent_token: None,
                },
            },
            &incoming_root,
            &assignment_metadata,
            &field_guide,
        )?;
        let child_report = OrchestratorReviewReport {
            id: assignment.id.clone(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: assignment.assigned_paths.clone(),
            semantic_symbols: assignment.semantic_symbols.clone(),
            semantic_modules: assignment.semantic_modules.clone(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            field_guide_entries: Vec::new(),
            worker_reports: Vec::new(),
            audit_reports: Vec::new(),
            review_lens_aggregate: None,
            decomposition_completions: Vec::new(),
            gate_denials: Vec::new(),
            gate_correction_outcomes: Vec::new(),
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        };
        let parent_auditor_prompt = parent_review_auditor_prompt_with_field_guide(
            ParentReviewAuditorPromptContext {
                plan: &plan,
                assignment: &assignment,
                assignment_metadata: &assignment_metadata,
                run_dir,
                worktree_path: &worktree.path,
                child_report_path: &child_report_path,
                auditor_report_path: &incoming_root.join(format!("{child_id}-review-auditor.json")),
                schema_path: &auditor_schema_path,
                child_report: &child_report,
            },
            &field_guide,
        )?;
        Ok((
            worker_prompt,
            child_prompt,
            auditor_prompt,
            parent_auditor_prompt,
        ))
    }

    fn common_prefix_bytes(left: &str, right: &str) -> usize {
        left.bytes()
            .zip(right.bytes())
            .take_while(|(left_byte, right_byte)| left_byte == right_byte)
            .count()
    }

    #[test]
    fn worker_embedding_multiplier_uses_all_worker_roles_in_the_run() {
        let assignment = |id: &str, worker_count: usize| OrchestratorAssignment {
            id: id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("src/supervise/prompts.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: (0..worker_count)
                .map(|index| WorkerAssignment {
                    id: format!("{id}-worker-{index}"),
                    role: AgentRole::Worker,
                    assigned_paths: vec![PathBuf::from("src/supervise/prompts.rs")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    task: None,
                    environment_requirements: Vec::new(),
                    report_path: None,
                })
                .collect(),
            environment_requirements: Vec::new(),
            notes: None,
        };
        let plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "run-wide multiplier fixture".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 2,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 60,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![assignment("child-a", 1), assignment("child-b", 2)],
        };

        let multiplier =
            WorkerPromptEmbeddingMultiplier::for_plan(&plan).expect("run-wide multiplier");
        assert_eq!(multiplier.worker_roles_per_run, 3);
        assert_eq!(multiplier.levels_that_embed_template, 2);
        assert_eq!(multiplier.total_worker_template_embeddings, 6);
    }

    #[test]
    fn rendered_role_prompts_stay_within_declared_fixture_ceilings() {
        let (worker, child, auditor, parent_auditor) =
            fixed_prompt_fixture().expect("render the fixed prompt fixture");
        let measurements = [
            (
                "terminal worker",
                worker.as_str(),
                WORKER_PROMPT_FIXTURE_CEILING_BYTES,
            ),
            (
                "child orchestrator",
                child.as_str(),
                CHILD_ORCHESTRATOR_PROMPT_FIXTURE_CEILING_BYTES,
            ),
            (
                "review auditor",
                auditor.as_str(),
                REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
            ),
            (
                "parent acceptance auditor",
                parent_auditor.as_str(),
                PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES,
            ),
        ];

        for (role, rendered, ceiling) in measurements {
            eprintln!(
                "{role}: {} rendered bytes (ceiling {ceiling})",
                rendered.len()
            );
            enforce_rendered_prompt_ceiling(role, rendered, ceiling)
                .unwrap_or_else(|error| panic!("{error:#}"));
        }
    }

    #[test]
    fn rendered_role_prompt_ceiling_guard_rejects_growth() {
        let oversized = "x".repeat(WORKER_PROMPT_FIXTURE_CEILING_BYTES.saturating_add(1));
        let error = enforce_rendered_prompt_ceiling(
            "terminal worker",
            &oversized,
            WORKER_PROMPT_FIXTURE_CEILING_BYTES,
        )
        .expect_err("one byte beyond the declared ceiling must fail");

        assert!(error.to_string().contains("above its declared"));
        assert!(error
            .to_string()
            .contains(&WORKER_PROMPT_FIXTURE_CEILING_BYTES.to_string()));
    }

    #[test]
    fn rendered_role_prompts_carry_bounded_tool_call_batching_contract() {
        let (worker, child, auditor, parent_auditor) =
            fixed_prompt_fixture().expect("render the fixed prompt fixture");

        for rendered in [&worker, &child, &auditor, &parent_auditor] {
            assert!(rendered.contains(
                "Batch independent, side-effect-free inspections in one tool call when the runtime supports it."
            ));
            assert!(rendered.contains(
                "Keep dependent steps, approval-sensitive actions, and mutations ordered."
            ));
            assert!(rendered.contains(
                "Batching never relaxes ownership, journaling, validation, or audit requirements."
            ));
        }
    }

    #[test]
    fn rendered_role_prompts_share_invariant_bytes_before_role_specific_divergence() {
        let (worker_a, child_a, auditor_a, parent_auditor_a) =
            fixed_prompt_fixture_with_ids("child-a", "worker-a", "src/supervise/prompts-a.rs")
                .expect("render prompt fixture a");
        let (worker_b, child_b, auditor_b, parent_auditor_b) =
            fixed_prompt_fixture_with_ids("child-b", "worker-b", "src/supervise/prompts-b.rs")
                .expect("render prompt fixture b");
        let worker_prefix = worker_cacheable_prefix();
        let child_prefix = child_orchestrator_cacheable_prefix();
        let auditor_prefix = review_auditor_cacheable_prefix();
        let parent_auditor_prefix = parent_review_auditor_cacheable_prefix();
        let comparisons = [
            (
                "terminal worker",
                worker_a.as_str(),
                worker_b.as_str(),
                worker_prefix.as_str(),
            ),
            (
                "child orchestrator",
                child_a.as_str(),
                child_b.as_str(),
                child_prefix.as_str(),
            ),
            (
                "review auditor",
                auditor_a.as_str(),
                auditor_b.as_str(),
                auditor_prefix.as_str(),
            ),
            (
                "parent acceptance auditor",
                parent_auditor_a.as_str(),
                parent_auditor_b.as_str(),
                parent_auditor_prefix.as_str(),
            ),
        ];

        for (role, rendered_a, rendered_b, invariant_prefix) in comparisons {
            assert!(rendered_a.starts_with(invariant_prefix));
            assert!(rendered_b.starts_with(invariant_prefix));
            assert_eq!(
                &rendered_a.as_bytes()[..invariant_prefix.len()],
                &rendered_b.as_bytes()[..invariant_prefix.len()]
            );
            let divergence = common_prefix_bytes(rendered_a, rendered_b);
            assert!(
                divergence >= invariant_prefix.len(),
                "{role} diverged before its invariant prefix ended"
            );
            assert!(
                divergence < rendered_a.len() && divergence < rendered_b.len(),
                "{role} fixtures never diverged"
            );
            assert_ne!(
                rendered_a.as_bytes()[divergence],
                rendered_b.as_bytes()[divergence]
            );
            eprintln!(
                "{role}: {} invariant bytes, first fixture divergence at byte {divergence}",
                invariant_prefix.len()
            );
        }

        let worker_role_offset = worker_a
            .find("ROLE: TERMINAL_WORKER\n")
            .expect("worker role metadata block");
        assert_eq!(worker_role_offset, worker_prefix.len());
        let worker_field_guide_offset = worker_a
            .find(FIELD_GUIDE_SECTION_NOTICE)
            .expect("worker field-guide notice");
        assert_eq!(
            worker_field_guide_offset,
            worker_role_offset
                + supervise_role_prefix(SupervisePromptRole::TerminalWorker, "worker-a", None)
                    .len()
        );
        assert!(worker_a
            .find("Assignment-specific context:")
            .is_some_and(|offset| offset > worker_field_guide_offset));

        let child_role_prefix =
            supervise_role_prefix(SupervisePromptRole::O1ChildOrchestrator, "child-a", None);
        let child_role_offset = child_a
            .find("ROLE: O1_CHILD_ORCHESTRATOR\n")
            .expect("child role metadata block");
        assert_eq!(child_role_offset, child_prefix.len());
        let child_field_guide_offset = child_a
            .find(FIELD_GUIDE_SECTION_NOTICE)
            .expect("child field-guide notice");
        assert_eq!(
            child_field_guide_offset,
            child_role_offset + child_role_prefix.len()
        );
        assert!(child_a.starts_with(&format!(
            "{child_prefix}{child_role_prefix}{FIELD_GUIDE_SECTION_NOTICE}\n"
        )));

        let child_auditor_id = "child-a-review-auditor";
        let child_auditor_role_prefix =
            supervise_role_prefix(SupervisePromptRole::ReviewAuditor, child_auditor_id, None);
        let child_auditor_role_offset = auditor_a
            .find("ROLE: REVIEW_AUDITOR\n")
            .expect("child-side auditor role metadata block");
        assert_eq!(child_auditor_role_offset, auditor_prefix.len());
        let child_auditor_field_guide_offset = auditor_a
            .find(FIELD_GUIDE_SECTION_NOTICE)
            .expect("child-side auditor field-guide notice");
        assert_eq!(
            child_auditor_field_guide_offset,
            child_auditor_role_offset + child_auditor_role_prefix.len()
        );
        assert!(auditor_a.starts_with(&format!(
            "{auditor_prefix}{child_auditor_role_prefix}{FIELD_GUIDE_SECTION_NOTICE}\n"
        )));

        let parent_auditor_role_prefix =
            supervise_role_prefix(SupervisePromptRole::ReviewAuditor, child_auditor_id, None);
        let parent_auditor_role_offset = parent_auditor_a
            .find("ROLE: REVIEW_AUDITOR\n")
            .expect("parent auditor role metadata block");
        assert_eq!(parent_auditor_role_offset, parent_auditor_prefix.len());
        let parent_auditor_field_guide_offset = parent_auditor_a
            .find(FIELD_GUIDE_SECTION_NOTICE)
            .expect("parent auditor field-guide notice");
        assert_eq!(
            parent_auditor_field_guide_offset,
            parent_auditor_role_offset + parent_auditor_role_prefix.len()
        );
        assert!(parent_auditor_a.starts_with(&format!(
            "{parent_auditor_prefix}{parent_auditor_role_prefix}{FIELD_GUIDE_SECTION_NOTICE}\n"
        )));
    }

    #[test]
    fn review_lens_dispatch_preserves_distinct_runtime_selection_and_scope() -> Result<()> {
        let assignment = OrchestratorAssignment {
            id: "child-decorrelated".to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("src/review.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some("review the bounded change".to_string()),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            notes: None,
        };
        let diff_lens = ReviewLensConfig {
            id: "diff-security".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-alpha".to_string(),
                model: "model-alpha".to_string(),
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::DiffOnly,
        };
        let report_lens = ReviewLensConfig {
            id: "report-consistency".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-beta".to_string(),
                model: "model-beta".to_string(),
                reasoning_effort: Some("xhigh".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        };
        let sources = ReviewLensRequestSources {
            child_transcript: "TRANSCRIPT_MUST_NOT_CROSS_NARROW_LENSES",
            diff: "DIFF_VISIBLE_ONLY_TO_DIFF_LENS",
            output_report: "REPORT_VISIBLE_ONLY_TO_REPORT_LENS",
        };
        let diff_request = build_review_lens_request(&diff_lens, sources)?;
        let report_request = build_review_lens_request(&report_lens, sources)?;
        let coverage = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let diff_prompt = render_review_lens_auditor_prompt(
            ReviewLensAuditorPromptContext {
                assignment: &assignment,
                lens: &diff_lens,
                request: &diff_request,
                required_coverage: &coverage,
            },
            0,
        )?
        .prompt;
        let report_prompt = render_review_lens_auditor_prompt(
            ReviewLensAuditorPromptContext {
                assignment: &assignment,
                lens: &report_lens,
                request: &report_request,
                required_coverage: &coverage,
            },
            1,
        )?
        .prompt;
        assert!(diff_prompt.contains("DIFF_VISIBLE_ONLY_TO_DIFF_LENS"));
        assert!(!diff_prompt.contains("REPORT_VISIBLE_ONLY_TO_REPORT_LENS"));
        assert!(!diff_prompt.contains("TRANSCRIPT_MUST_NOT_CROSS_NARROW_LENSES"));
        assert!(report_prompt.contains("REPORT_VISIBLE_ONLY_TO_REPORT_LENS"));
        assert!(!report_prompt.contains("DIFF_VISIBLE_ONLY_TO_DIFF_LENS"));
        assert!(!report_prompt.contains("TRANSCRIPT_MUST_NOT_CROSS_NARROW_LENSES"));

        let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs([
            "model-alpha",
            "model-beta",
        ])?);
        let primary = tempfile::tempdir()?;
        let child_worktree = tempfile::tempdir()?;
        let make_command = |lens: &ReviewLensConfig, prompt_name: &str| -> Result<_> {
            let workspace = create_review_lens_scope_workspace()?;
            let command = ExternalAgentCommand::codex(
                "codex",
                workspace.path(),
                Path::new(prompt_name),
                Path::new("/tmp/review-lens-test.jsonl"),
                Path::new("/tmp/review-lens-test.json"),
                Duration::from_secs(30),
            );
            let command = apply_review_lens_model_selection(
                command,
                lens,
                SupervisorRuntime::Codex,
                &catalog,
            )?;
            let command = configure_review_lens_execution_boundary(
                command,
                primary.path(),
                child_worktree.path(),
            )?;
            Ok((workspace, command))
        };
        let (diff_workspace, diff_command) = make_command(&diff_lens, "diff-prompt.md")?;
        let (report_workspace, report_command) = make_command(&report_lens, "report-prompt.md")?;
        assert_ne!(diff_workspace.path(), report_workspace.path());
        assert_eq!(diff_command.cwd, diff_workspace.path());
        assert_eq!(report_command.cwd, report_workspace.path());
        assert_eq!(
            diff_command.hidden_roots,
            vec![
                primary.path().to_path_buf(),
                child_worktree.path().to_path_buf()
            ]
        );
        assert_eq!(
            diff_command.model_provider.as_deref(),
            Some("provider-alpha")
        );
        assert_eq!(diff_command.model.as_deref(), Some("model-alpha"));
        assert_eq!(diff_command.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(
            report_command.model_provider.as_deref(),
            Some("provider-beta")
        );
        assert_eq!(report_command.model.as_deref(), Some("model-beta"));
        assert_eq!(report_command.reasoning_effort.as_deref(), Some("xhigh"));
        let diff_argv = crate::external_agent::command_argv(&diff_command)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let report_argv = crate::external_agent::command_argv(&report_command)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(diff_argv
            .windows(2)
            .any(|pair| pair == ["-m", "model-alpha"]));
        assert!(diff_argv
            .iter()
            .any(|argument| argument == "model_provider=\"provider-alpha\""));
        assert!(diff_argv
            .iter()
            .any(|argument| argument == "model_reasoning_effort=\"high\""));
        assert!(report_argv
            .windows(2)
            .any(|pair| pair == ["-m", "model-beta"]));
        assert!(report_argv
            .iter()
            .any(|argument| argument == "model_provider=\"provider-beta\""));
        assert!(report_argv
            .iter()
            .any(|argument| argument == "model_reasoning_effort=\"xhigh\""));
        Ok(())
    }

    #[test]
    fn review_lens_prompt_rejects_parent_auditor_ceiling_overrun() -> Result<()> {
        let assignment = OrchestratorAssignment {
            id: "child-bounded-lens".to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("src/review.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            notes: None,
        };
        let lens = ReviewLensConfig {
            id: "bounded-output".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: "gpt-5".to_string(),
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        };
        let oversized_report = "x".repeat(PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES);
        let request = build_review_lens_request(
            &lens,
            ReviewLensRequestSources {
                child_transcript: "",
                diff: "",
                output_report: &oversized_report,
            },
        )?;
        let error = match render_review_lens_auditor_prompt(
            ReviewLensAuditorPromptContext {
                assignment: &assignment,
                lens: &lens,
                request: &request,
                required_coverage: &ReviewCoverageRequirement::default(),
            },
            0,
        ) {
            Ok(_) => panic!("an oversized real lens prompt must fail before launch"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("parent acceptance auditor review lens"),
            "unexpected rejection: {error}"
        );
        assert!(error
            .to_string()
            .contains(&PARENT_REVIEW_AUDITOR_PROMPT_FIXTURE_CEILING_BYTES.to_string()));
        Ok(())
    }
}
