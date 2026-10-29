mod acceptance_integrity;
mod autonomy_kpis;
mod budget;
mod catalog_preflight_admission;
mod environment_controls;
mod licensed_breakage;
mod plan_runtime;
mod primary_worktree;
mod prompts_gates;
mod reaudit;
mod role_transition;
mod run_artifacts;
mod scheduler;
mod source_base;
use super::*;
use crate::{
    external_agent::{
        CapturedOutput, CodexPermissionEvidence, EnvironmentConfiguration,
        EnvironmentNetworkAccess, EnvironmentPreflightStatus, SandboxDenialBoundary,
        SandboxDenialRetryability, SandboxDeniedOperation,
    },
    field_guide::{encode_utf8_lower_hex, FIELD_GUIDE_PROMPT_ENTRY_PREFIX},
    hierarchy_ledger::{
        reconstruct_hierarchy_ledger, GATE_OWNERSHIP_FIELD, ROLE_TRANSITION_FIELD,
        SUPERVISION_EDGE_FIELD,
    },
    orchestration_event::{
        set_orchestration_event_append_fault, OrchestrationEvent, ORCHESTRATION_EVENT_PATH,
    },
    process_runner::{ContainmentBackend, SideEffectConfinementProfileKind},
};
use git2::Signature;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Condvar,
};
use std::time::Instant;

fn injected_codex_runtime_catalog(slugs: &[&str]) -> RuntimeModelCatalog {
    RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs(slugs.iter().copied())
            .expect("valid injected Codex runtime model catalog"),
    )
}

fn install_named_test_models(models: &[&str]) -> InstalledModelCapabilityPolicy {
    let entries = models
        .iter()
        .map(|model| (*model, ModelCapabilityClass::CriticalJudgment))
        .collect::<Vec<_>>();
    install_test_fixture_models(&entries).expect("test fixture capability policy")
}

#[cfg(unix)]
fn mandatory_control_test_workspace() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary mandatory-control workspace");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).expect("create mandatory-control workspace");
    fs::write(
        workspace.join(".git"),
        b"gitdir: /held/common/worktrees/test\n",
    )
    .expect("write linked-worktree marker fixture");
    (temp, workspace)
}

fn control_test_command(workspace: &Path, artifact_root: &Path) -> ExternalAgentCommand {
    ExternalAgentCommand::codex(
        "/run/current-system/sw/bin/codex",
        workspace,
        workspace.join("prompt.md"),
        artifact_root.join("events.jsonl"),
        artifact_root.join("report.json"),
        Duration::from_secs(1),
    )
}

fn denial_fixture(
    boundary: SandboxDenialBoundary,
    policy_id: &str,
    path: Option<&str>,
    retryability: SandboxDenialRetryability,
) -> SandboxDenialEvidence {
    SandboxDenialEvidence {
        boundary,
        policy_id: policy_id.to_string(),
        operation: match boundary {
            SandboxDenialBoundary::OuterSystemd => SandboxDeniedOperation::EstablishBoundary,
            SandboxDenialBoundary::InnerCodex => SandboxDeniedOperation::Write,
        },
        path: path.map(PathBuf::from),
        retryability,
    }
}

fn bounded_loader_plan_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "task": "bounded loader",
        "max_depth": 2,
        "max_child_assignments": 1,
        "max_child_retries": 0,
        "child_timeout_seconds": 60,
        "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["README.md"],
            "worker_assignments": []
        }]
    }))
    .expect("serialize bounded loader plan")
}

fn canonical_test_field_guide_line(
    finding: &str,
    context: &str,
    date: &str,
    source_run: &str,
) -> String {
    format!(
            "{FIELD_GUIDE_PROMPT_ENTRY_PREFIX}finding_utf8_hex={}|context_utf8_hex={}|date={date}|source_run={source_run}",
            encode_utf8_lower_hex(finding),
            encode_utf8_lower_hex(context)
        )
}

fn single_field_guide_frame_tokens(prompt: &str) -> (String, String) {
    let opening_tokens = prompt
        .lines()
        .filter(|line| line.starts_with(FIELD_GUIDE_FRAME_BEGIN_PREFIX))
        .collect::<Vec<_>>();
    let closing_tokens = prompt
        .lines()
        .filter(|line| line.starts_with(FIELD_GUIDE_FRAME_END_PREFIX))
        .collect::<Vec<_>>();
    assert_eq!(opening_tokens.len(), 1, "expected one opening frame token");
    assert_eq!(closing_tokens.len(), 1, "expected one closing frame token");
    let opening_token = opening_tokens[0].to_string();
    let closing_token = closing_tokens[0].to_string();
    let opening_nonce = opening_token
        .strip_prefix(FIELD_GUIDE_FRAME_BEGIN_PREFIX)
        .expect("opening nonce");
    let closing_nonce = closing_token
        .strip_prefix(FIELD_GUIDE_FRAME_END_PREFIX)
        .expect("closing nonce");
    assert_eq!(opening_nonce, closing_nonce);
    assert_eq!(opening_nonce.len(), 64);
    assert!(opening_nonce
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    assert_eq!(prompt.matches(opening_token.as_str()).count(), 1);
    assert_eq!(prompt.matches(closing_token.as_str()).count(), 1);
    (opening_token, closing_token)
}

fn read_finalized_orchestration_events(reader: &ArtifactRunReader) -> Vec<OrchestrationEvent> {
    let contents = reader
        .read(ORCHESTRATION_EVENT_PATH)
        .expect("read finalized orchestration journal");
    std::str::from_utf8(&contents)
        .expect("UTF-8 orchestration journal")
        .lines()
        .map(|line| serde_json::from_str(line).expect("schema-conforming event record"))
        .collect()
}

fn correction_correlation_id_from_prompt(prompt: &str) -> &str {
    prompt
        .lines()
        .find_map(|line| line.strip_prefix("Correction correlation id: "))
        .expect("correction prompt must carry a correlation id")
}

fn assert_single_gate_lifecycle_correlation(
    report: &SupervisorFinalReport,
    correction_prompts: &[String],
    reader: &ArtifactRunReader,
    expected_states: &[&str],
) {
    assert_eq!(report.gate_denials.len(), 1);
    assert_eq!(report.gate_correction_outcomes.len(), 1);
    let denial = &report.gate_denials[0];
    let expected_correlation = denial.correction_correlation_id.as_str();
    let outcome = &report.gate_correction_outcomes[0];
    assert_eq!(outcome.denial_id, denial.denial_id.as_str());
    assert_eq!(outcome.correction_correlation_id, expected_correlation);
    if !report.orchestrator_reports.is_empty() {
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|child| child.gate_denials.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|child| child.gate_correction_outcomes.len())
                .sum::<usize>(),
            1
        );
    }
    for recorded_denial in report.gate_denials.iter().chain(
        report
            .orchestrator_reports
            .iter()
            .flat_map(|child| child.gate_denials.iter()),
    ) {
        assert_eq!(recorded_denial.denial_id, denial.denial_id);
        assert_eq!(
            recorded_denial.correction_correlation_id,
            denial.correction_correlation_id
        );
    }
    for recorded_outcome in report.gate_correction_outcomes.iter().chain(
        report
            .orchestrator_reports
            .iter()
            .flat_map(|child| child.gate_correction_outcomes.iter()),
    ) {
        assert_eq!(recorded_outcome.denial_id, denial.denial_id.as_str());
        assert_eq!(
            recorded_outcome.correction_correlation_id,
            expected_correlation
        );
    }
    for prompt in correction_prompts {
        assert_eq!(
            correction_correlation_id_from_prompt(prompt),
            expected_correlation
        );
    }

    let gate_events = read_finalized_orchestration_events(reader)
        .into_iter()
        .filter(|event| event.kind == OrchestrationEventKind::Gate)
        .filter(|event| event.payload.get("state").is_some())
        .collect::<Vec<_>>();
    assert_eq!(gate_events.len(), expected_states.len());
    for (event, expected_state) in gate_events.iter().zip(expected_states) {
        assert_eq!(event.payload["state"], *expected_state);
        assert_eq!(event.payload["denial_id"], denial.denial_id.as_str());
        assert_eq!(
            event.payload["correction_correlation_id"],
            expected_correlation
        );
    }
}

fn assert_final_decision_event<T: ReportStatus>(
    events: &[OrchestrationEvent],
    node: &str,
    parent: &str,
    role: OrchestrationRole,
    report: &T,
) {
    let expected_kind = if report_failed(report) {
        OrchestrationEventKind::Reject
    } else {
        OrchestrationEventKind::Accept
    };
    let event = events
        .iter()
        .find(|event| {
            event.node == node
                && event.parent.as_deref() == Some(parent)
                && event.role == role
                && event.kind == expected_kind
                && event.payload.get("scope").is_none()
        })
        .unwrap_or_else(|| {
            panic!("missing final {expected_kind:?} event for {role:?} {node} under {parent}")
        });
    assert_eq!(event.payload["accepted"], report.accepted());
    assert_eq!(event.payload["rejected"], report.rejected());
    assert_eq!(
        event.payload["status"],
        serde_json::to_value(report.status()).expect("serialize report status")
    );
}

pub(super) fn injected_repository() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary repository root");
    let path = temp.path().join("repo");
    Repository::init(&path).expect("initialize injected repository");
    fs::write(path.join("README.md"), "baseline\n").expect("write injected baseline");
    commit_injected_repository(&path, "baseline");
    (temp, path)
}

fn commit_injected_repository(path: &Path, message: &str) {
    let repo = crate::git_repository::open(path).expect("open injected repository");
    let mut index = repo.index().expect("open injected index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("stage injected repository");
    index.write().expect("write injected index");
    let tree_id = index.write_tree().expect("write injected tree");
    let tree = repo.find_tree(tree_id).expect("find injected tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
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
    .expect("commit injected repository");
}

fn run_injected_git(repo: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run injected Git command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn injected_assignment(with_worker: bool) -> OrchestratorAssignment {
    OrchestratorAssignment {
        assignment_shape: None,
        id: "child-a".to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("README.md")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        worker_assignments: with_worker
            .then(|| WorkerAssignment {
                id: "worker-a".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                environment_requirements: Vec::new(),
                report_path: None,
            })
            .into_iter()
            .collect(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
        decision_refs: Vec::new(),
    }
}

fn injected_named_assignment(id: &str, path: &str) -> OrchestratorAssignment {
    OrchestratorAssignment {
        assignment_shape: None,
        id: id.to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from(path)],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        worker_assignments: Vec::new(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
        decision_refs: Vec::new(),
    }
}

pub(crate) fn single_parent_acceptance_review_lenses() -> Vec<ReviewLensConfig> {
    vec![ReviewLensConfig {
        id: "parent-acceptance".to_string(),
        backend: ReviewLensBackendConfig::Model {
            backend_id: "openai".to_string(),
            model: DEFAULT_PROFILE_MODEL.to_string(),
            reasoning_effort: Some("xhigh".to_string()),
        },
        information_scope: ReviewInformationScope::FullChildTranscript,
    }]
}

fn injected_multi_plan(
    assignments: Vec<OrchestratorAssignment>,
    max_child_retries: u8,
) -> SupervisorPlan {
    SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task: "injected concurrent supervisor fixture".to_string(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: assignments.len(),
        max_child_retries,
        max_gate_corrections: 0,
        child_timeout_seconds: 10,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: single_parent_acceptance_review_lenses(),
        review_lens_correlation: Default::default(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments,
    }
}

fn injected_command_assignment_id(command: &ExternalAgentCommand) -> String {
    command
        .output_last_message
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .trim_end_matches(".json")
        .split(".attempt-")
        .next()
        .unwrap_or_default()
        .to_string()
}

fn write_injected_assignment_report(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
) {
    write_injected_json(
        &command.output_last_message,
        &injected_child_report(assignment),
    );
}

fn injected_plan(assignment: OrchestratorAssignment, max_child_retries: u8) -> SupervisorPlan {
    SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task: "injected supervisor fixture".to_string(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries,
        max_gate_corrections: 0,
        child_timeout_seconds: 10,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: single_parent_acceptance_review_lenses(),
        review_lens_correlation: Default::default(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![assignment],
    }
}

fn injected_run_budget(
    soft_tokens: Option<usize>,
    hard_tokens: Option<usize>,
    soft_cost_usd: Option<f64>,
    hard_cost_usd: Option<f64>,
    child_tokens: usize,
    auditor_tokens: usize,
) -> SupervisorBudgetConfig {
    SupervisorBudgetConfig {
        limits: RunBudgetLimits {
            soft_tokens,
            hard_tokens,
            soft_cost_usd,
            hard_cost_usd,
        },
        role_token_reservations: BTreeMap::from([
            (AgentRole::ChildOrchestrator, child_tokens),
            (AgentRole::Auditor, auditor_tokens),
        ]),
    }
}

fn inject_priced_process_roles(plan: &mut SupervisorPlan, model: &str, rate: f64) {
    let selection = RoleModelSelection {
        model: Some(model.to_string()),
        reasoning_effort: None,
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    };
    plan.role_models
        .insert(AgentRole::ChildOrchestrator, selection.clone());
    plan.role_models.insert(AgentRole::Auditor, selection);
    for lens in &mut plan.review_lenses {
        if let ReviewLensBackendConfig::Model {
            model: lens_model, ..
        } = &mut lens.backend
        {
            *lens_model = model.to_string();
        }
    }
    plan.model_pricing.insert(
        model.to_string(),
        ModelPricing {
            input_usd_per_million_tokens: rate,
            output_usd_per_million_tokens: rate,
        },
    );
}

pub(crate) fn write_injected_usage(
    command: &ExternalAgentCommand,
    input_tokens: usize,
    output_tokens: usize,
) {
    fs::write(
            &command.json_log,
            format!(
                "{{\"type\":\"turn.completed\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":{output_tokens}}}}}\n"
            ),
        )
        .expect("write injected Codex usage");
}

fn injected_machine_global_retention(
    root: &Path,
) -> crate::machine_global::MachineGlobalRetentionBinding {
    crate::machine_global::MachineGlobalRetentionBinding {
        config: root.join("unused-machine-global.json"),
        root_id: "runtime".to_string(),
        owner: "maco-supervise-test".to_string(),
        correction_correlation_id: "injected-supervise-test".to_string(),
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_supervisor_plan_with_selected_nested_review_fixture(
    mut plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    budget: SupervisorBudgetConfig,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    supplied_catalog: Option<RuntimeModelCatalog>,
    owner: &tempfile::TempDir,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    use super::model_policy::{ModelCapabilityEvidence, ModelCapabilityPolicy};
    use super::prior_input::{bind_operator_prior_data, OperatorPriorSnapshot};
    use std::io::Write;

    if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation
        || options.runtime != SupervisorRuntime::Codex
        || !options
            .repo
            .canonicalize()?
            .starts_with(owner.path().canonicalize()?)
    {
        bail!("nested review fixture requires owned Codex NonpublishableSimulation inputs");
    }
    let child = effective_role_model_selection(&plan, AgentRole::ChildOrchestrator);
    let model = child
        .model
        .clone()
        .context("fixture authored child model")?;
    let effort = child
        .reasoning_effort
        .as_deref()
        .map(|authored| ReasoningEffort::parse(authored).context("fixture child effort"))
        .transpose()?;
    if effort.is_none() {
        let admitted_missing_child_effort = matches!(plan.review_lenses.len(), 2 | 3)
            || (plan.review_lenses.len() == 1 && plan.review_lenses[0].id == "parent-acceptance");
        if !admitted_missing_child_effort {
            bail!("fixture child effort");
        }
    }
    // A lens contract can identify the existing uniform fixture shape, but it
    // never supplies the absent child effort. Only assessed selection below does.
    let uniform_effort = effort.map(ReasoningEffort::as_str).or_else(|| {
        plan.review_lenses
            .first()
            .and_then(|lens| lens.backend.reasoning_effort())
    });
    let uniform = plan.review_lenses.len() == 3
        && uniform_effort.is_some()
        && plan.review_lenses.iter().all(|lens| {
            lens.backend.model() == model && lens.backend.reasoning_effort() == uniform_effort
        });
    if !uniform {
        plan.role_models
            .get_mut(&AgentRole::ChildOrchestrator)
            .context("fixture child preference")?
            .reasoning_effort = child.reasoning_effort.clone();
    }
    // This is an authored preference only. The bootstrap and final initialization
    // must independently obtain matching account/policy selector decisions.
    let auditor = RoleModelSelection {
        model: Some(model.clone()),
        reasoning_effort: if uniform {
            None
        } else {
            effort.map(|effort| effort.as_str().to_string())
        },
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    };
    if let Some(authored) = plan.role_models.get(&AgentRole::Auditor) {
        // Keep an explicit independent Auditor preference. Its model and effective
        // effort receive synthetic observations below and still pass normal selection.
        if authored.model.is_none() {
            bail!("nested review fixture requires an explicit authored Auditor model");
        }
    } else {
        plan.role_models.insert(AgentRole::Auditor, auditor);
    }
    let actual_catalog = match supplied_catalog {
        Some(catalog) => catalog,
        None => test_runtime_model_catalog(&plan, options.runtime)?,
    };
    let RuntimeModelCatalog::Codex(catalog) = &actual_catalog else {
        bail!("nested review fixture requires its actual supplied Codex catalog");
    };
    let mut metadata = SupervisorPlanMetadata::default();
    let policy = bind_assessed_injected_plan(&plan, &options.repo, &mut metadata)?;
    let base = super::selection_bridge::base_selector_priors_with_terminal_worker_economics()?;
    let baseline = base
        .models
        .iter()
        .find(|row| row.runtime == "codex" && row.model == FRONTIER_PROFILE_MODEL)
        .cloned()
        .context("nested review fixture baseline prior")?;
    let mut profiles = BTreeMap::<String, BTreeSet<String>>::new();
    // For an absent effort, retain the baseline's full existing prior menu.
    // Do not add review evidence for an invented child effort.
    profiles
        .entry(model.clone())
        .or_default()
        .extend(effort.map(|effort| effort.as_str().to_string()));
    for lens in &plan.review_lenses {
        profiles
            .entry(lens.backend.model().to_string())
            .or_default()
            .insert(resolve_review_lens_reasoning_effort(lens, None).resolved);
    }
    if let Some(auditor) = plan.role_models.get(&AgentRole::Auditor) {
        profiles
            .entry(auditor.model.clone().context("fixture Auditor model")?)
            .or_default()
            .extend(enforce_role_reasoning_effort_floor(
                AgentRole::Auditor,
                auditor.reasoning_effort.clone(),
            ));
    }
    let mut priors = Vec::new();
    let mut capabilities = Vec::new();
    for (model, efforts) in profiles {
        let mut prior = baseline.clone();
        prior.model = model.clone();
        prior.source_id = "synthetic-nested-review-profile".to_string();
        prior.prior_scope = "nonlive nested review fixture only".to_string();
        prior.limitations.push(
            "synthetic profile; not measured model evidence or account/launch authority"
                .to_string(),
        );
        // Explicit synthetic eligibility for an authored high-effort review.
        // Production policy and selector hard gates are not changed by this fixture.
        for effort in efforts {
            let effort: crate::selection::ReasoningEffort = serde_json::from_value(json!(effort))?;
            if !prior
                .class_fit
                .iter()
                .any(|row| row.task_class == "review_gate" && row.effort == effort)
            {
                let mut row = baseline
                    .class_fit
                    .iter()
                    .find(|row| row.task_class == "review_gate")
                    .cloned()
                    .context("fixture baseline review evidence")?;
                row.effort = effort;
                prior
                    .authority_evidence
                    .push(crate::selection::AuthorityEvidencePrior {
                        task_class: row.task_class.clone(),
                        role: crate::selection::AuthorityRole::ReviewAuditor,
                        effort,
                        quality_basis_points: row.quality_basis_points,
                        sample_size: row.sample_size,
                    });
                prior.class_fit.push(row);
            }
        }
        priors.push(prior);
        capabilities.push(ModelCapabilityEvidence {
            model,
            capability: ModelCapabilityClass::CriticalJudgment,
            eligible: true,
            evidence: "synthetic fixture only; no account or launch authority".to_string(),
            as_of: base.published_on.clone(),
        });
    }
    let snapshot = OperatorPriorSnapshot {
        schema_version: 1,
        dataset_id: "synthetic-nested-review-prior".to_string(),
        revision: format!("{}+nested-review-fixture", base.revision),
        published_on: base.published_on.clone(),
        models: priors,
        capability_policy: ModelCapabilityPolicy {
            id: "synthetic-nested-review-capability".to_string(),
            version: 1,
            source: "nonlive nested review fixture only".to_string(),
            models: capabilities,
        },
    };
    let relative = Path::new("nested-review-fixture-prior.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(options.repo.join(relative))?;
    file.write_all(&serde_json::to_vec(&snapshot)?)?;
    drop(file);
    let _prior = bind_operator_prior_data(&options.repo, relative)?;
    let effort = match effort {
        Some(effort) => effort,
        None => {
            let frozen = metadata
                .resolved_routing_policy
                .as_ref()
                .context("default fixture frozen policy")?;
            let assessment = metadata
                .task_routing_assessment
                .as_ref()
                .context("default fixture parsed assessment")?;
            assessment.validate_for_task(frozen, &plan.task)?;
            let admission = SupervisorAdmissionPolicyInput::resolve(
                &options.repo,
                1,
                metadata.admission,
                SupervisorAdmissionConfig::default(),
            )?;
            let objective =
                resolve_objective_profile(&options.repo, metadata.objective_profile.as_deref())?;
            let history = super::outcome_history::load_frozen_outcome_history(
                &options.repo,
                &options.run_id,
            )?;
            let _bootstrap_account = super::scheduler::install_licensed_autopilot_account_fixture(
                owner,
                &actual_catalog,
            )?;
            let _bootstrap_policy =
                crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
            let mut observation = super::scheduler::account_observation_for_launch_runtime(
                SupervisorRuntime::Codex,
                None,
            )?
            .context("default fixture selected account observation")?;
            // Preserve the explicit model preference while selecting the missing
            // effort from its complete genuine current record. Remove alternatives;
            // never add access, effort, provenance or selected-account evidence.
            let observed = observation
                .models
                .as_mut()
                .filter(|category| {
                    category.outcome
                        == coding_agent_manager_lib::account_authority::ObservationOutcome::Observed
                })
                .and_then(|category| category.content.as_mut())
                .context("default fixture observed model menu")?;
            observed.models.retain(|row| row.model_id == model);
            if observed.models.len() != 1 || !catalog.contains(&model) {
                bail!("default fixture authored model lacks its unique current catalog record");
            }
            let observations = [(SupervisorRuntime::Codex, observation)];
            let (subject, subject_decision) =
                super::selection_bridge::select_normal_account_intake_with_assessment(
                    &plan,
                    frozen,
                    &observations,
                    &admission,
                    &objective,
                    Some(&history),
                    Some(assessment),
                )?;
            let subject = subject.context("default fixture subject selection refused")?;
            let (auditor, auditor_decision) =
                super::selection_bridge::select_account_review_auditor_with_assessment(
                    &plan,
                    frozen,
                    &observations,
                    &admission,
                    &objective,
                    Some(assessment),
                )?;
            let auditor = auditor.context("default fixture Auditor selection refused")?;
            for (role, selected, decision) in [
                (AgentRole::ChildOrchestrator, &subject, &subject_decision),
                (AgentRole::Auditor, &auditor, &auditor_decision),
            ] {
                let receipt = decision
                    .routing_policy
                    .as_ref()
                    .context("default fixture selector policy receipt")?;
                let choice = decision
                    .choice
                    .as_ref()
                    .context("default fixture genuine selected choice")?;
                selected.validate_binding(&(&observations[0].1.binding).into())?;
                if decision.status != crate::selection::DecisionStatus::Selected
                    || selected.candidate() != &choice.candidate
                    || choice.candidate.runtime != SupervisorRuntime::Codex.as_str()
                    || choice.candidate.model != model
                    || receipt.frozen != *frozen
                    || receipt.role != role.as_str()
                    || selected.policy_digest != frozen.sha256
                    || selected.task_features != receipt.features
                    || decision.operator_prior_data != super::prior_input::current_provenance()
                    || decision.normalized_input.debug_override.is_some()
                    || !decision.candidate_set.iter().any(|candidate| {
                        candidate.candidate == choice.candidate
                            && candidate.eligible
                            && candidate.ineligibility_reasons.is_empty()
                    })
                {
                    bail!("default fixture profile differs from its genuine assessed selection");
                }
            }
            let selected_effort = ReasoningEffort::parse(subject.candidate().effort.as_str())
                .context("default fixture selected child effort")?;
            // Keep authored Nones for the existing uniform bootstrap only when
            // both selected profiles and the authored lenses actually match.
            let uniform_selected_profile = uniform
                && auditor.candidate().effort == subject.candidate().effort
                && uniform_effort == Some(auditor.candidate().effort.as_str());
            if !uniform_selected_profile {
                // Resolve absent preferences only after genuine normal decisions.
                // Heterogeneous lens triples are never changed by this bootstrap.
                for (role, selected) in [
                    (AgentRole::ChildOrchestrator, &subject),
                    (AgentRole::Auditor, &auditor),
                ] {
                    let preference = plan
                        .role_models
                        .get_mut(&role)
                        .context("default fixture authored role preference")?;
                    if preference.reasoning_effort.is_some() {
                        bail!("default fixture must not replace an explicit role effort");
                    }
                    preference.reasoning_effort =
                        Some(selected.candidate().effort.as_str().to_string());
                }
            }
            selected_effort
        }
    };

    let _fixture = super::scheduler::install_selected_nested_review_fixture(
        &plan, &options, catalog, metadata, owner, policy, effort,
    )?;
    let mut plan_metadata = SupervisorPlanMetadata {
        run_budget: budget,
        ..SupervisorPlanMetadata::default()
    };
    super::scheduler::carry_selected_concurrent_fixture_metadata(
        &plan,
        &options,
        &actual_catalog,
        &mut plan_metadata,
    )?;
    let serialized_runner = std::sync::Mutex::new(external_runner);
    super::run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata,
        },
        options,
        1,
        execution_runtime,
        SupervisorWorktreeCreation::TestOnly,
        Ok(actual_catalog),
        &|command, _cancellation, _review_runtime| match serialized_runner.lock() {
            Ok(mut runner) => runner(command),
            Err(poisoned) => poisoned.into_inner()(command),
        },
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_supervisor_plan_with_selected_nested_review_fixture(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    budget: SupervisorBudgetConfig,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    supplied_catalog: Option<RuntimeModelCatalog>,
    owner: &tempfile::TempDir,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    // Match the existing fixture wrapper's unsupported-platform behavior; the
    // Linux branch always requires its selected-account binding and assessment.
    let _ = owner;
    let catalog = match supplied_catalog {
        Some(catalog) => catalog,
        None => test_runtime_model_catalog(&plan, options.runtime)?,
    };
    run_supervisor_plan_with_budget_catalog_and_runner(
        plan,
        consultant,
        budget,
        options,
        execution_runtime,
        Ok(catalog),
        external_runner,
    )
}

fn run_supervisor_plan_with_selected_default_parent_acceptance_fixture(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    owner: &tempfile::TempDir,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    #[cfg(target_os = "linux")]
    {
        let SupervisorExecutionRuntime::NonpublishableSimulation = execution_runtime else {
            bail!("selected default parent-acceptance fixture requires NonpublishableSimulation");
        };
        if options.runtime != SupervisorRuntime::Codex
            || !plan.role_models.is_empty()
            || serde_json::to_value(&plan.review_lenses)?
                != serde_json::to_value(single_parent_acceptance_review_lenses())?
        {
            bail!("selected default parent-acceptance fixture requires its default Codex input contract");
        }
        let mut document = serde_json::to_value(&plan)?;
        let mut metadata = SupervisorPlanMetadata::default();
        {
            // Retain the parsed assessment, then restore this temporary policy
            // before creating the guard that owns the account and frozen policy.
            let _assessment = bind_assessed_injected_plan(&plan, &options.repo, &mut metadata)?;
            document["resolved_routing_policy"] =
                serde_json::to_value(&metadata.resolved_routing_policy)?;
            document["task_routing_assessment"] =
                serde_json::to_value(&metadata.task_routing_assessment)?;
        }
        let parent_acceptance =
            crate::supervise::bind_injected_supervisor_parent_acceptance_for_test(
                &options.repo,
                &mut document,
                owner,
            )?;
        let plan: SupervisorPlan = serde_json::from_value(document)?;
        let catalog = test_runtime_model_catalog(&plan, options.runtime)?;
        // This existing binder admits bounded nested workers and carries the
        // assessment into normal selection for this exact run and repository.
        let _selected_source = super::scheduler::bind_selected_licensed_source_fixture(
            &plan,
            &options,
            &catalog,
            metadata,
            &parent_acceptance,
        )?;
        let serialized_runner = std::sync::Mutex::new(external_runner);
        super::run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            consultant,
            options,
            1,
            &|command, _cancellation, _review_runtime| match serialized_runner.lock() {
                Ok(mut runner) => runner(command),
                Err(poisoned) => poisoned.into_inner()(command),
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = owner;
        run_supervisor_plan_with_runner(
            plan,
            consultant,
            options,
            execution_runtime,
            external_runner,
        )
    }
}

#[cfg(target_os = "linux")]
fn selected_concurrent_injected_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    owner: &'a tempfile::TempDir,
) -> Result<super::scheduler::SelectedConcurrentFixtureGuard<'a>> {
    let RuntimeModelCatalog::Codex(catalog) = test_runtime_model_catalog(plan, options.runtime)?
    else {
        bail!("selected concurrent fixture requires an actual supplied Codex catalog");
    };
    let mut metadata = SupervisorPlanMetadata::default();
    let policy = bind_assessed_injected_plan(plan, &options.repo, &mut metadata)?;
    super::scheduler::install_selected_concurrent_fixture(
        plan, options, &catalog, metadata, owner, policy,
    )
}

fn run_supervisor_plan_with_selected_concurrent_injected_fixture(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    owner: &tempfile::TempDir,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    #[cfg(target_os = "linux")]
    {
        let SupervisorExecutionRuntime::NonpublishableSimulation = execution_runtime else {
            bail!("selected concurrent injected fixture helper requires NonpublishableSimulation");
        };
        let _fixture = selected_concurrent_injected_fixture(&plan, &options, owner)?;
        let serialized_runner = std::sync::Mutex::new(external_runner);
        super::run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            consultant,
            options,
            1,
            &|command, _cancellation, _review_runtime| match serialized_runner.lock() {
                Ok(mut runner) => runner(command),
                Err(poisoned) => poisoned.into_inner()(command),
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = owner;
        run_supervisor_plan_with_runner(
            plan,
            consultant,
            options,
            execution_runtime,
            external_runner,
        )
    }
}

#[cfg(target_os = "linux")]
fn selected_concurrent_parent_custody<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    owner: &'a tempfile::TempDir,
    ready: &Path,
) -> Result<super::scheduler::ParentConcurrentFixtureCustody<'a>> {
    let RuntimeModelCatalog::Codex(_catalog) = test_runtime_model_catalog(plan, options.runtime)?
    else {
        bail!("inherited concurrent fixture requires an actual supplied Codex catalog");
    };
    let mut metadata = SupervisorPlanMetadata::default();
    let policy = bind_assessed_injected_plan(plan, &options.repo, &mut metadata)?;
    // tempfile 3.27.0 only applies a directory mode when Builder::permissions is
    // Some; the default TempDir may remain Managed-legal while custody create
    // requires an owner-private root. Pin only this creator-owned fixture.
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = owner.path();
        let before = fs::symlink_metadata(path)?;
        if !before.is_dir() || before.file_type().is_symlink() {
            bail!("inherited concurrent fixture owner is not a non-symlink directory");
        }
        // SAFETY: geteuid reads only the calling process's effective UID.
        if before.uid() != unsafe { libc::geteuid() } {
            bail!("inherited concurrent fixture owner is not owned by the current euid");
        }
        let mut permissions = before.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)?;
        let after = fs::symlink_metadata(path)?;
        if !after.is_dir()
            || after.file_type().is_symlink()
            || after.uid() != unsafe { libc::geteuid() }
            || after.mode() & 0o077 != 0
            || after.dev() != before.dev()
            || after.ino() != before.ino()
        {
            bail!("inherited concurrent fixture owner did not remain the pinned private directory");
        }
    }
    super::scheduler::ParentConcurrentFixtureCustody::create(
        plan, options, &metadata, owner, ready, policy,
    )
}

#[cfg(target_os = "linux")]
struct InheritedSelectedConcurrentFixture {
    custody: super::scheduler::InheritedConcurrentFixtureRoot,
    registry_owner: tempfile::TempDir,
    catalog: CodexRuntimeModelCatalog,
    metadata: Option<SupervisorPlanMetadata>,
    policy: Option<crate::selection::routing_policy::RoutingPolicyGuard>,
}

#[cfg(target_os = "linux")]
fn selected_concurrent_inherited_fixture(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    root: &Path,
    ready: &Path,
    witness: &Path,
) -> Result<InheritedSelectedConcurrentFixture> {
    let RuntimeModelCatalog::Codex(catalog) = test_runtime_model_catalog(plan, options.runtime)?
    else {
        bail!("inherited concurrent fixture requires an actual supplied Codex catalog");
    };
    let mut metadata = SupervisorPlanMetadata::default();
    let policy = bind_assessed_injected_plan(plan, &options.repo, &mut metadata)?;
    let custody = super::scheduler::InheritedConcurrentFixtureRoot::open(
        plan, options, &metadata, root, ready, witness,
    )?;
    // Only a fresh registry subdirectory is child-owned, never the inherited root.
    // Parent TempDir cleanup also covers the intentional SIGKILL before child Drop.
    let registry_owner = tempfile::tempdir_in(root)?;
    Ok(InheritedSelectedConcurrentFixture {
        custody,
        registry_owner,
        catalog,
        metadata: Some(metadata),
        policy: Some(policy),
    })
}

#[cfg(target_os = "linux")]
impl InheritedSelectedConcurrentFixture {
    fn install(
        &mut self,
        plan: &SupervisorPlan,
        options: &SupervisorRunOptions,
    ) -> Result<super::scheduler::SelectedConcurrentFixtureGuard<'_>> {
        let metadata = self
            .metadata
            .take()
            .context("inherited fixture metadata already consumed")?;
        let policy = self
            .policy
            .take()
            .context("inherited fixture policy already consumed")?;
        super::scheduler::install_selected_inherited_concurrent_fixture(
            plan,
            options,
            &self.catalog,
            metadata,
            &self.registry_owner,
            policy,
            &self.custody,
        )
    }
}

fn injected_options(repo: &Path, root: &Path, run_id: &str) -> SupervisorRunOptions {
    SupervisorRunOptions {
        repo: repo.to_path_buf(),
        plan_file: root.join(format!("{run_id}.json")),
        run_id: RunId::new(run_id).expect("valid injected run id"),
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(injected_machine_global_retention(root)),
    }
}

pub(super) fn artifact_test_final_report(run_id: &RunId) -> SupervisorFinalReport {
    SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id: run_id.clone(),
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: PathBuf::from("plan.json"),
        run_dir: RunArtifactFamily::Supervise
            .run_root()
            .join(run_id.as_str()),
        runtime: SupervisorRuntime::Fake,
        publishable: false,
        success: true,
        accepted: false,
        rejected: false,
        status: ReviewStatus::Succeeded,
        run_lifecycle: SupervisorRunLifecycle::Finalized,
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
        gate_denials: Vec::new(),
        pre_action_review_metrics: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        autonomy_kpis: AutonomyKpiReport::default(),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: Vec::new(),
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
        remaining_risk: "private test evidence".to_string(),
        next_safe_action: "none".to_string(),
        executable: None,
    }
}

fn injected_child_report(assignment: &OrchestratorAssignment) -> OrchestratorReviewReport {
    let worker_reports = assignment
        .worker_assignments
        .iter()
        .map(|worker| WorkerReport {
            id: worker.id.clone(),
            role: AgentRole::Worker,
            assignment_kind: AssignmentKind::Ordinary,
            target_path: None,
            assigned_paths: worker.assigned_paths.clone(),
            semantic_symbols: worker.semantic_symbols.clone(),
            semantic_modules: worker.semantic_modules.clone(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            files_changed: Vec::new(),
            validation_results: vec![ValidationResult {
                name: "injected worker validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: None,
            }],
            findings: Vec::new(),
            field_guide_entries: Vec::new(),
            bloated_file_flags: Vec::new(),
            decomposition_completion: None,
            no_further_delegation: Some(true),
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "review".to_string(),
        })
        .collect();
    OrchestratorReviewReport {
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
        validation_results: vec![ValidationResult {
            name: "injected child validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        field_guide_entries: Vec::new(),
        worker_reports,
        audit_reports: Vec::new(),
        review_lens_aggregate: None,
        decomposition_completions: Vec::new(),
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "none".to_string(),
        next_safe_action: "review".to_string(),
    }
}

fn injected_auditor_report(
    assignment: &OrchestratorAssignment,
    child: &OrchestratorReviewReport,
) -> AuditorReport {
    AuditorReport {
        id: review_lens_auditor_id(assignment, 0),
        role: AgentRole::Auditor,
        reviewed_worker_ids: required_auditor_prompt_subject_ids(assignment, child),
        reviewed_paths: required_auditor_review_paths(assignment, child),
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        validation_results: vec![ValidationResult {
            name: "injected auditor validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        rejection_kind: None,
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "none".to_string(),
        next_safe_action: "review".to_string(),
    }
}

fn attach_parent_computed_review_lens_aggregate(
    plan: &SupervisorPlan,
    assignment: &OrchestratorAssignment,
    child: &mut OrchestratorReviewReport,
) {
    let output_report = serde_json::to_string(child).expect("serialize aggregate fixture report");
    let sources = ReviewLensRequestSources {
        child_transcript: "bounded test transcript",
        diff: "bounded test diff",
        output_report: &output_report,
    };
    let coverage = supervisor_review_coverage_requirement(assignment, child);
    let requests = plan
        .review_lenses
        .iter()
        .map(|lens| build_review_lens_request(lens, sources).expect("build fixture lens request"))
        .collect::<Vec<_>>();
    let verdicts = plan
        .review_lenses
        .iter()
        .zip(&requests)
        .map(|(lens, request)| {
            ReviewLensVerdict::for_lens(
                lens,
                request.request_binding.clone(),
                ReviewLensVerdictStatus::Accept,
                ReviewLensCoverage {
                    worker_ids: coverage.worker_ids.clone(),
                    paths: coverage.paths.clone(),
                },
                vec![(
                    ReviewLensEvidenceKind::ModelReview,
                    format!("parent test evidence for {}", lens.id),
                )],
            )
            .expect("construct fixture lens verdict")
        })
        .collect::<Vec<_>>();
    child.review_lens_aggregate = Some(
        aggregate_review_lenses_against_requests(
            &plan.review_lenses,
            &requests,
            plan.review_aggregation_policy,
            coverage,
            verdicts,
        )
        .expect("aggregate fixture review lenses"),
    );
}

fn injected_worker_journal_evidence(
    status: WorkerExecutionJournalStatus,
) -> WorkerExecutionJournalEvidenceSet {
    WorkerExecutionJournalEvidenceSet::from([(
        "worker-a".to_string(),
        WorkerExecutionJournalEvidence {
            incoming_relative_path: PathBuf::from("worker-journals/worker-a.jsonl"),
            evidence_relative_path: worker_execution_journal_evidence_relative(
                "child-a", "worker-a",
            ),
            command_binding: None,
            status,
        },
    )])
}

fn injected_journal_entry(changed_paths: Vec<PathBuf>) -> WorkerExecutionJournalEntry {
    WorkerExecutionJournalEntry {
        command: vec!["injected-worker".to_string()],
        cwd: PathBuf::from("."),
        start_timestamp: "2026-01-01T00:00:00Z".to_string(),
        end_timestamp: "2026-01-01T00:00:01Z".to_string(),
        changed_paths,
        observation: None,
    }
}

fn injected_oid(value: &str) -> Oid {
    Oid::hash_object(ObjectType::Blob, value.as_bytes()).expect("hash injected object")
}

fn injected_index_key(path: &str) -> PrimaryIndexEntryKey {
    PrimaryIndexEntryKey {
        path: path.as_bytes().to_vec(),
        stage: 0,
    }
}

fn injected_primary_snapshot() -> PrimaryWorktreeSnapshot {
    let baseline = injected_oid("baseline");
    PrimaryWorktreeSnapshot {
        head: PrimaryHeadSnapshot {
            detached: false,
            reference_name: Some(b"refs/heads/master".to_vec()),
            symbolic_target: None,
            target: Some(injected_oid("head")),
        },
        index: BTreeMap::from([(
            injected_index_key("README.md"),
            PrimaryIndexEntryState {
                id: baseline,
                mode: 0o100644,
                tag: b'H',
            },
        )]),
        index_storage: PrimaryIndexStorageSnapshot {
            worktree_index: IndexFileSnapshot::Present {
                bytes: 8,
                digest: injected_oid("index"),
            },
            shared_index: None,
        },
        status: BTreeMap::new(),
        worktree: BTreeMap::from([(
            b"README.md".to_vec(),
            PrimaryPathState::File {
                id: baseline,
                mode: 0o100644,
            },
        )]),
        inspection_error: None,
    }
}

fn injected_target_attempted(run: ExternalAgentRun) -> ExternalAgentRun {
    let output_last_message = run.output_last_message.clone();
    let mut launched: ExternalAgentRun = serde_json::from_value(
        serde_json::to_value(&run).expect("serialize injected launched run"),
    )
    .expect("restore injected launched run");
    launched.output_last_message = output_last_message;
    launched
}

pub(crate) fn injected_verified_run(command: &ExternalAgentCommand) -> ExternalAgentRun {
    commit_injected_managed_child_result(command);
    write_injected_worker_journals_from_report(command);
    let mut run = injected_verified_run_without_journals(command);
    let captures = command
        .worker_journal_artifacts
        .iter()
        .map(|artifact| WorkerJournalArtifactCapture {
            worker_id: artifact.worker_id.clone(),
            path: artifact.path.clone(),
            command_binding: None,
            status: match fs::read(&artifact.path) {
                Ok(bytes) => WorkerJournalArtifactCaptureStatus::Loaded(bytes),
                Err(error) => WorkerJournalArtifactCaptureStatus::Invalid(format!(
                    "injected trusted journal capture failed: {error}"
                )),
            },
        })
        .collect();
    run.replace_worker_journal_artifacts(captures);
    run
}

// Opt-in synthetic parent capture for explicitly priced, single-turn fixtures.
// The generic injected runner deliberately retains no observed model identity.
fn retain_priced_single_turn_fixture(
    run: &mut ExternalAgentRun,
    command: &ExternalAgentCommand,
    observed_model: &str,
    complete_capture: &[u8],
) {
    use crate::external_agent::{
        CodexParentEvidence, CodexParentResolvedField as Field, CodexParentTurnUsage,
    };
    assert_eq!(command.model.as_deref(), Some(observed_model));
    assert!(!run.stdout.raw_capture_truncated());
    let usage = codex_usage_from_jsonl(complete_capture)
        .expect("valid complete priced fixture capture")
        .expect("priced fixture has observed usage");
    let completed_turns = complete_capture
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter(|event| event.get("type").and_then(Value::as_str) == Some("turn.completed"))
        .count();
    assert_eq!(completed_turns, 1, "single-turn fixture required");
    run.codex_parent_evidence = Some(CodexParentEvidence {
        codex_version: Some("0.144.4".to_string()),
        thread_id: Some("priced-fixture-thread".to_string()),
        requested_model: command.model.clone(),
        requested_effort: command.reasoning_effort.clone(),
        rollout_model: Field::Known(observed_model.to_string()),
        rollout_effort: Field::Unknown,
        observed_model: Field::Known(observed_model.to_string()),
        observed_effort: Field::Unknown,
        server_rerouted_model: None,
        model_mismatch: false,
        turn_usage: CodexParentTurnUsage::Known {
            input_tokens: u64::try_from(usage.input_tokens).expect("fixture input count fits"),
            output_tokens: u64::try_from(usage.output_tokens).expect("fixture output count fits"),
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
        resolution_status: "complete".to_string(),
    });
    run.retain_cli_parent_evidence_for_test(complete_capture);
}

fn commit_injected_managed_child_result(command: &ExternalAgentCommand) {
    if command.workspace_access != WorkspaceAccess::ReadWrite
        || command.writable_launch_target
            != crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree
    {
        return;
    }
    if !command.cwd.join(".git").is_file() {
        // Fixtures without a linked-worktree gitdir pointer (no .git, or a
        // plain repository .git directory) exercise paths before or beside
        // the child Git boundary; there is nothing to commit on their behalf.
        return;
    }

    crate::external_agent::prepare_managed_child_git_boundary_for_test(&command.cwd)
        .expect("prepare injected managed-child private Git boundary");
    let boundary = crate::external_agent::bind_existing_managed_child_git_boundary(&command.cwd)
        .expect("bind injected managed-child private Git boundary");
    let git = || {
        let mut process = std::process::Command::new("git");
        process
            .current_dir(&command.cwd)
            .env("GIT_DIR", boundary.private_git_dir())
            .env("GIT_WORK_TREE", &command.cwd)
            .env("GIT_OBJECT_DIRECTORY", boundary.private_object_dir())
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                boundary.shared_object_dir(),
            )
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "maco test")
            .env("GIT_AUTHOR_EMAIL", "maco-test@example.invalid")
            .env("GIT_COMMITTER_NAME", "maco test")
            .env("GIT_COMMITTER_EMAIL", "maco-test@example.invalid");
        process
    };

    let add = git()
        .args(["add", "--all", "--", "."])
        .output()
        .expect("stage injected managed-child result");
    assert!(
        add.status.success(),
        "staging injected managed-child result failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let diff = git()
        .args(["diff", "--cached", "--quiet", "--exit-code"])
        .output()
        .expect("inspect injected managed-child result");
    if diff.status.success() {
        return;
    }
    assert_eq!(
        diff.status.code(),
        Some(1),
        "inspecting injected managed-child result failed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );

    let commit = git()
        .args([
            "commit",
            "--no-gpg-sign",
            "-m",
            "injected managed child result",
        ])
        .output()
        .expect("commit injected managed-child result");
    assert!(
        commit.status.success(),
        "committing injected managed-child result failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
}

fn injected_verified_nonzero_run(
    command: &ExternalAgentCommand,
    exit_code: i32,
) -> ExternalAgentRun {
    let mut run = injected_verified_run(command);
    run.exit_code = Some(exit_code);
    run.publishable = false;
    run.error = Some(format!("external agent exited with status {exit_code}"));
    run
}

fn injected_verified_run_without_journals(command: &ExternalAgentCommand) -> ExternalAgentRun {
    ExternalAgentRun {
        command: vec!["injected-runner".to_string()],
        cwd: command.cwd.clone(),
        timeout_seconds: command.timeout.as_secs(),
        exit_code: Some(0),
        duration_ms: 1,
        timed_out: false,
        process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        )),
        side_effects: Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        )),
        publishable: true,
        program_trust: ExternalProgramTrust::TrustedSystemCodex,
        codex_permissions: Some(CodexPermissionEvidence {
            codex_version: "0.142.3".to_string(),
            minimum_version: "0.138.0".to_string(),
            permission_profile: "maco_external_codex".to_string(),
            workspace_access: command.workspace_access,
            network_enabled: false,
            argv_digest: "injected-digest".to_string(),
            executable_identity: "injected-identity".to_string(),
        }),
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
        output_last_message: fs::read(&command.output_last_message).ok(),
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        cursor_managed_parent_evidence: None,
        codex_parent_evidence: None,
    }
}

fn write_injected_worker_journals_from_report(command: &ExternalAgentCommand) {
    let contents = match fs::read(&command.output_last_message) {
        Ok(contents) => contents,
        Err(_) => return,
    };
    // Both report structs share enough fields that Serde can deserialize a
    // direct Worker report as an orchestrator report with zero workers. Use the
    // envelope key to distinguish the two fixture formats before parsing.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&contents) else {
        return;
    };
    let workers = if value.get("worker_reports").is_some() {
        let Ok(report) = serde_json::from_value::<OrchestratorReviewReport>(value) else {
            return;
        };
        report.worker_reports
    } else {
        let Ok(worker) = serde_json::from_value::<WorkerReport>(value) else {
            return;
        };
        vec![worker]
    };
    for worker in &workers {
        let Some(artifact) = command
            .worker_journal_artifacts
            .iter()
            .find(|artifact| artifact.worker_id == worker.id)
        else {
            continue;
        };
        let journal = if worker.files_changed.is_empty() && worker.commands_run.is_empty() {
            String::new()
        } else {
            let entries = injected_worker_journal_entries(worker);
            entries
                .iter()
                .map(|entry| {
                    serde_json::to_string(entry).expect("serialize injected worker journal entry")
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&artifact.path)
            .expect("open precreated injected worker journal");
        std::io::Write::write_all(&mut file, journal.as_bytes())
            .expect("append injected worker journal");
    }
}

fn injected_worker_journal_entries(worker: &WorkerReport) -> Vec<WorkerExecutionJournalEntry> {
    if worker.commands_run.is_empty() {
        return vec![injected_journal_entry(worker.files_changed.clone())];
    }
    worker
        .commands_run
        .iter()
        .map(|record| WorkerExecutionJournalEntry {
            command: record.command.clone(),
            cwd: record.cwd.clone(),
            start_timestamp: "2026-01-01T00:00:00Z".to_string(),
            end_timestamp: "2026-01-01T00:00:01Z".to_string(),
            changed_paths: worker.files_changed.clone(),
            observation: None,
        })
        .collect()
}

fn injected_command_record() -> CommandRunRecord {
    CommandRunRecord {
        command: vec!["injected-runner".to_string()],
        cwd: PathBuf::from("."),
        exit_code: Some(0),
        status: ReviewStatus::Succeeded,
        timeout_seconds: 1,
        duration_ms: 1,
        timed_out: false,
        stdout: String::new(),
        stderr: String::new(),
        sandbox_denials: Vec::new(),
        environment_preflight_results: Vec::new(),
        environment_failures: Vec::new(),
        error: None,
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        codex_parent_evidence: None,
        fixed_version_probe_evidence: None,
    }
}

pub(crate) fn write_injected_json(path: &Path, value: &impl Serialize) {
    fs::write(
        path,
        serde_json::to_vec(value).expect("serialize injected report"),
    )
    .expect("write injected report");
}

fn remove_report_slot_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn finding_messages(report: &OrchestratorReviewReport) -> String {
    report
        .findings
        .iter()
        .map(|finding| finding.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn assert_injected_dispatch_cleanup(
    report: &SupervisorFinalReport,
    repo: &Path,
    run_id: &str,
    started_worktree: &str,
    unstarted_worktrees: &[&str],
    expected_scheduler_budget_denial: bool,
) {
    assert_eq!(report.released_claims.len(), 1);
    assert!(report.release_errors.is_empty());
    assert_eq!(report.released_semantic_intents.len(), 1);
    assert_eq!(report.released_semantic_intents[0].agent_id, "child-a");
    assert_eq!(
        report.released_semantic_intents[0].paths,
        vec![PathBuf::from("README.md")]
    );
    assert!(report.semantic_release_errors.is_empty());
    assert!(report.breaker_trip.is_none());
    if expected_scheduler_budget_denial {
        assert_eq!(report.gate_denials.len(), 1);
        assert!(matches!(
            report.gate_denials[0].reason,
            GateDenialReason::BudgetAdmission {
                denial: BudgetAdmissionDenial::NewDispatchStopped,
            }
        ));
    } else {
        assert!(report.gate_denials.is_empty());
    }
    assert!(report.gate_correction_outcomes.is_empty());
    assert!(SyncStore::open(repo)
        .expect("reopen lifecycle sync store")
        .snapshot()
        .expect("snapshot lifecycle claims")
        .is_empty());
    assert!(SemanticIntentStore::open(repo)
        .expect("reopen lifecycle semantic store")
        .snapshot()
        .expect("snapshot lifecycle semantic intents")
        .is_empty());

    let run_root = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id);
    let scratch_entries = fs::read_dir(&run_root)
        .expect("read finalized lifecycle artifact root")
        .map(|entry| {
            entry
                .expect("read lifecycle artifact entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("incoming") || name.starts_with("capture"))
        .collect::<Vec<_>>();
    assert!(
        scratch_entries.is_empty(),
        "invocation scratch artifacts leaked: {scratch_entries:?}"
    );
    assert!(run_root.join(ARTIFACT_FINALIZATION_MARKER).exists());

    let manager = WorktreeManager::new(repo);
    let records = manager.list().expect("list lifecycle worktrees");
    assert!(records.iter().any(|record| record.name == started_worktree));
    for unstarted in unstarted_worktrees {
        assert!(
            records.iter().all(|record| record.name != *unstarted),
            "pending assignment worktree {unstarted} was unexpectedly created"
        );
    }
    let lease = manager
        .acquire_write_execution_lease(started_worktree)
        .expect("started worktree execution lease must be released");
    drop(lease);
}

#[derive(Clone, Copy)]
enum ParseablePartialRunOutcome {
    Failed,
    TimedOut,
}

fn assert_parseable_partial_usage_is_conservative(
    run_id: &str,
    partial_outcome: ParseablePartialRunOutcome,
) {
    let _capability = install_test_fixture_models(&[(
        FRONTIER_PROFILE_MODEL,
        ModelCapabilityClass::CriticalJudgment,
    )])
    .expect("partial-usage fixture capability policy");
    let (temp, repo_path) = injected_repository();
    let child_a = injected_named_assignment("child-a", "README.md");
    let child_b = injected_named_assignment("child-b", "src/lib.rs");
    let mut plan = injected_multi_plan(vec![child_a.clone(), child_b], 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    inject_priced_process_roles(&mut plan, FRONTIER_PROFILE_MODEL, 1.0);
    let existing_effort = plan
        .review_lenses
        .first()
        .expect("partial-usage fixture parent lens")
        .backend
        .reasoning_effort()
        .expect("partial-usage fixture parent-lens effort")
        .to_string();
    for role in [AgentRole::ChildOrchestrator, AgentRole::Auditor] {
        plan.role_models
            .get_mut(&role)
            .expect("partial-usage priced process role")
            .reasoning_effort = Some(existing_effort.clone());
    }
    let budget = injected_run_budget(None, Some(200), None, Some(1.0), 50, 50);
    let options = injected_options(&repo_path, temp.path(), run_id);
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        assert_eq!(
            injected_command_assignment_id(command),
            "child-a",
            "latched degraded settlement must prevent the later child dispatch"
        );
        write_injected_assignment_report(command, &child_a);
        // The capture is syntactically complete and contains a genuine Codex usage event,
        // but it is only a partial observation because the enclosing run does not complete.
        write_injected_usage(command, 7, 3);
        match partial_outcome {
            ParseablePartialRunOutcome::Failed => injected_verified_nonzero_run(command, 23),
            ParseablePartialRunOutcome::TimedOut => {
                let mut run = injected_verified_run(command);
                run.exit_code = None;
                run.timed_out = true;
                run.publishable = false;
                run.error = Some("external agent timed out after partial usage".to_string());
                run
            }
        }
    };

    let report = run_supervisor_plan_with_selected_nested_review_fixture(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        None,
        &temp,
        &mut runner,
    )
    .expect("finalize partial-usage run");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    assert!(!report.usage_complete);
    assert!(report.total_usage.is_none());
    assert!(report.total_cost_usd.is_none());
    assert!(report.role_usage[&AgentRole::Supervisor]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("missing, incomplete, or unreliable")));
    let child_usage = &report.role_usage[&AgentRole::ChildOrchestrator];
    assert_eq!(
        child_usage.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(child_usage.usage.is_none());
    assert!(child_usage.cost_usd.is_none());
    assert!(child_usage
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("no reliable process-observable usage sample")));
    let budget = report.run_budget.as_ref().expect("partial usage budget");
    assert_eq!(budget.consumed.tokens, 50);
    assert_eq!(budget.committed.tokens, 50);
    assert_eq!(budget.consumed.cost_usd, None);
    assert_eq!(budget.committed.cost_usd, None);
    assert_eq!(budget.remaining.hard_cost_usd, None);
    assert!(!budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::OwnerEscalation);
    assert!(budget
        .reasons
        .contains(&BudgetReason::EstimatedProviderUsage));
    assert_eq!(report.gate_denials.len(), 1);
    let denial = &report.gate_denials[0];
    assert_eq!(
        denial.reason,
        GateDenialReason::BudgetAdmission {
            denial: BudgetAdmissionDenial::NewDispatchStopped,
        }
    );
    assert_eq!(denial.context.owner, "child-b");
    assert_eq!(denial.context.source, GateCheckSource::BudgetAdmission);
    assert_eq!(denial.route, GateDenialRoute::ChildController);
    assert_eq!(denial.retryability, GateRetryability::NotRetryable);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("conservatively reconciled")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("observed but unreliable")));
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("run budget stopped one or more new dispatches")));
    assert_injected_dispatch_cleanup(&report, &repo_path, run_id, "child-a", &["child-b"], true);
}

pub(super) fn sample_child_report_json(id: &str) -> String {
    format!(
        r#"{{
  "id": "{id}",
  "role": "child_orchestrator",
  "assigned_paths": ["README.md"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "claim_token": null,
  "semantic_intent_token": null,
  "commands_run": [],
  "files_changed": [],
  "validation_results": [],
  "findings": [],
  "worker_reports": [],
  "audit_reports": [],
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review"
}}"#
    )
}

fn sample_auditor_report_json(id: &str) -> String {
    format!(
        r#"{{
  "id": "{id}",
  "role": "auditor",
  "reviewed_worker_ids": ["child-a"],
  "reviewed_paths": ["README.md"],
  "commands_run": [],
  "validation_results": [],
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review"
}}"#
    )
}
