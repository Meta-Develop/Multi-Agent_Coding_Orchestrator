use super::*;
use crate::{
    external_agent::ExternalAgentCommand,
    gate_denial::GateDenialReason,
    mutation_taxonomy::{
        set_autopilot_dispatch_decisions_for_test, AutonomousMutationDecision,
        TAXONOMY_REVIEW_REQUIRED_GATE_ID,
    },
    supervise::{
        AuditorReport, Finding, LicensedBreakageDeclaration, LicensedBreakageDependentScope,
        OrchestratorReviewReport,
    },
    worktree::WorktreeCreateOptions,
};
use serde_json::json;
use std::{
    cell::{Cell, RefCell},
    fs::File,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
};

// Snapshot-heavy Autopilot fixtures each launch contained Git processes against
// the shared systemd slot set. Concurrent siblings only add contention; unique
// RunIds and temp dirs still keep durable state from colliding across leftover
// runs. Serialization is not a substitute for keeping the fixtures themselves.
static SNAPSHOT_HEAVY_AUTOPILOT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock_snapshot_heavy_autopilot_test() -> MutexGuard<'static, ()> {
    SNAPSHOT_HEAVY_AUTOPILOT_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_prepublication_fixture_test() -> MutexGuard<'static, ()> {
    lock_snapshot_heavy_autopilot_test()
}

#[cfg(target_os = "linux")]
static NEXT_ISOLATED_AUTOPILOT_RUN: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
fn isolated_autopilot_run_name(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        NEXT_ISOLATED_AUTOPILOT_RUN.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(target_os = "linux")]
struct IsolatedLicensedAutopilot {
    _lock: MutexGuard<'static, ()>,
    temp: tempfile::TempDir,
    repo: PathBuf,
    run_name: String,
}

#[cfg(target_os = "linux")]
impl IsolatedLicensedAutopilot {
    fn new(label: &str) -> Self {
        let lock = lock_snapshot_heavy_autopilot_test();
        clear_autopilot_test_hooks();
        supervise::clear_follow_up_cascade_test_isolation();
        let temp = tempfile::tempdir().expect("tempdir");
        let run_name = isolated_autopilot_run_name(label);
        let repo = create_committed_autopilot_repo(temp.path());
        Self {
            _lock: lock,
            temp,
            repo,
            run_name,
        }
    }

    fn temp_path(&self) -> &Path {
        self.temp.path()
    }
}

#[cfg(target_os = "linux")]
impl Drop for IsolatedLicensedAutopilot {
    fn drop(&mut self) {
        supervise::clear_follow_up_cascade_test_isolation();
        clear_autopilot_test_hooks();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_licensed_autopilot_fixture_disables_split_index_and_unique_run_ids() {
    skip_without_containment!();
    let first = IsolatedLicensedAutopilot::new("isolation-probe");
    let first_name = first.run_name.clone();
    let split_index = crate::git_repository::open(&first.repo)
        .expect("open isolated fixture")
        .config()
        .expect("open isolated fixture config")
        .get_bool("core.splitIndex")
        .expect("read isolated split-index setting");
    assert!(!split_index);
    crate::orchestrator::RunId::new(&first_name).expect("first isolated run id");
    drop(first);
    let second = IsolatedLicensedAutopilot::new("isolation-probe");
    assert_ne!(first_name, second.run_name);
    crate::orchestrator::RunId::new(&second.run_name).expect("second isolated run id");
}

fn supervisor_profile_test_plan() -> AutopilotPlan {
    AutopilotPlan {
        version: AUTOPILOT_SCHEMA_VERSION,
        task: AutopilotTask {
            title: "Profile plumbing".to_string(),
            body: "Keep the supervisor profile bound to this attempt.".to_string(),
        },
        assigned_paths: vec![PathBuf::from("README.md")],
        path_proposal: planning::TaskPathProposalDiagnostics::default(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        validation_commands: Vec::new(),
        max_repair_attempts: 1,
        forge_mode: AutopilotForgeMode::Fake,
        reviewer: ReviewerConfig::default(),
        publish_mode: AutopilotPublishMode::DraftOnly,
        auto_merge: false,
        external_source: None,
    }
}

fn nondefault_test_profile() -> AutopilotProfile {
    AutopilotProfile {
        version: AUTOPILOT_PROFILE_SCHEMA_VERSION,
        role_models: BTreeMap::from([(
            AgentRole::Worker,
            RoleModelSelection {
                model: Some("profile-worker".to_string()),
                reasoning_effort: Some("medium".to_string()),
                unavailable_model_fallback:
                    crate::supervise::UnavailableModelFallback::LocalDeterministicFake,
            },
        )]),
        model_pricing: BTreeMap::from([(
            "profile-worker".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.25,
                output_usd_per_million_tokens: 5.5,
            },
        )]),
        review_lenses: vec![ReviewLensConfig {
            id: "profile-review".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "profile-provider".to_string(),
                model: "profile-review-model".to_string(),
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: crate::review::ReviewInformationScope::DiffOnly,
        }],
        review_aggregation_policy: ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 1 },
    }
}

#[test]
fn omitted_profile_preserves_legacy_supervisor_plan_bytes() {
    let plan = supervisor_profile_test_plan();
    let profile = AutopilotProfile::default();
    let actual = supervisor_plan_for_attempt(&plan, &profile, "agent-a", 1, &[]);
    let task = supervisor_task(&plan, 1, &[]);
    let legacy = SupervisorPlan {
        version: 1,
        task: task.clone(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: crate::supervise::default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![OrchestratorAssignment {
            id: "agent-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: plan.assigned_paths.clone(),
            semantic_symbols: plan.semantic_symbols.clone(),
            semantic_modules: plan.semantic_modules.clone(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: "agent-a-worker".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: plan.assigned_paths.clone(),
                semantic_symbols: plan.semantic_symbols.clone(),
                semantic_modules: plan.semantic_modules.clone(),
                task: Some(task),
                environment_requirements: Vec::new(),
                report_path: None,
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: Some("autopilot attempt 1".to_string()),
        }],
    };

    assert_eq!(
        serde_json::to_vec(&actual).expect("serialize actual supervisor plan"),
        serde_json::to_vec(&legacy).expect("serialize legacy supervisor plan")
    );
}

#[test]
fn requested_effective_profile_mismatch_is_typed_and_blocks_dispatch() {
    let plan = supervisor_profile_test_plan();
    let requested = nondefault_test_profile();
    let mut effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    effective.role_models.clear();
    effective.model_pricing.clear();
    effective.review_lenses = crate::supervise::default_supervisor_review_lenses();
    effective.review_aggregation_policy = ReviewAggregationPolicy::AllMustAccept;

    let binding = AutopilotProfileBindingReport::from_effective(requested, &effective);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
    assert_eq!(
        binding.configuration_status,
        AutopilotProfileBindingStatus::Mismatch
    );
    assert_eq!(
        binding.failure,
        Some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedEffectiveMismatch,
            mismatched_fields: vec![
                AutopilotProfileBindingField::RoleModels,
                AutopilotProfileBindingField::ModelPricing,
                AutopilotProfileBindingField::ReviewLenses,
                AutopilotProfileBindingField::ReviewAggregationPolicy,
            ],
            mismatched_roles: Vec::new(),
            mismatched_review_lens_ids: Vec::new(),
        })
    );
    assert!(!binding.permits_dispatch());
}

#[test]
fn requested_effective_lens_mismatch_blocks_before_dispatch() {
    let plan = supervisor_profile_test_plan();
    let requested = nondefault_test_profile();
    let mut effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let ReviewLensBackendConfig::Model { backend_id, .. } = &mut effective.review_lenses[0].backend
    else {
        panic!("test profile lens must be model-backed");
    };
    *backend_id = "different-effective-provider".to_string();

    let binding = AutopilotProfileBindingReport::from_effective(requested, &effective);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
    assert_eq!(
        binding.configuration_status,
        AutopilotProfileBindingStatus::Mismatch
    );
    assert_eq!(
        binding.failure,
        Some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedEffectiveMismatch,
            mismatched_fields: vec![AutopilotProfileBindingField::ReviewLenses],
            mismatched_roles: Vec::new(),
            mismatched_review_lens_ids: Vec::new(),
        })
    );
    assert!(!binding.permits_dispatch());
}

fn process_observed_role_usage(models: Vec<&str>) -> RoleUsageReport {
    RoleUsageReport {
        models: models.into_iter().map(str::to_string).collect(),
        usage: Some(crate::llm::provider::Usage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
        }),
        cost_usd: None,
        observation: RoleUsageObservation::ProcessObserved,
        unavailable_reason: None,
    }
}

fn process_observed_lens_usage(lens: &ReviewLensConfig, model: &str) -> ReviewLensUsageReport {
    ReviewLensUsageReport {
        lens_id: lens.id.clone(),
        backend_id: lens.backend.backend_id().to_string(),
        model: model.to_string(),
        usage: Some(crate::llm::provider::Usage {
            input_tokens: 8,
            output_tokens: 4,
            total_tokens: 12,
        }),
        cost_usd: None,
        observation: RoleUsageObservation::ProcessObserved,
        unavailable_reason: None,
    }
}

fn synthetic_lens_dispatch_evidence(
    backend_id: Option<&str>,
    model: Option<&str>,
    reasoning_effort: Option<&str>,
) -> Vec<ReviewLensDispatchEvidence> {
    let command = crate::external_agent::ExternalAgentCommand::codex(
        "codex",
        ".",
        "prompt.md",
        "capture.jsonl",
        "report.json",
        Duration::from_secs(30),
    )
    .with_model_provider(backend_id.map(str::to_string))
    .with_model_selection(
        model.map(str::to_string),
        reasoning_effort.map(str::to_string),
    );
    let command = CommandRunRecord {
        command: crate::external_agent::command_argv(&command)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect(),
        cwd: PathBuf::from("<child-worktree>"),
        exit_code: Some(0),
        status: ReviewStatus::Succeeded,
        timeout_seconds: 30,
        duration_ms: 1,
        timed_out: false,
        stdout: String::new(),
        stderr: String::new(),
        sandbox_denials: Vec::new(),
        environment_preflight_results: Vec::new(),
        environment_failures: Vec::new(),
        error: None,
    };
    review_lens_dispatch_evidence_from_records(
        [("agent-a-review-auditor-lens-0", Some(&command))],
        1,
    )
}

#[test]
fn observed_requested_execution_profile_is_matched() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("profile-child".to_string()),
            reasoning_effort: None,
            unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
        },
    )]);
    let ReviewLensBackendConfig::Model {
        reasoning_effort, ..
    } = &mut requested.review_lenses[0].backend
    else {
        panic!("test profile lens must be model-backed");
    };
    *reasoning_effort = None;
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let role_usage = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        process_observed_role_usage(vec!["profile-child"]),
    )]);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];

    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("profile-provider"),
        Some("profile-review-model"),
        None,
    );
    binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Matched);
    assert_eq!(
        binding.configuration_status,
        AutopilotProfileBindingStatus::Matched
    );
    assert!(binding.failure.is_none());
    let execution = binding.execution.expect("execution binding");
    assert_eq!(
        execution.role_models[0].observed_models,
        vec!["profile-child"]
    );
    assert_eq!(
        execution.review_lenses[0].observed_model.as_deref(),
        Some("profile-review-model")
    );
}

#[test]
fn observed_different_execution_profile_is_typed_mismatch() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("profile-child".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
        },
    )]);
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let role_usage = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        process_observed_role_usage(vec!["different-child"]),
    )]);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];

    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("profile-provider"),
        Some("profile-review-model"),
        Some("high"),
    );
    binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
    assert_eq!(
        binding.configuration_status,
        AutopilotProfileBindingStatus::Matched
    );
    assert_eq!(
        binding.failure,
        Some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedObservedSelectionMismatch,
            mismatched_fields: vec![AutopilotProfileBindingField::RoleModels],
            mismatched_roles: vec![AgentRole::ChildOrchestrator],
            mismatched_review_lens_ids: Vec::new(),
        })
    );
}

#[test]
fn synthetic_complete_lens_dispatch_mismatch_is_a_defensive_signal() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models.clear();
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];
    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("different-synthetic-provider"),
        Some("profile-review-model"),
        Some("high"),
    );

    binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Mismatch);
    assert_eq!(
        binding.failure,
        Some(AutopilotProfileBindingFailure {
            kind: AutopilotProfileBindingFailureKind::RequestedObservedSelectionMismatch,
            mismatched_fields: vec![AutopilotProfileBindingField::ReviewLenses],
            mismatched_roles: Vec::new(),
            mismatched_review_lens_ids: vec!["profile-review".to_string()],
        })
    );
    let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
    assert_eq!(
        observed.observed_backend_id.as_deref(),
        Some("different-synthetic-provider")
    );
    assert_eq!(
        observed.observed_model.as_deref(),
        Some("profile-review-model")
    );
    assert_eq!(observed.observed_reasoning_effort.as_deref(), Some("high"));
    assert_eq!(observed.dispatch_count, 1);
}

#[test]
fn incomplete_lens_dispatch_with_different_backend_is_incomparable() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models.clear();
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];
    let lens_dispatch =
        synthetic_lens_dispatch_evidence(Some("different-synthetic-provider"), None, Some("high"));

    binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    assert!(binding.failure.is_none());
    let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
    assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
    assert_eq!(
        observed.observed_backend_id.as_deref(),
        Some("different-synthetic-provider")
    );
    assert!(observed.observed_model.is_none());
    assert_eq!(
        observed.observation,
        RoleUsageObservation::NotProcessObservable
    );
}

#[test]
fn complete_lens_dispatch_without_usage_is_incomparable() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models.clear();
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("profile-provider"),
        Some("profile-review-model"),
        Some("high"),
    );

    binding.observe_execution_reports(&BTreeMap::new(), &[], &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    assert!(binding.failure.is_none());
    let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
    assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
    assert_eq!(observed.dispatch_count, 1);
    assert_eq!(
        observed.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(observed
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not_process_observable")));
}

#[test]
fn plan_echoed_lens_usage_without_dispatched_selection_is_incomparable() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models.clear();
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];
    let lens_dispatch = synthetic_lens_dispatch_evidence(None, None, None);

    binding.observe_execution_reports(&BTreeMap::new(), &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    assert!(binding.failure.is_none());
    let observed = &binding.execution.as_ref().expect("execution").review_lenses[0];
    assert_eq!(observed.status, AutopilotProfileBindingStatus::Incomparable);
    assert!(observed.observed_backend_id.is_none());
    assert!(observed.observed_model.is_none());
    assert_eq!(observed.dispatch_count, 1);
    assert!(observed
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not_process_observable")));
}

#[test]
fn fake_worker_selection_is_incomparable_not_matched() {
    let plan = supervisor_profile_test_plan();
    let requested = nondefault_test_profile();
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let role_usage = BTreeMap::from([(
        AgentRole::Worker,
        RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(
                "nested fake worker usage is not process observable".to_string(),
            ),
        },
    )]);
    let lens_usage = vec![ReviewLensUsageReport {
        lens_id: requested.review_lenses[0].id.clone(),
        backend_id: requested.review_lenses[0].backend.backend_id().to_string(),
        model: requested.review_lenses[0].backend.model().to_string(),
        usage: None,
        cost_usd: None,
        observation: RoleUsageObservation::NotProcessObservable,
        unavailable_reason: Some("fake lens usage is not process observable".to_string()),
    }];

    let lens_dispatch = synthetic_lens_dispatch_evidence(None, None, None);
    binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    assert_eq!(
        binding.configuration_status,
        AutopilotProfileBindingStatus::Matched
    );
    assert!(binding.failure.is_none());
    let worker = &binding.execution.as_ref().expect("execution").role_models[0];
    assert_eq!(
        worker.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_ne!(worker.status, AutopilotProfileBindingStatus::Matched);
}

#[test]
fn runtime_default_without_explicit_model_is_incomparable() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: None,
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: crate::supervise::UnavailableModelFallback::RuntimeDefault,
        },
    )]);
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let role_usage = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        process_observed_role_usage(Vec::new()),
    )]);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];

    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("profile-provider"),
        Some("profile-review-model"),
        Some("high"),
    );
    binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    let role = &binding.execution.as_ref().expect("execution").role_models[0];
    assert_eq!(role.observation, RoleUsageObservation::NotProcessObservable);
    assert!(role
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("runtime_default")));
}

#[test]
fn unobserved_reasoning_effort_keeps_matching_model_incomparable() {
    let plan = supervisor_profile_test_plan();
    let mut requested = nondefault_test_profile();
    requested.role_models = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("profile-child".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: crate::supervise::UnavailableModelFallback::FailClosed,
        },
    )]);
    let ReviewLensBackendConfig::Model {
        reasoning_effort, ..
    } = &mut requested.review_lenses[0].backend
    else {
        panic!("test profile lens must be model-backed");
    };
    *reasoning_effort = None;
    let effective = supervisor_plan_for_attempt(&plan, &requested, "agent-a", 1, &[]);
    let mut binding = AutopilotProfileBindingReport::from_effective(requested.clone(), &effective);
    let role_usage = BTreeMap::from([(
        AgentRole::ChildOrchestrator,
        process_observed_role_usage(vec!["profile-child"]),
    )]);
    let lens_usage = vec![process_observed_lens_usage(
        &requested.review_lenses[0],
        "profile-review-model",
    )];

    let lens_dispatch = synthetic_lens_dispatch_evidence(
        Some("profile-provider"),
        Some("profile-review-model"),
        None,
    );
    binding.observe_execution_reports(&role_usage, &lens_usage, &lens_dispatch);

    assert_eq!(binding.status, AutopilotProfileBindingStatus::Incomparable);
    let role = &binding.execution.as_ref().expect("execution").role_models[0];
    assert_eq!(role.observation, RoleUsageObservation::NotProcessObservable);
    assert!(role
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("reasoning effort")));
}

fn create_committed_autopilot_repo(root: &Path) -> PathBuf {
    let repo_path = root.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    fs::write(repo_path.join(".gitignore"), ".maco/\n.agents/\n").expect("write gitignore");
    let repository = crate::git_repository::open(&repo_path).expect("open repository");
    {
        let mut config = repository.config().expect("open isolated Autopilot config");
        config
            .set_bool("core.splitIndex", false)
            .expect("disable split-index for isolated Autopilot fixture");
        config
            .set_bool("core.fsmonitor", false)
            .expect("disable fsmonitor for isolated Autopilot fixture");
        config
            .set_bool("core.untrackedCache", false)
            .expect("disable untracked cache for isolated Autopilot fixture");
    }
    let mut index = repository.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index
        .add_path(Path::new(".gitignore"))
        .expect("stage gitignore");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repository.find_tree(tree_id).expect("find tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repository
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    drop(tree);
    drop(repository);
    repo_path
}

#[cfg(target_os = "linux")]
fn secure_autopilot_machine_global_retention(
    root: &Path,
    correlation_id: &str,
) -> MachineGlobalRetentionBinding {
    use std::os::unix::fs::PermissionsExt;

    let runtime_root = root.join(format!("{correlation_id}-isolated-runtime"));
    fs::create_dir(&runtime_root).expect("create isolated Autopilot runtime root");
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700))
        .expect("secure isolated Autopilot runtime root");
    let state_root = root.join(format!("{correlation_id}-machine-global-state"));
    fs::create_dir(&state_root).expect("create injected Autopilot machine-global state");
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .expect("secure injected Autopilot machine-global state");
    let config = root.join(format!("{correlation_id}-machine-global.json"));
    fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))
        .expect("serialize injected Autopilot machine-global config"),
    )
    .expect("write injected Autopilot machine-global config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("secure injected Autopilot machine-global config");
    MachineGlobalRetentionBinding {
        config,
        root_id: "runtime".to_string(),
        owner: "maco-autopilot-test".to_string(),
        correction_correlation_id: correlation_id.to_string(),
    }
}

fn licensed_autopilot_supervisor_plan() -> (Value, LicensedBreakageDeclaration, String) {
    let declaration = LicensedBreakageDeclaration {
        migration_rationale: "Rename callers to crate::api::new_name before dependent dispatch"
            .to_string(),
        dependents: vec![LicensedBreakageDependentScope {
            dependent_id: "client-a".to_string(),
            paths: vec![PathBuf::from("src/client.rs")],
            interfaces: vec!["crate::api::new_name".to_string()],
        }],
    };
    let declaration_sha256 = crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(&declaration).expect("serialize Autopilot license declaration"),
    );
    let plan = SupervisorPlan {
        version: 1,
        task: "perform licensed source change and bounded dependent update".to_string(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: 10,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: crate::supervise::default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![OrchestratorAssignment {
            id: "child-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some("apply licensed breaking source change".to_string()),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: Some(declaration.clone()),
            notes: None,
        }],
    };
    (
        serde_json::to_value(plan).expect("serialize licensed Autopilot supervisor plan"),
        declaration,
        declaration_sha256,
    )
}

fn injected_autopilot_child_report(
    id: &str,
    assigned_paths: Vec<PathBuf>,
    semantic_symbols: Vec<String>,
    files_changed: Vec<PathBuf>,
    licensed_failure: bool,
) -> OrchestratorReviewReport {
    let (validation_results, findings, accepted, rejected, status) = if licensed_failure {
        let signature =
            "error[E0425]: cannot find function crate::api::new_name in dependent client";
        (
            vec![ValidationResult {
                name: "client-a".to_string(),
                status: ReviewStatus::Failed,
                command: vec!["cargo".to_string(), "check".to_string()],
                message: Some(signature.to_string()),
            }],
            vec![Finding {
                severity: FindingSeverity::Error,
                message: signature.to_string(),
                paths: vec![PathBuf::from("src/client.rs")],
            }],
            false,
            true,
            ReviewStatus::Failed,
        )
    } else {
        (
            vec![ValidationResult {
                name: "injected generated validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: None,
            }],
            Vec::new(),
            true,
            false,
            ReviewStatus::Succeeded,
        )
    };
    OrchestratorReviewReport {
        id: id.to_string(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths,
        semantic_symbols,
        semantic_modules: Vec::new(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        files_changed,
        validation_results,
        findings,
        field_guide_entries: Vec::new(),
        worker_reports: Vec::new(),
        audit_reports: Vec::new(),
        review_lens_aggregate: None,
        decomposition_completions: Vec::new(),
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted,
        rejected,
        status,
        remaining_risk: if licensed_failure {
            "declared dependent update remains".to_string()
        } else {
            "none".to_string()
        },
        next_safe_action: "parent review".to_string(),
    }
}

fn injected_autopilot_auditor_report(
    assignment_id: &str,
    reviewed_paths: Vec<PathBuf>,
    declaration_sha256: Option<&str>,
) -> AuditorReport {
    let mut validation_results = vec![ValidationResult {
        name: "injected auditor validation".to_string(),
        status: ReviewStatus::Succeeded,
        command: Vec::new(),
        message: None,
    }];
    if let Some(declaration_sha256) = declaration_sha256 {
        validation_results.push(ValidationResult {
            name: "licensed_breakage_declaration".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: Some(declaration_sha256.to_string()),
        });
    }
    AuditorReport {
        id: format!("{assignment_id}-review-auditor-lens-0"),
        role: AgentRole::Auditor,
        reviewed_worker_ids: vec![assignment_id.to_string()],
        reviewed_paths,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        validation_results,
        findings: Vec::new(),
        rejection_kind: None,
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "none".to_string(),
        next_safe_action: "parent acceptance".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn injected_licensed_autopilot_runner(
    declaration_sha256: String,
    source_child_dispatches: Arc<AtomicUsize>,
    follow_up_child_dispatches: Arc<AtomicUsize>,
) -> impl FnMut(&ExternalAgentCommand, &ProcessCancellation) -> crate::external_agent::ExternalAgentRun
       + Send {
    move |command: &ExternalAgentCommand, _cancellation: &ProcessCancellation| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if is_auditor && is_follow_up {
            supervise::write_injected_json(
                &command.output_last_message,
                &injected_autopilot_auditor_report(
                    "child-a-licensed-update-01",
                    vec![PathBuf::from("src/client.rs")],
                    None,
                ),
            );
        } else if is_auditor {
            supervise::write_injected_json(
                &command.output_last_message,
                &injected_autopilot_auditor_report(
                    "child-a",
                    vec![PathBuf::from("README.md")],
                    Some(&declaration_sha256),
                ),
            );
        } else if is_follow_up {
            let count = follow_up_child_dispatches
                .fetch_add(1, Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "generated child reran");
            fs::create_dir_all(command.cwd.join("src"))
                .expect("create injected Autopilot dependent dir");
            fs::write(
                command.cwd.join("src/client.rs"),
                "pub fn migrated_client() {}\n",
            )
            .expect("write injected Autopilot dependent update");
            supervise::write_injected_json(
                &command.output_last_message,
                &injected_autopilot_child_report(
                    "child-a-licensed-update-01",
                    vec![PathBuf::from("src/client.rs")],
                    vec!["crate::api::new_name".to_string()],
                    vec![PathBuf::from("src/client.rs")],
                    false,
                ),
            );
        } else {
            let count = source_child_dispatches
                .fetch_add(1, Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "Autopilot source child reran");
            fs::write(command.cwd.join("README.md"), "licensed source change\n")
                .expect("write injected Autopilot source candidate");
            supervise::write_injected_json(
                &command.output_last_message,
                &injected_autopilot_child_report(
                    "child-a",
                    vec![PathBuf::from("README.md")],
                    Vec::new(),
                    vec![PathBuf::from("README.md")],
                    true,
                ),
            );
        }
        supervise::write_injected_usage(command, 0, 1);
        supervise::injected_verified_run(command)
    }
}

#[cfg(target_os = "linux")]
fn injected_cancelling_licensed_autopilot_runner(
    declaration_sha256: String,
    caller_cancellation: ProcessCancellation,
    source_scheduler_cancellation_observed: Arc<AtomicBool>,
    source_child_dispatches: Arc<AtomicUsize>,
    follow_up_child_dispatches: Arc<AtomicUsize>,
) -> impl FnMut(&ExternalAgentCommand, &ProcessCancellation) -> crate::external_agent::ExternalAgentRun
       + Send {
    let mut injected_runner = injected_licensed_autopilot_runner(
        declaration_sha256,
        source_child_dispatches,
        follow_up_child_dispatches,
    );
    move |command: &ExternalAgentCommand, scheduler_cancellation: &ProcessCancellation| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if !is_follow_up && !is_auditor {
            assert!(
                !scheduler_cancellation.is_cancelled(),
                "source scheduler token was cancelled before the caller requested cancellation"
            );
            caller_cancellation.cancel();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !scheduler_cancellation.is_cancelled() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "caller cancellation did not propagate to the in-flight source scheduler token"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            source_scheduler_cancellation_observed.store(true, Ordering::SeqCst);
        }
        injected_runner(command, scheduler_cancellation)
    }
}

#[cfg(target_os = "linux")]
fn run_injected_licensed_autopilot_cascade_result(
    temp_root: &Path,
    repo: &Path,
    run_name: &str,
) -> (Result<AutopilotFinalReport>, usize, usize) {
    run_injected_licensed_autopilot_cascade_result_with_bounds(
        temp_root, repo, run_name, None, None,
    )
}

#[cfg(target_os = "linux")]
fn run_injected_licensed_autopilot_cascade_result_with_bounds(
    temp_root: &Path,
    repo: &Path,
    run_name: &str,
    max_child_dispatches: Option<usize>,
    cancellation: Option<ProcessCancellation>,
) -> (Result<AutopilotFinalReport>, usize, usize) {
    let outer_plan = temp_root.join(format!("{run_name}-autopilot.json"));
    fs::write(
        &outer_plan,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "task": {
                "title": "Licensed cascade",
                "body": "Dispatch one bounded generated dependent update."
            },
            "assigned_paths": ["README.md"],
            "auto_merge": false
        }))
        .expect("serialize injected Autopilot outer plan"),
    )
    .expect("write injected Autopilot outer plan");
    let (supervisor_plan, _declaration, declaration_sha256) = licensed_autopilot_supervisor_plan();
    let source_child_dispatches = Arc::new(AtomicUsize::new(0));
    let follow_up_child_dispatches = Arc::new(AtomicUsize::new(0));
    let mut runner = injected_licensed_autopilot_runner(
        declaration_sha256,
        Arc::clone(&source_child_dispatches),
        Arc::clone(&follow_up_child_dispatches),
    );
    let report = run_autopilot_plan_file_with_injected_supervisor_and_runner(
        AutopilotRunOptions {
            repo: repo.to_path_buf(),
            plan_file: outer_plan,
            run_id: RunId::new(run_name).expect("injected Autopilot run id"),
            codex_bin: Some(PathBuf::from("unused-injected-codex")),
            reviewer_command: None,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            max_child_dispatches,
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            cancellation,
        },
        None,
        secure_autopilot_machine_global_retention(temp_root, run_name),
        supervisor_plan,
        &mut runner,
    );
    (
        report,
        source_child_dispatches.load(Ordering::SeqCst),
        follow_up_child_dispatches.load(Ordering::SeqCst),
    )
}

#[cfg(target_os = "linux")]
fn run_injected_licensed_autopilot_cascade(
    temp_root: &Path,
    repo: &Path,
    run_name: &str,
) -> (AutopilotFinalReport, usize) {
    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result(temp_root, repo, run_name);
    assert_eq!(source_child_dispatches, 1);
    (
        report.expect("run injected licensed Autopilot cascade"),
        follow_up_child_dispatches,
    )
}

#[cfg(target_os = "linux")]
fn assert_finalized_autopilot_source_cleanup(
    repo: &Path,
    report: &AutopilotFinalReport,
    source_run_id: &RunId,
) {
    let source = report
        .supervisor
        .as_ref()
        .expect("admitted source supervisor report");
    assert_eq!(source.run_id, *source_run_id);
    assert_eq!(source.released_claims.len(), 1, "{source:#?}");
    assert!(source.release_errors.is_empty(), "{source:#?}");
    assert!(source.semantic_release_errors.is_empty(), "{source:#?}");
    assert!(SyncStore::open(repo)
        .expect("reopen Autopilot source sync store")
        .snapshot()
        .expect("snapshot Autopilot source claims")
        .is_empty());
    assert!(SemanticIntentStore::open(repo)
        .expect("reopen Autopilot source semantic store")
        .snapshot()
        .expect("snapshot Autopilot source semantic intents")
        .is_empty());

    let source_run_root = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(source_run_id.as_str());
    let scratch_entries = fs::read_dir(&source_run_root)
        .expect("read finalized Autopilot source artifacts")
        .map(|entry| {
            entry
                .expect("read Autopilot source artifact entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("incoming") || name.starts_with("capture"))
        .collect::<Vec<_>>();
    assert!(
        scratch_entries.is_empty(),
        "Autopilot source scratch artifacts leaked: {scratch_entries:?}"
    );
    assert!(source_run_root.join(ARTIFACT_FINAL_MARKER).exists());
    ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, source_run_id)
        .expect("open finalized Autopilot source supervisor artifacts");
    assert!(repo
        .join(RunArtifactFamily::Autopilot.run_root())
        .join(report.run_id.as_str())
        .join(ARTIFACT_FINAL_MARKER)
        .exists());
    ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open finalized Autopilot artifacts");

    let manager = WorktreeManager::new(repo);
    assert!(manager
        .pending_operations()
        .expect("read finalized Autopilot worktree operations")
        .is_empty());
    let records = manager.list().expect("list Autopilot managed worktrees");
    assert!(records.iter().any(|record| record.name == "child-a"));
    assert!(records
        .iter()
        .all(|record| record.name != "child-a-licensed-update-01"));
    let lease = manager
        .acquire_write_execution_lease("child-a")
        .expect("source managed worktree write lease must be released");
    drop(lease);
}

#[cfg(target_os = "linux")]
fn assert_undispatched_generated_follow_up_queue(
    queue: &supervise::SupervisorFollowUpQueueSummary,
) {
    assert_eq!(queue.item_count, 1, "{queue:#?}");
    assert_eq!(queue.pending_count, 1, "{queue:#?}");
    assert_eq!(queue.claimed_count, 0, "{queue:#?}");
    assert_eq!(queue.dispatch_started_count, 0, "{queue:#?}");
    assert_eq!(queue.dispatch_observed_count, 0, "{queue:#?}");
    assert_eq!(queue.acknowledged_terminal_count, 0, "{queue:#?}");
    assert_eq!(queue.held_ambiguous_count, 0, "{queue:#?}");
    assert_eq!(
        queue.authenticated_child_dispatch_started_count, 0,
        "{queue:#?}"
    );
}

#[cfg(target_os = "linux")]
fn assert_pre_dispatch_autopilot_cleanup(
    repo: &Path,
    report: &AutopilotFinalReport,
    source_run_id: &RunId,
) {
    assert!(report.supervisor.is_none(), "{report:#?}");
    assert!(SyncStore::open(repo)
        .expect("reopen pre-dispatch Autopilot sync store")
        .snapshot()
        .expect("snapshot pre-dispatch Autopilot claims")
        .is_empty());
    assert!(SemanticIntentStore::open(repo)
        .expect("reopen pre-dispatch Autopilot semantic store")
        .snapshot()
        .expect("snapshot pre-dispatch Autopilot semantic intents")
        .is_empty());
    let manager = WorktreeManager::new(repo);
    assert!(manager
        .pending_operations()
        .expect("read pre-dispatch Autopilot worktree operations")
        .is_empty());
    assert!(manager
        .list()
        .expect("list pre-dispatch Autopilot managed worktrees")
        .is_empty());
    assert!(repo
        .join(RunArtifactFamily::Autopilot.run_root())
        .join(report.run_id.as_str())
        .join(ARTIFACT_FINAL_MARKER)
        .exists());
    ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open finalized pre-dispatch Autopilot artifacts");
    assert!(ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, source_run_id).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_taxonomy_refuses_source_before_any_dispatch_with_exact_gate() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-taxonomy-source-refused");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let source_run_id =
        RunId::new(format!("{run_name}-supervise")).expect("taxonomy source run id");
    let _taxonomy_override =
        set_autopilot_dispatch_decisions_for_test([AutonomousMutationDecision::Refuse {
            gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        }]);

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result_with_bounds(
            fixture.temp_path(),
            repo,
            run_name,
            None,
            None,
        );
    let report = report.expect("return taxonomy source refusal report");

    assert_eq!(source_child_dispatches, 0);
    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Refused, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert_eq!(report.attempt_count, 0, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(matches!(
        report.gate_denials.as_slice(),
        [GateDenial {
            context: VerifiedGateContext {
                source: GateCheckSource::FutureApprovalReview,
                owner,
                ..
            },
            reason: GateDenialReason::ApprovalReview {
                denial: ApprovalReviewDenial::HumanReviewRequired
            },
            ..
        }] if owner == TAXONOMY_REVIEW_REQUIRED_GATE_ID
    ));
    assert!(report
        .next_action
        .contains(TAXONOMY_REVIEW_REQUIRED_GATE_ID));
    assert_pre_dispatch_autopilot_cleanup(repo, &report, &source_run_id);
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone())
            .expect("collect taxonomy-refused source run")["status"],
        Value::String("refused".to_string())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_max_zero_refuses_source_before_any_dispatch_and_leaves_no_state() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-max-zero-source-refused");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let source_run_id = RunId::new(format!("{run_name}-supervise")).expect("bounded source run id");
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture max-zero Autopilot primary baseline");
    let primary_readme_before =
        fs::read(repo.join("README.md")).expect("read max-zero Autopilot primary bytes");
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    supervise::set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result_with_bounds(
            fixture.temp_path(),
            repo,
            run_name,
            Some(0),
            None,
        );
    supervise::clear_generated_follow_up_queue_observer();
    let report = report.expect("return max-zero Autopilot refusal report");

    assert_eq!(source_child_dispatches, 0);
    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Refused, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert_eq!(report.attempt_count, 0, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert_eq!(report.gate_denials.len(), 1, "{report:#?}");
    assert!(matches!(
        report.gate_denials[0].reason,
        GateDenialReason::BudgetAdmission {
            denial: BudgetAdmissionDenial::NewDispatchStopped
        }
    ));
    assert!(
        observations.borrow().is_empty(),
        "{:#?}",
        observations.borrow()
    );
    assert_pre_dispatch_autopilot_cleanup(repo, &report, &source_run_id);
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone()).expect("collect max-zero Autopilot run")
            ["status"],
        Value::String("refused".to_string())
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture max-zero Autopilot final primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("reread max-zero Autopilot primary bytes"),
        primary_readme_before
    );
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_cancellation_after_source_gate_refuses_dispatch_and_finalizes_cancelled() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-source-gate-cancelled");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let source_run_id =
        RunId::new(format!("{run_name}-supervise")).expect("cancelled source run id");
    let caller_cancellation = ProcessCancellation::new();
    let hook_cancellation = caller_cancellation.clone();
    set_autopilot_profile_callsite_hook(move |_effective| hook_cancellation.cancel());
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture source-gate cancellation primary baseline");
    let primary_readme_before =
        fs::read(repo.join("README.md")).expect("read source-gate cancellation primary bytes");
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    supervise::set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result_with_bounds(
            fixture.temp_path(),
            repo,
            run_name,
            None,
            Some(caller_cancellation.clone()),
        );
    supervise::clear_generated_follow_up_queue_observer();
    let report = report.expect("source-gate cancellation must finalize");

    assert!(caller_cancellation.is_cancelled());
    assert_eq!(source_child_dispatches, 0);
    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Cancelled, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert_eq!(report.attempt_count, 0, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(report.gate_denials.is_empty(), "{report:#?}");
    assert!(
        observations.borrow().is_empty(),
        "{:#?}",
        observations.borrow()
    );
    assert_pre_dispatch_autopilot_cleanup(repo, &report, &source_run_id);
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone())
            .expect("collect source-gate cancelled Autopilot run")["status"],
        Value::String("cancelled".to_string())
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture source-gate cancellation final primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("reread source-gate cancellation primary bytes"),
        primary_readme_before
    );
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_source_child_cancellation_propagates_and_cleanly_unwinds() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-source-child-cancelled");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let run_id = RunId::new(run_name).expect("cancelled Autopilot run id");
    let source_run_id =
        RunId::new(format!("{run_name}-supervise")).expect("cancelled source run id");
    let outer_plan = fixture
        .temp_path()
        .join(format!("{run_name}-autopilot.json"));
    fs::write(
        &outer_plan,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "task": {
                "title": "Cancelled licensed cascade",
                "body": "Cancel while the source child is in flight."
            },
            "assigned_paths": ["README.md"],
            "auto_merge": false
        }))
        .expect("serialize cancelling Autopilot outer plan"),
    )
    .expect("write cancelling Autopilot outer plan");
    let (supervisor_plan, _declaration, declaration_sha256) = licensed_autopilot_supervisor_plan();
    let caller_cancellation = ProcessCancellation::new();
    let source_scheduler_cancellation_observed = Arc::new(AtomicBool::new(false));
    let source_child_dispatches = Arc::new(AtomicUsize::new(0));
    let follow_up_child_dispatches = Arc::new(AtomicUsize::new(0));
    let mut runner = injected_cancelling_licensed_autopilot_runner(
        declaration_sha256,
        caller_cancellation.clone(),
        Arc::clone(&source_scheduler_cancellation_observed),
        Arc::clone(&source_child_dispatches),
        Arc::clone(&follow_up_child_dispatches),
    );
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture cancelling Autopilot primary baseline");
    let primary_readme_before =
        fs::read(repo.join("README.md")).expect("read cancelling Autopilot primary bytes");
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    supervise::set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });

    let report = run_autopilot_plan_file_with_injected_supervisor_and_runner(
        AutopilotRunOptions {
            repo: repo.clone(),
            plan_file: outer_plan,
            run_id,
            codex_bin: Some(PathBuf::from("unused-injected-codex")),
            reviewer_command: None,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            max_child_dispatches: None,
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            cancellation: Some(caller_cancellation.clone()),
        },
        None,
        secure_autopilot_machine_global_retention(fixture.temp_path(), run_name),
        supervisor_plan,
        &mut runner,
    )
    .expect("cancelled source child must unwind to a finalized Autopilot report");
    supervise::clear_generated_follow_up_queue_observer();

    assert!(caller_cancellation.is_cancelled());
    assert!(source_scheduler_cancellation_observed.load(Ordering::SeqCst));
    assert_eq!(source_child_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(follow_up_child_dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(report.status, AutopilotRunStatus::Cancelled, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert_eq!(report.attempt_count, 1, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(report.gate_denials.is_empty(), "{report:#?}");
    let source = report
        .supervisor
        .as_ref()
        .expect("cancelled Autopilot retains finalized source report");
    assert!(source.success, "{source:#?}");
    assert_eq!(source.generated_follow_up_tasks.len(), 1, "{source:#?}");

    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open finalized cancelled Autopilot artifacts");
    let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
        &reader
            .read(Path::new("follow-up-cascade-report.json"))
            .expect("read cancelled Autopilot cascade report"),
    )
    .expect("decode cancelled Autopilot cascade report");
    assert!(!cascade.follow_up_cascade_success, "{cascade:#?}");
    assert!(cascade.follow_up_reports.is_empty(), "{cascade:#?}");
    assert!(cascade.follow_up_gate_denials.is_empty(), "{cascade:#?}");
    assert!(
        cascade.follow_up_environment_failures.is_empty(),
        "{cascade:#?}"
    );
    assert!(cancelled_cascade_cleanup_completed(repo, &cascade, true)
        .expect("classify completed cancellation cleanup"));
    assert!(!cancelled_cascade_cleanup_completed(repo, &cascade, false)
        .expect("classify cancellation with changed primary worktree"));
    let mut release_failed = cascade.clone();
    release_failed
        .source_report
        .release_errors
        .push("injected unreleased claim".to_string());
    assert!(
        !cancelled_cascade_cleanup_completed(repo, &release_failed, true)
            .expect("classify cancellation with failed claim release")
    );
    let mut queue_ambiguous = cascade.clone();
    queue_ambiguous
        .follow_up_queue
        .as_mut()
        .expect("cancelled queue summary for cleanup classification")
        .held_ambiguous_count = 1;
    assert!(
        !cancelled_cascade_cleanup_completed(repo, &queue_ambiguous, true)
            .expect("classify cancellation with ambiguous queue item")
    );
    assert_undispatched_generated_follow_up_queue(
        cascade
            .follow_up_queue
            .as_ref()
            .expect("cancelled Autopilot queue summary"),
    );
    let observations = observations.borrow();
    let enqueued = observations
        .iter()
        .find(|observation| observation.label == "enqueued")
        .expect("observe generated follow-up before cancellation release");
    assert!(enqueued.subordinate_run_ids.is_empty(), "{enqueued:#?}");
    assert_eq!(enqueued.pending_count, 1, "{enqueued:#?}");
    assert_eq!(enqueued.claimed_count, 0, "{enqueued:#?}");
    assert_eq!(enqueued.dispatch_started_count, 0, "{enqueued:#?}");
    assert_eq!(enqueued.dispatch_observed_count, 0, "{enqueued:#?}");
    assert_eq!(
        enqueued.authenticated_child_dispatch_started_count, 0,
        "{enqueued:#?}"
    );
    assert!(
            observations
                .iter()
                .all(|observation| observation.label != "dispatch_started"),
            "cancellation must release before any generated follow-up dispatch marker: {observations:#?}"
        );
    drop(observations);

    assert_finalized_autopilot_source_cleanup(repo, &report, &source_run_id);
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone())
            .expect("collect cancelled Autopilot run")["status"],
        Value::String("cancelled".to_string())
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture cancelling Autopilot final primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("reread cancelling Autopilot primary bytes"),
        primary_readme_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_max_child_dispatches_refuses_first_follow_up_before_dispatch_and_releases_claim() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-max-one-follow-up-refused");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let source_run_id = RunId::new(format!("{run_name}-supervise")).expect("bounded source run id");
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture bounded Autopilot primary baseline");
    let primary_readme_before =
        fs::read(repo.join("README.md")).expect("read bounded Autopilot primary bytes");
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    supervise::set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result_with_bounds(
            fixture.temp_path(),
            repo,
            run_name,
            Some(1),
            None,
        );
    supervise::clear_generated_follow_up_queue_observer();
    let report = report.expect("return bounded Autopilot refusal report");

    assert_eq!(source_child_dispatches, 1);
    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Refused, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert_eq!(report.attempt_count, 1, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert_eq!(report.gate_denials.len(), 1, "{report:#?}");
    let denial = &report.gate_denials[0];
    assert!(matches!(
        denial.reason,
        GateDenialReason::BudgetAdmission {
            denial: BudgetAdmissionDenial::NewDispatchStopped
        }
    ));
    assert_eq!(
        denial.retryability,
        crate::gate_denial::GateRetryability::NotRetryable
    );
    assert_eq!(
        denial.next_safe_operation,
        crate::gate_denial::NextSafeOperation::ReviewRunBudgetAndStartNewRun
    );

    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open bounded Autopilot artifacts");
    let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
        &reader
            .read(Path::new("follow-up-cascade-report.json"))
            .expect("read bounded Autopilot cascade report"),
    )
    .expect("decode bounded Autopilot cascade report");
    assert!(!cascade.follow_up_cascade_success, "{cascade:#?}");
    assert_eq!(cascade.follow_up_gate_denials, report.gate_denials);
    assert_undispatched_generated_follow_up_queue(
        cascade
            .follow_up_queue
            .as_ref()
            .expect("bounded Autopilot queue summary"),
    );
    let enqueued = observations
        .borrow()
        .iter()
        .find(|observation| observation.label == "enqueued")
        .cloned()
        .expect("observe bounded generated follow-up enqueue");
    assert!(enqueued.subordinate_run_ids.is_empty(), "{enqueued:#?}");
    assert_eq!(enqueued.pending_count, 1, "{enqueued:#?}");
    assert_eq!(enqueued.claimed_count, 0, "{enqueued:#?}");
    assert_eq!(enqueued.dispatch_started_count, 0, "{enqueued:#?}");
    assert_eq!(enqueued.dispatch_observed_count, 0, "{enqueued:#?}");
    assert_eq!(
        enqueued.authenticated_child_dispatch_started_count, 0,
        "{enqueued:#?}"
    );
    assert!(
        observations
            .borrow()
            .iter()
            .all(|observation| observation.label != "dispatch_started"),
        "bounded admission must refuse before the generated follow-up dispatch marker: {:#?}",
        observations.borrow()
    );

    assert_finalized_autopilot_source_cleanup(repo, &report, &source_run_id);
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone()).expect("collect bounded Autopilot run")
            ["status"],
        Value::String("refused".to_string())
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture bounded Autopilot final primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("reread bounded Autopilot primary bytes"),
        primary_readme_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_taxonomy_refuses_generated_follow_up_as_typed_outcome() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-taxonomy-follow-up-refused");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let _taxonomy_override = set_autopilot_dispatch_decisions_for_test([
        AutonomousMutationDecision::Allow,
        AutonomousMutationDecision::Refuse {
            gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        },
    ]);

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result(fixture.temp_path(), repo, run_name);
    let report = report.expect("return taxonomy follow-up refusal report");

    assert_eq!(source_child_dispatches, 1);
    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Refused, "{report:#?}");
    assert!(!report.success, "{report:#?}");
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(report.gate_denials.iter().any(|denial| {
        denial.context.owner == TAXONOMY_REVIEW_REQUIRED_GATE_ID
            && matches!(
                denial.reason,
                GateDenialReason::ApprovalReview {
                    denial: ApprovalReviewDenial::HumanReviewRequired
                }
            )
    }));
    assert!(report
        .next_action
        .contains(TAXONOMY_REVIEW_REQUIRED_GATE_ID));

    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open taxonomy-refused Autopilot artifacts");
    let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
        &reader
            .read(Path::new("follow-up-cascade-report.json"))
            .expect("read taxonomy-refused cascade report"),
    )
    .expect("decode taxonomy-refused cascade report");
    assert!(!cascade.follow_up_cascade_success, "{cascade:#?}");
    assert_undispatched_generated_follow_up_queue(
        cascade
            .follow_up_queue
            .as_ref()
            .expect("taxonomy-refused queue summary"),
    );
}

#[test]
fn dispatched_subordinate_denial_cannot_impersonate_taxonomy_refusal() {
    let denial = GateDenial::from_approval_review(
        "generated-item",
        TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        ApprovalReviewDenial::HumanReviewRequired,
        [PathBuf::from("src/lib.rs")],
    )
    .expect("construct taxonomy-shaped denial");
    assert_eq!(
        find_generated_follow_up_taxonomy_gate_id(std::slice::from_ref(&denial), &[]),
        Some(TAXONOMY_REVIEW_REQUIRED_GATE_ID.to_string())
    );
    assert_eq!(
        find_generated_follow_up_taxonomy_gate_id(std::slice::from_ref(&denial), &[&denial]),
        None
    );
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_authenticated_follow_up_dispatch_sets_boolean_after_real_gates() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-licensed-follow-up-allowed");
    let repo = &fixture.repo;
    let head_before = crate::git_repository::open(repo)
        .expect("open injected Autopilot repository")
        .head()
        .expect("read injected Autopilot HEAD")
        .target()
        .expect("injected Autopilot HEAD oid");
    let (report, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade(fixture.temp_path(), repo, &fixture.run_name);

    assert_eq!(follow_up_child_dispatches, 1);
    assert_eq!(report.status, AutopilotRunStatus::Succeeded, "{report:#?}");
    assert!(report.success, "{report:#?}");
    assert!(report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(!report.auto_merge_requested);
    assert!(!report.auto_merge_performed);
    assert!(report.supervisor.as_ref().is_some_and(|source| {
        source.success && source.publishable && source.generated_follow_up_tasks.len() == 1
    }));
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open injected Autopilot final artifacts");
    assert_eq!(
        collect_autopilot_run(repo, report.run_id.clone())
            .expect("collect completed Autopilot run")["status"],
        Value::String("succeeded".to_string())
    );
    let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
        &reader
            .read(Path::new("follow-up-cascade-report.json"))
            .expect("read injected Autopilot cascade report"),
    )
    .expect("decode injected Autopilot cascade report");
    assert!(cascade.follow_up_cascade_success, "{cascade:#?}");
    assert_eq!(
        cascade
            .follow_up_queue
            .expect("injected Autopilot queue summary")
            .authenticated_child_dispatch_started_count,
        1
    );
    assert_eq!(
        crate::git_repository::open(repo)
            .expect("reopen injected Autopilot repository")
            .head()
            .expect("reread injected Autopilot HEAD")
            .target()
            .expect("reread injected Autopilot HEAD oid"),
        head_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_cascade_error_after_authenticated_follow_up_start_never_reports_false() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-post-authenticated-start-error");
    let repo = &fixture.repo;
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture primary before post-start failure");
    supervise::set_interrupt_after_authenticated_follow_up_child_start();

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result(
            fixture.temp_path(),
            repo,
            &fixture.run_name,
        );
    let report = report.expect("return an honest failed Autopilot report");

    assert_eq!(source_child_dispatches, 1);
    assert_eq!(follow_up_child_dispatches, 1);
    assert_eq!(report.status, AutopilotRunStatus::Failed, "{report:#?}");
    assert!(!report.success);
    assert!(report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(!report.auto_merge_performed);
    assert!(report.next_action.contains("dispatch started"));
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open finalized honest post-start Autopilot report");
    let final_report: Value = serde_json::from_slice(
        &reader
            .read(Path::new("final-report.json"))
            .expect("read honest post-start final report"),
    )
    .expect("decode honest post-start final report");
    assert_eq!(
        final_report["generated_follow_up_dispatch_performed"],
        Value::Bool(true)
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture primary after post-start failure"),
        primary_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_marker_without_child_checkpoint_refuses_a_false_final_report() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-unobservable-generated-dispatch");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let run_id = RunId::new(run_name).expect("unobservable Autopilot run id");
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture primary before marker-only interruption");
    supervise::set_interrupt_after_follow_up_dispatch_started();

    let (report, source_child_dispatches, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade_result(fixture.temp_path(), repo, run_name);
    let error = report.expect_err("marker-only dispatch state must not finalize false");

    assert_eq!(source_child_dispatches, 1);
    assert_eq!(follow_up_child_dispatches, 0);
    let message = format!("{error:#}");
    assert!(message.contains("not_process_observable"), "{message}");
    assert!(
        message.contains("refusing to finalize a false execution claim"),
        "{message}"
    );
    assert!(
        !crate::artifacts::final_report_path(repo, RunArtifactFamily::Autopilot, &run_id,).exists()
    );
    assert!(ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &run_id).is_err());
    assert!(!repo
        .join(RunArtifactFamily::Autopilot.run_root())
        .join(run_id.as_str())
        .join(ARTIFACT_FINAL_MARKER)
        .exists());
    let collect_error = collect_autopilot_run(repo, run_id.clone())
        .expect_err("crashed or interrupted Autopilot run must stay uncollectable");
    assert!(
        format!("{collect_error:#}").contains("active or unfinalized"),
        "{collect_error:#}"
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture primary after marker-only interruption"),
        primary_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn autopilot_generated_plan_refusal_keeps_dispatch_boolean_false() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-licensed-follow-up-refused");
    let repo = &fixture.repo;
    supervise::set_before_generated_follow_up_plan_load_hook(|path| {
        let bytes = fs::read(path).expect("read persisted Autopilot generated plan");
        let mut value: Value =
            serde_json::from_slice(&bytes).expect("decode Autopilot generated plan");
        value["assignments"][0]["assigned_paths"] = json!(["src/client.rs", "src/expanded.rs"]);
        fs::write(
            path,
            serde_json::to_vec_pretty(&value).expect("encode drifted Autopilot generated plan"),
        )
        .expect("mutate persisted Autopilot generated plan");
    });

    let (report, follow_up_child_dispatches) =
        run_injected_licensed_autopilot_cascade(fixture.temp_path(), repo, &fixture.run_name);

    assert_eq!(follow_up_child_dispatches, 0);
    assert_eq!(report.status, AutopilotRunStatus::Failed, "{report:#?}");
    assert!(!report.success);
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(report.primary_worktree_untouched);
    assert!(!report.auto_merge_performed);
    assert!(report.gate_denials.iter().any(|denial| {
        matches!(
            denial.reason,
            GateDenialReason::ApprovalReview {
                denial: ApprovalReviewDenial::PermissionExpansion
            }
        )
    }));
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, &report.run_id)
        .expect("open refused injected Autopilot artifacts");
    let cascade = serde_json::from_slice::<supervise::SupervisorCascadeOutcome>(
        &reader
            .read(Path::new("follow-up-cascade-report.json"))
            .expect("read refused Autopilot cascade report"),
    )
    .expect("decode refused Autopilot cascade report");
    let queue = cascade.follow_up_queue.expect("refused Autopilot queue");
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn interrupted_autopilot_queue_resumes_through_supervise_without_duplicate_identity() {
    skip_without_containment!();
    let fixture = IsolatedLicensedAutopilot::new("autopilot-cross-entrypoint-resume");
    let repo = &fixture.repo;
    let run_name = fixture.run_name.as_str();
    let outer_run_id = RunId::new(run_name).expect("cross-entrypoint Autopilot run id");
    let supervisor_run_id =
        RunId::new(format!("{run_name}-supervise")).expect("source supervisor run id");
    let outer_plan = fixture
        .temp_path()
        .join(format!("{run_name}-autopilot.json"));
    fs::write(
        &outer_plan,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "task": {
                "title": "Cross-entrypoint licensed cascade",
                "body": "Resume the durable generated dependent through supervise run."
            },
            "assigned_paths": ["README.md"],
            "auto_merge": false
        }))
        .expect("serialize cross-entrypoint Autopilot plan"),
    )
    .expect("write cross-entrypoint Autopilot plan");
    let (supervisor_plan, _declaration, declaration_sha256) = licensed_autopilot_supervisor_plan();
    let retention = secure_autopilot_machine_global_retention(fixture.temp_path(), run_name);
    let source_child_dispatches = Arc::new(AtomicUsize::new(0));
    let follow_up_child_dispatches = Arc::new(AtomicUsize::new(0));
    let mut runner = injected_licensed_autopilot_runner(
        declaration_sha256,
        Arc::clone(&source_child_dispatches),
        Arc::clone(&follow_up_child_dispatches),
    );
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    supervise::set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let head_before = crate::git_repository::open(repo)
        .expect("open cross-entrypoint repository")
        .head()
        .expect("read cross-entrypoint HEAD")
        .target()
        .expect("cross-entrypoint HEAD oid");
    let primary_before = supervise::verified_whole_primary_snapshot_sha256(repo)
        .expect("capture cross-entrypoint primary baseline");

    supervise::set_interrupt_after_follow_up_enqueue();
    let interrupted = run_autopilot_plan_file_with_injected_supervisor_and_runner(
        AutopilotRunOptions {
            repo: repo.clone(),
            plan_file: outer_plan,
            run_id: outer_run_id.clone(),
            codex_bin: Some(PathBuf::from("unused-injected-codex")),
            reviewer_command: None,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            max_child_dispatches: None,
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            cancellation: None,
        },
        None,
        retention.clone(),
        supervisor_plan,
        &mut runner,
    )
    .expect("return failed Autopilot report after injected enqueue interruption");
    assert_eq!(interrupted.status, AutopilotRunStatus::Failed);
    assert!(!interrupted.generated_follow_up_dispatch_performed);
    assert!(interrupted.primary_worktree_untouched);
    assert!(!interrupted.auto_merge_performed);
    assert_eq!(source_child_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(follow_up_child_dispatches.load(Ordering::SeqCst), 0);
    let interrupted_queue = observations
        .borrow()
        .iter()
        .find(|observation| observation.label == "enqueued")
        .cloned()
        .expect("observe durable Autopilot-origin enqueue");
    assert_eq!(interrupted_queue.outer_entrypoint, "autopilot_run");
    assert_eq!(interrupted_queue.outer_command_run_id, run_name);
    assert_eq!(interrupted_queue.item_ids.len(), 1);
    assert!(interrupted_queue.subordinate_run_ids.is_empty());
    assert_eq!(interrupted_queue.pending_count, 1);
    assert_eq!(interrupted_queue.dispatch_started_count, 0);

    let supervisor_plan_file = repo
        .join(".maco/autopilot/runs")
        .join(run_name)
        .join("supervisor-plan.json");
    let resume_cancellation = ProcessCancellation::new();
    let mut resume_runner = |command: &ExternalAgentCommand| runner(command, &resume_cancellation);
    let resumed = supervise::resume_supervisor_plan_file_cascade_with_runner(
        SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: supervisor_plan_file,
            run_id: supervisor_run_id.clone(),
            parent_node: None,
            codex_bin: PathBuf::from("unused-injected-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: true,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(retention),
        },
        &mut resume_runner,
    )
    .expect("resume Autopilot-origin queue through direct supervise");
    supervise::clear_generated_follow_up_queue_observer();

    assert_eq!(resumed.source_report.run_id, supervisor_run_id);
    assert!(resumed.source_report.success, "{resumed:#?}");
    assert!(resumed.follow_up_cascade_success, "{resumed:#?}");
    assert!(resumed.generated_follow_up_dispatch_performed());
    assert_eq!(resumed.follow_up_primary_worktree_untouched, Some(true));
    assert_eq!(source_child_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(follow_up_child_dispatches.load(Ordering::SeqCst), 1);
    let final_queue = resumed
        .follow_up_queue
        .expect("cross-entrypoint final queue summary");
    assert_eq!(
        final_queue.queue_instance_id,
        interrupted_queue.queue_instance_id
    );
    assert_eq!(final_queue.pending_count, 0);
    assert_eq!(final_queue.dispatch_started_count, 0);
    assert_eq!(final_queue.acknowledged_terminal_count, 1);
    assert_eq!(final_queue.authenticated_child_dispatch_started_count, 1);
    let observations = observations.borrow();
    let reopened = observations
        .iter()
        .rfind(|observation| observation.label == "created_or_opened")
        .expect("observe direct supervise queue reopen");
    let started = observations
        .iter()
        .find(|observation| observation.label == "dispatch_started")
        .expect("observe resumed subordinate dispatch start");
    let acknowledged = observations
        .iter()
        .find(|observation| observation.label == "acknowledged_terminal")
        .expect("observe resumed subordinate acknowledgement");
    for observation in [reopened, started, acknowledged] {
        assert_eq!(
            observation.queue_instance_id,
            interrupted_queue.queue_instance_id
        );
        assert_eq!(observation.outer_entrypoint, "autopilot_run");
        assert_eq!(observation.outer_command_run_id, run_name);
        assert_eq!(observation.item_ids, interrupted_queue.item_ids);
    }
    assert_eq!(started.subordinate_run_ids.len(), 1);
    assert_eq!(
        acknowledged.subordinate_run_ids,
        started.subordinate_run_ids
    );
    assert_eq!(
        supervise::verified_whole_primary_snapshot_sha256(repo)
            .expect("capture cross-entrypoint final primary"),
        primary_before
    );
    assert_eq!(
        crate::git_repository::open(repo)
            .expect("reopen cross-entrypoint repository")
            .head()
            .expect("reread cross-entrypoint HEAD")
            .target()
            .expect("reread cross-entrypoint HEAD oid"),
        head_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[test]
fn autopilot_missing_retention_binding_fails_before_any_repository_or_runtime_side_effect() {
    let temp = tempfile::tempdir().expect("tempdir");
    let sentinel = temp.path().join("sentinel");
    fs::write(&sentinel, b"unchanged").expect("write sentinel");
    let safety_hook_called = Rc::new(Cell::new(false));
    let observed = Rc::clone(&safety_hook_called);
    set_after_autopilot_safety_hook(move || observed.set(true));
    let before = fs::read_dir(temp.path())
        .expect("read temp before")
        .map(|entry| entry.expect("temp entry").file_name())
        .collect::<BTreeSet<_>>();

    let error = run_autopilot_plan_file(AutopilotRunOptions {
        repo: temp.path().join("repository-must-not-be-opened"),
        plan_file: temp.path().join("plan-must-not-be-read"),
        run_id: RunId::new("failclosed-no-effects").expect("run id"),
        codex_bin: Some(temp.path().join("worker-must-not-run")),
        reviewer_command: None,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        max_child_dispatches: None,
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        cancellation: None,
    })
    .expect_err("autopilot must require the supervise retention binding");

    let after = fs::read_dir(temp.path())
        .expect("read temp after")
        .map(|entry| entry.expect("temp entry").file_name())
        .collect::<BTreeSet<_>>();
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| {
        slot.borrow_mut().take();
    });
    assert_eq!(before, after);
    assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"unchanged");
    assert!(!safety_hook_called.get());
    assert!(!temp.path().join(".maco").exists());
    assert!(format!("{error:#}").contains("--machine-global-config"));
}

#[cfg(unix)]
#[test]
fn repository_binding_rejects_root_swap_after_safety_preflight() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    let displaced = temp.path().join("repo-displaced");
    let replacement = repo.clone();
    let bindings = RepositoryPathBindings::bind(&repo).expect("bind repository");
    set_after_autopilot_safety_hook(move || {
        fs::rename(&replacement, &displaced).expect("displace repository root");
        fs::create_dir(&replacement).expect("create replacement root");
    });

    let error = verify_after_autopilot_safety(&bindings)
        .expect_err("repository root replacement must fail closed");

    assert!(format!("{error:#}").contains("repository"));
}

#[test]
fn autopilot_rechecks_dirty_primary_immediately_before_supervisor_dispatch() {
    skip_without_containment!();
    use crate::gate_denial::GateDenialReason;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    fs::write(repo.join("README.md"), "baseline\n").expect("write README");
    let repository = crate::git_repository::open(&repo).expect("open repo");
    let mut index = repository.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repository.find_tree(tree_id).expect("find tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repository
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
    drop(tree);
    drop(repository);
    let plan = temp.path().join("plan.json");
    fs::write(
        &plan,
        r#"{
              "version": 1,
              "task": {"title": "TOCTOU", "body": "Refuse drift before dispatch."},
              "assigned_paths": ["README.md"]
            }"#,
    )
    .expect("write plan");
    let primary = repo.clone();
    set_after_autopilot_safety_hook(move || {
        fs::write(primary.join("README.md"), "changed after preflight\n")
            .expect("change primary after first preflight");
    });

    let report = run_autopilot_plan_file_with_retention(
        AutopilotRunOptions {
            repo: repo.clone(),
            plan_file: plan,
            run_id: RunId::new("predispatch-primary-drift").expect("run id"),
            codex_bin: None,
            reviewer_command: None,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            max_child_dispatches: None,
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            cancellation: None,
        },
        Some(MachineGlobalRetentionBinding {
            config: temp.path().join("must-not-open.json"),
            root_id: "runtime".to_string(),
            owner: "maco-autopilot".to_string(),
            correction_correlation_id: "predispatch-primary-drift".to_string(),
        }),
    )
    .expect("finalize typed pre-dispatch refusal");

    assert_eq!(report.status, AutopilotRunStatus::Refused);
    assert!(matches!(
        report.gate_denials.as_slice(),
        [GateDenial {
            reason: GateDenialReason::MergeRemediation {
                blocker: ApplyBlocker::DirtyPrimary
            },
            ..
        }]
    ));
    assert!(!repo.join(".maco/o2").exists());
}

#[test]
fn autopilot_reloads_effective_profile_at_call_site_before_starting_supervisor() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = create_committed_autopilot_repo(temp.path());
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "version": 1,
              "task": {"title": "Profile call site", "body": "Refuse persisted drift."},
              "assigned_paths": ["README.md"]
            }"#,
    )
    .expect("write plan");
    set_autopilot_profile_callsite_hook(|effective| {
        effective.role_models.clear();
    });

    let report = run_autopilot_plan_file_with_profile_and_retention(
        AutopilotRunOptions {
            repo: repo.clone(),
            plan_file: plan_path,
            run_id: RunId::new("effective-profile-callsite").expect("run id"),
            codex_bin: None,
            reviewer_command: None,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            max_child_dispatches: None,
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            cancellation: None,
        },
        Some(nondefault_test_profile()),
        Some(MachineGlobalRetentionBinding {
            config: temp.path().join("must-not-open.json"),
            root_id: "runtime".to_string(),
            owner: "maco-autopilot".to_string(),
            correction_correlation_id: "effective-profile-callsite".to_string(),
        }),
    )
    .expect("finalize requested/effective call-site refusal");

    assert_eq!(report.status, AutopilotRunStatus::Failed);
    assert_eq!(report.attempt_count, 0);
    assert!(report.supervisor.is_none());
    assert_eq!(
        report.profile_binding.configuration_status,
        AutopilotProfileBindingStatus::Mismatch
    );
    assert!(!report.generated_follow_up_dispatch_performed);
    assert!(!repo.join(".maco/o2").exists());
}

#[test]
fn autopilot_plan_input_is_bounded_nofollow_and_json_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");

    let malformed = temp.path().join("malformed.json");
    fs::write(&malformed, "{\"version\": 1,").expect("malformed plan");
    let error = autopilot_plan_from_task_file(&repo, &malformed)
        .expect_err("JSON-looking malformed plan must not become plain text");
    assert!(format!("{error:#}").contains("JSON-looking"));

    let oversized = temp.path().join("oversized.plan");
    File::create(&oversized)
        .expect("oversized file")
        .set_len(AUTOPILOT_PLAN_MAX_BYTES + 1)
        .expect("set oversized length");
    let error = autopilot_plan_from_task_file(&repo, &oversized)
        .expect_err("oversized plan must fail before parsing");
    assert!(format!("{error:#}").contains("bounded read limit"));
    assert!(!repo.join(".maco/autopilot").exists());
}

#[test]
fn public_autopilot_plan_refuses_unsupported_or_malformed_depth_shape() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = create_committed_autopilot_repo(temp.path());
    let plan_path = temp.path().join("plan.json");
    let plan = |shape: &str| {
        format!(
            r#"{{
                  "version": 1,
                  "task": {{"title": "Depth contract", "body": "Keep depth bounded."}},
                  "assigned_paths": ["README.md"]
                  {shape}
                }}"#
        )
    };

    fs::write(&plan_path, plan(", \"max_depth\": 2")).expect("supported plan");
    autopilot_plan_from_task_file(&repo, &plan_path).expect("depth two remains supported");

    fs::write(&plan_path, plan(", \"max_depth\": 3")).expect("depth three plan");
    let error = autopilot_plan_from_task_file(&repo, &plan_path)
        .expect_err("depth three must not be normalized away");
    assert!(format!("{error:#}").contains("supports exactly max_depth 2"));

    fs::write(
        &plan_path,
        plan(
            r#", "max_depth": 2,
                  "assignments": [{
                    "id": "depth-two",
                    "child_assignments": [{"id": "depth-three"}]
                  }]"#,
        ),
    )
    .expect("recursive plan");
    let error = autopilot_plan_from_task_file(&repo, &plan_path)
        .expect_err("recursive assignments must not be normalized away");
    assert!(format!("{error:#}").contains("no recursive child_assignments"));

    fs::write(&plan_path, plan(", \"max_depth\": \"2\"")).expect("malformed plan");
    let error = autopilot_plan_from_task_file(&repo, &plan_path)
        .expect_err("a non-integer max_depth must be invalid");
    assert!(format!("{error:#}").contains("max_depth must be an integer"));
}

#[test]
fn unsupported_depth_shapes_are_typed_preflight_permission_expansions() {
    skip_without_containment!();
    use crate::gate_denial::{
        GateDenialReason, GateDenialRoute, GateRetryability, NextSafeOperation,
    };

    let cases = [
        ("depth-three-refusal", r#""max_depth": 3"#),
        (
            "recursive-depth-refusal",
            r#""max_depth": 2,
                    "assignments": [{
                      "id": "depth-two",
                      "child_assignments": [{"id": "depth-three"}]
                    }]"#,
        ),
    ];
    for (run_id, shape) in cases {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = create_committed_autopilot_repo(temp.path());
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            format!(
                r#"{{
                      "version": 1,
                      "task": {{"title": "Depth refusal", "body": "Do not expand depth."}},
                      "assigned_paths": ["README.md"],
                      {shape}
                    }}"#
            ),
        )
        .expect("write unsupported plan");

        let report = run_autopilot_plan_file_with_retention(
            AutopilotRunOptions {
                repo: repo.clone(),
                plan_file: plan_path,
                run_id: RunId::new(run_id).expect("run id"),
                codex_bin: None,
                reviewer_command: None,
                allow_dirty_primary: false,
                allow_live_run_collision: false,
                max_child_dispatches: None,
                budget_overrides: crate::supervise::RunBudgetLimits::default(),
                budget_max_duration_seconds: None,
                cancellation: None,
            },
            Some(MachineGlobalRetentionBinding {
                config: temp.path().join("must-not-open.json"),
                root_id: "runtime".to_string(),
                owner: "maco-autopilot".to_string(),
                correction_correlation_id: run_id.to_string(),
            }),
        )
        .expect("finalize typed depth refusal");

        assert_eq!(report.status, AutopilotRunStatus::Refused);
        assert!(!report.success);
        assert_eq!(report.attempt_count, 0);
        assert!(report.supervisor.is_none());
        assert!(matches!(
            report.gate_denials.as_slice(),
            [GateDenial {
                reason: GateDenialReason::ApprovalReview {
                    denial: ApprovalReviewDenial::PermissionExpansion
                },
                retryability: GateRetryability::RetryAfterCorrection,
                route: GateDenialRoute::ChildController,
                next_safe_operation: NextSafeOperation::NarrowActionOrChooseAnotherTool,
                ..
            }]
        ));
        assert!(!repo.join(".maco/o2").exists());
    }
}

#[test]
fn autopilot_plan_bounds_attempts_and_defaults_validation_timeout() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    fs::write(repo.join("README.md"), "# Test\n").expect("readme");
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
              "version": 1,
              "task": {"title": "Test", "body": "Test"},
              "assigned_paths": ["README.md"],
              "validation_commands": ["true"],
              "max_repair_attempts": 2
            }"#,
    )
    .expect("plan");
    let plan = autopilot_plan_from_task_file(&repo, &plan_path).expect("bounded plan");
    assert_eq!(
        plan.validation_commands[0].timeout_seconds,
        Some(DEFAULT_CHILD_TIMEOUT_SECONDS)
    );

    fs::write(
        &plan_path,
        r#"{
              "version": 1,
              "task": {"title": "Test", "body": "Test"},
              "assigned_paths": ["README.md"],
              "max_repair_attempts": 3
            }"#,
    )
    .expect("excessive plan");
    let error = autopilot_plan_from_task_file(&repo, &plan_path)
        .expect_err("excessive repair attempts must fail");
    assert!(format!("{error:#}").contains("max_repair_attempts"));
    assert!(!repo.join(".maco/autopilot").exists());
}

#[test]
fn validation_commands_honor_caller_cancellation_between_commands() {
    let cancellation = ProcessCancellation::new();
    cancellation.cancel();
    let mut plan = supervisor_profile_test_plan();
    plan.validation_commands = vec![
        AutopilotValidationCommand {
            name: Some("first".to_string()),
            command: "true".to_string(),
            timeout_seconds: Some(600),
        },
        AutopilotValidationCommand {
            name: Some("second".to_string()),
            command: "true".to_string(),
            timeout_seconds: Some(600),
        },
    ];

    let error = run_validation_commands(Path::new("."), &plan, &cancellation)
        .expect_err("cancelled validation must not start commands");
    let message = format!("{error:#}");
    assert!(
        message.contains("cancelled before command 1"),
        "remaining commands must be skipped without waiting on timeouts: {message}"
    );
}

#[cfg(unix)]
#[test]
fn autopilot_plan_input_refuses_symlink_leaf_and_ancestor() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    let input = temp.path().join("input");
    fs::create_dir_all(&input).expect("input directory");
    fs::write(input.join("task.md"), "Update README\n").expect("task");
    symlink(input.join("task.md"), temp.path().join("task-link.md")).expect("leaf link");
    symlink(&input, temp.path().join("input-link")).expect("ancestor link");

    for path in [
        temp.path().join("task-link.md"),
        temp.path().join("input-link/task.md"),
    ] {
        assert!(autopilot_plan_from_task_file(&repo, path).is_err());
    }
}

#[test]
fn bounded_repository_status_detects_present_deleted_and_untracked_paths() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo, _manager) = create_managed_worktree_fixture(temp.path(), "status-agent");
    assert!(bounded_repository_dirty_paths(&repo)
        .expect("clean status")
        .is_empty());

    fs::create_dir_all(repo.join(".maco/runtime")).expect("runtime dir");
    fs::write(repo.join(".maco/runtime/ignored"), "ignored\n").expect("runtime file");
    fs::write(repo.join("untracked.txt"), "untracked\n").expect("untracked");
    let dirty = bounded_repository_dirty_paths(&repo).expect("untracked status");
    assert_eq!(dirty, vec![PathBuf::from("untracked.txt")]);

    fs::remove_file(repo.join("untracked.txt")).expect("remove untracked");
    fs::hard_link(repo.join("README.md"), repo.join("linked-readme"))
        .expect("tracked-file hard link");
    let dirty = bounded_repository_dirty_paths(&repo).expect("hard-linked status");
    assert_eq!(dirty, vec![PathBuf::from("linked-readme")]);
    fs::remove_file(repo.join("linked-readme")).expect("remove hard link");

    fs::remove_file(repo.join("README.md")).expect("remove tracked");
    let dirty = bounded_repository_dirty_paths(&repo).expect("deleted status");
    assert_eq!(dirty, vec![PathBuf::from("README.md")]);
}

#[cfg(unix)]
#[test]
fn active_artifact_status_uses_nofollow_inventory() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    let run_id = RunId::new("active-inventory").expect("run id");
    let run_dir = repo.join(".maco/autopilot/runs/active-inventory");
    fs::create_dir_all(&run_dir).expect("run dir");
    fs::write(run_dir.join("plan.json"), "{}\n").expect("plan");

    let status = autopilot_status(&repo, run_id.clone()).expect("active status");
    assert!(status.artifacts.plan);
    assert!(!status.artifacts.final_report);

    fs::remove_file(run_dir.join("plan.json")).expect("remove plan");
    let outside = temp.path().join("outside-plan");
    fs::write(&outside, "{}\n").expect("outside plan");
    symlink(&outside, run_dir.join("plan.json")).expect("plan link");
    assert!(autopilot_status(&repo, run_id).is_err());
}

fn create_managed_worktree_fixture(root: &Path, agent_id: &str) -> (PathBuf, WorktreeManager) {
    let repo_path = root.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    let mut index = repo.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    repo.config()
        .expect("repo config")
        .set_str("user.name", "maco test")
        .expect("set user name");
    repo.config()
        .expect("repo config")
        .set_str("user.email", "maco-test@example.invalid")
        .expect("set user email");
    drop(tree);
    drop(repo);
    let manager = WorktreeManager::new(&repo_path);
    manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: agent_id.to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create managed worktree");
    (repo_path, manager)
}

#[cfg(target_os = "linux")]
fn create_prepublication_fixture(
    root: &Path,
    agent_id: &str,
) -> (PathBuf, WorktreeManager, PathBuf) {
    let (repo, manager) = create_managed_worktree_fixture(root, agent_id);
    let record = manager
        .get_managed_verified(agent_id)
        .expect("verified managed worktree");
    fs::write(
        record.path.join("README.md"),
        format!("# Prepared candidate for {agent_id}\n"),
    )
    .expect("edit candidate README");
    (repo, manager, record.path)
}

#[cfg(target_os = "linux")]
struct DeterministicPreparedCandidate {
    metadata: crate::merge::WorktreeMergeMetadata,
    binding: CandidateValidationBinding,
    raw_diff: Vec<u8>,
    snapshot_tree: git2::Oid,
}

#[cfg(target_os = "linux")]
fn create_deterministic_prepublication_fixture(
    root: &Path,
    agent_id: &str,
) -> (PathBuf, WorktreeManager, DeterministicPreparedCandidate) {
    let (repo, manager) = create_managed_worktree_fixture(root, agent_id);
    let record = manager
        .get_managed_verified(agent_id)
        .expect("verified managed worktree");
    fs::write(
        record.path.join("README.md"),
        format!("# Prepared candidate for {agent_id}\n"),
    )
    .expect("edit candidate README");

    let candidate_repo =
        crate::git_repository::open(&record.path).expect("open candidate repository");
    let parent = candidate_repo
        .head()
        .expect("candidate HEAD")
        .peel_to_commit()
        .expect("candidate parent commit");
    let primary_head = parent.id();
    let mut index = candidate_repo.index().expect("open candidate index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage candidate README");
    index.write().expect("write candidate index");
    let snapshot_tree = index.write_tree().expect("write candidate tree");
    let tree = candidate_repo
        .find_tree(snapshot_tree)
        .expect("find candidate tree");
    let signature = git2::Signature::now("maco test", "maco-test@example.invalid")
        .expect("candidate signature");
    let agent_head = candidate_repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "prepared candidate",
            &tree,
            &[&parent],
        )
        .expect("commit prepared candidate");
    drop(tree);
    drop(parent);
    drop(candidate_repo);

    let metadata = crate::merge::WorktreeMergeMetadata {
        agent_id: agent_id.to_string(),
        worktree_path: record.path,
        branch: record.branch,
        primary_repo_root: repo.clone(),
        primary_head: Some(primary_head.to_string()),
        agent_head: Some(agent_head.to_string()),
        merge_base: Some(primary_head.to_string()),
        base_matches_primary: Some(true),
    };
    let raw_diff =
        format!("diff --git a/README.md b/README.md\n+Prepared candidate for {agent_id}\n")
            .into_bytes();
    let binding = crate::merge::candidate_validation_binding(&metadata, &raw_diff)
        .expect("deterministic candidate binding");
    (
        repo,
        manager,
        DeterministicPreparedCandidate {
            metadata,
            binding,
            raw_diff,
            snapshot_tree,
        },
    )
}

#[cfg(target_os = "linux")]
fn passed_merge_safety_check() -> crate::merge::SafetyCheck {
    crate::merge::SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn deterministic_prepared_report(
    candidate: &DeterministicPreparedCandidate,
    forge: ForgeKind,
) -> PrPublicationReport {
    let changed_paths = vec![PathBuf::from("README.md")];
    let diff_summary = crate::merge::OutputSummary {
        text: String::from_utf8_lossy(&candidate.raw_diff).into_owned(),
        truncated: false,
    };
    let preview = crate::merge::MergeApplyPreview {
        review_intent: crate::merge::MergeApplyReviewIntent::default(),
        candidate: crate::merge::MergeCandidate {
            metadata: candidate.metadata.clone(),
            claimed_paths: changed_paths.clone(),
            changed_paths: changed_paths.clone(),
            changes: vec![crate::merge::ChangedPath {
                path: PathBuf::from("README.md"),
                kind: crate::merge::ChangeKind::Modified,
            }],
            unclaimed_changed_paths: Vec::new(),
            diff: crate::merge::DiffOutput {
                summary: diff_summary.clone(),
                full: Some(diff_summary.text.clone()),
            },
            validations: Vec::new(),
            validation_binding: candidate.binding.clone(),
            validation_evidence: ValidationEvidenceBundle::default(),
            raw_diff: candidate.raw_diff.clone(),
            snapshot_tree: candidate.snapshot_tree,
        },
        safety: crate::merge::MergeApplySafety {
            primary_state_unchanged: passed_merge_safety_check(),
            dirty_primary: passed_merge_safety_check(),
            stale_base: passed_merge_safety_check(),
            apply_check: passed_merge_safety_check(),
            unclaimed_edits: passed_merge_safety_check(),
            validation: passed_merge_safety_check(),
            validation_evidence: crate::merge::ValidationEvidenceCheck {
                status: SafetyCheckStatus::Passed,
                binding_status: crate::merge::ValidationBindingStatus::NotRequired,
                message: None,
                paths: Vec::new(),
            },
            megafile: passed_merge_safety_check(),
            megafile_warnings: Vec::new(),
            megafile_decomposition_target: None,
            megafile_decomposition_evidence: None,
            megafile_blocking: false,
            validation_required: false,
            candidate_validation_commands: Vec::new(),
            force_options: crate::merge::MergeForceOptions::default(),
            apply_mode: crate::merge::ApplyMode::Direct,
            semantic_conflicts: crate::merge_semantic::SemanticConflictClassification::no_conflict(
            ),
            readiness: crate::merge::ApplyReadiness {
                status: ApplyReadinessStatus::Safe,
                blockers: Vec::new(),
                forced: Vec::new(),
                details: Vec::new(),
            },
        },
    };
    let agent_head = candidate
        .binding
        .agent_head
        .clone()
        .expect("deterministic candidate HEAD");
    PrPublicationReport {
        status: PrPublicationStatus::Preview,
        agent_id: candidate.metadata.agent_id.clone(),
        branch: candidate.metadata.branch.clone(),
        base: "main".to_string(),
        base_head: candidate.binding.primary_head.clone(),
        remote: None,
        forge,
        draft: true,
        title: "Prepared candidate".to_string(),
        body_summary: crate::merge::OutputSummary {
            text: "Prepared candidate".to_string(),
            truncated: false,
        },
        changed_paths,
        validation_status: SafetyCheckStatus::Passed,
        validation_required: false,
        readiness: ApplyReadinessStatus::Safe,
        blockers: Vec::new(),
        commit_id: Some(agent_head.clone()),
        head_id: Some(agent_head),
        pr_url: None,
        pushed: false,
        created: false,
        publication_receipt: None,
        next_action: "validate the deterministic candidate".to_string(),
        preview,
    }
}

#[cfg(target_os = "linux")]
fn deterministic_fake_publication_report(
    candidate: &DeterministicPreparedCandidate,
) -> PrPublicationReport {
    let mut report = deterministic_prepared_report(candidate, ForgeKind::Fake);
    report.status = PrPublicationStatus::Published;
    report.created = true;
    report.pr_url = Some(format!(
        "https://example.invalid/fake/{}",
        candidate.metadata.agent_id
    ));
    report.next_action = "review the deterministic fake publication".to_string();
    report
}

#[cfg(target_os = "linux")]
fn deterministic_candidate_is_clean(_: &Path) -> Result<bool> {
    Ok(true)
}

#[cfg(target_os = "linux")]
fn prepublication_test_plan(
    forge_mode: AutopilotForgeMode,
    reviewer_mode: ReviewerMode,
) -> AutopilotPlan {
    AutopilotPlan {
        version: AUTOPILOT_SCHEMA_VERSION,
        task: AutopilotTask {
            title: "Strict pre-publication test".to_string(),
            body: "Exercise the exact prepared candidate gate.".to_string(),
        },
        assigned_paths: vec![PathBuf::from("README.md")],
        path_proposal: planning::TaskPathProposalDiagnostics::default(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        validation_commands: Vec::new(),
        max_repair_attempts: 1,
        forge_mode,
        reviewer: ReviewerConfig {
            mode: reviewer_mode,
            blocking_attempts: 0,
            finding: None,
            program: (reviewer_mode == ReviewerMode::ExternalCommand)
                .then(|| PathBuf::from("/bin/true")),
            args: Vec::new(),
            command: None,
            timeout_seconds: None,
        },
        publish_mode: AutopilotPublishMode::DraftOnly,
        auto_merge: false,
        external_source: None,
    }
}

#[cfg(target_os = "linux")]
fn passed_prepublication_validation() -> Vec<ValidationReport> {
    vec![ValidationReport {
        name: "prepared-unit".to_string(),
        status: ValidationStatus::Passed,
        message: None,
        paths: vec![PathBuf::from("README.md")],
    }]
}

#[cfg(target_os = "linux")]
fn injected_external_review(options: ReviewPrOptions, status: ReviewReportStatus) -> ReviewReport {
    let blocked = status == ReviewReportStatus::Blocked;
    let findings = if blocked {
        vec![review::ReviewFinding {
            severity: "error".to_string(),
            path: Some(PathBuf::from("README.md")),
            summary: "injected blocking finding".to_string(),
            suggested_fix: "repair before publication".to_string(),
            blocking: true,
        }]
    } else {
        Vec::new()
    };
    ReviewReport {
        version: REVIEW_REPORT_SCHEMA_VERSION,
        status,
        success: status == ReviewReportStatus::Passed,
        target: options.target,
        reviewer: review::ReviewerIdentity {
            mode: ReviewerMode::ExternalCommand,
            reviewer_id: format!("{EXTERNAL_REVIEWER_ID_PREFIX}{}", "b".repeat(32)),
            model: EXTERNAL_REVIEWER_MODEL.to_string(),
        },
        attempt: options.attempt,
        request_binding: "a".repeat(REVIEW_REQUEST_BINDING_HEX_LEN),
        blocking_finding_count: findings.len(),
        findings,
        changed_paths: options.changed_paths,
        diff_source: "sanitized_merge_candidate_summary".to_string(),
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: None,
        next_action: "continue only after the strict gate".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn injected_external_publication_review(
    options: ReviewPrOptions,
    status: ReviewReportStatus,
) -> review::PublicationReviewResult {
    let report = injected_external_review(options.clone(), status);
    review::PublicationReviewResult::issue_for_test(options, report, true)
}

#[cfg(target_os = "linux")]
fn publication_transactions_path(repo: &Path) -> PathBuf {
    repo.join(".git/maco/state/publication-transactions")
}

#[cfg(target_os = "linux")]
fn assert_no_remote_publication_state(repo: &Path) {
    assert!(!publication_transactions_path(repo).exists());
    let repository = crate::git_repository::open(repo).expect("open primary repository");
    let mut references = repository
        .references_glob("refs/remotes/*")
        .expect("list remote refs");
    assert!(references.next().is_none(), "unexpected remote reference");
}

#[test]
fn validate_autopilot_plan_refuses_empty_path_proposal() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    git2::Repository::init(repo).expect("init repo");
    fs::create_dir_all(repo.join("src")).expect("create src");
    fs::write(repo.join("src/lib.rs"), "pub fn unrelated() {}\n").expect("write src");

    let result = validate_autopilot_plan(
        repo,
        AutopilotPlan {
            version: AUTOPILOT_SCHEMA_VERSION,
            task: AutopilotTask {
                title: "Unmatched task".to_string(),
                body: "No concrete path or symbol appears here.".to_string(),
            },
            assigned_paths: Vec::new(),
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            validation_commands: Vec::new(),
            max_repair_attempts: default_max_repair_attempts(),
            forge_mode: AutopilotForgeMode::Fake,
            reviewer: ReviewerConfig::default(),
            publish_mode: AutopilotPublishMode::DraftOnly,
            auto_merge: false,
            external_source: None,
        },
    );

    let error = result.expect_err("empty proposal must be refused");
    assert!(error.to_string().contains("assigned paths are empty"));
}

#[test]
fn real_forges_require_external_reviewer_authority() {
    let direct = ReviewerConfig {
        mode: ReviewerMode::ExternalCommand,
        program: Some(PathBuf::from("reviewer")),
        ..ReviewerConfig::default()
    };
    assert!(reviewer_config_may_authorize_publication(
        ForgeKind::Git,
        &direct
    ));
    assert!(reviewer_config_may_authorize_publication(
        ForgeKind::Github,
        &direct
    ));

    let legacy = ReviewerConfig {
        mode: ReviewerMode::ExternalCommand,
        command: Some("reviewer --legacy-shell".to_string()),
        ..ReviewerConfig::default()
    };
    assert!(!reviewer_config_may_authorize_publication(
        ForgeKind::Git,
        &legacy
    ));
    assert!(!reviewer_config_may_authorize_publication(
        ForgeKind::Github,
        &ReviewerConfig::default()
    ));
    assert!(reviewer_config_may_authorize_publication(
        ForgeKind::Fake,
        &ReviewerConfig::default()
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn retry_prompt_excludes_external_review_text_diagnostics_and_paths() {
    let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    let options = ReviewPrOptions {
        repo: PathBuf::from("/private/review-worktree"),
        target: "prepared-candidate:agent@1111111111111111111111111111111111111111".to_string(),
        reviewer: plan.reviewer.clone(),
        attempt: 1,
        changed_paths: vec![PathBuf::from("private/external-path.rs")],
        diff_summary: Some("external diff summary sentinel".to_string()),
    };
    let mut report = injected_external_review(options, ReviewReportStatus::Blocked);
    report.findings[0].summary = "external summary sentinel".to_string();
    report.findings[0].suggested_fix = "external suggested fix sentinel".to_string();
    report.findings[0].path = Some(PathBuf::from("private/external-path.rs"));
    report.next_action = "external next action sentinel".to_string();
    report.diagnostics = Some(review::ReviewCommandDiagnostics {
        timed_out: false,
        timeout_seconds: Some(1),
        exit_code: Some(1),
        stdout: review::ReviewOutputSummary {
            text: "external stdout diagnostic sentinel".to_string(),
            truncated: false,
        },
        stderr: review::ReviewOutputSummary {
            text: "external stderr diagnostic sentinel".to_string(),
            truncated: false,
        },
        process_error: Some("external process diagnostic sentinel".to_string()),
    });
    let outcome = stopped_prepublication(
        "review_blocked",
        review_repair_reason(&report),
        true,
        AutopilotValidationSummary {
            status: AutopilotValidationStatus::Passed,
            reports: passed_prepublication_validation(),
        },
        Some(report),
        None,
        None,
        None,
    );

    let prompt = supervisor_task(&plan, 2, &[RepairPromptContext::from_outcome(&outcome)]);

    assert!(prompt.contains("reason_code=review_blocked"));
    assert!(prompt.contains("blocking_findings=1"));
    assert!(prompt.contains("severity_counts=critical:0,error:1,warning:0,info:0"));
    for untrusted in [
        "external summary sentinel",
        "external suggested fix sentinel",
        "external next action sentinel",
        "external stdout diagnostic sentinel",
        "external stderr diagnostic sentinel",
        "external process diagnostic sentinel",
        "private/external-path.rs",
        "external diff summary sentinel",
    ] {
        assert!(!prompt.contains(untrusted), "prompt leaked {untrusted}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn publication_authority_requires_opaque_exact_review_receipt() {
    let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    let options = ReviewPrOptions {
        repo: PathBuf::from("/bound/review-worktree"),
        target: "prepared-candidate:agent@1111111111111111111111111111111111111111".to_string(),
        reviewer: plan.reviewer,
        attempt: 1,
        changed_paths: vec![PathBuf::from("README.md")],
        diff_summary: Some("bound summary".to_string()),
    };
    let report = injected_external_review(options.clone(), ReviewReportStatus::Passed);
    let syntactic_only =
        review::PublicationReviewResult::issue_for_test(options.clone(), report.clone(), false);
    assert!(!syntactic_only.has_exact_external_authority(&options));

    let exact = review::PublicationReviewResult::issue_for_test(options.clone(), report, true);
    assert!(exact.has_exact_external_authority(&options));
    let mut different_args = options;
    different_args.reviewer.args.push("changed".to_string());
    assert!(!exact.has_exact_external_authority(&different_args));
}

#[test]
fn publish_requested_records_failed_real_attempts_but_not_fake_simulation() {
    assert!(publish_requested_for_audit(
        true,
        AutopilotForgeMode::Github,
        true
    ));
    assert!(!publish_requested_for_audit(
        true,
        AutopilotForgeMode::Github,
        false
    ));
    assert!(!publish_requested_for_audit(
        true,
        AutopilotForgeMode::Fake,
        true
    ));
    assert!(!publish_requested_for_audit(
        false,
        AutopilotForgeMode::Git,
        true
    ));
}

#[test]
fn autopilot_message_sanitization_redacts_paths_secrets_and_bounds_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("private-repo");
    Repository::init(&repo).expect("init repository");
    let secret = "autopilot-private-secret";
    let message = format!(
        "repo={}\nAPI_TOKEN={secret}\n{}\0",
        repo.display(),
        "x".repeat(AUTOPILOT_MESSAGE_LIMIT_CHARS * 2)
    );

    let sanitized = sanitize_text(&repo, &message);

    assert!(!sanitized.contains(&repo.display().to_string()));
    assert!(!sanitized.contains(secret));
    assert!(!sanitized.contains('\0'));
    assert!(sanitized.contains("<redacted:"));
    assert!(sanitized.ends_with("…<truncated>"));
    assert!(
        sanitized.chars().count() <= AUTOPILOT_MESSAGE_LIMIT_CHARS + "…<truncated>".chars().count()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn strict_prepublication_orders_prepare_validate_review_publish_under_one_lease() {
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "order-agent";
    let (repo, manager, candidate) =
        create_deterministic_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::ExternalCommand);
    let trace = RefCell::new(Vec::new());
    let publish_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options: PrPublicationOptions| {
            trace.borrow_mut().push("prepare");
            Ok(deterministic_prepared_report(&candidate, options.forge))
        },
        validate: |_| {
            trace.borrow_mut().push("validate");
            Ok(passed_prepublication_validation())
        },
        review: |options| {
            trace.borrow_mut().push("review");
            Ok(injected_external_publication_review(
                options,
                ReviewReportStatus::Passed,
            ))
        },
        publish: |_, _| {
            trace.borrow_mut().push("publish");
            publish_calls.set(publish_calls.get() + 1);
            Ok(deterministic_fake_publication_report(&candidate))
        },
        candidate_clean: deterministic_candidate_is_clean,
    };

    let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

    assert_eq!(
        trace.into_inner(),
        vec!["prepare", "validate", "prepare", "review", "prepare", "publish", "prepare"]
    );
    assert_eq!(publish_calls.get(), 1);
    assert_eq!(outcome.disposition, PrepublicationDisposition::Published);
    assert!(outcome.publication_attempted);
    assert!(outcome.publication_effect_observed);
    assert!(outcome
        .reviewed_candidate
        .as_ref()
        .is_some_and(|reviewed| reviewed.authoritative));
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn real_publication_rejects_fake_blocking_and_failed_review_before_publish() {
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "review-gate-agent";
    let (repo, manager, candidate) =
        create_deterministic_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let review_calls = Cell::new(0usize);
    let publish_calls = Cell::new(0usize);
    let prepare_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options: PrPublicationOptions| {
            prepare_calls.set(prepare_calls.get() + 1);
            Ok(deterministic_prepared_report(&candidate, options.forge))
        },
        validate: |_| Ok(passed_prepublication_validation()),
        review: |options: ReviewPrOptions| {
            review_calls.set(review_calls.get() + 1);
            let status = match options.reviewer.args.first().map(String::as_str) {
                Some("blocked") => ReviewReportStatus::Blocked,
                Some("failed") => ReviewReportStatus::Failed,
                _ => ReviewReportStatus::Passed,
            };
            Ok(injected_external_publication_review(options, status))
        },
        publish: |_, _| {
            publish_calls.set(publish_calls.get() + 1);
            bail!("publish must not be called for rejected review")
        },
        candidate_clean: deterministic_candidate_is_clean,
    };

    let fake_plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::Fake);
    let fake = run_prepublication_attempt(&repo, agent_id, 1, &fake_plan, &lease, &mut hooks);
    assert_eq!(fake.reason, "reviewer_not_authoritative");
    assert!(!fake.publication_attempted);
    assert_eq!(review_calls.get(), 0);

    let mut blocked_plan =
        prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    blocked_plan.reviewer.args = vec!["blocked".to_string()];
    let blocked = run_prepublication_attempt(&repo, agent_id, 1, &blocked_plan, &lease, &mut hooks);
    assert_eq!(blocked.reason, "review_blocked");
    assert!(!blocked.publication_attempted);

    let mut failed_plan = blocked_plan;
    failed_plan.reviewer.args = vec!["failed".to_string()];
    let failed = run_prepublication_attempt(&repo, agent_id, 1, &failed_plan, &lease, &mut hooks);
    assert_eq!(failed.reason, "review_failed");
    assert!(!failed.publication_attempted);
    assert_eq!(review_calls.get(), 2);
    assert_eq!(publish_calls.get(), 0);
    assert_eq!(prepare_calls.get(), 6);
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn empty_validation_refuses_real_publication_before_review_or_publish() {
    skip_without_containment!();
    let _fixture_guard = lock_prepublication_fixture_test();
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "empty-validation-agent";
    let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    let review_calls = Cell::new(0usize);
    let publish_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
        validate: |_| Ok(Vec::new()),
        review: |options| {
            review_calls.set(review_calls.get() + 1);
            Ok(injected_external_publication_review(
                options,
                ReviewReportStatus::Passed,
            ))
        },
        publish: |_, _| {
            publish_calls.set(publish_calls.get() + 1);
            bail!("empty validation must stop before publication")
        },
        candidate_clean: repository_worktree_is_clean,
    };

    let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

    assert_eq!(outcome.reason, "validation_evidence_invalid");
    assert!(!outcome.publication_attempted);
    assert_eq!(review_calls.get(), 0);
    assert_eq!(publish_calls.get(), 0);
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn review_mutation_changes_binding_and_prevents_publication() {
    skip_without_containment!();
    let _fixture_guard = lock_prepublication_fixture_test();
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "review-mutation-agent";
    let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    let publish_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
        validate: |_| Ok(passed_prepublication_validation()),
        review: |options: ReviewPrOptions| {
            fs::write(
                options.repo.join("README.md"),
                "# Mutated during independent review\n",
            )
            .expect("inject review mutation");
            Ok(injected_external_publication_review(
                options,
                ReviewReportStatus::Passed,
            ))
        },
        publish: |_, _| {
            publish_calls.set(publish_calls.get() + 1);
            bail!("mutated review candidate must not publish")
        },
        candidate_clean: repository_worktree_is_clean,
    };

    let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

    assert_eq!(outcome.reason, "candidate_binding_mismatch");
    assert!(!outcome.publication_attempted);
    assert_eq!(publish_calls.get(), 0);
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn fake_forge_with_fake_reviewer_is_local_and_non_authoritative() {
    skip_without_containment!();
    let _fixture_guard = lock_prepublication_fixture_test();
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "fake-local-agent";
    let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::Fake);
    let publish_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
        validate: |_| Ok(passed_prepublication_validation()),
        review: review::review_pr_for_publication,
        publish: |options, evidence| {
            publish_calls.set(publish_calls.get() + 1);
            publication::publish_prepared_pr_with_write_lease(options, &evidence, &lease)
        },
        candidate_clean: repository_worktree_is_clean,
    };

    let outcome = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);

    assert_eq!(outcome.disposition, PrepublicationDisposition::Published);
    assert_eq!(publish_calls.get(), 1);
    assert!(outcome
        .reviewed_candidate
        .as_ref()
        .is_some_and(|reviewed| !reviewed.authoritative));
    assert_eq!(
        outcome.publication.as_ref().map(|report| report.forge),
        Some(ForgeKind::Fake)
    );
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn prepublication_retry_reuses_prepared_commit_without_duplicate_effect() {
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "retry-agent";
    let (repo, manager, candidate) =
        create_deterministic_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let mut plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::Fake);
    plan.reviewer.blocking_attempts = 1;
    let publish_calls = Cell::new(0usize);
    let prepare_calls = Cell::new(0usize);
    let mut hooks = PrepublicationHooks {
        prepare: |options: PrPublicationOptions| {
            prepare_calls.set(prepare_calls.get() + 1);
            Ok(deterministic_prepared_report(&candidate, options.forge))
        },
        validate: |_| Ok(passed_prepublication_validation()),
        review: review::review_pr_for_publication,
        publish: |_, _| {
            publish_calls.set(publish_calls.get() + 1);
            Ok(deterministic_fake_publication_report(&candidate))
        },
        candidate_clean: deterministic_candidate_is_clean,
    };

    let first = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);
    assert_eq!(first.reason, "review_blocked");
    assert!(!first.publication_attempted);
    assert_eq!(publish_calls.get(), 0);

    let second = run_prepublication_attempt(&repo, agent_id, 2, &plan, &lease, &mut hooks);
    assert_eq!(second.disposition, PrepublicationDisposition::Published);
    assert_eq!(publish_calls.get(), 1);
    assert_eq!(prepare_calls.get(), 6);
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn publication_hook_report_forge_and_base_mismatch_are_nonretryable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "hook-mismatch-agent";
    let (repo, manager, candidate) =
        create_deterministic_prepublication_fixture(temp.path(), agent_id);
    let lease =
        acquire_autopilot_worktree_write_lease(&manager, agent_id).expect("autopilot write lease");
    let plan = prepublication_test_plan(AutopilotForgeMode::Git, ReviewerMode::ExternalCommand);
    let publish_calls = Cell::new(0usize);
    let prepare_calls = Cell::new(0usize);
    let return_base_mismatch = Cell::new(false);
    let mut hooks = PrepublicationHooks {
        prepare: |options: PrPublicationOptions| {
            prepare_calls.set(prepare_calls.get() + 1);
            Ok(deterministic_prepared_report(&candidate, options.forge))
        },
        validate: |_| Ok(passed_prepublication_validation()),
        review: |options| {
            Ok(injected_external_publication_review(
                options,
                ReviewReportStatus::Passed,
            ))
        },
        publish: |_: PrPublicationOptions, _: BoundValidationEvidenceBundle| {
            publish_calls.set(publish_calls.get() + 1);
            let mut report = deterministic_fake_publication_report(&candidate);
            if return_base_mismatch.get() {
                let expected_head = candidate
                    .binding
                    .agent_head
                    .clone()
                    .context("bound evidence HEAD")?;
                report.forge = ForgeKind::Git;
                report.pushed = true;
                report.created = false;
                report.pr_url = None;
                report.publication_receipt = Some(publication::PrPublicationReceipt {
                    version: 1,
                    transaction_id: "injected-receipt".to_string(),
                    sequence: 1,
                    phase: publication::PublicationTransactionPhase::Completed,
                    expected_oid: expected_head.clone(),
                    expected_base_oid: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
                    remote_ref: "refs/heads/injected".to_string(),
                    github_repository: None,
                    push_observed_oid: Some(expected_head),
                    pr_url: None,
                    pr_head_oid: None,
                    pr_base: None,
                    pr_state: None,
                    pr_is_draft: None,
                    create_attempted: false,
                    created_by_transaction: false,
                    observed_existing_pr: false,
                    last_error: None,
                });
            }
            Ok(report)
        },
        candidate_clean: deterministic_candidate_is_clean,
    };

    let wrong_forge = run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks);
    assert_eq!(wrong_forge.reason, "publication_receipt_invalid");
    assert!(wrong_forge.publication_attempted);
    assert!(!wrong_forge.retryable);

    return_base_mismatch.set(true);
    let wrong_base = run_prepublication_attempt(&repo, agent_id, 2, &plan, &lease, &mut hooks);
    assert_eq!(wrong_base.reason, "publication_receipt_invalid");
    assert!(wrong_base.publication_attempted);
    assert!(wrong_base.publication_effect_observed);
    assert!(!wrong_base.retryable);
    assert_eq!(publish_calls.get(), 2);
    assert_eq!(prepare_calls.get(), 6);
    assert_no_remote_publication_state(&repo);
}

#[cfg(target_os = "linux")]
#[test]
fn write_lease_excludes_competing_access_through_review_and_releases_on_error() {
    skip_without_containment!();
    let _fixture_guard = lock_prepublication_fixture_test();
    let temp = tempfile::tempdir().expect("tempdir");
    let agent_id = "review-lease-agent";
    let (repo, manager, _) = create_prepublication_fixture(temp.path(), agent_id);
    let plan = prepublication_test_plan(AutopilotForgeMode::Fake, ReviewerMode::ExternalCommand);
    let publish_calls = Cell::new(0usize);
    let outcome = {
        let lease = acquire_autopilot_worktree_write_lease(&manager, agent_id)
            .expect("autopilot write lease");
        let mut hooks = PrepublicationHooks {
            prepare: |options| publication::prepare_pr_candidate_with_write_lease(options, &lease),
            validate: |_| Ok(passed_prepublication_validation()),
            review: |_: ReviewPrOptions| {
                manager
                    .acquire_read_execution_lease(agent_id)
                    .expect_err("review retains writer against readers");
                manager
                    .acquire_write_execution_lease(agent_id)
                    .expect_err("review retains writer against writers");
                manager
                    .remove(agent_id, true, false)
                    .expect_err("review retains writer against removal");
                bail!("injected independent review failure")
            },
            publish: |_, _| {
                publish_calls.set(publish_calls.get() + 1);
                bail!("review error must stop before publication")
            },
            candidate_clean: repository_worktree_is_clean,
        };
        run_prepublication_attempt(&repo, agent_id, 1, &plan, &lease, &mut hooks)
    };

    assert_eq!(outcome.reason, "review_execution_failed");
    assert!(!outcome.publication_attempted);
    assert_eq!(publish_calls.get(), 0);
    manager
        .remove(agent_id, true, false)
        .expect("error scope releases the retained write lease");
}

#[test]
fn injected_autopilot_lease_barrier_blocks_removal_until_quiescence() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (_repo, manager) = create_managed_worktree_fixture(temp.path(), "barrier-agent");
    let lease = acquire_autopilot_worktree_write_lease(&manager, "barrier-agent")
        .expect("acquire autopilot write lease");
    let removal_error = manager
        .remove("barrier-agent", true, false)
        .expect_err("active autopilot write lease must exclude removal");
    assert!(removal_error
        .to_string()
        .contains("active cooperative execution lease"));
    let second_writer = acquire_autopilot_worktree_write_lease(&manager, "barrier-agent")
        .expect_err("active autopilot writer must exclude another writer");
    let second_writer = format!("{second_writer:#}");
    assert!(second_writer.contains("exclusive") && second_writer.contains("lease"));

    drop(lease);
    manager
        .remove("barrier-agent", true, false)
        .expect("removal succeeds after final quiescence");
}

#[test]
fn injected_autopilot_error_path_releases_write_lease() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (_repo, manager) = create_managed_worktree_fixture(temp.path(), "error-agent");
    let injected_error = (|| -> Result<()> {
        let _lease = acquire_autopilot_worktree_write_lease(&manager, "error-agent")?;
        bail!("injected post-acquisition failure")
    })();
    assert!(injected_error
        .expect_err("injected failure must escape")
        .to_string()
        .contains("injected post-acquisition failure"));
    manager
        .remove("error-agent", true, false)
        .expect("error return drops autopilot write lease");
}
