//! Vibe admission tests.
//!
//! Every test builds its assignment from minimal JSON so the assertions stay
//! independent of the repository sandbox fixtures. No environment variables are
//! mutated and no live Vibe process or fake provider is started.

use std::collections::BTreeMap;

use clap::ValueEnum;
use serde_json::{json, Value};

use super::vibe_worker::validate_assignment;
use super::{
    AgentRole, AssignmentPhase, OrchestratorAssignment, RoleCategory, RoleModelSelection,
    RuntimeModelCatalog, SupervisorPlan, SupervisorRuntime, UnavailableModelFallback,
};

/// Minimal direct execution-phase non-delegating terminal Worker assignment.
fn vibe_worker_assignment() -> OrchestratorAssignment {
    serde_json::from_value(json!({
        "id": "vibe-worker",
        "phase": "execution",
        "role": "worker",
        "role_category": "non_delegating_terminal_worker",
        "runtime": "vibe",
        "assigned_paths": ["README.md"],
    }))
    .expect("minimal Vibe worker assignment must deserialize")
}

fn assignment_with(overrides: Value) -> OrchestratorAssignment {
    let mut value = json!({
        "id": "vibe-worker",
        "phase": "execution",
        "role": "worker",
        "role_category": "non_delegating_terminal_worker",
        "runtime": "vibe",
        "assigned_paths": ["README.md"],
    });
    let object = value
        .as_object_mut()
        .expect("assignment fixture is a JSON object");
    for (key, replacement) in overrides.as_object().expect("overrides are a JSON object") {
        object.insert(key.clone(), replacement.clone());
    }
    serde_json::from_value(value).expect("overridden assignment must deserialize")
}

/// A nested worker assignment shaped like the existing plan fixtures.
fn nested_worker_assignment() -> Value {
    json!({
        "id": "vibe-nested-worker",
        "role": "worker",
        "role_category": "non_delegating_terminal_worker",
        "assigned_paths": ["README.md"],
    })
}

fn plan_with(assignments: Vec<OrchestratorAssignment>) -> SupervisorPlan {
    let mut plan: SupervisorPlan = serde_json::from_value(json!({
        "task": "vibe admission",
        "assignments": [],
    }))
    .expect("minimal plan must deserialize");
    plan.assignments = assignments;
    plan
}

#[test]
fn vibe_worker_guidance_launch_limits() {
    let template = crate::runtime_adapter::vibe::immutable_argument_template();
    for (flag, value) in [
        ("--max-turns", "200"),
        ("--max-tokens", "10000000"),
        ("--time-limit", "3600"),
    ] {
        let index = template.iter().position(|arg| arg == flag).unwrap();
        assert_eq!(template[index + 1], value);
        assert_eq!(template.iter().filter(|arg| *arg == flag).count(), 1);
    }
}

#[test]
fn vibe_runtime_is_a_cli_value_enum_and_serde_runtime() {
    assert_eq!(
        SupervisorRuntime::from_str("vibe", true).expect("vibe is a CLI runtime value"),
        SupervisorRuntime::Vibe
    );
    assert_eq!(
        SupervisorRuntime::Vibe
            .to_possible_value()
            .unwrap()
            .get_name(),
        "vibe"
    );
    let parsed: SupervisorRuntime =
        serde_json::from_value(json!("vibe")).expect("vibe is a serde runtime value");
    assert_eq!(parsed, SupervisorRuntime::Vibe);
    assert_eq!(
        serde_json::to_value(SupervisorRuntime::Vibe).unwrap(),
        json!("vibe")
    );
    assert_eq!(SupervisorRuntime::Vibe.as_str(), "vibe");
}

#[test]
fn vibe_worker_admission_accepts_the_exact_direct_terminal_worker() {
    let assignment = vibe_worker_assignment();
    assert_eq!(assignment.phase, AssignmentPhase::Execution);
    assert_eq!(assignment.role, AgentRole::Worker);
    assert_eq!(
        assignment.effective_role_category(),
        RoleCategory::NonDelegatingTerminalWorker
    );
    assert!(assignment.worker_assignments.is_empty());
    validate_assignment(&assignment, SupervisorRuntime::Vibe)
        .expect("the exact direct terminal Worker shape is admitted for Vibe");
}

#[test]
fn vibe_worker_admission_is_a_noop_for_other_runtimes() {
    let assignment = assignment_with(json!({ "role": "child_orchestrator" }));
    for runtime in [
        SupervisorRuntime::Codex,
        SupervisorRuntime::Fake,
        SupervisorRuntime::Grok,
        SupervisorRuntime::Cursor,
        SupervisorRuntime::ClaudeCode,
        SupervisorRuntime::GeminiCli,
        SupervisorRuntime::DeepSeek,
    ] {
        validate_assignment(&assignment, runtime)
            .expect("non-Vibe runtimes keep their own admission");
    }
}

#[test]
fn vibe_worker_admission_refuses_planning_phase() {
    let assignment = assignment_with(json!({ "phase": "planning" }));
    let error = validate_assignment(&assignment, SupervisorRuntime::Vibe)
        .expect_err("planning-phase Vibe must be refused");
    let message = error.to_string();
    assert!(message.contains("Vibe"), "{message}");
    assert!(message.contains("execution"), "{message}");
    assert!(
        message.contains("non-delegating terminal Worker"),
        "{message}"
    );
}

#[test]
fn vibe_worker_admission_refuses_every_other_role() {
    for role in [
        "supervisor",
        "child_orchestrator",
        "researcher",
        "gate_classifier",
        "auditor",
    ] {
        let assignment = assignment_with(json!({ "role": role, "role_category": null }));
        let error = validate_assignment(&assignment, SupervisorRuntime::Vibe)
            .expect_err("a non-Worker Vibe role must be refused");
        assert!(
            error.to_string().contains("non-delegating terminal Worker"),
            "role {role} refusal must name the admitted shape: {error}"
        );
    }
}

#[test]
fn vibe_worker_admission_refuses_every_other_category() {
    for category in [
        "delegating_coordinator",
        "read_only_researcher",
        "read_only_review_auditor",
    ] {
        let assignment = assignment_with(json!({ "role_category": category }));
        let error = validate_assignment(&assignment, SupervisorRuntime::Vibe)
            .expect_err("a non-terminal-Worker Vibe category must be refused");
        assert!(
            error.to_string().contains("non-delegating terminal Worker"),
            "category {category} refusal must name the admitted shape: {error}"
        );
    }
}

#[test]
fn vibe_worker_admission_refuses_nested_worker_assignments() {
    let assignment = assignment_with(json!({
        "role": "child_orchestrator",
        "role_category": "delegating_coordinator",
        "worker_assignments": [nested_worker_assignment()],
    }));
    assert_eq!(assignment.worker_assignments.len(), 1);
    let error = validate_assignment(&assignment, SupervisorRuntime::Vibe)
        .expect_err("a delegating Vibe coordinator must be refused");
    assert!(error.to_string().contains("Vibe"), "{error}");
    assert!(
        error.to_string().contains("non-delegating terminal Worker"),
        "{error}"
    );

    let worker_with_children = assignment_with(json!({
        "worker_assignments": [nested_worker_assignment()],
    }));
    validate_assignment(&worker_with_children, SupervisorRuntime::Vibe)
        .expect_err("a Worker carrying nested assignments must be refused");
}

#[test]
fn vibe_worker_nested_launch_refusal_names_vibe() {
    let error = super::vibe_worker::refuse_nested_worker_launch()
        .expect_err("nested Vibe Worker launch is never admitted");
    assert_eq!(
        error.to_string(),
        "Vibe is not admitted for nested Worker assignments"
    );
}

#[test]
fn vibe_worker_plan_phase_contract_refuses_explicit_vibe_planning_assignment() {
    let planning = assignment_with(json!({ "phase": "planning" }));
    let plan = plan_with(vec![planning]);
    let error = super::plan_validation::validate_assignment_phase_contract(&plan)
        .expect_err("an explicit Vibe planning assignment must fail the phase contract");
    assert!(error.to_string().contains("Vibe"), "{error}");
}

#[test]
fn vibe_worker_plan_phase_contract_accepts_explicit_vibe_execution_worker() {
    let plan = plan_with(vec![vibe_worker_assignment()]);
    super::plan_validation::validate_assignment_phase_contract(&plan)
        .expect("an explicit Vibe execution Worker passes the phase contract");
}

#[test]
fn vibe_selector_runtime_name_round_trips() {
    assert_eq!(
        super::selection_bridge::runtime_from_name("vibe").unwrap(),
        SupervisorRuntime::Vibe
    );
    assert_eq!(
        super::selection_bridge::runtime_from_name(super::selection_bridge::runtime_name(
            SupervisorRuntime::Vibe
        ))
        .unwrap(),
        SupervisorRuntime::Vibe
    );
}

#[test]
fn vibe_worker_plan_validation_requires_a_managed_child_worktree() {
    let mut assignment = vibe_worker_assignment();
    assignment.assigned_paths = vec!["src/vibe-fixture.rs".into()];
    let mut plan = plan_with(vec![assignment]);
    plan.max_child_retries = 0;
    plan.max_gate_corrections = 0;
    let mut metadata = super::SupervisorPlanMetadata {
        execution_target: Some(super::SupervisorExecutionTarget::PrimaryWorktree {
            claim_paths: plan.assignments[0].assigned_paths.clone(),
        }),
        assignment_schedule: vec![super::AssignmentScheduleEntry {
            assignment_id: "vibe-worker".to_string(),
            parent_assignment_id: None,
            depth: super::MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        ..super::SupervisorPlanMetadata::default()
    };
    let error = super::plan_validation::validate_supervisor_plan(plan.clone(), metadata.clone())
        .expect_err("a Vibe Worker cannot execute in the primary worktree");
    let message = error.to_string();
    assert!(message.contains("vibe-worker"), "{message}");
    assert!(
        message.contains("Vibe requires a managed child worktree"),
        "{message}"
    );
    metadata.execution_target = None;
    super::plan_validation::validate_supervisor_plan(plan, metadata)
        .expect("the same Vibe Worker plan is admitted with a managed child worktree");
}

#[test]
fn vibe_worker_plan_phase_contract_ignores_omitted_runtime() {
    let assignment = assignment_with(json!({ "runtime": null, "phase": "planning" }));
    assert!(assignment.runtime.is_none());
    let plan = plan_with(vec![assignment]);
    super::plan_validation::validate_assignment_phase_contract(&plan)
        .expect("an omitted runtime stays a no-op and keeps the Codex default");
}

#[test]
fn vibe_worker_models_resolve_through_the_operator_declared_catalog() {
    let catalog = RuntimeModelCatalog::OperatorDeclared;
    for model in ["deepseek-v4-1-flash-1017", "zai-glm-5-3"] {
        let configured = RoleModelSelection {
            model: Some(model.to_string()),
            reasoning_effort: None,
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        };
        let resolution = catalog
            .resolve_role_model_selection(&configured, SupervisorRuntime::Vibe)
            .expect("operator-declared Vibe model resolves");
        assert_eq!(resolution.selection.model.as_deref(), Some(model));
        assert_eq!(
            crate::runtime_adapter::vibe::validate_model(resolution.selection.model.as_deref())
                .expect("resolved Vibe model id is a plain provider identifier"),
            model
        );
    }
}

#[test]
fn vibe_worker_model_validation_refuses_a_missing_model() {
    let catalog = RuntimeModelCatalog::OperatorDeclared;
    let configured = RoleModelSelection {
        model: None,
        reasoning_effort: None,
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    };
    let resolution = catalog
        .resolve_role_model_selection(&configured, SupervisorRuntime::Vibe)
        .expect("an empty selection resolves without a model");
    assert!(resolution.selection.model.is_none());
    crate::runtime_adapter::vibe::validate_model(resolution.selection.model.as_deref())
        .expect_err("Vibe requires an operator-declared model");
}

#[test]
fn vibe_worker_role_models_plan_field_carries_the_worker_model() {
    let mut role_models = BTreeMap::new();
    role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("zai-glm-5-3".to_string()),
            reasoning_effort: None,
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let mut plan: SupervisorPlan = serde_json::from_value(json!({
        "task": "vibe admission",
        "assignments": [],
    }))
    .expect("minimal plan must deserialize");
    plan.role_models = role_models;
    let configured = super::effective_role_model_selection(&plan, AgentRole::Worker);
    assert_eq!(configured.model.as_deref(), Some("zai-glm-5-3"));
}

#[test]
fn vibe_generated_and_published_schemas_admit_the_runtime() -> anyhow::Result<()> {
    fn validate_runtime_enums(value: &Value) -> usize {
        let mut checked = 0;
        match value {
            Value::Object(object) => {
                if object
                    .get("enum")
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values.contains(&json!("codex")) && values.contains(&json!("deepseek"))
                    })
                {
                    let mut compiler = boon::Compiler::new();
                    let mut schemas = boon::Schemas::new();
                    let uri = "https://maco.invalid/vibe-runtime";
                    compiler
                        .add_resource(uri, value.clone())
                        .expect("local runtime enum");
                    let schema = compiler
                        .compile(uri, &mut schemas)
                        .expect("compile runtime enum");
                    assert!(schemas.validate(&json!("vibe"), schema).is_ok());
                    assert!(schemas.validate(&json!("codex"), schema).is_ok());
                    assert!(schemas.validate(&json!("unknown-runtime"), schema).is_err());
                    checked += 1;
                }
                checked += object.values().map(validate_runtime_enums).sum::<usize>();
            }
            Value::Array(values) => {
                checked += values.iter().map(validate_runtime_enums).sum::<usize>()
            }
            _ => {}
        }
        checked
    }

    for (generated, published) in [
        (
            super::schema_artifacts::operator_pricing_plan_schema_value(),
            include_str!("../../schemas/operator-pricing-plan-v1.schema.json"),
        ),
        (
            super::schema_artifacts::supervisor_final_report_schema_value(),
            include_str!("../../schemas/supervisor-final-report-v1.schema.json"),
        ),
        (
            super::schema_artifacts::supervisor_collect_report_schema_value(),
            include_str!("../../schemas/supervisor-collect-report-v1.schema.json"),
        ),
    ] {
        let published: Value = serde_json::from_str(published)?;
        assert_eq!(generated, published);
        assert!(validate_runtime_enums(&generated) > 0);
    }
    let admission = super::schema_artifacts::worktree_writable_admission_schema_value();
    assert!(validate_runtime_enums(&admission) > 0);
    Ok(())
}

#[test]
fn vibe_worker_settlement_keeps_export_tokens_and_unknown_cost_and_identity() -> anyhow::Result<()>
{
    use super::*;
    use crate::external_agent::CapturedOutput;
    use crate::process_runner::{ContainmentBackend, SideEffectConfinementProfileKind};
    use crate::runtime_adapter::{IdentityBasis, RuntimeAdapterConfig};

    let valid: &[u8] = br#"{"usage":{"input_tokens":11,"output_tokens":7,"cached_input_tokens":3,"total_tokens":18},"cost_usd":0.0}"#;
    let stream = concat!(
        "{\"type\":\"message\",\"role\":\"assistant\",\"generationStatus\":\"completed\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}\n",
        "{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":99999,\"output_tokens\":99999}}\n"
    );
    let command = ExternalAgentCommand::codex(
        "vibe-fixture",
        "/workspace",
        "/private/prompt",
        "/private/log",
        "/private/report",
        Duration::from_secs(1),
    )
    .with_runtime_adapter(
        SupervisorRuntime::Vibe,
        RuntimeAdapterConfig::defaults(SupervisorRuntime::Vibe),
    )
    .with_model_selection(Some("deepseek-v4-1-flash-1017".into()), Some("high".into()));

    for (export, expected_tokens, exit_code) in [
        (Some(valid), Some(18), 0),
        (Some(valid), Some(18), 3),
        (None, None, 0),
        (Some(&b"malformed"[..]), None, 0),
    ] {
        let mut run = ExternalAgentRun {
            command: vec!["vibe-fixture".into()],
            cwd: command.cwd.clone(),
            timeout_seconds: 1,
            exit_code: Some(exit_code),
            duration_ms: 1,
            timed_out: false,
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            )),
            publishable: true,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: Some(b"done".to_vec()),
            grok_stream_usage_evidence: None,
            grok_acp_parent_evidence: None,
            cursor_managed_parent_evidence: None,
            codex_parent_evidence: None,
        };
        run.retain_vibe_fixture_for_test(&command, export, stream.as_bytes())?;
        assert_eq!(
            external_process_completed(&run, SupervisorRuntime::Vibe),
            exit_code == 0
        );
        let identity = crate::runtime_adapter::RuntimeIdentityObservation::capture(
            &run,
            &command,
            SupervisorRuntime::Vibe,
        );
        assert_eq!(identity.requested_model, command.model);
        assert_eq!(identity.model_basis, Some(IdentityBasis::Requested));
        assert_eq!(identity.model, None);
        assert_eq!(identity.effort, None);

        let ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        let BudgetAdmission::Admitted { reservation, .. } =
            ledger.reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 64,
                cost_usd: None,
            })?
        else {
            panic!("Vibe fixture reservation refused")
        };
        // Even a retained nonzero reservation estimate cannot establish Vibe spend.
        let mut held = DispatchBudgetReservation {
            ledger: &ledger,
            reservation,
            pricing: Some(ModelPricing {
                input_usd_per_million_tokens: 10.0,
                output_usd_per_million_tokens: 20.0,
            }),
            pricing_model: command.model.clone(),
            state: DispatchBudgetReservationState::Invoked(SupervisorRuntime::Vibe),
        };
        let settlement = held.settle_bound_runtime(&run, &command)?;
        assert_eq!(
            settlement.observed_usage.map(|usage| usage.total_tokens),
            expected_tokens
        );
        assert_eq!(settlement.cost_usd, None);
        assert_eq!(settlement.model, None);
        assert_eq!(
            settlement.reliability,
            if expected_tokens.is_some() && exit_code == 0 {
                DispatchUsageReliability::Reliable
            } else if expected_tokens.is_some() {
                DispatchUsageReliability::Estimated
            } else {
                DispatchUsageReliability::Missing
            }
        );
        if let Some(usage) = settlement.observed_usage {
            assert_eq!(
                (usage.input_tokens, usage.output_tokens, usage.total_tokens),
                (11, 7, 18)
            );
        }
        let restored: ExternalAgentRun = serde_json::from_value(serde_json::to_value(&run)?)?;
        assert!(
            restored.vibe_usage(&command).is_none(),
            "serialized public reports cannot restore held usage"
        );
    }
    Ok(())
}
