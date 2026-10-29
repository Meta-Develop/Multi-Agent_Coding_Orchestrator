use std::collections::BTreeSet;

use super::*;
use crate::optimizer::ids::RuntimeSlug;
use crate::optimizer::quota_pools::{
    AccountId, ConsumptionSource, ExhaustionBehavior, PoolKind, PoolReference, ResetWindow,
};

fn leaf_task() -> TaskProfile {
    TaskProfile {
        task_class: "localized_code_change".to_string(),
        risk: RiskLevel::Medium,
        boundedness: Boundedness::Bounded,
        context: ContextSize::Medium,
        horizon: TaskHorizon::Medium,
        authority_role: AuthorityRole::TerminalLeaf,
    }
}

fn capabilities(
    task_class: &str,
    authority: AuthorityRole,
    long_context: bool,
) -> CandidateCapabilities {
    CandidateCapabilities {
        task_classes: [task_class.to_string()].into_iter().collect(),
        authority_roles: [authority].into_iter().collect(),
        boundedness: [
            Boundedness::TightlyBounded,
            Boundedness::Bounded,
            Boundedness::CrossCutting,
        ]
        .into_iter()
        .collect(),
        maximum_risk: RiskLevel::Critical,
        maximum_context: ContextSize::Long,
        maximum_horizon: TaskHorizon::Long,
        long_context,
    }
}

fn catalog(
    runtime: &str,
    revision: &str,
    task_class: &str,
    authority: AuthorityRole,
    models: &[(&str, &[ReasoningEffort], bool)],
) -> RuntimeCatalog {
    RuntimeCatalog {
        runtime: runtime.to_string(),
        revision: revision.to_string(),
        advertised_at: "2026-08-21".to_string(),
        models: models
            .iter()
            .map(|(model, efforts, long_context)| CatalogModel {
                model: (*model).to_string(),
                available: true,
                access: None,
                supported_efforts: efforts.to_vec(),
                capabilities: capabilities(task_class, authority, *long_context),
            })
            .collect(),
    }
}

fn pool(runtime: &str, pressure: u16) -> RuntimePoolState {
    RuntimePoolState {
        runtime: runtime.to_string(),
        admission_open: true,
        pool_reference: None,
        pool_kind: None,
        entitlement_bounded: true,
        entitlement_capacity_units: 100,
        entitlement_remaining_units: 100,
        pool_pressure_basis_points: pressure,
        observed_consumption_units: 0,
        marginal_cost_microunits: 0,
        exhausted: false,
        exhaustion_behavior: None,
        authorized_alternatives: Vec::new(),
        observation_revision: format!("{runtime}-pool-r1"),
        observation_source: None,
        admission_provenance: "deterministic fixture".to_string(),
        failover_provenance: None,
    }
}

fn pool_reference(runtime: &str) -> PoolReference {
    PoolReference {
        runtime: RuntimeSlug::new(runtime).expect("runtime"),
        account: AccountId::new("operator").expect("account"),
        window: ResetWindow::CalendarMonth,
    }
}

fn configure_exhausted_quota(
    input: &mut SelectionInput,
    behavior: ExhaustionBehavior,
    authorized_runtimes: &[&str],
) {
    let source = pool_reference("codex");
    let authorized_alternatives = authorized_runtimes
        .iter()
        .map(|runtime| pool_reference(runtime))
        .collect::<Vec<_>>();
    for pool in &mut input.pools {
        let reference = pool_reference(&pool.runtime);
        let is_source = reference == source;
        pool.pool_reference = Some(reference);
        pool.pool_kind = Some(PoolKind::SubscriptionIncluded);
        pool.entitlement_bounded = true;
        pool.entitlement_capacity_units = 100;
        pool.entitlement_remaining_units = if is_source { 0 } else { 100 };
        pool.exhausted = is_source;
        pool.admission_open = !is_source || behavior == ExhaustionBehavior::Degrade;
        pool.exhaustion_behavior = Some(if is_source {
            behavior
        } else {
            ExhaustionBehavior::FailClosed
        });
        pool.authorized_alternatives = if is_source {
            authorized_alternatives.clone()
        } else {
            Vec::new()
        };
        pool.observation_revision = format!("{}-workspace-ledger-r7", pool.runtime);
        pool.observation_source = Some(ConsumptionSource::LocalObserved);
    }
    input.quota_source = Some(source);
}

pub(crate) fn base_input() -> SelectionInput {
    SelectionInput {
        task: leaf_task(),
        catalogs: vec![
            catalog(
                "codex",
                "codex-r1",
                "localized_code_change",
                AuthorityRole::TerminalLeaf,
                &[
                    (
                        "gpt-5.6-sol",
                        &[ReasoningEffort::High, ReasoningEffort::Xhigh],
                        true,
                    ),
                    ("gpt-5.6-luna", &[ReasoningEffort::High], false),
                ],
            ),
            catalog(
                "grok",
                "grok-r1",
                "localized_code_change",
                AuthorityRole::TerminalLeaf,
                &[("grok-code-fast-1", &[ReasoningEffort::High], false)],
            ),
            catalog(
                "cursor",
                "cursor-r1",
                "localized_code_change",
                AuthorityRole::TerminalLeaf,
                &[("cursor-composer-1", &[ReasoningEffort::High], false)],
            ),
        ],
        pools: vec![pool("codex", 0), pool("grok", 0), pool("cursor", 0)],
        quota_source: None,
        constraints: OperatorConstraints {
            allowed_runtimes: BTreeSet::new(),
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: false,
        },
        priors: built_in_prior_dataset().expect("built-in priors"),
        objective_profile: SelectorCalibrationRef {
            name: "accepted-task-total-cost".to_string(),
            version: 3,
            expected_digest: None,
        },
        resolved_objective_profile: crate::objective_profile::ResolvedObjectiveProfile {
            profile: crate::objective_profile::default_objective_profile()
                .binding()
                .expect("default objective profile binding"),
            source: crate::objective_profile::ObjectiveProfileSource::BuiltIn,
        },
        outcomes: Vec::new(),
        signals: DynamicSignals {
            retry_count: 0,
            budget_signal: BudgetSignal::Continue,
            previous_choice: None,
            previous_catalog_digest: None,
            environment_rejections: Vec::new(),
            observed_cost_per_accepted_task_microunits: None,
        },
        debug_override: None,
        operational_observations: None,
    }
}

pub(crate) fn loaded_policy_test_receipt() -> anyhow::Result<routing_policy::RoutingPolicyReceipt> {
    use super::routing_policy::*;
    let temp = tempfile::tempdir()?;
    Ok(RoutingPolicyReceipt {
        frozen: load_routing_policy(temp.path())?,
        role: "worker".into(),
        features: TaskRoutingFeatures {
            scope_paths: 1,
            scope_modules: 0,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 0,
            independent_groups: 1,
            evidence: vec!["test scope".into()],
        },
    })
}

fn single_current_prior_input() -> SelectionInput {
    let mut input = base_input();
    input.catalogs.truncate(1);
    input.catalogs[0].models.truncate(1);
    input.catalogs[0].models[0].supported_efforts = [ReasoningEffort::High].into_iter().collect();
    let prior = input
        .priors
        .models
        .iter_mut()
        .find(|prior| {
            prior.runtime == input.catalogs[0].runtime
                && prior.model == input.catalogs[0].models[0].model
        })
        .expect("current fixture prior");
    prior.prohibited = false;
    prior.prohibited_authority_roles.clear();
    prior.prohibition_reason = Some("current operator evaluation prohibition".into());
    input
}

#[test]
fn loaded_policy_preserves_current_model_wide_prohibition() -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    for routing in [None, Some(&receipt)] {
        let mut input = single_current_prior_input();
        let permitted = select_with_loaded_routing_policy(&input, &[], routing)?;
        assert!(
            permitted.choice.is_some(),
            "permitted control must remain selectable"
        );
        let candidate = permitted.choice.as_ref().unwrap().candidate.clone();
        let prior = input
            .priors
            .models
            .iter_mut()
            .find(|prior| prior.runtime == candidate.runtime && prior.model == candidate.model)
            .unwrap();
        prior.prohibited = true;
        let prohibited = select_with_loaded_routing_policy(&input, &[], routing)?;
        assert!(prohibited.choice.is_none());
        assert!(!prohibited.candidate_set[0].eligible);
        assert!(prohibited.candidate_set[0].score.is_none());
        let reasons = &prohibited.candidate_set[0].ineligibility_reasons;
        assert_eq!(
            reasons
                .iter()
                .filter(|reason| reason.code == IneligibilityCode::PolicyProhibited)
                .count(),
            1
        );
        assert!(reasons
            .iter()
            .any(|reason| reason.code == IneligibilityCode::PolicyProhibited
                && reason.detail == "current operator evaluation prohibition"));
    }
    Ok(())
}

#[test]
fn loaded_policy_preserves_current_role_prohibition_and_permitted_role() -> anyhow::Result<()> {
    let mut receipt = loaded_policy_test_receipt()?;
    let mut input = single_current_prior_input();
    input.catalogs[0].models[0]
        .capabilities
        .authority_roles
        .insert(AuthorityRole::ReviewAuditor);
    input
        .priors
        .models
        .iter_mut()
        .find(|prior| {
            prior.runtime == input.catalogs[0].runtime
                && prior.model == input.catalogs[0].models[0].model
        })
        .unwrap()
        .prohibited_authority_roles
        .insert(AuthorityRole::ReviewAuditor);
    let permitted = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert!(
        permitted.choice.is_some(),
        "role-specific prohibition must not exclude a permitted role"
    );
    assert!(!permitted.candidate_set[0]
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::PolicyProhibited));
    input.task.authority_role = AuthorityRole::ReviewAuditor;
    receipt.role = "auditor".into();
    let prohibited = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert!(prohibited.choice.is_none());
    assert!(!prohibited.candidate_set[0].eligible);
    assert!(prohibited.candidate_set[0].score.is_none());
    assert!(prohibited.candidate_set[0]
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::PolicyProhibited));
    Ok(())
}

#[test]
fn loaded_policy_unknown_models_fail_closed_for_judgment_roles() -> anyhow::Result<()> {
    let mut receipt = loaded_policy_test_receipt()?;
    for (role, authority) in [
        ("supervisor", AuthorityRole::AcceptanceGate),
        ("child_orchestrator", AuthorityRole::Delegating),
        ("auditor", AuthorityRole::ReviewAuditor),
        ("auditor", AuthorityRole::Audit),
        ("supervisor", AuthorityRole::ConflictResolution),
        ("gate_classifier", AuthorityRole::FailureClassification),
        ("supervisor", AuthorityRole::GitPublication),
        ("supervisor", AuthorityRole::UnknownJudgment),
    ] {
        receipt.role = role.into();
        let mut input = base_input();
        input.task.authority_role = authority;
        input.catalogs = vec![catalog(
            "grok",
            "observed-menu",
            &input.task.task_class,
            authority,
            &[("unknown-grok-model", &[ReasoningEffort::Xhigh], true)],
        )];
        input.pools = vec![pool("grok", 0)];
        let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
        assert_eq!(decision.status, DecisionStatus::FailClosed, "{role}");
        assert!(decision.choice.is_none());
        assert_eq!(decision.candidate_set.len(), 1);
        let candidate = &decision.candidate_set[0];
        assert!(!candidate.eligible);
        assert!(candidate.score.is_none());
        assert!(candidate
            .ineligibility_reasons
            .iter()
            .any(|reason| reason.code == IneligibilityCode::MissingDatedPrior));
    }
    Ok(())
}

#[test]
fn loaded_policy_unknown_model_none_effort_is_honest_and_exactly_authorized() -> anyhow::Result<()>
{
    use super::routing_policy::*;
    let temp = tempfile::tempdir()?;
    let frozen = load_routing_policy(temp.path())?;
    let receipt = RoutingPolicyReceipt {
        frozen: frozen.clone(),
        role: "worker".into(),
        features: TaskRoutingFeatures {
            scope_paths: 1,
            scope_modules: 0,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 0,
            independent_groups: 1,
            evidence: vec!["test scope".into()],
        },
    };
    let mut input = base_input();
    input.catalogs = vec![catalog(
        "codex",
        "observed-menu",
        "localized_code_change",
        AuthorityRole::TerminalLeaf,
        &[(
            "account-advertised-unmeasured-model",
            &[ReasoningEffort::None],
            true,
        )],
    )];
    input.pools = vec![pool("codex", 0)];
    let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert!(decision.candidate_set.iter().all(|entry| !entry
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::PolicyProhibited)));
    let chosen = decision
        .choice
        .as_ref()
        .expect("unknown model policy choice");
    assert_eq!(chosen.candidate.effort, ReasoningEffort::None);
    let evidence = decision
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == chosen.candidate)
        .and_then(|entry| entry.loaded_policy_evidence.as_ref())
        .expect("explicit unknown evidence");
    assert_eq!(evidence.quality_basis_points, None);
    assert_eq!(evidence.expected_accepted_cycle_cost_microunits, None);
    assert_eq!(evidence.samples, 0);
    assert!(evidence.uncertainty_penalty > 0);
    let _binding = bind_routing_policy(Some(frozen))?;
    assert!(validate_selected_launch("worker", "codex", &chosen.candidate.model, "none").is_err());
    seal_selected_candidate("worker", &decision)?;
    validate_selected_launch("worker", "codex", &chosen.candidate.model, "none")?;
    for (role, runtime, model, effort) in [
        ("auditor", "codex", chosen.candidate.model.as_str(), "none"),
        ("worker", "grok", chosen.candidate.model.as_str(), "none"),
        ("worker", "codex", "unselected-model", "none"),
        ("worker", "codex", chosen.candidate.model.as_str(), "high"),
    ] {
        assert!(validate_selected_launch(role, runtime, model, effort).is_err());
    }
    input.catalogs[0].models[0].available = false;
    assert!(
        select_with_loaded_routing_policy(&input, &[], Some(&receipt))?
            .choice
            .is_none()
    );
    input.catalogs[0].models[0].available = true;
    input.pools[0].admission_open = false;
    assert!(
        select_with_loaded_routing_policy(&input, &[], Some(&receipt))?
            .choice
            .is_none()
    );
    Ok(())
}

#[test]
fn loaded_policy_score_semantics_v1_remains_deserializable() {
    let v1 = serde_json::from_value::<RoutingScoreSemantics>(serde_json::json!(
        "loaded_policy_evidence_penalty_v1"
    ))
    .expect("historical loaded-policy v1 token");
    assert_eq!(v1, RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV1);
    let v2 = serde_json::from_value::<RoutingScoreSemantics>(serde_json::json!(
        "loaded_policy_evidence_penalty_v2"
    ))
    .expect("loaded-policy v2 token");
    assert_eq!(v2, RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV2);

    let schema = schema::selection_event_schema_value();
    let score = &schema["properties"]["provenance"]["properties"]["candidate_set"]["items"]
        ["properties"]["score"];
    let score_object = score["oneOf"]
        .as_array()
        .expect("nullable score schema")
        .iter()
        .find(|alt| alt.get("properties").is_some())
        .expect("candidate_set item score object schema");
    let tokens = score_object["properties"]["routing_score_semantics"]["enum"]
        .as_array()
        .expect("routing_score_semantics enum");
    let tokens = tokens
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(tokens.contains(&"legacy_baseline_plus_cost_proxy_adjustments_v1"));
    assert!(tokens.contains(&"loaded_policy_evidence_penalty_v1"));
    assert!(tokens.contains(&"loaded_policy_evidence_penalty_v2"));
}

#[test]
fn loaded_policy_unknown_evidence_skips_quality_normalization() -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    let mut input = base_input();
    input.catalogs = vec![catalog(
        "codex",
        "observed-menu",
        "localized_code_change",
        AuthorityRole::TerminalLeaf,
        &[(
            "account-advertised-unmeasured-model",
            &[ReasoningEffort::None],
            true,
        )],
    )];
    input.pools = vec![pool("codex", 0)];
    let candidate = CandidateKey {
        runtime: "codex".to_string(),
        model: "account-advertised-unmeasured-model".to_string(),
        effort: ReasoningEffort::None,
    };
    input.signals.previous_choice = Some(candidate.clone());
    input.signals.retry_count = 3;
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "review-sensitive-unknown-loaded-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 25;
    profile.tradeoffs.human_review_percent = 75;
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    let evaluation = decision
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == candidate)
        .expect("unknown loaded-policy evaluation");
    let evidence = evaluation
        .loaded_policy_evidence
        .as_ref()
        .expect("unknown loaded-policy evidence");
    assert_eq!(evidence.quality_basis_points, None);
    assert_eq!(evidence.expected_accepted_cycle_cost_microunits, None);
    assert!(evidence.uncertainty_penalty > 0);
    let score = evaluation
        .score
        .as_ref()
        .expect("unknown loaded-policy score");
    assert_eq!(
        score.routing_score_semantics,
        RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV2
    );
    assert_eq!(score.posterior_quality_basis_points, 0);
    assert_eq!(score.retry_cost_microunits, 0);
    assert_eq!(score.human_review_cost_proxy_microunits, 0);
    assert_eq!(score.human_review_adjustment_microunits, 0);
    Ok(())
}

#[test]
fn loaded_policy_observed_ledger_without_class_fit_applies_review_tradeoffs() -> anyhow::Result<()>
{
    let receipt = loaded_policy_test_receipt()?;
    let mut input = base_input();
    input.catalogs = vec![catalog(
        "codex",
        "observed-menu",
        "localized_code_change",
        AuthorityRole::TerminalLeaf,
        &[(
            "account-advertised-unmeasured-model",
            &[ReasoningEffort::None],
            true,
        )],
    )];
    input.pools = vec![pool("codex", 0)];
    let candidate = CandidateKey {
        runtime: "codex".to_string(),
        model: "account-advertised-unmeasured-model".to_string(),
        effort: ReasoningEffort::None,
    };
    input.outcomes.push(OutcomeRecord {
        attempt_id: "attempt-1".to_string(),
        task: input.task.clone(),
        candidate: candidate.clone(),
        result: OutcomeResult::Accepted,
        failure_class: None,
        execution_cost_microunits: 10,
        review_cost_microunits: 25,
        rework_cost_microunits: 8,
        rereview_cost_microunits: 0,
        environment_cost_microunits: 0,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    });
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "review-sensitive-observed-ledger-loaded-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 25;
    profile.tradeoffs.human_review_percent = 75;
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    let evaluation = decision
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == candidate)
        .expect("observed-ledger loaded-policy evaluation");
    assert!(evaluation.prior_source_id.is_none());
    assert!(evaluation.eligible);
    let evidence = evaluation
        .loaded_policy_evidence
        .as_ref()
        .expect("observed-ledger loaded-policy evidence");
    assert!(evidence.quality_basis_points.is_some());
    assert!(evidence.expected_accepted_cycle_cost_microunits.is_some());
    assert_eq!(evidence.uncertainty_penalty, 0);
    let score = evaluation
        .score
        .as_ref()
        .expect("observed-ledger loaded-policy score");
    assert_eq!(
        score.routing_score_semantics,
        RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV2
    );
    assert_eq!(score.human_review_cost_proxy_microunits, 25);
    assert_eq!(score.retry_rework_cost_proxy_microunits, 8);
    assert_eq!(
        score.human_review_adjustment_microunits,
        score.human_review_cost_proxy_microunits * 75 / 25
    );
    assert_eq!(
        score.total_score_microunits,
        score.legacy_baseline_score_microunits + score.total_adjustment_microunits
    );
    Ok(())
}

#[test]
fn loaded_policy_known_fit_uses_prior_review_and_previous_choice_retry() -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "review-sensitive-known-loaded-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 25;
    profile.tradeoffs.human_review_percent = 75;
    let mut input = base_input();
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let initial = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    for evaluation in initial.candidate_set.iter().filter(|entry| entry.eligible) {
        let score = evaluation.score.as_ref().expect("known-fit loaded score");
        assert_eq!(
            score.routing_score_semantics,
            RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV2
        );
        assert_eq!(score.retry_cost_microunits, 0);
        assert_eq!(
            score.human_review_adjustment_microunits,
            score.human_review_cost_proxy_microunits * 75 / 25
        );
        assert_eq!(
            score.total_score_microunits,
            score.legacy_baseline_score_microunits + score.total_adjustment_microunits
        );
        assert!(score.human_review_cost_proxy_microunits > 0);
    }
    let previous = initial
        .choice
        .as_ref()
        .expect("known-fit loaded choice")
        .candidate
        .clone();
    input.signals.previous_choice = Some(previous.clone());
    input.signals.retry_count = 3;
    let retried = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    let previous_score = retried
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == previous)
        .and_then(|entry| entry.score.as_ref())
        .expect("previous loaded-policy retry score");
    assert!(previous_score.retry_cost_microunits > 0);
    assert!(retried.candidate_set.iter().all(|entry| {
        entry.candidate == previous
            || entry
                .score
                .as_ref()
                .is_none_or(|score| score.retry_cost_microunits == 0)
    }));
    Ok(())
}

#[test]
fn loaded_policy_nonzero_retry_rework_weight_adds_utility_preference_not_a_second_bill(
) -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "retry-rework-utility-loaded-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 75;
    profile.tradeoffs.quota_consumption_percent = 0;
    profile.tradeoffs.latency_percent = 0;
    profile.tradeoffs.retry_rework_percent = 25;
    profile.tradeoffs.human_review_percent = 0;
    let mut input = base_input();
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let initial = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    let previous = initial
        .choice
        .as_ref()
        .expect("initial loaded-policy choice")
        .candidate
        .clone();
    let before = initial
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == previous)
        .and_then(|entry| entry.score.as_ref())
        .expect("initial previous-candidate score");
    assert_eq!(before.retry_cost_microunits, 0);
    assert_eq!(before.switch_cost_microunits, 0);
    assert_eq!(before.switch_transition, ContextSwitchTransition::Continue);
    let r = before.retry_rework_cost_proxy_microunits;
    let before_cycle = before.expected_total_cost_per_accepted_task_microunits;
    let before_baseline = before.legacy_baseline_score_microunits;
    let before_total = before.total_score_microunits;
    input.signals.previous_choice = Some(previous.clone());
    input.signals.retry_count = 3;
    let retried = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    let after_eval = retried
        .candidate_set
        .iter()
        .find(|entry| entry.candidate == previous)
        .expect("retried previous-candidate evaluation");
    let after = after_eval
        .score
        .as_ref()
        .expect("retried previous-candidate score");
    let p = after.retry_cost_microunits;
    assert!(p > 0);
    assert!(retried.candidate_set.iter().all(|entry| {
        entry.candidate == previous
            || entry
                .score
                .as_ref()
                .is_none_or(|score| score.retry_cost_microunits == 0)
    }));
    assert_eq!(
        after.expected_total_cost_per_accepted_task_microunits,
        before_cycle
    );
    assert_eq!(
        after_eval
            .loaded_policy_evidence
            .as_ref()
            .and_then(|evidence| evidence.expected_accepted_cycle_cost_microunits),
        Some(before_cycle)
    );
    assert_eq!(after.switch_cost_microunits, 0);
    assert_eq!(after.switch_transition, ContextSwitchTransition::Continue);
    assert_eq!(after.legacy_baseline_score_microunits, before_baseline + p);
    assert_eq!(after.retry_rework_cost_proxy_microunits, r + p);
    assert_eq!(after.human_review_adjustment_microunits, 0);
    let expected_total_increment = p + ((r + p) * 25 / 75) - (r * 25 / 75);
    assert_eq!(
        after.total_score_microunits,
        before_total + expected_total_increment
    );
    Ok(())
}

#[test]
fn legacy_catalog_access_absence_preserves_wire_digest_and_replay() {
    let input = base_input();
    let legacy_bytes = serde_json::to_vec(&input).unwrap();
    let legacy: serde_json::Value = serde_json::from_slice(&legacy_bytes).unwrap();
    for catalog in legacy["catalogs"].as_array().unwrap() {
        for model in catalog["models"].as_array().unwrap() {
            assert!(model.get("access").is_none());
            assert_eq!(model.as_object().unwrap().len(), 4);
        }
    }
    let restored: SelectionInput = serde_json::from_slice(&legacy_bytes).unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), legacy_bytes);
    assert!(restored
        .catalogs
        .iter()
        .all(|catalog| { catalog.models.iter().all(|model| model.access.is_none()) }));
    let decision = select(&input).unwrap();
    let replayed = select(&restored).unwrap();
    assert_eq!(decision, replayed);
    let catalog_bytes = serde_json::to_vec(&decision.normalized_input.catalogs).unwrap();
    assert_eq!(
        decision.input_digests.catalogs.value,
        crate::artifacts::state_auth::sha256_hex(&catalog_bytes)
    );
    assert_eq!(decision.schema_version, 4);
}

#[test]
fn typed_catalog_access_survives_normalization_and_changes_digests() {
    use crate::selection::ModelAccessOutcome;
    let mut input = base_input();
    let runtime = input.catalogs[0].runtime.clone();
    let model = input.catalogs[0].models[0].model.clone();
    input.catalogs[0].models[0].access = Some(ModelAccessOutcome::UnknownAccess);
    let unknown = select(&input).unwrap();
    input.catalogs[0].models[0].access = Some(ModelAccessOutcome::Available);
    let available = select(&input).unwrap();
    for (decision, access) in [
        (&unknown, ModelAccessOutcome::UnknownAccess),
        (&available, ModelAccessOutcome::Available),
    ] {
        let retained = decision
            .normalized_input
            .catalogs
            .iter()
            .find(|catalog| catalog.runtime == runtime)
            .unwrap()
            .models
            .iter()
            .find(|entry| entry.model == model)
            .unwrap();
        assert_eq!(retained.access, Some(access));
        assert!(retained.available);
        let candidates: Vec<_> = decision
            .candidate_set
            .iter()
            .filter(|entry| entry.candidate.runtime == runtime && entry.candidate.model == model)
            .collect();
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|entry| !entry
            .ineligibility_reasons
            .iter()
            .any(|reason| reason.code == IneligibilityCode::CatalogUnavailable)));
    }
    assert_ne!(
        unknown.input_digests.catalogs,
        available.input_digests.catalogs
    );
    assert_ne!(
        unknown.input_digests.normalized_input,
        available.input_digests.normalized_input
    );
}

#[test]
fn explicit_catalog_access_never_overrides_eligibility_refusal() {
    use crate::selection::ModelAccessOutcome;
    for (eligible, access) in [
        (true, ModelAccessOutcome::Unavailable),
        (false, ModelAccessOutcome::Available),
    ] {
        let mut input = base_input();
        let runtime = input.catalogs[0].runtime.clone();
        let model = input.catalogs[0].models[0].model.clone();
        input.catalogs[0].models[0].available = eligible;
        input.catalogs[0].models[0].access = Some(access);
        let decision = select(&input).unwrap();
        let candidates: Vec<_> = decision
            .candidate_set
            .iter()
            .filter(|entry| entry.candidate.runtime == runtime && entry.candidate.model == model)
            .collect();
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|entry| !entry.eligible
            && entry
                .ineligibility_reasons
                .iter()
                .any(|reason| reason.code == IneligibilityCode::CatalogUnavailable)));
        assert!(decision.choice.as_ref().is_none_or(|choice| {
            choice.candidate.runtime != runtime || choice.candidate.model != model
        }));
    }
}

fn codex_model_switch_input(model_switch_cost_microunits: u64) -> SelectionInput {
    let mut input = base_input();
    input.catalogs.retain(|catalog| catalog.runtime == "codex");
    input.catalogs[0]
        .models
        .retain(|model| matches!(model.model.as_str(), "gpt-5.6-sol" | "gpt-5.6-luna"));
    for model in &mut input.catalogs[0].models {
        model
            .supported_efforts
            .retain(|effort| *effort == ReasoningEffort::High);
    }
    input.pools.retain(|pool| pool.runtime == "codex");
    input.signals.previous_choice = Some(CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-sol".to_string(),
        effort: ReasoningEffort::High,
    });
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.switch_costs.model_change_same_runtime_microunits = model_switch_cost_microunits;
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::BuiltIn,
    );
    input
}

fn resolved_routing_profile(
    profile: crate::objective_profile::ObjectiveProfile,
    source: crate::objective_profile::ObjectiveProfileSource,
) -> crate::objective_profile::ResolvedObjectiveProfile {
    crate::objective_profile::ResolvedObjectiveProfile {
        profile: profile.binding().expect("routing objective binding"),
        source,
    }
}

#[test]
fn built_in_routing_objective_preserves_legacy_scores_choice_and_runner_order() {
    let decision = select(&base_input()).expect("default objective selection");
    assert_eq!(decision.schema_version, 4);
    let mut legacy_ranked = decision
        .candidate_set
        .iter()
        .filter(|candidate| candidate.eligible)
        .map(|candidate| {
            let score = candidate.score.as_ref().expect("eligible candidate score");
            assert_eq!(
                score.total_score_microunits,
                score.legacy_baseline_score_microunits
            );
            assert_eq!(score.total_adjustment_microunits, 0);
            assert_eq!(
                score.routing_score_semantics,
                RoutingScoreSemantics::LegacyBaselinePlusCostProxyAdjustmentsV1
            );
            assert_eq!(score.routing_tradeoff_weights.monetary_cost_percent, 100);
            assert_eq!(score.routing_tradeoff_weights.quota_consumption_percent, 0);
            (
                candidate.candidate.clone(),
                score.legacy_baseline_score_microunits,
            )
        })
        .collect::<Vec<_>>();
    legacy_ranked.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    let choice = decision.choice.as_ref().expect("default choice");
    assert_eq!(
        choice.reason,
        ChoiceReason::LowestExpectedTotalCostPerAcceptedTask
    );
    assert_eq!(
        Some(&choice.candidate),
        legacy_ranked.first().map(|(candidate, _)| candidate)
    );
    assert_eq!(
        decision
            .runner_up_scores
            .iter()
            .map(|ranked| (&ranked.candidate, ranked.total_score_microunits))
            .collect::<Vec<_>>(),
        legacy_ranked
            .iter()
            .skip(1)
            .map(|(candidate, score)| (candidate, *score))
            .collect::<Vec<_>>()
    );
}

#[test]
fn unsupported_quota_and_latency_weights_fail_closed_without_numeric_zero_evidence() {
    let mut input = base_input();
    let mut quota_profile = crate::objective_profile::default_objective_profile();
    quota_profile.id = "quota-first-routing-v1".to_string();
    quota_profile.tradeoffs.monetary_cost_percent = 75;
    quota_profile.tradeoffs.quota_consumption_percent = 25;
    input.resolved_objective_profile = resolved_routing_profile(
        quota_profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message == "resolved objective profile requests quota_consumption_percent=25 but typed contract-backed per-runtime quota evidence is unavailable"
    ));

    let mut latency_profile = crate::objective_profile::default_objective_profile();
    latency_profile.id = "latency-first-routing-v1".to_string();
    latency_profile.tradeoffs.monetary_cost_percent = 75;
    latency_profile.tradeoffs.latency_percent = 25;
    input.resolved_objective_profile = resolved_routing_profile(
        latency_profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message == "resolved objective profile requests latency_percent=25 but typed per-candidate observed or predicted latency evidence is unavailable"
    ));
}

#[test]
fn typed_quota_and_latency_observations_admit_nonzero_profile_weights() {
    let mut input = base_input();
    let mut quota_profile = crate::objective_profile::default_objective_profile();
    quota_profile.id = "quota-first-routing-v1".to_string();
    quota_profile.tradeoffs.monetary_cost_percent = 75;
    quota_profile.tradeoffs.quota_consumption_percent = 25;
    input.resolved_objective_profile = resolved_routing_profile(
        quota_profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    input.operational_observations = Some(LiveOperationalObservations {
        quota: Some(TypedAxisObservation {
            kind: TypedObservationKind::Measured,
            unit: "entitlement_consumed_fraction_bp".to_string(),
            value_basis_points: 2_500,
        }),
        latency: Some(TypedAxisObservation {
            kind: TypedObservationKind::Measured,
            unit: "wall_time_ms".to_string(),
            value_basis_points: 1_000,
        }),
        retry_rate: None,
        review_load: None,
    });
    select(&input).expect("typed quota observation licenses the quota weight");

    let mut latency_profile = crate::objective_profile::default_objective_profile();
    latency_profile.id = "latency-first-routing-v1".to_string();
    latency_profile.tradeoffs.monetary_cost_percent = 75;
    latency_profile.tradeoffs.latency_percent = 25;
    input.resolved_objective_profile = resolved_routing_profile(
        latency_profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    select(&input).expect("typed latency observation licenses the latency weight");
}

#[test]
fn supported_cost_proxy_adjustments_use_exact_arithmetic_and_can_change_ranking() {
    let input = base_input();
    let default = select(&input).expect("default objective selection");
    let default_choice = default
        .choice
        .as_ref()
        .expect("default choice")
        .candidate
        .clone();

    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "review-sensitive-routing-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 25;
    profile.tradeoffs.human_review_percent = 75;
    let mut adjusted_input = input;
    adjusted_input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let adjusted = select(&adjusted_input).expect("supported adjusted selection");
    let adjusted_choice = adjusted.choice.as_ref().expect("adjusted choice");
    assert_eq!(
        adjusted_choice.reason,
        ChoiceReason::LowestLegacyBaselinePlusCostProxyAdjustments
    );
    assert_ne!(adjusted_choice.candidate, default_choice);

    for candidate in adjusted
        .candidate_set
        .iter()
        .filter(|candidate| candidate.eligible)
    {
        let score = candidate.score.as_ref().expect("eligible score");
        assert_eq!(
            score.routing_score_semantics,
            RoutingScoreSemantics::LegacyBaselinePlusCostProxyAdjustmentsV1
        );
        assert_eq!(score.routing_tradeoff_weights.monetary_cost_percent, 25);
        assert_eq!(score.routing_tradeoff_weights.human_review_percent, 75);
        assert_eq!(score.retry_rework_adjustment_microunits, 0);
        assert_eq!(
            score.human_review_adjustment_microunits,
            score.human_review_cost_proxy_microunits * 75 / 25
        );
        assert_eq!(
            score.total_adjustment_microunits,
            score.human_review_adjustment_microunits
        );
        assert_eq!(
            score.total_score_microunits,
            score.legacy_baseline_score_microunits + score.total_adjustment_microunits
        );
    }
}

#[test]
fn retry_and_review_cost_proxy_adjustments_are_proportional_to_the_monetary_baseline() {
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "retry-and-review-sensitive-routing-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 50;
    profile.tradeoffs.retry_rework_percent = 25;
    profile.tradeoffs.human_review_percent = 25;
    let mut input = base_input();
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );

    let decision = select(&input).expect("supported retry/review adjusted selection");
    for candidate in decision
        .candidate_set
        .iter()
        .filter(|candidate| candidate.eligible)
    {
        let score = candidate.score.as_ref().expect("eligible score");
        assert_eq!(
            score.retry_rework_adjustment_microunits,
            score.retry_rework_cost_proxy_microunits * 25 / 50
        );
        assert_eq!(
            score.human_review_adjustment_microunits,
            score.human_review_cost_proxy_microunits * 25 / 50
        );
        assert_eq!(
            score.total_adjustment_microunits,
            score.retry_rework_adjustment_microunits + score.human_review_adjustment_microunits
        );
        assert_eq!(
            score.total_score_microunits,
            score.legacy_baseline_score_microunits + score.total_adjustment_microunits
        );
    }
}

#[test]
fn resolved_routing_objective_round_trips_and_invalid_binding_fails_closed() {
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.id = "review-aware-routing-v1".to_string();
    profile.tradeoffs.monetary_cost_percent = 50;
    profile.tradeoffs.human_review_percent = 50;
    let mut input = base_input();
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
    );
    let input_json = serde_json::to_value(&input).expect("serialize selection input");
    let input_round_trip: SelectionInput =
        serde_json::from_value(input_json.clone()).expect("deserialize selection input");
    assert_eq!(input_round_trip, input);
    let decision = select(&input_round_trip).expect("selection with resolved objective");
    assert_eq!(
        decision.resolved_objective_profile,
        input.resolved_objective_profile
    );
    let decision_round_trip: SelectionProvenance = serde_json::from_value(
        serde_json::to_value(&decision).expect("serialize selection provenance"),
    )
    .expect("deserialize selection provenance");
    assert_eq!(decision_round_trip, decision);

    let mut missing = input_json.clone();
    missing
        .as_object_mut()
        .expect("selection input object")
        .remove("resolved_objective_profile");
    assert!(serde_json::from_value::<SelectionInput>(missing).is_err());

    let mut invalid_source = input_json;
    invalid_source["resolved_objective_profile"]["source"] =
        serde_json::Value::String("unverified_external".to_string());
    assert!(serde_json::from_value::<SelectionInput>(invalid_source).is_err());

    let mut invalid = input;
    invalid.resolved_objective_profile.profile.content_hash = "0".repeat(64);
    assert!(matches!(
        select(&invalid),
        Err(SelectionError::InvalidInput(message)) if message.contains("content_hash")
    ));
}

#[test]
fn legacy_v2_selector_wire_is_explicitly_rejected_after_objective_split() {
    let mut legacy = base_input();
    legacy.priors.schema_version = 1;
    legacy.objective_profile.version = 2;
    legacy.priors.objective_profiles[0].version = 2;

    let error = select(&legacy).expect_err("legacy v2 selector semantics must fail closed");
    assert!(matches!(
        error,
        SelectionError::InvalidInput(message)
            if message.contains("legacy selector wire is incompatible")
                && message.contains("embedded switch-cost objective semantics")
    ));
}

#[test]
fn cheap_lane_shape_ceilings_survive_pressure_and_loaded_policy() -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    for widened in [false, true] {
        let mut input = base_input();
        input.task.risk = RiskLevel::Low;
        input.task.boundedness = Boundedness::TightlyBounded;
        input.task.context = ContextSize::Small;
        input.task.horizon = TaskHorizon::Short;
        configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok", "cursor"]);
        input.signals.budget_signal = BudgetSignal::Degrade;
        for prior in &mut input.priors.models {
            if prior.model == "gpt-5.6-sol" {
                continue;
            }
            prior.long_context_eligible = true;
            prior.task_shape_ceiling = widened.then(|| TaskShapeCeiling {
                boundedness: [
                    Boundedness::TightlyBounded,
                    Boundedness::Bounded,
                    Boundedness::CrossCutting,
                ]
                .into_iter()
                .collect(),
                maximum_risk: RiskLevel::Critical,
                maximum_context: ContextSize::Long,
                maximum_horizon: TaskHorizon::Long,
            });
        }
        for loaded in [false, true] {
            let evaluate = |input: &SelectionInput| {
                select_with_loaded_routing_policy(input, &[], loaded.then_some(&receipt))
            };
            let tight = evaluate(&input)?;
            assert!(tight.choice.is_some(), "bounded task remains eligible");
            let mut unknown = input.clone();
            unknown.task.risk = RiskLevel::Unknown;
            assert!(evaluate(&unknown).is_err());
            for catalog in &tight.normalized_input.catalogs {
                for model in &catalog.models {
                    if model.model != "gpt-5.6-sol" {
                        assert_eq!(model.capabilities.maximum_risk, RiskLevel::Medium);
                        assert_eq!(model.capabilities.maximum_horizon, TaskHorizon::Medium);
                    }
                }
            }
            for dimension in ["risk", "boundedness", "context", "horizon"] {
                let mut broad = input.clone();
                match dimension {
                    "risk" => broad.task.risk = RiskLevel::High,
                    "boundedness" => broad.task.boundedness = Boundedness::CrossCutting,
                    "context" => broad.task.context = ContextSize::Large,
                    "horizon" => broad.task.horizon = TaskHorizon::Long,
                    _ => unreachable!(),
                }
                let decision = evaluate(&broad)?;
                assert!(decision.choice.is_none(), "{dimension}, loaded={loaded}");
                for candidate in decision
                    .candidate_set
                    .iter()
                    .filter(|candidate| candidate.candidate.model != "gpt-5.6-sol")
                {
                    assert!(!candidate.eligible);
                    assert!(candidate.ineligibility_reasons.iter().any(|reason| {
                        reason.code == IneligibilityCode::TaskShapeNotAdvertised
                    }));
                }
                assert_eq!(evaluate(&decision.normalized_input)?, decision);
            }
        }
    }
    Ok(())
}

#[test]
fn task_shape_ceiling_prior_compatibility_and_validation() -> anyhow::Result<()> {
    let priors = built_in_prior_dataset()?;
    validate_prior_dataset(&priors)?;
    let prior = priors
        .models
        .iter()
        .find(|prior| prior.model == "gpt-5.6-luna")
        .unwrap();
    let mut legacy = serde_json::to_value(prior)?;
    legacy.as_object_mut().unwrap().remove("task_shape_ceiling");
    let legacy: ModelPrior = serde_json::from_value(legacy)?;
    assert!(legacy.task_shape_ceiling.is_none());
    let legacy_wire = serde_json::to_value(&legacy)?;
    assert_eq!(
        legacy_wire.get("task_shape_ceiling"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(serde_json::from_value::<ModelPrior>(legacy_wire)?, legacy);
    assert_eq!(
        effective_task_shape_ceiling(&legacy.runtime, &legacy.model, None)?,
        TaskShapeCeiling::bounded_terminal()
    );
    let mut invalid = priors.clone();
    invalid.models[0]
        .task_shape_ceiling
        .as_mut()
        .unwrap()
        .maximum_risk = RiskLevel::Unknown;
    assert!(validate_prior_dataset(&invalid).is_err());
    let mut input = base_input();
    input.priors = invalid;
    assert!(select(&input).is_err());
    let mut narrow = TaskShapeCeiling::bounded_terminal();
    narrow.maximum_risk = RiskLevel::Low;
    let mut input = base_input();
    input
        .priors
        .models
        .iter_mut()
        .find(|model| model.model == prior.model)
        .unwrap()
        .task_shape_ceiling = Some(narrow);
    let decision = select(&input)?;
    let narrowed = decision
        .candidate_set
        .iter()
        .find(|row| row.candidate.model == prior.model)
        .unwrap();
    assert!(!narrowed.eligible);
    assert!(narrowed
        .ineligibility_reasons
        .iter()
        .any(|reason| { reason.code == IneligibilityCode::TaskShapeNotAdvertised }));
    let unqualified = effective_task_shape_ceiling("unknown", "new-model", None)?;
    assert_eq!(unqualified, TaskShapeCeiling::bounded_terminal());
    let wire = serde_json::to_value(select(&base_input())?)?;
    let decoded: SelectionProvenance = serde_json::from_value(wire)?;
    assert_eq!(select(&decoded.normalized_input)?, decoded);
    let schema = selection_event_schema_value();
    let model_schema = &schema["properties"]["provenance"]["properties"]["normalized_input"]
        ["properties"]["priors"]["properties"]["models"]["items"];
    assert!(model_schema["properties"]["task_shape_ceiling"].is_object());
    assert!(model_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field == "task_shape_ceiling"));
    Ok(())
}

#[test]
fn built_in_data_is_dated_and_keeps_policy_in_data() {
    let priors = built_in_prior_dataset().expect("built-in priors");
    let _: &SelectorCalibration = &priors.objective_profiles[0];
    assert_eq!(priors.revision, "2026-10-29.1");
    assert_eq!(priors.published_on, "2026-10-29");
    assert_eq!(priors.schema_version, 2);
    assert_eq!(priors.models.len(), 9);
    assert_eq!(priors.objective_profiles[0].version, 3);
    assert_eq!(priors.objective_profiles[0].effective_date, "2026-08-26");
    assert!(priors.models.iter().any(|prior| prior.prohibited));
    assert!(priors
        .models
        .iter()
        .any(|prior| !prior.strong_gate_fallback_efforts.is_empty()));
    assert_eq!(
        base_input().resolved_objective_profile.profile.switch_costs,
        ContextSwitchCosts::default()
    );
}

const ALL_AUTHORITY_ROLES: [AuthorityRole; 9] = [
    AuthorityRole::TerminalLeaf,
    AuthorityRole::Delegating,
    AuthorityRole::AcceptanceGate,
    AuthorityRole::ReviewAuditor,
    AuthorityRole::Audit,
    AuthorityRole::ConflictResolution,
    AuthorityRole::FailureClassification,
    AuthorityRole::GitPublication,
    AuthorityRole::UnknownJudgment,
];

fn current_codex_input(authority: AuthorityRole) -> SelectionInput {
    let mut input = base_input();
    input.task.authority_role = authority;
    if authority != AuthorityRole::TerminalLeaf {
        input.task.task_class = "review_gate".into();
        input.task.risk = RiskLevel::Critical;
        input.task.boundedness = Boundedness::CrossCutting;
        input.task.context = ContextSize::Long;
        input.task.horizon = TaskHorizon::Long;
    }
    input.catalogs = vec![catalog(
        "codex",
        "codex-0.162.0",
        &input.task.task_class,
        authority,
        &[
            (
                "gpt-6-astra",
                &[
                    ReasoningEffort::None,
                    ReasoningEffort::Minimal,
                    ReasoningEffort::Low,
                    ReasoningEffort::Medium,
                    ReasoningEffort::High,
                    ReasoningEffort::Xhigh,
                    ReasoningEffort::Max,
                    ReasoningEffort::Ultra,
                ],
                true,
            ),
            (
                "gpt-6.1-sol",
                &[ReasoningEffort::High, ReasoningEffort::Xhigh],
                true,
            ),
        ],
    )];
    input.pools = vec![pool("codex", 0)];
    input
}

#[test]
fn current_codex_priors_keep_owner_policy_distinct_from_measured_evidence() {
    let priors = built_in_prior_dataset().expect("built-in priors");
    validate_prior_dataset(&priors).expect("valid built-in priors");
    let prior = |model| {
        priors
            .models
            .iter()
            .find(|prior| prior.runtime == "codex" && prior.model == model)
            .expect("Codex policy prior")
    };
    let sol = prior("gpt-6.1-sol");
    let previous = prior("gpt-5.6-sol");
    assert!(sol.source_id.starts_with("owner-policy-"));
    assert!(sol.limitations.iter().any(|limitation| limitation
        .contains("owner-policy baseline values")
        && limitation.contains("not measured local evidence")));
    assert_eq!(sol.class_fit, previous.class_fit);
    assert!(sol.strength_rank > previous.strength_rank);
    assert_eq!(
        sol.strong_gate_fallback_efforts,
        previous.strong_gate_fallback_efforts
    );
    assert!(sol.authority_evidence.is_empty());
    let astra = prior("gpt-6-astra");
    let terra = prior("gpt-5.6-terra");
    assert!(astra.prohibited && terra.prohibited);
    assert!(astra
        .prohibition_reason
        .as_ref()
        .unwrap()
        .contains("owner policy"));
    assert_eq!(
        astra.prohibited_authority_roles,
        terra.prohibited_authority_roles
    );
    assert_eq!(
        astra.prohibited_authority_roles,
        ALL_AUTHORITY_ROLES.into_iter().collect()
    );
    for model in ["gpt-6-sol", "gpt-6-luna"] {
        assert_eq!(
            priors.measured_authority_eligibility(model, AuthorityRole::TerminalLeaf),
            MeasuredAuthorityEligibility::NoDatedEvidence
        );
    }
}

#[test]
fn current_sol_passes_judgment_admission_while_astra_is_prohibited() -> anyhow::Result<()> {
    use crate::supervise::{
        admit_role_category, validate_known_judgment_role_model, AgentRole, RoleCategory,
    };

    for role in [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::Researcher,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ] {
        validate_known_judgment_role_model(role, Some("gpt-6.1-sol"))?;
        let denied = validate_known_judgment_role_model(role, Some("gpt-6-astra"))
            .expect_err("standing owner prohibition must precede static capability fallback");
        assert!(denied.to_string().contains("standing owner policy"));
    }
    for category in [
        RoleCategory::DelegatingCoordinator,
        RoleCategory::ReadOnlyReviewAuditor,
    ] {
        admit_role_category(category, Some("gpt-6.1-sol"))?;
        assert!(admit_role_category(category, Some("gpt-6-astra")).is_err());
    }
    Ok(())
}

#[test]
fn no_prior_astra_is_refused_by_loaded_policy_and_legacy_selector() -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    let mut input = current_codex_input(AuthorityRole::AcceptanceGate);
    // Removing the dated prohibition cannot grant an unknown model judgment authority.
    input
        .priors
        .models
        .retain(|prior| prior.model != "gpt-6-astra");
    input.catalogs[0]
        .models
        .retain(|model| model.model == "gpt-6-astra");
    assert_eq!(
        input
            .priors
            .measured_authority_eligibility("gpt-6-astra", input.task.authority_role),
        MeasuredAuthorityEligibility::NoDatedEvidence
    );
    let legacy = select(&input)?;
    assert!(legacy.choice.is_none());
    assert!(legacy.candidate_set.iter().all(|evaluation| evaluation
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::MissingDatedPrior)));
    let loaded = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert!(loaded.choice.is_none());
    assert!(!loaded.candidate_set.is_empty());
    assert!(loaded.candidate_set.iter().all(|evaluation| {
        !evaluation.eligible
            && evaluation.score.is_none()
            && evaluation.ineligibility_reasons.iter().any(|reason| {
                reason.code == IneligibilityCode::MissingDatedPrior
                    && reason
                        .detail
                        .contains("judgment authority requires a dated model prior")
            })
    }));
    Ok(())
}

#[test]
fn current_codex_policy_excludes_astra_for_every_authority_and_catalog_fallback(
) -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    for authority in ALL_AUTHORITY_ROLES {
        let input = current_codex_input(authority);
        assert!(matches!(
            input
                .priors
                .measured_authority_eligibility("gpt-6-astra", authority),
            MeasuredAuthorityEligibility::Ineligible { .. }
        ));
        assert_eq!(
            input
                .priors
                .measured_authority_eligibility("gpt-6.1-sol", authority),
            MeasuredAuthorityEligibility::Eligible
        );
        for routing in [None, Some(&receipt)] {
            let decision = select_with_loaded_routing_policy(&input, &[], routing)?;
            let astra = decision
                .candidate_set
                .iter()
                .filter(|evaluation| evaluation.candidate.model == "gpt-6-astra")
                .collect::<Vec<_>>();
            assert_eq!(astra.len(), 8);
            assert!(astra.iter().all(|evaluation| !evaluation.eligible
                && evaluation.score.is_none()
                && evaluation
                    .ineligibility_reasons
                    .iter()
                    .any(|reason| reason.code == IneligibilityCode::PolicyProhibited)));
            if authority == AuthorityRole::UnknownJudgment {
                assert!(decision.choice.is_none());
            } else {
                let choice = decision.choice.expect("permitted Sol choice");
                assert_eq!(choice.candidate.model, "gpt-6.1-sol");
                if routing.is_none() && authority != AuthorityRole::TerminalLeaf {
                    assert_eq!(
                        choice.reason,
                        ChoiceReason::StrongestNoEvidenceJudgmentFallback
                    );
                    assert_eq!(choice.candidate.effort, ReasoningEffort::Xhigh);
                }
            }
            let mut withdrawn = input.clone();
            withdrawn.catalogs[0]
                .models
                .retain(|model| model.model != "gpt-6.1-sol");
            assert!(select_with_loaded_routing_policy(&withdrawn, &[], routing)?
                .choice
                .is_none());
        }
    }
    Ok(())
}

#[test]
fn current_sol_is_the_strongest_approved_no_evidence_judgment_fallback() {
    for authority in ALL_AUTHORITY_ROLES.into_iter().filter(|authority| {
        !matches!(
            authority,
            AuthorityRole::TerminalLeaf | AuthorityRole::UnknownJudgment
        )
    }) {
        let mut input = current_codex_input(authority);
        let mut previous = input.catalogs[0].models[1].clone();
        previous.model = "gpt-5.6-sol".into();
        input.catalogs[0].models.push(previous);
        let decision = select(&input).expect("owner-policy default gate fallback");
        let choice = decision.choice.expect("strong Sol judgment choice");
        assert_eq!(choice.candidate.model, "gpt-6.1-sol");
        assert_eq!(
            choice.reason,
            ChoiceReason::StrongestNoEvidenceJudgmentFallback
        );
    }
}

#[test]
fn astra_prohibition_cannot_be_bypassed_by_environment_fallback_or_debug_override(
) -> anyhow::Result<()> {
    let receipt = loaded_policy_test_receipt()?;
    for authority in ALL_AUTHORITY_ROLES {
        let mut input = current_codex_input(authority);
        let source = CandidateKey {
            runtime: "codex".into(),
            model: "gpt-6.1-sol".into(),
            effort: ReasoningEffort::Xhigh,
        };
        let target = CandidateKey {
            model: "gpt-6-astra".into(),
            ..source.clone()
        };
        input
            .priors
            .models
            .iter_mut()
            .find(|prior| prior.model == source.model)
            .unwrap()
            .one_shot_environment_fallbacks
            .push(OneShotEnvironmentFallback {
                rejection_code: "test_environment_rejection".into(),
                target_runtime: target.runtime.clone(),
                target_model: target.model.clone(),
                target_effort: target.effort,
            });
        input.signals.previous_choice = Some(source.clone());
        input
            .signals
            .environment_rejections
            .push(EnvironmentRejectionState {
                candidate: source,
                rejection_code: "test_environment_rejection".into(),
                evidence_id: "test-rejection-evidence".into(),
                fallback_transition_used: false,
            });
        if authority != AuthorityRole::UnknownJudgment {
            let mut no_prior = input.clone();
            no_prior
                .priors
                .models
                .retain(|prior| prior.model != target.model);
            if authority != AuthorityRole::TerminalLeaf {
                let broad = select_with_loaded_routing_policy(&no_prior, &[], Some(&receipt))?;
                assert!(broad.environment_fallback.is_none());
                assert!(broad
                    .candidate_set
                    .iter()
                    .filter(|evaluation| evaluation.candidate.model == target.model)
                    .all(|evaluation| !evaluation.eligible
                        && evaluation.ineligibility_reasons.iter().any(|reason| {
                            reason.code == IneligibilityCode::TaskShapeNotAdvertised
                        })));
            }
            // Isolate authority from the independent bundled shape ceiling.
            input.task.risk = RiskLevel::Medium;
            input.task.boundedness = Boundedness::Bounded;
            input.task.context = ContextSize::Medium;
            input.task.horizon = TaskHorizon::Medium;
            no_prior.task = input.task.clone();
            let control = select_with_loaded_routing_policy(&no_prior, &[], Some(&receipt))?;
            assert_eq!(
                control
                    .choice
                    .expect("unmeasured environment fallback")
                    .reason,
                ChoiceReason::OneShotEnvironmentFallback
            );
            assert_eq!(control.environment_fallback.unwrap().target, target);
            if authority != AuthorityRole::TerminalLeaf {
                // The source declaration authorizes only this unused transition,
                // never ordinary unknown-model judgment or a debug override.
                for invalidation in 0..5 {
                    let mut invalid = no_prior.clone();
                    match invalidation {
                        0 => {
                            invalid.signals.environment_rejections[0].fallback_transition_used =
                                true
                        }
                        1 => {
                            invalid.signals.environment_rejections[0].rejection_code =
                                "different_rejection".into()
                        }
                        2 => invalid.signals.previous_choice = None,
                        3 => invalid
                            .priors
                            .models
                            .iter_mut()
                            .find(|prior| prior.model == "gpt-6.1-sol")
                            .unwrap()
                            .one_shot_environment_fallbacks
                            .clear(),
                        4 => {
                            invalid.constraints.allow_debug_override = true;
                            invalid.debug_override = Some(DebugOverride {
                                candidate: target.clone(),
                                requested_by: "test operator".into(),
                                reason: "fallback is not debug judgment authority".into(),
                            });
                        }
                        _ => unreachable!(),
                    }
                    let denied = select_with_loaded_routing_policy(&invalid, &[], Some(&receipt))?;
                    assert!(
                        denied
                            .choice
                            .as_ref()
                            .is_none_or(|choice| choice.candidate.model != target.model),
                        "{authority:?}, case {invalidation}"
                    );
                    assert!(denied.environment_fallback.is_none());
                    assert!(
                        denied
                            .candidate_set
                            .iter()
                            .filter(|evaluation| { evaluation.candidate.model == target.model })
                            .all(|evaluation| !evaluation.eligible
                                && evaluation.score.is_none()
                                && evaluation.ineligibility_reasons.iter().any(|reason| {
                                    reason.code == IneligibilityCode::MissingDatedPrior
                                })),
                        "{authority:?}, case {invalidation}"
                    );
                }
            }
        }
        for routing in [None, Some(&receipt)] {
            let decision = select_with_loaded_routing_policy(&input, &[], routing)?;
            assert!(decision.environment_fallback.is_none());
            assert!(decision
                .candidate_set
                .iter()
                .filter(|evaluation| evaluation.candidate.model == target.model)
                .all(|evaluation| !evaluation.eligible
                    && evaluation.score.is_none()
                    && evaluation
                        .ineligibility_reasons
                        .iter()
                        .any(|reason| { reason.code == IneligibilityCode::PolicyProhibited })));
            assert!(decision
                .choice
                .is_none_or(|choice| choice.candidate.model == "gpt-6.1-sol"));
            let mut overridden = input.clone();
            overridden.constraints.allow_debug_override = true;
            overridden.debug_override = Some(DebugOverride {
                candidate: target.clone(),
                requested_by: "test operator".into(),
                reason: "prove the standing prohibition survives an explicit override".into(),
            });
            let decision = select_with_loaded_routing_policy(&overridden, &[], routing)?;
            assert!(decision.choice.is_none());
            assert_eq!(
                decision.debug_override.unwrap().disposition,
                DebugOverrideDisposition::Rejected
            );
        }
    }
    Ok(())
}

#[test]
fn configured_resolved_prior_and_inferred_evidence_charge_conservative_maximum() {
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };

    for cost in [0, 20_000, 400_000] {
        let decision = select(&codex_model_switch_input(cost)).expect("inferred-prior selection");
        let switch_score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == switch)
            .and_then(|evaluation| evaluation.score.as_ref())
            .expect("switch score");
        assert_eq!(switch_score.configured_switch_cost_microunits, cost);
        assert_eq!(
            switch_score.configured_switch_cost_origin,
            ConfiguredSwitchCostOrigin::ResolvedProfileInferredPrior
        );
        assert_eq!(
            switch_score.switch_cost_origin,
            SwitchCostEvidenceOrigin::OptimizerColdStartPrior
        );
        assert_eq!(
            switch_score.switch_cost_estimate.status,
            crate::optimizer::switch_cost::SwitchEvidenceStatus::Inferred
        );
        let evidence_derived = u64::try_from(
            switch_score
                .switch_cost_estimate
                .explicit_objective_term_micros(),
        )
        .expect("nonnegative inferred switch estimate");
        assert_eq!(
            switch_score.applied_switch_cost_microunits,
            evidence_derived.max(cost)
        );
        assert!(switch_score.switch_cost_microunits >= switch_score.applied_switch_cost_microunits);
    }
}

#[test]
fn measured_optimizer_switch_evidence_is_applied_and_preserved_for_ranking() {
    let input = codex_model_switch_input(0);
    let stay = input
        .signals
        .previous_choice
        .clone()
        .expect("previous candidate");
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    let measured = crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
        crate::optimizer::switch_cost::TransitionClass::ModelChangeSameRuntime,
        0,
        0,
        0,
        1_000_000,
        crate::optimizer::resources::ObservationKind::Measured,
    );

    let decision = select_with_switch_cost_estimates(
        &input,
        &[CandidateSwitchCostEvidence {
            candidate: switch.clone(),
            estimate: measured.clone(),
        }],
    )
    .expect("selection with canonical measured switch evidence");

    assert_eq!(
        decision
            .choice
            .as_ref()
            .expect("measured-cost choice")
            .candidate,
        stay,
        "measured optimizer evidence must be applied to the literal stay/switch comparison"
    );
    let runner_up = decision
        .runner_up_scores
        .iter()
        .find(|score| score.candidate == switch)
        .expect("measured switch runner-up");
    assert_eq!(
        runner_up.switch_cost_origin,
        SwitchCostEvidenceOrigin::OptimizerEstimate
    );
    assert_eq!(runner_up.switch_cost_estimate, measured);
    assert_eq!(runner_up.configured_switch_cost_microunits, 0);
    assert_eq!(
        runner_up.configured_switch_cost_origin,
        ConfiguredSwitchCostOrigin::ResolvedProfileInferredPrior
    );
    assert_eq!(runner_up.applied_switch_cost_microunits, 1_000_000);
    assert!(runner_up.switch_cost_microunits >= 1_000_000);
    assert_eq!(decision.provided_switch_cost_evidence.len(), 1);
    let replay = select_with_switch_cost_estimates(
        &decision.normalized_input,
        &decision.provided_switch_cost_evidence,
    )
    .expect("self-contained switch-evidence replay");
    assert_eq!(replay, decision);
}

#[test]
fn explicit_fresh_session_estimate_overrides_candidate_key_transition_class() {
    let input = codex_model_switch_input(0);
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    let fresh = crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
        crate::optimizer::switch_cost::TransitionClass::FreshSessionOrWorktree,
        0,
        0,
        0,
        1,
        crate::optimizer::resources::ObservationKind::Measured,
    );
    let decision = select_with_switch_cost_estimates(
        &input,
        &[CandidateSwitchCostEvidence {
            candidate: switch.clone(),
            estimate: fresh.clone(),
        }],
    )
    .expect("fresh-session selection");
    let choice = decision.choice.expect("fresh-session choice");
    assert_eq!(choice.candidate, switch);
    assert_eq!(
        choice.switch_transition,
        crate::optimizer::switch_cost::TransitionClass::FreshSessionOrWorktree
    );
    assert_eq!(choice.switch_cost_estimate, fresh);
    assert_eq!(
        choice.switch_cost_origin,
        SwitchCostEvidenceOrigin::OptimizerEstimate
    );
    assert_eq!(choice.applied_switch_cost_microunits, 1);
    assert!(choice.switch_cost_microunits >= 1);
}

#[test]
fn supplied_inferred_optimizer_estimate_is_charged_without_relabelling() {
    let input = codex_model_switch_input(0);
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    let inferred = crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
        crate::optimizer::switch_cost::TransitionClass::ModelChangeSameRuntime,
        0,
        0,
        0,
        1_000_000,
        crate::optimizer::resources::ObservationKind::Inferred,
    );
    let decision = select_with_switch_cost_estimates(
        &input,
        &[CandidateSwitchCostEvidence {
            candidate: switch.clone(),
            estimate: inferred.clone(),
        }],
    )
    .expect("inferred-evidence selection");
    let score = decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == switch)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("inferred-evidence switch score");
    assert_eq!(score.switch_cost_estimate, inferred);
    assert_eq!(
        score.switch_cost_origin,
        SwitchCostEvidenceOrigin::OptimizerEstimate
    );
    assert_eq!(score.applied_switch_cost_microunits, 1_000_000);
    assert!(score.switch_cost_microunits >= 1_000_000);
}

#[test]
fn supplied_runtime_transition_uses_canonical_runtime_class() {
    let mut input = base_input();
    input.signals.previous_choice = Some(CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-sol".to_string(),
        effort: ReasoningEffort::High,
    });
    let runtime = CandidateKey {
        runtime: "grok".to_string(),
        model: "grok-code-fast-1".to_string(),
        effort: ReasoningEffort::High,
    };
    let measured = crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
        crate::optimizer::switch_cost::TransitionClass::RuntimeAdapterChange,
        0,
        0,
        1,
        0,
        crate::optimizer::resources::ObservationKind::Measured,
    );
    let decision = select_with_switch_cost_estimates(
        &input,
        &[CandidateSwitchCostEvidence {
            candidate: runtime.clone(),
            estimate: measured.clone(),
        }],
    )
    .expect("runtime evidence selection");
    let score = decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == runtime)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("runtime score");
    assert_eq!(
        score.switch_transition,
        TransitionClass::RuntimeAdapterChange
    );
    assert_eq!(score.switch_cost_estimate, measured);
    assert_eq!(score.applied_switch_cost_microunits, 25_000);
    assert!(score.switch_cost_microunits >= 25_000);
}

#[test]
fn duplicate_mismatched_and_invalid_switch_evidence_fail_closed() {
    let input = codex_model_switch_input(0);
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    let measured = crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
        TransitionClass::ModelChangeSameRuntime,
        0,
        0,
        0,
        10,
        crate::optimizer::resources::ObservationKind::Measured,
    );
    let item = CandidateSwitchCostEvidence {
        candidate: switch.clone(),
        estimate: measured.clone(),
    };
    assert!(matches!(
        select_with_switch_cost_estimates(&input, &[item.clone(), item]),
        Err(SelectionError::InvalidInput(message)) if message.contains("duplicate candidate")
    ));

    let mismatched = CandidateSwitchCostEvidence {
        candidate: switch.clone(),
        estimate: crate::optimizer::switch_cost::SwitchCostEstimate::from_explicit_terms(
            TransitionClass::RuntimeAdapterChange,
            0,
            0,
            10,
            0,
            crate::optimizer::resources::ObservationKind::Measured,
        ),
    };
    assert!(matches!(
        select_with_switch_cost_estimates(&input, &[mismatched]),
        Err(SelectionError::InvalidInput(message)) if message.contains("candidate keys imply")
    ));

    let mut invalid = measured;
    invalid.total_cost_micros += 1;
    assert!(matches!(
        select_with_switch_cost_estimates(
            &input,
            &[CandidateSwitchCostEvidence {
                candidate: switch,
                estimate: invalid,
            }],
        ),
        Err(SelectionError::InvalidInput(message)) if message.contains("aggregate fields conflict")
    ));
}

#[test]
fn continue_model_and_runtime_transitions_are_typed_with_honest_fallbacks() {
    let initial = select(&base_input()).expect("initial selection");
    assert!(initial
        .candidate_set
        .iter()
        .filter_map(|candidate| candidate.score.as_ref())
        .all(
            |score| score.switch_transition == ContextSwitchTransition::Initial
                && score.configured_switch_cost_microunits == 0
                && score.switch_cost_microunits == 0
        ));

    let previous = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-sol".to_string(),
        effort: ReasoningEffort::High,
    };
    let mut input = base_input();
    input.signals.previous_choice = Some(previous.clone());
    let decision = select(&input).expect("transition classification");
    let score_for = |candidate: &CandidateKey| {
        decision
            .candidate_set
            .iter()
            .find(|evaluation| &evaluation.candidate == candidate)
            .and_then(|evaluation| evaluation.score.as_ref())
            .expect("eligible candidate score")
    };

    let stay = score_for(&previous);
    assert_eq!(stay.switch_transition, ContextSwitchTransition::Stay);
    assert_eq!(stay.switch_cost_microunits, 0);

    let effort = score_for(&CandidateKey {
        effort: ReasoningEffort::Xhigh,
        ..previous.clone()
    });
    assert_eq!(
        effort.switch_transition,
        ContextSwitchTransition::EffortChangeSameRuntimeModel
    );
    assert_eq!(effort.configured_switch_cost_microunits, 0);
    assert_eq!(effort.switch_cost_microunits, 0);

    let model = score_for(&CandidateKey {
        model: "gpt-5.6-luna".to_string(),
        ..previous.clone()
    });
    assert_eq!(
        model.switch_transition,
        ContextSwitchTransition::ModelChangeSameRuntime
    );
    assert_eq!(model.configured_switch_cost_microunits, 10_000);
    assert_eq!(
        model.switch_cost_origin,
        SwitchCostEvidenceOrigin::OptimizerColdStartPrior
    );
    assert_eq!(
        model.configured_switch_cost_origin,
        ConfiguredSwitchCostOrigin::ResolvedProfileInferredPrior
    );
    assert_eq!(
        model.switch_cost_estimate.status,
        crate::optimizer::switch_cost::SwitchEvidenceStatus::Inferred
    );
    assert_eq!(model.switch_cost_estimate.sample_count, 0);
    assert!(
        model
            .switch_cost_estimate
            .provenance
            .cached_prefix_invalidation
            .source
            == crate::optimizer::switch_cost::SwitchEvidenceSource::ColdStartPrior
    );
    assert!(model.applied_switch_cost_microunits > 0);
    assert!(model.switch_cost_microunits > 0);
    assert!(
        model.switch_cost_estimate.uncertainty_micros.lower
            < model.switch_cost_estimate.total_cost_micros
    );
    assert!(
        model.switch_cost_estimate.uncertainty_micros.upper
            > model.switch_cost_estimate.total_cost_micros
    );

    let runtime = score_for(&CandidateKey {
        runtime: "grok".to_string(),
        model: "grok-code-fast-1".to_string(),
        effort: ReasoningEffort::High,
    });
    assert_eq!(
        runtime.switch_transition,
        ContextSwitchTransition::RuntimeChange
    );
    assert_eq!(runtime.configured_switch_cost_microunits, 25_000);
    assert_eq!(
        runtime.switch_cost_origin,
        SwitchCostEvidenceOrigin::OptimizerColdStartPrior
    );
    assert!(runtime.applied_switch_cost_microunits > 0);
    assert!(runtime.switch_cost_microunits > 0);
}

#[test]
fn zero_config_still_prices_inferred_switches_and_keeps_continue_zero() {
    let decision = select(&codex_model_switch_input(0)).expect("zero-config selection");

    for evaluation in &decision.candidate_set {
        let score = evaluation.score.as_ref().expect("candidate score");
        assert_eq!(
            score.switch_cost_microunits == 0,
            !score.switch_transition.is_switch()
        );
    }
}

#[test]
fn switch_evidence_round_trips_and_matches_selected_and_runner_up_scores() {
    let decision = select(&codex_model_switch_input(20_000)).expect("switch decision");
    let selected = decision.choice.as_ref().expect("selected choice");
    let selected_score = decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == selected.candidate)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("selected candidate score");
    assert_eq!(selected.switch_transition, selected_score.switch_transition);
    assert_eq!(
        selected.switch_cost_origin,
        selected_score.switch_cost_origin
    );
    assert_eq!(
        selected.switch_cost_estimate,
        selected_score.switch_cost_estimate
    );
    assert_eq!(
        selected.configured_switch_cost_microunits,
        selected_score.configured_switch_cost_microunits
    );
    assert_eq!(
        selected.configured_switch_cost_origin,
        selected_score.configured_switch_cost_origin
    );
    assert_eq!(
        selected.applied_switch_cost_microunits,
        selected_score.applied_switch_cost_microunits
    );
    assert_eq!(
        selected.switch_cost_microunits,
        selected_score.switch_cost_microunits
    );
    assert_eq!(
        selected.total_score_microunits,
        selected_score.total_score_microunits
    );

    for runner_up in &decision.runner_up_scores {
        let score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == runner_up.candidate)
            .and_then(|evaluation| evaluation.score.as_ref())
            .expect("runner-up score");
        assert_eq!(runner_up.switch_transition, score.switch_transition);
        assert_eq!(runner_up.switch_cost_origin, score.switch_cost_origin);
        assert_eq!(runner_up.switch_cost_estimate, score.switch_cost_estimate);
        assert_eq!(
            runner_up.configured_switch_cost_microunits,
            score.configured_switch_cost_microunits
        );
        assert_eq!(
            runner_up.configured_switch_cost_origin,
            score.configured_switch_cost_origin
        );
        assert_eq!(
            runner_up.applied_switch_cost_microunits,
            score.applied_switch_cost_microunits
        );
        assert_eq!(
            runner_up.switch_cost_microunits,
            score.switch_cost_microunits
        );
        assert_eq!(
            runner_up.total_score_microunits,
            score.total_score_microunits
        );
    }

    let json = serde_json::to_vec(&decision).expect("serialize selection evidence");
    let round_trip: SelectionProvenance =
        serde_json::from_slice(&json).expect("deserialize selection evidence");
    assert_eq!(round_trip, decision);
    assert_eq!(round_trip.schema_version, 4);
}

#[test]
fn selector_calibration_rejects_duplicate_objective_switch_costs() {
    let mut value =
        serde_json::to_value(built_in_prior_dataset().expect("priors")).expect("serialize priors");
    value["objective_profiles"][0]["switch_costs"] = serde_json::json!({
        "model_change_same_runtime_microunits": 10_000,
        "runtime_change_microunits": 25_000
    });
    assert!(serde_json::from_value::<PriorDataset>(value).is_err());
}

#[test]
fn unnormalizable_maximum_resolved_profile_switch_cost_fails_closed() {
    let mut input = codex_model_switch_input(u64::MAX);
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.switch_costs.model_change_same_runtime_microunits = u64::MAX;
    profile.switch_costs.runtime_change_microunits = u64::MAX;
    input.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::BuiltIn,
    );
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("context-switch cost per accepted task overflowed u64")
    ));
}

#[test]
fn measured_eligibility_keeps_static_table_from_overriding_dated_ineligibility() {
    let priors = built_in_prior_dataset().expect("built-in priors");
    assert!(matches!(
        priors.measured_authority_eligibility("gpt-5.6-luna", AuthorityRole::TerminalLeaf),
        MeasuredAuthorityEligibility::Eligible
    ));
    assert!(matches!(
        priors.measured_authority_eligibility("gpt-5.6-luna", AuthorityRole::Delegating),
        MeasuredAuthorityEligibility::Ineligible { .. }
    ));
    assert!(matches!(
        priors.measured_authority_eligibility("gpt-5.6-terra", AuthorityRole::TerminalLeaf),
        MeasuredAuthorityEligibility::Ineligible { .. }
    ));
    assert!(matches!(
        priors.measured_authority_eligibility("gpt-5.6-sol", AuthorityRole::AcceptanceGate),
        MeasuredAuthorityEligibility::Eligible
    ));
    assert_eq!(
        priors.measured_authority_eligibility("unknown-model", AuthorityRole::Delegating),
        MeasuredAuthorityEligibility::NoDatedEvidence
    );
    assert!(matches!(
        measured_authority_eligibility("gpt-5.6-luna", AuthorityRole::Delegating)
            .expect("built-in eligibility"),
        MeasuredAuthorityEligibility::Ineligible { .. }
    ));
}

#[test]
fn owner_same_class_fixture_uses_codex_fresh_and_alternate_under_pressure() {
    let fresh = select(&base_input()).expect("fresh selection");
    assert_eq!(fresh.status, DecisionStatus::Selected);
    assert_eq!(
        fresh
            .choice
            .as_ref()
            .expect("fresh choice")
            .candidate
            .runtime,
        "codex"
    );
    assert!(fresh.quota.is_none());

    let mut pressured = base_input();
    pressured
        .pools
        .iter_mut()
        .find(|pool| pool.runtime == "codex")
        .expect("Codex pool")
        .pool_pressure_basis_points = 10_000;
    let pressured = select(&pressured).expect("pressured selection");
    assert!(matches!(
        pressured
            .choice
            .as_ref()
            .map(|choice| choice.candidate.runtime.as_str()),
        Some("grok" | "cursor")
    ));
}

#[test]
fn exhausted_source_degrades_only_to_an_exact_authorized_pool() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok"]);

    let decision = select(&input).expect("authorized quota degrade");
    let choice = decision.choice.as_ref().expect("authorized alternative");
    assert_eq!(choice.candidate.runtime, "grok");
    assert_eq!(choice.reason, ChoiceReason::AuthorizedQuotaDegrade);
    assert!(decision
        .triggers
        .contains(&SelectionTrigger::QuotaExhaustion));
    let quota = decision.quota.as_ref().expect("quota provenance");
    assert_eq!(quota.source_pool, pool_reference("codex"));
    assert_eq!(quota.configured_behavior, ExhaustionBehavior::Degrade);
    assert_eq!(quota.disposition, QuotaDecisionDisposition::Degraded);
    assert_eq!(quota.selected_alternative.as_ref(), Some(&choice.candidate));
    assert!(quota
        .eligible_alternatives
        .iter()
        .all(|candidate| candidate.runtime == "grok"));
    assert!(decision
        .candidate_set
        .iter()
        .filter(|candidate| candidate.candidate.runtime == "cursor")
        .all(|candidate| candidate
            .ineligibility_reasons
            .iter()
            .any(|reason| { reason.code == IneligibilityCode::QuotaAlternativeNotAuthorized })));
}

#[test]
fn fail_closed_exhaustion_refuses_even_with_unrelated_eligible_catalogs() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::FailClosed, &[]);

    let decision = select(&input).expect("quota fail closed");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    assert_eq!(
        decision
            .quota
            .as_ref()
            .expect("quota provenance")
            .disposition,
        QuotaDecisionDisposition::FailClosed
    );
    assert!(decision.candidate_set.iter().all(|candidate| candidate
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::QuotaFailClosed)));
}

#[test]
fn authorized_degrade_refuses_when_the_authorized_pool_fails_catalog_gate() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok"]);
    input
        .catalogs
        .iter_mut()
        .find(|catalog| catalog.runtime == "grok")
        .expect("Grok catalog")
        .models
        .iter_mut()
        .for_each(|model| model.available = false);

    let decision = select(&input).expect("no eligible authorized alternative");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    let quota = decision.quota.expect("quota provenance");
    assert_eq!(
        quota.disposition,
        QuotaDecisionDisposition::RefusedNoEligibleAlternative
    );
    assert!(quota.eligible_alternatives.is_empty());
    assert!(quota.rejected_alternatives.iter().any(|alternative| {
        alternative.candidate.runtime == "grok"
            && alternative
                .reasons
                .iter()
                .any(|reason| reason.code == IneligibilityCode::CatalogUnavailable)
    }));
}

#[test]
fn unauthorized_debug_override_cannot_bypass_exhausted_pool_policy() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok"]);
    input.constraints.allow_debug_override = true;
    input.debug_override = Some(DebugOverride {
        candidate: CandidateKey {
            runtime: "cursor".to_string(),
            model: "cursor-composer-1".to_string(),
            effort: ReasoningEffort::High,
        },
        requested_by: "test operator".to_string(),
        reason: "verify quota authorization remains a hard gate".to_string(),
    });

    let decision = select(&input).expect("debug override refusal");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    assert_eq!(
        decision
            .debug_override
            .as_ref()
            .expect("debug provenance")
            .disposition,
        DebugOverrideDisposition::Rejected
    );
    assert_eq!(
        decision
            .quota
            .as_ref()
            .expect("quota provenance")
            .disposition,
        QuotaDecisionDisposition::RefusedByExplicitOverride
    );
}

#[test]
fn marginal_cost_reorders_only_the_authorized_alternative_set() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok", "cursor"]);
    let first = select(&input)
        .expect("first quota choice")
        .choice
        .expect("first alternative")
        .candidate;
    input
        .pools
        .iter_mut()
        .find(|pool| pool.runtime == first.runtime)
        .expect("selected pool")
        .marginal_cost_microunits = 10_000_000_000;

    let second = select(&input)
        .expect("repriced quota choice")
        .choice
        .expect("repriced alternative")
        .candidate;
    assert_ne!(second.runtime, first.runtime);
    assert!(matches!(second.runtime.as_str(), "grok" | "cursor"));
}

#[test]
fn pool_pressure_cannot_bypass_class_fit_eligibility() {
    let mut input = base_input();
    input
        .pools
        .iter_mut()
        .find(|pool| pool.runtime == "codex")
        .expect("Codex pool")
        .pool_pressure_basis_points = 10_000;
    for catalog in input
        .catalogs
        .iter_mut()
        .filter(|catalog| catalog.runtime != "codex")
    {
        for model in &mut catalog.models {
            model.capabilities.task_classes.clear();
        }
    }
    let decision = select(&input).expect("class-fit constrained selection");
    assert_eq!(
        decision
            .choice
            .as_ref()
            .expect("eligible Codex choice")
            .candidate
            .runtime,
        "codex"
    );
}

#[test]
fn judgment_authority_uses_data_marked_strong_fallback_and_otherwise_fails_closed() {
    let mut strong = base_input();
    strong.task = TaskProfile {
        task_class: "review_gate".to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role: AuthorityRole::AcceptanceGate,
    };
    strong.catalogs = vec![catalog(
        "codex",
        "codex-gate-r1",
        "review_gate",
        AuthorityRole::AcceptanceGate,
        &[("gpt-5.6-sol", &[ReasoningEffort::Xhigh], true)],
    )];
    strong.pools = vec![pool("codex", 0)];
    let decision = select(&strong).expect("strong gate selection");
    assert_eq!(
        decision.choice.as_ref().expect("strong choice").reason,
        ChoiceReason::StrongestNoEvidenceJudgmentFallback
    );
    assert!(decision.candidate_set[0].strong_gate_fallback);

    let mut unknown = strong;
    unknown.catalogs = vec![catalog(
        "grok",
        "grok-gate-r1",
        "review_gate",
        AuthorityRole::AcceptanceGate,
        &[("grok-code-fast-1", &[ReasoningEffort::High], false)],
    )];
    unknown.pools = vec![pool("grok", 0)];
    let decision = select(&unknown).expect("unknown authority decision");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
}

#[test]
fn judgment_fallback_below_xhigh_remains_ineligible_despite_prior_declaration() {
    let mut input = base_input();
    input.task = TaskProfile {
        task_class: "review_gate".to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role: AuthorityRole::AcceptanceGate,
    };
    let prior = input
        .priors
        .models
        .iter_mut()
        .find(|prior| !prior.strong_gate_fallback_efforts.is_empty())
        .expect("dated prior with a strong-gate fallback");
    let mut low_class_fit = prior
        .class_fit
        .iter()
        .find(|class_fit| {
            class_fit.task_class == input.task.task_class
                && class_fit.effort == ReasoningEffort::Xhigh
        })
        .cloned()
        .expect("strong-gate prior has exact xhigh class-fit evidence");
    low_class_fit.effort = ReasoningEffort::Low;
    prior.class_fit.push(low_class_fit);
    prior.strong_gate_fallback_efforts = [ReasoningEffort::Low].into_iter().collect();
    let runtime = prior.runtime.clone();
    let model = prior.model.clone();
    let long_context = prior.long_context_eligible;
    input.catalogs = vec![catalog(
        &runtime,
        "malformed-low-gate-fallback",
        &input.task.task_class,
        input.task.authority_role,
        &[(model.as_str(), &[ReasoningEffort::Low], long_context)],
    )];
    input.pools = vec![pool(&runtime, 0)];
    input.outcomes.push(OutcomeRecord {
        attempt_id: "verified-low-gate-outcome-fixture".to_string(),
        task: input.task.clone(),
        candidate: CandidateKey {
            runtime: runtime.clone(),
            model,
            effort: ReasoningEffort::Low,
        },
        result: OutcomeResult::Accepted,
        failure_class: None,
        execution_cost_microunits: 1,
        review_cost_microunits: 0,
        rework_cost_microunits: 0,
        rereview_cost_microunits: 0,
        environment_cost_microunits: 0,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    });

    let decision = select(&input).expect("low judgment fallback decision");

    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    assert!(!decision.candidate_set[0].strong_gate_fallback);
    assert!(decision.candidate_set[0]
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::MissingAuthorityEvidence));
}

#[test]
fn unknown_judgment_authority_never_uses_strong_fallback() {
    let mut input = base_input();
    input.task = TaskProfile {
        task_class: "review_gate".to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role: AuthorityRole::UnknownJudgment,
    };
    input.catalogs = vec![catalog(
        "codex",
        "codex-unknown-gate-r1",
        "review_gate",
        AuthorityRole::UnknownJudgment,
        &[("gpt-5.6-sol", &[ReasoningEffort::Xhigh], true)],
    )];
    input.pools = vec![pool("codex", 0)];

    let decision = select(&input).expect("unknown judgment decision");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    assert!(!decision.candidate_set[0].strong_gate_fallback);
    assert!(decision.candidate_set[0]
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::UnknownJudgmentAuthority));
}

#[test]
fn eligible_debug_override_is_applied_and_recorded() {
    let mut input = base_input();
    input.constraints.allow_debug_override = true;
    input.debug_override = Some(DebugOverride {
        candidate: CandidateKey {
            runtime: "grok".to_string(),
            model: "grok-code-fast-1".to_string(),
            effort: ReasoningEffort::High,
        },
        requested_by: "test operator".to_string(),
        reason: "replay a bounded debug case".to_string(),
    });
    let decision = select(&input).expect("debug selection");
    assert_eq!(
        decision.choice.as_ref().expect("debug choice").reason,
        ChoiceReason::DebugOverride
    );
    assert_eq!(
        decision
            .debug_override
            .as_ref()
            .expect("debug provenance")
            .disposition,
        DebugOverrideDisposition::Applied
    );
    assert_eq!(decision.triggers, vec![SelectionTrigger::DebugOverride]);
}

#[test]
fn normalization_is_deterministic_across_input_order() {
    let input = base_input();
    let expected = select(&input).expect("ordered selection");
    let mut shuffled = input;
    shuffled.catalogs.reverse();
    shuffled.pools.reverse();
    for catalog in &mut shuffled.catalogs {
        catalog.models.reverse();
        for model in &mut catalog.models {
            model.supported_efforts.reverse();
        }
    }
    shuffled.priors.models.reverse();
    let actual = select(&shuffled).expect("shuffled selection");
    assert_eq!(actual, expected);
}

#[test]
fn retry_degrade_and_catalog_change_are_provenance_triggers() {
    let initial = select(&base_input()).expect("initial decision");
    let mut input = base_input();
    input.signals.retry_count = 1;
    input.signals.budget_signal = BudgetSignal::Degrade;
    input.signals.previous_choice = initial.choice.map(|choice| choice.candidate);
    input.signals.previous_catalog_digest = Some("0".repeat(64));
    let decision = select(&input).expect("dynamic selection");
    assert!(decision.triggers.contains(&SelectionTrigger::Retry));
    assert!(decision.triggers.contains(&SelectionTrigger::BudgetDegrade));
    assert!(decision.triggers.contains(&SelectionTrigger::CatalogChange));
    let previous = decision
        .normalized_input
        .signals
        .previous_choice
        .as_ref()
        .expect("same-run previous choice");
    let stay = decision
        .candidate_set
        .iter()
        .find(|evaluation| &evaluation.candidate == previous)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("previous choice evaluation");
    assert_eq!(stay.switch_transition, ContextSwitchTransition::Stay);
    assert_eq!(stay.switch_cost_microunits, 0);
}

#[test]
fn complete_observed_cpo_overrides_only_previous_choice_expected_cost() {
    let initial = select(&base_input()).expect("initial decision");
    let previous = initial
        .choice
        .as_ref()
        .map(|choice| choice.candidate.clone())
        .expect("initial choice");
    let catalog_expected = initial
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == previous)
        .and_then(|evaluation| evaluation.score.as_ref())
        .map(|score| score.expected_total_cost_per_accepted_task_microunits)
        .expect("catalog expected cost");

    let mut unchanged = base_input();
    unchanged.signals.previous_choice = Some(previous.clone());
    unchanged.signals.previous_catalog_digest = Some(initial.input_digests.catalogs.value.clone());
    let none_decision = select(&unchanged).expect("none observed CPO");
    let none_expected = none_decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == previous)
        .and_then(|evaluation| evaluation.score.as_ref())
        .map(|score| score.expected_total_cost_per_accepted_task_microunits)
        .expect("none observed expected cost");
    assert_eq!(none_expected, catalog_expected);

    let mut observed = unchanged;
    observed.signals.observed_cost_per_accepted_task_microunits = Some(9_000_001);
    let observed_decision = select(&observed).expect("observed CPO");
    let previous_score = observed_decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == previous)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("previous choice score");
    assert_eq!(
        previous_score.expected_total_cost_per_accepted_task_microunits,
        9_000_001
    );
    for evaluation in &observed_decision.candidate_set {
        if evaluation.candidate == previous {
            continue;
        }
        if let Some(score) = evaluation.score.as_ref() {
            assert_ne!(
                score.expected_total_cost_per_accepted_task_microunits,
                9_000_001
            );
        }
    }
}

#[test]
fn accepted_task_cost_ledger_includes_every_cost_class() {
    let mut input = base_input();
    let candidate = CandidateKey {
        runtime: "grok".to_string(),
        model: "grok-code-fast-1".to_string(),
        effort: ReasoningEffort::High,
    };
    input.outcomes.push(OutcomeRecord {
        attempt_id: "attempt-1".to_string(),
        task: input.task.clone(),
        candidate: candidate.clone(),
        result: OutcomeResult::Accepted,
        failure_class: None,
        execution_cost_microunits: 1,
        review_cost_microunits: 2,
        rework_cost_microunits: 3,
        rereview_cost_microunits: 4,
        environment_cost_microunits: 5,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    });
    let decision = select(&input).expect("ledger selection");
    let ledger = &decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == candidate)
        .expect("Grok evaluation")
        .ledger;
    assert_eq!(ledger.total_cycle_cost_microunits, 15);
    assert_eq!(ledger.accepted, 1);
}

#[test]
fn native_environment_rejection_allows_exactly_one_data_declared_fallback() {
    let mut input = base_input();
    let rejected = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    input.signals.previous_choice = Some(rejected.clone());
    input.signals.environment_rejections = vec![EnvironmentRejectionState {
        candidate: rejected,
        rejection_code: "native_multiagent_v2_model_rejected".to_string(),
        evidence_id: "environment-evidence-1".to_string(),
        fallback_transition_used: false,
    }];
    let decision = select(&input).expect("environment fallback");
    assert_eq!(
        decision.choice.as_ref().expect("fallback choice").reason,
        ChoiceReason::OneShotEnvironmentFallback
    );
    let transition = decision.environment_fallback.expect("fallback provenance");
    assert_eq!(transition.transition_ordinal, 1);
    assert_eq!(transition.maximum_transitions, 1);
    let choice = decision.choice.as_ref().expect("fallback choice evidence");
    assert_eq!(
        choice.switch_transition,
        ContextSwitchTransition::ModelChangeSameRuntime
    );
    assert_eq!(choice.configured_switch_cost_microunits, 10_000);
    assert!(choice.applied_switch_cost_microunits > 0);
    assert!(choice.switch_cost_microunits > 0);

    input.signals.environment_rejections[0].fallback_transition_used = true;
    let second = select(&input).expect("post-fallback selection");
    assert!(second.environment_fallback.is_none());
}

#[test]
fn malformed_pool_pressure_is_rejected() {
    let mut input = base_input();
    input.pools[0].pool_pressure_basis_points = 10_001;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(_))
    ));
}

#[test]
fn malformed_prior_dataset_published_date_is_rejected() {
    let mut input = base_input();
    input.priors.published_on = "2026-8-21".to_string();
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("priors.published_on must be a valid YYYY-MM-DD calendar date")
    ));
}

#[test]
fn invalid_objective_profile_calendar_date_is_rejected() {
    let mut input = base_input();
    input.priors.objective_profiles[0].effective_date = "2026-02-30".to_string();
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("objective_profile.effective_date must be a valid YYYY-MM-DD calendar date")
    ));
}

#[test]
fn invalid_prior_observation_calendar_date_is_rejected() {
    let mut input = base_input();
    input.priors.models[0].observed_on = "2026-13-01".to_string();
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("prior.observed_on must be a valid YYYY-MM-DD calendar date")
    ));
}

#[test]
fn empty_debug_requester_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.constraints.allow_debug_override = true;
    input.debug_override = Some(DebugOverride {
        candidate: CandidateKey {
            runtime: input.catalogs[0].runtime.clone(),
            model: input.catalogs[0].models[0].model.clone(),
            effort: input.catalogs[0].models[0].supported_efforts[0],
        },
        requested_by: String::new(),
        reason: "bounded replay".to_string(),
    });
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("debug_override.requested_by must be non-empty and trimmed")
    ));
}

#[test]
fn empty_debug_reason_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.constraints.allow_debug_override = true;
    input.debug_override = Some(DebugOverride {
        candidate: CandidateKey {
            runtime: input.catalogs[0].runtime.clone(),
            model: input.catalogs[0].models[0].model.clone(),
            effort: input.catalogs[0].models[0].supported_efforts[0],
        },
        requested_by: "test operator".to_string(),
        reason: String::new(),
    });
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("debug_override.reason must be non-empty and trimmed")
    ));
}

#[test]
fn unknown_catalog_boundedness_member_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.catalogs[0].models[0]
        .capabilities
        .boundedness
        .insert(Boundedness::Unknown);
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("capabilities.boundedness must not contain unknown")
    ));
}

#[test]
fn unknown_catalog_maximum_risk_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.catalogs[0].models[0].capabilities.maximum_risk = RiskLevel::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("capabilities.maximum_risk must be known")
    ));
}

#[test]
fn unknown_catalog_maximum_context_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.catalogs[0].models[0].capabilities.maximum_context = ContextSize::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("capabilities.maximum_context must be known")
    ));
}

#[test]
fn unknown_catalog_maximum_horizon_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.catalogs[0].models[0].capabilities.maximum_horizon = TaskHorizon::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message))
            if message.contains("capabilities.maximum_horizon must be known")
    ));
}

#[test]
fn unknown_task_risk_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.task.risk = RiskLevel::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("task.risk must be known")
    ));
}

#[test]
fn unknown_task_boundedness_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.task.boundedness = Boundedness::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("task.boundedness must be known")
    ));
}

#[test]
fn unknown_task_context_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.task.context = ContextSize::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("task.context must be known")
    ));
}

#[test]
fn unknown_task_horizon_is_rejected_before_candidate_evaluation() {
    let mut input = base_input();
    input.task.horizon = TaskHorizon::Unknown;
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("task.horizon must be known")
    ));
}

#[test]
fn duplicate_supported_efforts_are_canonicalized_as_set_membership() {
    let canonical = base_input();
    let mut repeated = canonical.clone();
    let effort = repeated.catalogs[0].models[0].supported_efforts[0];
    repeated.catalogs[0].models[0]
        .supported_efforts
        .extend([effort, effort]);

    assert_eq!(
        select(&repeated).expect("repeated effort advertisement"),
        select(&canonical).expect("canonical effort advertisement")
    );
}

#[test]
fn conflicting_duplicate_outcome_attempt_ids_fail_independent_of_order() {
    let mut input = base_input();
    let candidate = input.catalogs[0].models[0].model.clone();
    let candidate = CandidateKey {
        runtime: input.catalogs[0].runtime.clone(),
        model: candidate,
        effort: input.catalogs[0].models[0].supported_efforts[0],
    };
    let accepted = OutcomeRecord {
        attempt_id: "duplicate-attempt".to_string(),
        task: input.task.clone(),
        candidate: candidate.clone(),
        result: OutcomeResult::Accepted,
        failure_class: None,
        execution_cost_microunits: 10,
        review_cost_microunits: 20,
        rework_cost_microunits: 0,
        rereview_cost_microunits: 0,
        environment_cost_microunits: 0,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    };
    let mut rejected = accepted.clone();
    rejected.result = OutcomeResult::Rejected;
    rejected.failure_class = Some(FailureClass::ModelQuality);
    rejected.execution_cost_microunits = 99;
    input.outcomes = vec![accepted.clone(), rejected.clone()];
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("duplicate attempt_id")
    ));

    input.outcomes = vec![rejected, accepted];
    assert!(matches!(
        select(&input),
        Err(SelectionError::InvalidInput(message)) if message.contains("duplicate attempt_id")
    ));
}

#[test]
fn operational_costs_are_normalized_per_accepted_task() {
    let mut input = base_input();
    for pool in &mut input.pools {
        pool.marginal_cost_microunits = 9_001;
    }
    let decision = select(&input).expect("operational-cost decision");
    let choice = decision.choice.as_ref().expect("operational-cost choice");
    let score = decision
        .candidate_set
        .iter()
        .find(|candidate| candidate.candidate == choice.candidate)
        .and_then(|candidate| candidate.score.as_ref())
        .expect("operational-cost score");
    let quality = u128::from(score.posterior_quality_basis_points);
    let expected = (u128::from(9_001u64) * 10_000).div_ceil(quality);
    assert_eq!(score.marginal_cost_microunits, expected as u64);
}

#[test]
fn ambiguous_semantic_keys_are_rejected_independent_of_order() {
    let mut objective = base_input();
    let mut duplicate_profile = objective.priors.objective_profiles[0].clone();
    duplicate_profile.minimum_quality_basis_points = duplicate_profile
        .minimum_quality_basis_points
        .saturating_sub(1);
    objective.priors.objective_profiles.push(duplicate_profile);
    assert!(matches!(
        select(&objective),
        Err(SelectionError::InvalidInput(_))
    ));
    objective.priors.objective_profiles.reverse();
    assert!(matches!(
        select(&objective),
        Err(SelectionError::InvalidInput(_))
    ));

    let mut class_fit = base_input();
    {
        let prior = class_fit
            .priors
            .models
            .iter_mut()
            .find(|prior| !prior.class_fit.is_empty())
            .expect("class-fit prior");
        let mut duplicate_class_fit = prior.class_fit[0].clone();
        duplicate_class_fit.quality_basis_points =
            duplicate_class_fit.quality_basis_points.saturating_sub(1);
        prior.class_fit.push(duplicate_class_fit);
    }
    assert!(matches!(
        select(&class_fit),
        Err(SelectionError::InvalidInput(_))
    ));
    class_fit
        .priors
        .models
        .iter_mut()
        .find(|prior| prior.class_fit.len() > 1)
        .expect("duplicated class-fit prior")
        .class_fit
        .reverse();
    assert!(matches!(
        select(&class_fit),
        Err(SelectionError::InvalidInput(_))
    ));

    let mut authority = base_input();
    {
        let prior = authority
            .priors
            .models
            .iter_mut()
            .find(|prior| !prior.class_fit.is_empty())
            .expect("class-fit prior for authority fixture");
        let class_fit = &prior.class_fit[0];
        let evidence = AuthorityEvidencePrior {
            task_class: class_fit.task_class.clone(),
            role: AuthorityRole::AcceptanceGate,
            effort: class_fit.effort,
            quality_basis_points: class_fit.quality_basis_points,
            sample_size: class_fit.sample_size,
        };
        let mut duplicate_authority = evidence.clone();
        duplicate_authority.sample_size = duplicate_authority.sample_size.saturating_add(1);
        prior.authority_evidence.push(evidence);
        prior.authority_evidence.push(duplicate_authority);
    }
    assert!(matches!(
        select(&authority),
        Err(SelectionError::InvalidInput(_))
    ));
    authority
        .priors
        .models
        .iter_mut()
        .find(|prior| prior.authority_evidence.len() > 1)
        .expect("duplicated authority prior")
        .authority_evidence
        .reverse();
    assert!(matches!(
        select(&authority),
        Err(SelectionError::InvalidInput(_))
    ));

    let mut fallback = base_input();
    {
        let prior = fallback
            .priors
            .models
            .iter_mut()
            .find(|prior| !prior.one_shot_environment_fallbacks.is_empty())
            .expect("environment fallback prior");
        let mut duplicate_fallback = prior.one_shot_environment_fallbacks[0].clone();
        duplicate_fallback.target_effort = ReasoningEffort::Xhigh;
        prior
            .one_shot_environment_fallbacks
            .push(duplicate_fallback);
    }
    assert!(matches!(
        select(&fallback),
        Err(SelectionError::InvalidInput(_))
    ));
    fallback
        .priors
        .models
        .iter_mut()
        .find(|prior| prior.one_shot_environment_fallbacks.len() > 1)
        .expect("duplicated environment fallback prior")
        .one_shot_environment_fallbacks
        .reverse();
    assert!(matches!(
        select(&fallback),
        Err(SelectionError::InvalidInput(_))
    ));

    let mut rejection = base_input();
    let candidate = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };
    rejection.signals.environment_rejections = vec![
        EnvironmentRejectionState {
            candidate: candidate.clone(),
            rejection_code: "native_rejection".to_string(),
            evidence_id: "evidence-a".to_string(),
            fallback_transition_used: false,
        },
        EnvironmentRejectionState {
            candidate,
            rejection_code: "native_rejection".to_string(),
            evidence_id: "evidence-b".to_string(),
            fallback_transition_used: true,
        },
    ];
    assert!(matches!(
        select(&rejection),
        Err(SelectionError::InvalidInput(_))
    ));
    rejection.signals.environment_rejections.reverse();
    assert!(matches!(
        select(&rejection),
        Err(SelectionError::InvalidInput(_))
    ));
}

#[test]
fn cost_and_score_overflow_fail_closed() {
    let mut prior_cost = base_input();
    for prior in &mut prior_cost.priors.models {
        for class_fit in &mut prior.class_fit {
            class_fit.execution_cost_microunits = u64::MAX;
            class_fit.review_cost_microunits = 1;
        }
    }
    assert!(matches!(
        select(&prior_cost),
        Err(SelectionError::InvalidInput(message)) if message.contains("prior cycle cost overflowed")
    ));

    let mut total_score = base_input();
    for pool in &mut total_score.pools {
        pool.marginal_cost_microunits = u64::MAX;
    }
    assert!(matches!(
        select(&total_score),
        Err(SelectionError::InvalidInput(message)) if message.contains("overflowed")
    ));
}

#[test]
fn prohibited_debug_override_is_rejected_and_fails_closed() {
    let mut input = base_input();
    input.catalogs[0].models.push(CatalogModel {
        model: "gpt-5.6-terra".to_string(),
        available: true,
        access: None,
        supported_efforts: vec![ReasoningEffort::High],
        capabilities: capabilities("localized_code_change", AuthorityRole::TerminalLeaf, false),
    });
    let prohibited = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-terra".to_string(),
        effort: ReasoningEffort::High,
    };
    input.constraints.allow_debug_override = true;
    input.debug_override = Some(DebugOverride {
        candidate: prohibited.clone(),
        requested_by: "test operator".to_string(),
        reason: "prove a policy prohibition cannot be bypassed".to_string(),
    });

    let decision = select(&input).expect("prohibited debug decision");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.choice.is_none());
    assert_eq!(
        decision
            .debug_override
            .as_ref()
            .expect("debug provenance")
            .disposition,
        DebugOverrideDisposition::Rejected
    );
    let evaluation = decision
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == prohibited)
        .expect("prohibited candidate evaluation");
    assert!(evaluation
        .ineligibility_reasons
        .iter()
        .any(|reason| reason.code == IneligibilityCode::PolicyProhibited));
}

#[test]
fn catalog_withdrawal_reselects_deterministically() {
    let initial = select(&base_input()).expect("initial decision");
    let previous = initial
        .choice
        .as_ref()
        .expect("initial choice")
        .candidate
        .clone();
    let mut withdrawn = base_input();
    withdrawn
        .catalogs
        .iter_mut()
        .find(|catalog| catalog.runtime == previous.runtime)
        .expect("selected runtime catalog")
        .models
        .retain(|model| model.model != previous.model);
    withdrawn.signals.previous_choice = Some(previous.clone());
    withdrawn.signals.previous_catalog_digest = Some(initial.input_digests.catalogs.value);

    let first = select(&withdrawn).expect("withdrawal decision");
    let replay = select(&withdrawn).expect("withdrawal replay");
    assert_eq!(first, replay);
    assert!(first.triggers.contains(&SelectionTrigger::CatalogChange));
    assert_ne!(
        first.choice.as_ref().expect("replacement choice").candidate,
        previous
    );
    let replacement = first.choice.as_ref().expect("replacement evidence");
    assert!(matches!(
        replacement.switch_transition,
        ContextSwitchTransition::ModelChangeSameRuntime | ContextSwitchTransition::RuntimeChange
    ));
    assert!(replacement.configured_switch_cost_microunits > 0);
    assert!(replacement.applied_switch_cost_microunits > 0);
    assert!(replacement.switch_cost_microunits > 0);
}

#[test]
fn normalized_input_is_a_self_contained_replay_fixture() {
    let decision = select(&base_input()).expect("initial decision");
    let replay = select(&decision.normalized_input).expect("provenance replay");
    assert_eq!(replay, decision);
}

#[test]
fn quota_provenance_round_trips_and_is_required_by_the_strict_artifact_schema() {
    let mut input = base_input();
    configure_exhausted_quota(&mut input, ExhaustionBehavior::Degrade, &["grok"]);
    let decision = select(&input).expect("quota decision");
    let bytes = serde_json::to_vec(&decision).expect("serialize quota decision");
    let decoded = serde_json::from_slice::<SelectionProvenance>(&bytes)
        .expect("strict quota provenance round trip");
    assert_eq!(decoded, decision);
    assert_eq!(decoded.schema_version, 4);

    let schema = selection_event_schema_value();
    let provenance = &schema["properties"]["provenance"];
    let required = provenance["required"].as_array().expect("required fields");
    assert!(required.iter().any(|field| field == "quota"));
    let runtime_pool = &provenance["properties"]["runtime_operations"]["items"];
    let pool_required = runtime_pool["required"]
        .as_array()
        .expect("runtime pool required fields");
    for field in [
        "pool_reference",
        "pool_kind",
        "exhausted",
        "exhaustion_behavior",
        "authorized_alternatives",
        "observation_source",
        "marginal_cost_microunits",
    ] {
        assert!(pool_required.iter().any(|required| required == field));
    }
}

#[test]
fn schema_v3_without_canonical_switch_evidence_is_rejected() {
    let decision = select(&base_input()).expect("schema-v4 decision");
    let mut value = serde_json::to_value(decision).expect("selector JSON");
    let object = value.as_object_mut().expect("selector object");
    object.insert("schema_version".to_string(), serde_json::json!(3));
    object.remove("provided_switch_cost_evidence");
    object["input_digests"]
        .as_object_mut()
        .expect("input digests")
        .remove("switch_cost_evidence");
    for candidate in object["candidate_set"]
        .as_array_mut()
        .expect("candidate set")
    {
        if let Some(score) = candidate["score"].as_object_mut() {
            for field in [
                "switch_cost_origin",
                "switch_cost_estimate",
                "configured_switch_cost_origin",
                "applied_switch_cost_microunits",
            ] {
                score.remove(field);
            }
        }
    }
    if let Some(choice) = object["choice"].as_object_mut() {
        for field in [
            "switch_cost_origin",
            "switch_cost_estimate",
            "configured_switch_cost_origin",
            "applied_switch_cost_microunits",
        ] {
            choice.remove(field);
        }
    }
    for runner in object["runner_up_scores"]
        .as_array_mut()
        .expect("runner ups")
    {
        let runner = runner.as_object_mut().expect("runner-up object");
        for field in [
            "switch_cost_origin",
            "switch_cost_estimate",
            "configured_switch_cost_origin",
            "applied_switch_cost_microunits",
        ] {
            runner.remove(field);
        }
    }

    assert!(serde_json::from_value::<SelectionProvenance>(value).is_err());
}

#[test]
fn historical_schema_v1_without_quota_fields_remains_readable() {
    let decision = select(&base_input()).expect("legacy-compatible decision");
    let mut value = serde_json::to_value(decision).expect("selector JSON");
    let object = value.as_object_mut().expect("selector object");
    object.insert("schema_version".to_string(), serde_json::json!(1));
    object.remove("quota");
    object
        .get_mut("normalized_input")
        .and_then(serde_json::Value::as_object_mut)
        .expect("normalized input")
        .remove("quota_source");
    for collection in ["normalized_input", "runtime_operations"] {
        let pools = if collection == "normalized_input" {
            object[collection]["pools"]
                .as_array_mut()
                .expect("normalized pools")
        } else {
            object[collection]
                .as_array_mut()
                .expect("runtime operations")
        };
        for pool in pools {
            let pool = pool.as_object_mut().expect("pool object");
            for field in [
                "pool_reference",
                "pool_kind",
                "entitlement_bounded",
                "exhausted",
                "exhaustion_behavior",
                "authorized_alternatives",
                "observation_source",
            ] {
                pool.remove(field);
            }
        }
    }
    for candidate in object["candidate_set"]
        .as_array_mut()
        .expect("candidate set")
    {
        candidate
            .as_object_mut()
            .expect("candidate object")
            .remove("quota");
    }

    let decoded = serde_json::from_value::<SelectionProvenance>(value)
        .expect("historical schema-v1 selector event");
    assert_eq!(decoded.schema_version, 1);
    assert!(decoded.quota.is_none());
    assert!(decoded.candidate_set.iter().all(|candidate| {
        candidate.quota.disposition == QuotaCandidateDisposition::LegacyUnconfigured
    }));
}

#[test]
fn legacy_unconfigured_zero_remaining_pool_still_fails_exhausted() {
    let mut input = base_input();
    input.constraints.allowed_runtimes = ["codex".to_string()].into_iter().collect();
    let codex = input
        .pools
        .iter_mut()
        .find(|pool| pool.runtime == "codex")
        .expect("Codex pool");
    codex.entitlement_remaining_units = 0;
    codex.exhausted = false;

    let decision = select(&input).expect("legacy exhaustion decision");
    assert_eq!(decision.status, DecisionStatus::FailClosed);
    assert!(decision.quota.is_none());
    assert!(decision
        .candidate_set
        .iter()
        .filter(|candidate| candidate.candidate.runtime == "codex")
        .all(|candidate| candidate
            .ineligibility_reasons
            .iter()
            .any(|reason| { reason.code == IneligibilityCode::EntitlementExhausted })));
}

fn rust_source_excluding_cfg_test(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(idx) = rest.find("#[cfg(test)]") {
        output.push_str(&rest[..idx]);
        rest = rest[idx + "#[cfg(test)]".len()..].trim_start();
        rest = skip_following_rust_item(rest);
    }
    output.push_str(rest);
    output
}

fn skip_following_rust_item(source: &str) -> &str {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut seen_brace = false;
    let mut in_string = None;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => {
                in_string = Some(c);
                i += 1;
            }
            b'{' => {
                depth += 1;
                seen_brace = true;
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if seen_brace && depth == 0 {
                    return &source[i..];
                }
            }
            b';' if !seen_brace && depth == 0 => return &source[i + 1..],
            _ => i += 1,
        }
    }
    &source[i..]
}

#[test]
fn automatic_policy_and_bridge_contain_no_model_slug_constants() {
    let automatic_sources = [
        include_str!("selector.rs"),
        include_str!("../supervise/selection_bridge.rs"),
        include_str!("../optimizer/evaluation_fn.rs"),
        include_str!("../optimizer/seed_evidence.rs"),
    ]
    .into_iter()
    .map(rust_source_excluding_cfg_test)
    .collect::<Vec<_>>()
    .join("\n");
    for slug in [
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
        "grok-code-fast-1",
        "cursor-composer-1",
    ] {
        assert!(
            !automatic_sources.contains(slug),
            "automatic Rust policy path hardcodes model slug {slug}"
        );
    }
}
